#!/usr/bin/env python3
"""Decode socrates ETE with the device's OpenCSD, preserving the original trace.

The stock recorder writes metadata IDs 0x10+2*cpu while formatted AUX uses cpu+1.
This narrowly scoped harness fixes only those metadata fields on a copy, then
uses `dump --dump-etm element` (NOT inject's unformatted input path). It does
not implement ETE decoding and never equates a nonempty dump with a full trace.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import subprocess
import struct
import sys
import uuid

import ete_addr_space as A
import ete_patch_traceid as P

KIND = re.compile(r"^Idx:(\d+); ID:([0-9a-fA-F]+); (OCSD_GEN_TRC_ELEM_[A-Z_]+)")
RANGE = re.compile(r"exec range=(0x[0-9a-f]+):\[(0x[0-9a-f]+)\] num_i\((\d+)\)")
ASYNC = b"\x00" * 11 + b"\x80"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def async_scan(stream):
    """I_ASYNC candidates: 11 zeros then 0x80. Not proof of valid execution.

    OpenCSD trc_pkt_proc_etmv4i.cpp::iPktASync accepts 12 bytes ending in
    0x80; while unsynced, extra leading zeros are ignored. ETE uses this same
    processor. The old `0x0f ... 0xf8` probe did not test this protocol.
    """
    offsets = []
    count = 0
    at = stream.find(ASYNC)
    while at >= 0:
        count += 1
        if len(offsets) < 8:
            offsets.append(at)
        at = stream.find(ASYNC, at + len(ASYNC))
    return {"i_async_candidates": count, "first_offsets": offsets}


def protocol_scan(path):
    """Scan each deframed record/source separately: never bridge capture gaps."""
    rows, payload_records = [], []
    for payload, idx, cpu in P.D.walk_aux_payloads(path):
        payload_records.append({"record_index": idx, "cpu": cpu, "payload_bytes": len(payload),
                                "unprocessed_tail_bytes": len(payload) % 16})
        streams, cur = {}, P.D.BAD_SRC_ID
        for at in range(0, len(payload) - 15, 16):
            emitted, cur = P.D.unpack_frame(payload[at:at + 16], cur)
            for sid, byte in emitted:
                streams.setdefault(sid, bytearray()).append(byte)
        for sid, stream in sorted(streams.items()):
            rows.append(dict(record_index=idx, cpu=cpu, trace_id=sid,
                             deframed_bytes=len(stream), **async_scan(stream)))
    return {"criterion": "11*00 + 80 (OpenCSD I_ASYNC)", "records": rows,
            "payload_records": payload_records,
            "unprocessed_tail_bytes": sum(r["unprocessed_tail_bytes"] for r in payload_records),
            "i_async_candidates": sum(r["i_async_candidates"] for r in rows),
            "limits": "Candidates only, not decoder acceptance; record boundaries are not joined."}


def prepare_trace(src, dst):
    if Path(dst).exists() or Path(src).resolve() == Path(dst).resolve():
        raise ValueError("refusing to overwrite source or an existing output")
    data = Path(src).read_bytes()
    if not data.startswith(b"PERFILE2"):
        raise ValueError("not a PERFILE2 trace")
    rec_off, body = P.find_info_record(data)
    meta, entries = P.parse_info(body)
    if (meta["aux_type"] != 3 or meta["version"] != 1 or meta["snapshot"] != 0
            or meta["nr_cpu"] != 8 or any(e["kind"] != "ETEInfo" for e in entries)):
        raise ValueError("this repair is restricted to observed eight-source socrates ETE")
    if {e["cpu"] for e in entries} != set(range(8)):
        raise ValueError("expected exactly one metadata entry for cpu0..cpu7")
    for e in entries:
        if e["nrtrcparams"] != 8 or e["trctraceidr"] not in (0x10 + 2 * e["cpu"], e["cpu"] + 1):
            raise ValueError("unexpected trace-ID layout; refusing a guessed repair")
    stream_ids = P.in_stream_ids(src)
    if not stream_ids or any(sid != cpu + 1 for cpu, sid in stream_ids.items()):
        raise ValueError("formatted stream does not match the observed cpu+1 layout")
    fixed, changes = bytearray(data), []
    for e in entries:
        at = rec_off + 8 + e["offset"] + 8 * P.TRCTRACEIDR_WORD
        struct.pack_into("<Q", fixed, at, e["cpu"] + 1)
        changes.append({"cpu": e["cpu"], "old_trctraceidr": hex(e["trctraceidr"]),
                        "new_trctraceidr": hex(e["cpu"] + 1),
                        "in_stream_id": stream_ids.get(e["cpu"])})
    if sha256(src) != hashlib.sha256(data).hexdigest():
        raise ValueError("source changed during preparation")
    with open(dst, "xb") as fh:
        fh.write(fixed)
    return changes


def summarise(dump, resolvers=()):
    counts, by_id, mapped = Counter(), {}, Counter()
    failures, samples, first_range, malformed, range_count = [], [], None, 0, 0
    decoder_errors, error_samples = Counter(), []
    no_sync_reasons = Counter()
    # Validate each unique range once, but count every occurrence in the dump.
    cache = {}
    unique_per_module = Counter()
    with open(dump, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for error in re.findall(r"OCSD_ERR_[A-Z_]+", line):
                decoder_errors[error] += 1
                if len(error_samples) < 8:
                    error_samples.append(line.strip()[:500])
            m = KIND.match(line)
            if not m:
                continue
            kind = m[3].removeprefix("OCSD_GEN_TRC_ELEM_")
            counts[kind] += 1
            by_id.setdefault(m[2], Counter())[kind] += 1
            if kind == "NO_SYNC":
                reason = re.search(r"NO_SYNC\(([^)]*)\)", line)
                no_sync_reasons[reason[1] if reason else "unspecified"] += 1
            if kind != "INSTR_RANGE":
                continue
            r = RANGE.search(line)
            if not r:
                malformed += 1
                continue
            start, end, num_i = int(r[1], 16), int(r[2], 16), int(r[3])
            range_count += 1
            if first_range is None:
                first_range = {"trace_index": int(m[1]), "trace_id": m[2],
                               "start": r[1], "end_exclusive": r[2]}
            key = (start, end, num_i)
            if key not in cache:
                result = {"start": r[1], "end_exclusive": r[2], "num_i": num_i,
                          "a64_size_agrees": end > start and start % 4 == 0
                          and end % 4 == 0 and end - start == num_i * 4,
                          "module": None, "coordinate_verified": False}
                for resolver in resolvers:
                    owned = [row for row in resolver.rows
                             if row["path"] in resolver.mapped_paths
                             and "x" in row["perms"] and row["start"] <= start
                             and start < end <= row["end"]]
                    if not owned or not resolver.is_a64 or not result["a64_size_agrees"]:
                        continue
                    a, b = resolver.resolve(start), resolver.resolve(end - 4)
                    result["module"] = resolver.module
                    if (a["status"] == b["status"] == "resolved"
                            and a.get("cross_check") == b.get("cross_check") == "agree"
                            and a["segment"] == b["segment"]):
                        off, last = int(a["file_offset"], 16), int(b["file_offset"], 16)
                        blob = resolver.bytes_at(off, end - start)
                        checked = last - off == end - start - 4 and len(blob) == end - start
                        result.update(coordinate_verified=checked,
                                      link_vaddr=a["link_vaddr"], file_offset=a["file_offset"],
                                      range_bytes_sha256=hashlib.sha256(blob).hexdigest(),
                                      last_word=blob[-4:].hex(),
                                      last_instruction=A.disassemble_a64(blob[-4:]))
                    unique_per_module[resolver.module] += 1
                    break
                cache[key] = result
                if len(samples) < 20 and result["coordinate_verified"]:
                    samples.append(result)
                if not result["a64_size_agrees"] and len(failures) < 10:
                    failures.append(result)
            result = cache[key]
            if result["coordinate_verified"]:
                mapped[result["module"]] += 1
    return {"element_counts": dict(counts),
            "per_trace_id": {sid: dict(c) for sid, c in by_id.items()},
            "instruction_ranges": range_count, "unique_ranges": len(cache),
            "malformed_range_lines": malformed,
            "decoder_error_mentions": dict(decoder_errors), "decoder_error_samples": error_samples,
            "no_sync_reasons": dict(no_sync_reasons),
            "requested_module_identities": [r.identity for r in resolvers],
            "a64_size_mismatches_unique": sum(not r["a64_size_agrees"] for r in cache.values()),
            "mapped_range_occurrences": dict(mapped),
            "unique_ranges_in_requested_modules": dict(unique_per_module),
            "first_instruction_range": first_range, "verified_samples": samples,
            "size_mismatch_examples": failures,
            "address_validation_requested": bool(resolvers),
            "full_trace_verified": False,
            "limits": "NO_SYNC/overflow/ADDR_NACC gaps are not execution edges. Only requested modules are mapped; "
                      "ELF checks do not prove business semantics, all inputs or data values. "
                      "Last-instruction mnemonics use address zero: branch immediates are not runtime targets."}


def run_adb(adb, serial, args, timeout, **kwargs):
    p = subprocess.run([adb, "-s", serial, *args], timeout=timeout, **kwargs)
    if p.returncode:
        raise RuntimeError("adb command failed (rc=%d): %s" % (p.returncode, args[0]))
    return p


def decode(args):
    out = Path(args.out_dir)
    # Fresh directory: never silently overwrite a previous experiment.
    out.mkdir(parents=True, exist_ok=False)
    source = Path(args.trace).resolve()
    report = {"schema": 1, "source": str(source),
              "device_serial": args.serial, "status": "started"}
    report_path = out / "decode.json"
    remote = "/data/local/tmp/pi_ete_decode_" + uuid.uuid4().hex
    created = False
    try:
        report["source_sha256"] = sha256(source)
        resolvers = []
        if args.module:
            manifest = json.loads(Path(args.manifest).read_text(encoding="utf8"))
            rows, bad = A.parse_maps(Path(args.maps).read_text(encoding="utf8"))
            if bad:
                raise ValueError("unparseable maps rows")
            for module in args.module:
                resolvers.append(A.ModuleResolver(manifest, rows, module, elf_dir=args.elf_dir))
            report["address_inputs"] = {"maps_sha256": sha256(args.maps),
                                        "manifest_sha256": sha256(args.manifest)}
        fixed = out / "id-aligned.perf"
        report["trace_id_changes"] = prepare_trace(source, fixed)
        report["fixed_sha256"] = sha256(fixed)
        report["protocol_scan"] = protocol_scan(fixed)
        env = run_adb(args.adb, args.serial,
                      ["shell", "su 0 sh -c 'id; uname -r; getenforce; simpleperf --version; "
                       "sha256sum /system/bin/simpleperf'"], 15, capture_output=True)
        report["device_environment"] = (env.stdout + env.stderr).decode("utf8", "replace")
        if ("uid=0" not in report["device_environment"]
                or "5.15.41-android13-8-00015-gde2a4c25826b-ab9439604" not in report["device_environment"]):
            raise ValueError("root/exact socrates kernel gate failed")
        run_adb(args.adb, args.serial, ["shell", "mkdir " + remote], 15, capture_output=True)
        created = True
        run_adb(args.adb, args.serial, ["push", str(fixed), remote + "/trace.perf"], 30,
                capture_output=True)
        command = "su 0 sh -c 'timeout %d simpleperf --log error dump -i %s/trace.perf --dump-etm element'" % (
            args.timeout, remote)
        report["decode_command"] = command
        dump, errors = out / "elements.txt", out / "decoder.stderr.txt"
        with dump.open("wb") as stdout, errors.open("wb") as stderr:
            run_adb(args.adb, args.serial, ["shell", "-T", command], args.timeout + 15,
                    stdout=stdout, stderr=stderr)
        report.update(summarise(dump, resolvers))
        report["dump_sha256"] = sha256(dump)
        report["dump_bytes"] = dump.stat().st_size
        report["stderr_bytes"] = errors.stat().st_size
        report["source_unchanged"] = report["source_sha256"] == sha256(source)
        if not report["source_unchanged"]:
            raise ValueError("original trace changed")
        report["status"] = "decoded_ranges" if report["instruction_ranges"] else "no_instruction_ranges"
    except (OSError, ValueError, RuntimeError, struct.error, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        report["status"], report["error"] = "unavailable", str(exc)
    finally:
        if "source_sha256" in report:
            try:
                report["source_unchanged"] = report["source_sha256"] == sha256(source)
                if not report["source_unchanged"]:
                    report["status"], report["error"] = "unavailable", "original trace changed"
            except OSError as exc:
                report["source_unchanged"] = False
                report["status"], report["error"] = "unavailable", str(exc)
        if created:
            try:
                run_adb(args.adb, args.serial,
                        ["shell", "su 0 sh -c 'rm -f %s/trace.perf; rmdir %s'" % (remote, remote)],
                        15, capture_output=True)
                report["remote_cleanup"] = True
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                report["remote_cleanup"], report["cleanup_error"] = False, str(exc)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf8")
    print("REPORT=" + str(report_path))
    print("INSTR_RANGES=" + str(report.get("instruction_ranges", 0)))
    print("RESULT=" + report["status"])
    if report.get("remote_cleanup") is False:
        return 2
    return 0 if report["status"] == "decoded_ranges" else 1 if report["status"] == "no_instruction_ranges" else 2


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--adb", default="adb")
    ap.add_argument("--serial", required=True)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--maps")
    ap.add_argument("--manifest")
    ap.add_argument("--elf-dir")
    ap.add_argument("--module", action="append", default=[])
    args = ap.parse_args()
    if not 1 <= args.timeout <= 300:
        ap.error("timeout must be 1..300 seconds")
    if args.module and not all((args.maps, args.manifest, args.elf_dir)):
        ap.error("--module requires --maps, --manifest and --elf-dir")
    try:
        return decode(args)
    except OSError as exc:
        print("ERROR=" + str(exc), file=sys.stderr)
        print("RESULT=unavailable")
        return 2


if __name__ == "__main__":
    sys.exit(main())
