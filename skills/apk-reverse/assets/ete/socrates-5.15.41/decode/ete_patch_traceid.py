#!/usr/bin/env python3
"""Read / rewrite the per-CPU ETE trace IDs that the decoder routes on.

Why this exists
---------------
`simpleperf`'s ETE decoder builds one OpenCSD decoder per CPU and *attaches its
packet sink only at the ID taken from the driver metadata*:

    ETMDecoder.cpp:665-686 (AOSP 13)
        CHECK_EQ(info[0], AuxTraceInfoRecord::MAGIC_ETE);
        cfg.reg_traceidr = ete.trctraceidr;
        trace_id = cfg.reg_traceidr & 0x7f;
        trace_ids_.emplace(ete.cpu, trace_id);
        decode_tree_.CreateDecoder(...); decode_tree_.AttachPacketSink(trace_id, ...);

For the formatted branch the bytes are first split by the CoreSight frame
deformatter, which routes on the ID **inside the stream**
(`trc_frame_deformatter.cpp` drops data for a trace ID with no attached sink).
So if the metadata ID and the in-stream ID differ, the formatted path loses every
byte *silently*: no error, no elements.

Record layout, record.h:502-524 (all u64 unless noted):

    DataType      aux_type u32 | reserved u32 | version u64 | nr_cpu u32 |
                  pmu_type u32 | snapshot u64 | info[]
    ETEInfo       magic | cpu | nrtrcparams | trcconfigr | trctraceidr |
                  trcidr0 | trcidr1 | trcidr2 | trcidr8 | trcauthstatus | trcdevarch

Measured on the exact socrates baseline, in a local capture: trctraceidr =
0x10,0x12,...,0x1e for cpu0..7, i.e. 0x10 + 2*cpu.

Usage
-----
    python ete_patch_traceid.py IN.perf                       # report only
    python ete_patch_traceid.py IN.perf OUT.perf --set cpu+1   # rewrite IDs
    python ete_patch_traceid.py IN.perf OUT.perf --set 0x21
    python ete_patch_traceid.py OUT.perf --verify --expected cpu+1
"""

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ete_deframe as D                                     # noqa: E402

AUXTRACE_INFO = 70
AUXTRACE_TYPE = 71
MAGIC_ETE = 0x5050505050505050
MAGIC_ETM4 = 0x4040404040404040
INFO_LAYOUT = {"ETEInfo": 11, "ETM4Info": 10}
TRCTRACEIDR_WORD = 4          # index of trctraceidr inside an ETE/ETM4 info block
DATA_FMT = "<QQQIIII"


def find_info_record(data):
    """Return (record_offset, body) of the single AUXTRACE_INFO record."""
    d_off, d_size = struct.unpack_from("<QQ", data, 40)
    pos, end = d_off, d_off + d_size
    hits = []
    while pos + 8 <= end:
        rtype, _misc, rsize = struct.unpack_from("<IHH", data, pos)
        if rsize < 8:
            raise ValueError("unwalkable record size %d at 0x%x" % (rsize, pos))
        if rtype == AUXTRACE_INFO:
            hits.append((pos, bytes(data[pos + 8:pos + rsize])))
            pos += rsize
        elif rtype == AUXTRACE_TYPE:
            asz, = struct.unpack_from("<Q", data, pos + 8)
            pos += 48 + ((asz + 7) & ~7)
        else:
            pos += rsize
    if len(hits) != 1:
        raise ValueError("expected exactly 1 AUXTRACE_INFO record, found %d" % len(hits))
    return hits[0]


def parse_info(body):
    """Return (meta, [ {cpu, trctraceidr, magic, offset} ]) for one AUXTRACE_INFO body."""
    aux_type, _reserved, version, nr_cpu, pmu_type = struct.unpack_from("<IIQII", body, 0)
    snapshot, = struct.unpack_from("<Q", body, 24)
    meta = {"aux_type": aux_type, "version": version, "nr_cpu": nr_cpu,
            "pmu_type": pmu_type, "snapshot": snapshot}
    entries = []
    off = 32
    for _ in range(nr_cpu):
        magic, cpu, nrtrcparams, trcconfigr, trctraceidr = struct.unpack_from("<QQQQQ", body, off)
        if magic not in (MAGIC_ETE, MAGIC_ETM4):
            raise ValueError("bad ETE/ETM4 magic 0x%x at body offset %d" % (magic, off))
        kind = "ETEInfo" if magic == MAGIC_ETE else "ETM4Info"
        entries.append({"cpu": cpu, "kind": kind, "nrtrcparams": nrtrcparams,
                        "trcconfigr": trcconfigr, "trctraceidr": trctraceidr,
                        "decoder_trace_id": trctraceidr & 0x7F, "offset": off})
        off += 8 * INFO_LAYOUT[kind]
    if off != len(body):
        raise ValueError("info blocks consume %d bytes but body is %d" % (off, len(body)))
    return meta, entries


def in_stream_ids(path, per_cpu_bytes=200000):
    """Recovered CoreSight source ID carrying the most bytes, per CPU."""
    out = {}
    for payload, _idx, cpu in D.walk_aux_payloads(path):
        _b, ids = D.deformat(payload[:per_cpu_bytes])
        if not ids:
            continue
        hist = {}
        for sid in ids:
            hist[sid] = hist.get(sid, 0) + 1
        top = max(hist.items(), key=lambda kv: kv[1])
        cur = out.setdefault(cpu, {})
        cur[top[0]] = cur.get(top[0], 0) + top[1]
    return {cpu: max(h.items(), key=lambda kv: kv[1])[0] for cpu, h in out.items()}

def resolve_rule(rule, cpu, stream_ids):
    """Desired decoder ID for one CPU. `in-stream` falls back to cpu+1 for a CPU
    that produced no trace at all, so the rule cannot silently skip a CPU."""
    if rule == "cpu+1":
        return cpu + 1, "cpu+1"
    if rule == "in-stream":
        if cpu in stream_ids:
            return stream_ids[cpu], "in-stream"
        return cpu + 1, "cpu+1(fallback)"
    return int(rule, 0), "literal"


def patch(src, dst, rule):
    data = bytearray(open(src, "rb").read())
    rec_off, body = find_info_record(data)
    meta, entries = parse_info(body)
    stream_ids = in_stream_ids(src) if rule in ("cpu+1", "in-stream") else {}
    changes = []
    for e in entries:
        want, how = resolve_rule(rule, e["cpu"], stream_ids)
        want &= 0x7F
        at = rec_off + 8 + e["offset"] + 8 * TRCTRACEIDR_WORD
        old, = struct.unpack_from("<Q", data, at)
        struct.pack_into("<Q", data, at, want)
        changes.append({"cpu": e["cpu"], "old_trctraceidr": "0x%x" % old,
                        "new_trctraceidr": "0x%x" % want, "rule": how,
                        "in_stream_id": ("0x%x" % stream_ids[e["cpu"]]
                                         if e["cpu"] in stream_ids else None)})
    if os.path.abspath(src) == os.path.abspath(dst):
        raise ValueError("refusing to overwrite the source trace")
    open(dst, "wb").write(data)
    return meta, changes


def verify(path, rule):
    data = open(path, "rb").read()
    _rec_off, body = find_info_record(data)
    meta, entries = parse_info(body)
    stream_ids = in_stream_ids(path) if rule in ("cpu+1", "in-stream") else {}
    bad = []
    for e in entries:
        want, _how = resolve_rule(rule, e["cpu"], stream_ids)
        if e["decoder_trace_id"] != (want & 0x7F):
            bad.append("cpu %d has decoder ID 0x%x, expected 0x%x"
                       % (e["cpu"], e["decoder_trace_id"], want & 0x7F))
    for line in bad:
        print("VERIFY FAIL", line)
    print("nr_cpu=%d ids=%s" % (meta["nr_cpu"],
                                ["0x%x" % e["decoder_trace_id"] for e in entries]))
    return not bad


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="inspect or rewrite AUXTRACE_INFO trctraceidr (the decoder's routing key)")
    ap.add_argument("src")
    ap.add_argument("dst", nargs="?")
    ap.add_argument("--set", help="value, or 'cpu+1' / 'in-stream'")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--expected", default="cpu+1")
    args = ap.parse_args(argv)

    if args.verify:
        ok = verify(args.src, args.expected)
        print("verify:", "PASS" if ok else "FAIL")
        return 0 if ok else 1

    data = open(args.src, "rb").read()
    _rec_off, body = find_info_record(data)
    meta, entries = parse_info(body)
    print("aux_type=%d version=%d nr_cpu=%d pmu_type=%d" %
          (meta["aux_type"], meta["version"], meta["nr_cpu"], meta["pmu_type"]))
    stream = in_stream_ids(args.src)
    for e in entries:
        sid = stream.get(e["cpu"])
        print("  cpu%-2d %-8s trctraceidr=0x%-4x decoder_id=0x%-4x in_stream_id=%-6s %s"
              % (e["cpu"], e["kind"], e["trctraceidr"], e["decoder_trace_id"],
                 "0x%x" % sid if sid is not None else "-",
                 "MATCH" if sid is not None and sid == e["decoder_trace_id"] else "MISMATCH"))
    if not args.dst:
        return 0
    if not args.set:
        ap.error("--dst requires --set")
    _meta, changes = patch(args.src, args.dst, args.set)
    for c in changes:
        print("  patch cpu%-2d 0x%x -> 0x%x (in-stream %s)"
              % (c["cpu"], int(c["old_trctraceidr"], 16), int(c["new_trctraceidr"], 16),
                 c["in_stream_id"]))
    print("wrote", args.dst)
    return 0


if __name__ == "__main__":
    sys.exit(main())
