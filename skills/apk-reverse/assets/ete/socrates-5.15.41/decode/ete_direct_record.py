#!/usr/bin/env python3
"""Direct CPU0 ETE capture with strict loss-marker checks, not a full-path guarantee."""
import argparse
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import shlex
import struct
import subprocess
import sys
import uuid

import ete_deframe as deframe
import ete_addr_space
from ete_loss import perf_loss
import ete_target_manifest as target

RELEASE = "5.15.41-android13-8-00015-gde2a4c25826b-ab9439604"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record_header(kind, body, misc=0):
    return struct.pack("<IHH", kind, misc, len(body) + 8) + body


def package(attr, events, aux, maps, tid, info):
    """Wrap original events/AUX without removing flags or changing payload bytes."""
    if len(attr) < 112 or struct.unpack_from("<Q", attr, 24)[0] != 128:
        raise ValueError("expected direct recorder PERF_SAMPLE_CPU attribute")
    records = []
    for line in maps.splitlines():
        fields = line.split(maxsplit=5)
        if len(fields) < 6:
            continue
        span, perms, offset, _dev, _inode, name = fields
        low, high = (int(v, 16) for v in span.split("-"))
        prot = sum(bit for char, bit in (("r", 1), ("w", 2), ("x", 4)) if char in perms)
        filename = name.encode("utf8") + b"\0"
        filename += b"\0" * (-len(filename) % 8)
        body = struct.pack("<IIQQQIIQQII", tid, tid, low, high - low, int(offset, 16),
                           0, 0, 0, 0, prot, 2) + filename + struct.pack("<II", 0, 0)
        records.append(record_header(10, body, 2))
    records += [record_header(70, info), events]
    size = len(attr) + 16
    ids_offset, data_offset = 104 + size, 104 + size + 8
    aux_offset = data_offset + sum(map(len, records))
    records.append(record_header(71, struct.pack("<QQQIIII", len(aux), 0, 0, 0, tid, 0, 0))
                   + aux + b"\0" * (-len(aux) % 8))
    data = b"".join(records)
    feature = struct.pack("<QQ", aux_offset, 48)
    feature_offset = data_offset + len(data) + 16
    header = b"PERFILE2" + struct.pack("<QQQQQQQQ", 104, size, 104, size,
                                       data_offset, len(data), 0, 0) + (1 << 18).to_bytes(32, "little")
    return (header + attr + struct.pack("<QQ", ids_offset, 8) + struct.pack("<Q", 1) + data
            + struct.pack("<QQ", feature_offset, len(feature)) + feature)


def validate(args):
    if not args.serial or args.tid <= 0:
        raise ValueError("explicit serial and positive existing TID required")
    if not math.isfinite(args.duration) or not 0 < args.duration <= .03:
        raise ValueError("duration must be in (0, 0.03] seconds")
    size = args.aux_buffer_size
    if not 1048576 <= size <= 67108864 or size & (size - 1):
        raise ValueError("AUX size must be a power of two from 1 to 64 MiB")
    data = Path(args.recorder).read_bytes()
    if len(data) < 64 or data[:5] != b"\x7fELF\x02" or struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("recorder must be an AArch64 ELF built from ete_direct_record.c")


def capture(args):
    validate(args)
    root = Path(args.out_dir)
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise ValueError("out-dir must be empty")
    adb = [args.adb, "-s", args.serial]
    remote = "/data/local/tmp/pi_ete_direct_" + uuid.uuid4().hex
    idle_command = 'for f in /sys/bus/coresight/devices/coresight-ete*/enable_source; do cat "$f"; done'
    created = False
    report = {"status": "unavailable", "full_trace_verified": False, "remote_cleanup": False,
              "cpu": 0, "requested_duration_seconds": args.duration, "target_modified": False}

    def shell(command, timeout=20):
        result = subprocess.run(adb + ["shell", "-T", "su -c " + shlex.quote(command)],
                                capture_output=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf8", "replace"))
        return result.stdout.decode("utf8", "replace").replace("\r\n", "\n").strip()

    def pull(source, destination):
        result = subprocess.run(adb + ["pull", source, str(destination)],
                                capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf8", "replace"))

    def affinity():
        status = shell("cat /proc/%d/status" % args.tid)
        values = [line.split(":", 1)[1].strip() for line in status.splitlines()
                  if line.startswith("Cpus_allowed_list:")]
        if values != ["0"]:
            raise ValueError("target must already be pinned to CPU0; this tool never changes affinity")

    try:
        if shell("getprop ro.product.device") != "socrates" or RELEASE != shell("uname -r"):
            raise ValueError("exact socrates kernel gate failed")
        if shell("getenforce") != "Enforcing" or "uid=0" not in shell("id"):
            raise ValueError("root/Enforcing gate failed")
        # No module loading, affinity changes or frequency changes.
        if shell(idle_command).splitlines() != ["0"] * 8:
            raise ValueError("eight idle sources required")
        affinity()
        maps = shell("cat /proc/%d/maps" % args.tid)
        (root / "maps.txt").write_text(maps + "\n", encoding="utf8")
        elf_dir = root / "elf"
        elf_dir.mkdir()
        rows, bad = ete_addr_space.parse_maps(maps)
        if bad or any("x" in row["perms"] and not row["path"] for row in rows):
            raise ValueError("unparseable or anonymous executable mappings")
        paths = sorted({row["path"] for row in rows if "x" in row["perms"] and row["path"] != "[vdso]"})
        identities, modules = [], []
        for path in paths:
            if not path.startswith("/") or " (deleted)" in path or "!" in path:
                raise ValueError("all executable mappings must be ordinary file-backed ELF")
            name = PurePosixPath(path).name
            if name in modules:
                raise ValueError("ambiguous ELF basenames")
            local = elf_dir / name
            expected = shell("sha256sum " + shlex.quote(path)).split()[0]
            pull(path, local)
            if digest(local) != expected:
                raise ValueError("capture-time ELF hash mismatch")
            identities.append(target.manifest_from_bytes(local.read_bytes(),
                              {"kind": "file", "path": str(local), "file_sha256": expected}))
            modules.append(name)
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"schema": "ete-target-manifest/1", "targets": identities},
                                       indent=2) + "\n", encoding="utf8")
        pmu = int(shell("cat /sys/bus/event_source/devices/cs_etm/type"), 0)
        info = struct.pack("<IIQIIQ", 3, 0, 1, 8, pmu, 0)
        for cpu in range(8):
            base = "/sys/bus/event_source/devices/cs_etm/cpu%d/" % cpu
            values = [int(shell("cat " + base + path), 0) for path in
                      ("trcidr/trcidr0", "trcidr/trcidr1", "trcidr/trcidr2", "trcidr/trcidr8",
                       "mgmt/trcauthstatus", "mgmt/trcdevarch")]
            if values[-1] == 0:
                raise ValueError("expected ETE device architecture")
            info += struct.pack("<" + "Q" * 11, 0x5050505050505050, cpu, 8, 64,
                                0x10 + 2 * cpu, *values)
        shell("mkdir -m 777 " + remote)
        created = True
        result = subprocess.run(adb + ["push", args.recorder, remote + "/recorder"],
                                capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError(result.stderr.decode("utf8", "replace"))
        report["recorder_sha256"] = digest(Path(args.recorder))
        if shell("sha256sum " + remote + "/recorder").split()[0] != report["recorder_sha256"]:
            raise ValueError("remote recorder hash mismatch")
        shell("chmod 755 " + remote + "/recorder")
        affinity()
        if shell("cat /proc/%d/maps" % args.tid) != maps:
            raise ValueError("maps changed before capture")
        report["recorder_stdout"] = shell("timeout 5 " + shlex.join(
            [remote + "/recorder", str(args.tid), str(args.duration), str(args.aux_buffer_size), remote]), 10)
        for name in ("events.bin", "aux.bin", "attr.bin", "direct.json", "vdso-before.bin", "vdso-after.bin"):
            pull(remote + "/" + name, root / name)
        report["timing"] = json.loads((root / "direct.json").read_text())
        affinity()
        maps_after = shell("cat /proc/%d/maps" % args.tid)
        (root / "maps-after.txt").write_text(maps_after + "\n", encoding="utf8")
        if (root / "vdso-before.bin").read_bytes() != (root / "vdso-after.bin").read_bytes():
            raise ValueError("vDSO changed during capture")
        vdso = elf_dir / "[vdso]"
        vdso.write_bytes((root / "vdso-before.bin").read_bytes())
        identities.append(target.manifest_from_bytes(vdso.read_bytes(),
                          {"kind": "memory-snapshot", "path": str(vdso), "file_sha256": digest(vdso)}))
        modules.append("[vdso]")
        manifest.write_text(json.dumps({"schema": "ete-target-manifest/1", "targets": identities},
                                       indent=2) + "\n", encoding="utf8")
        if maps_after != maps:
            raise ValueError("maps changed during capture")
        for path, identity in zip(paths, identities):
            if shell("sha256sum " + shlex.quote(path)).split()[0] != identity["sha256"]:
                raise ValueError("executable ELF changed during capture")
        trace = root / "trace.perf"
        aux = (root / "aux.bin").read_bytes()
        trace.write_bytes(package((root / "attr.bin").read_bytes(), (root / "events.bin").read_bytes(),
                                  aux, maps, args.tid, info))
        if b"".join(row[0] for row in deframe.walk_aux_payloads(trace)) != aux:
            raise ValueError("packaged AUX differs from original")
        report["aux_bytes"] = len(aux)
        report["aux_unchanged"] = True
        report["trace_sha256"] = digest(trace)
        report["loss_audit"] = perf_loss(trace)
        argv = [sys.executable, str(Path(__file__).with_name("ete_decode.py")),
                "--trace", str(trace), "--out-dir", str(root / "decoded"), "--serial", args.serial,
                "--adb", args.adb, "--timeout", "300", "--maps", str(root / "maps.txt"),
                "--manifest", str(manifest), "--elf-dir", str(elf_dir), "--require-loss-clear"]
        for module in modules:
            argv += ["--module", module]
        result = subprocess.run(argv, capture_output=True, timeout=330)
        (root / "decode.log").write_bytes(result.stdout + result.stderr)
        decoded = json.loads((root / "decoded" / "decode.json").read_text())
        report["decode_rc"] = result.returncode
        report["loss_markers_clear"] = decoded.get("loss_markers_clear", False)
        if (result.returncode == 0 and report["loss_markers_clear"]
                and decoded.get("source_unchanged") and decoded.get("remote_cleanup")):
            report["status"] = "loss_markers_clear"
        elif result.returncode == 1 and decoded.get("status") in ("trace_has_gaps", "no_aux_data"):
            report["status"] = "trace_has_gaps"
        else:
            report["status"] = "unavailable"
            report["loss_markers_clear"] = False
            report["error"] = decoded.get("error", "decoder did not complete strict validation")
    except (OSError, ValueError, RuntimeError, struct.error, subprocess.SubprocessError) as exc:
        report["error"] = str(exc)
    finally:
        if created:
            try:
                names = ["recorder", "events.bin", "aux.bin", "attr.bin", "direct.json",
                         "vdso-before.bin", "vdso-after.bin"]
                shell("rm -f " + " ".join(remote + "/" + name for name in names) + "; rmdir " + remote)
                report["remote_cleanup"] = True
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                report["cleanup_error"] = str(exc)
        else:
            report["remote_cleanup"] = True
        try:
            report["source_enable_after"] = shell(idle_command).splitlines()
            if report["source_enable_after"] != ["0"] * 8:
                report["status"] = "unavailable"
                report["loss_markers_clear"] = False
        except (OSError, RuntimeError, subprocess.SubprocessError, UnboundLocalError):
            report["source_enable_after"] = None
            report["loss_markers_clear"] = False
            report["status"] = "unavailable"
        if not report["remote_cleanup"]:
            report["loss_markers_clear"] = False
            report["status"] = "unavailable"
            report["remote_staging_remaining"] = remote
        (root / "record.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--tid", required=True, type=int)
    parser.add_argument("--duration", type=float, default=.001)
    parser.add_argument("--aux-buffer-size", type=int, default=16777216)
    parser.add_argument("--recorder", required=True, help="AArch64 ELF compiled from bundled C source")
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()
    try:
        report = capture(args)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))
    print("RESULT=" + report["status"])
    return {"loss_markers_clear": 0, "trace_has_gaps": 1}.get(report["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
