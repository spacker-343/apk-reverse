#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""capability: device_hw_probe
Read-only ARM hardware-tracing capability probe for an Android device.

This script deliberately reports four separate layers instead of saying
"ETE supported" from one sysfs directory:

  hardware_hint -> kernel_interface -> recorder_event -> trace_smoke

The default probe does not write to the device. ``--smoke-test`` performs a
bounded user-space cs-etm recording in /data/local/tmp and removes the file
afterwards. Recording AUXTRACE structure does not verify instruction decode.

Usage:
  python device_hw_probe.py
  python device_hw_probe.py --adb /path/to/adb --serial SERIAL --json
  python device_hw_probe.py --expect-root
  python device_hw_probe.py --smoke-test --duration 1
"""

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import uuid
from typing import Any, Dict, List, Optional, Tuple


PROPS = (
    "ro.product.model",
    "ro.product.device",
    "ro.soc.model",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.product.cpu.abi",
    "ro.product.cpu.abilist",
    "ro.boot.slot_suffix",
    "ro.boot.flash.locked",
    "ro.boot.verifiedbootstate",
)


def run(cmd: List[str], timeout: int = 30) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           errors="replace", timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except FileNotFoundError:
        return 127, "not found: %s" % cmd[0]
    except subprocess.TimeoutExpired:
        return 124, "TIMEOUT after %ss: %s" % (timeout, " ".join(cmd[:5]))
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "error: %s" % exc


def adb_cmd(adb: str, serial: Optional[str], *args: str) -> List[str]:
    return [adb] + (["-s", serial] if serial else []) + list(args)


def device_shell(adb: str, serial: str, command: str,
                 root: bool = False, timeout: int = 30) -> Tuple[int, str]:
    # Dynamic arguments are validated and shell-quoted before reaching here.
    if root:
        command = "su -c %s" % shlex.quote(command)
    return run(adb_cmd(adb, serial, "shell", command), timeout)


def choose_device(adb: str, requested: Optional[str]) -> Tuple[str, str]:
    rc, out = run([adb, "devices", "-l"])
    if rc != 0:
        raise RuntimeError("adb devices failed: %s" % out)
    online = []
    for line in out.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            online.append(fields[0])
    if requested:
        if requested not in online:
            raise RuntimeError("requested serial is not online: %s" % requested)
        return requested, out
    if len(online) != 1:
        raise RuntimeError("need exactly one online device; found %d" % len(online))
    return online[0], out


def lines(text: str) -> List[str]:
    return [x.strip() for x in text.splitlines() if x.strip()]


def contains_any(text: str, needles: Tuple[str, ...]) -> bool:
    lower = text.lower()
    return any(n.lower() in lower for n in needles)


def validate_aux_size(value: str) -> str:
    """Accept positive byte counts or K/M/G suffixes, never shell syntax."""
    match = re.fullmatch(r"([0-9]+)([KMG]?)", str(value), re.IGNORECASE)
    if not match:
        raise ValueError("--aux-buffer-size must be positive bytes or use K/M/G")
    size = int(match.group(1)) * (1024 ** " KMG".index(match.group(2).upper()))
    if size <= 0 or size > 1024 ** 3:
        raise ValueError("--aux-buffer-size must be between 1 byte and 1 GiB")
    return str(size)


def smoke_record(adb: str, serial: str, root: bool, duration: Optional[int],
                 aux_size: str) -> Dict[str, Any]:
    aux_size = validate_aux_size(aux_size)
    if duration is not None and not 1 <= duration <= 30:
        raise ValueError("--duration must be between 1 and 30 seconds")
    remote = "/data/local/tmp/apk_reverse_cs_etm_%s.data" % uuid.uuid4().hex
    quoted_remote = shlex.quote(remote)
    command = ("/system/bin/simpleperf record -e cs-etm:u "
               "--aux-buffer-size %s --no-dump-symbols --no-dump-kernel-symbols "
               "-o %s" % (shlex.quote(aux_size), quoted_remote))
    if duration is not None:
        command += " --duration %d" % duration
    command += " -- /system/bin/ls /system/bin"
    smoke: Dict[str, Any] = {
        "command": command, "remote_path": remote, "exit_code": None,
        "output": "", "file_size_bytes": None, "dump_exit_code": None,
        "auxtrace_structure": False, "cleaned": False, "recorded": False,
        "full_instruction_decode": "unverified",
    }
    try:
        rc, output = device_shell(adb, serial, command, root=root,
                                  timeout=max(30, (duration or 0) + 20))
        smoke.update(exit_code=rc, output=output)
        stat_rc, stat_out = device_shell(
            adb, serial, "stat -c %s " + quoted_remote, root=root, timeout=10)
        smoke.update(file_check_exit_code=stat_rc, file_check=stat_out)
        if stat_rc == 0 and re.fullmatch(r"[0-9]+", stat_out):
            smoke["file_size_bytes"] = int(stat_out)
        if rc == 0 and (smoke["file_size_bytes"] or 0) > 0:
            dump_rc, dump_out = device_shell(
                adb, serial, "/system/bin/simpleperf dump -i " + quoted_remote,
                root=root, timeout=20)
            # AUXTRACE_INFO describes metadata, not an actual AUXTRACE record.
            auxtrace = bool(re.search(
                r"^\s*(?:record\s+|type:\s*)?(?:PERF_RECORD_)?AUXTRACE\b",
                dump_out, re.IGNORECASE | re.MULTILINE))
            smoke.update(dump_exit_code=dump_rc, dump_output=dump_out,
                         auxtrace_structure=auxtrace,
                         recorded=dump_rc == 0 and auxtrace)
    except Exception as exc:  # still remove any partial recording
        smoke["error"] = str(exc)
        smoke["recorded"] = False
    finally:
        try:
            rm_rc, rm_out = device_shell(
                adb, serial, "rm -f " + quoted_remote, root=root, timeout=10)
            smoke.update(cleanup_exit_code=rm_rc, cleanup_output=rm_out)
        except Exception as exc:
            smoke["cleanup_error"] = str(exc)
            rm_rc = 1
        try:
            absent_rc, absent_out = device_shell(
                adb, serial,
                "if [ ! -e %s ] && [ ! -L %s ]; then echo ABSENT; "
                "else echo PRESENT; exit 1; fi" % (quoted_remote, quoted_remote),
                root=root, timeout=10)
            smoke.update(cleanup_check_exit_code=absent_rc,
                         cleanup_check=absent_out,
                         cleaned=rm_rc == 0 and absent_rc == 0 and absent_out == "ABSENT")
        except Exception as exc:
            smoke["cleanup_check_error"] = str(exc)
    return smoke


def probe(adb: str, serial: str, smoke: bool, duration: Optional[int],
          aux_size: str) -> Dict[str, Any]:
    aux_size = validate_aux_size(aux_size)
    if duration is not None and not 1 <= duration <= 30:
        raise ValueError("--duration must be between 1 and 30 seconds")
    result: Dict[str, Any] = {"serial": serial, "properties": {}, "layers": {}}
    props = result["properties"]
    assert isinstance(props, dict)
    for prop in PROPS:
        _rc, value = device_shell(adb, serial, "getprop %s" % prop)
        props[prop] = value.splitlines()[-1].strip() if value else ""

    shell_rc, shell_id = device_shell(adb, serial, "id")
    root_rc, root_id = device_shell(adb, serial, "id", root=True)
    shell_root = shell_rc == 0 and "uid=0" in shell_id
    has_root = shell_root or (root_rc == 0 and "uid=0" in root_id)
    use_su = has_root and not shell_root
    result["shell_id"] = shell_id
    result["root_id"] = root_id
    result["root"] = has_root
    kernel_rc, kernel = device_shell(adb, serial, "uname -a")
    result["kernel"] = {"exit_code": kernel_rc, "uname": kernel}

    _rc, events = device_shell(adb, serial,
                               "ls -1 /sys/bus/event_source/devices 2>/dev/null",
                               root=use_su)
    _rc, coresight = device_shell(adb, serial,
                                  "ls -1 /sys/bus/coresight/devices 2>/dev/null",
                                  root=use_su)
    list_rc, simpleperf = device_shell(adb, serial,
                                       "/system/bin/simpleperf list 2>&1",
                                       root=use_su)
    status_rc, source_status = device_shell(
        adb, serial,
        "echo DRIVERS; ls -1 /sys/bus/coresight/drivers 2>&1; "
        "for d in /sys/bus/coresight/devices/*; do "
        "[ -e \"$d\" ] || continue; "
        "echo SOURCE:$d; echo DRIVER; readlink \"$d/driver\" 2>&1; "
        "if [ -r \"$d/enable_source\" ]; then "
        "echo ENABLE_SOURCE; cat \"$d/enable_source\" 2>&1; fi; done",
        root=use_su)
    result["ete_source_driver_status"] = {
        "exit_code": status_rc, "output": source_status,
        "meaning": "Read-only CoreSight driver links and source enable state; "
                   "ETE/ETM names are hints, not proof of recording or decode.",
    }
    result["simpleperf_list_exit_code"] = list_rc
    result["simpleperf_list_as_root"] = has_root
    _rc, cs_attrs = device_shell(
        adb, serial,
        "ls -1 /sys/bus/event_source/devices/cs_etm 2>/dev/null; "
        "echo TYPE; cat /sys/bus/event_source/devices/cs_etm/type 2>&1; "
        "echo CPUMASK; cat /sys/bus/event_source/devices/cs_etm/cpumask 2>&1",
        root=use_su)
    _rc, perf_paranoid = device_shell(
        adb, serial, "cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null",
        root=use_su)

    events_list = lines(events)
    coresight_list = lines(coresight)
    result["event_sources"] = events_list
    result["coresight_devices"] = coresight_list
    result["simpleperf_trace_lines"] = [
        x for x in lines(simpleperf)
        if contains_any(x, ("cs-etm", "etm", "ete", "spe", "brbe", "coresight"))
    ]
    result["cs_etm_attributes"] = cs_attrs
    result["perf_event_paranoid"] = perf_paranoid

    layers = result["layers"]
    assert isinstance(layers, dict)
    hardware_hint = contains_any(
        "\n".join(coresight_list) + "\n" + source_status,
        ("ete", "etm")) or "cs_etm" in events_list
    kernel_interface = "cs_etm" in events_list and bool(coresight_list)
    recorder_event = list_rc == 0 and any(
        x.startswith("cs-etm") for x in result["simpleperf_trace_lines"])
    layers["hardware_hint"] = "present" if hardware_hint else "not_observed"
    layers["kernel_interface"] = "exposed" if kernel_interface else "not_observed"
    layers["recorder_event"] = "listed" if recorder_event else "not_listed"
    layers["trace_smoke"] = "not_run"
    layers["full_instruction_decode"] = "unverified"

    if smoke:
        smoke_result = smoke_record(adb, serial, use_su, duration, aux_size)
        result["smoke"] = smoke_result
        layers["trace_smoke"] = "recorded" if smoke_result["recorded"] else "failed"

    # The probe is useful even when a vendor kernel exposes names but cannot
    # create an ETM event. Keep the verdict explicit and conservative.
    if smoke and (layers["trace_smoke"] != "recorded" or not result["smoke"]["cleaned"]):
        result["verdict"] = "record_failed"
    elif layers["trace_smoke"] == "recorded":
        result["verdict"] = "trace_recorded"
    elif recorder_event:
        result["verdict"] = "recorder_listed_not_tested"
    elif hardware_hint or kernel_interface:
        result["verdict"] = "interface_visible_but_not_recorded"
    else:
        result["verdict"] = "not_observed"
    return result


def print_human(data: Dict[str, Any]) -> None:
    props = data.get("properties", {})
    layers = data.get("layers", {})
    print("device=%s" % data.get("serial", "?"))
    if isinstance(props, dict):
        for key in ("ro.product.model", "ro.product.device", "ro.soc.model",
                    "ro.build.version.release", "ro.product.cpu.abi",
                    "ro.boot.flash.locked", "ro.boot.verifiedbootstate"):
            print("  %-28s %s" % (key, props.get(key, "")))
    print("root=%s" % ("yes" if data.get("root") else "no"))
    kernel = data.get("kernel", {})
    if isinstance(kernel, dict):
        print("kernel=%s" % kernel.get("uname", ""))
    status = data.get("ete_source_driver_status", {})
    if isinstance(status, dict):
        print("ETE/CoreSight source and driver status (read-only):")
        print(status.get("output", ""))
    print("layers:")
    if isinstance(layers, dict):
        for key in ("hardware_hint", "kernel_interface", "recorder_event", "trace_smoke",
                    "full_instruction_decode"):
            print("  %-20s %s" % (key, layers.get(key, "")))
    print("verdict=%s" % data.get("verdict"))
    trace_lines = data.get("simpleperf_trace_lines", [])
    if trace_lines:
        print("simpleperf trace-related lines:")
        for line in trace_lines:
            print("  %s" % line)
    if data.get("smoke"):
        smoke = data["smoke"]
        if isinstance(smoke, dict):
            print("smoke output: %s" % smoke.get("output", ""))
            print("smoke file bytes=%s AUXTRACE=%s cleaned=%s" % (
                smoke.get("file_size_bytes"), smoke.get("auxtrace_structure"),
                smoke.get("cleaned")))
    print("meaning: a visible cs_etm/CoreSight node is not proof that a trace can be recorded;")
    print("         a successful smoke test verifies AUXTRACE recording structure only.")
    print("         full instruction decode remains unverified.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    ap.add_argument("--serial", default=None)
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--expect-root", action="store_true")
    ap.add_argument("--smoke-test", action="store_true",
                    help="record a short cs-etm:u ls workload and remove its trace")
    ap.add_argument("--duration", type=int, default=None,
                    help="optional recording limit in seconds (1-30); workload exits earlier")
    ap.add_argument("--aux-buffer-size", default="1048576",
                    help="positive bytes or K/M/G suffix (maximum 1 GiB)")
    args = ap.parse_args()
    if args.duration is not None and not 1 <= args.duration <= 30:
        ap.error("--duration must be between 1 and 30 seconds")
    try:
        args.aux_buffer_size = validate_aux_size(args.aux_buffer_size)
    except ValueError as exc:
        ap.error(str(exc))
    if shutil.which(args.adb) is None and not os.path.exists(args.adb):
        print("adb not found: %s" % args.adb, file=sys.stderr)
        return 2
    try:
        serial, _devices = choose_device(args.adb, args.serial)
        data = probe(args.adb, serial, args.smoke_test, args.duration,
                     args.aux_buffer_size)
    except RuntimeError as exc:
        print("BLOCKED: %s" % exc, file=sys.stderr)
        return 2
    if args.expect_root and not data.get("root"):
        print("BLOCKED: root shell was not available", file=sys.stderr)
        return 1
    if args.as_json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print_human(data)
    if args.smoke_test:
        smoke_data = data.get("smoke", {})
        if data.get("verdict") == "record_failed" or not smoke_data.get("cleaned"):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
