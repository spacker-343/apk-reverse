#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""capability: device_hw_probe
Read-only ARM hardware-tracing capability probe for an Android device.

This script deliberately reports four separate layers instead of saying
"ETE supported" from one sysfs directory:

  hardware_hint -> kernel_interface -> recorder_event -> trace_smoke

The default probe does not write to the device. ``--smoke-test`` performs a
bounded cs-etm recording in /data/local/tmp and removes the file afterwards.
It is still an observation, not a patch or a bypass.

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
import time
from typing import Dict, List, Optional, Tuple


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
    # Commands are constants from this file, not user-provided shell text.
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


def probe(adb: str, serial: str, smoke: bool, duration: int,
          aux_size: str) -> Dict[str, object]:
    result: Dict[str, object] = {"serial": serial, "properties": {}, "layers": {}}
    props = result["properties"]
    assert isinstance(props, dict)
    for prop in PROPS:
        _rc, value = device_shell(adb, serial, "getprop %s" % prop)
        props[prop] = value.splitlines()[-1].strip() if value else ""

    _rc, shell_id = device_shell(adb, serial, "id")
    _root_rc, root_id = device_shell(adb, serial, "id", root=True)
    has_root = "uid=0" in root_id
    result["shell_id"] = shell_id
    result["root_id"] = root_id
    result["root"] = has_root

    _rc, events = device_shell(adb, serial,
                               "ls -1 /sys/bus/event_source/devices 2>/dev/null")
    _rc, coresight = device_shell(adb, serial,
                                  "ls -1 /sys/bus/coresight/devices 2>/dev/null")
    _rc, simpleperf = device_shell(adb, serial,
                                   "/system/bin/simpleperf list 2>/dev/null")
    _rc, cs_attrs = device_shell(
        adb, serial,
        "ls -1 /sys/bus/event_source/devices/cs_etm 2>/dev/null; "
        "echo TYPE; cat /sys/bus/event_source/devices/cs_etm/type 2>&1; "
        "echo CPUMASK; cat /sys/bus/event_source/devices/cs_etm/cpumask 2>&1",
        root=has_root)
    _rc, perf_paranoid = device_shell(
        adb, serial, "cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null",
        root=has_root)

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
        "\n".join(coresight_list), ("ete", "etm")) or "cs_etm" in events_list
    kernel_interface = "cs_etm" in events_list and bool(coresight_list)
    recorder_event = any(x.startswith("cs-etm") for x in result["simpleperf_trace_lines"])
    layers["hardware_hint"] = "present" if hardware_hint else "not_observed"
    layers["kernel_interface"] = "exposed" if kernel_interface else "not_observed"
    layers["recorder_event"] = "listed" if recorder_event else "not_listed"
    layers["trace_smoke"] = "not_run"

    if smoke:
        remote = "/data/local/tmp/apk_reverse_cs_etm_%d.data" % int(time.time())
        command = ("/system/bin/simpleperf record -e cs-etm -a --duration %d "
                   "--aux-buffer-size %s -o %s" %
                   (duration, aux_size, remote))
        rc, output = device_shell(adb, serial, command, root=has_root,
                                  timeout=max(30, duration + 20))
        _ls_rc, ls_out = device_shell(adb, serial, "ls -l %s 2>&1" % remote,
                                      root=has_root)
        _rm_rc, _rm_out = device_shell(adb, serial, "rm -f %s" % remote,
                                       root=has_root)
        layers["trace_smoke"] = "recorded" if rc == 0 and "No such file" not in ls_out else "failed"
        result["smoke"] = {"command": command, "exit_code": rc,
                            "output": output, "file_check": ls_out,
                            "cleaned": True}

    # The probe is useful even when a vendor kernel exposes names but cannot
    # create an ETM event. Keep the verdict explicit and conservative.
    if layers["trace_smoke"] == "recorded":
        result["verdict"] = "trace_recorded"
    elif recorder_event:
        result["verdict"] = "recorder_listed_not_tested"
    elif hardware_hint or kernel_interface:
        result["verdict"] = "interface_visible_but_not_recorded"
    else:
        result["verdict"] = "not_observed"
    return result


def print_human(data: Dict[str, object]) -> None:
    props = data.get("properties", {})
    layers = data.get("layers", {})
    print("device=%s" % data.get("serial", "?"))
    if isinstance(props, dict):
        for key in ("ro.product.model", "ro.product.device", "ro.soc.model",
                    "ro.build.version.release", "ro.product.cpu.abi",
                    "ro.boot.flash.locked", "ro.boot.verifiedbootstate"):
            print("  %-28s %s" % (key, props.get(key, "")))
    print("root=%s" % ("yes" if data.get("root") else "no"))
    print("layers:")
    if isinstance(layers, dict):
        for key in ("hardware_hint", "kernel_interface", "recorder_event", "trace_smoke"):
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
    print("meaning: a visible cs_etm/CoreSight node is not proof that a trace can be recorded;")
    print("         require a successful bounded smoke test before calling ETE usable.")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    ap.add_argument("--serial", default=None)
    ap.add_argument("--json", action="store_true", dest="as_json")
    ap.add_argument("--expect-root", action="store_true")
    ap.add_argument("--smoke-test", action="store_true",
                    help="run and remove a bounded cs-etm recording")
    ap.add_argument("--duration", type=int, default=1)
    ap.add_argument("--aux-buffer-size", default="1M")
    args = ap.parse_args()
    if args.duration < 1 or args.duration > 30:
        ap.error("--duration must be between 1 and 30 seconds")
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
