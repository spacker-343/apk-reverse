#!/usr/bin/env python3
"""capability: device_hw_probe
Verify or explicitly reload the bundled, exact-kernel socrates ETE source module.
Default: read-only device status. --verify-only: host assets only. --load: device writes.
No flashing, autoload configuration, SELinux changes, force-loading or tracing.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys

from device_hw_probe import choose_device, device_shell, run, adb_cmd

ASSETS = Path(__file__).resolve().parents[1] / "assets" / "ete" / "socrates-5.15.41"
REMOTE = "/data/local/tmp/coresight-etm4x.ko"
STATUS_COMMAND = """set -e
printf 'INITSTATE='; cat /sys/module/coresight_etm4x/initstate
printf 'BOOT_ENABLE='; cat /sys/module/coresight_etm4x/parameters/boot_enable
printf 'PM_SAVE_ENABLE='; cat /sys/module/coresight_etm4x/parameters/pm_save_enable
for n in 0 1 2 3 4 5 6 7; do
  d=/sys/bus/coresight/devices/coresight-ete$n
  test -d "$d"
  test -e /sys/bus/platform/drivers/coresight-etm4x/soc:ete$n
  printf 'SOURCE%s=' "$n"; cat "$d/enable_source"
done
"""


def verify_assets(directory=ASSETS):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    path = directory / manifest["module"]
    blob = path.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if len(blob) != manifest["module_bytes"] or digest != manifest["module_sha256"]:
        raise RuntimeError("bundled module size/hash mismatch; do not load")
    if blob[:6] != b"\x7fELF\x02\x01" or int.from_bytes(blob[18:20], "little") != 183:
        raise RuntimeError("bundled module is not a little-endian AArch64 ELF64")
    if (manifest["kernel"] + " SMP preempt mod_unload modversions aarch64").encode() not in blob:
        raise RuntimeError("bundled module vermagic does not match manifest")
    return manifest, path


def checked_shell(adb, serial, command, root=True):
    rc, output = device_shell(adb, serial, command, root=root, timeout=30)
    if rc:
        raise RuntimeError("device command failed (rc=%d): %s\n%s" % (rc, command, output))
    return output.strip()


def inspect_device(adb, serial, manifest):
    ident = checked_shell(adb, serial, "id")
    if not re.search(r"\buid=0\b", ident):
        raise RuntimeError("root shell not available")
    facts = {}
    for name, command in (("device", "getprop ro.product.device"),
                          ("kernel", "uname -r"),
                          ("fingerprint", "getprop ro.build.fingerprint"),
                          ("selinux", "getenforce")):
        facts[name] = checked_shell(adb, serial, command)
    for name in ("device", "kernel", "fingerprint"):
        if facts[name] != manifest[name]:
            raise RuntimeError("%s mismatch: expected %s, got %s; revalidate ABI, do not reuse" %
                               (name, manifest[name], facts[name]))
    if facts["selinux"] != "Enforcing":
        raise RuntimeError("recorded baseline requires SELinux Enforcing; this tool never changes it")
    modules = checked_shell(adb, serial, "cat /proc/modules")
    if not re.search(r"^coresight\s.*\bLive\b", modules, re.M):
        raise RuntimeError("stock coresight dependency is not Live")
    facts["loaded"] = bool(re.search(r"^coresight_etm4x\s.*\bLive\b", modules, re.M))
    if not facts["loaded"] and re.search(r"^coresight_etm4x\s", modules, re.M):
        raise RuntimeError("ETM4x is present but not Live; do not repeat insmod")
    return facts


def verify_loaded(adb, serial):
    output = checked_shell(adb, serial, STATUS_COMMAND)
    values = dict(re.findall(r"^(INITSTATE|BOOT_ENABLE|PM_SAVE_ENABLE|SOURCE[0-7])=(\S+)$",
                             output, re.M))
    if values.get("INITSTATE", "").lower() != "live":
        raise RuntimeError("loaded module is not live")
    if values.get("BOOT_ENABLE") != "0" or values.get("PM_SAVE_ENABLE") != "1":
        raise RuntimeError("loaded parameters differ from recorded baseline; do not unload automatically")
    sources = [values.get("SOURCE%d" % n) for n in range(8)]
    if any(value not in ("0", "1") for value in sources):
        raise RuntimeError("missing/invalid ETE source status")
    return {"source_enable": sources, "idle": all(value == "0" for value in sources),
            "boot_enable": 0, "pm_save_enable": 1}


def ensure_module(adb, serial, manifest, path, load=False):
    facts = inspect_device(adb, serial, manifest)
    facts["action"] = "read_only"
    if facts["loaded"]:
        facts.update(verify_loaded(adb, serial))
        return facts
    if not load:
        facts["state"] = "not_loaded_after_boot; use --load only on matching baseline"
        return facts
    if checked_shell(adb, serial, "cat /proc/sys/kernel/modules_disabled") != "0":
        raise RuntimeError("kernel module loading disabled")
    # No arbitrary shell paths, force flags, partition writes or boot policy changes.
    rc, output = run(adb_cmd(adb, serial, "push", str(path), REMOTE), timeout=30)
    if rc:
        raise RuntimeError("adb push failed: %s" % output)
    digest = checked_shell(adb, serial, "sha256sum %s" % shlex.quote(REMOTE)).split()[0]
    if digest.lower() != manifest["module_sha256"]:
        raise RuntimeError("device module hash mismatch; refusing insmod")
    checked_shell(adb, serial, "chmod 600 %s" % shlex.quote(REMOTE))
    # Re-check identity/state immediately before loading, including races with other loaders.
    facts = inspect_device(adb, serial, manifest)
    if not facts["loaded"]:
        checked_shell(adb, serial, "insmod %s boot_enable=0 pm_save_enable=1" % shlex.quote(REMOTE))
        facts = inspect_device(adb, serial, manifest)
        if not facts["loaded"]:
            raise RuntimeError("insmod returned but module is not Live; inspect dmesg")
        facts["action"] = "loaded"
    else:
        facts["action"] = "already_loaded"
    facts.update(verify_loaded(adb, serial))
    return facts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default=os.environ.get("ADB", "adb"))
    parser.add_argument("--serial")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--verify-only", action="store_true", help="verify bundled binary without a device")
    group.add_argument("--load", action="store_true", help="explicitly push and insmod after baseline/hash checks")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        manifest, path = verify_assets()
        data = {"asset_verified": True, "module_sha256": manifest["module_sha256"],
                "decode_verified": False, "autoload_configured_by_tool": False}
        if not args.verify_only:
            if not shutil.which(args.adb) and not Path(args.adb).is_file():
                raise RuntimeError("adb not found; use --adb or ADB")
            serial, _ = choose_device(args.adb, args.serial)
            data.update(ensure_module(args.adb, serial, manifest, path, args.load))
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return 0
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print("BLOCKED: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
