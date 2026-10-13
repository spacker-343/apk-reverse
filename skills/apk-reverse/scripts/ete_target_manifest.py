#!/usr/bin/env python3
"""capability: static_native
Record exact ELF identity and PT_LOAD coordinates before trusting ETE addresses.
Use --elf or --apk with --entry; this does not edit the APK or contact a device.
"""
from pathlib import Path
import runpy
import sys


def main():
    backend = Path(__file__).resolve().parents[1] / "assets" / "ete" / "socrates-5.15.41" / "decode"
    sys.path.insert(0, str(backend))
    runpy.run_path(str(backend / "ete_target_manifest.py"), run_name="__main__")


if __name__ == "__main__":
    main()
