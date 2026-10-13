#!/usr/bin/env python3
"""capability: device_hw_trace
Decode an ID-aligned socrates ETE copy with device OpenCSD; never claim a full path.
Use --trace --out-dir --serial; --module additionally requires capture-time maps,
manifest and exact ELF bytes. See references/ete-decoding.md for limits.
"""
from pathlib import Path
import runpy
import sys


def main():
    backend = Path(__file__).resolve().parents[1] / "assets" / "ete" / "socrates-5.15.41" / "decode"
    sys.path.insert(0, str(backend))
    runpy.run_path(str(backend / "ete_decode.py"), run_name="__main__")


if __name__ == "__main__":
    main()
