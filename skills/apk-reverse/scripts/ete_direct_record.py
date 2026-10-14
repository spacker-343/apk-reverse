#!/usr/bin/env python3
"""capability: device_hw_trace
Direct bounded CPU0 ETE capture with loss-marker rejection; never a full-path claim.
"""
from pathlib import Path
import runpy
import sys


def main():
    backend = Path(__file__).resolve().parents[1] / "assets" / "ete" / "socrates-5.15.41" / "decode"
    sys.path.insert(0, str(backend))
    runpy.run_path(str(backend / "ete_direct_record.py"), run_name="__main__")


if __name__ == "__main__":
    main()
