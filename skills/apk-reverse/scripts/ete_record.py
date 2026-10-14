#!/usr/bin/env python3
"""capability: device_hw_trace
Record bounded socrates ETE data with final hardware disable before reader shutdown.
Requires an explicit serial, existing TID and loaded ETE sources; never autoloads.
"""
from pathlib import Path
import runpy
import sys


def main():
    backend = Path(__file__).resolve().parents[1] / "assets" / "ete" / "socrates-5.15.41" / "decode"
    sys.path.insert(0, str(backend))
    runpy.run_path(str(backend / "ete_record.py"), run_name="__main__")


if __name__ == "__main__":
    main()
