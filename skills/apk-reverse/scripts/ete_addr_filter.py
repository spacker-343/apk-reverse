#!/usr/bin/env python3
"""capability: static_native
Plan explicit ETE file filters from hashed ELF/maps, avoiding the socrates VMA-end bug.
Read-only; cropped boundary bytes are reported. Use --help for inputs.
"""
from pathlib import Path
import runpy
import sys


def main():
    backend = Path(__file__).resolve().parents[1] / "assets" / "ete" / "socrates-5.15.41" / "decode"
    sys.path.insert(0, str(backend))
    runpy.run_path(str(backend / "ete_addr_filter.py"), run_name="__main__")


if __name__ == "__main__":
    main()
