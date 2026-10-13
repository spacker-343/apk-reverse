#!/usr/bin/env python3
"""capability: static_native
Cross-check an ETE runtime address against capture-time maps and hashed ELF bytes.
Use --help for the manifest/maps/module interface. This tool never decodes AUX.
"""
from pathlib import Path
import runpy
import sys


def main():
    backend = Path(__file__).resolve().parents[1] / "assets" / "ete" / "socrates-5.15.41" / "decode"
    sys.path.insert(0, str(backend))
    runpy.run_path(str(backend / "ete_addr_space.py"), run_name="__main__")


if __name__ == "__main__":
    main()
