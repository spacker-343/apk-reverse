#!/usr/bin/env python3
"""Generate a separate perf core source copy; never install or modify a kernel.

Only the recorded byte-identical MiCode/stock ACK core.c is accepted. An unexpected source
needs a separate review, not a --force switch. Output must be a new regular file.
"""
import argparse
import hashlib
from pathlib import Path
import sys

SOURCE_SHA256 = "19999bbbf7b9b651e84d33a044c292527c775d38a3659b8b888afeef80ab17b9"
FUNCTION_SHA256 = "d81fc7748429af1789ac0ebb676823a0b2b82b2635a8593c3653c4f9bca10ca6"
BEGIN = b"static bool perf_addr_filter_match("
END = b"\nstatic bool perf_addr_filter_vma_adjust("


def generate(source):
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise ValueError("unexpected core.c SHA-256; review the source instead of forcing")
    if source.count(BEGIN) != 1 or source.count(END) != 1:
        raise ValueError("unexpected function anchors")
    start = source.index(BEGIN)
    end = source.index(END, start)
    if hashlib.sha256(source[start:end]).hexdigest() != FUNCTION_SHA256:
        raise ValueError("unexpected original function")
    fragment = Path(__file__).with_name("perf_addr_filter_match.c").read_bytes()
    replacement = fragment[fragment.index(BEGIN):]
    return source[:start] + replacement + source[end:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="original kernel/events/core.c")
    parser.add_argument("--output", required=True, type=Path, help="new core.c in a build copy")
    args = parser.parse_args()
    try:
        if args.source.resolve() == args.output.resolve():
            raise ValueError("input is read-only; output must be a separate file")
        original = args.source.read_bytes()
        fixed = generate(original)
        with args.output.open("xb") as handle:
            handle.write(fixed)
        print("SOURCE_SHA256=" + hashlib.sha256(original).hexdigest())
        print("OUTPUT_SHA256=" + hashlib.sha256(fixed).hexdigest())
    except (OSError, ValueError) as exc:
        print("RESULT=unavailable: " + str(exc), file=sys.stderr)
        return 2
    print("RESULT=source_generated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
