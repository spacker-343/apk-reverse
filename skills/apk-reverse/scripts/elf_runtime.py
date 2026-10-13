#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""capability: static_native
Map Android PIE/shared-library runtime addresses to ELF file offsets.

A tombstone PC is a process address. A disassembler usually needs a file
offset or a link-time virtual address. For a PT_LOAD segment the relationship
is:

    file_offset = p_offset + (runtime_pc - load_bias - p_vaddr)

This script checks the segment bounds before applying that formula. It does
not guess from the first mapping line and it does not modify the ELF.

Usage:
  python elf_runtime.py libfoo.so --runtime-address 0x7abc123456
  python elf_runtime.py libfoo.so --runtime-address 0x7abc123456 --load-bias 0x7abc000000
  python elf_runtime.py libfoo.so --file-offset 0x1234
  python elf_runtime.py app-pie --runtime-address 0x7000123456 --load-bias 0x7000000000 --json
"""

import argparse
import json
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple


PT_LOAD = 1
ET_DYN = 3
ET_EXEC = 2


def number(text: str) -> int:
    return int(text, 0)


def unpack(fmt: str, data: bytes, offset: int) -> Tuple[Any, ...]:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ValueError("ELF header/table is truncated at 0x%x" % offset)
    return struct.unpack_from(fmt, data, offset)


def parse_elf(data: bytes) -> Dict[str, Any]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    elf_class = data[4]
    endian = "<" if data[5] == 1 else ">" if data[5] == 2 else ""
    if not endian:
        raise ValueError("unsupported ELF byte order")
    if elf_class == 2:
        hdr = unpack(endian + "16sHHIQQQIHHHHHH", data, 0)
        _ident, e_type, machine, _version, entry, phoff, _shoff, _flags, _ehsize, phentsize, phnum, *_ = hdr
        ph_fmt = endian + "IIQQQQQQ"
    elif elf_class == 1:
        hdr = unpack(endian + "16sHHIIIIIHHHHHH", data, 0)
        _ident, e_type, machine, _version, entry, phoff, _shoff, _flags, _ehsize, phentsize, phnum, *_ = hdr
        ph_fmt = endian + "IIIIIIII"
    else:
        raise ValueError("unsupported ELF class: %r" % elf_class)

    segments: List[Dict[str, int]] = []
    for index in range(phnum):
        off = phoff + index * phentsize
        fields = unpack(ph_fmt, data, off)
        if elf_class == 2:
            p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_align = fields
        else:
            p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz, p_flags, p_align = fields
        if p_type == PT_LOAD:
            segments.append({"index": index, "flags": p_flags,
                             "offset": p_offset, "vaddr": p_vaddr,
                             "filesz": p_filesz, "memsz": p_memsz,
                             "align": p_align})
    return {"class": 64 if elf_class == 2 else 32,
            "endian": "little" if endian == "<" else "big",
            "type": e_type, "machine": machine, "entry": entry,
            "segments": segments}


def find_segment_for_runtime(segments: List[Dict[str, int]], runtime: int,
                             load_bias: int) -> Optional[Dict[str, int]]:
    link_vaddr = runtime - load_bias
    for seg in segments:
        if seg["vaddr"] <= link_vaddr < seg["vaddr"] + seg["memsz"]:
            return seg
    return None


def find_segment_for_file(segments: List[Dict[str, int]], file_offset: int) -> Optional[Dict[str, int]]:
    for seg in segments:
        if seg["offset"] <= file_offset < seg["offset"] + seg["filesz"]:
            return seg
    return None


def result_for_runtime(info: Dict[str, Any], runtime: int, load_bias: int) -> Dict[str, Any]:
    segments = info["segments"]
    assert isinstance(segments, list)
    seg = find_segment_for_runtime(segments, runtime, load_bias)
    out: Dict[str, Any] = {"kind": "runtime-address", "runtime_address": hex(runtime),
                           "load_bias": hex(load_bias)}
    if seg is None:
        out["mapped"] = False
        out["reason"] = "address is outside every PT_LOAD memory range"
        return out
    link_vaddr = runtime - load_bias
    delta = link_vaddr - seg["vaddr"]
    out.update({"mapped": delta < seg["filesz"], "link_vaddr": hex(link_vaddr),
                "file_offset": hex(seg["offset"] + delta),
                "segment": seg})
    if delta >= seg["filesz"]:
        out["reason"] = "address is in zero-filled BSS tail; no file byte exists"
    return out


def result_for_file(info: Dict[str, Any], file_offset: int) -> Dict[str, Any]:
    segments = info["segments"]
    assert isinstance(segments, list)
    seg = find_segment_for_file(segments, file_offset)
    out: Dict[str, Any] = {"kind": "file-offset", "file_offset": hex(file_offset)}
    if seg is None:
        out["mapped"] = False
        out["reason"] = "offset is outside every PT_LOAD file range"
        return out
    delta = file_offset - seg["offset"]
    out.update({"mapped": True, "link_vaddr": hex(seg["vaddr"] + delta),
                "segment": seg})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("elf", help="local PIE executable or shared-library ELF")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--runtime-address", type=number,
                       help="process address from a tombstone or trace")
    group.add_argument("--file-offset", type=number,
                       help="file offset to map back to a link-time address")
    ap.add_argument("--load-bias", type=number, default=0,
                    help="runtime mapping base minus ELF p_vaddr base (default: 0)")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()
    try:
        with open(args.elf, "rb") as fh:
            info = parse_elf(fh.read())
        if args.runtime_address is not None:
            answer = result_for_runtime(info, args.runtime_address, args.load_bias)
        else:
            answer = result_for_file(info, args.file_offset)
        answer["elf"] = args.elf
        answer["elf_class"] = info["class"]
        answer["elf_type"] = {ET_DYN: "ET_DYN", ET_EXEC: "ET_EXEC"}.get(info["type"], info["type"])
        answer["machine"] = info["machine"]
    except (OSError, ValueError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 2
    if args.as_json:
        print(json.dumps(answer, indent=2))
    else:
        print("elf=%s class=%db type=%s machine=%s" %
              (answer["elf"], answer["elf_class"], answer["elf_type"], answer["machine"]))
        print("kind=%s mapped=%s" % (answer["kind"], answer["mapped"]))
        for key in ("runtime_address", "load_bias", "link_vaddr", "file_offset", "reason"):
            if key in answer:
                print("  %-18s %s" % (key, answer[key]))
        if not answer["mapped"]:
            print("next: check the live /proc/<pid>/maps line and use its mapping base as load bias")
    return 0 if answer["mapped"] else 1


if __name__ == "__main__":
    sys.exit(main())
