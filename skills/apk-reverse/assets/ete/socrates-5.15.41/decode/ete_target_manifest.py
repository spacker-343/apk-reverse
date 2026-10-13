#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a reproducible target-ELF manifest for the ETE workstream.

Extracts named ELF entries out of an APK into this workstream's own directory,
then records the identity this route needs before any address from a trace is
trusted:

  * SHA-256 of the extracted ELF (the only thing that ties a trace address to a
    disassembly),
  * ELF class / machine / type / entry,
  * every PT_LOAD (offset, vaddr, filesz, memsz, flags, align),
  * NT_GNU_BUILD_ID when present,
  * the APK entry CRC32 + size + compression method, so an on-device file can be
    compared without pulling 120 MB.

It never writes into the APK and never touches the device. Anything it cannot
determine is recorded as null plus a reason -- the manifest is allowed to say
"unknown", it is not allowed to guess.

Usage:
  python ete_target_manifest.py --apk path/to/base.apk \
      --entry lib/arm64-v8a/libfoo.so \
      --out-dir work/ete/manifests
  python ete_target_manifest.py --elf path/to/already-extracted.so --json
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zipfile

PT_LOAD = 1
PT_NOTE = 4
NT_GNU_BUILD_ID = 4

MACHINE = {0x03: "x86", 0x28: "arm", 0x3E: "x86_64", 0xB7: "aarch64"}
ETYPE = {1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN"}


class ElfError(ValueError):
    """Raised when the bytes are not an ELF we can reason about."""


def parse_elf(data: bytes) -> dict:
    """Parse just the ELF identity fields this route needs (no section walk)."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise ElfError("unsupported ELF class %r" % ei_class)
    if ei_data not in (1, 2):
        raise ElfError("unsupported ELF endianness %r" % ei_data)
    end = "<" if ei_data == 1 else ">"
    if ei_class == 2:
        (e_type, machine, _ver, entry, phoff, _shoff, _flags, _ehsize,
         phentsize, phnum, _shentsize, _shnum, _shstrndx) = struct.unpack_from(
            end + "HHIQQQIHHHHHH", data, 16)
        ph_fmt = end + "IIQQQQQQ"
    else:
        (e_type, machine, _ver, entry, phoff, _shoff, _flags, _ehsize,
         phentsize, phnum, _shentsize, _shnum, _shstrndx) = struct.unpack_from(
            end + "HHIIIIIHHHHHH", data, 16)
        ph_fmt = end + "IIIIIIII"
    if phentsize < struct.calcsize(ph_fmt):
        raise ElfError("program header entry size %d too small" % phentsize)

    loads, notes = [], []
    for i in range(phnum):
        off = phoff + i * phentsize
        f = struct.unpack_from(ph_fmt, data, off)
        if ei_class == 2:
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_align = f
        else:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, p_align = f
        if p_type == PT_LOAD:
            loads.append({"index": i, "flags": p_flags, "offset": p_offset,
                          "vaddr": p_vaddr, "filesz": p_filesz,
                          "memsz": p_memsz, "align": p_align})
        elif p_type == PT_NOTE:
            notes.append((p_offset, p_filesz))

    if not loads:
        raise ElfError("no PT_LOAD segment -- this is not a loadable module")
    return {
        "elf_class": 64 if ei_class == 2 else 32,
        "endianness": "little" if ei_data == 1 else "big",
        "e_type": ETYPE.get(e_type, e_type),
        "machine": MACHINE.get(machine, "0x%x" % machine),
        "machine_raw": machine,
        "entry": entry,
        "pt_load": loads,
        "build_id": build_id_from_notes(data, notes, end),
    }


def build_id_from_notes(data: bytes, notes, end: str):
    """Return NT_GNU_BUILD_ID as hex, or None. Never a plausible substitute."""
    for offset, size in notes:
        pos = offset
        end_pos = offset + size
        while pos + 12 <= end_pos:
            namesz, descsz, ntype = struct.unpack_from(end + "III", data, pos)
            pos += 12
            name = data[pos:pos + namesz]
            pos += (namesz + 3) & ~3
            desc = data[pos:pos + descsz]
            pos += (descsz + 3) & ~3
            if pos > end_pos:
                return None          # truncated note table
            if ntype == NT_GNU_BUILD_ID and name.startswith(b"GNU"):
                return desc.hex()
    return None


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest_from_bytes(data: bytes, source: dict) -> dict:
    info = parse_elf(data)
    out = {"source": source, "size_bytes": len(data),
           "sha256": hashlib.sha256(data).hexdigest()}
    out.update(info)
    lowest = min(l["vaddr"] for l in info["pt_load"])
    out["lowest_pt_load_vaddr"] = lowest
    out["bss_tail_segments"] = [l["index"] for l in info["pt_load"]
                               if l["memsz"] > l["filesz"]]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--apk", help="APK to read entries from (opened read-only)")
    src.add_argument("--elf", help="an already extracted ELF file")
    ap.add_argument("--entry", action="append", default=[],
                    help="APK entry to extract (repeatable)")
    ap.add_argument("--out-dir", default=None,
                    help="where to write extracted ELFs and the manifest JSON")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    manifests = []
    if args.elf:
        with open(args.elf, "rb") as fh:
            data = fh.read()
        manifests.append(manifest_from_bytes(data, {
            "kind": "file", "path": os.path.abspath(args.elf),
            "file_sha256": sha256_file(args.elf)}))
    else:
        if not args.entry:
            print("ERROR: --apk needs at least one --entry", file=sys.stderr)
            return 2
        # a basename collision only matters when the bytes are actually written
        # into one directory: without --out-dir nothing is extracted and two ABIs
        # in one manifest are legitimate. Refuse before writing anything, so a
        # rejected run leaves no half-extracted directory behind.
        if args.out_dir:
            claimed = {}
            for name in args.entry:
                base = os.path.basename(name)
                if base in claimed:
                    print("ERROR: two entries share the file name %s (%s and %s). "
                          "Extract one ABI per --out-dir so no manifest entry can "
                          "point at another entry's bytes."
                          % (base, claimed[base], name), file=sys.stderr)
                    return 2
                claimed[base] = name
        apk_sha = sha256_file(args.apk)   # once: it cannot change while reading
        with zipfile.ZipFile(args.apk) as zf:     # read-only, always closed
            written = {}      # out_path -> entry that claimed it, this run only
            for name in args.entry:
                try:
                    data = zf.read(name)
                except KeyError:
                    print("ERROR: entry not in APK: %s" % name, file=sys.stderr)
                    return 2
                zi = zf.getinfo(name)
                out_path = None
                if args.out_dir:
                    os.makedirs(args.out_dir, exist_ok=True)
                    out_path = os.path.join(args.out_dir, os.path.basename(name))
                    # two APK entries can share a basename (arm64-v8a and
                    # armeabi-v7a each carrying libfoo.so). Writing one over the
                    # other would leave a manifest whose second entry points at
                    # bytes it never wrote -- the exact ARM32/ARM64 mix this
                    # route must never produce, so the run is refused instead.
                    if out_path in written:
                        print("ERROR: two entries share the file name %s (%s and "
                              "%s). Extract one ABI per --out-dir so no manifest "
                              "entry can point at another entry's bytes."
                              % (os.path.basename(name), written[out_path], name),
                              file=sys.stderr)
                        return 2
                    written[out_path] = name
                    # a re-run must not silently replace the bytes an earlier
                    # manifest describes: overwriting libfoo.so with a different
                    # ABI's copy leaves an archive whose ELF no longer matches the
                    # manifest that is still on disk next to it. Identical bytes
                    # are fine, so a reproducible re-run stays a re-run.
                    if os.path.exists(out_path):
                        on_disk = sha256_file(out_path)
                        incoming = hashlib.sha256(data).hexdigest()
                        if on_disk != incoming:
                            print("ERROR: %s already holds different bytes "
                                  "(on disk %s, this entry %s). Extract into a "
                                  "fresh --out-dir rather than overwriting the "
                                  "ELF an earlier manifest describes."
                                  % (out_path, on_disk[:16], incoming[:16]),
                                  file=sys.stderr)
                            return 2
                    with open(out_path, "wb") as fh:
                        fh.write(data)
                src = {"kind": "apk-entry", "apk": os.path.abspath(args.apk),
                       "apk_sha256": apk_sha, "entry": name,
                       "entry_crc32": "%08x" % zi.CRC,
                       "entry_compress_type": zi.compress_type,
                       "entry_size": zi.file_size,
                       "extracted_to": os.path.abspath(out_path) if out_path else None}
                manifests.append(manifest_from_bytes(data, src))

    doc = {"schema": "ete-target-manifest/1", "targets": manifests}
    if args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        with open(os.path.join(args.out_dir, "target-manifest.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, sort_keys=True)
    if args.as_json:
        print(json.dumps(doc, indent=2, sort_keys=True))
        return 0
    for m in manifests:
        src = m["source"]
        print("entry/elf      : %s" % src.get("entry") or src.get("path"))
        print("size / sha256  : %d / %s" % (m["size_bytes"], m["sha256"]))
        print("class/machine  : %db %s %s" % (m["elf_class"], m["machine"],
                                              m["e_type"]))
        print("build id       : %s" % (m["build_id"] or "NONE-RECORDED"))
        print("PT_LOAD        :")
        for l in m["pt_load"]:
            print("   [%d] off=0x%x vaddr=0x%x filesz=0x%x memsz=0x%x flags=0x%x"
                  % (l["index"], l["offset"], l["vaddr"], l["filesz"],
                     l["memsz"], l["flags"]))
        if m["bss_tail_segments"]:
            print("   BSS tail in segments %s -- file bytes do not exist there"
                  % m["bss_tail_segments"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
