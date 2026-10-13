#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resolve trace addresses into a defensible address coordinate system.

A trace/ETE address is only meaningful together with (a) the mapping that owned
it at that moment and (b) the exact ELF bytes that were mapped there. This tool
takes a captured `/proc/<pid>/maps` dump plus the target manifest produced by
ete_target_manifest.py and answers, for each runtime address:

    module-relative offset  =  link-time vaddr            (ET_DYN, base vaddr 0)
    link-time vaddr         =  runtime - start + p_vaddr + (pgoff - p_offset)
    file offset             =  p_offset + (link_vaddr - p_vaddr)

Resolution is per PT_LOAD mapping, not "first maps line minus bias": the pgoff
of the mapping is matched against the page-aligned p_offset of a PT_LOAD. The
single-bias formula is computed as a cross-check; when the two disagree the
answer is reported as NOT RESOLVED rather than averaged.

Every failure mode returns a verdict of "unclosed" with a reason. It never
invents an offset for: a library absent from maps, a basename matching several
mappings, an address outside every PT_LOAD memsz, a BSS tail (memsz > filesz),
a region that is not file-backed (JIT / anon), or a local ELF whose hash does
not match the manifest recorded for the capture.

Usage:
  python ete_addr_space.py --manifest .../target-manifest.json \
      --maps maps.txt --module libfoo.so \
      --address 0x7b1234abcd --address 0x7b12041020 --elf-dir .../targets
  python ete_addr_space.py --manifest m.json --maps maps.txt \
      --module libfoo.so --stdin-addresses < addrs.txt --json
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys

PAGE = 0x1000
EM_AARCH64 = 183             # e_machine of every library this route may decode
MAPS_RE = re.compile(
    r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+([rwxps-]{4})\s+([0-9a-fA-F]+)\s+"
    r"(\S+)\s+(\S+)\s*(.*)$")


class ResolveError(Exception):
    """A coordinate system could not be established. Message = reported reason."""


def local_elf_ident(data: bytes) -> dict:
    """EI_CLASS and e_machine straight from the bytes on disk.

    The manifest is not trusted for this: a manifest written by an earlier
    armeabi-v7a extraction would otherwise be allowed to convert an ARM64
    runtime address, which the task forbids explicitly.
    """
    if len(data) < 20 or data[:4] != b"\x7fELF":
        raise ResolveError("the file is not an ELF (no \\x7fELF magic, %d bytes)"
                           % len(data))
    ei_class = data[4]
    machine = struct.unpack_from("<H", data, 18)[0]
    return {"elf_class": 64 if ei_class == 2 else 32 if ei_class == 1 else None,
            "e_machine": machine,
            "machine": ("aarch64" if machine == EM_AARCH64
                        else "arm" if machine in (40, 0x28, 0xbf51)
                        else "0x%x" % machine),
            "data_is little_endian": data[5] == 1}


def parse_maps(text: str):
    """Parse /proc/<pid>/maps text into dicts. Unparseable lines are counted."""
    rows, unparsed = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = MAPS_RE.match(line)
        if not m:
            unparsed += 1
            continue
        start, end, perms, pgoff, _dev, _inode, path = m.groups()
        rows.append({"start": int(start, 16), "end": int(end, 16),
                     "perms": perms, "pgoff": int(pgoff, 16),
                     "path": path.strip(), "raw": line})
    return rows, unparsed


def load_bias_from_maps(rows, path: str):
    """The pgoff==0 mapping of `path`, if there is exactly one unambiguously."""
    zero = [r for r in rows if r["path"] == path and r["pgoff"] == 0]
    if len(zero) != 1:
        return None, "expected exactly one pgoff-0 mapping, found %d" % len(zero)
    return zero[0]["start"], None


def module_candidates(rows, want: str):
    """All distinct mapped paths whose basename, or full path, matches `want`."""
    out = {}
    for r in rows:
        p = r["path"]
        if not p:
            continue
        base = p.rsplit("/", 1)[-1]
        # an APK-embedded mapping is ".../base.apk!/lib/arm64-v8a/libfoo.so",
        # whose basename is already the library name
        if want in (p, base) or p.endswith("/" + want) or base == want:
            out.setdefault(p, []).append(r)
    return out


class ModuleResolver:
    """One module, one ELF, one coordinate system -- or a refusal."""

    def __init__(self, manifest: dict, rows, module: str, elf_dir=None,
                 elf_path=None, page_size=PAGE, allow_hash_skip=False):
        self.module = module
        self.rows = rows
        self.page = page_size
        cand = module_candidates(rows, module)
        if not cand:
            raise ResolveError("module %r is not present in the maps dump -- "
                               "no address may be attributed to it" % module)
        paths = sorted(cand)
        if len(paths) > 1:
            raise ResolveError(
                "module name %r matches %d distinct mappings (%s); pass the full "
                "mapped path as --module to disambiguate" % (module, len(paths),
                                                             ", ".join(paths)))
        if elf_path:
            self.elf_path = elf_path
        else:
            base = os.path.basename(paths[0].split("!/")[-1]) if "!/" in paths[0] \
                else os.path.basename(paths[0])
            self.elf_path = os.path.join(elf_dir or ".", base)

        self.mapped_paths = paths
        self.local_sha = self._sha(self.elf_path)
        with open(self.elf_path, "rb") as fh:
            self.elf_bytes = fh.read()
        # identity comes from the bytes on disk; the manifest may only confirm
        # them, never describe this file with another ABI's record
        self.local_ident = local_elf_ident(self.elf_bytes)
        target = self._match_manifest(manifest, module, self.local_sha,
                                      allow_hash_skip, self.local_ident)
        self.pt_load = target["pt_load"]
        self.manifest_sha = target.get("sha256")
        self.is_a64 = (self.local_ident["elf_class"] == 64
                       and self.local_ident["e_machine"] == EM_AARCH64)
        self.identity = {"elf_path": os.path.abspath(self.elf_path),
                         "local_sha256": self.local_sha,
                         "manifest_sha256": self.manifest_sha,
                         "elf_class": self.local_ident["elf_class"],
                         "machine": self.local_ident["machine"],
                         "manifest_elf_class": target.get("elf_class"),
                         "manifest_machine": target.get("machine"),
                         "disassembly_allowed": self.is_a64,
                         "build_id": target.get("build_id"),
                         "lowest_pt_load_vaddr": target.get("lowest_pt_load_vaddr")}
        bias, why = load_bias_from_maps(rows, paths[0])
        self.single_bias = None if bias is None else bias
        self.bias_note = why

    @staticmethod
    def _sha(path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _match_manifest(manifest, module, local_sha, allow_hash_skip,
                        local_ident=None):
        targets = manifest.get("targets", []) if isinstance(manifest, dict) else manifest
        want = os.path.basename(module)
        named = []
        for t in targets:
            src = t.get("source") or {}
            entry = src.get("entry", "") or src.get("path", "")
            if os.path.basename(entry) in (module, want):
                named.append(t)
        if not named:
            if allow_hash_skip:
                raise ResolveError("no manifest entry for %r" % module)
            raise ResolveError("the manifest records no ELF named %r -- this "
                               "capture cannot be tied to bytes" % module)
        if len(named) > 1:
            shas = {t.get("sha256") for t in named}
            if len(shas) > 1:
                raise ResolveError("manifest holds several different ELFs named "
                                   "%r (%s)" % (module, ", ".join(sorted(shas))))
        t = named[0]
        if local_ident is not None:
            for key in ("elf_class", "machine"):
                claimed = t.get(key)
                if claimed is not None and claimed != local_ident[key]:
                    raise ResolveError(
                        "the manifest entry for %r says %s=%r but the ELF on disk "
                        "is %s=%r; converting these runtime addresses with the "
                        "other ABI's program headers is the ARM32/ARM64 mix this "
                        "route forbids" % (module, key, claimed, key,
                                           local_ident[key]))
        if not allow_hash_skip and t.get("sha256") != local_sha:
            raise ResolveError(
                "local ELF %s has sha256 %s but the manifest recorded %s; the "
                "bytes behind these addresses are not the bytes being disassembled"
                % (module, local_sha, t.get("sha256")))
        return t

    def _segment_for_mapping(self, row):
        """PT_LOAD whose page-aligned p_offset equals this mapping's pgoff."""
        hits = [s for s in self.pt_load
                if (s["offset"] & ~(self.page - 1)) == row["pgoff"]]
        return hits

    def resolve(self, runtime: int) -> dict:
        out = {"runtime_address": "0x%x" % runtime, "module": self.module,
               "status": "unclosed", "reason": None}
        hits = [r for r in self.rows
                if r["path"] in self.mapped_paths and r["start"] <= runtime < r["end"]]
        if not hits:
            anon = [r for r in self.rows
                    if r["start"] <= runtime < r["end"] and not r["path"]]
            out["reason"] = ("address is not inside any mapping of this module"
                             + ("; it falls in an anonymous (non-file-backed) region "
                                "-- ETE paths through JIT/anonymous code have no ELF "
                                "coordinate" if anon else ""))
            return out
        if len(hits) > 1:
            out["reason"] = ("address falls in %d mappings of the same module; the "
                             "maps dump is inconsistent" % len(hits))
            return out
        row = hits[0]
        segs = self._segment_for_mapping(row)
        if not segs:
            out["reason"] = ("mapping at pgoff 0x%x matches no PT_LOAD p_offset of "
                             "the recorded ELF (page size assumption 0x%x)"
                             % (row["pgoff"], self.page))
            return out
        if len(segs) > 1:
            out["reason"] = ("pgoff 0x%x matches %d PT_LOAD segments; the mapping "
                             "cannot be attributed to one segment"
                             % (row["pgoff"], len(segs)))
            return out
        seg = segs[0]
        # this mapping covers file bytes [pgoff, pgoff + (end-start)) at
        # [start, end), so the file byte under `runtime` is
        #     F = pgoff + (runtime - start)
        # and the segment puts file byte F at vaddr + (F - p_offset). The
        # correction term is therefore (pgoff - p_offset), NOT the other way
        # round: p_offset is only page-aligned to pgoff, and the residue
        # (p_offset & (page-1)) can be non-zero (e.g. 0x700 or 0xea0), so a
        # flipped sign silently shifts every converted address by twice that
        # residue. The independent check below catches it; the check itself
        # only exists because the two formulas must agree byte for byte.
        link = (runtime - row["start"] + seg["vaddr"]
                + (row["pgoff"] - seg["offset"]))
        # the single-bias formula is compared before ANY refusal branch returns,
        # including the one that rejects an address for landing outside the
        # segment: a value that never met the other formula is not a verified
        # coordinate either, and the BSS-tail branch used to return its link
        # vaddr unchecked
        alt = None if self.single_bias is None else runtime - self.single_bias
        if alt is not None and alt != link:
            out["cross_check"] = "DISAGREE"
            # once the two formulas disagree neither value is trustworthy, and
            # printing them here would hand back the exact coordinates the
            # refusal rejects, so only the relative gap is reported
            out["reason"] = ("the per-segment and the single-bias conversion "
                             "differ by %d bytes; no coordinate is reported "
                             "because neither can be confirmed" % abs(alt - link))
            out["status"] = "unclosed"
            # no coordinate is popped here because none was ever written: every
            # coordinate key is added after this point. A purge list here would
            # silently swallow a future code move that wrote a coordinate before
            # the check, so the ordering itself is the guard -- and
            # test_disagreement_refusal_ships_no_coordinates,
            # test_a_bss_tail_answer_is_cross_checked_too and
            # test_an_outside_segment_refusal_is_cross_checked_before_it are the
            # tests that go red if that ordering is ever inverted.
            return out
        if not (seg["vaddr"] <= link < seg["vaddr"] + seg["memsz"]):
            # only now, with the two formulas already known to agree (or with no
            # single bias available at all), is "outside PT_LOAD" the honest
            # verdict. A rejected conversion must not ship a coordinate: the
            # value that fell out of the segment is precisely the number a
            # reader must not quote, so the refusal states the mismatch in
            # relative terms only
            seg_low, seg_high = seg["vaddr"], seg["vaddr"] + seg["memsz"]
            outside = seg_low - link if link < seg_low else link - seg_high
            out["reason"] = ("the converted link vaddr fell %d bytes outside "
                             "PT_LOAD %d, which spans %d link bytes from vaddr "
                             "%d; the mapping cannot be tied to this segment, "
                             "so no coordinate is reported"
                             % (outside, seg["index"], seg["memsz"], seg_low))
            return out
        delta = link - seg["vaddr"]
        checked = ("agree" if alt is not None
                   else "unavailable: " + (self.bias_note or "no pgoff-0 map"))
        if delta >= seg["filesz"]:
            out.update(status="unclosed", link_vaddr="0x%x" % link,
                       reason="link vaddr is in the zero-filled BSS tail of segment "
                              "%d -- no file byte exists, so no instruction exists"
                              % seg["index"],
                       cross_check=checked)
            if alt is not None:
                out["single_bias_link_vaddr"] = "0x%x" % alt
            return out
        foff = seg["offset"] + delta
        low = self.identity["lowest_pt_load_vaddr"]
        out.update(status="resolved", mapped_path=row["path"],
                   perms=row["perms"], mapping_start="0x%x" % row["start"],
                   pgoff="0x%x" % row["pgoff"], segment=seg["index"],
                   link_vaddr="0x%x" % link, file_offset="0x%08x" % foff,
                   module_relative_offset="0x%x" % (link - (low if low is not None else 0)),
                   lowest_pt_load_vaddr=None if low is None else "0x%x" % low,
                   cross_check=checked)
        if alt is not None:
            out["single_bias_link_vaddr"] = "0x%x" % alt
        return out

    def bytes_at(self, file_offset: int, size: int):
        return self.elf_bytes[file_offset:file_offset + size]

    def insn_at(self, res: dict, nbytes: int):
        """Raw bytes at a resolved address, or a refusal if not AArch64.

        Disassembling an ELF32 word as A64 produces a plausible A64 mnemonic out
        of ARM32 bytes, which is the one mix this route must never produce.
        """
        if res.get("status") != "resolved" or "file_offset" not in res:
            return None, "no file offset to read (status=%s)" % res.get("status")
        if not self.is_a64:
            return None, ("not disassembled: %s is elf_class=%s machine=%s, not "
                          "AArch64" % (self.module, self.local_ident["elf_class"],
                                        self.local_ident["machine"]))
        need = max(1, min(int(nbytes), 16))
        blob = self.bytes_at(int(res["file_offset"], 16), need)
        if len(blob) < need:
            return None, ("file holds only %d bytes at offset %s; the request was "
                          "%d" % (len(blob), res["file_offset"], need))
        return blob, None


def disassemble_a64(word: bytes):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    except Exception:
        return None
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    # capstone's Python binding spells the method disasm(); there is no
    # disassemble() in 5.x.
    for ins in md.disasm(word, 0):
        return ("%s %s" % (ins.mnemonic, ins.op_str)).strip()
    return None


def plt_stub_at(resolver, file_offset: int):
    """Does the AArch64 code at this file offset look like a PLT stub?

    An AArch64 PLT stub is exactly
        adrp x16, #page
        ldr  x17, [x16, #ofs]
        add  x16, x16, #ofs
        br   x17
    A sample may land on any word of a stub, including the final `br x17`
    or the second-word `ldr x17`, so all four positions are tried. The criterion
    itself is not loosened: the same four-word sequence, in order, still has
    to be present. This is a check on the ELF's own bytes -- it borrows no
    other tool's symbol names, so the claim "this offset is PLT, not ordinary
    code" stays locally verifiable.

    Returns the stub start offset (relative to file_offset) or None.
    """
    if not getattr(resolver, "is_a64", False):
        return None
    words = {}
    for delta in (-12, -8, -4, 0, 4, 8, 12):
        # a negative index into the ELF image would wrap to its end and mix
        # unrelated tail bytes into the four words, so a candidate that starts
        # before the first byte is not read at all
        if file_offset + delta < 0:
            continue
        blob = resolver.bytes_at(file_offset + delta, 4)
        if len(blob) < 4:
            continue
        words[delta] = disassemble_a64(blob) or ""

    def stub_at(start):
        seq = [words.get(start + d, "") for d in (0, 4, 8, 12)]
        return (seq[0].startswith("adrp x16")
                and seq[1].startswith("ldr x17")
                and seq[2].startswith("add x16")
                and seq[3].startswith("br x17"))
    for start in (-12, -8, -4, 0):
        if stub_at(start):
            return start
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--maps", required=True,
                    help="file holding the captured /proc/<pid>/maps text")
    ap.add_argument("--module", required=True,
                    help="library basename, or the full mapped path")
    ap.add_argument("--address", action="append", default=[],
                    help="runtime address, repeatable")
    ap.add_argument("--stdin-addresses", action="store_true",
                    help="read one hex/dec address per line from stdin")
    ap.add_argument("--elf-dir", default=None,
                    help="directory holding the extracted ELF (default: cwd)")
    ap.add_argument("--elf", default=None, help="explicit ELF file path")
    ap.add_argument("--page-size", type=lambda s: int(s, 0), default=PAGE)
    ap.add_argument("--allow-hash-mismatch", action="store_true",
                    help="resolve even when the local ELF hash differs from the "
                         "manifest (results are then labelled not-tied-to-capture)")
    ap.add_argument("--show-insn", type=int, default=0, metavar="N",
                    help="also print N bytes (max 16) at the file offset and an A64 "
                         "disassembly of the first word -- refused if the ELF is "
                         "not AArch64, never guessed from foreign bytes")
    ap.add_argument("--json", action="store_true", dest="as_json")
    args = ap.parse_args()

    try:
        addrs = [int(a, 0) for a in args.address]
        if args.stdin_addresses:
            addrs += [int(ln.strip(), 0) for ln in sys.stdin if ln.strip()]
    except ValueError as exc:
        print("ERROR: an address argument is not a number: %s" % exc,
              file=sys.stderr)
        return 2
    if not addrs:
        print("ERROR: no addresses given (--address / --stdin-addresses)",
              file=sys.stderr)
        return 2
    doc = {"schema": "ete-address-space/1", "module": args.module,
           "results": []}
    try:
        # inside the try: a missing or half-written manifest/maps file is an
        # unclosed answer, not a Python traceback
        with open(args.manifest, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
        with open(args.maps, "r", encoding="utf-8", errors="replace") as fh:
            rows, unparsed = parse_maps(fh.read())
        doc["maps_unparsed_lines"] = unparsed
        r = ModuleResolver(manifest, rows, args.module, elf_dir=args.elf_dir,
                           elf_path=args.elf, page_size=args.page_size,
                           allow_hash_skip=args.allow_hash_mismatch)
        doc["identity"] = r.identity
        doc["identity"]["hash_tied_to_manifest"] = (
            r.identity["manifest_sha256"] == r.identity["local_sha256"])
        for a in addrs:
            res = r.resolve(a)
            if args.show_insn:
                blob, why = r.insn_at(res, args.show_insn)
                res["file_bytes_requested"] = args.show_insn
                if blob is None:
                    # the coordinate may still be sound; only the byte/opcode
                    # cross-check is refused, so say so instead of printing a
                    # disassembly built from bytes this ELF cannot contain
                    res["insn_error"] = why
                else:
                    res["file_bytes"] = blob.hex(" ")
                    res["a64"] = (disassemble_a64(blob[:4]) if len(blob) >= 4
                                  else "requested fewer than 4 bytes")
            doc["results"].append(res)
    except ResolveError as exc:
        doc["status"] = "unclosed"
        doc["reason"] = str(exc)
    except (OSError, ValueError, struct.error) as exc:
        doc["status"] = "unclosed"
        doc["reason"] = "could not read inputs: %s" % exc

    resolved = sum(1 for x in doc["results"] if x.get("status") == "resolved")
    # a --allow-hash-mismatch run must be visible to a human reading only the
    # text output, not just to a --json consumer
    ident = doc.get("identity") or {}
    untied = bool(ident) and not ident.get("hash_tied_to_manifest", True)
    if args.as_json:
        print(json.dumps(doc, indent=2, sort_keys=True))
    else:
        if doc.get("status") == "unclosed":
            print("UNCLOSED: %s" % doc["reason"])
        if untied:
            print("NOT-TIED-TO-CAPTURE: --allow-hash-mismatch was given, so the "
                  "local ELF digest differs from the manifest and every file "
                  "offset / byte shown below belongs to a different build than "
                  "the one that was captured")
            print("    manifest_sha256  %s" % ident.get("manifest_sha256"))
            print("    local_sha256     %s" % ident.get("local_sha256"))
        for x in doc["results"]:
            print("%-16s %-9s %s" % (x["runtime_address"], x["status"],
                                     x.get("reason") or ""))
            for k in ("link_vaddr", "module_relative_offset", "file_offset",
                      "file_bytes", "a64", "insn_error", "segment",
                      "mapping_start", "pgoff", "cross_check", "mapped_path"):
                if k in x:
                    print("    %-22s %s" % (k, x[k]))
        print("resolved %d/%d%s (unclosed addresses are a valid answer)"
              % (resolved, len(doc["results"]),
                 " [NOT TIED TO CAPTURE]" if untied else ""))
    # exit 1 only when no coordinate system could be established at all;
    # individual addresses that stay unclosed are an answer, not a failure
    return 1 if doc.get("status") == "unclosed" else 0


if __name__ == "__main__":
    sys.exit(main())
