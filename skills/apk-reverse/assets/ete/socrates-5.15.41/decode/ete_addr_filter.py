#!/usr/bin/env python3
"""Plan explicit ELF address filters for the recorded socrates perf VMA boundary bug.

Read-only: never connects to the phone or changes a kernel/source. Requires a
hashed ELF and the live process maps. Output is an --addr-filter argument, not
a shell command. On this kernel a file filter touching the preceding VMA end
can bind to that VMA as a zero-length range. Also simpleperf VaddrToOff rejects
an exclusive PT_LOAD end. Cropped bytes are reported, never silently covered.
Use no hardware address filter when complete boundary coverage is required.
"""
import argparse
import json
from pathlib import Path
import sys

import ete_addr_space as A


def kernel_first_match(rows, path, start, size):
    """Model stock perf_addr_filter_apply/vma_adjust's inclusive overlap test."""
    for row in sorted(rows, key=lambda r: r["start"]):
        if row["path"] != path:
            continue
        off, length = row["pgoff"], row["end"] - row["start"]
        if start > off + length or start + size < off:
            continue
        delta = max(0, start - off)
        covered = min(length - delta, size - max(0, off - start))
        return row, row["start"] + delta, covered
    return None, 0, 0


def plan(resolver, start_vaddr=None, end_vaddr=None):
    if not resolver.is_a64:
        raise A.ResolveError("only file-backed AArch64 instruction filters are supported")
    if resolver.local_sha != resolver.manifest_sha:
        raise A.ResolveError("ELF hash must be tied to the manifest")
    path = resolver.mapped_paths[0]
    if not path.startswith("/") or any(c.isspace() or c in ",@!" for c in path) or path.endswith("(deleted)"):
        raise A.ResolveError("filter requires a plain mapped ELF path; APK/anonymous/deleted paths need another route")
    if (start_vaddr is None) != (end_vaddr is None):
        raise A.ResolveError("provide both --start-vaddr and --end-vaddr")
    if start_vaddr is not None and (
            start_vaddr < 0 or start_vaddr >= end_vaddr or start_vaddr % 4 or end_vaddr % 4):
        raise A.ResolveError("requested A64 range must be nonempty and 4-byte aligned")
    segments = [s for s in resolver.pt_load if s["flags"] & 1 and s["filesz"]]
    if start_vaddr is not None:
        segments = [s for s in segments if s["vaddr"] <= start_vaddr < end_vaddr <= s["vaddr"] + s["filesz"]]
        if len(segments) != 1:
            raise A.ResolveError("requested interval must stay inside one executable file-backed PT_LOAD")
    results = []
    for seg in segments:
        requested_start = seg["offset"] + (start_vaddr - seg["vaddr"] if start_vaddr is not None else 0)
        requested_end = seg["offset"] + (end_vaddr - seg["vaddr"] if end_vaddr is not None else seg["filesz"])
        # Native simpleperf converts BOTH range endpoints with VaddrToOff. Keep
        # the exclusive end address inside PT_LOAD, not exactly at its end.
        end = requested_end - (requested_end % 4)
        if end == seg["offset"] + seg["filesz"]:
            end -= 4
        start = (requested_start + 3) & ~3
        adjustments = []
        row, runtime, size = kernel_first_match(resolver.rows, path, start, max(0, end - start))
        if row and size == 0 and "x" not in row["perms"] and start == row["pgoff"] + row["end"] - row["start"]:
            start += 4
            adjustments.append("skip first A64 word: stock inclusive VMA-end match binds zero-length prior mapping")
            row, runtime, size = kernel_first_match(resolver.rows, path, start, max(0, end - start))
        if end <= start or not row or "x" not in row["perms"] or size != end - start:
            raise A.ResolveError("filter cannot map completely to one executable VMA; use unfiltered capture")
        first, last = resolver.resolve(runtime), resolver.resolve(runtime + size - 4)
        if (first.get("status") != "resolved" or last.get("status") != "resolved"
                or first.get("cross_check") != "agree" or last.get("cross_check") != "agree"
                or int(first["file_offset"], 16) != start
                or int(last["file_offset"], 16) != end - 4):
            raise A.ResolveError("filter ELF/maps coordinate cross-check failed")
        if end < requested_end:
            adjustments.append("exclusive end kept inside executable PT_LOAD for native VaddrToOff")
        link_start = seg["vaddr"] + start - seg["offset"]
        link_end = seg["vaddr"] + end - seg["offset"]
        results.append({"segment": seg["index"], "mapped_path": path,
                        "requested_file_range": [hex(requested_start), hex(requested_end)],
                        "file_range": [hex(start), hex(end)],
                        "link_vaddr_range": [hex(link_start), hex(link_end)],
                        "runtime_range": [hex(runtime), hex(runtime + size)],
                        "cropped_start_bytes": start - requested_start,
                        "cropped_end_bytes": requested_end - end,
                        "adjustments": adjustments,
                        "simpleperf_filter": "filter %#x-%#x@%s" % (link_start, link_end, path),
                        "kernel_filter": "filter %#x/%#x@%s" % (start, size, path)})
    if not results:
        raise A.ResolveError("no executable file-backed interval")
    return {"schema": "ete-address-filter/1", "status": "planned", "identity": resolver.identity,
            "addr_filter": ",".join(r["simpleperf_filter"] for r in results), "ranges": results,
            "coverage_complete": all(not r["cropped_start_bytes"] and not r["cropped_end_bytes"] for r in results),
            "limits": "Plan for these maps/ELF only. Recheck live maps before capture. Never claim cropped words were traced. "
                      "For full boundary coverage use cs-etm:u without a hardware address filter and restrict modules after decoding."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--maps", required=True)
    parser.add_argument("--elf-dir", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--start-vaddr", type=lambda s: int(s, 0))
    parser.add_argument("--end-vaddr", type=lambda s: int(s, 0), help="exclusive link-time virtual end")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
        rows, bad = A.parse_maps(Path(args.maps).read_text(encoding="utf-8"))
        if bad:
            raise A.ResolveError("unparseable maps rows")
        resolver = A.ModuleResolver(manifest, rows, args.module, elf_dir=args.elf_dir)
        data = plan(resolver, args.start_vaddr, args.end_vaddr)
    except (A.ResolveError, OSError, ValueError, KeyError) as exc:
        print("RESULT=unavailable: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
    else:
        print("ADDR_FILTER=" + data["addr_filter"])
        print("COVERAGE_COMPLETE=" + str(data["coverage_complete"]))
        print(json.dumps(data["ranges"], indent=2, ensure_ascii=False))
        print("RESULT=planned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
