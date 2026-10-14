#!/usr/bin/env python3
"""Run actual original/fixed matching and original VMA conversion in host C.

Requires the original recorded core.c and a host C compiler. This is NOT an
in-kernel test or device verification. Outputs/intermediates stay in --work-dir.
"""
import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import subprocess

import apply_perf_fix as P

STUBS = r"""
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <limits.h>
_Static_assert(sizeof(unsigned long) == 8, "use an LP64 host for the AArch64 model");
struct file { unsigned long inode; };
struct dentry { unsigned long inode; };
struct perf_addr_filter {
    struct { struct dentry *dentry; } path;
    unsigned long offset, size;
};
struct perf_addr_filter_range { unsigned long start, size; };
struct vm_area_struct {
    unsigned long vm_start, vm_end, vm_pgoff;
    struct file *vm_file;
};
#define PAGE_SHIFT 12
#define min(a,b) ((a) < (b) ? (a) : (b))
#define d_inode(d) ((d)->inode)
#define file_inode(f) ((f)->inode)
"""
EXPORTS = r"""
int match(unsigned long start, unsigned long length, unsigned long off,
          unsigned long size, int same, int backed)
{
    struct dentry d = { 1 };
    struct file file = { same ? 1 : 2 };
    struct perf_addr_filter f = { { backed ? &d : NULL }, start, length };
    return perf_addr_filter_match(&f, &file, off, size);
}
int first(unsigned long start, unsigned long length,
          unsigned long *runtime, unsigned long *covered)
{
    struct dentry d = { 1 };
    struct file file = { 1 };
    struct perf_addr_filter f = { { &d }, start, length };
    struct vm_area_struct vmas[] = {
        { 0x100000, 0x10b000, 0, &file },
        { 0x200000, 0x240000, 0xb, &file }
    };
    struct perf_addr_filter_range r = { 0, 0 };
    for (int i = 0; i < 2; i++) {
        if (perf_addr_filter_vma_adjust(&f, &vmas[i], &r)) {
            *runtime = r.start;
            *covered = r.size;
            return i;
        }
    }
    *runtime = r.start;
    *covered = r.size;
    return -1;
}
"""


def build(source, name, root, cc):
    start = source.index(P.BEGIN.decode())
    end = source.index("\nstatic void __perf_addr_filters_adjust(", start)
    c = root / (name + ".c")
    lib = root / (name + ".so")
    c.write_text(STUBS + source[start:end] + EXPORTS, encoding="utf8")
    subprocess.run([cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
                    str(c), "-o", str(lib)], check=True, timeout=60)
    loaded = ctypes.CDLL(str(lib))
    loaded.match.argtypes = [ctypes.c_ulong] * 4 + [ctypes.c_int] * 2
    loaded.match.restype = ctypes.c_int
    loaded.first.argtypes = [ctypes.c_ulong] * 2 + [ctypes.POINTER(ctypes.c_ulong)] * 2
    loaded.first.restype = ctypes.c_int
    return loaded, hashlib.sha256(lib.read_bytes()).hexdigest()


def reference(start, length, off, size):
    # Python integers model mathematical endpoints without unsigned wrapping.
    return bool(size and (off <= start < off + size if not length
                          else start < off + size and off < start + length))


def first(lib, start, size):
    runtime, covered = ctypes.c_ulong(), ctypes.c_ulong()
    index = lib.first(start, size, ctypes.byref(runtime), ctypes.byref(covered))
    return [index, runtime.value, covered.value]


def run(source, root, cc):
    original = source.read_bytes()
    fixed = P.generate(original)
    old, old_sha = build(original.decode(), "original", root, cc)
    new, new_sha = build(fixed.decode(), "fixed", root, cc)
    cases = [
        ("preceding_vma_end", 0xb000, 0x3f684, 0, 0xb000),
        ("interior", 0xb004, 0x3f680, 0xb000, 0x40000),
        ("range_end_at_vma_start", 0xaffc, 4, 0xb000, 0x40000),
        ("point_at_vma_start", 0xb000, 0, 0xb000, 0x40000),
        ("point_at_vma_end", 0x4b000, 0, 0xb000, 0x40000),
        ("point_inside", 0xb004, 0, 0xb000, 0x40000),
        ("point_before", 0xaffc, 0, 0xb000, 0x40000),
        ("range_straddles_start", 0xaffc, 8, 0xb000, 0x40000),
        ("range_straddles_end", 0x4affc, 8, 0xb000, 0x40000),
        ("empty_vma", 0xb000, 4, 0xb000, 0),
        ("large_filter_end", 0xb000, (1 << 64) - 1, 0xc000, 0x1000),
        ("large_vma_end", (1 << 64) - 2, 1, (1 << 64) - 4, 8),
    ]
    observations = []
    for name, start, length, off, size in cases:
        expected = reference(start, length, off, size)
        actual = bool(new.match(start, length, off, size, 1, 1))
        assert actual == expected, name
        observations.append({"case": name, "original": bool(old.match(start, length, off, size, 1, 1)),
                             "fixed": actual, "expected": expected})
    assert not new.match(0xb004, 4, 0xb000, 0x40000, 0, 1)
    assert not new.match(0xb004, 4, 0xb000, 0x40000, 1, 0)
    boundary_old, boundary_new = first(old, 0xb000, 0x3f684), first(new, 0xb000, 0x3f684)
    assert boundary_old == [0, 0x10b000, 0]
    assert boundary_new == [1, 0x200000, 0x3f684]
    assert first(old, 0xb004, 0x3f680) == first(new, 0xb004, 0x3f680) == [1, 0x200004, 0x3f680]
    assert first(new, 0xb000, 0) == [1, 0x200000, 0]
    assert first(new, 0x4b000, 0) == [-1, 0, 0]
    rng = random.Random(8550)
    edge = [0, 1, 4, 0xaffc, 0xb000, 0xb004, (1 << 64) - 4, (1 << 64) - 1]
    checks = 0
    for _ in range(50000):
        off = rng.choice(edge) if rng.randrange(2) else rng.getrandbits(64)
        size = rng.choice(edge) if rng.randrange(2) else rng.getrandbits(64)
        start = rng.choice(edge) if rng.randrange(2) else rng.getrandbits(64)
        length = rng.choice(edge) if rng.randrange(2) else rng.getrandbits(64)
        assert bool(new.match(start, length, off, size, 1, 1)) == reference(start, length, off, size)
        checks += 1
    return {"schema": "perf-filter-c-regression/1", "status": "passed", "execution": "host_C_not_kernel",
            "source_sha256": hashlib.sha256(original).hexdigest(),
            "fixed_core_sha256": hashlib.sha256(fixed).hexdigest(),
            "host_library_sha256": {"original": old_sha, "fixed": new_sha},
            "named_cases": observations, "random_checks": checks, "identity_rejections": 2,
            "first_match_boundary": {"original": boundary_old, "fixed": boundary_new},
            "runtime_kernel_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=False)
    result = run(args.source, args.work_dir, args.cc)
    (args.work_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf8")
    print(json.dumps(result, indent=2))
    print("RESULT=host_c_regression_passed")


if __name__ == "__main__":
    main()
