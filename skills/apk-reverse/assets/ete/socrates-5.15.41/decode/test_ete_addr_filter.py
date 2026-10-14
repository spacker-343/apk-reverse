#!/usr/bin/env python3
"""Synthetic fallback planner regressions; no phone and no real APK inputs."""
import os
from pathlib import Path
import struct
import tempfile
import unittest

import ete_addr_filter as F
import ete_addr_space as A
import ete_test_fixtures as T


class TestFilter(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("PI_SCRATCH_DIR"))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def resolver(self, prior=True, path="/system/lib64/libfoo.so"):
        blob, _ = T.mkelf()
        blob = bytearray(blob)
        # First PT_LOAD read-only; second executable with unequal vaddr/offset.
        struct.pack_into("<I", blob, 64 + 4, 4)
        struct.pack_into("<I", blob, 64 + 56 + 4, 5)
        elf = self.root / "libfoo.so"
        elf.write_bytes(blob)
        low_end = "10002000" if prior else "10001000"
        maps = "10000000-%s r--p 00000000 07:12 101 %s\n" % (low_end, path)
        maps += "10003000-10005000 r-xp 00002000 07:12 101 %s\n" % path
        rows, bad = A.parse_maps(maps)
        self.assertFalse(bad)
        return A.ModuleResolver(T.manifest_for("libfoo.so", blob), rows, "libfoo.so", elf_path=elf)

    def test_model_preceding_endpoint(self):
        resolver = self.resolver()
        row, start, size = F.kernel_first_match(resolver.rows, resolver.mapped_paths[0], 0x2000, 0xffc)
        self.assertNotIn("x", row["perms"])
        self.assertEqual((0x10002000, 0), (start, size))

    def test_boundary_and_exclusive_end_crops_disclosed(self):
        data = F.plan(self.resolver())
        self.assertEqual("filter 0x3004-0x3ffc@/system/lib64/libfoo.so", data["addr_filter"])
        self.assertFalse(data["coverage_complete"])
        row = data["ranges"][0]
        self.assertEqual(["0x2004", "0x2ffc"], row["file_range"])
        self.assertEqual(["0x10003004", "0x10003ffc"], row["runtime_range"])
        self.assertEqual((4, 4), (row["cropped_start_bytes"], row["cropped_end_bytes"]))

    def test_interior_has_no_crop(self):
        data = F.plan(self.resolver(), 0x3004, 0x3ff8)
        self.assertTrue(data["coverage_complete"])
        self.assertEqual("filter 0x3004-0x3ff8@/system/lib64/libfoo.so", data["addr_filter"])

    def test_no_prior_vma_keeps_start(self):
        row = F.plan(self.resolver(prior=False))["ranges"][0]
        self.assertEqual((0, 4), (row["cropped_start_bytes"], row["cropped_end_bytes"]))

    def test_invalid_intervals(self):
        resolver = self.resolver()
        for start, end in [(0x3001, 0x3010), (0x3000, 0x3000), (-4, 4),
                           (0x2ffc, 0x3004), (0x3000, 0x4004), (None, 0x3010),
                           (0x3000, 0x3004), (0x3ffc, 0x4000)]:
            with self.subTest(start=start, end=end), self.assertRaises(A.ResolveError):
                F.plan(resolver, start, end)

    def test_hash_mismatch_rejected(self):
        resolver = self.resolver()
        resolver.manifest_sha = "0" * 64
        with self.assertRaises(A.ResolveError):
            F.plan(resolver)

    def test_nonplain_paths_rejected(self):
        for path in [T.MAP_PATH, "relative/libfoo.so", "/system/lib64/libfoo.so (deleted)"]:
            with self.subTest(path=path):
                with self.assertRaises(A.ResolveError):
                    F.plan(self.resolver(path=path))

    def test_non_a64_rejected(self):
        resolver = self.resolver()
        resolver.is_a64 = False
        with self.assertRaises(A.ResolveError):
            F.plan(resolver)

    def test_no_executable_segment_rejected(self):
        resolver = self.resolver()
        resolver.pt_load = [dict(s, flags=4) for s in resolver.pt_load]
        with self.assertRaises(A.ResolveError):
            F.plan(resolver)

    def test_nonexecutable_or_short_vma_rejected(self):
        for mode in ["nonexec", "short"]:
            resolver = self.resolver()
            for row in resolver.rows:
                if "x" in row["perms"]:
                    if mode == "nonexec":
                        row["perms"] = "r--p"
                    else:
                        row["end"] = row["start"] + 0x800
            with self.subTest(mode=mode), self.assertRaises(A.ResolveError):
                F.plan(resolver)


if __name__ == "__main__":
    unittest.main()
