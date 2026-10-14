"""Synthetic direct-entry guards and cleanup; no device is contacted."""
import json
from pathlib import Path
import shlex
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import ete_direct_record as D
import ete_test_fixtures as F


class DirectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.blob, _ = F.mkelf()
        self.recorder = self.root / "recorder"
        self.recorder.write_bytes(self.blob)
        self.args = SimpleNamespace(serial="synthetic", tid=42, duration=.001,
                                    aux_buffer_size=16777216, recorder=str(self.recorder),
                                    out_dir=self.root / "out", adb="synthetic-adb")

    def test_invalid_bounds_before_adb(self):
        for key, value in (("serial", ""), ("tid", 0), ("duration", float("nan")),
                           ("duration", .031), ("aux_buffer_size", 1234)):
            with self.subTest(key=key, value=value), patch.object(D.subprocess, "run") as run:
                args = SimpleNamespace(**vars(self.args))
                setattr(args, key, value)
                with self.assertRaises(ValueError):
                    D.capture(args)
                run.assert_not_called()

    def test_invalid_recorder_before_adb(self):
        self.recorder.write_bytes(b"not ELF")
        with patch.object(D.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                D.capture(self.args)
            run.assert_not_called()

    def test_existing_output_preserved(self):
        self.args.out_dir.mkdir()
        existing = self.args.out_dir / "keep"
        existing.write_bytes(b"unchanged")
        with patch.object(D.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                D.capture(self.args)
            run.assert_not_called()
        self.assertEqual(existing.read_bytes(), b"unchanged")

    def fake_capture(self, failure=None, decode_rc=0):
        maps = "10000000-10001000 r-xp 00000000 00:01 1 /system/lib64/libfoo.so\n"
        maps += "20000000-20001000 r-xp 00000000 00:00 0 [vdso]\n"
        if failure == "anonymous":
            maps += "30000000-30001000 r-xp 00000000 00:00 0\n"
        calls, map_calls, idle_calls = [], 0, 0
        attr = bytearray(136)
        struct.pack_into("<Q", attr, 24, 128)
        struct.pack_into("<Q", attr, 40, 1 << 18)
        events = D.record_header(11, struct.pack("<QQQII", 0, 16, 0, 0, 0))
        native = {"attr.bin": bytes(attr), "events.bin": events, "aux.bin": bytes(range(16)),
                  "direct.json": b'{"cpu":0,"aux_bytes":16}',
                  "vdso-before.bin": self.blob, "vdso-after.bin": self.blob}

        def run(argv, **kwargs):
            nonlocal map_calls, idle_calls
            calls.append(argv)
            stdout = b""
            if argv[0] == "synthetic-adb":
                self.assertEqual(argv[1:3], ["-s", "synthetic"])
                if argv[3] == "shell":
                    command = shlex.split(argv[-1])[-1]
                    if command == "getprop ro.product.device":
                        stdout = b"wrong" if failure == "kernel" else b"socrates"
                    elif command == "uname -r":
                        stdout = D.RELEASE.encode()
                    elif command == "getenforce":
                        stdout = b"Enforcing"
                    elif command == "id":
                        stdout = b"uid=0"
                    elif "enable_source" in command:
                        idle_calls += 1
                        if failure == "source" and idle_calls > 1:
                            raise OSError("source read failed")
                        stdout = ("0\n" * 8).encode()
                    elif command == "cat /proc/42/status":
                        stdout = ("Cpus_allowed_list:\t" + ("4" if failure == "affinity" else "0")).encode()
                    elif command == "cat /proc/42/maps":
                        map_calls += 1
                        stdout = (maps + ("changed" if failure == "maps" and map_calls > 1 else "")).encode()
                    elif command.startswith("sha256sum "):
                        import hashlib
                        blob = self.recorder.read_bytes() if command.endswith("/recorder") else self.blob
                        stdout = hashlib.sha256(blob).hexdigest().encode() + b"  file"
                    elif command.startswith("cat /sys/"):
                        stdout = b"0x47705a13"
                    elif command.startswith("rm -f ") and failure == "cleanup":
                        raise OSError("cleanup failed")
                elif argv[3] == "pull":
                    name = Path(argv[4]).name
                    Path(argv[5]).write_bytes(native.get(name, self.blob))
            else:
                out = self.args.out_dir / "decoded"
                out.mkdir()
                (out / "decode.json").write_text(json.dumps({
                    "status": "trace_has_gaps" if decode_rc == 1 else "decoded_ranges",
                    "loss_markers_clear": decode_rc == 0, "source_unchanged": True,
                    "remote_cleanup": True}))
                return SimpleNamespace(returncode=decode_rc, stdout=b"", stderr=b"")
            return SimpleNamespace(returncode=0, stdout=stdout, stderr=b"")
        with patch.object(D.subprocess, "run", side_effect=run):
            report = D.capture(self.args)
        return report, calls

    def test_capture_success_preserves_aux_and_cleans(self):
        report, _ = self.fake_capture()
        self.assertEqual(report["status"], "loss_markers_clear")
        self.assertTrue(report["aux_unchanged"] and report["remote_cleanup"])
        self.assertFalse(report["full_trace_verified"])

    def test_negative_guards_before_push(self):
        for failure in ("kernel", "affinity", "anonymous", "maps"):
            with self.subTest(failure=failure):
                self.args.out_dir = self.root / failure
                report, calls = self.fake_capture(failure)
                self.assertEqual(report["status"], "unavailable")
                self.assertFalse(any("/recorder" in str(c) and "timeout 5" in str(c) for c in calls))

    def test_cleanup_and_source_failure_not_success(self):
        for failure in ("cleanup", "source"):
            with self.subTest(failure=failure):
                self.args.out_dir = self.root / failure
                report, _ = self.fake_capture(failure)
                self.assertEqual(report["status"], "unavailable")
                self.assertFalse(report.get("loss_markers_clear"))

    def test_loss_rejection_distinct_from_decoder_failure(self):
        for rc, status in ((1, "trace_has_gaps"), (2, "unavailable")):
            self.args.out_dir = self.root / str(rc)
            report, _ = self.fake_capture(decode_rc=rc)
            self.assertEqual(report["status"], status)


if __name__ == "__main__":
    unittest.main()
