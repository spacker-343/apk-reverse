import argparse
import io
import queue
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import ete_record as R


class ControlTests(unittest.TestCase):
    def test_disable_ack_precedes_eof(self):
        events = []
        messages = queue.Queue()
        messages.put(b"started")

        class Pipe:
            def write(self, value):
                events.append(("write", value))

            def flush(self):
                events.append("flush")
                messages.put(b"ok")

            def close(self):
                events.append("eof")

        times = iter([0, .15, .152])
        report = R.controlled_window(SimpleNamespace(stdin=Pipe()), messages, .15, 1,
                                     clock=lambda: next(times), sleep=lambda s: events.append(("sleep", s)))
        self.assertEqual(events, [("write", b"pause\n"), "flush", ("write", b"resume\n"), "flush",
                                  ("sleep", .15), ("write", b"pause\n"), "flush", "eof"])
        self.assertTrue(report["final_disable_acknowledged"])
        self.assertTrue(report["initial_restart_acknowledged"])
        self.assertEqual(report["pause_ack_after_started_seconds"], .152)

    def test_failed_pause_does_not_claim_or_close_success(self):
        messages = queue.Queue()
        messages.put(b"started")
        messages.put(b"error")
        pipe = io.BytesIO()
        with self.assertRaises(RuntimeError):
            R.controlled_window(SimpleNamespace(stdin=pipe), messages, .03, 1, sleep=lambda _: None)
        self.assertFalse(pipe.closed)
        self.assertEqual(pipe.getvalue(), b"pause\n")

    def test_eof_before_started_is_failure(self):
        messages = queue.Queue()
        messages.put(None)
        with self.assertRaises(RuntimeError):
            R.expect(messages, b"started", 1)

    def test_ack_timeout_is_failure(self):
        with self.assertRaises(TimeoutError):
            R.expect(queue.Queue(), b"ok", .001)

    def test_nonempty_output_is_preserved(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "original.perf"
            path.write_bytes(b"preserved")
            args = argparse.Namespace(serial="synthetic", tid=1, duration=.15, timeout=1,
                                      aux_buffer_size=4096, addr_filter=None, out_dir=temp)
            with patch.object(R.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    R.record(args)
                run.assert_not_called()
            self.assertEqual(path.read_bytes(), b"preserved")

    def test_invalid_bounds_before_device_operations(self):
        args = argparse.Namespace(serial="synthetic", tid=1, duration=.15, timeout=1,
                                  aux_buffer_size=4096, addr_filter=None)
        for key, values in {"duration": [0, -1, 61, float("nan"), float("inf")],
                            "timeout": [0, 31, float("nan")], "tid": [0, -1],
                            "aux_buffer_size": [1024, 4097, 134217728],
                            "addr_filter": ["filter\nother"]}.items():
            original = getattr(args, key)
            for value in values:
                setattr(args, key, value)
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    R.validate_args(args)
            setattr(args, key, original)


if __name__ == "__main__":
    unittest.main()
