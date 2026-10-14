#!/usr/bin/env python3
"""Bounded cs-etm capture with acknowledged final disable before reader shutdown."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import queue
import shlex
import subprocess
import threading
import time
import uuid

from ete_deframe import walk_aux_payloads


def read_lines(pipe, lines, messages):
    for line in iter(pipe.readline, b""):
        lines.append(line)
        messages.put(line.strip())
    messages.put(None)


def expect(messages, wanted, timeout):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("recorder acknowledgement timeout: " + wanted.decode())
        try:
            line = messages.get(timeout=remaining)
        except queue.Empty as exc:
            raise TimeoutError("recorder acknowledgement timeout: " + wanted.decode()) from exc
        if line == wanted:
            return
        if line is None or line == b"error":
            raise RuntimeError("recorder did not acknowledge " + wanted.decode())


def controlled_window(proc, messages, duration, timeout, clock=time.monotonic, sleep=time.sleep):
    """Do not close stdin before the synchronous PERF_EVENT_IOC_DISABLE acknowledgement."""
    expect(messages, b"started", timeout)
    # Existing-TID events can start before their AUX mmap exists. Restart only after
    # simpleperf confirms all buffers/readers are ready; never depend on a context switch.
    for command in (b"pause\n", b"resume\n"):
        proc.stdin.write(command)
        proc.stdin.flush()
        expect(messages, b"ok", timeout)
    started = clock()
    sleep(duration)
    sent = clock()
    proc.stdin.write(b"pause\n")
    proc.stdin.flush()
    expect(messages, b"ok", timeout)
    acknowledged = clock()
    proc.stdin.close()
    return {"pause_sent_after_started_seconds": sent - started,
            "pause_ack_after_started_seconds": acknowledged - started,
            "initial_restart_acknowledged": True, "final_disable_acknowledged": True}


def validate_args(args):
    if not args.serial or args.tid <= 0:
        raise ValueError("an explicit serial and a positive existing thread ID are required")
    if not math.isfinite(args.duration) or not 0 < args.duration <= 60:
        raise ValueError("duration must be finite and in (0, 60] seconds")
    if not math.isfinite(args.timeout) or not 1 <= args.timeout <= 30:
        raise ValueError("timeout must be finite and in [1, 30] seconds")
    size = args.aux_buffer_size
    if size < 4096 or size > 64 * 1024 * 1024 or size & (size - 1):
        raise ValueError("AUX buffer must be a power of two between 4096 and 67108864 bytes")
    if args.addr_filter and any(c in args.addr_filter for c in ("\n", "\r", "\x00")):
        raise ValueError("address filter must be a single line")


def record(args):
    validate_args(args)
    root = Path(args.out_dir)
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise ValueError("out-dir must be empty; original captures are never overwritten")
    adb = [args.adb, "-s", args.serial]
    remote = "/data/local/tmp/pi_ete_record_" + uuid.uuid4().hex
    watchdog = math.ceil(args.duration + 3 * args.timeout + 2)
    proc = None
    threads = []
    out, err = [], []
    created = False
    stopped = False
    report = {"status": "unavailable", "full_trace_verified": False,
              "final_disable_acknowledged": False, "remote_cleanup": False,
              "requested_duration_seconds": args.duration, "aux_bytes": 0}

    def shell(cmd):
        result = subprocess.run(adb + ["shell", "-T", "su -c " + shlex.quote(cmd)],
                                capture_output=True, timeout=args.timeout)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))
        return result.stdout.decode(errors="replace").replace("\r\n", "\n").strip()

    def pull(name):
        result = subprocess.run(adb + ["pull", remote + "/" + name, str(root / name)],
                                capture_output=True, timeout=args.timeout)
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors="replace"))

    try:
        report["device"] = shell("getprop ro.product.device")
        if report["device"] != "socrates":
            raise ValueError("this tested capture entry point requires socrates")
        report["kernel"] = shell("cat /proc/version")
        report["security"] = shell("id; getenforce")
        report["simpleperf_sha256"] = shell("sha256sum /system/bin/simpleperf").split()[0]
        report["target_exe"] = shell("readlink -f /proc/%d/exe" % args.tid)
        maps = shell("cat /proc/%d/maps" % args.tid)
        (root / "maps.txt").write_text(maps + "\n", encoding="utf8")
        shell("mkdir -m 755 " + remote)
        created = True
        argv = ["simpleperf", "record", "-e", "cs-etm:u", "-t", str(args.tid),
                "--stdio-controls-profiling", "--aux-buffer-size", str(args.aux_buffer_size),
                "--no-dump-symbols", "--no-dump-kernel-symbols", "-o", remote + "/trace.perf"]
        if args.addr_filter:
            argv += ["--addr-filter", args.addr_filter]
        cmd = "exec timeout %d %s" % (watchdog, shlex.join(argv))
        proc = subprocess.Popen(adb + ["shell", "-T", "su -c " + shlex.quote(cmd)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        messages = queue.Queue()
        for pipe, lines, mailbox in ((proc.stdout, out, messages), (proc.stderr, err, queue.Queue())):
            thread = threading.Thread(target=read_lines, args=(pipe, lines, mailbox), daemon=True)
            thread.start()
            threads.append(thread)
        report.update(controlled_window(proc, messages, args.duration, args.timeout))
        report["recorder_rc"] = proc.wait(timeout=args.timeout)
        stopped = True
        if report["recorder_rc"] != 0:
            raise RuntimeError("simpleperf recording failed: rc=" + str(report["recorder_rc"]))
        pull("trace.perf")
        trace = root / "trace.perf"
        report["trace_sha256"] = hashlib.sha256(trace.read_bytes()).hexdigest()
        report["trace_bytes"] = trace.stat().st_size
        payloads = walk_aux_payloads(trace)
        report["aux_bytes"] = sum(len(row[0]) for row in payloads)
        report["aux_records"] = len(payloads)
        report["status"] = "captured" if report["aux_bytes"] else "no_aux_data"
    except (OSError, ValueError, RuntimeError, TimeoutError, subprocess.SubprocessError) as exc:
        report["error"] = str(exc)
    finally:
        if proc is not None and not stopped:
            # Closing the control pipe also lets normal error exits finish. The remote timeout
            # bounds tracing even when USB fails; never kill or stop the user's target thread.
            try:
                if not proc.stdin.closed:
                    proc.stdin.close()
                proc.wait(timeout=watchdog + args.timeout)
                stopped = True
            except (OSError, subprocess.SubprocessError):
                proc.kill()
                proc.wait(timeout=3)
        for thread in threads:
            thread.join(timeout=2)
        (root / "recorder.stdout").write_bytes(b"".join(out))
        (root / "recorder.stderr").write_bytes(b"".join(err))
        if created and (proc is None or stopped):
            try:
                shell("rm -f " + remote + "/trace.perf; rmdir " + remote)
                report["remote_cleanup"] = True
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                report["cleanup_error"] = str(exc)
        elif not created:
            report["remote_cleanup"] = True
        try:
            report["source_enable_after"] = shell(
                'for f in /sys/bus/coresight/devices/coresight-ete*/enable_source; do cat "$f"; done'
            ).splitlines()
        except (OSError, RuntimeError, subprocess.SubprocessError):
            report["source_enable_after"] = None
        if not report["remote_cleanup"]:
            report["remote_staging_remaining"] = remote
            report["status"] = "unavailable"
        (root / "record.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, help="explicit socrates adb serial")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--tid", required=True, type=int, help="existing target thread; never killed/stopped")
    parser.add_argument("--duration", required=True, type=float, help="active window, at most 60 seconds")
    parser.add_argument("--addr-filter", help="simpleperf file filter; passed literally, not evaluated")
    parser.add_argument("--aux-buffer-size", type=int, default=1048576)
    parser.add_argument("--timeout", type=float, default=10, help="ack/device operation deadline, 1..30 seconds")
    parser.add_argument("--out-dir", required=True, help="empty directory for local trace/maps/report")
    args = parser.parse_args()
    try:
        report = record(args)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("RESULT=" + report["status"])
    return {"captured": 0, "no_aux_data": 1}.get(report["status"], 2)


if __name__ == "__main__":
    raise SystemExit(main())
