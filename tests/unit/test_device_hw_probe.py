"""Mock-only tests for the read-only probe and opt-in AUXTRACE smoke test."""
import json
import shlex
import subprocess
import sys
from unittest.mock import Mock

import pytest

from conftest import load_script

hw = load_script("device_hw_probe.py")
pytestmark = pytest.mark.unit


class DeviceShell:
    def __init__(self, *, root_rc=0, shell_root=False, list_rc=0,
                 record_rc=0, stat_rc=0, size="4096", dump_rc=0,
                 dump="record auxtrace: size 0x1000\n  auxtrace_size: 2048",
                 rm_rc=0, absent_rc=0, absent="ABSENT", raises=None):
        self.root_rc = root_rc
        self.shell_root = shell_root
        self.list_rc = list_rc
        self.record_rc = record_rc
        self.stat_rc = stat_rc
        self.size = size
        self.dump_rc = dump_rc
        self.dump = dump
        self.rm_rc = rm_rc
        self.absent_rc = absent_rc
        self.absent = absent
        self.raises = raises
        self.calls = []

    def __call__(self, adb, serial, command, root=False, timeout=30):
        self.calls.append((command, root, timeout))
        if self.raises and self.raises in command:
            raise RuntimeError("injected failure")
        if command.startswith("getprop "):
            return 0, "mock-property"
        if command == "id":
            if root:
                return self.root_rc, "uid=0(root)"  # rc must also succeed
            return 0, "uid=0(root)" if self.shell_root else "uid=2000(shell)"
        if command == "uname -a":
            return 0, "Linux localhost 5.15.0-test #1 SMP aarch64"
        if command.startswith("ls -1 /sys/bus/event_source/devices/cs_etm"):
            return 0, "TYPE\n11\nCPUMASK\n0-7"
        if command.startswith("ls -1 /sys/bus/event_source/devices "):
            return 0, "cpu\ncs_etm"
        if command.startswith("ls -1 /sys/bus/coresight/devices "):
            return 0, "ete0\netr0"
        if command.startswith("echo DRIVERS;"):
            return 0, "DRIVERS\nete\nSOURCE:/sys/bus/coresight/devices/ete0\nDRIVER\n../../drivers/ete\nENABLE_SOURCE\n0"
        if command.startswith("cat /proc/sys/kernel/perf_event_paranoid"):
            return 0, "2"
        if command.startswith("/system/bin/simpleperf list"):
            return self.list_rc, "List of events:\n  cs-etm    ARM CoreSight ETM"
        if command.startswith("/system/bin/simpleperf record"):
            return self.record_rc, "record output"
        if command.startswith("stat -c %s "):
            return self.stat_rc, self.size
        if command.startswith("/system/bin/simpleperf dump"):
            return self.dump_rc, self.dump
        if command.startswith("rm -f "):
            return self.rm_rc, "" if self.rm_rc == 0 else "permission denied"
        if command.startswith("if [ ! -e "):
            return self.absent_rc, self.absent
        raise AssertionError("unexpected command: " + command)

    def matching(self, prefix):
        return [call for call in self.calls if call[0].startswith(prefix)]


def probe(monkeypatch, device, *, smoke=True, duration=None, aux_size="1048576"):
    monkeypatch.setattr(hw, "device_shell", device)
    return hw.probe("adb", "MOCK_SERIAL", smoke, duration, aux_size)


def cli(monkeypatch, device, *args):
    monkeypatch.setattr(sys, "argv", ["device_hw_probe.py", "--json", *args])
    monkeypatch.setattr(hw.shutil, "which", lambda name: "mock-adb")
    monkeypatch.setattr(hw, "choose_device", lambda adb, serial: ("MOCK_SERIAL", ""))
    monkeypatch.setattr(hw, "device_shell", device)
    return hw.main()


@pytest.mark.parametrize("dump", [
    "record auxtrace: size 0x1000\n  auxtrace_size: 2048",
    "  PERF_RECORD_AUXTRACE size=4096",
    "  type: AUXTRACE\n  size: 4096",
])
def test_success_checks_positive_stat_dump_and_exact_workload(monkeypatch, dump):
    device = DeviceShell(dump=dump)
    data = probe(monkeypatch, device)
    smoke = data["smoke"]
    remote = smoke["remote_path"]
    assert smoke["command"] == (
        "/system/bin/simpleperf record -e cs-etm:u --aux-buffer-size 1048576 "
        "--no-dump-symbols --no-dump-kernel-symbols -o " + remote +
        " -- /system/bin/ls /system/bin")
    assert smoke["exit_code"] == 0
    assert smoke["file_size_bytes"] == 4096
    assert smoke["dump_exit_code"] == 0
    assert smoke["auxtrace_structure"] is True
    assert smoke["recorded"] is True
    assert smoke["cleaned"] is True
    assert data["verdict"] == "trace_recorded"
    assert data["layers"]["full_instruction_decode"] == "unverified"
    assert smoke["full_instruction_decode"] == "unverified"
    assert device.calls[-2][0] == "rm -f " + remote
    assert device.calls[-1][0].startswith("if [ ! -e " + remote)
    assert all(0 < call[2] <= 50 for call in device.calls)
    assert all(call[1] for call in device.calls if remote in call[0])


def test_unique_paths_and_optional_duration(monkeypatch):
    device = DeviceShell()
    first = probe(monkeypatch, device, duration=2, aux_size="1M")["smoke"]
    second = probe(monkeypatch, device)["smoke"]
    assert first["remote_path"] != second["remote_path"]
    assert "--duration 2 -- /system/bin/ls /system/bin" in first["command"]
    assert "--duration" not in second["command"]
    assert "--aux-buffer-size 1048576" in first["command"]
    assert "-a" not in shlex.split(first["command"])


@pytest.mark.parametrize("options", [
    {"record_rc": 1},
    {"record_rc": 124},
    {"size": "0"},
    {"stat_rc": 1, "size": "4096"},
    {"size": "stat: permission denied"},
    {"size": "-1"},
    {"size": "4096\nwarning"},
    {"dump_rc": 1},
    {"dump": "record auxtrace_info: size 0x100"},
    {"dump": "error: no AUXTRACE records found"},
    {"dump": ""},
])
def test_failed_or_empty_smoke_is_failed_nonzero_not_untested(monkeypatch, capsys, options):
    device = DeviceShell(**options)
    assert cli(monkeypatch, device, "--smoke-test") == 1
    data = json.loads(capsys.readouterr().out)
    assert data["verdict"] == "record_failed"
    assert data["layers"]["trace_smoke"] == "failed"
    assert data["smoke"]["recorded"] is False
    assert data["smoke"]["cleaned"] is True
    assert device.matching("rm -f ")
    if options.get("record_rc", 0) != 0 or options.get("stat_rc", 0) != 0 or "size" in options:
        assert not device.matching("/system/bin/simpleperf dump")


@pytest.mark.parametrize("options", [
    {"rm_rc": 1},  # absence alone does not prove that rm succeeded
    {"absent_rc": 1, "absent": "PRESENT"},
    {"absent_rc": 124, "absent": "TIMEOUT"},
    {"absent": ""},
    {"raises": "rm -f "},
    {"raises": "if [ ! -e "},
])
def test_cleanup_failure_is_not_cleaned_and_returns_nonzero(monkeypatch, capsys, options):
    device = DeviceShell(**options)
    assert cli(monkeypatch, device, "--smoke-test") == 1
    data = json.loads(capsys.readouterr().out)
    assert data["smoke"]["recorded"] is True
    assert data["smoke"]["cleaned"] is False
    assert data["verdict"] == "record_failed"
    assert device.matching("if [ ! -e ")


@pytest.mark.parametrize("raises", ["simpleperf record", "stat -c", "simpleperf dump"])
def test_finally_cleans_partial_trace_after_exception(monkeypatch, raises):
    device = DeviceShell(raises=raises)
    data = probe(monkeypatch, device)
    assert data["verdict"] == "record_failed"
    assert data["smoke"]["error"] == "injected failure"
    assert data["smoke"]["cleaned"] is True
    assert device.matching("rm -f ")
    assert device.matching("if [ ! -e ")


@pytest.mark.parametrize("root_rc,shell_root,want_root,want_su", [
    (0, False, True, True),
    (1, False, False, False),
    (1, True, True, False),  # an already-root adb shell need not use su
])
def test_default_read_only_list_uses_available_root_and_reports_status(
        monkeypatch, capsys, root_rc, shell_root, want_root, want_su):
    device = DeviceShell(root_rc=root_rc, shell_root=shell_root)
    assert cli(monkeypatch, device) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["root"] is want_root
    assert data["simpleperf_list_as_root"] is want_root
    assert device.matching("/system/bin/simpleperf list")[0][1] is want_su
    assert data["kernel"]["uname"].startswith("Linux ")
    assert "ENABLE_SOURCE\n0" in data["ete_source_driver_status"]["output"]
    assert data["layers"]["trace_smoke"] == "not_run"
    assert data["verdict"] == "recorder_listed_not_tested"
    assert "smoke" not in data
    assert not device.matching("/system/bin/simpleperf record")
    assert not device.matching("rm -f ")
    assert not any(" > " in command for command, _, _ in device.calls)


def test_list_error_does_not_claim_event_is_listed(monkeypatch):
    data = probe(monkeypatch, DeviceShell(list_rc=1), smoke=False)
    assert data["layers"]["recorder_event"] == "not_listed"
    assert data["simpleperf_list_exit_code"] == 1


def test_root_shell_command_quotes_whole_command(monkeypatch):
    runner = Mock(return_value=(0, "cs-etm"))
    monkeypatch.setattr(hw, "run", runner)
    command = "/system/bin/simpleperf list 2>&1"
    assert hw.device_shell("adb", "SERIAL", command, root=True, timeout=10) == (0, "cs-etm")
    runner.assert_called_once_with(
        ["adb", "-s", "SERIAL", "shell", "su -c " + shlex.quote(command)], 10)


@pytest.mark.parametrize("value,expected", [
    ("1048576", "1048576"), ("1M", "1048576"), ("2k", "2048"),
    ("1G", "1073741824"), ("0001", "1"),
])
def test_aux_size_normalization(value, expected):
    assert hw.validate_aux_size(value) == expected


@pytest.mark.parametrize("value", [
    "1M; touch /data/local/tmp/injected", "$(id)", "1M && id", "1\n", "",
    "0", "0M", "-1", "1 MB", "2G", "1.5M", "'1M'",
])
def test_invalid_aux_rejected_before_any_device_command(monkeypatch, value):
    device = Mock(side_effect=AssertionError("must not reach adb"))
    monkeypatch.setattr(hw, "device_shell", device)
    with pytest.raises(ValueError, match="--aux-buffer-size"):
        hw.probe("adb", "SERIAL", True, None, value)
    with pytest.raises(ValueError, match="--aux-buffer-size"):
        hw.smoke_record("adb", "SERIAL", True, None, value)
    device.assert_not_called()


@pytest.mark.parametrize("args", [
    ["--aux-buffer-size", "1M;id"], ["--duration", "0"], ["--duration", "31"],
])
def test_cli_validation_before_adb(monkeypatch, capsys, args):
    monkeypatch.setattr(sys, "argv", ["device_hw_probe.py", *args])
    runner = Mock(side_effect=AssertionError("must not reach adb"))
    monkeypatch.setattr(hw, "run", runner)
    with pytest.raises(SystemExit) as exc:
        hw.main()
    assert exc.value.code == 2
    assert "error:" in capsys.readouterr().err
    runner.assert_not_called()


@pytest.mark.parametrize("devices,requested", [
    ("List of devices attached\n", None),
    ("List of devices attached\nSERIAL offline\n", None),
    ("List of devices attached\nA device\nB device\n", None),
    ("List of devices attached\nA device\n", "B"),
])
def test_no_suitable_device_is_blocked_before_probe(monkeypatch, capsys, devices, requested):
    argv = ["device_hw_probe.py", "--smoke-test"]
    if requested:
        argv.extend(["--serial", requested])
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.setattr(hw.shutil, "which", lambda name: "mock-adb")
    monkeypatch.setattr(hw, "run", Mock(return_value=(0, devices)))
    device = Mock(side_effect=AssertionError("must not reach device"))
    monkeypatch.setattr(hw, "device_shell", device)
    assert hw.main() == 2
    assert "BLOCKED:" in capsys.readouterr().err
    device.assert_not_called()


def test_missing_adb_is_blocked(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["device_hw_probe.py", "--adb", "missing-adb"])
    monkeypatch.setattr(hw.shutil, "which", lambda name: None)
    monkeypatch.setattr(hw.os.path, "exists", lambda path: False)
    assert hw.main() == 2
    assert "adb not found" in capsys.readouterr().err


def test_successful_smoke_cli_returns_zero(monkeypatch, capsys):
    assert cli(monkeypatch, DeviceShell(), "--smoke-test") == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "trace_recorded"


def test_command_timeout_is_bounded_failure(monkeypatch):
    runner = Mock(side_effect=subprocess.TimeoutExpired(["adb"], 10))
    monkeypatch.setattr(hw.subprocess, "run", runner)
    rc, output = hw.run(["adb", "devices"], timeout=10)
    assert rc == 124
    assert "TIMEOUT after 10s" in output
    assert runner.call_args.kwargs["timeout"] == 10
