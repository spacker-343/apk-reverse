"""Bundled artifact identity and guarded reload (no device writes in tests)."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "skills" / "apk-reverse" / "scripts"
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location("ete_module_test", SCRIPTS / "ete_module.py")
ete = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ete)


def test_bundled_module_and_manifest():
    manifest, path = ete.verify_assets()
    assert manifest["device"] == "socrates"
    assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest["module_sha256"]
    assert not manifest["instruction_path_decoding_verified"]
    assert not manifest["autoload_configured"]


def test_checksum_inventory():
    for line in (ete.ASSETS / "SHA256SUMS.txt").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((ete.ASSETS / name).read_bytes()).hexdigest() == digest


def test_corrupted_bundle_rejected(tmp_path):
    manifest, path = ete.verify_assets()
    (tmp_path / "module").mkdir()
    (tmp_path / manifest["module"]).write_bytes(path.read_bytes()[:-1])
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match="size/hash"):
        ete.verify_assets(tmp_path)


def fake_device(monkeypatch, loaded=False, overrides=None, bad_hash=False):
    manifest, _ = ete.verify_assets()
    state = {"loaded": loaded, "commands": [], "pushes": []}
    facts = {"getprop ro.product.device": manifest["device"],
             "uname -r": manifest["kernel"],
             "getprop ro.build.fingerprint": manifest["fingerprint"],
             "getenforce": "Enforcing", "id": "uid=0(root)",
             "cat /proc/sys/kernel/modules_disabled": "0"}
    facts.update(overrides or {})

    def shell(adb, serial, command, root=True, timeout=30):
        state["commands"].append(command)
        assert root
        if command in facts:
            return 0, facts[command]
        if command == "cat /proc/modules":
            return 0, "coresight 156800 0 - Live 0x0\n" + (
                "coresight_etm4x 1647368 0 - Live 0x0\n" if state["loaded"] else "")
        if command == ete.STATUS_COMMAND:
            return 0, "INITSTATE=live\nBOOT_ENABLE=0\nPM_SAVE_ENABLE=1\n" + "".join(
                "SOURCE%d=0\n" % n for n in range(8))
        if command.startswith("sha256sum"):
            return 0, ("0" * 64 if bad_hash else manifest["module_sha256"]) + "  " + ete.REMOTE
        if command.startswith("chmod"):
            return 0, ""
        if command.startswith("insmod"):
            state["loaded"] = True
            return 0, ""
        pytest.fail("unexpected command: " + command)

    def run(command, timeout=30):
        assert "push" in command
        state["pushes"].append(command)
        return 0, "pushed"

    monkeypatch.setattr(ete, "device_shell", shell)
    monkeypatch.setattr(ete, "run", run)
    return state


def test_default_unloaded_is_read_only(monkeypatch):
    state = fake_device(monkeypatch)
    manifest, path = ete.verify_assets()
    data = ete.ensure_module("adb", "fixture", manifest, path)
    assert not data["loaded"] and data["action"] == "read_only"
    assert not state["pushes"]
    assert not any(cmd.startswith(("chmod", "insmod")) for cmd in state["commands"])


def test_loaded_not_reloaded(monkeypatch):
    state = fake_device(monkeypatch, loaded=True)
    manifest, path = ete.verify_assets()
    data = ete.ensure_module("adb", "fixture", manifest, path, load=True)
    assert data["idle"]
    assert not state["pushes"]
    assert not any("insmod" in cmd for cmd in state["commands"])


def test_explicit_load_gates_and_checks_sources(monkeypatch):
    state = fake_device(monkeypatch)
    manifest, path = ete.verify_assets()
    data = ete.ensure_module("adb", "fixture", manifest, path, load=True)
    assert data["loaded"] and data["idle"] and data["action"] == "loaded"
    assert len(state["pushes"]) == 1
    loads = [cmd for cmd in state["commands"] if cmd.startswith("insmod")]
    assert loads == ["insmod %s boot_enable=0 pm_save_enable=1" % ete.REMOTE]


@pytest.mark.parametrize("command,value", [
    ("uname -r", "different-kernel"), ("getprop ro.product.device", "other-device"),
    ("getprop ro.build.fingerprint", "updated-system"), ("getenforce", "Permissive"),
    ("id", "uid=2000(shell)"), ("cat /proc/sys/kernel/modules_disabled", "1"),
])
def test_baseline_mismatch_never_pushes(monkeypatch, command, value):
    state = fake_device(monkeypatch, overrides={command: value})
    manifest, path = ete.verify_assets()
    with pytest.raises(RuntimeError):
        ete.ensure_module("adb", "fixture", manifest, path, load=True)
    assert not state["pushes"]


def test_remote_hash_mismatch_never_insmods(monkeypatch):
    state = fake_device(monkeypatch, bad_hash=True)
    manifest, path = ete.verify_assets()
    with pytest.raises(RuntimeError, match="hash mismatch"):
        ete.ensure_module("adb", "fixture", manifest, path, load=True)
    assert not any(cmd.startswith("insmod") for cmd in state["commands"])


def test_source_missing_or_params_wrong(monkeypatch):
    monkeypatch.setattr(ete, "checked_shell", lambda *a, **kw:
                        "INITSTATE=live\nBOOT_ENABLE=0\nPM_SAVE_ENABLE=1\nSOURCE0=0\n")
    with pytest.raises(RuntimeError, match="source status"):
        ete.verify_loaded("adb", "fixture")


def test_published_binary_exception_is_hash_and_path_bound(tmp_path):
    root = SCRIPTS.parents[2]
    spec = importlib.util.spec_from_file_location("ete_repo_check", root / "check_repo.py")
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    assert gate.reviewed_binary_excludes(str(root)) == [gate.PUBLIC_BINARY]
    assert gate.reviewed_binary_excludes(str(tmp_path)) == []
    path = tmp_path / gate.PUBLIC_BINARY
    path.parent.mkdir(parents=True)
    path.write_bytes(b"changed artifact")
    assert gate.reviewed_binary_excludes(str(tmp_path)) == []
