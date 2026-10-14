"""Install-independent ETE assets and synthetic regressions; no device or real APK."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

SKILL = Path(__file__).resolve().parents[2] / "skills" / "apk-reverse"
ASSETS = SKILL / "assets" / "ete" / "socrates-5.15.41"
HISTORICAL_LIMIT = "小过滤样本仍只有 NO_SYNC，具体原因未闭合；成功样本也存在 reset/overflow 缺口。因此当前验证的是真实指令区间，不是无缺口完整执行路径或业务语义。"
LIMIT = "文件过滤的 VMA 边界误匹配已修复，零 AUX 的独立启停问题由 ete_record.py 修正；持久部署后 30ms/150ms 六次采集均有真实解码区间。仍有 reset/overflow 缺口，历史失败 trace 未恢复，不是无缺口完整执行路径或业务语义。"


def run(argv, cwd):
    env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8", PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run([sys.executable, *map(str, argv)], cwd=cwd, env=env,
                            capture_output=True, text=True, encoding="utf-8", timeout=90)
    assert result.returncode == 0, result.stdout + result.stderr
    return result


def install(tmp_path):
    """Only shipped assets and wrappers, with no project/repository search path."""
    dest = tmp_path / "installed"
    shutil.copytree(ASSETS, dest / "assets" / "ete" / "socrates-5.15.41",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (dest / "scripts").mkdir()
    for name in ("ete_decode.py", "ete_target_manifest.py", "ete_addr_space.py", "ete_addr_filter.py", "ete_record.py"):
        shutil.copy2(SKILL / "scripts" / name, dest / "scripts" / name)
    return dest


@pytest.mark.parametrize("name", ["ete_decode.py", "ete_target_manifest.py", "ete_addr_space.py", "ete_addr_filter.py", "ete_record.py"])
def test_installed_cli_help(tmp_path, name):
    dest = install(tmp_path)
    result = run(["-I", dest / "scripts" / name, "--help"], tmp_path)
    assert "usage:" in result.stdout


def test_installed_offline_regressions(tmp_path):
    dest = install(tmp_path)
    backend = dest / "assets" / "ete" / "socrates-5.15.41" / "decode"
    result = run(["-I", "-m", "unittest", "discover", "-s", backend, "-p", "test_ete_decode.py", "-v"], tmp_path)
    assert "Ran 29 tests" in result.stderr
    assert "OK" in result.stderr
    result = run(["-I", "-m", "unittest", "discover", "-s", backend, "-p", "test_ete_addr_filter.py", "-v"], tmp_path)
    assert "Ran 10 tests" in result.stderr
    assert "OK" in result.stderr
    result = run(["-I", "-m", "unittest", "discover", "-s", backend, "-p", "test_ete_record.py", "-v"], tmp_path)
    assert "Ran 6 tests" in result.stderr
    assert "OK" in result.stderr


def test_installed_manifest_address_flow(tmp_path):
    dest = install(tmp_path)
    backend = dest / "assets" / "ete" / "socrates-5.15.41" / "decode"
    # Build wholly synthetic ELF/maps using shipped fixtures in a separate interpreter.
    script = ("import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); "
              "import ete_test_fixtures as f; blob,_=f.mkelf(); "
              "Path('libfoo.so').write_bytes(blob); "
              "Path('capture.maps').write_text(f.maps_text(0x10000000),encoding='utf8')")
    run(["-I", "-c", script, backend], tmp_path)
    manifest_dir = tmp_path / "manifest"
    result = run(["-I", dest / "scripts" / "ete_target_manifest.py", "--elf", tmp_path / "libfoo.so",
                  "--out-dir", manifest_dir, "--json"], tmp_path)
    manifest = json.loads(result.stdout)
    assert len(manifest["targets"]) == 1
    assert manifest["targets"][0]["sha256"] == hashlib.sha256((tmp_path / "libfoo.so").read_bytes()).hexdigest()
    assert not (manifest_dir / "libfoo.so").exists()  # --elf does not extract/copy it.
    result = run(["-I", dest / "scripts" / "ete_addr_space.py", "--manifest", manifest_dir / "target-manifest.json",
                  "--maps", tmp_path / "capture.maps", "--elf-dir", tmp_path, "--module", "libfoo.so",
                  "--address", "0x10000100", "--json"], tmp_path)
    assert '"resolved"' in result.stdout
    assert '"unclosed"' not in result.stdout
    # A plain file-backed path is required for the hardware filter fallback.
    (tmp_path / "capture.maps").write_text(
        (tmp_path / "capture.maps").read_text(encoding="utf8").replace(
            "/data/app/x/base.apk!/lib/arm64-v8a/libfoo.so", "/system/lib64/libfoo.so"), encoding="utf8")
    result = run(["-I", dest / "scripts" / "ete_addr_filter.py", "--manifest", manifest_dir / "target-manifest.json",
                  "--maps", tmp_path / "capture.maps", "--elf-dir", tmp_path, "--module", "libfoo.so",
                  "--start-vaddr", "0x100", "--end-vaddr", "0x108", "--json"], tmp_path)
    planned = json.loads(result.stdout)
    assert planned["coverage_complete"]
    assert planned["addr_filter"] == "filter 0x100-0x108@/system/lib64/libfoo.so"


def test_evidence_and_limits():
    evidence = json.loads((ASSETS / "evidence" / "decode-result.json").read_text(encoding="utf8"))
    assert evidence["limits"] == HISTORICAL_LIMIT  # Preserve measured historical snapshot.
    assert evidence["runtime_trace_decoding_verified"] and not evidence["full_trace_verified"]
    target = evidence["reports"]["target"]
    assert (target["instruction_ranges"], target["unique_ranges"]) == (610502, 19918)
    assert sum(target["mapped_range_occurrences"].values()) == target["instruction_ranges"]
    assert sum(target["unique_ranges_in_requested_modules"].values()) == target["unique_ranges"]
    small = evidence["reports"]["small_filtered"]
    assert small["instruction_ranges"] == 0 and small["element_counts"] == {"NO_SYNC": 2163}
    assert small["native_decoder_rc"] == 0 and small["harness_rc"] == 1
    for report in evidence["reports"].values():
        assert not report["full_trace_verified"]
        assert sum(report["no_sync_reasons"].values()) == report["element_counts"]["NO_SYNC"]
        assert len(report["source_sha256"]) == 64
    matrix = json.loads((SKILL / "evidence" / "capability-matrix.json").read_text(encoding="utf8"))
    row = next(r for r in matrix["capabilities"] if r["capability"] == "socrates-ete-native-range-decoding")
    assert row["route_measured"] and not row["full_trace_verified"] and LIMIT in row["limits"]
    assert all((SKILL / path).exists() for path in row["evidence"])
    assert LIMIT in (SKILL / "references" / "ete-decoding.md").read_text(encoding="utf8")


@pytest.mark.parametrize("rel", [
    "SKILL.md", "references/ete-decoding.md", "references/ete-socrates-module.md",
    "references/arm-tracing-elf-and-crash.md", "references/evidence-summary.md",
    "evidence/known-limitations.md", "evidence/capability-matrix.json",
    "assets/ete/socrates-5.15.41/README.md", "references/coverage-and-limits.md",
    "../../README.md", "../../README.zh-CN.md",
])
def test_current_guidance_does_not_repeat_obsolete_filtered_failure(rel):
    text = (SKILL / rel).read_text(encoding="utf8")
    assert "原因未闭合" not in text
    assert "perf-filter-deployment.json" in text or "持久部署" in text or "persistently deployed" in text
    assert "overflow" in text.lower()
    assert "filtered sample remains NO_SYNC-only" not in text


def test_asset_inventory_complete_and_identity_preserved():
    entries = {}
    for line in (ASSETS / "SHA256SUMS.txt").read_text(encoding="utf8").splitlines():
        digest, rel = line.split("  ", 1)
        assert rel not in entries
        entries[rel] = digest
        assert hashlib.sha256((ASSETS / rel).read_bytes()).hexdigest() == digest
    actual = {p.relative_to(ASSETS).as_posix() for p in ASSETS.rglob("*")
              if p.is_file() and "__pycache__" not in p.parts and p.name != "SHA256SUMS.txt"}
    assert set(entries) == actual
    assert entries["module/coresight-etm4x.ko"] == "285f8be46dbba1003d5b2d1c0bfb32c7d4dcbc81397145c428adf4ded1960fb4"
    old = json.loads((ASSETS / "manifest.json").read_text(encoding="utf8"))
    assert not old["instruction_path_decoding_verified"]
