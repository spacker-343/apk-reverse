"""Guarded kernel source generation contracts, independent of the real source tree."""
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "skills/apk-reverse/assets/ete/socrates-5.15.41/build/perf-fix"
spec = importlib.util.spec_from_file_location("perf_fix", FIX / "apply_perf_fix.py")
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def test_unknown_source_refused():
    with pytest.raises(ValueError, match="unexpected core.c"):
        P.generate(b"not the official source")


def test_generator_only_replaces_function(monkeypatch):
    original = b"header\n" + P.BEGIN + b"old body\n}\n" + P.END + b"unchanged tail\n"
    begin, end = original.index(P.BEGIN), original.index(P.END)
    monkeypatch.setattr(P, "SOURCE_SHA256", hashlib.sha256(original).hexdigest())
    monkeypatch.setattr(P, "FUNCTION_SHA256", hashlib.sha256(original[begin:end]).hexdigest())
    fixed = P.generate(original)
    assert fixed.startswith(original[:begin]) and fixed.endswith(original[end:])
    assert b"filter->offset - offset < size" in fixed
    assert b"filter->size > offset - filter->offset" in fixed
    assert b"old body" not in fixed


def test_cli_same_path_protects_input(tmp_path):
    source = tmp_path / "core.c"
    source.write_bytes(b"preserve")
    result = subprocess.run([sys.executable, FIX / "apply_perf_fix.py", "--source", source,
                             "--output", source], capture_output=True, text=True, timeout=20)
    assert result.returncode == 2 and "read-only" in result.stderr
    assert source.read_bytes() == b"preserve"


def test_cli_unknown_source_preserves_existing_output(tmp_path):
    source, output = tmp_path / "source.c", tmp_path / "output.c"
    source.write_bytes(b"unknown")
    output.write_bytes(b"preserve")
    result = subprocess.run([sys.executable, FIX / "apply_perf_fix.py", "--source", source,
                             "--output", output], capture_output=True, text=True, timeout=20)
    assert result.returncode == 2
    assert source.read_bytes() == b"unknown" and output.read_bytes() == b"preserve"


def test_repair_evidence_does_not_claim_device_fixed():
    import json
    evidence = json.loads((FIX.parents[1] / "evidence/perf-filter-repair.json").read_text(encoding="utf8"))
    assert not evidence["runtime_kernel_repair_verified"] and not evidence["full_trace_verified"]
    assert evidence["module_unchanged"] and evidence["source"]["micode_and_ack_core_byte_identical"]
    assert evidence["source"]["original_core_sha256"] == P.SOURCE_SHA256
    assert evidence["host_c_regression"]["random_checks"] == 50000
    assert evidence["kbuild"]["status"] == "full_image_built"
    assert evidence["kbuild"]["last_completed_full_image_attempt"]["returncode"] == 0
    assert evidence["kbuild"]["image"]["sha256"] == "43306d8330674e5a66da1102ab5f08257709e4ed991a4e709a7b56811b785f33"
    exports = evidence["kbuild"]["static_stock_export_comparison"]
    assert exports["all_crc_type_namespace_match"] and exports["stock"] == exports["built"] == 7029
    assert not evidence["kbuild"]["stock_vendor_abi_compatibility_verified"]
    integrity = evidence["kbuild"]["archive_regular_file_verification"]
    assert integrity == {"checked": 73852, "complete": True, "only_expected_core_patch_differs": True}
    assert evidence["kbuild"]["whole_output_recreated_case_sensitive_with_backup"]
    assert not evidence["deployment"]["attempted"]


def test_deployment_evidence_separates_boot_comparator_and_trace():
    import json
    evidence = json.loads((FIX.parents[1] / "evidence/perf-filter-deployment.json").read_text(encoding="utf8"))
    deployment = evidence["deployment"]
    assert deployment["attempted"] and deployment["android_boot_completed"]
    assert deployment["runtime_btf_equals_built_vmlinux"]
    assert deployment["persistent_flash_attempted"] and deployment["partition_writes"]
    assert deployment["written_partitions"] == ["boot_a"] and deployment["persistent_flash_success"]
    assert deployment["normal_reboot_persistence_verified"] and deployment["persistent_android_boot_checks"] == 2
    assert deployment["other_four_backed_up_partitions_unchanged"] and deployment["boot_a_partition_equals_candidate"]
    assert not deployment["slot_changed"] and not deployment["full_vendor_abi_verified"]
    assert evidence["runtime_comparator_boundary_fix_verified"]
    assert evidence["runtime_kernel_repair_verified"]
    assert evidence["boundary_execution_decode_verified"] and not evidence["full_trace_verified"]
    controls = evidence["controls"]
    boundary = controls["boundary"]
    expected_size = int(boundary["file_end_exclusive"], 16) - int(boundary["file_start"], 16)
    assert controls["valid_pairs"] == 2
    assert boundary["comparator_sizes_after_patch"] == [expected_size] * 2
    assert boundary["historical_decode_returncodes"] == [2, 2] and not boundary["verified_instruction_ranges"]
    assert boundary["corrected_decode_status"] == "no_aux_data" and boundary["aux_bytes"] == [0, 0]
    assert controls["interior"]["instruction_ranges"] == [437857, 440138]
    assert controls["interior"]["all_ranges_mapped_to_requested_shell_elf"]
    assert all(controls["interior"]["no_sync_overflow"])
    baseline = evidence["health_baseline_comparison"]
    assert baseline["failed_module_name_sets_equal"] and baseline["warning_sites_and_counts_equal"]
    assert baseline["rebuilt_kernel_split_btf_failed_modules"] == baseline["original_kernel_split_btf_failed_modules"]
    final = evidence["final_device"]
    assert final["persistent_repaired_kernel_active"] and not final["temporary_repaired_kernel_active"]
    assert not final["original_kernel_restored_by_normal_reboot"] and not final["all_five_backed_up_partitions_unchanged"]
    assert final["only_boot_a_updated_other_four_unchanged"]
    assert final["source_enable"] == [0] * 8 and not final["autoload_configured"]
    assert final["remote_packaging_and_capture_staging_cleaned"]
    second = evidence["second_trial_boundary"]
    assert second["instruction_ranges"] == 433583 and second["comparator_size"] == expected_size
    repair = evidence["capture_lifecycle_repair"]
    assert not repair["system_simpleperf_replaced"] and not repair["target_thread_stopped_or_killed_by_entry_point"]
    latest = repair["initial_restart_and_final_flush_test"]
    assert latest["durations_seconds"] == [0.15, 0.03] * 3
    assert len(latest["instruction_ranges"]) == 6 and all(latest["instruction_ranges"]) and all(latest["aux_bytes"])
    assert latest["all_capture_and_decode_returncodes_zero"] and latest["all_acknowledgements_received"]
    assert latest["all_ranges_mapped_to_requested_shell_elf"] and latest["all_sources_unchanged_and_remote_cleanup"]
    assert latest["a64_size_mismatches_unique"] == [0] * 6 and not latest["full_trace_verified"]
    persistent = evidence["persistent_capture_verification"]
    assert persistent["durations_seconds"] == [0.15, 0.03] * 3
    assert len(persistent["instruction_ranges"]) == 6 and all(persistent["instruction_ranges"])
    assert all(persistent["aux_bytes"]) and persistent["a64_size_mismatches_unique"] == [0] * 6
    assert persistent["all_ranges_mapped_to_requested_shell_elf"] and persistent["all_final_decode_returncodes_zero"]
    assert persistent["all_sources_unchanged_and_remote_cleanup"] and not persistent["full_trace_verified"]
    assert persistent["interrupted_remote_staging_cleaned"] and persistent["same_original_traces_decoded_successfully_on_retry"]
