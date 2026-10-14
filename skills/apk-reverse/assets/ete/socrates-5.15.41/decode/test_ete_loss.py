import re
import struct
import tempfile
from pathlib import Path
import unittest

import ete_direct_record as direct
import ete_loss as loss

KIND = re.compile(r"^Idx:(\d+); ID:([0-9a-fA-F]+); (OCSD_GEN_TRC_ELEM_[A-Z_]+)")


class LossTests(unittest.TestCase):
    def perf(self, flags=0, offset=0, lost=False):
        attr = bytearray(136)
        struct.pack_into("<Q", attr, 24, 128)
        struct.pack_into("<Q", attr, 40, 1 << 18)
        events = direct.record_header(11, struct.pack("<QQQII", offset, 16, flags, 0, 0))
        if lost:
            events += direct.record_header(2, struct.pack("<QQ", 1, 9))
        return direct.package(bytes(attr), events, bytes(range(16)), "", 1, bytes(32))

    def audit(self, data):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "trace.perf"
            path.write_bytes(data)
            return loss.perf_loss(path)

    def test_clear_flags_and_payload(self):
        self.assertTrue(self.audit(self.perf())["perf_loss_markers_clear"])

    def test_every_nonzero_flag_rejected(self):
        for flag in (1, 2, 4, 8, 16, 256, 1 << 63):
            with self.subTest(flag=flag):
                self.assertFalse(self.audit(self.perf(flag))["perf_loss_markers_clear"])

    def test_lost_record_rejected(self):
        self.assertFalse(self.audit(self.perf(lost=True))["perf_loss_markers_clear"])

    def test_missing_or_noncontiguous_aux_rejected(self):
        self.assertFalse(self.audit(self.perf(offset=16))["perf_loss_markers_clear"])

    def test_invalid_record_bounds_rejected(self):
        data = bytearray(self.perf())
        struct.pack_into("<Q", data, 48, len(data))
        with self.assertRaises(ValueError):
            self.audit(data)

    def elements(self, lines):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "elements.txt"
            path.write_text("\n".join(lines))
            return loss.audit_elements(path, KIND)

    def test_only_initial_zero_reset_allowed(self):
        lines = ["Idx:0; ID:1; OCSD_GEN_TRC_ELEM_NO_SYNC( [reset-decoder])",
                 "Idx:30; ID:1; OCSD_GEN_TRC_ELEM_INSTR_RANGE(any)"]
        self.assertTrue(self.elements(lines)["element_loss_markers_clear"])
        lines += ["Idx:100; ID:1; OCSD_GEN_TRC_ELEM_NO_SYNC( [reset-decoder])"]
        self.assertFalse(self.elements(lines)["element_loss_markers_clear"])

    def test_overflow_bad_packet_and_address_gap_rejected(self):
        for line in ("NO_SYNC( [overflow])", "NO_SYNC( [bad-packet])", "ADDR_NACC(x)"):
            result = self.elements(["Idx:1; ID:1; OCSD_GEN_TRC_ELEM_INSTR_RANGE(x)",
                                    "Idx:2; ID:1; OCSD_GEN_TRC_ELEM_" + line])
            self.assertFalse(result["element_loss_markers_clear"])

    def test_missing_execution_and_nonzero_initial_reset_rejected(self):
        self.assertFalse(self.elements([])["element_loss_markers_clear"])
        self.assertFalse(self.elements(["Idx:50; ID:1; OCSD_GEN_TRC_ELEM_NO_SYNC( [reset-decoder])",
                                        "Idx:60; ID:1; OCSD_GEN_TRC_ELEM_INSTR_RANGE(x)"])
                         ["element_loss_markers_clear"])

    def test_package_aux_payload_and_index_preserved(self):
        data = self.perf()
        offset, size = struct.unpack_from("<QQ", data, 40)
        feature_offset, feature_size = struct.unpack_from("<QQ", data, offset + size)
        self.assertEqual(feature_size, 16)
        record_offset, header_size = struct.unpack_from("<QQ", data, feature_offset)
        self.assertEqual(header_size, 48)
        self.assertEqual(data[record_offset + 48:record_offset + 64], bytes(range(16)))

    def test_payload_offset_and_cpu_mismatch_rejected(self):
        for value, field in ((8, 16), (4, 40)):
            data = bytearray(self.perf())
            offset, size = struct.unpack_from("<QQ", data, 40)
            feature_offset = struct.unpack_from("<Q", data, offset + size)[0]
            record_offset = struct.unpack_from("<Q", data, feature_offset)[0]
            struct.pack_into("<Q" if field == 16 else "<I", data, record_offset + field, value)
            self.assertFalse(self.audit(data)["perf_loss_markers_clear"])

    def test_unknown_and_malformed_elements_rejected(self):
        for text in ("Idx:broken; OCSD_GEN_TRC_ELEM_INSTR_RANGE(x)",
                     "Idx:2; ID:1; OCSD_GEN_TRC_ELEM_UNKNOWN(x)"):
            self.assertFalse(self.elements(["Idx:1; ID:1; OCSD_GEN_TRC_ELEM_INSTR_RANGE(x)", text])
                             ["element_loss_markers_clear"])

    def test_reset_source_identity_is_numeric(self):
        self.assertFalse(self.elements([
            "Idx:0; ID:01; OCSD_GEN_TRC_ELEM_INSTR_RANGE(x)",
            "Idx:0; ID:1; OCSD_GEN_TRC_ELEM_NO_SYNC( [reset-decoder])"])
            ["element_loss_markers_clear"])


if __name__ == "__main__":
    unittest.main()
