#!/usr/bin/env python3
"""Offline tests for the bounded socrates repair harness."""
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import ete_decode as D
import ete_test_fixtures as T


def trace_blob(ids=None, cpu=3):
    body = struct.pack('<IIQIIQ', 3, 0, 1, 8, 10, 0)
    for c in range(8):
        sid = ids[c] if ids else 0x10 + 2 * c
        body += struct.pack('<11Q', D.P.MAGIC_ETE, c, 8, 64, sid, 0, 0, 0, 0, 0, 0)
    # One formatted frame, ID4 with an I_ASYNC candidate on source4.
    frame = bytes([2 * (cpu + 1) + 1]) + b'\0' * 11 + b'\x80\0\0\0'
    return T.perf_build([T.perf_record(70, body), T.perf_auxtrace(16, 0, cpu, 42, fill=frame)])


def element(start=0x10000100, end=0x10000108, num=2, sid='4'):
    return (f'Idx:123; ID:{sid}; OCSD_GEN_TRC_ELEM_INSTR_RANGE(exec range={start:#x}:'
            f'[{end:#x}] num_i({num}) last_sz(4) A64:ret)\n')


class TestDecode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('PI_SCRATCH_DIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.src, self.dst = self.root / 'source.perf', self.root / 'fixed.perf'
        self.src.write_bytes(trace_blob())

    def dump(self, text):
        f = self.root / 'elements.txt'
        f.write_text(text, encoding='utf8')
        return f

    def resolver(self, cls=64):
        blob, _ = T.mkelf(cls=cls)
        elf = self.root / 'libfoo.so'
        elf.write_bytes(blob)
        rows, _ = D.A.parse_maps(T.maps_text(0x10000000))
        return D.A.ModuleResolver(T.manifest_for('libfoo.so', blob), rows, 'libfoo.so', elf_path=elf)

    def test_patch_only_metadata_original_unchanged(self):
        original = self.src.read_bytes()
        changes = D.prepare_trace(self.src, self.dst)
        self.assertEqual(8, len(changes))
        self.assertEqual(original, self.src.read_bytes())
        fixed = self.dst.read_bytes()
        rec, body = D.P.find_info_record(original)
        _, entries = D.P.parse_info(body)
        allowed = {rec + 8 + e['offset'] + 8 * D.P.TRCTRACEIDR_WORD + k
                   for e in entries for k in range(8)}
        self.assertTrue(all(a == b or i in allowed for i, (a, b) in enumerate(zip(original, fixed))))
        self.assertEqual(len(original), len(fixed))
        self.assertEqual(list(range(1, 9)), [e['trctraceidr'] for e in D.P.parse_info(D.P.find_info_record(fixed)[1])[1]])
        self.assertEqual(D.P.D.walk_aux_payloads(self.src), D.P.D.walk_aux_payloads(self.dst))

    def test_refuse_same_path_existing_output(self):
        for dst in (self.src, self.dst):
            dst.write_bytes(b'preserve' if dst == self.dst else trace_blob())
            before = dst.read_bytes()
            with self.assertRaises(ValueError):
                D.prepare_trace(self.src, dst)
            self.assertEqual(before, dst.read_bytes())

    def test_accept_already_aligned(self):
        self.src.write_bytes(trace_blob(ids=list(range(1, 9))))
        D.prepare_trace(self.src, self.dst)
        self.assertEqual(self.src.read_bytes(), self.dst.read_bytes())

    def test_refuse_unknown_layout(self):
        self.src.write_bytes(trace_blob(ids=[42] * 8))
        with self.assertRaises(ValueError):
            D.prepare_trace(self.src, self.dst)
        self.assertFalse(self.dst.exists())

    def test_refuse_unobserved_stream_id(self):
        with patch.object(D.P, 'in_stream_ids', return_value={3: 42}):
            with self.assertRaises(ValueError):
                D.prepare_trace(self.src, self.dst)

    def test_refuse_empty_stream(self):
        with patch.object(D.P, 'in_stream_ids', return_value={}):
            with self.assertRaises(ValueError):
                D.prepare_trace(self.src, self.dst)

    def test_async_real_criterion_and_zero_padding(self):
        stream = b'\x0f\0\0\0\xf8' + b'\0' * 50 + D.ASYNC * 2
        result = D.async_scan(stream)
        self.assertEqual(2, result['i_async_candidates'])
        self.assertEqual([55, 67], result['first_offsets'])
        self.assertEqual(0, D.async_scan(b'\0' * 100)['i_async_candidates'])
        self.assertEqual(8, len(D.async_scan(D.ASYNC * 20)['first_offsets']))

    def test_protocol_scan_reports_partial_tail(self):
        with patch.object(D.P.D, 'walk_aux_payloads', return_value=[(b'\0' * 19, 0, 3)]):
            result = D.protocol_scan(self.src)
        self.assertEqual(3, result['unprocessed_tail_bytes'])
        self.assertEqual(19, result['payload_records'][0]['payload_bytes'])

    def test_protocol_scan_uses_deframed_source(self):
        result = D.protocol_scan(self.src)
        self.assertEqual(1, result['i_async_candidates'])
        self.assertEqual(4, result['records'][0]['trace_id'])

    def test_protocol_scan_never_bridges_records(self):
        payloads = [(b'1' * 16, 0, 3), (b'2' * 16, 1, 3)]
        def unpack(frame, cur):
            stream = b'\0' * 11 if frame[0] == 49 else b'\x80'
            return [(4, b) for b in stream], 4
        with patch.object(D.P.D, 'walk_aux_payloads', return_value=payloads), patch.object(D.P.D, 'unpack_frame', side_effect=unpack):
            self.assertEqual(0, D.protocol_scan(self.src)['i_async_candidates'])

    def test_summary_counts_entire_dump_and_unique(self):
        text = 'Idx:1; ID:4; OCSD_GEN_TRC_ELEM_NO_SYNC(overflow)\n' + element() * 3 + element(sid='5')
        result = D.summarise(self.dump(text))
        self.assertEqual(4, result['instruction_ranges'])
        self.assertEqual(1, result['unique_ranges'])
        self.assertEqual(3, result['per_trace_id']['4']['INSTR_RANGE'])
        self.assertEqual(1, result['element_counts']['NO_SYNC'])
        self.assertFalse(result['full_trace_verified'])
        self.assertEqual({'overflow': 1}, result['no_sync_reasons'])
        self.assertFalse(result['address_validation_requested'])

    def test_summary_verified_coordinate_and_bytes(self):
        r = self.resolver()
        result = D.summarise(self.dump(element() * 2), [r])
        self.assertEqual({'libfoo.so': 2}, result['mapped_range_occurrences'])
        sample = result['verified_samples'][0]
        self.assertEqual('0x100', sample['link_vaddr'])
        self.assertEqual('0x00000100', sample['file_offset'])
        self.assertEqual('00000000', sample['last_word'])
        self.assertEqual(64, len(sample['range_bytes_sha256']))

    def test_summary_invalid_ranges_not_verified(self):
        text = element(num=3) + element(end=0x10000100) + element(start=0x10000102) + element(end=0x10002004, num=1985)
        result = D.summarise(self.dump(text), [self.resolver()])
        self.assertEqual(3, result['a64_size_mismatches_unique'])
        self.assertEqual([], result['verified_samples'])

    def test_summary_a32_never_disassembled(self):
        with patch.object(D.A, 'disassemble_a64') as dis:
            self.assertEqual([], D.summarise(self.dump(element()), [self.resolver(32)])['verified_samples'])
            dis.assert_not_called()

    def test_summary_malformed_and_errors(self):
        text = 'Idx:1; ID:4; OCSD_GEN_TRC_ELEM_INSTR_RANGE(bad)\nOCSD_ERR_INVALID_PCKT_HDR\n'
        result = D.summarise(self.dump(text))
        self.assertEqual(1, result['malformed_range_lines'])
        self.assertEqual(0, result['instruction_ranges'])
        self.assertEqual({'OCSD_ERR_INVALID_PCKT_HDR': 1}, result['decoder_error_mentions'])

    def args(self):
        return SimpleNamespace(out_dir=self.root / 'out', trace=self.src, serial='fake', adb='fake-adb', timeout=1,
                               module=[], maps=None, manifest=None, elf_dir=None)

    def run_fake(self, stage=None, output=None):
        calls = []
        def fake(adb, serial, args, timeout, **kwargs):
            calls.append(args)
            if args[:2] == ['shell', '-T']:
                kwargs['stdout'].write((output or element()).encode())
                if stage == 'decode':
                    raise subprocess.TimeoutExpired(args, timeout)
            if args[0] == 'push' and stage == 'push':
                raise RuntimeError('push failed')
            if 'rmdir' in args[-1] and stage == 'cleanup':
                raise RuntimeError('cleanup failed')
            return SimpleNamespace(stdout=b'uid=0 5.15.41-android13-8-00015-gde2a4c25826b-ab9439604 Enforcing', stderr=b'')
        with patch.object(D, 'run_adb', side_effect=fake), contextlib.redirect_stdout(io.StringIO()):
            rc = D.decode(self.args())
        report = json.loads((self.root / 'out' / 'decode.json').read_text(encoding='utf8'))
        return rc, report, calls

    def test_decode_success_and_cleanup(self):
        rc, report, _ = self.run_fake()
        self.assertEqual(0, rc)
        self.assertTrue(report['source_unchanged'])
        self.assertTrue(report['remote_cleanup'])
        self.assertEqual('decoded_ranges', report['status'])

    def test_decode_no_ranges_not_success(self):
        rc, report, _ = self.run_fake(output='Idx:1; ID:4; OCSD_GEN_TRC_ELEM_NO_SYNC(overflow)\n')
        self.assertEqual(1, rc)
        self.assertEqual('no_instruction_ranges', report['status'])

    def test_decode_push_failure_cleans_upload(self):
        rc, report, _ = self.run_fake(stage='push')
        self.assertEqual(2, rc)
        self.assertTrue(report['remote_cleanup'])
        self.assertTrue(report['source_unchanged'])

    def test_decode_timeout_still_cleans_and_reports(self):
        rc, report, _ = self.run_fake(stage='decode')
        self.assertEqual(2, rc)
        self.assertTrue(report['remote_cleanup'])
        self.assertIn('error', report)

    def test_decode_cleanup_failure_not_success(self):
        rc, report, _ = self.run_fake(stage='cleanup')
        self.assertEqual(2, rc)
        self.assertFalse(report['remote_cleanup'])

    def test_decode_invalid_trace_report_not_traceback(self):
        self.src.write_bytes(b'PERFILE2')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(2, D.decode(self.args()))
        report = json.loads((self.root / 'out' / 'decode.json').read_text(encoding='utf8'))
        self.assertEqual('unavailable', report['status'])
        self.assertTrue(report['source_unchanged'])

    def test_decode_missing_source_report(self):
        self.src.unlink()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(2, D.decode(self.args()))
        self.assertTrue((self.root / 'out' / 'decode.json').exists())

    def test_decode_refuses_existing_directory(self):
        (self.root / 'out').mkdir()
        with self.assertRaises(FileExistsError):
            D.decode(self.args())


if __name__ == '__main__':
    unittest.main()
