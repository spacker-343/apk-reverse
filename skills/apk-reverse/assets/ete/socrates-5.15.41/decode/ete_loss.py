"""Fail-closed loss-marker audit; marker clearance is not a complete-path proof."""
import struct


def perf_loss(path):
    data = path.read_bytes()
    if len(data) < 104 or data[:8] != b"PERFILE2":
        raise ValueError("invalid perf header")
    attr_size, attr_pos, attr_bytes = struct.unpack_from("<QQQ", data, 16)
    sample_type, sample_all = None, False
    if attr_bytes:
        if attr_size < 64 or attr_bytes != attr_size or attr_pos + attr_bytes > len(data):
            raise ValueError("single valid perf attribute required for loss audit")
        sample_type = struct.unpack_from("<Q", data, attr_pos + 24)[0]
        sample_all = bool(struct.unpack_from("<Q", data, attr_pos + 40)[0] & (1 << 18))
    pos, size = struct.unpack_from("<QQ", data, 40)
    end = pos + size
    if pos < 104 or end > len(data):
        raise ValueError("invalid perf data bounds")
    aux, lost, payloads = [], [], []
    while pos < end:
        if pos + 8 > end:
            raise ValueError("short perf record")
        typ, _misc, length = struct.unpack_from("<IHH", data, pos)
        if length < 8 or pos + length > end:
            raise ValueError("invalid perf record bounds")
        advance = length
        if typ == 11:
            if length < 32:
                raise ValueError("short AUX record")
            offset, count, flags = struct.unpack_from("<QQQ", data, pos + 8)
            cpu = None
            if sample_all and sample_type is not None and sample_type & 128:
                trailer = 8 * sum(bool(sample_type & bit) for bit in (2, 4, 64, 512, 128, 65536))
                if length < 32 + trailer:
                    raise ValueError("short AUX sample-id trailer")
                cpu_pos = pos + length - (16 if sample_type & 65536 else 8)
                cpu = struct.unpack_from("<I", data, cpu_pos)[0]
            aux.append({"cpu": cpu, "offset": offset, "bytes": count, "flags": flags})
        elif typ in (2, 13):
            lost.append(typ)
        elif typ == 71:
            if length != 48:
                raise ValueError("invalid AUXTRACE header")
            count, offset = struct.unpack_from("<QQ", data, pos + 8)
            cpu = struct.unpack_from("<I", data, pos + 40)[0]
            advance += (count + 7) & ~7
            if pos + advance > end:
                raise ValueError("short AUX payload")
            payloads.append({"cpu": cpu, "offset": offset, "bytes": count})
        pos += advance
    if pos != end:
        raise ValueError("perf records do not fill data section")

    def coverage(rows):
        ends, valid = {}, bool(rows)
        for row in rows:
            cpu = row["cpu"]
            valid &= (cpu is not None and row["bytes"] > 0
                      and row["offset"] == ends.get(cpu, 0)
                      and row["offset"] + row["bytes"] < 1 << 64)
            ends[cpu] = row["offset"] + row["bytes"]
        return ends, bool(valid)

    # Match ordered, non-overlapping coverage separately for every CPU. Equal total
    # byte counts alone would accept duplicate payloads, wrong CPUs or offset holes.
    aux_ends, contiguous = coverage(aux)
    payload_ends, payload_contiguous = coverage(payloads)
    flags_clear = bool(aux) and all(row["flags"] == 0 and row["bytes"] > 0 for row in aux)
    matched = contiguous and payload_contiguous and aux_ends == payload_ends
    return {"aux_records": aux, "lost_record_types": lost, "aux_payload_records": payloads,
            "aux_payload_bytes": sum(row["bytes"] for row in payloads),
            "aux_flags_clear": flags_clear, "aux_offsets_contiguous": contiguous,
            "aux_payload_accounted": matched,
            "perf_loss_markers_clear": flags_clear and matched and not lost}


def audit_elements(path, kind_pattern):
    initial, gaps, gap_count, errors, ranges, malformed = 0, [], 0, 0, 0, 0
    seen = set()
    allowed = {"NO_SYNC", "TRACE_ON", "EO_TRACE", "PE_CONTEXT", "INSTR_RANGE",
               "EXCEPTION", "EXCEPTION_RET", "TIMESTAMP", "CYCLE_COUNT", "EVENT",
               "SWTRACE", "SYNC_MARKER", "MEMTRANS", "CUSTOM"}
    with path.open(encoding="utf8", errors="replace") as fh:
        for line in fh:
            if "OCSD_ERR_" in line or "\ufffd" in line:
                errors += 1
            match = kind_pattern.match(line)
            if not match:
                malformed += "OCSD_GEN_TRC_ELEM_" in line or line.startswith("Idx:")
                continue
            idx, sid, raw = int(match[1]), int(match[2], 16), match[3]
            kind = raw.removeprefix("OCSD_GEN_TRC_ELEM_")
            at_start = sid not in seen
            seen.add(sid)
            ranges += kind == "INSTR_RANGE"
            if kind == "NO_SYNC" and at_start and idx == 0 and "[reset-decoder]" in line:
                initial += 1
                continue
            if kind == "NO_SYNC" or kind not in allowed:
                gap_count += 1
                if len(gaps) < 12:
                    gaps.append({"trace_index": idx, "trace_id": hex(sid), "kind": kind,
                                 "text": line.strip()[:400]})
    return {"initial_resets": initial, "interior_gap_count": gap_count,
            "gap_examples": gaps, "decoder_errors": errors, "malformed_element_lines": malformed,
            "instruction_ranges": ranges,
            "element_loss_markers_clear": ranges > 0 and gap_count == 0 and errors == 0 and malformed == 0,
            "limits": "An initial reset is permitted only at index zero before any source element. "
                      "No exact endpoint, all instructions, data values or business semantics are certified."}
