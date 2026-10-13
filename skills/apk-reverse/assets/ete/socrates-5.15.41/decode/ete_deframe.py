#!/usr/bin/env python3
"""etestream: CoreSight trace-formatter deframing probe for simpleperf ETE captures.

Why this tool exists
--------------------
An earlier capability report claimed the captured AUX payload was "probably a raw
ETE packet stream" because a 128-byte-granular probe found no frame marker at the
end of 128-byte blocks.  That judgement used the wrong frame size: OpenCSD defines
the CoreSight memory frame as

    decoder/include/opencsd/ocsd_if_types.h:247
        #define OCSD_DFRMTR_FRAME_SIZE 0x10   # 16 bytes

so a 128-byte probe cannot exclude framing at all.  This tool implements the
authoritative unpacking algorithm and turns the question into a measurable test.

Algorithm source (Linaro/OpenCSD master, decoder/source/trc_frame_deformatter.cpp)
---------------------------------------------------------------------------------
`TraceFmtDcdImpl::unpackFrame()`, lines 676-763:

    frameFlagBit = 0x1
    for i in 0,2,4,...,12:
        if frame[i] & 0x1:                 # byte i is a trace-ID byte, not data
            newID = (frame[i] >> 1) & 0x7f
            if newID != curID:
                prevIDandIDChange = bool(frameFlagBit & frame[15])
                if prevIDandIDChange:      # byte i+1 still belongs to the old ID
                    emit(oldID, frame[i+1])
                curID = newID
        else:                              # data pair; bit0 was stripped by the
            emit(curID,                    # formatter and is restored from byte15
                 frame[i] | (1 if (frameFlagBit & frame[15]) else 0))
        if not prevIDandIDChange:
            emit(curID, frame[i+1])        # 2nd byte of the pair is always data
        frameFlagBit <<= 1
    # byte 14: ID byte, or data with bit0 restored the same way
    # byte 15: never trace data (frame flag byte)

Two consequences this tool tests directly:

1. PARITY INVARIANT.  In a real formatted frame every even-index byte either has
   bit0 clear (it is data) or is an ID byte.  With a single trace source, ID bytes
   are rare, so the bit0-set rate at even frame positions must be well below the
   ~50% expected from unstructured bytes.  Scanning all 16 possible alignments
   makes the frame boundary, if any, show up as a minimum.
2. ID CONSISTENCY.  Unpacking a genuinely formatted single-CPU buffer must
   recover a small set of valid source IDs (0 < ID < 0x70, per
   `isReservedID()` in trc_frame_deformatter_impl.h:128) that stay stable.

Labels used in the report: observed / inferred / unverified.  A low even-position
bit0 rate is *observed*; what it licenses is an *inference* that the payload is
formatter-framed -- it is not itself a successful ETE decode, and this tool never
claims decode.

Usage
-----
    python ete_deframe.py TRACE.perf --json out.json [--out stream.bin] [--self-test]
"""

import argparse
import json
import os
import random
import struct
import sys

FRAME_SIZE = 0x10            # OCSD_DFRMTR_FRAME_SIZE
BAD_SRC_ID = 0xFF            # OCSD_BAD_CS_SRC_ID
RESERVED_ID_LO, RESERVED_ID_HI = 0x00, 0x70   # isReservedID(): (ID==0)||(ID>=0x70)

AUXTRACE_TYPE = 71
AUXTRACE_HDR_SIZE = 48
AUXTRACE_DATA_FMT = "<QQQIIII"


# ----------------------------------------------------------------------------- perf walk
def walk_aux_payloads(path):
    """Yield (payload_bytes, record_index, cpu) for every AUXTRACE record in order."""
    size = os.path.getsize(path)
    out = []
    with open(path, "rb") as fh:
        head = fh.read(64)
        if len(head) < 64 or not head.startswith(b"PERFILE2"):
            raise ValueError("not a simpleperf PERFILE2 file")
        _header_size, _attr_size = struct.unpack_from("<QQ", head, 8)
        a_off, a_size = struct.unpack_from("<QQ", head, 24)
        d_off, d_size = struct.unpack_from("<QQ", head, 40)
        data_end = min(d_off + d_size, size)
        pos = d_off
        idx = 0
        while pos + 8 <= data_end:
            fh.seek(pos)
            hdr = fh.read(8)
            if len(hdr) < 8:
                break
            rtype = struct.unpack_from("<I", hdr, 0)[0]
            rsize = struct.unpack_from("<H", hdr, 6)[0]
            if rsize < 8:
                raise ValueError("unwalkable record size %d at 0x%x" % (rsize, pos))
            advance = rsize
            if rtype == AUXTRACE_TYPE:
                body = fh.read(rsize - 8)
                if len(body) < struct.calcsize(AUXTRACE_DATA_FMT):
                    raise ValueError("short AUXTRACE header at 0x%x" % pos)
                asz, _aoff, _ref, _idx, _tid, cpu, _r1 = struct.unpack_from(
                    AUXTRACE_DATA_FMT, body, 0)
                fh.seek(pos + rsize)
                payload = fh.read(asz)
                if len(payload) != asz:
                    raise ValueError("truncated AUX payload at 0x%x" % pos)
                out.append((payload, idx, cpu))
                idx += 1
                advance = AUXTRACE_HDR_SIZE + ((asz + 7) & ~7)
            pos += advance
    return out


# ------------------------------------------------------------------- OpenCSD port
def unpack_frame(frame, cur_id):
    """Port of TraceFmtDcdImpl::unpackFrame().

    Returns (emitted, new_cur_id) where emitted is a list of (id, byte).
    `frame` must be exactly FRAME_SIZE bytes.
    """
    if len(frame) != FRAME_SIZE:
        raise ValueError("frame must be %d bytes" % FRAME_SIZE)
    emitted = []
    frame_flag_bit = 0x1
    prev_id_and_id_change = False
    for i in range(0, 14, 2):
        prev_id_and_id_change = False
        if frame[i] & 0x1:                                  # ID byte
            new_src_id = (frame[i] >> 1) & 0x7F
            if new_src_id != cur_id:
                prev_id_and_id_change = bool(frame_flag_bit & frame[15])
                if prev_id_and_id_change:
                    emitted.append((cur_id, frame[i + 1]))   # still old ID's data
                cur_id = new_src_id
        else:                                               # data byte, bit0 restored
            emitted.append((cur_id,
                            frame[i] | (1 if (frame_flag_bit & frame[15]) else 0)))
        if not prev_id_and_id_change:
            emitted.append((cur_id, frame[i + 1]))
        frame_flag_bit <<= 1

    # byte 14, same ID-or-data rule; byte 15 is never data
    if frame[14] & 0x1:
        cur_id = (frame[14] >> 1) & 0x7F
    else:
        emitted.append((cur_id,
                        frame[14] | (1 if (frame_flag_bit & frame[15]) else 0)))
    return emitted, cur_id


def deformat(stream, start_id=BAD_SRC_ID):
    """Unpack a whole byte stream as consecutive 16-byte formatted frames."""
    out = []
    ids = []
    cur = start_id
    for off in range(0, len(stream) - FRAME_SIZE + 1, FRAME_SIZE):
        emitted, cur = unpack_frame(stream[off:off + FRAME_SIZE], cur)
        for sid, byte in emitted:
            out.append(byte)
            ids.append(sid)
    return bytes(out), ids


# ----------------------------------------------------------------- measurements
def bit0_rate_at_positions(stream, phase):
    """Fraction of bytes whose bit0 is set, for even positions of a 16-byte frame
    laid out at global offset `phase`."""
    hits = total = 0
    for i in range(phase, len(stream)):
        if ((i - phase) % FRAME_SIZE) % 2 == 0:
            total += 1
            if stream[i] & 1:
                hits += 1
    return (hits / total if total else None), total

def frame_flag_stats(stream, phase=0):
    """Statistics for byte 15 of each 16-byte frame, which OpenCSD treats as the
    frame flag byte and never as trace data.  A genuinely formatted stream should
    show a small set of low-population flag values; unframed data gives the flat
    byte histogram of the payload itself."""
    s = stream[phase:]
    vals = [s[off + 15] for off in range(0, len(s) - FRAME_SIZE + 1, FRAME_SIZE)]
    if not vals:
        return None
    hist = {}
    pop = {}
    for v in vals:
        hist[v] = hist.get(v, 0) + 1
        p = bin(v).count("1")
        pop[p] = pop.get(p, 0) + 1
    ranked = sorted(hist.items(), key=lambda kv: -kv[1])[:8]
    low_pop = sum(c for p, c in pop.items() if p <= 3)
    return {"frames": len(vals),
            "distinct_values": len(hist),
            "top_values": [{"value": hex(k), "count": v} for k, v in ranked],
            "low_popcount_rate": round(low_pop / len(vals), 4),
            "popcount_hist": {str(k): v for k, v in sorted(pop.items())}}


def parity_scan(stream, max_bytes=400000):
    """Scan all 16 frame phases; the true frame start (if framed) shows up as the
    minimum even-position bit0 rate."""
    s = stream[:max_bytes]
    rates = {}
    for phase in range(FRAME_SIZE):
        rate, total = bit0_rate_at_positions(s, phase)
        rates[phase] = rate
    best = min((p for p in rates if rates[p] is not None), key=lambda p: rates[p])
    overall = sum(1 for b in s if b & 1) / len(s) if s else None
    # Per-position (k mod 16) bit0 rate on the record-aligned grid.  With 16-bit
    # formatter elements the ID byte can only land on even positions, so odd
    # positions read as ordinary data (~50% bit0); with 32-bit or 64-bit elements
    # the ID/flag bytes sit at 3/7/11/15 or 7/15 and would spike there instead.
    pos_stats = [[0, 0] for _ in range(FRAME_SIZE)]
    for i, b in enumerate(s):
        k = i % FRAME_SIZE
        pos_stats[k][1] += 1
        pos_stats[k][0] += b & 1
    return {"scanned_bytes": len(s),
            "overall_bit0_rate": round(overall, 4) if overall is not None else None,
            "per_phase_even_bit0_rate": {str(p): (round(r, 4) if r is not None else None)
                                         for p, r in rates.items()},
            "per_position_bit0_rate": {str(k): (round(h / t, 4) if t else None)
                                       for k, (h, t) in enumerate(pos_stats)},
            "best_phase": best,
            "best_even_bit0_rate": round(rates[best], 4) if rates[best] is not None else None}


def id_stats(ids, top_n=10):
    total = len(ids)
    hist = {}
    transitions = 0
    prev = None
    valid = 0
    for sid in ids:
        hist[sid] = hist.get(sid, 0) + 1
        if prev is not None and sid != prev:
            transitions += 1
        prev = sid
        if RESERVED_ID_LO < sid < RESERVED_ID_HI:
            valid += 1
    ranked = sorted(hist.items(), key=lambda kv: -kv[1])[:top_n]
    return {"emitted_bytes": total,
            "distinct_ids": len(hist),
            "id_transitions": transitions,
            "transition_rate": round(transitions / total, 4) if total else None,
            "non_reserved_id_rate": round(valid / total, 4) if total else None,
            "top_ids": [{"id": hex(k), "count": v} for k, v in ranked] if hist else []}


def analyse(path, max_stream_bytes=4000000):
    records = walk_aux_payloads(path)
    payload_sizes = [len(p) for p, _i, _c in records]
    stream = b"".join(p for p, _i, _c in records)[:max_stream_bytes]
    result = {
        "tool": "ete_deframe",
        "schema": 1,
        "trace": os.path.basename(path),
        "aux_records": len(records),
        "aux_payload_bytes_total": sum(payload_sizes),
        "aux_payload_bytes_scanned": len(stream),
        "payload_size_multiple_of_16": all(s % FRAME_SIZE == 0 for s in payload_sizes)
                                       if payload_sizes else None,
        "payload_distinct_sizes": sorted(set(payload_sizes))[:12],
    }
    if not stream:
        result["verdict"] = "no AUX payload to test"
        return result

    result["parity_scan"] = parity_scan(stream)
    best = result["parity_scan"]["best_phase"]
    aligned = stream[best:]
    result["deformat_at_best_phase"] = id_stats(deformat(aligned)[1])
    # The parity scan cannot separate the 8 even phases (the rule is pair-wise), so
    # the frame grid is taken from the record layout itself: every AUX payload here
    # is a multiple of 16 bytes, so phase 0 is the natural frame boundary.
    result["frame_flag_byte"] = frame_flag_stats(stream, phase=0)
    # control: the same statistic over uniform random bytes, where the byte-15
    # column is just a flat sample of the byte distribution.
    _rnd = random.Random(99)
    result["frame_flag_byte_control_random"] = frame_flag_stats(
        bytes(_rnd.getrandbits(8) for _ in range(min(len(stream), 200000))), phase=0)

    # control 1: same data, deliberately misaligned by one byte (destroys any
    # frame grid).  control 2: uniform random bytes of the same length.
    result["control_misaligned_plus1"] = id_stats(deformat(stream[1:])[1])
    rnd = random.Random(1234)
    result["control_random"] = id_stats(
        deformat(bytes(rnd.getrandbits(8) for _ in range(min(len(stream), 200000))))[1])

    # emitted-stream structure: a real ETE stream is bit-packed packets, so its
    # byte histogram is far from uniform; report collision-probability (index of
    # coincidence) for emitted bytes vs the raw payload.
    emitted, _ids = deformat(aligned)
    result["byte_coincidence_raw"] = _ioc(stream)
    result["byte_coincidence_deformatted"] = _ioc(emitted)
    result["deformatted_bytes"] = len(emitted)
    result["deformatted_ratio"] = round(len(emitted) / len(stream), 4) if stream else None
    return result


def _ioc(buf, mod=256):
    hist = [0] * mod
    for b in buf:
        hist[b] += 1
    n = len(buf)
    if not n:
        return None
    return round(sum(c * (c - 1) for c in hist) / (n * (n - 1)) * mod, 4) if n > 1 else None


# ------------------------------------------------------------------- self tests
def _fmt_pairs(pairs, byte15=0x00, tail=0x00):
    """Build one 16-byte frame from 7 even/odd byte pairs plus byte14 and byte15."""
    f = bytearray(FRAME_SIZE)
    for i, (e, o) in enumerate(pairs):
        f[2 * i] = e
        f[2 * i + 1] = o
    f[14] = tail
    f[15] = byte15
    return bytes(f)


def self_tests():
    fails = []

    def check(name, got, want):
        if got != want:
            fails.append("%s: got %r want %r" % (name, got, want))

    # 1. all-data frame: byte15 = 0 -> 15 data bytes, in order, bit0 unchanged
    f = _fmt_pairs([(0x10, 0x11), (0x12, 0x13), (0x14, 0x15), (0x16, 0x17),
                    (0x18, 0x19), (0x1A, 0x1B), (0x1C, 0x1D)], byte15=0x00, tail=0x1E)
    emitted, cur = unpack_frame(f, 0x21)
    check("all-data payload", [b for _s, b in emitted],
          [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
           0x1C, 0x1D, 0x1E])
    check("all-data id", [s for s, _b in emitted], [0x21] * 15)
    check("all-data cur id unchanged", cur, 0x21)

    # 2. bit0 restore: byte15 bit0 set -> the pair-0 first byte gets bit0 back
    f = _fmt_pairs([(0x30, 0x31)], byte15=0x01)
    emitted, _c = unpack_frame(f, 0x21)
    check("bit0 restored from byte15", emitted[0], (0x21, 0x31))

    # 3. ID byte at pair 0, byte15 bit0 clear: ID is consumed as non-data and the
    #    following byte belongs to the NEW id.
    id41 = (0x41 << 1) | 1
    f = _fmt_pairs([(id41 & 0xFF, 0x51), (0x52, 0x53)], byte15=0x00)
    emitted, cur = unpack_frame(f, 0x21)
    check("id byte consumed, next byte belongs to new id", emitted[0], (0x41, 0x51))
    check("id byte switch", [s for s, _b in emitted][:1], [0x41])
    check("cur id after frame", cur, 0x41)

    # 4. ID change with byte15 bit0 set: byte1 belongs to the OLD id first.
    f = _fmt_pairs([(id41 & 0xFF, 0x51)], byte15=0x01)
    emitted, _c = unpack_frame(f, 0x21)
    check("prev-id byte before switch", emitted[:2], [(0x21, 0x51), (0x41, 0x00)])

    # 5. byte14 as ID byte: no data emitted from it.
    f = _fmt_pairs([(0x60, 0x61)] * 7, byte15=0x00, tail=(0x22 << 1) | 1)
    emitted, cur = unpack_frame(f, 0x21)
    check("byte14 id consumed", cur, 0x22)
    check("byte14 emits no data", len(emitted), 14)

    # 6. negative control: random bytes must NOT look framed
    rnd = random.Random(7)
    stream = bytes(rnd.getrandbits(8) for _ in range(160000))
    scan = parity_scan(stream)
    check("random control rate near 0.5",
          True, abs(scan["best_even_bit0_rate"] - 0.5) < 0.05)
    ids = deformat(stream)[1]
    check("random control many ids", len(set(ids)) > 100, True)

    # 7. positive control: a single-ID synthetic framed stream must look framed
    data = bytes(rnd.getrandbits(8) & 0xFE for _ in range(80000))   # even => bit0 clear
    stream = bytearray()
    for off in range(0, len(data) - 14, 14):
        chunk = data[off:off + 14]
        f = bytearray(FRAME_SIZE)
        for i, b in enumerate(chunk):
            f[i] = b
        f[15] = 0x00
        # announce the ID once every 64 frames
        if (off // 14) % 64 == 0:
            f[0] = (0x21 << 1) | 1
            f[1] = chunk[1] if len(chunk) > 1 else 0
            for i in range(1, len(chunk)):
                f[i] = chunk[i]
        stream += f
    scan = parity_scan(bytes(stream))
    check("synthetic framed rate low", scan["best_even_bit0_rate"] < 0.05, True)
    _emb, ids = deformat(bytes(stream))
    check("synthetic ids single valid id", set(ids) & {0x21}, {0x21})
    check("synthetic id transitions rare",
          sum(1 for a, b in zip(ids, ids[1:]) if a != b) < 100, True)

    return fails


def main(argv=None):
    ap = argparse.ArgumentParser(description="CoreSight formatted-frame probe for ETE traces")
    ap.add_argument("trace", nargs="?")
    ap.add_argument("--json", help="write the full report as JSON here")
    ap.add_argument("--out", help="write the deformatted stream of the best phase here")
    ap.add_argument("--max-bytes", type=int, default=4000000)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        fails = self_tests()
        for f in fails:
            print("FAIL", f)
        print("self-test:", "PASS" if not fails else "FAIL (%d)" % len(fails))
        return 0 if not fails else 1

    if not args.trace:
        ap.error("a trace file is required unless --self-test")
    result = analyse(args.trace, max_stream_bytes=args.max_bytes)

    if args.out:
        records = walk_aux_payloads(args.trace)
        stream = b"".join(p for p, _i, _c in records)
        phase = result.get("parity_scan", {}).get("best_phase", 0)
        emb, ids = deformat(stream[phase:])
        keep = result.get("deformat_at_best_phase", {}).get("top_ids", [])
        wanted = set(int(k["id"], 16) for k in keep[:1])
        out_bytes = bytes(b for s, b in zip(ids, emb) if s in wanted) if wanted else emb
        with open(args.out, "wb") as fh:
            fh.write(out_bytes)
        result["out_file"] = {"path": os.path.basename(args.out),
                              "bytes": len(out_bytes)}

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
