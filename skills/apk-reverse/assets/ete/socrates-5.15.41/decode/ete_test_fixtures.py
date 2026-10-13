import struct
import ete_target_manifest as man

def perf_record(rtype, body, misc=0):
    return struct.pack("<IHH", rtype, misc, 8 + len(body)) + body


def perf_auxtrace(aux_size, offset, cpu, tid, idx=0, fill=b"\xAA"):
    """AUXTRACE as simpleperf writes it: the 16-bit header size covers only
    header(8) + DataType(40); aux_size bytes of payload follow outside it and are
    padded to a multiple of 8 (AOSP record.h:534-556)."""
    body = struct.pack("<QQQIIII", aux_size, offset, 0, idx, tid, cpu, 0)
    assert len(body) == 40, len(body)
    payload = (fill * (aux_size // len(fill) + 1))[:aux_size]
    payload += b"\0" * ((-aux_size) % 8)
    return struct.pack("<IHH", 71, 0, 8 + len(body)) + body + payload


def perf_build(records, feats=(18, 129), attr_type=1234):
    """A minimal perf/simpleperf record file with one attr and given records."""
    ids = struct.pack("<Q", 0x1001)
    attr_body = bytearray(112)
    struct.pack_into("<II", attr_body, 0, attr_type, 112)
    struct.pack_into("<Q", attr_body, 8, 0x400000002)      # config
    struct.pack_into("<Q", attr_body, 16, 0x111)           # sample_type
    attr_size = 112 + 16
    header_len = 104
    attr_off = header_len
    data_off = attr_off + attr_size + len(ids)
    recs = b"".join(records)
    flags = bytearray(32)
    for f in feats:
        flags[f // 8] |= 1 << (f % 8)
    head = b"PERFILE2" + struct.pack(
        "<QQQQQQQQ", header_len, attr_size,
        attr_off, attr_size, data_off, len(recs), 0, 0) + bytes(flags)
    assert len(head) == header_len, len(head)
    ids_off = attr_off + attr_size          # ids payload follows the attr
    attr = bytes(attr_body) + struct.pack("<QQ", ids_off, len(ids))
    return head + attr + ids + recs

def mkelf(cls=64, build_id="aabbccdd00112233", with_bss=True, residue=0):
    """A minimal but valid ELF with two PT_LOADs (seg1 has a BSS tail) + a note.

    `residue` shifts seg1's p_offset and p_vaddr together, which is what real
    linkers do: p_vaddr stays congruent to p_offset modulo the page size, so the
    page that reaches the mapping's pgoff is only the page-aligned part of
    p_offset. With residue != 0 the conversion has to subtract that residue; the
    default (0) leaves the fixture unable to tell the two signs apart, which is
    exactly why a residue fixture needs to exist next to this one.
    """
    segs = [
        {"offset": 0x0,           "vaddr": 0x0,           "filesz": 0x2000, "memsz": 0x2000,
         "flags": 5, "align": 0x1000},
        {"offset": 0x2000 + residue, "vaddr": 0x3000 + residue, "filesz": 0x1000, "memsz": 0x2000,
         "flags": 6, "align": 0x1000},
    ]
    note = b""
    if build_id:
        raw = bytes.fromhex(build_id)
        name = b"GNU\0"
        note = struct.pack("<III", len(name), len(raw), 4) + name + \
            raw + b"\0" * ((4 - len(raw) % 4) % 4)
    if cls == 64:
        e_phent, hdr_sz, ph_fmt = 56, 64, "<IIQQQQQQ"
    else:
        e_phent, hdr_sz, ph_fmt = 32, 52, "<IIIIIIII"
    note_off = 0x4000
    all_ph = [dict(s, p_type=1) for s in segs]
    all_ph.append({"p_type": 4, "offset": note_off, "vaddr": 0x5000,
                   "filesz": len(note), "memsz": len(note), "flags": 4,
                   "align": 4})
    phoff = hdr_sz
    blob = bytearray(note_off + len(note))
    for i, p in enumerate(all_ph):
        args = (p["p_type"], p["offset"], p["vaddr"], p["vaddr"], p["filesz"],
                p["memsz"], p["flags"], p["align"])
        if cls == 64:      # p_flags comes second in ELF64
            args = (p["p_type"], p["flags"], p["offset"], p["vaddr"], p["vaddr"],
                    p["filesz"], p["memsz"], p["align"])
        blob[phoff + i * e_phent:phoff + (i + 1) * e_phent] = struct.pack(ph_fmt, *args)
    ident = b"\x7fELF" + bytes([2 if cls == 64 else 1, 1, 1, 0]) + b"\0" * 8
    if cls == 64:
        hdr = ident + struct.pack("<HHIQQQIHHHHHH", 3, 0xB7, 1, 0x1234, phoff, 0, 0,
                                  hdr_sz, e_phent, len(all_ph), 0, 0, 0)
    else:
        hdr = ident + struct.pack("<HHIIIIIHHHHHH", 3, 0x28, 1, 0x1234, phoff, 0, 0,
                                  hdr_sz, e_phent, len(all_ph), 0, 0, 0)
    blob[0:len(hdr)] = hdr
    blob[note_off:note_off + len(note)] = note
    # give a couple of file offsets a recognizable "instruction" word
    blob[0x2000 + 0x100:0x2000 + 0x104] = bytes.fromhex("2100014a")
    return bytes(blob), segs


def manifest_for(name, elf_bytes):
    m = man.manifest_from_bytes(elf_bytes, {"kind": "file", "path": name,
                                            "file_sha256": None})
    return {"schema": "ete-target-manifest/1", "targets": [m]}


MAP_PATH = "/data/app/x/base.apk!/lib/arm64-v8a/libfoo.so"


def maps_text(base, path=MAP_PATH, extra=""):
    return (
        "%x-%x r-xp 00000000 07:12 101 %s\n"
        "%x-%x rw-p 00002000 07:12 101 %s\n"
        "%x-%x ---p 00000000 00:00 0 \n"
        "%s" % (base, base + 0x2000, path,
                base + 0x3000, base + 0x5000, path,
                0x60000000, 0x60001000, extra)).replace("\n\n", "\n")
