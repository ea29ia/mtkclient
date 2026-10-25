#!/usr/bin/env python3
"""Static audit of an MTK DA2 blob (ARM32, file offset 0 == VA 0x40000000).

Built for the RMX3630 / MT6789 DA2 comparison (200EX01 vs 2710EX01) and the
claims in bkerler/mtkclient#409. Everything is derived from the raw bytes:

  * identity (size / sha256)
  * HeapBait tripwire string and whether it is *live* (movw/movt xref)
  * fp_read_host_file: is the per-chunk recv request clamped to
    min(remaining, packet_max) or not
  * XML escape helper: is the output buffer bounded (0xBFA) or not
  * registered "CMD:*" names present in the blob
  * RPMB entry points (rpmb_hmac, key stage, key wipe) and XML RPMB commands

Usage:
    python3 da2_static_audit.py DA2.bin [--json]
"""
import hashlib
import json
import struct
import sys

BASE = 0x40000000
MASK_MOVW = 0x0FF00000
MASK_MOVT = 0x0FF00000
MOVW = 0x03000000
MOVT = 0x03400000


def cstr(data, va):
    off = va - BASE
    if not 0 <= off < len(data):
        return "<oob>"
    end = data.find(b"\x00", off)
    return data[off:end].decode("latin1", "replace")


def find_str(data, needle):
    out, start = [], 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return out
        out.append(BASE + i)
        start = i + 1


def movw_movt_pairs(data):
    """(value, movw_site, movt_site) for every movw/movt pair building a constant."""
    words = [struct.unpack_from("<I", data, o)[0] for o in range(0, len(data) - 3, 4)]
    half = {}
    for i, w in enumerate(words):
        if (w & MASK_MOVW) == MOVW:
            half[i] = ((w >> 12) & 0xF, ((w >> 4) & 0xF000) | (w & 0xFFF))
    pairs = []
    for i, (rd, lo) in half.items():
        for j in range(i + 1, min(i + 6, len(words))):
            w = words[j]
            if (w & MASK_MOVT) == MOVT and ((w >> 12) & 0xF) == rd:
                hi = ((w >> 4) & 0xF000) | (w & 0xFFF)
                pairs.append(((hi << 16) | lo, BASE + i * 4, BASE + j * 4))
                break
    return pairs


def lit_dword_refs(data, value):
    pat = struct.pack("<I", value)
    out, start = [], 0
    while True:
        i = data.find(pat, start)
        if i < 0:
            return out
        if i % 4 == 0:
            out.append(BASE + i)
        start = i + 4


def xrefs(data, pairs, va):
    out = [(a1, "movw/movt", a2) for (v, a1, a2) in pairs if v == va]
    out += [(a, "literal", None) for a in lit_dword_refs(data, va)]
    return out


def nearest_dword(data, va, needle, back=0x800, fwd=0x80):
    """Is `needle` (dword) present in the code window around va?"""
    lo = max(BASE, va - back) - BASE
    hi = min(len(data) - 4, va + fwd - BASE)
    pat = struct.pack("<I", needle)
    return data.find(pat, lo, hi) >= 0


def imm12_search(data, va, value, back=0x400, fwd=0x200):
    """Search for a movw/movt or `mov rX,#value` encoding of value near va."""
    lo = max(BASE, va - back) - BASE
    hi = min(len(data) - 4, va + fwd - BASE)
    for off in range(lo & ~3, hi, 4):
        w = struct.unpack_from("<I", data, off)[0]
        # mov rX,#imm12 (ARM data-processing immediate, opcode MOV)
        if (w & 0x0FE00000) == 0x03A00000 and (w & 0xFFF) == value:
            return BASE + off
        if (w & MASK_MOVW) == MOVW and (((w >> 4) & 0xF000) | (w & 0xFFF)) == value:
            return BASE + off
    return None


def main():
    path = sys.argv[1]
    data = open(path, "rb").read()
    pairs = movw_movt_pairs(data)
    out = {
        "file": path,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "strings": {},
    }

    targets = {
        "heapbait_tripwire": b"Dest XML file name buffer overflow",
        "fp_buffer_too_small": b"fp_read_host_file buffer is too small.",
        "download_host_file": b"Download host file:%s",
        "usb_error": b"USB error or buffer is too small to contain all data.",
        "cmd_loop_dpc": b"\n@Protocol: DPC CALL\n",
        "rpmb_hmac_name": b"rpmb_hmac",
        "customrpmbi": b"CUSTOMRPMBI",
        "customrpmbk": b"CUSTOMRPMBK",
        "customrpmbr": b"CUSTOMRPMBR",
        "get_rpmb_key_status": b"GET-RPMB-KEY-STATUS",
    }
    for name, needle in targets.items():
        vas = find_str(data, needle)
        entry = {"va": [hex(v) for v in vas], "xrefs": []}
        for va in vas[:1]:
            entry["xrefs"] = [
                {"at": hex(a), "kind": kind,
                 "func_hint": hex(a - 0x200)}
                for (a, kind, _lit) in xrefs(data, pairs, va)
            ]
        out["strings"][name] = entry

    # all registered / embedded "CMD:" names
    cmds, start = set(), 0
    while True:
        i = data.find(b"CMD:", start)
        if i < 0:
            break
        end = data.find(b"\x00", i)
        s = data[i:end]
        if 4 < len(s) < 64 and all(32 <= c < 127 for c in s):
            cmds.add(s.decode())
        start = i + 1
    out["cmd_names"] = sorted(cmds)

    # heapbait primitive: locate fp_read_host_file via the "Download host file" xref
    fph = None
    if out["strings"]["download_host_file"]["xrefs"]:
        fph = int(out["strings"]["download_host_file"]["xrefs"][0]["at"], 16)
    entry = {"anchor": hex(fph) if fph else None}
    if fph:
        entry.update(_analyse_fp_read_host_file(data, fph))
    out["fp_read_host_file"] = entry

    # XML escape bound: function referenced by the tripwire string
    esc = None
    if out["strings"]["heapbait_tripwire"]["xrefs"]:
        esc = int(out["strings"]["heapbait_tripwire"]["xrefs"][0]["at"], 16)
    out["escape_helper"] = {
        "tripwire_xref": hex(esc) if esc else None,
        "output_bound_0xbfa": bool(esc and imm12_search(data, esc, 0xBFA, back=0x200, fwd=0x100)),
    }

    # RPMB key stage / wipe
    stage = imm12_search(data, fph or BASE, 0xF058, back=0, fwd=0)  # placeholder (unused)
    out["rpmb"] = {
        "key_stage_0x4006f058_refs": [],
        "key_stage_0x4006e8d8_refs": [],
    }
    for val, tag in ((0x4006F058, "key_stage_0x4006f058_refs"),
                     (0x4006E8D8, "key_stage_0x4006e8d8_refs")):
        out["rpmb"][tag] = [hex(a1) for (v, a1, a2) in pairs if v == val]

    print(json.dumps(out, indent=2))


def _analyse_fp_read_host_file(data, anchor):
    """Decide whether the download loop clamps the recv request.

    Vulnerable (200EX01) shape:      ldr r0,[sp,#0x24] ; str r0,[sp,#0x7c]
    Patched   (2710EX01) shape:      sub r0, sb, r7 ; cmp r0, r1 ; movhs r0, r1
                                     ; str r0,[sp,#0x7c]
    We disassemble the function window and look for the `movhs` clamp idiom
    (min via conditional move) in front of the recv call.
    """
    res = {"clamped": None, "evidence": []}
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
    except ImportError:
        res["evidence"].append("capstone not installed")
        return res

    # function start: last push{...,lr} before the anchor
    lo = max(BASE, anchor - 0x2000)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    start = anchor
    for i in md.disasm(data[lo - BASE:anchor - BASE], lo):
        if i.mnemonic == "push" and "lr" in i.op_str:
            start = i.address
    res["func_start"] = hex(start)

    insns = []
    for i in md.disasm(data[start - BASE:start - BASE + 0x800], start):
        insns.append((i.address, i.mnemonic, i.op_str))
        if len(insns) > 400:
            break

    for idx, (a, mn, ops) in enumerate(insns):
        if mn not in ("movhs", "movcs") or not ops.startswith("r0,"):
            continue
        window = insns[max(0, idx - 3):idx + 4]
        has_sub = any(m == "sub" and o.startswith("r0,") for (_a, m, o) in window)
        has_cmp = any(m in ("cmp", "cmphs") for (_a, m, o) in window)
        res["evidence"].append(
            f"0x{a:08x}: {'; '.join(f'{m} {o}' for (_x, m, o) in window)}")
        if has_sub and has_cmp:
            res["clamped"] = True
    if res["clamped"] is None:
        res["clamped"] = False
        # show the request-load site for the report
        for idx, (a, mn, ops) in enumerate(insns):
            if mn == "ldr" and ops.startswith("r0,") and "[sp, #0x24]" in ops:
                res["evidence"].append(f"0x{a:08x}: {mn} {ops} (unclamped request)")
                break
    return res


if __name__ == "__main__":
    main()
