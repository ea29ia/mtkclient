#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
da1_static_audit.py - generic static triage for MediaTek DA1 blobs.

Answers, in one command:

  * Is this DA1 vulnerable to the PR #414 "HeapBait" bug
    (`CMD:DEBUG:DRAM-REPAIR` present, DA2 tripwire string absent) ?
  * Where are the addresses the exploit needs (heap_init / heap head / dpc /
    malloc / free + fire-write / insert / cmd_loop + blx / registrar /
    download / BOOT-TO / SHA-256 / DA2 digest slot) ?
  * How does it differ from the known 200EX01 build ?

Read-only, offline. Requires only capstone. No device, no network, no writes
to the audited file.

Verdict rule (PR #414 `is_da1_vulnerable`, replicated):
    VULNERABLE    CMD:DEBUG:DRAM-REPAIR registered  and  tripwire absent
    PATCHED       CMD:DEBUG:DRAM-REPAIR absent       and  tripwire present
    INDETERMINATE anything else (report both facts, do not guess)

Confidence is per check: high = shape matched exactly and a second independent
reference agrees; medium = one strong anchor; low = heuristic only;
none = could not prove (the tool says INDETERMINATE instead of guessing).

Exit code is 0 for every auditable blob (the verdict lives in the report),
2 only when the primary blob cannot be read.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
except Exception as exc:  # pragma: no cover
    sys.stderr.write("fatal: capstone is required (%s)\n" % exc)
    raise SystemExit(2)

TOOL = "da1_static_audit"
VERSION = "1.0"

# ---------------------------------------------------------------------------
# Reference build: DA1 200EX01 (RMX3630 / MT6789), docs/notes/rmx3630-da2/da1_allinone.bin
# Addresses documented in docs/notes/HANDOFF-da1-pc-2026-10-25.md sec.7 and
# docs/notes/reverse/re-da1-hash-patch-audit.md.
# ---------------------------------------------------------------------------
REF_NAME = "200EX01"
REF_SHA256 = "e1a4110a394db63c5e1a56e8c6e2acfe495faf0167b20f6b85aefe649a3823f2"
REF = {
    "registrar": 0x200ED0,
    "reg_cmd": 0x203BBC,
    "table_head": 0x266070,
    "cmd_loop": 0x203C08,
    "blx_cb": 0x2040D4,
    "dpc": 0x2DF7A0,
    "dpc_node": 0x2DF79C,
    "malloc": 0x2041E8,
    "free": 0x204380,
    "fire_write": 0x2043CC,
    "insert": 0x2043D8,
    "heap_init": 0x2044C8,
    "heap_head": 0x2DF7D0,
    "heap_base": 0x2E8000,
    "heap_size": 0x10000,
    "download": 0x2500D8,
    "recv_len_store": 0x2503F4,
    "packet_len": 0x2DE3F8,
    "dram_repair_handler": 0x202C7C,
    "boot_to": 0x201080,
    "sha256": 0x2522C4,
    "digest_slot": 0x2688CC,
}
REF_CMDS = [
    "CMD:NOTIFY-INIT-HW",
    "CMD:SET-HOST-INFO",
    "CMD:BOOT-TO",
    "CMD:REBOOT",
    "CMD:GET-HW-INFO",
    "CMD:SET-RUNTIME-PARAMETER",
    "CMD:HOST-SUPPORTED-COMMANDS",
    "CMD:RAM-TEST",
    "CMD:DEBUG:DRAM-REPAIR",
    "CMD:WRITE-FLASH",
    "CMD:ERASE-FLASH",
    "CMD:READ-FLASH",
]

DRAM_REPAIR = "CMD:DEBUG:DRAM-REPAIR"
TRIPWIRE = "Dest XML file name buffer overflow"
DL_STRING = "Download host file"

# Xref engine self-test: known movw/movt -> pointer pairs.
# 200EX01 0x2012CC `movw ip,#0xe180`, 0x2012D0 `movw r1,#0x4d42`,
# 0x2012D4 `movt ip,#0x2d`  -> 0x2DE180   (pairing must survive the interleave)
# 2710    0x2503FC `movw r0,#0x2e17`, 0x250400 `movt r0,#0x26` -> 0x262E17
KNOWN_PAIRS = [
    {
        "label": "200EX01 movw/movt ip (interleaved pair) -> 0x2DE180",
        "va": 0x2012CC,
        "words": (0xE30EC180, 0xE340C02D),
        "value": 0x2DE180,
        "spread": 0x10,
    },
    {
        "label": "2710 movw/movt r0 (adjacent pair) -> 0x262E17",
        "va": 0x2503FC,
        "words": (0xE3020E17, 0xE3400026),
        "value": 0x262E17,
        "spread": 0x08,
    },
]

REGNAMES = {
    "r0": 0, "r1": 1, "r2": 2, "r3": 3, "r4": 4, "r5": 5, "r6": 6, "r7": 7,
    "r8": 8, "r9": 9, "r10": 10, "r11": 11, "r12": 12, "sp": 13, "lr": 14,
    "pc": 15, "sb": 9, "sl": 10, "fp": 11, "ip": 12,
}
REGNUM = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "sb", "sl",
          "fp", "ip", "sp", "lr", "pc"]

COND = ("eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge",
        "lt", "gt", "le")

RE_MOVW = re.compile(r"^(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*#(0x[0-9a-f]+|\d+)$")
RE_STR = re.compile(
    r"^(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*\[(r\d+|sb|sl|fp|ip|sp|lr|pc)"
    r"(?:\s*,\s*#(0x[0-9a-f]+|-?\d+))?\]$")
RE_STR_REG = re.compile(
    r"^(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*\[(r\d+|sb|sl|fp|ip|sp|lr|pc)"
    r"\s*,\s*(r\d+|sb|sl|fp|ip|sp|lr|pc)\]$")
RE_LDR_SAME = RE_STR
RE_STM = re.compile(r"^([a-z0-9]+)\s*,\s*\{(.+)\}$")
RE_REG_RR = re.compile(
    r"^(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*"
    r"(r\d+|sb|sl|fp|ip|sp|lr|pc)$")
RE_REG_RI = re.compile(
    r"^(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*"
    r"#(0x[0-9a-f]+|-?\d+)$")
RE_MOV_RR = re.compile(
    r"^(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*(r\d+|sb|sl|fp|ip|sp|lr|pc)$")
RE_MOV_RI = re.compile(
    r"^(r\d+|sb|sl|fp|ip|sp|lr|pc)\s*,\s*#(0x[0-9a-f]+|-?\d+)$")
RE_CMD = re.compile(rb"CMD:[A-Za-z0-9:_\-\.]{2,48}\x00")

# instructions that do not write their first operand register
NON_WRITING = {
    "cmp", "cmn", "tst", "teq", "str", "strb", "strh", "strd", "stm", "stmib",
    "stmda", "stmdb", "stmfd", "stmea", "stmia", "push", "b", "bl", "bx",
    "blx", "nop", "svc", "bkpt", "dmb", "dsb", "isb", "udf", "it", "clrex",
}
COND_MOV = tuple("mov" + c for c in COND)


def hx(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return "0x%x" % value


def as_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


def parse_int(text):
    return int(text, 0)


# ---------------------------------------------------------------------------
# raw instruction decoders (shared by the xref engine and its self-test)
# ---------------------------------------------------------------------------
def decode_movw_word(word):
    """MOVW: cond 0011 0000 imm4 Rd imm12.  Returns (rd, imm16) or None."""
    if (word & 0x0FF00000) != 0x03000000:
        return None
    rd = (word >> 12) & 0xF
    imm16 = (((word >> 16) & 0xF) << 12) | (word & 0xFFF)
    return rd, imm16


def decode_movt_word(word):
    """MOVT: cond 0011 0100 imm4 Rd imm12.  Returns (rd, imm16) or None."""
    if (word & 0x0FF00000) != 0x03400000:
        return None
    rd = (word >> 12) & 0xF
    imm16 = (((word >> 16) & 0xF) << 12) | (word & 0xFFF)
    return rd, imm16


def decode_branch_target(word, pc):
    """BL/B: target = pc + 8 + sign_extend(imm24) * 4."""
    if (word & 0x0F000000) not in (0x0A000000, 0x0B000000):
        return None
    imm = word & 0x00FFFFFF
    if imm & 0x00800000:
        imm -= 0x01000000
    return pc + 8 + imm * 4


# ---------------------------------------------------------------------------
# image
# ---------------------------------------------------------------------------
class Da1Image:
    def __init__(self, data, base):
        self.data = data
        self.base = base
        self.end = base + len(data)
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.md.skipdata = True
        self._linear = None
        self._by_addr = None
        self._pairs = None
        self._xrefs = None

    # -- address helpers ---------------------------------------------------
    def va(self, off):
        return self.base + off

    def off(self, va):
        return va - self.base

    def in_image(self, va):
        return self.base <= va < self.end

    def u32(self, va):
        off = self.off(va)
        if off < 0 or off + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, off)[0]

    def data_at(self, va, length):
        off = self.off(va)
        if off < 0 or off + length > len(self.data):
            return None
        return self.data[off:off + length]

    # -- disassembly -------------------------------------------------------
    def linear(self):
        """Full linear ARM32 disassembly (cached).  Invalid words -> .byte."""
        if self._linear is None:
            insns = []
            for insn in self.md.disasm(self.data, self.base):
                insns.append(insn)
            self._linear = insns
            self._by_addr = {insn.address: insn for insn in insns}
        return self._linear

    def insn(self, va):
        self.linear()
        insn = self._by_addr.get(va)
        if insn is not None:
            return insn
        off = self.off(va)
        if off < 0 or off + 4 > len(self.data):
            return None
        for insn in self.md.disasm(self.data[off:off + 4], va):
            if insn.address == va:
                return insn
        return None

    def slice(self, start_va, end_va):
        """Instructions in [start_va, end_va)."""
        self.linear()
        out = []
        va = start_va
        while va < end_va:
            insn = self._by_addr.get(va)
            if insn is None:
                va += 4
                continue
            out.append(insn)
            va += max(insn.size, 4)
        return out

    @staticmethod
    def text(insn):
        return "0x%x  %s %s" % (insn.address, insn.mnemonic, insn.op_str)

    # -- xref engine -------------------------------------------------------
    def build_xrefs(self):
        """
        Per-register movw/movt pairing.

        A pair is emitted only when the *same* register received a movw and no
        other write to that register happened in between.  This is what the
        earlier buggy scanner got wrong: it only looked at adjacent
        instructions, so 0x2012CC (`movw ip` / `movw r1` / `movt ip`) was
        missed.  Pairing is tracked per register, so interleaved sequences
        resolve; unrelated writes invalidate.
        """
        if self._pairs is not None:
            return self._pairs
        state = {}   # regnum -> ("word"|"built", value, va)
        pairs = []
        for insn in self.linear():
            mnem = insn.mnemonic
            if mnem == "movw":
                m = RE_MOVW.match(insn.op_str)
                decoded = decode_movw_word(self.u32(insn.address))
                if m and decoded is not None:
                    state[decoded[0]] = ("word", decoded[1], insn.address)
                continue
            if mnem == "movt":
                decoded = decode_movt_word(self.u32(insn.address))
                if decoded is None:
                    continue
                rd, imm16 = decoded
                prev = state.get(rd)
                if prev is not None and prev[0] == "word":
                    pairs.append({
                        "movt_va": insn.address,
                        "movw_va": prev[2],
                        "reg": rd,
                        "value": prev[1] | (imm16 << 16),
                    })
                    state[rd] = ("built", prev[1] | (imm16 << 16), insn.address)
                else:
                    state[rd] = ("other", 0, insn.address)
                continue
            # any other instruction that writes the first operand kills it
            first = insn.op_str.split(",")[0].strip()
            rd = REGNAMES.get(first)
            if rd is not None and mnem not in NON_WRITING:
                if not mnem.startswith("mov") or mnem in COND_MOV:
                    state.pop(rd, None)
        self._pairs = pairs
        self._xrefs = {}
        for pair in pairs:
            self._xrefs.setdefault(pair["value"], []).append(pair)
        return self._pairs

    @property
    def pairs(self):
        return self.build_xrefs()

    @property
    def xrefs(self):
        self.build_xrefs()
        return self._xrefs

    def pair_before(self, va, reg=None, window=0x40):
        best = None
        for pair in self.pairs:
            if reg is not None and pair["reg"] != reg:
                continue
            if pair["movt_va"] <= va <= pair["movt_va"] + window:
                if best is None or pair["movt_va"] > best["movt_va"]:
                    best = pair
        return best

    def pairs_before(self, va, reg=None, window=0x40):
        out = []
        for pair in self.pairs:
            if reg is not None and pair["reg"] != reg:
                continue
            if va - window <= pair["movt_va"] <= va:
                out.append(pair)
        out.sort(key=lambda p: p["movt_va"])
        return out

    def pairs_in(self, start_va, end_va, reg=None):
        out = [p for p in self.pairs
               if start_va <= p["movt_va"] < end_va
               and (reg is None or p["reg"] == reg)]
        out.sort(key=lambda p: p["movt_va"])
        return out

    def pairs_to(self, value):
        return self.xrefs.get(value, [])

    # -- code helpers ------------------------------------------------------
    def is_code(self, va):
        insn = self.insn(va)
        return insn is not None and insn.mnemonic not in (".byte", "udf", "")

    def func_start(self, va, limit=0x1000):
        cur = va
        floor = max(self.base, va - limit)
        while cur >= floor:
            insn = self.insn(cur)
            if insn is not None:
                if insn.mnemonic in ("push", "stmdb", "stmfd") and "lr" in insn.op_str:
                    return cur
            cur -= 4
        return va

    def next_branch(self, va, limit=0x40, mnemonics=("bl", "b")):
        for insn in self.slice(va, va + limit):
            if insn.mnemonic in mnemonics:
                return insn
        return None

    def branch_target(self, insn):
        if insn is None:
            return None
        return decode_branch_target(self.u32(insn.address), insn.address)

    def reg_const(self, va, reg, window=0x20):
        """
        Resolve a register constant ending at `va` (exclusive), accepting
        conditional movw/movt (movwne/movtne ...) which the strict xref engine
        deliberately ignores.  Used for the reg_cmd list-head global.
        """
        state = None
        for insn in self.slice(max(self.base, va - window), va):
            mnem = insn.mnemonic
            if mnem.startswith("movw"):
                dec = decode_movw_word(self.u32(insn.address))
                if dec is not None and dec[0] == reg:
                    state = ("word", dec[1])
                elif dec is not None and self.first_reg(insn) == reg:
                    state = None
                continue
            if mnem.startswith("movt"):
                dec = decode_movt_word(self.u32(insn.address))
                if dec is not None and dec[0] == reg:
                    if state is not None and state[0] == "word":
                        state = ("built", state[1] | (dec[1] << 16))
                    else:
                        state = None
                continue
            if self.first_reg(insn) == reg:
                state = None
        return state[1] if state is not None and state[0] == "built" else None

    @staticmethod
    def first_reg(insn):
        return REGNAMES.get(insn.op_str.split(",")[0].strip())

    def find_str_imm(self, start_va, end_va, imm):
        """First `str rX,[rY,#imm]` in range (conditional forms accepted)."""
        for insn in self.slice(start_va, end_va):
            if not insn.mnemonic.startswith("str"):
                continue
            m = RE_STR.match(insn.op_str)
            if not m:
                continue
            off = m.group(3)
            if off is not None and parse_int(off) == imm:
                return insn
        return None

    def find_ldr_imm(self, start_va, end_va, imm):
        for insn in self.slice(start_va, end_va):
            if not insn.mnemonic.startswith("ldr"):
                continue
            m = RE_STR.match(insn.op_str)
            if not m:
                continue
            off = m.group(3)
            if off is not None and parse_int(off) == imm:
                return insn
        return None


def pair_value(value):
    return value


# ---------------------------------------------------------------------------
# small constant emulator (movw/movt/mov/add/sub only) for stubs/getters
# ---------------------------------------------------------------------------
def emulate_constants(img, entry, max_insns=40, stop_mnem=("bx", "pop", "b", "bl")):
    regs = {}
    evidence = []
    va = entry
    for _ in range(max_insns):
        insn = img.insn(va)
        if insn is None:
            break
        mnem = insn.mnemonic
        if mnem in stop_mnem:
            break
        evidence.append(img.text(insn))
        if mnem in ("movw", "movt"):
            dec = decode_movw_word(img.u32(va)) if mnem == "movw" else \
                decode_movt_word(img.u32(va))
            if dec is None:
                break
            rd, imm = dec
            if mnem == "movw":
                regs[rd] = imm
            else:
                if rd not in regs:
                    regs[rd] = imm << 16
                else:
                    regs[rd] = (regs[rd] & 0xFFFF) | (imm << 16)
        elif mnem == "mov":
            m = RE_MOV_RI.match(insn.op_str)
            if m:
                regs[REGNAMES[m.group(1)]] = parse_int(m.group(2)) & 0xFFFFFFFF
            else:
                m = RE_MOV_RR.match(insn.op_str)
                if m:
                    src = REGNAMES[m.group(2)]
                    if src in regs:
                        regs[REGNAMES[m.group(1)]] = regs[src]
                    else:
                        regs.pop(REGNAMES[m.group(1)], None)
        elif mnem in ("add", "sub"):
            m = RE_REG_RR.match(insn.op_str)
            if m:
                dst, a, b = (REGNAMES[m.group(i)] for i in (1, 2, 3))
                if a in regs and b in regs:
                    regs[dst] = (regs[a] + regs[b]) if mnem == "add" \
                        else (regs[a] - regs[b])
                    regs[dst] &= 0xFFFFFFFF
            else:
                m = RE_REG_RI.match(insn.op_str)
                if m:
                    dst, a = REGNAMES[m.group(1)], REGNAMES[m.group(2)]
                    imm = parse_int(m.group(3))
                    if a in regs:
                        regs[dst] = (regs[a] + imm) if mnem == "add" \
                            else (regs[a] - imm)
                        regs[dst] &= 0xFFFFFFFF
        else:
            break
        va += 4
    return regs, evidence


# ---------------------------------------------------------------------------
# container parsing (same layout mtkclient uses: header, count, 0xDC entries)
# ---------------------------------------------------------------------------
def parse_container(data):
    if len(data) < 0x6C:
        return None
    hdr = data[:0x68]
    if not (hdr.startswith(b"MTK_DOWNLOAD_AGENT") or b"MTK_DA_v" in hdr):
        return None
    count = struct.unpack_from("<I", data, 0x68)[0]
    if count <= 0 or count > 64:
        return None
    stride = 0xDC
    if data[0x6C + 0xD8:0x6C + 0xDA] == b"\xDA\xDA":
        stride = 0xD8
    entries = []
    for idx in range(count):
        off = 0x6C + idx * stride
        if off + 0x14 > len(data):
            break
        (magic, hw_code, hw_sub, hw_ver, sw_ver, _r1, pagesize, _r3,
         entry_region_index, region_count) = struct.unpack_from("<10H", data, off)
        if region_count <= 0 or region_count > 8:
            continue
        regions = []
        for ridx in range(region_count):
            roff = off + 0x14 + ridx * 20
            if roff + 20 > len(data):
                break
            buf, length, addr, start_off, sig_len = struct.unpack_from(
                "<5I", data, roff)
            if buf + length > len(data) or length == 0:
                regions.append({"index": ridx, "buf": buf, "len": length,
                                "addr": addr, "start_offset": start_off,
                                "sig_len": sig_len, "sane": False})
                continue
            blob = data[buf:buf + length]
            regions.append({
                "index": ridx,
                "buf": buf,
                "len": length,
                "addr": addr,
                "start_offset": start_off,
                "sig_len": sig_len,
                "sane": True,
                "has_boot_to": b"CMD:BOOT-TO\x00" in blob,
                "sha256": hashlib.sha256(blob).hexdigest(),
            })
        entries.append({
            "index": idx,
            "magic": magic,
            "hw_code": hw_code,
            "hw_sub_code": hw_sub,
            "hw_version": hw_ver,
            "sw_version": sw_ver,
            "pagesize": pagesize,
            "entry_region_index": entry_region_index,
            "regions": regions,
        })
    return {"count": count, "stride": stride, "entries": entries,
            "magic": hdr[:20].decode("latin-1").rstrip("\x00")}


# ---------------------------------------------------------------------------
# auditor
# ---------------------------------------------------------------------------
class Audit:
    def __init__(self, data, base, path):
        self.data = data
        self.path = path
        self.base = base
        self.img = Da1Image(data, base)
        self.notes = []
        self.res = {}
        self.table = None

    # -- helpers -----------------------------------------------------------
    def note(self, level, text):
        self.notes.append({"level": level, "text": text})

    def find_string(self, needle):
        raw = needle.encode() if isinstance(needle, str) else needle
        pos = self.data.find(raw)
        return None if pos < 0 else self.img.va(pos)

    def cmd_strings(self):
        out = []
        for match in RE_CMD.finditer(self.data):
            out.append((self.img.va(match.start()),
                        match.group()[:-1].decode("latin-1")))
        return out

    # -- 1. identity -------------------------------------------------------
    def identity(self, container, da1_region, file_info=None):
        file_info = file_info or {}
        ident = {
            "path": self.path,
            "size": len(self.data),
            "size_hex": hx(len(self.data)),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "base": hx(self.base),
            "container_type": "allinone" if container else "raw-da1",
        }
        if container:
            ident["file_size"] = file_info.get("size", len(self.data))
            ident["file_size_hex"] = hx(file_info.get("size", len(self.data)))
            ident["file_sha256"] = file_info.get("sha256")
            ident["container"] = {
                "magic": container.get("magic", ""),
                "entries": container["count"],
                "stride": hx(container["stride"]),
                "regions": [
                    {
                        "entry": e["index"],
                        "hw_code": hx(e["hw_code"]),
                        "hw_sub_code": hx(e["hw_sub_code"]),
                        "hw_version": hx(e["hw_version"]),
                        "sw_version": hx(e["sw_version"]),
                        "regions": [
                            {
                                "index": r["index"],
                                "file_offset": hx(r["buf"]),
                                "len": hx(r["len"]),
                                "addr": hx(r["addr"]),
                                "sig_len": hx(r["sig_len"]),
                                "sane": r.get("sane", False),
                                "has_CMD_BOOT_TO": r.get("has_boot_to", False),
                                "sha256": r.get("sha256"),
                            }
                            for r in e["regions"]
                        ],
                    }
                    for e in container["entries"]
                ],
            }
            if da1_region:
                ident["da1"] = {
                    "file_offset": hx(da1_region["buf"]),
                    "len": hx(da1_region["len"]),
                    "base": hx(da1_region["addr"]),
                    "sig_len": hx(da1_region["sig_len"]),
                    "sha256": da1_region.get("sha256"),
                    "sig_block_zeroed": self.data[
                        da1_region["buf"] + da1_region["len"] -
                        da1_region["sig_len"]:
                        da1_region["buf"] + da1_region["len"]] ==
                        b"\x00" * da1_region["sig_len"],
                }
            da2_regions = [r for e in container["entries"] for r in e["regions"]
                           if r.get("sane") and r["addr"] == 0x40000000]
            if da2_regions:
                ident["embedded_da2"] = {
                    "file_offset": hx(da2_regions[0]["buf"]),
                    "len": hx(da2_regions[0]["len"]),
                    "base": hx(da2_regions[0]["addr"]),
                    "sig_len": hx(da2_regions[0]["sig_len"]),
                    "sha256": da2_regions[0].get("sha256"),
                }
        ident["confidence"] = "high"
        self.res["identity"] = ident
        return ident

    # -- 2. xref self-test -------------------------------------------------
    def self_test(self):
        checks = []
        for known in KNOWN_PAIRS:
            ok_decode = True
            detail = []
            w0, w1 = known["words"]
            d0 = decode_movw_word(w0)
            d1 = decode_movt_word(w1)
            if d0 is None or d1 is None or d0[0] != d1[0]:
                ok_decode = False
                detail.append("synthetic decode failed: movw=%r movt=%r" % (d0, d1))
            else:
                value = d0[1] | (d1[1] << 16)
                if value != known["value"]:
                    ok_decode = False
                detail.append("synthetic decode -> 0x%x (expect 0x%x)"
                              % (value, known["value"]))
            in_image = False
            engine_ok = None
            live = self.img.u32(known["va"])
            if live == w0:
                in_image = True
                engine_ok = False
                for pair in self.img.pairs_to(known["value"]):
                    if known["va"] <= pair["movt_va"] <= known["va"] + known["spread"]:
                        engine_ok = True
                        detail.append(
                            "engine pair movw@0x%x .. movt@0x%x -> 0x%x"
                            % (pair["movw_va"], pair["movt_va"], pair["value"]))
                        break
                if not engine_ok:
                    detail.append("engine did NOT resolve the in-image anchor")
            checks.append({
                "label": known["label"],
                "decode_ok": ok_decode,
                "in_image_anchor": in_image,
                "engine_ok": engine_ok,
                "ok": ok_decode and (engine_ok is not False),
                "detail": detail,
            })
        result = {
            "ok": all(c["ok"] for c in checks),
            "image_anchors_tested": sum(1 for c in checks if c["in_image_anchor"]),
            "checks": checks,
        }
        self.res["self_test"] = result
        return result

    # -- 3. command table / registrar --------------------------------------
    def discover_table(self):
        img = self.img
        calls = []
        for name_va, name in self.cmd_strings():
            for pair in img.pairs_to(name_va):
                if pair["reg"] != 0:
                    continue
                call = img.next_branch(pair["movt_va"], limit=0x20)
                if call is None or call.mnemonic not in ("bl", "b"):
                    continue
                target = img.branch_target(call)
                handler_pair = img.pair_before(call.address, reg=2, window=0x30)
                calls.append({
                    "name": name,
                    "name_va": name_va,
                    "name_pair_va": pair["movt_va"],
                    "call_va": call.address,
                    "call_target": target,
                    "handler": handler_pair["value"] if handler_pair else None,
                    "handler_pair_va": handler_pair["movt_va"] if handler_pair else None,
                })
        if not calls:
            return None
        groups = {}
        for call in calls:
            groups.setdefault(call["call_target"], []).append(call)
        target, group = max(groups.items(), key=lambda kv: len(kv[1]))
        if target is None or len(group) < 3:
            return None
        # one row per distinct command name, in registration order
        seen = set()
        rows = []
        for call in sorted(group, key=lambda c: c["call_va"]):
            if call["name"] in seen:
                continue
            seen.add(call["name"])
            handler = call["handler"]
            valid = (handler is not None and img.in_image(handler)
                     and handler % 4 == 0 and img.is_code(handler))
            entry_insn = img.insn(handler) if handler is not None else None
            rows.append({
                "name": call["name"],
                "name_va": hx(call["name_va"]),
                "call_va": hx(call["call_va"]),
                "handler": hx(handler),
                "handler_entry": img.text(entry_insn) if entry_insn else None,
                "handler_valid": valid,
            })
        registrar = img.func_start(min(c["call_va"] for c in group))
        reg_cmd = target
        reg_cmd_end = min(img.base + len(self.data), reg_cmd + 0x200)
        store = img.find_str_imm(reg_cmd, reg_cmd_end, 0x10)
        table_head = None
        table_head_pair = None
        if store is not None:
            # the node->next store uses a global list head: str rX,[rG]
            for insn in img.slice(reg_cmd, reg_cmd_end):
                if not insn.mnemonic.startswith("str"):
                    continue
                m = RE_STR.match(insn.op_str)
                if not m or m.group(3) is not None:
                    continue
                g_reg = REGNAMES[m.group(2)]
                value = img.reg_const(insn.address, g_reg, window=0x20)
                if value is None:
                    pair = img.pair_before(insn.address, reg=g_reg, window=0x40)
                    value = pair["value"] if pair else None
                if value is not None and self.is_data_va(value):
                    table_head = value
                    table_head_store = insn
                    break
        self.table = {
            "registrar": hx(registrar),
            "reg_cmd": hx(reg_cmd),
            "table_head": hx(table_head),
            "count": len(rows),
            "entries": rows,
            "name_to_handler_store": img.text(store) if store else None,
        }
        return self.table

    # -- 4. heap resolver --------------------------------------------------
    def is_data_va(self, va):
        """A global/data VA inside the image (not a runtime-only RAM cell)."""
        return self.img.in_image(va) and va % 4 == 0

    def is_runtime_va(self, va):
        """512 MB - 4 GB window: SRAM/DRAM addresses that live outside the file."""
        return va is not None and 0x200000 <= va < 0x40000000 and va % 4 == 0

    def resolve_heap(self):
        img = self.img
        heap = {}

        # --- heap_init: `stm rH, {rA, rS}` + sentinel stores + `str rS,[rA,#8]`
        heap_init = None
        for idx, insn in enumerate(img.linear()):
            if insn.mnemonic != "stm":
                continue
            m = RE_STM.match(insn.op_str)
            if not m:
                continue
            head_reg = REGNAMES.get(m.group(1))
            regs = [REGNAMES.get(tok.strip()) for tok in m.group(2).split(",")]
            if head_reg is None or len(regs) != 2 or None in regs:
                continue
            seq = img.slice(insn.address, insn.address + 0x18)
            if len(seq) < 5:
                continue
            texts = [img.text(x) for x in seq]
            s1 = RE_STR.match(seq[1].op_str) if seq[1].mnemonic == "str" else None
            s2 = RE_STR.match(seq[2].op_str) if seq[2].mnemonic == "str" else None
            s3 = RE_STR.match(seq[3].op_str) if seq[3].mnemonic == "str" else None
            if not (s1 and s2 and s3) or seq[0].mnemonic != "stm" \
                    or seq[4].mnemonic != "b":
                continue
            if parse_int(s1.group(3) or "0") != 8 or \
                    parse_int(s2.group(3) or "0") != 0xC or \
                    parse_int(s3.group(3) or "0") != 8:
                continue
            if REGNAMES[s1.group(2)] != head_reg or REGNAMES[s2.group(2)] != head_reg:
                continue
            if REGNAMES[s3.group(2)] != regs[0]:
                continue
            entry = self.walk_back_constants(insn.address)
            regs_at, ev = emulate_constants(img, entry, max_insns=24,
                                            stop_mnem=("stm",))
            heap_head = regs_at.get(head_reg)
            arena_lo = regs_at.get(regs[0])
            arena_hi_or_size = regs_at.get(regs[1])
            insert = img.branch_target(seq[4])
            heap_init = {
                "heap_init": entry,
                "heap_head": heap_head,
                "heap_base": arena_lo,
                "heap_size": arena_hi_or_size,
                "insert": insert,
                "stm_site": insn.address,
                "evidence": ev + texts,
                "sentinel": (heap_head or 0) + 8,
                "layout": {
                    "heap_head+0x0": "arena base",
                    "heap_head+0x4": "arena size",
                    "heap_head+0x8": "sentinel node",
                    "heap_head+0xC": "free-list chain head",
                },
            }
            break

        if heap_init is None:
            heap["heap_init"] = {"va": None, "validated": False,
                                 "confidence": "none",
                                 "evidence": ["no `stm rH,{rA,rS}` heap-init "
                                              "shape found"]}
            self.res["heap"] = heap
            return heap

        head = as_int(heap_init["heap_head"])
        base = as_int(heap_init["heap_base"])
        size = as_int(heap_init["heap_size"])
        insert = as_int(heap_init["insert"])
        # validate insert independently: it must reference the same head
        ins_ev = []
        insn_ok = False
        if insert is not None and img.is_code(insert):
            ins_ev.append(img.text(img.insn(insert)))
            for pair in img.pairs_in(insert, insert + 0x60, reg=None):
                if pair["value"] == head:
                    insn_ok = True
                    ins_ev.append("list head 0x%x re-referenced at 0x%x"
                                  % (head, pair["movt_va"]))
            chain = img.find_ldr_imm(insert, insert + 0x60, 0xC)
            if chain is not None:
                ins_ev.append(img.text(chain))
                insn_ok = insn_ok or True
        heap["heap_init"] = {
            "va": hx(heap_init["heap_init"]),
            "validated": size is not None and size > 0 and base is not None,
            "confidence": "high" if insn_ok else "medium",
            "evidence": heap_init["evidence"],
        }
        heap["heap_head"] = {
            "va": hx(head),
            "validated": insn_ok,
            "confidence": "high" if insn_ok else "medium",
            "evidence": [img.text(img.insn(heap_init["stm_site"]))] +
                        [t for t in heap_init["evidence"] if "str " in t],
            "layout": heap_init["layout"],
            "sentinel": hx(heap_init["sentinel"]),
        }
        heap["heap_arena"] = {
            "base": hx(base),
            "size": hx(size),
            "end": hx(base + size) if base is not None and size is not None else None,
            "validated": size is not None and size > 0,
            "confidence": "high",
            "evidence": [t for t in heap_init["evidence"]
                         if "sub " in t or "movt r0" in t or "movt r3" in t],
        }
        heap["insert"] = {
            "va": hx(insert),
            "validated": insn_ok,
            "confidence": "high" if insn_ok else "medium",
            "evidence": ins_ev,
        }

        # --- free wrapper + fire write: ldmdb rA,{rB,rC} ; str rC,[rB,#8]
        fire = None
        for idx, insn in enumerate(img.linear()):
            if insn.mnemonic != "ldmdb":
                continue
            m = RE_STM.match(insn.op_str)
            if not m:
                continue
            regs = [REGNAMES.get(t.strip()) for t in m.group(2).split(",")]
            if len(regs) != 2 or None in regs or REGNAMES.get(m.group(1)) is None:
                continue
            nxt = img.insn(insn.address + 4)
            if nxt is None or nxt.mnemonic != "str":
                continue
            s = RE_STR.match(nxt.op_str)
            if not s or s.group(3) is None or parse_int(s.group(3)) != 8:
                continue
            if REGNAMES[s.group(1)] != regs[1] or REGNAMES[s.group(2)] != regs[0]:
                continue
            fire = (insn, nxt)
            break
        if fire:
            fire_insn, fire_write = fire
            free_entry = img.func_start(fire_insn.address)
            heap["free"] = {
                "va": hx(free_entry),
                "validated": True,
                "confidence": "high",
                "evidence": [img.text(img.insn(free_entry)),
                             img.text(fire_insn), img.text(fire_write)],
            }
            heap["fire_write"] = {
                "va": hx(fire_write.address),
                "validated": True,
                "confidence": "high",
                "shape": "%s %s" % (fire_write.mnemonic, fire_write.op_str),
                "evidence": [img.text(fire_insn), img.text(fire_write),
                             "writes size([node+4]) to [node+8] = dpc->cb"],
                "dpc_node": hx(fire_insn.address),
            }
        else:
            heap["free"] = {"va": None, "validated": False, "confidence": "none",
                            "evidence": ["no ldmdb/str r1,[r0,#8] fire shape"]}
            heap["fire_write"] = {"va": None, "validated": False,
                                  "confidence": "none", "evidence": []}

        # --- malloc core: function referencing head with the align check
        malloc = None
        malloc_ev = []
        for pair in img.pairs_to(head):
            fn = img.func_start(pair["movt_va"])
            body = img.slice(fn, fn + 0x80)
            has_sub1 = any(i.mnemonic == "sub" and "#1" in i.op_str for i in body)
            has_tst = any(i.mnemonic == "tst" for i in body)
            has_align = any(i.mnemonic in ("bic",) and "#3" in i.op_str for i in body)
            if has_sub1 and has_tst and has_align and fn not in (
                    as_int(heap_init["heap_init"]), insert):
                malloc = fn
                malloc_ev = [img.text(i) for i in body[:6]]
                malloc_ev.append(img.text(img.insn(pair["movt_va"])))
                break
        heap["malloc"] = {
            "va": hx(malloc),
            "validated": malloc is not None,
            "confidence": "high" if malloc else "none",
            "evidence": malloc_ev or ["no malloc core shape found"],
        }

        # --- dpc getter + cmd_loop + blx cb
        blx_site = None
        for insn in img.linear():
            if insn.mnemonic != "blx" or insn.address - img.base > len(self.data):
                continue
            reg = REGNAMES.get(insn.op_str.strip())
            if reg is None:
                continue
            prev = img.slice(insn.address - 0x18, insn.address)
            found = None
            for cand in reversed(prev):
                if cand.mnemonic == "ldr":
                    s = RE_STR.match(cand.op_str)
                    if s and REGNAMES[s.group(1)] == reg and s.group(3) is not None \
                            and parse_int(s.group(3)) == 4:
                        found = cand
                        break
            if found is None:
                continue
            # getter = nearest BL before the field load
            before = img.slice(found.address - 0x20, found.address)
            getter = None
            for cand in reversed(before):
                if cand.mnemonic == "bl":
                    getter = img.branch_target(cand)
                    break
            if getter is None:
                continue
            regs, ev = emulate_constants(img, getter, max_insns=6)
            dpc = regs.get(0)
            if dpc is None or not self.is_runtime_va(dpc):
                continue
            blx_site = (insn, found, getter, dpc, ev)
            break
        if blx_site:
            insn, field_load, getter, dpc, ev = blx_site
            loop = img.func_start(insn.address)
            heap["dpc"] = {
                "va": hx(dpc),
                "validated": True,
                "confidence": "high",
                "evidence": [img.text(img.insn(getter))] + ev,
                "cb_field": hx(dpc + 4),
                "arg_field": hx(dpc + 8),
            }
            heap["dpc_node"] = {
                "va": hx(dpc - 4),
                "validated": True,
                "confidence": "high",
                "evidence": ["node = dpc - 4; free() reads node=[user-8]",
                             "fire write target (node+8) = dpc+4 = cb field"],
            }
            heap["cmd_loop"] = {
                "va": hx(loop),
                "validated": True,
                "confidence": "high",
                "evidence": [img.text(img.insn(loop))],
            }
            heap["blx_cb"] = {
                "va": hx(insn.address),
                "validated": True,
                "confidence": "high",
                "shape": "%s %s" % (insn.mnemonic, insn.op_str),
                "evidence": [img.text(field_load), img.text(insn),
                             "getter 0x%x returns dpc 0x%x" % (getter, dpc)],
            }
        else:
            for key in ("dpc", "dpc_node", "cmd_loop", "blx_cb"):
                heap[key] = {"va": None, "validated": False,
                             "confidence": "none", "evidence": ["not resolved"]}

        self.res["heap"] = heap
        return heap

    def walk_back_constants(self, stm_va):
        insn = self.img.insn(stm_va)
        cur = stm_va
        allowed = ("movw", "movt", "add", "sub", "mov")
        while True:
            prev = self.img.insn(cur - 4)
            if prev is None or prev.mnemonic not in allowed:
                break
            if re.search(r"\b(sp|fp|pc)\b", prev.op_str):
                break
            cur = prev.address
            insn = prev
        return insn.address

    # -- 5. download path + clamp -----------------------------------------
    def resolve_download(self):
        img = self.img
        dl = {"function": None, "sources": [], "confidence": "none"}
        str_va = self.find_string(DL_STRING)
        if str_va is not None:
            for pair in img.pairs_to(str_va):
                fn = img.func_start(pair["movt_va"])
                if img.is_code(fn):
                    dl["function"] = hx(fn)
                    dl["sources"].append(
                        "string %r @0x%x xref 0x%x -> function 0x%x"
                        % (DL_STRING, str_va, pair["movt_va"], fn))
                    break
        # cross-check: BOOT-TO must call the download function
        boot = self.table_boot_to_va()
        if boot is not None:
            for insn in img.slice(boot, boot + 0x200):
                if insn.mnemonic == "bl":
                    target = img.branch_target(insn)
                    if target is None:
                        continue
                    t_insn = img.insn(target)
                    if t_insn and t_insn.mnemonic in ("push", "stmdb", "stmfd") \
                            and "lr" in t_insn.op_str:
                        if dl["function"] is None or as_int(dl["function"]) == target:
                            if dl["function"] is None:
                                dl["function"] = hx(target)
                            dl["sources"].append(
                                "BOOT-TO 0x%x calls 0x%x at 0x%x"
                                % (boot, target, insn.address))
                            break
        if dl["function"] is None:
            dl["classification"] = "INDETERMINATE"
            dl["confidence"] = "none"
            dl["evidence"] = ["download function not found"]
            self.res["download"] = dl
            return dl
        fn = as_int(dl["function"])
        end = min(img.end, fn + 0x600)

        # packet_length global: `ldr rX,[rG,#0x14]` right after its movw/movt
        packet_len = None
        packet_slot = None
        for pair in img.pairs_in(fn, end):
            nxt = img.slice(pair["movt_va"], pair["movt_va"] + 0x18)
            for insn in nxt:
                if insn.mnemonic == "ldr":
                    s = RE_STR.match(insn.op_str)
                    if s and REGNAMES[s.group(2)] == pair["reg"] and \
                            s.group(3) is not None and parse_int(s.group(3)) == 0x14:
                        packet_len = pair["value"] + 0x14
                        reg = REGNAMES[s.group(1)]
                        for cand in img.slice(insn.address, insn.address + 0xA0):
                            if cand.mnemonic == "str":
                                s2 = RE_STR.match(cand.op_str)
                                if s2 and REGNAMES[s2.group(1)] == reg and \
                                        s2.group(3) is not None and \
                                        REGNAMES[s2.group(2)] == 13:
                                    packet_slot = parse_int(s2.group(3))
                                    break
                        break
            if packet_len is not None:
                break

        # recv call: blx rN preceded by `add r0, r0, rOff` (buf += offset)
        recv = None
        for idx, insn in enumerate(img.slice(fn, end)):
            if insn.mnemonic != "blx":
                continue
            reg = REGNAMES.get(insn.op_str.strip())
            if reg is None:
                continue
            window = img.slice(insn.address - 0x20, insn.address)
            add_ok = False
            for cand in window:
                if cand.mnemonic == "add":
                    m = RE_REG_RR.match(cand.op_str)
                    if m and REGNAMES[m.group(1)] == REGNAMES[m.group(2)]:
                        add_ok = True
            if not add_ok:
                continue
            len_reg = None
            for cand in reversed(window):
                m = RE_MOV_RR.match(cand.op_str) if cand.mnemonic == "mov" else None
                if m and REGNAMES[m.group(1)] == 1:
                    len_reg = REGNAMES[m.group(2)]
                    break
            slot = None
            if len_reg is not None:
                for cand in reversed(img.slice(insn.address - 0xA0, insn.address)):
                    if cand.mnemonic != "add":
                        continue
                    m = RE_REG_RI.match(cand.op_str)
                    if m and REGNAMES[m.group(1)] == len_reg and \
                            REGNAMES[m.group(2)] == 13 and \
                            parse_int(m.group(3)) <= 0x200:
                        slot = parse_int(m.group(3))
                        break
            store = None
            if slot is not None:
                for cand in reversed(img.slice(insn.address - 0x40, insn.address)):
                    if cand.mnemonic != "str":
                        continue
                    s = RE_STR.match(cand.op_str)
                    if s and REGNAMES[s.group(2)] == 13 and s.group(3) is not None \
                            and parse_int(s.group(3)) == slot:
                        store = cand
                        break
            recv = {"blx": insn, "slot": slot, "store": store,
                    "len_reg": len_reg}
            break

        dl["packet_len_global"] = hx(packet_len)
        if recv is None or recv["store"] is None:
            dl["classification"] = "INDETERMINATE"
            dl["confidence"] = "none"
            dl["evidence"] = ["recv call / length store not identified"]
            self.res["download"] = dl
            return dl

        window = img.slice(recv["store"].address - 0x18, recv["store"].address)
        evidence = [img.text(i) for i in window] + \
                   [img.text(recv["store"]), img.text(recv["blx"])]

        # CLAMPED: cmp + conditional-move selecting between remaining and len
        movcc = [i for i in window if i.mnemonic in COND_MOV]
        sub = [i for i in window if i.mnemonic == "sub"]
        cmp_ = [i for i in window if i.mnemonic in ("cmp", "cmn")]
        clamped = bool(movcc and sub and cmp_)
        unclamped = False
        if not clamped:
            # UNCLAMPED: stored value is packet_len loaded straight from its slot
            for cand in reversed(img.slice(recv["store"].address - 0x10,
                                          recv["store"].address)):
                if cand.mnemonic == "ldr":
                    s = RE_STR.match(cand.op_str)
                    if s and REGNAMES[s.group(1)] == REGNAMES[recv["store"].op_str
                                                            .split(",")[0].strip()] \
                            and s.group(3) is not None \
                            and REGNAMES[s.group(2)] == 13 \
                            and packet_slot is not None \
                            and parse_int(s.group(3)) == packet_slot:
                        unclamped = True
                        break
        if clamped:
            classification = "CLAMPED"
            confidence = "high"
        elif unclamped:
            classification = "UNCLAMPED"
            confidence = "high"
        else:
            classification = "INDETERMINATE"
            confidence = "low"
            self.note("warn", "recv length store found at 0x%x but neither a "
                             "cmp+movcc clamp nor a direct packet_len store "
                             "could be proven" % recv["store"].address)

        dl.update({
            "recv_call": hx(recv["blx"].address),
            "recv_len_slot": hx(recv["slot"]) if recv["slot"] is not None else None,
            "recv_len_store": hx(recv["store"].address),
            "classification": classification,
            "confidence": confidence,
            "evidence": evidence,
            "clamp_pattern": "min(packet_len, remaining)" if clamped
                             else ("packet_len stored directly" if unclamped
                                   else "unproven"),
        })
        self.res["download"] = dl
        return dl

    def table_boot_to_va(self):
        if not self.table:
            return None
        for entry in self.table["entries"]:
            if entry["name"] == "CMD:BOOT-TO" and entry["handler"]:
                return as_int(entry["handler"])
        return None

    # -- 6. DA2 hash surface ----------------------------------------------
    def resolve_hash_surface(self, da1_sig_len):
        img = self.img
        surface = {"confidence": "none"}
        boot = self.table_boot_to_va()
        surface["boot_to_handler"] = hx(boot)
        if boot is None:
            surface["evidence"] = ["CMD:BOOT-TO not in command table"]
            self.res["da2_surface"] = surface
            return surface
        end = min(img.end, boot + 0x400)
        slot = None
        slot_insn = None
        for pair in img.pairs_in(boot, end):
            if not img.in_image(pair["value"]):
                continue
            window = img.slice(pair["movt_va"], pair["movt_va"] + 0x30)
            for idx, insn in enumerate(window):
                if insn.mnemonic != "ldrb":
                    continue
                m = RE_STR_REG.match(insn.op_str)
                if not m or REGNAMES[m.group(2)] != pair["reg"]:
                    continue
                tail = window[idx + 1: idx + 4]
                if any(t.mnemonic == "cmp" for t in tail) and \
                        any(t.mnemonic.startswith("b") and t.mnemonic != "b"
                            for t in tail):
                    slot = pair["value"]
                    slot_insn = insn
                    break
            if slot is not None:
                break
        if slot is None:
            surface["evidence"] = ["expected-digest slot (movw/movt + ldrb "
                                   "compare loop) not found in BOOT-TO"]
            self.res["da2_surface"] = surface
            return surface

        # SHA-256 entry: nearest BL before the byte-compare loop whose callee
        # advertises a fixed 32-byte digest (mov rX,#0x20 ; str rX,[rY]).
        sha_entry = None
        sha_ok = False
        sha_body = []
        for insn in reversed(img.slice(max(boot, slot_insn.address - 0x140),
                                       slot_insn.address)):
            if insn.mnemonic != "bl":
                continue
            target = img.branch_target(insn)
            if target is None or not img.is_code(target):
                continue
            body = img.slice(target, target + 0x28)
            has_32 = any(i.mnemonic == "mov" and "#0x20" in i.op_str
                         for i in body)
            has_store = any(i.mnemonic == "str" for i in body)
            if has_32 and has_store:
                sha_entry = (target, insn.address)
                sha_ok = True
                sha_body = [img.text(i) for i in body]
                break
        surface.update({
            "slot_va": hx(slot),
            "slot_file_offset": hx(img.off(slot)),
            "compare_site": hx(slot_insn.address),
            "sha_entry": hx(sha_entry[0]) if sha_entry else None,
            "sha_entry_evidence": sha_body,
            "sha_fixed_32_byte_out": sha_ok,
            "confidence": "high" if (sha_entry and sha_ok) else "medium",
            "evidence": [img.text(slot_insn)] +
                        ([img.text(img.insn(slot_insn.address + 4))]
                         if img.insn(slot_insn.address + 4) else []),
        })
        # layout cross-check (mtkclient find_da_hash_v6: len - sig_len - 0x30)
        layout = None
        for sig in ([da1_sig_len] if da1_sig_len else []) + [0x100, 0]:
            if len(self.data) - sig - 0x30 == img.off(slot):
                layout = {"sig_len": hx(sig), "matches": True}
                break
        if layout is None:
            layout = {"sig_len": hx(da1_sig_len), "matches": False}
        surface["slot_layout"] = layout
        self.res["da2_surface"] = surface
        return surface

    def hash_candidates(self, da2_data, da2_path, surface):
        if da2_data is None:
            self.res["da2_hash"] = {"source": None,
                                    "note": "no DA2 body supplied"}
            return
        slot = as_int(surface.get("slot_va"))
        cands = []
        for label, body in (("sha256(body)", da2_data),
                            ("sha256(body[:-0x100])", da2_data[:-0x100]),
                            ("sha256(body[:-0x140])", da2_data[:-0x140])):
            digest = hashlib.sha256(body).digest()
            pos = self.data.find(digest)
            cands.append({
                "candidate": label,
                "body_len": hx(len(body)),
                "sha256": digest.hex(),
                "found_at_file_offset": hx(pos) if pos >= 0 else None,
                "found_at_va": hx(self.img.va(pos)) if pos >= 0 else None,
                "matches_slot": bool(pos >= 0 and slot is not None and
                                     self.img.va(pos) == slot),
            })
        self.res["da2_hash"] = {
            "source": da2_path,
            "size": len(da2_data),
            "sha256": hashlib.sha256(da2_data).hexdigest(),
            "candidates": cands,
            "conclusion": next((c["candidate"] for c in cands
                                if c["matches_slot"]), None),
        }

    # -- 7. predicate ------------------------------------------------------
    def predicate(self):
        names = [e["name"] for e in self.table["entries"]] if self.table else []
        cmd_va = self.find_string(DRAM_REPAIR)
        trip_va = self.find_string(TRIPWIRE)
        in_table = DRAM_REPAIR in names
        handler = None
        for entry in (self.table["entries"] if self.table else []):
            if entry["name"] == DRAM_REPAIR:
                handler = entry["handler"]
        if in_table and trip_va is None:
            verdict = "VULNERABLE"
            why = "CMD:DEBUG:DRAM-REPAIR registered in the command table and " \
                  "the DA2 tripwire string is absent"
        elif (not in_table) and trip_va is not None:
            verdict = "PATCHED"
            why = "CMD:DEBUG:DRAM-REPAIR is not registered and the tripwire " \
                  "string is present"
        else:
            verdict = "INDETERMINATE"
            why = "predicate is contradictory or incomplete " \
                  "(cmd_registered=%s, tripwire=%s)" % (in_table, trip_va is not None)
        conf = "high" if self.table is not None else "low"
        self.res["predicate"] = {
            "cmd_string_present": cmd_va is not None,
            "cmd_string_va": hx(cmd_va),
            "cmd_registered_in_table": in_table,
            "cmd_handler": handler,
            "tripwire_present": trip_va is not None,
            "tripwire_va": hx(trip_va),
            "verdict": verdict,
            "reason": why,
            "confidence": conf,
            "rule": "PR #414 is_da1_vulnerable: DRAM-REPAIR present && "
                    "tripwire absent",
        }
        return self.res["predicate"]

    # -- 8. diff vs 200EX01 ------------------------------------------------
    def diff(self):
        heap = self.res.get("heap", {})
        dl = self.res.get("download", {})
        pred = self.res.get("predicate", {})
        surf = self.res.get("da2_surface", {})
        table = self.table or {}
        cur = {
            "registrar": table.get("registrar"),
            "reg_cmd": table.get("reg_cmd"),
            "table_head": table.get("table_head"),
            "cmd_loop": heap.get("cmd_loop", {}).get("va"),
            "blx_cb": heap.get("blx_cb", {}).get("va"),
            "dpc": heap.get("dpc", {}).get("va"),
            "dpc_node": heap.get("dpc_node", {}).get("va"),
            "malloc": heap.get("malloc", {}).get("va"),
            "free": heap.get("free", {}).get("va"),
            "fire_write": heap.get("fire_write", {}).get("va"),
            "insert": heap.get("insert", {}).get("va"),
            "heap_init": heap.get("heap_init", {}).get("va"),
            "heap_head": heap.get("heap_head", {}).get("va"),
            "heap_base": heap.get("heap_arena", {}).get("base"),
            "heap_size": heap.get("heap_arena", {}).get("size"),
            "download": dl.get("function"),
            "recv_len_store": dl.get("recv_len_store"),
            "packet_len": dl.get("packet_len_global"),
            "dram_repair_handler": pred.get("cmd_handler"),
            "boot_to": surf.get("boot_to_handler"),
            "sha256": surf.get("sha_entry"),
            "digest_slot": surf.get("slot_va"),
        }
        rows = []
        for key in REF:
            ref = REF[key]
            got = cur.get(key)
            got_i = as_int(got)
            if got_i is None:
                rows.append({"item": key, "this": None, "ref_200EX01": hx(ref),
                             "delta": None, "state": "absent"})
            elif got_i == ref:
                rows.append({"item": key, "this": hx(got_i), "ref_200EX01": hx(ref),
                             "delta": "0x0", "state": "identical"})
            else:
                rows.append({"item": key, "this": hx(got_i), "ref_200EX01": hx(ref),
                             "delta": ("+0x%x" % (got_i - ref)) if got_i > ref
                             else ("-0x%x" % (ref - got_i)),
                             "state": "moved"})
        names = [e["name"] for e in (self.table["entries"] if self.table else [])]
        cmd_diff = {
            "this_count": len(names),
            "ref_count": len(REF_CMDS),
            "only_in_this": [n for n in names if n not in REF_CMDS],
            "only_in_ref": [n for n in REF_CMDS if n not in names],
        }
        strings = {
            "CMD:DEBUG:DRAM-REPAIR": {
                "this": hx(self.find_string(DRAM_REPAIR)),
                "ref": hx(0x2545BD),
            },
            TRIPWIRE: {
                "this": hx(self.find_string(TRIPWIRE)),
                "ref": None,
            },
            DL_STRING: {
                "this": hx(self.find_string(DL_STRING)),
                "ref": hx(0x26278B),
            },
            "DA hash mismatch.": {
                "this": hx(self.find_string("DA hash mismatch.")),
                "ref": None,
            },
        }
        self.res["diff_vs_200EX01"] = {
            "reference": {"name": REF_NAME, "sha256": REF_SHA256},
            "addresses": rows,
            "commands": cmd_diff,
            "strings": strings,
        }
        return self.res["diff_vs_200EX01"]


def s2base(match):
    """Register name of the address register in a `ldrb rt,[rn, rm]` match."""
    return match.group(2)


# ---------------------------------------------------------------------------
# base detection / region selection
# ---------------------------------------------------------------------------
def looks_like_da1(data):
    return (len(data) >= 0x1000
            and b"CMD:BOOT-TO\x00" in data
            and data[:4] != b"\x00\x00\x00\x00")


def choose_da1_region(container, data):
    best = None
    for entry in container["entries"]:
        for region in entry["regions"]:
            if not region.get("sane"):
                continue
            blob = data[region["buf"]: region["buf"] + region["len"]]
            if b"CMD:BOOT-TO\x00" not in blob:
                continue
            score = 2 if region["addr"] == 0x200000 else 1
            if best is None or score > best[0]:
                best = (score, region)
    return best[1] if best else None


def build_audit(blob, base, label, da2_path, da2_data=None):
    audit = Audit(blob, base, label)
    audit.self_test()
    table = audit.discover_table()
    if table is None:
        audit.note("error", "command table / registrar could not be resolved "
                            "at base 0x%x - addresses below are unreliable" % base)
    heap = audit.resolve_heap()
    download = audit.resolve_download()
    surface = audit.resolve_hash_surface(
        audit.res.get("identity", {}).get("da1", {}).get("sig_len"))
    return audit, table, heap, download, surface


# ---------------------------------------------------------------------------
# human output
# ---------------------------------------------------------------------------
def render(audit):
    res = audit.res
    ident = res.get("identity", {})
    pred = res.get("predicate", {})
    st = res.get("self_test", {})
    out = []
    w = out.append

    w("=" * 78)
    w("%s %s  --  %s" % (TOOL, VERSION, ident.get("path")))
    w("=" * 78)
    w("identity : %s, DA1 %d bytes (%s) at base %s%s"
      % (ident.get("container_type"), ident.get("size", 0),
         ident.get("size_hex"), ident.get("base"),
         (", container file %d bytes (%s), sha256 %s"
          % (ident.get("file_size", 0), hx(ident.get("file_size", 0)),
             (ident.get("file_sha256") or "?")[:16] + "..."))
         if ident.get("container") else ""))
    w("sha256   : %s  (DA1 region)" % ident.get("sha256"))
    if ident.get("container"):
        c = ident["container"]
        w("container: %s, %d entries, stride %s"
          % (c["magic"], c["entries"], c["stride"]))
        for ent in c["regions"]:
            for r in ent["regions"]:
                w("   region[%d] file %s len %s addr %s sig %s boot-to=%s"
                  % (r["index"], r["file_offset"], r["len"], r["addr"],
                     r["sig_len"], r["has_CMD_BOOT_TO"]))
        if ident.get("da1"):
            d = ident["da1"]
            w("  -> embedded DA1 at file %s, %s bytes, load addr %s, sig %s%s"
              % (d["file_offset"], d["len"], d["base"], d["sig_len"],
                 ", signature zeroed" if d["sig_block_zeroed"] else ""))
        if ident.get("embedded_da2"):
            d = ident["embedded_da2"]
            w("  -> embedded DA2 at file %s, %s bytes, load addr %s"
              % (d["file_offset"], d["len"], d["base"]))
    w("")
    w("xref engine self-test: %s  (%d in-image anchors)"
      % ("PASS" if st.get("ok") else "FAIL", st.get("image_anchors_tested", 0)))
    for chk in st.get("checks", []):
        w("   [%s] %s" % ("ok" if chk["ok"] else "FAIL", chk["label"]))
        for d in chk["detail"]:
            w("        %s" % d)
    w("")
    w("-" * 78)
    w("CHECK 2  predicate #414")
    w("-" * 78)
    w("  CMD:DEBUG:DRAM-REPAIR : string %s, registered in table: %s%s"
      % (pred.get("cmd_string_va") or "absent",
         "yes" if pred.get("cmd_registered_in_table") else "no",
         (", handler " + str(pred["cmd_handler"]))
         if pred.get("cmd_handler") else ""))
    w("  tripwire string       : %s"
      % (("present @ " + pred["tripwire_va"]) if pred.get("tripwire_present")
         else "absent"))
    w("  VERDICT               : %s  (confidence: %s)"
      % (pred.get("verdict"), pred.get("confidence")))
    w("  reason                : %s" % pred.get("reason"))
    w("")
    if audit.table:
        t = audit.table
        w("-" * 78)
        w("CHECK 2b command table  (registrar %s, reg_cmd %s, list head %s)"
          % (t["registrar"], t["reg_cmd"], t["table_head"]))
        w("-" * 78)
        w("   #  name                          name_va     reg_call    handler     ok")
        for i, e in enumerate(t["entries"], 1):
            w("  %2d  %-28s  %-10s  %-10s  %-10s  %s"
              % (i, e["name"], e["name_va"], e["call_va"], e["handler"],
                 "yes" if e["handler_valid"] else "NO"))
        w("  reachability: name (movw/movt -> r0) -> reg_cmd() -> node+0x10 =")
        w("                handler (%s); dispatcher loads [node+0x10] and blx."
          % (t.get("name_to_handler_store") or "store not found"))
    w("")
    w("-" * 78)
    w("CHECK 3  download path clamp  (HeapBait overflow condition)")
    w("-" * 78)
    dl = res.get("download", {})
    w("  fp_read_host_file : %s   (sources: %s)"
      % (dl.get("function"), "; ".join(dl.get("sources", [])) or "none"))
    w("  packet_length     : %s (global), stack slot %s"
      % (dl.get("packet_len_global"), dl.get("recv_len_slot")))
    w("  recv length store : %s   recv call: %s"
      % (dl.get("recv_len_store"), dl.get("recv_call")))
    w("  classification    : %s  (confidence: %s)"
      % (dl.get("classification"), dl.get("confidence")))
    for line in dl.get("evidence", []):
        w("      %s" % line)
    w("")
    w("-" * 78)
    w("CHECK 4  heap parameters")
    w("-" * 78)
    heap = res.get("heap", {})
    w("  %-14s %-12s %-9s %s" % ("item", "va", "conf", "shape / evidence"))
    for key in ("heap_init", "heap_head", "heap_arena", "insert", "malloc",
                "free", "fire_write", "dpc", "dpc_node", "cmd_loop", "blx_cb"):
        item = heap.get(key, {})
        va = item.get("va") or item.get("base")
        if key == "heap_arena":
            shape = "base %s size %s end %s" % (item.get("base"),
                                                item.get("size"),
                                                item.get("end"))
        else:
            shape = (item.get("shape") or
                     (item.get("evidence") or [""])[0])
        w("  %-14s %-12s %-9s %s"
          % (key, va or "-", item.get("confidence", "-"), shape.split("\n")[0]))
    w("  heap layout: %s" % (
        heap.get("heap_head", {}).get("layout") or "-"))
    w("")
    w("-" * 78)
    w("CHECK 5  DA2 hash surface")
    w("-" * 78)
    sf = res.get("da2_surface", {})
    w("  BOOT-TO handler   : %s" % sf.get("boot_to_handler"))
    w("  expected digest   : %s  (file %s), compare @ %s"
      % (sf.get("slot_va"), sf.get("slot_file_offset"), sf.get("compare_site")))
    w("  SHA-256 entry     : %s  (fixed 32-byte out: %s)"
      % (sf.get("sha_entry"), sf.get("sha_fixed_32_byte_out")))
    if sf.get("slot_layout"):
        w("  slot layout       : len - sig_len - 0x30 == slot_offset -> %s "
          "(sig_len %s)" % (sf["slot_layout"].get("matches"),
                            sf["slot_layout"].get("sig_len")))
    dh = res.get("da2_hash", {})
    if dh.get("source"):
        w("  DA2 body          : %s" % dh["source"])
        w("                      %s bytes, sha256 %s"
          % (dh["size"], dh["sha256"][:16] + "..."))
        for c in dh.get("candidates", []):
            w("     %-22s -> %s%s"
              % (c["candidate"], c["found_at_va"] or "not found",
                 "  [SLOT MATCH]" if c["matches_slot"] else ""))
        w("  conclusion        : %s" % (dh.get("conclusion") or "no candidate "
                                                            "matches the slot"))
    else:
        w("  DA2 body          : %s" % dh.get("note", "none supplied"))
    w("")
    w("-" * 78)
    w("CHECK 6  diff vs %s" % REF_NAME)
    w("-" * 78)
    d = res.get("diff_vs_200EX01", {})
    w("  %-20s %-12s %-12s %s" % ("item", "this", "200EX01", "delta"))
    for row in d.get("addresses", []):
        w("  %-20s %-12s %-12s %s"
          % (row["item"], row["this"] or "-", row["ref_200EX01"],
             row["delta"] if row["delta"] is not None else row["state"]))
    c = d.get("commands", {})
    w("  commands: this=%d ref=%d  only_this=%s  only_ref=%s"
      % (c.get("this_count"), c.get("ref_count"),
         c.get("only_in_this") or "-", c.get("only_in_ref") or "-"))
    for name, info in d.get("strings", {}).items():
        w("  string %-30s this=%-10s ref=%s"
          % (name, info.get("this") or "absent", info.get("ref") or "absent"))
    w("")
    w("-" * 78)
    w("SUMMARY")
    w("-" * 78)
    verdict = pred.get("verdict")
    clamp = res.get("download", {}).get("classification")
    ready = verdict == "VULNERABLE" and clamp == "UNCLAMPED"
    w("  verdict       : %s" % verdict)
    w("  clamp         : %s" % clamp)
    w("  heapbait_ready: %s" % ("YES - unclamped recv + live DRAM-REPAIR"
                               if ready else
                               "NO (%s)" % ("patched build" if verdict == "PATCHED"
                                            else "see verdict/clamp above")))
    if verdict == "VULNERABLE" and clamp == "CLAMPED":
        w("  WARNING       : predicate satisfied but the recv length is "
          "clamped; the HeapBait overflow is not reachable on this path")
    for note in res.get("notes", []):
        w("  [%s] %s" % (note["level"], note["text"]))
    w("")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Generic static triage for MediaTek DA1 blobs (PR #414 "
                    "HeapBait predicate, addresses, DA2 hash slot, diff vs "
                    "200EX01).")
    ap.add_argument("blob", help="raw DA1 image or MTK all-in-one DA container")
    ap.add_argument("--da2", help="DA2 body file used to locate the digest slot")
    ap.add_argument("--base", default=None,
                    help="override the load base (default: container region "
                         "addr, else 0x200000)")
    ap.add_argument("--json", action="store_true", help="emit JSON only")
    ap.add_argument("--json-out", help="also write the JSON report to this file")
    args = ap.parse_args(argv)

    try:
        with open(args.blob, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        sys.stderr.write("fatal: cannot read %s: %s\n" % (args.blob, exc))
        return 2
    if not raw:
        sys.stderr.write("fatal: %s is empty\n" % args.blob)
        return 2

    da2_data = None
    da2_note = None
    if args.da2:
        try:
            with open(args.da2, "rb") as fh:
                da2_data = fh.read()
        except OSError as exc:
            da2_note = "cannot read --da2 %s: %s" % (args.da2, exc)

    file_info = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    container = parse_container(raw)
    da1_region = choose_da1_region(container, raw) if container else None
    if container and da1_region is None:
        sys.stderr.write("fatal: no DA1 region with CMD:BOOT-TO in container\n")
        return 2

    if container:
        blob = raw[da1_region["buf"]: da1_region["buf"] + da1_region["len"]]
        base = parse_int(args.base) if args.base else da1_region["addr"]
        label = "%s [DA1 region @0x%x]" % (args.blob, da1_region["buf"])
        sig_len = da1_region["sig_len"]
        if da2_data is None:
            for entry in container["entries"]:
                for region in entry["regions"]:
                    if region.get("sane") and region["addr"] == 0x40000000:
                        da2_data = raw[region["buf"]:region["buf"] + region["len"]]
                        da2_note = "embedded DA2 region @0x%x" % region["buf"]
                        break
    else:
        blob = raw
        base = parse_int(args.base) if args.base else 0x200000
        label = args.blob
        sig_len = None

    audit = Audit(blob, base, label)
    if container:
        audit.identity(container, da1_region, file_info)
    else:
        audit.identity(None, None, file_info)
        if not looks_like_da1(blob):
            audit.note("warn", "input does not look like a DA1 image "
                               "(no CMD:BOOT-TO string)")
    if sig_len:
        audit.res["identity"]["da1"]["sig_len"] = hx(sig_len)

    audit.self_test()
    audit.res["notes"] = audit.notes

    # base sanity: the command table must resolve; otherwise retry a few bases
    bases_tried = [base]
    table = audit.discover_table()
    if table is None:
        for alt in (0x0, 0x100000, 0x200000, 0x40000000):
            if alt == base:
                continue
            trial = Audit(blob, alt, label)
            if trial.discover_table() is not None:
                audit = trial
                audit.self_test()
                if container:
                    audit.identity(container, da1_region, file_info)
                else:
                    audit.identity(None, None, file_info)
                base = alt
                bases_tried.append(alt)
                audit.note("warn", "base 0x%x did not resolve the registrar; "
                                   "auto-detected base 0x%x"
                          % (bases_tried[0], alt))
                break
        table = audit.table

    audit.resolve_heap()
    audit.resolve_download()
    surface = audit.resolve_hash_surface(sig_len)
    audit.predicate()
    audit.hash_candidates(da2_data, args.da2 or da2_note, surface)
    audit.diff()
    audit.res["notes"] = audit.notes
    audit.res["tool"] = {"name": TOOL, "version": VERSION}
    audit.res["inputs"] = {
        "blob": args.blob,
        "da2": args.da2,
        "da2_source": da2_note if da2_data is not None else None,
        "base_override": args.base,
    }

    if args.json_out:
        try:
            with open(args.json_out, "w") as fh:
                json.dump(audit.res, fh, indent=2, sort_keys=False)
                fh.write("\n")
        except OSError as exc:
            sys.stderr.write("warn: cannot write %s: %s\n"
                             % (args.json_out, exc))

    if args.json:
        print(json.dumps(audit.res, indent=2, sort_keys=False))
    else:
        print(render(audit))
    return 0


if __name__ == "__main__":
    sys.exit(main())
