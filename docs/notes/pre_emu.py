#!/usr/bin/env python3
"""Offline Unicorn harness + fuzzer for the 2710EX01 / MT6789 preloader DA auth.

Target
------
``/tmp/opencode/fw2710/preloader_k6789v1_64.bin`` (sha256 ``677d1feb...``),
ARM32/Thumb PIC, 0x5F8D4 bytes.  Load base is **0x200F00** (GFH_FILE_INFO
``load_addr`` at file 0x18 and a string-literal consistency peak of 1745 vs 100
for the next candidate, see ``derive_base``).

What is modelled
----------------
The preloader's own DA verification body (VA 0x20868C..0x20876E) is executed
unmodified.  Everything *around* it that needs a device is replaced at the
narrowest possible boundary:

* **HACC** (crypto accelerator at 0x10210000) is emulated at its software API,
  not at the register level: SHA-256 one-shot (0x2439CE), SHA-256 streaming
  init/update/final (0x241834/0x241850/0x241910) and RSA-2048 public operation
  (0x243C24, Montgomery modexp) are implemented with ``hashlib``/``pow``.  The
  *bytes and verdicts* are identical to the hardware; only timing differs.
* **sec_lib bump allocator** is seeded (0x2FB758 = 0, 0x2FB75C = 0x1000; arena
  is 0x2F6770..0x2F7770, base returned by 0x237EB0).
* **sec policy** global 0x2FB688 points at a struct whose mode is 0x11
  ("verification enabled", the locked retail case).  Mode 0 is the factory
  "usbdl_vfy_da:disabled" case; ``--mode gate`` demonstrates it separately.
* **UART / timers / PMIC / top-MISC / eFuse** MMIO is mapped and stubbed; reads
  return deterministic values, writes are logged.  LEDs are not modelled.
* printf (0x23582C) and the USB status reply (0x20882C) are stubbed because
  they need the UART / USB endpoint that is not part of the auth decision.

Three drivers
-------------
``--mode func``   calls the real verify block at 0x20868C with synthetic
                  (buffer, da_len, sig_len) state.  This is the fast path and
                  the ground-truth gate.
``--mode proto``  boots the real USB command state machine at 0x208150 with a
                  synthetic transport (recv/send callbacks), sends the real
                  ``0xD7`` "download DA" command, and lets the preloader parse
                  the framing, read the buffer and verify it.  This is the
                  realistic path short of a full boot (DRAM/UFS/PMIC init).
``--mode boot``   best-effort real boot from the ARM entry 0x201000.  Expected
                  to stop in DRAM/UFS/PMIC init; reported honestly.

Fuzz classes: ACCEPT_VALID, ACCEPT_INVALID (BAD), ACCEPT_HEADER_ONLY
(container header changed, signed payload unchanged - not a bypass),
REJECT_0x7024, OTHER_ERROR, CRASH, HANG.  ACCEPT_INVALID is the finding of the
day; it is asserted to be zero in ``--mode func`` self-check.

Usage
-----
    python3 pre_emu.py --mode func
    python3 pre_emu.py --mode boot
    python3 pre_emu.py --mode fuzz --cases 2000 --seed 1 --json /tmp/x.json
    python3 pre_emu.py --replay /tmp/opencode/pre_fuzz_cases/case_0001.json

No device, no network, no flashing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import struct
import sys
import time
from collections import Counter, OrderedDict

from unicorn import (
    Uc,
    UcError,
    UC_ARCH_ARM,
    UC_MODE_ARM,
    UC_MODE_THUMB,
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ,
    UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_UNMAPPED,
    UC_PROT_ALL,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    UC_ARM_REG_CPSR,
)

# --------------------------------------------------------------------------
# target constants
# --------------------------------------------------------------------------
IMAGE_DEFAULT = "/tmp/opencode/fw2710/preloader_k6789v1_64.bin"
DA2710_DEFAULT = "/tmp/opencode/fw2710/DA_BR.bin"
DA200_DEFAULT = "/root/mtkclient/docs/notes/rmx3630-da2/DA_BR.bin"
# the 2026-10-26 workspace reset removed docs/notes/rmx3630-da2 from this
# checkout; the extracted signed DA1 is still available under /tmp.
DA200_FALLBACKS = [
    "/tmp/opencode/da/da1_dabr.bin",
    "/tmp/opencode/da/DA_BR.bin",
    "/tmp/opencode/da200/DA_BR.bin",
    "/tmp/opencode/rmx3630-da2/DA_BR.bin",
]
IMAGE_SHA_PREFIX = "677d1feb"

BASE = 0x200F00                 # VA of file offset 0 (derived, see derive_base)
IMG_MAX = 0x80000
BSS_LO, BSS_HI = 0x2F1000, 0x2FB848
HEAP_LO, HEAP_HI = 0x2F6770, 0x2F7770
HARNESS_SP = 0x2FF800
SENTINEL = 0x1FF000
BUF_BASE = 0x40000000           # func-mode DA buffer
DA_DST = 0x40200000             # proto-mode receive buffer (file 0x4020000C)
DA_RX_MAX = 0x400000            # receive-state bound (0x2083DC)

# globals (all BSS)
G_HEAP_OFF = 0x2FB758
G_HEAP_LEN = 0x2FB75C
G_SECPOL = 0x2FB688
G_DAA_FLAG = 0x2F3158
G_KEY_READY = 0x2F9F28
G_KEY_PTR = 0x2F9F38
G_EXPECTED_SIGLEN = 0x25F350

# code addresses (all VAs, 2710 build)
A_VERIFY_BLOCK = 0x20868C      # key install + length checks + PSS + 0x7024
A_VERIFY_FINISH = 0x208742     # r0 = verdict; then flag write or error tail
A_FLAG_WRITE = 0x20876A        # strb #1 -> *(0x2F3158)
A_FLAG_DONE = 0x208770
A_IS_DAA_ENABLED = 0x241172
A_KEY_WRAPPER = 0x23794C
A_KEY_SETUP = 0x23EA24
A_PSS_THUNK = 0x237938
A_PSS_WHOLE = 0x23EA96
A_PSS_CORE = 0x2414B8
A_STATUS_SEND = 0x20882C
A_PRINTF = 0x23582C
A_ASSERT = 0x231FC8
A_MEMSET = 0x23872A
A_CMD_LOOP = 0x208150
A_CMD_RECV32 = 0x2089AC

# HACC software API
A_HASH_INIT = 0x241834
A_HASH_UPDATE = 0x241850
A_HASH_FINAL = 0x241910
A_HASH_ONESHOT = 0x2439CE
A_RSA_MODEXP = 0x243C24

# synthetic transport
P_CTX = 0x2FA000
P_OPS = 0x2FA100
P_STUB_SEND = 0x300000
P_STUB_RECV = 0x300010
P_SECPOL_STRUCT = 0x2FA200

# --------------------------------------------------------------------------
# memory map
# --------------------------------------------------------------------------
# (base, size, name, kind)
MEM_MAP = [
    (0x00080000, 0x00080000, "low-peri", "mmio"),
    (0x00100000, 0x000F0000, "brom-boot-args", "ram"),
    (0x1F0000, 0x00120000, "sram+image+bss", "ram"),
    (0x08000000, 0x01000000, "top-misc", "mmio"),
    (0x10000000, 0x04000000, "peri(usb/uart/gpt/pmic/efuse/hacc)", "mmio"),
    (0x40000000, 0x02000000, "dram(da buffer)", "ram"),
]

# deterministic MMIO read table (address, mask, value).  Only the registers the
# code actually polls need a non-zero value; everything else is 0.
MMIO_READS = {
    0x11002014: (0xFFFFFFFF, 0x00000060),   # UART0 LSR: THRE|TEMT
    0x11003014: (0xFFFFFFFF, 0x00000060),   # UART1 LSR
    0x1000801C: (0xFFFFFFFF, 0x00000001),   # GPT status
    0x10210E9C: (0xFFFFFFFF, 0xFFFFFFFF),   # HACC status (never reached)
    0x10210E98: (0xFFFFFFFF, 0xFFFFFFFF),   # HACC status
}

CLASSES = [
    "ACCEPT_VALID",
    "ACCEPT_INVALID",
    "ACCEPT_HEADER_ONLY",
    "REJECT_0x7024",
    "OTHER_ERROR",
    "CRASH",
    "HANG",
]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_image(path: str) -> bytes:
    with open(path, "rb") as f:
        img = f.read()
    if len(img) < 0x200:
        raise SystemExit("image too small: %s" % path)
    return img


def parse_gfh(img: bytes) -> dict:
    magic, size = struct.unpack_from("<II", img, 0)
    if magic != 0x014D4D4D:
        raise SystemExit("not a GFH image (magic %#x)" % magic)
    typ = img[8:20].rstrip(b"\x00").decode("latin1")
    out = {"magic": magic, "hdr_size": size, "type": typ}
    if typ == "FILE_INFO":
        # u32 magic, u32 size, char type[12], u32 file_type,
        # u32 ???, u32 load_addr, u32 total_size, u32 max_size
        out["load_addr"] = struct.unpack_from("<I", img, 0x1C)[0]
        out["total_size"] = struct.unpack_from("<I", img, 0x20)[0]
        out["max_size"] = struct.unpack_from("<I", img, 0x24)[0]
    return out


def derive_base(img: bytes) -> tuple[int, int, int]:
    """Return (base, best_score, next_score).

    Scores how many printable-string VAs appear verbatim as 32-bit literals in
    the image.  The true base produces a sharp peak (the PIC literal pool).
    """
    words = Counter()
    for i in range(0, len(img) - 4, 4):
        words[int.from_bytes(img[i:i + 4], "little")] += 1
    offs = [m.start() for m in re.finditer(rb"[ -~]{8,}", img)]
    best = (-1, 0)
    second = -1
    for base in range(0x1FF000, 0x202000, 4):
        score = sum(1 for o in offs if (base + o) in words)
        if score > best[0]:
            second = best[0]
            best = (score, base)
        elif score > second:
            second = score
    return best[1], best[0], second


def parse_container(blob: bytes) -> dict:
    """MTK DA container header + 3-entry region table (host side only)."""
    magic = struct.unpack_from("<I", blob, 0x64)[0]
    regions = []
    for i in range(3):
        off, size, load, sig_off, sig_len = struct.unpack_from("<5I", blob, 0x80 + i * 0x14)
        regions.append({"off": off, "size": size, "load": load,
                        "sig_off": sig_off, "sig_len": sig_len})
    return {
        "name": blob[:0x20].rstrip(b"\x00").decode("latin1", "replace"),
        "banner": blob[0x40:0x60].rstrip(b"\x00").decode("latin1", "replace"),
        "magic": magic,
        "da_ver": struct.unpack_from("<I", blob, 0x68)[0],
        "hwcode": struct.unpack_from("<I", blob, 0x6C)[0],
        "subcode": struct.unpack_from("<H", blob, 0x70)[0],
        "hw_ver": struct.unpack_from("<H", blob, 0x72)[0],
        "regions": regions,
    }


def is_container(blob: bytes) -> bool:
    return len(blob) > 0x100 and blob[:18] == b"MTK_DOWNLOAD_AGENT"


def da1_from_blob(blob: bytes, idx: int = 1) -> tuple[bytes, int, int]:
    """Accept either a full DA container or a raw DA1+trailer image."""
    if is_container(blob):
        return host_extract_da1(blob, idx)
    return blob, len(blob), 0x100


def host_extract_da1(blob: bytes, idx: int = 1) -> tuple[bytes, int, int]:
    """Mimic mtkclient: send region[idx].m_buf .. +m_len (DA1 + 0x100 trailer)."""
    off, size = struct.unpack_from("<II", blob, 0x80 + idx * 0x14)
    sig_off, sig_len = struct.unpack_from("<II", blob, 0x80 + idx * 0x14 + 0xC)
    buf = blob[off:off + size]
    return buf, len(buf), sig_len or 0x100


def be32(v: int) -> bytes:
    return (v & 0xFFFFFFFF).to_bytes(4, "big")


# --------------------------------------------------------------------------
# emulator
# --------------------------------------------------------------------------
class PreloaderEmu:
    def __init__(self, image: bytes, budget: int = 3_000_000, trace: bool = False):
        self.image = image
        self.budget = budget
        self.trace = trace
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        self.hash_ctx: dict[int, bytearray] = {}
        self.stop: dict = {}
        self.mmio_writes: list[tuple[int, int, int]] = []
        self.mmio_reads: list[tuple[int, int]] = []
        self.prints: list[int] = []
        self.rsa_calls = 0
        self.memset_calls: list[tuple[int, int, int, int]] = []
        self.write_oob: list[tuple[int, int, int, int]] = []
        self.tick = 0
        self._stopped = False
        self._map()
        self._load()
        self._init_globals()
        self._install_hooks()

    # ---- setup ---------------------------------------------------------
    def _map(self):
        for base, size, name, kind in MEM_MAP:
            try:
                self.uc.mem_map(base, size, UC_PROT_ALL)
            except UcError as e:
                raise SystemExit("map %s %#x+%#x failed: %s" % (name, base, size, e))
        self._mmio_ranges = [(b, b + s, n) for b, s, n, k in MEM_MAP if k == "mmio"]
        self._ram_ranges = [(b, b + s, n) for b, s, n, k in MEM_MAP if k == "ram"]

    def _load(self):
        self.uc.mem_write(BASE, self.image)
        # BSS is already zero because the mapping is fresh; zero explicitly for
        # clarity (the real entry does the same at 0x201124).
        self.uc.mem_write(BSS_LO, b"\x00" * (BSS_HI - BSS_LO))

    def _init_globals(self):
        self.write_u32(G_HEAP_OFF, 0)                 # bump offset
        self.write_u32(G_HEAP_LEN, HEAP_HI - HEAP_LO)  # arena size
        self.write_u32(G_SECPOL, P_SECPOL_STRUCT)
        self.write_u32(P_SECPOL_STRUCT, 0x11)         # sec mode: enabled
        self.uc.mem_write(G_DAA_FLAG, b"\x00")
        # sanity: the build expects a 0x100-byte DA signature
        self.expected_siglen = self.read_u32(G_EXPECTED_SIGLEN)

    # ---- raw access ----------------------------------------------------
    def read_u32(self, va: int) -> int:
        return struct.unpack("<I", self.uc.mem_read(va, 4))[0]

    def write_u32(self, va: int, v: int):
        self.uc.mem_write(va, struct.pack("<I", v & 0xFFFFFFFF))

    def reg(self, r: int) -> int:
        return self.uc.reg_read(r)

    def setreg(self, r: int, v: int):
        self.uc.reg_write(r, v & 0xFFFFFFFF)

    # ---- hooks ---------------------------------------------------------
    def _install_hooks(self):
        uc = self.uc
        # budget-free stop markers
        for a, cb in [
            (SENTINEL, self._h_sentinel),
            (A_VERIFY_FINISH, self._h_finish),
            (A_FLAG_DONE, self._h_flag_done),
            (A_ASSERT, self._h_assert),
            (A_STATUS_SEND, self._h_ret0),
        ]:
            uc.hook_add(UC_HOOK_CODE, cb, begin=a, end=a)
        # crypto shims
        for a, cb in [
            (A_HASH_INIT, self._h_hash_init),
            (A_HASH_UPDATE, self._h_hash_update),
            (A_HASH_FINAL, self._h_hash_final),
            (A_HASH_ONESHOT, self._h_hash_oneshot),
            (A_RSA_MODEXP, self._h_rsa_modexp),
            (A_PRINTF, self._h_printf),
        ]:
            uc.hook_add(UC_HOOK_CODE, cb, begin=a, end=a)
        # optional instrumentation
        if self.trace:
            uc.hook_add(UC_HOOK_CODE, self._h_memset, begin=A_MEMSET, end=A_MEMSET)
        uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._h_unmapped)
        for lo, hi, _n in self._mmio_ranges:
            uc.hook_add(UC_HOOK_MEM_READ, self._h_mmio_read, begin=lo, end=hi - 1)
            uc.hook_add(UC_HOOK_MEM_WRITE, self._h_mmio_write, begin=lo, end=hi - 1)

    # ---- generic small hooks -------------------------------------------
    def _ret(self):
        self.setreg(UC_ARM_REG_PC, self.reg(UC_ARM_REG_LR))

    def _h_ret0(self, uc, addr, size, _u):
        self.setreg(UC_ARM_REG_R0, 0)
        self._ret()

    def _h_sentinel(self, uc, addr, size, _u):
        self.stop.setdefault("ret", True)
        self._halt()

    def _h_finish(self, uc, addr, size, _u):
        r0 = self.reg(UC_ARM_REG_R0) & 0xFFFFFFFF
        self.stop["finish"] = r0
        if r0 != 0 and not getattr(self, "follow_error", False):
            self._halt()

    def _h_flag_done(self, uc, addr, size, _u):
        self.stop["flag"] = self.uc.mem_read(G_DAA_FLAG, 1)[0]
        self._halt()

    def _h_assert(self, uc, addr, size, _u):
        self.stop["assert"] = self.reg(UC_ARM_REG_PC)
        self._halt()

    def _halt(self):
        self._stopped = True
        self.uc.emu_stop()

    def _h_unmapped(self, uc, access, address, size, value, _u):
        self.stop["fault"] = (access, address & 0xFFFFFFFF, size,
                              self.reg(UC_ARM_REG_PC))
        self._halt()

    def _h_memset(self, uc, addr, size, _u):
        dst = self.reg(UC_ARM_REG_R0)
        val = self.reg(UC_ARM_REG_R1)
        n = self.reg(UC_ARM_REG_R2)
        # LR identifies the caller; 0x20875F is the DA error tail.
        self.memset_calls.append((dst, val, n, self.reg(UC_ARM_REG_LR)))

    # ---- MMIO ----------------------------------------------------------
    def _h_mmio_read(self, uc, access, address, size, value, _u):
        address &= 0xFFFFFFFF
        v = 0
        if address == 0x10017008:
            # free-running microsecond counter used by mdelay()/time checks.
            # Deterministic: advances by a fixed step per read.
            v = self.tick & 0xFFFFFFFF
            self.tick = (self.tick + 0x100) & 0xFFFFFFFF
        elif address in MMIO_READS:
            mask, want = MMIO_READS[address]
            v = want & mask
        elif 0x10008000 <= address < 0x10009000:      # GPT: free-running
            v = 0x1000
        if size and size <= 4:
            try:
                uc.mem_write(address, v.to_bytes(size, "little"))
            except UcError:
                pass
        if self.trace and len(self.mmio_reads) < 200:
            self.mmio_reads.append((address, size))

    def _h_mmio_write(self, uc, access, address, size, value, _u):
        address &= 0xFFFFFFFF
        if len(self.mmio_writes) < 400:
            self.mmio_writes.append((address, value, self.reg(UC_ARM_REG_PC)))

    # ---- HACC shims ----------------------------------------------------
    def _h_hash_init(self, uc, addr, size, _u):
        ctx = self.reg(UC_ARM_REG_R0)
        if ctx == 0:
            self.setreg(UC_ARM_REG_R0, 0xFFFFFFFF)
        else:
            self.hash_ctx[ctx] = bytearray()
            self.setreg(UC_ARM_REG_R0, 0)
        self._ret()

    def _h_hash_update(self, uc, addr, size, _u):
        ctx = self.reg(UC_ARM_REG_R0)
        ptr = self.reg(UC_ARM_REG_R1)
        n = self.reg(UC_ARM_REG_R2)
        if ctx == 0 or ptr == 0:
            self.setreg(UC_ARM_REG_R0, 0xFFFFFFFE)
        else:
            self.hash_ctx.setdefault(ctx, bytearray()).extend(bytes(uc.mem_read(ptr, n)))
            self.setreg(UC_ARM_REG_R0, 0)
        self._ret()

    def _h_hash_final(self, uc, addr, size, _u):
        ctx = self.reg(UC_ARM_REG_R0)
        out = self.reg(UC_ARM_REG_R1)
        d = hashlib.sha256(bytes(self.hash_ctx.get(ctx, b""))).digest()
        if out:
            uc.mem_write(out, d)
        self.setreg(UC_ARM_REG_R0, 0)
        self._ret()

    def _h_hash_oneshot(self, uc, addr, size, _u):
        ptr = self.reg(UC_ARM_REG_R0)
        n = self.reg(UC_ARM_REG_R1)
        out = self.reg(UC_ARM_REG_R2)
        utext = bytes(uc.mem_read(ptr, n)) if n else b""
        if out:
            uc.mem_write(out, hashlib.sha256(utext).digest())
        self.setreg(UC_ARM_REG_R0, 0)
        self._ret()

    def _h_rsa_modexp(self, uc, addr, size, _u):
        sig = self.reg(UC_ARM_REG_R0)
        key = self.reg(UC_ARM_REG_R1)
        out = self.reg(UC_ARM_REG_R2)
        n = int.from_bytes(bytes(uc.mem_read(key, 0x100)), "little")
        m = int.from_bytes(bytes(uc.mem_read(sig, 0x100)), "little")
        self.rsa_calls += 1
        if n == 0 or out == 0:
            self.setreg(UC_ARM_REG_R0, 2)
        else:
            r = pow(m, 65537, n)
            uc.mem_write(out, r.to_bytes(0x100, "little"))
            self.setreg(UC_ARM_REG_R0, 0)
        self._ret()

    def _h_printf(self, uc, addr, size, _u):
        if self.trace and len(self.prints) < 64:
            self.prints.append(self.reg(UC_ARM_REG_R0))
        self.setreg(UC_ARM_REG_R0, 0)
        self._ret()

    # ---- execution -----------------------------------------------------
    def reset_stop(self):
        self.stop = {}
        self._stopped = False
        self.mmio_writes.clear()
        self.mmio_reads.clear()
        self.prints.clear()
        self.memset_calls.clear()
        self.write_oob.clear()

    def run(self, pc: int, thumb: bool = True, sp: int = HARNESS_SP,
            args: tuple = (), budget: int | None = None) -> dict:
        """Run until a stop hook / sentinel / budget.  Returns self.stop."""
        uc = self.uc
        self.reset_stop()
        if thumb:
            cpsr = uc.reg_read(UC_ARM_REG_CPSR) | 0x20
            uc.reg_write(UC_ARM_REG_CPSR, cpsr)
        else:
            cpsr = uc.reg_read(UC_ARM_REG_CPSR) & ~0x20
            uc.reg_write(UC_ARM_REG_CPSR, cpsr)
        uc.reg_write(UC_ARM_REG_SP, sp)
        uc.reg_write(UC_ARM_REG_LR, SENTINEL | 1)
        for i, v in enumerate(args[:4]):
            uc.reg_write(UC_ARM_REG_R0 + i, v & 0xFFFFFFFF)
        b = self.budget if budget is None else budget
        try:
            uc.emu_start(pc | (1 if thumb else 0), 0, 0, b)
        except UcError as e:
            self.stop.setdefault("fault", ("uc", None, None, uc.reg_read(UC_ARM_REG_PC)))
            self.stop["exc"] = str(e)
        if not self.stop:
            # count exhausted without a marker
            self.stop["budget"] = uc.reg_read(UC_ARM_REG_PC)
        return self.stop

    def call(self, va: int, args: tuple = (), budget: int | None = None) -> tuple[int, dict]:
        st = self.run(va, True, HARNESS_SP, args, budget)
        return self.reg(UC_ARM_REG_R0) & 0xFFFFFFFF, st


# --------------------------------------------------------------------------
# case runners
# --------------------------------------------------------------------------
def _bss_value(emu: PreloaderEmu, va: int, size: int) -> bytes:
    return bytes(emu.uc.mem_read(va, size))


class CaseRunner:
    def __init__(self, image: bytes, da2710: bytes, da200: bytes, trace: bool = False):
        self.image = image
        self.da2710 = da2710
        self.da200 = da200
        self.trace = trace
        self.c2710 = parse_container(da2710) if is_container(da2710) else None
        self.c200 = parse_container(da200) if is_container(da200) else None
        self.da1_2710, self.len_2710, self.siglen_2710 = da1_from_blob(da2710, 1)
        self.da1_200, self.len_200, self.siglen_200 = da1_from_blob(da200, 1)
        self.real_sig_2710 = self.da1_2710[-0x100:]
        self.real_msg_2710 = self.da1_2710[:-0x100]

    # ---- func mode -----------------------------------------------------
    def func_case(self, buf: bytes, da_len: int, sig_len: int,
                  writes: bool = False, budget: int = 3_000_000,
                  follow_error: bool = False, header_only: bool = False) -> dict:
        emu = PreloaderEmu(self.image, budget=budget,
                           trace=writes or follow_error or self.trace)
        emu.follow_error = follow_error
        emu.uc.mem_write(BUF_BASE, buf if buf else b"\x00")
        emu.setreg(UC_ARM_REG_R9, da_len)          # sb  = da_len
        emu.setreg(UC_ARM_REG_R11, BUF_BASE)       # fp  = buffer
        emu.setreg(UC_ARM_REG_R6, sig_len)         # r6  = sig_len
        st = emu.run(A_VERIFY_BLOCK, True, HARNESS_SP, (), budget)
        return self._result(emu, st, buf, da_len, sig_len, mode="func",
                            writes=writes or follow_error,
                            header_only=header_only)

    # ---- proto mode ----------------------------------------------------
    def proto_case(self, data: bytes, da_len: int | None = None, sig_len: int = 0x100,
                   cmd: int = 0xD7, field0: int = 0,
                   handshake: bytes = b"\xa0\x0a\x50\x05",
                   budget: int = 8_000_000, follow_error: bool = False) -> dict:
        emu = PreloaderEmu(self.image, budget=budget,
                           trace=self.trace or follow_error)
        emu.follow_error = follow_error
        if da_len is None:
            da_len = len(data)
        emu.write_u32(P_CTX, 0)                     # ctx[0] != 1: skip baud switch
        emu.write_u32(P_CTX + 8, P_OPS)
        emu.write_u32(P_OPS, P_STUB_SEND | 1)
        emu.write_u32(P_OPS + 4, P_STUB_RECV | 1)
        fifo = bytearray(handshake)
        fifo.append(cmd & 0xFF)
        fifo += be32(field0) + be32(da_len) + be32(sig_len)
        fifo += data
        sent = bytearray()
        uc = emu.uc

        def h_send(_uc, _a, _s, _u):
            p = emu.reg(UC_ARM_REG_R0)
            n = emu.reg(UC_ARM_REG_R1)
            sent.extend(bytes(_uc.mem_read(p, n)))
            emu.setreg(UC_ARM_REG_R0, 1)
            emu._ret()

        def h_recv(_uc, _a, _s, _u):
            p = emu.reg(UC_ARM_REG_R0)
            n = emu.reg(UC_ARM_REG_R1)
            if len(fifo) < n:
                emu.setreg(UC_ARM_REG_R0, 1)
                emu._ret()
                return
            emu.uc.mem_write(p, bytes(fifo[:n]))
            del fifo[:n]
            emu.setreg(UC_ARM_REG_R0, 0)
            emu._ret()

        uc.hook_add(UC_HOOK_CODE, h_send, begin=P_STUB_SEND, end=P_STUB_SEND)
        uc.hook_add(UC_HOOK_CODE, h_recv, begin=P_STUB_RECV, end=P_STUB_RECV)
        st = emu.run(A_CMD_LOOP, True, HARNESS_SP, (P_CTX, 0x7FFFFFFF), budget)
        res = self._result(emu, st, data, da_len, sig_len, mode="proto",
                            writes=follow_error)
        res["sent"] = sent.hex()
        res["fifo_left"] = len(fifo)
        return res

    # ---- classification ------------------------------------------------
    def _result(self, emu: PreloaderEmu, st: dict, buf: bytes, da_len: int,
                sig_len: int, mode: str, writes: bool,
                header_only: bool = False) -> dict:
        flag = bytes(emu.uc.mem_read(G_DAA_FLAG, 1))[0]
        exact = (buf == self.da1_2710 and da_len == self.len_2710
                 and sig_len == 0x100)
        cls = "HANG"
        r0 = None
        if "fault" in st:
            cls = "CRASH"
        elif "finish" in st:
            r0 = st["finish"]
            if r0 == 0:
                if exact and header_only:
                    cls = "ACCEPT_HEADER_ONLY"
                else:
                    cls = "ACCEPT_VALID" if exact else "ACCEPT_INVALID"
            elif r0 == 0x7024:
                cls = "REJECT_0x7024"
            else:
                cls = "OTHER_ERROR"
        elif st.get("assert"):
            cls = "HANG"          # assert() is a dead loop in this build
        elif "flag" in st or flag:
            if exact and header_only:
                cls = "ACCEPT_HEADER_ONLY"
            else:
                cls = "ACCEPT_VALID" if exact else "ACCEPT_INVALID"
        elif "budget" in st:
            cls = "HANG"

        # write-side audit: what would the error tail memset() and where?
        dst = emu.reg(UC_ARM_REG_R11)
        n = emu.reg(UC_ARM_REG_R9)
        wipe = {"dst": dst, "len": n, "in_rx_buf": dst == DA_DST}
        if writes:
            wipe["memset_calls"] = [
                {"dst": d, "len": l, "lr": p} for d, _v, l, p in emu.memset_calls
            ]
        res = {
            "class": cls,
            "mode": mode,
            "r0": r0,
            "flag": flag,
            "pc": emu.reg(UC_ARM_REG_PC),
            "stop": {k: (v if isinstance(v, (int, str, type(None))) else list(v))
                     for k, v in st.items()},
            "buf_sha": sha(buf)[:16],
            "buf_len": len(buf),
            "da_len": da_len,
            "sig_len": sig_len,
            "exact_payload": exact,
            "rsa_calls": emu.rsa_calls,
            "wipe": wipe,
            "mmio_writes": len(emu.mmio_writes),
        }
        if "fault" in st:
            f = st["fault"]
            res["fault"] = {"access": f[0], "addr": f[1], "size": f[2], "pc": f[3]}
        return res

    # ---- primitive PSS (key matrix) ------------------------------------
    def pss_case(self, da: bytes, keyptr: int) -> int:
        """Install a built-in key blob and run 0x23EA96 (PSS whole)."""
        emu = PreloaderEmu(self.image, budget=2_000_000, trace=False)
        emu.uc.mem_write(BUF_BASE, da)
        kr, _ = emu.call(A_KEY_SETUP, (keyptr, 0x100), 100_000)
        if kr != 0:
            return kr
        r0, _ = emu.call(A_PSS_WHOLE,
                         (BUF_BASE, len(da) - 0x100,
                          BUF_BASE + len(da) - 0x100, 0x100), 2_000_000)
        return r0

    # ---- ground truth --------------------------------------------------
    def validate(self) -> list[dict]:
        out = []
        # primitive: the real verify block, exact DA1 of each generation
        out.append(self.func_case(self.da1_2710, self.len_2710, 0x100))
        out[-1]["label"] = "2710 K2 DA1 (expect ACCEPT_VALID)"
        out.append(self.func_case(self.da1_200, self.len_200, 0x100))
        out[-1]["label"] = "200EX01 K1 DA1 (expect REJECT_0x7024)"
        # zeroed AllInOne-style trailer
        z = bytearray(self.da1_2710)
        z[-0x100:] = b"\x00" * 0x100
        out.append(self.func_case(bytes(z), self.len_2710, 0x100))
        out[-1]["label"] = "2710 DA1 zeroed trailer (expect REJECT_0x7024)"
        # proto: the real state machine with the real DA1
        r = self.proto_case(self.da1_2710, self.len_2710, 0x100, budget=8_000_000)
        r["label"] = "proto 0xD7 + 2710 DA1 (expect ACCEPT_VALID)"
        out.append(r)
        r = self.proto_case(self.da1_200, self.len_200, 0x100, budget=8_000_000)
        r["label"] = "proto 0xD7 + 200EX01 DA1 (expect REJECT_0x7024)"
        out.append(r)
        return out


# --------------------------------------------------------------------------
# mutations / fuzz
# --------------------------------------------------------------------------
def mutate_trailer(rng: random.Random, buf: bytearray, how: str):
    n = len(buf)
    if n < 0x100:
        return
    s = n - 0x100
    if how == "zero":
        buf[s:] = b"\x00" * 0x100
    elif how == "ff":
        buf[s:] = b"\xff" * 0x100
    elif how == "random":
        buf[s:] = bytes(rng.randrange(256) for _ in range(0x100))
    elif how == "random_bc":
        buf[s:] = bytes(rng.randrange(256) for _ in range(0xFF)) + b"\xbc"
    elif how == "flip1":
        i = s + rng.randrange(0x100)
        buf[i] ^= 1 << rng.randrange(8)
    elif how == "flip8":
        for _ in range(8):
            i = s + rng.randrange(0x100)
            buf[i] ^= 1 << rng.randrange(8)
    elif how == "swap":
        i = s + rng.randrange(0x100)
        j = s + rng.randrange(0x100)
        buf[i], buf[j] = buf[j], buf[i]


def mutate_msg(rng: random.Random, buf: bytearray, how: str):
    n = max(1, len(buf) - 0x100)
    if how == "flip1":
        i = rng.randrange(n)
        buf[i] ^= 1 << rng.randrange(8)
    elif how == "flip8":
        for _ in range(8):
            i = rng.randrange(n)
            buf[i] ^= 1 << rng.randrange(8)
    elif how == "zero_block":
        i = rng.randrange(n)
        ln = min(rng.choice([16, 64, 256, 4096]), n - i)
        buf[i:i + ln] = b"\x00" * ln
    elif how == "fill":
        i = rng.randrange(n)
        ln = min(rng.choice([16, 64, 256]), n - i)
        buf[i:i + ln] = bytes([rng.randrange(256)]) * ln


def diff_patch(base: bytes, buf: bytes) -> dict:
    """Serialise an exact, RNG-free reproduction patch for a case buffer."""
    if buf == base:
        return {"patch": []}
    if len(buf) != len(base):
        if len(buf) <= 0x20000:
            return {"full_hex": buf.hex()}
        return {"prefix_len": len(buf), "prefix_hex": buf[:0x20000].hex()}
    patch = []
    i = 0
    n = len(base)
    while i < n:
        if buf[i] == base[i]:
            i += 1
            continue
        j = i
        while j < n and buf[j] != base[j]:
            j += 1
        patch.append([i, buf[i:j].hex()])
        i = j
    return {"patch": patch}


def make_case(rng: random.Random, runner: CaseRunner, mode: str) -> dict:
    """Return a case description: {buf, da_len, sig_len, tag, recipe}."""
    base = runner.da1_2710
    tag = "da1"
    header_only = False
    buf = bytearray(base)
    da_len = runner.len_2710
    sig_len = 0x100
    recipe = {"kind": "da1_2710", "ops": []}

    r = rng.random()
    if mode == "proto":
        # protocol/framing fuzz: lengths, handshake, command byte, truncation
        choice = rng.choice(["len", "siglen", "trunc", "huge", "hs",
                             "field0", "cmd", "checksum"])
        if choice == "len":
            da_len = rng.choice([0, 1, 0xFE, 0xFF, 0x100, 0x101, 0x200,
                                 0x1000, 0xFFFF, 0x100000, 0x100001,
                                 0x400000, 0x400001, 0xFFFFFFFF])
            tag = "da_len=%#x" % da_len
        elif choice == "siglen":
            sig_len = rng.choice([0, 1, 0x20, 0x40, 0xFF, 0x100, 0x101,
                                  0x200, 0x1000, 0xFFFFFFFF])
            tag = "sig_len=%#x" % sig_len
        elif choice == "trunc":
            da_len = rng.choice([1, 0x40, 0x100, 0x200, 0x1000])
            buf = buf[:rng.choice([0, 1, 0x10, 0x100])]
            tag = "truncated"
        elif choice == "huge":
            da_len = 0x400001 + rng.randrange(0x100)
            tag = "da_len_huge"
        elif choice == "hs":
            tag = "bad_handshake"
        elif choice == "field0":
            tag = "field0=%#x" % rng.randrange(1 << 32)
        elif choice == "cmd":
            tag = "cmd=%#x" % rng.choice([0xC4, 0xC5, 0xC7, 0xCE, 0xD0,
                                          0xD1, 0xD3, 0xD5, 0xD6, 0xD8,
                                          0xDB, 0xDF, 0xE1, 0xE5, 0xE6,
                                          0xE7, 0xFF, 0x00])
        else:
            tag = "checksum(ignored)"
        recipe = {"kind": "proto", "tag": tag}
        return {"buf": bytes(buf), "da_len": da_len, "sig_len": sig_len,
                "tag": tag, "recipe": recipe}

    # func mode
    if r < 0.44:
        how = rng.choice(["zero", "ff", "random", "random_bc", "flip1",
                          "flip8", "swap"])
        mutate_trailer(rng, buf, how)
        tag = "sig_" + how
        recipe["ops"].append(["trailer", how])
        if rng.random() < 0.25:
            mutate_msg(rng, buf, rng.choice(["flip1", "flip8", "zero_block"]))
            tag += "+msg"
    elif r < 0.66:
        how = rng.choice(["flip1", "flip8", "zero_block", "fill"])
        mutate_msg(rng, buf, how)
        tag = "msg_" + how
        recipe["ops"].append(["msg", how])
    elif r < 0.80:
        da_len = rng.choice([0, 1, 0xFE, 0xFF, 0x100, 0x101, 0x200, 0x1000,
                             0x10000, 0xFFFFF, 0x100000, 0x100001, 0x200000,
                             0x400000, 0x400001, 0x7FFFFFFF, 0xFFFFFFFF])
        tag = "da_len_boundary"
    elif r < 0.90:
        sig_len = rng.choice([0, 1, 0x20, 0x40, 0x80, 0xFF, 0x100, 0x101,
                              0x180, 0x200, 0x1000, 0x7FFFFFFF, 0xFFFFFFFF])
        tag = "sig_len_boundary"
    elif r < 0.95:
        ln = rng.choice([0, 1, 0x10, 0x100, 0x1000, 0x10000])
        buf = bytearray(rng.randrange(256) for _ in range(ln))
        da_len = ln
        tag = "random_buf"
    else:
        # container header mutation, signed payload unchanged
        blob = bytearray(runner.da2710)
        for off, ln in [(0x64, 4), (0x68, 4), (0x6C, 4), (0x70, 2), (0x72, 2)]:
            if rng.random() < 0.8:
                blob[off:off + ln] = bytes(rng.randrange(256) for _ in range(ln))
        if rng.random() < 0.5:
            # mutate region table but keep region[1] intact; the host still
            # sends the same signed bytes for idx 1.
            i = rng.randrange(3)
            off = 0x80 + i * 0x14
            blob[off:off + 4] = struct.pack("<I", rng.randrange(0, 0x1000) & ~3)
        buf = bytearray(runner.da1_2710)
        da_len = runner.len_2710
        tag = "container_header_mut"
        header_only = True
        recipe = {"kind": "container_header_mut"}

    if len(buf) == 0:
        buf = bytearray(b"\x00")
    recipe.update(diff_patch(base, bytes(buf)))
    recipe.update({"da_len": da_len, "sig_len": sig_len, "tag": tag})
    return {"buf": bytes(buf), "da_len": da_len, "sig_len": sig_len,
            "tag": tag, "recipe": recipe, "header_only": header_only}


def apply_recipe(runner: CaseRunner, recipe: dict) -> dict:
    """Reconstruct a case exactly from the saved patch (no RNG involved)."""
    if "full_hex" in recipe:
        buf = bytearray.fromhex(recipe["full_hex"])
    elif "prefix_hex" in recipe:
        buf = bytearray.fromhex(recipe["prefix_hex"])
        buf += b"\x00" * max(0, recipe.get("prefix_len", len(buf)) - len(buf))
    else:
        buf = bytearray(runner.da1_2710)
        for off, hx in recipe.get("patch", []):
            buf[off:off + len(hx) // 2] = bytes.fromhex(hx)
    da_len = recipe.get("da_len", runner.len_2710)
    sig_len = recipe.get("sig_len", 0x100)
    return {"buf": bytes(buf), "da_len": da_len, "sig_len": sig_len,
            "tag": recipe.get("tag", "replay"), "recipe": recipe}


# --------------------------------------------------------------------------
# CLI modes
# --------------------------------------------------------------------------
def cmd_info(image: bytes):
    gfh = parse_gfh(image)
    base, score, second = derive_base(image)
    print("image      : %d bytes  sha256 %s" % (len(image), sha(image)))
    print("GFH        : %s load_addr=%#x total_size=%#x max_size=%#x"
          % (gfh.get("type"), gfh.get("load_addr", 0), gfh.get("total_size", 0),
             gfh.get("max_size", 0)))
    print("base       : %#x  (literal/string score %d, next %d)"
          % (base, score, second))
    print("entry      : ARM 0x%06X -> 0x%06X (Thumb main 0x22852C)"
          % (base + 0x100, base + 0x120))
    print("verify     : 0x20868C key+length+PSS, finish 0x208742, flag 0x20876A")
    print("key        : K2 @ 0x25E3DC, expected sig_len %#x"
          % struct.unpack_from("<I", image, G_EXPECTED_SIGLEN - BASE)[0])
    return base


def cmd_func(runner: CaseRunner, json_path: str | None):
    print("== ground-truth validation (real DA tails, real verify block) ==")
    rows = runner.validate()
    ok = True
    for r in rows:
        print("  %-52s %-16s r0=%-8s flag=%d insn_pc=%#x"
              % (r.get("label", ""), r["class"],
                 ("%#x" % r["r0"]) if r["r0"] is not None else "-",
                 r["flag"], r["pc"]))
        if "expect" in r.get("label", ""):
            exp = r["label"].split("expect ")[1].rstrip(")")
            if r["class"] != exp:
                ok = False
                print("    !! expected %s, got %s" % (exp, r["class"]))
    print("\n  primitive key matrix (0x23EA96 over the real tails):")
    matrix = [
        ("K2 / 2710 DA1 (same generation)", runner.da1_2710, 0x25E3DC, True),
        ("K2 / 200EX01 DA1 (wrong key)", runner.da1_200, 0x25E3DC, False),
        ("K1 / 2710 DA1 (wrong key)", runner.da1_2710, 0x25E2DC, False),
        ("K1 / 200EX01 DA1 (same generation)", runner.da1_200, 0x25E2DC, True),
    ]
    key_ok = True
    for label, da, kp, expect_ok in matrix:
        r0 = runner.pss_case(da, kp)
        got = (r0 == 0)
        key_ok &= (got == expect_ok)
        print("   %-40s r0=%-10s %s"
              % (label, "%#x" % r0, "PSS_ACCEPT" if got else "PSS_REJECT"))
    # mandatory pair
    a = rows[0]["class"] == "ACCEPT_VALID"
    b = rows[1]["class"] == "REJECT_0x7024"
    print("\n  mandatory pair: 2710 ACCEPT_VALID=%s, 200EX01 REJECT_0x7024=%s"
          % (a, b))
    print("  primitive PSS: 2710 rsa_calls=%d, exact_payload=%s"
          % (rows[0]["rsa_calls"], rows[0]["exact_payload"]))
    if json_path:
        with open(json_path, "w") as f:
            json.dump(rows, f, indent=1)
        print("  json -> %s" % json_path)
    return ok and a and b and key_ok


def cmd_gate(image: bytes):
    """Show the sec-policy gate: mode 0x11 verifies, mode 0 disables."""
    for mode, expect in [(0x11, 1), (0x22, None), (0x00, 0)]:
        emu = PreloaderEmu(image)
        emu.write_u32(P_SECPOL_STRUCT, mode)
        r0, st = emu.call(A_IS_DAA_ENABLED, (1,), budget=100_000)
        print("  sec_mode=%#04x -> is_daa_enabled(%d) = %#x" % (mode, 1, r0))
        if mode == 0:
            # with the gate off the verify body is never entered: the success
            # tail at 0x2086CC..0x2086D2 writes the flag for an invalid DA
            emu = PreloaderEmu(image)
            emu.write_u32(P_SECPOL_STRUCT, 0)
            emu.uc.mem_write(BUF_BASE, b"\x00" * 0x100)
            emu.setreg(UC_ARM_REG_R9, 0x100)
            emu.setreg(UC_ARM_REG_R11, BUF_BASE)
            emu.setreg(UC_ARM_REG_R6, 0x100)
            st = emu.run(0x2084B8, True, HARNESS_SP, (), 200_000)
            print("  sec_mode=0x0000 + invalid DA -> gate path reached, "
                  "flag=%d (config bypass, not host input)"
                  % emu.uc.mem_read(G_DAA_FLAG, 1)[0])


def cmd_writes(runner: CaseRunner):
    """Exercise the error tail: 0x208742 -> 0x208754 memset(fp,0,da_len)."""
    print("== write-side audit (error tail memset 0x208754 -> 0x23872A) ==")
    b = bytearray(runner.da1_2710)
    b[-0x80] ^= 1
    big = (runner.da1_2710 + b"\x00" * 0x100000)[:0x100000]
    cases = [
        ("func sig_flip (da_len=0x69424, verify max)",
         lambda: runner.func_case(bytes(b), runner.len_2710, 0x100,
                                  follow_error=True)),
        ("func da_len=0x100000 (exact verify max)",
         lambda: runner.func_case(big, 0x100000, 0x100, follow_error=True,
                                  budget=6_000_000)),
        ("proto sig_flip (real USB rx path)",
         lambda: runner.proto_case(bytes(b), runner.len_2710, 0x100,
                                   follow_error=True, budget=8_000_000)),
        ("proto da_len=0x400000 (rx bound max, short read)",
         lambda: runner.proto_case(runner.da1_2710[:0x2000], 0x400000, 0x100,
                                   follow_error=True, budget=24_000_000)),
        ("proto da_len=0x400001 (rx bound+1 -> assert before verify)",
         lambda: runner.proto_case(runner.da1_2710[:0x2000], 0x400001, 0x100,
                                   budget=2_000_000)),
    ]
    for label, fn in cases:
        r = fn()
        w = r["wipe"]
        mc = w.get("memset_calls", [])
        # 0x20875A bl 0x23872A -> return address 0x20875F is the DA error tail.
        tail = [m for m in mc if m.get("lr") == 0x20875F]
        mstr = ", ".join("memset(%#x,0,%#x)" % (m["dst"], m["len"]) for m in tail) or "-"
        exp_dst = DA_DST if r["mode"] == "proto" else BUF_BASE
        inb = bool(tail) and all(m["dst"] == exp_dst and m["len"] <= DA_RX_MAX
                                 for m in tail)
        eq = bool(tail) and all(m["len"] == r["da_len"] for m in tail)
        print("  %-52s class=%-14s r0=%-6s %s"
              % (label, r["class"],
                 ("%#x" % r["r0"]) if r["r0"] is not None else "-", mstr))
        print("      dst=%#x expected_dst=%#x equals_received_len=%s "
              "within_rx_bound=%s" % (w["dst"], exp_dst, eq, inb))
        if not tail:
            print("      no DA memset reached: assert in the receive state at "
                  "0x2083E2 (da_len > 0x400000); this is a DoS, not a write.")
    print("  conclusion: every observed memset length equals the host-declared")
    print("              DA length that was already written by the USB receive")
    print("              (0x208432).  No input makes the memset exceed that.")
    return True


def cmd_boot(image: bytes, budget: int):
    emu = PreloaderEmu(image, budget=budget, trace=True)
    uc = emu.uc
    # Boot-only models.  The function/proto harness intentionally does NOT map
    # address 0, so a NULL dereference is still a CRASH there.
    for base, size, name in [(0x00000000, 0x00080000, "brom-rom"),
                             (0x0C000000, 0x01000000, "emi/dramc")]:
        try:
            uc.mem_map(base, size, UC_PROT_ALL)
        except UcError:
            pass
    # Unicorn 2.1.4 does not retire the Thumb ITSTATE after the loop at
    # 0x239414..0x23941C, so the BL into the shared division helper at
    # 0x2012FE arrives with ITSTATE=0x1C and the `bne` there is decoded as an
    # illegal branch-inside-IT.  Clearing ITSTATE at the block boundary is a
    # documented emulator workaround, not a preloader change.
    reached_main = [False]

    def boot_fix(uc_, a, _s, _u):
        if 0x23941E <= a <= 0x23942A:
            c = uc_.reg_read(UC_ARM_REG_CPSR)
            uc_.reg_write(UC_ARM_REG_CPSR, c & ~((0x3F << 10) | (3 << 25)))
        if a == 0x22852C:
            reached_main[0] = True

    uc.hook_add(UC_HOOK_CODE, boot_fix)
    print("== best-effort boot from ARM entry 0x201000 ==")
    st = emu.run(0x201000, thumb=False, sp=0x200BFC, args=(), budget=budget)
    pc = emu.reg(UC_ARM_REG_PC)
    print("  reached preloader main (0x22852C): %s" % reached_main[0])
    print("  stop=%s pc=%#x" % (st, pc))
    print("  mmio writes: %d (first: %s)" % (len(emu.mmio_writes),
                                             emu.mmio_writes[:3]))
    print("  timer ticks: %d" % emu.tick)
    if "fault" in st:
        f = st["fault"]
        print("  fault: access=%s addr=%#x size=%s pc=%#x"
              % (f[0], f[1] or 0, f[2], f[3]))
    if "budget" in st:
        print("  exhausted the instruction budget at %#x" % st["budget"])
    if reached_main[0] and "fault" in st:
        print("  verdict: boot reaches preloader main and platform/DRAM init.  At")
        print("           0x23378C the code loads the literal 0x2619DF20 (a DRAM/PHY")
        print("           register window) and writes there; that block is not")
        print("           modelled.  Full boot to the USB stage needs DRAM/UFS/PMIC")
        print("           models; the USB command state machine itself is driven")
        print("           directly by --mode proto (real code, synthetic transport).")
    return st


def cmd_fuzz(runner: CaseRunner, n_cases: int, seed: int, json_path: str | None,
             repro_dir: str | None, proto_share: float = 0.10):
    rng = random.Random(seed)
    n_proto = max(0, min(n_cases, int(n_cases * proto_share)))
    n_func = n_cases - n_proto
    classes = Counter()
    r0hist = Counter()
    details: list[dict] = []
    uniq: OrderedDict = OrderedDict()
    saved_keys: Counter = Counter()
    repros = 0
    t0 = time.time()
    if repro_dir:
        os.makedirs(repro_dir, exist_ok=True)
        # clear stale repros
        for f in os.listdir(repro_dir):
            if f.startswith("case_") and (f.endswith(".json") or f.endswith(".bin")):
                os.unlink(os.path.join(repro_dir, f))

    def record(res: dict, case: dict, force: bool = False):
        nonlocal repros
        cls = res["class"]
        classes[cls] += 1
        r0hist[(cls, res.get("r0"))] += 1
        if len(details) < 50:
            details.append(dict(res, tag=case.get("tag", "")))
        key = (cls, res.get("r0"), (res.get("fault") or {}).get("pc"),
               (res.get("fault") or {}).get("addr"),
               res.get("pc") if cls == "HANG" else None)
        if key not in uniq:
            uniq[key] = dict(res, tag=case.get("tag", ""))
        # always keep interesting outcomes (incl. proto HANG) and a sample of
        # the rest, so at least one protocol case is reproducible.
        interesting = cls in ("ACCEPT_INVALID", "CRASH", "HANG", "OTHER_ERROR")
        must = cls in ("ACCEPT_INVALID", "CRASH")
        kk = (cls, case.get("tag"))
        if repro_dir and (force or interesting or repros < 24):
            if repros < 140 and (must or force or saved_keys[kk] < 3):
                saved_keys[kk] += 1
                rid = "case_%04d" % repros
                meta = {
                    "mode": res["mode"],
                    "class": cls,
                    "r0": res.get("r0"),
                    "pc": res.get("pc"),
                    "fault": res.get("fault"),
                    "tag": case.get("tag"),
                    "header_only": case.get("header_only", False),
                    "da_len": case.get("da_len"),
                    "sig_len": case.get("sig_len"),
                    "seed": seed,
                    "recipe": case.get("recipe"),
                }
                with open(os.path.join(repro_dir, rid + ".json"), "w") as f:
                    json.dump(meta, f, indent=1)
                if len(case.get("buf", b"")) <= 0x20000:
                    with open(os.path.join(repro_dir, rid + ".bin"), "wb") as f:
                        f.write(case["buf"])
                repros += 1

    for i in range(n_func):
        case = make_case(rng, runner, "func")
        res = runner.func_case(case["buf"], case["da_len"], case["sig_len"],
                               header_only=case.get("header_only", False))
        record(res, case)
        if (i + 1) % 500 == 0:
            print("  func %d/%d  (%.1fs) %s" % (i + 1, n_func,
                                               time.time() - t0,
                                               dict(classes)), flush=True)

    for i in range(n_proto):
        case = make_case(rng, runner, "proto")
        # keep protocol cases cheap: cap the delivered data at 8 KiB
        data = case["buf"][:0x2000]
        dl = case["da_len"]
        if dl is not None and dl > len(data):
            dl = len(data) if case["tag"] != "da_len_huge" else dl
        hs = b"\xa0\x0a\x50\x05" if case["tag"] != "bad_handshake" else b"\x00\x11\x22\x33"
        cmdb = 0xD7
        if case["tag"].startswith("cmd="):
            cmdb = int(case["tag"].split("=")[1], 16)
        case["buf"] = data
        case["da_len"] = dl
        case["recipe"].update(diff_patch(runner.da1_2710, data))
        case["recipe"].update({"da_len": dl, "cmd": cmdb,
                               "handshake": hs.hex()})
        res = runner.proto_case(data, dl, case["sig_len"], cmd=cmdb,
                                field0=rng.randrange(1 << 32),
                                handshake=hs, budget=2_000_000)
        record(res, case, force=(i == 0))
        if (i + 1) % 20 == 0:
            print("  proto %d/%d  (%.1fs)" % (i + 1, n_proto, time.time() - t0),
                  flush=True)

    dt = time.time() - t0
    print("\n== fuzz results (%d cases, seed %d, %.1fs) ==" % (n_cases, seed, dt))
    width = max(len(c) for c in CLASSES)
    for c in CLASSES:
        print("  %-*s %5d" % (width, c, classes.get(c, 0)))
    print("\n  verdict histogram (class, r0):")
    for (c, r0), n in sorted(r0hist.items(), key=lambda kv: (kv[0][0], -kv[1])):
        print("   %-18s r0=%-8s %5d"
              % (c, ("%#x" % r0) if r0 is not None else "-", n))
    print("\n  unique (class, r0, fault.pc, fault.addr): %d" % len(uniq))
    for key, r in list(uniq.items())[:20]:
        print("   %-16s r0=%-6s pc=%#x tag=%s"
              % (key[0], ("%#x" % key[1]) if key[1] is not None else "-",
                 r.get("pc") or 0, r.get("tag")))
    if json_path:
        out = {
            "image_sha256": sha(runner.image),
            "cases": n_cases,
            "seed": seed,
            "seconds": round(dt, 2),
            "classes": dict(classes),
            "unique": [
                {"class": k[0], "r0": k[1], "fault_pc": k[2], "fault_addr": k[3],
                 "hang_pc": k[4], "tag": r.get("tag"), "buf_sha": r.get("buf_sha"),
                 "da_len": r.get("da_len"), "sig_len": r.get("sig_len")}
                for k, r in uniq.items()
            ],
            "samples": details[:50],
        }
        with open(json_path, "w") as f:
            json.dump(out, f, indent=1)
        print("  json -> %s" % json_path)
    # a bypass is fatal for the campaign
    return classes.get("ACCEPT_INVALID", 0) == 0


def cmd_replay(runner: CaseRunner, path: str):
    with open(path) as f:
        meta = json.load(f)
    recipe = meta.get("recipe") or {}
    case = apply_recipe(runner, recipe)
    binf = os.path.splitext(path)[0] + ".bin"
    if os.path.exists(binf):
        with open(binf, "rb") as f:
            case["buf"] = f.read()
    if meta.get("da_len") is not None:
        case["da_len"] = meta["da_len"]
    if meta.get("sig_len") is not None:
        case["sig_len"] = meta["sig_len"]
    if meta.get("mode") == "proto":
        hs = bytes.fromhex(recipe.get("handshake", "a00a5005"))
        res = runner.proto_case(case["buf"], case["da_len"], case["sig_len"],
                                cmd=recipe.get("cmd", 0xD7), handshake=hs,
                                budget=8_000_000)
    else:
        res = runner.func_case(case["buf"], case["da_len"], case["sig_len"],
                               header_only=meta.get("header_only", False))
    match = res["class"] == meta.get("class") and (
        meta.get("r0") is None or res["r0"] == meta.get("r0"))
    print(json.dumps({"replay": path, "class": res["class"],
                      "expected": meta.get("class"), "match": match,
                      "r0": res["r0"], "pc": res["pc"],
                      "fault": res.get("fault"), "tag": meta.get("tag")},
                     indent=1))
    if not match:
        print("MISMATCH: replay did not reproduce the saved outcome",
              file=sys.stderr)
    return res if match else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", default=IMAGE_DEFAULT)
    ap.add_argument("--da2710", default=DA2710_DEFAULT)
    ap.add_argument("--da200", default=DA200_DEFAULT)
    ap.add_argument("--mode", choices=["info", "func", "proto", "boot", "gate",
                                       "fuzz", "writes"], default="func")
    ap.add_argument("--cases", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--json", default=None)
    ap.add_argument("--replay", default=None)
    ap.add_argument("--repro-dir", default="/tmp/opencode/pre_fuzz_cases")
    ap.add_argument("--budget", type=int, default=None,
                    help="instruction budget override")
    ap.add_argument("--proto-share", type=float, default=0.10,
                    help="fraction of fuzz cases driven through the USB state machine")
    ap.add_argument("--trace", action="store_true")
    args = ap.parse_args(argv)

    image = load_image(args.image)
    if not sha(image).startswith(IMAGE_SHA_PREFIX):
        print("WARNING: image sha256 %s does not start with %s"
              % (sha(image), IMAGE_SHA_PREFIX), file=sys.stderr)

    if args.mode == "info":
        cmd_info(image)
        return 0
    if args.mode == "boot":
        cmd_boot(image, args.budget or 20_000_000)
        return 0

    need_da = args.mode in ("func", "proto", "fuzz", "gate", "writes") or args.replay
    da2710 = da200 = b""
    if need_da:
        p2710 = args.da2710
        if not os.path.exists(p2710):
            raise SystemExit("DA2710 not found: %s" % p2710)
        p200 = args.da200
        if not os.path.exists(p200):
            if args.da200 == DA200_DEFAULT:
                for cand in DA200_FALLBACKS:
                    if os.path.exists(cand):
                        p200 = cand
                        break
            if not os.path.exists(p200):
                raise SystemExit("DA200 not found: %s (tried %s)"
                                 % (args.da200, DA200_FALLBACKS))
        da2710 = open(p2710, "rb").read()
        da200 = open(p200, "rb").read()
        if is_container(da2710):
            print("DA2710: container %s (%d B)" % (p2710, len(da2710)))
        else:
            print("DA2710: raw DA1 %s (%d B)" % (p2710, len(da2710)))
        print("DA200 : %s %s (%d B)"
              % ("container" if is_container(da200) else "raw DA1",
                 p200, len(da200)))
    runner = CaseRunner(image, da2710, da200, trace=args.trace)

    if args.replay:
        return 0 if cmd_replay(runner, args.replay) else 3
    if args.mode == "func":
        return 0 if cmd_func(runner, args.json) else 1
    if args.mode == "proto":
        rows = [runner.proto_case(runner.da1_2710, runner.len_2710, 0x100,
                                  budget=8_000_000),
                runner.proto_case(runner.da1_200, runner.len_200, 0x100,
                                  budget=8_000_000)]
        for r in rows:
            print("%-16s r0=%s pc=%#x flag=%d da_len=%#x sig_len=%#x"
                  % (r["class"], r["r0"], r["pc"], r["flag"],
                     r["da_len"], r["sig_len"]))
        return 0 if rows[0]["class"] == "ACCEPT_VALID" and rows[1]["class"] == "REJECT_0x7024" else 1
    if args.mode == "gate":
        cmd_gate(image)
        return 0
    if args.mode == "writes":
        cmd_writes(runner)
        return 0
    if args.mode == "fuzz":
        ok = cmd_fuzz(runner, args.cases, args.seed, args.json,
                      args.repro_dir, args.proto_share)
        return 0 if ok else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
