#!/usr/bin/env python3
"""DA1 (RMX3630 / MT6789) user-mode emulator harness.

Purpose: run the real DA1 code (allocator, XML parser, command handlers,
`fp_read_host_file`) in Unicorn so the HeapBait port can be developed and
debugged without touching the phone.

Memory map used here (all inside DA1's own 0x20xxxx/0x2Dxxxx windows):

    0x200000..0x280000   DA1 image (file offset 0 == VA 0x200000)
    0x2B0000..0x2C0000   harness scratch: session struct + trampolines
    0x2C0000..0x300000   DA1 .data/.bss + heap (heap: 0x2E8000..0x2F8000)
                          stack lives at 0x2CF000 (grows down)

Resolved DA1 parameters (see docs/notes/reverse/re-da1-heapbait-port.md):

    heap_init        0x2044C8   (heap_base 0x2E8000, size 0x10000)
    heap_head        0x2DF7D0
    malloc core      0x2041E8
    free wrapper     0x204380   (core write at 0x2043CC)
    insert           0x2043D8
    dpc struct       0x2DF7A0   (dpc_addr = struct-4 = 0x2DF79C)
    cmd_loop         0x203C08
    reg_cmd          0x203BBC
    get_node         0x201004
    load_str         0x206DD4
    download         0x2500D8
    DRAM-REPAIR      0x202C7C
"""
from __future__ import annotations

import struct
import sys

from unicorn import (
    Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_INTR, UC_HOOK_CODE,
    UC_PROT_ALL,
)
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
)

BASE = 0x200000
IMG_SIZE = 0x80000
DATA_LO, DATA_HI = 0x2C0000, 0x300000
SCRATCH_LO, SCRATCH_HI = 0x2B0000, 0x2C0000
STACK_TOP = 0x2CF000
SESSION = 0x2B0100
TRAMP_RECV = 0x2B1000
TRAMP_SEND = 0x2B1010
TRAMP_TRAP = 0x2B1F00

HEAP_INIT = 0x2044C8
HEAP_HEAD = 0x2DF7D0
MALLOC = 0x2041E8
FREE = 0x204380
INSERT = 0x2043D8
DPC_STRUCT = 0x2DF7A0
CMD_LOOP = 0x203C08
REG_CMD = 0x203BBC
GET_NODE = 0x201004
LOAD_STR = 0x206DD4
DOWNLOAD = 0x2500D8
DRAM_REPAIR = 0x202C7C

BKPT = b"\x70\x00\x20\xe1"          # bkpt #0
BX_LR = b"\x1e\xff\x2f\xe1"         # bx lr


class DA1Emu:
    def __init__(self, image: str, verbose: bool = True):
        self.verbose = verbose
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.mem_map(BASE, IMG_SIZE)
        with open(image, "rb") as f:
            self.uc.mem_write(BASE, f.read())
        self.uc.mem_map(SCRATCH_LO, SCRATCH_HI - SCRATCH_LO)
        self.uc.mem_map(DATA_LO, DATA_HI - DATA_LO)
        self.uc.mem_write(TRAMP_RECV, BKPT)
        self.uc.mem_write(TRAMP_SEND, BKPT)
        self.uc.mem_write(TRAMP_TRAP, BKPT)
        # session struct: [0]=recv, [4]=send
        self.uc.mem_write(SESSION, struct.pack("<II", TRAMP_RECV, TRAMP_SEND))
        self.uc.reg_write(UC_ARM_REG_SP, STACK_TOP)

        self.rx: list[bytes] = []       # packets the host would send
        self.tx: list[bytes] = []       # what the DA sent
        self.mmio_reads: dict[int, int] = {}
        self.alloc_log: list[str] = []
        self._ret = False
        self.on_send = None

        self.uc.hook_add(UC_HOOK_INTR, self._on_intr)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, self._on_mem_read)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._on_mem_write)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code, begin=MALLOC, end=MALLOC)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code, begin=FREE, end=FREE)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code, begin=INSERT, end=INSERT)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code, begin=HEAP_INIT, end=HEAP_INIT)

    # ---------------- infrastructure ----------------
    def log(self, *a):
        if self.verbose:
            print(*a)

    def call(self, addr: int, args: list[int] = (), count: int = 2_000_000) -> int:
        """Call a DA1 function with up to 4 args, return r0."""
        for i, v in enumerate(args[:4]):
            self.uc.reg_write([UC_ARM_REG_R0, UC_ARM_REG_R1,
                              UC_ARM_REG_R2, UC_ARM_REG_R3][i], v)
        self.uc.reg_write(UC_ARM_REG_LR, TRAMP_TRAP)
        self.uc.reg_write(UC_ARM_REG_SP, STACK_TOP)
        self._ret = False
        pc = addr
        for _ in range(10000):
            try:
                self.uc.emu_start(pc, 0, count=count)
            except Exception as e:
                self.log(f"[emu] stop: {e}")
                return -1
            if self._ret:
                return self.uc.reg_read(UC_ARM_REG_R0)
            pc = self.uc.reg_read(UC_ARM_REG_PC)
        return -1

    def _on_intr(self, uc, intno, ud):
        pc = uc.reg_read(UC_ARM_REG_PC)
        lr = uc.reg_read(UC_ARM_REG_LR)
        if pc == TRAMP_TRAP:
            self._ret = True
            uc.emu_stop()
            return
        if pc == TRAMP_RECV:
            buf = uc.reg_read(UC_ARM_REG_R0)
            lp = uc.reg_read(UC_ARM_REG_R1)
            want = struct.unpack("<I", uc.mem_read(lp, 4))[0]
            data = b""
            timeout = not self.rx
            if self.rx:
                data = self.rx.pop(0)[:want]
            else:
                data = b""
                self.log(f"[emu] recv({want:#x}) -> timeout")
            if data:
                uc.mem_write(buf, data)
            uc.mem_write(lp, struct.pack("<I", len(data)))
            # a real USB read with nothing pending fails; returning success
            # with len 0 would spin the DA's recv loop forever
            uc.reg_write(UC_ARM_REG_R0, 0xFFFFFFFF if timeout else 0)
            self.log(f"[emu] DA recv {want:#x} -> {len(data):#x} {data[:32]!r}")
        elif pc == TRAMP_SEND:
            buf = uc.reg_read(UC_ARM_REG_R0)
            ln = uc.reg_read(UC_ARM_REG_R1)
            if 0 < ln < 0x2000:
                data = bytes(uc.mem_read(buf, ln))
                self.tx.append(data)
                self.log(f"[emu] DA send {ln:#x}: {data[:160]!r}")
                if self.on_send:
                    self.on_send(data)
            uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, lr)

    def _on_mem_read(self, uc, access, address, size, value, ud):
        # MMIO: return 0 (UART/WDT/timers). Track for the port notes.
        self.mmio_reads[address & ~3] = self.mmio_reads.get(address & ~3, 0) + 1
        return True

    def _on_mem_write(self, uc, access, address, size, value, ud):
        return True

    def _on_code(self, uc, address, size, ud):
        if address == HEAP_INIT:
            self.log(f"[emu] heap_init call (sp={uc.reg_read(UC_ARM_REG_SP):#x})")
        elif address == MALLOC:
            self.log(f"[emu] malloc(r0={uc.reg_read(UC_ARM_REG_R0):#x}, "
                     f"r1={uc.reg_read(UC_ARM_REG_R1):#x}) lr={uc.reg_read(UC_ARM_REG_LR):#x}")
        elif address == FREE:
            self.log(f"[emu] free(r0={uc.reg_read(UC_ARM_REG_R0):#x}) "
                     f"lr={uc.reg_read(UC_ARM_REG_LR):#x}")
        elif address == INSERT:
            self.log(f"[emu] insert(node={uc.reg_read(UC_ARM_REG_R0):#x})")

    # ---------------- helpers ----------------
    def read_u32(self, addr: int) -> int:
        return struct.unpack("<I", self.uc.mem_read(addr, 4))[0]

    def write_bytes(self, addr: int, data: bytes):
        self.uc.mem_write(addr, data)

    def heap_state(self):
        head = HEAP_HEAD
        base = self.read_u32(head)
        size = self.read_u32(head + 4)
        first = self.read_u32(head + 8)
        last = self.read_u32(head + 0xc)
        return dict(base=base, size=size, first=first, last=last)

    def free_list(self, limit=32):
        out = []
        node = self.read_u32(HEAP_HEAD + 8)
        sentinel = HEAP_HEAD + 8
        n = 0
        while node not in (0, sentinel) and n < limit:
            size = self.read_u32(node + 8)
            out.append((node, size))
            node = self.read_u32(node + 4)
            n += 1
        return out


def demo(image: str):
    emu = DA1Emu(image)
    emu.log("=== heap_init ===")
    rc = emu.call(HEAP_INIT)
    emu.log("rc", rc, emu.heap_state(), "free:", emu.free_list())

    emu.log("\n=== malloc/free x3 ===")
    # malloc is (r0=size, r1=align?) per the disassembly at 0x2041E8
    for req in (0x100, 0x200, 0x40):
        p = emu.call(MALLOC, [req, 0])
        emu.log(f"malloc({req:#x}) -> {p:#x}" if p >= 0 else f"malloc({req:#x}) failed")
    emu.log("free list:", emu.free_list())

    emu.log("\n=== DRAM-REPAIR handler (no transport data yet) ===")
    xml = (b'<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>'
           b'<command>CMD:DEBUG:DRAM-REPAIR</command><arg>'
           b'<target_file>target</target_file>'
           b'<param_file>param</param_file></arg></da>\x00')
    xml_addr = 0x2BF000
    emu.write_bytes(xml_addr, xml)
    rc = emu.call(DRAM_REPAIR, [SESSION, xml_addr])
    emu.log("handler rc:", rc)
    emu.log("DA tx count:", len(emu.tx))
    for t in emu.tx:
        emu.log("   ", t[:200])
    emu.log("free list after:", emu.free_list())


if __name__ == "__main__":
    img = sys.argv[1] if len(sys.argv) > 1 else \
        "/home/musin/mtkclient/docs/notes/rmx3630-da2/da1_allinone.bin"
    demo(img)
