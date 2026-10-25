#!/usr/bin/env python3
"""Offline fuzzing campaign against DA1 200EX01 (RMX3630 / MT6789).

Threat model: the **host is untrusted**.  DA1 parses every byte the host sends:
the command XML in ``cmd_loop``, the ``OK``/``OK@<len>`` handshake in
``fp_read_host_file``, and the per-chunk data frames.  This script drives those
real DA1 code paths inside the Unicorn harness and classifies every stop.

It does not re-implement the harness: ``boot()``, ``install_budget()``,
``walk_free_list()``, ``ChainHost``/``BootHost``, the packet length, the
registrar and all DA1 constants come from ``da1_fixed_stage.py`` (which imports
the boot plumbing from ``da1_fire_chain.py``).

Phases (``--phase all|xml|proto|handlers|random``)
--------------------------------------------------
``xml``      mutated command XML driven through the REAL command loop
             (``cmd_loop`` 0x203C08, registrar 0x200ED0 already run by boot):
             truncation, NUL/binary bytes, missing/duplicated/reordered tags,
             huge/negative integers, deep nesting, long names/values, entities,
             unclosed CDATA/comments, invalid/empty command names, oversized
             total length.
``proto``    malformed host replies in the download protocol
             (``fp_read_host_file`` 0x2500D8) reached through DRAM-REPAIR
             (0x202C7C, malloc destination) and BOOT-TO (0x201080, fixed
             0x40000000 destination): ACK variants, declared lengths
             0/1/0xFF/0xFFFFFFFF/0xFFFFFFFC/0x7FFFFFFF, declared-vs-delivered
             mismatch in both directions, zero-length/extra chunks, early EOF,
             non-hex length tokens, repeated OK frames.
``handlers`` direct calls of all 12 registered handlers with mutated XML.
``random``   uniform random byte strings (NULs included) through ``cmd_loop``
             and as the download frames -- the non-XML control.

Every case gets a **fresh** ``DA1Emu`` + ``boot()`` (determinism/isolation),
packet_len 0x2000 and the existing loop budget.  A loop-budget trip or an
instruction-cap stop is reported as ``HANG`` -- a result, not a campaign crash.

Outcome classes
---------------
``OK_RC``        handler returned 0 / ``<result>OK</result>``
``ERR_RC``       handler returned non-zero (or command unsupported)
``DATA_ABORT``   emulator stop at a non-MMIO address (PC + fault address kept)
``HANG``         loop budget / instruction cap hit
``HEAP_CORRUPT`` free-list walk broke (forged node / zero link / duplicate /
                 out-of-heap node / impossible size)
``CB_SET``       ``dpc->cb`` became non-zero from the input; the ``blx r4`` is
                 intercepted (target recorded, not executed)
``UNMAPPED_IO``  fault at an on-chip peripheral address (UART/timer/crypto,
                 0x10000000..0x20000000) -- expected, NOT a crash
``HARNESS_ERROR`` a bug in this fuzzer (should stay 0)

Input-derived flag
------------------
For every non-OK/ERR case the classifier searches the input for the PC, the
fault address and every register value (4-byte windows at every offset, plus
the Thumb bit and small store offsets), and whether the little-endian address
bytes appear verbatim in the input.  That is the exploitability signal.

Usage
-----
    python docs/notes/da1_fuzz.py --image docs/notes/rmx3630-da2/da1_allinone.bin \\
        --phase all --cases 2000 --json /tmp/opencode/fuzz.json
    python docs/notes/da1_fuzz.py --seed 0x1234 --cases 500 --json /tmp/opencode/fuzz2.json
    python docs/notes/da1_fuzz.py --replay /tmp/opencode/da1_fuzz_cases/x.json

The run is deterministic for a given (--seed, --phase, --cases).  ``--save-dir``
receives one minimal JSON repro per deduplicated group; ``--replay`` re-runs
one of those files byte-for-byte.  Exit 0 means the campaign completed and the
three validation controls passed; exit 1 means the classifier is broken.
"""
from __future__ import annotations

import argparse
import gc
import json
import os
import random
import re
import struct
import sys
import time
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import unicorn                                              # noqa: E402
import unicorn.arm_const as ac                              # noqa: E402
from unicorn import UC_HOOK_CODE                            # noqa: E402
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM           # noqa: E402

# --- the existing harness / boot plumbing (do not duplicate it) -------------
from da1_fixed_stage import (                               # noqa: E402
    boot, walk_free_list, ChainHost, BootHost,
    CMD_LOOP, DPC_STRUCT, SESSION, XML_ADDR, CMD_XML, BENIGN_XML,
    BOOT_TO, BOOT_XML, FAKE_MAGIC, DPC_ADDR, DA2_AT, CHUNK_HDR,
    _align4, make_payload, FixedChainHost, install_sha_engine,
    BLX_SITE, SAFE_CONT, DA2_BODY,
)
from da1_fire_chain import install_budget                  # noqa: E402
from da1_emu import DRAM_REPAIR, TRAMP_TRAP, STACK_TOP      # noqa: E402

PACKET_LEN = 0x2000
XML_MAX = 0x800
HANDLER_ENTRY_SITE = 0x203FB4       # cmd_loop: blx r2 (handler call)
HANDLER_RET_SITE = 0x203FB8         # cmd_loop: mov sb, r0 (handler return)
MMIO_LO, MMIO_HI = 0x10000000, 0x20000000

# audit note §2.2: all 12 registrations, in registration order
HANDLERS = [
    ("NOTIFY-INIT-HW", 0x2016E8),
    ("SET-HOST-INFO", 0x20173C),
    ("BOOT-TO", 0x201080),
    ("REBOOT", 0x2023B4),
    ("GET-HW-INFO", 0x202868),
    ("SET-RUNTIME-PARAMETER", 0x201404),
    ("HOST-SUPPORTED-COMMANDS", 0x202DD0),
    ("RAM-TEST", 0x202590),
    ("DRAM-REPAIR", 0x202C7C),
    ("WRITE-FLASH", 0x2017EC),
    ("ERASE-FLASH", 0x201E98),
    ("READ-FLASH", 0x201C5C),
]
HANDLER_BY_ADDR = {a: n for n, a in HANDLERS}

# plausible argument trees (names taken from the handlers / audit note)
ARG_TREE = {
    "NOTIFY-INIT-HW": "<info>init</info>",
    "SET-HOST-INFO": "<target_file>t</target_file><param_file>p</param_file>",
    "BOOT-TO": ("<at_address>0x40000000</at_address>"
                "<jmp_address>0x40000000</jmp_address>"
                "<source_file>da2</source_file>"),
    "REBOOT": "<delay>0</delay>",
    "GET-HW-INFO": "<target_file>t</target_file>",
    "SET-RUNTIME-PARAMETER": ("<param_name>log_level</param_name>"
                              "<param_value>1</param_value>"),
    "HOST-SUPPORTED-COMMANDS": "",
    "RAM-TEST": "<function>FLIP</function><start_address>0x40000000</start_address>"
                "<length>0x100</length>",
    "DRAM-REPAIR": ("<target_file>target</target_file>"
                    "<param_file>param</param_file>"
                    "<source_file>param</source_file>"),
    "WRITE-FLASH": ("<partition_name>boot</partition_name>"
                    "<file_name>f</file_name><length>0x100</length>"),
    "ERASE-FLASH": "<partition_name>boot</partition_name>",
    "READ-FLASH": ("<partition_name>boot</partition_name>"
                   "<file_name>f</file_name><length>0x100</length>"),
}

PHASE_ORDER = ("xml", "proto", "handlers", "random")
PHASE_ID = {p: i for i, p in enumerate(PHASE_ORDER)}

_CS = Cs(CS_ARCH_ARM, CS_MODE_ARM)
_REG = {
    "r0": ac.UC_ARM_REG_R0, "r1": ac.UC_ARM_REG_R1, "r2": ac.UC_ARM_REG_R2,
    "r3": ac.UC_ARM_REG_R3, "r4": ac.UC_ARM_REG_R4, "r5": ac.UC_ARM_REG_R5,
    "r6": ac.UC_ARM_REG_R6, "r7": ac.UC_ARM_REG_R7, "r8": ac.UC_ARM_REG_R8,
    "r9": ac.UC_ARM_REG_R9, "r10": ac.UC_ARM_REG_R10, "r11": ac.UC_ARM_REG_R11,
    "r12": ac.UC_ARM_REG_R12, "sp": ac.UC_ARM_REG_SP, "lr": ac.UC_ARM_REG_LR,
    "pc": ac.UC_ARM_REG_PC,
}
# capstone prints the ARM APCS aliases for r9-r12
_REG_ALIAS = dict(_REG)
_REG_ALIAS.update({"sb": ac.UC_ARM_REG_R9, "sl": ac.UC_ARM_REG_R10,
                   "fp": ac.UC_ARM_REG_R11, "ip": ac.UC_ARM_REG_R12})
_ERRNAME = {}
for _n in dir(unicorn):
    if _n.startswith("UC_ERR_"):
        _ERRNAME.setdefault(getattr(unicorn, _n), _n[7:])


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _u32(uc, addr):
    try:
        return struct.unpack("<I", uc.mem_read(addr, 4))[0]
    except Exception:
        return None


def _pc(emu):
    try:
        return emu.uc.reg_read(ac.UC_ARM_REG_PC)
    except Exception:
        return None


def _regs(emu):
    out = {}
    for n, rid in _REG.items():
        try:
            out[n] = emu.uc.reg_read(rid) & 0xFFFFFFFF
        except Exception:
            pass
    return out


def _fault_from_instruction(uc, pc):
    """Decode the faulting load/store at PC and evaluate its address operand.

    Unicorn 2.1.4 raises UC_ERR_MAP for unmapped accesses but does not report
    the address, so we recover it from the instruction and the live registers.
    Returns (address, disassembly-text) or (None, text).
    """
    try:
        blob = bytes(uc.mem_read(pc, 4))
    except Exception:
        # PC itself is unmapped -> fetch fault; the address *is* PC
        return pc, "<fetch at pc>"
    for ins in _CS.disasm(blob, pc):
        op = ins.op_str
        m = re.search(r"\[([a-z0-9]+)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]", op)
        if m:
            base_s = m.group(1)
            if base_s == "pc":
                base = pc + 8
            else:
                rid = _REG_ALIAS.get(base_s)
                base = uc.reg_read(rid) & 0xFFFFFFFF if rid is not None else None
            if base is None:
                return None, f"{ins.mnemonic} {op}"
            off = int(m.group(2), 0) if m.group(2) else 0
            return (base + off) & 0xFFFFFFFF, f"{ins.mnemonic} {op}"
        m = re.match(r"(r\d+)", op)
        if m and ins.mnemonic.split(".")[0] in ("ldm", "ldmia", "ldmib",
                                                "stm", "stmia", "stmib"):
            rid = _REG_ALIAS.get(m.group(1))
            if rid is not None:
                return uc.reg_read(rid) & 0xFFFFFFFF, f"{ins.mnemonic} {op}"
        return None, f"{ins.mnemonic} {op}"
    return None, "<undecodable>"


def _fl_check(emu):
    """Free-list invariant: walk + forged/zero/dup/out-of-heap/size checks."""
    walk = walk_free_list(emu.uc)
    try:
        heap = emu.heap_state()
        base, size = heap["base"], heap["size"]
    except Exception:
        base, size = 0, 0
    bad = []
    seen = set()
    for n in walk["nodes"]:
        a, s = n["addr"], n["size"]
        if a in seen:
            bad.append("duplicate")
        seen.add(a)
        if not (base <= a < base + size):
            bad.append("outside-heap")
        if s is None or s < 0xC or s > max(size, 0x10000):
            bad.append("bad-size")
        if a % 4:
            bad.append("unaligned")
    ok = bool(walk["sentinel_reached"] and not walk["forged_present"]
              and not walk["zero_link"] and not bad
              and walk["count"] <= 64)
    return {
        "count": walk["count"], "sentinel_reached": walk["sentinel_reached"],
        "forged_present": walk["forged_present"], "zero_link": walk["zero_link"],
        "bad": sorted(set(bad)), "ok": ok,
        "nodes": [{"addr": n["addr"], "size": n["size"]}
                  for n in walk["nodes"][:16]],
        "heap_base": base, "heap_size": size,
    }


def _looks_mmio(addr):
    return addr is not None and MMIO_LO <= addr < MMIO_HI


def _is_known_heapbait(data, verdict, fault, pc, cb_at_blx):
    """True only when the crash follows the already-known HeapBait mechanism:
    a fake {0xDEADBEEF, dpc_addr, ...} allocator header that becomes a free-list
    node (cb fire, DEADBEF3 unlink, or the insert/unlink walk).  A fake header
    that merely sits in random payload next to an unrelated parser NULL deref
    must NOT be labelled known."""
    fake = struct.pack("<II", FAKE_MAGIC, DPC_ADDR) in data
    if fault is not None and abs(fault - 0xDEADBEF3) <= 0x20:
        return True
    if cb_at_blx == 0xC0DE0001:
        return True
    if fake and verdict == "CB_SET":
        return True
    if fake and pc in (0x204400, 0x20441C, 0x204430):
        return True
    return False


def _is_corruption_pc(pc):
    """PCs of the allocator / free-list / XML / download-parser code.

    A fault in these regions is never an 'expected' peripheral access, even if
    a wild pointer happens to land in the 0x10000000..0x20000000 window.
    """
    if pc is None:
        return False
    return (0x204000 <= pc < 0x20A000) or (0x250000 <= pc < 0x251200)


def input_derived(data: bytes, pc, fault, regs) -> dict:
    """Explicit input-derived analysis: does PC/fault/register come from input?

    Searches every 4-byte window (aligned *and* unaligned) of the input for the
    value of PC, the fault address and each register.  Also accepts the ARM
    Thumb bit (value|1 / value&~1) and the small store offsets -4/+4/+8/+0xC,
    because a corrupted free-list pointer normally faults at ``word+off``.
    A separate byte-level test looks for the little-endian address bytes
    verbatim in the input.
    """
    if not data:
        return {"derived": False, "pc_hit": False, "fault_hit": False,
                "reg_hits": [], "hits": [], "byte_hits": []}
    targets = {}

    def add(val, where):
        if val is None or val < 0x1000:
            return
        val &= 0xFFFFFFFF
        for rel, cand in (("eq", val), ("thumb", val | 1),
                          ("aligned", val & ~1)):
            targets.setdefault(cand, []).append((where, rel))
        # a corrupted allocator pointer almost always faults at word+off:
        # free() writes node+8, insert/unlink use +0/+4, never exactly word.
        for d in (4, 8, 0xC):
            targets.setdefault((val + d) & 0xFFFFFFFF, []).append(
                (where, f"+{d:#x}"))
        targets.setdefault((val - 4) & 0xFFFFFFFF, []).append(
            (where, "-0x4"))

    add(pc, "pc")
    add(fault, "fault")
    for name, val in regs.items():
        if name not in ("pc",):
            add(val, name)

    hits = []
    n = len(data)
    for off in range(0, max(0, n - 3)):
        w = struct.unpack_from("<I", data, off)[0]
        got = targets.get(w)
        if got:
            for where, rel in got:
                hits.append({"offset": off, "word": w, "where": where,
                             "relation": rel})
    # byte-level: the address bytes appear contiguously in the input
    byte_hits = []
    for label, val in (("pc", pc), ("fault", fault)):
        if val is None or val < 0x1000:
            continue
        for k in (3, 4):
            pat = (val & 0xFFFFFFFF).to_bytes(4, "little")[:k]
            if pat in data:
                byte_hits.append({"where": label, "bytes": pat.hex(),
                                  "len": k})
                break
    pc_hit = any(h["where"] == "pc" for h in hits)
    fault_hit = any(h["where"] == "fault" for h in hits)
    reg_hits = sorted({h["where"] for h in hits
                       if h["where"] not in ("pc", "fault")})
    return {"derived": bool(hits or byte_hits),
            "pc_hit": pc_hit, "fault_hit": fault_hit,
            "reg_hits": reg_hits, "hits": hits[:12],
            "byte_hits": byte_hits}


# ---------------------------------------------------------------------------
# one case: build the emulator, feed the frames, run, classify
# ---------------------------------------------------------------------------
class ScriptedHost(ChainHost):
    """ChainHost subclass that pre-queues an exact list of host frames.

    Used for the proto/random download phases: on ``CMD:DOWNLOAD-FILE`` it
    queues the whole (deliberately malformed) reply sequence.  The DA consumes
    frames one ``recv`` at a time, so the order is fully deterministic.
    """

    def __init__(self, emu, frames):
        super().__init__(emu, 0, overflow=False, packet_len=PACKET_LEN)
        self.frames = list(frames)
        self.requests = 0

    def on_send(self, data):
        text = bytes(data)
        if b"CMD:DOWNLOAD-FILE" in text:
            self.requests += 1
            for f in self.frames:
                self.emu.rx.append(f)


def _run(emu, addr, args=(), max_insn=10_000_000):
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
    except Exception as exc:                      # UcError or _BudgetExceeded
        err = exc
    returned = bool(emu._ret)
    pc = _pc(emu)
    return {"err": err, "returned": returned, "pc": pc,
            "rc": (uc.reg_read(ac.UC_ARM_REG_R0) & 0xFFFFFFFF)
            if returned else None}


def execute(spec: dict, image: str, max_insn: int = 10_000_000) -> dict:
    """Run exactly one case.  ``spec`` is fully concrete (used by --replay)."""
    mode = spec["mode"]
    rec = {"mode": mode, "spec": spec, "entry": spec.get("entry"),
           "handler": None, "rc": None, "handler_rc": None,
           "stop": None, "pc_stop": None, "fault_pc": None,
           "fault_addr": None, "fault_insn": None, "errno": None,
           "budget_hit": False, "budget_hits": 0,
           "cb_before": 0, "cb_at_blx": None, "cb_after": None,
           "blx_target": None, "fl_before": None, "fl_after": None,
           "unmapped_reads": [], "tx": [], "tx_result": None,
           "verdict": None, "derived": None, "known_heapbait": False,
           "baseline_match": False, "harness_error": None}

    emu = None
    try:
        map_da2 = mode == "proto_bootto"
        emu = boot(image, map_da2=map_da2)
        if map_da2:
            # the real BOOT-TO staging window is 16 MiB; boot() maps 1 MiB.
            try:
                emu.uc.mem_map(DA2_AT + 0x100000, 0x1000000 - 0x100000)
            except Exception:
                pass
            install_sha_engine(emu)       # [DEV] same model as da1_fixed_stage

        st = {"entry": None, "hrc": None}

        if mode == "cmdloop":
            emu.uc.hook_add(UC_HOOK_CODE,
                            lambda uc, a, s, u: st.__setitem__(
                                "entry", uc.reg_read(ac.UC_ARM_REG_R2)),
                            begin=HANDLER_ENTRY_SITE, end=HANDLER_ENTRY_SITE)
            emu.uc.hook_add(UC_HOOK_CODE,
                            lambda uc, a, s, u: st.__setitem__(
                                "hrc", uc.reg_read(ac.UC_ARM_REG_R0)),
                            begin=HANDLER_RET_SITE, end=HANDLER_RET_SITE)

        # intercept cmd_loop's blx r4: record the target, do not execute it
        def on_blx(uc, a, s, u):
            target = uc.reg_read(ac.UC_ARM_REG_R4)
            rec["cb_at_blx"] = target
            rec["blx_target"] = target
            uc.reg_write(ac.UC_ARM_REG_PC, SAFE_CONT)
        emu.uc.hook_add(UC_HOOK_CODE, on_blx, begin=BLX_SITE, end=BLX_SITE)

        emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
        rec["cb_before"] = _u32(emu.uc, DPC_STRUCT + 4) or 0
        rec["fl_before"] = _fl_check(emu)
        mmio_before = set(emu.mmio_reads)

        if mode == "cmdloop":
            for f in spec["frames"]:
                emu.rx.append(f)
            emu.budget["hits"] = 0
            emu.budget["hit"] = False
            run = _run(emu, CMD_LOOP, [], max_insn)
        elif mode == "handler":
            emu.write_bytes(XML_ADDR, spec["xml"])
            emu.budget["hits"] = 0
            emu.budget["hit"] = False
            run = _run(emu, spec["entry"], [SESSION, XML_ADDR], max_insn)
        elif mode in ("proto_dram", "proto_bootto"):
            xml = CMD_XML if mode == "proto_dram" else BOOT_XML
            emu.write_bytes(XML_ADDR, xml)
            emu.on_send = ScriptedHost(emu, spec["frames"]).on_send
            entry = DRAM_REPAIR if mode == "proto_dram" else BOOT_TO
            rec["entry"] = entry
            emu.budget["hits"] = 0
            emu.budget["hit"] = False
            run = _run(emu, entry, [SESSION, XML_ADDR], max_insn)
        else:
            raise ValueError(f"bad mode {mode!r}")

        rec["handler_rc"] = st["hrc"]
        if mode == "cmdloop" and st["entry"] is not None:
            rec["handler"] = HANDLER_BY_ADDR.get(st["entry"])
        elif mode in ("handler", "proto_dram", "proto_bootto"):
            rec["handler"] = HANDLER_BY_ADDR.get(rec["entry"])

        rec["rc"] = run["rc"]
        rec["pc_stop"] = run["pc"]
        rec["declared"] = spec.get("declared")
        rec["delivered"] = spec.get("delivered")
        rec["desync"] = (rec["declared"] is not None
                         and rec["delivered"] is not None
                         and rec["declared"] != rec["delivered"])
        rec["overshoot"] = (rec["delivered"] - rec["declared"]
                            if rec["desync"] else 0)
        rec["budget_hit"] = bool(emu.budget.get("hit"))
        rec["budget_hits"] = emu.budget.get("hits", 0)
        # never keep the exception object: its traceback references this frame
        # (and therefore the Uc instance), which leaks a JIT buffer per case.
        err = run["err"]
        if err is not None:
            rec["errno"] = _ERRNAME.get(getattr(err, "errno", None),
                                        getattr(err, "errno", None))
            fault, insn = _fault_from_instruction(emu.uc, run["pc"])
            rec["fault_addr"] = fault
            rec["fault_insn"] = insn
            rec["fault_pc"] = run["pc"]
        rec["cb_after"] = _u32(emu.uc, DPC_STRUCT + 4)
        rec["fl_after"] = _fl_check(emu)
        rec["unmapped_reads"] = sorted(
            set(emu.mmio_reads) - mmio_before)[:16]
        rec["tx"] = [bytes(t) for t in emu.tx]
        rec["tx_result"] = None
        for t in rec["tx"]:
            m = re.search(rb"<result>(.*?)</result>", t, re.S)
            if m:
                rec["tx_result"] = m.group(1)[:40].decode("latin-1", "replace")

        # ---- stop reason --------------------------------------------------
        if rec["budget_hit"]:
            rec["stop"] = "budget"
        elif err is not None:
            rec["stop"] = "exception"
        elif not run["returned"]:
            rec["stop"] = "insn-cap"
        else:
            rec["stop"] = "returned"

        # ---- input-derived flag (needed by the MMIO/corruption split) ------
        data = _input_bytes(spec)
        cb_eff = (rec["cb_at_blx"] if rec["cb_at_blx"] is not None
                  else rec["cb_after"])
        crashish = (rec["stop"] in ("exception", "insn-cap", "budget")
                    or (cb_eff not in (None, 0)
                        and cb_eff != rec["cb_before"])
                    or not (rec["fl_after"] or {}).get("ok", True))
        if crashish:
            probe_pc = (rec["cb_at_blx"] if cb_eff not in (None, 0)
                        else (rec["fault_pc"] if rec["fault_pc"] is not None
                              else rec["pc_stop"]))
            rec["derived"] = input_derived(data, probe_pc,
                                           rec["fault_addr"], _regs(emu))
        else:
            rec["derived"] = {"derived": False, "pc_hit": False,
                              "fault_hit": False, "reg_hits": [],
                              "hits": [], "byte_hits": []}

        # ---- verdict ------------------------------------------------------
        rec["verdict"] = _classify(rec)
        rec["known_heapbait"] = _is_known_heapbait(
            data, rec["verdict"], rec["fault_addr"], rec["fault_pc"],
            rec["cb_at_blx"])
        if rec["verdict"] == "CB_SET":
            rec["fault_pc"] = BLX_SITE
            rec["fault_addr"] = rec["cb_at_blx"] if rec["cb_at_blx"] is not None \
                else rec["cb_after"]
        return rec
    except Exception as exc:                       # keep the campaign alive
        rec["harness_error"] = "".join(
            traceback.format_exception_only(type(exc), exc)).strip()
        rec["verdict"] = "HARNESS_ERROR"
        rec["stop"] = "harness-error"
        return rec
    finally:
        if emu is not None:
            try:
                # break host<->emu cycles and drop the only reference so the
                # Uc/JIT buffer is released before the next case
                emu.on_send = None
                emu.rx = []
                emu.tx = []
                rec.pop("err", None)
                del emu
            except Exception:
                pass


def _input_bytes(spec):
    if "input" in spec:
        return spec["input"]
    if spec.get("mode") == "handler":
        return spec.get("xml", b"")
    return b"".join(spec.get("frames", []))


def _classify(rec) -> str:
    if rec["budget_hit"] or rec["stop"] == "insn-cap":
        return "HANG"
    if rec["stop"] == "exception":
        f = rec["fault_addr"]
        d = rec.get("derived") or {}
        if (_looks_mmio(f) and not _is_corruption_pc(rec.get("fault_pc"))
                and not d.get("derived")):
            return "UNMAPPED_IO"
        return "DATA_ABORT"
    cb = rec["cb_at_blx"] if rec["cb_at_blx"] is not None else rec["cb_after"]
    if cb not in (None, 0) and cb != rec["cb_before"]:
        return "CB_SET"
    fl = rec["fl_after"] or {}
    if fl and not fl.get("ok", True):
        return "HEAP_CORRUPT"
    if rec["mode"] == "cmdloop":
        hrc = rec["handler_rc"]
        if hrc is not None:
            return "OK_RC" if hrc == 0 else "ERR_RC"
        return "OK_RC" if rec.get("tx_result") == "OK" else "ERR_RC"
    return "OK_RC" if rec["rc"] == 0 else "ERR_RC"


# ---------------------------------------------------------------------------
# XML corpus + mutation engine
# ---------------------------------------------------------------------------
INTS = [b"0xFFFFFFFF", b"0xFFFFFFFC", b"0x7FFFFFFF", b"0x80000000",
        b"-1", b"-4", b"4294967295", b"99999999999999999999",
        b"0x1000000", b"0x2001", b"0x0", b""]
CMD_GARBAGE = [b"", b"CMD:", b"CMD:UNKNOWN", b"CMD:DEBUG:DRAM-REPAIR" * 8,
               b"cmd:set-host-info", b"CMD:SET-HOST-INFO\x00X",
               b"CMD:\xff\xfe", b"CMD:NOT-A-COMMAND", b"\x00" * 8]
ENTITIES = [b"&amp;", b"&lt;", b"&#x41;", b"&#0;", b"&bogus;",
            b"<!ENTITY x \"y\">", b"<!DOCTYPE da [<!ENTITY a \"b\">]>",
            b"&#xFFFFFFFF;", b"%x;"]
ELEM_RE = re.compile(rb"<([A-Za-z_][\w.\-]*)>(.*?)</\1>", re.S)
DIGIT_RE = re.compile(rb"-?\d+")


def base_xml(name: str, arg: str | None = None, version: str = "1.0",
             nul: bool = True) -> bytes:
    if arg is None:
        arg = ARG_TREE.get(name, "")
    body = (f'<?xml version="1.0" encoding="utf-8"?><da>'
            f'<version>{version}</version>'
            f'<command>CMD:{name}</command><arg>{arg}</arg></da>').encode()
    return body + (b"\x00" if nul else b"")


def _pos(b, rng):
    return rng.randrange(len(b) + 1)


def mut_truncate(b, rng):
    p = _pos(b, rng)
    return b[:p], f"trunc@{p:#x}"


def mut_binary(b, rng):
    p = _pos(b, rng)
    n = rng.choice([1, 2, 4, 8, 16, 64, 0x100])
    return b[:p] + rng.randbytes(n) + b[p:], f"binary@{p:#x}+{n:#x}"


def mut_nul(b, rng):
    p = _pos(b, rng)
    n = rng.choice([1, 2, 4, 16, 0x40])
    return b[:p] + b"\x00" * n + b[p:], f"nul@{p:#x}+{n:#x}"


def mut_drop_tag(b, rng):
    ms = list(ELEM_RE.finditer(b))
    if not ms:
        return mut_binary(b, rng)
    m = rng.choice(ms)
    mode = rng.randrange(3)
    if mode == 0:      # drop opening tag only
        out = b[:m.start()] + m.group(2) + b[m.end():]
    elif mode == 1:    # drop closing tag only
        close = b"</" + m.group(1) + b">"
        idx = b.rfind(close, m.start(), m.end())
        out = b[:idx] + b[idx + len(close):] if idx >= 0 else b
    else:              # drop whole element
        out = b[:m.start()] + b[m.end():]
    return out, f"drop-tag:{m.group(1).decode('latin-1')}/m{mode}"


def mut_dup_tag(b, rng):
    ms = list(ELEM_RE.finditer(b))
    if not ms:
        return mut_binary(b, rng)
    m = rng.choice(ms)
    return (b[:m.end()] + m.group(0) + b[m.end():],
            f"dup-tag:{m.group(1).decode('latin-1')}")


def mut_reorder(b, rng):
    cmd = re.search(rb"<command>.*?</command>", b, re.S)
    arg = re.search(rb"<arg>.*?</arg>", b, re.S)
    if not cmd or not arg:
        return mut_binary(b, rng)
    a, c = cmd.group(0), arg.group(0)
    if cmd.start() < arg.start():
        out = b[:cmd.start()] + c + b[cmd.end():arg.start()] + a + b[arg.end():]
    else:
        out = b[:arg.start()] + a + b[arg.end():cmd.start()] + c + b[cmd.end():]
    return out, "reorder-command-arg"


def mut_int(b, rng, token=None):
    ms = list(DIGIT_RE.finditer(b))
    if not ms:
        return mut_binary(b, rng)
    m = rng.choice(ms)
    tok = token if token is not None else rng.choice(INTS)
    return b[:m.start()] + tok + b[m.end():], f"int:{tok.decode('latin-1')}"


def mut_long(b, rng):
    ms = list(ELEM_RE.finditer(b))
    if not ms:
        return mut_binary(b, rng)
    m = rng.choice(ms)
    n = rng.choice([0x80, 0x100, 0x400, 0x900])
    fill = bytes([rng.choice(b"Aa0 <>/")]) * n
    return (b[:m.start(2)] + fill + b[m.end(2):],
            f"long:{m.group(1).decode('latin-1')}+{n:#x}")


def mut_deep(b, rng):
    n = rng.choice([32, 64, 128, 200, 300])
    inner = b"<a>" * n + b"</a>" * n
    for marker in (b"</arg>", b"</da>"):
        idx = b.rfind(marker)
        if idx >= 0:
            return b[:idx] + inner + b[idx:], f"deep:{n}"
    return b + inner, f"deep-append:{n}"


def mut_entity(b, rng):
    p = _pos(b, rng)
    tok = rng.choice(ENTITIES)
    return b[:p] + tok + b[p:], f"entity:{tok[:12].decode('latin-1')}"


def mut_cdata(b, rng):
    p = _pos(b, rng)
    tok = rng.choice([b"<![CDATA[", b"<!--", b"]]>", b"-->",
                      b"<![CDATA[unclosed", b"<!--unclosed"])
    return b[:p] + tok + b[p:], f"cdata:{tok.decode('latin-1')}"


def mut_cmd(b, rng):
    m = re.search(rb"<command>(.*?)</command>", b, re.S)
    if not m:
        return mut_binary(b, rng)
    tok = rng.choice(CMD_GARBAGE)
    return b[:m.start(1)] + tok + b[m.end(1):], "cmd-garbage"


def mut_dup_command(b, rng):
    m = re.search(rb"<command>.*?</command>", b, re.S)
    if not m:
        return mut_dup_tag(b, rng)
    return (b[:m.end()] + m.group(0) + b[m.end():], "dup-command")


def mut_drop_version(b, rng):
    m = re.search(rb"<version>.*?</version>", b, re.S)
    if not m:
        return mut_binary(b, rng)
    return b[:m.start()] + b[m.end():], "drop-version"


def mut_oversize(b, rng):
    out = bytearray(b)
    while len(out) < XML_MAX + rng.choice([1, 0x40, 0x200]):
        out += b"<pad>%d</pad>" % rng.randrange(1000)
    return bytes(out), f"oversize:{len(out):#x}"


def mut_tag_garbage(b, rng):
    p = _pos(b, rng)
    tok = rng.choice([b"<<", b"< ", b"<>", b"</>", b"<a", b">", b"\x00<"])
    return b[:p] + tok + b[p:], "tag-garbage"


MUTATORS = [mut_truncate, mut_binary, mut_nul, mut_drop_tag, mut_dup_tag,
            mut_reorder, mut_int, mut_long, mut_deep, mut_entity, mut_cdata,
            mut_cmd, mut_dup_command, mut_drop_version, mut_oversize,
            mut_tag_garbage]


def _apply_mutations(b, rng, count):
    labels = []
    for _ in range(count):
        fn = rng.choice(MUTATORS)
        try:
            b, lab = fn(b, rng)
        except Exception:
            b, lab = b, "mut-fail"
        labels.append(lab)
    return b, "+".join(labels)


def _curated_xml_cases(seed):
    """One case per (command, mutation) so every mutation type is exercised."""
    out = []
    for ti, (name, _addr) in enumerate(HANDLERS):
        base = base_xml(name)
        for mi, fn in enumerate(MUTATORS):
            rng = random.Random((seed * 1000003) ^ (ti << 16) ^ mi ^ 0x58584D4C)
            try:
                data, lab = fn(base, rng)
            except Exception:
                continue
            if fn is mut_int:            # curate a specific huge token too
                data, lab = fn(base, random.Random(mi), INTS[mi % len(INTS)])
            out.append((f"{name}:{lab}", data))
    return out


# ---------------------------------------------------------------------------
# phase case generators: each yields a fully concrete spec
# ---------------------------------------------------------------------------
def _cmdloop_spec(xml_bytes: bytes, handshake=b"OK\x00") -> dict:
    frames = [handshake, xml_bytes]
    return {"mode": "cmdloop", "entry": None, "frames": frames,
            "input": b"".join(frames)}


def gen_xml(seed, cases):
    corpus = _curated_xml_cases(seed)
    rng = random.Random(seed ^ 0x584D4C00)
    for i in range(cases):
        if i < len(corpus):
            label, data = corpus[i]
        else:
            name = rng.choice([n for n, _ in HANDLERS])
            base = base_xml(name)
            data, label = _apply_mutations(base, rng, rng.choice([1, 1, 2, 3]))
            if rng.random() < 0.10:      # random handshake corruption
                hs = rng.choice([b"", b"OK", b"OK\x00", b"OK@", b"NO\x00",
                                 rng.randbytes(rng.randrange(0, 0x41))])
            else:
                hs = b"OK\x00"
            spec = _cmdloop_spec(data, hs)
            spec.update({"label": label, "cmd": name})
            yield i, spec
            continue
        spec = _cmdloop_spec(data)
        spec.update({"label": label, "cmd": label.split(":")[0]})
        yield i, spec


def gen_handlers(seed, cases):
    rng = random.Random(seed ^ 0x48414E44)
    corpus = [(name, fn)
              for name, _a in HANDLERS for fn in MUTATORS]
    for i in range(cases):
        if i < len(corpus):
            name, fn = corpus[i]
            rng2 = random.Random((seed * 7919) ^ (i * 131))
            try:
                data, lab = fn(base_xml(name), rng2)
            except Exception:
                data, lab = base_xml(name), "base"
        else:
            name = rng.choice([n for n, _ in HANDLERS])
            data, lab = _apply_mutations(base_xml(name), rng,
                                         rng.choice([1, 1, 2, 3]))
        addr = dict(HANDLERS)[name]
        yield i, {"mode": "handler", "entry": addr, "xml": data,
                  "label": lab, "cmd": name, "input": data}


def _proto_frames(scen):
    frames = []
    if scen.get("ack1") is not None:
        frames.append(scen["ack1"])
    if scen.get("lenframe") is not None:
        frames.append(scen["lenframe"])
    for chunk in scen.get("chunks", []):
        frames.append(b"OK\x00")
        frames.append(chunk)
    frames.extend(scen.get("extra", []))
    return frames


def _proto_spec(scen):
    mode = "proto_bootto" if scen.get("target") == "bootto" else "proto_dram"
    frames = _proto_frames(scen)
    chunks = scen.get("chunks", [])
    return {"mode": mode, "entry": None, "frames": frames,
            "declared": scen.get("declared"),
            "delivered": sum(len(c) for c in chunks),
            "input": b"".join(frames)}


def _curated_proto(seed):
    """Concrete protocol pathologies, incl. the known HeapBait and the new
    declared-vs-delivered desync / integer-wrap cases."""
    S = []

    def add(label, target="dram", declared=0x10, ack1=b"OK\x00",
            lenframe=None, chunks=None, extra=None):
        if lenframe is None:
            lenframe = b"OK@0x%x\x00" % declared
        S.append({"label": label, "target": target, "declared": declared,
                  "ack1": ack1, "lenframe": lenframe,
                  "chunks": chunks or [], "extra": extra or []})

    # --- ACK / length-token pathologies ---------------------------------
    add("no-reply-at-all", ack1=None, lenframe=None)
    add("ack1-missing", ack1=None)
    add("ack1-OK-no-nul", ack1=b"OK")
    add("ack1-OK-at", ack1=b"OK@")
    add("ack1-OK-at-0x", ack1=b"OK@0x")
    add("ack1-OK-at-0xZZ", ack1=b"OK@0xZZ\x00")
    add("ack1-OK-garbage", ack1=b"OK\x00" + b"\xff" * 0x20)
    add("ack1-NO", ack1=b"NO\x00")
    add("ack1-empty", ack1=b"")
    add("len-missing", lenframe=None)
    add("len-no-at", lenframe=b"OK\x00")
    add("len-OK-at", lenframe=b"OK@\x00")
    add("len-0x", lenframe=b"OK@0x\x00")
    add("len-0xZZ", lenframe=b"OK@0xZZ\x00")
    add("len-negative", lenframe=b"OK@-1\x00")
    add("len-negative4", lenframe=b"OK@-4\x00")
    add("len-huge-dec", lenframe=b"OK@" + b"9" * 32 + b"\x00")
    add("len-no-nul", declared=0x10, lenframe=b"OK@0x10")
    add("len-junk-suffix", lenframe=b"OK@0x10JUNK\x00")
    add("len-huge-ffffffff", declared=0xFFFFFFFF,
        lenframe=b"OK@0xffffffff\x00", chunks=[b"A" * 0x2000])
    add("len-huge-fffffffc", declared=0xFFFFFFFC,
        lenframe=b"OK@0xfffffffc\x00", chunks=[b"A" * 0x2000])
    add("len-7fffffff", declared=0x7FFFFFFF,
        lenframe=b"OK@0x7fffffff\x00", chunks=[b"A" * 0x40])
    add("len-ffffff", declared=0xFFFFFF, chunks=[b"A" * 0x40])
    add("decl-0", declared=0, chunks=[b"A" * 0x2000])
    add("decl-1", declared=1, chunks=[b"A" * 0x2000])
    add("decl-ff", declared=0xFF, chunks=[b"A" * 0x2000])
    add("decl-0x10-data-0x2000", declared=0x10, chunks=[b"A" * 0x2000])
    add("decl-0x10-data-0x41", declared=0x10, chunks=[b"A" * 0x41])
    add("decl-0x2000-data-0x2000", declared=0x2000,
        chunks=[b"A" * 0x2000])
    add("decl-0x2001-data-0x2000", declared=0x2001,
        chunks=[b"A" * 0x2000])
    add("short-delivery", declared=0x100, chunks=[b"A" * 0x10])
    add("zero-len-chunk", declared=0x10, chunks=[b""])
    add("extra-chunks", declared=0x10, chunks=[b"B" * 0x10, b"C" * 0x10,
                                               b"D" * 0x10])
    add("early-eof", declared=0x1000, chunks=[b"A" * 0x10])
    add("repeated-ok", declared=0x10, chunks=[b"A" * 0x10],
        extra=[b"OK\x00"] * 8)
    add("repeated-ok-no-data", declared=0x10, chunks=[],
        extra=[b"OK\x00"] * 16)
    # --- declared-vs-delivered desync (new class): 4 bytes past exact fit ---
    add("desync-cb-L3c-overshoot4", declared=0x3C,
        chunks=[make_payload(0x3C, 0x40000000) + b"AAAA"])
    # --- known HeapBait (fake allocator header, exact fit) --------------
    add("known-heapbait-L3c", declared=0x3C,
        chunks=[make_payload(0x3C, 0xC0DE0001)], extra=[])
    add("known-heapbait-L40", declared=0x40,
        chunks=[make_payload(0x40, 0xC0DE0001)], extra=[])
    add("fakehdr-at-cap-0x10", declared=0x10,
        chunks=[make_payload(0x10, 0xC0DE0001)])
    add("fakehdr-at-cap-0x100", declared=0x100,
        chunks=[make_payload(0x100, 0xC0DE0001)])
    # --- BOOT-TO: fixed 0x40000000, declared < 0x1000000 gate -----------
    add("bootto-ok-small", target="bootto", declared=0x10,
        chunks=[b"\x00" * 0x10])
    add("bootto-decl-0x1000000", target="bootto", declared=0x1000000,
        chunks=[b"A" * 0x40])
    add("bootto-decl-0xffffff", target="bootto", declared=0xFFFFFF,
        chunks=[b"A" * 0x40])
    add("bootto-desync", target="bootto", declared=0x10,
        chunks=[b"A" * 0x2000])
    add("bootto-huge", target="bootto", declared=0x7FFFFFFF,
        chunks=[b"A" * 0x40])
    add("bootto-wrap", target="bootto", declared=0xFFFFFFFC,
        chunks=[b"A" * 0x40])
    add("bootto-nonhex", target="bootto", declared=0x10,
        lenframe=b"OK@0xZZ\x00", chunks=[b"A" * 0x40])
    add("bootto-noack", target="bootto", declared=0x10, ack1=None)
    return S


def gen_proto(seed, cases):
    corpus = _curated_proto(seed)
    rng = random.Random(seed ^ 0x50524F54)
    for i in range(cases):
        if i < len(corpus):
            scen = dict(corpus[i])
            label = scen.pop("label")
        else:
            target = rng.choice(["dram", "dram", "dram", "bootto"])
            declared = rng.choice([0, 1, 0xFF, 0x10, 0x3C, 0x40, 0x100,
                                   0x2000, 0x2001, 0xFFFF, 0xFFFFFF,
                                   0x1000000, 0x7FFFFFFF, 0xFFFFFFFC,
                                   0xFFFFFFFF])
            if target == "bootto" and declared not in (0x1000000,
                                                       0x7FFFFFFF,
                                                       0xFFFFFFFC,
                                                       0xFFFFFFFF):
                declared = rng.choice([0, 1, 0x10, 0x2000, 0xFFFF, 0xFFFFFF])
            ack1 = rng.choice([b"OK\x00", b"OK", b"OK@", b"OK@0x",
                               b"OK@0xZZ\x00", b"NO\x00", b"",
                               b"OK\x00" + rng.randbytes(rng.randrange(1, 0x20)),
                               None])
            lf = rng.choice([
                None,
                b"OK@0x%x\x00" % declared,
                b"OK@0x%x" % declared,
                b"OK@%d\x00" % declared,
                b"OK@" + rng.randbytes(rng.randrange(0, 12)) + b"\x00",
                b"OK@0xZZ\x00", b"OK@\x00", b"OK\x00",
            ])
            chunks = []
            for _ in range(rng.choice([0, 1, 1, 1, 2, 3])):
                kind = rng.randrange(5)
                if kind == 0:
                    chunks.append(rng.randbytes(rng.choice(
                        [0, 1, 2, 0x10, 0x40, 0x100, 0x1000, 0x2000])))
                elif kind == 1:
                    chunks.append(b"A" * rng.choice([0x10, 0x41, 0x100,
                                                     0x1000, 0x2000]))
                elif kind == 2:
                    chunks.append(make_payload(
                        max(0, min(declared, 0x1FF0)),
                        rng.choice([0xC0DE0001, 0x40000000])))
                elif kind == 3:
                    chunks.append(b"\x00" * rng.choice([0x10, 0x100, 0x2000]))
                else:
                    cap = _align4(max(0, min(declared, 0x1FF0)) + 0x10) \
                        - CHUNK_HDR
                    buf = bytearray(rng.choice([0x10, 0x100, 0x2000]))
                    hdr = struct.pack("<III", FAKE_MAGIC, DPC_ADDR,
                                      rng.choice([0xC0DE0001, 0x40000000]))
                    if cap + CHUNK_HDR <= len(buf):
                        buf[cap:cap + CHUNK_HDR] = hdr
                    chunks.append(bytes(buf))
            scen = {"target": target, "declared": declared, "ack1": ack1,
                    "lenframe": lf, "chunks": chunks,
                    "extra": [b"OK\x00"] * rng.randrange(0, 4)}
            label = (f"rand:{target}:decl={declared:#x}:"
                     f"nchunk={len(chunks)}")
        spec = _proto_spec(scen)
        spec.update({"label": label, "target": scen.get("target", "dram"),
                     "declared": scen.get("declared")})
        yield i, spec


def gen_random(seed, cases):
    rng = random.Random(seed ^ 0x52414E44)
    for i in range(cases):
        if i % 2 == 0:
            # random bytes as the whole command-loop conversation
            hs = rng.randbytes(rng.choice([0, 1, 2, 3, 4, 0x40, 0x41]))
            if rng.random() < 0.6:
                hs = b"OK\x00" + hs
            body = rng.randbytes(rng.choice([0, 1, 2, 16, 0x40, 0x100,
                                             0x400, 0x800, 0x900]))
            spec = _cmdloop_spec(body, hs)
            spec.update({"label": f"rand-cmdloop:{len(body):#x}",
                         "cmd": "random"})
        else:
            target = rng.choice(["dram", "bootto"])
            declared = rng.choice([0, 1, 0xFF, 0x10, 0x2000, 0xFFFFFFFF,
                                   0xFFFFFFFC, 0x7FFFFFFF, 0xFFFFFF,
                                   rng.randrange(0, 0x10000)])
            ack1 = rng.randbytes(rng.randrange(0, 0x41))
            if rng.random() < 0.5:
                ack1 = b"OK\x00" + ack1
            lf = b"OK@0x%x\x00" % declared if rng.random() < 0.7 \
                else rng.randbytes(rng.randrange(0, 0x20))
            chunks = []
            for _ in range(rng.randrange(0, 4)):
                chunks.append(rng.randbytes(rng.choice(
                    [0, 1, 2, 0x10, 0x40, 0x100, 0x800, 0x2000])))
            scen = {"target": target, "declared": declared, "ack1": ack1,
                    "lenframe": lf, "chunks": chunks,
                    "extra": [rng.randbytes(rng.randrange(0, 0x20))
                              for _ in range(rng.randrange(0, 3))]}
            spec = _proto_spec(scen)
            spec.update({"label": f"rand-dl:{target}",
                         "target": target, "declared": declared})
        yield i, spec


GENERATORS = {"xml": gen_xml, "proto": gen_proto,
              "handlers": gen_handlers, "random": gen_random}


# ---------------------------------------------------------------------------
# validation controls (abort exit 1 if the classifier is broken)
# ---------------------------------------------------------------------------
def validation_controls(image):
    out = []

    # (a) known-good: valid CMD:SET-HOST-INFO through the real command loop
    spec = _cmdloop_spec(BENIGN_XML)
    rec = execute(spec, image)
    out.append({"name": "control-a-known-good", "want": "OK_RC",
                "got": rec["verdict"], "entry": rec["handler"],
                "pc": rec["pc_stop"], "fault": rec["fault_addr"],
                "ok": rec["verdict"] == "OK_RC"})

    # (b) known-bad: DRAM-REPAIR HeapBait with {DEADBEEF,2DF79C,C0DE0001} @L=3C
    payload = make_payload(0x3C, 0xC0DE0001)
    emu = boot(image)
    try:
        host = FixedChainHost(emu, 0x3C, payload, 0xC0DE0001,
                              packet_len=PACKET_LEN)
        emu.on_send = host.on_send
        rec = _execute_cmdloop_on(emu, CMD_XML, image)
    finally:
        emu.on_send = None
        del emu
    ok = (rec["verdict"] == "CB_SET"
          and rec["cb_at_blx"] == 0xC0DE0001
          and rec["known_heapbait"])
    out.append({"name": "control-b-known-bad-cb", "want": "CB_SET/0xC0DE0001",
                "got": f"{rec['verdict']}/{rec['cb_at_blx']:#x}"
                if rec["cb_at_blx"] is not None else rec["verdict"],
                "entry": rec["handler"], "pc": rec["fault_pc"],
                "fault": rec["fault_addr"], "ok": bool(ok)})

    # (c) known-abort: L=0x40 free-remainder poison -> data abort near
    #     0xDEADBEF3 (unlink store through the 0xDEADBEEF "prev" pointer)
    payload = make_payload(0x40, 0xC0DE0001)
    emu = boot(image)
    try:
        host = FixedChainHost(emu, 0x40, payload, 0xC0DE0001,
                              packet_len=PACKET_LEN)
        emu.on_send = host.on_send
        rec = _execute_cmdloop_on(emu, CMD_XML, image)
    finally:
        emu.on_send = None
        del emu
    near = (rec["fault_addr"] is not None
            and abs(rec["fault_addr"] - 0xDEADBEF3) <= 0x10)
    ok = rec["verdict"] == "DATA_ABORT" and near
    out.append({"name": "control-c-known-abort", "want": "DATA_ABORT@~DEADBEF3",
                "got": f"{rec['verdict']}@{rec['fault_addr']:#x}"
                if rec["fault_addr"] is not None else rec["verdict"],
                "entry": rec["handler"], "pc": rec["fault_pc"],
                "fault": rec["fault_addr"], "ok": bool(ok)})
    return out


def _execute_cmdloop_on(emu, xml_bytes, image):
    """Run a cmd_loop case on an emulator that already has a host installed."""
    # execute() makes its own emulator, so the control runs its tiny cmd_loop
    # branch directly on the already-booted emulator that has the host installed
    # (kept in sync with execute()'s cmdloop branch).
    st = {"entry": None, "hrc": None}

    def on_entry(uc, a, s, u):
        st["entry"] = uc.reg_read(ac.UC_ARM_REG_R2)

    def on_ret(uc, a, s, u):
        st["hrc"] = uc.reg_read(ac.UC_ARM_REG_R0)

    def on_blx(uc, a, s, u):
        rec_cb["cb"] = uc.reg_read(ac.UC_ARM_REG_R4)
        uc.reg_write(ac.UC_ARM_REG_PC, SAFE_CONT)

    rec_cb = {}
    emu.uc.hook_add(UC_HOOK_CODE, on_entry, begin=HANDLER_ENTRY_SITE,
                    end=HANDLER_ENTRY_SITE)
    emu.uc.hook_add(UC_HOOK_CODE, on_ret, begin=HANDLER_RET_SITE,
                    end=HANDLER_RET_SITE)
    emu.uc.hook_add(UC_HOOK_CODE, on_blx, begin=BLX_SITE, end=BLX_SITE)
    emu.write_bytes(XML_ADDR, xml_bytes)
    emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
    fl_before = _fl_check(emu)
    emu.rx.clear()
    emu.rx.append(b"OK\x00")
    emu.rx.append(xml_bytes)
    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    run = _run(emu, CMD_LOOP, [])
    fault = None
    fault_insn = None
    if run["err"] is not None:
        fault, fault_insn = _fault_from_instruction(emu.uc, run["pc"])
    r = {"mode": "cmdloop", "entry": st["entry"],
         "handler": HANDLER_BY_ADDR.get(st["entry"]),
         "rc": run["rc"], "handler_rc": st["hrc"], "pc_stop": run["pc"],
         "fault_pc": run["pc"] if run["err"] is not None else None,
         "fault_addr": fault, "fault_insn": fault_insn,
         "budget_hit": bool(emu.budget["hit"]),
         "stop": ("budget" if emu.budget["hit"] else
                  "exception" if run["err"] is not None else
                  "returned" if run["returned"] else "insn-cap"),
         "cb_before": 0, "cb_at_blx": rec_cb.get("cb"),
         "cb_after": _u32(emu.uc, DPC_STRUCT + 4),
         "fl_before": fl_before, "fl_after": _fl_check(emu),
         "tx": [bytes(t) for t in emu.tx], "tx_result": None,
         "budget_hits": emu.budget["hits"]}
    for t in r["tx"]:
        m = re.search(rb"<result>(.*?)</result>", t, re.S)
        if m:
            r["tx_result"] = m.group(1)[:40].decode("latin-1", "replace")
    data = b"OK\x00" + xml_bytes
    cb_eff = (r["cb_at_blx"] if r["cb_at_blx"] is not None else r["cb_after"])
    crashish = (r["stop"] in ("exception", "insn-cap", "budget")
                or (cb_eff not in (None, 0) and cb_eff != r["cb_before"])
                or not (r["fl_after"] or {}).get("ok", True))
    if crashish:
        probe_pc = (r["cb_at_blx"] if cb_eff not in (None, 0)
                    else (r["fault_pc"] if r["fault_pc"] is not None
                          else r["pc_stop"]))
        r["derived"] = input_derived(data, probe_pc, r["fault_addr"],
                                     _regs(emu))
    else:
        r["derived"] = {"derived": False}
    r["verdict"] = _classify(r)
    r["known_heapbait"] = _is_known_heapbait(
        data, r["verdict"], r["fault_addr"], r["fault_pc"], r["cb_at_blx"])
    if r["verdict"] == "CB_SET":
        r["fault_pc"] = BLX_SITE
        r["fault_addr"] = r["cb_at_blx"] if r["cb_at_blx"] is not None \
            else r["cb_after"]
    return r


# ---------------------------------------------------------------------------
# baseline table: a case is "baseline" when an unmutated valid command already
# produces the same (entry, class, pc, fault).  Prevents calling an emulation
# gap a new bug.
# ---------------------------------------------------------------------------
def build_baselines(image, max_insn):
    bl = []
    for name, _addr in HANDLERS:
        spec = _cmdloop_spec(base_xml(name))
        r = execute(spec, image, max_insn)
        bl.append({"cmd": name, "route": "cmdloop", "entry": r["entry"],
                   "verdict": r["verdict"], "pc": r["fault_pc"],
                   "fault": r["fault_addr"]})
        spec = {"mode": "handler", "entry": dict(HANDLERS)[name],
                "xml": base_xml(name)}
        r = execute(spec, image, max_insn)
        bl.append({"cmd": name, "route": "handler", "entry": r["entry"],
                   "verdict": r["verdict"], "pc": r["fault_pc"],
                   "fault": r["fault_addr"]})
    return bl


def baseline_lookup(baselines, rec):
    for b in baselines:
        if (b["entry"] == rec.get("entry")
                and b["verdict"] == rec["verdict"]
                and b["pc"] == rec.get("fault_pc")
                and b["fault"] == rec.get("fault_addr")):
            return b
    return None


# ---------------------------------------------------------------------------
# campaign
# ---------------------------------------------------------------------------
class PhaseClock:
    def __init__(self, seconds):
        self.seconds = seconds
        self.start = time.time()
        self.hit = False

    def expired(self):
        if self.seconds <= 0:
            return False
        if time.time() - self.start >= self.seconds:
            self.hit = True
            return True
        return False


def run_phase(phase, image, seed, cases, max_insn, clock, baselines,
              save_dir, verbose=True):
    results = []
    gen = GENERATORS[phase](seed, cases)
    counts = {}
    t0 = time.time()
    effective = 0
    for idx, spec in gen:
        if clock.expired():
            break
        rec = execute(spec, image, max_insn)
        rec["phase"] = phase
        rec["index"] = idx
        rec["seed"] = seed
        b = baseline_lookup(baselines, rec)
        if b is not None and rec["verdict"] in ("DATA_ABORT", "UNMAPPED_IO",
                                                "HANG"):
            rec["baseline_match"] = True
        counts[rec["verdict"]] = counts.get(rec["verdict"], 0) + 1
        results.append(rec)
        effective += 1
        if effective % 200 == 0:
            gc.collect()          # reclaim any Uc cycles promptly
        if verbose and (effective % 250 == 0 or effective == cases):
            cs = " ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            print(f"  [{phase}] {effective}/{cases} {cs}", flush=True)
    dt = time.time() - t0
    print(f"  [{phase}] done: {effective} cases in {dt:.1f}s "
          f"({dt / max(effective, 1) * 1000:.1f} ms/case) "
          f"{'[CLOCK TRUNCATED]' if clock.hit else ''}", flush=True)
    return results, effective


SEVERITY = {"HARNESS_ERROR": 0, "DATA_ABORT": 1, "HEAP_CORRUPT": 2,
            "CB_SET": 3, "HANG": 4, "UNMAPPED_IO": 5, "ERR_RC": 6,
            "OK_RC": 7}


def dedup(results):
    groups = {}
    for r in results:
        key = (r["phase"], r["verdict"], r.get("fault_pc"),
               r.get("entry"))
        g = groups.get(key)
        if g is None:
            g = {"key": key, "count": 0, "rep": r,
                 "min_len": len(_input_bytes(r["spec"])), "faults": {}}
            groups[key] = g
        g["count"] += 1
        n = len(_input_bytes(r["spec"]))
        if n < g["min_len"]:
            g["min_len"] = n
            g["rep"] = r
        fa = r.get("fault_addr")
        old = g["faults"].get(fa)
        if old is None or n < len(_input_bytes(old["spec"])):
            g["faults"][fa] = r
    return sorted(groups.values(),
                  key=lambda g: (PHASE_ID.get(g["key"][0], 9),
                                 SEVERITY.get(g["key"][1], 9),
                                 g["key"][2] or 0))


def _hex_short(data, n=72):
    h = data[:n].hex()
    return h + ("..." if len(data) > n else "")


def _ascii_short(data, n=48):
    s = "".join(chr(c) if 32 <= c < 127 else "." for c in data[:n])
    return s + ("..." if len(data) > n else "")


def save_repro(rec, save_dir):
    os.makedirs(save_dir, exist_ok=True)
    mode = rec["mode"]
    spec = rec["spec"]
    out = {
        "meta": {"phase": rec.get("phase"), "index": rec.get("index"),
                 "seed": rec.get("seed"), "verdict": rec["verdict"],
                 "handler": rec.get("handler"), "entry": rec.get("entry"),
                 "pc": rec.get("fault_pc"), "fault_addr": rec.get("fault_addr"),
                 "cb_at_blx": rec.get("cb_at_blx"),
                 "known_heapbait": rec.get("known_heapbait"),
                 "declared": rec.get("declared"),
                 "delivered": rec.get("delivered"),
                 "overshoot": rec.get("overshoot"),
                 "input_len": len(_input_bytes(spec))},
        "spec": {"mode": mode, "entry": spec.get("entry"),
                 "xml": spec.get("xml", b"").hex(),
                 "frames": [f.hex() for f in spec.get("frames", [])],
                 "input": _input_bytes(spec).hex()},
    }
    pc = rec.get("fault_pc")
    fa = rec.get("fault_addr")
    ent = rec.get("entry") or 0
    idx = rec.get("index")
    name = (f"{rec.get('phase','x')}_{rec['verdict']}_e{ent:08x}_"
            f"pc{(pc if pc is not None else 0):08x}_"
            f"fa{(fa if fa is not None else 0):08x}_i{idx}.json")
    path = os.path.join(save_dir, name)
    with open(path, "w") as f:
        json.dump(out, f, indent=1)
    return path


def print_table(groups):
    print("")
    print("-- deduplicated results "
          "(phase, class, fault_pc, handler/entry) --")
    hdr = ("count", "phase", "class", "entry", "fault_pc", "fault_addrs",
           "minlen", "derived", "flags")
    rows = [hdr]
    saved = []
    for g in groups:
        r = g["rep"]
        ent = r.get("handler") or (f"0x{r['entry']:x}"
                                   if r.get("entry") else "-")
        flags = []
        if r.get("known_heapbait"):
            flags.append("KNOWN-HEAPBAIT")
        if r.get("baseline_match"):
            flags.append("BASELINE")
        if r["verdict"] in ("OK_RC", "ERR_RC"):
            flags = ["-"]
        pc = f"0x{r['fault_pc']:x}" if r.get("fault_pc") is not None else "-"
        fa_list = sorted(g["faults"], key=lambda x: (x is None, x))
        fa_s = ",".join("0x%x" % x if x is not None else "-"
                        for x in fa_list[:3])
        if len(fa_list) > 3:
            fa_s += ",..."
        any_derived = any((rr.get("derived") or {}).get("derived")
                          for rr in g["faults"].values())
        row = (str(g["count"]), r["phase"], r["verdict"], ent, pc, fa_s,
               str(g["min_len"]), "YES" if any_derived else "-",
               ",".join(flags) or "-")
        rows.append(row)
        saved.append((g, r))
    widths = [max(len(str(row[i])) for row in rows) for i in range(len(hdr))]
    for ri, row in enumerate(rows):
        print("  " + "  ".join(str(v).ljust(w)
                               for v, w in zip(row, widths)))
        if ri == 0:
            print("  " + "  ".join("-" * w for w in widths))
    return saved


def print_interesting(saved, save_dir, max_rows=20):
    print("")
    print("-- interesting cases (deduplicated, smallest repro kept) --")
    shown = 0
    interesting = [(g, r) for g, r in saved
                   if r["verdict"] not in ("OK_RC", "ERR_RC")]
    for g, r in interesting:
        if shown >= max_rows:
            print(f"  ... {len(interesting) - shown} more in JSON")
            break
        shown += 1
        # prefer a derived variant when the group has one, so the printed
        # bytes actually explain the fault address
        rep = r
        for rr in g["faults"].values():
            if (rr.get("derived") or {}).get("derived"):
                rep = rr
                break
        data = _input_bytes(rep["spec"])
        ent = rep.get("handler") or (f"0x{rep['entry']:x}"
                                     if rep.get("entry") else "-")
        print(f"  [{shown}] {rep['phase']} {rep['verdict']} entry={ent} "
              f"pc={rep['fault_pc'] and hex(rep['fault_pc'])} "
              f"fault={rep['fault_addr'] and hex(rep['fault_addr'])} "
              f"len={len(data)} count={g['count']}"
              + (" DERIVED" if (rep.get("derived") or {}).get("derived")
                 else "")
              + (" KNOWN" if rep.get("known_heapbait") else "")
              + (" BASELINE" if rep.get("baseline_match") else ""))
        print(f"       bytes: {_hex_short(data)}")
        print(f"       ascii: {_ascii_short(data)}")
        d = rep.get("derived") or {}
        if d.get("derived"):
            hits = d.get("hits") or []
            print("       derived: "
                  + ", ".join(f"{h['where']}{h['relation']}<-in["
                              f"{h['offset']:#x}]={h['word']:#x}"
                              for h in hits[:4])
                  + (f", byte-match={d['byte_hits']}" if d.get("byte_hits")
                     else ""))
        if save_dir:
            # one minimal repro per distinct fault address in this group
            for fa in sorted(g["faults"], key=lambda x: (x is None, x)):
                p = save_repro(g["faults"][fa], save_dir)
                print(f"       repro[{('-' if fa is None else hex(fa))}]: {p}")


def matrix(results):
    classes = ["OK_RC", "ERR_RC", "DATA_ABORT", "HEAP_CORRUPT", "CB_SET",
               "HANG", "UNMAPPED_IO", "HARNESS_ERROR"]
    ph = [p for p in PHASE_ORDER]
    tab = {p: {c: 0 for c in classes} for p in ph}
    for r in results:
        tab.setdefault(r["phase"], {c: 0 for c in classes})
        tab[r["phase"]][r["verdict"]] = \
            tab[r["phase"]].get(r["verdict"], 0) + 1
    return tab, classes


def print_matrix(results):
    tab, classes = matrix(results)
    print("")
    print("-- summary matrix (cases per phase/class) --")
    hdr = ["phase"] + classes
    rows = [hdr]
    for p in PHASE_ORDER:
        if p in tab:
            rows.append([p] + [tab[p].get(c, 0) for c in classes])
    rows.append(["TOTAL"] + [sum(tab[p].get(c, 0) for p in tab)
                             for c in classes])
    widths = [max(len(str(r[i])) for r in rows) for i in range(len(hdr))]
    for ri, row in enumerate(rows):
        print("  " + "  ".join(str(v).ljust(w)
                               for v, w in zip(row, widths)))
        if ri == 0:
            print("  " + "  ".join("-" * w for w in widths))


def json_result(results, controls, baselines, seed, cases, phases,
                runtime, truncated, image):
    out_results = []
    for r in results:
        data = _input_bytes(r["spec"])
        interesting = r["verdict"] not in ("OK_RC", "ERR_RC")
        keep = data if interesting else data[:0x100]
        out_results.append({
            "phase": r["phase"], "index": r["index"], "seed": r["seed"],
            "verdict": r["verdict"], "mode": r["mode"],
            "handler": r.get("handler"), "entry": r.get("entry"),
            "rc": r.get("rc"), "handler_rc": r.get("handler_rc"),
            "stop": r.get("stop"), "pc_stop": r.get("pc_stop"),
            "fault_pc": r.get("fault_pc"), "fault_addr": r.get("fault_addr"),
            "fault_insn": r.get("fault_insn"), "errno": r.get("errno"),
            "cb_before": r.get("cb_before"), "cb_at_blx": r.get("cb_at_blx"),
            "cb_after": r.get("cb_after"),
            "budget_hit": r.get("budget_hit"),
            "budget_hits": r.get("budget_hits"),
            "fl_before": r.get("fl_before"), "fl_after": r.get("fl_after"),
            "unmapped_reads": r.get("unmapped_reads"),
            "tx_result": r.get("tx_result"),
            "known_heapbait": r.get("known_heapbait"),
            "baseline_match": r.get("baseline_match"),
            "derived": r.get("derived"),
            "input_len": len(data),
            "input_hex": keep.hex(),
            "input_truncated": len(keep) < len(data),
            "label": r["spec"].get("label"),
            "declared": r["spec"].get("declared"),
            "delivered": r["spec"].get("delivered"),
            "desync": r.get("desync"),
            "overshoot": r.get("overshoot"),
            "target": r["spec"].get("target"),
            "harness_error": r.get("harness_error"),
        })
    return {
        "tool": "da1_fuzz.py", "image": os.path.abspath(image),
        "seed": seed, "cases_per_phase": cases, "phases": phases,
        "packet_len": PACKET_LEN, "runtime_seconds": round(runtime, 1),
        "clock_truncated": truncated,
        "controls": controls, "baselines": baselines,
        "results": out_results,
    }


# ---------------------------------------------------------------------------
# --replay
# ---------------------------------------------------------------------------
def replay(path, image, max_insn):
    with open(path) as f:
        obj = json.load(f)
    s = obj["spec"]
    spec = {"mode": s["mode"], "entry": s.get("entry"),
            "frames": [bytes.fromhex(x) for x in s.get("frames", [])],
            "xml": bytes.fromhex(s.get("xml", "")),
            "input": bytes.fromhex(s.get("input", ""))}
    if spec["mode"] == "handler" and not spec["xml"]:
        spec["xml"] = spec["input"]
    rec = execute(spec, image, max_insn)
    print(f"replay {path}")
    print(f"  phase={obj['meta'].get('phase')} "
          f"index={obj['meta'].get('index')} "
          f"seed={obj['meta'].get('seed')}")
    print(f"  expected: {obj['meta'].get('verdict')} "
          f"pc={obj['meta'].get('pc')} fault={obj['meta'].get('fault_addr')}")
    print(f"  replay  : {rec['verdict']} pc={rec.get('fault_pc')} "
          f"fault={rec.get('fault_addr')} cb={rec.get('cb_at_blx')} "
          f"derived={bool((rec.get('derived') or {}).get('derived'))}")
    same = (rec["verdict"] == obj["meta"].get("verdict")
            and rec.get("fault_pc") == obj["meta"].get("pc")
            and rec.get("fault_addr") == obj["meta"].get("fault_addr"))
    print(f"  {'REPRODUCED' if same else 'MISMATCH'}")
    return 0 if same else 2


# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="DA1 200EX01 offline host-input fuzzing campaign")
    ap.add_argument("--image", default=os.path.join(
        _HERE, "rmx3630-da2", "da1_allinone.bin"))
    ap.add_argument("--phase", default="all",
                    choices=("all",) + PHASE_ORDER)
    ap.add_argument("--cases", type=int, default=2000,
                    help="cases per phase (default 2000)")
    ap.add_argument("--seed", type=lambda s: int(s, 0), default=0xD1A1)
    ap.add_argument("--json", default=os.path.join(
        _HERE, "da1_fuzz_results.json"))
    ap.add_argument("--save-dir",
                    default="/tmp/opencode/da1_fuzz_cases")
    ap.add_argument("--max-insn", type=int, default=10_000_000,
                    help="instruction cap per case (HANG if not returned; "
                         "deep-but-finite XML needs >2M)")
    ap.add_argument("--time-cap", type=float, default=840.0,
                    help="whole-campaign wall clock cap in seconds")
    ap.add_argument("--replay", default=None,
                    help="re-run one saved repro JSON and exit")
    ap.add_argument("--quiet-progress", action="store_true")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.image):
        ap.error(f"image not found: {args.image}")
    if args.cases < 0:
        ap.error("--cases must be >= 0")

    if args.replay:
        return replay(args.replay, args.image, args.max_insn)

    phases = list(PHASE_ORDER) if args.phase == "all" else [args.phase]
    t_start = time.time()

    print("=" * 78)
    print("DA1 200EX01 host-input fuzzing campaign (Unicorn, offline)")
    print("=" * 78)
    print(f"image      : {os.path.abspath(args.image)}")
    print(f"seed       : {args.seed:#x}   cases/phase: {args.cases}   "
          f"phases: {','.join(phases)}")
    print(f"packet_len : {PACKET_LEN:#x}   xml_max: {XML_MAX:#x}   "
          f"max_insn/case: {args.max_insn}")
    print(f"time cap   : {args.time_cap:.0f}s   "
          f"repros: {args.save_dir}")
    print("threat     : host untrusted; DA1 parses host XML + download frames")
    print("")

    # ---- validation controls (must pass before any campaign case) -------
    print("-- validation controls (classifier self-test) --")
    controls = validation_controls(args.image)
    bad = 0
    for c in controls:
        status = "PASS" if c["ok"] else "FAIL"
        print(f"  {status} {c['name']:24s} want={c['want']:22s} "
              f"got={c['got']}")
        if not c["ok"]:
            bad += 1
    if bad:
        print(f"CONTROLS FAILED ({bad}/{len(controls)}): classifier is broken, "
              f"refusing to run the campaign")
        return 1
    print(f"  all {len(controls)} controls PASS")

    t_bl = time.time()
    print("-- baselines (valid command -> expected behaviour) --")
    baselines = build_baselines(args.image, args.max_insn)
    for b in baselines:
        if b["verdict"] not in ("OK_RC", "ERR_RC"):
            print(f"  baseline {b['cmd']:24s} {b['route']:8s} "
                  f"{b['verdict']:12s} pc={b['pc'] and hex(b['pc'])} "
                  f"fault={b['fault'] and hex(b['fault'])}")
    print(f"  {len(baselines)} baseline runs ({time.time() - t_bl:.1f}s)")

    # ---- campaign -------------------------------------------------------
    print("")
    print("-- campaign --")
    slice_s = args.time_cap / max(len(phases), 1)
    all_results = []
    effective = {}
    truncated = False
    for phase in phases:
        clock = PhaseClock(slice_s)
        rows, n = run_phase(phase, args.image, args.seed, args.cases,
                            args.max_insn, clock, baselines, args.save_dir,
                            verbose=not args.quiet_progress)
        all_results.extend(rows)
        effective[phase] = n
        truncated = truncated or clock.hit
        if clock.hit:
            print(f"  [TIME-CAP] phase {phase} stopped early after {n} cases "
                  f"(requested {args.cases}); effective cases reduced")
    runtime = time.time() - t_start

    print_matrix(all_results)
    groups = dedup(all_results)
    saved = print_table(groups)
    print_interesting(saved, args.save_dir)

    # ---- stdout summary + json -----------------------------------------
    harness_errors = sum(1 for r in all_results if r["verdict"] == "HARNESS_ERROR")
    new_crash = [r for r in all_results
                 if r["verdict"] in ("DATA_ABORT", "HEAP_CORRUPT", "CB_SET")
                 and not r.get("known_heapbait")
                 and not r.get("baseline_match")]
    derived = [r for r in new_crash
               if (r.get("derived") or {}).get("derived")]
    print("")
    print("-- bottom line --")
    print(f"  cases run            : {len(all_results)} "
          f"({', '.join(f'{p}={effective.get(p, 0)}' for p in phases)})")
    print(f"  runtime              : {runtime:.1f}s"
          + ("  [CLOCK TRUNCATED]" if truncated else ""))
    print(f"  harness errors       : {harness_errors}")
    print(f"  non-baseline crash-ish classes: {len(new_crash)}")
    print(f"    of which input-derived      : {len(derived)}")
    if derived:
        for r in derived[:10]:
            print(f"    {r['phase']:8s} {r['verdict']:12s} "
                  f"entry={r.get('handler') or hex(r.get('entry') or 0)} "
                  f"pc={r['fault_pc'] and hex(r['fault_pc'])} "
                  f"fault={r['fault_addr'] and hex(r['fault_addr'])}")
    print("  controls             : "
          + ", ".join(f"{c['name'].split('-')[1]}={'PASS' if c['ok'] else 'FAIL'}"
                      for c in controls))

    payload = json_result(all_results, controls, baselines, args.seed,
                          args.cases, phases, runtime, truncated, args.image)
    try:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(payload, f, indent=1)
        print(f"  json                 : {args.json} "
              f"({os.path.getsize(args.json)} bytes)")
    except Exception as exc:
        print(f"  json write failed    : {exc}")
    print(f"  repros               : {args.save_dir} "
          f"({len(os.listdir(args.save_dir)) if os.path.isdir(args.save_dir) else 0} files)")
    print("")
    print("RESULT: PASS (campaign completed)" if harness_errors == 0
          else "RESULT: FAIL (harness errors)")
    return 0 if harness_errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
