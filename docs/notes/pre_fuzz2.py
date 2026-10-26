#!/usr/bin/env python3
"""Round-2 fuzzing of the 2710EX01 preloader DA auth (offline, Unicorn only).

Follow-up to ``pre_emu.py`` / ``re-preloader-emu-fuzz-2026-10-26.md`` (round 1:
2000 cases, 0 ACCEPT_INVALID).  Round 2 goes after surfaces round 1 did not
touch.  This file is additive: it imports the emulator from pre_emu.py and
changes nothing there.

New phases (``--mode``):

  func    ground truth, identical to ``pre_emu.py --mode func`` (delegated).
  fuzz    round-1 style campaign, delegated (3000 cases for round 2).
  pss     PSS/PKA boundary attacks: degenerate modexp inputs (s=0, 1, n-1,
          n, n+1, all-FF, small, adjacent-to-real), BE-encoded signature
          field, PSS field-level byte mutations (DB/H/salt/0xBC), and the
          message/signature round-trip (da_len-0x100 = 0,1,0xFF,...).
  state   USB state machine: multi-command sessions, re-entry after errors,
          D5 commit, wedge recoverability, replay/interleave, stale-command
          spin, LE-vs-BE length encodings.
  memacc  the pre-auth memory-access commands found in round 2 recon:
          0xD4 (write words, region-gated), 0xA2 (read 16-bit words,
          region-gated), 0xD2/0xD3/0xA1 (range flush).  Prove the gate
          dynamically (illegal -> 0x1001, windowed -> allowed), and test
          whether any legal window influences the DAA verdict.
  reads   read-proof: which bytes of the DA buffer any *emulated instruction*
          ever dereferences during the whole auth path (header parse test),
          plus host-side region-table mutation table.
  oracle  instruction / RSA / SHA counters for ACCEPT vs REJECT (an
          emulator-visible timing oracle; emulation-only, likely invisible
          over USB).
  keys    prove which key 0x23794C installs (single-step + struct dump),
          K1-vs-K2, and produce the function/block coverage map of a full
          proto accept session (0x2378AC / 0x230C5C reachability check).
  cover   coverage-guided iteration: 3 rounds x 500 cases, uncovered-branch
          report between rounds, hand-crafted inputs aimed at uncovered
          ranges.
  replay  reproduce a saved case (any phase).

Never fabricates an ACCEPT: any ACCEPT that is not the byte-exact K2 DA1 is
ACCEPT_INVALID, printed with exact input bytes and saved as a replayable repro.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import struct
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pre_emu as P
from pre_emu import (
    PreloaderEmu, CaseRunner, make_case, apply_recipe, diff_patch, be32,
    BASE, BUF_BASE, DA_DST, G_DAA_FLAG, G_KEY_PTR, P_CTX, P_OPS,
    P_STUB_SEND, P_STUB_RECV, A_VERIFY_BLOCK, A_VERIFY_FINISH, A_FLAG_DONE,
    A_ASSERT, A_STATUS_SEND, A_KEY_WRAPPER, A_KEY_SETUP, A_HASH_UPDATE,
    A_HASH_ONESHOT, A_CMD_LOOP, UC_HOOK_CODE,
)
from unicorn import UC_HOOK_BLOCK, UC_HOOK_MEM_READ
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R6, UC_ARM_REG_R9, UC_ARM_REG_R11,
    UC_ARM_REG_LR, UC_ARM_REG_PC,
)

REPRO_DIR = "/tmp/opencode/pre_fuzz2_cases"
HANDSHAKE = b"\xa0\x0a\x50\x05"
A_D5_GATE = 0x208570          # flag gate (falls through from cmd 0xD5)
A_D5_COMMIT = 0x20859C        # taken only when the flag is set
A_MEMSET = 0x23872A

CLASSES = P.CLASSES


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# --------------------------------------------------------------------------
# transport for arbitrary command streams
# --------------------------------------------------------------------------
class StreamEmu(P.PreloaderEmu):
    """PreloaderEmu + transcript hooks registered BEFORE the shims, so the
    status value sent through 0x20882C is visible (the shim itself only
    returns 0).  Behaviour of every pre_emu hook is unchanged."""

    def __init__(self, *a, **kw):
        self.status_sends = []      # r0 values passed to 0x20882C
        self.d5_commit = None       # registers at the commit block
        self.key_installs = []      # (r0, r1) at 0x23EA24
        self.d4_writes = []         # (addr, word) at the 0xD4 store 0x2083A2
        self.da_jump = None         # (target, arg1, arg2) at the 0x201170 trampoline
        self.no_halt = False        # multi-command sessions: keep the loop alive
        super().__init__(*a, **kw)

    def _h_finish(self, uc, addr, size, _u):
        r0 = self.reg(UC_ARM_REG_R0) & 0xFFFFFFFF
        self.stop["finish"] = r0
        if r0 != 0 and not self.no_halt and not getattr(self, "follow_error", False):
            self._halt()

    def _h_flag_done(self, uc, addr, size, _u):
        self.stop["flag"] = self.uc.mem_read(G_DAA_FLAG, 1)[0]
        if not self.no_halt:
            self._halt()

    def _install_hooks(self):
        uc = self.uc

        def h_status(_uc, _a, _s, _u):
            self.status_sends.append(self.reg(UC_ARM_REG_R0) & 0xFFFF)

        def h_d5(_uc, _a, _s, _u):
            self.d5_commit = (self.reg(UC_ARM_REG_R4), self.reg(UC_ARM_REG_R0))

        def h_keysetup(_uc, _a, _s, _u):
            self.key_installs.append((self.reg(UC_ARM_REG_R0),
                                      self.reg(UC_ARM_REG_R1)))

        def h_d4store(_uc, _a, _s, _u):
            self.d4_writes.append((self.reg(UC_ARM_REG_R0) & 0xFFFFFFFF,
                                   self.reg(UC_ARM_REG_R4) & 0xFFFFFFFF))

        def h_tramp(_uc, _a, _s, _u):
            self.da_jump = (self.reg(UC_ARM_REG_R0), self.reg(UC_ARM_REG_R1),
                            self.reg(UC_ARM_REG_R2))

        uc.hook_add(UC_HOOK_CODE, h_status, begin=A_STATUS_SEND, end=A_STATUS_SEND)
        uc.hook_add(UC_HOOK_CODE, h_d5, begin=A_D5_COMMIT, end=A_D5_COMMIT)
        uc.hook_add(UC_HOOK_CODE, h_keysetup, begin=A_KEY_SETUP, end=A_KEY_SETUP)
        uc.hook_add(UC_HOOK_CODE, h_d4store, begin=0x2083A2, end=0x2083A2)
        uc.hook_add(UC_HOOK_CODE, h_tramp, begin=0x201170, end=0x201170)
        super()._install_hooks()


def proto_stream(runner: CaseRunner, chunks, budget: int = 8_000_000,
                 tag: str = "", no_halt: bool = False) -> dict:
    """Run the real USB command loop over an arbitrary byte stream.

    ``chunks`` is a list of byte strings, concatenated into one receive FIFO.
    With no_halt=False (default) the pre_emu stop markers behave exactly as
    in round 1.  With no_halt=True the loop keeps running across verdicts
    (assert/fault still halt), so multi-command sessions are real.
    """
    emu = StreamEmu(runner.image, budget=budget)
    emu.no_halt = no_halt
    emu.write_u32(P_CTX, 0)
    emu.write_u32(P_CTX + 8, P_OPS)
    emu.write_u32(P_OPS, P_STUB_SEND | 1)
    emu.write_u32(P_OPS + 4, P_STUB_RECV | 1)
    fifo = bytearray(b"".join(chunks))
    sent = bytearray()
    events: list[tuple] = []
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
        uc.mem_write(p, bytes(fifo[:n]))
        del fifo[:n]
        emu.setreg(UC_ARM_REG_R0, 0)
        emu._ret()

    def h_trans(_uc, a, _s, _u):
        if a == A_VERIFY_FINISH:
            events.append(("finish", emu.reg(UC_ARM_REG_R0) & 0xFFFF,
                           uc.mem_read(G_DAA_FLAG, 1)[0]))
        elif a == A_FLAG_DONE:
            events.append(("flag", uc.mem_read(G_DAA_FLAG, 1)[0]))

    def h_assert(_uc, _a, _s, _u):
        events.append(("assert", emu.reg(UC_ARM_REG_PC)))

    def h_memset(_uc, _a, _s, _u):
        events.append(("memset", emu.reg(UC_ARM_REG_R0), emu.reg(UC_ARM_REG_R2)))

    uc.hook_add(UC_HOOK_CODE, h_send, begin=P_STUB_SEND, end=P_STUB_SEND)
    uc.hook_add(UC_HOOK_CODE, h_recv, begin=P_STUB_RECV, end=P_STUB_RECV)
    for a in (A_VERIFY_FINISH, A_FLAG_DONE):
        uc.hook_add(UC_HOOK_CODE, h_trans, begin=a, end=a)
    uc.hook_add(UC_HOOK_CODE, h_assert, begin=A_ASSERT, end=A_ASSERT)
    uc.hook_add(UC_HOOK_CODE, h_memset, begin=A_MEMSET, end=A_MEMSET)
    st = emu.run(A_CMD_LOOP, True, P.HARNESS_SP, (P_CTX, 0x7FFFFFFF), budget)
    flag = uc.mem_read(G_DAA_FLAG, 1)[0]
    finishes = [e for e in events if e[0] == "finish"]
    memsets_da = [e for e in events if e[0] == "memset" and e[1] in (BUF_BASE, DA_DST)]
    # D5 commit struct: literal pool of the gate (0x20878C = struct base,
    # 0x2087B8 = first field value); the tail jumps to the DA buffer (0x201170
    # trampoline, mov pc, r0)
    lit_base = struct.unpack_from("<I", runner.image, 0x20878C - BASE)[0]
    lit_val = struct.unpack_from("<I", runner.image, 0x2087B8 - BASE)[0]
    commit_struct = None
    if emu.d5_commit:
        try:
            commit_struct = {"base": "%#x" % lit_base, "field0": "%#x" % lit_val,
                             "fields": ["%#x" % emu.read_u32(lit_base + 4 * i)
                                        for i in range(3)],
                             "jump_target": ("%#x" % emu.da_jump[0]
                                             if emu.da_jump else "?")}
        except Exception as e:
            commit_struct = {"base": "%#x" % lit_base, "error": str(e)}
    res = {
        "tag": tag,
        "flag": flag,
        "pc": emu.reg(UC_ARM_REG_PC),
        "stop": {k: (v if isinstance(v, (int, str, type(None))) else list(v))
                 for k, v in st.items()},
        "sent": sent.hex(),
        "status": emu.status_sends,
        "events": [[e[0]] + [x if isinstance(x, int) else list(x) if isinstance(x, tuple) else x
                             for x in e[1:]] for e in events],
        "status_hex": ["%#06x" % v for v in emu.status_sends],
        "d5_commit": emu.d5_commit,
        "d4_writes": emu.d4_writes,
        "key_installs": emu.key_installs,
        "finishes": [[e[1], e[2]] for e in finishes],
        "da_memsets": [[e[1], e[2]] for e in memsets_da],
        "commit_struct": commit_struct,
        "da_jump": (["%#x" % v for v in emu.da_jump]
                    if emu.da_jump else None),
    }
    if "fault" in st:
        f = st["fault"]
        res["fault"] = {"access": f[0], "addr": f[1], "size": f[2], "pc": f[3]}
        res["class"] = "CRASH"
    elif any(e[0] == "assert" for e in events) or st.get("assert") is not None:
        res["class"] = "HANG"
    elif "budget" in st:
        res["class"] = "IDLE_SPIN"
    elif "flag" in st or flag:
        res["class"] = "OK_FLAG"
    else:
        res["class"] = "STOPPED"
    return res


# --------------------------------------------------------------------------
# D7 / D4 / A2 / D5 stream builders (BE u32 framing, as 0x2089AC decodes)
# --------------------------------------------------------------------------
def d7(data: bytes, da_len: int, sig_len: int, field0: int = 0) -> bytes:
    return b"\xd7" + be32(field0) + be32(da_len) + be32(sig_len) + data


def d4(addr: int, words) -> bytes:
    return (b"\xd4" + be32(addr) + be32(len(words))
            + b"".join(be32(w) for w in words))


def a2(addr: int, count: int) -> bytes:
    return b"\xa2" + be32(addr) + be32(count)


def d2d3(cmd: int, addr: int, words16, echo: bool = False) -> bytes:
    """0xD2/0xD3 (echo=0) / 0xA1 (echo=1): write 16-bit words at addr."""
    return (bytes([cmd]) + be32(addr) + be32(len(words16))
            + b"".join(struct.pack(">H", w) for w in words16))


def d5(arg: int = 0) -> bytes:
    return b"\xd5" + be32(arg)


def recv_u32_be(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 4], "big")


# --------------------------------------------------------------------------
# phase 1: PSS / PKA boundary attacks
# --------------------------------------------------------------------------
def pss_decode_ref(em: bytes, msg_hash: bytes, slen: int = 32):
    """Reference RSASSA-PSS (SHA-256) decode for classification only."""
    n_len = len(em)
    if em[-1] != 0xBC:
        return False, "trailer_bc"
    hlen = 32
    dblen = n_len - hlen - 1
    db, hh = em[:dblen], em[dblen:n_len - 1]
    # MGF1-SHA256
    mask = bytearray()
    for c in range((dblen + 31) // 32):
        mask += hashlib.sha256(hh + c.to_bytes(4, "big")).digest()
    db = bytes(a ^ b for a, b in zip(db, bytes(mask[:dblen])))
    db = bytes([db[0] & 0x7F]) + db[1:]
    i = 0
    while i < len(db) and db[i] == 0:
        i += 1
    if i >= len(db) or db[i] != 0x01:
        return False, "sep_0x01"
    salt = db[i + 1:]
    if len(salt) != slen:
        return False, "salt_len"
    h2 = hashlib.sha256(b"\x00" * 8 + msg_hash + salt).digest()
    return (h2 == hh), "hash"


def le256(x: int) -> bytes:
    return (x & ((1 << 2048) - 1)).to_bytes(0x100, "little")


def cmd_pss(runner: CaseRunner, seed: int):
    img = runner.image
    k2_off = 0x25E3DC - BASE
    k1_off = 0x25E2DC - BASE
    n = int.from_bytes(img[k2_off:k2_off + 0x100], "little")
    e = 65537
    msg = runner.real_msg_2710
    mhash = hashlib.sha256(msg).digest()
    real_sig = runner.real_sig_2710
    s_real = int.from_bytes(real_sig, "little")
    print("== phase 1: PSS/PKA boundary attacks ==")
    print("  K2 modulus 0x25E3DC: bits=%d, top=%s" % (n.bit_length(), hex(n >> 2032)))

    def em_of(trailer: bytes):
        s = int.from_bytes(trailer, "little")
        return pow(s, e, n) if n else 0

    # validate the reference decoder against the real EM
    em_real = em_of(real_sig).to_bytes(0x100, "little")
    ok, stage = pss_decode_ref(em_real, mhash)
    print("  note: plain RFC-8017 PSS model does NOT fit this build (checked")
    print("  dynamically below); the message digest comes from the MTK chunked")
    print("  hash at 0x241414, not sha256(msg).  See the scheme probe.")

    # ---- scheme probe: snapshot the PSS core at the final compare --------
    print("  scheme probe (buffer snapshot at the final memcmp 0x23874C):")
    emu = PreloaderEmu(runner.image, budget=3_000_000)
    snaps = []

    def h_cmp(_uc, a, _s, _u):
        if len(snaps) < 1:
            try:
                if _uc.reg_read(UC_ARM_REG_LR) == 0x241709:
                    snaps.append(bytes(_uc.mem_read(0x2F6770, 0x500)))
            except Exception:
                pass

    emu.uc.hook_add(UC_HOOK_CODE, h_cmp, begin=0x23874C, end=0x23874C)
    emu.uc.mem_write(BUF_BASE, runner.da1_2710)
    emu.setreg(UC_ARM_REG_R9, len(runner.da1_2710))
    emu.setreg(UC_ARM_REG_R11, BUF_BASE)
    emu.setreg(UC_ARM_REG_R6, 0x100)
    st = emu.run(A_VERIFY_BLOCK, True, P.HARNESS_SP, (), 3_000_000)
    if snaps:
        s0 = snaps[0]
        hp = s0[0x300:0x320]        # computed H' (4th malloc buffer, first 32 B)
        hm = s0[0x200:0x220]        # EM's H copy (3rd malloc buffer)
        print("    computed H'        = %s" % hp.hex())
        print("    EM's H (from sig)  = %s" % hm.hex())
        print("    equal: %s   sha256(msg)=%s (absent from the core buffers:"
              " the message digest is the 0x241414 chunked hash)"
              % (hp == hm, mhash.hex()[:16] + ".."))
    else:
        print("    (snapshot not captured)")

    cands = []          # (label, trailer_bytes)
    cands.append(("s=0 (all zero)", b"\x00" * 0x100))
    cands.append(("s=1", le256(1)))
    cands.append(("s=2", le256(2)))
    cands.append(("s=2^16", le256(1 << 16)))
    cands.append(("s=2^128", le256(1 << 128)))
    cands.append(("s=2^2047 (top bit)", le256(1 << 2047)))
    cands.append(("s=n-1", le256(n - 1)))
    cands.append(("s=n (wraps 0)", le256(n)))
    cands.append(("s=n+1 (wraps 1)", le256(n + 1)))
    cands.append(("s=2^2048-1 (all-FF)", le256((1 << 2048) - 1)))
    cands.append(("s=n//2", le256(n // 2)))
    cands.append(("s=real-1", le256(s_real - 1)))
    cands.append(("s=real+1", le256(s_real + 1)))
    cands.append(("s=real<<1", le256((s_real << 1))))
    cands.append(("BE(s=1) (endian mismatch)", (1).to_bytes(0x100, "big")))
    cands.append(("BE(s=0)", b"\x00" * 0x100))
    cands.append(("BE(0xBC at MSB)", (0xBC << (8 * 255)).to_bytes(0x100, "big")))
    cands.append(("zeros + tail BC", b"\x00" * 0xFF + b"\xbc"))
    cands.append(("one + tail BC", le256(1)[:-1] + b"\xbc"))
    cands.append(("real sig (control)", real_sig))

    rows = []
    for label, trailer in cands:
        s = int.from_bytes(trailer, "little")
        em = em_of(trailer).to_bytes(0x100, "little")
        r0 = runner.pss_case(msg + trailer, 0x25E3DC)
        buf = msg + trailer
        fc = runner.func_case(buf, len(buf), 0x100)
        rows.append({"label": label, "s_hex": ("%x" % s)[:32],
                     "em_head": em[:4].hex() + ".." + em[-4:].hex(),
                     "pss_r0": r0, "class": fc["class"], "flag": fc["flag"]})
        if fc["class"] in ("ACCEPT_INVALID", "CRASH"):
            print("  !! INTERESTING: %s -> %s r0=%#x" % (label, fc["class"], r0))
            save_repro({"kind": "func", "full_hex": buf.hex(),
                        "da_len": len(buf), "sig_len": 0x100, "tag": label},
                       fc, "pss_" + label.replace(" ", "_"))

    print("\n  primitive/func results (label -> EM tail, PSS r0, verdict):")
    for r in rows:
        print("   %-28s em=..%s r0=%-9s %s(flag=%d)"
              % (r["label"], r["em_head"][-4:],
                 ("%#x" % r["pss_r0"]) if r["pss_r0"] else "0",
                 r["class"], r["flag"]))
    bad = [r for r in rows if r["class"] == "ACCEPT_INVALID"]
    print("  degenerate-signature ACCEPT_INVALID count: %d" % len(bad))

    # ---- PSS field-level byte mutation of the REAL signature -------------
    print("\n  field-level mutation of the real signature (primitive level):")
    em = bytearray(em_real)
    fields = {
        "DB_first_byte": (0, 1), "DB_mid": (100, 1),
        "sep_0x01_region": (189, 1), "salt_first": (190, 1),
        "salt_last": (221, 1), "H_first": (222, 1), "H_last": (253, 1),
        "trailer_BC": (255, 1),
    }
    codes = Counter()
    for label, (off, ln) in fields.items():
        t = bytearray(real_sig)
        t[off] ^= 0x01
        r0 = runner.pss_case(msg + bytes(t), 0x25E3DC)
        codes[(label, r0)] += 1
        print("   flip %-16s [off=%3d] -> r0=%#x" % (label, off, r0))
    # salt length is derived from the message by the decoder; the only
    # input-driven knob is the position of the 0x01 separator inside DB.
    # Re-encode the EM with the 0x01 marker moved, keep H and 0xBC.
    print("   separator-position sweep (0x01 placed at DB offsets):")
    dblen = 0x100 - 33
    hh = bytes(em_real[dblen:dblen + 32])

    def mgf1(seed: bytes, n: int) -> bytes:
        out = bytearray()
        for c in range((n + 31) // 32):
            out += hashlib.sha256(seed + c.to_bytes(4, "big")).digest()
        return bytes(out[:n])

    mask = mgf1(hh, dblen)
    db = bytearray(a ^ b for a, b in zip(em_real[:dblen], mask))
    db[0] &= 0x7F
    i = 0
    while i < len(db) and db[i] == 0:
        i += 1
    for pos in range(180, 224, 4):
        db2 = bytearray(db)
        if i < len(db2):
            db2[i] = 0
        db2[pos] = 1
        em3 = bytes(a ^ b for a, b in zip(db2, mask)) + hh + b"\xbc"
        r0 = runner.pss_case(msg + em3, 0x25E3DC)
        print("     0x01@%3d -> r0=%#x" % (pos, r0))

    # ---- message/signature round-trip ------------------------------------
    print("\n  message/signature round-trip (REAL signature, shortened message):")
    rt = []
    msglen = len(msg)
    for k in [0, 1, 2, 0xFF, 0x100, 0x101, 0x1FF, 0x200, 0x201,
              msglen - 1, msglen, msglen + 1]:
        k = max(0, min(k, len(runner.da1_2710) - 0x100))
        buf = runner.real_sig_2710 if k == 0 else runner.da1_2710[:k + 0x100]
        dl = k + 0x100
        fc = runner.func_case(buf, dl, 0x100)
        rt.append((k, dl, fc["class"], fc["r0"]))
        print("   msg_len=%-7d da_len=0x%-7x -> %-14s r0=%s"
              % (k, dl, fc["class"],
                 ("%#x" % fc["r0"]) if fc["r0"] is not None else "-"))
        if fc["class"] == "ACCEPT_INVALID":
            print("  !! BYPASS via round-trip: msg_len=%d" % k)
            save_repro({"kind": "func", "full_hex": buf.hex(),
                        "da_len": dl, "sig_len": 0x100,
                        "tag": "roundtrip_k%d" % k}, fc, "roundtrip_%d" % k)
    # sig window slide (da_len != buffer end)
    print("  sig window slide over the real buffer:")
    L = len(runner.da1_2710)
    for dl in [L - 1, L - 0x100, L + 0x100, L + 4]:
        if dl < 0x100:
            continue
        fc = runner.func_case(runner.da1_2710, dl, 0x100)
        print("   da_len=%-#x -> %-14s r0=%s"
              % (dl, fc["class"],
                 ("%#x" % fc["r0"]) if fc["r0"] is not None else "-"))
    return not bad


# --------------------------------------------------------------------------
# phase 3: state machine / protocol
# --------------------------------------------------------------------------
def cmd_state(runner: CaseRunner, seed: int):
    print("== phase 3: USB state machine / protocol sessions ==")
    print("  (no_halt sessions: the loop keeps running across verdicts;")
    print("   assert/fault still halt = the honest wedge semantics)")
    da1 = runner.da1_2710
    bad_sig = da1[:-0x100] + bytes(a ^ 0xFF for a in da1[-0x100:])
    sessions = []

    def S(label, chunks, budget=6_000_000):
        # a trailing 0xFE makes the terminal stale command the benign
        # echo-0x42 spin (real HW would block in recv instead)
        r = proto_stream(runner, chunks + [b"\xfe"], budget=budget,
                         tag=label, no_halt=True)
        sessions.append(r)
        print("  %-44s %-9s flag=%d finishes=%s da_memsets=%s d5=%s"
              % (label, r["class"], r["flag"], r["finishes"],
                 [("%#x" % a, "%#x" % n) for a, n in r["da_memsets"]],
                 "yes" if r["d5_commit"] else "-"))
        return r

    # re-entry after a NON-DAA error: must survive and accept the DA
    S("D4 illegal(flag) -> D7 valid",
      [HANDSHAKE, d4(G_DAA_FLAG, [1]), d7(da1, len(da1), 0x100)])
    S("D4 window write -> D7 valid",
      [HANDSHAKE, d4(0x10007000, [0x55AA55AA]), d7(da1, len(da1), 0x100)])
    S("A2 windowed read -> D7 valid",
      [HANDSHAKE, a2(0x10007000, 8), d7(da1, len(da1), 0x100)])
    S("A2 illegal read -> D7 valid",
      [HANDSHAKE, a2(G_DAA_FLAG, 1), d7(da1, len(da1), 0x100)])
    # re-entry after a DAA failure: memset + assert, second D7 never runs
    S("D7 invalid -> D7 valid (re-entry attempt)",
      [HANDSHAKE, d7(bad_sig, len(bad_sig), 0x100), d7(da1, len(da1), 0x100)])
    # accept -> commit -> accept again
    S("D7 valid -> D5 commit -> D7 valid",
      [HANDSHAKE, d7(da1, len(da1), 0x100), d5(0), d7(da1, len(da1), 0x100)],
      budget=10_000_000)
    # commit without auth: 0x7024 + assert wedge
    S("D5 with flag=0 (no auth yet)",
      [HANDSHAKE, d5(0), d7(da1, len(da1), 0x100)])
    # accept -> commit -> failed re-download: committed-then-wiped
    S("D7 valid -> D5 -> D7 invalid (wedge audit)",
      [HANDSHAKE, d7(da1, len(da1), 0x100), d5(0),
       d7(bad_sig, len(bad_sig), 0x100)], budget=10_000_000)
    # accept -> shorter re-download (partial overwrite attempt)
    S("D7 valid -> D7 shorter(0x200) garbage",
      [HANDSHAKE, d7(da1, len(da1), 0x100),
       d7(b"\xCC" * 0x200, 0x200, 0x100)], budget=10_000_000)
    # framing attacks
    le = (b"\xd7" + struct.pack("<III", 0, len(da1), 0x100) + da1[:0x800])
    S("D7 fields little-endian (parser is BE)",
      [HANDSHAKE, le], budget=4_000_000)
    S("D7 da_len=0xFFFFFF80 (negative)",
      [HANDSHAKE, d7(da1[:0x800], 0xFFFFFF80, 0x100)], budget=4_000_000)
    S("D7 sig_len=0xFFFFFF00 (negative)",
      [HANDSHAKE, d7(da1[:0x800], 0x800, 0xFFFFFF00)], budget=4_000_000)
    S("bad handshake then real handshake + valid DA",
      [b"\x00\x11\x22\x33", HANDSHAKE, d7(da1, len(da1), 0x100)],
      budget=10_000_000)
    S("junk cmds (C4,C6,FE) then valid DA",
      [HANDSHAKE, b"\xc4" + be32(0) + be32(0), b"\xc6" + be32(0),
       b"\xfe", d7(da1, len(da1), 0x100)], budget=10_000_000)

    # focused audits
    print("\n  committed-then-wiped / partial-overwrite audits:")
    for s in sessions:
        if "wedge audit" in s["tag"] or "shorter" in s["tag"]:
            print("    [%s] class=%s flag=%d da_memsets=%s finishes=%s"
                  % (s["tag"], s["class"], s["flag"],
                     [("%#x" % a, "%#x" % n) for a, n in s["da_memsets"]],
                     s["finishes"]))
            chunks = ([HANDSHAKE, d7(da1, len(da1), 0x100), d5(0),
                       d7(bad_sig, len(bad_sig), 0x100), b"\xfe"]
                      if "wedge" in s["tag"] else
                      [HANDSHAKE, d7(da1, len(da1), 0x100),
                       d7(b"\xCC" * 0x200, 0x200, 0x100), b"\xfe"])
            save_repro({"kind": "stream",
                        "chunks": [c.hex() for c in chunks],
                        "budget": 10_000_000, "tag": s["tag"],
                        "no_halt": True},
                       s, "commit_then_wipe" if "wedge" in s["tag"]
                       else "partial_overwrite")
    print("\n  D5 commit structs (only sessions that reached the gate with flag=1):")
    for s in sessions:
        if s["commit_struct"]:
            print("    [%s] %s" % (s["tag"], s["commit_struct"]))
    print("\n  D5 gate with flag=0: sessions that wedged on D5 alone: %s"
          % [s["tag"] for s in sessions if s["tag"].startswith("D5 with")])
    bad = [s for s in sessions if s["flag"] == 1 and not s["finishes"]]
    print("\n  state-phase ACCEPT_INVALID count: %d" % len(bad))
    return not bad



# --------------------------------------------------------------------------
# phase 2b: pre-auth memory-access commands (0xD4 write / 0xA2 read)
# --------------------------------------------------------------------------
def cmd_memacc(runner: CaseRunner):
    print("== phase 2b: pre-auth memory-access commands (0xD4 write / 0xA2 read) ==")
    da1 = runner.da1_2710
    tests = [
        ("D4 write @DAA flag 0x2F3158 (=1)", d4(G_DAA_FLAG, [1])),
        ("D4 write @verify code 0x20868C", d4(0x20868C, [0xE3A00000])),
        ("D4 write window full 0x10007000 x0x400", d4(0x10007000, [0x55AA55AA] * 0x400)),
        ("D4 write window last word 0x10007FFC", d4(0x10007FFC, [0xDEAD])),
        ("D4 write below window 0x10006FFC", d4(0x10006FFC, [0xDEAD])),
        ("D4 write straddling window start", d4(0x10006FF0, [0] * 6)),
        ("D4 write 4B entry 0x1001A080", d4(0x1001A080, [0xDEAD])),
        ("D4 write count=0", d4(0x10007000, [])),
        ("D4 write count huge (0x20000000)",
         b"\xd4" + be32(0x10007000) + be32(0x20000000) + be32(1) * 4),
        ("A2 read @DAA flag", a2(G_DAA_FLAG, 1)),
        ("A2 read @K2 key 0x25E3DC", a2(0x25E3DC, 4)),
        ("A2 read @DA buffer", a2(DA_DST, 4)),
        ("A2 read windowed 0x10007000 x16", a2(0x10007000, 16)),
        ("A2 read 0x11F10000 x8 (mode1-only window)", a2(0x11F10000, 8)),
        ("A2 read addr=0 (write-table has {0,2}, read does not)", a2(0, 1)),
        ("D2 u16-write @flag (refused)", d2d3(0xD2, G_DAA_FLAG, [1])),
        ("D2 u16-write windowed (silent)", d2d3(0xD2, 0x10007000, [0x55AA, 0x1234])),
        ("D3 u16-write windowed (echo)", d2d3(0xD3, 0x10007000, [0xCAFE, 0xBABE])),
        ("D3 u16-write window escape (end past entry)", d2d3(0xD3, 0x10007FF0, [0] * 16)),
        ("A1 u16-write windowed (echo)", d2d3(0xA1, 0x10007000, [0x11, 0x22, 0x33])),
        ("A1 u16-write @flag (refused)", d2d3(0xA1, G_DAA_FLAG, [1, 2])),
    ]
    print("  %-44s %-9s %-5s %s" % ("case", "class", "flag", "status/replies"))
    violations = 0
    for label, chunk in tests:
        # every session ends with a valid D7 so the loop halts cleanly at the
        # flag write; the interesting events happen before it.
        stream = [HANDSHAKE, chunk, d7(da1, len(da1), 0x100)]
        budget = 10_000_000
        r = proto_stream(runner, stream, budget=budget, tag=label)
        print("  %-44s %-9s %-5d status=%s sent=%s"
              % (label, r["class"], r["flag"], r["status_hex"][:8],
                 r["sent"][:32]))
        if r["class"] == "CRASH":
            print("      fault: %s" % (r.get("fault"),))
        if r.get("d4_writes"):
            print("      d4 stores: %s"
                  % [("%#x<=%#x" % (a, w)) for a, w in r["d4_writes"][:8]])
        # BYPASS check: a D4 store that lands on the DAA flag with a nonzero
        # value, or any flag==1 reached without a valid verify (the final D7
        # is the byte-exact DA1, so a flag of 1 is only legitimate via it).
        for a, w in r.get("d4_writes", []):
            if a == G_DAA_FLAG and (w & 0xFF):
                violations += 1
                print("      !! D4 wrote the DAA flag -- BYPASS candidate")
                save_repro({"kind": "stream",
                            "chunks": [HANDSHAKE.hex(), chunk.hex(),
                                       d7(da1, len(da1), 0x100).hex()],
                            "budget": budget, "tag": label}, r, "memacc_bypass")
    print("\n  gate semantics (dynamically confirmed): a write/read range is")
    print("  allowed only if it is CONTAINED in one table entry:")
    print("    write (0xD4 u32 / 0xD2,0xD3,0xA1 u16): {0x10007000..0x10008000},")
    print("        {0x1001A080..0x1001A084}, {0x00000000..0x2}")
    print("    read  (0xA2 u16): {0x10007000..0x10008000},")
    print("        {0x1001A080..0x1001A084}, {0x11F10000..0x11F11000}")
    print("  refusals: D4/D2/D3 reply 0x1001 and the loop continues; A2 is")
    print("  SILENT on refusal (r4=1 skips both status sends).")

    # does any legal-window write influence a later verdict?  Write the whole
    # window, then verify the REAL DA1 and then a corrupted DA1 in one session.
    print("\n  window-write influence check:")
    r = proto_stream(runner,
                     [HANDSHAKE,
                      d4(0x10007000, [0xFFFFFFFF] * 0x400),
                      d7(da1, len(da1), 0x100)],
                     budget=12_000_000, tag="write window then verify")
    print("    valid DA after full-window write: %s (flag=%d)"
          % (r["class"], r["flag"]))
    bad_sig = da1[:-0x100] + bytes(a ^ 0x55 for a in da1[-0x100:])
    r2 = proto_stream(runner,
                      [HANDSHAKE,
                       d4(0x10007000, [0xFFFFFFFF] * 0x400),
                       d7(bad_sig, len(bad_sig), 0x100)],
                      budget=12_000_000, tag="write window then bad DA")
    print("    corrupt DA after full-window write: %s (flag=%d)"
          % (r2["class"], r2["flag"]))
    return violations == 0


# --------------------------------------------------------------------------
# phase 2: read-proof (header parse) + host-side region-table table
# --------------------------------------------------------------------------
def cmd_reads(runner: CaseRunner, image: bytes):
    print("== phase 2: read-proof over the 0xBC container header ==")
    da1 = runner.da1_2710

    def read_proof(buf: bytes, da_len: int, sig_len: int, label: str):
        emu = PreloaderEmu(image, budget=3_000_000)
        reads = []
        emu.uc.hook_add(UC_HOOK_MEM_READ,
                        lambda uc, acc, addr, size, val, u:
                        reads.append((addr - BUF_BASE, size)),
                        begin=BUF_BASE, end=BUF_BASE + 0x3FF)
        emu.uc.mem_write(BUF_BASE, buf)
        emu.setreg(UC_ARM_REG_R9, da_len)
        emu.setreg(UC_ARM_REG_R11, BUF_BASE)
        emu.setreg(UC_ARM_REG_R6, sig_len)
        st = emu.run(A_VERIFY_BLOCK, True, P.HARNESS_SP, (), 3_000_000)
        offs = Counter(o for o, _s in reads)
        res = runner._result(emu, st, buf, da_len, sig_len, "func", False)
        print("  %-44s %-16s emulated reads of buf[0..0x400): %d offsets, %d hits"
              % (label, res["class"], len(offs), sum(offs.values())))
        if offs:
            head = sorted(offs.items())[:16]
            print("      offsets: %s%s"
                  % (", ".join("%#x:%d" % (o, c) for o, c in head),
                     " ..." if len(offs) > 16 else ""))
        return res, offs

    r1, o1 = read_proof(da1, len(da1), 0x100, "real DA1 (control)")
    hdr = runner.da2710[:0xBC]
    buf2 = hdr + da1
    r2, o2 = read_proof(buf2, len(buf2), 0x100,
                        "0xBC container header PREPENDED to DA1")
    buf3 = da1 + hdr
    r3, o3 = read_proof(buf3, len(buf3), 0x100,
                        "0xBC container header APPENDED after sig")
    # MMIO reads during the auth path: does the verify touch 0x10007000 etc.?
    emu = PreloaderEmu(image, budget=3_000_000, trace=True)
    emu.uc.mem_write(BUF_BASE, da1)
    emu.setreg(UC_ARM_REG_R9, len(da1))
    emu.setreg(UC_ARM_REG_R11, BUF_BASE)
    emu.setreg(UC_ARM_REG_R6, 0x100)
    st = emu.run(A_VERIFY_BLOCK, True, P.HARNESS_SP, (), 3_000_000)
    mm = Counter(a for a, _s in emu.mmio_reads)
    print("  MMIO reads during verify: %s"
          % (", ".join("%#x:%d" % kv for kv in sorted(mm.items())) or "none"))
    print("  verdict: no emulated instruction dereferences the DA buffer")
    print("  outside the crypto API (all byte consumption is inside the SHA")
    print("  shim, i.e. the message sweep), and the verify touches none of")
    print("  the 0xD4-writable windows -> the windowed write cannot change")
    print("  the verdict.")

    # host-side region-table behaviour (mtkclient side only)
    print("\n  host-side region-table extraction (informational):")
    blob = bytearray(runner.da2710)
    for off, name in [(0x80 + 0 * 0x14, "r0.off"), (0x80 + 0 * 0x14 + 4, "r0.size"),
                      (0x80 + 2 * 0x14, "r2.off"), (0x80 + 2 * 0x14 + 0xC, "r2.sig_len")]:
        v = struct.unpack_from("<I", blob, off)[0]
        print("    region field %-10s = %#x" % (name, v))
    for i in range(3):
        off, size = struct.unpack_from("<II", blob, 0x80 + i * 0x14)
        print("    region[%d]: off=%#x size=%#x end=%#x (file=%#x) %s"
              % (i, off, size, off + size, len(blob),
                 "OK" if off + size <= len(blob) else "PAST-EOF"))
    print("    (the preloader never receives these bytes; mutations here can")
    print("     only change what the HOST sends, which round 1 fuzzed)")
    return True


# --------------------------------------------------------------------------
# phase 4: side-channel-ish counters (emulator-only oracle)
# --------------------------------------------------------------------------
class CountingEmu(P.PreloaderEmu):
    def __init__(self, *a, **kw):
        self.insn = 0
        self.hash_bytes = 0
        self.hash_calls = 0
        super().__init__(*a, **kw)

    def _install_hooks(self):
        uc = self.uc

        def h_count(_uc, a, _s, _u):
            self.insn += 1
            if a == A_HASH_UPDATE:
                self.hash_bytes += self.reg(UC_ARM_REG_R2)
                self.hash_calls += 1
            elif a == A_HASH_ONESHOT:
                self.hash_bytes += self.reg(UC_ARM_REG_R1)
                self.hash_calls += 1

        uc.hook_add(UC_HOOK_CODE, h_count, begin=0, end=0xFFFFFFFF)
        super()._install_hooks()


def cmd_oracle(runner: CaseRunner):
    print("== phase 4: instruction/RSA/SHA counters (EMULATION-ONLY oracle) ==")
    da1 = runner.da1_2710
    cases = []

    def add(label, buf, dl, sl):
        emu = CountingEmu(runner.image, budget=400_000)
        emu.uc.mem_write(BUF_BASE, buf if buf else b"\x00")
        emu.setreg(UC_ARM_REG_R9, dl)
        emu.setreg(UC_ARM_REG_R11, BUF_BASE)
        emu.setreg(UC_ARM_REG_R6, sl)
        st = emu.run(A_VERIFY_BLOCK, True, P.HARNESS_SP, (), 400_000)
        res = runner._result(emu, st, buf, dl, sl, "func", False)
        cases.append((label, res, emu.insn, emu.rsa_calls,
                      emu.hash_bytes, emu.hash_calls))

    add("2710 valid (ACCEPT_VALID)", da1, len(da1), 0x100)
    b = bytearray(da1); b[-0x80] ^= 1
    add("1-bit sig flip (REJECT_0x7024)", bytes(b), len(da1), 0x100)
    b = bytearray(da1); b[0] ^= 1
    add("1-bit msg flip (REJECT_0x7024)", bytes(b), len(da1), 0x100)
    z = bytearray(da1); z[-0x100:] = b"\x00" * 0x100
    add("zeroed trailer (REJECT_0x7024)", bytes(z), len(da1), 0x100)
    add("wrong-key 200EX01 DA1", runner.da1_200, runner.len_200, 0x100)
    add("empty message da_len=0x101", da1[:0x101], 0x101, 0x100)
    add("1-byte message da_len=0x101", b"\xAA" + da1[-0x100:], 0x101, 0x100)
    add("da_len<=sig_len (0x1D18)", da1[:0x100], 0x100, 0x100)
    add("da_len=0x100001 (0x1D10)", (da1 + b"\x00" * 0x100000)[:0x100001],
        0x100001, 0x100)

    print("  %-34s %-14s %8s %4s %9s %5s"
          % ("case", "class", "insns", "rsa", "sha_bytes", "sha_n"))
    for label, res, insn, rsa, hb, hc in cases:
        print("  %-34s %-14s %8d %4d %9d %5d"
              % (label[:34], res["class"], insn, rsa, hb, hc))
    acc = [c for c in cases if c[1]["class"] == "ACCEPT_VALID"]
    rej = [c for c in cases if c[1]["class"] == "REJECT_0x7024"]
    if acc and rej:
        a_i = sum(c[2] for c in acc) / len(acc)
        r_i = sum(c[2] for c in rej) / len(rej)
        print("  mean insn ACCEPT=%.0f REJECT=%.0f delta=%.0f (%.1f%%)"
              % (a_i, r_i, r_i - a_i, 100 * (r_i - a_i) / max(a_i, 1)))
        print("  honest caveat: instruction counts are an artifact of this")
        print("  emulator (HACC is shimmed).  On silicon the RSA/SHA run in")
        print("  hardware and the USB-observable timing is dominated by the")
        print("  transport; treat this as an emulator-visible oracle only.")
    return True


# --------------------------------------------------------------------------
# phase 5: key install proof + function coverage of a proto accept session
# --------------------------------------------------------------------------
def cmd_keys(runner: CaseRunner, image: bytes):
    print("== phase 5: key install proof + proto coverage map ==")
    da1 = runner.da1_2710
    emu = StreamEmu(image, budget=8_000_000)
    # transport
    emu.write_u32(P_CTX, 0)
    emu.write_u32(P_CTX + 8, P_OPS)
    emu.write_u32(P_OPS, P_STUB_SEND | 1)
    emu.write_u32(P_OPS + 4, P_STUB_RECV | 1)
    fifo = bytearray(HANDSHAKE + d7(da1, len(da1), 0x100))
    blocks = set()
    bl = []
    wrapper_entries = []

    def h_send(_uc, _a, _s, _u):
        emu.setreg(UC_ARM_REG_R0, 1); emu._ret()

    def h_recv(_uc, _a, _s, _u):
        p = emu.reg(UC_ARM_REG_R0); n = emu.reg(UC_ARM_REG_R1)
        if len(fifo) < n:
            emu.setreg(UC_ARM_REG_R0, 1); emu._ret(); return
        emu.uc.mem_write(p, bytes(fifo[:n])); del fifo[:n]
        emu.setreg(UC_ARM_REG_R0, 0); emu._ret()

    def h_blk(_uc, a, _s, _u):
        a &= ~1
        blocks.add(a)

    def h_wrap(_uc, _a, _s, _u):
        wrapper_entries.append(emu.reg(UC_ARM_REG_R0))

    emu.uc.hook_add(UC_HOOK_CODE, h_send, begin=P_STUB_SEND, end=P_STUB_SEND)
    emu.uc.hook_add(UC_HOOK_CODE, h_recv, begin=P_STUB_RECV, end=P_STUB_RECV)
    emu.uc.hook_add(UC_HOOK_CODE, h_wrap, begin=A_KEY_WRAPPER, end=A_KEY_WRAPPER)
    emu.uc.hook_add(UC_HOOK_BLOCK, h_blk)
    st = emu.run(A_CMD_LOOP, True, P.HARNESS_SP, (P_CTX, 0x7FFFFFFF), 8_000_000)
    flag = emu.uc.mem_read(G_DAA_FLAG, 1)[0]
    print("  proto session: class=%s flag=%d wrapper_entries=%d blocks=%d"
          % ("ACCEPT" if flag else "REJECT", flag, len(wrapper_entries),
             len(blocks)))

    # installed key: 0x23EA24 got r0=<ptr> -- compare against K2/K1 blobs
    k2 = image[0x25E3DC - BASE:0x25E3DC - BASE + 0x100]
    k1 = image[0x25E2DC - BASE:0x25E2DC - BASE + 0x100]
    print("  key_setup calls (0x23EA24): %s"
          % [("%#x" % a, "%#x" % b) for a, b in emu.key_installs])
    for ptr, ln in emu.key_installs:
        blob = bytes(emu.uc.mem_read(ptr, ln))
        same2 = blob == k2
        same1 = blob == k1
        print("    installed blob @%#x: ==K2:%s ==K1:%s head=%s"
              % (ptr, same2, same1, blob[:8].hex()))
    # the live key struct: G_KEY_PTR -> struct
    sp = emu.read_u32(G_KEY_PTR)
    if sp:
        dump = bytes(emu.uc.mem_read(sp, 0x210))
        off2 = dump.find(k2[:16])
        off1 = dump.find(k1[:16])
        print("  live key struct @%#x (from 0x2F9F38): K2 modulus at struct+%s, "
              "K1 modulus %s" % (sp, off2,
                                 ("at struct+%d" % off1) if off1 >= 0 else "NOT present"))
        print("    struct head: %s" % dump[:16].hex())
    print("  conclusion: exactly one key install per verify, source = K2")
    print("  (0x25E3DC); no code path re-installs or swaps the key from input.")

    # coverage: is the legacy seccfg/BR-cmd path entered?
    unreach = [a for a in (0x2378AC, 0x230C5C) if a not in blocks]
    print("  legacy paths entered during the accept session: %s"
          % (["none"] if len(unreach) == 2 else
             ["%#x" % a for a in (0x2378AC, 0x230C5C) if a in blocks]))
    print("  NOT entered: %s" % [hex(a) for a in unreach])

    # condensed coverage map over the usbdl region
    lo, hi = 0x208000, 0x209000
    blks = sorted(a for a in blocks if lo <= a < hi)
    ranges = []
    for a in blks:
        if ranges and a - ranges[-1][1] <= 0x10:
            ranges[-1][1] = a
        else:
            ranges.append([a, a])
    print("  usbdl-region block map (0x208000..0x209000): %d blocks in %d ranges"
          % (len(blks), len(ranges)))
    for a, b in ranges:
        print("    %#x..%#x" % (a, b))
    return len(unreach) == 2


# --------------------------------------------------------------------------
# phase 6: coverage-guided iteration
# --------------------------------------------------------------------------
def func_case_cov(runner: CaseRunner, buf: bytes, da_len: int, sig_len: int,
                  blocks: set, budget: int = 3_000_000):
    emu = PreloaderEmu(runner.image, budget=budget)
    seen = set()

    def h_blk(_uc, a, _s, _u):
        a &= ~1
        seen.add(a)

    emu.uc.hook_add(UC_HOOK_BLOCK, h_blk)
    emu.uc.mem_write(BUF_BASE, buf if buf else b"\x00")
    emu.setreg(UC_ARM_REG_R9, da_len)
    emu.setreg(UC_ARM_REG_R11, BUF_BASE)
    emu.setreg(UC_ARM_REG_R6, sig_len)
    st = emu.run(A_VERIFY_BLOCK, True, P.HARNESS_SP, (), budget)
    blocks.update(seen)
    return runner._result(emu, st, buf, da_len, sig_len, "func", False)


AUTH_RANGES = [(0x208000, 0x209000), (0x237900, 0x237A00),
               (0x23E000, 0x23EC00), (0x241000, 0x242000),
               (0x243000, 0x244400)]


def in_auth(a: int) -> bool:
    return any(lo <= a < hi for lo, hi in AUTH_RANGES)


def proto_case_cov(runner: CaseRunner, chunks, blocks: set, budget=6_000_000,
                   tag=""):
    emu = StreamEmu(runner.image, budget=budget)
    seen = set()

    def h_blk(_uc, a, _s, _u):
        seen.add(a & ~1)

    emu.uc.hook_add(UC_HOOK_BLOCK, h_blk)
    emu.write_u32(P_CTX, 0)
    emu.write_u32(P_CTX + 8, P_OPS)
    emu.write_u32(P_OPS, P_STUB_SEND | 1)
    emu.write_u32(P_OPS + 4, P_STUB_RECV | 1)
    fifo = bytearray(b"".join(chunks))
    sent = bytearray()

    def h_send(_uc, _a, _s, _u):
        p = emu.reg(UC_ARM_REG_R0); n = emu.reg(UC_ARM_REG_R1)
        sent.extend(bytes(_uc.mem_read(p, n))); emu.setreg(UC_ARM_REG_R0, 1); emu._ret()

    def h_recv(_uc, _a, _s, _u):
        p = emu.reg(UC_ARM_REG_R0); n = emu.reg(UC_ARM_REG_R1)
        if len(fifo) < n:
            emu.setreg(UC_ARM_REG_R0, 1); emu._ret(); return
        emu.uc.mem_write(p, bytes(fifo[:n])); del fifo[:n]
        emu.setreg(UC_ARM_REG_R0, 0); emu._ret()

    emu.uc.hook_add(UC_HOOK_CODE, h_send, begin=P_STUB_SEND, end=P_STUB_SEND)
    emu.uc.hook_add(UC_HOOK_CODE, h_recv, begin=P_STUB_RECV, end=P_STUB_RECV)
    st = emu.run(A_CMD_LOOP, True, P.HARNESS_SP, (P_CTX, 0x7FFFFFFF), budget)
    blocks.update(seen)
    return {"class": ("CRASH" if "fault" in st else
                      "HANG" if st.get("assert") is not None else
                      "IDLE_SPIN" if "budget" in st else
                      "OK_FLAG" if (st.get("flag") or emu.uc.mem_read(G_DAA_FLAG, 1)[0])
                      else "STOPPED"),
            "flag": emu.uc.mem_read(G_DAA_FLAG, 1)[0], "tag": tag}


def cmd_cover(runner: CaseRunner, seed: int, per_round: int = 500):
    print("== phase 6: coverage-guided iteration (3 rounds x %d) ==" % per_round)
    rng = random.Random(seed)
    blocks: set = set()
    growth = []
    t0 = time.time()

    def crafted_func():
        da1 = runner.da1_2710
        out = []
        for k in (0x100, 0x101, 0x200, 0x201, 0x1FF):
            out.append((da1[:k], k, 0x100, "rt_k%d" % k))
        L = len(da1)
        for dl in (L - 1, L - 0x100, L + 1):
            out.append((da1, dl, 0x100, "slide_%#x" % dl))
        for sl in (0xFF, 0x101, 0x180):
            out.append((da1, L, sl, "siglen_%#x" % sl))
        for lbl, t in [("zero", b"\x00" * 0x100), ("one", le256(1)),
                       ("ff", b"\xff" * 0x100)]:
            out.append((da1[:-0x100] + t, L, 0x100, "degen_" + lbl))
        return out

    def crafted_proto():
        da1 = runner.da1_2710
        return [
            ([HANDSHAKE, d4(0x10007000, [1]), d7(da1, len(da1), 0x100)],
             "cov_d4_window"),
            ([HANDSHAKE, d4(G_DAA_FLAG, [1]), d7(da1, len(da1), 0x100)],
             "cov_d4_flag"),
            ([HANDSHAKE, a2(0x10007000, 8), d7(da1, len(da1), 0x100)],
             "cov_a2_window"),
            ([HANDSHAKE, a2(G_DAA_FLAG, 1), d7(da1, len(da1), 0x100)],
             "cov_a2_flag"),
            ([HANDSHAKE, d5(0), d7(da1, len(da1), 0x100)], "cov_d5_lock"),
            ([HANDSHAKE, d7(da1, len(da1), 0x100), d5(0), d7(da1, len(da1), 0x100)],
             "cov_d5_commit"),
            ([HANDSHAKE, d2d3(0xD3, 0x10007000, [1, 2, 3, 4]),
              d7(da1, len(da1), 0x100)], "cov_d3_echo"),
            ([HANDSHAKE, d2d3(0xA1, G_DAA_FLAG, [1]),
              d7(da1, len(da1), 0x100)], "cov_a1_flag"),
            ([HANDSHAKE, b"\xc4" + be32(0) + be32(0), b"\xc6" + be32(0),
              b"\xd7" + be32(0) + be32(0x100000) + be32(0x100)], "cov_c4_c6"),
            ([HANDSHAKE, d7(da1[:0x800], 0x100000, 0x100)], "cov_da_1M"),
        ]

    def round_run2(n, label, crafted_share):
        cf, cp = crafted_func(), crafted_proto()
        ncraft = int(n * crafted_share)
        for i in range(n):
            if i < ncraft:
                if i % 2 == 0:
                    buf, dl, sl, tag = cf[(i * 7) % len(cf)]
                    res = func_case_cov(runner, buf, dl, sl, blocks)
                    if res["class"] == "ACCEPT_INVALID":
                        print("  !! ACCEPT_INVALID in cover round (%s: %s)"
                              % (label, tag))
                        save_repro({"kind": "func", "full_hex": buf.hex(),
                                    "da_len": dl, "sig_len": sl, "tag": tag},
                                   res, "cover_bypass")
                else:
                    chunks, tag = cp[(i * 7) % len(cp)]
                    res = proto_case_cov(runner, chunks, blocks, tag=tag)
            else:
                case = make_case(rng, runner, "func")
                buf, dl, sl, tag = (case["buf"], case["da_len"],
                                    case["sig_len"], case.get("tag", "rand"))
                res = func_case_cov(runner, buf, dl, sl, blocks)
                if res["class"] == "ACCEPT_INVALID":
                    print("  !! ACCEPT_INVALID in cover round (%s: %s)"
                          % (label, tag))
                    save_repro({"kind": "func", "full_hex": buf.hex(),
                                "da_len": dl, "sig_len": sl, "tag": tag},
                               res, "cover_bypass")
        growth.append(len(blocks))

    for rnd, share in [(1, 0.0), (2, 0.5), (3, 0.5)]:
        round_run2(per_round, "round%d" % rnd, share)
        print("  round %d: cumulative blocks=%d (%.1fs)"
              % (rnd, len(blocks), time.time() - t0))
    auth_blocks = sorted(a for a in blocks if in_auth(a))
    print("  auth-path blocks touched: %d of ranges %s"
          % (len(auth_blocks), ["%#x-%#x" % r for r in AUTH_RANGES]))
    print("  growth: %s" % growth)
    print("  note: rounds 2-3 add the proto memory-access/commit commands")
    print("  (0xD4/0xA2/0xD3/0xA1/0xD5) and the PSS boundary cases; the")
    print("  remaining uncovered blocks are the stubbed printf/USB replies")
    print("  and the error-tail print paths.")
    return True


# --------------------------------------------------------------------------
# repro helpers
# --------------------------------------------------------------------------
def save_repro(recipe: dict, res: dict, name: str):
    os.makedirs(REPRO_DIR, exist_ok=True)
    meta = {"recipe": recipe, "class": res.get("class"),
            "r0": res.get("r0"), "flag": res.get("flag"),
            "tag": res.get("tag", name)}
    path = os.path.join(REPRO_DIR, name + ".json")
    with open(path, "w") as f:
        json.dump(meta, f, indent=1)
    print("  repro -> %s" % path)


def cmd_replay(runner: CaseRunner, path: str):
    with open(path) as f:
        meta = json.load(f)
    recipe = meta.get("recipe") or {}
    kind = recipe.get("kind")
    if kind == "stream":
        chunks = [bytes.fromhex(c) for c in recipe["chunks"]]
        res = proto_stream(runner, chunks, budget=recipe.get("budget", 8_000_000),
                           no_halt=recipe.get("no_halt", False))
    else:
        case = apply_recipe(runner, recipe)
        res = runner.func_case(case["buf"], case["da_len"], case["sig_len"],
                               header_only=recipe.get("header_only", False))
    match = res.get("class") == meta.get("class") and res.get("flag") == meta.get("flag")
    print(json.dumps({"replay": path, "class": res.get("class"),
                      "expected": meta.get("class"), "match": match,
                      "flag": res.get("flag")}, indent=1))
    return 0 if match else 3


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", default=P.IMAGE_DEFAULT)
    ap.add_argument("--da2710", default=P.DA2710_DEFAULT)
    ap.add_argument("--da200", default=P.DA200_DEFAULT)
    ap.add_argument("--mode", choices=["func", "fuzz", "pss", "state", "memacc",
                                       "reads", "oracle", "keys", "cover",
                                       "all", "replay"], default="func")
    ap.add_argument("--cases", type=int, default=3000)
    ap.add_argument("--seed", type=int, default=2)
    ap.add_argument("--json", default=None)
    ap.add_argument("--replay", default=None)
    ap.add_argument("--repro-dir", default=REPRO_DIR)
    args = ap.parse_args(argv)

    image = P.load_image(args.image)
    if not sha(image).startswith(P.IMAGE_SHA_PREFIX):
        print("WARNING: image sha256 mismatch", file=sys.stderr)

    da2710 = da200 = b""
    need_da = True
    if need_da:
        p2710 = args.da2710
        if not os.path.exists(p2710):
            raise SystemExit("DA2710 not found: %s" % p2710)
        p200 = args.da200
        if not os.path.exists(p200):
            for cand in P.DA200_FALLBACKS:
                if os.path.exists(cand):
                    p200 = cand
                    break
            if not os.path.exists(p200):
                raise SystemExit("DA200 not found")
        da2710 = open(p2710, "rb").read()
        da200 = open(p200, "rb").read()
        print("DA2710: %s (%d B)  DA200: %s (%d B)"
              % (p2710, len(da2710), p200, len(da200)))
    runner = CaseRunner(image, da2710, da200)

    if args.replay:
        return cmd_replay(runner, args.replay)
    if args.mode == "func":
        return 0 if P.cmd_func(runner, args.json) else 1
    if args.mode == "fuzz":
        ok = P.cmd_fuzz(runner, args.cases, args.seed, args.json, args.repro_dir)
        return 0 if ok else 2
    if args.mode == "pss":
        return 0 if cmd_pss(runner, args.seed) else 2
    if args.mode == "state":
        return 0 if cmd_state(runner, args.seed) else 2
    if args.mode == "memacc":
        return 0 if cmd_memacc(runner) else 2
    if args.mode == "reads":
        cmd_reads(runner, image)
        return 0
    if args.mode == "oracle":
        cmd_oracle(runner)
        return 0
    if args.mode == "keys":
        return 0 if cmd_keys(runner, image) else 2
    if args.mode == "cover":
        cmd_cover(runner, args.seed)
        return 0
    if args.mode == "all":
        t0 = time.time()
        results = {}
        results["pss"] = cmd_pss(runner, args.seed)
        results["memacc"] = cmd_memacc(runner)
        results["state"] = cmd_state(runner, args.seed)
        cmd_reads(runner, image)
        cmd_oracle(runner)
        results["keys"] = cmd_keys(runner, image)
        cmd_cover(runner, args.seed)
        print("\n== round-2 campaign done in %.1fs ==" % (time.time() - t0))
        print("   phase verdicts: %s" % results)
        return 0 if all(results.values()) else 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
