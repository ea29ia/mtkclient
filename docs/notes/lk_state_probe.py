#!/usr/bin/env python3
"""lk_state_probe.py -- read LK's own view of the lock state, without Android.

WHY
---
`SecondStageMain` gates the adb_debug.prop load on

    getenv("INIT_FORCE_DEBUGGABLE") == "true"  &&  AvbHandle::IsDeviceUnlocked()

and `IsDeviceUnlocked()` is just `fs_mgr_get_boot_config("verifiedbootstate") ==
"orange"`. LK emits that string from its boot-state variable (VA 0x500C4FA8),
which is set to 2 (orange) **only** at 0x50053AD4, and only if
`sec_cfg_get_lock_state()` returned 0 (validated) *and* the record's lock_state
byte (+0x0C) == 3. Any validation failure fail-safes to 1 -> green.

The phone has a dead screen, adb is unauthorized (no shell) and the DA is only
reachable in preloader mode. So the question "did LK see lock_state == 3?" has
to be answered from a surface that does not need Android at all.

Three such surfaces exist in THIS LK build, in this order of cost:

  1. fastboot `getvar secure` / `getvar unlocked` / `getvar all`
     -> runs the *same* validated getter LK uses for the boot decision
        (0x50032670 -> 0x50082E10 -> 0x50082AE0 -> 0x500827E8).
        No shell, no screen, no ADB. `getvar` is allowed on a LOCKED device.
  2. preloader/DA read of the `seccfg` partition, then offline validation
     (docs/notes/seccfg_validate.py). Read-only, but a DA session is a bigger
     hammer than fastboot.
  3. expdb / UART (`oem p2u on`) if both of the above are unreachable.

THIS TOOL
---------
  --plan            the ordered procedure for the human (default)
  --decode FILE     decode a captured fastboot transcript into a verdict
  --verify-lk PATH  re-derive, from lk_payload.bin, which getvar variables and
                    which code paths actually exist (the evidence, not a claim)
  --self-test       synthetic transcripts: orange / green / unreadable

Nothing here touches a device. --verify-lk only reads a local file.

Exit codes: 0 ok; 2 bad file/usage; 3 self-test or verification failure.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LK = os.path.join(HERE, "rmx3630-lk", "lk_payload.bin")
LK_BASE = 0x50000000
LK_SHA256 = "e7c857896bfe83966595dc61bea8ced5ef6ad0d6dcf57f7ec5a9892eabd8c763"

# --- anchors proven in docs/notes/reverse/re-lk-rescue-surfaces.md + this task
FB_PUBLISH = 0x5000582C          # fastboot_publish(name, value)  (list head 0x501120B8)
FB_REGISTER = 0x50005768         # fastboot_register(name, cb, flagA, flagB)
FB_OKAY = 0x50005B14             # fastboot_okay(value)
FB_FAIL = 0x50005ADC             # fastboot_fail(reason)
GETVAR_CB = 0x50006808           # "getvar:" handler
SEC_GET_LS = 0x50082AE0          # sec_cfg_get_lock_state core
SEC_GET_LS_WRAP = 0x50082E10     # is-unlocked wrapper (0x50032670 thunk)
SEC_MASTER = 0x500827E8          # sec_check_major_integrity_seccfg
DISPATCH_GATE = (0x50005F1C, 0x50005F50)
PUBLISH_SECURE = 0x50007600      # "secure" + "unlocked" publisher
# function roots that contain a fastboot_publish() call
PUB_ROOTS = (
    0x50006230,   # fastboot_init: version, version-bootloader, max-download-size, ...
    0x50007600,   # secure / unlocked
    0x50006D6C,   # oem off-mode-charge handler (re-publishes its value)
    0x50007230,   # partition-size / partition-type enumerator (dynamic names)
)


def _merge_env(a: dict, b: dict) -> dict:
    """Join two register environments: keep only values that agree."""
    return {k: v for k, v in a.items() if k in b and b[k] == v}

# --------------------------------------------------------------- aarch64 mini
def _sext(v: int, bits: int) -> int:
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def _rd(w: int, n: int) -> int:
    return (w >> (5 * n)) & 0x1F


def _rn(n: int) -> str:
    return "sp" if n == 31 else f"x{n}"


def decode(w: int, va: int) -> dict:
    """Decode just enough AArch64 for the arguments we need to recover."""
    D = {"va": va, "w": w, "kind": "other", "text": f".word 0x{w:08x}"}
    if (w & 0x9F000000) == 0x90000000:                       # ADRP
        rd = w & 0x1F
        imm = (((w >> 5) & 0x7FFFF) << 2) | ((w >> 29) & 3)
        imm = _sext(imm, 21)
        tgt = (va & ~0xFFF) + (imm << 12)
        return {"va": va, "w": w, "kind": "adrp", "rd": rd, "imm": tgt,
                "text": f"adrp x{rd}, {tgt:#x}"}
    if (w & 0xFFC00000) == 0x91000000:                       # ADD (imm, 64-bit)
        rd, rn = w & 0x1F, _rd(w, 1)
        imm = (w >> 10) & 0xFFF
        if (w >> 22) & 1:
            imm <<= 12
        return {"va": va, "w": w, "kind": "add", "rd": rd, "rn": rn, "imm": imm,
                "text": f"add {_rn(rd)}, {_rn(rn)}, #{imm:#x}"}
    if (w & 0xFFC00000) == 0xD1000000:                       # SUB (imm)
        rd, rn = w & 0x1F, _rd(w, 1)
        return {"va": va, "w": w, "kind": "sub", "rd": rd, "rn": rn,
                "imm": (w >> 10) & 0xFFF,
                "text": f"sub {_rn(rd)}, {_rn(rn)}, #{(w >> 10) & 0xFFF:#x}"}
    if (w & 0x7F800000) == 0x52800000:                       # MOVZ w
        rd = w & 0x1F
        imm = (((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3)))
        return {"va": va, "w": w, "kind": "movz", "rd": rd, "imm": imm,
                "text": f"mov w{rd}, #{imm:#x}"}
    if (w & 0x7F800000) == 0xD2800000:                       # MOVZ x
        rd = w & 0x1F
        imm = (((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3)))
        return {"va": va, "w": w, "kind": "movz", "rd": rd, "imm": imm,
                "text": f"mov x{rd}, #{imm:#x}"}
    if (w & 0x7F800000) == 0x12800000:                       # MOVN w
        rd = w & 0x1F
        imm = ~(((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3))) & 0xFFFFFFFF
        return {"va": va, "w": w, "kind": "movz", "rd": rd, "imm": imm,
                "text": f"mov w{rd}, #{imm:#x}"}
    if (w & 0x7F800000) == 0x72800000:                       # MOVK w
        rd = w & 0x1F
        return {"va": va, "w": w, "kind": "movk", "rd": rd,
                "imm": ((w >> 5) & 0xFFFF) << (16 * ((w >> 21) & 3)),
                "text": f"movk w{rd}, #{(w >> 5) & 0xFFFF:#x}, lsl #{16 * ((w >> 21) & 3)}"}
    if (w & 0xFFE0FFE0) == 0x2A0003E0:                       # MOV w-reg (mov wd, wm)
        rd, rm = w & 0x1F, (w >> 16) & 0x1F
        return {"va": va, "w": w, "kind": "mov32", "rd": rd, "rm": rm,
                "text": f"mov w{rd}, w{rm}"}
    if (w & 0xFFE0FFE0) == 0xAA0003E0:                       # MOV (orr xd, xzr, xm)
        rd, rm = w & 0x1F, (w >> 16) & 0x1F
        return {"va": va, "w": w, "kind": "mov", "rd": rd, "rm": rm,
                "text": f"mov x{rd}, x{rm}"}
    if (w & 0xFC000000) == 0x94000000:                       # BL
        imm = _sext(w & 0x3FFFFFF, 26)
        return {"va": va, "w": w, "kind": "bl", "target": va + imm * 4,
                "text": f"bl {va + imm * 4:#x}"}
    if (w & 0xFC000000) == 0x14000000:                       # B
        imm = _sext(w & 0x3FFFFFF, 26)
        return {"va": va, "w": w, "kind": "b", "target": va + imm * 4,
                "text": f"b {va + imm * 4:#x}"}
    if (w & 0xFF000010) == 0x54000000:                       # B.cond
        imm = _sext((w >> 5) & 0x7FFFF, 19)
        cond = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"][w & 0xF]
        return {"va": va, "w": w, "kind": "bcond", "target": va + imm * 4,
                "text": f"b.{cond} {va + imm * 4:#x}"}
    if (w & 0x7E000000) == 0x34000000:                       # CBZ/CBNZ
        op = "cbnz" if (w >> 24) & 1 else "cbz"
        imm = _sext((w >> 5) & 0x7FFFF, 19)
        return {"va": va, "w": w, "kind": op, "rt": w & 0x1F,
                "target": va + imm * 4, "text": f"{op} w{w & 0x1F}, {va + imm * 4:#x}"}
    if (w & 0xFFC00000) in (0xF9400000, 0xF9000000, 0xB9400000, 0xB9000000):
        load = (w & 0xFFC00000) in (0xF9400000, 0xB9400000)
        rt, rn = w & 0x1F, _rd(w, 1)
        off = ((w >> 10) & 0xFFF) * (8 if (w & 0xFFC00000) in (0xF9400000, 0xF9000000) else 4)
        return {"va": va, "w": w, "kind": "ldr" if load else "str",
                "rt": rt, "rn": rn, "off": off,
                "text": f"{'ldr' if load else 'str'} {'x' if (w & 0xFFC00000) in (0xF9400000, 0xF9000000) else 'w'}{rt}, [{_rn(rn)}, #{off:#x}]"}
    if (w & 0x9F000000) == 0x8B000000:                       # ADD (reg, shifted/extended)
        rd, rn, rm = w & 0x1F, _rd(w, 1), (w >> 16) & 0x1F
        ext = (w >> 21) & 1
        imm = (w >> 10) & (7 if ext else 0x3F)
        return {"va": va, "w": w, "kind": "addreg", "rd": rd, "rn": rn, "rm": rm,
                "scale": 1 << min(imm, 3),
                "text": f"add x{rd}, x{rn}, x{rm}, lsl #{imm}"}
    if (w & 0x7F000000) == 0x71000000:                       # SUBS imm (cmp)
        rn, imm = _rd(w, 1), (w >> 10) & 0xFFF
        return {"va": va, "w": w, "kind": "cmp", "rn": rn, "imm": imm,
                "text": f"cmp w{rn}, #{imm:#x}   // lock_state" if imm == 3 else f"cmp w{rn}, #{imm:#x}"}
    if (w & 0x7FE00C00) == 0x1A800400:                       # CSINC
        cond = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"][(w >> 12) & 0xF]
        return {"va": va, "w": w, "kind": "csinc", "rd": w & 0x1F,
                "rn": _rd(w, 1), "rm": (w >> 16) & 0x1F, "cond": cond,
                "text": f"csinc w{w & 0x1F}, w{_rd(w, 1)}, w{(w >> 16) & 0x1F}, {cond}"}
    if (w & 0x7FE00C00) == 0x1A800000:                       # CSEL
        cond = ["eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
                "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"][(w >> 12) & 0xF]
        return {"va": va, "w": w, "kind": "csel", "rd": w & 0x1F,
                "rn": _rd(w, 1), "rm": (w >> 16) & 0x1F, "cond": cond,
                "text": f"csel x{w & 0x1F}, x{_rd(w, 1)}, x{(w >> 16) & 0x1F}, {cond}"}
    if (w & 0xFFFFFC1F) == 0xD63F0000:                       # BLR
        return {"va": va, "w": w, "kind": "blr", "rn": _rd(w, 1),
                "text": f"blr x{_rd(w, 1)}"}
    if w == 0xD65F03C0:
        return {"va": va, "w": w, "kind": "ret", "text": "ret"}
    return D


class Blob:
    def __init__(self, data: bytes):
        self.d = data
        self.base = LK_BASE

    def word(self, va: int) -> int:
        o = va - self.base
        if o < 0 or o + 4 > len(self.d):
            raise IndexError(f"{va:#x} outside payload")
        return struct.unpack_from("<I", self.d, o)[0]

    def va_of_offset(self, off: int) -> int:
        return off + self.base

    def cstr(self, va: int, maxlen: int = 96) -> str | None:
        o = va - self.base
        if o < 0 or o >= len(self.d):
            return None
        raw = self.d[o:o + maxlen].split(b"\0")[0]
        if not raw:
            return ""
        try:
            s = raw.decode("ascii")
        except UnicodeDecodeError:
            return None
        return s if all(32 <= ord(c) < 127 for c in s) else None

    # -- display-only linear scan -----------------------------------------
    def linear(self, start: int, end: int):
        va = start
        while va < end:
            yield decode(self.word(va), va)
            va += 4

    # -- forward CFG walk with register tracking ---------------------------
    def cfg_calls(self, roots, callee: int, budget: int = 40000):
        """Collect BL sites to `callee` reachable from `roots`, with arguments.

        Each event is (call_va, {0: val, 1: val, 2: val, 3: val}).  A value is
        ('addr', va) | ('int', n) | ('sel', (a, b)) | ('buf',).
        Registers are merged at join points (kept only when all paths agree),
        and x0-x18 are dropped at every call (AAPCS caller-saved), so an
        argument never leaks from a sibling branch.
        """
        events = []
        for root in roots:
            work = [(root, {})]
            seen: dict[int, dict] = {}
            steps = 0
            while work and steps < budget:
                va, env = work.pop()
                while True:
                    steps += 1
                    if steps > budget:
                        break
                    try:
                        w = self.word(va)
                    except IndexError:
                        break
                    d = decode(w, va)
                    k = d["kind"]
                    if va in seen:
                        merged = _merge_env(seen[va], env)
                        if merged == seen[va]:
                            break
                        env = merged
                        seen[va] = dict(merged)
                    else:
                        seen[va] = dict(env)

                    # --- update the environment ---
                    rd = d.get("rd")
                    if k == "adrp":
                        env[rd] = ("addr", d["imm"])
                    elif k == "add" and d["rn"] in env:
                        b = env[d["rn"]]
                        if b[0] in ("addr", "int"):
                            env[rd] = (b[0], b[1] + d["imm"])
                        else:
                            env[rd] = ("buf",)
                    elif k == "add" and d["rn"] not in env:
                        env[rd] = ("buf",)
                    elif k == "addreg":
                        base = env.get(d["rn"])
                        if base and base[0] == "addr" and d["scale"] <= 8:
                            env[rd] = ("table", base[1], d["scale"])
                        else:
                            env[rd] = ("buf",)
                    elif k == "movz":
                        env[rd] = ("int", d["imm"])
                    elif k == "movk":
                        prev = env.get(rd)
                        if prev and prev[0] == "int":
                            env[rd] = ("int", prev[1] | d["imm"])
                        else:
                            env[rd] = ("buf",)
                    elif k == "mov32":
                        if d["rm"] == 31:
                            env[rd] = ("int", 0)
                        else:
                            env[rd] = env.get(d["rm"], ("buf",))
                    elif k == "mov":
                        env[rd] = env.get(d["rm"], ("buf",))
                    elif k == "csel":
                        a = env.get(d["rn"])
                        b = env.get(d["rm"])
                        env[rd] = (("sel", (a, b)) if a and b and a[0] == "addr"
                                   and b[0] == "addr" else ("buf",))
                    elif k == "csinc":
                        env[rd] = env.get(d["rn"], ("buf",))
                    elif k in ("ldr", "str"):
                        env.pop(d["rt"], None)

                    if k == "bl":
                        if d["target"] == callee:
                            events.append((va, {i: env.get(i) for i in range(4)}))
                        for i in range(19):
                            env.pop(i, None)
                    elif k == "b":
                        work.append((d["target"], dict(env)))
                        break
                    elif k in ("bcond", "cbz", "cbnz"):
                        work.append((d["target"], dict(env)))
                    elif k == "ret":
                        break
                    va += 4
        # the roots overlap; report each site/argument combination once
        uniq, out = set(), []
        for va, args in events:
            key = (va, tuple(args.get(i) for i in range(4)))
            if key in uniq:
                continue
            uniq.add(key)
            out.append((va, args))
        return out


def _va(v):
    return v[1] if v and v[0] == "addr" and isinstance(v[1], int) else None


def arg_str(blob: Blob, regs: dict, n: int) -> tuple[str | None, int | None]:
    v = regs.get(n)
    if not v:
        return None, None
    if v[0] == "addr":
        return blob.cstr(v[1]), v[1]
    if v[0] == "sel":
        a, b = v[1]
        va, vb = _va(a), _va(b)
        sa = blob.cstr(va) if va else None
        sb = blob.cstr(vb) if vb else None
        return f"{sa}|{sb}", va
    if v[0] == "table":
        base, scale = v[1], v[2]
        a, b = blob.cstr(base), blob.cstr(base + scale)
        if scale == 4 and a in ("no", "yes") and b in ("no", "yes"):
            return f"{a}|{b}", base
        return "<table>", base
    if v[0] == "int":
        return None, v[1]
    return None, None


def arg_int(regs: dict, n: int):
    v = regs.get(n)
    if not v:
        return None
    if v[0] == "int":
        return v[1]
    if v[0] == "addr":
        return v[1]
    return None


# ------------------------------------------------------------- LK verification
def verify_lk(path: str, show_disasm: bool = False) -> int:
    print(f"=== static verification of {path} ===")
    try:
        data = open(path, "rb").read()
    except OSError as e:
        print(f"[-] {e}")
        return 2
    h = hashlib.sha256(data).hexdigest()
    print(f"size   : {len(data)} bytes")
    print(f"sha256 : {h}")
    if h != LK_SHA256:
        print(f"[!] WARNING: expected {LK_SHA256} (the analysed stock payload).")
        print("    Continuing, but every VA below was derived for that exact file.")
    else:
        print("         == the payload analysed in re-lk-seccfg.md / re-lk-initdb docs")

    blob = Blob(data)
    ok = True
    checks: list[tuple[str, bool, str]] = []

    def ck(name: str, cond: bool, detail: str = "") -> None:
        nonlocal ok
        checks.append((name, bool(cond), detail))
        ok &= bool(cond)

    # ---- 1. the fastboot command registration ---------------------------
    reg = blob.cfg_calls([0x50006230], FB_REGISTER)
    names = []
    for va, regs in reg:
        s, sva = arg_str(blob, regs, 0)
        cb = arg_int(regs, 1)
        flagA = arg_int(regs, 2)
        flagB = arg_int(regs, 3)
        names.append((va, s, cb, flagA, flagB))
    getvar_reg = [x for x in names if x[1] == "getvar:"]
    ck("fastboot_register(\"getvar:\") exists", bool(getvar_reg),
       f"{len(getvar_reg)} site(s): " + ", ".join(f"{v:#x}" for v, *_ in getvar_reg))
    if getvar_reg:
        va, s, cb, fa, fb = getvar_reg[0]
        ck("getvar: registered with flagA=1 flagB=0 (runs while LOCKED)",
           fa == 1 and fb == 0, f"at {va:#x}: flagA={fa} flagB={fb} -> public command")
        ck("getvar: handler is 0x50006808", cb == GETVAR_CB, f"handler={cb and hex(cb)}")

    # ---- 2. published getvar variables ----------------------------------
    pubs = blob.cfg_calls(PUB_ROOTS, FB_PUBLISH)
    pub_list = []
    for va, regs in pubs:
        s, sva = arg_str(blob, regs, 0)
        v, vva = arg_str(blob, regs, 1)
        pub_list.append((va, s, v, sva, vva))
    static_names = sorted({p[1] for p in pub_list if p[1]})
    print("\n--- fastboot_publish() sites (these ARE the getvar variables) ---")
    for va, name, val, sva, vva in sorted(pub_list, key=lambda x: (x[1] or "~", x[0])):
        n = name if name is not None else "<runtime buffer>"
        v = val if val is not None else "<runtime value>"
        nva = f"{sva:#x}" if sva else "     -"
        print(f"  {va:#010x}  {nva}  {n:<20} = {v}")

    for need in ("secure", "unlocked", "version-bootloader", "current-slot",
                 "slot-count", "off-mode-charge", "is-userspace"):
        ck(f'getvar variable "{need}" is published',
           need in static_names,
           "" if need in static_names else "not found in any publication site")

    # absence proof for the vars people keep hoping for
    for absent in ("avb", "verifiedbootstate", "is-unlocked", "is_unlocked",
                   "vbmeta", "lock_state", "seccfg"):
        ck(f'no getvar variable "{absent}" (so do not ask for it)',
           absent not in static_names, "published anyway!" if absent in static_names else "")

    # ---- 3. the secure/unlocked publisher -------------------------------
    print("\n--- secure/unlocked publisher (0x50007600) ---")
    blk = list(blob.linear(PUBLISH_SECURE, PUBLISH_SECURE + 0xA8))
    for ins in blk:
        if ins["kind"] in ("bl", "cmp", "csinc", "csel", "cbz", "cbnz", "bcond"):
            print(f"  {ins['va']:#010x}  {ins['text']}")
    calls = [(i["va"], i["target"]) for i in blk if i["kind"] == "bl"]
    ck("publisher calls the validated lock getter (0x50032670 -> 0x50082E10)",
       (PUBLISH_SECURE + 0x14, 0x50032670) in calls,
       f"calls: " + ", ".join(f"{a:#x}->{t:#x}" for a, t in calls))
    ck("publisher fetches existing value with fastboot_get(name) 0x5000590C",
       any(t == 0x5000590C for _, t in calls), "")
    ck("publisher writes with fastboot_publish 0x5000582C and update 0x500058B4",
       any(t == FB_PUBLISH for _, t in calls) and any(t == 0x500058B4 for _, t in calls),
       "")

    # value table "no"/"yes" 4 bytes apart: adrp x19,0x50090000 ; add x19,x19,#0x821
    tbl_va = None
    for ins in blob.linear(PUBLISH_SECURE, PUBLISH_SECURE + 0x50):
        if ins["kind"] == "add" and ins["rd"] == 19 and ins["imm"] == 0x821:
            tbl_va = 0x50090000 + 0x821
    no_s = blob.cstr(0x50090821)
    yes_s = blob.cstr(0x50090825)
    ck("lock-state value table is {no, yes} at 0x50090821",
       no_s == "no" and yes_s == "yes", f"got {no_s!r}, {yes_s!r}")

    # ---- 4. the dispatcher gate ----------------------------------------
    print("\n--- command gate in the fastboot dispatcher ---")
    gate = list(blob.linear(*DISPATCH_GATE))
    for ins in gate:
        print(f"  {ins['va']:#010x}  {ins['text']}")
    ck("dispatcher calls S-CHIP check 0x5007EF04",
       any(i["kind"] == "bl" and i["target"] == 0x5007EF04 for i in gate), "")
    ck("dispatcher calls sec_cfg_get_lock_state 0x500326AC",
       any(i["kind"] == "bl" and i["target"] == 0x500326AC for i in gate), "")
    ck("dispatcher compares lock_state with #3 and denies when !=",
       any(i["kind"] == "cmp" and i["imm"] == 3 for i in gate)
       and any(i["kind"] == "bcond" for i in gate), "")

    # ---- 5. getter semantics -------------------------------------------
    print("\n--- getter semantics (fail-safe) ---")
    core = list(blob.linear(SEC_GET_LS, SEC_GET_LS + 0x30))
    for ins in core:
        print(f"  {ins['va']:#010x}  {ins['text']}")
    ck("core getter calls the master validator 0x500827E8",
       any(i["kind"] == "bl" and i["target"] == SEC_MASTER for i in core), "")
    ck("core getter fail-safes lock_state to 1 (csinc w8,w8,wzr,eq)",
       any(i["kind"] == "csinc" and i["rn"] == 8 and i["rm"] == 31 and i["cond"] == "eq"
           for i in core), "")
    wrap = list(blob.linear(SEC_GET_LS_WRAP, SEC_GET_LS_WRAP + 0x40))
    for ins in wrap:
        print(f"  {ins['va']:#010x}  {ins['text']}")
    ck("wrapper maps lock_state != 3 -> 1 (locked)",
       any(i["kind"] == "cmp" and i["imm"] == 3 for i in wrap)
       and any(i["kind"] == "csinc" for i in wrap), "")

    # ---- 6. getvar:all --------------------------------------------------
    h_all = blob.cstr(0x500AA6C4)
    h_done = blob.cstr(0x5008F989)
    ck('getvar handler compares the argument with "all"', h_all == "all", f"{h_all!r}")
    ck('getvar:all finishes with OKAY "Done!!"', h_done == "Done!!", f"{h_done!r}")
    ck('unknown/failed getvar replies use OKAY/FAIL strings',
       blob.cstr(0x5008F49D) == "OKAY" and blob.cstr(0x5008F498) == "FAIL", "")

    if show_disasm:
        print("\n--- objdump cross-check (same VAs) ---")
        for lo, hi in ((0x5000635C, 0x50006380), (0x50006814, 0x50006830),
                       (0x5000760C, 0x500076A0), (0x50005F18, 0x50005F50),
                       (0x50082AE0, 0x50082B20), (0x50082E20, 0x50082E44)):
            out = subprocess.run(
                ["aarch64-linux-gnu-objdump", "-D", "-b", "binary", "-m", "aarch64",
                 f"--adjust-vma={LK_BASE:#x}", f"--start-address={lo:#x}",
                 f"--stop-address={hi:#x}", path],
                capture_output=True, text=True)
            print(out.stdout if out.stdout else out.stderr)

    print("\n=== summary ===")
    for name, passed, detail in checks:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}" + (f"   ({detail})" if detail else ""))
    print(f"\n{sum(1 for _, p, _ in checks if p)}/{len(checks)} checks passed")
    if pub_list:
        print("\n=> usable surfaces, in order:")
        print("   1. fastboot getvar secure     (yes/no, runs the validated getter)")
        print("   2. fastboot getvar unlocked   (yes/no)")
        print("   3. fastboot getvar all        (full published table)")
        print("   4. DA read of seccfg + docs/notes/seccfg_validate.py --info")
    return 0 if ok else 3


# --------------------------------------------------------- transcript decode
KV_RE = re.compile(r"^\s*(?:\(bootloader\)\s*)?([A-Za-z0-9_.:\-]+)\s*:\s*(.*?)\s*$")
FAIL_RE = re.compile(r"(?:\(bootloader\)\s*)?(?:FAILED|FAIL)\b(.*)$", re.I)
CMD_RE = re.compile(r"^\s*\$?\s*(?:sudo\s+)?fastboot\s+(?:-s\s+\S+\s+)?getvar\s+(\S+)", re.I)


def decode_transcript(text: str) -> tuple[str, list[str], dict]:
    """Return (verdict, notes, kv). verdict in {orange, green, unreadable}."""
    kv: dict[str, str] = {}
    failed: list[str] = []
    cmds: list[str] = []
    for line in text.splitlines():
        m = CMD_RE.match(line)
        if m:
            cmds.append(m.group(1))
            continue
        m = FAIL_RE.search(line)
        if m:
            failed.append(m.group(1).strip())
            continue
        m = KV_RE.match(line)
        if m:
            k, v = m.group(1).lower(), m.group(2)
            if k in ("finished.", "total time", "fastboot"):
                continue
            kv[k] = v
    notes: list[str] = []

    secure = kv.get("secure")
    unlocked = kv.get("unlocked")
    if secure is not None:
        notes.append(f"secure = {secure!r}  (LK published this from the validated record)")
    if unlocked is not None:
        notes.append(f"unlocked = {unlocked!r}")
    if any("secure status" in f.lower() for f in failed):
        notes.append("LK answered FAIL 'Failed to get secure status!' "
                     "-> the getter errored; fail-safe lock_state = 1")
        return "green", notes, kv
    if failed:
        notes.append("unparsed FAIL line(s): " + " | ".join(failed))

    if secure is None and unlocked is None:
        if cmds:
            notes.append("no secure/unlocked value in the transcript: either the "
                         "variable was never published (getvar returns OKAY with an "
                         "empty value) or the output was not captured")
        notes.append("=> unreadable: fall back to the seccfg/DA path or retry getvar all")
        return "unreadable", notes, kv

    if secure is not None:
        s = secure.strip().lower()
        if s == "no":
            notes.append("=> LK sees lock_state == 3 (unlocked): verifiedbootstate=orange")
            return "orange", notes, kv
        if s == "yes":
            notes.append("=> LK sees locked (either lock_state != 3 or seccfg invalid "
                         "fail-safe): verifiedbootstate=green")
            return "green", notes, kv
    if unlocked is not None:
        u = unlocked.strip().lower()
        if u == "yes":
            notes.append("=> LK sees lock_state == 3 (unlocked): verifiedbootstate=orange")
            return "orange", notes, kv
        if u == "no":
            notes.append("=> LK sees locked: verifiedbootstate=green")
            return "green", notes, kv
    notes.append(f"unrecognised values secure={secure!r} unlocked={unlocked!r}")
    return "unreadable", notes, kv


VERDICT_ACTION = {
    "orange": [
        "orange CONFIRMED. The 5-second-stall hypothesis is irrelevant (see "
        "re-lk-state-probe.md section 3) and the SecondStageMain gate is being "
        "satisfied.",
        "Next: re-open why /debug_ramdisk/adb_debug.prop does not take effect --",
        "  * is /force_debuggable present in the *boot* ramdisk and is first-stage",
        "    init the boot one (PLAN A/B, re-vendor-boot-q1.md)?",
        "  * does first stage actually copy it to /debug_ramdisk/adb_debug.prop?",
        "  * is ro.adb.secure rejected by the property context (build_prop) rather",
        "    than never being read (re-init-prop-gate.md)?",
        "Do NOT touch seccfg: it is already correct.",
    ],
    "green": [
        "green/locked: the adb path is a dead end until the lock state changes.",
        "Confirmed by LK itself, independent of Android. Fix seccfg/RPMB:",
        "  * python3 docs/notes/seccfg_validate.py --info seccfg.bin",
        "  * if INIT_NV: the record was rewritten locked -> the unlock never stuck",
        "    (SEJ/HACC silent failure, re-seccfg-digest-equiv.md section 4)",
        "  * RPMB boot-info mirror (blocks 0x1DC-0x1DF) wins over a forged seccfg",
        "    (unlock_state_check.py); a mirror mismatch re-locks and powers off.",
        "Do NOT spend more time on the ramdisks: no ramdisk can create orange.",
    ],
    "unreadable": [
        "unreadable: no LK-level answer. Camera-free diagnostics, cheapest first:",
        "  1. re-run the fastboot ritual; check 'getvar version' == 0.5 ",
        "     and 'getvar product' == k6789v1_64  (proves it is THIS LK)",
        "  2. DA read of seccfg (preloader mode) + seccfg_validate.py --info",
        "  3. expdb partition (LK log ring) via DA read -- read-only",
        "  4. UART: fastboot 'oem p2u on' (allowed while locked) then capture the",
        "     LK print 'sboot_state is %d, lock_state is %d, isunlocked is %d'",
        "     (string 0x5008E089, site 0x5000262C)",
        "  5. USB timing with a known-green baseline (NOT as a standalone proof).",
    ],
}


# --------------------------------------------------------------------- plan
PLAN = r"""
================================================================================
LK STATE PROBE -- ordered, read-only procedure
================================================================================
Preconditions: battery > 30%, original cable, host = Termux/OTG.
Nothing below writes, flashes, erases or reboots the device.
--------------------------------------------------------------------------------
STEP 1  Enter fastboot (no screen needed)
--------------------------------------------------------------------------------
  The boot mode is chosen by the PRELOADER (HW reg 0x10007024 low nibble:
  2=recovery, 3=fastboot), not by anything writable from flash. Use the key
  combo, cable out/in:
     hold VOL-DOWN, plug the cable, keep holding ~8 s
     if that lands in preloader/DA (USB id 22d9:0006), retry with
     VOL-UP + VOL-DOWN held, then with VOL-UP alone.
  Detect WITHOUT trusting the screen:
     fastboot devices            # must list a serial
     lsusb | grep -i 22d9        # fastboot mode is NOT 0006 (that is preloader)
  Also fine: `mtk.py` reports the boot mode in preloader, but only fastboot gives
  you LK's post-validation view, so prefer fastboot here.

--------------------------------------------------------------------------------
STEP 2  Prove you are talking to THIS LK  (5 s)
--------------------------------------------------------------------------------
     fastboot getvar version      # expected: 0.5        (literal at 0x5008F7E3)
     fastboot getvar product      # expected: k6789v1_64 (literal at 0x5008F814)
  Both are hard-coded strings published by fastboot_init (0x500064E4 / 0x5000651C).
  A different value means a different bootloader -> stop and re-derive everything.
  ("version-bootloader" is also available but it is the runtime getver() result,
   published at 0x500064F8 -- do not use it as the identity check.)

--------------------------------------------------------------------------------
STEP 3  THE decisive query: what does LK think of the lock record?  (5 s)
--------------------------------------------------------------------------------
     fastboot getvar secure
  Expected outputs and meaning:
     secure: no    -> validated lock_state == 3  (UNLOCKED)
                      => verifiedbootstate=orange  => the adb gate CAN pass
     secure: yes   -> locked, or the record failed validation (fail-safe 1)
                      => verifiedbootstate=green   => no ramdisk can help
     FAILED (remote: 'Failed to get secure status!')
                   -> the getter path errored => fail-safe => green
     secure: ""    -> the variable was never published (should not happen in
                      this build) => treat as unreadable

     fastboot getvar unlocked
  Expected: yes (unlocked) / no (locked). Same information, opposite polarity,
  use it as a cross-check: `secure: no` must come with `unlocked: yes`.

--------------------------------------------------------------------------------
STEP 4  Capture the whole table (one shot, for the record)
--------------------------------------------------------------------------------
     fastboot getvar all  2>&1 | tee /tmp/opencode/getvar_all.txt
  Sanity anchors in the dump:
     version: 0.5
     product: k6789v1_64
     is-userspace: no
     current-slot: a|b          (needs A/B support)
     slot-count: <n>
     off-mode-charge: 0|1
     secure / unlocked           <- the two that matter
  Note: an unknown getvar name is answered OKAY with an EMPTY value, it does
  NOT fail -- so "" means "not published", never "no".

--------------------------------------------------------------------------------
STEP 5  Turn the capture into a verdict
--------------------------------------------------------------------------------
     python3 docs/notes/lk_state_probe.py --decode /tmp/opencode/getvar_all.txt
  It prints orange / green / unreadable plus the next action.

--------------------------------------------------------------------------------
STEP 6  Independent confirmation from flash (only if step 3 was unclear)
--------------------------------------------------------------------------------
  Power off, enter preloader (VOL-UP + VOL-DOWN while plugging; USB 22d9:0006),
  then READ ONLY:

     python3 mtk.py r seccfg /tmp/opencode/seccfg.bin
     python3 docs/notes/seccfg_validate.py --info /tmp/opencode/seccfg.bin

  This replays LK's master validator offline. If it says UNDECIDABLE, the
  digest is HACC-signed and only the device can judge it -- that is exactly
  the case where step 3 is the only answer. If it says INIT_NV, LK rewrote a
  default LOCKED record: the unlock never persisted.
  Optional extra, same session, still read-only:
     python3 mtk.py r expdb /tmp/opencode/expdb.bin     # LK log ring
     python3 mtk.py r misc  /tmp/opencode/misc.bin      # BCB / boot reason

--------------------------------------------------------------------------------
STEP 7  If even fastboot is unreachable
--------------------------------------------------------------------------------
  * UART: `oem p2u on` is allowed on a LOCKED device (flagA=1 flagB=0). It muxes
    LK printk to the UART pads; look for
      "sboot_state is %d, lock_state is %d, isunlocked is %d"   (0x5008E089)
    and for the AVB line "[AVB] img_auth_required = %d"          (0x500AC46C).
  * expdb via DA (read-only): LK's log ring.
  * USB timing: see section 3 of docs/notes/reverse/re-lk-state-probe.md --
    it ONLY distinguishes orange from green against a known-green baseline of
    the SAME image. A 5 s stall on its own proves nothing.

ORDER MATTERS: fastboot first (no DA session), seccfg dump second, expdb/UART
last. Never write seccfg while diagnosing -- a failed write is what creates the
green state you are trying to measure.
"""


# ------------------------------------------------------------------ self-test
def self_test() -> int:
    tests: list[tuple[str, bool, str]] = []
    orange = """$ fastboot getvar secure
secure: no
Finished. Total time: 0.002s
$ fastboot getvar unlocked
unlocked: yes
Finished. Total time: 0.001s
"""
    green = """$ fastboot getvar secure
(bootloader) secure: yes
OKAY [  0.002s]
Finished. Total time: 0.002s
"""
    err = """$ fastboot getvar secure
FAILED (remote: 'Failed to get secure status!')
fastboot: error: Command failed
"""
    empty = """$ fastboot getvar secure
secure:
Finished. Total time: 0.001s
"""
    junk = """$ fastboot devices
abc123\tfastboot
"""

    v, n, _ = decode_transcript(orange)
    tests.append(("transcript 'secure: no' -> orange", v == "orange", v))
    v, n, _ = decode_transcript(green)
    tests.append(("transcript '(bootloader) secure: yes' -> green", v == "green", v))
    v, n, _ = decode_transcript(err)
    tests.append(("FAIL 'Failed to get secure status!' -> green", v == "green", v))
    v, n, _ = decode_transcript(empty)
    tests.append(("empty value -> unreadable", v == "unreadable", v))
    v, n, _ = decode_transcript(junk)
    tests.append(("no values at all -> unreadable", v == "unreadable", v))
    v, n, _ = decode_transcript("unlocked: yes\n")
    tests.append(("unlocked: yes alone -> orange", v == "orange", v))
    v, n, kv = decode_transcript("secure: yes\nunlocked: no\n")
    tests.append(("secure/unlocked agree -> green", v == "green", v))

    # every verdict must have a next-action block
    tests.append(("all verdicts have an action block",
                  all(k in VERDICT_ACTION for k in ("orange", "green", "unreadable")), ""))

    print("=== lk_state_probe.py self-test ===")
    ok = True
    for name, passed, detail in tests:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}" + (f"   ({detail})" if not passed else ""))
        ok &= passed
    print(f"\n{sum(1 for _, p, _ in tests if p)}/{len(tests)} passed")
    return 0 if ok else 3


# ----------------------------------------------------------------------- main
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Read LK's own lock/boot-state view without Android "
                    "(fastboot getvar probes + offline seccfg) - read only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="No device access is performed by this script.")
    ap.add_argument("--plan", action="store_true", help="print the ordered procedure (default)")
    ap.add_argument("--decode", metavar="TRANSCRIPT",
                    help="decode a captured fastboot getvar transcript")
    ap.add_argument("--verify-lk", nargs="?", const=DEFAULT_LK, metavar="LK_PAYLOAD",
                    help=f"prove the getvar surfaces exist in the LK payload (default {DEFAULT_LK})")
    ap.add_argument("--disasm", action="store_true",
                    help="with --verify-lk: also print objdump for the same VAs")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if args.verify_lk:
        return verify_lk(args.verify_lk, args.disasm)
    if args.decode:
        try:
            text = open(args.decode, "r", errors="replace").read()
        except OSError as e:
            print(f"[-] {e}")
            return 2
        verdict, notes, kv = decode_transcript(text)
        print(f"=== decoding {args.decode} ===")
        for k in ("version-bootloader", "product", "secure", "unlocked",
                  "current-slot", "slot-count", "is-userspace", "off-mode-charge"):
            if k in kv:
                print(f"  {k:<20} = {kv[k]!r}")
        print()
        for n in notes:
            print("  " + n)
        print(f"\nVERDICT: {verdict.upper()}")
        print()
        for line in VERDICT_ACTION[verdict]:
            print("  " + line)
        return 0
    print(PLAN)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
