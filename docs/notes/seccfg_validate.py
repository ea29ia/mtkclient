#!/usr/bin/env python3
"""seccfg_validate.py -- offline re-implementation of LK's seccfg lock-state validation.

WHAT THIS IS
------------
LK (the bootloader in docs/notes/rmx3630-lk/lk_payload.bin) decides
`androidboot.verifiedbootstate` from a *validated* seccfg record:

    sec_cfg_get_lock_state()  (VA 0x50082AE0)
      -> sec_check_major_integrity_seccfg()  (VA 0x500827E8)    <- the master check
      -> *out = record[0x0C]                                   <- lock_state
         on ANY failure *out = 1 (locked)                        <- csinc @0x50082B0C
    set_boot_state(2 /*orange*/) if *out == 3                    <- 0x50053ACC/0x50053AD4

This tool replays that decision offline on a dumped `seccfg` partition.

RECORD LAYOUT (V4, 0x3C bytes) -- identical in LK, the DA2 and mtkclient:
    off  size  field
    0x00   4   magic           0x4D4D4D4D "MMMM"     (checked by LK 0x5008250C-0x50082528)
    0x04   4   seccfg_ver     == 4                    (covered by the digest)
    0x08   4   seccfg_size    == 0x3C                 (covered by the digest)
    0x0C   4   lock_state     3 = unlocked, 1/2/4 = locked  (the value LK maps to orange)
    0x10   4   dm_verity_state
    0x14   4   sboot_runtime
    0x18   4   endflag        0x45454545 "EEEE"       (covered by the digest)
    0x1C  0x20 stored_digest
Main record at partition offset 0x00, backup at 0x3C.

THE DIGEST (the only thing LK really checks)
--------------------------------------------
    stored_digest == HACC_encrypt( SHA256(record[0x00:0x1C]) )

  * SHA256(record[0:0x1C]) is plain software SHA-256 (LK 0x5007B1D0 / IV 6A09E667..).
  * HACC_encrypt is the on-die AES engine at 0x1000A008, ACON=3 (AES128|CBC|ENCRYPT),
    AKEY0..7 = 0 (key comes from the HUK/efuse path), ACFG0..3 = CBC IV =
    0x9ED40400 0x00E884A1 0xE3F083BD 0x2F4E6D8A (LK 0x50076EB8 -> 0x5007C838/900;
    DA2 0x40035030 -> 0x4003975c/800, see re-seccfg-digest-equiv.md).

  => The stored digest is DEVICE-BOUND and CANNOT be recomputed on a host.
     This tool therefore reports three different things separately:

       plain-sha256  : stored == SHA256(hdr)?   MATCH is DEFINITIVE
                       (it proves the device runs anti-clone OFF, and LK accepts).
       hacc-model    : stored == host AES-128-CBC model? CONSISTENT but NOT proof
                       (the real key is HUK-blended; this is the documented M1 model).
       device-HACC   : UNKNOWN offline by construction.

     A non-match under both host transforms is NOT a verdict -- only the device
     can decide. In that case the tool prints both branches of the LK decision and
     tells you to use the on-device probe (docs/notes/lk_state_probe.py).

FAIL-SAFE BEHAVIOUR REPRODUCED (LK 0x500827E8), all branches:
    1. read_partition("seccfg", buf, 0, 0x3000)
    2. main magic "MMMM" + digest OK            -> MAIN_OK
       (and if the backup magic is "MMMM", LK zeroes the backup slot: 0x3C..0x78)
    3. main bad, backup magic+digest OK         -> "sec_restore": backup copied over
                                                   main, flash rewritten, effective
                                                   state = backup's lock_state
    4. both bad                                 -> init-NV: LK SIGNS and WRITES a
                                                   default LOCKED record
                                                   (ver=4, size=0x3C, lock=1, dv=0,
                                                   sboot=0) -> effective locked
    In cases 3/4 the *getter* in the same boot returns the fail-safe 1 (locked)
    before the rewrite is visible -> `verifiedbootstate=green`, no orange.

    NOTE: this tool performs NO writes. Cases 3/4 are reported as "LK WOULD WRITE".

CLI
---
    python3 seccfg_validate.py --info seccfg.bin
    python3 seccfg_validate.py --info seccfg.bin --digest-mode plain
    python3 seccfg_validate.py --info seccfg.bin --digest-mode hacc-model
    python3 seccfg_validate.py --info seccfg.bin --json
    python3 seccfg_validate.py --self-test

--digest-mode selects what counts as "LK accepts this record":
    auto        (default) stored == plain SHA-256 -> YES (definitive);
                anything else -> UNKNOWN (only the device HACC can decide).
    plain       assume the device runs anti-clone OFF, i.e. LK compares against
                the plain SHA-256. Then a mismatch IS a reject (definitive
                inside that assumption).
    hacc-model  assume LK's transform equals the host AES-CBC model (also an
                assumption -- the real key is HUK-blended).
Only `auto` is safe on a dump of unknown provenance; the other two exist to make
synthetic tests and "device runs plain" hypotheses decidable.

Exit codes:
    0  analysis completed (whatever the verdict -- the verdict is the output)
    2  file unreadable / too short to contain a record at all
    3  --self-test failure
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys

# ---------------------------------------------------------------- constants ---
MAGIC = 0x4D4D4D4D          # "MMMM"
ENDFLAG = 0x45454545        # "EEEE"
REC_LEN = 0x3C              # 60 bytes
HDR_LEN = 0x1C              # 28 bytes hashed by LK
DIGEST_LEN = 0x20           # 32 bytes
MAIN_OFF = 0x00
BAK_OFF = 0x3C
LK_READ_LEN = 0x3000        # LK malloc(0x3000) + read_partition(.., 0x3000)

LOCK_UNLOCKED = 3
LOCK_LOCKED = 1
LOCK_NAMES = {1: "LOCKED(1)", 2: "UNLOCKED_OR_LOCKED(2)", 3: "UNLOCKED(3)", 4: "LOCKED(4)"}

# CBC IV words = ACFG0..3. NB: 0x9ED40400, not the 0x9ED44000 typo of the first
# write-up (see re-seccfg-digest-equiv.md TL;DR #1 and fix #5).
HACC_SEEDS = (0x9ED40400, 0x00E884A1, 0xE3F083BD, 0x2F4E6D8A)

# Reference md5s already used by the existing repo scripts (unlock_state_check.py,
# check_seccfg.py). Used only to recognise a known dump -- never to validate.
STOCK_MD5_FULL = "12a94a3ffbfc1a7f344e1dd6837b359a"   # full partition, lock_state=4
STOCK_MD5_4K = "1687ff2654c6d2a52e26a200c6b2ce48"     # first 0x1000 bytes

PASS = "PASS"
FAIL = "FAIL"
INFO = "INFO"
UNKNOWN = "UNKNOWN"


# ------------------------------------------------------------------ helpers ---
def md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def have_model() -> bool:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: F401
        return True
    except Exception:
        return False


def hacc_model(digest: bytes) -> bytes:
    """Host approximation of LK's HACC transform of the 32-byte SHA-256.

    AES-128-CBC encrypt, key = 16 zero bytes, IV = ACFG0..3 as little-endian words.
    This is the documented M1 model (re-seccfg-digest-equiv.md section 3). It is
    NOT the device transform: the real AES key is HUK-blended. Only useful as a
    discriminator: if a captured record matches this, the register model is
    confirmed end-to-end.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = struct.pack("<4I", *HACC_SEEDS)
    enc = Cipher(algorithms.AES(bytes(16)), modes.CBC(iv)).encryptor()
    return enc.update(digest) + enc.finalize()


def parse_record(rec: bytes) -> dict:
    """Parse a 0x3C record. Does NOT judge it."""
    f = struct.unpack("<7I", rec[:HDR_LEN])
    return {
        "magic": f[0],
        "ver": f[1],
        "size": f[2],
        "lock_state": f[3],
        "dm_verity": f[4],
        "sboot_runtime": f[5],
        "endflag": f[6],
        "digest": rec[HDR_LEN:REC_LEN],
        "hdr": rec[:HDR_LEN],
    }


def hexdump(b: bytes, base: int = 0, width: int = 16) -> str:
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        hx = " ".join(f"{c:02x}" for c in chunk)
        txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
        out.append(f"  {base + i:04x}  {hx:<{width * 3}} {txt}")
    return "\n".join(out)


# ----------------------------------------------------------------- analysis ---
class RecordVerdict:
    """Result of LK's per-record check (0x500824FC) as reproducible offline."""

    def __init__(self, name: str, raw: bytes, model: str):
        self.name = name
        self.raw = raw
        self.model = model
        self.zero = not any(raw)
        self.parsed = parse_record(raw) if len(raw) >= REC_LEN else None
        self.checks: list[tuple[str, str, str]] = []
        self.magic_ok = bool(self.parsed and self.parsed["magic"] == MAGIC)
        self.plain_ok = False
        self.model_ok = False
        self.digest_ok = False
        self.digest_note = ""
        if self.parsed is None:
            self.checks.append(("length", FAIL, f"{len(raw)} < {REC_LEN}"))
            return
        self._check_magic()
        self._check_structure()
        self._check_digest(model)

    # -- individual checks ---------------------------------------------------
    def _check_magic(self) -> None:
        p = self.parsed
        self.checks.append((
            "magic 'MMMM'",
            PASS if self.magic_ok else FAIL,
            f"0x{p['magic']:08X}" + ("" if self.magic_ok else "  (LK 0x50082528 -> b.ne: err 0x10003004)"),
        ))

    def _check_structure(self) -> None:
        """LK does not read these explicitly, but they are inside the hashed 0x1C
        bytes, so an inconsistency here can only survive if the record was signed
        with that exact content. Reported as INFO to stay faithful to LK."""
        p = self.parsed
        st = PASS if p["ver"] == 4 else INFO
        self.checks.append(("ver == 4", st, f"{p['ver']}"))
        st = PASS if p["size"] == REC_LEN else INFO
        self.checks.append(("size == 0x3C", st, f"0x{p['size']:X}"))
        st = PASS if p["endflag"] == ENDFLAG else INFO
        self.checks.append(("endflag 'EEEE'", st, f"0x{p['endflag']:08X}"))
        ls = p["lock_state"]
        self.checks.append((
            "lock_state sane",
            PASS if ls in LOCK_NAMES else INFO,
            f"{ls} ({LOCK_NAMES.get(ls, 'unknown')})",
        ))
        self.checks.append(("dm_verity_state", INFO, f"{p['dm_verity']}"))
        self.checks.append(("sboot_runtime", INFO, f"{p['sboot_runtime']}"))

    def _check_digest(self, model: str) -> None:
        p = self.parsed
        want = sha256(p["hdr"])
        stored = p["digest"]
        self.checks.append(("sha256(hdr)", INFO, want.hex()))
        self.checks.append(("stored digest", INFO, stored.hex()))
        self.plain_ok = stored == want
        self.checks.append((
            "digest == plain sha256(hdr)",
            PASS if self.plain_ok else FAIL,
            "anti-clone OFF on device; LK accepts" if self.plain_ok
            else "no (expected -- normal for a stock/HACC record)",
        ))
        if model != "plain":
            if have_model():
                try:
                    m = hacc_model(want)
                    self.model_ok = stored == m
                    self.checks.append((
                        "digest == HACC host MODEL",
                        INFO if self.model_ok else INFO,
                        ("CONSISTENT: " if self.model_ok else "no: ") + m.hex()[:16] + "..",
                    ))
                except Exception as e:  # pragma: no cover
                    self.checks.append(("digest == HACC host MODEL", INFO, f"skip ({e})"))
            else:
                self.checks.append(("digest == HACC host MODEL", INFO, "skip (no cryptography)"))

        if self.plain_ok:
            self.digest_verdict = PASS
            self.digest_note = "definitive: stored digest is the plain SHA-256"
        elif self.model_ok:
            self.digest_verdict = UNKNOWN
            self.digest_note = "consistent with the HACC host model; device HACC still unproven"
        else:
            self.digest_verdict = UNKNOWN
            self.digest_note = ("cannot be decided offline (device HACC key is HUK-blended)")

        # What counts as "LK accepts" depends on the stated assumption.
        if model == "plain":
            self.digest_ok = self.plain_ok
            self.digest_note = ("assumption: device runs anti-clone OFF; "
                                + ("digest matches" if self.plain_ok else "digest mismatch -> reject"))
        elif model == "hacc-model":
            self.digest_ok = self.model_ok
            self.digest_note = ("assumption: LK transform == host model; "
                                + ("digest matches" if self.model_ok else "digest mismatch -> reject"))
        else:  # auto
            self.digest_ok = self.plain_ok

    # -- LK decision ---------------------------------------------------------
    @property
    def lk_accept(self) -> str:
        """'YES' | 'NO' | 'UNKNOWN' -- would LK's 0x500824FC return 0 for this record?"""
        if self.parsed is None or not self.magic_ok:
            return "NO"
        if self.model == "auto":
            return "YES" if self.plain_ok else "UNKNOWN"
        return "YES" if self.digest_ok else "NO"

    @property
    def is_blank(self) -> bool:
        return self.zero

    def summary(self) -> str:
        if self.is_blank:
            return "blank (all zero) -- LK: magic != MMMM -> invalid"
        if self.parsed is None:
            return "too short"
        p = self.parsed
        return (f"magic={p['magic']:08X} ver={p['ver']} size=0x{p['size']:X} "
                f"lock={p['lock_state']} dv={p['dm_verity']} sboot={p['sboot_runtime']} "
                f"end={p['endflag']:08X} lk_accept={self.lk_accept}")


class Report:
    def __init__(self, blob: bytes, model: str):
        self.blob = blob
        self.model = model
        self.size = len(blob)
        self.head = blob[:LK_READ_LEN]
        self.main = RecordVerdict("main", self.head[MAIN_OFF:MAIN_OFF + REC_LEN], model)
        self.bak = RecordVerdict("backup", self.head[BAK_OFF:BAK_OFF + REC_LEN], model)
        self.md5_full = md5(blob)
        self.md5_4k = md5(blob[:0x1000]) if len(blob) >= 0x1000 else md5(blob)
        self.master, self.branches, self.note = self._master()

    # -- LK 0x500827E8 -------------------------------------------------------
    def _master(self) -> tuple[str, list[str], str]:
        m, b = self.main, self.bak
        if m.lk_accept == "YES":
            br = []
            if b.magic_ok:
                br.append("LK would zero the backup slot (+0x3C..0x78) -- 0x500827E8 step 6")
            br.append("effective lock_state = main +0x0C")
            return "MAIN_OK", br, ""
        if b.lk_accept == "YES":
            br = ["LK would copy backup -> main and rewrite +0x00..0x3C ('sec_restore')",
                  "effective lock_state = backup +0x0C"]
            return "SEC_RESTORE", br, ""
        if "UNKNOWN" in (m.lk_accept, b.lk_accept) and (m.magic_ok or b.magic_ok):
            br = []
            if m.magic_ok:
                br.append(f"if device HACC accepts main -> MAIN_OK, lock={m.parsed['lock_state']}")
            if b.magic_ok:
                br.append(f"if device HACC accepts backup -> SEC_RESTORE, lock={b.parsed['lock_state']}")
            br.append("if every magic-valid record is rejected -> INIT_NV, lock=1 (LOCKED)")
            return "UNDECIDABLE", br, (
                "A record with a non-plain digest can only be judged by the device's HACC "
                "engine. Use docs/notes/lk_state_probe.py (fastboot getvar secure) or "
                "the runtime print at LK 0x5008E089.")
        br = ["LK would build a default LOCKED record (ver=4 size=0x3C lock=1 dv=0 sboot=0),",
              "re-sign it with HACC and WRITE it to seccfg+0x00, then re-read.",
              "This boot: getter fail-safe -> lock_state = 1"]
        return "INIT_NV", br, "this tool writes nothing; the rewrite is only predicted"

    # -- derived boot state --------------------------------------------------
    def effective_lock(self) -> int | None:
        if self.master == "MAIN_OK":
            return self.main.parsed["lock_state"]
        if self.master == "SEC_RESTORE":
            return self.bak.parsed["lock_state"]
        if self.master == "INIT_NV":
            return LOCK_LOCKED
        return None

    def boot_state(self) -> tuple[str | None, str]:
        """(color, reason). None when offline-undecidable."""
        if self.master == "UNDECIDABLE":
            return None, "record acceptance needs the device HACC"
        ls = self.effective_lock()
        if ls == LOCK_UNLOCKED:
            return "orange", "validated lock_state == 3 -> LK set_boot_state(2) @0x50053AD4"
        return "green", f"validated lock_state = {ls} != 3 (or fail-safe 1) -> green @0x50053CC8"

    def boot_state_if_avb_fails(self) -> str:
        return "red (0x50053CC8 skipped; 0x50053F78 -> power off, no orange)"

    # -- rendering -----------------------------------------------------------
    def as_dict(self) -> dict:
        color, reason = self.boot_state()
        return {
            "file_bytes": self.size,
            "md5_full": self.md5_full,
            "md5_4k": self.md5_4k,
            "stock_match": {
                "full": self.md5_full == STOCK_MD5_FULL,
                "4k": self.md5_4k == STOCK_MD5_4K,
            },
            "main": {
                "summary": self.main.summary(),
                "lk_accept": self.main.lk_accept,
                "fields": {k: (v.hex() if isinstance(v, bytes) else v)
                           for k, v in (self.main.parsed or {}).items()},
                "checks": self.main.checks,
            },
            "backup": {
                "summary": self.bak.summary(),
                "lk_accept": self.bak.lk_accept,
                "fields": {k: (v.hex() if isinstance(v, bytes) else v)
                           for k, v in (self.bak.parsed or {}).items()},
                "checks": self.bak.checks,
            },
            "master": self.master,
            "master_actions": self.branches,
            "effective_lock_state": self.effective_lock(),
            "verifiedbootstate": color,
            "verifiedbootstate_reason": reason,
            "verifiedbootstate_if_avb_fails": self.boot_state_if_avb_fails(),
            "note": self.note,
        }

    def render(self) -> str:
        L = []
        L.append("=== seccfg record analysis (LK model) ===")
        L.append(f"file      : {self.size} bytes")
        L.append(f"digest mode: {self.model}"
                 + ("" if self.model == "auto"
                    else "   (assumption about the device HACC stage)"))
        L.append(f"md5 full  : {self.md5_full}"
                 + ("  == STOCK (lock=4) reference" if self.md5_full == STOCK_MD5_FULL else ""))
        L.append(f"md5 1st 4k: {self.md5_4k}"
                 + ("  == STOCK reference" if self.md5_4k == STOCK_MD5_4K else ""))
        L.append("")

        for label, rv, off in (("MAIN  (seccfg+0x00)", self.main, MAIN_OFF),
                               ("BACKUP(seccfg+0x3C)", self.bak, BAK_OFF)):
            L.append(f"--- {label} ---")
            if rv.is_blank:
                L.append("  blank record (all zero)")
                continue
            L.append(hexdump(rv.raw, base=off))
            if rv.parsed:
                p = rv.parsed
                L.append(f"  magic       : 0x{p['magic']:08X} {_ascii(p['magic'])}")
                L.append(f"  seccfg_ver  : {p['ver']}")
                L.append(f"  seccfg_size : 0x{p['size']:X}")
                L.append(f"  lock_state  : {p['lock_state']}  ({LOCK_NAMES.get(p['lock_state'], '?')})")
                L.append(f"  dm_verity   : {p['dm_verity']}")
                L.append(f"  sboot       : {p['sboot_runtime']}")
                L.append(f"  endflag     : 0x{p['endflag']:08X} {_ascii(p['endflag'])}")
            for name, st, detail in rv.checks:
                L.append(f"  [{st:8}] {name:<28} {detail}")
            L.append(f"  => LK per-record verdict (0x500824FC): {rv.lk_accept}"
                     + (f"  ({rv.digest_note})" if rv.digest_note else ""))
            L.append("")

        L.append("--- master check (0x500827E8 sec_check_major_integrity_seccfg) ---")
        L.append(f"  verdict : {self.master}")
        for b in self.branches:
            L.append(f"            * {b}")
        if self.note:
            L.append(f"  note    : {self.note}")
        L.append("")

        color, reason = self.boot_state()
        L.append("--- what LK would put on the kernel cmdline ---")
        if color is None:
            L.append("  androidboot.verifiedbootstate = <undecidable offline>")
            L.append(f"  reason: {reason}")
            L.append("  if the record validates:  lock=%s -> %s"
                     % (self.main.parsed["lock_state"] if self.main.parsed else "?",
                        "orange" if (self.main.parsed and self.main.parsed["lock_state"] == 3) else "green"))
            L.append("  if it does not:           lock=1 (fail-safe) -> green")
        else:
            L.append(f"  androidboot.verifiedbootstate = {color}")
            L.append(f"  reason: {reason}")
        L.append(f"  (AVB failure would instead give: {self.boot_state_if_avb_fails()})")
        L.append("")
        L.append("--- implication for the adb gate (SecondStageMain) ---")
        L.append("  IsDeviceUnlocked() == (verifiedbootstate == \"orange\")")
        if color == "orange":
            L.append("  => the gate CAN be satisfied: if adb is still unauthorized, the")
            L.append("     problem is in first/second stage (adb_debug.prop not loaded),")
            L.append("     NOT in the boot state.")
        elif color == "green":
            L.append("  => gate NOT satisfied: /debug_ramdisk is unmounted before")
            L.append("     PropertyInit(), so ro.adb.secure stays 1 -> unauthorized.")
            L.append("     Fix the lock record / unlock properly, not the ramdisk.")
        else:
            L.append("  => run the on-device probe (fastboot getvar secure) to settle it.")
        return "\n".join(L)


def _ascii(v: int) -> str:
    b = struct.pack(">I", v)
    return repr(b) if all(32 <= c < 127 for c in b) else ""


# ------------------------------------------------------------------ self-test -
def _mk_record(lock: int, *, ver: int = 4, dv: int = 0, sboot: int = 0,
               magic: int = MAGIC, endflag: int = ENDFLAG,
               digest_mode: str = "plain") -> bytes:
    hdr = struct.pack("<7I", magic, ver, REC_LEN, lock, dv, sboot, endflag)
    d = sha256(hdr)
    if digest_mode == "model":
        d = hacc_model(d)
    elif digest_mode == "garbage":
        d = bytes([0xA5]) * 32
    return hdr + d


def _mk_partition(main: bytes, bak: bytes | None = None, size: int = 0x4000) -> bytes:
    blob = bytearray(size)
    blob[MAIN_OFF:MAIN_OFF + REC_LEN] = main
    if bak is not None:
        blob[BAK_OFF:BAK_OFF + REC_LEN] = bak
    return bytes(blob)


def self_test() -> int:
    tests: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        tests.append((name, ok, detail))

    model = "hacc-model" if have_model() else "plain"

    # 1. valid unlocked record, plain digest -> orange, MAIN_OK
    blob = _mk_partition(_mk_record(3))
    r = Report(blob, "auto")
    color, _ = r.boot_state()
    add("valid main lock=3 -> orange", r.master == "MAIN_OK" and color == "orange",
        f"master={r.master} color={color}")

    # 2. same header, lock flipped 3 -> 1 *without* re-signing: LK must reject it.
    #    This is the negative control that proves the digest is actually checked.
    #    Run in plain mode so a mismatch is decidable (device assumed anti-clone OFF).
    bad = bytearray(_mk_record(3))
    bad[0x0C] = 1
    r = Report(_mk_partition(bytes(bad)), "plain")
    color, _ = r.boot_state()
    add("tampered lock 3->1 (no re-sign) -> rejected -> green",
        r.main.lk_accept == "NO" and r.master == "INIT_NV" and color == "green",
        f"lk_accept={r.main.lk_accept} master={r.master} color={color}")
    # 2b. the same input under 'auto' must stay honest (UNDECIDABLE, both branches)
    r = Report(_mk_partition(bytes(bad)), "auto")
    color, _ = r.boot_state()
    add("tampered record under 'auto' -> UNDECIDABLE, not a false PASS",
        r.main.lk_accept == "UNKNOWN" and r.master == "UNDECIDABLE" and color is None,
        f"lk_accept={r.main.lk_accept} master={r.master} color={color}")

    # 3. corrupted magic, valid digest -> rejected
    r = Report(_mk_partition(_mk_record(3, magic=0x4D4D4D00)), "plain")
    color, _ = r.boot_state()
    add("bad magic -> rejected -> green",
        r.main.lk_accept == "NO" and r.master == "INIT_NV" and color == "green",
        f"master={r.master} color={color}")

    # 4. corrupted digest byte -> rejected
    rec = bytearray(_mk_record(3))
    rec[0x20] ^= 0xFF
    r = Report(_mk_partition(bytes(rec)), "plain")
    color, _ = r.boot_state()
    add("corrupt digest byte -> rejected -> green",
        r.main.lk_accept == "NO" and color == "green",
        f"master={r.master} color={color}")

    # 5. valid locked record -> green
    r = Report(_mk_partition(_mk_record(1)), "auto")
    color, _ = r.boot_state()
    add("valid main lock=1 -> green", r.master == "MAIN_OK" and color == "green",
        f"master={r.master} color={color}")

    # 6. main bad, backup valid lock=3 -> SEC_RESTORE -> orange
    r = Report(_mk_partition(_mk_record(1, magic=0xDEADBEEF), _mk_record(3)), "auto")
    color, _ = r.boot_state()
    add("main bad + backup lock=3 -> SEC_RESTORE -> orange",
        r.master == "SEC_RESTORE" and color == "orange",
        f"master={r.master} color={color}")

    # 7. all zero partition -> INIT_NV -> green
    r = Report(bytes(0x4000), "auto")
    color, _ = r.boot_state()
    add("blank partition -> INIT_NV -> green",
        r.master == "INIT_NV" and color == "green", f"master={r.master} color={color}")

    # 8. HACC host-model record: plain does not match, model does -> UNDECIDABLE,
    #    and both branches must be printed.
    if have_model():
        r = Report(_mk_partition(_mk_record(3, digest_mode="model")), "auto")
        add("model-signed record -> model CONSISTENT, plain no, master UNDECIDABLE",
            (not r.main.plain_ok) and r.main.model_ok and r.master == "UNDECIDABLE",
            f"plain={r.main.plain_ok} model={r.main.model_ok} master={r.master}")
        r = Report(_mk_partition(_mk_record(3, digest_mode="model")), "hacc-model")
        add("model-signed record under hacc-model mode -> MAIN_OK -> orange",
            r.main.lk_accept == "YES" and r.master == "MAIN_OK"
            and r.boot_state()[0] == "orange",
            f"lk_accept={r.main.lk_accept} master={r.master}")
    else:
        add("model-signed record (skipped: no cryptography)", True, "skipped")

    # 9. short file -> structure error, no crash
    r = Report(b"MMMM" + bytes(10), "auto")
    add("short file handled", r.master == "INIT_NV", f"master={r.master}")

    # 10. backup self-heal keeps the *backup* lock byte (2, not 3) -> green
    r = Report(_mk_partition(bytes(0x3C), _mk_record(2)), "auto")
    color, _ = r.boot_state()
    add("backup lock=2 -> SEC_RESTORE -> green",
        r.master == "SEC_RESTORE" and color == "green",
        f"master={r.master} color={color}")

    print("=== seccfg_validate.py self-test ===")
    ok = True
    for name, passed, detail in tests:
        print(f"[{'PASS' if passed else 'FAIL'}] {name}"
              + (f"   ({detail})" if detail and not passed else ""))
        ok &= passed
    print(f"\n{sum(1 for _, p, _ in tests if p)}/{len(tests)} passed")
    return 0 if ok else 3


# ----------------------------------------------------------------------- main --
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Offline replay of LK's seccfg lock-state validation "
                    "(what verifiedbootstate LK would emit).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="No device access, no writes.")
    ap.add_argument("--info", metavar="SECCFG.bin",
                    help="dump of the seccfg partition (or at least its first 0x78 bytes)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--digest-mode", choices=("auto", "plain", "hacc-model"), default="auto",
                    help="what counts as 'LK accepts': auto (only plain sha256 is "
                         "definitive) | plain | hacc-model")
    ap.add_argument("--self-test", action="store_true",
                    help="synthesise valid/corrupted records and prove the verdicts flip")
    args = ap.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.info:
        ap.print_help()
        return 2
    try:
        blob = open(args.info, "rb").read()
    except OSError as e:
        print(f"[-] cannot read {args.info}: {e}", file=sys.stderr)
        return 2
    if len(blob) < REC_LEN:
        print(f"[-] {args.info}: {len(blob)} bytes, too short for a 0x3C record", file=sys.stderr)
        return 2

    rep = Report(blob, args.digest_mode)
    if args.json:
        print(json.dumps(rep.as_dict(), indent=2))
    else:
        print(rep.render())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
