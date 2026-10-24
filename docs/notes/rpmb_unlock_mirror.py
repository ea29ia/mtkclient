#!/usr/bin/env python3
"""PERSISTENT UNLOCK STEP: clear the RPMB boot-info mirror, then forge seccfg.

Why: LK's `double_check_lock_state` (0x500556C4) reads RPMB blocks
**0x1DC-0x1DF** (0x1DC is the JEDEC frame address field) and, if
`block+0xC == 1`, calls `sec_cfg_set_lock_state(locked)` and powers off —
which is why the forged seccfg lock=3 does not survive a reboot.  The mirror
on this unit was read out on 2026-10-24 (log `test9a`):

    +0x00 sboot=0  +0x04 dev_info=1  +0x08 bootmode=0  +0x0C locked=1
    +0x10 aux=0    +0x20 "RMX3630RU"
    SHA-256(payload) matches the stored digest at +0x3E0  => hash VALID

So the mirror is readable through the DA and its format is exactly as modelled.
If the DA can also *write* it with the SEJ-derived key, flipping +0xC to 0 and
re-hashing gives a clean unlocked mirror; one successful unlocked boot then
makes LK maintain it (`set_boot_info_to_rpmb(1,1)`).

RISKS / SAFETY
- If the derived key is NOT the device RPMB key, the write is rejected by the
  storage device (JEDEC result 1) and **nothing changes**.  We then stop and do
  not touch seccfg.
- A successful write bumps the hardware RPMB write counter.  t-base SFSRP keeps
  per-partition counters and fatals with "Mismatch between the counters" if the
  jump is unexpected; worst case trustedStorage/keystore is down for a boot
  (widevine broken), which is acceptable here and recoverable by DA.
- The original block is saved to /home/musin/rpmb_mirror_before.bin.  Run with
  MIRROR_RESTORE=1 to write it back (if the key works, this also works).
- seccfg is backed up (8 MB) before the write, as always.

USAGE
  dry-run (read + build only):      ./run_rpmb_unlock_mirror.sh
  real run:                         MIRROR_WRITE_GO=1 ./run_rpmb_unlock_mirror.sh
  restore the saved mirror block:   MIRROR_RESTORE=1 ./run_rpmb_unlock_mirror.sh
"""
import hashlib
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
os.chdir(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)

from planb_recon2 import rpmbk_set_key, rpmbi_derive, read_rpmb_range  # noqa: E402

MIRROR_BLOCK = 0x1DC
MIRROR_N = 4
BEFORE = "/home/musin/rpmb_mirror_before.bin"
NEW = "/home/musin/rpmb_mirror_new.bin"
GO = os.environ.get("MIRROR_WRITE_GO", "0") == "1"
RESTORE = os.environ.get("MIRROR_RESTORE", "0") == "1"


def show(blk: bytes, label: str):
    sboot, devinfo, bootmode, locked = struct.unpack("<4I", blk[:16])
    aux = struct.unpack("<I", blk[0x10:0x14])[0]
    calc = hashlib.sha256(blk[:0x3E0]).digest()
    stored = blk[0x3E0:0x400]
    print(f"[*] {label}: sboot={sboot} dev_info={devinfo} bootmode={bootmode} "
          f"locked={locked} aux={aux:#x}")
    print(f"    hash {'VALID' if calc == stored else 'MISMATCH'} "
          f"({calc.hex()[:16]}…)  id@0x20={blk[0x20:0x30]!r}")
    return locked, calc == stored


def build_unlocked(blk: bytes) -> bytes:
    b = bytearray(blk)
    b[0xC:0x10] = b"\x00\x00\x00\x00"          # locked bit -> 0 (unlocked)
    b[0x3E0:0x400] = b"\x00" * 0x20
    b[0x3E0:0x400] = hashlib.sha256(bytes(b[:0x3E0])).digest()
    return bytes(b)


def main():
    import argparse
    import mtk as mtk_cli
    parser = mtk_cli.create_base_parser()
    parser = argparse.ArgumentParser(parents=[parser], description=mtk_cli.INFO)
    sub = parser.add_subparsers(dest='cmd', required=False)
    sub.add_parser('custom')
    args = parser.parse_args(sys.argv[1:] + ['custom'])
    from mtkclient.Library.mtk_main import Main
    mtk = Main(args).run(parser)
    if mtk is None:
        print("[-] connect failed")
        return 1
    loader = mtk.daloader
    xmlft = loader.xmlft

    # --- key ---
    print("[*] custom_rpmb_init(None) — DA derives the SEJ RPMB key ...")
    if not xmlft.custom_rpmb_init():
        print("[-] rpmb_init failed")
        return 1
    D = rpmbi_derive(xmlft)
    if D is None:
        print("[-] cannot obtain derived key")
        return 1
    print(f"[+] key D = {D.hex()}")
    if not rpmbk_set_key(xmlft, D):
        print("[-] cannot set key D")
        return 1

    # --- read current mirror ---
    cur, _ = read_rpmb_range(xmlft, MIRROR_BLOCK, MIRROR_N, "mirror")
    if len(cur) != 0x400:
        print(f"[-] mirror read failed ({len(cur):#x} != 0x400)")
        return 1
    open(BEFORE, "wb").write(cur)
    locked, hash_ok = show(cur, "current mirror")
    print(f"[*] saved -> {BEFORE} (md5 {hashlib.md5(cur).hexdigest()})")

    # --- restore mode ---
    if RESTORE:
        try:
            orig = open(BEFORE, "rb").read()
        except OSError:
            print(f"[-] {BEFORE} missing")
            return 1
        print(f"[!] restoring the saved mirror block ({len(orig):#x} B) ...")
        ok = xmlft.custom_rpmb_write(MIRROR_BLOCK, MIRROR_N, orig)
        print(f"[*] write: {ok}")
        rb, _ = read_rpmb_range(xmlft, MIRROR_BLOCK, MIRROR_N, "readback")
        print(f"[*] readback identical: {rb == orig}")
        show(rb, "restored") if len(rb) == 0x400 else None
        return 0 if ok and rb == orig else 1

    if not hash_ok:
        print("[!] current mirror hash is INVALID — LK already treats it as "
              "unlocked (memset path). Nothing to do; just write seccfg=3.")
    elif locked != 1:
        print(f"[+] mirror already unlocked (locked={locked}) — no RPMB write needed")
    else:
        print("[*] mirror says LOCKED (locked=1) — this is what re-locks the device")

    new = build_unlocked(cur)
    open(NEW, "wb").write(new)
    show(new, "target mirror")
    diff = [i for i in range(0x400) if new[i] != cur[i]]
    print(f"[*] target differs at {len(diff)} byte(s): "
          f"{[hex(i) for i in diff[:8]]}{'…' if len(diff) > 8 else ''}")
    print(f"[*] target saved -> {NEW}")

    if not GO:
        print("[dryrun] rerun with MIRROR_WRITE_GO=1 to write the mirror + seccfg "
              "and reboot")
        return 0

    if locked != 1 and hash_ok:
        print("[i] mirror already unlocked — skipping the RPMB write")
    else:
        print(f"[!] WRITING mirror blocks {MIRROR_BLOCK:#x}..{MIRROR_BLOCK + MIRROR_N - 1:#x} "
              f"with key D ...")
        ok = xmlft.custom_rpmb_write(MIRROR_BLOCK, MIRROR_N, new)
        print(f"[*] rpmb write returned {ok}")
        time.sleep(1.0)
        rb, _ = read_rpmb_range(xmlft, MIRROR_BLOCK, MIRROR_N, "readback")
        if len(rb) != 0x400:
            print("[-] readback failed — ABORT (seccfg untouched)")
            return 1
        locked2, hash2 = show(rb, "after write")
        if rb != new:
            print("[!] MIRROR WRITE DID NOT STICK — derived key is probably not the "
                  "device RPMB key (auth rejected). seccfg left untouched; device "
                  "state unchanged. Original block: " + BEFORE)
            return 2
        print(f"[+] MIRROR UPDATED: locked={locked2}, hash {'valid' if hash2 else 'INVALID'}")
        if not hash2:
            print("[i] hash invalid is also fine: LK zeroes the buffer => mirror=0")

    # --- seccfg unlock (same session) ---
    _, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed — seccfg untouched")
        return 1
    ss = gpt.sectorsize
    seccfg = next((p for p in gpt.partentries if p.name.lower() == "seccfg"), None)
    if seccfg is None:
        print("[-] no seccfg in GPT")
        return 1
    full = seccfg.sectors * ss
    ts = time.strftime("%Y%m%d_%H%M%S")
    bk = f"/home/musin/seccfg_before_mirror_unlock_{ts}.bin"
    if not loader.readflash(addr=seccfg.sector * ss, length=full, filename=bk,
                            parttype="user", display=False):
        print("[-] seccfg backup failed — ABORT")
        return 1
    blob = open(bk, "rb").read()
    if blob[:4] != b"MMMM":
        print("[-] backup structure unexpected — ABORT")
        return 1
    print(f"[+] seccfg backup: {bk} (md5 {hashlib.md5(blob).hexdigest()})")

    hwc = xmlft.cryptosetup()
    from mtkclient.Library.Hardware.seccfg import SecCfgV4
    sc = SecCfgV4(hwc, mtk, xmlft.custom_sej_hw)
    if not sc.parse(blob[:0x1000]):
        print("[-] V4 parse failed — ABORT")
        return 1
    print(f"[*] parsed: ver={sc.seccfg_ver} size={sc.seccfg_size:#x} "
          f"lock={sc.lock_state} dm_verity={sc.dm_verity_state:#x}")
    if sc.lock_state == 3:
        print("[i] seccfg already 3")
        payload = blob[:0x200]
    else:
        ret, payload = sc.create(lockflag="unlock")
        if not ret:
            print(f"[-] create failed: {payload}")
            return 1
    wd = bytes(payload) + bytes(full - len(payload))
    print(f"[!] WRITING seccfg lock=3 ({len(wd):#x} B) ...")
    time.sleep(1.0)
    ok, msg = xmlft.seccfg_write_partition(seccfg, wd)
    print(f"[*] write: {ok!r} {msg!r}")
    if not ok:
        return 1
    time.sleep(1.0)
    chk = loader.readflash(addr=seccfg.sector * ss, length=0x1000, filename="",
                           parttype="user", display=False)
    chk = chk[0] if isinstance(chk, tuple) else chk
    if not chk or chk[:4] != b"MMMM":
        print("[-] readback empty — do NOT reboot blindly; re-check with "
              "seccfg_snapshot.py")
        return 1
    magic, ver, size, lock, dmv, sboot, endf = struct.unpack("<7I", chk[:28])
    print(f"[*] readback: magic={magic:#x} ver={ver} size={size:#x} lock={lock} "
          f"dm_verity={dmv:#x} sboot={sboot:#x} end={endf:#x}")
    if lock != 3:
        print(f"[-] readback lock={lock} != 3 — not rebooting")
        return 1

    print("[+] MIRROR=unlocked + seccfg lock=3 written in the same session")
    print("[*] rebooting. Next boot should be UNLOCKED (Orange State) and the "
          "mirror should be rewritten by LK as unlocked.")
    print("[*] after boot: `lsusb | grep 22d9`, `fastboot devices`, `adb devices`, "
          "then `./run_seccfg_snapshot.sh` to confirm persistence.")
    try:
        loader.shutdown(bootmode=loader.ShutDownModes.NORMAL)
    except Exception as e:  # noqa: BLE001
        print(f"[i] shutdown: {e!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
