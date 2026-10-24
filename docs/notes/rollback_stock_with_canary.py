#!/usr/bin/env python3
"""ROLLBACK to stock + LK-canary, one session, then reboot.

Purpose: get the phone back to a state that definitely booted Android before,
and at the same time answer "does LK even run?" with a cheap canary in `misc`.

Actions (all verified by readback):
  1. canary: `misc[0x804] = "XXXX"` (BCAB magic). LK's boot-control reader
     self-repairs an invalid BCAB magic by rewriting the block with "BCAB" +
     checksum (`re-lk-bootmode-priority.md` §4.1). So after one boot:
        misc[0x804] == "BCAB"  -> LK ran
        misc[0x804] == "XXXX"  -> LK never ran (preloader-level problem)
     BCB (first 14 bytes) is untouched.
  2. mirror -> locked=1 from /home/musin/rpmb_mirror_locked.bin
  3. seccfg -> stock image (default /home/musin/seccfg_before_mirror_unlock_20261024_214627.bin,
     md5 12a94a3ffbfc1a7f344e1dd6837b359a)
  4. reboot

Dry-run unless ROLLBACK_GO=1.  Env overrides: ROLLBACK_SECCFG, ROLLBACK_MIRROR.
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
SECCFG_DEF = "/home/musin/seccfg_before_mirror_unlock_20261024_214627.bin"
MIRROR_DEF = "/home/musin/rpmb_mirror_locked.bin"
STOCK_MD5 = "12a94a3ffbfc1a7f344e1dd6837b359a"
GO = os.environ.get("ROLLBACK_GO", "0") == "1"
SECCFG_SRC = os.environ.get("ROLLBACK_SECCFG", SECCFG_DEF)
MIRROR_SRC = os.environ.get("ROLLBACK_MIRROR", MIRROR_DEF)
MISC_CANARY = "/home/musin/misc_before_rollback.bin"


def rd(loader, addr, length):
    d = loader.readflash(addr=addr, length=length, filename="", parttype="user", display=False)
    d = d[0] if isinstance(d, tuple) else d
    if not d or isinstance(d, bool):
        return b""
    return bytes(d[:length])


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
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize

    def part(name):
        p = next((x for x in gpt.partentries if x.name.lower() == name), None)
        if p is None:
            raise SystemExit(f"[-] no partition {name}")
        return p, p.sector * ss, p.sectors * ss

    # --- inputs ---
    try:
        stock = open(SECCFG_SRC, "rb").read()
    except OSError:
        print(f"[-] cannot read {SECCFG_SRC}")
        return 1
    md5 = hashlib.md5(stock).hexdigest()
    print(f"[*] seccfg source: {SECCFG_SRC} ({len(stock):#x} B, md5 {md5})")
    if md5 != STOCK_MD5:
        print("[!] WARNING: this is not the known stock image (expected "
              f"{STOCK_MD5})")
    try:
        mir = open(MIRROR_SRC, "rb").read()
    except OSError:
        print(f"[-] cannot read {MIRROR_SRC}")
        return 1
    if len(mir) != 0x400:
        print(f"[-] mirror source must be 0x400 B (got {len(mir):#x})")
        return 1
    lk = struct.unpack("<I", mir[0xC:0x10])[0]
    hk = hashlib.sha256(mir[:0x3E0]).digest() == mir[0x3E0:0x400]
    print(f"[*] mirror source: {MIRROR_SRC} (md5 {hashlib.md5(mir).hexdigest()}, "
          f"locked={lk}, hash={'ok' if hk else 'BAD'})")
    if lk != 1:
        print("[-] mirror source is not locked=1 — refusing (use rpmb_mirror_locked.bin)")
        return 1

    # --- misc canary ---
    mp, mbase, mfull = part("misc")
    misc = rd(loader, mbase, mfull)
    if len(misc) != mfull:
        print("[-] misc read failed")
        return 1
    open(MISC_CANARY, "wb").write(misc)
    print(f"[*] misc saved -> {MISC_CANARY} (md5 {hashlib.md5(misc).hexdigest()})")
    print(f"[*] misc[0x800..0x820] before: {misc[0x800:0x820].hex()}")
    canary = bytearray(misc)
    canary[0x804:0x808] = b"XXXX"
    canary = bytes(canary)
    print(f"[*] misc[0x804] will be set to 'XXXX' (LK repairs it on boot if it runs)")

    if not GO:
        print("[dryrun] rerun with ROLLBACK_GO=1 to apply canary + mirror + seccfg "
              "and reboot")
        return 0

    # --- 1. misc canary ---
    print("[!] writing misc canary ...")
    ok, msg = xmlft.seccfg_write_partition(mp, canary)
    print(f"[*] misc write: {ok!r} {msg!r}")
    time.sleep(1.0)
    rb = rd(loader, mbase, 0x1000)
    print(f"[*] misc canary readback: {rb[0x800:0x820].hex()} "
          f"({'OK' if rb[0x804:0x808] == b'XXXX' else 'FAILED'})")

    # --- 2. mirror -> locked ---
    if not xmlft.custom_rpmb_init():
        print("[-] rpmb init failed")
        return 1
    D = rpmbi_derive(xmlft)
    if not D or not rpmbk_set_key(xmlft, D):
        print("[-] rpmb key setup failed")
        return 1
    cur, _ = read_rpmb_range(xmlft, MIRROR_BLOCK, MIRROR_N, "mirror")
    print(f"[*] mirror now: locked={struct.unpack('<I', cur[0xC:0x10])[0] if len(cur) == 0x400 else '?'}")
    ok = xmlft.custom_rpmb_write(MIRROR_BLOCK, MIRROR_N, mir)
    print(f"[*] mirror write: {ok}")
    time.sleep(1.0)
    rb, _ = read_rpmb_range(xmlft, MIRROR_BLOCK, MIRROR_N, "readback")
    lk2 = struct.unpack("<I", rb[0xC:0x10])[0] if len(rb) == 0x400 else None
    print(f"[*] mirror readback: locked={lk2} identical={rb == mir}")

    # --- 3. seccfg -> stock ---
    sp, sbase, sfull = part("seccfg")
    if len(stock) != sfull:
        print(f"[!] stock image is {len(stock):#x}, partition is {sfull:#x} — padding")
        stock = stock[:sfull] + bytes(max(0, sfull - len(stock)))
    print("[!] writing stock seccfg ...")
    ok2, msg2 = xmlft.seccfg_write_partition(sp, stock)
    print(f"[*] seccfg write: {ok2!r} {msg2!r}")
    time.sleep(1.0)
    chk = rd(loader, sbase, 0x1000)
    if chk[:4] == b"MMMM":
        _, ver, size, lock, dmv, sboot, endf = struct.unpack("<7I", chk[:28])
        print(f"[*] seccfg readback: lock={lock} dm_verity={dmv:#x} sboot={sboot:#x}")

    full = rd(loader, sbase, sfull)
    print(f"[*] seccfg full md5: {hashlib.md5(full).hexdigest()} "
          f"({'STOCK' if hashlib.md5(full).hexdigest() == STOCK_MD5 else 'NOT stock yet'})")

    print("[*] rebooting. Watch USB: canary result is read next session "
          "(run ./run_boot_forensics.sh); Android should come back as 22d9:2046.")
    try:
        loader.shutdown(bootmode=loader.ShutDownModes.NORMAL)
    except Exception as e:  # noqa: BLE001
        print(f"[i] shutdown: {e!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
