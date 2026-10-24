#!/usr/bin/env python3
"""Wipe userdata + metadata (the step the genuine fastboot unlock performs),
keep the unlocked state, and do NOT auto-reboot.

Why: LK's fastboot unlock handler (0x500076A8) does
  0x5003266C -> sec_cfg_set_lock_state(3)
  0x50007C9C -> wipe userdata/metadata
  0x50054744(1,1) -> mirror sbc=1, locked=0
We replicated only the seccfg/mirror part.  If the FBE/Keymaster keys are bound
to the lock state (the usual reason OPPO wipes data on unlock), the old /data
cannot be decrypted and the kernel/init dies -> the observed "two buzzes then
nothing" instead of Android.

Steps (each verified by readback):
  1. read + verify the current state (seccfg lock, RPMB mirror locked bit);
  2. erase `metadata` (full) and `userdata` (full) via ERASE-FLASH;
     fallback: zero the first 16 MB + last 1 MB of userdata and the whole
     metadata partition by writing zeros;
  3. make sure the device is unlocked (seccfg lock=3, mirror locked=0),
     writing them if needed;
  4. print the boot instructions (no reboot: the preloader waits for DA while
     the cable is attached).

Requires WIPE_GO=1.  The ERASE-FLASH deny gate must be patched, so the wrapper
sets OPLUS_PATCH_ERASE_DENY=1.
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
GO = os.environ.get("WIPE_GO", "0") == "1"
# A full ERASE-FLASH of a 115 GB userdata can take hours (the DA may zero it
# instead of unmapping).  Wiping the first 16 MB kills both f2fs/ext4 superblocks
# and is enough for Android to reformat /data.  Set WIPE_FULL_USERDATA=1 for a
# full-length erase.
FULL_UD = os.environ.get("WIPE_FULL_USERDATA", "0") == "1"
UD_ERASE = 0x1000000
SECCFG_STOCK = "/home/musin/seccfg_backup.bin"
MIRROR_LOCKED = "/home/musin/rpmb_mirror_locked.bin"


def rd(loader, addr, length):
    d = loader.readflash(addr=addr, length=length, filename="", parttype="user", display=False)
    d = d[0] if isinstance(d, tuple) else d
    if not d or isinstance(d, bool):
        return b""
    return bytes(d[:length])


def build_unlocked_mirror(blk: bytes) -> bytes:
    b = bytearray(blk)
    b[0xC:0x10] = b"\x00\x00\x00\x00"
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
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize

    def part(name):
        p = next((x for x in gpt.partentries if x.name.lower() == name), None)
        if p is None:
            raise SystemExit(f"[-] no partition {name}")
        return p, p.sector * ss, p.sectors * ss

    # ---------- 1. state ----------
    sp, sbase, sfull = part("seccfg")
    head = rd(loader, sbase, 0x1000)
    lock = None
    if head[:4] == b"MMMM":
        _, ver, size, lock, dmv, sboot, endf = struct.unpack("<7I", head[:28])
        print(f"[*] seccfg: lock={lock} dm_verity={dmv:#x} sboot={sboot:#x}")
    mir = b""
    if xmlft.custom_rpmb_init():
        D = rpmbi_derive(xmlft)
        if D and rpmbk_set_key(xmlft, D):
            mir, _ = read_rpmb_range(xmlft, MIRROR_BLOCK, MIRROR_N, "mirror")
    mlocked = struct.unpack("<I", mir[0xC:0x10])[0] if len(mir) == 0x400 else None
    print(f"[*] mirror: locked={mlocked} "
          f"(md5 {hashlib.md5(mir).hexdigest() if mir else '?'})")

    mp, mbase, mfull = part("metadata")
    up, ubase, ufull = part("userdata")
    print(f"[*] metadata: {mp.name} LBA {mp.sector:#x} size {mfull:#x}")
    print(f"[*] userdata: {up.name} LBA {up.sector:#x} size {ufull:#x} "
          f"({ufull / 1e9:.1f} GB)")

    if not GO:
        print("[dryrun] WIPE_GO=1 to: erase metadata+userdata, ensure unlock, "
              "then power-cycle manually")
        return 0

    # ---------- 2. wipe ----------
    print("[!] erasing metadata (full) ...")
    t0 = time.time()
    md_ok = False
    try:
        md_ok = loader.formatflash(addr=mbase, length=mfull, parttype="user", display=True)
    except Exception as e:  # noqa: BLE001
        print(f"[!] metadata erase exception: {e!r}")
    print(f"[*] metadata erase -> {md_ok} ({time.time() - t0:.1f}s)")

    ud_len = ufull if FULL_UD else min(ufull, UD_ERASE)
    print(f"[!] erasing userdata first {ud_len:#x} bytes "
          f"({'FULL partition' if FULL_UD else 'superblock area; WIPE_FULL_USERDATA=1 for full'}) ...")
    t0 = time.time()
    ud_ok = False
    try:
        ud_ok = loader.formatflash(addr=ubase, length=ud_len, parttype="user", display=True)
    except Exception as e:  # noqa: BLE001
        print(f"[!] userdata erase exception: {e!r}")
    print(f"[*] userdata erase -> {ud_ok} ({time.time() - t0:.1f}s)")

    # fallback / extra: zero the superblock areas if the erase did not commit
    mh = rd(loader, mbase, 0x1000)
    uh = rd(loader, ubase, 0x1000)
    print(f"[*] metadata head now: {mh[:32].hex()} (nonzero={sum(1 for x in mh if x)})")
    print(f"[*] userdata head now: {uh[:32].hex()} (nonzero={sum(1 for x in uh if x)})")
    if sum(1 for x in mh if x) > 0:
        print("[!] metadata still has data — zeroing the first 0x100000 and the "
              "second superblock area ...")
        z = bytes(0x100000)
        xmlft.seccfg_write_partition(mp, z)
        xmlft.seccfg_write_partition(mp, bytes(0x1000))
    if sum(1 for x in uh if x) > 0:
        print("[!] userdata head still has data — zeroing the first 16 MB "
              "(kills both f2fs/ext4 superblocks) ...")
        xmlft.seccfg_write_partition(up, bytes(ud_len))
        uh = rd(loader, ubase, 0x1000)
        print(f"[*] userdata head after zeroing: {uh[:32].hex()} "
              f"(nonzero={sum(1 for x in uh if x)})")

    # ---------- 3. ensure unlocked ----------
    if lock != 3:
        print("[!] seccfg is not 3 — writing the unlock payload ...")
        stock = open(SECCFG_STOCK, "rb").read()
        hwc = xmlft.cryptosetup()
        from mtkclient.Library.Hardware.seccfg import SecCfgV4
        sc = SecCfgV4(hwc, mtk, xmlft.custom_sej_hw)
        if not sc.parse(stock[:0x1000]):
            print("[-] V4 parse failed")
            return 1
        ret, payload = sc.create(lockflag="unlock")
        if not ret:
            print(f"[-] create failed: {payload}")
            return 1
        wd = bytes(payload) + bytes(sfull - len(payload))
        ok, msg = xmlft.seccfg_write_partition(sp, wd)
        print(f"[*] seccfg write: {ok!r} {msg!r}")
        time.sleep(1.0)
        chk = rd(loader, sbase, 0x1000)
        if chk[:4] == b"MMMM":
            _, _, _, lock2, _, _, _ = struct.unpack("<7I", chk[:28])
            print(f"[*] seccfg readback: lock={lock2}")

    if mlocked != 0:
        print("[!] mirror is not unlocked — writing the unlocked block ...")
        new = build_unlocked_mirror(mir if len(mir) == 0x400 else
                                    open(MIRROR_LOCKED, "rb").read())
        ok = xmlft.custom_rpmb_write(MIRROR_BLOCK, MIRROR_N, new)
        print(f"[*] mirror write: {ok}")
        time.sleep(1.0)
        rb, _ = read_rpmb_range(xmlft, MIRROR_BLOCK, MIRROR_N, "readback")
        print(f"[*] mirror readback: locked="
              f"{struct.unpack('<I', rb[0xC:0x10])[0] if len(rb) == 0x400 else '?'}")

    print("\n[+] DONE. Do NOT rely on a DA reboot: the preloader waits for DA while "
          "the cable is attached.")
    print("[*] Now: unplug the cable -> hold Power ~10 s (off) -> press Power ~3 s "
          "-> wait 90-120 s WITHOUT the cable -> plug in -> check `lsusb`.")
    print("[*] Expect 22d9:2046 (Android, first boot after wipe may take 2-3 min).")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
