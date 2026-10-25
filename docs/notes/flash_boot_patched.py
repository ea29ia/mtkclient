#!/usr/bin/env python3
"""Flash the patched boot image into boot_a (with a full backup first).

The patched image was produced by boot_ramdisk_patch.py:
  * `ro.adb.secure=0`  -> adbd accepts any host (the dead screen cannot approve)
  * `ro.debuggable=1`  -> adbd as root
  * `persist.sys.usb.config=adb` -> first boot exposes the ADB interface
  * `/adb_keys`        -> host public key pre-authorized
  * ramdisk recompressed as LZ4-legacy, header v4 sizes unchanged/updated

Safety:
  * the ENTIRE boot_a partition (64 MB) is backed up first;
  * the written range is read back and md5-compared;
  * no reboot (the preloader waits for DA while the cable is attached);
  * restore: BOOT_RESTORE=<backup> FLASH_GO=1 ./run_flash_boot_patched.sh

Requires FLASH_GO=1.
"""
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

IMG = os.environ.get("FLASH_IMG", "/home/musin/boot_patched.img")
GO = os.environ.get("FLASH_GO", "0") == "1"
RESTORE = os.environ.get("BOOT_RESTORE", "")
PART = os.environ.get("FLASH_PART", "boot_a")


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
    p = next((x for x in gpt.partentries if x.name.lower() == PART), None)
    if p is None:
        print(f"[-] no {PART}")
        return 1
    base, full = p.sector * ss, p.sectors * ss
    print(f"[*] {PART}: LBA {p.sector:#x} base {base:#x} size {full:#x}")

    # ---------------- restore mode ----------------
    if RESTORE:
        src = RESTORE
        if not os.path.exists(src):
            print(f"[-] {src} not found")
            return 1
        blob = open(src, "rb").read()
        print(f"[*] restoring {src} ({len(blob):#x} B) -> {PART}")
        if not GO:
            print("[dryrun] FLASH_GO=1 to write")
            return 0
        ok, msg = xmlft.seccfg_write_partition(p, blob)
        print(f"[*] write: {ok!r} {msg!r}")
        time.sleep(1.0)
        rb = rd(loader, base, len(blob))
        print(f"[*] readback identical: {rb == blob}")
        if rb == blob:
            print(f"[+] {PART} restored")
            return 0
        print("[!] restore MISMATCH — retry, do not power-cycle into Android")
        return 1

    # ---------------- flash patched ----------------
    if not os.path.exists(IMG):
        print(f"[-] {IMG} missing — run boot_ramdisk_patch.py first")
        return 1
    blob = open(IMG, "rb").read()
    want = b"VNDRBOOT" if PART.startswith("vendor_boot") else b"ANDROID!"
    if blob[:8] != want:
        print(f"[-] {IMG} has no {want.decode('ascii')} magic (got {blob[:8]!r})")
        return 1
    import struct
    if want == b"VNDRBOOT":
        print(f"[*] image: {len(blob):#x} B, vendor_ramdisk="
              f"{struct.unpack_from('<I', blob, 0x18)[0]:#x}")
    else:
        print(f"[*] image: {len(blob):#x} B, "
              f"kernel={struct.unpack_from('<I', blob, 8)[0]:#x}, "
              f"ramdisk={struct.unpack_from('<I', blob, 0xC)[0]:#x}")
    if len(blob) > full:
        print("[-] image larger than the partition")
        return 1

    ts = time.strftime("%Y%m%d_%H%M%S")
    bk = f"/home/musin/{PART}_backup_{ts}.img"
    print(f"[!] backing up the whole {PART} ({full:#x} B) -> {bk} ...")
    ok = loader.readflash(addr=base, length=full, filename=bk, parttype="user", display=False)
    if not ok:
        print("[-] backup failed — ABORT (no writes without a backup)")
        return 1
    cur = open(bk, "rb").read()
    print(f"[+] backup: {len(cur):#x} B md5={hashlib.md5(cur).hexdigest()}")

    if not GO:
        print(f"[dryrun] FLASH_GO=1 to write the patched boot to {PART}")
        return 0

    print(f"[!] WRITING patched boot ({len(blob):#x} B) -> {PART} ...")
    time.sleep(2)
    ok, msg = xmlft.seccfg_write_partition(p, blob)
    print(f"[*] write: {ok!r} {msg!r}")
    if not ok:
        return 1
    time.sleep(1.0)
    rb = rd(loader, base, len(blob))
    same = rb == blob
    print(f"[*] readback: {len(rb):#x} B, identical={same}, "
          f"md5={hashlib.md5(rb).hexdigest() if rb else '?'}")
    if not same:
        print("[!] READBACK MISMATCH — restoring the backup immediately")
        xmlft.seccfg_write_partition(p, cur)
        rb2 = rd(loader, base, len(cur))
        print(f"[*] restore identical: {rb2 == cur}")
        return 1

    print("\n[+] PATCHED BOOT WRITTEN and verified.")
    print(f"[*] backup: {bk}")
    print("[*] Now: unplug the cable -> hold Power ~10 s (off) -> press Power ~3 s "
          "-> wait 60-90 s WITHOUT the cable -> plug in.")
    print("[*] Then: `adb devices` should show the serial WITHOUT 'unauthorized'.")
    print("[*] If Android does not boot (AVB), restore with:")
    print(f"      BOOT_RESTORE={bk} FLASH_GO=1 ./run_flash_boot_patched.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
