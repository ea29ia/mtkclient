#!/usr/bin/env python3
"""Plan C: write a boot-recovery BCB into 'misc' via DA2 WRITE-PARTITION.

Evidence: docs/notes/reverse/re-lk-rescue-surfaces.md §4 (PROVEN):
 - LK misc BCB reader checks 14 bytes at misc offset 0 for the prefix
   "boot-recovery" -> next boot enters RECOVERY.
 - misc is WRITE-POLICY-ALLOWED on this DA2 (re-da2-policy-map.md).
 - LK reads ONLY "boot-recovery" on the boot path; "boot-fastboot" BCB is
   NOT read at boot (no evidence) — so we target recovery, and from the
   recovery menu (volume keys, dead-screen friendly) pick
   "Reboot to bootloader" -> fastbootd -> flashing unlock (frp gate armed).

BCB layout (Android bootloader_control): 8B command + 8B status + 8B
recovery message ("recovery\n<args>") + 8B stage + 24B reserved... The LK
reader here only needs the "boot-recovery" command string at offset 0 and
zeros after (per the RE note: 14 bytes checked, prefix match).

Usage (repo root):
  python docs/notes/plan_c_bcb_recovery.py           # dry-run: read misc
  PLAN_C_WRITE=1 python docs/notes/plan_c_bcb_recovery.py   # real write
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

WRITE = os.environ.get("PLAN_C_WRITE", "0") == "1"
# LK BCB writer memsets 0x1800 B, but the live misc holds the BCAB
# boot_control block at offset 0x800 (proven by live read 2026-10-24).
# Write only the first 0x800 bytes: command string + zeros; BCAB untouched.
BCB = b"boot-recovery\x00" + b"\x00" * (0x800 - 0xE)


def main():
    import argparse
    import mtk as mtk_cli
    parser = mtk_cli.create_base_parser()
    parser = argparse.ArgumentParser(parents=[parser], description=mtk_cli.INFO)
    sub = parser.add_subparsers(dest='cmd', required=False)
    sub.add_parser('custom')
    args = parser.parse_args(sys.argv[1:] + ['custom'])
    from mtkclient.Library.mtk_main import Main
    mtk_main = Main(args)
    mtk = mtk_main.run(parser)
    if mtk is None:
        print("[-] connect failed")
        return 1
    loader = mtk.daloader

    data, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = getattr(gpt, "sectorsize", 4096) or 4096

    misc = None
    for p in gpt.partentries:
        if p.name.lower() == "misc":
            misc = p
            break
    if misc is None:
        print("[-] no 'misc' partition in GPT")
        return 1
    size = misc.sectors * ss
    print(f"[+] misc: LBA {misc.sector:#x}..{misc.sector + misc.sectors:#x} "
          f"size {size:#x}")

    cur = None
    # Proven CLI path (run_misc_read.sh used mtk.py r misc successfully);
    # direct loader.readflash on small blocks hangs on this DA2 (EIO-class).
    import subprocess
    print("[*] reading misc back via mtk.py r (CLI, proven)...")
    r = subprocess.run(
        [sys.executable, "-u", "mtk.py", "r", "misc", "/tmp/misc_check.bin",
         "--preloader", os.environ.get("PRELOADER",
             "/home/musin/firmware/extracted/IMAGES/preloader_k6789v1_64.bin"),
         "--loader", os.environ.get("DALOADER",
             "/home/musin/firmware/extracted/IMAGES/download_agent/DA_BR.bin")],
        capture_output=True, text=True, timeout=180)
    if os.path.exists("/tmp/misc_check.bin"):
        blob = open("/tmp/misc_check.bin", "rb").read()
        cur = blob[:0x100]
        print(f"[*] misc[0:0x20]: {cur[:0x20].hex()} ({cur[:0xE]!r})")
    else:
        print("[!] readback via CLI failed — will write without pre-read")

    if not WRITE:
        print("[dryrun] nothing written. Rerun with PLAN_C_WRITE=1 to write "
              "the boot-recovery BCB.")
        return 0

    print("[!] writing boot-recovery BCB (first 0x800 bytes; BCAB at 0x800 "
          "is NOT touched) -> next boot enters RECOVERY. Ctrl-C to abort.")
    import time
    time.sleep(5)
    payload = BCB if len(BCB) <= size else BCB[:size]
    xmlft = getattr(loader, "xmlft", None)
    if xmlft is None:
        from mtkclient.Library.DA.xmlflash.extension.v6 import XmlFlashExt
        xmlft = XmlFlashExt(loader.mtk, loader.da, loader.loglevel)
    ok, msg = xmlft.seccfg_write_partition(misc, payload)
    if not ok:
        print(f"[-] misc write failed: {msg}")
        return 1

    # verify via the proven CLI path
    if os.path.exists("/tmp/misc_check.bin"):
        os.remove("/tmp/misc_check.bin")
    r2 = subprocess.run(
        [sys.executable, "-u", "mtk.py", "r", "misc", "/tmp/misc_check2.bin",
         "--preloader", os.environ.get("PRELOADER",
             "/home/musin/firmware/extracted/IMAGES/preloader_k6789v1_64.bin"),
         "--loader", os.environ.get("DALOADER",
             "/home/musin/firmware/extracted/IMAGES/download_agent/DA_BR.bin")],
        capture_output=True, text=True, timeout=180)
    chk = None
    if os.path.exists("/tmp/misc_check2.bin"):
        blob = open("/tmp/misc_check2.bin", "rb").read()
        chk = blob[:0x100]
        print(f"[*] misc[0:0x20] after write: {chk[:0x20].hex()}")
    if chk and chk.startswith(b"boot-recovery"):
        print("[+] VERIFY OK: misc now holds boot-recovery BCB (BCAB intact "
              f"at 0x800: {blob[0x800:0x808]!r})")
        print("[*] rebooting (normal); on next boot LK enters RECOVERY.")
        print("    In recovery (volume keys): look for 'Reboot to bootloader'")
        print("    -> fastbootd -> fastboot flashing unlock + Vol-UP <= 5 s")
        loader.shutdown(bootmode=loader.ShutDownModes.NORMAL)
        return 0
    print(f"[-] VERIFY FAILED: misc reads {chk[:14] if chk else None!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
