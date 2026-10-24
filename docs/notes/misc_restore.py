#!/usr/bin/env python3
"""misc rollback: restore the FULL misc partition from /home/musin/misc_before.bin
(0x80000 bytes) via WRITE-PARTITION by name (seccfg_write_partition), same route
that PROVED correct at full-partition size on seccfg (2026-10-23).

DRY-RUN by default. Set env PLAN_C_WRITE=1 for the real write.

Why full size: the OPLUS DA2 WRITE-PARTITION handler erases the whole partition
and only commits full-size writes (observed: the 0x800 BCB write did NOT commit —
misc[0x000:0x800] stayed zero; the 7-byte BCAB delta at 0x80C/0x818 is boot-time
bookkeeping from the reboot between the two reads, not write damage). Writing
the full 0x80000 image restores BCB zone (zeros) AND BCAB at 0x800 atomically.

After the write, verify IN THE SAME SESSION: re-read 0x1000 bytes and compare
against the backup head; then run run_misc_read.sh in a NEXT session for the
full after-image.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

BACKUP = os.environ.get("MISC_BACKUP", "/home/musin/misc_before.bin")
PARTITION = os.environ.get("MISC_PARTNAME", "misc")


def main():
    import argparse
    import time
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

    try:
        data = open(BACKUP, "rb").read()
    except OSError as e:
        print(f"[-] cannot read backup {BACKUP}: {e}")
        return 1

    xmlft = getattr(loader, "xmlft", None)
    if xmlft is None:
        from mtkclient.Library.DA.xmlflash.extension.v6 import XmlFlashExt
        xmlft = XmlFlashExt(loader.mtk, loader.da, loader.loglevel)

    data_gpt, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = getattr(gpt, "sectorsize", 4096) or 4096

    part = None
    for p in gpt.partentries:
        if p.name.lower() == PARTITION.lower():
            part = p
            break
    if part is None:
        print(f"[-] no '{PARTITION}' partition in GPT")
        return 1
    fullsize = part.sectors * ss
    print(f"[+] {PARTITION}: LBA {part.sector:#x}..{part.sector + part.sectors:#x} "
          f"size {fullsize:#x}, LBA {ss}")

    if len(data) != fullsize:
        print(f"[!] backup size {len(data):#x} != partition size {fullsize:#x}")
        if len(data) > fullsize:
            print("[-] backup larger than partition - aborting")
            return 1
        print(f"[+] padding {fullsize - len(data):#x} zero bytes to full size")
        data = data + bytes(fullsize - len(data))

    print(f"[*] backup head 0x800: {data[:0x10].hex()} (expect zeros: BCB zone)")
    print(f"[*] backup BCAB 0x800..0x820: {data[0x800:0x820].hex()}")

    if os.environ.get("PLAN_C_WRITE", "0") != "1":
        print("[*] DRY-RUN (PLAN_C_WRITE!=1): no write performed.")
        print("[*] real run:  PLAN_C_WRITE=1 ./run_misc_restore.sh")
        return 0

    print("[!] WRITING full partition image to misc (erase + program). "
          "Ctrl-C to abort.")
    time.sleep(5)
    ok, msg = xmlft.seccfg_write_partition(part, data)
    if not ok:
        print(f"[-] misc write failed: {msg}")
        return 1

    print("[+] write accepted. Same-session readback check...")
    time.sleep(1.0)
    check = xmlft.xflash.readflash(
        addr=part.sector * ss,
        length=0x1000, filename="", parttype="user", display=False)
    if not check:
        print("[-] readback empty - write did NOT commit")
        return 1
    mismatches = sum(
        1 for i in range(0x1000) if check[i] != data[i])
    if mismatches == 0:
        print("[+] readback matches backup for 0x0..0x1000 - WRITE COMMITTED")
        print("[!] NOW REBOOT: disconnect and hold Power 10 s, or:")
        print("      python -u mtk.py reset --preloader <...> --loader <...>")
        print("[*] full verify NEXT session: ./run_misc_read.sh -> misc_after.bin,")
        print("    then: cmp /home/musin/misc_before.bin /home/musin/misc_after.bin")
        return 0
    print(f"[-] readback MISMATCH: {mismatches} bytes differ in 0x0..0x1000")
    print(f"    readback BCAB: {check[0x800:0x820].hex()}")
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
