#!/usr/bin/env python3
"""Plan C step 2 (WRITE ONLY): boot-recovery BCB into 'misc' 0x000-0x800.

Verification is done SEPARATELY (a second run can't open USB while this
process holds the port):  ./run_misc_read.sh  -> check first bytes of
/home/musin/misc_after.bin for "boot-recovery".

misc layout (live read 2026-10-24): BCB zone 0x000-0x7FF (all zeros),
BCAB boot_control at 0x800 — NOT touched.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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

    print("[!] writing boot-recovery BCB (0x800 B; BCAB at 0x800 NOT touched)"
          " -> next boot enters RECOVERY. Ctrl-C to abort.")
    import time
    time.sleep(5)
    payload = BCB
    xmlft = getattr(loader, "xmlft", None)
    if xmlft is None:
        from mtkclient.Library.DA.xmlflash.extension.v6 import XmlFlashExt
        xmlft = XmlFlashExt(loader.mtk, loader.da, loader.loglevel)
    ok, msg = xmlft.seccfg_write_partition(misc, payload)
    if not ok:
        print(f"[-] misc write failed: {msg}")
        return 1

    print("[+] write command accepted by DA.")
    print("[!] NOW REBOOT: disconnect and hold Power 10 s, or run:")
    print("      python -u mtk.py reset --preloader <...> --loader <...>")
    print("[*] verifying NEXT session:  ./run_misc_read.sh   (misc_after.bin)")
    print("    expect misc[0:0xE] = 'boot-recovery'")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
