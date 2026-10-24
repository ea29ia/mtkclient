#!/usr/bin/env python3
"""Snapshot the current seccfg (read-only) and diff it against the original
backup; also compare misc with the earlier backup.

Saves: /home/musin/seccfg_after_unlock_reboot.bin (8 MB)
"""
import os, sys, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
ORIG = "/home/musin/seccfg_backup.bin"
OUT = "/home/musin/seccfg_after_unlock_reboot.bin"
MISC_ORIG = "/home/musin/rmx3630_backup_20261024_095607/misc.img"


def rd(loader, base, length):
    d = loader.readflash(addr=base, length=length, filename="", parttype="user", display=False)
    d = d[0] if isinstance(d, tuple) else d
    return bytes(d[:length]) if d and not isinstance(d, bool) else b""


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
        print("[-] connect failed"); return 1
    loader = mtk.daloader
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize
    p = next(x for x in gpt.partentries if x.name.lower() == "seccfg")
    base, full = p.sector * ss, p.sectors * ss

    now = rd(loader, base, full)
    print(f"[*] current seccfg: {len(now):#x} B md5={hashlib.md5(now).hexdigest()}")
    open(OUT, "wb").write(now)
    print(f"[*] saved -> {OUT}")

    orig = open(ORIG, "rb").read()
    print(f"[*] original: {len(orig):#x} B md5={hashlib.md5(orig).hexdigest()}")
    if len(now) == len(orig):
        diffs = [i for i in range(len(orig)) if now[i] != orig[i]]
        print(f"[*] differing bytes: {len(diffs)}")
        if diffs:
            print(f"[*] first diff @ {diffs[0]:#x}, last @ {diffs[-1]:#x}")
            # groups
            groups, start, prev = [], diffs[0], diffs[0]
            for i in diffs[1:]:
                if i != prev + 1:
                    groups.append((start, prev))
                    start = i
                prev = i
            groups.append((start, prev))
            print(f"[*] diff ranges ({len(groups)}):")
            for a, b in groups[:40]:
                print(f"    {a:#010x}..{b:#010x}  ({b-a+1} B)")
            for i in range(0, 0x40):
                a, b = orig[i], now[i]
                if a != b:
                    print(f"    byte {i:#04x}: {a:02x} -> {b:02x}")
    # misc
    mp = next(x for x in gpt.partentries if x.name.lower() == "misc")
    mi = rd(loader, mp.sector * ss, 0x1000)
    if os.path.exists(MISC_ORIG):
        mo = open(MISC_ORIG, "rb").read()[:0x1000]
        print(f"[*] misc: md5={hashlib.md5(mi).hexdigest()} vs backup {hashlib.md5(mo).hexdigest()} "
              f"({'SAME' if mi == mo else 'DIFF'})")
    print("[*] done")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
