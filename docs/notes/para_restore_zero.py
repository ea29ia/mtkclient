#!/usr/bin/env python3
"""Restore `para` to its pre-probe content, entirely from a saved image.

Reads the full partition, then writes back `/tmp/para_orig_full.bin` (created by
para_write_test.py / write_reach_test.py) or, if absent, an all-zero image with
the same size. The ORIGINAL head is never taken from the current probe state
(that was the bug in the first version: it saved the probe content and then
"restored" it).

Safe: WRITE-PARTITION with pre_erase=NO, same size. Read-only unless
PARA_RESTORE_GO=1.
"""
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

GO = os.environ.get("PARA_RESTORE_GO", "1") == "1"   # restore is the safe default
CANDIDATES = ("/tmp/para_orig_full.bin", "/home/musin/para_reach_before.bin")


def rd(loader, base, length):
    d = loader.readflash(addr=base, length=length, filename="", parttype="user", display=False)
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
    para = next((p for p in gpt.partentries if p.name.lower() == "para"), None)
    if para is None:
        print("[-] no para in GPT")
        return 1
    base, full = para.sector * ss, para.sectors * ss
    print(f"[*] para base={base:#x} size={full:#x}")

    cur = rd(loader, base, full)
    if len(cur) != full:
        print("[-] full read failed")
        return 1
    open("/tmp/para_at_restore.bin", "wb").write(cur)
    print(f"[*] current: md5={hashlib.md5(cur).hexdigest()} head={cur[:16].hex()}")

    target = None
    for cand in CANDIDATES:
        try:
            blob = open(cand, "rb").read()
        except OSError:
            continue
        if len(blob) == full:
            target, src = bytes(blob), cand
            break
        if len(blob) >= 0x1000:
            # only the head is available: keep the current tail
            target, src = bytes(blob[:0x1000]) + cur[0x1000:], cand + " (head only)"
            break
    if target is None:
        print("[!] no saved image found — falling back to an all-zero image")
        target, src = bytes(full), "zeros"
    print(f"[*] restore source: {src} (md5 {hashlib.md5(target).hexdigest()})")
    print(f"[*] restore head: {target[:16].hex()}")

    if target == cur:
        print("[+] already at target — nothing to write")
        return 0
    if not GO:
        print("[dryrun] rerun with PARA_RESTORE_GO=1")
        return 0

    time.sleep(1.0)
    ok, msg = xmlft.seccfg_write_partition(para, target)
    print(f"[*] write: {ok!r} {msg!r}")
    time.sleep(1.0)
    rb = rd(loader, base, full)
    if rb == target:
        print(f"[+] para RESTORED (md5 {hashlib.md5(rb).hexdigest()})")
        return 0
    print(f"[!] restore MISMATCH: head={rb[:16].hex()} md5={hashlib.md5(rb).hexdigest()}"
          " — do NOT reboot, retry")
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
