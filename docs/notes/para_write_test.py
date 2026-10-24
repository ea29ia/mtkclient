#!/usr/bin/env python3
"""Write-path proof on the unprotected `para` partition (first 0x1000 bytes).

Writes a distinctive 0x1000-byte pattern over the first block, keeps the REST of
the partition byte-identical (full-partition read + rewrite), reads the head
back, and restores the original image from the saved copy.

History: the original version compared a 0x1000 read against a 1024-byte
pattern (`(b"PARATEST"*128)[:0x1000]`), so its success branch was unreachable —
the real proof was the printed hex. Fixed per audit #2.

Read-only unless PARA_GO=1.
"""
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

GO = os.environ.get("PARA_GO", "0") == "1"
ORIG_FULL = "/tmp/para_orig_full.bin"
PATTERN = (b"PARATEST" * 0x200)[:0x1000]
assert len(PATTERN) == 0x1000


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
    print(f"[+] para: LBA {para.sector:#x} base {base:#x} size {full:#x}")

    orig = rd(loader, base, full)
    if len(orig) != full:
        print(f"[-] full read failed ({len(orig):#x} != {full:#x})")
        return 1
    open(ORIG_FULL, "wb").write(orig)
    print(f"[*] original: md5={hashlib.md5(orig).hexdigest()} -> {ORIG_FULL}")
    print(f"[*] head: {orig[:32].hex()}")

    blob = PATTERN + orig[0x1000:]
    assert len(blob) == full, "blob length bug"

    if not GO:
        print("[dryrun] would write the 0x1000 pattern to para. Rerun with PARA_GO=1")
        return 0

    verdict = 9
    try:
        print("[!] WRITE-PARTITION pattern -> para ...")
        time.sleep(3)
        ok, msg = xmlft.seccfg_write_partition(para, blob)
        print(f"[*] write result: {ok!r} {msg!r}")
        if ok:
            time.sleep(1.0)
            rb = rd(loader, base, 0x1000)
            if rb == PATTERN:
                print("[+] PARA COMMITTED — write path works")
                verdict = 0
            elif rb == orig[:0x1000]:
                print("[-] para UNCHANGED — write did not commit")
                verdict = 1
            else:
                print(f"[!] para changed but != pattern: {rb[:32].hex()}")
                verdict = 1
        else:
            verdict = 2
    finally:
        print("[*] restoring para original (always) ...")
        try:
            time.sleep(1.0)
            ok2, msg2 = xmlft.seccfg_write_partition(para, orig)
            print(f"[*] restore write: {ok2!r} {msg2!r}")
            time.sleep(1.0)
            cur = rd(loader, base, full)
            if cur == orig:
                print(f"[+] para restored (md5 {hashlib.md5(cur).hexdigest()})")
            else:
                print("[!] RESTORE MISMATCH — rerun /home/musin/run_para_restore.sh "
                      "immediately, do not reboot")
                verdict = 6
        except Exception as e:  # noqa: BLE001
            print(f"[!] RESTORE FAILED: {e!r} — restore from {ORIG_FULL}")
            verdict = 7
    return verdict


if __name__ == "__main__":
    sys.exit(main() or 0)
