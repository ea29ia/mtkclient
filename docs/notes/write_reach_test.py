#!/usr/bin/env python3
"""Q1 test: does a full-partition WRITE-PARTITION really program the TAIL?

The unlock write sent 8 MB to `seccfg`; after the reboot the untouched vendor
marker at offset 0x200 was present again.  Either the DA write loop stopped
after the first block, or something restored the whole partition.  This test
discriminates: it writes an image with a distinctive marker BOTH at offset 0
and at the last 0x1000 bytes of the unprotected `para` partition, re-reads both
ends, then restores the original image and verifies it end-to-end.

`para` is all zero on this unit, so the test image is zeros + two markers.

WRITE unless WRITE_REACH_GO=1 (default: dry-run, reads and prints the plan).
"""
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

GO = os.environ.get("WRITE_REACH_GO", "0") == "1"
MARK_HEAD = (b"REACHHEAD" * 128)[:0x1000]
MARK_TAIL = (b"REACHTAIL" * 128)[:0x1000]
BEFORE = "/home/musin/para_reach_before.bin"
AFTER = "/home/musin/para_reach_after_restore.bin"


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
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = gpt.sectorsize
    para = next((p for p in gpt.partentries if p.name.lower() == "para"), None)
    if para is None:
        print("[-] no para in GPT")
        return 1
    base = para.sector * ss
    full = para.sectors * ss
    print(f"[+] para: LBA {para.sector:#x} base {base:#x} size {full:#x}")

    orig = rd(loader, base, full)
    if len(orig) != full:
        print(f"[-] full read failed: {len(orig):#x} != {full:#x}")
        return 1
    open(BEFORE, "wb").write(orig)
    print(f"[*] original: md5={hashlib.md5(orig).hexdigest()} "
          f"nonzero={sum(1 for b in orig if b)} saved -> {BEFORE}")
    if orig[:0x1000] != bytes(0x1000):
        print("[!] para head is NOT zero — image below will overwrite it, "
              "but it is saved and restored at the end")

    img = bytearray(full)
    img[0:0x1000] = MARK_HEAD
    img[full - 0x1000:full] = MARK_TAIL
    img = bytes(img)
    print(f"[*] test image: markers at 0x0 and 0x{full - 0x1000:x} "
          f"({len(img):#x} B, md5={hashlib.md5(img).hexdigest()})")

    if not GO:
        print("[dryrun] rerun with WRITE_REACH_GO=1 to write + verify + restore")
        return 0

    print("[!] WRITING full para (WRITE-PARTITION, pre_erase=NO) ...")
    time.sleep(3)
    ok, msg = xmlft.seccfg_write_partition(para, img)
    print(f"[*] write: {ok!r} {msg!r}")
    if not ok:
        return 1

    time.sleep(1.0)
    head = rd(loader, base, 0x1000)
    tail = rd(loader, base + full - 0x1000, 0x1000)
    head_ok = head == MARK_HEAD
    tail_ok = tail == MARK_TAIL
    print(f"[*] head marker: {'OK' if head_ok else 'MISSING'} ({head[:16].hex()})")
    print(f"[*] tail marker: {'OK' if tail_ok else 'MISSING'} ({tail[:16].hex()})")

    if head_ok and tail_ok:
        print("[+] FULL WRITE CONFIRMED — the DA programs the whole region; "
              "the reverted seccfg 0x200 marker means an EXTERNAL full restore")
        verdict = 0
    elif head_ok and not tail_ok:
        print("[!] PARTIAL WRITE — the DA write loop stops early; the 8 MB "
              "seccfg payload never reached 0x200+, which explains the revert "
              "without any restore path")
        verdict = 2
    elif head_ok is False and tail_ok is False:
        print("[-] NOTHING CHANGED — write did not commit at all")
        verdict = 3
    else:
        print("[?] unexpected: tail only")
        verdict = 4

    # --- restore ---
    print("[*] restoring para original ...")
    time.sleep(1.0)
    ok2, msg2 = xmlft.seccfg_write_partition(para, orig)
    print(f"[*] restore write: {ok2!r} {msg2!r}")
    time.sleep(1.0)
    cur = rd(loader, base, full)
    open(AFTER, "wb").write(cur)
    same = cur == orig
    print(f"[*] restore verify: {'IDENTICAL' if same else 'MISMATCH'} "
          f"(md5 {hashlib.md5(cur).hexdigest()})")
    if not same:
        print("[!] RESTORE MISMATCH — rerun immediately, do not reboot")
        return 5
    print("[+] para restored")
    return verdict


if __name__ == "__main__":
    sys.exit(main() or 0)
