#!/usr/bin/env python3
"""Small write test: WRITE-PARTITION (pre_erase=NO) of a 0x1000-byte chunk of
the ORIGINAL seccfg backup at seccfg base. Zero risk: bytes already exist
elsewhere in the original image; no erase; lock state cannot worsen.

KEY LESSON (UFS): block size is 0x1000 (4096), NOT 0x200. Every READ/WRITE
transfer length AND offset must be 0x1000-aligned, otherwise the DA hangs in
the data phase (proven: all 0x200 transfers died, all >=0x1000 transfers OK).
"""
import os, sys, struct, hashlib, time
sys.path.insert(0, os.getcwd())
os.chdir('/home/musin/mtkclient')
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
    print("[-] connect failed"); sys.exit(1)
loader = mtk.daloader
xmlft = loader.xmlft

data, gpt = loader.get_gpt(parttype="user")
seccfg = next((p for p in gpt.partentries if p.name.lower() == "seccfg"), None)
ss = gpt.sectorsize
base = seccfg.sector * ss
print(f"[+] seccfg base addr: {base:#x} (LBA {seccfg.sector:#x}, ss={ss:#x})")
assert base % 0x1000 == 0, "base not block-aligned!"

bk = open("/home/musin/seccfg_backup.bin", "rb").read()
chunk = bk[:0x1000]  # block-aligned
print(f"[*] test chunk: first 0x1000 B of backup, md5 {hashlib.md5(chunk).hexdigest()}")

cur = loader.readflash(addr=base, length=0x1000, filename="", parttype="user", display=False)
cur = cur[0] if isinstance(cur, tuple) else cur
same = cur == chunk if cur else False
print(f"[*] current head == backup head: {same}")
if same:
    print("[+] flash already matches backup - nothing to write; write-ops are testable via the unlock step")
    sys.exit(0)

GO = os.environ.get("SMALL_GO", "0") == "1"
if not GO:
    print("[dryrun] would WRITE-PARTITION 0x1000 @ seccfg base (pre_erase=NO). Rerun with SMALL_GO=1")
    sys.exit(0)

print("[!] WRITE-PARTITION 0x1000 @ seccfg base (pre_erase=NO) ...")
time.sleep(5)
ok, msg = xmlft.seccfg_write_partition(seccfg, chunk)
print(f"[*] write result: {ok!r} {msg!r}")

time.sleep(1.0)
print("[*] same-session readback (0x1000)...")
try:
    rb = loader.readflash(addr=base, length=0x1000, filename="", parttype="user", display=False)
    rb = rb[0] if isinstance(rb, tuple) else rb
    if rb == chunk:
        print("[+] SAME-SESSION READBACK MATCH - write COMMITS, session alive!")
    elif rb:
        print(f"[!] readback differs: head={bytes(rb[:32]).hex()}")
    else:
        print("[-] readback empty")
except Exception as e:
    print(f"[-] same-session readback failed: {e!r}")
print("[*] smallwrite done")