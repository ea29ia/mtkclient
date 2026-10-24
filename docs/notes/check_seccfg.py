import os, sys, struct, hashlib
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
data, gpt = loader.get_gpt(parttype="user")
seccfg = next((p for p in gpt.partentries if p.name.lower()=="seccfg"), None)
ss = gpt.sectorsize
fullsize = seccfg.sectors * ss
full = loader.readflash(addr=seccfg.sector*ss, length=fullsize,
                        filename="/tmp/seccfg_now.bin", parttype="user", display=True)
full = full[0] if isinstance(full, tuple) else full
if not full:
    print("[-] read failed"); sys.exit(1)
rb = open("/tmp/seccfg_now.bin","rb").read()
m = hashlib.md5(rb).hexdigest()
head = struct.unpack("<7I", rb[:28])
print(f"[*] NOW: magic={head[0]:#x} ver={head[1]} size={head[2]:#x} lock_state={head[3]} "
      f"dm_verity={head[4]:#x} sboot={head[5]:#x} end={head[6]:#x}")
print(f"[*] md5 now: {m}")
print(f"[*] md5 backup : 12a94a3ffbfc1a7f344e1dd6837b359a (original, lock=4)")
if m == "12a94a3ffbfc1a7f344e1dd6837b359a":
    print("[+] RESTORE FULLY COMMITTED — flash == original backup (lock=4)")
elif rb[:4] == b"MMMM" and head[3] == 3:
    print("[+] UNLOCK PAYLOAD IN FLASH (lock=3) — unlock committed!")
elif rb[:4] == b"MMMM":
    print(f"[!] valid seccfg head but md5 mismatch: lock={head[3]} — unknown state")
else:
    print("[-] head not MMMM:", rb[:16].hex())
