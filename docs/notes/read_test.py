import os, sys, struct
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
ss = gpt.sectorsize
parts = {p.name.lower(): p for p in gpt.partentries}

def tryread(label, addr, ln):
    try:
        r = loader.readflash(addr=addr, length=ln, filename="", parttype="user", display=False)
        r = r[0] if isinstance(r, tuple) else r
        if r:
            print(f"[+] {label} @ {addr:#x} len={ln:#x}: OK ({len(r)} B) head={bytes(r[:16]).hex()}")
        else:
            print(f"[-] {label} @ {addr:#x} len={ln:#x}: EMPTY")
    except Exception as e:
        print(f"[-] {label} @ {addr:#x} len={ln:#x}: EXC {e!r}")

# scope test: does ONLY seccfg hang, or all reads beyond GPT?
for name in ("para", "misc", "frp", "proinfo", "seccfg"):
    p = parts.get(name)
    if p:
        tryread(name, p.sector * ss, 0x200)
sc = parts["seccfg"]
tryread("seccfg-0x1000(before)", (sc.sector - 4) * ss, 0x1000)
tryread("seccfg-1st-0x200", sc.sector * ss, 0x200)
tryread("seccfg-mid-0x200", (sc.sector + (sc.sectors // 2)) * ss, 0x200)
tryread("seccfg-end-0x200", (sc.sector + sc.sectors - 4) * ss, 0x1000)
print("[*] scope test done")
