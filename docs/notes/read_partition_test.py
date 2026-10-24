"""A/B test: READ-PARTITION (by name, 0x400032d0) vs READ-FLASH for seccfg."""
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
xf = loader.xmlft if hasattr(loader, "xmlft") else loader.xflash
data, gpt = loader.get_gpt(parttype="user")
seccfg = next((p for p in gpt.partentries if p.name.lower()=="seccfg"), None)
ss = gpt.sectorsize

def read_partition_by_name(name, fn="/tmp/seccfg_rp.bin"):
    """CMD:READ-PARTITION: whole partition by name, UpFile download flow."""
    from mtkclient.Library.DA.xmlflash.xml_lib import UpFile
    xf.send_command(xf.cmd.cmd_read_partition(name), noack=True)
    cmd, result = xf.get_command_result()
    if type(result) is not UpFile:
        print(f"[-] READ-PARTITION: no UpFile, got {cmd!r} {str(result)[:120]!r}")
        return None
    d = xf.download(result)
    scmd, sresult = xf.get_command_result()
    xf.ack()
    if sresult == "OK" or sresult == "START":
        return bytes(d)
    print(f"[-] READ-PARTITION tail: {scmd!r} {sresult!r}")
    return None

# Test A (READ-FLASH) skipped per directive — straight to Test B.
r1 = None

print("[*] B: READ-PARTITION by name (ai3 path)...")
r2 = read_partition_by_name("seccfg")
if r2:
    h = struct.unpack("<7I", r2[:28])
    print(f"[+] B result: OK {len(r2)} B head: ver={h[1]} size={h[2]:#x} lock={h[3]} "
          f"dmv={h[4]:#x} sboot={h[5]:#x} end={h[6]:#x}")
else:
    print("[-] B result: EMPTY/FAILED")
print("[*] A/B done")
