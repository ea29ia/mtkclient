#!/usr/bin/env python3
"""Region-list + UFS layer dump right after WRITE-PARTITION (same session).
Discriminates: empty region list (writer no-op) vs UFS dispatch issue."""
import os, sys, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

GO = os.environ.get("DUMP_GO", "0") == "1"

def dump(xmlft, addr, length, label):
    d = xmlft.custom_read(addr, length)
    if not d:
        print(f"[-] {label} @ {addr:#x}: READ FAIL")
        return None
    b = bytes(d)
    print(f"[*] {label} @ {addr:#x}: {b.hex()}")
    return b

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
        print("[-] connect failed"); return 1
    loader = mtk.daloader
    xmlft = loader.xmlft

    data, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize
    seccfg = next((p for p in gpt.partentries if p.name.lower() == "seccfg"), None)
    fullsize = seccfg.sectors * ss

    print("== UFS/storage layer (baseline) ==")
    dump(xmlft, 0x40056A70, 4, "active LU ptr 0x40056A70")
    # dev singletons family per report: [0x40066D80] etc — dump a few
    dump(xmlft, 0x40066D80, 0x10, "dev singleton candidates")

    if not GO:
        print("[dryrun] rerun with DUMP_GO=1")
        return 0

    # write (as planb)
    from mtkclient.Library.Hardware.seccfg import SecCfgV4
    bk = open("/home/musin/seccfg_backup.bin", "rb").read()
    hwc = xmlft.cryptosetup()
    sc = SecCfgV4(hwc, mtk, xmlft.custom_sej_hw)
    if not sc.parse(bk[:0x1000]):
        print("[-] parse failed"); return 1
    ret, writedata = sc.create(lockflag="unlock")
    wd = bytes(writedata) + bytes(fullsize - len(writedata))
    print(f"[!] WRITE {len(wd):#x} B ...")
    time.sleep(3)
    ok, msg = xmlft.seccfg_write_partition(seccfg, wd)
    print(f"[*] write: {ok!r}")

    print("== AFTER WRITE ==")
    lu = dump(xmlft, 0x40056A70, 4, "active LU ptr")
    if lu:
        lu_ptr = struct.unpack("<I", lu)[0]
        print(f"[*] LU ptr = {lu_ptr:#x}")
        if 0x40000000 < lu_ptr < 0x40300000:
            dump(xmlft, lu_ptr, 0x20, "LU struct +0x00..0x1F")
    dev = dump(xmlft, 0x40066D80, 0x10, "dev singletons")
    if dev:
        vals = struct.unpack("<4I", dev)
        for i, v in enumerate(vals):
            print(f"  dev[{i}] = {v:#x}")
            if 0x40000000 < v < 0x40300000:
                dump(xmlft, v, 8, f"dev[{i}] +0 (storage type!)")
    # region list
    rh = dump(xmlft, 0x4006E7D4, 4, "region head")
    if rh:
        rp = struct.unpack("<I", rh)[0]
        print(f"[*] region head = {rp:#x}")
        if 0x40000000 < rp < 0x40300000:
            dump(xmlft, rp, 0x40, "region list entries (offset/len u64 pairs?)")
    # bulk handle state
    dump(xmlft, 0x4006E790, 0x30, "bulk handle 0x4006E790")
    dump(xmlft, 0x4006E750, 0x30, "sparse handle 0x4006E750")
    dump(xmlft, 0x4006E730, 0x18, "0x4006E730 (+0x10/+0x14)")

    time.sleep(1.0)
    chk = loader.readflash(addr=seccfg.sector * ss, length=0x1000, filename="",
                           parttype="user", display=False)
    chk = chk[0] if isinstance(chk, tuple) else chk
    if chk and chk[:4] == b"MMMM":
        h = struct.unpack("<7I", chk[:28])
        print(f"[*] flash: magic={h[0]:#x} ver={h[1]} lock={h[3]}")
    print("[*] dump done")
    return 0

if __name__ == "__main__":
    sys.exit(main() or 0)
