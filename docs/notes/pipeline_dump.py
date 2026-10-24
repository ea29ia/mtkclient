#!/usr/bin/env python3
"""Live pipeline-state dump right after a WRITE-PARTITION (per
re-writepartition-silent-skip.md §4.2). Write + dump in ONE session.

Dump targets:
  [0x4006E7CC] ctx: +0x00, +0x18, +0x1C, +0x9C, +0xA0, +0xA4, +0xE0, +0xE4
  [0x4006E7C8] sparse flag
  [0x4006E7D4] region-list head
  ctx+0x24 -> 0x58-struct: bytes +0x00..+0x0F, u64 +0x48/+0x50
  [0x40067A08]: +0x14, +0x18, +0x1C
  [0x4006E084] async engine flag
Also dumps the record buffer (ctx slots) if pointers are sane.
"""
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

    # --- baseline state BEFORE write ---
    print("== BASELINE (before write) ==")
    ctx_ptr = dump(xmlft, 0x4006E7CC, 4, "ctx ptr 0x4006E7CC")
    c2_ptr = dump(xmlft, 0x4006E7D0, 4, "ctx2 ptr 0x4006E7D0")
    dump(xmlft, 0x4006E7C8, 4, "sparse flag")
    dump(xmlft, 0x4006E7D4, 4, "region head")
    dump(xmlft, 0x4006E084, 4, "async engine flag")
    dump(xmlft, 0x40067A08, 0x20, "0x40067A08 (+0x14/+0x18/+0x1C)")

    if not GO:
        print("[dryrun] rerun with DUMP_GO=1 to write + dump")
        return 0

    # --- write (same as planb) ---
    from mtkclient.Library.Hardware.seccfg import SecCfgV4
    bk = open("/home/musin/seccfg_backup.bin", "rb").read()
    hwc = xmlft.cryptosetup()
    sc = SecCfgV4(hwc, mtk, xmlft.custom_sej_hw)
    if not sc.parse(bk[:0x1000]):
        print("[-] parse failed"); return 1
    ret, writedata = sc.create(lockflag="unlock")
    if ret is False:
        print("[-] create failed"); return 1
    wd = bytes(writedata) + bytes(fullsize - len(writedata))
    print(f"[!] WRITE {len(wd):#x} B to seccfg ...")
    time.sleep(3)
    ok, msg = xmlft.seccfg_write_partition(seccfg, wd)
    print(f"[*] write: {ok!r} {msg!r}")

    # --- dump AFTER write (same session) ---
    print("== AFTER WRITE ==")
    ctx_ptr = dump(xmlft, 0x4006E7CC, 4, "ctx ptr")
    c2_ptr = dump(xmlft, 0x4006E7D0, 4, "ctx2 ptr")
    dump(xmlft, 0x4006E7C8, 4, "sparse flag")
    dump(xmlft, 0x4006E7D4, 4, "region head")
    dump(xmlft, 0x4006E084, 4, "async engine flag")
    dump(xmlft, 0x40067A08, 0x20, "0x40067A08")

    if ctx_ptr:
        ctx = struct.unpack("<I", ctx_ptr)[0]
        print(f"[*] ctx = {ctx:#x}")
        if 0x40000000 < ctx < 0x40300000:
            dump(xmlft, ctx, 0x20, "ctx +0x00..0x1F")
            dump(xmlft, ctx + 0x90, 0x20, "ctx +0x90..0xAF (9C/A0/A4)")
            dump(xmlft, ctx + 0xE0, 8, "ctx +0xE0/+0xE4")
    if c2_ptr:
        c2 = struct.unpack("<I", c2_ptr)[0]
        print(f"[*] ctx2 = {c2:#x}")
        if 0x40000000 < c2 < 0x40300000:
            dump(xmlft, c2, 0x20, "ctx2 +0x00..0x1F")
            dump(xmlft, c2 + 0xE0, 8, "ctx2 +0xE0/+0xE4")

    # 0x58-struct via ctx+0x24
    if ctx_ptr:
        ctx = struct.unpack("<I", ctx_ptr)[0]
        if 0x40000000 < ctx < 0x40300000:
            p24 = dump(xmlft, ctx + 0x24, 4, "ctx+0x24 (0x58-struct ptr)")
            if p24:
                st = struct.unpack("<I", p24)[0]
                if 0x40000000 < st < 0x40300000:
                    dump(xmlft, st, 0x10, "0x58-struct +0x00..0x0F (policy bytes!)")
                    dump(xmlft, st + 0x48, 0x10, "0x58-struct +0x48/+0x50 (LBA/size)")

    # flash check
    time.sleep(1.0)
    chk = loader.readflash(addr=seccfg.sector * ss, length=0x1000, filename="",
                           parttype="user", display=False)
    chk = chk[0] if isinstance(chk, tuple) else chk
    if chk and chk[:4] == b"MMMM":
        h = struct.unpack("<7I", chk[:28])
        print(f"[*] flash: magic={h[0]:#x} ver={h[1]} lock={h[3]}")
    else:
        print("[-] flash head:", (bytes(chk[:16]).hex() if chk else None))
    print("[*] dump done")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
