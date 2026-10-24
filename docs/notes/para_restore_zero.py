#!/usr/bin/env python3
"""Restore `para` first 0x1000 to zeros after the write-verification probe.
Reads the full partition, replaces the first 0x1000 with the original zeros,
writes the full image back, verifies. Safe: pre_erase=NO, same size.
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


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
    xmlft = loader.xmlft
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize
    para = next((p for p in gpt.partentries if p.name.lower() == "para"), None)
    base, fullsize = para.sector * ss, para.sectors * ss
    print(f"[*] para base={base:#x} size={fullsize:#x}")

    data = loader.readflash(addr=base, length=fullsize, filename="", parttype="user", display=False)
    data = data[0] if isinstance(data, tuple) else data
    if not data or isinstance(data, bool) or len(data) < fullsize:
        print("[-] full read failed"); return 1
    data = bytes(data[:fullsize])
    print(f"[*] current head: {data[:16].hex()}")
    open("/tmp/para_before_restore.bin", "wb").write(data)

    restored = bytes(0x1000) + data[0x1000:]
    print("[!] writing zeros over first 0x1000 ...")
    time.sleep(2)
    ok, msg = xmlft.seccfg_write_partition(para, restored)
    print(f"[*] write: {ok!r} {msg!r}")

    time.sleep(1)
    rb = loader.readflash(addr=base, length=0x1000, filename="", parttype="user", display=False)
    rb = rb[0] if isinstance(rb, tuple) else rb
    rb = bytes(rb[:0x1000]) if rb and not isinstance(rb, bool) else b""
    if rb == bytes(0x1000):
        print("[+] para RESTORED (first 0x1000 zeros)")
        return 0
    print(f"[-] restore mismatch: {rb[:16].hex()}")
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
