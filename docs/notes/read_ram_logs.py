#!/usr/bin/env python3
"""READ-ONLY: pull RAM log buffers from the running device via DA readmem.

Targets (physical, from the preloader's own log):
  0x48080000 aee_debug_kinfo    0x10000
  0x48090000 pstore/ramoops     0xE0000   (console 0x40000 + pmsg 0x10000)
  0x48700000 pl-drambuf         0x100000  (preloader ring)
  0x0011D000 SRAM ram_console   0x800

Writes nothing to flash.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

TARGETS = [
    ("pstore", 0x48090000, 0xE0000),
    ("kinfo", 0x48080000, 0x10000),
    ("pldram", 0x48700000, 0x100000),
    ("sram", 0x0011D000, 0x800),
]


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
    xmlft = mtk.daloader.xmlft
    for name, addr, size in TARGETS:
        try:
            d = xmlft.custom_read(addr, size)
            if isinstance(d, tuple):
                d = d[0]
            d = bytes(d) if d else b""
        except Exception as e:
            print("[-] %-7s @0x%08X: %r" % (name, addr, e))
            continue
        path = "/home/musin/ram_%s.bin" % name
        with open(path, "wb") as fh:
            fh.write(d)
        nz = sum(1 for b in d if b)
        print("[*] %-7s @0x%08X %d B read, %d non-zero -> %s"
              % (name, addr, len(d), nz, path))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
