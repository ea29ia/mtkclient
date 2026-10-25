#!/usr/bin/env python3
"""read_ram_props.py - READ-ONLY: scan low RAM for the live property area.

Answers, without adb/root, the question "did our adb_debug.prop actually take
effect, and what does ro.adb.secure hold right now?".

Method: DA readmem over 0x40000000..0x48000000 (128 MiB, the low DRAM window
where the init property area lives), then look for the property-area record
format `name\\0value\\0` for the keys we care about.

Output: for every hit, offset + the raw bytes around it (name/value visible),
plus a verdict line per property.

Nothing is written to the phone.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

BASE = 0x40000000
SIZE = 0x08000000          # 128 MiB
CHUNK = 0x00200000         # 2 MiB per readmem call
OUT = "/home/musin/ram_low.bin"

KEYS = [b"ro.adb.secure", b"ro.debuggable", b"ro.force.debuggable",
        b"persist.sys.usb.config", b"ro.boot.verifiedbootstate",
        b"ro.boot.slot_suffix"]


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

    buf = bytearray()
    for off in range(0, SIZE, CHUNK):
        try:
            d = xmlft.custom_read(BASE + off, CHUNK)
            if isinstance(d, tuple):
                d = d[0]
            d = bytes(d) if d else b""
        except Exception as e:
            print("[-] read 0x%08X: %r" % (BASE + off, e))
            d = b""
        buf += d.ljust(CHUNK, b"\x00")
        if (off // CHUNK) % 16 == 0:
            print("[*] 0x%08X ..." % (BASE + off), flush=True)
    with open(OUT, "wb") as fh:
        fh.write(buf)
    print("[*] dumped %d B -> %s" % (len(buf), OUT))

    verdicts = {}
    for key in KEYS:
        pat = key + b"\x00"
        hits = [m.start() for m in re.finditer(re.escape(pat), buf)]
        vals = []
        for h in hits:
            tail = bytes(buf[h + len(pat):h + len(pat) + 96])
            val = tail.split(b"\x00", 1)[0]
            vals.append(val)
        print("\n== %s: %d hit(s)" % (key.decode(), len(hits)))
        shown = 0
        for h, v in zip(hits, vals):
            if shown >= 12:
                print("   ... (%d more)" % (len(hits) - shown))
                break
            print("   0x%08X value=%r" % (BASE + h, v[:48]))
            shown += 1
        if vals:
            uniq = sorted({v for v in vals if v and len(v) < 64})
            verdicts[key.decode()] = uniq
    # kernel cmdline (boot_params) - tells us the boot model
    for m in re.finditer(rb"androidboot\.[ -~]{20,600}", buf):
        line = m.group().split(b"\x00")[0]
        print("\n== cmdline @0x%08X (%d B)" % (BASE + m.start(), len(line)))
        print("   " + line.decode("latin1")[:400])
        break

    print("\n== verdict ==")
    for k, v in verdicts.items():
        print("   %-28s %s" % (k, v))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
