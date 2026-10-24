#!/usr/bin/env python3
"""Boot-diagnosis probe (READ-ONLY).

Reads in ONE preloader session:
  - seccfg first 0x1000  -> verify lock_state still 3
  - expdb (up to 0x400000) -> LK/boot log, saved + keyword extraction
  - misc first 0x1000     -> boot command / BCB

Files: /tmp/seccfg_now.bin /tmp/expdb.bin /tmp/misc_now.bin
"""
import os, sys, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

KEYS = ("orange", "unlock", "lock", "rpmb", "watchdog", "wdt", "panic", "fail",
        "error", "verify", "vbmeta", "boot", "reboot", "wipe", "reset", "seccfg",
        "dm-verity", "dm_verity", "avb", "slot")


def get(loader, addr, length):
    d = loader.readflash(addr=addr, length=length, filename="", parttype="user",
                         display=False)
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
        print("[-] connect failed"); return 1
    loader = mtk.daloader
    xmlft = loader.xmlft
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize

    def readp(name, length):
        p = next((x for x in gpt.partentries if x.name.lower() == name), None)
        if p is None:
            print(f"[-] no partition {name}"); return None
        n = min(length, p.sectors * ss)
        d = get(loader, p.sector * ss, n)
        print(f"[*] {name}: LBA {p.sector:#x} size {p.sectors*ss:#x}, read {len(d):#x}")
        return d

    sc = readp("seccfg", 0x1000)
    if sc:
        open("/tmp/seccfg_now.bin", "wb").write(sc)
        import struct
        magic, ver, size, lock = struct.unpack("<4sIII", sc[:16])
        print(f"[*] seccfg: magic={magic!r} ver={ver} size={size:#x} lock_state={lock}")
        print(f"[*] seccfg md5={__import__('hashlib').md5(sc).hexdigest()}")

    exp = readp("expdb", 0x400000)
    if exp:
        open("/tmp/expdb.bin", "wb").write(exp)
        txt = exp.decode("latin-1", "ignore")
        lines = re.split(r"[\r\n]+", txt)
        hits = []
        for ln in lines:
            if not ln.strip():
                continue
            low = ln.lower()
            if any(k in low for k in KEYS) and sum(32 <= ord(c) < 127 for c in ln) > 6:
                hits.append(ln.strip())
        print(f"[*] expdb printable keyword lines: {len(hits)}")
        for ln in hits[-120:]:
            print("  |", ln[:200])

    mi = readp("misc", 0x1000)
    if mi:
        open("/tmp/misc_now.bin", "wb").write(mi)
        print(f"[*] misc head: {mi[:64].hex()}")
    print("[*] probe done")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
