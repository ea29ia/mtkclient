#!/usr/bin/env python3
"""READ-ONLY: dump the whole `oplusreserve1` and look for OPPO's boot-failure
bookkeeping and LK log store.

Why: LK has in this partition
  * `pl_lk log header`      ("failed to read oplusreserve1 pl_lk log header")
  * `kernel log header`
  * **`NoBoot` header**     ("no_boot_header.bootstage / bootcount / history")
    — OPPO's failed-boot counter.  LK prints "pon too much times, stop write now"
    when it gives up, and the seccfg code (0x50082EFC/0x50082F1C) also touches it.
  * the UFS descriptor at offset 0 (vendor/model/fw + 2 checksums)

If the phone is crash-looping when unlocked, `bootcount` should have grown, and
the LK log may say why.  Read-only; artifacts in /home/musin/reserve1_*.bin.

Header record layout (from 0x50004D70..0x50004E60): a 0x18-byte record whose
first bytes are `type, bootstage, bootcount, history` (LK prints
"After read:no_boot_header.bootstage is = %d, no_boot_header.bootco…" and
"stage %c count %c history %c").  LK reads it at `[part+0x28] * K` with
K ∈ {0x438, 0x49f, 0x201} depending on the record kind, so we scan the whole
partition instead of guessing.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

NAME = "oplusreserve1"
OUT = "/home/musin/reserve1_full.bin"
K_VALUES = (0x438, 0x49f, 0x201)


def rd(loader, addr, length):
    d = loader.readflash(addr=addr, length=length, filename="", parttype="user", display=False)
    d = d[0] if isinstance(d, tuple) else d
    if not d or isinstance(d, bool):
        return b""
    return bytes(d[:length])


def strs(b, minlen=6):
    out, cur = [], bytearray()
    for x in b:
        if 32 <= x < 127:
            cur.append(x)
        else:
            if len(cur) >= minlen:
                out.append((len(out), bytes(cur).decode("ascii", "ignore")))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append((len(out), bytes(cur).decode("ascii", "ignore")))
    return out


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
    loader = mtk.daloader
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize

    p = next((x for x in gpt.partentries if x.name.lower() == NAME), None)
    if p is None:
        print(f"[-] no {NAME}")
        return 1
    base, full = p.sector * ss, p.sectors * ss
    print(f"[*] {NAME}: LBA {p.sector:#x} size {full:#x} — reading all ...")

    blob = bytearray()
    step = 0x100000
    while len(blob) < full:
        n = min(step, full - len(blob))
        chunk = rd(loader, base + len(blob), n)
        if len(chunk) != n:
            print(f"[-] read failed at {len(blob):#x} (got {len(chunk):#x})")
            break
        blob.extend(chunk)
        print(f"    {len(blob):#x}/{full:#x}")
    blob = bytes(blob)
    open(OUT, "wb").write(blob)
    print(f"[+] saved -> {OUT} ({len(blob):#x} B, md5 {hashlib.md5(blob).hexdigest()})")

    # --- nonzero map per 64 KB ---
    print("\n=== nonzero map (64 KB blocks) ===")
    blocks = []
    for off in range(0, len(blob), 0x10000):
        nz = sum(1 for x in blob[off:off + 0x10000] if x)
        if nz:
            blocks.append((off, nz))
    for off, nz in blocks:
        print(f"  0x{off:06x}: {nz} nonzero")

    # --- candidate header offsets ---
    print("\n=== candidate record offsets ([part+0x28] * K) ===")
    cands = set()
    for scale in (0x1000, 0x800):
        for k in K_VALUES:
            off = scale * k
            if 0 <= off < len(blob) - 0x20:
                cands.add(off)
    for off in sorted(cands):
        rec = blob[off:off + 0x20]
        print(f"  0x{off:06x}: {rec.hex()}  {rec[:4]!r}")

    # --- strings ---
    print("\n=== strings (>=6 chars) ===")
    for i, s in strs(blob)[:80]:
        print("  |", s[:160])

    print("\n[*] reserve1 probe done (read-only)")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
