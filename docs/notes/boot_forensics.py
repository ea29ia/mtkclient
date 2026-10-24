#!/usr/bin/env python3
"""READ-ONLY boot forensics: why does the phone not reach Android?

Dumps the few flash surfaces LK's boot path actually consumes and prints a
compact report:

  * oplusreserve1[0x0..0x40]  — LK reads 0x34 bytes at offset 0 (0x500053E0,
    partition size / 0x438 is stored to 0x50112054); non-zero here can switch
    boot_mode_check to RECOVERY;
  * misc[0x0..0x1000]         — BCB command (first 14 B, "boot-recovery") and
    the BCAB control block at +0x800 (magic "BCAB" at +0x804);
  * expdb[0..0x100000]        — LK/AEE boot log (usually empty on this unit);
  * boot_para[0..0x1000]      — MTK boot parameter block;
  * seccfg header              — lock_state / marker (context).

No writes. Artifacts in /home/musin/forensics_*.bin
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

PARTS = [
    ("oplusreserve1", 0x2000),
    ("misc", 0x1000),
    ("expdb", 0x100000),
    ("boot_para", 0x1000),
    ("seccfg", 0x1000),
]


def rd(loader, addr, length):
    d = loader.readflash(addr=addr, length=length, filename="", parttype="user", display=False)
    d = d[0] if isinstance(d, tuple) else d
    if not d or isinstance(d, bool):
        return b""
    return bytes(d[:length])


def strs(b, minlen=4):
    out, cur = [], bytearray()
    for x in b:
        if 32 <= x < 127:
            cur.append(x)
        else:
            if len(cur) >= minlen:
                out.append(bytes(cur).decode("ascii", "ignore"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(bytes(cur).decode("ascii", "ignore"))
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

    got = {}
    for name, length in PARTS:
        p = next((x for x in gpt.partentries if x.name.lower() == name), None)
        if p is None:
            print(f"[-] no partition {name}")
            continue
        full = p.sectors * ss
        n = min(length, full)
        d = rd(loader, p.sector * ss, n)
        got[name] = d
        open(f"/home/musin/forensics_{name}.bin", "wb").write(d)
        nz = sum(1 for x in d if x)
        print(f"[*] {name}: LBA {p.sector:#x} size {full:#x}, read {len(d):#x}, "
              f"nonzero={nz}, md5={hashlib.md5(d).hexdigest()}")

    # --- oplusreserve1 ---
    r1 = got.get("oplusreserve1", b"")
    if r1:
        print("\n=== oplusreserve1 (LK reads 0x34 B at offset 0) ===")
        print(f"  head 0x40: {r1[:0x40].hex()}")
        for i in range(0, min(len(r1), 0x200), 16):
            row = r1[i:i + 16]
            if any(row):
                print(f"  {i:#06x}: {row.hex()}")
        words = [int.from_bytes(r1[i:i + 4], "little") for i in range(0, 0x40, 4)]
        print(f"  dwords[0..0x10]: {[hex(w) for w in words]}")
        print(f"  strings: {strs(r1[:0x400])[:10]}")

    # --- misc ---
    m = got.get("misc", b"")
    if m:
        print("\n=== misc ===")
        bcb = m[:0xE]
        print(f"  BCB[0..0xE]: {bcb!r}")
        if bcb.startswith(b"boot-recovery"):
            print("  [!] BCB says boot-recovery -> LK enters RECOVERY")
        blk = m[0x800:0x828]
        print(f"  BCAB block 0x800: {blk.hex()}")
        if blk[4:8] == b"BCAB":
            print("  [i] BCAB magic present (LK/accepted A/B control block)")
        else:
            print("  [i] no BCAB magic at 0x804")
        try:
            old = open("/home/musin/rmx3630_backup_20261024_095607/misc.img", "rb").read(0x1000)
            diff = [i for i in range(min(len(old), len(m))) if old[i] != m[i]]
            print(f"  vs pre-campaign backup: {len(diff)} differing byte(s)"
                  f"{' @ ' + ', '.join(hex(x) for x in diff[:12]) if diff else ''}")
        except OSError:
            pass

    # --- expdb ---
    e = got.get("expdb", b"")
    if e:
        print("\n=== expdb (LK/AEE log) ===")
        nz = sum(1 for x in e if x)
        print(f"  nonzero={nz}")
        if nz:
            for s in strs(e)[:20]:
                print("  |", s[:120])

    # --- boot_para ---
    bp = got.get("boot_para", b"")
    if bp:
        print("\n=== boot_para ===")
        print(f"  head 0x40: {bp[:0x40].hex()}")
        if any(bp):
            for i in range(0, min(len(bp), 0x100), 16):
                row = bp[i:i + 16]
                if any(row):
                    print(f"  {i:#06x}: {row.hex()}")
        print(f"  strings: {strs(bp)[:10]}")

    # --- seccfg context ---
    sc = got.get("seccfg", b"")
    if sc and sc[:4] == b"MMMM":
        import struct
        _, ver, size, lock, dmv, sboot, endf = struct.unpack("<7I", sc[:28])
        print("\n=== seccfg ===")
        print(f"  ver={ver} size={size:#x} lock={lock} dm_verity={dmv:#x} "
              f"sboot={sboot:#x} end={endf:#x} marker@0x200={sc[0x200:0x210].hex()}")

    print("\n[*] forensics done (read-only)")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
