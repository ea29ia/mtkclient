#!/usr/bin/env python3
"""READ-ONLY unlock-state check: seccfg header + RPMB mirror (blocks 0x1DC-0x1DF).

Answers in one preloader session:
  * what does the seccfg partition say now (lock_state / dm_verity / sboot)?
  * what does the RPMB boot-info mirror say (locked bit, hash validity)?
  * is the result consistent (i.e. did the persistent unlock hold)?

Verdicts:
  seccfg=3 + mirror locked=0  -> UNLOCK PERSISTED (LK should boot unlocked)
  seccfg=3 + mirror locked=1  -> LK re-locked again despite the mirror write
  seccfg=4 + mirror locked=1  -> back to stock (write reverted)
  mirror hash invalid         -> LK zeroes its buffer => treated as unlocked

No writes. Artifacts: /home/musin/state_seccfg.bin, /home/musin/state_mirror.bin
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
os.chdir(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)

from planb_recon2 import rpmbk_set_key, rpmbi_derive, read_rpmb_range  # noqa: E402

MIRROR_BLOCK = 0x1DC
MIRROR_N = 4
ORIG_MD5 = "12a94a3ffbfc1a7f344e1dd6837b359a"


def rd(loader, addr, length):
    d = loader.readflash(addr=addr, length=length, filename="", parttype="user", display=False)
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
        print("[-] connect failed")
        return 1
    loader = mtk.daloader
    xmlft = loader.xmlft
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize

    # --- seccfg ---
    sc = next((p for p in gpt.partentries if p.name.lower() == "seccfg"), None)
    if sc is None:
        print("[-] no seccfg")
        return 1
    head = rd(loader, sc.sector * ss, 0x1000)
    open("/home/musin/state_seccfg.bin", "wb").write(head)
    lock = dmv = sboot = None
    locked = None
    if head[:4] == b"MMMM":
        magic, ver, size, lock, dmv, sboot, endf = struct.unpack("<7I", head[:28])
        print(f"[*] seccfg: magic={magic:#x} ver={ver} size={size:#x} "
              f"lock_state={lock} dm_verity={dmv:#x} sboot={sboot:#x} end={endf:#x}")
        print(f"    head md5={hashlib.md5(head).hexdigest()} "
              f"(stock 4k md5 1687ff2654c6d2a52e26a200c6b2ce48)")
        print(f"    vendor marker @0x200: {head[0x200:0x210].hex()}")
    else:
        print(f"[!] seccfg head is not MMMM: {head[:16].hex()}")

    # --- full partition md5 (stock reference) ---
    full = sc.sectors * ss
    blob = rd(loader, sc.sector * ss, full)
    if len(blob) == full:
        md5 = hashlib.md5(blob).hexdigest()
        print(f"[*] seccfg full: {len(blob):#x} B md5={md5} "
              f"({'STOCK original' if md5 == ORIG_MD5 else 'MODIFIED vs stock'})")

    # --- RPMB mirror ---
    print("[*] RPMB mirror (blocks 0x1DC-0x1DF) ...")
    if xmlft.custom_rpmb_init():
        D = rpmbi_derive(xmlft)
        if D and rpmbk_set_key(xmlft, D):
            mir, _ = read_rpmb_range(xmlft, MIRROR_BLOCK, MIRROR_N, "mirror")
            if len(mir) == 0x400:
                open("/home/musin/state_mirror.bin", "wb").write(mir)
                s0, dev, bm, locked = struct.unpack("<4I", mir[:16])
                aux = struct.unpack("<I", mir[0x10:0x14])[0]
                calc = hashlib.sha256(mir[:0x3E0]).digest()
                ok = calc == mir[0x3E0:0x400]
                print(f"[*] mirror: sboot={s0} dev_info={dev} bootmode={bm} "
                      f"locked={locked} aux={aux:#x} hash={'VALID' if ok else 'INVALID'} "
                      f"md5={hashlib.md5(mir).hexdigest()}")
                print(f"    id@0x20={mir[0x20:0x30]!r}")
            else:
                print(f"[!] mirror read failed ({len(mir):#x})")
        else:
            print("[!] rpmb key setup failed")
    else:
        print("[!] custom_rpmb_init failed")

    # --- verdict ---
    print("\n=== VERDICT ===")
    mirror_locked = locked
    print(f"seccfg lock={lock}  mirror locked={mirror_locked}")
    if lock == 3 and mirror_locked == 0:
        print("[+] UNLOCK PERSISTED — seccfg=3 and the mirror says unlocked.")
    elif lock == 3 and mirror_locked == 1:
        print("[-] LK re-locked again (mirror=1) even though the mirror write stuck "
              "earlier — something rewrote it (LK or TEE). Need the boot log.")
    elif lock == 4:
        print("[-] seccfg back to 4 — the unlock was reverted again.")
    else:
        print("[?] inconsistent state, see values above")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
