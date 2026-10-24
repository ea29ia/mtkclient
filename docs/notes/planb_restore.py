#!/usr/bin/env python3
"""Plan B step 0: RESTORE the original seccfg from backup (the previous
partial write zeroed the partition: erase passed, program died on the
HACC-hang). Restore first, verify, THEN unlock.

Source: /home/musin/seccfg_backup.bin (8 MB, md5 12a94a3ffbfc1a7f344e1dd6837b359a)
With OPLUS_PATCH_ERASE_KILL=1 + OPLUS_PATCH_HACC_HANG=1 the WRITE-PARTITION
should now commit fully; verify byte-for-byte vs the backup afterwards.
"""
import os
import sys
import time
import hashlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

BACKUP = os.environ.get("SECCFG_BACKUP", "/home/musin/seccfg_backup.bin")
GO = os.environ.get("PLAN_B_GO", "0") == "1"


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
        print("[-] connect failed")
        return 1
    loader = mtk.daloader
    xmlft = loader.xmlft

    blob = open(BACKUP, "rb").read()
    md5 = hashlib.md5(blob).hexdigest()
    if blob[:4] != b"MMMM" or blob[0x18:0x1C] != b"\x45\x45\x45\x45":
        print("[-] backup structure unexpected — ABORT")
        return 1
    print(f"[+] backup: {BACKUP} ({len(blob)} B, md5 {md5})")
    import struct
    ver, size, _x, lock, dmv, sboot, endf = struct.unpack("<7I", blob[:28])
    print(f"[*] backup header: ver={ver} size={size:#x} lock_state={lock} "
          f"dm_verity={dmv:#x} sboot={sboot:#x}")

    data, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = gpt.sectorsize
    seccfg = next((p for p in gpt.partentries if p.name.lower() == "seccfg"), None)
    if seccfg is None:
        print("[-] no seccfg in GPT")
        return 1
    fullsize = seccfg.sectors * ss
    print(f"[+] seccfg: LBA {seccfg.sector:#x} size {fullsize:#x}")
    if len(blob) != fullsize:
        print(f"[-] backup size {len(blob)} != partition {fullsize} — ABORT")
        return 1

    # current state
    cur = loader.readflash(addr=seccfg.sector * ss, length=0x1000,
                           filename="", parttype="user", display=False)
    cur = cur[0] if isinstance(cur, tuple) else cur
    if cur and cur[:4] == b"MMMM":
        import struct as _s
        _v = _s.unpack("<7I", cur[:28])
        print(f"[*] current flash: ver={_v[1]} lock_state={_v[3]} (END {_v[6]:#x})")
    else:
        print("[*] current flash: ALL-ZERO (as expected after the failed write)")

    if not GO:
        print("[dryrun] nothing written. Rerun with PLAN_B_GO=1 to restore.")
        return 0

    print("[!] RESTORING original seccfg from backup. Ctrl-C to abort.")
    time.sleep(5)
    ok, msg = xmlft.seccfg_write_partition(seccfg, blob)
    if not ok:
        print(f"[-] restore write failed: {msg}")
        return 1

    # verify: read back first 0x1000 and compare to backup
    time.sleep(1.0)
    chk = loader.readflash(addr=seccfg.sector * ss, length=0x1000,
                           filename="", parttype="user", display=False)
    chk = chk[0] if isinstance(chk, tuple) else chk
    if chk and chk[:4] == b"MMMM":
        import struct as _s
        _v = _s.unpack("<7I", chk[:28])
        print(f"[*] readback: ver={_v[1]} lock_state={_v[3]} dm_verity={_v[4]:#x} sboot={_v[5]:#x}")
        if bytes(chk[:0x1000]) == blob[:0x1000]:
            print("[+] RESTORE VERIFIED: first 4 KB matches the backup byte-for-byte")
        else:
            print("[!] header matches backup but body differs (HACC-transformed data?)")
            print(f"    backup[0x1C:0x2C]: {blob[0x1C:0x2C].hex()}")
            print(f"    flash [0x1C:0x2C]: {bytes(chk[0x1C:0x2C]).hex()}")
        print("[*] full-partition md5 check:")
        full = loader.readflash(addr=seccfg.sector * ss, length=fullsize,
                                filename="/tmp/seccfg_after_restore.bin",
                                parttype="user", display=True)
        full = full[0] if isinstance(full, tuple) else full
        if full:
            rb = open("/tmp/seccfg_after_restore.bin", "rb").read()
            m2 = hashlib.md5(rb).hexdigest()
            print(f"[*] readback md5: {m2} (backup {md5})")
            if m2 == md5:
                print("[+] FULL RESTORE VERIFIED — seccfg is back to original")
                return 0
            print("[-] md5 mismatch — restore incomplete; DO NOT proceed to unlock")
            return 1
    else:
        print("[-] readback EMPTY/ZERO — restore did NOT commit")
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
