#!/usr/bin/env python3
"""Plan B step 1: RPMB reconnaissance (READ-ONLY).

1) connect (proven path),
2) read live seccfg (lock_state),
3) custom_rpmb_init() — DA derives the RPMB key via HACC; the derived key
   is printed AND staged at DA2 RAM 0x4006e8d8 (re-da2-rpmb-key.md),
4) read key from RAM via CUSTOMMEMR (before the wipe memset re-uses it),
5) auth_rpmb(dumped_key) + read RPMB sectors 0..3 -> file,
6) offline check: look for "4400RPMB" magic / boot-info block (+0xC field).

Outputs to /home/musin/planb_recon.log + /home/musin/rpmb_sectors0_3.bin
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

KEY_STAGE = 0x4006E8D8


def main():
    import argparse
    import time
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

    # --- 2. live seccfg ---
    data, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = gpt.sectorsize
    seccfg = next((p for p in gpt.partentries if p.name.lower() == "seccfg"), None)
    if seccfg is None:
        print("[-] no seccfg in GPT")
        return 1
    blob = loader.readflash(addr=seccfg.sector * ss, length=0x1000,
                            filename="", parttype="user", display=False)
    blob = blob[0] if isinstance(blob, tuple) else blob
    if blob and blob[:4] == b"MMMM":
        import struct
        ver, size, _x, lock, dmv, sboot, endf = struct.unpack("<IIIIIII", blob[:28])
        print(f"[*] LIVE seccfg: ver={ver} size={size:#x} lock_state={lock} "
              f"dm_verity={dmv:#x} sboot={sboot:#x}")
    else:
        print(f"[!] seccfg head: {(blob[:16] if blob else None)!r}")

    # --- 3. derive via DA (CUSTOMRPMBI) ---
    print("[*] custom_rpmb_init() — DA HACC-derives the RPMB key...")
    ok = xmlft.custom_rpmb_init()
    print(f"[*] rpmb_init -> {ok}")

    # --- 4. dump staged key from DA2 RAM ---
    raw = xmlft.custom_read(KEY_STAGE, 0x40)
    if raw:
        raw = bytes(raw)
        key = raw[:0x20]
        print(f"[+] KEY STAGE @0x{KEY_STAGE:x}: {raw.hex()}")
        print(f"[+] candidate RPMB key (first 0x20): {key.hex()}")
        with open("/home/musin/rpmb_key_candidate.bin", "wb") as f:
            f.write(key)
    else:
        print("[-] key-stage read failed (wipe already ran? key = None)")
        key = None

    # --- 5. authenticated RPMB read ---
    if key:
        print("[*] auth_rpmb(dumped key) + read sectors 0..3")
        try:
            if xmlft.auth_rpmb(key):
                if xmlft.read_rpmb(filename="/home/musin/rpmb_sectors0_3.bin",
                                   sector=0, sectors=4, display=False):
                    blob = open("/home/musin/rpmb_sectors0_3.bin", "rb").read()
                    print(f"[+] RPMB read OK: {len(blob)} B")
                    print(f"[*] sector0[:32]: {blob[:32].hex()}")
                    print(f"[*] magic check 4400RPMB @0x1BC? "
                          f"{blob[0x1BC:0x1C4]!r} | any 'RPMB': "
                          f"{blob.find(b'RPMB')}")
                else:
                    print("[-] rpmb read failed (wrong key?)")
            else:
                print("[-] auth_rpmb failed")
        except Exception as e:
            print(f"[-] rpmb path error: {e!r}")
    print("[*] recon done")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
