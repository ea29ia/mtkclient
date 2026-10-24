#!/usr/bin/env python3
"""Plan B EXECUTE: write seccfg V4 lock_state=3 (valid HACC hash), no RPMB work.

Facts established (recon + recon2, 2026-10-24):
 - live seccfg: ver=4, size=0x3C, lock_state=4 (locked), valid structure;
 - RPMB key NOT programmed; RPMB sectors 0..127 all zero (real data);
   => LK double_check_lock_state reads mirror=0 => [DC-3] no re-lock
   => forged seccfg with lock_state=3 SURVIVES without RPMB writes;
 - digest-accept bypass runtime-patched (0x40034f94 -> B) in every session;
 - WRITE-PARTITION full-size write is the proven safe path.

Sequence:
  1) connect,
  2) fresh seccfg backup to /home/musin/seccfg_before_unlock_<ts>.bin,
  3) parse live seccfg as V4, build unlock payload via the DA's own SEJ
     (valid HACC hash by construction),
  4) pad to full partition size, WRITE-PARTITION,
  5) same-session readback verify (lock_state must read 3),
  6) reboot via WDT (CUSTOMREGW nibble already 0) -> ORANGE STATE on next boot.

Env: PLAN_B_GO=1 for the real write (default dry-run).
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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

    # --- GPT / seccfg locate ---
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

    # --- fresh backup ---
    ts = time.strftime("%Y%m%d_%H%M%S")
    bk = f"/home/musin/seccfg_before_unlock_{ts}.bin"
    ok = loader.readflash(addr=seccfg.sector * ss, length=fullsize,
                          filename=bk, parttype="user", display=True)
    ok = ok[0] if isinstance(ok, tuple) else ok
    if not ok:
        print("[-] backup read failed — ABORT (no writes without backup)")
        return 1
    blob = open(bk, "rb").read()
    if blob[:4] != b"MMMM" or blob[0x18:0x1C] != b"\x45\x45\x45\x45":
        print("[-] backup structure unexpected — ABORT")
        return 1
    print(f"[+] backup saved: {bk} ({len(blob)} B, md5 {__import__('hashlib').md5(blob).hexdigest()})")

    # --- build unlock payload via the V4 class (DA-SEJ hash) ---
    live = blob[:0x1000]
    hwc = xmlft.cryptosetup()
    from mtkclient.Library.DA.xmlflash.extension.v6 import SecCfgV4
    sc = SecCfgV4(hwc, mtk, xmlft.custom_sej_hw)
    if not sc.parse(live):
        print("[-] V4 parse failed — ABORT")
        return 1
    print(f"[*] parsed: ver={sc.seccfg_ver} size={sc.seccfg_size:#x} "
          f"lock={sc.lock_state} dm_verity={sc.dm_verity_state:#x} sboot={sc.sboot_runtime:#x}")
    if sc.lock_state == 3:
        print("[+] already unlocked per seccfg — nothing to do")
        return 0
    ret, writedata = sc.create(lockflag="unlock")
    if ret is False:
        print(f"[-] create failed: {writedata}")
        return 1
    print(f"[+] unlock payload built: {len(writedata)} B")

    if not GO:
        open("/tmp/seccfg_unlock_payload.bin", "wb").write(writedata)
        print("[dryrun] payload saved to /tmp/seccfg_unlock_payload.bin — "
              "rerun with PLAN_B_GO=1 to write")
        return 0

    # --- write (payload as-is, 512 B, pre_erase=NO in the XML now) ---
    wd = bytes(writedata)
    print(f"[!] WRITING seccfg unlock ({len(wd)} B WRITE-PARTITION, pre_erase=NO). Ctrl-C to abort.")
    time.sleep(5)
    ok, msg = xmlft.seccfg_write_partition(seccfg, wd)
    if not ok:
        print(f"[-] write failed: {msg}")
        return 1

    # --- verify ---
    time.sleep(1.0)
    chk = xmlft.xflash.readflash(addr=seccfg.sector * ss, length=0x1000,
                                 filename="", parttype="user", display=False)
    chk = chk[0] if isinstance(chk, tuple) else chk
    if chk and chk[:4] == b"MMMM":
        import struct
        ver, size, _x, lock, dmv, sboot, endf = struct.unpack("<7I", chk[:28])
        print(f"[*] readback: ver={ver} size={size:#x} lock_state={lock} "
              f"dm_verity={dmv:#x} sboot={sboot:#x} end={endf:#x}")
        if lock == 3:
            print("[+] WRITE COMMITTED — lock_state=3 in flash")
            print("[*] rebooting -> next boot should be ORANGE STATE (unlocked)")
            try:
                loader.shutdown(bootmode=loader.ShutDownModes.NORMAL)
            except Exception as e:
                print(f"[i] shutdown: {e!r}")
            print("[*] watch: normal-mode USB should return in ~30-60 s")
            return 0
        print(f"[-] readback lock_state={lock} != 3")
        return 1
    print("[-] readback EMPTY/ZERO — write did NOT commit")
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
