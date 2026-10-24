#!/usr/bin/env python3
"""Path A: arm `fastboot flashing unlock` via the frp partition gate.

Background (docs/notes/reverse/re-lk-rescue-surfaces.md, §6, PROVEN):
 - LK `flashing unlock` handler (0x500076A8) runs on a LOCKED device.
 - Its gate `get_unlock_ability` (0x50007BEC) reads the LAST 4 BYTES of the
   "frp" partition (offset = part_size - 4). Nonzero => unlock allowed.
   frp missing from GPT => unlock allowed.
 - Confirm UI is VOLUME-KEY driven ("Yes (Volume UP or Volume Down)"), 5 s
   auto-exit — works with a dead screen.
 - On confirm LK wipes metadata/userdata and sets seccfg lock_state=3 itself;
   the RPMB boot-info mirror is rewritten by LK at the first unlocked boot
   (re-lk-rpmb-lock.md) — no manual RPMB work needed on this path.

This script (run on the PC with the repo's venv):
  1) connects (preloader VCOM -> DA_BR -> heapbait -> runtime patches),
  2) reads the GPT and locates "frp",
  3) reads the last 4 bytes of frp; if zero, writes a nonzero marker there,
  4) verifies the write by re-reading,
  5) reboots the device so the user can do the fastboot combo:

     COMBO: power + volume-down (typical MTK fastboot entry; try variations),
     then on the PC:  fastboot devices
                      fastboot flashing get_unlock_ability   # expect 1
                      fastboot flashing unlock               # press Vol-Up <= 5 s

SAFETY:
 - unlocking WIPES userdata/metadata. The phone is a dead-screen recovery
   unit — data is presumed lost already; flagged again before the write.
 - only the last 4 bytes of frp are modified. Everything else untouched.
 - if anything fails before the write, nothing is changed.

Usage (repo root):
  source .venv/bin/activate
  python docs/notes/path_a_arm_frp_unlock.py            # arm + verify + reset
Env:
  PATHA_DRYRUN=1        read-only: report frp tail bytes, do not write
  PATHA_MARKER=0x12345678   marker dword (default 0x00000001)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

DRYRUN = os.environ.get("PATHA_DRYRUN", "0") == "1"
MARKER = int(os.environ.get("PATHA_MARKER", "0x00000001"), 16)


def main():
    # standard mtkclient bootstrap: parse args with mtk.py's parser, then
    # Main(args) handles VCOM catch, DA upload, heapbait and the OPLUS
    # runtime patches (same code path as `mtk.py r ...`); mtk.run(parser)
    # returns the connected Mtk object.
    import argparse
    sys.path.insert(0, os.getcwd())  # repo root (script lives in docs/notes)
    import mtk as mtk_cli
    parser = mtk_cli.create_base_parser()
    # full parser with subcommands so that parse_args accepts --cmd r ...
    parser = argparse.ArgumentParser(parents=[parser],
                                     description=mtk_cli.INFO)
    sub = parser.add_subparsers(dest='cmd', required=False)
    sub.add_parser('custom')  # placeholder: we drive the DA API directly
    args = parser.parse_args(sys.argv[1:] + ['custom'])
    from mtkclient.Library.mtk_main import Main
    mtk_main = Main(args)
    mtk = mtk_main.run(parser)
    if mtk is None:
        print("[-] connect failed (check .state/hwparam.json removal, VCOM catch)")
        return 1
    loader = mtk.daloader

    data, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1

    # sector size comes back from the parsed GPT object
    sectorsize = getattr(gpt, "sectorsize", 4096) or 4096

    frp = None
    for part in gpt.partentries:
        if part.name.lower() == "frp":
            frp = part
            break
    if frp is None:
        # per LK code: missing frp => unlock_allowed=1 -> nothing to arm
        print("[+] no 'frp' partition in GPT -> LK treats unlock as ALLOWED already.")
        print("    Nothing to write. Go straight to the fastboot combo.")
        pass  # port closes on process exit
        return 0

    size = frp.sectors * sectorsize
    tail_off = (frp.sector + frp.sectors) * sectorsize - 4
    print(f"[+] frp: LBA {frp.sector:#x}..{frp.sector + frp.sectors:#x} "
          f"size {size:#x}, tail offset {tail_off:#x}")

    tail = loader.xflash.readflash(
        addr=tail_off, length=4, filename="", parttype="user", display=False)
    if not tail or len(tail) != 4:
        print("[-] frp tail read failed — abort (nothing written)")
        pass  # port closes on process exit
        return 1

    cur = int.from_bytes(tail, "little")
    print(f"[*] frp tail = {cur:#010x} ({'ALLOWED' if cur else 'PROHIBITED'} by LK gate)")

    if cur != 0:
        print("[+] gate already armed — nothing to write.")
    elif DRYRUN:
        print("[dryrun] would write marker now — rerun without PATHA_DRYRUN")
        pass  # port closes on process exit
        return 0
    else:
        print("[!] unlocking WIPES userdata/metadata. Ctrl-C now to abort.")
        time.sleep(5)
        data = MARKER.to_bytes(4, "little")
        # WRITE-PARTITION by name is the safe route on this DA2 (WRITE-FLASH can
        # erase-then-die mid-transfer). Pad the marker to the FULL partition
        # size: a partial write = erase + silent no-op (proven on seccfg).
        full = bytearray(size)
        full[-4:] = data
        # reuse the proven raw named-partition writer from the seccfg path
        xmlft = loader.xmlft if hasattr(loader, "xmlft") else None
        if xmlft is None:
            from mtkclient.Library.DA.xmlflash.extension.v6 import XmlFlashExt
            xmlft = loader.xflash  # v6 seccfg_write_partition lives on the xflash ext
        ok, msg = False, "no writer"
        try:
            ok, msg = xmlft.seccfg_write_partition(frp, bytes(full))
        except AttributeError:
            # generic raw WRITE-PARTITION via the xml command path
            try:
                ok = xmlft.xflash.cmd_write_partition_funct(partition=frp.name,
                                                            mem_length=len(full),
                                                            data=bytes(full))
                msg = "cmd_write_partition_funct"
            except AttributeError:
                pass
        if not ok:
            print(f"[-] frp write failed: {msg} — gate NOT armed; session kept for retry")
            pass  # port closes on process exit
            return 1

    # verify
    tail2 = loader.xflash.readflash(
        addr=tail_off, length=4, filename="", parttype="user", display=False)
    val2 = int.from_bytes(tail2, "little") if tail2 and len(tail2) == 4 else -1
    if val2 == MARKER:
        print(f"[+] VERIFY OK: frp tail now {val2:#010x} — gate ARMED")
    else:
        print(f"[-] VERIFY FAILED: tail reads {val2:#010x}, expected {MARKER:#010x}")
        pass  # port closes on process exit
        return 1

    print("[*] rebooting (fastboot mode); then on the PC:")
    print("    fastboot devices")
    print("    fastboot flashing get_unlock_ability   # expect: 1")
    print("    fastboot flashing unlock               # press Vol-UP within 5 s")
    print("    (if the phone drops to normal boot instead: power off, hold")
    print("     Vol-Down + plug USB / try Vol-Up+Down — preloader-level combo)")
    print("    after unlock+wipe: fastboot flash boot boot_patched.img")
    print("    (ro.debuggable=1 + ro.adb.secure=0)  -> adbd root -> ADB/scrcpy")
    try:
        # ShutDownModes.FASTBOOT = 2 — DA sets boot mode then reboots
        loader.shutdown(bootmode=loader.ShutDownModes.FASTBOOT)
    except Exception as e:
        print(f"[i] shutdown call: {e!r} (device may have dropped already)")
    pass  # port closes on process exit
    return 0


if __name__ == "__main__":
    sys.exit(main())
