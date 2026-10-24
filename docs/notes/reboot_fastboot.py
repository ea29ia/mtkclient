#!/usr/bin/env python3
"""Ask the DA to reboot into bootloader fastboot (SET-BOOT-MODE=FASTBOOT).

Uses the same connect path as Plan A, then ShutDownModes.FASTBOOT.

EXPECTATION (corrected, audit #2): this usually does NOT produce a fastboot
device on RMX3630.  LK enters mode 0x63 only if (a) the preloader-owned HW boot
nibble 0x10007024 & 0xF == 3, or (b) the reset-reason class check 0x5000B1E8
returns bit0 and seccfg lock_state == 3.  The DA's SET-BOOT-MODE value is not
forwarded through the preloader.  Observed result: 22d9:0006 -> 22d9:2046
(Android).  Treat a missing fastboot device as the expected outcome.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


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
    print("[*] sending reboot-to-fastboot (ShutDownModes.FASTBOOT)...")
    # The session ran with OPLUS_LEGACY_HOST=1 (single-shot, no retry). The
    # first SET-BOOT-MODE can hit the EIO class hazard — enable the proven
    # retry path in send_command just for the shutdown phase, and retry the
    # whole call a few times.
    os.environ["OPLUS_LEGACY_HOST"] = "0"
    import time
    for attempt in range(3):
        try:
            if loader.shutdown(bootmode=loader.ShutDownModes.FASTBOOT):
                print("[+] DA accepted SET-BOOT-MODE=FASTBOOT and reboot.")
                print("[*] Watch the USB for ~60 s.  Do NOT expect fastboot: "
                      "the preloader re-derives the boot mode, so the usual "
                      "outcome is 22d9:0006 -> 22d9:2046 (Android).  Verify "
                      "with `lsusb | grep -e 18d1 -e 22d9` and `fastboot devices`.")
                return 0
            print(f"[-] shutdown attempt {attempt + 1} returned False")
        except Exception as e:
            print(f"[!] shutdown attempt {attempt + 1}: {e!r}")
        time.sleep(1.0)
    print("[!] all attempts failed — device may reboot to normal mode; "
          "check lsusb for 22d9:2046")
    return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
