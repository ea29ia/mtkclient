#!/usr/bin/env python3
"""Reboot the device into bootloader fastboot via DA (no buttons needed).

Uses the same connect path as Plan A, then ShutDownModes.FASTBOOT.
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
                print("[+] shutdown OK. Watch the USB: device should "
                      "re-enumerate as fastboot (18d1:4ee0/4ee8 or similar).")
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
