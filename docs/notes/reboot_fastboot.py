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
    try:
        loader.shutdown(bootmode=loader.ShutDownModes.FASTBOOT)
        print("[+] sent. Watch the USB: device should re-enumerate as fastboot "
              "(Google 18d1:4ee0/4ee8 or similar).")
    except Exception as e:
        print(f"[!] shutdown call: {e!r} (device may have dropped already)")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
