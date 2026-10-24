#!/usr/bin/env python3
"""RGU nibble experiment v2 — via the PROVEN CUSTOMMEMR/CUSTOMMEMW primitives
(the same mechanism as the BROM dump, which worked on this unit).

Session A:
  1) connect,
  2) custom_read 0x10007024 -> print nibble[3:0] (baseline; expect 0),
  3) custom_write bits[3:0] = 3 (FASTBOOT per LK priority table),
  4) re-read -> verify,
  5) reboot (WDT SW-reset path preserves [3:0] — proven static).

Session B (--check): fresh connect, custom_read, verdict.

Usage:
  python docs/notes/rgu_nibble_test.py            # session A
  python docs/notes/rgu_nibble_test.py --check    # session B
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

RGU = 0x10007024


def read_word(loader):
    data = loader.xmlft.custom_read(RGU, 4)
    if not data or len(data) < 4:
        print(f"[dbg] custom_read returned {data!r}")
        return None
    print(f"[dbg] custom_read: {bytes(data).hex()}")
    return int.from_bytes(bytes(data[:4]), "little")


def write_word(loader, val):
    ok = loader.xmlft.custom_write(RGU, val.to_bytes(4, "little"))
    print(f"[dbg] custom_write -> {ok}")
    return ok


def main():
    import argparse
    import mtk as mtk_cli
    check = "--check" in sys.argv
    sys.argv = [a for a in sys.argv if a != "--check"]
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

    val = read_word(loader)
    if val is None:
        print("[-] custom_read failed")
        return 1
    print(f"[*] 0x{RGU:08x} = {val:#010x}, nibble[3:0] = {val & 0xF:#x}")

    if check:
        n = val & 0xF
        if n == 3:
            print("[!!!] NIBBLE SURVIVED the reset chain (== 3). LK *must* have")
            print("     seen FASTBOOT — if the phone booted normal, the loss is")
            print("     AFTER RGU: check LK-side read path / oplus boot-arg hooks.")
        elif n == 0:
            print("[!] NIBBLE LOST in the reset chain (== 0). DA2->fastboot via")
            print("    RGU is IMPOSSIBLE on this unit; button combos remain.")
        else:
            print(f"[?] unexpected nibble {n:#x}")
        return 0

    newval = (val & ~0xF) | 3
    ok = write_word(loader, newval)
    if not ok:
        print("[-] custom_write failed")
        return 1
    val2 = read_word(loader)
    if val2 is None:
        print("[-] verify read failed")
        return 1
    print(f"[*] after write: 0x{RGU:08x} = {val2:#010x}, nibble = {val2 & 0xF:#x}")
    if (val2 & 0xF) != 3:
        print("[-] write did not stick — aborting before reboot")
        return 1
    print("[+] nibble 3 set. Rebooting (WDT SW-reset preserves [3:0])...")
    loader.shutdown(bootmode=loader.ShutDownModes.NORMAL)
    print("[*] NEXT SESSION: ./run_rgu_check.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
