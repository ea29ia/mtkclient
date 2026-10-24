#!/usr/bin/env python3
"""RGU nibble experiment: does boot-mode nibble @0x10007024 survive a reboot?

Session A (this script):
  1) connect (proven DA path),
  2) READ-REGISTER 0x10007024 -> print nibble[3:0] (baseline; expect 0),
  3) WRITE-REGISTER: set bits[3:0] = 3 (FASTBOOT per LK priority table),
  4) re-read -> verify,
  5) REBOOT IMMEDIATE (DPC path, bic 0xff0 preserves [3:0] — proven).

Session B (next run, --check):
  1) connect fresh,
  2) READ-REGISTER 0x10007024 -> if nibble == 3 => it SURVIVED reset chain
     (LK must have seen fastboot — investigate LK side next);
     if nibble == 0 => nibble is LOST in reset chain (BROM/PMIC) =>
     DA2->fastboot impossible, fall back to button combos.

Usage:
  python docs/notes/rgu_nibble_test.py            # session A
  python docs/notes/rgu_nibble_test.py --check    # session B
Env vars: same OPLUS_* set by the run_*.sh wrappers.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

RGU = 0x10007024


def read_nibble(loader):
    data = loader.xmlft.read_register(RGU)
    if data is None:
        return None
    if isinstance(data, str):
        data = bytes.fromhex(data)
    val = int.from_bytes(data[:4], "little")
    return val


def write_nibble(loader, val):
    # write full 32-bit word with bits[3:0]=val, rest preserved by caller
    data = val.to_bytes(4, "little")
    return loader.xmlft.write_register(addr=RGU, data=data)


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

    val = read_nibble(loader)
    if val is None:
        print("[-] READ-REGISTER failed")
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

    # Session A: set nibble 3 preserving the rest
    newval = (val & ~0xF) | 3
    ok = write_nibble(loader, newval)
    if not ok:
        print("[-] WRITE-REGISTER failed")
        return 1
    val2 = read_nibble(loader)
    print(f"[*] after write: 0x{RGU:08x} = {val2:#010x}, nibble = {val2 & 0xF:#x}")
    if (val2 & 0xF) != 3:
        print("[-] write did not stick — aborting before reboot")
        return 1
    print("[+] nibble 3 set. Rebooting IMMEDIATE (DPC path preserves [3:0])...")
    loader.shutdown(bootmode=loader.ShutDownModes.NORMAL)
    print("[*] NEXT SESSION: ./run_rgu_check.sh  (expect nibble 3 == survived)")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
