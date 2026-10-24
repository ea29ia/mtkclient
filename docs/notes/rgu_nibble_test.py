#!/usr/bin/env python3
"""RGU nibble experiment v3 — РАБОЧИЙ метод записи в 0x10007024.

ПРИЧИНА БАГА v1 (proven, re-rgu-write.md §1): handler CMD:CUSTOMMEMW
в payloads/da_xml.bin (Thumb @0x448) НЕ ИМЕЕТ инструкции записи — он читает
адрес (8Б), длину (4Б) и данные (≤4Б) в собственный стек (данные затирают
буфер адреса) и возвращает 0 = OK. Поэтому custom_write() возвращал True,
а регистр оставался нетронутым. Никакого "APB bridge" (ai.txt §1) нет.

РАБОЧИЙ метод [proven по дизасму handler'а 0x48c]: CMD:CUSTOMREGW
(custom_writeregister) — читает 4Б адреса + 4Б значения и делает прямой
`str r0,[r1]` без каких-либо проверок адреса. DA2 сам пишет 0x10007024
такими же прямыми str (re-da2-bootmode-reboot.md §1.1/§4.3), т.е. регион
отображён и доступен на запись; unlock-последовательностей RGU нет.

Резервный метод [inferred, high]: heapbait.patch_mem (CMD:EXP-PATCH-MEM) —
уже писал в RAM DA2 (0x4005455c); адрес передаётся как VA, RGU в том же
адресном пространстве identity-mapped.

ВНИМАНИЕ: EXP-CALL-FUNC(0x4002a520) как fallback НЕ годится: (1) хендлер
EXP-CALL-FUNC парсит только da/arg/address — r0 не передаётся; (2) сам
0x4002a520 пишет ниббль в биты [7:4] (orr r0,lsl#4 после bic 0xff0), а
SET-BOOT-MODE/LK-семантика требует биты [3:0] (bfi #0,#4).

Session A:
  1) connect,
  2) custom_readregister 0x10007024 -> nibble[3:0] (baseline; expect 0),
  3) custom_writeregister bits[3:0] = 3 (FASTBOOT per LK priority table),
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
    data = loader.xmlft.custom_readregister(RGU, 1)
    if isinstance(data, int):
        print(f"[dbg] custom_readregister -> {data:#010x}")
        return data
    if data is None:
        return None
    if isinstance(data, list):
        print(f"[dbg] custom_readregister -> {[hex(v) for v in data]}")
        return data[0]
    print(f"[dbg] custom_readregister returned {data!r}")
    return None


def write_word(loader, val):
    # CUSTOMREGW (shellcode handler Thumb @0x48c): recv 4B addr + 4B value,
    # затем прямой `str r0,[r1]`. CUSTOMMEMW НЕ ПИШЕТ вообще — его handler
    # (@0x448) не содержит ни одной store-инструкции (re-rgu-write.md §1).
    ok = loader.xmlft.custom_writeregister(RGU, val)
    print(f"[dbg] custom_writeregister -> {ok}")
    return ok


def main():
    import argparse
    import mtk as mtk_cli
    check = "--check" in sys.argv
    nib = None
    if "--nibble" in sys.argv:
        i = sys.argv.index("--nibble")
        if i + 1 < len(sys.argv):
            nib = int(sys.argv[i + 1], 0)
        # remove both tokens before mtk's parser sees them
        del sys.argv[i:i + 2]
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
        print(f"[*] NEXT-BOOT nibble = {n:#x} "
              + ("(consumed by LK — channel WORKS)" if n == 0 else
                 "(SURVIVED — LK never ran?)"))
        return 0

    nibble = nib if nib is not None else 3
    newval = (val & ~0xF) | nibble
    ok = write_word(loader, newval)
    if not ok:
        print("[-] custom_writeregister failed — fallback: heapbait EXP-PATCH-MEM")
        import struct
        try:
            ok = loader.xmlft.heapbait.patch_mem(RGU, struct.pack("<I", newval))
            print(f"[dbg] patch_mem -> {ok}")
        except Exception as e:
            print(f"[!] patch_mem error: {e!r}")
    val2 = read_word(loader)
    if val2 is None:
        print("[-] verify read failed")
        return 1
    print(f"[*] after write: 0x{RGU:08x} = {val2:#010x}, nibble = {val2 & 0xF:#x}")
    if (val2 & 0xF) != nibble:
        print("[-] write did not stick — aborting before reboot")
        return 1
    names = {2: "RECOVERY", 3: "FASTBOOT", 4: "FACTORY", 1: "META/RECOVERY"}
    nname = names.get(nibble, f"mode-{nibble:#x}")
    print(f"[+] nibble {nibble} ({nname}) set. Rebooting (WDT SW-reset preserves [3:0])...")
    try:
        loader.shutdown(bootmode=loader.ShutDownModes.NORMAL)
    except Exception as e:
        print(f"[i] shutdown: {e!r} (device may have dropped already)")
    print("[*] NEXT SESSION: ./run_rgu_check.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
