#!/usr/bin/env python3
"""F5-marker probe (re-writepartition-consumer-wakeup.md §5/§9).

Requires wrapper with OPLUS_PATCH_F5_MARK=1 + OPLUS_PATCH_CONSUMER=1
(see /home/musin/run_f5_dump.sh). Writes 0x1000 pattern to para
(WRITE-PARTITION, pre_erase=NO), then — BEFORE any flash read — dumps the
§5 decision table fields + scheduler state:

  ctx1 = [0x4006E7CC]: +0x00, +0x10, +0x14, +0x18
  ctx2 = [0x4006E7D0]: +0x08, +0x0C, +0x10, +0x14, +0x1C, +0x30, +0x4C,
                       +0x60, +0x9C, +0xA0, +0xA4, +0xA8, +0xC4, +0xE0,
                       +0xE4, +0xE8
  bulk handle 0x4006E790: +0x00, +0x04, +0x08, +0x18, +0x28, +0x2C, +0x34
  0x4006E7C8 (F5 marker word!), 0x4006E6A0 +8/+0xC
  ctx1+0x24 -> 0x58-struct bytes +0..+3, word +0x10
  scheduler: 0x4006A034 ready bitmask, 0x40069EC8 TCB list scan for
             entry == 0x4002ff78 (consumer task) -> [tcb+0x18] state

Then reads para back to confirm unchanged.

Decision table (§5):
  h+0x34 !=0, ctx2+0xA0 >=1, 0x4006E7C8 !=0  -> consumer wrote; UFS layer
  h+0x34 !=0, ctx2+0xA0 >=1, marker ==0      -> consumer ran, len<0x100
  h+0x34 ==0, ctx2+0xA0 ==0                  -> consumer never woke up
"""
import os, sys, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

GO = os.environ.get("F5_GO", "0") == "1"


def dump(xmlft, addr, length, label):
    d = xmlft.custom_read(addr, length)
    if not d:
        print(f"[-] {label} @ {addr:#x}: READ FAIL")
        return None
    b = bytes(d)
    print(f"[*] {label} @ {addr:#x}: {b.hex()}")
    return b


def u32(b, off=0):
    return struct.unpack("<I", b[off:off + 4])[0]


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
        print("[-] connect failed"); return 1
    loader = mtk.daloader
    xmlft = loader.xmlft

    data, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize
    para = next((p for p in gpt.partentries if p.name.lower() == "para"), None)
    if para is None:
        print("[-] no para in GPT"); return 1
    base = para.sector * ss
    fullsize = para.sectors * ss

    orig = loader.readflash(addr=base, length=0x1000, filename="", parttype="user", display=False)
    orig = orig[0] if isinstance(orig, tuple) else orig
    print(f"[*] para original head: {bytes(orig[:16]).hex()}")

    # baseline fields
    print("== BASELINE ==")
    dump(xmlft, 0x4006E7C8, 4, "marker 0x4006E7C8")

    if not GO:
        print("[dryrun] rerun with F5_GO=1")
        return 0

    pattern = (b"PARATEST" * 0x200)[:0x1000]
    assert len(pattern) == 0x1000
    blob = pattern + bytes(orig[0x1000:]) if fullsize > 0x1000 else pattern
    blob = bytes(blob) + bytes(fullsize - len(blob)) if len(blob) < fullsize else bytes(blob[:fullsize])
    print(f"[!] WRITE-PARTITION {len(blob):#x} B -> para ...")
    time.sleep(3)
    ok, msg = xmlft.seccfg_write_partition(para, blob)
    print(f"[*] write: {ok!r} {msg!r}")

    # ---- §5 dump IMMEDIATELY (before any flash read) ----
    print("== §5 DUMP (post-write) ==")
    dump(xmlft, 0x4006E7C8, 4, "F5 MARKER 0x4006E7C8")
    dump(xmlft, 0x4006E6A0 + 8, 8, "0x4006E6A0 +8/+0xC (region list)")
    for base_a, name, offs in (
        (0x4006E7CC, "ctx1 ptr", [0]),
        (0x4006E7D0, "ctx2 ptr", [0]),
    ):
        p = dump(xmlft, base_a, 4, name)
        ptr = u32(p) if p else 0
        print(f"[*] {name} = {ptr:#x}")

    ctx1 = u32(dump(xmlft, 0x4006E7CC, 4, "ctx1")) if True else 0
    ctx2 = u32(dump(xmlft, 0x4006E7D0, 4, "ctx2")) if True else 0
    heap_ok = lambda a: 0x40000000 < a < 0x40300000
    if heap_ok(ctx1):
        for off, ln, lab in ((0x00, 0x20, "ctx1 +0x00..0x1F"),
                             (0x10, 4, "ctx1 +0x10"),
                             (0x18, 4, "ctx1 +0x18"),
                             (0x24, 4, "ctx1 +0x24 (0x58-struct)")):
            dump(xmlft, ctx1 + off, ln, lab)
        p24 = u32(dump(xmlft, ctx1 + 0x24, 4, "ctx1+0x24") or b"\0\0\0\0")
        if heap_ok(p24):
            dump(xmlft, p24, 4, "0x58-struct +0..+3 (policy bytes)")
            dump(xmlft, p24 + 0x10, 4, "0x58-struct +0x10")
    if heap_ok(ctx2):
        for off, ln, lab in ((0x08, 0x18, "ctx2 +0x08..0x1F"),
                             (0x30, 4, "ctx2 +0x30"),
                             (0x4C, 4, "ctx2 +0x4C"),
                             (0x60, 4, "ctx2 +0x60"),
                             (0x9C, 0x10, "ctx2 +0x9C..0xAB (A0/A4/A8)"),
                             (0xC4, 4, "ctx2 +0xC4"),
                             (0xE0, 0xC, "ctx2 +0xE0/E4/E8")):
            dump(xmlft, ctx2 + off, ln, lab)
    h = dump(xmlft, 0x4006E790, 0x38, "bulk handle +0x00..0x37")
    if h:
        for off in (0x00, 0x04, 0x08, 0x18, 0x28, 0x2C, 0x34):
            print(f"[*] h+{off:#x} = {u32(h, off):#x}")

    # scheduler state
    dump(xmlft, 0x4006A034, 8, "ready bitmask 0x4006A034")
    # TCB list scan: 0x40069EC8 list, find tcb with [tcb+0x38]==0x4002ff78
    lst = dump(xmlft, 0x40069EC8, 0x40, "TCB list head 0x40069EC8")
    if lst:
        seen = 0
        node = u32(lst)
        while 0x40000000 < node < 0x40300000 and seen < 16:
            t = dump(xmlft, node, 0x40, f"TCB node {seen} @ {node:#x}")
            if not t:
                break
            entry = u32(t, 0x38) if len(t) >= 0x3C else 0
            state = u32(t, 0x18) if len(t) >= 0x1C else -1
            if entry == 0x4002FF78:
                print(f"[+] CONSUMER TCB @ {node:#x}: state[+0x18]={state}")
            node = u32(t)
            seen += 1

    # flash check LAST
    time.sleep(1.0)
    rb = loader.readflash(addr=base, length=0x1000, filename="", parttype="user", display=False)
    rb = rb[0] if isinstance(rb, tuple) else rb
    if rb == pattern:
        print("[+] PARA COMMITTED")
    elif rb == orig:
        print("[-] para UNCHANGED")
    else:
        print(f"[!] para changed: {bytes(rb[:16]).hex() if rb else None}")
    print("[*] probe done")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
