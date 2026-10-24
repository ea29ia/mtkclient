#!/usr/bin/env python3
"""Discrimination test (jaq follow-up): does the WRITE-PARTITION program
phase commit AT ALL on this DA2?

Test: write a 0x1000-byte distinctive pattern to the UNPROTECTED `para`
partition (first 0x1000 bytes only), read back, restore original.
- para commits  -> program engine works; seccfg is silently protected
                   (deeper OPLUS write-intercept) -> find the intercept.
- para no-write -> program phase never commits for any partition (flush/
                   commit broken with our session style) -> investigate
                   engine/commit path (0x400306ac -> 0x40008234 stub etc).

Read-only unless PARA_GO=1.
"""
import os, sys, struct, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

GO = os.environ.get("PARA_GO", "0") == "1"


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
    print(f"[+] para: LBA {para.sector:#x} base {base:#x} (block-aligned: {base % 0x1000 == 0})")

    orig = loader.readflash(addr=base, length=0x1000, filename="/tmp/para_orig.bin",
                            parttype="user", display=False)
    orig = orig[0] if isinstance(orig, tuple) else orig
    if not orig or isinstance(orig, bool) or len(orig) < 0x1000:
        # with a filename the readflash path returns True, not data — re-read
        # into memory (no filename) to get bytes
        orig = loader.readflash(addr=base, length=0x1000, filename="",
                                parttype="user", display=False)
        orig = orig[0] if isinstance(orig, tuple) else orig
    if not orig or isinstance(orig, bool) or len(orig) < 0x1000:
        print("[-] para read failed"); return 1
    print(f"[*] para original head: {bytes(orig[:32]).hex()}")

    pattern = (b"PARATEST" * 128)[:0x1000]  # 4096 B distinctive
    if not GO:
        print("[dryrun] would write 0x1000 pattern to para. Rerun with PARA_GO=1")
        return 0

    print("[!] WRITE-PARTITION 0x1000 pattern -> para ...")
    time.sleep(3)
    # NOTE: para partition full size may exceed 0x1000; per the fullsize lesson
    # the DA region may be the WHOLE partition. To keep the transfer matched,
    # send pattern padded to the FULL para size (zeros after 0x1000 would erase
    # the rest... but pre_erase=NO means we only program; zeros would overwrite!
    # Safer: write pattern+original-rest: pattern for first 0x1000, original for the rest.
    fullsize = para.sectors * ss
    blob = pattern + bytes(orig[0x1000:]) if fullsize > 0x1000 else pattern
    blob = bytes(blob) + bytes(fullsize - len(blob)) if len(blob) < fullsize else bytes(blob[:fullsize])
    ok, msg = xmlft.seccfg_write_partition(para, blob)
    print(f"[*] write result: {ok!r} {msg!r}")

    time.sleep(1.0)
    rb = loader.readflash(addr=base, length=0x1000, filename="", parttype="user", display=False)
    rb = rb[0] if isinstance(rb, tuple) else rb
    if rb and not isinstance(rb, bool) and rb == pattern:
        print("[+] PARA COMMITTED — program engine WORKS; seccfg is silently protected")
        # restore
        print("[*] restoring para original...")
        time.sleep(1)
        full = loader.readflash(addr=base, length=fullsize, filename="/tmp/para_after.bin",
                                parttype="user", display=False)
        ok2, _ = xmlft.seccfg_write_partition(para, bytes(orig) + bytes(fullsize - 0x1000))
        rb2 = loader.readflash(addr=base, length=0x1000, filename="", parttype="user", display=False)
        rb2 = rb2[0] if isinstance(rb2, tuple) else rb2
        print(f"[*] para restore: {'OK' if rb2 == orig else 'MISMATCH'}")
        return 0
    elif rb and not isinstance(rb, bool) and rb == orig:
        print("[-] para UNCHANGED — program phase does NOT commit (global write issue)")
        return 1
    else:
        print(f"[!] para changed but != pattern: {bytes(rb[:32]).hex() if rb else None}")
        return 1


if __name__ == "__main__":
    sys.exit(main() or 0)
