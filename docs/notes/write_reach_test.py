#!/usr/bin/env python3
"""Q1 test: does a full-size WRITE-PARTITION really program the TAIL?

The unlock write sent 8 MB to `seccfg`; after the reboot the vendor marker at
offset 0x200 was present again.  Either the DA programs only the received bytes
(it always sends `<pre_erase>NO</pre_erase>`, and the consumer loops until
`accumulated == target`, target = received length), or an external full restore
exists.  This test discriminates on the unprotected `para` partition, which is
all zero on this unit.

Writes an image with a distinctive 0x1000-byte marker at offset 0 AND at the
last 0x1000 bytes, re-reads both ends, then ALWAYS restores the original image
and verifies it end-to-end (restore runs in `finally`, even on exception).

NOTE (audit #2): a same-session readback is weak evidence — v6.py documents that
in-session readbacks can deadlock/patch the protocol.  If the result matters,
re-check the partition in a FRESH preloader session.

WRITE unless WRITE_REACH_GO=1 (default: dry-run, reads and prints the plan).
"""
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

GO = os.environ.get("WRITE_REACH_GO", "0") == "1"
# NOTE: the pattern must be EXACTLY 0x1000 bytes.  (b"X"*128)[:0x1000] is a
# classic bug: "REACHHEAD" is 9 chars => 1152 bytes, which shrinks the image and
# makes every comparison fail.  Build a long pattern first, then slice.
MARK_HEAD = (b"REACHHEAD" * 0x200)[:0x1000]
MARK_TAIL = (b"REACHTAIL" * 0x200)[:0x1000]
BEFORE = "/home/musin/para_reach_before.bin"
AFTER = "/home/musin/para_reach_after_restore.bin"

assert len(MARK_HEAD) == 0x1000 and len(MARK_TAIL) == 0x1000, "marker length bug"


def rd(loader, addr, length):
    d = loader.readflash(addr=addr, length=length, filename="", parttype="user", display=False)
    d = d[0] if isinstance(d, tuple) else d
    if not d or isinstance(d, bool):
        return b""
    return bytes(d[:length])


def main():
    import argparse
    import mtk as mtk_cli
    parser = mtk_cli.create_base_parser()
    parser = argparse.ArgumentParser(parents=[parser], description=mtk_cli.INFO)
    sub = parser.add_subparsers(dest='cmd', required=False)
    sub.add_parser('custom')
    args = parser.parse_args(sys.argv[1:] + ['custom'])
    from mtkclient.Library.mtk_main import Main
    mtk = Main(args).run(parser)
    if mtk is None:
        print("[-] connect failed")
        return 1
    loader = mtk.daloader
    xmlft = loader.xmlft

    _, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = gpt.sectorsize
    para = next((p for p in gpt.partentries if p.name.lower() == "para"), None)
    if para is None:
        print("[-] no para in GPT")
        return 1
    base = para.sector * ss
    full = para.sectors * ss
    print(f"[+] para: LBA {para.sector:#x} base {base:#x} size {full:#x}")

    orig = rd(loader, base, full)
    if len(orig) != full:
        print(f"[-] full read failed: {len(orig):#x} != {full:#x}")
        return 1
    open(BEFORE, "wb").write(orig)
    print(f"[*] original: md5={hashlib.md5(orig).hexdigest()} "
          f"nonzero={sum(1 for b in orig if b)} saved -> {BEFORE}")
    if orig != bytes(full):
        print("[!] para is NOT all zero — the test image will overwrite it; "
              "it is saved and restored in `finally`")

    img = bytearray(full)
    img[0:0x1000] = MARK_HEAD
    img[full - 0x1000:full] = MARK_TAIL
    img = bytes(img)
    assert len(img) == full, f"image length bug: {len(img):#x} != {full:#x}"
    print(f"[*] test image: {len(img):#x} B, markers at 0x0 and 0x{full - 0x1000:x}, "
          f"md5={hashlib.md5(img).hexdigest()}")

    if not GO:
        print("[dryrun] rerun with WRITE_REACH_GO=1 to write + verify + restore")
        return 0

    verdict = 9
    try:
        print("[!] WRITING full para (WRITE-PARTITION, pre_erase=NO) ...")
        time.sleep(3)
        ok, msg = xmlft.seccfg_write_partition(para, img)
        print(f"[*] write: {ok!r} {msg!r}")
        if ok:
            time.sleep(1.0)
            head = rd(loader, base, 0x1000)
            tail = rd(loader, base + full - 0x1000, 0x1000)
            head_ok = head == MARK_HEAD
            tail_ok = tail == MARK_TAIL
            print(f"[*] head marker: {'OK' if head_ok else 'MISSING'} ({head[:16].hex()})")
            print(f"[*] tail marker: {'OK' if tail_ok else 'MISSING'} ({tail[:16].hex()})")
            if head_ok and tail_ok:
                print("[+] FULL WRITE CONFIRMED (same session) — the DA programs the "
                      "whole region; the reverted seccfg 0x200 marker then means an "
                      "EXTERNAL full restore. Re-verify in a fresh session before "
                      "acting on it.")
                verdict = 0
            elif head_ok and not tail_ok:
                print("[!] PARTIAL WRITE — only the received prefix is programmed "
                      "(tail untouched). With a size-matched 8 MB seccfg write this "
                      "would NOT explain the revert, so an external restore is still "
                      "the better hypothesis.")
                verdict = 2
            elif not head_ok and not tail_ok:
                print("[-] NOTHING CHANGED — the write did not commit at all")
                verdict = 3
            else:
                print("[?] unexpected: tail changed, head did not")
                verdict = 4
        else:
            print("[-] write rejected")
            verdict = 5
    finally:
        print("[*] restoring para original (always) ...")
        try:
            time.sleep(1.0)
            ok2, msg2 = xmlft.seccfg_write_partition(para, orig)
            print(f"[*] restore write: {ok2!r} {msg2!r}")
            time.sleep(1.0)
            cur = rd(loader, base, full)
            open(AFTER, "wb").write(cur)
            if cur == orig:
                print(f"[+] para restored (md5 {hashlib.md5(cur).hexdigest()})")
            else:
                print(f"[!] RESTORE MISMATCH — rerun immediately, do not reboot "
                      f"(md5 {hashlib.md5(cur).hexdigest()})")
                verdict = 6
        except Exception as e:  # noqa: BLE001 — must report, not hide
            print(f"[!] RESTORE FAILED: {e!r} — rerun or restore from {BEFORE}")
            verdict = 7
    return verdict


if __name__ == "__main__":
    sys.exit(main() or 0)
