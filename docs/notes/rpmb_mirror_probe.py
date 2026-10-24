#!/usr/bin/env python3
"""Q3 probe (READ-ONLY): is the DA's RPMB read path real on this UFS unit?

Background: LK reads the boot-info mirror (0x400 B at RPMB sector 0, TEE op
0x1DC) and demonstrably sees locked_bit=1 (it re-locks the device), yet the DA
returns all zeros for sectors 0..0x7F *and* returns the same zeros with a
deliberately wrong key.  Reads are supposed to be authenticated in RPMB, so
either the DA stub (`mmc_rpmb_send_command`, eMMC flavour) never reaches the
UFS RPMB, or the extracted key is irrelevant.

This probe re-checks the three discriminators in ONE session, no writes:

  1. derived key D (HACC from MEID, CUSTOMRPMBI) -> read sectors 0..3, dump;
  2. wrong key (0xA5 * 32)                        -> read sectors 0..3;
     * same data (or success)  => reads are NOT authenticated => DA data is
       not evidence of the real RPMB content;
     * auth failure            => reads ARE gated => D is the device key (or
       the device answer is real).
  3. GET-RPMB-KEY-STATUS with a FIXED parser (the old one searched for the
     substring "EXIST", which "NOT-EXIST" also contains).

Also reads sectors 0x1DC..0x1DF: `0x1DC` is the TEE op id in LK, not a sector,
but a couple of tools treat it as an address — this cheaply rules that out.

Outputs: /home/musin/rpmb_probe_derived.bin
         /home/musin/rpmb_probe_wrongkey.bin
         /home/musin/rpmb_probe_1dc.bin
"""
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(HERE)))
os.chdir(os.path.dirname(os.path.dirname(HERE)))
sys.path.insert(0, HERE)

from planb_recon2 import (  # noqa: E402  (helpers, no side effects beyond constants)
    rpmbk_set_key,
    rpmbi_derive,
    read_rpmb_range,
    analyze_dump,
)

WRONG_KEY = b"\xA5" * 32


def mirror_report(blob: bytes, label: str):
    if len(blob) < 0x400:
        print(f"[-] {label}: short read ({len(blob):#x})")
        return
    blk = blob[:0x400]
    sboot, devinfo, bootmode, locked = struct.unpack("<4I", blk[:16])
    aux = struct.unpack("<I", blk[0x10:0x14])[0]
    calc = hashlib.sha256(blk[:0x3E0]).digest()
    stored = blk[0x3E0:0x400]
    print(f"[*] {label} mirror block:")
    print(f"    +0x00 sboot={sboot}  +0x04 dev_info={devinfo}  "
          f"+0x08 last_bootmode={bootmode}  +0x0C locked_bit={locked}  +0x10 aux={aux:#x}")
    print(f"    sha256(0..0x3E0)={calc.hex()}")
    print(f"    stored    [0x3E0]={stored.hex()}")
    print(f"    hash {'VALID' if calc == stored else 'MISMATCH'}"
          f"{' (would zero the buffer -> mirror=0 -> no re-lock)' if calc != stored else ''}")
    print(f"    raw head: {blk[:0x40].hex()}")


def key_status(xmlft):
    """GET-RPMB-KEY-STATUS with a correct parser."""
    print("[*] EMMC-CONTROL GET-RPMB-KEY-STATUS ...")
    try:
        xmlft.xflash.send_command(
            xmlft.xflash.cmd.cmd_emmc_control(function="GET-RPMB-KEY-STATUS"), noack=True)
        cmd, result = xmlft.xflash.get_command_result()
        if result is None or isinstance(result, str):
            print(f"[-] no UpFile reply: cmd={cmd!r} result={str(result)[:200]!r}")
            return None
        data = xmlft.xflash.download(result)
        scmd, sresult = xmlft.xflash.get_command_result()
        xmlft.xflash.ack()
        if sresult == "OK":
            tcmd, tresult = xmlft.xflash.get_command_result()
            print(f"[*] tail: {tcmd!r} {tresult!r}")
        text = bytes(data).decode('utf-8', errors='replace') if data else ""
        v = text.strip("\x00 \r\n\t")
        print(f"[*] raw value: {text!r}")
        if "NOT-EXIST" in v:
            verdict = "NOT-EXIST (key NOT programmed, per DA)"
        elif "EXIST" in v:
            verdict = "EXIST (key programmed, per DA)"
        else:
            verdict = f"UNPARSED ({v!r})"
        print(f"[+] verdict: {verdict}")
        return v
    except Exception as e:
        print(f"[-] key-status error: {e!r}")
        return None


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

    print("[*] custom_rpmb_init(None) — DA derives the key via HACC ...")
    ok = xmlft.custom_rpmb_init()
    print(f"[*] rpmb_init -> {ok}")
    D = rpmbi_derive(xmlft)
    if D is None:
        print("[-] could not obtain derived key — abort")
        return 1
    print(f"[+] derived key D = {D.hex()}")

    # --- 1. correct key ---
    if not rpmbk_set_key(xmlft, D):
        print("[-] cannot set key D — abort")
        return 1
    good, _ = read_rpmb_range(xmlft, 0, 4, "D")
    open("/home/musin/rpmb_probe_derived.bin", "wb").write(good)
    print(f"[*] read with D: {len(good)} B")
    mirror_report(good, "key=D")
    analyze_dump(good, 0)

    # --- 2. wrong key control ---
    print("[*] control: CUSTOMRPMBK(wrong key) + read 0..3")
    if rpmbk_set_key(xmlft, WRONG_KEY):
        bad, _ = read_rpmb_range(xmlft, 0, 4, "WRONG")
        open("/home/musin/rpmb_probe_wrongkey.bin", "wb").write(bad)
        if bad:
            same = bad == good
            print(f"[!] read SUCCEEDED with a WRONG key ({len(bad)} B, "
                  f"{'IDENTICAL to key=D read' if same else 'DIFFERENT'})")
            print("    => DA RPMB reads are NOT authenticated: they cannot be "
                  "used as evidence about the real UFS RPMB content")
            mirror_report(bad, "key=wrong")
        else:
            print("[+] read FAILED with a wrong key => reads ARE authenticated; "
                  "D is the real device RPMB key")
    else:
        print("[!] wrong-key set failed — control skipped")

    # --- 3. key status (fixed parse) ---
    key_status(xmlft)

    # --- 4. 0x1DC as sector? (op-id vs address ambiguity) ---
    print("[*] reading sectors 0x1DC..0x1DF (rules out op-id/sector confusion)")
    rpmbk_set_key(xmlft, D)
    d2, _ = read_rpmb_range(xmlft, 0x1DC, 4, "0x1DC")
    open("/home/musin/rpmb_probe_1dc.bin", "wb").write(d2)
    print(f"[*] read 0x1DC: {len(d2)} B, nonzero="
          f"{sum(1 for b in d2 if b)}")
    if d2:
        mirror_report(d2, "sector 0x1DC")

    print("[*] probe done (read-only)")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
