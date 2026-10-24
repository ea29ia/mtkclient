#!/usr/bin/env python3
"""Plan B step 2: RPMB reconnaissance v2 (STILL READ-ONLY — no RPMB writes, no key prog).

Goals (fixes/extends planb_recon.py):
1) seccfg parse FIXED: dwords = [magic "MMMM", ver, size, lock_state, dm_verity,
   sboot, end "EEEE"] — recon v1 unpacked the magic as `ver` (1296911693=0x4D4D4D4D).
2) custom_rpmb_init(None) -> DA HACC-derived key D (printed by DA; expected 75a41c1a...).
   Save D to /home/musin/rpmb_key_derived.bin.
3) Key experiments to answer "is D the REAL device key?":
   a) CUSTOMRPMBK(D) directly (raw, like custom_rpmb_init does) -> read sectors 0..15.
   b) CUSTOMRPMBK(WRONG=b"\x11"*32) -> read sectors 0..3:
      - error (JEDEC result 1) => reads ARE device-authenticated => baseline success
        with D proves D == device RPMB key (factory key confirmed).
      - success => reads are NOT key-gated => the all-zero read is REAL data
        regardless of key; key question stays open (see 4).
   c) CUSTOMRPMBI(mode=0) raw after (b): does the DA return D again (independent
      HACC derivation) and does it OVERRIDE the working key? Follow-up read 0..3
      shows which key is in effect.
   d) restore CUSTOMRPMBK(D).
4) Extended RPMB scan: sectors 0..0x7F (128 x 256B = 32 KB) in 16-sector chunks.
   Stop on first error (with END/START ack-dance recovery — v6.custom_rpmb_read
   forgets the dance on error and would desync the protocol).
   Look for: t-base superblock magic "4400RPMB" at any 256-B boundary (=> S = k),
   any nonzero sector, any "RPMB" ASCII.
5) GET-RPMB-KEY-STATUS via CMD:EMMC-CONTROL (unwired in mtkclient; raw call here,
   check_lifecycle pattern from xml_lib.py:1619). EXIST/NOT-EXIST discriminates
   "key never provisioned" vs "key programmed".

NO custom_rpmb_prog() / write_rpmb() / erase_rpmb() calls — read-only session.

Outputs:
  /home/musin/planb_recon2.log (via wrapper tee)
  /home/musin/rpmb_key_derived.bin
  /home/musin/rpmb_exp1_derivedkey.bin   (sectors 0..15, key D)
  /home/musin/rpmb_scan.bin              (extended scan, key D)
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

KEY_STAGE = 0x4006E8D8
WRONG_KEY = b"\x11" * 32
SCAN_SECTORS = 0x80          # 128 sectors = 32 KB
CHUNK = 0x10                 # CUSTOMRPMBR chunk size used by mtkclient

RPMB_ERRORS = {
    0: "OK",
    1: "AUTH FAILURE (wrong key / general failure)",
    2: "COUNTER FAILURE",
    3: "ADDRESS FAILURE (out of range)",
    4: "WRITE FAILURE",
    5: "READ FAILURE",
    6: "AUTH KEY NOT YET PROGRAMMED",
}


def rpmb_err(raw: bytes) -> str:
    code = int.from_bytes(raw, 'little') if raw else -1
    return f"result={code} ({RPMB_ERRORS.get(code, 'unknown')})"


def rpmbk_set_key(xmlft, key: bytes) -> bool:
    """Raw CUSTOMRPMBK — set the DA working key WITHOUT the CUSTOMRPMBI step
    (so the derived key cannot override it). Mirrors v6.py:775-788."""
    xmlcmd = xmlft.xflash.cmd.create_cmd("CUSTOMRPMBK")
    if xmlft.xsend(xmlcmd):
        result = xmlft.xflash.get_response()
        if result == "OK":
            xmlft.xsend(key)
            read_key = xmlft.xflash.get_response(raw=True)
            # CMD:END
            result = xmlft.xflash.get_response()
            xmlft.xflash.ack()
            # CMD:START
            result = xmlft.xflash.get_response()
            xmlft.xflash.ack()
            if read_key == key:
                print(f"[*] CUSTOMRPMBK: key set + echo ok ({key.hex()})")
                return True
            print(f"[!] CUSTOMRPMBK echo mismatch: {read_key.hex() if read_key else None}")
    print("[-] CUSTOMRPMBK failed")
    return False


def rpmbi_derive(xmlft) -> bytes:
    """Raw CUSTOMRPMBI mode=0 — returns the key blob the DA sends back
    (its HACC-derived RPMB key). Mirrors v6.py:789-816."""
    xmlcmd = xmlft.xflash.cmd.create_cmd("CUSTOMRPMBI")
    if xmlft.xsend(xmlcmd):
        result = xmlft.xflash.get_response()
        if result == "OK":
            xmlft.xsend(0)  # mode 0 on hwcode 0x1208
            status = xmlft.xflash.get_response(raw=True)
            code = int.from_bytes(status, 'little') if status else -1
            if code == 0:
                derived = xmlft.xflash.get_response(raw=True)
                # CMD:END
                result = xmlft.xflash.get_response()
                xmlft.xflash.ack()
                # CMD:START
                result = xmlft.xflash.get_response()
                xmlft.xflash.ack()
                print(f"[*] CUSTOMRPMBI: status=0, returned key {bytes(derived).hex()}")
                return bytes(derived)
            print(f"[-] CUSTOMRPMBI status={code}")
    return None


def rpmb_read_chunk(xmlft, sector, sectors):
    """custom_rpmb_read + END/START ack-dance recovery on error
    (v6.py:703-726 returns early on per-sector error without the dance)."""
    data = xmlft.custom_rpmb_read(sector=sector, sectors=sectors)
    if data == b"":
        # error already logged by v6 as "Error on sector ...: <msg>"
        # the DA still closes the command session — do the dance to resync
        try:
            r = xmlft.xflash.get_response()
            xmlft.xflash.ack()
            r = xmlft.xflash.get_response()
            xmlft.xflash.ack()
            print(f"[*] ack-dance recovery after read error at sector {sector}: END={r!r}")
        except Exception as e:
            print(f"[!] ack-dance recovery failed: {e!r}")
    return data


def read_rpmb_range(xmlft, start, count, label):
    """Read `count` sectors from `start` in CHUNK-sized pieces; returns bytes
    (truncated at first error) and the sector index where it stopped."""
    buf = bytearray()
    done = 0
    while done < count:
        sz = min(CHUNK, count - done)
        data = rpmb_read_chunk(xmlft, start + done, sz)
        if data == b"":
            print(f"[-] {label}: read failed at sector {start + done}")
            break
        buf.extend(data)
        done += sz
    return bytes(buf), start + done


def analyze_dump(blob: bytes, base_sector: int):
    print(f"[*] analyze {len(blob)} B from sector {base_sector}:")
    magic_hits = []
    nonzero = []
    for i in range(0, len(blob), 0x100):
        sec = blob[i:i + 0x100]
        if sec != b"\x00" * 0x100:
            nonzero.append(base_sector + i // 0x100)
        if sec[:8] == b"4400RPMB":
            magic_hits.append(base_sector + i // 0x100)
        if b"RPMB" in sec:
            print(f"    sector {base_sector + i // 0x100}: contains 'RPMB' ascii "
                  f"@{sec.find(b'RPMB'):#x}")
    if nonzero:
        print(f"[+] NONZERO sectors: {[hex(s) for s in nonzero]}")
        for s in nonzero[:8]:
            off = (s - base_sector) * 0x100
            print(f"    sector {s}[:32]: {blob[off:off + 32].hex()}")
    else:
        print(f"[-] no nonzero sectors in [{base_sector}..{base_sector + len(blob) // 0x100})")
    if magic_hits:
        print(f"[+] '4400RPMB' superblock magic at sector(s): {magic_hits} "
              f"=> t-base SFSRP start block S = {magic_hits[0]}")
        k = magic_hits[0]
        off = (k - base_sector) * 0x100
        sb = blob[off:off + 0x20]
        ver, flags = struct.unpack("<II", sb[8:16])
        size = struct.unpack("<Q", sb[16:24])[0]
        print(f"    superblock: version={ver} flags={flags:#x} size={size:#x} "
              f"(expect version 1|2, flags 0, size 0x100)")
    else:
        print("[-] no '4400RPMB' magic found in scanned range")
    return magic_hits, nonzero


def rpmb_key_status(xmlft):
    """CMD:EMMC-CONTROL GET-RPMB-KEY-STATUS — check_lifecycle pattern
    (xml_lib.py:1619-1634). Reply field per re-da2-rpmb-key.md §4:
    RPMB-KEY-STATUS = EXIST | NOT-EXIST."""
    print("[*] EMMC-CONTROL GET-RPMB-KEY-STATUS ...")
    from mtkclient.Library.DA.xmlflash.xml_lib import UpFile
    try:
        xmlft.xflash.send_command(
            xmlft.xflash.cmd.cmd_emmc_control(function="GET-RPMB-KEY-STATUS"), noack=True)
        cmd, result = xmlft.xflash.get_command_result()
        if result is None or isinstance(result, str):
            print(f"[-] no UpFile reply: cmd={cmd!r} result={str(result)[:200]!r}")
            if cmd == 'CMD:END':
                xmlft.xflash.ack()
                scmd, sresult = xmlft.xflash.get_command_result()
                print(f"[*] post-END: {scmd!r} {str(sresult)[:200]!r}")
            return None
        data = xmlft.xflash.download(result)
        scmd, sresult = xmlft.xflash.get_command_result()
        xmlft.xflash.ack()
        if sresult == "OK":
            tcmd, tresult = xmlft.xflash.get_command_result()
            print(f"[*] key-status tail: {tcmd!r} {tresult!r}")
        text = bytes(data).decode('utf-8', errors='replace') if data else ""
        print(f"[*] key-status raw data ({len(data) if data else 0} B): {text[:200]!r}")
        for field in ("RPMB-KEY-STATUS", "RPMB-STATUS"):
            i = text.find(f"<{field}>")
            if i != -1:
                j = text.find(f"</{field}>", i)
                print(f"[+] {field} = {text[i + len(field) + 2:j]}")
        # NOTE: "NOT-EXIST" contains the substring "EXIST" — check the
        # negative form first (the old order mis-reported NOT-EXIST as EXIST).
        if "NOT-EXIST" in text:
            print("[+] verdict: RPMB key NOT-EXIST (not programmed, per DA)")
        elif "EXIST" in text:
            print("[+] verdict: RPMB key EXIST (programmed, per DA)")
        else:
            print(f"[!] verdict: unparsed ({text!r})")
        return text
    except Exception as e:
        print(f"[-] key-status parse error: {e!r}")
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
    mtk_main = Main(args)
    mtk = mtk_main.run(parser)
    if mtk is None:
        print("[-] connect failed")
        return 1
    loader = mtk.daloader
    xmlft = loader.xmlft

    # --- 1. live seccfg (FIXED parse) ---
    data, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = gpt.sectorsize
    seccfg = next((p for p in gpt.partentries if p.name.lower() == "seccfg"), None)
    if seccfg is None:
        print("[-] no seccfg in GPT")
        return 1
    blob = loader.readflash(addr=seccfg.sector * ss, length=0x1000,
                            filename="", parttype="user", display=False)
    blob = blob[0] if isinstance(blob, tuple) else blob
    if blob and blob[:4] == b"MMMM":
        magic, ver, size, lock, dmv, sboot, endf = struct.unpack("<IIIIIII", blob[:28])
        ok_end = endf == 0x45454545
        print(f"[*] LIVE seccfg (fixed): magic={magic:#x} ver={ver} size={size:#x} "
              f"lock_state={lock} dm_verity={dmv:#x} sboot={sboot:#x} "
              f"end=0x{endf:08x} ({'OK' if ok_end else 'BAD'})")
        # cross-check against the offline backup
        try:
            bak = open("/home/musin/seccfg_backup.bin", "rb").read()
            print(f"[*] backup head match live: {bak[:28] == blob[:28]}")
        except OSError:
            pass
    else:
        print(f"[!] seccfg head: {(blob[:16] if blob else None)!r}")

    # --- 2. derive via DA (CUSTOMRPMBI mode=0) ---
    print("[*] custom_rpmb_init(None) — DA HACC-derives the RPMB key ...")
    ok = xmlft.custom_rpmb_init()
    print(f"[*] rpmb_init -> {ok}")
    if not ok:
        print("[-] derive failed, aborting (session still usable for status?)")

    # key-stage dump (informational; wipe memset may have run already)
    raw = xmlft.custom_read(KEY_STAGE, 0x40)
    if raw:
        print(f"[*] KEY STAGE @0x{KEY_STAGE:x}: {bytes(raw).hex()}")

    # capture the derived key D from the last CUSTOMRPMBI blob:
    # custom_rpmb_init() prints it but does not return it — re-derive raw to grab it.
    D = rpmbi_derive(xmlft)
    if D is None:
        print("[-] could not obtain derived key raw — aborting RPMB experiments")
        return 1
    with open("/home/musin/rpmb_key_derived.bin", "wb") as f:
        f.write(D)
    print(f"[+] derived key D saved: {D.hex()}")

    # --- 3a. baseline: CUSTOMRPMBK(D) -> read 0..15 ---
    print("[*] EXP1: CUSTOMRPMBK(D) + read sectors 0..15")
    if not rpmbk_set_key(xmlft, D):
        print("[-] cannot set key D — abort")
        return 1
    exp1, _ = read_rpmb_range(xmlft, 0, 16, "EXP1")
    if exp1:
        with open("/home/musin/rpmb_exp1_derivedkey.bin", "wb") as f:
            f.write(exp1)
        print(f"[+] EXP1 read OK: {len(exp1)} B")
        analyze_dump(exp1, 0)
    else:
        print("[-] EXP1 read FAILED with derived key D — D is likely NOT the device key")

    # --- 3b. wrong-key control: CUSTOMRPMBK(W) -> read 0..3 ---
    print("[*] EXP2: CUSTOMRPMBK(WRONG) + read sectors 0..3 (control experiment)")
    if rpmbk_set_key(xmlft, WRONG_KEY):
        exp2, _ = read_rpmb_range(xmlft, 0, 4, "EXP2")
        if exp2:
            print(f"[!] EXP2 read SUCCEEDED ({len(exp2)} B) with a WRONG key -> "
                  f"reads are NOT device-key-gated (or stub skips MAC check). "
                  f"The all-zero result is therefore real DATA, not a key artifact.")
            nonzero2 = [i for i in range(0, len(exp2), 0x100)
                        if exp2[i:i + 0x100] != b"\x00" * 0x100]
            print(f"[*] EXP2 nonzero sectors: {nonzero2 if nonzero2 else 'none (all zero)'}")
        else:
            print("[+] EXP2 read FAILED (see v6 error line above) -> reads ARE "
                  "device-key-gated => EXP1 success with D PROVES D == the device "
                  "RPMB auth key (factory key).")
    else:
        print("[!] EXP2 key-set failed — skipping control")

    # --- 3c. CUSTOMRPMBI semantics: does it override the working key? ---
    print("[*] EXP3: CUSTOMRPMBI(mode=0) right after CUSTOMRPMBK(WRONG)")
    K2 = rpmbi_derive(xmlft)
    if K2 is not None:
        same = (K2 == D)
        print(f"[*] EXP3: CUSTOMRPMBI returned {'D again (independent derivation)' if same else 'a DIFFERENT key'}")
        # which key is in effect now? read 0..1 and compare against a known reference
        probe, _ = read_rpmb_range(xmlft, 0, 1, "EXP3-probe")
        print(f"[*] EXP3 probe read -> {'OK ' + probe[:16].hex() if probe else 'FAILED'}")
    else:
        print("[!] EXP3: CUSTOMRPMBI failed")

    # --- 3d. restore D ---
    rpmbk_set_key(xmlft, D)

    # --- 4. extended scan 0..0x7F ---
    print(f"[*] SCAN: reading RPMB sectors 0..{SCAN_SECTORS - 1} ({SCAN_SECTORS * 0x100} B)")
    scan, reached = read_rpmb_range(xmlft, 0, SCAN_SECTORS, "SCAN")
    if scan:
        with open("/home/musin/rpmb_scan.bin", "wb") as f:
            f.write(scan)
        print(f"[+] SCAN OK: {len(scan)} B (sectors 0..{reached - 1})")
        magic_hits, nonzero = analyze_dump(scan, 0)
        # boot-info mirror check if sectors 0..3 are non-zero
        if len(scan) >= 0x400 and scan[:0x3E0] != b"\x00" * 0x3E0:
            sbyte = struct.unpack("<I", scan[0xC:0x10])[0]
            calc = __import__('hashlib').sha256(scan[:0x3E0]).digest()
            stored = scan[0x3E0:0x400]
            print(f"[*] mirror@0: locked_bit(+0xC)={sbyte} "
                  f"hash_ok={calc == stored} last_bootmode={struct.unpack('<I', scan[8:12])[0]}")
    else:
        print(f"[-] SCAN failed at sector {reached} — region extent unknown")

    # --- 5. GET-RPMB-KEY-STATUS ---
    rpmb_key_status(xmlft)

    # --- region info ---
    try:
        st = xmlft.xflash.daconfig.storage
        print(f"[*] storage: emmc.rpmb_size={getattr(st.emmc, 'rpmb_size', None):#x} "
              f"ufs.lu1_size={getattr(st.ufs, 'lu1_size', None):#x}")
    except Exception as e:
        print(f"[*] storage info unavailable: {e!r}")

    print("[*] recon2 done")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
