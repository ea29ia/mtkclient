#!/usr/bin/env python3
"""Session step 1: connect, GET-HW-INFO (battery!), backup seccfg, verify.

Run from proot via rootbridge (real root, Termux-native python):
  python3 /data/data/com.termux/files/home/step1_backup.py

Sequence:
 1) standard mtk connect (VCOM -> DA_BR -> heapbait -> OPLUS patches)
 2) print GET-HW-INFO fields (battery voltage, ufs info) if available
 3) read seccfg (full 8MB) -> save /root/seccfg_backup_<ts>.bin
 4) offline-verify structure (MMMM magic, records)
 5) md5 + keep device connected for next steps? No — end session cleanly.
"""
import sys, os, hashlib, time

MTK_DIR = os.environ.get(
    "MTK_DIR",
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
OUT_DIR = os.environ.get("STEP1_OUT", MTK_DIR)
sys.path.insert(0, MTK_DIR)
os.chdir(MTK_DIR)


def main():
    import argparse
    sys.path.insert(0, os.getcwd())  # repo root (script lives in docs/notes)
    import mtk as mtk_cli
    parser = mtk_cli.create_base_parser()
    parser = argparse.ArgumentParser(parents=[parser],
                                     description=mtk_cli.INFO)
    args = parser.parse_args(sys.argv[1:])
    from mtkclient.Library.mtk_main import Main
    mtk_main = Main(args)
    mtk = mtk_main.run(parser)
    if mtk is None:
        print("[-] connect failed")
        return 1
    loader = mtk.daloader

    # 2) hardware info (battery is in GET-HW-INFO on this DA2: handler 0x400064bc
    #    reads battery via 0x4002a90c). mtkclient stores hw info in config.
    try:
        hw = mtk.config.hwparam if hasattr(mtk.config, "hwparam") else None
        print("[HW]", hw if hw else "(hwparam not exposed)")
    except Exception as e:
        print("[HW] err:", e)

    # Also try the xml get_hw_info if present
    try:
        xmlft = getattr(loader, "xmlft", None)
        if xmlft is None:
            xmlft = loader.xflash
        info = xmlft.get_hw_info() if hasattr(xmlft, "get_hw_info") else None
        print("[HWINFO]", info)
    except Exception as e:
        print("[HWINFO] err:", repr(e))

    # 3) seccfg backup via partition read
    data, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = getattr(gpt, "sectorsize", 4096) or 4096
    target = None
    for part in gpt.partentries:
        if part.name.lower() == "seccfg":
            target = part
            break
    if target is None:
        print("[-] seccfg partition not found in GPT")
        return 1
    size = target.sectors * ss
    addr = target.sector * ss
    print(f"[+] seccfg LBA {target.sector:#x}..{target.sector+target.sectors:#x} size {size:#x} @ {addr:#x}")

    ts = time.strftime("%Y%m%d_%H%M%S")
    out = os.path.join(OUT_DIR, f"seccfg_backup_{ts}.bin")
    ok = loader.xflash.readflash(
        addr=addr, length=size, filename=out, parttype="user", display=True)
    if not ok:
        print("[-] readflash failed")
        return 1
    blob = open(out, "rb").read()
    md5 = hashlib.md5(blob).hexdigest()
    print(f"[+] saved {out} ({len(blob)} bytes, md5 {md5})")
    print(f"[*] magic: {blob[:4]!r} (expect MMMM)")
    if blob[:4] == b"MMMM":
        import struct
        ver, rec_size, dmv, sboot, lock = struct.unpack_from("<IIIII", blob, 4)
        print(f"[*] ver={ver} rec_size={rec_size:#x} dm_verity={dmv} sboot={sboot} lock_state={lock}")
    nz = sum(1 for b in blob[:0x1000] if b)
    print(f"[*] first 4KB non-zero bytes: {nz}")
    print("[+] BACKUP OK — copy this file off-device before any write operation")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
