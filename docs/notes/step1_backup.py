#!/usr/bin/env python3
"""Session backup step: connect, GET-HW-INFO (battery!), full seccfg backup,
plus critical-partition backups. Verify offline.

Hosts:
  PC:   ./run_backup.sh   (MTK_DIR defaults to this repo; outputs to /home/musin)
  Termux: MTK_DIR=/root/mtkclient STEP1_OUT=/root python3 step1_backup.py

Sequence:
 1) standard mtk connect (VCOM -> DA_BR -> heapbait -> OPLUS runtime patches)
 2) print GET-HW-INFO fields (battery voltage, ufs info) if available
 3) read seccfg (full) -> OUT_DIR/seccfg_backup_<ts>.bin -> offline verify
 4) read critical partitions (nvdata/nvcf, persist, proinfo, frp, misc,
    oplusstanvbk, param, metadata) -> OUT_DIR/rmx3630_backup_<ts>/
 5) md5 manifest written next to the files.
"""
import sys
import os
import hashlib
import time

MTK_DIR = os.environ.get(
    "MTK_DIR",
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
OUT_DIR = os.environ.get("STEP1_OUT", MTK_DIR)
sys.path.insert(0, MTK_DIR)
os.chdir(MTK_DIR)

# Small, safety-critical partitions first; skip huge ones (userdata etc).
CRITICAL_PARTS = [
    "seccfg", "nvdata", "nvcf", "persist", "proinfo", "frp", "misc",
    "oplusstanvbk", "para", "param", "metadata", "protect1", "protect2",
    "oplusreserve", "reserve1", "reserve2",
]


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    import argparse
    sys.path.insert(0, os.getcwd())  # repo root (script lives in docs/notes)
    import mtk as mtk_cli
    parser = mtk_cli.create_base_parser()
    parser = argparse.ArgumentParser(parents=[parser],
                                     description=mtk_cli.INFO)
    sub = parser.add_subparsers(dest='cmd', required=False)
    sub.add_parser('custom')  # placeholder: we drive the DA API directly
    args = parser.parse_args(sys.argv[1:] + ['custom'])
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

    # 3) GPT
    data, gpt = loader.get_gpt(parttype="user")
    if not gpt:
        print("[-] GPT read failed")
        return 1
    ss = getattr(gpt, "sectorsize", 4096) or 4096

    # Save GPT itself
    ts = time.strftime("%Y%m%d_%H%M%S")
    bdir = os.path.join(OUT_DIR, f"rmx3630_backup_{ts}")
    os.makedirs(bdir, exist_ok=True)
    with open(os.path.join(bdir, "gpt.bin"), "wb") as f:
        f.write(data if isinstance(data, bytes) else bytes(data))
    print(f"[+] GPT saved to {bdir}/gpt.bin")

    manifest = []

    def backup_part(name):
        part = None
        for p in gpt.partentries:
            if p.name.lower() == name:
                part = p
                break
        if part is None:
            print(f"[i] '{name}': not in GPT — skipped")
            return
        size = part.sectors * ss
        addr = part.sector * ss
        out = os.path.join(bdir, f"{name}.img")
        print(f"[*] {name}: LBA {part.sector:#x}..{part.sector + part.sectors:#x} "
              f"size {size:#x} ...", flush=True)
        try:
            ok = loader.readflash(addr=addr, length=size, filename=out,
                                  parttype="user", display=True)
        except Exception as e:
            print(f"[-] {name} read failed: {e!r}")
            return
        res = ok[0] if isinstance(ok, tuple) else ok
        if not res or not os.path.exists(out) or os.path.getsize(out) == 0:
            print(f"[-] {name}: readflash failed — removing partial file")
            try:
                os.remove(out)
            except OSError:
                pass
            return
        m5 = md5_of(out)
        manifest.append(f"{m5}  {name}.img  ({size} bytes)")
        print(f"[+] {name}: {size} bytes md5 {m5}")

    for name in CRITICAL_PARTS:
        backup_part(name)

    with open(os.path.join(bdir, "MANIFEST.md5"), "w") as f:
        f.write("\n".join(manifest) + "\n")
    print(f"[+] manifest: {bdir}/MANIFEST.md5")
    print("[+] BACKUP DONE — copy this directory off-PC before any write "
          "operation")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
