#!/usr/bin/env python3
"""READ-ONLY slot diagnostic: dump boot_a / boot_b / misc and classify them.

Answers the question "is the device really booting the slot we patch?"
without touching the phone's flash (readflash only).

For every boot slot it reports:
  * md5 + sha256 and the known-image match (stock / v4 / v5 / v7),
  * kernel_size, ramdisk_size, rd_off, vbmeta offset,
  * cpio markers: /force_debuggable, /adb_debug.prop,
    debug_ramdisk/adb_debug.prop (v7 marker), and the /init P1 bytes.

misc is decoded as the A/B bootloader_control block at 0x800.
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

OUT = "/home/musin"
PAGE = 0x1000
KNOWN = {
    "356320597c88669f032e9736e5f906ce": "stock",
    "10f3576a": "old-stock(docs/rmx3630-lk/boot.img)",
    "76e089fa4aadc1bc17f931a50ccf33d4": "v4",
    "f0c1674243f465d9bb363a45642d2117": "v5",
    "5dbb19b2265a030557b78969368026cd": "v7",
}
P1_OFF = 0xF6D14
P1_PATCHED = b"\x24\x00\x00\x14"
P1_STOCK = b"\x93\x04\x00\x36"


def md5(b):
    return hashlib.md5(b).hexdigest()


def align_up(x, a=PAGE):
    return (x + a - 1) // a * a


def classify_boot(blob, label):
    print("  %s: size %d md5 %s sha256 %s"
          % (label, len(blob), md5(blob), hashlib.sha256(blob).hexdigest()))
    print("      known: %s" % KNOWN.get(md5(blob), "-"))
    if blob[:8] != b"ANDROID!":
        print("      not an Android boot image")
        return
    ks, rs = struct.unpack_from("<II", blob, 8)
    hv = struct.unpack_from("<I", blob, 0x28)[0]
    rd_off = align_up(PAGE + ks, PAGE)
    print("      hdr v%d kernel 0x%X ramdisk %d @0x%X"
          % (hv, ks, rs, rd_off))
    vb = None
    for off in range(align_up(rd_off + rs, PAGE), len(blob) - 4, PAGE):
        if blob[off:off + 4] == b"AVB0":
            vb = off
            break
    if vb is None:
        vb = blob.find(b"AVB0", rd_off)
        print("      vbmeta: scan fallback 0x%X" % vb if vb > 0 else "      vbmeta: none")
    else:
        print("      vbmeta: 0x%X (slot 0x%X)" % (vb, vb - rd_off))
    blob_rd = blob[rd_off:rd_off + rs]
    codec = "gzip" if blob_rd[:2] == b"\x1f\x8b" else (
        "lz4-legacy" if blob_rd[:4] == b"\x02\x21\x4c\x18" else blob_rd[:4].hex())
    print("      codec: %s" % codec)
    if codec != "gzip":
        return
    try:
        import gzip
        raw = gzip.decompress(blob_rd)
    except Exception as e:
        print("      gunzip failed: %r" % e)
        return
    # exact cpio entry names (a byte-count search is useless: /init itself
    # embeds the literal "/debug_ramdisk/adb_debug.prop")
    ents, i = [], 0
    while i + 110 <= len(raw):
        if raw[i:i + 6] != b"070701":
            break
        f = [int(raw[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        name = raw[i + 110:i + 110 + f[11] - 1].decode("utf-8", "replace")
        doff = align_up(i + 110 + f[11], 4)
        ents.append((name, doff, f[6]))
        i = align_up(doff + f[6], 4)
        if name == "TRAILER!!!":
            break
    names = [e[0] for e in ents]
    marks = {n: names.count(n) for n in
             ("force_debuggable", "adb_debug.prop", "debug_ramdisk",
              "debug_ramdisk/adb_debug.prop", "init")}
    print("      cpio %d B, %d entries: force_debuggable=%d adb_debug.prop=%d "
          "debug_ramdisk=%d rootfs_copy=%d"
          % (len(raw), len(names), marks["force_debuggable"],
             marks["adb_debug.prop"], marks["debug_ramdisk"],
             marks["debug_ramdisk/adb_debug.prop"]))
    p1 = None
    for name, doff, size in ents:
        if name == "init" and size > P1_OFF + 4:
            p1 = raw[doff + P1_OFF:doff + P1_OFF + 4]
    if p1 is not None:
        tag = {P1_STOCK: "stock", P1_PATCHED: "patched(v5+)"}.get(p1, "unknown")
        print("      /init@0x%X = %s (%s)" % (P1_OFF, p1.hex(), tag))
    verdict = ("v7" if marks["debug_ramdisk/adb_debug.prop"]
               else ("v5" if marks["force_debuggable"] else "stock-like"))
    print("      VERDICT: %s" % verdict)


def classify_misc(blob):
    print("  misc: size %d md5 %s" % (len(blob), md5(blob)))
    print("      BCB[0:64] = %r" % blob[:16])
    base = 0x800
    if blob[base + 4:base + 8] == b"BCAB":
        sfx = blob[base:base + 4]
        ver = blob[base + 8]
        bits = blob[base + 9]
        si = list(blob[base + 10:base + 14])
        print("      bootloader_control: suffix=%r ver=%d nb_slot=%d try_left=%d"
              % (sfx, ver, bits & 7, bits >> 3))
        for n, s in enumerate(si[:bits & 7]):
            print("         slot %s: priority=%d tries_left=%d successful=%d"
                  % ("abcd"[n], (s >> 4) & 0xF, (s >> 1) & 7, s & 1))
    else:
        print("      no BCAB at 0x800 (offset 0x800 = %s)" % blob[base:base + 16].hex())


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
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize
    ents = {p.name.lower(): p for p in gpt.partentries}

    print("== GPT (boot / misc / expdb) ==")
    for name in ("boot_a", "boot_b", "misc", "expdb", "vendor_boot_a"):
        p = ents.get(name)
        if p is None:
            print("  %-14s ABSENT" % name)
        else:
            print("  %-14s LBA 0x%-8X size 0x%X"
                  % (name, p.sector, p.sectors * ss))

    def read_part(name):
        p = ents.get(name)
        if p is None:
            return None
        size = p.sectors * ss
        addr = p.sector * ss
        d = loader.readflash(addr=addr, length=size, filename="",
                             parttype="user", display=False)
        d = d[0] if isinstance(d, tuple) else d
        if not d or isinstance(d, bool):
            print("  [-] %s: read failed" % name)
            return None
        d = bytes(d[:size])
        path = os.path.join(OUT, "slot_%s.img" % name)
        with open(path, "wb") as fh:
            fh.write(d)
        return d

    print("\n== boot slots ==")
    for name in ("boot_a", "boot_b"):
        d = read_part(name)
        print("  -- %s -> %s/slot_%s.img" % (name, OUT, name))
        if d is not None:
            classify_boot(d, name)

    print("\n== misc ==")
    d = read_part("misc")
    if d is not None:
        classify_misc(d)

    print("\n== vendor_boot_a ==")
    d = read_part("vendor_boot_a")
    if d is not None:
        print("  size %d md5 %s hdr %r" % (len(d), md5(d), d[:8]))
        print("  /init in cpio: %d" % d.count(b"init\x00"))
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
