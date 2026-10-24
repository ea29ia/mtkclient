#!/usr/bin/env python3
"""Read a file out of a dynamic partition (`super`) via DA — no full dump.

Pipeline:
  super (GPT partition) -> LP metadata (geometry + slot 0) -> partition table ->
  extent list for e.g. "system" -> ext4 on top of that extent -> path lookup ->
  file bytes.

Usage (device in preloader):
  ./run_super_extract.sh                     # default: system:/bin/init
  python docs/notes/super_extract.py --part system --path /bin/init --out /home/musin/system_bin_init
  python docs/notes/super_extract.py --part system --path /build.prop --out /home/musin/system_build.prop
  python docs/notes/super_extract.py --part system --path /etc/selinux --list

Read-only: never writes to the device.
"""
import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
os.chdir(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

LP_GEOM_MAGIC = 0x616C4467
LP_HDR_MAGIC = 0x414C5030
EXT4_MAGIC = 0xEF53


class Reader:
    """Cached 1 MB reads from the device by absolute byte address."""

    def __init__(self, loader, base):
        self.loader = loader
        self.base = base
        self.cache = {}

    def read(self, off, length):
        out = bytearray()
        pos = off
        need = length
        while need > 0:
            blk = pos // 0x100000
            if blk not in self.cache:
                d = self.loader.readflash(addr=self.base + blk * 0x100000,
                                          length=0x100000, filename="",
                                          parttype="user", display=False)
                d = d[0] if isinstance(d, tuple) else d
                self.cache[blk] = bytes(d) if d and not isinstance(d, bool) else b""
            buf = self.cache[blk]
            if not buf:
                raise IOError(f"read failed at {self.base + pos:#x}")
            inner = pos - blk * 0x100000
            take = min(need, len(buf) - inner)
            if take <= 0:
                raise IOError("short read")
            out += buf[inner:inner + take]
            pos += take
            need -= take
        return bytes(out)


def _scan_magic(rd, start, end, magic, step=0x1000):
    off = start
    while off < end:
        blk = rd.read(off, 0x1000)
        if len(blk) < 0x1000:
            return None
        if struct.unpack_from("<I", blk, 0)[0] == magic:
            return off
        off += step
    return None


def parse_lp(rd: Reader):
    """This device's LP container starts at 0x1000 inside `super`
    (geometry @0x1000, metadata header @0x3000), so locate the magics instead
    of assuming offset 0."""
    geo_off = _scan_magic(rd, 0, 0x20000, LP_GEOM_MAGIC)
    if geo_off is None:
        raise ValueError("LP geometry magic not found in the first 128 KB")
    geo = rd.read(geo_off, 52)
    magic, size = struct.unpack_from("<II", geo, 0)
    meta_max, slot_count, lb = struct.unpack_from("<III", geo, 40)
    print(f"[*] LP geometry @{geo_off:#x}: max={meta_max:#x} slots={slot_count} "
          f"block={lb}")

    def try_parse(hdr):
        if len(hdr) < 0x60 or struct.unpack_from("<I", hdr, 0)[0] != LP_HDR_MAGIC:
            return None
        for cand in (24, 20, 28, 32):
            try:
                po, pn, pe = struct.unpack_from("<III", hdr, cand)
                eo, en, ee = struct.unpack_from("<III", hdr, cand + 12)
            except struct.error:
                continue
            if pe == 52 and ee == 24 and 0 < pn < 200 and 0 < en < 100000 \
                    and po + pn * 52 <= len(hdr) and eo + en * 24 <= len(hdr):
                return (cand, po, pn, eo, en)
        return None

    hits = []
    off = geo_off
    while off < geo_off + 0x100000:
        blk = rd.read(off, 0x1000)
        if len(blk) < 0x1000:
            break
        if struct.unpack_from("<I", blk, 0)[0] == LP_HDR_MAGIC:
            hits.append(off)
        off += 0x1000
    print(f"[*] LP header candidates: {[hex(x) for x in hits]}")

    chosen = None
    for hoff in hits:
        hdr = rd.read(hoff, min(meta_max, 0x20000))
        r = try_parse(hdr)
        print(f"    @{hoff:#x}: v{struct.unpack_from('<HH', hdr, 4)} "
              f"hdr_size={struct.unpack_from('<I', hdr, 8)[0]} -> {r}")
        if r and chosen is None:
            chosen = (hoff, hdr, r)
    if chosen is None:
        raise ValueError("no parseable LP metadata header found")
    hdr_off, hdr, (base_off, parts_off, parts_num, ext_off, ext_num) = chosen
    print(f"[*] using header @{hdr_off:#x}: parts(off={parts_off} n={parts_num}) "
          f"extents(off={ext_off} n={ext_num})")

    parts = []
    for i in range(parts_num):
        e = hdr[parts_off + i * 52: parts_off + (i + 1) * 52]
        if len(e) < 52:
            break
        name = e[:36].split(b"\x00")[0].decode()
        attr, first_ext, num_ext, grp = struct.unpack_from("<IIII", e, 36)
        parts.append(dict(name=name, first_ext=first_ext, num_ext=num_ext))
    exts = []
    for i in range(ext_num):
        e = hdr[ext_off + i * 24: ext_off + (i + 1) * 24]
        if len(e) < 24:
            break
        num_sectors, ttype, tdata, tsrc = struct.unpack("<QIQI", e)
        exts.append(dict(num_sectors=num_sectors, type=ttype, data=tdata))
    print("[*] partitions:", ", ".join(p["name"] for p in parts))
    return parts, exts


def part_map(parts, exts, name):
    p = next((x for x in parts if x["name"] == name), None)
    if p is None:
        return None
    segs = []
    for i in range(p["num_ext"]):
        e = exts[p["first_ext"] + i]
        if e["type"] != 0:
            raise ValueError("non-linear extent not supported")
        segs.append((e["data"] * 512, e["num_sectors"] * 512))
    return segs


class Ext4:
    def __init__(self, rd, off, size):
        self.rd = rd
        self.off = off
        self.size = size
        sb = rd.read(off + 1024, 1024)
        if struct.unpack_from("<H", sb, 0x38)[0] != EXT4_MAGIC:
            raise ValueError("not ext4")
        self.inodes_count, = struct.unpack_from("<I", sb, 0)
        self.blocks_count_lo, = struct.unpack_from("<I", sb, 4)
        self.first_data_block, = struct.unpack_from("<I", sb, 0x14)
        self.log_block, = struct.unpack_from("<I", sb, 0x18)
        self.blocks_per_group, = struct.unpack_from("<I", sb, 0x20)
        self.inodes_per_group, = struct.unpack_from("<I", sb, 0x28)
        self.inode_size, = struct.unpack_from("<H", sb, 0x58)
        self.feature_incompat, = struct.unpack_from("<I", sb, 0x60)
        self.desc_size = 32
        if self.feature_incompat & 0x80:      # 64BIT
            self.desc_size = struct.unpack_from("<H", sb, 0xFE)[0] or 64
        self.bs = 1024 << self.log_block
        self.gd_off = (self.first_data_block + 1) * self.bs
        print(f"[*] ext4: bs={self.bs} inode_size={self.inode_size} "
              f"inodes={self.inodes_count} ipg={self.inodes_per_group} "
              f"desc={self.desc_size} incompat={self.feature_incompat:#x}")

    def _blk(self, n, count=1):
        return self.rd.read(self.off + n * self.bs, count * self.bs)

    def inode(self, ino):
        grp = (ino - 1) // self.inodes_per_group
        idx = (ino - 1) % self.inodes_per_group
        gd = self.rd.read(self.off + self.gd_off + grp * self.desc_size, self.desc_size)
        itab_lo, = struct.unpack_from("<I", gd, 8)
        itab_hi, = struct.unpack_from("<I", gd, 0x28) if self.desc_size >= 64 else (0,)
        itab = itab_lo | (itab_hi << 32)
        raw = self.rd.read(self.off + itab * self.bs + idx * self.inode_size, self.inode_size)
        mode, = struct.unpack_from("<H", raw, 0)
        size_lo, = struct.unpack_from("<I", raw, 4)
        size_hi, = struct.unpack_from("<I", raw, 0x6C)
        flags, = struct.unpack_from("<I", raw, 0x20)
        blocks = raw[0x28:0x28 + 60]
        return dict(mode=mode, size=size_lo | (size_hi << 32), flags=flags, blocks=blocks)

    def _extents(self, node, depth):
        magic, entries, emax, edepth = struct.unpack_from("<HHHH", node, 0)
        if magic != 0xF30A:
            return []
        out = []
        for i in range(entries):
            e = node[12 + i * 12: 24 + i * 12]
            ee_block, ee_len, ee_hi, ee_lo = struct.unpack("<IHHI", e)
            if edepth == 0:
                out.append((ee_block, ee_len & 0x7FFF, (ee_hi << 32) | ee_lo))
            else:
                child = self._blk((ee_hi << 32) | ee_lo)
                out += self._extents(child, edepth - 1)
        return out

    def read_file(self, ino):
        ino_d = self.inode(ino)
        if not (ino_d["mode"] & 0xF000) == 0x8000:
            return b""
        size = ino_d["size"]
        if ino_d["flags"] & 0x80000:          # EXTENTS_FL
            exts = self._extents(ino_d["blocks"], 0)
            data = bytearray()
            for (lb, ln, pb) in exts:
                data += self._blk(pb, ln)
            return bytes(data[:size])
        # direct blocks fallback
        data = bytearray()
        for i in range(12):
            pb, = struct.unpack_from("<I", ino_d["blocks"], i * 4)
            if pb:
                data += self._blk(pb)
        return bytes(data[:size])

    def listdir(self, ino):
        d = self.read_file(ino)
        out = []
        pos = 0
        while pos + 8 <= len(d):
            i, rec_len, name_len, ftype = struct.unpack_from("<IHBB", d, pos)
            if rec_len < 8:
                break
            name = d[pos + 8:pos + 8 + name_len].decode("utf-8", "replace")
            if name not in (".", ".."):
                out.append((name, i, ftype))
            pos += rec_len
        return out

    def lookup(self, path):
        ino = 2
        for part in [p for p in path.split("/") if p]:
            found = None
            for name, i, ftype in self.listdir(ino):
                if name == part:
                    found = i
                    break
            if found is None:
                raise FileNotFoundError(f"{part} in {path}")
            ino = found
        return ino


def main():
    import mtk as mtk_cli
    parser = mtk_cli.create_base_parser()
    parser = argparse.ArgumentParser(parents=[parser], description=mtk_cli.INFO)
    parser.add_argument('--super', default='super')
    parser.add_argument('--part', default='system')
    parser.add_argument('--path', default='/bin/init')
    parser.add_argument('--out', default='')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--scan', action='store_true')
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
    sp = next((x for x in gpt.partentries if x.name.lower() == args.super), None)
    if sp is None:
        print(f"[-] no {args.super}")
        return 1
    sbase = sp.sector * ss
    print(f"[*] super: LBA {sp.sector:#x} base {sbase:#x} size {sp.sectors * ss:#x}")

    rd = Reader(loader, sbase)
    if args.scan:
        head = rd.read(0, 0x1000)
        print("[*] first 0x100 bytes:", head[:0x100].hex())
        print("[*] ascii:", ''.join(chr(c) if 32 <= c < 127 else '.' for c in head[:128]))
        hits = {"LP_GEOM": [], "LP_HDR": [], "EXT4": []}
        off = 0
        while off < 0x4000000 and (len(hits["LP_GEOM"]) < 3 or len(hits["LP_HDR"]) < 3):
            blk = rd.read(off, 0x1000)
            if len(blk) < 0x1000:
                break
            if struct.unpack_from("<I", blk, 0)[0] == LP_GEOM_MAGIC:
                hits["LP_GEOM"].append(off)
            if struct.unpack_from("<I", blk, 0)[0] == LP_HDR_MAGIC:
                hits["LP_HDR"].append(off)
            if struct.unpack_from("<H", blk, 0x400 + 0x38)[0] == EXT4_MAGIC:
                hits["EXT4"].append(off)
            off += 0x1000
        for k, v in hits.items():
            print(f"[*] scan {k}: {[hex(x) for x in v[:5]]}")
        return 0
    parts, exts = parse_lp(rd)
    segs = part_map(parts, exts, args.part)
    if not segs:
        print(f"[-] partition {args.part} not in LP table: "
              f"{[p['name'] for p in parts]}")
        return 1
    print(f"[*] {args.part}: {len(segs)} extent(s), first @ {segs[0][0]:#x} "
          f"({sum(s[1] for s in segs) / 1e9:.2f} GB)")
    fs = Ext4(rd, segs[0][0], segs[0][1])

    if args.list:
        ino = fs.lookup(args.path)
        print(f"[*] {args.path} (inode {ino}, size {fs.inode(ino)['size']})")
        for name, i, ftype in fs.listdir(ino)[:100]:
            print(f"    {ftype} {i:8d} {name}")
        return 0

    ino = fs.lookup(args.path)
    data = fs.read_file(ino)
    print(f"[+] {args.part}:{args.path} inode={ino} size={len(data):#x}")
    if args.out:
        open(args.out, 'wb').write(data)
        print(f"[+] saved -> {args.out}")
    else:
        print(data[:512])
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
