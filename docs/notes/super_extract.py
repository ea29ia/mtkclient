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


def parse_lp(rd: Reader):
    geo = rd.read(0, 52)
    magic, size = struct.unpack_from("<II", geo, 0)
    if magic != LP_GEOM_MAGIC:
        raise ValueError(f"bad LP geometry magic {magic:#x}")
    meta_max, slot_count, lb = struct.unpack_from("<III", geo, 40)
    print(f"[*] LP geometry: max={meta_max:#x} slots={slot_count} block={lb}")
    hdr = rd.read(4096, meta_max)
    m, major, minor, hsize = struct.unpack_from("<IHHI", hdr, 0)
    if m != LP_HDR_MAGIC:
        raise ValueError(f"bad LP header magic {m:#x}")
    tables_size = struct.unpack_from("<I", hdr, 16)[0]
    parts_off, parts_num, ext_off, ext_num, grp_off, grp_num, bdev_off, bdev_num = \
        struct.unpack_from("<8I", hdr, 24)
    print(f"[*] LP header v{major}.{minor} hdr={hsize} tables={tables_size:#x} "
          f"parts={parts_num} extents={ext_num}")
    base = 4096 + hsize
    parts = []
    for i in range(parts_num):
        e = hdr[base + parts_off + i * 52: base + parts_off + (i + 1) * 52]
        name = e[:36].split(b"\x00")[0].decode()
        attr, first_ext, num_ext, grp = struct.unpack_from("<IIII", e, 36)
        parts.append(dict(name=name, first_ext=first_ext, num_ext=num_ext))
    exts = []
    for i in range(ext_num):
        e = hdr[base + ext_off + i * 24: base + ext_off + (i + 1) * 24]
        num_sectors, ttype, tdata, tsrc = struct.unpack("<QIQI", e)
        exts.append(dict(num_sectors=num_sectors, type=ttype, data=tdata))
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
    ap = argparse.ArgumentParser()
    ap.add_argument('--super', default='super')
    ap.add_argument('--part', default='system')
    ap.add_argument('--path', default='/bin/init')
    ap.add_argument('--out', default='')
    ap.add_argument('--list', action='store_true')
    args = ap.parse_args()

    import mtk as mtk_cli
    parser = mtk_cli.create_base_parser()
    parser = argparse.ArgumentParser(parents=[parser], description=mtk_cli.INFO)
    sub = parser.add_subparsers(dest='cmd', required=False)
    sub.add_parser('custom')
    cargs = parser.parse_args(sys.argv[1:] + ['custom'])
    from mtkclient.Library.mtk_main import Main
    mtk = Main(cargs).run(parser)
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
