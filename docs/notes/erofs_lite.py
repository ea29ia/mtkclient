#!/usr/bin/env python3
"""erofs_lite.py - minimal read-only EROFS reader (no erofs-utils needed).

Fallback for air-gapped hosts.  Understands the EROFS on-disk format enough to:
  * print the superblock,
  * walk directories (inline and flat-plain data),
  * stat files,
  * extract files stored inline or uncompressed (flat-plain).
Compressed files (LZ4/LZMA/deflate/zstd clusters) are detected and reported
as unsupported -- use `fsck.erofs --extract=DIR` for those.

Usage:
  erofs_lite.py --info IMAGE
  erofs_lite.py --ls PATH [--image IMAGE]
  erofs_lite.py --stat PATH [--image IMAGE]
  erofs_lite.py --extract PATH [-o OUT] [--image IMAGE]

Exit codes: 0 ok, 1 format/path error, 3 compressed payload (use fsck.erofs).
"""

import argparse
import hashlib
import struct
import sys

EROFS_MAGIC = 0xE0F5E1E2
SB_OFFSET = 1024
LAYOUT_NAMES = {0: "flat-plain", 1: "compressed-full", 2: "flat-inline",
                3: "compressed-compact", 4: "chunk-based"}
S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000


class ErofsError(Exception):
    pass


class Compressed(ErofsError):
    pass


class Erofs:
    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self.f.seek(SB_OFFSET)
        sb = self.f.read(128)
        if len(sb) < 128 or struct.unpack_from("<I", sb, 0)[0] != EROFS_MAGIC:
            raise ErofsError("not an EROFS image (magic at 0x400 is 0x%08x)" %
                             struct.unpack_from("<I", sb, 0)[0])
        self.magic, self.checksum, self.feature_compat = struct.unpack_from("<III", sb, 0)
        self.blkszbits = sb[12]
        self.blksz = 1 << self.blkszbits
        self.root_nid = struct.unpack_from("<H", sb, 14)[0]
        self.inos = struct.unpack_from("<Q", sb, 16)[0]
        self.blocks = struct.unpack_from("<I", sb, 36)[0]
        self.meta_blkaddr = struct.unpack_from("<I", sb, 40)[0]
        self.xattr_blkaddr = struct.unpack_from("<I", sb, 44)[0]
        self.feature_incompat = struct.unpack_from("<I", sb, 80)[0]

    def close(self):
        self.f.close()

    # ---- low level -------------------------------------------------
    def iloc(self, nid):
        """erofs_iloc(): inode slot address = meta_blkaddr + (nid*32)/blksz."""
        pos = nid << 5
        return (self.meta_blkaddr + (pos >> self.blkszbits)) * self.blksz + (pos & (self.blksz - 1))

    def inode(self, nid):
        iloc = self.iloc(nid)
        self.f.seek(iloc)
        b = self.f.read(64)
        if len(b) < 32:
            raise ErofsError("short inode read at 0x%x" % iloc)
        i_format, xicount = struct.unpack_from("<HH", b, 0)
        version = i_format & 1
        layout = (i_format >> 1) & 7
        if version == 0:
            if len(b) < 32:
                raise ErofsError("short compact inode")
            mode, nlink, size = struct.unpack_from("<HHI", b, 4)
            i_u = struct.unpack_from("<I", b, 16)[0]
            ino, uid, gid = struct.unpack_from("<IHH", b, 20)
            isize = 32
        else:
            if len(b) < 64:
                raise ErofsError("short extended inode")
            mode = struct.unpack_from("<H", b, 4)[0]
            size = struct.unpack_from("<Q", b, 8)[0]
            i_u = struct.unpack_from("<I", b, 16)[0]
            ino = struct.unpack_from("<I", b, 20)[0]
            uid, gid = struct.unpack_from("<II", b, 24)
            nlink = struct.unpack_from("<I", b, 44)[0]
            isize = 64
        xattr_isize = (12 + 4 * (xicount - 1)) if xicount else 0
        return dict(nid=nid, iloc=iloc, version=version, layout=layout, mode=mode,
                    nlink=nlink, size=size, i_u=i_u, ino=ino, uid=uid, gid=gid,
                    isize=isize, xattr_isize=xattr_isize,
                    data_off=iloc + isize + xattr_isize)

    def read_data(self, ino, length=None):
        """Return raw bytes of an inode's data area (no decompression)."""
        if ino["layout"] in (1, 3, 4):
            raise Compressed("inode %d uses %s data; needs fsck.erofs" %
                             (ino["nid"], LAYOUT_NAMES.get(ino["layout"], ino["layout"])))
        size = ino["size"] if length is None else length
        if ino["layout"] == 2:      # flat-inline
            off = ino["data_off"]
        elif ino["layout"] == 0:    # flat-plain
            off = ino["i_u"] * self.blksz
        else:
            raise ErofsError("unsupported data layout %d" % ino["layout"])
        self.f.seek(off)
        data = self.f.read(size)
        if len(data) != size:
            raise ErofsError("short read at 0x%x (%d/%d)" % (off, len(data), size))
        return data

    # ---- directories ---------------------------------------------
    def listdir(self, ino):
        if (ino["mode"] & S_IFMT) != S_IFDIR:
            raise ErofsError("not a directory")
        data = self.read_data(ino)
        out = []
        pos = 0
        while pos < len(data):
            blk = data[pos:pos + self.blksz]
            if len(blk) < 12:
                break
            first_nameoff = struct.unpack_from("<H", blk, 8)[0]
            count = first_nameoff // 12
            for j in range(count):
                nid, nameoff, ftype = struct.unpack_from("<QHB", blk, j * 12)
                end = (struct.unpack_from("<H", blk, (j + 1) * 12 + 8)[0]
                       if j + 1 < count else len(blk))
                name = blk[nameoff:end].split(b"\0", 1)[0]
                if name in (b".", b".."):
                    continue
                out.append((name.decode("utf-8", "replace"), nid, ftype,
                            nameoff, end - nameoff))
            pos += self.blksz
        return out

    def lookup(self, path):
        parts = [p for p in path.split("/") if p]
        ino = self.inode(self.root_nid)
        for part in parts:
            if (ino["mode"] & S_IFMT) != S_IFDIR:
                raise ErofsError("%s is not a directory" % path)
            found = None
            for name, nid, _ft, _o, _l in self.listdir(ino):
                if name == part:
                    found = nid
                    break
            if found is None:
                raise ErofsError("no such path: %s (missing %r)" % (path, part))
            ino = self.inode(found)
        return ino


def mode_str(mode):
    t = mode & S_IFMT
    kind = {S_IFDIR: "d", S_IFREG: "-", S_IFLNK: "l"}.get(t, "?")
    bits = "".join(c if mode & (1 << (8 - i)) else "-"
                   for i, c in enumerate("rwxrwxrwx"))
    return kind + bits


def cmd_info(fs):
    print("image           : %s" % fs.path)
    print("magic           : 0x%08X (EROFS)" % fs.magic)
    print("block size      : %d (blkszbits=%d)" % (fs.blksz, fs.blkszbits))
    print("inodes          : %d" % fs.inos)
    print("blocks          : %d (%d bytes)" % (fs.blocks, fs.blocks * fs.blksz))
    print("root nid        : %d (inode @0x%x)" % (fs.root_nid, fs.iloc(fs.root_nid)))
    print("meta_blkaddr    : %d" % fs.meta_blkaddr)
    print("feature_compat  : 0x%08x" % fs.feature_compat)
    print("feature_incompat: 0x%08x%s" % (
        fs.feature_incompat,
        " (COMPR_CFGS: some files may be compressed)" if fs.feature_incompat & 1 else ""))
    return 0


def cmd_ls(fs, path):
    ino = fs.lookup(path)
    if (ino["mode"] & S_IFMT) != S_IFDIR:
        return cmd_stat(fs, path)
    print("path: %s  nid=%d  layout=%s" % (path, ino["nid"], LAYOUT_NAMES.get(ino["layout"])))
    print("%-10s %8s %10s %s" % ("type", "nid", "size", "name"))
    for name, nid, ftype, _o, _l in fs.listdir(ino):
        try:
            child = fs.inode(nid)
            print("%-10s %8d %10d %s" % (mode_str(child["mode"]), nid, child["size"], name))
        except ErofsError:
            print("%-10s %8d %10s %s" % ("ftype=%d" % ftype, nid, "?", name))
    return 0


def cmd_stat(fs, path):
    ino = fs.lookup(path)
    print("path       : %s" % path)
    print("nid        : %d" % ino["nid"])
    print("inode      : @0x%x (%s, %d B)" % (ino["iloc"], "extended" if ino["version"] else "compact", ino["isize"]))
    print("mode       : %s (0%o)" % (mode_str(ino["mode"]), ino["mode"]))
    print("uid/gid    : %d/%d" % (ino["uid"], ino["gid"]))
    print("size       : %d" % ino["size"])
    print("layout     : %s" % LAYOUT_NAMES.get(ino["layout"], ino["layout"]))
    print("data_off   : 0x%x" % ino["data_off"])
    return 0


def cmd_extract(fs, path, out):
    ino = fs.lookup(path)
    if out is None:
        out = path.strip("/").replace("/", "_") or "root"
    try:
        data = fs.read_data(ino)
    except Compressed as e:
        print("cannot extract: %s" % e, file=sys.stderr)
        return 3
    with open(out, "wb") as o:
        o.write(data)
    print("wrote  : %s" % out)
    print("size   : %d" % len(data))
    print("sha256 : %s" % hashlib.sha256(data).hexdigest())
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Minimal read-only EROFS reader (pure python fallback).",
        epilog="Compressed files return exit 3; use erofs-utils fsck.erofs for those.")
    ap.add_argument("--image", default="/tmp/fw/system.raw",
                    help="EROFS image path (default: /tmp/fw/system.raw)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--info", action="store_true", help="print superblock")
    g.add_argument("--ls", metavar="PATH", help="list a directory")
    g.add_argument("--stat", metavar="PATH", help="show inode metadata")
    g.add_argument("--extract", metavar="PATH", help="extract a file")
    ap.add_argument("-o", "--output", help="output path for --extract")
    a = ap.parse_args(argv)

    try:
        fs = Erofs(a.image)
    except (OSError, ErofsError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    try:
        if a.info:
            return cmd_info(fs)
        if a.ls is not None:
            return cmd_ls(fs, a.ls)
        if a.stat is not None:
            return cmd_stat(fs, a.stat)
        return cmd_extract(fs, a.extract, a.output)
    except Compressed as e:
        print("unsupported: %s" % e, file=sys.stderr)
        return 3
    except ErofsError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    finally:
        fs.close()


if __name__ == "__main__":
    sys.exit(main())
