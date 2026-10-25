#!/usr/bin/env python3
"""sparse_unpack.py - inspect / unsparse Android sparse images offline.

Supports the Android sparse format (magic 0xED26FF3A, major 1):
  header 28 B, chunk header 12 B, chunk types RAW(0xCAC1), FILL(0xCAC2),
  DONT_CARE(0xCAC3), CRC32(0xCAC4).

Usage:
  sparse_unpack.py --info  IMAGE
  sparse_unpack.py --list  IMAGE
  sparse_unpack.py --unpack IMAGE [-o OUT]

--unpack writes the expanded raw image (or copies non-sparse input) and
prints the sha256 of the result.  Exit codes:
  0 ok, 1 bad/truncated image, 2 usage.
"""

import argparse
import hashlib
import os
import struct
import sys

SPARSE_MAGIC = 0xED26FF3A
CHUNK_RAW, CHUNK_FILL, CHUNK_DONT_CARE, CHUNK_CRC32 = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4
HDR_FMT = "<IHHHHIIII"          # 28 bytes
HDR_SIZE = struct.calcsize(HDR_FMT)  # 28
CHUNK_FMT = "<HHII"             # 12 bytes
CHUNK_SIZE = struct.calcsize(CHUNK_FMT)
TYPE_NAME = {CHUNK_RAW: "RAW", CHUNK_FILL: "FILL",
             CHUNK_DONT_CARE: "DONT_CARE", CHUNK_CRC32: "CRC32"}


class SparseError(Exception):
    pass


def read_header(f):
    f.seek(0)
    b = f.read(HDR_SIZE)
    if len(b) < HDR_SIZE:
        raise SparseError("file shorter than a sparse header")
    (magic, major, minor, fhdr, chdr, blk, total_blks,
     total_chunks, checksum) = struct.unpack(HDR_FMT, b)
    if magic != SPARSE_MAGIC:
        return None
    if major != 1:
        raise SparseError("unsupported sparse major version %d" % major)
    if fhdr < HDR_SIZE or chdr < CHUNK_SIZE:
        raise SparseError("bad header sizes fhdr=%d chdr=%d" % (fhdr, chdr))
    return dict(magic=magic, major=major, minor=minor, file_hdr_sz=fhdr,
                chunk_hdr_sz=chdr, blk_sz=blk, total_blks=total_blks,
                total_chunks=total_chunks, image_checksum=checksum)


def iter_chunks(f, h):
    f.seek(h["file_hdr_sz"])
    remaining = h["total_chunks"]
    while remaining:
        b = f.read(h["chunk_hdr_sz"])
        if len(b) < CHUNK_SIZE:
            raise SparseError("truncated chunk header (%d chunks left)" % remaining)
        ctype, _res, csz, tsz = struct.unpack(CHUNK_FMT, b[:CHUNK_SIZE])
        if tsz < h["chunk_hdr_sz"]:
            raise SparseError("chunk total_sz %d < chunk_hdr_sz" % tsz)
        data_off = f.tell()
        yield ctype, csz, tsz, data_off
        f.seek(data_off + (tsz - h["chunk_hdr_sz"]))
        remaining -= 1
    if f.read(1):
        raise SparseError("trailing bytes after %d chunks" % h["total_chunks"])


def cmd_info(f, h, path):
    print("file            : %s (%d bytes)" % (path, os.path.getsize(path)))
    print("format          : Android sparse, v%d.%d" % (h["major"], h["minor"]))
    print("file_hdr_sz     : %d" % h["file_hdr_sz"])
    print("chunk_hdr_sz    : %d" % h["chunk_hdr_sz"])
    print("block size      : %d" % h["blk_sz"])
    print("total blocks    : %d" % h["total_blks"])
    print("total chunks    : %d" % h["total_chunks"])
    print("image checksum  : 0x%08x" % h["image_checksum"])
    raw = h["total_blks"] * h["blk_sz"]
    print("raw size        : %d" % raw)
    print("expansion ratio : %.3fx (%d -> %d)" %
          (raw / float(os.path.getsize(path)), os.path.getsize(path), raw))
    return 0


def cmd_list(f, h, path):
    print("%-10s %10s %10s %12s" % ("type", "chunks", "bytes", "out_off"))
    out_off = 0
    csum = 0
    for i, (ctype, csz, tsz, off) in enumerate(iter_chunks(f, h)):
        print("%-10s %10d %10d %12d" % (TYPE_NAME.get(ctype, hex(ctype)), csz, tsz, out_off))
        csum += csz
        out_off += csz * h["blk_sz"]
    print("chunks=%d blocks=%d raw=%d" % (i + 1, csum, out_off))
    if csum != h["total_blks"]:
        print("WARNING: chunk blocks %d != header total_blks %d" % (csum, h["total_blks"]))
        return 1
    return 0


def cmd_unpack(f, h, path, out):
    if out is None:
        out = os.path.splitext(path)[0] + ".raw"
    blk = h["blk_sz"]
    digest = hashlib.sha256()
    n = 0
    with open(out, "wb") as o:
        for ctype, csz, tsz, off in iter_chunks(f, h):
            if ctype == CHUNK_RAW:
                f.seek(off)
                left = csz * blk
                if tsz - h["chunk_hdr_sz"] != left:
                    raise SparseError("RAW chunk data size mismatch")
                while left:
                    b = f.read(min(left, 1 << 22))
                    if not b:
                        raise SparseError("truncated RAW chunk")
                    o.write(b)
                    digest.update(b)
                    left -= len(b)
                    n += len(b)
            elif ctype == CHUNK_FILL:
                f.seek(off)
                fill = f.read(4)
                if len(fill) != 4:
                    raise SparseError("truncated FILL chunk")
                piece = fill * (min(csz * blk, 1 << 20) // 4)
                left = csz * blk
                while left:
                    b = piece[:min(left, len(piece))]
                    o.write(b)
                    digest.update(b)
                    left -= len(b)
                    n += len(b)
            elif ctype == CHUNK_DONT_CARE:
                left = csz * blk
                zero = bytes(min(left, 1 << 20))
                while left:
                    b = zero[:min(left, len(zero))]
                    o.write(b)
                    digest.update(b)
                    left -= len(b)
                    n += len(b)
            elif ctype == CHUNK_CRC32:
                pass  # no payload; nothing to emit
            else:
                raise SparseError("unknown chunk type 0x%04x" % ctype)
    print("wrote  : %s" % out)
    print("size   : %d" % n)
    print("sha256 : %s" % digest.hexdigest())
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Inspect or unsparse an Android sparse image (offline).",
        epilog="Exit: 0 ok, 1 bad image, 2 usage.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--info", action="store_true", help="print header and raw size")
    g.add_argument("--list", action="store_true", help="list chunks")
    g.add_argument("--unpack", action="store_true", help="expand to raw image")
    ap.add_argument("image", help="sparse image path")
    ap.add_argument("-o", "--output", help="output path for --unpack")
    a = ap.parse_args(argv)

    if not os.path.isfile(a.image):
        print("error: no such file: %s" % a.image, file=sys.stderr)
        return 1
    try:
        with open(a.image, "rb") as f:
            h = read_header(f)
            if h is None:
                print("not an Android sparse image (magic != 0xED26FF3A)")
                if a.unpack:
                    out = a.output or os.path.splitext(a.image)[0] + ".raw"
                    d = hashlib.sha256()
                    n = 0
                    with open(out, "wb") as o:
                        for b in iter(lambda: f.read(1 << 22), b""):
                            o.write(b); d.update(b); n += len(b)
                    print("copied : %s\nsize   : %d\nsha256 : %s" % (out, n, d.hexdigest()))
                    return 0
                return 1
            if a.info:
                return cmd_info(f, h, a.image)
            if a.list:
                return cmd_list(f, h, a.image)
            return cmd_unpack(f, h, a.image, a.output)
    except SparseError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
