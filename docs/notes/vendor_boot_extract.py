#!/usr/bin/env python3
"""vendor_boot_extract.py - parse Android vendor_boot v3/v4 images offline.

No external tools required for gzip/lz4: gzip uses zlib, LZ4 uses a pure-python
block decoder (legacy 0x184C2102 and modern frame 0x184D2204). zstd/xz degrade
to python modules or binaries, and are reported as BLOCKED when unavailable.

Usage:
  vendor_boot_extract.py --info  IMG
  vendor_boot_extract.py --list  IMG [--max-names N]
  vendor_boot_extract.py --extract DIR IMG [--unpack]

Exit codes: 0 ok, 1 header/parse error, 2 missing file.
"""

import argparse
import gzip
import hashlib
import io
import os
import shutil
import struct
import subprocess
import sys
import zlib

MAGIC = b"VNDRBOOT"
PAGE = 4096


# ---------------------------------------------------------------- lz4 block ---
def _lz4_block_decompress(src, out_hint=8 << 20):
    """Pure-python LZ4 block decode (no frame header)."""
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        out += src[i:i + lit]
        i += lit
        if i >= n:
            break
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if off == 0:
            raise ValueError("lz4: zero offset")
        mlen = token & 0x0F
        if mlen == 15:
            while True:
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        start = len(out) - off
        if start < 0:
            raise ValueError("lz4: offset before buffer start")
        for k in range(mlen):
            out.append(out[start + k])
    return bytes(out)


def lz4_decompress(data):
    """Legacy (0x184C2102) and frame (0x184D2204) LZ4 -> bytes.

    Raises NotImplementedError if the frame layout is not understood so the
    caller can fall back to an external binary.
    """
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0x184C2102:  # legacy
        out = bytearray()
        i = 4
        n = len(data)
        while i + 4 <= n:
            (bsz,) = struct.unpack_from("<I", data, i)
            i += 4
            if bsz == 0:
                break
            out += _lz4_block_decompress(data[i:i + bsz])
            i += bsz
        return bytes(out)
    if magic == 0x184D2204:  # modern frame
        i = 4
        flg = data[i]
        i += 1
        bd = data[i]
        i += 1
        if (flg >> 6) & 1:
            i += 8
        if (flg >> 5) & 1:
            i += 4
        if (flg >> 4) & 1:
            i += 4
        if (flg >> 3) & 1:
            i += 1 + data[i]
        i += 1  # header checksum
        out = bytearray()
        block_checksum = (flg >> 4) & 1
        content_size = (flg >> 3) & 1
        while i + 4 <= len(data):
            (bsz,) = struct.unpack_from("<I", data, i)
            i += 4
            if bsz == 0:
                break
            raw = bsz & 0x80000000
            bsz &= 0x7FFFFFFF
            chunk = data[i:i + bsz]
            i += bsz
            out += chunk if raw else _lz4_block_decompress(chunk)
            if block_checksum:
                i += 4
        _ = content_size
        return bytes(out)
    raise NotImplementedError("not lz4")


# ------------------------------------------------------------------ codecs ---
def _bin_decompress(data, cmds):
    for cmd in cmds:
        exe = shutil.which(cmd[0])
        if not exe:
            continue
        try:
            p = subprocess.run([exe] + cmd[1:], input=data,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=600)
            if p.returncode == 0 and p.stdout:
                return p.stdout
        except Exception:
            continue
    return None


def detect_codec(b):
    if b[:2] == b"\x1f\x8b":
        return "gzip"
    if b[:4] == b"\x02\x21\x4c\x18":
        return "lz4-legacy"
    if b[:4] == b"\x04\x22\x4d\x18":
        return "lz4-frame"
    if b[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if b[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if b[:5] == b"\x5d\x00\x00\x80\x00" or b[:3] == b"\x5d\x00\x00":
        return "lzma"
    if b[:6] in (b"070701", b"070702"):
        return "cpio-newc (uncompressed)"
    return "unknown/raw"


def decompress(data, codec):
    """Return (bytes|None, note)."""
    try:
        if codec == "gzip":
            return gzip.decompress(data), "gzip/zlib"
        if codec in ("lz4-legacy", "lz4-frame"):
            try:
                return lz4_decompress(data), "lz4 pure-python"
            except Exception as e:
                note = "lz4(py) failed: %s" % e
                out = _bin_decompress(data, [["lz4", "-d", "-c"], ["7z", "x", "-so", "-t", "lz4", "-si"],
                                             ["7za", "x", "-so", "-si"]])
                if out:
                    return out, note + " -> external lz4"
                return None, "BLOCKED: " + note
        if codec == "zstd":
            try:
                import zstandard
                return zstandard.ZstdDecompressor().decompress(data), "zstd(py)"
            except Exception:
                pass
            out = _bin_decompress(data, [["zstd", "-d", "-c"], ["7z", "x", "-so", "-si"]])
            return (out, "zstd external") if out else (None, "BLOCKED: no zstd")
        if codec == "xz":
            try:
                import lzma
                return lzma.decompress(data), "lzma(py)"
            except Exception:
                out = _bin_decompress(data, [["xz", "-d", "-c"], ["7z", "x", "-so", "-si"]])
                return (out, "xz external") if out else (None, "BLOCKED: no xz")
        if codec.startswith("cpio"):
            return data, "none (already cpio)"
    except Exception as e:
        return None, "BLOCKED: %s" % e
    return None, "BLOCKED: unknown codec %r" % codec


# -------------------------------------------------------------------- cpio ---
class CpioEntry:
    __slots__ = ("name", "size", "mode", "offset", "data_off")

    def __init__(self, name, size, mode, offset, data_off):
        self.name, self.size, self.mode = name, size, mode
        self.offset, self.data_off = offset, data_off


def cpio_newc_parse(buf):
    """Yield CpioEntry objects from a 'newc' archive. Pure python."""
    i = 0
    n = len(buf)
    while i + 110 <= n:
        magic = buf[i:i + 6]
        if magic not in (b"070701", b"070702"):
            break
        try:
            f = [int(buf[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        except ValueError:
            break
        mode, filesize, namesize = f[1], f[6], f[11]
        name = buf[i + 110:i + 110 + namesize - 1].decode("utf-8", "replace")
        data_off = (i + 110 + namesize + 3) & ~3
        if name == "TRAILER!!!":
            break
        yield CpioEntry(name, filesize, mode, i, data_off)
        i = (data_off + filesize + 3) & ~3


# ------------------------------------------------------------------ header ---
def parse_image(path):
    with open(path, "rb") as f:
        raw = f.read()
    if raw[:8] != MAGIC:
        raise ValueError("bad magic %r (not vendor_boot)" % raw[:8])
    ver, page_size, kernel_addr, ramdisk_addr, vrsize = struct.unpack_from("<5I", raw, 8)
    cmdline = raw[28:28 + 2048].split(b"\x00")[0].decode("utf-8", "replace")
    (tags_addr,) = struct.unpack_from("<I", raw, 2076)
    name = raw[2080:2096].split(b"\x00")[0].decode("utf-8", "replace")
    header_size, dtb_size = struct.unpack_from("<2I", raw, 2096)
    (dtb_addr,) = struct.unpack_from("<Q", raw, 2104)
    h = dict(version=ver, page_size=page_size, kernel_addr=kernel_addr,
             ramdisk_addr=ramdisk_addr, vendor_ramdisk_size=vrsize,
             cmdline=cmdline, tags_addr=tags_addr, name=name,
             header_size=header_size, dtb_size=dtb_size, dtb_addr=dtb_addr,
             table_size=0, table_num=0, table_entry_size=0, bootconfig_size=0,
             file_size=len(raw))
    if ver >= 4:
        (h["table_size"], h["table_num"], h["table_entry_size"],
         h["bootconfig_size"]) = struct.unpack_from("<4I", raw, 2112)

    ps = page_size
    h["ramdisk_off"] = ps
    # v4 section layout: header | vendor_ramdisk | dtb | table | bootconfig
    sec = ps
    if ver >= 4:
        sec += _align(vrsize, ps)
        h["dtb_off"] = sec
        sec += _align(dtb_size, ps)
        h["table_off"] = sec
        sec += _align(h["table_size"], ps)
        h["bootconfig_off"] = sec
    else:
        h["dtb_off"] = sec + _align(vrsize, ps)
        h["table_off"] = h["bootconfig_off"] = None

    # fragments
    frags = []
    if ver >= 4 and h["table_num"]:
        esz = h["table_entry_size"]
        for idx in range(h["table_num"]):
            base = h["table_off"] + idx * esz
            (rsize, roff, rtype) = struct.unpack_from("<3I", raw, base)
            rname = raw[base + 12:base + 44].split(b"\x00")[0].decode("utf-8", "replace")
            board = struct.unpack_from("<16I", raw, base + 44)
            frags.append(dict(index=idx, size=rsize, offset=roff, type=rtype,
                              name=rname, board=board,
                              abs_off=h["ramdisk_off"] + roff))
    else:
        frags.append(dict(index=0, size=vrsize, offset=0, type=None,
                          name="", board=None, abs_off=h["ramdisk_off"]))
    h["fragments"] = frags
    h["raw"] = raw
    return h


def _align(x, a):
    return (x + a - 1) // a * a


def sha(b):
    return hashlib.sha256(b).hexdigest()


def fmt_size(n):
    return "%d (0x%X)" % (n, n)


# ------------------------------------------------------------------ actions ---
def do_info(path):
    h = parse_image(path)
    r = h["raw"]
    print("file            : %s" % path)
    print("image sha256    : %s" % sha(r))
    print("file size       : %s" % fmt_size(h["file_size"]))
    print("magic           : %r" % r[:8].decode())
    print("header_version  : %d" % h["version"])
    print("page_size       : %d" % h["page_size"])
    print("kernel_addr     : 0x%08X" % h["kernel_addr"])
    print("ramdisk_addr    : 0x%08X" % h["ramdisk_addr"])
    print("vendor_ramdisk_size : %s" % fmt_size(h["vendor_ramdisk_size"]))
    print("cmdline         : %r" % h["cmdline"])
    print("tags_addr       : 0x%08X" % h["tags_addr"])
    print("name            : %r" % h["name"])
    print("header_size     : 0x%X" % h["header_size"])
    if h["version"] >= 4:
        print("dtb_size        : %s" % fmt_size(h["dtb_size"]))
        print("dtb_addr        : 0x%016X" % h["dtb_addr"])
        print("vendor_ramdisk_table_size       : %d" % h["table_size"])
        print("vendor_ramdisk_table_entry_num  : %d" % h["table_num"])
        print("vendor_ramdisk_table_entry_size : %d" % h["table_entry_size"])
        print("bootconfig_size : %d" % h["bootconfig_size"])
        print("layout          : ramdisk@0x%X dtb@0x%X table@0x%X bootconfig@0x%X"
              % (h["ramdisk_off"], h["dtb_off"], h["table_off"], h["bootconfig_off"]))
    else:
        print("dtb_size        : %s" % fmt_size(h["dtb_size"]))
        print("dtb_addr        : 0x%016X" % h["dtb_addr"])
    bc = b""
    if h["version"] >= 4 and h["bootconfig_size"]:
        o = h["bootconfig_off"]
        bc = r[o:o + h["bootconfig_size"]]
    print("bootconfig bytes: %d%s" % (len(bc), "" if bc else " (none / embedded in cmdline)"))
    if bc:
        print("bootconfig sha256: %s" % sha(bc))
    print("fragments       : %d" % len(h["fragments"]))
    for f in h["fragments"]:
        blob = r[f["abs_off"]:f["abs_off"] + f["size"]]
        print("  [%d] size=%-9d @0x%-8X type=%-4s name=%-16r codec=%s"
              % (f["index"], f["size"], f["abs_off"], f["type"], f["name"],
                 detect_codec(blob)))
    # dtbo sanity
    if h["version"] >= 4 and h["dtb_size"]:
        d = r[h["dtb_off"]:h["dtb_off"] + 64]
        print("dtb head        : %s" % d[:8].hex())
    return 0


def do_list(path, max_names):
    h = parse_image(path)
    r = h["raw"]
    rc = 0
    for f in h["fragments"]:
        blob = r[f["abs_off"]:f["abs_off"] + f["size"]]
        codec = detect_codec(blob)
        print("=" * 78)
        print("fragment %d: size=%d (0x%X) offset=0x%X" % (f["index"], f["size"], f["size"], f["abs_off"]))
        if f["type"] is not None:
            tname = {0: "NONE", 1: "PLATFORM", 2: "RECOVERY", 3: "DLKM"}.get(f["type"], "?")
            print("  table entry: platform/type=%d (%s) name=%r set_id/board_id=%r"
                  % (f["type"], tname, f["name"], list(f["board"])))
        else:
            print("  table entry: none (v3 single fragment)")
        print("  compression : %s" % codec)
        print("  raw sha256  : %s" % sha(blob))
        data, note = decompress(blob, codec)
        if data is None:
            print("  %s" % note)
            rc = 0  # degraded, keep going
            continue
        print("  decompress  : %s" % note)
        print("  uncompressed: %s" % fmt_size(len(data)))
        print("  unc sha256  : %s" % sha(data))
        entries = list(cpio_newc_parse(data))
        if not entries:
            print("  cpio        : not a newc archive / no entries")
            continue
        print("  cpio entries: %d" % len(entries))
        shown = 0
        for e in entries:
            if max_names and shown >= max_names:
                print("  ... (%d more)" % (len(entries) - shown))
                break
            marker = ""
            if e.name.lstrip("./").split("/")[-1] in ("init", "adb_debug.prop",
                                                      "force_debuggable", "prop.default"):
                body = data[e.data_off:e.data_off + e.size]
                marker = "  sha256=%s" % sha(body)
            print("    %-60s %8d%s" % (e.name, e.size, marker))
            shown += 1
        # report init explicitly
        for e in entries:
            if e.name.lstrip("./").endswith("init") and e.size:
                body = data[e.data_off:e.data_off + e.size]
                print("  INIT: %s size=%d sha256=%s" % (e.name, e.size, sha(body)))
    print("=" * 78)
    return rc


def do_extract(outdir, path, unpack):
    h = parse_image(path)
    r = h["raw"]
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "info.txt"), "w") as fh:
        old = sys.stdout
        sys.stdout = fh
        do_info(path)
        sys.stdout = old
    # bootconfig: always materialise the file (0 bytes when the image has none)
    bc = b""
    if h["version"] >= 4 and h["bootconfig_size"]:
        o = h["bootconfig_off"]
        bc = r[o:o + h["bootconfig_size"]]
    with open(os.path.join(outdir, "bootconfig.bin"), "wb") as f:
        f.write(bc)
    # table dump (raw single entries)
    if h["version"] >= 4 and h["table_num"]:
        esz = h["table_entry_size"]
        with open(os.path.join(outdir, "vendor_ramdisk_table.json"), "w") as f:
            import json
            json.dump([{k: v for k, v in fr.items()} for fr in h["fragments"]], f, indent=1)
        with open(os.path.join(outdir, "vendor_ramdisk_table.bin"), "wb") as f:
            f.write(r[h["table_off"]:h["table_off"] + h["table_size"]])
    with open(os.path.join(outdir, "dtb.bin"), "wb") as f:
        f.write(r[h["dtb_off"]:h["dtb_off"] + h["dtb_size"]])
    report = []
    for fr in h["fragments"]:
        blob = r[fr["abs_off"]:fr["abs_off"] + fr["size"]]
        codec = detect_codec(blob)
        base = os.path.join(outdir, "frag%d" % fr["index"])
        ext = {"gzip": ".gz", "lz4-legacy": ".lz4", "lz4-frame": ".lz4f",
               "zstd": ".zst", "xz": ".xz"}.get(codec, ".raw")
        with open(base + ext, "wb") as f:
            f.write(blob)
        data, note = decompress(blob, codec)
        report.append((fr["index"], fr["size"], codec, note, len(data) if data else None))
        if data is None:
            print("frag%d: %s -> %s" % (fr["index"], codec, note))
            continue
        with open(base + ".cpio", "wb") as f:
            f.write(data)
        entries = list(cpio_newc_parse(data))
        print("frag%d: %s -> %d B cpio, %d entries (%s)"
              % (fr["index"], codec, len(data), len(entries), note))
        if unpack and entries:
            root = os.path.join(outdir, "frag%d-root" % fr["index"])
            for e in entries:
                nm = e.name.lstrip("./")
                dst = os.path.join(root, nm)
                if nm.endswith("/") or (e.mode & 0o170000) == 0o040000:
                    os.makedirs(dst, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(dst) or root, exist_ok=True)
                body = data[e.data_off:e.data_off + e.size]
                with open(dst, "wb") as f:
                    f.write(body)
                if (e.mode & 0o170000) == 0o120000:  # symlink
                    try:
                        os.remove(dst)
                        os.symlink(body.decode("utf-8", "replace"), dst)
                    except Exception:
                        pass
                else:
                    os.chmod(dst, e.mode & 0o777 or 0o644)
            print("frag%d: unpacked -> %s" % (fr["index"], root))
    with open(os.path.join(outdir, "summary.txt"), "w") as f:
        f.write("bootconfig_size=%d\n" % len(bc))
        for idx, size, codec, note, ucs in report:
            f.write("frag%d raw=%d codec=%s note=%s uncompressed=%s\n"
                    % (idx, size, codec, note, ucs))
    print("wrote %d files to %s" % (len(os.listdir(outdir)), outdir))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Android vendor_boot v3/v4 parser")
    ap.add_argument("--info", metavar="IMG")
    ap.add_argument("--list", metavar="IMG")
    ap.add_argument("--extract", nargs=2, metavar=("DIR", "IMG"))
    ap.add_argument("--unpack", action="store_true", help="also unpack cpio trees on --extract")
    ap.add_argument("--max-names", type=int, default=0, help="limit cpio names per fragment in --list")
    a = ap.parse_args(argv)
    try:
        if a.info:
            return do_info(a.info)
        if a.list:
            return do_list(a.list, a.max_names)
        if a.extract:
            return do_extract(a.extract[0], a.extract[1], a.unpack)
    except FileNotFoundError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
