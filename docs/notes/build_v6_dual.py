#!/usr/bin/env python3
"""build_v6_dual.py - build AND verify a "v6"/"v7" boot/vendor_boot pair offline.

Variants
--------
  --variant v6 (legacy, kept byte-reproducible)
      boot ramdisk: P1 + /force_debuggable + /adb_debug.prop
      vendor_boot : P2 + /force_debuggable + /adb_debug.prop
  --variant v7 (default; v6 boot + the R4c rootfs property file)
      boot ramdisk: the v6 set PLUS /debug_ramdisk/adb_debug.prop, which lives
      in the *rootfs* directory under the tmpfs mount point.  The failing gate
      branch in SecondStageMain calls UmountDebugRamdisk() (0x139A28) BEFORE
      PropertyInit(), so PropertyLoadBootDefaults' access()/0x156FF0 on
      "/debug_ramdisk/adb_debug.prop" hits the underlying rootfs copy even when
      verifiedbootstate != "orange".  vendor_boot is unchanged from v6 and must
      NOT be flashed (it is only produced for reference / regression parity).

Both variants keep `--variant v6` byte-identical to the historical
/tmp/v6 outputs (af5c10c2... boot, fb83d015... vendor_boot).

Both ramdisks are patched, so the v6 result is correct regardless of which
/init the kernel ends up executing:

  boot.img ramdisk
      /init            @file offset 0xF6D14: 93 04 00 36 (tbz w19,#0,0x2F6DA4)
                          -> 24 00 00 14 (b 0x2F6DA4)
      + /force_debuggable (0 B, 0100644)
      + /adb_debug.prop   (see ADB_PROPS)
      everything else byte-identical to stock; [embedded vbmeta .. EOF] is
      copied verbatim (signed vbmeta cannot be rebuilt, so it is left alone).

  vendor_boot.img (v4, one PLATFORM fragment)
      system/bin/init  @file offset 0xF1710: 33 05 00 36 (tbz w19,#0,0xF17B4)
                          -> 29 00 00 14 (b 0xF17B4)
      + /force_debuggable, /adb_debug.prop at the cpio root
      the /init symlink is NOT touched; dtb bytes are identical; the v4
      header/table/page-aligned layout is recomputed; the embedded vbmeta
      (algorithm NONE = unsigned, self-hash only) gets its hash-descriptor
      image_size/digest recomputed and the AVB footer offset updated.

Codecs
------
* boot ramdisk: **gzip -9** (zlib, stdlib).  The pure-python LZ4-legacy
  compressor implemented here produces 1 857 958 B for this ramdisk, which
  does NOT fit the 1 654 784 B slot before the embedded vbmeta.  gzip -9 fits
  (1 419 8xx B) and v5 already booted with a gzip boot ramdisk
  (CONFIG_RD_GZIP=y, re-vendor-boot-q1.md 6.2).
* vendor_boot ramdisk: **LZ4 legacy only** (stock codec, required by the
  contract).  Complete stock 8 MiB blocks that end before the modified tail
  are reused verbatim; the tail is recompressed by the pure-python legacy
  compressor.  The result is re-decoded and compared before it is accepted.

Usage
-----
  python3 docs/notes/build_v6_dual.py build     [-o /tmp/v6|/tmp/v7]
  python3 docs/notes/build_v6_dual.py verify    [-o /tmp/v6|/tmp/v7]
  V7_FLASH_GO=1 python3 docs/notes/build_v6_dual.py flash --variant v7
                                                # gated, DA, boot_a only
  V6_FLASH_GO=1 python3 docs/notes/build_v6_dual.py flash --variant v6
                                                # gated, DA, both partitions

Exit codes: 0 all good, 1 failure/invariant broken, 2 missing input.
No device access except in the gated `flash` subcommand.
"""

import argparse
import gzip
import hashlib
import os
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import vendor_boot_extract as vbe  # noqa: E402  (pure-python lz4/cpio/gzip)

# --------------------------------------------------------------------------
# contract constants (stock inputs - never modified)
# --------------------------------------------------------------------------
STOCK_BOOT = os.path.join(REPO, "docs", "notes", "rmx3630-lk", "boot.img")
STOCK_VBOOT = "/tmp/fw/vendor_boot.img"
OUTDIR_V6 = "/tmp/v6"
OUTDIR_V7 = "/tmp/v7"
OUTDIR = OUTDIR_V6                    # historical default, kept for importers
DEFAULT_VARIANT = "v7"

STOCK_BOOT_SHA = "8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9"
STOCK_VBOOT_SHA = "1fa1e890275b176b85ef2c7186910d497f14f1642013a0a42c862b60977e7ab4"
STOCK_BOOT_INIT_SHA = "b8088eb2b895da034ba6048a159068b5ca6f39b54d40a849e66ec33a12b907c6"
STOCK_VINIT_SHA = "de4092871407b7946fbe8c55e75577d12bdb836d911a8c279ae2490fd0d580cd"
STOCK_BOOT_CPIO_SHA = "2b701091a8cf0c29a187e0440c3bbf6016e2809b0ef396b71831f2d1c030a135"
STOCK_VBOOT_CPIO_SHA = "6fa98ce5743dbd7d2823870654a58a0b94c513406c1015b15a5193959e4f98b5"
STOCK_BOOT_DTB_SHA = None          # vendor_boot only; compared stock vs v6
PART_SIZE = 64 << 20                # 67 108 864 = both partitions
LK_RAMDISK_LIMIT = 64 << 20         # LK_RAMDISK_SIZE check in lk_payload

BOOT_HDR_SIZE = 0x630
BOOT_KERNEL_SIZE = 20410061
BOOT_RD_SIZE = 1649781
BOOT_RD_SLOT = 1654784                 # 0x150C000 - 0x1378000, vbmeta starts after
PAGE = 4096

P1_OFF, P1_OLD, P1_NEW = 0xF6D14, bytes.fromhex("93040036"), bytes.fromhex("24000014")
P1_TARGET = 0x2F6DA4
P2_OFF, P2_OLD, P2_NEW = 0xF1710, bytes.fromhex("33050036"), bytes.fromhex("29000014")
P2_TARGET = 0xF17B4

# exact expected /adb_debug.prop content (4 lines, trailing newline, 81 bytes)
ADB_PROPS = (b"ro.adb.secure=0\n"
             b"ro.debuggable=1\n"
             b"ro.force.debuggable=1\n"
             b"persist.sys.usb.config=adb\n")

ADDED = ("force_debuggable", "adb_debug.prop")
# R4c: the same payload inside the stock 040755 rootfs directory that the
# first stage hides behind the /debug_ramdisk tmpfs mount.  After
# UmountDebugRamdisk() the underlying directory is visible again, so
# PropertyLoadBootDefaults reads this copy when the gate branch failed.
ROOTFS_PROP = "debug_ramdisk/adb_debug.prop"
ADDED_V7 = ADDED + (ROOTFS_PROP,)
VARIANT_ADDED = {"v6": ADDED, "v7": ADDED_V7}

BOOT_OUT = "boot_v6.img"
BOOT_OUT_V7 = "boot_v7.img"
VBOOT_OUT = "vendor_boot_v6.img"       # unchanged for both variants

VARIANT_BOOT_OUT = {"v6": BOOT_OUT, "v7": BOOT_OUT_V7}


def default_outdir(variant):
    return OUTDIR_V7 if variant == "v7" else OUTDIR_V6


def boot_out_name(variant):
    return VARIANT_BOOT_OUT[variant]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def sha(b):
    return hashlib.sha256(b).hexdigest()


def align_up(x, a=PAGE):
    return (x + a - 1) // a * a


def nonzero_gaps(data, sections):
    """Return the [start,end) ranges outside `sections` that hold nonzero bytes."""
    cur, out = 0, []
    for a, b in sorted(sections):
        if a > cur and any(data[cur:a]):
            out.append((cur, a))
        cur = max(cur, b)
    if cur < len(data) and any(data[cur:]):
        out.append((cur, len(data)))
    return out


def die(msg, rc=1):
    print("ERROR: %s" % msg, file=sys.stderr)
    return rc


def read_checked(path, expect_sha, what):
    if not os.path.exists(path):
        raise SystemExit(die("%s not found: %s" % (what, path), 2))
    data = open(path, "rb").read()
    got = sha(data)
    if got != expect_sha:
        raise SystemExit(die("%s sha256 mismatch\n  expected %s\n  got      %s\n"
                             "refusing to build from a non-stock image"
                             % (what, expect_sha, got)))
    return data


# ------------------------------------------------ LZ4 legacy (pure python) --
def lz4_block_compress(src):
    """Greedy LZ4 block compressor (token/literals/offset/matchlen)."""
    n = len(src)
    out = bytearray()
    if n == 0:
        return b""
    table = {}
    anchor = 0
    i = 0
    mflimit = n - 12          # last match must start >= 12 B before the end
    matchlimit = n - 5        # last 5 B are always literals
    search_nb = 1 << 6
    while i < mflimit:
        seq = src[i:i + 4]
        cand = table.get(seq)
        table[seq] = i
        if cand is None or (i - cand) > 65535:
            i += search_nb >> 6
            search_nb += 1
            continue
        search_nb = 1 << 6
        k = i + 4
        while k < matchlimit and src[cand + (k - i)] == src[k]:
            k += 1
        mlen = k - i
        litlen = i - anchor
        mcode = mlen - 4
        out.append(((15 if litlen >= 15 else litlen) << 4) |
                   (15 if mcode >= 15 else mcode))
        if litlen >= 15:
            rem = litlen - 15
            while rem >= 255:
                out.append(255)
                rem -= 255
            out.append(rem)
        out += src[anchor:i]
        off = i - cand
        out.append(off & 0xFF)
        out.append(off >> 8)
        if mcode >= 15:
            rem = mcode - 15
            while rem >= 255:
                out.append(255)
                rem -= 255
            out.append(rem)
        i = k
        anchor = k
    litlen = n - anchor
    out.append((15 if litlen >= 15 else litlen) << 4)
    if litlen >= 15:
        rem = litlen - 15
        while rem >= 255:
            out.append(255)
            rem -= 255
        out.append(rem)
    out += src[anchor:n]
    return bytes(out)


LZ4_LEGACY_MAGIC = 0x184C2102
LZ4_BLOCK = 8 << 20


def lz4_legacy_compress(data):
    out = bytearray(struct.pack("<I", LZ4_LEGACY_MAGIC))
    for o in range(0, len(data), LZ4_BLOCK):
        blk = lz4_block_compress(data[o:o + LZ4_BLOCK])
        out += struct.pack("<I", len(blk))
        out += blk
    return bytes(out)


def lz4_legacy_blocks(blob):
    """Decode a legacy stream -> (raw, blocks[(c_start, c_size, u_size)])."""
    if struct.unpack_from("<I", blob, 0)[0] != LZ4_LEGACY_MAGIC:
        raise ValueError("not an lz4-legacy stream")
    raw = bytearray()
    blocks = []
    i = 4
    while i + 4 <= len(blob):
        (bsz,) = struct.unpack_from("<I", blob, i)
        if bsz == 0:
            break
        start = i + 4
        chunk = blob[start:start + bsz]
        if len(chunk) != bsz:
            raise ValueError("truncated lz4 block")
        # public API of the unmodified parser: wrap the single block in a
        # minimal legacy frame instead of touching its private helper
        dec = vbe.lz4_decompress(struct.pack("<I", LZ4_LEGACY_MAGIC) +
                                 struct.pack("<I", len(chunk)) + chunk)
        blocks.append((start - 4, bsz, len(dec)))
        raw += dec
        i = start + bsz
    return bytes(raw), blocks


# -------------------------------------------------------------------- cpio ---
def cpio_walk(buf):
    """Yield dicts for every entry including TRAILER!!! (newc, pure python)."""
    i, n = 0, len(buf)
    while i + 110 <= n:
        if buf[i:i + 6] not in (b"070701", b"070702"):
            raise ValueError("bad cpio magic at 0x%X" % i)
        f = [int(buf[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        ino, mode, namesize, filesize = f[0], f[1], f[11], f[6]
        name = buf[i + 110:i + 110 + namesize - 1].decode("utf-8", "replace")
        data_off = align_up(i + 110 + namesize, 4)
        ent = dict(name=name, ino=ino, mode=mode, size=filesize,
                   offset=i, data_off=data_off,
                   data=buf[data_off:data_off + filesize],
                   end=align_up(data_off + filesize, 4))
        yield ent
        if name == "TRAILER!!!":
            return
        i = ent["end"]
        if i <= ent["offset"]:
            raise ValueError("cpio walk did not advance")


def cpio_entry(name, data, mode, ino):
    """Serialise one 'newc' entry (uid/gid 0, nlink 1, mtime 0)."""
    nb = name.encode()
    fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nb) + 1, 0)
    hdr = b"070701" + b"".join(b"%08X" % x for x in fields) + nb + b"\x00"
    out = bytearray(hdr)
    out += b"\x00" * ((-len(out)) % 4)
    out += data
    out += b"\x00" * ((-len(out)) % 4)
    return bytes(out)


def cpio_insert(raw, additions):
    """Insert entries immediately before TRAILER!!!; return new archive."""
    ents = list(cpio_walk(raw))
    trailer = [e for e in ents if e["name"] == "TRAILER!!!"]
    if len(trailer) != 1:
        raise ValueError("expected exactly one cpio trailer")
    off = trailer[0]["offset"]
    return raw[:off] + b"".join(additions) + raw[off:]


def additions_for(raw, variant="v6"):
    """Build the added cpio entries with fresh inodes.

    v6: /force_debuggable + /adb_debug.prop
    v7: the same two plus debug_ramdisk/adb_debug.prop (R4c rootfs copy).
    The v6 branch is byte-identical to the historical implementation.
    """
    if variant not in VARIANT_ADDED:
        raise ValueError("unknown variant %r" % (variant,))
    ino = max(e["ino"] for e in cpio_walk(raw))
    files = [("force_debuggable", b""), ("adb_debug.prop", ADB_PROPS)]
    if variant == "v7":
        files.append((ROOTFS_PROP, ADB_PROPS))
    adds = []
    for name, data in files:
        ino += 1
        adds.append(cpio_entry(name, data, 0o100644, ino))
    return adds, ino


# ------------------------------------------------------- boot header access ---
def boot_parse(img):
    if img[:8] != b"ANDROID!":
        raise ValueError("boot: bad magic")
    kernel_size, ramdisk_size = struct.unpack_from("<II", img, 8)
    os_version, header_size = struct.unpack_from("<II", img, 16)
    header_version = struct.unpack_from("<I", img, 0x28)[0]
    d = dict(kernel_size=kernel_size, ramdisk_size=ramdisk_size,
             os_version=os_version, header_size=header_size,
             header_version=header_version,
             rd_off=align_up(PAGE + kernel_size),
             file_size=len(img))
    if header_version == 4:
        d["signature_size"] = struct.unpack_from("<I", img, 0x62C)[0]
    return d


def avb_footer(img):
    f = img[-64:]
    if f[:4] != b"AVBf":
        raise ValueError("no AVBf footer in the last 64 bytes")
    maj, minr = struct.unpack_from(">II", f, 4)
    orig, vb_off, vb_size = struct.unpack_from(">QQQ", f, 12)
    return dict(major=maj, minor=minr, original_image_size=orig,
                vbmeta_offset=vb_off, vbmeta_size=vb_size)


def avb_parse_hash(vb):
    """Parse an AvbHashDescriptor inside an AVB0 vbmeta blob."""
    if vb[:4] != b"AVB0":
        raise ValueError("vbmeta: bad magic")
    auth, aux = struct.unpack_from(">QQ", vb, 12)
    alg = struct.unpack_from(">I", vb, 28)[0]
    off, end = 256 + auth, 256 + auth + aux
    while off + 16 <= end:
        tag, nb = struct.unpack_from(">QQ", vb, off)
        if tag == 0 and nb == 0:
            break
        if tag == 2:                                  # AVB_DESCRIPTOR_TAG_HASH
            image_size = struct.unpack_from(">Q", vb, off + 16)[0]
            halg = vb[off + 24:off + 56].split(b"\x00")[0].decode()
            pl, sl, dl, fl = struct.unpack_from(">4I", vb, off + 56)
            body = off + 132
            info = dict(desc_off=off, desc_len=16 + nb, image_size=image_size,
                        hash_algorithm=halg, name=vb[body:body + pl],
                        salt=vb[body + pl:body + pl + sl],
                        digest_off=body + pl + sl, digest_len=dl, flags=fl)
            if info["desc_off"] + info["desc_len"] > end:
                raise ValueError("hash descriptor overruns the aux block")
            return alg, info
        off += 16 + nb
    raise ValueError("no AvbHashDescriptor in vbmeta")


def avb_rehash(vb, prefix):
    """Rewrite image_size+digest of the hash descriptor (alg NONE only)."""
    alg, info = avb_parse_hash(vb)
    if alg != 0:
        raise ValueError("vbmeta is signed (algorithm %d): cannot rehash" % alg)
    if info["hash_algorithm"] != "sha256":
        raise ValueError("unexpected hash algorithm %r" % info["hash_algorithm"])
    out = bytearray(vb)
    struct.pack_into(">Q", out, info["desc_off"] + 16, len(prefix))
    struct.pack_into(">%ds" % info["digest_len"], out, info["digest_off"],
                     hashlib.sha256(info["salt"] + prefix).digest())
    return bytes(out), info


# ------------------------------------------------------ vendor_boot header ----
def vboot_parse(img):
    if img[:8] != b"VNDRBOOT":
        raise ValueError("vendor_boot: bad magic")
    ver, page, kaddr, raddr, vrsize = struct.unpack_from("<5I", img, 8)
    tags = struct.unpack_from("<I", img, 2076)[0]
    name = img[2080:2096].split(b"\x00")[0].decode()
    hsize, dsize = struct.unpack_from("<II", img, 2096)
    daddr = struct.unpack_from("<Q", img, 2104)[0]
    tsize, tnum, tent, bcsize = struct.unpack_from("<4I", img, 2112)
    d = dict(version=ver, page=page, kernel_addr=kaddr, ramdisk_addr=raddr,
             vendor_ramdisk_size=vrsize, tags_addr=tags, name=name,
             header_size=hsize, dtb_size=dsize, dtb_addr=daddr,
             table_size=tsize, table_num=tnum, table_entry_size=tent,
             bootconfig_size=bcsize, file_size=len(img),
             cmdline=img[28:28 + 2048].split(b"\x00")[0].decode())
    d["rd_off"] = page
    d["dtb_off"] = align_up(d["rd_off"] + vrsize, page)
    d["table_off"] = align_up(d["dtb_off"] + dsize, page)
    d["bc_off"] = align_up(d["table_off"] + tsize, page)
    return d


def vboot_table_entry(img, h, idx=0):
    base = h["table_off"] + idx * h["table_entry_size"]
    rsize, roff, rtype = struct.unpack_from("<3I", img, base)
    name = img[base + 12:base + 44].split(b"\x00")[0].decode()
    board = struct.unpack_from("<16I", img, base + 44)
    return dict(size=rsize, offset=roff, type=rtype, name=name,
                board=board, abs_off=h["rd_off"] + roff)


# ==========================================================================
# BUILD
# ==========================================================================
def build_boot(stock, variant="v6"):
    if variant not in VARIANT_ADDED:
        raise SystemExit(die("unknown variant %r" % (variant,)))
    p = boot_parse(stock)
    if (p["header_version"], p["header_size"], p["kernel_size"],
            p["ramdisk_size"]) != (4, BOOT_HDR_SIZE, BOOT_KERNEL_SIZE, BOOT_RD_SIZE):
        raise SystemExit(die("unexpected stock boot header %r" % p))
    foot = avb_footer(stock)
    vb_off = foot["vbmeta_offset"]
    if stock[vb_off:vb_off + 4] != b"AVB0":
        raise SystemExit(die("AVB0 missing at footer vbmeta_offset 0x%X" % vb_off))
    if stock.find(b"AVB0", p["rd_off"], vb_off) >= 0:
        raise SystemExit(die("stray AVB0 between ramdisk and embedded vbmeta"))
    budget = vb_off - p["rd_off"]
    if budget != BOOT_RD_SLOT:
        raise SystemExit(die("ramdisk slot is %d B, expected %d B (vbmeta @0x%X)"
                             % (budget, BOOT_RD_SLOT, vb_off)))
    bad = nonzero_gaps(stock, [(0, BOOT_HDR_SIZE),
                               (0x1000, 0x1000 + p["kernel_size"]),
                               (p["rd_off"], p["rd_off"] + p["ramdisk_size"]),
                               (vb_off, len(stock))])
    if bad:
        raise SystemExit(die("stock boot has nonzero bytes outside the known "
                             "sections %r - refusing to zero them" %
                             [(hex(a), hex(b)) for a, b in bad]))

    blob = stock[p["rd_off"]:p["rd_off"] + p["ramdisk_size"]]
    codec = vbe.detect_codec(blob)
    if codec != "lz4-legacy":
        raise SystemExit(die("stock boot ramdisk codec is %r, expected lz4-legacy" % codec))
    raw, _blocks = lz4_legacy_blocks(blob)
    if sha(raw) != STOCK_BOOT_CPIO_SHA:
        raise SystemExit(die("stock boot cpio sha256 mismatch: %s" % sha(raw)))
    ents = list(cpio_walk(raw))
    by = {e["name"].lstrip("./"): e for e in ents}
    init = by.get("init")
    if not init or init["size"] != 3143536 or sha(init["data"]) != STOCK_BOOT_INIT_SHA:
        raise SystemExit(die("stock boot ramdisk /init is not the expected binary"))
    if init["data"][P1_OFF:P1_OFF + 4] != P1_OLD:
        raise SystemExit(die("stock P1 site mismatch at 0x%X: %s"
                             % (P1_OFF, init["data"][P1_OFF:P1_OFF + 4].hex())))

    if variant == "v7":
        dr = by.get("debug_ramdisk")
        if dr is None or dr["mode"] != 0o040755 or dr["size"] != 0:
            raise SystemExit(die("stock cpio has no 040755 debug_ramdisk/ directory"))
        if ROOTFS_PROP in by:
            raise SystemExit(die("stock cpio already contains %s" % ROOTFS_PROP))

    # minimal-diff edit: patch /init in place, then insert the new files
    new_raw = bytearray(raw)
    new_raw[init["data_off"] + P1_OFF:init["data_off"] + P1_OFF + 4] = P1_NEW
    adds, _ino = additions_for(raw, variant)
    new_cpio = cpio_insert(bytes(new_raw), adds)
    if len(new_cpio) != len(raw) + len(b"".join(adds)):
        raise SystemExit(die("cpio rebuild changed the archive size unexpectedly"))

    comp = gzip.compress(new_cpio, 9, mtime=0)
    if len(comp) > budget or len(comp) > BOOT_RD_SLOT:
        raise SystemExit(die("gzip ramdisk %d B does not fit the %d B slot "
                             "before vbmeta" % (len(comp), budget)))

    out = bytearray(stock)                    # tail (vbmeta .. EOF) untouched
    struct.pack_into("<I", out, 0x0C, len(comp))
    out[p["rd_off"]:vb_off] = comp + bytes(budget - len(comp))

    info = dict(p=p, vb_off=vb_off, budget=budget, comp=comp, cpio=new_cpio,
                variant=variant, added=VARIANT_ADDED[variant],
                ents_old=len(ents) - 1,
                ents_new=len([e for e in cpio_walk(new_cpio)
                              if e["name"] != "TRAILER!!!"]),
                init_off=init["data_off"] + P1_OFF, foot=foot)
    return bytes(out), info


def build_vboot(stock):
    h = vboot_parse(stock)
    if h["version"] != 4 or h["page"] != PAGE or h["header_size"] != 0x850:
        raise SystemExit(die("unexpected vendor_boot header %r" % h))
    if (h["vendor_ramdisk_size"], h["dtb_size"], h["table_size"],
            h["table_num"], h["table_entry_size"], h["bootconfig_size"]) != \
            (35835345, 191577, 108, 1, 108, 0):
        raise SystemExit(die("unexpected vendor_boot geometry %r" % h))
    foot = avb_footer(stock)
    if foot["vbmeta_offset"] != h["bc_off"] or stock[h["bc_off"]:h["bc_off"] + 4] != b"AVB0":
        raise SystemExit(die("embedded vbmeta is not at the bootconfig offset"))
    bad = nonzero_gaps(stock, [(0, PAGE),
                               (h["rd_off"], h["rd_off"] + h["vendor_ramdisk_size"]),
                               (h["dtb_off"], h["dtb_off"] + h["dtb_size"]),
                               (h["table_off"], h["table_off"] + h["table_size"]),
                               (foot["vbmeta_offset"],
                                foot["vbmeta_offset"] + foot["vbmeta_size"]),
                               (len(stock) - 64, len(stock))])
    if bad:
        raise SystemExit(die("stock vendor_boot has nonzero bytes outside the "
                             "known sections %r - refusing to zero them" %
                             [(hex(a), hex(b)) for a, b in bad]))
    ent = vboot_table_entry(stock, h)
    if ent["abs_off"] != h["rd_off"] or ent["size"] != h["vendor_ramdisk_size"]:
        raise SystemExit(die("stock table entry does not point at the ramdisk: %r" % ent))

    blob = stock[h["rd_off"]:h["rd_off"] + h["vendor_ramdisk_size"]]
    if vbe.detect_codec(blob) != "lz4-legacy":
        raise SystemExit(die("stock vendor ramdisk is not lz4-legacy"))
    raw, blocks = lz4_legacy_blocks(blob)
    if sha(raw) != STOCK_VBOOT_CPIO_SHA:
        raise SystemExit(die("stock vendor cpio sha256 mismatch: %s" % sha(raw)))
    ents = list(cpio_walk(raw))
    by = {e["name"].lstrip("./"): e for e in ents}
    if by.get("init", {}).get("mode", 0) & 0o170000 != 0o120000:
        raise SystemExit(die("vendor /init is not the expected symlink"))
    vinit = by.get("system/bin/init")
    if not vinit or vinit["size"] != 2097128 or sha(vinit["data"]) != STOCK_VINIT_SHA:
        raise SystemExit(die("vendor system/bin/init is not the expected binary"))
    if vinit["data"][P2_OFF:P2_OFF + 4] != P2_OLD:
        raise SystemExit(die("stock P2 site mismatch at 0x%X: %s"
                             % (P2_OFF, vinit["data"][P2_OFF:P2_OFF + 4].hex())))

    new_raw = bytearray(raw)
    new_raw[vinit["data_off"] + P2_OFF:vinit["data_off"] + P2_OFF + 4] = P2_NEW
    adds, _ino = additions_for(raw)
    new_cpio = cpio_insert(bytes(new_raw), adds)

    trailer_off = [e for e in ents if e["name"] == "TRAILER!!!"][0]["offset"]

    # Rebuild the legacy stream block by block: stock 8 MiB blocks whose
    # uncompressed content is unchanged are copied verbatim, the block that
    # carries the P2 patch and the (grown) last block are recompressed.  If the
    # stock framing is not the expected 8 MiB one, fall back to a full recompress.
    if not blocks or any(u > LZ4_BLOCK for (_c, _s, u) in blocks):
        new_blob = lz4_legacy_compress(new_cpio)
        reused, recomp = 0, len(new_cpio)
    else:
        stream = bytearray(struct.pack("<I", LZ4_LEGACY_MAGIC))
        reused = recomp = 0
        acc = 0
        for idx, (c_off, c_size, u_len) in enumerate(blocks):
            u_start = acc
            acc += u_len
            if idx == len(blocks) - 1:
                for o in range(u_start, len(new_cpio), LZ4_BLOCK):
                    blk = lz4_block_compress(new_cpio[o:o + LZ4_BLOCK])
                    stream += struct.pack("<I", len(blk)) + blk
                    recomp += len(new_cpio[o:o + LZ4_BLOCK])
            elif new_cpio[u_start:u_start + u_len] == raw[u_start:u_start + u_len]:
                stream += blob[c_off:c_off + 4 + c_size]
                reused += 1
            else:
                blk = lz4_block_compress(new_cpio[u_start:u_start + u_len])
                stream += struct.pack("<I", len(blk)) + blk
                recomp += u_len
        new_blob = bytes(stream)
    rt, _ = lz4_legacy_blocks(new_blob)
    if rt != new_cpio:
        raise SystemExit(die("lz4-legacy round-trip mismatch after recompression"))

    new_rd_off = PAGE
    new_dtb_off = align_up(new_rd_off + len(new_blob))
    new_tab_off = align_up(new_dtb_off + h["dtb_size"])
    new_bc_off = align_up(new_tab_off + h["table_size"])
    new_vb_off = new_bc_off + h["bootconfig_size"]
    vb_size = foot["vbmeta_size"]
    if new_vb_off + vb_size > PART_SIZE:
        raise SystemExit(die("vendor_boot does not fit 64 MiB (needs 0x%X)"
                             % (new_vb_off + vb_size)))

    dtb = stock[h["dtb_off"]:h["dtb_off"] + h["dtb_size"]]
    table = bytearray(stock[h["table_off"]:h["table_off"] + h["table_size"]])
    struct.pack_into("<II", table, 0, len(new_blob), 0)
    old_vb = stock[foot["vbmeta_offset"]:foot["vbmeta_offset"] + vb_size]

    out = bytearray(PART_SIZE)
    hdr = bytearray(stock[:PAGE])
    if any(hdr[h["header_size"]:]):
        raise SystemExit(die("stock vendor_boot header page is not zero-padded"))
    struct.pack_into("<I", hdr, 24, len(new_blob))
    out[:PAGE] = hdr
    out[new_rd_off:new_rd_off + len(new_blob)] = new_blob
    out[new_dtb_off:new_dtb_off + h["dtb_size"]] = dtb
    out[new_tab_off:new_tab_off + h["table_size"]] = table
    if h["bootconfig_size"]:
        out[new_bc_off:new_bc_off + h["bootconfig_size"]] = \
            stock[h["bc_off"]:h["bc_off"] + h["bootconfig_size"]]
    new_vb, vb_info = avb_rehash(old_vb, bytes(out[:new_vb_off]))
    out[new_vb_off:new_vb_off + vb_size] = new_vb
    footer = bytearray(stock[-64:])
    struct.pack_into(">QQ", footer, 12, new_vb_off, new_vb_off)
    out[-64:] = footer

    info = dict(h=h, vb_off=new_vb_off, vb_size=vb_size, vb_info=vb_info,
                foot=foot, blocks=blocks, reused=reused, recomp=recomp,
                ents_old=len(ents) - 1,
                ents_new=len([e for e in cpio_walk(new_cpio)
                              if e["name"] != "TRAILER!!!"]),
                dtb_sha=sha(dtb), new_blob=new_blob, new_cpio=new_cpio,
                dtb_off=new_dtb_off, table_off=new_tab_off,
                init_off=vinit["data_off"] + P2_OFF)
    return bytes(out), info


def cmd_build(args):
    outdir = args.outdir or default_outdir(args.variant)
    os.makedirs(outdir, exist_ok=True)
    stock_boot = read_checked(args.stock_boot, STOCK_BOOT_SHA, "stock boot.img")
    stock_vb = read_checked(args.stock_vboot, STOCK_VBOOT_SHA, "stock vendor_boot.img")

    t0 = time.time()
    boot_img, bi = build_boot(stock_boot, args.variant)
    t1 = time.time()
    vb_img, vi = build_vboot(stock_vb)
    t2 = time.time()

    boot_path = os.path.join(outdir, boot_out_name(args.variant))
    vb_path = os.path.join(outdir, VBOOT_OUT)
    open(boot_path, "wb").write(boot_img)
    open(vb_path, "wb").write(vb_img)

    p, h = bi["p"], vi["h"]
    print("[*] variant %s" % args.variant)
    print("[*] stock boot.img         : %d B sha256 %s" % (len(stock_boot), STOCK_BOOT_SHA))
    print("    P1 @0x%X: %s -> %s (b 0x%X)" % (P1_OFF, P1_OLD.hex(), P1_NEW.hex(), P1_TARGET))
    print("    ramdisk: lz4-legacy %d B -> gzip %d B (slot %d B, slack %d B)"
          % (p["ramdisk_size"], len(bi["comp"]), bi["budget"],
             bi["budget"] - len(bi["comp"])))
    print("    layout: kernel 0x%X +0x1000, ramdisk @0x%X, vbmeta @0x%X (tail verbatim)"
          % (p["kernel_size"], p["rd_off"], bi["vb_off"]))
    print("    cpio entries: %d -> %d   (%.1fs)" % (bi["ents_old"], bi["ents_new"], t1 - t0))
    print("    added entries: %s" % ", ".join(bi["added"]))
    print("[*] stock vendor_boot.img : %d B sha256 %s" % (len(stock_vb), STOCK_VBOOT_SHA))
    print("    P2 @0x%X: %s -> %s (b 0x%X)" % (P2_OFF, P2_OLD.hex(), P2_NEW.hex(), P2_TARGET))
    print("    ramdisk: lz4-legacy %d B -> %d B (%d/%d stock 8 MiB blocks reused "
          "verbatim, %d B recompressed)"
          % (h["vendor_ramdisk_size"], len(vi["new_blob"]), vi["reused"],
             len(vi["blocks"]), vi["recomp"]))
    print("    layout: ramdisk@0x%X dtb@0x%X table@0x%X vbmeta@0x%X size=%d"
          % (PAGE, vi["dtb_off"], vi["table_off"], vi["vb_off"], len(vb_img)))
    print("    cpio entries: %d -> %d   (%.1fs)" % (vi["ents_old"], vi["ents_new"], t2 - t1))
    print("[*] LK in-memory initrd: vendor %d + boot %d + 0x800 = %d <= %d: %s"
          % (len(vi["new_blob"]), len(bi["comp"]), len(vi["new_blob"]) + len(bi["comp"]) + 0x800,
             LK_RAMDISK_LIMIT,
             len(vi["new_blob"]) + len(bi["comp"]) + 0x800 <= LK_RAMDISK_LIMIT))
    print("[+] wrote %s (%d B sha256 %s)" % (boot_path, len(boot_img), sha(boot_img)))
    print("[+] wrote %s (%d B sha256 %s)" % (vb_path, len(vb_img), sha(vb_img)))
    if args.variant == "v7":
        print("[!] v7: flash boot_a ONLY; %s is reference/regression parity "
              "(do NOT flash it)" % VBOOT_OUT)
    print("[*] now run: python3 %s verify --variant %s"
          % (os.path.relpath(__file__, REPO), args.variant))
    return 0


# ==========================================================================
# VERIFY - independent reparsing (no builder offsets are reused)
# ==========================================================================
class Checker:
    def __init__(self):
        self.failed = 0
        self.n = 0

    def __call__(self, name, ok, detail=""):
        self.n += 1
        if not ok:
            self.failed += 1
        print("%s  %s%s" % ("PASS" if ok else "FAIL", name,
                            ("  [%s]" % detail) if detail else ""))
        return ok


def v_boot_hdr(img):
    """Independent boot header parse (literal v3/v4 offsets)."""
    assert img[:8] == b"ANDROID!"
    ks, rs = struct.unpack_from("<II", img, 8)
    osv, hsz = struct.unpack_from("<II", img, 16)
    hv = struct.unpack_from("<I", img, 0x28)[0]
    return ks, rs, osv, hsz, hv, align_up(4096 + ks)


def v_footer(img):
    f = img[-64:]
    assert f[:4] == b"AVBf"
    return struct.unpack_from(">QQQ", f, 12)


def v_vboot_hdr(img):
    assert img[:8] == b"VNDRBOOT"
    ver, page, ka, ra, vrs = struct.unpack_from("<5I", img, 8)
    hs, ds = struct.unpack_from("<II", img, 2096)
    da = struct.unpack_from("<Q", img, 2104)[0]
    ts, tn, te, bcs = struct.unpack_from("<4I", img, 2112)
    return dict(ver=ver, page=page, ka=ka, ra=ra, vrs=vrs, hs=hs, ds=ds, da=da,
                ts=ts, tn=tn, te=te, bcs=bcs,
                cmdline=img[28:28 + 2048], name=img[2080:2096],
                tags=struct.unpack_from("<I", img, 2076)[0])


def v_unc(blob):
    """Decode a ramdisk blob by magic (independent of the builder's choices)."""
    if blob[:2] == b"\x1f\x8b":
        return gzip.decompress(blob), "gzip"
    if blob[:4] == b"\x02\x21\x4c\x18":
        raw, _ = lz4_legacy_blocks(blob)
        return raw, "lz4-legacy"
    raise ValueError("unknown ramdisk codec %s" % blob[:4].hex())


def v_cpio(buf):
    ents, i = [], 0
    while True:
        if buf[i:i + 6] != b"070701":
            raise ValueError("cpio magic expected at 0x%X" % i)
        f = [int(buf[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        name = buf[i + 110:i + 110 + f[11] - 1].decode()
        doff = align_up(i + 110 + f[11], 4)
        e = dict(name=name, ino=f[0], mode=f[1], size=f[6], off=i, doff=doff,
                 data=buf[doff:doff + f[6]],
                 end=align_up(doff + f[6], 4))
        if name == "TRAILER!!!":
            return ents, e
        ents.append(e)
        i = e["end"]


def v_branch_target(data, off):
    """Decode an AArch64 'b' at off -> absolute target (pc + 4*imm26)."""
    w = struct.unpack_from("<I", data, off)[0]
    if w >> 26 != 0b000101:
        return None
    imm = w & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return off + 4 * imm


def cmd_verify(args):
    c = Checker()
    variant = args.variant
    outdir = args.outdir or default_outdir(variant)
    boot_p = os.path.join(outdir, boot_out_name(variant))
    vb_p = os.path.join(outdir, VBOOT_OUT)
    for p in (boot_p, vb_p):
        if not os.path.exists(p):
            raise SystemExit(die("missing %s (run build first)" % p, 2))
    boot = open(boot_p, "rb").read()
    vbo = open(vb_p, "rb").read()
    s_boot = open(args.stock_boot, "rb").read()
    s_vb = open(args.stock_vboot, "rb").read()

    # ---------------------------------------------------------- stock side --
    sks, srs, sosv, shsz, shv, srd = v_boot_hdr(s_boot)
    s_orig, s_vb_off, s_vb_size = v_footer(s_boot)
    s_raw, _ = v_unc(s_boot[srd:srd + srs])
    s_ents, s_tr = v_cpio(s_raw)
    s_map = {e["name"].lstrip("./"): e for e in s_ents}
    sv = v_vboot_hdr(s_vb)
    sv_orig, sv_vb_off, sv_vb_size = v_footer(s_vb)
    sv_raw, _ = v_unc(s_vb[sv["page"]:sv["page"] + sv["vrs"]])
    sv_ents, sv_tr = v_cpio(sv_raw)
    sv_map = {e["name"].lstrip("./"): e for e in sv_ents}
    sv_dtb_off = align_up(sv["page"] + sv["vrs"])
    sv_tab_off = align_up(sv_dtb_off + sv["ds"])
    sv_dtb = s_vb[sv_dtb_off:sv_dtb_off + sv["ds"]]

    # ------------------------------------------------------------- boot ------
    ks, rs, osv, hsz, hv, rd = v_boot_hdr(boot)
    orig, vb_off, vb_size = v_footer(boot)
    c("boot: magic/header v4/header_size 0x630",
      hv == 4 and hsz == 0x630, "hv=%d hsz=0x%X" % (hv, hsz))
    c("boot: kernel_size unchanged", ks == sks == BOOT_KERNEL_SIZE,
      "0x%X" % ks)
    c("boot: ramdisk offset = align(0x1000+kernel)", rd == srd == 0x1378000,
      "0x%X" % rd)
    c("boot: size field == real ramdisk bytes",
      0 < rs <= s_vb_off - rd and boot[0:0x0C] == s_boot[0:0x0C] and
      boot[0x10:BOOT_HDR_SIZE] == s_boot[0x10:BOOT_HDR_SIZE],
      "ramdisk_size=%d" % rs)
    c("boot: kernel bytes byte-identical to stock",
      boot[0x1000:0x1000 + ks] == s_boot[0x1000:0x1000 + ks])
    c("boot: header/vbmeta/EOF tail byte-identical to stock",
      vb_off == s_vb_off and boot[vb_off:] == s_boot[vb_off:] and
      boot[0x10:BOOT_HDR_SIZE] == s_boot[0x10:BOOT_HDR_SIZE],
      "vbmeta@0x%X, footer=0x%X/%d" % (vb_off, orig, vb_size))
    c("boot: AVB0 at vbmeta offset, AVBf in last 64 B",
      boot[vb_off:vb_off + 4] == b"AVB0" and boot[-64:-60] == b"AVBf")
    c("boot: ramdisk end < vbmeta offset", rd + rs < vb_off,
      "end=0x%X < 0x%X, slack=%d" % (rd + rs, vb_off, vb_off - rd - rs))
    c("boot: no nonzero bytes outside header/kernel/ramdisk/vbmeta sections",
      not nonzero_gaps(boot, [(0, BOOT_HDR_SIZE), (0x1000, 0x1000 + ks),
                              (rd, rd + rs), (vb_off, len(boot))]))

    try:
        raw, codec = v_unc(boot[rd:rd + rs])
        ents, tr = v_cpio(raw)
        m = {e["name"].lstrip("./"): e for e in ents}
        c("boot: ramdisk decodes (%s), cpio parses" % codec, True,
          "%d B cpio, %d entries" % (len(raw), len(ents)))
        c("boot: cpio entry count == stock + %d" % len(VARIANT_ADDED[variant]),
          len(ents) == len(s_ents) + len(VARIANT_ADDED[variant]),
          "%d -> %d (variant %s)" % (len(s_ents), len(ents), variant))
        ini_doff = s_map["init"]["doff"]
        pref = [i for i in range(s_tr["off"]) if raw[i] != s_raw[i]]
        shift = len(raw) - len(s_raw)
        c("boot: cpio prefix is stock bytes except the 3 init bytes",
          len(pref) == 3 and
          all(ini_doff + P1_OFF <= i < ini_doff + P1_OFF + 4 for i in pref) and
          tr["off"] == s_tr["off"] + shift and shift > 0 and shift % 4 == 0 and
          raw[tr["off"]:] == s_raw[s_tr["off"]:],
          "trailer@0x%X (stock 0x%X, shift %d) diffs=%r"
          % (tr["off"], s_tr["off"], shift, [hex(i) for i in pref]))
        c("boot: /init is a regular file of 3143536 B",
          "init" in m and m["init"]["size"] == 3143536 and
          m["init"]["mode"] & 0o170000 == 0o100000)
        ini = m["init"]["data"]
        c("boot: P1 bytes at 0x%X are 24000014" % P1_OFF,
          ini[P1_OFF:P1_OFF + 4] == P1_NEW, ini[P1_OFF:P1_OFF + 4].hex())
        # boot /init is ET_EXEC with p_vaddr 0x200000, so the file offset
        # 0xF6D14 maps to VA 0x2F6D14: the same instruction, two names.
        c("boot: P1 decodes to 'b 0x%X' (VA 0x%X)" % (P1_TARGET - 0x200000, P1_TARGET),
          v_branch_target(ini, P1_OFF) == P1_TARGET - 0x200000,
          "file target=0x%X" % (v_branch_target(ini, P1_OFF) or 0))
        sini = s_map["init"]["data"]
        diffs = [i for i in range(len(sini)) if sini[i] != ini[i]]
        c("boot: /init differs from stock only in the 4-byte patch site",
          len(sini) == len(ini) and all(P1_OFF <= i < P1_OFF + 4 for i in diffs)
          and len(diffs) == 3, "bytes=%s" % [hex(i) for i in diffs])
        c("boot: /force_debuggable present, empty, 0100644",
          "force_debuggable" in m and m["force_debuggable"]["size"] == 0 and
          m["force_debuggable"]["mode"] == 0o100644,
          "mode=0o%o" % m.get("force_debuggable", {}).get("mode", 0))
        c("boot: /adb_debug.prop content == expected %d B" % len(ADB_PROPS),
          m["adb_debug.prop"]["data"] == ADB_PROPS,
          sha(m.get("adb_debug.prop", {}).get("data", b""))[:16])
        missing = [n for n in s_map if n not in m]
        changed = [n for n in s_map if n in m and n != "init" and
                   (s_map[n]["data"] != m[n]["data"] or
                    s_map[n]["mode"] != m[n]["mode"] or
                    s_map[n]["size"] != m[n]["size"])]
        c("boot: every stock entry preserved (no /prop.default, build.prop intact)",
          not missing and not changed and
          set(m) - set(s_map) == set(VARIANT_ADDED[variant]),
          "missing=%r changed=%r added=%r" %
          (missing, changed, sorted(set(m) - set(s_map))))

        if variant == "v7":
            # ---- R4c: rootfs copy under the /debug_ramdisk tmpfs mount ----
            dr = m.get("debug_ramdisk")
            sdr = s_map.get("debug_ramdisk")
            c("boot(v7): debug_ramdisk/ is still a 040755 directory",
              dr is not None and sdr is not None and
              dr["mode"] == 0o040755 and dr["size"] == 0 and
              dr["data"] == b"" and dr["ino"] == sdr["ino"] == 300000,
              "mode=0o%o ino=%s size=%s" %
              (dr["mode"] if dr else 0,
               dr["ino"] if dr else "?", dr["size"] if dr else "?"))
            rp = m.get(ROOTFS_PROP)
            c("boot(v7): %s is a 0100644 regular file of %d B" %
              (ROOTFS_PROP, len(ADB_PROPS)),
              rp is not None and rp["mode"] == 0o100644 and
              rp["mode"] & 0o170000 == 0o100000 and rp["size"] == len(ADB_PROPS),
              "mode=0o%o size=%s" % (rp["mode"] if rp else 0,
                                     rp["size"] if rp else "?"))
            c("boot(v7): %s bytes == /adb_debug.prop (byte-for-byte)" % ROOTFS_PROP,
              rp is not None and "adb_debug.prop" in m and
              rp["data"] == m["adb_debug.prop"]["data"] == ADB_PROPS,
              "%d B sha256 %s" % (len(rp["data"]) if rp else 0,
                                  sha(rp["data"] if rp else b"")[:16]))
            stock_max_ino = max([e["ino"] for e in s_ents] + [s_tr["ino"]])
            tail3 = ents[-3:]
            c("boot(v7): cpio delta vs stock is exactly the 3 expected entries",
              sorted(set(m) - set(s_map)) == sorted(ADDED_V7) and
              [e["name"] for e in tail3] == list(ADDED_V7) and
              [e["ino"] for e in tail3] == [stock_max_ino + 1, stock_max_ino + 2,
                                            stock_max_ino + 3] and
              all(sum(1 for e in ents if e["name"] == n) == 1
                  for n in ADDED_V7),
              "added=%r inodes=%r" % (sorted(set(m) - set(s_map)),
                                      [e["ino"] for e in tail3]))
    except Exception as e:
        c("boot: ramdisk decodes (%s)" % type(e).__name__, False, str(e))

    # ------------------------------------------------------- vendor_boot -----
    h = v_vboot_hdr(vbo)
    v_orig, v_vb_off, v_vb_size = v_footer(vbo)
    c("vendor_boot: file size == 64 MiB and <= partition",
      len(vbo) == PART_SIZE <= 64 << 20, "%d B" % len(vbo))
    c("vendor_boot: still v4/page 4096/one PLATFORM fragment",
      h["ver"] == 4 and h["page"] == 4096 and h["tn"] == 1 and h["te"] == 108 and
      h["ts"] == 108 and h["bcs"] == 0)
    c("vendor_boot: kernel/tags/dtb addrs, cmdline and name unchanged",
      (h["ka"], h["ra"], h["da"], h["tags"], h["cmdline"], h["name"], h["ds"]) ==
      (sv["ka"], sv["ra"], sv["da"], sv["tags"], sv["cmdline"], sv["name"], sv["ds"]))
    c("vendor_boot: header page identical except vendor_ramdisk_size@24",
      vbo[:24] == s_vb[:24] and vbo[28:0x1000] == s_vb[28:0x1000] and
      h["hs"] == sv["hs"], "hdr_size=0x%X" % h["hs"])

    dtb_off = align_up(4096 + h["vrs"])
    tab_off = align_up(dtb_off + h["ds"])
    bc_off = align_up(tab_off + h["ts"])
    exp_vb = bc_off + h["bcs"]
    c("vendor_boot: ramdisk@0x1000, dtb/table/vbmeta page-aligned in order",
      dtb_off == align_up(0x1000 + h["vrs"]) and
      tab_off == align_up(dtb_off + h["ds"]) and
      bc_off == align_up(tab_off + h["ts"]) and
      all(x % 4096 == 0 for x in (dtb_off, tab_off, bc_off)) and 0 < h["vrs"],
      "dtb@0x%X table@0x%X vbmeta@0x%X" % (dtb_off, tab_off, exp_vb))
    c("vendor_boot: table entry points exactly at ramdisk, size == header size",
      struct.unpack_from("<II", vbo, tab_off)[:2] == (h["vrs"], 0) and
      tab_off + h["ts"] <= exp_vb,
      "size=%d off=%d" % struct.unpack_from("<II", vbo, tab_off)[:2])
    c("vendor_boot: table type/name/board_id unchanged (PLATFORM, all-zero board)",
      struct.unpack_from("<I", vbo, tab_off + 8)[0] == 1 and
      vbo[tab_off + 8:tab_off + 108] == s_vb[sv_tab_off + 8:sv_tab_off + 108] and
      struct.unpack_from("<16I", vbo, tab_off + 44) == (0,) * 16)
    c("vendor_boot: dtb bytes byte-identical to stock",
      vbo[dtb_off:dtb_off + h["ds"]] == sv_dtb,
      "sha256 %s" % sha(vbo[dtb_off:dtb_off + h["ds"]])[:16])
    c("vendor_boot: gap between ramdisk and dtb is zero padding",
      not any(vbo[0x1000 + h["vrs"]:dtb_off]))
    c("vendor_boot: no nonzero bytes outside header/ramdisk/dtb/table/vbmeta",
      not nonzero_gaps(vbo, [(0, PAGE), (0x1000, 0x1000 + h["vrs"]),
                             (dtb_off, dtb_off + h["ds"]),
                             (tab_off, tab_off + h["ts"]),
                             (exp_vb, exp_vb + v_vb_size),
                             (len(vbo) - 64, len(vbo))]))
    try:
        vbm = vbo[exp_vb:exp_vb + v_vb_size]
        alg, vbinfo = avb_parse_hash(vbm)
        expect = hashlib.sha256(vbinfo["salt"] + vbo[:exp_vb]).digest()
        stored = vbm[vbinfo["digest_off"]:vbinfo["digest_off"] + 32]
        c("vendor_boot: embedded vbmeta is unsigned (alg NONE) and self-consistent",
          alg == 0 and vbinfo["image_size"] == exp_vb and
          vbinfo["digest_len"] == 32 and stored == expect,
          "name=%s image_size=%d digest=%s" %
          (vbinfo["name"].decode(), vbinfo["image_size"], expect.hex()[:16]))
    except Exception as e:
        c("vendor_boot: embedded vbmeta hash descriptor rehashed", False, str(e))
    c("vendor_boot: AVB footer -> same vbmeta offset, size %d, partition end" % v_vb_size,
      v_orig == v_vb_off == exp_vb and v_vb_size == sv_vb_size and
      vbo[exp_vb:exp_vb + 4] == b"AVB0", "orig=0x%X off=0x%X" % (v_orig, v_vb_off))

    try:
        vraw, vcodec = v_unc(vbo[0x1000:0x1000 + h["vrs"]])
        vents, vtr = v_cpio(vraw)
        vm = {e["name"].lstrip("./"): e for e in vents}
        c("vendor_boot: ramdisk decodes (%s), cpio parses" % vcodec, True,
          "%d B cpio, %d entries" % (len(vraw), len(vents)))
        c("vendor_boot: cpio entry count == stock + 2",
          len(vents) == len(sv_ents) + 2,
          "%d -> %d" % (len(sv_ents), len(vents)))
        vi_doff = sv_map["system/bin/init"]["doff"]
        vpref = [i for i in range(sv_tr["off"]) if vraw[i] != sv_raw[i]]
        vshift = len(vraw) - len(sv_raw)
        c("vendor_boot: cpio prefix is stock bytes except the 3 init bytes",
          len(vpref) == 3 and
          all(vi_doff + P2_OFF <= i < vi_doff + P2_OFF + 4 for i in vpref) and
          vtr["off"] == sv_tr["off"] + vshift and vshift > 0 and vshift % 4 == 0 and
          vraw[vtr["off"]:] == sv_raw[sv_tr["off"]:],
          "trailer@0x%X (stock 0x%X, shift %d) diffs=%r"
          % (vtr["off"], sv_tr["off"], vshift, [hex(i) for i in vpref]))
        c("vendor_boot: /init is still the untouched symlink -> /system/bin/init",
          vm["init"]["mode"] & 0o170000 == 0o120000 and
          vm["init"]["data"] == b"/system/bin/init",
          "mode=0o%o body=%r" % (vm["init"]["mode"], vm["init"]["data"]))
        vi = vm["system/bin/init"]["data"]
        c("vendor_boot: P2 bytes at 0x%X are 29000014" % P2_OFF,
          vi[P2_OFF:P2_OFF + 4] == P2_NEW, vi[P2_OFF:P2_OFF + 4].hex())
        c("vendor_boot: P2 decodes to 'b 0x%X'" % P2_TARGET,
          v_branch_target(vi, P2_OFF) == P2_TARGET,
          "target=0x%X" % (v_branch_target(vi, P2_OFF) or 0))
        si = sv_map["system/bin/init"]["data"]
        vdiffs = [i for i in range(len(si)) if si[i] != vi[i]]
        c("vendor_boot: system/bin/init differs only in the 4-byte patch site",
          len(si) == len(vi) and len(vdiffs) == 3 and
          all(P2_OFF <= i < P2_OFF + 4 for i in vdiffs),
          "bytes=%s" % [hex(i) for i in vdiffs])
        c("vendor_boot: /force_debuggable + /adb_debug.prop at the cpio root",
          vm.get("force_debuggable", {}).get("size") == 0 and
          vm.get("force_debuggable", {}).get("mode") == 0o100644 and
          vm.get("adb_debug.prop", {}).get("data") == ADB_PROPS,
          "props=%d B" % len(vm.get("adb_debug.prop", {}).get("data", b"")))
        vmissing = [n for n in sv_map if n not in vm]
        vchanged = [n for n in sv_map if n in vm and n != "system/bin/init" and
                    (sv_map[n]["data"] != vm[n]["data"] or
                     sv_map[n]["mode"] != vm[n]["mode"] or
                     sv_map[n]["size"] != vm[n]["size"])]
        c("vendor_boot: every stock entry preserved; only the 2 files added",
          not vmissing and not vchanged and
          set(vm) - set(sv_map) == set(ADDED),
          "missing=%r changed=%r added=%r" %
          (vmissing, vchanged[:4], sorted(set(vm) - set(sv_map))))
    except Exception as e:
        c("vendor_boot: ramdisk decodes (%s)" % type(e).__name__, False, str(e))

    # ---------------------------- external parser (vendor_boot_extract.py) ----
    ex = os.path.join(HERE, "vendor_boot_extract.py")
    info = subprocess.run([sys.executable, ex, "--info", vb_p],
                          capture_output=True, text=True)
    c("vendor_boot_extract.py --info exits 0", info.returncode == 0,
      "rc=%d" % info.returncode)
    lst = subprocess.run([sys.executable, ex, "--list", vb_p],
                         capture_output=True, text=True)
    names = [ln.strip().split()[0] for ln in lst.stdout.splitlines()
             if ln.strip().startswith(("force_debuggable", "adb_debug.prop"))]
    c("vendor_boot_extract.py --list exits 0", lst.returncode == 0,
      "rc=%d" % lst.returncode)
    c("vendor_boot_extract.py --list shows the 2 added entries and 917 entries",
      set(names) >= set(ADDED) and "cpio entries: 917" in lst.stdout,
      "%r, %s" % (names[:4], "917 found" if "cpio entries: 917" in lst.stdout
                 else "917 MISSING"))

    print()
    print("%d checks, %d failed -> %s" % (c.n, c.failed,
                                          "PASS" if c.failed == 0 else "FAIL"))
    return 0 if c.failed == 0 else 1


# ==========================================================================
# FLASH - gated, real DA session (never runs without V6_FLASH_GO=1)
# ==========================================================================
def cmd_flash(args):
    variant = args.variant
    go_env = "V7_FLASH_GO" if variant == "v7" else "V6_FLASH_GO"
    go = os.environ.get(go_env, "0") == "1"
    outdir = args.outdir or default_outdir(variant)
    boot_p = os.path.join(outdir, boot_out_name(variant))
    vb_p = os.path.join(outdir, VBOOT_OUT)
    for p in (boot_p, vb_p):
        if not os.path.exists(p):
            raise SystemExit(die("missing %s" % p, 2))
    print("[*] self-verify before any write:")
    rc = cmd_verify(args)
    if rc != 0:
        raise SystemExit(die("verify failed - refusing to flash"))
    # v7 touches boot_a ONLY: the R4c rootfs prop makes vendor_boot unnecessary,
    # so vendor_boot_v6.img is never written there.
    plan = [("boot_a", boot_p)]
    if variant == "v6":
        plan.append(("vendor_boot_a", vb_p))
    for part, path in plan:
        print("[*] plan: write %s (%d B sha256 %s) -> %s" %
              (path, os.path.getsize(path), sha(open(path, "rb").read()), part))
    if not go:
        print("[dryrun] no device touched. Re-run with %s=1 to write" % go_env)
        return 0

    sys.path.insert(0, REPO)
    import argparse as _ap
    import mtk as mtk_cli
    parser = _ap.ArgumentParser(parents=[mtk_cli.create_base_parser()],
                                description=mtk_cli.INFO)
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("custom")
    margs = parser.parse_args(args.extra + ["custom"])
    from mtkclient.Library.mtk_main import Main
    mtk = Main(margs).run(parser)
    if mtk is None:
        return die("connect failed (preloader 22d9:0006 not caught)")
    loader = mtk.daloader
    xmlft = loader.xmlft
    _, gpt = loader.get_gpt(parttype="user")
    ss = gpt.sectorsize

    def rd(addr, length):
        d = loader.readflash(addr=addr, length=length, filename="",
                             parttype="user", display=False)
        d = d[0] if isinstance(d, tuple) else d
        return bytes(d[:length]) if d and not isinstance(d, bool) else b""

    ts = time.strftime("%Y%m%d_%H%M%S")
    done = []
    for part, path in plan:
        p = next((x for x in gpt.partentries if x.name.lower() == part), None)
        if p is None:
            return die("no %s in GPT" % part)
        base, full = p.sector * ss, p.sectors * ss
        blob = open(path, "rb").read()
        if len(blob) > full:
            return die("%s image (%d B) larger than the partition (%d B)"
                       % (part, len(blob), full))
        bk = os.path.join(outdir, "stock_%s_%s.img" % (part, ts))
        print("[!] %s: backing up 0x%X B -> %s" % (part, full, bk))
        if not loader.readflash(addr=base, length=full, filename=bk,
                                parttype="user", display=False):
            return die("backup of %s failed - aborting before any write" % part)
        cur = open(bk, "rb").read()
        print("[+] backup %s: %d B sha256 %s" % (part, len(cur), sha(cur)))
        print("[!] writing %s (%d B) ..." % (part, len(blob)))
        ok, msg = xmlft.seccfg_write_partition(p, blob)
        print("[*] write: %r %r" % (ok, msg))
        if not ok:
            return die("write of %s failed" % part)
        time.sleep(1.0)
        rb = rd(base, len(blob))
        same = rb == blob
        print("[*] readback %s: %d B identical=%s md5=%s" %
              (part, len(rb), same, hashlib.md5(rb).hexdigest() if rb else "?"))
        if not same:
            print("[!] READBACK MISMATCH - restoring %s from %s" % (part, bk))
            xmlft.seccfg_write_partition(p, cur)
            return die("%s readback mismatch (restore attempted)" % part)
        done.append((part, bk))
    print("\n[+] %s image(s) written and read back:" %
          ("v7 boot" if variant == "v7" else "v6 pair"))
    for part, bk in done:
        print("    %-14s stock backup: %s" % (part, bk))
    print("[*] unplug, power off ~10 s, boot WITHOUT the cable, then plug in.")
    print("[*] rollback (stock copies just written):")
    for part, bk in done:
        print("      python3 mtk.py --vid 0x22d9 --pid 0x0006 w %s %s" % (part, bk))
    return 0


# --------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(description="v6/v7 dual-ramdisk builder/verifier")
    ap.add_argument("cmd", choices=("build", "verify", "flash"))
    ap.add_argument("--variant", choices=("v6", "v7"), default=DEFAULT_VARIANT,
                    help="v7 (default) = v6 boot + debug_ramdisk/adb_debug.prop; "
                         "v6 = historical, byte-reproducible pair")
    ap.add_argument("-o", "--outdir", default=None,
                    help="output dir (default /tmp/v7 for v7, /tmp/v6 for v6)")
    ap.add_argument("--stock-boot", default=STOCK_BOOT)
    ap.add_argument("--stock-vboot", default=STOCK_VBOOT)
    a, extra = ap.parse_known_args(argv)   # extras pass through to mtk (flash)
    a.extra = extra
    try:
        if a.cmd == "build":
            return cmd_build(a)
        if a.cmd == "verify":
            return cmd_verify(a)
        return cmd_flash(a)
    except SystemExit:
        raise
    except FileNotFoundError as e:
        return die(str(e), 2)
    except ValueError as e:
        return die(str(e))


if __name__ == "__main__":
    sys.exit(main())
