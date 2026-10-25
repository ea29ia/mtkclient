#!/usr/bin/env python3
"""build_v7_from_dump.py - assemble boot_v7.img from a FRESH boot_a dump.

Target: RMX3630 / MT6789 (Oplus), branch `oplus-mt6789-unlock`.
Spec:   obsolete route - the boot_a ramdisk is never unpacked, see
        docs/notes/reverse/re-v14-adb-works-2026-10-25.md
Why:    docs/notes/reverse/re-v7-rootfs-prop.md   (route R4c, historical)

v7 = the v5 ramdisk untouched, plus ONE extra cpio record
`debug_ramdisk/adb_debug.prop` whose payload is byte-identical to the
existing `/adb_debug.prop`.  The file sits *under* the /debug_ramdisk
tmpfs, so PropertyInit() finds it in both branches of the
`env && IsDeviceUnlocked()` gate.  Nothing else changes: kernel and the
embedded vbmeta/footer stay byte-for-byte as in the dump.

Nothing here is hardcoded to the old firmware: geometry, the ramdisk
codec, the AVB0 location and the vbmeta budget are all read from the
dump, so the same script works for the real device dump.

Usage:
  build   (default):  build_v7_from_dump.py DUMP OUT
  verify           :  build_v7_from_dump.py --verify DUMP OUT
  inspect          :  build_v7_from_dump.py --info DUMP

Exit codes: 0 = ok / all checks PASS, 1 = check failed, 2 = bad input,
3 = dump is not v5 (do NOT guess, report back).

Pure python3 + stdlib.
"""

import gzip
import hashlib
import struct
import sys

PAGE = 0x1000
PART_SIZE = 64 * 1024 * 1024          # boot_a partition size on this device
ROOTFS_PROP = "debug_ramdisk/adb_debug.prop"
P1_OFF = 0xF6D14                       # inside /init (second-stage gate patch)
P1_PATCHED = b"\x24\x00\x00\x14"       # v5: `b ...` (already applied)
P1_STOCK = b"\x93\x04\x00\x36"         # stock: `tbz w19,#0,...`
ADB_PROPS_EXPECTED_SIZE = 81           # v5 /adb_debug.prop is exactly 81 B
CPIO_MAGICS = (b"070701", b"070702")


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def sha256(b):
    return hashlib.sha256(b).hexdigest()


def md5(b):
    return hashlib.md5(b).hexdigest()


def align_up(x, a=4):
    return (x + a - 1) // a * a


def die(msg, rc=2):
    print("ERROR: %s" % msg, file=sys.stderr)
    return rc


def stop(msg):
    print("STOP: %s" % msg, file=sys.stderr)
    return 3


# --------------------------------------------------------------------------
# cpio newc (pure python)
# --------------------------------------------------------------------------
def cpio_walk(buf):
    """Yield dicts for every entry, TRAILER!!! last (newc)."""
    i, n = 0, len(buf)
    if not buf:
        raise ValueError("empty cpio")
    while i + 110 <= n:
        if buf[i:i + 6] not in CPIO_MAGICS:
            raise ValueError("bad cpio magic at 0x%X" % i)
        f = [int(buf[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
        ino, mode, namesize, filesize = f[0], f[1], f[11], f[6]
        name = buf[i + 110:i + 110 + namesize - 1].decode("utf-8", "replace")
        data_off = align_up(i + 110 + namesize, 4)
        ent = dict(name=name, ino=ino, mode=mode, uid=f[2], gid=f[3],
                   nlink=f[4], mtime=f[5], size=filesize, offset=i,
                   data_off=data_off,
                   data=buf[data_off:data_off + filesize],
                   end=align_up(data_off + filesize, 4))
        yield ent
        if name == "TRAILER!!!":
            return
        i = ent["end"]
        if i <= ent["offset"]:
            raise ValueError("cpio walk did not advance at 0x%X" % ent["offset"])
    raise ValueError("cpio has no TRAILER!!!")


def cpio_entry(name, data, mode, ino, uid=0, gid=0, nlink=1, mtime=0):
    """Serialise one newc entry."""
    nb = name.encode()
    fields = (ino, mode, uid, gid, nlink, mtime, len(data),
              0, 0, 0, 0, len(nb) + 1, 0)
    out = bytearray(b"070701" + b"".join(b"%08X" % x for x in fields) + nb + b"\x00")
    out += b"\x00" * ((-len(out)) % 4)
    out += data
    out += b"\x00" * ((-len(out)) % 4)
    return bytes(out)


def cpio_insert_before_trailer(raw, additions):
    """Insert raw entry blobs right before TRAILER!!! (stock bytes untouched)."""
    trailers = [e for e in cpio_walk(raw) if e["name"] == "TRAILER!!!"]
    if len(trailers) != 1:
        raise ValueError("expected exactly one cpio trailer, got %d" % len(trailers))
    off = trailers[0]["offset"]
    return raw[:off] + b"".join(additions) + raw[off:]


# --------------------------------------------------------------------------
# boot image header / ramdisk
# --------------------------------------------------------------------------
def boot_parse(img):
    if img[:8] != b"ANDROID!":
        raise ValueError("boot: bad magic %r (not an Android boot image)"
                         % img[:8])
    kernel_size, ramdisk_size = struct.unpack_from("<II", img, 8)
    os_version, header_size = struct.unpack_from("<II", img, 16)
    header_version = struct.unpack_from("<I", img, 0x28)[0]
    return dict(magic="ANDROID!", kernel_size=kernel_size,
                ramdisk_size=ramdisk_size, os_version=os_version,
                header_size=header_size, header_version=header_version,
                page=PAGE, rd_off=align_up(PAGE + kernel_size, PAGE),
                file_size=len(img))


def detect_codec(blob):
    if blob[:2] == b"\x1f\x8b":
        return "gzip"
    if blob[:4] == b"\x02\x21\x4c\x18":
        return "lz4-legacy"
    return "unknown:%s" % blob[:4].hex()


def unc_ramdisk(blob):
    codec = detect_codec(blob)
    if codec != "gzip":
        raise ValueError(codec)
    return gzip.decompress(blob)


def avb_footer(img):
    """Footer is the last 64 bytes: AVBf, version, vbmeta_offset, vbmeta_size."""
    f = img[-64:]
    if f[:4] != b"AVBf":
        return None
    ver, off, size = struct.unpack_from(">QQQ", f, 4)
    return dict(version=ver, vbmeta_offset=off, vbmeta_size=size,
                original_image_size=struct.unpack_from(">Q", f, 28)[0])


def find_vbmeta(img, rd_off):
    """Locate the embedded vbmeta page: footer first, then page scan."""
    foot = avb_footer(img)
    if foot and img[foot["vbmeta_offset"]:foot["vbmeta_offset"] + 4] == b"AVB0":
        return foot["vbmeta_offset"], "footer", foot
    for off in range(align_up(rd_off, PAGE), len(img) - 4, PAGE):
        if img[off:off + 4] == b"AVB0":
            return off, "scan", foot
    raise ValueError("no AVB0 page found at/after rd_off 0x%X" % rd_off)


def nonzero_ranges(data, keep):
    """[start,end) ranges outside `keep` that contain nonzero bytes."""
    cur, out = 0, []
    for a, b in sorted(keep):
        if a > cur and any(data[cur:a]):
            out.append((cur, a))
        cur = max(cur, b)
    if cur < len(data) and any(data[cur:]):
        out.append((cur, len(data)))
    return out


# --------------------------------------------------------------------------
# v5 preconditions (the ONLY base this spec is proven on)
# --------------------------------------------------------------------------
def check_v5(raw):
    """Return (init_entry, adb_props_data, debug_ramdisk_entry, entries).

    Raises ValueError with a human message when the dump is not v5.
    """
    ents = list(cpio_walk(raw))
    by = {e["name"].lstrip("./"): e for e in ents if e["name"] != "TRAILER!!!"}
    init = by.get("init")
    if init is None:
        raise ValueError("cpio has no /init")
    site = init["data"][P1_OFF:P1_OFF + 4]
    if site == P1_STOCK:
        raise ValueError(
            "dump is STOCK, not v5: /init@0x%X = %s (P1 not applied). "
            "v7 must be built from the currently flashed v5 dump."
            % (P1_OFF, site.hex()))
    if site != P1_PATCHED:
        raise ValueError("unexpected bytes at /init@0x%X: %s (neither stock "
                         "nor v5)" % (P1_OFF, site.hex()))
    if "force_debuggable" not in by:
        raise ValueError("v5 marker /force_debuggable missing in cpio")
    props = by.get("adb_debug.prop")
    if props is None:
        raise ValueError("v5 marker /adb_debug.prop missing in cpio")
    if props["size"] != ADB_PROPS_EXPECTED_SIZE:
        raise ValueError("/adb_debug.prop is %d B, expected %d B"
                         % (props["size"], ADB_PROPS_EXPECTED_SIZE))
    dr = by.get("debug_ramdisk")
    if dr is None or dr["mode"] != 0o040755 or dr["size"] != 0:
        raise ValueError("cpio has no `debug_ramdisk` directory with mode 040755")
    if ROOTFS_PROP in by:
        raise ValueError("%s already present - dump is v7, not v5" % ROOTFS_PROP)
    return init, props["data"], dr, ents


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------
def build(dump_path, out_path, allow_size=False):
    dump = open(dump_path, "rb").read()
    try:
        p = boot_parse(dump)
    except ValueError as e:
        raise SystemExit(die("%s: %s" % (dump_path, e), 2))
    if p["header_version"] != 4:
        raise SystemExit(die("dump header_version %d, expected 4"
                             % p["header_version"]))
    if not allow_size and p["file_size"] != PART_SIZE:
        raise SystemExit(die("dump is %d B, expected the full partition (%d B). "
                             "A partial dump cannot be flashed safely."
                             % (p["file_size"], PART_SIZE)))
    rd_off = p["rd_off"]
    blob = dump[rd_off:rd_off + p["ramdisk_size"]]
    codec = detect_codec(blob)
    if codec != "gzip":
        raise SystemExit(stop("ramdisk codec is %r, spec assumes the v5 gzip "
                              "ramdisk. Report the dump back instead of guessing."
                              % codec))
    raw = gzip.decompress(blob)
    try:
        init, props, dr, ents = check_v5(raw)
    except ValueError as e:
        raise SystemExit(stop(str(e)))

    try:
        vb_off, how, foot = find_vbmeta(dump, rd_off)
    except ValueError as e:
        raise SystemExit(die("%s: %s" % (dump_path, e), 2))
    if vb_off <= rd_off + p["ramdisk_size"]:
        raise SystemExit(die("vbmeta @0x%X overlaps the ramdisk region" % vb_off))
    slot = vb_off - rd_off

    # nothing may be lost: outside header/kernel/ramdisk/vbmeta there must be
    # no nonzero bytes we would overwrite with zeros
    bad = nonzero_ranges(dump, [(0, PAGE), (PAGE, PAGE + p["kernel_size"]),
                                (rd_off, rd_off + p["ramdisk_size"]),
                                (vb_off, len(dump))])
    if bad:
        print("WARN: nonzero bytes in the unused slot tail %s will be zeroed"
              % [(hex(a), hex(b)) for a, b in bad], file=sys.stderr)

    ino = max(e["ino"] for e in ents) + 1
    add = cpio_entry(ROOTFS_PROP, props, 0o100644, ino)
    new_cpio = cpio_insert_before_trailer(raw, [add])
    if len(new_cpio) != len(raw) + len(add):
        raise SystemExit(die("cpio insert changed the archive size unexpectedly "
                             "(stock %d + entry %d != %d)"
                             % (len(raw), len(add), len(new_cpio))))

    comp = gzip.compress(new_cpio, 9, mtime=0)
    if len(comp) > slot:
        raise SystemExit(die("gzip ramdisk %d B does not fit the %d B slot "
                             "before vbmeta @0x%X" % (len(comp), slot, vb_off)))

    out = bytearray(dump)
    struct.pack_into("<I", out, 0x0C, len(comp))   # ramdisk_size - only hdr edit
    out[rd_off:vb_off] = comp + bytes(slot - len(comp))

    if out_path:
        with open(out_path, "wb") as fh:
            fh.write(out)
    info = dict(p=p, rd_off=rd_off, vb_off=vb_off, vbmeta_how=how, foot=foot,
                slot=slot, codec=codec, stock_cpio=raw, cpio=new_cpio,
                comp=comp, add=add, props=props, ino=ino,
                stock_entries=len(ents) - 1,
                entries=len([e for e in cpio_walk(new_cpio)
                             if e["name"] != "TRAILER!!!"]))
    return bytes(out), info


def print_build_report(dump_path, dump, out, info):
    p = info["p"]
    print("stock dump : %s" % dump_path)
    print("            size %d  md5 %s" % (p["file_size"], md5(dump)))
    print("            sha256 %s" % sha256(dump))
    print("header     : v%d, header_size 0x%X" % (p["header_version"],
                                                  p["header_size"]))
    print("kernel_size: 0x%X (%d)" % (p["kernel_size"], p["kernel_size"]))
    print("ramdisk    : old %d B -> new %d B (%s)"
          % (p["ramdisk_size"], len(info["comp"]), info["codec"]))
    print("rd_off     : 0x%X" % info["rd_off"])
    print("vbmeta_off : 0x%X  (via %s)" % (info["vb_off"], info["vbmeta_how"]))
    print("slot       : 0x%X (%d B), used %d B, headroom %d B"
          % (info["slot"], info["slot"], len(info["comp"]),
             info["slot"] - len(info["comp"])))
    print("cpio       : %d records -> %d (+1: %s, ino %d, %d B)"
          % (info["stock_entries"], info["entries"], ROOTFS_PROP,
             info["ino"], len(info["props"])))
    print("output     : %s" % (info.get("out_path") or "(not written)"))
    print("            size %d  md5 %s" % (len(out), md5(out)))
    print("            sha256 %s" % sha256(out))
    print()
    # paste-ready acceptance block (handoff section 10)
    print("STOCK_DUMP_MD5=%s" % md5(dump))
    print("STOCK_DUMP_SHA256=%s" % sha256(dump))
    print("KERNEL_SIZE=%d" % p["kernel_size"])
    print("RD_OFF=0x%X" % info["rd_off"])
    print("VBMETA_OFF=0x%X" % info["vb_off"])
    print("SLOT=0x%X" % info["slot"])
    print("V7_MD5=%s" % md5(out))
    print("V7_SHA256=%s" % sha256(out))


# --------------------------------------------------------------------------
# verify (independent re-parse of the written file)
# --------------------------------------------------------------------------
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

    def report(self):
        verdict = "PASS" if self.failed == 0 else "FAIL"
        print("\n%d/%d checks %s" % (self.n - self.failed, self.n, verdict))
        return 0 if self.failed == 0 else 1


def verify(dump_path, out_path, allow_size=False):
    if not out_path:
        raise SystemExit(die("--verify needs DUMP and OUT", 2))
    dump = open(dump_path, "rb").read()
    out = open(out_path, "rb").read()
    c = Checker()

    c("output size == 0x4000000 (64 MiB)", len(out) == PART_SIZE, "%d" % len(out))
    if allow_size:
        c("dump size == output size", len(dump) == len(out), "%d" % len(dump))

    try:
        d = boot_parse(dump)
        o = boot_parse(out)
    except ValueError as e:
        raise SystemExit(die("boot header: %s" % e, 2))
    c("output magic ANDROID! + header v4",
      o["magic"] == "ANDROID!" and o["header_version"] == 4,
      "v%d" % o["header_version"])
    c("header unchanged except ramdisk_size@0x0C",
      out[:0x0C] + out[0x10:PAGE] == dump[:0x0C] + dump[0x10:PAGE])

    rd_off = d["rd_off"]
    c("rd_off identical and page aligned",
      o["rd_off"] == rd_off and rd_off % PAGE == 0, "0x%X" % rd_off)
    c("kernel_size identical", o["kernel_size"] == d["kernel_size"],
      "0x%X" % d["kernel_size"])
    c("kernel region byte-identical",
      out[PAGE:rd_off] == dump[PAGE:rd_off], "%d B" % (rd_off - PAGE))

    blob = out[rd_off:rd_off + o["ramdisk_size"]]
    c("ramdisk_size == written gzip length",
      o["ramdisk_size"] == len(blob), "%d" % o["ramdisk_size"])
    try:
        new_cpio = unc_ramdisk(blob)
    except Exception as e:
        c("output ramdisk decompresses as gzip", False, str(e))
        return c.report()
    c("output ramdisk decompresses as gzip", True, "%d B cpio" % len(new_cpio))

    try:
        vb_off, how, foot = find_vbmeta(dump, rd_off)
    except ValueError as e:
        raise SystemExit(die("dump: %s" % e, 2))
    slot = vb_off - rd_off
    c("gzip fits the slot", len(blob) <= slot, "%d <= %d" % (len(blob), slot))
    c("rd_off + gzip < vbmeta_off", rd_off + len(blob) < vb_off,
      "0x%X < 0x%X" % (rd_off + len(blob), vb_off))
    c("gap between ramdisk and vbmeta is zero",
      not any(out[rd_off + len(blob):vb_off]),
      "%d B" % (vb_off - rd_off - len(blob)))

    dvb, dhow, dfoot = find_vbmeta(dump, rd_off)
    c("vbmeta offset identical", vb_off == dvb, "0x%X unchanged" % vb_off)
    c("vbmeta + footer byte-identical", out[vb_off:] == dump[dvb:],
      "%d B" % (len(out) - vb_off))
    c("AVBf footer still last", out[-64:][:4] == b"AVBf")

    # ---- stock cpio (must be v5) ----
    stock_cpio = unc_ramdisk(dump[rd_off:rd_off + d["ramdisk_size"]])
    try:
        init, props, dr, sents = check_v5(stock_cpio)
    except ValueError as e:
        c("stock dump is v5", False, str(e))
        return c.report()
    c("stock dump is v5 (P1 patched, markers present)", True,
      "/init@0x%X=%s" % (P1_OFF, init["data"][P1_OFF:P1_OFF + 4].hex()))

    nents = list(cpio_walk(new_cpio))
    c("exactly one cpio TRAILER!!!", len([e for e in nents
                                         if e["name"] == "TRAILER!!!"]) == 1)
    nents = [e for e in nents if e["name"] != "TRAILER!!!"]
    sents = [e for e in sents if e["name"] != "TRAILER!!!"]
    snames = [e["name"] for e in sents]
    nnames = [e["name"] for e in nents]
    c("no duplicate entry names", len(set(nnames)) == len(nnames))

    added = [n for n in nnames if n not in snames]
    removed = [s for s in snames if s not in nnames]
    c("added exactly one entry", added == [ROOTFS_PROP], str(added))
    c("no stock entry removed or renamed", removed == [], str(removed))
    c("record count +1", len(nents) == len(sents) + 1,
      "%d -> %d" % (len(sents), len(nents)))

    sby = {e["name"]: e for e in sents}
    nby = {e["name"]: e for e in nents}
    diff = [n for n in snames
            if n in nby and (sby[n]["data"] != nby[n]["data"]
                             or sby[n]["mode"] != nby[n]["mode"]
                             or sby[n]["uid"] != nby[n]["uid"]
                             or sby[n]["gid"] != nby[n]["gid"])]
    c("every stock entry byte-identical (data+mode+uid+gid)", diff == [], str(diff))
    c("/init sha256 unchanged",
      nby["init"]["data"] == init["data"], sha256(init["data"])[:16])

    new = nby[ROOTFS_PROP]
    c("%s is a regular 0100644 file" % ROOTFS_PROP, new["mode"] == 0o100644,
      oct(new["mode"]))
    c("%s uid/gid 0, nlink 1, mtime 0" % ROOTFS_PROP,
      (new["uid"], new["gid"], new["nlink"], new["mtime"]) == (0, 0, 1, 0),
      "%d/%d n%d m%d" % (new["uid"], new["gid"], new["nlink"], new["mtime"]))
    c("new file payload == stock /adb_debug.prop",
      new["data"] == props, "%d B, sha256 %s" % (len(new["data"]),
                                                 sha256(new["data"])[:16]))
    c("debug_ramdisk dir still 040755",
      nby["debug_ramdisk"]["mode"] == 0o040755)

    # determinism: rebuild and compare bytes
    rebuilt, _info = build(dump_path, None, allow_size=allow_size)
    c("rebuild from the same dump is byte-identical",
      rebuilt == out, sha256(rebuilt)[:16])

    print()
    print("STOCK_DUMP_MD5=%s" % md5(dump))
    print("STOCK_DUMP_SHA256=%s" % sha256(dump))
    print("V7_MD5=%s" % md5(out))
    print("V7_SHA256=%s" % sha256(out))
    print("VERIFY=%s" % ("PASS" if c.failed == 0 else "FAIL"))
    return c.report()


# --------------------------------------------------------------------------
# info
# --------------------------------------------------------------------------
def info(dump_path):
    dump = open(dump_path, "rb").read()
    try:
        p = boot_parse(dump)
    except ValueError as e:
        raise SystemExit(die("%s: %s" % (dump_path, e), 2))
    print("file      : %s" % dump_path)
    print("size      : %d (0x%X)  md5 %s" % (len(dump), len(dump), md5(dump)))
    print("sha256    : %s" % sha256(dump))
    print("header    : v%d header_size 0x%X os_version 0x%08X"
          % (p["header_version"], p["header_size"], p["os_version"]))
    print("kernel    : 0x%X -> rd_off 0x%X" % (p["kernel_size"], p["rd_off"]))
    print("ramdisk   : %d B @0x%X" % (p["ramdisk_size"], p["rd_off"]))
    blob = dump[p["rd_off"]:p["rd_off"] + p["ramdisk_size"]]
    codec = detect_codec(blob)
    print("codec     : %s" % codec)
    try:
        vb_off, how, foot = find_vbmeta(dump, p["rd_off"])
    except ValueError as e:
        print("vbmeta    : none (%s)" % e)
        return 0
    print("vbmeta    : 0x%X (%s), slot 0x%X"
          % (vb_off, how, vb_off - p["rd_off"]))
    if foot:
        print("footer    : avb version %d, vbmeta_size %d, image_size %d"
              % (foot["version"], foot["vbmeta_size"],
                 foot["original_image_size"]))
    if codec != "gzip":
        print("cpio      : not inspected (codec %s)" % codec)
        return 0
    raw = gzip.decompress(blob)
    print("cpio      : %d B" % len(raw))
    ents = list(cpio_walk(raw))
    for e in ents:
        print("  %-40s mode %06o %8d B  ino %d"
              % (e["name"], e["mode"], e["size"], e["ino"]))
    try:
        init, props, _dr, _ = check_v5(raw)
    except ValueError as e:
        print("v5 check  : NOT v5 - %s" % e)
        return 0
    print("v5 check  : OK  (/init@0x%X handle %s, /adb_debug.prop %d B)"
          % (P1_OFF, init["data"][P1_OFF:P1_OFF + 4].hex(), len(props)))
    return 0


# --------------------------------------------------------------------------
def main(argv):
    args = list(argv[1:])
    mode = "build"
    allow_size = False
    rest = []
    for a in args:
        if a in ("-h", "--help"):
            print(__doc__)
            return 0
        elif a == "--verify":
            mode = "verify"
        elif a == "--info":
            mode = "info"
        elif a == "--allow-size-mismatch":
            allow_size = True
        elif a.startswith("-") and a != "-":
            raise SystemExit(die("unknown option %s" % a, 2))
        else:
            rest.append(a)

    if mode == "info":
        if len(rest) != 1:
            raise SystemExit(die("usage: --info DUMP", 2))
        return info(rest[0])
    if mode == "verify":
        if len(rest) != 2:
            raise SystemExit(die("usage: --verify DUMP OUT", 2))
        return verify(rest[0], rest[1], allow_size)
    if len(rest) != 2:
        raise SystemExit(die("usage: DUMP OUT   (or --help)", 2))
    out, inf = build(rest[0], rest[1], allow_size)
    inf["out_path"] = rest[1]
    print_build_report(rest[0], open(rest[0], "rb").read(), out, inf)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
