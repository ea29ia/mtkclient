#!/usr/bin/env python3
"""re_v7_rootfs_prop_test.py - negative + reproducibility tests for v7 (R4c).

Offline only: no device, no DA, no flashing, no writes outside /tmp.

What it proves (each case exercises the *real* verifier, not a model of it):

  A. corrupt one byte of the debug_ramdisk/adb_debug.prop payload in a COPY
     -> `build_v6_dual.py verify --variant v7` must exit 1 and the only failing
        check must be the byte-for-byte comparison with /adb_debug.prop.
  B. drop the debug_ramdisk/adb_debug.prop cpio entry in a COPY
     -> verify must exit 1 (entry count / delta / presence checks fail).
  C. two independent `build --variant v7` runs
     -> identical sha256 for boot_v7.img and vendor_boot_v6.img.

Usage:  python3 docs/notes/re_v7_rootfs_prop_test.py [-o /tmp/re_v7_test]
Exit:   0 all cases behaved as specified, 1 otherwise, 2 missing input.
"""

import argparse
import gzip
import os
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import build_v6_dual as B  # noqa: E402

TOOL = os.path.join(HERE, "build_v6_dual.py")
BOOT = "boot_v7.img"
VBOOT = "vendor_boot_v6.img"
PROP = B.ROOTFS_PROP
BASE = "/tmp/v7"


class T:
    def __init__(self):
        self.n = 0
        self.fail = 0

    def __call__(self, name, ok, detail=""):
        self.n += 1
        if not ok:
            self.fail += 1
        print("%s  %s%s" % ("PASS" if ok else "FAIL", name,
                            ("  [%s]" % detail) if detail else ""))
        return ok


def run_verify(outdir):
    p = subprocess.run([sys.executable, TOOL, "verify", "--variant", "v7",
                        "-o", outdir], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def rebuild_boot(img, new_cpio):
    """Recompress a cpio into an existing boot image, keeping the vbmeta tail."""
    p = B.boot_parse(img)
    vb_off = B.avb_footer(img)["vbmeta_offset"]
    comp = gzip.compress(new_cpio, 9, mtime=0)
    if len(comp) > vb_off - p["rd_off"]:
        raise SystemExit("test image would not fit the ramdisk slot")
    out = bytearray(img)
    struct.pack_into("<I", out, 0x0C, len(comp))
    out[p["rd_off"]:vb_off] = comp + bytes(vb_off - p["rd_off"] - len(comp))
    return bytes(out)


def make_case(outdir, img):
    """Write a mutated boot_v7.img + the reference vendor_boot into outdir."""
    os.makedirs(outdir, exist_ok=True)
    open(os.path.join(outdir, BOOT), "wb").write(img)
    shutil.copy2(os.path.join(BASE, VBOOT), os.path.join(outdir, VBOOT))


def cpio_of(img):
    p = B.boot_parse(img)
    return gzip.decompress(img[p["rd_off"]:p["rd_off"] + p["ramdisk_size"]])


def boot_of(outdir):
    return open(os.path.join(outdir, BOOT), "rb").read()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--outdir", default="/tmp/re_v7_test")
    a = ap.parse_args(argv)

    t = T()
    print("=" * 78)
    print("0. baseline: the real /tmp/v7 build must verify PASS")
    print("=" * 78)
    if not os.path.exists(os.path.join(BASE, BOOT)):
        raise SystemExit(B.die("missing %s/%s - run build --variant v7 first"
                               % (BASE, BOOT), 2))
    rc, out = run_verify(BASE)
    t("baseline verify --variant v7 exits 0", rc == 0, "rc=%d" % rc)
    t("baseline reports 47 checks, 0 failed", "47 checks, 0 failed -> PASS" in out,
      out.strip().splitlines()[-1] if out.strip() else "no output")
    stock = boot_of(BASE)

    # ---------------------------------------------------------------- A -----
    print()
    print("=" * 78)
    print("A. corrupt 1 byte of the rootfs prop payload in a COPY")
    print("=" * 78)
    raw = cpio_of(stock)
    ents = list(B.cpio_walk(raw))
    rp = [e for e in ents if e["name"] == PROP]
    t("copy source contains exactly one %s" % PROP, len(rp) == 1, "%d" % len(rp))
    if len(rp) == 1:
        e = rp[0]
        bad = bytearray(raw)
        orig = bad[e["data_off"]]
        bad[e["data_off"]] ^= 0x01          # same length, still a valid gzip
        case = os.path.join(a.outdir, "A_corrupt_prop")
        make_case(case, rebuild_boot(stock, bytes(bad)))
        ccase = cpio_of(boot_of(case))
        cent = {x["name"]: x for x in B.cpio_walk(ccase)}
        t("corrupted copy keeps the entry at 81 B, payload differs in 1 byte",
          cent[PROP]["size"] == 81 and cent[PROP]["data"] != B.ADB_PROPS and
          sum(x != y for x, y in zip(cent[PROP]["data"], B.ADB_PROPS)) == 1,
          "%d B" % cent[PROP]["size"])
        t("corrupted copy's /adb_debug.prop is still pristine",
          cent["adb_debug.prop"]["data"] == B.ADB_PROPS)
        rc, out = run_verify(case)
        t("A: verify exits 1", rc == 1, "rc=%d" % rc)
        fails = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
        t("A: exactly 1 failing check", len(fails) == 1, "|".join(fails))
        t("A: the failing check is the rootfs prop byte comparison",
          any("bytes == /adb_debug.prop" in ln for ln in fails),
          fails[0] if fails else "none")
        t("A: failure count line says 1 failed",
          "1 failed -> FAIL" in out,
          [ln for ln in out.splitlines() if "checks," in ln][0])

    # ---------------------------------------------------------------- B -----
    print()
    print("=" * 78)
    print("B. remove the %s entry in a COPY" % PROP)
    print("=" * 78)
    raw = cpio_of(stock)
    ents = list(B.cpio_walk(raw))
    keep = bytearray()
    dropped = 0
    for e in ents:
        if e["name"] == PROP:
            dropped += 1
            continue
        keep += raw[e["offset"]:e["end"]]
    tail = raw[ents[-1]["end"]:]          # trailing archive padding
    t("dropped exactly one entry", dropped == 1, "%d" % dropped)
    t("rebuilt cpio is 224 B smaller (entry header 140 + padded data 84)",
      len(keep) + len(tail) == len(raw) - 224,
      "%d -> %d" % (len(raw), len(keep) + len(tail)))
    case = os.path.join(a.outdir, "B_drop_rootfs_prop")
    make_case(case, rebuild_boot(stock, bytes(keep) + tail))
    rc, out = run_verify(case)
    t("B: verify exits 1", rc == 1, "rc=%d" % rc)
    fails = [ln for ln in out.splitlines() if ln.startswith("FAIL")]
    t("B: entry-count check fails", any("cpio entry count == stock + 3" in ln
                                        for ln in fails), "|".join(fails))
    t("B: presence/format check fails", any("0100644 regular file" in ln
                                            for ln in fails))
    t("B: byte-comparison check fails", any("bytes == /adb_debug.prop" in ln
                                            for ln in fails))
    t("B: >1 failing check (delta also broken)", len(fails) > 1,
      "%d fails" % len(fails))

    # ---------------------------------------------------------------- C -----
    print()
    print("=" * 78)
    print("C. reproducibility: two full `build --variant v7` runs")
    print("=" * 78)
    h1 = h2 = None
    for i in (1, 2):
        d = tempfile.mkdtemp(prefix="v7_rep%d_" % i, dir=a.outdir)
        p = subprocess.run([sys.executable, TOOL, "build", "--variant", "v7",
                            "-o", d], capture_output=True, text=True)
        imgs = {n: B.sha(open(os.path.join(d, n), "rb").read())
                for n in (BOOT, VBOOT) if os.path.exists(os.path.join(d, n))}
        if i == 1:
            h1 = imgs
        else:
            h2 = imgs
        t("C: build #%d exits 0" % i, p.returncode == 0, "rc=%d" % p.returncode)
        shutil.rmtree(d, ignore_errors=True)
    t("C: both runs produced both images", bool(h1) and bool(h2) and
      set(h1) == set(h2) == {BOOT, VBOOT}, "%r" % sorted(h1 or {}))
    t("C: boot_v7.img sha256 identical across runs",
      h1 and h2 and h1[BOOT] == h2[BOOT], (h1 or {}).get(BOOT, "?"))
    t("C: vendor_boot_v6.img sha256 identical across runs",
      h1 and h2 and h1[VBOOT] == h2[VBOOT], (h1 or {}).get(VBOOT, "?"))
    t("C: boot sha256 == the shipped /tmp/v7 build",
      h1 and h1[BOOT] == B.sha(stock), (h1 or {}).get(BOOT, "?"))
    t("C: vendor_boot sha256 == the historical v6 hash fb83d015...",
      h1 and h1[VBOOT] == "fb83d015979695b6d4e6ff1f29d9a00a180811d7c9a0877b26f8e0d171fb65a7",
      (h1 or {}).get(VBOOT, "?"))

    print()
    print("%d checks, %d failed -> %s" % (t.n, t.fail,
                                          "PASS" if t.fail == 0 else "FAIL"))
    return 0 if t.fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
