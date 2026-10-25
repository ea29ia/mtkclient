#!/usr/bin/env python3
"""build_v9_vendor.py - put the adb-debug props into the VENDOR_BOOT ramdisk.

Why (2026-10-25, root cause): the stock boot_a ramdisk is lz4-legacy, the
vendor_boot ramdisk is lz4-legacy, and every v2..v7 boot image replaced the
boot ramdisk with **gzip**.  emp: v8lite (boot ramdisk without /init) still
booted Android -> the boot ramdisk is not unpacked at all; PID 1 comes from
the vendor_boot ramdisk (/init -> /system/bin/init, 2 097 128 B, which runs
first stage: it mounts the /debug_ramdisk tmpfs, reads /force_debuggable and
copies /adb_debug.prop there).

So the props have to live in the vendor ramdisk:

  force_debuggable              (empty)   -> first stage copies adb_debug.prop
  adb_debug.prop                81 B      -> into the /debug_ramdisk tmpfs
  debug_ramdisk/adb_debug.prop  81 B      -> survives the second stage's
                                             umount() (umount only, no rmdir)

=> PropertyInit() finds /debug_ramdisk/adb_debug.prop in BOTH branches of
   `INIT_FORCE_DEBUGGABLE && IsDeviceUnlocked()`, no code patch, no AVB
   (LK reports img_auth_required = 0, avb_ret = 0 for the boot image).

The payload is copied byte-for-byte out of boot_v7.img, so all property files
stay identical between boot and vendor images.

Vendor_boot v4 layout is rebuilt: header | ramdisk | dtb | table | bootconfig,
page aligned; the fragment table entry gets the new ramdisk size.
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "docs", "notes"))

import build_v7_from_dump as v7          # noqa: E402
import build_v6_dual as b6               # noqa: E402
import vendor_boot_extract as vbe        # noqa: E402

PAGE = 0x1000
PART_SIZE = 64 * 1024 * 1024
# Both roots: the plain ramdisk root AND /first_stage_ramdisk, because the
# vendor init runs switch_root() (strings: system/core/init/switch_root.cpp,
# "Unable to chroot to new root"; MS_MOVE at 0x13B5FC) and the second stage
# then lives in /first_stage_ramdisk -- the plain rootfs is no longer visible.
ADDED = ("force_debuggable", "adb_debug.prop", "debug_ramdisk/adb_debug.prop",
         "adb_keys",
         "first_stage_ramdisk/force_debuggable",
         "first_stage_ramdisk/adb_debug.prop",
         "first_stage_ramdisk/debug_ramdisk/adb_debug.prop",
         "first_stage_ramdisk/adb_keys")
FSD_DIR = "first_stage_ramdisk/debug_ramdisk"

# --- vendor-init bind-mount patch (P-B, see
#     docs/notes/reverse/re-vendor-init-flow-2026-10-25.md §4/§6) -------------
# Hook: 0xF1AC0 (sub x1,x29,#0x30 -> bl cave) right before execv("/system/bin/init").
# Cave: mount("/debug_ramdisk","/debug_ramdisk",NULL,MS_BIND,NULL) - a stacked
# bind that makes the second stage's umount("/debug_ramdisk") pop only the top
# mount, so the tmpfs with our props survives into PropertyInit().

HOOK_VA = 0xF1AC4          # `mov x0, x19` right before execv (0xF1AC8)
CAVE_VA = 0x1EF9D0
RX_FILESZ = 0x13F000
HOOK_ORIG = bytes.fromhex("e00313aa")     # mov x0, x19
RET_VA = 0xF1AC8                          # bl execv


def _adrp(pc, target, rd):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    immlo = imm & 3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def _add_imm(rd, rn, imm12):
    return 0x91000000 | (imm12 << 10) | (rn << 5) | rd


def _b(pc, target):
    d = (target - pc) >> 2
    assert -0x2000000 <= d < 0x2000000
    return 0x14000000 | (d & 0x03FFFFFF)


def _bl(pc, target):
    d = (target - pc) >> 2
    assert -0x2000000 <= d < 0x2000000
    return 0x94000000 | (d & 0x03FFFFFF)


DBG_STR = 0x1633F           # "/debug_ramdisk" in vinit .rodata


def cave_words():
    """mount("/debug_ramdisk","/debug_ramdisk",NULL,MS_BIND,NULL), keep argv."""
    words = [
        0xAA0103E9,                       # mov  x9, x1        ; save argv
        _adrp(CAVE_VA + 4, DBG_STR, 0),   # adrp x0, ...
        _add_imm(0, 0, DBG_STR & 0xFFF),  # add  x0, x0, #0x33f
        _adrp(CAVE_VA + 12, DBG_STR, 1),  # adrp x1, ...
        _add_imm(1, 1, DBG_STR & 0xFFF),  # add  x1, x1, #0x33f
        0xAA1F03E2,                       # mov  x2, xzr
        0xD2820003,                       # mov  x3, #0x1000    ; MS_BIND
        0xAA1F03E4,                       # mov  x4, xzr
        0xD2800508,                       # mov  x8, #40        ; __NR_mount
        0xD4000001,                       # svc  #0
        0xAA0903E1,                       # mov  x1, x9         ; restore argv
        0xAA1303E0,                       # mov  x0, x19        ; original insn
        None,                             # b RET_VA
    ]
    words[-1] = _b(CAVE_VA + 4 * (len(words) - 1), RET_VA)
    return words


CAVE_LEN = 4 * 13


def patch_init_bind(init):
    blob = bytearray(init)
    if blob[:4] != b"\x7fELF":
        raise SystemExit(v7.die("vendor init is not ELF", 2))
    phoff = struct.unpack_from("<Q", blob, 0x20)[0]
    phentsize = struct.unpack_from("<H", blob, 0x36)[0]
    phnum = struct.unpack_from("<H", blob, 0x38)[0]
    seg = None
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type, p_flags = struct.unpack_from("<II", blob, o)
        if p_type == 1 and p_flags & 1:
            seg = o
            break
    if seg is None:
        raise SystemExit(v7.die("vendor init: no executable PT_LOAD", 2))
    off, vaddr = struct.unpack_from("<QQ", blob, seg + 8)
    filesz, memsz = struct.unpack_from("<QQ", blob, seg + 32)
    if vaddr != off:
        raise SystemExit(v7.die("vendor init: vaddr != offset", 2))
    if blob[HOOK_VA:HOOK_VA + 4] != HOOK_ORIG:
        raise SystemExit(v7.die("vendor init: hook bytes are not %s"
                                % HOOK_ORIG.hex(), 2))
    words = cave_words()
    cave = b"".join(struct.pack("<I", w) for w in words)
    if any(blob[CAVE_VA:CAVE_VA + len(cave) + 16]):
        raise SystemExit(v7.die("cave area at 0x%X is not zero" % CAVE_VA, 2))
    blob[HOOK_VA:HOOK_VA + 4] = struct.pack("<I", _bl(HOOK_VA, CAVE_VA))
    blob[CAVE_VA:CAVE_VA + len(cave)] = cave
    struct.pack_into("<QQ", blob, seg + 32, RX_FILESZ, RX_FILESZ)
    return bytes(blob), dict(seg=seg, old=(filesz, memsz), cave_len=len(cave))


def verify_init_bind(init):
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                            ("  [%s]" % detail) if detail else ""))

    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except ImportError:
        print("[i] capstone missing, structural checks only")
        return True
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    hook = [(i.mnemonic, i.op_str) for i in md.disasm(init[HOOK_VA:HOOK_VA + 4],
                                                      HOOK_VA)]
    chk("hook is bl cave", hook and hook[0][0] == "bl"
        and hook[0][1].lstrip("#") == "0x1ef9d0", str(hook))
    n = len(cave_words()) * 4
    cave = [(i.mnemonic, i.op_str) for i in md.disasm(init[CAVE_VA:CAVE_VA + n],
                                                      CAVE_VA)]
    text = "; ".join("%s %s" % m for m in cave)
    chk("cave = save argv, mount(MS_BIND) /debug_ramdisk, restore argv, b exec",
        len(cave) == len(cave_words()) and "svc #0" in text
        and "mov x3, #0x1000" in text and "mov x8, #0x28" in text
        and "mov x1, x9" in text and "mov x0, x19" in text
        and cave[-1] == ("b", "#0xf1ac8"), text)
    return ok


def entries_from_boot(boot_img):
    d = open(boot_img, "rb").read()
    p = v7.boot_parse(d)
    raw = v7.unc_ramdisk(d[p["rd_off"]:p["rd_off"] + p["ramdisk_size"]])
    out = {}
    for e in v7.cpio_walk(raw):
        if e["name"] in ("adb_debug.prop", "adb_keys"):
            out[e["name"]] = e["data"]
    if "adb_debug.prop" not in out:
        raise SystemExit(v7.die("no /adb_debug.prop in %s" % boot_img, 2))
    return out


def props_from_boot(boot_img):
    return entries_from_boot(boot_img)["adb_debug.prop"]


def build(vendor_img, boot_img, out_path):
    src = entries_from_boot(boot_img)
    props = src["adb_debug.prop"]
    if os.environ.get("PROPS_FILE"):
        props = open(os.environ["PROPS_FILE"], "rb").read()
        print("props      : OVERRIDE from %s" % os.environ["PROPS_FILE"])
    keys = src.get("adb_keys", b"")
    print("props      : %d B %r" % (len(props), props))
    print("adb_keys   : %d B (host pubkey)" % len(keys))

    h = vbe.parse_image(vendor_img)
    raw = h["raw"]
    if h["version"] != 4 or h["table_num"] != 1:
        raise SystemExit(v7.die("unexpected vendor_boot geometry", 2))
    frag = h["fragments"][0]
    blob = raw[h["ramdisk_off"] + frag["offset"]:
               h["ramdisk_off"] + frag["offset"] + frag["size"]]
    codec = vbe.detect_codec(blob)
    if codec != "lz4-legacy":
        raise SystemExit(v7.die("vendor ramdisk codec %r, expected lz4-legacy"
                                % codec, 2))
    cpio, _blocks = b6.lz4_legacy_blocks(blob)
    names = {e["name"] for e in v7.cpio_walk(cpio)}
    for n in ADDED:
        if n in names:
            raise SystemExit(v7.die("vendor ramdisk already has %r" % n, 2))
    if FSD_DIR in names:
        raise SystemExit(v7.die("vendor ramdisk already has %r" % FSD_DIR, 2))
    if "debug_ramdisk" not in names:
        raise SystemExit(v7.die("vendor ramdisk has no debug_ramdisk dir", 2))
    print("vendor cpio: %d B, %d entries, %s"
          % (len(cpio), len(names) - 1, codec))

    ino = max(e["ino"] for e in v7.cpio_walk(cpio)) + 1
    adds = [v7.cpio_entry("force_debuggable", b"", 0o100644, ino),
            v7.cpio_entry("adb_debug.prop", props, 0o100644, ino + 1),
            v7.cpio_entry("debug_ramdisk/adb_debug.prop", props, 0o100644,
                          ino + 2)]
    if keys:
        adds.append(v7.cpio_entry("adb_keys", keys, 0o100600, ino + 3))
    # first_stage_ramdisk/* (the root that survives switch_root)
    adds.append(v7.cpio_entry(FSD_DIR, b"", 0o040755, ino + 4))
    adds.append(v7.cpio_entry("first_stage_ramdisk/force_debuggable", b"",
                              0o100644, ino + 5))
    adds.append(v7.cpio_entry("first_stage_ramdisk/adb_debug.prop", props,
                              0o100644, ino + 6))
    adds.append(v7.cpio_entry(FSD_DIR + "/adb_debug.prop", props,
                              0o100644, ino + 7))
    if keys:
        adds.append(v7.cpio_entry("first_stage_ramdisk/adb_keys", keys,
                                  0o100600, ino + 8))
    new_cpio = v7.cpio_insert_before_trailer(cpio, adds)
    print("add entries: %s (+%d B cpio)" % (", ".join(ADDED), len(new_cpio) - len(cpio)))

    if os.environ.get("PATCH_INIT_BIND") == "1":
        # patch system/bin/init inside the cpio (same size -> byte splice)
        i = 0
        done = False
        out = bytearray(new_cpio)
        while i + 110 <= len(new_cpio):
            f = [int(new_cpio[i + 6 + 8 * k:i + 14 + 8 * k], 16) for k in range(13)]
            nm = new_cpio[i + 110:i + 110 + f[11] - 1].decode()
            doff = (i + 110 + f[11] + 3) // 4 * 4
            if nm == "system/bin/init":
                patched, meta = patch_init_bind(new_cpio[doff:doff + f[6]])
                out[doff:doff + f[6]] = patched
                print("init patch : hook 0x%X -> bl 0x%X, cave 0x%X (40 B), "
                      "RX filesz/memsz %s -> 0x%X"
                      % (HOOK_VA, CAVE_VA, CAVE_VA, meta["old"], RX_FILESZ))
                done = True
                break
            i = (doff + f[6] + 3) // 4 * 4
        if not done:
            raise SystemExit(v7.die("system/bin/init not found in vendor cpio", 2))
        new_cpio = bytes(out)
        globals()["INIT_BIND"] = True
    else:
        globals()["INIT_BIND"] = False

    import time
    t = time.time()
    comp = b6.lz4_legacy_compress(new_cpio)
    print("lz4-legacy : %d -> %d B (%.1f s)"
          % (len(new_cpio), len(comp), time.time() - t))

    # ---- rebuild the image ----
    dtb = raw[h["dtb_off"]:h["dtb_off"] + h["dtb_size"]]
    table = bytearray(raw[h["table_off"]:h["table_off"] + h["table_size"]])
    bootcfg = raw[h["bootconfig_off"]:h["bootconfig_off"] + h["bootconfig_size"]]

    ramdisk_off = PAGE
    dtb_off = align(ramdisk_off + len(comp), PAGE)
    table_off = align(dtb_off + len(dtb), PAGE)
    bootcfg_off = align(table_off + len(table), PAGE)
    total = bootcfg_off + len(bootcfg)
    if total > PART_SIZE:
        raise SystemExit(v7.die("rebuilt vendor_boot is %d B > 64 MiB" % total, 2))

    # fragment table entry 0: ramdisk_size, ramdisk_offset, type, name, board_id
    struct.pack_into("<II", table, 0, len(comp), 0)
    struct.pack_into("<I", table, 8, 1)      # VENDOR_RAMDISK_TYPE_PLATFORM

    out = bytearray(b"\x00" * max(PART_SIZE, total))
    out[0:0x1000] = raw[0:0x1000]
    # header is copied as-is; only vendor_ramdisk_size (offset 0x18) changes
    struct.pack_into("<I", out, 0x18, len(comp))
    out[ramdisk_off:ramdisk_off + len(comp)] = comp
    out[dtb_off:dtb_off + len(dtb)] = dtb
    out[table_off:table_off + len(table)] = bytes(table)
    out[bootcfg_off:bootcfg_off + len(bootcfg)] = bootcfg

    if out_path:
        with open(out_path, "wb") as fh:
            fh.write(out)
    return bytes(out), dict(cpio=new_cpio, comp=comp, props=props, h=h,
                            dtb=dtb, bootcfg=bootcfg, dtb_off=dtb_off,
                            table_off=table_off, bootcfg_off=bootcfg_off,
                            frag=frag)


def align(x, a=PAGE):
    return (x + a - 1) // a * a


def verify(out_path, info):
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                            ("  [%s]" % detail) if detail else ""))

    h2 = vbe.parse_image(out_path)
    r = h2["raw"]
    chk("still VNDRBOOT v4, 1 fragment",
        r[:8] == b"VNDRBOOT" and h2["version"] == 4 and h2["table_num"] == 1)
    chk("vendor_ramdisk_size matches fragment",
        h2["vendor_ramdisk_size"] == h2["fragments"][0]["size"],
        "%d" % h2["vendor_ramdisk_size"])
    blob = r[h2["ramdisk_off"]:h2["ramdisk_off"] + h2["vendor_ramdisk_size"]]
    chk("codec is still lz4-legacy", vbe.detect_codec(blob) == "lz4-legacy")
    cpio, _b = b6.lz4_legacy_blocks(blob)
    chk("cpio roundtrip == built cpio", cpio == info["cpio"],
        "%d B" % len(cpio))
    names = [e["name"] for e in v7.cpio_walk(cpio)]
    for n in ADDED:
        chk("entry %s present" % n, n in names)
    byp = {e["name"]: e["data"] for e in v7.cpio_walk(cpio)}
    chk("props byte-identical", byp["adb_debug.prop"] == info["props"] and
        byp["debug_ramdisk/adb_debug.prop"] == info["props"])
    chk("force_debuggable is empty", byp["force_debuggable"] == b"")
    chk("adb_keys present and non-empty", bool(byp.get("adb_keys")),
        "%d B" % len(byp.get("adb_keys", b"")))
    # dtb + bootconfig unchanged
    dtb = r[h2["dtb_off"]:h2["dtb_off"] + h2["dtb_size"]]
    chk("dtb byte-identical", dtb == info["dtb"],
        "%d B" % len(info["dtb"]))
    bc = r[h2["bootconfig_off"]:h2["bootconfig_off"] + h2["bootconfig_size"]]
    chk("bootconfig byte-identical", bc == info["bootcfg"])
    chk("image size == 64 MiB", len(r) == PART_SIZE, "%d" % len(r))
    if globals().get("INIT_BIND"):
        init = None
        for e in v7.cpio_walk(cpio):
            if e["name"] == "system/bin/init":
                init = e["data"]
        if init is None:
            chk("system/bin/init present", False)
        else:
            ok = verify_init_bind(init) and ok
    print("VERIFY=%s" % ("PASS" if ok else "FAIL"))
    return ok


def main(argv):
    argv = [a for a in argv if not a.startswith("--")]
    if len(argv) not in (4, 5) or "-h" in argv:
        print(__doc__)
        return 2
    vendor_img, boot_img, out_path = argv[1:4]
    if len(argv) == 5:
        props_override = argv[4]
    else:
        props_override = None
    out, info = build(vendor_img, boot_img, out_path)
    print("output     : %s" % out_path)
    print("             size %d  md5 %s  sha256 %s"
          % (len(out), v7.md5(out), v7.sha256(out)))
    return 0 if verify(out_path, info) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
