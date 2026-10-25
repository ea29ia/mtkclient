#!/usr/bin/env python3
"""vendor_props_edit.py - rewrite adb_debug.prop inside a vendor_boot ramdisk.

Used to make `adb root` survive a reboot: adding `service.adb.root=1` to the
prop file that the first stage copies into the /debug_ramdisk tmpfs makes adbd
start as root (works because SELinux is permissive, so the adbd -> su
`setcurrent` is no longer denied).

Everything else is preserved byte-for-byte: header (including the cmdline that
carries androidboot.selinux=permissive), dtb, vendor_ramdisk_table, bootconfig.

Usage:
    vendor_props_edit.py IN.img OUT.img --append "service.adb.root=1"
    vendor_props_edit.py IN.img OUT.img --props-file new_adb_debug.prop
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "docs", "notes"))

import build_v7_from_dump as v7          # noqa: E402
import build_v6_dual as b6               # noqa: E402
import patch_init_keyspawn as kp         # noqa: E402

PAGE = 0x1000
TARGETS = ("adb_debug.prop", "debug_ramdisk/adb_debug.prop")


def cpio_set(cpio, name, data):
    """Replace one cpio entry (header + payload); length may change."""
    for e in v7.cpio_walk(cpio):
        if e["name"] == name:
            ent = v7.cpio_entry(name, data, e["mode"], e["ino"],
                                uid=e["uid"], gid=e["gid"],
                                nlink=e["nlink"], mtime=e["mtime"])
            return cpio[:e["offset"]] + ent + cpio[e["end"]:]
    return None


def main(argv):
    if len(argv) < 4:
        print(__doc__)
        return 2
    src, dst = argv[1], argv[2]
    append = props_file = None
    for i, a in enumerate(argv):
        if a == "--append":
            append = argv[i + 1]
        elif a == "--props-file":
            props_file = argv[i + 1]
    if not append and not props_file:
        raise SystemExit(v7.die("need --append or --props-file", 2))

    img = open(src, "rb").read()
    vrs = kp.struct.unpack_from("<I", img, 0x18)[0]
    cpio, _ = b6.lz4_legacy_blocks(img[PAGE:PAGE + vrs])
    names = [e["name"] for e in v7.cpio_walk(cpio)]
    cur = None
    for e in v7.cpio_walk(cpio):
        if e["name"] == "adb_debug.prop":
            cur = e["data"]
    if cur is None:
        raise SystemExit(v7.die("no adb_debug.prop in the ramdisk", 2))
    if props_file:
        new = open(props_file, "rb").read()
    else:
        new = cur
        if not new.endswith(b"\n"):
            new += b"\n"
        if append.encode() not in new:
            new += append.encode() + b"\n"
    print("props old  : %d B" % len(cur))
    print("props new  : %d B %r" % (len(new), new))

    for t in TARGETS:
        if t in names:
            r = cpio_set(cpio, t, new)
            if r is None:
                raise SystemExit(v7.die("failed to replace %r" % t, 2))
            cpio = r
            print("updated    : %s" % t)

    out, info = kp.rebuild(img, cpio)
    with open(dst, "wb") as fh:
        fh.write(out)
    print("output     : %s  md5 %s" % (dst, v7.md5(out)))

    # verify
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                            ("  [%s]" % detail) if detail else ""))

    chk("VNDRBOOT v4, 64 MiB", out[:8] == b"VNDRBOOT" and len(out) == kp.PART,
        "%d" % len(out))
    cmd = out[28:28 + 2048].split(b"\x00")[0]
    chk("cmdline still carries androidboot.selinux=permissive",
        b"androidboot.selinux=permissive" in cmd, cmd.decode("latin1"))
    vrs2 = kp.struct.unpack_from("<I", out, 0x18)[0]
    cpio2, _ = b6.lz4_legacy_blocks(out[PAGE:PAGE + vrs2])
    got = {e["name"]: e["data"] for e in v7.cpio_walk(cpio2)}
    chk("props updated", got.get("adb_debug.prop") == new)
    chk("debug_ramdisk copy updated",
        got.get("debug_ramdisk/adb_debug.prop", new) == new)
    dtb_size = kp.struct.unpack_from("<I", out, 2100)[0]
    chk("dtb byte-identical", out[kp.align(PAGE + vrs2):][:dtb_size] == info["dtb"])
    chk("service.adb.root present", b"service.adb.root=1" in got["adb_debug.prop"])
    print("VERIFY=%s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
