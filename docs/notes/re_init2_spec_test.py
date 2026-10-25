#!/usr/bin/env python3
"""Patch-spec self-test for docs/notes/reverse/re-init2-escape.md (Task H).

Offline only: never touches a device, never writes a flashable image. Every
mutation is applied to a *copy* under /tmp/re_init2_spec and then diffed byte
by byte against the source.

Two groups are validated:

  A. R1 candidate ("/init2" redirect) -- the spec the document rejects.
     A1  /system/bin/init gate: 0x1344BC tbz -> nop
     A2  /system/bin/init gate: getenv-cbz -> nop + tbz -> b 0x13452C
         (self-sufficient variant: INIT_FORCE_DEBUGGABLE becomes irrelevant)
     A3  /system/bin/init literal "/system/bin/init" @0x238D8 -> "/init2"
     A4  first-stage /init   literal "/system/bin/init" @0x13BDB -> "/init2"

  B. Recommended route (R4c) -- no ELF byte is changed at all.
     Two cpio entries are added to the boot ramdisk:
         /force_debuggable                (0 B, 0644)   [copied to tmpfs]
         /adb_debug.prop                  (81 B, 0644)  [copied to tmpfs]
         /debug_ramdisk/adb_debug.prop    (81 B, 0644)  [rootfs layer]
     The third one stays visible after SecondStageMain umount()s the
     /debug_ramdisk tmpfs, so PropertyInit reads adb_debug.prop no matter
     whether AvbHandle::IsDeviceUnlocked() was true.

Exit status is 0 only if every check passes.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_v6_dual as B  # noqa: E402  (import only; never edited)

WORK = "/tmp/re_init2_spec"

STOCK_BOOT = os.path.join(HERE, "rmx3630-lk", "boot.img")
SYS_INIT = "/tmp/fw/system_init"
BOOT_INIT = "/tmp/initwork/ramdisk/init"

STOCK_BOOT_SHA = "8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9"
SYS_INIT_SHA = "a458669ba60984cedf3f0491da6325e2d9f28b51f93bef8522c07308cc8c0037"
BOOT_INIT_SHA = "b8088eb2b895da034ba6048a159068b5ca6f39b54d40a849e66ec33a12b907c6"
PROPS_SHA = "84bc904deff1cc6c7b42e6cccb2e085465250df54f92982001b3c0c313553599"

FAILS = []
PASSES = 0


def check(cond, msg):
    global PASSES
    if cond:
        PASSES += 1
        print("PASS  " + msg)
    else:
        FAILS.append(msg)
        print("FAIL  " + msg)
    return cond


def sha(b):
    return hashlib.sha256(b).hexdigest()


def readelf_ok(path):
    try:
        out = subprocess.run(["readelf", "-h", path], capture_output=True,
                             text=True, timeout=60)
    except Exception as exc:  # pragma: no cover
        return False, "readelf failed: %r" % (exc,)
    if out.returncode != 0:
        return False, out.stderr.strip()
    fields = dict(re.findall(r"^\s*(Type|Machine|Entry point address):\s*(.+)$",
                             out.stdout, re.M))
    ok = fields.get("Type") in ("DYN (Shared object file)",
                                "DYN (Position-Independent Executable file)",
                                "EXEC (Executable file)") and fields.get(
                                    "Machine") == "AArch64"
    return ok, "%s / %s" % (fields.get("Type"), fields.get("Machine"))


def diff_offsets(a, b):
    """Return [(offset, old_byte, new_byte)] for every differing byte."""
    return [(i, a[i], b[i]) for i in range(min(len(a), len(b))) if a[i] != b[i]]


def apply_patch(src, dst, patches):
    """patches: [(offset, old_bytes, new_bytes)]. Verify old bytes, apply."""
    data = bytearray(open(src, "rb").read())
    for off, old, new in patches:
        got = bytes(data[off:off + len(old)])
        if got != old:
            check(False, "%s: site 0x%X holds %s, expected %s"
                  % (os.path.basename(dst), off, got.hex(), old.hex()))
            return None, None
        data[off:off + len(new)] = new
    out = bytes(data)
    with open(dst, "wb") as fh:
        fh.write(out)
    return bytes(open(src, "rb").read()), out


def expect_diff(src_bytes, patched, patches, label):
    """cmp -l equivalent: exactly the bytes the spec says."""
    want = {}
    for off, old, new in patches:
        for i in range(len(old)):
            if old[i] != new[i]:
                want[off + i] = new[i]
    got = diff_offsets(src_bytes, patched)
    got_map = {off: nb for off, _ob, nb in got}
    ok = got_map == want and len(patched) == len(src_bytes)
    check(ok, "%s: cmp -l shows exactly %d changed byte(s) at %s"
          % (label, len(want), ", ".join("0x%X" % o for o in sorted(want))))
    if not ok:
        print("      want=%s\n      got =%s"
              % ({hex(k): "%02x" % v for k, v in sorted(want.items())},
                 {hex(k): "%02x" % v for k, v in sorted(got_map.items())}))
    return ok


def decode_b(word):
    """Decode an AArch64 'b' (0x14 imm26) to its signed byte offset."""
    assert word >> 26 == 0x14000000 >> 26
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return imm * 4


def section(title):
    print("\n" + "=" * 78 + "\n" + title + "\n" + "=" * 78)


def main():
    os.makedirs(WORK, exist_ok=True)

    section("A. R1 candidate spec (documented, REJECTED on SELinux grounds)")

    for path, want, what in ((STOCK_BOOT, STOCK_BOOT_SHA, "stock boot.img"),
                             (SYS_INIT, SYS_INIT_SHA, "/system/bin/init"),
                             (BOOT_INIT, BOOT_INIT_SHA, "boot ramdisk /init")):
        if not os.path.exists(path):
            check(False, "%s present at %s" % (what, path))
            continue
        got = sha(open(path, "rb").read())
        check(got == want, "%s sha256 %s" % (what, got[:16] + "..."))

    sysinit = open(SYS_INIT, "rb").read()
    bootinit = open(BOOT_INIT, "rb").read()

    # --- A1: gate tbz -> nop (keeps the env half of the AND) --------------
    a1 = [(0x1344BC, bytes.fromhex("00040036"), bytes.fromhex("1f2003d5"))]
    src, out = apply_patch(SYS_INIT, os.path.join(WORK, "sys_init.A1"), a1)
    if out is not None:
        print("      site 0x1344BC: %s -> %s  (tbz w0,#0,0x13453C -> nop)"
              % ("00 04 00 36", "1f 20 03 d5"))
        expect_diff(src, out, a1, "A1 system-init gate nop")
        ok, info = readelf_ok(os.path.join(WORK, "sys_init.A1"))
        check(ok, "A1 patched ELF still parses [%s]" % info)

    # --- A2: getenv cbz -> nop, tbz -> b 0x13452C (env-independent) -------
    b_off = (0x13452C - 0x1344BC) // 4
    b_word = 0x14000000 | (b_off & 0x03FFFFFF)
    b_bytes = b_word.to_bytes(4, "little")
    a2 = [(0x1344B0, bytes.fromhex("600400b4"), bytes.fromhex("1f2003d5")),
          (0x1344BC, bytes.fromhex("00040036"), b_bytes)]
    src, out = apply_patch(SYS_INIT, os.path.join(WORK, "sys_init.A2"), a2)
    if out is not None:
        print("      site 0x1344B0: 60 04 00 b4 -> 1f 20 03 d5  (cbz x0 -> nop)")
        print("      site 0x1344BC: 00 04 00 36 -> %s  (tbz -> b 0x13452C)"
              % " ".join("%02x" % x for x in b_bytes))
        check(decode_b(b_word) == 0x13452C - 0x1344BC,
              "A2 branch decodes to PropertyInit @0x13452C")
        expect_diff(src, out, a2, "A2 system-init gate bypass")
        ok, info = readelf_ok(os.path.join(WORK, "sys_init.A2"))
        check(ok, "A2 patched ELF still parses [%s]" % info)

    # --- A3/A4: "/system/bin/init" -> "/init2" literals -------------------
    old = b"/system/bin/init\x00"
    new = b"/init2\x00" + b"\x00" * (len(old) - 7)
    for label, path, off, blob in (
            ("A3 system-init literal @0x238D8", SYS_INIT, 0x238D8, sysinit),
            ("A4 boot-init literal @0x13BDB", BOOT_INIT, 0x13BDB, bootinit)):
        site = [(off, old, new)]
        src, out = apply_patch(path, os.path.join(WORK, os.path.basename(path) + "." + label[:2]),
                               site)
        if out is None:
            continue
        check(blob[off:off + len(old)] == old,
              "%s: stock bytes are %r" % (label, old))
        expect_diff(src, out, site, label)
        ok, info = readelf_ok(os.path.join(WORK, os.path.basename(path) + "." + label[:2]))
        check(ok, "%s: patched ELF still parses [%s]" % (label, info))

    section("B. Recommended route R4c: cpio only, zero ELF bytes changed")

    img = open(STOCK_BOOT, "rb").read()
    p = B.boot_parse(img)
    foot = B.avb_footer(img)
    vb_off = foot["vbmeta_offset"]
    budget = vb_off - p["rd_off"]
    blob = img[p["rd_off"]:p["rd_off"] + p["ramdisk_size"]]
    raw, _blocks = B.lz4_legacy_blocks(blob)
    print("      stock ramdisk: lz4-legacy %d B @0x%X, slot budget %d B, cpio %d B"
          % (p["ramdisk_size"], p["rd_off"], budget, len(raw)))

    stock_ents = list(B.cpio_walk(raw))
    by = {e["name"]: e for e in stock_ents}
    check("debug_ramdisk" in by and by["debug_ramdisk"]["mode"] & 0o170000 == 0o040000,
          "stock cpio has directory /debug_ramdisk (mode 040755)")
    check(by["init"]["size"] == 3143536 and sha(by["init"]["data"]) == BOOT_INIT_SHA,
          "stock cpio /init is the first-stage binary (sha256 b8088eb2...)")
    check(not any(e["name"].endswith("debug_ramdisk/adb_debug.prop") for e in stock_ents),
          "stock cpio has no /debug_ramdisk/adb_debug.prop")

    props = B.ADB_PROPS
    check(len(props) == 81 and sha(props) == PROPS_SHA,
          "/adb_debug.prop payload 81 B, sha256 %s" % PROPS_SHA[:16])

    ino = max(e["ino"] for e in stock_ents)
    adds = [
        B.cpio_entry("force_debuggable", b"", 0o100644, ino + 1),
        B.cpio_entry("adb_debug.prop", props, 0o100644, ino + 2),
        B.cpio_entry("debug_ramdisk/adb_debug.prop", props, 0o100644, ino + 3),
    ]
    new_cpio = B.cpio_insert(raw, adds)
    open(os.path.join(WORK, "boot_v7.cpio"), "wb").write(new_cpio)

    new_ents = {e["name"]: e for e in B.cpio_walk(new_cpio)}
    check(len(list(B.cpio_walk(new_cpio))) == len(stock_ents) + 3,
          "cpio entry count %d -> %d (only additions)"
          % (len(stock_ents), len(stock_ents) + 3))
    for name, size in (("force_debuggable", 0), ("adb_debug.prop", 81),
                       ("debug_ramdisk/adb_debug.prop", 81)):
        e = new_ents.get(name)
        check(e is not None and e["size"] == size and e["mode"] == 0o100644,
              "new entry %-34s size %d mode 0100644" % (name, size))
    check(sha(new_ents["debug_ramdisk/adb_debug.prop"]["data"]) == PROPS_SHA,
          "rootfs-layer prop content is byte-exact")

    trailer = [e["offset"] for e in stock_ents if e["name"] == "TRAILER!!!"][0]
    check(new_cpio[:trailer] == raw[:trailer]
          and new_cpio[trailer + len(b"".join(adds)):] == raw[trailer:],
          "cpio insert is a pure insertion before TRAILER (stock bytes intact)")

    check(sha(new_ents["init"]["data"]) == BOOT_INIT_SHA,
          "recommended route leaves /init byte-identical (no ELF patch)")

    init_copy = os.path.join(WORK, "init.from_v7")
    open(init_copy, "wb").write(new_ents["init"]["data"])
    ok, info = readelf_ok(init_copy)
    check(ok, "first-stage /init extracted from v7 still parses [%s]" % info)

    comp = __import__("gzip").compress(new_cpio, 9, mtime=0)
    open(os.path.join(WORK, "boot_v7.ramdisk.gz"), "wb").write(comp)
    check(len(comp) <= budget,
          "gzip -9 ramdisk %d B fits slot (%d B), slack %d B"
          % (len(comp), budget, budget - len(comp)))

    section("C. Policy assertions the verdict rests on")
    sel = "/tmp/fw/sysroot/system/etc/selinux"
    fc = open(os.path.join(sel, "plat_file_contexts")).read()
    cil = open(os.path.join(sel, "plat_sepolicy.cil")).read()
    pc = open(os.path.join(sel, "plat_property_contexts")).read()
    irc = open("/tmp/fw/sysroot/system/etc/init/hw/init.rc").read()

    def has(text, pat, flags=re.M):
        return re.search(pat, text, flags) is not None

    check(has(fc, r"^/init\s+u:object_r:init_exec:s0$"),
          "plat_file_contexts: /init -> u:object_r:init_exec:s0")
    check(has(fc, r"^/system/bin/init\s+u:object_r:init_exec:s0$"),
          "plat_file_contexts: /system/bin/init -> u:object_r:init_exec:s0")
    check(has(fc, r"^/debug_ramdisk\s+u:object_r:tmpfs:s0$"),
          "plat_file_contexts: /debug_ramdisk -> u:object_r:tmpfs:s0")
    check(has(cil, r'^\(genfscon rootfs "/" \(u object_r rootfs'),
          "plat_sepolicy.cil: genfscon rootfs \"/\" -> rootfs (no per-file xattr)")
    check(not has(cil, r"^\(fsuse .*rootfs"),
          "plat_sepolicy.cil: no (fsuse ...) for rootfs -> labels are genfs, not xattr")
    check(has(cil, r"^\(allow init init_exec \(file \(read getattr map execute open entrypoint\)\)\)"),
          "plat_sepolicy.cil: allow init init_exec (file (entrypoint)) exists")
    check(not has(cil, r"^\(allow init rootfs \(file \([^)]*entrypoint"),
          "plat_sepolicy.cil: NO allow init rootfs (file (entrypoint)) -> /init2 exec denied")
    check(has(cil, r"^\(allow init rootfs \(file \(read getattr map execute open\)\)\)"),
          "plat_sepolicy.cil: allow init rootfs (file (read ... open)) -> prop file readable")
    check(has(cil, r"^\(allow init property_type \(property_service \(set\)\)\)"),
          "plat_sepolicy.cil: allow init property_type (property_service (set))")
    check(has(pc, r"^ro\.adb\.secure\s+u:object_r:build_prop:s0\s+exact bool"),
          "plat_property_contexts: ro.adb.secure -> build_prop (init may set it)")
    check(has(cil, r"^\(allow init rootfs \(file \(relabelfrom\)\)\)"),
          "plat_sepolicy.cil: allow init rootfs (file (relabelfrom)) [why /adb_keys was considered]")
    check(has(cil, r"^\(allow adbd adb_keys_file \(file \(ioctl read getattr lock map open"),
          "plat_sepolicy.cil: adbd may read adb_keys_file, but has no read on rootfs")
    check(not has(cil, r"^\(allow adbd rootfs \(file "),
          "plat_sepolicy.cil: NO allow adbd rootfs (file ...) -> /adb_keys on rootfs unreadable")
    check("restorecon /adb_keys" in irc,
          "init.rc:31-49 restores /adb_keys (needs relabel, which genfs rootfs cannot do)")

    print("\nArtifacts (copies only, not flashable images):")
    for name in sorted(os.listdir(WORK)):
        fp = os.path.join(WORK, name)
        print("  %-28s %8d B  %s" % (name, os.path.getsize(fp),
                                     sha(open(fp, "rb").read())[:16]))

    print("\nRESULT: %s (%d pass, %d fail)"
          % ("PASS" if not FAILS else "FAIL", PASSES, len(FAILS)))
    return 0 if not FAILS else 1


if __name__ == "__main__":
    sys.exit(main())
