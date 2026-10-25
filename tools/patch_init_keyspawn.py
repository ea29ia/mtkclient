#!/usr/bin/env python3
"""patch_init_keyspawn.py - vendor_boot surgery: root script installs adb_keys.

Why: our props route (`ro.adb.secure=0`) lives in /debug_ramdisk and is broken
by Magisk (magiskinit uses /debug_ramdisk itself).  This patch instead makes adb
authorization independent of properties: the first-stage init (root) forks and
execs a small shell script that waits for /data, then writes our host public
key to /data/misc/adb/adb_keys with the right owner/mode/label.

Cave (VA 0x1EF9D0), all PC-relative so it survives KASLR/PIE:
    mount("/debug_ramdisk","/debug_ramdisk",NULL,MS_BIND,NULL)   ; keep props
    clone(SIGCHLD) -> child: execve("/system/bin/sh", ["sh","-c",SCRIPT], NULL)
    parent: restore argv/x0 and continue to execv("/system/bin/init")

Usage:
    patch_init_keyspawn.py VENDOR_BOOT_IN VENDOR_BOOT_OUT --key-file PUBKEY
    patch_init_keyspawn.py VENDOR_BOOT_IN VENDOR_BOOT_OUT --script-file SCRIPT

Exit codes: 0 ok, 1 verify failed, 2 bad input.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "docs", "notes"))

import build_v7_from_dump as v7      # noqa: E402
import build_v6_dual as b6           # noqa: E402

PAGE = 0x1000
PART = 64 * 1024 * 1024
VA_OFF = 0x200000          # system/bin/init is ET_EXEC: VA = file offset + 0x200000
HOOK_VA = 0xF1AC4          # `mov x0, x19` right before bl execv (0xF1AC8)
RET_VA = 0xF1AC8
CAVE_VA = 0x1EF9D0
RX_END = 0x1F0000          # next PT_LOAD starts here (page aligned)
HOOK_ORIG = bytes.fromhex("e00313aa")
DBG_STR = 0x1633F          # "/debug_ramdisk"


# ------------------------------------------------------------------ encoders --
def enc_b(pc, target):
    d = (target - pc) >> 2
    assert -0x2000000 <= d < 0x2000000
    return 0x14000000 | (d & 0x03FFFFFF)


def enc_bl(pc, target):
    d = (target - pc) >> 2
    assert -0x2000000 <= d < 0x2000000
    return 0x94000000 | (d & 0x03FFFFFF)


def enc_adrp(pc, target, rd):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    assert -0x100000 <= imm < 0x100000
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def enc_add(rd, rn, imm12):
    return 0x91000000 | ((imm12 & 0xFFF) << 10) | (rn << 5) | rd


def enc_movz(rd, imm16):
    return 0xD2800000 | ((imm16 & 0xFFFF) << 5) | rd


def enc_mov(rd, rn):                       # mov Xd, Xn  (orr Xd, xzr, Xn)
    return 0xAA0003E0 | (rn << 16) | rd


def enc_sub_sp(imm):
    return 0xD10003FF | ((imm & 0xFFF) << 10)


def enc_add_sp(imm):
    return 0x910003FF | ((imm & 0xFFF) << 10)


def enc_str(rt, rn, off):
    assert off % 8 == 0 and off < 0x8000
    return 0xF9000000 | ((off // 8) << 10) | (rn << 5) | rt


def enc_stp(rt, rt2, rn, off):
    assert off % 8 == 0
    return 0xA9000000 | (((off // 8) & 0x7F) << 15) | (rt2 << 10) | (rn << 5) | rt


def enc_cbnz(rt, pc, target):
    d = (target - pc) >> 2
    assert -0x40000 <= d < 0x40000
    return 0x35000000 | ((d & 0x7FFFF) << 5) | rt


SVC0 = 0xD4000001
XZR = 31


# --------------------------------------------------------------------- cave ---
def build_cave(script, clone_only=False):
    """Return (cave_bytes, layout) placed at CAVE_VA. Code is PC-relative."""
    sh = b"/system/bin/sh\x00"
    dashc = b"-c\x00"
    CODE_WORDS = 41
    code_len = 4 * CODE_WORDS
    sh_va = CAVE_VA + code_len
    dashc_va = sh_va + len(sh)
    script_va = dashc_va + len(dashc)
    total = code_len + len(sh) + len(dashc) + len(script) + 1
    if CAVE_VA + total > RX_END:
        raise SystemExit(v7.die("cave+strings don't fit the last RX page "
                                "(%d B needed, %d available)"
                                % (total, RX_END - CAVE_VA), 2))

    w = []

    def here():
        return CAVE_VA + 4 * len(w)

    def adr(rd, va):
        w.append(enc_adrp(here(), va, rd))
        w.append(enc_add(rd, rd, va & 0xFFF))

    # 1) mount("/debug_ramdisk","/debug_ramdisk",NULL,MS_BIND,NULL)
    w.append(0xAA0103E9)                      # mov x9, x1   ; save argv
    adr(0, DBG_STR)
    adr(1, DBG_STR)
    w.append(0xAA1F03E2)                      # mov x2, xzr
    w.append(enc_movz(3, 0x1000))             # MS_BIND
    w.append(0xAA1F03E4)                      # mov x4, xzr
    w.append(enc_movz(8, 40))                 # __NR_mount
    w.append(SVC0)
    # 2) argv on the stack: {"/system/bin/sh", "-c", SCRIPT, NULL}
    w.append(enc_sub_sp(0x40))
    adr(0, sh_va)
    adr(1, dashc_va)
    w.append(enc_stp(0, 1, XZR, 0))
    adr(2, script_va)
    w.append(enc_str(2, XZR, 16))
    w.append(enc_str(XZR, XZR, 24))
    # 3) clone(SIGCHLD)
    w.append(enc_movz(0, 17))
    w.append(enc_mov(1, XZR))
    w.append(enc_mov(2, XZR))
    w.append(enc_mov(3, XZR))
    w.append(enc_mov(4, XZR))
    w.append(enc_mov(5, XZR))
    w.append(enc_movz(8, 220))                # __NR_clone
    w.append(SVC0)
    cbnz_at = here()
    w.append(0)                               # cbnz x0, parent (filled below)
    # 4) child
    if clone_only:
        w.append(enc_movz(0, 0))              # exit(0)
        w.append(enc_movz(8, 93))             # __NR_exit
        w.append(SVC0)
        while len(w) < cbnz_at // 4 - CAVE_VA // 4 + 9:
            w.append(0xD503201F)              # nop padding (keeps layout)
    else:
        w.append(0xF94003E0)                  # ldr  x0, [sp]
        w.append(0x910003E1)                  # mov  x1, sp
        w.append(enc_mov(2, XZR))             # mov  x2, xzr  ; envp
        w.append(enc_movz(8, 221))            # __NR_execve
        w.append(SVC0)
        w.append(enc_movz(0, 1))              # exit(1)
        w.append(enc_movz(8, 93))             # __NR_exit
        w.append(SVC0)
    parent_va = here()
    w[cbnz_at // 4 - CAVE_VA // 4] = enc_cbnz(0, cbnz_at, parent_va)
    # 5) parent: restore and continue
    w.append(enc_add_sp(0x40))
    w.append(enc_mov(1, 9))                   # restore argv
    w.append(enc_mov(0, 19))                  # original instruction
    w.append(enc_b(here(), RET_VA))
    if len(w) != CODE_WORDS:
        raise SystemExit(v7.die("cave word count %d != %d"
                                % (len(w), CODE_WORDS), 2))
    cave = b"".join(struct.pack("<I", x) for x in w) + sh + dashc + script + b"\x00"
    return cave, dict(sh_va=sh_va, dashc_va=dashc_va, script_va=script_va,
                      total=total)


# ------------------------------------------------------------------- patcher --
def elf_text(blob):
    phoff = struct.unpack_from("<Q", blob, 0x20)[0]
    phentsize = struct.unpack_from("<H", blob, 0x36)[0]
    phnum = struct.unpack_from("<H", blob, 0x38)[0]
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type, p_flags = struct.unpack_from("<II", blob, o)
        if p_type == 1 and p_flags & 1:
            return o
    raise SystemExit(v7.die("no executable PT_LOAD", 2))


def patch_init(init, script, clone_only=False):
    blob = bytearray(init)
    seg = elf_text(blob)
    off, vaddr = struct.unpack_from("<QQ", blob, seg + 8)
    filesz, memsz = struct.unpack_from("<QQ", blob, seg + 32)
    if off != vaddr:
        raise SystemExit(v7.die("unexpected init segment layout "
                                "(off=0x%X va=0x%X)" % (off, vaddr), 2))
    hook = blob[HOOK_VA:HOOK_VA + 4]
    bl_here = struct.pack("<I", enc_bl(HOOK_VA, CAVE_VA))
    if hook == HOOK_ORIG:
        blob[HOOK_VA:HOOK_VA + 4] = bl_here
    elif hook != bl_here:
        raise SystemExit(v7.die("hook site is neither stock nor our bl", 2))
    cave, lay = build_cave(script, clone_only)
    if hook == HOOK_ORIG and any(blob[CAVE_VA:CAVE_VA + len(cave)]):
        raise SystemExit(v7.die("cave area is not zero", 2))
    blob[CAVE_VA:CAVE_VA + len(cave)] = cave
    new_memsz = RX_END - vaddr
    struct.pack_into("<QQ", blob, seg + 32, new_memsz, new_memsz)
    return bytes(blob), lay


# ------------------------------------------------------------- image rebuild --
def cpio_replace(cpio, name, data):
    out = bytearray(cpio)
    for e in v7.cpio_walk(cpio):
        if e["name"] == name:
            if len(data) != e["size"]:
                raise SystemExit(v7.die("replacement must keep the size", 2))
            out[e["data_off"]:e["data_off"] + e["size"]] = data
            return bytes(out)
    raise SystemExit(v7.die("cpio entry %r not found" % name, 2))


def rebuild(img, cpio):
    ver, page, ka, ra, vrs = struct.unpack_from("<5I", img, 8)
    if ver != 4 or page != PAGE:
        raise SystemExit(v7.die("not a vendor_boot v4 image", 2))
    dtb_size = struct.unpack_from("<I", img, 2100)[0]   # header_size is at 2096
    tsz, tnum, tesz, bcs = struct.unpack_from("<4I", img, 2112)
    ram_off = PAGE
    dtb_off = align(ram_off + vrs, PAGE)
    table_off = align(dtb_off + dtb_size, PAGE)
    bootcfg_off = align(table_off + tsz, PAGE)
    dtb = img[dtb_off:dtb_off + dtb_size]
    table = bytearray(img[table_off:table_off + tsz])
    bootcfg = img[bootcfg_off:bootcfg_off + bcs]

    comp = b6.lz4_legacy_compress(cpio)
    new_dtb_off = align(ram_off + len(comp), PAGE)
    new_table_off = align(new_dtb_off + len(dtb), PAGE)
    new_bootcfg_off = align(new_table_off + len(table), PAGE)
    total = new_bootcfg_off + len(bootcfg)
    if total > PART:
        raise SystemExit(v7.die("rebuilt image is larger than 64 MiB", 2))
    struct.pack_into("<II", table, 0, len(comp), 0)
    struct.pack_into("<I", table, 8, 1)

    out = bytearray(max(PART, total))
    out[0:PAGE] = img[0:PAGE]
    struct.pack_into("<I", out, 0x18, len(comp))
    out[ram_off:ram_off + len(comp)] = comp
    out[new_dtb_off:new_dtb_off + len(dtb)] = dtb
    out[new_table_off:new_table_off + len(table)] = bytes(table)
    out[new_bootcfg_off:new_bootcfg_off + len(bootcfg)] = bootcfg
    return bytes(out), dict(comp=comp, dtb=dtb, bootcfg=bootcfg,
                            dtb_size=dtb_size, cpio=cpio)


def align(x, a=PAGE):
    return (x + a - 1) // a * a


# -------------------------------------------------------------------- verify --
def verify(out_path, info, script, clone_only=False):
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                            ("  [%s]" % detail) if detail else ""))

    img = open(out_path, "rb").read()
    chk("VNDRBOOT v4, 64 MiB",
        img[:8] == b"VNDRBOOT" and struct.unpack_from("<I", img, 8)[0] == 4
        and len(img) == PART, "%d" % len(img))
    vrs = struct.unpack_from("<I", img, 0x18)[0]
    cpio, _ = b6.lz4_legacy_blocks(img[PAGE:PAGE + vrs])
    chk("ramdisk lz4 roundtrip == built cpio", cpio == info["cpio"],
        "%d B" % len(cpio))
    init = None
    for e in v7.cpio_walk(cpio):
        if e["name"] == "system/bin/init":
            init = e["data"]
    chk("system/bin/init present", init is not None)
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except ImportError:
        return True
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    hook = [(i.mnemonic, i.op_str) for i in md.disasm(init[HOOK_VA:HOOK_VA + 4],
                                                      HOOK_VA)]
    chk("hook is bl cave", hook and hook[0][0] == "bl"
        and hook[0][1].lstrip("#") == "0x1ef9d0", str(hook))
    n = len(build_cave(script, clone_only)[0])
    cave = [(i.mnemonic, i.op_str) for i in md.disasm(init[CAVE_VA:CAVE_VA + n],
                                                      CAVE_VA)]
    text = "; ".join("%s %s" % m for m in cave)
    if clone_only:
        chk("cave: mount + clone + child exit(0) + execv (no execve)",
            "svc #0" in text and "mov x3, #0x1000" in text
            and "mov x8, #0xdc" in text and "mov x8, #0x5d" in text
            and "0xdd" not in text
            and cave[-1][1].lstrip("#") == "0xf1ac8", "%d instr" % len(cave))
    else:
        chk("cave: mount + clone + execve(sh,-c,script) + execv",
            "svc #0" in text and "mov x3, #0x1000" in text
            and "mov x8, #0xdc" in text and "mov x8, #0xdd" in text
            and cave[-1][1].lstrip("#") == "0xf1ac8", "%d instr" % len(cave))
    chk("script embedded", script in init)
    # dtb unchanged
    dtb_size = struct.unpack_from("<I", img, 2100)[0]   # header_size is at 2096
    tsz = struct.unpack_from("<I", img, 2112)[0]
    table_off = align(align(PAGE + vrs, PAGE) + dtb_size, PAGE)
    bootcfg_off = align(table_off + tsz, PAGE)
    chk("dtb byte-identical",
        img[align(PAGE + vrs, PAGE):align(PAGE + vrs, PAGE) + dtb_size]
        == info["dtb"])
    print("VERIFY=%s" % ("PASS" if ok else "FAIL"))
    return ok


# ---------------------------------------------------------------------- main --
def default_script(key):
    return ("i=0;while [ ! -d /data/misc ];do /system/bin/sleep 1;i=$((i+1));"
            "[ $i -gt 900 ]&&break;done;"
            "/system/bin/mkdir -p /data/misc/adb;"
            "printf '%s\\n' '" + key.strip().decode() + "' >/data/misc/adb/adb_keys;"
            "/system/bin/chown 1000:2000 /data/misc/adb/adb_keys;"
            "/system/bin/chmod 640 /data/misc/adb/adb_keys;"
            "/system/bin/restorecon -R /data/misc/adb 2>/dev/null").encode()


def main(argv):
    if "-h" in argv or "--help" in argv or len(argv) < 3:
        print(__doc__)
        return 2
    src, dst = argv[1], argv[2]
    key = script = None
    for i, a in enumerate(argv):
        if a == "--key-file":
            key = open(argv[i + 1], "rb").read()
        elif a == "--script-file":
            script = open(argv[i + 1], "rb").read()
    if script is None:
        if key is None:
            raise SystemExit(v7.die("need --key-file or --script-file", 2))
        script = default_script(key)
    print("script     : %d B" % len(script))

    img = open(src, "rb").read()
    vrs = struct.unpack_from("<I", img, 0x18)[0]
    cpio, _ = b6.lz4_legacy_blocks(img[PAGE:PAGE + vrs])
    init = None
    for e in v7.cpio_walk(cpio):
        if e["name"] == "system/bin/init":
            init = e["data"]
    if init is None:
        raise SystemExit(v7.die("no system/bin/init in the vendor ramdisk", 2))
    clone_only = "--clone-only" in argv
    patched, lay = patch_init(init, script, clone_only)
    print("cave       : %d B at 0x%X (strings @0x%X/0x%X/0x%X)"
          % (lay["total"], CAVE_VA, lay["sh_va"], lay["dashc_va"],
             lay["script_va"]))
    new_cpio = cpio_replace(cpio, "system/bin/init", patched)
    out, info = rebuild(img, new_cpio)
    with open(dst, "wb") as fh:
        fh.write(out)
    print("output     : %s  md5 %s  sha256 %s"
          % (dst, v7.md5(out), v7.sha256(out)))
    return 0 if verify(dst, info, script, clone_only) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
