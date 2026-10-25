#!/usr/bin/env python3
"""boot_ramdisk_edit.py - experimental first-stage edits on top of v7.

Two modes, both start from a FRESH v5 boot_a dump and first reproduce v7
(`debug_ramdisk/adb_debug.prop` rootfs copy), then apply one edit:

  --drop-init DUMP OUT
      remove the `/init` record from the boot ramdisk.
      Discriminator: if the phone still boots, PID 1 is NOT the boot-ramdisk
      /init (i.e. vendor_boot's /init symlink wins); if it panics with
      "no init found", the boot ramdisk /init is the one running.

  --bind DUMP OUT
      keep everything, but patch first-stage /init so that right after
      copy_file("/adb_debug.prop" -> "/debug_ramdisk/adb_debug.prop") it does
      mount("/adb_debug.prop", "/debug_ramdisk/adb_debug.prop", NULL, MS_BIND,
      NULL)   (raw syscall 40, no libc symbols needed - init is static).

      Why: the bind mount makes /debug_ramdisk busy, so the second stage's
      UmountDebugRamdisk() (umount only, no rmdir) fails with EBUSY and the
      tmpfs stays mounted; the property file is then reachable in BOTH
      branches of the `INIT_FORCE_DEBUGGABLE && IsDeviceUnlocked()` gate.

Patch layout for --bind (verified by capstone in --verify):
  VA 0x2F6C94 (file 0xF6C94)  -> b 0x4E0300
  cave VA 0x4E0300 (file 0x2E0300, inside 0xD80 bytes of zero padding that
  follows .text) gets 44 bytes of code; the RX PT_LOAD is extended from
  0x1F3280 to 0x1F4000 (filesz == memsz) so the cave is mapped.

Nothing is written to the device by this script.
"""

import gzip
import hashlib
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import build_v7_from_dump as v7  # noqa: E402

PAGE = 0x1000
INIT_VA_OFF = 0x200000          # /init is ET_EXEC: VA = file_off + 0x200000
PATCH_VA = 0x2F6C94             # the `tbz w0,#0,...` after copy_file
CAVE_VA = 0x4E0300
CAVE_SIZE = 48


def md5(b):
    return hashlib.md5(b).hexdigest()


def sha256(b):
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- encoders --
def enc_b(pc, target):
    imm = (target - pc) >> 2
    assert -0x2000000 <= imm < 0x2000000, "branch out of range"
    return 0x14000000 | (imm & 0x03FFFFFF)


def enc_tbz(pc, target, rt=0, bit=0):
    imm = (target - pc) >> 2
    assert -0x2000 <= imm < 0x2000, "tbz out of range"
    return (0x36000000 | ((bit >> 5 & 1) << 31) | ((bit & 0x1F) << 19)
            | ((imm & 0x3FFF) << 5) | rt)


def enc_tbnz(pc, target, rt=0, bit=0):
    imm = (target - pc) >> 2
    assert -0x2000 <= imm < 0x2000, "tbnz out of range"
    return (0x37000000 | ((bit >> 5 & 1) << 31) | ((bit & 0x1F) << 19)
            | ((imm & 0x3FFF) << 5) | rt)


CAVE_CODE = [
    0x2A0003E9,   # mov  w9, w0            ; keep copy_file() result
    0x910043E0,   # add  x0, sp, #0x10     ; src "/adb_debug.prop" (SSO std::string)
    0xF85D03A1,   # ldur x1, [x29, #-0x30] ; dst "/debug_ramdisk/adb_debug.prop"
    0xAA1F03E2,   # mov  x2, xzr           ; fstype = NULL
    0xD2820003,   # mov  x3, #0x1000       ; MS_BIND
    0xAA1F03E4,   # mov  x4, xzr           ; data = NULL
    0xD2800508,   # mov  x8, #40           ; __NR_mount
    0xD4000001,   # svc  #0
    0x2A0903E0,   # mov  w0, w9            ; restore copy_file result
    None,         # tbnz w0,#0, <next>     ; success -> fall through
    None,         # b 0x2F6D7C             ; original error branch (far)
    None,         # b 0x2F6C98             ; success path
]


def cave_bytes():
    codes = list(CAVE_CODE)
    pc = CAVE_VA + 4 * (len(codes) - 3)
    codes[-3] = enc_tbnz(pc, pc + 8)
    codes[-2] = enc_b(pc + 4, 0x2F6D7C)
    codes[-1] = enc_b(pc + 8, 0x2F6C98)
    return b"".join(struct.pack("<I", c) for c in codes)


# ------------------------------------------------------------- cpio helpers --
def cpio_entries(raw):
    """[(name, offset, end, data_off, size)] in archive order."""
    out = []
    for e in v7.cpio_walk(raw):
        out.append((e["name"], e["offset"], e["end"], e["data_off"], e["size"]))
    return out


def cpio_remove(raw, name):
    for n, off, end, _d, _s in cpio_entries(raw):
        if n == name:
            return raw[:off] + raw[end:]
    raise SystemExit(v7.die("cpio entry %r not found" % name, 2))


def cpio_replace(raw, name, data):
    out = bytearray(raw)
    for n, _o, _e, doff, size in cpio_entries(raw):
        if n == name:
            if len(data) != size:
                raise SystemExit(v7.die("cpio_replace needs equal size", 2))
            out[doff:doff + size] = data
            return bytes(out)
    raise SystemExit(v7.die("cpio entry %r not found" % name, 2))


def assemble(dump, cpio):
    """Re-pack cpio into the dump: header, gzip, zero fill, keep vbmeta."""
    p = v7.boot_parse(dump)
    rd_off = p["rd_off"]
    vb_off, _how, _foot = v7.find_vbmeta(dump, rd_off)
    slot = vb_off - rd_off
    comp = gzip.compress(cpio, 9, mtime=0)
    if len(comp) > slot:
        raise SystemExit(v7.die("gzip ramdisk %d B does not fit slot %d B"
                                % (len(comp), slot), 2))
    out = bytearray(dump)
    struct.pack_into("<I", out, 0x0C, len(comp))
    out[rd_off:vb_off] = comp + bytes(slot - len(comp))
    return bytes(out)


# ------------------------------------------------------------------- elfs ----
def elf_rx_segment(blob):
    if blob[:4] != b"\x7fELF" or blob[4] != 2:
        raise SystemExit(v7.die("not an ELF64", 2))
    phoff = struct.unpack_from("<Q", blob, 0x20)[0]
    phentsize = struct.unpack_from("<H", blob, 0x36)[0]
    phnum = struct.unpack_from("<H", blob, 0x38)[0]
    for i in range(phnum):
        o = phoff + i * phentsize
        p_type, p_flags = struct.unpack_from("<II", blob, o)
        if p_type == 1 and p_flags & 1:          # PT_LOAD | PF_X
            return o
    raise SystemExit(v7.die("no executable PT_LOAD", 2))


def patch_bind(init_blob):
    blob = bytearray(init_blob)
    seg = elf_rx_segment(blob)
    off, vaddr = struct.unpack_from("<QQ", blob, seg + 8)
    filesz, memsz = struct.unpack_from("<QQ", blob, seg + 32)
    cave_off = CAVE_VA - vaddr + off
    if not (off <= cave_off and cave_off + CAVE_SIZE <= off + filesz + 0xD80):
        raise SystemExit(v7.die("cave not inside the RX segment padding", 2))
    # the padding must be zeros before we extend the segment over it
    if any(blob[off + filesz: cave_off + CAVE_SIZE]):
        raise SystemExit(v7.die("RX segment padding is not zero - abort", 2))
    new_size = align = ((CAVE_VA - vaddr + CAVE_SIZE + PAGE - 1) // PAGE) * PAGE
    # extend filesz/memsz to cover the cave, keeping the next segment page-clean
    struct.pack_into("<QQ", blob, seg + 32, new_size, new_size)
    struct.pack_into("<I", blob, PATCH_VA - vaddr + off, enc_b(PATCH_VA, CAVE_VA))
    blob[cave_off:cave_off + CAVE_SIZE] = cave_bytes()
    return bytes(blob), dict(seg=seg, seg_off=off, seg_va=vaddr,
                             old_size=filesz, new_size=new_size,
                             cave_off=cave_off, patch_off=PATCH_VA - vaddr + off)


# ------------------------------------------------------------------ verify ---
def capstone_disasm(blob, va, n):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
    except ImportError:
        return []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    off = va - INIT_VA_OFF
    return [(i.address, i.mnemonic, i.op_str)
            for i in md.disasm(blob[off:off + n], va)]


def verify_bind(out, dump, info):
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                            ("  [%s]" % detail) if detail else ""))

    chk("output size 64 MiB", len(out) == v7.PART_SIZE, str(len(out)))
    chk("kernel + vbmeta untouched",
        out[PAGE:v7.boot_parse(out)["rd_off"]] ==
        dump[PAGE:v7.boot_parse(dump)["rd_off"]])
    p = v7.boot_parse(out)
    raw = gzip.decompress(out[p["rd_off"]:p["rd_off"] + p["ramdisk_size"]])
    base = info["cpio"]
    names_out = [n for n, *_ in cpio_entries(raw) if n != "TRAILER!!!"]
    names_base = [n for n, *_ in cpio_entries(base) if n != "TRAILER!!!"]
    chk("same cpio entry list as v7", names_out == names_base,
        "%d entries" % len(names_out))
    chk("rootfs marker present",
        "debug_ramdisk/adb_debug.prop" in names_out)
    init = None
    for n, _o, _e, doff, size in cpio_entries(raw):
        if n == "init":
            init = raw[doff:doff + size]
    base_init = None
    for n, _o, _e, doff, size in cpio_entries(base):
        if n == "init":
            base_init = base[doff:doff + size]
    chk("/init size unchanged", init is not None and len(init) == len(base_init))
    seg = elf_rx_segment(init)
    diff = [i for i in range(len(init)) if init[i] != base_init[i]]
    chk("only the patch site + cave + phdr changed",
        set(diff) <= {0xF6C94 + k for k in range(4)} |
        {0x2E0300 + k for k in range(CAVE_SIZE)} |
        set(range(seg + 32, seg + 48)),
        "%d bytes differ" % len(diff))
    d1 = capstone_disasm(init, PATCH_VA, 4)
    if d1:
        chk("site branches to the cave", d1[0][1] == "b" and "0x4e0300" in d1[0][2],
            "%s %s" % (d1[0][1], d1[0][2]))
    d2 = capstone_disasm(init, CAVE_VA, CAVE_SIZE)
    if d2:
        text = "; ".join("%s %s" % (m, o) for _a, m, o in d2)
        chk("cave contains mount(MS_BIND) + svc #0 + branches",
            "svc #0" in text and "mov x8, #0x28" in text
            and "tbnz w0, #0" in text
            and d2[-2][2].lstrip("#") == "0x2f6d7c"
            and d2[-1][2].lstrip("#") == "0x2f6c98", text)
    print("VERIFY=%s" % ("PASS" if ok else "FAIL"))
    return ok


def verify_drop(out, dump, info):
    ok = True

    def chk(name, cond, detail=""):
        nonlocal ok
        ok = ok and bool(cond)
        print("%s  %s%s" % ("PASS" if cond else "FAIL", name,
                            ("  [%s]" % detail) if detail else ""))

    chk("output size 64 MiB", len(out) == v7.PART_SIZE, str(len(out)))
    p = v7.boot_parse(out)
    chk("kernel region untouched",
        out[PAGE:p["rd_off"]] == dump[PAGE:v7.boot_parse(dump)["rd_off"]])
    vb_out, _h, _f = v7.find_vbmeta(out, p["rd_off"])
    vb_dump, _h2, _f2 = v7.find_vbmeta(dump, p["rd_off"])
    chk("vbmeta + footer untouched", out[vb_out:] == dump[vb_dump:])
    raw = gzip.decompress(out[p["rd_off"]:p["rd_off"] + p["ramdisk_size"]])
    names_out = [n for n, *_ in cpio_entries(raw) if n != "TRAILER!!!"]
    names_base = [n for n, *_ in cpio_entries(info["cpio"]) if n != "TRAILER!!!"]
    chk("/init removed", "init" not in names_out)
    chk("everything else identical",
        names_out == [n for n in names_base if n != "init"],
        "%d -> %d entries" % (len(names_base), len(names_out)))
    for n, _o, _e, doff, size in cpio_entries(raw):
        base_data = None
        for n2, _o2, _e2, d2, s2 in cpio_entries(info["cpio"]):
            if n2 == n:
                base_data = info["cpio"][d2:d2 + s2]
        if n == "TRAILER!!!":
            continue
        if base_data != raw[doff:doff + size]:
            chk("entry %s byte-identical" % n, False)
            break
    else:
        chk("all remaining entries byte-identical", True)
    print("VERIFY=%s" % ("PASS" if ok else "FAIL"))
    return ok


# -------------------------------------------------------------------- main ---
def build_v7_base(dump_path):
    dump = open(dump_path, "rb").read()
    out, info = v7.build(dump_path, None)
    return dump, out, info


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = {a for a in argv[1:] if a.startswith("--")}
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0
    mode = "bind" if "--bind" in flags else ("drop" if "--drop-init" in flags else None)
    if mode is None or len(args) != 2:
        print(__doc__)
        return 2
    dump_path, out_path = args[0], args[1]
    dump, v7bytes, info = build_v7_base(dump_path)

    if mode == "drop":
        new_cpio = cpio_remove(info["cpio"], "init")
        out = assemble(dump, new_cpio)
        open(out_path, "wb").write(out)
        print("mode       : drop /init (discriminator)")
        print("v7 base    : md5 %s" % md5(v7bytes))
        print("cpio       : %d -> %d entries"
              % (len([1 for e in cpio_entries(info["cpio"])
                      if e[0] != "TRAILER!!!"]),
                 len([1 for e in cpio_entries(new_cpio)
                      if e[0] != "TRAILER!!!"])))
        print("output     : %s  md5 %s  sha256 %s"
              % (out_path, md5(out), sha256(out)))
        return 0 if verify_drop(out, dump, info) else 1

    # ---- bind ----
    init = None
    for n, _o, _e, doff, size in cpio_entries(info["cpio"]):
        if n == "init":
            init = info["cpio"][doff:doff + size]
    if init is None:
        raise SystemExit(v7.die("no /init in base cpio", 2))
    new_init, meta = patch_bind(init)
    new_cpio = cpio_replace(info["cpio"], "init", new_init)
    out = assemble(dump, new_cpio)
    open(out_path, "wb").write(out)
    print("mode       : bind-mount /adb_debug.prop over /debug_ramdisk/adb_debug.prop")
    print("RX PT_LOAD : 0x%X -> 0x%X (filesz=memsz)" % (meta["old_size"],
                                                       meta["new_size"]))
    print("patch site : VA 0x%X -> b 0x%X" % (PATCH_VA, CAVE_VA))
    print("cave       : VA 0x%X (%d bytes)" % (CAVE_VA, CAVE_SIZE))
    print("output     : %s  md5 %s  sha256 %s"
          % (out_path, md5(out), sha256(out)))
    return 0 if verify_bind(out, dump, info) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
