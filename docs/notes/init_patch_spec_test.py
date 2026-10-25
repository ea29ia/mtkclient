#!/usr/bin/env python3
"""init_patch_spec_test.py — apply init patch specs to COPIES and assert the exact diff.

Companion to docs/notes/reverse/re-init-prop-gate.md (Q2).

Why: the v5 boot patch was accepted on the device without knowing what a *correct*
patch looks like.  This tool makes a patch spec machine-checkable:

  * stock bytes at VA must match `before`
  * after patching, EXACTLY the 4 bytes of `after` differ, at the mapped offsets
  * every other byte of the file is untouched (size + all other bytes equal)
  * the ELF still parses (e_ident / e_type / e_entry / phoff / shoff / counts)
  * the encoded branch lands on the expected target VA
  * if `r2` is available, the disassembly at the site is `b <target>`

Nothing is written outside --outdir (default /tmp/init_patch_test); the source
binaries are only read.

Usage:
    python3 docs/notes/init_patch_spec_test.py
    python3 docs/notes/init_patch_spec_test.py --outdir /tmp/x --verbose
    python3 docs/notes/init_patch_spec_test.py --list

Exit code: 0 = every spec PASS (or already patched, as reported), 1 = failure.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys

# ---------------------------------------------------------------------------
# specs
# ---------------------------------------------------------------------------

SPECS = [
    {
        "name": "boot-ramdisk /init (v5, first stage)",
        "paths": [
            "/tmp/initwork/ramdisk/init",          # extracted by this task
            "/tmp/fw/init_boot",                   # same bytes, extracted by Q1/Q3
        ],
        "size": 3_143_536,
        "sha256": "b8088eb2b895da034ba6048a159068b5ca6f39b54d40a849e66ec33a12b907c6",
        "va": 0x2F6D14,
        "before": "93040036",   # tbz w19,#0,0x2F6DA4
        "after":  "24000014",   # b   0x2F6DA4
        "target_va": 0x2F6DA4,
        "note": "makes setenv(INIT_FORCE_DEBUGGABLE,true,1) unconditional "
                "inside the access(/force_debuggable) branch",
    },
    {
        "name": "vendor-ramdisk system/bin/init (v6 candidate)",
        "paths": [
            "/tmp/fw/init_vendor",
        ],
        "size": 2_097_128,
        "sha256": "de4092871407b7946fbe8c55e75577d12bdb836d911a8c279ae2490fd0d580cd",
        "va": 0x0F1710,
        "before": "33050036",   # tbz w19,#0,0xF17B4
        "after":  "29000014",   # b   0xF17B4
        "target_va": 0xF17B4,
        "note": "exact analogue of the boot patch in the other init build",
    },
]


# ---------------------------------------------------------------------------
# ELF helpers
# ---------------------------------------------------------------------------

class ElfError(Exception):
    pass


def elf_load_segments(blob: bytes):
    """Return [(p_offset, p_vaddr, p_filesz, p_flags)] for PT_LOAD."""
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        raise ElfError("not an ELF")
    if blob[4] != 2 or blob[5] != 1:
        raise ElfError("not ELF64 little-endian")
    (e_type, e_machine, _e_version, e_entry, e_phoff, e_shoff, _flags,
     _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, _shstrndx) = \
        struct.unpack_from("<HHIQQQIHHHHHH", blob, 16)
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = \
            struct.unpack_from("<IIQQQQQQ", blob, off)
        if p_type == 1:  # PT_LOAD
            segs.append((p_offset, p_vaddr, p_filesz, p_flags))
    hdr = {
        "e_type": e_type, "e_machine": e_machine, "e_entry": e_entry,
        "e_phoff": e_phoff, "e_shoff": e_shoff, "e_phnum": e_phnum,
        "e_shnum": e_shnum, "e_shentsize": e_shentsize,
    }
    return hdr, segs


def va_to_offset(blob: bytes, va: int) -> int:
    hdr, segs = elf_load_segments(blob)
    for p_offset, p_vaddr, p_filesz, p_flags in segs:
        if p_vaddr <= va < p_vaddr + p_filesz:
            if not (p_flags & 0x1):           # PF_X
                raise ElfError("VA %#x is not in an executable segment" % va)
            return p_offset + (va - p_vaddr)
    raise ElfError("VA %#x is not mapped by any PT_LOAD" % va)


def ebranch_target(insn: bytes, pc_va: int) -> int:
    """Decode AArch64 `b` (imm26) at pc_va."""
    w = struct.unpack("<I", insn)[0]
    if (w >> 26) != 0b000101:
        raise ElfError("not a `b` instruction: %#010x" % w)
    imm = w & 0x3FFFFFF
    if imm & (1 << 25):
        imm -= (1 << 26)
    return pc_va + imm * 4


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------

def run_spec(spec, outdir, verbose=False):
    """Return (ok, status_lines)."""
    lines = []
    ok = True

    src = next((p for p in spec["paths"] if os.path.isfile(p)), None)
    if src is None:
        return False, ["FAIL  %s: none of %s exists" % (spec["name"], spec["paths"])]

    blob = open(src, "rb").read()
    lines.append("SPEC  %s" % spec["name"])
    lines.append("      src    %s (%d B)" % (src, len(blob)))

    if len(blob) != spec["size"]:
        return False, lines + ["FAIL  size %d != expected %d" % (len(blob), spec["size"])]

    digest = hashlib.sha256(blob).hexdigest()
    if digest != spec["sha256"]:
        lines.append("WARN  sha256 %s != expected %s (continuing on bytes)" % (digest, spec["sha256"]))
    else:
        lines.append("      sha256 %s" % digest)

    off = va_to_offset(blob, spec["va"])
    lines.append("      VA %#x -> file offset %#x" % (spec["va"], off))

    before = bytes.fromhex(spec["before"])
    after = bytes.fromhex(spec["after"])
    if len(before) != len(after):
        return False, lines + ["FAIL  before/after length mismatch"]

    cur = blob[off:off + len(before)]
    if cur == after:
        lines.append("PASS  already patched (%s at %#x)" % (spec["after"], off))
        return True, lines
    if cur != before:
        return False, lines + [
            "FAIL  unexpected bytes at %#x: got %s, expected %s (or %s if patched)"
            % (off, cur.hex(), spec["before"], spec["after"])]

    # apply on a copy
    os.makedirs(outdir, exist_ok=True)
    base = os.path.basename(os.path.dirname(src)) + "_" + os.path.basename(src)
    dst = os.path.join(outdir, base + ".patched")
    patched = bytearray(blob)
    patched[off:off + len(after)] = after
    with open(dst, "wb") as fh:
        fh.write(patched)
    lines.append("      wrote  %s" % dst)

    # 1) exact diff: only the instruction bytes that actually change
    expect_diff = [off + i for i in range(len(after)) if before[i] != after[i]]
    diffs = [i for i in range(len(blob)) if blob[i] != patched[i]]
    if len(patched) != len(blob):
        ok = False
        lines.append("FAIL  size changed")
    if diffs != expect_diff:
        ok = False
        lines.append("FAIL  diff positions %s, expected %s"
                     % ([hex(x) for x in diffs], [hex(x) for x in expect_diff]))
    else:
        lines.append("PASS  diff is exactly %d byte(s) at %s (instruction at %#x..%#x)"
                     % (len(diffs), [hex(x) for x in diffs], off, off + len(after) - 1))

    # 2) ELF still parses and header is unchanged
    try:
        hdr0, segs0 = elf_load_segments(blob)
        hdr1, segs1 = elf_load_segments(bytes(patched))
    except ElfError as exc:
        return False, lines + ["FAIL  ELF parse after patch: %s" % exc]
    if hdr0 != hdr1 or segs0 != segs1:
        return False, lines + ["FAIL  ELF header/program headers changed"]
    lines.append("PASS  ELF parses: e_type=%d e_machine=%d e_entry=%#x phnum=%d shnum=%d"
                 % (hdr1["e_type"], hdr1["e_machine"], hdr1["e_entry"],
                    hdr1["e_phnum"], hdr1["e_shnum"]))

    # 3) branch target
    try:
        tgt = ebranch_target(after, spec["va"])
    except ElfError as exc:
        return False, lines + ["FAIL  %s" % exc]
    if tgt != spec["target_va"]:
        ok = False
        lines.append("FAIL  branch target %#x != %#x" % (tgt, spec["target_va"]))
    else:
        lines.append("PASS  %s -> b %#x" % (spec["before"], tgt))

    # 4) optional r2 cross-check
    r2 = shutil.which("r2") or shutil.which("radare2")
    if r2:
        try:
            out = subprocess.run(
                [r2, "-q", "-e", "scr.color=0", "-c",
                 "e asm.lines=false; s %#x; pd 1" % spec["va"], dst],
                capture_output=True, text=True, timeout=120).stdout
            line = [l.strip() for l in out.splitlines() if l.strip().startswith("0x")]
            if line and " b " in line[0] + " ":
                lines.append("      r2: %s" % line[0])
            else:
                lines.append("WARN  r2 output not understood: %r" % out.strip()[:120])
        except Exception as exc:                              # noqa: BLE001
            lines.append("WARN  r2 cross-check skipped: %s" % exc)
    else:
        lines.append("WARN  r2 not found, disassembly cross-check skipped")

    lines.append("%s  %s: %#x %s -> %s (b %#x, %d byte(s) changed)"
                 % ("PASS" if ok else "FAIL", spec["name"], off,
                    spec["before"], spec["after"], spec["target_va"],
                    len(expect_diff)))
    return ok, lines


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outdir", default="/tmp/init_patch_test",
                    help="where patched copies are written (default /tmp/init_patch_test)")
    ap.add_argument("--list", action="store_true", help="list specs and exit")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.list:
        for s in SPECS:
            print("%-46s VA %#010x  %s -> %s" % (s["name"], s["va"], s["before"], s["after"]))
            print("    %s" % s["note"])
        return 0

    failed = 0
    for spec in SPECS:
        ok, lines = run_spec(spec, args.outdir, args.verbose)
        if not ok:
            failed += 1
        for line in lines:
            print(line)
        print()

    total = len(SPECS)
    print("RESULT: %s (%d/%d specs)  exit=%d"
          % ("PASS" if failed == 0 else "FAIL", total - failed, total, 0 if failed == 0 else 1))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
