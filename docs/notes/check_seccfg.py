#!/usr/bin/env python3
"""Offline seccfg V4 validator (RMX3630 / MT6789 OPLUS).

Checks a seccfg partition image for valid V4 structure per the DA2 static map:
  - two 0x3c-byte records, magic 'MMMM' (0x4D4D4D4D): main @+0x00, backup @+0x3c
  - per re-reserve2-master.md: main valid -> state 1 path, backup -> state 2 path
  - lock_state dword @ record+0x0c (4=LOCK, 3=UNLOCK, per mtkclient seccfg.py LKS_*)
  - header dwords ver=4, size=0x3c (dm_verity, sboot follow)

Usage: python3 check_seccfg.py <seccfg.img>
Exit 0 = structure OK, 1 = problems found (details printed).
"""
import struct
import sys

MAGIC = b"MMMM"
REC = 0x3C


def rec_view(buf: bytes, off: int, label: str, problems: list) -> dict:
    info = {"label": label, "offset": off}
    if off + REC > len(buf):
        problems.append(f"{label}: record truncated (need {REC} bytes at +{off:#x})")
        return info
    rec = buf[off:off + REC]
    info["magic"] = rec[0:4]
    if rec[0:4] != MAGIC:
        problems.append(f"{label}: BAD magic {rec[0:4]!r} (expected MMMM)")
    dwords = struct.unpack_from("<12I", rec, 0)
    info["dwords"] = [hex(d) for d in dwords]
    # field mapping per campaign docs (ver, size, dm_verity, sboot, ... lock_state)
    info["ver"] = dwords[0]
    info["size"] = dwords[1]
    info["dm_verity"] = dwords[2]
    info["sboot"] = dwords[3]
    info["lock_state"] = dwords[3] if False else dwords[3]  # placeholder, real map below
    # lock_state at +0xc = dword index 3
    info["lock_state"] = dwords[3]
    names = {1: "LKS_???(1)", 2: "MP_DEFAULT", 3: "LKS_UNLOCK", 4: "LKS_LOCK"}
    info["lock_name"] = names.get(info["lock_state"], "UNKNOWN")
    if info["ver"] not in (3, 4):
        problems.append(f"{label}: unusual ver={info['ver']} (expect 4)")
    if info["size"] != REC and info["size"] != 0x3C:
        problems.append(f"{label}: unusual size={info['size']:#x} (expect 0x3c)")
    # non-zero tail check (padding inside record)
    print(f"--- {label} @ +{off:#x} ---")
    print(f"  magic      : {rec[0:4]!r}")
    print(f"  ver        : {dwords[0]}")
    print(f"  size       : {dwords[1]:#x}")
    print(f"  dm_verity  : {dwords[2]}")
    print(f"  sboot      : {dwords[3]}")
    print(f"  lock_state : {dwords[3]} ({info['lock_name']})")
    print(f"  dwords     : {' '.join(info['dwords'])}")
    return info


def main(path: str) -> int:
    buf = open(path, "rb").read()
    print(f"file: {path}  size: {len(buf):#x} ({len(buf)} bytes)")
    if len(buf) == 0:
        print("EMPTY FILE")
        return 1
    nz = sum(1 for b in buf if b)
    print(f"non-zero bytes: {nz}/{len(buf)} ({100.0*nz/len(buf):.2f}%)")
    if nz == 0:
        print("ALL-ZERO IMAGE (known scrubber/failed-write signature)")
        return 1
    problems = []
    m = rec_view(buf, 0x00, "main record", problems)
    b = rec_view(buf, REC, "backup record", problems)
    # dump first 0x80 bytes hex
    print("--- first 0x80 bytes ---")
    for i in range(0, 0x80, 16):
        row = buf[i:i+16]
        print(f"{i:04x}: {row.hex(' ')}  {repr(row)}")
    # whole-image MMMM scan (are there more records / other copies?)
    hits = []
    start = 0
    while True:
        i = buf.find(MAGIC, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    print(f"MMMM occurrences: {[hex(h) for h in hits[:16]]}" + (" ..." if len(hits) > 16 else ""))
    if problems:
        print("PROBLEMS:")
        for p in problems:
            print(" -", p)
        return 1
    print("STRUCTURE OK (magic/fields; hash validity is device-keyed — only on-device HACC check is authoritative)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
