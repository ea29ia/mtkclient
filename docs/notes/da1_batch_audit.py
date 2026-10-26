#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Batch #414 triage for a collection of MTK DA blobs.

Wraps ``da1_static_audit.py`` (which does the real work) and adds the two
things a collection needs:

  * container-level facts the single-blob tool does not print: the DA
    banner/version string, the container layout, and *which* preloader DA
    key signs the trailer (K1 = 200EX01/C.25 era, K2 = 2710 era);
  * one table sorted by verdict, plus JSON for later diffing.

Usage::

    python docs/notes/da1_batch_audit.py /tmp/opencode/said
    python docs/notes/da1_batch_audit.py blob1.bin blob2.bin --json out.json
    python docs/notes/da1_batch_audit.py --key-k1 k1.bin --key-k2 k2.bin DIR

Read-only, offline, no device.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
AUDIT = os.path.join(HERE, "da1_static_audit.py")
MAGIC = b"MTK_DOWNLOAD_AGENT"

DEFAULT_K1 = "/tmp/opencode/da/pl.bin"                      # 200EX01 preloader
DEFAULT_K2 = "/tmp/opencode/fw2710/preloader_k6789v1_64.bin"  # 2710 preloader
K1_OFF, K2_OFF = 0x5D2DC, 0x5D4DC


def banner(container: bytes) -> str:
    raw = container[0x20:0x80]
    return "".join(chr(c) if 32 <= c < 127 else " " for c in raw).strip()


def key_id(container: bytes, k1: bytes | None, k2: bytes | None) -> str:
    """Which RSA modulus verifies the container trailer (PSS tail 0xbc)."""
    if not container.startswith(MAGIC) or len(container) < 0x100:
        return "-"
    sig = container[-0x100:]
    s = int.from_bytes(sig, "big")
    for name, key in (("K1", k1), ("K2", k2)):
        if not key:
            continue
        n = int.from_bytes(key, "big")
        if s >= n:
            continue
        m = pow(s, 65537, n).to_bytes(0x100, "big")
        if m[-1] == 0xBC and (m[0] & 0x80) == 0:
            return name
    return "other"


def layout(container: bytes) -> dict:
    if not container.startswith(MAGIC) or len(container) < 0xC0:
        return {}
    return {
        "hdr": struct.unpack_from("<I", container, 0x80)[0],
        "da1_len": struct.unpack_from("<I", container, 0x84)[0],
        "da1_addr": struct.unpack_from("<I", container, 0x88)[0],
        "da2_off": struct.unpack_from("<I", container, 0xA8)[0],
        "da2_len": struct.unpack_from("<I", container, 0xAC)[0],
        "da2_addr": struct.unpack_from("<I", container, 0xB0)[0],
        "sig_off": struct.unpack_from("<I", container, 0xB4)[0],
    }


def audit_one(path: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        jp = tf.name
    try:
        subprocess.run([sys.executable, AUDIT, path, "--json-out", jp],
                       check=False, capture_output=True, text=True, timeout=600)
        with open(jp) as f:
            data = json.load(f)
    finally:
        try:
            os.unlink(jp)
        except OSError:
            pass
    blob = open(path, "rb").read()
    pred = data.get("predicate", {})
    dl = data.get("download", {})
    slot = "-"
    for a in data.get("diff_vs_200EX01", {}).get("addresses", []):
        if a.get("item") == "digest_slot":
            slot = a.get("this")
            break
    return {
        "file": os.path.basename(path),
        "path": path,
        "size": len(blob),
        "type": "container" if blob.startswith(MAGIC) else "raw",
        "banner": banner(blob),
        "layout": layout(blob),
        "verdict": pred.get("verdict"),
        "dram_repair": pred.get("cmd_registered_in_table"),
        "tripwire": pred.get("tripwire_present"),
        "clamp": dl.get("classification"),
        "slot_va": slot,
        "sha256": data.get("identity", {}).get("sha256"),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("targets", nargs="+", help="files or directories")
    ap.add_argument("--json", default=None)
    ap.add_argument("--key-k1", default=DEFAULT_K1)
    ap.add_argument("--key-k2", default=DEFAULT_K2)
    args = ap.parse_args(argv)

    files: list[str] = []
    for t in args.targets:
        if os.path.isdir(t):
            files += sorted(glob.glob(os.path.join(t, "*.bin")))
        else:
            files.append(t)
    if not files:
        print("no input files")
        return 2

    k1 = k2 = None
    try:
        if os.path.exists(args.key_k1):
            k1 = open(args.key_k1, "rb").read()[K1_OFF:K1_OFF + 0x100]
        if os.path.exists(args.key_k2):
            k2 = open(args.key_k2, "rb").read()[K2_OFF:K2_OFF + 0x100]
    except OSError:
        pass

    rows = []
    for p in files:
        try:
            r = audit_one(p)
        except Exception as e:                       # noqa: BLE001
            r = {"file": os.path.basename(p), "path": p, "type": "?",
                 "verdict": f"ERROR {type(e).__name__}", "clamp": "-"}
        if r.get("type") == "container":
            r["key"] = key_id(open(p, "rb").read(), k1, k2)
        else:
            r["key"] = "-"
            if r.get("verdict") == "INDETERMINATE":
                r["type"] = "raw-da2?"
        rows.append(r)
        print(f"  {r['file']:<32} {str(r['verdict']):<14} "
              f"{str(r['clamp']):<12} exploitable="
              f"{'YES' if r['verdict'] == 'VULNERABLE' and r['clamp'] == 'UNCLAMPED' else 'no'}"
              f" key={r['key']}", flush=True)

    rank = {"VULNERABLE": 0, "INDETERMINATE": 1, "PATCHED": 2}
    rows.sort(key=lambda r: (rank.get(str(r["verdict"]), 9), r["file"]))

    print()
    hdr = (f"{'file':<32} {'size':>8} {'type':<10} {'verdict':<13} "
           f"{'clamp':<11} {'expl':<5} {'DRAM':<5} {'key':<5} {'slot':<10} banner")
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        expl = "YES" if (r.get("verdict") == "VULNERABLE"
                         and r.get("clamp") == "UNCLAMPED") else "no"
        print(f"{r['file']:<32} {r.get('size', 0):>8} {str(r.get('type')):<10} "
              f"{str(r.get('verdict')):<13} {str(r.get('clamp')):<11} "
              f"{expl:<5} {str(r.get('dram_repair')):<5} {r.get('key', '-'):<5} "
              f"{str(r.get('slot_va') or '-'):<10} {r.get('banner', '')[:40]}")

    vuln = [r for r in rows if r["verdict"] == "VULNERABLE"]
    expl = [r for r in vuln if r["clamp"] == "UNCLAMPED"]
    print()
    print(f"total={len(rows)} predicate_vulnerable={len(vuln)} "
          f"heapbait_exploitable={len(expl)} "
          f"patched={sum(1 for r in rows if r['verdict'] == 'PATCHED')} "
          f"indeterminate={sum(1 for r in rows if r['verdict'] == 'INDETERMINATE')}")
    if expl:
        print("exploitable (command + no tripwire + UNCLAMPED): "
              + ", ".join(r["file"] for r in expl))
    clamped = [r for r in vuln if r["clamp"] == "CLAMPED"]
    if clamped:
        print("predicate-only, dead for heapbait (CLAMPED): "
              + ", ".join(r["file"] for r in clamped))

    if args.json:
        with open(args.json, "w") as f:
            json.dump(rows, f, indent=1)
        print(f"json: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
