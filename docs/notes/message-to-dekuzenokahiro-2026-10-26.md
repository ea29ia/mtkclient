Hi!

We've finished the offline work on the MT6789 (RMX3630) DA1 and found the
same vulnerability family in the **C.25** DA1 build — the one in the
`MTK6789_REALME.bin` blob (sha256 `024d01b8...`) you posted earlier.
Thanks for that — it turned out to be the key piece.

## What we did

1. Static audit of the C.25 DA1: `CMD:DEBUG:DRAM-REPAIR` is registered,
   the tripwire patch is absent, and the host-supplied recv length is
   unclamped — i.e. the HeapBait bug (bkerler/mtkclient PR #414) is alive
   in C.25.
2. We ported our chain to the Unicorn emulator: staging at the fixed
   address 0x40000000 via a deliberately failing BOOT-TO -> the
   DRAM-REPAIR overflow (declared length 0x3C) -> a 76-byte stub runs ->
   sha256(patched DA2) is written into DA1's expected-digest slot -> DA1
   stays alive -> the real BOOT-TO then accepts the patched DA2.
   Deterministic (5/5 runs).
3. We checked the signature: your container is signed with the same key
   (K1) as our 200EX01 build, so your preloader would also accept our
   signed DA1.

## Request: run the commands and send back the logs

The runner is ready: `docs/notes/da1_c25_run.py`, runbook
`docs/notes/reverse/re-da1-c25-runbook-2026-10-26.md` (branch
`oplus-mt6789-unlock` at https://github.com/ea29ia/mtkclient).

Important: NOTHING here writes to flash/seccfg/RPMB. The worst case is
the DA1 session dying, which is recovered by re-entering preloader
(step 5). The device is not rooted and not flashed by this script.

Install:
  pkg install python git libusb libudev-zero clang binutils   # Android host
  # on a Linux PC: git clone, then:
  pip install pyusb capstone unicorn mock serial pycryptodome colorama

Without the phone (please send the full output of both):
  python docs/notes/da1_c25_run.py --mode check --container <path to mt6789_realme.bin>
  python docs/notes/da1_c25_run.py --mode verify-offline --container <path>
Both must end with PASS.

With the phone, one step at a time (steps 2-4 immediately after step 1,
in the same session):
  python docs/notes/da1_c25_run.py --mode device --step 1 --dry-run
  python docs/notes/da1_c25_run.py --mode device --step 1   # attach + load DA1
  python docs/notes/da1_c25_run.py --mode device --step 2   # staging (fail BOOT-TO)
  python docs/notes/da1_c25_run.py --mode device --step 3   # fire (DRAM-REPAIR L=0x3C)
  python docs/notes/da1_c25_run.py --mode device --step 4   # BOOT-TO with patched DA2
  (step 5 = recovery: re-attach + re-load DA1)

Plug the phone while holding Vol Up + Vol Down + Power (the preloader
window is ~150-250 ms; start the command BEFORE plugging). On a Linux
PC run the device steps with sudo.

What to send back: the FULL stdout of every step (especially the
probe / BOOT-TO response / DA verdict / DRAM-REPAIR response lines) and
all [!]/[-]/mtkclient error lines. Step 4 success looks like:
  SUCCESS: DA1's own hash gate PASSED (rc=0) with the patched DA2.
If something dies — no problem: step 5, then start again from step 2.

Questions about any step — just ask; the runbook is short and concrete.
