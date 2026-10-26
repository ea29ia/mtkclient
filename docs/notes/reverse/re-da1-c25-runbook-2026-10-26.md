# Runbook: DA1 C.25 HeapBait chain on DekuzenOkahiro's phone (2026-10-26)

Target: RMX3630 / MT6789, C.25 DA1 (container `mt6789_realme.bin`,
sha256 024d01b8...). Chain proven offline (`docs/notes/da1_chain_c25.py`
RESULT: PASS). This runbook = how to try it ON DEVICE, one step at a time.

## 0. Install (once, on the Android host / Termux native — NOT proot)

```sh
pkg install python git libusb libudev-zero clang binutils
pip install pyusb capstone unicorn mock serial pycryptodome colorama
```
(`mock`/`serial`/`pycryptodome`/`colorama` cover mtkclient's imports;
capstone+unicorn are needed by the runner script itself.)

## 1. Files

Put on the host:
- `docs/notes/da1_c25_run.py` (the runner)
- `mtkclient/` checkout (branch oplus-mt6789-unlock)
- `/tmp/opencode/mt6789_realme.bin` -> keep the path, or pass
  `--container <path>`.

## 2. Before touching the phone (offline, ~1 min)

```sh
python docs/notes/da1_c25_run.py --mode check --container /tmp/opencode/mt6789_realme.bin
python docs/notes/da1_c25_run.py --mode verify-offline --container /tmp/opencode/mt6789_realme.bin
```
Expected tails: `RESULT: check PASS (right-firmware gate)` and
`RESULT: verify-offline PASS`. If check says REFUSING: wrong firmware -
STOP, copy the whole output back to us.

## 3. On device — steps, one at a time

Safety: nothing here writes flash / seccfg / RPMB. DA1 crash = recoverable
(step 5). FORBIDDEN while active: WRITE-FLASH to seccfg, any RPMB write.

Steps 2-4 MUST run in the SAME DA1 session as step 1 (staging lives in
that session). Run them immediately after step 1, without re-plugging.

```sh
su -c "setenforce 0"    # raw USB needs it
python docs/notes/da1_c25_run.py --mode device --step 1 --dry-run   # preview
python docs/notes/da1_c25_run.py --mode device --step 1             # attach+DA1
python docs/notes/da1_c25_run.py --mode device --step 2             # stage
python docs/notes/da1_c25_run.py --mode device --step 3             # fire
python docs/notes/da1_c25_run.py --mode device --step 4             # patched BOOT-TO
```

For each step: plug the target with the 3-button combo held (preloader
window ~150-250 ms; start the step BEFORE plugging).

## 4. What success / failure looks like

- step 1 PASS: `[+] step 1 PASS: DA1 alive and answering.`
- step 2 expected: `staging download completed` and a DA verdict line
  containing a hash-mismatch/ERR (rc 0xC0070004 class), NOT a transport
  error. Transport error => STOP, do not fire, report.
- step 3 expected: DA answers ERR (good) OR dies (acceptable).
- step 4 PASS:
  `SUCCESS: DA1's own hash gate PASSED (rc=0) with the patched DA2.`
  >>> STOP THERE. Nothing further in this session.

## 5. Recovery

Any step dies / device vanishes from USB:
1. unplug, plug again with 3-button combo (re-enter BROM),
2. `python docs/notes/da1_c25_run.py --mode device --step 5`
   (re-attach + DA1 reload, safe, standard op),
3. restart from step 2 in the new session.

## 6. What to copy back to us (exact log lines)

Always the FULL stdout of the failed/passed step, minimally:
- step 1: the `probe 1/2` lines and their `->` responses (verbatim),
- step 2: `BOOT-TO response:` and `DA verdict:` lines,
- step 3: `DRAM-REPAIR response:` and `DA verdict:` lines,
- step 4: `BOOT-TO response:`, `upload ->`, and the SUCCESS block if any,
- plus the `[!]`/`[-]`/mtkclient error lines immediately above.

## 7. Known TODO-ON-DEVICE points in the runner

- steps 2-4 reuse a live session via `device_attach_existing`; if your host
  cannot reuse the open port, run the steps from one python session by
  importing the script's `device_step*` helpers directly.
- step 2/3 rc classification is text-based (on-device we cannot read the
  numeric rc the way the emulator does) - the verbatim lines are the
  evidence.
