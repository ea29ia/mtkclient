# RE: LK state probe — reading `verifiedbootstate` without Android

Date: 2026-10-25. Device not connected, DA not started, nothing flashed.
Everything below is static evidence from `docs/notes/rmx3630-lk/lk_payload.bin`
(935 424 B, sha256 `e7c857896bfe83966595dc61bea8ced5ef6ad0d6dcf57f7ec5a9892eabd8c763`),
plus two offline tools:

* `docs/notes/lk_state_probe.py`   — the procedure, the transcript decoder, and the
  static proof that each fastboot surface exists;
* `docs/notes/seccfg_validate.py`  — a replay of LK's seccfg validator.

Companions: `re-lk-initrd-and-vbst.md` (§3 boot-state table, §4 AVB flags),
`re-lk-seccfg.md` (validator flow), `re-seccfg-digest-equiv.md` (HACC digest),
`re-lk-rescue-surfaces.md` (fastboot command table + gating),
`re-adb-unauthorized-checklist.md` (what to check once a shell exists).

---

## 0. The question being answered

`SecondStageMain` loads `/debug_ramdisk/adb_debug.prop` only when

```c
getenv("INIT_FORCE_DEBUGGABLE") == "true" && AvbHandle::IsDeviceUnlocked()
```

and `IsDeviceUnlocked()` is `fs_mgr_get_boot_config("verifiedbootstate") == "orange"`.
LK writes that string from its boot-state variable at **VA 0x500C4FA8**, and the
only assignment that can make it 2 (orange) from persistent state is

```
0x50053AB4  bl 0x500326AC          ; sec_cfg_get_lock_state(&ls)   <- runs the full validator
0x50053AC0  cbnz w0, 0x50053AD8    ; error -> do NOT set orange
0x50053AC8  cmp  w8, #3            ; record+0x0C == 3 ?
0x50053AD0  mov  w0, #2
0x50053AD4  bl   0x50053F6C        ; boot_state = ORANGE
```

So the whole adb question reduces to **one byte that survived one digest check**.
Everything else (ramdisk patches, vendor_boot, `force_debuggable`) is downstream.

The phone has no screen, `adb` is unauthorized (no shell) and the DA is only
reachable in preloader mode. Both tools below therefore read the state from a
surface that does not need Android.

---

## 1. What actually exists in this LK (evidence, not assumption)

All VAs are `payload_offset + 0x50000000`. Reproduce with
`python3 docs/notes/lk_state_probe.py --verify-lk --disasm`
(30/30 checks pass; it re-derives this table from the bytes, it does not trust
this document).

### 1.1 `getvar` is registered as a public command

```
0x50006364  adrp x0, 0x5008f000
0x5000636c  add  x0, x0, #0x794      -> 0x5008F794 "getvar:"
0x50006368  adrp x1, 0x50006000
0x50006370  add  x1, x1, #0x808      -> 0x50006808  handler
0x50006374  mov  w2, #1              -> flagA = 1
0x50006378  mov  w3, #0               -> flagB = 0
0x5000637c  bl   0x50005768          -> fastboot_register()
```

The dispatcher executes a command when `(flagA==1 && flagB==0) || lock_state==3`
(`0x50005F1C bl 0x5007EF04` S-CHIP, `0x50005F20 bl 0x500326AC` lock_state,
`0x50005F44 cmp w8,#3`, `0x50005F48 b.ne` deny). `getvar` is therefore **available
on a locked device** — that is the whole point.

### 1.2 The published getvar variables (complete list)

`fastboot_publish(name, value)` is **0x5000582C** (list head `0x501120B8`).
Every call site in the payload, with the literal name it registers:

| # | name | value | name VA | publish VA |
|---|---|---|---|---|
| 1 | `version` | `0.5` | 0x500B2901 | 0x500064E4 |
| 2 | `version-bootloader` | runtime (`getver()`) | 0x5008F7E7 | 0x500064F8 |
| 3 | `max-download-size` | runtime (`67108864`) | 0x5008F7FA | 0x50006508 |
| 4 | `product` | `k6789v1_64` | 0x5008F80C | 0x5000651C |
| 5 | `serialno` | runtime | 0x5008F81F | 0x50006530 |
| 6 | `is-userspace` | `no` | 0x5008F828 | 0x50006548 |
| 7 | `version-baseband` | runtime | 0x5008F835 | 0x5000655C |
| 8 | `current-slot` | `a` / `b` (A/B only) | 0x5008F846 | 0x500065A4 |
| 9 | `slot-count` | runtime | 0x5008F88A | 0x500065CC |
| 10 | `slot-unbootable:a` | `no`/`yes` | 0x5008F895 | 0x50006634 |
| 11 | `slot-unbootable:b` | `no`/`yes` | 0x5008F8AB | 0x50006658 |
| 12 | `slot-successful:a` | `no`/`yes` | 0x5008F8BD | 0x5000667C |
| 13 | `slot-successful:b` | `no`/`yes` | 0x5008F8CF | 0x500066A0 |
| 14 | `slot-retry-count:a` | runtime | 0x5008F905 | 0x500066D8 |
| 15 | `slot-retry-count:b` | runtime | 0x5008F93C | 0x50006738 |
| 16 | `off-mode-charge` | `0` / `1` | 0x5008FAE4 | 0x50006768, 0x50006DE8 |
| 17 | **`secure`** | **`no` / `yes`** | **0x50090037** | **0x50007660** |
| 18 | **`unlocked`** | **`yes` / `no`** | **0x5009003E** | **0x50007698** |

plus dynamic names built at runtime by the partition enumerator at 0x50007230
(`snprintf` from `"%s"`/`"%s_a"` around 0x5008FEC0 `"-slot:"`, AOSP-style
`partition-size:`/`partition-type:` — the exact prefixes are not string literals, so
they are deliberately **not** part of the verified table above; nothing there can
carry the lock state).

**Absent, verified by absence of any publication site:** `avb`, `verifiedbootstate`,
`is-unlocked`, `is_unlocked`, `vbmeta`, `lock_state`, `seccfg`. Asking fastboot for
any of those returns **OKAY with an empty value** (the not-found path loads the
empty string at 0x50091523), not an error — an empty value must never be read as
"no".

### 1.3 `secure` / `unlocked` are computed from the *validated* record

Publisher `0x50007600` (called from `fastboot_init` at 0x50006564):

```
0x5000760C  add  x0, sp, #0x1c
0x50007610  str  wzr, [sp, #0x1c]      ; local = 0
0x50007614  bl   0x50032670            ; thunk -> 0x50082E10 (is-unlocked wrapper)
0x50007618  cbz  w0, 0x5000762C        ; (never taken: see below)
0x50007624  bl   0x50005ADC            ; fastboot_fail("Failed to get secure status!")
0x5000762C  "secure"   -> 0x5000590C (fastboot_get), 0x50007660 publish / 0x50007658 update
0x50007664  "unlocked" -> same pattern, 0x50007698
```

Value table: **0x50090821 = "no"**, **0x50090825 = "yes"** (4 bytes apart,
selected by `ldrsw x9,[sp,#0x1c]` and `cset w8,eq` respectively).

The getter chain is exactly the boot-decision chain:

```
0x50082E10 (wrapper)
  0x50082E28  bl 0x500326AC        ; -> 0x50082AE0
0x50082AE0 (core)
  0x50082AF4  bl 0x500827E8        ; sec_check_major_integrity_seccfg
  0x50082AFC  ldr w8, [x8, #0x84C] ; record+0x0C
  0x50082B0C  csinc w8, w8, wzr, eq ; on error -> 1  (FAIL-SAFE LOCKED)
0x50082E34  cmp w8, #3
0x50082E38  csinc w8, wzr, wzr, eq ; -> islocked (1 when != 3)
```

**Two consequences that matter for the decision table:**

1. `getvar secure` = `no` **is** "validated `lock_state == 3`", i.e. the same
   predicate that sets orange. It is not a proxy — it is the same byte.
2. The wrapper **always returns 0** (`0x50082E30 mov w0, wzr`), so the
   `"Failed to get secure status!"` branch at 0x50007624 is **dead code** in this
   build. A seccfg error is therefore indistinguishable from "locked": both give
   `secure: yes` / `unlocked: no`. Both mean **green**. To separate
   "genuinely locked" from "record invalid" you need the dump
   (`seccfg_validate.py --info`), not fastboot.

---

## 2. The decision table

`fastboot getvar X = V` / `seccfg field F = W  =>  boot_state  =>  next action`.

| # | Observation | LK boot_state | Confidence | Next action |
|---|---|---|---|---|
| 1 | `secure: no` **and** `unlocked: yes` | **orange** | definitive (same validated byte, 0x50053AD4) | The gate is being satisfied. Stop touching seccfg and ramdisks. Re-open why `adb_debug.prop` does not take effect: is `/force_debuggable` in the executed (boot) ramdisk, does first stage copy it to `/debug_ramdisk/adb_debug.prop`, is `ro.adb.secure` dropped by the `build_prop` SELinux context (`re-init-prop-gate.md` §2). The 5 s stall question is dead — see §3. |
| 2 | `secure: yes` **and** `unlocked: no` | **green** | definitive | The adb path is a dead end. Fix the lock state: dump seccfg (§4) and run the validator. If `INIT_NV` → the record was rewritten locked, the unlock never persisted. If RPMB mirror `locked=1` → LK re-locks and powers off (`unlock_state_check.py`). No ramdisk can create orange. |
| 3 | `secure:` empty / var absent from `getvar all` | **unreadable** | — | Either you are not talking to this LK (`getvar version` != `0.5` / `product` != `k6789v1_64`) or the output was not captured. Re-run §5 step 2, then fall back to the DA dump. |
| 4 | `FAILED (remote: 'Failed to get secure status!')` | (green) | impossible in this build | This branch is dead (0x50082E30 always returns 0). If you ever see it, the LK on the phone is **not** the one analysed here — stop and re-dump LK. |
| 5 | seccfg dump: main `MMMM`, digest `PASS` (plain SHA-256), `lock_state == 3` | **orange** | definitive | Same as #1. |
| 6 | seccfg dump: main valid, `lock_state` ∈ {1,2,4} | **green** | definitive | Same as #2. |
| 7 | seccfg dump: `INIT_NV` (main and backup both unusable) | **green** | definitive | LK rebuilt a default LOCKED record (lock=1) and wrote it. The previous unlock was lost — the seccfg write path is the bug (`re-seccfg-digest-equiv.md` §4: silent SEJ/HACC failure). |
| 8 | seccfg dump: `SEC_RESTORE` (main bad, backup valid) | backup's `lock_state` | definitive | If the backup says 3 → orange; but the main record is corrupt, so the next write may lose it. Investigate why main failed. |
| 9 | seccfg dump: `UNDECIDABLE` (digest is HACC, not plain) | unknown | — | Offline cannot decide. Use #1 (`getvar secure`) — that runs the real HACC on the device. This is the branch the tools deliberately refuse to guess. |
| 10 | `getvar` unreachable **and** no dump | unknown | — | §6 (expdb, UART, USB timing with a baseline). |
| — | any yellow | **not producible** | — | The only writer of 1 (yellow) is the AVB layer; seccfg can only give green/orange (or transient red → power off). Yellow/red at the banner jump to `verify boot fail, it will power off!` (0x500557C0). A powered-off device after LK is *not* a locked-but-booting device. |

Polarity sanity check (do this every time): `secure: no` must be accompanied by
`unlocked: yes`. If they disagree, you have mixed output from two different boots.

Caveat on *when* the value is computed: `secure`/`unlocked` are published by
`fastboot_init` (0x50007600, called at 0x50006564), i.e. during a **fastboot** boot,
while orange is decided later in `boot_linux_from_storage` (0x50053AD4) during an
**Android** boot. Both read the same persistent seccfg record through the same
validator, so the prediction holds unless something rewrites the record in between.
The one known writer is the RPMB force-relock (`double_check_lock_state`,
0x500556C4), and that path powers the device off instead of booting — so it shows up
as "no boot", never as "boots green with an unlocked record".

---

## 3. Retracting the "5-second stall proves orange" claim

The earlier write-up (`re-lk-initrd-and-vbst.md` §5.3) proposed:

> Δ (preloader USB gone → adbd interface appears) differs by ≈5.0 s ⇒ orange is present.

**This is withdrawn as evidence.** Three reasons, in order of weight:

1. **The measurement is not attributable.** Δ contains kernel decompression,
   dm-verity, first-stage init, property loading and adbd startup. Those vary by
   seconds between boots of the *same* image. A single Δ cannot attribute 5 s to
   LK. The original text itself demanded "сравнить с заведомо green-загрузкой"
   (compare with a known-green boot) and then dropped that qualifier in the
   verdict sentence — that dropped qualifier is the weak claim.
2. **Precision.** LK's delay is exactly `mdelay(0x4C4B40)` = 5 000 000 µs
   (0x50053FF4–0x50053FFC). Human-timed cable/power events are ±0.5 s at best, and
   the adbd interface appears asynchronously. "≈5 s" vs "no stall" is not a
   separation you can trust on one sample.
3. **Scope of the spin.** Per the disassembly the delay sits in the `state == 2`
   branch only (`0x50053F98 cmp w8,#2; b.ne 0x50054004` → return; the 5 s path is
   0x50053FA0–0x50053FFC). So it is not literally executed on a green boot — but
   that makes the timing test *worse*, not better: the signal is a ~5 s increment
   inside a multi-second noisy interval, and the absence of the increment is also
   what a "green + slow boot" looks like.

Additionally, the spin is **not** a reliable marker even in principle: the banner
(0x50053F78) is called at 0x50053AF0, i.e. after *both* the green assignment
(0x50053CC8 -> 0x50053A88) and the lock_state override (0x50053AD4). Any change to
that ordering (or a different LK build) silently invalidates the timing heuristic,
while `getvar secure` reads the actual predicate.

**Replacement:** `fastboot getvar secure` (§2 #1/#2). It is one command, needs no
screen, no shell, no baseline, and is answered by the exact function that decides
orange. The timing probe is retired.

---

## 4. The seccfg side (what `seccfg_validate.py` proves and what it cannot)

Record layout (V4, 0x3C), identical in LK, the DA2 and mtkclient
(`Library/Hardware/seccfg.py`, and the `<7I` unpack in `unlock_state_check.py`):

| off | field | LK's treatment |
|---|---|---|
| 0x00 | magic `MMMM` | **checked explicitly** (0x5008250C–0x50082528, err 0x10003004) |
| 0x04 | `seccfg_ver` = 4 | only via the digest |
| 0x08 | `seccfg_size` = 0x3C | only via the digest |
| 0x0C | `lock_state` | read **after** validation; 3 ⇒ orange |
| 0x10 | `dm_verity_state` | read separately (0x50082C5C) |
| 0x14 | `sboot_runtime` | policy key, not boot state |
| 0x18 | `EEEE` | only via the digest |
| 0x1C | digest[0x20] | `HACC(SHA256(record[0:0x1C]))`, compared at 0x500825AC–0x500825E8 |

Master check 0x500827E8, all branches (reproduced by the tool):

```
main magic+digest OK                 -> MAIN_OK      (and backup, if "MMMM", is zeroed)
main bad, backup magic+digest OK     -> SEC_RESTORE  (backup -> main, flash rewritten)
both bad                             -> INIT_NV      (default LOCKED record signed + written)
any getter error in the same boot    -> *out = 1 (locked), csinc @0x50082B0C
```

**What the tool can decide offline:** magic, structure, and — when the stored
digest equals the plain SHA-256 — that LK accepts the record (a plain match means
the device runs anti-clone OFF; a HACC digest cannot coincidentally equal it).

**What it cannot:** a non-plain digest. The HACC key path is HUK/efuse-blended
(`re-seccfg-digest-equiv.md` §1.4/§1.6), so no host can reproduce
`HACC_encrypt(SHA256(hdr))`. The tool reports `UNDECIDABLE` and prints both
branches rather than inventing a verdict. That is the honest answer, and it is
precisely the case where `getvar secure` is the only cheap truth.

No seccfg dump exists in the repo (`docs/notes/*.bin` has none, `logs-rmx3630/`
has none), so the layout was cross-checked against
`Library/Hardware/seccfg.py` (`pack("<7I", MMMM, ver, 0x3C, lock, dv, sboot, EEEE)`
+ 0x20 digest) and the offsets used by `unlock_state_check.py` / `check_seccfg.py`
(`struct.unpack("<7I", head[:28])`, known md5s `12a94a3f…` full / `1687ff26…` 4k).
The tool's `--self-test` synthesises a full 0x4000 partition, so every branch is
exercised without a device; it also recognises the two stock md5s when a real dump
is supplied.

---

## 5. Ordered procedure (one command first)

```
# 0. fastboot, no screen: hold VOL-DOWN while plugging; if that is preloader (22d9:0006)
#    retry VOL-UP+VOL-DOWN, then VOL-UP.  Detect with `fastboot devices`.
fastboot getvar secure
```

Full runbook (including the fallbacks and their expected outputs):
`python3 docs/notes/lk_state_probe.py --plan`.

Then, in this order — cheapest and least invasive first:

| step | command | expected | meaning |
|---|---|---|---|
| 1 | `fastboot getvar version` / `getvar product` | `0.5` / `k6789v1_64` | you are talking to *this* LK |
| 2 | `fastboot getvar secure` | `no` / `yes` | **the** answer |
| 3 | `fastboot getvar unlocked` | `yes` / `no` | cross-check (opposite polarity) |
| 4 | `fastboot getvar all 2>&1 \| tee /tmp/opencode/getvar_all.txt` | full table | record + sanity |
| 5 | `python3 docs/notes/lk_state_probe.py --decode /tmp/opencode/getvar_all.txt` | `VERDICT: ORANGE\|GREEN\|UNREADABLE` | decision table row |
| 6 | `python3 mtk.py r seccfg /tmp/opencode/seccfg.bin` (preloader) then `python3 docs/notes/seccfg_validate.py --info /tmp/opencode/seccfg.bin` | `MAIN_OK` / `SEC_RESTORE` / `INIT_NV` / `UNDECIDABLE` | independent, flash-level |

`mtk.py r` is read-only. Do not run anything that writes seccfg while diagnosing:
a failed write is exactly what produces the green state you are trying to measure.

---

## 6. If nothing above works (camera-free diagnostics)

1. **expdb** — LK's log ring, read-only over DA:
   `python3 mtk.py r expdb /tmp/opencode/expdb.bin`, then search for
   `sboot_state is %d, lock_state is %d, isunlocked is %d` (string 0x5008E089,
   print site 0x5000262C). This is LK printing the *same* numbers the getter
   returns, so it settles the question even without fastboot.
2. **UART** — if fastboot works at all, `oem p2u on` is allowed while locked
   (flagA=1/flagB=0) and muxes LK printk to the pads; then read the line above and
   `[AVB] img_auth_required = %d` (0x500AC46C). `oem dump_pllk_log` and the
   `oem mrdump_*` commands are also locked-OK.
3. **USB timing** — only as a *paired* A/B against a known-green boot of the same
   image, and only if 1 and 2 are impossible. See §3 for why a single measurement
   is worthless.
4. **misc / BCB** — `python3 mtk.py r misc …`: tells you whether the device is
   being forced into recovery (`boot-recovery` at misc+0) instead of normal boot,
   which would make every userspace observation meaningless.

---

## 7. Confidence

| claim | confidence | falsifier |
|---|---|---|
| `getvar` runs while locked | high (registration flags + dispatcher code) | a `FAILED (remote: 'No support by lock control')` on `getvar` |
| the published variable set is exactly table §1.2 | high (every `fastboot_publish` call site in the payload) | a `getvar all` line not in the table |
| `secure`/`unlocked` derive from the validated lock_state | high (0x50007614 → 0x50032670 → 0x50082AE0 → 0x500827E8) | `secure: no` while the seccfg dump shows an invalid main record |
| `secure == "no"` ⇔ LK sets orange | high (same byte, 0x50053ACC/0x50053AD4) | orange banner observed with `secure: yes` |
| the `Failed to get secure status!` branch is dead | high (0x50082E30 `mov w0, wzr`) | seeing that string on a real device |
| a 5 s stall does not prove orange | high (§3) | a paired A/B on the same image showing a clean 5.000 s separation |
| offline HACC digest verification is impossible | high (HUK key path) | a captured stock record whose digest matches the host model byte-for-byte |
