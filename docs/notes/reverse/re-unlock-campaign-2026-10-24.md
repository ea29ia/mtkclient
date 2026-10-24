# RE / campaign report: RMX3630 (MT6789) — unlock write works, unlock does NOT survive reboot

Date: 2026-10-24. Branch `oplus-mt6789-unlock` (report + probes committed in
`04db714`/`4aa8956`).

> **Amended after consistency audit #2** (`re-consistency-audit-2.md`): the RPMB
> mirror is at blocks **0x1DC–0x1DF**, not 0–3 (§2.2/§2.3); ATAG does not
> produce fastboot (§2.3); `misc` is not zero (§8).
Companions: `re-lk-rpmb-lock.md`, `re-lk-seccfg.md`, `re-tbase-sfsrp.md`,
`re-lk-bootmode-priority.md`, `re-f804-rootcause.md`, `re-mtkclient-rpmb-audit.md`,
`re-da2-rpmb-key.md`.

Status legend: **[proven]** = disassembly / device bytes / log evidence,
**[observed]** = device run, **[inferred]** = conclusion from indirect evidence,
**[disproven]** = tested and false.

---

## TL;DR

1. **The write path is fixed and proven.** The long-standing "silent no-op" was our
   own patch stubbing `0x4002F804`, the write-consumer dispatcher. With
   `OPLUS_PATCH_F804_STUB` off (default since `bcf4011`) `WRITE-PARTITION` reaches
   UFS: `para` was written (`PARATEST…`), read back, and restored to zeros. [observed]
2. **The unlock write itself succeeds**: `seccfg` payload `MMMM ver=4 size=0x3C
   lock_state=3` + valid `HACC(SHA-256(hdr[0x1C]))` digest, full-partition
   `WRITE-PARTITION` (`pre_erase=NO`), same-session `READ-FLASH` readback shows
   `lock_state=3`. [observed, log `test8final`]
3. **It does not persist.** On the next boot the partition is back to the original
   byte-for-byte (`0x800000` B, md5 `12a94a3ffbfc1a7f344e1dd6837b359a`,
   0 differing bytes). [observed, log `snap`]
4. **Most probable mechanism: LK `double_check_lock_state`** (0x500556C4) sees the
   RPMB boot-info mirror at `block+0xC == 1` (locked), calls
   `sec_cfg_set_lock_state(locked)` and powers off. Because HACC is deterministic
   over the 0x1C-byte header, the rewritten record is bit-identical to the
   original — a reverted image is **not** evidence of a failed write. [proven
   code, inferred path]
5. **But one fact does not fit DC-only:** the `seccfg` partition also carries an
   unrelated 8-byte vendor marker at offset `0x200` (`90 79 09 22 00 00 00 01`),
   which our 8 MB payload would have zeroed. It is present again after the
   reboot. DC rewrites only
   `0x3C` bytes, so either **the 8 MB write did not cover the tail**, or **another
   actor restored the full partition**. This is now the top open question (§5 Q1).
6. **DA-side RPMB is not trustworthy on this UFS unit.** Reads succeed with a
   *wrong* key and return all zeros; `GET-RPMB-KEY-STATUS` says `NOT-EXIST`
   (the old script mis-printed it as EXIST because `"EXIST" in "NOT-EXIST"`).
   LK, however, demonstrably reads a valid mirror (it re-locks), and t-base
   SFSRP uses the same device RPMB key. So the DA's `CUSTOMRPMBR/W` path
   (patched `mmc_rpmb_send_command`, eMMC flavour) does not reach the real UFS
   RPMB. [observed + proven]
7. **fastboot is unreachable from the DA side in the tested configuration.**
   Mode `0x63` has exactly two entry paths (§2.3): the preloader-owned HW
   boot-nibble (`0x10007024 & 0xF == 3`) and the `rc_wdt-class && lock_state==3`
   branch. **ATAG values 1/4/7 produce modes 1/4/7 (META/factory/UNKNOWN), not
   fastboot.** `SET-BOOT-MODE=FASTBOOT` is accepted by DA2 but the device
   re-enumerates `0006 → 2046` (Android). [proven code + observed]
8. **Device state at the end of the campaign: alive, boots Android normally,
   `seccfg` = original (lock=4), USB `22d9:2046` exposes only Audio/MIDI
   interfaces → no ADB, no MTP.** `adb devices` empty. [observed]

---

## 1. What was done, in order (evidence trail)

| # | action | result | evidence |
|---|---|---|---|
| 1 | stub `0x4002F804` root-caused and gated behind `OPLUS_PATCH_F804_STUB` (OFF) | write path restored | `docs/notes/reverse/re-f804-rootcause.md`, commit `bcf4011` |
| 2 | `para` write test (`PARATEST…` at 0) | committed: `h+0x8=0x88000`, `h+0x34=0x4006E6A0` | `/home/musin/test7live` |
| 3 | `para` restored to zeros | `[+] para RESTORED` | `/home/musin/estorepara` |
| 4 | dry-run of Plan B (backup + payload build) | backup md5 = original, no write | `/home/musin/test8b` |
| 5 | real unlock write `PLAN_B_GO=1` | readback `lock_state=3`, WDT reboot | `/home/musin/test8final` |
| 6 | boot after unlock | Android up, `22d9:2046`, **no ADB**, MIDI-only USB | user `lsusb`/`adb` output, `los.txt` |
| 7 | boot diagnosis (`seccfg`/`expdb`/`misc`) | first run bogus (CUSTOMMEMR), fixed to READ-FLASH | `/home/musin/naw`, `hek` |
| 8 | post-reboot `seccfg` snapshot | **back to original, 0 diffs over 8 MB** | `/home/musin/snap` |
| 9 | fastboot attempts (Vol−, DA `SET-BOOT-MODE`) | never enumerates as fastboot | user `fastboot devices`, `fsst`/`fst` |
| 10 | RPMB recon v2 | all-zero reads, key-gating absent, key-status `NOT-EXIST` | `/home/musin/planb_recon2.log` |

---

## 2. Proven facts (device bytes / disassembly)

### 2.1 `seccfg` partition layout (8 MB, LBA 0x24000, UFS block 0x1000)

```
+0x000  main V4 record (0x3C):
        MMMM | ver=4 | size=0x3C | lock_state | dm_verity | sboot | EEEE
+0x01C  digest = HACC_AES(SHA-256(record[0x00:0x1C]))      (0x20 B)
+0x03C  backup record slot — EMPTY in this unit (all zero)
+0x200  8-byte vendor marker: 90 79 09 22 00 00 00 01  (rest zero)
+0x210..0x7FFFFF  all zero
```
* Only **one** `MMMM` in the whole 8 MB; LK's validator reads only the first
  `0x3000`. [proven: byte scan + `re-lk-seccfg.md` §3.2]
* `protect1` / `protect2` / `frp` / `nvdata` / `persist` / `proinfo` /
  `metadata` do **not** contain the header or the digest of the seccfg record —
  no offline "second copy" of `seccfg` in the partitions we have dumped.
  [disproven for the dumped set]

### 2.2 LK seccfg / RPMB code paths (payload `docs/notes/rmx3630-lk/lk_payload.bin`, base `0x50000000`)

| VA | role |
|---|---|
| 0x5000E15C | call to `boot_mode_check` (0x5000AAAC) — **runs first** |
| 0x5000E270 | call to `sec_boot_init` (0x5000262C) — **runs after** the banner/mode check |
| 0x500026B8 | `double_check_lock_state` (0x500556C4) call site |
| 0x500026E4 | `set_boot_info_to_rpmb` (0x50054744) call site (every boot) |
| 0x500078E8 | `set_boot_info_to_rpmb(1,1)` call site (fastboot unlock commit) |
| 0x50054674 | `km_client_read_rpmb_boot_info(buf)` |
| 0x50055570 | read helper: `w0=0x1DC` (**RPMB block address**, not an op id), `x1=buf`, `w2=0x400`; dev 2 → 0x5003E4E4 (TEE) with one retry, dev 1 → 0x5002FD14 |
| 0x50055508 | `SHA-256(buf, 0x3E0, out)` (software SHA-256 core 0x5008B4DC) |
| 0x50055364 | memcmp(0x20) |
| 0x50055368 | memset (0x400) — **hash mismatch zeroes the buffer and returns success** |
| 0x500556C4 | `double_check_lock_state`: mirror==1 → `sec_cfg_set_lock_state_wrapper(1)` + power-off |
| 0x50082B30 | `sec_cfg_set_lock_state` core (copies main→bak, re-signs, writes both) |
| 0x500ACA4…0x500ACB8 | **fastboot gate**: `hw_boot_nibble (0x50040538) == 3` → mode `0x63`; else fall through |

Consequences:

* A corrupted/unreadable mirror block means `mirror = 0` ⇒ **no re-lock, unlock
  survives** (and LK then rewrites the mirror as unlocked). [proven]
* `0x1DC` is the **JEDEC address field** of the RPMB frame: inside
  `rpmb_read_direct` (0x5002FD14) the argument is stored at `frame+0x1F8`
  (`rev w10,w22; lsr #16; strh w10,[sp,#0x228]`, frame base `sp+0x30`) and the
  request type `0x400` at `frame+0x1FE`. So the mirror is RPMB **blocks
  0x1DC–0x1DF**, i.e. 0x400 bytes at byte offset **0x1DC00** — *not* 0–3.
  (Corrected after audit #2; the "sectors 0–3" claim was wrong.)

### 2.3 `fastboot` entry (verified in disassembly)

```
0x5000AC80  bl 0x5000B1E8          ; reset-reason class; tbz w0,#0 -> skip lock gate
0x5000AC94  bl 0x500326AC          ; seccfg lock_state getter
0x5000AC9C  cmp w8,#3
0x5000ACA0  b.ne 0x5000ADD4        ; not unlocked -> recovery branch
0x5000ACA4  bl 0x50040538          ; HW boot nibble (0x10007024 & 0xF, cached)
0x5000ACAC  cmp w8,#3
0x5000ACB0  b.ne 0x5000ACBC        ; !=3 -> try path (b)
0x5000ACB4  mov w8,#0x63           ; FASTBOOT  (path a)

0x5000ACBC  bl 0x5000B1E8          ; path (b): reset-reason class
0x5000ACC0  tbz w0,#0, 0x5000AD08  ; not that class -> boot-reason table
0x5000ACD0  bl 0x500326AC          ; lock_state
0x5000ACD8  cmp w8,#3
0x5000ACDC  b.ne 0x5000AD08
0x5000ACE0  mov w0,#0xC ; bl 0x50021D2C ; print "fastboot_check gpio condition is %d"
0x5000AD04  b 0x5000ACB4           ; -> 0x63 regardless of the GPIO value
```
So there are **two** paths to FASTBOOT: (a) preloader HW nibble == 3, (b)
reset-reason class of `0x5000B1E8` **and** `seccfg==3` (GPIO only logged).
ATAG boottags are `1 -> mode 1 (META)`, `4 -> mode 4 (factory)`,
`7 -> mode 7 (banner "UNKNOWN BOOT")`; `0x63` is never produced from ATAG.
Our WDT reboot with `seccfg==3` did **not** reach fastboot, so path (b)'s first
condition was false for that reset — an open question (§5 Q5).

---

## 3. Unlock attempt — exact settings and why it reverted

* Payload: `SecCfgV4` parsed with `hwtype = "V4"` (legacy `sej_sec_cfg_hw_V3`),
  `create(lockflag="unlock")` ⇒ `lock_state=3`, `dm_verity=0`, `sboot=0`,
  512-byte image zero-padded to 8 MB, written with `WRITE-PARTITION pre_erase=NO`.
* Same-session verification (`READ-FLASH`, 0x1000): `magic=0x4d4d4d4d ver=4
  size=0x3c lock_state=3 dm_verity=0x0 sboot=0x0 end=0x45454545`.
* Reboot: DA `shutdown(bootmode=NORMAL)` (RGU/WDT reset), device re-enumerated
  `0006 → 2046` two or three times, then booted Android normally.
* Post-boot: identical original image (0 diffs), so **LK re-locked**.

Branch that produced this (inferred, matches all observations):

```
boot_mode_check: nibble!=3, reset-reason class false -> NORMAL
sec_boot_init:
    lock_state()==3            -> run double_check_lock_state
    RPMB read of blocks 0x1DC..0x1DF succeeds -> mirror(+0xC) == 1 (written by the previous locked boot)
    [DC-2] sec_cfg_set_lock_state(locked)  -> header re-signed (deterministic HACC)
           power-off  -> the extra USB re-enumerations
next boot: lock_state==4 -> DC skipped -> normal boot
```

**Caveat (open, §5 Q1):** the 0x200 marker being back means the partition was
restored *beyond* the 0x3C bytes DC touches. Two candidate explanations:
(a) the 8 MB write only reached the first block (0x200), or (b) an additional
full-partition restore path exists (preloader/TEE/`sec_backup`-like). Resolve
with `write_reach_test.py`.

---

## 4. Why ADB/scrcpy is still out of reach

* Normal-mode USB descriptor (`lsusb -v -d 22d9:2046`): `bNumInterfaces=2`,
  class 1/subclass 1 "MIDI function", class 1/subclass 3 "MIDI Streaming".
  No class `ff/42/01` (ADB), no class 6 (MTP/PTP). `adb devices` empty.
* So the kernel's USB config is "MIDI" (`persist.sys.usb.config` family) and/or
  `adbd` is not started. `ro.adb.secure`/`service.adb.tcp.port` are inside
  `boot`/`system`, which are AVB-protected while `lock_state=4`.
* fastboot cannot be entered (see §2.3); without fastboot there is no supported
  way to flash a patched `boot`/`vbmeta` while locked.

---

## 5. Open questions (ordered by value)

**Q1 — does a full-partition `WRITE-PARTITION` really write the whole region?**
`write_reach_test.py` writes an 0x80000-byte image into `para` (marker at 0 and
at 0x7F000), re-reads both ends, then restores the original 0x80000 bytes and
verifies both ends again. If the tail sticks, the 8 MB seccfg write was real and
something restores the partition; if the tail comes back unchanged, the DA write
loop stops early and the unlock payload never reached 0x200+.

**Q2 — what restores `seccfg` (if Q1 shows the write was full)?**
Search the untouched partitions for a seccfg copy: `otp`, `sec1`, `frp`,
`proinfo`, `nvcfg`, `oplusreserve1..6`. A "restore source" that we can patch
would make the forged record survive.

**Q3 — is the real UFS RPMB reachable from DA2 at all?**
`DA_BR.bin` contains `ufs_rpmb_pre_nonce`, `rpmb_ufs_set_wp/clr_wp`,
`rpmb_authen_key_program`, `rpmb_authen_secure_write_protect_conf_block_*`.
mtkclient's `CUSTOMRPMBR/W` patches `mmc_rpmb_send_command` (eMMC path) — the
observed "read succeeds with any key, all zeros" is consistent with the read
never reaching the device. `rpmb_mirror_probe.py` re-checks this in one
read-only session (derived key vs. deliberately wrong key + raw key-status).

**Q4 — can we make the TEE RPMB read fail once?** (Would give [DC-1] / [BR-4]
and therefore a permanently unlocked boot.) Requires either a key mismatch
(impossible once programmed) or making the RPMB region unreadable — no safe
method identified.

**Q5 — META/TEST/factory modes.** `ShutDownModes.TEST/META` exist in DA. LK's
mode table maps several reset-reason classes to modes 1/4/0xC; whether any of
them starts `adbd` is untested. Cheap to try (no flash writes).

**Q6 — ADB via AVB-neutral surface.** If `dm_verity_state`/AVB is not enforced
in the locked state on this build, patching `boot_a` (adding
`ro.adb.secure=0`/`service.adb.tcp.port`) might boot. Must first confirm AVB
behaviour and keep full `boot_a` + `vbmeta_a` backups (recoverable via DA).

---

## 6. Scripts and tools (all in `docs/notes/`, wrappers in `/home/musin/run_*.sh`)

| script | write? | purpose |
|---|---|---|
| `planb_execute.py` | yes (`PLAN_B_GO=1`) | backup `seccfg` → build V4 `lock=3` → `WRITE-PARTITION` → same-session readback → WDT reboot |
| `planb_restore.py` | yes | restore `seccfg` from a backup |
| `planb_recon2.py` | no | RPMB recon (derived key, wrong-key control, scan 0–0x7F, key-status) |
| `seccfg_snapshot.py` | no | full 8 MB `seccfg` dump + diff vs. original + `misc` compare |
| `boot_diag.py` | no | `seccfg` + `expdb` + `misc` via READ-FLASH |
| `f5_dump.py` | no | post-write DA state dump (F5 marker / consumer handle) |
| `para_write_test.py` / `para_restore_zero.py` | yes | write-path proof / cleanup |
| `reboot_fastboot.py` | no (reboot) | DA `SET-BOOT-MODE=FASTBOOT` + reboot |
| **`write_reach_test.py`** | yes (`WRITE_REACH_GO=1`) | **Q1**: does the write reach the partition tail? (with restore) |
| **`rpmb_mirror_probe.py`** | no | **Q3**: mirror blocks **0x1DC–0x1DF** with correct vs. wrong key, raw key-status |

Environment for every run (as in `run_boot_diag.sh`): `OPLUS_PATCH_LEVEL=5`,
`OPLUS_SBC_PATCH=0`, `OPLUS_STORAGE=ufs`, `OPLUS_WRITE_BYPASS=1`,
`OPLUS_FLUSH=1`, `OPLUS_PATCH_CONSUMER=1`, `OPLUS_PATCH_HACC_*`,
**`OPLUS_PATCH_F804_STUB` unset**, `OPLUS_PATCH_F5_MARK` unset.
Fresh CWD (no `.state`, no `hwparam.json`) before each attempt.

---

## 7. Rollback data (do not lose)

| item | path | md5 |
|---|---|---|
| pristine 8 MB `seccfg` (lock=4) | `/home/musin/seccfg_backup.bin` | `12a94a3ffbfc1a7f344e1dd6837b359a` |
| pre-unlock backup (same content) | `/home/musin/seccfg_before_unlock_20261024_200955.bin` | same |
| 13-partition dump | `/home/musin/rmx3630_backup_20261024_095607/` | `MANIFEST.md5` |
| post-reboot snapshot | `/home/musin/seccfg_after_unlock_reboot.bin` | `12a94a…` |

`seccfg` currently on flash = original. The device boots.

---

## 8. Confidence

* **Proven:** all LK addresses/paths in §2.2–2.3 (capstone on `lk_payload.bin`),
  write path and `para`/`seccfg` commits, the 0x200 marker and repo-wide absence
  of a second seccfg copy in dumped partitions, MIDI-only USB descriptor.
* **Observed:** the revert, the USB re-enumerations, `expdb` = 0 (4 MB, OPPO does
  not log LK there), DA RPMB reads all zero. `misc` is **not** zero: it carries a
  BCAB control block at +0x800 (`5f 61 00 00 42 43 41 42 01 02 00 00 ff 00 7f 00 …`,
  14 nonzero bytes), and 6 bytes of it changed during the session — LK rewrote
  the BCAB (checksum + slot fields).
* **Inferred:** DC-2 as the re-lock mechanism (code + behaviour agree, but
  `expdb` does not carry the LK log to prove it on-device); the full-partition
  restore question is explicitly left open.

---

## 4bis. UPDATE 2026-10-24 21:40 — оба вопроса закрыты (test9 / test9a)

### Q1 (answered): WRITE-PARTITION действительно пишет всю партицию

`WRITE_REACH_GO=1 ./run_write_reach.sh` (log `/home/musin/test9`):

```
[+] para: LBA 0x88 base 0x88000 size 0x80000
[*] original: md5=00ff461906b45fc4af74f81839a30069 nonzero=31
[*] test image: 0x80000 B, markers at 0x0 and 0x7f000
[*] head marker: OK (524541434848454144…)
[*] tail marker: OK (52454143485441494c…)
[+] FULL WRITE CONFIRMED
[+] para restored (md5 00ff461906b45fc4af74f81839a30069)
```

⇒ DA программирует весь регион, а не только принятый префикс. Значит
8-МБ запись seccfg дошла до конца, и вернувшийся маркер `0x200` означает
**внешний полный restore** (не «неполную запись»). Источник restore надо искать
в партициях, которые мы ещё не снимали (`otp`, `sec1`, `nvcfg`,
`oplusreserve1..6`), либо в TEE/preloader.

### Q3 (answered): зеркало RPMB реально читается и лежит в 0x1DC

`./run_rpmb_probe.sh` (log `/home/musin/test9a`), блоки 0x1DC–0x1DF:

```
+0x00 sboot=0  +0x04 dev_info=1  +0x08 last_bootmode=0  +0x0C locked_bit=1
+0x10 aux=0    +0x20 "RMX3630RU"
sha256(0..0x3E0) == stored[0x3E0..0x400]        -> hash VALID
```

* Это **настоящие данные RPMB** (модель устройства внутри блока!) — не нули.
* Чтение под заведомо неверным ключом (0xA5×32) вернуло **те же байты** —
  ожидаемо: запрос RPMB-read не подписывается MAC, а заглушка не проверяет
  MAC ответа. Поэтому «успех с неверным ключом» **ничего не доказывает** про
  ключ (это исправлено и в скрипте).
* `GET-RPMB-KEY-STATUS` снова `NOT-EXIST`, но на UFS это слабый сигнал.
* Зеркало = `locked_bit=1` ⇒ именно это и заставляет LK перезалочивать.

### Следующий шаг: `run_rpmb_unlock_mirror.sh`

Скрипт `docs/notes/rpmb_unlock_mirror.py`:
1. dry-run: читает зеркало, строит «unlocked»-блок (`+0xC=0`, пересчёт
   SHA-256) и печатает diff;
2. `MIRROR_WRITE_GO=1`: пишет блоки 0x1DC–0x1DF ключом D, проверяет readback;
3. если запись не встала (ключ не тот → JEDEC auth failure) — **останавливается
   и не трогает seccfg**;
4. если встала — в той же сессии бэкапит seccfg, пишет `lock=3`, проверяет
   readback и перезагружает;
5. `MIRROR_RESTORE=1` — вернуть сохранённый блок (`/home/musin/rpmb_mirror_before.bin`).

Риск: удачная запись сдвигает аппаратный счётчик RPMB; t-base SFSRP может
один раз упасть в «Mismatch between the counters» (trustedStorage/widevine
недоступны на этот бут). Откат — тем же ключом из сохранённого блока.
