# RE: LK seccfg validation on RMX3630 (MT6789) — does LK duplicate the DA2 checks?

Date: 2026-10-23. Tool: radare2 (`-a arm -b 64 -m 0x50000000`). Target:
`docs/notes/rmx3630-lk/lk.img` (2,884,672 B). Companion notes:
`rmx3630-da2/README.md`, `re-reserve2-master.md`, `re-sec-dispatch.md`
(DA2 model: two 0x3c-byte "MMMM" records, main @+0x00 / backup @+0x3c,
SHA256-of-header + HACC anti-clone scramble, lock_state @ record+0xC).

## TL;DR (answers)

1. **Yes, LK contains a full seccfg parser/validator and it duplicates the DA2
   model exactly**: V4 record layout (magic `MMMM` @+0, ver @+4, size @+8,
   lock_state @+0xC, dm_verity @+0x10, sboot_runtime @+0x14, `EEEE` @+0x18),
   main record at partition offset **+0x00**, backup record at **+0x3C**,
   hash = **plain software SHA-256 over the first 0x1C header bytes**, then the
   0x20-byte digest is scrambled through the **HACC hardware AES engine at
   physical 0x1000A008** (accessed via the `0xFFFF00001000A008` alias) before it
   is compared with the stored digest at record+0x1C.
2. **LK does verify the hash — it does not just read +0xC.** Reading +0xC only
   happens *after* `sec_check_major_integrity_seccfg()` returns 0. On any
   validation failure the getters fail safe to "locked".
3. **Fail behavior: no Red State.** There is no "red state" / "enterprise"
   string in LK; AVB red/yellow are the AVB layer (yellow *and* red lead to the
   same power-off block as the seccfg path, orange only shows a banner). On
   seccfg hash/magic failure LK (a) fails safe to LOCKED in every getter, and
   (b) **silently rewrites a default LOCKED record to flash** (init-NV: magic
   MMMM, ver=4, size=0x3C, lock_state=1, dm_verity=0, sboot=0, EEEE, re-signed
   and HACC-scrambled). If only the main record is bad but the backup validates,
   LK **self-heals** by copying backup→main and rewriting flash.
4. **RPMB wins over a forged seccfg unlock.** `double_check_lock_state()
   (0x500556C4)` runs on every boot where seccfg says UNLOCKED
   (`sec_cfg_get_lock_state` wrapper returns "is-unlocked = (state!=3)"; the
   RPMB check is only entered when that is 0). It reads the RPMB boot-info
   block (`km_client_read_rpmb_boot_info`, 0x3E0-byte block + 0x20-byte SHA-256
   at +0x3E0), and if the RPMB mirror field at block+0xC is 1 it calls
   `sec_cfg_set_lock_state(locked)` — which re-signs and rewrites the seccfg
   record — prints `%s rebooting the device`, then `verify boot fail, it will
   power off!` and powers off after a 3 s delay. **If RPMB is disabled or the
   read fails, it only logs and continues** — that is the only crack in the
   RPMB mirror.

---

## 1. Container / payload layout

The file is a MediaTek multi-image secure container (magic `0x58881688` per
entry, trailer magic `0x58891689`, cert blocks `0x12345678` / `0x12345622`).
Each image entry is `0x30` bytes of header (magic, size, name, offset, …)
followed by `cert1` (0x6C5 B) + `cert2` (0x3F3 B) hash certificates.

| payload start | name | size | content |
|---|---|---|---|
| 0x000200 | `lk` | 0xE4600 | ARM64 LK (analyzed here) |
| 0x0E4800 | `cert1`/`cert2` | 0x6C5/0x3F3 | certs for lk |
| 0x0E56D0 | `bl2_ext` | 0xB57A0 | 2nd binary (contains its own copy of the same seccfg strings @file 0x15FAFA) |
| 0x19BF40 | `aee` | 0xF3740 | 3rd binary (third copy of seccfg strings @file 0x22074A) |
| 0x290750 | `lk_main_dtb` | 0x2EC19 | device tree |

**Load base = 0x50000000 (determined, not guessed).** The payload is compiled
PC-relative (no absolute DRAM pointers in literal pools except one data table).
The AVB boot-state string pointer table at payload offset 0xAC700 contains
`0x50FAC5D6 / 0x50FAC5FB / 0x50FAC620 / 0x50FAC642`, which map *exactly*
(offset − table index) onto the strings
`androidboot.verifiedbootstate=orange/yellow/red/green` at payload 0xAC5D6…:
`ptr − 0xAC5D6..0xAC642 = 0x50000000` for all four entries. So
**VA = payload_offset + 0x50000000** (payload offset 0 == VA 0x50000000).
All addresses below are real VAs. (Analysis was first done at a provisional
0x40000000 base; add 0x10000000 to any old address.)

## 2. Function table

| VA | name / anchor | notes |
|---|---|---|
| 0x500827E8 | **sec_check_major_integrity_seccfg** | string anchor `SEC_CFG` + `sec_check_major_integrity_seccfg` (0x500B8FDB/0x500B8FE3). Master validator. |
| 0x500824FC | record digest validator (main slot) | prints "fail in seccfg hash calculation" (0x500B8FA9) and "hacc encrpytion fail" (0x500B9004) |
| 0x500826DC | init-NV writer (default LOCKED record) | no string; reached on total validation failure |
| 0x500825EC | "sec_update" — re-sign + commit main record | `[%s] %s` (SEC_CFG, "sec_update" 0x500B903F) |
| 0x50082AE0 | **sec_cfg_get_lock_state** (core) | reads `[0x5014484C]` = record+0xC |
| 0x50082E10 | is-unlocked wrapper over getter | `*out = (lock_state != 3)`; thunk 0x50032670 |
| 0x50082B30 | **sec_cfg_set_lock_state** (core) | copies main→bak, re-signs, writes both; thunk 0x500326B0 |
| 0x50082E88 | logical set-lock wrapper | arg 0 → set 3 (unlock); arg 1 → set 2 (if cur==1) else 4 |
| 0x50082C5C | dm-verity-state getter (record+0x10) | caller 0x5005360C = set_dm_verity_state |
| 0x50082CD4 | dm-verity-state setter | caller 0x500536DC = clear_dm_verity_status |
| 0x5007AB58 | hash dispatcher (by boot medium: 0x50003890) | ==1 → 0x5007B910; ==2 → 0x5007B538/660/6A4; else → **0x5007B1D0 = software SHA-256** (IV constants 6A09E667/BB67AE85/3C6EF372/A54FF53A/510E527F at 0x5007B1EC…) |
| 0x50076EB8 | HACC scramble wrapper (buf, 0x20) | → 0x5007C838 init, 0x5007C900 AES block loop, 0x5007C97C deinit |
| 0x5007C838/900/97C | HACC HW access | base built as `0xFFFF0000_1000A008` (`mov x19,#0xA008; movk x19,#0x1000,lsl 16; movk x19,#0xFFFF,lsl 48`); regs +0x08..0x14 key, +0x18..0x34 IV(=0), seeds 0x9ED44000/0x00E884A1/0xE3F083BD/0x2F4E6D8A @+0x38..0x44, cfg @+0xB4, status poll bit15, out @+0x48..0x54 |
| 0x50083848 / 0x50083904 | partition read / write by name | `0x50069B84` name lookup → `0x50069C10` block IO; "seccfg" name string is the tail of `"sec_get_seccfg"` @0x500B9241 |
| 0x5000262C | sboot/lock boot init | prints `efuse_value is %d, sbc_enable is %d, daa_enable is %d`, sets `mtkboot.sbootstate=on` cmdline, prints `sboot_state is %d, lock_state is %d, isunlocked is %d` (0x5008E089), then set_boot_info_to_rpmb; called from 0x5000E270 (bootstrap, fcn.5000E1C0) |
| 0x500556C4 | **double_check_lock_state** | RPMB cross-check, see §5 |
| 0x50054674 | km_client_read_rpmb_boot_info | RPMB read + hash verify (0x50055364 over +0x3E0, 0x20 B) |
| 0x50054744 | set_boot_info_to_rpmb | prints `set_boot_info_to_rpmb: secureboot_state:%u lock_state:%d boot_mode:%d` (0x500ACA50) |
| 0x50053F3C/60/6C | avb boot-state cmdline / get / set | global 0x500C4FA8; table 0x500AC700 = {green,yellow,orange,red} strings |
| 0x50053F78 | boot-state banner | orange → "Orange State / Your device has been unlocked and can't be trusted / Your device will boot in 5 seconds" + 5 s delay; **state 1 (yellow) and 3 (red) → jump into the power-off block 0x500557C0** |
| 0x500557C0 | power-off block | wait loop, `verify boot fail, it will power off!` (0x500ACEEF), mdelay(0x2DC6C0), power off |

Dead strings (present, **zero code xrefs** in the LK payload — verified by a
full ADRP+ADD/ADR scan): `[%s] Show seccfg status`,
`[%s] Major/Bak SECCFG_MAGIC_CORRECT/VALID/NOT_VALID/MAGIC_INCORRECT`,
`sec_test_init_seccfg_major_NV`, `sec_init_seccfg_bak`. The same strings are
alive in the `bl2_ext` and `aee` copies. So the "Show seccfg status" printer
known from other builds was stripped/not called in this LK.

## 3. The validator (annotated disasm)

### 3.1 Per-record digest check — 0x500824FC (`R = 0x50144840`, main slot)

```asm
0x5008250C  adrp x8, 0x50144000        ; record slot R = 0x50144840
0x50082510  ldr  w8, [x8, 0x840]       ; R->magic
0x50082514  mov  w9, #0x4D4D ; movk w9, #0x4D4D, lsl 16   ; "MMMM"
0x50082520  cmp  w8, w9
0x50082528  b.ne 0x5008255C            ; magic wrong -> err = 0x10003004
0x50082534  mov  x2, sp ; mov w1, #0x1c
0x50082544  bl  0x5007AB58             ; SHA-256 over R[0..0x1C) -> sp (0x20)
0x50082548  cbz w0, 0x50082564
        ; fail -> print "[%s] %s, fail in seccfg hash calculation. (0x%x)"
        ;          (SEC_CFG, sec_check_major_integrity_seccfg), ret 0x10003004
0x50082564  bl  0x50076EB8             ; HACC-encrypt sp (0x20 bytes, in place)
0x50082570  cbz w0, 0x500825AC
        ; fail -> print "[%s] %s, hacc encrpytion fail. (0x%x)", ret err
0x500825AC  adrp x8, 0x50144000 ; add x8, x8, 0x85c   ; R+0x1C = stored digest
        ; XOR-compare 32 bytes: (R+0x1C..0x3C) vs sp, OR-accumulate
0x500825E0  cmp  x8, #0
0x500825E4  csel w19, wzr, w20, eq     ; w20 = 0x10003000 (generic fail code)
0x500825E8  b   0x50082598             ; return w19 (0 == VALID)
```

So the check is: `HACC_encrypt(SHA256(record[0:0x1C])) == record[0x1C:0x3C]`.
Same primitive pair as DA2 (`0x4003a2d4` decrypt + `0x40035030` scramble),
here done in the forward (encrypt) direction. The HACC key/seed words are
hardcoded (0x9ED44000, 0x00E884A1, 0xE3F083BD, 0x2F4E6D8A) — the anti-clone
scramble is the standard SEJ-style HACC config, not device-specific in code.

### 3.2 Master check — 0x500827E8 sec_check_major_integrity_seccfg

```
R_main = 0x50144840 (0x3C bytes), R_bak = 0x50144880 (0x3C bytes)
err base w19 = 0x00100006
1. malloc(0x3000); read_partition("seccfg", buf, 0, 0x3000)   @0x50082868
   fail -> err, free, return
2. memcpy(R_main, buf+0x00, 0x3C);  memcpy(R_bak, buf+0x3C, 0x3C)
3. if (R_main.magic == MMMM):
       if (digest_check(R_main) == 0):            ; 0x50082910 bl 0x500824FC
           goto MAIN_OK (0x500829B4)
   ; main magic wrong OR hash mismatch:
4. if (R_bak.magic == MMMM):                      ; 0x5008291C
       SHA256(R_bak[0:0x1C]) -> sp ; HACC(sp)     ; 0x50082944 / 0x50082954
       if (sp == R_bak+0x1C)  -> 0x50082A04:      ; BACKUP VALID
           print "[%s] %s" (SEC_CFG, "sec_restore")
           memcpy(R_main, R_bak, 0x3C)            ; self-heal
           write_partition("seccfg", R_main, off=0, len=0x3C)
           fail -> "[%s] %s, seccfg restore fail." (0x500B9248)
           return 0
5. else (both records unusable) -> 0x50082990 bl 0x500826DC
       ; init-NV: build default record
       ;   [0]=MMMM, [4]=4(ver), [8]=0x3C(size), [0xC]=1(LOCKED),
       ;   [0x10]=0(dm_verity), [0x14]=0(sboot), [0x18]=0x45454545
       ;   SHA256(0x1C) -> HACC -> store digest @+0x1C
       ;   write_partition("seccfg", R_main, 0, 0x3C); re-read
       ;   malloc-fail -> err 0x00100006
6. MAIN_OK path: if (R_bak.magic == MMMM)
       write_partition("seccfg", zeros, off=0x3C, len=0x3C)  ; clear bak
       fail -> "[%s] %s, clear bak fail." (0x500B921F)
   return 0
```

Note the record layout produced/expected matches mtkclient's `SecCfgV4.parse`
(`Library/Hardware/seccfg.py`): magic, seccfg_ver=4, seccfg_size=0x3C,
lock_state@+0xC, dm_verity_state@+0x10, sboot_runtime@+0x14, endflag 0x45454545,
hash = last 0x20 bytes.

### 3.3 Getter/setter

```asm
; sec_cfg_get_lock_state core 0x50082AE0 (thunk 0x500326AC, wrapper 0x50082E10)
0x50082AF4  bl 0x500827E8              ; full validation first
0x50082AF8  adrp x8, 0x50144000
0x50082AFC  ldr w8, [x8, 0x84C]        ; *out = R_main->lock_state  (+0xC)
0x50082B0C  csinc w8, w8, wzr, eq      ; on error -> *out = 0 (fail-safe)
0x50082B18  csel w0, wzr, w9, eq       ; ret 0 or 0x10003000
; wrapper 0x50082E10: *out2 = (lock_state != 3)   ; "isunlocked"
```

The value at +0xC is read **only after** the record passed magic+hash+HACC.
`sec_cfg_set_lock_state` core (0x50082B30): validate → `memcpy(R_bak, R_main)`
(print `SEC_CFG`/`"sec_backup"`) → modify → re-sign (0x500825EC-style:
SHA256+HACC+store digest) → `write_partition("seccfg", …, 0, 0x3C)` → re-read
verify.

Logical wrapper 0x50082E88 (thunk 0x5003266C): `arg==0 → set 3 (unlock)`;
`arg==1 → current==1 ? set 2 : set 4`. Printed "locked"/"unlocked" via
0x50090037/0x5009003E. Callers: only double_check_lock_state (forced lock).
The unlock path (set 3) is reachable from the fastboot
`flashing unlock` flow region (0x50090047 "flashing unlock",
"Unlock the device successfully! Will return to fastboot in 3s"), i.e. the
value written on a legitimate unlock is 3.

## 4. Q2 verdict — verify or just read?

**It verifies.** Every consumer of the lock state goes through
`0x500326AC/0x500326B0` thunks → `sec_check_major_integrity_seccfg` →
digest check (SHA-256 + HACC-AES at 0x1000A008). A forged record with
`lock_state=3` but a wrong/stale digest fails validation; the getter then
returns `*out = 0` with error `0x10003000`, the is-unlocked wrapper maps that
to `isunlocked = 1` (locked semantics), and the dm-verity getter likewise
fails safe. The DA2 lesson ("the hash must be recomputed with the device-bound
scramble") applies unchanged — and here the scramble is straight HACC-AES ECB
with fixed seeds, not SEJ.

## 5. Q3 verdict — failure policy

Branches enumerated from the code:

* **Hash mismatch / MAGIC_INCORRECT (both records)** → `init-NV` writer
  0x500826DC builds a **default LOCKED record (lock_state=1)**, re-signs it and
  **writes it to the seccfg partition** — a forced re-lock, done silently (no
  banner, no reboot). All getters fail safe to locked in the same boot
  regardless.
* **Main bad / backup good** → backup copied over main and rewritten
  ("sec_restore" path) — self-heal, boot continues with the backup's state.
* **Partition read fails** → error (`0x10003000`-family), getters fail safe to
  LOCKED; boot continues (no red state, no reboot).
* **No "Red State"/red-state download mode in LK**: no such strings. The
  AVB states exist (green/yellow/orange/red via 0x500C4FA8), and for
  yellow(1) and red(3) the banner function jumps into the same
  `verify boot fail, it will power off!` block (0x500557C0) — power-off, not
  fastboot. Orange only shows "Your device has been unlocked and can't be
  trusted … will boot in 5 seconds".
* **RPMB mismatch (seccfg=unlocked, RPMB mirror=1)** → force re-lock of the
  seccfg record + `%s rebooting the device` + `verify boot fail, it will
  power off!` + 3 s + power off (details in §6).
* There is **no** branch that reboots to fastboot on seccfg corruption; the
  fastboot string set ("FASTBOOT mode…") is only reached from key-combo /
  boot-mode logic.

Policy call chain for the "sboot_state is %d, lock_state is %d, isunlocked is
%d" site (fcn.5000262C, called at 0x5000E270 from the LK main/bootstrap
flow):

```
sec_boot_init (0x5000262C):
  get sbc/daa efuse info -> print
  if sboot bit: append "mtkboot.sbootstate=on" to cmdline (0x50018204)
  is_unlocked = sec_cfg_get_lock_state wrapper  (0x50032670)
      -> underlying: sec_check_major_integrity_seccfg + [record+0xC]; fail->locked
  if is_unlocked == 0:                    ; i.e. seccfg says UNLOCKED(3)
      double_check_lock_state(&lock_state)   ; RPMB mirror, see §6
  print "sboot_state is %d, lock_state is %d, isunlocked is %d"
  set_boot_info_to_rpmb(sboot, lock_state)   ; 0x50054744
      fail -> "%s set boot info to rpmb fail !!!"
```

So the boot policy input is *sboot efuse bit AND validated seccfg lock_state*;
the seccfg value can never be "unlocked" unless it survived both the hash
check and the RPMB mirror.

## 6. Q4 verdict — RPMB vs forged seccfg

`double_check_lock_state` 0x500556C4 (string anchors
`%s: get_rpmb_lock_state: read boot info from rpmb fail status = %d`
0x500ACF35, `get_rpmb_lock_state` 0x500ACF7A,
`%s: seccfg_lock_state is 0, rpmb_lock_state is %d, so need change seccfg
state` 0x500ACF8E, `double_check_lock_state` 0x500ACFDF,
`%s: sec_set_device_lock, change seccfg lock state failed !!!` 0x500ACFF7,
`%s rebooting the device` 0x500AD036, `%s: seccfg_lock_state is the same as
rpmb_lock_state. It will do nothing and boot normal.` 0x500AD04F):

```
0x500556C4  double_check_lock_state(out):
  memset(sp, 0x400); km_client_read_rpmb_boot_info(sp)     ; 0x50054674
    ; reads 0x3E0-byte boot-info block from RPMB (0x50055508),
    ; SHA-256 of block[0:0x3E0] vs block[0x3E0:0x400] (0x50055364)
  if read/hash fail:
      print "…get_rpmb_lock_state: read boot info from rpmb fail status=%d"
      print "…rpmb not enable or get_rpmb_lock_state failed status=%d !!!"
      return                        ; <-- NO enforcement, seccfg stands
  if (rpmb_block[0xC] == 1):        ; RPMB mirror says locked
      print "seccfg_lock_state is 0, rpmb_lock_state is 1, so need change…"
      *out = 0
      sec_cfg_set_lock_state_wrapper(1)   ; 0x50082E88 -> rewrites seccfg LOCKED
      fail -> "sec_set_device_lock, change seccfg lock state failed !!!"
      print "%s rebooting the device"; LED/key setup; wait loop
      print "verify boot fail, it will power off!"; mdelay(0x2DC6C0); power off
  else:
      print "…seccfg_lock_state is the same as rpmb_lock_state. …"
  ; tail (0x50055808+): OplusInitRecordData / OplusRecordFastbootUnlock —
  ; re-reads "oplusreserve1" (0x5008EEFA) and records unlock attempts (SHA-256
  ; of serial, "hash data wrong: " 0x500AD1CF) — separate oplus bookkeeping.
```

**Who wins: RPMB.** If seccfg is forged to state=3 (unlocked) while the RPMB
boot-info mirror (field +0xC of the km_client block, written by
`set_boot_info_to_rpmb` as `w22 = (lock_state_arg == 0) ? 1 : 0` — exact
semantics of the 0/1 encoding are the one part I could not fully pin down,
see uncertainty below) disagrees, LK rewrites seccfg as locked and powers
off. The check only runs on boots where seccfg claims unlocked, so a locked
device never triggers it. If the RPMB read fails or RPMB is reported
disabled, the function returns without action — so the RPMB mirror is an
*advisory-but-enforced* check, not a hard dependency.

## 7. Practical notes (for the unlock campaign)

* A forged seccfg with state=3 must carry a valid `HACC(SHA256(hdr))` digest.
  The digest depends only on the 0x1C header (no HRID/serial input visible in
  the LK path), so it is *computable offline* if the HACC key/seed semantics
  are reproduced (fixed seeds in code; key source = HACC internal — same
  engine the DA used, so a DA-side or mtkclient-side HACC emulation that
  already passes DA2 validation should produce byte-identical digests).
* Even with a valid digest, the unlock will only survive boot if the RPMB
  boot-info block agrees; otherwise the device re-locks and powers off on the
  next boot.
* `seccfg` is read/written purely **by partition name** through GPT lookup
  (0x50069B84) — no hardcoded LBAs.

## 8. Confidence

* High: base 0x50000000 (4/4 pointer-table match); validator flow, record
  layout, SHA-256 (SW constants) + HACC-AES at 0xFFFF00001000A008; getter/
  setter semantics; the force-lock + power-off path; "Show seccfg status"/
  "SECCFG_MAGIC_*" strings having no xrefs in this payload.
* Medium: exact meaning of the RPMB mirror bit (block+0xC) and of seccfg
  lock_state values 1/2/4 (naming from OPLUS convention + observed device
  value 4; the code only proves the transitions `0→3`, `1→2`, `else→4`).
* Low/unresolved: which of `bl2_ext`/`aee` also execute this validator at
  runtime (same code is linked into both; not traced); the precise field
  offsets inside the 0x3E0 RPMB boot-info block beyond the +0xC field read by
  double_check; caller of the banner function 0x50053F78 (no direct xrefs
  found — likely reached via a thunk/table).
