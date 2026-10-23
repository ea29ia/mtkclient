# RE: LK "rescue surfaces" on RMX3630 (MT6789) — fastboot dispatcher, META/factory entry, misc/BCB, recovery fallback

Date: 2026-10-23. Target: `docs/notes/rmx3630-lk/lk.img`, payload `lk` (file off 0x200,
size 0xE4600). VA = payload_offset + 0x50000000 (per `re-lk-seccfg.md`; all addresses
below are real VAs). Method: r2 (`-a arm -b 64 -m 0x50000000`) + a custom ADRP/ADD/BL
cross-reference scanner (`/tmp/opencode/lk/refs2.py`). Companions:
`re-lk-seccfg.md`, `re-lk-rpmb-lock.md`, `re-preloader-daa-lk.md`.

## TL;DR

1. **fastboot_register = 0x50005768**, command list head `0x501120B0`, dispatcher
   (command loop) `0x50005BE0…0x50006120` (string anchors `fastboot: processing
   commands` @0x5008F56F, `fastboot: %s[len:%d]` @0x5008F593). **27 commands
   total**: 12 registered inline in `fastboot_init` (0x50006230…0x50008210), 15
   from a static table at **0x500BDD10** (0x18 B/entry, iterated at 0x50006428).
   NOTE: table pointers are stored **skewed by +0xF00000** (uniform, verified
   against string addresses); subtract 0xF00000 to get the real VA.
2. **Gating (proven, per-command flags):** each registration carries two booleans
   (node+0x14 = flagA, node+0x18 = flagB). Dispatcher logic at 0x50005F0C-0x50005F6C:
   on an S-CHIP (`0x5007EE3C` → "[%s] S-CHIP"), a command is executed iff
   **flagA==1 && flagB==0**, or the device is unlocked (seccfg lock_state==3 via
   `0x500326AC`→0x50082AE0). flagA==0 commands (`continue`, `oem usb2jtag`) and
   flagB==1 commands (`flash:`, `erase:`, `oem ultraflash*`, `oem get_socid`,
   `oem printk-ratelimit`) are **denied while locked** ("No support by lock
   control" 0x5008F615 / "No support by security control" 0x5008F5F6).
   getvar/reboot*/set_active/download:/flashing unlock/lock/**oem p2u/oem
   off-mode-charge/mrdump oems/oem cdms work on a LOCKED device.**
3. **No `fastboot boot` command exists** (no registration, no handler). So no
   RAM-boot rescue via fastboot.
4. **META/factory machinery is fully present** (app/mt_boot/meta.c): boot-mode
   jump table at 0x5000E1A0 (byte table 0x50093A89): 0=NORMAL, 1=META,
   2=RECOVERY, 3=UNKNOWN, 4=FACTORY, 8=POWEROFF-CHARGING, 0x63=FASTBOOT.
   Mode sources: preloader PL boottags (`platform_pl_boottags_boot_mode_hook`
   0x8E62E) → [0x50112024]; hardware reg `0xFFFF000010007024` low nibble
   (0x50040538); misc BCB; reboot-reason table. **We cannot inject ATAGs —
   they come from the preloader.**
5. **misc is used in two ways** (both DA2-writable): (a) raw BCB — LK reads
   misc[0..0xE] and if it starts with **"boot-recovery"** boots RECOVERY;
   `reboot-recovery`/`reboot-fastboot` handlers write a 0x1800-byte
   zeroed block with the ASCII command at offset 0 (0x50006928); (b) OPLUS/AB
   boot_control block with magic **"BCAB"** (0x42414342 at buf+4), read/written
   by `read_write_partition_info` (0x5001E040) / `set_active_slot` (0x5001E338).
6. **Killer finding:** `fastboot flashing unlock` (handler 0x500076A8) IS
   runnable on a locked device, and its gate `get_unlock_ability` (0x50007BEC)
   reads **the last 4 bytes of the `frp` partition** (offset `size-4`); any
   nonzero value allows unlock ("frp missing → allowed=1" path at 0x50007C78).
   If fastboot is reachable by key combo, and frp[-4:] != 0, a dead-screen
   device can be unlocked interactively with the volume keys (the confirm UI is
   button-driven, no display needed beyond text output).

---

## 1. Q1 — fastboot dispatcher and full command table

### Infrastructure

| item | VA |
|---|---|
| `fastboot_register(name, cb, flagA, flagB)` | 0x50005768 (list push at 0x501120B0; node: next@0, name@8, len@0x10, flagA@0x14, flagB@0x18, cb@0x20) |
| command dispatcher loop | 0x50005BE0 (first match at 0x50005C40), main loop 0x50005CE4, match `0x5006C990` memcmp, execute `blr` @0x50005F68 |
| S-CHIP check `0x5007EE3C` (wrapped by 0x5007EF04) | result 1 = secure chip ([%s] S-CHIP / NS-CHIP strings 0x500B8A89/96) |
| lock-state read in dispatcher | `bl 0x500326AC` → `sec_cfg_get_lock_state` core 0x50082AE0 |
| deny msg A | "No support by security control" 0x5008F5F6 (0x50006000 path) |
| deny msg B | "No support by lock control" 0x5008F615 (0x50005FB0 path: flagB!=0 && lock_state!=3) |
| unknown command | "[unknown command]*[%s]*" 0x5008F63F, "unknown command" 0x5008F658 |
| state machine global | [0x501120AC] (1=cmd, 2=STATE_RETURN, 4=download) |

### Gating rule (derived from 0x50005F0C-0x50005F6C, proven)

```
exec if (flagA==1 && flagB==0)                 ; "public" command
   or (S-CHIP==0 && flagB==0)                  ; insecure build
   or (lock_state == 3 /*unlocked*/)           ; everything on unlocked dev
else FAIL "No support by lock/security control"
```

i.e. on a LOCKED S-CHIP production device: allowed = flagA==1 && flagB==0.

### Table of registrations

Inline registrations (fastboot_init):

| cmd (VA of string) | handler | flagA(w2) | flagB(w3) | locked? |
|---|---|---|---|---|
| `getvar:` 0x5008F794 | 0x50006808 | 1 | 0 | OK |
| `download:` 0x50090844 | 0x50008224 | 1 | 0 | OK |
| `reboot` 0x50091046 | 0x500068BC | 1 | 0 | OK |
| `reboot-bootloader` 0x5008F79C | 0x500068E8 | 1 | 0 | OK |
| `reboot-fastboot` 0x5008F7AE | 0x5000691C (→BCB writer 0x50006928 "boot-fastboot") | 1 | 0 | OK |
| `reboot-recovery` 0x5008F7BE | 0x50006A18 (→BCB writer 0x50006928 "boot-recovery") | 1 | 0 | OK |
| `continue` 0x5008F7CE | 0x50006AB8 | **0** | 0 | **DENIED when locked** |
| `set_active:` 0x5008F7D7 | 0x50006A24 | 1 | 0 | OK |
| `download:`(2nd reg site 0x5000818C; handler 0x50008224) | — | 1 | 0 | OK |
| `flash:` 0x5009085E | 0x500082DC | 1 | **1** | **UNLOCK only** |
| `erase:` 0x5009084E | 0x500083CC | 1 | **1** | **UNLOCK only** |
| `oem ultraflash:` 0x50090855 | 0x500083CC (same fn as erase) | 1 | **1** | **UNLOCK only** |
| `oem ultraflash_en` 0x50090865 | 0x50008664 | 1 | **1** | **UNLOCK only** |

Static table @0x500BDD10, 15 × 0x18 entries, consumed by the loop at
0x50006428 (pointers stored +0xF00000; entries #15+ are garbage/end):

| # | cmd | handler (true VA) | A | B | locked? |
|---|---|---|---|---|---|
| 0 | `oem p2u` | 0x50006AD8 | 1 | 0 | OK (UART mux on/off) |
| 1 | `oem dump_pllk_log` | 0x50006B60 | 1 | 0 | OK |
| 2 | `oem printk-ratelimit` | 0x50006C00 | 1 | 1 | UNLOCK only |
| 3 | `oem usb2jtag` | 0x50006C94 | **0** | 0 | **DENIED when locked** |
| 4 | `oem off-mode-charge` | 0x50006D6C | 1 | 0 | OK |
| 5 | `oem mrdump_out_set` | 0x50006E00 | 1 | 0 | OK |
| 6 | `oem mrdump_fallocate` | 0x50006E5C | 1 | 0 | OK |
| 7 | `oem mrdump_chkimg` | 0x50006FC0 | 1 | 0 | OK |
| 8 | `oem get_socid` | 0x50007004 | 1 | 1 | UNLOCK only |
| 9 | `flashing unlock` | 0x500076A8 | 1 | 0 | OK (see §6) |
| 10 | `flashing lock` | 0x5000792C | 1 | 0 | OK |
| 11 | `flashing get_unlock_ability` | 0x50007B8C | 1 | 0 | OK |
| 12 | `oem set_enckey` | 0x500075D4 | 1 | 0 | OK (SEC oemkey) |
| 13 | `oem get_key` | 0x500075A8 | 1 | 0 | OK |
| 14 | `oem cdms` | 0x50053820 | 1 | 0 | OK — calls `clear_dm_verity_status` (0x500536DC, seccfg +0x10) after printing "cdms" (0x500AC36E) |

Notable absences (strings searched, zero hits / zero registrations): **no
`boot`**, no `oem get_identifier_token`, no `oplusunlock`, no `oem edl`, no
`flashing unlock_critical`, no `flashing apex`/`flashing lock_critical`, no
`flashing unlock_bootloader` variants. Also present but internal: `Tdownload:`
string 0x50090843 (variant label inside the download path).

Handler notes:
- `flash:` 0x500082DC: calls 0x50008730 which is **`mov w0,1; ret`** (stub —
  the "skip fastboot verify when secureboot is off!" string is dead in this
  path); then sparse-magic (0xED26FF3A) vs raw branch; the oplus download-auth
  compare (first 0x20 B vs [0x501121C0], gated by [0x500BF60C] && [0x501121E8])
  belongs to the ultraflash path.
- `reboot-bootloader`: set_reboot_reason(3) via 0x50040514 (writes the HW
  reboot-reason register `0xFFFF000010007024`), then 0x5001FBE0(1,7) reboot.
  **No misc write on this path.**

## 2. Q2 — `fastboot boot` from memory

**Not present.** No command registered with prefix "boot" (registration list is
exhaustive above); no AVB-bypass boot-from-RAM path in fastboot. `download:`
loads into RAM but the only consumers are ultraflash (unlock-gated) and the
download-auth compare. **Verdict: no RAM-boot rescue via fastboot on this
build.**

## 3. Q3 — META / factory mode

Boot-mode enum and banner dispatcher (0x5000E180): byte jump table at
**0x50093A89**, targets relative to 0x5000E1AC:

| value | mode | banner string |
|---|---|---|
| 0 | NORMAL | "=> NORMAL MODE" 0x50092A25 |
| 1 | META | "=> META MODE" 0x50092A36 |
| 2 | RECOVERY | "=> RECOVERY MODE" 0x50092A57 |
| 3 | UNKNOWN | "=> UNKNOWN BOOT" 0x50092A9A |
| 4 | FACTORY | "=> FACTORY MODE" 0x50092A45 |
| 8 | POWER-OFF-CHARGING | "=> POWER OFF CHARGING MODE" 0x50092A6A |
| 0x63 | FASTBOOT | "=> FASTBOOT MODE" 0x50092A87 |

Mode-selection function `boot_mode_check` (0x5000AAAC, prints
"boot_mode_check:g_boot_mode is set %u" 0x50090FC8), decision inputs:

1. **Early mode getter 0x500036C0** = [0x50112024], written by
   `platform_pl_boottags_boot_mode_hook` (string 0x5008E62E) — i.e. **preloader
   PL boottags/ATAGs**. Values 1/7 → mode 7; 4 → mode 4 + cmdline
   `oplus_ftm_mode=factory1` (0x50090F9A).
2. **HW reg 0x50040538** reads `0xFFFF000010007024` & 0xF (MTK boot-arg
   register, written by preloader): 2 → RECOVERY, 3 → FASTBOOT (0x63), 0xC →
   agingtest branch (`oplus_ftm_mode=ftmaging` 0x50091064 + **`androidboot.
   selinux=permissive`** 0x500910B8 + factory), 0xA→0xC, 0xB → passthrough.
3. **misc BCB**: reads 14 B at misc offset 0; prefix `boot-recovery` → RECOVERY.
4. **Reboot-reason table**: 0x5000AD08 compares [0x50112020] (reboot reason,
   getters 0x500036B4/0x500036C0) against table **{0,4,6,8,9,0xA,0x1E,0x1F,
   0x20,0x21} @0x500BF6A8** (matches HW_reboot/SPM_Thermal_reboot/…
   name strings at 0x500BF7DC..0x500BFB20); unmatched reasons go through
   0x5001EBC0/0x5001ED9C/0x5001EC48 → mode 0 (normal) or 8 (charging).
5. `0x500053E0` (boot-state getter) nonzero → RECOVERY.

META plumbing (app/mt_boot/meta.c @0x5000C4C0-0x5000C6E0):
- `atag,meta` tag parsed at 0x5000C61C (search kernel boot tags for
  "atag,meta" 0x500914C1); meta com id/type/uart copied into 0x50113298…
  and repacked into an ATAG for the kernel (0x50038960 builder).
- cmdline for META/FACTORY (mode==1 or 4): `androidboot.init_rc=/system_ext/
  etc/init/hw/meta_init.system.rc` (0x92606), `oplusboot.mode=meta|factory`
  (0x5000D3BC printer), `androidboot.meta_log_disable=0/1`, and
  `androidboot.usbconfig=1/0/2` (0x915A0 strings) driven by flags in
  [0x5011329C] (bit0=adb) / [0x501132A4].
- Print "adb:%d elt:%d meta_com_id:%x" (0x50091B7E) site 0x5000C508.

**ADB in META/FACTORY:** LK only exports the cmdline knobs (`usbconfig`,
`meta_init.*.rc`, `meta_log_disable`); whether adbd comes up unauthorized
(`ro.adb.secure=0`) is a userspace property — **inference (medium)**: oplus
factory/meta builds conventionally run adb open, and the presence of
`usbconfig=1` + `meta_init` plumbing strongly suggests it. **But the entry
vector is the preloader**, not something we control from flash: the
`0x10007024` boot-arg register and ATAGs are produced by preloader key
detection / RTC state. From our position (DA2 flash write only) there is **no
proven path to force META**.

## 4. Q4 — misc partition / BCB / boot reason

Two structures (misc partition, both reachable from DA2 writes):

1. **Raw BCB (command string)** — proven both directions:
   - read: `boot_mode_check` opens "misc" (0x50069B84), reads **0xE bytes at
     offset 0** (0x50069C10 block IO), `memcmp` against "boot-recovery"
     (substring pointer 0x5008F7C0 of "reboot-recovery"); match → mode 2.
   - write: `0x50006928(mode_string)` — open "misc", memset a **0x1800**-byte
     buffer, copy the command string to offset 0, write the whole 0x1800 at
     misc offset 0 ("bio_write failed" 0x5008FB88 on error). Callers:
     `reboot-recovery` → "boot-recovery" (13 B), `reboot-fastboot` →
     "boot-fastboot" (0x5008F7B0).
   - **No standard Android bootloader_message struct** (no "bootloader",
     no status/cookie fields; the read only ever looks at offset 0).
   - **DA2 action: write "boot-recovery\0" + zeros (0x1800 B) at misc offset 0
     → next LK boot enters RECOVERY.**
2. **A/B boot_control ("BCAB")** — `read_write_partition_info` 0x5001E040
   reads 0x800 B from misc, checks magic word **0x42414342 ("BCAB") at buf+4**
   ([LK_AB] strings 0x50098150…: "read boot_control fail", "boot_ctrl magic
   number is zero for nonAB project"); `set_active_slot` 0x5001E338 (suffix
   strings "_a"/"_b" 0x500B7438/0x500B743F) is called from the **locked-OK**
   `set_active:` command. Exact block offset inside misc not pinned (read call
   args 0x800/0x20 — likely sector arithmetic); **mark: partially proven.**
   DA2 can flip the active slot here if boot_a is corrupt.

Boot reason: `androidboot.bootreason=` cmdline (0x9102F) built from the
reboot-reason name table (0x500BF7DC: HW_reboot, SPM_reboot, security_reboot,
reboot_longkey, unknown_reboot, …); `register_reboot_reason`/
`reboot_reason_shutdown_callback` (0x974FF/0x97516). The mode-carrying register
`0xFFFF000010007024` (low nibble) is the only cross-reboot mode channel and is
preloader-owned — **not writable from flash**.

## 5. Q5 — recovery path on boot failure

- "kernel err 3 times, will go to recovery" (0x5008F30F) and "kernel data err 3
  times…" (0x5008F36F) are **dead strings — zero code xrefs** (verified by full
  ADRP/ADR scan); the automatic boot-fail→recovery retry loop of upstream LK is
  not called in this build.
- What actually happens on failed boot: AVB orange → banner + 5 s → boot;
  yellow/red or RPMB-mismatch → `verify boot fail, it will power off!` +
  power-off (see re-lk-seccfg.md §5). No fastboot fallback.
- Recovery is entered only via: misc BCB "boot-recovery", HW boot-arg==2, or
  `fastboot reboot-recovery` (allowed locked). "load recovery image"
  (0x500921AE) → recovery partition image (signed; not replaceable without
  unlock).

## 6. Q6 — the unlock gate itself (new finding, most actionable)

`flashing unlock` handler 0x500076A8 (registered flagA=1/flagB=0 → runs on a
LOCKED device):

1. `get_unlock_ability` **0x50007BEC**: open partition **"frp"** (name string
   0x50090434), take `size` from part->size (x1=[part+0x20]), compute
   `offset = size - 4`, read **4 bytes** at that offset into *out; read<4 →
   print "Failed to get unlock allow flag" and *out=0; **frp missing → *out=1**
   (0x50007C78 path, prints "No frp partition exists").
   Prints "frp paritition size: 0x%llx" / "unlock_allowed_flag_offset: 0x%llx".
2. allowed==0 → "Prohibit unlock operation" (0x500900C9). Nonzero → proceed.
3. Prints the "Unlock bootloader?" disclaimer pages, shows confirm UI
   (0x500323D4), waits for Volume-UP/Down ("Yes (Volume UP or Volume Down)")
   with 5 s auto-exit — **button-only interaction, no display content needed**.
4. On confirm → 0x50007C9C: erases/wipes ("metadata" 0x5009059E, "md_udc",
   userdata wipe "[SEC] Fastboot wip user data fail") and sets lock_state=3
   via the seccfg setter; RPMB boot-info rewritten by LK itself at the next
   unlocked boot (re-lk-rpmb-lock.md). Unlock ability is additionally consulted
   by `flashing get_unlock_ability` (0x50007B8C).

**Inference (high confidence):** if `fastboot` is reachable (power + volume
combo, handled in preloader; LK only re-checks the nibble via 0x50040538), the
whole unlock succeeds with zero display. If frp[-4:] reads zero, a **single
4-byte DA2 flash write at the end of the frp partition** arms the unlock.

## 7. Ranked actionable rescue options (from DA2 flash-write position)

1. **(Top) Arm + execute `fastboot flashing unlock`.** Enter fastboot by key
   combo (preloader-level; dead screen doesn't matter — LK prints via UART and
   the confirm UI is volume-key driven). If `frp` last 4 bytes are 0, write
   them nonzero first via DA2 (offset `part_size-4`; exact offset from GPT).
   After unlock: flash:/erase: open → flash stock boot/recovery → ADB.
   Caveats: full userdata wipe; RPMB mirror must agree (it will — LK rewrites
   it at first unlocked boot, per re-lk-rpmb-lock.md; oplusreserve1 unlock
   counter bookkeeping exists but is not shown to block).
2. **Force recovery via misc BCB**: DA2 write 0x1800 B at misc offset 0 =
   "boot-recovery"+zeros → stock recovery. Whether stock recovery exposes an
   unauthorized ADB is userspace — inference (low/medium). Reversible
   (rewrite with zeros restores normal boot).
3. **Slot flip via "BCAB" boot_control in misc** (offset TBD) if the failure is
   a corrupt active slot (boot_a) — cheaper than 2, target same partition.
4. **UART debug**: if the device reaches fastboot, `oem p2u on` (locked-OK)
   muxes logs to UART; `oem dump_pllk_log`, mrdump oems also locked-OK.
   `oem usb2jtag` would give JTAG but is lock-blocked.
5. **Not available**: fastboot boot from RAM (absent), forced META from flash
   (mode inputs are preloader-owned), unlocked-only oems (get_socid,
   printk-ratelimit, ultraflash).

## 8. Confidence

- **High:** registration list & flags (decoded from real code + literal tables),
  gating logic in the dispatcher, S-CHIP check, `boot_mode_check` flow and jump
  table, misc BCB read/write (both directions), frp[-4:] unlock gate, "BCAB"
  magic, absence of `boot`/oem-auth strings.
- **Medium:** exact semantic naming of flagA/flagB (behavior derived, names
  inferred from deny strings); reboot-reason table meaning; oplus_ftm_mode
  details; whether stock recovery ADB is open.
- **Low/unresolved:** byte offset of the "BCAB" block inside misc; the writer
  for [0x5011329C] adb/elt flags (meta.c parses them from the `atag,meta`
  ATAG); caller of 0x5001E040 (reached via indirect call — not located);
  boot-menu (`Select Boot Mode:`) trigger conditions (dconfig-gated, refs not
  resolvable by static scan).
