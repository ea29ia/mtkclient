# Consistency audit #2 — RMX3630 docs vs binary, code and device evidence

Date: 2026-10-24 (evening). Branch `oplus-mt6789-unlock`.
Method: 5 parallel audit agents (one per doc cluster) + manual verification of every
critical claim by capstone disassembly / file hashing / log inspection.
Everything below is checked by the author of this file; where an agent was wrong,
it is marked **[agent error]** so it does not leak into later work.

Companion: `re-consistency-audit.md` (audit #1, now partly stale — see §6).

---

## 0. Verdict in one paragraph

The campaign's *actions* were sound, but several **documents contain wrong addresses
and wrong semantics**, and two of the **new probe scripts had a fatal marker bug**
that would have produced a false "nothing changed" result. The single most
important correction: the LK boot-info mirror is **not** at RPMB blocks 0–3 — the
`0x1DC` argument is the JEDEC **address field** of the RPMB frame, so the mirror
lives at **blocks 0x1DC–0x1DF** (byte offset 0x1DC00). Every RPMB conclusion drawn
from "sectors 0–7F are zero" was therefore about the wrong region, and the probe
must be re-aimed. Second most important: `WRITE-PARTITION` always sends
`<pre_erase>NO</pre_erase>`, so our patch-based "silent erase" model was
superfluous, and the DA programs exactly the **received** byte count — the
"whole partition" claim needs the reach test.

---

## 1. CRITICAL corrections (change the next action)

### C1. RPMB mirror is at blocks `0x1DC..0x1DF`, not at 0..3 — **[proven]**

`km_client_read_rpmb_boot_info` (0x50054674) calls 0x50055570, which calls the
transport with `w0 = 0x1DC`, `x1 = buf`, `w2 = 0x400`. Inside
`rpmb_read_direct` 0x5002FD14:

```
0x5002fd34  mov  w22, w0                     ; w22 = 0x1DC  (argument)
0x5002fdb0  add  x9, sp, #0x30               ; x9 = frame base
0x5002fe6c  mov  w8, #0x400
0x5002fe70  strh w8, [sp, #0x22e]            ; frame + 0x1FE = request/response type
0x5002fe78  rev  w10, w22
0x5002fe7c  lsr  w10, w10, #0x10
0x5002fe88  strh w10, [sp, #0x228]           ; frame + 0x1F8 = JEDEC **address**
```

Frame + 0x1F8 is the 2-byte block-address field of the standard 512-byte RPMB
frame; +0x1FE is the request type. The TEE path 0x5003E4E4 does the same at
0x5003E5C4–0x5003E5DC and increments the address per block at 0x5003E66C.
Therefore the mirror = **RPMB blocks 0x1DC–0x1DF**, 0x400 bytes at byte offset
**0x1DC00**. `0x1DC` is an address, not an op id.

Consequences (all docs listed must be amended):
* `planb_recon2` scanned blocks 0..0x7F → **wrong region**; its "all zero ⇒
  mirror=0" reasoning was void (this was already suspected, now proven).
* `re-mtkclient-rpmb-audit.md` §6 (`sectors 0..3`), `re-tee-efuse.md` mirror row,
  `re-tbase-sfsrp.md` §3/§5 collision maths, `re-lk-rpmb-lock.md` §3/§4 wording
  ("cmd 0x1DC"), `re-unlock-campaign-2026-10-24.md` §2.2 (written earlier today).
* The t-base SFSRP "S ≥ 4 because LK occupies 0–3" inference is **void** — LK
  occupies 0x1DC–0x1DF, so a superblock at S ≤ 3 no longer collides. S stays
  unknown (needs a RAM read at 0x05F8471C or a t-base-visible dump).

### C2. Probe scripts had a marker-length bug (would always print "no change") — **[proven by arithmetic]**

`(b"REACHHEAD" * 128)[:0x1000]` is **1152** bytes (`"REACHHEAD"` is 9 chars),
`(b"PARATEST" * 128)[:0x1000]` is **1024** bytes. Assigning such a value to a
0x1000-byte bytearray slice *shrinks* the image, and comparing a 0x1000-byte
read against the short constant is always `False`.
* `write_reach_test.py`: image became 0x7F480 bytes, both markers "MISSING" —
  always verdict 3. **Fixed** (markers now exactly 0x1000, `assert len(img)==full`,
  restore in `finally`).
* `f5_dump.py`, `para_write_test.py`, `para_restore_zero.py`: success branch was
  unreachable; the real evidence of the `para` write was the printed hex
  (`5041524154455354…` = `PARATESTPARATEST…`), not the boolean. **Fixed**.
* `seccfg_snapshot.py` silently skips the diff if lengths differ. **Fixed**
  (hard fail on short read + reference md5 asserted).
* `planb_execute.py` treated a same-session readback as "committed" and printed
  "ORANGE STATE / ADB" promises. **Fixed** (prints "UNVERIFIED until a fresh
  session reads it back" + a post-reboot instruction).
* `reboot_fastboot.py` promised `fastboot devices` would answer. **Fixed**
  (expectation text now mentions the preloader-owned nibble).

### C3. `WRITE-PARTITION` always sends `pre_erase=NO` — our patch was belt-and-braces — **[proven]**

`mtkclient/Library/DA/xmlflash/xml_cmd.py:450-453`:
`# pre_erase present with value != "YES" => DA skips the erase` +
`<pre_erase>NO</pre_erase>`. The DA's erase phase is skipped by the flag
(0x400021E4/0x40002200). So:
* `re-write-chain.md` §3/§5, `re-write-partition-offset.md` §1–§5 and
  `re-writeflash-scrubber.md` ("no pre_erase node is sent", "silent erase")
  are **wrong**. Our `OPLUS_PATCH_ERASE_KILL` is redundant, not the cause.
* The real reason nothing was erased was (a) the flag and (b) the F804 stub.

### C4. Program length = received length, not whole partition — **[proven code, needs a device test for the DA side]**

The consumer computes `len = [record+0xC] + [record+0x10]` (0x4002FFD0) and the
loop ends when `accumulated == target`; the default region is the whole partition
(0x4002D970) but only the bytes actually received are programmed, at offset 0.
Evidence for the DA honouring this: the misc incident — an 0x800-byte image left
`BCAB` at misc+0x800 intact (a whole-partition program would have zeroed it).
The 8 MB seccfg write was size-matched, so it cannot discriminate. Hence the
open question in today's report stands, and `write_reach_test.py` (fixed) is the
right instrument.

### C5. `misc` is **not** zero — the BCAB block lives at +0x800 — **[proven]**

`/tmp/misc_now.bin` = `5f 61 00 00 42 43 41 42 01 02 00 00 ff 00 7f 00 …`
at 0x800, i.e. control block with magic `BCAB` at +0x804 (14 nonzero bytes).
Six bytes differ from the pre-campaign backup (`0x80C`, `0x80E`, `0x81C..0x81F`
= checksum), i.e. **LK rewrote the BCAB control block during the session**
(slot bookkeeping / self-repair), which also means `misc` is actively written by
LK and can be used as a signal.
Earlier claims "misc all zero / BCAB not present" were based on the truncated
0x1000 read of a *different* image and are withdrawn.

### C6. `fastboot` has **two** entry paths, and ATAG does not produce fastboot — **[proven]**

`boot_mode_check` entry **0x5000AAAC**, single caller **0x5000E15C**, which runs
**before** `sec_boot_init` (call at 0x5000E270).

```
ATAG boottags [0x50112024]:
  1 -> mode 1 (META banner)           0x5000AAC8 b.eq 0x5000AAE8 (strb w0 = 1)
  4 -> mode 4 (factory, +oplus_ftm_mode=factory1)  0x5000AAE0/AAE4
  7 -> mode 7 (banner "UNKNOWN BOOT") 0x5000AAE4 mov w0,#7
  0x63 is never tested
FASTBOOT (0x63) paths:
  (a) HW nibble == 3:  0x5000ACA4 bl 0x50040538 ; cmp #3 ; b.ne ; mov w8,#0x63
  (b) rc_wdt-class && seccfg==3: 0x5000ACBC..0x5000AD04 -> b 0x5000ACB4 -> 0x63
      (GPIO read at 0x50021D2C is only logged; its value is unused)
```
Banner table 0x50093A89 maps modes 0..8; only 0x63 dispatches to
`=> FASTBOOT MODE` (0x5000E3E4/0x5000E3EC → 0x500061FC).

So "ATAG 1/7 → fastboot" (in `re-lk-bootmode-priority.md`,
`re-lk-rescue-surfaces.md`, and my own report today) is **wrong**. And my
correction "the rc_wdt/GPIO branch is unconditional-to-0x63 is wrong" was itself
an **overcorrection**: path (b) *does* jump to 0x63 unconditionally once
`rc_wdt-class && lock_state==3` holds. Our WDT reboot with seccfg=3 produced no
fastboot ⇒ one of those two conditions was false on the device (open question,
needs the UART log or a reset-reason experiment).

### C7. `re-lk-bootmode-priority.md` is offset-shifted by +0x78 and semantically wrong in 6 places — **[proven]**

All code addresses in that doc are 0x78 too high (e.g. entry 0x5000AB24 → real
0x5000AAAC; caller 0x5000E1D4 → real 0x5000E15C; BCB read 0x50069C88 → 0x50069C10;
misc open 0x50069BFC → 0x50069B84; malloc 0x5006AD00 → 0x5006AC88;
strcmp 0x5006CD64 → 0x5006CCEC; HW getter 0x500405B0 → 0x50040538;
oplusreserve check 0x50005458 → 0x500053E0; kpoc 0x5001F078 → 0x5001F000).
Semantic errors: ATAG 1→META (not fastboot), mode 7 = UNKNOWN (not fastboot),
rc_wdt+locked → **RECOVERY** (not META), HW nibble 0xB → stores 0xB (not
pass-through), BCB comparison is `strcmp` (needs a NUL at misc[13]), and BCAB is
read **0x20 bytes at offset 0x800** (not 0x800 bytes at 0) — so the "BCAB at
0x800 is refuted" and "0x80C is outside the struct / safe" sections are wrong
(0x80C is BCAB+0xC, and LK's repair writes 0x77 there).
The doc needs regeneration, not patching; an errata banner has been added.

---

## 2. LK seccfg / RPMB corrections (high/medium)

| # | wrong claim | actual | evidence |
|---|---|---|---|
| L1 | backup-valid ⇒ self-heal copies backup→main (`re-lk-seccfg` §3.2) | the "restore" branch hashes **R_main** (0x50144840) and compares with the digest at **R_bak+0x1C** (0x5014489C); with a broken main magic it cannot fire and the flow falls to init-NV (lock=1) | 0x50082928 `adrp/add x19,#0x840`; 0x5008295C `add x8,#0x89c` |
| L2 | `sec_cfg_get_lock_state` fails safe to `0` | `csinc w8,w8,wzr,eq` → on error `*out = 1` | 0x50082B0C |
| L3 | mirror block fields: +0x0 sbc, +0x4 dev_info, +0x8 bootmode, +0xC locked | `stp w21,w23,[sp,#0x24]` ⇒ **+0x4 sbc**, **+0x8 boot_mode** (from `get_boot_mode` 0x5005536C); `stp w22,w19,[sp,#0x2c]` ⇒ **+0xC locked**, **+0x10 aux**; +0x0 stays 0 | 0x50054814/0x50054818 |
| L4 | TEE retry delay "0xA120 ms" | `mov w0,#0xa120; movk w0,#7,lsl16` = **0x7A120 µs = 500 ms** | 0x500555B4-BC |
| L5 | "0x500a06bd = mmc0rpmb, RPMB device name" | 0x500A06BD = `"preloader_a"`; `"mmc0rpmb"` is at **0x500A06D5** | string dump |
| L6 | power-off string at 0x500ACEEF | **0x500AD0EF** (0x500ACEEF is the tail of the storage-write error string) | 0x500557E4 |
| L7 | "0x50055368 is a second RPMB read (`rpmb_read(buf,0x3E0,sp)`) whose failure prints 'get sha256 fail'" | 0x50055508 is the **SHA-256** computation (0x5008B4DC/534/718); that error branch is dead | 0x500546B0 |
| L8 | digest error codes 0x10003004 / 0x10003000 | magic → **0x10003005**, digest → **0x10003001** | 0x500824FC |
| L9 | HACC register roles "+0x08..0x14 key, +0x18..+0x34 IV" | AKEY = +0x18..+0x34 (zeroed), seeds at +0x38..+0x44, data in at +0x08..+0x14; `re-seccfg-digest-equiv.md` is right | 0x5007C838/0x5007C900 |
| L10 | `sec_cfg_set_lock_state` wrapper has "only" the DC caller | 4 call sites: 0x50055784 (DC) + fastboot 0x50007804/0x50007A84/0x5000D90C | BL-xref sweep |
| L11 | `re-tee-efuse.md`: load base unresolved, `qword 0x05F00240` | base **0x05F00000** proven (`tee.img` body at 0x31660+0x440); the 0x05F00240 qword is at segment-header **+0x28** | file map |
| L12 | t-base magic "4400RPMB" / grep bytes `34 34 30 30…` | magic = **0x424D5052_3030344B** = `K400RPMB` (bytes `4B 34 30 30 52 50 4D 42`) | 0x5F760C0-CC |
| L13 | "RPMB reads need no key" (`re-tbase-sfsrp` §5) | RPMB **read requests carry no MAC**, but the **response is MAC'd** and must be verified; without the key the reply cannot be authenticated | JEDEC frame layout (proven field offsets in LK) |

Verified correct and unchanged: seccfg V4 layout (0x3C digest at +0x1C,
HACC over SHA-256 of the 0x1C header), DC branch map, `set_boot_info_to_rpmb`
semantics (`locked_bit=(flag==0)?1:0`), hash-mismatch ⇒ zeroed buffer ⇒ success,
call sites 0x500026E4/0x500078E8, plain SHA-256 for the RPMB block vs
HACC-scrambled digest for seccfg, `sec_cfg_set_lock_state(1)` → 4 when
current==3.

---

## 3. DA2 pipeline corrections (high/medium)

| # | wrong claim | actual | evidence |
|---|---|---|---|
| P1 | program dispatcher is `0x4002AAC0` reached via `[0x40054320+0x10]` | 0x4002AAC0 is **dead code** (no B/BL target); the storage table slot is **+8** (0x40054328) | xref sweep, table words |
| P2 | F5 marker stores `r1 = len` | at 0x4002F858 `r1 = ldrb [r1,#2]` = policy[+2] (`img_auth_required`); the F5 patch *deletes* `mov r1,sl`. Marker is 0/1 only | 0x4002F84C/858 |
| P3 | "bulk handle 0x4006E790 all zero ⇒ 0x4002D5A8 not called" is proof | the slot is reused by the read engine after the readback; the init stores `[h+0x34]` unconditionally at 0x4002D608, so the dump is not a reliable "not called" proof. Use the F804 stub/consumer evidence instead | 0x4002D608 + `re-writepartition-consumer-wakeup` §2.3 |
| P4 | write loop exits when `sl ≥ [sp+4]` or `accumulated == target` (two different docs) | only one exit: `accumulated == target` (0x40030490 `bne`), after the release handshake; `target == 0` skips everything (0x40030250) | 0x40030460-94 |
| P5 | 0x4000EA94 = "send response" / "send error status" | 0x4000EA94 is a **recursive tree free** (`bl 0x4000A5F0` at 0x4000EB4C) — mxmlDelete | disasm |
| P6 | sec-dispatch: bit1 = hash_binding; policy miss → −1 | bit**2** = hash_binding (0x4002CDF4 `ubfx #2`); miss → default entry (0x4002CCD0) | disasm |
| P7 | `g_oplus_auth_status` at 0x40054314 | 0x40054314 is an XML-error string pointer; the status is **0x4005455C** | policy-map §… (already right there) |
| P8 | 0x400031A8 `ldrb r0,[sp,0x30]`; 0x40003234 `movt #0x4004` | +0x31 and `movt #0x4002` | bytes |

## 4. **[agent error]** "DA_BR.bin is a different build"

One auditor disassembled `DA_BR.bin` at `0x40000000 + VA` and concluded the docs'
addresses do not apply. That is wrong: `DA_BR.bin` = **0x68AB8-byte header**
(`"MTK_DOWNLOAD_AGENT"`, `"MTK_DA_v6_2024-09-02 22:21:09"`) + the DA image;
the image runs from file offset 0x68AB8 and is byte-identical to
`da2_oplus.bin` **except the last 254 bytes** (0x56EC8–0x56FC7 = signature area).
Both are 0x56FC8 bytes; code hashes match. So every DA2 address in the docs
applies to the running DA. `DA_BR.bin[0x68AB8:]` md5 `9bda6b74…`,
`da2_oplus.bin` md5 `74d2b9f2…` — different only in the tail.

---

## 5. What the probes should now test (updated priorities)

1. `write_reach_test.py` (fixed) — full vs partial program semantics (Q1).
2. `rpmb_mirror_probe.py` (fixed) — **blocks 0x1DC–0x1DF** with key D and with a
   wrong key; only a non-zero reply can distinguish, and even then D≠device key
   is possible. This is now the only RPMB target that matches LK.
3. Reset-reason experiment for fastboot path (b): reboot with an rc_wdt-class
   reset while seccfg==3 (needs UART or USB observation); cheap, no flash risk.
4. Find the full-`seccfg` restore actor (if Q1 shows a full program).

---

## 6. Doc status after this audit

| doc | status |
|---|---|
| `re-unlock-campaign-2026-10-24.md` | **fixed** (0x1DC, ATAG, misc, commit refs) |
| `re-lk-bootmode-priority.md` | **errata banner** added; body needs regeneration (+0x78 shift, §C7) |
| `re-lk-rescue-surfaces.md` | banner: ATAG claim, mirror wording |
| `re-lk-seccfg.md` | banner: L1/L2/L8/L9 |
| `re-lk-rpmb-lock.md` | banner: C1/L3/L4/L6/L7 |
| `re-lk-rpmb-key-derivation.md` | banner: C1/L5, MAC layer superseded |
| `re-mtkclient-rpmb-audit.md` | **fixed** §6 (mirror blocks), stub-is-eMMC note |
| `re-tbase-sfsrp.md` | **fixed** magic + geometry note; §3 collision void |
| `re-tee-efuse.md` | banner: base resolved, mirror blocks |
| `re-da2-rpmb-key.md` | banner: live/dead xref list, op-3 proof demoted |
| `re-write-chain.md`, `re-write-partition-offset.md` | banner: P1/P4/C3 |
| `re-writeflash-scrubber.md` | banner: C3/P8 |
| `re-writepartition-consumer-wakeup.md` | banner: P2/P3/P4 |
| `re-sec-dispatch.md` | banner: P6/P7 |
| `re-postwrite-hang.md`, `re-erase-patch-audit.md` | banner: P5 |
| `re-da2-policy-map.md` | banner: A1 (F804 is the dispatcher) |
| `re-consistency-audit.md` | banner: audit #1 is historical (stale items S1–S7) |
| `re-preloader-bootmode-atag.md` | banner: scope of "no str into 0x10007024" |
| `re-da2-bootmode-reboot.md` | banner: nibble-loss verdict conflicts with `re-rgu-nibble-loss` |
| `re-reserve2-master.md`, `re-md1img-scan.md`, `re-ghostlock-applicability.md` | banner: plans invalidated (no RPMB write path / no persistence) |
| `problem_status.md` | §11 marked SUPERSEDED, §1–§9 historical note, §12 extended |
