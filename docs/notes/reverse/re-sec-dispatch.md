# RE: SEC service dispatch in RMX3630 OPLUS DA2 (question 4)

> **ERRATA (2026-10-24, audit #2):** (1) policy bit **2** is `hash_binding`
> (`ubfx #2` @0x4002CDF4), not bit 1. (2) A policy-table miss returns the
> **default entry** (0x4002CCD0), not −1. (3) `g_oplus_auth_status` is at
> **0x4005455C**; 0x40054314 is an XML-error string pointer.
> See `re-consistency-audit-2.md` §3.

Date: 2026-10-23. Tool: radare2, `-a arm -b 32 -m 0x40000000`, file offset 0 == VA 0x40000000.
Binary: `docs/notes/rmx3630-da2/da2_oplus.bin` (356296 B, sha256 fd3a5038…).

## TL;DR

* **The premise of question 4 is false.** `0x4002c800` is **not a function entry** and there is
  **no dispatch table pointing at it** (a byte-exact scan of the whole blob for the little-endian
  pointer `00 c8 02 40`, and for *any* pointer into `0x4002c600–0x4002d000`, finds **zero**
  references). `0x4002c800` is an interior basic block of `fcn.4002c6f0`, which is the
  **GPT/PMT partition-record compare helper** (strings "GPT/PMT Changed, Scatter file has New
  partition[%s]" etc.). That explains "table-dispatched, no direct BL callers": it was never a
  separate function.
* The code that actually prints `[SEC] set lock state as LOCKED` lives in **`fcn.4002ce08`**
  (print site `0x4002ceac`, string `0x4004e8da`). It is **not** dispatched through a function
  pointer table either — it is called directly (`bl`) from three tiny bit-extractor wrappers.
* The real "table-driven" SEC object in this DA is the **per-partition security-policy table at
  `0x4005628c`** (64 entries × 32 bytes) with its lookup/getter family. Full map below.
* The lock-state decision (LOCKED vs MP_DEFAULT) is made by the **seccfg loader
  `fcn.40034dfc`**: it reads the `seccfg` partition, looks for one or two magic `"MMMM"`
  (0x4D4D4D4D) records, anti-clone-verifies them, and sets the lock-state global `0x4006E9F0`
  to 1 (slot 0) or 2 (slot 1). If seccfg is empty/unreadable it returns `0xC002005A` and the
  caller defaults the state to **LOCKED (1)**.

---

## 1. What 0x4002c800 really is

```
$ r2 -q -c 's 0x4002c800; pd 4' da2_oplus.bin
0x4002c800  ldr r7, [var_18h]      ; 18709de5
0x4002c804  ldrd r2, r3, [r5, -8]
0x4002c808  ldr sl, [var_1ch]
0x4002c80c  ldrd r0, r1, [r7, 0x48]
```

No `push {.., lr}` prologue — this is mid-function. Nearest ARM prologue above it:
`0x4002c6f0: push {r4,r5,r6,r7,r8,sb,sl,fp,lr}` (`f04f2de9`).

**Pointer search (python, whole file):**
* `\x00\xc8\x02\x40` → 0 hits.
* any 4-byte LE word in `0x4002c600..0x4002d000` → 0 hits.

So nothing in the blob — code, literal pool or data — references 0x4002c800 as an address.
"Table dispatch" was a mis-read of `r2` auto-analysis that started a fake `fcn.4002c800`.

**What `fcn.4002c6f0` does** (the containing function, 692 B):
* takes two list descriptors (`sl` = new, `sb` = old); records are **0x58 bytes** each,
  name at `+8` (0x40 bytes, compared with `memcmp` `0x4000b57c`), offsets/sizes as 64-bit
  pairs at `+0x48/+0x50`.
* The block at **0x4002c800** XOR-compares the 64-bit offset fields of two records
  (`ldrd … eor/eor/orrs`, `0x4002c810`–`0x4002c834`) — i.e. "did this partition move?".
* On mismatch it prints via `0x40007c10` with string `0x4004e3c0` =
  `[%s]Changed At[(S)0x%llx->(GPT)0x%llx] Len[(S)0x%llx->(GPT)0x%llx]`; siblings print
  `GPT/PMT Changed, Scatter file has New partition[%s]` / `...Removed a partition[%s]` /
  `GPT/PMT Unchanged`.
* Return values 0/1/2 are the caller-visible status (`mov r7,2` @0x4002c8a0, `mov r7,1`
  @0x4002c840/0x4002c93c, `mov r7,0` @0x4002c91c).
* Direct `bl` callers of `fcn.4002c6f0`: **0x400026b8** (inside WRITE-PARTITIONS/FU-S1 logic),
  **0x4000411c**, **0x40005010** (firmware-upgrade record diff sites; the "rcd->changed_status"
  and "In FU_S1" strings live in the same region).

## 2. The real "[SEC] set lock state" code and its dispatch chain

### 2.1 `fcn.4002ce08` — SEC state query (contains the print)

Prologue at `0x4002ce08: push {r4,r5,fp,lr}` (280 bytes). Contract:
`int sec_policy_flag(int idx)` — takes a **policy-table index**, returns the flag byte
`table[idx] + 0x16` (see §3), after touching both security inputs:

```
0x4002ce14  mov r4, r0                  ; idx
0x4002ce24  add r0, sp, 4
0x4002ce28  bl 0x40033b08               ; get_sboot_state(&out)  (EFUSE SBC)
0x4002ce2c  cmp r0, 0 ; beq 0x4002ce7c  ; ret!=0 -> error path, print
            ;   0x4004e891 "[SEC] get sboot state fail, ret: %x\n"   (site 0x4002ce4c)
...
0x4002ce7c  mov r0, sp
0x4002ce80  bl 0x40034d6c               ; sec_get_seccfg(&lock_state)
0x4002ce88  beq 0x4002ceb8              ; ret==0 -> use fetched state
0x4002ce9c  cmp r5, 0xC002005A          ; "seccfg empty" error?
0x4002cea0  bne 0x4002cf0c              ; else print "[SEC] get lock state fail, ret: %x" (0x4004e8b6)
0x4002ceac  movw r0, 0xe8da ; movt r0, 0x4004
0x4002ceb4  bl 0x40007c10               ; <<< "[SEC] set lock state as LOCKED\n"
0x4002ceb8  ldr r0,[sp] ; sub r0,1 ; cmp r0,1
            ; state in {1,2} -> 0x4002cec8: store 4, print 0x4004e8fa
            ;   "[SEC] lock_state(default) = 0x%x"
            ; else -> 0x4002ceec: print 0x4004e91c "[SEC] lock_state = 0x%x"
0x4002ce64  movw r0, 0x628c ; movt 0x4005 ; add r0, r0, r4, lsl 5
0x4002ce70  ldrb r0, [r0, 0x16]         ; return table[idx].flag_byte
```

Notes / uncertainty: the `str 4,[sp]` at `0x4002cec8` before the "(default)" print looks like a
compiler leftover of an inlined struct store (the same `mov r0,4; str [sp]` + `mov r0,1;
str [sp,4]` pair also appears at `0x4002ce54/58` on the error path and is equally unused by the
return value). The returned value is only the table flag byte; the prints are diagnostics.

### 2.2 Who calls it (no table — plain BL chain)

Three 8-byte wrappers extract bits of the returned flag byte:

| VA | body | meaning |
|---|---|---|
| `0x4002cdf4` | `bl 0x4002ce08; ubfx r0,r0,2,1` | flag bit 2 |
| `0x4002cf20` | `bl 0x4002ce08; ubfx r0,r0,1,1` | flag bit 1 |
| `0x4002cf34` | `bl 0x4002ce08; and r0,r0,1` | flag bit 0 |
| `0x4002cf48` | `ldr r0,[0x4005628c + r0<<5]` | entry word accessor |
| `0x4002cf58` | `mov r1,1; str r1,[r0]` | small setter |

All three are called from **`fcn.4002cf68`** — the *policy query builder*:

```
0x4002cf68 (name, out):                  ; r5=name, r4=out struct
  r6 = fcn.4002cbb4(name)                ; 0x4002cf80: partition name -> policy index
  out[1] = bit2(idx)   ; 0x4002cf88
  out[2] = bit1(idx)   ; 0x4002cf94
  out[3] = bit0(idx)   ; 0x4002cfa0
  out[4] = fcn.4002cd44(idx)  ; 0x4002cfac  (parses entry+0x18 wide-digit field)
  out[8] = fcn.4002cd30(idx)  ; 0x4002cfb8  (entry+0x1c word)
  if (loglevel<=1) prints 0x4004e935 "==========security policy=========="
                  0x4004e95a "policy of partition: %s"
                  0x4004e973 "hash_binding = %d" (+ more below 0x4002cfd8)
```

`fcn.4002cf68` is called (direct `bl`) from ~10 sites, all inside storage command handlers:

| call site | enclosing handler (by nearby strings) |
|---|---|
| `0x4000217c` | CMD:WRITE-PARTITION (`0x40002034`; "Download partition [%s]", "Cannot find [%s] info from partition table.") |
| `0x40002784`, `0x40002ad0` | CMD:WRITE-PARTITIONS / FU-S1 region (`0x40002598`; "rcd->changed_status = %x", "In FU_S1", "da/arg/pre_erase") |
| `0x40003190` | CMD:WRITE-FLASH (`0x40002e60`; "[%s][storege/section …][max-size …]") |
| `0x40003928` | CMD:READ-PARTITION-TABLE (`0x4000362c`; "partition_list: %s", also reads `g_oplus_auth_status` 0x40054314) |
| `0x40003cc8` | erase region ("partition_list"/GPT layout change strings) |
| `0x400041b8`, `0x40004d78` | FU flash_list helpers ("XML parser exception. flash_list not found.") |
| `0x40004530` | ERASE handler ("Erase [%s] is not allowed.") |
| `0x40005578` | (no unique string nearby — same FU helper family) |

So: **the "dispatcher" of the SEC lock-state code is the per-command storage handlers
themselves** — every WRITE/ERASE/READ-PARTITION-TABLE exchange first builds the partition's
security-policy record via `0x4002cf68`, which pulls sboot + seccfg lock state through
`0x4002ce08`.

### 2.3 The XML command table (the actual dispatcher of the DA)

Command registration sweep at `0x40001a90–0x40001e28`: each entry is
`movw r0,<cmd string>; movw r2,<handler>; bl 0x400086d4` (register). Extracted map:

| cmd string VA | command | handler |
|---|---|---|
| 0x40041459 | CMD:WRITE-EFUSE | 0x4000599c |
| 0x40041469 | CMD:READ-EFUSE | 0x40005a80 |
| 0x40041478 | CMD:GET-HW-INFO | 0x400064bc |
| 0x40041488 | CMD:READ-REGISTER | 0x40006eec |
| 0x400414ff | CMD:WRITE-REGISTER | 0x4000700c |
| 0x40041512 | CMD:WRITE-PARTITION | 0x40002034 |
| 0x40041526 | CMD:WRITE-FLASH | 0x40002e60 |
| 0x40041536 | CMD:WRITE-PARTITIONS | 0x40002598 |
| 0x4004154b | CMD:READ-PARTITION-TABLE | 0x4000362c |
| 0x40041564 | CMD:DEBUG:UFS | 0x4000713c |
| 0x40041572 | CMD:EMMC-CONTROL | 0x400069f4 |
| 0x40041583 | CMD:REBOOT | 0x40005ba8 |
| 0x4004158e | CMD:READ-PARTITION | 0x400032d0 |
| 0x400415a1 | CMD:READ-FLASH | 0x400033f0 |
| 0x400415be | CMD:ERASE-PARTITION | 0x400037ec |
| 0x400415d2 | CMD:ERASE-FLASH | 0x400039c0 |
| 0x400415f3 | CMD:SET-BOOT-MODE | 0x40005d84 |
| 0x40041605 | CMD:SET-RSC | 0x40005f64 |
| 0x40041611 | CMD:WRITE-PRIVATE-CERT | 0x40006394 |
| 0x40041628 | CMD:GET-DA-INFO | 0x400068d0 |
| 0x40041638 | CMD:SET-HOST-INFO | 0x40001f84 |
| 0x4004166c | CMD:NOTIFY-INIT-HW | 0x40001f30 |
| **0x4004167f** | **CMD:SECURITY-SET-ALLINONE-SIGNATURE** | **0x40006c1c** |
| 0x400416a3 | CMD:GET-SYS-PROPERTY | 0x400077c4 |
| **0x400416c7** | **CMD:SECURITY-GET-DEV-FW-INFO** | **0x40006cf4** |
| **0x400416e4** | **CMD:SECURITY-SET-FLASH-POLICY** | **0x40006ddc** |
| 0x40041702 | CMD:OPLUS-WRITE-HASH256-ID | 0x40010a0c |
| 0x4004171d | CMD:OPLUS-GET-CPUID | 0x40010a9c |

(Registered via `0x400086d4(name, r1=group-str, handler)`; one special case at `0x40001db8`
uses `0x40008720` with the strings at `0x400416b8`/`0x400416bf` — the "DA.SLA ENABLED" area.)

SECURITY-\* handlers:
* `0x40006c1c` SET-ALLINONE-SIGNATURE: XML-parse, get node **"Signature"** (`0x40042f12`),
  call shared secure-node executor `0x4002ae8c`, then `0x4002d428`.
* `0x40006cf4` GET-DEV-FW-INFO: XML-parse, `0x40007a24`, call `0x4002b330` with node
  "Signature" (`0x40042f1c` path base).
* `0x40006ddc` SET-FLASH-POLICY: XML-parse, call `0x4002ae8c` with node **"SEC-POLICY"**
  (`0x40042f28`), then **`cust_security_verify_sec_policy` `0x40007abc`** — the known RET0
  patch target. Deny path prints `0x40042f33` = "Server is not authenticated. Locked.".
* `0x4002ae8c` (the "secure-node executor") builds an XML payload (snprintf into a 0x400-byte
  stack buffer via `0x4000a638`) and invokes two function pointers from the session object
  (`blx r2` on `[r8]`/`[r8+4]`), then string-compares the reply to `"OK"` (`0x4002aff8`:
  `cmp r1,0x4F 'O'` / `cmpeq 0x4B 'K'`).

## 3. The SEC policy table (the actual "table-driven SEC" object)

Table: **`0x4005628c`, 64 entries × 32 bytes**, looked up by `fcn.4002cbb4(name)`:
* Linear scan over all 64 entries (`0x4002cce0: cmp r4,0x3f`), comparing the requested
  partition name against entry fields `+4`, `+8`, `+0xc`, `+0x10` (plain strcmp against C
  strings; up to 4 aliases per entry, e.g. boot/boot_a/boot_b).
* Special case: if `g_oplus_auth_status` (`0x4005455c`) == 5, entry[61] must byte-match the
  18-byte string at `0x4004e825` = **"oplus_single_mode"** (`0x4002cbf0` loop, 0x12 bytes);
  a pointer to that string also exists in data at `0x40056a30`.
* Not found → return −1 (path `0x4002cd0c`).

Full entry dump (index, VA, name fields, `+0x14` word, extra ptr `+0x1c`):

```
[ 0] 0x4005628c "default"
[ 1] 0x400562ac "preloader"                    +0x14=0x20000
[ 2] 0x400562cc "lk"                           +0x14=0x20000
[ 3] 0x400562ec "logo"                         +0x14=0x20000
[ 4] 0x4005630c "boot","boot_a","boot_b"
[ 5] 0x4005632c "vendor_boot","vendor_boot_a","vendor_boot_b"
[ 6] 0x4005634c "recovery"
[ 7] 0x4005636c "system","system_a","system_b"
[ 8] 0x4005638c "vendor","vendor_a","vendor_b"
[ 9] 0x400563ac "odm","odm_a","odm_b"
[10] 0x400563cc "vbmeta","vbmeta_a","vbmeta_b"
[11] 0x400563ec "tee1"                         +0x14=0x20000
[12] 0x4005640c "tee2"                         +0x14=0x20000
[13] 0x4005642c "cache"
[14] 0x4005644c "secro"
[15] 0x4005646c "oemkeystore"                  +0x14=0x20000
[16] 0x4005648c "keystore"                     +0x14=0x20000
[17] 0x400564ac "userdata"                     +0x14=0x20000
[18] 0x400564cc "md1img","md1img_a","md1img_b" +0x14=0x20000  +0x1c=0x40055fac
[19] 0x400564ec "md1img_1",…_a,…_b             +0x14=0x20000  +0x1c=0x40055fac
[20] 0x4005650c "md1dsp"                       +0x14=0x20000
[21] 0x4005652c "md1arm7"                      +0x14=0x20000
[22] 0x4005654c "md3img"                       +0x14=0x20000
[23] 0x4005656c "sgpt","SGPT"
[24] 0x4005658c "pgpt","PGPT"
[25] 0x400565ac "efuse","EFUSE"
[26..28] cam_vpu1/2/3                          +0x14=0x20000
[29] 0x4005662c "spmfw","SPMFW"                +0x14=0x20000
[30] 0x4005664c "mcupmfw","MCUPMFW"            +0x14=0x20000
[31..36] nvram, protect1, protect2, proinfo, nvcfg, persist
[37] 0x4005672c "odmdtbo",…_a,…_b,"ODMDTBO"    +0x14=0x20000
[38] 0x4005674c "dtbo",…_a,…_b,"DTBO"          +0x14=0x20000
[39] 0x4005676c "persistent",…_a,…_b
[40] 0x4005678c "vbmeta_system",…_a,…_b
[41] 0x400567ac "vbmeta_vendor",…_a,…_b
[42] 0x400567cc "super","super_a","super_b"
[43..46] mcf1, mcf2, mcf_ota, rootfs (+_a/_b)
[47,48] (empty names)
[49] "reserve3"  [50] "reserve4"  [51] "reserve_exp2"  [52] "reserve_exp3"
[53] "special_preload"  [54] "ocdt"  [55] "oplus_custom"
[56] "oplusreserve1"  [57] "oplusreserve2"  [58] "oplusreserve5"  [59] "oplusreserve6"
[60] "param"
[61] "oplus_single_mode"
[62] "NULL"×4 (sentinel)
[63] f0=1, f5=0x11c10430 … (terminator/garbage — treat table as 63 entries + sentinel)
```

Flag byte at `entry+0x16`: since `+0x14` holds `0x00020000` for the hash-bound partitions,
`+0x16` (byte 2 of that word) = **2** for preloader/lk/logo/tee1/tee2/oemkeystore/keystore/
userdata/md1img(_1)/md1dsp/md1arm7/md3img/cam_vpu*/spmfw/mcupmfw/odmdtbo/dtbo, and **0** for
everything else. This byte is exactly what `fcn.4002ce08` returns; `bit1` of it is printed as
**"hash_binding = %d"** by `0x4002cf68`. So bit1 = hash-binding required; bits 0/2 are
additional per-partition policy bits (not yet named — uncertainty).

`0x4002cd44` parses `entry+0x18` as a **wide (2-byte stride) digit/hex string** into a number
(only entry[1] "preloader" has a non-null `+0x18` = `0x4004e4c1`); `0x4002cd30` returns
`entry+0x1c` (pointer `0x40055fac` for md1img entries).

## 4. Lock-state machinery — LOCKED vs MP_DEFAULT decision

### 4.1 `sec_get_seccfg` `0x40034d6c` (wrapper)

```
0x40034d78  bl 0x40034dfc          ; load & verify seccfg into cache structs
0x40034d8c  print "[%s] sec_get_seccfg ret=%x"  (%s = 0x400510c3 "SEC_CFG")
0x40034da4  r1 = global 0x4006E9F0           ; which slot verified
            1 -> r0 = [0x40067640+0xc]       ; slot-0 struct, +0xc = lock_state field
            2 -> r0 = [0x40067600+0xc]       ; slot-1 struct
            other -> r5 = 0xC002005B (err)
0x40034df0  str r0, [out]     ; NOTE: default r0=1, so any weird path still stores 1
```

### 4.2 `fcn.40034dfc` — seccfg loader / verifier (the decision point)

```
0x40034e18  memset local 0x40
0x40034e30  memset struct A = 0x40067640 (0x40)   ; slot-0 cache
0x40034e48  memset struct B = 0x40067600 (0x40)   ; slot-1 cache
0x40034e64  memset 0x4005cf00 (0x3000)            ; raw seccfg image buffer
0x40034e84  bl 0x4002d4d8("seccfg", 0, 0, buf=0x4005cf00, len=0x3000, 0)
            ; read whole seccfg partition by name ("seccfg" string @0x400454bc)
            ; fail -> ret 0xC002002E, print "…sec_get_seccfg ret=%x"
0x40034ec4  memcpy: A+0x00 <- raw+0x00 (0x1c)   ; slot0 header
            A+0x20 <- raw+0x1c (0x20)           ; slot0 digest
            B+0x00 <- raw+0x3c (0x1c)           ; slot1 header
            B+0x20 <- raw+0x58 (0x20)           ; slot1 digest
0x40034f1c  memcmp(A, zeros, 0x40) != 0 -> goto 0x40034f40
            else memcmp(B, zeros, 0x40): both zero -> 0x40035008:
                 r4 += 0x2c  => return 0xC002005A   ; "seccfg empty"
0x40034f40  if (A.hdr[0] == 0x4D4D4D4D "MMMM"):
                 zero 0x20 buffer
                 bl 0x4003a2d4(A, 0x1c, buf)      ; compute record digest over header
                 bl 0x40035030(buf)               ; anti-clone scramble
                 memcmp(A+0x20, buf, 0x20)==0
                 -> 0x40034ffc: global 0x4006E9F0 = 1 ; ret 0        ; SLOT0 -> state 1
0x40034f98  if (B.hdr[0] == "MMMM"):
                 same with B
                 -> 0x40035010: global 0x4006E9F0 = 2 ; ret 0        ; SLOT1 -> state 2
            A not MMMM      -> r4 += 1  => 0xC002005F
            B missing/mismatch -> r4 += 2 => 0xC0020030
```

So the two "states" **1 and 2 are not LOCKED/MP_DEFAULT values — they identify which of the
two seccfg slots carried a valid anti-clone-signed record**. The actual lock value the rest of
the DA sees is the **`+0xc` dword of the winning record's 0x1c-byte header** (e.g. `4` on this
device — the session notes' seccfg V4 `lock_state=4`; MP_DEFAULT-style value lives in the
record, not in the global).

### 4.3 What drives "LOCKED vs MP_DEFAULT" in `fcn.4002ce08`

Inputs, in order:
1. **sboot state** (`0x40033b08`): reads byte flag `0x4006E938` and word `0x40056E28`;
   if the module value is 0 → treated as 0x22, if 0x22 → **`get_hw_sbc` `0x40039d00`** (EFUSE
   SBC eFuse read; the known optional OPLUS_SBC_PATCH target). Result stored to out-param.
2. **seccfg lock state** (`0x40034d6c`, §4.2): the fetched `+0xc` field.
   * fetch returns `0xC002005A` (seccfg partition empty/absent) → the DA logs
     **"[SEC] set lock state as LOCKED"** (site `0x4002ceac`) and `sec_get_seccfg`'s default
     store leaves **1 = LOCKED** in the out-param. I.e. *missing seccfg ⇒ LOCKED by default*.
   * fetch returns any other error → "[SEC] get lock state fail, ret: %x".
   * success: the header field is printed — `"[SEC] lock_state = 0x%x"` (raw value,
     e.g. 4 = the device's shipped MP_DEFAULT-style value) or, when the field is 1 or 2,
     `"[SEC] lock_state(default) = 0x%x"` (branch `0x4002ceb8–0x4002cee8`; the extra
     `str 4,[sp]` at `0x4002cec8` makes the exact printed number uncertain — flagged above).
3. The final return value combines neither of the two directly: it is the **per-partition flag
   byte** from table `0x4005628c[idx]+0x16` — i.e. the policy is
   *table(partition) × (sboot state, seccfg lock state)*, and the seccfg/sboot state only gates
   the diagnostics/defaults around it.

The lock-state **global `0x4006E9F0` has exactly two writers, both inside `fcn.40034dfc`**
(`mov r1,1` @0x40034ffc store `0x40035020`; `mov r1,2` @0x40035014 same store) — consistent
with the README's "SEC state writers" note. Nothing else in the blob writes it, so the only way
the DA "sets lock state" is by re-reading and re-verifying seccfg.

### 4.4 Reserve copy

`oplusreserve2` string @`0x400454f5` is referenced once, at `0x40010924` — inside the
CMD:OPLUS-WRITE-HASH256-ID handler region (`0x40010a0c`/`0x40010a9c` registered at
`0x40001e10/0x40001e28`). The seccfg loader (`fcn.40034dfc`) reads **only** the partition
named `"seccfg"` (string `0x400454bc` passed to `0x4002d4d8`) — no reference to
oplusreserve* in that path. So question 3's reserve-copy hypothesis gets no static support
here; the reserve2 pointer at 0x40010924 belongs to the oplus hash256-ID machinery
(not analyzed further in this pass).

## 5. Op/handler summary of the SEC machinery ("op map")

| Op | VA | Notes |
|---|---|---|
| register XML command | `0x400086d4` (also `0x40008720`) | dispatcher builder, used at 0x40001a90–0x40001e28 |
| SECURE node executor (XML out, expect "OK") | `0x4002ae8c` | used by SECURITY-* cmds, node names "Signature", "SEC-POLICY" |
| CMD:SECURITY-SET-ALLINONE-SIGNATURE | `0x40006c1c` | node "Signature" → 0x4002ae8c → 0x4002d428 |
| CMD:SECURITY-GET-DEV-FW-INFO | `0x40006cf4` | 0x40007a24 → 0x4002b330 |
| CMD:SECURITY-SET-FLASH-POLICY | `0x40006ddc` | node "SEC-POLICY" → 0x4002ae8c → `cust_security_verify_sec_policy 0x40007abc` |
| policy lookup by partition name | `0x4002cbb4` | table 0x4005628c, 64×32B, alias fields +4/+8/+0xc/+0x10; auth==5 ⇒ "oplus_single_mode" 18-B match |
| policy query builder | `0x4002cf68` | fills out[1..3] flags, out[4], out[8]; prints "policy of partition: %s", "hash_binding = %d" |
| flag-byte getter | `0x4002ce08` | sboot + seccfg inputs; **contains "[SEC] set lock state as LOCKED" @0x4002ceac** |
| flag-bit extractors | `0x4002cdf4` (bit2), `0x4002cf20` (bit1), `0x4002cf34` (bit0) | |
| entry accessors | `0x4002cf48` (+0 word), `0x4002cd30` (+0x1c), `0x4002cd44` (+0x18 wide-digit parse) | |
| sboot state getter | `0x40033b08` | globals 0x4006E938 / 0x40056E28 → `get_hw_sbc` 0x40039d00 (EFUSE) |
| seccfg loader/verifier (state decider) | `0x40034dfc` | reads "seccfg" via 0x4002d4d8 into 0x4005cf00; two 0x3c-byte "MMMM" slots; sets 0x4006E9F0 = 1/2 |
| seccfg get wrapper | `0x40034d6c` | maps global 1→[0x40067640+0xc], 2→[0x40067600+0xc], else 0xC002005B |
| record digest | `0x4003a2d4` (→ `0x4003a510`) | 0x1c header → 0x20 digest |
| anti-clone scramble | `0x40035030` | flag byte 0x40056E30; prints "[%s] SECCFG Anti-Clone Enabled" (0x400510eb, %s="SEC_CFG"); → 0x400347d8 / 0x40034840(buf,0x20,flag) |
| partition read by name | `0x4002d4d8` | used with "seccfg" |
| GPT/PMT record compare (contains bogus "0x4002c800") | `0x4002c6f0` | called at 0x400026b8 / 0x4000411c / 0x40005010 |

Error codes observed: `0xC002002E` (seccfg read fail), `0xC002005A` (seccfg empty ⇒ default
LOCKED), `0xC002005B` (lock-state global invalid), `0xC002005F`/`0xC0020030` (record magic /
digest mismatch), `0xC0010001` (generic XML executor failure).

## 6. Confidence

* High: 0x4002c800 is not a function / no references exist (exhaustive byte scan);
  function starts `0x4002c6f0`, `0x4002ce08`, `0x40034dfc`, `0x40034d6c`, `0x4002cbb4`,
  `0x4002cf68`; command registration table; policy-table contents; "MMMM" slot verification;
  global 0x4006E9F0 writer sites.
* Medium: exact semantics of `0x4003a2d4`/`0x40034840` (labelled digest/scramble from call
  shapes and strings only), and the meaning of the `str 4,[sp]` inside the `{1,2}` print branch.
* Low/unverified: mapping of every `fcn.4002cf68` call site to its exact XML command (done by
  nearby strings, not full control-flow proof); whether entry flag bits 0/2 have dedicated
  names (no strings found).
