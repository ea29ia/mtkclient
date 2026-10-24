# RE: complete per-partition security-policy map, RMX3630 OPLUS DA2 (`da2_oplus.bin`)

> **ERRATA (2026-10-24, audit #2):** 0x4002F804 is the per-chunk **write
> dispatcher**, not an "image hash-list check" — stubbing it turned every write
> into a silent no-op (`re-f804-rootcause.md`). Q1/Q3/Q5 remain valid.
> See `re-consistency-audit-2.md` §3 (P1).

Date: 2026-10-24. Tool: radare2 (`-a arm -b 32 -m 0x40000000`, file offset 0 == VA).
Binary: `docs/notes/rmx3630-da2/da2_oplus.bin`, 356296 B = **0x56FC8** bytes
(sha256 `fd3a5038…`). Anything at VA ≥ 0x40056FC8 is **.bss** (zero at boot) — this
includes `g_oplus_auth_status` 0x4005455c and the tail-flag store **0x40067cce**.

Headline corrections vs earlier notes (marked **CORRECTION** throughout):

1. **Flag-byte bit assignment (proven):** of the flag byte at `table[idx]+0x16`,
   bit0 = `dl_forbidden`, bit1 = `img_auth_required`, bit2 = `hash_binding`.
   `re-sec-dispatch.md` §3 had bit1 = hash_binding — that is wrong; the parse
   `0x4002cf68` stores bit2→out[+1], bit1→out[+2], bit0→out[+3], and the print
   strings prove the names: `0x4004e973 "hash_binding = %d"` prints **out[+1]
   (bit2)**, `0x4004e986 "img_auth_required = %d"` prints **out[+2] (bit1)**,
   `0x4004e99e "dl_forbidden = %d"` prints **out[+3] (bit0)**.
2. **Lookup miss does NOT return −1 (proven).** `fcn.4002cbb4` walks r4 = 0..0x3e;
   on miss prints `0x4004e85f "[SEC_POLICY] reached the end, use default policy"`
   and **returns 0** — the `"default"` entry (flag byte 2 = img_auth_required=1).
   `re-sec-dispatch.md` §3 "Not found → return −1" is wrong (the −1-style exit
   only exists for r4==0x3f, which is converted to 0 at 0x4002cd0c–0x4002cd28).
3. **The policy-table deny byte (+3 = dl_forbidden) is 0 for every stock entry**
   (stock flag bytes are only 0x00 or 0x02). Stock deny for non-table partitions
   (seccfg, frp, …) comes from the **default entry's img_auth_required=1** via the
   WRITE-FLASH three-flag check — not from dl_forbidden.
4. **The uploaded SEC-POLICY body is never parsed into the table (proven).**
   `oplus_security_verify_sec_policy` (0x400103dc–0x400106a0) touches only:
   tail memcpy 0x40067cce←policy+0x700 (5 B), ctx byte [0x4006a088+0xc]=0x52,
   and `g_oplus_auth_status` writes (1/2/3/4/5). The 64-entry table at
   0x4005628c is **static and immutable at runtime**. A crafted policy body
   therefore changes *nothing* per-partition; only the 5 tail bytes matter, and
   under our RET0 patch not even those (see Q4).

---

## Q1 — Policy table dump (0x4005628c, 64 × 32 B)

Entry layout (proven from lookup `0x4002cbb4` + accessors `0x4002cd30/0x4002cd44/0x4002cf48`):

| off | field |
|---|---|
| +0x00 | dword `sw_id` — expected partition SWID, consumed by `fcn.40035e90` (`sw_id_verify`, prints `[SC] sw_id = 0x%x` / `partition_sw_id = 0x%x`, mismatch → 0xC0020027; callers 0x40036c2c / 0x40037590 = image-verify paths). Anti-rollback field. All stock entries = 0. |
| +0x04..+0x13 | up to 4 C-string pointers (name + aliases; strcmp'd in order +4, +8, +0xc, +0x10) |
| +0x14 | dword flag word; **byte at +0x16 (byte 2 of the word) is THE flag byte** returned by `fcn.4002ce08` |
| +0x18 | ptr to "wide-digit" string (2-byte stride parse → number); only preloader non-null |
| +0x1c | ptr to extra name (md1img/md1img_1 → `"md1_filter"` @0x40055fac) |

Full dump (decoded from raw bytes; `fb` = flag byte +0x16, bits h/i/d = hash_binding/img_auth/dl_forbidden):

| idx | VA | name(s) | +0x14 | fb | h | i | d | extra |
|---|---|---|---|---|---|---|---|---|
| 0 | 0x4005628c | default | 0x20000 | 2 | 0 | 1 | 0 | fallback for ALL non-table names |
| 1 | 0x400562ac | preloader | 0x20000 | 2 | 0 | 1 | 0 | +0x18 = 0x4004e4c1 = 64-hex string `fdd62730afd983f367b267037d1668c164ab51568485ba305621cc28d6268d96` (wide-parsed into out[4]; inferred: expected preloader hash) |
| 2 | 0x400562cc | lk | 0x20000 | 2 | 0 | 1 | 0 | |
| 3 | 0x400562ec | logo | 0x20000 | 2 | 0 | 1 | 0 | |
| 4 | 0x4005630c | boot, boot_a, boot_b | 0 | 0 | 0 | 0 | 0 | |
| 5 | 0x4005632c | vendor_boot, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 6 | 0x4005634c | recovery | 0 | 0 | 0 | 0 | 0 | |
| 7 | 0x4005636c | system, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 8 | 0x4005638c | vendor, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 9 | 0x400563ac | odm, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 10 | 0x400563cc | vbmeta, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 11 | 0x400563ec | tee1 | 0x20000 | 2 | 0 | 1 | 0 | |
| 12 | 0x4005640c | tee2 | 0x20000 | 2 | 0 | 1 | 0 | |
| 13 | 0x4005642c | cache | 0 | 0 | 0 | 0 | 0 | |
| 14 | 0x4005644c | secro | 0 | 0 | 0 | 0 | 0 | |
| 15 | 0x4005646c | oemkeystore | 0x20000 | 2 | 0 | 1 | 0 | |
| 16 | 0x4005648c | keystore | 0x20000 | 2 | 0 | 1 | 0 | |
| 17 | 0x400564ac | userdata | 0x20000 | 2 | 0 | 1 | 0 | |
| 18 | 0x400564cc | md1img, _a, _b | 0x20000 | 2 | 0 | 1 | 0 | +0x1c="md1_filter" |
| 19 | 0x400564ec | md1img_1, _a, _b | 0x20000 | 2 | 0 | 1 | 0 | +0x1c="md1_filter" |
| 20 | 0x4005650c | md1dsp | 0x20000 | 2 | 0 | 1 | 0 | |
| 21 | 0x4005652c | md1arm7 | 0x20000 | 2 | 0 | 1 | 0 | |
| 22 | 0x4005654c | md3img | 0x20000 | 2 | 0 | 1 | 0 | |
| 23 | 0x4005656c | sgpt, SGPT | 0 | 0 | 0 | 0 | 0 | |
| 24 | 0x4005658c | pgpt, PGPT | 0 | 0 | 0 | 0 | 0 | |
| 25 | 0x400565ac | efuse, EFUSE | 0 | 0 | 0 | 0 | 0 | |
| 26 | 0x400565cc | cam_vpu1 | 0x20000 | 2 | 0 | 1 | 0 | |
| 27 | 0x400565ec | cam_vpu2 | 0x20000 | 2 | 0 | 1 | 0 | |
| 28 | 0x4005660c | cam_vpu3 | 0x20000 | 2 | 0 | 1 | 0 | |
| 29 | 0x4005662c | spmfw, SPMFW | 0x20000 | 2 | 0 | 1 | 0 | |
| 30 | 0x4005664c | mcupmfw, MCUPMFW | 0x20000 | 2 | 0 | 1 | 0 | |
| 31 | 0x4005666c | nvram | 0 | 0 | 0 | 0 | 0 | |
| 32 | 0x4005668c | protect1 | 0 | 0 | 0 | 0 | 0 | |
| 33 | 0x400566ac | protect2 | 0 | 0 | 0 | 0 | 0 | |
| 34 | 0x400566cc | proinfo | 0 | 0 | 0 | 0 | 0 | |
| 35 | 0x400566ec | nvcfg | 0 | 0 | 0 | 0 | 0 | |
| 36 | 0x4005670c | persist | 0 | 0 | 0 | 0 | 0 | |
| 37 | 0x4005672c | odmdtbo, _a, _b, ODMDTBO | 0x20000 | 2 | 0 | 1 | 0 | |
| 38 | 0x4005674c | dtbo, _a, _b, DTBO | 0x20000 | 2 | 0 | 1 | 0 | |
| 39 | 0x4005676c | persistent, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 40 | 0x4005678c | vbmeta_system, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 41 | 0x400567ac | vbmeta_vendor, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 42 | 0x400567cc | super, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 43 | 0x400567ec | mcf1, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 44 | 0x4005680c | mcf2, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 45 | 0x4005682c | mcf_ota, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 46 | 0x4005684c | rootfs, _a, _b | 0 | 0 | 0 | 0 | 0 | |
| 47 | 0x4005686c | "" (empty name ptr 0x4004b1e8) | 0 | 0 | 0 | 0 | 0 | dead slot |
| 48 | 0x4005688c | "" (same) | 0 | 0 | 0 | 0 | 0 | dead slot |
| 49 | 0x400568ac | reserve3 | 0 | 0 | 0 | 0 | 0 | |
| 50 | 0x400568cc | reserve4 | 0 | 0 | 0 | 0 | 0 | |
| 51 | 0x400568ec | reserve_exp2 | 0 | 0 | 0 | 0 | 0 | |
| 52 | 0x4005690c | reserve_exp3 | 0 | 0 | 0 | 0 | 0 | |
| 53 | 0x4005692c | special_preload | 0 | 0 | 0 | 0 | 0 | |
| 54 | 0x4005694c | ocdt | 0 | 0 | 0 | 0 | 0 | |
| 55 | 0x4005696c | oplus_custom | 0 | 0 | 0 | 0 | 0 | |
| 56 | 0x4005698c | oplusreserve1 | 0 | 0 | 0 | 0 | 0 | |
| 57 | 0x400569ac | oplusreserve2 | 0 | 0 | 0 | 0 | 0 | |
| 58 | 0x400569cc | oplusreserve5 | 0 | 0 | 0 | 0 | 0 | |
| 59 | 0x400569ec | oplusreserve6 | 0 | 0 | 0 | 0 | 0 | |
| 60 | 0x40056a0c | param | 0 | 0 | 0 | 0 | 0 | |
| 61 | 0x40056a2c | oplus_single_mode | 0 | 0 | 0 | 0 | 0 | matched byte-exactly only when g_oplus_auth_status==5 |
| 62 | 0x40056a4c | NULL ×4 (ptr 0x4004e837) | 0 | 0 | 0 | 0 | 0 | sentinel |
| 63 | 0x40056a6c | — | — | 0xc1* | 1 | 1 | 1 | terminator/garbage (`f0=1, +0x14=0x11c10430`); *never used: miss returns idx 0, not 63* |

Semantics of the flag word's other bytes (+0x14 low byte, +0x15, +0x17): all zero in
every stock entry — no additional per-entry flags exist in this build. No
"read-back-only" or "no-erase" bit exists **in the table** (the keep/no-erase
machinery lives elsewhere — see Q4).

Special case (proven): `g_oplus_auth_status == 5` ("oplus_single_mode", policy
tail byte +0x700 == 0x19) changes the lookup so only a byte-exact 18-B match of
entry 61 `"oplus_single_mode"` succeeds. Irrelevant under our patches (status=1).

## Q2 — Parsed policy-struct layout (built by `fcn.4002cf68(name, struct)`)

`0x4002cf68` = lookup + 3 bit-extractor calls + 2 accessor calls, storing **bytes**
into the caller's struct. Callers memset only 0x14 bytes before the call
(e.g. WRITE-PARTITION `memset(fp-0x90,0,0x14)` @0x40002144; ERASE-FLASH
`memset(sp+0x40,0,0x14)`; the "0x200 buffer" in the mission brief is the
SET-FLASH-POLICY XML-unescape buffer `0x4002aba8` — a different object; the
policy struct itself is this small stack struct). Proven layout:

| off | type | content | consumers |
|---|---|---|---|
| +0x00 | dword | 0 (memset only; parse never writes it) | — |
| +0x01 | byte | **hash_binding** = flag-byte bit2 | WRITE-FLASH deny (3rd check, [base+1]); preloader write-engine per-chunk SHA-256 gate (`0x4000bdb0 ldrb [sl,1]` → memcmp vs expected hash) |
| +0x02 | byte | **img_auth_required** = bit1 | WRITE-FLASH deny (2nd check, [base+2]); preloader-engine secondary hash/ACC verify (`0x4000be10 ldrb [sl,2]` → `0x40037f70`) |
| +0x03 | byte | **dl_forbidden** = bit0 — **THE deny byte** | WRITE-PARTITION @0x400021a0; WRITE-FLASH (1st check, [base+3]) @0x40003194; WRITE-PARTITIONS @0x40002788 & 0x40002af4; ERASE-PARTITION @0x4000392c; ERASE-FLASH @0x40003ccc & 0x40004554 |
| +0x04 | dword | number wide-parsed from entry+0x18 (preloader only: the 64-hex string) | logged/unused elsewhere (uncertainty) |
| +0x08 | dword | entry+0x1c pointer ("md1_filter" for md1img*) | passed to md1 filter machinery (uncertainty) |
| +0x0c..0x13 | — | 0 (memset tail) | — |

Predicting a crafted policy blob: **it cannot change any of the above** — the
parse always reads the static table. The only runtime-mutable policy state is the
5-byte tail store 0x40067cce (Q4) and `g_oplus_auth_status`. Since the stock table
has dl_forbidden=0 everywhere and default-entry img_auth=1, the *effective* stock
denies are: WRITE-FLASH on any img_auth partition or non-table partition;
everything else writable policy-wise.

### Deny-check inventory (all proven sites)

| cmd | site | check | stock outcome for non-table name (e.g. seccfg) |
|---|---|---|---|
| WRITE-PARTITION (0x40002034) | 0x400021a0 | `if (s[3]) deny` | **allowed** (default dl_forbidden=0); logs `hash_binding:%d, img_auth_required:%d` |
| WRITE-FLASH (0x40002e60) | 0x40003194–0x400031b0 (BEQs to 0x400031d4 at 0x400031a4/0x400031b0) | `if (s[3]==1 \|\| s[2]==1 \|\| s[1]==1) deny` | **denied** (img_auth=1) — the observed `Security deny for [seccfg].` |
| WRITE-PARTITIONS (0x40002598) | 0x40002788 (bne→0x40002e38), 0x40002af4 | `if (s[3]) deny` | allowed |
| ERASE-PARTITION (0x400037ec) | 0x4000392c | `if (s[3]) deny` | allowed |
| ERASE-FLASH (0x400039c0) | 0x40003ccc (loop over flash list, struct sp+0x40) and 0x40004554 (second loop, struct sp+0x70, plus byte `[0x4006a974+0x10][i]`) | `if (s[3]) deny` (+ extra flash-list byte) | allowed policy-wise |
| READ-PARTITION / READ-FLASH / READ-PARTITION-TABLE (0x400032d0 / 0x400033f0 / 0x4000362c) | none | no policy parse, no deny | always allowed (gated only by command-table registration) |

Note: the session note "WRITE-PARTITIONS global 0x40054314" is a **misread**
(proven): 0x40054314 holds the pointer to `"Required XML node path not found. …"`
(0x40041748) and the sites (0x40002108/0x4000211c/0x40002658/…) are XML-parse
error prints through the generic printer 0x400084a4 — not a deny flag. The
~130 callers of 0x400084a4 include ordinary error prints; it is a printf-class
helper, which is why patching it was forbidden.

## Q3 — Effective per-partition permissions with the campaign patch set

Patch set (from session notes, all runtime via heapbait `patch_mem`):
P1 `oplus_security_verify_sec_policy` 0x400103dc RET0 (+ `cust_…` 0x40007abc RET0);
P2 `g_oplus_auth_status` 0x4005455c := 1 → FULL command table;
P3 WRITE-FLASH deny BEQs 0x400031a4/0x400031b0 NOPed;
P4 WRITE-PARTITION deny byte 0x400021a0 → `mov r0,#0`;
P5 digest-accept bypass (image hash-list 0x4002f804 RET0 family).
NOT patched: ERASE-PARTITION 0x4000392c, ERASE-FLASH 0x40003ccc/0x40004554,
WRITE-PARTITIONS 0x40002788/0x40002af4, SWID check `fcn.40035e90`, seccfg
loader/anti-clone (0x40034dfc/0x40035030), WRITE-FLASH scrubber.

Consequence of Q1: stock dl_forbidden = 0 for **all** reachable lookups
(table entries and default fallback), so the unpatched ERASE/WRITE-PARTITIONS
dl_forbidden checks never fire against stock policy. `hash_binding` = 0
everywhere too; `img_auth_required` = 1 for the 20 "secure-boot image"
entries + default.

Legend: **R/W/E** = read/write/erase via the respective XML commands.
- read: always **allowed** for every partition (no policy check in any READ-*
  handler; needs status 4+ table ⇒ satisfied by P2). Wedged-DA sessions can
  return zeros (session observation) — operational, not policy.
- write via WRITE-PARTITION: **allowed for every partition** (P4 kills the only
  check; dl_forbidden was 0 anyway).
- write via WRITE-FLASH: **allowed for every partition** (P3 kills the
  three-flag check; stock it would deny the img_auth set + all non-table names).
  **EXCEPTION seccfg (and the seccfg area): FORBIDDEN operationally** — any
  WRITE-FLASH exchange touching seccfg zero-scrubs the area (observed 4×,
  session notes §"Anti-tamper scrubber"); use WRITE-PARTITION only.
- write via WRITE-PARTITIONS: allowed (dl_forbidden=0; check unpatched but inert).
- erase via ERASE-PARTITION / ERASE-FLASH: **policy-allowed for every
  partition** (dl_forbidden=0 everywhere). Residual risks: the ERASE-FLASH
  second-loop flash-list byte (0x4006a974 array, host/XML-fed) and the
  post-write/post-erase SEC service pass (seccfg regeneration; post-write
  hang/EIO — session open question).

Per-partition matrix (GPT names from the campaign's 44-partition read; "table"
columns show which policy entry the lookup hits; ⚠ marks operational
non-policy hazards; GPT-name→table mapping is proven for exact-name matches,
inference `~` where the GPT spelling may differ):

| GPT partition | policy lookup | stock img_auth | read | write (WP/WF) | erase | notes |
|---|---|---|---|---|---|---|
| preloader | [1] preloader (2) | 1 | allowed | allowed / allowed | allowed | preloader-engine path (0x4000c348→fcn.4000bb14) with per-chunk SHA-256 + `md1_filter`-style extra verify; P5 covers the hash checks; hash string out[4] |
| lk | [2] lk (2) | 1 | allowed | allowed/allowed | allowed | |
| logo | [3] (2) | 1 | allowed | allowed/allowed | allowed | |
| boot, boot_a/b | [4] (0) | 0 | allowed | allowed/allowed | allowed | |
| vendor_boot | [5] (0) | 0 | allowed | allowed/allowed | allowed | |
| recovery | [6] (0) | 0 | allowed | allowed/allowed | allowed | |
| system | [7] (0) | 0 | allowed | allowed/allowed | allowed | super subvol typically |
| vendor | [8] (0) | 0 | allowed | allowed/allowed | allowed | |
| odm | [9] (0) | 0 | allowed | allowed/allowed | allowed | |
| vbmeta (+_system/_vendor) | [10]/[40]/[41] (0) | 0 | allowed | allowed/allowed | allowed | AVB: device may still refuse at boot (out of DA scope) |
| tee1/tee2 (~GPT "tee") | [11]/[12] (2) | 1 | allowed | allowed/allowed | allowed | |
| cache | [13] (0) | 0 | allowed | allowed/allowed | allowed | |
| secro | [14] (0) | 0 | allowed | allowed/allowed | allowed | |
| oemkeystore/keystore | [15]/[16] (2) | 1 | allowed | allowed/allowed | allowed | |
| userdata | [17] (2) | 1 | allowed | allowed/allowed | allowed | fscrypt keys inside — erasing = data loss |
| md1img | [18] (2) | 1 | allowed | allowed/allowed | allowed | +0x1c "md1_filter" |
| md1img_1 | [19] (2) | 1 | allowed | allowed/allowed | allowed | |
| md1dsp / md1arm7 / md3img | [20]/[21]/[22] (2) | 1 | allowed | allowed/allowed | allowed | ~GPT may not expose these |
| sgpt / pgpt | [23]/[24] (0) | 0 | allowed | allowed/allowed | allowed | GPT itself — write carefully |
| efuse | [25] (0) | 0 | allowed | allowed/allowed | allowed | efuse *partition*; real efuse via READ/WRITE-EFUSE cmds |
| cam_vpu1/2/3 | [26–28] (2) | 1 | allowed | allowed/allowed | allowed | ~not in this GPT |
| spmfw | [29] (2) | 1 | allowed | allowed/allowed | allowed | |
| mcupm (~GPT name; table "mcupmfw") | [30] (2) if exact match, else default | 1 | allowed | allowed/allowed | allowed | |
| nvram / protect1 / protect2 / proinfo / nvcfg / persist | [31–36] (0) | 0 | allowed | allowed/allowed | allowed | **back these up first** (persist=sen-sor cal etc.) |
| odmdtbo / dtbo | [37]/[38] (2) | 1 | allowed | allowed/allowed | allowed | |
| persistent | [39] (0) | 0 | allowed | allowed/allowed | allowed | |
| super | [42] (0) | 0 | allowed | allowed/allowed | allowed | |
| mcf1 / mcf2 / mcf_ota / rootfs | [43–46] (0) | 0 | allowed | allowed/allowed | allowed | ~may be absent |
| reserve3/4/exp2/exp3, special_preload, ocdt, oplus_custom, param | [49–55], [60] (0) | 0 | allowed | allowed/allowed | allowed | ocdt/oplus_custom feed the signed device ctx — **do not modify** (breaks ctx match for any future genuine-policy replay) |
| oplusreserve1 / 2 / 5 / 6 | [56–59] (0) | 0 | allowed | allowed/allowed | allowed | oplusreserve2 holds a seccfg V4 copy (session proven); writing it does NOT touch real seccfg |
| **seccfg** | **miss → default (2)** | 1 | allowed | allowed via WP (**WF FORBIDDEN — scrubber zeroes it**) ⚠ | allowed policy-wise ⚠ | WRITE-PARTITION commit triggers SEC regeneration: uploaded bytes ignored, state rewritten (session-proven). Full 8MB padded write required |
| frp | miss → default (2) | 1 | allowed | allowed/allowed | allowed | |
| misc, para | miss → default (2) | 1 | allowed | allowed/allowed | allowed | para = bootloader msg |
| gz | miss → default (2) | 1 | allowed | allowed/allowed | allowed | ~not in DA table |
| scp / sspm / pi_img | miss → default (2) | 1 | allowed | allowed/allowed | allowed | |
| md1gd3 | miss → default (2) | 1 | allowed | allowed/allowed | allowed | |
| nvdata | miss → default (2) | 1 | allowed | allowed/allowed | allowed | table has nvcfg, not nvdata |
| persistbak | miss → default (2) | 1 | allowed | allowed/allowed | allowed | |
| oplusreserve3/4 (if present) | miss → default (2) | 1 | allowed | allowed/allowed | allowed | table has 1,2,5,6 only |

Bottom line for the campaign: **with the patch set, nothing is policy-blocked**.
The remaining protections are non-policy: (a) WRITE-FLASH seccfg scrubber
(operational rule: never WRITE-FLASH seccfg), (b) SEC-service regeneration of
seccfg content on WRITE-PARTITION, (c) post-write hang/EIO of unknown origin
(session open question 1), (d) boot-time AVB/anti-rollback outside the DA
(vbmeta/lk contents still matter), (e) READ/WRITE-EFUSE and DEBUG:UFS remain
as registered.

## Q4 — keep/no-erase semantics and the RET0-vs-seeding question

**Answer: with our RET0 patch, the seeding does NOT run; 0x40067cce stays
all-zero.** Trace (proven from disasm):

```
cust_security_verify_sec_policy 0x40007abc   <- RET0 patched here too
  ... bl 0x400103dc  (at 0x40007a?? region)  <- never reached
oplus_security_verify_sec_policy 0x400103dc  <- RET0 patched here
  0x400103f4 bl 0x40007cbc        (loglevel get)
  0x400103f8 cmp r0,4 / bhi       (log gate)
  0x40010424 movw r5,0x7cce       ; dest = 0x40067cce (.bss)
  0x40010428 add r1,r6,0x700      ; src = policy+0x700
  0x40010430 mov r2,5
  0x40010434 mov r0,r5
  0x40010438 bl 0x4000b110        ; memcpy — the seeding
```

A `mov r0,#0; bx lr` stub at 0x400103dc (8 bytes) returns before 0x40010424;
the cust-wrapper RET0 at 0x40007abc returns even earlier. Either patch alone
prevents the seeding. Also note: even on stock, the XML node buffer is ≤0x200
and policy len ≤0x400, so policy+0x700 in the 2MB zero-filled malloc copy reads
as 0 — the tail flags are unreachable via the normal XML path anyway
(re-oplus-auth-paths.md §2.3, inference, stands).

What 0x40067cce controls (only consumer: `fcn.400108c4(name)` — the
OPLUS-WRITE-HASH256-ID / format decision helper, called from the
0x40010a0c/0x40010a9c command handlers):

| 0x40067cce byte | meaning (proven from 0x400108c4) |
|---|---|
| +0 | "single mode" selector (verifier-side: ==0x19 && status==1 ⇒ status=5) — never consumed by 0x400108c4 |
| +1 | oplusreserve2 format flag: ==0x1a ⇒ "need format in smt" (return 1), else "do not format" (2) |
| +2 | seccfg format flag: ==1 ⇒ "[OPLUS] need format seccfg" (return 1), else 2 |
| +3 | master kill: !=0 ⇒ function returns 0 immediately for every name |
| +4 | userdata/metadata format flag: ==1 ⇒ return 1, else 2 |

Return values: 1 = format/wipe allowed, 2 = "do not format", 0 = name not
applicable. With 0x40067cce all-zero (our patch state): seccfg→2,
oplusreserve2→2, userdata→2, metadata→2, everything else→0. I.e. **the
hash256-ID/format machinery is in its most conservative state — nothing gets
auto-formatted.** This is safe (no accidental wipes) and only blocks the
OPLUS-WRITE-HASH256-ID formatting behavior, which we don't use.

**"[oplus]keep %s" (fcn.40005400) — NOT policy-table driven (proven).** It reads
the flash-list session object at 0x4006a974: `[+4]` = entry count,
`[+8]` = 0x58-stride name records (name at +8), `[+0x10]` = 0x20c-stride records
whose byte at +0x200 is the keep flag and dword at +0x208 is compared to 3.
These records are populated from the **uploaded XML flash_list of a firmware-
upgrade package** (FU_S1/FU_S3 machinery, "In FU_S3" string adjacent), i.e. the
keep/no-erase set is whatever the host's flash_list marks — not the 0x4005628c
table and not 0x40067cce. At boot with no FU package, the list is empty and no
partition is marked keep. Practical consequence: when using WRITE-PARTITIONS /
FU flows, keep flags come from our own XML; ordinary WRITE-PARTITION /
ERASE-PARTITION never consult them.

Which partitions does *stock* policy mark keep/no-erase: **none** — there is no
keep flag in the policy table (all non-flag bytes zero) and the flash list is
empty at boot. The only "protected" stock behavior for seccfg/oplusreserve2/
userdata/metadata is the hash256-ID format gate above (returns 2 = do-not-format
with zeroed tail flags), plus the WRITE-FLASH scrubber/SEC-regeneration behavior
(operational, session-proven).

## Confidence summary

- **Proven (disassembly):** table contents/layout; flag-bit naming; parse-struct
  layout and all deny sites incl. WRITE-FLASH three-flag logic; lookup-miss →
  default entry (flag 2); policy body never parsed into the table; seeding
  memcpy at 0x40010424–0x40010438 inside the RET0'd function; 0x40067cce is
  .bss; 0x400108c4 semantics; 0x40054314 = XML-error string ptr (not a deny
  global); "[oplus]keep" flash-list mechanism; SWID field (+0) semantics.
- **Inference (medium):** preloader +0x18 64-hex string = expected preloader
  hash (parsed but not traced to a compare site); out[4]/out[8] downstream use;
  GPT-name→table alias mapping for names not seen verbatim (tee→tee1/tee2,
  mcupm→mcupmfw, md1gd3, gz, pi_img → default).
- **Operational (session-proven, not static):** seccfg WRITE-FLASH scrubber,
  seccfg regeneration on WRITE-PARTITION, post-write hang/EIO.
