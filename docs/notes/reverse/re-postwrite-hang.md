# Re: post-WRITE hang / EIO after full WRITE-PARTITION to seccfg

> **ERRATA (2026-10-24, audit #2):** 0x4000EA94 is a **recursive tree free**
> (`bl 0x4000A5F0` @0x4000EB4C, mxmlDelete), not a "send response" or
> "send error status" helper. See `re-consistency-audit-2.md` §3 (P5).

Reverse-engineering answer to open question #1 of
`docs/notes/rmx3630-da2/README.md`. Blob: `docs/notes/rmx3630-da2/da2_oplus.bin`
(file offset 0 == VA 0x40000000, ARM32, analyzed with radare2).

## TL;DR verdict

The post-upload hang is the **HACC (Hardware AES) busy-wait inside the
"ACC" anti-clone pass that runs on the write buffer after the last data
chunk is received** — not in `sec_get_seccfg` itself, but in the HACC
driver it shares.

Three **unbounded, zero-timeout busy-wait loops** on the HACC registers
at `0x1000A008/0x1000A060`:

| VA | loop | waits for |
|---|---|---|
| **0x400397d8–0x400397e0** | `ldr r0,[r1]; cmn r0,#1; bgt 0x400397d8` | `0x1000A008 == 0xFFFFFFFF` (HACC init, fcn.4003975c) |
| **0x40039840–0x40039848** | `ldr r4,[r3]; tst r4,#0x8000; beq 0x40039840` | READY bit 0x8000 at `0x1000A008` (HACC transform, fcn.40039800) |
| **0x40034b10–0x40034b18** | `ldr r0,[ip]; tst r0,#0x8000; beq 0x40034b10` | READY bit 0x8000 (fcn.40034a78) |

If the HACC AHB register never reaches the awaited state (clock gated,
hardware wedged, register stuck at a non-matching value — intermittently,
matching the observed "sometimes completes, sometimes hangs" behavior),
the DA spins forever: no response → host timeout → EIO → device drops.

### Most likely hang instruction

`0x40039844: tst r4, #0x8000` / `0x40039848: beq 0x40039840` — the
READY-poll of the HACC data transform, reached with r3 = 0x1000A008
during the post-upload ACC pass. Runner-up: the init poll at
`0x400397dc` (`cmn r0,#1; bgt`). Ambiguity is acknowledged below.

### Runtime patch (heapbait `patch_mem`)

Minimal, safe-order:

1. **Kill the busy-waits** (turn the hardware polls into single-shot
   reads):
   - `0x40039848`: `beq 0x40039840` → `nop` (`00 00 A0 E1`)
   - `0x400397e0`: `bgt 0x400397d8` → `nop`
   - `0x40034b18`: `beq 0x40034b10` → `nop`
2. **Or/and skip the whole ACC pass** in the write engine: patch
   `0x4000c210` (`beq 0x4000c258`, taken when the ACC flag byte is 0)
   to an unconditional `b 0x4000c258` (`ea 00 00 0e`), so
   fcn.40034810/40034840/4003482c never run on writes. Alternatively
   `patch_mem` a 0 into the ACC-enable byte `0x40067BA9`
   (read by fcn.40033b64 at 0x40033bbc) before the write.
   *Caveat*: this skips the HACC transformation of the written data —
   if any reader expects the ACC-encrypted layout, content differs.
   Since the SEC service regenerates seccfg content itself anyway, this
   is likely acceptable for unlock purposes, but it is unverified.
3. Do **not** RET0 the SEC state writers (0x40034ffc/0x40035014) to fix
   the hang — session evidence (commit 39ac1f3) suggests patching them
   broke regeneration without removing the hang. The hang and the
   state-rewrite are separate mechanisms.

---

## 1. `sec_get_seccfg` (0x40034d6c) — full disassembly & callees

```
0x40034d6c  push {r4,r5,fp,lr}
0x40034d70  add  fp, sp, #8
0x40034d74  mov  r4, r0                ; out ptr
0x40034d78  bl   0x40034dfc            ; UNCONDITIONAL: full seccfg re-read+classify
0x40034d7c  mov  r5, r0                ; ret of init (0 ok / 0xc002xxxx err)
0x40034d80  bl   0x40007cbc            ; get loglevel
0x40034d84  cmp  r0, #4 ; bhi skip log ; "[SEC] sec_get_seccfg ret=%..." print
0x40034da4  movw r0, 0xE9F0 ; movt 0x4006  ; r0 = &lock-state global 0x4006E9F0
0x40034dac  ldr  r1, [r0]
0x40034db0  mov  r0, #1
0x40034db4  cmp  r1, #0 ; beq 0x40034df0   ; state 0  -> *out = 1
0x40034dbc  cmp  r1, #2 ; beq 0x40034dd8   ; state 2  -> *out = [0x40067600+0xc]
0x40034dc4  cmp  r1, #1 ; bne 0x40034de8   ; else     -> r5 = 0xC002005B (err)
0x40034dcc  movw r0, 0x7640 ; movt 0x4006  ; state 1  -> [0x40067640+0xc]
0x40034dd8/... ldr r0, [r0, #0xc]
0x40034df0  str  r0, [r4]
0x40034df4  mov  r0, r5
0x40034df8  pop  {r4,r5,fp,pc}
```

**Key correction to the session notes:** `sec_get_seccfg` does NOT only
"cache state in 0x4006E9F0" — it calls the init/classify worker
`0x40034dfc` on **every invocation** (no "already initialized" check).
Only the resulting state *number* (1/2) is cached in 0x4006E9F0; the
expensive part (flash read + SHA + HACC) re-runs each call.

### Callee fcn.40034dfc (the worker) — this is where the work/hang risk is

```
0x40034e08-34e64  memset/memzero: sp+0x10 (0x40), 0x40067640 (0x40),
                  0x40067600 (0x40), 0x4005CF00 (0x3000)   ; 0x4000b330 = memset
0x40034e68-34e84  r0=0x400454BC (name "seccfg"-ish), r2=0, r3=0,
                  sp={0x3000, 0, 0x4005CF00}
0x40034e84        bl 0x4002d4d8          ; FLASH READ of ~0x3000 bytes into 0x4005CF00
0x40034e88-34e90  r4 = 0xC002002E ; cmp r0,0 ; beq ok
                  ... err path: r4 = 0xC002002E/2F/... return
--- ok path ---
0x40034ec4-34f08  memcpy pieces of the 0x58-byte record from 0x4005CF00
                  into 0x40067640 (r6) and 0x40067600 (sl)
                  (0x4000b110 = memcpy, 0x4000b0d8 = memcmp)
0x40034f0c-34f3c  memcmp 0x40 bytes: [0x40067640] vs stack copy,
                  then [0x40067600] vs stack copy; both equal -> 0x40035008 (r4 += 0x2c)
0x40034f40        ldr r0,[r6]; cmp r0,#0x4D4D4D4D  ; "MMMM" magic
                  if match: sha/decrypt 0x1c bytes via 0x4003a2d4 (SHA-256 wrapper:
                  0x4003a334 init, 0x4003a3a4 update w/ last-block flag)
                  -> fcn.40035030(buf)  [STATE CLASSIFIER + HACC, see below]
                  -> memcmp(buf, 0x40067640+0x20, 0x20) == 0 -> 0x40034ffc
0x40034f98        same for sl (0x40067600): magic MMMM -> classify -> match -> 0x40035010
0x40034fec/34ff4  r4 += 2 / r4 += 1  (verification-failure error codes)
--- state writers (as in notes) ---
0x40034ffc  movw r0,0xE9F0 ; mov r1,#1 ; b 0x40035018   ; LOCKED
0x40035010  movw r0,0xE9F0 ; mov r1,#2                  ; MP_DEFAULT
0x40035018  movt r0,0x4006 ; mov r4,#0
0x40035020  str  r1,[r0]                                ; [0x4006E9F0] = 1|2
0x40035024  mov r0,r4 ; pop
```

### Callee fcn.40035030 (classifier) — HACC gate + the Anti-Clone print

```
0x40035030  push {r4,r5,fp,lr}; r5 = arg (0x20-byte hash block)
0x4003503c  movw r0,0x6E30; movt 0x4005
0x40035044  ldrb r4,[0x40056E30]        ; ACC/HACC-enabled flag (global)
0x40035048  cmp r4,#0 ; movwne r4,#1 ; beq 0x40035090 (skip HACC)
0x40035054  get loglevel; print "[%s] SECCFG Anti-Clone Enabled\n" (0x400510eb)
0x40035074  bl 0x400347d8               ; if [0x400679D8] has MMMM magic:
            0x400347fc: bl 0x400398b0   ; copy 8 words -> 0x1000A060 (HACC key reg)
0x4003507c  bl 0x40034840(r5, 0x20, r4) ; HACC-decrypt the 0x20 hash block
0x40035088  b   0x4003482c              ; HACC key clear (0x400398d4: memset 0x1000A060,0x20)
```

`0x40056E30`'s writers were not located (no movw/movt pair found —
possibly set via literal pool in a region r2 did not analyze); marking
that as **ambiguous**.

### fcn.40034840 — the HACC wrapper (both read-classify and write path)

```
0x40034840  push {r4,r5,r6,sl,fp,lr}; r4=buf r5=len r6=flag(arg3)
0x40034854  get loglevel; "SEC_HACC" prints (0x40051078)
0x4003487c  mov r0,#1 ; bl 0x4003975c     ; HACC init (arg1=1)
0x40034890  bl 0x40039800(r4, r5, r4)     ; HACC transform in place
0x40034894  bl 0x40039880                 ; HACC reset regs
            (arg3==0 path: 0x400348bc bl 0x40034948(0,0x20) then b 0x40034a78)
0x400348e8  b 0x40034a78                  ; secondary HACC op (also busy-waits)
```

### The HACC driver polling loops (the hang candidates)

fcn.4003975c (HACC init, base r1 = 0x1000A008):

```
0x400397a4  str r2,[r1]            ; write config (2 or 3)
0x400397cc  ldr r0,[r1]
0x400397d0  orr r0,r0,#0x40000000  ; START bit
0x400397d4  str r0,[r1]
0x400397d8  ldr r0,[r1]            ; <-- POLL
0x400397dc  cmn r0,#1              ; until register == 0xFFFFFFFF
0x400397e0  bgt 0x400397d8         ; NO TIMEOUT
```

fcn.40039800 (HACC transform, r3 = 0x1000A008):

```
0x4003983c  str lr,[r3]            ; lr=1: GO
0x40039840  ldr r4,[r3]            ; <-- POLL
0x40039844  tst r4,#0x8000         ; READY bit
0x40039848  beq 0x40039840         ; NO TIMEOUT
0x40039850  ... read results from [r3+r4*2+0x48], loop 4 words per 16-byte block
```

fcn.40034a78 (secondary HACC op, ip = 0x1000A008-ish):

```
0x40034b10  ldr r0,[ip]            ; <-- POLL
0x40034b14  tst r0,#0x8000
0x40034b18  beq 0x40034b10         ; NO TIMEOUT
```

None of the three has a counter/timeout — a single wedged HACC
transaction hangs the whole agent permanently.

## 2. Who calls `sec_get_seccfg` (axt)

Direct callers (exactly one call site):

```
0x4002ce80  bl 0x40034d6c      ; inside fcn.4002ce08 ("get lock state")
```

Upstream:

```
fcn.4002ce08 (0x4002ce08)           -- resolve lock_state, prints
    "[SEC] set lock state as LOCKED" @0x4002ceac when ret==0xC002005A
    "[SEC] lock_state = 0x%x" / "(default)"
  <- 0x4002cf20 (img_auth flag extractor)
  <- 0x4002cf34 (dl_forbidden flag extractor)
  <- 0x4002cdf4
       <- both extractors called from 0x4002cf68 ("parse policy flags")
          <- 0x4000217c  WRITE-PARTITION  (0x40002034)   [pre-upload deny check]
          <- 0x40002754  WRITE-PARTITIONS (0x40002598)
          <- 0x400030f0  WRITE-FLASH      (0x40002e60)
          <- 0x400038e8 / 0x40003c30 / 0x400040e4 / 0x40004c74 / 0x4000bb44
```

So: **WRITE-PARTITION invokes the `sec_get_seccfg` chain during the
policy-flag parse (pre-upload)** — that already performs a flash read of
~0x3000 bytes + SHA-256 + (if 0x40056E30 != 0) a HACC decrypt with the
unbounded polls. The WRITE-PARTITION deny byte-check at 0x400021a0
sits right after that parse. This pre-upload HACC pass can also hang,
but the observed "hang after 100% upload" points at the second,
post-upload pass described next.

No literal-pool or `movw` references to `0x40034d6c`/`0x40034dfc` exist
in the image (verified byte-search), so there is no second, hidden entry
point.

## 3. WRITE-PARTITION (0x40002034) epilogue — what runs after the commit

Order of the tail of the handler (full `pdf` at 0x40002034):

```
data phase (inside fcn.4000bb14, called via 0x4002ad04 -> 0x4000c348):
  0x4000bc50..0x4000c150  chunk loop: 0x4000aef4 (recv+program), USB via blx r2
  -- AFTER THE LAST CHUNK (i.e. host has uploaded 100%) --
  0x4000c1e8  bl 0x40033b64(buf, &out2, &out3, 1)   ; ACC config lookup:
                if [0x40067BA9]==0 -> acc flag = 0 (plain write)
                else flag = [0x40067BA9], acc_offset=[0x40067BA0+0xc]+[0x40067770+0x28],
                     acc_len=[0x40067BA0+0x10]; prints "[ACC] acc_en/acc_offset/acc_len"
  0x4000c204  ldrb r4,[acc_flag]
  0x4000c20c  cmp r4,#0 ; beq 0x4000c258            ; no ACC -> plain write
  0x4000c228  bl  0x40034810                         ; load HACC keys -> 0x1000A060
  0x4000c240  bl  0x40034840(buf+acc_off, len, 1)    ; HACC transform  <-- HANG POINT
  0x4000c244  bl  0x4003482c                         ; wipe key regs
handler epilogue:
  0x400023fc  bl 0x4002d970                          ; range table fixup
  0x4000241c  bl 0x4002d2cc                          ; storage op
  0x40002440/0x400024ac  bl 0x4002b874               ; flush/program (+ "OK" retries)
  0x400024f0  bl 0x4002ad04                          ; write wrapper (-> 0x4000c348)
  0x40002504  bl 0x4002c664(name)                    ; name in {PGPT,SGPT,PMT}?
  0x40002514  bl 0x4001231c                          ; GPT repair (only PGPT/SGPT/PMT)
  0x40002528/0x40002590  bl 0x4000ea94               ; send response
```

Call-chain diagram:

```
host "100% uploaded"
  └─ WRITE-PARTITION 0x40002034
       └─ 0x4002ad04 ─ 0x4000c348 ─ fcn.4000bb14   (8MB chunk loop)
            └─ last chunk done:
                 0x40033b64  ACC config (acc_en @ 0x40067BA9)
                 └─ enabled:
                      0x40034810 ─ 0x400398b0  (key words -> 0x1000A060)
                      0x40034840 ─ 0x4003975c  HACC init
                      │             └─ poll 0x400397d8 (reg==0xFFFFFFFF)  [UNBOUNDED]
                      │            0x40039800  HACC transform
                      │             └─ poll 0x40039840 (bit 0x8000)       [UNBOUNDED]
                      │            0x40039880  reset
                      │            0x40034a78  ─ poll 0x40034b10 (bit 0x8000) [UNBOUNDED]
                      0x4003482c ─ 0x400398d4  (wipe 0x1000A060)
       └─ 0x4002c664 name check (PGPT/SGPT/PMT only) -> response 0x4000ea94
```

seccfg carries the ACC/anti-clone flag (its classifier prints
"SECCFG Anti-Clone Enabled"), so an 8MB seccfg WRITE-PARTITION takes the
HACC branch; ordinary partitions do not — consistent with only seccfg
writes hanging. The intermittent nature (one restore completed with
state=2, later identical ones hung) is consistent with a HACC
transaction that sometimes completes and sometimes wedges; the exact
hardware trigger is **not resolvable statically** (honest ambiguity).

Note: the pre-upload policy parse (0x4000217c → 0x4002cf68 →
0x4002ce08 → sec_get_seccfg) runs the *same* HACC wrapper via
fcn.40035030 gated by 0x40056E30 — it is a second, earlier occurrence
of the same polling loops and can hang the same way.

## 4. "SECCFG Anti-Clone Enabled" string + xrefs

- The string is at **file offset 0x510EB / VA 0x400510EB**:
  `[%s] SECCFG Anti-Clone Enabled\n` (the session notes' `0x510cb` is
  actually the neighboring string `[%s] storage read fail, ret=%x\n`).
- Exactly **one code xref**: `0x40035060` (movw r0,#0x10eb; movt r0,#0x4005)
  inside the classifier fcn.40035030, printed only when the global byte
  `0x40056E30` is non-zero, immediately before the HACC decrypt of the
  seccfg hash block. Neighboring strings confirm the context:
  `SEC_CFG`, `SEC_HACC`, `HACC_SK`, `SW ENC`, `HW ENC`,
  `[%s] sec_get_seccfg ret=%...`.

## Summary

- The hang is the **HACC hardware busy-wait** (no timeout, bit 0x8000 /
  reg==0xFFFFFFFF at 0x1000A008) reached from the **post-upload ACC
  anti-clone pass** at 0x4000c1e8–0x4000c244 inside the WRITE-PARTITION
  write engine fcn.4000bb14 (and, pre-upload, from every
  sec_get_seccfg-driven policy parse).
- Neutralization via `patch_mem`: NOP the three poll branches
  (0x40039848, 0x400397e0, 0x40034b18) and/or force the ACC flag off
  (`b 0x4000c258` at 0x4000c210, or 0 → byte 0x40067BA9).
- Ambiguities stated honestly: (a) which of the three polls wedges
  first cannot be proven statically; (b) the writer of the read-path
  gate 0x40056E30 was not located; (c) why HACC wedges intermittently
  (clock/reset vs. secure-world contention) needs a device-side probe
  (e.g. READ-REGISTER on 0x1000A008 after a hang — if the readout
  itself responds, that also proves the CPU is spinning in this loop,
  since a dead agent could not answer).
