# RE: seccfg digest equivalence — mtkclient SecCfgV4 V4-mode vs DA2/LK HACC scramble

Date: 2026-10-23. Scope: `mtkclient/Library/Hardware/seccfg.py` (`SecCfgV4.create()`
zero-recovery path), `hwcrypto_sej.py` (SEJ/HACC register model), and the DA2 blob
`docs/notes/rmx3630-da2/da2_oplus.bin` (base 0x40000000, `-a arm -b 32`). Companion
notes: `re-lk-seccfg.md`, `re-reserve2-master.md`, `re-sec-dispatch.md`,
`re-consistency-audit.md` (Task2 item 5 / Task3(c)-4).

## TL;DR (answers)

1. **The suspected "SEJ-V4-legacy ≠ HACC" mismatch is NOT present at the register
   level — proven equal.** mtkclient's `sej_sec_cfg_hw_V3(..., legacy=True)` drives
   the *same physical engine* (0x1000A008 registers, reached through the DA's
   READ-REGISTER/WRITE-REGISTER commands) with a register program that is
   **instruction-for-instruction equivalent** to the DA2 scramble
   (`0x4003975c` init + `0x40039800` block loop): ACON=3 (ENC|CBC|AES128),
   ACONK=0x10 (BK2C), AKEY0..7=0, ACFG0..3 = seeds
   `0x9ED40400,0x00E884A1,0xE3F083BD,0x2F4E6D8A` (mtkclient `g_HACC_CFG_1[0..3]`,
   byte-identical to the DA2 table at 0x4005348C), same legacy 0x1000ABC dance,
   same per-16-byte ASRC→START→poll-RDY→AOUT loop. The one transcription slip to
   correct: `re-lk-seccfg.md` says seed `0x9ED44000`; the actual literal (both in
   DA2 and in mtkclient) is **0x9ED40400**.
2. **What is hashed and what is stored (proven):** the DA2 loader
   (0x40034dfc) computes `digest = 0x4003a2d4(record[0:0x1C], 0x1C)` (digest of the
   0x1C-byte header; standard SHA-256 semantics — LK does the same in software,
   proven in re-lk-seccfg §3.1), scrambles it in place with `0x40035030(buf, 0x20)`
   (HACC transform, gated by the anti-clone flag byte at 0x40056E30, static value
   0x01 in the blob), and compares with the 0x20 bytes stored at record+0x1C.
   **Stored digest = HACC_scramble(SHA256(record[0:0x1C]))** in the
   anti-clone-on configuration.
3. **Record shape: correct, no mismatch.** `create()` emits
   `pack("<7I", MMMM, ver, 0x3C, lock_state, dm_verity, sboot, 0x45454545)` (0x1C)
   + 0x20-byte enc_hash = 0x3C, main record at partition +0x00, zeros at +0x3C
   (backup), then zero padding to full partition size (v6.py pads to
   `rp.sectors * sectorsize`). Matches the device layout exactly; both validators
   accept a zero backup (DA2: backup magic ≠ MMMM → skipped; LK: main valid →
   clears bak, re-lk-seccfg §3.2 step 6).
4. **Verdict: NOT "cryptographically wrong by construction".** The digest the
   zero-recovery payload carries is computed by the device's own HACC engine with
   the same configuration the validator uses — so *if the register sequence
   actually executed against the real engine*, the record validates. This resolves
   the audit's "[CODE-RISK] Hash primitive ... unverified equivalence" as
   **equivalent at register level**. What remains genuinely open (and is the
   plausible cause of the observed "regenerated with state=2"):
   - **(a) silent-error risk:** mtkclient's poll loops do NOT abort on timeout —
     `SEJ_V3_Init`/`HACC_V3_Run` only log "SEJ Hardware seems not to be configured
     correctly" and **continue**, so a failed/unreachable engine (or a garbage
     READ-REGISTER answer) silently produces a garbage enc_hash that is written to
     flash as if valid. `create()` has no round-trip self-check.
   - **(b) anti-clone flag path:** if the runtime value of 0x40056E30 is 0, the
     reader does NOT use the 0x4003975c/0x40039800 scramble; it either skips the
     transform entirely (plain-SHA256 comparison) or uses the alternate
     struct-keyed transform 0x40034a78 (key material loaded from the RAM struct at
     0x4006E948 — untraced). A digest produced for the flag=1 path then fails.
   - **(c) readback classification:** per re-sec-dispatch §4.2 the DA2 "state"
     global is slot identity; a readback that reports the backup slot (state=2)
     means *the freshly written main record failed validation* — consistent with
     (a) or (b), not with a fixable "wrong algorithm".
5. **The digest is NOT computable offline.** The engine key path involves the
   efuse/HUK side (AKEY=0 + BK2C + legacy init); no host-only reconstruction can
   produce the device digest. Any fix must compute the digest **on the device**
   (as mtkclient already does via registers) — or reuse a captured stock record's
   digest trick (see §5 fix 2, which does not even need the engine).

## 1. DA2 digest chain — disassembly evidence (proven unless marked)

### 1.1 Loader/validator 0x40034dfc (main slot, r6 = 0x40067640, sb = +0x20 hash)

```asm
0x40034f40  ldr r0,[r6]          ; slot->magic
0x40034f4c  cmp r0, r7           ; r7 = 0x4D4D4D4D "MMMM"
0x40034f54  add r5, sp, 0x10     ; scratch
0x40034f64  bl 0x4000b330        ; memset(scratch, 0, 0x20)
0x40034f68  mov r0, r6 ; mov r1, #0x1c ; mov r2, r5
0x40034f74  bl  0x4003a2d4       ; digest(record[0:0x1C]) -> scratch (0x20)
0x40034f7c  bl  0x40035030       ; scramble(scratch, 0x20)  -- in place
0x40034f80  mov r0, sb ; mov r1, r5 ; mov r2, #0x20
0x40034f8c  bl  0x4000b0d8       ; memcmp(record+0x20 [i.e. +0x1C of the record
                                 ;   body slot layout], scratch, 0x20)
0x40034f94  beq 0x40034ffc       ; equal -> MAIN VALID (state writer = 1)
```
Backup slot (0x40067600 / hash at 0x40067620) gets the identical treatment at
0x40034fa4–0x40034fe8 (`beq 0x40035010` → state writer = 2).
Hashed range: **exactly the first 0x1C bytes of the record** — magic, ver, size,
lock_state(+0xC), dm_verity(+0x10), sboot(+0x14), EEEE(+0x18).

### 1.2 Digest primitive 0x4003a2d4

`0x4003a2d4 → 0x4003a510 → 0x4003a334 (init) + 0x4003a3a4 (update) → 0x4003a4b8`.
The init writes `0x18000000` to **0x1000108C** and uses the **0x1021xxxx**
mailbox region — the HACC2/CFIFO engine (same engine family as the RPMB key
derivation, re-da2-rpmb-key). So the digest is computed by hardware, not a
software SHA-256. *Inference (medium):* the algorithm is standard SHA-256 — LK
uses plain software SHA-256 (IV constants 6A09E667… at 0x5007B1EC, re-lk-seccfg
§2) over the same 0x1C bytes for the same partition, and the two validators must
agree on factory records; a nonstandard digest in the DA would break every
LK-written record.

### 1.3 Scramble classifier 0x40035030

```asm
0x4003503c  movw r0,0x6e30 / movt 0x4005 ; ldrb r4,[0x40056E30]  ; anti-clone flag
0x40035048  cmp r4,0 ; movwne r4,#1
0x40035050  beq 0x40035090       ; flag==0 -> alt path (see 1.5)
0x40035074  bl  0x400347d8       ; HACC key-copy check (MMMM key source 0x400679D8)
0x40035078  mov r0,r5 ; mov r1,#0x20 ; mov r2,r4
0x40035084  bl  0x40034840       ; HACC transform(buf, 0x20, flag)
```
Static value of 0x40056E30 in the blob: **0x01** (anti-clone on by default).
The runtime writer of this byte is still unlocated (audit open question 5).

### 1.4 HACC transform 0x40034840 → init 0x4003975c → block loop 0x40039800

`0x40034840(buf, 0x20, flag≠0)`: `0x4003975c(1)` init → `0x40039800(buf,0x20,buf)`
in place → `0x40039880` key wipe.

Init (r1 = base **0x1000A008**; offsets below are from that base; the
mtkclient-equivalent absolute addresses are in brackets, using sej_base 0x1000A000):

```asm
0x40039764  movw r1,0xa008 / movt 0x1000          ; base = 0x1000A008
0x40039774  loop: str 0,[base + i*4 + 0x18], i=0..7  ; zero 8 words @+0x18..+0x34
                                                   ;   [0x1000A020..0x1000A03C] = AKEY0..7 = 0
0x40039788  movw lr,0x348c / movt 0x4005          ; seed table @0x4005348C
0x40039798  movweq ip,#2 ; mov ip,#3              ; arg!=0 -> ip=3 (ENCRYPT)
0x400397a8  loop: ldr r3,[table + i*4] ; str r3,[base + i*4 + 0x38], i=0..3
                                                   ;   seeds -> +0x38..+0x44
                                                   ;   [0x1000A040..0x1000A04C] = ACFG0..3
0x400397c0  ldr/str: [base+0xB4] |= 2             ; [0x1000ABC] = HACC_SECINIT0_new |= 2
0x400397cc  [base] |= 0x40000000                  ; [0x1000A008] = ACON2 |= 0x40000000
0x400397d8  poll [base] until >= 0 (bit31 clear)  ; unbounded
0x400397e4  [base+0xB4] &= ~1                     ; [0x1000ABC] &= 0xFFFFFFFE
0x400397f0  [base+4] = 0x10                       ; [0x1000A00C] = ACONK = BK2C
0x400397f8  [base-4] = ip                         ; [0x1000A004] = ACON = 3 (ENC|CBC|AES128)
```
Seed table @0x4005348C (read from the blob): `9ed40400 00e884a1 e3f083bd 2f4e6d8a`.

Block loop (0x40039800, per 16 bytes):
```asm
0x40039824  ASRC0..3 [0x1000A010..0x1C] <- 4 words of input (LE)
0x4003983c  [base] = 1                            ; ACON2 = START
0x40039840  poll [base] bit 0x8000 (RDY)
0x40039850  AOUT0..3 [0x1000A050..0x5C] -> 4 words of output
```

### 1.5 The flag==0 branch (0x40034840 else path) — partly untraced

```asm
0x400348bc  mov r0,0 ; mov r1,0x20 ; bl 0x40034948
0x400348c8  cmp r0,0 ; beq 0x400348d4
            ; !=0 -> return without any transform (stored digest == plain digest)
0x400348d4  -> 0x40034a78 : alternate HACC op; key material loaded from struct
               [0x4006E948+0x20..] into [0x1000A044..] (seed/ACFG slots), plus a
               block loop polling [0x1000A008] bit 0x8000 (0x40034b10)
```
So with anti-clone OFF, the expected stored digest is either the **plain digest**
or the **struct-keyed transform** of it — *which of the two is determined by the
(untraced) return value of 0x40034948*. Not resolved here.

### 1.6 What the seeds are (key? IV? round constants?)

With the corrected base mapping the four seed words land in **ACFG0..3 = the CBC
IV registers** (0x1000A040..0x1000A04C), and **AKEY0..7 are zeroed**. So in the
mtkclient register model the seeds are the CBC IV and the AES-128 key is the
hardware-key path (AKEY=0 + BK2C + legacy init ⇒ efuse/HUK involvement). They are
**neither a plain AES key nor round constants** in any host-reproducible sense.

## 2. mtkclient side — what create() actually computes (proven, code-level)

Zero-recovery path: `v6.py seccfg()` (L1150–1204) → `SecCfgV4(hwc, mtk,
custom_sej_hw)`, `hwtype = "V4"` forced → `create()` L178–179:

```python
dec_hash = hashlib.sha256(seccfg_data).digest()          # standard SW SHA-256, 0x1C hdr
enc_hash = self.hwc.sej.sej_sec_cfg_hw_V3(dec_hash, encrypt=True, legacy=True)
```

`sej_sec_cfg_hw_V3` = `hw_aes128_cbc_encrypt(buf, encrypt=True, legacy=True,
iv=g_HACC_CFG_1)` → `SEJ_V3_Init(ben=True, iv=g_HACC_CFG_1, legacy=True)` +
`HACC_V3_Run(buf)` + `sej_terminate()`, all through `HaccReg` with
`setup.read32/writereg32 = v6.readmem/writeregister` (v6.py L1079–1080) — i.e.
**real device register access** via the DA's READ-REGISTER/WRITE-REGISTER
(0x40006eec / 0x4000700c, present and session-proven on this DA2). `sej_base` for
hwcode 0x1208 (MT6789) is 0x1000A000 (brom_config.py L1957) — same engine the DA
uses.

Register-program comparison (mtkclient legacy=True vs DA2 init):

| item | DA2 (0x4003975c/800) | mtkclient SEJ_V3_Init(legacy=True)+HACC_V3_Run | equal? |
|---|---|---|---|
| AKEY0..7 | zeroed (+0x18..+0x34) | zeroed (L815–822) | ✔ |
| ACFG0..3 | seeds 9ED40400,00E884A1,E3F083BD,2F4E6D8A | `g_HACC_CFG_1[0..3]` — same words (L169–170, L835–838) | ✔ |
| ACON | 3 (ENC\|CBC\|AES128) | `CHG_BO_OFF\|AES_128\|CBC\|ENC` = 3 (L806–812, L853) | ✔ |
| ACONK | 0x10 (BK2C) | BK2C then legacy branch resets to BK2C (L829–830, L852) | ✔ |
| SECINIT reg 0x1000ABC | `\|=2`, ACON2`\|=0x40000000`, poll, `&=~1` | `HACC_SECINIT0_new(0xBC)` same dance (L841–851) | ✔ |
| key-derive pattern rounds | none | none in legacy branch (else-branch only) | ✔ |
| block loop | ASRC←data, ACON2=1, poll 0x8000, AOUT→out | HACC_V3_Run identical (L472–494) | ✔ |
| direction | ACON=3 = encrypt | encrypt=True | ✔ |
| termination | 0x40039880 key wipe | sej_terminate (key wipe + ACON2 CLR) | ✔ (post-op, no effect on output) |

Minor (non-material) deltas: mtkclient polls bounded (20 iterations) and **logs
and continues on timeout** instead of aborting (see §4 risk (a)); mtkclient sets
ACFG *before* the legacy ACON2-clear, same as the DA (both leave ACFG written
after the 0x40000000 clear — order identical, and 0x40000000 is not the CLR bit).
`tz_pre_init()` is a no-op stub.

Note: `create()`'s HW/HWXOR/V2/V3 branches and `parse()`'s whole detection ladder
are irrelevant to the zero-recovery path (hwtype forced to "V4"); the
`custom_sej_hw` DA-side command is **not** used by the V4 branch despite the
v6.py comment claiming "hash comes from the DA's own SEJ via custom_sej_hw" —
the comment is stale; the mechanism is the register path instead (equally
device-genuine).

## 3. Python test (offline, no device)

Script (run output below; full script inline, pure-python + `cryptography`):

```python
# /tmp/opencode/seccfg_digest_test.py (abridged logic)
SEEDS = [0x9ED40400, 0x00E884A1, 0xE3F083BD, 0x2F4E6D8A]
hdr = pack("<7I", 0x4D4D4D4D, 4, 0x3C, 3, 0, 0, 0x45454545)
sha = hashlib.sha256(hdr).digest()
# M1: AES-128-CBC enc, key=16 zero bytes, IV=seeds(LE)  <- best host model of
#     the DA/LK register program (key path HUK-blended on device: unknowable)
# M3/M4: alternative interpretations rejected by the disasm (seeds are ACFG=IV)
```

Output:
```
header (0x1C) : 4d4d4d4d040000003c00000003000000000000000000000045454545
sha256(hdr)   : 47f70ff4018e93cf825cd099f474b7913352f8630c6247ee7ca7a61670454929
--- host MODELS (not device truth) ---
M1 AES-128-CBC enc key=0 IV=seeds: 353ed95b1acb6566e3a40927dd521faff8404c5964f4b23fadbf8ca4a64a59a9
M2 AES-128-CBC dec key=0 IV=seeds: ba9c0bae9ee287495c8c7ff1c0f4a2e11428f2bb17e12f00855ea94f178deb15
M3 AES-128-ECB enc key=seeds     : 1790d4c0c28477dcd286e1e42cc193bd3e7f8b0f4b1268c81e46b792ce267c7b
M4 AES-256-ECB key=0x00*16+seeds : 0d7da536648f6f4885ea3b7fc5653e1832e12bee25d84319154b63edadbe6d1a
M5 plain sha256 (no scramble)    : 47f70ff4018e93cf825cd099f474b7913352f8630c6247ee7ca7a61670454929
--- shape ---
record len: 0x3c magic@0 b'MMMM' EEEE@0x18 b'EEEE' digest@0x1C len 0x20
```

**Interpretation:** none of M1–M4 can be asserted as the device digest — the
engine's AES-128 key is the HUK-blended hardware key (AKEY written as 0 + BK2C +
legacy init), so the host model is only an approximation. The equivalence proof
is structural (same engine, same register program, same input), not a
byte-equality of host models. To *prove* byte-equality on real data, use a
captured stock seccfg image and the discriminators D1/D2/D3 in the script: if
`stored == sha256(hdr)` the device runs anti-clone OFF (no scramble) and
mtkclient's scrambled digest will never validate (→ state=2); if `stored ==
transform(sha256(hdr))` the register model is confirmed end-to-end.

## 4. Verdict

**Is the zero-recovery payload cryptographically acceptable to the DA2 reader
(0x40034dfc) / LK (0x500827E8)? — Conditionally yes; not "structurally right,
cryptographically wrong".**

* The digest algorithm/config mtkclient uses (SW SHA-256 over the 0x1C header +
  legacy SEJ/HACC scramble via the device engine with the fixed seeds) is the
  same primitive pair and the same engine configuration as both validators.
* The digest is device-bound (HUK in the key path) — it cannot be forged or
  recomputed offline, only computed on-device, which the register path does.
* The observed "regeneration to state=2" is therefore **not explained by an
  algorithm mismatch**. Remaining candidate explanations (ranked):
  1. **[most likely] Silent SEJ failure** — poll-timeout/garbage register reads
     inside `SEJ_V3_Init`/`HACC_V3_Run` are logged but not fatal; a garbage
     enc_hash gets written and the main record then fails the DA's digest check
     on readback → backup-slot classification (state=2). Fits the session's
     observation that readback showed a "valid new hash" the DA itself accepted
     into its own slots.
  2. **Anti-clone flag off at runtime** — if 0x40056E30 reads 0 at run time, the
     reader's expected digest is plain-SHA256 or the 0x40034a78 struct-keyed
     transform, not the 0x4003975c scramble mtkclient emulates.
  3. WRITE-REGISTER access to the SEJ register window (physical 0x1000A0xx)
     silently denied/ignored for the host-issued commands (session never
     explicitly verified a readback of an SEJ register it had written).

## 5. Proposed fixes (diffs here only — not applied)

**Fix 1 (P0): round-trip self-check in `SecCfgV4.create()`** — after computing
`enc_hash`, immediately verify it with the inverse operation and abort on
mismatch instead of writing a possibly-garbage digest:

```python
# mtkclient/Library/Hardware/seccfg.py, SecCfgV4.create(), V4 branch (L178-179)
        elif self.hwtype == "V4":
            enc_hash = self.hwc.sej.sej_sec_cfg_hw_V3(dec_hash, encrypt=True, legacy=True)
+           # round-trip: decrypt direction must reproduce the plain SHA-256;
+           # abort instead of writing a record that can never validate
+           dec_check = self.hwc.sej.sej_sec_cfg_hw_V3(enc_hash, encrypt=False, legacy=True)
+           if dec_check != dec_hash:
+               self.error("SEJ digest round-trip FAILED - not writing seccfg "
+                          "(engine unreachable or misconfigured)")
+               return False, "SEJ digest round-trip failed; seccfg not modified"
```
(Direction symmetry ACON=3 enc / ACON=2 dec is exactly what the DA's own
`ip=3/ip=2` argument encodes, 0x40039798; if the transform is not involutive
under CBC the check still fails loudly instead of silently.)

**Fix 2 (P0, zero-cost discriminator): stock-record digest test in `parse()`** —
detect the anti-clone-off case before writing anything:

```python
# SecCfgV4.parse(), after computing _hash (L65):
        if self.hash == _hash:                      # stored == plain sha256(hdr)
            self.info("seccfg digest is PLAIN SHA-256 (anti-clone disabled) - "
                      "V4 hash must be written unscrambled")
            self.hwtype = "PLAIN"
```
plus a `"PLAIN"` branch in `create()` that stores `_hash` directly. Run this
once against the existing `seccfg_backup.bin`: it decides between hypotheses 1
and 2 in §4 without any device risk.

**Fix 3 (P1): make SEJ poll failures fatal** — in `hwcrypto_sej.py`
`SEJ_V3_Init` (L844–850, L866–872) and `HACC_V3_Run` (L478–483), raise/return an
error on poll timeout instead of `self.error(...)` + continue, so a dead engine
can never yield a silently-wrong `enc_hash`.

**Fix 4 (P2): stale comment** — v6.py L1156–1157 ("its hash comes from the DA's
own SEJ via custom_sej_hw") is wrong for the V4 branch; the mechanism is the
register-level SEJ path (`sej_sec_cfg_hw_V3(..., legacy=True)` through
READ/WRITE-REGISTER). Reword to avoid the next auditor chasing `custom_sej_hw`.

**Fix 5 (P2): documentation** — correct `0x9ED44000` → `0x9ED40400` in
`re-lk-seccfg.md` §3.1 (the DA2 table and mtkclient agree on 0x9ED40400).

## 6. Confidence

* **Proven (disasm):** hashed range = record[0:0x1C]; stored digest at +0x1C =
  scrambled digest; scramble = HACC 0x20-byte in-place transform gated by
  0x40056E30; seed table values (0x9ED40400 first word); full DA2 init/block-loop
  register program; base mapping onto mtkclient's `regval` (AKEY/ACFG/AOUT
  slots); record shape equality with `create()`.
* **Proven (code):** what `create()` computes in the V4 branch; the register
  sequence it issues; wiring of read32/write32 to DA register commands;
  `sej_base=0x1000A000` for hwcode 0x1208.
* **Inference (medium):** digest algorithm is standard SHA-256 (LK does software
  SHA-256 over the same range; both validators must agree); the "state=2"
  observation is main-record validation failure (per re-sec-dispatch slot model).
* **Unknown:** runtime value of the anti-clone byte 0x40056E30; the return-value
  semantics of 0x40034948 (flag==0 branch: plain vs 0x40034a78 struct-keyed
  transform); whether WRITE-REGISTER can actually reach the SEJ window on this
  DA2; the exact HUK blending (makes offline digest computation impossible — by
  design).
