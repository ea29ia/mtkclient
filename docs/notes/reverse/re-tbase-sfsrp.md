# RE: t-base MTEE SFSRP — RPMB region layout, anti-rollback semantics, blast radius for the LK mirror write

Date: 2026-10-23. Target: `docs/notes/rmx3630-lk/tee.img` (768816 B, MT6789,
fw 14.0.0.200EX01), `tee` segment = Trustonic t-base-MTK-A64O-Android-510a-V009-20220818.
Method: container-header parse + `strings` + r2 static disasm (AArch64).
Companions: `re-tee-efuse.md` (Q1 baseline), `re-lk-rpmb-lock.md` (mirror format),
`re-da2-rpmb-key.md` (DA2 key path).

## TL;DR — verdicts

1. **Load base of the `tee` payload is PROVEN: 0x05F00000.** The payload contains
   an MTEE image header ("TEE "/"MTK " magic, 0x240 B) whose last word
   (payload 0x43C) is **0x05F00000**; the image body (0x891C0 B) starts at
   payload 0x440 and maps linearly to VA 0x05F00000. The container-header qword
   0x05F00240 = base + 0x240 (VA of the MTEE header). All adrp/add xrefs resolve
   cleanly with this base (prior report's failure was an analysis artifact).
2. **SFSRP region layout (proven formulas):** t-base's RPMB window is addressed
   from a single runtime base block **S** (u32 @ RAM 0x05F8471C):
   * block **S** = 256-byte superblock, magic **0x424D5052_3030344B** = ASCII **`K400RPMB`** (note: *not* "4400RPMB"), version 2,
     flags=0, size=0x100, **per-partition u64 anti-rollback counters at +0x40, +0x48, …**
   * blocks **S+1 … S+16** = the SFSL1 data window: 4 cache lines × 1 KB, line *i*
     read/written as **4 consecutive 256-B blocks at S + 4·i + 1**.
   Total window = **17 RPMB sectors (256 B each) starting at S**.
3. **S is NOT in the image.** It is the `+4` field of the value blob of the
   platform property **`com.trustonic.trustedStorage.antiRollback.rpmbCfg`**,
   fetched at driver-init via the t-base property service (svc 0x2c) into RAM
   0x05F84718 (blob ≤ 0xC B: +0 u32 partition-enable bitmask, +2 u16 power-of-2
   size code, +4 u32 start block). If the property is absent the BSS default is
   0 → S = 0. **S is unknown on this unit.** (The earlier "S ≥ 4" argument was
   based on the LK mirror living at sectors 0–3; that is now disproven — the
   mirror is at blocks **0x1DC–0x1DF**, so no collision argument exists.)
4. **Empty vs garbage behavior (proven branch map):** superblock all-zero →
   `[SFSRP]Formating data` → silent in-RAM format (magic, version=2, size=0x100,
   counters = 0) → self-heals, **loses all previous t-base SFS state**.
   Garbage that keeps the magic but fails version/flags/size checks →
   `[SFSRP] ERROR Invalid version/flags/size` → fatal module error
   (0x0F01000x through the t-base error/panic path 0x5F78200) → trustedStorage
   down for that boot ([STH2] mount failures).
5. **Key question (Q4):** there is **no software SHA-256/HMAC and no HACC key
   derivation inside the tee segment** (no SHA-256 IV/K-table anywhere; the only
   crypto is the ARMv8 SHA-extension CryptoDriver at ~0x5F49C00–0x5F4A100; no
   "SASI"/"RPMB KEY" tags). RPMB frames are built by SFSRP and pushed through
   **TLAPI driver id 0x700** (svc 0xc); ATF is consulted via
   **drApiPlatformControl (svc 0x17, op 0xB0)** for the RPMB-enabled flag
   ("[SFSRP]ATF reports RPMB disabled : No Downgrade protection"). Whether the
   frame MAC is computed in the (external) driver module or by the EL3
   "mmap rpmb hmac" service is **not resolvable from this image (inference,
   medium: EL3 service)** — but it is **irrelevant for the mirror plan**: an
   eMMC/UFS device has exactly ONE programmed RPMB auth key, so every
   authenticated writer (LK/TEE path, DA2, t-base SFSRP) uses the **same device
   key** by construction. t-base's area and LK's mirror are keyed identically.
6. **Blast radius verdict for the mirror write at sectors 0–3:** if S ≥ 4
   (expected), rewriting sectors 0–3 cannot touch the t-base superblock or its
   L1 window — **no t-base impact**. If S ≤ 3 (would mean the platform ships a
   colliding config — no evidence), any mirror write would corrupt the
   "4400RPMB" superblock; a zeroed sector 0–3 window would make t-base silently
   reformat (trustedStorage content reset — TEE-side secure files lost), and
   magic-preserving garbage would fatal-error SFSRP. **Mandatory pre-check
   below (§5) resolves S empirically via DA2 before any write.**

---

## 1. tee segment layout (proven)

```
tee.img
  0x00000  seg `atf`  0x30588   (EL3/ATF, base 0x48200000 — see re-tee-efuse.md)
  0x30790  seg `cert1` 0x6c5
  0x31060  seg `cert2` 0x3f3
  0x31660  seg `tee`   0x89400
     +0x000  seg header (magic 0x58881688, size 0x89400, name "tee",
             qword +0x20 = 0x05F00240)
     +0x030  inner header (0x58881689, 0x200, 1, 0, 0x1000)
     +0x060  0xFFFFFFFF filler to +0x200
     +0x200  MTEE image header, 0x240 B:
             "TEE " "MTK " | 0x240 | 0x30010001 | 1 | 0x891C0 | 0x891C0 |
             zeros | 0xD0-byte signature blob (0x330–0x43B) | u32 0x05F00000
     +0x440  image body (0x891C0 B) → VA 0x05F00000, linear
  0xbac60  seg `cert1` (repeat)
  0xbb530  seg `cert2` (repeat)
```

Image memory map (VA = image offset + 0x05F00000; **image offset = payload-file
offset − 0x440**):

| range (VA) | content |
|---|---|
| 0x5F00000–0x5F71000 | MTEE kernel + services (vectors @0x5F00000; SMC conduit sites 0x5F0025D4, 0x5F002ECC, 0x5F00B1FC/0xB27C/0xB2F8/0xB34C, generic 4-arg SMC 0x5F00D008; SMC IDs seen: 0xB2000002, 0xB2000004, small ids 1/4/6) |
| 0x5F49C00–0x5F4A100 | CryptoDriver SHA-256 (ARMv8 crypto extensions: sha256h/sha256h2/sha256su0/su1) + bignum code |
| 0x5F71A30–0x5F81500 | **SFSRP driver layer** (functions below) |
| 0x5F81548–0x5F82250 | rodata string pool (incl. the [SFSRP]/[STH2]/[SFSL1] cluster) |
| 0x5F82250–0x5F84000 | .data.rel.ro pointer tables (RVA entries, relocated at load) |
| 0x5F84000–… | .bss (SFSRP globals below) — file bytes there are the next module, not loaded here |
| appended at image off 0x84000 (payload 0x84440) | **MCLF module** ("MCLF" magic, memBase 0x00500000) = **[CR0] Crypto Driver** trustlet/driver (own strings "[CR0] Crypto Driver, Build Aug 18 2022", "gpd.ta.*" TA manifest keys) — NOT the RPMB driver |

Key BSS globals:

| VA | role |
|---|---|
| 0x5F84410 | cached drApiPlatformControl(0xB0) result (0xA5A5A5A5 = refetch marker; 0xDEAD_BEEF = SMC failed) |
| 0x5F84710 | u32 log2(size code) result of rpmbCfg validation |
| 0x5F84718 | **antiRollback.rpmbCfg value blob (≤12 B)**: +0 u32 partition-enable bitmask, +2 u16 power-of-2 size code, **+4 u32 = SFSRP start block S** |
| 0x5F84714 | u8 "superblock dirty" flag |
| 0x5F84730 | **superblock cache** (256 B mirror of RPMB block S) |
| 0x5F84618 | RPMB driver config (u16 cfg value @+0, type code @+2, per-slot array @+0x2C init −1) |
| 0x5F84830 | SFSL1 line buffers (4 × 0x400) |
| 0x5F85830 | SFSL1 per-line dirty/sector fields (4 × u32; 22-bit block index) |

## 2. SFSRP function map (VA + anchor)

| VA | role | anchor |
|---|---|---|
| 0x5F71A30 / 0x5F781F0 | SFSRP init: stores RPMB size (KB) into dev desc +0x74, log2 into +0x76, zeroes L1 context @0x5F84580, allocates L1 cache (entries × 0x48 B, count = min(max, 8/7/0xC)), then calls 0x5F73AC0 | `bl 0x5f73ac0` @0x5F71B4C |
| 0x5F73AC0 (+tail 0x5F76C70) | driver config setter + **antiRollback.rpmbCfg property fetch** (svc 0x2c wrapper 0x5F80BB8, args −3, name@0x5F81968, buf 0x5F84718, len 0xC); validates u32@+0 ≠ 0 and popcount(u16@+2)==1 → returns log2 (clz/rbit) | string xref "com.trustonic.trustedStorage.antiRollback.rpmbCfg" |
| 0x5F76D50 | `antiRollbackEnabled(partition_id)`: tests flags bit (1<<id) vs u16@0x5F84718; lazily fetches drApiPlatformControl(0xB0) via svc 0x17, caches @0x5F84410; 0 → "[SFSRP]ATF reports RPMB disabled : No Downgrade protection" (0x5F819A0); SMC fail → "drApiPlatformControl failed(%d)…" (0x5F819E0) | svc 0x17 / w0=0xB0 @0x5F76DA8 |
| 0x5F76070 | **superblock load/validate/format.** reads 1 block at S=[0x5F8471C] (via 0x5F80BE8) into 0x5F84730; checks magic == "4400RPMB" (const 0x424D5052_30303434), version ∈ {1,2} (1 → "[SFSRP]Version 1 -> 2", bumps to 2, zeroes +0x48), flags@+0xC == 0, u64 size@+0x10 == 0x100; magic mismatch → "[SFSRP]Formating data" (0x5F817D0) + in-RAM format; violations → prints + fatal 0x5F78200(0x0F01000x); sets dirty flag 0x5F84714 | magic compare @0x5F760C0–D4 |
| 0x5F76E10 | **anti-rollback counter bump + check + superblock write.** If partition bit set: state=0x5F76070(0); stored = state[0x40 + 8·id]; new = stored+1 → state[...]; **if new != [ctx+0xA18] → "[SFSRP] ERROR Mismatch between the counters" (0x5F81A30) → fatal 0x5F78200(0x0F010001)**; else write 1 block at S (data = superblock cache); write fail → "[SFSRP] ERROR Write error (0x%08X)" (0x5F81940) → fatal | `bl 0x5f80cb0` @0x5F76EA0; mismatch print @0x5F76F48 |
| 0x5F80BE8 | RPMB **read** (frame type 2): builds 0x414-B request {+0 u32 block addr, +4 u32 0, +2 u16 type=2, +0xC u32 nblocks (≤4), +0x14 data}, sends via svc 0xc to driver 0x700 (0x5F80868), memcpy out nblocks·0x100 | `strh 2` @0x5F80C3C |
| 0x5F80CB0 | RPMB **write** (frame type 1, same layout, nblocks ≤ 4 else err 0x10B): retry loop ×10 with 1000 ms (0x3E8) waits; per-attempt failure → "Error: failure on block blk_num %d, err = 0x%08X" (0x5F821B0→VA 0x5F81D70); 10 exhausted → "Error: failed to write to RPMB after %d attempts" (VA 0x5F81DA8) | `strh 1` @0x5F80D04; retry loop 0x5F80D44–0x5F80DAC |
| 0x5F76210 | **SFSL1 flush**: for i in 0..3, if dirty[i] ≠ −1: write **4 blocks at S + 4·i + 1** from buffer 0x5F84830 + i·0x400 (memset 0xA5 after); err 0x10B → "[SFSL1] cache" print + fatal; then clears dirty table | `ubfiz w1,w1,2,0x16; add w1,w1,1` @0x5F76250 |
| 0x5F762F0 | SFSL1 line (re)load: **read 4 blocks at S + 4·i + 1** into line buffer | `bl 0x5f80be8` w2=4 @0x5F76370 |
| 0x5F75710 | sector free/flush path (SFSL1/L2 glue): calls 0x5F76210, then writes the superblock (1 block @ S) if dirty 0x5F84714 | `bl 0x5f76210` @0x5F76908; sb write @0x5F76928 |
| 0x5F71C20 / 0x5F72EC0 | SFSRP sector open/close contexts (partition id @ctx+0x10, tracked hw write counter @ctx+0xA18); call 0x5F76E10 (counter check fires on open) | `bl 0x5f76e10` @0x5F71F48 / 0x5F73080 |
| 0x5F78200 | t-base error/panic sink: stores code in global (via [0x5F81E70] dev struct), then 0x5F70694(struct+0x80, 1) — module-level fatal | 76 xrefs |
| 0x5F80868 / 0x5F80BB8 | syscall wrappers: svc #0xC (driver IO, id in w0 = 0x700 for RPMB), svc #0x2C (getProperty) | `br x16` tails |

String cluster (VAs): [SFSRP] errors 0x5F816F0–0x5F81A68; "[SFSRP]Formating data"
0x5F817D0; "Version 1 -> 2" 0x5F817E8; "Invalid version/flags/size"
0x5F81800/0x5F81828/0x5F81850; "Write error" 0x5F81940; rpmbCfg 0x5F81968;
"ATF reports RPMB disabled" 0x5F819A0; "drApiPlatformControl failed" 0x5F819E0;
"Mismatch between the counters" 0x5F81A30; "blk_num" 0x5F81D70; "failed to
write to RPMB after %d attempts" 0x5F81DA8.

## 3. RPMB region layout — verdict

* **t-base SFSRP window = 17 × 256-B RPMB sectors [S .. S+16]**, where S is the
  u32 at +4 of the `antiRollback.rpmbCfg` property value (runtime platform
  config; BSS default 0 if the property is absent — inference on the default
  path, the read at [0x5F8471C] itself is proven).
  * S = superblock (`K400RPMB`, version, flags, size, counters).
  * S+1..S+16 = SFSL1 data (4 lines × 1 KB; line i = sectors S+4i+1 .. S+4i+4).
* **Coexistence with the LK boot-info mirror (blocks 0x1DC–0x1DF):** the two
  layouts collide only if S falls inside 0x1DC..0x1DF(+16). With the mirror no
  longer at 0–3, the old "S ≥ 4" inference is **withdrawn**; S must be measured
  (RAM 0x05F8471C in MTEE, or a dump of the RPMB area once a working UFS RPMB
  reader exists).
* There is no separate "SFS start sector" knob in code — the single property
  blob carries both the size code and the start block.

## 4. Anti-rollback semantics + failure behavior

* Mechanism: **per-partition u64 counters persisted inside the "4400RPMB"
  superblock** (slots at +0x40, +0x48, …; version 1→2 migration added a second
  slot), cross-checked against the driver-tracked hardware RPMB write counter
  (ctx+0xA18) before each superblock write. `antiRollback.rpmbCfg` +0 bitmask
  selects which SFS partition ids are counter-protected; the hardware
  enable/disable flag comes from EL3 via drApiPlatformControl(0xB0) (cached;
  0 → no downgrade protection, logged, not fatal; SMC error → "act as downgrade
  protection active", i.e. treated as enabled).
* **Empty/zero RPMB window** (never formatted): magic mismatch → in-RAM format
  ("Formating data", version=2, size=0x100, counters=0) → proceeds; previous
  SFS contents are gone (data sectors read as garbage → STH2 partition
  mount/format layer handles/reports corruption: "Partition %d is corrupted",
  "Failed to mount partition %d after %d attempts"). **Not a boot-loop by
  itself, but a full trustedStorage data reset.**
* **Garbage with intact magic**: Invalid version/flags/size → fatal 0x0F01000x
  → SFSRP/trustedStorage unavailable for that boot (depends on platform retry
  policy whether this surfaces as a boot problem).
* **Counter mismatch** ("Mismatch between the counters"): the persisted
  counter+1 no longer matches the driver's tracked hardware write counter —
  e.g. someone rewrote/rolled back RPMB content outside t-base — → fatal
  0x0F010001. **This is the tripwire relevant to any RPMB tampering: if the
  mirror write path ever wrote into the t-base window (or rolled the device
  write counter back, which the device forbids anyway), t-base SFSRP fatals.**

## 5. Concrete on-device pre-check procedure (before touching sectors 0–3)

1. **Dump RPMB sectors around the expected window with the AP quiesced**
   (caveat: the mtkclient `da rpmb` path resolves to the **eMMC/MSDC** stub and
   does not reach UFS RPMB — see `re-consistency-audit-2.md` §1; also, RPMB read
   *requests* carry no MAC but the *responses are MAC'd*, so "reads need no key"
   is wrong: without the key the reply cannot be authenticated).
   Look for the 8-byte magic **`K400RPMB`** (hex `4B 34 30 30 52 50 4D 42`) at
   any 256-B block boundary, and separately for the LK mirror at **0x1DC–0x1DF**.
   * Found at sector k → **S = k**. If k ≥ 4 (expected): sectors 0–3 are LK-only
     → mirror write is safe w.r.t. t-base. Record k and never write ≥ k.
   * Not found in 0–0x1F → widen the read (0x20–0x80). Still nothing → either
     SFSRP is configured with rpmbCfg absent (S=0 → **overlap — do NOT write**)
     or the window lies further out; also inspect sector 0–3 for non-mirror
     structure (per re-tee-efuse.md §1c checklist).
2. Cross-check: at the found S, verify +0x08 u32 ∈ {1,2}, +0x0C == 0, +0x10
   u64 == 0x100 — a match confirms the t-base superblock beyond doubt.
3. During any later mirror experiment, watch the boot log for
   `[SFSRP]`/`[STH2]`/`[SFSL1]` lines; any of
   "Mismatch between the counters" / "Invalid version|flags|size" /
   "Formating data" appearing after the write = overlap confirmed → restore
   the original sector bytes immediately (keep a DA2-side backup of sectors
   0–0x1F before the first write).
4. Note SFSRP writes race concurrent RPMB access; do all reads/writes from DA
   mode with the AP held out of the TEE.

## 6. Confidence

* **Proven (container/header/disasm):** load base 0x05F00000 + image map;
  SFSRP function map and branch logic as in §2; frame format (0x414 B, types
  1/2, ≤4 blocks/req, ≤0x400 data); L1 window formula S+4i+1 (4 lines);
  superblock format "4400RPMB"/version/flags/size/counters@+0x40; rpmbCfg
  property fetch into 0x5F84718 with popcount-of-+2 validation and S read from
  +4; drApiPlatformControl(0xB0) enable query; no SHA-256 tables/HACC tags in
  the tee segment; appended MCLF = CR0 Crypto Driver.
* **Inference:** S ≥ 4 on shipping units (operational-necessity argument);
  property blob field roles (+0 bitmask / +2 size / +4 start block — the +4
  read as start block is proven, its *source* being the property value is the
  only writer found); HMAC performed by the EL3 "mmap rpmb hmac" service or an
  external TLAPI driver module (not resolvable in-image); BSS-default S=0 when
  the property is absent; frame-MAC keying equivalence (proven by the
  single-key-per-device property of RPMB itself).
* **Unresolved / next probes:** actual numeric value of S (needs the on-device
  dump of §5, or a runtime dump of RAM 0x05F8471C inside MTEE); full semantics
  of the ctx+0xA18 counter source; whether an external `.drw` RPMB driver
  module exists in another partition (not in tee.img).
