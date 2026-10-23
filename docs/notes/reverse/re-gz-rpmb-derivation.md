# RE: GenieZone gz.img (RMX3630, MT6789) — container, RPMB key derivation, and the DA2-key question

Date: 2026-10-23. Target: `docs/notes/rmx3630-lk/gz.img` (2 692 720 B).
Companion analysis of the plaintext ATF payload in the same folder:
`docs/notes/rmx3630-lk/tee.img` (768 816 B, magic `atf`) — this turned out to
be the decisive evidence source, because **the GZ binary itself is encrypted**.

## TL;DR verdict

1. **The gz.img payload cannot be analyzed statically** — both the `gz` binary
   (0x26C5F0 B @0x200) and the second entry `unmap2` (0x22EE0 B) are
   **encrypted** (entropy 8.00, zero AArch64 prologues, byte distribution
   ≈ uniform). The RPMB derivation code inside GZ is therefore **not reachable
   from this image**. (Proven.)
2. **But the derivation was found anyway — in the ATF image** (`tee.img`,
   plaintext AArch64, load base **0x48200000**). ATF at EL3 implements the
   RPMB HMAC service itself:
   `SMC 0xC2000414 = MTK_SIP_BL_MMC_CONTROL` (and
   `SMC 0xC200040D = MTK_SIP_BL_UFS_CONTROL` for UFS) with sub-op 2 =
   *derive RPMB key via HACC @ 0x10210000 with tags "SASI"+"RPMB KEY",
   then HMAC-SHA256 the 0x11C-B frame from the shm @ 0x48400000 and write the
   32-B MAC to shm+0xF00*. (Proven by disasm.)
3. This is **byte-for-byte the same scheme as the OPLUS DA2** (same HACC base
   0x10210000, same tag pair `SASI` + `RPMB KEY`, same second tag group ≈
   `BTTJSQNC!LFZ` obfuscated +1 per byte). The derivation is **deterministic,
   efuse/HACC-keyed, label-based** — not random, not stored-only-in-eMMC.
4. **Verdict for the mission question: probability that the DA2-dumped key ==
   the device-programmed RPMB auth key is HIGH.** Reasoning in §6.

---

## 1. gz.img container layout (proven, byte-level)

MTK multi-image secure container (same family as lk.img; GFH magic
`0x58881688` per entry, per-entry trailer `0x58891689` + cert blocks
`0x12345678`/`0x12345622`). Entries are 0x30-B headers; the file header at 0x0
pre-declares entry 1.

| file off | name | size | content |
|---|---|---|---|
| 0x000000 | header `gz` | 0x26C5F0 | GFH_FILE_INFO (magic 0x58881688, name "gz", payload size 0x26C5F0) |
| 0x000200 | **gz payload** | 0x26C5F0 | **ENCRYPTED** (entropy 8.00; 0 AArch64 `stp x29`-style prologues in the whole region) |
| 0x26C7F0 | `cert1` | 0x6C5 | X.509-ish cert data (Oplus_cert0 / Mediatek / Some-State strings visible, DER) |
| 0x26C820 | sec-cfg entry | 0x200 | 0x58891689 trailer block |
| 0x26D0C0 | `cert2` | 0x3F3 | second cert |
| 0x26D6C0 | `unmap2` | 0x22EE0 | **ENCRYPTED** second binary (entropy 8.00) |
| 0x2907A0 | `cert1` | 0x6C5 | certs for unmap2 |
| 0x291070 | `cert2` | 0x3F3 | |

Header compare with lk.img (plaintext payload, same 0x30-B header layout):
structurally identical; no obvious per-entry "encrypted" flag differs in the
first 0x60 bytes — the encryption is indicated by content, not by a header
bit we could identify. Mark: *header-field semantics not fully resolved
(the 0x28/0x2C word is 0xFFFFFFFF in both)*.

Encryption key/decryption agent: **inference (strong)** — MTK decrypts
GenieZone images with the HACC engine keyed from efuse; ATF contains a full
HACC driver (`"%s: hacc fail"` string at tee file 0x284B3, xref
`fcn.48211128`, and the gz loader dispatcher `init_gz_info`/`init_gz_plat`
@ `fcn.48204aec` with per-type jump tables). So gz.img is decrypted by
ATF/EL3 at boot using efuse-keyed HACC. Decryption is **not reproducible
host-side** without the efuse key; and even with DA-level efuse reads, the
HACC key register is write-only.

tee.img itself: GFH "atf" payload 0x30588 B @0x200, **plaintext** AArch64.

## 2. ATF load base = 0x48200000 (proven)

`VA = file_offset − 0x200 + 0x48200000` (i.e. payload offset 0 == 0x48200000).
Derived from the SIP dispatch table: handler entries are absolute VAs
(0x482xxxxx) that land inside the payload (e.g. 0x4820C270 = payload 0xC270),
and every disassembled handler resolves cleanly (stack canary
`ldr [0x4822E080]`, string refs, HACC regs) at that base.

## 3. MTK SIP dispatch table (ATF, payload 0x2B000–0x2B7FF)

32-byte records: `{handler_va, 0, smc32_id, smc64_id, name_str?, 0, ?, 0}`.
Excerpt (full table preserved in analysis):

| SMC64 | handler VA | identification |
|---|---|---|
| 0xC2000414 | **0x4820C270** | name string at payload 0x2AA9C = **"MTK_SIP_BL_MMC_CONTROL"** — the RPMB HMAC service used by LK (`re-lk-rpmb-key-derivation.md`) |
| 0xC200040D | **0x4821E2A4** | name string at payload 0x2A0B0 = **"MTK_SIP_BL_UFS_CONTROL"** — second RPMB HMAC service (entry `x0==0x10`), UFS path |
| 0xC2000410 | 0x4820A590 | (crypto hw engine init family per nearby strings) |
| 0xC2000115 | 0x48204D74 | MTK_SIP_KERNEL_BOOT |
| 0xC2000507 | 0x4820A544 | MTK_SIP_MTK_LPM_CONTROL |
| … | … | ~60 entries total |

## 4. The RPMB HMAC service — annotated disasm (proven)

### 4.1 `MTK_SIP_BL_MMC_CONTROL` handler — 0x4820C270

```asm
0x4820c270  MMC_CONTROL(x0=op, x1=arg):
  canary check
  cmp x0, 1 ; b.ne -> -1            ; only x0==1 accepted (LK/preloader realm)
  x1==0: mmap  (0x48400000, 0x48400000, 0x1000, attr 0x1a)   ; the "vm_hmac" carveout
         fail -> "mmap rpmb hmac error."
  x1==1: unmap (0x48400000, 0x1000)  ; "mmap remove rpmb hmac error."
  x1==2: ; ---- THE HMAC OPERATION (LK's dev1 path: SMC 0xC2000414(1,2,...)) ----
    x1=sp+8; w2=0x20; w0=0
    bl 0x48215b34                    ; DERIVE(op=0, out=sp+8, len=0x20)
                                     ;  -> 32-B RPMB key materializes on ATF stack
    bl 0x48203c9c(0x48400000,0x11c)  ; dcache invalidate shm (frame in)
    bl 0x48209e44(sp+8, 0x20, 0x48400000, 0x11c, 0x48400F00)
              ; HMAC-SHA256(key=sp+8 len 0x20, data=shm frame 0x11C, out=shm+0xF00)
    bl 0x48203b84(0x48400F00, 0x20)  ; dcache clean of MAC
  ret 0
```

This **corrects** the LK note's attribution: the HMAC for the `dev1`
(`rpmb_read_direct`) path is computed **in ATF at EL3**, not inside GZ/EL2.
The 0xC2000414 channel is ATF's own service ("BL_" prefix = called from
bootloaders); GZ is not in this path at all.

### 4.2 Key derivation — `derive(op, out, outlen)` @ 0x48215b34 (696 B)

```asm
0x48215b34  derive(op /*w21*/, out /*x19*/, outlen /*w20*/):
  x9  = "RPMB KEY"   (0x5945_4B20_424D_5052 LE) ; stored at x29-0x10
  w10 = "SASI"       (0x49534153)               ; stored at x29-0x14  -> "SASI"|"RPMB KEY" contiguous
  x11 = 0x5B47_4D22_444F_5254 ("TROD" "\"MG[")  ; stored at sp+0x10
  w12 = 0x4B554355 ("UCKU")                     ; stored at sp+0x0C
  bl 0x4821dae4(1)                    ; HACC engine lock/claim (cf. DA2 fcn.4003a2d8(1))
  bl 0x48200ee8(0x10210000, sp+8)     ; HACC version probe:
                                      ;   poll [0x10210ABC]&1 ready, version = [0x10210AD4]&0xFF
                                      ;   accepts ver==1 or 5; ver5 sub-check via 0x48200f94
  if (ver|4) != 5 -> "unsupported hacc version", err 0xe
  if op == 2:  tag8=&sp+0x10 ("TROD\"MG["), tag4=&sp+0x0C ("UCKU")
  elif op == 0: tag8=&x29-0x10 ("RPMB KEY"), tag4=&x29-0x14 ("SASI")
  else: err 0
  bl 0x48200c1c(0x10210000, 1, tag8, 8, tag4, 4, out, outlen)
                ; HACC DER-style derive submit (DER/TLV packer, validates
                ;  tag lens <=0x20, packs 0x43-B descriptor, engine mailbox)
  on error: err 0xd/0xf, zero-fill out[outlen]
  bl 0x4821dae4(0)                    ; engine release
```

* **Tag set A** (op=0) is **exactly** DA2's RPMB profile:
  tag8 `"RPMB KEY"` + tag4 `"SASI"` — identical byte strings, identical
  order, identical HACC base 0x10210000.
* **Tag set B** (op=2): stored bytes `"UCKU"` + `"TROD\"MG["`; **each byte
  minus 1** yields `TBTJSQNC!LFZ` — a permutation of DA2's second profile tag
  `"BTTJSQNC!LFZ"` (the first dword is pair-swapped: `BTTJ`↔`TBTJ`; the
  `SQNC!LFZ` part matches exactly after de-obfuscation). So ATF obfuscates
  this tag (+1/byte); DA2 stores it plain. **Caveat (open):** DA2 packs the
  second profile as tag8=`"BTTJSQNC"` (first 8 chars) while ATF splits
  tag4=`TBTJ`/tag8=`SQNC!LFZ` — the two builds may not feed the HACC the
  same DER blob for profile B. Irrelevant for RPMB (profile A is identical);
  only affects the unknown op=1/2 "second key" use.

### 4.3 HMAC core — 0x48209e44

Validates `len ≤ 0x400`, `keylen ≤ 0x40`, non-NULL; scratch 0x440; uses the
**SHA-256 IV tables at payload 0x22EC8 / 0x22F48** (67E6096A…5BE0CD19, two
copies) → HMAC-SHA256, matching DA2's software HMAC-SHA256.

### 4.4 HACC hardware (proven addresses)

* Engine base **0x10210000** — identical to DA2. Status/ready at +0xABC
  (poll bit0), version at +0xAD4 (low byte 1 or 5 accepted; bit8/bit9
  feature flags checked).
* Second register block **0x1020F000** used by the HACC driver
  (`fcn.48211128`, the `%s: hacc fail` site): reads/sets [+0x0], [+0x8],
  [+0xC] (|= 0x20, |= 1) — consistent with HACC key/CFG/SEC init (likely the
  efuse-key enable path; exact semantics not proven).

## 5. Task answers

### T1 — GZ image structure
Encrypted GFH container (§1). GZ version strings, derivation code, and any
GZ-side service code are **inside the encrypted payload — not statically
recoverable from this dump**. The only GZ-visible artifacts in the clear are
the container, two OPLUS/Mediatek certs, and the loader/decrypt plumbing in
ATF (`init_gz_info` @0x48204AEC, `init_gz_plat`, HACC driver).

### T2 — RPMB key derivation inside "GZ"
Found in **ATF instead**: `derive` @0x48215B34 → HACC @0x10210000 with
tag4 `"SASI"` + tag8 `"RPMB KEY"` (op=0), producing the 32-byte RPMB
HMAC-SHA256 key. Inputs: **only the HACC's internal efuse-protected secure
key + the two tag strings** (no SoCID, no serial, no per-boot data — the
ATF call passes nothing else; DA2 matches). Crypto: HACC hardware KDF
(DER-style descriptor), then software HMAC-SHA256 for the frame MAC.
An earlier suspicion that GZ mixes in "device serial" is **not supported**
by the ATF code — the derivation is stateless and label-only.

### T3 — "gz rpmb_key" service / raw key crossing boundaries
* The LK `dev1` channel (0xC2000414) **never carries the raw key**: only the
  0x11C frame goes into shm and only the 0x20 MAC comes back. Key material
  stays on the ATF stack (sp+8..0x27) for the duration of one op.
* **The raw key MUST exist outside the TEE at some point** because preloader
  programs it into eMMC/UFS (`rpmb_authen_key_program`,
  "RPMB Key has been written!" — proven strings in preloader). Where it is
  generated for preloader is **not in ATF's SIP table** (no key-return op
  exists in the ~60-entry table; both MMC/UFS handlers only accept their
  mapped/unmap/hmac ops). **Inference:** preloader derives the key itself
  with its own HACC driver — preloader contains `key_derive fails(0x%x)`,
  `[HACC_CON setting]`, EFUSE driver, and runs at EL3 with full HACC access
  *before* ATF is booted (it cannot SMC into ATF at that stage). Under this
  model the string `gz rpmb_key fail` refers to a later-stage GZ availability
  check or a differently-routed call; the *key bytes* come from the same
  HACC scheme. Alternative (weaker): an undocumented GZ SIP op returns the
  key; nothing in ATF's table supports it.
* **Interception point if preloader execution were ever obtained:** the
  preloader RAM region holding the 32-B key between its HACC derive and
  `rpmb_authen_key_program` (preloader is PIC, base unresolved — locate via
  the `rpmb_authen_key_program` call path at runtime). Also ATF's own stack
  during any 0xC2000414 op(1,2) holds the key transiently.

### T4 — Provisioning vs fixed vs random
**Deterministic.** Proven: ATF re-derives the key **per HMAC call** from
HACC+tags — there is no key store, no load-once global, no eMMC read-back of
a stored key in the service. The key is a pure function of (efuse HACC key,
"SASI", "RPMB KEY"). Therefore:
* DA2's dump (same engine, same tags) **must equal** ATF's key, and
* a second unit of the same model/firmware gets a **different** key only
  because its efuse HUK differs (per-device, not per-image).
* No "re-derive/restore" logic is needed or expected: the eMMC copy is
  *recomputable at will* by any component with HACC access. This reconciles
  the DA2 observation: DA2 doesn't "know" a random key — it recomputes the
  same deterministic value that preloader programmed at first boot.

## 6. Final verdict

**Probability that DA2-dumped key == device-programmed RPMB auth key: HIGH
(~90%).**

* DA2 and ATF implement the identical derivation (same HACC base
  0x10210000, same tag bytes `"SASI"`+`"RPMB KEY"`, same 32-B output length,
  same HMAC-SHA256 framing). The only secret input is the efuse-protected
  HACC key, common to both.
* The derivation is deterministic and per-call; GZ being encrypted does not
  matter for the key value — the EL3 service that actually serves LK's RPMB
  ops is in plaintext ATF and was fully reversed.
* Residual risk (the missing ~10%): (i) the *programmed* key could have been
  written by a different agent with a different value only if the stock
  provisioning flow skipped the HACC scheme — no evidence for that, and DA2's
  init-time authenticated writes succeed (MACs accepted by the controller),
  which is itself live proof of key equality; (ii) profile-B tag-packing
  divergence shows the two builds aren't byte-identical libraries — but the
  RPMB profile A is byte-identical, and profile A is what rpmb_hmac uses in
  both.

**If on-device confirmation is still wanted** (settles it absolutely):
run DA2 once with the 0x40033028 wipe-NOP patch (per `re-da2-rpmb-key.md`
§6), dump `0x4006E8D8`, then issue one RPMB authenticated *read* against the
device's boot-info block with that key from mtkclient's `da rpmb` path —
a valid MAC response from the controller proves equality without ever
needing GZ.

## Confidence summary

* **Proven (disasm/byte-level):** container layout & encryption of gz payload
  + unmap2; ATF base 0x48200000; SIP table incl. 0xC2000414="MTK_SIP_BL_MMC_
  CONTROL" and 0xC200040D="MTK_SIP_BL_UFS_CONTROL"; handler op map (mmap/
  unmap/hmac); `derive` @0x48215B34 tags `"SASI"`+`"RPMB KEY"`, HACC base
  0x10210000 (+0xABC/+0xAD4 regs), version gate 1/5; op=2 tag set =
  byte+1-obfuscated `TBTJSQNC!LFZ`; HMAC-SHA256 core (IV tables 0x22EC8/
  0x22F48); per-call derivation (no key store); no key-export SIP op in ATF.
* **Inference:** gz.img is HACC-decrypted by ATF at boot (HACC driver + gz
  loader present; exact loader branch not traced to completion); preloader
  derives/programs the raw key itself via its own HACC (PIC, unanalyzed);
  exact semantics of the 0x1020F000 register block.
* **Correction to `re-lk-rpmb-key-derivation.md`:** the dev1 RPMB HMAC is
  computed **in ATF (EL3)**, not "inside GZ/TEE"; the "vm_hmac" carveout at
  0x48400000 is ATF's service buffer. The note's core conclusion (key never
  in LK, derived from efuse material in secure world) stands.
