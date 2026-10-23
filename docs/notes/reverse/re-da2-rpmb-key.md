# RE: OPLUS DA2 (RMX3630, `da2_oplus.bin`) — where does the RPMB HMAC auth key come from?

Date: 2026-10-23. Target: `docs/notes/rmx3630-da2/da2_oplus.bin` (356296 B, **entirely
ARM32 despite the README's Thumb warning** — all "push {…}" prologues decode as ARM
`STMFD`; load base 0x40000000, file off == VA - 0x40000000).
Method: r2 (`-a arm -b 32 -m 0x40000000`) + byte-level movw/movt xref scan (many RPMB
library strings have **zero** code references — see §5).

## TL;DR — verdicts

* **T1 (key materializes in DA2 RAM): TRUE.** The RPMB frame MAC is computed by a
  **software HMAC-SHA256 inside DA2** (`rpmb_hmac` = `0x40032e5c`), keyed by a
  32-byte key that **materializes in DA2 RAM**, staged through the global
  **`0x4006e8d8`**. It is *not* an embedded constant and *not* host-supplied: it is
  **derived on-chip by the HACC (hardware crypto) engine at physical base
  `0x10210000`** from the eFuse-protected secure key, using the literal tags
  `RPMB KEY` / `SASI` (and `BTTJSQNC!LFZ`).
* **T2 (all auth goes through TEE/SMC, raw key never enters DA2): FALSE for this
  blob.** There is **no SMC/ATF conduit at all** in the image (byte-scan for ARM
  `SMC` encoding `E3x00F7xx` at 4-aligned offsets: zero hits; the Thumb `svc`
  hits earlier in ad-hoc dumps were misdisassembled ARM). The "secure" dependency
  is the **HACC engine**, not TrustZone. The raw 32-byte key lands in DA2 RAM
  (malloc'd 0x20 buffer + copy at `0x4006e8d8`) on **every** HMAC computation, and
  is wiped after each use (memset at `0x40033028`).
* **T3 (key-programming takes a key from a host command): FALSE for stock OPLUS
  DA2.** `mmc_rpmb_set_key` (0x400471e6), `rpmb_authen_key_program` (0x4004bd9e),
  `ufs_rpmb_authen_key_program` (0x4004bf96) and the whole
  "[%s]: RPMB Fail in Sending authen key program request…" string cluster are
  **referenced by no code** (ARM + Thumb movw/movt scan, literal-pool scan: 0 hits)
  — dead library code. The only RPMB host surface is `CMD:EMMC-CONTROL`
  (handler `0x400069f4`) whose XML `da/arg/function` sub-ops
  `GET-RPMB-KEY-STATUS` / `LIFE-CYCLE-STATUS` answer **`RPMB-KEY-STATUS`
  EXIST / NOT-EXIST** — status only, no key transfer. mtkclient's
  `da rpmb a <key>` path relies on mtkclient's *own* patched-in stub
  (`44 44 44 44` markers), not this stock DA2.
* Corollary: since the DA2 computes frame MACs with the HACC-derived key and
  performs **authenticated RPMB writes at UFS init** (`ufs_clr_write_protect`
  path, §3), the derived key **is the device's real RPMB auth key** — and it can
  be dumped from DA2 RAM (§6).

---

## 1. `rpmb_hmac` — `0x40032e5c` (504 B, ARM)

```
0x40032e5c  rpmb_hmac(u8 *data /*r0*/, u32 len /*r1*/, u8 out_mac[32] /*r2*/):
  if (!data || !out_mac)                      -> "[%s] Invalid address" (0x40050e7a)
  buf = malloc(0x1000)  (0x4000a5b4)          ; fail -> same error
  if (len > 0xb40)                            -> "[%s] size over maximum allowed size"
                                                 (0x40050e0c) ; max 0xb40 bytes payload
  if (len == 0)                               -> "[%s] size is zero" (0x40050e9a)
  memcpy(buf+0x40, data, len)                 ; 0x4000b110
  tmp = malloc(0x20) ; memset(tmp,0,0x20)
  fcn.4003a944(0, tmp, 0x20)                  ; <<< THE KEY DERIVATION (§2)
      on failure: memset(buf), error out
  memset(0x4006e8d8, 0, 0x40)                 ; clear key stage
  memcpy(0x4006e8d8, tmp, 0x20)               ; KEY IS NOW AT 0x4006e8d8
  fcn.40032ca4(buf, 0x4006e8d8, 0x20, buf+0x40, {len+0x40...}, buf+0xce0)
                                              ; ^ HMAC-SHA256 core, key ptr = 0x4006e8d8
  memcpy(out_mac /*r6*/, buf+0xce0, 0x20)
  free(buf)
  0x40033018: memset(0x4006e8d8, 0, 0x40)     ; <<< KEY WIPED on every exit
  0x40033028: bl memset  <-- patch point to keep the key resident (§6)
```

## 2. Key derivation — `fcn.4003a944` (0x4003a944–0x4003aa74)

```
0x4003a944  derive(op /*r0*/, out /*r1*/, outlen /*r2*/):
  stack tags (little-endian words):
    sp+0x24 "SASI"   sp+0x28 "RPMB"   sp+0x2c " KEY"   -> "SASI"+"RPMB KEY"
    sp+0x14 "BTTJ"   sp+0x18 "SQNC"   sp+0x1c "!LFZ"
  fcn.4003a2d8(1)                              ; engine lock/claim
  if op == 0:                                  ; path used by rpmb_hmac
      r0=0x10210000, r1=1, r2=&"RPMB KEY"(sp+0x28), r3=8,
      sp[0]=&"SASI..."(sp+0x24), sp[4]=4, sp[8]=out, sp[0xc]=0, sp[0x10]=outlen
  else: same but r2=&"BTTJ..."(sp+0x14)
  bl fcn.40040b38                              ; HACC task submit
  ret==0  -> return 0 (out[] now holds 32 bytes)
  ret!=0  -> print 0x400519ed, memset(out,0,outlen), return err
  fcn.4003a2d8(0)                              ; engine release
```

Call chain into hardware:

* `0x40040b38` — task/DER-style parameter packer (words `0xF2000003`,
  `0x01001C20`, `0x80001C26`, block loop 0x10 B, helpers `0x40040e7c/e84/e88`,
  `0x400409a8` → `0x40040cfc`).
* `0x40040cfc` — builds **HACC descriptors** (opcode bytes 0x41/0x42,
  flags in `0x800…` words) and pushes them via `fcn.4003fe24`.
* `0x4003fe24` — **mailbox/CFIFO pusher**: polls `[base+0xE9C] & 0xF`, then
  writes 6 words to `[base+0xE80 .. +0xE94]`. Base = **0x10210000** (HACC/SEJ3
  register block, passed straight through from `0x4003a944` as `r0`).
* The engine computes the derivation from its **eFuse-protected secure key**
  and DMA-writes the 32-byte result into the caller's buffer. The efuse key
  itself is never readable; **the derived RPMB key is**.

## 3. Live RPMB frame layer (UFS device) — branch map

Registered at boot: `0x400018a4` (storage init) → `0x40030dd4`
("interface_ufs_init") → `0x400251c4` — builds the UFS RPMB device object
**`0x4006def8`**: +0xc zeroed 0x20 field, +0x20 = `0x40025298`, +0x24 =
`0x400252ec`, +0x2c = `0x40025340` (ops: UFS RPMB get-size/query wrappers over
`0x40024838`), buffers 0x1000; then calls `0x400270b0`:

```
0x400270b0  ufs_clr_write_protect():
  fcn.40026ea8(0, 1, 0, 0, 4)   ; RPMB sec-wp conf op 1
  fcn.40026ea8(0, 2, 0, 0, 4)   ; op 2
  fcn.40026ea8(0, 3, 0, 0, 4)   ; op 3   (auth WRITE — proves key match)
    errors -> print __func__ "ufs_clr_write_protect" (0x4004c37a)
```

* `0x40026ea8` — per-op driver: 3 call sites into `fcn.40026044`
  (0x40026f20 / 0x40026f98 / 0x40027004).
* `0x40026044` (0x40026044–0x400266d4) — frame build/response check;
  calls `rpmb_hmac` (0x40026614) and `fcn.400266d4` (0x40026544);
  on HMAC failure prints `"%s, rpmb_hmac error.\n"` (0x4004c6d6).
* `0x400266d4` (0x400266d4–0x40026dbc) — second frame checker; calls
  `rpmb_hmac` (0x40026944, 0x40026ce8); prints rpmb_hmac error (0x40026d08).
* `0x40026dbc` — caller of `0x400266d4` (0x40026e64) and of `0x40025fb0`
  (0x40026dd8) = `ufs_rpmb_pre_nonce` (nonce generator, string @0x4004c5c9,
  ref 0x4002602c): 4 random bytes into **`0x4006df40`**.
* SHA-256 core used by the HMAC: `fcn.4003a2d4` (plain SHA-256, K-table at
  **0x40054068**, standard IV 67E6096A…; same primitive used by the SEC/seccfg
  code at 0x40034bc4/0x40034f74).

**Implication:** the DA2 performs authenticated RPMB operations during UFS init
itself; if the derived key did not match the key programmed in the UFS device,
these writes would be rejected by the controller. ⇒ derived key == programmed
RPMB auth key (on units where the key was provisioned by this same scheme;
a TEE-provisioned random key would NOT match — see §7).

## 4. Host command surface — `CMD:EMMC-CONTROL` = handler `0x400069f4`

Registrar `0x40001a6c` registers `0x40041572`="CMD:EMMC-CONTROL" → handler
**0x400069f4** (matches the session notes' static map).

```
0x400069f4  emmc_control(req, xml):
  node = xml_lookup(req, stub 0x4000EDE8)            ; 0x4000d0bc
  fn   = value_of(node, "da/arg/function")           ; 0x40001e48, key 0x40042557
  arg2 = value_of(node, "da/arg/target_file")        ; 0x40001e48, key 0x40041a27
  r8 = [0x40067458]    ; storage singleton A (eMMC)
  r5 = [0x40066d80]    ; storage singleton B (UFS)
  if strncmp(fn,"GET-RPMB-KEY-STATUS",0x40)==0:      ; strncmp = 0x4000b57c
      code = 0x30
      if (r5 == 0) code = 0x10
      if (r8 != 0) code = 1
      st = [0x40054374+0xc](code, 8, 0, 0, &out, 4, 0, 0)   ; internal svc call
      if st == 0x10: reply field "RPMB-KEY-STATUS" = "EXIST"   (0x40042ecb, len 6)
      else:          reply field "RPMB-KEY-STATUS" = "NOT-EXIST"(0x40042ed1, len 10)
      sender 0x4002b330
  elif strncmp(fn,"LIFE-CYCLE-STATUS",0x40)==0:      ; 0x40042eeb
      st = [0x40054374+0xc](code, 9, 0, 0, 0, 0, 0, 0)
      st==0xC003001C -> "WARNING"(0x40042f07) ; st==0xC003001D -> "EXHAUSTED"(0x40042efd)
  else: return 0
```

* Status-code globals: `0x40066d80`, `0x40067458`, `0x40067738`
  (singletons initialized in storage init; `GET-HW-INFO` handler 0x400064bc
  also reads them for `rpmb_size`/device fields).
* No other RPMB-named host commands exist in the registrar tables
  (0x40041520–0x40041660 name block checked: only storage/flash/security names).

## 5. Dead (unreferenced) RPMB strings — do NOT chase these

`mmc rpmb`(0x4004714e — referenced only inside the MMC driver debug prints at
0x40017e78+), `mmc_rpmb_set_key`, `rpmb_authen_key_program`,
`ufs_rpmb_authen_key_program`, `rpmb_authen_read_counter`(referenced only as
`__func__` at 0x40025d60/0x40025f14), `rpmb key is already programmed!!`,
`rpmb key has/has not been programmed!!`, `will be programmed!!`,
`[%s]: RPMB Fail in Sending authen key program request…`, `rpmb_ufs_set_wp/clr_wp`
error cluster, `%s: get enable rpmb flag…`, `%s: rpmb keyprovision flag …`,
`update_rpmb_key_flag`. **Zero movw/movt (ARM+Thumb) and zero literal-pool
references** — the UFS RPMB *key-programming* library is compiled in but not
entered from any live path. (`rpmb_authen_read_counter`'s `__func__` refs sit in
the live frame-check functions 0x40026044/0x400266d4 — the checkers themselves
are live, only the program/counter entry points are dead.)

## 6. How to extract the key at runtime (heapbait patch_mem)

The key is wiped by `memset(0x4006e8d8, 0, 0x40)` at **0x40033028**
(`bl fcn.4000b330`; args set at 0x40033018–0x40033024). To keep it resident:

1. `EXP-PATCH-MEM` VA `0x40033028`: write `00 00 A0 E1` (`mov r0,r0`) — 4 bytes,
   NOPs the wipe memset (the arg-setup block 0x40033018.. stays harmless).
2. Trigger any RPMB activity so `rpmb_hmac` runs once: a UFS re-init
   (`0x40030dd4`) or any `CMD:EMMC-CONTROL` exchange that reaches the frame
   layer. (Each `rpmb_hmac` call re-derives the key via HACC and re-stages it
   at `0x4006e8d8`.)
3. Dump 32 bytes at **`0x4006e8d8`** (read-mem via patch_mem/exploit) — that is
   the RPMB HMAC-SHA256 auth key. (First 0x20 bytes of the 0x40 stage; bytes
   0x20–0x3F are stale padding.)
4. Alternative hook point: `fcn.4003a944` return (0x4003aa20–0x4003aa2c) —
   the freshly derived key is also in the caller's malloc'd buffer; patching a
   copy loop there into a fixed scratch address works if you want a dedicated
   location, but the memset-NOP route above needs no new code.

Caveat: this is a runtime patch on the *running* DA2 (DA1 hash rule) — same
procedure as every other patch in `rmx3630_session_2026-10-23.md`.

## 7. Open / to verify on device

* Whether the UFS device's programmed RPMB key was provisioned with this same
  HACC "RPMB KEY" derivation (MTK scheme) or by TEE with a random key. If the
  latter, the derived key ≠ device key and `GET-RPMB-KEY-STATUS`/init writes
  will fail (frame MAC rejected). The init-time `ufs_clr_write_protect` result
  and the `EXIST/NOT-EXIST` reply are the empirical discriminators.
* Exact semantics of status codes 0x30/0x10/1 into `[0x40054374+0xc]`
  (likely: per-storage-type query); EXIST ⇔ returned status == 0x10.
* The second tag group `BTTJSQNC!LFZ` (op==1 variant of `0x4003a944`) —
  presumably a second HACC derivation profile (not used by rpmb_hmac).

## Confidence

* **Proven (disassembly + byte-level xref):** rpmb_hmac location/structure, HMAC
  = software HMAC-SHA256 (0x36/0x5c pads, K-table 0x40054068), key stage global
  0x4006e8d8 + wipe site 0x40033028, key-derivation call chain into the HACC
  mailbox (0x10210000, CFIFO +0xE80, status +0xE9C), absence of SMC in the
  image, EMMC-CONTROL registration & GET-RPMB-KEY-STATUS handler logic, dead
  status of the key-programming string cluster.
* **Inference:** "HACC base 0x10210000" naming (descriptor/CFIFO layout is
  HACC-shaped), equivalence of the derived key with the device-programmed RPMB
  key (strong, pending on-device confirmation).
