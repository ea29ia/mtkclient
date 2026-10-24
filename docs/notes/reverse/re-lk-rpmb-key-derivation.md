# RE: RPMB auth-key provisioning/derivation on MT6789 (RMX3630) — LK + preloader

> **ERRATA (2026-10-24, audit #2):** (1) the LK mirror is at RPMB blocks
> **0x1DC–0x1DF** (0x1DC is the frame address field), not at 0–3. (2) The RPMB
> device-name string at 0x500A06BD is `preloader_a`; `mmc0rpmb` is 0x500A06D5.
> (3) "MAC computed in GZ/TEE" is superseded by `re-gz-rpmb-derivation.md`
> (ATF/EL3, SMC 0xC2000414); t-base SFSRP uses a separate TLAPI driver channel.
> See `re-consistency-audit-2.md` §L13.

Date: 2026-10-23. Companion: `re-lk-rpmb-lock.md` (read fully; this file extends §4/§5 of it).
Targets: LK payload (`lk.img`, off 0x200, VA = off + 0x50000000, AArch64),
`preloader_k6789v1_64.bin` (ARM32/Thumb, position-independent — load base **not
resolved**; preloader cites below are FILE OFFSETS), `md1img.img` (grep only).

## Verdict (TL;DR)

**Neither (a) host-side-derivable nor (c) fixed.** The evidence points to a
hybrid closest to **(b), with (a)-style derivation happening *inside* the
secure world**: LK never holds the RPMB auth key. Both RPMB read paths in LK
(delegate the HMAC to EL3/TEE over SMC). Preloader evidence shows the key is
obtained **from GenieZone (GZ/TEE)** ("`gz rpmb_key`") and programmed into
eMMC by preloader during a first-boot "keyprovision" flow — i.e. the key is
generated/derived in the TEE from SoC-secret material (efuse HUK), stored
only in eMMC RPMB auth-key slot, and never exposed as plaintext to LK,
preloader, or DA. Confidence: **high** for "key not in LK / not LK-computed"
(proven by disasm); **medium** for "derived from efuse inside GZ, not random"
(string-level evidence, GZ image not analyzed).

## Q1. rpmb_read_direct vs rpmb_read_via_tee — and who computes the HMAC

`rpmb_get_device_type` (0x50055570), proven branch map:

```
0x50055570  rpmb_get_device_type(buf, 0x1DC, 0x400, &status):
  st = 0x50074f54()                 ; "rpmb enable" probe (hardcoded ret 1 in this build)
  st==1 → 0x500555d8: bl 0x5002fd14   rpmb_read_direct            ; "dev1"
  st==2 → 0x500555a0: bl 0x5003e4e4   rpmb_read_via_tee (dev2),   ; retry once after
                      ; sleep 0x74A120 us (0x5006a7dc) on failure
  else  → "ERROR read storage failed unknown device: %d", ret -1
```

### Q1 KEY ANSWER: dev1 does NOT mean "LK talks raw eMMC with its own HMAC"

Full trace of `rpmb_read_direct` (0x5002fd14, 1036 B, dump in analysis):

1. Builds the RPMB frame locally in LK memory (frame buffer at sp+0x30,
   0x1FE-byte memset, block address `rev(w22)>>16` stored at sp+0x228,
   0x400 stored at sp+0x22e, nonce copied to x25 = sp+0x1E4 area,
   0x5002fdc8–0x5002fe90).
2. `bl 0x5002fb24` — frame dispatcher → `0x50030510` (mmc_rpmb_send_command):
   cmd types 3 / 5 / 4 with sub-encodings (read-counter, sec-write-probe,
   data read) — plain eMMC transport only, **no key material passed**.
3. **The HMAC round-trip goes through EL3**, 0x5002ff00–0x50030008:
   ```
   0x5002ff0c  adrp x8, 0x50133000 ; x27 = *(0x50133A00)   ; shm buffer ptr
   0x5002ff18  bl 0x5006c9c8        ; memcpy(x27, src, 0x11C)  ; frame → shm
   0x5002ff24  bl 0x50003acc        ; dcache clean (x27, 0x1000)
   0x5002ff28  bl 0x50003890        ; dcache inval/flush
   0x5002ffd4  mov w0, 0xC2000414   ; SMC id
               mov w1, 1 ; w2, 2    ; args; frame ptr on stack
   0x50030008  bl 0x5001db88        ; raw `smc #0` wrapper (verified: smc 0 @ 0x5001db88)
   0x5002ff40  ...                  ; response: XOR-compare 32 B (nonce) from
                                    ; *(0x50133A08) against local nonce; second
                                    ; 32-B compare vs *(0x50133A00) contents
   ```
   Errors from the SMC are logged as `"%s, rpmb_hmac error. (0x%x)"`
   (0x500a0f2d) / `"%s, mmc_rpmb_part_ops failed!!"` etc. Nonce/HMAC mismatch
   paths: `"%s, compare hmac error!!"` (0x500a0f4a) → -1/-2/-3 returns.
4. Only **after** the secure-side MAC check passes does LK copy data out
   (`memcpy(dst=x21, src=frame, ≤0x100)` loop, 0x5002ffa0–0x5002ffc8).

The shared-memory service is registered at init (0x5002f5a4 region):

```
0x5002f5a4  x5 = "system_rpmb_hmac-reserved"        ; 0x500a0e04
            bl 0x50018a34                            ; reserve phys region
0x5002f5c0  w21 = 0x48400000                          ; shm phys base (carveout)
            bl 0x500695d8 → memcpy(0x50141660, "vm_hmac" /*0x500a0e51*/, 0x1000, ...)
0x5002f61c  *(0x50133A00) = shm base; *(0x50133A08) = shm+0xF00
0x5002f63c  SMC 0xC2000414(1, ...)                    ; register shm/subscribe
```

So the 0x1000-B carveout at **phys 0x48400000**, named **`vm_hmac` /
`system_rpmb_hmac-reserved`**, is the EL3↔NLK RPMB channel. The name set
("system_rpmb_hmac", "vm_hmac" = per-VM hmac service) is GenieZone/hypervisor
terminology: the MAC is computed **inside secure world (GZ/TEE), keyed by the
RPMB key held there**, not by LK.

`rpmb_read_via_tee` (0x5003e4e4) is a GP-TEE client: context global
0x5013CE18, session open 0x5003BB40, invoke 0x50039224/0x5003DCF0, 0x200-size
shared param at 0x5013D040 — same conclusion (key inside TEE), different
transport.

**Answer to the key question:** LK never computes HMAC and never holds the
key. There is no global key buffer, no efuse read, and no derivation call in
either read path. The only "secret" LK touches is the plain SHA-256 of the
boot-info block (host-computable, per `re-lk-rpmb-lock.md` §4).

## Q2. Key-related strings

### lk.img (VA = off + 0x50000000; `strings -a -t x lk_payload.bin`)
| VA | string |
|---|---|
| 0x500a06bd | `mmc0rpmb` (RPMB dev name) |
| 0x500a0ce3 | `RPMB don't support erase operation` |
| 0x500a0e04 | `system_rpmb_hmac-reserved` ← shm name, ref 0x5002f5a4 |
| 0x500a0e1e | `rpmb_hmac_addr (0x%x) is not taken from mb (0x%x)` |
| 0x500a0e51 | `vm_hmac` ← shm name registered to EL3, ref 0x5002f5d8 |
| 0x500a0e59 | `err=%d, vm_hmac (0x%p) expected (0x%lx)` |
| 0x500a0f2d | `%s, rpmb_hmac error. (0x%x)` (SMC error path 0x50030014) |
| 0x500a0f4a | `%s, compare hmac error!!` |
| 0x500a0f99 | `mmc_rpmb_set_key` (driver symbol only; not called from boot path found) |
| 0x500a0faa | `mmc rpmb key is already programmed!!` |
| 0x500a548f..0x500a5ec3 | full UFS RPMB driver set (`rpmb_authen_key*`, `rpmb_get_mac`, `rpmb_ufs_set_wp`...) |
| 0x500a1a65 | `sec_key_derive` (no code xref found — dead/feature-gated symbol) |
| 0x5008e03b | `efuse_value is %d, sbc_enable is %d, daa_enable is %d` (DAA/SBC fuse read) |
| 0x500925dc | `efuse_Serial_verify` (serial fuses, not RPMB) |

No `huk`, `auth key`, `Provision`, `seeds`, `keyslot` strings in LK.

### preloader_k6789v1_64.bin (file offsets — PIC, no load base)
| off | string |
|---|---|
| 0x490d2 | **`[%s] gz rpmb_key fail, ret=%d`** ← key comes from GenieZone |
| 0x48d88/0x48da8/0x48dc0 | `gz part check failed`, `GZ fatal error`, `geniezone/gz_init.c` |
| 0x50db4 | `%s: hacc fail` |
| 0x50df2 | **` RPMB storage get key fail ret = %d`** |
| 0x527b0 | `nMagicNum1..nUsbAutoSwitch:%d, rpmb_en:%d, rpmb_key:%d` (boot-params struct carrying RPMB enable/key flags) |
| 0x53ca6 | `[UFS] err: ufs_aio_rpmb_get_lu_size` |
| 0x53cca | `rpmb_authen_key_program` (+ `Fail in Sending authen key program request`, `Authentication Key Program Fail`) |
| 0x53f08 | `[UFS] RPMB Key has been written! ret = %d` |
| 0x53f33/0x53f66 | `rpmb key has not been programmed!!` / `will be programmed!!` |
| 0x53f94/0x53fdd | `[Failed] Authentication Key not Programed this time` / `[PASS] Authentication Key Program Success` |
| 0x54e1f/0x54e5a | `%s: get enable rpmb flag, enter enable flow` / `%s: not enable rpmb` |
| 0x54e6f/0x54e9b | `rpmb keyprovision flag has been setted` / `not set` |
| 0x54ec6/0x54f05 | `%s:update_rpmb_key_flag addr=0x%llx` / `update_rpmb_key_flag` (persisted flag) |
| 0x546aa | ` RPMB storage get key fail err = %d` |
| 0x546cf..0x54953 | UFS RPMB (`rpmb_get_mac`, `Fail in checking MAC`, `Fail in Write Counter Increasement!`) |
| 0x567ab | `[CC] not unique key, lcs = 0x%x` (chip-config/LCS fuse state) |
| 0x567da | **`key_derive fails(0x%x)`** |
| 0x56857/0x56874 | `[HACC_CON setting]` (HW crypto used in preloader) |
| 0x569fe..0x56a2e | `[EFUSE] Error: reinit fail`, `EFUSE lock/unlock` |
| 0x51801/0x5182d/0x5185b/0x5189f | `efuse`, `EFUSE`, `efuse_storage_read in efuse_part_start_offset=%d`, `efuse_secure_read` |
| 0x519f0/0x519fc | `oemkeystore`, `keystore` |

Note: preloader has the *whole* RPMB provisioning toolchain (set-key program,
read-counter, SWPCB) plus a "get key" API that **fails with `RPMB storage get
key fail`** when the key is unavailable — and a separate GZ call path whose
failure is `gz rpmb_key fail`. The key itself is not a preloader constant.

## Q3. Derivation: is it efuse-HUK-based and host-reproducible?

* No `HMAC(HUK, "RPMB")`-style label strings, no derivation constants found in
  LK or preloader. LK's `sec_key_derive` symbol has no xref in this build.
* Preloader has `key_derive fails(0x%x)` + `[CC] not unique key, lcs=0x%x` +
  full EFUSE driver + HACC — consistent with MTK's standard model: secure-world
  (GenieZone TEE on this generation) derives per-purpose keys (RPMB, fde,
  huk-children) from efuse HUK/SCA material using HACC/MDP internals; preloader
  merely *consumes* the result via a GZ call ("gz rpmb_key").
* `rpmb_en:%d, rpmb_key:%d` in the preloader boot-params magic struct and the
  `update_rpmb_key_flag` persisted flag show provisioning is a **one-time
  first-boot flow**: if `rpmb_en && key not provisioned && keyprovision flag
  not set` → ask GZ for the key → `rpmb_authen_key_program` → mark flag. After
  that the key lives only in the eMMC/UFS controller and inside GZ.
* **Consequence for (a):** even if DA READ-EFUSE exposes HUK bytes, the
  derivation algorithm lives in the unanalyzed GenieZone image (and may also
  mix in per-device values like `efuse_Serial`). Reproducing host-side
  requires reversing GZ (`tee.img`/`gz` partition), not just reading efuses.
  *However* — see next-probe list: if the device's key was **never
  provisioned**, we don't need it at all (mtkclient `da rpmb` can program ours).

## Q4. Preloader RPMB provisioning path

Evidence (strings above) supports this flow, in file-offset clusters:

* 0x54e1f–0x54f05: `get enable rpmb flag` → `not enable rpmb` exit, or
  `keyprovision flag has been setted` exit, else "enter enable flow" →
  `update_rpmb_key_flag addr=0x%llx` (writes the persisted flag after
  programming).
* 0x53cca–0x53fdd: `rpmb_authen_key_program` → `RPMB Key has been written!` /
  `[PASS] Authentication Key Program Success`, with `has not been
  programmed!!`/`will be programmed!!` set-key-state probes (same strings also
  present in LK's mmc driver and in DA2).
* 0x50df2/0x546aa: "RPMB storage get key fail" — the key supplier is queried,
  not embedded.
* No 32-byte plaintext key blob was found near the RPMB code regions (the
  0x45e00–0x46000 literal-pool hits were ASCII text false positives; preloader
  is PIC and string refs are PC-relative, so no absolute key pointers were
  extractable — a limitation noted below).

## Q5. md1img.img

`strings -a | grep -i rpmb` → **zero hits**. Modem is out of the RPMB path.

## Next probes on device (ordered)

1. **Check key-provision state first** (cheapest, decisive):
   `mtkclient da rpmb ...` / DA2 `GET-RPMB-KEY-STATUS`. If "not programmed"
   → program our own key via DA and the whole mirror problem is solved; no
   derivation needed.
2. If already programmed: dump efuses via the OPLUS DA READ-EFUSE
   (cmd 0x40005a80) — target the HUK/SCA/serial banks referenced by preloader
   efuse code (`efuse_storage_read`, `efuse_Serial_verify` indices in LK) and
   the DAA/SBC fuses. If any bank reads as 0/locked (DFD disabled:
   `get_efuse_dfd_disabled`, `dfd_disable_efuse` in LK), HUK reads will
   likely be masked — check that first.
3. Extract **GenieZone/TEE images** (gz/tee partition) from a full dump and
   reverse the `rpmb_key` service (`gz rpmb_key` provider; look for the
   derivation: HACC/SHA + "system_rpmb_hmac" service name should appear there
   too). That is where an (a)-style algorithm, if any, lives.
4. Optional: at runtime, SNIFF the shm carveout at phys 0x48400000 during an
   LK RPMB op (with a patched LK not possible on-device — but with DA2
   `patch_mem`/heapbait the EL3 SMC 0xC2000414 request frame layout can be
   probed to enumerate other ops of the `vm_hmac` service, e.g. a key-export
   op if one exists).
5. Cross-check on an identically-built second unit whether RPMB reads of the
   boot-info block succeed with a *shared* key (would indicate (c) fixed
   platform key — cheap test if another devboard is available).

## Confidence summary

* **Proven (LK disasm):** device-type dispatch; dev1 path = frame build +
  SMC 0xC2000414 via `smc #0` wrapper 0x5001db88 with 0x11C-B frame in the
  registered "vm_hmac"/"system_rpmb_hmac-reserved" shm @ phys 0x48400000;
  nonce/HMAC compare after SMC; no key material in LK. dev2 = GP-TEE client.
* **Proven (strings):** preloader provisioning toolchain + GZ key supplier +
  keyprovision/update_rpmb_key_flag persistence; md1img clean.
* **Inference:** key derived from efuse HUK inside GZ (MTK standard practice,
  `key_derive fails` + `[CC] lcs` strings); retail unit already provisioned.
* **Limitation:** preloader load base unresolved (PIC; literal/adr scans
  found no consistent base), so preloader evidence is string-level only; no
  disassembly-verified preloader flow. A follow-up should locate the base
  (e.g., via the GFH headers / known SRAM entry for MT6789) before trusting
  any preloader VA.
