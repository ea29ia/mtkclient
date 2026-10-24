# RE: tee.img (Trustonic MTEE) RPMB ownership + efuse map (efuse.xml / Efuse.ini / efuse.img)

> **ERRATA (2026-10-24, audit #2):** (1) the tee load base **is resolved**:
> 0x05F00000 (`tee.img` body at 0x31660+0x440; the 0x05F00240 qword sits at
> segment-header +0x28) — `re-tbase-sfsrp.md` is right. (2) The LK boot-info
> mirror is at RPMB blocks **0x1DC–0x1DF**, not 0–3 — the "SFSRP must start at
> S≥4" reasoning is therefore void. (3) "TEE performs its own keyed RPMB" stays
> unresolved: no HMAC in the tee segment; the key may live in EL3/an external
> TLAPI driver. See `re-consistency-audit-2.md`.

Date: 2026-10-23. Targets: `docs/notes/rmx3630-lk/tee.img` (768816 B),
`/root/firmware/IMAGES/{efuse.xml,Efuse.ini,efuse.img}` (efuse.img/Efuse.ini
extracted from `RMX3630export_11_14.0.0.200EX01_2024090223460108.zip`).
Method: strings + container-header parse + targeted r2 disasm of DA2
(`da2_oplus.bin`, ARM32 @ 0x40000000). **No full tbase RE — load base of the tee
payload unresolved** (adrp/add xref scan produced no consistent base; see §1d).

Companions: `re-lk-rpmb-lock.md` (mirror block format), `re-lk-rpmb-key-derivation.md`,
`re-da2-rpmb-key.md`, `re-oplus-auth-paths.md`.

---

## Q1 — tee.img: format and RPMB ownership

### (d) Container format (proven at container level)

`tee.img` is an **MTK multi-segment TEE container** (same format as `gz.img`,
whose single segment is named `gz`). Structure, proven by byte inspection:

```
per-segment record:
  +0x00 u32 magic 0x58881688     ; segment header magic
  +0x04 u32 payload size
  +0x08 char name[16]            ; "atf" / "cert1" / "cert2" / "tee" / "gz"
  +0x28 u32 0xffffffff (uuid filler; cert1 uses 0x12345678)
  +0x30 inner header: u32 0x58881689, u32 0x200 (block size 512), u32 1, u32 0,
                      u32 0x1000 (align), u32 uuid/0
  then payload
```

Segments found in tee.img (offsets = file):

| off | name | size | content |
|---|---|---|---|
| 0x00000 | `atf` | 0x30588 | **EL3 monitor / ATF** (aarch64; `lib/el3_runtime/aarch64/context_mgmt.c`, `PANIC in EL3.`, MTK SIP handlers) |
| 0x30790 | `cert1` | 0x6c5 | cert blob |
| 0x31060 | `cert2` | 0x3f3 | cert blob |
| 0x31660 | `tee` | 0x89400 | **Trustonic t-base MTEE** (`MTK: t-base-MTK-A64O-Android-510a-V009-20220818_151637_48165_17ce0`, `[CR0] t-base-...`, `[STH2] 1.1, Build Aug 18 2022`) |
| 0xbac60 | `cert1` | 0x6c5 | cert blob (repeat) |
| 0xbb530 | `cert2` | 0x3f3 | cert blob (repeat) |

* Arch: **AArch64 for both payloads** (clean ADRP/ADD/STP decodes throughout;
  `com.trustonic.tee.isa.arm.aarch64` property string; "A64O" in build id).
  ARM32 TAs are supported at runtime (`isa.arm.armv7`/`aarch32` property strings).
* The `tee` segment header carries a nonzero qword at header+0x20 = **0x05F00240**
  (absent in the `atf` record) — plausibly the payload's load VA. **Inference,
  unverified** (all adrp/add xref scans failed to confirm any base; the 0x58881689
  inner header suggests per-segment relocation done by the loader).

### (a) Does this TEE do its OWN RPMB operations? — YES (proven, string-level)

The image contains **two independent secure RPMB stacks**:

1. **EL3/ATF side (the `atf` segment)** — the RPMB HMAC *service* that LK's
   `rpmb_read_direct` talks to (SMC 0xC2000414, shm `system_rpmb_hmac-reserved`
   @ phys 0x48400000, per `re-lk-rpmb-key-derivation.md` §Q1):
   * `plat/mediatek/drivers/ufs/ufs_ctrl.c` + `mmap rpmb hmac error.` /
     `mmap remove rpmb hmac error.` (file off 0x2a2c8/0x2a305)
   * SMC surface names: `MTK_SIP_BL_UFS_CONTROL`, `MTK_SIP_KERNEL_UFS_CONTROL`,
     `MTK_SIP_BL_MMC_CONTROL`, `MTK_SIP_KERNEL_MMC_CONTROL`, `mmc_remap_mmap`
     (0x2a282–0x2acce). "mmap rpmb hmac" = EL3 maps the caller's RPMB frame
     buffer so the secure side can HMAC it — this is the server side of LK's
     `vm_hmac` channel.
   * Correction to `re-lk-rpmb-key-derivation.md`: the EL3 HMAC service lives in
     **tee.img** (this ATF segment), **not** in gz.img — `strings gz.img | grep
     -i rpmb|hmac` = **zero hits** (gz.img is the GenieZone hypervisor proper,
     no RPMB code). (Inference on the exact serving layer EL3-vs-EL2-GZ: medium,
     but gz.img being clean is proven.)
2. **t-base MTEE side (the `tee` segment)** — Trustonic's own RPMB client:
   * `[SFSRP]` driver cluster (0xb3210–0xb35xx): `Error: failed to write to RPMB
     after %d attempts`, `Error: failure on block blk_num %d, err = 0x%08X`,
     `[SFSRP] ERROR Mismatch between the counters`, `[SFSRP] ERROR Read/Write
     error (0x%08x)` — a full authenticated RPMB read/write layer **inside the
     TEE**, keyed by the TEE-held RPMB auth key (SFS = Secure File System,
     trustedStorage).
   * `[SFSRP]ATF reports RPMB disabled : No Downgrade protection` +
     `[SFSRP]drApiPlatformControl failed(%d). act as downgrade protection active`
     — tbase asks the EL3 firmware (via drApiPlatformControl) whether RPMB is
     usable; the error path exists because normally it **is** enabled.
   * SFSL1/L2 sector cache + STH2 partition mount/format layer on top
     (`SFSL1AllocateSector`, `[STH2] Mounting partition %d...`,
     `Formatting partition %d...`).

So: **yes — the Trustonic TEE performs its own HMAC-authenticated RPMB reads AND
writes** (SFSRP), independent of the LK boot-info mirror path, plus it also
*serves* LK's mirror ops on the dev2/GP-TEE path. The RPMB key consumer set is
{ATF/EL3 HMAC service, tbase SFSRP} — matching the preloader's `gz rpmb_key`
provisioning picture.

### (b) `com.trustonic.trustedStorage.antiRollback.rpmbCfg`

Found twice: in the tbase property-name pool (0x581db, among
`com.trustonic.tee.*` / `gpd.tee.*` property keys — this is the getProperty
registry exposed to TAs) and again directly in the SFSRP string cluster
(0xb3408, immediately before `[SFSRP]ATF reports RPMB disabled`).

Verdict (**inference, string-level**): it is a **configuration/property key
selecting RPMB as the backend for trustedStorage anti-rollback** (downgrade
protection) — i.e. the anti-rollback version/counter state for the SFS
"trustedStorage" partitions is kept in RPMB, protected by the hardware RPMB
*write counter* (consistent with `[SFSRP] ERROR Mismatch between the counters`:
stored counter vs device RPMB write-counter check). It is **not** a data blob
stored in the image — only the property *name* exists here; no literal value
blob was found near either occurrence. `gpd.tee.trustedStorage.antiRollback.
protectionLevel` (0x582aa) is the exposed GPD property reporting the achieved
level. So: **RPMB-stored anti-rollback config/state: yes, that is what the
string indicates; exact on-flash layout: unresolved.**

### (c) Sector-ownership map / overlap risk with the boot-info mirror

Known (proven from LK/ATF side):

| consumer | RPMB area | evidence |
|---|---|---|
| LK boot-info mirror | **sectors 0–3** (block addr 0, one 0x400 read/write, cmd 0x1DC / dev1 shm) | `re-lk-rpmb-lock.md` §1/§3/§4 (proven) |
| tbase SFSRP (trustedStorage) | own SFS partitions somewhere in RPMB, **start sector not resolved** | SFSRP string cluster only |

**Unresolved, flagged as the key risk:** the SFSRP strings never state a start
sector; the RPMB block layer prints `blk_num %d` but the load base of the tee
segment could not be pinned down (§1d), so the block-number constants feeding it
could not be read out of the code. Known Trustonic SFS-on-RPMB deployments
 typically format the SFS superblock at the start of *their configured RPMB
window* — and the `rpmbCfg` property (b) is exactly the kind of knob that would
carry that window. Two scenarios:

1. **SFS window starts at sector ≥ 4** (platform config reserves 0–3 for the
   LK mirror — MTK's `mcConfig`/platform glue normally carves this): mirror
   rewrite is safe w.r.t. Trustonic state. *(inference)*
2. **SFS owns sector 0–3 too** (SFS formatted from block 0 and LK mirror layered
   on top / vice versa): rewriting the mirror (or the "write garbage" variant of
   `re-lk-rpmb-lock.md` §9) would corrupt SFS → `[STH2] ERROR Partition %d is
   corrupted` / reformat loops, and `[SFSRP] ERROR Mismatch between the counters`
   on every boot. *(inference)*

**Mandatory on-device check before any mirror write (ordered):**
1. `da rpmb r` sectors 0..~0x20 and look for SFS signatures (SFS superblock /
   `SFSRP`-style headers / plausible sector-allocation tables) outside the
   known mirror layout at 0x0–0x3FF. Mirror bytes are +0x0/+0x4/+0x8/+0xC/+0x10
   + SHA-256 at +0x3E0 — anything else nonzero/structured nearby is SFS.
2. Watch the boot log for `[SFSRP]`/`[STH2]`/`SFSL1` lines after a mirror
   experiment — any SFS complaint = overlap confirmed, restore mirror.
3. Note SFSRP **writes** on every storage flush; DA-side read of RPMB while the
   device is running is racing the TEE — do reads with the AP quiesced (DA mode).

Bottom line: **overlap is possible and unproven either way; treat sectors 0–3 as
potentially shared until the empirical dump says otherwise.** The mirror rewrite
plan (re-lk-rpmb-lock.md §9) keeps its single hard blocker: the RPMB auth key.

---

## Q2 — efuse map (MT6789)

### efuse.xml (proven parse)

Flash-tool (SP-style) efuse config, `chip-name MT6789`, `storage-type UFS`.
It is **semantic only — no byte/bit offsets** are given anywhere in the file.
Header magic keys `key1=756c706f` `key2=74726563` = ASCII **"ulpotrec"** —
identical to the first 8 bytes of `efuse.img` (so efuse.img carries the
matching magic; "cert-oplu(i)-re(c)" — an OPLUS cert/efuse marker; inference
on the exact intended reading).

| field group | xml keys | purpose | state in XML |
|---|---|---|---|
| magic-key | key1/key2 | efuse-image header magic | 0x756c706f / 0x74726563 |
| common-ctrl | Disable_NAND_boot_speedup, Disable_UFS_boot, USB_download_type, Disable_NAND_boot, Disable_EMMC_boot | boot-mode control fuses | all false/0 |
| **secure-ctrl** | Disable_DBGPORT_LOCK, Enable_SW_JTAG_CON(**true**), Enable_ACC(false), Enable_ACK(false), **Enable_SLA(false)**, **Enable_DAA(true)**, **Enable_SBC(true)**, Disable_JTAG(false) | security-control word bits | **SBC + DAA blown; SLA/ACC/ACK not** |
| **sbc-pub-key** | key-type **pss**, pub-key-e 010001, pub-key-n (256 B = **RSA-2048 modulus**) | verified-boot public key fused into efuse | present (see hash test below) |
| common-lock | com_ctrl_lock, usb_id_lock | lock bits | false |
| secure-lock | custk_lock, sec_msc_lock, sec_attr_lock, ackey_lock, sbc_pubk_hash_lock | lock bits | all false |
| usb-id | vid/pid 0000 | USB ID override | unset |
| sec_msc | md1_sbc_en, c2k_sbc_en | modem SBC | false |
| c_lock / c_ctrl0-1 / c_data0-5 | 8 custom words + locks ("run_time_blowing_config" bypass flags) | customer ctrl/data words | values commented out |
| ac-key | 16 B (commented out) | ACCredit key | unset |
| custk | 16 B (commented out) | CUSTomer Key | unset |
| cm_flag | Enable_kcust | custom-key enable flag | false |
| read-back | dir/name | dump target | — |

RSA-2048 SBC pubkey: `n = B6E0D492…8604D` (256 B), e=0x10001, PKCS#1 **PSS**
(matches preloader's SHA-384/PSS cert-chain strings). Test performed:
SHA-256(n BE) and SHA-256(n LE) both **≠** any nonzero blob in efuse.img (so the
sbc_pubk_hash is not what efuse.img carries, or it's hashed in a different
encoding — e.g. with DER prefix/lengths; unresolved, low value).

Corroborations: Enable_SBC/Enable_DAA=true matches LK/preloader/DA2 findings
(`sbc_en = 1`, `efuse_value is %d, sbc_enable is %d, daa_enable is %d`,
img_auth_required). Enable_SW_JTAG_CON=true — SW JTAG console fuse is the one
debug-ish fuse set.

### Efuse.ini (proven parse)

```
Enable=1, SettingsEnable=0, LockEnable=0, ReadBackEnable=0
EfuseXmlPath=efuse.xml, EfuseImage=efuse.img, auth_sv5Path=auth_sv5.auth, daa_open=1
```
Flash-tool-side switchboard; nothing crypto-bearing. (`daa_open=1` = DA auth
required — consistent with DAA blown.)

### efuse.img (512 B — NOT a zero template; proven byte-level)

```
0x000  "ulpotrec"                      ; magic = xml magic-key1+key2 (proven match)
0x008  zeros
0x01c  u32 0x19084feb
0x020  47f6d87d 98f8be37 b1b5b35d 2a149932 4d2b7aa4 3808acfb 6b029b35  (28 B)
0x03c  00000000                        ; 0x1c..0x40 = 36-byte nonzero blob
0x040..0x06f  zeros
0x070  u32 0x00000046                  ; = 70 (word idx 28)
0x074..0x1df  zeros
0x1e0  32 B = SHA-256(bytes 0x000..0x1e0)   ; integrity trailer (verified match)
```

So the image contains a **pre-provisioned 32/36-byte secret-looking blob at
0x1c–0x40** (word indices 7–15), a lone word **0x46 at 0x70 (word 28)**, and a
SHA-256 trailer. It is a record of already-blown efuse content, not a blank
template. Purpose of the 32-byte blob: **unresolved** — size/entropy fits a
per-device key (OPLUS factory key / device-ID seed); it is *not* the SBC pubkey
hash (tested above); it is not ac-key/custk (those are 16 B). **Inference:
factory-provisioned device-unique key material.**

### DA2 READ-EFUSE whitelist (proven, disasm `da2_oplus.bin`)

Whitelist check `0x40039ca0` compares the requested efuse word id against a
table at **0x40056e5c** (17 entries; miss ⇒ 0xC0020039):

```
0x00, 0x1f, 0x0c, 0x0d, 0x0e, 0x0f, 0x37, 0x38, 0x39, 0x3a,
0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46
```

Callers (BL xref, 3 sites):
* `0x40039e74` (GET-HW-INFO chain 0x4002ba0c →): reads **ids 0xC,0xD,0xE,0xF**
  (16 bytes), SHA-256 over them (`0x4003a2d4`), formats
  `"%08x%08x%08x%08x"` → this is the `<random_id>` field of the GET-HW-INFO
  XML. ⇒ **words 0xC–0xF = a 16-byte device-unique ID, deliberately host-visible**
  (it is printed to the host in every GET-HW-INFO reply). Not secret key
  material by construction.
* `0x40032bf8`: loop probing ids `x+0x3f` … (`0x46` range) with popcount-style
  result — reads the 0x37–0x46 block as **flag/status words** (read-only device
  info; matches re-oplus-auth-paths.md §5 note).
* `0x4003512c`: id taken from a descriptor table — same read-only family.
* `0x1f` = SBC word: `get_hw_sbc 0x40039d00` does `efuse_read(0x1f)`, `ubfx r0,
  r0, 1, 1` → **SBC-enable is bit 1 of word 0x1f** (proven).

### Word-offset map (as far as evidenced)

Byte offset = word id × 4 (MTK convention; **inference** — no MT6789 offset
table available in-repo):

| word id(s) | bytes | content / role | source |
|---|---|---|---|
| 7–15 | 0x1c–0x40 | 32-B provisioned blob (see efuse.img) — words 12–15 = ids **0xC–0xF** = "random_id" source, host-readable | efuse.img + DA2 disasm |
| 0x1f | 0x7c | SBC control, **bit1 = SBC enable** | DA2 disasm (proven) |
| 0x37–0x46 | 0xdc–0x11b | 16 read-only device-info/flag words (readable via DA) | DA2 whitelist (proven), semantics unresolved |
| — | — | everything else (SLA/DAA keys, custk, ackey, sbc_pubk_hash, **SEC_KEY/HUK**) | NOT in whitelist |

`efuse.xml` names vs word ids could not be aligned (no offsets in the XML).
No field named `huk`/`sec_key`/`seal`/`scs` exists in the XML; the "secureRO"-
and accdet-flavored names from the mission prompt do not appear either — the
XML's key-ish fields are only `ac-key`/`custk` (both unblown/unset in this XML)
and the SBC pubkey.

### HUK verdict

* **No HUK/SEC_KEY material is readable via the DA2 READ-EFUSE whitelist.**
  The whitelist exposes exactly: word 0, word 0x1f (SBC bit), words 0xC–0xF
  (device-unique "random_id", already handed to the host in GET-HW-INFO), and
  words 0x37–0x46 (device-info flags). None of these is secret-derived key
  material: 0xC–0xF is *printed in the XML to the host by design*, so it cannot
  double as the HUK input.
* The 32-byte blob at efuse.img 0x1c–0x40 (words 7–15) partially overlaps the
  whitelist (words 12–15) — but those words are the random_id itself; the
  interesting part (words 7–11, 0x1c–0x30) is **outside** the whitelist.
* efuse.xml/Efuse.ini confirm no HUK field is even *addressable* by the flash
  tool on MT6789.
* ⇒ Consistent with `re-lk-rpmb-key-derivation.md`: the efuse-HUK→RPMB-key
  derivation happens inside the secure world (t-base MTEE / EL3 glue in
  tee.img), **and the HUK input cannot be exfiltrated host-side via DA READ-EFUSE.**
  Host-side derivation attempts are dead; the viable routes remain (1) DA2 RAM
  key dump (re-da2-rpmb-key.md §6 — the *derived* RPMB key, not the HUK), or
  (2) reversing the tee.img `tee` segment (MTEE) `rpmb_key`/SFSRP derivation.
* Note: even a full HUK leak would not be sufficient without the GZ/MTEE
  derivation algorithm; and conversely the DA2 RAM dump yields the final key
  directly, making the HUK question moot for the unlock goal.

---

## Confidence

* **Proven (container/header/strings/disasm):** tee.img segment layout & names
  (atf/cert1/cert2/tee, magic 0x58881688/0x58881689); AArch64 arch; MTEE build id;
  ATF-side `mmap rpmb hmac` + MTK_SIP_*_UFS/MMC_CONTROL surface; tbase SFSRP
  RPMB read/write/counter strings; `antiRollback.rpmbCfg` is a property key;
  gz.img contains zero RPMB strings; efuse.xml/Efuse.ini contents; efuse.img
  byte map incl. SHA-256 trailer; DA2 efuse whitelist table + the 0xC–0xF →
  SHA-256 → `%08x%08x%08x%08x` `random_id` chain; word 0x1f bit1 = SBC.
* **Inference:** 0x05F00240 = tee payload load VA; SFSRP anti-rollback = RPMB
  write-counter-backed; rpmbCfg semantics; SFS RPMB window placement (both
  scenarios) and the whole sector-overlap question; byte-offset=word×4 mapping;
  the purpose of the efuse.img 32-byte blob; magic reading "oplus-cert".
* **Unresolved / next probes:** SFSRP start sector (needs either tbase base
  resolution + disasm of the RPMB block layer, or the on-device RPMB dump of
  §1c); meaning of words 0x37–0x46; exact SBC-pubkey-hash encoding.
