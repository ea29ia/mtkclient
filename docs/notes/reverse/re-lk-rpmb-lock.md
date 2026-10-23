# RE: LK RPMB lock mirror on RMX3630 (MT6789) — double_check_lock_state, its writer, and the DA2 path to a persistent unlock

Date: 2026-10-23. Target: `docs/notes/rmx3630-lk/lk.img` payload (`lk`, file off 0x200,
size 0xE4600). Method: `dd` payload → `lk_payload.bin`, analyzed with
`r2 -a arm -b 64 -m 0x50000000` (VA = payload offset + 0x50000000, per
`re-lk-seccfg.md`). Companion: `re-lk-seccfg.md`, `re-heapbait-vuln.md`,
`rmx3630-da2/README.md`.

## TL;DR

1. **`double_check_lock_state` (0x500556C4) has exactly one enforcement branch**
   (RPMB mirror field @block+0xC == 1 → force seccfg re-lock + power-off) and
   **three no-action exits** (RPMB read failure; hash mismatch; mirror != 1).
   Crucially, **a hash mismatch is treated as SUCCESS**: LK memsets the 0x400
   buffer to zero and returns 0, so the mirror reads 0 and the unlock stands.
2. **The hash over the RPMB boot-info block is plain software SHA-256** over
   bytes [0x0,0x3E0), stored at +0x3E0 (0x20 B). **Not HACC-scrambled, not
   device-keyed — fully reproducible host-side.** The only secret in the RPMB
   path is the eMMC RPMB auth key (HMAC of the frames), which lives in the
   eMMC/TEE, not in LK.
3. **The mirror is written by LK itself, every boot** (`set_boot_info_to_rpmb`
   0x50054744, called at the end of `sec_boot_init` and after a fastboot
   unlock), via the TEE RPMB write op (cmd 0x1DC). It compares the freshly
   computed hash against the stored one and only writes when they differ. So
   after one successful unlocked boot, **LK maintains an "unlocked" mirror
   itself**.
4. **DA2 verdict: full RPMB capability exists in `da2_oplus.bin`** (key
   program, read counter, authenticated read/write, "rpmb_hmac",
   `GET-RPMB-KEY-STATUS`/`RPMB-KEY-STATUS` host commands; mtkclient even ships
   `da rpmb r/w/e/a` including `auth_rpmb(host_key)`). **But** an
   already-provisioned device only accepts frames HMAC'd with the factory
   RPMB key — the DA cannot forge writes without it. If the key were never
   programmed (or on a unit where we may program it first), the DA can
   program/use our own key and then write the mirror freely.
5. **LK patchability verdict: dead on-device.** Preloader authenticates LK with
   a cert chain (`cert chain vfy fail`, `%s img: %s cert vfy(%d ms)`,
   `seclib_img_auth_load_sig`, SHA-384 / PKCS#1 PSS strings, `img_auth_required`)
   — a patched LK partition fails preloader verification and the device will
   not boot LK.
6. **No boot-mode bypass.** `double_check_lock_state` has exactly one caller
   (0x500026B8 inside `sec_boot_init` 0x5000262C, called unconditionally from
   the bootstrap at 0x5000E270); it is gated **only** on
   `sec_cfg_get_lock_state()==3`. No factory/FTM/META gate found around it.

**Practical conclusion:** forge seccfg lock_state=3 with a valid HACC(SHA256)
digest (per `re-lk-seccfg.md`) **and** make the RPMB mirror read ≠1 at the next
boot. The mirror currently reads 1 (locked), and fixing it needs one
authenticated RPMB write (key-gated) — but it needs to happen **only once**:
the moment an unlocked boot completes, LK rewrites the mirror as unlocked with
a valid hash by itself. If the RPMB key can be obtained (or the device's RPMB
key is not yet programmed), the whole sequence is: write mirror block with
field+0xC=0 + valid SHA-256, write forged seccfg, reboot → persistent unlock.

---

## 1. `km_client_read_rpmb_boot_info` (0x50054674) — full branch map (proven)

```
0x50054674  km_client_read_rpmb_boot_info(char *buf /*0x400*/):
  zero [sp..sp+0x20] status vars
  st = rpmb_get_device_type()          ; 0x50055570
       ── 0x50074f54 "rpmb enable" check:
            looks up RPMB dev by name (0x50069a88, string @0x500a06bd),
            dev missing -> print "Partition [preloader_a] is not exist."
            (0x500b6b95, log-only) — and returns 1 ANYWAY (hardcoded w8=1)
  switch (st):
    case 1:  st = rpmb_read_direct(buf, 0x1DC, 0x400, &status)   ; 0x5002fd14
    case 2:  st = rpmb_read_via_tee (buf, 0x1DC, 0x400, &status) ; 0x5003e4e4
             ; retry once after 0xA120 ms sleep on failure (0x5006a7dc)
    default: print "ERROR read storage failed unknown device: %d"
             return -1                                            ; [BR-1]
  if (st != 0) return st                                          ; [BR-2]
  if (rpmb_read(buf, 0x3E0, sp) != 0)     ; 0x50055508
      print "get sha256 fail, status = %d" (0x500acc50)
      print "km_client_read_rpmb_boot_info: hash error" (0x500ac993)
      return -1                                                    ; [BR-3]
  if (SHA256(buf, 0x3E0) != buf[0x3E0..0x400])   ; 0x50055364 → 0x5006c990
      print "km_client_read_rpmb_boot_info: hash error" (0x500ac9be)
      memset(buf, 0, 0x400)                        ; 0x50055368 → 0x5006cbc4
      return 0                                     ; ← SUCCESS!    ; [BR-4]
  print "km_client_read_rpmb_boot_info: last_bootmode:%d"  ; buf+8
  return 0                                                        ; [BR-5]
```

* 0x50055364/68/60 are thunks to `0x5006c990` (memcmp-0x20/compare),
  `0x5006cbc4` (memset — same function double_check uses for its own buffer),
  `0x5006c9c8` (memcpy 0x20).
* The SHA-256 core is at 0x5008B4DC (init, K-table at 0x500BC9F0, IV constants
  6A09E667… identical to the seccfg hasher) + 0x5008B534 (update) +
  0x5008B718 (final). Plain software SHA-256. **No HACC, no device key.**
* **[BR-4] is the soft spot:** a corrupted/garbage boot-info block does not
  fail the read — it zeroes the caller's buffer and reports success. The
  caller then reads mirror field 0x00000000.

## 2. `double_check_lock_state` (0x500556C4) — full branch map (proven)

252 bytes, 0x500556C4–0x500557C0 (tail runs into the known power-off block).

```
0x500556C4  double_check_lock_state(int *out):
  memset(sp, 0, 0x400)
  st = km_client_read_rpmb_boot_info(sp)                    ; 0x500556F0
  if (st != 0):                                             ; [DC-1] NO ACTION
      print "%s: get_rpmb_lock_state: read boot info from rpmb fail status = %d"
      print "%s: rpmb not enable or get_rpmb_lock_state failed status=%d !!!"
      goto TAIL                                              ; seccfg stands
  mirror = *(u32*)(sp + 0xC)
  if (mirror == 1):                                         ; [DC-2] ENFORCE
      print "%s: seccfg_lock_state is 0, rpmb_lock_state is %d, so need change seccfg state"
      *out = 0                                              ; 0x50055780
      sec_cfg_set_lock_state_wrapper(1)                     ; 0x50082E88(1)
        ; per re-lk-seccfg.md: cur==1 → seccfg=2, else seccfg=4 (locked values)
      if failed: print "%s: sec_set_device_lock, change seccfg lock state failed !!!"
      print "%s rebooting the device"
      → power-off block 0x500557C0: LED/key setup (0x5001FBE0(1,7)),
        "verify boot fail, it will power off!" (0x500ACEEF), mdelay(0x2DC6C0), off
  else:                                                     ; [DC-3] NO ACTION
      print "%s: seccfg_lock_state is the same as rpmb_lock_state. It will do
             nothing and boot normal."                       ; 0x5005573C
  TAIL: return
```

Important consequence of [BR-4]+[DC-3]:

* **Hash-mismatch path: mirror = 0 → branch [DC-3] → no re-lock → boot
  continues UNLOCKED.** The "hash error" line will appear in the LK log, and
  `sec_boot_init` will then *rewrite* the mirror (see §3) with the new state
  and a valid hash — i.e. a single corruption of the RPMB boot-info block
  permanently converts the mirror to "unlocked" on the very next boot.
* **Read-failure path [DC-1]:** identical outcome (log-only). Note the "rpmb
  enable" probe (0x50074F54) *always* returns 1 in this build (it even
  hardcodes w8=1 before checking partition existence), so the "rpmb not
  enable" wording is misleading — the only way into [DC-1] is a real read
  error from 0x5002FD14/0x5003E4E4.

## 3. Who writes the mirror — `set_boot_info_to_rpmb` (0x50054744) (proven)

Called from exactly two sites (xref scan):
* **0x500026E4** — end of `sec_boot_init`, every boot.
* **0x500078E8** — fastboot unlock-commit flow, `set_boot_info_to_rpmb(1, 1)`
  (sboot=1, flag=1 → mirror=0 "unlocked") followed by reboot plumbing
  (0x50055B00/0x50007910). This is the legitimate `flashing unlock` path
  updating the mirror **before** rebooting — the mirror is an LK-side
  artifact, not written by DA2 flash ops or only by TEE.

```
0x50054744  set_boot_info_to_rpmb(u32 sboot, u32 flag):
  memset(block, 0, 0x400)
  locked_bit  = (flag == 0) ? 1 : 0          ; w22 → stored at block+0xC
  sbc_bit     = sboot & 1                    ; w21 → block+0x0
  dev_info    = get_dev_info() & 0xFF        ; 0x5005536C → 0x500036C0 → block+0x4
  aux         = (sboot&1)==0 && flag!=0 ? anti-rollback checks (0x50055414,
                0x500553A0: requires dev_info==4) : 0/1/2   ; → block+0x10
  (fill remaining fields via 0x5005544C / 0x50055484, boot_mode etc.; block+8
   = boot_mode, printed back as "last_bootmode" on read)
  if (km_client_read_rpmb_boot_info(block) == 0):        ; read current
      write fields into block (block+0x0 sbc_bit, +0x4 dev_info,
        +0xC locked_bit, +0x10 aux, +0x14 w20, +0x18/0x1C zeros)
      SHA256(block, 0x3E0) vs block[0x3E0..0x400]:
      if EQUAL: "hash is the same, dont need write data to rpmb." → done
      else:     0x50055630 = RPMB WRITE, cmd 0x1DC
                dev 1 → 0x50030120, dev 2 → 0x5003E91C (TEE), else
                "ERROR write storage failed unknown device: %d"
                fail → "updata boot info to rpmb fail, status = %d"
```

Semantics proven from both call sites:

| caller | flag arg | written mirror (+0xC) |
|---|---|---|
| `sec_boot_init`, locked boot (state≠3, double_check skipped) | 0 | **1 (locked)** |
| `sec_boot_init`, unlocked boot, RPMB says not-locked | 1 (preset) | **0 (unlocked)** |
| `sec_boot_init`, RPMB forced re-lock ([DC-2]) | 0 | **1 (locked)** |
| fastboot unlock commit (0x500078E8) | 1 | **0 (unlocked)** |

So mirror+0xC == 1 ⇔ "device was locked at last write". (This resolves the
uncertainty flagged in `re-lk-seccfg.md` §8: the field is a 0/1 locked-bit,
written as `(flag==0)?1:0`.)

## 4. RPMB boot-info block format (proven)

* Size 0x400 (one 256 B-sector-pair… actually 1024 B = 2 RPMB frames' worth
  of data, read as one request, cmd 0x1DC, size 0x400).
* Bytes [0x0,0x3E0): payload. Fields: +0x0 sbc_bit(1/0), +0x4 dev_info,
  **+0x8 last_bootmode**, **+0xC locked bit (1=locked, 0=unlocked)**,
  +0x10 aux/anti-rollback, +0x14 …, tail zeroed.
* Bytes [0x3E0,0x400): **plain SHA-256 of [0x0,0x3E0)**. Software SHA-256,
  constant IV, no HACC, no device key → **any host can compute it.**
* Frame-level security is the standard eMMC/UFS RPMB HMAC (DA2 strings:
  `rpmb_hmac error`, nonce/wr-counter handling) — that MAC is keyed by the
  RPMB auth key programmed into the storage device; LK itself never touches
  it (TEE does, op 0x1DC).

## 5. DA2 RPMB capability (rmx3630-da2/da2_oplus.bin) (proven strings, inference on exploitability)

Strings found (`strings -a`): `mmc rpmb`, `mmc_rpmb_set_key`,
`rpmb_authen_key_program`, `rpmb_authen_read_counter`,
`rpmb_authen_secure_write_protect_conf_block_read/check/write`,
`rpmb_ufs_set_wp/clr_wp`, `ufs_rpmb_pre_nonce`, `rpmb_hmac error`,
`rpmb key is already programmed!!` / `has not been programmed!!` /
`will be programmed!!`, host commands `GET-RPMB-KEY-STATUS` / `RPMB-KEY-STATUS`,
and `<rpmb_size>` in the DA hw-info XML. mtkclient additionally ships a
DA-extension RPMB implementation (`da rpmb r/w/e/a`; `auth_rpmb(key)` passes a
**host-supplied** key into the patched-in `mmc_rpmb_send_command` stub found
via the `44 44 44 44` markers).

Verdict:
* **DA2 can talk raw RPMB frames (read freely; write only with a valid HMAC).**
* If the RPMB key is **already programmed** (expected on a retail RMX3630 —
  TEE provisions it), forged writes are rejected by the eMMC controller; the
  DA has no bypass (the MAC is checked inside the storage device).
* If the key is **not programmed** (or on units where programming is allowed),
  the DA can program a key of our choice and then read/write RPMB at will —
  the mirror becomes fully ours.
* With heapbait/patch_mem we control DA2 code, so *if* the key is
  extractable (TEE-side or derived), the write is achievable. Key
  extraction from TEE is out of scope here — **inference: the write itself is
  gated solely on possessing the auth key.**

## 6. LK patchability (DIRECTION 2.4) (proven strings; severity inference)

`preloader_k6789v1_64.bin` (390,868 B, present at
`/root/firmware/IMAGES/`) contains:
`[%s] img_auth_required = %x`, `[%s] cert chain vfy fail...`,
`[%s] cert verify, part = %s, img = %s...`, `[%s] dump (imghdr + image) hash...`,
`seclib_img_auth_load_sig`, SHA-384/PKCS#1-PSS strings, `Error: Img hash is
incorrect`, `[%s] part: %s img: %s vfy(%d ms)`, `off_lk/sz_lk/lk_flag`,
`lk partition not found`, `boot to LK by ATAG`.

Verdict: **preloader authenticates LK from flash with the MTK cert chain
(DAA-style, SHA-384-RSA-PSS) whenever img_auth_required is set (retail: yes,
sbc/DAA fuses blown — inference). A patched LK partition will be rejected and
the device will not boot. Direction 2 (patch LK on flash) is dead on-device.**
(Host-side analysis/emulation of patched LK remains fine.)

## 7. Bypass via boot mode? (DIRECTION 2.5)

* `double_check_lock_state` has **one** call site (0x500026B8), inside
  `sec_boot_init`, which the bootstrap (0x5000E270) calls unconditionally
  before boot-mode dispatch. Gate is only `seccfg state == 3`.
* Factory/FTM surface exists (`oplusboot.mode=factory`, `oplus_ftm_mode=factory1`,
  `sec_is_in_factory`, META strings) but no reference from the
  seccfg/RPMB code path; nothing in sec_boot_init consults boot mode. **No
  bypass found.**
* The wrapper 0x50082E10 proven: `*out = (lock_state != 3)` — double_check
  runs exactly when seccfg == 3.

## 8. Q6: seccfg=3 with mirror not-locked / absent (proven)

Traced: mirror != 1 → [DC-3] log + return → `sec_boot_init` continues with
`*out`/flag = 1 → prints `sboot_state is %d, lock_state is %d, isunlocked is
%d` with the unlocked state → boots normally unlocked → then rewrites the
mirror as unlocked (§3). Read-failure and hash-mismatch behave identically.
**Yes: seccfg=3 + mirror(0 or unreadable) = unlocked boot, permanently
self-maintaining afterwards.**

## 9. Practical sequence (what DA2-side operations yield persistent unlock)

Given DA2 write access + heapbait patch_mem:

1. **Forge seccfg** lock_state=3 with a valid `HACC(SHA256(hdr))` digest
   (method per `re-lk-seccfg.md` — digest is host-computable, fixed HACC
   seeds). *Presumed doable — prior campaign already writes seccfg.*
2. **Neutralize the RPMB mirror (one time).** Options, in order of realism:
   a. Read RPMB block 0 (`da rpmb r`): if field +0xC ≠ 1 already — nothing to
      do; reboot and done.
   b. If +0xC == 1: authenticated write of a 0x400 block with +0xC=0 and a
      correct plain SHA-256 at +0x3E0 (format in §4). Requires the device
      RPMB key (`da rpmb a <key>` then `da rpmb w`). If the key is not
      obtainable and RPMB was never keyed, program ours first
      (`custom_rpmb_prog`). *Gated on key possession — the single hard
      blocker.*
   c. Alternatively write *garbage* through the same authenticated channel —
      any hash-breaking write triggers [BR-4] → mirror=0 → [DC-3] pass, and
      LK then rewrites a clean unlocked mirror itself. Same key requirement.
3. **Reboot.** `double_check_lock_state` sees mirror 0 (or a failed/mismatched
   read) → no action → boot proceeds unlocked; `set_boot_info_to_rpmb`
   persists the unlocked mirror with a valid hash. From then on the state is
   stable without further DA access.

If the RPMB key cannot be obtained, **no** DA2-side seccfg-only forge survives
reboot on this build: the check itself cannot be skipped (single unconditional
call site, preloader-verified LK), and the mirror cannot be edited without the
key.

## 10. Confidence

* **Proven (disassembly):** both branch maps (§1, §2), memset-on-hash-mismatch
  (0x50055368 → 0x5006CBC4 = the same memset double_check uses), plain
  software SHA-256 (0x5008B4DC family, standard IV/K-table), mirror writer
  call sites and semantics, mirror bit meaning (1=locked), block layout,
  preloader cert-chain verification strings, single caller of
  double_check_lock_state, `*out=(state!=3)` wrapper.
* **Inference:** device RPMB key is already programmed on retail units
  (standard TEE provisioning); img_auth_required active on this retail unit
  (DAA/SBC fuses blown); exact contents of RPMB fields beyond +0x0/+0x4/+0x8/
  +0xC/+0x10 (filled by helpers 0x5005544C/0x50055484, not fully traced);
  which TEE app serves op 0x1DC (matched by command id only).
