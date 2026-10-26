# RE: Preloader DAA mystery, LK verification gate, rpmb_en flags (RMX3630 / MT6789)

Date: 2026-10-23. Targets: `IMAGES/preloader_k6789v1_64.bin` (390868 B, ARM32/Thumb, PIC),
`IMAGES/preloader_raw.img` (**md5-identical** to the .bin: `8a320d0eb0002acd09762778ac5eff99` —
no separate analysis needed), `MTK_AllInOne_DA.bin`, `download_agent/DA_BR.bin` (extracted from
`RMX3630export_11_14.0.0.200EX01_2024090223460108.zip` to `/tmp/opencode/da/`).

## Load base — RESOLVED (new result, supersedes the "base unresolved" limitation of
`re-lk-rpmb-key-derivation.md`)

**VA = file_offset + 0x200F10** (proven, not inferred): brute-forcing candidate bases
`B = literal_word − string_offset` over all string offsets found **1856 literals** consistent
with B = 0x200F10 (next-best candidate: 89). All preloader addresses below are VAs
(file offset = VA − 0x200F10). Disassembly: `r2 -m 0x200f10 -a arm -b 16`.

Header (GFH, "MMM" magic @0): FILE_INFO v1, sig_type≠0, total size 0x5F6D4 — consistent
with a ~0x200000-based SRAM load at 0x200F10.

## Q1 — DAA mystery: WHY DA_BR's DA1 passes, AllInOne's DA1 gets 0x7024

### VERDICT (proven by byte diff): **the AllInOne DA ships UNSIGNED — its 256-byte signature
trailer is all zeros.** Key-rotation hypothesis is unnecessary and wrong for this failure.

Evidence:

1. Container headers of `MTK_AllInOne_DA.bin` and `DA_BR.bin` are **identical**
   (`MTK_DOWNLOAD_AGENT` / `MTK_DA_v6_2024-09-02 22:21:09`, version 1, magic 0x22668899,
   hwcode `dada 0812` = 0x1208, same entry table: DA1 @0xBC size 0x689FC, DA2 @0x68AB8
   size 0x56FC8, DA1 entry 0x200000, DA2 entry 0x40000000). DA_BR is the same container
   format — parsed, DA1 extracted at 0xBC/0x689FC as assumed.
2. `da1_allinone.bin` vs `da1_dabr.bin` (both 428540 B): **exactly one differing range —
   file 0x688FC–0x689FF (256 B, the RSA signature trailer)**:
   - DA_BR: random-looking signature, e.g. `629d 6113 920b bdb4 c8ef dd16 acb0 a54b …`
     (254 nonzero bytes, first and last byte zero).
   - AllInOne: **`0000 0000 …` — all 256 bytes zero.**
3. `da2_allinone.bin` vs `da2_dabr.bin` (356296 B each): identical except file
   0x56F40–0x56FF7 (254 B of the 256-B trailer; 2 incidental zero-equal bytes). DA_BR's
   DA2 tail is signed, AllInOne's is zero.
4. So both DAs contain **the same code bytes**; only the DA_BR copies carry a valid RSA
   signature blob.

Preloader-side DAA verification (download.c, `usbdl vfy da` state machine, VA ~0x2081F4):

| VA | what |
|---|---|
| 0x208626 | DA size ≤ 0x100000 check (else err 0x1D10) |
| 0x23E8F8 | key-material selector (sec_auth.c): DA-declared key size 0x100/0x180/0x200 → memcpy from built-in blobs at **0x2F96A8 / 0x2F97A8 / 0x2F9928** (preloader .data; RSA-2048/3072/4096 sizes), sets `done` flag 0x2F9B28=1 |
| 0x23F1A6+ | SHA-256 update wrappers (0x20-byte chunk loop over received DA) |
| 0x208666–0x20867E | compare (memcmp 0x23780C) of computed hash/sig → mismatch: `movw r0, 0x7024` (0x20867E) |
| 0x208620→0x208632 | `bl 0x237820` (sec_auth.c:66, key check via 0x23E8F8 against *(0x25E1EC), 0x100 B) ≠ 0 → `movw r0, 0x7024` |
| 0x2086CC | success path: `*(0x2F3158) = 1` (DAA-verified flag) |
| 0x20856C | `usbdl_jump_da`: if `*(0x2F3158) != 1` → `movw r0, 0x7024` ("DAA_SIG_VERIFY_FAILED") |

Also: `usbdl_verify_da: da_len (0x%x) is less than sig_len (0x%x)` (string 0x2475C8) —
the preloader explicitly expects a signature trailer of nonzero length.

Conclusion: with an all-zero 256-B trailer the signature/hash compare cannot pass → 0x7024.
No "key rotation with firmware build" is needed to explain the observation; OPLUS (or the
export-zip packager) simply shipped a **zeroed-signature AllInOne DA** in this exact export,
while `DA_BR.bin` kept real signatures. Whether a *properly signed* AllInOne DA of another
build would also fail on a fuse-hash mismatch remains untested (the `[EFUSE] sbc_pub_key_hash`
/ `sbc_key_hash is incorrect/correct` machinery exists in the preloader), but that is a
separate question from the observed 0x7024. **Practical fix: use DA1/DA2 extracted from
DA_BR.bin (already done by mtkclient path), or re-sign — not possible without MTK/OPLUS key.**

## Q2 — LK verification gate

Code path (all VA, file = VA − 0x200F10):

1. Generic partition loader `partition.c` **VA 0x231004** (function containing the refs):
   - 0x23105E: `img_auth_required` ← `bl 0x237C60`; printed "[%s] img_auth_required = %x" (0x24ED2C).
   - `0x237C60` = `ubfx r0, r0, 1, 1` of `0x237BA8` (**sec_policy getter**):
     `sboot_state` (0x241128 → 0x243190 → efuse read **word index 0x1F, bit 1** via efuse driver
     0x244996) combined with `lock_state` (0x240A1A: cached `*(0x2F4348)`, default 1; live value
     from seccfg driver `*(0x2FB284)+0xC`). Returns bit1 — auth required when the policy word
     says so (exact boolean combination not fully decoded — **inference**: secure-boot fuse ON
     and device locked ⇒ img auth required).
   - If img_auth_required ≠ 0 (0x2310D6):
     - **cert chain verify `bl 0x23ED90`** (0x2310E4). Nonzero → "[ %s] cert chain vfy fail..."
       (0x24ED63) + assert (partition.c line 0xEC) → boot abort.
     - **img version check `bl 0x242624`** (anti-rollback, touches cert/hash tables 0x2FB1B8 /
       0x2FAD54). Fail → "img ver check fail...." + assert.
   - After the full image is loaded: **hash verify "img vfy..."** `bl 0x23F0D8` (0x23125C):
     computes a **HACC (hardware AES) keyed hash** over the loaded image (worker 0x23EB60,
     uses ctx `*(0x2F4370)`, end pointer `*(0x2F9B60)`), compares (0x2406FC) against the
     **hash table at 0x2FB1B8** filled from the parsed cert chain (table 0x2FAD54, 0x464 B,
     per-image entries). Mismatch → "fail(0x%x)" (err 0x1004) + assert (partition.c line 0x119).
     Success → "[%s] img auth ok" (file 0x559E3).

2. Where the cert chain lives — **found in lk.img itself (proven):** the tail of
   `IMAGES/lk.img` (0x2BFDE2–0x2C0433) contains an appended **"cert2" section**:
   - header at 0x2BFE40: magic 0x58881688, size 0x3F3, name **"cert2"**, ext magic 0x58881689,
     "xV4\""/0x78563422 marker;
   - a full **X.509 DER certificate** at 0x2C0040 (0x3EF B): issuer/subject
     `C=AU / O=Mediatek / OU=Oplus_cert0`, validity 2015-06-04…2035-06-04, RSA-2048;
   - a trailing **256-byte signature blob** at 0x2C0333 (ends at file end 0x2C0433/0x2C0440).
   So the preloader verifies a **signature chain (RSA PKCS#1 PSS / SHA-384 software lib —
   `pkcs_1_pss_decode_sha384*` strings) bound to per-image hashes**, then hashes the payload
   with HACC and compares against the cert-declared hashes. It is **not** a plain
   hash-vs-fuse compare.

3. Scope: (a) — **the whole loaded image content is verified, not just the `lk` payload
   section** (inference, medium-high): the cert chain is an appended *section of the same
   partition image* ("cert2"), the hash compare covers the loaded image buffer against the
   cert's per-image hash entries, and the same generic loader/verify path is applied to
   every authenticated partition (gz/tee/md1img are separate partitions with the same
   0x200-header + cert scheme — gz.img header confirmed identical layout). Any patched
   byte in the payload breaks either the cert-hash compare or requires a new cert2 +
   signature, which requires the OPLUS/MTK private key.

4. Fallback/dev-mode: **none found.** No "skip cert verify" fuse path; the only bypass is
   the `sboot` efuse bit itself (word 0x1F bit 1) — i.e. factory-level SBC state — or an
   unlocked `lock_state` in seccfg which the OPLUS DA2 auth gate prevents modifying.
   `S_EFUSE_MARK_SKIP` / `sbc_key_hash` efuse code paths exist but apply to efuse
   programming tools, not to the boot verify decision. **Verdict: on this unit (SBC blown,
   per target_config 0x5), LK patching on-device is dead** unless the DA2 auth gate
   (`g_oplus_auth_status`) is defeated AND flash-write of a re-signed LK were possible —
   it isn't (no signing key). Also note `DA hash validation` in DA1 (`cmd_boot_to`,
   strings 0x546E8/0x5477B) covers DA2, not LK.

## Q3 — rpmb_en / rpmb_key / update_rpmb_key_flag

**The flags are NOT efuse — they live in OPLUS flash partitions (proven by disasm):**

1. **Boot-params struct** (string 0x527B0 → literal VA 0x239248, printed at VA 0x239186 in
   `oplus_usb_handshake`, VA 0x23913C): filled by **VA 0x230834** which reads **0x258 bytes
   from the `oplus_custom` partition** (magic `"oppo"` = 0x6F70706F checked at 0x2308B2;
   `OPLUS_CUSTOM_PARTITION` log tag). Layout used: `nMagicNum1 @+0x00, nMagicNum2 @+0x04,
   nPlUsbEnumEnabled @+0x08, nUsbAutoSwitch @+0x0C` (bitfield test `(v&0xE)==0xA` at
   0x239190), **`rpmb_en @+0x250`, `rpmb_key @+0x254`** (printf stack args from
   `[sp,0x260]/[sp,0x264]` = buffer+0x250/+0x254).

2. **RPMB enable / keyprovision markers — `oplusreserve1` partition** (dispatcher
   **VA 0x23CB54**, string tag "OPLUSRESERVE1", partition name "oplusreserve1" @0x24E213;
   reads a **0x28-byte record** at a computed partition offset, `blkdev_read` 0x20661C):
   - record **+0x00 == "0x9621"** (ASCII) → RPMB enabled (`check_rpmb_enable_flag`,
     VA 0x23CA08; match ⇒ "get enable rpmb flag, enter enable flow").
   - record **+0x14 == "0x594553"** (ASCII; = hex of "YES") → keyprovision flag SET
     (`check_keyprovision_flag`, VA 0x23CA48, memcmp at +0x14).
   - cmd_type switch (TBB at 0x23CC14): 0=query enable, 1=query keyprovision,
     **2 = write "0x594553" (set flag), 3 = write "0x4e4f" (= "NO", clear flag)** via
     `update_rpmb_key_flag` (VA 0x23CA88; logs `[%s:update_rpmb_key_flag addr=0x%llx]`,
     write via `blkdev_write` 0x206638, addr = partition base + 0x236C-block offset —
     the addr printed is the absolute flash address).

3. **Provisioning flow** `ufs_rpmb_authen_key_program` **VA 0x23BFF0** (caller VA 0x23603A,
   `rpmb_storage_get_key`-style wrapper):
   - read oplus_custom boot-params (0x230834) → rpmb_en/rpmb_key flags;
   - pre-nonce: `VA 0x23C0EC` fills **0x2F86C0 (64 B) from `get_rnd` (0x235D70)** — random nonce;
   - **key source: VA 0x235FEC** → UFS path `VA 0x235FA0`: cached key at `0x2F4315`
     (flag `0x2F4314`), else **VA 0x2428DE(0, buf, 0x20)** — builds stack strings
     **"RPMB" / " KEY"** ("0x59454B20") and requests **32 bytes** through a hardware
     mailbox at **0x10210008** (wait loop 0x242AF4 on `+0xABC` status) — i.e. the key
     comes from **EL3/secure world (ATF/GZ), not from the host and not a preloader constant**.
   - if enabled && keyprovision flag NOT set → program: `VA 0x23BC08(0, key, 0x20)`
     (SCSI SECURITY PROTOCOL OUT) → on success write keyprovision marker (cmd 2) →
     "[PASS] Authentication Key Program Success"; on fail "[Failed] … not Programed this
     time"; if flag already set → skip programming, "RPMB Key has been written!".

4. **Could update_rpmb_key_flag be reset?** Mechanically yes: it is an ASCII marker
   ("0x594553" ↔ "0x4e4f") in a 0x28-B record in the `oplusreserve1` partition; anything
   that can write that partition (authenticated DA2 session) can flip it. Assessment:
   - **Not an attack vector**: the 32-byte key value is fetched from the secure-world
     mailbox — the host can never supply its own key bytes, so resetting the flag cannot
     inject a known RPMB key.
   - **Mostly harmless on an already-provisioned device**: the storage controller rejects
     a second AUTH_KEY_PROGRAM after the key slot is written; flow then logs
     "[Failed] Authentication Key not Programed this time" and continues.
   - **Residual danger (flagged)**: if the mailbox key were per-request random rather than
     efuse-derived-deterministic, and the device were in a never-provisioned state, a
     reset would cause a one-time (irreversible) program with a key we don't know —
     losing RPMB access. Determinism is **unproven** (the derivation lives in GZ/ATF;
     see `re-lk-rpmb-key-derivation.md` Q3). **Do not reset the flag on a retail unit
     without a dump-based confirmation that the key is deterministic.**

## Evidence index

- Preloader base: 0x200F10 (literal cross-check, 1856 hits) — proven.
- DA1/DA2 sig diff: `cmp -l` output ranges above — proven.
- Preloader code: r2 disasm at VAs cited — proven (read of instructions).
- lk.img "cert2" + X.509 Oplus_cert0 + 256-B tail sig — proven (bytes inspected).
- Exact span of the HACC payload hash (vs `*(0x2F9B60)` end pointer) — inference.
- img_auth_required boolean combination (sboot ∧ lock) — inference.
- efuse word 0x1F bit1 = SBC/sboot — proven as *the source read*; semantic mapping
  to "SBC enable" fuse — high-confidence inference (matches LK's `efuse_value/sbc_enable`
  string and MTK convention).
- Key determinism of the GZ/EL3 mailbox key — unknown/unproven.

## ERRATA (2026-10-26, build-scoped)

The `VA = file_offset + 0x200F10` base proven above is the **200EX01** preloader only.
The 2710EX01 preloader base is **0x200F00** (literal-consistency scan 1817/3182 vs 86 for the
runner-up; image ends `0x2607D4`; functionally confirmed by the class gate at `0x25F350`
reading `0x100` under this base). Every `0x25xxxx`/`0x2Fxxxx` VA quoted for 200EX01 must be
rescaled by −0x10 for 2710; `0x200F10` reads garbage on the 2710 image. Full derivation:
`/tmp/opencode/deliverable/preloader2710_daa.md`; survey:
`re-penumbra-survey-2026-10-26.md`.
