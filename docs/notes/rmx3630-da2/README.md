# RMX3630 OPLUS DA2 — reversing blob

`da2_oplus.bin` — stage-2 download agent extracted from the realme 10 4G
(RMX3630, MT6789/Helio G99) firmware bundle. This is the binary all the
runtime-patch addresses in `docs/notes/rmx3630_session_2026-10-23.md`
refer to.

- md5:  `74d2b9f26b57ec3bc0ec04bf2b5c2d37`
- sha256: `fd3a5038518441299e6a60e94a6db43613950c028508cb522f3e3343f9947a60`
- size: 356296 bytes
- provenance: `/home/musin/firmware/extracted/IMAGES/da2_oplus.bin`
  (extracted 2026-10-23). Code bytes are identical to stage 2 of
  `download_agent/DA_BR.bin`; the difference is the trailing 0x100-byte
  signature block — this copy has it **zeroed**, the `DA_BR.bin` copy
  below is **signed**. DA1 validates the DA2 hash, so NEVER patch this
  file offline; all patches are runtime via heapbait `patch_mem`.

## Signed container for DA-swap tests — `DA_BR.bin`

Full MTK DA container (DA1 + DA2 back to back) from the same 200EX01
export, with **real signatures** (this is the pair the preloader will
verify with RSA-PSS, unlike the AllInOne container whose trailer is
zeroed):

- size: 785024 bytes
- md5:    `9bc9fcc51dce9fce6b4932e74976b9c8`
- sha256: `abee43e8abc67de86c5f4e20eb58f8665cb560fa38ce1b135aa7c0f97ca8007c`
- provenance: `/home/musin/firmware/extracted/IMAGES/download_agent/DA_BR.bin`
  (RMX3630export_11_14.0.0.200EX01)

Region table (offsets in this file; stage 1 is the DAA-signed image):

| stage | file offset | length | load VA | sha256 of region |
|---|---|---|---|---|
| DA1 | `0xBC` | `0x689FC` | `0x200000` | `7932352b2fbe572fc17ae0bd594021f448dbf153e8bc1b94d3234ebfe2fa69e7` |
| DA2 | `0x68AB8` | `0x56FC8` | `0x40000000` | `8f99fb3ef27b6239a3962ae91e407268ff504edb8855ef51bab1c93815e0ceb0` |

mtkclient can consume it directly: `--loader docs/notes/rmx3630-da2/DA_BR.bin`
(`DAconfig - Using custom loader: …`). Use it only for the DAA
accept/reject experiment; the DA2 inside is the unclamped 200EX01 build.

## Loading / disassembly hints

- Load base: **0x40000000** (file offset 0 == VA 0x40000000).
- Architecture: ARM32 (ARM state, prologues are `STMFD`/`PUSH`;
  some Thumb code regions exist).
- Strings are plain UTF-8-ish C strings, e.g. `sec_get_seccfg`,
  `SEC_CFG`, `[SEC] set lock state as LOCKED`, `SECCFG Anti-Clone
  Enabled`, `Security deny for [%s]`, `DA.SLA ENABLED/DISABLE`.

## Known addresses (verified in this campaign)

| VA | What |
|---|---|
| 0x40007abc | `cust_security_verify_sec_policy` (RET0 patch OK) |
| 0x400103dc | `oplus_security_verify_sec_policy` (RET0 + status global via patch_mem) |
| 0x400021a0 | WRITE-PARTITION policy deny byte-check (LDRB +3) |
| 0x4000392c | WRITE-FLASH policy deny byte-check (LDRB +3) |
| 0x400031a4 / 0x400031b0 | WRITE-FLASH handler deny BEQs |
| 0x40002e60 | WRITE-FLASH handler start |
| 0x40002034 | WRITE-PARTITION handler start |
| 0x40002598 | WRITE-PARTITIONS deny keyed on global 0x40054314 (untouched) |
| 0x4002f804 | oplus image hash-list check (RET0) |
| 0x4002fcf4 | entity-compare deny gate (BEQ->B) |
| 0x4002c800 | SEC service function containing "set lock state as LOCKED" print; print site 0x4002ceac; table-dispatched, no direct BL callers |
| 0x40034d6c | `sec_get_seccfg` — state cached in global 0x4006E9F0 |
| 0x40034ffc / 0x40035014 | SEC state writers: MOV r1,#1 / MOV r1,#2; STR @0x40035020 |
| 0x4006E9F0 | SEC lock-state global (writers store 1/2 here) |
| 0x4005455c | `g_oplus_auth_status` (patch_mem to 1 = FULL) |
| 0x40039d00 | `get_hw_sbc` (patch optional, OPLUS_SBC_PATCH=1) |
| 0x400416bf | "DA.SLA ENABLED" -> DISABLE string reference site |
| 0x400084a4 | generic "Security deny for [%s]" printer (~130 callers — do NOT patch) |

## Open reversing questions

1. Where does the post-write hang/EIO come from — SEC service pass after
   WRITE-PARTITION commit (suspect around `sec_get_seccfg` 0x40034d6c)?
2. Where does the WRITE-FLASH anti-tamper scrubber live (any exchange
   touching seccfg zeroes the area, even before data transfer)?
3. Does the SEC service restore seccfg from the oplusreserve2 copy
   (UFS offset 0x4800000) — i.e. is reserve2 the "master" it
   regenerates from?
4. Which code dispatches to the table-driven SEC service at 0x4002c800?
