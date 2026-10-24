# re-md1img-scan — RPMB / seccfg dependency scan of md1img.img (MT6789 modem, fw 14.0.0.200EX01)

> **ERRATA (2026-10-24, audit #2):** the "planned mirror rewrite" is invalid —
> the mirror is at RPMB blocks 0x1DC–0x1DF and the DA RPMB path is eMMC-only;
> the forged seccfg did not survive the reboot. See `re-unlock-campaign-2026-10-24.md`.

**Date:** 2026-10-23 · **Target:** `/root/firmware/IMAGES/md1img.img` (55623168 bytes) · **Method:** strings-level only, bounded scan.

## 1. Keyword hit matrix

| Keyword | Hits | Notes |
|---|---|---|
| `rpmb` / `RPMB` (case-insensitive) | **0** | Zero occurrences in whole 55 MB image |
| `seccfg` / `SEC_CFG` | **0** | |
| `hacc` (standalone) | **0** | Only false sub-word matches (C-HLCK, etc.) |
| `anti.?clone` / `anti-cl` | **0** | |
| `lock_state` | 3 | 0x14c8d60 `GET_DEVICELOCK_STATE common_info[0] is %d`, 0x165b1c4 `get_devicelock_state`, 0x13ca840 `sml_check_ctrlslot_if_all_cat_unlock_state` (SIM-lock, not seccfg) |
| `oplusreserve` | **0** | |
| `md1db` / `mdbgp` / `nvcff` | **0** | Modem does NOT reference its NVRAM partition names |
| `efuse` | 2 | 0x132ad08 `protocol/el2/el2_sec/emac/src/emac_sec_efuse.c`, 0x1343ad8 `errc_spv_efuse_protect.c` — protocol-layer source paths, no storage I/O |
| `IMEI`-related | many | `+VGETNVDATA` (0x118a568), `FTC_CMD_NV_WRITEIMEI_F` (0x1346570), `SBP_IMEI_LOCK_SUPPORT` (0x13be71c) — NV-based, served via NVRAM service |
| `NVRAM` | ~100+ | Extensive but all IPC-service based (see §2) |

## 2. Classification of interesting hits

### (a) NVRAM access model — the key finding
Strings around 0x12d2218–0x12d22f0:
```
NVRAM module is not existed.
(send_req)NVRAM request: %d, file_id: %d
(req_handler) NVRAM request: %d, file_id: %d
```
This is the classic MTK modem pattern: the modem issues **NVRAM requests over the AP-IPC channel** (`send_req`/`req_handler`), referencing **logical file_ids (LIDs)**, not partitions or block devices. Physical persistence (`nvram`, `nvcff`, `md1db`, `nvdata`) is handled entirely by the AP-side NVRAM daemon. **No partition name, no `/dev/...`, no block-device path, no UFS/eMMC RPMB command strings exist anywhere in the image.**

### (b) SIM-lock / device lock (SML, oplus_simlock)
- 0x1282254–0x12899xx: `sml_lock_rule`, `[LINK_SML]`, `smu_assign_u8(SMU_*)` — SIM-lock state stored in **NVRAM LIDs** (e.g. `FTC_CMD_NV_WRITESML_F` at 0x1346614 writes SML data via the NV service).
- 0x14c8790–0x14c8c00: `oplus_simlock_lib.c`, `oplus_simlock_validate_integrity`, `oplus_ft_simmelock_hdlr`, `oplus_set_operator_flag_handler` — Oppo/realme custom simlock, again operating on **simlock data blobs delivered from AP** (`+ESLBLOB` AT protocol).
- 0x14c8d60: `GET_DEVICELOCK_STATE common_info[0] is %d`, `GET_FEE_STATE common_info[1]`, `GET_LOCKMARK device_lock_mark` — queried via AT/common-info channel from AP; **not** read from storage by the modem itself.

### (c) Error/dead-code strings
- `emac_sec_efuse.c`, `errc_spv_efuse_protect.c` (0x132ad08, 0x1343ad8) — LTE security-protocol source paths (protection against protocol-level attacks); "efuse" here is terminology, no efuse/RPMB storage access.
- `[VAL_ATC]ATC NVRAM not ready` (0x1189160) — ATC test framework error string.
- `MUXZ_TYPE_MD_DB_SIGNATURE` (0x12d3d68) — metadata signature check on in-memory MD DB, not flash.

## 3. NV-RAM-on-RPMB check

**Not present.** There is no evidence the modem:
- talks to RPMB at all (0 hits),
- references `md1db`/`mdbgp`/`nvcff` partitions (0 hits),
- performs any direct flash/block-device I/O (no mmc/ufs/flash device strings; only innocuous binary-noise matches).

Modem NVRAM (including SML/simlock data, IMEI, `NVDATA` via `+VGETNVDATA`) is proxied through the AP. Anti-clone/security-check state for this Oppo build lives in oplus simlock blobs validated in-modem but written/read by the AP side.

## 4. Sector-ownership verdict

| Region | Consumer of record | Modem involvement |
|---|---|---|
| RPMB sectors 0–3 (boot-info mirror) | LK + TEE only (per re-lk-rpmb-lock.md) | **None — zero RPMB strings in md1img** |
| seccfg partition | AP (LK/TEE/`seccfg` daemon) | **None — zero seccfg strings** |
| nvcff / nvdata / md1db | AP NVRAM daemon ↔ modem IPC | Indirect via file_ids only; unaffected by seccfg/RPMB writes |

## 5. FLAG check

🚩 condition (modem keeps NVRAM on RPMB sectors 0–3 or anti-rollback counters there): **NOT TRIGGERED**. The planned operations — seccfg rewrite at the UFS 0x24000000 area and RPMB sectors 0–3 mirror rewrite — have **no strings-level evidence of any md1img/modem dependency**. The `re-lk-rpmb-lock.md` assumption (only LK + TEE consume RPMB sectors 0–3) is consistent with the modem image contents.

Caveat (bounded scan): this is a strings-level verdict, not full RE. A hypothetical RPMB dependency implemented purely with obfuscated/opaque constants and no diagnostic strings cannot be excluded at this effort level, but that would be highly atypical for MTK modem builds — the NVRAM-over-IPC pattern is uniformly present and no alternate storage path exists in the image.
