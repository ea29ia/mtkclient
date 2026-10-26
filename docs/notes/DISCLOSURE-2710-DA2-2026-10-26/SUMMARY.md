# SUMMARY — OPLUS/MTK XML Download Agent 2 (DA2), CMD:WRITE-EFUSE debug-XML path

Date of analysis: 2026-10-26 · Target: realme 10 4G (RMX3630, MT6789/hwcode 0x1208) ·
Affected artifact audited: the 2710EX01-era OPLUS DA2 (`DA_BR.bin` 2025-12-09, DA2 blob
sha256 `f95f2b82c684115a0fd4bf50f3286ebcb357721a19134d56515d534e209dde47`).
All findings are emulation-proven (Unicorn 2.1.4); no device was used.

## One-paragraph summary

The OPLUS/MediaTek XML Download Agent 2 shipped with realme RMX3630 firmware exposes a
`CMD:WRITE-EFUSE` command whose *debug XML* input path performs an **unvalidated
arbitrary 32-bit write** ("write-what-where") anywhere the DA address space maps —
efuse controller registers, DA RAM globals, SoC MMIO. The only validation in the whole
path is a payload-length check (`len == 0x200`). A single reversible RAM write through
it forges the DA's own authorization level (`g_oplus_auth_status` = 5), which collapses
every per-partition flash-policy deny (`oplus_single_mode` special case), opening the
flash layer (partition writes/erases; seccfg included at the driver boundary). The same
primitive can also blow real efuse words (e.g. the security-control word at
`0x11C10060`) — an irreversible, device-bricking class of effect. Reaching the command
requires an authorized DA session with a legitimately OPLUS-signed flash policy — the
same precondition as any normal flash operation — so this is an in-session privilege
escalation, not a keyless unlock; but the signature that buys "flash this device"
silently also buys "rewrite its security state".

## Affected-build timeline (from our committed audit notes)

| build / blob | date | WRITE-EFUSE debug path | evidence |
|---|---|---|---|
| DA1-era blobs 2022–2025 (13 heapbait-exploitable in our 19-blob corpus) | 2022-12 … 2025-06 | DA1 layer, separate issue (#414-family) | `re-da1-collection-audit-2026-10-26.md` |
| 14.0.0.200EX01 (RMX3630, DA_BR 2024-09-02) | 2024-09 | command registered unconditionally; handler not diffed at the debug-path level — **unverified** | `re-da2-readregister.md`, `re-da2-2710-audit-2026-10-25.md` |
| 14.0.0.420EX01 (2025-03-04) | 2025-03 | not audited | `oplus_mt6789_rmx3630.md` |
| C.25-era unit (community) | 2023-03 blob | not audited for this path | `re-da1-collection-audit-2026-10-26.md` |
| **14.0.0.2710EX01-era DA2 (2025-12-09)** | 2025-12 | **PROVEN vulnerable** (audit + emulation, rc=0 writes) | `re-da2-2710-efuse-2026-10-26.md`, `re-da2-2710-efuse-chain-2026-10-26.md` |

## Root cause (see ADVISORY.md for the full ladder)

`CMD:WRITE-EFUSE` handler `0x40005C20` accepts a 512-byte payload and parses it as XML.
If XML parsing succeeds, the handler walks `debug → write → verify/read → extra →
option` and for each `<option address="0x…">N</option>` executes a raw
`*(u32*)address = value` (blow engine `0x40031A18`, raw writer `0x4003184A`) — with no
address validation, no whitelist, no authorization query. All of the guards one would
expect (image SHA-256, revert/ECC/ackey/custk consistency, SBC-engaged guard, battery
check) belong to the *binary-image* branch, which only runs when XML parsing fails; the
debug-XML path never reaches them (emulation-proven, supersedes the earlier static
reading — see ERRATA in `re-da2-2710-efuse-2026-10-26.md`).

## Impact

1. **Reversible policy collapse**: one option — `<option address="0x40054C88">5</option>`
   — sets the DA's authorization global to 5 ("oplus_single_mode"); every partition→
   policy lookup then collapses to that entry (flags 0) and the per-partition
   deny layer disarms for the whole table (proven by execution: seccfg/lk/userdata/
   pro_info flags 2→0). Under that state the flash layer is reachable: the erase
   dispatcher fires through the real handler, and block writes land byte-exact at the
   driver boundary with no second gate inside the DA
   (`re-da2-2710-flash-layer-2026-10-26.md`).
2. **Irreversible bricking class**: the same `<option>` mechanism addresses the efuse
   controller window (`0x11C10000–0x11C12000`), where blown bits are 0→1 only — e.g.
   the SBC/security-control word `0x11C10060`, lock words, public-key hash words.
   A hostile or buggy client can permanently destroy a device's secure-boot state.
3. Session-scoped only: a DA reload (BROM→DA1→DA2) restores the forged RAM global;
   only real efuse blows persist.

## The exact reversible PoC chain (proven in emulation)

```
1. Obtain the authorized session (the only door):
   CMD:SECURITY-SET-ALLINONE-SIGNATURE → CMD:SECURITY-GET-DEV-FW-INFO →
   CMD:SECURITY-SET-FLASH-POLICY with an OPLUS-server-signed policy.
   (Unsigned policy → "Server is not authenticated. Locked.", rc=0xE0000010 — executed.)
2. CMD:WRITE-EFUSE with the 512-byte debug XML (space-padded):
<?xml version="1.0" encoding="utf-8"?><efuse><debug><write fsource="3000" vcore="1200"><verify><vcore>1200</vcore></verify><read fsource="3000" vcore="1200"/><extra><option address="0x40054C88">5</option></extra></write></debug></efuse>
   rc=0; the write log diff contains exactly ONE persistent RAM write: 0x40054C88 ← 5.
   (The minimal XML shape requires <verify> AND <read> sections — fuzz-proven.)
3. Effect: registrar gate passes, the hash-list verifier's status==2 extra check is
   skipped, every partition→policy lookup returns entry 62 with flags 0.
Zero efuse-word writes; one DA reload restores everything.
```

## Why this is reportable despite the session precondition

The signed policy is the *only* thing standing between "a legitimate flash-tool
session" and "arbitrary DA-state + efuse-state rewrite". Nothing in the policy's
semantic contract grants that: the policy body is never parsed into any capability
table (proven on 200EX01: `re-da2-policy-map.md` Q1.4); the debug path ignores the
authorization level entirely. A compromised/legit-but-hostile flash tool, or any future
weakening of the session door, inherits a write-what-where primitive over the SoC's
security state. We consider this a defense-in-depth failure of high severity with a
bricking impact class, not a remote-code-execution bug.

## Credit policy proposal

* Joint credit: **alexander-dev2313123** (independent finder of the 2710EX01 DA2 audit;
  supplied the build to the mtkclient community thread and published his own
  `EFUSE_2710_AUDIT.md`, whose post-merge erratum agrees with our correction) and the
  RMX3630 research team behind this note set (GitHub user **ea29ia**, mtkclient issue
  #409 participants).
* Coordinated disclosure to MediaTek PSIRT and OPPO OSRC (realme brand) in parallel;
  CVE ID requested from MITRE (this component sits outside the vendors' CNA scope as
  far as we know).
* mtkclient-side: we recommend NOT implementing `CMD:WRITE-EFUSE` against this DA
  family (already noted in `re-da2-2710-efuse-2026-10-26.md` §6).

## Full technical detail

See `ADVISORY.md` (technical advisory), `CONTACTS.md` (where to report),
`TIMELINE.md` (proposed 90-day cadence), `RULES.md` (hard constraints for whoever
sends this). Every claim traces to a committed note under `docs/notes/reverse/` or to
an executed emulator run (`docs/notes/da2_2710_efuse_chain.py`,
`docs/notes/da2_2710_efuse_flash.py`).
