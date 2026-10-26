# MILESTONE — RMX3630 / MT6789 research campaign: closed for now (2026-10-26)

**Status: research is CLOSED as of this date.** No further active work on the
DA1/DA2/preloader unlock campaign is planned. This note is a status marker, not
a findings document — all technical detail lives in the notes referenced below.

## What was accomplished (chronological)

1. **200EX01 campaign** — full end-to-end result on live hardware:
   bootloader unlocked in the Oplus sense (orange state), Android boot after
   wipe, `adb root` → uid 0 (Magisk/permissive path). Documented in
   `docs/notes/reverse/re-unlock-campaign-2026-10-24.md`,
   `re-root-achieved-2026-10-25.md`, `re-magisk-adb-coexist-2026-10-25.md`.

2. **DA1 hardening timeline** — dated across 19 MT6789 blobs
   (pre-2024-09 unclamped → clamp window closes 2025-01-03 → command removed
   2025-12). Delivered upstream via PRs bkerler/mtkclient **#423** (clamp-gate +
   transport hardening) and **#424** (5 bugfixes).

3. **DA-swap dead, PSS verified** — DAA key rotation S/K1 → K27/K2 proven by
   full offline PSS verification of all six DAA trailers (6/6, per-era key
   model). Verifier shared with the community collaborator
   (alexander-dev2313123, PR #1 of the research repo).

4. **2710EX01 DA2 chain closed** — WRITE-EFUSE debug-XML path analyzed,
   forged-session write path proven in emulation; data-phase state machine
   pumped end-to-end; the seccfg-regeneration question answered (no
   regeneration on the write path; digest verification happens at boot in LK,
   outside the DA session). Final note:
   `docs/notes/reverse/re-da2-2710-flash-layer-2026-10-26.md` (§5 ERRATA/UPDATE).

5. **Disclosure decision** — vendor report is NOT filed. Rationale: the
   primitive is gated behind a legitimately-signed-policy session (same
   precondition as any flash operation), the unlock path dies at the
   boot-time LK/RPMB gates, and the material is already public. The prepared
   disclosure package remains on disk for the record.

6. **Community collaboration** — coordinated with alexander-dev2313123
   (mutually cross-checked EFUSE/cert-chain/PSS work, all closed with
   agreeing texts); DekuzenOkahiro outreach for the C.25 on-device run
   remains unanswered since 2026-09-24 and is dropped.

## What remains open (parked, not active)

- bkerler review of PRs #423/#424 (ping after ~1 week of silence, one polite
  reminder only).
- RPMB-mirror neutralization on 2710-class devices (single remaining gate
  beyond the DA layer) — parked indefinitely.
- ARM64 port of the DA1 chain — parked (no target device need).

## Housekeeping

- All work committed on branch `oplus-mt6789-unlock` through this milestone
  commit. The pre-commit hook (`core.hooksPath` → git-template) remains active:
  research artifacts named by the FORBIDDEN patterns and files >100 KB stay
  out of future commits.
- Proprietary device bundles (Wi-Fi package, DTB) are indexed by path+sha256
  only (commits `d072ef6`, `a4be97c`) and stored outside git.

**Nothing further is scheduled. This campaign is closed.**
