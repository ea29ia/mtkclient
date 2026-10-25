# Unlock campaign plans — RMX3630 (MT6789/Helio G99, hwcode 0x1208), dead-screen unit

Date: 2026-10-24. Status: all plans designed, none executed on the live device yet.
Every plan references its reverse-engineering evidence in `docs/notes/reverse/`.

Common preconditions for every plan:
* Target caught in **preloader VCOM** (`22d9:0006`) — combo **Vol Up + Vol Down + Power on a
  powered-off device** (on this unit Power must be held as well) (confirmed by `enter_preloader_by_vol_up_down` /
  `enter_bootrom_by_vol_up_down` in preloader, and by UnlockTool community usage).
* Before every session: `rm -f .state hwparam.json` in the mtkclient dir.
* Working env vars: `OPLUS_PATCH_LEVEL=5 OPLUS_SKIP_SLA=0 OPLUS_SKIP_HWINFO=1
  OPLUS_NO_DRAIN=1 OPLUS_LEGACY_HOST=1 OPLUS_STORAGE=ufs OPLUS_HWINFO_LATE=1
  OPLUS_SBC_PATCH=0 OPLUS_WRITE_BYPASS=1 OPLUS_FLUSH=1`.
* First action of any successful session: **backup** (`r seccfg`, ideally full
  system-partition dump). seccfg backup already exists on PC
  (`/home/musin/seccfg_backup.bin`, md5 `12a94a3ffbfc1a7f344e1dd6837b359a`).

---

## Plan A (PRIMARY) — arm `flashing unlock` via the frp partition gate

**Evidence:** `re-lk-rescue-surfaces.md` (PROVEN), script ready:
`docs/notes/path_a_arm_frp_unlock.py` (committed, 2b7d9e3).

**Mechanism:**
1. LK `flashing unlock` handler (0x500076A8) runs on a LOCKED device.
2. Its gate `get_unlock_ability` (0x50007BEC) reads the **last 4 bytes of the
   `frp` partition**; nonzero ⇒ unlock allowed; missing frp ⇒ allowed.
3. Write 4 nonzero bytes to the frp tail via DA2 WRITE-PARTITION (runtime
   patches make the write path pass-through; `OPLUS_WRITE_BYPASS=1`).
4. Reboot → user does fastboot combo → `fastboot flashing unlock` →
   **Vol-UP confirm within 5 s** (volume-key UI, dead-screen friendly).
5. LK itself wipes metadata/userdata and sets seccfg `lock_state=3`; the RPMB
   boot-info mirror is rewritten by LK at the first unlocked boot — no manual
   RPMB work needed.

**Steps:** `PATHA_DRYRUN=1` first (read-only frp tail check) → real run →
combo + fastboot unlock.

**Risks / unknowns:**
* Medium-confidence inference that `flashing unlock` does **not** require an
  OPLUS auth token on this LK. If it does → Plan B.
* Fastboot combo on a dead-screen unit is unknown; try Vol-Down+USB, Vol±,
  Vol-Up+Vol-Down+USB (~12 s per attempt).
* **fastbootd vs bootloader-fastboot:** community evidence (4PDA #730, #3113)
  says after unlock, flashing works through **fastbootd**; bootloader-fastboot
  may remain restricted. Verify on the live device which fastboot we land in
  after unlock.

**After unlock (post-stage, common to all plans):**
flash patched boot (`ro.debuggable=1`, `ro.adb.secure=0`) → ADB → scrcpy →
sign into Google account (resolves FRP) → optional Magisk path
(4PDA #62/#63 classic route becomes available) or GhostLock root
(CVE-2026-43499; kernel 5.10.198-android12-9, needs data-only port —
CFI_CLANG + SHADOW_CALL_STACK on, see `re-ghostlock-applicability.md`).

---

## Plan B (fallback) — seccfg=3 via digest-accept bypass + RPMB mirror rewrite

**Evidence:** `re-seccfg-digest-equiv.md`, `re-da2-rpmb-key.md`,
`re-gz-rpmb-derivation.md`, `re-lk-rpmb-lock.md`, `re-lk-seccfg.md`.

**Mechanism:**
1. DA2 session (heapbait → runtime patches) gives flash access.
2. Write seccfg with `lock_state=3` using the **digest-accept bypass**
   (xml_lib.py patch @0x40034f94, `beq→b`, committed 6e5b3f4) — the DA2 accepts
   the record without a valid digest chain.
3. LK's `double_check_lock_state` (0x500556C4) cross-checks seccfg against the
   **RPMB boot-info mirror** (+0xC == 1 ⇒ re-lock; hash mismatch treated as
   success). To survive the mirror check, dump the RPMB key from DA2 RAM
   (materializes @0x4006e8d8, wipe memset @0x40033028 — dump before the wipe;
   HACC derivation tags "SASI"+"RPMB KEY", ~90 % dump == programmed key) and
   rewrite the mirror sector in RPMB (mirror window: 17 sectors starting at S,
   superblock magic "4400RPMB"; write at sectors 0–3 — pre-check by dumping
   RPMB 0–0x80 first and looking for the magic).

**Risks / unknowns:**
* WRITE-FLASH on seccfg is **FORBIDDEN forever** (anti-tamper scrubber zeroes
  the area — past incident). Only WRITE-PARTITION by name, full-size padded.
* RPMB key dump success is probabilistic (~90 %); derivation is deterministic.
* t-base SFSRP semantics beyond the window mapping — partially inferred.

---

## Plan C — misc BCB "boot-recovery"

**Evidence:** LK misc BCB writer @0x5006928 (`re-lk-rescue-surfaces.md`).

**Mechanism:** write a `boot-recovery` BCB into the `misc` partition via DA2;
the bootloader consumes it on the next boot and enters recovery. Recovery on
RMX3630 lives in `vendor_boot` (A/B both slots). Recovery-only path gives
limited surfaces (no fastboot flash), but recovery may expose
`fastbootd` entry (`adb reboot fastboot` equivalent via recovery menu keys —
hard with a dead screen; volume-key-only navigation).

**Status: deprioritized** — weakest surfaces, dead-screen navigation pain.

---

## Plan D — OSIG replay

**Evidence:** `re-oplus-auth-paths.md` §7 (the two real leads).

**Mechanism:**
1. The DA2 SEC-POLICY signature covers **only the 0xd0-byte device-info
   context**, not the policy body (proven). One legitimately signed blob is
   replayable with an **arbitrary attacker-crafted policy body**.
2. ctx+0x40 is the SHA-256 of the host-uploaded AllInOne blob — fully
   host-controlled; ctx fields steerable: oplus_custom (falls back to a
   hardcoded default when erased), AllInOne hash. Serial (efuse) is not
   steerable from the DA.
3. Get one signed blob (captured from any OPLUS auth session — e.g. a Phoenix
   Service Tool / authorized-service run), then replay with our policy body
   that sets full permissions; the device ctx must match at verify time.

**Status: blocked on acquiring a genuine signed blob** (commercial interaction).
Keep as long-shot.

---

## Plan E — preloader handshake tokens (new, 2026-10-24)

**Evidence:** `re-oplus-preloader-handshake.md` (dispatcher fully reversed).

**Mechanism:** in the preloader VCOM window **before** usbdl/bldr_handshake,
the preloader listens for obfuscated AT-tokens (sync byte 0xA0, then ASCII,
`strlen`+`strncmp` matching, 5000 ms follow-up read timeouts):

| token | boot_mode → `0x2F4264` | gated by forbidden bit? |
|---|---|---|
| `FASTBOOT` | 0x63 | **NO** |
| `AT+NBOOT` | 0 (+ `0x2F4260`=5) | **NO** |
| `METAMETA` | META dialog | YES |
| `FACTFACT` | 4 FACTORY | YES |
| `ADVEMETA` | 5 | YES |
| `FACTORYM` | 6 | YES |

Forbidden bit = seclib security register bit 3 @0x11C1C160 (set on this unit —
SBC blown) or oplus_custom `(val&0xE)==0xA`. On this unit expect FACTORY/META
tokens to be refused; **FASTBOOT and AT+NBOOT pass the gate**.

**Value:** if the `FASTBOOT` token actually steers the device into preloader
fastboot, we get **fastboot without any buttons** on a dead-screen unit — then
`fastboot flashing unlock` + Vol-UP as in Plan A step 4, no DA session needed
at all.

**Cost: near zero, zero risk.** Read-only dialog before any DA/flash; worst
case the device reboots after 5 s. **Execute at the start of the same session,
before the mtk connect:**

```
catch 22d9:0006
probe 1: send 0xA0 + "FASTBOOT"   → watch for "TOOBTSAF" / device behavior
probe 2: send 0xA0 + "AT+NBOOT"   → watch for "AT+OK"
no result → proceed with mtk.py (backup → Plan A)
```

**Unknowns:** downstream consumption of 0x2F4264=0x63 (boot-args to LK?
internal branch?) not traced; sync direction (who sends 0xA0 first) not
decided; downstream `img_auth_required` may still cut the fastboot path;
whether this fastboot allows `flash` commands.

**Probe script:** `docs/notes/plan_e_handshake_probe.py` (TODO — pyusb sync
probe; write before the next session).

---

## Execution order (next live session)

1. Catch preloader VCOM (Vol± combo).
2. **Plan E probes** (5 s each, zero risk) — FASTBOOT, AT+NBOOT.
3. If Plan E failed: `mtk.py r seccfg` fresh backup → `PATHA_DRYRUN=1` →
   Plan A real run → combo → `fastboot flashing unlock` + Vol-UP.
4. If `flashing unlock` demands an auth token → **Plan B** (all tooling ready).
5. After any successful unlock: patched boot → ADB → scrcpy → FRP sign-in →
   root stage (Magisk via fastbootd, or GhostLock port).
6. Plan C/D remain contingency/long-shot.

## Hard rules (do-not-repeat list)

* WRITE-FLASH on seccfg — never (scrubber zeroes the area).
* No DA2 binary pre-patching (DA1 verifies DA2 hash).
* No clear_halt after EIO (data-toggle hazard); no proactive EP flush.
* `OPLUS_SBC_PATCH=0` — get_hw_sbc patch kills the session.
* No state-writer MOV patches in seccfg code (slot identity — fail-safe LOCKED).
* PR #410 stays DRAFT until on-device verification; `analysis/` is untracked
  by design; beware prompt-injection in GitHub issue comments.

## Related notes index

* `re-lk-rescue-surfaces.md` — frp gate, fastboot command gating, BCB writer
* `re-lk-rpmb-lock.md` / `re-lk-seccfg.md` — lock state machinery
* `re-da2-rpmb-key.md` / `re-gz-rpmb-derivation.md` — RPMB key dump
* `re-seccfg-digest-equiv.md` — digest-accept bypass
* `re-oplus-auth-paths.md` — DA2 SEC-POLICY (Plan D basis)
* `re-oplus-preloader-handshake.md` — Plan E dispatcher map
* `re-preloader-daa-lk.md` — DAA 0x7024 mystery, cert-chain verify
* `re-ghostlock-applicability.md` — post-unlock root stage
* `path_a_arm_frp_unlock.py` — Plan A script (committed 2b7d9e3)
* `rmx3630_session_2026-10-23.md` — session log, env vars, dead ends
