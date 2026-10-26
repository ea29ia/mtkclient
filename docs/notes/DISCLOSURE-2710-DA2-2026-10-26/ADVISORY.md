# ADVISORY — Ungated arbitrary 32-bit write in the OPLUS/MTK XML DA2
# CMD:WRITE-EFUSE debug-XML path (2710EX01 build)

Status: prepared for coordinated disclosure · 2026-10-26 · **emulation-proven only;
no device was used and no efuse word was blown during this research.**

---

## 1. Affected component

* Component: OPLUS-branded MediaTek XML-protocol Download Agent stage 2 (DA2) as
  shipped in realme RMX3630 (MT6789 / Helio G99, hwcode 0x1208) firmware.
* Audited build: DA2 blob of the 2710EX01-era `DA_BR.bin` (container build date
  2025-12-09); DA2 image sha256
  `f95f2b82c684115a0fd4bf50f3286ebcb357721a19134d56515d534e209dde47`,
  358,160 B, ARM32, VA base `0x40000000` = file offset 0.
* Vulnerable handler: **`CMD:WRITE-EFUSE` at `0x40005C20`** (registered by the
  SEC-POLICY command-registration block `0x40001A78` via registrar `0x400083DC`).
* Vulnerable code path: the debug-XML engine **`0x40031A18`** (Thumb) and the raw
  32-bit writer **`0x4003184A`** (Thumb).
* Reference build (200EX01, DA_BR 2024-09-02, DA2 sha `fd3a5038…`): `CMD:WRITE-EFUSE`
  is registered unconditionally as well (handler `0x4000599C` —
  `re-da2-readregister.md`); whether the 200EX01 handler carries the same debug-XML
  path was **not** audited and is marked unverified.

Build timeline relevant to scoping (all from committed audit notes):

| build | date | status for THIS issue |
|---|---|---|
| DA1-era blobs 2022-12 … 2025-06 | — | out of scope here (separate DA1 issue family, cf. `re-da1-collection-audit-2026-10-26.md`) |
| 200EX01 (RMX3630 14.0.0.200EX01, 2024-09-02) | 2024-09 | command present; debug path unverified |
| 420EX01 (2025-03-04) | 2025-03 | DA1 audited 2026-10-26 (`re-da1-420audit-2026-10-26.md`): VULNERABLE/UNCLAMPED, S(K1)-signed, same DA1 code as 200EX01; DA2 debug path still unverified |
| **2710EX01 (2025-12-09)** | 2025-12 | **proven vulnerable** (static audit + emulation) |

## 2. Severity reasoning (CVSS v3.1-style)

The write path itself performs **no authentication and no authorization query** —
there is no check of any kind between the XML `<option>` attribute and the `str`
instruction. However, the command is not reachable from a cold plug: it is registered
only inside the SEC-POLICY session ladder, which requires an OPLUS-server-signed flash
policy — the same precondition as any legitimate flash operation. CVSS cannot express
"signed-session-gated write-what-where with irreversible hardware side effects" well;
our best-effort vector and its honest limits:

* Vector: `CVSS:3.1/AV:P/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` → ≈ 6.9 (High).
  Physical/USB attack vector (the DA only talks over the BROM/preloader USB session),
  privileges required (the signed-policy session), scope changed (the compromise
  reaches permanent device security state beyond the session), full C/I/A on the DA's
  security domain.
* What CVSS under-represents: (a) the efuse variant is **irreversible** (blown bits
  never reset) — permanent bricking of the secure-boot state from a single malformed
  or malicious flash-tool run; (b) the auth-forge variant converts an already-authorized
  session into a **policy-collapsed** session, disarming the entire per-partition
  protection model in one command; (c) if any future keyless path to command
  registration appears, the same primitive becomes Critical
  (`AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`). No keyless path was found
  (`re-da2-2710-efuse-chain-2026-10-26.md` §1, §7: boot table = 9 commands, no write
  primitive; the fetch-engine clamp closes the heapbait shortcut on 2710).

## 3. Root cause

### 3.1 Handler structure

```
CMD:WRITE-EFUSE 0x40005C20 (ARM)
├─ 0x40008134                  session scratch alloc
├─ 0x4000CFEC                  mxml parse of the command packet
├─ 0x400020AC                  the ONLY XML argument: da/arg/source_file
├─ 0x4002AFD8                  fetch the payload from the host (category "efuse")
└─ 0x40007EA8                  dev_efuse_write wrapper
    ├─ cmp len, #0x200 / bne → 0xC0030007     *** the ONLY input validation ***
    ├─ 0x40031A18 (Thumb)      blow engine: parses the 512-B PAYLOAD AS XML
    │   ├─ debug → write(fsource, vcore) → verify(vcore) → read(fsource, vcore)
    │   ├─ extra → option children:
    │   │     addr = strtol(attr "address")   (0x4000CD2C → 0x4000AC20)
    │   │     data = strtol(node text)        (0x4000E924 → 0x4000AC20)
    │   │     blow_list[i] = {addr, data}     ← NO validation of addr whatsoever
    │   ├─ 0x400318EA(0): [0x11C10008] ← 0x6B32970A   (BPKEY unlock)
    │   ├─ loop: for each option: 0x4003184A(addr, data)
    │   ├─ loop: read back each addr, compare (read oracle, logs 0x%x != 0x%x)
    │   ├─ 0x400318EA(1): [0x11C10008] ← 0             (BPKEY re-lock)
    │   └─ 0x4003189E: [0x11C10000] |= 4, wait bit0    (controller reinit)
    └─ 0x4003184A(addr, data) = the primitive:
        poll controller ready (timeout 0x1000); str r1, [r0]; poll done
```

`0x4003184A` performs a raw 32-bit store to whatever address the host supplied. The
reachable space is everything the DA address space maps: the efuse controller window
`0x11C10000–0x11C12000` (including the security-control word `0x11C10060` — sbc_en /
daa_en / sla_en / jtag bits — and the lock words `0x11C10020`-class), DA RAM globals
(e.g. `0x40054C88` = `g_oplus_auth_status`), SoC MMIO (watchdog `0x10007000` was
written in emu), and the DA's own code segment.

### 3.2 Why the debug-XML path bypasses the binary-branch guards

The handler branches on how the 512-byte payload parses:

* **Binary branch** ("ulpotrec" image, XML parse fails): runs the full guard ladder —
  image magic/SHA-256 (`0x400321A8`), revert/ECC/ackey/sbc/custk consistency
  (`0x400326F4…0x40032914`), the SBC-engaged guard (`0x40032DC4`), battery check.
  This is the OEM flash-tool flow.
* **Debug-XML branch** (XML parse succeeds): walks `debug/write/extra/option` and
  **never reaches any of the guards above**. Proven by execution: options writing the
  SBC word (`0x11C10060 ← 0xFFFFFFFF`) and the auth global (`0x40054C88 ← 5`) both
  complete with `rc = 0`. This supersedes the earlier static reading that attributed
  the guards to the write path generally (ERRATA in `re-da2-2710-efuse-2026-10-26.md`;
  alexander-dev2313123's post-merge erratum on his `EFUSE_2710_AUDIT.md`, commit
  `ca3c7f2`, agrees).

Minimal working XML shape (fuzz-proven; `<verify>` AND `<read>` are REQUIRED —
dropping either makes the walker skip `<extra>` entirely):

```
<?xml version="1.0" encoding="utf-8"?><efuse><debug>
<write fsource="3000" vcore="1200">
  <verify><vcore>1200</vcore></verify>
  <read fsource="3000" vcore="1200"/>
  <extra><option address="0x…">DEC</option></extra>
</write></debug></efuse>
```

The root element name is irrelevant; only `<write>` + `<extra>/<option>` fire the raw
write. The payload must be exactly 512 bytes (space-padded) — the `len == 0x200`
check is the sole validation in the entire path.

### 3.3 Session preconditions (what the attack does and does not need)

* At DA boot only 9 commands are registered; `CMD:WRITE-EFUSE` is **not** among them
  (registrar walk, executed). The full command table — including WRITE-EFUSE and the
  write family — appears only after `CMD:SECURITY-SET-FLASH-POLICY` succeeds, which
  requires `[0x400683A4]`/`[0x400683A8]` session stages and an RSA-2048 (e=65537,
  hardcoded OPLUS modulus) verified policy. An unsigned policy is refused:
  `"Server is not authenticated. Locked."`, rc `0xE0000010` (executed in emu).
* The EFUSE commands are registered **before and independent of** the
  `g_oplus_auth_status ∈ {3,4}` gate in the same block; the write family
  (WRITE-PARTITION/WRITE-FLASH/WRITE-PARTITIONS) is suppressed at status 3/4 and
  registered at 1/2/5.
* Therefore: the vulnerability requires an **authorized DA session** — the same
  precondition as any flash operation — and then removes every limit that session was
  supposed to carry.

## 4. Impact

### 4.1 The reversible auth-forge (demonstrated)

`CMD:WRITE-EFUSE` with the 512-byte XML above (one option
`<option address="0x40054C88">5</option>`) sets `g_oplus_auth_status = 5`
("oplus_single_mode"). Executed consequences (all emulator-proven, differential
write-log isolation):

* exactly ONE persistent RAM write: `0x40054C88 ← 5`; the only other writes are the
  efuse-controller BPKEY unlock/re-lock and reinit control pokes (no efuse DATA word
  is addressed);
* the registrar gate passes (write family stays registered);
* the hash-list verifier's `status==2` extra comparison is skipped;
* **every partition→policy lookup collapses to entry 62 (`oplus_single_mode`), whose
  flag byte is 0** — the per-partition hash-id/hash-binding/img_auth denies disarm for
  the whole table (seccfg/lk/userdata/pro_info flags 2→0, executed);
* the DA's own log confirms it at runtime: `[SEC_POLICY] in oplus_single_mode`,
  followed by the policy dump with `hash_binding = 0 / img_auth_required = 0 /
  dl_forbidden = 0`.

### 4.2 Post-forge flash reachability (storage-layer study)

With a synthetic UFS/storage layer behind the DA's real storage-ops table
(`0x40054A9C`), executed evidence (`re-da2-2710-flash-layer-2026-10-26.md`):

* pre-forge (status 1): `CMD:WRITE-FLASH` targeting the seccfg byte range exits at
  `Security deny` **before any write-class storage op**;
* post-forge (status 5): the deny is gone; the **real erase dispatcher fires**
  (`Erase [UFS-LUA0] At[0xA00000] Len[0x200]`) and the storage model is actually
  erased; the handler proceeds to `CMD:PROGRESS-REPORT` + `CMD:DOWNLOAD-FILE`;
* the storage-ops ABI is `(offset64, buf, len, …, record)` — **no session, auth or
  policy parameter exists at the driver boundary** (checked at all ~40 reference
  sites); the DA's real write wrapper commits attacker bytes byte-exact with no gate;
* a full SecCfgV4 record with `lock_state=3` lands verbatim at the seccfg offset
  through the driver boundary. The 2710 DA2 does carry a seccfg anti-clone loader
  (`sec_get_seccfg`, MMMM record + HW-scrambled digest) — in the emulated write flows
  it acts as instrumentation only, and its failure did not block erase/download;
  whether a *valid* record triggers in-DA regeneration (the 200EX01 session-proven
  "SEC regeneration" behavior) is unresolved (HACC-blocked in emu).
* The gates that survive for seccfg CONTENT are boot-time and outside the DA session:
  LK's `sec_check_major_integrity_seccfg` (SHA-256 over the 0x1C header + HACC-AES
  with fixed seeds) and the RPMB boot-info mirror (`double_check_lock_state` —
  re-locks and powers off on mismatch). Both are unaffected by the forge.

### 4.3 The irreversible efuse-blow class

The same `<option>` mechanism addresses real efuse words. Efuse bits are 0→1 only:
blowing sbc_en/daa_en/lock/public-key-hash words on a factory-fresh unit is
permanent and bricks the device's secure boot. Executed in emu:
`0x11C10060 ← 0xFFFFFFFF` completes with rc=0 (in emu this is a model write; on
silicon it would be destructive). We did NOT and will NOT execute this on hardware.

### 4.4 Reversibility table (from `re-da2-2710-efuse-chain-2026-10-26.md` §5)

| WRITE-EFUSE `<option address>` variant | effect | reversible? |
|---|---|---|
| `0x40054C88` (auth status) | one RAM dword | **YES** — DA reload restores; the chain's core |
| `0x4006819C` (packet-length global) | one RAM dword | **YES** (demonstrated; useless for the 2710 heapbait — the clamp is closed) |
| verifier code words (`0x400076DC`+) | DA code RAM patch | RAM-reversible only; code modification — NOT part of any recommended chain |
| any efuse DATA word `0x11C10000–0x11C12000` (e.g. `0x11C10060` SBC) | **blows efuse bits (0→1 only)** | **NO — DANGEROUS/BRICKING** |
| watchdog/RGU class (`0x10007000`) | can reboot/kill the session | session-hostile, not persistent — avoid |
| flash writes via storage commands post-forge | persistent device state | outside the RAM chain; see §4.2 |

**The demonstrated PoC chain contains zero irreversible steps.**

## 5. Proof of concept (byte-exact, 512 bytes)

Host command:

```
<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version><command>CMD:WRITE-EFUSE</command><arg><source_file>efuseimg</source_file></arg></da>
```

Payload fetched for `source_file` (core 236 bytes, space-padded to exactly 0x200 = 512):

```
<?xml version="1.0" encoding="utf-8"?><efuse><debug><write fsource="3000" vcore="1200"><verify><vcore>1200</vcore></verify><read fsource="3000" vcore="1200"/><extra><option address="0x40054C88">5</option></extra></write></debug></efuse>
```

Result: handler rc = 0x0, `g_oplus_auth_status` = 5. This exact byte sequence is the
one committed in `docs/notes/da2_2710_efuse_chain.py` (mode `forge`) and executed
against the real handler in Unicorn; the differential write-log proof (identical run
with a scratch-target option) shows the forge is a single 32-bit RAM write.

## 6. Remediation suggestions

1. **Validate/whitelist option addresses**: the debug path must accept addresses only
   inside the efuse controller's legal data window for the target SoC (for MT6789:
   `0x11C10000`-based word table, as already enumerated in the DA's own word→register
   table at `0x400540F4`), and reject everything else — including DA RAM and generic
   MMIO. A size/count cap on `<option>` elements is also missing.
2. **Require an explicitly-signed policy for the debug path**: gate the
   `debug/<write>/<extra>` branch behind a dedicated, separately-signed capability (or
   drop it from production entirely) — the current signed flash policy must not imply
   efuse-blow rights.
3. **Remove the debug path from production builds**: the binary-image branch already
   implements the guarded OEM flow; the debug branch exists for factory debugging and
   is the entire vulnerability.
4. **Share the guard ladder across branches**: at minimum, run the SBC-engaged guard
   (`0x40032DC4`) and the ackey/custk consistency checks on BOTH branches, so a
   production build cannot blow security words even from a legitimately signed
   session.
5. Defense-in-depth on the consumer side (mtkclient and similar tools): do not
   implement `CMD:WRITE-EFUSE` against this DA family; treat `CMD:READ-EFUSE`'s
   37-register dump as information only (it leaks SBC state but no key material).

## 7. What we did NOT test (explicit honesty list)

* **Silicon behaviour**: every result in this advisory is from Unicorn emulation of
  the real DA2 binary. Real efuse controller timing, blow semantics, and the actual
  read-back behaviour were never exercised on hardware.
* Real UFS/flash-driver behaviour below the DA's storage-ops table (HW write-protect
  configuration, RPMB framing at the frame-helper layer) — the DA code never consults
  any such gate on this path, but the physical layer was not tested (no device).
* The RTOS scheduler + HW checksum engine completion of the flash data phase
  (`initial_chksum_info`) — emulation stops there; on silicon both are transparent.
* Whether the 200EX01 (2024-09) or 420EX01 (2025-03) DA2 builds carry the same
  ungated debug-XML path (command presence is proven for 200EX01; handler-level
  equivalence is not). Note: the 420EX01 **DA1** was fully audited on 2026-10-26
  (`re-da1-420audit-2026-10-26.md`) — VULNERABLE/UNCLAMPED, S(K1)-signed — but that
  is the #414-family DA1 issue, not this DA2 path.
* Whether a *valid* seccfg record on silicon triggers in-DA regeneration of seccfg
  content on write (the 200EX01-observed behavior class) — HACC-blocked in emu.

## 8. Proven-in-emulation vs expected-on-silicon

| claim | status |
|---|---|
| debug-XML path performs unvalidated 32-bit writes, rc=0 | **proven in emulation** (3 layers: payload entry, blow engine, full registered handler) |
| auth forge = exactly one RAM dword, reversible | **proven in emulation** (differential write log) |
| policy collapse (entry 62, flags 0) + deny disarm | **proven in emulation** (executed lookups + the DA's own log lines) |
| erase dispatcher fires post-forge through the real handler | **proven in emulation** (storage-op log + model state) |
| block write lands byte-exact at the driver boundary, no gate in the ABI | **proven in emulation** (ops call + real wrapper) |
| seccfg V4 record (lock_state=3) lands verbatim | **proven in emulation** (ops boundary) |
| efuse blow destroys the device permanently | **expected on silicon** (standard efuse one-way semantics; the write path reaches the controller registers — emulation models the write, not the silicon) |
| in-DA seccfg regeneration on valid records | **unknown** (HACC-blocked in emu) |
| sub-driver silicon protections | **untested** (no device) |

## 9. Source traceability

Every technical claim above traces to a committed note or an executed run:

| claim group | source |
|---|---|
| handler call tree, raw writer, guard-by-pass | `docs/notes/reverse/re-da2-2710-efuse-2026-10-26.md` §§2, 5 |
| session ladder, registration matrix, forge, policy collapse, reversibility | `docs/notes/reverse/re-da2-2710-efuse-chain-2026-10-26.md` + `docs/notes/da2_2710_efuse_chain.py` (executed, exit 0) |
| flash-layer reachability, ops ABI, seccfg byte proof | `docs/notes/reverse/re-da2-2710-flash-layer-2026-10-26.md` + `docs/notes/da2_2710_efuse_flash.py` (executed, exit 0) |
| policy table / flag semantics | `docs/notes/reverse/re-da2-policy-map.md` |
| cert chain "holds" context | `docs/notes/reverse/re-da2-2710-certchain-2026-10-26.md` |
| LK boot-time seccfg gates | `docs/notes/reverse/re-lk-seccfg.md` |
| build corpus / timeline | `docs/notes/reverse/re-da1-collection-audit-2026-10-26.md`, `docs/notes/oplus_mt6789_rmx3630.md` |
