# DA1 #414 audit across the saidanimelek26 firmware collection

Date: 2026-10-26. Tool: `docs/notes/da1_batch_audit.py` (wrapper around
`da1_static_audit.py`). Inputs: `/tmp/opencode/said` (16 blobs from
saidanimelek26/DA_mtk_FirehoseLoaders), plus our 200EX01 `DA_BR.bin`,
the 2710 `DA_BR.bin` (Alexander) and the C.25 `mt6789_realme.bin`.

Read-only, offline, no device. Verdicts below are static; the exploit chain
itself was executed only on 200EX01 (and is being ported to C.25).

## 1. What is measured

Three independent facts per blob, because the PR #414 predicate alone
over-reports:

1. `CMD:DEBUG:DRAM-REPAIR` is **registered in the command table** (not just
   present as a string);
2. the tripwire string `Dest XML file name buffer overflow` is **absent**
   (its presence means the recv clamp is live);
3. the download path is **UNCLAMPED** (`packet_len` stored into the recv
   length slot, no `min(packet_len, sb-r7)`).

`heapbait_exploitable = (1) && (2) && (3)`. Clause (3) is what #414 misses.

Signature key: the container trailer is a PSS signature; it is checked
against K1 (`0x2000F10`-era preloader, file `0x5D2DC`) and K2 (2710,
file `0x5D4DC`). `other` = OEM-specific modulus (not our K1/K2).

## 2. Results (sorted by build date)

| blob | build date | verdict | clamp | exploitable | key | digest slot |
|---|---|---|---|---|---|---|
| `vivo.bin` | 2022-12-12 | VULNERABLE | UNCLAMPED | **YES** | other | `0x25F414` |
| `mt6789_realme.bin` (C.25) | 2023-03-14 | VULNERABLE | UNCLAMPED | **YES** | **K1** | `0x264C28` |
| `xiaomi.bin` | 2023-08-15 | VULNERABLE | UNCLAMPED | **YES** | other | `0x261778` |
| `SAMSUNG_TAB_A9_DA_MT6789.bin` | 2023-09-11 | VULNERABLE | UNCLAMPED | **YES** | other | `0x261A54` |
| `samsung.bin` | 2023-09-11 | VULNERABLE | UNCLAMPED | **YES** | other | `0x261A54` |
| `infinix0.bin` | 2023-09-28 | VULNERABLE | UNCLAMPED | **YES** | other | `0x261D88` |
| `TB351F_MT6789.bin` | 2024-03-07 | VULNERABLE | UNCLAMPED | **YES** | other | `0x261960` |
| `lenovo.bin` | 2024-03-07 | VULNERABLE | UNCLAMPED | **YES** | other | `0x261960` |
| `DA_BR.bin` (200EX01) | 2024-09-02 | VULNERABLE | UNCLAMPED | **YES** | **K1** | `0x2688CC` |
| `infinix2.bin` | 2024-09-29 | VULNERABLE | UNCLAMPED | **YES** | other | `0x262C40` |
| `oukitel.bin` | 2025-01-03 | VULNERABLE | **CLAMPED** | no | other | `0x260244` |
| `infinix3.bin` | 2025-01-08 | VULNERABLE | **CLAMPED** | no | other | `0x262F58` |
| `doogee.bin` | 2025-06-24 | VULNERABLE | **CLAMPED** | no | other | `0x2604F4` |
| `DA_BR.bin` (2710) | 2025-12-09 | **PATCHED** | CLAMPED | no | **K2** | `0x2692F4` |
| `DA1_6789_in.bin` (raw) | — | VULNERABLE | UNCLAMPED | **YES** | — | `0x262DA8` |
| `DA1_6789_op.bin` (raw) | — | VULNERABLE | UNCLAMPED | **YES** | — | `0x266298` |
| `DA2_6789_in.bin` (raw DA2) | — | n/a | — | n/a | — | — |
| `DA2_6789_op.bin` (raw DA2) | — | n/a | — | n/a | — | — |

Totals: 19 inputs → **13 heapbait-exploitable**, 3 predicate-only/clamped,
1 patched, 2 are DA2 (not DA1).

## 3. Patterns

1. **The recv clamp is the real fix, and it arrived between 2024-09 and
   2025-01.** 2022–2024 builds are all UNCLAMPED. From 2025-01 the
   command stays registered and the tripwire string is still absent, but
   the clamp makes HeapBait inert — this is exactly why #414 alone is not
   a vulnerability verdict.
2. **2025-12 (2710) is the second stage of the fix**: the command is
   removed entirely, the tripwire is present, and the DAA key is rotated
   K1 → K2. Nothing of the DA1 path survives.
3. **The DA2 hash slot moves per build** (`0x25F414` … `0x2692F4`), so a
   chain port is mechanical but not constant-free: fire write, `cmd_loop`
   and `blx` move too (`da1_static_audit.py` resolves them).
4. **K1-era blobs are interchangeable with 200EX01** (C.25 proves it:
   trailer verifies under K1), so the staging trick at `0x40000000` and
   the fixed-address stub stay valid; only the build's own addresses and
   digest slot change.
5. OEM containers (`other` keys) are only usable on a device whose
   preloader trusts that OEM's key; they are useful as *code* to study and
   as chain-port targets if such a device is at hand.

## 4. What this means for the campaign

* The C.25 unit is the best real target: K1, UNCLAMPED, command present,
  and its own trailer is accepted by our key family.
* Every K1-era blob above is a candidate for the same treatment; the port
  cost is a re-run of the sweep + constant update, not new research.
* For 2025-01+ builds (oukitel/infinix3/doogee) the DA1 door is closed but
  the build still ships `CMD:DEBUG:DRAM-REPAIR` — a different bug in the
  same handler (or in the clamped recv path) would be needed; none found
  by the fuzz campaign on 200EX01 so far.
* 2710 remains closed in both directions (own DA1 patched, our DA1
  rejected by K2).

## 5. Reproduction

```bash
pip install unicorn capstone          # only capstone is needed for the audit
python docs/notes/da1_batch_audit.py /tmp/opencode/said \
    /tmp/opencode/fw2710/DA_BR.bin docs/notes/rmx3630-da2/DA_BR.bin \
    /tmp/opencode/mt6789_realme.bin --json /tmp/opencode/batch.json
```

Per-blob detail (command table, clamp evidence, resolved addresses):
`python docs/notes/da1_static_audit.py <blob>`.
