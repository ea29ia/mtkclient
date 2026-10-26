# RE: round 2 — deeper fuzzing of the 2710EX01 preloader DA authentication

Date: 2026-10-26. Offline, no device, no flashing, no network. Follow-up to
`re-preloader-emu-fuzz-2026-10-26.md` (round 1: 2000 cases, 0 ACCEPT_INVALID,
2710 DA auth holds in the emulator).

Deliverables:

| what | path |
|---|---|
| round-2 driver (imports `pre_emu.py`, additive) | `docs/notes/pre_fuzz2.py` |
| this report | `docs/notes/reverse/re-preloader-fuzz2-2026-10-26.md` |
| fuzz JSON (3000 cases) | `/tmp/opencode/pre_fuzz2_3000.json` |
| repros | `/tmp/opencode/pre_fuzz2_cases/` |

Tooling: `/tmp/opencode/da1venv/bin/python` (unicorn 2.1.4, capstone 5.0.7).
`docs/notes/pre_emu.py` is unchanged; every round-2 phase reuses its emulator
and adds only hooks at *unused* addresses, so all round-1 modes behave
identically (verified, §8).

---

## 0. TL;DR — verdict table

| # | question (round 2) | answer | evidence |
|---|---|---|---|
| 1 | Does any PSS/PKA boundary input accept? | **No** | 20 degenerate signatures (s=0, 1, 2, 2^16, 2^128, 2^2047, n−1, n, n+1, 2^2048−1, n/2, real±1, real<<1, BE encodings, forced 0xBC tails) → all `0x102005` / `0x7024`; only the real K2 signature accepts. |
| 2 | Is the signature scheme plain RSASSA-PSS? | **No — an MTK PSS variant** | The message digest comes from a custom chunked-hash at `0x241414` (per-32-byte-block chained hash with a 4-byte counter), not `sha256(msg)`. The signature is byte-reversed before the modexp. `sha256(msg)` is absent from the PSS core buffers. |
| 3 | Are there pre-auth memory-access commands? | **Yes — 5 of them, all window-gated** | `0xD4` (u32 write), `0xA2` (u16 read), `0xD2`/`0xD3`/`0xA1` (u16 write, `0xD3`/`0xA1` echo). Gate = queried range ⊆ one table entry. Verified dynamically, all edges. |
| 4 | Can any of them flip the DAA flag or alter the verdict? | **No** | Flag `0x2F3158`, verify code, DA buffer, K2 key are all outside the windows; the verify reads none of the writable windows (read-proof, §4). Full-window write then verify: verdict unchanged both ways. |
| 5 | Does the state machine reset after a DAA failure? | **No — permanent wedge** | Any nonzero verdict → status → `memset(DA_DST,0,da_len)` → `assert 0x231FC8` (dead loop). A later valid D7 in the same session never runs. |
| 6 | What is the flag consumer? | **cmd 0xD5 → commit+jump** | `0xD5` → gate `0x208570` (flag must be 1) → writes `[0x58885168, 1, 3]` at `0x401FFFF4`, flushes caches (CP15), and jumps into the DA at the **constant** `0x40200000`. |
| 7 | New DoS class? | **Yes: committed-then-wiped** | `D7 valid → D5 → D7 invalid`: flag stays 1 after the commit, the failed re-download wipes the DA buffer and wedges — a device that already jumped would have booted, but a pre-jump wedge with flag=1 and a zeroed buffer is a new state. |
| 8 | Emulator-visible timing oracle? | **Yes, but emulation-only** | ACCEPT ≈ 26 570 insns vs REJECT ≈ 18 594 (−20 %); RSA=1 in every crypto path. On silicon HACC is hardware; treat as emulator artifact. |
| 9 | Which key is installed? | **Exactly K2, once** | `key_setup(0x25E3DC, 0x100)` is the only install in a full accept session; K1 (`0x25E2DC`) is not in the live key struct; `0x2378AC`/`0x230C5C` are not entered. |
| 10 | Round-2 bottom line | **No bypass; the auth surface is now fully mapped** | 3000-case campaign: `ACCEPT_INVALID=0` again; the new surfaces (memory-access commands, commit path) are contained. |

---

## 1. Method

Round 1 fuzzed the verify block's direct inputs. Round 2 first did a static
sweep of the *whole* command dispatcher (the `tbh` tables at `0x208220` and
`0x2082C6`, commands `0xC4..0xE7` plus `0x80/0x90/0xA1/0xA2/0xF0/0xFB..0xFE`),
then built dynamic phases for every handler that touches memory or state.
New harness pieces (all in `pre_fuzz2.py`):

* `StreamEmu` — `PreloaderEmu` + transcript hooks at `0x20882C` (status
  channel), `0x20859C` (commit block), `0x23EA24` (key install), `0x2083A2`
  (0xD4 store), `0x201170` (jump trampoline). A `no_halt` mode lets one
  emulated session execute **several** commands across verdicts (the round-1
  harness stopped at the first verdict).
* `proto_stream` — arbitrary byte streams into the real USB command loop
  (`0x208150`), with event recording (finish/flag/assert/memset).

Phase budget (measured): func 40 s, pss 240 s, memacc 100 s, state 120 s,
reads 60 s, oracle 20 s, keys 40 s, cover 190 s, fuzz 137 s. Total ≈ 16 min.

---

## 2. Phase 1 — PSS/PKA boundary attacks

The K2 modulus (`0x25E3DC`, 2048-bit, top `0x9572`) was extracted and every
degenerate signature candidate was run through both the real verify block
(`0x20868C`) and the primitive (`0x23EA96` with the key installed):

| candidate (0x100-byte LE field) | EM tail after modexp | primitive r0 | verdict |
|---|---|---|---|
| s=0 / s=n | all zero | 0x102005 | REJECT_0x7024 |
| s=1 / s=n+1 | 0x000..01 | 0x102005 | REJECT_0x7024 |
| s=2, 2^16, 2^128, 2^2047, 2^2048−1, n/2 | pseudo-random | 0x102005 | REJECT_0x7024 |
| s=real−1, real+1, real<<1 | pseudo-random | 0x102005 | REJECT_0x7024 |
| BE(s) encodings, forced-0xBC tails | — | 0x102005 | REJECT_0x7024 |
| real signature (control) | — | 0 | ACCEPT_VALID |

Field-level byte flips of the real signature (DB, separator region, salt,
H, trailer) and an 11-position separator sweep all reject with `0x102005`.
The message/signature round-trip rejects every shortened/shifted window
(`da_len−0x100` = 0, 1, 0xFF, 0x100, 0x101 …); `da_len=0x100` is a length
error (`0x1D18`), and only the exact `da_len=0x69424` accepts.

### 2.1 The actual scheme (new, confirmed dynamically)

A snapshot of the PSS core buffers at the final compare (`0x23874C`, called
from `0x241709`) shows:

```
computed H'       = edbcfd114046a086818429c2aada24c2835e84f722a950bdb965e2e110a758c3
EM's H (from sig) = edbcfd114046a086818429c2aada24c2835e84f722a950bdb965e2e110a758c3
sha256(DA1 body)  = 5bd5d34fb39ba1cd95a486abb4fd26b08557872ce768d0135f09dffb290cdb6a  <- ABSENT
```

`sha256(message)` is nowhere in the core's working buffers: the digest fed to
PSS is produced by `0x241414`, a **custom chunked hash** — per 32-byte message
block it runs `sha_init; sha_update(block); sha_update(4-byte BE counter);
sha_final` and XOR-folds the four 8-byte sub-blocks into the state
(`0x24142A..0x24148C`). Also, the PSS core here is the `0x241C58` variant
(EM byte 0x00 handling differs from `0x2414B8`), the signature is
byte-reversed before the modexp, and the EM layout is `M ‖ H(32) ‖ S(32)` with
the `0xBC` semantics inside the masked-DB region. **Consequence: an attacker
cannot build a forged EM with a generic PSS toolkit; the scheme must be
reimplemented exactly.** This makes round 1's verdict *stronger*: forging
requires emulating an MTK-specific hash, not just PSS.

---

## 3. Phase 2b — the pre-auth memory-access commands (new surface)

Static recon found five commands that transfer raw memory under host control;
all were verified dynamically in full sessions:

| cmd | framing | direction | size | reply on success | reply on refusal |
|---|---|---|---|---|---|
| `0xD4` | `u32 addr, u32 count, count×u32` | write | 4 B | `0x0000` | `0x1001` |
| `0xA2` | `u32 addr, u32 count` | read | 2 B | one status per word | **silent** |
| `0xD2` | `u32 addr, u32 count, count×u16` | write | 2 B | `0x0000` (silent) | `0x1001` |
| `0xD3` | same | write | 2 B | echoes each word | `0x1001` |
| `0xA1` | same | write | 2 B | echoes each word | `0x1001` |

The gate (`0x237E34` → `0x237DD4` → `0x237DAC`) is **inverted containment**:
an access is allowed only if `[addr, addr+len)` is contained in one entry of a
per-direction table (`cbz r2` ⇒ mode 0 = *write* table at `0x25E6EC`:

```
write: {0x10007000..0x10008000}, {0x1001A080..0x1001A084}, {0x00000000..0x2}
read : {0x10007000..0x10008000}, {0x1001A080..0x1001A084}, {0x11F10000..0x11F11000}
```

Observed edge behaviour (all confirmed in emulation):

* writes/reads outside every entry are refused (`0x1001`; `0xA2` returns
  nothing at all — `r4=1` skips both status sends);
* a range that merely *overlaps* an entry is refused (`0x10006FFC`,
  straddling start, end-past-entry) — no off-by-one;
* `count=0` returns `0xFFFE`; `count=0x20000000` is refused by the
  `~addr >= len` overflow guard;
* `{0..2}` is writable but reads of `0..2` are refused (the entry is only in
  the write table) — and no instruction fetches from there in practice;
* legal writes land (`d4 stores` transcript), legal reads return the window
  contents (all zeros — modelled MMIO is inert).

**Impact on the DA auth: none.** The read-proof (§4) shows the verify path
dereferences none of these windows, and a full-window `0xFFFFFFFF` write
before a verify leaves both the accept and the reject verdict unchanged.
The windows (`0x10007000` = a peripheral window, `0x1001A080`,
`0x11F10000`) look like instrumentation/debug banks on this SoC; on real
silicon their contents are unknown, so this remains a *contained* pre-auth
R/W primitive worth documenting for the SoC-generic case, not a 2710 bypass.

---

## 4. Phase 2 — read-proof over the container header

Hooking every emulated read over `buf[0..0x400)` during the full verify:

```
real DA1 (control)         ACCEPT_VALID    reads of buf[0..0x400): 0 offsets, 0 hits
header PREPENDED to DA1    REJECT_0x7024   0 reads
header APPENDED after sig  REJECT_0x7024   0 reads
MMIO reads during verify:  0x10017008:2 (the free-running timer only)
```

No instruction ever dereferences the DA buffer directly — all byte
consumption happens inside the SHA shim (the message sweep). This is the
dynamic proof of round 1's static claim: **the 0xBC container header is
never parsed by the preloader**, and the writable windows never touch the
verdict. Host-side region-table layout (informational):
`region[0]==region[1]` (`off=0xBC size=0x69424`), `region[2] off=0x694E0
size=0x57710`; all within the 0xC0BF0 container.

---

## 5. Phase 3 — state machine / protocol sessions

Multi-command sessions (loop kept alive across verdicts):

| session | result |
|---|---|
| `D4 illegal(flag) → D7 valid` | refused `0x1001`, loop continues, DA accepts (flag=1) |
| `D4 window → D7 valid` / `A2 window → D7 valid` / `A2 illegal → D7 valid` | same: errors never poison later commands |
| `D7 invalid → D7 valid` | **first verdict wedges**: `memset(0x40200000,0,0x69424)` then assert; the second D7 never runs |
| `D7 valid → D5 → D7 valid` | accepts, commits, accepts again |
| `D5 with flag=0` | `0x7024` + assert wedge (no DA memset) |
| `D7 valid → D5 → D7 invalid` | commit happened; the failed re-download is the wedge below |
| `D7 valid → D7 shorter(0x200) garbage` | **committed-then-wiped**: finishes `[0,0]` then `[0x7024,1]`, `memset(0x40200000,0,0x200)`, assert — flag stays 1, buffer zeroed |
| `D7` fields little-endian | wedges (lengths decode huge) |
| `da_len=0xFFFFFF80` (negative) | wedges |
| `sig_len=0xFFFFFF00` | `0x1D18`-class verdict → memset+assert wedge |
| `bad handshake → real handshake + valid DA` | recovers, accepts |
| `junk cmds (C4,C6,FE) → valid DA` | accepts |

### 5.1 The commit path (new, byte-exact)

`0xD5` (`0x208560`) reads one u32 (echoed back), then falls through into the
gate at `0x208570`:

* flag `*(0x2F3158) != 1` → status `0x7024` → assert wedge;
* flag == 1 → `*(0x401FFFF4)=0x58885168`, `+4=1`, `+8=3`, then CP15 cache
  maintenance (`0x20117C/0x201188/0x201190/0x2011A8`), a 12-byte copy
  (`0x22844C`, args `(0x40200000, 0x401FFFF4, 0xC)`), and the jump
  trampoline `0x201170: mov pc, r0` with `r0=0x40200000`.

The jump target is a **constant**; the commit struct is at a **constant**
address; the boot-arg magic `0x58885168` is fixed. Nothing host-supplied
influences where execution goes — the only lever is the flag, and the flag
requires the K2 signature. Note the cached flag: after a commit, a *failed*
re-download cannot clear it (§0 #7), so the ordering (commit before any
further download) is safety-critical on this build.

### 5.2 Wedge taxonomy (recovery check)

Round 1's DoS wedges are **not recoverable**: the assert at `0x231FC8` is a
dead loop and every D7 verdict error reaches it. There is no state in which a
wedge accepts a later command; the only "recovery" observed is the
non-DAA-related command errors (`0x1001`, `0xFFFE`, framing echoes), which
return to the loop cleanly. So the state machine is either *working* or
*permanently wedged*; no confused intermediate state exists.

---

## 6. Phase 4 — counters (emulator-only oracle)

| case | class | insns | rsa | sha bytes | sha calls |
|---|---|---:|---:|---:|---:|
| 2710 valid | ACCEPT_VALID | 26 570 | 1 | 431 208 | 18 |
| 1-bit sig flip | REJECT_0x7024 | 18 594 | 1 | 430 884 | 1 |
| 1-bit msg flip | REJECT_0x7024 | 26 244 | 1 | 431 208 | 18 |
| zeroed trailer | REJECT_0x7024 | 18 594 | 1 | 430 884 | 1 |
| wrong-key 200EX01 | REJECT_0x7024 | 18 594 | 1 | 428 284 | 1 |
| empty message | REJECT_0x7024 | 18 594 | 1 | 1 | 1 |
| da_len ≤ sig_len | OTHER_ERROR | 1 589 | 0 | 0 | 0 |
| da_len > 0x100000 | OTHER_ERROR | 1 582 | 0 | 0 | 0 |

ACCEPT runs ~20 % more instructions than the *sig-corrupt* rejects (the
reject exits right after the EM decode), but a *message-corrupt* reject costs
nearly the same as an accept. The observable split is therefore
`reject-after-EM-decode (18594)` vs `reject-after-H'-compare (26244)` vs
`accept (26570)` — a fine-grained emulator-visible oracle (which PSS stage
failed). **Honest caveat:** this is an artifact of the shimmed HACC; on
silicon the hash/RSA run in hardware and the USB transport dominates timing.
No overclaim.

---

## 7. Phase 5 — key install + coverage map; phase 6 — coverage-guided rounds

`--mode keys`: a full accept session performs exactly one `key_setup`
(`r0=0x25E3DC`, `r1=0x100`); the installed blob equals the K2 image bytes;
the live key struct (`0x2F9AA8`, via `0x2F9F38`) contains the K2 modulus and
**not** the K1 copy; the legacy paths `0x2378AC` (seccfg/BR-cmd) and
`0x230C5C` (DA-version floor) are never entered.

`--mode cover` (3 rounds × 500 cases, block coverage):

| round | cumulative blocks | new |
|---|---:|---:|
| 1 (random + boundary func cases) | 187 | +187 |
| 2 (+ crafted proto: D4/A2/D3/A1/D5, framing) | 311 | +124 |
| 3 (same mix) | 311 | 0 (saturated) |

Auth-range blocks touched: 256 across `0x208000-0x209000`,
`0x237900-0x237A00`, `0x23E000-0x23EC00`, `0x241000-0x242000`,
`0x243000-0x244400`. The usbdl-region block map of the accept path
(58 blocks / 19 ranges, `--mode keys`) shows the loop uses `0x208150..0x2081C4`
(handshake), `0x2083AE..0x2084BE` (D7 receive/checksum/gate),
`0x20868C..0x20876E` (verify), `0x2087D8/0x20882C/0x20897C/0x2089AC..` (USB
helpers) — and nothing else. The remaining uncovered blocks are the stubbed
printf/USB-reply paths.

---

## 8. Generic campaign + reproduction

`--mode fuzz --cases 3000 --seed 2` (delegates to round-1 `cmd_fuzz`):

| class | count |
|---|---:|
| ACCEPT_VALID | 27 |
| **ACCEPT_INVALID** | **0** |
| ACCEPT_HEADER_ONLY | 130 |
| REJECT_0x7024 | 2320 |
| OTHER_ERROR (0x1D18/0x1D10) | 412 |
| CRASH | 0 |
| HANG | 111 |

9 unique outcomes, identical structure to round 1 (seed 1). Exit 0, 137 s.

```
cd /root/mtkclient
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode func      # ground truth
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode pss       # PSS boundary + scheme probe
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode memacc    # 0xD4/0xA2/D2/D3/A1
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode state     # multi-command sessions
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode reads     # read-proof
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode oracle    # counters
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode keys      # key install + coverage
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode cover     # 3 coverage rounds
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --mode fuzz --cases 3000 --seed 2
python /tmp/opencode/da1venv/bin/python docs/notes/pre_fuzz2.py --replay /tmp/opencode/pre_fuzz2_cases/partial_overwrite.json
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py --mode func        # unchanged, exit 0
```

All modes exit 0; replays reproduce (`--replay` exits 0 on match, 3 on
mismatch). The saved `partial_overwrite.json` reproduces the
committed-then-wiped wedge byte-exactly (class HANG, flag 1, memset
`0x40200000 len 0x200`).

---

## 9. Top 5 findings

1. **The signature scheme is an MTK PSS variant, not RFC PSS** — custom
   chunked message hash (`0x241414`), PSS variant core (`0x241C58`), reversed
   signature into the modexp. Forgery requires reimplementing this exactly;
   every generic-PSS forgery vector is structurally off the table.
2. **Five pre-auth memory-access commands** (`0xD4` write u32, `0xA2` read
   u16, `0xD2/D3/A1` write u16) with an inverted-containment window gate.
   Fully mapped and confirmed contained on the 2710: none of the writable
   windows feeds the auth path. A SoC-generic concern (window contents on
   other chips may include DA-relevant state), not a 2710 bypass.
3. **The commit path is `D5 → flag gate → CP15 flush → jump 0x40200000`**
   with fixed boot args `[0x58885168, 1, 3]` at a fixed struct — the flag is
   the only lever, and the jump target is a constant.
4. **Committed-then-wiped state** (new DoS class): after a commit, a failed
   re-download memsets the DA buffer and wedges with the flag still set —
   ordering-sensitive state, no path clears the flag.
5. **Permanent-wedge semantics proven exhaustively**: every D7 verdict error
   ends in the same memset+assert tail; no interleave/replay/ordering makes
   the loop accept anything after a failure.

---

## 10. Honest bottom line

Round 2 found **no bypass and no new crash class beyond round 1's DoS** —
`ACCEPT_INVALID` is still zero across every new input class. What round 2
adds is a complete, dynamic map of the authentication surface: the exact
(non-RFC) signature scheme, five previously undocumented pre-auth
memory-access commands and their containment windows, the full commit/jump
mechanics, the wedge taxonomy, and a 311-block coverage map. The 2710 DA
auth conclusion of round 1 stands, now with the remaining unknowns reduced to
the window contents on real silicon and the (unmodelled) HACC timing.
