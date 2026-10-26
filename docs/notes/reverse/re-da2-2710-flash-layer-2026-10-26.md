# RE: the storage layer under the auth=5 forge — what WRITE-PARTITION / WRITE-FLASH
# actually do on the 2710EX01 DA2 (synthetic UFS model, Unicorn-proven)

Date: 2026-10-26. Artifact: `/tmp/opencode/fw2710/x/da2_2710.bin` (358,160 B, sha256
`f95f2b82…`, ARM32, VA base 0x40000000 = file offset 0). Emulator: Unicorn 2.1.4 via
`/tmp/opencode/efuse2710/harness.py` (DA2Emu, reused unmodified) + the new driver
**`docs/notes/da2_2710_efuse_flash.py`** (modes `calib`, `probe`, `seccfg`, `all`; full
log `/tmp/opencode/flash2710/flash_all_output.txt`, exit 0). **Emulator-only; no device,
no flashing, no efuse word touched.** The forge is the proven reversible RAM write from
`re-da2-2710-efuse-chain-2026-10-26.md` (one dword at 0x40054C88 via the real
CMD:WRITE-EFUSE debug-XML path).

Companions: `re-da2-2710-efuse-2026-10-26.md` (write-path audit),
`re-da2-2710-efuse-chain-2026-10-26.md` (the forge + policy collapse),
`re-da2-2710-certchain-2026-10-26.md`, `re-da2-policy-map.md` (200EX01 policy map —
the structural reference this note confirms/corrects for 2710),
`re-writeflash-scrubber.md` (200EX01 erase-before-program mechanics),
`re-lk-seccfg.md` (the boot-time seccfg validator this note leans on).

## TL;DR verdict table

| question | verdict |
|---|---|
| Q1: what does a forged session's WRITE-* reach? | **The flash layer.** Post-forge, CMD:WRITE-FLASH's policy deny is disarmed (the DA's own log prints `[SEC_POLICY] in oplus_single_mode`, policy dump `hash_binding = 0 / img_auth_required = 0 / dl_forbidden = 0`) and the REAL erase dispatcher (`ops[8]`) fires at the target range — the synthetic model was actually erased (`ERASE start=0xA00000 len=0x200`). The data-phase block write is proven at the driver boundary + through the DA's real write wrapper (byte-exact). |
| Q2: any SECOND gate at the flash layer? | **None inside the DA.** The storage-ops ABI is `(off64, buf, len, …, record)` — no session/auth/policy parameter at any of the ~40 call sites. The DA's seccfg loader (`sec_get_seccfg`) runs during write flows but is instrumentation-only in the deny path (every branch of the flag getter returns the static table byte). The "verified image name" check fails OPEN (`get verified image name failed but could use original name.`). The download checksum engine is integrity, not auth. Below the DA (UFS write-protect, RPMB framing at the frame-helper layer) — untested, no device. |
| Q3: can a forged session WRITE seccfg content? | **Bytes land verbatim** at the driver boundary (a full SecCfgV4 record with `lock_state=3` was committed byte-exact through the DA's own write wrapper `0x4002D734`). The DA-side seccfg machinery (MMMM record + HW-scrambled digest — it DOES exist on 2710, correction below) did not reject or rewrite anything in the emulated path, and its failure (`0xC002002F`) did not block erase/download (fail-open). What still gates seccfg CONTENT is boot-time and outside the DA session: LK's `sec_check_major_integrity_seccfg` (SHA-256 + HACC digest) and the RPMB boot-info mirror — plus the unresolved question whether a *valid* record triggers in-DA regeneration (200EX01 session-proven behavior class; HACC-blocked in emu). |
| Overall | **post-forge flash writes = possible** at the DA level (proven to the driver boundary; erase proven through the real handler end-to-end). Two honest limits: the data-phase state machine was not pumped end-to-end in emu (RTOS scheduler + HW checksum engine unmodeled — on silicon both are transparent), and sub-driver silicon protections are untested. |

> **UPDATE (2026-10-26, later session):** both honest limits above are now closed —
> the data-phase SM *was* pumped end-to-end in emu and the "HW checksum engine"
> attribution is corrected (it is software). See §5 ERRATA/UPDATE at the end of this
> note; the deliverable script is `docs/notes/da2_2710_flash_dataphase.py`.

---

## 1. The storage architecture (static, 2710EX01)

### 1.1 Two target namespaces

* **GPT-partition commands** (WRITE/READ/ERASE-PARTITION): resolve `da/arg/partition`
  through the GPT cache list `0x4006B0F0` (`{valid u8 @0, count @4, records @8}`,
  0x58-stride records: name @+8 (0x40 B), start64 @+0x48, size64 @+0x50), filled by
  bootstrap2's GPT scan (`0x40001F20` region). Finder = `0x40012F04` (searches the
  pseudo/SGPT list `0x4006B0E4` first, then the GPT list; miss →
  `"Not have GPT. On finding [%s]"` / `"Cannot find [%s] info from partition table.\n"`).
  READ-PARTITION-TABLE just formats this cached list (`<pt><name>%s</name><start>0x%llx</start>
  <size>0x%llx</size></pt>`) — no flash I/O.
* **Raw-region commands** (WRITE/READ-FLASH): `da/arg/partition` must be one of the 12
  storage-region names in the table at `0x40053A2C` (`EMMC-BOOT1/2`, `EMMC-USER`,
  `EMMC-GP1`, `UFS-LUA0..3`, `NAND-WHOLE/AREA0`, `NOR-WHOLE/AREA0`), classified by
  `0x40012C88` against the runtime device globals: UFS handle `[0x40067500]` with
  capacity64 at `0x40067508/10/18` (types 0x100/0x101/0x102), eMMC handle
  `[0x40067BD8]` with capacities at `0x40067BE0/E8/C18` (types 1/2/8). The handler
  then resolves the write offset **against the GPT** to attach policy
  (`policy of partition: <name>` in the DA log) and range-checks against the region
  capacity.

### 1.2 The driver boundary — storage ops table `0x40054A9C`

Runtime-initialised function table (all 35 movw/movt reference sites are READERS —
`ldr r3,[r0]`-style; the table is populated by the storage init we do not emulate).
Slots (from call-site analysis):

| slot | role | call shape |
|---|---|---|
| +0 | **block READ** | `(off_lo, off_hi, buf, <junk=fnptr>, stack{len, x, record})` — used by the image-verify cluster's read wrapper `0x4002D690` (7 call sites, incl. the cert-container reads at 0x400363CC) and directly by the chunk pump `0x40030AA4` |
| +4 | **block WRITE** | same shape — used by the write wrapper `0x4002D734` (hash-record writer sites 0x40010744/0x4001076C) |
| +8 | erase dispatcher | `(record_or_request, aux, callback=0x4002B80C)` — the WRITE-FLASH unconditional erase and the WRITE-PARTITION `pre_erase` erase |
| +0xC/+0x10 | aux (info/control) | e.g. `0x400040A8` calls +0xC with (1,0,0,{0,0}) |

The block wrappers `0x4002D6CC`(read)/`0x4002D734`(write) take
`(name, X, off_lo, off_hi)` + stack `{buf, ?, len, ?}`, resolve the name via
`0x40012F04`, compute `abs64 = record.start64 + off64`, and call the slot.
**The ABI carries no session, auth, or policy parameter anywhere** — checked at every
reference site; the only inputs are geometry (offset/len/record) and the buffer.

### 1.3 Handler-level gates (all pre-storage)

| cmd | checks before any storage op |
|---|---|
| WRITE-PARTITION `0x400022B4` | GPT-record lookup; policy parse `0x4002D15C`; **only `dl_forbidden`** (struct[3]) denies (`Security deny for [%s].`); erase iff (`pre_erase` absent or `"YES"`) and name ≠ `PRELOADER` (`0x4002C844` = strncmp 9); then region list from the XML body (`<space_list>/<space offset length>`) → program engine `0x4002AE50` → session `0x40030918` |
| WRITE-FLASH `0x400030EC` | region classify (12-name table); offset+filesize vs capacity range check; **three-flag deny** (`struct[3]==1 ‖ struct[2]==1 ‖ struct[1]==1` → deny, 0x40003418–0x40003434); **unconditional erase** (ops[8]) before the data phase — the 200EX01 scrubber mechanics, present unchanged |
| READ-PARTITION `0x40003554` / READ-FLASH `0x40003674` | **no policy parse at all** (statically: no `0x4002D15C` call in either handler) — gated only by command registration |
| ERASE-PARTITION `0x40003A64` | dl_forbidden only |

The policy flag getter `0x4002CFFC(idx)` (the byte at `0x400569B4 + idx*0x20 + 0x16`)
contains a **seccfg interlude**: before returning the byte it calls
`0x40033DE4` (lock-state-lite: cached at `[0x40057570]`, `0x22` = unread, real read =
`0x40039FB8` = `sec_get_seccfg` core) and `0x40034E84`. **Every branch of the getter
converges on returning the static table byte** — the lock-state result only feeds log
lines (`[SEC_CFG] sec_get_seccfg ret=%x`, `[SEC] get lock state fail, ret: %x`).
That is why every WRITE-* run shows exactly 3 `sec_get_seccfg` queries (the three bit
extractors `0x4002CFE8/0x4002D114/0x4002D128` each walk the getter).

### 1.4 [CORRECTION] the seccfg anti-clone cluster DOES exist on 2710

The efuse-chain note's statement "the seccfg lock-state machinery … the forge does not
touch it" stands, but the earlier implication that the DA2 has no seccfg parser is
wrong for 2710: the cluster is present —

* `sec_get_seccfg` core `0x40039FB8` (string `[%s] sec_get_seccfg ret=%x` @0x400516C8,
  tag `SEC_CFG`); MMMM record magic via the movw/movt pair at **`0x4003505C`** (a raw
  dword scan misses it — that is how the first pass concluded "absent"); record
  digest via the HW scrambler `0x40039FD0`/HACC (same engine family the certchain
  found engine-blocked offline); "SECCFG Anti-Clone Enabled" string @0x40051713;
  a second record magic `0x014D4D4D` built at `0x40034440`.
* Readers besides the flag getter: `0x400343AC/0x40034400` (a seccfg re-read pair in
  the writer cluster), `0x40038460`, `0x400392BC`, `0x4003EA28/3EA3C`.
* In the emulated WRITE flows it behaved as **instrumentation only** (see §2), and its
  failure did not gate the flow.

## 2. Executed evidence (all from `flash_all_output.txt`, exit 0)

### 2.1 calib — the ops ABI and slot direction (direct calls)

```
[1] direct ops[1] WRITE: ops1(0xA00100,0, buf, junk, {0x40,0,rec})
    rc=0; slot[ 1] off=0x0000A00100 buf=0x40471000 len=0x40 rec=seccfg
    model@0xA00100 now: 000102030405060708090a0b0c0d0e0f ... pattern landed: True
[2] direct ops[0] READ: ops0(0xA00100,0, sink, junk, {0x40,0,rec})
    rc=0; sink == written pattern: True
[3] wrapper cross-check: WRAP_WRITE(name='seccfg', off=0x180, stack{buf,?,0x40,0})
    rc=0x0; model@0xA00180 == pattern: True
    slot[ 1] off=0x0000A00180 ... data[:32]=000102...1f
```

The DA's real write wrapper resolved "seccfg" through the GPT cache, added the
record base, and committed the bytes — no gate anywhere on the path.

### 2.2 probe — the handler matrix (status 1 pre-forge vs status 5 post-forge)

| run | deny | storage ops | model effect |
|---|---|---|---|
| st=1 WRITE-FLASH(UFS-LUA0, off=0xA00000) | **`Security deny`** | 3 × ops[0] read 0x3000 (sec_get_seccfg probes) | none |
| st=5 WRITE-FLASH(same) | none | 3 × read + **ops[8] ERASE start=0xA00000 len=0x200** | **model erased** |
| st=1 WRITE-PARTITION(seccfg, pre_erase=YES) | none | 3 × read + **ops[8] ERASE start=0xA00000 len=0x800000** | full 8 MiB seccfg erased |
| st=5 WRITE-PARTITION(same) | none | identical | identical |
| READ-* (both statuses) | none | 0 (read engine's registered callback is an emu artifact: `UC_ERR_FETCH_UNMAPPED` at PC 0x1000 — RTOS-registered handler absent) | — |

The DA's own log for the status-5 WRITE-PARTITION run (captured at the uart-flush
helper 0x4000792C) — the forge's effect in the DA's own words:

```
Download partition [seccfg]
[SEC_POLICY] in oplus_single_mode
[SEC] RW Session Init.
[SEC_CFG] sec_get_seccfg ret=c002002f      (x3 — blank model content)
[SEC] get lock state fail, ret: c002002f   (x3)
==========security policy==========
policy of partition: seccfg
hash_binding = 0
img_auth_required = 0
dl_forbidden = 0
===================================
hash_binding:0, img_auth_required:0
get verified image name failed but could use original name.
Host file system OP: <xml>CMD:FILE-SYS-O…
Download [seccfg] with file:p
initial_chksum_info: prepare for checksum.
No flashinfo part exists. skip write device_action_history.
ASSERT FAILED at (/work/000e/workspace/Build_S_Vendor/49048/code/source/vnd/vendor/mediatek/proprietary/bootab…
```

And the WRITE-FLASH status-5 log: `Erase [UFS-LUA0] At[0xA00000] Len[0x200]` →
`CMD:PROGRESS-REPORT` → `Progress report EOT.` → `Download [UFS-LUA0] with file:p` →
`CMD:DOWNLOAD-FILE` announce (packet_length from `[0x4006819C]`) → host ack →
`initial_chksum_info: prepare for checksum.` → the fatal spin (the checksum MMIO and
the RTOS scheduler are not modeled — the run ends there, at 0x4000786C's print-and-hang
tail).

The pre-forge WRITE-FLASH run ends at the policy deny with **zero** write-class
storage ops — the deny precedes the erase (matching the 200EX01 scrubber order:
policy check → erase → program).

### 2.3 seccfg — byte-level content proof

* status-1 baseline: the same WRITE-PARTITION(pre_erase=YES) **also** erases the full
  8 MiB seccfg partition (dl_forbidden = 0 for every stock entry — the erase path is
  not forge-gated; honest nuance vs WRITE-FLASH).
* status 5: after the handler-level erase, the data path was proven at the ops
  boundary: ops[1] committed the payload

```
4d4d4d4d 04000000 3c000000 03000000 00000000 00000000 45454545 00000000 …
   MMMM     ver=4   size=0x3C  lock_state=3                    EEEE
```

  byte-exact at `0xA00000` (`payload landed VERBATIM: True`), i.e. a forged
  `lock_state=3` SecCfgV4 record reached the flash model with the DA applying no
  content transformation and no rejection.

## 3. Answers to the three task questions

**Q1 — what can a forged session read/write?** Everything the command table exposes:
the policy layer that produced `Security deny` on stock sessions is collapsed
(entry 62 `oplus_single_mode`, flags 0 — observed in the DA's own log), so
WRITE-FLASH-class denies vanish and the raw-region path (UFS-LUA0 with an arbitrary
64-bit offset) becomes the general-purpose flash write primitive; GPT-partition writes
are likewise unguarded at the DA level. Reads were never policy-gated (no policy parse
in any READ-* handler, static). The emulated runs prove reachability up to the driver
boundary and one full erase through the real handler; the block-write call itself is
proven at the boundary and through the real wrapper (§2.1/§2.3).

**Q2 — second gate at the flash layer?** Inside the DA: **no**. The ops ABI is pure
geometry+buffer (§1.2); the seccfg loader is instrumentation in the deny path (§1.3);
the image-name check fails open; the checksum engine is an integrity feature on the
download, not an authorization check; RPMB framing exists only in the boot-time UFS
frame helpers (2710 audit: `rpmb_hmac` = `0x40032F9C`, 3 callers, boot-time only) —
not on the WRITE-PARTITION/WRITE-FLASH path. What *may* still act as a gate is (a)
the untested sub-driver silicon (UFS write-protect LPW configuration, if the OEM
sets it — nothing in the DA sets or queries it), and (b) the unresolved
valid-record regeneration question (§3 Q3).

**Q3 — seccfg specifically.** The 2710 DA2 **has** the seccfg anti-clone cluster
([CORRECTION] §1.4): `sec_get_seccfg` (0x40039FB8) validates the MMMM record pair and
its HW-scrambled digest — but on the write path it is consulted for logging only; the
deny decision remains the static policy-table byte, which the forge zeroes. In emu:
* the seccfg loader FAILING (blank content, `0xC002002F`) did not block the erase or
  the download (fail-open);
* a forged `lock_state=3` V4 record lands byte-exact at the driver boundary;
* what mtkclient's own unlock flow requires is unchanged in kind from 200EX01:
  read seccfg → parse SecCfgV4 → set `lock_state=3` → re-sign the digest with the
  device-bound HACC/SEJ scramble (the part that requires the hardware crypto) → write
  back; the DA session-level gate (policy deny) is the only thing the forge removes.
* unresolved in emu (HACC + RTOS not modeled): whether a *succeeding* sec_get_seccfg
  makes the 2710 DA regenerate/ignore uploaded seccfg bytes post-write — the 200EX01
  session-proven "SEC regeneration" class. And on silicon the written record only
  MATTERS if LK accepts it at boot (`re-lk-seccfg.md`: SHA-256 over the 0x1C header +
  HACC-AES with fixed seeds; RPMB mirror re-locks and powers off on mismatch) — those
  gates are outside the DA session and unaffected by the forge.

## 4. Emulation limits (honest list)

1. The data-phase state machine (fetch → chunk pump `0x40030D28` → `0x40030AA4` →
   ops) is RTOS-threaded; the scheduler's context switch needs VFP (enabled in this
   harness) *and* live thread structures; the run reaches the fetch announce and then
   the **hardware checksum engine** (`initial_chksum_info`), which we do not model —
   the same class of engine-blocked boundary as the certchain's HACC finding.
   Consequently the *handler-end-to-end* block-write ops call is NOT demonstrated;
   the write is demonstrated one level down (ops ABI + real wrapper) plus the erase
   one level up (real handler). Both are real DA code; the pump calls the same ops.
2. Sub-driver silicon (UFS HW write-protect, RPMB at the frame layer) untested —
   no device, by task constraint.
3. The `0x3000` sec_get_seccfg reads returned our seeded 0xCD/0xFF content; on
   silicon the digest check would engage the HACC and cannot complete offline —
   expected-fail, fail-open observed.

## Reproduction

```
cd /root/mtkclient
/tmp/opencode/da1venv/bin/python docs/notes/da2_2710_efuse_flash.py all   # exit 0
# per mode: calib | probe | seccfg
# requires /tmp/opencode/efuse2710/harness.py (unicorn 2.1.4) and
# /tmp/opencode/fw2710/x/da2_2710.bin

# data-phase update (§5):
/tmp/opencode/da1venv/bin/python docs/notes/da2_2710_flash_dataphase.py all  # exit 0
# per mode: engine | pump | regen | semantics
```

Confidence: high on everything quoted from executed runs (ops logs, model diffs, DA
log lines); static claims are instruction-quoted. The emu-only caveats are §4.

---

## 5. ERRATA / UPDATE (2026-10-26, second session — data phase pumped end-to-end)

Deliverable: `docs/notes/da2_2710_flash_dataphase.py` (modes `engine|pump|regen|semantics`,
all exit 0; full log `flash_dataphase_all_output.txt`). Everything below is EXECUTED
evidence in Unicorn (image `/tmp/opencode/fw2710/x/da2_2710.bin`), except where the
disassembly is quoted. This section **supersedes** the two open items of §3/§4:
the "data-phase SM not pumped" limit and the "HW checksum engine" attribution.

### 5.1 [ERRATA] the download checksum engine is SOFTWARE, not HW

* `initial_chksum_info` = `0x40000F50` (executed, rc=0). It **benchmarks 8 additive
  word-sum candidates** (`0x400010D0..0x4000140C`, each a `sum-of-words` loop) against
  a fake monotonic timer and **picks one into the function pointer at `0x400548F8`**
  (executed pick = `0x400010D0`).
* Executed identity check: the picked fn over 0x1000 scripted bytes returned
  `0x1FDF800`; a python `sum(u32[i]) & 0xFFFFFFFF` replica returns the same — **the
  engine is a plain 32-bit word-sum**. Convention: `(buf, len) -> r0`.
* Per-chunk bookkeeping: `set_chunk_info` `0x4000105C` is a pure 0x20-byte memcpy
  into the info struct; the report/dispatch path `0x40001504` calls the SAME picked
  word-sum (`0x40001594` loads the `0x4006A560` candidate list).
* **The prior "fatal spin" was never MMIO**: `thread_create` `0x400094CC` hits the
  RTOS assert at thread.c:399 (empty highest-prio ready queue); the assert printer
  `0x40007828` self-spins at `0x4000786C`. Modelled (capture + inline worker), the
  state machine runs to completion.
* Negotiation: the download driver stamps `<checksum>CHK_ADD|CHK_NO</checksum>` into
  its own DOWNLOAD-FILE XML from config bit `[0x40068188]&1` (`0x4002AEEC`). Under
  CHK_ADD the host's in-loop `OK@0x<hex>` ack carries the chunk's EXPECTED word-sum;
  the producer computes the real engine over the received chunk (`0x400014D4`
  dispatch) and compares at `0x400305D4`. Executed both ways (§5.3): correct value →
  write proceeds; corrupted value → DA prints `USB checksum error. Host: 0x… /
  Device: 0x…` (the Device field is its not-yet-updated accumulator — cosmetic),
  sets `[ctx+0xE0]=0xC0040003` and the consumer **refuses the chunk** (no boundary
  write). mtkclient always negotiates CHK_NO → **with CHK_NO there is NO post-write
  read-back at all** (the pumped flow performs zero storage reads after the write).
  Integrity mechanism on the transport; never consults session state, keys or efuse.

### 5.2 The data-phase state machine (what actually runs)

* `CMD:WRITE-PARTITION` handler `0x400022B4`: policy parse → `sec_get_seccfg`
  (instrumentary; blank flash ⇒ `ret=c002002F`, fail-open) →
  `Download [seccfg] with file:MEM://0x0:0x200` (`0x4002AE84`) → download driver
  `0x4002AE50` → `initial_chksum_info` → producer → consumer → `Download_data end`.
* **Two transport channels**, both decoded:
  - *XML channel* — `SESSION` struct `0x405F0100`, `[+0]`=recv(buf,&max)/`[+4]`=send:
    the DA sends the `FileSysOp EXISTS` query (answered `OK@0x0` = .sig absent) and
    the `CMD:DOWNLOAD-FILE` XML (announce answer `OK@0x200`; the driver checks only
    `'O','K'`, `0x4002AF74`). Non-OK reply ⇒ `0xC0010001` from `0x4002AF98`.
  - *data channel* — table `0x40054A48` (`[+0]`→`0x4002AA28` packet reader,
    `[+4]`→`0x4002AB08` sender), which reads **12-byte packets
    `{0xFEEEEEEF, DT_PROTOCOL_FLOW=1, len}` + payload** over the session-op table
    `0x40054A58+8/+0xC` (magic mismatch ⇒ `0xC0010005`; capacity shortfall ⇒
    `0xC0010006`). Same wire format as mtkclient `xml_lib.xsend`.
* The producer (`0x40030364`, runs inline) fills a 0x4C-byte staging slot of the
  download buffer (`[0x40068188+0x14]`=packet_length `0x200000`, `+0x18`, `+0x1C`
  buffer size — initialised by `0x4002F66C` from the RTOS thread-start path
  `0x400093A4`; **if that init is skipped the chunk size computes 0 and the loop
  spins** — this was the pump's blocking bug), then waits at `0x400306D8` for the
  **consumer thread** (`thread_create`'d entry `0x400301D0`, arg 0) to drain the
  slot. The consumer pops the ready slot (`0x4002FA5C`) and drives the real write
  chain (`write bulk image`, `0x40030178`); on verify failure it can **erase the
  written span via `OPS_TAB+4`** (`0x40030318..0x4003034C` — rollback-on-fail).
* Pumped end-to-end with the forged session: `handler rc=0`, model write
  `[(0xA00000, 0x200)]`, boundary `VERBATIM=True`, `content[:0x20] =
  4d4d4d4d 04000000 3c000000 03000000 …` — lock_state=3 on the wire, byte-exact.

### 5.3 [ANSWERED] the seccfg-regeneration question (both scenarios, byte-diffed)

`mode regen` runs the full write flow twice — S1 empty flash, S2 flash seeded with a
VALID record (built with the modelled digest, see §5.4):

| scenario | during flow | write | pre→post diff | post-write `sec_get_seccfg` |
|---|---|---|---|---|
| S1 empty | `ret=c002002F` (fail-open) | `0x200` B verbatim | 512 B, `ff→4d…` | `rc=c002002F`, state global=0, no record extracted |
| S2 seeded valid (`lock_state=1`, digest=SEJ(SHA256(hdr))) | **`ret=0`** (validator ACCEPTS the seeded record — the digest model is self-consistent) | `0x200` B verbatim | 485 B: `@0x0C 01→03` (our lock_state), `@0x1C…` our digest slot | state global=**1**, **lock_state_of_surviving_record=3** (rc still `c002002F` — the uploaded record's filler digest fails, and the getter STILL extracts lock_state=3 — fail-open again) |

**Answer: NO regeneration exists on the 2710 write path.** In both scenarios the DA
wrote the uploaded bytes verbatim and did NOT regenerate, re-sign or replace them;
a *succeeding* `sec_get_seccfg` only flips the slot-state global
(`0x4006F168`: 1=main/2=backup) and feeds the policy getter. The 200EX01
"SEC regeneration" class does not exist here; the 200EX01 readback normalization is
a read-path/erase-order artifact there, as `re-write-chain.md` concluded.

### 5.4 [SEMANTICS] which seccfg bytes are unlock-relevant, and the honest boundary

Record layout (mtkclient `Library/Hardware/seccfg.py` == the 2710 validator
`0x40034F14` == LK's boot-time validator): `+0x00` magic `0x4D4D4D4D`; `+0x04` ver=4;
`+0x08` size=0x3C; **`+0x0C` lock_state (1=locked, 3=unlocked — THE unlock field)**;
`+0x10` dm_verity; `+0x14` sboot; `+0x18` sentinel `0x45454545`; `+0x1C` enc_hash
(0x20 B) = `SEJ_scramble(SHA256(hdr[0:0x1C]))` — the only content DA/LK verify, and
it covers exactly the 0x1C header (so lock_state IS digest-protected).

* DA-side write-path transform of these bytes: **NONE** (executed: the record lands
  byte-exact; the digest is neither recomputed nor verified on the write path — a
  garbage-digest record was written without complaint).
* The validator's digest = SEJ(SHA256(hdr[0:0x1C])) with the key the REAL loader
  `0x400348F0` places at `0x1000A060` (zeros when no `0x014D4D4D` custom record is
  harvested — observed) and IV = the fixed seed table `0x40053AE4`
  (`9ED40400 00E884A1 E3F083BD 2F4E6D8A`, LE). The seeded S2 record built with this
  model was ACCEPTED by the real validator code (ret=0) — model/device consistency
  executed, not assumed.
* **One-line answer** to "can a forged session write an unlock-relevant seccfg that
  survives to LK unchanged?": **Yes at the DA layer — the forged session writes the
  SecCfgV4 record byte-exact and nothing on the 2710 write path rewrites or rejects
  it — but the record only *matters* if its `enc_hash` is a correct on-device
  SEJ(SHA256(header)) digest, because LK's `sec_check_major_integrity_seccfg`
  re-derives it at boot (and the RPMB boot-info mirror re-locks on mismatch); the
  DA session neither helps nor hinders that part.**

### 5.5 Emu plumbing notes (for reproducibility)

Model-write cap lifted `0x200000→0x10000000` (`install_storage_bigcap`) — fl's cap
silently DROPPED the full-partition ops[1] write. Worker injection is LR-gated: the
consumer thread runs inline only at the producer's post-fill drain-wait
(`EVENT_WAIT` with LR=`0x400306DC`); injecting at other waits preempts the producer
with an empty staging buffer. The `MEM://` source_file does NOT use the fetch engine
`0x4002AFD8` (that is the named-file path, efuse flow) — the bytes arrive as
transport packets and land in the download buffer (observed base `0x80001000`).
