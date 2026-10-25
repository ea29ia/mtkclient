# DA1 200EX01 (RMX3630 / MT6789) — offline host-input fuzzing report

**Date:** 2026-10-25  
**Target:** `docs/notes/rmx3630-da2/da1_allinone.bin` (DA1 200EX01, `sha256 e1a4110a…3823f2`)  
**Branch:** `oplus-mt6789-unlock`  
**Harness:** Unicorn 2.1.4 + capstone 5.0.7, `/tmp/opencode/da1venv/bin/python`  
**Device access:** none. Everything below is emulator evidence; silicon behaviour is marked `[?]`.

**Deliverable:** `docs/notes/da1_fuzz.py` (new). This report. Generated JSON/repros under `/tmp/opencode/` (not committed).

---

## 0. TL;DR (honest bottom line)

The campaign ran **8,000 cases** (2,000 × `xml|proto|handlers|random`) in **174 s**, exit **0**,
with **0 harness errors** and all three classifier controls passing. A second run
(`--seed 0x1234 --cases 500`, 2,000 cases) also exited 0.

**Yes, the garbage found new exploitable surface — but it is a stronger form of the
already-known download bug, not a new root cause.**

| verdict class | count |
|---|---:|
| OK_RC / ERR_RC | 7,164 |
| expected peripheral MMIO (`UNMAPPED_IO`) | 441 |
| **NEW** length-desync heap overflow (`DATA_ABORT`) | **145** |
| **NEW** NULL deref in the length parser (`DATA_ABORT`) | **197** |
| **NEW** silent free-list corruption (`HEAP_CORRUPT`) | **1** |
| **NEW** malformed-BOOT-TO fixed reset call (`CB_SET`) | **6** |
| already-known DRAM-REPAIR HeapBait (`DATA_ABORT`/`CB_SET`) | 46 |
| HANG | **0** |
| HARNESS_ERROR | **0** |

New findings (not HeapBait, not the audit's `0x251C58` path, not MMIO):

1. **`F1` length desync / unbounded heap overflow** (145 cases, 72 distinct
   (PC, fault) pairs, **97 input-derived**). The declared length sizes the malloc, but each
   delivered chunk is independent and up to `packet_len` (0x2000); the download loop
   exits only on **exact equality** (`r7 == declared`), so a mismatch is never
   rejected. Bytes from the payload become free-list pointers; the fuzzer hit both
   *reads* (`0x20441C ldr r3,[r1]`) and **writes** (`0x204430 str r0,[r3,#4]`,
   `0x2043CC str r1,[r0,#8]`, `0x20872C strne r3,[r2,#4]`) through attacker-chosen
   addresses. At `0x2043CC` the fuzzer observed **both the write address and the
   write value coming from the payload** — a true write-what-where.
2. **`F2` integer wrap in the download allocation** (66 of the 145): declared
   `0xFFFFFFFC`/`0xFFFFFFFF` make `malloc(declared+4)` allocate 0–3 bytes; the next
   0x2000-byte chunk then overruns a 12-byte chunk.
3. **`F3` NULL deref in the length parser** (197 cases): a second ACK without `@`
   (`"OK\0"`) leaves the token pointer NULL and `0x205584` executes `ldrb ip,[r0]`
   at address 0. Input = 5 bytes. Reliable DA abort / DoS.
4. **`F4` silent free-list corruption** (1 case): a 15-byte overshoot returns
   `0xC0010001` with the free list already poisoned (node `0x40000000`, zero link);
   the *next* malloc/insert dies.
5. **`F5` desync reaches the known `cb` fire without the 12-byte exact-fit
   requirement** for the header placement: declared 0x3C + delivered 0x50
   (4-byte overshoot) fires `dpc->cb = 0x40000000` and the DA survives. (Still the
   known fire primitive; new trigger.)

**Not found:** any XML-parser memory corruption, any new code-execution path, any
true hang. The 2,000 XML cases and the 2,000 direct-handler cases did not move the crash surface
past the known baseline (UART/SHA/peripheral MMIO). The only XML-specific control
transfer is the audit's `dpc->cb = 0x251C58` invalid-address reset path, confirmed
here with a real ACK: cmd_loop calls `0x251C58`, which touches the reset controller
at `0x10007024` (DA reset; fixed target, not attacker-controlled).

---

## 1. Methodology

### 1.1 Harness reuse (no fork of the plumbing)

`da1_fuzz.py` imports the existing harness rather than copying it:

```python
from da1_fixed_stage import (boot, walk_free_list, ChainHost, BootHost,
    CMD_LOOP, DPC_STRUCT, SESSION, XML_ADDR, CMD_XML, BENIGN_XML,
    BOOT_TO, BOOT_XML, FAKE_MAGIC, DPC_ADDR, DA2_AT, CHUNK_HDR,
    _align4, make_payload, FixedChainHost, install_sha_engine,
    BLX_SITE, SAFE_CONT, DA2_BODY)
from da1_fire_chain import install_budget
from da1_emu import DRAM_REPAIR, TRAMP_TRAP, STACK_TOP
```

`boot()` runs `heap_init` + the registrar `0x200ED0`, installs the loop budget and
the real USB trampolines. `install_budget()` is imported from `da1_fire_chain`
(where it is defined; `da1_fixed_stage` re-exports the other boot pieces).

### 1.2 Per-case isolation and determinism

* **Fresh `DA1Emu` + `boot()` for every case.** No heap/registrar/`dpc` state
  leaks between cases.
* `packet_len = 0x2000` (the real global `0x2DE3F8`).
* `dpc` struct zeroed before each case (`cb_before = 0`).
* Loop budget: the existing 200,000-hit budget on the malloc/insert/recv/cmd_loop
  hot spots. A budget trip is `HANG`.
* Instruction cap: 10,000,000 per case (raised after the first run; see §10). A
  cap stop is `HANG`.
* **`cmd_loop`'s `blx r4` is intercepted** (`0x2040D4`): the target is recorded and
  the PC is redirected to `SAFE_CONT` (`0x2040D8`). The campaign therefore measures
  the `dpc->cb` primitive (`CB_SET`) instead of executing an arbitrary target.
* Deterministic RNG: `random.Random(seed ^ phase_constant)`, drawn sequentially in
  index order. Same `(seed, phase, cases)` ⇒ byte-identical cases.
* **Determinism proof:** two separate-process runs of `--phase proto --cases 300`
  and `--phase xml --cases 300` with seed `0xD1A1` produced identical
  `(index, verdict, handler, fault_pc, fault_addr, cb_at_blx, free-list-ok,
  full-input-hex)` tuples (`identical=True` for both, 300/300 cases). The final
  acceptance runs use the same code.

### 1.3 Case execution

| phase | entry | host data |
|---|---|---|
| `xml` | `cmd_loop 0x203C08` (registrar already run) | handshake `OK\0`, then mutated XML (recv truncates at the real `0x800` buffer) |
| `proto` | `DRAM-REPAIR 0x202C7C` or `BOOT-TO 0x201080` | exact frame list queued on `CMD:DOWNLOAD-FILE` (`ScriptedHost(ChainHost)`) |
| `handlers` | direct `handler(SESSION, XML_ADDR)` for all 12 | mutated XML; no download responder |
| `random` | `cmd_loop` or the download protocol | uniform random bytes incl. NULs |

`ScriptedHost` is a small `ChainHost` subclass: on `CMD:DOWNLOAD-FILE` it queues a
pre-computed list of frames. DA1 consumes one frame per `recv`, so the malformed
protocol is delivered in exact order. This does not re-implement the harness.

### 1.4 Classification

Priority: `HANG` > `DATA_ABORT` > `UNMAPPED_IO` > `CB_SET` > `HEAP_CORRUPT` >
`OK_RC`/`ERR_RC`.

* **DATA_ABORT**: emulator stop (`UcError`, mostly `UC_ERR_MAP`) at a non-MMIO
  address. Unicorn 2.1.4 does not report the fault address, so it is recovered by
  disassembling the faulting instruction and evaluating its `[base, #imm]` operand
  from the live registers. Fetch faults use PC.
* **UNMAPPED_IO**: MMIO address (`0x10000000..0x20000000`) **and** the faulting PC
  is not in the allocator/XML/download-parser windows
  (`0x204000..0x20A000`, `0x250000..0x251200`) **and** neither PC nor fault is
  input-derived. This prevents a wild free-list pointer that happens to land in the
  peripheral window from being excused as a UART access (the first run had exactly
  one such case; it is now `DATA_ABORT`).
* **CB_SET**: `dpc->cb` became non-zero and differs from the pre-case value
  (captured at `blx r4` for `cmd_loop`, post-run for direct handlers).
* **HEAP_CORRUPT**: `walk_free_list` did not reach the sentinel, or the forged node
  `0x2DF79C` is present, or a zero/duplicate/out-of-heap/unaligned node, or an
  impossible size (`<0xC` or `>heap_size`), while the handler returned normally.
* **HANG**: loop budget or instruction cap. No other stop is invented.
* **OK_RC/ERR_RC**: handler return 0 / non-zero, or for `cmd_loop` the captured
  handler rc (`0x203FB8`), falling back to `<result>OK</result>`.

### 1.5 Input-derived flag (implemented explicitly)

For every non-OK/ERR case, `input_derived()` scans **every 4-byte window at every
byte offset** of the full host input for:

* PC and fault address (exact, `|1` Thumb bit, `&~1`);
* every register `r0..r12, sp, lr`;
* the small store offsets `+4`, `+8`, `+0xC`, `-4` (a corrupted allocator pointer
  faults at `word+offset`), for all of the above;
* a byte-level test: the little-endian bytes of PC/fault (2, 3 or 4 bytes) appear
  contiguously in the input.

The hit records `(where, relation, word, input_offset)` and is stored per case.
Values below `0x1000` are ignored to avoid trivial small-integer matches. This is
what separates "the DA crashed at a constant" (NULL deref, reset call) from "the DA
crashed at *our* bytes" (exploitability).

### 1.6 Deduplication

The printed table is grouped by `(phase, class, fault_pc, handler/entry)` exactly as
specified, with the distinct `fault_addr` set and the smallest repro per fault
address kept. Console bytes are truncated; the repo/repro JSON has the full input.

---

## 2. Corpus and mutations

### 2.1 XML phase (and the `handlers` arg trees)

Base XML for all 12 registered commands, with plausible argument trees (from the
audit / handler strings): `NOTIFY-INIT-HW`, `SET-HOST-INFO`, `BOOT-TO`,
`REBOOT`, `GET-HW-INFO`, `SET-RUNTIME-PARAMETER`, `HOST-SUPPORTED-COMMANDS`,
`RAM-TEST`, `DRAM-REPAIR`, `WRITE-FLASH`, `ERASE-FLASH`, `READ-FLASH`.

16 mutation operators, applied singly (curated: every command × every operator, 192
cases) or in random combinations of 1–3:

| operator | what it does |
|---|---|
| `truncate` | cut at a random byte |
| `binary` | insert NULs/random bytes (1..0x100) at a random offset |
| `nul` | insert a NUL run |
| `drop-tag` | remove an opening tag / closing tag / whole element |
| `dup-tag` | duplicate a random element |
| `reorder` | swap `<command>` and `<arg>` |
| `int` | replace a numeric token with `0xFFFFFFFF`, `0xFFFFFFFC`, `0x7FFFFFFF`, `0x80000000`, `-1`, `-4`, 20-digit decimal, `0x1000000`, `0x2001`, `0` |
| `long` | replace an element body with 0x80..0x900 bytes |
| `deep` | 32/64/128/200/300 nested `<a>` elements |
| `entity` | `&amp; &#x41; &#0; &bogus; <!ENTITY…> <!DOCTYPE…>` |
| `cdata` | unclosed `<![CDATA[`, `<!--`, stray `]]>`, `-->` |
| `cmd-garbage` | empty/`CMD:`/`CMD:UNKNOWN`/lowercase/overlong/non-ASCII command |
| `dup-command`, `drop-version` | structural duplicates/omissions |
| `oversize` | append `<pad>` elements past 0x800 (cmd_loop truncates at 0x800) |
| `tag-garbage` | `<<`, `<>`, `</>`, stray `>` |

Plus a 10 % random handshake corruption in the `xml` phase. The command name copy in
`cmd_loop` is bounded (0x40) and the version copy is bounded (0x10), so these
mutations cannot overflow those buffers.

### 2.2 Proto phase (download protocol)

Frames are built for the two real `fp_read_host_file` callers only (a full-image BL
scan shows exactly two: `0x2011E4` in BOOT-TO, `0x202D0C` in DRAM-REPAIR).

Curated scenarios include: no reply at all; first ACK missing/short/`OK`/`OK@`/
`OK@0x`/`OK@0xZZ`/`NO`/empty/with garbage; length frame missing, `OK` without `@`,
`OK@`, `OK@0x`, `OK@0xZZ`, `OK@-1`, `OK@-4`, 32-digit decimal, no NUL, junk suffix;
declared `0`, `1`, `0xFF`, `0x10`, `0x3C`, `0x40`, `0x100`, `0x2000`, `0x2001`,
`0xFFFF`, `0xFFFFFF`, `0x1000000`, `0x7FFFFFFF`, `0xFFFFFFFC`, `0xFFFFFFFF`;
declared/delivered mismatch in both directions; zero-length chunk; 0x2000 chunk into
a small buffer; extra chunks; early EOF; repeated `OK` frames; the known HeapBait
L=0x3C/L=0x40 payloads; a 4-byte-overshoot desync that still fires `cb`; and the
BOOT-TO-specific clamp cases (`0x1000000`, `0xFFFFFF`, desync, wrap, non-hex, no
ACK). The remaining cases are randomised around the same axes.

### 2.3 Random phase

Half: random handshake (sometimes `OK`-prefixed) + random XML/body up to 0x900
bytes, including NULs. Half: random download target, declared value, ACK bytes,
length-token bytes, 0–3 random data chunks up to 0x2000 each, and random trailing
frames.

---

## 3. Validation controls (proved before every campaign)

The script runs these first and exits 1 if any fails. Actual output from the final
runs:

```
PASS control-a-known-good     want=OK_RC                 got=OK_RC
PASS control-b-known-bad-cb   want=CB_SET/0xC0DE0001     got=CB_SET/0xc0de0001
PASS control-c-known-abort    want=DATA_ABORT@~DEADBEF3  got=DATA_ABORT@0xdeadbef3
all 3 controls PASS
```

* **(a)** valid `CMD:SET-HOST-INFO` through the real `cmd_loop` ⇒ handler
  `0x20173C` called, `rc=0`, `OK_RC`.
* **(b)** `CMD:DEBUG:DRAM-REPAIR`, fake header
  `{0xDEADBEEF, 0x2DF79C, 0xC0DE0001}` at L=0x3C ⇒ `CB_SET`, target
  `0xC0DE0001`, marked known-HeapBait.
* **(c)** same header at L=0x40 ⇒ `DATA_ABORT` at PC `0x204430`
  (`str r0,[r3,#4]`), fault **`0xDEADBEF3`** = `0xDEADBEEF + 4`.

A **baseline table** of 24 unmutated runs (12 commands through `cmd_loop` + 12
direct handlers) is built before the campaign. A crash that matches a baseline
`(entry, class, pc, fault)` is flagged `BASELINE` and excluded from new findings.
This is how the expected peripheral faults were kept out of the new-findings count:

| baseline | PC | fault | meaning |
|---|---|---|---|
| `NOTIFY-INIT-HW` | `0x2448B8` | `0x11017048` | UART TX register (write) |
| `GET-HW-INFO` | `0x241344` | `0x100268A8` | on-chip peripheral read |
| `BOOT-TO` | `0x252F28` | `0x1000108C` | SHA-256 clock gate (hardware engine) |

The `BOOT-TO` SHA path is the only place where a model is used. In `xml`/`handlers`
it is not installed, so BOOT-TO with a valid address faults at the clock gate (the
same emulation gap documented in `da1_fixed_stage.py`). In `proto_bootto` the
existing `install_sha_engine` hashlib model is installed (labelled `[DEV]`) so the
download path can finish and be classified; this does not affect the download code
under test.

---

## 4. Results

### 4.1 Primary run — seed `0xD1A1`, 2000/phase (8,000 cases, 174 s, exit 0)

```
phase     OK_RC  ERR_RC  DATA_ABORT  HEAP_CORRUPT  CB_SET  HANG  UNMAPPED_IO  HARNESS_ERROR
xml          58    1810        0            0           3      0       129           0
proto       552    1109      332            1           6      0         0           0
handlers    167    1518        0            0           3      0       312           0
random       21    1929       50            0           0      0         0           0
TOTAL       798    6366      382            1          12      0       441           0
```

`UNMAPPED_IO` is entirely the three baseline sites (441/441 flagged `BASELINE`).
`HANG = 0`: the loop budget and the 10M-instruction cap were never reached by a true
loop (the earlier 0.5M/2M caps produced false HANGs on finite deep XML; see §10).

### 4.2 Second run — seed `0x1234`, 500/phase (2,000 cases, 40 s, exit 0)

```
phase     OK_RC  ERR_RC  DATA_ABORT  HEAP_CORRUPT  CB_SET  HANG  UNMAPPED_IO  HARNESS_ERROR
xml          18     448        0            0           0      0        34           0
proto       149     265       84            0           2      0         0           0
handlers     41     385        0            0           3      0        71           0
random        3     480       17            0           0      0         0           0
TOTAL       211    1578      101            0           5      0       105           0
```

No harness errors, controls PASS, same new classes, same baseline sites.

### 4.3 New-vs-known split (primary run)

| category | cases | note |
|---|---:|---|
| ok / err | 7,164 | normal |
| baseline MMIO | 441 | UART / peripheral / SHA clock gate |
| **new: length desync** | **145** | 97 input-derived, 72 distinct (PC, fault) pairs |
| **new: NULL deref** | **197** | 5-byte trigger, fault 0 |
| **new: silent heap corrupt** | **1** | returns `0xC0010001`, free list already broken |
| **new: fixed reset call** | **6** | known audit path, confirmed |
| known HeapBait | 46 | exact-fit `cb` fire and L=0x40 abort, incl. the desync 4-byte variant |

Length-desync sub-patterns (145 cases):

* **integer wrap** (declared `0xFFFFFFFC`/`0xFFFFFFFF`): **66** cases;
* **positive overshoot** (delivered > declared): **79** cases, overshoot
  **15 … 16,368 bytes**, median **2,032**;
* fault PC distribution: `0x20872C` 58, `0x2043CC` 37, `0x204430` 27,
  `0x20441C` 15, `0x204400` 8.

All 197 NULL derefs are `pc=0x20558C`, `fault=0`, and are **not** input-derived
(the address is a constant NULL; the *trigger* is input).

---

## 5. Deduplicated interesting cases (exact bytes)

All repro paths are under `/tmp/opencode/da1_fuzz_cases/`; each JSON contains the
full frames and a `--replay`-able spec. Console bytes are abbreviated here only
where marked.

### 5.1 `F1` — desync → read through a payload pointer (34 bytes)

Transcript (frames in order): first ACK `OK@0xZZ\0`, length `OK@0x1\0`
(declared **1**), chunk ACK `OK\0`, data **16 × `41`**.

```
f0  4f4b4030785a5a00                 "OK@0xZZ\0"
f1  4f4b4030783100                   "OK@0x1\0"      declared = 1
f2  4f4b00                           "OK\0"
f3  41414141414141414141414141414141 16 × 'A'        delivered = 16
```

`malloc(1+4)` → chunk `0x14`, user capacity `8`; the 16-byte frame overwrites the
next chunk header. Later `insert()` executes `0x20441C  ldr r3,[r1]` with
**`r1 = 0x41414141`** → `DATA_ABORT`, fault **`0x41414141`**. Input-derived:
`fault eq r1 <- in[0xe] = 0x41414141`.

Repro: `proto_DATA_ABORT_e00202c7c_pc0020441c_fa41414141_i1689.json`

### 5.2 `F1` — desync → **write** through a payload pointer (145 bytes)

```
f0  4f4b40                            "OK@"
f1  4f4b40363400                      "OK@64\0"      declared = 64 (decimal)
f2  4f4b00                            "OK\0"
f3  41 × 0x41                         'A' × 65       delivered = 65
f4  4f4b00                            "OK\0"
f5  41 × 0x41                         'A' × 65       delivered = 130 total
```

`0x204430  str r0,[r3,#4]` with **`r3 = 0x41414141`** → fault **`0x41414145`**
(`r3+4`). The stored value `r0` is the current free-list node; the address is ours.
Input-derived: `fault -0x4 <- in[0xe] = 0x41414141`.

Repro: `proto_DATA_ABORT_e00202c7c_pc00204430_fa41414145_i702.json`

### 5.3 `F1` — both write address **and** value from the payload (362 bytes)

```
f0  4f4b403078                        "OK@0x"
f1  4f4b40363000                      "OK@60\0"      declared = 60 (decimal)
f2  4f4b00                            "OK\0"
f3  41 × 16                           'A' × 16
f4  4f4b00                            "OK\0"
f5  7d1768b304a6c2641a9e9be438f87f81c6dd8fb13911a79dcfe16bf6ea6e0586
    21cadcc0aa97e4e7e4af7f863e21f7c9eb56dab2cc6850602a6b3393035cadc1
    (64 random bytes; carried verbatim)
f6  4f4b00                            "OK\0"
f7  00 × 0x40, then efbeadde 9cf72d00 0100dec0, then zeros (256 B)
f8,f9  4f4b00 4f4b00
```

Declared 60, delivered 336 (overshoot 276). The 64-byte `f5` straddles the next live
chunk header at `D+0x40`: `f5[52:56] = 0x605068CC` becomes the chunk's `node`,
`f5[56:60] = 0x93336B2A` becomes its `size` (input offsets `0x55`/`0x59` in the
whole input). `free(victim)` executes `0x2043CC  str r1,[r0,#8]`:

```
r0 = 0x605068CC   (payload, in[0x55])   -> write address
r1 = 0x93336B2A   (payload, in[0x59])   -> write value
fault = r0+8 = 0x605068D4
```

This is a **write-what-where with both operands controlled by host bytes**, subject
only to the freed chunk's header being the 12 bytes we planted. The fault is an
unmapped target, not a missing primitive.

Repro: `proto_DATA_ABORT_e00202c7c_pc002043cc_fa605068d4_i683.json`

### 5.4 `F1` — large desync → free-list write in `mxmlDelete` (272 bytes)

```
f0  4f4b                            "OK"
f1  4f4b403100                      "OK@1\0"        declared = 1
f2  4f4b00                          "OK\0"
f3  41 × 0x100                      'A' × 256       delivered = 256
f4,f5 4f4b00 4f4b00
```

`0x20872C  strne r3,[r2,#4]`, `r2 = 0x41414141` → fault **`0x41414145`**.
Input-derived. This is the post-download `mxmlDelete`/free-list path writing through
a link taken from the heap, which the overflow filled with our bytes.

Repro: `proto_DATA_ABORT_e00202c7c_pc0020872c_fa41414145_i164.json`

### 5.5 `F2` — integer wrap (92 bytes)

```
f0  4f4b                            "OK"
f1  4f4b403078666666666666666600    "OK@0xffffffff\0"   declared = 0xFFFFFFFF
f2  4f4b00                          "OK\0"
f3  1ed614eb d00e2e60 a2221863 7877f025 5f3fb077 a349066f
    fc1ad147 4f979d4b 40d1c696 6f76b3f9 515ba0ae 3932be8a
    bcf4b41a 8b78715f 4bbbfe0f e5fcaa64                  (64 random bytes)
```

`malloc(0xFFFFFFFF + 4)` wraps to `malloc(3)` → chunk `0x10`, user capacity 4; the
64-byte frame overruns it immediately. `0x20441C ldr r3,[r1]`, fault
**`0x631822A2`** (input-derived). 39 cases used `0xFFFFFFFC`, 27 used
`0xFFFFFFFF`.

Repro: `proto_DATA_ABORT_e00202c7c_pc0020441c_fa631822a2_i1951.json`

### 5.6 `F3` — NULL deref in the length parser (5 bytes)

```
f0  4f4b        "OK"        first ACK (passes the OK check)
f1  4f4b00      "OK\0"      second frame, no '@'
```

The tokenizer `0x2037F4` splits on `@`; with no `@`, the second-token pointer stays
`0` (the stack was zeroed), and `0x205584` starts with `ldrb ip,[r0]` → PC
**`0x20558C`**, fault **`0`**. Reliable DA data abort: 5 host bytes.

Repro: `proto_DATA_ABORT_e00202c7c_pc0020558c_fa00000000_i315.json`

### 5.7 `F4` — silent free-list corruption (8,244 bytes)

Declared `0x2001` (8193), delivered 8208 (16 random + 0x2000 zeros): the 16-byte
first chunk is followed by 0x2000 zeros, which overwrite the next header with zeros.
The handler returns **`0xC0010001`** (no exception), but the free list is already:

```
count=3  sentinel_reached=False  zero_link=True
[0x2E919C/0x4C, 0x2E??/0x4B4F, 0x40000000/None]   (node 0x40000000 is outside the heap)
```

The next malloc/insert will dereference a bogus node. This is a **silent**
corruption class the existing classifier would have reported as a plain error.

Repro: `proto_HEAP_CORRUPT_e00202c7c_pc00000000_fa00000000_i1318.json`

### 5.8 `F5` — desync reaches the `cb` fire (declared 0x3C, delivered 0x50)

`make_payload(0x3C, 0x40000000) + "AAAA"`:
the known lazy header at `D+0x40` still lands on the live victim chunk, 4 bytes past
the exact-fit length. `free(victim)` sets **`dpc->cb = 0x40000000`** and the handler
returns; free list broken (`CB_SET`, flagged known-HeapBait because it is the same
fire primitive). With 0x60+ bytes delivered the DA instead dies in `insert`
(`0x20872C`) before the victim is freed — see §8 for why the extra bytes matter.

Repro: `proto_CB_SET_e00202c7c_pc002040d4_fa40000000_i1430.json` (curated
`desync-cb-L3c-overshoot4`).

### 5.9 `K1` — malformed BOOT-TO arms the fixed reset call (208 bytes)

```xml
<?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>
<command>CMD:BOOT-TO</command><arg><at_address>0x</at_address>
<jmp_address>0x40000000</jmp_address><source_file>da2</source_file></arg></da>
```

`at_address` parses to 0, the `0x40000000` gate fails, and the error path
(`0x201154..0x201180`) stores **`dpc->cb = 0x251C58`**. Through `cmd_loop` this is
`CB_SET` (target `0x251C58`). With a *normal* trailing ACK, cmd_loop actually
`blx`es there; the function reads/writes the reset controller at
`0x10007024` (PC `0x24EAF0`), i.e. the DA performs its "reset" path. Fixed target,
not attacker-controlled → DoS only. This path is documented in
`re-da1-hash-patch-audit.md` §3.1; the fuzzer confirms it independently.

Repro: `xml_CB_SET_e00000000_pc002040d4_fa00251c58_i985.json`

### 5.10 `K2` — known HeapBait, reproduced

* L=0x3C, header `{0xDEADBEEF,0x2DF79C,0xC0DE0001}` → `CB_SET` target
  `0xC0DE0001` (control b).
* L=0x40, free-remainder poison → `DATA_ABORT` PC `0x204430`, fault
  `0xDEADBEF3` (control c).
* 46 campaign cases are this class (18 × `0xDEADBEF3`, 10 × `0x4` at
  `0x204430`, 8 × `0x4` at `0x204400`, 3 × cb=`0x40000000`, 3 × cb=`0xC0DE0001`,
  plus variants). They are **excluded** from the new-findings count.

---

## 6. Input-derived analysis

* **97 of the 349 new cases** have a PC/fault/register value that appears as a
  4-byte word in the host input (all of them in the length-desync class).
* The clean demonstrators:
  * `0x41414141` → `r1`/`r3` → fault `0x41414141` (read, `0x20441C`);
  * `0x41414141` → fault `0x41414145` (write, `0x204430`, `r3+4`);
  * `0x41414141` → fault `0x41414145` (write, `0x20872C`, `r2+4`);
  * random words e.g. `0x381f8473` → fault `0x381f8477`; `0x1d3bd496` →
    fault `0xe1f7a4fc` (via a different register/link, recorded in the JSON);
  * `0x605068CC`/`0x93336B2A` → *both operands* of the free-core write
    (`0x2043CC`).
* **Not input-derived:** the NULL deref (`0x20558C`, fault 0) and the fixed reset
  call (`0x251C58`). These are reliable DoS, not memory-control signals.
* The known L=0x40 abort fault `0xDEADBEF3` is derived from the *constant*
  `0xDEADBEEF` fake magic plus 4, not from the payload being the current input in
  the same sense; it is flagged `KNOWN-HEAPBAIT` and excluded.

Exploitability signal: in the desync cases the DA is not merely reading/writing
near the heap — it is dereferencing **our 32-bit values as pointers**. With the
free-core write both the address and the value are ours.

---

## 7. Length-trust map (which code trusts which length, and where it is clamped)

Only two functions call `fp_read_host_file 0x2500D8` (full-image BL scan):
`BOOT-TO 0x2011E4` and `DRAM-REPAIR 0x202D0C`. The other ten commands never see a
download length.

`fp_read_host_file 0x2500D8`:

1. Sends `CMD:DOWNLOAD-FILE`, receives a 0x40-byte ACK and requires `"OK"`.
2. Receives a second 0x40-byte frame, tokenizes on `@`, parses token 2 with
   `0x205584` (**decimal, `0x`-hex, optional `-`; no range check; no NULL check**).
   A missing `@` leaves the token pointer NULL → `F3`.
3. **Destination-dependent sizing:**
   * `dest == 0` (**DRAM-REPAIR**): `malloc(declared + 4)` — **32-bit add, no upper
     bound**. `0xFFFFFFFC..0xFFFFFFFF` wraps to `malloc(0..3)` → `F2`.
   * `dest != 0` (**BOOT-TO** passes `dest=0x40000000`, `max=0x1000000`): if
     `max <= declared` → error `"too big"`; else `*len = declared`. So BOOT-TO’s
     declared length is clamped to `< 0x1000000`.
4. Sends `OK\0`, then loops: receive an ACK frame, require `"OK"`, send `OK\0`,
   `recv(base + r7, packet_length)` with **`packet_length` (0x2000), never
   `min(packet_length, declared - r7)`**, then `r7 += recv_len` and loop while
   `r7 != declared` (**equality, not `>=`**).
5. On `r7 == declared`: `base[declared] = 0`, return 0. Any overshoot can never
   satisfy equality, so the loop keeps writing until the host stops or a receive
   fails.

`BOOT-TO 0x201080`:

* hard-gates `at_address == jmp_address == 0x40000000` (`0x20113C`);
* ignores the **return value** of `fp_read_host_file` (`0x2011E8` deletes the XML
  and falls through to SHA-256 over `[0x40000000, len)`), so a failed download still
  hashes the full 16 MiB window with the default length 0x1000000;
* invalid-address path sets `dpc->cb = 0x251C58` and returns `0xC0010001` (`K1`);
* success path sets `dpc->cb = 0x40000000`, `dpc->arg = 0x2DE180` (the existing
  fixed-stage chain).

`RAM-TEST 0x202590`:

* parses `function` (`FLIP`/`MAX`/`CALIBRATION`), `start_address`, `length` as
  64-bit values and **bounds-checks them against a DRAM window read from
  `0x2DE548+0x10/+0x14`** (`0x2027D0`); out-of-range is rejected before any access.
  No arbitrary read/write from XML here.

`cmd_loop 0x203C08`:

* XML buffer is a fixed `0x800` malloc; `recv(buf, 0x800)` truncates;
* command name is copied into a `0x40` stack buffer with a bounded copy
  (`0x209358`, len 0x40); version into `0x10`; registry compare is bounded.
  This is why 2,000 mutated XML documents (including 0x900-byte values and
  300-deep nesting) produced no memory corruption.

Other handlers: `SET-RUNTIME-PARAMETER` uses a fixed whitelist table
(`0x263494`) and a fixed global; `WRITE-FLASH`/`ERASE-FLASH`/`READ-FLASH` do not
call the host download and operate on flash/partition names; `NOTIFY-INIT-HW`,
`SET-HOST-INFO`, `REBOOT`, `GET-HW-INFO`, `HOST-SUPPORTED-COMMANDS` have no
host-length input. None of them produced a new memory-safety class.

---

## 8. Why the desync is stronger than the known HeapBait — and its limit

Known HeapBait: `malloc(declared+4)` must consume an **exact-fit** free node, so the
12-byte fake header written at `D+capacity` lands exactly on the **next live chunk
header**; when `mxmlDelete` frees that victim, `free()` does
`*(fake_node+8) = fake_size` and `dpc->cb` fires. If the malloc splits a larger
node, the fake header lands in the free remainder and `insert()` crashes first
(the L=0x40 control).

Desync: the host can deliver a chunk **larger** than the declared remainder, so the
write is not limited to 12 bytes. Observed consequences:

* the 12-byte header at the victim position can be **any 12 payload bytes**, and
  the fuzzer reached `*(r0+8)=r1` with **both r0 and r1 from the payload**
  (`0x2043CC`), i.e. the known fire write generalises to write-what-where;
* *however*, the same large write also overwrites the free remainder above the
  victim. `free(param_buf)` calls `insert()`, which walks that remainder **before**
  `mxmlDelete` frees the victim. A naive 0x2000-byte payload (e.g. `'A'`) therefore
  dies in `insert` (`0x20441C`/`0x204430`) or later in `mxmlDelete` (`0x20872C`)
  instead of firing `cb`. This is exactly what the 145 crash cases show.
* A **small** overshoot keeps the remainder usable: declared 0x3C + delivered 0x50
  still fires `cb=0x40000000` (`F5`). So the desync is not a free pass that removes
  all heap-shaping; it removes the *12-byte size* restriction and gives full
  content control of the overflow, at the cost of having to keep the intervening
  free-list consistent.

To turn `F1` into a reliable `cb`/hash-slot write you must therefore spray the
0x2000 region as a **consistent free list** (valid sentinel links, plausible sizes)
while placing the forged header at the header of a chunk that is later freed, or
use the proved small overshoot on a known exact-fit hole.

---

## 9. Ranked “what is worth turning into an exploit next”

| # | primitive | evidence | confidence | why / next step |
|---|---|---|---|---|
| 1 | **Desync → arbitrary 32-bit write** (`free` core `*(r0+8)=r1`, both from payload) → `dpc->cb` (`0x2DF7A4`) or DA2 hash slot (`0x2688CC`) | `F1` §5.1–5.3; r0/r1 = `0x605068CC`/`0x93336B2A` from input; 97 derived cases | **High** that the write is reachable and controlled; **Medium-High** for a reliable fire on a new build | Craft the overflow as a valid free list (sentinel `0x2DF7D8`, `+0/+4/+8` links, sizes) and put `{0xDEADBEEF, 0x2DF79C, 0x40000000}` on a chunk that `mxmlDelete` frees. This reuses the fixed-stage stub at `0x40000000`; no exact-fit scan needed. |
| 2 | **Integer wrap** declared `0xFFFFFFFC`/`0xFFFFFFFF` → tiny malloc + 0x2000 write | `F2` §5.5; 66 cases | **High** for corruption/DoS; **Medium-High** for control | Guarantees a tiny buffer regardless of heap chunk sizes; combine with #1’s free-list spray. Good fallback when no exact-fit hole exists. |
| 3 | **Silent free-list poison** (small overshoot) | `F4` §5.7 | **High** for next-malloc abort; **Low** for control | Useful as a one-shot DA reset or to force a re-upload; not a write primitive by itself. |
| 4 | **NULL deref in the length parser** (second ACK without `@`) | `F3` §5.6 | **High** DoS; **Low** exploitability | 5-byte reliable DA abort. Not a memory-control bug: fault address is 0. |
| 5 | **Malformed BOOT-TO → fixed reset call** `0x251C58` | `K1` §5.9 | **High** DoS; **Low** exploitability | Fixed target, reset-controller MMIO `0x10007024`; already in the audit. |
| 6 | XML name/value/tag/nesting fuzzing | 2,000 cases/phase, no new crash | **High** that this surface is bounded (0x40/0x10/0x800 copies) | Not worth more fuzzing effort unless a new command/handler is added. |

The known exact-fit HeapBait (L=0x3C) still works and is the shortest path to
`cb=0x40000000` on the current emulated heap; the desync is the better bet when the
heap layout is unknown (other build/device) because it does not depend on finding an
exact-fit hole and it gives a stronger write.

---

## 10. Limitations and honesty notes

* **Emulation, not silicon.** No device was touched. `[?]` items: real USB packet
  boundaries/timing, the I-cache/clean behaviour of `0x40000000`, and whether the
  heap layout on 420EX01 matches 200EX01.
* **SHA-256 is modelled** (hashlib) for `proto_bootto`, exactly as in
  `da1_fixed_stage.py`; the native `0x2522C4` needs the crypto block. The download
  code under test is native. In `xml`/`handlers` the model is not installed, so
  BOOT-TO with a valid address faults at the clock gate (flagged baseline).
* **MMIO is not modelled.** Expected peripheral faults (UART `0x11017048`,
  `0x100268A8`, SHA clock gate `0x1000108C`, reset controller `0x10007024`) are
  classified `UNMAPPED_IO` only at known driver PCs and only when not
  input-derived. A wild pointer that lands in the peripheral window from the
  allocator/XML code is still `DATA_ABORT`.
* **Instruction cap.** The first runs used 0.5M/2M and produced false `HANG`s on
  finite deep-XML cases (a 300-deep + duplicated `<da>` document needs >2M
  instructions but returns in ~0.16 s). The final cap is 10M; no true hang was
  found. A hostile XML larger than the 0x800 `cmd_loop` buffer cannot reach the
  parser on the real command path, so this is not a device DoS.
* **No controlled code execution was observed.** The `CB_SET` from heap data is
  the known HeapBait (plus the 4-byte-overshoot variant). The desync’s arbitrary
  write was observed as aborts at input-chosen addresses, not yet converted into a
  controlled `cb`. Do not read this report as “RCE proved”.
* **New vs known.** The unclamped per-chunk recv is already noted in
  `re-da1-hash-patch-audit.md` §3.1 as the HeapBait overflow; `0x251C58` is in §3.1
  as well. What is new here is the **declared/delivered desync as a distinct
  unbounded-overflow class**, the **integer wrap**, the **NULL deref**, the
  **silent corruption**, and the **both-operand free write** evidence. The root
  cause of `F1`/`F5` is shared with the known bug and is stated as such.
* **Runtime cap.** The whole campaign finished in 174 s (seed 1) / 40 s (seed 2),
  far below the 15 min cap; no automatic `--cases` reduction was needed. The
  per-phase clock would have truncated and printed `[TIME-CAP]` if it had.

---

## 11. Reproduction / acceptance evidence

Environment: `/tmp/opencode/da1venv/bin/python` (Unicorn 2.1.4, capstone 5.0.7).

```bash
# primary acceptance run: 8000 cases, 174 s, exit 0
/tmp/opencode/da1venv/bin/python docs/notes/da1_fuzz.py \
  --image docs/notes/rmx3630-da2/da1_allinone.bin \
  --phase all --cases 2000 --json /tmp/opencode/fuzz.json
# exit 0; controls a/b/c PASS; 0 harness errors; HANG 0

# second seed: 2000 cases, 40 s, exit 0
/tmp/opencode/da1venv/bin/python docs/notes/da1_fuzz.py \
  --image docs/notes/rmx3630-da2/da1_allinone.bin \
  --phase all --seed 0x1234 --cases 500 --json /tmp/opencode/fuzz2.json
# exit 0; controls a/b/c PASS; 0 harness errors

# determinism: same seed twice, separate processes, identical per-case tuples
# (300 proto + 300 xml, 2 runs each) -> identical=True, 300/300

# replay one minimal repro
/tmp/opencode/da1venv/bin/python docs/notes/da1_fuzz.py \
  --replay /tmp/opencode/da1_fuzz_cases/proto_DATA_ABORT_e00202c7c_pc0020441c_fa41414141_i1689.json
# -> REPRODUCED (same verdict, pc, fault)
```

Existing scripts re-verified after the campaign (all exit 0):

```bash
/tmp/opencode/da1venv/bin/python docs/notes/da1_fixed_stage.py \
  --image docs/notes/rmx3630-da2/da1_allinone.bin        # RESULT: PASS, exit 0
/tmp/opencode/da1venv/bin/python docs/notes/da1_heap_sweep.py \
  --image docs/notes/rmx3630-da2/da1_allinone.bin --lo 0x3c --hi 0x3c
                                                          # fired: 0x3c, exit 0
/tmp/opencode/da1venv/bin/python docs/notes/da1_emu.py \
  docs/notes/rmx3630-da2/da1_allinone.bin                # demo ok, exit 0
```

Artifacts:

| item | path |
|---|---|
| fuzzer | `docs/notes/da1_fuzz.py` |
| report | `docs/notes/da1_fuzz_report.md` |
| primary JSON (18.4 MB) | `/tmp/opencode/fuzz.json` |
| second-seed JSON | `/tmp/opencode/fuzz2.json` |
| repros (smallest per phase/class/pc/entry, one per distinct fault) | `/tmp/opencode/da1_fuzz_cases/` (54 files), `/tmp/opencode/da1_fuzz_cases2/` |
| campaign logs | `/tmp/opencode/full.log`, `/tmp/opencode/full2.log` |

`--json` defaults to `docs/notes/da1_fuzz_results.json` per the CLI contract, but
the acceptance runs above pass explicit `/tmp` paths so no generated JSON is added
to the repo.
