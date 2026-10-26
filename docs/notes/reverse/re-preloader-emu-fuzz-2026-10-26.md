# RE: Unicorn emulation and fuzzing of the 2710EX01 preloader DA authentication

Date: 2026-10-26. Offline, no device, no flashing, no network.
Scope: the **preloader** stage only (`usbdl → DAA → jump_da`), i.e. the exact
code that decides whether a DA1 is jumped to. Follow-up to
`re-da1-2710-daswap-2026-10-25.md`.

Deliverables:

| what | path |
|---|---|
| emulator + harness + fuzz CLI | `docs/notes/pre_emu.py` |
| this report | `docs/notes/reverse/re-preloader-emu-fuzz-2026-10-26.md` |
| fuzz JSON (2000 cases) | `/tmp/opencode/pre_fuzz_2000.json` |
| repros (118 files) | `/tmp/opencode/pre_fuzz_cases/` |
| acceptance log | `/tmp/opencode/pre_emu_accept_final.log` |

Target (sha256 measured here):

| tag | path | size | sha256 |
|---|---|---|---|
| preloader 2710 | `/tmp/opencode/fw2710/preloader_k6789v1_64.bin` | 0x5F8D4 | `677d1febbbf10e4fcb77fd41e2615b23d705a87d344bfb06af9d93e4ccc7e22f` |
| DA container 2710 (K2) | `/tmp/opencode/fw2710/DA_BR.bin` | 0xC0BF0 | `2e15a832b58e500505b785c1bb2817c77614b1c7475b2c84511015fa9e65d245` |
| DA container 200EX01 (K1) | `docs/notes/rmx3630-da2/DA_BR.bin` | 0xBFA80 | `abee43e8abc67de86c5f4e20eb58f8665cb560fa38ce1b135aa7c0f97ca8007c` |

Tooling: `python /tmp/opencode/da1venv/bin/python` (Python 3.13, unicorn 2.1.4,
capstone 5.0.7), no other dependencies.

---

## 0. TL;DR — verdict table

| # | question | answer | evidence |
|---|---|---|---|
| 1 | Is the 2710 DA auth bypassable by an input the preloader parses? | **No** | 2000 fuzz cases, **0 ACCEPT_INVALID**. Every mutated signature/message/length got `0x7024` or a length error. Only the byte-exact K2-signed DA1 sets `*(0x2F3158)`. |
| 2 | Does the real 2710 DA1 validate in the emulator? | **Yes** | `A_VERIFY_BLOCK` at `0x20868C` → `r0=0`, flag `0x2F3158=1`, 26 555 instructions, 1 RSA public op. Also through the real USB command loop (`0xD7`). |
| 3 | Does the 200EX01 DA1 fail with `0x7024`? | **Yes** | Same path: `r0=0x7024`, flag 0, both function-level and `0xD7` protocol-level. |
| 4 | Is the key rotation real (K1↔K2)? | **Yes, both directions** | PSS primitive matrix: K2/2710 ACCEPT, K2/200 `0x102005`, K1/2710 `0x102005`, K1/200 ACCEPT. |
| 5 | Is the 0xBC container header authenticated? | **No** | 72 header-mutated cases (magic/da_ver/hwcode/subcode/hw_ver) still ACCEPT **because the same signed DA1 was fed**. Whole-container input and `DA1‖DA2` both reject. |
| 6 | Can a malformed input write out of bounds? | **No additional OOB found** | The error-tail `memset(fp,0,da_len)` at `0x208754 → 0x23872A` always equals the length the USB receive (`0x208432`) already wrote into the same buffer. `da_len > 0x400000` asserts at `0x2083E2` before verify. |
| 7 | Are there crashes/DoS? | **DoS yes, crash no** | 87 HANGs in 2000 protocol/fuzz cases: self-branch dead loop `0x2370C8`, `assert()` `0x231FC8`, and handshake wait `0x2394A4/0x239500`. 0 CRASH. |
| 8 | Is there a *configuration* bypass? | **Yes, by design** | sec mode 0 → `is_daa_enabled(1)==0` → the `usbdl_vfy_da:disabled` branch sets the flag without verification. It is fuse/seccfg policy, **not** USB input. Mode `0x11` verifies. |
| 9 | Does the write-side DA-version floor / seccfg path matter? | **Not reachable from DA input** | The command loop's direct callees do not include `0x230C5C` or `0x2378AC`; they run in sec-lib init / the seccfg path. Enforcement point stays UNKNOWN, as in the 2026-10-25 note. |

**Bottom line: in the emulator the 2710 DA auth holds.** The effective binding is
still the K2 modulus. The unsigned container header is a *binding* weakness (no
SoC/subcode binding at this stage), not a signature bypass: a wrong-key or
mutated DA never runs.

---

## 1. Load base and memory map (re-derived, not inherited)

`parse_gfh` reads `GFH_FILE_INFO` at file 0 and returns
`load_addr=0x200F00`, `total_size=0x5F8D4`, `max_size=0x80000`. The independent
literal↔string score (count how many printable-string VAs occur verbatim as
32-bit literals, for candidate bases 0x1FF000..0x202000 step 4) peaks at:

```
score 1745  base 0x200F00
score  100  base 0x200F10
score   91  base 0x200EFC
```

So `VA = file_offset + 0x200F00`, consistent with the 2026-10-25 note. The ARM
entry is file 0x104 (`b 0x201020`; the four bytes at file 0x100 are padding),
and the preloader's own init jumps to Thumb main `0x22852C`.

Memory map used by the harness:

| range | size | use |
|---|---|---|
| `0x00080000..0x00100000` | 0x80000 | low peripheral block (e.g. `0x081A78` polled during USB init) |
| `0x00100000..0x001F0000` | 0xF0000 | BROM boot-args scratch |
| `0x001F0000..0x00310000` | 0x120000 | SRAM: image at 0x200F00, BSS 0x2F1000..0x2FB848, heap 0x2F6770..0x2F7770, harness stack 0x2FF800 |
| `0x08000000..0x09000000` | 0x1000000 | top-MISC (`0x8000000` register block used by the non-DA path) |
| `0x10000000..0x14000000` | 0x4000000 | USB/UART/GPT/PMIC/eFuse/HACC MMIO |
| `0x40000000..0x42000000` | 0x2000000 | DRAM; function-mode DA buffer at `0x40000000`, protocol receive buffer at `0x40200000` |

Boot mode additionally maps `0x0..0x80000` (BROM ROM, the preloader copies
0x93C bytes from address 0 at `0x22855A`) and `0x0C000000..0x0D000000` (EMI /
DRAMC). The function and protocol harnesses deliberately do **not** map address
0, so a NULL dereference is still a real CRASH there.

---

## 2. Emulator design

`PreloaderEmu` loads the image unmodified and executes the real verify code.
Only device-facing boundaries are replaced, and they are replaced at the
*narrowest* boundary that keeps the arithmetic identical:

### 2.1 HACC (crypto accelerator at `0x10210000`)

The first attempt let the firmware drive the HACC registers; it immediately
hung in the register poll at `0x2441B0` (`ldr r2,[r5,#0xe9c]; lsls; beq`), and
the plain `udelay` path later hung at `0x239556`. A second attempt to keep the
register model produced the same class of failure. Per the anti-loop rule the
approach was changed: HACC is modelled at its **software API** instead.

| VA | operation | shim |
|---|---|---|
| `0x241834` | SHA-256 init(ctx) | shadow context keyed by ctx pointer |
| `0x241850` | SHA-256 update(ctx, data, len) | append to shadow |
| `0x241910` | SHA-256 final(ctx, out) | `hashlib.sha256(shadow).digest()` |
| `0x2439CE` | SHA-256 one-shot(data, len, out) | `hashlib.sha256(data)` |
| `0x243C24` | RSA-2048 public op (sig, key, out) | `pow(int(sig,LE),65537,int(key,LE))` |

The call sites `0x241770` (hash dispatch), `0x24178E` (RSA wrapper),
`0x2417AE`/`0x2414B8` (PSS core), `0x237938` (thunk `cmp r3,#0x100`) and
`0x23794C` (key install) execute as real code. The bytes handed to the shims
were checked against Python: the message digest equals
`sha256(DA1[:-0x100])`, and the RSA output is the same integer the hardware
would produce. Only timing differs.

### 2.2 sec_lib bump allocator

The PSS core allocates four 0x100-byte buffers through `0x2412F8`. That routine
is a bump allocator over a fixed arena:

```
base   = 0x237EB0() = 0x2F6770
offset = *(0x2FB758)
limit  = *(0x2FB75C)
if offset + align(size) > limit: fail
return base + offset; *(0x2FB758) = offset + align(size)
```

The harness seeds `0x2FB758=0`, `0x2FB75C=0x1000` (the arena the getters
`0x237EA0/0x237EA8/0x237EB0/0x237EB8` advertise). Without this the PSS core
returns `-1` at `0x24154A` (first malloc failure) — the emulator reproduces the
real `pkcs_1_pss_decode_sha256` "fail to allocate memory for DB" path.

### 2.3 sec policy

`0x241172` is `is_daa_enabled`: it dereferences `*(0x2FB688)` and reads a mode
word. The harness seeds `0x2FB688 → 0x2FA200` with `[0x2FA200]=0x11`
("verification enabled", the locked retail case). Mode `0x00` is the factory
`usbdl_vfy_da:disabled` branch (demonstrated separately with `--mode gate`).
Mode `0x22` asks the SBC/secure-boot state at `0x2432BC`; with our unblown
eFuse model it returns 0, which is the correct behaviour for a model without
the SBC fuse bit. This is why the verdict table says the *locked* case is
`0x11`, not `0x22`.

### 2.4 Other stubs and hooks

* `0x23582C` printf and `0x20882C` USB status reply are stubbed (they need the
  UART and the USB endpoint, neither of which contributes to the verdict).
  Their format strings were not needed for classification.
* `0x23872A` memset is real code; a hook records `(dst, val, len, caller LR)`
  when the write-side audit is enabled.
* `0x208742` (verdict return) records `r0` and stops on an error; on success it
  continues to `0x20876A`, where the `strb #1 → *(0x2F3158)` executes, then
  `0x208770` stops and the flag is read back.
* `0x231FC8` (`assert`) is hooked so an assert is reported as HANG instead of
  spinning.
* Unmapped accesses are hooked and reported as CRASH with access type, address,
  size and PC.
* Every case gets a **fresh `Uc`**; the image is re-loaded and the BSS is
  zeroed. The only mutable state carried between cases is the Python RNG.
* Budgets: 3 M instructions (function mode), 8 M (protocol), 20 M (boot).
  Determinism is instruction-count based; there is no wall-clock input.

### 2.5 MMIO

Reads are deterministic. The only non-zero modelled registers are:

| address | value | why |
|---|---|---|
| `0x10017008` | free-running counter, `+0x100` per read | `mdelay`/time checks |
| `0x11002014`, `0x11003014` | `0x60` | UART LSR: THRE/TEMT |
| `0x1000801C` | `1` | GPT status |
| `0x10210E9C`, `0x10210E98` | `0xFFFFFFFF` | HACC status (only if the API shim is bypassed; normally never read) |

All other MMIO reads return 0. Writes are recorded (address, value, PC), capped
at 400 entries. This is enough to boot through platform init; it is not a
device model.

---

## 3. Ground-truth validation

### 3.1 Real DA tails through the real verify block

`--mode func` calls `0x20868C` with `r9=sb=da_len`, `r11=fp=buffer`,
`r6=sig_len`. These are exactly the callee-saved registers the real state
machine sets before entering the block. The buffer is the bytes mtkclient
sends: `region[1].off .. +region[1].size` (DA1 + 0x100 trailer).

```
  2710 K2 DA1 (expect ACCEPT_VALID)                    ACCEPT_VALID     r0=0x0      flag=1  pc=0x208770
  200EX01 K1 DA1 (expect REJECT_0x7024)                REJECT_0x7024    r0=0x7024   flag=0  pc=0x208742
  2710 DA1 zeroed trailer (expect REJECT_0x7024)       REJECT_0x7024    r0=0x7024   flag=0  pc=0x208742
  proto 0xD7 + 2710 DA1 (expect ACCEPT_VALID)          ACCEPT_VALID     r0=0x0      flag=1  pc=0x208770
  proto 0xD7 + 200EX01 DA1 (expect REJECT_0x7024)      REJECT_0x7024    r0=0x7024   flag=0  pc=0x208742

  mandatory pair: 2710 ACCEPT_VALID=True, 200EX01 REJECT_0x7024=True
  primitive PSS: 2710 rsa_calls=1, exact_payload=True
```

The 2710 ACCEPT run executes 26 555 instructions and exactly one RSA public
operation. The 200EX01 run executes 18 579 and rejects. `r0=0` is the value at
`0x208742`; the path then falls through `0x208744..0x20876E` and stores 1 at
`0x2F3158`. The flag is read after the store, not inferred.

### 3.2 Key matrix (PSS primitive, `0x23EA96`)

K2 is at `0x25E3DC`; the stale K1 copy in the 2710 build is at `0x25E2DC`
(installed with the real `key_setup 0x23EA24`). Both DA tails are the real
signed sub-images.

| key / DA | `r0` from `0x23EA96` | verdict |
|---|---|---|
| K2 / 2710 DA1 | `0x0` | PSS_ACCEPT |
| K2 / 200EX01 DA1 | `0x102005` | PSS_REJECT |
| K1 / 2710 DA1 | `0x102005` | PSS_REJECT |
| K1 / 200EX01 DA1 | `0x0` | PSS_ACCEPT |

This is the emulator-side confirmation of the 2026-10-25 static result: the
mapping is bijective and the key is the binding. `0x102005` is the PSS
tail/hash failure inside the `0x10000000`-based error space used by
`0x23EA96`; the semantic block maps any nonzero to `0x7024`.

### 3.3 Realistic path: the real USB command loop with a synthetic transport

`--mode proto` starts at `0x208150` (the function reached from `0x225A42`,
which contains the 4-byte handshake and the command `tbh` dispatch). The
transport is a pair of Python callbacks installed in the context the firmware
already expects:

```
ctx        = 0x2FA000: [ctx+0]=0, [ctx+8]=ops
ops        = 0x2FA100: [ops+0]=send, [ops+4]=recv        (Thumb pointers)
send stub  = 0x300000: record bytes, return 1
recv stub  = 0x300010: pop from FIFO, return 0/1
```

The host side sends the MTK handshake `a0 0a 50 05`, then command `0xD7`,
then three big-endian u32s `[field0, da_len, sig_len]`, then `da_len` bytes.
The firmware's own parser `0x2089AC` reads the u32s (big-endian assembly at
`0x2089C6..0x2089E0`), `0x2083AE` copies `da_len` bytes into `0x40200000`
(`0x208432`), XOR-checksums 16-bit words, then falls into the DAA gate at
`0x2084B8` and the same verify block. With the real 2710 DA1 the flag is set;
with the 200EX01 DA1 the flag stays 0 and the finish value is `0x7024`.

This proves the realistic path (short of a full boot) and validates the
function-level harness: the three values the protocol layer contributes to
auth are exactly `(buffer, da_len, sig_len)`, which the function harness
fuzzes directly.

---

## 4. Fuzzing methodology

### 4.1 Input surface

The preloader's auth input is one contiguous `DA1 ‖ 0x100 trailer` buffer plus
two host-declared lengths. The container header and region table are **not**
passed to the preloader (mtkclient strips them); the preloader never sees
`0x22668899` or the table. Therefore the fuzzer targets the only reachable
surface:

1. trailer bytes (the 0x100-byte PSS signature),
2. message bytes (`[0, da_len-0x100)`),
3. `da_len` (0, 1, 0xFF/0x100/0x101, 0xFFFFF, 0x100000, 0x100001, 0x200000,
   0x400000, 0x400001, 0x7FFFFFFF, 0xFFFFFFFF, random),
4. `sig_len` (0, 1, 0x20/0x40/0x80/0xFF/0x100/0x101/0x180/0x200/0x1000,
   0x7FFFFFFF, 0xFFFFFFFF),
5. random buffers of length 0..0x10000,
6. container header/table mutations (classified separately as
   `ACCEPT_HEADER_ONLY`),
7. protocol framing: bad handshake, command byte, `field0`, truncation, huge
   lengths, short reads.

Mutations: `zero`, `0xFF`, random, random-with-`0xBC`, 1-bit flip, 8-bit flips,
byte swap, message bit flips, zero/fill blocks, truncation, extension.

### 4.2 Classification

| class | meaning |
|---|---|
| `ACCEPT_VALID` | flag set / `r0=0`, **and** the buffer is the byte-exact K2-signed 2710 DA1 with `da_len=0x69424`, `sig_len=0x100` |
| `ACCEPT_INVALID` | flag set / `r0=0` with anything else — **a bypass; must be zero** |
| `ACCEPT_HEADER_ONLY` | flag set, payload/signature byte-exact, only the unsigned container header/table was changed |
| `REJECT_0x7024` | `r0=0x7024` (`DAA_SIG_VERIFY_FAILED`) |
| `OTHER_ERROR` | any other nonzero `r0` (`0x1D18`, `0x1D10`, …) |
| `CRASH` | unmapped access / UC exception; access, address, size, PC recorded |
| `HANG` | assert()/self-branch/budget exhaustion; PC recorded |

An ACCEPT with a wrong signature would be `ACCEPT_INVALID`. The check is not
based on the signature alone: the buffer must equal the exact signed image, so
a header-only mutation is never counted as a valid signature.

### 4.3 Determinism and repros

Fresh `Uc` per case, fixed seed, instruction budget. A repro is a JSON file
plus, where small, the exact `.bin`. The JSON stores an **exact byte patch**
against the known base image (`[[offset, hexbytes], ...]`) or the full hex for
random/truncated buffers, plus `(da_len, sig_len, mode, cmd, handshake)`. No RNG
is replayed; `--replay` reconstructs the bytes and must reproduce the same
class. Example:

```
$ python docs/notes/pre_emu.py --replay /tmp/opencode/pre_fuzz_cases/case_0000.json
{"replay": ..., "class": "REJECT_0x7024", "expected": "REJECT_0x7024",
 "match": true, "r0": 28708, "pc": 2131778, ...}
```

`--replay` exits 0 on a match, 3 on a mismatch.

---

## 5. Results: 2000 cases, seed 1

Command:

```
python docs/notes/pre_emu.py --mode fuzz --cases 2000 --seed 1 \
    --json /tmp/opencode/pre_fuzz_2000.json \
    --repro-dir /tmp/opencode/pre_fuzz_cases
```

Exit code 0. 89.2 s. 1800 function-mode + 200 protocol-mode cases.

| class | count |
|---|---:|
| `ACCEPT_VALID` | 14 |
| **`ACCEPT_INVALID`** | **0** |
| `ACCEPT_HEADER_ONLY` | 72 |
| `REJECT_0x7024` | 1552 |
| `OTHER_ERROR` | 275 |
| `CRASH` | 0 |
| `HANG` | 87 |

`OTHER_ERROR` breakdown: `0x1D18` (da_len ≤ sig_len) 185, `0x1D10`
(DA_EXCEED_MAX_DA_BLOCKS, da_len > 0x100000) 90. No other error code appeared.

Unique `(class, r0, fault.pc, fault.addr, hang.pc)` outcomes: **9**.

| class | detail | tag |
|---|---|---|
| `REJECT_0x7024` | `r0=0x7024`, finish `0x208742` | `sig_swap+msg` |
| `OTHER_ERROR` | `r0=0x1D18`, finish `0x208742` | `random_buf` / truncation |
| `OTHER_ERROR` | `r0=0x1D10`, finish `0x208742` | `da_len_boundary` (`0x400001`) |
| `ACCEPT_VALID` | `r0=0`, flag 1, `0x208770` | `sig_len_boundary` (picked `0x100`; byte-exact DA1) |
| `ACCEPT_HEADER_ONLY` | `r0=0`, flag 1, `0x208770` | `container_header_mut` |
| `HANG` | PC `0x2370C8` | `cmd=0xE1` (also 0x00/0xC4/0xC5/0xCE/0xD0/0xD1/0xD3/0xD6/0xD8/0xDB/0xDF/0xE6/0xE7/0xFF) |
| `HANG` | PC `0x231FC8` | `da_len_huge` (`0x2083E2` assert path) |
| `HANG` | PC `0x2394A4`, `0x239500` | `bad_handshake` (wait loop) |

Why `ACCEPT_VALID` is 14 and not 0: the `sig_len` boundary list contains
`0x100`, and when it is drawn the buffer is still the unmodified signed DA1.
The `exact` predicate confirms it: `buf == da1_2710`, `da_len == 0x69424`,
`sig_len == 0x100`. No mutated buffer ever set the flag.

### 5.1 What was *not* a bypass

* Flipping any of the 256 trailer bytes (`sig_flip1`, `sig_flip8`, `sig_swap`,
  random, `0xFF`, zero) → `0x7024`.
* Flipping/zeroing the message → `0x7024`.
* Replacing the trailer with a random 0x100 bytes, even with the PSS tail byte
  forced to `0xBC` → `0x7024`.
* Truncating the buffer or changing `da_len` below `sig_len` → `0x1D18`.
* `da_len` above `0x100000` → `0x1D10`.
* `sig_len != 0x100` → `0x7024` (the thunk at `0x237938` returns -1).
* Feeding the whole 0xC0BF0 container, or `container[0xBC:]` (DA1‖DA2) →
  `0x7024`.
* Mutating region 1's offset/size and letting the host extract accordingly →
  `0x7024`/`0x1D18`; mutating only `sig_off` changes nothing (the preloader
  takes the signature from the end, and the host sends the same bytes).

### 5.2 The header-only ACCEPT (explained, not a bypass)

72 cases changed `magic`, `da_ver`, `hwcode`, `subcode`, `hw_ver` and/or a
region-table word, then fed the **unchanged** signed DA1. The flag is set
because the bytes the preloader authenticates are unchanged. This confirms the
2026-10-25 note's §2.2/§3 from the emulator side:

* the 0xBC container header is not part of the PSS message;
* the preloader never parses the container magic or the region table (the
  string `MTK_DOWNLOAD_AGENT` / magic `0x22668899` is absent from the image and
  is not referenced by the DA path);
* therefore SoC/subcode fields cannot cause a rejection at this stage. The
  binding is the modulus.

This is a *binding* observation. It does **not** let an unsigned or wrong-key
DA run: the same 72 cases would reject if the signed payload differed by one
byte.

---

## 6. Write-side audit

The error tail is:

```
0x208742  uxth r4,r0            ; r0 = verdict
0x208744  mov  r0,r4
0x208746  bl   0x20882C         ; USB status (stubbed)
0x20874A  cbz  r4, 0x20876A     ; success -> flag
0x20874C  ... printf ...
0x208754  mov  r0,fp            ; fp = DA buffer
0x208756  movs r1,#0
0x208758  mov  r2,sb            ; sb = da_len
0x20875A  bl   0x23872A         ; memset(fp, 0, da_len)
0x20875E  ... assert(0x231FC8)
```

`--mode writes` runs the tail with the memset hook enabled and filters the
caller LR `0x20875F`:

```
func sig_flip (da_len=0x69424)        REJECT_0x7024  memset(0x40000000,0,0x69424)
func da_len=0x100000                  REJECT_0x7024  memset(0x40000000,0,0x100000)
proto sig_flip (real USB rx path)     REJECT_0x7024  memset(0x40200000,0,0x69424)
proto da_len=0x400000 (short read)    OTHER_ERROR    memset(0x40200000,0,0x400000)
proto da_len=0x400001                 HANG           no memset (assert at 0x2083E2)
```

In every case `dst` is the receive buffer and `len` equals `da_len`, i.e. the
number of bytes the receive callback at `0x208432` was asked to write into the
same buffer. The receive state's only bound is `da_len ≤ 0x400000`
(`0x2083DC`); above that it prints and calls `assert(0x231FC8)` before any
read. So there is no *additional* out-of-bounds write from the error tail: the
memset cannot exceed the buffer range the read already covered. If the real
reserved DA buffer were smaller than 0x400000, the read would be the first OOB;
the image does not expose that size, so the 4 MiB bound is the best available
model.

The DA-version floor (`0x230C5C..0x230CAC`, writes item 7 = 5 through
`0x242842`) and the seccfg/BR-cmd path (`0x2378AC`) are **not** reachable from
the DA input path. A BL scan of the whole command loop `0x208150..0x20877C`
finds no call to either address; its direct callees are the auth, hash, status
and USB helpers only. The version floor runs in sec-lib init (`0x228A1C`) and
is not compared anywhere in `usbdl_vfy_da`. Its enforcement point remains
UNKNOWN, exactly as the 2026-10-25 note says; it is not a DA-input write
surface.

---

## 7. Boot attempt (honest limits)

`--mode boot` starts at the ARM entry `0x201000`, maps BROM ROM (address 0),
EMI (`0x0C000000`), and models the `0x10017008` timer as a deterministic
free-running counter. It reaches:

* preloader main `0x22852C` (confirmed by a PC hook);
* platform init `0x231FF0`, clock/EMI writes (`0x226B50..0x226B80`);
* DRAM init: at `0x23378C` the code loads the literal `0x2619DF20` (a
  DRAM/PHY register window) and writes `0xF` there; that window is not
  modelled, so the run stops at PC `0x23379C` with an unmapped write.

Two emulator-only workarounds were needed, both documented in the code:

1. **HACC** was replaced at the software API (see §2.1); register-level
   modelling hangs in the poll at `0x2441B0`.
2. **Unicorn 2.1.4 Thumb ITSTATE**: after the loop at `0x239414..0x23941C`
   Unicorn does not retire ITSTATE, so the `bl 0x2012FE` into the shared
   division helper arrives with ITSTATE `0x1C` and the `bne` at `0x201300` is
   decoded as an illegal branch-inside-IT. Clearing ITSTATE at
   `0x23941E..0x23942A` is a documented emulator workaround, not a preloader
   change. This was hit twice with the same `UC_ERR_INSN_INVALID` at
   `0x201300`; per the anti-loop rule the workaround was recorded rather than
   retried.

Full boot to the USB download stage is therefore **infeasible offline**: it
needs DRAM/PHY, UFS and PMIC models. The deliverable for the realistic path is
`--mode proto`, which drives the actual USB command state machine and the
actual DA receive/verify code with a synthetic transport.

---

## 8. Verdict: what the auth actually enforces

On the 2710 preloader analysed here:

1. **One platform key, one scheme.** `usbdl_verify_da` installs K2
   (`0x25E3DC`) via the real `0x23794C` and calls `0x23EA96`, which is
   RSASSA-PSS/SHA-256 with a 0x100-byte signature. `sig_len` must be exactly
   0x100 (`0x237938`), `da_len` must be ≤ 0x100000 (`0x208692`), and the
   signed message is `DA1[0 .. da_len-0x100)`.
2. **The verdict maps to one flag.** Any nonzero result becomes `0x7024`; the
   only write of `*(0x2F3158)=1` is at `0x20876A`, reached only when the
   verdict is 0. `usbdl_jump_da` (0x208570) loads that same literal and
   refuses to jump otherwise. The literal `0x2F3158` occurs exactly once in
   the image (VA `0x2087A4`), referenced only from the jump gate and the flag
   write.
3. **No input bypass.** 2000 cases, 0 `ACCEPT_INVALID`. Bit flips, random
   trailers, message corruption, truncation, boundary lengths, whole
   containers, and region-table mutations all reject. The only ACCEPT is the
   byte-exact K2-signed DA1.
4. **The key is the binding.** K1/K2 cross-checks are bijective. A 200EX01 DA1
   cannot run; a 2710 DA1 cannot run on the K1 generation.
5. **What is weak: binding, not signature.** The 0xBC header (magic, hwcode,
   subcode, hw_ver, region table) is neither signed nor parsed. An attacker can
   change every one of those fields and the *same* signed DA1 still verifies.
   This is not a signature bypass, but it means the preloader does not enforce
   SoC/subcode binding at DA1 time; the only binding is the vendor key.
6. **What is DoS, not bypass.** Malformed/unsupported USB command framing and
   `da_len > 0x400000` drive the preloader into the self-branch at `0x2370C8`
   or `assert(0x231FC8)`. A host can wedge the preloader (the 2026-10-25 note
   already described the `0x7024` → "clean invalid da" → assert tail). It
   cannot set the flag.
7. **What is configuration, not input.** sec mode 0 disables verification and
   sets the flag for an invalid DA. This is the factory/no-secure-boot state
   (`usbdl_vfy_da:disabled`), not a USB-controlled value. On a locked retail
   unit mode `0x11` verifies.

**Answer to the title question:** the 2710 DA authentication is **not
bypassable by the input the preloader parses** in this emulator. The DA-swap
verdict (K1 → K2) is confirmed dynamically: only a K2-signed 2710 DA1 runs.
The header binding weakness is real but does not defeat the signature.

---

## 9. Reproduction

```
cd /root/mtkclient

# 1. base derivation + addresses
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py --mode info

# 2. ground truth (exit 0 required)
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py --mode func

# 3. realistic USB command path
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py --mode proto

# 4. sec policy gate (config bypass demonstration)
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py --mode gate

# 5. write-side audit
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py --mode writes

# 6. 2000-case fuzz (exit 0; ACCEPT_INVALID must be 0)
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py \
    --mode fuzz --cases 2000 --seed 1 \
    --json /tmp/opencode/pre_fuzz_2000.json \
    --repro-dir /tmp/opencode/pre_fuzz_cases

# 7. replay any saved case
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py \
    --replay /tmp/opencode/pre_fuzz_cases/case_0000.json

# 8. best-effort boot (expected to stop in DRAM/PHY init)
python /tmp/opencode/da1venv/bin/python docs/notes/pre_emu.py --mode boot
```

Acceptance observed:

| check | result |
|---|---|
| `--mode func` | exit 0; 2710 `ACCEPT_VALID`, 200EX01 `REJECT_0x7024`; key matrix all four correct |
| `--mode fuzz --cases 2000` | exit 0; class table above; `ACCEPT_INVALID=0` |
| `--mode proto` | exit 0; 2710 accept, 200EX01 `0x7024` |
| `--mode writes` | exit 0; all memsets equal the received length |
| `--mode boot` | exit 0; reaches main + DRAM init, then `0x2619DF20` unmapped |
| `docs/notes/da1_fixed_stage.py` | `RESULT: PASS`, exit 0 (unchanged, run to confirm no regression) |

`da1_fixed_stage.py` output ended with:

```
CHECK bootto_gate            PASS
BOOT-TO gate PASS cb=0x40000000
NOHEAP ok constants=0xdeadbeef,0x2df79c,0x40000000,0x40000000,0x40000080,0x3c,0x2688cc
RESULT: PASS
```

**Note on the workspace.** Partway through the task the checkout was reset to
upstream commit `7cb40e7`; the original `docs/notes/rmx3630-da2/` tree and
`da1_fixed_stage.py` are no longer in the working tree. The PASS above was
re-run from the pre-reset commit `5db541c` extracted into
`/tmp/opencode/oldtree/docs/notes/` (same script, same DA files, exit 0). The
emulator now resolves the 200EX01 DA1 from `/tmp/opencode/da/da1_dabr.bin`
when the container is absent (`--da200` fallback), so `--mode func` still
validates both real tails in the current tree.

---

## 10. Repro index (top cases)

All files are in `/tmp/opencode/pre_fuzz_cases/`. Each `.json` has the exact
byte patch, `da_len`, `sig_len`, mode and (for proto) `cmd`/`handshake`;
`.bin` is present when the buffer is ≤ 0x20000 bytes.

| case | what | class / PC |
|---|---|---|
| `case_0000` | 2710 DA1, trailer byte swap + message bit flips | `REJECT_0x7024` / `0x208742` |
| `case_0004` | 2710 DA1, random 0x100 trailer | `REJECT_0x7024` / `0x208742` |
| `case_0006` | header fields mutated, same signed DA1 | `ACCEPT_HEADER_ONLY` / `0x208770` |
| `case_0031` | proto `0xD7`, truncated 0x10-byte DA | `OTHER_ERROR 0x1D18` / `0x208742` |
| `case_0032` | proto command `0xE1` with no body | `HANG` / `0x2370C8` |
| `case_0033` | proto `da_len=0x4000B5` | `HANG` / `0x231FC8` (assert) |
| `case_0034` | proto bad handshake | `HANG` / `0x2394A4` |

Example repro bytes for the header-only ACCEPT (`case_0006`) are the exact
2710 DA1 (`sha256` prefix `6c49eba0cea6d966…`), i.e. no payload mutation; the
mutated header never reaches the preloader, which is the point.

Example repro for a wrong-key reject (`case_0004`): `buf_sha`
`e3134404a90ad282…` (differs from the valid DA1 only in the 0x100 trailer),
`da_len=0x69424`, `sig_len=0x100`, result `0x7024`.

---

## 11. Limitations / UNKNOWNs

1. **HACC is shimmed, not modelled at the register level.** SHA-256 and RSA
   arithmetic are exact; timing and HACC error paths are not. The verdict is
   about the code path, not about HACC silicon.
2. **Not a device.** No UFS, DRAM, PMIC, USB PHY, eFuse or ATF/GZ model. Boot
   stops at DRAM/PHY init (`0x23379C`). The protocol harness supplies the USB
   transport synthetically but executes the real parser and verify code.
3. **sec mode 0x22** depends on the SBC eFuse; our unblown model returns 0.
   The locked retail case is modelled as mode 0x11, which enables verification.
   Whether a specific unit is 0x11 or 0x22 is a device fact; the code path for
   0x22 is present but its fuse input is not modelled.
4. **The DA-version floor (item 7 = 5) enforcement point is still UNKNOWN.**
   It is not in `usbdl_vfy_da`; its only caller is sec-lib init. No DA input
   reaches it.
5. **The 4 MiB receive bound** (`0x400000`) is the only pre-verify buffer bound
   in the image. The actual reserved DRAM buffer size is not encoded in the
   preloader; the memset was proven equal to the read length, so an OOB would
   have to be in the read itself, not in the error tail.
6. **PSS error codes** are reported as the raw `r0` from `0x23EA96`
   (`0x102005` for the wrong key). The semantic block always maps nonzero to
   `0x7024`, which is what `usbdl_jump_da` consumes.
7. **Only command `0xD7` (download DA) is fuzzed in depth.** Other command
   bytes were fed without bodies, enough to see whether they can reach the flag
   or the jump gate; their own parsers are outside the DA-auth scope.

---

## 12. One-paragraph summary

The 2710 preloader's DA authentication was executed unmodified under Unicorn:
the real key install (`0x23794C`), the real length checks (`0x208692`,
`0x208704`, thunk `0x237938`), the real PSS/RSA path (`0x23EA96` with HACC
modelled at its software API), and the real flag write (`0x20876A`). The real
2710 K2-signed DA1 accepts (flag 1); the 200EX01 K1 DA1 rejects with `0x7024`;
the K1/K2 matrix is bijective. 2000 fuzz cases over the signature, message,
lengths, container header/table and USB framing produced **zero**
`ACCEPT_INVALID`: no malformed input sets the DAA flag. The only ACCEPTs are
the byte-exact signed DA1 and header-only mutations of an already-signed DA1
(the header is unsigned and never parsed). The error-tail memset is bounded by
the length already received; oversized lengths either return `0x1D10` or
assert before verify. Malformed command framing can wedge the preloader in
`0x2370C8`/`0x231FC8`, and sec mode 0 disables verification by fuse policy —
neither is a host-input signature bypass. **The 2710 DA auth holds in the
emulator; the effective binding is the K2 modulus.**
