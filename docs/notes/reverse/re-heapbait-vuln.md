# RE: HeapBait vulnerable path in RMX3630 OPLUS DA2 (da2_oplus.bin)

Date: 2026-10-23. Tool: radare2 `-a arm -b 32 -m 0x40000000` (file offset 0 == VA 0x40000000).
Binary: `docs/notes/rmx3630-da2/da2_oplus.bin`, 356296 B, sha256 `fd3a5038…`.
Anchored against the exploit implementation `mtkclient/Library/Exploit/heapbait.py`
(`run_exploit` / `find_*` resolvers / `build_shellcode_payload`).

## TL;DR verdict

**VULNERABLE.** The patch-detection string `"Dest XML file name buffer overflow"`
is **absent** from the blob (`b"Dest XML" in da2` → False; only fragment found is
`"...pmic_monitor...dest_addr is null!"` at 0x40048c29, unrelated). HeapBait's
`is_vulnerable()` therefore returns True for this DA2, consistent with the
campaign's ~50% on-device success rate (the failures are heap-layout/race
issues, not a patch — see §6).

Every primitive HeapBait resolves at runtime is present and was located:

| Primitive (heapbait.py) | Resolver anchor | VA in this blob |
|---|---|---|
| `reg_cmd` (register_xml_cmd) | "CMD:REBOOT" (0x40041583) → next BL | **0x400086d4** |
| `secure_cmds` / register_all_cmds | function containing "CMD:REBOOT" ref | **0x40001a6c** |
| `cmd_loop` (dagent_command_loop2) | function containing "\n@Protocol: DPC CALL\n" (0x400437f8, ref site 0x40008c0c) | **0x4000875c** |
| `dpc_addr` (dpc struct − 4) | DPC getter `fcn.40001f08` returns the struct | struct @ **0x40069dec**, dpc_addr = **0x40069de8** |
| `download_addr` (find_download_func) | function containing "Download host file:%s" (0x4004dd6c, ref site 0x4002aebc) | **0x4002ae8c** = `fp_read_host_file` |
| `free` | "Bad %s" (0x400446c9, ref 0x4000e138) → BL 0x4000ed70 → next BL | **0x4000a5f0** → tail `b 0x40008f08` |
| `get_node` | "runtime_switchable_config/magic" (0x400426ba, ref 0x40006070) → next BL | **0x40001e48** |
| `load_str` (mxml_load_string) | function containing "Bad %s" | **0x4000d0bc** region (mxml parser, 4748 B) |
| malloc / calloc | wrappers | **0x4000a59c** (→ b 0x40008d3c), 0x4000a5b4 |
| heap free-list head | literal in allocator | **0x40069e94** (+8 first node, +0xc sentinel) |

## 1. Vulnerability check

```
izz~Dest  →  no "Dest XML file name buffer overflow" anywhere in the blob.
```
Patched DA2 builds carry that string next to a clamp of the per-chunk receive
length. This blob has only the *unclamped* variant (§2). Verdict: **HeapBait-vulnerable**.

## 2. The vulnerable function: `fp_read_host_file` @ 0x4002ae8c

This is the DA's "pull a file from the host" engine. It builds
`CMD:DOWNLOAD-FILE ... <source_file>%s ... <packet_length>0x%x` (fmt 0x4004dc6a),
sends it, expects OK, then parses the host's reply XML (0x40008300) and streams
the file body over USB into a heap buffer.

### (a) The chunk allocation

```
0x4002b0ac  ldr r0,[sp,0x74]        ; hex string of advertised total length from host reply XML
0x4002b0b0  bl 0x4000aef4           ; ascii-hex -> u64   => sb = 0x13FC in heapbait stage 3
0x4002b0b8  ldr r0,[r6]             ; existing buffer?
0x4002b0c0  ... bne 0x4002b0f0      ; reuse path: cmp r0,sb ; bls -> "fp_read_host_file buffer is too small." (0x4004dd9f)
0x4002b0cc  add r0, sb, 4
0x4002b0d4  bl 0x4000a59c           ; malloc(sb + 4)  => 0x1400-byte chunk
0x4002b0dc  str r0,[r6]
```
malloc(sb+4): advertised 0x13FC ⇒ **0x1400-byte chunk** (matches heapbait
comment "allocates a 0x1400 byte buffer").

### (b) The copy WITHOUT bounds check = the overflow

Per-chunk receive loop:

```
0x4002b110  ldr r0,[r6]             ; buffer
0x4002b114  cmp sb,0 ; str r0,[sp,0x20]
0x4002b11c  beq 0x4002b1e4          ; done
0x4002b134  ldr r2,[r8]             ; USB recv op
0x4002b13c  str 0x40,[sp,0x7c] ...  ; recv status hdr
0x4002b16c  bl 0x40008300           ; recv "OK" framing
0x4002b1a0  ldr r0,[sp,0x24]        ; <<<< request length = [0x40067A08+0x14] (packet_len global, 0x2000)
0x4002b1a4  mov r1, sl (=&[sp,0x7c])
0x4002b1a8  str r0,[sp,0x7c]        ; requested = packet_len, NOT min(packet_len, sb-r7)
0x4002b1ac  ldr r0,[sp,0x20]; add r0,r0,r7
0x4002b1b8  blx r2                  ; USB RECV into buf + r7, up to 0x2000 bytes
0x4002b1d0  ldr r6,[sp,0x7c]        ; actual received
0x4002b1d8  add r7,r6,r7            ; advance
0x4002b1dc  cmp r7,sb ; bne loop
0x4002b1e4  strb 0,[r1,sb]          ; NUL-terminate at sb
```

The requested length at **0x4002b1a0 is never clamped to the remaining
capacity** (`sb − r7`). Whatever the host actually delivers in a chunk is
written at `buf + r7`. HeapBait advertises 0x13FC (alloc 0x1400) and then sends
0x140C bytes (`USB_DATA_SIZE(0x1400)` zeros + 12 fake-header bytes) → the recv
writes **0xC bytes past the chunk end**, exactly one allocator chunk header.

A patched build would clamp the request to `sb − r7` and print
"Dest XML file name buffer overflow" on violation — that string and that clamp
are both absent here.

### (c) XML command + field that reach it

`CMD:SECURITY-SET-ALLINONE-SIGNATURE` (handler **0x40006c1c**, registered at
0x40001a6c-table, string 0x4004167f):

```
0x40006c28  bl 0x4000d0bc           ; mxml_load_string(cmd)
0x40006c50  bl 0x40001e48           ; get_node("da/arg/source_file")  (path 0x400417cc)
0x40006c84  bl 0x4002ae8c           ; fp_read_host_file(session, node_value, "Signature"(0x40042f12), &len)
0x40006c9c  bl 0x4002d428           ; process downloaded body
0x40006cdc  bl 0x4000a5f0           ; FREE the downloaded buffer   <-- trigger point
```

Field: `<da><command>CMD:SECURITY-SET-ALLINONE-SIGNATURE</command><arg>
<source_file>NAME</source_file>…` — `NAME` is the "dest XML file name". The
5000-'A' stage-2 filename becomes an mxml node-value heap buffer; the download
body of stage 3 is the overflow payload. (`CMD:SECURITY-SET-FLASH-POLICY`
0x40006ddc reaches the same executor via node "SEC-POLICY".)

## 3. Heap infrastructure the payload hijacks

### Allocator `0x40008d3c` (malloc core; wrappers 0x4000a59c/a5b4/a5f0)

Free-list head at **0x40069e94**: `+8` = first free node, `+0xc` = sentinel
(`head+8`). Free-node layout (confirmed in both alloc walk and free insert):

```
node+0x0 : next
node+0x4 : prev
node+0x8 : size
```
Allocation carve-out at 0x40008ddc–0x40008e7c: unlink node
(`[prev]->next = next; [next]->prev = prev`), split remainder, then stamp the
user chunk header:
```
0x40008e70  movw r1,0x6170; movt r1,0x6865   ; magic 0x68657061 ("apeh")
0x40008e78  str r1,[r5,-0xc]                 ; [user-0xc] = magic
0x40008e7c  stmdb r5,{r0,r6}                 ; [user-0x8] = free-node ptr, [user-0x4] = size
```
So the 12 bytes immediately before a user chunk are **magic | node_ptr | size** —
exactly the "ARM32: magic(4) | ptr(4) | size(4)" header HeapBait overwrites.

### free `0x40008f08`

```
0x40008f78  ldmdb r4,{r0,r1}        ; r0 = [user-8] node ptr, r1 = [user-4] size
0x40008f7c  str r1,[r0,8]           ; node->size = size     <<<< KEY WRITE
0x40008f80  bl 0x40008fa0           ; insert node into free list
```
(0x40008f44 confirms the same layout on the debug path: prints
"allocation was %zd bytes long at ptr %p" from `[r4,-8]`/`[r4,-4]`.)

### get_node `0x40001e48` / DPC

`get_node(path)` = mxml node lookup (`0x4000ef5c` walk, `[node]==2` value-node
check). DPC struct at **0x40069dec** (`fcn.40001f08` returns it; `fcn.40001f14`
zeroes +0/+4/+8):

```
dpc+0x0 : command-name ptr ("reboot", 0x400424a9, compared with memcmp 7 at 0x40008c44)
dpc+0x4 : callback fn ptr
dpc+0x8 : callback arg
```

### cmd_loop `0x4000875c` — the DPC dispatch (the hijack site)

```
0x40008bf0  bl 0x40001f08           ; r0 = &dpc (0x40069dec)
0x40008bf4  ldr r0,[r0,4]; cmp 0; beq skip
0x40008c1c  ldr r4,[dpc,4]          ; r4 = dpc->cb
0x40008c20  bl 0x40001f08; ldr r0,[r0,8]   ; r0 = dpc->arg
0x40008c28  blx r4                  ; <<<< indirect call of dpc->cb
0x40008c2c  ...; if dpc->name: memcmp(name,"reboot",7) -> set reboot flag @0x40069e8c
```

## 4. Exploit primitive, mechanically (grounded in the code above)

1. **Stage 1** – `CMD:SECURITY-SET-ALLINONE-SIGNATURE` (AIO1) with the
   heapbait_arm.bin body (NOP sled + shellcode, placeholders patched with
   reg_cmd/cmd_loop/heap/download/free/get_node/load_str/uart). The downloaded
   body lands in a large heap chunk → shellcode parked in the heap.
2. **Stage 2** – same command with a 5000-'A' `source_file` name; the mxml
   parser (0x4000d0bc) allocates a ~0x13a0 value buffer for the name. Heap
   shaping: this chunk ends up **immediately after** the chunk stage 3 will get.
3. **Stage 3** – download with advertised length 0x13FC → `fp_read_host_file`
   mallocs 0x1400 and the unclamped recv (0x4002b1a0/0x4002b1b8) accepts
   0x140C bytes → 0xC-byte overflow = the *next* chunk's header becomes
   `magic=0xDEADBEEF | node_ptr = 0x40069de8 (dpc_addr) | size = shellcode_addr`.
4. **Trigger** – when the handler tears down (0x40006cdc `bl 0x4000a5f0` /
   XML-tree free walk), `free()` reads the fake header:
   `node = 0x40069de8`, then **`str size,[node+8]`** → writes
   `shellcode_addr` to **0x40069df0 = dpc->cb**; the list insertion
   (0x40008fa0) additionally scribbles next/prev into 0x40069de8/dec (dpc−4 and
   dpc->name), which also makes `dpc->name != NULL` but ≠ "reboot".
   HeapBait chose `dpc_addr = struct − 4` precisely so that the allocator's
   `node->size` write lands on `dpc+4` (cb) — this is the reason for the −4.
5. **Fire** – next iteration of `cmd_loop` (0x4000875c) sees `dpc->cb != 0`
   and executes `blx r4` at **0x40008c28** → shellcode runs with r0 = dpc->arg.
   The shellcode re-enters the XML command loop with two extra commands,
   `CMD:EXP-PATCH-MEM` (write arbitrary bytes via patch_mem) and
   `CMD:EXP-CALL-FUNC` (call arbitrary VA), which the campaign then uses for
   the runtime security patches (0x40007abc, 0x400103dc, 0x4005455c, …).

All of these components are **visible in this blob**: node next/prev/size at
+0/+4/+8, header at user−0xc/−8/−4, dpc struct layout, DPC dispatch blx. No
CFI/hardening observed on the `blx r4` path.

## 5. Where the ~50% failure comes from

* **Heap-layout adjacency (main internal condition).** The 0xC-byte overflow is
  blind: it corrupts whatever chunk physically follows the 0x1400 download
  buffer. Only if that is the stage-2 mxml filename buffer (and it is freed
  afterwards) does the fake header reach `free()`. Different allocation order,
  prior frees/reuse, or differing earlier command traffic → the 12 bytes land
  in an unrelated chunk: crash or silent no-op.
* **DPC idle requirement.** `dpc->cb` must be 0 when the poisoned free happens,
  and cmd_loop must reach the DPC check again (it does every loop).
* **USB framing / READY desync (external, known).** The preloader↔DA CDC
  handshake desync shifts packet boundaries/ACK sequencing
  (`ack_value(USB_DATA_SIZE-4)` / `ack_value(0)` / `GETBAITED\0` handshakes in
  heapbait.py); a desync aborts the exchange before the overflow or before the
  poisoned free completes. This matches the campaign note that the external
  READY-desync is a known factor.

## 6. Uncertainty

* `[0x40067A08+0x14]` is treated as the USB packet-length global (0x2000 per
  heapbait.py's comment); its exact runtime value was not traced to the USB
  init — medium confidence.
* The precise identity of the victim chunk (mxml filename buffer vs. other
  stage-2 allocation) follows heapbait.py's design comments, not a dynamic
  trace; the static record (mxml value buffers are heap allocations from the
  same 0x40008d3c allocator) is consistent with it.
* `mxml_load_string` start given as the 0x4000d0bc parser region; heapbait's
  resolver would return whatever prologue-scan it finds in that region —
  0x4000d0bc is the natural candidate but the exact value it computes was not
  re-derived bit-for-bit.
* Free-list coalescing after the fake insert (0x40009010–0x40009048) was not
  fully traced; it does not affect the cb write, which happens before it.

## ERRATA (2026-10-26, penumbra survey)

1. **packet_len global corroborated.** Penumbra's own exploit code
   (`core_src_exploit_heapbait.rs`, stage-3 comment) states
   `packet_length (0x2000)`, matching our resolver
   (`[0x40067A08+0x14] = 0x2000`, line ~72 above). Their **doc**
   (Heapbait.md) and the r0rt1z2 blog say `0x20000` — that is a
   docs-copied-from-blog artifact; code vs code, both implementations agree on
   0x2000 (for 200EX01). 2710 value still unconfirmed (one disasm pass on
   `[0x40067A08+0x14]` of the 2710 DA2).
2. **The XML-escape overflow is an independent vector, not a footnote.** Our
   note treated the `0x200` escape buffer as context. r0rt1z2's writeup
   (and the Chimera trace) show `mxml_escape` (fixed `malloc(0x200)`, expands
   `&quot;`-class entities, no bounds check) overflows +172 B on its own and
   can corrupt the AIO1 buffer that is then `free()`d by the next AIO command —
   a self-contained primitive. It is exactly the overflow the
   `MAX_FILE_NAME_LEN*6` + "Dest XML file name buffer overflow" tripwire
   (live on 2710, bound `0xBFA`) guards. Both vectors (XML-escape and the
   `fp_read_host_file` chunk loop) share the tripwire.
3. Detection cross-check and full comparison: `re-penumbra-survey-2026-10-26.md`.
