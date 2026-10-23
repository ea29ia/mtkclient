# Audit: proposed `mov r0,#0` patch at 0x4000325c (WRITE-FLASH erase kill) — RMX3630 DA2

Binary: `docs/notes/rmx3630-da2/da2_oplus.bin`, VA base 0x40000000, ARM32.
Tooling: `r2 -a arm -b 32 -m 0x40000000` (radare2 6.2.4). All addresses are VAs.
Question under audit: does replacing `blx r2` @ `0x4000325c` with `mov r0,#0`
(`e3a00000`) leave **any secondary conditional check on the erase result / erased-block
state** before the data-receive/program call `0x4002ad04`, and is the
`0x4002b5b4`/`0x4002b790` pair balanced afterwards?

**VERDICT: SAFE.** All paths from the patched site reach `0x4002ad04` when r0==0.
There is exactly ONE consumer of the erase result in WRITE-FLASH — `cmp r5,#0;
bne 0x400032c4` @ `0x4000326c/0x40003270` — and r5==0 takes the fall-through (success)
path. No length recompute, no bad-block scan, no post-erase verify read exists in the
window. One **correction to prior notes**: `0x4002b5b4`/`0x4002b790` are NOT a flash
lock/unlock pair — they are the **host progress-report / progress-report-EOT senders**;
the patch keeps both calls, so the host protocol exchange is unchanged.

---

## 1. Context: how r2 is loaded (0x40003200–0x4000325c)

```
0x40003200  ad1200eb  bl 0x40007cbc          ; log level -> r0
0x40003204  020050e3  cmp r0, #2             ; flags Z/C
0x40003208  0700008a  bhi 0x4000322c         ; level>2 -> skip the Erase log print
0x4000320c  18009de5  ldr r0, [sp,0x18]      ; r0 = ptr (offset field holder)
0x40003210  d020c0e1  ldrd r2,r3,[r0]        ; r2:r3 = 64-bit value (offset)
0x40003214  d000c5e1  ldrd r0,r1,[r5]        ; r0:r1 = 64-bit value (len; r5 = [sp,0x14])
0x40003218  03008de8  stm sp, {r0,r1}        ; push 2nd u64 onto stack args
0x4000321c  110b01e3  movw r0, #0x1b11       ; -> 0x40041b11
0x40003220  040044e3  movt r0, #0x4004       ; "Erase [%s] At[0x%llx] Len[0x%llx]\n"
0x40003224  0a10a0e1  mov r1, sl             ; sl = region-name ptr (arg for %s)
0x40003228  781200eb  bl 0x40007c10          ; log print
; ---- erase call setup ----
0x4000322c  a0060be3  movw r0, #0xb6a0       ; -> 0x4002b6a0
0x40003230  0a10a0e1  mov r1, sl             ; progress-report text arg (sl = sp+0x58+8 area)
0x40003234  020044e3  movt r0, #0x4004
0x40003238  20408de5  str r4, [sp,0x20]      ; [sp+0x20] = r4 (session ctx) -- arg block for blx
0x4000323c  24008de5  str r0, [sp,0x24]      ; [sp+0x24] = 0x4002b6a0
0x40003240  0400a0e1  mov r0, r4             ; r0 = session ctx
0x40003244  daa000eb  bl 0x4002b5b4          ; send CMD:PROGRESS-REPORT to host, wait "OK"
0x40003248  740304e3  movw r0, #0x4374       ; -> 0x40054374 (dispatch table)
0x4000324c  20108de2  add r1, sp, #0x20      ; r1 = &stack arg block {r4, 0x4002b6a0}
0x40003250  050044e3  movt r0, #0x4005
0x40003254  082090e5  ldr r2, [r0,#8]        ; r2 = [0x40054374+8] = 0x4002eca4 (erase fnptr)
0x40003258  58008de2  add r0, sp, #0x58      ; r0 = request struct
0x4000325c  32ff2fe1  blx r2                 ; <-- THE ERASE (patch site)
```

So r2 comes from the dispatch table word at `0x4005437c` (= 0x4002eca4), loaded by
`ldr r2,[r0,#8]` at `0x40003254` — not from a literal pool. The patch replaces exactly
the 4-byte `32 ff 2f e1` at `0x4000325c`.

**Xref check on 0x4000325c:** `axt` (after `aaa`) returns **nothing**, and byte scans for
the words `0x4000325c`, `0x40003260`, `0x40003270` anywhere in the file find **no hits**
(no literal-pool / vtable references). No other code jumps into the block. Minor caveat:
r2's axt misses `movw/movt` immediate references by design; but a *branch target* must be
encoded either as a PC-relative branch (all of which are visible in the handler disasm
below — none target 0x4000325c/60/70) or via a literal word (which the scan would have
caught). Confidence: high.

## 2. Annotated disasm 0x40003260–0x40003290 (the audited window)

```
0x40003260  0050a0e1  mov r5, r0            ; r5 = erase result. PATCHED: blx r2 -> mov r0,#0,
                                            ;   so r5 = 0 ("erase ok"). r1-r4 unchanged (r4=session).
0x40003264  0400a0e1  mov r0, r4            ; r0 = session ctx (arg for unlock/progress-EOT)
0x40003268  48a100eb  bl 0x4002b790         ; send PROGRESS-REPORT EOT ("Progress report EOT."),
                                            ;   waits for host "OK"; return in r0
0x4000326c  000055e3  cmp r5, #0            ; *** THE ONLY ERASE-RESULT CHECK ***
                                            ; tests r5 (= injected 0). Does NOT test r0
                                            ; (the progress-EOT return) — Z set by cmp r5.
0x40003270  1300001a  bne 0x400032c4        ; r5!=0 -> error path. With r5==0: NOT taken.
; ---- success path (taken with the patch) ----
0x40003274  0000a0e3  mov r0, #0            ; r0=0; flags unchanged (MOV no-S)
0x40003278  58208de2  add r2, sp, #0x58     ; r2 = request struct
0x4000327c  30308de2  add r3, sp, #0x30     ; r3 = out-param block
0x40003280  00008de5  str r0, [sp]          ; [sp] = 0 (5th arg)
0x40003284  0400a0e1  mov r0, r4            ; r0 = session ctx
0x40003288  0910a0e1  mov r1, sb            ; r1 = sb (sp+0x48: partition name buf)
0x4000328c  9c9e00eb  bl 0x4002ad04         ; DATA RECEIVE + PROGRAM (its first byte moves here)
0x40003290  000050e3  cmp r0, #0            ; program result check (post-0x2ad04, not erase-related)
```

Every instruction between `0x40003260` and `0x4000328c` is `mov/add/str` argument setup —
no loads of the request-struct erase status, no second cmp/tst on anything derived from
the erase call. The `cmp r0,#0` at `0x40003290` tests **0x4002ad04's own** return.

## 3. What if r5==0 — path analysis

- `cmp r5,#0` @ `0x4000326c` with r5==0 → Z=1 → `bne` **not taken** → fall-through to
  `0x40003274` → unconditionally reaches `bl 0x4002ad04` @ `0x4000328c`. **Single path,
  no fork.**
- The error path `0x400032c4` (`mov r0, r8; bl 0x4000ea94` = send error status to host;
  `b 0x40003044` = return r7) is **unreachable** with r5==0. Notably WRITE-FLASH's erase
  failure path does **not** print an erase-specific string at all (see §4).
- After `0x40003294`, r5 is **never read again** anywhere in the handler (full-handler
  grep of r5: last read is the `cmp r5,#0` at 0x4000326c; next r5 write is
  `mov r5,r1` @ `0x400032dc`, which is the *next* function's prologue). So no later
  branch can resurrect the injected value.

## 4. Strings "Erase [%s] Failed." / "Error: Erase ... failed, error code[0x%x]" — where they really live

- `0x40041b34` `"Erase [%s] Failed."` is referenced by **movw @ 0x40002320** — that is
  inside **WRITE-PARTITION** (`0x40002034`), its erase-failure branch
  (`cmp r5,0; beq 0x40002218` @ `0x40002318`, fail → print → `b 0x400021b4`).
- `0x40041d56` `"Error: Erase [%s] At[0x%llx] Len[0x%llx] failed, error code[0x%x]"` is
  referenced at **0x40002c3c** (a FLASH-ALL-family function) and **0x4000597c** (inside
  the generic erase dispatcher region near `fcn.40005400`) — **not** by WRITE-FLASH.
- WRITE-FLASH's erase-failure handling is the bare `0x400032c4` error-status send only.
  Conclusion stands: the WRITE-FLASH erase result has exactly one consumer.

## 5. Second erase-status consumer between 0x4000325c and first use of the buffer? — NONE

Window `0x40003260`–`0x4000328c`: no length recompute, no bad-block scan, no verify
read. The setup at `0x40003274`–`0x40003288` passes: r0=session, r1=name buffer,
r2=request struct (the SAME struct that fed the erase — name/offset/len fields
untouched), r3=out-block, [sp]=0. `0x4002ad04` receives no erase-result argument, and
being a `bl` callee it cannot see the handler's r5 (callee-saved; it overwrites its own
r5 from `[fp,#8]` at `0x4002ad28`).

`0x4002ad04` internals (spot-audited, honest caveat: it is a large ~2 KB function not
fully traced): its prologue builds a `CMD:DOWNLOAD-FILE` progress XML and uses session
fnptr table `[r4+0]`/`[r4+4]` for send/recv — its many `blx r2` sites are its **own**
dispatch entries, not the erase table slot `[0x40054374+8]`. No call into
`0x4002eca4`/`0x4002f11c` was found inside its first 0x2000 bytes. I did not prove the
absence of a re-erase over the *entire* function — residual low-severity uncertainty.

## 6. The 0x4002b5b4 / 0x4002b790 "lock/unlock" pair — CORRECTED IDENTIFICATION

Disassembly shows these are **not flash lock/unlock**:

- `0x4002b5b4`: builds XML `CMD:PROGRESS-REPORT` (string `0x4004df31`), sends it via
  session fnptrs `[r4+4]`/`[r4]`, then waits for a host reply and validates it starts
  with `"OK"` (`cmp r1,#0x4f 'O'; cmpeq r0,#0x4b 'K'` @ `0x4002b670-0x4002b67c`).
  I.e. **"send progress message + await OK"**.
- `0x4002b790`: same skeleton with string `0x4004dfe7` = `"Progress report EOT."`.

Order in WRITE-FLASH: `bl 0x4002b5b4` @ `0x40003244` (progress start) → `blx r2`
@ `0x4000325c` (erase) → `bl 0x4002b790` @ `0x40003268` (progress EOT). The pair
brackets the erase for **progress-reporting**, not for hardware locking. Consequences
for the patch:

1. Both calls are **kept** by the proposed patch (only `blx r2` is replaced), so the
   host still sees the progress-report exchange and the pair is trivially balanced.
   No protocol desync.
2. There is no flash lock state that skipping the erase would leave held — even the
   "alternative" patch (`b 0x40003274` from `0x4000322c`, dropping both calls) would
   not leak a hardware lock; it would only skip two progress messages the host
   (mtkclient) likely tolerates or expects. The proposed patch remains the safer choice.
3. Since the progress-start call awaits host "OK" *before* the erase, the injected
   `mov r0,#0` executes after that exchange — timing/flow unchanged.

## 7. Final verdict

`mov r0,#0` (`00 00 a0 e3`) @ `0x4000325c` is **SAFE** for WRITE-FLASH:

- single erase-result check (`cmp r5,#0; bne 0x400032c4` @ `0x4000326c/70`); r5==0
  takes the success fall-through straight into `0x4002ad04` argument setup;
- no secondary erase-status consumers, no bad-block scan, no post-erase verify in the
  window; r5 dead after 0x4000326c;
- no xrefs (branch, literal, or vtable) into 0x4000325c/60/70 from anywhere else;
- `0x4002b5b4`/`0x4002b790` are progress-report/EOT senders, both preserved → protocol
  exchange intact; no lock-state imbalance possible.

No additional NOPs or companion patches are required. The only untouched residual
risks: (a) `0x4002ad04` not traced end-to-end (no erase re-check found, but not
exhaustively excluded); (b) r2 `axt` blind spots for movw-immediate references (mitigated
by byte-level scans). Note this patch affects only WRITE-FLASH; WRITE-PARTITION's erase
site (`0x40002308` region) and ERASE-FLASH's sites (`0x40003dac`, `0x40003e58`) are
separate call sites and remain untouched.
