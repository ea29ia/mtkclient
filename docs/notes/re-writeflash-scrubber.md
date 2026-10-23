# WRITE-FLASH "anti-tamper scrubber" — reverse-engineering report (RMX3630 OPLUS DA2)

Binary: `docs/notes/rmx3630-da2/da2_oplus.bin` (md5 74d2b9f2…), VA base 0x40000000,
ARM32. Tooling: radare2 (`r2 -a arm -b 32 -m 0x40000000`). All addresses below are VAs.

## TL;DR

There is **no separate anti-tamper scrubber function**. The scrub is the WRITE-FLASH
command's own **mandatory erase-before-program stage**:

- `CMD:WRITE-FLASH` handler `0x40002e60` **unconditionally erases** the target range
  (via storage fnptr `[0x40054374+8]` = `0x4002eca4`) **before** it receives/programs a
  single byte (`0x4002ad04` at `0x4000328c`).
- If the session hangs/aborts anywhere between the erase call and the data phase, the
  erased (all-zero) region is what remains — exactly the observed 4× zeroing of the 8 MB
  seccfg area, including runs that "hung before any data transfer" (the data phase starts
  only after the erase has completed).
- The DA *does* have a seccfg-aware "do not format" protection layer
  (`fcn.400108c4`, flags at `0x40067cce`, log `"[OPLUS] do not format %s"` /
  `"[oplus]keep %s"`), but **WRITE-FLASH never consults it** — that is the hole.
- `CMD:WRITE-PARTITION` (`0x40002034`) erases only behind two gates
  (`pre_erase == "YES"` and name ≠ `"PRELOADER"`), which is why writes by partition name
  do not show the same unconditional scrub behavior.

## 1. WRITE-FLASH handler `0x40002e60` — full flow map

Prologue/parse:

```
0x40002e60  push {r4..fp, lr}
0x40002e88  bl 0x4000b330          ; memset(sp+0x58, 0, 0x58)  request struct
0x40002e9c  bl 0x4000d0bc          ; parse command XML (r1=session, r2=fmt 0x4000ede8)
0x40002ea4  beq 0x4000302c         ; parse fail -> err print global 0x40054314
0x40002eb4  bl 0x40001e48  (node "da/arg/partition"   0x40041a69) -> r6
0x40002ed0  bl 0x40001e48  (node "da/arg/source_file" 0x400417cc) -> r4
0x40002eec  bl 0x40001e48  (node "da/arg/offset"      0x40041d99) -> r5
0x40002f20  bl 0x40012c20          ; copy partition name -> sp+0x48
```

Address/length computation and range check:

```
0x40002f4c  bl 0x4000aef4          ; ascii-hex -> u64 (offset)
0x40002f60  subs r5, r2, r0        ; offset vs partition max size
0x40002f74  bhs 0x40003064         ; too big -> "[%s]Base address[...] larger than partition max size" (0x40041dd3)
0x40002fa4  bl 0x4000f6f8          ; build 0x40-stride storage region entries (name+addr+len) into sp+0x58 struct
```

Host file size (the eventual WRITE length):

```
0x40002fb8  bl 0x4002b874          ; r1=2 (FILE-SIZE op), r2=source_file node, default "0x0" (0x40041e16)
0x40002fd8  ble 0x4000307c         ; -1 -> "Get host file size failed." (0x40041e1a)
0x40002ff8  bhs 0x4000308c         ; file size <= partition max : ok
0x40003008  bl 0x400084a4          ; "Host file size[%llx] is larger than max partition available size[%llx]" (0x40041e35)
```

Policy parse + per-partition deny loop (the already-known deny sites):

```
0x400030f0  bl 0x4002cf58          ; writes 1 into [sp+0x2c] ("policy check enabled"), returns 0
0x40003138  bl 0x40012fb8          ; enum regions of the request struct (r1=&cnt1 sp+0x20, r2=&cnt2 sp+0x28)
0x40003188  loop: bl 0x4002cf68    ; parse policy entry (0x40 stride) -> sp+0x30
0x40003194  ldrb r0,[sp,0x30]; cmp 1
0x400031a4  beq 0x400031d4         ;  <-- deny BEQ #1 (NOPed)
0x400031a8  ldrb r0,[sp,0x30]; cmp 1
0x400031b0  beq 0x400031d4         ;  <-- deny BEQ #2 (NOPed)
0x400031d4  movw r0,0x1af8 -> "Security deny for [%s]." (0x40041af8); bl 0x400084a4; r6=0xC002C000 err
```

**The erase-then-program core** (this is the scrubber):

```
0x40003200  bl 0x40007cbc          ; log level
0x4000321c  movw r0,0x1b11 -> "Erase [%s] At[0x%llx] Len[0x%llx]\n" (0x40041b11)
0x40003228  bl 0x40007c10          ; <-- the erase is logged BEFORE any data moves
0x4000322c  movw r0,0xb6a0         ; 0x4002b6a0 (stored to [var_24h])
0x40003244  bl 0x4002b5b4          ; flash/storage lock (session)
0x4000325c  blx r2                 ; r2 = [0x40054374+8] = 0x4002eca4  <== THE ERASE
                                   ; args: r0 = request struct sp+0x58 (name/section/addr/len),
                                   ;       r1 = sp+0x20
0x40003260  mov r5, r0
0x40003268  bl 0x4002b790          ; flash/storage unlock (session)
0x40003270  bne 0x400032c4         ; erase failed -> error out
0x40003274  mov r0,0 / r2=sp+0x58 / r3=sp+0x30 / str r0,[sp]
0x4000328c  bl 0x4002ad04          ; <== DATA RECEIVE + PROGRAM (first byte of payload moves HERE)
0x40003290  cmp r0,0; bne 0x400032c4
0x400032b0  bl 0x4002c4a0          ; post-write pass (feedback/verify), r0=request struct tail
0x400032c0  mov r7,0               ; success
```

`0x40054374` dispatch table (words): `0x40008238, 0x4000823c, 0x4002eca4, 0x4002f228,
0x4002f3d8, …` — slot +8 = `0x4002eca4`, the storage erase dispatcher (splits the request
into erase regions — strings `storage_erase` 0x4004a7d0, `erase_storage` 0x4004f077 — and
finally calls the low-level erase at `0x4002f11c` → `0x4000f760` / `0x4000ccb8`).

### Erase-early mechanism (answers "where can an ERASE occur BEFORE data transfer")

The order inside the handler is fixed:

1. XML parse → partition name / offset / source_file nodes.
2. `FILE-SIZE` query to host (`0x4002b874`, op=2) — no payload moves yet.
3. Policy deny loop (0x40003188…) — prints only, already NOPed.
4. **ERASE of the whole declared range** (`blx 0x4002eca4` @ `0x4000325c`, after the
   `"Erase [%s] At[...] Len[...]"` log at 0x4000321c).
5. Only then `0x4002ad04` = receive + program.

So a WRITE-FLASH exchange that dies at any point after step 4 (including the classic
post-command hang, or a death during the subsequent bulk phase) leaves the target
**fully erased**. The erase length equals the declared write length (host file size), so
an 8 MB seccfg write attempt → 8 MB of 0x00. Nothing seccfg-specific here; it is plain
erase-then-program semantics with no pre_erase opt-in.

## 2. seccfg special-casing and the (real) anti-tamper layer

### Partition-name protection: `fcn.400108c4`

```
0x400108f8  ldrb r0,[r6,3]         ; r6 = 0x40067cce (runtime config, 5 bytes)
0x40010900  cmp r0,0; bne …        ; byte+3 == 0 -> return 0 (protection DISABLED)
0x40010914  bl 0x4000b0d8 (name, "seccfg" 0x400454bc, 6)  -> eq: flag = [r6+2]
0x40010934  bl 0x4000b0d8 (name, "oplusreserve2" 0x400454f5, 0xd) -> eq: flag = [r6+1]
0x40010950/0x4001096c (name, "userdata"/"metadata" 0x40045548/0x40045551, 8) -> flag = [r6+4]
0x4001098c  flag==1    -> "[OPLUS] do not format %s" (0x400454c2), return 1
0x400109b4  flag!=1    -> "[OPLUS] need format  %s in smt" (0x400454db), return 2
   (oplusreserve2 variant: flag==0x1a -> "[OPLUS] do not format %s in upgrade" 0x40045503, return 1)
```

The only direct BL caller is `0x400055a8` inside the generic erase dispatcher
`fcn.40005400`:

```
0x400055a8  bl 0x400108c4          ; r0 = partition name
0x400055ac  cmp r0,2; bne 0x400055d8
0x400055c4  movw r0,0x247b -> "[oplus]keep %s" (0x4004247b)   ; return 2 -> erase SKIPPED
0x400055d8  bl 0x4002c6cc          ; name == "PRELOADER" (0x40045bf6, 9 chars) -> skip erase
0x4000561c…0x4000564c  blx [0x40054374+8]                   ; the same erase call
```

Note the semantics are inverted from the log text: return 2 ("need format in smt") is the
value that makes the generic erase dispatcher **keep** the partition; return 1
("do not format") falls through and the erase still runs. What protects seccfg in
ERASE-FLASH/ERASE-PARTITION-type flows is therefore: config byte+3 ≠ 0 **and** seccfg
flag byte+2 ≠ 1.

### Where the config comes from

`oplus_security_verify_sec_policy` (`0x400103dc`) — i.e. the SET-FLASH-POLICY blob you
already upload — seeds it:

```
0x40010438  bl 0x4000b110          ; memcpy(0x40067cce, policy_blob+0x700, 5)
0x400105e8  (policy byte[1]==0x1c) -> [0x4005455c]=4  (read-back mode; "[OPLUS] this is read back mode")
0x40010630  (policy byte[0]==0x19 && status==1) -> [0x4005455c]=5 ("[OPLUS] Dev Mode")
```

So the seccfg "do not format" state is **host-controllable via the policy blob** at
offset 0x700 (bytes +1/+2/+3/+4). In file the config area is 0xFF (uninitialized);
runtime value depends on what was uploaded. **Caveat:** we have not dumped the live
0x40067cce content during a session, so the actual on-device flag values are unknown.

### Negative results (honest)

- `izz` finds `seccfg` (0x400454bc), `SEC_CFG` (0x400510c3),
  `[%s] SECCFG Anti-Clone Enabled\n` (0x400510eb), `[%s] sec_get_seccfg ret=%x`
  (0x400510a7). Full-`aaa` xrefs: the plain `seccfg` string is referenced **only** by
  `fcn.400108c4` (0x40010910) and `sec_get_seccfg` region (0x40034e70). No code xrefs
  found for the `SEC_CFG` / `Anti-Clone` strings by r2's xref engine (movw/movt immediate
  refs are frequently missed by r2; treat "no xrefs" with mild suspicion, but byte-level
  scans for the corresponding movw/movt pairs around the WRITE-FLASH handler found
  nothing either).
- I found **no** "erase seccfg on verification failure" or "zero on session abort" code
  path. Everything observed is explained by the unconditional WRITE-FLASH erase followed
  by a dead session. (Residual uncertainty: the post-write SEC pass `0x4002c4a0` /
  `sec_get_seccfg` `0x40034d6c` / table service `0x4002c800` may *rewrite* seccfg after a
  successful write — that is question 1/3 territory, not the zeroing mechanism.)

## 3. ERASE-FLASH `0x400039c0` — shared logic

Same skeleton as WRITE-FLASH: XML parse (0x4000d0bc), nodes `da/arg/partition`
(0x40041a69), `da/arg/offset` (0x40041d99) plus strncmp checks against 0x4004209f (9
chars) / 0x400420a8 (4) / 0x400420ac (4); per-partition policy parse loop with
`0x4002cf68` at `0x40003928` and the deny byte check:

```
0x4000392c  ldrb r0,[sp,3]; cmp 0; beq ok
0x40003944  bl 0x400084a4          ; "Security deny for [%s]." ; r6=0xC002004 err
```

**Attribution correction:** the deny site `0x4000392c` documented in the session notes as
"WRITE-FLASH" is actually inside **ERASE-FLASH** `fcn.400039c0` (WRITE-FLASH's own deny
checks are the 0x40003194–0x400031b0 pair). ERASE-FLASH also erases through the same
fnptr: `blx r2` with `[0x40054374+8]` at `0x40003dac` (and a second dispatch at
`0x40003e58`).

## 4. WRITE-PARTITION `0x40002034` — discriminating branches

WRITE-PARTITION parses `da/arg/partition`, `da/arg/source_file` and additionally
**`da/arg/pre_erase`** (0x40041a7a). Its erase stage is gated:

```
0x400021d8  cmp r8,0               ; r8 = "da/arg/pre_erase" node value
0x400021e4  beq 0x40002204         ; node absent -> go to name check
0x400021f8  bl 0x4000b5e0          ; strncmp(value, "YES" @0x40041a01, 4)
0x40002200  bne 0x40002218         ; != "YES" -> SKIP ERASE, program only
0x40002204  bl 0x4002c6cc          ; name == "PRELOADER" (0x40045bf6) ? -> returns 1
0x40002214  beq 0x400022a8         ; == 0 (not preloader) -> ERASE path (0x400022a8)
0x400022a8  "Erase [%s] At[...] Len[...]" ; bl 0x4002b5b4; blx [0x40054374+8]; bl 0x4002b790
0x4000231c  beq 0x40002218         ; after erase, join program path
```

So:

| | WRITE-FLASH 0x40002e60 | WRITE-PARTITION 0x40002034 |
|---|---|---|
| pre_erase gate | **none** (3rd node is `da/arg/offset`) | erase only if `pre_erase == "YES"` |
| name gate | none | erase skipped for `"PRELOADER"` (`0x4002c6cc`) |
| OPLUS keep-check `fcn.400108c4` | **not called** | not called either (but same erase call) |
| erase call | unconditional `0x4000325c` | conditional `0x40002308` |
| data phase | `0x4002ad04` @ 0x4000328c | receive loop from `0x40002218`/`0x4000edf0` @ 0x400024f0 |

mtkclient's `cmd_write_partition()` (`Library/DA/xmlflash/xml_cmd.py:443`) sends only
`<partition>` + `<source_file>` — **no `pre_erase` node** — so per the disasm it *should*
still hit the name check → erase path. **Honest discrepancy:** the session log records
that even a 512 B WRITE-PARTITION zeroed the readback ("erase + silent no-op"), which is
consistent with WRITE-PARTITION erasing too; the practical reason WRITE-PARTITION is
safe for seccfg is that its full-8MB transfers complete and the SEC service then
regenerates the block, whereas the WRITE-FLASH exchanges repeatedly died after the erase
but before programming. If WRITE-PARTITION's silent scrubbing is also unwanted, the same
neutralization applies (see below, second patch site).

## 5. Proposed `patch_mem` neutralization

Primary — kill the WRITE-FLASH erase while keeping the lock/unlock pair balanced
(single 32-bit word at the erase call site):

| VA | stock | patch | effect |
|---|---|---|---|
| `0x4000325c` | `blx r2` (`32 ff 2f e1`) | `mov r0,#0` (`00 00 a0 e3`) | erase dispatcher is never called; handler sees "erase ok" (r5=0) and proceeds straight to the data receive `0x4002ad04`. `0x4002b5b4`/`0x4002b790` (lock/unlock) remain paired. On UFS, programming over non-erased LBAs is fine. |

Alternative — skip the whole erase block:

| VA | stock | patch |
|---|---|---|
| `0x4000322c` | `movw r0,0xb6a0` (`a0 06 0b e3`) | `b 0x40003274` (`10 00 00 ea`) — jumps past 0x4002b5b4/blx/0x4002b790 directly into the data-receive setup. Slightly riskier (drops the lock/unlock pair). |

Optional hardening for WRITE-PARTITION (not currently needed, only if its erase turns
out to matter): patch `0x40002214` `beq 0x400022a8` (`23 00 00 0a`) → `b 0x40002218`
 NOP (`00 00 a0 e1` … precisely: replace with `nop`-equivalent or invert) so the
erase path is unreachable; or patch `0x4000220c`'s `bl 0x4002c6cc` to `mov r0,#1`
(`01 00 a0 e3`), which forces the "name==PRELOADER" skip for every partition.

Do NOT patch: `0x400084a4` (generic deny printer, ~130 callers), `0x4002eca4` itself
(it is the shared erase used by ERASE-* commands), or the `fcn.400108c4` protection
(it is the only thing keeping ERASE-PARTITION/ERASE-FLASH from wiping seccfg in flows
that consult it).

## 6. Uncertainties

- Live value of the 5 config bytes at `0x40067cce` (set from policy blob +0x700 by
  `0x40010438`) was not observed on device; the dummy policy's content determines
  whether the keep-protection is even enabled (byte+3).
- `fcn.40005400` (the oplus-aware erase dispatcher with the `[oplus]keep` check) has no
  direct BL callers and no literal-pool references found — presumably reached through the
  `0x4002f228`/`0x4002f3d8` dispatch slots (FLASH-ALL/FLASH-UPDATE download flows).
  Low confidence on its exact callers; the protection analysis stands on its own code.
- Whether WRITE-PARTITION's erase length is the write length or the full partition size
  (explains the 512 B "erase + no-op" observation) was not traced to the bottom.
- The post-write hang/EIO itself (question 1 of the open list) is untouched by this
  analysis; neutralizing the erase will not by itself fix the hang, but it removes the
  data-destructive consequence of the hang.
