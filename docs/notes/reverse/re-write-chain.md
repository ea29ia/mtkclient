# RE: USB-received write payload → storage-write data path (RMX3630 OPLUS DA2)

> **ERRATA (2026-10-24, audit #2):** (1) the program dispatcher 0x4002AAC0 is
> **dead code**; the storage table slot is **+8** (0x40054328), not +0x10.
> (2) `<pre_erase>NO</pre_erase>` **is always sent** (xml_cmd.py:453), so the DA
> erase phase was skipped **by the flag** — the "silent erase" model is void.
> (3) The write loop has a single exit (`accumulated == target`).
> See `re-consistency-audit-2.md` §C3/§3.

Binary: `docs/notes/rmx3630-da2/da2_oplus.bin` (356296 B, file offset 0 == VA 0x40000000),
ARM32. Tool: radare2 (`-a arm -b 32 -m 0x40000000`). This answers open question:
**is the uploaded payload written as-received, or does a SEC "normalizer" rewrite it?**

## TL;DR verdict

**DIRECT PASS-THROUGH.** The bytes the host uploads are DMA'd into a bounce buffer and
written to UFS **unmodified**. There is **no** SEC normalizer, no hash recomputation, no
HACC transform, and no staging/rewrite path anywhere between USB receive and
`blx [0x40054374+4]`. The only per-chunk security operation is an optional **HACC
(ACC anti-clone) transform of the buffer BEFORE writing** (i.e. the payload is
*encrypted/obfuscated in place*, not replaced) and it is gated on the ACC-enable byte
`0x40067BA9` — the same branch documented in `re-postwrite-hang.md`.

Consequence for the observed "uploaded seccfg comes back normalized/regenerated":
that behavior is **not** produced by a write-time normalizer. Consistent with
`re-reserve2-master.md`, the readback difference comes from the **read/verify path**
(seccfg loader `0x40034dfc` re-reads, re-validates the two "MMMM" records with the
device-keyed digest `0x4003a2d4` + anti-clone check `0x40035030`, and reports by
`+0xc` of the surviving record) — plus, critically, **WRITE-PARTITION's erase stage
(§3)**, which with mtkclient's current XML (no `pre_erase` node) wipes the partition
before the data phase. The DA never stores different bytes than it received.

## 1. Entry 0x4002ad04 — the post-parse write driver (both engines)

```
0x4002ad04  push {r4-r8,sb,sl,fp,lr}; sub sp,#0x49c ; args: r0=fmt/handle, r1=name, r2=region-array, r3, [sp]=count
0x4002ad28  ldr r5,[sp,8]                 ; count / or default
0x4002ad4c  movw r0,0x7a08; movt 0x4006   ; globals 0x40067A08 (chk flags), +0x14
0x4002ad64  bl 0x4000b668                 ; strlen(name)
0x4002ad70  bl 0x4002aba8                 ; CHK_ADD / CHK_NO header select (strings 0x4004dd49 / 0x4004dc6a)
0x4002adb4  bl 0x4000a638                 ; snprintf XML: "CMD:DOWNLOAD-FILE ... <checksum>%s<info>%s<source_file>%s<packet_length>0x%x" (fmt 0x4004dd51)
0x4002adbc  ldr r2,[r4,4]; blx r2         ; send to host
0x4002addc  ldr r2,[r4];   blx r2         ; read host reply (0x40-byte buf)
0x4002ae28  cmp 'O','K'                   ; expect "OK" else 0xC0010001
--- name gate ---
0x4002ae60  bl 0x4002c6cc                 ; == "PRELOADER" (0x40045bf6, 9B)?  (clz/lsr wrapper)
0x4002ae68  beq 0x4002ae7c                ; PRELOADER -> fcn.4000c348 engine
0x4002ae74  bl 0x4000c348                 ; (r0=region array, r1=arg4)
0x4002ae7c  bl 0x400306ac                 ; NON-preloader -> engine-2 (0x400306ac)
```

Note the branch polarity: **`beq 0x4002ae7c` falls into the non-preloader engine** —
i.e. every ordinary partition (incl. seccfg) takes **0x400306ac**, and only
PRELOADER-named writes take `0x4000c348 → fcn.4000bb14`.

## 2. Engine 1: fcn.4000c348 → fcn.4000bb14 (WRITE-PARTITION path)

```
0x4000c348  progress-slot ptr 0x4006A040 <- sp+8 {+8=1, +0xc=0}; memset 0x18
0x4000c39c  log "Download [%s] with file:%s" (0x40043b79)
0x4000c3ac  bl fcn.4000bb14
0x4000c3d4  log 0x40043b8a (result) ; return r4
```

fcn.4000bb14 (chunk loop, r7 = region array, r4 = [0x40067A08+0x14] total len):

```
0x4000bb44  bl 0x4002cf58                 ; policy-parse enabled flag
0x4000bb5c  sl = (total+0x3f) & ~0x3f     ; chunk size 64-aligned
0x4000bb60  bl 0x4000a59c                 ; alloc bounce buffer (size=sl)
0x4000bb84  bl 0x4000c274                 ; XML FILE-SIZE op -> sp+0x14/0x18 (offset,len)
0x4000bbac  bl 0x4000aef4                 ; ascii-hex -> u64 ; store into 0x4006A040+0x10 (u64)
0x4000bbbc  remaining = [r7+0x50..] - off ; larger -> err 0x40043ac9
0x4000bc30  blx [0x40054320+4]            ; USB: log op 3 ("packet start")
0x4000bcc4  r1 = sp+0x20; ldr r2,[r5]     ; r5=0x40054320
0x4000bcd4  ldr r0,[var_10h]              ; the bounce buffer
0x4000bcd8  blx r2                        ; <-- USB RECEIVE into bounce buffer (per chunk)
0x4000bd28  bl 0x40001508(buf, len)       ; chk/progress reporter (uses 0x4000f068 hex fmt,
                                          ;  blx [0x40054320+4]) — read-only, no transform
0x4000bd90  bl 0x400334ac(buf)            ; checksum/CRC length helper
0x4000bda4  bl 0x40034250(off, len)       ; region lookup (see below)
0x4000bdb0  ldrb r0,[sl,1]                ; policy struct byte+1
0x4000bdc8  bl 0x4000b330                 ; memset(sp+0x28, 0, 0x20)
0x4000bdec  bl 0x4003a2d4(buf, len, sp+0x28)  ; SHA-256 over the RECEIVED chunk (verification digest)
0x4000c01c  bl 0x4000b0d8(digest, [sl+4], 0x20) ; memcmp vs expected hash
0x4000be10  ldrb r0,[sl,2]                ; policy byte+2
0x4000be28  bl 0x40037f70(buf, len)       ; secondary hash/verify (ACC-related)
0x4000c168  bl 0x40035ce4
0x4000c194  bl 0x40035654(request+8, region)  ; per-chunk oplus SEC hook (ret!=0 -> error)
--- program the chunk ---
0x4000bf20  bl 0x4000c3e4(bounce_buf, chunk_len, r7)  ; r2 = region array
--- write engine internals ---
0x4000bef4  ldr r2,[0x40054374+8]; blx r2 ; unit-prepare op (r0=0,r1=chunk_off)
0x4000bf20  bl 0x4000c3e4                 ; program (below)
0x4000bf88  bl 0x40033cd0                 ; SEC pass (see §2.1)
0x4000bfe4  bl 0x400348ec                 ; SEC pass 2 (see §2.1)
--- after last chunk ---
0x4000c1e8  bl 0x40033b64(&acc_en, &acc_off, &acc_len, 1)
0x4000c210  beq 0x4000c258                ; acc_en==0 -> plain
0x4000c228  bl 0x40034810                 ; HACC key load -> 0x1000A060
0x4000c240  bl 0x40034840(buf+acc_off, acc_len, 1) ; HACC transform OF THE BUFFER (the hang site)
0x4000c244  bl 0x4003482c                 ; key wipe
```

### 2.1 fcn.4000c3e4 — the actual program step (this is [0x40054374+4])

```
0x4000c440  bl 0x4000c6b8(region_array, sp+0x20) ; split chunk into region slices
0x4000c4bc  movw r0,0x4374; movt r0,0x4005   ; THE ops table
0x4000c4cc  ldr r3,[r0,4]                     ; r3 = [0x40054374+4]
0x4000c4f4  blx r3                            ; r0=0, r1=LBA, r2=buf, r3=len, [sp]=phys, +4/8=region arr
0x4000c520  bl 0x40001508(buf,len)            ; progress/echo
0x4000c534  ldr r3,[r0]                       ; r3 = [0x40054374+0]
0x4000c554  blx r3                            ; READ-BACK verify of the same region
0x4000c568  bl 0x40001508(buf,len)
0x4000c570  bne 0x4000c688                    ; mismatch -> error
```

**No transformation of the buffer between USB receive and the write call.**
The buffer pointer flows: `0x4000a59c` alloc → `blx [0x40054320]` (USB recv) →
`0x4000c3e4` arg0 → `blx [0x40054374+4]` arg2.

## 3. Engine 2: 0x400306ac (non-PRELOADER path, incl. seccfg)

```
0x400306ac  progress-slot 0x4006E7CC <- fp-0x40 {+8=1}; 0x4006E7D0 <- sp+4
0x400306e0  bl 0x4002f5f8                 ; open/lookup partition (ret<0 -> err)
0x400306fc  strb 1,[slot]; [slot+0x20]=r4(handler ctx); [slot+0x24]=r7
0x40030720  bl 0x40007d5c(request+8, len) ; log
0x4003076c  bl 0x400096d8(0x10000,0x4002ff78,0,0x10)  ; storage setup
0x4003077c  bl 0x4003010c                 ; THE DATA LOOP (see below)
0x400307f4  bl 0x4002f7bc                 ; close/flush
0x40030810  bl 0x40008234                 ; commit
```

fcn.4003010c (per-chunk):

```
0x4003014c  bl 0x4003053c(sp+0xc)         ; USB XML exchange: blx [0x40054320] send,
                                          ; 0x40008300 recv, expect "OK"
0x4003016c  bl 0x4000aef4                 ; hex -> u64 (chunk offset)
0x400301ec  blx [0x40054320+4]            ; USB op 3 (log/packet)
0x40030398  ldr r0,[0x4006E7D0+8]; add r0,sl ; ldr r2,[0x40054320]
0x40030398  blx r2                        ; <-- USB RECEIVE chunk into buffer (bounce buf from 0x4002aac0 region)
0x400303d0  bl 0x40001508(buf,len)        ; checksum/progress reporter (read-only)
0x400303ec  [0x4006E7D0 slot +0x4c] += len; [0x4006E7CC+0x18] += len
0x40030444  bl 0x40030610(off,r2,r3)      ; progress log to host (hex fmt 0x4004f54f)
0x40030418  ldr r2,[0x4006E7D0+8]         ; the PROGRAM slot:
0x40030420  ldr r2,[0x4006E7D0 slot+0x10]; add r2,r2,r7 ; r2 = dest pointer += chunk len
```

The write is issued by the program dispatcher **`0x4002aac0`** (referenced only from
literal pool `0x40054328`, i.e. inside the `0x40054320` session-op table):

```
0x4002aac0  movw r6,0x4330; movt 0x4005   ; r6 = 0x40054330 ("chunk/page size", 0xFF-filled)
0x4002aae4  ldr r2,[r6,0x10]
0x4002aaf4  cmp r2,0 ; beq 0x4002ab74     ; not configured -> skip
            ... 0x4002ab3x: blx [r2+X]    ; low-level program with the received buffer
```

Same conclusion: the received buffer address is handed straight to the program call;
the only intervening code is logging (`0x40007c10/0x40007d5c`), checksum echo
(`0x40001508`), and progress math. `0x40030610` formats a progress string
(`0x4004f54f`) and sends via `[0x40054320+4]` — metadata only, never the payload.

## 4. The `0x40054374` / `0x40054320` ops tables

```
0x40054374: +0x00 0x40008238 -> b 0x4002f2f0   (read-back/verify used by 0x4000c534)
            +0x04 0x4000823c -> b 0x4002e744   (WRITE / program  — the task's target)
            +0x08 0x4002eca4                    (erase dispatcher, per re-writeflash-scrubber.md)
            +0x0c 0x4002f228                    (region/request helper)
0x40054320: +0x00 0x40008244 -> b 0x4002a934   (USB send/log op)
            +0x04 0x40008240 -> b 0x4002aa14   (USB receive/other op)
            +0x10 0x4002aac0                    (program dispatcher, lit-pool ref at 0x40054328)
```

`0x4002e744` (+4 target) was not fully disassembled in this pass; its callers pass the
same untouched buffer pointer and it is the low-level program entry behind the
readback-verify pair above (honest uncertainty: its internal queueing not traced to
the UFI command).

## 5. Why the seccfg readback "regenerates" — where the normalization is NOT

- **`sec_get_seccfg` 0x40034d6c / loader 0x40034dfc / classifier 0x40035030 /
  digest 0x4003a2d4 are never called from any write engine.** Verified: their only
  caller is `0x4002ce80` (policy-flag getter `fcn.4002ce08`), reached only from the
  **pre-upload** policy parse (`0x4000217c` WRITE-PARTITION, `0x400030f0` WRITE-FLASH).
- The "state writers" `0x40034ffc/0x40035014` write 1/2 into `0x4006E9F0` during that
  **read** classification — they set no flash content.
- There is no code that builds a fresh "MMMM"-magic record buffer and writes it: the
  only write-by-name call sites in the blob are the two `0x4002d540("oplus_custom")`
  calls inside `sec_write_wrapper` at `0x40010728/0x40010750` (CMD:OPLUS-WRITE-HASH256-ID
  region, string `[OPLUS]sec_write_wrapper two time fail` 0x400453a3) — a different
  command, not the seccfg path.
- Therefore the "device-keyed normalized content on readback" is the read path's
  classification + the **erase that precedes the data phase** (WRITE-PARTITION erases
  when `pre_erase` node is absent and name != PRELOADER — `0x400021d8 cmp r8,0 →
  0x40002204 → 0x40002214 beq 0x400022a8 erase path`, and mtkclient sends no
  `pre_erase`), not a rewrite by the DA.

## 6. Call-chain summary

```
WRITE-PARTITION 0x40002034
  └ 0x4002ad04 (post-parse driver; "OK" handshake)
      └ (name != PRELOADER) 0x400306ac
          └ 0x4003010c   loop:
              0x4003053c USB XML "OK" exchange
              0x4000aef4 offset parse
              blx [0x40054320]    USB RECV chunk -> bounce buffer
              0x40001508          checksum/progress echo (no transform)
              (dest ptr built at 0x40030418; program via 0x4002aac0 lit-pool @0x40054328)
      └ (name == PRELOADER) 0x4000c348 → fcn.4000bb14
          0x4000a59c alloc bounce buf
          blx [0x40054320]        USB RECV chunk
          0x4003a2d4 / 0x40037f70 digest checks (read-only)
          0x4000c3e4 → blx [0x40054374+4]  PROGRAM (payload as received)
          blx [0x40054374+0]      read-back verify
          [0x40067BA9] ACC gate → 0x40034810/0x40034840/0x4003482c (in-place HACC, hang site)
```

## 7. Patch guidance

- **There is no normalization to disable** — no `patch_mem` point in the write chain
  changes the stored bytes. Do not hunt for one.
- To keep the payload exactly as uploaded AND avoid the HACC hang:
  `0x4000c210` (`beq 0x4000c258`) → `b 0x4000c258` (`EA00000A`), or zero the
  ACC-enable byte `0x40067BA9` before the write. This only skips the in-place HACC
  pass; the plain bytes still get written (the HACC branch transforms in place, so
  skipping it changes stored content only if a reader expects ACC-encrypted layout).
- To avoid the seccfg scrub on WRITE-PARTITION, patch the erase gate as documented in
  `re-writeflash-scrubber.md` §5 (`0x40002308 blx r2` region / `0x4000325c` for
  WRITE-FLASH) — or send a `pre_erase=YES`-absent-compatible flow is already default;
  the current silent-erase comes from the missing-node branch at `0x400021e4`.
- The read-side "validation" (digest mismatch → state classification) lives at
  `0x40034f94`/`0x40034fdc` beqs + `0x40035030` (per re-reserve2-master.md §5) —
  that is the lever if the goal is to make the DA *accept* uploaded seccfg content
  as valid; it is a read-path change, not a write-path one.

## 8. Uncertainty

- `0x4002e744` / `0x4002aac0` internals (low-level UFI/program queue) not traced to
  the hardware command; concluded from caller-side buffer-flow analysis only.
- Whether `0x40035654` (per-chunk SEC hook in engine 1, called with `request+8`) can
  modify the buffer was not fully disassembled; it is called *after* the digest and
  *before* the program call, so a malicious/odd return value only produces an error
  path (`0x4000c1a0`); it receives `r0=request+8, r1=region`, not a data pointer.
- The ACC transform is in-place (buf+acc_off, acc_len) per `re-postwrite-hang.md`;
  treating "in-place transform ≠ replace" as the operative distinction.
