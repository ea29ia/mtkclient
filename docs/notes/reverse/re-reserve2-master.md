# Q3: Is oplusreserve2 (UFS 0x4800000) the "master copy" the SEC service restores seccfg from?

**Verdict: NO.** The DA2 SEC service never reads oplusreserve2. The state=2
"regeneration" after a full WRITE-PARTITION of seccfg is produced entirely from
the seccfg partition's *own* dual-record structure (main record @+0x00, backup
record @+0x3c), read back by name `"seccfg"` — not from reserve2, not from a
byte address, and not from efuse constants.

Analysis of `da2_oplus.bin` (md5 74d2b9f2…), load base 0x40000000, ARM32 +
isolated Thumb regions. All disassembly via radare2, `-a arm -b 32 -m 0x40000000`.

---

## 1. Constant search: 0x4800000 / 0x4800 / 0x24000000 / 0x12000000

Raw byte scan of the whole file (little-endian word, so it would also catch any
literal-pool entry):

| constant | hits as 32-bit word |
|---|---|
| `0x04800000` | **none** |
| `0x00004800` | 0x5454f (padding/data coincidence, `48 00 00 00` inside a table region, not code) |
| `0x24000000` | 0x543bd, 0x56c75, 0x56dfd — all inside data tables; context shows they are fragments of unrelated dwords (`0x11c10520`, `0x11c10534`, …), i.e. low bytes `00 00 00 24` coincidences, **not** addresses |
| `0x12000000` | 0x533d9 — same: fragment of `0x40045e07` pointer table area, not an address |

ARM immediate-operand encoding search (rotated imm8; `0x4800 = 0x48 ror 24`
→ imm12r `0xC48`; `0x24000000 = 0x24 ror 8` → imm12r `0x424`):

- `imm12r == 0xC48` (i.e. `#0x4800`): one site, **0x40025554** — it is
  `movw r0, 0xbc48 / movt r0, 0x4004`, a *string pointer* (0x4004bc48), not the
  constant 0x4800. False positive.
- `imm12r == 0x424` (i.e. `#0x24000000`): 0x400273ec, 0x400275a0, 0x4002798c —
  all `movw rX, #0x424` forming *struct field offsets* (`strh r6,[r5,#0x424]`,
  `strh r5,[r4,#0x424]` in a UFS descriptor init). False positives.

Thumb `movw/movt` pairs (T3 encoding) for 0x54bc/0x54f5/etc.: no relevant hits.

**Conclusion: the blob contains no reference to byte address 0x4800000, nor to
LBA 0x4800, nor to the seccfg byte base 0x24000000.** All flash addressing in
this DA is **partition-name-based** (see §2).

## 2. The only references to the strings "seccfg" and "oplusreserve2"

Complete xref census (ARM movw/movt pairs + literal pools, exhaustive scan):

| string VA | referenced from | purpose |
|---|---|---|
| `"seccfg"` 0x400454bc | **0x40034e68** (inside inner reader 0x40034dfc, callee of `sec_get_seccfg` 0x40034d6c) | flash READ of the seccfg partition |
| `"seccfg"` 0x400454bc | **0x40010908** (format-decision fn 0x400108c4) | "need format" decision |
| `"oplusreserve2"` 0x400454f5 | **0x40010924** (the same format-decision fn 0x400108c4) | "need format" decision — **the ONLY reference in the entire binary** |

(There is also a `"seccfg"` reference in `0x40034e70` — same pair, and the
policy hash table at 0x400569b0 holds the `oplusreserve2` name pointer for the
per-partition policy lookup 0x4002cbb4; no code path fetches seccfg data through
it.)

So: **nothing in the DA ever reads oplusreserve2 for any purpose except the
format-permission check.** In particular there is no memcpy-style
reserve2→seccfg loop anywhere: such a loop would need either the name string
(one ref only, in the format decision) or a byte address/LBA (none exist).

## 3. Full trace of sec_get_seccfg 0x40034d6c (the "regeneration" source)

### 3.1 Outer wrapper 0x40034d6c

```
0x40034d6c  push {r4, r5, fp, lr}
0x40034d74  mov r4, r0            ; r0 = out ptr (caller's state slot)
0x40034d78  bl  0x40034dfc        ; inner reader/normalizer
0x40034d7c  mov r5, r0
...
0x40034da4  movw r0, 0xe9f0 / movt r0,0x4006   ; r0 = 0x4006E9F0 (the lock-state global)
0x40034dac  ldr r1, [r0]
0x40034db0  mov r0, #1
0x40034db8  beq 0x40034df0        ; global==0 -> r0=1, done
0x40034dbc  cmp r1, #2
0x40034dc0  beq 0x40034dd8        ; global==2 -> r0 = [0x40067600+0xc]
0x40034dc4  cmp r1, #1
0x40034dd8  movw r0, 0x7600/0x7640 (0x40067600 / 0x40067640)
0x40034de0  ldr r0, [r0, #0xc]    ; record pointer+0xc
0x40034df0  str r0, [r4]          ; *out = ...
```

### 3.2 Inner reader 0x40034dfc — this is where the "state" comes from

```
0x40034e68  movw r0, 0x54bc / movt r0, 0x4004   ; r0 = "seccfg"
0x40034e84  bl  0x4002d4d8                       ; read_by_name("seccfg", buf=0x4005cf00, 0x3000)
```

`0x4002d4d8` resolves the name through the partition-list lookup **0x40012e9c**
(iterates partition entries, 0x58-byte records, strcmp on entry+8) and issues
the read through the storage ops table **[0x40054374]** (`blx r3` with
`ldrd r4,r5,[lr,#0x48]` = LBA from the partition entry). Pure GPT-name access —
no hardcoded offset anywhere.

It then copies the two 0x3c-byte records of the read buffer into two RAM
"slots":

```
0x40034ec4  memcpy(0x40067640, buf,      0x1c)   ; main record body
0x40034ed4  sb = 0x40067660 ; memcpy(sb, buf+0x1c, 0x20) ; main record hash area
0x40034ee8  memcpy(0x40067600, buf+0x3c, 0x1c)   ; BACKUP record body
0x40034f04  r8 = 0x40067620 ; memcpy(r8, buf+0x58, 0x20) ; backup record hash area
```

Validation sequence (`r7 = 0x4d4d4d4d` magic, "MMMM"):

```
0x40034f18  memcmp(main_slot, zero_buf, 0x40)   ; if BOTH slots are all-zero:
0x40034f38  memcmp(backup_slot, zero_buf, 0x40)
0x40034f3c  beq 0x40035008  ->  r4 += 0x2c, return 0x2c   ; blank seccfg -> error 0x2c
0x40034f4c  ldr r0,[main_slot]; cmp r0, 0x4d4d4d4d
            valid -> 0x4003a2d4 (HACC decrypt, 0x1c bytes) -> 0x40035030 (anti-clone hash check)
0x40034f8c  memcmp(main_slot+0x20, decrypted, 0x20) == 0
0x40034f94  beq 0x40034ffc                       ; MAIN RECORD VALID
0x40034fa0  ...same for backup slot...
0x40034fe8  beq 0x40035010                       ; BACKUP RECORD VALID (main invalid)
```

The state writers (the "normalizer" found in the session):

```
0x40034ffc  movw r0, 0xe9f0 / 0x40035000 mov r1, #1   ; MAIN valid  -> state = 1 (LOCKED)
0x40035014  mov r1, #2                                 ; only BACKUP valid -> state = 2 (MP_DEFAULT)
0x40035018  movt r0, 0x4006
0x40035020  str r1, [r0]                               ; [0x4006E9F0] = 1 or 2
0x4003501c  mov r4, #0
```

### 3.3 Read-back of that decision

`sec_get_seccfg` is called from exactly **one** place: 0x4002ce80, inside the
img_auth flag getter 0x4002ce08 (itself wrapped by 0x4002cdf4 → called from
0x4002cf88, the dl_forbidden/img_auth extractors used by the read/write policy
checks):

```
0x4002ce7c  mov r0, sp
0x4002ce80  bl 0x40034d6c                 ; sec_get_seccfg(&state)
0x4002ce84  cmp r0, #0
0x4002ce9c  cmp r5, r1                    ; r1 = 0xc0025a00 (C002 error code)
            equal -> 0x4002ceac: print "[SEC] set lock state as LOCKED"
0x4002ceb8  ldr r0,[sp]; sub r0,#1; cmp r0,#1
            state in {1,2} -> [sp] = 4 ... (format/flag classification)
```

The extra `0x400343xx` function in the same SEC cluster scans the shared seccfg
buffer 0x4005cf00 for records with magic `0x014d4d4d` and copies 0x2bc-byte
blobs to 0x400652cc — the anti-clone record scanner. It also reads only the
seccfg partition content, not reserve2.

## 4. The format-decision function 0x400108c4 (the reserve2/seccfg connection)

This is the only code that mentions both names, and it is about *formatting*,
not about restore:

```
0x40010908  movw r1,0x54bc / movt r1,0x4004   ; "seccfg"
0x40010914  mov r2, #6 ; bl 0x4000b0d8        ; strncmp(name,"seccfg",6) == 0
            -> r5 = [0x40067cce+2]
0x40010924  movw r1,0x54f5 / movt r1,0x4004   ; "oplusreserve2"
0x40010930  mov r2, #0xd ; strncmp(name,"oplusreserve2",13) == 0
0x40010940  "userdata" / 0x4001095c "metadata"
            -> r5 = [0x40067cce+4]
0x40010984  cmp r5, #1
            ==1 -> print "[OPLUS] need format %s"      (0x400454c3)
            !=1 -> print "[OPLUS] do not format %s"    (0x400454db)
```

Same pattern for `oplusreserve2` with the "in smt / in upgrade" strings
(0x40045503 / 0x40045523). So seccfg and oplusreserve2 share the same
**erase-permission gate** (per-name flags in the struct at 0x40067cce) — they
are treated as a *protected pair* for formatting purposes, but this says
nothing about content restoration.

## 5. Verdict on the master-copy hypothesis

**NO — reserve2 is not the master copy the SEC service restores from.**

Evidence:

1. No code references byte address 0x4800000, LBA 0x4800, or 0x24000000
   (exhaustive raw-word + rotated-immediate + movw/movt scan, §1). All flash
   access is name-based through 0x40012e9c / ops table 0x40054374.
2. `"oplusreserve2"` has exactly one code reference in the whole 356 KB binary:
   the format-permission check at 0x40010924. There is no read of that
   partition, no copy loop, no pointer to it in any SEC path.
3. The state=2 write (0x40035014) and state=1 write (0x40035000) are inside the
   seccfg *reader/normalizer* 0x40034dfc, which reads **the seccfg partition
   itself by name** and validates its two internal records. The DA's "own
   state" is a **fallback classification**, not content copied from reserve2.

### Interpretation of the observed state=2 "regeneration" (with uncertainty)

The reader logic implies: after your full WRITE-PARTITION, the DA (during the
post-write policy pass) reads back the freshly written seccfg and classifies it:
main record passes validation → state 1; main record fails but the duplicate
record at +0x3c passes → **state 2 (MP_DEFAULT)** — exactly what was observed
after restoring the original state=4 backup. So the "regeneration with its own
state" is most plausibly: *the DA did not regenerate the content; its
validation of your uploaded main record failed (device-specific
anti-clone/HACC hash), so it classified the partition by its backup record —
state 2.* The "valid new hash" seen on readback is then the record the DA
itself wrote when it committed (or the record that survived), not something
derived from reserve2. I could not locate an explicit flash-rewrite of seccfg
inside the DA (`write-by-name` 0x4002d540 is only called for
`"oplus_custom"` at 0x40010728/0x40010750), so the exact mechanism by which the
readback content differs from the uploaded payload is the remaining unknown —
it may also be that READ-PARTITION for seccfg is served through the same
validated/normalized view rather than raw flash. Honest uncertainty: this last
step is inference, not proven by a located write call.

### Consequences / practical patch guidance

- **Do not bother writing state=3 into oplusreserve2** — it will not propagate;
  the SEC service never reads it. (The existing state=3 block at 0x4800000
  remains forensically inert for the DA; it matters only if LK/bootloader-level
  code consults it, which is outside this blob.)
- The state lever remains the two writers, **but note they are in the *read*
  path, not a write-time regenerator**: `0x40035000` (`MOV r1,#1`→`#3`) and
  `0x40035014` (`MOV r1,#2`→`#3`), storing into 0x4006E9F0. Patching them makes
  every subsequent classification (and therefore every `[SEC]` policy decision
  in read/write handlers) see state=3. Since they run on *every* read pass, the
  right sequence is: commit the write with the stock DA, **then** apply the
  writer patches via patch_mem, then issue any read/verify — matching the
  open question 2 in the session log. If the patched-writers run produced
  all-zero readbacks, the more likely cause is the flaky-read/scrubber
  behaviour documented in the session log, not the writer patch itself.
- If the goal is to make the DA accept *your* seccfg content as valid (state as
  uploaded), the validation to neutralize is the pair
  decrypt(0x4003a2d4) → check(0x40035030) → memcmp at 0x40034f8c/0x40034fdc:
  forcing the `memcmp == 0` branch for the main record (patch the
  `beq 0x40034ffc` decision at 0x40034f94 to unconditional, or RET0 the hash
  check 0x40035030) would make the reader classify any uploaded main record as
  valid → state=1 path with your content. This is untested on-device and should
  be tried only after a verified-good backup; the backup-record branch
  (0x40034fe8) is the fallback.
- The 0x40035008 "both records all-zero → 0x2c" branch is why a zeroed seccfg
  reads as error C002… in later sessions.

## 6. Address quick-reference (this build)

| VA | meaning |
|---|---|
| 0x40034d6c | sec_get_seccfg (outer) |
| 0x40034dfc | inner seccfg reader/normalizer (reads "seccfg" @0x40034e68) |
| 0x40034e68/0x40034e70 | movw/movt → "seccfg" string |
| 0x40034ffc/0x40035000 | state writer #1 (main record valid → 1) |
| 0x40035014 | state writer #2 (backup-only valid → 2) |
| 0x40035020 | `str r1,[0x4006E9F0]` |
| 0x40067640 / 0x40067660 | main record slot (body / hash) |
| 0x40067600 / 0x40067620 | backup record slot (body / hash) |
| 0x4005cf00 | shared 0x3000-byte seccfg read buffer |
| 0x4002d4d8 / 0x4002d464 | read-by-name wrapper / init |
| 0x40012e9c | partition-name lookup (GPT entries, 0x58 stride) |
| 0x40054374 | storage ops table (read @+0, write @+4) |
| 0x4003a2d4 | HACC decrypt (record body) |
| 0x40035030 | anti-clone hash check (keyed on byte @0x40056e30) |
| 0x400108c4 | format-decision fn (the only "oplusreserve2" ref @0x40010924) |
| 0x400569b0 | policy-table entry alias "oplusreserve2" (idx 57, table 0x4005628c) |
