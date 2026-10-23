# RE: legitimate authorization paths in RMX3630 OPLUS DA2 (`da2_oplus.bin`)

Date: 2026-10-24. Tool: radare2 (`-a arm -b 32 -m 0x40000000`, file offset 0 == VA).
Binary: `docs/notes/rmx3630-da2/da2_oplus.bin` (356296 B, sha256 `fd3a5038…`).
Mission: find any path that sets `g_oplus_auth_status` (0x4005455c) to 1/2 (FULL command
table) **without** the OPLUS auth server.

## TL;DR

**No unsigned/fallback/efuse/factory bypass exists.** The only writer of 1/2 is
`oplus_security_verify_sec_policy` (0x400103dc), and it requires a 2048-bit
RSA PKCS#1 v1.5 / SHA-256 signature under a **hardcoded modulus** with **e = 65537**.
The signature covers the **device-info context** (not the policy body!). One real
weakness found: **the policy body after the first 0x100 bytes is not covered by the
signature**, and one signed-message input (SHA-256 of the uploaded AllInOne blob) is
fully host-controlled — but both only matter *once you already possess one validly
signed blob*, which still requires the OPLUS auth server. Runtime patching remains
the practical route.

---

## 1. SET-ALLINONE-SIGNATURE (0x40006c1c) — what it does (proven)

```
0x40006c1c  get XML doc (0x4000d0bc), node "Signature" (0x40042f12)
            -> 0x4002ae8c (secure-node executor: unescape into buffer, out ptr/len
               at [sp+8]/[sp+0xc]; session-object funcptrs must answer "OK")
            -> 0x4002d428(ptr, len): frees old, stores ptr -> [0x40067cf8],
               len -> [0x40067cfc]      (globals: g_ext_all_in_one_sig / _sz)
```
* **No crypto in the handler.** The blob is merely *stored*. It is not compared to
  anything, not RSA-verified here.
* Consumers: `fcn.4000fc24` (device-info builder, see §3) requires `sz != 0`
  (error print `0x400451fd` = "get devinfo failed, g_ext_all_in_one_sig_sz = 0")
  and logs cert-version bytes `[ptr+0x93b]` ("atf cert1 version %d") and
  `[ptr+0xece]` ("atf cert2 version %d").
* Interpretation (medium confidence, inference): the blob is the AllInOne-DA
  signature trailer/cert container that DA_BR's stripped DA2 lacks; the actual
  "external sig vfy ok/fail" checks (`fcn` cluster 0x40036398–0x40037134, strings
  `get_ext_sig_from_allinone_ext_sig`, `[%s] external sig vfy ok/fail(0x%x)`,
  `sig types are different in rom(0x%x) and ram(0x%x)`) belong to the *image*
  signature machinery. **The writer scan (§4) proves none of these ever touch
  `g_oplus_auth_status`** — so SET-ALLINONE-SIGNATURE alone grants nothing.
* Its only auth-relevant role: it is a **prerequisite** — without a nonzero
  `g_ext_all_in_one_sig_sz`, GET-DEV-FW-INFO cannot build the device-info context,
  and without the context SET-FLASH-POLICY cannot verify anything.
* **Host-controlled content**: the stored blob is arbitrary host data; its SHA-256
  is fed into the signed message (§3).

## 2. SET-FLASH-POLICY chain and the crypto (proven)

```
CMD:SECURITY-SET-FLASH-POLICY 0x40006ddc
  parse XML, node "SEC-POLICY" (0x40042f28) -> 0x4002ae8c (unescape -> buf, len)
  if ret >= 0: cust_security_verify_sec_policy(buf, len)   [ALWAYS called — no
               conditional skip, no unsigned fallback; checked full disasm]
      0x40007abc: malloc 0x200000, zero-fill tail, copy buf/len
                  -> oplus_security_verify_sec_policy(copy, len, 0x400529e0)
                  !=0 -> -1
  if verify ret < 0: print 0x40042f33 "Server is not authenticated. Locked."
  if ret == 0: **re-run registrar 0x40001a6c** -> re-registers the command table
               according to the (now 1/2) g_oplus_auth_status  <- table upgrade
```

### 2.1 The verifier 0x400103dc

* `memcpy(0x40067cce, policy+0x700, 5)` — 5 "tail flag" bytes (see §2.3).
* `fcn.40039538(0x400529e0, 0x100)`: copies the **static 256-byte blob at
  0x400529e0** into global `0x4007a1c` and byte-reverses it (big↔little-endian
  conversion for the bignum layer). Only caller of 0x40039538 is this site —
  the key is always the static blob, never host data.
* Two verification passes of `0x40039598(ctx=0x4006a088, 0xd0, policy_buf, 0x100, mode=2)`:
  1. pass 1: `ctx[8] = 0x59 'Y'` → success ⇒ **status = 1** ("Ok in oplus")
  2. pass 2 (only if pass 1 failed): `ctx[8] = 0x4e 'N'` → success ⇒ **status = 2**
     ("Ok after sale"); both fail ⇒ **status = 3**, ret `0xE0000002`.

### 2.2 The signature primitive (all proven from disassembly)

`fcn.40039598`:
* `0x4003a2d4(ctx, 0xd0, hash[32])` — SHA-256 over the 0xd0-byte device-info
  context (hash engine init `0x4003a334`, update `0x4003a3a4`).
* signature = **first 0x100 bytes of the policy blob**; `sig_len != 0x100` ⇒
  error `0xC002000E+8` — no zero-length fallback.
* `0x4003c8c8` (thunk → `0x4003a76c`): public-key op over the 256-byte signature
  with modulus = `0x4007a1c` (the static blob). Exponent: at `0x40040244`
  `movw r1,#1 ; movt r1,#1` ⇒ **e = 0x10001 = 65537**, imported into the bignum
  layer (`0x4004086c`) as exponent. (A second, independent Montgomery RSA with
  the same 15-square+1-multiply structure exists at `0x4003c8d0` for the generic
  image-sig path — same e.)
* `0x4003c7d0` — PKCS#1 v1.5 block check of the recovered 256-byte block:
  * `block[0]==0x00 && block[1]==0x01`
  * bytes 2..: each must be `0xFF` **or `0x00`** (slightly weaker than RFC 8017
    which requires all-0xFF) until the terminator
  * first `0x00` must be at offset **0xCC**
  * `memcmp(DigestInfo, block+0xCD, 0x13)==0` where DigestInfo = the 19-byte
    SHA-256 DER prefix stored at **0x40053C10**:
    `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`
    (unique occurrence in the file)
  * `memcmp(hash, block+0xE0, 0x20)==0` — **full 32-byte SHA-256 compare**, not
    truncated.

### 2.3 The hardcoded RSA modulus (proven location; role inferred)

256 bytes at **0x400529e0** (file offset 0x529e0), byte-reversed into 0x4007a1c
before use (so big-endian modulus = reverse of this dump):

```
e8 fa 24 c7 51 ab 52 71 ed 90 0e ee d9 d5 8b 8d e4 4a e8 37 65 ab 5d 88
c9 ba 12 d9 39 fe 6c 1e 7d 67 13 a1 19 8f db 9b f7 59 f6 c3 24 95 80 3d
08 45 84 8b 10 e6 2f bb 02 d5 f3 56 10 e5 01 96 c4 41 49 a3 24 95 aa b7
63 8a 54 bb 8b 2d 87 18 0b bd 1f c5 55 c1 5f 63 3f 42 20 db 6b 6f 38 99
21 6d 9f 9f 5d 4b 3f 33 1a 97 52 55 78 5a ba 40 82 d3 63 7f ed 38 93 8a
21 fe 8c 62 04 20 64 40 7b 9b ae aa 93 0c 5c f4 5a 5c 7b cc 2a 31 64 3e
9e 7b 7e 6e f0 0c 2e 39 7b 8b 01 49 65 b0 4c 9a 29 6f fe 82 c5 4d 71 af
06 82 ae 09 fc 8b cc 28 11 6e 88 b5 4d cf 04 ed 37 fa f5 b6 f1 3c f8 0e
dc 34 71 7d 65 52 5e 23 34 f2 86 7e 15 9f 2d 89 09 e0 7f 4c 90 c9 5b 94
6d 85 20 d8 81 15 04 10 a3 58 58 93 55 e1 34 b9 e3 62 0d 58 a1 c7 5e ed
92 ce c0 0b 23 0d ba cd 34 3a a8 34 17 55 0a 85
```
No ASN.1/DER key structure nearby (raw modulus), e hardcoded. Private key is not
in the binary. ⇒ **forging a policy signature requires the OPLUS server key.**

### 2.4 Policy tail flags (policy+0x700..0x704, copied to 0x40067cce)

* `[+0] == 0x19` && status==1 ⇒ **status = 5** ("oplus_single_mode"; note 5 still
  passes the registrar gate, since the gate only special-cases 3 and 4).
* `[+1] == 0x1c` ⇒ **status = 4** (expired/read-only) — overrides the stored 1/2.
* `[+2]/[+3]/[+4]`: read by `fcn.400108c4` (`[OPLUS] %s, factory = %d`) in the
  OPLUS-WRITE-HASH256-ID machinery — gates seccfg/oplusreserve2/"param" hash-id
  write protection, **not** the flash-command table.
* Practical note: the XML node buffer is ≤ 0x200 bytes (per prior session notes)
  and the verifier rejects len > 0x400 (`cmp r8,#0x400; bhi err`), so a payload
  can never legitimately reach +0x700 in-RAM — the wrapper's 2 MB malloc is
  zero-filled, so the tail flags read as 0 (status 4/5 unreachable via the
  normal XML path; flags only matter for other blob formats). Inference, medium
  confidence.

## 3. What is actually signed: the device-info context (proven)

`oplus_security_verify_sec_policy` hashes **only** the 0xd0-byte context at
`0x4006a088` — **the policy body is NOT covered by the signature.** The context is
built by `fcn.4000fc24` (called via `cust_security_get_dev_fw_info` 0x40007a24 ←
CMD:SECURITY-GET-DEV-FW-INFO 0x40006cf4). Layout:

| off | content | source |
|---|---|---|
| +0x00 | `"OSIG"` (dword 0x4749534F) | constant |
| +0x04 | 0x30 ('0') | constant |
| +0x08 | 0x59 'Y' / 0x4e 'N' | verifier (in-oplus vs after-sale selector) |
| +0x0C | 0x57 ('W') | constant |
| +0x10 | `"MTK"` (3 bytes from 0x40044f9c) | constant |
| +0x18 | strlen(arg3) bytes — arg3 = 0x4005328e whose first byte is 0x00 ⇒ **empty** | static |
| +0x20 | 16 bytes serial | efuse @ **0x11C10140** (4 dwords, `fcn.4003a044`); if all-zero ⇒ hardcoded default **"0123456789ABCDEF"** @0x400533c0 |
| +0x30 | 8 hex chars of a 4-byte value (`get random_num: %d` family) | device-derived |
| +0x40 | 64 hex chars = hex(SHA-256(**uploaded AllInOne blob**)) — computed by `0x4002d3d4` → `0x4003a2d4(0x40067cf8, 0x40067cfc, out)` | **host-controlled** |
| +0x80 | first 0x40 bytes of partition **"oplus_custom"**; if read fails **or the 0x40 bytes sum to 0 (erased)** ⇒ hardcoded default string substituted | flash / hardcoded |
| +0xC0 | hex of a value derived from partition **"ocdt"** (0xC0 bytes; nonzero content gets XOR-scrambled by `0x4000fb9c` first) | flash |

**Hardcoded default for erased oplus_custom (0x40053348, 60 hex chars):**
```
efa7fb062ebcdd06c56adc949bce9402012fad08a768308c93520fb7f307
```
(Substituted via `ldm/stm` at 0x40010018–0x40010034 when the 64-byte sum of the
partition head is 0x0000 after masking 0xFFFF.)

The device-info function sets `g_oplus_auth_status = 1` **temporarily** at entry
(0x4000fc50, presumably so partition reads inside are permitted) and restores the
saved value on **every** exit (error path 0x4000febc, normal exit 0x400103cc) —
both restore sites verified; **no leak path**.

## 4. Complete writer list of g_oplus_auth_status (proven by movw/movt scan)

Exhaustive scan for `movw rX,#0x455c` + `movt rX,#0x4005` pairs → 10 sites, all
accounted for:

| VA | effect |
|---|---|
| 0x40001adc | **read** (registrar gate) |
| 0x4000fc50 | **write 1** (temporary, devinfo builder; always restored) |
| 0x4000feac | **write saved value** (restore, error path) |
| 0x4000ff74 / 0x40010038 / 0x40010194 | address re-materializations inside fcn.4000fc24 (restore at 0x400103cc) |
| 0x40010400 | **read** (log print) |
| 0x40010568 | **write 3** (verify failure) |
| 0x400105b8 | **write 1/2** (verify success — the ONLY grant) |
| 0x400105c8→0x400105ec | **write 4** (policy tail +1 == 0x1c) |
| 0x40010664 | **write 5** (policy tail +0 == 0x19 && status==1) |
| 0x4002cbbc | **read** (policy lookup: ==5 ⇒ "oplus_single_mode" name match) |

**No timer, no debug command, no efuse-driven, no fallback writer.** The literal
0x4005455c never appears in a literal pool (pure movw/movt immediates), so the
scan is exhaustive.

## 5. Efuse angle (question 6) — verdict: dead

* The "[OPLUS] Download authorization Ok after sale" state (2) is **not efuse
  driven** — it is chosen by *which context variant the server signed* (ctx[8]='Y'
  vs 'N'). Same for the error string — it is simply the both-passes-failed print.
* Efuse participates only as the **serial-number source** (0x11C10140, 16 B) in
  the signed context. A wrong/absent serial makes the context *mismatch the
  signature* — it never grants anything.
* READ-EFUSE handler (0x40005a80) is a generic executor pass-through
  (buffer → 0x4002b330); the efuse whitelist ids 0xC–0xF (via 0x40039ca0 /
  GET-HW-INFO 0x4002ba0c→0x40039e74) are read-only device info.
* sboot/SBC (0x40033b08 → get_hw_sbc 0x40039d00) feeds the per-partition flag
  diagnostics, not the auth status.

## 6. Weak-crypto audit (question 5) — summary

| check | result |
|---|---|
| signature length | fixed 0x100 enforced twice; len 0 ⇒ error, no fallback |
| hash | SHA-256, full 32-byte compare, DigestInfo prefix verified exactly |
| padding | PKCS#1 v1.5 type-01, terminator position enforced (0xCC); **deviation: filler bytes may be 0x00 as well as 0xFF** |
| exponent | 65537 (hardcoded) — no e=3 small-exponent attack; Bleichenbacher-style middle-garbage forgery blocked because **all** filler bytes are range-checked |
| unsigned-policy path | none: verify call is unconditional in 0x40006ddc (full disasm checked); "SEC-POLICY" node missing ⇒ error before verify |
| SMT/factory bypass | none in the auth path; "factory"/"smt" strings belong to hash256-ID/format logic |
| status tampering | status is checked only at registrar time + policy lookup; no re-read after timer |

## 7. Findings that DO matter (the two real leads)

1. **Policy body is unsigned (proven).** The RSA signature covers only the 0xd0-byte
   device-info context. Everything after policy[0:0x100] (partition permissions,
   tail flags) is plaintext. Therefore: **one single legitimately captured signed
   blob for this device is replayable with an arbitrary, attacker-crafted policy
   body** — e.g. permissions for all partitions, or tail flags 0x19/0x1c for
   single-mode/expired variants — as long as the device ctx (serial, oplus_custom,
   ocdt, AllInOne-blob hash) still matches the signed one at verify time. This
   lowers the value of a captured blob from "one policy" to "master authorization
   for the device".
2. **ctx+0x40 = SHA-256 of the host-uploaded AllInOne blob (proven).** The DA never
   verifies that blob in the devinfo path. So the signed message contains a value
   fully chosen by the host. This is consistent with the intended flow (the host
   relays dev_info, including this hash, to the OPLUS server which signs it) — it
   does **not** by itself enable forgery (SHA-256 preimage/collision not feasible),
   but it means a hypothetical signature oracle needs no fixed blob: the server
   signs whatever ctx the host reports. No offline shortcut found.

## 8. Ranked list: legitimate-auth options vs runtime patching

| rank | option | verdict |
|---|---|---|
| 1 | **Genuine OPLUS-server-signed SEC-POLICY for this device** (commercial remote auth; the intended flow: SET-ALLINONE-SIGNATURE → SECURITY-GET-DEV-FW-INFO → relay dev_info to server → SECURITY-SET-FLASH-POLICY) | **works, needs server/key** — the only clean path; per §7.1 one captured blob is replayable with arbitrary policy body |
| 2 | Replay of a signed blob captured from *another* device/unit | **dead** unless the device ctx can be steered to match the foreign signed ctx (serial from efuse cannot be changed from the DA; only oplus_custom→default and the AllInOne-blob hash are steerable). Improbable; the steerable-ctx angle is the only non-key avenue left and depends on unknown ctx fields (+0x30/+0x40 source chain) — flagged, not proven either way |
| 3 | Unsigned/dev-mode policy, empty-signature default, SMT/factory mode, loglevel magic | **dead** (§6) |
| 4 | Efuse-state authorization (bits making the DA permanently authorize) | **dead** (§5) — no efuse-driven status writer exists |
| 5 | Timer/expiry path that re-grants | **dead** — status 4 (expired) only *downgrades* 1/2 when policy tail byte == 0x1c |
| 6 | **Runtime patching via heapbait** (current approach: RET0 on 0x400103dc + direct write of 1 to 0x4005455c via patch_mem) | **works, proven on device** — remains the recommended route |

Uncertainty notes: (a) exact role of the 0x400529e0 blob as modulus vs key-blob —
high confidence it is the RSA modulus (256 B, consumed as bignum modulus together
with hardcoded e=0x10001, output PKCS#1-checked); (b) whether the public-key op is
software Montgomery or HW-engine assisted (calls into 0x10210000-region code) —
does not change feasibility; (c) the odd conditional at 0x40010610
(`moveq r6,0xE0000009; cmpeq r0,#0x1a`) decodes oddly in r2 and looks like
dead/debug code — it does not affect the final success value (r6 reset to 0 at
0x4001066c on all fall-through paths).
