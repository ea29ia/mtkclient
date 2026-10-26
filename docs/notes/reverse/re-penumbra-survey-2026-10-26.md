# RE: Penumbra (shomykohai) — docs/code survey vs our RMX3630 notes

Date: 2026-10-26. Sources: README + `docs/content/Mediatek/**` (Download Agent,
DA Extensions, XFlash/XML DA Protocol, Seccfg, Carbonara/Heapbait/Kamakiri) at
`main`, plus the local source copies in `/tmp/opencode/pen/`
(`core_src_exploit_heapbait.rs`, `core_src_exploit_carbonara.rs` and others).
Everything below was byte-checked against our corpus before writing; nothing is
taken from their prose on trust.

Companions: `re-heapbait-vuln.md`, `re-heapbait-stabilize.md`,
`re-da1-2710-daswap-2026-10-25.md`, `re-sec-dispatch.md`, `re-da2-readregister.md`,
`re-preloader-daa-lk.md`, `re-tee-efuse.md`.

## 1. What they document that we did not (gap list, now partially imported)

* **Kamakiri anatomy** (their Kamakiri.md): stale-byte retention in
  `usbacm_tx_buf` (cursor reset on flush, bytes stay), unbounded
  `wIndex` → `if_info[wIndex].if_class_specific_hdlr` dispatch,
  `BromCmd_SendCert` (cmd `0xE0`) staging the blob in RAM *before* the failing
  cert verify and never cleaning it, the read32/write32 spray recipe against a
  scratch address in the watchdog register range (15 iterations, −4/iteration),
  and the trigger `ctrl_transfer(0xA1,0,0,wIndex,0)`. We never had this as a
  reference; not applicable to RMX3630 (BROM closed, DAA/SLA live) but worth
  keeping for other MT6789 targets.
* **V6/XML protocol reference** (their XML DA Protocol.md): CMD:START/END
  framing, `OK@0x<hex>\0` handshake, `OK!PROGRESS@<pct>` / `OK!EOT`,
  DOWNLOAD-FILE/UPLOAD-FILE flows (incl. the device-sent `OK@0x0` before host
  data). Our equivalent knowledge lived in code+logs only (cf. #409 analysis);
  it is now a proper reference point.
* **Generic DA container layout** (their Download Agent.md): entry size
  `0xD8` (Legacy) / `0xDC` (XFlash+XML), region record `0x20`
  {offset, len, addr, region_len, sig_len}, `DADA` magic. We only had this per
  build (`verify/harvest.md`); their table is the generic form.
* **Tool landscape** from their Learning Resources we had not studied:
  `hacc` (their DA parser), `da-boot` (mt6572-mainline), `kaeru` /
  `moto-experiments` (R0rt1z2), `mtk-payloads` (shellcode repo — hakujoudai
  lives there). All to-study; no immediate RMX3630 bearing.
* **ARM32 heapbait specifics in code**: chunk header
  `magic|ptr|size` with magic ignored by `free()`; penumbra fills it with
  `0x54494142` ("BAIT") in code, `0xDEADBEEF` in the doc. Their doc's ARM64
  dictionary is the mirror gap of ours (we have ARM32; they documented both).
* **DA Extensions slot `0x68000000`**: their DA Extensions.md states the
  standard extension load address is `0x68000000` (DA2 far-heap), which
  independently corroborates our `re-da2-bootmode-reboot.md` / `da2_6789_op`
  reading that the leaked `DA2_6789_op.bin` native `CMD:CUSTOM` handler
  (`blx 0x68000000`) is an ext-loader slot, not a vendor backdoor.

## 2. What we have that they do not

* **Fix timeline, dated.** Their Carbonara doc: "Devices released during or
  after 2024 aren't guaranteed"; their Heapbait doc: "patched … somewhere
  around November 2024 … exact date unknown". Ours: clamp window
  `(2024-09-29, 2025-01-03]`, gate window `(2024-03-07, 2024-09-02]`, command
  removal 2025-12-09 (2710EX01) — proven on the 11-build/19-blob corpus.
* **Behavioral 3-fact predicate** (command registered / tripwire absent / recv
  unclamped) vs their pattern-only `is_vulnerable`. See §3 for the measured
  consequence.
* **Latent detector bug, unpatched upstream** — see §3.
* **RMX3630/MT6789 ground truth**: 2710 preloader base `0x200F00`, gate force
  `0x40000000`, stored DA2 hash at file `0x692F4`, SET-FLASH-POLICY
  store-inventory + model-wide RSA modulus, cert-chain design fragility
  (host-supplied modulus slots), EFUSE audit (UNISOC controller
  `0x11C10000`, write side without whitelist), offline Unicorn pipeline
  (victim-identity lottery, scratch linkA retry, exit-condition trap,
  L≤0x3C desync window) with PASS on DA1 200EX01 + C.25.
* **Penumbra sled design is declaration-based**: code
  `HEAP_SIZE = 0x32000000`, `SLED_OFF = (HEAP_SIZE/10)*9/10`,
  `HEAP_SIZE/40` NOP repeats (~12.5 MB sled) — i.e. the sled address is derived
  from the *declared* heap size, not measured heap state. Our
  lottery/scratch-retry approach does not trust the declaration. Their ~80 MB
  figure in the doc does not match their own code constant (0x32000000/40
  repeats ≈ 12.5 MB of NOPs before the shellcode — likely the doc counts the
  full 0x32000000 allocation, the code comment history would tell).

## 3. Detector audit — their `is_vulnerable` run on our corpus

Their Carbonara detector = 4 byte/ASCII patterns taken from mtkclient's
`da_parser.py`; Heapbait detector = 3 patterns (1×ARM32, 2×ARM64). Run over
`/tmp/opencode/said/*.bin` + 2710/200 DA_BR DA1 regions:

* On 2710 DA1 (`issue409/x/DA1_extracted.bin`) and on `doogee.bin` (2025-06
  build), the **only** matching Carbonara pattern is the ASCII string
  `"2nd DA address is invalid."` (`0x54C43` / `0x4E34C`). The r4 clamp form
  `\x01\x01\x54\xE3…` is absent — the 2710/doogee clamp is the r6 form
  `\x01\x01\x56\xE3` (`e3560101`), which **no** pattern covers. Both
  penumbra and mtkclient therefore detect "patched" on these builds only
  through the string; a string rename flips their verdict to "vulnerable".
  This is the same latent bug we documented in `verify/gate.md` — still
  unfixed upstream.
* Heapbait detector: `doogee.bin` carries the ARM32 pattern at `0x4BB7C`
  (clamped → correctly "not vulnerable"); all pre-clamp blobs report "vuln?"
  consistent with our 3-fact predicate's 13/19 exploitable set.
* Their carbonara.rs comment "patterns were taken from mtkclient" confirms the
  inheritance; mtkclient carries the same r6 blind spot (documented in
  #409/PR already).

## 4. Measured contradiction inside penumbra: heapbait `packet_size`

* Their **doc** (Heapbait.md) and the r0rt1z2 blog say the read loop uses
  `packet_size = 0x20000` per chunk.
* Their **code** (`core_src_exploit_heapbait.rs`, stage-3 comment) says
  `packet_length (0x2000)` — matching our 200EX01 resolver
  (`[0x40067A08+0x14] = 0x2000`, `re-heapbait-vuln.md` line ~72).
* Verdict for 200EX01: **our 0x2000 is right; their code agrees; their doc
  copied the blog.** Remaining open: confirm the 2710 DA2 value of
  `[0x40067A08+0x14]` (one disasm pass) before quoting any of this in #409.

## 5. Corrections imported into our notes (errata pointers)

* `re-sec-dispatch.md`, `re-da2-readregister.md`, `re-da_br-readregister.md`:
  200EX01 handler table stays valid **for that build**; 2710 registrar instead
  uses string-named registration (`bl 0x400083DC` @`0x40001A9C`/`0x40001AB4`),
  real handlers WRITE-EFUSE `0x40005C20` / READ-EFUSE `0x40005D04`, and the
  READ/WRITE-REGISTER commands are **absent** on 2710 entirely.
* `re-preloader-daa-lk.md`: base `0x200F10` is 200EX01-only; 2710 is
  `0x200F00` (every `0x25xxxx` VA rescales by −0x10).
* `re-heapbait-vuln.md`: packet_len 0x2000 corroborated; XML-escape overflow
  (`mxml_escape`, fixed `malloc(0x200)`, +172 B) recognized as an independent
  vector, not a footnote.
* `re-tee-efuse.md`: 200EX01 whitelist map unchanged; 2710 adds the UNISOC
  controller facts (`0x11C10000`, BPKEY `0x6B32970A`, no write whitelist,
  guard `0x40032DC4`).
* `re-da1-2710-daswap-2026-10-25.md`: trailer cross byte is `0x3C`
  (200 trailer × 2710 K27), not the `0x7C` quoted in our #409 comment
  `6410927123` (correction posted as comment `6411816675`).

## 6. Not imported (and why)

* Their `linecode`/Kamakiri2 (WinUSB/Zadig prerequisite) — VCOM-level BROM
  work, blocked for us by DAA/SLA on this unit.
* amonet (their roadmap, not implemented) — n/a.
* Seccfg V4 doc — we already have the equivalent plus the digest-equivalence
  proof (`re-seccfg-digest-equiv.md`).
