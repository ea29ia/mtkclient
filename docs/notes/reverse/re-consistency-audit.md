# Consistency audit — RMX3630/MT6789 RE reports vs mtkclient implementation

> **HISTORICAL (audit #1).** Superseded in parts by `re-consistency-audit-2.md`:
> the 0x4002AAC0 "program dispatcher" model (dead code; slot +8), the
> "0x4002f804 hash-list check" label, the "state-writer patches must be removed"
> (now default-off), the "missing patches" list (all implemented, default-off),
> the heapbait bug list (fixed), and `v6.seccfg()` padding (padding lives in the
> caller; `seccfg_write_partition` sends `len(writedata)` verbatim).

Date: 2026-10-24. Scope: all `docs/notes/re-*.md`, campaign docs (`rmx3630-da2/README.md`,
`rmx3630_session_2026-10-23.md`, `oplus_mt6789_rmx3630.md`), and
`heapbait.py`, `xml_lib.py` (apply_oplus_runtime_patches), `seccfg.py`, `v6.py seccfg()`.
Read-only audit; no repo code was modified.

Legend: **[COLLISION]** = two reports disagree; **[STALE]** = one report superseded by a
newer one; **[CODE-BUG]** / **[CODE-STALE]** = implementation vs reports.

---

# TASK 1 — Cross-report collision scan

## 1.a HeapBait: vuln report vs stabilize report

Confirmed: `re-heapbait-stabilize.md` §1 proves the allocator is **address-ascending
first-fit from the lowest free node** (insert walks the +4 link, `bhi` at 0x40008fc0,
carve is low-end). This supersedes the direction guess in `re-heapbait-vuln.md` §6
("LIFO/highest-first" wording) — the vuln report does not label it a guess loudly enough.

Other statements in `re-heapbait-vuln.md` corrected by the stabilize report:

| Vuln report says | Stabilize report proves | Status |
|---|---|---|
| §6 "victim = stage-2 mxml filename buffer", identity follows heapbait.py design comments | §2.1: the filename chunk (F1/F2) is allocated **before** the download buffer D and freed **after** it in the same invocation — it can never be the chunk above D. Victim is a lottery; the natural deterministic victim is the **cached-previous download buffer S1**, freed at 0x4002d44c (0x4002d428 = cache setter + free-previous, not "process body") | **[STALE]** |
| §5 "USB framing/READY desync … external known factor" (partial) | §2.3: the ~50 % rate is the **victim-identity lottery** (X = allocated-later / remainder-node / virgin), with proof that X=R leads to a Data Abort at [0xDEADBEEF+4] | **[STALE]** (vuln's framing incomplete) |
| §2b "recv loop … bne loop" (loop shape) | §2.4: the loop exits **only on exact r7==sb**; with the overflow delivered the exit is unreachable → always terminates via recv error/timeout, and the poisoned free still fires on the error epilogue | **[STALE]** (refines failure model) |
| §2b "malloc(sb+4) ⇒ 0x1400-byte chunk" | §1: malloc(n) needed = align4(n+0xC); malloc(0x13FC+4) ⇒ chunk 0x140C, user capacity 0x1400, next node starts exactly at user+0x1400 | consistent (wording refined) |
| §5 "DPC idle requirement" | unchanged | consistent |
| §0/§2 primitives table (reg_cmd 0x400086d4, cmd_loop 0x4000875c, free 0x4000a5f0, malloc 0x4000a59c, dpc 0x40069dec/de8, free-list head 0x40069e94) | §0 replays the same values via the host resolvers | consistent |

Note: `re-heapbait-vuln.md` §2c/§4 remain valid (vulnerable function 0x4002ae8c, unclamped
recv at 0x4002b1a0, trigger path 0x40006cdc → free → `str size,[node+8]` → dpc->cb).

## 1.b 0x4000392c attribution (WRITE-FLASH vs ERASE-FLASH)

- `rmx3630-da2/README.md` table: "0x4000392c WRITE-FLASH policy deny byte-check (LDRB +3)" — **[STALE]**.
- `rmx3630_session_2026-10-23.md` §23:1x: "site2 0x4000392c" listed as a WRITE-FLASH deny site — **[STALE]**.
- `re-writeflash-scrubber.md` §3 already contains the correction ("Attribution correction:
  0x4000392c … is actually inside ERASE-FLASH fcn.400039c0; WRITE-FLASH's own deny checks
  are the 0x40003194–0x400031b0 pair") — so the scrubber report is internally consistent
  (its TL;DR and §1 talk about WRITE-FLASH, its §3 corrects the old map).
- `re-erase-patch-audit.md` is consistent (does not re-discuss 0x4000392c; §7 lists
  ERASE-FLASH sites 0x40003dac/0x40003e58 as separate).
- **`xml_lib.py` L951–954 still labels 0x4000392c "WRITE-FLASH deny-check"** — stale label
  in code (see Task 2).

Current truth: 0x4000392c = ERASE-FLASH deny byte-check; WRITE-FLASH deny = 0x40003194/
0x400031a4/0x400031a8/0x400031b0/0x400031d4.

## 1.c Write-engine attribution: 0x4000c348/fcn.4000bb14 vs 0x400306ac

- `re-postwrite-hang.md` analyzes 0x4000c348→fcn.4000bb14 as "the WRITE-PARTITION
  (8 MB chunk loop) engine" and places the HACC hang at 0x4000c1e8–0x4000c244 inside
  fcn.4000bb14, saying seccfg writes "take the HACC branch".
- `re-write-chain.md` §1 proves the branch polarity in 0x4002ad04: **name == "PRELOADER" →
  engine 1 (0x4000c348→fcn.4000bb14); every non-PRELOADER name (incl. seccfg) → engine 2
  (0x400306ac)**. Engine 2's shown disassembly (0x4003010c loop) contains no HACC/ACC pass.
- `re-write-chain.md` TL;DR itself says the ACC branch is "the same branch documented in
  re-postwrite-hang.md" while §2 documents it only in engine 1 — internally untidy.

**Current best-supported model** (per write-chain, the later/more complete analysis):
`WRITE-PARTITION 0x40002034 → 0x4002ad04 → (non-PRELOADER) 0x400306ac → 0x4003010c →
program via 0x4002aac0 [lit 0x40054328]`; engine 1 (0x4000c348/fcn.4000bb14, with the
0x4000c210 ACC/HACC gate and the digest chain 0x4003a2d4/0x40037f70) is the **PRELOADER
path only**. Consequence: **[COLLISION]** — the postwrite-hang hang-site attribution
(HACC busy-wait inside fcn.4000bb14 during seccfg writes) is not established for the
seccfg path; either engine 2 has an untraced equivalent HACC pass, or the observed
post-upload hang has a different site. The three HACC poll loops themselves
(0x400397d8/0x40039840/0x40034b10) are proven in both reports and remain valid hang
candidates; only the *call path for seccfg* is in dispute.

## 1.d Consolidated address table + stale entries

Full table (VA → attribution → source reports → status). Conflicts marked.

### DA2 code (base 0x40000000)

| VA | Attribution | Sources | Status |
|---|---|---|---|
| 0x40001508 | checksum/progress echo reporter (read-only) | write-chain | ok |
| 0x400018a4 | storage init (registers UFS RPMB device) | da2-rpmb-key | ok |
| 0x40001a6c | command registrar (XML cmd table) | session, sec-dispatch, auth-paths, vuln | ok |
| 0x40001adc | registrar gate: read g_oplus_auth_status | auth-paths | ok |
| 0x40001db8 | special registration (DA.SLA ENABLED area) | sec-dispatch | ok |
| 0x40001e10/0x40001e28 | OPLUS-* command registrations | sec-dispatch | ok |
| 0x40001e48 | get_node (mxml node lookup) | vuln, scrubber | ok |
| 0x40001f08 / 0x40001f14 | DPC struct getter / zeroing | vuln, stabilize | ok |
| 0x40001f30 / 0x40001f84 | NOTIFY-INIT-HW / SET-HOST-INFO handlers | sec-dispatch | ok |
| 0x40002034 | CMD:WRITE-PARTITION handler | sec-dispatch, scrubber, write-chain, session | ok |
| 0x4000217c | WRITE-PARTITION policy-query call site | postwrite-hang, sec-dispatch | ok |
| 0x400021a0 | WRITE-PARTITION deny byte-check (LDRB +3) | README, session, xml_lib | ok |
| 0x400021d8–0x40002308 | pre_erase/PRELOADER erase gate; erase call 0x40002308 | scrubber, write-chain | ok |
| 0x4000231c (movw) | "Erase [%s] Failed." ref, WRITE-PARTITION erase-fail branch | erase-audit | ok |
| 0x400024f0/0x40002504/0x40002514/0x40002528 | epilogue: 0x4002ad04 call, PGPT/SGPT/PMT check, GPT repair, response | postwrite-hang | ok |
| 0x40002598 | CMD:WRITE-PARTITIONS handler (deny keyed on global 0x40054314) | README, session, sec-dispatch | ok |
| 0x400026b8 / 0x4000411c / 0x40005010 | callers of GPT/PMT compare fcn.4002c6f0 | sec-dispatch | ok |
| 0x40002ad04 | post-parse write driver (both engines); builds CMD:DOWNLOAD-FILE | write-chain | ok |
| 0x40002ae60–0x40002ae7c | name gate in 0x4002ad04 (PRELOADER vs other) — note: **inside 0x4002ad04, addresses 0x4002ae60–0x4002ae7c** | write-chain | ok |
| 0x40002c3c | FLASH-ALL-family erase-fail string ref | erase-audit | ok |
| 0x40002e60 | CMD:WRITE-FLASH handler | all | ok |
| 0x400030f0 / 0x40003138 / 0x40003188 | WRITE-FLASH policy-enable / enum-regions / deny loop | scrubber | ok |
| 0x40003194 / 0x400031a4 / 0x400031a8 / 0x400031b0 / 0x400031d4 | WRITE-FLASH two-flag deny block + deny print | scrubber, session, xml_lib | ok |
| 0x40003200–0x40003228 | erase-log block (loglevel gate, "Erase [%s] At…") | scrubber, erase-audit | ok |
| 0x4000322c | `movw r0,0xb6a0` (progress text) — scrubber mis-called it "flash/storage lock" setup | scrubber vs erase-audit | **[STALE]** (erase-audit §6 corrects: 0x4002b5b4/0x4002b790 = progress-report senders, NOT lock/unlock) |
| 0x40003244 / 0x4000325c / 0x40003268 / 0x4000326c–70 / 0x4000328c / 0x400032b0 / 0x400032c4 | progress-start / **ERASE blx (patch site)** / progress-EOT / sole erase-result check / data receive+program / post-write pass / error path | scrubber, erase-audit, write-chain | ok |
| 0x4000362c | CMD:READ-PARTITION-TABLE (reads 0x40054314) | sec-dispatch, session | ok (but see 0x40054314 conflict below) |
| 0x400037ec / 0x400039c0 | CMD:ERASE-PARTITION / CMD:ERASE-FLASH handlers | sec-dispatch, scrubber | ok |
| 0x4000392c | **ERASE-FLASH** deny byte-check | scrubber §3, erase-audit | **[COLLISION]** README + session + xml_lib say WRITE-FLASH |
| 0x40003dac / 0x40003e58 | ERASE-FLASH erase dispatch sites | scrubber, erase-audit | ok |
| 0x40003cc8 / 0x40004530 | erase-region policy call / "Erase [%s] is not allowed." | sec-dispatch | ok |
| 0x40003edc / 0x40004874 | FLASH-ALL / FLASH-UPDATE handlers | session | ok |
| 0x400032d0 / 0x400033f0 | READ-PARTITION / READ-FLASH | sec-dispatch, session | ok |
| 0x400041b8 / 0x40004d78 / 0x40005578 | FU flash_list helpers | sec-dispatch | ok |
| 0x40005400 / 0x400055a8 / 0x400055c4 / 0x400055d8 | oplus-aware erase dispatcher + keep-check call + "[oplus]keep" print + PRELOADER skip | scrubber | ok |
| 0x4000597c | generic-erase-region erase-fail string ref | erase-audit | ok |
| 0x4000599c / 0x40005a80 / 0x400064bc / 0x40006eec / 0x4000700c | WRITE-EFUSE / READ-EFUSE / GET-HW-INFO / READ-REGISTER / WRITE-REGISTER | session, sec-dispatch | ok (200EX01 only; 2710 differs — see sec-dispatch errata) |
| 0x400069f4 | CMD:EMMC-CONTROL (GET-RPMB-KEY-STATUS / LIFE-CYCLE-STATUS) | da2-rpmb-key, sec-dispatch | ok |
| 0x40005ba8 / 0x40005d84 / 0x40005f64 / 0x40006394 / 0x400068d0 / 0x400077c4 | REBOOT / SET-BOOT-MODE / SET-RSC / WRITE-PRIVATE-CERT / GET-DA-INFO / GET-SYS-PROPERTY | sec-dispatch | ok |
| 0x40006c1c / 0x40006cf4 / 0x40006ddc | SECURITY-SET-ALLINONE-SIGNATURE / GET-DEV-FW-INFO / SET-FLASH-POLICY | sec-dispatch, auth-paths, vuln | ok |
| 0x40010a0c / 0x40010a9c | OPLUS-WRITE-HASH256-ID / OPLUS-GET-CPUID | sec-dispatch | ok |
| 0x40007abc | cust_security_verify_sec_policy (RET0 target) | README, auth-paths, sec-dispatch | ok |
| 0x400103dc | oplus_security_verify_sec_policy | README, auth-paths | ok |
| 0x40010438 / 0x400105e8 / 0x40010630 | memcpy(0x40067cce ← policy+0x700,5) / read-back mode / dev-mode writers | scrubber, auth-paths | ok |
| 0x40010568 / 0x400105b8 / 0x400105c8→0x400105ec / 0x40010664 | status writers 3 / 1-or-2 / 4 / 5 | auth-paths | ok |
| 0x4000fc24 / 0x4000fc50 / 0x4000feac / 0x400103cc | devinfo builder + temporary status=1 write/restore | auth-paths | ok |
| 0x40010728 / 0x40010750 | sec_write_wrapper write-by-name("oplus_custom") calls | write-chain, reserve2 | ok |
| 0x400108c4 / 0x40010908–0x400109b4 / 0x40010924 | format-decision fn (seccfg/oplusreserve2/userdata/metadata flags) | scrubber, reserve2 | ok |
| 0x4000c348 / 0x4000bb14 | **PRELOADER-only** write engine + chunk loop | write-chain §1–2 | **[COLLISION]** postwrite-hang treats it as the seccfg/WRITE-PARTITION engine |
| 0x4000bb44 / 0x4000bc30 / 0x4000bcd8 / 0x4000bd28 / 0x4000bda4 / 0x4000bdec / 0x4000be28 / 0x4000c1e8 / 0x4000c204–0x4000c244 | engine-1 internals: policy flag, USB ops, recv, digest (0x4003a2d4/0x40037f70), region lookup, ACC gate 0x4000c210, HACC key load/transform/wipe | write-chain, postwrite-hang | ok |
| 0x4000c3e4 / 0x4000c440 / 0x4000c4bc–0x4000c4f4 / 0x4000c534–0x4000c570 / 0x4000c6b8 | program step (= ops-table +4), region split, read-back verify | write-chain | ok |
| 0x400306ac / 0x4003010c / 0x4003053c / 0x40030398 / 0x40030418 / 0x40030610 / 0x4002f5f8 / 0x4002f7bc / 0x40008234 / 0x4003076c | **non-PRELOADER engine** (seccfg path): loop, USB XML exchange, recv, program slot, progress log, open/close/commit/setup | write-chain §3 | ok (HACC presence untraced — open) |
| 0x4002aac0 | program dispatcher (lit-pool ref 0x40054328) | write-chain | ok |
| 0x4002b044 / 0x4002b090 | recv error paths | stabilize | ok |
| 0x4002b190 | per-chunk "OK" sent BEFORE data recv | stabilize §2.4 | ok |
| 0x4002b1a0 / 0x4002b1b8 / 0x4002b1dc–0x4002b1e4 | unclamped recv request / recv / exact-match exit | vuln, stabilize | ok |
| 0x4002b0ac–0x4002b0dc | advertised-len parse + malloc(sb+4) | vuln | ok |
| 0x4002ae8c | fp_read_host_file **AND** secure-node XML executor (dual role, same function) | vuln, sec-dispatch, auth-paths | ok (dual role, consistent) |
| 0x4002aba8 | XML-unescape copy (F2 chunk source) | vuln (via stabilize §2.2), session | ok |
| 0x4002b5b4 / 0x4002b790 | **progress-report / progress-EOT senders** | erase-audit §6 | **[STALE]** scrubber §1/§5 calls them "flash lock/unlock pair" |
| 0x4002b874 | FILE-SIZE host op (r1=2) | scrubber, write-chain | ok |
| 0x4002c4a0 | post-write pass (feedback/verify) | scrubber | ok |
| 0x4002c6cc | PRELOADER name compare helper | scrubber, write-chain | ok |
| 0x4002c664 / 0x4002d2cc / 0x4002d970 | PGPT/SGPT/PMT name check / storage op / range-table fixup | postwrite-hang | ok |
| 0x4002d3d4 | SHA-256 of uploaded AllInOne blob (ctx+0x40) | auth-paths | ok |
| 0x4002d428 | **cache setter** (frees previous, stores ptr/len → 0x40067cf8/0x40067cfc) | stabilize §2.1, auth-paths | **[STALE]** vuln §2c calls it "process downloaded body" |
| 0x4002d44c | free-of-previous-cached-buffer (the guaranteed post-overflow free) | stabilize | ok |
| 0x4002d464 / 0x4002d4d8 | read-by-name init / read-by-name ("seccfg" user) | reserve2, sec-dispatch | ok |
| 0x4002d540 | write-by-name (only used for "oplus_custom") | write-chain, reserve2 | ok |
| 0x4002c6f0 | GPT/PMT partition-record compare helper (0x4002c800 is an interior BB) | sec-dispatch | **[COLLISION]** (see 0x4002c800) |
| 0x4002c800 | README: "SEC service function containing 'set lock state as LOCKED' print, table-dispatched" | README, session §23:5x, scrubber §2 | **[STALE/COLLISION]** sec-dispatch §1 proves: interior basic block of fcn.4002c6f0 (GPT/PMT compare, XOR of 64-bit offset fields), zero pointer references |
| 0x4002cbb4 | policy-table name lookup (0x4005628c) | README, sec-dispatch, auth-paths, heapbait comment | ok |
| 0x4002cbf0 / 0x4002cce0 | "oplus_single_mode" 18-B loop / 64-entry scan | sec-dispatch | ok |
| 0x4002cd30 / 0x4002cd44 / 0x4002cf48 / 0x4002cf58 | entry accessors (+0x1c ptr / +0x18 wide-digit / +0 word / setter) | sec-dispatch | ok |
| 0x4002cdf4 / 0x4002cf20 / 0x4002cf34 | flag-bit extractors (bit2 / bit1 / bit0) | sec-dispatch, postwrite-hang | ok |
| 0x4002ce08 | flag-byte getter `sec_policy_flag(idx)` — **contains** the "[SEC] set lock state as LOCKED" print | sec-dispatch, postwrite-hang | **[STALE]** README/session point at 0x4002c800 as "func start"; the real prologue is 0x4002ce08 |
| 0x4002ceac | print site "[SEC] set lock state as LOCKED" | sec-dispatch, postwrite-hang, session | ok |
| 0x4002cf68 | policy query builder (called from all WRITE/ERASE/RPT handlers) | sec-dispatch, postwrite-hang | ok |
| 0x40033b08 / 0x40033b64 / 0x40033bbc | sboot-state getter / ACC config lookup / gate site | sec-dispatch, postwrite-hang, write-chain | ok |
| 0x400334ac / 0x40034250 / 0x40035654 / 0x40035ce4 / 0x40037f70 | checksum helper / region lookup / per-chunk SEC hook / misc / secondary hash | write-chain | ok |
| 0x400347d8 / 0x40034810 / 0x40034840 / 0x4003482c / 0x400348bc / 0x40034948 | HACC key-copy check / key load / transform wrapper / key wipe / alt path | postwrite-hang, reserve2 | ok |
| 0x40034a78 / 0x40034b10–0x40034b18 | secondary HACC op + unbounded poll | postwrite-hang | ok |
| 0x4003975c / 0x400397d8–0x400397e0 / 0x40039800 / 0x40039840–0x40039848 / 0x40039880 / 0x400398b0 / 0x400398d4 | HACC init + init poll / transform + poll / reset / key copy / wipe | postwrite-hang, reserve2 | ok |
| 0x40039d00 | get_hw_sbc (bogus blx-thunk 0x40031504; returns 1 from garbage) | session, sec-dispatch, auth-paths, xml_lib | ok |
| 0x4003f37c | get_hw_sbc log wrapper | session | ok |
| 0x40034d6c | sec_get_seccfg (outer; calls 0x40034dfc **every invocation**) | all DA2 SEC reports | ok (postwrite-hang's "key correction" stands) |
| 0x40034dfc | seccfg loader/verifier (reads "seccfg" @0x40034e68/70, two 0x3C-byte "MMMM" slots) | reserve2, sec-dispatch, postwrite-hang | ok |
| 0x40034e18–0x40034f98 | loader internals (memset 0x4005cf00/0x3000, memcpy slots, magic/digest checks) | sec-dispatch, postwrite-hang, reserve2 | ok |
| 0x40034f94 / 0x40034fe8 | main-valid / backup-valid beq decisions | write-chain, reserve2 | ok |
| 0x40034ffc / **0x40035000** / 0x40035010 / 0x40035014 / 0x40035018 / 0x40035020 | state-writer block: movw @0x40034ffc, `MOV r1,#1` @0x40035000, `MOV r1,#2` @0x40035014, store @0x40035020 | sec-dispatch, reserve2 | **[COLLISION on MEANING]**: README + session + postwrite-hang label 1="LOCKED", 2="MP_DEFAULT"; sec-dispatch §4.2 proves 1/2 = **slot identity** (which record validated), actual lock value = record+0xC |
| 0x40035008 | both-slots-zero → err +0x2c (0xC002005A) | reserve2, sec-dispatch | ok |
| 0x40035030 | anti-clone classifier/scramble (flag byte 0x40056E30) | reserve2, sec-dispatch, postwrite-hang | ok |
| 0x40035044–0x40035088 | classifier internals (anti-clone print @0x40035060) | sec-dispatch, postwrite-hang | ok |
| 0x4003a2d4 | SHA-256 wrapper / record digest ("decrypt" direction in DA2) | reserve2, write-chain, da2-rpmb-key | ok |
| 0x4003a2d8 / 0x4003a334 / 0x4003a3a4 | engine lock / SHA init / SHA update | da2-rpmb-key, postwrite-hang | ok |
| 0x4003a944 / 0x4003aa20–0x4003aa2c | RPMB key derivation (HACC, tags "SASI"+"RPMB KEY"/"BTTJSQNC!LFZ") / return site | da2-rpmb-key | ok |
| 0x40032e5c / 0x40032ca4 / 0x40033018 / 0x40033028 | rpmb_hmac / HMAC-SHA256 core / wipe arg setup / **wipe memset (patch point)** | da2-rpmb-key | ok |
| 0x4006e8d8 | RPMB key stage global (0x40; first 0x20 = key) | da2-rpmb-key | ok |
| 0x40040b38 / 0x40040cfc / 0x4003fe24 / 0x40040e7c/e84/e88 / 0x400409a8 | HACC task packer / descriptor builder / CFIFO pusher / helpers | da2-rpmb-key | ok |
| 0x40026044 / 0x400266d4 / 0x40026dbc / 0x40025fb0 / 0x4006df40 / 0x40026ea8 / 0x400270b0 / 0x400251c4 / 0x4006def8 / 0x40024838 / 0x40030dd4 | UFS RPMB frame checkers / pre-nonce (+0x4006df40) / sec-wp ops / clr_write_protect / RPMB device object / UFS init | da2-rpmb-key | ok |
| 0x40039538 / 0x40039598 / 0x4003c8c8→0x4003a76c / 0x4003c7d0 / 0x40040244 / 0x4004086c / 0x4003c8d0 | modulus byte-reverse / policy sig verify / RSA op / PKCS#1 v1.5 check / e=65537 / bignum import / second Montgomery RSA | auth-paths | ok |
| 0x4002ffd8 / 0x4002f804 / 0x4002fcf0–0x4002fcf4 / 0x4002fd04 | hash-list single caller / hash-list check (RET0 target) / entity-compare gate (BEQ→B) / deny print | README, xml_lib | ok |
| 0x40008d3c / 0x40008ddc–0x40008e7c / 0x40008e10 / 0x40008e04 / 0x40008f08 / 0x40008f78 / 0x40008f7c / 0x40008fa0 / 0x40009010 / 0x4000904c / 0x40009080 / 0x40009090 | malloc core / carve+header stamp / low-end carve / split rule / free core / free internals / **`str r1,[r0,#8]` fire write** / insert / backward coalesce / forward coalesce / forward-coalesce abort write (`str r5,[r3,#4]`) / heap_init | vuln, stabilize | ok |
| 0x4000a59c / 0x4000a5b4 / 0x4000a5f0 | malloc / calloc / free wrappers | vuln | ok |
| 0x4000aef4 | ascii-hex→u64 | vuln, scrubber, write-chain | ok |
| 0x4000b0d8 / 0x4000b110 / 0x4000b330 / 0x4000b57c / 0x4000b5e0 / 0x4000b668 | strncmp/memcmp / memcpy / memset / strcmp / strncmp / strlen | multiple | ok |
| 0x4000d0bc | mxml_load_string (parser region) | vuln, stabilize | ok (bit-exact resolver value unverified, vuln §6) |
| 0x4000e138 / 0x4000ed70 | "Bad %s" ref / free-chain hop | vuln | ok |
| **0x4000ea94** | scrubber/erase-audit: "send error status to host"; stabilize §2.1: "mxmlDelete(tree)" (called at 0x40006ce4) | **[COLLISION]** — two reports attribute the same VA to different functions. One of the two call-site attributions is wrong (likely two adjacent thunks; needs one re-check) |
| 0x40007c10 / 0x40007cbc / 0x40007d5c | log print / loglevel / log | multiple | ok |
| 0x400084a4 | generic "Security deny for [%s]" printer (~130 callers, do NOT patch) | README, session, scrubber | ok |
| 0x4000f760 / 0x4000ccb8 / 0x4002f11c / 0x4002eca4 / 0x4002f228 / 0x4002f3d8 | low-level erase chain; 0x4002eca4 = erase dispatcher (ops table +8) | scrubber, write-chain | ok |
| 0x4002e744 | low-level program (ops table +4) | write-chain | ok (internals untraced) |
| 0x4002a934 / 0x4002aa14 | USB send op / USB recv op (session table 0x40054320) | write-chain | ok |
| 0x40031504 | bogus blx-thunk inside get_hw_sbc | session | ok |
| 0x40037134-area (0x40036398–0x40037134) | external-sig vfy cluster (never touches g_oplus_auth_status) | auth-paths | ok |

### DA2 data / globals

| VA | Attribution | Sources | Status |
|---|---|---|---|
| 0x4005455c | g_oplus_auth_status | README, session, auth-paths, xml_lib | ok |
| 0x40054314 | WRITE-PARTITIONS deny global / err-print global | README, session, scrubber | **[COLLISION]** re-sec-dispatch §2.2 calls it "g_oplus_auth_status" in the RPT row — mislabel (auth status is 0x4005455c) |
| 0x4006E9F0 | lock-state global — **slot identity (1/2)**, not lock value | sec-dispatch, reserve2 | **[COLLISION]** on semantics (see 1.e) |
| 0x40067640/0x40067660, 0x40067600/0x40067620 | slot-0 (main) / slot-1 (backup) record slots (body/hash) | sec-dispatch, reserve2, postwrite-hang | ok |
| 0x4005cf00 | 0x3000-byte seccfg read buffer | reserve2, sec-dispatch | ok |
| 0x40067cce | 5-byte runtime config (policy+0x700) | scrubber, auth-paths | ok |
| 0x40067cf8 / 0x40067cfc | g_ext_all_in_one_sig ptr/len | stabilize, auth-paths | ok |
| 0x40067BA9 (+0x40067BA0, 0x40067770) | ACC enable byte (+ config) | postwrite-hang, write-chain | ok |
| 0x40067A08 (+0x14) | chk flags / packet-len global (runtime value unproven) | vuln, write-chain | ok (medium conf) |
| 0x40069e94 (+8/+0xc) | free-list head / sentinel | vuln, stabilize | ok |
| 0x40069dec / 0x40069de8 / 0x40069df0 / 0x40069e8c | dpc struct / dpc_addr (−4) / dpc->cb / reboot flag | vuln, stabilize | ok |
| 0x4006A040 | engine-1 progress slot | write-chain | ok |
| 0x4006E7CC / 0x4006E7D0 | engine-2 progress slots | write-chain | ok |
| 0x40070e00 | heap base (heap_init r0) | stabilize | ok |
| 0x4005628c | SEC policy table (64 × 32 B) | README, sec-dispatch | ok |
| 0x400569b0 | policy-table alias entry "oplusreserve2" (idx 57) | reserve2, sec-dispatch | ok |
| 0x40056a30 / 0x40055fac / 0x4004e4c1 | single_mode string ptr / md1img +0x1c ptr / preloader +0x18 field | sec-dispatch | ok |
| 0x40056E28 / 0x4006E938 / 0x40056E30 / 0x400679D8 | sboot module word / sboot byte flag / anti-clone flag byte (writer unknown) / MMMM key source | sec-dispatch, postwrite-hang | ok (0x40056E30 writer = open) |
| 0x4007a1c / 0x400529e0 / 0x4006a088 / 0x40053C10 | reversed modulus / RSA modulus / devinfo ctx / DigestInfo prefix | auth-paths | ok |
| 0x40054374 | storage ops table: +0 0x40008238→0x4002f2f0 (read/verify), +4 0x4000823c→0x4002e744 (program), +8 0x4002eca4 (erase), +0xc 0x4002f228 | scrubber, write-chain, da2-rpmb-key (uses +0xc as svc call) | ok |
| 0x40054320 (+0x40054328) | session USB op table (+0x10 = 0x4002aac0 program, lit ref) | write-chain | ok |
| 0x40066d80 / 0x40067458 / 0x40067738 | storage singletons (UFS/eMMC/…) | da2-rpmb-key | ok |

### DA2 strings (selected, consistent across reports)

0x40041459–0x4004171d command-name strings (sec-dispatch table, matches session map);
0x40042f12 "Signature"; 0x40042f28 "SEC-POLICY"; 0x40042f33 "Server is not authenticated.
Locked."; 0x4004e8da "[SEC] set lock state as LOCKED"; 0x4004e891/0x4004e8b6/0x4004e8fa/
0x4004e91c SEC prints; 0x400510c3 "SEC_CFG"; 0x400510eb "[%s] SECCFG Anti-Clone Enabled"
(**0x400510eb** — session doc's "0x510cb" is **[STALE]**, corrected by postwrite-hang §4);
0x400454bc "seccfg"; 0x400454f5 "oplusreserve2"; 0x40045bf6 "PRELOADER"; 0x40041b11 erase
log fmt; 0x40041b34 "Erase [%s] Failed."; 0x40041d56 erase-fail+code; 0x400454c2/0x400454db/
0x40045503 keep/format strings; 0x4004dd6c "Download host file:%s"; 0x400437f8 DPC CALL;
0x40041583 "CMD:REBOOT"; 0x400424a9 "reboot"; 0x4004dc6a/0x4004dd49/0x4004dd51 CHK/download
fmts; 0x4004dd9f "buffer too small"; 0x4004df31/0x4004dfe7 progress/EOT; 0x4004f54f progress
hex fmt; 0x4004a7d0/0x4004f077 storage_erase strings; 0x40042ecb/0x40042ed1 RPMB-KEY-STATUS
EXIST/NOT-EXIST; 0x40042eeb LIFE-CYCLE-STATUS; 0x40050e7a/0x40050e0c/0x40050e9a rpmb_hmac
errors; 0x4004c6d6/0x4004c5c9/0x4004c37a rpmb prints; 0x400519ed derive fail; 0x400533c0
default serial; 0x40053348 default oplus_custom hex; 0x4004e3c0 "Changed At…" GPT print;
0x4004e825 "oplus_single_mode"; 0x40051078 "SEC_HACC"; 0x400426ba runtime_switchable_config.

### Physical addresses

| Addr | Attribution | Sources |
|---|---|---|
| 0x1000A008 | HACC/SEJ-style engine regs (poll base) | postwrite-hang, re-lk-seccfg |
| 0x1000A060 | HACC key regs | postwrite-hang |
| 0x10210000 | HACC2/derivation mailbox base (CFIFO +0xE80, status +0xE9C) | da2-rpmb-key |
| 0x11C10140 | efuse serial (16 B) | auth-paths |
| 0x48400000 | "vm_hmac"/"system_rpmb_hmac-reserved" shm carveout (LK↔EL3) | lk-rpmb-key-derivation |
| 0x4800000 / 0x24000000 | oplusreserve2 / seccfg byte addresses (session only; DA uses names) | session, reserve2 |

### LK (base 0x50000000) — consistent within the two LK reports

0x500827E8 master validator; 0x500824FC record digest check; 0x500826DC init-NV writer
(lock_state=1 default); 0x500825EC sec_update re-sign; 0x50082AE0 getter core;
0x50082E10 is-unlocked wrapper (`!=3`); 0x50082B30 setter core; 0x50082E88 logical wrapper
(0→3; 1→cur==1?2:4); 0x50082C5C/0x50082CD4 dm-verity get/set; 0x5007AB58 hash dispatcher;
0x5007B1D0 SW SHA-256; 0x50076EB8 HACC wrapper; 0x5007C838/0x5007C900/0x5007C97C HACC HW;
0x50083848/0x50083904 partition IO; 0x50069B84/0x50069C10 name lookup/block IO;
0x5000262C sec_boot_init; 0x500026B8 (double_check call) / 0x500026E4 (mirror write);
0x500556C4 double_check_lock_state; 0x500557C0 power-off block; 0x50054674
km_client_read_rpmb_boot_info; 0x50054744 set_boot_info_to_rpmb; 0x50055508/0x50055364/
0x50055368 read+hash+memset-on-mismatch; 0x50055570 device-type; 0x50074f54 "rpmb enable"
(hardcoded ret 1); 0x5002fd14 rpmb_read_direct (SMC 0xC2000414 via 0x5001db88, shm
0x50133A00/0x50133A08); 0x5003e4e4 rpmb_read_via_tee; 0x50030510 mmc_rpmb_send_command;
0x5002fb24 frame dispatcher; 0x5008B4DC/0x5008B534/0x5008B718 SW SHA-256; 0x500BC9F0 K-table;
0x5006c990/0x5006c9c8/0x5006cbc4 cmp/memcpy/memset thunks; 0x500326AC/0x50032670/0x500326B0/
0x5003266C thunks; 0x5005360C/0x500536DC dm-verity callers; 0x50053F3C/0x50053F60/0x50053F6C/
0x50053F78 AVB state + banner; 0x500C4FA8 state global; 0x500AC700 string table;
0x5000E270 bootstrap; 0x500078E8 fastboot unlock commit; 0x50144840/0x50144880 record slots
(+0xC lock_state); 0x50055414/0x500553A0/0x5005544C/0x50055484 mirror field helpers;
0x5005536C/0x500036C0 dev_info; 0x5001FBE0 LED; 0x50030120/0x5003E91C RPMB write; 0x5006a7dc
retry sleep; 0x5008EEFA oplusreserve1 (bookkeeping). No conflicts found between
re-lk-seccfg.md and re-lk-rpmb-lock.md/re-lk-rpmb-key-derivation.md addresses; the two
latter explicitly resolve re-lk-seccfg §8's flagged uncertainties (see 1.e).

### Summary of stale/conflicting table entries (Task 1.d answer)

1. **0x4002c800** — README "SEC service fn (print 0x4002ceac), table-dispatched" and
   session §23:5x "func start 0x4002c800" and scrubber §2 "table service 0x4002c800" are
   all **[STALE]**; re-sec-dispatch proves interior BB of fcn.4002c6f0 (GPT/PMT compare).
2. **0x40034ffc/0x40035014** — README "SEC state writers: MOV r1,#1 / MOV r1,#2" and
   session/postwrite-hang labels (LOCKED/MP_DEFAULT) are **[STALE]** vs re-sec-dispatch's
   slot-1/slot-2 reinterpretation; also the MOV for writer #1 is at **0x40035000**
   (0x40034ffc is the movw of the global address) — session/xml_lib quote "0x40034ffc:
   MOV r1,#1" which conflates the two instructions.
3. **0x4000392c** — README/session/xml_lib "WRITE-FLASH deny" **[STALE]** → ERASE-FLASH
   (re-writeflash-scrubber §3).
4. **0x4002b5b4/0x4002b790** — scrubber "flash lock/unlock" **[STALE]** → progress-report
   senders (re-erase-patch-audit §6).
5. **0x4002d428** — vuln "process downloaded body" **[STALE]** → cache setter + free-prev
   (stabilize §2.1).
6. **0x4000ea94** — **[COLLISION]**: "send error status" (scrubber, erase-audit §3) vs
   "mxmlDelete(tree)" (stabilize §2.1). One attribution is wrong.
7. **0x40054314** — re-sec-dispatch §2.2 parenthetical "also reads g_oplus_auth_status
   0x40054314" is a **[COLLISION]** mislabel (0x40054314 is the WRITE-PARTITIONS deny /
   print global; auth status = 0x4005455c).
8. **0x4000c348/fcn.4000bb14** — postwrite-hang "WRITE-PARTITION engine (seccfg)" vs
   write-chain "PRELOADER-only engine" — **[COLLISION]** (see 1.c).
9. Session doc: "0x510cb" anti-clone string **[STALE]** → 0x510eb (postwrite-hang §4).
10. Session doc: "seccfg at LBA 147456-149503 (0x12000000 area, 4MB)" — **[STALE]** line
    inside the same doc that later says 0x24000000/8 MB (see 1.f).

## 1.e LK lock_state semantics and mirror bit (wording drift)

- `re-lk-seccfg.md`: proves wrapper transitions "0→3 (unlock), 1→cur==1?2:4", unlock value
  = 3 (fastboot path), init-NV default LOCKED = 1; flags values 1/2/4 semantics as medium
  confidence (OPLUS-convention naming). §6 flags the mirror bit (+0xC == 1) as uncertain.
- `re-lk-rpmb-lock.md` §3 **resolves** the mirror bit: written as `(flag==0)?1:0`,
  1 = locked, 0 = unlocked — explicitly "resolves the uncertainty flagged in
  re-lk-seccfg.md §8". Consistent.
- `re-lk-rpmb-lock.md` §2 [DC-2]: force-relock via wrapper(1) → per lk-seccfg cur==1→2
  else 4. Consistent.
- **Drift to flag**: the labels "state=1 is LOCKED / state=2 is MP_DEFAULT" appear in
  `re-postwrite-hang.md` §1 (writer comments), `re-reserve2-master.md` §3.2 and its §5
  patch guidance ("patch the writers so every classification sees state=3"), and
  `rmx3630_session_2026-10-23.md` §23:5x — all for the **DA2 global 0x4006E9F0**.
  `re-sec-dispatch.md` §4.2 proves those 1/2 values are **slot identity** (which seccfg
  record validated), and the lock value the DA consumes is record+0xC. Under the proven
  model, patching the writers to store 3 makes `sec_get_seccfg`'s wrapper hit the
  "else → 0xC002005B" path (default store leaves out=1, i.e. LOCKED default) — the
  opposite of the intended effect. Three documents repeat the stale interpretation:
  postwrite-hang §TL;DR/§1, reserve2 §5 "practical patch guidance", session §23:5x
  ("commit 39ac1f3 … BOTH writer MOVs patched to MOV r1,#3 (LKS_UNLOCK)"), plus
  xml_lib.py (Task 2). Note this is a *different* 1/2 pair than LK's record lock_state
  values (1/2/4 locked-family) — the two domains must not be conflated.

## 1.f seccfg size

- `rmx3630_session_2026-10-23.md`: GPT-read line says "LBA 147456-149503 (0x12000000
  area, 4MB)"; the seccfg-backup section says **8 MB (2048 LBAs @4096), not 2 MB — 2× the
  GPT-entry estimate**, md5-verified 8388608 B. The 0x12000000/4 MB line is internally
  inconsistent (147456×4096 = 0x24000000; 2048×4096 = 8 MB) — **[STALE]** first line.
- DA2 reports: the loader reads only **0x3000 bytes** (buffer 0x4005cf00); no report
  assumes a partition size. mtkclient reads/writes the full GPT-declared size
  (`v6.seccfg()`, padded to `fullsize`). No live contradiction beyond the session doc's
  own stale line; the "2 MB GPT-entry estimate" never appears in any other report.

## 1.g RPMB-key workstream mutual consistency

Three reports + lock report:

| Question | da2-rpmb-key | lk-rpmb-key-derivation | mtkclient-rpmb-audit | lk-rpmb-lock |
|---|---|---|---|---|
| Where is the key? | **Materializes in DA2 RAM** (0x4006e8d8), derived on-chip by HACC @0x10210000 (tags SASI/"RPMB KEY"); no SMC in DA2 | Key **never in LK/preloader/DA**; derived in GenieZone TEE; LK delegates HMAC via SMC/GP-TEE | Host supplies key to the patched-in stub; DA does HMAC | Key lives in eMMC/TEE, not LK |
| Programable? | Stock DA2: key-program library **dead** (no xrefs); only status query live | Preloader provisions once via GZ (`rpmb_authen_key_program`, keyprovision flag) | `custom_rpmb_prog` (CUSTOMRPMBP) via mtkclient's patched-in stub programs our key | Same (§5, §9.2b) |
| mtkclient `da rpmb` usable? | — (not in scope) | Notes `da rpmb` can program our own key if unprovisioned | Fully audited: r/w/e/a + prog work through the runtime stub; CLI hex-key bug | §5 consistent |

**[COLLISION]**: `re-lk-rpmb-key-derivation.md` TL;DR says the key is "never exposed as
plaintext to LK, preloader, **or DA**". `re-da2-rpmb-key.md` proves the opposite **for
DA2**: the derived 32-byte key is staged into DA2 RAM at 0x4006e8d8 on every rpmb_hmac
call and can be dumped (§6). Both can be true simultaneously (DA2 uses the HACC engine
directly; LK goes through GZ/SMC), but the derivation report's blanket wording is wrong
for the DA and materially changes the plan: **dumping the DA2-resident key (da2-rpmb-key
§6) is a fourth, cheaper option that lk-rpmb-key-derivation's probe list (§Next probes)
omits entirely** — its probe list starts at "check key-provision state", never mentioning
the RAM-dump route.
Related minor tension: da2-rpmb-key §7 leaves open whether the HACC-derived key == the
device's programmed key, while lk-rpmb-key-derivation infers a TEE-random (or GZ-derived)
key — these two hypotheses are mutually exclusive for a provisioned unit; the on-device
discriminator (init-time `ufs_clr_write_protect` result / `rpmb_hmac error`) is named only
in da2-rpmb-key.
Verdict consistency with `re-lk-rpmb-lock.md` "one authed write = permanent unlock" (§8/§9):
consistent — audit §6–7 gives the exact sector-0..3 rewrite recipe; lk-rpmb-lock §9 step 2
matches; both agree the mirror fix is needed only once (LK self-maintains afterwards).

---

# TASK 2 — Reports vs mtkclient code

## 2.1 heapbait.py

1. **[CODE-BUG, confirmed] `cmd_exp_call_func` builds EXP-PATCH-MEM** (line 597:
   `cmd = self.create_cmd("EXP-PATCH-MEM", content)` inside `cmd_exp_call_func`). Breaks
   `call_func()` → breaks `apply_oplus_runtime_patches()` E3 registrar re-invocation
   (xml_lib.py L1050). Fix = stabilize §3.2 diff. Docstring of `cmd_exp_call_func` also
   still documents a `<length>` tag that is not emitted.
2. **[CODE-STALE] Heap-layout comments (L773–779)**: "This buffer will be allocated right
   after the AIO2 data buffer… [AIO2 data buffer (0x1410)] [XML filename buffer (0x13a0)]"
   — contradicted by stabilize §2.1/§2.2 (ascending first-fit, no cross-command LIFO
   reuse, victim = lottery; the deterministic victim is S1, the cached-previous buffer
   freed at 0x4002d44c, not the filename chunk). The comments should be rewritten or the
   stabilize findings inlined, otherwise the next maintainer re-derives the wrong model.
3. **[CODE-STALE] Stage-3 overflow-size comment (L787–797)**: "By sending 0x1410 bytes
   total, we overflow 0x10 bytes past the buffer" — true only for ARM64 (0x1400+8+8 =
   0x1410); the ARM32 path (L802–809) sends 0x1400+4+4+4 = **0x140C** and overflows
   **0xC** bytes (as re-heapbait-vuln §2b states). Comment overgeneralizes.
4. **[CODE-GAP] No scratch-word / no retry loop**: L807 still writes 0xDEADBEEF as linkA
   (stabilize §3.1 P0: converts wrong-victim runs into DA death); no `_try_bait`
   stepping/probe (§3.3), no GETBAITED re-read hardening (§3.4). Matches "plan not yet
   applied" — listed so it is not forgotten.
5. **[OK] USB_DATA_SIZE=0x1400 vs advertised 0x13FC** (`ack_value(USB_DATA_SIZE - 4)`,
   L810): consistent with the DA's `malloc(sb+4)` (vuln §2a) — advertises 0x13FC so the
   allocation is exactly 0x1400 user capacity. Not a bug.
6. **[OK/fragile] ack sequence vs DA's per-chunk OK-before-recv** (L810–819): the DA sends
   "OK" before each data recv (0x4002b190, stabilize §2.4) and, once overflowed, the loop
   never exits exactly — the response after `xsend(payload2)` is the DA's *error* packet.
   heapbait checks `ack != "OK"` only on the first response and discards the second
   (L817) and the post-payload response (L819) — works "by accident" per stabilize §2.4;
   stabilize §3.4 asks for logging + tolerant GETBAITED re-read. Not currently wrong, but
   unhardened.
7. **[OK] `patch_da` OPLUS guard** (L620–632) implements the session-doc dead-end
   (mis-targeted hash_bind / file-offset SLA write). Consistent.
8. **[OK] ARM32/ARM64 header wording** (L796–797): "ARM32: magic|ptr|size" matches the
   proven allocator stamp `[user-0xc]=magic, [user-8]=node, [user-4]=size` (vuln §3,
   stabilize §1). The ARM32 fake-header triple {linkA=scratch/DEADBEEF, linkB=dpc_addr,
   size=shellcode} lands exactly on those three fields.
9. **[NOTE] `is_vulnerable()`** string check matches vuln §1 (string absent in this blob →
   vulnerable). Consistent.
10. **[NOTE] `find_heap_struct` ARM32 resolves r1; `parse_heap_init` ARM32 resolves r3**
    for heap_size — stabilize §0 confirms r3 = end−base computed in heap_init's prologue;
    replay matched (0x32000000). Consistent.

## 2.2 xml_lib.py `apply_oplus_runtime_patches` (L784–1054)

Patch-by-patch against the consolidated table:

| Patch (code label) | VA | Verdict vs reports |
|---|---|---|
| cust_security_verify_sec_policy RET0 | resolved via string | OK (auth-paths §2: unconditional call, RET0 = "authorized") |
| oplus_security_verify_sec_policy RET0/stub + status | resolved | OK; level semantics match session/auth-paths (3=locked default, 4=read-only, 0/1/2=full). Level-5 E1 direct write of 0x4005455c = auth-paths §8 rank-6 route. OK |
| DA.SLA ENABLED→DISABLE | file-offset→VA handled correctly here (L904–907 uses `da2address + idx`) | OK (README 0x400416bf area) |
| get_hw_sbc RET0 | resolved or fallback 0x40039d00 | OK; default off matches session ("OPLUS_SBC_PATCH=0; patch DEATH post-SLA") |
| "WRITE-PARTITION deny-check 0x400021a0 → MOV R0,#0" | 0x400021a0 | OK |
| **"WRITE-FLASH deny-check 0x4000392c → MOV R0,#0"** | 0x4000392c | **[CODE-STALE + risk]**: this is the **ERASE-FLASH** deny check (scrubber §3). The patch forces the ERASE-FLASH deny check to always pass — i.e. it *lowers* a protection on the erase path for exactly the partitions the campaign must never erase (seccfg). Either relabel and drop it (WRITE-FLASH's own denies are 0x400031a4/0x400031b0, patched separately), or keep it consciously with a corrected comment. |
| WRITE-FLASH deny BEQs 0x400031a4/0x400031b0 → NOP | ok | OK (scrubber §1, session 23:1x) |
| oplus hash-list check 0x4002f804 RET0 / entity-compare 0x4002fcf4 BEQ→B | ok | OK (README) |
| **"SEC seccfg state writer 0x40034ffc MOV r1,#1 → #3" @0x40035000** and **"0x40035014 MOV r1,#2 → #3"** | 0x40035000 / 0x40035014 | **[CODE-BUG per the proven model]**: the global 0x4006E9F0 holds **slot identity (1/2)**, not the lock value (re-sec-dispatch §4.2). Storing 3 makes `sec_get_seccfg` classify the global as invalid → wrapper error 0xC002005B with the default store leaving **out = 1 (LOCKED)**. The patch cannot make regenerated seccfg "state=3" — the lock value lives in record+0xC, which the DA never rewrites (write-chain §5, reserve2 §3). It also explains the session's "state-writer patch run produced unreadable/zeros" observation as *plausibly this* (postwrite-hang's caveat + session open-question 2). Should be removed or replaced by the read-path validation bypass (reserve2 §5: 0x40034f94 beq → unconditional / RET0 0x40035030) if the goal is to make the DA accept uploaded content. |
| Missing patches that newer reports endorse | — | **[CODE-GAP]**: none of (a) WRITE-FLASH erase-kill `0x4000325c → mov r0,#0` (audit-proven SAFE, the direct fix for the seccfg-zeroing scrub), (b) HACC poll NOPs 0x40039848/0x400397e0/0x40034b18 (postwrite-hang), (c) ACC-gate skip 0x4000c210 → b 0x4000c258 or 0→0x40067BA9, (d) heapbait scratch-word / retry (stabilize §3.1/§3.3), (e) READY-spam drain (stabilize §3.5) is implemented. |
| dpc->cb pre-clear between attempts | — | Not present (stabilize §4.3) — only relevant once retry loop exists. |

## 2.3 seccfg.py vs the LK/DA2 record model

- **lock_state constants**: `create()` writes **3 for unlock, 1 for lock**. LK-proven
  semantics (re-lk-seccfg §3.3/§8): unlock = 3 (fastboot path writes 3; is-unlocked =
  `state != 3`); locked family = 1/2/4 (init-NV default = 1; wrapper arg1 → 2 or 4);
  the shipped device value is 4. So `unlock→3` matches the DA/LK honor semantics.
  The comment block in `parse()` (L124–134) documents LKS_* including LKS_LOCK=0x04 —
  consistent as *record values*; **no mismatch in the written values**.
  The genuine mismatch is elsewhere: mtkclient's mental model ("lock_state=3 written ⇒
  device unlocked") is incomplete — the DA2 `0x4006E9F0` writers and the LK RPMB mirror
  are separate layers; the practical impact of the xml_lib writer patch (§2.2) is that
  mtkclient's unlock *verification* (readback expecting 3) can never be satisfied by that
  patch route.
- **Record shape (zero-recovery path)**: `SecCfgV4.create()` emits
  `pack("<IIIIIII", magic, ver, size, lock_state, dm_verity, sboot, 0x45454545)` = 0x1C
  bytes, then `enc_hash` (0x20) → total **0x3C**, zero-padded to the partition size.
  Reports' layout (re-lk-seccfg §1/§3.2, re-sec-dispatch §4.2): magic@+0x00, ver@+4,
  size@+8, **lock_state@+0xC**, dm_verity@+0x10, sboot@+0x14, **EEEE@+0x18**, digest
  @+0x1C (0x20 B); main record @ partition +0x00, backup @ +0x3C. **The built payload is
  the right shape**: MMMM@+0, EEEE@+0x18, hash@+0x1C, and a zero backup at +0x3C is
  handled by both validators (DA2: backup memcmp-zero → skipped; LK: main valid →
  clears bak). ✓
- **[CODE-RISK] Hash primitive**: `create("unlock")` with `hwtype="V4"` computes
  `sej_sec_cfg_hw_V3(sha256(hdr), encrypt=True, legacy=True)`. The reports prove the
  DA2/LK digest is **HACC-AES(SHA256(hdr[0:0x1C])) with fixed seeds** (LK §3.1: seeds
  0x9ED44000/0x00E884A1/0xE3F083BD/0x2F4E6D8A; DA2: same primitive pair, encrypt-direction
  in LK). Whether the SEJ-V4-legacy host emulation reproduces that HACC scramble is
  **unverified anywhere** — if it differs, every written record fails DA2/LK validation
  on next read (fail-safe LOCKED / init-NV rewrite). The session log's claim "hash comes
  from the DA's own SEJ/HACC via custom_sej_hw" is asserted, not proven. This is the
  single highest-value open verification for the unlock path.
- **[NOTE] `parse()`** reads hash at `seccfg_size-0x20` (=0x1C for size 0x3C) — correct.
  `parse()`'s verification family is likewise SEJ-based (same open question).
- **[NOTE] v6.seccfg() zero-recovery** (v6.py L1150–1204): forces hwtype V4, seeds
  ver/size/dm_verity/sboot from the backup header (plain dwords — matches reports: those
  fields are unencrypted), pads to full partition size, writes via WRITE-PARTITION —
  consistent with the scrubber/write-chain findings (full-size WRITE-PARTITION commits;
  WRITE-FLASH forbidden). Address fix (sector × sectorsize) matches the session's pagesize
  incident. Sound.

---

# TASK 3 — Fix / extend list (ranked)

## (a) Report edits

1. **[P0] re-reserve2-master.md §5 "practical patch guidance"** — the writer-patch recipe
   ("patch 0x40035000/0x40035014 MOV → #3 so every classification sees state=3") is wrong
   under re-sec-dispatch §4.2 (slot identity). Replace with the read-path validation
   bypass (0x40034f94 beq → unconditional, or RET0 0x40035030) + a note that the record's
   +0xC is the real lock value.
2. **[P0] re-postwrite-hang.md** — (i) §1/§TL;DR writer comments "1=LOCKED / 2=MP_DEFAULT"
   → relabel as slot-1/slot-2 identity per re-sec-dispatch; (ii) §3/§Summary: the seccfg
   write path is engine 2 (0x400306ac) per re-write-chain — mark the fcn.4000bb14 HACC
   attribution as PRELOADER-path-only and flag "engine-2 HACC pass untraced" as the open
   hang question; (iii) drop "3. Do not RET0 the SEC state writers … broke regeneration"
   → reword: the writers set the *slot global*, so patching them cannot affect content or
   fix the hang.
3. **[P0] re-lk-rpmb-key-derivation.md TL;DR** — "never exposed … to DA" is false for
   DA2 (re-da2-rpmb-key §1/§6: key staged at 0x4006e8d8 every rpmb_hmac call, wipe-NOP
   dump recipe). Add the DA2-RAM-dump as probe #0 (before the key-provision check) and
   cross-reference the mutually-exclusive provisioned-key hypotheses (HACC-derived vs
   TEE-random) with the named on-device discriminator.
4. **[P1] rmx3630-da2/README.md address table** — correct 0x4000392c (→ERASE-FLASH),
   0x4002c800 (→interior BB of fcn.4002c6f0, GPT/PMT compare; print lives in fcn.4002ce08
   @0x4002ceac), 0x40034d6c entry fine; re-annotate 0x40034ffc/0x40035014 as
   slot-identity writers (MOV at 0x40035000), and close open questions 1–4 with pointers
   to the answering reports (postwrite-hang, writeflash-scrubber, reserve2-master,
   sec-dispatch).
5. **[P1] rmx3630_session_2026-10-23.md** — mark superseded sections rather than deleting:
   §23:5x "SEC service REGENERATES seccfg with ITS OWN state" (reserve2-master §5: no
   regeneration; classification + erase), "func start 0x4002c800" (sec-dispatch),
   "0x510cb" (0x510eb), the "0x12000000 area, 4MB" GPT line (0x24000000 / 8 MB), and the
   commit-39ac1f3 writer patch (ineffective/harmful per slot-identity model).
6. **[P1] re-writeflash-scrubber.md** — §1/§5 still describe 0x4002b5b4/0x4002b790 as
   "flash/storage lock-unlock"; add a pointer to erase-audit §6 (progress-report senders).
   §2 negative-results mention of "table service 0x4002c800" → replace with fcn.4002ce08.
7. **[P2] re-heapbait-vuln.md** — add a header banner: "§5/§6 direction+victim statements
   superseded by re-heapbait-stabilize.md §1–§2.4".
8. **[P2] re-write-chain.md** — TL;DR cites "the same branch documented in
   re-postwrite-hang.md" for the ACC gate; clarify the gate is engine-1(PRELOADER)-only
   and that engine-2's (seccfg) post-loop behavior is untraced.
9. **[P2] re-sec-dispatch.md §2.2** — fix the "g_oplus_auth_status 0x40054314" parenthetical
   (0x40054314 is the WRITE-PARTITIONS deny/print global; auth status is 0x4005455c).
10. **[P2] Resolve 0x4000ea94** — one re-disassembly pass to decide "send error status"
    vs "mxmlDelete" (both reports cite it for different callees at different call sites;
    likely two adjacent thunks — name both).

## (b) Code fixes

1. **heapbait.py:597** — `cmd_exp_call_func` must build `EXP-CALL-FUNC`
   (stabilize §3.2 diff); fixes E3 registrar re-invocation.
2. **xml_lib.py:990–993** — remove (or neuter) the two "SEC seccfg state writer" patches:
   they write 3 into the slot-identity global 0x4006E9F0 → `sec_get_seccfg` errors
   (0xC002005B) and defaults to LOCKED. If an unlock-content lever is wanted, patch the
   read-path digest decision (0x40034f94) instead.
3. **xml_lib.py:951–954** — relabel 0x4000392c as ERASE-FLASH deny-check; recommend
   removing the patch (it disables an erase protection on the partition the campaign
   must not erase) or gating it behind a separate env var.
4. **heapbait.py:807** — replace 0xDEADBEEF with a verified scratch word
   (stabilize §3.1; READ-REGISTER probe first; fallback 0x40069de0).
5. **heapbait.py:773–799** — rewrite the stage-2/3 heap comments to the proven model
   (ascending first-fit; S1 victim; 0xC ARM32 overflow).
6. **heapbait.py L810–834 / new `_try_bait`** — implement stabilize §3.3/§3.4: attempt
   loop with filename-length stepping, EXP-PATCH-MEM probe, logging of the unchecked
   `get_response()` results, tolerant GETBAITED re-read.
7. **xml_lib.py `send_command`** — add the READY-spam drain (stabilize §3.5,
   `OPLUS_READY_FILTER`) instead of discard-all flush on EIO.
8. **New patch entries in `apply_oplus_runtime_patches`** (env-gated):
   WRITE-FLASH erase-kill `0x4000325c → 00 00 A0 E3` (audit-proven safe);
   HACC poll NOPs 0x40039848 / 0x400397e0 / 0x40034b18; ACC skip `0x4000c210 → b`.
9. **mtk_da_handler.py:1629–1631** — hex-string RPMB key bug: wrap with
   `bytes.fromhex` when `args.rpmbkey` is a str (re-mtkclient-rpmb-audit §2).
10. **seccfg.py** — no shape change needed; add a HACC-fixed-seed digest mode (or an
    explicit warning) for the V4 hash so the write path can be validated against the
    LK/DA2 proven primitive (currently SEJ-V4-legacy only, unverified equivalence).

## (c) New questions worth an agent (emerged from the collision scan only)

1. **Engine-2 (0x400306ac/0x4003010c) post-loop trace**: does the non-PRELOADER engine
   run any HACC/ACC pass or SEC hook after the last chunk? Decides whether the
   postwrite-hang HACC model applies to seccfg writes at all (directly resolves
   collision 1.c).
2. **0x4000ea94 identity**: disassemble 0x4000e9xx–0x4000eab0 to split the two thunks
   (send-error-status vs mxmlDelete) and correct both reports.
3. **Engine-2 program path buffer flow**: confirm 0x4002aac0 receives the unmodified
   buffer (completing write-chain's §8 uncertainty) and check for a per-chunk digest
   equivalent to engine 1's 0x4003a2d4/0x40037f70 pair.
4. **HACC-vs-SEJ digest equivalence test**: offline, compute
   HACC-AES(SHA256(sample_hdr)) with the LK-proven fixed seeds and compare against
   `sej_sec_cfg_hw_V3(..., legacy=True)` output for the same input — one host script,
   no device needed; decides whether mtkclient's written seccfg digests can ever validate.
5. **Writer of 0x40056E30** (anti-clone flag byte): still unlocated (postwrite-hang §1
   ambiguity) — a movw/movt + literal-pool scan focused on the storage-init/region
   0x4002f2xx/0x4002f3xx dispatch slots would settle whether the read-path HACC classify
   is host-controllable via SET-FLASH-POLICY tail bytes.
