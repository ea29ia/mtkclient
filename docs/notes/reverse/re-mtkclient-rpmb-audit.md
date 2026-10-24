# mtkclient RPMB capability audit — host-side levers for RMX3630 (MT6789, hwcode 0x1208), DA2

Date: 2026-10-23. Read-only audit; companion to `re-lk-rpmb-lock.md` (§5, §9) and
`rmx3630_session_2026-10-23.md`. Everything below is from mtkclient source (repo root
`/root/mtkclient`); MT6789 + OPLUS DA2 ⇒ the **xmlflash (DA v6)** path is the live one;
the parallel xflash (DA v5) implementation exists but is not used on this target.

## 1. `da rpmb` subcommands — wiring

CLI: `mtk.py` lines 281–298 defines `da rpmb {r,w,e,a}` with `--sector` ("offset/0x100
bytes"), `--sectors`, `--rpmbkey` ("hexstring, 32 bytes").

Dispatch: `mtkclient/Library/DA/mtk_da_handler.py:1619-1631` (`handle_da` → `subcmd == "rpmb"`):

| subcmd | calls | xmlflash impl (active on DA2) |
|---|---|---|
| `r` | `daloader.read_rpmb(filename, sector, sectors)` | `v6.py:840 read_rpmb` |
| `w` | `daloader.write_rpmb(...)` | `v6.py:875 write_rpmb` |
| `e` | `daloader.erase_rpmb(...)` | `v6.py:919 erase_rpmb` |
| `a` | `daloader.auth_rpmb(args.rpmbkey)` | `v6.py:914 auth_rpmb` |

`mtk_daloader.py:500-535` routes to `self.xmlft` (= `Library/DA/xmlflash/extension/v6.py`,
class `XmlFlashExt`) when `self.xmlft` is set.

DA-extension plumbing: `v6.py:249-391` patches a **DA-side stub pointer** into the OPLUS
DA2 at runtime (heapbait-style): it locates `mmc_rpmb_send_command` in `da2_oplus.bin`
via the `44 44 44 44` marker holes (and via the `"%sreq/1 fail %d\n"` string /
`get_next_bl_from_off` fallback, `v6.py:298-303`) and writes its resolved address into
the extension blob before upload. So all RPMB commands are served by this patched-in
stub inside DA2, not by stock DA code.

### Exact wire protocol (all commands are XML `CMD:*` headers, then raw binary args over the data channel via `xml_lib.py:251 xsend`)

* **`CUSTOMRPMBR`** — `v6.py:693 custom_rpmb_read(sector, sectors)`:
  `create_cmd("CUSTOMRPMBR")` → wait `OK` → `xsend(sector)` as `<I` u32 LE →
  `xsend(sectors)` u32 LE → for each sector read one raw 0x100 (256 B) blob; a non-0x100
  response is a little-endian u32 **JEDEC RPMB result code**, mapped by
  `rpmb_error_msg` (`v6.py:27-44`: resp 1..6 = auth failure / counter failure / address
  failure / write failure / read failure / **"Authentication key not yet programmed"**).
* **`CUSTOMRPMBW`** — `v6.py:718 custom_rpmb_write(sector, sectors, data)`:
  requires `len(data) % 0x100 == 0`; sends `CUSTOMRPMBW` → `OK` → sector u32, sectors
  u32 → per 0x100-byte chunk: data blob, then a u16 LE result; non-zero ⇒ abort with
  `rpmb_error_msg`.
* **`CUSTOMRPMBK`** — `v6.py:756-780` (inside `custom_rpmb_init`): sends `CUSTOMRPMBK`
  → `OK` → sends the 32-byte key blob → DA **echoes the key back** (`read_key`);
  host compares and prints "Setting rpmbkey: ok" only on match.
* **`CUSTOMRPMBI`** — `v6.py:779-799` (also `custom_rpmb_init`): sends `CUSTOMRPMBI` →
  `OK` → `xsend(mode)` u32, where `mode = 1` only for hwcode 0x1209/0x1129, else `0`
  (**0x1208 → mode 0**) → reads a u32 status; 0 ⇒ a second raw blob = the
  **derived RPMB key**, printed as hex ("Derived rpmb key: …"). Returns True on success.
  `write_rpmb`/`erase_rpmb` call `custom_rpmb_init()` first, so every write re-derives
  and re-sets the key.
* **`CUSTOMRPMBP`** — `v6.py:808 custom_rpmb_prog(rpmbkey)`: sends `CUSTOMRPMBP` → `OK`
  → 32-byte key → u32 status: `0` = "Key successfully programmed :)",
  `1` = "Key already programmed :(", other = error. **Not wired to any CLI subcommand**
  (only a commented-out call at `v6.py:841`) — call it via API.
* Read/write chunking: 16 sectors (0x1000 bytes) per command iteration
  (`v6.py:857, 890, 934`).

xflash (DA v5) twin for reference: `Library/DA/xflash/extension/xflash.py:478-560`
(`custom_rpmb_read/write/init`, same command names, signature-scanned stub
`xflash.py:109-111`).

## 2. `auth_rpmb(key)` — key format

* API path: `v6.py:914 auth_rpmb(rpmbkey)` → `custom_rpmb_init(rpmbkey)` → **`CUSTOMRPMBK`
  command, key sent as a raw 32-byte binary blob** in the data phase (not an XML field),
  echoed back for verification, then `CUSTOMRPMBI` derives/confirms.
* **CLI bug risk**: `mtk_da_handler.py:1629-1631` passes `args.rpmbkey` (a **hex
  string**) straight through to `auth_rpmb` → `custom_rpmb_init` uses it as-is, and
  `xsend` on a `str` sends ASCII bytes (`xml_lib.py:260-262`), not `bytes.fromhex`.
  Only a `bytes` key works correctly — use the API (`daloader.auth_rpmb(bytes.fromhex(...))`)
  or fix before device use. If `rpmbkey is None`, the key is derived on-host from
  MEID+OTP via SEJ: `hwc.aes_hwcrypt(mode="rpmb", data=meid, btype="sej", otp=otp)`
  (`v6.py:762-763`; hwcrypto backends in `Library/Hardware/hwcrypto*.py`).
* `custom_rpmb_prog` (`v6.py:808`) is the actual **key programming** op
  (`CUSTOMRPMBP`) — `auth_rpmb` only *sets* the working key in the DA; it does not
  program it into eMMC.

## 3. Key-STATUS query — implemented?

* **No host-side caller for `GET-RPMB-KEY-STATUS` / `RPMB-KEY-STATUS`.** The only
  EMMC-CONTROL builder is `xml_cmd.py:408 cmd_emmc_control(function="GET-RPMB-STATUS",
  mem_offset, mem_length)`, producing:
  ```xml
  <?xml version="1.0" encoding="utf-8"?><da><version>1.0</version>
  <command>CMD:EMMC-CONTROL</command><arg>
  <function>GET-RPMB-KEY-STATUS</function>
  <target_file>MEM://0x...:0x200000</target_file></arg></da>
  ```
  (registrar format: `create_cmd`, `xml_cmd.py:18-30`; the only live user is
  `check_lifecycle` with `function="LIFE-CYCLE-STATUS"`, `xml_lib.py:1583-1599` — copy
  that pattern: `send_command(..., noack=True)` → expect `UpFile` → `download(result)`
  → `CMD:END`/`CMD:START` ack dance).
* Indirect status probe that DOES exist: the JEDEC result code 6
  ("Authentication key not yet programmed") returned by `CUSTOMRPMBR` on an unkeyed
  device — an authenticated read of block 0 doubles as the status query. Also
  `CUSTOMRPMBP` returns 1 ("already programmed") / 0 (programmed ok) explicitly.

## 4. Frame construction / HMAC — host or DA?

**The DA does the HMAC internally.** The host never builds RPMB frames for the
custom commands: `CUSTOMRPMBW` takes plain 256-byte sector payloads; the patched-in
`mmc_rpmb_send_command` stub in DA2 owns nonce, write counter and HMAC
(`rpmb_hmac error`, `rpmb_authen_read_counter`, `ufs_rpmb_pre_nonce` strings in
`da2_oplus.bin`, §5 of the LK note). The host code only *sets which key* the DA uses
(`CUSTOMRPMBK`/`CUSTOMRPMBP`).

Consequence: given a dumped/factory key K, `da rpmb a K` + `da rpmb w` produces
validly-HMAC'd writes — no client-side frame builder needed. The only client-side
HMAC code is a standalone verification test, `Tools/rpmb_test.py` (verifies
`HMAC-SHA256(key, frame[0xE4:0x100]) == frame[0xC4:0xE4]` for a sample frame; not
wired into the DA flow).

## 5. Read/write counters, caching

* No host-side read-counter or write-counter handling at all — the DA stub manages
  the eMMC write counter per write and returns JEDEC result codes (1 = counter
  failure, `v6.py:31`) on mismatch. Host code just checks the per-sector result.
* Caching: `custom_rpmb_init()` is re-run before every `w`/`e` (no state kept between
  commands). The only RPMB-related persistence is from `generatekeys`:
  `v6.py:1545/1609/1613/1681` `config.hwparam.writesetting("rpmbkey"|"mirpmbkey"|
  "rpmb2key", hex)` into `hwparam.json` — those are SEJ/DXCC-*derived* keys, never
  read back by the RPMB write path. Remember the session-log caveat: a stale
  `.state`/`hwparam.json` in the CWD makes `DaHandler.connect()` skip the DA upload —
  delete it before every device attempt.

## 6. Block addressing & the LK boot-info mirror

* Addressing: `--sector` is in units of **256 bytes** (RPMB data sector) — CLI help
  "offset/0x100 bytes" (`mtk.py:285`); `CUSTOMRPMBR/W` take `sector` as a u32
  sector index; each read/write unit is 0x100 bytes of data. Sector 0 = byte offset 0
  of the RPMB region.
* The LK boot-info mirror is a **0x400-byte** structure read/written in one call
  whose first argument is the **RPMB block address `0x1DC`** (JEDEC frame field
  `frame+0x1F8`), with 4 blocks (`frame+0x1FE` = request type). It therefore lives
  at RPMB **blocks 0x1DC–0x1DF** = byte offset **0x1DC00–0x1DFFF**, NOT at 0.
  (Corrected 2026-10-24: `0x1DC` was previously mis-read as a TEE op id. Proof:
  `rpmb_read_direct` 0x5002FD14 stores `rev(w0)>>16` at `[sp,#0x228]` with frame
  base `sp+0x30`; the TEE path 0x5003E4E4 does the same at 0x5003E5C4.)
  Block fields: +0x4 sbc, **+0x8 last_bootmode**, **+0xC locked bit (1=locked)**,
  +0x10 aux, plain SHA-256 over [0x0,0x3E0) stored at +0x3E0
  (`re-lk-rpmb-lock.md` §4; field map corrected there).
  On the host: `da rpmb r --sector 0x1DC --sectors 4` captures the mirror
  (if the DA RPMB path worked on UFS at all — it does not, see §7a).

## 7. Device runbook (RMX3630, DA2 after heapbait + OPLUS table-unlock patches)

Prereqs (from session log): fresh CWD (no `.state`, no `hwparam.json`), DA2 running,
`g_oplus_auth_status` forced to ≤2 (full table), security policy neutralized,
`get_hw_sbc` force-returned. Use the Python API, not the CLI, to avoid the hex-string
bug (§2):

```python
from mtkclient.Library.mtk_da_handler import DaHandler
# standard connect (see examples/load_config.py pattern) → mtk, config
dl = mtk.daloader                      # xmlft path active on DA2
xmlft = dl.xmlft                       # XmlFlashExt instance (v6.py)

# (a) Key status — two options
#  a1. JEDEC probe: authenticated read of block 0; result code 6 = not programmed
data = xmlft.custom_rpmb_read(sector=0, sectors=4)   # b"" on error; inspect last resp via log
#  a2. EMMC-CONTROL query (unwired; needs a small helper, no source change):
xmlft.xflash.send_command(
    xmlft.xflash.cmd.cmd_emmc_control(function="GET-RPMB-KEY-STATUS"), noack=True)
# parse like xml_lib.py:1583 check_lifecycle (UpFile → download → END/START ack)

# (b) Attempt authenticated read with a host key (e.g. dumped or SEJ-derived)
dl.auth_rpmb(bytes.fromhex("<32-byte hex key>"))     # CUSTOMRPMBK + CUSTOMRPMBI
data = xmlft.custom_rpmb_read(sector=0, sectors=4)
open("rpmb_mirror.bin","wb").write(data)             # check field +0xC

# (c) If unprovisioned: program our key, then set it and write
xmlft.custom_rpmb_prog(bytes.fromhex("<key>"))       # CUSTOMRPMBP; 0=ok, 1=already set
dl.auth_rpmb(bytes.fromhex("<key>"))

# Mirror rewrite (once +0xC==1 must be cleared):
buf = bytearray(open("rpmb_mirror.bin","rb").read()) # 0x400
buf[0xC:0x10] = b"\x00"*4                            # unlocked
buf[0x3E0:0x400] = hashlib.sha256(buf[:0x3E0]).digest()
open("rpmb_new.bin","wb").write(buf)
dl.write_rpmb("rpmb_new.bin", sector=0, sectors=4)   # runs custom_rpmb_init() first
```

Failure interpretation: per-sector result 1 = auth failure (wrong key / already
provisioned with factory key), 2 = counter failure, 3 = address failure,
6 = key not yet programmed → go to (c).

## 8. Audit verdicts

1. `da rpmb r/w/e/a` fully implemented for DA2 via runtime-patched stub; commands
   `CUSTOMRPMBR/W/K/I/P`.
2. `auth_rpmb` sends the raw 32-byte key after `CUSTOMRPMBK`; CLI hex-string pass-through
   is a live bug — use the API with `bytes.fromhex`.
3. No `GET-RPMB-KEY-STATUS` caller; `cmd_emmc_control` (`xml_cmd.py:408`) already
   produces the right XML shape — one-line helper needed.
4. HMAC is DA-internal; host supplies the key. A dumped key is immediately usable
   via `auth_rpmb` + `write_rpmb`.
5. Counters handled wholly in DA; only `hwparam.json` rpmbkey writes exist (never
   re-read), and `.state` must be cleared per session.
6. Boot-info mirror = RPMB sectors 0–3 (0x400 B at offset 0); sector unit = 256 B.
   The single hard blocker remains possession (or first-programming) of the eMMC
   RPMB auth key.
