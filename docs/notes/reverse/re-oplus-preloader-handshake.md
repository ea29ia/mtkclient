# RE: "OPLUS preloader auth" = oplus_usb_handshake — token dispatcher of AT-commands (RMX3630 / MT6789)

Date: 2026-10-24. Tool: radare2 (`r2 -m 0x200f10 -a arm -b 16`), `strings -t x`.
Target: `IMAGES/preloader_k6789v1_64.bin` (same binary as in `re-preloader-daa-lk.md`;
VA = file offset + 0x200F10 — proven there, reused here).
Context: commercial tools (UnlockTool, profile "Oppo Realme V3", button
[PRELOADER] UNLOCK BOOTLOADER) advertise an "OPLUS preloader auth" step. This note
identifies what that actually is in the preloader binary — and what it is not.

Related notes: `re-preloader-daa-lk.md` (DAA mechanics, err 0x7024, VA base),
`re-oplus-auth-paths.md` (DA2 `g_oplus_auth_status` layer — a *different* layer,
do not confuse: that one lives in the DA2, this one lives in the preloader).

## TL;DR

The "preloader auth" used by commercial tools (UnlockTool, profile
"Oppo Realme V3", button [PRELOADER] UNLOCK BOOTLOADER) is implemented in the
preloader as **`oplus_usb_handshake`** — a **token dispatcher of AT-commands** with
hardcoded obfuscated tokens (plain string comparison, no asymmetric crypto).
Asymmetric crypto in the preloader exists **only** in the DAA path (`sec_auth.c`,
error 0x7024 — see `re-preloader-daa-lk.md`) and in cert-chain verification of
boot images. Our path (mtkclient via usbdl → DA) does **not** require the
handshake — it gates **boot-mode selection**, not the download agent.

## 1. String evidence (all proven, `strings -t x`)

| file offset | VA | string | meaning |
|---|---|---|---|
| 0x52814 | 0x253724 | `oplus_usb_handshake` | function name (log tag) |
| 0x4b470 | 0x24C380 | `Oplus USB handshake` | log title |
| 0x4b437 | 0x24C347 | `USB handshake ok` | success print |
| 0x4b3ef | 0x24C2FF | `Tool connection is unlocked` | outcome branch |
| 0x4b40f | 0x24C31F | `In fast meta, bypass usb handshake.` | bypass branch |
| 0x527b0 | — | `nMagicNum1:0x%x, nMagicNum2:0x%x, nPlUsbEnumEnabled:%d, nUsbAutoSwitch:%d, rpmb_en:%d, rpmb_key:%d` | boot-params gate print (same struct as re-preloader-daa-lk.md §Q3.1) |
| 0x52772 | — | `enter_preloader_by_force_download_key` | key-driven entry |
| 0x52753 | — | `enter_preloader_by_vol_up_down` | button-combo entry |
| 0x52700 | — | `enter_bootrom_by_vol_up_down` | bootrom button entry |

The last three confirm the button-combo entry paths exist as functions (see §4d).

## 2. Dispatcher map (VA 0x228C60–0x228EF2 — proven span)

The dispatcher performs string comparisons against tokens; the tokens are stored
in the binary **reversed/obfuscated** (read them right-to-left):

| token (VA) | de-obfuscated | effect | provenance |
|---|---|---|---|
| 0x24C17B | `AT+` | command prefix | proven |
| 0x24C199 | `METAMETA` | boot mode 1/5 (META) | proven |
| 0x24C20A | `FACTFACT` | FACTORY, boot mode 4 | proven |
| 0x24C21C | `ADVEMETA` | ADV META, boot mode 5 | proven |
| 0x24C240 | `FASTBOOT` | → `0x2F4264 = 0x63`; response `TOOBTSAF`; **not gated** by forbidden bit | proven (0x228D40, 0x228F6E) |
| 0x24C17F | `AT+NBOOT` | response `AT+OK` (0x24C188); `0x2F4264 ← 0`, `0x2F4260 ← 5`; **not gated** | proven (0x228D5E, 0x228EBA–0x228EF0) |
| 0x24C199 | `METAMETA` | dialog "ATEM0001"/"ATEM0002": read 12 B (timeout 5000 ms) → `*0x2F4244 = meta_com_id`; read 16 B → `md_type[0..1]` → `*(0x2F3160)+0x81998`; byte `0x2F4248 = meta_log_disable` | proven (0x228CB0–0x228E68) |
| 0x24C20A | `FACTFACT` | read 5 B (timeout 5) → `*0x2F4244`; response `TCAFTCAF` (0x24C213) | proven |
| 0x24C21C | `ADVEMETA` | helper 0x228FF4 (send 10 B, timeout 0x3E8, "DISCONNECT" check); response `ATEMEVDX` (0x24C225) | proven |
| 0x24C22E | `FACTORYM` | read 5 B → `*0x2F4244`; response `MYROTCAF` (0x24C237) | proven |

Boot-mode sinks (proven write sites): **0x2F4264** ← boot mode (0 = NBOOT ack, 4 =
FACTORY @0x228EB6, 5 = ADV/ATE META @0x228EEE, 6 = FACTORYM @0x228F30, 0x63 =
FASTBOOT @0x228F6E); **0x2F4260** ← 5 (NBOOT branch); **0x2F4244** ← meta_com_id /
mode payload; **0x2F4248** ← meta_log_disable byte. `0x2F4240` ← 1/2 set in main
after `bl 0x231594` (0x228858/0x22885E).

Outcome strings binding (proven, TBB table @0x2287AC keyed by seclib
`brom_meta_mode` r4): 1 → `%s BR META BOOT`; 4 → `%s BR FACTORY BOOT`; 5 →
`%s BR ADVMETA BOOT`; 6 → `%s BR ATE FACTORY BOOT`; {2,3,>6} → `%s UNKNOWN MODE`;
0 → normal path (proven: 0x2287F0/0x228826/0x228834/0x228842/0x22881A).

## 3. What the handshake is NOT

* **No asymmetric crypto** in the dispatcher: comparisons are plain
  `memcmp`-style string matches against hardcoded (obfuscated) tokens. No RSA,
  no signature, no challenge-response found in the 0x228C60–0x228EF2 span.
* **Not the DA2 auth layer.** The RSA-2048 SEC-POLICY machinery (`g_oplus_auth_status`)
  lives in `da2_oplus.bin` — see `re-oplus-auth-paths.md`. Different binary, different layer.
* **Not the DAA gate.** DAA (sig verify of the download agent, err 0x7024) is a
  separate path (`sec_auth.c`, `usbdl vfy da`) — see `re-preloader-daa-lk.md` Q1.
* It gates **boot-mode selection** (META/FACTORY/ADV/ATE/fastboot), not the
  download-agent entry.

## 4. Campaign implications

a) UnlockTool "PRELOADER Auth" = **the token profile + their signed DA_BR for
DAA** (not a server-side authorization inside the preloader). *Inferred, high
confidence.*

b) The mtkclient path (VCOM → usbdl → DA) does **not** pass through the
handshake — it gates boot-mode, not download. **Call order in `main()` is now
proven** (0x228756 register dispatcher ctx → 0x228764
`enter_preloader_by_vol_up_down` → 0x228782 `brom_meta_mode` + security bit →
BR-mode TBB switch → 0x228ACA `bl 0x23913C` (oplus_usb_handshake, sync byte
0xA0 via 0x2257EC, timeouts 8/10 s) → on success 0x228864 `blx sb` =
**bldr_handshake** = MTK download protocol; on failure "reboot again when do
not plug usb cable", 5000 ms delay, reboot). Handshake listens **before** the
usbdl/download entry — proven by this order.

c) **Plan E (new, deprioritized):** send the tokens (`METAMETA`/`FACTFACT`)
over the preloader VCOM to enter FACTORY/META mode as an alternative rescue
channel. Protocol skeleton now proven: sync byte 0xA0, then ASCII token,
dispatcher matches with `strlen`+`strncmp`; timeout 5000 ms on the follow-up
read. **Gating (proven):** all META/FACTORY/ADVEMETA/FACTORYM branches check
`ctx+4 bit0` (`lsls r0,r5,0x1f; bne 0x228F34` → "%s '%s' is forbidden!",
return 0); the bit is set from **seclib security register bit 3 of [0x11C1C160]**
(`bl 0x24497A` in main @0x228788) or from the oplus_custom block when
`(val & 0xE) == 0xA` (0x2391AE–0x2391B4). **FASTBOOT and AT+NBOOT branches are
NOT gated** — on a security-locked unit only they pass. brom_meta_mode values
1 and 0x64 skip the handshake entirely (0x2287DA–0x2287E6).
Risk: `img_auth_required` under SBC may cut factory boot downstream
(cf. re-preloader-daa-lk.md Q2); what consumes 0x2F4264 downstream (boot-args
to LK?) — inferred, TBD при живой сессии.

d) Vol Up + Vol Down + Power combo on a powered-off device is **confirmed by the existence**
of `enter_preloader_by_vol_up_down` (called from main @0x228764 — proven) /
`enter_bootrom_by_vol_up_down` (*proven* that the functions exist; exact key
semantics — inference from names).

## 5. Uncertainty notes

* Downstream consumers of 0x2F4264/0x2F4260 (how the boot mode reaches LK /
  whether LK honors factory mode under SBC) — inferred, TBD при живой сессии.
* Exact semantics of seclib bit 3 @0x11C1C160 (SBC state vs DAA state) — inferred.
* USB packet framing beyond the 0xA0 sync byte (chunking of 8-byte reads,
  checksums, if any) — not decoded; timeouts 8000/10000 ms proven in 0x2257EC.
* rpmb_en/rpmb_key fields of the oplus_custom block: printed in logs only
  (0x239186); role in handshake — none observed.

## Evidence index

* Strings and file offsets: `strings -t x` output — proven.
* VA mapping: file + 0x200F10 (established in re-preloader-daa-lk.md) — proven.
* Dispatcher span 0x228C60–0x228EF2, token VAs, sink globals: r2 disasm —
  proven as read of instructions; token→global binding — partial/inferred.
* "No crypto in handshake": absence-of-evidence argument over the dispatcher
  span — high-confidence inference.
