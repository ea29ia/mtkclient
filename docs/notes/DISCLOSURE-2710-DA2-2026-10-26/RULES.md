# RULES — hard constraints for whoever sends/executes this disclosure

These constraints are absolute. They exist because the underlying vulnerability has a
**permanently destructive variant** (real efuse writes) in addition to its reversible
variants, and because this research was performed entirely in emulation on a device we
do not own.

## 1. No efuse writes on real devices — EVER

* Every result in this package comes from Unicorn emulation of the real DA2 binary.
  Nothing in this research has written, or may ever write, a real efuse word
  (`0x11C10000–0x11C12000`) on hardware.
* Efuse bits are one-way (0→1). A single wrong write (SBC word `0x11C10060`, lock
  words, public-key-hash words) permanently destroys the device's secure boot.
  There is no recovery, no test, no "harmless variant" of this on silicon.
* When demonstrating anything to a vendor, use the emulation harness
  (`docs/notes/da2_2710_efuse_chain.py`, `da2_2710_efuse_flash.py`) or the vendor's
  own lab devices. Do not offer device-side demonstrations.

## 2. No device work in this campaign

* The disclosure is documentation-only. Do not connect the RMX3630 (or any MT6789
  device) to run, validate, or film the vulnerability for the report. The emulation
  evidence (write logs, model diffs, the DA's own log lines) is sufficient and
  reproducible for the vendor.

## 3. No disclosure before the vendor acknowledgement window

* Follow `TIMELINE.md`. Do not publish the advisory, post new exploit detail on
  mtkclient #409, or share the PoC outside the coordinated set before Day 90 —
  unless a third party publishes first (then collapse the timeline per TIMELINE.md).
* Exception allowed earlier, per TIMELINE.md: the tool-side DEFENSIVE guidance for
  mtkclient (do-not-implement WRITE-EFUSE) may be published after vendor
  acknowledgement (~Day 14+), since it is protective, not offensive.

## 4. Coordinate with the other finder — mandatory, before sending

* alexander-dev2313123 independently found and audited this DA2 build and supplied it
  to the community thread. He must see and agree to the final report text before it
  goes to any vendor. Joint credit is proposed in SUMMARY.md; do not send a
  single-credit version.

## 5. Do not publish PoC blobs that brick

* The reversible PoC (the single `<option address="0x40054C88">5</option>` forge) is
  already committed in the notes and is RAM-only, reversible, and documented as such —
  it may be published with the advisory after the window.
* Do NOT publish, attach, or otherwise distribute a runnable payload that writes any
  address inside `0x11C10000–0x11C12000` (except the two controller control registers
  the engine always touches: `0x11C10000`, `0x11C10008`). The advisory describes the
  mechanism and the guard bypass in prose; it does not ship a bricking payload.
* Likewise: no watchdog/RGU-targeting payloads (`0x10007000`-class).

## 6. No GitHub issues / public posts as part of THIS disclosure

* Disclosure goes to the vendor contacts in CONTACTS.md only (email/portal).
* Do not open a new GitHub issue for the vulnerability, do not post the advisory to
  social media or mailing lists, and do not email anyone outside the contact list
  before the window closes. The mtkclient #409 thread stays frozen at its current
  detail level during the window.

## 7. Accuracy and traceability

* Every claim sent to a vendor must trace to a committed note
  (`docs/notes/reverse/…`) or an executed emulator run. If a vendor asks something we
  have not tested (silicon behaviour, sub-driver protections, seccfg regeneration),
  answer "not tested — emulation only" (ADVISORY.md §7/§8 lists these explicitly).
  Never extrapolate emulation results into silicon claims.

## 8. Legal/ethical boundaries

* This research targets our own/legitimately-held analysis artifacts and publicly
  distributed firmware blobs; the emulated PoC never touched a live device.
* The report must NOT include instructions for abusing the forge against devices the
  sender does not own (e.g. no "how to unlock a locked phone with this" framing).
  The framing is: a defense-in-depth failure in a signed-session-gated debug path,
  with irreversible-impact potential.
* If any vendor responds with legal threats instead of triage, stop, do not engage
  further without counsel, and keep the record in this directory.
