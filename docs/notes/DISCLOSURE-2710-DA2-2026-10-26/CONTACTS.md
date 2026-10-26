# CONTACTS — where to report the 2710EX01 DA2 WRITE-EFUSE issue

Prepared 2026-10-26. Addresses verified against public vendor pages on this date
(MediaTek page fetched directly; OPPO/OSRC confirmed via OSRC's own public channels
and the OPPO bug-bounty pages). Nothing has been sent from this package yet.

## 1. MediaTek PSIRT (chip vendor — the DA2 is MediaTek code with OPLUS branding)

* **Email: `security@mediatek.com`** — VERIFIED 2026-10-26 from
  <https://www.mediatek.com/security-contact> ("Report Vulnerability"):
  > Please send the security report to: security@mediatek.com
* Their published policy (relevant to our timeline):
  - aims to address and communicate within **90 days**;
  - CVSS v3.1 severity ratings; PGP key available for encrypted submission;
  - reports need: affected product(s)/version(s), vulnerability overview, issue
    description and impact, **root-cause analysis**, a **functional PoC**,
    reproduction steps, and reproduction evidence — reports without a functional PoC
    "may not be processed" (our ADVISORY.md is structured to satisfy this);
  - anonymous submission allowed; attribution in security bulletins optional;
  - private (invite-only) HackerOne program for researchers with a track record of
    high-quality reports to security@mediatek.com.
* Why MediaTek first: the vulnerable handlers (`0x40005C20`, `0x40031A18`,
  `0x4003184A`) are MediaTek DA framework code; the same XML DA framework ships
  across vendors, so a MediaTek-side fix fixes the class.

## 2. OPPO / OSRC (device vendor — OPLUS branding, signed policy, ship decision)

* **Email: `security@oppo.com`** — VERIFIED 2026-10-26 from OPPO Security (OSRC)
  public channels (OSRC's own posts direct urgent matters to security@oppo.com; the
  CVE-application service also names security@oppo.com).
* Web portal: <https://security.oppo.com/en/report> (OPPO Security Center; supports
  submission via their HackerOne Bug Bounty Program `oppo_bbp` or email; PGP key
  published for email submissions).
* Responsible-disclosure terms: <https://security.oppo.com/en/responsibleDisclosure>
  (standard: reasonable time before publication, no exploitation of reported issues).
* Why OPPO: the affected DA2 ships inside realme RMX3630 firmware; the signed-policy
  session ladder and the OPLUS policy key are OPPO-side; the ship/remediation decision
  for affected devices is theirs.

## 3. realme (brand owner of the affected device)

* Security center / responsible disclosure:
  <https://privacy.realme.com/global/security> ("Security and Privacy" →
  "Responsible Disclosure"). The RMX3630 (realme 10 4G) appears in realme's
  90-day security-update program listing on that page.
* Direct security email: **commonly cited as `security@realme.com` but NOT verified
  from the fetched page content (the page is device-list-heavy and the address was
  not visible in the retrieved text) — MARK FOR LOOKUP** by whoever sends the
  report: confirm the submission address on the realme Security Center page (or
  submit through the form) before relying on it. In practice the OPPO/OSRC channel
  covers realme devices (same OPLUS software stack), so OPPO OSRC is the primary
  device-vendor contact and realme is a courtesy copy.

## 4. Coordination with the independent finder — REQUIRED before sending

* **alexander-dev2313123** — independent finder of the 2710EX01 DA2 audit. He supplied
  the 2710 `DA_BR.bin` build to the mtkclient community thread, ran his own audit, and
  published `EFUSE_2710_AUDIT.md` on his repo (post-merge erratum at commit `ca3c7f2`),
  which agrees with our correction that the debug-XML path bypasses the binary-branch
  guards and additionally notes the `g_oplus_auth_status=5` forge.
* Coordinate BEFORE any vendor submission: agree on the report date, the joint credit
  wording (see SUMMARY.md credit proposal), and who holds the master copy of the
  advisory. Do not send a version he has not seen.
* His analysis and ours are complementary: his = audit of the blob and on-device
  observations; ours = the full chain proof + storage-layer study, all in emulation.

## 5. Community channels already involved (FYI in the report, not recipients)

* **bkerler/mtkclient issue #409** — the public thread where the 2710EX01 DA2 was
  circulated and where our earlier analysis comments already exist (e.g. comments
  `6414049606`, correction `6414467746`, DA1-swap corrections `6410927123`/
  `6411816675`). The disclosure report should reference that the analysis lineage is
  already partially public there.
* **Penumbra (shomykohai)** — the penumbra project documents the XML DA protocol and
  related MTK DA techniques; their docs were used as a protocol reference
  (`re-penumbra-survey-2026-10-26.md`). Not a recipient; context only.
* **mtkclient maintainers/community** — the mitigation note for the tool side
  ("do not implement CMD:WRITE-EFUSE against this DA family") belongs in the mtkclient
  repository docs, not in a public issue, until the vendor window closes.

## 6. What NOT to do with these contacts

See `RULES.md`. Short version: no emails are sent by this package; the sender must be
a human who has read `RULES.md` and coordinated with alexander-dev2313123 first.
