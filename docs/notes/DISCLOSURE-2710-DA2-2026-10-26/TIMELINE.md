# TIMELINE — suggested disclosure schedule (90-day coordinated model)

Reference date: **Day 0 = the day the report is actually emailed** (nothing is sent
today; this file only fixes the cadence). MediaTek's published policy targets
resolution/communication within 90 days — our cadence mirrors that and defers to
their bulletin cycle.

## Cadence

| day | action |
|---|---|
| −14 … −1 | Coordinate with alexander-dev2313123 (CONTACTS.md §4): agree report date, joint credit, master-copy ownership. Final read-through of ADVISORY.md by both parties. |
| 0 | Send the report **in parallel** to MediaTek `security@mediatek.com` (PGP-encrypted) and OPPO OSRC `security@oppo.com` (PGP-encrypted / portal). Attach: SUMMARY.md, ADVISORY.md, the byte-exact PoC XML, and pointer to the reproduction scripts. Do NOT attach bricking-capable efuse-write variants as runnable material (RULES.md). |
| ~3 | Ack check. If no acknowledgement from a vendor, one polite follow-up per week, logged. |
| 14 | Status ping #1 to both vendors (expect triage feedback / CVE discussion; request a CVE ID from MITRE if neither vendor claims CNA scope). |
| 30 | Status ping #2. Offer the emulation harness details under NDA-style private terms if the vendor requests reproduction support. |
| 45 | Begin drafting the publication version of our notes (what we will publish on our side, below). |
| 60 | Status ping #3. If a fix ships in a beta/OTA, verify it (in emulation only — RULES.md) and confirm the fix closes the debug-XML path. |
| 90 | **Publication window opens** (whichever comes first: vendor fix shipped, or 90 days elapsed without a fix). Publish our side (see below). |
| 90+ | If vendors request extension with credible reasons (OTA cadence), one extension of up to 30 days maximum, then publish regardless. |

## What we publish on our side, and when

| material | before Day 90 | at/after Day 90 |
|---|---|---|
| The reverse-engineering note set (`docs/notes/reverse/re-da2-2710-*.md`) | stays in our private repo only (already committed to the private branch) | publish as-is |
| The PoC chain script `da2_2710_efuse_chain.py` (emulation-only, reversible-RAM chain) | private | publish with the notes (it contains no bricking material; the efuse-word option is documented but the script's safety comments and the chain never target the efuse window) |
| The storage-layer script `da2_2710_efuse_flash.py` | private | publish |
| The mtkclient-side mitigation (do-not-implement WRITE-EFUSE; READ-EFUSE info-only) | after vendor ack (~Day 14+, tool-side guidance is defensive, may go earlier) | as part of the mtkclient docs |
| The advisory text | private | publish on the repo + request/quote the CVE ID |
| Working bricking-capable efuse-write material | **never** (see RULES.md — we do not publish blobs that brick; the advisory describes the mechanism and the guard bypass without a runnable efuse-blow payload beyond what the committed audit notes already contain) | never |

## Public-thread policy during the window

* mtkclient issue #409 already contains earlier, partial analysis (commands,
  corrections). During the disclosure window: do not post NEW exploit detail beyond
  what is already public there; answer triage questions from the vendors privately.
* If a third party independently publishes first, collapse the timeline: publish our
  advisory immediately with credit, and notify both vendors the same day.

## Record-keeping

Keep in this directory (append-only): copies of every email sent (with dates),
vendor replies, the final published advisory. The disclosure package must remain
internally consistent with the committed notes it cites.
