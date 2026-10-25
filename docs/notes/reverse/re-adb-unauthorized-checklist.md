# RE: `adb unauthorized` on RMX3630 — ordered diagnostic checklist

Date: 2026-10-25. Scope: after boot v6 is flashed. Host = rooted Android + OTG
(Termux), target = RMX3630 (MT6789, Android 12, dead screen).
**Read-only:** every check is a read; nothing here writes, flashes or reboots.

Run `bash docs/notes/verify_adb_state.sh --live -v` first — it executes checks
2–9 and prints the verdict block. This file is the manual fallback and the
"what does the value mean" decoder.

Decision tree, 4 lines:

```
check 2 says `device`      -> auth passed, go to 3
check 4 = 1                -> Q2: our init ran, property gate rejects ro.adb.secure
check 4 = 0                -> Q1: our init never ran, vendor_boot init wins
no authorized shell at all -> checks 1, 8 only (offline branch)
```

---

## 0. The boot ritual (must precede every check)

```
1) unplug cable            4) wait 90 s, cable still out
2) Power ~10 s (off)       5) plug cable -> checks 1-2
3) Power ~3 s (cable out)
```

Skipping the 90 s leaves the target in the preloader/DA path and it never
reaches Android, which looks identical to "adb broken" in a 10-second test.

---

## 1. Did the target reach Android at all?

```sh
watch -n 2 'lsusb | grep -i 22d9'
```

* **want:** `22d9:2769` (Android, ADB interface `ff/42/01`) within ~90 s of the cable.
* **kill signal:** `22d9:0006` = preloader/VCOM, i.e. the target aborted boot.
  Re-do ritual 0; do not debug adb until `2769` appears.
* proves: boot v6 did not brick the boot chain (AVB/ramdisk slot still valid).

## 2. Is the ADB transport authorized?

```sh
adb devices -l
```

* **want:** `<serial>  device  usb:... product:ossi model:RMX3630 ...`
* **discriminator:** `unauthorized` = adbd up, `ro.adb.secure=1` path active;
  `offline` = adbd died mid-handshake (check 9); empty list = check 1.
* proves: whether anything below is reachable at all.

## 3. Is the auth gate actually open?

```sh
adb shell getprop ro.adb.secure
```

* **want:** `0`
* **discriminator:** `1` = the property never changed, the original failure.
  `0` here but `unauthorized` in check 2 = stale host key, not our bug
  (`adb kill-server; adb devices`).
* proves: whether the v6 property patch took effect.

## 4. Q1 vs Q2 — did our patched init run? (primary discriminator)

```sh
adb shell getprop ro.debuggable
```

* **want (Q2):** `1` — forced-debuggable executed, i.e. the patched
  boot-ramdisk `init` is the one running; only the per-property gate still
  rejects `ro.adb.secure` (build_prop context).
* **want (Q1):** `0` — the patch is inert; `vendor_boot`'s `init` (or its
  overlay) won, so nothing we put in the boot ramdisk is read.
* proves: which of the two hypotheses to spend the next day on.

## 5. Confirm which `init` is executing

```sh
adb shell ls -l /init
```

* **want (Q2):** size `3143536` — the boot-ramdisk init we patched at
  `VA 0x2F6D14`.
* **discriminator:** any other size = a different init (vendor_boot / system
  build) is first stage -> Q1.
* proves: identity of the running first stage, independent of check 4.

## 6. Was `adb_debug.prop` read but gated? (Q2 proof)

```sh
adb shell 'getprop | grep -iE "adb|debuggable"'
```

* **want (Q2):** both `[ro.debuggable]: [1]` and `[ro.adb.secure]: [1]` — the
  file was parsed, but the `ro.adb.secure` line was dropped by the property
  service (SELinux `build_prop`, not readable by the loading context).
* **discriminator:** neither key present / `ro.debuggable=0` = file never read
  (Q1), not a per-property rejection.
* proves: that the failure is a property-context rejection, not a missing file.

## 7. What context does the gate assign to the key?

```sh
adb shell grep -n 'ro\.adb\.secure' /system/etc/selinux/plat_property_contexts
```

* **want:** `ro.adb.secure u:object_r:build_prop:s0 exact bool`
* **discriminator:** `build_prop` (expected) = only `init` first stage can
  write it; a `vendor_*`/`default_prop` context instead would mean the block is
  elsewhere and Q2 needs re-scoping.
* proves: the concrete rule that rejects our value; needs root.

## 8. Q1 offline branch — is there an `init` in vendor_boot?

```sh
python3 docs/notes/vendor_boot_extract.py --list --in IMAGES/vendor_boot.img | grep -w init
```

* **want (Q1 live):** an `init` entry in the vendor ramdisk -> it can shadow
  the boot one; move `/force_debuggable` + `/adb_debug.prop` (and the
  `0x2F6D14` patch equivalent) there for v7.
* **discriminator:** no output = vendor_boot carries no `init`; Q1 is dead and
  the whole budget goes to Q2 (check 7).
* proves: the Q1 hypothesis without needing a shell on the target.
* note: the extractor is task A's artifact; if it is absent, stop here and
  report `BLOCKED` instead of hand-rolling a parser.

## 9. Q3 — is adbd coming from the updatable APEX?

```sh
adb shell 'readlink -f /proc/$(pidof adbd)/exe'
```

* **want:** `/apex/com.google.android.adbd/bin/adbd` (or
  `/apex/com.google.android.adbd@*/bin/adbd`) -> adbd is the signed APEX
  payload; swapping it needs an APEX signature bypass, so Q3 is a dead end on
  a user build (`ro.apex.updatable=1` does not help without the key).
* **discriminator:** `/system/bin/adbd` = legacy in-system adbd, Q3 becomes
  viable via a plain system patch.
* proves: whether the last-resort route is worth any effort at all.

---

## Reading the result

| checks | picture | next action |
|---|---|---|
| 2=`device`, 3=`0`, id `uid=0` | done | run `scrcpy`; campaign closed |
| 4=`1`, 6 both keys, 7 `build_prop` | Q2 | patch the gate at `0x2D81A0` / plant the key from a context that passes |
| 4=`0`, 5 size != 3143536, 8 finds `init` | Q1 | v7: marker files + init patch inside vendor_boot |
| 2=`offline` | transport | `adb kill-server`, re-plug, check 1; adbd likely crashed (see 9) |
| no `device` and no shell | blind | only 1 and 8 are usable; dump vendor_boot via DA |

Do **not** use `setenforce 0` on the target as a "fix": it does not touch
`ro.adb.secure`, and it hides which check failed.
