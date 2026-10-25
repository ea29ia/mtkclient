# ROOT achieved on RMX3630 (Android 14): `adb root` → uid 0

Date: 2026-10-25. Build `RMX3630_14.0.0.420(EX01)`, kernel `5.10.209-android12-9-o-05206-g23c1467af8f7`.
Bootloader unlocked in the Oplus sense (`seccfg lock_state=3`, `ro.boot.verifiedbootstate=orange`);
LK does **not** verify the boot image (`img_auth_required=0`, `avb_ret=0`).
corrected: an earlier draft said only "unlocked (`verifiedbootstate=orange`, `flash.locked=0`)" — the
authoritative markers are `seccfg lock_state=3` plus `ro.boot.verifiedbootstate=orange`, and the reason
it works is that LK does not authenticate `boot`/`vendor_boot`.

## What worked (31 bytes appended to the header cmdline)

`adb root` used to die on sepolicy:

```
avc: denied { setcurrent } for scontext=u:r:adbd:s0 tcontext=u:r:adbd:s0 tclass=process permissive=0
```

Fix: append `" androidboot.selinux=permissive"` to the **vendor_boot v4 header** cmdline field
(offset 0x1C) — file bytes `0x44..0x62`, 31 bytes, NUL-terminated.

Chain (verified by disassembly and on the device):

1. LK `load_bootinfo_from_hdr` @`0x50009FE8` copies the header, `boot_linux_from_storage`
   appends `get_vendor_boot_cmdline` (`0x5000A3A0`) via `cmdline_append` (`0x50018204`) —
   **without filtering** `androidboot.*`;
2. LK builds the bootconfig itself (`bootconfig_build` @`0x5000B46C`, call @`0x5000D5F4`) and puts
   it at the tail of the initrd; the `bootconfig` section inside the image itself is **not** read
   by LK (dead data);
3. system-init `SelinuxInitialize` (`0x174C54..0x174D48`) sees `androidboot.selinux` == `permissive`
   (`0x21E11` / `0x1F2AD`) and calls `security_setenforce(0)`;
4. permissive lifts the `process:setcurrent` check, so adbd (APEX, `--root_seclabel=u:r:su:s0`)
   can switch to `u:r:su:s0` → `adb root` yields uid 0.

Note: the vendor-ramdisk first-stage init (`vinit`) does **not** read `androidboot.selinux` —
the mode is set by system-init (`init second_stage`).

## Images

```
/home/musin/vendor_boot_v18_selinux.img   md5 1d6a665a8422cffc4e3a56bfd2950079
diff vs vendor_boot_v14.img (ad5c09b9…): 31 bytes, 0x44..0x62; ramdisk/dtb/table untouched

/home/musin/vendor_boot_v19_root.img      md5 93d4cbb183752c47f571928d80aadd76   <- adb-root image
= v18 + `service.adb.root=1` in adb_debug.prop (ramdisk repacked, cmdline/dtb preserved)
```

All images are 64 MiB `VNDRBOOT` v4 and are flashed with fastbootd
(`fastboot flash vendor_boot_a`).

| image | md5 | what |
|---|---|---|
| `vendor_boot_v14.img` | `ad5c09b9e75b6cc5daa137e875b1a98d` | props + self-bind cave; adb authorised, **no root** |
| `vendor_boot_v18_selinux.img` | `1d6a665a8422cffc4e3a56bfd2950079` | v14 + 31 bytes appended to the header cmdline (` androidboot.selinux=permissive`, offsets `0x44..0x62`); SELinux boots permissive |
| `vendor_boot_v19_root.img` | `93d4cbb183752c47f571928d80aadd76` | v18 + `service.adb.root=1` in `adb_debug.prop` (81 → 100 B) ⇒ persistent adb root, `uid=0`, `u:r:su:s0`, without `adb root` |
| `vendor_boot_v22_magisk.img` | `a874a5c217d2e42aa7813a151bbd78be` | **CURRENT image**: v19 + Magisk (see below) |
| `vendor_boot_v20_magisk.img` | `02d4e1f76e486fb95b20b1bc2eea0a03` | earlier Magisk image; it **booted** but adb stayed unauthorised |
| `vendor_boot_magisk.img` | `14f93d33f7888641f1e0f4c1cad4f2a9` | first Magisk experiment (v14 + Magisk): booted, props lost, adb unauthorised |
| `vendor_boot_v17a.img` | `6704ba8a1f3af10f541bb19d965fe1f3` | clone-only cave; **never flashed** |
| `vendor_boot_v17.img` | `4c30b1c36e45c627c7e20f671ef0c676` | **CORRUPT image** (vendor_ramdisk_table = 108 zero bytes, dtb truncated at `0x106C` of `0x2EC59`) — see `re-vendor-boot-v17-bootloop-2026-10-25.md` |

Stock `vendor_boot_a` dump: `/home/musin/slot_vendor_boot_a.img`,
sha256 `5c2277bd6b42e72f3a376f8c27c2065e2364c4c9e463521736ff6aac892813c7`.
corrected: `vendor_boot_v19_root.img` was earlier labelled "flash this one"; the current image is
`vendor_boot_v22_magisk.img`. Any mention of `dbcefcac…` as "v17" is wrong — the v17 file on disk is
`4c30b1c3…`.

## Device check

```
getenforce                  -> Permissive
getprop ro.boot.selinux     -> permissive
cat /proc/bootconfig        -> androidboot.selinux = "permissive"
adb shell id (before adb root) -> uid=2000(shell)
adb root; adb shell id      -> uid=0(root) gid=0(root) ... context=u:r:su:s0
ps -A | grep adbd           -> root
mount | grep ' /data '      -> f2fs rw (file write tested)
```

## Limitations and consequences

* **Root is persistent (v19)**: `service.adb.root=1` is added to the boot props, so adbd starts as
  root by itself and `adb root` is **not** needed after a reboot. The image
  `/home/musin/vendor_boot_v19_root.img` (md5 `93d4cbb183752c47f571928d80aadd76`) is built from v18
  with `tools/vendor_props_edit.py` (`--append "service.adb.root=1"`) and was verified over two
  consecutive boots: `uid=0(root)`, `u:r:su:s0`, `getenforce=Permissive`.
* **No `su`**: root is reachable only through adb (there is no root manager for apps in this image).
* **SELinux is permissive globally** — this is a debug mode: Play Integrity / banking apps may
  complain. `setenforce 1` is said to restore enforcing until the next reboot (unverified).
* The kernel is **not** patched, and AVB does not check `boot`. `/system`, `/vendor`, `/product` stay
  EROFS read-only (dm-23/24/25/26) — those partitions were not touched.

## Rollback

```
# preloader: hold Power 20-30 s -> Vol+ & Vol- + cable -> 22d9:0006
cd /home/musin
FLASH_IMG=/home/musin/vendor_boot_v14.img FLASH_PART=vendor_boot_a FLASH_GO=1 ./run_flash_vendor_boot.sh
```

## Side result: what did NOT work (do not repeat)

* the boot ramdisk is not used at all — the `boot_a` ramdisk is **not unpacked** (codec mismatch:
  gzip vs the vendor ramdisk's `lz4-legacy`); proven with an image whose boot ramdisk has no `/init`
  — it still boots;
* Magisk in vendor_boot boots, but `magiskinit::patch_ro_root()` moves our props tmpfs below its own
  `/data` tmpfs (mount stack root→M0→D→M1) → `ro.adb.secure` is lost;
* `adb_keys` cannot be written from first stage: `/data` is `latemount`, the policy grants
  `adb_keys_file` only to `adbd` (r) and `system_server` (rw), and a pre-policy fork stays in the
  `kernel` domain;
* KSU-Next LKM: 61 of the module's 230 imports are missing from the kernel
  (`kallsyms_lookup_name`, `sys_call_table`, …);
* GhostLock: the vulnerability exists, but there is no PoC and no leak from shell.

---

# Magisk 30.7: installed and working (v22)

Result: **Magisk is alive**, `adb shell su -c id` → `uid=0(root)`, context `u:r:magisk:s0`, and it
survives a reboot. The manager `com.topjohnwu.magisk` v30.7 is installed.

## How it is put together

1. `vendor_boot_a` = `vendor_boot_v22_magisk.img` (md5 `a874a5c217d2e42aa7813a151bbd78be`):
   base v19 (permissive cmdline, props, `service.adb.root=1`) + magiskboot patch of the ramdisk
   (`init` = magiskinit, 199,960 B; `.backup/init` symlink; `overlay.d/sbin/{magisk,stub,init-ld}.xz`),
   and the `0xF1AC4` cave replaced by a clone + `execve("/system/bin/sh", "-c", script)` variant.
2. `/data/adb/magisk` is pre-seeded from the APK (busybox, magisk64, magisk32, magiskinit,
   magiskpolicy, stub.apk, 0755/0644) — without it `magiskd` logs
   `E: * Magisk environment incomplete, abort` (visible in `/cache/magisk.log`).
3. `/data/adb/post-fs-data.d/adbkey.sh` (a root hook run by magiskd) writes our `adb_keys` into
   `/data/misc/adb/` — this is what authorises adb, because under Magisk our vendor-init
   **does not run** and the props route is dead (`ro.debuggable=0`, `ro.adb.secure=1`,
   `/debug_ramdisk/adb_debug.prop` absent).
4. `su` for uid 2000 is allowed in the manager: Settings → Superuser access → **Apps and ADB**
   (stored in `magisk.db`, survives a reboot).

## Verified after a reboot

```
adb devices                     -> device (no unauthorized)
adb shell id                    -> uid=2000(shell)          # adbd stays shell
adb shell su -c id              -> uid=0(root) u:r:magisk:s0
getenforce                      -> Permissive (from the v22 cmdline)
```

Device provisioning done as root (dead panel, so it had to be scripted):
`device_provisioned=1`, `user_setup_complete=1`, `development_settings_enabled=1`,
`stay_on_while_plugged_in=7`, `screen_off_timeout=1800000`; the ColorOS setup wizard
(`com.coloros.bootreg`, `com.google.android.setupwizard`) is `disabled-user`.

## Important

* `adb root` **does not** give root under Magisk (adbd drops privileges: `ro.debuggable=0`);
  the only path is `adb shell su -c ...` (or `su` in an interactive session).
* Our vendor-init cave does not execute under Magisk (magiskinit goes straight to the system init),
  so props / `service.adb.root` are useless there — do not waste time on them.
* Two working images: `vendor_boot_v19_root.img` (adb root without Magisk) and
  `vendor_boot_v22_magisk.img` (Magisk + su). Switching is a single
  `fastboot flash vendor_boot_a`.
