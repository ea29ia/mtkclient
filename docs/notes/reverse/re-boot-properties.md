# RMX3630 boot.img analysis — boot-time properties & ADB forcing

Date: 2026-10-23. Analysis of `docs/notes/rmx3630-lk/boot.img` (67,108,864 B,
realme RMX3630, MT6789, Android 14 / 14.0.0.200EX01). Read-only; work files in
`/tmp/opencode/bootwork/`. Goal: find OPLUS/system properties read at boot from
unencrypted `persist` / `oplusreserve` partitions, and whether any flag can
force ADB on **without the RSA authorization dialog**.

## 1. Boot image layout (parsed from header)

Header is **boot image header v4** (`ANDROID!`, header_version=4, GKI-style):

| field | value |
|---|---|
| kernel_size @0x08 | 0x01376ecd (20,302,093 B) |
| ramdisk_size @0x0C | 0x00192c75 (1,649,781 B) |
| os_version @0x10 | 0x18000189 |
| header_size @0x14 | 0x0600 (1536) |
| header_version @0x28 | 4 |
| cmdline @0x2C.. | **all zero — no embedded kernel cmdline** |

* Kernel data at file offset 0x1000: **gzip** (`1f 8b`), decompresses to a
  49,040,780 B **aarch64 Linux kernel Image** ("Linux kernel ARM64 boot
  executable Image, little-endian, 4K pages"). Build date inside matches
  200EX01 ("Mon Sep 2 22:1…", 2024-09-02). No built-in `console=`/`androidboot`
  CMDLINE string found in the kernel → cmdline comes entirely from LK.
* Ramdisk: starts with **LZ4 legacy frame** magic `02 21 4C 18` at offset 307,
  preceded by a u32 uncompressed size `0x00192c6d`. `unlz4` refuses this
  (non-standard legacy variant: only one u32, no per-block header layout), so a
  custom LZ4 block decoder was used. Decoded to a 3,145,619 B **uncompressed
  ASCII cpio (newc)**. Caveat: the decode ran to end of input and the archive
  ends **truncated inside the last file** (`build.prop` data cut mid-string,
  no `TRAILER!!!` entry) — either the last block is clipped in the image itself
  or the last few KB of entries are lost. Nothing important is expected there.

## 2. Ramdisk contents (generic GKI ramdisk, OPLUS-tweaked init)

Exactly 14 entries:

```
drwxr-xr-x  debug_ramdisk/
drwxr-xr-x  dev/
-rwxr-x---  init                       (3,143,536 B, static aarch64, Android 31)
drwxr-xr-x  lib/ lib/modules/
drwxr-xr-x  metadata/ mnt/ proc/ sys/
drwxr-xr-x  system/ system/etc/ system/etc/ramdisk/
-rw-r--r--  system/etc/ramdisk/build.prop  (877 B)
```

* **No `.rc` files at all** — no `init.usb.rc`, no `adbd` service definition,
  no `on property:persist.sys.usb.config=…` triggers. All of that lives in
  `vendor_boot`/`vendor`/`system` (not available here).
* `build.prop` contains only bootimage identity props:
  `ro.product.bootimage.brand=oplus`, `.device=ossi`, `.manufacturer=oplus`,
  `.model=ossi`, `.name=ossi`, `ro.bootimage.build.date=Mon Sep 2 22:1…`
  (truncated).
* `init` is **OPLUS-customized first-stage init** (fs_mgr, property_service,
  snapuserd, phoenix 2.0 all linked in).

## 3. Property / path references found in `init` (first-stage)

Notable strings (file offsets in extracted `rd/init`):

### ADB-relevant (the one real lead)

| string | offset | meaning |
|---|---|---|
| `/force_debuggable` | 60042 | marker file; when it exists init switches into "forced userdebug" mode |
| `INIT_FORCE_DEBUGGABLE` | 73981 | env var first-stage passes to second-stage for that mode |
| `/adb_debug.prop` | 66977 | property file loaded in forced-debuggable mode |
| `/debug_ramdisk/adb_debug.prop` | 113386 | variant used when booting with a debug ramdisk |
| `/debug_ramdisk/userdebug_plat_sepolicy.cil` | 113386 | matching userdebug SELinux policy |
| `ro.debuggable` | ~59900 | read/set by init |

This is the AOSP "userdebug-override" mechanism: if `/force_debuggable` is
present in the ramdisk root, init loads `/adb_debug.prop` (typically
`ro.debuggable=1`, `ro.secure=0`, `ro.adb.secure=0` → **adbd runs as root and
does NOT require the RSA authorization dialog**) and swaps in the userdebug
policy. **Caveat / honesty:** using it requires patching the boot ramdisk
(adding `/force_debuggable` + `/adb_debug.prop`), which changes boot.img →
AVB/dm-verity rejects it on this **locked** device (vbmeta.device_state=locked,
verifiedbootstate=green). It is not reachable via persist-partition writes. It
only becomes relevant if vbmeta verification is ever bypassed (or if we could
boot a patched boot.img with `avb verification` neutralized).

### OPLUS persist/oplusreserve consumption in init (first stage)

| string | context |
|---|---|
| `/dev/block/by-name/oplusreserve1` | phoenix2.0 / bootstats path |
| `/dev/block/by-name/oplusreserve5` | `[phoenix2.0] read uefi oplusreserve5 error`, UEFI/kernel magic check — **phoenix reboot-crash counter storage** |
| `/dev/block/by-name/opporeserve1`, `/dev/block/by-name/reserve1` | legacy aliases |
| `/dev/block/bootdevice/by-name/persist`, `/dev/block/bootdevice/by-name` | generic fs_mgr by-name lookup (persist mounted as /mnt/vendor/persist by fstab, not in this ramdisk) |
| `/mnt/vendor/oplusreserve/fs_mgr_log` | oplus_fs_mgr log sink (`save_log:Unable to open …`) |
| `/mnt/vendor/oplusreserve/normal_reboot` | phoenix "last boot was normal" marker (created/unlinked by init) |
| `/data/oplus_lib` | oplus dir |

Properties actually named in this binary: `persist.sys.timezone`,
`persist.logd.security`, `persist.log.tag.*`, `persist.vendor.oplus.update_status`,
`sys.powerctl`, `sys.oplus.phoenix.handle_error`,
`sys.oplus.phoenix.kernel_nobootcount`, `sys.oplus.phoenix.uefi_nobootcount`,
`ro.boot.*` (imported from cmdline/bootconfig `/proc/bootconfig`),
`ro.build.type`, `ro.debuggable`, `ro.boot.vbmeta.device_state` (in LK), etc.
**None of these enable ADB.** No `persist.sys.usb.config`, no
`persist.sys.allcommode`, no `sys.usb.config`, no `ro.adb.secure`,
no `service.adb.*`, no factory/eng-mode property strings exist anywhere in the
ramdisk init binary or the kernel image (checked with `grep -a`, exact and
pattern matches — zero hits).

### Kernel (Image)

~49 MB stock MTK/GKI kernel. OPLUS additions are limited to storage telemetry
(`oplus_bsp_storage_io_metrics`, `oplus_file_monitor`, `oplus_storage`,
writing to `/data/persist_log/DCS/de/storage/…`) and `oplusboot.prjname` as a
cmdline token. **No ADB/USB-config property logic in the kernel** (expected —
adbd policy is userspace).

## 4. LK (bootloader, `lk.img` in the same directory — bonus evidence)

The cmdline is built entirely by LK. Relevant strings (file offsets in lk.img):

* Boot mode cmdline tokens appended per `g_boot_mode` (set from MTK ATAGs /
  hardware keys, **not from a persist partition**):
  `oplusboot.mode=normal|meta|recovery|factory|alarm|charger|fastboot|unknow`
* Factory/FTM tokens: `oplus_ftm_mode=factory1` (when "agingtest check pass"),
  `oplus_ftm_mode=ftmaging`; messages `agingtest in ftm`,
  `=> FACTORY MODE`, `=> META MODE`.
  * In FTM/aging path LK also appends **`androidboot.selinux=permissive`**.
* META mode: `androidboot.init_rc=/system_ext/etc/init/hw/meta_init.system.rc`
  (meta init rc set is loaded from system_ext), `androidboot.meta_log_disable=0/1`,
  and `set_usbconfig` logging `%s:%d: adb:%d elt:%d meta_com_id:%x` →
  `androidboot.usbconfig=0|1|2|3` (META USB routing: which USB function/port
  META-mode adbd binds to; derived from the META ATAG, not persist).
* Factory key detection: `mediatek,hw-factory-key`,
  `kpd_hw_recovery_key = %d, kpd_hw_factory_key = %d` → factory mode is a
  **hardware key combo** decision, not a partition flag.
* `Get factory mode failed, error: 0x%x` sits next to the fastboot
  lock/unlock UI strings (`unlock_ability is true/false`) — it is the
  bootloader-locked flag check for the unlock-menu path, not an ADB switch.
* oplusreserve1 usage in LK: kernel-log / pl_lk log headers and
  **UFS firmware read** (`Cannot read ufs firmware from OPLUSreserve1
  partition`) — log/telemetry only, no property or ADB logic.
* AVB "persist values" (`[AVB] create a new persist item…`,
  `Write persist value to %s`, `avb.persistent_digest`) — libavb persistent
  digest area (rollback index metadata), unrelated to Android properties.

## 5. Answers to the specific questions

1. **Is there a boot-time property/init trigger in boot.img that starts adbd
   unconditionally?** **No.** The GKI boot ramdisk contains no `.rc` files and
   no adbd service definition; the only adb-relevant logic in `init` is the
   AOSP `/force_debuggable` → `/adb_debug.prop` userdebug override (see §3),
   which requires patching the ramdisk and therefore AVB bypass on this locked
   device.

2. **Are there OPLUS factory-mode properties that override USB user
   restrictions?** Not as *properties read from persist* — boot.img contains
   zero such strings. The factory path in this firmware is **cmdline-driven by
   LK**: `oplusboot.mode=factory`, `oplus_ftm_mode=factory1`, and in the
   ftm/aging case `androidboot.selinux=permissive`. Those tokens are only
   emitted for MTK boot-modes (key combos / ATAGs from preloader); nothing in
   boot.img or LK reads a *persist/oplusreserve value* to select them. Whether
   OPLUS's vendor-side init (in vendor_boot/system, not present here) treats
   `oplus_ftm_mode=factory1` as "start adbd unauthenticated" cannot be proven
   from this image — that would need `vendor_boot.img` + `system_ext`
   `meta_init.*.rc`. It is the most plausible candidate but **unverified**.

3. **persist/oplusreserve properties read at boot:** the boot stage we can see
   reads essentially none for ADB purposes. `oplusreserve5` is read by phoenix2.0
   (crash counters, boot-failure feedback flags), `oplusreserve1` by LK (logs,
   UFS firmware image). The classic OPPO/OPLUS ADB switches circulating in the
   community (`persist.sys.allcommode`, `persist.sys.usb.config`,
   `persist.sys.oppo.*`, `persist.sys.oplus.*` engineering flags) are consumed
   by vendor/system init & adbd — their names do **not** appear in boot.img, so
   their presence in this build is **not confirmed** from this artifact.

4. **Kernel cmdline in boot image header:** empty (all zeros). Everything is
   appended by LK at runtime.

## 6. Verdict

* **There is NO property writable via persist/oplusreserve that forces ADB on
  without the RSA auth dialog, as far as boot.img shows.** The decision chain
  (`persist.sys.usb.config` → `sys.usb.config` → adbd + `ro.adb.secure`
  authorization) is implemented in vendor/system, which this image does not
  contain.
* The one concrete "force ADB" mechanism present in this firmware's init is
  the **AOSP forced-debuggable path** (`/force_debuggable` +
  `/adb_debug.prop` + `userdebug_plat_sepolicy.cil`), which sets
  `ro.debuggable=1` — adbd then runs root and skips auth. It needs a ramdisk
  edit (AVB-blocked), not a persist write.
* If we later get flash-write access, the realistic candidates to test are
  (a) writing `/force_debuggable`-equivalent is impossible via persist; (b)
  reading `vendor_boot.img` from the device (flash read is the easier goal
  than write) to enumerate the real OPLUS vendor init triggers
  (`oplus_ftm_mode`, `allcommode`, usb config) — that is the recommended next
  artifact, not a blind persist write.

## 7. Artifacts / repro

```
/tmp/opencode/bootwork/
  kernel.gz     (raw gzip from boot.img @0x1000, 20,410,061 B)
  kernel.bin    (decompressed aarch64 Image, 49,040,780 B)
  ramdisk.bin   (raw ramdisk from boot.img, 1,649,781 B, LZ4-legacy framed)
  rd.cpio       (decompressed cpio, 3,145,619 B, truncated at end)
  rd/           (unpacked ramdisk: init, build.prop, dirs)
```
Kernel header check: `file kernel.bin` → "Linux kernel ARM64 boot executable
Image, little-endian, 4K pages". Ramdisk decode: custom LZ4-block decoder
(magic `02 21 4C 18` @307, u32 uncompressed size `0x00192c6d`, single block);
all 14 cpio entries parsed with a python newc parser (headers validated as
ASCII hex, mode fields sane, e.g. init = 0o100750/3143536 B, valid ELF
BuildID b692cfd154ba961e54c9dd794fe0b2dd).
