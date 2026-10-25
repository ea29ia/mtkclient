# vendor_boot `/system/bin/init` (RMX3630, MT6789): the real boot flow + bind-mount patch spec

Date: 2026-10-25. **Offline**: the device was not touched, DA was not started, nothing was flashed,
nothing was committed. All conclusions come from the bytes of `/tmp/opencode/vinit` and
`lk_payload.bin`.

Binary under analysis: `/tmp/opencode/vinit` = `system/bin/init` from the vendor ramdisk
(`/tmp/opencode/vb/frag0.cpio`, data-off **0x30AE6BC**), 2 097 128 B (0x1FFFE8),
sha256 `de4092871407b7946fbe8c55e75577d12bdb836d911a8c279ae2490fd0d580cd`,
ELF64 ET_DYN PIE, VA == file offset everywhere (checked with `readelf -l`).

Tooling: capstone 5.0.7 + pyelftools 0.30; function bounds from `.eh_frame`
(`readelf --debug-dump=frames`), PLT names from `.rela.plt` + parsing `.plt`
(525 stubs). Scripts: `/tmp/opencode/re_tools.py`, `/tmp/opencode/annot.py`,
`/tmp/opencode/mkpatch.py`.

---

## 0. TL;DR (EN)

1. On a normal boot LK appends `androidboot.force_normal_boot=1` to the kernel
   cmdline (every boot mode except 2 = recovery). The vendor-ramdisk init then
   executes **two** `SwitchRoot()` calls: `SwitchRoot("/first_stage_ramdisk")`
   @`0xF1994` and, inside `DoFirstStageMount()`, `SwitchRoot("/system")`
   @`0xF4E74`. **Final root of the second stage = the mounted system partition
   (system-as-root)** — not the ramdisk root, not `/first_stage_ramdisk`.
   The `boot_a` ramdisk is **not unpacked at all** (an image whose boot ramdisk
   has no `/init` still boots); the effective initramfs is this vendor ramdisk.
2. `execv("/system/bin/init", {"selinux_setup"})` is at `0xF1AC8`; the binary
   then re-execs itself as `second_stage` (`0x134A64`). The second-stage init in
   the normal flow is the **system.img** init, not this file.
3. `/debug_ramdisk/adb_debug.prop` is **written** by first stage (`0xF168C`,
   gated by `access("/force_debuggable")` @`0xF1630`) and **read** only by
   `SecondStageMain`→`PropertyLoadBootDefaults` (`0x11B3C0`). It is never read
   from `/second_stage_resources/`.
4. Patch: hook `0xF1AC0` (`a1 c3 00 d1` → `c4 f7 03 94`), code cave @`0x1EF9D0`
   (40 B, in the last RX page after `.plt`), RX `PT_LOAD` `p_filesz`/`p_memsz`
   extended `0x13E9D0` → `0x13F000` (fields at file 0x108 / 0x110).
   corrected: this 40-byte shape is analysis variant P-A. Every image that was
   actually flashed (v14, v18, v19, v22) hooks `0xF1AC4` (`e0 03 13 aa` →
   `c3 f7 03 94`) with a **52-byte** cave that saves `argv` in `x9`, restores it
   in `x1` and rejoins at `0xF1AC8`; that is variant P-B (self-bind of
   `/debug_ramdisk`), see §10 and `re-v14-adb-works-2026-10-25.md`.
5. **BLOCKER** for the requested target: `/system/build.prop` is a 235-line file
   (`ro.build.version.sdk`, `ro.product.system.name`, …). Replacing it with an
   81-byte props file breaks the second stage. Recommended variant P-B
   (same cave, `mount("/debug_ramdisk","/debug_ramdisk",MS_BIND)`) keeps all
   stock props and defeats `umount("/debug_ramdisk")` in the second stage.

---

## 1. Fact table (address → meaning)

### 1.1 Entry point and mode dispatcher (`main` = 0xB1054..0xB1200)

| VA | what |
|---|---|
| `0xB1054` | `main(argc, argv)` |
| `0xB1088` | `strcmp(basename(argv[0]), "ueventd")` (string `0x1306E`) → `0xB10FC` → `ueventd_main` `0x13D194` |
| `0xB10AC` | `argv[1] == "subcontext"` (`0x1742E`) → `0xB110C` |
| `0xB10C4` | `argv[1] == "selinux_setup"` (`0x15505`) → `0xB1170` → **`SetupSelinux` 0x1345E8** |
| `0xB10D8` | `argv[1] == "second_stage"` (`0x14399`) → `0xB117C` → **`SecondStageMain` 0xFFBA8** |
| `0xB10EC` | default → **`FirstStageMain` 0xEEDFC** |

### 1.2 `FirstStageMain` = 0xEEDFC..0xF2124 (13 096 B, sole caller — `0xB10EC`)

| VA | what | evidence |
|---|---|---|
| `0xEEE44` | `clearenv()`, `0xEEE64` `setenv("PATH",...)` | PLT `clearenv`/`setenv`, strings `0x21144` "PATH" / `0x22F8E` _PATH_DEFPATH |
| `0xEEF20` | `mount("tmpfs","/dev","tmpfs",MS_NOSUID,"mode=0755")` | strings `0x1B6E0` "tmpfs" / `0x1B6E6` "/dev" / `0x13289` "mode=0755" |
| `0xEF234` | `mount("proc","/proc","proc",0,"hidepid=2,gid=3009")` | `0x22F88` "/proc" / `0x1CD1B` "proc" / `0x18C01` "hidepid=2,gid=3009" |
| `0xEF2E0` | `chmod("/proc/cmdline",0440)` | `0x18034` |
| `0xEF3A4` | `ReadFileToString("/proc/cmdline")` → `[x29-0x68]` | `0x1edea0`, dst `x1 = x29-0x68` |
| `0xEF3C8` | `chmod("/proc/bootconfig",0440)` | `0x16131` |
| `0xEF3FC` | `ReadFileToString("/proc/bootconfig")` → `[x29-0x80]` | dst `x1 = x29-0x80` |
| `0xEF4C4` | `mount("sysfs","/sys",...)`; `0xEF568` `mount("selinuxfs","/sys/fs/selinux",...)` | `0x238EA` "/sys" / `0x1969D` "sysfs" / `0x23070` "/sys/fs/selinux" / `0x25905` "selinuxfs" |
| `0xF0C4C` | `mount("tmpfs","/mnt","tmpfs",MS_NOEXEC\|NOSUID\|NODEV,"mode=0755,uid=0,gid=1000")` | `0x22674` "/mnt" / `0x1C336` "mode=0755,uid=0,gid=1000", w3=0xE |
| `0xF0EB8` | **`mount("tmpfs","/debug_ramdisk","tmpfs",MS_NOEXEC\|NOSUID\|NODEV,"mode=0755,uid=0,gid=0")`** | `0x1633F` "/debug_ramdisk" / `0x110DF` "mode=0755,uid=0,gid=0", w3=0xE |
| `0xF0F74` | **`mount("tmpfs","/second_stage_resources",...)`** | `0x26970` "/second_stage_resources" / `0x110DF`, w3=0xE |
| `0xF1390` | `LoadKernelModules(IsRecoveryMode && !ForceNormalBoot, want_console)` → `0xEE4BC` | opens `/lib/modules` (0xEE58C) |
| `0xF1434` | `access("/system/etc/ramdisk/build.prop")` | `0x269A0` |
| `0xF1478`–`0xF1554` | copy of ramdisk `build.prop` → **`/second_stage_resources/system/etc/ramdisk/build.prop`** (`create_directories` 0x152F08 @`0xF1510`) | `0x26970` + `0x269A0` |
| `0xF1630` | `access("/force_debuggable", F_OK)` | `0x1C34F` |
| `0xF166C` / `0xF168C` | `copy_file("/adb_debug.prop" (0x1D7DB) → "/debug_ramdisk/adb_debug.prop" (0x269BF))` | string `0x269BF` is used **only** here |
| `0xF16BC` / `0xF16DC` | `copy_file("/userdebug_plat_sepolicy.cil" → "/debug_ramdisk/userdebug_plat_sepolicy.cil")` | `0x18C55`, `0x269DD` |
| `0xF17C8` | `setenv("INIT_FORCE_DEBUGGABLE","true",1)` (`0x1EBE4`, `0x1AAAA`) | |
| `0xF17CC`–`0xF1924` | **inline `ForceNormalBoot()`**: looks for `androidboot.force_normal_boot = "1"` in bootconfig (36 B, `memchr` @`0xF1824`) **or** `androidboot.force_normal_boot=1` in cmdline (31 B, `memchr` @`0xF18CC`) | see §2 |
| `0xF1928` | `mkdir("/first_stage_ramdisk",0755)` | `0x14E87`, `w1=0x1ED` |
| `0xF1950` | **`mount("/first_stage_ramdisk","/first_stage_ramdisk",NULL,MS_BIND=0x1000,NULL)`** | `0x1000` in `w3` |
| `0xF1994` | **`SwitchRoot("/first_stage_ramdisk")`** → `0x13B32C` | |
| `0xF19A8`/`0xF19AC` | `DoFirstStageMount()` → `0xF6564` | |
| `0xF19E4` | `stat("/")`, `0xF1A04/0xF1A20/0xF1A28` `FreeRamdisk(old_root)` | strings `0x22679` `Could not stat("/")…`, `0x13442` `Could not opendir("/")…`, `0x21199` `Copied ramdisk prop to ` |
| `0xF1A2C` | `SetInitAvbVersionInRecovery()` → `0xF6728` | `INIT_AVB_VERSION` @`0x1772D` |
| `0xF1A58`/`0xF1A60` | `setenv("FIRST_STAGE_STARTED_AT", to_string(boot_clock))` | `0x26A08` |
| `0xF1A8C`–`0xF1ABC` | `open("/dev/kmsg",O_WRONLY\|O_CLOEXEC)`, `dup2(fd,1)`, `dup2(fd,2)`, `close` | `0x132B5` |
| **`0xF1AC0`** | **`sub x1, x29, #0x30`** (`a1 c3 00 d1`) — patch slot for variant P-A | |
| **`0xF1AC4`** | **`mov x0, x19`** (`e0 03 13 aa`) — patch slot for the shipped images (x19 = **`0x20543` = "/system/bin/init"**, loaded at `0xF1A78`) | |
| **`0xF1AC8`** | **`bl execv` (PLT `0x1EDB40`)**; argv = `x29-0x30` = `{"/system/bin/init", "selinux_setup" (0x15505), NULL}` (built at `0xF1A74`–`0xF1A88`) | |
| `0xF1C2C`–`0xF1C54` | log `execv("/system/bin/init") failed` | `0x1B7D9` `execv("` + `0x13438` `") failed` |

### 1.3 `SwitchRoot` = 0x13B32C..0x13B9A0 (1 652 B) — exactly 2 callers

| VA | what |
|---|---|
| `0x13B374` | `setmntent("/proc/mounts","re")` (`0x119F0`, `0x12857`) |
| `0x13B39C` | `getmntent` loop; `[mnt+8]` = `mnt_dir` |
| `0x13B41C` | skip `mnt_dir == "/"` |
| `0x13B460` | skip `mnt_dir == new_root` |
| `0x13B49C` | dedupe nested mount points (`StartsWith`) → `std::string` vector at `sp+8` |
| `0x13B5B8` | `new_mount_point = new_root + mnt_dir` (`0xBFDA0` = concatenation) |
| `0x13B5D0` | `mkdir(new_root + mnt_dir, 0755)` |
| `0x13B604` | **`mount(mnt_dir, new_root+mnt_dir, NULL, MS_MOVE=0x2000, NULL)`** (`w3=0x2000` @`0x13B5FC`) |
| `0x13B6AC` | `chdir(new_root)` |
| `0x13B6E8` | `mount(new_root, "/", NULL, MS_MOVE, NULL)` |
| `0x13B708` | **`chroot(".")`** (PLT `0x1EF110`); `0x127B8` = "." |
| strings | `0x1A505` `switch_root.cpp`, `0x1A526` `Unable to move mount at '`, `0x2089A` `Could not chdir to new_root, '`, `0x25179` `Unable to chroot to new root`, `0x2298F` `Failed to open /proc/mounts` |

Callers: `0xF1994` (`FirstStageMain`) and `0xF4E74` (`TrySwitchSystemAsRoot`).
There is no other `chroot` in the binary (the only `bl` to PLT `0x1EF110` is `0x13B708`).

### 1.4 `FirstStageMount` (the first mount stage)

| VA | what |
|---|---|
| `0xF6564`..`0xF6728` | `DoFirstStageMount()`: `IsRecoveryMode()` (`0xC3E84`), `FirstStageMount::Create` (`0xF2848`), `Init` (`0xF2DF4`), `DoFirstStageMount` (`0xF3A80`) |
| `0xF3A80`..`0xF3B7C` | body of `DoFirstStageMount()`: looks in fstab for an entry with bit 0x13 (bit 19 = `first_stage_mount`) |
| `0xF3B7C`..`0xF4CF8` | `MountPartitions()`: `0xF3BAC` → `0xF4CF8`; then loops over fstab (skip `/system`, skip `emmc`), `fs_mgr_do_mount_one` (`0xF31DC`) |
| `0xF4CF8`..`0xF4F10` | **`TrySwitchSystemAsRoot()`**: `0xF4D20` `UseDsuIfPresent` (`0xF4F10`), `0xF4D28` `PreloadAvbKeys` (`0xF48EC`), `/system` lookup (`0xF4D50`), `0xF4DBC` `MountPartition`, `0xF4DD0` `fs_mgr_verity_is_check_at_most_once`, `0xF4E44`–`0xF4E6C` builds the `/system` string, **`0xF4E74` `SwitchRoot("/system")`** |
| `0xF4F10`..`0xF5560` | `UseDsuIfPresent()`: `/metadata/gsi/dsu/active`, `DSU slot: `, `DSU indicator file could not be written` |
| `0xCDF58` | the only PLT call to `fs_mgr_mount_all` (`0x1EE040`) |

### 1.5 Second stage in **this** binary (executed only in recovery)

| VA | what |
|---|---|
| `0x1345E8`..`0x134F68` | `SetupSelinux`; `0x1349E0` = "/system/bin/init", `0x134A64` `execv` with argv `{..., "second_stage"(0x14399)}` |
| `0xFFBA8`..`0x102948` | `SecondStageMain` |
| `0xFFD60` / `0xFFD70` | `getenv("INIT_FORCE_DEBUGGABLE")`, `AvbHandle::IsDeviceUnlocked()` (PLT `0x1EE930`) |
| `0xFFDE4`/`0xFFDEC` | gate passed: `PropertyInit` (`0x11E130`) → `UmountSecondStageRes` (`0x102A04`) → `UmountDebugRamdisk` (`0x102948`) |
| `0xFFE00`/`0xFFE04` | else: **`UmountDebugRamdisk` BEFORE `PropertyInit`** |
| `0x102948`..`0x102A04` | `UmountDebugRamdisk()`: `umount("/debug_ramdisk")` @`0x102970` (PLT `0x1EE0D0`, **not** `umount2`), log `Failed to umount /debug_ramdisk` (`0x158E1`) |
| `0x11AB38`..`0x11D370` | `PropertyLoadBootDefaults()` |
| `0x11B3C0` | `access("/debug_ramdisk/adb_debug.prop", R_OK)` (string `0x26AF6`) |
| `0x11B3E8` | `load_properties_from_file(...)`; `0x11CF78` — log `Loading /debug_ramdisk/adb_debug.prop` |

### 1.6 Strings / PLT referenced by the patch

| address | string |
|---|---|
| `0x1128F` | `/system/build.prop` |
| `0x20543` | `/system/bin/init` |
| `0x15505` | `selinux_setup` |
| `0x14E87` | `/first_stage_ramdisk` |
| `0x1633F` | `/debug_ramdisk` |
| `0x183D9`, `0x26970` | `/second_stage_resources` |
| `0x1C34F` | `/force_debuggable` |
| `0x1D7DB` | `/adb_debug.prop` |
| `0x269BF` | `/debug_ramdisk/adb_debug.prop` (copy #1, first stage) |
| `0x26AF6` | `/debug_ramdisk/adb_debug.prop` (copy #2, second stage) |

PLT: `execv 0x1EDB40`, `mount 0x1EE070`, `umount 0x1EE0D0`, `umount2 0x1EE4D0`,
`chroot 0x1EF110`, `fs_mgr_mount_all 0x1EE040`, `IsDeviceUnlocked 0x1EE930`.

---

## 2. The `ForceNormalBoot` gate (full addresses)

Two template strings of length 36 and 31 bytes are compared by hand (`memchr` for `'a'` plus
`eor` of 8-byte constants):

```
0xF17F8  mov x23, #0x746f / movk 0x3d20 / movk 0x2220 / movk 0x2231   ; "ot = \"1\""
0xF1808  mov x19, #0x625f / movk 0x6f6f / movk 0x2074 / movk 0x203d   ; "_boot = "
0xF1824  bl memchr(cmdline_bootconfig, 'a', len-0x22)
0xF1834  eor x8, x8, x28 ; eor x9, x9, x26 ; eor x10, x10, x25 ; eor x11, x11, x19
0xF1840  ldr x12, [x0,#0x1b] ; eor x10, x12, x23
```

`x28/x26/x25` = `"androidb"`, `"oot.forc"`, `"e_normal"` → the 35-byte key
**`androidboot.force_normal_boot = "1"`** (bootconfig form, string `[x29-0x80]`
= `/proc/bootconfig`), then a second pass (`0xF18B0`–`0xF18D0`) over
`[x29-0x68]` = `/proc/cmdline` for **`androidboot.force_normal_boot=1`**
(`x22 = 0x5f6c 6f62 746f 313d` = `"l_boot=1"`).

Result: `0xF1884 b.ne 0xF1928` — found ⇒ `mkdir`+bind+`SwitchRoot`.

### 2.1 LK really does set this key on a normal boot

`/home/musin/mtkclient/docs/notes/rmx3630-lk/lk_payload.bin`:

| offset | what |
|---|---|
| `0x92646` | string `androidboot.force_normal_boot=1` |
| `0xD0B0`–`0xD0C4` | `bl 0xAAA0` (get boot mode), `w24 = mode & 0xff` |
| `0xD0C8` | `if mode == 4` → factory branch `0xD0E0` (adds `androidboot.init_rc=…` `0x92606`, then `0x92646`) |
| `0xD0D0` | `if mode == 2` → `0xD1D8` — **adds nothing** |
| `0xD0D8` | `if mode != 1` → `0xD180` |
| **`0xD184`/`0xD188`** | `x0 = 0x92646; bl 0x18204` — **adds `androidboot.force_normal_boot=1`** (mode 0 = normal lands here) |
| `0xD104` | same addition for mode 1/4 |

That mode 2 = recovery is proven by the transition table `0x93A80`:
`[0]=0x16` → `0xD420` (normal: no `oplusboot.mode=`), `[1]=0x00` → `0xD3C8`
(`oplusboot.mode=meta` `0x9276D`), **`[2]=0x0B` → `0xD3F4` → `oplusboot.mode=recovery`
`0x92781`**, `[4]=0x0E` → `oplusboot.mode=factory` `0x92799`.

⇒ On a normal boot (mode 0) `/proc/cmdline` contains
`androidboot.force_normal_boot=1`, so `SwitchRoot("/first_stage_ramdisk")`
at `0xF1994` **does execute**.

---

## 3. Boot flow with addresses

```
LK, boot_mode=0 (normal)
 └─ cmdline += "androidboot.force_normal_boot=1"          lk_payload 0xD184
kernel: execve("/init")   [vendor cpio: /init -> /system/bin/init]
 └─ PID1 = vinit (sha256 de409287…)  → main 0xB1054 → FirstStageMain 0xEEDFC
     ├─ 0xEEF20…0xF0EB8  mount /dev,/proc,/sys,/mnt, tmpfs /debug_ramdisk
     ├─ 0xF0F74           mount tmpfs /second_stage_resources
     ├─ 0xF1434…0xF1554   access/copy /system/etc/ramdisk/build.prop →
     │                    /second_stage_resources/system/etc/ramdisk/build.prop
     ├─ 0xF1630           access("/force_debuggable")          (see §4)
     │   └─ 0xF168C       copy /adb_debug.prop → /debug_ramdisk/adb_debug.prop (tmpfs!)
     │   └─ 0xF17C8       setenv("INIT_FORCE_DEBUGGABLE","true")
     ├─ 0xF17CC           ForceNormalBoot? == YES (cmdline)
     │   ├─ 0xF1928       mkdir /first_stage_ramdisk
     │   ├─ 0xF1950       mount("/first_stage_ramdisk","/first_stage_ramdisk",MS_BIND)
     │   └─ 0xF1994       SwitchRoot("/first_stage_ramdisk")   ← ROOT #1
     │       0x13B604     mount("/dev", "/first_stage_ramdisk/dev", MS_MOVE) … (all mounts)
     │       0x13B6E8     mount("/first_stage_ramdisk","/",MS_MOVE); 0x13B708 chroot(".")
     ├─ 0xF19AC DoFirstStageMount 0xF6564 → 0xF3A80 → 0xF3B7C → 0xF4CF8
     │   ├─ 0xF4DBC       fs_mgr_do_mount_one("/system", erofs, ro, avb=vbmeta_system)
     │   └─ 0xF4E74       SwitchRoot("/system")                ← ROOT #2 = FINAL
     │       0x13B604     mount("/dev","/system/dev",MS_MOVE) …
     │       0x13B6E8     mount("/system","/",MS_MOVE); 0x13B708 chroot(".")
     ├─ 0xF19E4 / 0xF1A28 FreeRamdisk(old root)   ← ramdisk files are deleted
     ├─ 0xF1A2C           SetInitAvbVersionInRecovery()
     ├─ 0xF1A60           setenv("FIRST_STAGE_STARTED_AT", …)
     ├─ 0xF1A8C…0xF1ABC   open /dev/kmsg + dup2(1),dup2(2)
     └─ 0xF1AC8           execv("/system/bin/init", {"selinux_setup"})
           │
           └─ /system/bin/init = init from system.img (3 085 160 B)
                ├─ 0xB1054 main → "selinux_setup" → SetupSelinux 0x1345E8
                ├─ 0x134A64 execv("/system/bin/init", {"second_stage"})
                └─ 0xB1054 main → "second_stage" → SecondStageMain 0xFFBA8
                     └─ gate 0x1344AC..0x13454C (see re-init-prop-gate.md §3)
                        → PropertyInit → /system/build.prop (#5)
                                       → /debug_ramdisk/adb_debug.prop (#13)
```

Fstab (`first_stage_ramdisk/fstab.mt6789`, from the cpio) — proof that
`/system` is mounted in the first stage:

```
system /system ext4  ro wait,slotselect,avb=vbmeta_system,logical,first_stage_mount,avb_keys=…
system /system erofs ro wait,slotselect,avb=vbmeta_system,logical,first_stage_mount,avb_keys=…
```

---

## 4. Answer to Q1: what root does the second stage get

**On a normal boot BOTH `SwitchRoot` calls execute.**

1. `0xF1994` — `SwitchRoot("/first_stage_ramdisk")`, gated by `ForceNormalBoot`
   (§2), runs before `DoFirstStageMount`.
2. `0xF4E74` — `SwitchRoot("/system")` inside `TrySwitchSystemAsRoot`
   (`0xF4CF8`), called from `MountPartitions` (`0xF3B7C`) → `DoFirstStageMount`
   (`0xF19AC`). The only skip condition is a missing `/system` entry in
   fstab (`0xF4D9C`) or `check_at_most_once` on external media (`0xF4DD4`);
   our fstab has the entry and there is no DSU (`dsu_not_on_userdata_ == 0`).

Therefore the second stage's root is **(c) something else: the mounted `system` partition**
(system-as-root). `/first_stage_ramdisk` is only an intermediate root.

Independent check: `first_stage_ramdisk/` cpio does **not** contain `system/bin/init`
(only `fstab.mt6789`, `fstab.emmc`, `system/bin/{e2fsck,linker64,linker_asan64,snapuserd}`,
`system/lib64/*`). If the second `SwitchRoot` did not happen, `execv("/system/bin/init")`
after `chroot("/first_stage_ramdisk")` would give ENOENT and the phone would not boot.
The phone boots ⇒ `SwitchRoot("/system")` did run.

Circumstantial evidence: `/system/build.prop` inside the vendor ramdisk is 3024 B with
`ro.build.version.sdk=31` (Android 12), while in the system image (ColorOS 14 / Android 14,
RMX3630 14.0.0) it is 8168 B with `ro.build.version.sdk=34`. Obviously the second file is the
one in effect ⇒ the effective root is the system image, not the ramdisk (see also §9).

Consequences (important for any ramdisk patch):

* everything placed in the vendor ramdisk (root or `first_stage_ramdisk/`)
  **disappears** by the time of `execv`: the root is swapped twice and the old
  one is additionally wiped (`0xF1A28` `FreeRamdisk`);
* `first_stage_ramdisk/adb_debug.prop` and `first_stage_ramdisk/force_debuggable`
  are invisible to the `access("/force_debuggable")` check — that check runs **before**
  the first `SwitchRoot` (`0xF1630 < 0xF1994`);
* the only thing that survives both `SwitchRoot` calls is **mounts**:
  the tmpfs `/debug_ramdisk`, tmpfs `/second_stage_resources`, `/dev`, `/proc`,
  `/sys`, `/mnt` are carried into the new root (`0x13B604`), because
  `SwitchRoot` moves **all** mount points from `/proc/mounts`,
  not only those under `new_root`.

---

## 5. Answer to Q2: where `execv("/system/bin/init")` is

| | |
|---|---|
| site | **`0xF1AC8`** `bl #0x1EDB40` (`execv`), bytes `1e f0 03 94` |
| string xref | `0xF1A78` `add x19, x19, #0x543` → `x19 = 0x20543`; `0xF1AC4` `mov x0, x19` |
| argv | `0xF1A74`–`0xF1A88`: `stp x19, x8, [x29,#-0x30]` (x8 = `0x15505`), `stur xzr,[x29,#-0x20]` ⇒ `{path, "selinux_setup", NULL}` |
| between mount(/system) and exec | `SwitchRoot("/system")` @`0xF4E74` → `stat("/")` @`0xF19E4` → `FreeRamdisk` @`0xF1A28` → `SetInitAvbVersionInRecovery` @`0xF1A2C` → `setenv FIRST_STAGE_STARTED_AT` @`0xF1A60` → `open /dev/kmsg`+`dup2(1,2)` @`0xF1A8C`–`0xF1ABC` → `execv` |
| `umount("/debug_ramdisk")` | **not** in `FirstStageMain`; it exists only in `SecondStageMain` (`0x102948`, `umount` @`0x102970`) and in the system.img init (prior: `0x139A28`) |
| `SetUpSecondStageResources` | not in the first stage; it only creates the tmpfs and copies `build.prop` (see `0xF0F74`/`0xF1430`). The function itself is in the second stage (`system.img`) |

The order "`selinux_setup` → `second_stage`" is confirmed: `0x134A64` (`SetupSelinux`)
does `execv("/system/bin/init", {"second_stage"})`.

---

## 6. Answer to Q3: who reads `/debug_ramdisk/adb_debug.prop`

| string | xref | role |
|---|---|---|
| `0x269BF` | **only** `0xF166C` | **writer**: destination of `copy_file("/adb_debug.prop" → "/debug_ramdisk/adb_debug.prop")`, call `0xF168C`; gate is `access("/force_debuggable")` @`0xF1630` |
| `0x26AF6` | `0x11B3B8`, `0x11B3DC`, `0x11CF7C` | **reader**: `PropertyLoadBootDefaults` in `SecondStageMain` — `access(..., R_OK)` @`0x11B3C0`, `load_properties_from_file` @`0x11B3E8`, log `Loading …` @`0x11CF78` |
| `0x26970` | `0xF0F54`, `0xF1288`, `0xF12D4`, `0xF1308` | first stage only: tmpfs name `/second_stage_resources` and path prefix for the `build.prop` copy |
| `0x183D9` | `0x11B0E0` | second stage: source #4 `/second_stage_resources/system/etc/ramdisk/build.prop` |

Bottom line: `adb_debug.prop` is read **only** from `/debug_ramdisk/`, never from
`/second_stage_resources/`. Exactly one file travels in `/second_stage_resources`:
`system/etc/ramdisk/build.prop` (and it is applied **before**
`/system/build.prop`, so it cannot override `ro.adb.secure`).

Note: in the normal flow the second stage is the init from **system.img**
(`a458669b…`, unverified), but the path is the same (`/debug_ramdisk/adb_debug.prop`,
`re-init-prop-gate.md` §4.1).

---

## 7. Answer to Q5: is `/system` mounted by the time of exec

Yes. `system /system … first_stage_mount` from `fstab.mt6789` is mounted inside
`DoFirstStageMount()` (`0xF19AC`), namely at `0xF4DBC` (`fs_mgr_do_mount_one`),
and only after that come `SwitchRoot("/system")` (`0xF4E74`) and `execv` (`0xF1AC8`).
So at the hook `/system` is a real partition (erofs/ext4, ro), and
`/system/build.prop` is the very file the second stage reads as source #5
(`0x156D78` in the system.img init; in this binary — `0x11B23C`).

Caveat: if `DoFirstStageMount` returns 0, the code still reaches `execv`
(it only logs `Failed to mount required partitions early ...`, `0xF1E98`
`b 0xF19C4`), but then `execv("/system/bin/init")` fails (ENOENT) — i.e.
**if exec happened, `/system` is already mounted**. For our hook this means:
`mount(...)` either works or returns an error (in which case we simply go on to
exec, like stock does).

---

## 8. Patch spec

### 8.1 Hook point

`0xF1AC0` (`sub x1, x29, #0x30`):

```
0xF1AB8  mov  x0, w21
0xF1ABC  bl   close                   ; fd = /dev/kmsg
0xF1AC0  a1 c3 00 d1   sub  x1, x29, #0x30     <-- HOOK (P-A)
0xF1AC4  e0 03 13 aa   mov  x0, x19            ; "/system/bin/init"
0xF1AC8  1e f0 03 94   bl   execv
0xF1ACC  ...                                   ; only if execv fails
```

Why `0xF1AC0` and not `0xF1AC8`:

* there is no branch at `0xF1AC0`/`0xF1AC4`/`0xF1AC8` — only
  fall-through (all 67 225 branches in `.text` were checked);
* after returning from the cave, `0xF1AC0`/`0xF1AC4` recompute `x1` and `x0`,
  so no registers have to be saved;
* `x2, x3, x4, x8` are dead after `execv` (execv takes 2 arguments);
* `adrp/add/movz/svc` do **not** change NZCV, `svc` preserves the other registers
  (the kernel restores `pt_regs`, only `x0` is clobbered) ⇒ the semantics of the
  original instruction are preserved trivially (and it is re-executed anyway).

corrected: the reasoning holds for both slots, but the images that were actually
built (v14 and later) hook **`0xF1AC4`** (`e0 03 13 aa` → `c3 f7 03 94`, a `bl`
whose return address is `0xF1AC8`) and use the 52-byte cave from §10 that saves
`argv` in `x9` and rejoins at `0xF1AC8`. The 40-byte P-A/P-B forms below with the
hook at `0xF1AC0` were never flashed.

### 8.2 Code cave and segment extension

Executable `PT_LOAD`: `p_offset=0xB1000`, `p_vaddr=0xB1000`,
`p_filesz=p_memsz=0x13E9D0` ⇒ end `0x1EF9D0`. Past `.plt` (which ends at the same
place) the file has **1584 zero bytes** `0x1EF9D0..0x1F0000`, and the next `PT_LOAD`
(RW) starts exactly at `0x1F0000`.

Cave: **`0x1EF9D0`**, 40 bytes (`0x1EF9D0..0x1EF9F7`), the rest zeros.

We extend `p_filesz` and `p_memsz` of the RX segment `0x13E9D0 → 0x13F000`
(which is exactly `0x1F0000 = 0x1EF9D0 + 0x630`).

An honest caveat on necessity: `elf_map()` in `fs/binfmt_elf.c` maps
`ELF_PAGEALIGN(p_filesz + ELF_PAGEOFFSET(p_vaddr))`, i.e. the whole last page
`0x1EF000..0x1F0000` from the file; `padzero()` is only called when
`p_memsz > p_filesz`, and in stock they are equal ⇒ technically the cave would be
mapped RX even without the phdr edit. But the extension:

* makes the cave bytes **formally** part of `p_filesz` (no reliance on page
  rounding in the kernel or in the bionic linker);
* rules out any variant that zeroes the segment "tail";
* keeps the ELF self-consistent (`p_filesz == p_memsz`, end == start of the
  next `PT_LOAD`).

The price is 8 bytes in two phdr fields (below).

Page arithmetic:

```
RX : [0x0B1000, 0x1EF9D0) -> page 0x0B1000 .. ALIGN_UP(0x1EF9D0)=0x1F0000
new p_filesz = 0x1F0000 - 0x0B1000 = 0x13F000   (p_memsz the same)
RW : [0x1F0000, 0x1F4910) — no overlap (the boundary coincides, overlap = 0)
GNU_RELRO [0x1F0000,0x1F5910), GNU_EH_FRAME [0x99274,0x9D590) — untouched
```

Program header fields (phdr #3, file `0x40 + 3*56 = 0xE8`):

| file | field | was | became |
|---|---|---|---|
| `0x108` | `p_filesz` | `d0 e9 13 00 00 00 00 00` (0x13E9D0) | `00 f0 13 00 00 00 00 00` (0x13F000) |
| `0x110` | `p_memsz` | `d0 e9 13 00 00 00 00 00` | `00 f0 13 00 00 00 00 00` |

### 8.3 Exact bytes (variant P-A — exactly what was asked for)

```
hook  0x0F1AC0 : a1 c3 00 d1  ->  c4 f7 03 94        (bl 0x1EF9D0)
phdr  0x000108 : d0 e9 13 00 00 00 00 00 -> 00 f0 13 00 00 00 00 00
phdr  0x000110 : d0 e9 13 00 00 00 00 00 -> 00 f0 13 00 00 00 00 00
cave  0x1EF9D0 (40 B):
  a0 f1 ff f0  00 fc 26 91  01 f1 ff d0  21 3c 0a 91
  e2 03 1f aa  03 00 82 d2  e4 03 1f aa  08 05 80 d2
  01 00 00 d4  33 08 fc 17
```

The cave in disassembly (capstone over the **patched** file):

```
0x1ef9d0  adrp x0, #0x26000
0x1ef9d4  add  x0, x0, #0x9bf      ; -> 0x269bf "/debug_ramdisk/adb_debug.prop"
0x1ef9d8  adrp x1, #0x11000
0x1ef9dc  add  x1, x1, #0x28f      ; -> 0x1128f "/system/build.prop"
0x1ef9e0  mov  x2, xzr             ; filesystemtype = NULL
0x1ef9e4  mov  x3, #0x1000         ; MS_BIND
0x1ef9e8  mov  x4, xzr             ; data = NULL
0x1ef9ec  mov  x8, #0x28           ; __NR_mount = 40
0x1ef9f0  svc  #0
0x1ef9f4  b    #0xf1ac0            ; re-execute sub x1,x29,#0x30
```

(`0x1000` = `MS_BIND` = 1<<12; `x8=40` = `__NR_mount` for arm64.)

Branches and range (ARM64 `b`/`bl`: imm26 is signed, ±128 MiB = ±0x7FFFFFC):

```
bl 0x0F1AC0 -> 0x1EF9D0 : delta +0xFDF10  imm26 260036  OK
b  0x1EF9F4 -> 0x0F1AC0 : delta -0xFDF34  imm26 260045  OK
adrp in the cave: ±4 GiB, delta to 0x26000/0x11000 — certainly OK
```

`readelf -l` after the patch:

```
LOAD 0x0b1000 0x00000000000b1000 0x13f000 0x13f000 R E 0x1000
LOAD 0x1f0000 0x00000000001f0000 0x004910 0x004910 RW  0x1000
```

sha256 of the patched file (P-A): `cb2f75378bb35c73e8be94ffa281f0f9d7f746253025004bc60b7729791bf81a`,
44 bytes changed.

### 8.4 Python (applied to ELF bytes, returns bytes)

```python
import struct

HOOK   = 0xF1AC0            # sub x1, x29, #0x30
CAVE   = 0x1EF9D0
REEXEC = 0xF1AC0
RX_PHDR_FILESZ = 0x108      # p_filesz  LOAD #3 (R E)
RX_PHDR_MEMSZ  = 0x110      # p_memsz
SRC = 0x269BF               # "/debug_ramdisk/adb_debug.prop"
TGT = 0x1128F               # "/system/build.prop"

def adrp(rd, pc, t):
    d = ((t & ~0xFFF) - (pc & ~0xFFF)) >> 12
    return 0x90000000 | ((d & 3) << 29) | (((d >> 2) & 0x7FFFF) << 5) | rd
def addi(rd, rn, imm):
    return 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd
def movz(rd, imm):
    return 0xD2800000 | (imm << 5) | rd
def br(pc, t, link=False):
    return (0x94000000 if link else 0x14000000) | (((t - pc) >> 2) & 0x3FFFFFF)

def patch(b):
    b = bytearray(b)
    assert b[HOOK:HOOK+4] == bytes.fromhex("a1c300d1"), b[HOOK:HOOK+4].hex()
    struct.pack_into("<Q", b, RX_PHDR_FILESZ, 0x13F000)
    struct.pack_into("<Q", b, RX_PHDR_MEMSZ,  0x13F000)
    struct.pack_into("<I", b, HOOK, br(HOOK, CAVE, link=True))
    code = [adrp(0, CAVE,      SRC), addi(0, 0, SRC & 0xFFF),
            adrp(1, CAVE + 8,  TGT), addi(1, 1, TGT & 0xFFF),
            0xAA1F03E2,               # mov x2, xzr
            movz(3, 0x1000),          # MS_BIND
            0xAA1F03E4,               # mov x4, xzr
            movz(8, 40),              # __NR_mount
            0xD4000001,               # svc #0
            br(CAVE + 36, REEXEC)]    # b 0xF1AC0
    payload = b"".join(struct.pack("<I", i) for i in code)
    assert len(payload) == 40
    b[CAVE:CAVE+40] = payload
    return bytes(b)
```

The check script (`/tmp/opencode/mkpatch.py`) and this snippet produce
byte-identical output (sha256 above).

### 8.5 Where to write this in the image

`system/bin/init` lives in cpio `frag0.cpio` at data-offset **0x30AE6BC**
(sha256 matches vinit). Absolute offsets in the cpio:

| what | cpio offset |
|---|---|
| `p_filesz` (elf 0x108) | `0x30AE7C4` |
| `p_memsz` (elf 0x110) | `0x30AE7CC` |
| hook (elf 0xF1AC0) | `0x31A017C` |
| cave (elf 0x1EF9D0, 40 B) | `0x329E08C … 0x329E0B3` |

Then: repack lz4-legacy, update `vendor_ramdisk_size` and the page-aligned
offsets of dtb/table/bootconfig (ready-made primitives are in
`docs/notes/build_v6_dual.py`, but it hardcodes the old P2 `0xF1710` — it must be
replaced with this spec).

Correction to earlier documents: the data-offset of `system/bin/init` is **0x30AE6BC**,
not `0x30A5F74` (`0x30A5F74 + 0xF1710` does not contain `33 05 00 36`;
`0x30AE6BC + 0xF1710` does).

---

## 9. BLOCKER for P-A: `/system/build.prop` cannot be replaced wholesale

`/system/build.prop` is a full build.prop and the only source of
`ro.build.version.sdk` (34), `ro.product.system.name`, `ro.adb.secure=1`,
`ro.debuggable=0` and ~230 more properties. Bind-mounting the 81-byte
`adb_debug.prop` over it **deletes all those properties** ⇒ the second
stage/zygote will not come up.

The numbers (both copies are full build.prop files):

| file | size | lines | key entries |
|---|---|---|---|
| `/tmp/opencode/sysa/system/build.prop` (system image tree) | **8168 B** | 235 | `ro.build.version.sdk=34` (32), `ro.adb.secure=1` (121), `ro.debuggable=0` (123) |
| `system/build.prop` inside the vendor ramdisk (cpio data-off `0x3B8343C`) | 3024 B | 80 | `ro.build.version.sdk=31` (31), `ro.adb.secure=1` (68), `ro.debuggable=0` (70) — a different build, but still a full prop file |

So the size is not "a couple of bytes": P-A as it stands is guaranteed to break
`PropertyLoadBootDefaults` → `ro.build.version.sdk` empty → zygote does not start.

Therefore P-A is only a "mechanics demonstration"; for a real image use P-B.

---

## 10. P-B (recommended variant): loosen `umount("/debug_ramdisk")`

Idea: do not touch any stock `*.prop`; instead make the second stage **unable** to
unmount the tmpfs `/debug_ramdisk` before `PropertyInit()`. Then source
#13 (`/debug_ramdisk/adb_debug.prop` — the copy that first stage made from
`/adb_debug.prop`) is read under **any** `verifiedbootstate`.

Patch (same hook, same cave) — a self-bind of the directory:

```
mount("/debug_ramdisk", "/debug_ramdisk", NULL, MS_BIND, NULL)   // 0x1633F -> 0x1633F

cave 0x1EF9D0 (40 B):
  20 f1 ff f0  00 fc 0c 91  21 f1 ff f0  21 fc 0c 91
  e2 03 1f aa  03 00 82 d2  e4 03 1f aa  08 05 80 d2
  01 00 00 d4  33 08 fc 17
```

corrected: as shipped in v14/v18/v19/v22 the cave is the 52-byte form at the
`0xF1AC4` hook: `mov x9,x1` first, the same `adrp/add` of `0x1633F` into `x0`
and `x1`, `mov x2,xzr`, `mov x3,#0x1000`, `mov x4,xzr`, `mov x8,#40`,
`svc #0`, then `mov x1,x9`, `mov x0,x19`, `b 0xF1AC8`. The 40-byte listing above
is the same code at the `0xF1AC0` hook (it ends by re-executing
`sub x1,x29,#0x30` instead of restoring `argv`).

Why it works:

* `0x1633F` = `"/debug_ramdisk"` (NUL-terminated);
* `mount(a, a, MS_BIND)` creates a **stack** of two mounts at one point;
* the second stage calls `umount("/debug_ramdisk")` (in the system.img init —
  `0x139A28`; in this binary — `0x102970`), i.e. `umount(2)`, not
  `umount2(MNT_DETACH)`; only the **top** mount is popped, the lower tmpfs
  stays mounted;
* `PropertyLoadBootDefaults` → `access("/debug_ramdisk/adb_debug.prop")` @`0x11B3C0`
  (system.img: `0x156FE4`) finds the file ⇒ `ro.adb.secure=0`, `ro.debuggable=1`,
  `ro.force.debuggable=1`, `persist.sys.usb.config=adb` are applied;
* `/system/build.prop` and all other stock props stay untouched.

Preconditions (already satisfied in these builds):

1. `/force_debuggable` — in the **ramdisk root** (`access()` uses the path
   `/force_debuggable` **before** the first `SwitchRoot`, `0xF1630`);
2. `/adb_debug.prop` — in the ramdisk root; the copy into the tmpfs is made at
   `0xF168C` (0x460 bytes before the hook, in time);
3. if the copy failed, the bind is still created but the props are not applied
   (silent no-op, nothing breaks).

Limitation: the variant relies on `umount("/debug_ramdisk")` being a plain
`umount`, not `MNT_DETACH`. Both inits were checked by disassembly
(`0x102970` / `0x139A28`, PLT `umount`, not `umount2`).

## 11. P-C (alternative, if a prop-file swap is really wanted)

Do not replace `/system/build.prop`; replace instead a file that is read **after** it and whose
loss is tolerable: `/odm_dlkm/etc/build.prop` (source #11, string
`0x24517`; in this binary it is read inside `PropertyLoadBootDefaults`):

```
cave 0x1EF9D0 (40 B):
  a0 f1 ff f0  00 fc 26 91  a1 f1 ff b0  21 5c 14 91
  e2 03 1f aa  03 00 82 d2  e4 03 1f aa  08 05 80 d2
  01 00 00 d4  33 08 fc 17
```

`adrp x1, #0x24000; add x1,x1,#0x517` → `0x24517` = `/odm_dlkm/etc/build.prop`.
Risk: if the file does not exist the bind silently does nothing (no-op); if it
does exist, the odm_dlkm properties are lost (not critical, but it must be
checked). P-B is safer.

---

## 12. Corrections to earlier documents

| where | was | fact |
|---|---|---|
| `re-vendor-boot-q1.md` §7, `re-init-prop-gate.md` §1 | PID 1 = `/init` from the **boot** ramdisk | after v8lite: PID 1 = the vendor-ramdisk `/system/bin/init` (vinit, `de409287…`); the boot ramdisk is not unpacked at all; this document analyses exactly it |
| `re-vendor-boot-q1.md` §4 | second stage = `/system/bin/init` from system.img, "the root is the ramdisk" | the second stage's root is the **system partition** (two `SwitchRoot`: `0xF1994` → `/first_stage_ramdisk`, `0xF4E74` → `/system`) |
| `re-v7-rootfs-prop.md` §2 | `debug_ramdisk/` in the cpio — "the lower layer" under the tmpfs | after the two `SwitchRoot` calls the lower layer is an empty directory created by `mkdir` in `SwitchRoot` (`0x13B5D0`); the ramdisk files are deleted by `FreeRamdisk` (`0xF1A28`) |
| cpio offsets in `re-init-prop-gate.md` §6 (P2) | data-off of `system/bin/init` = `0x30A5F74` | **0x30AE6BC** |
| `re-init-prop-gate.md` §2.2 | `/force_debuggable` "is mandatory" | correct, but it matters that it must be in the **ramdisk root**, not in `first_stage_ramdisk/` |
| this document §0.4 / §8 | hook at `0xF1AC0`, 40-byte cave ("P-A/P-B") | the flashed images hook `0xF1AC4` with the 52-byte cave; P-A was never used (it breaks `/system/build.prop`, §9) |

---

## 13. Reproduction

```sh
cd /tmp/opencode

# 1) function bounds and xrefs
readelf --debug-dump=frames vinit | grep -oE 'pc=[0-9a-f]+\.\.[0-9a-f]+' > fderanges.txt
python3 annot.py 0xeedfc 0xf2124 | grep '; "'      # FirstStageMain
python3 annot.py 0xf1928 0xf19b0                    # mkdir/bind/SwitchRoot
python3 annot.py 0x13b32c 0x13b720                  # SwitchRoot
python3 annot.py 0xf4cf8 0xf4f10                    # TrySwitchSystemAsRoot

# 2) patch + check
python3 mkpatch.py                                  # -> /tmp/opencode/vinit.patched
readelf -lW vinit.patched | grep LOAD
python3 - <<'PY'
from capstone import *
d=open('/tmp/opencode/vinit.patched','rb').read()
md=Cs(CS_ARCH_ARM64,CS_MODE_ARM)
for a,n in ((0xf1ac0,8),(0x1ef9d0,40)):
    for i in md.disasm(d[a:a+n],a):
        print('%#08x %-8s %s %s'%(i.address,i.bytes.hex(),i.mnemonic,i.op_str))
PY
sha256sum vinit.patched        # cb2f7537…1bf81a (P-A)

# 3) LK
python3 - <<'PY'
d=open('/home/musin/mtkclient/docs/notes/rmx3630-lk/lk_payload.bin','rb').read()
i=d.find(b'androidboot.force_normal_boot=1'); print(hex(i))   # 0x92646
PY
```

Everything listed is read-only with respect to the device; only files in
`/tmp/opencode` and this document were modified.
