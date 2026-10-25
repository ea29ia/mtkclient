# DATA-ONLY permissive SELinux on RMX3630 (MT6789, Android 14): LK cmdline → bootconfig → init

Date: 2026-10-25. Target device: Realme RMX3630 (realme 10 4G), MT6789, Android 14, build
`RMX3630_14.0.0.420(EX01)`, kernel `5.10.209-android12-9-o-05206-g23c1467af8f7`, unlocked bootloader
(`seccfg lock_state=3`, `ro.boot.verifiedbootstate=orange`), boot image not verified by LK
(`img_auth_required=0`, `avb_ret=0`). Base image: `/home/musin/vendor_boot_v14.img`
(md5 `ad5c09b9e75b6cc5daa137e875b1a98d`, 64 MiB, VNDRBOOT v4).
corrected: an earlier draft called the device unlocked on the basis of `ro.boot.flash.locked=0`
alone; the authoritative markers are `seccfg lock_state=3` plus `ro.boot.verifiedbootstate=orange`,
and the reason an unverified image boots is that LK does not authenticate `boot`/`vendor_boot`.

The effective initramfs is the **vendor_boot_a ramdisk**, not the `boot_a` one: a boot image whose
ramdisk contains no `/init` still boots, i.e. the `boot_a` ramdisk is never unpacked. The
vendor-ramdisk `/init` is a symlink to `/system/bin/init`, which runs `FirstStageMain`, then
`SwitchRoot("/first_stage_ramdisk")`, `SwitchRoot("/system")` and finally
`execv("/system/bin/init", {"selinux_setup"})`; the patch hook sits at `0xF1AC4` of that binary.

Everything below is static (offline) analysis of `docs/notes/rmx3630-lk/lk_payload.bin`,
`/tmp/opencode/sysa/system/bin/init` (system.img init, 3 085 160 B, sha256 `a458669b…`, VA==offset),
`/tmp/opencode/vinit` (vendor-ramdisk `/system/bin/init`, 2 097 128 B, sha256 `de409287…`),
`/home/musin/system_a.erofs:/system/etc/selinux/plat_sepolicy.cil`, plus read-only `adb shell`
queries (`getprop`, `ps`, `getenforce`). **Nothing was flashed or written to the device** while this
analysis was made; the resulting image was flashed afterwards (results in §4.4).

---

## 0. TL;DR verdict

| question | verdict |
|---|---|
| 1. LK forwards the vendor_boot **header cmdline**? | **YES.** Appended verbatim (with a leading space) to LK's kernel-cmdline buffer right before the bootconfig conversion. It does **not** sanitise `androidboot.*` — it *moves* those tokens into a bootconfig blob it generates itself. |
| 2. LK uses the image **bootconfig** section? | **NO** — dead. LK never reads `bootconfig_size` (hdr+0x84C) or the fragment table (`+0x840/0x844/0x848`). But bootconfig itself **is** delivered: LK *synthesises* a bootconfig blob from the cmdline and puts it at the initrd tail; this kernel (`CONFIG_BOOT_CONFIG=y`) consumes it (proven by `ro.boot.*` reaching userspace). |
| 3. Who decides SELinux mode? | The **system.img init** (= PID 1, `init second_stage`). `SelinuxInitialize()` reads the key `androidboot.selinux` and the value `permissive` from the imported kernel cmdline/bootconfig and calls `security_setenforce(0)`. The vendor-ramdisk first-stage init (`vinit`) does **not** look at `androidboot.selinux` (it only force-permissives in MTK *factory* boot mode). |
| 4. Minimal patch | 31 bytes appended to the vendor_boot **header cmdline**: ` androidboot.selinux=permissive`, at file offsets `0x44..0x62`, NUL terminated. No layout change, no table/bootconfig update, image stays 64 MiB. Built as `/home/musin/vendor_boot_v18_selinux.img`; on the device it yields `getenforce=Permissive`, `ro.boot.selinux=permissive`. |
| 5. `adb root` after permissive | **Confirmed on device.** The only block is the SELinux `process:setcurrent` check, which permissive does not enforce; adbd (APEX, `--root_seclabel=u:r:su:s0`) then runs uid 0 and `setcon("u:r:su:s0")`, giving `uid=0 u:r:su:s0`. |

`CONFIG_SECURITY_SELINUX_DEVELOP=y`, `# CONFIG_SECURITY_SELINUX_BOOTPARAM is not set`,
`# CONFIG_SECURITY_SELINUX_DISABLE is not set`, `CONFIG_BOOT_CONFIG=y`
(read from `/proc/config.gz` on the device and from `docs/notes/rmx3630-lk/ikconfig.txt`).

---

## 1. Q1 — does LK forward the vendor_boot header cmdline?

**Yes. Proven code path (VAs = payload offset + 0x50000000):**

### 1.1 header load

`load_bootinfo_from_hdr` @ **0x50009fe8** (its `__func__` string is `0x50090EDA`).

```
0x5000A004  adrp x1, "ANDROID!" (0x50090EB0) ; memcmp(hdr, "ANDROID!", 8)
0x5000A01C  adrp x1, "VNDRBOOT"  (0x50090EF1) ; memcmp(hdr, "VNDRBOOT", 8)
0x5000A098  adrp x0, 0x501129D0 ; add x0, x0, #0x9D0
0x5000A0A0  mov  w2, #0x850
0x5000A0A8  bl   memcpy          ; memcpy(0x501129D0, vndr_hdr, 0x850)
```

So the whole **vendor_boot v4 header (0x850 B) is kept at `0x501129D0`**, cmdline field (hdr+0x1C)
therefore at **`0x501129EC`**. Getter:

```
0x5000A3A0  (get_vendor_boot_cmdline)
0x5000A3B8  add  x19, x19, #0x9EC      ; == 0x501129D0 + 0x1C
0x5000A3C0  bl   strlen
0x5000A3CC  csel x0, xzr, x19, eq      ; return NULL if empty, else the string
```

### 1.2 append to the kernel cmdline

Inside `boot_linux_from_storage` (0x5000Dxxx; `boot_linux_fdt` is inlined around 0x5000CD00):

```
0x5000DA7C  bl  0x5000A340        ; get_boot_cmdline()        (returns 0x50112390 if non-empty)
0x5000DA80  bl  0x50018204        ; cmdline_append()
0x5000DA84  bl  0x5000A144        ; get_boot_header_version() = [0x50112378] (boot hdr+0x28)
0x5000DA88  cmp w0, #3
0x5000DA8C  b.lo 0x5000DA98       ; vendor_boot exists only for boot hdr v3/v4
0x5000DA90  bl  0x5000A3A0        ; get_vendor_boot_cmdline() (vndr hdr+0x1C!)
0x5000DA94  bl  0x50018204        ; cmdline_append()
```

`cmdline_append` @ **0x50018204**:

```
0x50018264  adrp x2, 0x500B2000 ; add x2, x2, #0x344   ; fmt = " %s"  (0x500B2344)
0x50018274  mov  x3, x19                               ; the string
0x50018278  bl   snprintf                              ; snprintf(cur, end-cur, " %s", s)
0x50018280  add  x8, x8, w0, sxtw ; str x8,[0x50116058] ; advance cursor
```

Buffer: `0x50116050` (base) / `0x50116058` (cursor) / `0x50116060` (end), allocated as **0x800 B**
in the kcmdline init @ 0x50017D30 (string `lib/kcmdline/kcmdline.c` @ 0x50095239). Overflow path
prints `"cmdline buffer is overflow!!!"` (0x5009502F5) and hits the MTK assert, i.e. a boot loop —
see the headroom note in §5.

**Answer:** the vendor_boot header cmdline is concatenated verbatim after the boot image cmdline,
`" "`-separated, no filtering, no rewriting of `androidboot.*`. The stock boot.img cmdline is empty
(`slot_boot_a.img` hdr+0x2C = `""`), so the kernel cmdline starts with
`bootopt=64S3,32N2,64N2 buildvariant=user`.

### 1.3 what happens to `androidboot.*` afterwards — LK moves it into its own bootconfig

`bootconfig_build` @ **0x5000B46C**, called from **0x5000D5F4**:

```
0x5000D5E4  mov  x8, #0x66F00000            ; == vendor_boot hdr .ramdisk_addr
0x5000D5EC  add  x1, x8, w27, uxtw          ; dst = 0x66F00000 + total ramdisk size
0x5000D5F4  bl   0x5000B46C                ; (fdt, dst) -> bootconfig size
0x5000D5FC  add  w9, w22, w27
0x5000D600  add  w9, w9, w0                 ; initrd-end = start + ramdisk + bootconfig
0x5000D624  bl   fdt_setprop("linux,initrd-end")
```

Inside `0x5000B46C`:

| step | VA | what |
|---|---|---|
| alloc 0x800 | 0x5000B490 | buffer A → `0x50113248` (bootconfig body) |
| alloc 0x800 | 0x5000B4CC | buffer B → `0x50113258` (non-androidboot cmdline) |
| read `/chosen/bootargs` | 0x5000B508 / 0x5000B528 | `fdt_path_offset(fdt,"/chosen")`, `fdt_getprop(...,"bootargs",...)` |
| tokenize on `" \t"` | 0x5000B570 (delims `0x50091521`), 0x5000B5C4 | `strtok`-style loop |
| token starts with `androidboot.`? | 0x5000B5DC `strncmp(tok, "androidboot.", 12)` (string `0x50091524`) | if **yes** → append `"\n%s"` (fmt `0x50091531`) to buffer A |
| else | 0x5000B620..0x5000B650 | append `" %s"` (fmt `0x500B2344`) to buffer B |
| write back plain cmdline | 0x5000B6C0 | `fdt_setprop(fdt, chosen, "bootargs", B, strlen(B)+1)` |
| trailer | 0x5000B778..0x5000B7B4 | `size`, `checksum`, magic `"#BOOTCONFIG"` (`0x50091577`) at the tail |
| copy to dst | 0x5000B7B8 | `memcpy(dst, blob, size)`; returns size |

So `androidboot.selinux=permissive` will **not** stay in `/chosen/bootargs`; it becomes one line of
LK's bootconfig blob: `androidboot.selinux=permissive`.

---

## 2. Q2 — is the image's bootconfig section used? Is a bootconfig delivered at all?

Header fields read from the `0x501129D0` copy — complete list (full ADRP+ADD scan of the 935 424 B
payload for every address in `0x501129D0..0x50113220`):

| header field | v4 offset | mirror VA | read at |
|---|---|---|---|
| page_size | 0x00C | 0x501129DC | 0x5000A210, 0x5000A42C, 0x5000A4C0, 0x5000A5E8, 0x5000A6A4, 0x5000A80C, 0x5000A890 |
| kernel_addr | 0x010 | 0x501129E0 | 0x5000A210 (csel pair) |
| ramdisk_addr | 0x014 | 0x501129E4 | 0x5000A57C |
| vendor_ramdisk_size | 0x018 | 0x501129E8 | 0x5000A7B4 |
| **cmdline** | **0x01C** | **0x501129EC** | **0x5000A3B8** |
| dtb_size | 0x834 | 0x50113204 | 0x5000A100 |
| tags_addr | 0x81C | 0x501131EC | 0x5000A9C8 |

**There is no reference to `+0x840` (vendor_ramdisk_table_size), `+0x844` (entry_num),
`+0x848` (entry_size) or `+0x84C` (bootconfig_size) anywhere in the payload.** The only hits for
`0x840..0x84E` in the whole binary are *string* immediates (`0x50090844` = `download:`,
`0x50093836`, `0x5009384E`) in the fastboot/DRM code, not header offsets.

Consequences:

* LK treats the vendor ramdisk as a **single blob** of `vendor_ramdisk_size` bytes located at
  `ramdisk_addr` (`0x66F00000`); the fragment table is ignored (harmless today: 1 platform fragment
  covering the whole blobs).
* The **image bootconfig section is dead** — you can put anything at hdr+0x84C and LK will not look.
  Do not use that route.
* Bootconfig nevertheless **works**, because LK generates it (§1.3) into the initrd tail, and this
  kernel has `CONFIG_BOOT_CONFIG=y`. Empirical proof that this kernel accepts LK's blob:
  the device's image has `bootconfig_size = 0` and the boot.img cmdline is empty, yet these
  LK-only literals are visible in userspace via `getprop ro.boot.*`:

  ```
  adb shell getprop ro.boot.force_normal_boot   -> 1                 (LK str 0x50092646)
  adb shell getprop ro.boot.opt_sim_count       -> 2                 (LK add_cmdline_sim_count)
  adb shell getprop ro.boot.slot_suffix         -> _a                (LK str 0x500926CA)
  adb shell getprop ro.boot.dtbo_idx            -> 1                 (LK str 0x50092729)
  adb shell getprop ro.boot.prjname             -> 2269E             (LK str 0x50091D9B)
  ```
  They can only reach userspace through LK's synthesised bootconfig (LK strips `androidboot.*`
  from `/chosen/bootargs`). ⇒ the route header-cmdline → LK bootconfig → kernel is **live**.

`/proc/cmdline` and `/proc/bootconfig` are 0440 root-only (verified: `cat` → EACCES as shell), so the
final check must be done via `getprop ro.boot.selinux` (§4.4) after the flash.

---

## 3. Q3 — what does init actually read?

PID 1 on the device is the **system.img** init (from `system_a.erofs`), not the vendor-ramdisk copy:

```
adb shell ps -A -o USER,PID,NAME,ARGS | head
root  1  init  init second_stage
```

The first-stage init comes from the vendor_boot_a ramdisk (`/init` → `/system/bin/init`); after
`SwitchRoot("/system")` it `execv`s the **system image's** `/system/bin/init`, and that binary is
the one that owns PID 1 and runs `SelinuxInitialize` below.

### 3.1 system init (3 085 160 B, `/tmp/opencode/sysa/system/bin/init`) — the one that decides

`SelinuxInitialize()` ≈ 0x174900–0x174D60 (PLT resolved from `.rela.plt`; note stubs are offset by
one slot: `security_getenforce` = stub 0x2D9880 / GOT 0x2E11B8, `security_setenforce` = stub
0x2D99A0 / GOT 0x2E1248, `security_load_policy` = stub 0x2D9990 / GOT 0x2E1240):

```
0x174BC8/0x174BD0  ... bl security_load_policy            ; load /system/etc/selinux policy
0x174C54           bl security_getenforce                 ; w21 = kernel enforcing (0/1)
0x174C74           str w8,[sp,#0xE0]  (w8=1)              ; is_enforcing = true (default)
0x174C60..0x174CB4 std::function(vtable 0x2DCF30) + invoke  ; phase 1: import cmdline/bootconfig
0x174CB8           ldr w8,[sp,#0xE0]; cmp #1
0x174CC4..0x174D24 std::function(vtable 0x2DCF78) + invoke  ; phase 2 (second source: /proc/bootconfig)
0x174D28..0x174D40 w9=(w21!=1); w21=(w8==1); w8=w9^w21
0x174D40           tbnz w8 -> 0x174D60                    ; if (kernel_enforcing == is_enforcing) skip
0x174D48           bl security_setenforce(w21)             ; <-- the only setenforce call site in init
0x174D50           PLOG(FATAL) 'security_setenforce(' …    ; str 0x2C207
```

The two lambdas that set `is_enforcing = false`:

```
IsEnforcing lambda        0x179730   (vtable 0x2DCF78, thunk 0x1796D0)
ProcessKernelCmdline      0x1795F0   (vtable 0x2DCF30)
    cmp  key_len, #0x13   (19 = strlen("androidboot.selinux"))
    cmp  key, "androidboot.selinux"   (str 0x21E11, len 19)
    cmp  val_len, #0xA    (10 = strlen("permissive"))
    cmp  val, "permissive"            (str 0x1F2AD, len 10)
    ldr  x8,[x19,#8]; str wzr,[x8]    ; captured bool = 0  (=> permissive)
```

Accepted values: **only the literal `permissive`** ⇒ `security_setenforce(0)`. `enforcing` and
`disabled` are *not* recognised (they just leave the default `true`). Because
`CONFIG_SECURITY_SELINUX_DEVELOP=y`, the `setenforce` write to `/sys/fs/selinux/enforce` is legal
for init (it is still in the kernel domain at that point).

`ALLOW_PERMISSIVE_SELINUX` is compiled **in**: the comparison code, the string `"permissive"` and
the `security_setenforce` call are all present (a build with `ALLOW_PERMISSIVE_SELINUX=0` compiles
them out entirely). Consistent with `ro.debuggable=1`.

Oplus extra (cosmetic): `"Permissive SELinux boot, forcing sys.init.perf_lsm_hooks to 1."`
(str `0x1C25D`, used at 0x1702D8) — the ROM explicitly supports permissive boots and flips that
property.

### 3.2 first-stage vendor init (`/tmp/opencode/vinit`, 2 097 128 B) — does NOT do it

Same `SelinuxInitialize` shape at 0x1345E8, `security_setenforce` stub 0x1EF050 called once at
**0x1348F0**, but the decision is:

```
0x13480C  bl security_getenforce                      ; w21
0x13481C  open("/sys/class/BOOT/BOOT/boot/boot_mode", O_RDONLY)   ; str 0x18FAE
0x134834  read(fd, buf, 3); atoi(buf)
0x134860  cmp w0, #4                                  ; 4 == MTK FACTORY boot mode
0x134864  b.ne 0x1348E0                               ; not factory -> enforce
0x134874  cmp w21,#1 ; b.ne 0x134908 ; w21=0 ; b 0x1348EC -> setenforce(0)
0x1348E0  cmp w21,#1 ; b.eq 0x134908 ; w21=1                     -> setenforce(1)
```

No `androidboot.selinux` string exists in `vinit` (0 hits; the `"permissive"` strings are inside
longer log messages). It only goes permissive in MTK *factory* mode (`boot_mode` sysfs == 4), which
we cannot reach from the boot image. That is fine: `vinit` runs first, the system.img init runs
later and the **last writer wins** ⇒ permissive.

---

## 4. Q4 — exact patch

### 4.1 what to change

vendor_boot v4 header, **cmdline field at file offset 0x1C, 2048 bytes (0x1C..0x81B)**. Current
value `"bootopt=64S3,32N2,64N2 buildvariant=user"` (40 chars, NUL padded). Append

```
" androidboot.selinux=permissive"      # 31 bytes (space + 30)
```

⇒ new field is 71 chars, remaining 1977 bytes stay NUL. Only file bytes **0x44..0x62** change
(the NULs they overwrite were already zero).

Nothing else changes:

* `bootconfig_size` stays `0` (LK ignores it anyway, §2);
* fragment table stays `108/1/108`, `table[0].size` is still `vendor_ramdisk_size` = 42 629 225
  (0x28A7869) — the ramdisk is **not** touched or recompressed;
* layout unchanged: ramdisk@0x1000, dtb@0x28A9000, table@0x28D8000, bootconfig@0x28D9000;
* file stays 64 MiB (0x4000000).

### 4.2 recipe (data-only, no re-build of the ramdisk)

```python
#!/usr/bin/env python3
# patch_selinux_permissive.py  -- data-only vendor_boot v4 cmdline patch
import struct, hashlib
SRC = 'vendor_boot_v14.img'          # md5 ad5c09b9e75b6cc5daa137e875b1a98d
OUT = 'vendor_boot_v18_selinux.img'
CMD_OFF, CMD_MAX = 0x1C, 2048
OLD = "bootopt=64S3,32N2,64N2 buildvariant=user"
NEW = OLD + " androidboot.selinux=permissive"

d = open(SRC, 'rb').read()
assert len(d) == 64 * 1024 * 1024
assert d[:8] == b'VNDRBOOT' and struct.unpack_from('<I', d, 8)[0] == 4
cur = d[CMD_OFF:CMD_OFF + CMD_MAX].split(b'\0')[0].decode()
assert cur == OLD, cur
assert len(NEW) <= CMD_MAX

o = bytearray(d)
o[CMD_OFF:CMD_OFF + CMD_MAX] = NEW.encode() + b'\0' * (CMD_MAX - len(NEW))
open(OUT, 'wb').write(o)

# ---- verify ----
n = bytes(o)
assert len(n) == 64 * 1024 * 1024
g = lambda off: struct.unpack_from('<I', n, off)[0]
assert n[CMD_OFF:CMD_OFF + CMD_MAX].split(b'\0')[0].decode() == NEW
assert g(0x18) == 42629225 and g(0x834) == 191577           # ramdisk size, dtb size
assert (g(0x840), g(0x844), g(0x848), g(0x84C)) == (108, 1, 108, 0)
al = lambda x: (x + 0xFFF) // 0x1000 * 0x1000
r, dtb = 0x1000, al(0x1000 + g(0x18))
tab, bc = al(dtb + g(0x834)), al(al(dtb + g(0x834)) + 108)
for off, size in ((r, g(0x18)), (dtb, g(0x834)), (tab, 108), (bc, 0)):
    assert d[off:off + size] == n[off:off + size]           # ramdisk/dtb/table/bootconfig identical
diff = [i for i in range(len(d)) if d[i] != n[i]]
assert min(diff) >= CMD_OFF and max(diff) < CMD_OFF + len(NEW)
print("differing bytes:", len(diff), hex(min(diff)), hex(max(diff)))
print("md5   ", hashlib.md5(n).hexdigest())
print("sha256", hashlib.sha256(n).hexdigest())
```

Executed result (already built, **not flashed**):

```
differing bytes: 31 0x44 0x62
md5    1d6a665a8422cffc4e3a56bfd2950079
sha256 bd2064aecf7b3d215bcd0ef010d3bd2f7810b1541e5ade9b344029139940932d
size 67108864   cmdline "bootopt=64S3,32N2,64N2 buildvariant=user androidboot.selinux=permissive"
```

Independent re-parse with `docs/notes/vendor_boot_extract.py --info vendor_boot_v18_selinux.img`
gives the same header, `bootconfig_size 0`, `fragments 1 type=1 codec=lz4-legacy @0x1000`.

### 4.3 why no bootconfig blob is needed

If we wanted the bootconfig route we would have to (a) append `androidboot.selinux=permissive\n` +
the 12-byte trailer `[size][checksum]"#BOOTCONFIG\n"` after the table, (b) set
`bootconfig_size` at 0x84C and (c) shift nothing (bootconfig is last) — but **LK never reads it**
(§2), so that would be dead bytes. The cmdline route is the only live one.

### 4.4 verification after flashing (all shell-readable, no root) — executed, all four matched

```
adb shell getprop ro.boot.selinux     # expect: permissive   (ProcessKernelCmdline imports androidboot.* -> ro.boot.*)
adb shell getenforce                  # expect: Permissive   (authoritative)
adb shell id                          # still uid=2000 shell (adbd not restarted as root yet)
adb root                              # expect: "restarting adbd as root" (no AVC abort)
adb shell id                          # expect: uid=0(root) ... context=u:r:su:s0
```

All five lines above were reproduced on the device with `vendor_boot_v18_selinux.img`; `adb root`
then gives `uid=0 u:r:su:s0`. Follow-ups built on this image (same cmdline, same 31 bytes):
`vendor_boot_v19_root.img` (md5 `93d4cbb183752c47f571928d80aadd76`) adds `service.adb.root=1` to
`adb_debug.prop`, so root comes up without `adb root` (verified over two reboots); the current image
`vendor_boot_v22_magisk.img` (md5 `a874a5c217d2e42aa7813a151bbd78be`) is v19 plus Magisk.

If `getprop ro.boot.selinux` is `permissive` but `getenforce` still says `Enforcing`, the problem is
not the cmdline (LK did its job) — look at a later `setenforce(1)` writer.

---

## 5. Risks / what breaks / recovery

### 5.1 LK buffer headroom (the only *boot* risk)

* cmdline buffer = 0x800 B, bootconfig body buffer = 0x800 B; overflow → assert
  (`"cmdline buffer is overflow!!!"` 0x5009502F5 / `cmdline_append` error 0x500182B8) = bootloop.
* Current usage, measured from the device: 24 `ro.boot.*` keys ⇒ bootconfig body ≈ **0.9 KiB of
  2 KiB**; the non-androidboot cmdline (`bootopt…`, `buildvariant.buildvariant=user`,
  `oplusboot.mode/serialno/prjname`, `oplus.avbkeysha256`, `root=/dev/ram`, …) ≈ **0.3 KiB**.
  Adding 31 B leaves >1 KiB headroom in both buffers. Safe.

### 5.2 functional risk table

Measured on the stock (non-permissive) image, this is the only thing that stops
`adb root`:

```
avc: denied { setcurrent } for scontext=u:r:adbd:s0 tcontext=u:r:adbd:s0 tclass=process permissive=0
```

| area | effect of `setenforce 0` | severity |
|---|---|---|
| `adb root` / adbd | the measured block (`process:setcurrent`, scontext=adbd tcontext=adbd) stops being enforced (logged as `permissive=1`). adbd runs from APEX: `/apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0` (from `/system/etc/init/hw/init.usb.rc:15`, service `seclabel u:r:adbd:s0`, `user` unset ⇒ root) ⇒ uid 0. | **intended** |
| SELinux enforcement globally | every avc denial becomes a log line; any process can do anything, incl. contexts that are `neverallow`ed (e.g. `neverallow adbd domain (process (dyntransition))`, plat_sepolicy.cil:17123). Security is gone until reverted. | high (by design) |
| keystore / Keymaster / TEE | not stopped: keymaster runs in TEE, unaffected by the APEX/system SELinux mode. Key *attestation* that asserts `verifiedbootstate` is already broken (`orange`, unlocked) — no additional change from permissive. | low |
| Play Integrity / GMS / banking apps | already failing today (unlocked, orange, custom vendor_boot). Permissive can be detected additionally (`ro.boot.selinux`, `getenforce`) and some apps refuse. | medium (was already broken) |
| Oplus/Realme services | ROM explicitly handles it: `"Permissive SELinux boot, forcing sys.init.perf_lsm_hooks to 1."` (init 0x1C25D / 0x1702D8). Expect extra avc spam in logcat/dmesg; no known hard dependency. | low-medium |
| vold / mounts / erofs ro | unchanged: no mount option depends on the mode; `system`/`vendor` stay erofs read-only, `/data` still FBE. | none |
| dm-verity / AVB | unchanged; vendor_boot is not verified by LK on this device (`img_auth_required=0`). | none |
| `su` domain | `(type su)` and `(type su_exec)` exist (plat_sepolicy.cil:4080/4082), `su` is a member of the `domain` attribute (line 761), but there is **no** `allow adbd su …` and no `setcurrent` allow for adbd: only `runas, app_zygote, simpleperf_app_runner, system_server_startup, webview_zygote, zygote` have `(allow X self (process (setcurrent)))`. Under permissive adbd's `setcon()` succeeds anyway (denial logged) and the shell comes up as **`u:r:su:s0`** with uid 0 — confirmed on device. | intended |

### 5.3 recovery (bootloop / no adb)

The image is not verified by LK, so a bad vendor_boot cannot brick the device — worst case it does
not boot Android. Recovery = reflash the old image from **preloader mode**
(phone off, Vol Up + Vol Down + Power + USB ⇒ `22d9:0006`):

```bash
cd /home/musin
FLASH_IMG=/home/musin/vendor_boot_v14.img FLASH_PART=vendor_boot_a FLASH_GO=1 \
    ./run_flash_vendor_boot.sh
```

(`run_flash_vendor_boot.sh` defaults to `/home/musin/vendor_boot_v9.img`; the env var overrides it.
The same script flashed v14, so it is the known-good path. `slot_vendor_boot_a.img`
md5 `2aadbb47e2ba10b917ee7034740f6afa` is the untouched stock dump, and
`vendor_boot_a_backup_20261025_*.img` are the DA readbacks.)

If fastboot is reachable instead (unlocked device ⇒ `flash:` is allowed), the equivalent is
`fastboot flash vendor_boot_a vendor_boot_v14.img`.

---

## 6. Falsification / open items

* We could not read `/proc/cmdline` or `/proc/bootconfig` (0440 root-only) — the header→kernel
  forwarding is proven from LK code plus the `ro.boot.force_normal_boot=1` round-trip, not from a
  direct readback. After the flash, `getprop ro.boot.selinux` is the readback proof.
* The measured AVC is same-type (`tcontext=u:r:adbd:s0`) while `init.usb.rc` passes
  `--root_seclabel=u:r:su:s0`; the exact setcon target inside adbd was not pinned down
  (`selinux_android_setcon` is called once, at `adbd_from_payload` 0xA0674, with the string from
  `[0x1E5000+0x618]`). Either way permissive makes the check non-fatal; the measured result is uid 0
  with `u:r:su:s0` (confirmed by `adb shell id`).
* Not analysed: whether any Oplus userspace daemon re-asserts enforcing (a `setenforce 1` writer
  outside init). `security_setenforce` appears only once in the system init; a vendor binary could
  still do it. The `getenforce` check in §4.4 catches this immediately.

## 7. Repro (offline)

```bash
cd /home/musin
python3 mtkclient/docs/notes/vendor_boot_extract.py --info vendor_boot_v14.img
python3 - <<'EOF'   # the snippet from §4.2
...
EOF
md5sum vendor_boot_v14.img vendor_boot_v18_selinux.img
```

LK reference dump helpers used here: capstone + a 21-bit ADRP/ADD cross-reference scanner over
`docs/notes/rmx3630-lk/lk_payload.bin` with `VA = file_offset + 0x50000000` (same convention as
`re-lk-rescue-surfaces.md`).
