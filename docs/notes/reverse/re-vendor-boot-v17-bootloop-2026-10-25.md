# Why the v17 first-stage cave bootloops — RMX3630 (MT6789, Android 14)

Date: 2026-10-25. Offline analysis + read-only `adb shell` only; nothing was flashed or written to the device
*during this analysis* (v17 itself had been flashed earlier — that is exactly why the device looped).
Scope: `vendor_boot` ramdisk `system/bin/init` (2,097,128 B ELF64 PIE, vaddr == file offset), hook at
`FirstStageMain` `0xF1AC4` (`mov x0,x19` -> `bl 0x1EF9D0`), cave in the zero padding `0x1EF9D0..0x1F0000`
(1584 B, last page of the R E `PT_LOAD`).

---

## 0. TL;DR (ranked)

1. **The bootloop is not the code. `/home/musin/vendor_boot_v17.img` is a structurally corrupt image.**
   Its `dtb` region is zeroed past `dtb+0x106C` (of `0x2EC59`) and its whole `vendor_ramdisk_table`
   entry is zero (`size=0`, `offset=0`, `type=0=NONE`), while the header still advertises
   `vendor_ramdisk_table_size=108`, `entry_num=1`, `entry_size=108`.
   A `type=NONE / size=0` fragment means *no platform ramdisk*, and a 99.1 %-zeroed FDT means the
   bootloader cannot apply the DT. Either one alone is fatal.
2. The md5 in the task brief (`dbcefcac…`) is **stale**. The file on disk is `4c30b1c3…`, and the
   device-partition read-backs taken at 15:58:35 and 16:13:07 are **byte-identical to it** — i.e. this
   corrupt image is exactly what the device had in `vendor_boot_a` while it was looping.
3. The cave's encodings and ABI are correct (capstone + unicorn verified). Every one of the 41
   instructions does what it was intended to do. The `execve("/system/bin/sh")` step is denied by
   SELinux, but *harmlessly* (child exits), so it cannot be the loop cause.
4. The `adb_keys` goal itself is unachievable from this hook on this device: `/data` is
   `latemount` (mounted in second stage, **after** the policy is loaded) and the vendored policy only
   allows `adbd` (read) and `system_server` (rw) on `adb_keys_file`. v14's `ro.adb.secure=0` bind-mount
   (what the device was running at the time, verified) is the actual adb-authorisation bypass.
   corrected: that is not "root" — `uid=0` came later, from the permissive `androidboot.selinux=permissive`
   cmdline (v18) plus `service.adb.root=1` (v19).

---

## 1. Artifacts, and the md5 discrepancy

| file | md5 (measured) | note |
|---|---|---|
| `/home/musin/vendor_boot_v14.img` | `ad5c09b9e75b6cc5daa137e875b1a98d` | matches brief; boots |
| `/home/musin/vendor_boot_v17.img` | **`4c30b1c36e45c627c7e20f671ef0c676`** | brief said `dbcefcac…` — file was rebuilt after the brief was written |
| `/home/musin/vendor_boot_v17a.img` | `6704ba8a1f3af10f541bb19d965fe1f3` | matches brief; valid package |
| `vendor_boot_a_backup_20261025_155835.img` | `4c30b1c36e45c627c7e20f671ef0c676` | read-back from device |
| `vendor_boot_a_backup_20261025_161307.img` | `4c30b1c36e45c627c7e20f671ef0c676` | read-back from device |

So the artifact that looped is the one we have; the "code bisect" v17→v17a silently changed three
things at once (cave child body **and** dtb **and** table).

---

## 2. Q1 — byte audit of the v17 hook and cave

Extraction: `vendor_boot` header v4 -> `vendor_ramdisk_size` @0x18, payload at 0x1000, lz4-legacy
(`02 21 4c 18`), cpio newc entry `system/bin/init`.

**Every byte that differs between the working v14 and the looping v17 is one contiguous region:**

```
diff v14 -> v17 (2,097,128 B images): exactly 1 region
  0x1EF9F8 .. 0x1EFE8E  (1174 B)
```
`0xF1AC4` is `c3f70394` in *both* builds, the 10-instruction prologue `0x1EF9D0..0x1EF9F8` is
byte-identical to v14, and the program headers are identical (v14 already had
`p_filesz = p_memsz = 0x13F000`, i.e. the cave page was already mapped R-X).

Cave extension (`0x1EF9F8..0x1EFA70`, 31 instructions), as disassembled from the v17 ramdisk:

| addr | bytes | disasm | intent | ok |
|---|---|---|---|---|
| 1EF9F8 | ff0301d1 | `sub sp, sp, #0x40` | reserve argv | ✅ |
| 1EF9FC | 00000090 | `adrp x0, #0x1ef000` | | ✅ |
| 1EFA00 | 00d02991 | `add x0, x0, #0xa74` | `"/system/bin/sh"` = 0x1EFA74 | ✅ |
| 1EFA04 | 01000090 | `adrp x1, #0x1ef000` | | ✅ |
| 1EFA08 | 210c2a91 | `add x1, x1, #0xa83` | `"-c"` = 0x1EFA83 | ✅ |
| 1EFA0C | e00700a9 | `stp x0, x1, [sp]` | argv[0], argv[1] | ✅ |
| 1EFA10 | 02000090 | `adrp x2, #0x1ef000` | | ✅ |
| 1EFA14 | 42182a91 | `add x2, x2, #0xa86` | script = 0x1EFA86 | ✅ |
| 1EFA18 | e20b00f9 | `str x2, [sp, #0x10]` | argv[2] | ✅ |
| 1EFA1C | ff0f00f9 | `str xzr, [sp, #0x18]` | argv[3] = NULL | ✅ |
| 1EFA20 | 200280d2 | `mov x0, #0x11` | SIGCHLD (17) | ✅ |
| 1EFA24 | e1031faa | `mov x1, xzr` | stack = NULL (fork-like) | ✅ |
| 1EFA28 | e2031faa | `mov x2, xzr` | parent_tid | ✅ |
| 1EFA2C | e3031faa | `mov x3, xzr` | tls | ✅ |
| 1EFA30 | e4031faa | `mov x4, xzr` | child_tid | ✅ |
| 1EFA34 | e5031faa | `mov x5, xzr` | (unused, 5th arg slot) | ✅ |
| 1EFA38 | 881b80d2 | `mov x8, #0xdc` | __NR_clone = 220 | ✅ |
| 1EFA3C | 010000d4 | `svc #0` | | ✅ |
| 1EFA40 | 20010035 | `cbnz w0, #0x1efa64` | parent if pid != 0 | ✅ |
| 1EFA44 | e00340f9 | `ldr x0, [sp]` | child: path | ✅ |
| 1EFA48 | e1030091 | `mov x1, sp` | child: argv | ✅ |
| 1EFA4C | e2031faa | `mov x2, xzr` | envp = NULL | ✅ |
| 1EFA50 | a81b80d2 | `mov x8, #0xdd` | __NR_execve = 221 | ✅ |
| 1EFA54 | 010000d4 | `svc #0` | | ✅ |
| 1EFA58 | 200080d2 | `mov x0, #1` | | ✅ |
| 1EFA5C | a80b80d2 | `mov x8, #0x5d` | __NR_exit = 93 | ✅ |
| 1EFA60 | 010000d4 | `svc #0` | | ✅ |
| 1EFA64 | ff030191 | `add sp, sp, #0x40` | parent: undo | ✅ |
| 1EFA68 | e10309aa | `mov x1, x9` | parent: restore argv | ✅ |
| 1EFA6C | e00313aa | `mov x0, x19` | parent: path | ✅ |
| 1EFA70 | 1608fc17 | `b #0xf1ac8` | rejoin at execv | ✅ |

`0x1EF9D0..0x1EF9F8` (unchanged from the working v14): `mov x9,x1`; adrp/add `"/debug_ramdisk"`
(0x1633F) into x0 and x1; `mov x2,xzr`; `mov x3,#0x1000` (MS_BIND); `mov x4,xzr`;
`mov x8,#40` (mount); `svc #0`.

**Verdict: 0 mis-encoded instructions.** In particular `stp x0,x1,[sp]` = `0xA90007E0` ✅,
`str x2,[sp,#16]` = `0xF9000BE2` (`e20b00f9`) ✅, `str xzr,[sp,#24]` = `0xF9000FFF` (`ff0f00f9`) ✅,
`movz x8,#220/221/93` = `0xD2801B88`/`0xD2801BA8`/`0xD2800BA8` ✅, `cbnz w0` imm19=9 -> 0x1EFA64 ✅,
`add sp,sp,#0x40` = `0x910103FF` (`ff030191`) ✅.

Three *semantic* observations (not encoding bugs):

* `sub sp,sp,#0x40` happens in the **parent** too, and the 32 B argv block sits at `[sp-0x40, sp-0x20)`
  — i.e. below the current `sp` of `FirstStageMain`. There is no AArch64 red zone; this is inside
  init's 8 MiB stack mapping and unicorn shows `sp` restored exactly, so it is *legal*, but it is the
  one place where v17 differs from the proven v14 in a way that touches live memory.
* All cave bytes live in the **R E** segment (`PT_LOAD #3`, `p_flags=5`, `p_filesz=0x13F000`,
  `0x1EF9D0..0x1F0000`). The strings are readable, but the cave must never be *written* at runtime —
  "put argv in the cave area" is impossible without also extending the RW segment.
* Cave use ends at `0x1EFE8E`; 0x172 B of headroom remain, so the 1215 B claim fits — size was never
  the problem.

---

## 3. Q2 — ABI audit of the hook site

`0xF1AC0: sub x1,x29,#0x30` builds `argv = {"/system/bin/init"(0x20543), "selinux_setup"(0x15505), NULL}`
at `[x29-0x30]` via `stp x19,x8,[x29,#-0x30]` / `stur xzr,[x29,#-0x20]` at `0xF1A84`/`0xF1A88`.

Live at `0xF1AC4`:

| reg | value | live across hook? | cave |
|---|---|---|---|
| x0 | dead (set from x19 by the hooked insn) | no | set to x19 at end |
| **x1** | `argv` = `x29-0x30` | **YES** | saved in x9, restored |
| x2..x5 | dead | no | clobbered (x2..x4 used for clone args) |
| x8 | `"selinux_setup"` ptr, already consumed by the `stp` | no | clobbered (syscall nr) |
| x9 | dead | no | scratch |
| **x19** | `"/system/bin/init"` (0x20543) | **YES** | preserved (`x0=x19` at end) |
| **x20** | `DIR*` from the opendir at 0xF1A?; used by the error path `cbz x20 / closedir` | **YES** | preserved |
| x29 | frame pointer | yes | preserved |
| x30 | return addr from `bl cave` = 0xF1AC8 | **yes** | must stay 0xF1AC8; cave ends with `b`, not `ret` ✅ |
| sp | init stack | yes | v17: transient -0x40; parent restored ✅ |

**Callee identification** (asked explicitly): `0xF1AC8: bl 0x1EDB40`; the stub is
`adrp x16,#0x1f3000 ; ldr x17,[x16,#0x9c8] ; add x16,x16,#0x9c8 ; br x17`
-> GOT slot **0x1F39C8** -> `.rela.plt` -> `.dynsym` = **`execv`**.
(`0x1EDAE0` = `close`, `0x1ED980` = `android::base::ShouldLog`, `0x1EDF50` = `dup2`.)

So it is `execv(path, argv)` — **2 arguments; x2 is not envp** and clobbering x2 is harmless.
The error path (`0xF1ACC: mov w0,#6 ; mov x1,xzr ; bl ShouldLog ; tbnz ; cbz x20 ; mov x0,x20 ; bl closedir`
… `ldur x19,[x29,#-0x50]`) reads only x0, x1, x20 and stack locals `[x29-0x80..-0x40]`; it never reads
x2..x9 and re-loads x19 from the stack. Nothing else is needed.

**Verdict:** ABI-clean. The cave preserves everything that is live.

---

## 4. Q3 — is `clone` legal/safe here?

* Syscall numbers/args in the cave are correct for arm64: clone=220, execve=221, exit=93,
  exit_group=94, mount=40, SIGCHLD=17, `child_stack=NULL` -> fork semantics (`sys_clone` is
  `(flags, stack, parent_tid, tls, child_tid)`; with no `CLONE_VM` the child gets a COW copy).
* **No seccomp, no prctl, no capset, no personality in first stage.** Full PLT call set of
  `FirstStageMain` (`0xEEDFC..0xF1C40`): mount ×9, mknod ×32, mkdir ×8, chmod, access, stat,
  opendir/closedir, execv, dup2, close, setenv, clearenv, setgroups, umask, `__open_2`, plus
  libbase/libc++ helpers. Seccomp is never installed by this init at all (no `seccomp` string in the
  binary); enforcement of the syscall filter is not a factor.
* **SELinux is not yet initialized at the hook.** The policy is loaded later, by
  `SetupSelinux` (`argv[1]=="selinux_setup"`), which then **re-execs** `/system/bin/init` with
  `argv[1]="second_stage"` (string `second_stage` @0x14399 is present for exactly this). That second
  exec is what finally puts PID 1 in `u:r:init:s0`, via the policy rules
  `(allow kernel init (process (transition)))` and `(typetransition kernel init_exec process init)`.
  Consequence: **a child forked at the hook keeps `SECINITSID_KERNEL` ("kernel") forever** — it never
  execs, so it never transitions. After the policy loads, `kernel` allows it almost nothing.
* `execve("/system/bin/sh")` from the child would be evaluated *after* the policy load in the
  normal case (the script's first action is `while [ ! -d /data/misc ]`), and `kernel` has no
  `shell_exec:file entrypoint/execute` rule -> **EACCES**, child exits(1). Harmless (`(a)`), and
  even the very first exec is not the cause of a loop.
* Forking PID 1 at this point is legal. `execv` keeps the PID, so the child remains a child of PID 1;
  SIGCHLD default disposition in first stage means it can linger as a zombie until the second-stage
  SIGCHLD/signalfd handler reaps it. No functional impact; `clone(SIGCHLD)` does not disturb init's
  single-threaded first stage, does not share memory, does not require a stack (NULL = fork).
* Practical caveat: a child that spins without sleeping would burn a core during the ~10-30 s second
  stage. Use `nanosleep`, not a busy loop.

**Verdict:** clone is legal and safe *as a mechanism*; it simply cannot reach the data it wants.

---

## 5. Q4 — structural audit and ranked hypotheses

`vendor_boot` v4 layout is `header(0x850) | ramdisk | dtb | table | bootconfig`, page-aligned
(verified with an independent parser, cross-checked against `magiskboot unpack -h`):

| image | ramdisk_size @0x18 | dtb region == stock dtb | dtb last nonzero | table (size, off, type) | bootconfig |
|---|---|---|---|---|---|
| v9 | 0x28A7481 | yes | 0x2EC57/0x2EC59 | (0x28A7481,0,1) | 0 |
| v10 | 0x28A777E | yes | 0x2EC57 | (0x28A777E,0,1) | 0 |
| v11/v12 | 0x28A7837 | yes | 0x2EC57 | (…,0,1) | 0 |
| v13 | 0x28A7865 | yes | 0x2EC57 | (…,0,1) | 0 |
| **v14** | 0x28A7869 | yes | 0x2EC57 | (0x28A7869,0,**1**) | 0 |
| v15 | 0x28A7866 | yes | 0x2EC57 | (…,0,1) | 0 |
| v16 | 0x28A7878 | yes | 0x2EC57 | (…,0,1) | 0 |
| **v17** | 0x28A7C65 | **NO — zeroed from dtb+0x106C** (corrected: an earlier draft said dtb+0x850) | **0x106B** | **(0,0,0 = NONE)** | 0 |
| v17a | 0x28A7C5F | yes | 0x2EC57 | (0x28A7C5F,0,1) | 0 |

Details on v17:

* dtb area at `0x28A9000`, `dtb_size=0x2EC59`: matches stock for the first `0x106C` bytes, everything
  after is `00`, plus a few stragglers; 107,091 bytes differ. A garbage FDT at `dtb_addr 0x47C80000`
  is not bootable on MTK.
* `vendor_ramdisk_table` @`0x28D8000` = 108 zero bytes while the header says
  `table_size=108, entry_num=1, entry_size=108`. `magiskboot` even reports
  `VND_RAMDISK type=[none] size=[0] fmt=[raw]` for v17 (and `type=[platform]` for all others) — an
  independent parser reaching the same conclusion. A `NONE` fragment contributes **no** platform
  ramdisk -> the kernel gets no `/init`.
* The image stops at `0x28AA06C` (the last non-zero byte is `0x28AA06B`): it was assembled from a
  source/short write that ended there, and everything past it (rest of dtb, table, bootconfig area)
  is zero-fill. That is a packer bug, not a kernel/LK size limit.

**The "dtb offset shifted by 0x1000" theory is falsified:** the dtb is at `0x28A9000` in *all* of
v9..v17a. The repack made the *compressed* ramdisk much larger than stock (42.6 MB vs 35.8 MB — an
inefficient lz4 stream, not a content change), but even v17's `0x28A7C65` stays inside the same page
(`< 0x28A8000`), so nothing shifted. `bootconfig_size=0` in every image, so bootconfig placement is a
zero-length no-op at `0x28D9000`. Hence "the layout is invalid for this LK" is not the explanation;
the *content* is.

Unicorn emulation of the v17 cave (synthetic map, `svc` intercepted, hook context
`x1=argv, x19=0x20543, x30=0xF1AC8`):

```
PARENT (clone->1234): pc=0xf1ac8 sp=0x70008000(=entry) x0=0x20543 x1=argv x30=0xf1ac8
                      mount("/debug_ramdisk","/debug_ramdisk",MS_BIND); clone(17,NULL)
CHILD  (clone->0):    execve("/system/bin/sh", {"/system/bin/sh","-c",<1032B script>,NULL}, NULL)
                      -> fails -> exit(1)
```
i.e. the flow is exactly as designed and returns to `execv` with `sp/x0/x1` restored.

**Ranking**

| # | hypothesis | verdict / evidence |
|---|---|---|
| 1 | **(e) image/package corruption** | **CONFIRMED, fatal.** dtb 99.1 % zero, table entry `NONE/size 0`; v17 is the only such image of ten; device read-back is byte-identical. |
| 2 | (a) child `execve(sh)` denied -> child exits | True (kernel domain has no `shell_exec` rule) but **harmless**; cannot loop. |
| 3 | (c) stack manipulation | Only real code-level risk. Unicorn: `sp` restored exactly, block is 0x40 B inside an 8 MiB stack; v17a runs the same code. Low. |
| 4 | (b) clone breaks init | No evidence: no seccomp, parent path returns correctly, v17a (valid image) exercises it. |
| 5 | (d) strings / `adrp` range | Exonerated: unicorn resolves 0x1EFA74/0x1EFA83/0x1EFA86 and the 714 B key inside the mapped R-X page. |

Note the bisect is contaminated: `u17/ramdisk.cpio` and `u17a/ramdisk.cpio` differ in **exactly one
32-byte region**, init `0x1EFA44..0x1EFA64` (the child body), so the *code* delta is clean — but the
*images* differ in package validity too.

---

## 6. Q6 — would SELinux block the write to `/data/misc/adb/adb_keys`?

Yes, unambiguously, and for the child *and* for init.

Label (`plat_file_contexts`, ramdisk): `/data/misc/adb(/.*)?  u:object_r:adb_keys_file:s0`.
Complete set of allow rules touching that type in the device's `plat_sepolicy.cil`
(2,136,014 B, pulled read-only from `/system/etc/selinux/`, plus `/vendor/etc/selinux/vendor_sepolicy.cil`
— no additional rules there):

```
(allow adbd          adb_keys_file (dir  (search)))
(allow adbd          adb_keys_file (file (ioctl read getattr lock map open watch watch_reads)))
(allow system_server adb_keys_file (dir  (ioctl read write create getattr setattr lock rename open watch watch_reads add_name remove_name reparent search rmdir)))
(allow system_server adb_keys_file (file (ioctl read write create getattr setattr lock append map unlink rename open watch watch_reads)))
```

There is **no** `allow init adb_keys_file`, no `allow kernel adb_keys_file`, no `allow shell adb_keys_file`.
So:

* the forked child (`kernel` domain, see §4) is denied on `openat(O_CREAT)` -> EACCES;
* a `u:r:init:s0` process would be denied as well — this is why even a "hook second-stage init" plan
  (option C) does not work;
* the denial cannot be dodged by timing: `/data` is mounted from the fstab entry
  `/dev/block/by-name/userdata /data f2fs … latemount,fileencryption=…` — `latemount` means
  `mount_all --late` in second stage, i.e. **after** `selinux_setup` loaded the policy. There is no
  window in which `/data/misc/adb` exists and policy is not enforced.

The only bypass that works on this device is what v14 already does: bind-mount `/debug_ramdisk` onto
itself so the second stage's `umount("/debug_ramdisk")` pops only our layer and the tmpfs holding
`adb_debug.prop` survives, so init reads `ro.adb.secure=0` (verified live: `getprop ro.adb.secure` = 0,
`ro.debuggable` = 1, `/debug_ramdisk/adb_debug.prop` present). corrected: an earlier draft said the
debug props were bound over `/system/build.prop`; that is variant P-A (40-byte cave, hook `0xF1AC0`),
which deletes `ro.build.version.sdk` and breaks the second stage — it must not be shipped.

---

## 7. Q5 — corrected cave spec (option A chosen)

### Why A

* **B (exec `sh` as PID 1) is the most dangerous of the three.** It makes PID 1 a shell before the
  policy exists, so any script bug, any unexpected `exec` failure, or a policy denial on the final
  `exec /system/bin/init` ends with PID 1 exiting -> `Kernel panic - Attempted to kill init`. It buys
  nothing (same SELinux dead end).
* **C (hook second stage) is not implementable here**: `/system` is EROFS+AVB, the only patchable copy
  of that binary is the ramdisk one (bind-mount over `/system/bin/init` is possible), but the result
  is still `u:r:init:s0`, which the policy does not allow to write `adb_keys_file`.
* **A** keeps the proven mount, never touches the parent's stack, never execs, never depends on
  `/system/bin/sh`, and has a hard 60 s self-terminating child. It is the only shape that cannot
  regress the boot.

### Spec (apply to the stock `system/bin/init`; base = v14's init is already patched)

1. `0xF1AC4`: `e00313aa` (`mov x0,x19`) -> **`c3f70394`** (`bl 0x1EF9D0`).
2. RX `PT_LOAD` #3 (`e_phoff=0x40`, entry 3 -> file offsets `0x108` / `0x110`):
   `p_filesz`/`p_memsz` `0x13E9D0` -> **`0x13F000`** (so `0x1EF9D0..0x1F0000` is mapped).
3. cave at `0x1EF9D0`, 1082 B total (`code 320 B` + strings at `0x1EFB10/0x1EFB20/0x1EFB40`,
   ends `0x1EFE0A`; 502 B still free).

```
0000  e90301aa mov x9,x1              ; save argv
     20f1fff0 / 00fc0c91            ; x0 = "/debug_ramdisk" (0x1633F)  [verbatim v14]
     21f1fff0 / 21fc0c91            ; x1 = same
     020080d2 mov x2,xzr
     030082d2 mov x3,#0x1000
     040080d2 mov x4,xzr
     080580d2 mov x8,#40  ; mount
     010000d4 svc #0
     200280d2 mov x0,#17  ; SIGCHLD
     010080d2 mov x1,#0   ; child_stack = NULL
     020080d2 mov x2,#0
     030080d2 mov x3,#0
     040080d2 mov x4,#0
     881b80d2 mov x8,#220 ; clone
     010000d4 svc #0
     80070035 cbnz w0, 0x1EFB04      ; parent -> return path
--- child: no exec, no shell, no argv, no parent-stack writes
     ff8300d1 sub sp,sp,#0x20        ; child-private COW frame (timespec)
     13000090/73422c91  x19 = "/data/misc/adb"        (0x1EFB10)
     14000090/94822c91  x20 = "/data/misc/adb/adb_keys" (0x1EFB20)
     15000090/b5022d91  x21 = public key blob          (0x1EFB40)
     565980d2 mov x22,#0x2CA         ; key length 714 (incl. '\n')
     972580d2 mov x23,#300           ; retries
loop 600c8092 mov x0,#-100 ; AT_FDCWD
     e10313aa mov x1,x19
     2200a0d2 mov x2,#0x10000       ; O_DIRECTORY
     030080d2 mov x3,#0
     080780d2 mov x8,#56  ; openat
     010000d4 svc #0
     e003f837 tbnz w0,#31, 0x1EFAD0 ; ENOENT/EACCES -> sleep
     280780d2 mov x8,#57 ; close(probe fd)
     010000d4 svc #0
     600c8092 mov x0,#-100
     e10314aa mov x1,x20
     224880d2 mov x2,#0x241         ; O_WRONLY|O_CREAT|O_TRUNC
     033080d2 mov x3,#0x180         ; 0600
     080780d2 mov x8,#56
     010000d4 svc #0
     0004f837 tbnz w0,#31, 0x1EFAF8 ; -> exit(2)
     ea0300aa mov x10,x0
     e0030aaa/e10315aa/e20316aa    ; write(fd, key, 714)
     080880d2 mov x8,#64 ; svc
     e0030aaa/013480d2             ; fchmod(fd,0640)
     880680d2 mov x8,#52 ; svc
     e0030aaa/017d80d2/02fa80d2    ; fchown(fd,1000,2000)
     e80680d2 mov x8,#55 ; svc
     e0030aaa/280780d2             ; close(fd)
     000080d2/a80b80d2/010000d4    ; exit(0)
retry ff0300f9 str xzr,[sp]        ; tv_sec = 0
     607d8152/0040b872             ; w0 = 200000000 (0.2 s)
     e00700f9 str x0,[sp,#8]
     e0030091 mov x0,sp
     010080d2 mov x1,#0
     a80c80d2 mov x8,#101 ; nanosleep
     010000d4 svc #0
     f70600d1 sub x23,x23,#1
     57faff35 cbnz w23, 0x1EFA3C    ; 300 x 0.2 s = 60 s max
fail 400080d2 mov x0,#2
     a80b80d2 mov x8,#93 ; exit(2)
     010000d4 svc #0
parent e10309aa mov x1,x9
     e00313aa mov x0,x19
     ef07fc17 b 0xF1AC8
```

Full 320-byte code blob (little-endian words, this is what the verifier assembled):

```
e90301aa20f1fff000fc0c9121f1fff021fc0c91020080d2030082d2040080d2080580d2010000d4
200280d2010080d2020080d2030080d2040080d2881b80d2010000d480070035ff8300d113000090
73422c911400009094822c9115000090b5022d91565980d2972580d2600c8092e10313aa2200a0d2
030080d2080780d2010000d4e003f837280780d2010000d4600c8092e10314aa224880d2033080d2
080780d2010000d40004f837ea0300aae0030aaae10315aae20316aa080880d2010000d4e0030aaa
013480d2880680d2010000d4e0030aaa017d80d202fa80d2e80680d2010000d4e0030aaa280780d2
010000d4000080d2a80b80d2010000d4ff0300f9607d81520040b872e00700f9e0030091010080d2
a80c80d2010000d4f70600d157faff35400080d2a80b80d2010000d4e10309aae00313aaef07fc17
```
(the original 1215-byte script approach is dropped: 714 B of that was the key itself.)

### Verification

* **capstone 5.0.7**: every instruction above reassembled and disassembled to the intended mnemonic;
  branch targets resolve to `0x1EFB04` (parent), `0x1EFAD0` (retry), `0x1EFAF8` (fail), `0xF1AC8`.
* **unicorn 2.1.4** (installed to `/tmp/opencode/pylibs`), synthetic map, `svc` intercepted:

```
PARENT (clone->pid): pc=0xf1ac8 reached=True sp=0x70008000 x0=0x20543 x1=0x70007fd0 x30=0xf1ac8
                     stack bytes below entry sp: UNTOUCHED (0/128 changed)
CHILD, /data present: openat("/data/misc/adb",O_DIRECTORY)=ok; close;
                     openat("/data/misc/adb/adb_keys",0x241,0600)=ok;
                     write(714,"QAAAAJWBdrJDPrIG3tq7..." ); fchmod(0640); fchown(1000,2000); close; exit(0)
CHILD, /data absent: 300 x openat -> ENOENT with nanosleep in between; exit(2)
```
* **image build** (`/tmp/opencode/vendor_boot_v18.img`, md5 `bc18ce7bad84356435d2878dc9ae34e4`):
  stock layout `dtb@0x2230000, table@0x225F000, bootconfig@0x2260000`, `dtb == stock`,
  `table=(0x222E96C,0,1)`, `magiskboot` parses it as `type=[platform] lz4_legacy`,
  and the embedded `system/bin/init` md5 equals the patched blob (`dcae0be17ebd79577ff896c2e4f6f0c1`).
  Note: this `/tmp` artifact is a P-A experiment and is **not** the image later shipped as
  `/home/musin/vendor_boot_v18_selinux.img` (md5 `1d6a665a8422cffc4e3a56bfd2950079`), which is
  v14 + the 31-byte `androidboot.selinux=permissive` cmdline append.

### Residual risk (be explicit)

This cave **will not create `adb_keys`** on this firmware: after the policy loads the child is in the
`kernel` domain and `openat(O_CREAT)` on `adb_keys_file` is EACCES (§6). It is a *boot-safe* container
for the write, nothing more. Ship it only as the skeleton for a policy-side fix, otherwise keep v14.

---

## 8. Recommendation

1. **Do not debug the cave further.** Fix the packer first. Minimum invariants to assert after every
   build: (a) `header.vendor_ramdisk_size == len(lz4)`; (b) table entry `{size==ramdisk_size,
   offset==0, type==1}`, header `table_size==108/entry_num==1/entry_size==108`; (c) `dtb == stock dtb`
   byte-for-byte and `dtb_size == 0x2EC59`; (d) `file.nonzero_end >= table_offset + 108`;
   (e) the embedded `system/bin/init` md5 equals the intended blob. v17 violates (b), (c) and (d).
2. **Next flash should be `v17a`** (already valid, md5 `6704ba8a…`): if it boots, the package
   hypothesis is confirmed and clone/stack/parent-return are exonerated. If you want the *exact* v17
   code with a valid package, use `/tmp/opencode/vendor_boot_v17fix.img`
   (md5 `6ad0aa0a5eedec9b36fc3d17481bc7e4`, v17 cave bytes + stock dtb + correct table) — that is the
   clean A/B for the script step. (History: `v17a` was **never flashed**; the bootloop was closed by
   the corruption analysis above instead.)
3. **For the auth bypass keep v14** (52-byte mount-only cave). It is what the device was running when
   this analysis was written, and `ro.adb.secure=0` is live there. corrected: the current image is
   `vendor_boot_v22_magisk.img` (md5 `a874a5c217d2e42aa7813a151bbd78be`), built on the v19 lineage
   (permissive cmdline + `service.adb.root=1` + Magisk). `adb_keys` cannot be delivered from
   `vendor_boot` on this device; it would need either a policy change (new `allow init adb_keys_file:file
   { create write … }`, which lives on EROFS+AVB `/system`) or a system-side daemon.
4. If the key material must be carried anyway, the corrected option-A cave above is the safe carrier;
   it costs one child that exits within 60 s and cannot affect PID 1.

---

## 9. Artifacts produced (all offline, nothing flashed)

| path | what |
|---|---|
| `/tmp/opencode/u14/init.bin`, `u17/init.bin`, `u17a/init.bin` | extracted init from each image |
| `/tmp/opencode/caveA.bin` | 1082 B cave blob (md5 `817302ec318e7995035b5d8cbbfa5232`) |
| `/tmp/opencode/u18_init.bin` | stock init + corrected cave (md5 `dcae0be17ebd79577ff896c2e4f6f0c1`) |
| `/tmp/opencode/vendor_boot_v18.img` | corrected cave, valid package (md5 `bc18ce7bad84356435d2878dc9ae34e4`) |
| `/tmp/opencode/vendor_boot_v17fix.img` | v17 cave bytes + valid package (md5 `6ad0aa0a5eedec9b36fc3d17481bc7e4`) |
| `/tmp/opencode/mkcaveA.py`, `emu3.py`, `build_img.py`, `vbhdr.py`, `cpio.py`, `annotate.py` | builder / emulator / parsers |
| `/tmp/opencode/sys/plat_sepolicy.cil`, `vendor_sepolicy.cil` | pulled read-only from the device |
