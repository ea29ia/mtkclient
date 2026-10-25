# SELinux → permissive by patching the kernel — RMX3630 / MT6789 / 5.10.209

Date: 2026-10-25. Scope: **offline** RE of `boot_v7.img` + the decompressed
`Image`, the extracted platform policy, and **read-only** `adb shell`
(`getprop`, `ls`, `cat` only). Nothing was flashed or written to the device;
`mtk.py`/DA were not run.

Goal: make `adb root` work by booting SELinux permissive, as the fallback to
the `androidboot.selinux=permissive` (vendor_boot cmdline) route.

**Status: this route was NOT needed.** The vendor_boot cmdline route worked
(`vendor_boot_v18_selinux.img`, 31 bytes at `0x44..0x62` ⇒
`getenforce=Permissive`, `adb root` → `uid=0 u:r:su:s0`), so no kernel was
patched and `boot_a` was left stock. Everything below is kept as the
fallback analysis: the offsets, byte patches and builder were verified
offline only.

---

## 0. TL;DR — the kernel already initialises permissive (userspace turns enforcing on)

This is the important finding, and it changes the answer to question 2(A):

| Fact | Evidence |
|---|---|
| The stock kernel initialises `selinux_state.enforcing = 0` | `selinux_enforcing_boot` (`.data`) is **0** in the image; `selinux_init` stores `!!0` to `state->enforcing` (`strb w8,[x19]`, `cset w8,ne` on a zero input). See §2. |
| The device nevertheless runs Enforcing | `getenforce` = `Enforcing`, `/sys/fs/selinux/enforce` = `1`. |
| Userspace is what turns it on | `vinit` (vendor first-stage init) calls `security_setenforce(1)` at `vinit+0x1348f0` when the kernel is not already enforcing (non-factory boot mode); the system init has the same update in `SelinuxInitialize` (`init+0x174d48`, executed only if `getenforce()` differs from the cmdline-derived state). |
| The kernel was still permissive when init saw it | running property `sys.init.perf_lsm_hooks = 1`, set by init **only when `security_getenforce()==0`** (`init+0x170024`: `bl security_getenforce; cbz w0,<set-prop>`; `vinit` contains the same helper). |

So option **A as literally described ("patch the initial value to 0") is a
no-op on this build** — it is already 0 — and by itself it is undone by init's
single write to `/sys/fs/selinux/enforce`. The missing half is to neutralise
that write.

**Fallback bundle analysed here (8 bytes, two instructions in the decompressed Image; never applied):**

| # | Image offset | VA | stock bytes | patched bytes | meaning |
|---|---|---|---|---|---|
| P1 | `0x25b2164` | `ffffffc00a5b2164` | `68 02 00 39` | `7f 02 00 39` | `selinux_init`: `strb w8,[x19]` → `strb wzr,[x19]` (force `enforcing=0`, immune to `enforcing=` on the cmdline) |
| P2 | `0x931270` | `ffffffc008931270` | `e8 13 40 b9` | `e8 03 1f 2a` | `sel_write_enforce`: `ldr w8,[sp,#0x10]` → `mov w8,wzr` (treat every enforce write as "0") |

P2 alone is enough on the measured firmware (kernel starts at 0); P1 makes it
robust against an `enforcing=1` kernel cmdline. Recompressed kernel is 5 bytes
shorter (`0x137dd70`), still lands on the same ramdisk page `0x137f000`; the
ramdisk, AVB footer and every other byte of `boot_v7.img` are unchanged.
Note that this `boot_a` ramdisk is **never unpacked at boot** — the effective
initramfs is the `vendor_boot_a` ramdisk (proven: a boot image without `/init`
in its ramdisk still boots) — so the ramdisk bytes here are inert either way.

---

## 1. Artifacts and Image mapping

`/home/musin/boot_v7.img` (64 MiB, stock kernel + v7 ramdisk):

corrected: the "v7 ramdisk" inside `boot_a` does not participate in boot. The
`boot_a` ramdisk is not unpacked (a boot image whose ramdisk has no `/init`
still boots); the effective initramfs, including the `/debug_ramdisk` props
trick, lives in the **`vendor_boot_a`** ramdisk. The table below is therefore
a map of the `boot_a` container, not of anything init executes.

| Field | Value |
|---|---|
| magic / header | `ANDROID!`, boot header **v4** |
| `kernel_size` @`0x08` | `0x137dd75` (20,438,389) |
| `ramdisk_size` @`0x0c` | `0x15ad6c` (1,420,652) — **not** `0x18000193`; that is `os_version` @`0x10` |
| kernel payload | file `0x1000`, gzip (`1f 8b 08 00 … 02 03`), md5 `f48f277fb189a77301f9f32270fa1499` |
| ramdisk | file `0x137f000` (`align_up(0x1000+kernel_size)`) |
| AVB0 footer | file `0x1513000` |
| whole file | sha256 `df3f98061277d2d8c069610d5f9608f9cb3e50ffe2e72bafbf7e47535bed3b5f`, md5 `5dbb19b2265a030557b78969368026cd` |

Decompressed `Image` (49,109,052 B, md5 `bcc7a908b26a8bd325f661d7a9b1697f`):
`VA = 0xffffffc008000000 + file_offset` (validated by `linux_banner` @`0x21de7a4`).
Kallsyms decode is the one from
`re-ghostlock-5.10.209-2026-10-25.md` (170,751 symbols).

Extract: `dd if=boot_v7.img bs=1 skip=4096 count=$((0x137dd75)) | gzip -dc > Image`.
`vendor_boot_v14.img` v4 cmdline is `bootopt=64S3,32N2,64N2 buildvariant=user`;
the file contains neither `androidboot.selinux` nor `enforcing=`.

`/proc/config.gz` (running kernel), relevant switches:

```
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_DEVELOP=y          # permissive is not compiled out
# CONFIG_SECURITY_SELINUX_BOOTPARAM is not set
# CONFIG_SECURITY_SELINUX_DISABLE is not set
CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0
CONFIG_LSM="lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"
# CONFIG_SECURITY_SELINUX_ALWAYS_CHECKREQPROT is not present at all
# CONFIG_IMA is not set ; # CONFIG_MODULE_SIG is not set ; # CONFIG_SECURITY_LOCKDOWN_LSM is not set
```

Note the `BOOTPARAM` oddity: even with `CONFIG_SECURITY_SELINUX_BOOTPARAM=n`,
the image **does** contain `enforcing_setup` in `__init.setup`
(pointer @file `0x2864bc8` → `enforcing_setup.cfi_jt`, string `"enforcing="`
@file `0x285a614`). So an `enforcing=1` passed by LK/DT would win over the
static 0. This is why P1 is kept.

---

## 2. Q1a — `selinux_state` and how enforcing is set at boot

All addresses from kallsyms (exact, no KASLR applied); Image offset = VA −
`0xffffffc008000000`.

| Symbol | VA | Image off | Type |
|---|---|---|---|
| `selinux_state` | `ffffffc00ab59488` | `0x2b59488` | B (bss), size `0x88` (`memset(…,0x88)`) |
| `selinux_state.enforcing` | `+0` | `0x2b59488` | byte |
| `selinux_state.checkreqprot` | `+1` | `0x2b59489` | byte |
| `selinux_state.initialized` | `+2` | `0x2b5948a` | byte (read by `security_bounded_transition`) |
| `selinux_checkreqprot_boot` | `ffffffc00ab59484` | `0x2b59484` | b |
| `selinux_enforcing_boot` | `ffffffc00a854c84` | `0x2854c84` | d, **value 0** |
| `selinux_enabled_boot` | `ffffffc00a854c88` | `0x2854c88` | D, value 1 |
| `selinux_init` | `ffffffc00a5b2110` | `0x25b2110` | t |
| `enforcing_setup` | `ffffffc00a5b1fec` | `0x25b1fec` | t |
| `checkreqprot_setup` | `ffffffc00a5b2074` | `0x25b2074` | t |
| `sel_read_enforce` | `ffffffc0089310a0` | `0x9310a0` | t |
| `sel_write_enforce` | `ffffffc0089311d0` | `0x9311d0` | t |
| `sel_enforce_ops` | `ffffffc00a2d4990` | `0x22d4990` | d (`read`=+0x10, `write`=+0x18) |

There is **no kernel symbol `security_setenforce`**. `security_setenforce()` is
libselinux: it writes `/sys/fs/selinux/enforce`, which the kernel handles in
`sel_write_enforce` (file ops confirmed).

`selinux_init` (file `0x25b2110`):

```
0x25b2130  adrp x19, state ; add x19,x19,#0x488
0x25b2138  mov  w2,#0x88
0x25b213c  mov  x0,x19
0x25b2140  mov  w1,wzr
0x25b2144  bl   memset                     ; state = all zero
0x25b2148  adrp x8, 0xffffffc00a854000
0x25b214c  ldr  w8,[x8,#0xc84]             ; selinux_enforcing_boot  == 0
0x25b2150  adrp x9, 0xffffffc00ab59000
0x25b2154  adrp x20, 0xffffffc00ab57000
0x25b2158  add  x20,x20,#0xc40
0x25b215c  cmp  w8,#0
0x25b2160  cset w8,ne                      ; w8 = 0
0x25b2164  strb w8,[x19]                   ; state->enforcing = 0    <-- P1 site
0x25b2168  ldr  w8,[x9,#0x484]             ; selinux_checkreqprot_boot
0x25b217c  cset w8,ne
0x25b2184  strb w8,[x19,#1]                ; state->checkreqprot = 0
```

`enforcing_setup` (file `0x25b1fec`) parses `enforcing=` with `kstrtouint` and
(when it returns 0 from the parse) does `str w8,[x9,#0xc84]` at `0x25b2040`,
i.e. it overwrites `selinux_enforcing_boot`. P1 neutralises that too, because
it forces the value actually stored into the state.

Measured on the running unit (read-only): `getenforce` = `Enforcing`,
`/sys/fs/selinux/enforce` = `1`, `ro.boot.selinux` = *(empty)*,
`ro.boot.verifiedbootstate` = `orange`, `ro.debuggable` = `1`,
`ro.adb.secure` = `0`, `sys.init.perf_lsm_hooks` = `1`.

---

## 3. Q1b — `/proc/self/attr/current` → `selinux_setprocattr`

| Symbol | VA | Image off |
|---|---|---|
| `selinux_setprocattr` | `ffffffc0089276b8` | `0x9276b8` |
| `avc_has_perm` | `ffffffc00891dd88` | `0x91dd88` |
| `avc_denied` (the permissive gate) | `ffffffc00891cb6c` | `0x91cb6c` |
| `security_context_to_sid_core` | `ffffffc0089437d4` | `0x9437d4` |
| `current_is_single_threaded` | `ffffffc008acfe64` | `0xacfe64` |
| `security_bounded_transition` | `ffffffc0089419d4` | `0x9419d4` |

`selinux_setprocattr` selects the permission from the attribute name, then
does one common `avc_has_perm(state, ssid, ssid, SECCLASS_PROCESS=2, perm)`:

| attr | perm | value |
|---|---|---|
| `exec` | `PROCESS__SETEXEC` | `0x00020000` |
| `fscreate` | `PROCESS__SETFSCREATE` | `0x00040000` |
| `keycreate` | `PROCESS__SETKEYCREATE` | `0x10000000` |
| `sockcreate` | `PROCESS__SETSOCKCREATE` | `0x20000000` |
| **`current`** | **`PROCESS__SETCURRENT`** | **`0x01000000`** |

(The values were verified against the kernel's `process_class[]` name array at
Image `0x2995120`; the Android order is fork, transition, sigchld, sigkill,
sigstop, signull, signal, ptrace, getsched, setsched, getsession, getpgid,
setpgid, getcap, setcap, share, getattr, setexec, setfscreate, noatsecure,
siginh, setrlimit, rlimitinh, dyntransition, setcurrent, execmem, … — so
`SETCURRENT = 1<<24` and `DYNTRANSITION = 1<<23 = 0x800000`.)

The `setcurrent` check the device fails is therefore:

```
0x92779c  mov  w4,#0x1000000        ; "current" branch
0x9277a0  adrp x0, state
0x9277a4  add  x0,x0,#0x488
0x9277a8  mov  w3,#2                ; SECCLASS_PROCESS
0x9277ac  mov  w1,w23               ; ssid = old_sid
0x9277b0  mov  w2,w23               ; tsid = old_sid
0x9277b4  mov  x5,xzr
0x9277b8  bl   avc_has_perm         ; <-- the measured { setcurrent } denial
0x9277bc  mov  w24,w0
0x9277c0  cbnz w0, fail
```

The full "current" path after that (only reached if setcurrent passes):

```
0x927924  bl security_context_to_sid_core   ; parse "u:r:su:s0" -> sid
0x927860  bl current_is_single_threaded
0x927864  tbnz w0,#0, 0x927884              ; single-threaded => skip bounded check
0x927878  bl security_bounded_transition    ; policy check, NOT permissive-gated
0x9278a0  bl avc_has_perm                   ; PROCESS__DYNTRANSITION (0x800000)
0x9278dc  str  w22,[x25,#4]                 ; tsec->sid = new sid
```

Permissive is honoured inside `avc_denied` (file `0x91cb6c`):

```
0x91cb88  ldarb w12,[x0]      ; state->enforcing
0x91cb98  tbz   w12,#0, 0x91cbac   ; enforcing==0 -> audit and return 0
0x91cba4  mov   w0,#-0xd           ; enforcing==1 -> -EACCES
```

So when `state->enforcing==0`, **both** the `setcurrent` and the
`dyntransition` checks return 0 regardless of whether an allow exists.

---

## 4. Q3 — will `adb root` actually work in permissive?

### 4.1 Policy facts (extracted `/system/etc/selinux/plat_sepolicy.cil`)

| Fact | CIL |
|---|---|
| `su` is a declared type and a domain | `(type su)` line 4080; `su` is in the `domain` typeattributeset line 761 |
| `su` has role `r` (so `u:r:su:s0` is a valid context) | `(roletype r domain)` line 755, applies to every type in `domain` → `su` |
| `su_exec` exists | `(type su_exec)` line 4082 |
| **No** `allow adbd su:process dyntransition` | grep `(allow adbd su` → nothing |
| **No** `allow adbd self:process setcurrent` | grep `(allow adbd … (process` → transition/siginh/rlimitinh/signal only |
| Inbound neverallow only | `(neverallow base_typeattr_209 adbd (process (dyntransition)))` line 6954 forbids transitions **to** adbd, not adbd→su |
| Runtime `setenforce` is never allowed | `(neverallow base_typeattr_209 kernel (security (setenforce)))` line 8068 with `base_typeattr_209 = (all)`; no `allow … setenforce` exists in plat policy |

corrected: "inbound neverallow only" above is incomplete. There is also an
outbound neverallow, `(neverallow adbd domain (process (dyntransition)))`
(plat_sepolicy.cil:17123), so an **adbd → su dyntransition is explicitly
neverallowed** as well. That does not change the conclusion: permissive
bypasses the check (`avc_denied` returns 0 before the neverallow is enforced
at runtime).

Consequence: under **Enforcing**, adbd's `setcon("u:r:su:s0")` is denied at the
`setcurrent` check (exactly the measured denial) and would then be denied again
at the `dyntransition` check. Under **Permissive**, `avc_has_perm` returns 0 at
both points no matter that no allow exists — this is the explicit answer:
**in permissive the missing allows do not matter.** Nothing else in the policy
needs to change.

The one check permissive does **not** bypass is
`security_bounded_transition()`: it reads `state->initialized` (`[state+2]`),
not `state->enforcing`. It is skipped here because adbd calls `setcon()` while
the daemon is still single-threaded:

* `adbd` receives `--root_seclabel=u:r:su:s0` from `adbd.rc`, calls
  `selinux_android_setcon(root_seclabel)` in `daemon/main.cpp:162`;
* `watchdog::Initialize()` and `adbd_auth_init()` — the first thread spawns —
  are called **after** `drop_privileges()` (`daemon/main.cpp:250` comment).
* For a single-threaded process the kernel takes the `tbnz w0,#0, 0x927884`
  branch and never calls `security_bounded_transition`.

So: `adb root` → adbd restarts as uid 0, `setcon("u:r:su:s0")` succeeds,
`adb shell id` returns `uid=0(root) … context=u:r:su:s0`, and the shell child
inherits that context (the `u:r:shell:s0` switch in `shell_service.cpp` is
inside `#ifdef __ANDROID_RECOVERY__`).

**Residual dependency:** if a future adbd ever calls `setcon()` after spawning
threads, add a third 4-byte NOP at Image `0x927878`
(`57 68 00 94` → `1f 20 03 d5`, `bl security_bounded_transition` → `nop`), or
force the branch at `0x927864` to always skip. On this build it is not needed.

### 4.2 Why the userspace route is fragile on this unit (coordination note)

`vinit` (vendor first-stage init) reads
`/sys/class/BOOT/BOOT/boot/boot_mode` and, for `boot_mode != 4`,
unconditionally does `security_setenforce(1)` if the kernel is not already
enforcing (`vinit+0x1348e0..0x1348f0`). The system init only parses
`androidboot.selinux` later (`init+0x174c2c..0x174d48`). The kernel patch is
order-independent and covers both; a vendor_boot cmdline change must be checked
against the earlier `vinit` write.

corrected: this was checked experimentally — the system init runs after `vinit`
and is the last writer, so a cmdline-only change does win (`vendor_boot_v18`,
`getenforce=Permissive`). The "earlier vinit write" is thus not an obstacle.

---

## 5. Q2 — ranked patches (exact bytes)

All offsets are in the **decompressed Image** (`VA = 0xffffffc008000000 + off`);
inside `boot_v7.img` they are compressed and must be applied after `gzip -dc`.

### Rank 1 — P1 + P2 (recommended fallback, 8 bytes; not applied)

```
P1  0x25b2164 : 68 02 00 39  ->  7f 02 00 39    strb w8,[x19] -> strb wzr,[x19]
P2  0x931270 : e8 13 40 b9  ->  e8 03 1f 2a    ldr  w8,[sp,#0x10] -> mov w8,wzr
```

* Effect: `state->enforcing` is 0 at `selinux_init` and can never be raised by
  a write to `/sys/fs/selinux/enforce`; when init writes `1`, the handler
  normalises it to `0`, sees `new == old == 0`, and returns success without
  touching the state (`0x931290 b.eq 0x9312dc`, which returns `count`).
* What breaks: `setenforce 1` (and `setenforce 0`) become no-ops until reboot;
  SELinux cannot be re-enabled without reflashing a stock kernel. Audit still
  logs denials (`permissive=1`), which is useful.
* Blast radius: **whole system permissive** — all SELinux checks bypassed, so
  every process can use whatever DAC allows. This is a debug/fallback image,
  not a daily driver.
* AVB/dm-verity: survives at runtime (see §6). The embedded AVB footer is now
  stale; it is not read on this boot path.

### Rank 2 — P2 only (4 bytes, minimum on this firmware)

```
P2  0x931270 : e8 13 40 b9  ->  e8 03 1f 2a
```

* Effect: identical to rank 1 on the measured boot, because the stock kernel
  already starts at 0 (`.data` = 0, confirmed at runtime by
  `sys.init.perf_lsm_hooks=1`).
* Fails if the effective kernel cmdline ever contains `enforcing=1` (then
  `selinux_init` sets 1, init sees `kernel_enforcing==is_enforcing==1` and never
  writes, so P2 has nothing to clamp). Add P1 if there is any doubt.
* `setenforce 1/0` become no-ops. Same blast radius as rank 1.

### Rank 3 — B: bypass the setprocattr checks (keeps "Enforcing" label)

```
0x9277b8 : 74 d9 ff 97 -> 1f 20 03 d5   bl avc_has_perm   (setcurrent) -> nop
0x9278a0 : 3a d9 ff 97 -> 1f 20 03 d5   bl avc_has_perm   (dyntransition) -> nop
0x927878 : 57 68 00 94 -> 1f 20 03 d5   bl security_bounded_transition -> nop  (only if multithreaded)
```

* Effect: any process can write any label to `/proc/self/attr/current` and
  become any domain (including `init`/`su`). `getenforce` still says
  `Enforcing`.
* Blast radius: **worse than permissive in practice** — a trivial, app-
  triggerable local root primitive that is silently available, while the
  system still reports Enforcing. Every other SELinux denial remains in force,
  so it does not even solve the general "policy blocks X" problem.
* Verdict: do not use. It was the "surgical" idea but the profile is bad.

### Rank 4 — C: allow `setenforce 0` from the shell

```
0x9312c8 : b0 b2 ff 97 -> 1f 20 03 d5   bl avc_has_perm (SECURITY__SETENFORCE) -> nop
```

* Useless here: `/sys/fs/selinux/enforce` is `0644 root:root`, so uid 2000
  (`shell`) cannot open it for write at all (DAC), independent of SELinux.
  A root process that could write it does not need this patch. In addition,
  plat policy neverallows `setenforce` to `kernel` once enforcing (line 8068),
  so this is a weakening of the last line of defence with no gain.
* Verdict: reject.

### Optional / orthogonal

* `0x25b2164` alone (P1) — **not** a fix; init re-enables. Only useful as the
  first half of rank 1.
* Third patch for B / future multithreaded adbd: `0x927878` → `nop` (above).

---

## 6. Build recipe (tested offline)

Kernel lives in **`boot_a`, not `vendor_boot`** — the v14 `vendor_boot` is a
separate partition (vendor ramdisk/cmdline/DTB). Keep whatever `vendor_boot`
the current working setup uses; only `boot_a` changes.

`mtkclient/tools/build_v7_from_dump.py` is **ramdisk-only**: its build and
`--verify` deliberately assert that the kernel region is byte-identical
(“kernel region byte-identical”, “kernel_size identical”). Do not try to inject
the kernel with it; either post-process the already-working
`boot_v7.img` with the snippet below, or let the tool rebuild the ramdisk and
then swap only the gzip payload (the snippet does exactly the latter on the
finished image).

If the base is a fresh stock `boot_a` dump, first run
`build_v7_from_dump.py DUMP v7.img`, then run the snippet on `v7.img`.
`vendor_boot_v14.img` is **not** an input here and does not need to be rebuilt
for this fallback; it only matters for the parallel cmdline route.

corrected: the v7 builder writes the ramdisk (and `adb_debug.prop`) into
`boot_a`, but that ramdisk is **not unpacked at boot**, so those bytes cannot
make adb work. The props that actually worked (`/debug_ramdisk/adb_debug.prop`
plus the self-bind cave) live in the `vendor_boot_a` ramdisk. For a kernel-only
fallback only the gzip payload in `boot_a` matters; the matching working
`vendor_boot` must still be flashed separately.

Facts used by the builder:

* `gzip.compress(Image, 9, mtime=0)` reproduces the stock kernel payload
  **byte-for-byte** (md5 `f48f277fb189a77301f9f32270fa1499`, same header
  `1f 8b 08 00 00 00 00 00 02 03`, same 20,438,389 B). The toolchain matches.
* With the patches the gzip is 20,438,384 B (`0x137dd70`), 5 B shorter than
  stock. `align_up(0x1000 + 0x137dd70) = 0x137f000`, so the ramdisk offset does
  not move. Only `kernel_size` @`0x08` is rewritten; `ramdisk_size` @`0x0c`
  and every byte from `0x137f000` to EOF (ramdisk + AVB footer) are identical.
* If a different zlib ever makes the gzip cross `0x137e000`, recompute
  `rd_off = align_up(0x1000+len, 0x1000)` and rebuild the whole image with the
  v7/v14 builder (moving the ramdisk also moves the AVB footer). Not the case
  here.

Tested builder (writes `/tmp/opencode/seldec/boot_permissive.img`, 64 MiB):

```python
#!/usr/bin/env python3
# build_permissive_boot.py SRC OUT [--p2-only] [--verify]
import gzip, hashlib, struct, sys
PAGE = 0x1000
P1 = (0x25B2164, bytes.fromhex("68020039"), bytes.fromhex("7f020039"))
P2 = (0x931270,  bytes.fromhex("e81340b9"), bytes.fromhex("e8031f2a"))

def build(src, out, p2_only=False):
    img = bytearray(open(src, "rb").read())
    assert bytes(img[:8]) == b"ANDROID!"
    ks, rs = struct.unpack_from("<II", img, 8)
    assert struct.unpack_from("<I", img, 0x28)[0] == 4
    raw = bytearray(gzip.decompress(bytes(img[PAGE:PAGE+ks])))
    assert len(raw) == 49109052
    assert hashlib.md5(raw).hexdigest() == "bcc7a908b26a8bd325f661d7a9b1697f"
    for off, old, new in ([P2] if p2_only else [P1, P2]):
        assert raw[off:off+4] == old, hex(off)
        raw[off:off+4] = new
    comp = gzip.compress(bytes(raw), 9, mtime=0)
    rd = (PAGE + len(comp) + PAGE - 1) & ~(PAGE - 1)
    assert rd == 0x137F000, hex(rd)
    new = bytearray(img)
    struct.pack_into("<I", new, 0x08, len(comp))       # only header edit
    new[PAGE:rd] = comp + b"\0" * (rd - PAGE - len(comp))
    open(out, "wb").write(new)
    print("Image md5", hashlib.md5(raw).hexdigest(),
          "kernel_size", hex(len(comp)), "sha256", hashlib.sha256(new).hexdigest())
    return new, raw

def verify(src, out, p2_only=False):
    a = open(src, "rb").read(); b = open(out, "rb").read()
    ks = struct.unpack_from("<I", b, 8)[0]
    assert len(b) == 64 << 20 and b[:8] == b"ANDROID!"
    assert (0x1000 + ks + 0xfff) & ~0xfff == 0x137F000
    assert b[0x137F000:] == a[0x137F000:]                 # ramdisk + AVB footer
    assert all(a[i] == b[i] for i in range(0x1000) if not 8 <= i < 12)
    raw = gzip.decompress(b[0x1000:0x1000+ks])
    exp = bytearray(gzip.decompress(a[0x1000:0x1000+struct.unpack_from("<I", a, 8)[0]]))
    for off, _, new in ([P2] if p2_only else [P1, P2]):
        exp[off:off+4] = new
    assert raw == bytes(exp)
    print("PASS: header-only-ks, ramdisk+footer identical, only patch bytes differ")

if __name__ == "__main__":
    args = [x for x in sys.argv[1:] if not x.startswith("--")]
    if "--verify" in sys.argv: verify(args[0], args[1], "--p2-only" in sys.argv)
    else: build(args[0], args[1], "--p2-only" in sys.argv)
```

Produced and verified here:

| Variant | Image md5 | boot sha256 | kernel_size |
|---|---|---|---|
| P1+P2 (rank 1) | `1943f4b1c95b5bac68a1fdd76f70eec6` | `c35010e8ac440395afac5085c5f84ef38471a6e1e2c8011df5f5855f2f074f47` | `0x137dd70` |
| P2 only (rank 2) | `47ed572f9d99ad23a22182c6d14c9a20` | `662b3f4e66d07a5e678ba83babf1ddd975ba83f970fd0897701beb506e560432` | `0x137dd70` |

Independent checks that were run: `gzip -t` equivalent (decompress), header
diff is exactly bytes `0x08..0x0b`, `b[0x137f000:] == a[0x137f000:]`,
decompressed size 49,109,052, and the decompressed Image differs from stock in
exactly the 8 patch bytes (4 for P2-only).

---

## 7. Flash + on-device verification (not done in this study)

Backup first, then write **only `boot_a`**:

```sh
cd ~/mtkclient
# preloader mode: phone OFF, hold Vol Up + Vol Down + Power, plug USB -> 22d9:0006
python3 mtk.py --vid 0x22d9 --pid 0x0006 r boot_a /tmp/boot_a_before.img
sha256sum /tmp/boot_a_before.img
python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a /tmp/opencode/seldec/boot_permissive.img
python3 mtk.py --vid 0x22d9 --pid 0x0006 r boot_a /tmp/boot_a_after.img
cmp /tmp/boot_a_after.img /tmp/opencode/seldec/boot_permissive.img
```

(`fastboot flash boot_a <img>` is equivalent, bootloader is unlocked.)

Expected, read-only, after boot:

```text
getenforce                         -> Permissive
cat /sys/fs/selinux/enforce        -> 0
adb root                           -> restarting adbd as root
adb shell id                       -> uid=0(root) gid=0(root) ... context=u:r:su:s0
adb shell cat /proc/self/attr/current -> u:r:su:s0
logcat/dmesg                       -> avc ... permissive=1 (audit only)
```

If `getenforce` is still `Enforcing`, the patched kernel is not the one that
booted (wrong slot / stale image / build ran on the wrong payload), because
P2 makes the init write a no-op.

corrected: these expectations were never exercised with a patched kernel. The
same post-conditions (`getenforce=Permissive`, `adb root` → `uid=0
u:r:su:s0`) were observed with the cmdline-only image, which is why this
fallback stayed unused.

---

## 8. Recovery

```sh
# A) known-good v7 (stock kernel + v7 ramdisk) -- best first test
python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a /home/musin/boot_v7.img

# B) full stock boot_a (stock kernel + stock ramdisk)
sha256sum /home/musin/boot_a_backup_20261024_225408.img
python3 mtk.py --vid 0x22d9 --pid 0x0006 w boot_a /home/musin/boot_a_backup_20261024_225408.img
# or docs/notes/rmx3630-lk/boot.img, sha256 8c9ef5391a6f90fa43bcf46cdd4eeb4bdbae9b55595b9bdb2e4d84c20d45a8c9

# C) fastboot alternative
fastboot flash boot_a /home/musin/boot_v7.img
```

Distinguishing kernel vs ramdisk:

| Symptom | Likely cause |
|---|---|
| no adb, device resets/loops; `boot_v7.img` (same ramdisk, stock kernel) boots | kernel patch / this boot image |
| no adb, **both** patched and `boot_v7.img` fail | ramdisk/vendor_boot/slot state, not the kernel |
| boots, `getenforce` still Enforcing | P2 not in the running kernel (wrong slot, build from the wrong source, or header size mismatch) |
| permissive, `adb root` still fails | check `ro.debuggable=1` / `service.adb.root`; if `Could not set SELinux context`, the setcon path (bounded transition/threads) needs the optional `0x927878` NOP |
| total silence, no preloader/fastboot | bootloader/partition write issue; recover with preloader + DA and re-check the readback |

A kernel panic usually leaves the device in preloader/fastboot after the
watchdog reset; after recovering to a booting image, `ls /sys/fs/pstore` may
still contain the last `dmesg` (ramoops).

---

## 9. Risk / survival matrix

| | P1+P2 (recommended) | P2 only | B (setprocattr) | C (setenforce) |
|---|---|---|---|---|
| size | 8 B | 4 B | 8–12 B | 4 B |
| gets permissive | yes | yes on this fw | no (label stays Enforcing) | no |
| `setenforce 1` after boot | no-op | no-op | works (still enforcing) | works |
| `adb root` | yes | yes | yes | no (DAC 0644) |
| blast radius | all SELinux checks off | same | any app can `setcon` to any domain (silent root) | removes last guard for root only |
| survives runtime AVB/dm-verity | yes | yes | yes | yes |
| boot image AVB footer | stale hash, unchecked | same | same | same |
| recommended | **yes** | yes if cmdline is known clean | no | no |

Survival details: LK does not authenticate the boot image (`img_auth_required=0`,
`avb_ret=0` measured); dm-verity covers `system`/`vendor`/`product`, not
`boot`; `CONFIG_IMA=n`, `CONFIG_MODULE_SIG=n`, `CONFIG_SECURITY_LOCKDOWN_LSM=n`;
nothing re-hashes the kernel at runtime. The AVB0 footer inside `boot_a` still
contains the stock hash and would be wrong for a patched kernel — harmless on
this path, but do not re-lock the bootloader or run any verifier that checks
`boot` with such an image.

corrected: none of the variants in this matrix was applied. The route that
shipped is the vendor_boot cmdline one (`vendor_boot_v18_selinux.img`,
`getenforce=Permissive`), so `boot_a` and its AVB footer remain stock and
correct. The "recommended" column is a static ranking only.

Open items / not proven on hardware (by design, no flashing here):

1. The two instruction patches are verified statically only; boot behaviour is
   inferred from the disassembly + the stock boot's `sys.init.perf_lsm_hooks=1`.
2. Whether LK ever passes `enforcing=1` is not observable from `shell`
   (`/proc/cmdline` denied). P1 makes it irrelevant if it does.
3. If a future adbd performs `setcon()` from a multithreaded process, add the
   `security_bounded_transition` NOP (§4.1).
