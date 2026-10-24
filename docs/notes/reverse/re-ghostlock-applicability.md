# GhostLock (CVE-2026-43499) applicability — RMX3630 / realme 10 4G

> **ERRATA (2026-10-24, audit #2):** conclusions conditional on "seccfg/unlock
> succeeds" are moot until the re-lock is solved: the forged lock=3 did not
> survive the reboot (LK re-locked via the RPMB mirror check).
> See `re-unlock-campaign-2026-10-24.md`.

Date: 2026-10-24. Method: kernel extracted from our own `boot.img`
(docs/notes/rmx3630-lk/boot.img → gzip-decompressed 49 MB aarch64 Image),
embedded ikconfig found via `IKCFG_ST` (5800 CONFIG lines) and analyzed.

## Verdict: VULNERABLE — primary targets present

```
Linux version 5.10.198-android12-9-o-gf7a7af5fc933
```

Kernel 5.10 is inside the affected range of CVE-2026-43499
(futex PI stack-UAF via `remove_waiter()` proxy path; introduced 2.6.39,
fixed in 7.1). Confirmed from the device's own embedded kernel config:

```
CONFIG_FUTEX=y
CONFIG_FUTEX_PI=y            <- the ONLY hard requirement (proven present)
CONFIG_RT_MUTEXES=y
```

No special privileges, no namespaces, no kernel config tricks needed to
trigger. This matches the community devices already rooted with GhostLock on
the same SoC family: POCO M6 Pro (Helio G99 Ultra / MT6789, kernel
6.12.30) and RedMagic — i.e., the bug family is being actively exploited on
MT6789-class phones with LOCKED bootloaders.

## Device profile for exploit engineering (from ikconfig + kernel banner)

| Factor | Value | Impact |
|---|---|---|
| Kernel | 5.10.198-android12-9 (GKI-1) | exploit needs 5.10-specific stack-frame/offset tuning (differs from public 6.1/6.12 ports) |
| `CONFIG_CFI_CLANG` | **y** (+ shadow) | kCFI function-signature checks ON: the x86 inet6_protos trick is out; Android path needs same-signature fops swap (NebuSec part-III uses ashmem/configfs) |
| `CONFIG_SHADOW_CALL_STACK` | **y** | ARM64 SCS: classic return-address pivot/ROP over callstack dead; data-only or SCS-aware chain needed |
| `CONFIG_VMAP_STACK` | y | stack-UAF reclaim still works (freed thread stack is vmapped; the waiter frame dies with task exit as in the bug) |
| `CONFIG_RANDOMIZE_BASE` | y | KASLR on; ARM64 linear-map base NOT randomized (1db780bafa4c era) => physmap known; slide leak needed (part-III boot_id/nfulnl trick) |
| `CONFIG_RANDOMIZE_KSTACK_OFFSET` | not in config dump as y/n -> check on device via /proc | 5.10 backport exists; if enabled, frame-depth tuning needs the leak dance |
| `CONFIG_STATIC_USERMODE_HELPER` | absent (5.10 doesn't have it) | DirtyMode-style core_pattern attack viable (modemmanager semantics aside) |
| `CONFIG_SLAB_FREELIST_{RANDOM,HARDENED}` | y,y | standard, public exploits already handle |
| `CONFIG_BPF_JIT_ALWAYS_ON` | y, unpriv bpf NOT off (`BPF_UNPRIV_DEFAULT_OFF` unset) | cBPF/bpf available for sprays if needed |
| SELinux | enforcing (stock) | part-III includes SELinux-disable technique post-root |
| SECCOMP | y (+filter) | app-layer seccomp may constrain syscalls; exploit runs inside a normal app context? -> needs testing |

## What this changes for the campaign

GhostLock gives **temporary root WITHOUT unlocking the bootloader** — directly
usable for the mission's Phase 1 goal (enable ADB for scrcpy on the
dead-screen unit):

1. Root via GhostLock on-device (needs a way to RUN code — see blocker below).
2. With root: `setprop persist.sys.usb.config adb` / `settings put global
   adb_enabled 1`, restart adbd -> scrcpy.
3. Bootloader itself stays locked/verified — LK/RPMB/seccfg work becomes
   OPTIONAL for ADB (still useful for permanence: root-only ADB dies on
   reboot since the exploit must re-run; persistence requires either an
   on-device trigger app started at boot (e.g., autostart via a benign app)
   or the full unlock path).

## The blocker for OUR unit specifically: dead screen + no ADB

GhostLock is a LOCAL userspace exploit: something must execute the exploit
binary ON the device. Our unit has no ADB, no screen — cannot install/run an
APK. Options:

- **Wireless ADB pairing won't help** (needs UI).
- If the phone has ever paired with a Wear/watch or has an accessibility
  service... speculative, not actionable.
- **Realistic route**: our existing PC-path work (unlock or persist-props)
  gets ADB ONCE (any path), and THEN GhostLock gives root on the stock
  locked system with zero flash risk. I.e., GhostLock SOLVES the "root"
  phase (was: unknown after ADB), not the "ADB" phase (solved by unlock/seccfg).
- Alternative: if seccfg/unlock succeeds via DA2, GhostLock becomes the
  cleanest root: no patched boot image, no AVB problems, KernelSU install
  from root shell (boot.img untouched -> LK verification irrelevant).

## Relation to our reverse-engineering stack

- GhostLock root + KernelSU gives us `su` ON the target -> direct block-device
  access from Android -> could replace the DA2 flash path for later steps
  (e.g., write oplusreserve2/misc/seccfg with dd if SELinux allows; RPMB still
  needs the kernel's rpmb char device which respects the write counter).
- Persistence question: KernelSU without unlocked bootloader needs a stock
  boot image patch — NOT possible on locked+AVB (our re-preloader-daa-lk
  proves LK verifies). So the honest model: GhostLock = re-runnable temp root;
  permanent root requires the unlock chain (our main path) OR an always-on
  exploit trigger.

## Confidence

* Kernel version + FUTEX_PI: proven (extracted from our boot.img).
* "Vulnerable": high — version in range + only requirement present; the
  upstream fix (3bfdc63936dd) postdates 5.10.198. But per-build offsets
  (stack frame depth for reclaim, fops addresses) differ from public ports —
  exploit engineering against THIS kernel image still required (use the
  extracted kernel.bin for static offset harvesting).
* Dead-screen blocker for running the exploit: proven environment fact.
