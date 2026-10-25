# GhostLock (CVE-2026-43499) offline feasibility — RMX3630 / MT6789 / 5.10.209

Date: 2026-10-25. Scope: **offline RE only** (kernel Image + `/proc/config.gz`),
plus read-only `adb shell` on the authorised unit
(`SG7DCQW8X8ONCI9T`, uid 2000 shell, `u:r:shell:s0`, SELinux **Enforcing at the
time of measurement** — the unit was later switched to permissive, see below).
Nothing was written to the device, nothing flashed, DA/mtk.py not used.

Target: Realme RMX3630 (realme 10 4G), MT6789, Android 14 / ColorOS
14.0.0.420EX01.

**Campaign outcome (2026-10-25), which supersedes this note's framing:** root was
obtained on this unit **without any kernel exploit** — via the vendor_boot
header cmdline `androidboot.selinux=permissive` (31 bytes) ⇒ SELinux permissive
⇒ `adb root` (uid 0, `u:r:su:s0`, v18/v19), and later via Magisk `su`
(uid 0, `u:r:magisk:s0`, v22 `a874a5c217d2e42aa7813a151bbd78be`). GhostLock was
therefore never ported; the NO-GO below is a statement about cost/benefit, not
about root being unreachable.

---

## 0. TL;DR

| Question | Answer |
|---|---|
| Same build as running kernel? | **Yes, byte-identical payload.** `boot_v7.img` kernel payload md5 `f48f277fb189a77301f9f32270fa1499` == stock `boot_a_backup_20261024_225408.img`; decompressed `Image` md5 `bcc7a908b26a8bd325f661d7a9b1697f`; banner at file `0x21de7a4` says `5.10.209-android12-9-o-05206-g23c1467af8f7 ... Tue Feb 25 12:41:07 UTC 2025`. |
| kallsyms in image? | **Yes**, base-relative, **170 751** symbols. Fully decoded offline (see §1.3). Static addresses below are exact; runtime addresses need the KASLR slide. |
| Futex-PI bug shape present? | **All pre-fix machinery present** (stack `rt_mutex_waiter`, proxy trylock, `remove_waiter`, `exit_pi_state_list`, `attach_to_pi_state`). Build is from Feb-2025, i.e. predates a 2026 fix. Confidence: **high** that it is *vulnerable in principle*; **medium** that the exact 3bfdc63936dd ordering is byte-for-byte unfixed (no fix diff available offline). |
| Practical from shell uid? | **No, not with what is present now** — as measured on the stock enforcing image. After the v18 permissive cmdline, the SELinux domain is no longer the limiting factor (see the outcome note). No KASLR leak reachable from `shell` (`/proc/kallsyms`, `dmesg`, `pagemap`, `/sys/kernel/notes`, module addrs all blocked/zeroed), and kCFI + SCS are active. |
| 1-day from-scratch port? | **NO-GO** (see §5). Also unnecessary: root was already obtained via the permissive vendor_boot cmdline (and later Magisk), with no kernel exploit. |

---

## 1. Kernel identity, load address, kallsyms

### 1.1 Boot image / payload

`/home/musin/boot_v7.img` (`ANDROID!`, header_version 4, 64 MiB):

| Field | Value |
|---|---|
| `kernel_size` @0x08 | `0x137dd75` (20 438 389 B) |
| kernel payload file offset | `0x1000` (gzip, magic `1f 8b 08 00`) |
| payload end | `0x137ed75`, ramdisk at `0x137f000` |
| `kernel_addr` @0x0c | `0x0015ad6c` (non-standard, ignored by LK) |
| ramdisk_size @0x10 | `0x18000193` (nonsense value; header is vendor-mangled) |

Decompressed Image (49 109 052 B):

| arm64 Image header | Value |
|---|---|
| code0/code1 | `4d5a0091 ffff9514` |
| magic @0x38 | `41 52 4d 64` = `ARMd` ✔ |
| `text_offset` | `0x0` |
| `image_size` | `0x2ca0000` |
| `flags` | `0xa` |

Payload equality:

```
boot_v7.img                              kernel md5 f48f277fb189a77301f9f32270fa1499
boot_a_backup_20261024_225408.img        kernel md5 f48f277fb189a77301f9f32270fa1499
Image (gzip -dc)                         md5 bcc7a908b26a8bd325f661d7a9b1697f
```

Whole-file md5s differ (`5dbb19…` vs `356320…`) only because of header/ramdisk
metadata, not the kernel.

### 1.2 Link / load addresses

With `CONFIG_ARM64_4K_PAGES=y` and `CONFIG_ARM64_VA_BITS=39`:

| Region | Address |
|---|---|
| linear map (physmap) base | `0xffffffc000000000` — **fixed**, arm64 does not randomise the linear map |
| `_text` / link base | `0xffffffc008000000` (= `_kallsyms_relative_base`) |
| `_stext` | `0xffffffc008010000` (file `0x10000`) |
| `linux_banner` | `0xffffffc00a1de7a4` (file `0x21de7a4`) |
| `sys_call_table` | `0xffffffc00a1df160` (file `0x21df160`) |
| runtime | `link + slide`, slide 2 MiB-aligned, < 512 MiB (VA_BITS=39 KIMAGE window) |

File offset → VA is simply `0xffffffc008000000 + file_offset` (verified:
`linux_banner` symbol offset `0x21de7a4` == the file position holding
`"Linux version 5.10.209-android12-9-o-05206-g23c1467af8f7"`).

### 1.3 kallsyms is present and was decoded

A plain `grep kallsyms_token_table` fails because all symbol names are
token-compressed. The tables are nevertheless in `.rodata` and were located
and self-validated (offsets monotonic, `linux_banner` resolves to its literal):

| Array | file offset | VA |
|---|---|---|
| `kallsyms_offsets` | `0x1ddca08` | `0xffffffc009ddca08` |
| `kallsyms_relative_base` | `0x1e83608` = `0xffffffc008000000` | — |
| `kallsyms_num_syms` | `0x1e83610` = `0x29aff` = **170 751** | — |
| `kallsyms_names` | `0x1e83618` | `0xffffffc009e83618` |
| `kallsyms_markers` | `0x20d9430` (667 u32) | `0xffffffc00a0d9430` |
| `kallsyms_token_table` | `0x20d9ea0` | `0xffffffc00a0d9ea0` |
| `kallsyms_token_index` | `0x20da268` | `0xffffffc00a0da268` |

Format: 5.10 1-byte length + token bytes (0..255), first char = kallsyms type
letter (`T`/`t`/`D`…), `CONFIG_KALLSYMS_BASE_RELATIVE=y`,
`s32 offset = addr - 0xffffffc008000000`.

Consequence: **every static address in this note is symbol-exact**, not
pattern-matched. Runtime use still needs the KASLR slide.

Handy symbols:

```
_text                      0xffffffc008000000
commit_creds               0xffffffc0081aa1c4
prepare_kernel_cred        0xffffffc0081a9540
kallsyms_lookup_name       0xffffffc0082d1a2c   (present in kallsyms, NOT exported)
modprobe_path              0xffffffc00a8c1078
core_pattern               0xffffffc00a96e7b0
init_cred                  0xffffffc00a8c0ce0
```

corrected: an earlier revision of this table called `kallsyms_lookup_name`
"exported". It is not: the export (`__ksymtab_strings`) carving yields **0**
hits for that name, so the KSUNext LKM cannot resolve it (see
`re-ksunext-lkm-2026-10-25.md` — 61 of 230 imports missing). The address above
is the kallsyms entry, usable only with the KASLR slide and only from a
privileged context.

---

## 2. Futex-PI code: is the CVE-2026-43499 shape here?

### 2.1 Entry path

`sys_call_table[98]` (arm64 `__NR_futex`) = `0xffffffc00982dcc0`
(`__arm64_sys_futex.cfi_jt`) → body `__arm64_sys_futex @ 0xffffffc0082bed70`
→ `do_futex @ 0xffffffc0082b4ed8`. `__NR_futex_waitv`/`futex_waitv` does
**not** exist (5.10 has no waitv) — the trigger must be the classic
`FUTEX_WAIT_REQUEUE_PI` + `FUTEX_CMP_REQUEUE_PI` pair, which is present.

### 2.2 Symbols (all present)

| Symbol | Address | Type |
|---|---|---|
| `futex_wait` | `0xffffffc0082b5214` | t |
| `futex_wake` | `0xffffffc0082b5658` | t |
| `futex_requeue` | `0xffffffc0082b5fc8` | t |
| `futex_lock_pi` | `0xffffffc0082b8404` | t |
| `futex_unlock_pi` | `0xffffffc0082b905c` | t |
| `futex_wait_requeue_pi` | `0xffffffc0082b9b84` | t |
| `futex_proxy_trylock_atomic` | `0xffffffc0082be544` | t |
| `attach_to_pi_state` | `0xffffffc0082bd064` | t |
| `attach_to_pi_owner` | `0xffffffc0082bd5b0` | t |
| `exit_pi_state_list` | `0xffffffc0082bfc80` | t |
| `__fixup_pi_state_owner` | `0xffffffc0082bb378` | t |
| `fixup_owner` | `0xffffffc0082bbe94` | t |
| `remove_waiter` | `0xffffffc00830f408` | t |
| `rt_mutex_start_proxy_lock` | `0xffffffc008211a80` | T |
| `rt_mutex_wait_proxy_lock` | `0xffffffc008211c80` | T |
| `rt_mutex_cleanup_proxy_lock` | `0xffffffc008211e2c` | T |

corrected: `remove_waiter` is `0xffffffc00830f408` (an earlier draft had
`0xffffffc00820f408`, a one-digit error); the three `bl` call sites in §2.3(d)
are unchanged.

### 2.3 The vulnerable ingredients, with instruction evidence

**(a) The waiter is a stack object of `futex_wait_requeue_pi`** — the
prerequisite for “freed/reclaimed stack frame”:

```
ffffffc0082b9b88: sub  sp, sp, #0x1a0          ; frame
ffffffc0082b9e30: add  x2, sp, #0x90           ; &rt_waiter  (3rd arg)
ffffffc0082b9e34: mov  x0, x22                 ; &pi_state->pi_mutex
ffffffc0082b9e3c: bl   rt_mutex_wait_proxy_lock
```

`rt_waiter` lives at `sp+0x90`; the frame is destroyed on return, i.e. any
residual link into the PI list is a stack UAF by construction.

**(b) `pi_state->pi_mutex` (not a copy on `q`) is the lock used in the proxy
path** — the `pi_state->pi_mutex` vs `q->pi_mutex` distinction called out in
the CVE description. `q.pi_state` is loaded from `[sp,#0x50]`, then
`&pi_state->pi_mutex = pi_state + 0x10`:

```
ffffffc0082b9e20: ldp  x8, x9, [sp, #0x50]     ; x8 = q.pi_state
ffffffc0082b9e2c: add  x22, x8, #0x10          ; &pi_state->pi_mutex
```

**(c) Conditional unlink ordering in the waiter** — cleanup only runs when
`rt_mutex_wait_proxy_lock` returns non-zero:

```
ffffffc0082b9e3c: bl   rt_mutex_wait_proxy_lock
ffffffc0082b9e54: mov  w23, w0
ffffffc0082b9e80: cbz  w23, 0xffffffc0082ba374  ; ret==0 -> skip cleanup
ffffffc0082b9e88: bl   rt_mutex_cleanup_proxy_lock
ffffffc0082b9e90: tst  w0,#1 / csel w22,w23,wzr,ne
ffffffc0082ba38c: bl   fixup_owner               ; with x1 = sp (=&q)
```

The proxy waiter path acquires through
`rt_mutex_wait_proxy_lock → __rt_mutex_slowlock`, which at
`0xffffffc009a0a994` calls `try_to_take_rt_mutex(lock, current, waiter)` and
returns 0 as soon as that succeeds (`0xffffffc009a0a99c`) — i.e. the dequeue
for a waking waiter is inside `try_to_take_rt_mutex`, not a separate call.
The *cleanup* path is what unlinks a waiter that was queued but lost the race.
The exact 2026 ordering change is not visible without the fix diff — see
confidence below.

**(d) `remove_waiter()` is genuinely wired into the proxy paths** — it has
exactly **three** `bl` call sites in the whole image (full-text scan of
`0xffffffc008000000..0xffffffc009c00000`):

```
0xffffffc008211b0c   rt_mutex_start_proxy_lock
0xffffffc008211ec0   rt_mutex_cleanup_proxy_lock
0xffffffc009a0a8d4   rt_mutex_slowlock

rt_mutex_start_proxy_lock:
  0xffffffc008211af8  bl try_to_take_rt_mutex
  0xffffffc008211afc  cbz w0, <queue path>
  0xffffffc008211b0c  bl remove_waiter
  0xffffffc008211b68  bl task_blocks_on_rt_mutex (queue path)

rt_mutex_cleanup_proxy_lock:
  0xffffffc008211ea0  bl try_to_take_rt_mutex
  0xffffffc008211eb4  cmp x22, x19 ; owner == current ? skip
  0xffffffc008211ec0  bl remove_waiter
```

**(e) `futex_requeue` proxy block** (the requeueing thread):

```
ffffffc0082b6880: bl futex_proxy_trylock_atomic    ; may take pi_mutex for us
ffffffc0082b6f64: ldr x1, [x23, #0x40]            ; waiter = q->rt_waiter
ffffffc0082b6f68: ldr x2, [x23, #0x10]            ; task
ffffffc0082b6f70: ldr x0, [sp, #0x10]             ; pi_state->pi_mutex
ffffffc0082b6f78: bl rt_mutex_start_proxy_lock
```

**(f) `exit_pi_state_list` walks the PI wait list and can unlock/put states**
at task exit (`rt_mutex_futex_unlock`, `put_pi_state`, `__list_del_entry_valid`),
which is the second path that can dereference a stale stack waiter.

**Coverage of the fix.** `CONFIG_DEBUG_LIST=y` + `CONFIG_BUG_ON_DATA_CORRUPTION=y`
mean a stale plist/list link panics rather than silently continuing; this is
relevant both to detection and to exploit stability.

### 2.4 Verdict and confidence

* **Present:** every structure the CVE needs (stack waiter, pi-state proxy,
  `remove_waiter`, `exit_pi_state_list`, `attach_to_pi_state`,
  `futex_requeue` PI branch). Evidence: §2.2/§2.3 addresses and call order.
* **Build age:** Feb 25 2025, i.e. **before** the 2026 fix 3bfdc63936dd.
  Android 5.10 LTS would have to have backported it; no evidence of a backport
  (functions and signatures match the pre-7.1 upstream shape).
* **Confidence:** *vulnerable in principle / pre-fix code lineage* = **high**.
  *exact CVE trigger ordering* = **medium** — the fix diff cannot be obtained
  offline, so I can prove the machinery and the build date, not a byte-level
  equivalence to the disclosed bug.

Practical translation: GhostLock is a **real but non-trivial** bug here; it is
not “one ioctl away”.

---

## 3. Mitigations actually in force (read from this device)

Source: `zcat /proc/config.gz` (authoritative, running kernel), `/proc/cpuinfo`,
`getenforce`, `/proc/self/status`, `/proc/sys/*`, `/proc/modules`.

| Control | Value | Effective? | Exploit impact |
|---|---|---|---|
| `CONFIG_FUTEX` / `CONFIG_FUTEX_PI` | `y` / `y` | yes | vulnerable code compiled in |
| `CONFIG_RANDOMIZE_BASE` | `y` | yes | kernel-image slide unknown; need a leak |
| `CONFIG_RANDOMIZE_KSTACK_OFFSET` | **absent from config (not a 5.10 option)** | **no** | no per-syscall kstack offset scrambling to defeat |
| `CONFIG_VMAP_STACK` | `y` | yes | thread stacks are vmalloc'd; stack frame reuse still possible via another thread/exit path |
| `CONFIG_SHADOW_CALL_STACK` | `y` | **yes** (x18: `str x30,[x18],#8` in every prologue) | classic return-address ROP dead; need data-only or SCS-aware chain |
| `CONFIG_CFI_CLANG` / `_SHADOW` | `y` / `y` | **yes** (`commit_creds.cfi_jt`, syscall table points at `.cfi_jt`) | indirect-call target overwrite must hit a CFI-trampoline with matching prototype |
| `CONFIG_ARM64_PTR_AUTH` | `y` | **no** — `/proc/cpuinfo` Features has no `paca`/`pacg` (Cortex-A76/A55, ARMv8.2) | `paciasp/autiasp` are HINT/NOP; PAC gives no protection |
| `CONFIG_ARM64_BTI_KERNEL` | `y` | **no** — no `bti` in Features | BTI HINT only |
| `CONFIG_ARM64_MTE` + `CONFIG_KASAN_HW_TAGS` | `y` / `y` | **no** — no `mte` in Features | **KASAN is inactive**; UAF is not sanitizer-caught |
| `CONFIG_KFENCE` | `y`, `SAMPLE_INTERVAL=500`, 63 objects | yes | low-probability UAF sampling; a bad allocation choice can still panic |
| `CONFIG_SLAB_FREELIST_RANDOM` / `_HARDENED` | `y` / `y` | yes | standard heap-grooming cost |
| `CONFIG_INIT_ON_ALLOC_DEFAULT_ON` | `y` | yes | uninitialised stack/heap reads return zeros; info-leak harder |
| `CONFIG_INIT_ON_FREE` | not set | — | freed objects keep contents (good for UAF fidelity) |
| `CONFIG_HARDENED_USERCOPY` | `y` | yes | `copy_*_user` stack overflows hit the check |
| `CONFIG_STACKPROTECTOR_STRONG` | `y` | yes | stack canaries |
| `CONFIG_DEBUG_LIST` + `CONFIG_BUG_ON_DATA_CORRUPTION` | `y` + `y` | yes | stale list/plist links **panic** |
| `CONFIG_SECCOMP` / `_FILTER` | `y` / `y` | shell has **0 filters** (`Seccomp: 0`), `NoNewPrivs: 0` | all syscalls reachable from adb shell |
| SELinux | Enforcing (stock image; **Permissive after v18**) | yes | at measurement time the `shell` domain gated everything below |
| `CONFIG_NF_TABLES` | **not set** | — | nftables CVE class unavailable |
| `CONFIG_USER_NS` | **not set** | — | no userns-based entry (big CVE-class reduction) |
| `CONFIG_IO_URING` | `y` | yes | io_uring syscalls reachable (no seccomp on shell) |
| `CONFIG_KEYS` | `y` | yes | keyctl reachable (SELinux permitting) |
| `CONFIG_MODULE_SIG` | **not set**, `MODVERSIONS=y` | — | unsigned modules loadable once CAP_SYS_MODULE (post-root only) |
| `CONFIG_STATIC_USERMODEHELPER` | `y`, path `""` | — | usermode-helper-path overwrite tricks constrained |

**Leak surface from `shell` (verified blocked):**

| Probe | Result |
|---|---|
| `/proc/kallsyms` | Permission denied (SELinux) |
| `dmesg` / `klogctl` | Permission denied |
| `/proc/sys/kernel/kptr_restrict` | Permission denied |
| `/proc/self/pagemap` | returns `0` (restricted) |
| `/sys/kernel/notes` | Permission denied |
| `/proc/modules` | readable but every base is `0x0000000000000000` |
| `/sys/module/.../sections/.text` | not readable |
| `/sys/kernel/tracing` | tracefs mounted, `trace` readable, but `available_filter_functions` absent / no address output |

`perf_event_paranoid = -1` and `unprivileged_bpf_disabled = 0` in the kernel,
but SELinux (`u:r:shell:s0`) is the open question — see §4.

---

## 4. Cheaper alternatives from `shell` uid on this exact build

Device-side access check (`exec 3</dev/X` from `adb shell`):

* **open OK:** `/dev/mali0` (`crw-rw-rw-`, `u:object_r:gpu_device:s0`)
* **denied:** `/dev/ashmem` (`ashmem_device`), `/dev/binder` (`binder_device`),
  `/dev/dma_heap/*`, `/dev/ged`, `/dev/mdp`, `/dev/mtk_disp`, `/dev/mtk_drm`

405 modules loaded (`/proc/modules`), all bases zeroed. GPU driver is a module:
`mali_kbase_mt6789` (1 028 096 B, in use by 16), plus `mtk_gpufreq_mt6789`,
`ged`, `mtk_gpu_qos`, `mtk_gpu_hal`.

### Top 3 candidates

1. **`perf_event_open` as a KASLR-leak enabler** — `__arm64_sys_perf_event_open
   @ 0xffffffc0083f442c`; kernel `perf_event_paranoid = -1`,
   `unprivileged_bpf_disabled = 0`, shell has no seccomp filter. If the shell
   SELinux domain is allowed `perf_event_open`, `PERF_SAMPLE_IP` /
   `PERF_SAMPLE_ADDR` gives kernel text addresses and removes the biggest
   GhostLock unknown (the slide). This is the **first thing to test**, and it
   is cheap (`perf` is not installed, but a static test binary is trivial).
   Caveat: it needs a *write* to `/data/local/tmp`, which this study did not do.
2. **`/dev/mali0` (Mali kbase ioctl)** — the only world-writable driver node
   that SELinux actually lets `shell` open. `mali_kbase_mt6789` is a vendor
   module not present in the Image (code must be pulled from the vendor_dlkm
   image offline). Historic Mali kbase ioctl bugs are a real class, but the
   DDK is heavily patched and there is no known 2025/2026 public bug for this
   MT6789 drop; exploitation needs a full kbase heap-grooming chain (days-weeks).
3. **`io_uring`** — `__arm64_sys_io_uring_setup @ 0xffffffc008a10230`,
   `enter @ 0xffffffc008a2b3c0`, `register @ 0xffffffc008a2872c`;
   `CONFIG_IO_URING=y`, no seccomp on shell. 5.10.209 is a late-2024 LTS with
   the well-known io_uring UAFs fixed; finding a new one is not a 1-day task.

Rejected quickly: nf_tables (not compiled), userns (not compiled), ashmem and
binder (SELinux denies from `shell`), keyctl (`0xffffffc008904bf8`, no
applicable 5.10.209 CVE known), cls_bpf/BPF (unpriv bpf syscall likely
SELinux-blocked and modern verifier bugs need a specialised chain).

**Note on Oplus/MTK ioctl handlers:** the Image itself contains no
`oplus_*ioctl`/`mtk_*ioctl` symbols (Oplus storage/`file_monitor` bits are
`__initstub__kmod_*`, the rest are modules). Any “weak vendor ioctl” would
have to be found in the 405 `.ko`s, which are not in `boot_v7.img`.

---

## 5. Go / no-go

### Verdict: **NO-GO for a from-scratch GhostLock port within one day.**

Reasons, in order of weight:

1. **No KASLR leak from `shell`.** Every static address above needs the slide;
   `/proc/kallsyms`, `dmesg`, pagemap, notes and module sections are all
   blocked/zeroed. Without a leak the exploit cannot even find
   `commit_creds`/`init_cred`, and a wrong guess panics the device. corrected:
   this is *not* a permanent brick — LK does not authenticate boot
   (`img_auth_required=0`, `avb_ret=0`) and fastbootd lives in the vendor_boot
   ramdisk — but every iteration still costs a full reboot and there is no
   in-kernel debug channel.
2. **The primitive is not a simple UAF write.** The stack waiter reclaim needs
   a deterministic cross-thread/exit interleaving, plus a reclaim object that
   survives kCFI (indirect calls only through `.cfi_jt` with matching
   prototypes) and SCS (no return-address overwrite). `DEBUG_LIST` +
   `BUG_ON_DATA_CORRUPTION` turn any plist mistake into a panic.
3. **No public 5.10.x PoC is available offline** (web access exhausted), and the
   fix diff 3bfdc63936dd is not in hand, so even the exact trigger shape is
   unverified.
4. **It is unnecessary for this mission.** Root was already obtained on this
   unit without any kernel exploit — permissive vendor_boot cmdline ⇒ `adb root`
   (uid 0, `u:r:su:s0`), later Magisk `su`. GhostLock would only add value if we
   needed root *without* touching a boot image, and even then it would still
   require a KASLR leak plus a CFI/SCS-safe chain; the boot-image route is
   already proven and strictly simpler.

### What would make it realistic

* A **leak primitive** on this build (most likely `perf_event_open` with
  `paranoid=-1`, if SELinux allows it), *or* an `init`-stage leak/helper that
  hands the slide to userspace.
* A **public PoC or the actual 3bfdc63936dd patch** for 5.10.y, which would
  let us (a) confirm the exact ordering and (b) copy the race choreography.
* A way to **disable one mitigation** for testing (e.g. boot a `kasan=off
  kfence=off` self-built 5.10.209 for development, which we can do offline),
  so the race can be debugged without bricking the daily device.

### First three concrete steps if it is pursued anyway

1. **Prove/disprove the leak (half a day).** Boot the patched vendor_boot once
   with a tiny static binary that calls `perf_event_open` (and, separately,
   `bpf(BPF_MAP_CREATE)`) and prints whether it succeeds under `u:r:shell:s0`.
   If `perf` is allowed, harvest `PERF_SAMPLE_IP` on a kernel-heavy workload
   and compute `slide = leaked_ip - static_addr`.
2. **Build a local 5.10.209 harness (1–2 days).** Reconstruct the futex
   functions in QEMU with the same config (`FUTEX_PI`, `VMAP_STACK`, SCS off
   for debug) and instrument `rt_mutex_start_proxy_lock` /
   `rt_mutex_cleanup_proxy_lock` / `exit_pi_state_list` to print the waiter
   pointer and list membership, so the free/reclaim window is measured rather
   than guessed.
3. **Pick a CFI-safe escalation target (2–3 days).** Data-only is strongly
   preferred: overwrite `cred` fields or a `struct file`/`seq_operations`-class
   object whose indirect calls go through a `.cfi_jt` entry with the same
   prototype. Anything requiring a stack pivot must respect SCS.

Only after 1–3 succeed is a device-side attempt worth the brick risk.

---

## 6. Reproducibility

* Kernel payload: `dd if=boot_v7.img bs=1 skip=4096 count=$((0x137dd75)) | gzip -dc > Image`
* kallsyms: `relative_base = u64@0x1e83608`, `num_syms = u64@0x1e83610`,
  names `@0x1e83618`, markers `@0x20d9430`, token table `@0x20d9ea0`,
  token index `@0x20da268`; `addr = 0xffffffc008000000 + s32(offsets[i])`.
* Validation used in this study: `offsets[]` monotonic, `num_syms = 170751`,
  and `kallsyms_lookup("linux_banner") = 0xffffffc00a1de7a4`, which is exactly
  the file offset of the banner string.
