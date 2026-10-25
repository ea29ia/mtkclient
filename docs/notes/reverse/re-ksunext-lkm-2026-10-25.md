# KernelSU-Next (LKM) on Realme RMX3630 / MT6789 / 5.10.209-o — feasibility RE

Date: 2026-10-25 · Target: RMX3630 (RE8DDCL1), MT6789, Android 14,
`5.10.209-android12-9-o-05206-g23c1467af8f7` aarch64, 4 KiB pages.

**Campaign outcome (2026-10-25), which supersedes the recommendation section:**
root was obtained **without any kernel module** — permissive vendor_boot
cmdline (`androidboot.selinux=permissive`, 31 bytes) ⇒ `adb root` (uid 0,
`u:r:su:s0`, v18/v19), then Magisk `su` (uid 0, `u:r:magisk:s0`, image
`vendor_boot_v22_magisk.img` md5 `a874a5c217d2e42aa7813a151bbd78be`). The
KernelSU-Next analysis below still stands: the LKM is not loadable on this
kernel, and that verdict is unchanged.

**Verdict: NOT VIABLE with the artifacts available offline.**
Two independent hard blockers, both *before* any CFI/ABI question:

1. 61 of the 230 symbols the shipped `.ko` imports are **not exported** by this
   vendor kernel (the sharpest: `kallsyms_lookup_name`, whose *name string does
   not exist anywhere in the 49 MB Image*, plus `init_mm`, `avc_has_perm`,
   `ksys_unshare`, `task_work_add`, most of the SELinux internals).
   `load_module()` fails in symbol resolution with
   `kernelsu: Unknown symbol … (err -2)` → `-ENOENT`. No root, no module.
2. There is no way to fix that by patching: (a) the kernel patch route would
   require *adding 61 new ksymtab exports* to a fully-LTO'd, rodata-protected
   kernel; (b) rebuilding the `.ko` requires the exact Oplus/MTK 5.10.209-o
   source tree + `Module.symvers` + an arm64 compiler — none of which exist on
   this machine (only x86 7.0.0 headers, no cross-compiler, no network).

Everything below is the evidence chain. Addresses are **offsets in the
decompressed `Image`** (`dd if=boot_v7.img skip=0x1000 count=0x137DD75 |
gzip -dc`), which is byte-identical to the virtual layout (ADRP xrefs resolve
with base 0); patch offsets are therefore directly usable on the file.

---

## 0. Artifacts used

| artifact | facts |
|---|---|
| `/tmp/opencode/ksu_5.10.ko` | 481 672 B, ELF64 REL, 42 sections, `vermagic=5.10.252-dirty SMP preempt mod_unload modversions aarch64`, `import_ns=VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver`, 230 undefined syms |
| `/home/musin/boot_v7.img` | header v4, `kernel_size=0x137DD75` @0x1000, **gzip** (max compression, 49 109 052 B uncompressed, `image_size=0x2ca0000`, `text_offset=0`) |
| device `/proc/config.gz` | world-readable, 8245 lines (see below) |

Key config (from the device, not assumed):

```
CONFIG_MODULES=y  CONFIG_MODULE_UNLOAD=y
CONFIG_MODVERSIONS=y  CONFIG_ASM_MODVERSIONS=y
# CONFIG_MODULE_FORCE_LOAD is not set
# CONFIG_MODULE_SIG is not set
CONFIG_KALLSYMS=y CONFIG_KALLSYMS_ALL=y CONFIG_KALLSYMS_BASE_RELATIVE=y
CONFIG_LTO_CLANG_FULL=y  CONFIG_CFI_CLANG=y  CONFIG_CFI_CLANG_SHADOW=y
# CONFIG_CFI_PERMISSIVE is not set
CONFIG_KPROBES=y  CONFIG_ARM64_BTI_KERNEL=y  CONFIG_SHADOW_CALL_STACK=y
# CONFIG_TRIM_UNUSED_KSYMS is not set
```

The `.ko`'s own section table is already informative:

```
[19] __versions   PROGBITS  size 0x000000   <-- EMPTY
[ 8] .plt / [9] .init.plt / [10] .text.ftrace_trampoline
[28] .rela.text.__cfi_check   (0x1e378 = 129 KB of relocs)
[33] .rela.data.__cfi_jt_init_module
```

`nm -u` → `__cfi_slowpath` (49 `R_AARCH64_CALL26` relocs), `__cfi_check` defined
in `.text.__cfi_check`. So: **5.10-era jump-table/shadow CFI, not the 5.16+
`__kcfi_typeid` form** (no `__kcfi_typeid_`, no `kCFI` string in either the module
or the kernel). corrected: the campaign summary calls this mitigation "kCFI";
that is the same `CONFIG_CFI_CLANG`, compiled in its 5.10
`__cfi_slowpath`+`.cfi_jt` variant.

---

## 1. vermagic — NOT a blocker (release token is skipped)

`check_modinfo()` is inlined; the comparison is compiled as
`same_magic(modmagic, vermagic, info->index.vers)`:

| what | addr (Image offset) |
|---|---|
| `ldr w8,[info+0x7c]` = `info->index.vers`, `cbz` → jump to plain strcmp | `0x2c9de4` |
| `strcspn(modmagic, " ")` (`bl 0xadc454`, arg `" "` @0x21058bb) | `0x2c9df8` |
| `add x0, x22, x0` (advance modmagic to the space) | `0x2c9e00` |
| kernel side strcspn constant-folded: `add x1,x1,#0xb4a` → 0x21f8b4a (i.e. skip 42+1 bytes) | `0x2c9e04` |
| `bl strcmp` (0x1feb0) | `0x2c9e18` |
| failure: print `"\x013%s: version magic '%s' should be '%s'\n"` (0x2155ed2) | `0x2c9e90` |
| `return -ENOEXEC` (`mov w0,#-8`) | `0x2c9ea8` |

Kernel vermagic string, `0x21f8b20`:
`5.10.209-android12-9-o-05206-g23c1467af8f7 SMP preempt mod_unload modversions aarch64`

Module vermagic: `5.10.252-dirty SMP preempt mod_unload modversions aarch64`.

`same_magic(..., has_crcs=true)` skips the first token on **both** sides and
compares `" SMP preempt mod_unload modversions aarch64"` → **identical**.
`has_crcs` is `info->index.vers != 0`; the `.ko` *does* carry a `__versions`
section header (index 19, SHF_ALLOC set), only its size is 0, and 5.10's
`find_sec()` keys on `SHF_ALLOC` + name, not on size.

⇒ **No vermagic patch needed.** (`insmod -f` is unavailable, and irrelevant.)

## 2. `CONFIG_MODVERSIONS` — not a blocker either (empty `__versions`)

`check_version()` at **0x2c9c20** (`paciasp` = 0xd503233f):

```
2c9c3c  cbz x2, 2c9ccc          ; !crc (kernel symbol has no CRC)   -> return 1
2c9c40  ldr w8,[x0,#0x7c]       ; info->index.vers
2c9c48  cbz w8, 2c9ce8          ; section ABSENT                   -> return 0
2c9c58  ldr x9,[shdr+0x20]      ; __versions.sh_size
2c9c5c  lsr x10,x9,#6           ; / sizeof(struct modversion_info)=64
2c9c60  cbz w10, 2c9c90         ; ZERO entries -> warn, return 1
2c9c7c  bl strcmp               ; versions[i].name == symname ?
2c9cbc  cmp x9, [x21]           ; crc equal -> return 1
2c9cd4  "disagrees about version of symbol %s" (0x20e9d13) -> return 0
2c9c90  "\x014%s: no symbol version for %s\n" (0x21bd149)  -> return 1
```

Because the section is present but empty, the kernel emits **one** warning
(`static bool` guard at `0x28aff8`, set at `0x2c9ca0`) and accepts every
symbol. `check_modstruct_version("module_layout")` goes through the same
function → also accepted. Therefore:

* the CRCs are never compared, so the 5.10.252 build's CRCs are irrelevant;
* nothing needs to be stripped from `__versions`;
* **but** the usual `struct module` layout guard (`module_layout` CRC) is also
  silently defeated — `struct module` is 0x400 B in the module; the vendor
  kernel's `mod->cfi_check` lives at `[mod+0x110]` (§3). Layout drift here
  would be silent memory corruption, not a clean error.

## 3. Kernel-side bypass candidates (and why they don't save it)

`CONFIG_MODULE_SIG` is not set: the string `module verification failed`
does not exist anywhere in the Image, and no signature path is compiled in.
**Nothing to patch.**

If one insisted, the two load-time gates could be neutered with:

| gate | offset | original bytes | patch | effect |
|---|---|---|---|---|
| vermagic strcmp result | `0x2c9e1c` | `80 03 00 35` (`cbnz w0, 0x2c9e8c`) | `1f 20 03 d5` (`nop`) | never print/reject on magic |
| `check_version()` | `0x2c9c20` / `0x2c9c24` | `3f 23 03 d5` `5e 86 00 f8` (`paciasp; str x30,[x18],#8`) | `20 00 80 52` `c0 03 5f d6` (`mov w0,#1; ret`) | every CRC check passes |

Both are *wasted effort*: §4 fails first, at `resolve_symbol()` →
`"\x014%s: Unknown symbol %s (err %d)\n"` (0x21ad6e7, printed at **0x2c7e48**,
`err = -2` via `csel` at 0x2c7e4c).

### CFI reality check (would bite *after* loading)

* The `.ko` contains **49** `bl __cfi_slowpath` call sites; each is preceded by
  a 64-bit build-time type hash, e.g. at `.text+0xda0`:
  `movz/movk x0 = 0x119325e1f7bf1cc0`, then `mov x1,x20; bl __cfi_slowpath`.
* Kernel side: `__cfi_slowpath` at **0x3f3e68**; it resolves the target with
  the module-lookup helper at 0x2cea20 (returns the containing `struct
  module`), then dispatches to `mod->cfi_check` (`ldr x23,[x0,#0x110]`,
  0x3f3f6c) for module text, or to the kernel's own `__cfi_check` at
  **0x22000** (0x3f3f44, inside the text range 0x10000–0x1a30000 tested at
  0x3f3f24–0x3f3f40) for kernel text, then `blr x23` with
  `(typeid, ptr, NULL)` (0x3f3fa0-0x3f3fac).
* Failure path `cfi_check_fail`: **0x3f3e48** prints
  `"CFI failure (target: %pS)"` (0x2147202) and then `BUG` —
  `brk #0x800` at 0x3f3e24, or `bl 0x17c4f7c` at 0x3f3e98.
* `CONFIG_CFI_PERMISSIVE` is **not** set ⇒ a type-id mismatch is fatal
  (panic / boot loop), not a warning.

The scheme is the 5.10 shadow/jump-table CFI and the module side carries the
matching `__cfi_check` + `__cfi_slowpath` ABI, so CFI is not itself
incompatible. It is a *condition*, though: every cross-boundary indirect call
must have a byte-identical canonical prototype between the 5.10.252 GKI
headers and this Oplus/MTK 5.10.209-o tree, otherwise the module gets a
`BUG()` the first time it hooks/forwards such a pointer. For KSU that means
`sys_call_table[]` entries and the `security_hook_heads` slots — plausible but
unverifiable offline, and the failure mode is a non-booting device.

### Symbol gap (the real blocker)

Exported names were extracted from `__ksymtab_strings`
(0x25148b6 – 0x2565704, 14 481 NUL-separated names, verified to contain
`commit_creds`, `prepare_kernel_cred`, `printk`, `__SCK__tp_func_*`, etc.).
Intersecting with the module's 230 undefined symbols:

**169 exported / 61 NOT exported.** The missing set includes:

```
kallsyms_lookup_name  kallsyms_lookup  kallsyms_lookup_size_offset
sys_call_table  init_mm  __arch_copy_from_user  strncpy_from_user_nofault  copy_to_kernel_nofault
ksys_unshare  task_work_add  current_is_single_threaded  change_pid  alloc_uid
avc_has_perm  avc_ss_reset  avtab_*  ebitmap_*  cond_compute_av
policydb_read/write/destroy/filenametr_search/load_isids/context_isvalid
sidtab_*  mls_*  selinux_state  selinux_blob_sizes  security_bounded_transition
security_inode_init_security_anon  selnl_notify_policyload  symtab_*
path_mount  path_umount  ns_get_path  mntns_operations  set_fs_pwd  uts_sem
__arm64_sys_close  __arm64_sys_setns  __tracepoint_sys_enter  seccomp_filter_release
ext4_unregister_sysfs  __flush_dcache_area  __set_fixmap  __hashtab_insert
```

corrected: an earlier revision omitted `sys_call_table` from this list; it is
one of the 61 missing imports (the module needs it for the `su` syscall hook).

Independent confirmation for the sharpest one: `grep -abo kallsyms_lookup_name`
over the whole 49 MB Image → **0 hits**. Exported symbols are stored as plain
strings, so an export would be visible; the symbol survives only inside the
token-compressed kallsyms tables, which is why a stale offline tool could still
"find" it there. Whether Oplus removed the export or this tree simply never had
it (upstream dropped the export in 5.7) is not distinguishable offline —
(unverified). Either way KSU imports it, one missing symbol is enough to abort
the load, and there are 61.

Note the module *does* find the GKI VFS namespace
(`VFS_internal_I_am_really_…` exists at 0x252b780) — so the namespace check
passes; it is the individual symbol table that fails.

---

## 4. "Just flash a prebuilt KSU GKI kernel" — not viable

Device facts (read-only `adb shell`):

* `/vendor/lib/modules` → **236** `.ko` files (adsp, camera_isp, mali_kbase,
  ccci_*, mtk-*, wlan_drv_gen4m_6789, ~40 `oplus_bsp_*`, …).
* `/proc/modules` → **405** lines, i.e. ≈400 modules live, e.g.
  `wlan_drv_gen4m_6789 3534848 0 - Live … (O)`.
* These are built for exactly `5.10.209-android12-9-o-…` with
  `CONFIG_MODVERSIONS=y`, so they carry a full `__versions` table with that
  tree's CRCs.
* The `.ko` files themselves are not readable as `shell` (`EACCES`, SELinux
  `Enforcing`), so their vermagic could not be dumped live — the inference is
  from `CONFIG_MODVERSIONS=y` + the kernel's own `EXT_MODULES=…mediatek…`
  build list, which is unambiguous.

A 5.10.252 GKI kernel would (a) fail the MTK/Oplus modules on the first CRC
mismatch (`disagrees about version of symbol …` → `-EINVAL`, note this check
*does* compare CRCs on those modules), and (b) not even contain the MTK
drivers (14 481 exports, MTK `EXT_MODULES`, Oplus hooks — this is not a GKI
kernel). Losing ~400 modules = no display, touch, storage, wifi, modem.
**Rejected.**

## 5. "GKI mode" (KSU built into the kernel) — impossible here

Needs the exact `5.10.209-o` tree (or at least a matching `Module.symvers` +
generated headers) and an aarch64 toolchain. On this machine:
`/usr/src` = `linux-headers-7.0.0-{31,38}-generic`,
`linux-hwe-6.{14,17}`; `Module.symvers` exists only for x86 7.0.0;
`which aarch64-linux-gnu-gcc clang` → nothing (only host `gcc`); no vendor
tree, no network. **Impossible offline.**

---

## 6. Ranked recommendation

1. **(c) Drop KSU-Next; use the root we already have.** corrected: root was
   obtained without a kernel module — the permissive vendor_boot cmdline gives
   `adb root` (uid 0, `u:r:su:s0`, v18/v19) and the current image
   `vendor_boot_v22_magisk.img` (`a874a5c217d2e42aa7813a151bbd78be`) gives
   Magisk `su` (uid 0, `u:r:magisk:s0`). Neither needs kernel cooperation, so
   nothing has to be built here. (An earlier revision pointed at a
   `/system/bin/init` "cave" in the vendor_boot ramdisk; that was one of the
   intermediate experiments, not the final root path.)
2. **(b) Rebuild the `.ko` against this kernel** — the *correct* engineering
   path, but blocked today: needs the Oplus 5.10.209-o source/`Module.symvers`
   and an arm64 clang. If the source ever appears, this is the best option
   (it also produces correct `struct module`/CFI type ids). Prereq: verify
   `CONFIG_MODULE_SIG` stays off and `CONFIG_MODVERSIONS` CRCs match.
3. **(a) Foreign `.ko` + kernel patch** — dead. vermagic and CRCs are already
   non-issues (the shipped `.ko` is deliberately built CRC-free), but 61
   missing exports cannot be fixed by patching: you would have to synthesise
   61 `struct kernel_symbol` entries with correct relative `name_offset`s in
   read-only `.rodata` inside an LTO'd kernel, for functions that are not
   exported *by design*, and then still gamble on CFI/`struct module` layout.
   Effort/risk far exceeds value.

### If (c) is taken, first three steps

corrected: step 1 below described a hand-rolled `init` cave; the route that
actually worked was simpler — permissive cmdline (v18/v19) and then Magisk
(v22). The steps are kept as the fallback design, not as the current state.

1. Keep a single boot image that already gives root (v19 for `adb root`, v22 for
   `su`) and keep `/proc/config.gz` plus a `dmesg` dump as the regression check;
   only if a Magisk-free, app-visible `su` is needed, drop a static aarch64
   `su`/daemon + `sepolicy` into the vendor_boot ramdisk payload and start it
   right after `pivot_root` (no writes to `/system`, `/vendor`, `/boot`).
2. Audit GhostLock offline (it is unrelated to the ramdisk) for the same
   MT6789/Oplus quirks we already characterised, and only then decide whether
   it adds anything over the existing root — it does not, for this campaign.
3. Park KSU-Next: keep `ksu_5.10.ko` + notes, and re-open path (2) the moment
   a 5.10.209-o source drop or a matching `Module.symvers` becomes available —
   with the CEILING that the 61 exports must first be verified against that
   tree's `Module.symvers` before any build is attempted.
