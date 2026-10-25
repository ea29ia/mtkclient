# v14: adb works (RMX3630 / MT6789) — what the actual cause was

Date: 2026-10-25. Branch `oplus-mt6789-unlock`. Result: `adb devices` → `device`,
`ro.adb.secure=0`, `ro.debuggable=1`, `ro.boot.verifiedbootstate=orange`,
`ro.boot.slot_suffix=_a`; the panel is dead, but adb/scrcpy are available.

## Why v2…v12 did not work (three independent causes, all removed)

1. **Ramdisk codec.** corrected: the `boot_a` ramdisk is **not unpacked at all** — the effective
   initramfs is the `vendor_boot_a` ramdisk, which is `lz4-legacy`, while we had repacked the
   boot ramdisk as **gzip**. The decompressor is picked from the first stream, so our gzip stream
   was never decompressed (and is not needed in the first place).
   Proof: image `v8lite` (boot ramdisk **without `/init`**) booted normally.
2. **Second-stage root.** LK adds `androidboot.force_normal_boot=1`;
   vendor-init does **two** `SwitchRoot` calls — `/first_stage_ramdisk` (`0xF1994`) and
   `/system` (`0xF4E74`) — after which the old ramdisk is wiped (`FreeRamdisk 0xF1A28`).
   The final root is the **system image (system-as-root)**, so anything placed in the
   vendor ramdisk (root and `first_stage_ramdisk/`) is already invisible by the time the props are
   read. The same reason makes `/adb_keys` from the ramdisk useless.
3. **`umount("/debug_ramdisk")` before `PropertyInit()`.** `SwitchRoot` moves all mount points
   from `/proc/mounts`, so the tmpfs `/debug_ramdisk` (into which first stage copied
   `/adb_debug.prop`, because the ramdisk contains `/force_debuggable`) moves into the new root —
   but the second stage unmounts it **before** reading the props.

## Working recipe (v14)

Patch `system/bin/init` **in the vendor ramdisk** (`vendor_boot_a`), exactly one call:

```
hook 0xF1AC4  mov x0,x19  ->  bl 0x1EF9D0        ; before bl execv (0xF1AC8)
cave 0x1EF9D0 (52 B):
  mov x9, x1                         ; save argv
  adrp x0,#0x16000 ; add x0,x0,#0x33f      "/debug_ramdisk"
  adrp x1,#0x16000 ; add x1,x1,#0x33f
  mov x2,xzr ; mov x3,#0x1000 (MS_BIND) ; mov x4,xzr
  mov x8,#0x28 (mount) ; svc #0
  mov x1, x9                         ; restore argv
  mov x0, x19                        ; original instruction
  b 0xF1AC8
RX PT_LOAD p_filesz/p_memsz: 0x13E9D0 -> 0x13F000
```

Plus, in the root of the vendor ramdisk: `force_debuggable` (0 B), `adb_debug.prop`
(81 B: `ro.adb.secure=0`, `ro.debuggable=1`, `ro.force.debuggable=1`,
`persist.sys.usb.config=adb`), `adb_keys` (714 B, host key).

How it works: a bind mount of `/debug_ramdisk` onto itself makes the tmpfs a stack; the second
stage's `umount` pops only our top layer, the tmpfs with the copy of `adb_debug.prop` remains, and
`PropertyInit()` reads `ro.adb.secure=0`. `ro.*` values are overridden normally (verified:
`ro.adb.secure=0`, `ro.debuggable=1` at runtime).

Build: `PATCH_INIT_BIND=1 python3 tools/build_v9_vendor.py <vendor_boot_dump>
<boot_v7.img> <out.img>`. Check: 20/20 PASS (including disassembly of the hook and the cave).
Final image: md5 `ad5c09b9e75b6cc5daa137e875b1a98d`.

## The v13 bug (do not repeat it)

In v13 the cave returned to `0xF1AC0`, where a `bl` already sat → infinite loop, init never reached
`execv`, the kernel panicked ("no init"). Correct: hook `0xF1AC4` (`mov x0,x19`), and the cave itself
restores `argv` into `x1` and jumps to `0xF1AC8`.

## Next steps

* `adb root` on this image does **not** give uid 0: the request is denied by sepolicy
  (`avc: denied { setcurrent } scontext=u:r:adbd:s0 tcontext=u:r:adbd:s0 tclass=process
  permissive=0`), so adbd cannot switch to `u:r:su:s0`.
  corrected: the earlier guess ("`ro.secure=1` and `ro.build.type=user`, so v15 must set
  `ro.secure=0`") was wrong; `ro.secure=0` alone does not help. Root came from the
  `androidboot.selinux=permissive` cmdline (v18) plus `service.adb.root=1` (v19) — see
  `re-root-achieved-2026-10-25.md`.
* scrcpy is available: `scrcpy -s SG7DCQW8X8ONCI9T --no-audio` (the panel is dead,
  but the framebuffer works).
* Rollback: `BOOT_RESTORE=<vendor_boot_a_backup>.img FLASH_PART=vendor_boot_a
  FLASH_IMG=<dump> FLASH_GO=1 ./run_flash_vendor_boot.sh`.

## Tools

| file | what |
|---|---|
| `tools/build_v9_vendor.py` | vendor_boot packaging: props into the ramdisk + `PATCH_INIT_BIND=1` (init patch) |
| `tools/build_v7_from_dump.py` | v7 from a fresh `boot_a` (invariants, `--verify`) |
| `tools/boot_ramdisk_edit.py` | `--drop-init` (the discriminator) and `--bind` for the boot ramdisk |
| `run_flash_vendor_boot.sh` | flash `vendor_boot_a` (backup + readback), `FLASH_IMG`/`FLASH_PART` |
| `docs/notes/read_slots.py`, `read_ram_logs.py`, `read_ram_props.py` | read-only dumps of slots/memory |
