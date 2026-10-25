# RE: system-side (EROFS + fastbootd) root path for RMX3630 / MT6789 / Android 14

Date: 2026-10-25. **Offline analysis + read-only `adb shell`.** Nothing was flashed,
nothing was written to the device, no DA/preloader run. All experiments were done on
copies under `/tmp/opencode`. One file created: this note (not committed).

Inputs / tools used:

| item | value |
|---|---|
| `/home/musin/system_a.erofs` | 888,131,584 B, md5 `f66645e4e40702d60067b25dfba4e6b4e7` |
| `/tmp/opencode/sysa` | extracted tree (labels/xattrs lost) |
| `/tmp/opencode/vb/frag0.cpio` | vendor_boot vendor ramdisk (contains **fastbootd**) |
| CIL policies | `plat_sepolicy.cil` (from image) + `vendor_sepolicy.cil`, `system_ext_sepolicy.cil` pulled from the live device |
| host tools | `fsck.erofs`/`dump.erofs`/`mkfs.erofs` 1.7.1, `adb`, `fastboot 34.0.4`, python3+capstone |

Companions: `re-system-erofs-patch-2026-10-25.md` (build.prop splice, verity-tree math),
`re-v14-adb-works-2026-10-25.md` (current vendor_boot hack), `campaign-status-rmx3630.md`.

**Campaign outcome (2026-10-25), which supersedes this note:** this system-side
route was prepared but **not needed**. Root came from the vendor_boot header
cmdline `androidboot.selinux=permissive` (31 bytes) ⇒ `adb root` (uid 0,
`u:r:su:s0`, v18/v19), and then from Magisk `su` (uid 0, `u:r:magisk:s0`, v22
`a874a5c217d2e42aa7813a151bbd78be`). `/system` was left stock and read-only
(dm-23/24/25/26) throughout.

---

## 0. Verdict (read this first)

| question | answer |
|---|---|
| Is `fastboot flash system_a <888 MB raw EROFS>` viable? | **YES.** fastbootd writes through the existing LP extent list; image must be raw (or Android-sparse) and **≤ / == the current LP size**. Our dump is *exactly* the LP size (216,829 × 4096 = 888,131,584), so **no resize, no `--force`**. |
| Can a system `.rc` service give root? | **uid 0: YES** (deterministic, survives reboot, works with the stock kernel/verity). **True init-domain root: NO** without a sepolicy change — see §5.2 (SELinux, not verity, is the wall). |
| Can it install `/data/misc/adb/adb_keys`? | **NO** with plat/vendor policy: the file is writable only by `system_server` (plat CIL 27866/27867), readable by `adbd`. `init`/`shell`/`adbd` have no write rule at all. Use the already-active `ro.adb.secure=0` instead. |
| Verity verdict | dm-verity **is active** on `/system` (`/dev/block/mapper/system-verity` → `dm-23` → mounted as `/`), but the device is `orange`+`unlocked` and `/metadata/avb_enforce` is absent ⇒ fs_mgr permissive path (`hashtree_error_mode = LOGGING` / `ignore_corruption`). Evidence + the one remaining uncertainty in §3. |
| Cheapest safe implementation | **in-place patch of 2 FLAT_INLINE files in `/system` (2 × 4 KiB blocks), no rebuild.** Verified offline end-to-end (extraction + byte compare). Failure mode if verity were strict: *those 2 files unreadable, boot still completes* (no brick). |
| Full rebuild (`mkfs.erofs`) | possible and reproducible (§2.B) but it changes **every** block; only do it for the "real root" stage, after the 2-block probe has proven verity permissive. |
| Rollback | fastbootd itself lives **inside the vendor_boot ramdisk** (`system/bin/fastbootd`, 1,244,248 B) — it does not depend on `/system`. A dead system image is still recoverable by `fastboot reboot fastboot` → `fastboot flash system_a <stock dump>`. §6. |

Numbers used everywhere below:

```
LP size (system_a)      216829 blocks = 888,131,584 B   (== dump size, verified from super_extract.log geometry)
AVB image_size          214459 blocks = 878,424,064 B   (erofs fs end)
verity tree             1691 blocks   =   6,926,336 B   @ 878,424,064 .. 885,350,400
AVBf footer + blob                      2,781,184 B     @ 885,350,400 .. 888,131,584
hash                    4096/4096, sha256, salt af3f5efe5d390aa779eeb76564ca07eb
root digest             a0574fc18e00471d1e832cfe52180bd5722436710c40e9cac56d712cf10f28ab
```

---

## 1. Q1 — fastbootd and the logical partition

### 1.1 What fastbootd does with `flash`

`fastbootd` (from the vendor_boot ramdisk) links `liblp`, `libdm`, `libsparse`,
`libsnapshot`. It resolves the *logical* partition, opens it via `MetadataBuilder`,
and writes the received blob through the **existing extent list**
(`WritePartitionData` → per-extent writes). Consequences:

* the LP metadata is **not** rewritten if the image fits: partition size, extents,
  attributes stay as they are. `super` gets no new metadata blocks.
* if the image were **larger** than the LP size, the write fails (`Failed to flash
  data of len …`) — fastbootd does **not** auto-grow. Growing would need
  `fastboot resize-logical-partition system_a <size>` (supported, string present in
  the binary, but requires free space in super and rewrites LP metadata — *not* needed
  here).
* raw images are fine; Android-sparse is also accepted (`sparse_file_import_buf`),
  but our image is raw and exactly partition-sized, so don't bother.
* unlocked device is required: the binary contains `Flashing is not allowed on locked
  devices`; ours is unlocked (`seccfg lock_state=3`, `ro.boot.verifiedbootstate=orange`,
  `ro.boot.flash.locked=0`).

### 1.2 Partition name

The LP metadata (see `super_extract.log`) names the partitions **with the slot
suffix**: `vendor_a, system_a, product_a, odm_a, …`. So the partition is `system_a`;
`system` is only the *mount point* name in fstab. Use the explicit name; host
fastboot's slot magic is unnecessary and the device's `getvar` is unreliable
(notes say values are shifted):

```
# from adb (device boots):
adb reboot fastboot
fastboot devices                     # expect "<serial>  fastbootd"
fastboot getvar is-logical:system_a  # "yes" (nice-to-have; may be garbled)
```

### 1.3 Exact commands

```
# 1. verify the file we are about to write
md5sum system_a.patched.erofs                      # must equal the value from §2
stat -c%s system_a.patched.erofs                   # must be 888131584

# 2. flash the whole logical partition (raw, exact LP size)
fastboot flash system_a system_a.patched.erofs
#    fallback if the name is rejected:  fastboot flash system system_a.patched.erofs
#    fallback if it complains about size/unknown partition:  fastboot flash --force system_a …

# 3. leave fastbootd
fastboot reboot
```

Notes / gotchas:

* **`--force` is not needed** and does not help with a wrong size — it only bypasses
  the host's safety checks ("Force a flash operation that may be unsafe").
* `fastboot: error: cannot load '…'` → the file is not where you think; `fastboot`
  must run on the host, obviously.
* the 888 MB transfer is 14× the 64 MiB vendor_boot flash that is proven on this
  device. Expect 30–90 s. Do not interrupt; a truncated download leaves the
  partition half-written (recoverable, see §6).
* **snapshots**: `ro.virtual_ab.userspace.snapshots.enabled=true` and the mapper has
  `system_a-cow → dm-18`, but `apexd-snapshotde` is stopped and
  `persist.sys.sota.state=none`. If fastbootd ever answers with a snapshot error,
  run `fastboot snapshot-update cancel` first, then flash.
* `fastboot flash system_a` also rewrites the **verity tree and AVB footer** inside
  the partition (they are part of the 888 MB dump). That is desirable: the tree then
  matches the stock descriptor again, except for the leaves of the blocks we change.

---

## 2. Q2 — rebuild recipe

Two routes. **A is recommended** (2 blocks touched). B is only for the "real root"
stage (§5.3).

### 2.A In place: patch two FLAT_INLINE files (recommended, verified)

Key discovery: most small files under `/system` are **EROFS layout 2 (FLAT_INLINE)**
— the file bytes sit *verbatim* in the same 4 KiB metadata block as the inode, after
the 32 B inode + 16 B xattr body. No compression, no index pack, no data extent.
Therefore a **same-length byte replacement inside one block** changes nothing but
those bytes: `i_size`, `i_mode`, `i_uid/gid`, mtime, xattrs (incl. the SELinux label),
the inode, the superblock and all other blocks stay bit-identical.

```
cppreopts.rc  inode: i_format 0x0004 (v0/32B, layout 2=INLINE), i_mode 0100644, i_size 1690
              inode at 333,194,880 ; data at abs 333,194,928 ; block 0x13DC2000 (=333,193,216)
bug_map       inode at abs 334,625,440 ; data at abs 334,625,488 ; block 0x13F1A000 (=334,622,720)
```

Both files were verified to be stored verbatim (`dump.erofs --path=…` says
`Layout: 2, On-disk size == Size`, and the raw bytes are found with `mmap.find()`).

Chosen targets and why:

| target | size | why it is safe to overwrite |
|---|---|---|
| `/system/etc/init/cppreopts.rc` | 1690 B | post-OTA only (`on property:sys.cppreopt=requested`); dropping the `cppreopts` service only makes the first boot after an OTA slower. |
| `/system/etc/selinux/bug_map` | 1322 B | only used by debuggerd/tombstoned to map SELinux audit denials to bug ids. Never read at boot. |

Recipe (this is exactly what was run against a copy; the result was extracted and
compared):

```python
import hashlib
RC_OFF, RC_LEN = 333194928, 1690      # /system/etc/init/cppreopts.rc
SH_OFF, SH_LEN = 334625488, 1322      # /system/etc/selinux/bug_map
rc = open('rx.rc.txt','rb').read();  rc = rc + b'#'*(RC_LEN-1-len(rc)) + b'\n'
sh = open('rx.sh.txt','rb').read();  sh = sh + b'#'*(SH_LEN-1-len(sh)) + b'\n'
assert len(rc)==RC_LEN and len(sh)==SH_LEN
f = open('system_a.patched.erofs','r+b')
for off, data in ((RC_OFF, rc), (SH_OFF, sh)):
    blk = off & ~4095
    f.seek(blk); buf = bytearray(f.read(4096))
    buf[off-blk: off-blk+len(data)] = data
    f.seek(blk); f.write(buf)
f.close()
```

Result of the actual run (recorded):

```
block 333193216  old md5 98854eaa3562172b9da68c5e6f1ebb30
                 new md5 1d36da51af320bff587104f134c5fcd0
block 334622720  old md5 c7c97484cf9730aaf1053e5e30825de6
                 new md5 75d21536f0a71a0398e89f8674b5b159
whole image md5 d30409fbf1baaa2513d2ab3e21273286   (payload of §2.A)
```

Verification performed offline (all passed):

```
fsck.erofs --extract=/tmp/opencode/p2tree system_a.patched.erofs   # 5 s, clean
cmp p2tree/system/etc/init/cppreopts.rc   rx.rc.padded             # identical
cmp p2tree/system/etc/selinux/bug_map     rx.sh.padded             # identical
cmp p2tree/system/build.prop              sysa/system/build.prop   # identical (control)
diff -rq p2tree sysa    # no content differences (only "No such file" for the
                        # dangling symlinks that a non -x extraction drops)
```

(`fsck.erofs IMG` without `--extract` returns in 60 ms — it only validates the
superblock; always use `--extract` to force a full read of every block.)

Payload constraints for **future** payloads: the replacement must have **exactly** the
same length as `i_size`, and must stay inside the same 4 KiB block. Free space in the
block after our file is already used by the *next* inode — do not overflow.

### 2.B Full rebuild with `mkfs.erofs` (only if you need new files/policy)

Extracting with ownership (no root on the host):

```bash
cd /tmp/opencode
fakeroot -- bash -c '
  fsck.erofs --extract=tree --preserve /home/musin/system_a.erofs   # uid/gid via fakeroot
  # edit files here; new files go under tree/system/...
  mkfs.erofs -zlz4hc,9 -b4096 -C4096 -T 1740488008 \
      -U 7f7aaea8-4652-4378-b95d-a0e1d9155752 \
      --mount-point=/ \
      --file-contexts=tree/system/etc/selinux/plat_file_contexts \
      -x2 new_system.erofs tree
'
truncate -s 878424064 new_system.erofs        # hard cap = AVB image_size
```

Why these flags (all read out of the original superblock):

| flag | original value |
|---|---|
| `-b4096` | `blkszbits = 12` |
| `-C4096` | pcluster 4096, **no** `BIG_PCLUSTER` (feature_incompat = `ZERO_PADDING` only) |
| `-zlz4hc,9` | legacy single-algorithm format, `lz4_max_distance = 65535`, HEAD1 = LZ4 |
| `-x2` | `h_advise = Z_EROFS_ADVISE_COMPACTED_2B` |
| `-T`, `-U` | build_time 1740488008, uuid 7f7aaea8-4652-4378-b95d-a0e1d9155752 |
| `--mount-point=/` | the tree root *is* the image root (`/system` is a directory inside) |
| `--file-contexts` | the only way to get SELinux labels without root: rules are applied at mkfs time |

Measured (same tree, unmodified) in the companion note: 878,391,296 B, 3901 inodes
(identical), same feature set. With `--file-contexts` the image grows by ~24 KB of
xattr — still far below 878,424,064.

Caveats: **every block changes** (all verity leaves stale → permissive-only);
non-SELinux xattrs (`security.capability`) are lost by this route (check
`getfattr -d -m - -R tree` before trusting) — that alone can break `run-as`-style
helpers; and any metadata mistake is global instead of local.

### 2.C Verification checklist before flashing anything

```
stat -c%s  img   == 888131584                # exact LP size, or ≤ with --force
md5sum     img                               # record it
fsck.erofs --extract=/tmp/v img              # clean, and spot-compare 2–3 files
dump.erofs --path=/system/etc/init/cppreopts.rc img      # Size 1690, Layout 2
fsck.erofs --extract=… --preserve …          # ownership sanity (uid/gid/mode)
```

For route A: `cmp` of the two patched files against the intended text is the real test
(already done). For route B also check `dump.erofs img | head` feature line and total
inodes (3901 stock).

---

## 3. Q3 — verity: rejected, ignored, or inactive?

### 4.1 What is actually on the device right now (read-only, measured today)

```
$ adb shell ls -l /dev/block/mapper/ | grep -E 'system|verity'
system_a          -> dm-1
system-verity     -> dm-23            <-- verity device EXISTS
system_a-cow      -> dm-18
$ adb shell grep ' / ' /proc/mounts
/dev/block/dm-23 / erofs ro,seclabel,relatime,user_xattr,acl,cache_strategy=readaround 0 0
$ getprop ro.boot.veritymode            enforcing
$ getprop ro.boot.veritymode.managed    yes
$ getprop ro.boot.verifiedbootstate     orange
$ getprop ro.boot.vbmeta.device_state   unlocked
$ getprop ro.boot.flash.locked          0
$ getprop partition.system.verified     2
$ adb shell ls -l /metadata/avb_enforce -> No such file or directory
```

So: (i) dm-verity is **set up and in use** for `/system` — the root fs is mounted from
`dm-23`, which is `system-verity`, not from `system_a`; (ii) the same is true for
`/vendor` (dm-24), `/product` (dm-25), `/system_ext` (dm-26), and the two dlkm
partitions (dm-27/28); `/odm` is mounted straight from `odm_a` (dm-3) — **no odm-verity
device**, so odm simply has no hashtree; (iii) `partition.system.verified = 2`, with the
*stock* root digest `a0574fc1…` published in `partition.system.verified.root_digest` —
i.e. 2 is the normal state for stock, untouched partitions on this build, it does **not**
mean "corrupt". (All six verity partitions report 2; see `getprop | grep verified`.)

### 4.2 Which error mode is dm-verity running in?

`fs_mgr` logic (AOSP 14, `fs_mgr/fs_mgr.cpp:812` carries exactly this comment):

```c
// Orange state means the device is unlocked, see
// https://source.android.com/security/verifiedboot/verified-boot#device_state
bool fs_mgr_is_device_unlocked() { return get_boot_config("verifiedbootstate") == "orange"; }
```

On an unlocked (orange) device, `fs_mgr` (a) loads the vbmeta chain with
`AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR`, and (b) passes
`AVB_HASHTREE_ERROR_MODE_LOGGING` when creating the dm-verity target, which becomes
`ignore_corruption` in the dm table (the string `ignore_corruption` is compiled into
this build's init, next to `enforcing`/`logging`/`avb.managed_verity_mode`/
`verifiedbootstate` — checked in `/tmp/opencode/vb/x7/init`). `ignore_corruption` means:

* hash mismatches are **logged**, the data is **returned**;
* the mount succeeds, the file is readable;
* no `restart_on_error` reboot.

`/metadata/avb_enforce` is the one switch that turns this off
(`IsAvbPermissive()` requires it to be absent). It is **absent now** — but note it is
re-created by some OTA/`avb_enforce` flows, so **re-check before every write**.

### 4.3 What the tree says about our 2-block patch

The stock hashtree is genuine (companion note recomputed it); today's two blocks were
also verified against the on-disk leaves:

```
data blk 81346 (0x13DC2000) -> L0 blk 635 idx 66 -> leaf @ 881,088,576
   on disk 6392b6fda395b966f392f64e1508d6e8e7ca36233f39986cb05b03abb6316e63  == sha256(salt||stock block)  ✓
   new    6d74a5e1a7e150e64ef3fa310324f09794ff9fa536af6b8d03ccdc0d0b6b3dfe
data blk 81695 (0x13F1A000) -> L0 blk 638 idx 31 -> leaf @ 881,099,744
   on disk c09aeb6ae6267d52459e8decfe62e01bf6e21f613d84735ad32eb321f2f5f1b4  == sha256(salt||stock block)  ✓
   new    3ec82cef56fc822db043521f6cdd7a406baee62cfaaba0f3c548a3d261e1e1b0
```

Both L0 blocks are in L1 block 4, so exactly **2 leaves + 1 L1 block + the root block**
change. The root digest is anchored in the signed `vbmeta_system` (OEM key,
`SHA256_RSA2048`, chain sha1 `3c5f7b18…`) — **cannot** be re-signed, so a mismatch is
unavoidable; the question is only whether it is tolerated (it is, in logging mode).

### 4.4 Verdict + residual uncertainty

| scenario | result with our patch |
|---|---|
| orange/unlocked, no `/metadata/avb_enforce` (today) | verity table has `ignore_corruption`; our 2 blocks hash-fail, are logged, data is returned. Boot fine, service runs. **Expected.** |
| `ro.boot.veritymode=eio` / `restart` | dm-verity returns EIO on those 2 files. `init` logs "Failed to read /system/etc/init/cppreopts.rc" → *no service*, nothing else changes. Device still boots (the other 4,900 files are stock). **Benign failure.** |
| fully rebuilt image (§2.B) under EIO | every block fails, `/system` cannot be filled from page cache → mount succeeds but init cannot read *anything* → **no boot** → fastbootd rollback (§6). |
| `HASHTREE_DISABLED` in vbmeta_system | no dm-verity at all; everything readable (§4/Q4). |

The **only** unknown is the per-target error mode, and it cannot be read back with
uid 2000 (`/sys/block/dm-23/*`, `/proc/cmdline`, `/proc/partitions`, `dmesg` are all
SELinux-denied — verified). Settle it with the pre-flight checks and, if you want
proof instead of inference, with the 2-block probe itself (Stage 0, §8): it is a
*non-destructive* test of exactly this question — if the device boots and
`getprop init.svc.rx` is `running`, verity is permissive, full stop.

Pre-flight checklist (all read-only, 10 s):

```
adb shell getprop ro.boot.verifiedbootstate        # must be orange
adb shell getprop ro.boot.vbmeta.device_state      # unlocked
adb shell getprop ro.boot.flash.locked             # 0
adb shell getprop ro.boot.veritymode               # enforcing expected; eio => strict
adb shell ls -l /metadata/avb_enforce              # must be "No such file"
adb shell ls -l /dev/block/mapper/system-verity    # must exist (sanity)
```

---

## 4. Q4 — if verity must be disabled

`fbmeta` cannot be re-signed (OEM key), but on an unlocked device fs_mgr accepts a
chain-verification failure (`ALLOW_VERIFICATION_ERROR`). So the route is: **replace
`vbmeta_system_a` with a hand-built, unsigned vbmeta whose header flags say
`HASHTREE_DISABLED | VERIFICATION_DISABLED`.** Then fs_mgr does not even create
`system-verity`, and a rebuilt system is fully readable, no logged errors.

* `avbtool` is **not installed** here (`command -v avbtool` → missing; the
  `/tmp/opencode/avbtool.py` in this workspace is a 2-byte stub). It is not needed:
  a vbmeta is a 256 B header + descriptors, all little-endian; flags at header offset
  `0x78` (uint32). We can emit a ~1 KiB image with `algorithm = 0 (NONE)`,
  `auth_size=0`, `aux_size=0...`, `flags = 3`, no descriptors, `size = 256`.
* flash it to the **logical** partition: `fastboot flash vbmeta_system_a vbmeta_system.img`
  (LP name from the mapper: `vbmeta_system_a`; verify with
  `adb shell ls -l /dev/block/mapper | grep vbmeta` before rebooting).
* `fastboot --disable-verity --disable-verification flash vbmeta_system_a <stock
  vbmeta_system>` exists in host fastboot 34 (`--disable-verity: Sets disable-verity
  when flashing vbmeta`), but we **do not have the stock vbmeta_system image** (no
  `super` dump) and the flag rewrite invalidates the OEM signature anyway; it is the
  same permissive bet as the hand-built image, with an extra unknown. Prefer the
  hand-built one — or don't touch vbmeta at all.
* **Risk**: if fs_mgr treats "public key rejected" as fatal *despite* the unlock
  state, `/system` will not mount at all → no boot → §6 rollback. That is why this is
  a fallback, not part of the main plan.
* `fastboot getvar` is unreliable here, so pass the explicit partition name
  (`vbmeta_system_a`), not `vbmeta_system`.

---

## 5. Q5 — the service, the script, and what SELinux allows

### 6.1 The payload that was built and verified

`/system/etc/init/cppreopts.rc` (1690 B, `#` padded):

```
# rx.rc  (replaces cppreopts.rc; stock cppreopts service intentionally dropped)
service rx /system/bin/sh /system/etc/selinux/bug_map
    class late_start
    user root
    group root
    seclabel u:r:shell:s0
    disabled

on property:sys.boot_completed=1
    start rx
```

Why the shape:

* `class late_start` + `disabled` = starts only from the explicit `start`, after
  `sys.boot_completed` (i.e. `/data` is mounted and vold has run — everything the
  script needs).
* `user root` + `group root` → uid 0.
* `seclabel u:r:shell:s0` → the domain is `shell`, not `init`. This is forced by
  policy, see 6.2.
* no `oneshot` (the script is a long-lived loop; if it dies, init restarts it).
* the executable is `/system/bin/sh` (labeled `shell_exec`) with our script as argv[1]
  — `/system/etc/selinux/bug_map` keeps its stock `system_file` label and 0644 mode.

`/system/etc/selinux/bug_map` (1322 B, `#` padded):

```sh
#!/system/bin/sh
# rx: uid0 root channel for RMX3630 (runs u:r:shell:s0, uid 0)
D=/data/local/tmp
[ -d $D ] || exit 0
: > $D/.rx.cmd; : > $D/.rx.out 2>/dev/null
chmod 0666 $D/.rx.cmd $D/.rx.out 2>/dev/null
while :; do
  if [ -s $D/.rx.cmd ]; then
    mv $D/.rx.cmd $D/.rx.run 2>/dev/null || { sleep 1; continue; }
    { /system/bin/sh $D/.rx.run; } > $D/.rx.out 2>&1
    rm -f $D/.rx.run
    : > $D/.rx.out
    : > $D/.rx.cmd; chmod 0666 $D/.rx.cmd
  fi
  sleep 0.2
done
```

Client (works from the existing `adb shell`, uid 2000, no extra binary):

```
adb shell 'id; echo "id; toybox ps -A | head" > /data/local/tmp/.rx.cmd; \
           sleep 1; cat /data/local/tmp/.rx.out'
→ uid=0(root) gid=0(root) …       (in u:r:shell:s0)
```

Only regular files are used because of this exact policy fact: `shell` has
`dir/file/lnk_file` on `shell_data_file` but **no `fifo_file` and no `sock_file`**
classes → no FIFOs and no unix sockets in `/data/local/tmp`. A socket variant is
possible only in `/data/local/tests` (`shell_test_data_file` has full `sock_file`
perms) — but a `shell→shell` `unix_stream_socket:connectto` rule does **not** exist,
so a same-domain socket pair is denied; that is why the mailbox is used.

### 6.2 Why `u:r:init:s0` / `u:r:su:s0` are not used (and cannot be)

All statements below are greps of `plat_sepolicy.cil` (2,136,014 B, from the image)
plus `vendor_sepolicy.cil` and `system_ext_sepolicy.cil` (pulled from the device):

| fact | consequence |
|---|---|
| `(type su)` exists (line 4080), **zero** `(allow su …)` rules in plat+vendor+system_ext | `su` is an empty domain on this *user* build — `seclabel u:r:su:s0` = a process that can do nothing. |
| 99× `(typetransition init <x>_exec process <domain>)`, and **no** `init → init` transition allow (`(allow init init (process (transition)))` absent; only `(allow init self (process (setexec setfscreate setsockcreate)))`) | init itself is not an entry domain; a service cannot be *put into* `u:r:init:s0`. |
| `adb_keys_file`: `(allow adbd adb_keys_file (file (ioctl read getattr lock map open …)))` (read-only!) and `(allow system_server adb_keys_file (… write …))` — nothing else, in any of the three CILs | no system .rc service can create/append `/data/misc/adb/adb_keys` unless it runs in `system_server`. **The pubkey install as specified is not achievable without a policy change.** |
| `dir:add_name+write` on `shell_data_file` (`/data/local/tmp`) exists only for `adbd`, `dumpstate`, `shell`; none of them has `block_device`, `filesystem`/`mount` or `capability sys_admin` rules | the channel owner must be one of those three, and none of them is "real root". |
| the 99 targets include `vold`, `installd`, `apexd`, `adbd`, `dumpstate`, `shell` — but **not** `init` and **not** `vendor_init` (`(typetransition init … process vendor_init)` absent; `vendor_init` also has only `getattr` on `system_data_file`, no `shell_data_file`/`adb_keys_file` rules) | `u:r:vendor_init:s0` is both unreachable and useless here. |
| `shell` has `sock_file` write only for: `logd`, `logdr`, `dumpstate`, `property`, `traced_consumer`, `traced_producer`, `shell_test_data_file`; `connectto` only to `dumpstate`, `init`, `logd`, `traced` | socket channels are possible only against those domains. |

One caveat: whether the kernel *requires* `process:transition` for an explicit
`setexeccon()` (which is what `seclabel` does) is not settled by static analysis of the
CIL; the transition allow for `init → shell` exists anyway, and for `init → init` it
does not. You may try `seclabel u:r:init:s0` — if it is accepted the service runs in
init domain, but it still cannot create a node in `/data/local/tmp` (no `dir` rules)
and `/dev/socket` gives init only `relabelto`, so the *channel* stays blocked. The
`shell` domain is the practical answer either way.

⇒ **SELinux, not dm-verity, is the limiting factor.** A stock-policy system `.rc`
service can give a *deterministic uid 0* in `u:r:shell:s0`, but it cannot mount,
cannot open block devices, cannot write `adb_keys`, cannot `setprop` arbitrary
properties. It is "adb-root class" root.

corrected: an earlier revision added that `adb root` "demonstrably refuses" on
this user build. That was measured under the stock **enforcing** policy, where
Oplus denies `process:setcurrent` to adbd
(`avc: denied { setcurrent } scontext=u:r:adbd:s0 tcontext=u:r:adbd:s0
tclass=process permissive=0`). Once the vendor_boot cmdline sets SELinux
permissive, `adb root` succeeds and yields uid 0 in `u:r:su:s0` (v18/v19), so a
`.rc` service is not required for that class of root.

The adb key requirement is already satisfied by the boot images actually in use:
v14 (`ad5c09b9e75b6cc5daa137e875b1a98d`) carries `/force_debuggable` +
`/adb_debug.prop` with `ro.adb.secure=0` (adb authorised, no root), v19
(`93d4cbb183752c47f571928d80aadd76`) adds `service.adb.root=1`, and v22
(`a874a5c217d2e42aa7813a151bbd78be`) is the Magisk image. No
`/data/misc/adb/adb_keys` is needed while those are in place.

### 6.3 If you want *real* root (Stage B design; rebuild required)

The policy is compiled **from CIL at boot** — there is no `precompiled_sepolicy` in
`/system/etc/selinux`, `/vendor/etc/selinux` or `/system_ext/etc/selinux` (checked on
the live device), only `*.cil` + `plat_sepolicy_vers.txt`. So appended rules take
effect. Because `plat_sepolicy.cil` is 2.1 MB / compressed (14.38 %, layout 3) it
**cannot grow in place** → this needs the `mkfs.erofs` rebuild (§2.B). Minimal
neverallow-safe patch:

`/system/etc/selinux/plat_sepolicy.cil` (append at the end):

```
(type rx)
(roletype object_r rx)
(typepermissive rx)
(type rx_exec)
(roletype object_r rx_exec)
(typetransition init rx_exec process rx)
(allow init rx_exec (file (read getattr open execute map watch watch_reads)))
(allow rx rx_exec (file (read getattr open execute map getattr)))
```

`plat_file_contexts` (append):

```
/system/bin/rxd            u:object_r:rx_exec:s0
```

Then a `.rc` with `service rxd /system/bin/rxd …` (no `seclabel` needed — the
`typetransition` does it) and `/system/bin/rxd` a ~4 KiB static aarch64 binary
(`clang --target=aarch64-linux-gnu -nostdlib -static`, raw syscalls: `bind` on
`/data/local/tmp/rx.sock`, `accept`, `fork`, `execve("/system/bin/sh")`) or simply a
shell script labeled `rx_exec` (a permissive domain makes the script work with plain
`/system/bin/sh`). A `(typepermissive rx)` domain keeps the rest of the device
enforcing while giving the root channel real power: block devices, mount, `chcon`,
`adb_keys` (plus an explicit `(allow rx adb_keys_file (dir (search write add_name)))
(allow rx adb_keys_file (file (create write open getattr setattr)))` if you want the
key file written properly).

Add `/adb_keys` (root of the **initramfs**, `u:object_r:adb_keys_file:s0` via
file_contexts, 0644 root:root, our 713 B pubkey) at the same time if you want
key-based auth back with `ro.adb.secure=1`. corrected: the earlier caveat here
("could not be confirmed ... only `/data/misc/adb/adb_keys` was found") is
wrong — `/system/lib64/libadbd_auth.so` hard-codes
`{"/adb_keys","/data/misc/adb/adb_keys"}` (`adbd_auth_get_public_keys` at
`0x100e0`/`0x100f0`, array in `.data.rel.ro` at `0x3e078`, `access(path,R_OK)`
at `0x10160`), and reads them before any `ro.debuggable` test. The ramdisk was
inspected, not this library.

**Warning:** a CIL error (including a `neverallow` hit) makes the boot-time policy
compile fail → init panics → boot loop. Test the exact CIL by compiling locally
(`secilc` not installed; a `checkpolicy`-less dry run is not possible) or keep the
addition to the three `(type…)`/`(typepermissive …)`/`(typetransition …)` lines plus
one allow pair, and keep `fastbootd` recovery ready.

---

## 6. Q6 — rollback

Facts:

* `system_a` is a **logical** partition inside `super`; it is **fragmented into 22
  extents** (`super_extract.log`: first at `0x20d00000`, sizes `0x2e020000`, `0x2000`,
  `0xe000`, `0x569000`, `0x5000`, …). LP geometry: `max=0x10000 slots=3 block=4096`,
  header @ `0x3000`, 23 partitions, 186 extents.
* there is **no `super` dump** in this workspace — only the extracted `system_a`
  (888,131,584 B) and the log excerpt. A full-super restore is therefore impossible;
  rollback must be partition-scoped.
* `fastbootd` is in the **vendor_boot ramdisk**, so it survives a broken `/system`.

### 7.1 Preferred: from a booting device

```
adb reboot fastboot
fastboot devices
fastboot flash system_a /home/musin/system_a.erofs     # stock dump, md5 f66645e4…
fastboot reboot
```

This restores data + tree + AVB footer byte-exactly (the dump *is* the whole
partition), so verity is back to stock-equal.

### 7.2 If `/system` does not boot

1. Key combo into LK **bootloader fastboot** (power+vol-down; the port enumerates as
   `18d1:4ee0`/MTK fastboot depending on mode — check `lsusb`), then
   `fastboot reboot fastboot` → fastbootd (init from the vendor_boot ramdisk, no
   `/system` needed), then 6.1.
2. If LK fastboot is not reachable: preloader/BROM + DA (`docs/notes/reboot_fastboot.py`)
   — **documented as unreliable on this unit** ("DA's SET-BOOT-MODE is not forwarded
   through the preloader; observed result 22d9:0006 → 22d9:2046 (Android)").
3. Last resort, DA raw write of the 22 extents:
   `python3 docs/notes/super_extract.py --part system_a --path /x --dump …` prints the
   extent list (also `--dump-hdr`, `--scan`); then write each extent from the stock dump
   at `extent.phys + super_base (0x72000000)` with `loader.writeflash(...)`.
   **Caveat:** the campaign found the DA write path can report success without writing
   (`re-writepartition-silent-skip.md`: hash-binding gate at `0x4002f804`), so verify by
   read-back and expect to need retries. This is why the *whole-image* flash via
   fastbootd must be the plan of record.

### 7.3 For the 2-block patch specifically

The delta is 2 blocks → 8,192 B; the stock bytes are at
`333,193,216` and `334,622,720` (md5 `98854eaa…`, `c7c97484…`). If a partial write is
ever possible (DA), restoring just those two blocks is enough; otherwise the 888 MB
reflash above is the simple, provable route.

---

## 7. Risk / rollback table

| risk | likelihood | impact | mitigation |
|---|---|---|---|
| dm-verity is in `eio` mode (not logging) | low–medium (orange + no `avb_enforce` says logging) | Stage 0: service absent, boot OK. Stage B (rebuild): **no boot** | run Stage 0 first; it is the test. Keep fastbootd (§6.2) |
| `/metadata/avb_enforce` reappears after an OTA/wipe | medium | strict verity at next boot → patch inert | re-check before every flash; never OTA while patched |
| wrong EROFS offsets (block/inline assumption wrong) | very low (verified: extract + cmp) | that one file unreadable → benign | `fsck.erofs --extract` + `cmp` before flashing |
| payload longer than `i_size` or overflowing the 4 KiB block | low (assert in the tool) | corrupts the *next* inode in that block → possible init parse errors / lost file | pad exactly, assert `len==i_size`; keep `cmp` test |
| `fastboot flash` writes only part of 888 MB (USB drop) | medium (14× the proven 64 MiB) | partition half-new: unbootable | verify md5 of read-back? (fastbootd has no `fetch`); just re-flash; rollback per §6 |
| LP metadata gets rewritten/resized | none if image == LP size | — | do **not** run `resize-logical-partition` |
| snapshot (`system_a-cow`) interferes | low (`sota.state=none`) | flash refused or shadowed | `fastboot snapshot-update cancel`; re-check `apexd-snapshotde` |
| SELinux blocks the service (domain/label) | low (rules quoted in §5.2) | service starts then exits (rc `seclabel` failure = service not started, logged) | `getprop init.svc.rx`; `logcat -b all | grep rx` |
| `seclabel u:r:shell:s0` unexpectedly rejected at exec | low (init→shell transition allow exists) | no service | fallback: drop `seclabel`, exec `/system/bin/sh` gets `shell` anyway |
| CIL edit breaks policy compile (Stage B) | medium | boot loop | neverallow-clean 8-line addition; keep stock dump + fastbootd |
| device tree / OTA refuses to update afterwards | high | none for daily use | expected; keep dumps |

**Biggest risk:** the per-target verity error mode. Note that the *chosen* recipe makes
it a non-bricking risk (2 files, no stock block moved) — the danger only appears if you
skip Stage 0 and go straight to a full image rebuild.

---

## 8. Staged plan (what to actually do)

**Stage 0 — probe (2 blocks, reversible, ~15 min).**
Flash `system_a.patched.erofs` (md5 `d30409fbf1baaa2513d2ab3e21273286`, §2.A).
After reboot: `adb shell getprop init.svc.rx` → `running`, and
`echo id > /data/local/tmp/.rx.cmd; sleep 1; cat /data/local/tmp/.rx.out` → `uid=0`.
This simultaneously proves: patch mechanics, rc parsing, verity permissive.
Rollback: `fastboot flash system_a /home/musin/system_a.erofs`.

**Stage 1 — use it.** uid 0 (shell domain) via the mailbox. Enough for
`/data/local/tmp`, toybox, log access, reading `/data` that shell can read; **not**
enough for block devices/mount/adb_keys.

**Stage 2 — only if you need real root.** `mkfs.erofs` rebuild with the `rx`
permissive domain + file_contexts + (optionally) `/adb_keys`, per §5.3. Same
fastbootd flash; Stage 0 already told you the verity answer.

---

## 9. Open items

1. Confirm the per-target error mode by reading the dm table from a root shell (once
   Stage 0 runs): `dmsetup table system-verity` / `/sys/block/dm-23/dm/*` will show
   `ignore_corruption` or `restart_on_error` explicitly. corrected: this is now
   reachable — `adb root` (v19) or `su` (v22) is available; the expected answer
   is `ignore_corruption`.
2. `/adb_keys` is **verified** in this build: the two-path array is compiled into
   `/system/lib64/libadbd_auth.so` (`0x3e078` → `0x3349 "/adb_keys"`,
   `0x3e080` → `0x3603 "/data/misc/adb/adb_keys"`). corrected: the earlier
   "no such string in the APEX payload" observation was taken from the wrong
   file — the APEX `adbd` does not contain the path list, the library does.
3. Full `super` dump (16 × 0x10000 blocks geometry, 23 partitions) would turn the DA
   rollback from "22 extent writes of unproven reliability" into "one flash super";
   nothing in this workspace has it.
4. Whether `u:r:vold:s0` (mount + block devices, and init allows the transition) can be
   paired with a channel — no: vold has no rules on `shell_data_file`, so no client can
   reach it without a policy edit. Checked, dead end.
