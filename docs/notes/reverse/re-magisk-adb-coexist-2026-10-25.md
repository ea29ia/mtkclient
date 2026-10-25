# Magisk + our adb authorisation on RMX3630 (MT6789, Android 14)

Date: 2026-10-25. Scope: **offline** analysis of `vendor_boot_magisk.img`
(md5 `14f93d33f7888641f1e0f4c1cad4f2a9`, Magisk v30.7 / versionCode 30700,
patched with magiskboot exactly like `assets/boot_patch.sh` does for
VENDOR_BOOT). Device was only queried read-only (`adb shell`); one test image
was assembled **on the host** and verified statically (not flashed):
`/tmp/opencode/vendor_boot_magisk_B2.img`, md5 `fa44f119ccb1feb5aef9b81e7baec68f`.

corrected: the option-B design below was then implemented in
`vendor_boot_v22_magisk.img` (md5 `a874a5c217d2e42aa7813a151bbd78be`), which
**was flashed and tested** and is the current image. Observed outcome: our
vendor-init cave does **not** execute under Magisk at all, so the props copy
never ran. Props are unreachable under Magisk (`ro.debuggable=0`,
`ro.adb.secure=1`, no `/debug_ramdisk/adb_debug.prop`), `adb root` cannot give
uid 0, adb is authorised by `/data/adb/post-fs-data.d/adbkey.sh`, and root is
obtained with `adb shell su` (`uid=0 u:r:magisk:s0`). The analysis is kept as
the derivation; read §4.1/§4.2/§6 for the measured outcome.

Sources used:
* Magisk v30.7 source tarball (tag `v30.7`, matches the APK), files quoted by
  path below;
* AOSP `android14-release` `system/core/init` (first_stage_init.cpp,
  init.cpp, property_service.cpp, debug_ramdisk.h, second_stage_resources.h);
* the two binaries from the APK/ramdisk:
  `magiskinit` 199,960 B, sha256 `383670a7ba3a6a4b79e5f3467e1da4b66a5df66a9b356ab9f70916854dd6b468`;
  `magisk` 394,232 B, md5 `59d42441418ad61eaedbd0df04a55103` (also
  `lib/arm64-v8a/libmagisk.so` and `overlay.d/sbin/magisk.xz`).

---

## 0. TL;DR — what was planned, and what actually happened

The original recommendation was:

1. **Keep Magisk exactly as it is.** Do not move its temp dir, do not patch
   `magiskinit`.
2. **Move our props into the tmpfs Magisk itself prepares for us**: change
   the init cave so that, besides the v14 self-bind, it copies
   `/debug_ramdisk/adb_debug.prop` → `/data/adb_debug.prop`.
   That copy lands in magiskinit's `/data` tmpfs (`D` below). After
   magiskinit's `patch_ro_root()`, `D` is *the layer that `init`'s single
   `umount("/debug_ramdisk")` exposes*, so `PropertyInit()` reads our
   `ro.adb.secure=0` again.
3. **Pre-grant MagiskSU to the adb shell (uid 2000)** with an `overlay.d`
   init-rc snippet + a prebuilt `/data/adb/magisk.db` (policy row
   `uid=2000, policy=2 (Allow)`), and (belt-and-braces) install the host
   `adb_keys` from the same snippet.
4. Result: adb works on the **first** Magisk boot and
   `/debug_ramdisk/su -c id` returns uid 0, without the Magisk app.

corrected — measured result (`vendor_boot_v22_magisk.img`):

1. Keeping Magisk untouched was done (base v19 + magiskboot patch).
2. The copy into `D` was implemented, but **our init never runs under Magisk**
   (magiskinit goes straight to the system init), so step 2's code was dead:
   the props route is lost and `adb root` cannot give uid 0.
3. Adb authorisation is instead secured by a root hook,
   `/data/adb/post-fs-data.d/adbkey.sh`, which writes `/data/misc/adb/adb_keys`
   once magiskd runs (this requires `/data/adb/magisk` to be pre-seeded, §3).
4. `su` is allowed for uid 2000 in the Magisk app: Settings → Superuser access
   → **Apps and ADB** (persisted in `magisk.db`). Without that setting
   `adb shell su` returns "Permission denied".

Why not "just patch `/debug_ramdisk` out of magiskinit"? It is possible
(option A below, exact bytes given) but it requires patching three literals
in two Magisk binaries + recompressing `magisk.xz`, while option B changes
only *our* cave. B was therefore the recommendation; it is what v22 ships,
even though the copy itself turned out to be unreachable.

---

## 1. Execution order (answers Q1's ordering question)

The v14 facts + the v30.7 source gave this expected order (kept for the
derivation; the measured Magisk boot differs, see the note after the block):

```
PID 1 = magiskinit  (ramdisk /init, 199,960 B)
  first_stage():
    prepare_data()            mount tmpfs "magisk" -> /data  (D)
                              copy /init       -> /data/magiskinit
                              copy /.backup    -> /data/.backup
                              copy /overlay.d  -> /data/overlay.d
    hijack_init_with_switch_root()
    restore_ramdisk_init()    .backup/init (symlink /system/bin/init) -> /init
    exec_init()               execve("/init", argv)          <- PID 1 still

  original first-stage init  = system/bin/init from the vendor ramdisk
    (our patched one; magiskinit hexpatched its own "/system/bin/init"
     string to "/data/magiskinit", so the final execv below goes to
     magiskinit again)
    FirstStageMain():
      mount tmpfs "tmpfs" -> /debug_ramdisk                  (M0)
      if access("/force_debuggable")==0:                     <- COPY SITE
          copy /adb_debug.prop -> /debug_ramdisk/adb_debug.prop
          setenv INIT_FORCE_DEBUGGABLE=true
      SwitchRoot("/first_stage_ramdisk")
      SwitchRoot("/system")                                  (system-as-root)
      [our hook 0xF1AC4] v14 bind cave                       (M1)
      execv("/data/magiskinit", {..., "selinux_setup"})

  magiskinit, second_stage()   (argv[1]=="selinux_setup", is_rootfs()==false)
    unmount /init, /system/bin/init; remove /data/init
    patch_ro_root()            <-- THE COLLISION (section 2)
    exec_init()                execve("/init", argv)

  real second-stage init
    SetupSelinux() -> execv("/system/bin/init")
    SecondStageMain -> MountExtraFilesystems()
      if (!load_debug_prop) umount("/debug_ramdisk")         <- exactly ONE
      PropertyInit()  -> reads /debug_ramdisk/adb_debug.prop
```

corrected — observed on `vendor_boot_v22_magisk.img`: magiskinit does not hand
control to our patched vendor-ramdisk `system/bin/init`; it goes straight to
the system init. The "COPY SITE" above therefore never executes, and
`/debug_ramdisk/adb_debug.prop` is **absent** on a Magisk boot (`ro.debuggable=0`,
`ro.adb.secure=1`). The rest of the ordering (`patch_ro_root()` collision, one
umount) is confirmed.

`load_debug_prop` (AOSP init.cpp:964) is
`getenv("INIT_FORCE_DEBUGGABLE") && AvbHandle::IsDeviceUnlocked()`.
On v14 the pre-`PropertyInit` umount demonstrably runs, i.e. it is false
here (LK: `img_auth_required=0`, AVB not "unlocked" in libavb's sense).
Either value changes nothing under Magisk, because the prop file is not
created at all.

---

## 2. The collision, precisely (Q1)

Magisk v30.7 `native/src/init/rootdir.cpp`, `patch_ro_root()` (lines
257-292), abridged:

```cpp
void MagiskInit::patch_ro_root() noexcept {
    mount_list.emplace_back("/data");
    ...
    if (access("/sbin", F_OK) == 0) {
        tmp_dir = "/sbin";
    } else {
        tmp_dir = "/debug_ramdisk";                              // (1)
        xmkdir("/data/debug_ramdisk", 0);                        // (2)
        xmount("/debug_ramdisk", "/data/debug_ramdisk",
               nullptr, MS_MOVE, nullptr);                       // (3)
    }
    setup_tmp(tmp_dir.data());      // bind-mounts /data (D) onto tmp_dir
    chdir(tmp_dir.data());
    ...
    if (tmp_dir == "/sbin") {
        ...
    } else {
        xmount("/data/debug_ramdisk", "/debug_ramdisk",
               nullptr, MS_MOVE, nullptr);                       // (4)
        rmdir("/data/debug_ramdisk");
    }
    ...
}
```

`setup_tmp()` (`native/src/init/mount.cpp:211`) does, among other things,
`chdir("/data"); ...; xmount(".", path, nullptr, MS_BIND, nullptr);` i.e. it
bind-mounts the `/data` tmpfs **onto** `tmp_dir`.

### 2.1 Literals in `magiskinit` (file offsets; ET_EXEC, file_off = VA-0x200000)

| file off | VA | bytes | used by |
|---|---|---|---|
| `0x20a0` | `0x2020a0` | `"/data/debug_ramdisk\0"` (20) | `xmkdir` staging `0x22f5a0`; restore source `0x216364`, `0x217e24` |
| `0x2a7b` | `0x202a7b` | `"/debug_ramdisk\0"` (15) | `tmp_dir =` at `0x22f5b4`; initial MS_MOVE uses `tmp_dir.c_str()`; restore target at `0x21636c`, `0x217e2c` |

`strings` also reports `0x20a5` `"/debug_ramdisk"` — that is **the suffix
inside `/data/debug_ramdisk`**, not a third literal. Nothing references it
as a separate string.

There is no config/argv indirection: `parse_config_file()` only reads
`PREINITDEVICE`. The path is hardcoded, so one literal patch changes all
`tmp_dir` uses consistently (plus one literal in the core `magisk` binary,
see option A).

Note also that `is_rootfs()` is false after `SwitchRoot("/system")`
(system is EROFS), so `patch_ro_root()` is the branch that runs; and
`/sbin` does **not** exist in the system-as-root tree
(`adb shell ls /` on v14: no `/sbin`), so the `"/sbin"` branch is not
taken either.

### 2.2 Mount stack — reproduced on the host with user+mount namespaces

Simulation (identical operations; `M0` = first-stage props tmpfs,
`M1` = our v14 self-bind, `D` = magiskinit's `/data` tmpfs):

```sh
unshare -rm sh -c '
  mount -t tmpfs M0 /debug; echo prop > /debug/adb_debug.prop
  mount --bind /debug /debug                      # our v14 cave  -> M1
  mount -t tmpfs D /data; echo magisk > /data/magisk
  mkdir /data/debug
  mount --move /debug /data/debug                 # patch_ro_root (3)
  mount --bind /data /debug                       # setup_tmp
  mount --move /data/debug /debug                 # patch_ro_root (4)
  ls /debug; umount /debug; ls /debug'
```

Observed `/proc/self/mountinfo` after (4), parent chain / stack:

```
root(514) -> M0(955) -> D(958) -> M1(956)      # M1 = bind clone of M0
```

* before `umount`: `/debug` shows **M1** → `adb_debug.prop` (our props)
* after the **single** `umount("/debug_ramdisk")`: `/debug` shows **D**
  (magiskinit's `/data` tmpfs) → `magisk`, `debug/`, **no
  `adb_debug.prop`** → `ro.adb.secure` stays 1.

Without our bind cave the stack is `root -> D -> M0`:
before umount `M0` (props), after umount `D` — still no props.
(That is also why the stock-Magisk image fails even though the props file
was written; Magisk *intends* `init` to unmount the debug ramdisk so that
`D` becomes its `MAGISKTMP`.)

**Conclusion:** Magisk deliberately makes `D` the surviving layer at
`/debug_ramdisk`; the last `umount` always reveals `D`. The v14 trick only
changed which layer is popped, never which layer survives.

### 2.3 What is hidden / clobbered

| our artifact | fate under Magisk |
|---|---|
| `/debug_ramdisk/adb_debug.prop` (M0) | survives in M0 but is **hidden below D**; init never reads it |
| `/debug_ramdisk/adb_keys` (if present) | same |
| `/force_debuggable`, `/adb_debug.prop`, `/adb_keys` in ramdisk root | read by the first stage before `SwitchRoot`; the rootfs is then freed — unchanged behaviour |
| `/first_stage_ramdisk/*` copies | not used by the second stage; harmless |
| `/second_stage_resources/` | init reads only `/second_stage_resources/system/etc/ramdisk/build.prop` and loads it **before** `/system/build.prop` (property_service.cpp:817-826, 1172-1176), so it cannot override `ro.adb.secure`; init also umounts it after `PropertyInit` |
| plain files in the new root | **nothing survives `SwitchRoot` except mounts** — confirmed; do not try a new file at `/` |

corrected: the first two rows describe the mount model. On the measured v22
boot, our init does not run, so `/debug_ramdisk/adb_debug.prop` (M0) is not
created at all (and M1 is absent); the practical result is the same — no props
under Magisk.

---

## 3. Q5 — MagiskSU for the `shell` user

Not automatic. With **no manager app** it is denied outright (not prompted);
with the manager installed it must be granted as described at the end of this
section.

corrected: on v22 the manager is installed and `adb shell su` works only after
Settings → Superuser access → **Apps and ADB**; with the default setting the
call returns "Permission denied".

Source facts:

* `native/src/core/su/db.rs:8`: `impl Default for SuPolicy { fn default() -> Self { SuPolicy::Query } }`
* `native/src/core/su/daemon.rs:271`:
  ```rust
  if access.policy == SuPolicy::Query && mgr_uid < 0 {
      return Ok(Arc::new(SuInfo::deny(uid)));
  }
  ```
  (`mgr_uid < 0` = manager app not installed) → **immediate deny**.
* If the app *is* installed, `connect.rs::app_request()` opens a FIFO and
  waits up to **70 s** for the app to answer; a dead screen ⇒ effectively
  deny.
* `root_access` selects which callers MagiskSU accepts (`core/db.rs:59-68`),
  persisted as `settings.root_access`. It must be **Apps and ADB** for uid 2000
  to pass; otherwise `adb shell su` returns "Permission denied" even with an
  Allow row.
* `su` must be the applet of the *same inode* as magiskd
  (`daemon.rs:164 is_client` compares `/proc/<pid>/exe`); that is why
  `/debug_ramdisk/su` (symlink to `./magisk`) works but a copied/renamed
  `su` binary would not.
* `magisk --sqlite` **requires uid 0** (`daemon.rs:227-234`,
  `RequestCode::SQLITE_CMD => if !is_root { ROOT_REQUIRED }`), so adb shell
  cannot self-grant; it must be run by a root process (init rc / our
  script) or the DB must be pre-seeded.

`SuPolicy` enum order: `Query=0, Deny=1, Allow=2, Restrict=3`
(`core/lib.rs:100`). DB schema v12 (`core/sqlite.cpp:205-226`):

```sql
CREATE TABLE policies (uid INT, policy INT, until INT, logging INT,
                       notification INT, PRIMARY KEY(uid));
CREATE TABLE settings (key TEXT, value INT, PRIMARY KEY(key));
CREATE TABLE strings  (key TEXT, value TEXT, PRIMARY KEY(key));
CREATE TABLE denylist (package_name TEXT, process TEXT, PRIMARY KEY(package_name, process));
PRAGMA user_version=12;
INSERT INTO policies VALUES(2000,2,0,1,1);      -- uid 2000, Allow, never expires
INSERT INTO settings VALUES('root_access',3);   -- AppsAndAdb
INSERT INTO settings VALUES('multiuser_mode',0);-- OwnerOnly
```

`/data/adb/magisk.db` must exist **before magiskd's first DB open**; on a
fresh install `/data/adb` itself is missing and v30.7 aborts
`post-fs-data` (`bootstages.rs:116-122`:
`if !secure_dir.exists() ... error!("* /data/adb is not present, abort")`,
sdk ≥ 24). It is created only at `boot_complete` (line 180). Our rc snippet
creates `/data/adb` + the DB at `post-fs-data` *before* Magisk's own action.
(corrected: on v22 `/data/adb` existed but `/data/adb/magisk` was empty — see
the measured state below.)

Prebuilt DB used here: 36,864 B, md5 `45775916c134edfce35b09337522c5f3`,
`PRAGMA integrity_check = ok`, `user_version = 12`. It is read/written by
magiskd as before; magiskd is `permissive` and explicitly allowed all
`file_type` access (`native/src/sepolicy/rules.rs`), so the label of the
freshly created file does not matter for the daemon.

Measured first-boot state on v22: `/data/adb/magisk` was empty, so
`setup_magisk_env()` aborted (`/cache/magisk.log`:
`E : * Magisk environment incomplete, abort`) and no `post-fs-data.d` script
ran. The fix is to **pre-seed** `/data/adb/magisk` from the v30.7 APK with
`busybox`, `magisk64`, `magisk32`, `magiskinit`, `magiskpolicy` and
`stub.apk` (0755 for executables, 0644 for `stub.apk`). Once seeded, magiskd
starts, the environment check passes, and `post-fs-data.d` scripts (including
`adbkey.sh`, §4.2) execute. The su path still needs magiskd + the DB;
installing the manager (`adb install /tmp/opencode/Magisk.apk`) and setting
Superuser access to **Apps and ADB** is what makes `su` succeed.

---

## 4. Options, ranked

### 4.1 Recommended — **B: put the props into magiskinit's `/data` tmpfs (`D`)** (implemented in v22; props unreachable)

Keep Magisk untouched. Replace the v14 cave at `0x1EF9D0` with:
self-bind (unchanged v14 behaviour) **+ copy
`/debug_ramdisk/adb_debug.prop` → `/data/adb_debug.prop`** using raw
syscalls (no fork, no race).

Why this is correct: `D` is created by magiskinit's *first* stage, i.e.
before our cave runs, and `setup_tmp()` later bind-mounts exactly `D` onto
`/debug_ramdisk`; the real init's one `umount` reveals `D`. Note that `D`
is **magiskinit's tmpfs mounted at `/data`**, not the real (latemount)
f2fs `/data`: the copy happens in the first stage, and the tmpfs
superblock survives both `exec_init()`'s `umount("/data")` and the later
mount of the real `/data` because the `D` bind at `/debug_ramdisk` holds
it. Therefore:

| load_debug_prop | our cave | what init reads |
|---|---|---|
| false (this device) | with bind | umount pops M1 → **D**, props in D ✔ |
| false | without bind | umount pops M0 → **D**, props in D ✔ |
| true | with bind | reads M1 (=M0, props) ✔ |
| true | without bind | reads M0 (props) ✔ |

i.e. it is robust in all four combinations; the bind cave may be kept or
removed (kept = keeps the image working if it is ever booted without
Magisk).

corrected (measured on v22): the table is the design model and it does not
survive contact with the real Magisk boot. Our init does not run at all under
Magisk, so the cave (and with it the copy) never executes: the props are
**unreachable** under Magisk, and no combination of `load_debug_prop` changes
that. v22 therefore keeps the analysis but does not rely on it — adb
authorisation comes from the `post-fs-data.d` key hook (§4.2), and root from
`adb shell su`. In v22 the 300-byte cave is further replaced by a
clone + `execve("/system/bin/sh", "-c", script)` variant built on the v19
base; it still does not run under Magisk.

Cave (300 bytes, verified with capstone; keeps `x9=argv`, `x19` untouched,
restores the original `mov x0,x19`, branches to `0xF1AC8`):

```
0x1EF9D0  mov  x9, x1                 ; save argv
0x1EF9D4  sub  sp, sp, #0x100         ; 256-byte copy buffer
0x1EF9D8  mount("/debug_ramdisk","/debug_ramdisk",0,MS_BIND,0)
0x1EF9FC  openat(AT_FDCWD,"/debug_ramdisk/adb_debug.prop",O_RDONLY,0)
0x1EFA20  openat(AT_FDCWD,"/data/adb_debug.prop",
                 O_WRONLY|O_CREAT|O_TRUNC=0x241, 0644)
0x1EFA44  read(fd,sp,256) / write(fd2,sp,n) loop
0x1EFA7C  close(fd); close(fd2)
0x1EFAA4  add sp,sp,#0x100
0x1EFAA8  mov x1,x9
0x1EFAAC  mov x0,x19
0x1EFAB0  b   0xF1AC8
0x1EFAB4  "/debug_ramdisk"                 (bind)
0x1EFAC4  "/debug_ramdisk/adb_debug.prop"  (source)
0x1EFAE4  "/data/adb_debug.prop"           (target)
```

Exact bytes (300 B, to be written at file offset/VA `0x1EF9D0`):

```
e90301aaff0304d10000009000d02a910100009021d02a91e2031faa030082d2
e4031faa080580d2010000d4600c80920100009021102b91e2031faae3031faa
080780d2010000d4ea0300aa4004f836600c80920100009021902b91224880d2
833480d2080780d2010000d4eb0300aac002f836e0030aaae1030091022080d2
e80780d2010000d42001f8b6000100b4ec0300aae0030baae1030091e2030caa
080880d2010000d4f3ffff17e0030aaa280780d2010000d4e0030baa280780d2
010000d404000014e0030aaa280780d2010000d4ff030491e10309aae00313aa
0608fc172f64656275675f72616d6469736b00002f64656275675f72616d6469
736b2f6164625f64656275672e70726f700000002f646174612f6164625f6465
6275672e70726f7000000000
```

Hook (already present in the v14 init; write it if starting from stock):
`0xF1AC4: e0 03 13 aa  ->  c3 f7 03 94` (`bl 0x1EF9D0`).
The RX `PT_LOAD` must have `p_filesz=p_memsz=0x13F000` (already true in
`vendor_boot_magisk.img`; stock init needs the extension and the cave area
must be all-zero — both are done by `tools/build_v9_vendor.py` logic).
Patched init: 2,097,128 B, md5 `90f7ac9b8c6860cd3fb87decea83373f`
(only the 300-byte cave differs from the v14 init).

**Plus the SU/adb-keys `overlay.d` snippet** (see §4.2) so root comes up
too. This is what the verified host image `vendor_boot_magisk_B2.img`
contains.

### 4.2 SU pre-grant + adb_keys fallback via `overlay.d` (planned; v22 uses `post-fs-data.d` instead)

`overlay.d` is the *only* pre-seedable root-execution hook that works on a
first boot without `/data/adb`:

* `magiskinit`'s `patch_ro_root()` renames `overlay.d` → `ROOTOVL =
  <tmp>/.magisk/rootdir`;
* `load_overlay_rc(ROOTOVL)` reads every top-level `*.rc` and appends its
  **contents** to the generated `init.rc` (rootdir.cpp:94-104), replacing
  `${MAGISKTMP}` with the tmp dir; `inject_magisk_rc()` is appended *after*
  it, so an `on post-fs-data` action in our rc runs **before** Magisk's
  own `exec ... magisk --post-fs-data`;
* other `overlay.d` files are only bind-mounted over **existing** `/` files
  (`mount_overlay` → `mount_impl` checks `dest.exists()`), so you can
  replace files but not create new paths. Our files are read from
  `${MAGISKTMP}/.magisk/rootdir/...` instead.
* `.backup/.magisk` config has no execution hook (only
  `KEEPVERITY/KEEPFORCEENCRYPT/RECOVERYMODE/PREINITDEVICE`);
  `/data/adb/post-fs-data.d` and `/data/adb/service.d` cannot be
  pre-seeded (they need the real, encrypted `/data`) and on a fresh install
  Magisk aborts `post-fs-data` before running them
  (`bootstages.rs:116-152`); `boot-completed.d` does **not** exist in
  v30.7 (only the `post-fs-data` and `service` stage dirs are executed).

corrected: v22 does not use the `overlay.d` snippet. Once `/data/adb/magisk`
is pre-seeded (§3), magiskd survives the environment check and **does** run
`/data/adb/post-fs-data.d/adbkey.sh`, which is what authorises adb on the
device. That hook needs the real (encrypted, latemount) `/data` to be up,
which it is by `post-fs-data`. So "`post-fs-data.d` cannot be pre-seeded" was
true only for the un-seeded image; it is the route that actually works after
the §3 fix. The `overlay.d` files below are kept as the alternative design
(and were present in the host-only B2 image).

Files added to the ramdisk (already in `vendor_boot_magisk_B2.img`):

`overlay.d/adbroot.rc` (289 B, md5 `42bb8e14d97efa057399bc6624ba0355`):

```
on post-fs-data
    exec u:r:magisk:s0 root root -- /system/bin/sh ${MAGISKTMP}/.magisk/rootdir/adbroot.sh

on property:sys.boot_completed=1
    exec u:r:magisk:s0 root root -- ${MAGISKTMP}/magisk --sqlite "REPLACE INTO policies(uid,policy,until,logging,notification)VALUES(2000,2,0,1,1)"
```

`overlay.d/adbroot.sh` (733 B, md5 `590860a49dd9c5e1a3549e84e10734f7`):

```sh
#!/system/bin/sh
TMP=/debug_ramdisk/.magisk/rootdir
# 1) Pre-seed MagiskSU policy DB: uid 2000 (adb shell) = Allow.
if [ ! -f /data/adb/magisk.db ] && [ -f "$TMP/magisk.db" ]; then
  mkdir -p /data/adb
  cp "$TMP/magisk.db" /data/adb/magisk.db
  chown 0:0 /data/adb/magisk.db
  chmod 600 /data/adb/magisk.db
fi
# 2) Fallback adb authorisation independent of ro.adb.secure.
if ! grep -q 'musin@tomato' /data/misc/adb/adb_keys 2>/dev/null; then
  mkdir -p /data/misc/adb
  cp "$TMP/adb_keys" /data/misc/adb/adb_keys
  chown 1000:2000 /data/misc/adb/adb_keys
  chmod 640 /data/misc/adb/adb_keys
  restorecon /data/misc/adb/adb_keys 2>/dev/null
fi
exit 0
```

`overlay.d/magisk.db` = the 36,864 B DB from §3.
`overlay.d/adb_keys` = the host key, 714 B, md5 `711e0052cb6c7c7b59f52531260c54d5`
(same bytes as the `adb_keys` already in the v14 ramdisk,
`... musin@tomato\n`). `restorecon` labels it `u:object_r:adb_keys_file:s0`
(verified in `plat_file_contexts`).

The `--sqlite` action is idempotent and fixes an *existing*
`magisk.db` that lacks the row. It runs as uid 0 (`SQLITE_CMD` requires
root) and the manager app is not needed.

### 4.3 Option A — relocate Magisk's temp dir (viable, but not recommended)

Instead of copying props, keep v14 untouched and move magiskinit's
`tmp_dir` to an empty, non-mountpoint directory that exists in
system-as-root. Verified on the device: `/my_version` exists, is empty,
and is **not** a mountpoint (`/proc/mounts`, v14). All patches are
in-place, NUL-padded, same length:

| binary | file off | old | new (exact bytes) |
|---|---|---|---|
| `magiskinit` | `0x2a7b` | `"/debug_ramdisk\0"` (15) | `/my_version\0\0\0\0` |
| `magisk` core | `0x9241` | `"/debug_ramdisk/.magisk\0"` (23) | `/my_version/.magisk\0\0\0\0` |
| `magisk` core | `0x9258` | `"/debug_ramdisk\0"` (15) | `/my_version\0\0\0\0` |

(`magisk` core = `overlay.d/sbin/magisk.xz` content, also
`lib/arm64-v8a/libmagisk.so`; recompress with
`magiskboot compress=xz magisk_patched magisk.xz`.  `magiskinit` is the
cpio entry `init`.)  `0x2020a0 "/data/debug_ramdisk"` stays — it is only
the staging dir inside `/data`.

Why it works: `patch_ro_root()` assigns `tmp_dir` from the patched literal;
the initial `MS_MOVE` source is `tmp_dir`, target is
`/data/debug_ramdisk`. Because `/my_version` is **not** a mountpoint,
`MS_MOVE` fails with `EINVAL` (xmount logs and returns -1, non-fatal,
`base/xwrap.rs:220`), `setup_tmp()` then bind-mounts `/data` onto
`/my_version`, and the restore `MS_MOVE` also fails harmlessly
(`rmdir("/data/debug_ramdisk")` succeeds). `/debug_ramdisk` is never
touched, so the v14 bind trick keeps working unchanged. The core binary's
`get_magisk_tmp()` (`core/utils.cpp:33-45`, literals
`/debug_ramdisk/.magisk` and `/debug_ramdisk`) must be patched as above,
otherwise magiskd cannot find its tmp dir/socket
(`MAIN_SOCKET = .magisk/device/socket`, built from `get_magisk_tmp()`).

Risks: three literal patches in two Magisk binaries + xz repack; relies on
`/my_version` never becoming a mountpoint; a later app "additional setup"
can put an unpatched `magisk` into `/data/adb/magisk` (boot-time daemon
still runs the ramdisk one, so only confusing, not fatal — unverified).
This option touches Magisk internals and is therefore ranked below B.

### 4.4 Option C alone — adb_keys only

Works for adb, but not for root, and is racier: it needs a root child
(fork in the cave) that waits for the real `/data` and writes
`/data/misc/adb/adb_keys` before adbd starts. The v17 attempt to
`execve("/system/bin/sh")` from the first-stage hook is denied by SELinux
(see `re-vendor-boot-v17-bootloop-2026-10-25.md` §0/§4); the `overlay.d`
rc route used above runs **after** the policy is loaded, in the permissive
`u:r:magisk:s0` domain, so writing/relabelling `adb_keys` is allowed (this
combination was never booted — unverified). We
therefore keep C only as the fallback in §4.2, not as a replacement for
the props.

corrected: v22 realises the same idea the other way round — the key is written
by a `post-fs-data.d` script (`adbkey.sh`) run by magiskd, not by a
first-stage cave, which is why it works without any policy trick.

### 4.5 App approval only (this is what v22 uses for `su`)

Install `/tmp/opencode/Magisk.apk`, open it (scrcpy; panel is dead) and
answer the 70 s prompt. Then, in the manager, open
**Settings → Superuser access** and choose **Apps and ADB**; the choice is
persisted in `magisk.db` and survives reboots. Without it `adb shell su`
returns "Permission denied". Not suitable headless; the manager app also
needs its own first-run setup. Only as a fallback if the DB pre-seed is
skipped.

---

## 5. Exact build recipe (host, no flashing)

Starting from `vendor_boot_magisk.img` (md5 `14f93d33...`), magiskboot v30.7.
corrected: this recipe produced the host-only B2 image below. The shipped
`vendor_boot_v22_magisk.img` (md5 `a874a5c217d2e42aa7813a151bbd78be`) starts
from the v19 base (permissive cmdline, props, `service.adb.root=1`) instead,
uses the same magiskboot patch, and replaces the v14 cave with the
clone + `execve("/system/bin/sh", "-c", script)` variant; the `overlay.d`
payloads were not used and `/data/adb/post-fs-data.d/adbkey.sh` authorises adb
instead. The commands and byte strings are unchanged and still describe the
B2 build accurately.

```sh
mkdir /tmp/vbB && cd /tmp/vbB
cp /path/to/magiskboot . ; cp /path/to/vendor_boot_magisk.img .
./magiskboot unpack vendor_boot_magisk.img        # -> vendor_ramdisk/ramdisk.cpio, dtb, config

./magiskboot cpio vendor_ramdisk/ramdisk.cpio "extract system/bin/init init.orig"
python3 - <<'PY'
b = bytearray(open('init.orig','rb').read())
assert b[0xF1AC4:0xF1AC8] in (bytes.fromhex('e00313aa'), bytes.fromhex('c3f70394'))
b[0xF1AC4:0xF1AC8] = bytes.fromhex('c3f70394')          # bl 0x1EF9D0
CAVE = bytes.fromhex(
 "e90301aaff0304d10000009000d02a910100009021d02a91e2031faa030082d2"
 "e4031faa080580d2010000d4600c80920100009021102b91e2031faae3031faa"
 "080780d2010000d4ea0300aa4004f836600c80920100009021902b91224880d2"
 "833480d2080780d2010000d4eb0300aac002f836e0030aaae1030091022080d2"
 "e80780d2010000d42001f8b6000100b4ec0300aae0030baae1030091e2030caa"
 "080880d2010000d4f3ffff17e0030aaa280780d2010000d4e0030baa280780d2"
 "010000d404000014e0030aaa280780d2010000d4ff030491e10309aae00313aa"
 "0608fc172f64656275675f72616d6469736b00002f64656275675f72616d6469"
 "736b2f6164625f64656275672e70726f700000002f646174612f6164625f6465"
 "6275672e70726f7000000000")
assert len(CAVE) == 300
b[0x1EF9D0:0x1EF9D0+300] = CAVE
open('init.patched','wb').write(b)
PY

# adbroot.rc / adbroot.sh / magisk.db / adb_keys from §4.2 (§3 for the DB)
./magiskboot cpio vendor_ramdisk/ramdisk.cpio \
  "add 0755 system/bin/init init.patched" \
  "add 0644 overlay.d/adbroot.rc adbroot.rc" \
  "add 0755 overlay.d/adbroot.sh adbroot.sh" \
  "add 0600 overlay.d/magisk.db magisk.db" \
  "add 0600 overlay.d/adb_keys adb_keys"
./magiskboot repack vendor_boot_magisk.img vendor_boot_magisk_B2.img
```

Reproduced result: 67,108,864 B, `VNDRBOOT` v4,
md5 `fa44f119ccb1feb5aef9b81e7baec68f`; statically verified: cpio has
`init`=magiskinit (199,960 B), `.backup/init`→`/system/bin/init`,
`system/bin/init`=patched (2,097,128 B, hook `bl 0x1ef9d0`, cave ok),
`overlay.d/{adbroot.rc,adbroot.sh,magisk.db,adb_keys}`, props and
`force_debuggable` intact, DB `user_version=12` + policy row.
Not flashed.

The repack was also checked against the v17 failure mode
(`re-vendor-boot-v17-bootloop-2026-10-25.md`): the B2 `dtb` is intact
(108,348 non-zero bytes of 191,577) and the `vendor_ramdisk_table` entry is
`type=1 (platform), size=<ramdisk_size>, offset=0` — i.e. magiskboot
preserved them; do **not** use the old custom vendor_boot rebuilder for
this image without re-checking those two regions.

If the base init is stock (no hook / RX segment shorter): apply the hook,
extend the RX `PT_LOAD` `p_filesz=p_memsz` to `0x13F000`, and require the
cave region `0x1EF9D0..0x1EFAFC` to be zero (the existing
`tools/build_v9_vendor.py` does this for the v14 cave; same mechanics).

## 6. Post-flash verification (read-only)

The block below is the **B2 design's** expectation and is kept for the record.
corrected: on the shipped v22 image the measured values are `ro.adb.secure=1`
and `ro.debuggable=0`, `/debug_ramdisk/adb_debug.prop` is absent, and adb is
authorised by the key hook instead — so `ro.adb.secure=0` / `ro.debuggable=1`
are **not** what you will see under Magisk. Use the v22 checks after it.

```sh
adb shell getprop ro.adb.secure            # expect 0
adb shell getprop ro.debuggable            # expect 1
adb shell grep debug_ramdisk /proc/self/mountinfo
#   expect the surviving tmpfs to be the Magisk one (contains magisk,su,.magisk)
adb shell /debug_ramdisk/su -c 'id; ls -la /debug_ramdisk | head'
#   expect uid=0(root); adb_debug.prop, magisk, su, .magisk visible
adb shell /debug_ramdisk/su -c 'ls -l /data/adb/magisk.db /data/misc/adb/adb_keys'
adb shell /debug_ramdisk/su -c 'grep -c musin@tomato /data/misc/adb/adb_keys'
```

v22 checks (all read-only, no root needed for the first three):

```sh
adb devices                              # -> device, no "unauthorized"
adb shell id                             # -> uid=2000(shell); adbd stays shell
adb shell getprop ro.adb.secure          # -> 1
adb shell getprop ro.debuggable          # -> 0
adb shell getenforce                     # -> Permissive (from the v22 cmdline)
adb shell ls /debug_ramdisk/adb_debug.prop   # -> No such file (props route dead)
adb shell su -c id                       # -> uid=0(root) ... u:r:magisk:s0
```

If `adb devices` shows `unauthorized` under Magisk, the `post-fs-data.d`
key hook did not run — check `/data/adb/magisk` is fully pre-seeded (§3) and
`/data/misc/adb/adb_keys` contains the host key. If `su` is denied, set
Superuser access to **Apps and ADB** (§4.5); with the default setting
`adb shell su` returns "Permission denied" even if an Allow row exists.

## 7. Risks / caveats

* The B2 image was never flashed (v22 is), so its cave is only statically
  verified: real ARM64 code, and a fault before `execv` = no init = preloader
  recovery. The code touches only registers/stack, checks open/read errors,
  and restores `x0/x1`; still, the first flash should be done with the
  recovery path ready.
* corrected: the first Magisk boot is **not** just SafeMode. With an empty
  `/data/adb/magisk` magiskd aborts (`E : * Magisk environment incomplete,
  abort` in `/cache/magisk.log`) and nothing runs. Pre-seed the environment
  (§3) before the first boot; then modules/Zygisk work normally.
* corrected: our vendor-init cave does not execute under Magisk at all, so
  `ro.adb.secure=0`/`ro.debuggable=1` never reach the second stage. Do not
  expect the props route to work; use `adb shell su`.
* The DB is copied only when `/data/adb/magisk.db` does not exist, to avoid
  clobbering a later user DB; the `--sqlite` at boot-completed is the
  idempotent backstop.
* Option A relies on `/my_version` not being a mountpoint and on patched
  `get_magisk_tmp()`; if used, re-check both on any ROM update.
* `ro.adb.secure=0` makes adb trust any host (no key needed) — this is
  the existing v14 behaviour and is what the props file is for; under Magisk
  the `adb_keys` key hook is the only working path.

## 8. Artifacts on the host (not committed)

| path | what |
|---|---|
| `/tmp/opencode/vendor_boot_magisk_B2.img` | recommended test image, md5 `fa44f119ccb1feb5aef9b81e7baec68f` |
| `/tmp/opencode/init_magisk_props.bin` | patched `system/bin/init`, md5 `90f7ac9b8c6860cd3fb87decea83373f` |
| `/tmp/opencode/mkcave_b.py` | cave builder/verifier (encoders + capstone dump) |
| `/tmp/opencode/{adbroot.rc,adbroot.sh,magisk.db,adbroot_keys}` | overlay.d payloads from §4.2 |
| `/tmp/opencode/mwork3/`, `mwork4/`, `mwork5/` | magiskboot unpack/repack work dirs |
| `/tmp/opencode/Magisk-30.7/` | Magisk source used for the quotes |

corrected: the image that was actually flashed and is current is
`/home/musin/vendor_boot_v22_magisk.img` (md5
`a874a5c217d2e42aa7813a151bbd78be`); B2 above is the host-only precursor.
