# RE: patching `adbd` inside the ADBD APEX — route assessment

Date: 2026-10-25. Branch `oplus-mt6789-unlock`. **Offline only** (no phone, no DA,
no flashing, nothing written back). Inputs: stock export
`RMX3630export_11_14.0.0.200EX01_2024090223460108.zip`, member `IMAGES/system.img`
(884,732,164 B, Android sparse). Work dir `/tmp/fw`, large temporaries deleted
after the run.

Companion contracts: `PLAN-q1-q2-2026-10-25.md` §C, `HANDOFF-termux-2026-10-25.md`
§2.3 / §6 item 3.

---

## 0. Verdict (short)

| route | verdict |
|---|---|
| push a modified APEX into `/data/apex/active` | **NOT VIABLE** — apexd requires the update's bundled `apex_pubkey` to equal the pre-installed one and then verifies `apex_payload.img` AVB `SHA256_RSA4096`; the key is Google's |
| replace `/system/apex/com.google.android.adbd.apex` with a re-signed APEX | **NEEDS-ROOT / NEEDS-FLASH** — apexd itself would accept it (the trust anchor is the key *inside* the APEX), but `/system` is dm-verity protected by `vbmeta_system` (`Flags: 0`), so the write must be a raw flash of `system_a` **plus** a re-generated, re-signed `vbmeta_system` |

The exact blocking check for the *userspace* route is
`ApexFileRepository::AddDataApex()` (android12-release,
`apexd/apex_file_repository.cpp:130-141`): "public key doesn't match
pre-installed one" (string present in `/system/bin/apexd`), followed by
`ApexFile::VerifyApexVerity()` in `MountPackage()` (`apexd/apexd.cpp:483-488`).

---

## 1. Pipeline and logs

### 1.1 sparse → raw

`docs/notes/sparse_unpack.py` (new, `--help` exit 0):

```
$ python3 docs/notes/sparse_unpack.py --info /tmp/fw/system.img
file            : /tmp/fw/system.img (884732164 bytes)
format          : Android sparse, v1.0
block size      : 4096
total blocks    : 216676
total chunks    : 19
raw size        : 887504896
expansion ratio : 1.003x (884732164 -> 887504896)

$ python3 docs/notes/sparse_unpack.py --unpack /tmp/fw/system.img -o /tmp/fw/system.raw
wrote  : /tmp/fw/system.raw
size   : 887504896
sha256 : bd106e1ccd590f0e6911f6fbb130096b2bc12dbe86953d293c448ec0d00628e1
(unpack_exit=0)
```

Sanity: the filesystem itself is `214308 * 4096 = 877,805,568 B` (matches the
`system` hashtree descriptor in `vbmeta_system`, §3.3). The extra
`887,504,896 - 877,805,568 = 9,699,328 B` is the dm-verity tree area
(6,922,240 B) plus export padding — i.e. the exported raw is partition-sized,
not filesystem-sized.

### 1.2 filesystem detection

```
offset 0x400 magic: 0xE0F5E1E2 EROFS      (ext4 magic @0x438 = ab15 -> not ext4)
block_size=4096  root_nid=62  inodes=3901  blocks=214308
feature_compat=0x00000003  feature_incompat=0x00000001 (COMPR_CFGS)
available_compr_algs=0xffff (lz4, lzma, deflate, zstd)
```

### 1.3 EROFS access — what was tried, in order

1. `7z l system.raw` (p7zip 17.05) — **fails**: misdetects the image as `zip`,
   `Headers Error / Unconfirmed start of archive`, lists one bogus 285 MB file.
   p7zip has no EROFS driver.
2. `apt-get install -y erofs-utils` — **worked** (network was available):
   `erofs-utils 1.8.6-1` (`fsck.erofs` supports lz4/lz4hc/lzma/deflate/zstd).
   ```
   $ fsck.erofs --extract=/tmp/fw/sysroot --overwrite /tmp/fw/system.raw
   (extract_exit=0, 9 s, 1.4 GB extracted, no integrity complaints)
   ```
3. `docs/notes/erofs_lite.py` (new pure-python fallback, `--help` exit 0):
   parses superblock/compact+extended inodes/inline+flat-plain dirents and
   files. It correctly lists both trees and extracts inline/flat-plain files
   (`/system/ro.prop` extracted byte-identical to `fsck.erofs`), but on this
   image **all four target files use `compressed-compact` data**, where it
   returns exit 3 by design:
   ```
   $ erofs_lite.py --extract /system/build.prop
   cannot extract: inode 10348988 uses compressed-compact data; needs fsck.erofs
   (exit=3)
   $ erofs_lite.py --ls /system | grep build.prop
   -rw------- 10348988 8152 build.prop
   ```
   So the pure-python path alone would have been **insufficient** for these
   files; `fsck.erofs` was required. This is stated rather than hidden.

### 1.4 extracted targets (from `fsck.erofs` output)

| path | size (B) | sha256 |
|---|---|---|
| `/system/apex/com.google.android.adbd.apex` | 8,822,784 | `ce80eb5a2ea4ad05be8d362e684e214d7da53e1a5a9df1670040c9d39e39f108` |
| `/system/build.prop` | 8,152 | `66be13e6b4b9bca5f8644ea427db0b56dc04e6f2e3e0909a05095782bc42a025` |
| `/system/etc/selinux/plat_property_contexts` | 102,885 | `736ba6743e8c98196de4f603df1a36b5d65ef4ef4516e5e484516cc021acbbce` |
| `/system/bin/init` | 3,085,160 | `a458669ba60984cedf3f0491da6325e2d9f28b51f93bef8522c07308cc8c0037` |

Sizes of APEX and `init` match the handoff exactly. `build.prop` is **8,152 B**
here vs 8,168 B in the handoff — same content class, different recorded dump;
`ro.adb.secure=1` etc. are confirmed below.

`/system/bin/init` was copied to **`/tmp/fw/system_init`** (3,085,160 B, sha256
`a458669b…`) for the Q2 agent.

`/system/bin/adbd` **does not exist** — `2>&1` from `ls` returns
`No such file or directory`; adbd only ships inside the APEX.

---

## 2. APEX anatomy

`unzip -l` (exit 0):

```
   Length      Name
      218      apex_manifest.pb            -> name "com.android.adbd"
  8544256      apex_payload.img
     1032      apex_pubkey
     1632      AndroidManifest.xml
     1446      apex_build_info.pb
   230046      assets/NOTICE.html.gz
       32      stamp-cert-sha256
      782      META-INF/CERT.SF
     2242      META-INF/CERT.RSA
      647      META-INF/MANIFEST.MF
```

* `apex_payload.img`: 8,544,256 B, **ext4** (`53 ef` @0x438), containing
  `bin/adbd` (2,291,304 B, sha256
  `8fe599ba81bdf4bc5684e1df87d94f38ba73ee042636f7df49f07368145a3962`),
  `lib{,64}/*`, `etc/init.rc`, `apex_manifest.pb`. Payload init.rc:
  ```
  service adbd /apex/com.android.adbd/bin/adbd --root_seclabel=u:r:su:s0
      class core
      socket adbd seqpacket 660 system system
      disabled
      override
      seclabel u:r:adbd:s0
      user root
  ```
* `apex_pubkey`: 1,032 B AVB/RSA public key, `key_num_bits=4096`,
  sha256 `e38c26f133fa88a72dbfc8e5cd73cecdb5d82131140b1d067bafbb4886a9aade`,
  sha1 `d0b0b877bc6a48b1ecd17632205e5fb4d92b9273`.

### 2.1 payload is AVB-signed with that exact key

`avbtool info_image --image apex_payload.img`:

```
Footer version:           1.0
Image size:               8544256 bytes
Original image size:      8462336 bytes
VBMeta offset:            8536064   VBMeta size: 2240
Header Block: 256  Authentication Block: 576  Auxiliary Block: 1408
Public key (sha1):        d0b0b877bc6a48b1ecd17632205e5fb4d92b9273
Algorithm:                SHA256_RSA4096
Descriptors:
    Hashtree descriptor:
      Image Size: 8462336   Tree Offset: 8462336  Tree Size: 73728
      Hash Algorithm: sha256
      Salt:        66f97e8d6a3839403a930f0e7777b072e72d18d639ed94f5610c9ee3b5189dd8
      Root Digest: a2091f569353e861e298048980dc3db399ff95a2aa6408f317afea29373475c6
      Flags: 0
    Prop: apex.key -> 'com_google_android_adbd-image'
```

`sha1(apex_pubkey) == d0b0b877…`, i.e. **the payload is signed by the key that
travels inside the same APEX** (self-contained / self-signed trust). The APEX
zip's own `META-INF/CERT.RSA` is not part of this chain and apexd never reads it
(§3.1).

---

## 3. What verifies it on-device

### 3.1 apexd reads the key out of the APEX itself

android12-release `apexd/apex_file.cpp` (`ApexFile::Open`, lines 83-190) opens
the zip, locates `apex_payload.img` + `apex_manifest.pb` + `apex_pubkey`, and
does **no JAR/META-INF signature check**. `apex_file.h:53`:
`GetBundledPublicKey() { return apex_pubkey_; }`.

`apexd/apex_file_repository.cpp:41-89` (`ScanBuiltInDir`, `/system/apex`) stores
each `ApexFile`; `GetPublicKey(name)` (line 171-177) returns
`it->second.GetBundledPublicKey()` — again the key from the scanned file.

`apexd/apexd.cpp:483-488` (`MountPackage`) then does, for **every** mount,
including pre-installed APEX:

```cpp
auto public_key = instance.GetPublicKey(apex.GetManifest().name());
auto verity_data = apex.VerifyApexVerity(*public_key);
```

and the comment at `apexd.cpp:499-504` is explicit:

> for APEXes in immutable partitions, we don't need to mount them on dm-verity
> because they are already in the dm-verity protected partition; system.
> However, note that we don't skip verification to ensure that APEXes are
> correctly signed.

Consequence: **the APEX signature is not an independent trust anchor for a
pre-installed APEX on this build.** A re-signed APEX placed in `/system/apex`
carries its own matching key and would verify. What protects `/system/apex` is
the system partition itself (§3.3).

### 3.2 there is no separate on-device key store

The premise `/system/etc/security/apex/` or `/system/etc/security/apex_pubkey`
does not hold on this build:

```
$ ls system/etc/security/
cacerts/  cacerts_google/  fsverity/  otacerts.zip -> /my_engineering/etc/security/otacerts.zip
$ find system -name '*apex_pubkey*' -o -name '*.avbpubkey'
(no output)
$ strings /system/bin/apexd | grep -E '/system/etc/security|apex_pubkey'
apex_pubkey        # only the zip entry name; no /system/etc/security path
```

So there is no built-in key list to compare against — the only "anchor" is the
key bundled in the pre-installed APEX plus the system partition's dm-verity.

### 3.3 `/system` is dm-verity protected, and that is the real wall

`vbmeta_system.img` from the stock export (`avbtool info_image`):

```
Flags: 0            (neither VERIFICATION_DISABLED nor HASHTREE_DISABLED)
Chain: vbmeta.img -> vbmeta_system   public key (sha1) 3c5f7b18b6d554a9c198f42ef90f7751d28fb8d6
Hashtree descriptor (system):
  Image Size:   877805568
  Tree Offset:  877805568   Tree Size: 6922240
  Salt:         4841e948e880155bfb8282e13062e61e
  Root Digest:  fa1a75fd2115eb855bc41448a6c90ee204000bff6ebebc53954e9a07dfc14c0c
  Flags:        0
```

`vbmeta.img` is `SHA256_RSA2048`, key sha1 `3c5f7b18…`, and chains
`boot`, `vbmeta_system`, `vbmeta_vendor` to the same OPLUS key.

Userspace (`fs_mgr/libfs_avb/fs_avb.cpp:270-291`) tolerates
`ERROR_VERIFICATION` / `PUBLIC_KEY_REJECTED` only when `IsDeviceUnlocked()`
returns true, and even then not if `/metadata/avb_enforce` exists:

```cpp
static bool IsAvbPermissive() {
    if (IsDeviceUnlocked()) {
        if (!access(DSU_METADATA_PREFIX "avb_enforce", F_OK)) {
            LINFO << "Enforcing AVB verification when the device is unlocked";
            return false;
        }
        return true;
    }
    return false;
}
```

This matches the campaign state (handoff §2.1: LK runs `avb_slot_verify` with
`ALLOW_VERIFICATION_ERRORS` because `img_auth_required=0`; patched boot with a
hash mismatch does boot). `metadata` was wiped, so no `avb_enforce` marker is
expected. **But permissive verification does not disable dm-verity**: it only
lets the modified descriptors through. A patched `/system` mounted with the
stock `vbmeta_system` hashtree fails reads on every modified block; the
descriptor has to be re-generated and the vbmeta re-signed with a key of ours.

### 3.4 the `/data/apex/active` path

`ro.apex.updatable=true` is present — `/system/build.prop:130`:

```
ro.apex.updatable=true
```

so apexd does scan `/data/apex/active` (`apexd.cpp` OnStart ->
`ApexFileRepository::AddDataApex`). But `apex_file_repository.cpp:130-141`:

```cpp
auto pre_installed_public_key = GetPublicKey(name);
if (!pre_installed_public_key.ok() ||
    apex_file->GetBundledPublicKey() != *pre_installed_public_key) {
    LOG(ERROR) << "Skipping " << file
               << " : public key doesn't match pre-installed one";
    continue;
}
```

Present in the on-device binary (`strings /system/bin/apexd`, both spellings
`pre-installed` and `pre-installed one`). An update APEX must therefore contain
**Google's** `apex_pubkey` (sha1 `d0b0b877…`), and its payload must pass
`VerifyApexVerity()` → `SHA256_RSA4096`. We have neither the private key nor a
way around `libavb`. Dropping the stock APEX back in changes nothing; dropping
a patched one is rejected on the key, and re-signing with our own key is
rejected on the key comparison.

Also relevant: `apexd` only accepts updates with `version >= pre-installed`
and only activates the staged/active file after `VerifyPackageBoot()`
(`apexd.cpp:797-812`, called at 2136 for staged packages and 3446 for non-staged
installs).

---

## 4. `init` disassembly for Q2 (handoff §2.3 correction)

File: `/tmp/fw/system_init` (3,085,160 B, sha256 `a458669b…`), left there for
the other agent.

The handoff guessed `0x2D81A0` "may reject" property loading. It does not.
`readelf -rW /tmp/fw/system_init` resolves it:

```
00000000002e0648  0000000d00000402 R_AARCH64_JUMP_SLOT  _ZN7android4base9ShouldLogENS0_11LogSeverityEPKc + 0
```

`0x2D81A0` is the PLT thunk for `android::base::ShouldLog(LogSeverity, const char*)`.

```
0x00156fe4  e0f6ffb0  adrp x0, 0x33000
0x00156fe8  00b82391  add x0, x0, 0x8ee          ; "/debug_ramdisk/adb_debug.prop"
0x00156fec  81008052  mov w1, 4                  ; R_OK
0x00156ff0  ec050694  bl sym.imp.access
0x00156ff4  60030035  cbnz w0, 0x157060           ; no file -> skip
0x00156ff8  40008052  mov w0, 2                  ; VERBOSE
0x00156ffc  e1031faa  mov x1, xzr
0x00157000  68040694  bl sym.imp.android::base::ShouldLog
0x00157004  e0e30037  tbnz w0, 0, 0x158c80       ; -> verbose-log block
0x00157008  ...
0x0015700c  adrp x0, 0x33000                    ; same path, reloaded
0x00157028  bl  load_properties_from_file(...)  ; executed unconditionally
```

`0x158C80` is that verbose-log block, not a rejection branch:

```
0x00158c80  bl sym.imp.__errno
0x00158c88  ldr w22, [x0]                        ; save errno
0x00158ca8  bl android::base::LogMessage          ; file "system/core/init/property_service.cpp", line 0x810, severity 2 (VERBOSE)
0x00158cc0  bl __put_character_sequence           ; "Loading " (8 B @0x1b360)
0x00158cd0  bl __put_character_sequence           ; "/debug_ramdisk/adb_debug.prop" (29 B @0x338ee)
0x00158cdc  str w22, [x19]                        ; restore errno
0x00158ce0  b 0x157008                            ; back to the normal path
```

This is literally `LOG(VERBOSE) << "Loading " << kDebugRamdiskProp;` from
`property_service.cpp`. **Nothing here can reject the property file**; Q2's
blocker must be in `load_properties_from_file()` / property-set semantics, not
in this call.

---

## 5. Why the flash route is not a userspace trick

If `/system/apex/com.google.android.adbd.apex` is replaced by a patched APEX
adbd binary and re-signed with *our* key + matching `apex_pubkey`:

1. apexd accepts it (self-referential key, §3.1) — but only after `/system` is
   readable, which requires the dm-verity root digest to match;
2. the hash tree is described by `vbmeta_system`, `Flags: 0`, so the whole
   `vbmeta_system` must be rebuilt (`avbtool add_hashtree_footer`) and signed
   with a key we control;
3. `vbmeta.img` chains `vbmeta_system` to OPLUS key `3c5f7b18…`; that signature
   cannot be reproduced. It is only tolerated because the device is unlocked
   and both LK (`ALLOW_VERIFICATION_ERRORS`, `img_auth_required=0`) and
   `fs_mgr` (`IsAvbPermissive()`) accept verification errors.

So the route exists, but it is a **raw flash of `system_a` + `vbmeta_system`**
(with re-generated verity trees), not an APEX push. It is also destructive to
the "stock, verifiable system" property of the phone.

---

## 6. Reproduction

```bash
# 1. pull only the one member (zip stays untouched)
python3 - <<'EOF'
import zipfile
src='/data/data/com.termux/files/home/RMX3630export_11_14.0.0.200EX01_2024090223460108.zip'
with zipfile.ZipFile(src) as z, z.open('IMAGES/system.img') as f, open('/tmp/fw/system.img','wb') as o:
    for b in iter(lambda: f.read(1<<22), b''): o.write(b)
EOF

# 2. unsparse + detect + extract
python3 docs/notes/sparse_unpack.py --info   /tmp/fw/system.img
python3 docs/notes/sparse_unpack.py --unpack /tmp/fw/system.img -o /tmp/fw/system.raw
fsck.erofs --extract=/tmp/fw/sysroot --overwrite /tmp/fw/system.raw
python3 docs/notes/erofs_lite.py --ls /system --image /tmp/fw/system.raw   # fallback view

# 3. hashes
sha256sum /tmp/fw/sysroot/system/{build.prop,bin/init} \
          /tmp/fw/sysroot/system/apex/com.google.android.adbd.apex \
          /tmp/fw/sysroot/system/etc/selinux/plat_property_contexts

# 4. APEX
unzip -o /tmp/fw/sysroot/system/apex/com.google.android.adbd.apex -d /tmp/fw/apex/adbd_apex
python3 /tmp/fw/avbtool.py info_image --image /tmp/fw/apex/adbd_apex/apex_payload.img
7z x -y -o/tmp/fw/apex /tmp/fw/apex/adbd_apex/apex_payload.img bin/adbd etc/init.rc

# 5. init sites
readelf -rW /tmp/fw/system_init | grep -i 2e0648
r2 -q -c 'e scr.color=0; s 0x156fe4; pd 20' /tmp/fw/system_init
r2 -q -c 'e scr.color=0; s 0x158c80; pd 26' /tmp/fw/system_init
```

## 7. Files added

| file | purpose |
|---|---|
| `docs/notes/sparse_unpack.py` | sparse `--info` / `--list` / `--unpack`, `--help` exit 0 |
| `docs/notes/erofs_lite.py` | pure-python EROFS `--info/--ls/--stat/--extract` fallback, `--help` exit 0 |
| `docs/notes/reverse/re-adbd-apex-route.md` | this report |

No tracked binary or other task's file was modified; nothing committed.
