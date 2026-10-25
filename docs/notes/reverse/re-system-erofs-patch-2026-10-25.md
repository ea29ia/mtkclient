# RE: patching one byte in `/system/build.prop` on RMX3630 (MT6789) — EROFS in-place feasibility

Date: 2026-10-25. **Read-only / offline**: no phone, no DA, no flashing, nothing
written to the device. One note (this file) was created; large temporaries were
made under `/tmp/opencode` only.

Inputs:

| file | size | md5 |
|---|---|---|
| `/home/musin/system_a.erofs` | 888,131,584 B | `f66645e4e40702d60067b25dfba4e6b4e7` |
| `/tmp/opencode/sysa` (extracted, `--no-preserve`) | 1.4 GB tree | — |
| `/tmp/opencode/vb/frag0.cpio` (vendor_boot ramdisk) | 88,000,768 B | — |

Companions: `re-adbd-apex-route.md` §3.3 (vbmeta_system / dm-verity, stock export),
`campaign-status-rmx3630.md` §"ro.adb.secure".

**Campaign outcome (2026-10-25), which supersedes this note's premise:** the
`ro.adb.secure=1` wall was removed **without touching `/system`** — the
vendor_boot header cmdline `androidboot.selinux=permissive` (31 bytes) gives
`adb root` (uid 0, `u:r:su:s0`, v18/v19), and `vendor_boot_v22_magisk.img`
(md5 `a874a5c217d2e42aa7813a151bbd78be`) gives Magisk `su`. This EROFS patch was
prepared and verified offline but was **not** applied to the device.

---

## 0. Verdict (short)

| question | answer |
|---|---|
| flip the byte "raw" in the LZ4 stream (no re-compress)? | **NO** — the `'1'` is produced by an LZ4 **match** (back-reference), it has no byte of its own in the stream |
| rewrite the whole 4 KiB pcluster in place, metadata untouched? | **YES** — 3,954 B written at partition offset `0x13C6708E`; inode, size, index pack, `i_u`, mtime all unchanged. **Verified end-to-end** with `fsck.erofs` on a patched copy |
| does dm-verity tolerate it? | tree/descriptor are **real and enforced by construction** (`flags = 0`), but on this unlocked (orange) device verification is *permissive* → reads succeed (see §4.4) |
| rebuild from a tree | possible and reproducible (`mkfs.erofs` recipe §3, measured 878,391,296 B) but rebuild breaks **every** verity block; strictly worse than the in-place patch |

corrected: the permissive-verity conclusion is no longer pending — the device is
orange/unlocked, `/metadata/avb_enforce` is absent, and `/` is mounted from
dm-23 (`system-verity`) with `ignore_corruption`; the `getprop` pre-check is
now only a 10-second sanity check, not a blocker.

The in-place patch is the recommended route: it touches 4 KiB of one block,
invalidates exactly one verity leaf, and is fully revertible from the dump.

---

## 1. EROFS layout facts (decoded from `system_a.erofs`)

### 1.1 superblock (offset 1024, 128 B)

```
magic              0xE0F5E1E2      blkszbits 12  -> 4096 B blocks
feature_compat     0x3             = SB_CHKSUM | MTIME
feature_incompat   0x1             = ZERO_PADDING only
                                  (no COMPR_CFGS, no BIG_PCLUSTER, no FRAGMENTS,
                                   no CHUNKED_FILE, no DEDUPE, no ZTAILPACKING)
lz4_max_distance   65535           (field @+84; implies the legacy single-algorithm
                                   format: compressor == LZ4)
blocks             214459          -> fs = 214459*4096 = 878,424,064 B
ino count          3901            build_time 1740488008
meta_blkaddr 0   xattr_blkaddr 0   dirblkbits 0
uuid               7f7aaea8-4652-4378-b95d-a0e1d9155752
```

Partition is 216,830 blocks; the 2,370 blocks after the fs are the verity area
(§4). Tail of the partition: `AVBf` footer + unsigned `AVB0` vbmeta blob (§4.1).

### 1.2 `/system/build.prop`

`dump.erofs --path=/system/build.prop`:

```
NID 10359109  Layout: 3 ("compressed-compact")  Inode size 32  Xattr size 16
Size 8168  On-disk 4096  Access 0600  Uid 0 Gid 0  mtime 2025-02-25 17:53:28
Ext 0..8168 (8168) -> physical 331,771,904..331,776,000 (4096)
```

Hand-decoded inode (absolute file offset `0x13C228A0` = block 80930 + 2208):

```
i_format   0x0006 -> ver 0 (32 B inode), datalayout 3 (COMPACT), xattr_icount 2
i_mode     0x8180 (0100600)   i_nlink 1   i_size 0x1FE8 = 8168   i_reserved 0
i_u        1  (compressed blocks)    i_ino 556    i_uid/i_gid 0
xattr body 16 B at 0x13C228C0 -> data_off 0x13C228D0
```

### 1.3 where the compressed data really is (this is the trap)

For `datalayout == 3` (COMPACT) the bytes at `data_off` are **not** the data —
they are the 8-byte `z_erofs_map_header` + the compacted lcluster index pack:

```
0x13C228D0  map header : h_advise=0x0001 (Z_EROFS_ADVISE_COMPACTED_2B),
                         h_algorithmtype=0x00 -> HEAD1 = LZ4,
                         h_clusterbits=0x00 -> logical cluster = 4096,
                         h_idata_size/fragmentoff = 0
0x13C228D8  index pack : 00 10 e8 0f 66 3c 01 00
            lcn0: type=HEAD1, clusterofs=0, pblk = 0x13C66 + 1 = 0x13C67 = 80999
```

So the single pcluster is **block 80999** = `331,771,904 .. 331,776,000`
(no big-pcluster: `plen = 4096`, `m_llength = 8168`).

With `ZERO_PADDING` the compressed stream is **right-aligned inside the pcluster**
(the decoder, `z_erofs_fixup_insize()`, skips the leading zero run and takes the
input up to the end of the pcluster):

```
331,771,904 .. 331,772,053   149 x 0x00   (padding)
331,772,053 .. 331,776,000   3,947 B     LZ4 stream -> 8,168 B plaintext
```

Cross-checked on other files: `/system/bin/sh` last pcluster has 513 leading
zeros; `/system/etc/hosts` is layout 2 (flat-inline) and unaffected.

---

## 2. Q1 — can we just flip the byte?

### 2.1 why not (exact reason)

The target is file offset **4188** (0-based), line 121, column 15:
`ro.adb.secure=` is 14 chars, the `'1'` is at `4174+14`.

Parsing the stream into LZ4 ops and tracking provenance of every output byte:

```
output 4188 ('1')  <- match(off=39, len=10) starting at output 4180
                      source byte = output 4149 ('1' of `ro.adb.secure=1` earlier
                      in a repeated "debuggable" block)
```

There is **no literal byte in the stream holding that `'1'`** — the decoder copies
it from 39 bytes back. Therefore a 1-byte on-disk flip is impossible: the only
byte that carries `'1'` is used 39 bytes earlier for a *different* property line.
(And a "fix the source byte too" flip would corrupt that other line.)

Also structural: the stream is 3,947 B inside a 4,096 B pcluster. There is no
per-lcluster index pointing at individual bytes; the only metadata is the 4-byte
pblk + 2-bit type/offset packing in the index pack at `0x13C228D8`, which does
**not** change.

### 2.2 what *is* possible — full pcluster rewrite (yes)

Because `ZERO_PADDING` right-aligns the stream and there are **149 bytes of free
zero padding** at the front of the pcluster, a new stream of length ≤ 4096 B can
be dropped in with **zero metadata change** (`i_size`, `i_u`, index pack, inode
mtime, sb checksum all untouched; only the sb checksum covers the superblock, and
no per-inode checksum exists).

Constructed edit (byte-level splice of the original stream, no re-compression):

```
original : ... lit(3 @4177) [tok:ll=3,ml=6] + off(39)  ;  lit(0 @4190) [tok:ll=0,ml=0] + off(16) ...
patched  : ... lit(13 @4177: "ro.adb.secure=0\n")  [tok: ll=13, ml=0] + off(16) ...
bytes    : stream[2210..2216) replaced, stream[2216..2219) dropped, +7 B total
```

* no later op references output 4188 as a source (verified exhaustively), so the
  change cannot propagate;
* new stream: **3,954 B** (3,947 + 7), first byte `0x1f` (non-zero, required by
  the 0-padding skip);
* decompresses to 8,168 B that differs from the original file in exactly one
  byte (offset 4188: `0x31` -> `0x30`).

### 2.3 verification (done offline, real files)

```
cp system_a.erofs /tmp/opencode/sysa_patched.erofs
write 3954 B at 331,772,046
fsck.erofs --extract=... sysa_patched.erofs     -> clean, 4.9 s
cmp -l  sysa/system/build.prop  pv/system/build.prop
        4189  61  60            (1-based byte 4189: '1' -> '0')
sed -n 121p pv/system/build.prop -> ro.adb.secure=0
md5 (patched build.prop) e066140ff69b7fabdb4ba5ab358086fc
```

`fsck.erofs` uses the same EROFS/LZ4 decode path as the kernel (including the
leading-zero skip), so the layout assumption is confirmed, not assumed.

### 2.4 patch recipe (exact bytes)

```
READ   (for the diff/record): partition "system_a", bytes 331,771,904..331,776,000 (4096)
WRITE  : partition "system_a", bytes 331,772,046..331,776,000 (3,954 bytes)
         (= LBA 647,992 .. 647,999; the first 142 bytes of LBA 647,992 stay 0x00)
ENSURE : bytes 331,771,904..331,772,046 are 0x00 (they already are)
```

Nothing else in the partition changes. New stream = second column of the diff;
it is reproducible with the 30-line splice in §7 (script embedded at the end).
Integrity of the payload: `3954 B, md5 a4416fb25ddc5bbdcbcc702da3d3b286`.

If the writer is 512-B-sector based, the minimum *transfer* is the whole
4096-byte block 331,771,904..331,776,000 (read-modify-write), because the first
142 bytes are implicit padding.

---

## 3. Q2 — rebuild with `mkfs.erofs`

### 3.1 parameters inferred from the image

```
block size 4096, pcluster 4096 (no BIG_PCLUSTER), lz4hc level 9,
ZERO_PADDING on (default in erofs-utils 1.7), COMPACTED_2B indexes,
COMPACT 32-byte inodes, no fragments/dedupe/chunking.
=> the exact command that reproduces the superblock feature set and inode count:
```

### 3.2 recipe (no root needed: `fakeroot` + `--file-contexts`)

```bash
cd /tmp/opencode
fakeroot -- bash -c '
  # 1. metadata-faithful extract: uid/gid/mode/mtime are *faked* by fakeroot,
  #    so this works without root and without newuidmap
  fsck.erofs --extract=tree --preserve /home/musin/system_a.erofs

  # 2. edit
  sed -i "s/^ro.adb.secure=1$/ro.adb.secure=0/" tree/system/build.prop

  # 3. rebuild (paths inside the image are /system/... -> mount point is "/")
  mkfs.erofs -zlz4hc,9 -b4096 -C4096 \
      -T 1740488008 \
      -U 7f7aaea8-4652-4378-b95d-a0e1d9155752 \
      --mount-point=/ \
      --file-contexts=tree/system/etc/selinux/plat_file_contexts \
      -x2 \
      new_system.erofs tree
'
truncate -s 878424064 new_system.erofs     # must not exceed the verity data size
```

Measured on this dump (same tree, unpatched file):

```
Filesystem total blocks: 214451 (of 4096-byte blocks)   = 878,391,296 B
Filesystem total inodes: 3901 (identical to the original)
features: sb_csum mtime 0padding  (identical)
/system/build.prop: Layout 3, 8168 B, one pcluster of 4096 (50.15%)  (identical shape)
```

So the expected size is **878,391,296 B** (32,768 B smaller than the original
878,424,064 B); the 24 KB of extra selinux xattrs from `--file-contexts` keeps it
well under budget.

### 3.3 size budget and what must not grow

* hard ceiling for a dm-verity-compatible image: **878,424,064 B**
  (`image_size` in the hashtree descriptor, §4.1) — pad with `truncate`;
* hard ceiling for the partition: 888,131,584 B (tree + footer + vbmeta live
  after the fs, they are *not* part of the rebuilt image);
* ownership: derived from the EROFS inodes via `fsck.erofs --preserve` under
  `fakeroot` (verified: `/system/bin/sh` -> `0:2000 0755`,
  `/system/build.prop` -> `0:0 0600`, `/system/etc/hosts` -> `0:0 0644`);
* SELinux: from the image's own `plat_file_contexts` (`--file-contexts`), because
  `security.selinux` xattrs cannot be written unprivileged (no CAP_SYS_ADMIN in
  a userns, no SELinux on the host). That reproduces the *rules*, not the stored
  values — for a few paths where the stored label was set by a later fixup the
  rule may differ. Non-selinux xattrs (e.g. `security.capability`) are **lost**
  by this route; check with `getfattr -d -m - -R tree | head` before trusting it.
  A root build (or a tar with `SCHILY.xattr.*` produced from the EROFS xattr
  records) is the only exact route for those.

Caveat: a rebuild changes *every* block → every verity leaf mismatch. It is only
viable under the same permissive condition as the patch (§4.4), and it cannot be
verified incrementally.

---

## 4. Q3 — verity: is the modified system rejected?

### 4.1 `vbmeta_system` is in `super` — but its authoritative descriptor is also inside `system_a`

`vbmeta_system`/`vbmeta_vendor` are LP partitions inside `super`; there is **no
local `super` dump** in this workspace, so LP metadata could not be parsed here
(`/home/musin/mtkclient/docs/notes/super_extract.py` does the LP parse when a
device or super image is available: geometry @4096, header @12288, partition
table entry -> extent list -> `target_data` sector of `super`).

However `avbtool add_hashtree_footer` appends an **unsigned copy of the
descriptor block** to the image, and it is present in our dump:

```
abs 885,350,400  "AVB0" vbmeta, avbtool 1.2.0, algorithm NONE (unsigned),
                 auth block 0, aux block 448, header flags 0x00000000,
                 rollback_index 0, rollback_index_location 0
   Hashtree descriptor (partition "system"):
     dm-verity version 1
     Image Size   878,424,064
     Tree Offset  878,424,064      Tree Size 6,926,336 (1691 blocks)
     Data block   4096             Hash block 4096     FEC: none
     Hash algo    sha256
     Salt         af3f5efe5d390aa779eeb76564ca07eb
     Root Digest  a0574fc18e00471d1e832cfe52180bd5722436710c40e9cac56d712cf10f28ab
     Flags        0
footer: "AVBf" in the last 64 B of the partition
```

`make_vbmeta_image --include_descriptors_from_image system.img` copies exactly
these descriptor bytes into the signed `vbmeta_system`, so the numbers above are
the ones the device enforces. (Note: `re-adbd-apex-route.md` §3.3 quotes *other*
salt/digest values — that was the stock export `14.0.0.200EX01`
(image 877,805,568 B); the device's current build is the one in this dump.)

### 4.2 the tree is real — verified cryptographically

Recomputing the tree from the dump with that salt reproduces the descriptor:

```
layout on disk:  root block @ tree+0, L1 (14 blocks) @ tree+4096,
                 L0 (1676 blocks) @ tree+15*4096, tree = 1691 blocks
L0 == sha256(salt||data_block)       -> matches byte-for-byte for all 1676 blocks
L1 == sha256(salt||L0_block)         -> 14/14 blocks match
root == sha256(salt||root_block)     -> a0574fc1... == descriptor digest  ✓
```

`image_size` 878,424,064 = 214,459 blocks × 4096 exactly = end of the EROFS fs.

### 4.3 what our 4 KiB write does to the tree

The patched block is data block 80999 -> L0 block 632, digest index 103:

```
stale leaf digest at  abs 881,077,472   (tree+15*4096+632*4096+103*32), 32 B
old leaf  adc55419...      new leaf 5bae20f0...
old root  a0574fc1...      new root 0e27a1081a6b116d36731a510c28e6a7423742ccd02a9a31fa69b20d97f6f62d
```

So the mismatch is unavoidable, and the root cannot be re-signed (OPLUS key;
`vbmeta.img` `SHA256_RSA2048`, chain key sha1 `3c5f7b18…`). Patching the stale
leaf/L1/root in the image would only move the mismatch to the signed root.

### 4.4 verdict: rejected or ignored?

The **hashtree_error_mode is not stored in vbmeta** — the bootloader/`fs_mgr`
chooses it, and `vbmeta_system` header `flags = 0` means *verity is enabled*
(neither `HASHTREE_DISABLED (1<<0)` nor `VERIFICATION_DISABLED (1<<1)`), so
dm-verity **is** set up and our block **will** hash-fail. Behaviour on failure:

| device state | `fs_mgr` | dm-verity table | result for our block |
|---|---|---|---|
| locked / green | `AVB_SLOT_VERIFY_FLAGS_NONE` | `restart_on_error`/eio | **I/O error** on read of `build.prop`; profile silently keeps the *default* `ro.adb.secure=1` (=> patch ineffective, boot usually still completes) |
| unlocked / orange | `ALLOW_VERIFICATION_ERROR`, `IsAvbPermissive()==true` | `ignore_corruption`/logging | hash error logged, **data returned** => `ro.adb.secure=0` takes effect |
| `vbmeta_system` built with `--flags 1` | — | verity not mounted | patch always works |

Evidence for orange on this unit: `seccfg lock_state=3`, RPMB boot-info mirror
`locked=0/isunlocked=1`, and LK's own `[AVB] img_auth_required = 0, avb_ret = 0`
for `boot`. `fs_mgr` also requires `/metadata/avb_enforce` to be absent for
permissiveness (`fs_avb.cpp` `IsAvbPermissive()`); `metadata` was wiped, so it is
absent — but note the *next* wipe/OTA may recreate it.

**Do this one-line check before writing** (it needs a working adb shell, which is
available on the current images: adb is authorised under v14/v18/v19/v22, and
`adb shell su -c ...` works on the Magisk image):

```
getprop ro.boot.veritymode        # "eio" = strict, "logging"/"ignore" = tolerant
getprop ro.boot.verifiedbootstate # "orange" expected
```

If it prints `eio`, do not write (or accept "no effect, only log noise").

---

## 5. Q4 — write plan, risk, rollback

### 5.1 exact write

| item | value |
|---|---|
| partition | **`system_a`** (logical partition inside `super`; fstab: `system /system ext4 ro ... logical,avb=vbmeta_system`) |
| offset in `system_a` | `0x13C6708E` = **331,772,046** (LBA 647,992 + 142) |
| length | **3,954** B, ends at 331,776,000 (block boundary, LBA 648,000) |
| block touched | 1 block: LBA 647,992..647,999 (pcluster of `/system/build.prop`) |
| offset in `super` | `system_a_extent_start_bytes + 331,772,046` — **requires LP metadata**; not derivable offline (no super dump). `super_extract.py` prints the extent list; for a linear extent `abs = target_data*512 + 331,772,046` |
| metadata churn | none (inode, index pack, `i_size`, mtime, sb checksum all untouched) |
| bytes to preserve | 331,771,904..331,772,046 must stay 0x00 |

### 5.2 rollback

* **minimal**: write back the original 3,954 B `[331,771,904+142 .. 331,776,000)`
  (or the whole 4,096-B block) from `/home/musin/system_a.erofs` (md5
  `f66645e4…`). No other state is involved, so a byte-exact restore is trivial
  and does not require a full re-flash.
* **full**: `fastboot flash system_a system_a.erofs` in fastbootd (the
  documented path; `fastboot reboot fastboot`, device `18d1:4ee0`), or a raw
  `super` restore of `system_a` from the same dump. corrected: an earlier draft
  wrote `fastboot flash system` — on this device the LP name is `system_a`.
* the verity tree is *not* modified, so after rollback the leaf digest matches
  again and verity is bit-exact equal to stock (nothing to regenerate).

### 5.3 risk table

| risk | likelihood | impact | mitigation |
|---|---|---|---|
| dm-verity in `eio` mode ⇒ `build.prop` unreadable | medium (needs `ro.boot.veritymode` check) | patch silently ineffective (defaults `ro.adb.secure=1`); possible boot loop if init treats the read failure as fatal | check `ro.boot.veritymode` first; keep 5.2 handy |
| bad splice / bad 0-padding alignment ⇒ decoder error on that pcluster | low (already verified with `fsck.erofs` on a real copy) | same as above, only for `build.prop` | re-verify the produced stream with the §7 script before writing; compare decompressed bytes |
| writing the wrong absolute offset (logical vs physical) | medium if written raw to `super` | corruption of an unrelated block of another logical partition | write through `fastboot flash system` / fastbootd, or resolve the LP extent first |
| 512-B-sector writer rounds down | low | would zero the 142 B of padding (harmless) or, if it rounds *up*, no effect | do a 4,096-B read-modify-write |
| `metadata/avb_enforce` reappears after wipe/OTA | medium | strict verity at next boot → patch ineffective | re-check after OTA; do not OTA while patched |
| SELinux: rebuild path loses non-selinux xattrs | only for §3 route | subtleperms breakage (e.g. capabilities) | prefer the in-place patch |
| OTA refuses to apply (system hash mismatch) | high | manual re-flash needed | expected; keep the dump |

Biggest risk: **the device turns out to be in `eio` verity mode**, in which case
the write is wasted (and possibly a boot-loop on some init versions). The 4 KiB
write itself is safe — it changes exactly one pcluster and is revertible with
3,954 bytes from the dump.

---

## 6. Open items

1. `getprop ro.boot.veritymode` / `ro.boot.verifiedbootstate` — corrected:
   adb now works (v18/v19/v22 images boot with an authorised shell; `su` on
   Magisk), so this is a trivial check rather than a blocked one. Expected:
   `verifiedbootstate=orange`, `veritymode` tolerant (`logging`/`ignore`).
2. LP metadata for `super` (or a `super` dump) to convert `331,772,046` into an
   absolute `super` byte offset, and to read the *signed* `vbmeta_system`
   header flags directly (expected `0`, cf. stock export).
3. Optional hardening: after the patch one could also rewrite the stale digest
   slots — 32 B at `881,077,472` (L0 leaf), 32 B at `878,448,384` (L1) and the
   root block at `878,424,064` — **pointless**: the anchor is the signed root
   digest `a0574fc1…`, which cannot be re-signed.

---

## 7. Reproducer (patch stream, run offline)

```python
# in:  system_a.erofs (or the 4096-B block), out: 3954-B stream + verification
PCL, TGT = 80999*4096, 4188
blk = open('system_a.erofs','rb').read()[PCL:PCL+4096]
s = 0
while blk[s] == 0: s += 1
src = blk[s:]                       # 3947 B, right-aligned LZ4 stream
ref = open('/tmp/opencode/sysa/system/build.prop','rb').read()

# parse (token offsets + provenance)
tok, out, i = {}, bytearray(), 0
while i < len(src):
    tp = i; t = src[i]; i += 1
    ll = t >> 4
    if ll == 15:
        while True:
            x = src[i]; i += 1; ll += x
            if x != 255: break
    tok[len(out)] = tp; out += src[i:i+ll]; i += ll
    if i >= len(src): break
    off = src[i] | src[i+1] << 8; i += 2
    ml = t & 15
    if ml == 15:
        while True:
            x = src[i]; i += 1; ml += x
            if x != 255: break
    ml += 4
    st = len(out) - off
    for k in range(ml): out.append(out[st+k])
assert bytes(out) == ref and src[tok[4177]] >> 4 == 3

A = tok[4177]                                       # pair lit(3)+match(10)
C = tok[4194]                                       # next pair
mid = bytes([13 << 4]) + ref[4177:4188] + b'0' + ref[4189:4190] + bytes([16, 0])
new = src[:A] + mid + src[C:]                       # 3954 B

# decompress check: exactly one byte differs (4188 '1'->'0')
d = bytearray(); i = 0
while i < len(new):
    t = new[i]; i += 1; ll = t >> 4
    if ll == 15:
        while True:
            x = new[i]; i += 1; ll += x
            if x != 255: break
    d += new[i:i+ll]; i += ll
    if i >= len(new): break
    off = new[i] | new[i+1] << 8; i += 2
    ml = t & 15
    if ml == 15:
        while True:
            x = new[i]; i += 1; ml += x
            if x != 255: break
    ml += 4; st = len(d) - off
    for k in range(ml): d.append(d[st+k])
assert len(d) == 8168 and d[4188] == 0x30
assert [k for k in range(len(ref)) if d[k] != ref[k]] == [4188]
assert len(new) <= 4096 and new[0] != 0
open('newstream.bin','wb').write(new)   # write at PCL + 4096 - len(new)
```
