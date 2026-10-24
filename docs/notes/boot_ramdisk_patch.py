#!/usr/bin/env python3
"""Boot-image (v3/v4) ramdisk patcher for RMX3630 — enables ADB without a screen.

Pipeline: parse ANDROID! v4 header -> slice kernel/ramdisk -> LZ4-legacy
decompress -> newc cpio unpack -> patch -> repack -> LZ4-legacy compress ->
rebuild the image (header copied, sizes updated).

Patch applied by default:
  * default.prop / prop.default: force `ro.adb.secure=0` (adbd accepts any host)
  * add `/adb_keys` with the host public key (belt and braces)

Usage:
  ./boot_ramdisk_patch.py --in docs/notes/rmx3630-lk/boot.img \
      --out /home/musin/boot_patched.img [--list] [--key ~/.android/adbkey.pub]
"""
import argparse
import os
import struct
import sys

PAGE = 0x1000
LZ4_LEGACY_MAGIC = 0x184C2102
MAX_BLOCK = 0x400000          # 4 MiB per legacy block (safe)


# ---------------- LZ4 legacy ----------------
def lz4_legacy_decompress(data: bytes) -> bytes:
    out = bytearray()
    pos = 0
    if struct.unpack_from('<I', data, 0)[0] != LZ4_LEGACY_MAGIC:
        raise ValueError('not an LZ4 legacy frame')
    pos = 4
    while pos + 4 <= len(data):
        size = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if size == 0 or size > 0x800000 or pos + size > len(data):
            break
        blk = data[pos:pos + size]
        pos += size
        i = 0
        while i < len(blk):
            token = blk[i]
            i += 1
            litlen = token >> 4
            if litlen == 15:
                while True:
                    b = blk[i]
                    i += 1
                    litlen += b
                    if b != 255:
                        break
            out.extend(blk[i:i + litlen])
            i += litlen
            if i >= len(blk):
                break
            offset = blk[i] | (blk[i + 1] << 8)
            i += 2
            if offset == 0 or offset > len(out):
                raise ValueError(f'bad LZ4 offset {offset} at {i}')
            matchlen = token & 0xF
            if matchlen == 15:
                while True:
                    b = blk[i]
                    i += 1
                    matchlen += b
                    if b != 255:
                        break
            matchlen += 4
            start = len(out) - offset
            for k in range(matchlen):
                out.append(out[start + k])
    return bytes(out)


def lz4_legacy_compress(data: bytes) -> bytes:
    """Literals-only LZ4 legacy frame (valid, ~0.4% overhead)."""
    out = bytearray(struct.pack('<I', LZ4_LEGACY_MAGIC))
    for off in range(0, len(data), MAX_BLOCK):
        chunk = data[off:off + MAX_BLOCK]
        n = len(chunk)
        seq = bytearray()
        if n < 15:
            seq.append(n << 4)
        else:
            seq.append(0xF0)
            rem = n - 15
            while rem >= 255:
                seq.append(255)
                rem -= 255
            seq.append(rem)
        seq.extend(chunk)
        out.extend(struct.pack('<I', len(seq)))
        out.extend(seq)
    return bytes(out)


# ---------------- newc cpio ----------------
def cpio_parse(blob: bytes):
    entries = []
    pos = 0
    while True:
        if pos + 110 > len(blob):
            break
        if blob[pos:pos + 6] != b'070701':
            break
        f = [int(blob[pos + 6 + i * 8: pos + 14 + i * 8], 16) for i in range(13)]
        (ino, mode, uid, gid, nlink, mtime, filesize,
         devmajor, devminor, rdevmajor, rdevminor, namesize, check) = f
        name_off = pos + 110
        name = blob[name_off:name_off + namesize - 1].decode('utf-8', 'replace')
        data_off = (name_off + namesize + 3) & ~3
        data = blob[data_off:data_off + filesize]
        pos = (data_off + filesize + 3) & ~3
        entries.append(dict(name=name, mode=mode, uid=uid, gid=gid, nlink=nlink,
                            mtime=mtime, devmajor=devmajor, devminor=devminor,
                            rdevmajor=rdevmajor, rdevminor=rdevminor, data=data))
        if name == 'TRAILER!!!':
            break
    return entries


def cpio_build(entries) -> bytes:
    out = bytearray()
    ino = 300000
    for e in entries:
        name = e['name'].encode() + b'\x00'
        data = e['data']
        if e['name'] == 'TRAILER!!!':
            name = b'TRAILER!!!\x00'
            data = b''
        hdr = b'070701' + b''.join(
            f'{v:08x}'.encode() for v in (
                ino, e['mode'], e['uid'], e['gid'], e['nlink'], e['mtime'],
                len(data), e['devmajor'], e['devminor'], e['rdevmajor'],
                e['rdevminor'], len(name), 0))
        out.extend(hdr)
        out.extend(name)
        out.extend(b'\x00' * ((-len(out)) & 3))
        out.extend(data)
        out.extend(b'\x00' * ((-len(out)) & 3))
        ino += 1
    return bytes(out)


# ---------------- boot image ----------------
def parse_boot(d: bytes):
    if d[:8] != b'ANDROID!':
        raise ValueError('not an ANDROID! boot image')
    hv = struct.unpack_from('<I', d, 0x28)[0]
    if hv < 3:
        raise ValueError(f'unsupported header version {hv}')
    kernel_size = struct.unpack_from('<I', d, 0x08)[0]
    ramdisk_size = struct.unpack_from('<I', d, 0x0C)[0]
    os_version = struct.unpack_from('<I', d, 0x10)[0]
    header_size = struct.unpack_from('<I', d, 0x14)[0]
    kernel = d[PAGE:PAGE + kernel_size]
    rd_off = PAGE + ((kernel_size + PAGE - 1) // PAGE) * PAGE
    ramdisk = d[rd_off:rd_off + ramdisk_size]
    return dict(hv=hv, kernel_size=kernel_size, ramdisk_size=ramdisk_size,
                os_version=os_version, header_size=header_size,
                header=d[:header_size], kernel=kernel, ramdisk=ramdisk,
                rd_off=rd_off)


def build_boot(p, new_ramdisk_comp: bytes) -> bytes:
    hdr = bytearray(p['header'])
    struct.pack_into('<I', hdr, 0x0C, len(new_ramdisk_comp))
    out = bytearray(hdr)
    out.extend(b'\x00' * ((-len(out)) & (PAGE - 1)))
    out.extend(p['kernel'])
    out.extend(b'\x00' * ((-len(out)) & (PAGE - 1)))
    out.extend(new_ramdisk_comp)
    out.extend(b'\x00' * ((-len(out)) & (PAGE - 1)))
    return bytes(out)


def patch_prop(text: str, kv: dict) -> str:
    """Replace or append the given key=value pairs."""
    keys = tuple(kv)
    lines = [ln for ln in text.splitlines()
             if not ln.strip().startswith(tuple(k + '=' for k in keys))]
    for k, v in kv.items():
        lines.append(f'{k}={v}')
    return '\n'.join(lines) + '\n'


PROPS = {
    'ro.adb.secure': '0',        # adbd accepts any host key (no screen to tap)
    'ro.debuggable': '1',        # adbd runs as root; `adb root` works
    'persist.sys.usb.config': 'adb',   # first boot: USB = adb (no /data yet)
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', required=True)
    ap.add_argument('--out', dest='out', required=True)
    ap.add_argument('--key', dest='key', default=os.path.expanduser('~/.android/adbkey.pub'))
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--no-secure-patch', action='store_true')
    args = ap.parse_args()

    d = open(args.inp, 'rb').read()
    p = parse_boot(d)
    print(f"[*] header v{p['hv']} header_size={p['header_size']:#x} "
          f"kernel={p['kernel_size']:#x} ramdisk={p['ramdisk_size']:#x} at {p['rd_off']:#x}")

    raw = lz4_legacy_decompress(p['ramdisk'])
    print(f"[+] ramdisk decompressed: {len(raw):#x} B")

    entries = cpio_parse(raw)
    print(f"[+] cpio entries: {len(entries)}")
    if args.list:
        for e in entries:
            print(f"    {e['mode']:07o} {e['name']}{'/' if e['mode'] & 0o170000 == 0o040000 else ''}")

    # patch properties
    changed = []
    if not args.no_secure_patch:
        targets = ('default.prop', 'prop.default',
                   'system/etc/ramdisk/build.prop')
        for e in entries:
            if e['name'] in targets:
                txt = e['data'].decode('utf-8', 'replace')
                e['data'] = patch_prop(txt, PROPS).encode()
                changed.append(e['name'])
                print(f"[+] patched {e['name']}: " +
                      ", ".join(f"{k}={v}" for k, v in PROPS.items()))
        if not changed:
            print("[!] no property file found in the ramdisk")

    # add /adb_keys
    try:
        pub = open(args.key, 'rb').read().strip()
    except OSError:
        pub = b''
    if pub:
        names = {e['name'] for e in entries}
        if 'adb_keys' in names:
            for e in entries:
                if e['name'] == 'adb_keys':
                    e['data'] = pub + b'\n'
        else:
            entries.insert(len(entries) - 1, dict(
                name='adb_keys', mode=0o100644, uid=0, gid=0, nlink=1,
                mtime=0, devmajor=0, devminor=0, rdevmajor=0, rdevminor=0,
                data=pub + b'\n'))
        print(f"[+] /adb_keys set ({len(pub)} B)")

    new_raw = cpio_build(entries)
    print(f"[*] new cpio: {len(new_raw):#x} B (was {len(raw):#x})")
    comp = lz4_legacy_compress(new_raw)
    print(f"[*] LZ4 recompressed: {len(comp):#x} B (was {len(p['ramdisk']):#x})")
    # sanity: round-trip
    if lz4_legacy_decompress(comp) != new_raw:
        print("[-] LZ4 round-trip FAILED")
        return 1
    img = build_boot(p, comp)
    open(args.out, 'wb').write(img)
    print(f"[+] wrote {args.out} ({len(img):#x} B)")
    # verify the produced image parses and the ramdisk round-trips
    q = parse_boot(open(args.out, 'rb').read() + bytes(PAGE))
    raw2 = lz4_legacy_decompress(q['ramdisk'])
    print(f"[+] verify: ramdisk {len(raw2):#x} B, cpio entries "
          f"{len(cpio_parse(raw2))}, adb.secure patched={bool(changed)}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
