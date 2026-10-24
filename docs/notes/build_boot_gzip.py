#!/usr/bin/env python3
"""Build a boot_a image that keeps the stock LAYOUT (vbmeta + AVB footer in place).

The stock `boot_a` is a v4 image with an **embedded vbmeta** at 0x1513000 and an
AVB footer in the last 64 bytes of the partition.  A ramdisk larger than the
original slot overwrites the vbmeta -> libavb sees garbage -> hard boot failure.
(That is what happened with the first LZ4 rewrite.)

This builder avoids that:
  * ramdisk is compressed with **gzip -9** (0x15acb6 B, well inside the
    0x194000-byte slot between the ramdisk start 0x137f000 and the vbmeta
    0x1513000);
  * everything from the vbmeta offset to the end of the partition is copied
    VERBATIM from the stock backup, so the vbmeta/footer structure stays valid;
  * only the ramdisk region changes -> AVB will report a hash mismatch (expected;
    the device is unlocked/orange, which should tolerate it).

Patch inside the ramdisk: ro.adb.secure=0, ro.debuggable=1,
persist.sys.usb.config=adb, plus /adb_keys with the host public key.
"""
import gzip
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from boot_ramdisk_patch import (  # noqa: E402
    parse_boot, lz4_legacy_decompress, cpio_parse, cpio_build, patch_prop,
)

PROPS = {'ro.adb.secure': '0', 'ro.debuggable': '1',
         'persist.sys.usb.config': 'adb'}


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else \
        '/home/musin/boot_a_backup_20261024_225408.img'
    out = sys.argv[2] if len(sys.argv) > 2 else '/home/musin/boot_patched.img'
    key = os.path.expanduser('~/.android/adbkey.pub')

    stock = open(src, 'rb').read()
    p = parse_boot(stock)
    vb_off = p['rd_off'] + ((p['ramdisk_size'] + 0xfff) & ~0xfff)
    # vbmeta usually starts right after the ramdisk, aligned to 0x1000
    while vb_off < len(stock) and stock[vb_off:vb_off + 4] not in (b'AVB0', b''):
        vb_off += 0x1000
    print(f"[*] stock: kernel={p['kernel_size']:#x} ramdisk={p['ramdisk_size']:#x} "
          f"rd_off={p['rd_off']:#x} vbmeta≈{vb_off:#x}")

    raw = lz4_legacy_decompress(p['ramdisk'])
    ents = cpio_parse(raw)
    changed = []
    for e in ents:
        if e['name'] in ('default.prop', 'prop.default',
                         'system/etc/ramdisk/build.prop'):
            e['data'] = patch_prop(e['data'].decode('utf-8', 'replace'), PROPS).encode()
            changed.append(e['name'])
    pub = open(key, 'rb').read().strip()
    ents.insert(len(ents) - 1, dict(name='adb_keys', mode=0o100644, uid=0, gid=0,
                                    nlink=1, mtime=0, devmajor=0, devminor=0,
                                    rdevmajor=0, rdevminor=0, data=pub + b'\n'))
    new_raw = cpio_build(ents)
    comp = gzip.compress(new_raw, 9, mtime=0)
    print(f"[*] patched props in {changed}; /adb_keys {len(pub)} B")
    print(f"[*] cpio {len(new_raw):#x} -> gzip {len(comp):#x}")

    slot = vb_off - p['rd_off']
    if len(comp) > slot:
        print(f"[-] gzip ramdisk does not fit the stock slot "
              f"({len(comp):#x} > {slot:#x})")
        return 1
    print(f"[+] fits the stock slot {slot:#x} (slack {slot - len(comp):#x})")

    img = bytearray(stock)                     # start from stock: vbmeta+footer kept
    hdr = bytearray(stock[:p['header_size']])
    struct.pack_into('<I', hdr, 0x0C, len(comp))
    img[0:len(hdr)] = hdr
    img[p['rd_off']:vb_off] = comp + bytes(slot - len(comp))
    open(out, 'wb').write(bytes(img))
    print(f"[+] wrote {out} ({len(img):#x} B)")

    # verify
    q = parse_boot(bytes(img))
    assert q['ramdisk_size'] == len(comp)
    raw2 = gzip.decompress(bytes(img[q['rd_off']:q['rd_off'] + len(comp)]))
    ents2 = cpio_parse(raw2)
    names = {e['name'] for e in ents2}
    print(f"[+] verify: ramdisk_size={q['ramdisk_size']:#x} entries={len(ents2)} "
          f"adb_keys={'adb_keys' in names}")
    assert bytes(img[vb_off:vb_off + 4]) == b'AVB0', 'vbmeta moved!'
    assert bytes(img[-64:-60]) == b'AVBf', 'AVB footer lost!'
    print("[+] vbmeta and AVB footer are byte-identical to stock")
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
