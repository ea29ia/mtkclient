#!/usr/bin/env python3
"""Full offline RSASSA-PSS verification of RMX3630 DA1/DA2 trailers.

Key result (2026-10-26): the in-file per-build 256-byte blocks in the OPLUS
preloaders ARE the live DAA verify moduli.

  S   = preloader 200EX01 @ file 0x5D2DC (== 2710 @ 0x5D3DC), sha256 97e49b50...
  K27 = preloader 2710EX01 @ file 0x5D4DC (head af102e73...), absent from 200EX01

Verified (PSS-SHA256, salt 32 B, MGF1-SHA256, separator DB[0xBE]==0x01,
H' = SHA256(0^8 || SHA256(msg) || salt) == EM[223:255]):

  200EX01 DA_BR  DA1 x S   -> VERIFIED      2710EX01 DA_BR  DA1 x K27 -> VERIFIED
  200EX01 DA_BR  DA2 x S   -> VERIFIED      2710EX01 DA_BR  DA2 x K27 -> VERIFIED
  C.25 (2023-03-14) DA1 x S -> VERIFIED      C.25 DA2 x S              -> VERIFIED

  crosses (200 x K27, 2710 x S, C.25 x K27, doogee/oukitel/infinix3 x S/K27):
  no-BC / struct-fail  (different per-build keys; their preloaders not in corpus)

Deviation from strict RSASSA-PSS: DB[0] = 0x80 (top bit NOT cleared, i.e. the
emBits=2048 variant); everything else matches. Alexander's verifier spec
(docs/DA_TIMELINE.md in alexander-dev2313123/realme10-rmx3630-research):
"EM[0xFF]==0xBC, MGF1-SHA256 unmask, DB[0xBE]==0x01, full 32-byte compare" --
reproduced exactly. His runtime-SRAM model (modulus staged at 0x2F9F38) is
therefore confirmed with the in-file block as the staged source.
"""
import hashlib, struct, sys

def mgf1(seed: bytes, ln: int) -> bytes:
    out = b''; c = 0
    while len(out) < ln:
        out += hashlib.sha256(seed + c.to_bytes(4, 'big')).digest(); c += 1
    return out[:ln]

def pss_verify(N_b: bytes, sig: bytes, msg: bytes):
    N = int.from_bytes(N_b, 'big')
    em = pow(int.from_bytes(sig, 'big'), 65537, N).to_bytes(256, 'big')
    if em[-1] != 0xBC:
        return 'no-BC'
    db = bytes(a ^ b for a, b in zip(em[:223], mgf1(em[223:-1], 223)))
    if db[0xBE] != 1:
        return 'struct-fail'
    h2 = hashlib.sha256(b'\x00' * 8 + hashlib.sha256(msg).digest() + db[0xBF:0xDF]).digest()
    return 'VERIFIED' if h2 == em[223:-1] else 'digest-fail'

def da1_region(C: bytes):
    buf, l, addr, soff, sl = struct.unpack('<IIIII', C[0x80:0x94])
    return buf, soff

if __name__ == '__main__':
    A = open('fw2710/preloader_k6789v1_64.bin', 'rb').read()
    D = open('da/pl.bin', 'rb').read()
    S = D[0x5D2DC:0x5D2DC + 0x100]
    K27 = A[0x5D4DC:0x5D4DC + 0x100]
    for label, path, N_b, da2 in (
            ('200 DA1 x S',   'notes/DA_BR.bin',      S,   (0x68AB8, 0xBF980)),
            ('200 DA2 x S',   'notes/DA_BR.bin',      S,   (0x68AB8, 0xBF980)),
            ('2710 DA1 x K27','fw2710/DA_BR.bin',     K27, None),
            ('C.25 DA1 x S',  'said/mt6789_realme.bin', S, None),
    ):
        C = open(path, 'rb').read()
        if 'DA1' in label:
            buf, soff = da1_region(C)
        else:
            buf, soff = da2
        print(f"{label}: {pss_verify(N_b, C[soff:soff+0x100], C[buf:soff])}")
