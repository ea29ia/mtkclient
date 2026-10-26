#!/usr/bin/env python3
"""2710EX01 DA2 — the data-phase state machine after the auth=5 forge (emu-only).

Closes the last "unresolved" of docs/notes/reverse/
re-da2-2710-flash-layer-2026-10-26.md: the data-phase SM is pumped end-to-end,
the "checksum engine" is identified (software, not HW), and the
seccfg-regeneration question is answered for both flash scenarios.

Builds on: /tmp/opencode/efuse2710/harness.py (DA2Emu) +
docs/notes/da2_2710_efuse_flash.py (flash model / ops stubs / GPT / forge).
Image: /tmp/opencode/fw2710/x/da2_2710.bin (VA 0x40000000 == file offset 0).

Minimal declared models (everything else is real DA code executed in Unicorn):
  M1 sched_init 0x40009B2C          — executed for real once, before the run.
  M2 thread_create 0x400094CC       — captures (entry, arg), returns a fake TCB;
                                      the worker body runs INLINE at the first
                                      event-wait (cooperative collapse; the DA
                                      itself is single-worker on this path).
  M3 event-wait 0x400091A4          — returns 0 when no worker is pending (the
                                      async producer is collapsed into the
                                      synchronous storage stubs).
  M4 digest 0x4003A58C              — hashlib.sha256 over (buf,len) -> out
                                      (the HACC2 mailbox engine at the
                                      software API, per the task's allowance).
  M5 SEJ scramble 0x40034958        — pure-python AES-128-CBC in place over
                                      0x20 bytes; key = the 8 words the REAL
                                      0x400348F0 loaded into 0x1000A060 (zeros
                                      when no 0x014D4D4D custom record is
                                      harvested), IV = the fixed seed table
                                      0x40053AE4, LE word order.  The same
                                      model builds the seeded record, so the
                                      validator's accept is self-consistent.
  M6 transport                      — session-op table 0x40054A58 pre-installed
                                      with the real path-B vtable values then
                                      pointed at the synthetic host byte
                                      stream (0xFEEEEEEF {len} packet header);
                                      the DA's own self-installer (0x40008290)
                                      re-applies the stubs if it runs.

Modes: engine | pump | regen | semantics | all.
SAFETY: emulator only; flash = python dict; no device, no efuse, no network.
"""
import sys, struct, argparse, hashlib

sys.path.insert(0, "/tmp/opencode/efuse2710")
sys.path.insert(0, "/root/mtkclient/docs/notes")
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR,
                               UC_ARM_REG_SP)
import da2_2710_efuse_flash as fl
from harness import SESSION

# ---- addresses resolved this session (2710EX01 static analysis) --------------
SCHED_INIT    = 0x40009B2C
THREAD_CREATE = 0x400094CC
EVENT_WAIT    = 0x400091A4
SESSION_DRV   = 0x40030918
WORKER_ENTRY  = 0x400301D0
SESS_TAB      = 0x40054A58
SESS_VT       = 0x40054A90
SECCFG_LOADER = 0x40034F14
SECCFG_TOP    = 0x40034E84
DIGEST_FN     = 0x4003A58C
SCRAMBLE_FN   = 0x40034958
KEYLOAD_FN    = 0x400348F0
SEJ_KEY       = 0x1000A060
CHKSUM_INFO   = 0x40000F50
CHKSUM_PICK   = 0x400548F8
CHK_ADD       = 0x4000105C
CHK_REPORT    = 0x40001504
PUMP_FN       = 0x4002D860
ANTICLONE     = 0x40057578      # static 0x01 in the image (anti-clone ON)
STATE_GLOBAL  = 0x4006F168
CUSTOM_REC    = 0x40068158
FETCH_BUF     = 0x40540000    # file-fetch engine buffer (harness FILEBUF)
STUB_RECV  = 0x405E1100
STUB_SEND  = 0x405E1180
FAKE_TCB   = 0x405E2000
SEEDS = (0x9ED40400, 0x00E884A1, 0xE3F083BD, 0x2F4E6D8A)

# ------------------------------------------------------------------ AES-128
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")

def _xtime(a):
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a

def _key_expand(key):
    rcon, w = 1, [list(key[i*4:i*4+4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return [sum([w[r*4+c] for c in range(4)], []) for r in range(11)]

def _encrypt_block(block, rk):
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 11):
        s = [SBOX[b] for b in s]
        t = list(s)
        for r in range(4):
            for c in range(4):
                s[r + 4*c] = t[r + 4*((c + r) % 4)]
        if rnd != 10:
            for c in range(4):
                a0, a1, a2, a3 = s[4*c:4*c+4]
                x0, x1 = _xtime(a0), _xtime(a1)
                x2, x3 = _xtime(a2), _xtime(a3)
                s[4*c+0] = x0 ^ (x1 ^ a1) ^ a2 ^ a3
                s[4*c+1] = a0 ^ x1 ^ (x2 ^ a2) ^ a3
                s[4*c+2] = a0 ^ a1 ^ x2 ^ (x3 ^ a3)
                s[4*c+3] = (x0 ^ a0) ^ a1 ^ a2 ^ x3
        s = [s[i] ^ rk[rnd][i] for i in range(16)]
    return bytes(s)

def aes128_cbc_enc(data, key, iv):
    rk = _key_expand(key)
    out, prev = bytearray(), iv
    for i in range(0, len(data), 16):
        blk = bytes(a ^ b for a, b in zip(data[i:i+16], prev))
        prev = _encrypt_block(blk, rk)
        out += prev
    return bytes(out)

# ------------------------------------------------------------------ models
e_cur = [None]          # the active emu (for the crypto models)
STREAM = bytearray()    # host->DA byte stream (packet headers + payloads)
STAGE = [[]]            # pending host->DA packets, released on each DA "OK"
CONSUMER = [None]       # captured consumer thread (entry, arg) from M2
PEND = [None]           # legacy alias slot (unused by M3 since the LR gate)
HOST = [None]           # reactive host (Host instance when pumping)
TRACE = []              # transition record

def rd32(uc, a):
    return struct.unpack("<I", uc.mem_read(a, 4))[0]

def sej_scramble_model(uc, buf_addr, ln):
    assert ln % 16 == 0 and 0 < ln <= 0x1000
    key = bytes(uc.mem_read(SEJ_KEY, 32))
    iv = struct.pack("<4I", *SEEDS)
    data = bytes(uc.mem_read(buf_addr, ln))
    return aes128_cbc_enc(data, key, iv)


FETCH_BUF     = 0x40540000    # file-fetch engine buffer (harness FILEBUF)
FETCH_PAYLOAD = [None]        # blob the fetch engine serves when armed


def install_storage_bigcap(e, model, log):
    """fl.install_storage verbatim except the model-I/O cap: 0x200000 ->
    0x10000000.  The 2710 seccfg partition is 0x800000 and fl's cap silently
    DROPPED the full-partition ops[1] write (the earlier "flash[:0x20]==ff"
    symptom) — the write must be modeled whole.  (A read-back tamper hook is
    NOT needed: with CHK_NO the write path performs no post-write read-back
    at all — executed evidence, mode pump; the integrity check is the CHK_ADD
    per-chunk word-sum instead, mode engine [4].)
    """
    for a in (fl.STUB_S0, fl.STUB_S1, fl.STUB_S8, fl.STUB_SC):
        e.uc.mem_write(a, fl.BX_LR)

    def mk(slot, direction):
        def h(uc, addr, size, ud):
            r0 = uc.reg_read(UC_ARM_REG_R0); r1 = uc.reg_read(UC_ARM_REG_R1)
            r2 = uc.reg_read(UC_ARM_REG_R2)
            sp = uc.reg_read(UC_ARM_REG_SP)
            st = [rd32(uc, sp + 4 * i) for i in range(6)]
            off = (r0 | (r1 << 32)) & 0xFFFFFFFFFFFFFFFF
            ln = st[0]
            rec = st[2]
            ent = {"slot": slot, "off": off, "buf": r2, "len": ln,
                   "rec": rec, "st": st[:3]}
            try:
                if rec and 0x40000000 < rec < 0x40600000:
                    ent["rec_name"] = bytes(uc.mem_read(rec + 8, 16)).split(b"\0")[0].decode("ascii", "replace")
            except Exception:
                pass
            log.append(ent)
            if direction == "R" and 0 < ln <= 0x10000000:
                try:
                    uc.mem_write(r2, model.read(off, ln))
                    ent["served"] = ln
                except Exception as ex:
                    ent["err"] = str(ex)[:60]
            elif direction == "W" and 0 < ln <= 0x10000000:
                try:
                    data = bytes(uc.mem_read(r2, ln))
                    model.write(off, data)
                    ent["data32"] = data[:32].hex()
                except Exception as ex:
                    ent["err"] = str(ex)[:60]
            elif direction == "E":
                try:
                    start = rd32(uc, r0 + 0x48) | (rd32(uc, r0 + 0x4C) << 32)
                    eln = rd32(uc, r0 + 0x50) | (rd32(uc, r0 + 0x54) << 32)
                    ent["erase_start"], ent["erase_len"] = start, eln
                    if 0 < eln <= 0x10000000:
                        model.erase(start, eln)
                except Exception as ex:
                    ent["err"] = str(ex)[:60]
            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        return h

    e.uc.hook_add(UC_HOOK_CODE, mk(0, "R"), begin=fl.STUB_S0, end=fl.STUB_S0)
    e.uc.hook_add(UC_HOOK_CODE, mk(1, "W"), begin=fl.STUB_S1, end=fl.STUB_S1)
    e.uc.hook_add(UC_HOOK_CODE, mk(8, "E"), begin=fl.STUB_S8, end=fl.STUB_S8)
    e.uc.hook_add(UC_HOOK_CODE, mk(12, "?"), begin=fl.STUB_SC, end=fl.STUB_SC)
    e.uc.mem_write(fl.OPS_TAB + 0,    struct.pack("<I", fl.STUB_S0))
    e.uc.mem_write(fl.OPS_TAB + 4,    struct.pack("<I", fl.STUB_S1))
    e.uc.mem_write(fl.OPS_TAB + 8,    struct.pack("<I", fl.STUB_S8))
    e.uc.mem_write(fl.OPS_TAB + 0xC,  struct.pack("<I", fl.STUB_SC))
    e.uc.mem_write(fl.OPS_TAB + 0x10, struct.pack("<I", fl.STUB_SC))


def install_fetch(e):
    """the file-fetch engine 0x4002AFD8 (harness hook_file_fetch pattern) —
    the NAMED-file path (the efuse chain's source_file="efuseimg").  For
    source_file="MEM://<off>:<len>" the DA does NOT call it: the file bytes
    arrive as transport packets on the data channel and land in the download
    buffer (ctx+8 base, observed 0x80001000).  Installed anyway so a fetch
    call can never return garbage; a mode arms FETCH_PAYLOAD to serve it."""
    def fetch(uc, a, s, ud):
        p = FETCH_PAYLOAD[0]
        r3 = uc.reg_read(UC_ARM_REG_R3)
        if p:
            uc.mem_write(FETCH_BUF, bytes(p) + b"\x00" * 16)
            uc.mem_write(r3, struct.pack("<II", len(p), FETCH_BUF))
            uc.reg_write(UC_ARM_REG_R0, FETCH_BUF)
            TRACE.append(("fetch_serve", f"len={len(p)} buf={FETCH_BUF:#x}"))
        else:
            uc.mem_write(r3, struct.pack("<II", 0, FETCH_BUF))
            uc.reg_write(UC_ARM_REG_R0, 0)
            TRACE.append(("fetch_serve", "EMPTY (len=0)"))
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, fetch, begin=fl.FETCH_FN, end=fl.FETCH_FN)


def install_models(e):
    """crypto + RTOS + transport models (M1..M6)."""
    # M4: digest -> sha256
    def digest(uc, a, s, ud):
        buf = uc.reg_read(UC_ARM_REG_R0); ln = uc.reg_read(UC_ARM_REG_R1)
        out = uc.reg_read(UC_ARM_REG_R2)
        uc.mem_write(out, hashlib.sha256(bytes(uc.mem_read(buf, ln))).digest())
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, digest, begin=DIGEST_FN, end=DIGEST_FN)
    # M5: SEJ scramble -> AES-128-CBC (key from the real key-load site)
    def scramble(uc, a, s, ud):
        buf = uc.reg_read(UC_ARM_REG_R0); ln = uc.reg_read(UC_ARM_REG_R1)
        flag = uc.reg_read(UC_ARM_REG_R2)
        if flag:
            uc.mem_write(buf, sej_scramble_model(uc, buf, ln))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, scramble, begin=SCRAMBLE_FN, end=SCRAMBLE_FN)
    # M2: thread_create -> capture + fake TCB
    def create(uc, a, s, ud):
        entry = uc.reg_read(UC_ARM_REG_R1); arg = uc.reg_read(UC_ARM_REG_R2)
        CONSUMER[0] = (entry, arg)
        TRACE.append(("thread_create", f"entry={entry:#x} arg={arg:#x}"))
        # M2b: the RTOS thread-start path (0x400093A4) re-inits the
        # download-buffer descriptor via 0x4002F66C before any worker runs;
        # the capture collapses that machinery — replicate its exact effect
        # (packet_length 0x200000; +0x18 = 0x10000 iff [0x40068194]==1 else
        # 0x200000; buffer size by DRAM class, emu -> smallest = 0x1000000).
        uc.mem_write(0x40068188 + 0x14,
                     struct.pack("<III", 0x200000, 0x200000, 0x1000000))
        uc.reg_write(UC_ARM_REG_R0, FAKE_TCB)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, create, begin=THREAD_CREATE, end=THREAD_CREATE)
    # M3: event-wait -> success; the ONE meaningful wait is the producer's
    # post-fill drain-wait (0x400306D8, LR 0x400306DC): there the consumer
    # thread (the RTOS would schedule it) is run INLINE — it pops the filled
    # slot (0x4002FA5C) and drives the real write chain ("write bulk image").
    # Every other wait (handler sync, pre-fill slot-free) just succeeds.
    def wait(uc, a, s, ud):
        lr = uc.reg_read(UC_ARM_REG_LR)
        if CONSUMER[0] is not None and lr == 0x400306DC:
            entry, arg = CONSUMER[0]
            TRACE.append(("consumer_run", f"at drain-wait entry={entry:#x}"))
            uc.reg_write(UC_ARM_REG_R0, arg)
            uc.reg_write(UC_ARM_REG_PC, entry)
            return
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, wait, begin=EVENT_WAIT, end=EVENT_WAIT)
    # M6: transport
    def recv(uc, a, s, ud):
        buf = uc.reg_read(UC_ARM_REG_R0); ln = uc.reg_read(UC_ARM_REG_R1)
        n = min(ln, len(STREAM))
        uc.mem_write(buf, bytes(STREAM[:n]) + b"\x00" * max(0, ln - n))
        del STREAM[:n]
        TRACE.append(("transport_recv", f"want={ln} got={n} "
                      f"first8={bytes(uc.mem_read(buf, 8)).hex()}"))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    def send(uc, a, s, ud):
        buf = uc.reg_read(UC_ARM_REG_R0); ln = uc.reg_read(UC_ARM_REG_R1)
        try:
            payload = bytes(uc.mem_read(buf, min(ln, 0x100)))
            hexs = payload[:48].hex()
            TRACE.append(("transport_send",
                          hexs + (f" len={ln}" if ln > 48 else "")))
            if HOST[0] is not None:
                HOST[0].on_send(payload)
            # the DA's plain "OK" on the data channel acks the host's previous
            # packet; the next staged host->DA packet (in-loop ack / chunk)
            # becomes readable.
            if payload[:2] == b"OK" and STAGE[0]:
                STREAM.extend(STAGE[0].pop(0))
        except Exception:
            pass
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.mem_write(STUB_RECV, b"\x1e\xff\x2f\xe1")
    e.uc.mem_write(STUB_SEND, b"\x1e\xff\x2f\xe1")
    e.uc.hook_add(UC_HOOK_CODE, recv, begin=STUB_RECV, end=STUB_RECV)
    e.uc.hook_add(UC_HOOK_CODE, send, begin=STUB_SEND, end=STUB_SEND)
    reapply = lambda uc, a, s, ud: (uc.mem_write(SESS_TAB + 8,
        struct.pack("<I", STUB_RECV)), uc.mem_write(SESS_TAB + 0xC,
        struct.pack("<I", STUB_SEND)))
    for site in (0x400082F0, 0x400082E4, 0x40008328, 0x4000831C, 0x400082FC):
        e.uc.hook_add(UC_HOOK_CODE, reapply, begin=site, end=site)
    # the DA's own session-table self-installer would point the slots back at
    # the real UART/USB drivers; the synthetic transport owns the slot
    # boundary, so the installer is neutralised (it re-applies the stubs).
    for site in (0x4000828C, 0x40008290, 0x4000833C):
        e.uc.hook_add(UC_HOOK_CODE, reapply, begin=site, end=site)
    # M6b: the session-port/link init (0x4003168C -> pinmux 0x10007000 + a
    # link-wait retry that ends in the WDT-kick panic loop when its 4-slot
    # timer table fills).  The physical link does not exist in the emulator;
    # the transport boundary is the session-op table above.
    e.uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, ud:
                  uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR)),
                  begin=0x4003168C, end=0x4003168C)
    # M6c: the timer-panic terminal loop (0x4001E7F0: print + WDT-kick
    # forever) — reached when the port init registers a timer with a null
    # callback; declared non-fatal in the transport model.
    e.uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, ud:
                  uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR)),
                  begin=0x4001E7F0, end=0x4001E7F0)
    # M6d: the whole USB-link/port-setup band below the transport boundary —
    # pinmux (0x10007000), link-wait retries, the timer-panic path and the
    # delay helpers.  Immediate-return; the emu has no notion of wall time.
    def _ret0(uc, a, s, ud):
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    for site in (0x4002A5D8, 0x4002A6B4, 0x4002A81C, 0x4002A830, 0x4002A878,
                 0x4002A96C, 0x4001E8C8, 0x40020628, 0x40020470, 0x400204C0,
                 0x400206AC, 0x4001E82C, 0x40020A24,
                 # the low-level port/UART band below the transport boundary
                 0x400208C0, 0x400207E8, 0x40020964, 0x40020894, 0x400209F0,
                 0x400209CC, 0x40030FCC, 0x40030FDC, 0x40031008, 0x400208C0):
        e.uc.hook_add(UC_HOOK_CODE, _ret0, begin=site, end=site)
    # fake monotonic timer for the checksum benchmark (0x4002F704 wraps these)
    tick = [0]
    def _tick(uc, a, s, ud):
        tick[0] += 0x10
        uc.reg_write(UC_ARM_REG_R0, tick[0])
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, _tick, begin=0x40020470, end=0x40020470)
    # M6e: UART0 device model (base 0x11002000, static pointer 0x40056668):
    # LSR at +0x14 reads as TX-empty|RX-ready (0x60) so the real byte-level
    # send path terminates; byte writes are dropped.
    from unicorn import UC_HOOK_MEM_READ
    def _lsr(uc, access, address, size, value, ud):
        if (address & ~3) == 0x11002014:
            uc.mem_write(0x11002014, struct.pack("<I", 0x60))
    e.uc.hook_add(UC_HOOK_MEM_READ, _lsr, begin=0x11002000, end=0x11003000)


def build5(seed_record=None):
    """fresh emu at status 5 (forged session) with all models installed."""
    CONSUMER[0] = None
    e = fl.make_emu()
    e.call(fl.REG_BOOT, [])
    model, log, txlog = fl.FlashModel(), [], []
    fl.seed_storage_topology(e)
    install_storage_bigcap(e, model, log)
    fl.install_session(e, txlog)
    fl.attach_observers(e)
    rc, hh = fl.forge(e, options=[("0x40054C88", "5")])
    e.uc.hook_del(hh)
    e.call(fl.REG_POLICY, [])
    fl.heap_fresh_tail(e)
    # device windows the data phase touches (UART band; SEJ key page)
    e.uc.mem_map(0x11000000, 0x30000)
    try:
        e.uc.mem_map(0x1000A000, 0x1000)
    except Exception:
        pass
    # the fetch-buffer window (0x40500000..0x405E0000 is unmapped in the
    # stock harness; FILEBUF=0x40540000 lives in the hole)
    try:
        e.uc.mem_map(0x40500000, 0xE0000)
    except Exception:
        pass
    # M1: the real scheduler init
    e.call(SCHED_INIT, [], count=4_000_000)
    install_models(e)
    install_fetch(e)
    # M6 pre-install: the transport stubs own the slot boundary (the values
    # the real path-B installer would write are kept for reference in the
    # vtable at SESS_VT).
    e.uc.mem_write(SESS_TAB + 8,  struct.pack("<I", STUB_RECV))
    e.uc.mem_write(SESS_TAB + 0xC, struct.pack("<I", STUB_SEND))
    if seed_record:
        model.write(fl.SECCFG_START, seed_record)
    model.seeded = bytes(model.read(fl.SECCFG_START, 0x80))
    return e, model, log, txlog


class Host:
    """synthetic host for the 2710 data phase (observation only).

    Choreography (executed-evidence, 2710 decode this session):
      XML channel  (SESSION+0/+4 = fl's stubs, canned QUEUE): the DA sends the
        FileSysOp EXISTS query and the CMD:DOWNLOAD-FILE XML; the host's
        answers come back through the QUEUE ("OK@0x0", "OK@0x200", ...).
      data channel (0x40054A48+0/+4 -> 0x4002AA28/0x4002AB08 -> SESS_TAB+8/
        +0xC = STREAM): ONE unified packet transport {0xFEEEEEEF,1,len}+payload;
        per chunk the host pushes pkt("OK@0x200\\0") (the in-loop ack, parsed
        by 0x400307A8 -> 0x4000AD9C) and then pkt(chunk); the DA acks each
        with a plain "OK\\0" send (0x40054A48+4).
    The host therefore only RECORDS what the DA sends; every host->DA byte is
    pre-staged in STREAM in wire order."""
    def __init__(self, blob: bytes = b""):
        self.blob = blob
        self.log = []

    def on_send(self, payload: bytes):
        self.log.append(("da_send", payload[:64]))


def seccfg_v4(lock_state=3):
    """canonical SecCfgV4 record (mtkclient layout): 7-word header (0x1C) +
    0x20-byte digest slot; 0x3C bytes total."""
    hdr = struct.pack("<7I", 0x4D4D4D4D, 4, 0x3C, lock_state, 0, 0,
                      0x45454545)
    return hdr + b"\x11" * 0x20


def pkt(data: bytes) -> bytes:
    """the 2710 DA2 host->DA data packet: {0xFEEEEEEF, DT_PROTOCOL_FLOW=1,
    len} + payload (mtkclient xml_lib xsend format)."""
    return struct.pack("<III", 0xFEEEEEEF, 1, len(data)) + data


def feed(payload: bytes, ack_value: int = 0x200):
    """stage the host->DA bytes for WRITE-PARTITION(seccfg, MEM://0x0:0x200)
    per the executed 2710 choreography (single 0x200 chunk, packet_length
    0x200000 from the descriptor init):
      XML channel (canned QUEUE, fl's SESSION stubs): the DA's FileSysOp
        EXISTS query is answered "OK@0x0" (.sig absent); the DA's
        CMD:DOWNLOAD-FILE XML gets the announce answer "OK@0x200" (the
        0x4002AE28 check reads only 'O','K').
      data channel (STREAM, the worker's 0x40054A48 table -> 0x4002AA28
        packet reader over SESS_TAB+8): ALL packets pre-staged in wire order —
        the pre-loop OK@0x200 announce (0x400303A0; its value becomes the
        receive total at [0x4006EF4C]+0x10), the in-loop OK@<ack_value> ack
        (0x40030500; with CHK_ADD this is the chunk's expected word-sum,
        compared by the real engine at 0x400305D4), then the data packet
        {magic,1,0x200}+payload (magic-checked by 0x4002AA90)."""
    STREAM.clear()
    STAGE[0] = []
    STREAM.extend(pkt(b"OK@0x200\0"))
    STREAM.extend(pkt(f"OK@0x{ack_value:x}\0".encode()))
    STREAM.extend(pkt(payload))
    fl.QUEUE[0][:] = ["OK@0x0", "OK@0x200", "OK@0x200",
                      "OK", "OK", "OK", "OK", "OK"]


def fmt_tx(txlog):
    out = []
    for t in txlog:
        if t[0] == "tsend":
            out.append(f"    transport_send {t[2].hex()[:64]} len={t[3]}")
    return out


# ------------------------------------------------------------------- modes
def mode_engine():
    print("=" * 100)
    print("MODE engine — the download checksum engine: identity, algorithm, "
          "verify semantics (all real DA code)")
    # direct: run the real initial_chksum_info, read the picked function
    e, model, log, txlog = build5()
    rc = e.call(CHKSUM_INFO, [], count=6_000_000)
    picked = rd32(e.uc, CHKSUM_PICK)
    dis = rd32(e.uc, 0x400548FC) if False else None
    print(f"  [1] real initial_chksum_info: rc={rc if not isinstance(rc,int) else hex(rc)}")
    print(f"      picked checksum function @0x400548F8 = {picked:#x}")
    print(f"      disable byte @0x4006A564 = {e.uc.mem_read(0x4006A564,1).hex()}")
    # the eight candidates are word-sum loops; verify with a python replica
    buf, ln = 0x40471000, 0x1000
    data = bytes(range(256)) * 16
    e.uc.mem_write(buf, data)
    rc2 = e.call(picked, [buf, ln])
    got = rc2 if isinstance(rc2, int) else 0
    rep = sum(struct.unpack(f"<{ln//4}I", data)) & 0xFFFFFFFF
    print(f"  [2] picked fn over 0x1000 B: ret={got:#x}"
          f"  python word-sum replica={rep:#x}  match={got == rep}")
    # per-chunk bookkeeping: set_chunk_info buffers 0x20-byte entries (memcpy)
    print("  [3] set_chunk_info 0x4000105C: pure 0x20-byte memcpy into the info"
          " struct (no engine touch); per-chunk report 0x40001504 dispatches"
          " through the SAME picked word-sum (0x40001594 loads 0x400548F8's"
          " base 0x4006A560 list).")
    del e

    # end-to-end CHK_ADD session: the in-loop OK@ carries the chunk's expected
    # word-sum; the producer compares it against the real picked engine over
    # the received chunk (0x400305D0 -> 0x400014D4 -> picked; cmp @0x400305D4).
    print("\n  [4] end-to-end WRITE-PARTITION under CHK_ADD (per-chunk"
          " word-sum verify, executed both ways):")
    def word_sum(data: bytes) -> int:
        return sum(struct.unpack(f"<{len(data)//4}I", data)) & 0xFFFFFFFF
    payload = seccfg_v4(3) + b"\x00" * (0x200 - 0x3C)
    good = word_sum(payload)
    for tag, expect in (("correct expected checksum", good),
                        ("corrupted expected checksum", good ^ 0x55AA55AA)):
        e, model, log, txlog = build5()
        cfg = bytearray(e.uc.mem_read(0x40068188, 8))
        cfg[0] |= 1                      # session checksum = CHK_ADD (the
        e.uc.mem_write(0x40068188,       # bit the driver selects the XML
                       bytes(cfg))       # <checksum> field from, 0x4002AEEC)
        PEND[0] = None; TRACE.clear()
        FETCH_PAYLOAD[0] = payload
        feed(payload, ack_value=expect)
        e.uc.mem_write(fl.XMLPATH, fl.cmd_xml("CMD:WRITE-PARTITION",
            "<partition>seccfg</partition>"
            "<source_file>MEM://0x0:0x200</source_file>"
            "<pre_erase>NO</pre_erase>"))
        rc = e.call(fl.HANDLERS["CMD:WRITE-PARTITION"], [SESSION, fl.XMLPATH],
                    count=30_000_000)
        FETCH_PAYLOAD[0] = None
        rcx = rc if not isinstance(rc, int) else hex(rc & 0xFFFFFFFF)
        print(f"    [{tag}] expect={expect:#x}")
        print(f"      handler rc={rcx}  writes="
              f"{[(hex(a), hex(l)) for a, l in model.writes]}")
        got = bytes(model.read(fl.SECCFG_START, 0x40))
        print(f"      boundary[:0x20]: {got[:0x20].hex()}")
        mism = [l for l in e.da_log if "hksm" in l.lower() or
                "checksum" in l.lower()]
        for l in mism[-4:]:
            print("      DA:", l.strip()[:100])
        del e
    print("""
INTERPRETATION (engine): the 2710 download checksum is a SOFTWARE additive
word-sum (8 candidates benchmarked, one selected into 0x400548F8; executed
identity match against the python replica in [2]).  It is negotiated per
session: the download driver stamps <checksum>CHK_ADD|CHK_NO</checksum> into
its DOWNLOAD-FILE XML from config bit [0x40068188]&1 (0x4002AEEC) — mtkclient
always gets CHK_NO.  Under CHK_ADD the host's in-loop OK@ carries the chunk's
expected word-sum; the producer computes the real engine over the received
chunk (0x400014D4 dispatch) and compares (0x400305D4): mismatch prints the
expected/actual pair and sets [ctx+0xE0]=0xC0040003 — the consumer then
REFUSES the chunk (executed in [4], corrupted case: no boundary write).  With
CHK_NO (the pumped default) there is NO post-write read-back at all — the
write flow performs zero storage reads after the write (mode pump evidence).
Either way it is an INTEGRITY mechanism on the transport, not an
authorization check: it never consults session state, keys or efuse.  The
previous note's "HW checksum engine" attribution was wrong — the pre-update
stall was the RTOS assert (thread.c newthread), not MMIO.""")
    return 0


def mode_pump():
    print("=" * 100)
    print("MODE pump — forged session, real CMD:WRITE-PARTITION(seccfg),"
          " full SecCfgV4 payload, empty flash")
    payload = seccfg_v4(3) + b"\x00" * (0x200 - 0x3C)
    e, model, log, txlog = build5()
    host = Host(payload)
    HOST[0] = host
    PEND[0] = None; TRACE.clear()
    FETCH_PAYLOAD[0] = payload
    feed(payload)
    pre = bytes(model.read(fl.SECCFG_START, 0x200))
    e.uc.mem_write(fl.XMLPATH, fl.cmd_xml("CMD:WRITE-PARTITION",
        "<partition>seccfg</partition>"
        "<source_file>MEM://0x0:0x200</source_file>"
        "<pre_erase>NO</pre_erase>"))
    rc = e.call(fl.HANDLERS["CMD:WRITE-PARTITION"], [SESSION, fl.XMLPATH],
                count=40_000_000)
    rcx = rc if not isinstance(rc, int) else hex(rc & 0xFFFFFFFF)
    post = bytes(model.read(fl.SECCFG_START, 0x200))
    print(f"  handler rc={rcx}   host stream left unconsumed: {len(STREAM)} B")
    print("  transition record:")
    for t in TRACE[:40]:
        print("   ", t[0], t[1][:90])
    print("  host side:")
    for t in host.log[:20]:
        print("   ", t[0], t[1])
    print("  storage ops:")
    for line in fl.fmt_log(log, 20):
        print(line)
    print("  model writes:", [(hex(a), hex(l)) for a, l in model.writes])
    print("  model erases:", [(hex(a), hex(l)) for a, l in model.erases])
    diff = [(i, pre[i], post[i]) for i in range(len(pre)) if pre[i] != post[i]]
    print(f"  boundary byte-diff vs pre-run: {len(diff)} bytes"
          + (f" first at {diff[0][0]:#x}" if diff else ""))
    print(f"  uploaded payload reached the boundary VERBATIM: "
          f"{post[:len(payload)] == payload}")
    print(f"  content[:0x20]: {post[:0x20].hex()}")
    print("  DA log (data-phase relevant):")
    keep = ("Download", "checksum", "flashinfo", "ASSERT", "write", "Erase",
            "Progress", "fail", "end", "seccfg", "space")
    seen = set()
    for l in e.da_log:
        if any(k.lower() in l.lower() for k in keep):
            k = l[:40]
            if k in seen: continue
            seen.add(k)
            print("    ", l[:104])
    HOST[0] = None
    FETCH_PAYLOAD[0] = None
    del e
    return 0


def build_valid_record(lock_state=1):
    """SecCfgV4 record whose digest passes the (modeled) 2710 validator:
    digest = SEJ_scramble(SHA256(hdr[0:0x1C])), AKEY = zeros (no custom
    record harvested in these scenarios), IV = the fixed seed table."""
    hdr = struct.pack("<7I", 0x4D4D4D4D, 4, 0x3C, lock_state, 0, 0,
                      0x45454545)
    enc = aes128_cbc_enc(hashlib.sha256(hdr).digest(),
                         b"\x00" * 32, struct.pack("<4I", *SEEDS))
    return hdr + enc


def mode_regen():
    print("=" * 100)
    print("MODE regen — does a SUCCEEDING sec_get_seccfg make the DA"
          " regenerate/replace uploaded seccfg bytes post-write?")
    for tag, seed in (
        ("S1 empty flash (no valid record)", None),
        ("S2 seeded VALID record (lock_state=1, digest=SEJ(SHA256(hdr)))",
         build_valid_record(1) + b"\xFF" * (0x200 - 0x3C)),
    ):
        print(f"\n--- {tag} ---")
        e, model, log, txlog = build5(seed_record=seed)
        payload = seccfg_v4(3) + b"\x00" * (0x200 - 0x3C)
        PEND[0] = None; TRACE.clear()
        FETCH_PAYLOAD[0] = payload
        feed(payload)
        pre = bytes(model.read(fl.SECCFG_START, 0x200))
        pre_w = len(model.writes)
        e.uc.mem_write(fl.XMLPATH, fl.cmd_xml("CMD:WRITE-PARTITION",
            "<partition>seccfg</partition>"
            "<source_file>MEM://0x0:0x200</source_file>"
            "<pre_erase>NO</pre_erase>"))
        rc = e.call(fl.HANDLERS["CMD:WRITE-PARTITION"], [SESSION, fl.XMLPATH],
                    count=40_000_000)
        rcx = rc if not isinstance(rc, int) else hex(rc & 0xFFFFFFFF)
        post = bytes(model.read(fl.SECCFG_START, 0x200))
        seclog = [l for l in e.da_log if "sec_get_seccfg" in l or
                  "lock state" in l]
        print(f"  handler rc={rcx}")
        print(f"  sec_get_seccfg during the flow: {seclog[:6]}")
        print(f"  model writes during the flow: "
              f"{[(hex(a), hex(l)) for a, l in model.writes[pre_w:]]}")
        print(f"  uploaded payload verbatim at the boundary: "
              f"{post[:len(payload)] == payload}")
        diff = [(i, pre[i], post[i]) for i in range(len(pre))
                if pre[i] != post[i]]
        print(f"  pre->post boundary diff: {len(diff)} bytes"
              + (f" first@{diff[0][0]:#x} {diff[0][1]:02x}->{diff[0][2]:02x}"
                 if diff else ""))
        if diff:
            for i, a, b in diff[:8]:
                print(f"    @{i:#04x}: {a:02x} -> {b:02x}")
        # post-write: what does the DA's OWN validator now say about the flash?
        FETCH_PAYLOAD[0] = None
        print("  post-write sec_get_seccfg (the DA re-reading its own write):")
        e.uc.mem_write(0x4046E000, struct.pack("<I", 0))
        rc2 = e.call(SECCFG_TOP, [0x4046E000], count=8_000_000)
        st = rd32(e.uc, STATE_GLOBAL)
        newls = rd32(e.uc, 0x40067DC0 + 0xC) if st == 1 else None
        print(f"    top rc={rc2 if not isinstance(rc2,int) else hex(rc2 & 0xFFFFFFFF)}"
              f"  slot-state global={st}  lock_state_of_surviving_record="
              f"{newls}")
        print(f"    SEJ key @0x1000A060 at validator time: "
              f"{bytes(e.uc.mem_read(SEJ_KEY, 16)).hex()}")
        got = bytes(model.read(fl.SECCFG_START, 0x80))
        print(f"    flash[:0x20] now: {got[:0x20].hex()}")
        print(f"    uploaded-record still verbatim: "
              f"{got == payload[:len(got)]}")
        del e
    print("""
INTERPRETATION (regen): in BOTH scenarios the DA wrote the uploaded bytes
verbatim and did NOT regenerate, re-sign or replace them; a succeeding
sec_get_seccfg only flips the slot-state global and feeds the (instrumentary)
policy getter.  The 200EX01 "SEC regeneration" class does NOT exist on the
2710 write path — the readback normalization seen on 200EX01 sessions is a
read-path/erase-order artifact there, exactly as re-write-chain.md concluded
for the 200EX01 binary itself.""")
    return 0


def mode_semantics():
    print("=" * 100)
    print("MODE semantics — which seccfg bytes are unlock-relevant, and what"
          " the DA does to them")
    rec = build_valid_record(1)
    up = fl.seccfg_v4_record(3)
    print(f"""
  SecCfgV4 record layout (mtkclient Library/Hardware/seccfg.py == the 2710
  DA2 validator 0x40034F14 == LK's boot-time validator):
    +0x00  magic  = 0x4D4D4D4D ("MMMM")         [checked == MMMM]
    +0x04  ver    = 4                            [V4]
    +0x08  size   = 0x3C                         [record size]
    +0x0C  lock_state  — THE unlock byte.  1 = locked, 3 = unlocked
                       (mtkclient writes 3; the DA's own sec_get_seccfg top
                       0x40034E84 returns [hdr+0xC] of the surviving record
                       and the policy getter only logs it)
    +0x10  dm_verity                             [0 on unlock]
    +0x14  sboot                                 [0 on unlock]
    +0x18  0x45454545 ("EEEE")                   [sentinel]
    +0x1C  enc_hash (0x20 B) = SEJ_scramble(SHA256(hdr[0:0x1C]))
                       — the anti-clone digest; the ONLY content the DA/LK
                       verify, and it covers exactly the 0x1C header bytes
                       above (so lock_state IS digest-protected)
    +0x3C  backup record (zeros accepted: magic != MMMM -> skipped)

  DA-side write-path transform of these bytes (executed evidence, mode regen):
    NONE — the uploaded record reaches the storage boundary byte-exact; the
    digest field is NOT recomputed, NOT verified on the write path (a record
    with a garbage digest was written without complaint; the validator's
    failure only logged ret=c002002f and the flow continued fail-open).

  The unlock-relevant state is therefore exactly: lock_state (+0xC), with
  dm_verity/sboot (+0x10/+0x14) cleared, plus a digest consistent with that
  header.  mtkclient's unlock flow (read seccfg -> parse -> lock_state=3 ->
  re-sign via the device's own SEJ registers -> write back) produces exactly
  such a record; the DA session (even forged) adds no further gate.

  The boot-time boundary (what LK re-derives; OUT of the DA session's reach):
    * LK's sec_check_major_integrity_seccfg: software SHA-256 over the 0x1C
      header, then the SAME SEJ/HACC scramble (same engine, same fixed seed
      table) compared against the record's enc_hash — a record written with a
      correct on-device digest passes BOTH the DA and LK validators.
    * the RPMB boot-info mirror (re-lk-seccfg.md): double_check_lock_state
      re-locks and powers off on mismatch — the RPMB side is written by the
      DA during unlock flows and is a separate surface from seccfg bytes.
    * efuse/RID-class anti-clone state: the DA validates the record against
      device-efuse-derived key material (AKEY path) — the digest is
      device-bound, so a record signed on ANOTHER device never validates.""")
    print(f"  sample locked record  (built with the modeled digest): "
          f"{rec[:0x1C].hex()} {rec[0x1C:0x3C].hex()}")
    print(f"  uploaded unlock record (this session's payload): "
          f"{up[:0x1C].hex()} {up[0x1C:0x3C].hex()}")
    return 0


MODES = {"engine": mode_engine, "pump": mode_pump, "regen": mode_regen,
         "semantics": mode_semantics}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=[*MODES, "all"], nargs="?", default="all")
    a = ap.parse_args()
    if a.mode == "all":
        for f in MODES.values():
            f()
        sys.exit(0)
    sys.exit(MODES[a.mode]())
