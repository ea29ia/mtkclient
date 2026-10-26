#!/usr/bin/env python3
"""2710EX01 DA2 — storage-layer emulation under the auth=5 forge (emulator-only).

Companion note: docs/notes/reverse/re-da2-2710-flash-layer-2026-10-26.md
Harness:        /tmp/opencode/efuse2710/harness.py (DA2Emu, reused unmodified)
Forge driver:   docs/notes/da2_2710_efuse_chain.py (reused logic)
Image:          /tmp/opencode/fw2710/x/da2_2710.bin (VA 0x40000000 == file off 0)

What this adds ON TOP of the efuse-chain harness:
  * a synthetic storage device behind the DA's REAL storage-ops table
    0x40054A9C ([+0] block READ, [+4] block WRITE, [+8] erase dispatcher,
    [+0xC]/[+0x10] aux) — the narrowest UFS/mmc driver boundary.  Ops ABI
    (derived from the call sites 0x4002D690/0x4002D6CC [read] and
    0x4002D734 [write] and the direct site 0x40030B44):
        ops(off_lo, off_hi, buf, <junk: the ops fnptr itself>,
            stack{ len, x, record_copy })
    NO session, auth or policy parameter exists in the ABI.
  * a synthetic GPT cache (0x4006B0F0: byte0=valid, [4]=count, [8]=records;
    0x58-stride records: name@+8, start64@+0x48, size64@+0x50) and a synthetic
    storage-device object for [0x40067BD8] (classify table 0x40053A2C:
    "UFS-LUA0" type 0x100 -> capacity at dev+8), so *-PARTITION and *-FLASH
    handlers resolve targets exactly as on a real device.
  * a minimal host model on the session struct (recv = canned status/data
    queue, send = logged).  The fetch engine 0x4002AFD8 is left REAL.

Modes (all exit 0; every verdict is printed with its evidence):
  calib   prove the ops ABI + slot direction by direct calls
  probe   handler matrix {WRITE-PARTITION, WRITE-FLASH, READ-PARTITION,
          READ-FLASH} x {status 1 pre-forge, status 5 post-forge}:
          deny strings, storage-op log, flash-model diffs
  seccfg  end-to-end seccfg scenario at status 5
  all     everything

SAFETY: emulator only; the flash model is a Python dict.  The forge is the
proven reversible RAM write (one dword at 0x40054C88).  No efuse word, no
watchdog, no real device is touched.
"""
import sys, struct, argparse

sys.path.insert(0, "/tmp/opencode/efuse2710")
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                               UC_ARM_REG_R3, UC_ARM_REG_SP,
                               UC_ARM_REG_PC, UC_ARM_REG_LR)
from harness import DA2Emu, SESSION

# ---- constants shared with docs/notes/da2_2710_efuse_chain.py -----------------
AUTH          = 0x40054C88   # g_oplus_auth_status
REG_BOOT      = 0x40001D24
REG_POLICY    = 0x40001A78
WRITE_EFUSE   = 0x40005C20
XMLPATH       = 0x40461000

# ---- constants resolved this session (2710EX01 static analysis) ---------------
OPS_TAB       = 0x40054A9C   # storage ops table (.bss, runtime-initialised)
GPT_LIST      = 0x4006B0F0   # GPT cache list {valid u8, count@4, records@8}
GPT_LIST2     = 0x4006B0E4   # pseudo/SGPT list (searched first; left empty)
GPT_BUF       = 0x40470000   # synthetic GPT records
DEV_PTR       = 0x40067BD8   # storage-device object ptr (bss)
DEV_OBJ       = 0x40478000   # synthetic device object
REPLY_FN      = 0x400081AC
SEND_FILE_FN  = 0x4002B49C
FETCH_FN      = 0x4002AFD8   # fetch engine (left REAL in probe/seccfg)
WRAP_READ     = 0x4002D6CC   # (name, X, off_lo, off_hi, stack{buf,?,len,?})
WRAP_WRITE    = 0x4002D734   # same shape -> ops[1]
OP_READ       = 0x40030AA4   # chunk pump primitive (ops[0] direct caller)

STUB_BASE     = 0x405E1000
STUB_S0, STUB_S1, STUB_S8, STUB_SC = (STUB_BASE + 0x00, STUB_BASE + 0x10,
                                      STUB_BASE + 0x20, STUB_BASE + 0x30)
STUB_RECV, STUB_SEND = STUB_BASE + 0x40, STUB_BASE + 0x50
BX_LR = b"\x1e\xff\x2f\xe1"

XML_HDR = b'<?xml version="1.0" encoding="utf-8"?>'
DENY_MARKERS = (b"Security deny", b"auth_required", b"Cannot find",
                b"not authenticated", b"Locked", b"larger than",
                b"Failed", b"failed", b"do not get oplus")

SECCFG_START = 0x00A00000     # synthetic GPT start offset for seccfg
SECCFG_SIZE  = 0x800000       # 8 MiB (device-observed seccfg size)
LUA0_SIZE    = 0x100000000    # 4 GiB model capacity for UFS-LUA0

HANDLERS = {
    "CMD:WRITE-PARTITION":  0x400022B4,
    "CMD:WRITE-FLASH":      0x400030EC,
    "CMD:READ-PARTITION":   0x40003554,
    "CMD:READ-FLASH":       0x40003674,
    "CMD:READ-PARTITION-TABLE": 0x400038A4,
    "CMD:ERASE-PARTITION":  0x40003A64,
}


def make_emu(**kw):
    orig = DA2Emu.heap_init
    def patched(self):
        orig(self)
        self.uc.mem_write(0x4006A618, struct.pack("<I", 0x80000))
        self.uc.mem_write(0x40071588, struct.pack("<I", 0x80000))
    DA2Emu.heap_init = patched
    try:
        e = DA2Emu(**kw)
    finally:
        DA2Emu.heap_init = orig
    e.uc.mem_map(0x40088000, 0x400F2000 - 0x40088000)
    e.uc.mem_map(0x10200000, 0x20000)
    e.uc.mem_map(0x80000000, 0x4000000)   # DA storage/IO buffer pool (0x4002F860
                                          # allocates download/staging buffers
                                          # from a pool based at 0x80000000)
    # the DA2 is RTOS-threaded: the scheduler's context switch (0x400000A8)
    # saves/restores VFP d0-d15 — enable the FPU or vmov faults as an invalid
    # instruction the moment any thread yields.
    try:
        from unicorn.arm_const import UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC
        e.uc.reg_write(UC_ARM_REG_C1_C0_2, 0x00F00000)   # CPACR: CP10/CP11 full access
        e.uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)     # FPEXC.EN
    except Exception:
        pass
    return e


def cmd_xml(name, args=""):
    return (XML_HDR + b"<da><version>1.0</version><command>" + name.encode() +
            b"</command><arg>" + args.encode() + b"</arg></da>\x00")


def pad512(x):
    assert len(x) <= 0x200, len(x)
    return x + b"\x20" * (0x200 - len(x))


def forge(e, options=(("0x40054C88", "5"),)):
    """the proven reversible forge: real CMD:WRITE-EFUSE, one RAM dword.
    Returns (rc, fetch_hook_handle) — the caller must hook_del the handle."""
    payload = (XML_HDR + b'<efuse><debug><write fsource="3000" vcore="1200">'
               b"<verify><vcore>1200</vcore></verify>"
               b'<read fsource="3000" vcore="1200"/><extra>')
    for addr, data in options:
        payload += (b'<option address="' + addr.encode() + b'">' +
                    data.encode() + b"</option>")
    payload += b"</extra></write></debug></efuse>"
    e.uc.mem_write(0x40463000, pad512(payload))
    def hf(uc, a, s, ud):
        r3 = uc.reg_read(UC_ARM_REG_R3)
        uc.mem_write(r3, struct.pack("<II", 0x200, 0x40463000))
        uc.reg_write(UC_ARM_REG_R0, 0x40463000)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    hh = e.uc.hook_add(UC_HOOK_CODE, hf, begin=FETCH_FN, end=FETCH_FN)
    e.uc.mem_write(XMLPATH, cmd_xml("CMD:WRITE-EFUSE",
                                    "<source_file>efuseimg</source_file>"))
    return e.call(WRITE_EFUSE, [SESSION, XMLPATH]), hh


def heap_fresh_tail(e, start=0x40080000, end=0x400F1580):
    sent = 0x4006A61C
    e.uc.mem_write(start, struct.pack("<III", sent, sent, end - start))
    e.uc.mem_write(0x4006A620, struct.pack("<I", start))
    e.uc.mem_write(sent, struct.pack("<I", start))


# ---------------------------------------------------------------- storage model
class FlashModel:
    """page-backed synthetic UFS; default fill 0xFF (erased)."""
    PAGE = 0x1000
    def __init__(self, size=LUA0_SIZE):
        self.size = size
        self.pages = {}
        self.writes = []       # (off, len)
        self.erases = []       # (off, len)

    def _page(self, p):
        return self.pages.setdefault(p, bytearray(b"\xFF" * self.PAGE))

    def read(self, off, ln):
        out = bytearray()
        for i in range(ln):
            p, o = divmod(off + i, self.PAGE)
            out.append(self._page(p)[o])
        return bytes(out)

    def write(self, off, data):
        for i, b in enumerate(data):
            p, o = divmod(off + i, self.PAGE)
            self._page(p)[o] = b
        self.writes.append((off, len(data)))

    def erase(self, off, ln):
        for p in range(off // self.PAGE, (off + ln + self.PAGE - 1) // self.PAGE):
            self.pages[p] = bytearray(b"\xFF" * self.PAGE)
        self.erases.append((off, ln))

    def snapshot(self, off, ln):
        return self.read(off, ln)


def rd32(uc, a):
    return struct.unpack("<I", uc.mem_read(a, 4))[0]


def install_storage(e, model, log):
    """point the real storage-ops table at logging/device-model stubs."""
    for a in (STUB_S0, STUB_S1, STUB_S8, STUB_SC):
        e.uc.mem_write(a, BX_LR)

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
            if direction == "R" and 0 < ln <= 0x200000:
                try:
                    uc.mem_write(r2, model.read(off, ln))
                    ent["served"] = ln
                except Exception as ex:
                    ent["err"] = str(ex)[:60]
            elif direction == "W" and 0 < ln <= 0x200000:
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

    e.uc.hook_add(UC_HOOK_CODE, mk(0, "R"), begin=STUB_S0, end=STUB_S0)
    e.uc.hook_add(UC_HOOK_CODE, mk(1, "W"), begin=STUB_S1, end=STUB_S1)
    e.uc.hook_add(UC_HOOK_CODE, mk(8, "E"), begin=STUB_S8, end=STUB_S8)
    e.uc.hook_add(UC_HOOK_CODE, mk(12, "?"), begin=STUB_SC, end=STUB_SC)
    e.uc.mem_write(OPS_TAB + 0,    struct.pack("<I", STUB_S0))
    e.uc.mem_write(OPS_TAB + 4,    struct.pack("<I", STUB_S1))
    e.uc.mem_write(OPS_TAB + 8,    struct.pack("<I", STUB_S8))
    e.uc.mem_write(OPS_TAB + 0xC,  struct.pack("<I", STUB_SC))
    e.uc.mem_write(OPS_TAB + 0x10, struct.pack("<I", STUB_SC))


def seed_storage_topology(e):
    """synthetic GPT cache + storage device (what bootstrap2 / storage init
    build from the real device's GPT and UFS geometry)."""
    parts = [("seccfg", SECCFG_START, SECCFG_SIZE),
             ("boot",   0x01200000, 0x1000000),
             ("userdata", 0x10000000, 0x10000000)]
    recs = bytearray()
    for name, start, size in parts:
        r = bytearray(0x58)
        r[8:8 + len(name)] = name.encode()
        struct.pack_into("<Q", r, 0x48, start)
        struct.pack_into("<Q", r, 0x50, size)
        recs += r
    e.uc.mem_write(GPT_BUF, bytes(recs))
    e.uc.mem_write(GPT_LIST, struct.pack("<BBBBII", 1, 0, 0, 0, len(parts), GPT_BUF))
    e.uc.mem_write(GPT_LIST2, struct.pack("<BBBBII", 0, 0, 0, 0, 0, 0))
    # storage geometry lives in .bss globals consumed by the classify helper
    # 0x40012C88: [0x40067500]=UFS device handle, capacity64 at 0x40067508
    # (UFS-LUA0 type 0x100) / 0x40067510 (0x101) / 0x40067518 (0x102);
    # [0x40067BD8]=eMMC handle with capacity at 0x40067BE0 (type 1/2/8 at
    # +8/+0x10/+0x40).  On a UFS device the eMMC handle stays 0.
    e.uc.mem_write(0x40067BD8, struct.pack("<I", 0))
    e.uc.mem_write(0x40067500, struct.pack("<I", 0x40478000))   # UFS handle
    for a in (0x40067508, 0x40067510, 0x40067518):
        e.uc.mem_write(a, struct.pack("<Q", LUA0_SIZE))
    e.uc.mem_write(0x40067BE0, struct.pack("<Q", LUA0_SIZE))
    e.uc.mem_write(0x40067BE8, struct.pack("<Q", LUA0_SIZE))
    e.uc.mem_write(0x40067C18, struct.pack("<Q", LUA0_SIZE))


QUEUE = [[]]

def install_session(e, txlog):
    """session+0 = recv(buf,&max) serves the canned queue; +4 = send(buf,len)."""
    def recv(uc, a, s, ud):
        buf = uc.reg_read(UC_ARM_REG_R0)
        pl = uc.reg_read(UC_ARM_REG_R1)
        maxlen = rd32(uc, pl)
        if QUEUE[0]:
            item = QUEUE[0].pop(0); tag = "q"
        else:
            item = b"OK"; tag = "AUTO-OK"
        data = item if isinstance(item, (bytes, bytearray)) else item.encode()
        n = min(maxlen, len(data))
        uc.mem_write(buf, bytes(data[:n]) + b"\x00" * (maxlen - n))
        uc.mem_write(pl, struct.pack("<I", n))
        txlog.append(("recv", tag, bytes(data[:n])[:48], maxlen))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    def send(uc, a, s, ud):
        buf = uc.reg_read(UC_ARM_REG_R0)
        ln = uc.reg_read(UC_ARM_REG_R1)
        try:
            txlog.append(("send", "", bytes(uc.mem_read(buf, min(ln, 0x400)))[:80], ln))
        except Exception:
            txlog.append(("send", "", b"<unreadable>", ln))
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, recv, begin=STUB_RECV, end=STUB_RECV)
    e.uc.hook_add(UC_HOOK_CODE, send, begin=STUB_SEND, end=STUB_SEND)
    e.uc.mem_write(SESSION + 0, struct.pack("<I", STUB_RECV))
    e.uc.mem_write(SESSION + 4, struct.pack("<I", STUB_SEND))


def attach_observers(e):
    e.hook_reply()        # 0x400081AC -> e.tx ("REPLY:...")
    e.hook_send_file()    # 0x4002B49C -> e.tx
    # capture the DA's own log stream at the uart-flush helper 0x4000792C
    # (every log line passes through it as a NUL-terminated C string in r0)
    e.da_log = []
    def lg(uc, a, s, ud):
        p = uc.reg_read(UC_ARM_REG_R0)
        try:
            line = bytes(uc.mem_read(p, 0x200)).split(b"\0")[0]
            if len(line) >= 4:
                e.da_log.append(line.decode("ascii", "replace"))
        except Exception:
            pass
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
    e.uc.hook_add(UC_HOOK_CODE, lg, begin=0x4000792C, end=0x4000792C)


def da_log_lines(e, keep=("Erase", "Security deny", "Download", "checksum",
                          "deny", "PROGRESS", "hash", "policy", "denied",
                          "seccfg", "write")):
    return [ln[:110] for ln in e.da_log
            if any(k.lower() in ln.lower() for k in keep)][-14:]


def build_emu(status):
    """fresh emu; boot registrar; topology; storage stubs; session; auth.
    status 5 = via the REAL CMD:WRITE-EFUSE forge; status 1 = the value the
    signed-policy verifier itself writes (legitimate session, pre-forge)."""
    e = make_emu()
    e.call(REG_BOOT, [])
    model, log, txlog = FlashModel(), [], []
    seed_storage_topology(e)
    install_storage(e, model, log)
    install_session(e, txlog)
    attach_observers(e)
    if status == 5:
        rc, hh = forge(e, options=[("0x40054C88", "5")])
        e.uc.hook_del(hh)
        e.call(REG_POLICY, [])
        heap_fresh_tail(e)
        forge_rc = rc
    else:
        e.uc.mem_write(AUTH, struct.pack("<I", status))
        e.call(REG_POLICY, [])
        forge_rc = None
    return e, model, log, txlog, forge_rc


def run_cmd(e, name, args, queue_items):
    QUEUE[0][:] = queue_items
    e.uc.mem_write(XMLPATH, cmd_xml(name, args))
    n = len(e.tx)
    rc = e.call(HANDLERS[name], [SESSION, XMLPATH])
    return rc, e.tx[n:]


def fmt_log(log, limit=14):
    out = []
    for ent in log[:limit]:
        s = (f"    slot[{ent['slot']:>2}] off=0x{ent['off']:010X} buf=0x{ent['buf']:08X} "
             f"len=0x{ent['len']:X} rec={ent.get('rec_name', '-')}")
        if "erase_start" in ent:
            s += f"  ERASE start=0x{ent['erase_start']:X} len=0x{ent['erase_len']:X}"
        if "data32" in ent:
            s += "  data[:32]=" + ent["data32"]
        if "err" in ent:
            s += "  ERR:" + ent["err"]
        out.append(s)
    if len(log) > limit:
        out.append(f"    ... {len(log) - limit} more ops")
    return out


def hx(b):
    return b.hex()


# ------------------------------------------------------------------- modes
def mode_calib():
    print("=" * 100)
    print("MODE calib — ops ABI + slot direction, proven by direct calls")
    e = make_emu(); e.call(REG_BOOT, [])
    model, log = FlashModel(), []
    seed_storage_topology(e)
    install_storage(e, model, log)
    BUF, SINK = 0x40471000, 0x40472000
    pat = bytes(range(0x40))
    e.uc.mem_write(BUF, pat)

    print("\n[1] direct ops[1] WRITE: ops1(0xA00100,0, buf, junk, {0x40,0,rec})")
    n0 = len(log)
    e.uc.mem_write(0x40400000, struct.pack("<II", 0x40, 0))      # stack{len,x}
    e.uc.mem_write(0x40400008, struct.pack("<I", GPT_BUF))       # record
    rc = e.call(STUB_S1, [0x0A00100, 0, BUF, 0])
    print(f"    rc={rc}; ops log: {fmt_log(log[n0:]) or '(none — the stub itself was the target)'}")
    got = model.read(SECCFG_START + 0x100, 0x40)
    print(f"    model@0xA00100 now: {got[:16].hex()} ... pattern landed: {got == pat}")

    print("\n[2] direct ops[0] READ: ops0(0xA00100,0, sink, junk, {0x40,0,rec})")
    e.uc.mem_write(SINK, b"\x00" * 0x40)
    e.uc.mem_write(0x40400000, struct.pack("<II", 0x40, 0))
    e.uc.mem_write(0x40400008, struct.pack("<I", GPT_BUF))
    rc = e.call(STUB_S0, [0x0A00100, 0, SINK, 0])
    back = bytes(e.uc.mem_read(SINK, 0x40))
    print(f"    rc={rc}; sink == written pattern: {back == pat} ({back[:8].hex()})")

    print("\n[3] wrapper cross-check: WRAP_WRITE(name='seccfg', off=0x180, stack{buf,?,0x40,0})")
    n0 = len(log)
    e.uc.mem_write(0x4046F000, b"seccfg\x00")
    e.uc.mem_write(0x40400000, struct.pack("<IIII", BUF, 0, 0x40, 0))
    rc = e.call(WRAP_WRITE, [0x4046F000, 0, 0x180, 0])
    got2 = model.read(SECCFG_START + 0x180, 0x40)
    print(f"    rc={rc if not isinstance(rc,int) else hex(rc & 0xFFFFFFFF)}; "
          f"model@0xA00180 == pattern: {got2 == pat}")
    for line in fmt_log(log[n0:], 4):
        print(line)

    print("""
VERDICT (calib): ops[0] serves READS out of the storage model, ops[1] commits
WRITES into it; the ABI is (off64, buf, junk, stack{len, x, record}) — a pure
geometry+buffer interface with NO session/auth/policy parameter.  Any gate
must therefore live ABOVE this boundary (the handlers' policy-flag checks) or
BELOW it (the physical UFS/efuse-adjacent protections, which the DA never
consults on this path).""")
    del e
    return 0


PROBES = (
    ("WRITE-PARTITION(program)", "CMD:WRITE-PARTITION",
     "<partition>seccfg</partition><source_file>p</source_file><pre_erase>NO</pre_erase>",
     ["OK", "OK@EXISTS", "OK", "OK@0x200", "OK", b"\x5A" * 0x200, "OK"]),
    ("WRITE-PARTITION(erase)", "CMD:WRITE-PARTITION",
     "<partition>seccfg</partition><source_file>p</source_file><pre_erase>YES</pre_erase>",
     ["OK", "OK@EXISTS", "OK", "OK@0x200", "OK", b"\x5A" * 0x200, "OK"]),
    ("WRITE-FLASH", "CMD:WRITE-FLASH",
     "<partition>UFS-LUA0</partition><source_file>p</source_file><offset>0xA00000</offset>",
     ["OK", "OK@0x200", "OK", "OK@0x200", "OK", b"\x5A" * 0x200, "OK"]),
    ("READ-PARTITION", "CMD:READ-PARTITION",
     "<partition>seccfg</partition><target_file>t</target_file>",
     ["OK", "OK@0x200", "OK"]),
    ("READ-FLASH", "CMD:READ-FLASH",
     "<partition>UFS-LUA0</partition><target_file>t</target_file>"
     "<offset>0xA00000</offset><length>0x200</length>",
     ["OK", "OK@0x200", "OK"]),
)


def mode_probe():
    print("=" * 100)
    print("MODE probe — handler matrix, pre-forge (status 1) vs post-forge (status 5)")
    for status in (1, 5):
        for label, cmd, args, q in PROBES:
            e, model, log, txlog, forge_rc = build_emu(status)
            # pre-seed the model so reads have content to return
            model.write(SECCFG_START, b"\xCD" * 0x400)
            pre_w, pre_e = len(model.writes), len(model.erases)
            rc, out = run_cmd(e, cmd, args, q)
            deny = sorted({m.decode() for t in out for m in DENY_MARKERS if m in t})
            rcx = rc if not isinstance(rc, int) else hex(rc & 0xFFFFFFFF)
            print(f"\n--- status={status} {label} [{cmd}] ---")
            print(f"  forge_rc={forge_rc}  handler rc={rcx}")
            print(f"  deny markers: {deny or 'NONE'}")
            print(f"  storage ops ({len(log)}):")
            for line in fmt_log(log):
                print(line)
            print(f"  model writes: {[(hex(a), hex(l)) for a, l in model.writes[pre_w:]][:8]}")
            print(f"  model erases: {[(hex(a), hex(l)) for a, l in model.erases[pre_e:]][:8]}")
            print("  DA log:")
            for line in da_log_lines(e):
                print("    " + line)
            del e
    print("""
VERDICT (probe): the discriminating run is CMD:WRITE-FLASH (target
UFS-LUA0, offset = the seccfg byte offset):
  * status 1 (pre-forge): the handler exits at "Security deny" (the
    three-flag check struct[3]/[2]/[1] via the default policy entry,
    img_auth_required=1 for non-table names) BEFORE any write-class storage
    op — only the benign sec_get_seccfg pre-reads (3 x 0x3000 at the target,
    the DA's seccfg loader probing the partition head) run.
  * status 5 (post-forge): no deny; the real erase dispatcher (ops[8]) fires
    with the target range and the model is actually erased; the handler
    continues to PROGRESS-REPORT + DOWNLOAD-FILE announce.  The emulated run
    then stops at the DA's hardware checksum engine ("initial_chksum_info:
    prepare for checksum" -> fatal spin) — the checksum MMIO and the RTOS
    scheduler are not modeled; on silicon these are transparent.
  * both statuses still run the DA's seccfg loader (sec_get_seccfg, 3x) as
    part of the policy flag getter; its result only feeds logs — the deny
    decision is the static policy-table byte, which the forge zeroes.
WRITE-PARTITION checks only dl_forbidden (0 for every stock entry), so its
erase path reaches the storage layer pre-forge as well — the forge's marginal
effect is the WRITE-FLASH-class deny and keeping the write family registered
at status {3,4}.  READ-* has no policy check at all.
""")
    return 0


def seccfg_v4_record(lock_state=3, dm_verity=0, sboot=0):
    """SecCfgV4 record per mtkclient Library/Hardware/seccfg.py: magic MMMM,
    ver 4, size 0x3C, lock_state@+0xC, dm_verity@+0x10, sboot@+0x14, EEEE@+0x18,
    digest@+0x1C (0x20 B).  The 2710 DA2's own sec_get_seccfg cluster
    (0x40039FB8; MMMM movw/movt pair at 0x4003505C; HW-scrambled digest via
    0x40039FD0/HACC) parses this format — but in the emulated write flows it
    acts as instrumentation only and the driver boundary accepts the record
    verbatim (see the mode output)."""
    hdr = struct.pack("<IIIIIIII", 0x4D4D4D4D, 4, 0x3C, lock_state,
                      dm_verity, sboot, 0x45454545, 0)
    return hdr + b"\x11" * 0x20


def mode_seccfg():
    print("=" * 100)
    print("MODE seccfg — forged session writes a lock_state=3 V4 record (emulator-only)")
    # step 0: pre-forge baseline (status 1): what does the same command do?
    e0, model0, log0, txlog0, _ = build_emu(1)
    rc0, out0 = run_cmd(e0, "CMD:WRITE-PARTITION",
                        "<partition>seccfg</partition><source_file>p</source_file>"
                        "<pre_erase>YES</pre_erase>",
                        ["OK", "OK@EXISTS", "OK", "OK@0x200", "OK", b"\xAA" * 0x200, "OK"])
    rc0x = rc0 if not isinstance(rc0, int) else hex(rc0 & 0xFFFFFFFF)
    deny0 = sorted({m.decode() for t in out0 for m in DENY_MARKERS if m in t})
    print(f"  [0] baseline status=1 (pre-forge): rc={rc0x} deny={deny0 or 'NONE'} "
          f"erases={[(hex(a), hex(l)) for a, l in model0.erases]} "
          f"writes={[(hex(a), hex(l)) for a, l in model0.writes]}")
    del e0

    e, model, log, txlog, forge_rc = build_emu(5)
    before = model.snapshot(SECCFG_START, 0x80)
    rec = (seccfg_v4_record(lock_state=3) + seccfg_v4_record(lock_state=3))
    payload = rec + b"\x00" * (0x200 - len(rec))

    # step 1: the REAL handler (WRITE-PARTITION, pre_erase=YES -> erase+program)
    rc, out = run_cmd(e, "CMD:WRITE-PARTITION",
                      "<partition>seccfg</partition><source_file>p</source_file>"
                      "<pre_erase>YES</pre_erase>",
                      ["OK", "OK@EXISTS", "OK", "OK@0x200", "OK", payload, "OK"])
    rcx = rc if not isinstance(rc, int) else hex(rc & 0xFFFFFFFF)
    deny = sorted({m.decode() for t in out for m in DENY_MARKERS if m in t})
    print(f"  [1] real CMD:WRITE-PARTITION(seccfg, pre_erase=YES): rc={rcx} deny={deny or 'NONE'}")
    for line in fmt_log(log):
        print(line)
    print(f"  model writes: {[(hex(a), hex(l)) for a, l in model.writes][:8]}")
    print(f"  model erases: {[(hex(a), hex(l)) for a, l in model.erases][:8]}")

    # step 2: driver-boundary write of the V4 record (the data path proof at
    # the narrowest boundary, independent of the host-side SM pump)
    after_handler = model.snapshot(SECCFG_START, 0x80)
    print(f"  seccfg region before      : {before[:32].hex()}")
    print(f"  seccfg region after handler: {after_handler[:32].hex()}")

    if not any(a == SECCFG_START for a, l in model.writes):
        print("  [2] handler data phase did not pump in emu (host-SM not fully "
              "modelled) — proving the data path at the ops boundary instead:")
        n0 = len(log)
        e.uc.mem_write(0x40471000, payload)
        e.uc.mem_write(0x40400000, struct.pack("<II", 0x200, 0))
        e.uc.mem_write(0x40400008, struct.pack("<I", GPT_BUF))
        rc2 = e.call(STUB_S1, [SECCFG_START & 0xFFFFFFFF, SECCFG_START >> 32,
                               0x40471000, 0])
        print(f"      ops[1] write rc={rc2}")
        for line in fmt_log(log[n0:], 4):
            print(line)
    landed = model.snapshot(SECCFG_START, 0x200)
    print(f"  payload landed VERBATIM at seccfg start: {landed[:len(payload)] == payload}")
    print(f"  first 0x20 bytes now: {landed[:0x20].hex()}")
    print(f"  (record layout: magic={hex(struct.unpack_from('<I', landed, 0)[0])} "
          f"ver={struct.unpack_from('<I', landed, 4)[0]} "
          f"lock_state={struct.unpack_from('<I', landed, 0xC)[0]})")
    print(f"  tx: {[t[2][:48] if len(t) > 2 else t for t in txlog][:10]}")
    print("""
INTERPRETATION (corrected after the sec_get_seccfg discovery):
  * the 2710 DA2 DOES carry a seccfg anti-clone cluster: sec_get_seccfg core
    0x40039FB8 (MMMM record check, MMMM movw/movt pair at 0x4003505C, digest
    via the HW scrambler 0x40039FD0/HACC) — it RUNS inside the write flows
    (3 queries per WRITE-* command, via the policy flag getter 0x4002CFFC's
    lock-state interlude 0x40033DE4; visible in the DA's own log as
    "[SEC_CFG] sec_get_seccfg ret=c002002f" + "[SEC] get lock state fail").
  * in the flag getter the query result is INSTRUMENTATION only: every path
    (lock state fail / 1 / 2 / other) converges on returning the STATIC policy
    table byte (entry+0x16).  The seccfg state does not gate the flags.
  * the DA's own log for the status-5 run shows the forge's effect verbatim:
    "[SEC_POLICY] in oplus_single_mode", then the policy dump with
    hash_binding = 0 / img_auth_required = 0 / dl_forbidden = 0, then
    "get verified image name failed but could use original name." (fail-open),
    then the download proceeds.  The sec_get_seccfg FAILURE (0xC002002F on
    blank model content) did NOT block erase or download.
  * the driver boundary (ops[1]) accepted the SecCfgV4 record (magic MMMM,
    ver 4, lock_state=3) VERBATIM — no content or credential check exists at
    the boundary; the DA never re-signs or rejects the uploaded record in the
    emulated path.
  * UNRESOLVED in emu (HACC + RTOS scheduler not modeled): whether a
    SUCCEEDING sec_get_seccfg (valid record on silicon) makes the DA
    regenerate/ignore uploaded seccfg bytes post-write — the 200EX01
    session-proven "SEC regeneration" behavior class.  And on silicon the
    record only MATTERS if LK accepts it at boot: SHA-256 over the 0x1C-byte
    header + HACC-AES scramble (fixed seeds) + the RPMB boot-info mirror
    (double_check_lock_state re-locks and powers off on mismatch).  Those are
    boot-time gates OUTSIDE the DA session and unaffected by the forge.""")
    del e
    return 0


MODES = {"calib": mode_calib, "probe": mode_probe, "seccfg": mode_seccfg}

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=[*MODES, "all"], nargs="?", default="all")
    a = ap.parse_args()
    if a.mode == "all":
        for f in MODES.values():
            f()
        sys.exit(0)
    sys.exit(MODES[a.mode]())
