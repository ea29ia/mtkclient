#!/usr/bin/env python3
"""Plan E: preloader handshake token probe (zero risk, read-only dialog).

Evidence: docs/notes/reverse/re-oplus-preloader-handshake.md (dispatcher fully
reversed). In the preloader VCOM window BEFORE the usbdl/bldr_handshake, the
preloader runs `oplus_usb_handshake`:
  - sync byte 0xA0 (helper @0x2257EC, timeouts 8000/10000 ms),
  - then an ASCII token, matched with strlen+strncmp,
  - tokens: FASTBOOT -> response "TOOBTSAF", 0x2F4264=0x63 (NOT gated);
            AT+NBOOT -> response "AT+OK", 0x2F4264=0, 0x2F4260=5 (NOT gated);
            METAMETA/FACTFACT/ADVEMETA/FACTORYM are gated (forbidden bit set
            on this unit) — expect "is forbidden" / no response.
  - on handshake success main() proceeds to bldr_handshake (MTK download
    protocol); on failure preloader reboots after 5000 ms.

Sync direction (who sends 0xA0 first) is NOT decided statically — this probe
therefore tries both orders and logs everything. Worst case: 5 s and a reboot.

Run from the repo root with the venv active:
  python docs/notes/plan_e_handshake_probe.py            # one probe cycle
  python docs/notes/plan_e_handshake_probe.py --loop     # re-arm loop
  python docs/notes/plan_e_handshake_probe.py --token AT+NBOOT --only
Env:
  PLANE_VID=0x22d9 PLANE_PID=0x0006
  PLANE_ORDER=a0_first|token_first|both   (default both)
  PLANE_WAIT=1   wait for a FRESH 22d9:0006 enumeration first (default 1)
"""
import os
import sys
import time
import argparse

try:
    import usb.core
    import usb.util
except ImportError:
    print("[-] pyusb missing (source .venv/bin/activate)")
    sys.exit(1)

VID = int(os.environ.get("PLANE_VID", "0x22d9"), 16)
PID = int(os.environ.get("PLANE_PID", "0x0006"), 16)

# (token, expected response, gated?)
TOKENS = [
    ("FASTBOOT", "TOOBTSAF", False),
    ("AT+NBOOT", "AT+OK", False),
    ("METAMETA", "ATEM0001/2 or forbidden", True),  # control probes
    ("FACTFACT", "TCAFTCAF or forbidden", True),
]

# Meaningful hits only (a bare 'U'/READY and reverb garbage don't count).
MAGICS = (b"TOOBTSAF", b"AT+OK", b"forbidden", b"ATEM", b"TCAFTCAF",
          b"DISCONNECT")
STATE_FILE = "/tmp/.plan_e_state"  # round-robin progress across cycles


def meaningful(resp):
    return resp and any(m in resp for m in MAGICS)

# Send variants for the sync byte: the dispatcher reads sync + token with
# separate reads (strlen/strncmp on a second buffer) — framing is NOT proven.
# 'combo'  : one bulk-OUT write b"\xa0"+token
# 'split'  : 0xA0 write, pause, token write
# 'raw'    : token only
# 'sync1'  : single byte 0xA0, wait for any non-READY reply, then token
SEND_VARIANTS = ["combo", "split", "raw", "sync1"]

LOG = []


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    LOG.append(line)


def find_device():
    return usb.core.find(idVendor=VID, idProduct=PID)


def wait_fresh(timeout_s=180):
    """Wait for the device to be absent, then appear (fresh preloader entry)."""
    log("waiting for the device to vanish (power off)...")
    t0 = time.time()
    while find_device() is not None:
        if time.time() - t0 > timeout_s:
            log("device never disappeared; aborting wait")
            return False
        time.sleep(0.3)
    log("device absent - now plug/power it in preloader combo (Vol+ + Vol-)")
    t0 = time.time()
    while find_device() is None:
        if time.time() - t0 > timeout_s:
            log("no fresh preloader in time")
            return False
        time.sleep(0.2)
    time.sleep(1.0)  # let the kernel settle
    log("fresh 22d9:0006 detected")
    return True


def open_endpoints(dev):
    """Return (ep_out, ep_in, intf) for the VCOM bulk interface, or None."""
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except Exception:
        pass
    try:
        dev.set_configuration()
    except Exception as e:
        log(f"set_configuration: {e!r}")
    for cfg in dev:
        for intf in cfg:
            eps_out = [e for e in intf if usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK]
            eps_in = [e for e in intf if usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK]
            if eps_out and eps_in:
                return eps_out[0], eps_in[0], intf
    return None


GONE = {"flag": False}  # set when the port dies (EIO) — device rebooted
NOISE = b"READY"  # OPLUS preloader CDC bulk-IN spam (proven live 2026-10-24)


def strip_noise(data):
    """Remove READY spam; return (clean_bytes, noise_bytes_count)."""
    clean = data.replace(NOISE, b"")
    return clean, len(data) - len(clean)


def read_any(ep_in, timeout_ms):
    """Read whatever arrives; return bytes or b'' on timeout/port error."""
    try:
        return bytes(ep_in.read(ep_in.wMaxPacketSize, timeout=timeout_ms))
    except usb.core.USBError as e:
        if e.errno in (110, 7, 60, 10060):  # timeout family
            return b""
        if e.errno == 5:  # EIO — preloader rebooted / CDC spam hazard.
            GONE["flag"] = True  # do NOT clear_halt (do-not-repeat list)
            return b""
        raise


def drain(ep_in, total_ms=3000, ignore_noise=False):
    """Collect everything the device sends for total_ms (reactive only).

    With ignore_noise, READY spam is neither counted as data nor as an
    end-of-burst marker — keep reading until the full window expires
    (the real token response may be buried in/after READY spam).
    """
    out = b""
    noise = 0
    idle_after_data = 0
    deadline = time.time() + total_ms / 1000
    while time.time() < deadline:
        chunk = read_any(ep_in, 300)
        if chunk:
            idle_after_data = 0
            if ignore_noise:
                c, n = strip_noise(out + chunk)
                out, noise = c, noise + n
                # restart window a bit when only spam arrives? no — honor it
                if not out and n:
                    # pure spam so far — keep listening until deadline
                    pass
            else:
                out += chunk
        elif GONE["flag"]:
            log("[i] port died (EIO) — preloader rebooted, stopping read")
            break
        else:
            if out and not ignore_noise:
                idle_after_data += 300
                if idle_after_data >= 700:  # end of burst
                    break
    if ignore_noise and noise:
        log(f"[*] filtered {noise} B of READY spam")
    return out


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else f"\\x{c:02x}" for c in b)


def probe(token, mode, eps, dev_addr):
    """Send variants: combo / split / raw / sync1 (see SEND_VARIANTS)."""
    ep_out, ep_in, _ = eps
    t0 = time.time()
    log(f"=== probe token={token!r} mode={mode} ===")
    tok = token.encode()
    try:
        if mode == "combo":
            payload = b"\xa0" + tok
            ep_out.write(payload, timeout=2000)
            log(f"sent {len(payload)} B: {printable(payload)}")
        elif mode == "split":
            ep_out.write(b"\xa0", timeout=2000)
            log("sent sync 0xA0")
            time.sleep(0.15)
            ep_out.write(tok, timeout=2000)
            log(f"sent token {len(tok)} B: {token}")
        elif mode == "sync1":
            ep_out.write(b"\xa0", timeout=2000)
            log("sent single sync 0xA0 — listening for sync ack (0x55?)...")
            ack = drain(ep_in, 2500, ignore_noise=True)
            if ack:
                log(f"[i] sync ack after 0xA0 ({time.time()-t0:.1f}s): {printable(ack)}")
            ep_out.write(tok, timeout=2000)
            log(f"sent token {len(tok)} B: {token}")
        else:  # raw
            ep_out.write(tok, timeout=2000)
            log(f"sent {len(tok)} B: {token}")
    except Exception as e:
        log(f"[-] write failed: {e!r}")
        return None
    resp = drain(ep_in, 11000, ignore_noise=True)  # full 8/10 s timeout window
    if resp:
        log(f"[+] RESPONSE {len(resp)} B ({time.time()-t0:.1f}s after write): {printable(resp)}")
        for expect, _, _ in TOKENS:
            if expect.encode() in resp:
                log(f"[+] contains {expect!r}")
        for magic in MAGICS:
            if magic in resp:
                log(f"[!!!] MATCH {magic!r} — handshake hit")
    else:
        log(f"[-] no meaningful response in 11 s (EIO={GONE['flag']}, {time.time()-t0:.1f}s total)")
    return resp


def load_state():
    try:
        return int(open(STATE_FILE).read().strip())
    except Exception:
        return 0


def save_state(i):
    open(STATE_FILE, "w").write(str(i))


def build_pairs(tokens, modes):
    # priority: FASTBOOT variants first, then AT+NBOOT, then controls
    prio = {"FASTBOOT": 0, "AT+NBOOT": 1}
    pairs = []
    for tok in sorted(tokens, key=lambda t: prio.get(t, 9)):
        for m in modes:
            pairs.append((tok, m))
    return pairs


def watch_reenumerate(seconds=15):
    """After a token hit, watch what the device re-enumerates as."""
    import usb.core as _u
    log("[*] watching re-enumeration for 15 s...")
    seen = set()
    t0 = time.time()
    while time.time() - t0 < seconds:
        for d in _u.find(find_all=True):
            key = (d.idVendor, d.idProduct, d.bus, d.address)
            if key not in seen:
                seen.add(key)
                vid, pid = d.idVendor, d.idProduct
                mode = ("FASTBOOT?" if vid == 0x18D1 else
                        "OPLUS preloader/VCOM" if (vid, pid) == (0x22D9, 0x0006) else
                        "OPLUS normal" if (vid, pid) == (0x22D9, 0x2046) else
                        "other")
                log(f"[USB] {vid:04x}:{pid:04x} bus={d.bus} addr={d.address} -> {mode}")
        time.sleep(0.2)
    if not seen:
        log("[USB] device never came back in 15 s")


def one_cycle(only_token=None, order_mode=None):
    if os.environ.get("PLANE_WAIT", "1") == "1" and not wait_fresh():
        return False
    dev = find_device()
    if dev is None:
        log("[-] no device")
        return False
    log(f"device: {dev.idVendor:04x}:{dev.idProduct:04x} bus={dev.bus} addr={dev.address}")
    eps = open_endpoints(dev)
    if not eps:
        log("[-] no bulk endpoints found — dumping descriptors")
        print(dev)
        return False
    # passive listen first: maybe the preloader sends 0xA0 to us (sync direction)
    log("[*] passive listen 3 s (does the preloader send 0xA0 first?)")
    pre = drain(eps[1], 3000, ignore_noise=True)
    if pre:
        log(f"[!] unsolicited from device {len(pre)} B: {printable(pre)}")
        if b"\xa0" in pre:
            log("[!] device sent sync 0xA0 — reply with tokens next!")
    if GONE["flag"]:
        log("[i] device rebooted during passive listen — cycle ends, re-arm")
        return False
    tokens = [only_token] if only_token else [t for t, _, _ in TOKENS]
    modes = list(order_mode) if order_mode else list(SEND_VARIANTS)
    pairs = build_pairs(tokens, modes)
    idx = load_state() % len(pairs)
    tok, mode = pairs[idx]
    log(f"[i] round-robin step {idx + 1}/{len(pairs)}: {tok}/{mode} "
        f"(state file {STATE_FILE}; delete to restart)")
    GONE["flag"] = False
    r = probe(tok, mode, eps, dev.address)
    hit = meaningful(r)
    if hit:
        save_state(0)
        # Token accepted. The preloader consumed our handshake and now sits
        # in bldr_handshake (MTK download protocol) on the SAME VCOM session
        # with boot_mode=0x63 (FASTBOOT) alive in SRAM (0x2F4264). Release
        # the USB and let the DA session attach on this very instance —
        # its shutdown(FASTBOOT) path is the downstream consumer of 0x63.
        try:
            usb.util.dispose_resources(dev)
        except Exception:
            pass
        log("[+] token hit on LIVE preloader instance. NOW, within ~10 s, run:")
        log("    ./run_reboot_fastboot.sh     (it connects to THIS VCOM)")
        log("[*] holding the port open 60 s to keep the window visible...")
        time.sleep(60)
        log("[i] exiting — rerun the probe for the next hit (no auto-retry "
            "on a hit: the next cycle would race the live window)")
        return True
    else:
        save_state(idx + 1)
    log("=== CYCLE SUMMARY ===")
    log(f"  {tok}/{mode}: "
        + (f"RESP {printable(r)}" if r else "no response")
        + ("  <<< MATCH" if hit else ""))
    if hit:
        log("[+] handshake response confirmed — STOP and analyze before writes")
    elif GONE["flag"]:
        log("[i] device rebooted ~5 s after write — consistent with the "
            "failed-handshake reboot path (dispatcher DID see our data)")
    fn = f"/tmp/plan_e_probe_{time.strftime('%H%M%S')}.log"
    open(fn, "w").write("\n".join(LOG) + "\n")
    log(f"log saved: {fn}")
    return hit


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="keep re-arming and probing")
    ap.add_argument("--token", default=None, help="probe a single token")
    ap.add_argument("--only", action="store_true", help="with --token: no control probes")
    ap.add_argument("--order", choices=SEND_VARIANTS, action="append",
                    help="force send mode(s), repeatable (default: all)"),
    ap.add_argument("--no-wait", action="store_true", help="device already in VCOM")
    a = ap.parse_args()
    if a.no_wait:
        os.environ["PLANE_WAIT"] = "0"
    if a.loop:
        while True:
            try:
                if one_cycle(a.token, a.order):
                    log("[+] RESULT — inspect log before further sessions")
                    break
            except KeyboardInterrupt:
                break
            except Exception as e:
                log(f"[!] cycle error: {e!r}")
            log("cycle done; device rebooting — next cycle re-arms with the "
                "next variant")
        log("[i] all variants tried — Plan E exhausted; proceed with step1/Plan A")
    else:
        ok = one_cycle(a.token, a.order)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
