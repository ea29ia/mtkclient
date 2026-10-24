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

TOKENS = [
    # (token, expected response, gated?)
    ("FASTBOOT", "TOOBTSAF", False),
    ("AT+NBOOT", "AT+OK", False),
    ("METAMETA", "?", True),      # expect forbidden / nothing — control probes
    ("FACTFACT", "?", True),
]

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


def read_any(ep_in, timeout_ms):
    """Read whatever arrives; return bytes or b'' on timeout."""
    try:
        return bytes(ep_in.read(ep_in.wMaxPacketSize, timeout=timeout_ms))
    except usb.core.USBError as e:
        if e.errno in (110, 7, 60, 10060):  # timeout family
            return b""
        raise


def drain(ep_in, total_ms=3000):
    """Collect everything the device sends for total_ms (reactive only)."""
    out = b""
    deadline = time.time() + total_ms / 1000
    while time.time() < deadline:
        chunk = read_any(ep_in, 300)
        if chunk:
            out += chunk
        else:
            if out:  # one idle gap after data = end of burst
                break
    return out


def printable(b):
    return "".join(chr(c) if 32 <= c < 127 else f"\\x{c:02x}" for c in b)


def probe(token, order, eps, dev_addr):
    ep_out, ep_in, _ = eps
    log(f"=== probe token={token!r} order={order} ===")
    # fresh device each probe: device reboots after failed handshake
    try:
        if order == "a0_first":
            payload = b"\xa0" + token.encode()
        else:
            payload = token.encode() + b"\xa0"
        ep_out.write(payload, timeout=2000)
        log(f"sent {len(payload)} B: {printable(payload)}")
    except Exception as e:
        log(f"[-] write failed: {e!r}")
        return None
    resp = drain(ep_in, 11000)  # preloader follow-up timeouts are 8/10 s
    if resp:
        log(f"[+] RESPONSE {len(resp)} B: {printable(resp)}")
        for expect, _, gated in [(t, e, g) for t, e, g in TOKENS]:
            if expect.encode() in resp:
                log(f"[+] contains {expect!r} (gated={gated})")
    else:
        log("[-] no response in 11 s (device will reboot in ~5 s)")
    return resp


def one_cycle(only_token=None, order_mode="both"):
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
    log("[*] passive listen 12 s (does the preloader send 0xA0 first?)")
    pre = drain(eps[1], 12000)
    if pre:
        log(f"[!] unsolicited from device {len(pre)} B: {printable(pre)}")
        if b"\xa0" in pre:
            log("[!] device sent sync 0xA0 — reply with tokens next!")
    tokens = [only_token] if only_token else [t for t, _, _ in TOKENS]
    results = {}
    for tok in tokens:
        orders = ["a0_first", "token_first"] if order_mode == "both" else [order_mode]
        for od in orders:
            r = probe(tok, od, eps, dev.address)
            results[f"{tok}/{od}"] = r
            if r:
                break  # got a response for this token — skip other order
    log("=== CYCLE SUMMARY ===")
    for k, v in results.items():
        log(f"  {k}: {'RESP ' + printable(v) if v else 'no response'}")
    fn = f"/tmp/plan_e_probe_{time.strftime('%H%M%S')}.log"
    open(fn, "w").write("\n".join(LOG) + "\n")
    log(f"log saved: {fn}")
    return any(v for v in results.values())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="keep re-arming and probing")
    ap.add_argument("--token", default=None, help="probe a single token")
    ap.add_argument("--only", action="store_true", help="with --token: no control probes")
    ap.add_argument("--order", choices=["a0_first", "token_first", "both"], default="both")
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
            log("cycle done; device rebooting — next cycle re-arms")
    else:
        ok = one_cycle(a.token, a.order)
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
