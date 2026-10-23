"""netview's live view: the firewall's own counters, sampled while someone is
looking (a browser asked within the last IDLE seconds), nothing stored.

  throughput    every SAMPLE s, the interfaces' byte counters (OPNsense
                Reporting: Traffic API) -> bits/s per interface, the last
                KEEP seconds kept in memory.
  top talkers   every TOP s, the firewall's live per-host rates on the LAN
                interface, with the peers each host is talking to.

Download/upload are from the LAN's side: on an external interface (WAN, VPN)
download is what the firewall receives, on an internal one what it sends.
Uses the same API key as dns.py - its user needs the Reporting: Traffic
privilege (netview_stack.yml gives it).
"""
import collections
import json
import os
import threading
import time

import requests

OPN_URL = os.environ.get("OPN_URL", "").rstrip("/")
OPN_KEY = os.environ.get("OPN_KEY", "")
OPN_SECRET = os.environ.get("OPN_SECRET", "")
# device -> {"label": .., "external": bool}; interfaces not listed aren't shown.
INTERFACES = json.loads(os.environ.get("LIVE_INTERFACES") or "{}")
TOP_IFACE = os.environ.get("LIVE_TOP_IFACE", "lan")  # OPNsense interface key of the LAN
SAMPLE, TOP, KEEP, IDLE = 2, 5, 600, 60

status = {"enabled": bool(OPN_URL and OPN_KEY and INTERFACES), "last_error": "", "top_error": ""}
_wanted = [0.0]
_points = {dev: collections.deque(maxlen=KEEP // SAMPLE) for dev in INTERFACES}  # (t, down, up)
_top = {"t": 0, "hosts": []}
_session = requests.Session()
_session.auth = (OPN_KEY, OPN_SECRET)
_session.verify = False


def wanted():
    _wanted[0] = time.time()


def _active():
    return time.time() - _wanted[0] < IDLE


def _get(path, timeout):
    r = _session.get(OPN_URL + path, timeout=timeout)
    r.raise_for_status()
    return r.json()


def _sample_loop():
    last = {}  # device -> (t, rx, tx)
    while True:
        time.sleep(SAMPLE)
        if not _active():
            last.clear()  # a gap, not one long average, when sampling resumes
            continue
        try:
            ifaces = _get("/api/diagnostics/traffic/interface", 10).get("interfaces", {})
            now = time.time()
            for info in ifaces.values():
                dev = info.get("device")
                if dev not in INTERFACES:
                    continue
                rx, tx = int(info.get("bytes received", 0)), int(info.get("bytes transmitted", 0))
                if dev in last:
                    t0, rx0, tx0 = last[dev]
                    dt = now - t0
                    if dt > 0 and rx >= rx0 and tx >= tx0:  # skip counter resets
                        rin, rout = (rx - rx0) * 8 / dt, (tx - tx0) * 8 / dt
                        down, up = (rin, rout) if INTERFACES[dev].get("external") else (rout, rin)
                        _points[dev].append((int(now), down, up))
                last[dev] = (now, rx, tx)
            status["last_error"] = ""
        except Exception as e:  # the firewall may be busy - try again next tick
            status["last_error"] = f"{type(e).__name__}: {e}"[:300]


def _top_loop():
    while True:
        time.sleep(TOP)
        if not _active():
            continue
        try:
            recs = _get(f"/api/diagnostics/traffic/top/{TOP_IFACE}", 20).get(TOP_IFACE, {}).get("records", [])
            # On the LAN interface "in" is towards the host: its download.
            _top["hosts"] = [{
                "ip": r.get("address", ""), "down": r.get("rate_bits_in", 0), "up": r.get("rate_bits_out", 0),
                "peers": [{"ip": d.get("address", ""), "rate": d.get("rate_bits", 0)}
                          for d in sorted(r.get("details", []), key=lambda d: -d.get("rate_bits", 0))[:10]],
            } for r in recs]
            _top["t"] = int(time.time())
            status["top_error"] = ""
        except Exception as e:
            status["top_error"] = f"{type(e).__name__}: {e}"[:300]


def points(since=0):
    wanted()
    return [{"device": dev, "label": INTERFACES[dev].get("label", dev),
             "external": bool(INTERFACES[dev].get("external")),
             "points": [p for p in _points[dev] if p[0] > since]} for dev in INTERFACES]


def top():
    wanted()
    return _top


def start():
    if status["enabled"]:
        threading.Thread(target=_sample_loop, daemon=True, name="live").start()
        threading.Thread(target=_top_loop, daemon=True, name="live-top").start()
