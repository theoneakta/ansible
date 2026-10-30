"""Sentry Lens sensor: measures the traffic mirrored to it with nDPI
(nfstream) - each flow's application, category, the server name asked for,
the client's fingerprint - and posts the flows to Sentry Lens every half
minute (POST /api/sensor/flows, sensor.py there).

One meter per interface (SENSOR_IFACES): a GRE tunnel from each hypervisor
whose uplink is mirrored to it (mirror playbook), a NIC on a switch's mirror
port... An interface that isn't there yet is waited for.

  SENTRY_URL     where Sentry Lens answers (http://127.0.0.1:8082 on its own host)
  SENSOR_KEY     the key Sentry Lens knows the sensor by
  SENSOR_IFACES  the interfaces to listen on, comma or space separated
  SENSOR_NAME    how it's shown (default: the host's name)
"""
import json
import multiprocessing as mp
import os
import threading
import time
import urllib.request

URL = os.environ.get("SENTRY_URL", "http://127.0.0.1:8082").rstrip("/")
KEY = os.environ.get("SENSOR_KEY", "")
NAME = os.environ.get("SENSOR_NAME") or os.uname().nodename
IFACES = [i for i in os.environ.get("SENSOR_IFACES", "").replace(",", " ").split() if i]
EVERY = 30        # seconds between posts
MOST = 20000      # flows kept while Sentry Lens doesn't answer (per interface)


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def post(iface, flows):
    body = json.dumps({"sensor": NAME, "iface": iface, "flows": flows}).encode()
    req = urllib.request.Request(URL + "/api/sensor/flows", data=body, method="POST",
                                 headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        r.read()


def row(f):
    return {"first_ms": f.bidirectional_first_seen_ms, "last_ms": f.bidirectional_last_seen_ms, "src": f.src_ip, "dst": f.dst_ip,
            "sport": f.src_port, "dport": f.dst_port, "proto": f.protocol, "vlan": f.vlan_id, "src_mac": f.src_mac, "dst_mac": f.dst_mac,
            "bytes": f.bidirectional_bytes, "packets": f.bidirectional_packets, "up_bytes": f.src2dst_bytes, "down_bytes": f.dst2src_bytes,
            "app": f.application_name, "category": f.application_category_name, "guessed": f.application_is_guessed,
            "server_name": f.requested_server_name, "client_fp": f.client_fingerprint, "user_agent": f.user_agent}


def meter(iface):
    """One interface: measure, and post what's finished every EVERY seconds."""
    from nfstream import NFStreamer
    while not os.path.exists(f"/sys/class/net/{iface}"):
        time.sleep(10)
    buf, lock = [], threading.Lock()

    def sender():
        sent, failing = 0, False
        while True:
            time.sleep(EVERY)
            with lock:
                batch = buf[:]
                buf.clear()
            if not batch:
                continue
            try:
                post(iface, batch)
                sent += len(batch)
                if failing:
                    log(f"{iface}: Sentry Lens answers again")
                failing = False
            except Exception as e:  # noqa: BLE001 - kept for the next try (up to MOST)
                if not failing:
                    log(f"{iface}: can't post to Sentry Lens ({e}) - keeping the flows")
                failing = True
                with lock:
                    buf[:0] = batch[-MOST:]
                    del buf[MOST:]

    threading.Thread(target=sender, daemon=True).start()
    log(f"{iface}: listening")
    # Flows end after 2 min idle; a long one is reported every 10 min (nDPI names it from its first packets).
    for f in NFStreamer(source=iface, promiscuous_mode=True, snapshot_length=1536, idle_timeout=120, active_timeout=600,
                        accounting_mode=1, n_dissections=20, statistical_analysis=False, splt_analysis=0, performance_report=0):
        with lock:
            buf.append(row(f))
            if len(buf) > MOST:
                del buf[: len(buf) - MOST]


def main():
    if not KEY or not IFACES:
        raise SystemExit("SENSOR_KEY and SENSOR_IFACES, please")
    log(f"Sentry Lens sensor {NAME} -> {URL}: {', '.join(IFACES)}")
    procs = {}
    while True:  # each interface in its own process (nfstream starts its own), started again if it stops
        for i in IFACES:
            p = procs.get(i)
            if p is None or not p.is_alive():
                if p is not None:
                    log(f"{i}: stopped ({p.exitcode}) - starting again")
                procs[i] = mp.Process(target=meter, args=(i,), name=f"meter-{i}")
                procs[i].start()
        time.sleep(15)


if __name__ == "__main__":
    main()
