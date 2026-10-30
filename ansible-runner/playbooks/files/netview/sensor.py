"""Sentry Lens: what the sensor says about the traffic - each flow's
application (nDPI: "TLS.YouTube", "DNS.Google"...), its category, the server
name asked for (TLS SNI, HTTP Host, DNS query), the client's fingerprint.

The sensor (sensor/, sensor playbook) captures mirrored traffic - each
hypervisor's uplink copied to it over GRE, a switch's mirror port, whatever the
site has - and posts what it measured every half minute. It authenticates
with SENSOR_KEY (made by the playbook, given to both). The flow totals stay
flowd's (the firewall's NetFlow, softflowd): these rows add the application.

  netview.app_flows   one row per flow the sensor finished (or every 60 s of a long one)
"""
import hmac
import ipaddress
import os
import time

from fastapi import APIRouter, HTTPException, Request

import assets

router = APIRouter()
SENSOR_KEY = os.environ.get("SENSOR_KEY", "")
KEEP_DAYS = int(os.environ.get("APP_FLOWS_DAYS", "14"))
DDL = [
    f"""CREATE TABLE IF NOT EXISTS netview.app_flows (
        t DateTime, first DateTime, sensor LowCardinality(String), iface LowCardinality(String),
        src String, dst String, sport UInt16, dport UInt16, proto UInt8, vlan UInt16, src_mac String, dst_mac String,
        bytes UInt64, packets UInt64, up_bytes UInt64, down_bytes UInt64,
        app LowCardinality(String), category LowCardinality(String), guessed UInt8,
        server_name String, client_fp String, user_agent String
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (t, src) TTL t + INTERVAL {KEEP_DAYS} DAY""",
]
_ready = [False]
SEEN = {}  # sensor name -> {iface: {"t": last post, "flows": in it, "drops": the capture's}}


def q(sql, **params):
    if not _ready[0]:
        assets.ready()
        for d in DDL:
            assets.checks.ch(d)
        _ready[0] = True
    return assets.checks.query(sql, **params)


def _sensor(request):
    got = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not SENSOR_KEY or not got or not hmac.compare_digest(got, SENSOR_KEY):
        raise HTTPException(401, "unknown sensor key")


def _s(v, n):
    return str(v or "")[:n]


@router.post("/api/sensor/flows")
async def sensor_flows(request: Request):
    """{sensor, iface, drops, flows: [{first_ms, last_ms, src, dst, sport, dport, proto, vlan, src_mac, dst_mac,
    bytes, packets, up_bytes, down_bytes, app, category, guessed, server_name, client_fp, user_agent}]}."""
    _sensor(request)
    b = await request.json()
    sensor, iface = _s(b.get("sensor"), 60) or "sensor", _s(b.get("iface"), 40)
    rows = []
    for f in (b.get("flows") or [])[:50000]:
        try:
            src, dst = str(ipaddress.ip_address(f["src"])), str(ipaddress.ip_address(f["dst"]))
        except (KeyError, ValueError):
            continue
        rows.append({"t": int(f.get("last_ms", 0)) // 1000 or int(time.time()), "first": int(f.get("first_ms", 0)) // 1000 or int(time.time()),
                     "sensor": sensor, "iface": iface, "src": src, "dst": dst, "sport": int(f.get("sport") or 0) & 0xFFFF,
                     "dport": int(f.get("dport") or 0) & 0xFFFF, "proto": int(f.get("proto") or 0) & 0xFF, "vlan": int(f.get("vlan") or 0) & 0xFFFF,
                     "src_mac": _s(f.get("src_mac"), 17).upper(), "dst_mac": _s(f.get("dst_mac"), 17).upper(),
                     "bytes": int(f.get("bytes") or 0), "packets": int(f.get("packets") or 0),
                     "up_bytes": int(f.get("up_bytes") or 0), "down_bytes": int(f.get("down_bytes") or 0),
                     "app": _s(f.get("app"), 80) or "Unknown", "category": _s(f.get("category"), 40), "guessed": 1 if f.get("guessed") else 0,
                     "server_name": _s(f.get("server_name"), 255), "client_fp": _s(f.get("client_fp"), 120), "user_agent": _s(f.get("user_agent"), 300)})
    if rows:
        q("SELECT 1")
        assets.insert("app_flows", rows)
    SEEN.setdefault(sensor, {})[iface] = {"t": time.time(), "flows": len(rows), "drops": int(b.get("drops") or 0)}
    return {"ok": True, "flows": len(rows)}


# ------------------------------------------------------------------ the views
def _hours(h):
    return max(1, min(int(h or 24), 24 * KEEP_DAYS))


@router.get("/api/appflows")
def top(hours: int = 24, host: str = ""):
    """The applications seen (bytes, flows, hosts) - everywhere, or of one host (an address)."""
    hours = _hours(hours)
    where, params = "t > now() - toIntervalHour({h:UInt32})", {"h": hours}
    if host:
        try:
            params["ip"] = str(ipaddress.ip_address(host))
        except ValueError:
            raise HTTPException(400, "host: an address")
        where += " AND (src = {ip:String} OR dst = {ip:String})"
    apps = q(f"""SELECT app, any(category) AS category, sum(bytes) AS bytes, count() AS flows,
        uniqExact(src) AS hosts, max(t) AS last FROM netview.app_flows WHERE {where}
        GROUP BY app ORDER BY bytes DESC LIMIT 200""", **params)
    cats = q(f"""SELECT category, sum(bytes) AS bytes, count() AS flows FROM netview.app_flows WHERE {where}
        GROUP BY category ORDER BY bytes DESC LIMIT 40""", **params)
    names = q(f"""SELECT server_name AS name, any(app) AS app, sum(bytes) AS bytes, count() AS flows FROM netview.app_flows
        WHERE {where} AND server_name != '' GROUP BY server_name ORDER BY bytes DESC LIMIT 100""", **params)
    for a in apps:
        a["last"] = assets._ts(a["last"])
    return {"hours": hours, "host": host, "apps": apps, "categories": cats, "names": names, "sensors": status()}


@router.get("/api/appflows/app")
def app_hosts(app: str, hours: int = 24):
    """One application: who uses it (the hosts on the LAN side) and the servers."""
    hours = _hours(hours)
    rows = q("""SELECT src AS host, sum(bytes) AS bytes, count() AS flows, groupUniqArray(5)(server_name) AS names
        FROM netview.app_flows WHERE t > now() - toIntervalHour({h:UInt32}) AND app = {app:String}
        GROUP BY src ORDER BY bytes DESC LIMIT 100""", h=hours, app=app)
    for r in rows:
        r["name"] = assets.NAMER[0](r["host"])
        r["names"] = [n for n in r["names"] if n]
    return {"app": app, "hours": hours, "hosts": rows}


def status():
    """Each sensor interface: when it last posted (this process's memory), and rows in the last hour."""
    try:
        last = q("""SELECT sensor, iface, max(t) AS t, countIf(t > now() - INTERVAL 1 HOUR) AS hour
            FROM netview.app_flows WHERE t > now() - INTERVAL 1 DAY GROUP BY sensor, iface""")
    except Exception:  # noqa: BLE001 - no table yet
        last = []
    out = {(r["sensor"], r["iface"]): {"sensor": r["sensor"], "iface": r["iface"], "last_flow": assets._ts(r["t"]), "flows_hour": r["hour"]}
           for r in last}
    for s, ifs in SEEN.items():
        for i, v in ifs.items():
            out.setdefault((s, i), {"sensor": s, "iface": i, "last_flow": 0, "flows_hour": 0}).update(
                {"last_post": int(v["t"]), "drops": v["drops"]})
    return sorted(out.values(), key=lambda x: (x["sensor"], x["iface"]))
