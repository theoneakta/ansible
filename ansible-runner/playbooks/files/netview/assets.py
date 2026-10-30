"""Sentry Lens: assets - what the collectors find on the network.

A collector (files/collector, collector.yml) is a small container on any
machine of a network: it sweeps its subnets with nmap (ARP where it can,
ping/TCP probes past a router), records each device's MAC and vendor, its
names (DNS, NetBIOS) and open ports, and posts that here. It only talks out,
with its own key; an admin adds it on the Assets page (the key is shown once,
kept here as a hash) and gives it its subnets and how often to sweep.

  netview.collectors   one row per collector (newest version wins): name, key
                       hash, subnets, interval, last contact, last scan
  netview.asset_obs    every sighting of every device, kept OBS_DAYS
  netview.assets       each device's current picture (newest version wins),
                       keyed by MAC - or "ip:<address>" when the collector
                       is past a router and can't see MACs

Passive discovery (passive_loop) adds what a sweep can't see - a phone asleep
when it's asked doesn't answer: a LAN address in the flows is a sighting
(collector "flows"), and addresses in the SNMP ARP tables or DHCP leases that
no one has seen are listed as known only (last_seen 0, their source as the
collector) - such entries can be days old.

The collector's endpoints (/api/collector/...) are outside the sign-in (the
key is the sign-in); the rest is for signed-in users, changes for admins.
"""
import calendar
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import time

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

import auth
import checks  # ClickHouse helpers

OBS_DAYS = 90
MAX_HOSTS = 70000  # one sweep: a /16 at most
ONLINE_GRACE = 2.5  # a collector or device is "online" if seen within this many intervals
COUNTERS_MIN = 5  # how often collectors poll their SNMP devices' interface counters
router = APIRouter()
NAMER = [lambda ip: ""]  # app.py's name_of (the DHCP / static names), given at start()

DDL = [
    """CREATE TABLE IF NOT EXISTS netview.collectors (
        id String, name String, key_hash String, subnets Array(String), interval_min UInt32,
        created DateTime, last_seen DateTime, last_scan DateTime, last_hosts UInt32, version String,
        address String, deleted UInt8, ver UInt64
    ) ENGINE = ReplacingMergeTree(ver) ORDER BY id""",
    f"""CREATE TABLE IF NOT EXISTS netview.asset_obs (
        t DateTime, collector String, scan String, key String, ip String, mac String, vendor String,
        hostname String, netbios String, ports Array(UInt16), rtt_ms Float32, method LowCardinality(String)
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (key, t)
    TTL t + INTERVAL {OBS_DAYS} DAY""",
    """CREATE TABLE IF NOT EXISTS netview.assets (
        key String, ip String, ips Array(String), mac String, vendor String, hostname String, netbios String,
        ports Array(UInt16), collector String, first_seen DateTime, last_seen DateTime, tags Array(String), ver UInt64
    ) ENGINE = ReplacingMergeTree(ver) ORDER BY key""",
    # Its key, encrypted (auth's settings key): what snmp.py encrypts its credentials with.
    "ALTER TABLE netview.collectors ADD COLUMN IF NOT EXISTS key_enc String DEFAULT ''",
    # A key it's being rotated to (its hash, and itself encrypted) - until it uses it.
    "ALTER TABLE netview.collectors ADD COLUMN IF NOT EXISTS pending_hash String DEFAULT ''",
    "ALTER TABLE netview.collectors ADD COLUMN IF NOT EXISTS pending_enc String DEFAULT ''",
    # JSON: {subnet: minutes} where a subnet isn't swept every interval_min (0: on demand only),
    # {subnet: {last, hosts}} its last sweep, and a sweep asked for now {id, subnets, t}.
    "ALTER TABLE netview.collectors ADD COLUMN IF NOT EXISTS schedule String DEFAULT ''",
    "ALTER TABLE netview.collectors ADD COLUMN IF NOT EXISTS subnet_state String DEFAULT ''",
    "ALTER TABLE netview.collectors ADD COLUMN IF NOT EXISTS sweep_now String DEFAULT ''",
    # How it can update itself (2.5.0+: systemd, task, restart - see UPDATERS), and the
    # version an admin asked it to update to (Update on the page), until it runs it.
    "ALTER TABLE netview.collectors ADD COLUMN IF NOT EXISTS updater String DEFAULT ''",
    "ALTER TABLE netview.collectors ADD COLUMN IF NOT EXISTS update_to String DEFAULT ''",
    # What the devices' open ports said in a sweep (collector 2.4.0+, services.go) - the posture checks'.
    """CREATE TABLE IF NOT EXISTS netview.asset_services (
        t DateTime, collector String, ip String, mac String, port UInt16, kind LowCardinality(String),
        banner String, tls Array(String), cert_subject String, cert_issuer String, cert_not_after DateTime,
        self_signed UInt8, smb1 UInt8
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (ip, port, t) TTL t + INTERVAL 30 DAY""",
]
_ready = [False]


def ready():
    if not _ready[0]:
        for d in DDL:
            checks.ch(d)
        _ready[0] = True


def q(sql, **params):
    ready()
    return checks.query(sql, **params)


def insert(table, rows):
    if rows:
        ready()
        checks.ch(f"INSERT INTO netview.{table} FORMAT JSONEachRow", "\n".join(json.dumps(r) for r in rows))


def start(namer=None):
    if namer:
        NAMER[0] = namer
    threading.Thread(target=_oui_loop, daemon=True, name="oui").start()
    threading.Thread(target=passive_loop, daemon=True, name="passive").start()


# ------------------------------------------------------------------ MAC vendors
# Wireshark's list (from the IEEE registries - whose own site turns scripts
# away), refreshed weekly: the first 3 bytes of a MAC, or 28 / 36 bits for
# the smaller blocks. Collectors send MACs; the vendor is named here.
OUI_URL = "https://www.wireshark.org/download/automated/data/manuf"
_oui = {"24": {}, "28": {}, "36": {}, "loaded": 0, "error": ""}


def _oui_load():
    r = requests.get(OUI_URL, timeout=120, headers={"User-Agent": "sentry-lens"})
    r.raise_for_status()
    tables = {"24": {}, "28": {}, "36": {}}
    for line in r.text.splitlines():
        if not line or line.startswith("#"):
            continue
        p = line.split("\t")
        if len(p) < 2:
            continue
        prefix, _, bits = p[0].strip().partition("/")
        hexs = prefix.replace(":", "").replace("-", "").upper()
        bits = bits or "24"
        if bits in tables:
            tables[bits][hexs[:int(bits) // 4]] = (p[2] if len(p) > 2 and p[2].strip() else p[1]).strip()
    if len(tables["24"]) < 10000:
        raise RuntimeError(f"only {len(tables['24'])} vendors")
    _oui.update(tables, loaded=int(time.time()), error="")


def _oui_loop():
    while True:
        try:
            _oui_load()
            time.sleep(7 * 86400)
        except Exception as e:  # noqa: BLE001 - the vendors are a nicety: try again in an hour
            _oui["error"] = str(e)[:200]
            time.sleep(3600)


def vendor_for(mac):
    """The vendor of a MAC - or that it's a random one (phones and laptops hide theirs)."""
    h = (mac or "").replace(":", "").upper()
    if len(h) != 12:
        return ""
    if int(h[1], 16) & 0x2:
        return "Private (random MAC)"
    return _oui["36"].get(h[:9]) or _oui["28"].get(h[:7]) or _oui["24"].get(h[:6]) or ""


def _admin(request):
    if auth.ENABLED:
        auth.require_admin(request)


def _is_admin(request):
    try:
        _admin(request)
        return True
    except HTTPException:
        return False


def _hash(key):
    return hashlib.sha256(key.encode()).hexdigest()


# ------------------------------------------------------------------ collectors
def collectors(include_deleted=False):
    rows = q("SELECT * FROM netview.collectors FINAL" + ("" if include_deleted else " WHERE deleted = 0"))
    return {r["id"]: r for r in rows}


def save_collector(c):
    c = dict(c)
    c["ver"] = time.time_ns()
    for k in ("created", "last_seen", "last_scan"):
        c[k] = _ts(c.get(k) or 0)
    insert("collectors", [c])


def check_subnets(subnets):
    out = []
    for s in subnets if isinstance(subnets, list) else str(subnets).replace(",", " ").split():
        try:
            n = ipaddress.ip_network(str(s).strip(), strict=False)
        except ValueError:
            raise HTTPException(400, f"not a subnet: {s}")
        if n.version == 4 and n.prefixlen < 16 or n.version == 6 and n.prefixlen < 112:
            raise HTTPException(400, f"{n} is too big to sweep: a /16 at most (IPv6: /112)")
        out.append(str(n))
    if not out:
        raise HTTPException(400, "at least one subnet, e.g. 192.168.1.0/24")
    return list(dict.fromkeys(out))  # each once (one added twice)


def _json(c, k):
    try:
        return json.loads(c.get(k) or "{}")
    except ValueError:
        return {}


def schedule(c):
    """{subnet: minutes} for each of its subnets: its own, else the collector's (0: on demand only)."""
    own = _json(c, "schedule")
    return {s: int(own.get(s, c["interval_min"])) for s in c["subnets"]}


def every_for(c, ip):
    """How often the subnet holding ip is swept (minutes, 0: on demand) - the collector's interval if none does."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return c.get("interval_min", 30)
    for s, m in schedule(c).items():
        n = ipaddress.ip_network(s)
        if a.version == n.version and a in n:
            return m
    return c.get("interval_min", 30)


SWEEP_NOW_KEPT = 3600  # a sweep asked for and not done within this (collector off, or too old): dropped


def sweep_now(c):
    s = _json(c, "sweep_now")
    return s if s and time.time() - s.get("t", 0) < SWEEP_NOW_KEPT else {}


def public(c):
    now = time.time()
    online = c["last_seen"] and now - _ts(c["last_seen"]) < max(300, c["interval_min"] * 60 * ONLINE_GRACE)
    return {k: c[k] for k in ("id", "name", "subnets", "interval_min", "last_hosts", "version", "address")} | {
        "created": _ts(c["created"]), "last_seen": _ts(c["last_seen"]), "last_scan": _ts(c["last_scan"]), "online": bool(online),
        "creds_ok": bool(c.get("key_enc")), "rotating": bool(c.get("pending_hash")),
        "can_rotate": can_rotate(c.get("version", "")), "can_schedule": can_rotate(c.get("version", ""), SCHEDULE_FROM),
        "schedule": schedule(c), "subnet_state": _json(c, "subnet_state"), "sweep_now": sweep_now(c),
        "updater": UPDATERS.get(c.get("updater", ""), ""), "can_update": c.get("updater", "") in UPDATERS,
        "outdated": older(c.get("version", ""), latest()), "update_to": c.get("update_to", "")}


# How a collector updates itself (it runs unprivileged and can't replace its
# own program): it asks what installed it, which downloads the new one from
# Sentry Lens, checks it against SHA256SUMS and restarts it.
UPDATERS = {"systemd": "Linux service (its updater unit)", "task": "Windows service (its updater task)",
            "restart": "Docker (fetches the collector at each start)"}


def latest():
    import dist  # here: a module of the app
    return dist.version()


def older(version, than):
    """version is older than `than` (both x.y.z; an unknown one counts as older)."""
    try:
        return bool(than) and tuple(int(x) for x in version.split(".")[:3]) < tuple(int(x) for x in than.split(".")[:3])
    except ValueError:
        return bool(than)


# Collectors before 2.1.0 switch to a rotated key without keeping it (Linux
# had no state folder): after a restart they're back on the old, dead key.
ROTATE_FROM = (2, 1, 0)
# Collectors before 2.3.0 sweep all their subnets every interval_min, and don't sweep on demand.
SCHEDULE_FROM = (2, 3, 0)


def can_rotate(version, since=ROTATE_FROM):
    try:
        return tuple(int(x) for x in version.split(".")[:3]) >= since
    except ValueError:
        return False


# Keys Sentry Lens refused lately, by the address they came from: a collector
# installed with a replaced key, or one whose collector was deleted, keeps
# asking - shown on the Collectors page (in memory: a restart forgets them).
REFUSED = {}
REFUSED_SHOWN = 3600


def refused():
    now = time.time()
    for a in [a for a, r in REFUSED.items() if now - r["last"] > REFUSED_SHOWN]:
        del REFUSED[a]
    return sorted(({"address": a} | r for a, r in REFUSED.items()), key=lambda r: -r["last"])


def _ts(v):
    """ClickHouse DateTime (text, UTC) -> epoch seconds."""
    if isinstance(v, (int, float)):
        return int(v)
    if not v or v.startswith("1970-01-01"):
        return 0
    return calendar.timegm(time.strptime(v, "%Y-%m-%d %H:%M:%S"))


@router.get("/api/collectors")
def list_collectors(request: Request):
    """The collectors, and what the install lines need: the addresses Sentry Lens answers at, the version it hands out."""
    import dist  # here: a module of the app
    urls = [u for u in (os.environ.get("COLLECTOR_LAN_URL", ""), os.environ.get("PUBLIC_URL", ""), dist.base_url(request)) if u]
    return {"collectors": sorted((public(c) for c in collectors().values()), key=lambda c: c["name"].lower()),
            "urls": list(dict.fromkeys(u.rstrip("/") for u in urls)), "version": dist.version(),
            "refused": refused() if _is_admin(request) else []}


@router.post("/api/collectors")
async def add_collector(request: Request):
    """An admin adds a collector: {name, subnets, interval_min}. The answer
    has its key - shown this once, kept only as a hash."""
    _admin(request)
    b = await request.json()
    name = str(b.get("name", "")).strip()[:60]
    if not re.fullmatch(r"[\w .-]{1,60}", name):
        raise HTTPException(400, "a name: letters, digits, spaces, . - _")
    interval = int(b.get("interval_min") or 30)
    if not 5 <= interval <= 1440:
        raise HTTPException(400, "sweep every 5 to 1440 minutes")
    key = "slc_" + secrets.token_urlsafe(32)
    cid = secrets.token_hex(6)
    save_collector({"id": cid, "name": name, "key_hash": _hash(key), "key_enc": auth._fernet.encrypt(key.encode()).decode(), "subnets": check_subnets(b.get("subnets", [])),
                    "interval_min": interval, "created": time.time(), "last_seen": 0, "last_scan": 0, "last_hosts": 0,
                    "version": "", "address": "", "deleted": 0})
    return {"id": cid, "key": key}


@router.post("/api/collectors/{cid}")
async def change_collector(request: Request, cid: str):
    """{subnets, interval_min, name} - or {delete: true} (its key stops working;
    what it found stays)."""
    _admin(request)
    c = collectors().get(cid)
    if not c:
        raise HTTPException(404, "no such collector")
    b = await request.json()
    if b.get("rotate_key"):
        # Rotation: the collector gets the new key at its next contact (encrypted
        # with the one it has), and the old one stops working the moment it uses
        # the new one. Nothing to reinstall; the new key is never shown.
        key = "slc_" + secrets.token_urlsafe(32)
        save_collector(c | {"pending_hash": _hash(key), "pending_enc": auth._fernet.encrypt(key.encode()).decode()})
        return {"ok": True, "rotating": True}
    if "update" in b:
        # Updated at its next contact: it asks its updater for the version Sentry
        # Lens hands out (collector 2.5.0+; an older one needs its install line once).
        if b["update"] and c.get("updater", "") not in UPDATERS:
            raise HTTPException(400, "this collector can't update itself yet (before 2.5.0): run its install line "
                                     "once more - from then on, Update does it")
        if b["update"] and not older(c.get("version", ""), latest()):
            raise HTTPException(400, f"it already runs {latest()}")
        save_collector(c | {"update_to": latest() if b["update"] else ""})
        return {"ok": True, "update_to": latest() if b["update"] else ""}
    if b.get("regenerate_key"):
        # Replacement (a lost or leaked key): the old one stops working now; the
        # collector needs the new one - its install line, run again.
        key = "slc_" + secrets.token_urlsafe(32)
        save_collector(c | {"key_hash": _hash(key), "key_enc": auth._fernet.encrypt(key.encode()).decode(),
                            "pending_hash": "", "pending_enc": ""})
        return {"ok": True, "key": key}
    if b.get("sweep_now"):
        # Swept at its next contact (within a minute): these subnets, or all of them.
        want = [s for s in check_subnets(b["subnets"]) if s in c["subnets"]] if b.get("subnets") else []
        if b.get("subnets") and not want:
            raise HTTPException(400, "not one of its subnets")
        c["sweep_now"] = json.dumps({"id": secrets.token_hex(4), "subnets": want, "t": int(time.time())})
        save_collector(c)
        return {"ok": True}
    if b.get("delete"):
        c["deleted"] = 1
    else:
        if "subnets" in b:
            c["subnets"] = check_subnets(b["subnets"])
        if "interval_min" in b:
            c["interval_min"] = max(5, min(1440, int(b["interval_min"])))
        if "schedule" in b:  # {subnet: minutes, or 0: on demand only}; left out: the collector's interval
            own = {}
            for s, m in (b["schedule"] or {}).items():
                s, m = check_subnets([s])[0], int(m)
                if m and not 5 <= m <= 1440:
                    raise HTTPException(400, f"{s}: every 5 to 1440 minutes, or on demand only")
                own[s] = m
            c["schedule"] = json.dumps(own)
        # Subnets removed: their schedule and last sweep go too.
        c["schedule"] = json.dumps({s: m for s, m in _json(c, "schedule").items() if s in c["subnets"] and m != c["interval_min"]})
        c["subnet_state"] = json.dumps({s: v for s, v in _json(c, "subnet_state").items() if s in c["subnets"]})
        if b.get("name"):
            c["name"] = str(b["name"]).strip()[:60]
    save_collector(c)
    return {"ok": True}


# ------------------------------------------------------------------ the collector's side
def _key(request):
    h = request.headers.get("authorization", "")
    key = h[7:] if h.lower().startswith("bearer ") else ""
    if not key.startswith("slc_"):
        raise HTTPException(401, "a collector key")
    return key


def _collector(request):
    """The collector a request's key belongs to (or a 401). A collector
    using the key it was rotated to makes that key its key: the old one
    stops working there."""
    digest = _hash(_key(request))
    for c in collectors().values():
        if hmac.compare_digest(c["key_hash"], digest):
            return c
        if c.get("pending_hash") and hmac.compare_digest(c["pending_hash"], digest):
            c |= {"key_hash": c["pending_hash"], "key_enc": c["pending_enc"], "pending_hash": "", "pending_enc": ""}
            save_collector(c)
            return c
    addr = (request.headers.get("x-forwarded-for") or (request.client.host if request.client else "?"))[:60]
    r = REFUSED.setdefault(addr, {"first": time.time(), "count": 0})
    r |= {"last": time.time(), "count": r["count"] + 1, "version": request.query_params.get("version", "")[:40]}
    raise HTTPException(401, "unknown or deleted collector")


@router.get("/api/collector/config")
def collector_config(request: Request, version: str = "", updater: str = ""):
    """What a collector sweeps, and how often - also its heartbeat, how a
    rotated key reaches it (encrypted with the key it used to ask), and an
    update asked for (2.5.0+: it says how it can update itself, updater)."""
    c = _collector(request)
    c |= {"last_seen": time.time(), "version": version[:40], "updater": updater if updater in UPDATERS else "",
          "address": (request.headers.get("x-forwarded-for") or (request.client.host if request.client else ""))[:60]}
    if c.get("update_to") and not older(version, c["update_to"]):
        c["update_to"] = ""  # done
    save_collector(c)
    import snmp  # here: it imports this module
    creds, n = snmp.for_collector(c)
    out = {"id": c["id"], "name": c["name"], "subnets": c["subnets"], "interval_min": c["interval_min"],
           "counters_min": COUNTERS_MIN, "credentials": creds, "credential_count": n,
           # 2.3.0+: each subnet on its own schedule, and a sweep asked for on the page (older ones: interval_min)
           "schedule": [{"subnet": s, "every_min": m} for s, m in schedule(c).items()]}
    now_ = sweep_now(c)
    if now_:
        out["sweep_now"] = {"id": now_["id"], "subnets": now_.get("subnets", [])}
    out["snmp_profiles"] = snmp.PROFILES  # what to read beyond the basics (snmp.py)
    if can_rotate(version, (2, 6, 0)):
        import inventory  # here: it imports this module
        out["forget_pins"] = inventory.forget_for(c["id"])  # Trust the new key (inventory.py)
    if c.get("update_to") and c["updater"]:
        out["update"] = c["update_to"]
    if c.get("pending_enc") and can_rotate(version):  # an older one would lose it (ROTATE_FROM)
        new = auth._fernet.decrypt(c["pending_enc"].encode())
        out["new_key"] = snmp.collector_fernet(_key(request)).encrypt(new).decode()
    return out


MAC = re.compile(r"[0-9A-F]{2}(:[0-9A-F]{2}){5}")


@router.post("/api/collector/results")
async def collector_results(request: Request):
    """One sweep: {scan, started, finished, hosts: [{ip, mac, vendor, hostname,
    netbios, ports, rtt_ms, method, services}]} - kept as sightings, merged into
    assets; what the ports said (2.4.0+) into asset_services."""
    c = _collector(request)
    b = await request.json()
    hosts = b.get("hosts") or []
    if not isinstance(hosts, list) or len(hosts) > MAX_HOSTS:
        raise HTTPException(400, "hosts: a list")
    now = int(time.time())
    scan = str(b.get("scan", ""))[:40]
    obs, svcs = [], []
    for h in hosts:
        try:
            ip = str(ipaddress.ip_address(str(h.get("ip", ""))))
        except ValueError:
            continue
        mac = str(h.get("mac") or "").upper()
        mac = mac if MAC.fullmatch(mac) else ""
        ports = sorted({int(p) for p in (h.get("ports") or []) if str(p).isdigit() and 0 < int(p) < 65536})[:200]
        obs.append({"t": now, "collector": c["id"], "scan": scan, "key": mac or f"ip:{ip}", "ip": ip, "mac": mac,
                    "vendor": (str(h.get("vendor") or "") or vendor_for(mac))[:80], "hostname": str(h.get("hostname") or "")[:200],
                    "netbios": str(h.get("netbios") or "")[:60], "ports": ports,
                    "rtt_ms": float(h.get("rtt_ms") or 0), "method": str(h.get("method") or "")[:20]})
        svcs += services_of(h.get("services"), now, c["id"], ip, mac)
    insert("asset_obs", obs)
    insert("asset_services", svcs)
    merge(obs, c["id"], now)
    # Which subnets this sweep covered (2.3.0+; before: all of them) - and the sweep asked for, done.
    swept = [s for s in (b.get("subnets") or c["subnets"]) if s in c["subnets"]]
    state = _json(c, "subnet_state")
    ips = [ipaddress.ip_address(o["ip"]) for o in obs]
    for s in swept:
        n = ipaddress.ip_network(s)
        state[s] = {"last": now, "hosts": sum(1 for a in ips if a.version == n.version and a in n)}
    c |= {"last_seen": now, "last_scan": now, "last_hosts": len(obs), "subnet_state": json.dumps(state)}
    if b.get("forced") and b["forced"] == _json(c, "sweep_now").get("id"):
        c["sweep_now"] = ""
    save_collector(c)
    return {"ok": True, "hosts": len(obs)}


SERVICE_KINDS = {"tls", "ssh", "http", "smb", "ftp", "telnet"}
TLS_VERSIONS = {"1.0", "1.1", "1.2", "1.3"}


def services_of(raw, now, cid, ip, mac):
    """A host's services as the collector sent them, checked and trimmed."""
    out = []
    for s in (raw if isinstance(raw, list) else [])[:50]:
        if not isinstance(s, dict) or s.get("kind") not in SERVICE_KINDS:
            continue
        try:
            port, not_after = int(s.get("port", 0)), int(s.get("cert_not_after") or 0)
        except (TypeError, ValueError):
            continue
        if not 0 < port < 65536:
            continue
        out.append({"t": now, "collector": cid, "ip": ip, "mac": mac, "port": port, "kind": s["kind"],
                    "banner": str(s.get("banner") or "")[:200],
                    "tls": [v for v in (s.get("tls") or []) if v in TLS_VERSIONS],
                    "cert_subject": str(s.get("cert_subject") or "")[:300],
                    "cert_issuer": str(s.get("cert_issuer") or "")[:300],
                    "cert_not_after": min(max(not_after, 0), 4294967295),
                    "self_signed": int(bool(s.get("self_signed"))), "smb1": int(bool(s.get("smb1")))})
    return out


def merge(obs, cid, now, passive=False):
    """Fold a sweep into the assets: a device keeps its first sighting, its
    names and ports from the latest sweep that had any, every address it used.
    A passive sighting (flows) keeps the collector that found it, and is
    dated when it happened."""
    if not obs:
        return
    keys = [o["key"] for o in obs]
    cur = {r["key"]: r for r in q("SELECT * FROM netview.assets FINAL WHERE key IN {keys:Array(String)}", keys=keys)}
    rows = []
    for o in obs:
        a = cur.get(o["key"])
        ips = sorted(set((a or {}).get("ips", [])) | {o["ip"]})[-20:]
        rows.append({"key": o["key"], "ip": o["ip"], "ips": ips, "mac": o["mac"] or (a or {}).get("mac", ""),
                     "vendor": o["vendor"] or (a or {}).get("vendor", ""),
                     "hostname": o["hostname"] or (a or {}).get("hostname", ""),
                     "netbios": o["netbios"] or (a or {}).get("netbios", ""),
                     "ports": o["ports"] or (a or {}).get("ports", []),
                     # (a known-only entry, never seen, takes the sighting's collector)
                     "collector": (a["collector"] if a and _ts(a["last_seen"]) else cid) if passive else cid,
                     "first_seen": _ts(a["first_seen"]) if a else o["t"],
                     "last_seen": max(o["t"], _ts(a["last_seen"]) if a else 0) if passive else now,
                     "tags": (a or {}).get("tags", []), "ver": time.time_ns()})
    insert("assets", rows)


# ------------------------------------------------------------------ passive discovery
PASSIVE_MIN = 5
FRESH = 900  # seen this recently (a sweep): a flow adds no sighting - keeps asset_obs small
LAN_ROLE = os.environ.get("LAN_ROLE", "lan")
NAMES_FILE = os.environ.get("NAMES_FILE", "/data/names.json")


def _network():
    """The IPv4 subnets the collectors sweep: "the network" passive discovery keeps to."""
    nets = set()
    for c in collectors().values():
        for s in c["subnets"]:
            try:
                n = ipaddress.ip_network(s)
            except ValueError:
                continue
            if n.version == 4:
                nets.add(n)
    return list(nets)


def _on(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n and (n.prefixlen >= 31 or a not in (n.network_address, n.broadcast_address)) for n in nets)


def _learned(nets):
    """ip -> (MAC, where it was learned), for addresses on the network: the
    DHCP leases (names.json), else the SNMP ARP tables - each device's latest
    reading, the MAC most of them report."""
    out = {}
    rows = q("""SELECT a.ip AS ip, upper(a.mac) AS mac, groupUniqArray(d.sys_name) AS by, count() AS n
        FROM netview.snmp_arp a LEFT JOIN (SELECT key, sys_name FROM netview.snmp_devices FINAL) d ON a.key = d.key
        WHERE (a.key, a.t) IN (SELECT key, max(t) FROM netview.snmp_arp GROUP BY key)
        GROUP BY a.ip, mac ORDER BY n""")
    for r in rows:  # by count: the MAC most tables agree on wins
        if _on(r["ip"], nets) and MAC.fullmatch(r["mac"]) and r["mac"] not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            by = ", ".join(sorted(b for b in r["by"] if b)[:3]) or "a device"
            out[r["ip"]] = (r["mac"], f"ARP table of {by}")
    try:
        with open(NAMES_FILE, encoding="utf-8") as f:
            leases = json.load(f).get("names") or {}
    except (OSError, ValueError):
        leases = {}
    for ip, v in leases.items():
        mac = str((v or {}).get("mac") or "").upper()
        if _on(ip, nets) and MAC.fullmatch(mac):
            out[ip] = (mac, "DHCP lease")
    return out


def passive_once():
    """One pass: (sightings from the flows, devices newly known only)."""
    nets = _network()
    if not nets:
        return 0, 0
    learned = _learned(nets)
    # A LAN address that sent traffic is there. Twice the period back: flows
    # arrive a minute or two late, and a sighting already folded in is skipped.
    seen = [r for r in q("""SELECT replaceOne(IPv6NumToString(SrcAddr), '::ffff:', '') AS ip, toUInt32(max(TimeReceived)) AS t
        FROM flows WHERE TimeReceived > now() - INTERVAL {win:UInt32} SECOND AND SrcNetRole = {lan:String}
        GROUP BY ip""", win=PASSIVE_MIN * 120, lan=LAN_ROLE) if _on(r["ip"], nets)]
    assets = q("SELECT key, ip, ips, mac, last_seen FROM netview.assets FINAL")
    by_ip = {}
    for a in assets:  # an address -> its device, the last seen one if several
        for ip in set(a["ips"]) | {a["ip"]}:
            if ip not in by_ip or _ts(a["last_seen"]) > _ts(by_ip[ip]["last_seen"]):
                by_ip[ip] = a
    obs = []
    for r in seen:
        ip, t = r["ip"], int(r["t"])
        a = by_ip.get(ip)
        mac = learned.get(ip, ("", ""))[0] or (a["mac"] if a else "")
        key = mac or (a["key"] if a else f"ip:{ip}")
        if a and a["key"] == key and _ts(a["last_seen"]) >= min(t, time.time() - FRESH):
            continue  # nothing new: a sweep or an earlier pass saw it lately
        obs.append({"t": t, "collector": "flows", "scan": "passive", "key": key, "ip": ip, "mac": mac,
                    "vendor": vendor_for(mac), "hostname": "", "netbios": "", "ports": [], "rtt_ms": 0.0,
                    "method": "flow"})
    if obs:
        insert("asset_obs", obs)
        merge(obs, "flows", int(time.time()), passive=True)
    # Known only: addresses nobody has seen, nor their MAC under another one.
    keys = {a["key"] for a in assets} | {o["key"] for o in obs}
    seen_ips = set(by_ip) | {o["ip"] for o in obs}
    now = int(time.time())
    known = [{"key": mac, "ip": ip, "ips": [ip], "mac": mac, "vendor": vendor_for(mac), "hostname": "", "netbios": "",
              "ports": [], "collector": source, "first_seen": now, "last_seen": 0, "tags": [], "ver": time.time_ns()}
             for ip, (mac, source) in learned.items() if ip not in seen_ips and mac not in keys]
    insert("assets", list({k["key"]: k for k in known}.values()))
    return len(obs), len(known)


def passive_loop():
    time.sleep(60)  # let the app start
    while True:
        try:
            n, k = passive_once()
            if n or k:
                print(f"assets: {n} seen in the flows, {k} known only (ARP tables, DHCP)", flush=True)
        except Exception as exc:  # noqa: BLE001 - next pass
            print(f"assets: passive discovery: {exc}", flush=True)
        time.sleep(PASSIVE_MIN * 60)


# ------------------------------------------------------------------ the views
@router.get("/assets")
def assets_page():
    return FileResponse(STATIC + "/assets.html")


STATIC = __file__.rsplit("/", 1)[0] + "/static"


@router.get("/api/assets")
def list_assets():
    """Every device the collectors found, with its best name and whether it answered lately."""
    cs = collectors(include_deleted=True)
    now = time.time()
    out = []
    for a in q("SELECT * FROM netview.assets FINAL"):
        c = cs.get(a["collector"], {})
        m = every_for(c, a["ip"]) if c else 30
        grace = max(900, m * 60 * ONLINE_GRACE) if m else 86400  # on demand only: answered within a day
        last, first = _ts(a["last_seen"]), _ts(a["first_seen"])
        dhcp = NAMER[0](a["ip"])
        name = dhcp or (a["hostname"].split(".")[0] if a["hostname"] else "") or a["netbios"] or ""
        out.append({k: a[k] for k in ("key", "ip", "ips", "mac", "vendor", "hostname", "netbios", "ports", "tags")} | {
            "vendor": a["vendor"] or vendor_for(a["mac"]), "name": name, "dhcp_name": dhcp, "collector": c.get("name", a["collector"]), "first_seen": first, "last_seen": last,
            # known only: in an ARP table or a DHCP lease, never seen answering or sending (passive_once)
            "online": bool(last) and now - last < grace, "new": bool(last) and now - first < 86400, "known_only": not last})
    out.sort(key=lambda a: tuple(int(x) for x in a["ip"].split(".")) if "." in a["ip"] else (999, a["ip"]))
    return {"assets": out, "collectors": len([c for c in cs.values() if not c["deleted"]])}


@router.get("/api/assets/{key}")
def asset(key: str):
    """One device: its picture and its sightings (when, where, what answered)."""
    a = q("SELECT * FROM netview.assets FINAL WHERE key = {key:String}", key=key)
    if not a:
        raise HTTPException(404, "no such asset")
    hist = q("""SELECT toUInt32(t) AS t, collector, ip, hostname, netbios, ports, rtt_ms, method
        FROM netview.asset_obs WHERE key = {key:String} ORDER BY t DESC LIMIT 500""", key=key)
    # Sightings per day over the last 30 days: a presence strip.
    days = q("""SELECT toUInt32(toStartOfDay(t)) AS d, count() AS n FROM netview.asset_obs
        WHERE key = {key:String} AND t > now() - INTERVAL 30 DAY GROUP BY d ORDER BY d""", key=key)
    cs = collectors(include_deleted=True)
    for h in hist:
        h["collector"] = cs.get(h["collector"], {}).get("name", h["collector"])
    return a[0] | {"first_seen": _ts(a[0]["first_seen"]), "last_seen": _ts(a[0]["last_seen"]),
                   "dhcp_name": NAMER[0](a[0]["ip"]), "history": hist, "days": days}


TAG = re.compile(r"[a-z0-9][a-z0-9_.-]{0,23}")


@router.post("/api/assets/{key}/tags")
async def asset_tags(request: Request, key: str):
    _admin(request)
    tags = sorted({str(t).strip().lower() for t in (await request.json()).get("tags", []) if str(t).strip()})
    if len(tags) > 10 or any(not TAG.fullmatch(t) for t in tags):
        raise HTTPException(400, "up to 10 tags, each a short word: letters, digits, - _ .")
    a = q("SELECT * FROM netview.assets FINAL WHERE key = {key:String}", key=key)
    if not a:
        raise HTTPException(404, "no such asset")
    row = a[0] | {"tags": tags, "ver": time.time_ns(), "first_seen": _ts(a[0]["first_seen"]), "last_seen": _ts(a[0]["last_seen"])}
    insert("assets", [row])
    return {"tags": tags}
