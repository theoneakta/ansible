"""netview - our own traffic views over Akvorado's ClickHouse.

Akvorado collects and stores the flows (OPNsense + softflowd -> ClickHouse);
this only reads them, with views Akvorado's console doesn't have: device names
instead of IPs, drill-down from any number to who and what is behind it,
websites, and what's new today.

Which exporter answers what (see akvorado_stack.yml):
  internet traffic   the firewall only (WAN_EXPORTER) - it exports its LAN
                     interface, so each internet flow is counted once; the
                     side towards an external interface is the remote one.
  LAN-to-LAN         the Proxmox nodes' softflowd (LAN_EXPORTERS). A flow
                     between VMs on two nodes is seen by both, so per-host LAN
                     figures take the busiest exporter rather than the sum.

Websites come from the firewall's DNS query log (dns.py, the one part that
writes - to its own netview database): lookups say who visited what, and
flows are matched to the domain the device last looked up for that IP.
Live throughput and top talkers come straight from the firewall (live.py).

Every view takes a time window - a preset (range=1h|6h|24h|7d) or from/to
(epoch seconds, e.g. a zoom on a chart) - and the drill-down ones take any of
the FILTERS. The views' queries run with readonly=2. Device names come from
names.json, written by the playbook from the firewall's DHCP leases.
"""
import ipaddress
import json
import os
import pathlib
import re
import time
from contextlib import asynccontextmanager
from typing import Optional

import requests
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import dns
import live

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
NAMES_FILE = pathlib.Path(os.environ.get("NAMES_FILE", "/data/names.json"))
WAN_EXPORTER = os.environ.get("WAN_EXPORTER", "opnsense")
LAN_EXPORTERS = [e for e in os.environ.get("LAN_EXPORTERS", "pve5,pve6").split(",") if e]
LAN_ROLE = os.environ.get("LAN_ROLE", "lan")  # Src/DstNetRole of the local network
STATIC = pathlib.Path(__file__).parent / "static"

RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
STEPS = [60, 120, 300, 600, 900, 1800, 3600, 7200]  # chart buckets; flows come per minute
MAX_POINTS = 200
KEEP = 7 * 86400  # raw flows' TTL (akvorado_resolutions)
STACK = 7  # series in a breakdown chart before the rest folds into "other"


@asynccontextmanager
async def lifespan(_app):
    dns.start()
    live.start()
    yield


app = FastAPI(title="netview", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ------------------------------------------------------------------ ClickHouse
def query(sql, **params):
    """Run one SELECT; {name:Type} placeholders are bound server-side."""
    args = {"readonly": 2, "max_execution_time": 60, "default_format": "JSON",
            "output_format_json_quote_64bit_integers": 0}
    args.update({f"param_{k}": v if not isinstance(v, list)
                 else "[" + ",".join(f"'{x}'" if isinstance(x, str) else str(x) for x in v) + "]"
                 for k, v in params.items()})
    r = requests.post(CH_URL, params=args, data=sql.encode(), timeout=70)
    if r.status_code != 200:
        raise HTTPException(502, f"ClickHouse: {r.text[:300]}")
    return r.json()["data"]


def window(rng, frm, to):
    """(start, end, step): a preset ending now, or from/to clipped to what's kept."""
    now = int(time.time())
    if frm is not None or to is not None:
        if frm is None or to is None or not 0 < frm < to:
            raise HTTPException(400, "from and to are epoch seconds, from < to")
        start, end = max(frm, now - KEEP), min(to, now)
        if end - start < 300:
            raise HTTPException(400, "pick at least 5 minutes within the last 7 days")
    else:
        if rng not in RANGES:
            raise HTTPException(400, f"range must be one of {list(RANGES)}")
        start, end = now - RANGES[rng], now
    step = next((s for s in STEPS if (end - start) / s <= MAX_POINTS), STEPS[-1])
    return start, end, step


def check_ip(ip):
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(400, "not an IP address")


def check_site(site):
    site = site.lower()
    if not re.fullmatch(r"[a-z0-9_.-]{1,253}", site):
        raise HTTPException(400, "not a domain name")
    return site


def check_country(cc):
    if not re.fullmatch(r"[A-Z]{2}", cc):
        raise HTTPException(400, "not a country code")
    return cc


def check_svc(svc):
    m = re.fullmatch(r"(\d{1,3})/(\d{1,5})", svc)
    if not m:
        raise HTTPException(400, "service is <protocol number>/<port>")
    return int(m.group(1)), int(m.group(2))


IP = "replaceRegexpOne(IPv6NumToString({col}), '^::ffff:', '')"
SERVICE = ("multiIf(Proto = 6, dictGetOrDefault('tcp', 'name', toUInt64(rport), ''), "
           "Proto = 17, dictGetOrDefault('udp', 'name', toUInt64(rport), ''), '')")
PROTO = "dictGetOrDefault('protocols', 'name', toUInt64(Proto), toString(Proto))"
ASN_NAME = "dictGetOrDefault('asns', 'name', toUInt32(ras), '')"
BETWEEN = "BETWEEN toDateTime({start:UInt32}) AND toDateTime({end:UInt32})"

# Internet flows from the firewall, turned around so every row reads from the
# LAN host's side: local/remote address, remote AS/country/port, direction.
WAN = f"""
wan AS (
    SELECT TimeReceived AS t,
           InIfBoundary = 'external' AS dl,
           if(dl, DstAddr, SrcAddr) AS local, if(dl, SrcAddr, DstAddr) AS remote,
           if(dl, SrcAS, DstAS) AS ras,
           replaceAll(toString(if(dl, SrcCountry, DstCountry)), '\\0', '') AS rcc,
           if(dl, SrcPort, DstPort) AS rport, Proto,
           Bytes * SamplingRate AS b
    FROM flows
    WHERE ExporterName = {{wan:String}} AND TimeReceived {BETWEEN}
      AND ((InIfBoundary = 'external' AND DstNetRole = {{lan:String}})
        OR (OutIfBoundary = 'external' AND SrcNetRole = {{lan:String}}))
)"""

# ...with the website each flow went to: the domain that device last looked up
# for that remote IP (a day of lookups back, for connections opened before the
# window). No match = site ''.
MATCHED = f"""{WAN},
dips AS (
    SELECT client, ip, t AS dt, site FROM netview.dns_ips
    WHERE t BETWEEN toDateTime({{start:UInt32}}) - INTERVAL 1 DAY AND toDateTime({{end:UInt32}})
),
matched AS (
    SELECT w.t AS t, w.dl AS dl, w.local AS local, w.remote AS remote, w.ras AS ras, w.rcc AS rcc,
           w.rport AS rport, w.Proto AS Proto, w.b AS b, d.site AS site
    FROM wan AS w ASOF LEFT JOIN dips AS d
      ON w.local = d.client AND w.remote = d.ip AND w.t >= d.dt
)"""
UNMATCHED = f"""{WAN},
matched AS (SELECT t, dl, local, remote, ras, rcc, rport, Proto, b, '' AS site FROM wan)"""

# LAN-to-LAN flows from the Proxmox nodes' softflowd.
LAN = f"""
lanf AS (
    SELECT TimeReceived AS t, ExporterName AS exp, SrcAddr, DstAddr, SrcPort, DstPort, Proto,
           Bytes * SamplingRate AS b
    FROM flows
    WHERE ExporterName IN {{lanexp:Array(String)}} AND TimeReceived {BETWEEN}
      AND SrcNetRole = {{lan:String}} AND DstNetRole = {{lan:String}}
)"""

# A visit: one device using a site within a 5-minute window - so the sites a
# device looks up every few seconds in the background don't top the list.
VISITS = "uniq(client, toStartOfInterval(t, INTERVAL 5 MINUTE))"
DNS_IN = f"t {BETWEEN}"

# Drill-down filters: query parameter -> (condition on `matched`, check).
FILTERS = {
    "host": ("local = toIPv6({f_host:String})", check_ip),
    "remote": ("remote = toIPv6({f_remote:String})", check_ip),
    "asn": ("ras = {f_asn:UInt32}", int),
    "country": ("rcc = {f_country:String}", check_country),
    "svc": ("Proto = {f_proto:UInt32} AND rport = {f_port:UInt32}", check_svc),
    "site": ("site = {f_site:String}", check_site),
}

# What a breakdown chart can be split by: dimension -> key on `matched`.
BY = {
    "host": IP.format(col="local"),
    "remote": IP.format(col="remote"),
    "asn": f"concat('AS', toString(ras), ' ', {ASN_NAME})",
    "country": "rcc",
    "svc": "concat(toString(Proto), '/', toString(rport))",
    "site": "site",
}


def matched():
    return UNMATCHED if not dns.status["enabled"] else MATCHED


def base_params(start, end):
    return {"wan": WAN_EXPORTER, "lanexp": LAN_EXPORTERS, "lan": LAN_ROLE, "start": start, "end": end}


def filters(request):
    """WHERE clause + params from the request's filter parameters."""
    conds, params, applied = ["1"], {}, {}
    for name, (cond, check) in FILTERS.items():
        raw = request.query_params.get(name)
        if raw is None or raw == "":
            continue
        try:
            value = check(raw)
        except ValueError:
            raise HTTPException(400, f"bad {name}")
        if name == "svc":
            params["f_proto"], params["f_port"] = value
        else:
            params[f"f_{name}"] = value
        conds.append(cond)
        applied[name] = raw
    return " AND ".join(conds), params, applied


# ------------------------------------------------------------------ names
_names = {"mtime": None, "data": {}}


def names():
    """names.json, re-read when the playbook rewrites it."""
    try:
        mtime = NAMES_FILE.stat().st_mtime
    except OSError:
        return {}
    if mtime != _names["mtime"]:
        try:
            doc = json.loads(NAMES_FILE.read_text())
            data = dict(doc.get("names", {}))
            for ip, name in doc.get("static", {}).items():
                data[str(ip)] = {"name": name, "mac": data.get(str(ip), {}).get("mac", ""), "source": "static"}
            _names["data"] = data
        except (OSError, ValueError, AttributeError):
            _names["data"] = {}
        _names["mtime"] = mtime
    return _names["data"]


def name_of(ip):
    return names().get(ip, {}).get("name", "")


def name_rows(rows, *cols):
    """Add <col>_name next to each IP column."""
    for row in rows:
        for c in cols:
            row[f"{c}_name"] = name_of(row[c])
    return rows


def buckets(start, end, step):
    return list(range(start // step * step, end // step * step + 1, step))


def series(rows, start, end, step):
    """Chart points with the empty buckets filled in (bits/s)."""
    by_t = {r["ts"]: r for r in rows}
    ts = buckets(start, end, step)
    return {"t": ts,
            "down": [by_t.get(t, {}).get("down", 0) * 8 / step for t in ts],
            "up": [by_t.get(t, {}).get("up", 0) * 8 / step for t in ts]}


def win_out(start, end, step):
    return {"start": start, "end": end, "step": step}


# ------------------------------------------------------------------ API
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/explore")
def explore(request: Request, range: str = "6h",
            frm: Optional[int] = Query(None, alias="from"), to: Optional[int] = None):
    """Internet traffic for any filter combination: chart, totals, and the top
    hosts / remotes / networks / countries / services / websites behind it."""
    start, end, step = window(range, frm, to)
    where, fp, applied = filters(request)
    p = base_params(start, end) | fp | {"step": step}
    # One pass over the flows (the website match is the costly part) for the
    # chart, the totals and all six top lists, as grouping sets. grouping():
    # bit set = column NOT grouped, first argument = highest bit.
    cols = ["local", "remote", "ras", "rcc", "Proto", "rport", "site", "ts"]
    full = (1 << len(cols)) - 1
    gid = {name: full ^ sum(1 << (len(cols) - 1 - cols.index(c)) for c in grouped)
           for name, grouped in {"hosts": ["local"], "remotes": ["remote"], "asns": ["ras"],
                                 "countries": ["rcc"], "services": ["Proto", "rport"],
                                 "sites": ["site"], "chart": ["ts"], "totals": []}.items()}
    rows = query(f"""WITH {matched()}
        SELECT grouping({", ".join(cols)}) AS g,
               toUInt32(toStartOfInterval(t, toIntervalSecond({{step:UInt32}}))) AS ts,
               {IP.format(col='local')} AS host, {IP.format(col='remote')} AS rip,
               ras AS asn, {ASN_NAME} AS asn_name, rcc AS country,
               Proto AS proto_num, {PROTO} AS proto, rport AS port, {SERVICE} AS service, site,
               sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up, count() AS flows,
               uniq(local) AS hosts, uniq(remote) AS remotes, sumIf(b, site = '') AS unnamed,
               any(ras) AS any_asn, any(rcc) AS any_cc
        FROM matched WHERE {where}
        GROUP BY GROUPING SETS ((local), (remote), (ras), (rcc), (Proto, rport), (site), (ts), ())
        ORDER BY down + up DESC
        LIMIT {MAX_POINTS + 10} BY g""", **p)
    tops = {name: [] for name in gid}
    by_g = {v: k for k, v in gid.items()}
    for r in rows:
        name = by_g.get(r["g"])
        if name == "remotes":
            r["asn"], r["country"] = r["any_asn"], r["any_cc"]
            r["asn_name"] = ""  # filled below, per AS
        if name:
            tops[name].append(r)
    chart = tops.pop("chart")
    totals = (tops.pop("totals") or [{"down": 0, "up": 0, "flows": 0, "hosts": 0, "remotes": 0, "unnamed": 0}])[0]
    tops = {name: rows[:15] for name, rows in tops.items()}
    asn_names = {r["asn"]: r["asn_name"] for r in tops["asns"]}
    missing = {r["asn"] for r in tops["remotes"] if r["asn"] not in asn_names}
    if missing:
        for r in query("SELECT a AS asn, dictGetOrDefault('asns', 'name', toUInt32(a), '') AS name "
                       "FROM (SELECT arrayJoin({asns:Array(UInt32)}) AS a)", asns=sorted(missing)):
            asn_names[r["asn"]] = r["name"]
    for r in tops["remotes"]:
        r["asn_name"] = asn_names.get(r["asn"], "")
    name_rows(tops["hosts"], "host")
    return {"window": win_out(start, end, step), "filters": applied, "dns": dns.status["enabled"],
            "series": series(chart, start, end, step), "totals": totals, "tops": tops,
            "names": {k: name_of(v) for k, v in applied.items() if k == "host"}}


@app.get("/api/breakdown")
def breakdown(request: Request, by: str = "host", range: str = "6h",
              frm: Optional[int] = Query(None, alias="from"), to: Optional[int] = None):
    """Stacked chart: traffic over time split by one dimension - the top STACK
    keys, the rest summed as "other" (bits/s, both directions)."""
    if by not in BY:
        raise HTTPException(400, f"by must be one of {list(BY)}")
    start, end, step = window(range, frm, to)
    where, fp, applied = filters(request)
    p = base_params(start, end) | fp | {"step": step}
    key = BY[by]
    rows = query(f"""WITH {matched()}
        SELECT toUInt32(toStartOfInterval(t, toIntervalSecond({{step:UInt32}}))) AS ts,
               if(k IN (SELECT {key} FROM matched WHERE {where}
                        GROUP BY {key} ORDER BY sum(b) DESC LIMIT {STACK}), k, '~other~') AS key,
               sum(b) AS bytes
        FROM (SELECT t, b, {key} AS k FROM matched WHERE {where})
        GROUP BY ts, key ORDER BY ts""", **p)
    ts = buckets(start, end, step)
    index = {t: i for i, t in enumerate(ts)}
    data, totals = {}, {}
    for r in rows:
        k = "other" if r["key"] == "~other~" else r["key"]
        data.setdefault(k, [0.0] * len(ts))
        if r["ts"] in index:
            data[k][index[r["ts"]]] += r["bytes"] * 8 / step
        totals[k] = totals.get(k, 0) + r["bytes"]
    keys = sorted((k for k in data if k != "other"), key=lambda k: -totals[k]) + (["other"] if "other" in data else [])
    out = [{"key": k, "label": label(by, k), "bytes": totals[k], "values": data[k]} for k in keys]
    return {"window": win_out(start, end, step), "by": by, "filters": applied, "t": ts, "series": out}


def label(by, key):
    if key == "other":
        return "Everything else"
    if by == "host":
        return name_of(key) or key
    if by == "site":
        return key or "(no DNS name)"
    if by == "svc":
        proto, _, port = key.partition("/")
        return {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(proto, proto) + "/" + port
    return key


@app.get("/api/hosts")
def hosts(range: str = "24h", frm: Optional[int] = Query(None, alias="from"), to: Optional[int] = None):
    start, end, step = window(range, frm, to)
    p = base_params(start, end)
    wan = query(f"""WITH {WAN}
        SELECT {IP.format(col='local')} AS ip, sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up,
               count() AS flows, uniq(remote) AS remotes, toUInt32(max(t)) AS last
        FROM wan GROUP BY local""", **p)
    # Per host and exporter first, then the busiest exporter (see the docstring).
    lan = query(f"""WITH {LAN}
        SELECT ip, max(bytes) AS lan, max(peers) AS lan_peers, max(last) AS last
        FROM (SELECT {IP.format(col='pair.1')} AS ip, exp, sum(b) AS bytes,
                     uniq(pair.2) AS peers, toUInt32(max(t)) AS last
              FROM lanf ARRAY JOIN [(SrcAddr, DstAddr), (DstAddr, SrcAddr)] AS pair
              GROUP BY ip, exp)
        GROUP BY ip""", **p)
    merged = {}
    for r in wan:
        merged[r["ip"]] = r | {"lan": 0, "lan_peers": 0}
    for r in lan:
        m = merged.setdefault(r["ip"], {"ip": r["ip"], "down": 0, "up": 0, "flows": 0,
                                        "remotes": 0, "last": 0})
        m["lan"], m["lan_peers"] = r["lan"], r["lan_peers"]
        m["last"] = max(m["last"], r["last"])
    n = names()
    rows = sorted(merged.values(), key=lambda r: r["down"] + r["up"] + r["lan"], reverse=True)
    for r in rows:
        r["name"] = n.get(r["ip"], {}).get("name", "")
        r["mac"] = n.get(r["ip"], {}).get("mac", "")
    return {"window": win_out(start, end, step), "hosts": rows}


@app.get("/api/host/{ip}")
def host(ip: str, range: str = "24h", frm: Optional[int] = Query(None, alias="from"), to: Optional[int] = None):
    """What only a device page has: its LAN peers and the websites it visited."""
    ip = check_ip(ip)
    start, end, step = window(range, frm, to)
    p = base_params(start, end) | {"ip": ip}
    # LAN peers: the other side's port is the likely service (ours is ephemeral).
    lan_peers = query(f"""WITH {LAN}
        SELECT ip, max(sent) AS sent, max(received) AS received,
               arrayStringConcat(arraySlice(arraySort(groupUniqArrayArray(ports)), 1, 6), ' ') AS ports
        FROM (SELECT {IP.format(col="if(SrcAddr = toIPv6({ip:String}), DstAddr, SrcAddr)")} AS ip, exp,
                     sumIf(b, SrcAddr = toIPv6({{ip:String}})) AS sent,
                     sumIf(b, DstAddr = toIPv6({{ip:String}})) AS received,
                     groupUniqArray(toString(if(SrcAddr = toIPv6({{ip:String}}), DstPort, SrcPort))) AS ports
              FROM lanf
              WHERE SrcAddr = toIPv6({{ip:String}}) OR DstAddr = toIPv6({{ip:String}})
              GROUP BY ip, exp)
        GROUP BY ip ORDER BY sent + received DESC LIMIT 25""", **p)
    sites = [] if not dns.status["enabled"] else site_rows(start, end, ip=ip, limit=50)
    info = names().get(ip, {})
    return {"window": win_out(start, end, step), "ip": ip, "name": info.get("name", ""),
            "mac": info.get("mac", ""), "lan_peers": name_rows(lan_peers, "ip"),
            "sites": sites, "dns": dns.status["enabled"]}


def site_rows(start, end, ip=None, limit=300):
    """Websites by visits, with their traffic - the whole LAN, or one device."""
    p = base_params(start, end) | {"ip": ip or ""}
    me = "AND client = toIPv6({ip:String})" if ip else ""
    visits = query(f"""
        SELECT site, {VISITS} AS visits, uniq(client) AS devices, count() AS lookups,
               toUInt32(max(t)) AS last
        FROM netview.dns WHERE {DNS_IN} {me}
        GROUP BY site ORDER BY visits DESC LIMIT {int(limit)}""", **p)
    traffic = query(f"""WITH {MATCHED}
        SELECT site, sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up FROM matched
        {"WHERE local = toIPv6({ip:String})" if ip else ""}
        GROUP BY site""", **p)
    by_site = {r["site"]: r for r in traffic}
    return [r | {"down": by_site.get(r["site"], {}).get("down", 0), "up": by_site.get(r["site"], {}).get("up", 0)}
            for r in visits]


@app.get("/api/sites")
def sites(range: str = "24h", frm: Optional[int] = Query(None, alias="from"), to: Optional[int] = None):
    start, end, step = window(range, frm, to)
    if not dns.status["enabled"]:
        return {"window": win_out(start, end, step), "dns": False, "sites": []}
    return {"window": win_out(start, end, step), "dns": True, "sites": site_rows(start, end)}


@app.get("/api/site/{site}")
def site(site: str, range: str = "24h", frm: Optional[int] = Query(None, alias="from"), to: Optional[int] = None):
    """What only a website page has: visits per device and the names looked up."""
    site = check_site(site)
    start, end, step = window(range, frm, to)
    if not dns.status["enabled"]:
        raise HTTPException(404, "the DNS collector isn't set up")
    p = base_params(start, end) | {"site": site}
    devices = query(f"""
        SELECT {IP.format(col='client')} AS ip, {VISITS} AS visits, count() AS lookups,
               toUInt32(min(t)) AS first, toUInt32(max(t)) AS last
        FROM netview.dns WHERE {DNS_IN} AND site = {{site:String}}
        GROUP BY client ORDER BY visits DESC""", **p)
    domains = query(f"""
        SELECT domain, count() AS lookups, uniq(client) AS devices, toUInt32(max(t)) AS last
        FROM netview.dns WHERE {DNS_IN} AND site = {{site:String}}
        GROUP BY domain ORDER BY lookups DESC LIMIT 30""", **p)
    return {"window": win_out(start, end, step), "site": site,
            "devices": name_rows(devices, "ip"), "domains": domains}


@app.get("/api/new")
def new():
    """First seen in the last 24 h, within the raw flows kept (7 days)."""
    now = int(time.time())
    p = base_params(now - KEEP, now)
    start = query("SELECT toUInt32(min(TimeReceived)) AS t FROM flows")[0]["t"]
    new_hosts = query(f"""
        SELECT {IP.format(col='h')} AS ip, toUInt32(min(t)) AS first, sum(b) AS bytes
        FROM (SELECT SrcAddr AS h, TimeReceived AS t, Bytes * SamplingRate AS b FROM flows
              WHERE SrcNetRole = {{lan:String}} AND TimeReceived {BETWEEN}
              UNION ALL
              SELECT DstAddr, TimeReceived, Bytes * SamplingRate FROM flows
              WHERE DstNetRole = {{lan:String}} AND TimeReceived {BETWEEN})
        GROUP BY h HAVING first > now() - INTERVAL 1 DAY ORDER BY first DESC""", **p)
    new_asns = query(f"""WITH {WAN}
        SELECT {IP.format(col='local')} AS ip, ras AS asn, {ASN_NAME} AS name,
               toUInt32(min(t)) AS first, sum(b) AS bytes, uniq(remote) AS remotes
        FROM wan WHERE ras != 0 GROUP BY local, ras
        HAVING first > now() - INTERVAL 1 DAY ORDER BY bytes DESC LIMIT 50""", **p)
    new_countries = query(f"""WITH {WAN}
        SELECT {IP.format(col='local')} AS ip, rcc AS country,
               toUInt32(min(t)) AS first, sum(b) AS bytes, uniq(remote) AS remotes
        FROM wan WHERE rcc != '' GROUP BY local, rcc
        HAVING first > now() - INTERVAL 1 DAY ORDER BY bytes DESC LIMIT 50""", **p)
    return {"history_start": start, "hosts": name_rows(new_hosts, "ip"),
            "asns": name_rows(new_asns, "ip"), "countries": name_rows(new_countries, "ip")}


@app.get("/api/live")
def live_points(since: int = 0):
    if not live.status["enabled"]:
        raise HTTPException(404, "live data isn't set up")
    return {"now": int(time.time()), "interfaces": live.points(since), "error": live.status["last_error"]}


@app.get("/api/live/top")
def live_top():
    if not live.status["enabled"]:
        raise HTTPException(404, "live data isn't set up")
    top = live.top()
    hosts = [h | {"name": name_of(h["ip"]),
                  "peers": [x | {"name": name_of(x["ip"])} for x in h["peers"]]} for h in top["hosts"]]
    return {"t": top["t"], "hosts": hosts, "error": live.status["top_error"]}


@app.get("/api/live/flows")
def live_flows(seconds: int = 120):
    """The latest internet conversations (device, remote, service), newest
    first, from the flows - the firewall reports a long connection once a
    minute, so this trails real time by up to that."""
    seconds = max(60, min(seconds, 900))
    now = int(time.time())
    rows = query(f"""WITH {matched()}
        SELECT {IP.format(col='local')} AS host, {IP.format(col='remote')} AS rip,
               Proto AS proto_num, {PROTO} AS proto, rport AS port, {SERVICE} AS service,
               ras AS asn, {ASN_NAME} AS asn_name, any(rcc) AS country, anyIf(site, site != '') AS site,
               sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up, count() AS flows, toUInt32(max(t)) AS last
        FROM matched GROUP BY local, remote, Proto, rport, ras
        ORDER BY last DESC, down + up DESC LIMIT 2000""", **base_params(now - seconds, now))
    return {"seconds": seconds, "now": now, "flows": name_rows(rows, "host")}


@app.get("/api/health")
def health():
    return {"clickhouse": query("SELECT version() AS v")[0]["v"], "names": len(names()),
            "wan_exporter": WAN_EXPORTER, "lan_exporters": LAN_EXPORTERS, "dns": dns.status,
            "live": live.status}
