"""netview - our own traffic views over Akvorado's ClickHouse.

Akvorado collects and stores the flows (OPNsense + softflowd -> ClickHouse);
this only reads them, with views Akvorado's console doesn't have: device names
instead of IPs, "what is this host doing", and what's new today.

Which exporter answers what (see akvorado_stack.yml):
  internet traffic   the firewall only (WAN_EXPORTER) - it exports its LAN
                     interface, so each internet flow is counted once; the
                     side towards an external interface is the remote one.
  LAN-to-LAN         the Proxmox nodes' softflowd (LAN_EXPORTERS). A flow
                     between VMs on two nodes is seen by both, so per-host LAN
                     figures take the busiest exporter rather than the sum.

Read-only: every query runs with readonly=2. Device names come from
names.json, written by the playbook from the firewall's DHCP leases.
"""
import ipaddress
import json
import os
import pathlib
import time

import requests
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
NAMES_FILE = pathlib.Path(os.environ.get("NAMES_FILE", "/data/names.json"))
WAN_EXPORTER = os.environ.get("WAN_EXPORTER", "opnsense")
LAN_EXPORTERS = [e for e in os.environ.get("LAN_EXPORTERS", "pve5,pve6").split(",") if e]
LAN_ROLE = os.environ.get("LAN_ROLE", "lan")  # Src/DstNetRole of the local network
STATIC = pathlib.Path(__file__).parent / "static"

# range -> (seconds, chart step in seconds)
RANGES = {"1h": (3600, 60), "6h": (21600, 300), "24h": (86400, 900), "7d": (604800, 3600)}

app = FastAPI(title="netview")
app.mount("/static", StaticFiles(directory=STATIC), name="static")


# ------------------------------------------------------------------ ClickHouse
def query(sql, **params):
    """Run one SELECT; {name:Type} placeholders are bound server-side."""
    args = {"readonly": 2, "max_execution_time": 30, "default_format": "JSON",
            "output_format_json_quote_64bit_integers": 0}
    args.update({f"param_{k}": v if not isinstance(v, list) else "[" + ",".join(f"'{x}'" for x in v) + "]"
                 for k, v in params.items()})
    r = requests.post(CH_URL, params=args, data=sql.encode(), timeout=40)
    if r.status_code != 200:
        raise HTTPException(502, f"ClickHouse: {r.text[:300]}")
    return r.json()["data"]


def window(rng):
    if rng not in RANGES:
        raise HTTPException(400, f"range must be one of {list(RANGES)}")
    return RANGES[rng]


def check_ip(ip):
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        raise HTTPException(400, "not an IP address")


IP = "replaceRegexpOne(IPv6NumToString({col}), '^::ffff:', '')"

# Internet flows from the firewall, turned around so every row reads from the
# LAN host's side: local/remote address, remote AS/country/port, direction.
WAN = f"""
wan AS (
    SELECT TimeReceived AS t,
           InIfBoundary = 'external' AS dl,
           if(dl, DstAddr, SrcAddr) AS local, if(dl, SrcAddr, DstAddr) AS remote,
           if(dl, SrcAS, DstAS) AS ras, if(dl, SrcCountry, DstCountry) AS rcc,
           if(dl, SrcPort, DstPort) AS rport, Proto,
           Bytes * SamplingRate AS b
    FROM flows
    WHERE ExporterName = {{wan:String}}
      AND TimeReceived > now() - INTERVAL {{secs:UInt32}} SECOND
      AND ((InIfBoundary = 'external' AND DstNetRole = {{lan:String}})
        OR (OutIfBoundary = 'external' AND SrcNetRole = {{lan:String}}))
)"""

# LAN-to-LAN flows from the Proxmox nodes' softflowd.
LAN = """
lanf AS (
    SELECT TimeReceived AS t, ExporterName AS exp, SrcAddr, DstAddr, SrcPort, DstPort, Proto,
           Bytes * SamplingRate AS b
    FROM flows
    WHERE ExporterName IN {lanexp:Array(String)}
      AND TimeReceived > now() - INTERVAL {secs:UInt32} SECOND
      AND SrcNetRole = {lan:String} AND DstNetRole = {lan:String}
)"""

SERVICE = ("multiIf(Proto = 6, dictGetOrDefault('tcp', 'name', toUInt64(rport), ''), "
           "Proto = 17, dictGetOrDefault('udp', 'name', toUInt64(rport), ''), '')")
PROTO = "dictGetOrDefault('protocols', 'name', toUInt64(Proto), toString(Proto))"
ASN_NAME = "dictGetOrDefault('asns', 'name', toUInt32(ras), '')"


def base_params(secs):
    return {"wan": WAN_EXPORTER, "lanexp": LAN_EXPORTERS, "lan": LAN_ROLE, "secs": secs}


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


def name_rows(rows, *cols):
    """Add <col>_name next to each IP column."""
    n = names()
    for row in rows:
        for c in cols:
            row[f"{c}_name"] = n.get(row[c], {}).get("name", "")
    return rows


def series(rows, secs, step):
    """Chart points with the empty buckets filled in (bits/s)."""
    end = int(time.time()) // step * step
    start = end - secs // step * step
    by_t = {r["ts"]: r for r in rows}
    out = {"t": [], "down": [], "up": []}
    for t in range(start, end + 1, step):
        r = by_t.get(t, {})
        out["t"].append(t)
        out["down"].append(r.get("down", 0) * 8 / step)
        out["up"].append(r.get("up", 0) * 8 / step)
    return out


# ------------------------------------------------------------------ API
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/overview")
def overview(range: str = "6h"):
    secs, step = window(range)
    p = base_params(secs) | {"step": step}
    chart = query(f"""WITH {WAN}
        SELECT toUInt32(toStartOfInterval(t, toIntervalSecond({{step:UInt32}}))) AS ts,
               sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up
        FROM wan GROUP BY ts ORDER BY ts""", **p)
    totals = query(f"""WITH {WAN}
        SELECT sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up, count() AS flows,
               uniq(local) AS hosts, uniq(remote) AS remotes
        FROM wan""", **p)[0]
    hosts = query(f"""WITH {WAN}
        SELECT {IP.format(col='local')} AS ip, sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up,
               count() AS flows, uniq(remote) AS remotes
        FROM wan GROUP BY local ORDER BY down + up DESC LIMIT 10""", **p)
    asns = query(f"""WITH {WAN}
        SELECT ras AS asn, {ASN_NAME} AS name, sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up,
               uniq(local) AS hosts
        FROM wan WHERE ras != 0 GROUP BY ras ORDER BY down + up DESC LIMIT 10""", **p)
    countries = query(f"""WITH {WAN}
        SELECT rcc AS country, sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up, uniq(local) AS hosts
        FROM wan WHERE rcc != '' GROUP BY rcc ORDER BY down + up DESC LIMIT 10""", **p)
    services = query(f"""WITH {WAN}
        SELECT {PROTO} AS proto, rport AS port, {SERVICE} AS service,
               sum(b) AS bytes, uniq(local) AS hosts
        FROM wan GROUP BY Proto, rport ORDER BY bytes DESC LIMIT 10""", **p)
    return {"range": range, "series": series(chart, secs, step), "totals": totals,
            "hosts": name_rows(hosts, "ip"), "asns": asns, "countries": countries,
            "services": services}


@app.get("/api/hosts")
def hosts(range: str = "24h"):
    secs, _ = window(range)
    p = base_params(secs)
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
    return {"range": range, "hosts": rows}


@app.get("/api/host/{ip}")
def host(ip: str, range: str = "24h"):
    ip = check_ip(ip)
    secs, step = window(range)
    p = base_params(secs) | {"step": step, "ip": ip}
    me = "local = toIPv6({ip:String})"
    chart = query(f"""WITH {WAN}
        SELECT toUInt32(toStartOfInterval(t, toIntervalSecond({{step:UInt32}}))) AS ts,
               sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up
        FROM wan WHERE {me} GROUP BY ts ORDER BY ts""", **p)
    peers = query(f"""WITH {WAN}
        SELECT {IP.format(col='remote')} AS ip, any(ras) AS asn,
               dictGetOrDefault('asns', 'name', toUInt32(any(ras)), '') AS asn_name,
               any(rcc) AS country, sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up, count() AS flows,
               arrayStringConcat(arraySlice(arraySort(groupUniqArray(toString(rport))), 1, 6), ' ') AS ports,
               toUInt32(max(t)) AS last
        FROM wan WHERE {me} GROUP BY remote ORDER BY down + up DESC LIMIT 25""", **p)
    services = query(f"""WITH {WAN}
        SELECT {PROTO} AS proto, rport AS port, {SERVICE} AS service,
               sumIf(b, dl) AS down, sumIf(b, NOT dl) AS up, uniq(remote) AS remotes
        FROM wan WHERE {me} GROUP BY Proto, rport ORDER BY down + up DESC LIMIT 15""", **p)
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
    info = names().get(ip, {})
    return {"range": range, "ip": ip, "name": info.get("name", ""), "mac": info.get("mac", ""),
            "series": series(chart, secs, step), "peers": peers, "services": services,
            "lan_peers": name_rows(lan_peers, "ip")}


@app.get("/api/new")
def new():
    """First seen in the last 24 h, within the raw flows kept (7 days)."""
    p = base_params(7 * 86400)
    start = query("SELECT toUInt32(min(TimeReceived)) AS t FROM flows")[0]["t"]
    new_hosts = query(f"""
        SELECT {IP.format(col='h')} AS ip, toUInt32(min(t)) AS first, sum(b) AS bytes
        FROM (SELECT SrcAddr AS h, TimeReceived AS t, Bytes * SamplingRate AS b FROM flows
              WHERE SrcNetRole = {{lan:String}} AND TimeReceived > now() - INTERVAL {{secs:UInt32}} SECOND
              UNION ALL
              SELECT DstAddr, TimeReceived, Bytes * SamplingRate FROM flows
              WHERE DstNetRole = {{lan:String}} AND TimeReceived > now() - INTERVAL {{secs:UInt32}} SECOND)
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


@app.get("/api/health")
def health():
    return {"clickhouse": query("SELECT version() AS v")[0]["v"], "names": len(names()),
            "wan_exporter": WAN_EXPORTER, "lan_exporters": LAN_EXPORTERS}
