"""Sentry Lens: what the collectors read over SNMP - and the credentials they
read it with.

Credentials (SNMP v2c communities, v3 users) are added by admins, kept
encrypted (auth's settings key), each limited to subnets. A collector gets
the ones for its subnets in its config, encrypted with a key derived from its
own key (which this side keeps encrypted too - assets.py), so they're safe on
plain HTTP. It tries them on every device it finds; the ones that answer it
reads (system, ENTITY-MIB, IF-MIB, the bridge's MAC table, ARP, LLDP/CDP) at
each sweep, and polls their interface counters every few minutes.

  netview.credentials       newest version wins; the secret part encrypted
  netview.snmp_devices      a device's latest reading (newest version wins)
  netview.snmp_interfaces   its interfaces (newest version wins)
  netview.snmp_counters     interface counters over time -> traffic, errors
  netview.snmp_fdb          the MACs each port learned (latest per device)
  netview.snmp_arp          its ARP table (latest per device)
  netview.snmp_lldp         its LLDP / CDP neighbors (latest per device)

A device is keyed like the assets: its MAC (from the sweep, matched on IP),
else "ip:<address>".
"""
import base64
import hashlib
import ipaddress
import json
import re
import time

from cryptography.fernet import Fernet
from fastapi import APIRouter, HTTPException, Request

import assets
import auth
import creds

router = APIRouter()
KEEP_DAYS = 90

# What collectors read beyond the basics, from standard MIBs (and a few vendor
# ones) - sent with their config, read generically (collector/snmp.go
# readProfiles), kept in netview.snmp_tables and shown on the device's page.
# Columns: [name, OID] - relative to base, or absolute when it starts with ".";
# the first column tells whether a device has the table.
PROFILES = [
    # Printer-MIB (RFC 3805): ink / toner / drums / waste, their colour, the page count, the state.
    {"id": "supplies", "base": ".1.3.6.1.2.1.43.11.1.1", "columns": [
        ["level", "9"], ["max", "8"], ["descr", "6"], ["type", "5"], ["class", "4"], ["colorant", "3"], ["unit", "7"]]},
    {"id": "colorants", "base": ".1.3.6.1.2.1.43.12.1.1", "columns": [["name", "4"]]},
    {"id": "pages", "base": ".1.3.6.1.2.1.43.10.2.1", "columns": [["count", "4"], ["unit", "3"]]},
    {"id": "printer", "base": ".1.3.6.1.2.1.25.3.5.1", "columns": [["status", "1"], ["errors", "2"]]},
    # HOST-RESOURCES-MIB (RFC 2790): disks, memory, CPU load.
    {"id": "storage", "base": ".1.3.6.1.2.1.25.2.3.1", "columns": [
        ["descr", "3"], ["type", "2"], ["unit", "4"], ["size", "5"], ["used", "6"]]},
    {"id": "cpu", "base": ".1.3.6.1.2.1.25.3.3.1", "columns": [["load", "2"]]},
    # ENTITY-SENSOR-MIB (RFC 3433): temperatures, fans, voltages, power - named from ENTITY-MIB.
    {"id": "sensors", "base": ".1.3.6.1.2.1.99.1.1.1", "columns": [
        ["value", "4"], ["type", "1"], ["scale", "2"], ["precision", "3"], ["status", "5"],
        ["name", ".1.3.6.1.2.1.47.1.1.1.1.7"]]},
    # UPS-MIB (RFC 1628), and APC's PowerNet for APC units.
    {"id": "ups", "base": ".1.3.6.1.2.1.33.1", "scalar": True, "columns": [
        ["battery_status", "2.1.0"], ["minutes_left", "2.3.0"], ["charge", "2.4.0"], ["battery_temp", "2.7.0"],
        ["on_battery_s", "2.2.0"], ["output_source", "4.1.0"], ["model", "1.2.0"], ["maker", "1.1.0"]]},
    {"id": "ups_output", "base": ".1.3.6.1.2.1.33.1.4.4.1", "columns": [["load", "5"], ["voltage", "2"], ["power_w", "4"]]},
    {"id": "apc_ups", "base": ".1.3.6.1.4.1.318.1.1.1", "scalar": True, "columns": [
        ["battery_status", "2.1.1.0"], ["charge", "2.2.1.0"], ["battery_temp", "2.2.2.0"], ["runtime_ticks", "2.2.3.0"],
        ["replace", "2.2.4.0"], ["load", "4.2.3.0"], ["output_status", "4.1.1.0"], ["model", "1.1.1.0"]]},
    # POWER-ETHERNET-MIB (RFC 3621): the PoE budget and what each port delivers.
    {"id": "poe", "base": ".1.3.6.1.2.1.105.1.3.1.1", "columns": [["power_w", "2"], ["status", "3"], ["used_w", "4"]]},
    {"id": "poe_ports", "base": ".1.3.6.1.2.1.105.1.1.1", "columns": [["admin", "3"], ["detect", "6"], ["class", "10"]]},
    # Q-BRIDGE-MIB: VLAN names, and each bridge port's untagged VLAN.
    {"id": "vlans", "base": ".1.3.6.1.2.1.17.7.1.4.3.1", "columns": [["name", "1"]]},
    {"id": "port_vlan", "base": ".1.3.6.1.2.1.17.7.1.4.5.1", "columns": [["pvid", "1"]]},
    # Synology DSM.
    {"id": "synology", "base": ".1.3.6.1.4.1.6574.1", "scalar": True, "columns": [
        ["status", "1.0"], ["temp", "2.0"], ["power", "3.0"], ["fan_system", "4.1.0"], ["fan_cpu", "4.2.0"],
        ["model", "5.1.0"], ["serial", "5.2.0"], ["version", "5.3.0"], ["upgrade", "5.4.0"]]},
    {"id": "synology_disks", "base": ".1.3.6.1.4.1.6574.2.1.1", "columns": [
        ["name", "2"], ["model", "3"], ["status", "5"], ["temp", "6"]]},
    {"id": "synology_raid", "base": ".1.3.6.1.4.1.6574.3.1.1", "columns": [["name", "2"], ["status", "3"], ["free", "4"], ["total", "5"]]},
]
PROFILE_IDS = {p["id"] for p in PROFILES}

DDL = [
    """CREATE TABLE IF NOT EXISTS netview.credentials (
        id String, name String, kind LowCardinality(String), scope Array(String), summary String,
        secret String, created DateTime, by String, deleted UInt8, ver UInt64
    ) ENGINE = ReplacingMergeTree(ver) ORDER BY id""",
    """CREATE TABLE IF NOT EXISTS netview.snmp_devices (
        key String, ip String, collector String, cred String, sys_name String, sys_descr String, sys_object_id String,
        location String, contact String, uptime_s UInt64, vendor String, model String, serial String, firmware String,
        hardware String, if_count UInt32, if_up UInt32, last_poll DateTime, ver UInt64
    ) ENGINE = ReplacingMergeTree(ver) ORDER BY key""",
    """CREATE TABLE IF NOT EXISTS netview.snmp_interfaces (
        key String, if_index UInt32, name String, descr String, alias String, type UInt32, speed_mbps UInt64,
        mac String, admin UInt8, oper UInt8, ver UInt64
    ) ENGINE = ReplacingMergeTree(ver) ORDER BY (key, if_index)""",
    f"""CREATE TABLE IF NOT EXISTS netview.snmp_counters (
        t DateTime, key String, if_index UInt32, in_octets UInt64, out_octets UInt64,
        in_errors UInt64, out_errors UInt64, oper UInt8
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (key, if_index, t) TTL t + INTERVAL {KEEP_DAYS} DAY""",
    """CREATE TABLE IF NOT EXISTS netview.snmp_fdb (
        t DateTime, key String, if_index UInt32, mac String, vlan UInt32
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (key, t) TTL t + INTERVAL 30 DAY""",
    """CREATE TABLE IF NOT EXISTS netview.snmp_arp (
        t DateTime, key String, ip String, mac String, if_index UInt32
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (key, t) TTL t + INTERVAL 30 DAY""",
    f"""CREATE TABLE IF NOT EXISTS netview.snmp_tables (
        t DateTime, key String, profile LowCardinality(String), idx String, data Map(String, String)
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (key, profile, t) TTL t + INTERVAL 30 DAY""",
    """CREATE TABLE IF NOT EXISTS netview.snmp_lldp (
        t DateTime, key String, local_if UInt32, local_port String, proto LowCardinality(String), remote_name String,
        remote_port String, remote_port_descr String, remote_chassis String, remote_mgmt String, remote_descr String
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (key, t) TTL t + INTERVAL 30 DAY""",
]
_ready = [False]


def q(sql, **params):
    if not _ready[0]:
        assets.ready()
        for d in DDL:
            assets.checks.ch(d)
        _ready[0] = True
    return assets.checks.query(sql, **params)


def insert(table, rows):
    if rows:
        q("SELECT 1")
        assets.insert(table, rows)


def _admin(request):
    if auth.ENABLED:
        auth.require_admin(request)
    u = getattr(request.state, "user", None)
    return u["email"] if u else "local"


# ------------------------------------------------------------------ credentials
# Kept by creds.py: in Sentry Lens's vault (Vaultwarden) when it has one, else here.
@router.get("/api/credentials")
def list_credentials(request: Request):
    _admin(request)
    used = {r["cred"]: r["n"] for r in q("SELECT cred, count() AS n FROM netview.snmp_devices FINAL GROUP BY cred")}
    return {"credentials": sorted((creds.public(c, used) for c in creds.all_creds().values()), key=lambda c: c["name"].lower()),
            "vault": creds.status(), "kinds": creds.KINDS}


@router.post("/api/credentials")
async def add_credential(request: Request):
    """{name, kind, scope, and the kind's fields} - kind: snmp_v2c {community},
    snmp_v3 {user, level, auth_proto, auth_pass, priv_proto, priv_pass}, ssh
    {user, password and / or private_key, port}, winrm {user, password, https,
    port}, proxmox {user: user@realm!token, secret, port}; scope: hosts or
    subnets ([] = everywhere)."""
    by = _admin(request)
    b = await request.json()
    name, kind = str(b.get("name", "")).strip()[:80], b.get("kind")
    if not name or kind not in creds.KINDS:
        raise HTTPException(400, f"a name, and a kind: {', '.join(creds.KINDS)}")
    secret, summary = creds.make_secret(b, kind)
    return {"id": creds.save({"name": name, "kind": kind, "scope": creds.check_scope(b.get("scope")), "secret": secret,
                              "summary": summary, "by": by, "created": int(time.time())})}


@router.post("/api/credentials/{cid}")
async def change_credential(request: Request, cid: str):
    """{delete: true} or {name, scope, kind, and its fields - empty secrets kept}.
    The collectors get the change at their next contact."""
    by = _admin(request)
    c = creds.all_creds().get(cid)
    if not c:
        raise HTTPException(404, "no such credential")
    b = await request.json()
    if b.get("delete"):
        creds.delete(cid)
        return {"ok": True}
    kind = b.get("kind") or c["kind"]
    if kind not in creds.KINDS:
        raise HTTPException(400, f"a kind: {', '.join(creds.KINDS)}")
    secret, summary = creds.make_secret(b, kind, c["secret"] if kind == c["kind"] else None)
    c |= {"name": str(b.get("name") or c["name"]).strip()[:80], "kind": kind, "secret": secret, "summary": summary, "by": by,
          "scope": creds.check_scope(b["scope"]) if "scope" in b else c["scope"]}
    creds.save(c, cid)
    return {"ok": True}


def collector_fernet(key):
    """What a collector's credentials are encrypted with: derived from its key (collector.py does the same)."""
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(b"sentry-lens-collector-creds:" + key.encode()).digest()))


def for_collector(c):
    """The credentials for this collector (creds.py), encrypted for it ('' if it can't get them)."""
    if not c.get("key_enc"):
        return "", 0
    out = creds.for_collector(c, c.get("version", ""))
    key = auth._fernet.decrypt(c["key_enc"].encode()).decode()
    return collector_fernet(key).encrypt(json.dumps(out).encode()).decode(), len(out)


# ------------------------------------------------------------------ the collector's readings
ENTERPRISES = {9: "Cisco", 11: "HP", 43: "3Com", 171: "D-Link", 311: "Microsoft", 2011: "Huawei", 2636: "Juniper", 4413: "Broadcom",
               4526: "Netgear", 6876: "VMware", 8072: "net-snmp", 11863: "TP-Link", 12356: "Fortinet", 14988: "MikroTik",
               25506: "HPE / H3C", 30065: "Arista", 41112: "Ubiquiti", 50536: "TrueNAS", 6574: "Synology", 24681: "QNAP", 674: "Dell",
               2: "IBM", 1588: "Brocade", 3375: "F5", 25461: "Palo Alto", 8741: "SonicWall", 12325: "pfSense / BSD", 10002: "Ubiquiti"}


def vendor_of(oid):
    m = re.match(r"\.?1\.3\.6\.1\.4\.1\.(\d+)", oid or "")
    return ENTERPRISES.get(int(m.group(1)), f"enterprise {m.group(1)}") if m else ""


def key_for(ip):
    a = q("SELECT key FROM netview.assets FINAL WHERE ip = {ip:String} AND mac != '' LIMIT 1", ip=ip)
    return a[0]["key"] if a else f"ip:{ip}"


def ingest(c, b):
    """A collector's SNMP readings: {devices: [{ip, cred, system, entity, interfaces, fdb, arp, neighbors}]}."""
    now = int(time.time())
    devs, ifs, fdb, arp, nb, tab = [], [], [], [], [], []
    for d in (b.get("devices") or [])[:5000]:
        try:
            ip = str(ipaddress.ip_address(d.get("ip", "")))
        except ValueError:
            continue
        key = key_for(ip)
        s, e = d.get("system") or {}, d.get("entity") or {}
        interfaces = d.get("interfaces") or []
        devs.append({"key": key, "ip": ip, "collector": c["id"], "cred": str(d.get("cred", ""))[:40],
                     "sys_name": str(s.get("name", ""))[:200], "sys_descr": str(s.get("descr", ""))[:500],
                     "sys_object_id": str(s.get("object_id", ""))[:120], "location": str(s.get("location", ""))[:200],
                     "contact": str(s.get("contact", ""))[:200], "uptime_s": int(s.get("uptime_s") or 0),
                     "vendor": vendor_of(s.get("object_id", "")) or str(e.get("mfg", ""))[:80],
                     "model": str(e.get("model", ""))[:120], "serial": str(e.get("serial", ""))[:80],
                     "firmware": str(e.get("firmware", ""))[:120], "hardware": str(e.get("hardware", ""))[:80],
                     "if_count": len(interfaces), "if_up": sum(1 for i in interfaces if i.get("oper") == 1),
                     "last_poll": now, "ver": time.time_ns()})
        for i in interfaces[:2000]:
            ifs.append({"key": key, "if_index": int(i.get("index", 0)), "name": str(i.get("name", ""))[:120],
                        "descr": str(i.get("descr", ""))[:200], "alias": str(i.get("alias", ""))[:200], "type": int(i.get("type") or 0),
                        "speed_mbps": int(i.get("speed_mbps") or 0), "mac": str(i.get("mac", ""))[:17],
                        "admin": int(i.get("admin") or 0), "oper": int(i.get("oper") or 0), "ver": time.time_ns()})
        fdb += [{"t": now, "key": key, "if_index": int(f.get("if_index") or 0), "mac": str(f.get("mac", "")).upper()[:17],
                 "vlan": int(f.get("vlan") or 0)} for f in (d.get("fdb") or [])[:50000]]
        arp += [{"t": now, "key": key, "ip": str(a.get("ip", ""))[:45], "mac": str(a.get("mac", "")).upper()[:17],
                 "if_index": int(a.get("if_index") or 0)} for a in (d.get("arp") or [])[:50000]]
        nb += [{"t": now, "key": key, "local_if": int(n.get("local_if") or 0), "local_port": str(n.get("local_port", ""))[:120],
                "proto": n.get("proto", "lldp")[:8], "remote_name": str(n.get("remote_name", ""))[:200],
                "remote_port": str(n.get("remote_port", ""))[:120], "remote_port_descr": str(n.get("remote_port_descr", ""))[:200],
                "remote_chassis": str(n.get("remote_chassis", ""))[:60], "remote_mgmt": str(n.get("remote_mgmt", ""))[:45],
                "remote_descr": str(n.get("remote_descr", ""))[:300]} for n in (d.get("neighbors") or [])[:2000]]
        for prof, rows in (d.get("tables") or {}).items():
            if prof in PROFILE_IDS and isinstance(rows, dict):
                tab += [{"t": now, "key": key, "profile": prof, "idx": str(i)[:60],
                         "data": {str(k)[:40]: str(v)[:300] for k, v in row.items()}}
                        for i, row in list(rows.items())[:500] if isinstance(row, dict)]
    for t, rows in (("snmp_devices", devs), ("snmp_interfaces", ifs), ("snmp_fdb", fdb), ("snmp_arp", arp), ("snmp_lldp", nb), ("snmp_tables", tab)):
        insert(t, rows)
    return len(devs)


def ingest_counters(b):
    """{devices: [{ip, ifs: [[index, in, out, in_errors, out_errors, oper], ...]}]} - every few minutes."""
    now = int(time.time())
    rows = []
    keys = {}
    for d in (b.get("devices") or [])[:5000]:
        ip = str(d.get("ip", ""))
        k = keys.setdefault(ip, key_for(ip))
        for x in (d.get("ifs") or [])[:2000]:
            if len(x) >= 6:
                rows.append({"t": now, "key": k, "if_index": int(x[0]), "in_octets": int(x[1]), "out_octets": int(x[2]),
                             "in_errors": int(x[3]), "out_errors": int(x[4]), "oper": int(x[5])})
    insert("snmp_counters", rows)
    return len(rows)


@router.post("/api/collector/snmp")
async def collector_snmp(request: Request):
    c = assets._collector(request)
    return {"ok": True, "devices": ingest(c, await request.json())}


@router.post("/api/collector/counters")
async def collector_counters(request: Request):
    assets._collector(request)
    return {"ok": True, "rows": ingest_counters(await request.json())}


# ------------------------------------------------------------------ the views
LATEST = "t = (SELECT max(t) FROM netview.{table} WHERE key = {{key:String}})"


def rates(key, since):
    """Each interface's traffic and errors per second, between consecutive counter readings."""
    return q("""
        SELECT if_index, toUInt32(t) AS t, d_in / dt * 8 AS rx, d_out / dt * 8 AS tx, (d_ie + d_oe) / dt AS errs, oper FROM (
            SELECT if_index, t, oper,
                   dateDiff('second', lagInFrame(t) OVER w, t) AS dt,
                   toInt64(in_octets) - toInt64(lagInFrame(in_octets) OVER w) AS d_in,
                   toInt64(out_octets) - toInt64(lagInFrame(out_octets) OVER w) AS d_out,
                   toInt64(in_errors) - toInt64(lagInFrame(in_errors) OVER w) AS d_ie,
                   toInt64(out_errors) - toInt64(lagInFrame(out_errors) OVER w) AS d_oe,
                   row_number() OVER w AS n
            FROM netview.snmp_counters WHERE key = {key:String} AND t > toDateTime({since:UInt32})
            WINDOW w AS (PARTITION BY if_index ORDER BY t ROWS BETWEEN 1 PRECEDING AND CURRENT ROW))
        WHERE n > 1 AND dt > 0 AND d_in >= 0 AND d_out >= 0 ORDER BY if_index, t""", key=key, since=since)


def latest_tables(key=""):
    """Each device's latest reading of each profile: {key: {profile: {row index: {column: value}}}}."""
    one = "AND key = {key:String}" if key else ""
    rows = q("SELECT key, profile, idx, data FROM netview.snmp_tables WHERE t > now() - INTERVAL 2 DAY " + one + """
        AND (key, profile, t) IN (SELECT key, profile, max(t) FROM netview.snmp_tables
                                  WHERE t > now() - INTERVAL 2 DAY """ + one + " GROUP BY key, profile)", key=key)
    out = {}
    for r in rows:
        out.setdefault(r["key"], {}).setdefault(r["profile"], {})[r["idx"]] = r["data"]
    return out


INKS = [("black", "#1f2328"), ("cyan", "#00a3e0"), ("magenta", "#e0157f"), ("yellow", "#f2c40f")]


def _int(v, default=-2):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return default


def supplies(t):
    """A printer's supplies (Printer-MIB): [{name, pct (None if it won't say), state, color, waste}]."""
    names = {i: r.get("name", "") for i, r in t.get("colorants", {}).items()}
    out = []
    for i, r in sorted(t.get("supplies", {}).items(), key=lambda x: [_int(p, 0) for p in x[0].split(".")]):
        level, top = _int(r.get("level")), _int(r.get("max"))
        colorant = names.get(i.split(".")[0] + "." + str(r.get("colorant", "")), "")
        name = colorant or r.get("descr", "") or f"supply {i}"
        pct = max(0, min(100, round(100 * level / top))) if level >= 0 and top > 0 else None
        state = "" if pct is not None else "some left" if level == -3 else "unknown"
        both = f"{colorant} {r.get('descr', '')}".lower()
        color = next((c for word, c in INKS if word in both), "")
        out.append({"name": name, "descr": r.get("descr", ""), "pct": pct, "state": state, "color": color,
                    "waste": _int(r.get("class"), 0) == 4})
    return out


@router.get("/api/snmp/devices")
def devices():
    tables = latest_tables()
    names = {a["key"]: a for a in q("SELECT key, ip, hostname, netbios FROM netview.assets FINAL")}
    now = time.time()
    out = []
    for d in q("SELECT * FROM netview.snmp_devices FINAL ORDER BY sys_name"):
        last = assets._ts(d["last_poll"])
        a = names.get(d["key"], {})
        out.append({k: d[k] for k in ("key", "ip", "sys_name", "sys_descr", "vendor", "model", "serial", "firmware", "location",
                                      "uptime_s", "if_count", "if_up")} | {
            "name": assets.NAMER[0](d["ip"]) or d["sys_name"] or a.get("hostname", ""), "last_poll": last, "online": now - last < 3600,
            "supplies": supplies(tables.get(d["key"], {}))})
    return {"devices": out}


@router.get("/api/snmp/device/{key}")
def device(key: str, hours: int = 24):
    d = q("SELECT * FROM netview.snmp_devices FINAL WHERE key = {key:String}", key=key)
    if not d:
        raise HTTPException(404, "no SNMP reading of this device")
    d = d[0]
    hours = max(1, min(hours, 24 * 30))
    since = int(time.time()) - hours * 3600
    ifs = {i["if_index"]: i for i in q("SELECT * FROM netview.snmp_interfaces FINAL WHERE key = {key:String}", key=key)}
    rs = rates(key, since)
    series = {}
    for r in rs:
        series.setdefault(r["if_index"], []).append([r["t"], r["rx"], r["tx"]])
    for idx, i in ifs.items():
        s = series.get(idx, [])
        i["rx"], i["tx"] = (s[-1][1], s[-1][2]) if s else (None, None)
        i["errors"] = sum(r["errs"] for r in rs if r["if_index"] == idx and r["t"] > time.time() - 3600)
    # The MACs each port learned (the latest reading), named from the assets.
    by_mac = {a["mac"]: a for a in q("SELECT key, ip, mac, vendor, hostname FROM netview.assets FINAL WHERE mac != ''")}
    fdb = q(f"SELECT if_index, mac, vlan FROM netview.snmp_fdb WHERE key = {{key:String}} AND {LATEST.format(table='snmp_fdb')}", key=key)
    per_port = {}
    for f in fdb:
        a = by_mac.get(f["mac"], {})
        per_port.setdefault(f["if_index"], []).append({"mac": f["mac"], "vlan": f["vlan"], "ip": a.get("ip", ""),
                                                      "name": assets.NAMER[0](a.get("ip", "")) or a.get("hostname", ""), "vendor": a.get("vendor", "")})
    nb = q(f"SELECT * FROM netview.snmp_lldp WHERE key = {{key:String}} AND {LATEST.format(table='snmp_lldp')}", key=key)
    t = latest_tables(key).get(key, {})
    arp_n = q(f"SELECT count() AS n FROM netview.snmp_arp WHERE key = {{key:String}} AND {LATEST.format(table='snmp_arp')}", key=key)[0]["n"]
    out_ifs = []
    for idx, i in sorted(ifs.items()):
        out_ifs.append({k: i[k] for k in ("if_index", "name", "descr", "alias", "type", "speed_mbps", "mac", "admin", "oper", "rx", "tx", "errors")}
                       | {"macs": per_port.get(idx, []), "neighbors": [n for n in nb if n["local_if"] == idx],
                          "series": series.get(idx, [])})
    return {k: d[k] for k in ("key", "ip", "sys_name", "sys_descr", "sys_object_id", "vendor", "model", "serial", "firmware",
                              "hardware", "location", "contact", "uptime_s", "if_count", "if_up")} | {
        "name": assets.NAMER[0](d["ip"]) or d["sys_name"], "last_poll": assets._ts(d["last_poll"]), "hours": hours,
        "interfaces": out_ifs, "neighbors": nb, "arp_entries": arp_n, "tables": t, "supplies": supplies(t)}


def where_connected(mac):
    """The switch port a MAC is on: of the ports that learned it (latest reading of each device), the one
    that learned the fewest MACs - an access port rather than an uplink."""
    if not mac:
        return None
    rows = q("""
        WITH latest AS (SELECT key, max(t) AS t FROM netview.snmp_fdb GROUP BY key),
             f AS (SELECT key, if_index, mac FROM netview.snmp_fdb WHERE (key, t) IN (SELECT key, t FROM latest)),
             counts AS (SELECT key, if_index, uniq(mac) AS macs FROM f GROUP BY key, if_index)
        SELECT f.key AS key, f.if_index AS if_index, c.macs AS macs FROM f JOIN counts AS c ON c.key = f.key AND c.if_index = f.if_index
        WHERE f.mac = {mac:String} ORDER BY macs LIMIT 1""", mac=mac)
    if not rows:
        return None
    r = rows[0]
    dev = q("SELECT ip, sys_name FROM netview.snmp_devices FINAL WHERE key = {key:String}", key=r["key"])
    i = q("SELECT name, alias FROM netview.snmp_interfaces FINAL WHERE key = {key:String} AND if_index = {i:UInt32}", key=r["key"], i=r["if_index"])
    return {"device_key": r["key"], "device": (assets.NAMER[0](dev[0]["ip"]) or dev[0]["sys_name"]) if dev else r["key"],
            "port": (i[0]["name"] or str(r["if_index"])) if i else str(r["if_index"]), "alias": i[0]["alias"] if i else "",
            "macs_on_port": r["macs"]}


@router.get("/api/snmp/where/{key}")
def where(key: str):
    a = q("SELECT mac FROM netview.assets FINAL WHERE key = {key:String}", key=key)
    snmp = q("SELECT key FROM netview.snmp_devices FINAL WHERE key = {key:String}", key=key)
    return {"connected": where_connected(a[0]["mac"]) if a else None, "snmp": bool(snmp)}
