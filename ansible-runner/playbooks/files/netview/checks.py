"""Sentry Lens security checks - ntopng's behavioural checks (see
ntopng-security-checks.txt) rebuilt on what netview has: flow records
(addresses, ports, bytes, packets, AS, country - no payload, no TCP flags, no
MACs), the firewall's DNS log and the domain categories; and, beyond flows:

  layer 2   the collectors' ARP sweeps and SNMP ARP tables (spoofing, gateways)
  posture   what the devices' open ports said to a collector (2.4.0+): TLS
            certificates and versions, SSH / web server versions, SMBv1
  SNMP      the network devices' answers and interface counters
  infra     Prometheus: servers, disks, services, containers
  IDS       Suricata's alerts from the firewall (ids.py) - what needs packet
            contents (exploits, SQL injection, malware traffic)

What still can't be done: TCP-level checks (retransmissions, zero window -
flows have no TCP flags) and industrial protocols.

  run      every RUN_EVERY, each enabled check looks at the last WINDOW of
           flows (LAG behind now - the firewall reports long connections once
           a minute) or of lookups, and its hits become rows in netview.alerts
           with the check's score. A hit (check + key, e.g. device + server)
           alerts again only after the check's repeat_hours.
  settings per check: on/off, score 0-100 (the severity: critical >= 80, high
           >= 60, medium >= 40, low >= 20, info) and its thresholds / lists -
           defaults here, changes from the Checks page in
           netview.check_settings (newest version wins).
  feeds    every FEED_EVERY, the threat lists (FEEDS) into netview.threat_ips
           (IP ranges, an ip_trie dictionary) and netview.threat_asns - fresh
           tables swapped in whole.

  lists    the admins' ignore list (devices whose alerts are kept and shown as
           warnings, counted nowhere) and blacklist (addresses my_blacklist
           always flags) - see LISTS.

"Dangerous host" runs last: a device whose alerts add up to its threshold
within the hour.
"""
import ipaddress
import json
import math
import os
import re
import threading
import time
import urllib.request

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

import auth
import categories
import dns
import ids

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
WAN_EXPORTER = os.environ.get("WAN_EXPORTER", "opnsense")
LAN_EXPORTERS = [e for e in os.environ.get("LAN_EXPORTERS", "pve5,pve6").split(",") if e]
LAN_ROLE = os.environ.get("LAN_ROLE", "lan")
# Internet-facing side of the firewall's flows (SentryLens: FLOW_MODE).
TO_INTERNET = "OutIfBoundary = 'external'"
FIREWALL = (re.sub(r"^https?://", "", os.environ.get("OPN_URL", "")).split(":")[0].split("/")[0]
            or "192.168.3.1")
RUN_EVERY = int(os.environ.get("CHECKS_EVERY", "300"))
WINDOW = 600      # seconds of flows each run looks at (thresholds are per WINDOW)
LAG = 120         # behind now: flows still arriving
DNS_WINDOW = 1800  # lookups: domains get their category up to 5 min after the lookup
ALERT_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", "30"))
FEED_EVERY = 6 * 3600
STATIC = os.path.join(os.path.dirname(__file__), "static")

SEVERITIES = [(80, "critical"), (60, "high"), (40, "medium"), (20, "low"), (0, "info")]

# Threat lists: id -> (label, url, kind). cidr = an address or range per line.
FEEDS = {
    "feodo": ("abuse.ch Feodo Tracker (botnet C2)", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "cidr"),
    "firehol_level1": ("FireHOL level 1 (Spamhaus DROP, DShield, attacks)",
                       "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "cidr"),
    "et_compromised": ("Emerging Threats compromised hosts",
                       "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", "cidr"),
    "cins": ("CINS Army (bad actors)", "https://cinsscore.com/list/ci-badguys.txt", "cidr"),
    "tor": ("Tor relays (running)", "https://onionoo.torproject.org/summary?type=relay&running=true", "tor"),
    "asndrop": ("Spamhaus ASN-DROP (hijacked / criminal networks)", "https://www.spamhaus.org/drop/asndrop.json", "asn"),
}
IP_FEEDS = [f for f, (_, _, kind) in FEEDS.items() if kind != "asn"]
THREAT_DICT = "netview.threat_ip_dict"

DDL = [
    "CREATE DATABASE IF NOT EXISTS netview",
    f"""CREATE TABLE IF NOT EXISTS netview.alerts (
        t DateTime, check_id LowCardinality(String), score UInt8, host String, remote String,
        key String, detail String, value Float64
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (t, check_id)
    TTL t + INTERVAL {ALERT_DAYS} DAY""",
    """CREATE TABLE IF NOT EXISTS netview.check_settings (
        id String, enabled UInt8, score UInt8, params String, by String, version UInt64
    ) ENGINE = ReplacingMergeTree(version) ORDER BY id""",
    """CREATE TABLE IF NOT EXISTS netview.threat_ips (prefix String, lists String)
    ENGINE = MergeTree ORDER BY prefix""",
    """CREATE TABLE IF NOT EXISTS netview.threat_asns (asn UInt32, name String)
    ENGINE = MergeTree ORDER BY asn""",
    f"""CREATE DICTIONARY IF NOT EXISTS {THREAT_DICT} (prefix String, lists String)
    PRIMARY KEY prefix SOURCE(CLICKHOUSE(DB 'netview' TABLE 'threat_ips'))
    LAYOUT(IP_TRIE) LIFETIME(3600)""",
]

status = {"enabled": True, "last_run": 0, "last_error": "", "run_seconds": 0, "errors": {},
          "feeds": {}, "feeds_loaded": 0, "feeds_error": ""}
NAMER = [lambda ip: ""]  # app.py's name_of, given at start()


# ------------------------------------------------------------------ ClickHouse
def _lit(v):
    if isinstance(v, str):
        return "'" + v.replace("\\", "\\\\").replace("'", "\\'") + "'"
    return str(int(v)) if isinstance(v, bool) else str(v)


def query(sql, **params):
    """One SELECT; {name:Type} placeholders bound server-side."""
    args = {"readonly": 2, "max_execution_time": 60, "default_format": "JSON",
            "output_format_json_quote_64bit_integers": 0}
    args.update({f"param_{k}": "[" + ",".join(_lit(x) for x in v) + "]" if isinstance(v, list) else v
                 for k, v in params.items()})
    r = requests.post(CH_URL, params=args, data=sql.encode(), timeout=70)
    if r.status_code != 200:
        raise RuntimeError(f"ClickHouse: {r.text[:300]}")
    return r.json()["data"]


def ch(sql, data=None):
    """A statement that writes (DDL, INSERT)."""
    r = requests.post(CH_URL, params={"query": sql} if data is not None else None,
                      data=(data if data is not None else sql).encode(), timeout=300)
    if r.status_code != 200:
        raise RuntimeError(f"ClickHouse: {r.text[:300]}")
    return r.text


# ------------------------------------------------------------------ parameters
def _nets(v):
    out = []
    for x in v if isinstance(v, list) else str(v).replace(",", " ").split():
        try:
            out.append(str(ipaddress.ip_network(str(x).strip(), strict=False)))
        except ValueError:
            raise ValueError(f"not an address or range: {x}")
    return out


def _ports(v):
    out = []
    for x in v if isinstance(v, list) else str(v).replace(",", " ").split():
        if not str(x).strip().isdigit() or not 0 < int(x) < 65536:
            raise ValueError(f"not a port: {x}")
        out.append(int(x))
    return out


def _countries(v):
    out = [str(x).strip().upper() for x in (v if isinstance(v, list) else str(v).replace(",", " ").split())]
    bad = [x for x in out if not re.fullmatch(r"[A-Z]{2}", x)]
    if bad:
        raise ValueError(f"not a country code: {bad[0]}")
    return out


def _cats(v):
    out = [str(x).strip() for x in (v if isinstance(v, list) else str(v).replace(",", " ").split())]
    bad = [x for x in out if x not in categories.CATS]
    if bad:
        raise ValueError(f"not a category: {bad[0]}")
    return out


def _feeds(v):
    out = [str(x).strip() for x in (v if isinstance(v, list) else str(v).replace(",", " ").split())]
    bad = [x for x in out if x not in IP_FEEDS]
    if bad:
        raise ValueError(f"not a threat list: {bad[0]}")
    return out


def _int(v):
    v = int(v)
    if v < 0:
        raise ValueError("must be 0 or more")
    return v


TYPES = {"int": _int, "ips": _nets, "ports": _ports, "countries": _countries, "categories": _cats,
         "feeds": _feeds, "bool": lambda v: v if isinstance(v, bool) else str(v).lower() in ("1", "true", "yes", "on")}


# ------------------------------------------------------------------ check registry
CHECKS = {}
GROUPS = ["Rogue services", "Threat intelligence", "Scans & floods", "DNS abuse", "Risky websites", "Layer 2",
          "Insecure & remote access", "Service posture", "Devices & networks", "Network devices", "Infrastructure",
          "Intrusion detection", "Score"]


def check(cid, group, title, description, score, *, enabled=True, needs="flows", ntopng="", **params):
    """Register a check. params: key=(type, label, default); every check also
    gets repeat_hours (how soon the same hit alerts again): a day for what's
    a standing habit (a DNS server, a VPN), 6 h for scans and floods."""
    params.setdefault("repeat_hours", ("int", "Alert again after (hours)", 6 if group == "Scans & floods" else 24))

    def reg(fn):
        CHECKS[cid] = {"id": cid, "group": group, "title": title, "description": description, "score": score,
                       "enabled": enabled, "needs": needs, "ntopng": ntopng, "params": params, "run": fn}
        return fn
    return reg


def hit(host, key, detail, remote="", value=0):
    return {"host": host, "key": key, "detail": detail, "remote": remote, "value": float(value or 0)}


IP = "replaceRegexpOne(IPv6NumToString({}), '^::ffff:', '')".format
TIME = "TimeReceived BETWEEN toDateTime({start:UInt32}) AND toDateTime({end:UInt32})"
DNS_TIME = "t BETWEEN toDateTime({dstart:UInt32}) AND toDateTime({end:UInt32})"
# IPv4 only: the LAN's own IPv6 (ULA, fd..) isn't one of the site's networks.
PRIVATE = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"]
NOT_UNICAST = ["224.0.0.0/4", "255.255.255.255/32", "ff00::/8"]


def in_nets(expr, name):
    """expr (an address as text) is in one of the ranges of param `name`."""
    return f"arrayExists(c -> isIPAddressInRange({expr}, c), {{{name}:Array(String)}})"


# Internet flows from the firewall, read from the LAN device's side (as app.py's WAN).
WAN = """wan AS (
    SELECT TimeReceived AS t, InIfBoundary = 'external' AS dl,
           if(dl, DstAddr, SrcAddr) AS local, if(dl, SrcAddr, DstAddr) AS remote,
           if(dl, SrcAS, DstAS) AS ras, replaceAll(toString(if(dl, SrcCountry, DstCountry)), '\\0', '') AS rcc,
           if(dl, SrcPort, DstPort) AS rport, Proto, Packets, Bytes * SamplingRate AS b
    FROM flows
    WHERE ExporterName = {wan:String} AND """ + TIME + """
      AND ((InIfBoundary = 'external' AND DstNetRole = {lan:String})
        OR (OutIfBoundary = 'external' AND SrcNetRole = {lan:String}))
)"""
SERVICE = ("multiIf(Proto = 6, dictGetOrDefault('tcp', 'name', toUInt64({0}), ''), "
           "Proto = 17, dictGetOrDefault('udp', 'name', toUInt64({0}), ''), '')").format
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}


def fmt_bytes(b):
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if b < 1000:
            return f"{b:.0f} {unit}" if unit == "B" else f"{b:.1f} {unit}"
        b /= 1000
    return f"{b:.1f} PB"


def svc(proto, port, name=""):
    return f"{PROTO_NAME.get(proto, proto)}/{port}" + (f" ({name})" if name else "")


# ------------------------------------------------------------------ rogue services
def unexpected_server(p, w, protos, ports, what):
    rows = query(f"""
        SELECT {IP('SrcAddr')} AS host, groupUniqArray(10)({IP('DstAddr')}) AS servers,
               uniq(DstAddr) AS n, count() AS flows
        FROM flows
        WHERE {TIME} AND SrcNetRole = {{lan:String}} AND Proto IN {{protos:Array(UInt32)}}
          AND DstPort IN {{ports:Array(UInt32)}}
          AND NOT {in_nets(IP('DstAddr'), 'allowed')} AND NOT {in_nets(IP('SrcAddr'), 'ignore')}
        GROUP BY host""", **w, protos=protos, ports=ports, allowed=p["allowed"], ignore=p["ignore"])
    return [hit(r["host"], r["host"], f"uses {what} server{'s' if r['n'] > 1 else ''} "
                f"{', '.join(sorted(r['servers']))} - not an allowed one ({r['flows']} flows)",
                remote=sorted(r["servers"])[0], value=r["n"]) for r in rows]


@check("rogue_dhcp", "Rogue services", "Unexpected DHCP server",
       "A device answers DHCP (UDP 67 -> 68) and isn't an allowed DHCP server - a rogue or misconfigured router "
       "handing out addresses.", 80, ntopng="Unexpected DHCP Server",
       allowed=("ips", "Allowed DHCP servers", [FIREWALL]))
def rogue_dhcp(p, w):
    rows = query(f"""
        SELECT {IP('SrcAddr')} AS host, uniq(DstAddr) AS clients, count() AS flows
        FROM flows
        WHERE {TIME} AND Proto = 17 AND SrcPort = 67 AND DstPort = 68
          AND NOT {in_nets(IP('SrcAddr'), 'allowed')}
        GROUP BY host""", **w, allowed=p["allowed"])
    return [hit(r["host"], r["host"], f"answers DHCP ({r['flows']} replies to {r['clients']} devices) "
                "but isn't an allowed DHCP server", value=r["flows"]) for r in rows]


@check("rogue_dns", "Rogue services", "Unexpected DNS server",
       "A device sends DNS (53, or DNS over TLS on 853) to a server other than the allowed ones - it bypasses the "
       "firewall's DNS (and its filtering and logging).", 40, ntopng="Unexpected DNS Server",
       allowed=("ips", "Allowed DNS servers", [FIREWALL, "100.100.100.100"]),
       ignore=("ips", "Devices to ignore", [FIREWALL]))
def rogue_dns(p, w):
    return unexpected_server(p, w, [6, 17], [53, 853], "DNS")


@check("rogue_ntp", "Rogue services", "Unexpected NTP server",
       "A device syncs its clock (UDP 123) with a server other than the allowed ones. Off by default: without a "
       "local NTP server every device uses an internet one.", 20, enabled=False, ntopng="Unexpected NTP Server",
       allowed=("ips", "Allowed NTP servers", [FIREWALL]), ignore=("ips", "Devices to ignore", []))
def rogue_ntp(p, w):
    return unexpected_server(p, w, [17], [123], "NTP")


@check("rogue_smtp", "Rogue services", "Unexpected SMTP server",
       "A device sends mail straight to a mail server (TCP 25) that isn't an allowed relay - how spam bots work. "
       "Mail clients use 465/587 and aren't flagged.", 60, ntopng="Unexpected SMTP Server",
       allowed=("ips", "Allowed mail relays", []), ignore=("ips", "Devices allowed to send mail", []))
def rogue_smtp(p, w):
    return unexpected_server(p, w, [6], [25], "SMTP")


# ------------------------------------------------------------------ threat intelligence
def threat_hits(w, feeds, label):
    rows = query(f"""WITH {WAN},
        hits AS (SELECT local, remote, dl, b, dictGetOrDefault('{THREAT_DICT}', 'lists', tuple(remote), '') AS lists
                 FROM wan)
        SELECT {IP('local')} AS host, {IP('remote')} AS rip, any(lists) AS l,
               countIf(NOT dl) AS out_flows, countIf(dl) AS in_flows, sum(b) AS bytes
        FROM hits WHERE lists != '' AND hasAny(splitByChar(',', lists), {{feeds:Array(String)}})
        GROUP BY local, remote""", **w, feeds=feeds)
    out = []
    for r in rows:
        names = [FEEDS[f][0].split(" (")[0] for f in r["l"].split(",") if f in FEEDS and f in feeds]
        direction = ("contacted" if r["out_flows"] else "was contacted by") + f" {label} {r['rip']}"
        out.append(hit(r["host"], f"{r['host']}|{r['rip']}",
                       f"{direction} ({', '.join(names)}) - {r['out_flows']} flows out, {r['in_flows']} in, "
                       f"{fmt_bytes(r['bytes'])}", remote=r["rip"], value=r["bytes"]))
    return out


@check("threat_ip", "Threat intelligence", "Blacklisted IP",
       "Traffic between a device and an address on a threat list (botnet command servers, known attackers, "
       "compromised hosts).", 90, needs="feeds",
       ntopng="Blacklisted Flow / Blacklisted Client / Server Contact, Malware Host Contacted",
       feeds=("feeds", "Threat lists", ["feodo", "firehol_level1", "et_compromised", "cins"]))
def threat_ip(p, w):
    return threat_hits(w, p["feeds"], "blacklisted")


@check("tor", "Threat intelligence", "Tor network",
       "Traffic with a Tor relay - a device using Tor (to hide what it does), or Tor reaching it.", 40,
       needs="feeds", ntopng="Anonymous Subscriber / Tor")
def tor(p, w):
    return threat_hits(w, ["tor"], "Tor relay")


@check("risky_asn", "Threat intelligence", "Risky network (ASN)",
       "Traffic with a network on Spamhaus ASN-DROP - networks run by or hijacked for cyber criminals.", 70,
       needs="feeds", ntopng="Risky ASN")
def risky_asn(p, w):
    rows = query(f"""WITH {WAN}
        SELECT {IP('local')} AS host, ras AS asn, any(a.name) AS name, uniq(remote) AS remotes,
               any({IP('remote')}) AS rip, sum(b) AS bytes
        FROM wan INNER JOIN netview.threat_asns AS a ON a.asn = wan.ras
        GROUP BY local, ras""", **w)
    return [hit(r["host"], f"{r['host']}|AS{r['asn']}",
                f"traffic with AS{r['asn']} {r['name']} ({r['remotes']} addresses, {fmt_bytes(r['bytes'])})",
                remote=r["rip"], value=r["bytes"]) for r in rows]


def country_pairs(w, countries, ignore, through):
    """Device <-> address conversations with the countries, split by whether
    anything came back. The firewall's NetFlow sees a LAN packet before the
    GeoBlock rule rejects it, so a blocked attempt is a flow out with nothing
    in; one that got through (allowed, or a country the firewall's GeoIP
    places elsewhere) has traffic from the remote side."""
    return query(f"""WITH {WAN},
        pairs AS (SELECT local, remote, any(rcc) AS cc, countIf(dl) AS back, count() AS flows, sum(b) AS bytes
                  FROM wan WHERE rcc IN {{countries:Array(String)}} AND NOT {in_nets(IP('local'), 'ignore')}
                  GROUP BY local, remote)
        SELECT {IP('local')} AS host, cc, uniq(remote) AS remotes, any({IP('remote')}) AS rip,
               sum(flows) AS flows, sum(bytes) AS bytes
        FROM pairs WHERE {'back > 0' if through else 'back = 0'}
        GROUP BY local, cc""", **w, countries=countries, ignore=ignore)


@check("blocked_country", "Threat intelligence", "Blocked country (got through)",
       "Traffic that came back from a country on the list - the firewall's GeoBlock countries by default, so a "
       "hit means something got past the block (an exempt host, a network the firewall's GeoIP places in "
       "another country).", 70, ntopng="Blacklisted Country",
       countries=("countries", "Countries (ISO codes)", ["RU", "CN", "KP", "IR", "BY"]),
       ignore=("ips", "Devices to ignore", []))
def blocked_country(p, w):
    rows = country_pairs(w, p["countries"], p["ignore"], through=True)
    return [hit(r["host"], f"{r['host']}|{r['cc']}",
                f"traffic with {r['cc']} got through ({r['remotes']} addresses, {r['flows']} flows, "
                f"{fmt_bytes(r['bytes'])})", remote=r["rip"], value=r["bytes"]) for r in rows]


@check("blocked_country_attempt", "Threat intelligence", "Blocked country (attempt)",
       "A device tried to reach a country on the list (Blocked country's) and the firewall rejected it - "
       "nothing came back. P2P clients do this all the time.", 10,
       ignore=("ips", "Devices to ignore", []))
def blocked_country_attempt(p, w):
    rows = country_pairs(w, effective("blocked_country")["params"]["countries"], p["ignore"], through=False)
    return [hit(r["host"], f"{r['host']}|{r['cc']}",
                f"tried {r['cc']}, blocked ({r['remotes']} addresses, {r['flows']} attempts)",
                remote=r["rip"], value=r["flows"]) for r in rows]


@check("countries_contacts", "Threat intelligence", "Many countries",
       "A device talks to more countries than the threshold in 10 minutes - typical of P2P, scanning or a bot.",
       20, ntopng="Countries Contacts",
       threshold=("int", "Countries in 10 minutes", 60), ignore=("ips", "Devices to ignore", []))
def countries_contacts(p, w):
    rows = query(f"""WITH {WAN}
        SELECT {IP('local')} AS host, uniq(rcc) AS n FROM wan
        WHERE NOT dl AND rcc != '' AND NOT {in_nets(IP('local'), 'ignore')}
        GROUP BY local HAVING n >= {{threshold:UInt32}}""", **w, threshold=p["threshold"], ignore=p["ignore"])
    return [hit(r["host"], r["host"], f"talked to {r['n']} countries in 10 minutes", value=r["n"]) for r in rows]


# ------------------------------------------------------------------ scans & floods
@check("port_scan_lan", "Scans & floods", "Port scan (LAN)",
       "A device probes many ports on another LAN device (short flows, few packets) - lateral movement.", 70,
       ntopng="Port Scan / Probing Attempt",
       threshold=("int", "Ports probed in 10 minutes", 25), ignore=("ips", "Devices to ignore", []))
def port_scan_lan(p, w):
    return port_scan(p, w, "DstNetRole = {lan:String}")


@check("port_scan_internet", "Scans & floods", "Port scan (internet)",
       "A device probes many ports on one internet host. P2P clients (BitTorrent) do this all the time - add "
       "them to the ignore list.", 50, ntopng="Port Scan",
       threshold=("int", "Ports probed in 10 minutes", 100), ignore=("ips", "Devices to ignore", []))
def port_scan_internet(p, w):
    return port_scan(p, w, "ExporterName = {wan:String} AND OutIfBoundary = 'external'")


def port_scan(p, w, where):
    # A probe: from an ephemeral port to a low one, 3 packets or less - replies
    # (from a service port to many ephemeral ones) don't count.
    rows = query(f"""
        SELECT {IP('SrcAddr')} AS host, {IP('DstAddr')} AS rip,
               uniqIf(DstPort, DstPort < 10000 AND Packets <= 3 AND SrcPort >= 1024) AS ports
        FROM flows
        WHERE {TIME} AND Proto IN (6, 17) AND SrcNetRole = {{lan:String}} AND {where}
          AND NOT {in_nets(IP('SrcAddr'), 'ignore')}
        GROUP BY SrcAddr, DstAddr HAVING ports >= {{threshold:UInt32}}""",
                 **w, threshold=p["threshold"], ignore=p["ignore"] + collector_addresses())
    return [hit(r["host"], f"{r['host']}|{r['rip']}", f"probed {r['ports']} ports on {r['rip']} in 10 minutes",
                remote=r["rip"], value=r["ports"]) for r in rows]


@check("host_sweep", "Scans & floods", "Network sweep",
       "A device probes the same port on many LAN devices - network discovery or a worm looking for targets.",
       60, ntopng="Network Discovery",
       threshold=("int", "Devices probed in 10 minutes", 30), ignore=("ips", "Devices to ignore (monitoring)", []))
def host_sweep(p, w):
    rows = query(f"""
        SELECT {IP('SrcAddr')} AS host, Proto AS proto, DstPort AS port, {SERVICE('DstPort')} AS name,
               uniqIf(DstAddr, Packets <= 3) AS n
        FROM flows
        WHERE {TIME} AND SrcNetRole = {{lan:String}} AND DstNetRole = {{lan:String}} AND SrcPort >= 1024
          AND NOT {in_nets(IP('SrcAddr'), 'ignore')} AND NOT {in_nets(IP('DstAddr'), 'multicast')}
          AND NOT endsWith({IP('DstAddr')}, '.255')
        GROUP BY SrcAddr, Proto, DstPort HAVING n >= {{threshold:UInt32}}""",
                 **w, threshold=p["threshold"], ignore=p["ignore"] + collector_addresses(), multicast=NOT_UNICAST)
    return [hit(r["host"], f"{r['host']}|{r['proto']}/{r['port']}",
                f"probed {svc(r['proto'], r['port'], r['name'])} on {r['n']} LAN devices in 10 minutes",
                value=r["n"]) for r in rows]


@check("flow_flood", "Scans & floods", "Flow flood",
       "A device opens more connections per minute than the threshold - a flood, a scan or a runaway program.",
       50, ntopng="Flow Flood",
       threshold=("int", "Flows per minute", 6000), ignore=("ips", "Devices to ignore", []))
def flow_flood(p, w):
    rows = query(f"""
        SELECT host, max(n) AS peak FROM (
            SELECT {IP('SrcAddr')} AS host, toStartOfMinute(TimeReceived) AS m, count() AS n FROM flows
            WHERE {TIME} AND SrcNetRole = {{lan:String}} AND NOT {in_nets(IP('SrcAddr'), 'ignore')}
            GROUP BY host, m)
        GROUP BY host HAVING peak >= {{threshold:UInt32}}""", **w, threshold=p["threshold"], ignore=p["ignore"] + collector_addresses())
    return [hit(r["host"], r["host"], f"{r['peak']} flows in one minute", value=r["peak"]) for r in rows]


@check("icmp_flood", "Scans & floods", "ICMP flood",
       "A device sends more ICMP (ping) packets per minute than the threshold - a ping flood or sweep.", 50,
       ntopng="ICMP Flood",
       threshold=("int", "ICMP packets per minute", 6000), ignore=("ips", "Devices to ignore", []))
def icmp_flood(p, w):
    rows = query(f"""
        SELECT host, max(n) AS peak FROM (
            SELECT {IP('SrcAddr')} AS host, toStartOfMinute(TimeReceived) AS m, sum(Packets * SamplingRate) AS n
            FROM flows WHERE {TIME} AND Proto IN (1, 58) AND NOT {in_nets(IP('SrcAddr'), 'ignore')}
            GROUP BY host, m)
        GROUP BY host HAVING peak >= {{threshold:UInt32}}""", **w, threshold=p["threshold"], ignore=p["ignore"] + collector_addresses())
    return [hit(r["host"], r["host"], f"{r['peak']:.0f} ICMP packets in one minute", value=r["peak"]) for r in rows]


@check("unanswered", "Scans & floods", "Unanswered connections",
       "A device tries many internet hosts that never answer - malware trying dead command servers, or a "
       "scan.", 40, ntopng="Unidirectional Flow / TCP No Data Exchanged",
       threshold=("int", "Unanswered hosts in 10 minutes", 100), ignore=("ips", "Devices to ignore", []))
def unanswered(p, w):
    rows = query(f"""WITH {WAN},
        o AS (SELECT DISTINCT local, remote, rport FROM wan WHERE NOT dl AND Proto = 6),
        i AS (SELECT DISTINCT local, remote, rport FROM wan WHERE dl AND Proto = 6)
        SELECT {IP('local')} AS host, uniq(remote) AS n
        FROM (SELECT o.local AS local, o.remote AS remote FROM o LEFT ANTI JOIN i
              ON o.local = i.local AND o.remote = i.remote AND o.rport = i.rport)
        WHERE NOT {in_nets(IP('local'), 'ignore')}
        GROUP BY local HAVING n >= {{threshold:UInt32}}""", **w, threshold=p["threshold"], ignore=p["ignore"])
    return [hit(r["host"], r["host"], f"{r['n']} internet hosts didn't answer its TCP connections in 10 minutes",
                value=r["n"]) for r in rows]


@check("inbound_exposed", "Scans & floods", "Reachable from the internet",
       "Many internet hosts connect to the same port on a device - a port forward, UPnP or a P2P port open to "
       "the world.", 40, ntopng="Remote to Local Insecure Flow",
       threshold=("int", "Internet hosts in 10 minutes", 5),
       ignore_ports=("ports", "Ports to ignore (e.g. Tailscale 41641)", [41641]),
       ignore=("ips", "Devices to ignore", []))
def inbound_exposed(p, w):
    rows = query(f"""
        SELECT {IP('DstAddr')} AS host, Proto AS proto, DstPort AS port, {SERVICE('DstPort')} AS name,
               uniq(SrcAddr) AS n, any({IP('SrcAddr')}) AS rip
        FROM flows
        WHERE {TIME} AND ExporterName = {{wan:String}} AND InIfBoundary = 'external' AND DstNetRole = {{lan:String}}
          AND Proto IN (6, 17) AND DstPort < 32768 AND SrcPort >= 1024  -- not an outgoing connection's own port
          AND DstPort NOT IN {{ignore_ports:Array(UInt32)}} AND NOT {in_nets(IP('DstAddr'), 'ignore')}
        GROUP BY DstAddr, Proto, DstPort HAVING n >= {{threshold:UInt32}}""",
                 **w, threshold=p["threshold"], ignore_ports=p["ignore_ports"], ignore=p["ignore"])
    return [hit(r["host"], f"{r['host']}|{r['proto']}/{r['port']}",
                f"{svc(r['proto'], r['port'], r['name'])} reached by {r['n']} internet hosts in 10 minutes",
                remote=r["rip"], value=r["n"]) for r in rows]


@check("large_upload", "Scans & floods", "Large upload",
       "A device sends more than the threshold to one internet host in 10 minutes - backups, or data leaving. "
       "Not an ntopng check.", 40,
       threshold=("int", "MB to one host in 10 minutes", 5000), ignore=("ips", "Devices to ignore (backups)", []))
def large_upload(p, w):
    rows = query(f"""WITH {WAN}
        SELECT {IP('local')} AS host, {IP('remote')} AS rip, sum(b) AS bytes FROM wan
        WHERE NOT dl AND NOT {in_nets(IP('local'), 'ignore')}
        GROUP BY local, remote HAVING bytes >= {{threshold:UInt64}} * 1000000""",
                 **w, threshold=p["threshold"], ignore=p["ignore"])
    return [hit(r["host"], f"{r['host']}|{r['rip']}", f"sent {fmt_bytes(r['bytes'])} to {r['rip']} in 10 minutes",
                remote=r["rip"], value=r["bytes"]) for r in rows]


# ------------------------------------------------------------------ DNS abuse & risky websites
def category_hits(w, cats, what):
    rows = query(f"""
        SELECT {IP('client')} AS host, domain, dictGetOrDefault('{categories.DICT}', 'category', tuple(domain), '') AS cat,
               count() AS n
        FROM netview.dns WHERE {DNS_TIME} AND cat IN {{cats:Array(String)}}
        GROUP BY client, domain, cat""", **w, cats=cats)
    return [hit(r["host"], f"{r['host']}|{r['domain']}",
                f"{what} {r['domain']} ({categories.label(r['cat'])}, {r['n']} lookups)",
                remote=r["domain"], value=r["n"]) for r in rows]


@check("security_domain", "DNS abuse", "Malware / phishing domain",
       "A device looks up a domain listed as malware, phishing, stalkerware or dialer (UT1 lists).", 90,
       needs="dns", ntopng="Malware Host Contacted / Risky Domain",
       categories=("categories", "Categories", ["malware", "phishing", "stalkerware", "dialer"]))
def security_domain(p, w):
    return category_hits(w, p["categories"], "looked up")


@check("cryptomining", "DNS abuse", "Crypto mining",
       "A device looks up a crypto-mining (cryptojacking) domain.", 70, needs="dns", ntopng="Web Mining")
def cryptomining(p, w):
    return category_hits(w, ["cryptojacking"], "looked up mining domain")


def entropy(s):
    return -sum(c / len(s) * math.log2(c / len(s)) for c in (s.count(x) for x in set(s))) if s else 0


def looks_generated(site):
    """A registrable name whose first label looks machine-made (DGA). Names
    under a hosting platform's suffix (d1y8cgsxwc6rew.cloudfront.net - the
    public suffix list makes those registrable) are random by design: only
    names right under a TLD (or co.uk, com.au...) count."""
    label, _, rest = site.partition(".")
    if len(label) < 12 or ("." in rest and len(rest) > 6):
        return False
    letters = [c for c in label if c.isalpha()]
    vowels = sum(c in "aeiouy" for c in letters) / max(len(letters), 1)
    digits = sum(c.isdigit() for c in label) / len(label)
    return entropy(label) >= 3.5 and (vowels < 0.25 or digits >= 0.3) and "-" not in label


@check("dga", "DNS abuse", "Generated domain name (DGA)",
       "A device looks up a long, random-looking name no category list has - malware finds its command "
       "servers that way.", 60, needs="dns", ntopng="Susp. DGA Domain name")
def dga(p, w):
    rows = query(f"""
        SELECT {IP('client')} AS host, site, any(domain) AS dom, count() AS n
        FROM netview.dns
        WHERE {DNS_TIME}
          AND dictGetOrDefault('{categories.DICT}', 'category', tuple(domain), '') IN ('', '{categories.UNCATEGORIZED}')
        GROUP BY client, site""", **w)
    return [hit(r["host"], f"{r['host']}|{r['site']}", f"looked up {r['dom']}, a random-looking name",
                remote=r["site"], value=r["n"]) for r in rows if looks_generated(r["site"])]


@check("dns_tunnel", "DNS abuse", "DNS tunnel",
       "A device looks up many long, different names under one domain - data carried inside DNS.", 60,
       needs="dns", ntopng="Susp. DNS Traffic / Susp. Entropy",
       threshold=("int", "Long names under one domain in 30 minutes", 50))
def dns_tunnel(p, w):
    rows = query(f"""
        SELECT {IP('client')} AS host, site, uniqIf(domain, length(domain) - length(site) > 25) AS n
        FROM netview.dns WHERE {DNS_TIME}
        GROUP BY client, site HAVING n >= {{threshold:UInt32}}""", **w, threshold=p["threshold"])
    return [hit(r["host"], f"{r['host']}|{r['site']}", f"{r['n']} long, different names under {r['site']}",
                remote=r["site"], value=r["n"]) for r in rows]


@check("domain_flood", "DNS abuse", "Many domain names",
       "A device looks up more different names than the threshold - a crawler, a scan or a bot.", 30,
       needs="dns", ntopng="Domain Names Contacts",
       threshold=("int", "Names in 30 minutes", 1500), ignore=("ips", "Devices to ignore", []))
def domain_flood(p, w):
    rows = query(f"""
        SELECT {IP('client')} AS host, uniq(domain) AS n FROM netview.dns
        WHERE {DNS_TIME} AND NOT {in_nets(IP('client'), 'ignore')}
        GROUP BY client HAVING n >= {{threshold:UInt32}}""", **w, threshold=p["threshold"], ignore=p["ignore"])
    return [hit(r["host"], r["host"], f"looked up {r['n']} different names in 30 minutes", value=r["n"])
            for r in rows]


@check("punycode", "DNS abuse", "Punycode (IDN) domain",
       "A device looks up an internationalized name (xn--...) - look-alike domains used for phishing.", 30,
       needs="dns", ntopng="Punicody IDN")
def punycode(p, w):
    rows = query(f"""
        SELECT {IP('client')} AS host, domain, count() AS n FROM netview.dns
        WHERE {DNS_TIME} AND position(domain, 'xn--') > 0
        GROUP BY client, domain""", **w)
    return [hit(r["host"], f"{r['host']}|{r['domain']}", f"looked up {r['domain']}", remote=r["domain"],
                value=r["n"]) for r in rows]


@check("doh", "DNS abuse", "DNS over HTTPS",
       "A device uses DNS over HTTPS (a DoH domain, or HTTPS to a public resolver) - its lookups bypass the "
       "firewall and this app.", 30, needs="dns", ntopng="Unexpected DNS Server",
       resolvers=("ips", "Public DoH resolvers",
                  ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
                   "94.140.14.14", "94.140.15.15", "208.67.222.222", "208.67.220.220"]))
def doh(p, w):
    out = category_hits(w, ["doh"], "looked up DoH domain")
    rows = query(f"""WITH {WAN}
        SELECT {IP('local')} AS host, {IP('remote')} AS rip, count() AS n FROM wan
        WHERE NOT dl AND rport = 443 AND {in_nets(IP('remote'), 'resolvers')}
        GROUP BY local, remote""", **w, resolvers=p["resolvers"])
    return out + [hit(r["host"], f"{r['host']}|{r['rip']}", f"HTTPS to public resolver {r['rip']} ({r['n']} flows)",
                      remote=r["rip"], value=r["n"]) for r in rows]


@check("risky_category", "Risky websites", "Risky website category",
       "A device looks up a domain in one of the chosen categories.", 30, needs="dns",
       ntopng="Risky Domain",
       categories=("categories", "Categories", ["hacking", "ddos", "warez", "dangerous_material"]))
def risky_category(p, w):
    return category_hits(w, p["categories"], "looked up")


@check("anonymizer", "Risky websites", "VPN / proxy / anonymizer",
       "A device looks up a proxy or anonymizer service - traffic that hides where it goes. Add \"vpn\" to "
       "flag VPN services too (left out: Tailscale and PIA are in use here).", 20,
       needs="dns", ntopng="Obfuscated Traffic",
       categories=("categories", "Categories", ["redirector", "residential-proxies"]))
def anonymizer(p, w):
    return category_hits(w, p["categories"], "looked up")


# ------------------------------------------------------------------ insecure & remote access
def port_hits(p, w, what):
    # TCP (UDP only for udp_ports): P2P clients use random UDP ports, the low ones included.
    rows = query(f"""WITH {WAN}
        SELECT {IP('local')} AS host, Proto AS proto, rport AS port, {SERVICE('rport')} AS name,
               uniq(remote) AS remotes, any({IP('remote')}) AS rip, countIf(NOT dl) AS out_flows
        FROM wan WHERE ((Proto = 6 AND rport IN {{ports:Array(UInt32)}}) OR (Proto = 17 AND rport IN {{udp:Array(UInt32)}}))
          AND NOT {in_nets(IP('local'), 'ignore')}
        GROUP BY local, Proto, rport HAVING out_flows > 0""",
                 **w, ports=p["ports"], udp=p.get("udp_ports", []), ignore=p["ignore"])
    return [hit(r["host"], f"{r['host']}|{r['proto']}/{r['port']}",
                f"{what} {svc(r['proto'], r['port'], r['name'])} to {r['remotes']} internet "
                f"host{'s' if r['remotes'] > 1 else ''} (e.g. {r['rip']})", remote=r["rip"], value=r["remotes"])
            for r in rows]


@check("insecure_protocol", "Insecure & remote access", "Unencrypted / unsafe protocol",
       "A device uses a clear-text or unsafe protocol across the internet (FTP, Telnet, TFTP, POP3, IMAP, "
       "SMB/NetBIOS, SNMP, r-commands) - passwords and data readable on the way.", 50,
       ntopng="Clear-Text Credentials / Unsafe Protocol / SMB Insecure Vers",
       ports=("ports", "TCP ports", [21, 23, 110, 139, 143, 445, 512, 513, 514]),
       udp_ports=("ports", "UDP ports", [69, 161]), ignore=("ips", "Devices to ignore", []))
def insecure_protocol(p, w):
    return port_hits(p, w, "uses")


@check("remote_access", "Insecure & remote access", "Remote desktop / control",
       "A device runs a remote desktop or remote control session over the internet (RDP, VNC, TeamViewer, "
       "AnyDesk, or a remote-control domain).", 30, ntopng="Remote Access / Desktop/File Sharing",
       ports=("ports", "TCP ports", [3389, 5900, 5901, 5938, 6568]), ignore=("ips", "Devices to ignore", []))
def remote_access(p, w):
    out = port_hits(p, w, "uses")
    if dns.status["enabled"]:
        out += category_hits(w, ["remote-control"], "looked up remote-control domain")
    return out


# ------------------------------------------------------------------ devices & networks
@check("my_blacklist", "Threat intelligence", "Blacklisted IP (your list)",
       "Traffic with an address on your own blacklist (Alerts > Checks > Your blacklist) - internet or LAN.", 90)
def my_blacklist(p, w):
    bad = nets_of("blacklist")
    if not bad:
        return []
    # From whichever side isn't on the list (both on it: from the source).
    rows = query(f"""
        SELECT if(dst_bad AND NOT src_bad, {IP('SrcAddr')}, {IP('DstAddr')}) AS host,
               if(dst_bad AND NOT src_bad, {IP('DstAddr')}, {IP('SrcAddr')}) AS rip,
               count() AS flows, sum(Bytes * SamplingRate) AS bytes
        FROM (SELECT *, {in_nets(IP('SrcAddr'), 'bad')} AS src_bad, {in_nets(IP('DstAddr'), 'bad')} AS dst_bad
              FROM flows WHERE {TIME})
        WHERE src_bad OR dst_bad
        GROUP BY host, rip""", **w, bad=bad)
    return [hit(r["host"], f"{r['host']}|{r['rip']}",
                f"traffic with {r['rip']}, on your blacklist ({r['flows']} flows, {fmt_bytes(r['bytes'])})",
                remote=r["rip"], value=r["bytes"]) for r in rows]


@check("ghost_network", "Devices & networks", "Unknown network",
       "A private address outside the known networks shows up on the LAN - a device with a wrong or static "
       "address, or a second router.", 50, ntopng="Ghost Networks",
       known=("ips", "Other networks that are fine", []))
def ghost_network(p, w):
    rows = query(f"""
        SELECT {IP('SrcAddr')} AS host, groupUniqArray(ExporterName) AS seen_by, count() AS flows
        FROM flows
        WHERE {TIME} AND SrcNetRole = '' AND InIfBoundary != 'external'
          AND {in_nets(IP('SrcAddr'), 'private')} AND NOT {in_nets(IP('SrcAddr'), 'known')}
        GROUP BY SrcAddr""", **w, private=PRIVATE, known=p["known"])
    return [hit(r["host"], r["host"], f"address outside the known networks, seen by {', '.join(r['seen_by'])} "
                f"({r['flows']} flows)", value=r["flows"]) for r in rows]


_known = {"t": 0, "hosts": set()}


@check("new_device", "Devices & networks", "New device",
       "A LAN address not seen in the last 7 days starts talking. Not an ntopng check.", 30,
       unnamed_only=("bool", "Only devices without a DHCP / static name", False))
def new_device(p, w):
    if not _known["hosts"] or time.time() - _known["t"] > 86400:  # the 7 days, once a day
        _known["hosts"] = {r["host"] for r in query(f"""
            SELECT DISTINCT {IP('SrcAddr')} AS host FROM flows
            WHERE TimeReceived BETWEEN toDateTime({{start:UInt32}}) - INTERVAL 7 DAY AND toDateTime({{start:UInt32}})
              AND SrcNetRole = {{lan:String}}""", **w)}
        _known["t"] = time.time()
    rows = query(f"""
        SELECT {IP('SrcAddr')} AS host, count() AS flows FROM flows
        WHERE {TIME} AND SrcNetRole = {{lan:String}} GROUP BY SrcAddr""", **w)
    out = []
    for r in rows:
        if r["host"] in _known["hosts"]:
            continue
        _known["hosts"].add(r["host"])
        name = NAMER[0](r["host"])
        if not (p["unnamed_only"] and name):
            out.append(hit(r["host"], r["host"], f"first seen ({name or 'no DHCP name'})", value=r["flows"]))
    return out


@check("scan_victim", "Scans & floods", "Port scan target",
       "A LAN device is probed on many ports (short flows, few packets) from the LAN or the internet - by one "
       "scanner or several together.", 50, ntopng="Scan Victim / SYN Scan Victim",
       threshold=("int", "Ports probed in 10 minutes", 50), ignore=("ips", "Devices to ignore", []),
       scanners=("ips", "Scanners that are fine (monitoring; the collectors are always)", []))
def scan_victim(p, w):
    rows = query(f"""
        SELECT {IP('DstAddr')} AS host, uniq(DstPort) AS ports, uniq(SrcAddr) AS sources,
               any({IP('SrcAddr')}) AS rip
        FROM flows
        WHERE {TIME} AND Proto IN (6, 17) AND DstNetRole = {{lan:String}} AND SrcPort >= 1024 AND DstPort < 10000
          AND Packets <= 3 AND NOT {in_nets(IP('DstAddr'), 'ignore')} AND NOT {in_nets(IP('SrcAddr'), 'scanners')}
        GROUP BY DstAddr HAVING ports >= {{threshold:UInt32}}""",
                 **w, threshold=p["threshold"], ignore=p["ignore"], scanners=p["scanners"] + collector_addresses())
    return [hit(r["host"], r["host"], f"probed on {r['ports']} ports by {r['sources']} "
                f"source{'s' if r['sources'] > 1 else ''} (e.g. {r['rip']}) in 10 minutes", remote=r["rip"],
                value=r["ports"]) for r in rows]


@check("flow_flood_victim", "Scans & floods", "Flow flood target",
       "A device receives more connections per minute than the threshold - a flood aimed at it (DoS), or a "
       "very busy server.", 50, ntopng="Flow Flood Victim / SYN Flood Victim",
       threshold=("int", "Flows per minute", 6000), ignore=("ips", "Devices to ignore (busy servers)", []))
def flow_flood_victim(p, w):
    rows = query(f"""
        SELECT host, max(n) AS peak, max(s) AS sources FROM (
            SELECT {IP('DstAddr')} AS host, toStartOfMinute(TimeReceived) AS m, count() AS n, uniq(SrcAddr) AS s
            FROM flows WHERE {TIME} AND DstNetRole = {{lan:String}} AND NOT {in_nets(IP('DstAddr'), 'ignore')}
            GROUP BY host, m)
        GROUP BY host HAVING peak >= {{threshold:UInt32}}""", **w, threshold=p["threshold"], ignore=p["ignore"])
    return [hit(r["host"], r["host"], f"received {r['peak']} flows in one minute (from up to {r['sources']} "
                "addresses)", value=r["peak"]) for r in rows]


_beacon = {"t": 0}


@check("beaconing", "Threat intelligence", "Beaconing",
       "A device opens a new connection to the same internet address at a steady interval for hours - how "
       "malware checks in with its command server. Looked at once an hour, over the last 6 hours. By default "
       "only addresses the device never looked up in DNS (apps call home by name); a device with many such "
       "addresses at once is a P2P client re-announcing to its peers (BitTorrent), not malware, and is left out.",
       50, ntopng="Periodic Flow (ntopng Enterprise)",
       min_beacons=("int", "Connections in 6 hours (at least)", 12),
       jitter=("int", "Interval spread, % of the interval (at most)", 15),
       min_interval=("int", "Interval, seconds (at least)", 120),
       no_dns_only=("bool", "Only addresses it didn't look up in DNS", True),
       max_per_device=("int", "More addresses than this on one device: P2P, left out", 5),
       ignore_ports=("ports", "Ports to ignore (DNS, NTP)", [53, 123]),
       ignore=("ips", "Devices or addresses to ignore", []))
def beaconing(p, w):
    if time.time() - _beacon["t"] < 3600:
        return []
    _beacon["t"] = time.time()
    w = w | {"start": w["end"] - 6 * 3600}
    # One connection = one local port; its first sighting is when it opened.
    rows = query(f"""
        WITH conns AS (
            SELECT {IP('SrcAddr')} AS host, {IP('DstAddr')} AS rip, DstAddr AS raddr, SrcAddr AS laddr, Proto, DstPort,
                   SrcPort, toUInt32(min(TimeReceived)) AS opened
            FROM flows
            WHERE {TIME} AND ExporterName = {{wan:String}} AND {TO_INTERNET} AND SrcNetRole = {{lan:String}}
              AND Proto IN (6, 17) AND NOT {in_nets(IP('SrcAddr'), 'ignore')} AND NOT {in_nets(IP('DstAddr'), 'ignore')}
              AND DstPort NOT IN {{ignore_ports:Array(UInt32)}}
            GROUP BY SrcAddr, DstAddr, Proto, DstPort, SrcPort),
        series AS (
            SELECT host, rip, any(laddr) AS la, any(raddr) AS ra, Proto AS proto, DstPort AS port, count() AS n,
                   arrayPopFront(arrayDifference(arraySort(groupArray(opened)))) AS gaps
            FROM conns GROUP BY host, rip, Proto, DstPort HAVING n >= {{min_beacons:UInt32}})
        SELECT host, rip, proto, port, n, arrayAvg(gaps) AS mean,
               sqrt(arrayAvg(arrayMap(g -> pow(g - mean, 2), gaps))) AS spread
        FROM series
        LEFT JOIN (SELECT DISTINCT client, ip, 1 AS seen FROM netview.dns_ips WHERE t > now() - INTERVAL 1 DAY) AS d
          ON d.client = series.la AND d.ip = series.ra
        WHERE mean >= {{min_interval:UInt32}} AND spread <= mean * {{jitter:UInt32}} / 100
          {'AND d.seen = 0' if p['no_dns_only'] and dns.status['enabled'] else ''}""",
                 **w, min_beacons=p["min_beacons"], min_interval=p["min_interval"], jitter=p["jitter"],
                 ignore=p["ignore"], ignore_ports=p["ignore_ports"])
    per_device = {}
    for r in rows:
        per_device[r["host"]] = per_device.get(r["host"], 0) + 1
    return [hit(r["host"], f"{r['host']}|{r['rip']}|{r['port']}",
                f"connects to {r['rip']} {svc(r['proto'], r['port'])} every {r['mean'] / 60:.1f} min "
                f"(±{r['spread']:.0f} s, {r['n']} times in 6 hours)", remote=r["rip"], value=r["n"])
            for r in rows if per_device[r["host"]] <= p["max_per_device"]]


_collectors = {"t": 0, "ips": []}


def collector_addresses():
    """Where the collectors run: their sweeps probe every port of every device."""
    if time.time() - _collectors["t"] > 600:
        try:
            _collectors["ips"] = _nets([r["address"] for r in query(
                "SELECT DISTINCT address FROM netview.collectors FINAL WHERE deleted = 0 AND address != ''")])
        except (RuntimeError, ValueError, requests.RequestException):
            pass
        _collectors["t"] = time.time()
    return _collectors["ips"]


# Sentry Lens's own traffic - its host (COLLECTOR_IP, plus SELF_IPS) and the
# collectors: sweeps, SNMP polls, DNS lookups, Prometheus scrapes, Suricata
# seeing them. Never alerted on by the traffic checks, either side, and older
# alerts of theirs are left out of the lists. The health and posture checks
# (HEALTH) still look at those machines themselves.
HEALTH = ("Layer 2", "Service posture", "Network devices", "Infrastructure")
SELF_IPS = [a for a in [os.environ.get("COLLECTOR_IP", "")] + os.environ.get("SELF_IPS", "").replace(",", " ").split() if a]


def own_nets():
    out = []
    for a in SELF_IPS:
        try:
            out += _nets([a])
        except ValueError:
            pass
    return sorted(set(out + collector_addresses()))


def mine(addr, own):
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return False  # a domain, a name
    return any(a.version == n.version and a in n for n in own)


AS_IP = "if(isIPv4String({0}) OR isIPv6String({0}), {0}, '0.0.0.0')".format
# An alert row isn't one of Sentry Lens's own (SQL; with NOT_OWN_PARAMS()).
NOT_OWN = (f"NOT (check_id IN {{own_checks:Array(String)}} AND ({in_nets(AS_IP('host'), 'own')}"
           f" OR {in_nets(AS_IP('remote'), 'own')}))")


def NOT_OWN_PARAMS():
    return {"own": own_nets(), "own_checks": [i for i, c in CHECKS.items() if c["group"] not in HEALTH]}


# ------------------------------------------------------------------ layer 2
# What answers for an address: the collectors' ARP sweeps (asset_obs) and the
# ARP tables SNMP read from routers and switches (snmp_arp).
def l2_obs(hours, since_hours=0):
    return f"""obs AS (
        SELECT t, ip, mac FROM netview.asset_obs
        WHERE mac != '' AND t >= now() - INTERVAL {int(hours)} HOUR AND t < now() - INTERVAL {int(since_hours)} HOUR
        UNION ALL
        SELECT t, ip, mac FROM netview.snmp_arp
        WHERE mac != '' AND mac != '00:00:00:00:00:00' AND t >= now() - INTERVAL {int(hours)} HOUR
          AND t < now() - INTERVAL {int(since_hours)} HOUR)"""


@check("arp_conflict", "Layer 2", "ARP spoofing / duplicate address",
       "Two or more MAC addresses answer for the same IP address within the hour - ARP spoofing (a device "
       "putting itself in the middle), or two devices with the same static address. Needs a collector's ARP "
       "sweep or SNMP ARP tables.", 70, needs="arp", ntopng="ARP Spoofing / IP-MAC Reassociation",
       ignore=("ips", "Addresses to ignore (shared / failover addresses)", []))
def arp_conflict(p, w):
    rows = query(f"""WITH {l2_obs(1)}
        SELECT ip, groupUniqArray(mac) AS macs FROM obs
        WHERE NOT {in_nets('ip', 'ignore')} AND NOT {in_nets('ip', 'gw')}
        GROUP BY ip HAVING length(macs) > 1""", ignore=p["ignore"], gw=gateways())
    return [hit(r["ip"], f"{r['ip']}|{','.join(sorted(r['macs']))}",
                f"answered by {len(r['macs'])} MAC addresses: {', '.join(sorted(r['macs']))}", value=len(r["macs"]))
            for r in rows]


@check("unexpected_gateway", "Layer 2", "Unexpected gateway",
       "The gateway's address answers from a MAC address other than its usual one (the last 7 days) - a device "
       "posing as the router to see everyone's traffic.", 90, needs="arp", ntopng="Unexpected Gateway",
       gateways=("ips", "Gateways (empty: the firewall)", []))
def unexpected_gateway(p, w):
    rows = query(f"""WITH {l2_obs(24 * 7)},
        usual AS (SELECT ip, topK(1)(mac)[1] AS mac FROM obs WHERE t < now() - INTERVAL 1 HOUR AND {in_nets('ip', 'gw')}
                  GROUP BY ip)
        SELECT o.ip AS ip, u.mac AS usual, groupUniqArray(o.mac) AS macs FROM obs AS o INNER JOIN usual AS u ON o.ip = u.ip
        WHERE o.t >= now() - INTERVAL 1 HOUR AND o.mac != u.mac
        GROUP BY o.ip, u.mac""", gw=p["gateways"] or gateways())
    return [hit(r["ip"], f"{r['ip']}|{','.join(sorted(r['macs']))}",
                f"gateway {r['ip']} answered from {', '.join(sorted(r['macs']))} - usually {r['usual']}",
                value=len(r["macs"])) for r in rows]


@check("ip_mac_change", "Layer 2", "IP-MAC reassociation",
       "An address that belonged to one device the last 7 days now answers from another MAC address - an "
       "address reused by DHCP, a replaced device, or someone taking it over.", 20, needs="arp",
       ntopng="IP-MAC Reassociation", ignore=("ips", "Addresses to ignore (DHCP pools with short leases)", []))
def ip_mac_change(p, w):
    rows = query(f"""WITH {l2_obs(1)},
        before AS (SELECT ip, argMax(mac, t) AS last_mac FROM netview.asset_obs
                   WHERE mac != '' AND t >= now() - INTERVAL 7 DAY AND t < now() - INTERVAL 1 HOUR GROUP BY ip)
        SELECT o.ip AS ip, any(b.last_mac) AS was, groupUniqArray(o.mac) AS macs
        FROM obs AS o INNER JOIN before AS b ON o.ip = b.ip
        WHERE NOT {in_nets('o.ip', 'ignore')} AND NOT {in_nets('o.ip', 'gw')}
        GROUP BY o.ip HAVING length(macs) = 1 AND macs[1] != was""", ignore=p["ignore"], gw=gateways())
    return [hit(r["ip"], f"{r['ip']}|{r['macs'][0]}", f"now {r['macs'][0]}, was {r['was']}") for r in rows]


def gateways():
    return effective("unexpected_gateway")["params"]["gateways"] or (_nets([FIREWALL]) if FIREWALL else [])


# ------------------------------------------------------------------ service posture
# What the devices' open ports said in their latest sweep (collector 2.4.0+:
# services.go) - one row per address and port.
LATEST_SERVICES = """svc AS (
    SELECT s.* FROM netview.asset_services AS s
    INNER JOIN (SELECT ip, max(t) AS last FROM netview.asset_services WHERE t > now() - INTERVAL 2 DAY GROUP BY ip) AS l
    ON s.ip = l.ip AND s.t = l.last)"""


def services(where, **params):
    return query(f"WITH {LATEST_SERVICES} SELECT *, toUInt32(cert_not_after) AS na FROM svc "
                 f"WHERE {where} AND NOT {in_nets('ip', 'ignore')}", **params)


@check("tls_certificate", "Service posture", "TLS certificate expired / expiring",
       "A device's TLS certificate (HTTPS, mail, LDAPS...) has expired or expires within the days given.", 50,
       needs="services", ntopng="TLS Certificate Expired / About To Expire",
       days=("int", "Days before it expires", 14), ignore=("ips", "Devices to ignore", []),
       repeat_hours=("int", "Alert again after (hours)", 24))
def tls_certificate(p, w):
    rows = services("kind = 'tls' AND toUInt32(cert_not_after) > 0 "
                    "AND cert_not_after < now() + INTERVAL {days:UInt32} DAY", days=p["days"], ignore=p["ignore"])
    out = []
    for r in rows:
        days = (r["na"] - time.time()) / 86400
        when = f"expired {-days:.0f} days ago" if days < 0 else f"expires in {days:.0f} days"
        out.append(hit(r["ip"], f"{r['ip']}|{r['port']}", f"TCP/{r['port']}: certificate {when} ({r['cert_subject']})",
                       value=round(days)))
    return out


@check("tls_self_signed", "Service posture", "Self-signed TLS certificate",
       "A device's TLS certificate is self-signed - browsers warn, and users learn to click through. Off by "
       "default: most appliances (Proxmox, printers, switches) ship that way.", 10, enabled=False,
       needs="services", ntopng="TLS Self-signed Certificate", ignore=("ips", "Devices to ignore", []),
       repeat_hours=("int", "Alert again after (hours)", 168))
def tls_self_signed(p, w):
    return [hit(r["ip"], f"{r['ip']}|{r['port']}", f"TCP/{r['port']}: self-signed certificate ({r['cert_subject']})")
            for r in services("kind = 'tls' AND self_signed = 1", ignore=p["ignore"])]


@check("tls_obsolete", "Service posture", "Obsolete TLS version",
       "A device still accepts TLS 1.0 or 1.1 - retired versions with known weaknesses.", 30, needs="services",
       ntopng="TLS Obsolete Version / Weak Cipher", ignore=("ips", "Devices to ignore", []),
       repeat_hours=("int", "Alert again after (hours)", 168))
def tls_obsolete(p, w):
    return [hit(r["ip"], f"{r['ip']}|{r['port']}",
                f"TCP/{r['port']} accepts TLS {', '.join(v for v in r['tls'] if v in ('1.0', '1.1'))}")
            for r in services("kind = 'tls' AND hasAny(tls, ['1.0', '1.1'])", ignore=p["ignore"])]


def version(s):
    """'7.4p1' -> (7, 4, 1): the numbers in it, for comparing."""
    return tuple(int(x) for x in re.findall(r"\d+", s)[:4])


def _versions(v):
    out = [str(x).strip() for x in (v if isinstance(v, list) else str(v).replace(",", " ").split()) if str(x).strip()]
    bad = [x for x in out if not re.fullmatch(r"[\w.-]+/\d[\w.]*", x)]
    if bad:
        raise ValueError(f"not product/version: {bad[0]}")
    return out


TYPES["versions"] = _versions


def outdated(banner, minimums):
    """The 'product/version' in a banner older than its minimum - e.g.
    'Apache/2.2.15 (CentOS)' against Apache/2.4."""
    for m in minimums:
        product, least = m.split("/", 1)
        found = re.search(re.escape(product) + r"[/_ -]v?(\d[\w.]*)", banner, re.I)
        if found and version(found.group(1)) < version(least):
            return f"{product} {found.group(1)} (older than {least})"
    return ""


@check("ssh_obsolete", "Service posture", "Obsolete SSH server",
       "A device's SSH server speaks protocol 1, or is older than the minimum versions given (OpenSSH, "
       "Dropbear) - known vulnerabilities.", 40, needs="services", ntopng="SSH Obsolete Server",
       minimums=("versions", "Minimum versions", ["OpenSSH/8.0", "dropbear/2020.79"]),
       ignore=("ips", "Devices to ignore", []), repeat_hours=("int", "Alert again after (hours)", 168))
def ssh_obsolete(p, w):
    out = []
    for r in services("kind = 'ssh'", ignore=p["ignore"]):
        old = "SSH protocol 1" if re.match(r"SSH-1\.", r["banner"]) else outdated(r["banner"], p["minimums"])
        if old:
            out.append(hit(r["ip"], f"{r['ip']}|{r['port']}", f"TCP/{r['port']}: {old} - {r['banner']}"))
    return out


@check("http_obsolete", "Service posture", "Obsolete web server",
       "A device's web server announces a version older than the minimums given (its Server header).", 30,
       needs="services", ntopng="HTTP Obsolete Server",
       minimums=("versions", "Minimum versions",
                 ["Apache/2.4.50", "nginx/1.20", "Microsoft-IIS/10.0", "lighttpd/1.4.60", "OpenSSL/1.1.1"]),
       ignore=("ips", "Devices to ignore", []), repeat_hours=("int", "Alert again after (hours)", 168))
def http_obsolete(p, w):
    out = []
    for r in services("kind IN ('http', 'tls') AND banner != ''", ignore=p["ignore"]):
        old = outdated(r["banner"], p["minimums"])
        if old:
            out.append(hit(r["ip"], f"{r['ip']}|{r['port']}", f"TCP/{r['port']}: {old} - {r['banner']}"))
    return out


@check("smb_v1", "Service posture", "SMBv1 enabled",
       "A device accepts SMB version 1 - the protocol WannaCry and NotPetya spread through.", 60, needs="services",
       ntopng="SMB Insecure Version", ignore=("ips", "Devices to ignore", []),
       repeat_hours=("int", "Alert again after (hours)", 168))
def smb_v1(p, w):
    return [hit(r["ip"], r["ip"], "accepts SMBv1 on TCP/445")
            for r in services("kind = 'smb' AND smb1 = 1", ignore=p["ignore"])]


@check("cleartext_service", "Service posture", "Clear-text service on the LAN",
       "A device offers a login over a clear-text protocol (Telnet, FTP, rexec, rlogin) - passwords readable "
       "by anyone on the network. From the collectors' port scans.", 40, needs="arp",
       ntopng="Clear-Text Credentials / Unsafe Protocol",
       ports=("ports", "TCP ports", [21, 23, 512, 513]), ignore=("ips", "Devices to ignore", []),
       repeat_hours=("int", "Alert again after (hours)", 168))
def cleartext_service(p, w):
    rows = query(f"""
        SELECT ip, arrayFilter(x -> has({{ports:Array(UInt16)}}, x), ports) AS open, hostname
        FROM netview.assets FINAL
        WHERE last_seen > now() - INTERVAL 2 DAY AND length(open) > 0 AND NOT {in_nets('ip', 'ignore')}""",
                 ports=p["ports"], ignore=p["ignore"])
    return [hit(r["ip"], f"{r['ip']}|{','.join(map(str, r['open']))}",
                "offers " + ", ".join(svc(6, x, {21: "ftp", 23: "telnet", 512: "rexec", 513: "rlogin"}.get(x, ""))
                                      for x in r["open"])) for r in rows]


# ------------------------------------------------------------------ network devices (SNMP)
DEVICES = """dev AS (SELECT key, ip, if(sys_name != '', sys_name, ip) AS name, collector FROM netview.snmp_devices FINAL)"""


@check("snmp_unreachable", "Network devices", "Network device not answering",
       "A switch, router or access point that answered SNMP stops answering while its collector is still "
       "running - down, rebooting or cut off.", 70, needs="snmp", ntopng="SNMP Device Unreachable (ntopng Enterprise)",
       minutes=("int", "Silent for (minutes)", 20), ignore=("ips", "Devices to ignore", []),
       repeat_hours=("int", "Alert again after (hours)", 6))
def snmp_unreachable(p, w):
    rows = query(f"""WITH {DEVICES},
        last AS (SELECT key, toUInt32(max(t)) AS last FROM netview.snmp_counters WHERE t > now() - INTERVAL 1 DAY GROUP BY key),
        alive AS (SELECT id FROM netview.collectors FINAL WHERE deleted = 0 AND last_seen > now() - INTERVAL 10 MINUTE)
        SELECT dev.ip AS ip, dev.name AS name, last.last AS last FROM dev INNER JOIN last ON dev.key = last.key
        WHERE last.last < toUInt32(now()) - {{minutes:UInt32}} * 60 AND dev.collector IN (SELECT id FROM alive)
          AND NOT {in_nets('dev.ip', 'ignore')}""", minutes=p["minutes"], ignore=p["ignore"])
    return [hit(r["ip"], r["ip"], f"{r['name']} hasn't answered SNMP for {(time.time() - r['last']) / 60:.0f} minutes")
            for r in rows]


# Each interface's readings over the hours, oldest first.
READINGS = """SELECT c.key AS key, c.if_index AS if_index, any(dev.ip) AS ip, any(dev.name) AS name,
       if(any(i.name) != '', any(i.name), any(i.descr)) AS port, any(i.type) AS type, any(i.alias) AS alias, any(i.admin) AS admin,
       arrayMap(x -> x.2, arraySort(groupArray((c.t, c.oper)))) AS opers,
       arrayMap(x -> x.2, arraySort(groupArray((c.t, c.in_errors + c.out_errors)))) AS errors
    FROM netview.snmp_counters AS c
    INNER JOIN dev ON dev.key = c.key
    LEFT JOIN (SELECT key, if_index, name, descr, type, alias, admin FROM netview.snmp_interfaces FINAL) AS i
      ON i.key = c.key AND i.if_index = c.if_index
    WHERE c.t > now() - INTERVAL {hours:UInt32} HOUR AND NOT """ + in_nets("dev.ip", "ignore") + """
    GROUP BY c.key, c.if_index"""


def port_name(r):
    return f"{r['name']} {r['port'] or 'interface ' + str(r['if_index'])}" + (f" ({r['alias']})" if r["alias"] else "")


@check("snmp_if_down", "Network devices", "Network port went down",
       "A switch or router port that was up in the last day is down now (and not shut down on purpose). "
       "By default only ports with a description - uplinks, servers, access points; desktops sleep.", 50,
       needs="snmp", ntopng="SNMP Interface Status Change (ntopng Enterprise)",
       described_only=("bool", "Only ports with a description", True), ignore=("ips", "Devices to ignore", []),
       repeat_hours=("int", "Alert again after (hours)", 6))
def snmp_if_down(p, w):
    rows = query(f"WITH {DEVICES} {READINGS}", hours=24, ignore=p["ignore"])
    return [hit(r["ip"], f"{r['ip']}|{r['if_index']}", f"{port_name(r)} is down", value=r["if_index"])
            for r in rows if r["opers"] and r["opers"][-1] in (2, 7) and 1 in r["opers"] and r["admin"] != 2
            and (r["alias"] or not p["described_only"])]


@check("snmp_if_flap", "Network devices", "Network port flapping",
       "A switch or router port goes up and down again and again within the hour - a bad cable, a failing "
       "transceiver or a loop.", 50, needs="snmp", ntopng="SNMP Interface Flapping (ntopng Enterprise)",
       threshold=("int", "Changes in one hour", 4), ignore=("ips", "Devices to ignore", []))
def snmp_if_flap(p, w):
    rows = query(f"WITH {DEVICES} {READINGS}", hours=1, ignore=p["ignore"])
    out = []
    for r in rows:
        n = sum(a != b for a, b in zip(r["opers"], r["opers"][1:]))
        if n >= p["threshold"]:
            out.append(hit(r["ip"], f"{r['ip']}|{r['if_index']}", f"{port_name(r)} changed state {n} times in an hour",
                           value=n))
    return out


RADIO = re.compile(r"(ath|wifi|wlan|radio|ra|rai)\d", re.I)  # access points' radios, often typed ethernet


@check("snmp_if_errors", "Network devices", "Network port errors",
       "A switch or router port counts more errors (in + out) than the threshold in 30 minutes - a bad cable, "
       "a duplex mismatch or interference. Wi-Fi radios are left out (they count errors all the time).", 40,
       needs="snmp", ntopng="SNMP Interface Errors (ntopng Enterprise)",
       threshold=("int", "Errors in 30 minutes", 100), ignore=("ips", "Devices to ignore", []))
def snmp_if_errors(p, w):
    rows = query(f"WITH {DEVICES} {READINGS.replace('{hours:UInt32} HOUR', '30 MINUTE')}", ignore=p["ignore"])
    out = []
    for r in rows:
        if r["type"] in (1, 71) or RADIO.match(r["port"] or ""):  # radios count errors all the time
            continue
        n = sum(b - a for a, b in zip(r["errors"], r["errors"][1:]) if b >= a)  # a reset (reboot): skipped
        if n >= p["threshold"]:
            out.append(hit(r["ip"], f"{r['ip']}|{r['if_index']}", f"{port_name(r)}: {n} errors in 30 minutes", value=n))
    return out


# ------------------------------------------------------------------ infrastructure (Prometheus)
PROM_URL = os.environ.get("PROM_URL", "").rstrip("/")
FS = 'fstype!~"tmpfs|overlay|squashfs|ramfs|devtmpfs|nsfs|autofs|fuse.*|efivarfs|tracefs"'  # as infra.py


def prom(q):
    r = requests.get(f"{PROM_URL}/api/v1/query", params={"query": q}, timeout=30)
    body = r.json()
    if body.get("status") != "success":
        raise RuntimeError(f"Prometheus: {body.get('error', '')[:200]}")
    return body["data"]["result"]


def node_hosts():
    """host label -> its address (the node target's)."""
    return {r["metric"]["host"]: r["metric"].get("instance", "").rsplit(":", 1)[0]
            for r in prom('up{job="node"}') if r["metric"].get("host")}


@check("infra_host_down", "Infrastructure", "Server down",
       "A monitored server stopped answering Prometheus (node_exporter) - down, or its exporter is.", 80,
       needs="prometheus", repeat_hours=("int", "Alert again after (hours)", 6))
def infra_host_down(p, w):
    return [hit(r["metric"].get("instance", "").rsplit(":", 1)[0], r["metric"].get("host", ""),
                f"{r['metric'].get('host', '')} isn't answering Prometheus")
            for r in prom('up{job="node"} == 0')]


@check("infra_disk_full", "Infrastructure", "Disk almost full",
       "A server's filesystem is fuller than the threshold.", 60, needs="prometheus",
       threshold=("int", "% used", 90))
def infra_disk_full(p, w):
    ips = node_hosts()
    rows = prom(f'100 * (1 - node_filesystem_avail_bytes{{{FS}}} / node_filesystem_size_bytes{{{FS}}}) >= {int(p["threshold"])}')
    return [hit(ips.get(m.get("host", ""), m.get("host", "")), f"{m.get('host', '')}|{m.get('mountpoint', '')}",
                f"{m.get('host', '')} {m.get('mountpoint', '')} is {float(r['value'][1]):.0f}% full",
                value=float(r["value"][1])) for r in rows for m in [r["metric"]]]


@check("infra_service_failed", "Infrastructure", "Service failed",
       "A systemd service on a server is in the failed state.", 50, needs="prometheus")
def infra_service_failed(p, w):
    ips = node_hosts()
    return [hit(ips.get(m.get("host", ""), m.get("host", "")), f"{m.get('host', '')}|{m.get('name', '')}",
                f"{m.get('name', '')} failed on {m.get('host', '')}")
            for r in prom('node_systemd_unit_state{state="failed"} == 1') for m in [r["metric"]]]


@check("infra_container", "Infrastructure", "Container unhealthy / crash-looping",
       "A Docker container reports unhealthy, was killed for running out of memory, or restarted more than "
       "the threshold within the hour.", 50, needs="prometheus",
       restarts=("int", "Restarts in one hour", 3), repeat_hours=("int", "Alert again after (hours)", 6))
def infra_container(p, w):
    ips = node_hosts()
    out = []

    def add(m, what, value=0):
        h = m.get("host", "")
        out.append(hit(ips.get(h, h), f"{h}|{m.get('container', '')}|{what.split()[0]}",
                       f"container {m.get('container', '')} on {h} {what}", value=value))
    for r in prom('docker_container_info{job="node",health="unhealthy"}'):
        add(r["metric"], "is unhealthy")
    for r in prom('docker_container_oom_killed{job="node"} == 1'):
        add(r["metric"], "was killed: out of memory")
    for r in prom(f'increase(docker_container_restart_count{{job="node"}}[1h]) >= {int(p["restarts"])}'):
        add(r["metric"], f"restarted {float(r['value'][1]):.0f} times in an hour", float(r["value"][1]))
    return out


# ------------------------------------------------------------------ intrusion detection (Suricata)
def ids_hits(w, low, high):
    rows = query(f"""
        SELECT if({in_nets('src', 'private')}, src, dst) AS host, if({in_nets('src', 'private')}, dst, src) AS rip,
               sid, any(signature) AS sig, any(category) AS cat, count() AS n,
               countIf(action IN ('blocked', 'drop')) AS blocked, any(dst_port) AS port, any(proto) AS proto
        FROM netview.ids_alerts
        WHERE {TIME.replace('TimeReceived', 't')} AND severity BETWEEN {{low:UInt8}} AND {{high:UInt8}}
        GROUP BY host, rip, sid""", **w, low=low, high=high, private=PRIVATE)
    return [hit(r["host"], f"{r['host']}|{r['sid']}",
                f"{r['sig']} ({r['cat'] or 'no category'}) with {r['rip']} {r['proto']}/{r['port']} - "
                f"{r['n']} time{'s' if r['n'] > 1 else ''}" + (", blocked" if r["blocked"] else ""),
                remote=r["rip"], value=r["n"]) for r in rows]


@check("ids_high", "Intrusion detection", "IDS alert (high)",
       "Suricata on the firewall matched a severity 1 signature - exploits, malware command traffic, attacks "
       "on a service (SQL injection, XSS...).", 85, needs="ids", ntopng="Suricata / IDS alerts")
def ids_high(p, w):
    return ids_hits(w, 1, 1)


@check("ids_medium", "Intrusion detection", "IDS alert (medium)",
       "Suricata on the firewall matched a severity 2 signature - suspicious traffic, policy violations, "
       "known-bad software.", 50, needs="ids")
def ids_medium(p, w):
    return ids_hits(w, 2, 2)


@check("ids_low", "Intrusion detection", "IDS alert (low)",
       "Suricata on the firewall matched a severity 3 or lower signature - mostly informational. Off by "
       "default.", 15, enabled=False, needs="ids")
def ids_low(p, w):
    return ids_hits(w, 3, 255)


# Health, not security: a full disk doesn't make a device dangerous.
NOT_SECURITY = ("Infrastructure", "Network devices")


@check("dangerous_host", "Score", "Dangerous device",
       "A device's alerts add up to the threshold within an hour - several things wrong at once. The "
       "Infrastructure and Network devices checks (health, not security) don't count.", 100,
       needs="alerts", ntopng="Dangerous Host",
       threshold=("int", "Score in one hour", 150), repeat_hours=("int", "Alert again after (hours)", 1))
def dangerous_host(p, w):
    rows = query(f"""
        SELECT host, sum(score) AS total, uniq(check_id) AS checks, groupUniqArray(check_id) AS ids
        FROM netview.alerts WHERE t > now() - INTERVAL 1 HOUR AND check_id NOT IN {{not_security:Array(String)}}
          AND NOT {in_nets('host', 'ign')} AND {NOT_OWN}
        GROUP BY host HAVING total >= {{threshold:UInt32}}""", threshold=p["threshold"], ign=nets_of("ignore"),
                 not_security=[i for i, c in CHECKS.items() if c["group"] in NOT_SECURITY or i == "dangerous_host"],
                 **NOT_OWN_PARAMS())
    return [hit(r["host"], r["host"], f"score {r['total']} in the last hour from {r['checks']} checks: "
                + ", ".join(CHECKS[i]["title"] for i in r["ids"] if i in CHECKS), value=r["total"]) for r in rows]


# ------------------------------------------------------------------ settings
_settings = {"t": 0, "data": {}}
_lock = threading.Lock()


def severity(score):
    return next(name for floor, name in SEVERITIES if score >= floor)


def stored():
    with _lock:
        if time.time() - _settings["t"] > 10:
            try:
                rows = query("SELECT id, enabled, score, params, by, version FROM netview.check_settings FINAL")
                _settings["data"] = {r["id"]: r for r in rows}
                _settings["t"] = time.time()
            except (RuntimeError, requests.RequestException):
                pass  # not created yet, or ClickHouse away: the defaults (or the last read)
        return dict(_settings["data"])


def effective(cid, saved=None):
    """A check's settings: the defaults, with what's been saved over them."""
    c = CHECKS[cid]
    s = (saved if saved is not None else stored()).get(cid)
    params = {k: TYPES[t](d) for k, (t, _, d) in c["params"].items()}
    out = {"enabled": c["enabled"], "score": c["score"], "params": params, "by": "", "changed": 0}
    if s:
        try:
            for k, v in json.loads(s["params"] or "{}").items():
                if k in c["params"]:
                    params[k] = TYPES[c["params"][k][0]](v)
        except (ValueError, TypeError):
            pass  # a bad stored value: the default
        out.update(enabled=bool(s["enabled"]), score=int(s["score"]), by=s["by"], changed=s["version"] // 10**9)
    return out


# The admins' two address lists, stored as a pseudo-check's params - entries
# {net, note, by, added}:
#   ignore     devices whose alerts are still recorded and shown, as warnings,
#              but count nowhere (risk, totals, dangerous_host) - decided when
#              read, so taking a device off makes its alerts count again
#   blacklist  addresses the my_blacklist check always flags
GLOBAL = "_global"
LISTS = ("ignore", "blacklist")


def entries(kind, saved=None):
    s = (saved if saved is not None else stored()).get(GLOBAL)
    try:
        raw = json.loads(s["params"]).get(kind, []) if s else []
    except (ValueError, TypeError, AttributeError):
        return []
    out = []
    for e in raw:
        e = e if isinstance(e, dict) else {"net": e}  # a bare address (the first version)
        try:
            out.append({"net": _nets([e["net"]])[0], "note": str(e.get("note", "")), "by": e.get("by", ""),
                        "added": int(e.get("added", 0))})
        except (ValueError, KeyError):
            continue
    return out


def nets_of(kind, saved=None):
    return [e["net"] for e in entries(kind, saved)]


def save(cid, enabled, score, params, by):
    ch("INSERT INTO netview.check_settings FORMAT JSONEachRow",
       json.dumps({"id": cid, "enabled": int(enabled), "score": int(score), "params": json.dumps(params),
                   "by": by, "version": time.time_ns()}))
    _settings["t"] = 0


# ------------------------------------------------------------------ feeds
def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sentry-lens/1"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", "ignore")


# Never threats: FireHOL level 1 lists the bogons too - the LAN, Tailscale,
# multicast and broadcast among them.
SPECIAL = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
    "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "224.0.0.0/3", "::/8", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32")]


def _public(net):
    """A list's range, kept only if it's all public."""
    try:
        n = ipaddress.ip_network(net, strict=False)
    except ValueError:
        return None
    if n.prefixlen < (8 if n.version == 4 else 16) or any(n.version == s.version and n.overlaps(s) for s in SPECIAL):
        return None
    return str(n)


def load_feeds():
    prefixes, counts, asns, errors = {}, {}, [], []
    for fid, (_, url, kind) in FEEDS.items():
        try:
            text = _fetch(url)
            if kind == "asn":
                for line in text.splitlines():
                    try:
                        row = json.loads(line)
                    except ValueError:
                        continue
                    if "asn" in row:
                        asns.append({"asn": int(row["asn"]), "name": row.get("asname", "")})
                counts[fid] = len(asns)
                continue
            if kind == "tor":
                addrs = [a.strip("[]") for r in json.loads(text).get("relays", []) for a in r.get("a", [])]
            else:
                addrs = [line.split("#")[0].split(";")[0].strip() for line in text.splitlines()]
            n = 0
            for a in addrs:
                net = _public(a) if a else None
                if net:
                    prefixes.setdefault(net, []).append(fid)
                    n += 1
            counts[fid] = n
        except Exception as e:  # keep the other lists
            errors.append(f"{fid}: {e}")
    if not prefixes:
        raise RuntimeError("no threat list could be loaded: " + "; ".join(errors))
    ch("DROP TABLE IF EXISTS netview.threat_ips_new")
    ch("CREATE TABLE netview.threat_ips_new AS netview.threat_ips")
    rows = [f"{p}\t{','.join(ls)}" for p, ls in prefixes.items()]
    for i in range(0, len(rows), 100000):
        ch("INSERT INTO netview.threat_ips_new (prefix, lists) FORMAT TSV", "\n".join(rows[i:i + 100000]))
    ch("EXCHANGE TABLES netview.threat_ips AND netview.threat_ips_new")
    ch("DROP TABLE IF EXISTS netview.threat_ips_new")
    if asns:
        ch("DROP TABLE IF EXISTS netview.threat_asns_new")
        ch("CREATE TABLE netview.threat_asns_new AS netview.threat_asns")
        ch("INSERT INTO netview.threat_asns_new FORMAT JSONEachRow", "\n".join(json.dumps(a) for a in asns))
        ch("EXCHANGE TABLES netview.threat_asns AND netview.threat_asns_new")
        ch("DROP TABLE IF EXISTS netview.threat_asns_new")
    ch(f"SYSTEM RELOAD DICTIONARY {THREAT_DICT}")
    status.update(feeds=counts, feeds_loaded=int(time.time()), feeds_error="; ".join(errors))


# ------------------------------------------------------------------ the run
_last = {}  # (check, key) -> last alert time
_wake = threading.Event()


def available(c):
    """Why a check can't run now ('' = it can)."""
    if c["needs"] == "dns" and not dns.status["enabled"]:
        return "needs the DNS collector"
    if c["needs"] == "feeds" and not status["feeds_loaded"]:
        return "threat lists not loaded yet"
    if c["needs"] == "prometheus" and not PROM_URL:
        return "needs Prometheus (monitoring.yml)"
    if c["needs"] == "ids" and not ids.status["enabled"]:
        return "needs Suricata on the firewall and sl_ids: true (the sentrylens playbook)"
    if c["needs"] in NEEDS_DATA and not has_data(c["needs"]):
        return NEEDS_DATA[c["needs"]][1]
    return ""


# Checks fed by the collectors: nothing to look at until a collector sends it.
NEEDS_DATA = {
    "arp": ("SELECT (SELECT count() FROM netview.asset_obs WHERE mac != '' AND t > now() - INTERVAL 1 DAY)"
            " + (SELECT count() FROM netview.snmp_arp WHERE t > now() - INTERVAL 1 DAY) AS n",
            "needs a collector (Assets > Collectors) on the network"),
    "services": ("SELECT count() AS n FROM netview.asset_services WHERE t > now() - INTERVAL 2 DAY",
                 "needs a collector 2.4.0 or newer (Assets > Collectors)"),
    "snmp": ("SELECT count() AS n FROM netview.snmp_devices", "needs network devices read over SNMP (Assets > SNMP)"),
}
_has = {}  # needs -> (checked at, has data)


def has_data(needs):
    t, ok = _has.get(needs, (0, False))
    if time.time() - t > 600:
        try:
            ok = query(NEEDS_DATA[needs][0])[0]["n"] > 0
        except (RuntimeError, requests.RequestException, IndexError):
            ok = False  # its tables aren't there yet
        _has[needs] = (time.time(), ok)
    return ok


def run_once():
    t0 = time.time()
    end = int(t0) - LAG
    w = {"start": end - WINDOW, "end": end, "dstart": end - DNS_WINDOW, "wan": WAN_EXPORTER,
         "lanexp": LAN_EXPORTERS, "lan": LAN_ROLE}
    saved = stored()
    errors = {}
    # dangerous_host last: it adds up this run's alerts too.
    for cid in sorted(CHECKS, key=lambda i: CHECKS[i]["needs"] == "alerts"):
        c, s = CHECKS[cid], effective(cid, saved)
        if not s["enabled"] or available(c):
            continue
        try:
            hits = c["run"](s["params"], w)
        except Exception as e:  # one check failing doesn't stop the others
            errors[cid] = str(e)[:300]
            continue
        if c["group"] not in HEALTH:
            own = [ipaddress.ip_network(n) for n in own_nets()]
            hits = [h for h in hits if not (mine(h["host"], own) or mine(h["remote"], own))]
        repeat = s["params"].get("repeat_hours", 6) * 3600
        rows = []
        for h in hits:
            k = (cid, h["key"])
            if t0 - _last.get(k, 0) < repeat:  # ignored devices too: their alerts show as warnings
                continue
            _last[k] = t0
            rows.append(json.dumps({"t": int(t0), "check_id": cid, "score": s["score"], **h}))
        if rows:
            ch("INSERT INTO netview.alerts FORMAT JSONEachRow", "\n".join(rows))
    status.update(last_run=int(t0), run_seconds=round(time.time() - t0, 1), errors=errors, last_error="")


def loop():
    for d in DDL:
        try:
            ch(d)
        except Exception as e:
            status["last_error"] = f"setup: {e}"
            return
    # What alerted lately, so a restart doesn't repeat it.
    try:
        for r in query("SELECT check_id, key, toUInt32(max(t)) AS t FROM netview.alerts "
                       "WHERE t > now() - INTERVAL 2 DAY GROUP BY check_id, key"):
            _last[(r["check_id"], r["key"])] = r["t"]
    except Exception as e:
        status["last_error"] = f"alerts: {e}"
    next_feeds = 0
    while True:
        if time.time() >= next_feeds:
            try:
                load_feeds()
                next_feeds = time.time() + FEED_EVERY
            except Exception as e:
                status["feeds_error"] = str(e)[:300]
                next_feeds = time.time() + 1800
        try:
            run_once()
        except Exception as e:
            status["last_error"] = str(e)[:300]
        _wake.wait(RUN_EVERY)
        _wake.clear()


def start(namer=None):
    if namer:
        NAMER[0] = namer
    threading.Thread(target=loop, daemon=True, name="checks").start()


# ------------------------------------------------------------------ API
router = APIRouter()


def _admin(request):
    if auth.ENABLED:
        auth.require_admin(request)
    u = getattr(request.state, "user", None)
    return u["email"] if u else "local"


def _check_json(cid, saved, counts):
    c, s = CHECKS[cid], effective(cid, saved)
    return {"id": cid, "group": c["group"], "title": c["title"], "description": c["description"],
            "ntopng": c["ntopng"], "needs": c["needs"], "unavailable": available(c),
            "enabled": s["enabled"], "score": s["score"], "severity": severity(s["score"]),
            "default_enabled": c["enabled"], "default_score": c["score"], "by": s["by"], "changed": s["changed"],
            "params": [{"key": k, "type": t, "label": lbl, "value": s["params"][k], "default": d}
                       for k, (t, lbl, d) in c["params"].items()],
            "alerts_24h": counts.get(cid, {}).get("n", 0), "last_alert": counts.get(cid, {}).get("last", 0),
            "error": status["errors"].get(cid, "")}


@router.get("/alerts")
def alerts_page():
    return FileResponse(os.path.join(STATIC, "alerts.html"))


@router.get("/api/checks")
def list_checks():
    saved = stored()
    counts = {r["check_id"]: r for r in query(
        "SELECT check_id, count() AS n, toUInt32(max(t)) AS last FROM netview.alerts "
        "WHERE t > now() - INTERVAL 1 DAY GROUP BY check_id")}
    return {"groups": GROUPS, "severities": [{"min": f, "name": n} for f, n in SEVERITIES],
            "feeds": [{"id": f, "label": lbl, "count": status["feeds"].get(f, 0)} for f, (lbl, _, _) in FEEDS.items()],
            "categories": [{"key": k, "label": lbl, "group": g} for k, (lbl, g) in categories.CATS.items()],
            "checks": [_check_json(cid, saved, counts) for cid in CHECKS],
            "lists": {kind: entries(kind, saved) for kind in LISTS}, "own": own_nets(),
            "status": {k: v for k, v in status.items() if k != "errors"} | {"every": RUN_EVERY, "window": WINDOW}}


@router.post("/api/checks/run")
def run_now(request: Request):
    _admin(request)
    _wake.set()
    return {"ok": True}


@router.post("/api/lists/{kind}/{action}")
async def change_list(request: Request, kind: str, action: str):
    """Add an address or range to the ignore list or the blacklist
    ({net, note}), or take one off ({net})."""
    by = _admin(request)
    if kind not in LISTS or action not in ("add", "remove"):
        raise HTTPException(404, "lists are ignore / blacklist, actions add / remove")
    body = await request.json()
    try:
        net = _nets([str(body.get("net", "")).strip()])[0]
    except (ValueError, IndexError):
        raise HTTPException(400, "an IP address or range (192.168.3.4, 10.0.0.0/8)")
    _settings["t"] = 0  # the latest lists, not a cached read
    saved = stored()
    lists = {k: entries(k, saved) for k in LISTS}
    lists[kind] = [e for e in lists[kind] if e["net"] != net]
    if action == "add":
        lists[kind].append({"net": net, "note": str(body.get("note", ""))[:200], "by": by, "added": int(time.time())})
    save(GLOBAL, True, 0, lists, by)
    return {"lists": lists}


@router.post("/api/checks/{cid}")
async def change_check(request: Request, cid: str):
    """Turn a check on/off, set its score, change its parameters - or reset it."""
    by = _admin(request)
    body = await request.json()
    if cid not in CHECKS:
        raise HTTPException(404, "no such check")
    c = CHECKS[cid]
    if body.get("reset"):
        save(cid, c["enabled"], c["score"], {}, by)
    else:
        cur = effective(cid)
        score = body.get("score", cur["score"])
        if not isinstance(score, int) or not 0 <= score <= 100:
            raise HTTPException(400, "score is a whole number from 0 to 100")
        params = dict(cur["params"])
        for k, v in (body.get("params") or {}).items():
            if k not in c["params"]:
                raise HTTPException(400, f"no parameter {k}")
            try:
                params[k] = TYPES[c["params"][k][0]](v)
            except (ValueError, TypeError) as e:
                raise HTTPException(400, f"{c['params'][k][1]}: {e}")
        save(cid, bool(body.get("enabled", cur["enabled"])), score, params, by)
    return _check_json(cid, stored(), {})


RANGES = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
FLOWS_KEPT = int(os.environ.get("FLOWS_DAYS", "7")) * 86400  # flows kept (sl_flows_days) - the countries view can't go further back

# Internet conversations (device <-> address) read from the device's side,
# with whether anything came back: the firewall's NetFlow sees a LAN packet
# before a block rule drops it, so a blocked attempt is out with nothing in.
PAIRS = WAN + """,
pairs AS (SELECT local, remote, any(rcc) AS cc, any(ras) AS pasn, countIf(dl) AS back, count() AS flows, sum(b) AS bytes,
                 toUInt32(max(t)) AS last
          FROM wan WHERE rcc != '' GROUP BY local, remote)"""


def country_window(range):
    if range not in RANGES:
        raise HTTPException(400, f"range must be one of {list(RANGES)}")
    end = int(time.time())
    return {"start": end - min(RANGES[range], FLOWS_KEPT), "end": end, "wan": WAN_EXPORTER, "lan": LAN_ROLE}


@router.get("/api/countries")
def countries(range: str = "24h"):
    """Per country: the traffic that got through (anything came back) and the
    attempts that got nothing back - blocked by the firewall for a country on
    the block list (Blocked country's), unanswered for the others."""
    w = country_window(range)
    rows = query(f"""WITH {PAIRS}
        SELECT cc,
               sumIf(bytes, back > 0) AS through_bytes, sumIf(flows, back > 0) AS through_flows,
               uniqIf(remote, back > 0) AS through_ips, uniqIf(local, back > 0) AS through_devices,
               sumIf(flows, back = 0) AS attempts, uniqIf(remote, back = 0) AS attempt_ips,
               uniqIf(local, back = 0) AS attempt_devices, max(last) AS last
        FROM pairs GROUP BY cc ORDER BY through_bytes DESC""", **w)
    listed = effective("blocked_country")["params"]["countries"]
    for r in rows:
        r["blocklisted"] = r["cc"] in listed
    return {"range": range, "start": w["start"], "end": w["end"], "capped": RANGES[range] > FLOWS_KEPT,
            "blocklist": listed, "countries": rows}


@router.get("/api/countries/{cc}")
def country(cc: str, range: str = "24h"):
    """One country: per device and per remote address, got through vs not."""
    if not re.fullmatch(r"[A-Z]{2}", cc):
        raise HTTPException(400, "not a country code")
    w = country_window(range) | {"cc": cc}
    devices = query(f"""WITH {PAIRS}
        SELECT {IP('local')} AS host, sumIf(bytes, back > 0) AS through_bytes, sumIf(flows, back > 0) AS through_flows,
               uniqIf(remote, back > 0) AS through_ips, sumIf(flows, back = 0) AS attempts,
               uniqIf(remote, back = 0) AS attempt_ips, max(last) AS last
        FROM pairs WHERE cc = {{cc:String}} GROUP BY local ORDER BY through_bytes DESC, attempts DESC LIMIT 100""", **w)
    remotes = query(f"""WITH {PAIRS}
        SELECT {IP('remote')} AS ip, any(pasn) AS asn, dictGetOrDefault('asns', 'name', toUInt32(asn), '') AS asn_name,
               max(back) > 0 AS through, sum(bytes) AS bytes, sum(flows) AS flows, uniq(local) AS devices, max(last) AS last
        FROM pairs WHERE cc = {{cc:String}} GROUP BY remote ORDER BY through DESC, bytes DESC LIMIT 200""", **w)
    for r in devices:
        r["name"] = NAMER[0](r["host"])
    return {"cc": cc, "range": range, "blocklisted": cc in effective("blocked_country")["params"]["countries"],
            "devices": devices, "remotes": remotes}


@router.get("/api/alerts")
def list_alerts(range: str = "24h", check_id: str = "", host: str = "", min_score: int = 0,
                max_score: int = 100, ignored: bool = True):
    """Alerts newest first, with totals per check and per device (its risk
    score). Those of devices on the ignore list come as warnings (ignored =
    1, shown unless ignored=false) and count in no total or risk."""
    if range not in RANGES:
        raise HTTPException(400, f"range must be one of {list(RANGES)}")
    if check_id and check_id not in CHECKS:
        raise HTTPException(400, "no such check")
    if host:
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            raise HTTPException(400, "not an IP address")
    p = {"since": int(time.time()) - RANGES[range], "check": check_id, "host": host, "min": max(0, min_score),
         "max": min(100, max(0, max_score)), "ign": nets_of("ignore")} | NOT_OWN_PARAMS()
    where = ("t >= toDateTime({since:UInt32}) AND score BETWEEN {min:UInt32} AND {max:UInt32}"
             " AND ({check:String} = '' OR check_id = {check:String}) AND ({host:String} = '' OR host = {host:String})"
             " AND " + NOT_OWN)
    ign = in_nets("host", "ign")
    rows = query(f"""SELECT toUInt32(t) AS t, check_id, score, host, remote, detail, value, {ign} AS ignored
        FROM netview.alerts WHERE {where} {"" if ignored else f"AND NOT {ign}"}
        ORDER BY t DESC, score DESC LIMIT 1000""", **p)
    by_host = query(f"""SELECT host, any({ign}) AS ignored, sumIf(score, NOT {ign}) AS risk,
               countIf(NOT {ign}) AS alerts, countIf({ign}) AS warnings, max(score) AS top,
               groupUniqArray(check_id) AS checks, toUInt32(max(t)) AS last
        FROM netview.alerts WHERE {where} GROUP BY host ORDER BY ignored, risk DESC, warnings DESC LIMIT 200""", **p)
    by_check = query(f"""SELECT check_id, countIf(NOT {ign}) AS alerts, countIf({ign}) AS warnings,
               uniq(host) AS hosts, toUInt32(max(t)) AS last
        FROM netview.alerts WHERE {where} GROUP BY check_id ORDER BY alerts DESC""", **p)
    totals = query(f"""SELECT countIf(NOT {ign}) AS alerts, countIf(NOT {ign} AND score >= 60) AS serious,
               countIf({ign}) AS warnings, uniqIf(host, NOT {ign}) AS hosts
        FROM netview.alerts WHERE {where}""", **p)[0]
    titles = {cid: c["title"] for cid, c in CHECKS.items()}
    for r in rows:
        r |= {"title": titles.get(r["check_id"], r["check_id"]), "severity": severity(r["score"]),
              "name": NAMER[0](r["host"])}
    for r in by_host:
        r["name"] = NAMER[0](r["host"])
        r["severity"] = severity(r["top"])
    for r in by_check:
        r["title"] = titles.get(r["check_id"], r["check_id"])
    return {"range": range, "alerts": rows, "hosts": by_host, "checks": by_check, "totals": totals,
            "capped": len(rows) >= 1000}
