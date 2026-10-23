"""netview's DNS collector: which device looked up which domain, and the IPs
it got - what turns flows (IPs only) into visited websites.

Every POLL seconds it reads the firewall's Unbound query log (the DNS
overview API - the last 1000 lookups, ~10 min here) with netview's own
read-only API key, keeps the lookups newer than the last ones stored, and
writes them to netview.dns. Unbound doesn't log answers, so each new domain is
resolved again through the same Unbound - from its cache, so the IPs the
device just got - into netview.dns_ips (one row per device, domain and IP),
which the flows are matched against.

Kept out: our own lookups (COLLECTOR_IP - the Docker host), the firewall's
own, local names, reverse lookups and failed or blocked ones.
"""
import ipaddress
import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # the firewall's self-signed cert

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
OPN_URL = os.environ.get("OPN_URL", "").rstrip("/")
OPN_KEY = os.environ.get("OPN_KEY", "")
OPN_SECRET = os.environ.get("OPN_SECRET", "")
COLLECTOR_IP = os.environ.get("COLLECTOR_IP", "")
POLL = int(os.environ.get("DNS_POLL", "30"))
RETENTION_DAYS = int(os.environ.get("DNS_RETENTION_DAYS", "30"))
CACHE_TTL = 300  # seconds an answer is reused before resolving the domain again

TYPES = {"A", "AAAA", "HTTPS"}
SKIP_SUFFIXES = (".arpa", ".internal", ".local", ".lan", ".localdomain", ".home")

# One registrable name per domain ("lh3.googleusercontent.com" -> googleusercontent.com);
# ClickHouse's own list of public suffixes.
SITE = "if(cutToFirstSignificantSubdomain(domain) = '', domain, cutToFirstSignificantSubdomain(domain))"

DDL = [
    "CREATE DATABASE IF NOT EXISTS netview",
    f"""CREATE TABLE IF NOT EXISTS netview.dns (
        t DateTime, client IPv6, domain String, site LowCardinality(String),
        type LowCardinality(String), source LowCardinality(String)
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (t, client)
    TTL t + INTERVAL {RETENTION_DAYS} DAY""",
    f"""CREATE TABLE IF NOT EXISTS netview.dns_ips (
        t DateTime, client IPv6, ip IPv6, domain String, site LowCardinality(String)
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (client, ip, t)
    TTL t + INTERVAL {RETENTION_DAYS} DAY""",
]

status = {"enabled": bool(OPN_URL and OPN_KEY), "last_poll": 0, "last_error": "",
          "lookups": 0, "answers": 0, "watermark": 0}


def ch(sql, data=None):
    r = requests.post(CH_URL, params={"query": sql} if data is not None else None,
                      data=(data if data is not None else sql).encode(), timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"ClickHouse: {r.text[:300]}")
    return r.text


def insert(table, columns, select, rows):
    if rows:
        ch(f"INSERT INTO netview.{table} SELECT {select} FROM input('{columns}') FORMAT JSONEachRow",
           "\n".join(json.dumps(r) for r in rows))


class Collector:
    def __init__(self):
        self.opn = requests.Session()
        self.opn.auth = (OPN_KEY, OPN_SECRET)
        self.opn.verify = False
        self.cache = {}  # domain -> (expires, [ips])
        self.pool = ThreadPoolExecutor(8)
        self.seen_at_mark = set()  # lookups already stored at the watermark second

    def start(self):
        threading.Thread(target=self.loop, daemon=True, name="dns").start()

    def setup(self):
        for sql in DDL:
            ch(sql)
        status["watermark"] = int(ch("SELECT toUInt32(max(t)) FROM netview.dns").strip() or 0)
        self.ready = True

    def loop(self):
        self.ready = False
        while True:
            try:
                if not self.ready:
                    self.setup()
                self.poll()
                status["last_error"] = ""
            except Exception as e:  # keep going - the firewall or ClickHouse may be restarting
                status["last_error"] = f"{type(e).__name__}: {e}"[:300]
            status["last_poll"] = int(time.time())
            time.sleep(POLL)

    def fetch(self):
        r = self.opn.post(f"{OPN_URL}/api/unbound/overview/searchQueries",
                          json={"current": 1, "rowCount": -1, "searchPhrase": ""}, timeout=30)
        r.raise_for_status()
        return r.json().get("rows", [])

    def poll(self):
        mark = status["watermark"]
        new, at_mark = [], set()
        for row in self.fetch():
            t, client, domain = int(row.get("time") or 0), row.get("client") or "", (row.get("domain") or "").rstrip(".").lower()
            key = (t, client, domain, row.get("type"))
            if t < mark or (t == mark and key in self.seen_at_mark):
                continue
            if (row.get("type") not in TYPES or row.get("action") != "Pass" or row.get("rcode") != "NOERROR"
                    or row.get("source") == "Local" or client == COLLECTOR_IP or not is_ip(client)
                    or "." not in domain or domain.endswith(SKIP_SUFFIXES)):
                continue
            new.append({"t": t, "client": client, "domain": domain, "type": row["type"], "source": row.get("source") or ""})
            at_mark.add(key)
        if not new:
            return

        answers = self.resolve({r["domain"] for r in new})
        ips = [{"t": r["t"], "client": r["client"], "ip": ip, "domain": r["domain"]}
               for r in new for ip in answers.get(r["domain"], [])]
        # One row per device, domain and IP per poll is enough for the matching.
        ips = list({(r["client"], r["domain"], r["ip"]): r for r in ips}.values())
        insert("dns", "t UInt32, client String, domain String, type String, source String",
               f"toDateTime(t), toIPv6(client), domain, {SITE}, type, source", new)
        insert("dns_ips", "t UInt32, client String, ip String, domain String",
               f"toDateTime(t), toIPv6(client), toIPv6(ip), domain, {SITE}", ips)
        # Only once stored - a failed insert is retried on the next poll.
        top = max(r["t"] for r in new)
        self.seen_at_mark = {k for k in at_mark if k[0] == top} | (self.seen_at_mark if top == mark else set())
        status["watermark"] = top
        status["lookups"] += len(new)
        status["answers"] += len(ips)

    def resolve(self, domains):
        now = time.time()
        todo = [d for d in domains if self.cache.get(d, (0,))[0] < now]
        for d, ips in zip(todo, self.pool.map(lookup, todo)):
            self.cache[d] = (now + CACHE_TTL, ips)
        if len(self.cache) > 50000:
            self.cache = {d: v for d, v in self.cache.items() if v[0] >= now}
        return {d: self.cache[d][1] for d in domains if d in self.cache}


def is_ip(s):
    """The firewall's own lookups come in as "localhost"."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def lookup(domain):
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError:
        return []


def start():
    if status["enabled"]:
        Collector().start()
