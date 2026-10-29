"""Suricata's alerts from the firewall (OPNsense Services > Intrusion
Detection) - the payload checks flows can't do (exploits, SQL injection, XSS,
malware command servers, ...), as the ids_* checks' input.

Every POLL seconds it reads the newest alerts (api/ids/service/queryAlerts,
the netview API user - its "Services: Intrusion Detection" privilege comes
with IDS_ENABLED, sl_ids in the playbook) and keeps those newer than the last
ones stored in netview.ids_alerts. Nothing to read (IDS off, no privilege):
the ids checks say why they don't run.

OPNsense's alert list keeps only a signature's id, action and text - not its
severity or category. Those come from the rule (api/ids/settings/getRuleInfo,
once per rule): its classtype, whose priority in Suricata's
classification.config is the severity.
"""
import json
import os
import threading
import time
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # the firewall's self-signed cert

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
OPN_URL = os.environ.get("OPN_URL", "").rstrip("/")
OPN_KEY = os.environ.get("OPN_KEY", "")
OPN_SECRET = os.environ.get("OPN_SECRET", "")
ENABLED = os.environ.get("IDS_ENABLED", "") in ("1", "true", "yes") and bool(OPN_URL and OPN_KEY)
POLL = int(os.environ.get("IDS_POLL", "60"))
ROWS = 1000  # per poll - more than Suricata writes in a minute unless something's very wrong
RETENTION_DAYS = int(os.environ.get("ALERT_RETENTION_DAYS", "30"))

DDL = [
    "CREATE DATABASE IF NOT EXISTS netview",
    f"""CREATE TABLE IF NOT EXISTS netview.ids_alerts (
        t DateTime, src String, src_port UInt16, dst String, dst_port UInt16, proto LowCardinality(String),
        sid UInt32, signature String, category String, severity UInt8, action LowCardinality(String),
        iface LowCardinality(String), pos String
    ) ENGINE = MergeTree PARTITION BY toYYYYMMDD(t) ORDER BY (t, sid)
    TTL t + INTERVAL {RETENTION_DAYS} DAY""",
]

# Suricata's classification.config: classtype -> priority (1 = high ... 4 = low).
PRIORITY = {
    "not-suspicious": 3, "unknown": 3, "bad-unknown": 2, "attempted-recon": 2, "successful-recon-limited": 2,
    "successful-recon-largescale": 2, "attempted-dos": 2, "successful-dos": 2, "attempted-user": 1,
    "unsuccessful-user": 1, "successful-user": 1, "attempted-admin": 1, "successful-admin": 1, "rpc-portmap-decode": 2,
    "shellcode-detect": 1, "string-detect": 3, "suspicious-filename-detect": 2, "suspicious-login": 2,
    "system-call-detect": 2, "tcp-connection": 4, "trojan-activity": 1, "unusual-client-port-connection": 2,
    "network-scan": 3, "denial-of-service": 2, "non-standard-protocol": 2, "protocol-command-decode": 3,
    "web-application-activity": 2, "web-application-attack": 1, "misc-activity": 3, "misc-attack": 2, "icmp-event": 3,
    "inappropriate-content": 1, "policy-violation": 1, "default-login-attempt": 2, "targeted-activity": 1,
    "exploit-kit": 1, "external-ip-check": 2, "domain-c2": 1, "pup-activity": 2, "credential-theft": 1,
    "social-engineering": 2, "coin-mining": 2, "command-and-control": 1, "file-transfer": 2, "mail": 2,
    "media-streaming": 2, "messaging": 2, "social-media": 2, "test": 3, "uncategorized": 2,
}
UNKNOWN_PRIORITY = 2  # a classtype not in the table, or a rule that couldn't be read

status = {"enabled": ENABLED, "last_poll": 0, "last_error": "", "alerts": 0, "watermark": 0}


def ch(sql, data=None):
    r = requests.post(CH_URL, params={"query": sql} if data is not None else None,
                      data=(data if data is not None else sql).encode(), timeout=60)
    if r.status_code != 200:
        raise RuntimeError(f"ClickHouse: {r.text[:300]}")
    return r.text


def _time(s):
    """Suricata's 2024-05-01T12:00:00.123456+0200 -> epoch seconds."""
    try:
        return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp())
    except (TypeError, ValueError):
        return 0


def _int(v, top):
    try:
        return min(max(int(v), 0), top)
    except (TypeError, ValueError):
        return 0


class Reader:
    def __init__(self):
        self.opn = requests.Session()
        self.opn.auth = (OPN_KEY, OPN_SECRET)
        self.opn.verify = False
        self.seen_at_mark = set()
        self.ready = False
        self.rules = {}  # sid -> classtype

    def classtype(self, sid):
        if sid not in self.rules:
            try:
                r = self.opn.get(f"{OPN_URL}/api/ids/settings/getRuleInfo/{int(sid)}", timeout=30)
                ct = r.json().get("classtype", "") if r.status_code == 200 else ""
            except (requests.RequestException, ValueError, AttributeError):
                return ""  # asked again next time
            self.rules[sid] = "" if ct == "##none##" else str(ct)
        return self.rules[sid]

    def setup(self):
        for sql in DDL:
            ch(sql)
        status["watermark"] = int(ch("SELECT toUInt32(max(t)) FROM netview.ids_alerts").strip() or 0)
        self.ready = True

    def loop(self):
        while True:
            try:
                if not self.ready:
                    self.setup()
                self.poll()
                status["last_error"] = ""
            except Exception as e:  # the firewall or ClickHouse may be restarting
                status["last_error"] = f"{type(e).__name__}: {e}"[:300]
            status["last_poll"] = int(time.time())
            time.sleep(POLL)

    def poll(self):
        r = self.opn.post(f"{OPN_URL}/api/ids/service/queryAlerts",
                          data={"current": 1, "rowCount": ROWS, "searchPhrase": ""}, timeout=60)
        if r.status_code == 403:
            raise RuntimeError("the firewall refused: the netview API user needs Services: Intrusion Detection "
                               "(sl_ids: true, then the sentrylens playbook)")
        r.raise_for_status()
        mark, new, at_mark = status["watermark"], [], set()
        for row in r.json().get("rows", []):
            t = _time(row.get("timestamp"))
            pos = str(row.get("filepos", ""))
            if not t or t < mark or (t == mark and pos in self.seen_at_mark):
                continue
            new.append({"t": t, "src": str(row.get("src_ip", "")), "src_port": _int(row.get("src_port"), 65535),
                        "dst": str(row.get("dest_ip", "")), "dst_port": _int(row.get("dest_port"), 65535),
                        "proto": str(row.get("proto", ""))[:10], "sid": _int(row.get("alert_sid"), 2**32 - 1),
                        "signature": str(row.get("alert", ""))[:300], "category": str(row.get("alert_category", ""))[:120],
                        "severity": _int(row.get("alert_severity"), 255), "action": str(row.get("alert_action", ""))[:20],
                        "iface": str(row.get("in_iface", ""))[:30], "pos": pos})
            at_mark.add(pos)
        if not new:
            return
        for x in new:
            if not x["severity"]:  # (an OPNsense that someday passes it through: kept)
                x["category"] = x["category"] or self.classtype(x["sid"])
                x["severity"] = PRIORITY.get(x["category"], UNKNOWN_PRIORITY)
        ch("INSERT INTO netview.ids_alerts FORMAT JSONEachRow", "\n".join(json.dumps(x) for x in new))
        top = max(x["t"] for x in new)
        self.seen_at_mark = {x["pos"] for x in new if x["t"] == top} | (self.seen_at_mark if top == mark else set())
        status["watermark"] = top
        status["alerts"] += len(new)


def start():
    if ENABLED:
        threading.Thread(target=Reader().loop, daemon=True, name="ids").start()
