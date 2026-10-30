"""Sentry Lens: what the machines say when the collectors sign in with the
read-only accounts (creds.py; readonly_accounts.yml makes them) - Linux over
SSH, Windows by WMI over WinRM, Proxmox VE by its API. Collector 2.6.0+
reads each machine at most once an hour and sends what it got raw
(collector/inventory.go); it's read here, so what's shown can change without
a new collector.

  netview.host_inventory    a machine's latest reading, per way in (ssh / winrm
                            / proxmox): the summary, its packages or programs;
                            a failed reading keeps the last good one, with the error

Machines sign-in keys and certificates are pinned by the collector the first
time (collector/pins.go); Trust the new key lets one go after a reinstall.
"""
import ipaddress
import json
import re
import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request

import assets
import auth
import creds
import snmp

router = APIRouter()
KINDS = ("ssh", "winrm", "proxmox")
PORTS = {"ssh": 22, "winrm": 5986, "proxmox": 8006}
DDL = [
    """CREATE TABLE IF NOT EXISTS netview.host_inventory (
        ip String, kind LowCardinality(String), key String, collector String, cred String, t DateTime, ok UInt8,
        error String, last_ok DateTime, took_s Float32, summary String, packages String, ver UInt64
    ) ENGINE = ReplacingMergeTree(ver) ORDER BY (ip, kind) TTL t + INTERVAL 90 DAY""",
]
_ready = [False]
FORGET = {}  # collector id -> the pins to let go at its next contact ("ssh 10.0.0.5:22")


def q(sql, **params):
    if not _ready[0]:
        snmp.q("SELECT 1")
        for d in DDL:
            assets.checks.ch(d)
        _ready[0] = True
    return assets.checks.query(sql, **params)


def _admin(request):
    if auth.ENABLED:
        auth.require_admin(request)


# ------------------------------------------------------------------ Linux (sections of the script's output)
def _kv(text):
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            out[k.strip()] = v.strip().strip('"')
    return out


def _addr_port(s):
    """'0.0.0.0:22', '[::]:22', '*:22', '127.0.0.53%lo:53' -> ('0.0.0.0', 22)."""
    a, _, p = s.rpartition(":")
    a = a.strip("[]").split("%")[0]
    return a, int(p) if p.isdigit() else 0


ANSI = re.compile(r"\x1b\[[0-9;]*m")  # some ip builds colour their output even into a pipe
REMOTE_FS = ("cifs", "smb3", "nfs", "nfs4", "9p", "fuse")  # not this machine's disks: left out of the fullest


def parse_linux(sec):
    sec = {k: ANSI.sub("", v) for k, v in sec.items()}
    osr = _kv(sec.get("os", ""))
    uname = sec.get("uname", "").split()
    s = {"hostname": sec.get("hostname", "").strip(), "os": osr.get("PRETTY_NAME") or osr.get("NAME", ""),
         "os_id": osr.get("ID", ""), "version": osr.get("VERSION_ID", ""),
         "kernel": uname[1] if len(uname) > 1 else "", "arch": uname[2] if len(uname) > 2 else ""}
    try:
        s["uptime_s"] = int(float(sec.get("uptime", "0").split()[0]))
    except (ValueError, IndexError):
        s["uptime_s"] = 0
    cpu = [x for x in sec.get("cpu", "").splitlines() if x.strip()]
    s["cpu"] = cpu[0].split(":", 1)[1].strip() if cpu and ":" in cpu[0] else ""
    s["cores"] = int(cpu[-1]) if cpu and cpu[-1].strip().isdigit() else 0
    mem = {k: int(re.sub(r"\D", "", v) or 0) * 1024 for k, v in (ln.split(":", 1) for ln in sec.get("mem", "").splitlines() if ":" in ln)}
    s["mem_total"], s["mem_avail"] = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
    s["swap_total"], s["swap_free"] = mem.get("SwapTotal", 0), mem.get("SwapFree", 0)
    disks, seen = [], set()
    for ln in sec.get("disks", "").splitlines()[1:]:
        f = ln.split()
        if len(f) >= 7 and f[2].isdigit() and f[6] not in seen:
            seen.add(f[6])
            disks.append({"mount": f[6], "fs": f[1], "dev": f[0], "size": int(f[2]) * 1024, "used": int(f[3]) * 1024})
    s["disks"] = disks
    addrs = []
    for ln in sec.get("addrs", "").splitlines():
        f = ln.split()
        if len(f) >= 4 and f[2] in ("inet", "inet6") and f[1] != "lo" and not f[3].startswith("fe80:"):
            addrs.append({"if": f[1], "addr": f[3]})
    s["addrs"] = addrs
    listen = set()
    for ln in sec.get("listen", "").splitlines():
        f = ln.split()
        if len(f) >= 5:
            a, p = _addr_port(f[4])
            if p:
                listen.add((f[0], a, p))
    s["listening"] = [{"proto": pr, "addr": a, "port": p} for pr, a, p in sorted(listen, key=lambda x: (x[2], x[0], x[1]))]
    hw = [x.strip() for x in sec.get("hw", "").splitlines() if x.strip()]
    s["virt"] = hw[0] if hw and hw[0] != "none" else ""
    s["vendor"] = hw[1] if len(hw) > 1 else ""
    s["model"] = hw[2] if len(hw) > 2 else ""
    pkgs = []
    for ln in sec.get("packages", "").splitlines():
        if "\t" in ln:
            n, v = ln.split("\t", 1)
            pkgs.append([n, v])
        elif ln.strip():  # apk: name-version-rN
            m = re.match(r"(.+?)-(\d[^-]*-r\d+)$", ln.strip())
            pkgs.append([m.group(1), m.group(2)] if m else [ln.strip(), ""])
    pkgs.sort(key=lambda x: x[0].lower())
    updates = []
    sec_lines = sec.get("security", "")
    for ln in sec.get("updates", "").splitlines():
        if "/" in ln and "[upgradable" in ln:  # apt: name/origin,origin version arch [upgradable from: old]
            name, rest = ln.split("/", 1)
            f = rest.split()
            updates.append({"name": name, "version": f[1] if len(f) > 1 else "", "security": "-security" in f[0]})
        else:  # dnf: name.arch  version  repo
            f = ln.split()
            if len(f) == 3 and "." in f[0] and not ln.startswith(" "):
                if f[0].lower().startswith("obsoleting"):
                    break
                name = f[0].rsplit(".", 1)[0]
                updates.append({"name": name, "version": f[1],
                                "security": bool(re.search(rf"(?m)\s{re.escape(name)}-\d", sec_lines))})
    reboot = sec.get("reboot", "")
    s |= {"packages_n": len(pkgs), "updates_n": len(updates), "security_n": sum(u["security"] for u in updates),
          "updates": updates[:500], "reboot": "required" in reboot or "needs-restarting 1" in reboot,
          "updates_known": "updates" in sec and (s["os_id"] not in ("rocky", "rhel", "almalinux", "centos", "fedora", "ol")
                                                or "security" in sec)}
    return s, pkgs


# ------------------------------------------------------------------ Windows (WMI classes)
def _one(d, k):
    v = d.get(k) or []
    return v[0] if isinstance(v, list) and v else {}


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def _when(v):
    """A WMI datetime ('2026-10-29T08:00:00.5-04:00') or date ('10/15/2026') -> unix seconds (0: unknown)."""
    v = str(v or "").strip()
    for f in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%SZ", "%m/%d/%Y", "%Y%m%d"):
        try:
            d = datetime.strptime(re.sub(r"(\.\d{6})\d+", r"\1", v.replace("Z", "+00:00") if "%z" in f else v), f)
            return int((d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp())
        except ValueError:
            continue
    return 0


def _list(v):
    return v if isinstance(v, list) else [v] if v else []


def parse_windows(d):
    o, c, b, cpu = _one(d, "os"), _one(d, "computer"), _one(d, "bios"), _one(d, "cpu")
    boot = _when(o.get("LastBootUpTime"))
    hot = [{"id": h.get("HotFixID", ""), "what": h.get("Description", ""), "t": _when(h.get("InstalledOn"))} for h in d.get("hotfixes") or []]
    hot.sort(key=lambda h: -h["t"])
    listen = sorted({(x.get("LocalAddress", ""), _int(x.get("LocalPort"))) for x in d.get("listen") or []}, key=lambda x: (x[1], x[0]))
    pkgs = sorted(([str(p.get("Name", "")), str(p.get("Version", ""))] for p in d.get("programs") or [] if p.get("Name")),
                  key=lambda x: x[0].lower())
    s = {"hostname": o.get("CSName", ""), "os": o.get("Caption", ""), "version": o.get("Version", ""), "build": o.get("BuildNumber", ""),
         "arch": o.get("OSArchitecture", ""), "uptime_s": int(time.time()) - boot if boot else 0, "installed": _when(o.get("InstallDate")),
         "domain": c.get("Domain", "") if str(c.get("PartOfDomain", "")).lower() == "true" else "",
         "vendor": c.get("Manufacturer", ""), "model": c.get("Model", ""), "serial": b.get("SerialNumber", ""), "bios": b.get("SMBIOSBIOSVersion", ""),
         "cpu": cpu.get("Name", "").strip(), "cores": _int(c.get("NumberOfLogicalProcessors")),
         "mem_total": _int(o.get("TotalVisibleMemorySize")) * 1024, "mem_avail": _int(o.get("FreePhysicalMemory")) * 1024,
         "disks": [{"mount": x.get("DeviceID", ""), "fs": x.get("FileSystem", ""), "dev": x.get("VolumeName", ""),
                    "size": _int(x.get("Size")), "used": _int(x.get("Size")) - _int(x.get("FreeSpace"))} for x in d.get("disks") or []],
         "addrs": [{"if": n.get("Description", ""), "addr": a, "mac": n.get("MACAddress", "")}
                   for n in d.get("nics") or [] for a in _list(n.get("IPAddress")) if not a.startswith("fe80:")],
         "listening": [{"proto": "tcp", "addr": a, "port": p} for a, p in listen],
         "hotfixes": hot[:100], "last_hotfix": hot[0]["t"] if hot else 0, "packages_n": len(pkgs),
         "updates_known": False, "errors": d.get("errors") or {}}
    return s, pkgs


# ------------------------------------------------------------------ Proxmox VE (API answers, by path)
MACS = re.compile(r"(?i)\b([0-9a-f]{2}(?::[0-9a-f]{2}){5})\b")


def parse_proxmox(d):
    ver = d.get("/version") or {}
    status = d.get("/cluster/status") or []
    cluster = next((x.get("name", "") for x in status if x.get("type") == "cluster"), "")
    here = next((x.get("name", "") for x in status if x.get("type") == "node" and x.get("local")), "")  # the node asked
    nodes = []
    for n in d.get("/nodes") or []:
        st = d.get(f"/nodes/{n.get('node')}/status") or {}
        nodes.append({"name": n.get("node", ""), "status": n.get("status", ""), "cpu": n.get("cpu", 0), "cores": n.get("maxcpu", 0),
                      "mem": n.get("mem", 0), "mem_total": n.get("maxmem", 0), "uptime_s": n.get("uptime", 0),
                      "pve": st.get("pveversion", ""), "kernel": (st.get("current-kernel") or {}).get("release", "") or st.get("kversion", ""),
                      "model": (st.get("cpuinfo") or {}).get("model", ""), "load": st.get("loadavg", []),
                      "root_size": (st.get("rootfs") or {}).get("total", 0), "root_used": (st.get("rootfs") or {}).get("used", 0)})
    guests = []
    for r in d.get("/cluster/resources") or []:
        if r.get("type") not in ("qemu", "lxc"):
            continue
        base = f"/nodes/{r.get('node')}/{r['type']}/{r.get('vmid')}"
        cfg = d.get(base + "/config") or {}
        macs = sorted({m.upper() for k, v in cfg.items() if re.fullmatch(r"net\d+", k) for m in MACS.findall(str(v))})
        ips = sorted({i.get("inet", "").split("/")[0] for i in d.get(base + "/interfaces") or []
                      if i.get("name") != "lo" and i.get("inet")})
        guests.append({"vmid": r.get("vmid"), "name": r.get("name", ""), "type": r["type"], "node": r.get("node", ""),
                       "status": r.get("status", ""), "template": bool(r.get("template")), "cpu": r.get("cpu", 0), "cores": r.get("maxcpu", 0),
                       "mem": r.get("mem", 0), "mem_total": r.get("maxmem", 0), "disk": r.get("disk", 0), "disk_total": r.get("maxdisk", 0),
                       "uptime_s": r.get("uptime", 0), "os": cfg.get("ostype", ""), "macs": macs, "ips": ips,
                       "tags": [t for t in re.split(r"[;, ]", str(cfg.get("tags", ""))) if t]})
    guests.sort(key=lambda g: g["vmid"] or 0)
    first = next((n for n in nodes if n["name"] == here), nodes[0] if nodes else {})
    s = {"hostname": first.get("name", ""), "os": f"Proxmox VE {ver.get('version', '')}".strip(), "version": ver.get("version", ""),
         "kernel": first.get("kernel", ""), "cpu": first.get("model", ""), "cores": first.get("cores", 0),
         "mem_total": first.get("mem_total", 0), "mem_avail": first.get("mem_total", 0) - first.get("mem", 0),
         "uptime_s": first.get("uptime_s", 0), "cluster": cluster, "nodes": nodes, "guests": guests,
         "guests_n": len([g for g in guests if not g["template"]]), "running_n": len([g for g in guests if g["status"] == "running"]),
         "updates_known": False}
    return s, []


PARSE = {"ssh": parse_linux, "winrm": parse_windows, "proxmox": parse_proxmox}


# ------------------------------------------------------------------ from the collectors
def ingest(c, b):
    """{readings: [{ip, kind, cred, ok, error, took_s, data}]}."""
    now = int(time.time())
    rows = []
    for r in (b.get("readings") or [])[:2000]:
        try:
            ip = str(ipaddress.ip_address(r.get("ip", "")))
        except ValueError:
            continue
        kind = r.get("kind")
        if kind not in KINDS:
            continue
        row = {"ip": ip, "kind": kind, "key": snmp.key_for(ip), "collector": c["id"], "cred": str(r.get("cred", ""))[:40], "t": now,
               "ok": 1, "error": "", "last_ok": now, "took_s": float(r.get("took_s") or 0), "summary": "{}", "packages": "[]",
               "ver": time.time_ns()}
        err = str(r.get("error") or "")[:400]
        if r.get("ok") and isinstance(r.get("data"), dict):
            try:
                s, pkgs = PARSE[kind](r["data"])
                row |= {"summary": json.dumps(s), "packages": json.dumps(pkgs[:20000])}
            except Exception as e:  # noqa: BLE001 - a reading this side can't read: said, not lost
                err = f"Sentry Lens couldn't read the answer: {type(e).__name__}: {e}"[:400]
        else:
            err = err or "no answer"
        if err:  # the last good reading stays, with the error
            old = q("SELECT summary, packages, last_ok FROM netview.host_inventory FINAL WHERE ip = {ip:String} AND kind = {k:String}",
                    ip=ip, k=kind)
            row |= {"ok": 0, "error": err, "last_ok": assets._ts(old[0]["last_ok"]) if old else 0,
                    "summary": old[0]["summary"] if old else "{}", "packages": old[0]["packages"] if old else "[]"}
        rows.append(row)
    if rows:
        q("SELECT 1")
        assets.insert("host_inventory", rows)
    return len(rows)


@router.post("/api/collector/inventory")
async def collector_inventory(request: Request):
    c = assets._collector(request)
    return {"ok": True, "readings": ingest(c, await request.json())}


def forget_for(cid):
    """The pins this collector is to let go (sent once, in its config)."""
    return sorted(FORGET.pop(cid, set()))


# ------------------------------------------------------------------ the views
def _disk_max(s):
    return max((100 * x["used"] / x["size"] for x in s.get("disks") or []
                if x.get("size") and not str(x.get("fs", "")).startswith(REMOTE_FS)), default=0)


def _row(r, cs, full=False):
    s = json.loads(r["summary"] or "{}")
    name = assets.NAMER[0](r["ip"]) or (s.get("hostname") or "").split(".")[0]
    out = {"ip": r["ip"], "kind": r["kind"], "key": r["key"], "name": name, "ok": bool(r["ok"]), "error": r["error"],
           "t": assets._ts(r["t"]), "last_ok": assets._ts(r["last_ok"]), "took_s": round(r["took_s"], 1),
           "collector": cs.get(r["collector"], {}).get("name", r["collector"]),
           "trust": r["error"].startswith("pin:")}
    keep = ("hostname", "os", "version", "build", "kernel", "arch", "uptime_s", "cpu", "cores", "mem_total", "mem_avail", "virt", "vendor",
            "model", "packages_n", "updates_n", "security_n", "reboot", "updates_known", "last_hotfix", "guests_n", "running_n", "cluster")
    out |= {k: s.get(k) for k in keep if k in s} | {"disk_max": round(_disk_max(s), 1)}
    if full:
        out |= {"summary": s, "packages": json.loads(r["packages"] or "[]")}
    return out


@router.get("/api/inventory")
def inventory():
    cs = assets.collectors(include_deleted=True)
    rows = q("SELECT * EXCEPT packages FROM netview.host_inventory FINAL ORDER BY ip, kind")
    for r in rows:
        r["packages"] = "[]"
    out = [_row(r, cs) for r in rows]
    out.sort(key=lambda a: tuple(int(x) for x in a["ip"].split(".")) if "." in a["ip"] else (999, a["ip"]))
    logins = [c for c in creds.all_creds().values() if c["kind"] in KINDS]
    return {"hosts": out, "logins": len(logins)}


def guest_of(macs):
    """The Proxmox guest with one of these MACs: {host, node, vmid, name, type, status}."""
    macs = {m.upper() for m in macs if m}
    if not macs:
        return None
    for r in q("SELECT ip, summary FROM netview.host_inventory FINAL WHERE kind = 'proxmox' AND summary != '{}'"):
        for g in json.loads(r["summary"]).get("guests") or []:
            if macs & set(g.get("macs") or []):
                return {"host": r["ip"], "host_name": assets.NAMER[0](r["ip"]), "node": g["node"], "vmid": g["vmid"], "name": g["name"],
                        "type": g["type"], "status": g["status"], "cores": g["cores"], "mem_total": g["mem_total"], "disk_total": g["disk_total"]}
    return None


@router.get("/api/inventory/asset/{key}")
def for_asset(key: str):
    """What the machine said (one reading per way in), and the Proxmox guest it is."""
    a = q("SELECT ip, ips, mac FROM netview.assets FINAL WHERE key = {key:String}", key=key)
    ips = sorted(set(a[0]["ips"]) | {a[0]["ip"]}) if a else []
    if not ips and key.startswith("ip:"):
        ips = [key[3:]]
    cs = assets.collectors(include_deleted=True)
    rows = q("SELECT * FROM netview.host_inventory FINAL WHERE key = {key:String} OR has({ips:Array(String)}, ip) ORDER BY kind",
             key=key, ips=ips)
    return {"readings": [_row(r, cs, full=True) for r in rows], "guest": guest_of([a[0]["mac"]] if a else [])}


@router.post("/api/inventory/trust")
async def trust(request: Request):
    """Let go of a machine's pinned key (reinstalled): its collector forgets it at its next contact and reads it again."""
    _admin(request)
    b = await request.json()
    r = q("SELECT collector, cred FROM netview.host_inventory FINAL WHERE ip = {ip:String} AND kind = {k:String}",
          ip=str(b.get("ip", "")), k=str(b.get("kind", "")))
    if not r:
        raise HTTPException(404, "no reading of this machine")
    ip, kind = str(b["ip"]), str(b["kind"])
    port = (creds.all_creds().get(r[0]["cred"]) or {}).get("secret", {}).get("port") or PORTS[kind]
    FORGET.setdefault(r[0]["collector"], set()).add(f"{kind} [{ip}]:{port}" if ":" in ip else f"{kind} {ip}:{port}")
    return {"ok": True, "note": "Its collector lets the old key go within a minute, then reads the machine at its next sweep."}
