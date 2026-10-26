"""Sentry Lens <-> Uptime Kuma: the Applications section.

Kuma (2.x) has no REST API for its monitors - its own UI talks Socket.IO -
so this keeps one Socket.IO session open with the account from the vault
(KUMA_URL / KUMA_USER / KUMA_PASS, netview_stack.yml), and Kuma pushes
everything to it: the monitor list, every heartbeat, average response times,
uptime, certificates. The views read that state; the actions (pause, resume,
add, edit, delete) are Kuma's own calls, for admins.

Monitors hold secrets (basic-auth passwords, tokens, keys, connection
strings): only PUBLIC fields ever leave this module, and an edit merges the
EDITABLE fields into the full monitor fetched from Kuma - the secrets stay
where they are.
"""
import json
import os
import threading
import time
from collections import deque

import socketio
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

import auth

URL = os.environ.get("KUMA_URL", "").rstrip("/")
USER = os.environ.get("KUMA_USER", "")
PASSWORD = os.environ.get("KUMA_PASS", "")
STATIC = os.path.join(os.path.dirname(__file__), "static")
BEATS = 100  # recent heartbeats kept per monitor (the bars)
STATUS = {0: "down", 1: "up", 2: "pending", 3: "maintenance"}

# What the browser sees of a monitor, and what Sentry Lens may change.
PUBLIC = ("id", "name", "type", "url", "hostname", "port", "method", "interval", "retryInterval",
          "resendInterval", "maxretries", "timeout", "active", "parent", "path", "pathName", "description",
          "keyword", "invertKeyword", "ignoreTls", "upsideDown", "expiryNotification", "maxredirects",
          "accepted_statuscodes", "dns_resolve_type", "dns_resolve_server", "docker_container", "packetSize",
          "maintenance", "weight", "childrenIDs", "forceInactive")
EDITABLE = {"name": str, "type": str, "url": str, "hostname": str, "port": int, "method": str, "interval": int,
            "retryInterval": int, "resendInterval": int, "maxretries": int, "timeout": float, "parent": int,
            "description": str, "keyword": str, "invertKeyword": bool, "ignoreTls": bool, "upsideDown": bool,
            "expiryNotification": bool, "maxredirects": int, "accepted_statuscodes": list,
            "dns_resolve_type": str, "dns_resolve_server": str, "notificationIDList": dict}
TYPES = ["http", "keyword", "json-query", "port", "ping", "dns", "group", "push", "docker"]
# A new monitor: Kuma's own form defaults (EditMonitor.vue) for what isn't given.
NEW = {"type": "http", "name": "", "url": "https://", "method": "GET", "interval": 60, "retryInterval": 60,
       "resendInterval": 0, "maxretries": 0, "timeout": 48, "notificationIDList": {}, "ignoreTls": False,
       "upsideDown": False, "packetSize": 56, "expiryNotification": False, "maxredirects": 10,
       "accepted_statuscodes": ["200-299"], "dns_resolve_type": "A", "dns_resolve_server": "1.1.1.1",
       "docker_container": "", "docker_host": None, "proxyId": None, "mqttUsername": "", "mqttPassword": "",
       "mqttTopic": "", "mqttSuccessMessage": "", "mqttCheckType": "keyword", "authMethod": None,
       "oauth_auth_method": "client_secret_basic", "httpBodyEncoding": "json", "kafkaProducerBrokers": [],
       "kafkaProducerSaslOptions": {"mechanism": "None"}, "kafkaProducerSsl": False,
       "kafkaProducerAllowAutoTopicCreation": False, "gamedigGivenPortOnly": True, "remote_browser": None,
       "rabbitmqNodes": [], "rabbitmqUsername": "", "rabbitmqPassword": "", "conditions": [],
       "parent": None, "description": "", "keyword": "", "invertKeyword": False, "hostname": "", "port": None,
       "active": True}

status = {"enabled": bool(URL and USER and PASSWORD), "connected": False, "logged_in": False, "version": "",
          "last_error": "", "since": 0}
_lock = threading.Lock()
S = {"monitors": {}, "beats": {}, "ping": {}, "uptime": {}, "cert": {}, "maintenance": {},
     "notifications": {}, "tags": []}
_sio = socketio.Client(reconnection=True, reconnection_delay=5, reconnection_delay_max=60, logger=False)


# ------------------------------------------------------------------ Kuma's pushes
def _on(event):
    def reg(fn):
        _sio.on(event, fn)
        return fn
    return reg


@_on("connect")
def _connect():
    status.update(connected=True, last_error="")
    try:
        res = _sio.call("login", {"username": USER, "password": PASSWORD, "token": ""}, timeout=30)
    except Exception as e:  # noqa: BLE001 - socketio raises its own
        status["last_error"] = f"login: {e}"
        return
    if res.get("ok"):
        status.update(logged_in=True, since=int(time.time()))
    else:
        status.update(logged_in=False, last_error=f"login refused: {res.get('msg', '')}")


@_on("disconnect")
def _disconnect():
    status.update(connected=False, logged_in=False)


@_on("info")
def _info(data):
    if data.get("version"):
        status["version"] = data["version"]


@_on("monitorList")
def _monitor_list(data):
    with _lock:
        S["monitors"] = {int(k): v for k, v in data.items()}


@_on("updateMonitorIntoList")
def _monitor_update(data):
    with _lock:
        for k, v in data.items():
            S["monitors"][int(k)] = v


@_on("deleteMonitorFromList")
def _monitor_delete(mid):
    with _lock:
        S["monitors"].pop(int(mid), None)


@_on("heartbeatList")
def _beats(mid, beats, overwrite=False):
    with _lock:
        q = S["beats"].setdefault(int(mid), deque(maxlen=BEATS))
        if overwrite:
            q.clear()
        q.extend(beats[-BEATS:])


@_on("heartbeat")
def _beat(beat):
    with _lock:
        S["beats"].setdefault(int(beat["monitorID"]), deque(maxlen=BEATS)).append(
            beat | {"monitor_id": beat["monitorID"]})
        if beat.get("important"):
            _incidents["t"] = 0  # a status change: the dashboard's list is stale


@_on("avgPing")
def _avg_ping(mid, value):
    S["ping"][int(mid)] = value


@_on("uptime")
def _uptime(mid, period, value):
    S["uptime"][(int(mid), str(period))] = value  # periods: 24, 720 (hours), "1y"


# Incidents (status changes): Kuma 2 sends them only when asked - the latest
# across all monitors for the dashboard (kept a minute), one monitor's on its page.
_incidents = {"t": 0, "list": []}


def incidents(mid=None, count=30):
    if mid is None and time.time() - _incidents["t"] < 60:
        return _incidents["list"]
    rows = [b | {"monitor_id": b.get("monitor_id", b.get("monitorID"))}  # the rows come in camelCase
            for b in call("monitorImportantHeartbeatListPaged", mid, 0, count).get("data") or []]
    if mid is None:
        _incidents.update(t=time.time(), list=rows)
    return rows


@_on("certInfo")
def _cert(mid, info):
    try:
        S["cert"][int(mid)] = json.loads(info) if isinstance(info, str) else info
    except ValueError:
        pass


@_on("maintenanceList")
def _maintenance(data):
    S["maintenance"] = data


@_on("notificationList")
def _notifications(data):
    S["notifications"] = {n["id"]: {"id": n["id"], "name": n.get("name", ""), "isDefault": bool(n.get("isDefault"))}
                          for n in data}


def loop():
    """Connect, and keep at it - the client reconnects by itself once connected."""
    while True:
        if not _sio.connected:
            try:
                _sio.connect(URL, transports=["websocket"], wait_timeout=30)
            except Exception as e:  # noqa: BLE001
                status["last_error"] = f"connect: {e}"[:300]
        time.sleep(30)


def start():
    if status["enabled"]:
        threading.Thread(target=loop, daemon=True, name="kuma").start()


def call(event, *args, timeout=30):
    """One of Kuma's own calls; its {ok, msg} answer, or a 502."""
    if not status["logged_in"]:
        raise HTTPException(503, "not connected to Uptime Kuma" + (f": {status['last_error']}" if status["last_error"] else ""))
    try:
        res = _sio.call(event, args if len(args) != 1 else args[0], timeout=timeout) if args else _sio.call(event, timeout=timeout)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Uptime Kuma: {e}")
    if isinstance(res, dict) and not res.get("ok", True):
        raise HTTPException(400, f"Uptime Kuma: {res.get('msg', 'refused')}")
    return res


# ------------------------------------------------------------------ views
def _target(m):
    t = m.get("type")
    if t in ("http", "keyword", "json-query", "real-browser"):
        return m.get("url") or ""
    if t == "port":
        return f"{m.get('hostname')}:{m.get('port')}"
    if t == "docker":
        return m.get("docker_container") or ""
    if t == "group":
        return ""
    return m.get("hostname") or m.get("url") or ""


def _cert_days(mid):
    c = S["cert"].get(mid) or {}
    info = c.get("certInfo") or {}
    days = info.get("daysRemaining")
    return {"valid": bool(c.get("valid")), "days": days, "issuer": (info.get("issuer") or {}).get("O", ""),
            "subject": (info.get("subject") or {}).get("CN", "")} if c else None


def public(m):
    """A monitor as the browser may see it: no secrets, plus its live state."""
    mid = m["id"]
    beats = list(S["beats"].get(mid, ()))
    last = beats[-1] if beats else None
    state = "paused" if not m.get("active") else ("maintenance" if m.get("maintenance") else
                                                  STATUS.get(last["status"], "pending") if last else "pending")
    return {k: m.get(k) for k in PUBLIC} | {
        "tags": [{"name": t.get("name"), "value": t.get("value"), "color": t.get("color")} for t in m.get("tags") or []],
        "notifications": sorted(int(k) for k, v in (m.get("notificationIDList") or {}).items() if v),
        "target": _target(m), "state": state, "msg": last.get("msg", "") if last else "",
        "ping": last.get("ping") if last else None, "last": last.get("time") if last else None,
        "avg_ping": S["ping"].get(mid), "uptime_24h": S["uptime"].get((mid, "24")),
        "uptime_30d": S["uptime"].get((mid, "720")), "cert": _cert_days(mid),
        "beats": [{"s": b["status"], "t": b.get("time"), "p": b.get("ping"), "m": (b.get("msg") or "")[:160]}
                  for b in beats[-50:]]}


router = APIRouter()


def _admin(request):
    if auth.ENABLED:
        auth.require_admin(request)


def _need():
    if not status["enabled"]:
        raise HTTPException(404, "Uptime Kuma isn't set up (netview_kuma in netview_stack.yml)")


@router.get("/apps")
def apps_page():
    return FileResponse(os.path.join(STATIC, "apps.html"))


@router.get("/api/apps")
def apps():
    """Every monitor with its state, and the totals for the dashboard."""
    _need()
    with _lock:
        mons = [public(m) for m in S["monitors"].values()]
    real = [m for m in mons if m["type"] != "group"]
    counts = {s: sum(1 for m in real if m["state"] == s) for s in ("up", "down", "pending", "maintenance", "paused")}
    up24 = [m["uptime_24h"] for m in real if m["uptime_24h"] is not None and m["state"] != "paused"]
    pings = [m["avg_ping"] for m in real if m["avg_ping"]]
    certs = sorted((m for m in real if m["cert"] and m["cert"]["days"] is not None), key=lambda m: m["cert"]["days"])
    names = {m["id"]: m["name"] for m in mons}
    try:
        events = incidents()
    except HTTPException:
        events = []  # the totals and monitors still show
    return {"status": status, "counts": counts, "total": len(real),
            "uptime_24h": sum(up24) / len(up24) if up24 else None, "avg_ping": sum(pings) / len(pings) if pings else None,
            "certs": [{"id": m["id"], "name": m["name"], **m["cert"]} for m in certs[:8]],
            "events": [{"monitor_id": b["monitor_id"], "name": names.get(b["monitor_id"], ""), "status": STATUS.get(b["status"], ""),
                        "time": b.get("time"), "msg": (b.get("msg") or "")[:200]} for b in events],
            "monitors": sorted(mons, key=lambda m: (m.get("pathName") or m["name"]).lower()),
            "notifications": list(S["notifications"].values()), "types": TYPES}


@router.get("/api/apps/{mid}")
def app(mid: int, hours: int = 24):
    """One monitor: its state, its heartbeats over `hours` (the chart) and its incidents."""
    _need()
    if mid not in S["monitors"]:
        raise HTTPException(404, "no such monitor")
    hours = max(1, min(hours, 24 * 30))
    beats = call("getMonitorBeats", mid, hours, timeout=60).get("data", [])
    with _lock:
        m = public(S["monitors"][mid])
    # A long window: every Nth check, so the browser gets a few hundred - and
    # every check that wasn't up, so no outage falls between them.
    step = max(1, len(beats) // 600)
    pts = [{"t": b["time"], "p": b.get("ping"), "s": b["status"]} for i, b in enumerate(beats)
           if i % step == 0 or b["status"] != 1]
    downs = [b for b in beats if b["status"] == 0]
    return m | {"hours": hours, "series": pts, "checks": len(beats), "down_checks": len(downs),
                "uptime_window": (1 - len(downs) / len(beats)) if beats else None,
                "incidents": [{"status": STATUS.get(b["status"], ""), "time": b.get("time"), "msg": (b.get("msg") or "")[:300],
                               "duration": b.get("duration")} for b in incidents(mid, 50)]}


@router.post("/api/apps/{mid}/{action}")
async def app_action(request: Request, mid: int, action: str):
    """pause / resume / delete a monitor, or edit it (the EDITABLE fields)."""
    _need()
    _admin(request)
    if mid not in S["monitors"]:
        raise HTTPException(404, "no such monitor")
    if action == "pause":
        call("pauseMonitor", mid)
    elif action == "resume":
        call("resumeMonitor", mid)
    elif action == "delete":
        call("deleteMonitor", mid, False)
    elif action == "edit":
        full = call("getMonitor", mid).get("monitor")
        if not full:
            raise HTTPException(502, "Uptime Kuma sent no monitor")
        full |= _fields(await request.json())
        call("editMonitor", full, timeout=60)
    else:
        raise HTTPException(404, "actions: pause, resume, delete, edit")
    return {"ok": True}


@router.post("/api/apps")
async def app_add(request: Request):
    """A new monitor: Kuma's defaults with the EDITABLE fields given."""
    _need()
    _admin(request)
    body = _fields(await request.json())
    if not body.get("name"):
        raise HTTPException(400, "a name")
    res = call("add", NEW | body, timeout=60)
    return {"ok": True, "id": res.get("monitorID")}


def _fields(body):
    out = {}
    for k, v in body.items():
        if k not in EDITABLE:
            raise HTTPException(400, f"{k} can't be set from here - use Uptime Kuma")
        kind = EDITABLE[k]
        if v is None or v == "":
            out[k] = None if k in ("parent", "port") else ("" if kind is str else v)
            continue
        try:
            out[k] = kind(v) if kind not in (list, dict) else v
        except (TypeError, ValueError):
            raise HTTPException(400, f"bad {k}")
        if kind is list and not all(isinstance(x, str) for x in v):
            raise HTTPException(400, f"{k}: a list of text")
        if kind is dict:
            out[k] = {str(int(n)): bool(on) for n, on in v.items()}
    if "type" in out and out["type"] not in TYPES:
        raise HTTPException(400, f"type is one of {TYPES}")
    for k in ("interval", "retryInterval"):
        if k in out and out[k] is not None and out[k] < 20:
            raise HTTPException(400, f"{k}: 20 seconds or more")
    return out
