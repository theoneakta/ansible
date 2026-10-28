"""Sentry Lens: Docker actions - update a container to its image's latest
(recreated as it is, only the image new), delete unused images and volumes -
carried out on each Docker host by
docker-agent (files/docker_agent.py, cadvisor.yml), which asks here for its
host's jobs: no port opened on the hosts, no login to them kept here.

An admin queues a job on the Infrastructure > Docker page; the agent picks it
up within seconds (one at a time), tells every minute that it's still on it,
and posts its result. A job it went quiet on for STALL seconds (the agent or
its host stopped) is handed out again, up to TRIES times - an update and the
deletes come out the same run twice. What a job may touch is checked here
against what docker-meta reports (a container on that host; images and volumes
no container uses), and again on the host when it runs. Destructive jobs need
the confirmation word the page asked the admin to type.

  netview.docker_jobs     every job (newest version wins): who, what, when, its log
  netview.docker_agents   each host's agent: version, last contact, its last
                          update check {image: {status, local, remote, error}}

A host's agent key: derived from SESSION_SECRET and the host name (Prometheus's
host label) - cadvisor.yml derives the same from this host's session.env.
"""
import hashlib
import hmac
import json
import re
import secrets
import time

from fastapi import APIRouter, HTTPException, Request

import auth
import checks
import infra
from assets import _ts  # ClickHouse DateTime -> epoch seconds

router = APIRouter()
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}")
KINDS = ("update", "restart", "delete_images", "delete_volumes", "check_updates")
CONFIRM = "delete"  # what the page asks to type before a delete
QUEUED_FOR = 3600  # a job no agent picked up within this: expired
STALL = 300  # a job picked up, then no word from the agent for this long: handed out again
TRIES = 3  # ... this many times in all - then failed
SEEN_EVERY = 60  # an agent's contact is written at most this often
ONLINE = 120

DDL = [
    """CREATE TABLE IF NOT EXISTS netview.docker_jobs (
        id String, host String, kind LowCardinality(String), args String, state LowCardinality(String),
        by String, created DateTime, started DateTime, finished DateTime, log String, ver UInt64
    ) ENGINE = ReplacingMergeTree(ver) ORDER BY id TTL created + INTERVAL 90 DAY""",
    """CREATE TABLE IF NOT EXISTS netview.docker_agents (
        host String, version String, last_seen DateTime, checked DateTime, updates String, ver UInt64
    ) ENGINE = ReplacingMergeTree(ver) ORDER BY host""",
    # The agent's last word on a running job, and how many times it was handed out.
    "ALTER TABLE netview.docker_jobs ADD COLUMN IF NOT EXISTS beat DateTime DEFAULT 0",
    # A job to try again later (a registry turned a pull away): not handed out before this.
    "ALTER TABLE netview.docker_jobs ADD COLUMN IF NOT EXISTS after DateTime DEFAULT 0",
    "ALTER TABLE netview.docker_jobs ADD COLUMN IF NOT EXISTS tries UInt8 DEFAULT 0",
]
_ready = [False]
_seen = {}  # host -> when its contact was last written


def q(sql, **params):
    if not _ready[0]:
        for d in DDL:
            checks.ch(d)
        _ready[0] = True
    return checks.query(sql, **params)


def insert(table, rows):
    q("SELECT 1")
    checks.ch(f"INSERT INTO netview.{table} FORMAT JSONEachRow", "\n".join(json.dumps(r) for r in rows))


def agent_key(host):
    return "dka_" + hashlib.sha256(f"sentry-lens-docker-agent:{auth.SESSION_SECRET}:{host}".encode()).hexdigest()


def agents():
    return {r["host"]: r for r in q("SELECT * FROM netview.docker_agents FINAL")}


def save_agent(a):
    insert("docker_agents", [a | {"last_seen": int(_ts(a["last_seen"])), "checked": int(_ts(a["checked"])), "ver": time.time_ns()}])


def jobs(host="", limit=40):
    rows = q("SELECT * FROM netview.docker_jobs FINAL" + (" WHERE host = {h:String}" if host else "")
             + " ORDER BY created DESC LIMIT {n:UInt32}", h=host, n=limit)
    now = time.time()
    for j in rows:
        for k in ("created", "started", "finished", "beat", "after"):
            j[k] = _ts(j.get(k) or 0)
        j["args"] = json.loads(j["args"] or "{}")
        j["tries"] = int(j.get("tries") or 0)
        if j["state"] == "queued" and now - j["created"] > QUEUED_FOR:
            j["state"] = "expired"
        elif j["state"] == "running" and now - max(j["started"], j["beat"]) > STALL:
            # The agent went quiet on it (stopped, or its host): again, or failed after TRIES.
            again = j["tries"] < TRIES
            note = (f"No word from the agent for {STALL // 60} minutes (try {j['tries']} of {TRIES})"
                    + (" - handed out again." if again else " - given up."))
            j |= {"state": "queued" if again else "failed", "finished": 0 if again else now,
                  "log": (j["log"] + "\n" if j["log"] else "") + note}
            if again:
                j["created"] = max(j["created"], now - QUEUED_FOR + 600)  # keeps it from expiring right away
            save_job(j)
    return rows


def save_job(j):
    insert("docker_jobs", [j | {"args": json.dumps(j["args"]) if not isinstance(j["args"], str) else j["args"],
                                **{k: int(j.get(k) or 0) for k in ("created", "started", "finished", "beat", "after")},
                                "tries": int(j.get("tries") or 0), "ver": time.time_ns()}])


# ------------------------------------------------------------------ the agent's side
def _agent(request):
    host = request.headers.get("x-host", "")
    h = request.headers.get("authorization", "")
    key = h[7:] if h.lower().startswith("bearer ") else ""
    if not HOST.fullmatch(host) or not hmac.compare_digest(key, agent_key(host)):
        raise HTTPException(401, "unknown host or key")
    return host


def _contact(host, version, **more):
    now = time.time()
    if not more and now - _seen.get(host, 0) < SEEN_EVERY:
        return
    a = agents().get(host) or {"host": host, "checked": 0, "updates": "{}"}
    save_agent(a | {"version": version[:20], "last_seen": int(now)} | more)
    _seen[host] = now


@router.get("/api/docker-agent/jobs")
def agent_jobs(request: Request, version: str = ""):
    """The host's oldest queued job - one at a time (the agent runs them one by
    one: a second handed out with it would go quiet while it waits)."""
    host = _agent(request)
    _contact(host, version)
    rows = jobs(host, 20)
    if any(j["state"] == "running" for j in rows):
        return {"jobs": []}  # one in hand already (handed out again if it goes quiet)
    now = time.time()
    for j in reversed(rows):
        if j["state"] == "queued" and j["after"] <= now:
            save_job(j | {"state": "running", "started": now, "beat": now, "tries": j["tries"] + 1})
            return {"jobs": [{"id": j["id"], "kind": j["kind"], "args": j["args"]}]}
    return {"jobs": []}


@router.post("/api/docker-agent/jobs/{jid}")
async def agent_result(request: Request, jid: str):
    """{running: true} - still on it; or {ok, log, retry} - its result (taken even
    after it was handed out again or given up: what really happened wins).
    retry: turned away for now (a registry's rate limit) - again in STALL s, up to TRIES."""
    host = _agent(request)
    b = await request.json()
    j = next((j for j in jobs(host, 100) if j["id"] == jid), None)
    if not j:
        raise HTTPException(404, "no such job")
    if b.get("running"):
        if j["state"] == "running":
            save_job(j | {"beat": time.time()})
        return {"ok": True}
    log = str(b.get("log", ""))
    if j["log"]:  # what Sentry Lens noted on the way (handed out again)
        log = j["log"] + "\n" + log
    now = time.time()
    if not b.get("ok") and b.get("retry") and j["tries"] < TRIES:
        log += f"\n-- try {j['tries']} of {TRIES} turned away: again in {STALL // 60} minutes --"
        save_job(j | {"state": "queued", "after": now + STALL, "created": max(j["created"], now - QUEUED_FOR + STALL + 600),
                      "log": log[-16000:]})
        return {"ok": True}
    save_job(j | {"state": "done" if b.get("ok") else "failed", "finished": now, "log": log[-16000:]})
    return {"ok": True}


@router.post("/api/docker-agent/updates")
async def agent_updates(request: Request):
    """{images: {image: {status, local, remote, error}}, version} - the host's update check."""
    host = _agent(request)
    b = await request.json()
    imgs = b.get("images") or {}
    if not isinstance(imgs, dict) or len(imgs) > 1000:
        raise HTTPException(400, "images: {image: {...}}")
    clean = {str(k)[:300]: {f: str((v or {}).get(f, ""))[:200] for f in ("status", "local", "remote", "error")} for k, v in imgs.items()}
    _contact(host, str(b.get("version", "")), checked=int(time.time()), updates=json.dumps(clean))
    return {"ok": True}


# ------------------------------------------------------------------ the page's side
def _admin(request):
    if auth.ENABLED:
        auth.require_admin(request)
    u = getattr(request.state, "user", None)
    return u["email"] if u else "local"


@router.get("/api/infra/docker-actions")
def overview():
    """Each host's agent (online, version), its last update check, and the recent jobs."""
    now = time.time()
    out = {}
    for h, a in agents().items():
        seen, checked = _ts(a["last_seen"]), _ts(a["checked"])
        out[h] = {"version": a["version"], "last_seen": seen, "online": now - seen < ONLINE, "checked": checked,
                  "updates": json.loads(a["updates"] or "{}")}
    return {"agents": out, "jobs": jobs(), "confirm": CONFIRM}


@router.post("/api/infra/docker-actions")
async def queue(request: Request):
    """{host, kind, container | images | volumes, confirm} - checked against what
    docker-meta reports, then queued for the host's agent."""
    by = _admin(request)
    b = await request.json()
    host, kind = str(b.get("host", "")), b.get("kind")
    if kind not in KINDS:
        raise HTTPException(400, f"kind: one of {list(KINDS)}")
    if host not in infra.targets():
        raise HTTPException(404, "no such host")
    if host not in agents():
        raise HTTPException(409, f"{host} has no docker-agent yet - run cadvisor.yml for it")
    args = {}
    if kind in ("update", "restart"):
        name = str(b.get("container", ""))
        info = infra.docker_state(host)[0].get((host, name))
        if not info:
            raise HTTPException(404, "no such container on that host")
        args = {"container": name}
    elif kind == "delete_images":
        want = [str(x) for x in b.get("images") or []]
        if not 1 <= len(want) <= 200:
            raise HTTPException(400, "1 to 200 images")
        imgs = [i for i in infra.images()["images"] if i["host"] == host]
        unused = {i["image"] for i in imgs if not i["in_use"] and i["image"] != "<none>"} | {i["id"] for i in imgs if not i["in_use"]}
        bad = [x for x in want if x not in unused]
        if bad:
            raise HTTPException(400, f"not an unused image on {host}: {bad[0]}")
        args = {"images": want}
    elif kind == "delete_volumes":
        want = [str(x) for x in b.get("volumes") or []]
        if not 1 <= len(want) <= 200:
            raise HTTPException(400, "1 to 200 volumes")
        unused = {v["volume"] for v in infra.volumes(24)["volumes"] if v["host"] == host and not v["containers"]}
        bad = [x for x in want if x not in unused]
        if bad:
            raise HTTPException(400, f"not an unused volume on {host}: {bad[0]}")
        args = {"volumes": want}
    if kind.startswith("delete_") and b.get("confirm") != CONFIRM:
        raise HTTPException(400, f'type "{CONFIRM}" to confirm')
    for j in jobs(host, 50):
        if j["kind"] == kind and j["args"] == args and j["state"] in ("queued", "running"):
            raise HTTPException(409, "the same job is already waiting or running")
    jid = secrets.token_hex(6)
    save_job({"id": jid, "host": host, "kind": kind, "args": args, "state": "queued", "by": by,
              "created": time.time(), "started": 0, "finished": 0, "log": ""})
    return {"id": jid}
