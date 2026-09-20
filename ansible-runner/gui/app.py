"""Small web GUI for running install_software.yml against Windows hosts.

Runs entirely inside the `gui` container (see docker-compose.yml) alongside
the same Ansible stack used by run.sh - nothing here executes on the host.
"""
import json
import os
import pathlib
import sqlite3
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from typing import Optional

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = pathlib.Path("/ansible")
INVENTORY_DIR = BASE / "inventory"
HOSTS_FILE = INVENTORY_DIR / "hosts.yml"
GROUP_VAULT = INVENTORY_DIR / "group_vars" / "windows" / "vault.yml"
HOST_VARS_DIR = INVENTORY_DIR / "host_vars"
PLAYBOOK = "playbooks/install_software.yml"
DATA_DIR = pathlib.Path("/ansible/gui-data")
DB_PATH = DATA_DIR / "history.db"
VAULT_PASS_FILE = pathlib.Path("/run/secrets/vault_pass")
STATIC_DIR = pathlib.Path(__file__).parent / "static"

TASK_KIND = {
    "Install / upgrade packages to latest": "loop",
    "Install WSL with the latest Ubuntu": "single",
    "Finish the WSL/Ubuntu install after reboot": "single",
    "Install Wazuh agent (needs manager address)": "single",
    "Join Tailscale tailnet with auth key": "single",
    "Configure Git global user.name": "single",
    "Configure Git global user.email": "single",
}

DATA_DIR.mkdir(parents=True, exist_ok=True)
run_lock = threading.Lock()

app = FastAPI()


def has_vault_pass() -> bool:
    return VAULT_PASS_FILE.exists()


def vault_password_args() -> list[str]:
    return ["--vault-password-file", str(VAULT_PASS_FILE)] if has_vault_pass() else []


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT, finished_at TEXT,
            hosts TEXT, params TEXT, status TEXT, error TEXT
        )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS run_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER, host TEXT, package TEXT, status TEXT
        )"""
    )
    conn.commit()
    conn.close()


init_db()


def list_hosts() -> list[dict]:
    data = yaml.safe_load(HOSTS_FILE.read_text()) or {}
    try:
        hosts = list(data["all"]["children"]["windows"]["hosts"].keys())
    except (KeyError, TypeError):
        hosts = []
    return [
        {"name": str(h), "has_credential_override": (HOST_VARS_DIR / str(h) / "vault.yml").exists()}
        for h in hosts
    ]


def list_packages() -> list[dict]:
    docs = yaml.safe_load((BASE / PLAYBOOK).read_text())
    return docs[0]["vars"]["choco_packages"]


def vault_file_for_target(target: str) -> pathlib.Path:
    return GROUP_VAULT if target == "group" else HOST_VARS_DIR / target / "vault.yml"


def redact(extra_vars: dict) -> dict:
    redacted = dict(extra_vars)
    for k in ("wazuh_registration_password", "tailscale_authkey"):
        if k in redacted:
            redacted[k] = "***"
    return redacted


def record_run(started, finished, hosts, extra_vars, status, error, stats, per_host) -> int:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "INSERT INTO runs (started_at, finished_at, hosts, params, status, error) VALUES (?,?,?,?,?,?)",
        (started, finished, json.dumps(hosts or ["<all>"]), json.dumps(redact(extra_vars)), status, error),
    )
    run_id = cur.lastrowid
    if per_host:
        for host, items in per_host.items():
            for it in items:
                conn.execute(
                    "INSERT INTO run_results (run_id, host, package, status) VALUES (?,?,?,?)",
                    (run_id, host, it["package"], it["status"]),
                )
    elif stats:
        for host, s in stats.items():
            st = "failed" if (s.get("failures", 0) > 0 or s.get("unreachable", 0) > 0) else "success"
            conn.execute(
                "INSERT INTO run_results (run_id, host, package, status) VALUES (?,?,?,?)",
                (run_id, host, "(overall)", st),
            )
    conn.commit()
    conn.close()
    return run_id


@app.get("/api/hosts")
def api_hosts():
    return list_hosts()


@app.get("/api/packages")
def api_packages():
    return list_packages()


@app.get("/api/credentials/status")
def api_credentials_status():
    return {
        "vault_pass_configured": has_vault_pass(),
        "group": {"file": str(GROUP_VAULT.relative_to(BASE)), "exists": GROUP_VAULT.exists()},
        "hosts": list_hosts(),
    }


class CredentialsIn(BaseModel):
    target: str  # "group" or a host name from inventory
    username: Optional[str] = None
    password: Optional[str] = None
    tailscale_authkey: Optional[str] = None


@app.post("/api/credentials")
def api_set_credentials(body: CredentialsIn):
    if not has_vault_pass():
        raise HTTPException(400, "No vault password file on the server. Run ./run.sh --vault-init on the host first.")

    path = vault_file_for_target(body.target)
    existing: dict = {}
    if path.exists():
        proc = subprocess.run(
            ["ansible-vault", "view", str(path)] + vault_password_args(),
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise HTTPException(500, f"Failed to decrypt existing vault file: {proc.stderr.strip()}")
        existing = yaml.safe_load(proc.stdout) or {}

    if body.username:
        existing["vault_win_user"] = body.username
    if body.password:
        existing["vault_win_password"] = body.password
    if body.tailscale_authkey:
        existing["vault_tailscale_authkey"] = body.tailscale_authkey

    if not existing:
        raise HTTPException(400, "Nothing to save - provide at least one field.")

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(suffix=".yml", dir=str(DATA_DIR))
    try:
        with os.fdopen(fd, "w") as tmp:
            yaml.safe_dump(existing, tmp)
        # --output writes fresh; overwrite the real file only if encryption succeeds.
        proc = subprocess.run(
            ["ansible-vault", "encrypt", tmp_path, "--output", str(path)] + vault_password_args(),
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise HTTPException(500, f"Failed to encrypt vault file: {proc.stderr.strip()}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return {"ok": True, "file": str(path.relative_to(BASE))}


class WazuhParams(BaseModel):
    manager: str
    port: Optional[str] = None
    protocol: Optional[str] = None
    group: Optional[str] = None
    agent_name: Optional[str] = None
    registration_password: Optional[str] = None


class GitParams(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None


class RunIn(BaseModel):
    hosts: list[str] = []  # empty = all hosts in the windows group
    wazuh: Optional[WazuhParams] = None
    tailscale_authkey: Optional[str] = None
    git: Optional[GitParams] = None
    wsl_allow_reboot: bool = False


def build_extra_vars(body: RunIn) -> dict:
    extra_vars: dict = {}
    if body.wazuh and body.wazuh.manager:
        extra_vars["wazuh_manager"] = body.wazuh.manager
        if body.wazuh.port:
            extra_vars["wazuh_manager_port"] = body.wazuh.port
        if body.wazuh.protocol:
            extra_vars["wazuh_protocol"] = body.wazuh.protocol
        if body.wazuh.group:
            extra_vars["wazuh_group"] = body.wazuh.group
        if body.wazuh.agent_name:
            extra_vars["wazuh_agent_name"] = body.wazuh.agent_name
        if body.wazuh.registration_password:
            extra_vars["wazuh_registration_password"] = body.wazuh.registration_password
    if body.tailscale_authkey:
        extra_vars["tailscale_authkey"] = body.tailscale_authkey
    if body.git:
        if body.git.name:
            extra_vars["git_user_name"] = body.git.name
        if body.git.email:
            extra_vars["git_user_email"] = body.git.email
    if body.wsl_allow_reboot:
        extra_vars["wsl_allow_reboot"] = "true"
    return extra_vars


def parse_run_output(stdout: str) -> tuple[dict, dict]:
    """Returns (stats, per_host_package_results)."""
    data = json.loads(stdout)
    stats = data.get("stats", {})
    per_host: dict[str, list] = {}

    for play in data.get("plays", []):
        for task in play.get("tasks", []):
            tname = task.get("task", {}).get("name")
            kind = TASK_KIND.get(tname)
            if not kind:
                continue
            for host, hostres in task.get("hosts", {}).items():
                bucket = per_host.setdefault(host, [])
                if kind == "loop":
                    for r in hostres.get("results", []):
                        if r.get("skipped"):
                            continue
                        item = r.get("item", {})
                        label = item.get("label") or item.get("name") or "?"
                        if r.get("failed"):
                            status = "failed"
                        elif r.get("changed"):
                            status = "installed/upgraded"
                        else:
                            status = "already up to date"
                        bucket.append({"package": label, "status": status})
                else:
                    if hostres.get("skipped"):
                        continue
                    status = "failed" if hostres.get("failed") else ("done" if hostres.get("changed") else "no change")
                    bucket.append({"package": tname, "status": status})

    for host, s in stats.items():
        bucket = per_host.setdefault(host, [])
        if not bucket and (s.get("unreachable") or s.get("failures")):
            bucket.append({
                "package": "(connection)",
                "status": "unreachable" if s.get("unreachable") else "failed",
            })

    return stats, per_host


@app.post("/api/run")
def api_run(body: RunIn):
    if not has_vault_pass():
        raise HTTPException(400, "No vault password file on the server - cannot authenticate to hosts.")
    if not run_lock.acquire(blocking=False):
        raise HTTPException(409, "A run is already in progress. Wait for it to finish.")

    try:
        extra_vars = build_extra_vars(body)
        cmd = ["ansible-playbook", PLAYBOOK]
        if body.hosts:
            cmd += ["--limit", ",".join(body.hosts)]
        for k, v in extra_vars.items():
            cmd += ["-e", f"{k}={v}"]
        cmd += vault_password_args()

        env = os.environ.copy()
        env["ANSIBLE_STDOUT_CALLBACK"] = "json"
        env.setdefault("HOME", "/tmp")
        env.setdefault("ANSIBLE_LOCAL_TEMP", "/tmp/.ansible/tmp")

        started = datetime.now(timezone.utc).isoformat()
        try:
            proc = subprocess.run(cmd, cwd=str(BASE), env=env, capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            finished = datetime.now(timezone.utc).isoformat()
            record_run(started, finished, body.hosts, extra_vars, "timeout", "Run exceeded 30 minute timeout", {}, {})
            raise HTTPException(504, "Ansible run timed out after 30 minutes.")

        finished = datetime.now(timezone.utc).isoformat()

        try:
            stats, per_host = parse_run_output(proc.stdout)
            overall_status = "failed" if any(
                s.get("failures", 0) > 0 or s.get("unreachable", 0) > 0 for s in stats.values()
            ) else "success"
            error = None
        except (json.JSONDecodeError, KeyError, TypeError):
            stats, per_host = {}, {}
            overall_status = "error"
            error = (proc.stderr or proc.stdout or "")[-4000:]

        run_id = record_run(started, finished, body.hosts, extra_vars, overall_status, error, stats, per_host)

        return {
            "run_id": run_id,
            "status": overall_status,
            "stats": stats,
            "hosts": per_host,
            "error": error,
        }
    finally:
        run_lock.release()


@app.get("/api/history")
def api_history(limit: int = 20):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    runs = conn.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in runs:
        results = conn.execute(
            "SELECT host, package, status FROM run_results WHERE run_id = ?", (r["id"],)
        ).fetchall()
        by_host: dict[str, list] = {}
        for row in results:
            by_host.setdefault(row["host"], []).append({"package": row["package"], "status": row["status"]})
        out.append({
            "id": r["id"],
            "started_at": r["started_at"],
            "finished_at": r["finished_at"],
            "hosts": json.loads(r["hosts"]),
            "params": json.loads(r["params"]),
            "status": r["status"],
            "error": r["error"],
            "results": by_host,
        })
    conn.close()
    return out


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))
