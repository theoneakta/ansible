"""Small web GUI for running install_software.yml against Windows hosts.

Runs entirely inside the `gui` container (see docker-compose.yml) alongside
the same Ansible stack used by run.sh - nothing here executes on the host.
"""
import json
import os
import pathlib
import re
import socket
import sqlite3
import subprocess
import tempfile
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
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
CALLBACK_PLUGINS_DIR = pathlib.Path(__file__).parent / "callback_plugins"

TASK_KIND = {
    "Install / upgrade packages to latest": "loop",
    "Install selected WSL distros": "loop",
    "Finish any WSL distro installs after reboot": "loop",
    "Create per-user logon tasks to install WSL distro(s) for requested users": "loop",
    "Install Wazuh agent (needs manager address)": "single",
    "Join Tailscale tailnet with auth key": "single",
    "Configure Git global user.name": "single",
    "Configure Git global user.email": "single",
    "Run Win11Debloat (basic defaults, silent)": "single",
    "Install all RSAT (Remote Server Administration Tools) capabilities": "single",
}

DATA_DIR.mkdir(parents=True, exist_ok=True)
run_lock = threading.Lock()

app = FastAPI()


def has_vault_pass() -> bool:
    return VAULT_PASS_FILE.exists()


def vault_password_args() -> list[str]:
    return ["--vault-password-file", str(VAULT_PASS_FILE)] if has_vault_pass() else []


def db_connect() -> sqlite3.Connection:
    # WAL lets the frequent live-log polling reads proceed while a run's
    # background thread is writing results; busy_timeout retries instead of
    # raising "database is locked" on the rare overlap.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def init_db():
    conn = db_connect()
    conn.execute("PRAGMA journal_mode = WAL")
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


HOST_NAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$")


def add_host_to_inventory(name: str) -> None:
    if not HOST_NAME_RE.match(name):
        raise HTTPException(400, "Invalid host name/IP - use letters, numbers, dots, and hyphens only.")
    if name in {h["name"] for h in list_hosts()}:
        raise HTTPException(400, f"Host '{name}' is already in the inventory.")

    text = HOSTS_FILE.read_text()
    match = re.search(r"^([ \t]*)hosts:[ \t]*\r?\n", text, flags=re.MULTILINE)
    if not match:
        raise HTTPException(500, "Could not find a 'hosts:' section in inventory/hosts.yml.")

    entry_indent = match.group(1) + "  "
    insert_at = match.end()
    new_text = text[:insert_at] + f"{entry_indent}{name}:\n" + text[insert_at:]
    HOSTS_FILE.write_text(new_text)


def get_winrm_port() -> int:
    vars_path = INVENTORY_DIR / "group_vars" / "windows" / "vars.yml"
    try:
        data = yaml.safe_load(vars_path.read_text()) or {}
        return int(data.get("ansible_port", 5986))
    except (OSError, ValueError, TypeError):
        return 5986


def check_ping(host: str) -> dict:
    try:
        proc = subprocess.run(
            ["ping", "-c", "1", "-W", "2", host], capture_output=True, text=True, timeout=5,
        )
        if proc.returncode == 0:
            return {"ok": True, "detail": "Host replied to ICMP ping."}
        return {"ok": False, "detail": "No ICMP reply (often blocked by Windows Firewall by default - not necessarily a problem on its own)."}
    except FileNotFoundError:
        return {"ok": None, "detail": "ping is not available in this container."}
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": "Ping timed out."}


def check_tcp_port(host: str, port: int, timeout: float = 3.0) -> dict:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "detail": f"Connected to port {port}."}
    except socket.timeout:
        return {"ok": False, "detail": f"Timed out connecting to port {port}."}
    except ConnectionRefusedError:
        return {"ok": False, "detail": f"Port {port} is closed (connection refused)."}
    except OSError as e:
        return {"ok": False, "detail": f"Could not reach port {port}: {e}"}


def check_winrm(host: str) -> dict:
    if not has_vault_pass():
        return {"ok": False, "detail": "No vault password file on the server - cannot authenticate."}
    cmd = ["ansible", host, "-m", "ansible.windows.win_ping"] + vault_password_args()
    env = os.environ.copy()
    env.setdefault("HOME", "/tmp")
    env.setdefault("ANSIBLE_LOCAL_TEMP", "/tmp/.ansible/tmp")
    try:
        proc = subprocess.run(cmd, cwd=str(BASE), env=env, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        return {"ok": False, "detail": "WinRM check timed out after 30 seconds."}
    output = ((proc.stdout or "") + (proc.stderr or "")).strip()
    return {"ok": proc.returncode == 0, "detail": output[-1500:] or "(no output)"}


def test_host(host: str) -> dict:
    port = get_winrm_port()
    ping = check_ping(host)
    tcp = check_tcp_port(host, port)
    winrm = check_winrm(host)

    if winrm["ok"]:
        summary = "Connected successfully - credentials and WinRM are working."
    elif not tcp["ok"]:
        if ping["ok"] is False:
            summary = (
                f"Host looks unreachable on the network (no ping reply, port {port} closed). "
                "Check the IP/VLAN and that the PC is powered on and networked."
            )
        else:
            summary = (
                f"Network reachable but WinRM port {port} is closed. "
                "Check WinRM is enabled (`winrm quickconfig`) and the firewall allows that port."
            )
    else:
        summary = "WinRM port is open but the connection failed - likely a credentials or WinRM configuration issue. See details below."

    return {
        "host": host,
        "ping": ping,
        "port": {**tcp, "port": port},
        "winrm": winrm,
        "summary": summary,
    }


def list_packages() -> list[dict]:
    docs = yaml.safe_load((BASE / PLAYBOOK).read_text())
    return docs[0]["vars"]["choco_packages"]


PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.\-]*[A-Za-z0-9])?$")

CHOCO_NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "d": "http://schemas.microsoft.com/ado/2007/08/dataservices",
    "m": "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata",
}


def search_chocolatey(term: str, limit: int = 20) -> list[dict]:
    query = {
        "$filter": "IsLatestVersion",
        "$skip": "0",
        "$top": str(limit),
        "searchTerm": "'" + term.replace("'", "''") + "'",
        "targetFramework": "''",
        "includePrerelease": "false",
    }
    url = "https://community.chocolatey.org/api/v2/Search()?" + urllib.parse.urlencode(query)
    req = urllib.request.Request(url, headers={"User-Agent": "ansible-runner-gui/1.0", "Accept": "application/atom+xml"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read()
        root = ET.fromstring(data)
    except Exception as e:
        raise HTTPException(502, f"Could not search the Chocolatey package index: {e}")

    results = []
    for entry in root.findall("atom:entry", CHOCO_NS):
        pkg_id = (entry.findtext("atom:title", default="", namespaces=CHOCO_NS) or "").strip()
        if not pkg_id:
            continue
        props = entry.find("m:properties", CHOCO_NS)
        title = ((props.findtext("d:Title", default="", namespaces=CHOCO_NS) if props is not None else "") or pkg_id).strip()
        version = ((props.findtext("d:Version", default="", namespaces=CHOCO_NS) if props is not None else "") or "").strip()
        summary = " ".join((entry.findtext("atom:summary", default="", namespaces=CHOCO_NS) or "").split())
        if len(summary) > 220:
            summary = summary[:220].rsplit(" ", 1)[0] + "..."
        results.append({"id": pkg_id, "title": title, "version": version, "summary": summary})
    return results


def add_package_to_playbook(name: str, label: str) -> None:
    if name in {p["name"] for p in list_packages()}:
        raise HTTPException(400, f"Package '{name}' is already in the list.")

    path = BASE / PLAYBOOK
    text = path.read_text()
    match = re.search(r"^(\s*)tasks:[ \t]*\r?\n", text, flags=re.MULTILINE)
    if not match:
        raise HTTPException(500, "Could not find the 'tasks:' section in the playbook.")

    label_escaped = label.replace("\\", "\\\\").replace('"', '\\"')
    new_line = f'      - {{ name: {name}, label: "{label_escaped}" }}\n'
    insert_at = match.start()
    path.write_text(text[:insert_at] + new_line + text[insert_at:])


def list_wsl_distros() -> list[dict]:
    docs = yaml.safe_load((BASE / PLAYBOOK).read_text())
    return docs[0]["vars"].get("wsl_distros_available", [])


def vault_file_for_target(target: str) -> pathlib.Path:
    return GROUP_VAULT if target == "group" else HOST_VARS_DIR / target / "vault.yml"


def redact(extra_vars: dict) -> dict:
    redacted = dict(extra_vars)
    for k in ("wazuh_registration_password", "tailscale_authkey"):
        if k in redacted:
            redacted[k] = "***"
    return redacted


def start_run_record(started, hosts, extra_vars) -> int:
    conn = db_connect()
    cur = conn.execute(
        "INSERT INTO runs (started_at, finished_at, hosts, params, status, error) VALUES (?,?,?,?,?,?)",
        (started, None, json.dumps(hosts or ["<all>"]), json.dumps(redact(extra_vars)), "running", None),
    )
    run_id = cur.lastrowid
    conn.commit()
    conn.close()
    return run_id


def finalize_run(run_id, finished, status, error, stats, per_host) -> None:
    conn = db_connect()
    conn.execute(
        "UPDATE runs SET finished_at = ?, status = ?, error = ? WHERE id = ?",
        (finished, status, error, run_id),
    )
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


def build_per_host(host_events: dict, stats: dict) -> dict:
    """Turns the callback's flat per-host event list into the same
    {host: [{"package": label, "status": ...}]} shape the GUI renders."""
    per_host: dict[str, list] = {}
    for host, events in host_events.items():
        bucket = per_host.setdefault(host, [])
        for e in events:
            kind = TASK_KIND.get(e["task"])
            if not kind:
                continue
            label = (e["item"] or "?") if kind == "loop" else e["task"]
            if e.get("unreachable"):
                status = "unreachable"
            elif e.get("failed"):
                status = "failed"
            elif e.get("skipped"):
                status = "skipped"
            elif e.get("changed"):
                status = "installed/upgraded" if kind == "loop" else "done"
            else:
                status = "already up to date" if kind == "loop" else "no change"
            bucket.append({"package": label, "status": status})

    for host, s in stats.items():
        bucket = per_host.setdefault(host, [])
        if not bucket and (s.get("unreachable") or s.get("failures")):
            bucket.append({
                "package": "(connection)",
                "status": "unreachable" if s.get("unreachable") else "failed",
            })

    return per_host


@app.get("/api/hosts")
def api_hosts():
    return list_hosts()


class HostIn(BaseModel):
    name: str


@app.post("/api/hosts")
def api_add_host(body: HostIn):
    name = body.name.strip()
    if not name:
        raise HTTPException(400, "Host name/IP is required.")
    add_host_to_inventory(name)
    return {"ok": True, "name": name}


@app.post("/api/hosts/{name}/test")
def api_test_host(name: str):
    if name not in {h["name"] for h in list_hosts()}:
        raise HTTPException(404, f"Host '{name}' not found in inventory.")
    return test_host(name)


@app.get("/api/packages")
def api_packages():
    return list_packages()


class PackageIn(BaseModel):
    name: str
    label: Optional[str] = None


@app.post("/api/packages")
def api_add_package(body: PackageIn):
    name = body.name.strip()
    if not PACKAGE_ID_RE.match(name):
        raise HTTPException(400, "Invalid package id - use letters, numbers, dots, and hyphens only.")
    label = (body.label or name).strip()[:120] or name
    add_package_to_playbook(name, label)
    return {"ok": True, "name": name, "label": label}


@app.get("/api/chocolatey/search")
def api_chocolatey_search(q: str = ""):
    q = q.strip()
    if len(q) < 2:
        raise HTTPException(400, "Search term must be at least 2 characters.")
    return search_chocolatey(q)


@app.get("/api/wsl-distros")
def api_wsl_distros():
    return list_wsl_distros()


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
    packages: list[str] = []  # empty = install every package in choco_packages (see install_packages)
    install_packages: bool = True  # false = skip the Chocolatey step entirely (e.g. a WSL/Wazuh-only run)
    wazuh: Optional[WazuhParams] = None
    tailscale_join: bool = False  # explicit opt-in - a stored vault key alone must never be enough to join
    tailscale_authkey: Optional[str] = None  # optional override of the vault-stored key
    git: Optional[GitParams] = None
    wsl_distros: list[str] = []  # empty = WSL step skipped entirely
    wsl_allow_reboot: bool = False
    wsl_target_users: list[str] = []  # also provision selected distro(s) for these specific Windows users
    win11debloat: bool = False  # run Win11Debloat with its own default settings, silently
    rsat: bool = False  # install all RSAT (Remote Server Administration Tools) capabilities


def build_extra_vars(body: RunIn) -> dict:
    # Native Python types (bool/list/str), not pre-stringified - api_run sends
    # this whole dict as a single `-e <json>` argument, which is the only
    # extra-vars form ansible-playbook reliably parses complex types from.
    # `-e key=[...]` shorthand does NOT auto-parse as JSON in this ansible-core
    # version - the value stays a literal string, which silently breaks any
    # `loop:` over it ("must resolve to a 'list', not 'str'").
    extra_vars: dict = {}
    if not body.install_packages:
        extra_vars["install_packages"] = False
    elif body.packages:
        extra_vars["choco_packages_selected"] = body.packages
    if body.wsl_distros:
        extra_vars["wsl_enabled"] = True
        extra_vars["wsl_distros_selected"] = body.wsl_distros
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
    if body.tailscale_join:
        extra_vars["tailscale_join_enabled"] = True
        if body.tailscale_authkey:
            extra_vars["tailscale_authkey"] = body.tailscale_authkey
    if body.git:
        if body.git.name:
            extra_vars["git_user_name"] = body.git.name
        if body.git.email:
            extra_vars["git_user_email"] = body.git.email
    if body.wsl_allow_reboot:
        extra_vars["wsl_allow_reboot"] = True
    if body.wsl_target_users:
        extra_vars["wsl_target_users"] = body.wsl_target_users
    if body.win11debloat:
        extra_vars["win11debloat_enabled"] = True
    if body.rsat:
        extra_vars["rsat_enabled"] = True
    return extra_vars


def run_log_path(run_id: int) -> pathlib.Path:
    return DATA_DIR / f"run-{run_id}.log"


def run_result_path(run_id: int) -> pathlib.Path:
    return DATA_DIR / f"run-{run_id}.result.json"


def _execute_run(run_id: int, cmd: list[str], env: dict) -> None:
    try:
        try:
            # gui_stream writes everything useful (log + result JSON) straight
            # to files, so the parent doesn't need piped stdout/stderr - and
            # capturing via pipes from a background thread risks the pipe
            # filling up and backpressuring the child if this thread doesn't
            # get scheduled promptly (e.g. while the main thread is busy
            # serving frequent /api/run/{id}/log polls), which can disrupt
            # the run partway through. Redirect to /dev/null instead.
            subprocess.run(
                cmd, cwd=str(BASE), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=1800,
            )
        except subprocess.TimeoutExpired:
            finished = datetime.now(timezone.utc).isoformat()
            finalize_run(run_id, finished, "timeout", "Run exceeded 30 minute timeout", {}, {})
            return

        finished = datetime.now(timezone.utc).isoformat()
        result_path = run_result_path(run_id)
        if result_path.exists():
            data = json.loads(result_path.read_text())
            stats = data.get("stats", {})
            per_host = build_per_host(data.get("host_events", {}), stats)
            overall_status = "failed" if any(
                s.get("failures", 0) > 0 or s.get("unreachable", 0) > 0 for s in stats.values()
            ) else "success"
            error = None
        else:
            stats, per_host = {}, {}
            overall_status = "error"
            error = run_log_path(run_id).read_text()[-4000:] if run_log_path(run_id).exists() else "No output produced."

        finalize_run(run_id, finished, overall_status, error, stats, per_host)
    finally:
        run_lock.release()


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
        if extra_vars:
            cmd += ["-e", json.dumps(extra_vars)]
        cmd += vault_password_args()

        started = datetime.now(timezone.utc).isoformat()
        run_id = start_run_record(started, body.hosts, extra_vars)

        log_path = run_log_path(run_id)
        log_path.write_text("")

        env = os.environ.copy()
        env["ANSIBLE_STDOUT_CALLBACK"] = "gui_stream"
        env["ANSIBLE_CALLBACK_PLUGINS"] = str(CALLBACK_PLUGINS_DIR)
        env["GUI_LOG_PATH"] = str(log_path)
        env["GUI_RESULT_PATH"] = str(run_result_path(run_id))
        env.setdefault("HOME", "/tmp")
        env.setdefault("ANSIBLE_LOCAL_TEMP", "/tmp/.ansible/tmp")

        threading.Thread(target=_execute_run, args=(run_id, cmd, env), daemon=True).start()
    except Exception:
        run_lock.release()
        raise

    return {"run_id": run_id, "status": "running"}


@app.get("/api/run/{run_id}/log")
def api_run_log(run_id: int):
    conn = db_connect()
    row = conn.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404, "Run not found.")
    log_path = run_log_path(run_id)
    text = log_path.read_text() if log_path.exists() else ""
    return {"log": text, "status": row[0], "done": row[0] != "running"}


@app.get("/api/run/{run_id}")
def api_run_status(run_id: int):
    conn = db_connect()
    conn.row_factory = sqlite3.Row
    r = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if not r:
        conn.close()
        raise HTTPException(404, "Run not found.")
    results = conn.execute(
        "SELECT host, package, status FROM run_results WHERE run_id = ?", (run_id,)
    ).fetchall()
    conn.close()
    by_host: dict[str, list] = {}
    for row in results:
        by_host.setdefault(row["host"], []).append({"package": row["package"], "status": row["status"]})
    return {"run_id": r["id"], "status": r["status"], "error": r["error"], "hosts": by_host}


@app.get("/api/history")
def api_history(limit: int = 20):
    conn = db_connect()
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
