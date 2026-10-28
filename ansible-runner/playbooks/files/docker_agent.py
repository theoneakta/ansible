#!/usr/bin/env python3
"""docker-agent: carries out the Docker actions an admin asks for on Sentry
Lens's Infrastructure > Docker page, on this host - and tells it which
containers have a newer image.

It only talks out: every POLL seconds it asks Sentry Lens for this host's
queued jobs (its key: Authorization, its host name: X-Host), runs them, and
posts each one's result. No port is opened. It knows four jobs, nothing else:

  update          docker compose pull + up -d of one Compose container's
                  service, in its project's folder, with its project's files
                  (only Compose containers: their file says how to recreate them)
  delete_images   remove these images - each only if no container (running
                  or not) uses it: a tag is untagged, the last tag removes it
  delete_volumes  remove these volumes - each only if no container uses it
  check_updates   compare each container's image with its registry, now

Every CHECK_EVERY it checks for updates by itself: the digest the registry
has for the image's tag (a HEAD request: no download, and it doesn't count
against Docker Hub's pull limit) against the ones this host pulled. Images
from a registry that wants a login, built here, or pinned by digest are
"unknown", "local" or "pinned". Reads and writes nothing else: no
environment, no settings, no logs of the containers.

A job is never left half-done by the agent itself stopping (an update of the
agent restarts it): its commands run in their own systemd unit, which goes on
without it, and the job is kept in STATE until its result is sent - a restarted
agent waits for those commands, runs the job again (pull + up -d and the
deletes come out the same run twice) and sends the result. While a job runs it
tells Sentry Lens every BEAT seconds; Sentry Lens hands a job out again when it
hears nothing for 5 minutes (dockerops.py).

Run by docker-agent.service (cadvisor.yml); its settings in
/etc/docker-agent.env: SENTRY_URL, AGENT_HOST, AGENT_KEY, SENTRY_TLS_VERIFY.
"""
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.1.1"
STATE = os.path.join(os.environ.get("STATE_DIRECTORY", "/var/lib/docker-agent"), "job.json")
BEAT = 60
JOB_ID = re.compile(r"[0-9a-f]{1,32}")
SOCK = "/var/run/docker.sock"
POLL = 10
CHECK_EVERY = 6 * 3600
URL = os.environ.get("SENTRY_URL", "").rstrip("/")
HOST = os.environ.get("AGENT_HOST", "")
KEY = os.environ.get("AGENT_KEY", "")
CTX = None if os.environ.get("SENTRY_TLS_VERIFY", "1") != "0" else ssl._create_unverified_context()  # noqa: S323 - asked for
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}")
IMAGE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}")
LOG_MAX = 16000


def log(msg):
    print(msg, flush=True)


# ------------------------------------------------------------------ Docker's socket
class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, timeout):
        super().__init__("localhost", timeout=timeout)
        self._t = timeout

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self._t)
        self.sock.connect(SOCK)


def docker(method, path, timeout=120):
    c = UnixHTTP(timeout)
    try:
        c.request(method, path)
        r = c.getresponse()
        body = r.read()
    finally:
        c.close()
    data = json.loads(body) if body else None
    if r.status >= 300:
        raise RuntimeError((data or {}).get("message", f"HTTP {r.status}") if isinstance(data, dict) else f"HTTP {r.status}")
    return data


def q(s):
    return urllib.parse.quote(s, safe="")


# ------------------------------------------------------------------ Sentry Lens
def lens(method, path, body=None):
    req = urllib.request.Request(URL + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {KEY}", "X-Host": HOST, "Content-Type": "application/json",
                                          "User-Agent": f"docker-agent/{VERSION}"})
    with urllib.request.urlopen(req, timeout=30, context=CTX) as r:  # noqa: S310 - our own URL
        return json.loads(r.read() or b"{}")


# ------------------------------------------------------------------ jobs
def run(argv, cwd, unit, timeout=1800):
    """A command in its own transient systemd unit (docker-agent-<unit>): the
    agent stopping doesn't kill it halfway - a recreate cut short leaves the
    service down. The same unit still running from before a restart: waited for."""
    if not shutil.which("systemd-run"):
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)  # noqa: S603 - fixed argv
        return p.returncode, f"$ {' '.join(argv)}\n{p.stdout}{p.stderr}"
    name = f"docker-agent-{unit}"
    end, waited = time.time() + timeout, False
    while subprocess.run(["systemctl", "is-active", "--quiet", name]).returncode == 0 and time.time() < end:  # noqa: S603,S607
        waited = True
        time.sleep(5)
    p = subprocess.run(["systemd-run", "--quiet", "--wait", "--pipe", "--collect", f"--unit={name}",  # noqa: S603,S607
                        f"--working-directory={cwd}", f"--property=RuntimeMaxSec={timeout}", *argv],
                       capture_output=True, text=True, timeout=timeout + 60, stdin=subprocess.DEVNULL)
    return p.returncode, (f"(waited for the same step left running before a restart)\n" if waited else "") + \
        f"$ {' '.join(argv)}\n{p.stdout}{p.stderr}"


def refresh_meta(df=False):
    """docker-meta now, so the page shows the change soon - after the disk-use
    measure when images or volumes went (the image list comes from it)."""
    if df:
        subprocess.run(["systemctl", "start", "docker-meta-df.service"], capture_output=True, timeout=1200)  # noqa: S603,S607
    subprocess.run(["systemctl", "start", "--no-block", "docker-meta.service"], capture_output=True)  # noqa: S603,S607


def job_update(args, jid):
    name = str(args.get("container", ""))
    if not NAME.fullmatch(name):
        raise ValueError("a container name")
    d = docker("GET", f"/containers/{q(name)}/json")
    lab = (d.get("Config") or {}).get("Labels") or {}
    project, service = lab.get("com.docker.compose.project", ""), lab.get("com.docker.compose.service", "")
    folder = lab.get("com.docker.compose.project.working_dir", "")
    files = [os.path.join(folder, f) for f in lab.get("com.docker.compose.project.config_files", "").split(",") if f]
    if not (project and service and folder):
        raise ValueError(f"{name} isn't a Compose container - only those can be recreated from their file")
    if not os.path.isdir(folder):
        raise ValueError(f"its project folder {folder} isn't there any more")
    missing = [f for f in files if not os.path.isfile(f)]
    if missing:
        raise ValueError(f"its Compose file {missing[0]} isn't there any more")
    env = [a for f in lab.get("com.docker.compose.project.environment_file", "").split(",")
           if f and os.path.isfile(os.path.join(folder, f)) for a in ("--env-file", os.path.join(folder, f))]
    base = ["docker", "compose", "-p", project, *[a for f in files for a in ("-f", f)], *env]
    rc, out = run(base + ["pull", service], folder, f"{jid}-pull")
    if rc != 0:
        return False, out
    rc, out2 = run(base + ["up", "-d", "--no-deps", service], folder, f"{jid}-up")
    return rc == 0, out + "\n" + out2 + tidy_names(project, service)


def tidy_names(project, service):
    """A recreate cut short leaves the new container under Compose's temporary
    name (<id>_<name>), which a later up starts as is: its own name back."""
    flt = q(json.dumps({"label": [f"com.docker.compose.project={project}", f"com.docker.compose.service={service}"]}))
    names = {(c.get("Names") or ["/"])[0].lstrip("/"): c["Id"] for c in docker("GET", f"/containers/json?all=1&filters={flt}")}
    out = ""
    for name, cid in names.items():
        m = re.fullmatch(r"[0-9a-f]{12}_(.+)", name)
        if m and m.group(1) not in names:
            docker("POST", f"/containers/{cid}/rename?name={q(m.group(1))}")
            out += f"\nrenamed {name} back to {m.group(1)}"
    return out


def in_use():
    """The image IDs any container (running or not) uses."""
    return {c.get("ImageID", "") for c in docker("GET", "/containers/json?all=1")}


def job_delete_images(args, _jid):
    used, lines, ok = in_use(), [], True
    for ref in args.get("images") or []:
        ref = str(ref)
        if not IMAGE.fullmatch(ref):
            lines.append(f"{ref}: not an image name or ID - skipped"); ok = False
            continue
        try:
            img = docker("GET", f"/images/{q(ref)}/json")
        except RuntimeError as e:
            lines.append(f"{ref}: {e} - skipped (already gone?)")
            continue
        if img.get("Id") in used:
            lines.append(f"{ref}: a container uses it now - kept"); ok = False
            continue
        try:
            res = docker("DELETE", f"/images/{q(ref)}")
            gone = [r.get("Deleted") or r.get("Untagged") for r in res or []]
            lines.append(f"{ref}: removed ({len([r for r in res or [] if r.get('Deleted')])} layers deleted)" if gone else f"{ref}: removed")
        except RuntimeError as e:
            lines.append(f"{ref}: {e}"); ok = False
    return ok, "\n".join(lines) or "nothing to do"


def job_delete_volumes(args, _jid):
    lines, ok = [], True
    users = {}
    for c in docker("GET", "/containers/json?all=1"):
        for m in c.get("Mounts") or []:
            if m.get("Type") == "volume":
                users.setdefault(m.get("Name"), []).append((c.get("Names") or ["?"])[0].lstrip("/"))
    for name in args.get("volumes") or []:
        name = str(name)
        if not NAME.fullmatch(name):
            lines.append(f"{name}: not a volume name - skipped"); ok = False
            continue
        if users.get(name):
            lines.append(f"{name}: used by {', '.join(users[name])} - kept"); ok = False
            continue
        try:
            docker("DELETE", f"/volumes/{q(name)}")
            lines.append(f"{name}: removed")
        except RuntimeError as e:
            lines.append(f"{name}: {e}"); ok = False
    return ok, "\n".join(lines) or "nothing to do"


# ------------------------------------------------------------------ updates
ACCEPT = ", ".join(["application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json",
                    "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.oci.image.manifest.v1+json"])


def parse_ref(ref):
    """'nginx:1.27' -> ('registry-1.docker.io', 'library/nginx', '1.27'); None when pinned by digest."""
    if "@" in ref:
        return None
    name, tag = ref, "latest"
    if ":" in ref.rsplit("/", 1)[-1]:
        name, tag = ref.rsplit(":", 1)
    first = name.split("/", 1)[0]
    if "/" in name and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, name.split("/", 1)[1]
    else:
        registry, repo = "docker.io", name
    if registry == "docker.io":
        registry = "registry-1.docker.io"
        if "/" not in repo:
            repo = "library/" + repo
    return registry, repo, tag


class NotOnRegistry(RuntimeError):
    """Docker Hub turns away even an anonymous token: no such public image - built here, or private."""


def remote_digest(registry, repo, tag):
    url = f"https://{registry}/v2/{repo}/manifests/{tag}"
    headers = {"Accept": ACCEPT, "User-Agent": f"docker-agent/{VERSION}"}
    for attempt in range(2):
        req = urllib.request.Request(url, method="HEAD", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310 - https only
                d = r.headers.get("Docker-Content-Digest", "")
                if not d:
                    raise RuntimeError("the registry gave no digest")
                return d
        except urllib.error.HTTPError as e:
            auth = e.headers.get("WWW-Authenticate", "")
            if attempt and e.code == 401 and registry == "registry-1.docker.io":
                raise NotOnRegistry("not on Docker Hub - built here, or private")
            if e.code != 401 or attempt or not auth.lower().startswith("bearer "):
                raise RuntimeError(f"registry: HTTP {e.code}" + (" (needs a login)" if e.code in (401, 403) else
                                                                  " (the tag isn't there any more)" if e.code == 404 else ""))
            # Anonymous token for a public image (Docker Hub, ghcr.io, lscr.io, quay.io...).
            p = dict(re.findall(r'(\w+)="([^"]*)"', auth))
            realm = p.pop("realm", "")
            if not realm.startswith("https://"):
                raise RuntimeError("registry: an odd login request")
            with urllib.request.urlopen(realm + "?" + urllib.parse.urlencode(p), timeout=20) as r:  # noqa: S310
                t = json.loads(r.read())
            headers["Authorization"] = "Bearer " + (t.get("token") or t.get("access_token") or "")
    raise RuntimeError("registry: no answer")


def check_updates():
    """{image: {status, local, remote, error}} for the images this host's containers use."""
    refs = {}
    for c in docker("GET", "/containers/json?all=1"):
        refs.setdefault(c.get("Image", ""), c.get("ImageID", ""))
    out = {}
    for ref, image_id in refs.items():
        r = {"status": "unknown", "local": "", "remote": "", "error": ""}
        try:
            img = docker("GET", f"/images/{q(image_id or ref)}/json")
            local = [d.split("@", 1)[1] for d in img.get("RepoDigests") or [] if "@" in d]
            r["local"] = local[0] if local else ""
            parsed = parse_ref(ref)
            if ref.startswith("sha256:") or not parsed:
                r["status"] = "pinned"
            elif not local:
                r["status"] = "local"
            else:
                # (Docker's containerd image store gives images built here a "digest" too: their own ID.)
                r["remote"] = remote_digest(*parsed)
                r["status"] = "current" if r["remote"] in local else "update"
        except NotOnRegistry as e:
            r["status"], r["error"] = "local", str(e)
        except (RuntimeError, OSError, ValueError) as e:
            r["error"] = str(e)[:200]
        out[ref] = r
    return out


def report_updates():
    try:
        lens("POST", "/api/docker-agent/updates", {"images": check_updates(), "version": VERSION})
        log("updates checked")
    except (urllib.error.URLError, OSError, ValueError, RuntimeError) as e:
        log(f"couldn't check or send the updates: {e}")


JOBS = {"update": job_update, "delete_images": job_delete_images, "delete_volumes": job_delete_volumes}


# ------------------------------------------------------------------ the job in hand, kept
def keep(state):
    """The job in hand (and its result once there) - in STATE until Sentry Lens has the result."""
    if state is None:
        try:
            os.remove(STATE)
        except FileNotFoundError:
            pass
        return
    os.makedirs(os.path.dirname(STATE), mode=0o700, exist_ok=True)
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE)


def kept():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def execute(j):
    kind, args, jid = j.get("kind"), j.get("args") or {}, str(j.get("id", ""))
    if not JOB_ID.fullmatch(jid):
        return False, "an odd job ID"
    if kind == "check_updates":
        report_updates()
        return True, "checked"
    if kind not in JOBS:
        return False, f"this agent ({VERSION}) doesn't know {kind!r}"
    try:
        return JOBS[kind](args, jid)
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)


def send_result(state):
    """True once Sentry Lens has it (then the job is forgotten here)."""
    j, r = state["job"], state["result"]
    try:
        lens("POST", f"/api/docker-agent/jobs/{q(str(j.get('id', '')))}", {"ok": r["ok"], "log": r["log"][-LOG_MAX:]})
    except urllib.error.HTTPError as e:
        if e.code != 404:  # 404: Sentry Lens no longer has the job - nothing to send it to
            log(f"couldn't send job {j.get('id')}'s result (tried again in {POLL} s): {e}")
            return False
    except (urllib.error.URLError, OSError) as e:
        log(f"couldn't send job {j.get('id')}'s result (tried again in {POLL} s): {e}")
        return False
    keep(None)
    return True


def handle(j, resumed=False):
    """Run a job - telling Sentry Lens every BEAT s that it's still going - then send its result."""
    log(f"job {j.get('id')}: {j.get('kind')} {json.dumps(j.get('args') or {})[:200]}{' (again: cut short by a restart)' if resumed else ''}")
    keep({"job": j, "result": None})
    box = {}
    t = threading.Thread(target=lambda: box.update(zip(("ok", "log"), execute(j))), daemon=True)
    t.start()
    while True:
        t.join(BEAT)
        if not t.is_alive():
            break
        try:
            lens("POST", f"/api/docker-agent/jobs/{q(str(j.get('id', '')))}", {"running": True})
        except (urllib.error.URLError, OSError):
            pass
    if resumed:
        box["log"] = "(run again: the agent was restarted while it ran)\n" + box.get("log", "")
    state = {"job": j, "result": {"ok": bool(box.get("ok")), "log": box.get("log", "")}}
    keep(state)
    send_result(state)
    if j.get("kind") in JOBS:
        try:
            refresh_meta(df=j.get("kind") != "update")
        except (OSError, subprocess.TimeoutExpired) as e:
            log(f"couldn't refresh docker-meta: {e}")
    if j.get("kind") == "update" and box.get("ok"):
        report_updates()


def main():
    if not (URL and HOST and KEY):
        sys.exit("SENTRY_URL, AGENT_HOST and AGENT_KEY are needed (/etc/docker-agent.env)")
    log(f"docker-agent {VERSION} for {HOST} -> {URL}")
    last_check, refused = 0, 0
    # A job cut short by a restart: run again (its commands, still running, are waited for).
    state = kept()
    if state and state.get("result") is None:
        handle(state["job"], resumed=True)
    while True:
        state = kept()
        if state and state.get("result") is not None and not send_result(state):
            time.sleep(POLL)  # Sentry Lens can't be reached: its result first
            continue
        try:
            jobs = lens("GET", f"/api/docker-agent/jobs?version={VERSION}").get("jobs", [])
            refused = 0
        except urllib.error.HTTPError as e:
            if e.code == 401 and time.time() - refused > 3600:
                log("Sentry Lens refuses this host's key - run cadvisor.yml again for this host")
                refused = time.time()
            jobs = []
        except (urllib.error.URLError, OSError, ValueError) as e:
            log(f"can't reach Sentry Lens: {e}")
            jobs = []
        for j in jobs:
            handle(j)
            if j.get("kind") in ("check_updates", "update"):
                last_check = time.time()
        if time.time() - last_check > CHECK_EVERY:
            last_check = time.time()
            report_updates()
        time.sleep(POLL)


if __name__ == "__main__":
    if sys.argv[1:] == ["check"]:  # a test: what it would report
        print(json.dumps(check_updates(), indent=2))
    else:
        main()
