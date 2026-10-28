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

Run by docker-agent.service (cadvisor.yml); its settings in
/etc/docker-agent.env: SENTRY_URL, AGENT_HOST, AGENT_KEY, SENTRY_TLS_VERIFY.
"""
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.1"
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
def run(argv, cwd, timeout=900):
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)  # noqa: S603 - fixed argv
    out = f"$ {' '.join(argv)}\n{p.stdout}{p.stderr}"
    return p.returncode, out


def refresh_meta(df=False):
    """docker-meta now, so the page shows the change soon - after the disk-use
    measure when images or volumes went (the image list comes from it)."""
    if df:
        subprocess.run(["systemctl", "start", "docker-meta-df.service"], capture_output=True, timeout=1200)  # noqa: S603,S607
    subprocess.run(["systemctl", "start", "--no-block", "docker-meta.service"], capture_output=True)  # noqa: S603,S607


def job_update(args):
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
    rc, out = run(base + ["pull", service], folder)
    if rc != 0:
        return False, out
    rc, out2 = run(base + ["up", "-d", "--no-deps", service], folder)
    return rc == 0, out + "\n" + out2


def in_use():
    """The image IDs any container (running or not) uses."""
    return {c.get("ImageID", "") for c in docker("GET", "/containers/json?all=1")}


def job_delete_images(args):
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


def job_delete_volumes(args):
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


def main():
    if not (URL and HOST and KEY):
        sys.exit("SENTRY_URL, AGENT_HOST and AGENT_KEY are needed (/etc/docker-agent.env)")
    log(f"docker-agent {VERSION} for {HOST} -> {URL}")
    last_check, refused = 0, 0
    while True:
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
            kind, args = j.get("kind"), j.get("args") or {}
            log(f"job {j.get('id')}: {kind} {json.dumps(args)[:200]}")
            if kind == "check_updates":
                report_updates(); last_check = time.time()
                ok, out = True, "checked"
            elif kind in JOBS:
                try:
                    ok, out = JOBS[kind](args)
                except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
                    ok, out = False, str(e)
            else:
                ok, out = False, f"this agent ({VERSION}) doesn't know {kind!r}"
            try:
                lens("POST", f"/api/docker-agent/jobs/{q(str(j.get('id', '')))}", {"ok": ok, "log": out[-LOG_MAX:]})
            except (urllib.error.URLError, OSError) as e:
                log(f"couldn't send job {j.get('id')}'s result: {e}")
            if kind in JOBS:
                try:
                    refresh_meta(df=kind != "update")
                except (OSError, subprocess.TimeoutExpired) as e:
                    log(f"couldn't refresh docker-meta: {e}")
            if kind == "update" and ok:
                report_updates(); last_check = time.time()
        if time.time() - last_check > CHECK_EVERY:
            last_check = time.time()
            report_updates()
        time.sleep(POLL)


if __name__ == "__main__":
    if sys.argv[1:] == ["check"]:  # a test: what it would report
        print(json.dumps(check_updates(), indent=2))
    else:
        main()
