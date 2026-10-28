#!/usr/bin/env python3
"""docker-agent: carries out the Docker actions an admin asks for on Sentry
Lens's Infrastructure > Docker page, on this host - and tells it which
containers have a newer image.

It only talks out: every POLL seconds it asks Sentry Lens for this host's
queued jobs (its key: Authorization, its host name: X-Host), runs them, and
posts each one's result. No port is opened. It knows five jobs, nothing else:

  update          pull a container's image and, when it changed, recreate the
                  container as it is: its own settings (docker inspect) - name,
                  mounts, environment, ports, networks, restart policy, labels
                  - with only the image new. No Compose file is read again, so
                  nothing it says now (a ~, an edit) changes what it mounts.
                  The old container is kept, renamed, until the new one has
                  run for 20 s; if it doesn't stay up, the old one is back.
  delete_images   remove these images - each only if no container (running
                  or not) uses it: a tag is untagged, the last tag removes it
  delete_volumes  remove these volumes - each only if no container uses it
  restart         restart a container as it is (a stopped one is started)
  check_updates   compare each container's image with its registry, now

Every CHECK_EVERY it checks for updates by itself: the digest the registry
has for the image's tag (a HEAD request: no download, and it doesn't count
against Docker Hub's pull limit) against the ones this host pulled. Images
from a registry that wants a login, built here, or pinned by digest are
"unknown", "local" or "pinned".

A container's logs, when an admin opens them on the page: the agent waits on
Sentry Lens (a long poll, outgoing too) for what a page asks to see, reads
those lines from Docker and sends them back - kept nowhere. Reads and writes
nothing else: no environment, no settings.

A job is never left half-done by the agent itself stopping (an update of the
agent restarts it): the job is kept in STATE until its result is sent, and a
restarted agent runs it again - an update finds the old container it renamed
and finishes, or puts it back first; the deletes come out the same run twice.
While a job runs it tells Sentry Lens every BEAT seconds; Sentry Lens hands a
job out again when it hears nothing for 5 minutes (dockerops.py).

Run by docker-agent.service (cadvisor.yml); its settings in
/etc/docker-agent.env: SENTRY_URL, AGENT_HOST, AGENT_KEY, SENTRY_TLS_VERIFY.
"""
import calendar
import http.client
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "2.2.0"
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


def docker(method, path, timeout=120, body=None):
    c = UnixHTTP(timeout)
    try:
        if body is None:
            c.request(method, path)
        else:
            c.request(method, path, body=json.dumps(body), headers={"Content-Type": "application/json"})
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
def lens(method, path, body=None, timeout=30):
    req = urllib.request.Request(URL + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {KEY}", "X-Host": HOST, "Content-Type": "application/json",
                                          "User-Agent": f"docker-agent/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:  # noqa: S310 - our own URL
        return json.loads(r.read() or b"{}")


# ------------------------------------------------------------------ jobs
# A registry or the network turning a pull away for a moment: tried again.
TRANSIENT = re.compile(r"toomanyrequests|too many requests|rate limit|i/o timeout|TLS handshake timeout|connection reset"
                       r"|connection refused|unexpected EOF|503 Service Unavailable|502 Bad Gateway|no such host|temporary failure", re.I)
PULL_WAITS = (20, 60)  # seconds before the 2nd and 3rd attempt (then Sentry Lens tries the job again later)


def docker_stream(method, path, timeout=1800):
    """A Docker call answering with a stream of JSON lines (a pull): its text, and the first error in it."""
    c = UnixHTTP(timeout)
    try:
        c.request(method, path)
        r = c.getresponse()
        body = r.read().decode(errors="replace")
    finally:
        c.close()
    err = ""
    for line in body.splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if isinstance(m, dict) and m.get("error"):
            err = err or str(m["error"])
    if r.status >= 300 and not err:
        err = f"HTTP {r.status}: {body[:300]}"
    return body, err


def pull(ref):
    """Pull ref (repo[:tag]) - a registry or the network turning it away is tried
    again after PULL_WAITS; (ok, log, retry later)."""
    name, tag = ref, "latest"
    if ":" in ref.rsplit("/", 1)[-1]:
        name, tag = ref.rsplit(":", 1)
    out = f"pull {ref}\n"
    for attempt in range(len(PULL_WAITS) + 1):
        _, err = docker_stream("POST", f"/images/create?fromImage={q(name)}&tag={q(tag)}")
        if not err:
            return True, out + "pulled\n", False
        out += f"  {err}\n"
        if not TRANSIENT.search(err):
            return False, out, False
        if attempt < len(PULL_WAITS):
            out += f"  (the registry or the network turned it away - again in {PULL_WAITS[attempt]} s)\n"
            time.sleep(PULL_WAITS[attempt])
    return False, out + "(still turned away - Sentry Lens tries the job again in 5 minutes)\n", True


def create_body(d, old_image, ref):
    """The new container's settings: the old one's exactly, but the image - and
    where it only carried the old image's defaults (command, entrypoint,
    environment, labels...), the new image's defaults instead."""
    cfg, img = dict(d.get("Config") or {}), (old_image.get("Config") or {})
    cfg["Image"] = ref
    for k in ("Cmd", "Entrypoint", "WorkingDir", "User", "Healthcheck", "StopSignal", "Shell"):
        if k in cfg and cfg[k] == img.get(k):
            cfg.pop(k)  # the old image's default: the new image's applies
    if cfg.get("Env"):
        cfg["Env"] = [e for e in cfg["Env"] if e not in (img.get("Env") or [])]
    if cfg.get("Labels"):
        il = img.get("Labels") or {}
        cfg["Labels"] = {k: v for k, v in cfg["Labels"].items() if il.get(k) != v}
    for k in ("ExposedPorts", "Volumes"):
        if cfg.get(k):
            cfg[k] = {p: v for p, v in cfg[k].items() if p not in (img.get(k) or {})} or None
    if cfg.get("Hostname") == d["Id"][:12]:
        cfg.pop("Hostname")  # Docker's default (the ID): the new one gets its own
    cfg.pop("MacAddress", None)
    host = dict(d.get("HostConfig") or {})
    # Volumes it has that its settings don't name (anonymous ones, an image's
    # VOLUME): the same volumes again, not new empty ones.
    named = {(b.split(":")[1] if ":" in b else b) for b in host.get("Binds") or []}
    named |= {m.get("Target") for m in host.get("Mounts") or []}
    for m in d.get("Mounts") or []:
        if m.get("Type") == "volume" and m.get("Destination") not in named:
            host["Binds"] = (host.get("Binds") or []) + [f"{m['Name']}:{m['Destination']}" + ("" if m.get("RW", True) else ":ro")]
    nets = (d.get("NetworkSettings") or {}).get("Networks") or {}
    mode = host.get("NetworkMode", "")

    def endpoint(n):
        keep = {k: n.get(k) for k in ("IPAMConfig", "Links", "Aliases", "DriverOpts") if n.get(k)}
        if keep.get("Aliases"):
            keep["Aliases"] = [a for a in keep["Aliases"] if a != d["Id"][:12]]
        return keep
    first = mode if mode in nets else next(iter(nets), "")
    body = cfg | {"HostConfig": host}
    if first and not mode.startswith(("container:", "host", "none")):
        body["NetworkingConfig"] = {"EndpointsConfig": {first: endpoint(nets[first])}}
    others = {k: endpoint(v) for k, v in nets.items() if k != first} if not mode.startswith(("container:", "host", "none")) else {}
    return body, others


def job_update(args, jid):
    """Pull the container's image and, when it changed, recreate the container
    as it is - its own settings (docker inspect), only the image new. The old
    one is kept, renamed, until the new one runs: if it doesn't, the old one
    is back as it was."""
    name = str(args.get("container", ""))
    if not NAME.fullmatch(name):
        raise ValueError("a container name")
    resumed = resume(name, jid)
    if resumed:
        return True, resumed, False
    d = docker("GET", f"/containers/{q(name)}/json")
    name = d["Name"].lstrip("/")
    ref = (d.get("Config") or {}).get("Image", "")
    if not ref or ref.startswith("sha256:") or "@" in ref:
        return False, f"{name} runs an image by ID or digest ({ref}) - nothing to update to", False
    # Containers living in this one's network (network_mode: container:...) would lose it.
    tied = [(c.get("Names") or ["?"])[0].lstrip("/") for c in docker("GET", "/containers/json?all=1")
            if (c.get("HostConfig") or {}).get("NetworkMode", "") in (f"container:{d['Id']}", f"container:{name}")]
    if tied:
        return False, f"{', '.join(tied)} use{'s' if len(tied) == 1 else ''} {name}'s network - recreating it would cut them off. Update them together by hand.", False
    ok, out, retry = pull(ref)
    if not ok:
        return False, out, retry
    new_id = docker("GET", f"/images/{q(ref)}/json")["Id"]
    if new_id == d["Image"]:
        return True, out + f"{name} already runs the latest {ref} - not restarted", False
    old_image = docker("GET", f"/images/{q(d['Image'])}/json")
    body, others = create_body(d, old_image, ref)
    was_running = (d.get("State") or {}).get("Running")
    stop_t = (d.get("Config") or {}).get("StopTimeout") or 10
    keep = f"{name}_old_{jid}"
    out += f"recreating {name}: {d['Image'][7:19]} -> {new_id[7:19]}\n"
    docker("POST", f"/containers/{d['Id']}/stop?t={stop_t}", timeout=stop_t + 60)
    docker("POST", f"/containers/{d['Id']}/rename?name={q(keep)}")
    new = None

    def back(why):
        """Undo: the new container gone, the old one back under its name, started."""
        for step in (lambda: new and docker("DELETE", f"/containers/{new}?force=1"),
                     lambda: docker("POST", f"/containers/{d['Id']}/rename?name={q(name)}"),
                     lambda: was_running and docker("POST", f"/containers/{d['Id']}/start")):
            try:
                step()
            except (RuntimeError, OSError) as e:
                why += f"\n  (while putting it back: {e})"
        return False, out + why + f"\n{name} is back as it was, on its old image.", False
    try:
        new = _create(name, body)["Id"]
        for net, ep in others.items():
            docker("POST", f"/networks/{q(net)}/connect", body={"Container": new, "EndpointConfig": ep})
        if was_running:
            docker("POST", f"/containers/{new}/start")
            time.sleep(20)  # it must stay up: a new image that crashes at once goes back
            st = docker("GET", f"/containers/{new}/json")["State"]
            if not st.get("Running") or st.get("Restarting"):
                return back(f"the new container didn't stay up (exit {st.get('ExitCode')}).")
    except (RuntimeError, OSError) as e:
        return back(f"couldn't recreate it: {e}")
    try:
        docker("DELETE", f"/containers/{d['Id']}")  # the old one (its volumes stay - the new one has them)
    except (RuntimeError, OSError) as e:
        out += f"(the old container {keep} is left: {e})\n"
    return True, out + f"{name} runs the new image, with its settings as they were", False


def _create(name, body):
    return docker("POST", f"/containers/create?name={q(name)}", body=body)


def resume(name, jid):
    """The same job cut short (the agent restarted): its old container, renamed
    <name>_old_<jid>, is still there. The new one running: done, the old one
    removed ("" otherwise, after putting the old one back - then it's run again)."""
    keep = f"{name}_old_{jid}"
    try:
        old = docker("GET", f"/containers/{q(keep)}/json")
    except RuntimeError:
        return ""
    try:
        new = docker("GET", f"/containers/{q(name)}/json")
    except RuntimeError:
        new = None
    if new and (new.get("State") or {}).get("Running"):
        docker("DELETE", f"/containers/{old['Id']}")
        return f"(cut short by a restart, then finished: {name} runs the new image; the old container removed)"
    if new:
        docker("DELETE", f"/containers/{new['Id']}?force=1")
    docker("POST", f"/containers/{old['Id']}/rename?name={q(name)}")
    # It was stopped to be replaced (an update only stops a running one): started again, then updated anew.
    if not (old.get("State") or {}).get("Running"):
        docker("POST", f"/containers/{old['Id']}/start")
    return ""


def job_restart(args, _jid):
    """Restart a container as it is (a stopped one is started) - Docker's own
    restart: stopped with its stop timeout, started again, nothing recreated."""
    name = str(args.get("container", ""))
    if not NAME.fullmatch(name):
        raise ValueError("a container name")
    d = docker("GET", f"/containers/{q(name)}/json")
    was = "running" if (d.get("State") or {}).get("Running") else (d.get("State") or {}).get("Status", "stopped")
    stop_t = (d.get("Config") or {}).get("StopTimeout") or 10
    docker("POST", f"/containers/{d['Id']}/restart?t={stop_t}", timeout=stop_t + 120)
    time.sleep(5)
    st = docker("GET", f"/containers/{d['Id']}/json")["State"]
    if not st.get("Running") or st.get("Restarting"):
        return False, f"{name} ({was}) was restarted but isn't running (exit {st.get('ExitCode')}, {st.get('Status')})"
    return True, f"{name} {'restarted' if was == 'running' else 'started'} - it was {was}"


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


JOBS = {"update": job_update, "restart": job_restart, "delete_images": job_delete_images, "delete_volumes": job_delete_volumes}


# ------------------------------------------------------------------ a container's logs, when a page asks
LOGS_READ = 4 << 20  # at most this much read from Docker per ask
LOGS_SEND = 2 << 20  # ... and sent back (the newest lines)
LINE_MAX = 8000
SINCE = re.compile(r"\d{1,20}")


def ns_of(stamp):
    """Docker's RFC 3339 timestamp (always UTC, Z) -> ns since the epoch, as a string."""
    main, _, frac = stamp.rstrip("Z").partition(".")
    try:
        s = calendar.timegm(time.strptime(main, "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return "0"
    return str(s * 1_000_000_000 + int((frac[:9] or "0").ljust(9, "0")))


def read_logs(name, tail, since):
    """[[ns, stream, text]] - stream 1 stdout, 2 stderr, 0 a terminal's (both mixed) - and whether it was cut."""
    d = docker("GET", f"/containers/{q(name)}/json")
    tty = bool((d.get("Config") or {}).get("Tty"))
    path = f"/containers/{d['Id']}/logs?stdout=1&stderr=1&timestamps=1"
    path += f"&since={int(since) // 1_000_000_000}.{int(since) % 1_000_000_000:09d}" if since else f"&tail={tail}"
    c = UnixHTTP(60)
    try:
        c.request("GET", path)
        r = c.getresponse()
        raw = r.read(LOGS_READ + 1)
    finally:
        c.close()
    if r.status >= 300:
        try:
            raise RuntimeError(json.loads(raw).get("message", f"HTTP {r.status}"))
        except ValueError:
            raise RuntimeError(f"HTTP {r.status}") from None
    cut = len(raw) > LOGS_READ
    chunks = [(0, raw)] if tty else []
    i = 0
    while not tty and i + 8 <= len(raw):  # stdout and stderr multiplexed: 8-byte headers
        n = int.from_bytes(raw[i + 4:i + 8], "big")
        chunks.append((raw[i], raw[i + 8:i + 8 + n]))
        i += 8 + n
    lines = []
    for stream, b in chunks:
        for ln in b.decode(errors="replace").splitlines():
            stamp, _, text = ln.partition(" ")
            ns = ns_of(stamp)
            if since and int(ns) < int(since):  # Docker's since: to the microsecond at best
                continue
            lines.append([ns, stream if stream in (1, 2) else 0, text[:LINE_MAX]])
    lines = lines[-tail:] if not since else lines
    size = 0
    for k in range(len(lines) - 1, -1, -1):  # the newest lines within LOGS_SEND
        size += len(lines[k][2]) + 30
        if size > LOGS_SEND:
            lines, cut = lines[k + 1:], True
            break
    return lines, tty, cut


def answer_logs(ask):
    rid, name, since = str(ask.get("id", "")), str(ask.get("container", "")), str(ask.get("since") or "")
    if not JOB_ID.fullmatch(rid):
        return
    try:
        if not NAME.fullmatch(name) or (since and not SINCE.fullmatch(since)):
            raise ValueError("a container name, and since in ns")
        lines, tty, cut = read_logs(name, max(1, min(int(ask.get("tail") or 500), 5000)), since)
        out = {"lines": lines, "tty": tty, "cut": cut}
    except (RuntimeError, ValueError, OSError) as e:
        out = {"error": str(e)}
    try:
        lens("POST", f"/api/docker-agent/logs/{rid}", out, timeout=60)
    except (urllib.error.URLError, OSError) as e:
        log(f"couldn't send the logs of {name}: {e}")


def logs_loop():
    """Waits on Sentry Lens for logs a page asks for - each answered on a thread of its own."""
    while True:
        try:
            ask = lens("GET", f"/api/docker-agent/logs/wait?version={VERSION}", timeout=60).get("ask")
        except urllib.error.HTTPError as e:
            time.sleep(600 if e.code == 404 else POLL)  # 404: a Sentry Lens without logs yet
            continue
        except (urllib.error.URLError, OSError, ValueError):
            time.sleep(POLL)
            continue
        if ask:
            threading.Thread(target=answer_logs, args=(ask,), daemon=True).start()


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
        lens("POST", f"/api/docker-agent/jobs/{q(str(j.get('id', '')))}", {"ok": r["ok"], "log": r["log"][-LOG_MAX:], "retry": r.get("retry", False)})
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
    t = threading.Thread(target=lambda: box.update(zip(("ok", "log", "retry"), execute(j))), daemon=True)
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
    state = {"job": j, "result": {"ok": bool(box.get("ok")), "log": box.get("log", ""), "retry": bool(box.get("retry"))}}
    keep(state)
    send_result(state)
    if j.get("kind") in JOBS:
        try:
            refresh_meta(df=j.get("kind") in ("delete_images", "delete_volumes"))
        except (OSError, subprocess.TimeoutExpired) as e:
            log(f"couldn't refresh docker-meta: {e}")
    if j.get("kind") == "update" and box.get("ok"):
        report_updates()


def main():
    if not (URL and HOST and KEY):
        sys.exit("SENTRY_URL, AGENT_HOST and AGENT_KEY are needed (/etc/docker-agent.env)")
    log(f"docker-agent {VERSION} for {HOST} -> {URL}")
    threading.Thread(target=logs_loop, daemon=True).start()
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
