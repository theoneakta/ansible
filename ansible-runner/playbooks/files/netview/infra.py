"""Sentry Lens: the Infrastructure section - servers, hypervisors and their
Docker containers, read from Prometheus (PROM_URL, prometheus_stack.yml),
which scrapes node_exporter on each host (node_exporter.yml) and cAdvisor on
the Docker hosts (cadvisor.yml).

Every host is a target of the "node" job with the labels the playbook gives
it (host, role); its containers come from the "cadvisor" job under the same
host label, one series set per container (cAdvisor's "name"). The views ask
Prometheus for the current figures of all of them at once, and for one
host's or container's history. A host or container in a URL is matched
against what Prometheus reports - nothing a browser sends goes into a query
as such.
"""
import json
import os
import re
import time

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import FileResponse

import auth
import checks  # its ClickHouse helpers: the tags live in netview.tags

PROM_URL = os.environ.get("PROM_URL", "").rstrip("/")
STATIC = os.path.join(os.path.dirname(__file__), "static")
status = {"enabled": bool(PROM_URL)}

# Real filesystems, and the physical / host-facing network interfaces (not
# Docker's, the VMs' taps, Proxmox's firewall bridges, Tailscale, loopback).
FS = 'fstype!~"tmpfs|overlay|squashfs|ramfs|devtmpfs|nsfs|autofs|fuse.*|efivarfs|tracefs"'
NIC = 'device!~"lo|veth.*|docker.*|br-.*|tap.*|fwpr.*|fwbr.*|fwln.*|tailscale.*|virbr.*|cni.*|flannel.*"'
CT = 'job="cadvisor",name!=""'  # a container's series (cAdvisor also reports the cgroups around them)

router = APIRouter()


def prom(query, **params):
    """One PromQL query - instant, or a range given start/end/step."""
    if not PROM_URL:
        raise HTTPException(404, "Prometheus isn't set up (prometheus_stack.yml)")
    path = "query_range" if "step" in params else "query"
    try:
        r = requests.get(f"{PROM_URL}/api/v1/{path}", params={"query": query, **params}, timeout=30)
        body = r.json()
    except (requests.RequestException, ValueError) as e:
        raise HTTPException(502, f"Prometheus: {e}")
    if body.get("status") != "success":
        raise HTTPException(502, f"Prometheus: {body.get('error', '')[:200]}")
    return body["data"]["result"]


def by(query, *labels):
    """{(label values): value} of an instant query."""
    return {tuple(r["metric"].get(k, "") for k in labels): float(r["value"][1]) for r in prom(query)}


def targets():
    """The node targets: {host: {host, instance, role, up}}."""
    return {r["metric"]["host"]: {"host": r["metric"]["host"], "instance": r["metric"]["instance"],
                                  "role": r["metric"].get("role", "server"), "up": r["value"][1] == "1"}
            for r in prom('up{job="node"}') if r["metric"].get("host")}


@router.get("/infra")
def infra_page():
    return FileResponse(os.path.join(STATIC, "infra.html"))


@router.get("/api/infra")
def hosts():
    """Every host now: CPU, memory, disks, network, uptime, failed services, containers."""
    t = targets()
    q = {
        "cpu": '100 * (1 - avg by (host) (rate(node_cpu_seconds_total{mode="idle"}[5m])))',
        "cores": 'count by (host) (node_cpu_seconds_total{mode="idle"})',
        "load1": "node_load1",
        "mem": "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)",
        "mem_total": "node_memory_MemTotal_bytes",
        "root": f'100 * (1 - node_filesystem_avail_bytes{{mountpoint="/",{FS}}} / node_filesystem_size_bytes{{mountpoint="/",{FS}}})',
        "disk_max": f"max by (host) (100 * (1 - node_filesystem_avail_bytes{{{FS}}} / node_filesystem_size_bytes{{{FS}}}))",
        "rx": f"sum by (host) (rate(node_network_receive_bytes_total{{{NIC}}}[5m])) * 8",
        "tx": f"sum by (host) (rate(node_network_transmit_bytes_total{{{NIC}}}[5m])) * 8",
        "boot": "node_boot_time_seconds",
        "failed": 'sum by (host) (node_systemd_unit_state{state="failed"})',
        "containers": f"count by (host) (container_last_seen{{{CT}}})",
    }
    vals = {k: by(v, "host") for k, v in q.items()}
    info = {r["metric"].get("host"): r["metric"] for r in prom("node_uname_info")}
    osn = {r["metric"].get("host"): r["metric"].get("pretty_name", "") for r in prom("node_os_info")}
    now = time.time()
    out = []
    for name, h in t.items():
        v = {k: vals[k].get((name,)) for k in q}
        out.append(h | v | {"uptime": now - v["boot"] if v["boot"] else None, "hostname": info.get(name, {}).get("nodename", ""),
                            "kernel": info.get(name, {}).get("release", ""), "os": osn.get(name, "")})
    out.sort(key=lambda h: (h["role"] != "hypervisor", h["host"]))
    up = [h for h in out if h["up"]]
    avg = lambda k: sum(h[k] for h in up if h[k] is not None) / max(1, sum(1 for h in up if h[k] is not None))
    return {"hosts": out, "summary": {"total": len(out), "up": len(up), "cpu": avg("cpu"), "mem": avg("mem"),
                                      "failed": sum(int(h["failed"] or 0) for h in up),
                                      "disk_warn": sum(1 for h in up if (h["disk_max"] or 0) >= 85),
                                      "containers": sum(int(h["containers"] or 0) for h in out)}}



# ------------------------------------------------------------------ Docker
# Two sources: cAdvisor (job "cadvisor": what a running container uses) and
# docker-meta (node_exporter's textfile, job "node": what Docker knows - every
# container, running or not, with its mounts, networks, ports; volumes,
# networks, images). Containers are keyed (host, name) in both.
DM = 'job="node"'


def _rows(query, *labels):
    return [{**{k: r["metric"].get(k, "") for k in labels}, "v": float(r["value"][1])} for r in prom(query)]


def docker_state(host=""):
    """Everything docker-meta reports (one host's, or all), as dicts."""
    hs = f',host="{host}"' if host else ""
    info = {(r["host"], r["container"]): r for r in _rows(
        f"docker_container_info{{{DM}{hs}}}", "host", "container", "image", "state", "health", "compose_project",
        "compose_service", "restart_policy", "network_mode", "id")}
    num = {}
    for m in ("restart_count", "started_seconds", "finished_seconds", "exit_code", "oom_killed", "memory_limit_bytes",
              "cpu_limit", "rw_bytes"):
        for r in _rows(f"docker_container_{m}{{{DM}{hs}}}", "host", "container"):
            num.setdefault((r["host"], r["container"]), {})[m] = r["v"]
    mounts, nets, ports = {}, {}, {}
    for r in _rows(f"docker_container_mount_info{{{DM}{hs}}}", "host", "container", "type", "source", "destination", "mode"):
        mounts.setdefault((r["host"], r["container"]), []).append({k: r[k] for k in ("type", "source", "destination", "mode")})
    for r in _rows(f"docker_container_network_info{{{DM}{hs}}}", "host", "container", "network", "ip"):
        nets.setdefault((r["host"], r["container"]), []).append({"network": r["network"], "ip": r["ip"]})
    for r in _rows(f"docker_container_port_info{{{DM}{hs}}}", "host", "container", "private_port", "public_port", "proto", "host_ip"):
        ports.setdefault((r["host"], r["container"]), []).append({k: r[k] for k in ("private_port", "public_port", "proto", "host_ip")})
    return info, num, mounts, nets, ports


def usage(host=""):
    """cAdvisor: what each running container uses now, {(host, name): {...}}."""
    sel = CT + (f',host="{host}"' if host else "")
    q = {
        "cpu": f"sum by (host, name) (rate(container_cpu_usage_seconds_total{{{sel}}}[5m])) * 100",
        "mem": f"sum by (host, name) (container_memory_working_set_bytes{{{sel}}})",
        "rx": f"sum by (host, name) (rate(container_network_receive_bytes_total{{{sel}}}[5m])) * 8",
        "tx": f"sum by (host, name) (rate(container_network_transmit_bytes_total{{{sel}}}[5m])) * 8",
        "read": f"sum by (host, name) (rate(container_fs_reads_bytes_total{{{sel}}}[5m]))",
        "write": f"sum by (host, name) (rate(container_fs_writes_bytes_total{{{sel}}}[5m]))",
    }
    out = {}
    for f, v in q.items():
        for k, x in by(v, "host", "name").items():
            out.setdefault(k, {})[f] = x
    return out


def tags_for(kind):
    try:
        return {r["key"]: r["tags"] for r in checks.query(
            "SELECT key, tags FROM netview.tags FINAL WHERE kind = {kind:String} AND length(tags) > 0", kind=kind)}
    except Exception:  # noqa: BLE001 - the table isn't there before the first tag
        return {}


def container_row(key, i, n, mounts, nets, ports, use, tags):
    """One container: Docker's view, what it uses (when running), its tags."""
    now = time.time()
    u = use.get(key, {})
    n = n or {}
    vols = [m for m in mounts.get(key, []) if m["type"] == "volume"]
    binds = [m for m in mounts.get(key, []) if m["type"] == "bind"]
    return {"host": key[0], "name": key[1], "image": i.get("image", ""), "id": i.get("id", ""), "state": i.get("state", ""),
            "health": i.get("health", "none"), "project": i.get("compose_project", ""), "service": i.get("compose_service", ""),
            "restart_policy": i.get("restart_policy", ""), "network_mode": i.get("network_mode", ""),
            "restarts": int(n.get("restart_count", 0)), "exit_code": int(n.get("exit_code", 0)), "oom": bool(n.get("oom_killed")),
            "uptime": now - n["started_seconds"] if i.get("state") == "running" and n.get("started_seconds") else None,
            "stopped_since": n.get("finished_seconds") or None if i.get("state") != "running" else None,
            "limit": n.get("memory_limit_bytes") or None, "cpu_limit": n.get("cpu_limit") or None, "rw": n.get("rw_bytes"),
            "volumes": len(vols), "binds": len(binds), "networks": nets.get(key, []), "ports": ports.get(key, []),
            "tags": tags.get(f"{key[0]}/{key[1]}", []), **{f: u.get(f) for f in ("cpu", "mem", "rx", "tx", "read", "write")}}


@router.get("/api/infra/containers")
def containers(host: str = ""):
    """Every container (or one host's), running or not: state, health,
    restarts, Compose project, what it uses, its volumes, networks, ports, tags."""
    if host and host not in targets():
        raise HTTPException(404, "no such host")
    info, num, mounts, nets, ports = docker_state(host)
    use, tags = usage(host), tags_for("container")
    rows = [container_row(k, i, num.get(k), mounts, nets, ports, use, tags) for k, i in info.items()]
    # A running container cAdvisor sees but docker-meta hasn't reported yet.
    for k, u in use.items():
        if k not in info:
            rows.append(container_row(k, {"state": "running"}, None, mounts, nets, ports, use, tags))
    rows.sort(key=lambda r: (r["host"], r["name"]))
    return {"containers": rows, "cores": {h: c for (h,), c in by('count by (host) (node_cpu_seconds_total{mode="idle"})', "host").items()}}


RANGES = {1: 30, 6: 60, 24: 300, 168: 1800}  # hours -> step (seconds), ~200-300 points


def window(hours):
    if hours not in RANGES:
        raise HTTPException(400, f"hours is one of {list(RANGES)}")
    end = time.time()
    return {"start": end - hours * 3600, "end": end, "step": RANGES[hours]}


def series(query, rng):
    res = prom(query, **rng)
    return [[float(x), float(y)] for x, y in res[0]["values"]] if res else []


def known_container(host, name):
    known = {(r["metric"].get("host"), r["metric"].get("container")) for r in prom(f"docker_container_info{{{DM}}}")}
    known |= {(r["metric"].get("host"), r["metric"].get("name")) for r in prom(f"container_last_seen{{{CT}}}")}
    if (host, name) not in known:
        raise HTTPException(404, "no such container")


@router.get("/api/infra/container/{host}/{name}")
def container(host: str, name: str, hours: int = 6):
    """One container: Docker's view of it (mounts with volume sizes, networks,
    ports), and CPU, memory, network and disk I/O over the last hours."""
    known_container(host, name)
    key = (host, name)
    info, num, mounts, nets, ports = docker_state(host)
    row = container_row(key, info.get(key, {"state": "running"}), num.get(key), mounts, nets, ports, usage(host),
                        tags_for("container"))
    sizes = {r["volume"]: r["v"] for r in _rows(f'docker_volume_size_bytes{{{DM},host="{host}"}}', "volume")}
    row["mounts"] = [m | {"size": sizes.get(m["source"]) if m["type"] == "volume" else None} for m in mounts.get(key, [])]
    sel = f'{CT},host="{host}",name="{name}"'  # both checked against what Prometheus reports
    rng = window(hours)
    return row | {"hours": hours,
                  "cpu_series": series(f"sum(rate(container_cpu_usage_seconds_total{{{sel}}}[5m])) * 100", rng),
                  "mem_series": series(f"sum(container_memory_working_set_bytes{{{sel}}})", rng),
                  "rx_series": series(f"sum(rate(container_network_receive_bytes_total{{{sel}}}[5m])) * 8", rng),
                  "tx_series": series(f"sum(rate(container_network_transmit_bytes_total{{{sel}}}[5m])) * 8", rng),
                  "read_series": series(f"sum(rate(container_fs_reads_bytes_total{{{sel}}}[5m]))", rng),
                  "write_series": series(f"sum(rate(container_fs_writes_bytes_total{{{sel}}}[5m]))", rng),
                  "restart_series": series(f'max(docker_container_restart_count{{{DM},host="{host}",container="{name}"}})', rng)}


@router.get("/api/infra/docker")
def docker_overview(hours: int = 6, host: str = ""):
    """Graphs across containers: memory and CPU over time (the top 7, the rest
    summed), and Docker's disk use per host."""
    if host and host not in targets():
        raise HTTPException(404, "no such host")
    rng = window(hours)
    sel = CT + (f',host="{host}"' if host else "")

    def stack(expr):
        """expr(selector) per container: the 7 with the highest average over the
        window (their names come from Prometheus), and the total."""
        top = [(r["metric"].get("host", ""), r["metric"].get("name", ""))
               for r in prom(f"topk(7, avg_over_time(({expr(sel)})[{hours}h:{RANGES[hours]}s]))")]
        out = [{"key": f"{h}/{n}", "host": h, "name": n, "values": series(expr(f'{CT},host="{h}",name="{n}"'), rng)}
               for h, n in top]
        return {"top": out, "total": series(f"sum({expr(sel)})", rng)}

    mem = stack(lambda s: f"sum by (host, name) (container_memory_working_set_bytes{{{s}}})")
    cpu = stack(lambda s: f"sum by (host, name) (rate(container_cpu_usage_seconds_total{{{s}}}[5m])) * 100")
    disk = {}
    for r in _rows(f"docker_disk_bytes{{{DM}" + (f',host="{host}"' if host else "") + "}", "host", "kind"):
        disk.setdefault(r["host"], {})[r["kind"]] = r["v"]
    states = {}
    for r in _rows(f"docker_containers{{{DM}" + (f',host="{host}"' if host else "") + "}", "host", "state"):
        if r["v"]:
            states.setdefault(r["host"], {})[r["state"]] = int(r["v"])
    return {"hours": hours, "memory": mem, "cpu": cpu, "disk": disk, "states": states}


@router.get("/api/infra/volumes")
def volumes(hours: int = 168):
    """Every volume with its size and the containers using it, and every host folder mounted into one."""
    info = _rows(f"docker_volume_info{{{DM}}}", "host", "volume", "driver", "mountpoint", "compose_project")
    sizes = {(r["host"], r["volume"]): r["v"] for r in _rows(f"docker_volume_size_bytes{{{DM}}}", "host", "volume")}
    users, binds = {}, {}
    for r in _rows(f"docker_container_mount_info{{{DM}}}", "host", "container", "type", "source", "destination", "mode"):
        if r["type"] == "volume":
            users.setdefault((r["host"], r["source"]), []).append({"container": r["container"], "destination": r["destination"], "mode": r["mode"]})
        elif r["type"] == "bind":
            binds.setdefault((r["host"], r["source"]), []).append({"container": r["container"], "destination": r["destination"], "mode": r["mode"]})
    tags = tags_for("volume")
    vols = [{"host": r["host"], "volume": r["volume"], "driver": r["driver"], "project": r["compose_project"],
             "size": sizes.get((r["host"], r["volume"])), "containers": users.get((r["host"], r["volume"]), []),
             "tags": tags.get(f'{r["host"]}/{r["volume"]}', [])} for r in info]
    # Growth: each volume over the last day (a sparkline), and every host's total over the window.
    day = window(24)
    spark = {(r["metric"].get("host"), r["metric"].get("volume")): [float(v) for _, v in r["values"]]
             for r in prom(f"docker_volume_size_bytes{{{DM}}}", **day)}
    for v in vols:
        s = spark.get((v["host"], v["volume"]), [])
        v["spark"] = s
        v["growth_24h"] = (s[-1] - s[0]) if len(s) > 1 else None
    rng = window(hours)
    by_host = [{"host": r["metric"].get("host", ""), "values": [[float(t), float(x)] for t, x in r["values"]]}
               for r in prom(f"sum by (host) (docker_volume_size_bytes{{{DM}}})", **rng)]
    vols.sort(key=lambda v: -(v["size"] or 0))
    return {"volumes": vols, "history": by_host, "hours": hours,
            "binds": sorted(({"host": h, "path": p, "containers": c} for (h, p), c in binds.items()),
                            key=lambda b: (b["host"], b["path"]))}


# A container's traffic, put on each Docker network it's on: cAdvisor's
# per-container rate joined to docker-meta's membership. A container on two
# networks counts on both - it's "traffic of the containers on the network".
NET_TRAFFIC = ('sum by (host, network) (label_replace(docker_container_network_info{{job="node",network!="host"}}, "name", "$1", "container", "(.*)")'
               ' * on (host, name) group_left () sum by (host, name) (rate(container_network_{dir}_bytes_total{{{ct}}}[5m]) * 8))')


@router.get("/api/infra/networks")
def networks(hours: int = 6):
    """Every Docker network with its subnet, the containers on it (and their
    addresses), its containers' traffic now and over the window."""
    rng = window(hours)
    info = _rows(f"docker_network_info{{{DM}}}", "host", "network", "driver", "scope", "subnet", "gateway", "internal")
    members = {}
    for r in _rows(f"docker_container_network_info{{{DM}}}", "host", "container", "network", "ip"):
        members.setdefault((r["host"], r["network"]), []).append({"container": r["container"], "ip": r["ip"]})
    now = {d: {(r["host"], r["network"]): r["v"] for r in _rows(NET_TRAFFIC.format(dir=d, ct=CT), "host", "network")}
           for d in ("receive", "transmit")}
    nets = [{k: r[k] for k in ("host", "network", "driver", "scope", "subnet", "gateway")} | {
        "internal": r["internal"] == "true", "containers": sorted(members.get((r["host"], r["network"]), []), key=lambda m: m["container"]),
        "rx": now["receive"].get((r["host"], r["network"])), "tx": now["transmit"].get((r["host"], r["network"]))}
        for r in info]
    nets.sort(key=lambda n: (n["host"], -len(n["containers"]), n["network"]))
    # Over time: in + out per network, the 7 busiest and the rest.
    both = f"({NET_TRAFFIC.format(dir='receive', ct=CT)} + {NET_TRAFFIC.format(dir='transmit', ct=CT)})"
    series_all = {(r["metric"].get("host"), r["metric"].get("network")): [[float(t), float(x)] for t, x in r["values"]]
                  for r in prom(both, **rng)}
    top = sorted(series_all, key=lambda k: -sum(x for _, x in series_all[k]))[:7]
    total = {}
    for vals in series_all.values():
        for t, x in vals:
            total[t] = total.get(t, 0) + x
    return {"networks": nets, "hours": hours,
            "traffic": {"top": [{"key": f"{h}/{n}", "host": h, "name": n, "values": series_all[(h, n)]} for h, n in top],
                        "total": sorted(total.items())}}


@router.get("/api/infra/images")
def images():
    """Every image and its size, in use or not."""
    rows = _rows(f"docker_image_size_bytes{{{DM}}}", "host", "image", "id", "in_use")
    return {"images": sorted(({"host": r["host"], "image": r["image"], "id": r["id"], "in_use": r["in_use"] == "true",
                               "size": r["v"]} for r in rows), key=lambda i: -i["size"])}


# ------------------------------------------------------------------ tags
TAG = re.compile(r"[a-z0-9][a-z0-9_.-]{0,23}")
TAG_KINDS = ("container", "volume", "host")


@router.get("/api/infra/tags")
def all_tags():
    return {k: tags_for(k) for k in TAG_KINDS}


@router.post("/api/infra/tags/{kind}")
async def set_tags(request: Request, kind: str):
    """An admin sets the tags of a container, a volume or a host: {key, tags}
    (key = host/name for containers and volumes, the host for hosts)."""
    if auth.ENABLED:
        auth.require_admin(request)
    if kind not in TAG_KINDS:
        raise HTTPException(404, f"kinds: {list(TAG_KINDS)}")
    body = await request.json()
    key, tags = str(body.get("key", "")), body.get("tags", [])
    if not isinstance(tags, list) or len(tags) > 10:
        raise HTTPException(400, "up to 10 tags")
    tags = sorted({str(t).strip().lower() for t in tags if str(t).strip()})
    bad = [t for t in tags if not TAG.fullmatch(t)]
    if bad:
        raise HTTPException(400, f"a tag is a short word: letters, digits, - _ . (not {bad[0]!r})")
    if not key or len(key) > 300:
        raise HTTPException(400, "a key")
    u = getattr(request.state, "user", None)
    checks.ch("""CREATE TABLE IF NOT EXISTS netview.tags (
        kind LowCardinality(String), key String, tags Array(String), by String, version UInt64
    ) ENGINE = ReplacingMergeTree(version) ORDER BY (kind, key)""")
    checks.ch("INSERT INTO netview.tags FORMAT JSONEachRow", json.dumps(
        {"kind": kind, "key": key, "tags": tags, "by": u["email"] if u else "local", "version": time.time_ns()}))
    return {"key": key, "tags": tags}


@router.get("/api/infra/host/{name}")
def host(name: str, hours: int = 6):
    """One host: CPU, memory and network over the last hours, its filesystems and failed services."""
    t = targets().get(name)
    if not t:
        raise HTTPException(404, "no such host")
    sel = f'host="{name}",job="node"'  # a host Prometheus reports, not the request's text
    rng = window(hours)
    fs = {}
    for r in prom(f"node_filesystem_size_bytes{{{sel},{FS}}}"):
        fs[r["metric"]["mountpoint"]] = {"mount": r["metric"]["mountpoint"], "device": r["metric"].get("device", ""),
                                         "fstype": r["metric"].get("fstype", ""), "size": float(r["value"][1])}
    for r in prom(f"node_filesystem_avail_bytes{{{sel},{FS}}}"):
        if r["metric"]["mountpoint"] in fs:
            fs[r["metric"]["mountpoint"]]["avail"] = float(r["value"][1])
    failed = [r["metric"].get("name", "") for r in prom(f'node_systemd_unit_state{{{sel},state="failed"}} == 1')]
    return t | {
        "hours": hours, "step": RANGES[hours],
        "cpu": series(f'100 * (1 - avg(rate(node_cpu_seconds_total{{{sel},mode="idle"}}[5m])))', rng),
        "mem": series(f"100 * (1 - sum(node_memory_MemAvailable_bytes{{{sel}}}) / sum(node_memory_MemTotal_bytes{{{sel}}}))", rng),
        "rx": series(f"sum(rate(node_network_receive_bytes_total{{{sel},{NIC}}}[5m])) * 8", rng),
        "tx": series(f"sum(rate(node_network_transmit_bytes_total{{{sel},{NIC}}}[5m])) * 8", rng),
        "load": series(f"max(node_load1{{{sel}}})", rng),
        "filesystems": sorted(fs.values(), key=lambda f: f["mount"]),
        "failed_units": sorted(failed),
        "services": int(sum(float(r["value"][1]) for r in prom(f'node_systemd_unit_state{{{sel},state="active"}}'))),
    }
