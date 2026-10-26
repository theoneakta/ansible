#!/usr/bin/env python3
"""docker-meta: Docker's own view of this host - containers (running or not),
their mounts, networks and ports, the volumes and their sizes, the networks,
the images - as Prometheus metrics in node_exporter's textfile directory, so
they reach Prometheus with the host's other metrics (no port, no API opened).

Run every minute by docker-meta.timer (cadvisor.yml). Reads the local Docker
socket only. Never reads or writes environment variables, commands or other
settings that can hold secrets: names, images, states, mounts, addresses,
sizes. Disk usage ("docker system df" - minutes on a host with big volumes)
is measured apart, by `docker-meta --df` every 15 minutes (docker-meta-df.timer)
into DF_CACHE, which the minute runs read.
"""
import calendar
import http.client
import json
import os
import socket
import sys
import time

SOCK = "/var/run/docker.sock"
OUT = "/var/lib/node_exporter/textfile/docker.prom"
DF_CACHE = "/var/lib/node_exporter/docker-df.json"
EMPTY_DF = {"images": [], "containers": {}, "volumes": {}, "build_cache": 0}


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, timeout):
        super().__init__("localhost", timeout=timeout)
        self._t = timeout

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self._t)
        self.sock.connect(SOCK)


def get(path, timeout=60):
    c = UnixHTTP(timeout)
    try:
        c.request("GET", path)
        r = c.getresponse()
        body = r.read()
    finally:
        c.close()
    if r.status != 200:
        raise RuntimeError(f"{path}: HTTP {r.status}")
    return json.loads(body)


def esc(v):
    return str(v if v is not None else "").replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


# name -> (help, [sample lines]): the text format wants each metric's samples together.
families = {}


def metric(name, help_text, labels, value):
    fam = families.setdefault(name, (help_text, []))
    lab = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
    fam[1].append(f"{name}{{{lab}}} {value}")


def ts(iso):
    """Docker's RFC 3339 time (UTC) -> epoch seconds (0 for 'never')."""
    if not iso or iso.startswith("0001-"):
        return 0
    try:
        return calendar.timegm(time.strptime(iso.split(".")[0].rstrip("Z"), "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return 0


def disk_usage():
    """The last `--df` measure (empty until there's one)."""
    try:
        with open(DF_CACHE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return EMPTY_DF


def measure_df():
    """`docker system df -v`: sizes of images, containers' writable layers, volumes - into DF_CACHE."""
    df = get("/system/df", timeout=900)
    keep = {
        "images": [{"id": i.get("Id"), "tags": i.get("RepoTags") or [], "size": i.get("Size", 0), "containers": i.get("Containers", 0)}
                   for i in df.get("Images") or []],
        "containers": {c["Id"]: {"rw": c.get("SizeRw", 0), "root": c.get("SizeRootFs", 0)} for c in df.get("Containers") or []},
        "volumes": {v["Name"]: {"size": (v.get("UsageData") or {}).get("Size", -1), "refs": (v.get("UsageData") or {}).get("RefCount", -1)}
                    for v in df.get("Volumes") or []},
        "build_cache": sum(b.get("Size", 0) for b in df.get("BuildCache") or []),
    }
    tmp = DF_CACHE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(keep, f)
    os.replace(tmp, DF_CACHE)


def main():
    info = get("/info")
    ver = get("/version")
    metric("docker_engine_info", "The Docker engine.", {"version": ver.get("Version"), "os": info.get("OperatingSystem"),
           "storage_driver": info.get("Driver"), "cgroup": info.get("CgroupVersion")}, 1)
    df = disk_usage()

    containers = get("/containers/json?all=1")
    states = {}
    for c in containers:
        d = get(f"/containers/{c['Id']}/json")
        name = (d.get("Name") or "").lstrip("/")
        st = d.get("State") or {}
        cfg = d.get("Config") or {}
        host_cfg = d.get("HostConfig") or {}
        labels = cfg.get("Labels") or {}
        state = st.get("Status", "unknown")
        states[state] = states.get(state, 0) + 1
        health = (st.get("Health") or {}).get("Status", "none")
        base = {"container": name}
        metric("docker_container_info", "A container: image, state, health, Compose project.", base | {
            "image": cfg.get("Image", ""), "image_id": (d.get("Image") or "")[7:19], "state": state, "health": health,
            "compose_project": labels.get("com.docker.compose.project", ""),
            "compose_service": labels.get("com.docker.compose.service", ""),
            "restart_policy": (host_cfg.get("RestartPolicy") or {}).get("Name", ""),
            "network_mode": host_cfg.get("NetworkMode", ""), "id": c["Id"][:12]}, 1)
        metric("docker_container_running", "1 when the container runs.", base, int(state == "running"))
        metric("docker_container_restart_count", "Restarts by Docker's restart policy.", base, d.get("RestartCount", 0))
        metric("docker_container_created_seconds", "When the container was created.", base, ts(d.get("Created")))
        metric("docker_container_started_seconds", "When it last started.", base, ts(st.get("StartedAt")))
        metric("docker_container_finished_seconds", "When it last stopped (0: never).", base, ts(st.get("FinishedAt")))
        metric("docker_container_exit_code", "Its last exit code.", base, st.get("ExitCode", 0))
        metric("docker_container_oom_killed", "1 when its last stop was the kernel's out-of-memory killer.", base, int(bool(st.get("OOMKilled"))))
        metric("docker_container_memory_limit_bytes", "Its memory limit (0: none).", base, host_cfg.get("Memory", 0) or 0)
        metric("docker_container_cpu_limit", "Its CPU limit in cores (0: none).", base, (host_cfg.get("NanoCpus") or 0) / 1e9)
        sizes = df["containers"].get(c["Id"])
        if sizes:
            metric("docker_container_rw_bytes", "Its writable layer.", base, sizes["rw"])
        for mnt in d.get("Mounts") or []:
            metric("docker_container_mount_info", "A mount: a volume, a host folder (bind) or memory (tmpfs).", base | {
                "type": mnt.get("Type", ""), "source": mnt.get("Name") or mnt.get("Source", ""),
                "destination": mnt.get("Destination", ""), "mode": "rw" if mnt.get("RW") else "ro"}, 1)
        for net, n in ((d.get("NetworkSettings") or {}).get("Networks") or {}).items():
            metric("docker_container_network_info", "A network the container is on, with its address.", base | {
                "network": net, "ip": n.get("IPAddress", ""), "mac": n.get("MacAddress", "")}, 1)
        for p in c.get("Ports") or []:
            metric("docker_container_port_info", "A port: the container's, and the host's it's published on.", base | {
                "private_port": p.get("PrivatePort", ""), "public_port": p.get("PublicPort", ""),
                "proto": p.get("Type", ""), "host_ip": p.get("IP", "")}, 1)
    for s in ("running", "exited", "paused", "restarting", "created", "dead"):
        metric("docker_containers", "Containers by state.", {"state": s}, states.get(s, 0))

    for v in (get("/volumes").get("Volumes") or []):
        u = df["volumes"].get(v["Name"], {})
        lab = {"volume": v["Name"]}
        metric("docker_volume_info", "A volume.", lab | {"driver": v.get("Driver", ""), "mountpoint": v.get("Mountpoint", ""),
               "compose_project": (v.get("Labels") or {}).get("com.docker.compose.project", "")}, 1)
        if u.get("size", -1) >= 0:
            metric("docker_volume_size_bytes", "A volume's size (refreshed every 15 min).", lab, u["size"])
            metric("docker_volume_containers", "Containers using the volume.", lab, u.get("refs", 0))

    for n in get("/networks"):
        cfgs = (n.get("IPAM") or {}).get("Config") or [{}]
        metric("docker_network_info", "A network.", {"network": n.get("Name", ""), "driver": n.get("Driver", ""),
               "scope": n.get("Scope", ""), "subnet": cfgs[0].get("Subnet", "") if cfgs else "",
               "gateway": cfgs[0].get("Gateway", "") if cfgs else "", "internal": str(bool(n.get("Internal"))).lower()}, 1)

    for i in df["images"]:
        for tag in i["tags"] or ["<none>"]:
            metric("docker_image_size_bytes", "An image's size.", {"image": tag, "id": (i["id"] or "")[7:19],
                   "in_use": str(i["containers"] > 0).lower()}, i["size"])
    for kind in ("images", "volumes", "build_cache"):
        total = (sum(i["size"] for i in df["images"]) if kind == "images" else
                 sum(max(v["size"], 0) for v in df["volumes"].values()) if kind == "volumes" else df["build_cache"])
        metric("docker_disk_bytes", "Docker's disk use by kind.", {"kind": kind}, total)
    metric("docker_disk_bytes", "Docker's disk use by kind.", {"kind": "containers"}, sum(c["rw"] for c in df["containers"].values()))
    metric("docker_meta_last_run_seconds", "When docker-meta last ran.", {}, int(time.time()))
    try:
        metric("docker_meta_df_seconds", "When the disk use was last measured.", {}, int(os.stat(DF_CACHE).st_mtime))
    except OSError:
        pass

    out = []
    for name, (help_text, samples) in families.items():
        out += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"] + samples
    tmp = OUT + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(out) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, OUT)


if __name__ == "__main__":
    measure_df() if "--df" in sys.argv else main()
