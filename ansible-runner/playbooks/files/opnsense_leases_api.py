#!/usr/bin/env python3
"""OPNsense side of playbooks/netview_stack.yml: the firewall's DHCP leases
and reservations, and the tailnet's devices, read through the OPNsense API as
root - same web session as opnsense_pia_api.py. Read-only. Run on the
controller; prints one JSON line:
    {"names": {"192.168.3.17": {"name": "pc01", "mac": "..", "source": "kea"}},
     "sources": {"kea": 12, ...}}

Whichever DHCP server the firewall runs (Kea, dnsmasq, ISC) answers; the
others return nothing. A reservation's name wins over its lease's.

Settings come from the environment (the playbook passes them, no_log):
    OPN_URL, OPN_USER, OPN_PASS        firewall web UI + root login
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from opnsense_pia_api import Session  # noqa: E402

# (source, search path, address field, MAC field, name fields - first non-empty wins)
LEASES = [
    ("kea", "/api/kea/leases4/search", "address", "hwaddr", ["hostname"]),
    ("dnsmasq", "/api/dnsmasq/leases/search", "address", "hwaddr", ["hostname"]),
    ("isc", "/api/dhcpv4/leases/searchLease", "address", "mac", ["hostname", "descr"]),
]
RESERVATIONS = [
    ("kea", "/api/kea/dhcpv4/searchReservation", "ip_address", "hw_address", ["hostname", "description"]),
    ("dnsmasq", "/api/dnsmasq/settings/searchHost", "ip", "hwaddr", ["host", "descr"]),
]


def collect(s, specs, names, counts):
    for source, path, addr_f, mac_f, name_fs in specs:
        try:
            rows = s.search(path)
        except Exception:  # endpoint missing on this firewall - not its DHCP server
            continue
        for row in rows:
            ip = str(row.get(addr_f) or "").strip()
            name = next((str(row[f]).strip() for f in name_fs if str(row.get(f) or "").strip()), "")
            if not ip or not name:
                continue
            names[ip] = {"name": name.rstrip("."), "mac": str(row.get(mac_f) or "").lower(), "source": source}
            counts[source] = counts.get(source, 0) + 1


def tailnet(s, names, counts):
    """The tailnet's devices (the firewall's Tailscale status): hostname by
    100.x address, the firewall's own included - and by the real addresses
    their tunnels come from (CurAddr / Addrs), so a VPS's public IP or a LAN
    device without a DHCP lease gets its tailnet name. Those never replace a
    DHCP name."""
    st = s.call("GET", "/api/tailscale/status/status")
    nodes = [st.get("Self") or {}] + list((st.get("Peer") or {}).values())
    for i, node in enumerate(nodes):
        name = (node.get("HostName") or (node.get("DNSName") or "").split(".")[0]).strip()
        if not name:
            continue
        for ip in node.get("TailscaleIPs") or []:
            if ":" not in ip:
                names[ip] = {"name": f"{name} (tailscale)" if i == 0 else name, "mac": "", "source": "tailscale"}
                counts["tailscale"] = counts.get("tailscale", 0) + 1
        if i == 0:
            continue  # the firewall's own endpoints are its WAN/LAN addresses
        endpoints = [node.get("CurAddr") or ""] + list(node.get("Addrs") or [])
        for ep in endpoints:
            ip = ep.rsplit(":", 1)[0] if ep.count(":") == 1 else ""  # IPv4 "ip:port" only
            if ip and ip not in names:
                names[ip] = {"name": name, "mac": "", "source": "tailscale endpoint"}
                counts["tailscale endpoint"] = counts.get("tailscale endpoint", 0) + 1


def main():
    s = Session()
    names, counts = {}, {}
    collect(s, LEASES, names, counts)
    collect(s, RESERVATIONS, names, counts)
    tailnet(s, names, counts)  # no Tailscale plugin: an error payload, no nodes
    print(json.dumps({"names": names, "sources": counts}))


if __name__ == "__main__":
    main()
