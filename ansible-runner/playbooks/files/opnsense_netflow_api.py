#!/usr/bin/env python3
"""OPNsense side of playbooks/opnsense_netflow.yml: the firewall's NetFlow
export (Reporting > NetFlow), through the OPNsense API as root - same web
session as opnsense_pia_api.py. Run on the controller; prints one JSON line.

Settings come from the environment (the playbook passes them, no_log):
    OPN_URL, OPN_USER, OPN_PASS        firewall web UI + root login
    NETFLOW_PARAMS                     JSON: interfaces, egress_only, targets,
                                       version, active_timeout, inactive_timeout
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from opnsense_pia_api import Session  # noqa: E402

BASE = "/api/diagnostics/netflow"


def selected(field):
    """OPNsense option list -> sorted list of the selected keys."""
    return sorted(k for k, v in field.items() if v.get("selected"))


def main():
    p = json.loads(os.environ["NETFLOW_PARAMS"])
    s = Session()
    cur = s.call("GET", f"{BASE}/getconfig").get("netflow")
    if not cur:
        print(json.dumps({"failed": True, "msg": "NetFlow settings not readable through the API"}))
        sys.exit(1)
    unknown = [i for i in p["interfaces"] + p["egress_only"] if i not in cur["capture"]["interfaces"]]
    if unknown:
        print(json.dumps({"failed": True, "msg": f"unknown interfaces {unknown} - the firewall has "
                                                 f"{sorted(cur['capture']['interfaces'])}"}))
        sys.exit(1)

    before = {
        "interfaces": selected(cur["capture"]["interfaces"]),
        "egress_only": selected(cur["capture"]["egress_only"]),
        "targets": selected(cur["capture"]["targets"]),
        "version": selected(cur["capture"]["version"])[0],
        "active_timeout": int(cur["activeTimeout"]),
        "inactive_timeout": int(cur["inactiveTimeout"]),
    }
    after = {
        "interfaces": sorted(p["interfaces"]),
        "egress_only": sorted(p["egress_only"]),
        "targets": sorted(p["targets"]),
        "version": p["version"],
        "active_timeout": int(p["active_timeout"]),
        "inactive_timeout": int(p["inactive_timeout"]),
    }
    if before == after:
        print(json.dumps({"changed": False, "config": after, "status": s.call("GET", f"{BASE}/status")}))
        return

    out = s.call("POST", f"{BASE}/setconfig", {"netflow": {
        "capture": {
            "interfaces": ",".join(after["interfaces"]),
            "egress_only": ",".join(after["egress_only"]),
            "targets": ",".join(after["targets"]),
            "version": after["version"],
        },
        "activeTimeout": str(after["active_timeout"]),
        "inactiveTimeout": str(after["inactive_timeout"]),
    }})
    if out.get("result") != "saved":
        print(json.dumps({"failed": True, "msg": f"setconfig: {out}"}))
        sys.exit(1)
    s.call("POST", f"{BASE}/reconfigure", {})
    print(json.dumps({"changed": True, "before": before, "config": after,
                      "status": s.call("GET", f"{BASE}/status")}))


if __name__ == "__main__":
    main()
