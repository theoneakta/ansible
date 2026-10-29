#!/usr/bin/env python3
"""OPNsense side of playbooks/netview_stack.yml: netview's own API user, through
the OPNsense API as root - same web session as opnsense_pia_api.py. Run on
the controller; prints one JSON line.

The user can only read the DNS overview (Unbound's query log) and the live
traffic counters - no login page, no settings. A key is made only when asked (NETVIEW_NEED_KEY=1: the
collector has none); the user's old keys are deleted first, so there is only
ever the one in use.

Settings come from the environment (the playbook passes them, no_log):
    OPN_URL, OPN_USER, OPN_PASS        firewall web UI + root login
    NETVIEW_NEED_KEY                   1 to (re)create the API key
    NETVIEW_IDS                        1: also Services: Intrusion Detection (ids.py reads
                                       Suricata's alerts - OPNsense has no read-only
                                       privilege for them, so it can change IDS settings too)
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from opnsense_pia_api import Session, fail, log, saved, LOG  # noqa: E402

API_USER = "netview"
# Status: DNS Overview = api/unbound/overview* (dns.py),
# Reporting: Traffic = api/diagnostics/traffic/* (live.py) - both read-only.
API_PRIVS = ["page-status-dnsoverview", "page-status-trafficgraph"]
if os.environ.get("NETVIEW_IDS") == "1":
    API_PRIVS.append("page-services-ids")  # api/ids/service/queryAlerts (ids.py)


def main():
    s = Session()
    changed = False
    user = next((u for u in s.search("/api/auth/user/search") if u.get("name") == API_USER), None)
    if not user:
        saved(s.call("POST", "/api/auth/user/add", {"user": {
            "name": API_USER, "scrambled_password": "1", "priv": ",".join(API_PRIVS),
            "descr": "netview - API only, read-only DNS overview and traffic, managed by ansible-runner"}}),
            "add netview user")
        log("added user netview")
        changed = True
    else:
        priv = s.call("GET", f"/api/auth/user/get/{user['uuid']}").get("user", {}).get("priv", {})
        have = sorted(k for k, v in priv.items() if isinstance(v, dict) and v.get("selected"))
        if have != sorted(API_PRIVS):
            saved(s.call("POST", f"/api/auth/user/set/{user['uuid']}", {"user": {"priv": ",".join(API_PRIVS)}}),
                  "set netview privileges")
            log(f"netview privileges: {have} -> {sorted(API_PRIVS)}")
            changed = True
    result = {"changed": changed, "log": LOG}
    if os.environ.get("NETVIEW_NEED_KEY") == "1":
        for k in s.search("/api/auth/user/search_api_key"):
            if k.get("username") == API_USER:
                s.call("POST", f"/api/auth/user/del_api_key/{k['id']}", {})
                log("deleted an old netview key")
        out = s.call("POST", f"/api/auth/user/add_api_key/{API_USER}", {})
        if not out.get("key"):
            fail(f"creating the netview key: {out.get('result')}")
        log("created an API key for netview")
        result.update(changed=True, key=out["key"], secret=out["secret"])
    print(json.dumps(result))


if __name__ == "__main__":
    main()
