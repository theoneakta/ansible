#!/usr/bin/env python3
"""OPNsense side of playbooks/opnsense_geoblock.yml: country blocking through
the OPNsense API as root - same web session as opnsense_pia_api.py. Run on
the controller; prints one JSON line.

  GeoBlock         GeoIP alias of the countries (IPv4 + IPv6), from the
                   GeoLite2 database set in Firewall > Aliases > GeoIP settings
  GeoBlock_Exempt  LAN hosts the outbound rule leaves alone (only while not empty)
  rules            LAN -> GeoBlock rejected (fails fast), GeoBlock -> each
                   inbound interface blocked; logged, sequences 3.., before the
                   PIA route rule (it passes PIA_Hosts with "quick", so a later
                   rule never sees them) - moved to 10/11 here if it's lower

Settings come from the environment (the playbook passes them, no_log):
    OPN_URL, OPN_USER, OPN_PASS        firewall web UI + root login
    GEOBLOCK_PARAMS                    JSON: state, countries, outbound, exempt,
                                       inbound_interfaces
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from opnsense_pia_api import LOG, D_KILL, D_ROUTE, Session, delete, fail, log, saved, upsert  # noqa: E402

ALIAS, EXEMPT = "GeoBlock", "GeoBlock_Exempt"
D_OUT = "GeoBlock: reject LAN to blocked countries (ansible-runner)"
D_IN = "GeoBlock: block {iface} from blocked countries (ansible-runner)"
FIRST = 3  # our sequences: 3 (outbound), 4.. (inbound); the PIA rules go to 10/11


def ours(r):
    return r.get("description", "").startswith("GeoBlock: ")


def main():
    p = json.loads(os.environ["GEOBLOCK_PARAMS"])
    s = Session()
    filt, aliases = "/api/firewall/filter", "/api/firewall/alias"

    if p["state"] == "absent":
        for r in s.search(f"{filt}/search_rule"):
            if ours(r):
                delete(s, filt, "description", r["description"])
        s.call("POST", f"{filt}/apply", {})
        for name in (ALIAS, EXEMPT):
            delete(s, aliases, "name", name, search="search_item", delp="del_item")
        s.call("POST", f"{aliases}/reconfigure", {})
        print(json.dumps({"changed": bool(LOG), "log": LOG}))
        return

    geo = s.call("GET", f"{aliases}/get_geo_ip").get("alias", {}).get("geoip", {})
    if not int(geo.get("address_count") or 0):
        fail("no GeoIP database on the firewall - set the GeoLite2 URL in Firewall > Aliases > GeoIP settings first")

    # Aliases.
    upsert(s, aliases, "alias", "name", ALIAS, {
        "enabled": "1", "name": ALIAS, "type": "geoip", "proto": "IPv4,IPv6", "content": "\n".join(p["countries"]),
        "description": "Countries blocked in and out (managed by ansible-runner, opnsense_geoblock.yml)"},
        search="search_item", add="add_item", setp="set_item")
    if p["exempt"]:
        upsert(s, aliases, "alias", "name", EXEMPT, {
            "enabled": "1", "name": EXEMPT, "type": "host", "content": "\n".join(p["exempt"]),
            "description": "LAN hosts allowed to reach the GeoBlock countries (managed by ansible-runner)"},
            search="search_item", add="add_item", setp="set_item")
    s.call("POST", f"{aliases}/reconfigure", {})

    # The PIA rules must come after ours.
    for r in s.search(f"{filt}/search_rule"):
        want = {D_ROUTE: "10", D_KILL: "11"}.get(r.get("description"))
        if want and int(r.get("sequence") or 0) < int(want):
            saved(s.call("POST", f"{filt}/set_rule/{r['uuid']}", {"rule": {"sequence": want}}), "renumber PIA rule")
            log(f"moved '{r['description']}' to sequence {want}, after the GeoBlock rules")

    # Rules.
    wanted = set()
    if p["outbound"]:
        wanted.add(D_OUT)
        upsert(s, filt, "rule", "description", D_OUT, {
            "enabled": "1", "sequence": str(FIRST), "action": "reject", "quick": "1", "interface": "lan",
            "direction": "in", "ipprotocol": "inet46", "protocol": "any",
            "source_net": EXEMPT if p["exempt"] else "any", "source_not": "1" if p["exempt"] else "0",
            "destination_net": ALIAS, "destination_not": "0", "log": "1", "description": D_OUT})
    for i, iface in enumerate(p["inbound_interfaces"]):
        desc = D_IN.format(iface=iface)
        wanted.add(desc)
        upsert(s, filt, "rule", "description", desc, {
            "enabled": "1", "sequence": str(FIRST + 1 + i), "action": "block", "quick": "1", "interface": iface,
            "direction": "in", "ipprotocol": "inet46", "protocol": "any", "source_net": ALIAS, "source_not": "0",
            "destination_net": "any", "destination_not": "0", "log": "1", "description": desc})
    for r in s.search(f"{filt}/search_rule"):
        if ours(r) and r["description"] not in wanted:
            delete(s, filt, "description", r["description"])
    if not p["exempt"]:
        delete(s, aliases, "name", EXEMPT, search="search_item", delp="del_item")
        s.call("POST", f"{aliases}/reconfigure", {})
    s.call("POST", f"{filt}/apply", {})

    # What the alias resolved to, and our rules as the firewall now has them.
    size = s.call("GET", f"/api/firewall/alias_util/list/{ALIAS}")
    rules = [{k: r.get(k) for k in ("sequence", "action", "interface", "direction", "source_net", "source_not",
                                    "destination_net", "description")}
             for r in s.search(f"{filt}/search_rule") if ours(r) or r.get("description") in (D_ROUTE, D_KILL)]
    print(json.dumps({"changed": bool(LOG), "log": LOG, "alias_entries": size.get("total", size.get("rowCount")),
                      "database": {"addresses": geo.get("address_count"), "updated": geo.get("timestamp")},
                      "rules": sorted(rules, key=lambda r: int(r.get("sequence") or 0))}))


if __name__ == "__main__":
    main()
