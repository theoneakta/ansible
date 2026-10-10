#!/usr/bin/env python3
"""OPNsense side of playbooks/opnsense_pia.yml - everything done through the
OPNsense API (as root, via a web session + CSRF token, the way the web UI
itself calls it). Run on the controller by the playbook; prints one JSON line.

    opnsense_pia_api.py apiuser | configure | remove | status

Settings come from the environment (the playbook passes them, no_log):
    OPN_URL, OPN_USER, OPN_PASS        firewall web UI + root login
    PIA_PARAMS                         JSON, see configure()

One VPN setup is managed, under fixed names - the same ones the hand-made
first setup used (October 2026), so applying adopts it instead of
duplicating it: aliases PIA_Hosts / PIA_Bypass, tag ar_pia, rule/NAT
descriptions starting "PIA", cron job "PIA WireGuard monitor (ansible-runner)".
"""
import json
import os
import re
import sys
import time
import warnings
from html.parser import HTMLParser

import requests

warnings.filterwarnings("ignore")

TAG = "ar_pia"
D_ROUTE = "PIA: route PIA_Hosts through the tunnel (ansible-runner)"
D_KILL = "PIA kill switch: never let PIA_Hosts traffic out the WAN (ansible-runner)"
D_DNS = "PIA: DNS of PIA_Hosts to PIA DNS through the tunnel (ansible-runner)"
D_CRON = "PIA WireGuard monitor (ansible-runner)"
API_USER = "WireguardAPI"
API_PRIVS = ("page-firewall-alias-edit,page-firewall-aliases,page-system-staticroutes,"
             "page-wireguard-config,page-wireguard-diagnostics")
PIA_DNS = "10.0.0.243"
LOG = []


def log(msg):
    LOG.append(msg)


# ------------------------------------------------------------------ session
class Session:
    def __init__(self):
        self.base = os.environ["OPN_URL"].rstrip("/")
        self.s = requests.Session()
        self.s.verify = False
        page = self.s.get(self.base + "/", timeout=30).text
        data = {"usernamefld": os.environ["OPN_USER"], "passwordfld": os.environ["OPN_PASS"], "login": "1"}
        m = re.search(r'<input type="hidden" name="([^"]+)" value="([^"]+)"', page)
        if m:
            data[m.group(1)] = m.group(2)
        page = self.s.post(self.base + "/", data=data, timeout=30).text
        tok = re.search(r'"X-CSRFToken",\s*"([^"]+)"', page) or \
            re.search(r'X-CSRFToken["\']?\s*[:,]\s*["\']([^"\']+)', page)
        if not tok:
            fail("OPNsense web login failed (check the firewall's per-host root login in the vault)")
        self.s.headers["X-CSRFToken"] = tok.group(1)

    def call(self, method, path, body=None):
        r = self.s.request(method, self.base + path, json=body, timeout=120)
        try:
            return r.json()
        except ValueError:
            return {"_status": r.status_code, "_text": r.text[:300]}

    def search(self, path):
        return self.call("POST", path, {"current": 1, "rowCount": 1000, "searchPhrase": ""}).get("rows", [])


def fail(msg):
    print(json.dumps({"failed": True, "msg": msg, "log": LOG}))
    sys.exit(1)


def saved(out, what):
    if out.get("result") not in ("saved", "deleted", "ok"):
        fail(f"{what}: {out}")


def upsert(s, base, key, match_field, match_value, item, search="search_rule", add="add_rule", setp="set_rule"):
    """Create the item, or update it in place if one with that field value exists."""
    row = next((r for r in s.search(f"{base}/{search}") if r.get(match_field) == match_value), None)
    if row and all(k in row and str(row[k]) == str(v) for k, v in item.items()):
        return row["uuid"]
    if row:
        saved(s.call("POST", f"{base}/{setp}/{row['uuid']}", {key: item}), f"update {match_value}")
        log(f"updated: {match_value}")
        return row["uuid"]
    out = s.call("POST", f"{base}/{add}", {key: item})
    saved(out, f"add {match_value}")
    log(f"added: {match_value}")
    return out.get("uuid")


def delete(s, base, match_field, match_value, search="search_rule", delp="del_rule"):
    for r in s.search(f"{base}/{search}"):
        if r.get(match_field) == match_value:
            saved(s.call("POST", f"{base}/{delp}/{r['uuid']}", {}), f"delete {match_value}")
            log(f"deleted: {match_value}")


# ---------------------------------------------------- legacy (PHP) forms
class Form(HTMLParser):
    """Current values of the first <form> on a legacy page."""
    def __init__(self):
        super().__init__()
        self.data, self.in_form, self.select, self.submit, self.done = {}, False, None, None, False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form" and not self.done:
            self.in_form = True
        if not self.in_form:
            return
        n = a.get("name")
        if tag == "input" and n:
            t = (a.get("type") or "text").lower()
            if t in ("checkbox", "radio"):
                if "checked" in a:
                    self.data[n] = a.get("value", "on")
            elif t == "submit":
                if self.submit is None and n.lower() in ("submit", "save"):
                    self.submit = (n, a.get("value", "Save"))
            elif t != "button":
                self.data.setdefault(n, a.get("value", ""))
        elif tag == "select" and n:
            self.select = n
        elif tag == "option" and self.select and "selected" in a:
            self.data[self.select] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "select":
            self.select = None
        if tag == "form" and self.in_form:
            self.in_form, self.done = False, True


def legacy_form(s, page, overrides, apply=True):
    f = Form()
    f.feed(s.s.get(f"{s.base}/{page}", timeout=60).text)
    data = {**f.data, **overrides}
    if f.submit:
        data[f.submit[0]] = f.submit[1]
    s.s.post(f"{s.base}/{page}", data=data, timeout=120)
    if apply:
        f2 = Form()
        f2.feed(s.s.get(f"{s.base}/{page}", timeout=60).text)
        tok = {k: v for k, v in f2.data.items() if len(k) > 15 and k.isalnum()}
        s.s.post(f"{s.base}/{page}", data={**tok, "apply": "Apply changes"}, timeout=180)


# ------------------------------------------------------------------ actions
def apiuser(s):
    """The PIA script's own restricted API user; prints a new key only when
    asked to (PIA_NEED_KEY=1 - the playbook found none in the vault or on the firewall)."""
    if not any(u.get("name") == API_USER for u in s.search("/api/auth/user/search")):
        saved(s.call("POST", "/api/auth/user/add", {"user": {
            "name": API_USER, "scrambled_password": "1", "priv": API_PRIVS,
            "descr": "PIA WireGuard script (OPNsensePIAWireguard) - API only, managed by ansible-runner"}}),
            "add WireguardAPI user")
        log("added user WireguardAPI")
    result = {}
    if os.environ.get("PIA_NEED_KEY") == "1":
        out = s.call("POST", f"/api/auth/user/add_api_key/{API_USER}", {})
        if not out.get("key"):
            fail(f"creating the WireguardAPI key: {out.get('result')}")
        result = {"key": out["key"], "secret": out["secret"]}
        log("created an API key for WireguardAPI")
    return result


def wg_device(s, instance_name):
    for r in s.search("/api/wireguard/server/search_server"):
        if r.get("name") == instance_name:
            return r.get("interface") or ("wg" + str(r.get("instance", "")))
    return None


def configure(s):
    """PIA_PARAMS: instance (pia-toronto), instance_short (toronto),
    hosts [ips], bypass [nets], killswitch, dns, mss."""
    p = json.loads(os.environ["PIA_PARAMS"])
    gw_name = f"WAN_PIA_{p['instance_short'].upper()}_IPv4"

    # 1. Interface for the tunnel: assigned, enabled, no address (the WireGuard
    #    instance owns it), MSS clamped (WireGuard MTU 1420 - 40).
    dev = wg_device(s, p["instance"])
    if not dev:
        fail(f"no WireGuard instance {p['instance']} - the PIA script's first run should have created it")
    assigned = next((r for r in s.search("/api/interfaces/assignment/search_item") if r.get("if") == dev), None)
    if not assigned:
        out = s.call("POST", "/api/interfaces/assignment/add_item",
                     {"interface": {"if": dev, "descr": f"WAN_PIAWG_{p['instance_short'].upper()}"}})
        saved(out, "assign interface")
        ifname = out["uuid"]
        log(f"assigned {dev} as {ifname}")
    else:
        ifname = assigned.get("identifier")
    if not assigned or "text-success" not in assigned.get("icon", ""):
        # Only when new or down: re-saving the interface bounces the tunnel.
        legacy_form(s, f"interfaces.php?if={ifname}", {"enable": "yes", "type": "none", "type6": "none",
                                                       "mss": str(p.get("mss", 1380))})
        log(f"{ifname} ({dev}) enabled, MSS {p.get('mss', 1380)}")

    # 2. Gateway: created as dynamic, then the PIA script keeps its address
    #    current - so an update leaves the address alone. Far gateway,
    #    monitored, lower priority than the WAN, never the default.
    gw = {"disabled": "0", "name": gw_name, "interface": ifname, "ipprotocol": "inet", "defaultgw": "0",
          "fargw": "1", "monitor_disable": "0", "priority": "255", "weight": "1",
          "descr": "PIA WireGuard (OPNsensePIAWireguard) - managed by ansible-runner"}
    if not any(r.get("name") == gw_name for r in s.search("/api/routing/settings/search_gateway")):
        gw["gateway"] = "dynamic"
    upsert(s, "/api/routing/settings", "gateway_item", "name", gw_name, gw,
           search="search_gateway", add="add_gateway", setp="set_gateway")
    s.call("POST", "/api/routing/settings/reconfigure", {})

    # 3. Tunnel monitor (keeps it up, changes server when PIA's goes down).
    upsert(s, "/api/cron/settings", "job", "description", D_CRON, {
        "enabled": "1", "minutes": "*/5", "hours": "*", "days": "*", "months": "*", "weekdays": "*",
        "command": "piawireguard monitor", "description": D_CRON},
        search="search_jobs", add="add_job", setp="set_job")
    s.call("POST", "/api/cron/service/reconfigure", {})

    # 4. Aliases.
    upsert(s, "/api/firewall/alias", "alias", "name", "PIA_Hosts", {
        "enabled": "1", "name": "PIA_Hosts", "type": "host", "content": "\n".join(p["hosts"]),
        "description": "Hosts routed through PIA (managed by ansible-runner)"},
        search="search_item", add="add_item", setp="set_item")
    upsert(s, "/api/firewall/alias", "alias", "name", "PIA_Bypass", {
        "enabled": "1", "name": "PIA_Bypass", "type": "network", "content": "\n".join(p["bypass"]),
        "description": "Networks PIA_Hosts reach directly, not through PIA (managed by ansible-runner)"},
        search="search_item", add="add_item", setp="set_item")
    s.call("POST", "/api/firewall/alias/reconfigure", {})

    # 5. Filter rules. OPNsense 26 keeps the interface rules in the same model,
    #    ordered by sequence: ours must come before "Default allow LAN", or the
    #    hosts go out the WAN untouched (confirmed live) - move the defaults back.
    upsert(s, "/api/firewall/filter", "rule", "description", D_ROUTE, {
        "enabled": "1", "sequence": "1", "action": "pass", "quick": "1", "interface": "lan", "direction": "in",
        "ipprotocol": "inet", "protocol": "any", "source_net": "PIA_Hosts", "destination_net": "PIA_Bypass",
        "destination_not": "1", "gateway": gw_name, "tag": TAG, "description": D_ROUTE})
    if p.get("killswitch", True):
        upsert(s, "/api/firewall/filter", "rule", "description", D_KILL, {
            "enabled": "1", "sequence": "2", "action": "block", "quick": "1", "interface": "wan",
            "direction": "out", "ipprotocol": "inet", "protocol": "any", "source_net": "any",
            "destination_net": "any", "tagged": TAG, "log": "1", "description": D_KILL})
    else:
        delete(s, "/api/firewall/filter", "description", D_KILL)
    for r in s.search("/api/firewall/filter/search_rule"):
        if r.get("description", "").startswith("Default allow LAN") and int(r.get("sequence") or 0) <= 2:
            new = "20" if "IPv6" not in r["description"] else "21"
            saved(s.call("POST", f"/api/firewall/filter/set_rule/{r['uuid']}", {"rule": {"sequence": new}}),
                  "renumber default LAN rule")
            log(f"moved '{r['description']}' to sequence {new}, after the PIA rules")
    s.call("POST", "/api/firewall/filter/apply", {})

    # 6. DNS of the routed hosts goes to PIA's resolver, through the tunnel (no leak).
    def dnat(desc, rule, on):
        rows = [r for r in s.search("/api/firewall/d_nat/search_rule") if r.get("descr") == desc]
        if on and not rows:
            saved(s.call("POST", "/api/firewall/d_nat/add_rule", {"rule": rule}), f"add {desc}")
            log(f"added: {desc}")
        elif on:
            saved(s.call("POST", f"/api/firewall/d_nat/set_rule/{rows[0]['uuid']}", {"rule": rule}), f"update {desc}")
            log(f"updated: {desc}")
        else:
            for r in rows:
                saved(s.call("POST", f"/api/firewall/d_nat/del_rule/{r['uuid']}", {}), f"delete {desc}")
                log(f"deleted: {desc}")
    dnat(D_DNS, {"disabled": "0", "sequence": "10", "interface": "lan", "ipprotocol": "inet", "protocol": "tcp/udp",
                 "source": {"network": "PIA_Hosts", "not": "0"}, "destination": {"network": "any", "port": "53", "not": "0"},
                 "target": PIA_DNS, "local-port": "53", "pass": "", "descr": D_DNS}, p.get("dns", True))
    s.call("POST", "/api/firewall/d_nat/apply", {})
    return {"interface": ifname, "device": dev, "gateway": gw_name}


def remove(s):
    p = json.loads(os.environ["PIA_PARAMS"])
    gw_name = f"WAN_PIA_{p['instance_short'].upper()}_IPv4"
    for d in (D_ROUTE, D_KILL):
        delete(s, "/api/firewall/filter", "description", d)
    s.call("POST", "/api/firewall/filter/apply", {})
    for r in s.search("/api/firewall/d_nat/search_rule"):
        if r.get("descr") == D_DNS:
            saved(s.call("POST", f"/api/firewall/d_nat/del_rule/{r['uuid']}", {}), "delete DNAT")
            log(f"deleted: {r.get('descr')}")
    s.call("POST", "/api/firewall/d_nat/apply", {})
    for name in ("PIA_Hosts", "PIA_Bypass"):
        delete(s, "/api/firewall/alias", "name", name, search="search_item", delp="del_item")
    s.call("POST", "/api/firewall/alias/reconfigure", {})
    delete(s, "/api/cron/settings", "description", D_CRON, search="search_jobs", delp="del_job")
    s.call("POST", "/api/cron/service/reconfigure", {})
    delete(s, "/api/routing/settings", "name", gw_name, search="search_gateway", delp="del_gateway")
    s.call("POST", "/api/routing/settings/reconfigure", {})
    dev = wg_device(s, p["instance"])
    if dev:
        for r in s.search("/api/interfaces/assignment/search_item"):
            if r.get("if") == dev:
                legacy_form(s, f"interfaces.php?if={r['identifier']}", {"enable": ""})
                saved(s.call("POST", f"/api/interfaces/assignment/del_item/{r['identifier']}", {}), "unassign")
                log(f"unassigned {r['identifier']} ({dev})")
    for r in s.search("/api/wireguard/client/search_client"):
        if r.get("name") == f"{p['instance']}-server":
            delete(s, "/api/wireguard/client", "name", r["name"], search="search_client", delp="del_client")
    delete(s, "/api/wireguard/server", "name", p["instance"], search="search_server", delp="del_server")
    s.call("POST", "/api/wireguard/service/reconfigure", {})
    delete(s, "/api/auth/user", "name", API_USER, search="search", delp="del")
    return {}


def status(s):
    p = json.loads(os.environ.get("PIA_PARAMS", "{}"))
    gw = f"WAN_PIA_{p.get('instance_short', '').upper()}_IPv4"
    for _ in range(12):
        items = s.call("GET", "/api/routes/gateway/status").get("items", [])
        g = next((i for i in items if i.get("name") == gw), {})
        if g.get("status_translated") == "Online":
            break
        time.sleep(10)
    return {"gateway": gw, "address": g.get("address"), "status": g.get("status_translated"),
            "delay": g.get("delay"), "loss": g.get("loss")}


if __name__ == "__main__":
    action = sys.argv[1]
    session = Session()
    result = {"apiuser": apiuser, "configure": configure, "remove": remove, "status": status}[action](session)
    print(json.dumps({"failed": False, "changed": bool(LOG), "result": result, "log": LOG}))
