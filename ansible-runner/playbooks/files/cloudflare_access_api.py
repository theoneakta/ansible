#!/usr/bin/env python3
"""Cloudflare side of playbooks/cloudflare_access.yml: an Access (Zero Trust)
application in front of a self-hosted site, through the Cloudflare API with
the account's Global API Key. Run on the controller; prints one JSON line.

  login     the One-time PIN method (an emailed code - no identity provider
            to register) exists
  policy    a reusable Allow policy for the given emails (the account's own
            email when none are given)
  app       the self-hosted application on the domain, with that policy

Prints the team domain and the application's AUD tag - what the app behind
it checks Access's tokens against.

Settings come from the environment (the playbook passes them, no_log):
    CF_EMAIL, CF_KEY       account email + Global API Key
    ACCESS_PARAMS          JSON: zone, domain, name, logo_url, emails, session, team,
                           brand (login page colours + footer), public_paths
"""
import json
import os
import sys

import requests

API = "https://api.cloudflare.com/client/v4"
LOG = []


def fail(msg):
    print(json.dumps({"failed": True, "msg": msg, "log": LOG}))
    sys.exit(1)


def cf(method, path, body=None, soft=False):
    """One API call; soft=True returns the errors instead of failing."""
    r = requests.request(method, API + path, json=body, timeout=30, headers={
        "X-Auth-Email": os.environ["CF_EMAIL"], "X-Auth-Key": os.environ["CF_KEY"]})
    try:
        out = r.json()
    except ValueError:
        fail(f"{method} {path}: HTTP {r.status_code}")
    if not out.get("success"):
        errs = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in out.get("errors", [])) or r.text[:200]
        if soft:
            return {"_error": errs}
        fail(f"{method} {path}: {errs}")
    return out["result"]


def same(cur, want):
    return all(cur.get(k) == v for k, v in want.items())


def main():
    p = json.loads(os.environ["ACCESS_PARAMS"])
    emails = p["emails"] or [os.environ["CF_EMAIL"]]

    zones = cf("GET", f"/zones?name={p['zone']}")
    if not zones:
        fail(f"no zone {p['zone']} in this account")
    acc = zones[0]["account"]["id"]
    base = f"/accounts/{acc}/access"

    # Zero Trust's organization (the team domain): created when the account has none.
    org = cf("GET", f"{base}/organizations", soft=True)
    if "_error" in org:
        if "not_enabled" not in org["_error"]:
            fail(f"reading the Zero Trust organization: {org['_error']}")
        made = cf("POST", f"{base}/organizations", {"name": p["team"], "auth_domain": f"{p['team']}.cloudflareaccess.com"},
                  soft=True)
        if "_error" in made:
            fail(f"Zero Trust isn't enabled on this account and couldn't be from the API ({made['_error']}) - "
                 f"open one.dash.cloudflare.com once, pick the team name '{p['team']}' and the Free plan, then re-run")
        LOG.append(f"enabled Zero Trust: team {p['team']}.cloudflareaccess.com")
        org = made
    team = org.get("auth_domain")

    # The login page's look (team-wide): the app's name, logo and colours.
    if p.get("brand"):
        design = {"background_color": p["brand"]["background"], "text_color": p["brand"]["text"],
                  "logo_path": p["logo_url"], "header_text": p["name"], "footer_text": p["brand"]["footer"]}
        if any(org.get("login_design", {}).get(k) != v for k, v in design.items()):
            cf("PUT", f"{base}/organizations", {"name": org.get("name") or p["team"], "auth_domain": team,
                                                "login_design": design})
            LOG.append(f"login page branded: {p['name']}")

    idps = cf("GET", f"{base}/identity_providers")
    if not any(i.get("type") == "onetimepin" for i in idps):
        cf("POST", f"{base}/identity_providers", {"name": "One-time PIN", "type": "onetimepin", "config": {}})
        LOG.append("added the One-time PIN login method")
        idps = cf("GET", f"{base}/identity_providers")

    # Reusable policy, matched by name.
    pol_name = f"{p['name']} - allowed people (ansible-runner)"
    want_pol = {"name": pol_name, "decision": "allow", "include": [{"email": {"email": e}} for e in emails]}
    pol = next((x for x in cf("GET", f"{base}/policies") if x.get("name") == pol_name), None)
    if not pol:
        pol = cf("POST", f"{base}/policies", want_pol)
        LOG.append(f"added policy: {pol_name} ({len(emails)} email(s))")
    elif sorted(json.dumps(i, sort_keys=True) for i in pol.get("include", [])) != \
            sorted(json.dumps(i, sort_keys=True) for i in want_pol["include"]):
        pol = cf("PUT", f"{base}/policies/{pol['id']}", want_pol)
        LOG.append(f"updated policy: {pol_name} ({len(emails)} email(s))")

    # The application, matched by domain.
    want_app = {"name": p["name"], "domain": p["domain"], "type": "self_hosted",
                "session_duration": p["session"], "logo_url": p["logo_url"], "app_launcher_visible": True,
                "policies": [{"id": pol["id"], "precedence": 1}]}
    app = next((a for a in cf("GET", f"{base}/apps") if a.get("domain") == p["domain"]), None)
    if not app:
        app = cf("POST", f"{base}/apps", want_app)
        LOG.append(f"added application: {p['name']} on {p['domain']}")
    elif not same(app, {k: v for k, v in want_app.items() if k != "policies"}) or \
            [x.get("id") for x in app.get("policies", [])] != [pol["id"]]:
        app = cf("PUT", f"{base}/apps/{app['id']}", want_app)
        LOG.append(f"updated application: {p['name']} on {p['domain']}")

    # Paths anyone may load (the logo the login page shows, the app's sign-in
    # page assets): their own application with a Bypass policy - a more
    # specific path wins over the domain's application.
    for path in p.get("public_paths", []):
        bp_name = f"{p['name']} - public {path} (ansible-runner)"
        want_bp = {"name": bp_name, "decision": "bypass", "include": [{"everyone": {}}]}
        bpol = next((x for x in cf("GET", f"{base}/policies") if x.get("name") == bp_name), None)
        if not bpol:
            bpol = cf("POST", f"{base}/policies", want_bp)
            LOG.append(f"added policy: {bp_name}")
        dom = f"{p['domain']}/{path.strip('/')}"
        want_pa = {"name": f"{p['name']} ({path})", "domain": dom, "type": "self_hosted",
                   "session_duration": p["session"], "app_launcher_visible": False,
                   "policies": [{"id": bpol["id"], "precedence": 1}]}
        papp = next((a for a in cf("GET", f"{base}/apps") if a.get("domain") == dom), None)
        if not papp:
            cf("POST", f"{base}/apps", want_pa)
            LOG.append(f"added public path: {dom}")
        elif [x.get("id") for x in papp.get("policies", [])] != [bpol["id"]]:
            cf("PUT", f"{base}/apps/{papp['id']}", want_pa)
            LOG.append(f"updated public path: {dom}")

    print(json.dumps({"changed": bool(LOG), "log": LOG, "team_domain": team, "aud": app.get("aud"),
                      "app_id": app.get("id"), "allowed": len(emails),
                      "login_methods": sorted({i.get("name") or i.get("type") for i in idps})}))


if __name__ == "__main__":
    main()
