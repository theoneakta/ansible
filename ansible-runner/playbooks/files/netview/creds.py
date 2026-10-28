"""Sentry Lens: the credentials its collectors use - SNMP communities and v3
users, SSH, WinRM and Proxmox API logins - entered on Assets > Credentials
(or in the installer), each limited to hosts / subnets.

Where they're kept: Sentry Lens's vault (Vaultwarden, vault.py) when it has
one - VAULT_URL and its service account in vault.env, written by
vaultwarden.yml - as logins of the organization's collection, so people see
and manage them in any Bitwarden app too; without a vault, in ClickHouse
(netview.credentials), encrypted with the app's settings key. With a vault,
those stored before move into it once.

A vault login is one of ours when it has a hidden field "kind": snmp_v2c,
snmp_v3, ssh, winrm, proxmox (readonly_accounts.yml writes them the same
way; "proxmox-api" is read as proxmox). Its username / password are the
login's; the rest are hidden fields (scope, port, level, protocols, the
privacy password, an SSH private key - or key_item: the item holding it).
"""
import ipaddress
import json
import os
import re
import secrets
import threading
import time

from fastapi import HTTPException

import auth

KINDS = {"snmp_v2c": "SNMP v2c", "snmp_v3": "SNMP v3", "ssh": "SSH", "winrm": "WinRM", "proxmox": "Proxmox API"}
SNMP = ("snmp_v2c", "snmp_v3")
V3_AUTH = {"MD5", "SHA", "SHA-224", "SHA-256", "SHA-384", "SHA-512"}
V3_PRIV = {"DES", "AES", "AES-192", "AES-256"}
SECRET_FIELDS = ("community", "auth_pass", "priv_pass", "password", "private_key", "secret")
CACHE_FOR = 60  # vault reads, seconds - the collectors ask every minute

VAULT = {k: os.environ.get(f"VAULT_{k.upper()}", "") for k in ("url", "email", "password", "org", "collection", "admins")}
VAULT_CA = os.environ.get("VAULT_CA", "/data/vault-ca.pem")
_cache = {"t": 0, "items": None, "error": ""}
_lock = threading.Lock()


def vault_on():
    return bool(VAULT["url"] and VAULT["password"])


def _verify():
    try:
        return VAULT_CA if os.path.getsize(VAULT_CA) > 0 else True
    except OSError:
        return True


# ------------------------------------------------------------------ the secret of each kind
def _port(v, default):
    try:
        p = int(v or default)
    except (TypeError, ValueError):
        raise HTTPException(400, "a port number")
    if not 1 <= p <= 65535:
        raise HTTPException(400, "a port from 1 to 65535")
    return p


def make_secret(b, kind, old=None):
    """The secret and its summary from what the form sent. Editing (old: the
    secret it had, same kind): a value left empty is kept."""
    old = old or {}
    get = lambda k, d="": str(b.get(k) or old.get(k, d) or "")  # noqa: E731
    if kind == "snmp_v2c":
        community = get("community")
        if not 1 <= len(community) <= 64:
            raise HTTPException(400, "a community (1 to 64 characters)")
        return {"community": community}, "SNMP v2c community"
    if kind == "snmp_v3":
        user = get("user")
        if not re.fullmatch(r"[\w.@-]{1,32}", user):
            raise HTTPException(400, "a v3 user name")
        auth_pass, priv_pass = get("auth_pass"), get("priv_pass")
        level = b.get("level") or ("authPriv" if auth_pass and priv_pass else "authNoPriv" if auth_pass else "noAuthNoPriv")
        if level not in ("noAuthNoPriv", "authNoPriv", "authPriv"):
            raise HTTPException(400, "level: noAuthNoPriv, authNoPriv or authPriv")
        s = {"user": user, "level": level}
        if level != "noAuthNoPriv":
            proto = b.get("auth_proto") or old.get("auth_proto")
            if proto not in V3_AUTH or not 8 <= len(auth_pass) <= 128:
                raise HTTPException(400, f"auth protocol one of {sorted(V3_AUTH)}, password 8 characters or more")
            s |= {"auth_proto": proto, "auth_pass": auth_pass}
        if level == "authPriv":
            proto = b.get("priv_proto") or old.get("priv_proto")
            if proto not in V3_PRIV or not 8 <= len(priv_pass) <= 128:
                raise HTTPException(400, f"privacy protocol one of {sorted(V3_PRIV)}, password 8 characters or more")
            s |= {"priv_proto": proto, "priv_pass": priv_pass}
        return s, f"SNMP v3, user {user}, {level}" + (f" ({s.get('auth_proto')}/{s.get('priv_proto', '-')})" if level != "noAuthNoPriv" else "")
    if kind == "ssh":
        user, password, key = get("user"), get("password"), get("private_key")
        key_item = old.get("key_item", "") if not (b.get("password") or b.get("private_key")) else ""
        if not re.fullmatch(r"[\w.@-]{1,64}", user):
            raise HTTPException(400, "a user name")
        if key and "PRIVATE KEY" not in key:
            raise HTTPException(400, "the private key: the whole text, -----BEGIN ... PRIVATE KEY----- included")
        if not (password or key or key_item):
            raise HTTPException(400, "a password or a private key")
        s = {"user": user, "port": _port(b.get("port") or old.get("port"), 22)}
        s |= {k: v for k, v in (("password", password), ("private_key", key), ("key_item", key_item)) if v}
        return s, f"SSH, user {user}, " + ("key" if key or key_item else "password") + (f", port {s['port']}" if s["port"] != 22 else "")
    if kind == "winrm":
        user, password = get("user"), get("password")
        if not re.fullmatch(r"[\w.@\\ -]{1,104}", user):
            raise HTTPException(400, "a user name (user, DOMAIN\\user or user@domain)")
        if not password:
            raise HTTPException(400, "a password")
        https = str(b.get("https", old.get("https", True))).lower() not in ("false", "0", "no")
        s = {"user": user, "password": password, "https": https, "port": _port(b.get("port") or old.get("port"), 5986 if https else 5985)}
        return s, f"WinRM ({'HTTPS' if https else 'HTTP'} {s['port']}), user {user}"
    if kind == "proxmox":
        token, secret = get("user"), get("secret") or get("password")
        if not re.fullmatch(r"[\w.-]+@[\w.-]+![\w.-]+", token):
            raise HTTPException(400, "the token ID: user@realm!name (e.g. sentry@pve!lens)")
        if not secret:
            raise HTTPException(400, "the token's secret")
        s = {"user": token, "secret": secret, "port": _port(b.get("port") or old.get("port"), 8006)}
        return s, f"Proxmox API token {token}"
    raise HTTPException(400, f"kind: one of {list(KINDS)}")


def check_scope(scope):
    """Hosts or subnets, comma / space separated -> ['10.0.0.0/24', '10.0.0.5/32']; [] = everywhere."""
    out = []
    for s in scope if isinstance(scope, list) else str(scope or "").replace(",", " ").split():
        try:
            out.append(str(ipaddress.ip_network(str(s).strip(), strict=False)))
        except ValueError:
            raise HTTPException(400, f"not an address or subnet: {s}")
    return out


# ------------------------------------------------------------------ the vault
# One signed-in session, kept: Vaultwarden turns away more than a few
# sign-ins a minute. Signed in again before its token runs out (an hour), or
# when the server says it has.
SESSION_FOR = 45 * 60
_session = {"v": None, "t": 0, "org": None, "wait_until": 0, "backoff": 0}
_session_lock = threading.RLock()


def _signin():
    """Sign in - not again before the backoff is over after a failure (1 min,
    doubling to 15): Vaultwarden allows about one sign-in a minute."""
    import vault
    if time.time() < _session["wait_until"]:
        raise vault.VaultError(f"signing in again in {int(_session['wait_until'] - time.time())} s (the last try failed)")
    try:
        v = vault.Vault(VAULT["url"], VAULT["email"], VAULT["password"], _verify()).login()
        org = v.org(VAULT["org"])
        if not org:
            raise vault.VaultError(f"Sentry Lens's account isn't in the organization {VAULT['org']!r} - run vaultwarden.yml")
        col = v.collection(org[0], org[1], VAULT["collection"])
    except Exception:
        _session["backoff"] = min(900, max(60, _session["backoff"] * 2))
        _session["wait_until"] = time.time() + _session["backoff"]
        raise
    _session.update(v=v, t=time.time(), org=(org[0], org[1], col), backoff=0, wait_until=0)


def _open():
    """(vault, org id, org key, collection id) - the kept session."""
    with _session_lock:
        if _session["v"] is None or time.time() - _session["t"] > SESSION_FOR:
            _signin()
        return (_session["v"], *_session["org"])


def _with_vault(fn):
    """fn(vault, org_id, okey, col) - signed in again once if the server dropped the session."""
    import vault
    with _session_lock:
        try:
            return fn(*_open())
        except vault.VaultError as e:
            if "HTTP 401" not in str(e):
                raise
            _session["v"] = None
            return fn(*_open())


def _vault():
    return _open()[0]


def _from_item(name, it, items):
    """A vault login -> a credential {id, name, kind, scope, secret, summary, by, created, source} - or None."""
    f = dict(it.get("fields") or {})
    kind = {"proxmox-api": "proxmox"}.get(f.get("kind", ""), f.get("kind", ""))
    if kind not in KINDS:
        return None
    s = {"user": it.get("username") or ""}
    if kind == "snmp_v2c":
        s = {"community": it.get("password") or ""}
    elif kind == "snmp_v3":
        s |= {k: f[k] for k in ("level", "auth_proto", "priv_proto", "priv_pass") if f.get(k)}
        if it.get("password"):
            s["auth_pass"] = it["password"]
    elif kind == "proxmox":
        s |= {"secret": it.get("password") or "", "port": int(f.get("port") or 8006)}
    else:
        s |= {"port": int(f.get("port") or (22 if kind == "ssh" else 5986))}
        if it.get("password"):
            s["password"] = it["password"]
        if kind == "winrm":
            s["https"] = f.get("https", "true") != "false"
        if f.get("private_key"):
            s["private_key"] = f["private_key"]
        elif f.get("key_item"):
            s["key_item"] = f["key_item"]
            s["private_key"] = ((items.get(f["key_item"]) or {}).get("fields") or {}).get("private_key", "")
    scope = f.get("scope") or (f"{f['host']}/32" if f.get("host") and ":" not in f["host"] else f.get("host", ""))
    try:
        scope = check_scope(scope)
    except HTTPException:
        scope = []
    return {"id": it["id"], "name": name, "kind": kind, "scope": scope, "secret": s,
            "summary": f.get("summary") or make_summary(kind, s), "by": f.get("by", ""),
            "created": int(f.get("created") or 0), "source": "vault",
            "origin": "readonly_accounts.yml" if "readonly_accounts.yml" in (it.get("notes") or "") else ""}


def make_summary(kind, s):
    try:
        return make_secret(s, kind, s)[1]
    except HTTPException:
        return KINDS.get(kind, kind)


def _to_item(c):
    """A credential -> a vault login (vault.put's shape)."""
    s, kind = c["secret"], c["kind"]
    fields = {"kind": kind, "scope": ",".join(c["scope"]), "summary": c["summary"], "by": c.get("by", ""),
              "created": str(int(c.get("created") or time.time()))}
    user, password = s.get("user", ""), ""
    if kind == "snmp_v2c":
        password = s["community"]
    elif kind == "snmp_v3":
        password = s.get("auth_pass", "")
        fields |= {k: s[k] for k in ("level", "auth_proto", "priv_proto", "priv_pass") if s.get(k)}
    elif kind == "proxmox":
        password = s["secret"]
        fields["port"] = str(s["port"])
    else:
        password = s.get("password", "")
        fields["port"] = str(s["port"])
        if kind == "winrm":
            fields["https"] = "true" if s.get("https", True) else "false"
        if s.get("key_item"):
            fields["key_item"] = s["key_item"]
        elif s.get("private_key"):
            fields["private_key"] = s["private_key"]
    return {"name": c["name"], "username": user, "password": password, "fields": fields,
            "notes": c.get("notes") or f"{KINDS[kind]} credential for Sentry Lens's collectors (Assets > Credentials)."}


def _vault_items(fresh=False):
    """{name: item} of the collection, cached CACHE_FOR s."""
    with _lock:
        if fresh or _cache["items"] is None or time.time() - _cache["t"] > CACHE_FOR:
            try:
                _cache.update(items=_with_vault(lambda v, org_id, okey, col: v.items(org_id, okey)), t=time.time(), error="")
            except Exception as e:  # noqa: BLE001 - shown on the page; the last good copy is kept
                _cache["error"] = str(e)[:300]
                _cache["t"] = time.time() - CACHE_FOR + 15  # tried again in 15 s, not at every call
                if _cache["items"] is None:
                    _cache["items"] = {}
        return _cache["items"]


def status():
    if not vault_on():
        return {"on": False}
    _vault_items()
    return {"on": True, "url": VAULT["url"], "org": VAULT["org"], "collection": VAULT["collection"], "error": _cache["error"]}


# ------------------------------------------------------------------ the store
def _db():
    import snmp  # its ClickHouse helpers and the credentials table
    return snmp


def all_creds():
    """{id: credential} - from the vault, or from ClickHouse."""
    if vault_on():
        items = _vault_items()
        out = {}
        for name, it in items.items():
            c = _from_item(name, it, items)
            if c:
                out[c["id"]] = c
        return out
    db = _db()
    out = {}
    for r in db.q("SELECT * FROM netview.credentials FINAL WHERE deleted = 0"):
        out[r["id"]] = {k: r[k] for k in ("id", "name", "kind", "scope", "summary", "by")} | {
            "secret": json.loads(auth._fernet.decrypt(r["secret"].encode())), "created": db.assets._ts(r["created"]),
            "source": "local", "origin": ""}
    return out


def save(c, existing_id=None):
    """Store a credential (new, or replacing existing_id) - the id it has."""
    if vault_on():
        def put(v, org_id, okey, col):
            items = v.items(org_id, okey)
            old = next((it for it in items.values() if it["id"] == existing_id), None) if existing_id else None
            if c["name"] in items and items[c["name"]]["id"] != existing_id:
                raise HTTPException(409, f"the vault already has a login named {c['name']!r}")
            return v.put(org_id, okey, col, _to_item(c), old)
        cid = _with_vault(put)
        _vault_items(fresh=True)
        return cid
    db = _db()
    cid = existing_id or secrets.token_hex(6)
    db.insert("credentials", [{"id": cid, "name": c["name"], "kind": c["kind"], "scope": c["scope"], "summary": c["summary"],
                               "secret": auth._fernet.encrypt(json.dumps(c["secret"]).encode()).decode(),
                               "created": int(c.get("created") or time.time()), "by": c.get("by", ""), "deleted": 0,
                               "ver": time.time_ns()}])
    return cid


def delete(cid):
    if vault_on():
        _with_vault(lambda v, *_: v.call("PUT", f"/api/ciphers/{cid}/delete"))  # to the vault's trash: restorable there
        _vault_items(fresh=True)
        return
    db = _db()
    r = db.q("SELECT * FROM netview.credentials FINAL WHERE id = {id:String}", id=cid)
    if r:
        db.insert("credentials", [r[0] | {"created": db.assets._ts(r[0]["created"]), "deleted": 1, "ver": time.time_ns()}])


def public(c, used=None):
    """What the page sees: never a community, password, key or token secret."""
    s = c["secret"]
    return {k: c.get(k) for k in ("id", "name", "kind", "scope", "summary", "by", "created", "source", "origin")} | {
        "devices": (used or {}).get(c["id"], 0),
        "edit": {k: v for k, v in s.items() if k not in SECRET_FIELDS and k != "key_item"} | (
            {"key": "in the vault" if s.get("key_item") else "set" if s.get("private_key") else ""} if c["kind"] == "ssh" else {})}


def for_collector(c, version=""):
    """The credentials whose scope meets the collector's subnets, as it reads
    them. SSH / WinRM / Proxmox only for collectors that know them (2.4.0+):
    an older one would try them as SNMP v3 users."""
    import assets
    full = assets.can_rotate(version, (2, 4, 0))
    nets = [ipaddress.ip_network(s) for s in c["subnets"]]
    out = []
    for cr in all_creds().values():
        if cr["kind"] not in SNMP and not full:
            continue
        scope = [ipaddress.ip_network(s) for s in cr["scope"]]
        if scope and not any(a.overlaps(b) for a in scope for b in nets if a.version == b.version):
            continue
        s = {k: v for k, v in cr["secret"].items() if k != "key_item"}
        out.append({"id": cr["id"], "kind": cr["kind"], "scope": cr["scope"]} | s)
    return out


# ------------------------------------------------------------------ upkeep
def migrate():
    """With a vault: the credentials stored in ClickHouse before move into it (once)."""
    if not vault_on():
        return
    db = _db()
    try:
        rows = db.q("SELECT * FROM netview.credentials FINAL WHERE deleted = 0")
    except Exception:  # noqa: BLE001 - no table yet: nothing to move
        return
    for r in rows:
        c = {"name": r["name"], "kind": r["kind"], "scope": r["scope"], "summary": r["summary"], "by": r["by"],
             "created": db.assets._ts(r["created"]), "secret": json.loads(auth._fernet.decrypt(r["secret"].encode()))}
        if c["name"] not in _vault_items(fresh=True):
            save(c)
        db.insert("credentials", [r | {"created": db.assets._ts(r["created"]), "deleted": 1, "ver": time.time_ns()}])


def confirm_admins():
    """Admins invited to the organization who have registered since: confirmed (they then see it)."""
    admins = {a.strip().lower() for a in VAULT["admins"].split(",") if a.strip()}
    if not admins:
        return []

    def run(v, org_id, okey, col):
        done = []
        members = {m["email"].lower(): m for m in v.members(org_id)}
        for e in admins - set(members):
            v.invite(org_id, e, col)
        for e, m in members.items():
            if e in admins and m.get("status") == 1:
                v.confirm(org_id, okey, m)
                done.append(e)
        return done
    return _with_vault(run)


def upkeep_loop():
    time.sleep(20)
    try:
        migrate()
    except Exception as e:  # noqa: BLE001
        print(f"credentials: moving them into the vault failed: {e}", flush=True)
    while True:
        try:
            confirm_admins()
        except Exception as e:  # noqa: BLE001
            _cache["error"] = _cache["error"] or f"confirming admins: {str(e)[:200]}"
        time.sleep(300)


def start():
    if vault_on():
        threading.Thread(target=upkeep_loop, daemon=True, name="vault").start()
