"""Sentry Lens sign-in: built in, configured from the environment and from
the app's own Settings page, so any deployment can turn it on without a
particular proxy or identity service.

Methods (AUTH_METHODS, comma-separated):
  builtin     the app's own login page: local accounts (email + password,
              scrypt-hashed) and the sign-in methods below
  cloudflare  a Cloudflare Access token in front (CF_ACCESS_TEAM / _AUD)
              counts as signed in - for deployments already behind Access
  off         no sign-in at all (LAN-only installs)

Sign-in methods - one "Continue with ..." button each (LDAP: the password
form). From AUTH_PROVIDERS (a JSON list, read-only in the UI) and from
Settings > Sign-in methods (stored in ClickHouse, secrets encrypted):
  google     client_id, client_secret
  microsoft  Microsoft Entra ID (Azure AD): client_id, client_secret,
             tenant (a tenant ID for one organization, or common)
  apple      client_id (services ID), team_id, key_id, private_key (.p8)
  github     client_id, client_secret
  cognito    AWS Cognito user pool: region, user_pool_id, client_id,
             client_secret (and through it IAM Identity Center / SAML)
  oidc       any OpenID Connect server (Okta, Auth0, Keycloak, Authentik,
             Ping...): issuer, client_id, client_secret
  ldap       LDAP / Active Directory: url (ldap:// or ldaps://), start_tls,
             bind_dn, bind_password, base_dn, user_filter ({login} = what
             was typed), email_attr, name_attr, group_dn (required member)
Common options: name (the button), allowed_domains (only these email
domains), auto_approve (accounts from it skip the approval queue).
Redirect URI to register with an OAuth/OIDC provider:
<PUBLIC_URL>/auth/callback/<id>.

Who gets in: new accounts wait for an admin's approval (Users page), unless
their method auto-approves. ADMIN_EMAILS are approved admins as soon as
they sign in by any verified method. A fresh install with no admin offers
first-run setup, which needs SETUP_TOKEN (kept on the host, root-only).

Accounts and stored methods live in ClickHouse (AUTH_DB, default netview:
users, auth_methods) - no volume to keep. Sessions are signed cookies
(SESSION_SECRET), which also keys the encryption of stored secrets.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.parse

import jwt  # PyJWT
import requests
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from itsdangerous import BadSignature, URLSafeTimedSerializer

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
DB = os.environ.get("AUTH_DB", "netview")  # where accounts and stored methods live
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
METHODS = {m.strip() for m in os.environ.get("AUTH_METHODS", "builtin").split(",") if m.strip()}
SESSION_SECRET = os.environ.get("SESSION_SECRET") or secrets.token_urlsafe(48)  # unset: sessions end on restart
SETUP_TOKEN = os.environ.get("SETUP_TOKEN", "")
ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}
SECURE = (os.environ.get("SESSION_SECURE", "auto") == "true"
          or (os.environ.get("SESSION_SECURE", "auto") == "auto" and PUBLIC_URL.startswith("https://")))
SESSION_DAYS = int(os.environ.get("SESSION_DAYS", "7"))
CF_TEAM = os.environ.get("CF_ACCESS_TEAM", "")
CF_AUD = os.environ.get("CF_ACCESS_AUD", "")

ENABLED = "off" not in METHODS and bool(METHODS & {"builtin", "cloudflare"})
BUILTIN = "builtin" in METHODS
CLOUDFLARE = "cloudflare" in METHODS and bool(CF_TEAM and CF_AUD)

# Method types: label, the fields the Settings form asks for (secret ones
# encrypted, never sent back), and preset values.
F = lambda key, label, secret=False, required=True, hint="", kind="text": (  # noqa: E731
    {"key": key, "label": label, "secret": secret, "required": required, "hint": hint, "kind": kind})
TYPES = {
    "google": {"label": "Google", "fields": [F("client_id", "Client ID"), F("client_secret", "Client secret", True)],
               "preset": {"issuer": "https://accounts.google.com"}},
    "microsoft": {"label": "Microsoft Entra ID (Azure AD)",
                  "fields": [F("tenant", "Tenant ID", hint="your directory (tenant) ID for one organization; "
                               "'common' for any Microsoft account"),
                             F("client_id", "Application (client) ID"), F("client_secret", "Client secret", True)],
                  "preset": {"issuer": "https://login.microsoftonline.com/{tenant}/v2.0"}},
    "apple": {"label": "Apple", "fields": [F("client_id", "Services ID"), F("team_id", "Team ID"),
                                           F("key_id", "Key ID"), F("private_key", "Private key (.p8)", True, kind="textarea")],
              "preset": {"issuer": "https://appleid.apple.com", "scope": "name email", "response_mode": "form_post"}},
    "github": {"label": "GitHub", "fields": [F("client_id", "Client ID"), F("client_secret", "Client secret", True)],
               "preset": {}},
    "cognito": {"label": "AWS Cognito", "fields": [F("region", "Region", hint="e.g. ca-central-1"),
                                                   F("user_pool_id", "User pool ID"), F("client_id", "App client ID"),
                                                   F("client_secret", "App client secret", True, required=False)],
                "preset": {"issuer": "https://cognito-idp.{region}.amazonaws.com/{user_pool_id}"}},
    "oidc": {"label": "OpenID Connect (Okta, Auth0, Keycloak, Authentik...)",
             "fields": [F("issuer", "Issuer URL", hint="e.g. https://keycloak.example.com/realms/main"),
                        F("client_id", "Client ID"), F("client_secret", "Client secret", True, required=False)],
             "preset": {}},
    "ldap": {"label": "LDAP / Active Directory",
             "fields": [F("url", "Server URL", hint="ldaps://dc1.corp.example.com or ldap://...:389"),
                        F("start_tls", "Use StartTLS on ldap://", required=False, kind="checkbox"),
                        F("bind_dn", "Bind DN (service account)", required=False,
                          hint="e.g. CN=svc-lens,OU=Service,DC=corp,DC=example,DC=com - empty: anonymous search"),
                        F("bind_password", "Bind password", True, required=False),
                        F("base_dn", "Search base DN", hint="e.g. DC=corp,DC=example,DC=com"),
                        F("user_filter", "User filter", required=False,
                          hint="{login} = what the user typed. Default: "
                               "(|(mail={login})(userPrincipalName={login})(sAMAccountName={login})(uid={login}))"),
                        F("email_attr", "Email attribute", required=False, hint="default: mail"),
                        F("name_attr", "Name attribute", required=False, hint="default: displayName"),
                        F("group_dn", "Required group DN", required=False,
                          hint="only members of this group can sign in (memberOf)")],
             "preset": {}},
}
COMMON = [F("name", "Button / display name", required=False),
          F("allowed_domains", "Allowed email domains", required=False, hint="comma-separated, e.g. example.com - empty: any"),
          F("auto_approve", "Approve accounts from this method automatically", required=False, kind="checkbox")]
SECRET_KEYS = {f["key"] for t in TYPES.values() for f in t["fields"] if f["secret"]}
_fernet = Fernet(base64.urlsafe_b64encode(hashlib.sha256(("sentry-lens-settings:" + SESSION_SECRET).encode()).digest()))
_flow = URLSafeTimedSerializer(SESSION_SECRET, salt="sentry-lens-flow")


# ------------------------------------------------------------------ storage
DDL = [
    f"CREATE DATABASE IF NOT EXISTS {DB}",
    f"""CREATE TABLE IF NOT EXISTS {DB}.users (
        email String, name String, via LowCardinality(String), password String,
        role LowCardinality(String), status LowCardinality(String),
        created DateTime, last_login DateTime, version UInt64
    ) ENGINE = ReplacingMergeTree(version) ORDER BY email""",
    f"""CREATE TABLE IF NOT EXISTS {DB}.auth_methods (
        id String, config String, deleted UInt8, version UInt64
    ) ENGINE = ReplacingMergeTree(version) ORDER BY id""",
]
_cache = {"users": (0.0, {}), "methods": (0.0, {})}
_lock = threading.Lock()
_ready = [False]


def _ch(sql, data=None):
    r = requests.post(CH_URL, params={"query": sql} if data is not None else None,
                      data=(data if data is not None else sql).encode(), timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"ClickHouse: {r.text[:200]}")
    return r.text


def _rows(sql):
    if not _ready[0]:
        for d in DDL:
            _ch(d)
        _ready[0] = True
    return [json.loads(x) for x in _ch(sql + " FORMAT JSONEachRow").splitlines() if x]


def users(fresh=False):
    """Every account by email (cached a few seconds; deleted ones left out)."""
    with _lock:
        t, data = _cache["users"]
        if fresh or time.time() - t > 10:
            data = {u["email"]: u for u in _rows(f"SELECT email, name, via, password, role, status, toUInt32(created) AS created, toUInt32(last_login) AS last_login FROM {DB}.users FINAL WHERE status != 'deleted'")}
            _cache["users"] = (time.time(), data)
        return dict(data)


def save(user):
    """Write an account (a new version of its row)."""
    row = {"email": user["email"].lower(), "name": user.get("name", ""), "via": user.get("via", ""),
           "password": user.get("password", ""), "role": user.get("role", "user"),
           "status": user.get("status", "pending"), "created": int(user.get("created") or time.time()),
           "last_login": int(user.get("last_login") or 0), "version": time.time_ns()}
    _ch(f"INSERT INTO {DB}.users FORMAT JSONEachRow", json.dumps(row))
    users(fresh=True)
    return row


def has_admin():
    return any(u["role"] == "admin" and u["status"] == "approved" for u in users().values())


# ------------------------------------------------------------------ sign-in methods
def _seal(cfg):
    return {k: ("enc:" + _fernet.encrypt(str(v).encode()).decode()) if k in SECRET_KEYS and v else v
            for k, v in cfg.items()}


def _open(cfg):
    out = {}
    for k, v in cfg.items():
        if isinstance(v, str) and v.startswith("enc:"):
            try:
                v = _fernet.decrypt(v[4:].encode()).decode()
            except InvalidToken:  # sealed with another SESSION_SECRET - has to be entered again
                v = ""
        out[k] = v
    return out


def _complete(cfg, source):
    """A method's config with its type's preset and derived values."""
    t = TYPES[cfg["type"]]
    c = t["preset"] | {k: v for k, v in cfg.items() if v not in (None, "")}
    c["issuer"] = c.get("issuer", "").format(**{k: c.get(k, "") for k in ("tenant", "region", "user_pool_id")}) \
        if "{" in c.get("issuer", "") else c.get("issuer", "")
    if c["type"] == "microsoft" and not cfg.get("tenant"):
        c["issuer"] = t["preset"]["issuer"].replace("{tenant}", "common")
    c["name"] = c.get("name") or t["label"].split(" (")[0]
    c["source"] = source
    c["domains"] = [d.strip().lower().lstrip("@") for d in str(c.get("allowed_domains", "")).split(",") if d.strip()]
    c["auto_approve"] = str(c.get("auto_approve", "")).lower() in ("1", "true", "yes", "on")
    return c


def methods(fresh=False):
    """Every sign-in method by id: the deployment's (AUTH_PROVIDERS), then the stored ones."""
    with _lock:
        t, data = _cache["methods"]
        if not fresh and time.time() - t < 10:
            return dict(data)
    data = {}
    for p in json.loads(os.environ.get("AUTH_PROVIDERS") or "[]"):
        if p.get("type") in TYPES:
            p.setdefault("id", p["type"])
            data[p["id"]] = _complete(p, "config")
    try:
        for r in _rows(f"SELECT id, config FROM {DB}.auth_methods FINAL WHERE deleted = 0"):
            cfg = _open(json.loads(r["config"]))
            if cfg.get("type") in TYPES and r["id"] not in data:
                data[r["id"]] = _complete(cfg | {"id": r["id"]}, "settings")
    except RuntimeError:
        pass  # ClickHouse away - the deployment's methods still work
    with _lock:
        _cache["methods"] = (time.time(), data)
    return dict(data)


def store_method(mid, cfg, deleted=False):
    _rows("SELECT 1")  # tables exist
    _ch(f"INSERT INTO {DB}.auth_methods FORMAT JSONEachRow",
        json.dumps({"id": mid, "config": json.dumps(_seal(cfg)), "deleted": int(deleted), "version": time.time_ns()}))
    methods(fresh=True)


def signed_in_as(email, name="", via="", method=None):
    """An identity proved by a method / Cloudflare: its account, created the
    first time - approved for ADMIN_EMAILS (as admin) and auto-approving
    methods, pending otherwise."""
    email = email.lower()
    if method and method["domains"] and email.split("@")[-1] not in method["domains"]:
        raise ValueError(f"{email.split('@')[-1]} accounts can't sign in with {method['name']}")
    u = users().get(email)
    if not u:
        admin = email in ADMIN_EMAILS
        auto = admin or bool(method and method["auto_approve"])
        u = {"email": email, "name": name, "via": via, "role": "admin" if admin else "user",
             "status": "approved" if auto else "pending", "created": time.time()}
    elif email in ADMIN_EMAILS and (u["role"] != "admin" or u["status"] != "approved"):
        u |= {"role": "admin", "status": "approved"}
    elif method and method["auto_approve"] and u["status"] == "pending":
        u |= {"status": "approved"}
    u |= {"last_login": time.time(), "name": u.get("name") or name, "via": u.get("via") or via}
    return save(u)


# ------------------------------------------------------------------ passwords
def hash_password(pw):
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$16384$8$1$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def check_password(pw, stored):
    try:
        _, n, r, p, salt, h = stored.split("$")
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(got, base64.b64decode(h))
    except (ValueError, TypeError):
        return False


_fails = {}


def throttle(request):
    """At most 8 failed sign-ins per address in 5 minutes."""
    ip = request.client.host if request.client else "?"
    now = time.time()
    _fails[ip] = [t for t in _fails.get(ip, []) if now - t < 300]
    if len(_fails[ip]) >= 8:
        raise HTTPException(429, "too many attempts - wait a few minutes")
    return ip


def failed(ip):
    _fails.setdefault(ip, []).append(time.time())
    time.sleep(0.5)


# ------------------------------------------------------------------ LDAP
def _ldap_escape(s):
    return "".join(f"\\{ord(c):02x}" if c in "\\*()\0" else c for c in s)


def ldap_login(m, login, password):
    """Bind as the user found by the filter -> (email, name). ValueError if not."""
    import ldap3  # only needed when LDAP is used
    from ldap3.core.exceptions import LDAPException

    if not login or not password:
        raise ValueError("enter your username and password")
    try:
        server = ldap3.Server(m["url"], get_info=ldap3.NONE, connect_timeout=8)
        svc = ldap3.Connection(server, user=m.get("bind_dn") or None, password=m.get("bind_password") or None,
                               receive_timeout=10)
        if m.get("start_tls") and str(m["start_tls"]).lower() in ("1", "true", "on", "yes") and \
                m["url"].startswith("ldap://"):
            svc.open()
            svc.start_tls()
        if not svc.bind():
            raise ValueError(f"{m['name']}: the service account can't bind ({svc.result.get('description')})")
        flt = (m.get("user_filter") or
               "(|(mail={login})(userPrincipalName={login})(sAMAccountName={login})(uid={login}))")
        flt = flt.replace("{login}", _ldap_escape(login.strip()))
        email_attr, name_attr = m.get("email_attr") or "mail", m.get("name_attr") or "displayName"
        svc.search(m["base_dn"], flt, attributes=[email_attr, name_attr, "memberOf"], size_limit=2)
        if len(svc.entries) != 1:
            raise ValueError("unknown user")
        entry = svc.entries[0]
        user_dn = entry.entry_dn
        attrs = entry.entry_attributes_as_dict
        svc.unbind()
        if m.get("group_dn") and m["group_dn"].lower() not in [g.lower() for g in attrs.get("memberOf", [])]:
            raise ValueError(f"not a member of the group allowed to sign in")
        conn = ldap3.Connection(server, user=user_dn, password=password, receive_timeout=10)
        if m.get("start_tls") and str(m["start_tls"]).lower() in ("1", "true", "on", "yes") and \
                m["url"].startswith("ldap://"):
            conn.open()
            conn.start_tls()
        if not conn.bind():
            raise ValueError("wrong password")
        conn.unbind()
    except LDAPException as e:
        raise ValueError(f"{m['name']}: {type(e).__name__}: {e}")
    email = (attrs.get(email_attr) or [""])[0]
    if "@" not in str(email):
        raise ValueError(f"{m['name']}: this account has no email ({email_attr}) in the directory")
    return str(email), str((attrs.get(name_attr) or [""])[0])


def ldap_test(m):
    """Settings' Test button: can the service account bind and search?"""
    import ldap3
    server = ldap3.Server(m["url"], get_info=ldap3.NONE, connect_timeout=8)
    conn = ldap3.Connection(server, user=m.get("bind_dn") or None, password=m.get("bind_password") or None,
                            receive_timeout=10)
    if m.get("start_tls") and str(m["start_tls"]).lower() in ("1", "true", "on", "yes") and m["url"].startswith("ldap://"):
        conn.open()
        conn.start_tls()
    if not conn.bind():
        raise ValueError(f"bind failed: {conn.result.get('description')}")
    conn.search(m["base_dn"], "(objectClass=*)", search_scope=ldap3.BASE)
    ok = bool(conn.entries)
    conn.unbind()
    if not ok:
        raise ValueError("bound, but the search base wasn't found")
    return "bound and found the search base"


# ------------------------------------------------------------------ who is this
def _cloudflare_email(request):
    token = request.headers.get("cf-access-jwt-assertion") or request.cookies.get("CF_Authorization")
    if not token:
        return ""
    issuer = f"https://{CF_TEAM}" if "." in CF_TEAM else f"https://{CF_TEAM}.cloudflareaccess.com"
    try:
        key = _jwks(f"{issuer}/cdn-cgi/access/certs").get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=CF_AUD, issuer=issuer)
    except Exception:  # expired, forged, another app's
        return ""
    return str(claims.get("email") or "").lower()


def identify(request):
    """(account or None, how) for this request: the session, else a
    Cloudflare Access token. An account may still be pending or denied."""
    sess = request.session.get("user") if "session" in request.scope else None
    if sess and time.time() - sess.get("t", 0) < SESSION_DAYS * 86400:
        u = users().get(sess.get("email", ""))
        if u:
            return u, sess.get("via", "")
    if CLOUDFLARE:
        email = _cloudflare_email(request)
        if email:
            u = users().get(email)
            if not u or u.get("last_login", 0) < time.time() - 3600:  # once an hour is enough
                u = signed_in_as(email, via="cloudflare")
            return u, "cloudflare"
    return None, ""


def start_session(request, user, via):
    request.session["user"] = {"email": user["email"], "via": via, "t": time.time()}


# ------------------------------------------------------------------ OAuth / OIDC
_jwks_clients, _discovery = {}, {}


def _jwks(url):
    if url not in _jwks_clients:
        _jwks_clients[url] = jwt.PyJWKClient(url, cache_keys=True, lifespan=3600)
    return _jwks_clients[url]


def _meta(m):
    if m["issuer"] not in _discovery:
        r = requests.get(m["issuer"].rstrip("/") + "/.well-known/openid-configuration", timeout=15)
        r.raise_for_status()
        _discovery[m["issuer"]] = r.json()
    return _discovery[m["issuer"]]


def redirect_uri(request, mid):
    base = PUBLIC_URL or str(request.base_url).rstrip("/")
    return f"{base}/auth/callback/{mid}"


def _apple_secret(m):
    """Apple's client secret: a short-lived JWT signed with the .p8 key."""
    now = int(time.time())
    return jwt.encode({"iss": m["team_id"], "iat": now, "exp": now + 300, "aud": "https://appleid.apple.com",
                       "sub": m["client_id"]}, m["private_key"].replace("\\n", "\n"), algorithm="ES256",
                      headers={"kid": m["key_id"]})


def authorize_url(request, m):
    state, nonce, verifier = (secrets.token_urlsafe(24) for _ in range(3))
    flow = {"p": m["id"], "state": state, "nonce": nonce, "verifier": verifier}
    redirect = redirect_uri(request, m["id"])
    if m["type"] == "github":
        q = {"client_id": m["client_id"], "redirect_uri": redirect, "scope": "read:user user:email", "state": state}
        return "https://github.com/login/oauth/authorize?" + urllib.parse.urlencode(q), flow
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    q = {"client_id": m["client_id"], "redirect_uri": redirect, "response_type": "code",
         "scope": m.get("scope", "openid email profile"), "state": state, "nonce": nonce}
    if m["type"] != "apple":  # Apple doesn't do PKCE
        q |= {"code_challenge": challenge, "code_challenge_method": "S256"}
    if m.get("response_mode"):
        q["response_mode"] = m["response_mode"]
    return _meta(m)["authorization_endpoint"] + "?" + urllib.parse.urlencode(q), flow


def finish(request, m, params, flow):
    """The provider's answer -> (verified email, display name)."""
    if params.get("error"):
        raise ValueError(params.get("error_description") or params["error"])
    if not params.get("code") or not hmac.compare_digest(params.get("state", ""), flow.get("state", "")):
        raise ValueError("the sign-in expired or was tampered with - try again")
    redirect = redirect_uri(request, m["id"])

    if m["type"] == "github":
        tok = requests.post("https://github.com/login/oauth/access_token", headers={"Accept": "application/json"},
                            data={"client_id": m["client_id"], "client_secret": m.get("client_secret", ""),
                                  "code": params["code"], "redirect_uri": redirect}, timeout=15).json()
        if "access_token" not in tok:
            raise ValueError(tok.get("error_description", "GitHub refused the code"))
        h = {"Authorization": f"Bearer {tok['access_token']}", "Accept": "application/vnd.github+json"}
        me = requests.get("https://api.github.com/user", headers=h, timeout=15).json()
        mails = requests.get("https://api.github.com/user/emails", headers=h, timeout=15).json()
        email = next((x["email"] for x in mails if isinstance(x, dict) and x.get("primary") and x.get("verified")), "")
        if not email:
            raise ValueError("this GitHub account has no verified primary email")
        return email, me.get("name") or me.get("login") or ""

    meta = _meta(m)
    data = {"grant_type": "authorization_code", "code": params["code"], "redirect_uri": redirect,
            "client_id": m["client_id"]}
    auth = None
    if m["type"] == "apple":
        data["client_secret"] = _apple_secret(m)
    else:
        data["code_verifier"] = flow["verifier"]
        if m.get("client_secret"):
            if m["type"] == "cognito":  # Cognito wants the secret as HTTP basic auth
                auth = (m["client_id"], m["client_secret"])
            else:
                data["client_secret"] = m["client_secret"]
    tok = requests.post(meta["token_endpoint"], data=data, auth=auth, headers={"Accept": "application/json"},
                        timeout=15).json()
    if "id_token" not in tok:
        raise ValueError(tok.get("error_description") or tok.get("error") or "no ID token from the provider")
    key = _jwks(meta["jwks_uri"]).get_signing_key_from_jwt(tok["id_token"]).key
    claims = jwt.decode(tok["id_token"], key, algorithms=["RS256", "ES256"], audience=m["client_id"],
                        options={"verify_iss": False})
    issuer = meta.get("issuer", m["issuer"]).replace("{tenantid}", str(claims.get("tid", "")))  # Entra multi-tenant
    if claims.get("iss") != issuer:
        raise ValueError("the ID token's issuer doesn't match the provider")
    if claims.get("nonce") and not hmac.compare_digest(str(claims["nonce"]), flow["nonce"]):
        raise ValueError("the ID token's nonce doesn't match - try again")
    email = str(claims.get("email") or (claims.get("preferred_username") if m["type"] == "microsoft" else "") or "")
    if str(claims.get("email_verified", "true")).lower() == "false" or "@" not in email:
        raise ValueError("the provider gave no verified email for this account")
    name = claims.get("name") or claims.get("given_name") or ""
    if m["type"] == "apple" and params.get("user"):  # Apple sends the name once, on the first sign-in
        try:
            n = json.loads(params["user"]).get("name", {})
            name = " ".join(x for x in (n.get("firstName"), n.get("lastName")) if x)
        except ValueError:
            pass
    return email, name


# ------------------------------------------------------------------ routes
router = APIRouter()


def _same_origin(request):
    """Forms post from our own pages only (a cross-site form can't sign anyone in)."""
    origin = request.headers.get("origin") or request.headers.get("referer") or ""
    if origin and urllib.parse.urlsplit(origin).netloc != request.headers.get("host", ""):
        raise HTTPException(403, "cross-site request")


def _flow_cookie(resp, value=None):
    if value is None:
        resp.delete_cookie("sl_flow", path="/auth")
    else:  # Apple posts back cross-site: SameSite=None (HTTPS) so the cookie comes along
        resp.set_cookie("sl_flow", value, max_age=600, path="/auth", httponly=True, secure=SECURE,
                        samesite="none" if SECURE else "lax")


def _back(msg, extra=""):
    return RedirectResponse("/login?" + extra + "error=" + urllib.parse.quote(msg[:220]), status_code=303)


def _done(request, user, via):
    if user["status"] == "approved":
        start_session(request, user, via)
        return RedirectResponse("/", status_code=303)
    request.session["pending"] = user["email"]
    return RedirectResponse("/login?pending=1" if user["status"] == "pending" else "/login?denied=1", status_code=303)


@router.get("/auth/state")
def state(request: Request):
    """What the login page offers."""
    u, _ = identify(request) if ENABLED else (None, "")
    ms = methods() if BUILTIN else {}
    return {"enabled": ENABLED, "builtin": BUILTIN, "setup": BUILTIN and not has_admin(),
            "providers": [{"id": m["id"], "name": m["name"], "type": m["type"]}
                          for m in ms.values() if m["type"] != "ldap"],
            "directory": [m["name"] for m in ms.values() if m["type"] == "ldap"],
            "cloudflare": CLOUDFLARE, "signin_url": (PUBLIC_URL + "/") if CLOUDFLARE else "",
            "pending": request.session.get("pending", ""), "signed_in": bool(u and u["status"] == "approved")}


@router.get("/auth/login/{mid}")
def login(request: Request, mid: str):
    m = methods().get(mid)
    if not m or m["type"] == "ldap":
        raise HTTPException(404, "no such sign-in method")
    try:
        url, flow = authorize_url(request, m)
    except Exception as e:
        return _back(f"{m['name']}: {e}")
    resp = RedirectResponse(url, status_code=303)
    _flow_cookie(resp, _flow.dumps(flow))
    return resp


@router.api_route("/auth/callback/{mid}", methods=["GET", "POST"])
async def callback(request: Request, mid: str):
    m = methods().get(mid)
    if not m:
        raise HTTPException(404, "no such sign-in method")
    params = dict(request.query_params)
    if request.method == "POST":
        params |= {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
    try:
        flow = _flow.loads(request.cookies.get("sl_flow", ""), max_age=600)
        if flow.get("p") != mid:
            raise ValueError("the sign-in expired - try again")
        email, name = finish(request, m, params, flow)
        resp = _done(request, signed_in_as(email, name, mid, m), mid)
    except (BadSignature, ValueError, KeyError, requests.RequestException, jwt.PyJWTError) as e:
        resp = _back(f"{m['name']}: {'the sign-in expired - try again' if isinstance(e, BadSignature) else e}")
    _flow_cookie(resp)
    return resp


@router.post("/auth/local")
async def local_login(request: Request):
    """The password form: a local account, else each LDAP directory in turn."""
    _same_origin(request)
    if not BUILTIN:
        raise HTTPException(404, "password sign-in is off")
    ip = throttle(request)
    form = await request.form()
    login_name, pw = str(form.get("email", "")).strip(), str(form.get("password", ""))
    u = users().get(login_name.lower())
    if u and u.get("password") and check_password(pw, u["password"]):
        return _done(request, save(u | {"last_login": time.time()}), "password")
    problems = []
    for m in (m for m in methods().values() if m["type"] == "ldap"):
        try:
            email, name = ldap_login(m, login_name, pw)
            return _done(request, signed_in_as(email, name, m["id"], m), m["id"])
        except ValueError as e:
            if str(e) not in ("unknown user", "wrong password"):
                problems.append(str(e))
    failed(ip)
    return _back("wrong email/username or password" + (f" ({'; '.join(problems)})" if problems else ""))


@router.post("/auth/register")
async def register(request: Request):
    _same_origin(request)
    if not BUILTIN:
        raise HTTPException(404, "local accounts are off")
    ip = throttle(request)
    form = await request.form()
    email, pw, name = (str(form.get(k, "")).strip() for k in ("email", "password", "name"))
    email = email.lower()
    if "@" not in email or len(pw) < 10:
        return _back("use a valid email and a password of 10 characters or more", "register=1&")
    if email in users():
        failed(ip)
        return _back("that email already has an account - sign in")
    u = save({"email": email, "name": name, "via": "password", "password": hash_password(pw),
              "role": "user", "status": "pending", "created": time.time()})
    return _done(request, u, "password")


@router.post("/auth/setup")
async def setup(request: Request):
    """First run: the first admin, with the setup token from the host."""
    _same_origin(request)
    if not BUILTIN or has_admin():
        raise HTTPException(403, "already set up")
    ip = throttle(request)
    form = await request.form()
    token, email, pw, name = (str(form.get(k, "")).strip() for k in ("token", "email", "password", "name"))
    if not SETUP_TOKEN or not hmac.compare_digest(token, SETUP_TOKEN):
        failed(ip)
        return _back("wrong setup token")
    if "@" not in email or len(pw) < 10:
        return _back("use a valid email and a password of 10 characters or more")
    u = save({"email": email.lower(), "name": name, "via": "password", "password": hash_password(pw),
              "role": "admin", "status": "approved", "created": time.time(), "last_login": time.time()})
    return _done(request, u, "password")


@router.get("/auth/logout")
def logout(request: Request):
    via = (request.session.get("user") or {}).get("via", "")
    request.session.clear()
    if CLOUDFLARE and PUBLIC_URL and (via == "cloudflare" or not BUILTIN):
        return RedirectResponse(f"{PUBLIC_URL}/cdn-cgi/access/logout", status_code=303)
    return RedirectResponse("/login", status_code=303)


# ------------------------------------------------------------------ admin: users
def require_admin(request):
    u = getattr(request.state, "user", None)
    if not u or u["role"] != "admin":
        raise HTTPException(403, "admins only")
    return u


@router.get("/api/users")
def list_users(request: Request):
    require_admin(request)
    rows = sorted(users(fresh=True).values(),
                  key=lambda u: ({"pending": 0, "approved": 1}.get(u["status"], 2), u["email"]))
    names = {m["id"]: m["name"] for m in methods().values()} | {"password": "Password", "cloudflare": "Cloudflare Access"}
    return {"users": [{k: u[k] for k in ("email", "name", "role", "status", "created", "last_login")}
                      | {"via": names.get(u["via"], u["via"]), "has_password": bool(u.get("password"))} for u in rows]}


@router.post("/api/users")
async def add_user(request: Request):
    """An admin adds an account directly (approved) - with a password, or
    for someone who'll sign in through a provider or directory."""
    require_admin(request)
    body = await request.json()
    email, pw = str(body.get("email", "")).strip().lower(), str(body.get("password", ""))
    if "@" not in email or (pw and len(pw) < 10):
        raise HTTPException(400, "a valid email, and a password of 10 characters or more (or none, for provider sign-in)")
    if email in users(fresh=True):
        raise HTTPException(409, "that email already has an account")
    save({"email": email, "name": str(body.get("name", "")), "via": "password" if pw else "",
          "password": hash_password(pw) if pw else "", "role": "admin" if body.get("role") == "admin" else "user",
          "status": "approved", "created": time.time()})
    return {"ok": True}


@router.post("/api/users/{email}/{action}")
def change_user(request: Request, email: str, action: str):
    me = require_admin(request)
    u = users(fresh=True).get(email.lower())
    if not u:
        raise HTTPException(404, "no such account")
    if u["email"] == me["email"] and action in ("deny", "user", "delete"):
        raise HTTPException(400, "you can't lock yourself out - ask another admin")
    change = {"approve": {"status": "approved"}, "deny": {"status": "denied"}, "admin": {"role": "admin"},
              "user": {"role": "user"}, "delete": {"status": "deleted"}}.get(action)
    if change is None:
        raise HTTPException(400, "unknown action")
    save(u | change)
    return {"ok": True}


# ------------------------------------------------------------------ admin: sign-in methods
def _public(m, request):
    """A method for the Settings page: secrets only say whether they're set."""
    t = TYPES[m["type"]]
    out = {"id": m["id"], "type": m["type"], "type_label": t["label"], "source": m["source"],
           "callback": redirect_uri(request, m["id"]) if m["type"] != "ldap" else ""}
    for f in t["fields"] + COMMON:
        v = m.get(f["key"], "")
        out[f["key"]] = bool(v) if f["secret"] else (bool(v) if f["kind"] == "checkbox" else v)
    out["auto_approve"], out["allowed_domains"] = m["auto_approve"], ", ".join(m["domains"])
    return out


@router.get("/api/settings/auth")
def get_auth_settings(request: Request):
    require_admin(request)
    return {"methods": [_public(m, request) for m in methods(fresh=True).values()],
            "types": {k: {"label": t["label"], "fields": t["fields"]} for k, t in TYPES.items()}, "common": COMMON,
            "callback_base": redirect_uri(request, "<id>").replace("<id>", ""),
            "modes": sorted(METHODS), "public_url": PUBLIC_URL}


@router.put("/api/settings/auth/{mid}")
async def put_auth_method(request: Request, mid: str):
    require_admin(request)
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", mid):
        raise HTTPException(400, "the id is lowercase letters, digits and dashes (it's part of the callback URL)")
    cur = methods(fresh=True).get(mid)
    if cur and cur["source"] == "config":
        raise HTTPException(409, "this method comes from the deployment config - change it there")
    body = await request.json()
    kind = body.get("type") or (cur or {}).get("type")
    if kind not in TYPES:
        raise HTTPException(400, f"type must be one of {list(TYPES)}")
    cfg = {"type": kind}
    for f in TYPES[kind]["fields"] + COMMON:
        v = body.get(f["key"])
        if f["kind"] == "checkbox":
            v = bool(v)
        elif f["secret"] and not v and cur:  # empty = keep the stored secret
            v = cur.get(f["key"], "")
        v = v.strip() if isinstance(v, str) else v
        if f["required"] and not v:
            raise HTTPException(400, f"{f['label']} is required")
        cfg[f["key"]] = v
    store_method(mid, cfg)
    return {"ok": True}


@router.delete("/api/settings/auth/{mid}")
def delete_auth_method(request: Request, mid: str):
    require_admin(request)
    cur = methods(fresh=True).get(mid)
    if not cur:
        raise HTTPException(404, "no such method")
    if cur["source"] == "config":
        raise HTTPException(409, "this method comes from the deployment config - remove it there")
    store_method(mid, {}, deleted=True)
    return {"ok": True}


@router.post("/api/settings/auth/{mid}/test")
def test_auth_method(request: Request, mid: str):
    """Reach the provider: OIDC discovery, GitHub's API, or an LDAP bind."""
    require_admin(request)
    m = methods(fresh=True).get(mid)
    if not m:
        raise HTTPException(404, "no such method")
    try:
        if m["type"] == "ldap":
            return {"ok": True, "detail": ldap_test(m)}
        if m["type"] == "github":
            requests.get("https://github.com/login/oauth/authorize", timeout=10).raise_for_status()
            return {"ok": True, "detail": "GitHub reachable - finish with a real sign-in"}
        _discovery.pop(m["issuer"], None)
        meta = _meta(m)
        return {"ok": True, "detail": f"discovery OK ({meta.get('issuer')}) - finish with a real sign-in"}
    except Exception as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"[:300]}


def me_json(request):
    u = getattr(request.state, "user", None)
    via = getattr(request.state, "via", "")
    return {"auth": ENABLED, "email": u["email"] if u else "", "name": (u or {}).get("name", ""),
            "role": (u or {}).get("role", ""), "via": via, "logout": "/auth/logout" if ENABLED else "",
            "pending": sum(1 for x in users().values() if x["status"] == "pending")
            if u and u["role"] == "admin" else 0}


def denied(request, user):
    """The answer for a request that isn't signed in (or not approved)."""
    if request.url.path.startswith("/api/"):
        if not user:
            return JSONResponse({"detail": "sign in first"}, status_code=401)
        return JSONResponse({"detail": "waiting for an admin's approval" if user["status"] == "pending"
                             else "this account isn't allowed"}, status_code=403)
    if user:
        request.session["pending"] = user["email"]
        return RedirectResponse("/login?pending=1" if user["status"] == "pending" else "/login?denied=1",
                                status_code=303)
    return RedirectResponse("/login", status_code=303)
