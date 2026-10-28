"""Sentry Lens: its vault - a Vaultwarden (Bitwarden-compatible) server, used
as the password manager for the logins Sentry Lens itself needs (the
read-only accounts its collectors inventory machines with).

Bitwarden encrypts everything on the client: this module is that client, for
one account - Sentry Lens's service account - and one organization, "Sentry
Lens", whose collection holds the machine logins. People get to them with
their own Vaultwarden accounts (any Bitwarden app), as members of that
organization: Sentry Lens invites the admins and confirms them once they've
registered (it encrypts the organization's key with their public key).

  master key   PBKDF2-SHA256(password, email) - or Argon2id
  user key     64 random bytes (AES-256 + HMAC-SHA256 keys), stored by the
               server encrypted with the stretched master key ("2." strings)
  RSA keys     the account's key pair; an organization's key reaches its
               members encrypted with their public key ("4." strings)

Used by the app (vault_sync, the collectors' credentials) and by the
playbooks (deploy/playbooks/vaultwarden.yml, readonly_accounts.yml) through
its command line:  python3 vault.py setup|put|get|ssh-key|admin-hash  (JSON on stdin and stdout).
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import uuid

import requests
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600000
TIMEOUT = 30


class VaultError(Exception):
    pass


# ------------------------------------------------------------------ crypto
def b64(b):
    return base64.b64encode(b).decode()


def unb64(s):
    return base64.b64decode(s)


def master_key(password, email, kdf=0, iterations=PBKDF2_ITERATIONS, memory=64, parallelism=4):
    salt = email.strip().lower().encode()
    if kdf == 0:
        return PBKDF2HMAC(hashes.SHA256(), 32, salt, iterations).derive(password.encode())
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id  # cryptography 44+
    return Argon2id(salt=hashlib.sha256(salt).digest(), length=32, iterations=iterations,
                    lanes=parallelism, memory_cost=memory * 1024).derive(password.encode())


def password_hash(mkey, password):
    """What the server sees instead of the master password."""
    return b64(PBKDF2HMAC(hashes.SHA256(), 32, password.encode(), 1).derive(mkey))


def stretch(mkey):
    """The master key as an AES key + an HMAC key (HKDF-Expand)."""
    return (HKDFExpand(hashes.SHA256(), 32, b"enc").derive(mkey) + HKDFExpand(hashes.SHA256(), 32, b"mac").derive(mkey))


def enc(data, key):
    """AES-256-CBC + HMAC-SHA256 ("2." EncString) with a 64-byte key."""
    if isinstance(data, str):
        data = data.encode()
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    e = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    ct = e.update(p.update(data) + p.finalize()) + e.finalize()
    mac = hmac.new(key[32:], iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


def dec(s, key, private_key=None):
    """An EncString: "2." with a 64-byte key, "4." / "6." with an RSA private key - bytes."""
    if s is None:
        return None
    kind, _, body = s.partition(".")
    parts = body.split("|")
    if kind == "2":
        iv, ct, mac = (unb64(p) for p in parts)
        if not hmac.compare_digest(hmac.new(key[32:], iv + ct, hashlib.sha256).digest(), mac):
            raise VaultError("an encrypted value doesn't check out (wrong key?)")
        d = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).decryptor()
        u = padding.PKCS7(128).unpadder()
        return u.update(d.update(ct) + d.finalize()) + u.finalize()
    if kind in ("4", "6") and private_key is not None:
        return private_key.decrypt(unb64(parts[0]), apad.OAEP(apad.MGF1(hashes.SHA1()), hashes.SHA1(), None))
    raise VaultError(f"an encrypted value of a kind this client doesn't read ({kind})")


def dec_str(s, key):
    v = dec(s, key)
    return v.decode() if v is not None else None


def rsa_enc(data, public_der):
    pub = serialization.load_der_public_key(public_der)
    return "4." + b64(pub.encrypt(data, apad.OAEP(apad.MGF1(hashes.SHA1()), hashes.SHA1(), None)))


def new_keypair(key):
    """An RSA-2048 pair: (public key, base64 DER) and (private key encrypted with key)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return b64(pub), enc(der, key)


# ------------------------------------------------------------------ the server
class Vault:
    """One account on a Vaultwarden server, signed in."""

    def __init__(self, url, email, password, verify=True):
        self.url, self.email, self.password = url.rstrip("/"), email.strip().lower(), password
        self.s = requests.Session()
        self.s.verify = verify
        # As a Bitwarden client says who it is (Vaultwarden logs an error for each request without).
        self.s.headers.update({"User-Agent": "Sentry Lens", "Bitwarden-Client-Name": "cli",
                               "Bitwarden-Client-Version": "2025.1.0", "Device-Type": "25"})
        self.token = self.user_key = self.private_key = self.public_der = None

    # -- HTTP
    def call(self, method, path, **kw):
        h = kw.pop("headers", {})
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        r = self.s.request(method, self.url + path, headers=h, timeout=TIMEOUT, **kw)
        if r.status_code >= 400:
            try:
                msg = r.json().get("message") or r.json().get("error_description") or r.text
            except ValueError:
                msg = r.text
            raise VaultError(f"{method} {path}: HTTP {r.status_code} {str(msg)[:300]}")
        return r.json() if r.content and "json" in r.headers.get("content-type", "") else {}

    def kdf(self):
        p = self.call("POST", "/identity/accounts/prelogin", json={"email": self.email})
        return (p.get("kdf", p.get("Kdf", 0)), p.get("kdfIterations", p.get("KdfIterations", PBKDF2_ITERATIONS)),
                p.get("kdfMemory", p.get("KdfMemory")) or 64, p.get("kdfParallelism", p.get("KdfParallelism")) or 4)

    # -- account
    def register(self, name="Sentry Lens"):
        """A new account (the server lets this email in: invited, or sign-ups open)."""
        mkey = master_key(self.password, self.email)
        ukey = os.urandom(64)
        pub, priv = new_keypair(ukey)
        body = {"email": self.email, "name": name, "masterPasswordHash": password_hash(mkey, self.password),
                "masterPasswordHint": None, "key": enc(ukey, stretch(mkey)), "kdf": 0, "kdfIterations": PBKDF2_ITERATIONS,
                "keys": {"publicKey": pub, "encryptedPrivateKey": priv}}
        try:
            self.call("POST", "/identity/accounts/register", json=body)
        except VaultError as e:
            if "HTTP 404" not in str(e):
                raise
            self.call("POST", "/api/accounts/register", json=body)  # older servers

    def login(self):
        kdf, it, mem, par = self.kdf()
        mkey = master_key(self.password, self.email, kdf, it, mem, par)
        form = {"grant_type": "password", "username": self.email, "password": password_hash(mkey, self.password),
                "scope": "api offline_access", "client_id": "cli", "deviceType": "25",
                "deviceIdentifier": str(uuid.uuid5(uuid.NAMESPACE_URL, f"sentrylens:{self.url}:{self.email}")),
                "deviceName": "sentrylens"}
        self.token = None
        t = self.call("POST", "/identity/connect/token", data=form)
        self.token = t["access_token"]
        self.user_key = dec(t.get("Key") or t.get("key"), stretch(mkey))
        priv = dec(t.get("PrivateKey") or t.get("privateKey"), self.user_key)
        self.private_key = serialization.load_der_private_key(priv, None)
        self.public_der = self.private_key.public_key().public_bytes(serialization.Encoding.DER,
                                                                     serialization.PublicFormat.SubjectPublicKeyInfo)
        return self

    def sync(self):
        return self.call("GET", "/api/sync?excludeDomains=true")

    # -- the organization
    def org(self, name):
        """(id, key) of the organization of that name the account belongs to - or None."""
        for o in self.sync().get("profile", {}).get("organizations", []):
            if o.get("name") == name and o.get("key"):
                return o["id"], dec(o["key"], None, self.private_key)
        return None

    def make_org(self, name, collection):
        okey = os.urandom(64)
        pub, priv = new_keypair(okey)
        self.call("POST", "/api/organizations", json={
            "name": name, "billingEmail": self.email, "planType": 0, "collectionName": enc(collection, okey),
            "key": rsa_enc(okey, self.public_der), "keys": {"publicKey": pub, "encryptedPrivateKey": priv}})
        return self.org(name)

    def collection(self, org_id, okey, name):
        for c in self.call("GET", f"/api/organizations/{org_id}/collections").get("data", []):
            if dec_str(c["name"], okey) == name:
                return c["id"]
        return self.call("POST", f"/api/organizations/{org_id}/collections",
                         json={"name": enc(name, okey), "groups": [], "users": []})["id"]

    def members(self, org_id):
        return self.call("GET", f"/api/organizations/{org_id}/users").get("data", [])

    def invite(self, org_id, email, collection_id):
        self.call("POST", f"/api/organizations/{org_id}/users/invite", json={
            "emails": [email], "type": 1, "accessAll": True, "groups": [], "permissions": {},
            "collections": [{"id": collection_id, "readOnly": False, "hidePasswords": False, "manage": True}]})

    def confirm(self, org_id, okey, member):
        """A member who accepted: the organization's key, encrypted with their public key."""
        pub = self.call("GET", f"/api/users/{member['userId']}/public-key")
        key = rsa_enc(okey, unb64(pub.get("publicKey") or pub.get("PublicKey")))
        self.call("POST", f"/api/organizations/{org_id}/users/{member['id']}/confirm", json={"key": key})

    # -- items
    def items(self, org_id, okey):
        """{name: item} of the organization's logins, decrypted."""
        out = {}
        for c in self.call("GET", f"/api/ciphers/organization-details?organizationId={org_id}").get("data", []):
            if c.get("type") != 1 or c.get("deletedDate"):
                continue
            lg = c.get("login") or {}
            out[dec_str(c["name"], okey)] = {
                "id": c["id"], "username": dec_str(lg.get("username"), okey), "password": dec_str(lg.get("password"), okey),
                "uris": [dec_str(u.get("uri"), okey) for u in lg.get("uris") or []], "notes": dec_str(c.get("notes"), okey),
                "fields": {dec_str(f.get("name"), okey): dec_str(f.get("value"), okey) for f in c.get("fields") or []},
                "revision": c.get("revisionDate")}
        return out

    def put(self, org_id, okey, collection_id, item, existing=None):
        """Create or update a login: {name, username, password, uri, notes, fields: {name: value}} (fields hidden)."""
        cipher = {"type": 1, "organizationId": org_id, "name": enc(item["name"], okey),
                  "notes": enc(item["notes"], okey) if item.get("notes") else None, "favorite": False, "reprompt": 0,
                  "login": {"username": enc(item.get("username", ""), okey),
                            "password": enc(item["password"], okey) if item.get("password") else None,
                            "uris": [{"uri": enc(item["uri"], okey), "match": None}] if item.get("uri") else []},
                  "fields": [{"type": 1, "name": enc(k, okey), "value": enc(v, okey)} for k, v in (item.get("fields") or {}).items()]}
        if existing:
            self.call("PUT", f"/api/ciphers/{existing['id']}", json=cipher | {"lastKnownRevisionDate": existing.get("revision")})
            return existing["id"]
        return self.call("POST", "/api/ciphers/create", json={"cipher": cipher, "collectionIds": [collection_id]})["id"]


def admin_invite(url, admin_token, email, verify=True):
    """Invite an email through the admin panel (sign-ups stay closed)."""
    s = requests.Session()
    s.verify = verify
    r = s.post(url.rstrip("/") + "/admin", data={"token": admin_token}, timeout=TIMEOUT, allow_redirects=False)
    if r.status_code >= 400 or "VW_ADMIN" not in s.cookies:
        raise VaultError(f"the admin panel didn't take the token (HTTP {r.status_code})")
    r = s.post(url.rstrip("/") + "/admin/invite", json={"email": email}, timeout=TIMEOUT)
    if r.status_code >= 400 and "already exists" not in r.text.lower():
        raise VaultError(f"admin invite: HTTP {r.status_code} {r.text[:200]}")


# ------------------------------------------------------------------ the setup
def setup(c):
    """The service account (invited, registered once), the organization and
    its collection, the admins invited and - once registered - confirmed.
    {url, admin_token, email, password, org, collection, admins: [...], verify}."""
    v = Vault(c["url"], c["email"], c["password"], c.get("verify", True))
    try:
        v.login()
        made = False
    except VaultError:
        admin_invite(c["url"], c["admin_token"], c["email"], c.get("verify", True))
        v.register()
        v.login()
        made = True
    org = v.org(c["org"]) or v.make_org(c["org"], c["collection"])
    org_id, okey = org
    col = v.collection(org_id, okey, c["collection"])
    members = {m["email"].lower(): m for m in v.members(org_id)}
    invited, confirmed = [], []
    for e in [a.strip().lower() for a in c.get("admins") or [] if a.strip()]:
        if e == v.email:
            continue
        if e not in members:
            v.invite(org_id, e, col)
            invited.append(e)
        elif members[e].get("status") == 1:  # accepted (registered), not confirmed yet
            v.confirm(org_id, okey, members[e])
            confirmed.append(e)
    return {"account_created": made, "org_id": org_id, "collection_id": col, "invited": invited, "confirmed": confirmed,
            "members": {e: {0: "invited", 1: "accepted", 2: "confirmed"}.get(m.get("status"), str(m.get("status")))
                        for e, m in members.items()}}


def open_org(c):
    v = Vault(c["url"], c["email"], c["password"], c.get("verify", True)).login()
    org = v.org(c["org"])
    if not org:
        raise VaultError(f"the account isn't in the organization {c['org']!r} - run vaultwarden.yml")
    return v, org[0], org[1], v.collection(org[0], org[1], c["collection"])


def put_items(c):
    """{..., items: [{name, username, password, uri, notes, fields}], create_only} -
    created or updated by name (create_only: one already there is left as it is)."""
    v, org_id, okey, col = open_org(c)
    have = v.items(org_id, okey)
    done = {}
    for it in c.get("items") or []:
        old = have.get(it["name"])
        if old and c.get("create_only"):
            done[it["name"]] = "kept (already in the vault)"
            continue
        same = old and old["username"] == it.get("username", "") and old["password"] == (it.get("password") or None) \
            and old["fields"] == (it.get("fields") or {}) and old["uris"] == ([it["uri"]] if it.get("uri") else [])
        done[it["name"]] = "unchanged" if same else ("updated" if old else "created")
        if not same:
            v.put(org_id, okey, col, it, old)
    return done


def get_items(c):
    v, org_id, okey, _ = open_org(c)
    return v.items(org_id, okey)


SSH_KEY_ITEM = "SSH key ({user})"


def ssh_key(c):
    """The read-only accounts' SSH key: made once (Ed25519) and kept only in
    the vault - {public_key}. {..., user}."""
    v, org_id, okey, col = open_org(c)
    name = SSH_KEY_ITEM.format(user=c["user"])
    have = v.items(org_id, okey).get(name)
    if have and have["fields"].get("public_key"):
        return {"public_key": have["fields"]["public_key"], "created": False}
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + f" {c['user']}@sentrylens"
    v.put(org_id, okey, col, {"name": name, "username": c["user"], "notes": "The read-only accounts' SSH key (readonly_accounts.yml).",
                              "fields": {"private_key": priv, "public_key": pub}}, have)
    return {"public_key": pub, "created": True}


def self_signed(c):
    """The vault's certificate (its own CA, ten years): {cn, ips, names} -> {cert, key} (PEM)."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, c["cn"])])
    now = datetime.datetime.now(datetime.timezone.utc)
    san = [x509.IPAddress(ipaddress.ip_address(i)) for i in c.get("ips") or []] + [x509.DNSName(n) for n in c.get("names") or []]
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return {"cert": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption()).decode()}


def admin_hash(c):
    """The admin token as Vaultwarden wants it: an Argon2id PHC string (its documented settings)."""
    from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    salt = os.urandom(16)
    h = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65540).derive(c["token"].encode())
    nopad = lambda b: base64.b64encode(b).decode().rstrip("=")  # noqa: E731
    return {"hash": f"$argon2id$v=19$m=65540,t=3,p=4${nopad(salt)}${nopad(h)}"}


if __name__ == "__main__":
    # The playbooks' way in: the settings (secrets included) on stdin, never on the command line.
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        conf = json.load(sys.stdin)
        out = {"setup": setup, "put": put_items, "get": get_items, "ssh-key": ssh_key, "self-signed": self_signed,
               "admin-hash": admin_hash}[cmd](conf)
    except KeyError:
        sys.exit("usage: vault.py setup|put|get|ssh-key|admin-hash < settings.json")
    except (VaultError, requests.RequestException) as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
    print(json.dumps(out))
