#!/usr/bin/env python3
"""SimpleFIN -> Firefly III daily sync (fin.aktasolutions.com).

Runs inside the ansible-gui container (so it can read the vault):
    docker exec -w /ansible ansible-gui-1 python3 scripts/firefly_simplefin_sync.py [--dry-run]
Scheduled from the `claude` user's crontab on 192.168.3.8.

Secrets come from inventory/host_vars/fin.aktasolutions.com/vault.yml:
    vault_api_token             Firefly III personal access token
    vault_simplefin_access_url  SimpleFIN access URL (from a claimed setup token)

Each run asks SimpleFIN for the last LOOKBACK_DAYS and creates in Firefly every
transaction it doesn't have yet - matched on SimpleFIN's transaction id, stored
as the Firefly "external ID", so re-runs never duplicate anything. Firefly's own
rules run on each new transaction (categories etc.). Nothing is touched while
SimpleFIN has no transactions (e.g. the bank connection needs a re-login).

Accounts are created in Firefly once, the first time they have transactions,
with an opening balance that makes Firefly's balance match the bank's. Which
account is business / personal is set in ACCOUNTS below (by last 4 digits).
"""
import json
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

import requests

sys.path.insert(0, "/ansible")
from gui.app import HOST_VARS_DIR, read_vault  # noqa: E402

FIREFLY = "http://192.168.3.8:8080"
LOOKBACK_DAYS = 45          # SimpleFIN's recommended maximum per request
TZ = ZoneInfo("America/Toronto")   # bank days, as BMO shows them
TAG_IMPORTED = "simplefin"
# Last 4 digits of the bank account -> (Firefly account name, business/personal tag)
ACCOUNTS = {
    "3907": ("BMO Chequing (Akta Solutions)", "business"),
    "5348": ("BMO Savings (Akta Solutions)", "business"),
    "8138": ("BMO Joint - Other 1 PERSO", "personal"),
}
DRY = "--dry-run" in sys.argv


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}", flush=True)


class Firefly:
    def __init__(self, token):
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/vnd.api+json",
                               "Content-Type": "application/json"})

    def get_all(self, path, **params):
        page, out = 1, []
        while True:
            r = self.s.get(FIREFLY + path, params={**params, "page": page, "limit": 200}, timeout=60)
            r.raise_for_status()
            d = r.json()
            out += d.get("data", [])
            if page >= d.get("meta", {}).get("pagination", {}).get("total_pages", 1):
                return out
            page += 1

    def post(self, path, body):
        if DRY:
            log(f"  [dry-run] POST {path} {json.dumps(body)[:160]}")
            return {"data": {"id": "dry"}}
        r = self.s.post(FIREFLY + path, json=body, timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(f"POST {path}: {r.status_code} {r.text[:300]}")
        return r.json()


def simplefin_accounts(access_url):
    u = urlsplit(access_url)
    r = requests.get(f"{u.scheme}://{u.hostname}{u.path}/accounts", auth=(u.username, u.password),
                     params={"start-date": int(time.time()) - LOOKBACK_DAYS * 86400}, timeout=180)
    r.raise_for_status()
    d = r.json()
    for e in d.get("errors", []):
        if "recommended range" not in e:
            log(f"SimpleFIN says: {e}")
    return d.get("accounts", [])


def ensure_account(ff, existing, sf_acc, name, tag):
    """Firefly asset account for this SimpleFIN account (found by the id in its notes)."""
    marker = f"simplefin:{sf_acc['id']}"
    for a in existing:
        if marker in (a["attributes"].get("notes") or ""):
            return a["id"]
    tx = sf_acc.get("transactions", [])
    opening = float(sf_acc["balance"]) - sum(float(t["amount"]) for t in tx)
    first = min(t["posted"] for t in tx)
    body = {"name": name, "type": "asset", "account_role": "defaultAsset", "currency_code": sf_acc.get("currency", "CAD"),
            "opening_balance": f"{opening:.2f}",
            "opening_balance_date": (datetime.fromtimestamp(first, TZ) - timedelta(days=1)).strftime("%Y-%m-%d"),
            "notes": f"{marker}\n{sf_acc['org'].get('name', '')} - {sf_acc['name']} ({tag}). Synced from SimpleFIN by "
                     f"ansible-runner scripts/firefly_simplefin_sync.py"}
    acc_id = ff.post("/api/v1/accounts", body)["data"]["id"]
    log(f"created Firefly account '{name}' (opening balance {opening:.2f})")
    return acc_id


def main():
    v = read_vault(HOST_VARS_DIR / "fin.aktasolutions.com" / "vault.yml")
    ff = Firefly(v["vault_api_token"])
    accounts = simplefin_accounts(v["vault_simplefin_access_url"])
    total = sum(len(a.get("transactions", [])) for a in accounts)
    if not total:
        newest = max((int(a.get("balance-date", 0)) for a in accounts), default=0)
        log(f"no transactions from SimpleFIN (bank data as of {datetime.fromtimestamp(newest):%Y-%m-%d}) - nothing to do")
        return 0

    existing_accounts = ff.get_all("/api/v1/accounts", type="asset")
    created = skipped = 0
    for sf in accounts:
        txs = sf.get("transactions", [])
        if not txs:
            continue
        digits = (re.search(r"\((\d{4})\)", sf["name"]) or re.search(r"(\d{4})$", sf["name"]) or [None, ""])[1]
        name, tag = ACCOUNTS.get(digits, (f"{sf['org'].get('name', 'Bank')} {sf['name']}", "personal"))
        acc_id = ensure_account(ff, existing_accounts, sf, name, tag)
        start = (datetime.fromtimestamp(min(t["posted"] for t in txs), TZ) - timedelta(days=2)).strftime("%Y-%m-%d")
        have = set()
        if acc_id != "dry":
            end = (datetime.now(TZ) + timedelta(days=2)).strftime("%Y-%m-%d")   # Firefly wants both
            for j in ff.get_all(f"/api/v1/accounts/{acc_id}/transactions", start=start, end=end):
                for split in j["attributes"]["transactions"]:
                    if split.get("external_id"):
                        have.add(split["external_id"])
        for t in sorted(txs, key=lambda t: t["posted"]):
            ext = f"simplefin:{t['id']}"
            if ext in have:
                skipped += 1
                continue
            amount = float(t["amount"])
            payee = (t.get("payee") or t.get("description") or "Unknown").strip()[:255]
            split = {"type": "withdrawal" if amount < 0 else "deposit",
                     "date": datetime.fromtimestamp(t["posted"], TZ).strftime("%Y-%m-%d"),
                     "amount": f"{abs(amount):.2f}", "currency_code": sf.get("currency", "CAD"),
                     "description": (t.get("description") or payee).strip()[:255],
                     "external_id": ext, "tags": [tag, TAG_IMPORTED],
                     "notes": t.get("memo") or None}
            if amount < 0:
                split.update(source_id=acc_id, destination_name=payee)
            else:
                split.update(source_name=payee, destination_id=acc_id)
            try:
                ff.post("/api/v1/transactions", {"error_if_duplicate_hash": True, "apply_rules": True,
                                                 "fire_webhooks": True, "transactions": [split]})
                created += 1
            except RuntimeError as e:
                if "Duplicate of transaction" in str(e):
                    skipped += 1
                else:
                    log(f"FAILED {split['date']} {split['amount']} {split['description']}: {e}")
    log(f"done: {created} new transaction(s), {skipped} already in Firefly")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # one line in the log, not a traceback with URLs
        log(f"ERROR: {type(e).__name__}: {str(e)[:300]}")
        sys.exit(1)
