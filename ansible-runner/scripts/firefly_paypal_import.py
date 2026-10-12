#!/usr/bin/env python3
"""PayPal activity exports -> Firefly III.

    docker exec -w /ansible ansible-gui-1 python3 scripts/firefly_paypal_import.py [--dry-run]

Reads every *.csv in /ansible/gui-data/paypal (= gui/data/paypal on 192.168.3.8; PayPal
-> Activity -> Download, CSV, any period; overlapping exports are fine). Each completed
payment / refund becomes one record; the same payment in two exports counts once.

  Before the bank data starts (first BMO transaction from SimpleFIN):
      imported into the asset account "PayPal (history)" - payments as withdrawals, refunds as
      deposits, USD charges at the CAD amount the card was billed (USD kept as the
      foreign amount). Firefly's rules run on each, so categories, business/personal
      and subscription links follow the same rules as the bank transactions.
  From the bank data on:
      NOT imported (the money already shows on the BMO account as "PAYPAL ...");
      instead the matching BMO transaction (same CAD amount, 0-5 days later) gets a
      note with the real merchant / item from PayPal.

The "PayPal (history)" account only shows what went through PayPal: PayPal pulls each payment
from a card at that moment, so its balance just goes down - it's a history, not a wallet.
"""
import csv
import glob
import hashlib
import sys
from datetime import date, datetime, timedelta

import requests

sys.path.insert(0, "/ansible")
from gui.app import HOST_VARS_DIR, read_vault  # noqa: E402

FF = "http://192.168.3.8:8080"
FOLDER = "/ansible/gui-data/paypal"
ACCOUNT = "PayPal (history)"   # not just "PayPal": that is the expense account of the BMO "PAYPAL ..." payments
PAY_TYPES = {"PreApproved Payment Bill User Payment", "Express Checkout Payment", "Website Payment",
             "Subscription Payment", "Mobile Payment", "Donation Payment", "Payment Refund"}
DRY = "--dry-run" in sys.argv


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} [paypal] {msg}", flush=True)


def num(s):
    return float((s or "0").replace(",", "")) if (s or "").strip() else 0.0


def load():
    """Completed payments/refunds from all exports, de-duplicated, with the CAD amount."""
    rows = []
    for path in sorted(glob.glob(f"{FOLDER}/*.csv")):
        with open(path, newline="", encoding="utf-8-sig") as f:
            rows += [dict(r, _file=path) for r in csv.DictReader(f)]
    # CAD amount PayPal took from / returned to the card at the same instant (for USD charges)
    card = {}
    for r in rows:
        if r.get("Status") == "Completed" and r.get("Type") in ("General Card Deposit", "General Card Withdrawal") \
                and r.get("Currency") == "CAD":
            card.setdefault((r["Date"], r["Time"]), abs(num(r["Amount"])))
    out = {}
    for r in rows:
        if r.get("Status") != "Completed" or r.get("Type") not in PAY_TYPES or not (r.get("Name") or "").strip():
            continue
        amount = num(r["Amount"])
        key = "|".join((r["Date"], r["Time"], r["Name"].strip(), r["Currency"], f"{amount:.2f}"))
        if key in out:                       # the same payment in two overlapping exports
            if r.get("Transaction ID") and not out[key]["txn"]:
                out[key]["txn"] = r["Transaction ID"]
            continue
        cad = abs(amount) if r["Currency"] == "CAD" else card.get((r["Date"], r["Time"]))
        if cad is None:
            log(f"skipped (no CAD amount found): {r['Date']} {r['Name']} {r['Currency']} {amount}")
            continue
        out[key] = {"date": datetime.strptime(r["Date"], "%d/%m/%Y").date(), "name": r["Name"].strip(),
                    "refund": amount > 0, "cad": round(cad, 2), "currency": r["Currency"], "orig": abs(amount),
                    "item": (r.get("Item Title") or "").strip(), "txn": r.get("Transaction ID") or "",
                    "ext": "paypal:" + hashlib.sha1(key.encode()).hexdigest()[:16]}
    return sorted(out.values(), key=lambda x: x["date"])


class FF3:
    def __init__(self):
        tok = read_vault(HOST_VARS_DIR / "fin.aktasolutions.com" / "vault.yml")["vault_api_token"].strip()
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {tok}", "Accept": "application/json", "Content-Type": "application/json"})

    def req(self, method, path, **kw):
        if DRY and method != "GET":
            log(f"  [dry-run] {method} {path} {str(kw.get('json'))[:140]}")
            return {"data": {"id": "dry"}}
        r = self.s.request(method, FF + path, timeout=180, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path}: {r.status_code} {r.text[:300]}")
        return r.json() if r.content else {}

    def all(self, path, **params):
        out, page = [], 1
        while True:
            d = self.req("GET", path, params={**params, "page": page, "limit": 200})
            out += d["data"]
            if page >= d["meta"]["pagination"]["total_pages"]:
                return out
            page += 1


def main():
    pays = load()
    if not pays:
        log(f"no PayPal exports in {FOLDER}")
        return 0
    ff = FF3()
    assets = ff.all("/api/v1/accounts", type="asset")
    bank = [a for a in assets if a["attributes"]["name"].startswith("BMO")]
    bank_dates = [date.fromisoformat(s["date"][:10])
                  for a in bank
                  for g in ff.all(f"/api/v1/accounts/{a['id']}/transactions", start="2000-01-01", end=date.today().isoformat())
                  for s in g["attributes"]["transactions"] if s["type"] != "opening balance"]
    bank_start = min(bank_dates) if bank_dates else None
    log(f"{len(pays)} PayPal payments/refunds, {pays[0]['date']} .. {pays[-1]['date']}; bank data from {bank_start}")

    history = [p for p in pays if bank_start is None or p["date"] < bank_start]
    overlap = [p for p in pays if bank_start is not None and p["date"] >= bank_start]

    if history:
        if any(p["currency"] == "USD" for p in history):
            try:
                ff.req("POST", "/api/v1/currencies/USD/enable")
            except RuntimeError:
                pass
        acct = next((a["id"] for a in assets if a["attributes"]["name"] == ACCOUNT), None)
        if not acct:
            acct = ff.req("POST", "/api/v1/accounts", json={
                "name": ACCOUNT, "type": "asset", "account_role": "defaultAsset", "currency_code": "CAD",
                "notes": "Payments made through PayPal before the BMO bank data starts, from PayPal activity exports "
                         "(ansible-runner scripts/firefly_paypal_import.py). PayPal charged a card for each payment, "
                         "so the balance only goes down - it's a history, not a wallet."})["data"]["id"]
            log(f"created account '{ACCOUNT}'")
        have = set()
        if acct != "dry":
            for g in ff.all(f"/api/v1/accounts/{acct}/transactions", start="2000-01-01", end=date.today().isoformat()):
                have |= {s.get("external_id") for s in g["attributes"]["transactions"]}
        new = 0
        for p in history:
            if p["ext"] in have:
                continue
            split = {"type": "deposit" if p["refund"] else "withdrawal", "date": p["date"].isoformat(),
                     "amount": f"{p['cad']:.2f}", "currency_code": "CAD", "description": p["name"],
                     "external_id": p["ext"], "tags": ["paypal"],
                     "notes": "PayPal" + (f" transaction {p['txn']}" if p["txn"] else "") + (f" - item {p['item']}" if p["item"] else "")}
            if p["currency"] != "CAD":
                split.update(foreign_amount=f"{p['orig']:.2f}", foreign_currency_code=p["currency"])
            split.update({"destination_id": acct, "source_name": p["name"]} if p["refund"] else {"source_id": acct, "destination_name": p["name"]})
            ff.req("POST", "/api/v1/transactions", json={"error_if_duplicate_hash": False, "apply_rules": True,
                                                        "fire_webhooks": False, "transactions": [split]})
            new += 1
        log(f"history: {new} imported, {len(history) - new} already in Firefly")

    if overlap:
        bank_tx = []
        for a in bank:
            for g in ff.all(f"/api/v1/accounts/{a['id']}/transactions", start=(bank_start - timedelta(days=1)).isoformat(),
                            end=date.today().isoformat(), type="withdrawal"):
                for s in g["attributes"]["transactions"]:
                    if "PAYPAL" in s["description"].upper():
                        bank_tx.append({"group": g["id"], "id": s["transaction_journal_id"], "date": date.fromisoformat(s["date"][:10]),
                                        "amount": round(abs(float(s["amount"])), 2), "notes": s.get("notes") or "", "desc": s["description"]})
        labelled = 0
        for p in overlap:
            if p["refund"]:
                continue
            tag = f"PayPal: {p['name']}"
            m = next((t for t in bank_tx if t["amount"] == p["cad"] and 0 <= (t["date"] - p["date"]).days <= 5
                      and "PayPal:" not in t["notes"]), None)
            if not m:
                continue
            note = (m["notes"] + "\n" if m["notes"] else "") + tag + (f" - {p['item']}" if p["item"] else "") + \
                   (f" ({p['currency']} {p['orig']:.2f})" if p["currency"] != "CAD" else "") + (f" [{p['txn']}]" if p["txn"] else "")
            ff.req("PUT", f"/api/v1/transactions/{m['group']}", json={"transactions": [{"transaction_journal_id": m["id"], "notes": note}]})
            m["notes"] = note
            labelled += 1
            log(f"labelled bank '{m['desc'][:40]}' {m['amount']:.2f} -> {p['name']}")
        log(f"bank period: {labelled} BMO 'PAYPAL' transactions labelled with the real merchant, {len(overlap)} PayPal records seen")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"ERROR: {type(e).__name__}: {str(e)[:300]}")
        sys.exit(1)
