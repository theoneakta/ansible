#!/usr/bin/env python3
"""Link Paperless-ngx receipts/invoices to their Firefly III transactions.

Runs inside the ansible-gui container, after the SimpleFIN sync (same crontab line):
    docker exec -w /ansible ansible-gui-1 python3 scripts/firefly_paperless_link.py [--dry-run]

Tokens from the vault (ansible-runner "web" hosts, API token field):
    fin.aktasolutions.com        Firefly III personal access token
    paperless.aktasolutions.com  Paperless-ngx API token

For every Paperless document not yet tagged "in-firefly" or "unmatched" (and not a
bank statement / contract / tax document), it looks for a Firefly transaction with
the same amount, dated within DATE_WINDOW days of the document, and prefers the one
whose description shares a word with the document's correspondent/title. The
amount comes from the document's "Amount" custom field, or else from the totals
found in its OCR text (lines with "total"/"montant"/"amount due" first).

On a match (link mode - files stay only in Paperless):
  Firefly   : the transaction's external URL -> the Paperless document
  Paperless : "Firefly transaction" field -> the transaction, "Amount" filled in,
              tags in-firefly + business/personal (copied from the transaction)
A document still unmatched after GIVE_UP_DAYS gets the "unmatched" tag.
"""
import re
import sys
from datetime import date, datetime, timedelta

import requests

sys.path.insert(0, "/ansible")
from gui.app import HOST_VARS_DIR, read_vault  # noqa: E402

FIREFLY, FIREFLY_PUBLIC = "http://192.168.3.8:8080", "https://fin.aktasolutions.com"
PAPERLESS, PAPERLESS_PUBLIC = "http://192.168.3.8:8000", "https://paperless.aktasolutions.com"
DATE_WINDOW = 5         # days between the document date and the bank date
GIVE_UP_DAYS = 14       # then tag "unmatched"
SKIP_TYPES = {"Bank statement", "Contract", "Tax"}
DRY = "--dry-run" in sys.argv


def log(msg):
    print(f"{datetime.now():%Y-%m-%d %H:%M:%S} [paperless-link] {msg}", flush=True)


def token(host):
    return read_vault(HOST_VARS_DIR / host / "vault.yml")["vault_api_token"].strip()


class Api:
    def __init__(self, base, auth):
        self.base, self.s = base, requests.Session()
        self.s.headers.update({"Authorization": auth, "Accept": "application/json"})

    def get(self, path, **params):
        r = self.s.get(self.base + path, params=params, timeout=60)
        r.raise_for_status()
        return r.json()

    def write(self, method, path, body):
        if DRY:
            log(f"  [dry-run] {method} {path} {str(body)[:150]}")
            return {}
        r = self.s.request(method, self.base + path, json=body, timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path}: {r.status_code} {r.text[:200]}")
        return r.json() if r.content else {}


def money(text):
    """Amounts in a receipt's text, the likely total(s) first."""
    found, first = [], []
    for line in (text or "").splitlines():
        amounts = re.findall(r"(?<![\d.,])(\d{1,6}(?:[ ,]\d{3})*[.,]\d{2})(?![\d])", line)
        values = [float(a.replace(" ", "").replace(",", ".") if a.count(",") == 1 and "." not in a else a.replace(",", "").replace(" ", ""))
                  for a in amounts]
        (first if re.search(r"total|montant|amount due|à payer|balance due", line, re.I) else found).extend(values)
    seen, out = set(), []
    for v in first + found:
        if v > 0 and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def words(s):
    return {w for w in re.findall(r"[a-z0-9]{3,}", (s or "").lower())} - {"inc", "ltd", "the", "com", "www", "corp", "and"}


def main():
    pl = Api(PAPERLESS, "Token " + token("paperless.aktasolutions.com"))
    ff = Api(FIREFLY, "Bearer " + token("fin.aktasolutions.com"))
    pl.s.headers["Accept"] = "application/json; version=9"

    tags = {t["name"]: t["id"] for t in pl.get("/api/tags/", page_size=1000)["results"]}
    types = {t["id"]: t["name"] for t in pl.get("/api/document_types/", page_size=1000)["results"]}
    fields = {f["name"]: f["id"] for f in pl.get("/api/custom_fields/", page_size=1000)["results"]}
    corr = {c["id"]: c["name"] for c in pl.get("/api/correspondents/", page_size=1000)["results"]}
    for need in ("in-firefly", "unmatched", "business", "personal"):
        if need not in tags:
            raise SystemExit(f"Paperless tag '{need}' is missing")

    docs = pl.get("/api/documents/", page_size=200, ordering="-created",
                  tags__id__none=f"{tags['in-firefly']},{tags['unmatched']}")["results"]
    docs = [d for d in docs if types.get(d.get("document_type")) not in SKIP_TYPES]
    if not docs:
        log("no new documents to link")
        return 0

    start = min(date.fromisoformat(d["created"][:10]) for d in docs) - timedelta(days=DATE_WINDOW)
    end = date.today() + timedelta(days=1)
    txs, page = [], 1
    while True:
        d = ff.get("/api/v1/transactions", start=start.isoformat(), end=end.isoformat(), type="withdrawal", page=page, limit=200)
        for g in d["data"]:
            for split in g["attributes"]["transactions"]:
                txs.append({"group": g["id"], "id": split["transaction_journal_id"], "amount": round(abs(float(split["amount"])), 2),
                            "date": date.fromisoformat(split["date"][:10]), "desc": split["description"],
                            "tags": split.get("tags") or [], "url": split.get("external_url")})
        if page >= d["meta"]["pagination"]["total_pages"]:
            break
        page += 1
    used = {t["url"] for t in txs if t["url"]}

    linked = unmatched = 0
    for doc in docs:
        doc_date = date.fromisoformat(doc["created"][:10])
        amount_field = next((cf["value"] for cf in doc.get("custom_fields", []) if cf["field"] == fields.get("Amount") and cf["value"]), None)
        amounts = [float(re.sub(r"[^\d.]", "", str(amount_field)))] if amount_field else money(doc.get("content"))
        doc_url = f"{PAPERLESS_PUBLIC}/documents/{doc['id']}/details"
        hint = words(corr.get(doc.get("correspondent"), "")) | words(doc.get("title"))
        best = None
        for amt in amounts[:6]:
            cands = [t for t in txs if t["amount"] == round(amt, 2) and abs((t["date"] - doc_date).days) <= DATE_WINDOW and t["url"] not in used]
            cands.sort(key=lambda t: (-len(hint & words(t["desc"])), abs((t["date"] - doc_date).days)))
            if cands:
                best = (amt, cands[0])
                break
        if best:
            amt, t = best
            tx_url = f"{FIREFLY_PUBLIC}/transactions/show/{t['group']}"
            log(f"doc {doc['id']} '{doc['title']}' {amt:.2f} -> Firefly #{t['group']} {t['date']} '{t['desc']}'")
            ff.write("PUT", f"/api/v1/transactions/{t['group']}",
                     {"transactions": [{"transaction_journal_id": t["id"], "external_url": doc_url}]})
            cfs = [cf for cf in doc.get("custom_fields", []) if cf["field"] not in (fields.get("Amount"), fields.get("Firefly transaction"))]
            cfs += [{"field": fields["Firefly transaction"], "value": tx_url}, {"field": fields["Amount"], "value": f"CAD{amt:.2f}"}]
            new_tags = set(doc["tags"]) | {tags["in-firefly"]} | {tags[x] for x in ("business", "personal") if x in t["tags"]}
            pl.write("PATCH", f"/api/documents/{doc['id']}/", {"tags": sorted(new_tags), "custom_fields": cfs})
            used.add(doc_url)
            linked += 1
        elif (date.today() - doc_date).days > GIVE_UP_DAYS:
            pl.write("PATCH", f"/api/documents/{doc['id']}/", {"tags": sorted(set(doc["tags"]) | {tags["unmatched"]})})
            log(f"doc {doc['id']} '{doc['title']}' - no transaction found after {GIVE_UP_DAYS} days, tagged unmatched")
            unmatched += 1
    log(f"done: {linked} linked, {unmatched} newly unmatched, {len(docs) - linked - unmatched} waiting")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"ERROR: {type(e).__name__}: {str(e)[:300]}")
        sys.exit(1)
