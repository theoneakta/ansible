#!/usr/bin/env python3
"""Firefly III categories, business/personal tagging and subscriptions - as Firefly rules.

    docker exec -w /ansible ansible-gui-1 python3 scripts/firefly_setup_rules.py [--apply-existing]

Re-runnable: the three rule groups below (titles starting "ansible-runner:") are
rebuilt from this file on every run; categories and subscriptions are created when
missing. --apply-existing then runs the groups over all existing transactions.

Rules fire on NEW transactions only ("store-journal"), so a tag changed later -
by hand, or by the Paperless bridge from a receipt - is never reverted.

Decisions (2026-10-11, the user): business = the software/hosting tools below, the
Revenu Quebec payments from the Akta Solutions account,
BMO business plan fee, restaurant bills over $200, and ESI Technologies income.
Everything else is personal (Home Depot too). Amazon follows its Paperless receipt.
"""
import sys
from datetime import date

import requests

sys.path.insert(0, "/ansible")
from gui.app import HOST_VARS_DIR, read_vault  # noqa: E402

FF = "http://192.168.3.8:8080"
PREFIX = "ansible-runner: "

# Category -> description fragments (case-insensitive). First matching rule wins (top to bottom).
CATEGORIES = [
    ("Transfers between own accounts", ["^TF"]),   # ^ = description starts with
    ("Credit card payments", ["MBNA", "CAPITAL ONE", "NATIONAL BNK MC", "CARTES AMEX", "VISA DESJARDINS"]),
    ("Loans & Financing", ["EASYFINANCIAL", "CONSUMER LOANS", "FORD CREDIT", "FAIRSTONE", "FINANCEIT", "AFFIRM", "KLARNA", "PAYIN4"]),
    ("Income", ["ESITECHNOLOGIES", "CISSS", "PAYROLL", "PAIE/", "DEPOT CHEQUES"]),
    ("Software & Hosting", ["QUICKBOOKS", "ANTHROPIC", "IONOS", "INFOMANIAK", "MICROSOFT", "SIMPLEFIN", "GOOGLE SMART", "G1SK"]),
    ("Subscriptions & Streaming", ["NETFLIX", "SPOTIFY", "UBERONE", "SCENTBIRD", "AYLO", "PAYPAL X.", "GOOGLE GOOGLE", "ADOBE"]),
    ("Housing", ["EQUITABLE BANK", "HYDRO QUEBEC", "HYDRO-QUEBEC", "VEXTERMINATION", "VERTDURE",
                 "ENTREPRISES LIM", "L EXPERT DEPANN"]),   # Entreprises Limoges = home renovation (the user)
    ("Phone & Internet", ["BELL", "VIRGIN PLUS", "VIDEOTRON", "FIZZ"]),
    ("Insurance", ["INS/ASS", "RBCASSU", "ASSURANCE"]),
    ("Education", ["COLL GE", "COLLEGE", "ECOLE"]),
    ("Savings & Investments", ["KALEIDO", "BMO INV"]),
    ("Taxes", ["RQ CODE", "REVENU QUEBEC"]),
    ("Bank fees", ["FRAIS DE PROGRAMME", "PROGRAMME PRIVILEGE", "INTEREST"]),
    ("Gambling", ["LOTO-QUEBEC"]),
    ("Entertainment", ["BILLETTERIE", "FAMOUS PLAYER", "CINEPLEX", "CINEMA"]),
    ("Pets", ["PATTES & GRIFFE", "MONDOU", "PET"]),
    ("Memberships", ["CAAQUEBEC", "CAA QUEBEC"]),
    ("Discounts", ["REDUCTION "]),
    ("Pending", ["PROVISOIR"]),   # bank holds not yet final
    ("Restaurants & Fast food", ["MCDONALDS", "STARBUCKS", "TIM HORTONS", "UBEREATS", "FIVE GUYS", "RESTAURANT", "TIKI MING",
                                 "CARLOS AND PEPE", "SCORES", "SEL POIVRE", "LE CREME", "A&W", "SUBWAY", "ST-HUBERT",
                                 "STH 2", "WENDYS", "HARVEYS", "FRITOU", "HEART&CROWN", "MENCHIE", "KINTON", "TIME OUT", "COQ GARE",
                                 "BROADHEAD", "DEPANNEUR", "THAI EXPRESS", "PACINI", "SECOND CUP",
                                 "PRESOTEA", "BYTOWN CATER", "LA PREP", "ROCK N DELI", "JLIEU"]),
    ("Groceries", ["IGA", "METRO ", "MAXI", "SUPER C", "PROVIGO", "BOULANGERIE", "WALMART", "COSTCO WHOLESALE", "FARM BOY"]),
    ("Transport", ["PETRO-CANADA", "COSTCO ESSENCE", "ESSO", "SHELL", "ULTRAMAR", "UBERTRIP", "UBER TRIP", "OPUS",
                   "ELECTRIFY", "CIRCUIT ELECTRIQUE", "STATIONNEMENT"]),
    ("Health & Pharmacy", ["JEAN COUTU", "PHARMAPRIX", "UNIPRIX", "PR L'ASSOMPTION"]),
    ("Shopping", ["AMZN", "AMAZON", "NIKE", "MICHAEL KORS", "URBAN PLANET", "GAMESTOP", "HOME DEPOT", "CANAC", "PARTY EXPERT",
                  "EBAY", "TIGRE GEANT", "RUDSAK", "SHEIN", "INSTANTINK", "GALERIES",
                  "DOLLARAMA", "LOULOU", "BOUTIQUE", "HAIRGAMES", "STUDIO"]),
    ("E-transfers", ["VIR INTERAC"]),
]
BUSINESS_TOOLS = ["QUICKBOOKS", "ANTHROPIC", "IONOS", "INFOMANIAK", "MICROSOFT", "SIMPLEFIN", "FRAIS DE PROGRAMME"]
BUSINESS_INCOME = ["ESITECHNOLOGIES"]
# Paid from an Akta Solutions account = company taxes (GST/QST, source deductions, corporate tax) - the user, 2026-10-11
BUSINESS_FROM_COMPANY = ["RQ CODE", "REVENU QUEBEC"]
COMPANY_ACCOUNT = "Akta Solutions"
BUSINESS_MEAL_OVER = "200"

# Subscriptions: name, typical amount, repeat (weekly/monthly/...), skip (2-weekly = weekly skip 1), last seen, match fragments
SUBSCRIPTIONS = [
    ("QuickBooks", 40.24, "monthly", 0, "2026-10-06", ["QUICKBOOKS"]),
    ("Anthropic Claude", 32.19, "monthly", 0, "2026-10-01", ["ANTHROPIC"]),
    ("Microsoft", 13.11, "monthly", 0, "2026-09-18", ["MICROSOFT"]),
    ("Infomaniak", 7.94, "monthly", 0, "2026-09-18", ["INFOMANIAK"]),
    ("IONOS", 4.50, "monthly", 0, "2026-09-26", ["IONOS"]),
    ("SimpleFIN Bridge", 2.13, "monthly", 0, "2026-09-10", ["SIMPLEFIN"]),
    ("BMO business plan fee", 50.00, "monthly", 0, "2026-09-30", ["FRAIS DE PROGRAMME"]),
    ("BMO Privilege plan fee", 30.95, "monthly", 0, "2026-09-30", ["PROGRAMME PRIVILEGE"]),
    ("Netflix", 27.58, "monthly", 0, "2026-09-29", ["NETFLIX"]),
    ("Spotify", 27.58, "monthly", 0, "2026-10-06", ["SPOTIFY"]),
    ("Uber One", 11.49, "monthly", 0, "2026-10-02", ["UBERONE"]),
    ("Google (PayPal)", 3.21, "monthly", 0, "2026-10-02", ["GOOGLE GOOGLE"]),
    ("X Premium", 35.95, "monthly", 0, "2026-09-18", ["PAYPAL X."]),
    ("AYLO", 51.35, "monthly", 0, "2026-10-06", ["AYLO"]),
    ("Adobe", 37.93, "monthly", 0, "2026-09-18", ["ADOBE"]),
    ("Scentbird", 32.66, "monthly", 0, "2026-09-14", ["SCENTBIRD"]),
    ("OPUS transit pass", 71.50, "monthly", 0, "2026-09-30", ["OPUS"]),
    ("Bell internet/TV", 220.00, "monthly", 0, "2026-09-14", ["BELLFACT"]),
    ("Virgin Plus mobile", 130.00, "monthly", 0, "2026-09-14", ["VIRGIN PLUS"]),
    ("Mortgage - Equitable Bank", 2978.22, "monthly", 0, "2026-09-15", ["EQUITABLE BANK"]),
    ("easyfinancial loan", 1996.92, "monthly", 0, "2026-09-30", ["EASYFINANCIAL"]),
    ("Consumer loan", 256.78, "weekly", 1, "2026-10-03", ["CONSUMER LOANS"]),
    ("Ford Credit", 900.00, "weekly", 1, "2026-10-01", ["FORD CREDIT"]),
    ("Financeit", 340.43, "monthly", 0, "2026-09-15", ["FINANCEIT"]),
    ("Desjardins insurance", 625.69, "monthly", 0, "2026-09-15", ["DESJARDINS INS"]),
    ("RBC life insurance", 152.10, "monthly", 0, "2026-09-15", ["RBCASSU"]),
    ("Fondation Kaleido (RESP)", 274.04, "monthly", 0, "2026-09-15", ["KALEIDO"]),
    ("BMO investments", 75.00, "monthly", 0, "2026-09-15", ["BMO INV"]),
    ("Revenu Quebec payments", 170.00, "weekly", 1, "2026-10-03", ["RQ CODE"]),
]


class FF3:
    def __init__(self):
        tok = read_vault(HOST_VARS_DIR / "fin.aktasolutions.com" / "vault.yml")["vault_api_token"].strip()
        self.s = requests.Session()
        self.s.headers.update({"Authorization": f"Bearer {tok}", "Accept": "application/json", "Content-Type": "application/json"})

    def req(self, method, path, **kw):
        r = self.s.request(method, FF + path, timeout=120, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path}: {r.status_code} {r.text[:300]}")
        return r.json() if r.content else {}

    def all(self, path):
        out, page = [], 1
        while True:
            d = self.req("GET", path, params={"page": page, "limit": 200})
            out += d["data"]
            if page >= d["meta"]["pagination"]["total_pages"]:
                return out
            page += 1


def match(fragment):
    """"^X" = description starts with X, otherwise contains."""
    return trig("description_starts", fragment[1:]) if fragment.startswith("^") else trig("description_contains", fragment)


def trig(kind, value):
    return {"type": kind, "value": value, "active": True, "stop_processing": False, "prohibited": False}


def act(kind, value=None):
    a = {"type": kind, "active": True, "stop_processing": False}
    if value is not None:
        a["value"] = value
    return a


def group_subscriptions_by_account(ff, bills):
    """Group each subscription (Firefly "object group" = a heading on the Subscriptions page)
    under the account its linked payments come from, and say so in its notes."""
    for name, bill_id in bills.items():
        accounts = {}
        for g in ff.all(f"/api/v1/bills/{bill_id}/transactions"):
            for s in g["attributes"]["transactions"]:
                acct = s["source_name"] if s["type"] == "withdrawal" else s["destination_name"]
                accounts[acct] = accounts.get(acct, 0) + 1
        if not accounts:
            continue
        main_acct = max(accounts, key=accounts.get)
        also = [a for a in accounts if a != main_acct]
        note = f"Paid from: {main_acct}" + (f" (also: {', '.join(also)})" if also else "") + \
               ".\nCreated by ansible-runner scripts/firefly_setup_rules.py from the transactions seen Aug-Oct 2026."
        ff.req("PUT", f"/api/v1/bills/{bill_id}", json={"object_group_title": main_acct, "notes": note})
        print(f"subscription '{name}' -> {main_acct}" + (f" (also {also})" if also else ""))


def main():
    ff = FF3()
    have = {c["attributes"]["name"] for c in ff.all("/api/v1/categories")}
    for name, _ in CATEGORIES:
        if name not in have:
            ff.req("POST", "/api/v1/categories", json={"name": name})
            print("category created:", name)

    bills = {b["attributes"]["name"]: b["id"] for b in ff.all("/api/v1/bills")}
    for name, amt, freq, skip, last, _ in SUBSCRIPTIONS:
        body = {"name": name, "amount_min": f"{amt * 0.9:.2f}", "amount_max": f"{amt * 1.1:.2f}", "date": last,
                "repeat_freq": freq, "skip": skip, "currency_code": "CAD", "active": True,
                "notes": "Created by ansible-runner scripts/firefly_setup_rules.py from the transactions seen Aug-Oct 2026."}
        if name in bills:
            ff.req("PUT", f"/api/v1/bills/{bills[name]}", json=body)
        else:
            bills[name] = ff.req("POST", "/api/v1/bills", json=body)["data"]["id"]
            print("subscription created:", name)

    # Our rule groups: drop and rebuild, so this file stays the source of truth
    groups = {g["attributes"]["title"]: g["id"] for g in ff.all("/api/v1/rule-groups")}
    for title, gid in groups.items():
        if title.startswith(PREFIX):
            ff.req("DELETE", f"/api/v1/rule-groups/{gid}")
    gid = {}
    for i, title in enumerate(("1 categories", "2 business or personal", "3 subscriptions"), start=1):
        gid[title] = ff.req("POST", "/api/v1/rule-groups", json={
            "title": PREFIX + title, "order": i, "active": True,
            "description": "Managed by ansible-runner/scripts/firefly_setup_rules.py - edit the script, not here."})["data"]["id"]

    def rule(group, title, triggers, actions, strict=False, stop=False):
        ff.req("POST", "/api/v1/rules", json={"title": title, "rule_group_id": gid[group], "trigger": "store-journal",
                                              "active": True, "strict": strict, "stop_processing": stop,
                                              "triggers": triggers, "actions": actions})

    for name, frags in CATEGORIES:
        rule("1 categories", name, [match(f) for f in frags], [act("set_category", name)], stop=True)

    rule("2 business or personal", "Personal by default",
         [trig("transaction_type", "withdrawal"), trig("transaction_type", "deposit")],
         [act("remove_tag", "business"), act("add_tag", "personal")])
    rule("2 business or personal", "Business tools and fees", [trig("description_contains", f) for f in BUSINESS_TOOLS],
         [act("remove_tag", "personal"), act("add_tag", "business")])
    rule("2 business or personal", "Business income", [trig("description_contains", f) for f in BUSINESS_INCOME],
         [act("remove_tag", "personal"), act("add_tag", "business")])
    for frag in BUSINESS_FROM_COMPANY:
        rule("2 business or personal", f"Business taxes: {frag} from the company account",
             [trig("description_contains", frag), trig("source_account_contains", COMPANY_ACCOUNT)],
             [act("remove_tag", "personal"), act("add_tag", "business")], strict=True)
    rule("2 business or personal", f"Business meals over ${BUSINESS_MEAL_OVER}",
         [trig("category_is", "Restaurants & Fast food"), trig("amount_more", BUSINESS_MEAL_OVER)],
         [act("remove_tag", "personal"), act("add_tag", "business")], strict=True)

    for name, *_x, frags in SUBSCRIPTIONS:
        rule("3 subscriptions", name, [trig("description_contains", f) for f in frags], [act("link_to_bill", name)], stop=False)
    print(f"rules rebuilt: {len(CATEGORIES)} category, 4 business/personal, {len(SUBSCRIPTIONS)} subscription")

    group_subscriptions_by_account(ff, bills)

    if "--apply-existing" in sys.argv:
        for title in ("1 categories", "2 business or personal", "3 subscriptions"):
            ff.req("POST", f"/api/v1/rule-groups/{gid[title]}/trigger",
                   params={"start": "2020-01-01", "end": date.today().isoformat()})
            print("applied to existing transactions:", title)


if __name__ == "__main__":
    main()
