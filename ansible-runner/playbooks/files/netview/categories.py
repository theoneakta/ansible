"""netview's website categories: the UT1 blacklists (Universite Toulouse
Capitole, CC BY-SA 4.0 - ~5.7 million domains in ~70 categories) matched
against the domains the LAN actually looks up.

  lists      every LIST_EVERY, the archive streamed into netview.category_domains
             (domain, category, priority) - a fresh table swapped in whole
  classify   every CLASSIFY_EVERY, each domain seen in netview.dns that wasn't
             classified against the current lists gets its category in
             netview.domain_category: the most specific listed suffix wins
             ("x.blogspot.com" before "blogspot.com"), then the riskiest
             group; no match = "uncategorized"
  lookup     netview.domain_category_dict (that small table, in memory) -
             what the views call per flow: dictGet(..., tuple(domain))

CATS names and groups the categories; only those are loaded (the French
school lists and the duplicate redirector lists are left out).
"""
import os
import tarfile
import threading
import time
import urllib.request

import requests

CH_URL = os.environ.get("CLICKHOUSE_URL", "http://clickhouse:8123")
LIST_URLS = [u for u in os.environ.get("CATEGORY_LISTS", (
    "ftp://ftp.ut-capitole.fr/pub/reseau/cache/squidguard_contrib/blacklists.tar.gz "
    "https://github.com/olbat/ut1-blacklists/archive/refs/heads/master.tar.gz")).split() if u]
LIST_EVERY = 86400
CLASSIFY_EVERY = 300
DICT = "netview.domain_category_dict"

# Groups, riskiest first - the order also settles a domain listed in several.
GROUPS = ["Security threat", "Illicit", "Mature", "Gambling", "Proxy & VPN", "Ads & tracking",
          "Social", "Media", "Games", "Shopping & finance", "News", "Downloads", "Other"]
# UT1 category -> (label, group)
CATS = {
    "malware": ("Malware", "Security threat"), "phishing": ("Phishing", "Security threat"),
    "cryptojacking": ("Cryptojacking", "Security threat"), "stalkerware": ("Stalkerware", "Security threat"),
    "dialer": ("Dialers", "Security threat"),
    "drogue": ("Drugs", "Illicit"), "warez": ("Warez / piracy", "Illicit"), "hacking": ("Hacking", "Illicit"),
    "agressif": ("Hate / aggressive", "Illicit"), "ddos": ("DDoS for hire", "Illicit"),
    "dangerous_material": ("Dangerous material", "Illicit"), "tricheur": ("Cheating", "Illicit"),
    "sect": ("Sects", "Illicit"),
    "adult": ("Adult", "Mature"), "mixed_adult": ("Mixed adult", "Mature"), "lingerie": ("Lingerie", "Mature"),
    "dating": ("Dating", "Mature"),
    "gambling": ("Gambling", "Gambling"), "arjel": ("Online betting", "Gambling"),
    "vpn": ("VPN", "Proxy & VPN"), "redirector": ("Proxy / anonymizer", "Proxy & VPN"),
    "residential-proxies": ("Residential proxies", "Proxy & VPN"), "doh": ("DNS over HTTPS", "Proxy & VPN"),
    "remote-control": ("Remote control", "Proxy & VPN"), "dynamic-dns": ("Dynamic DNS", "Proxy & VPN"),
    "publicite": ("Advertising", "Ads & tracking"), "marketingware": ("Marketing / tracking", "Ads & tracking"),
    "social_networks": ("Social networks", "Social"), "chat": ("Chat", "Social"), "forums": ("Forums", "Social"),
    "blog": ("Blogs", "Social"),
    "audio-video": ("Streaming", "Media"), "radio": ("Radio", "Media"), "manga": ("Manga", "Media"),
    "celebrity": ("Celebrity", "Media"),
    "games": ("Games", "Games"), "educational_games": ("Educational games", "Games"),
    "shopping": ("Shopping", "Shopping & finance"), "bank": ("Banking", "Shopping & finance"),
    "financial": ("Finance", "Shopping & finance"), "bitcoin": ("Crypto", "Shopping & finance"),
    "press": ("News", "News"), "fakenews": ("Fake news", "News"),
    "download": ("Downloads", "Downloads"), "filehosting": ("File hosting", "Downloads"),
    "update": ("Software updates", "Downloads"),
    "jobsearch": ("Job search", "Other"), "webmail": ("Webmail", "Other"), "sports": ("Sports", "Other"),
    "cooking": ("Cooking", "Other"), "astrology": ("Astrology", "Other"), "translation": ("Translation", "Other"),
    "shortener": ("URL shorteners", "Other"), "webhosting": ("Web hosting", "Other"),
    "mobile-phone": ("Mobile phones", "Other"), "ai": ("AI", "Other"),
    # UT1 "cleaning" is really software and antivirus vendors (apple.com, microsoft.com, bitdefender...).
    "cleaning": ("Software & antivirus vendors", "Downloads"),
    "child": ("Kids", "Other"), "sexual_education": ("Sex education", "Other"),
}
UNCATEGORIZED = "uncategorized"

DDL = [
    """CREATE TABLE IF NOT EXISTS netview.category_domains (
        domain String, category LowCardinality(String), priority UInt8, loaded DateTime DEFAULT now()
    ) ENGINE = MergeTree ORDER BY domain""",
    """CREATE TABLE IF NOT EXISTS netview.domain_category (
        domain String, category LowCardinality(String), updated DateTime DEFAULT now()
    ) ENGINE = ReplacingMergeTree(updated) ORDER BY domain TTL updated + INTERVAL 60 DAY""",
    f"""CREATE DICTIONARY IF NOT EXISTS {DICT} (domain String, category String)
    PRIMARY KEY domain
    SOURCE(CLICKHOUSE(QUERY 'SELECT domain, argMax(category, updated) AS category FROM netview.domain_category GROUP BY domain'))
    LAYOUT(COMPLEX_KEY_HASHED()) LIFETIME(MIN 120 MAX 300)""",
]

status = {"enabled": True, "lists_loaded": 0, "list_domains": 0, "list_source": "", "classified": 0,
          "last_error": ""}


def label(cat):
    if cat == UNCATEGORIZED:
        return "Uncategorized"
    return CATS.get(cat, (cat, "Other"))[0] if cat else "(no DNS name)"


def group(cat):
    if cat == UNCATEGORIZED or not cat:
        return ""
    return CATS.get(cat, (cat, "Other"))[1]


def group_keys(name):
    """The category keys of a group (a drill-down filter)."""
    keys = [k for k, (_, g) in CATS.items() if g == name]
    if not keys:
        raise ValueError(name)
    return keys


def ch(sql, data=None):
    r = requests.post(CH_URL, params={"query": sql} if data is not None else None,
                      data=(data if data is not None else sql).encode(), timeout=600)
    if r.status_code != 200:
        raise RuntimeError(f"ClickHouse: {r.text[:300]}")
    return r.text


def load_lists():
    """Stream the archive into a fresh table and swap it in."""
    prio = {c: GROUPS.index(g) for c, (_, g) in CATS.items()}
    ch("DROP TABLE IF EXISTS netview.category_domains_new")
    ch("CREATE TABLE netview.category_domains_new AS netview.category_domains")
    last_err = None
    for url in LIST_URLS:
        try:
            total = 0
            with urllib.request.urlopen(url, timeout=120) as resp:
                with tarfile.open(fileobj=resp, mode="r|gz") as tar:
                    for m in tar:
                        parts = m.name.split("/")
                        if not m.isfile() or parts[-1] != "domains" or len(parts) < 3 or parts[-2] not in CATS:
                            continue
                        cat = parts[-2]
                        chunk = []
                        # Bytes, line by line: a streamed member can't seek (no text wrapper).
                        for raw in tar.extractfile(m):
                            d = raw.decode("utf-8", "ignore").strip().lower().rstrip(".")
                            if d and not d.startswith("#") and "\t" not in d:
                                chunk.append(f"{d}\t{cat}\t{prio[cat]}")
                            if len(chunk) >= 200000:
                                ch("INSERT INTO netview.category_domains_new (domain, category, priority) FORMAT TSV",
                                   "\n".join(chunk))
                                total += len(chunk)
                                chunk = []
                        if chunk:
                            ch("INSERT INTO netview.category_domains_new (domain, category, priority) FORMAT TSV",
                               "\n".join(chunk))
                            total += len(chunk)
            if total < 100000:
                raise RuntimeError(f"only {total} domains")
            ch("EXCHANGE TABLES netview.category_domains AND netview.category_domains_new")
            ch("DROP TABLE IF EXISTS netview.category_domains_new")
            status.update(list_domains=total, list_source=url, lists_loaded=int(time.time()))
            return
        except Exception as e:  # try the next source
            last_err = e
            ch("TRUNCATE TABLE netview.category_domains_new")
    raise RuntimeError(f"no category list could be loaded: {last_err}")


# A domain's suffixes down to two labels, with their depth (1 = the domain itself).
SUFFIXES = ("arrayMap(i -> arrayStringConcat(arraySlice(splitByChar('.', domain), i), '.'), "
            "range(1, greatest(length(splitByChar('.', domain)), 2)))")


def classify():
    """Categories for the domains not classified against the current lists."""
    loaded = int(ch("SELECT toUInt32(max(loaded)) FROM netview.category_domains").strip() or 0)
    if not loaded:
        return 0
    before = int(ch("SELECT count() FROM netview.domain_category").strip() or 0)
    ch(f"""INSERT INTO netview.domain_category (domain, category)
        WITH obs AS (
            SELECT DISTINCT domain FROM netview.dns
            WHERE t > now() - INTERVAL 30 DAY
              AND domain NOT IN (SELECT domain FROM netview.domain_category WHERE updated >= toDateTime({loaded}))
            LIMIT 200000
        ),
        sfx AS (
            SELECT domain, suffix, depth FROM obs
            ARRAY JOIN {SUFFIXES} AS suffix, arrayEnumerate({SUFFIXES}) AS depth
        ),
        hits AS (
            SELECT domain AS suffix, category, priority FROM netview.category_domains
            WHERE domain IN (SELECT suffix FROM sfx)
        )
        SELECT s.domain,
               if(argMinIf(h.category, (s.depth, h.priority), h.category != '') = '', '{UNCATEGORIZED}',
                  argMinIf(h.category, (s.depth, h.priority), h.category != ''))
        FROM sfx AS s LEFT JOIN hits AS h ON s.suffix = h.suffix
        GROUP BY s.domain""")
    ch(f"SYSTEM RELOAD DICTIONARY {DICT}")
    added = int(ch("SELECT count() FROM netview.domain_category").strip() or 0) - before
    status["classified"] += max(added, 0)
    return added


def loop():
    ready = False
    while True:
        try:
            if not ready:
                for sql in DDL:
                    ch(sql)
                status["lists_loaded"] = int(ch("SELECT toUInt32(max(loaded)) FROM netview.category_domains").strip() or 0)
                status["list_domains"] = int(ch("SELECT count() FROM netview.category_domains").strip() or 0)
                ready = True
            if time.time() - status["lists_loaded"] > LIST_EVERY:
                load_lists()
            classify()
            status["last_error"] = ""
        except Exception as e:  # keep going - the source or ClickHouse may be away
            status["last_error"] = f"{type(e).__name__}: {e}"[:300]
        time.sleep(CLASSIFY_EVERY)


def start():
    threading.Thread(target=loop, daemon=True, name="categories").start()
