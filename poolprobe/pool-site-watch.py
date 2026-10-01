#!/usr/bin/env python3
"""pool-site-watch.py - read what each pool advertises, and notice when it changes.

pool-survey.py probes endpoints every hour, but until 2026-09-29 it only knew
the endpoints written into pool-endpoints.json by hand. If a pool moved ports,
added a product, or retired one, the probe kept testing the old list and
nothing said so. On 2026-09-22 PyBLOCK's rows had pointed at their old SHA-256
site for ten days; the old ports still answered, so the probe looked healthy.

This reads each pool's pages and the chain, compares both with the list, and
does two things with what it finds:

  1. writes ~/.reorg-watch/site-endpoints.json: every host:port and 128-hex
     DATUM pubkey seen on each pool's own pages, with first/last seen times.
     pool-survey.py probes the endpoints in it that the list does not have,
     so a port a pool adds to its page is tested the next hour, by itself.
  2. mails when the set of differences changes:
     - site: host:ports or pubkeys on the pages that the list lacks, or listed
       ones gone from the pages
     - chain: labels with blocks in the last day that the list does not cover,
       and listed labels with no blocks in the last two weeks
     - probe: an endpoint whose survey verdict changed and stayed changed for
       two runs in a row (one bad connect is not news)

Findings go to ~/.reorg-watch/site-watch.txt every run. Mail goes out only
when the findings differ from the last mailed set, with counts ignored, so an
unfixed item is reported once, not once an hour.

Usage: pool-site-watch.py [--no-mail] [--print]
"""

import argparse, json, os, re, ssl, subprocess, sys, urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
SD = os.path.expanduser("~/.reorg-watch")
ENDPOINTS = os.path.join(HERE, "pool-endpoints.json")
SURVEY = os.path.join(SD, "pool-survey.json")
REWARDS = os.path.join(SD, "rewards.json")
STATE = os.path.join(SD, "site-watch.json")
REPORT = os.path.join(SD, "site-watch.txt")
SITE_EPS = os.path.join(SD, "site-endpoints.json")
try:
    with open(os.path.join(SD, "mailto")) as _f:
        MAILTO = _f.read().strip()  # one line; without it, nothing is mailed
except OSError:
    MAILTO = ""
UA = "Mozilla/5.0 (compatible; reorg.watch pool-site-watch; +https://reorg.watch)"

HOSTPORT = re.compile(r"(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,})(?::|&#58;|\s*port\s*)(\d{2,5})(?!\d)", re.I)
PUBKEY = re.compile(r"(?<![0-9a-f])[0-9a-f]{128}(?![0-9a-f])", re.I)
# A gateway config printed on the page: "pool_host": "host", "pool_port": 28915 (quotes may be &quot;)
CONFHOST = re.compile(r"pool_host(?:&quot;|\")?\s*:\s*(?:&quot;|\")?\s*((?:[a-z0-9-]+\.)+[a-z]{2,})\s*(?:&quot;|\")?\s*,\s*(?:&quot;|\")?pool_port(?:&quot;|\")?\s*:\s*(\d{2,5})", re.I)
WEB_PORTS = {"80", "443", "8080", "8443"}
OTHER_PORTS = {"50001", "50002", "8332", "8333", "18332", "18333", "3000", "3006"}   # electrum, node RPC/P2P, explorers
RECENT_BLOCKS = 144      # a day: an unlisted label with blocks here is worth a look
QUIET_BLOCKS = 2016      # two weeks: a listed label with nothing here may be retired
MIN_UNLISTED = 3
FORGET_DAYS = 30         # a page endpoint unseen this long is dropped from the feed


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch(url):
    """Page text, or raises. Falls back to an unverified TLS context only to read
    the page; the finding says so, since a pool with a broken cert is itself news."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            return r.read(2_000_000).decode("utf-8", "replace"), r.geturl(), False
    except urllib.error.URLError as e:
        if not isinstance(getattr(e, "reason", None), ssl.SSLError):
            raise
    ctx = ssl._create_unverified_context()
    with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
        return r.read(2_000_000).decode("utf-8", "replace"), r.geturl(), True


def pages_for(pool):
    """The pool's link plus every http(s) page its entries cite as a source."""
    urls = []
    cands = [pool.get("link", "")] + [e.get("source", "") for e in pool.get("endpoints", [])]
    cands.append((pool.get("terms") or {}).get("source", ""))
    cands.append((pool.get("sv1_closed") or {}).get("source", ""))
    for s in cands:
        m = re.match(r"\s*(https?://\S+)", s or "")
        if m and m.group(1) not in urls:
            urls.append(m.group(1))
    return urls


def listed_hostports(pool):
    out = set()
    for e in pool.get("endpoints", []):
        if e.get("url"):
            u = urlsplit(e["url"])
            if u.hostname and u.port:
                out.add(f"{u.hostname.lower()}:{u.port}")
        elif e.get("host") and e.get("port"):
            out.add(f"{e['host'].lower()}:{e['port']}")
    return out


def dom(host):
    return ".".join((host or "").split(":")[0].split(".")[-2:])


def site_findings(pools, feed):
    """Findings about the pages, and the per-pool record of what they showed."""
    found, cache = [], {}
    # Pools with several products (PyBLOCK) share pages, so a port on the page
    # counts as listed if any row on the same domain lists it.
    by_domain = {}
    for p in pools:
        for h in listed_hostports(p):
            by_domain.setdefault(dom(h), set()).add(h)
    stamp = now_iso()
    for p in pools:
        urls = pages_for(p)
        if not urls:
            continue
        seen, keys, errors, insecure, pages_ok = {}, {}, [], [], []
        for url in urls:
            if url not in cache:
                try:
                    cache[url] = fetch(url)
                except Exception as e:  # noqa: BLE001
                    cache[url] = e
            got = cache[url]
            if isinstance(got, Exception):
                errors.append(f"{url}: {type(got).__name__}: {got}"[:200])
                continue
            text, final, unverified = got
            pages_ok.append(url)
            if unverified:
                insecure.append(url)
            own = urlsplit(final)
            for host, port in HOSTPORT.findall(text) + CONFHOST.findall(text):
                host = host.lower()
                if port in WEB_PORTS or port in OTHER_PORTS or (host == (own.hostname or "") and port == str(own.port or "")):
                    continue
                if re.search(r"\.(png|jpe?g|svg|css|js|php|html?)$", host):
                    continue
                seen.setdefault(f"{host}:{port}", url)
            for k in PUBKEY.findall(text):
                keys.setdefault(k.lower(), url)
            if urlsplit(url).hostname != own.hostname:
                found.append(("site", p["label"], f"{url} now redirects to {final}"))
        label = p["label"]
        for e in errors:
            found.append(("site", label, f"page did not load: {e}"))
        for u in insecure:
            found.append(("site", label, f"{u}: TLS certificate does not verify"))
        listed = listed_hostports(p)
        # Only compare hosts the pool itself uses; a page naming another pool's
        # gateway is not this pool's endpoint.
        domains = {dom(h) for h in listed} | {dom(urlsplit(u).hostname) for u in urls}
        own_seen = {h: u for h, u in seen.items() if dom(h) in domains}
        # The feed: what this pool's own pages showed, merged with earlier reads.
        rec = feed.setdefault(label, {"endpoints": {}, "pubkeys": {}})
        rec.update(read=stamp, pages=pages_ok, errors=errors, readable=bool(own_seen))
        for h, u in own_seen.items():
            e = rec["endpoints"].setdefault(h, {"first_seen": stamp})
            e.update(last_seen=stamp, page=u)
        for k, u in keys.items():
            e = rec["pubkeys"].setdefault(k, {"first_seen": stamp})
            e.update(last_seen=stamp, page=u)
        if errors and not seen:
            continue
        anywhere = set().union(*(by_domain.get(d, set()) for d in domains))
        for h in sorted(set(own_seen) - anywhere):
            found.append(("site", label, f"on the site, not in the list: {h}"))
        if own_seen:
            for h in sorted(listed - set(own_seen)):
                found.append(("site", label, f"in the list, no longer on the site: {h}"))
        elif listed:
            found.append(("site", label, "no endpoints readable on the pages (script-rendered?); list not checked"))
        mine = (p.get("datum_pubkey") or "").lower()
        if mine and keys and mine not in keys:
            found.append(("site", label, f"listed DATUM pubkey {mine[:8]}... not on the site; site shows {', '.join(sorted(k[:8] + '...' for k in keys))}"))
        if not mine and len(keys) == 1:
            found.append(("site", label, f"site shows a DATUM pubkey the list lacks: {next(iter(keys))[:8]}..."))
    return found


def prune_feed(feed):
    cutoff = datetime.now(timezone.utc).timestamp() - FORGET_DAYS * 86400
    for rec in feed.values():
        for kind in ("endpoints", "pubkeys"):
            for k in list(rec.get(kind, {})):
                try:
                    seen = datetime.strptime(rec[kind][k]["last_seen"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
                except Exception:  # noqa: BLE001
                    seen = 0
                if seen < cutoff:
                    del rec[kind][k]


def chain_findings(pools):
    try:
        cb = json.load(open(REWARDS))["coinbases"]
    except Exception as e:  # noqa: BLE001
        return [("chain", "-", f"rewards.json unreadable: {e}")]
    rows = list(cb.values())
    if not rows:
        return []
    top = max(r["h"] for r in rows)
    recent, quiet = {}, {}
    for r in rows:
        lab = r.get("label") or ""
        if r["h"] > top - RECENT_BLOCKS:
            recent[lab] = recent.get(lab, 0) + 1
        if r["h"] > top - QUIET_BLOCKS:
            quiet[lab] = quiet.get(lab, 0) + 1
    listed = {p["label"] for p in pools}
    out = []
    for lab, n in sorted(recent.items(), key=lambda x: -x[1]):
        if lab not in listed and n >= MIN_UNLISTED and not lab.startswith(("Unknown", "Solo ")):
            out.append(("chain", lab, f"{n} blocks in the last {RECENT_BLOCKS}, not in the endpoint list"))
    for p in pools:
        if p.get("endpoints") and any(e.get("url") or e.get("host") for e in p["endpoints"]) \
                and not quiet.get(p["label"]) and not p["label"].endswith("(unattributed on-chain)"):
            out.append(("chain", p["label"], f"listed, but no blocks in the last {QUIET_BLOCKS}; retired or renamed?"))
    return out


def probe_findings(state):
    """Verdict per endpoint from the latest survey; report a change once it holds two runs."""
    try:
        sv = json.load(open(SURVEY))
    except Exception as e:  # noqa: BLE001
        return [("probe", "-", f"pool-survey.json unreadable: {e}")]
    last = state.get("verdicts", {})
    pending = state.get("pending", {})
    now, new_pending, out = {}, {}, []
    for p in sv.get("pools", []):
        for e in p.get("endpoints", []):
            k = f"{p['label']}|{e['endpoint']}"
            v = e.get("verdict", "")
            if e.get("datum_check"):
                v = "datum " + e["datum_check"].get("result", "")
            v = "socket-error" if v.startswith("socket-error") else v
            now[k] = last.get(k, v)
            if k in last and v != last[k]:
                if pending.get(k) == v:
                    out.append(("probe", p["label"], f"{e['endpoint']} was {last[k]}, now {v} (two runs)"))
                    now[k] = v
                else:
                    new_pending[k] = v
    state["verdicts"], state["pending"] = now, new_pending
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-mail", action="store_true")
    ap.add_argument("--print", action="store_true")
    ap.add_argument("--feed", default=SITE_EPS)
    a = ap.parse_args()

    pools = json.load(open(ENDPOINTS))["pools"]
    try:
        state = json.load(open(STATE))
    except Exception:  # noqa: BLE001
        state = {}
    try:
        feed = json.load(open(a.feed)).get("pools", {})
    except Exception:  # noqa: BLE001
        feed = {}

    found = site_findings(pools, feed) + chain_findings(pools) + probe_findings(state)
    prune_feed(feed)
    with open(a.feed + ".tmp", "w") as f:
        json.dump({"generated": now_iso(), "pools": feed}, f, indent=1, sort_keys=True)
    os.replace(a.feed + ".tmp", a.feed)

    lines = [f"[{k}] {lab}: {msg}" for k, lab, msg in found]
    # Probe changes are events, reported when they happen; site and chain
    # items are conditions, reported when the set of them changes. Counts in
    # a condition (blocks in the last day) change every run and are not news.
    cond = sorted(l for l in lines if not l.startswith("[probe]"))
    events = [l for l in lines if l.startswith("[probe]")]
    key = lambda l: re.sub(r"\d+", "N", l)  # noqa: E731

    body = f"pool-site-watch {now_iso()}\n\n" + ("\n".join(lines) if lines else "no differences") + "\n"
    with open(REPORT + ".tmp", "w") as f:
        f.write(body)
    os.replace(REPORT + ".tmp", REPORT)
    if a.print:
        sys.stdout.write(body)

    mailed = {key(l) for l in state.get("mailed", [])}
    new_items = [l for l in cond if key(l) not in mailed]
    if (new_items or events) and not a.no_mail and MAILTO:
        subj = f"reorg.watch: {len(new_items) + len(events)} pool listing change(s)"
        text = body + "\nNew since the last mail:\n" + "\n".join(new_items + events) + "\n\nList: " + ENDPOINTS + "\n"
        subprocess.run(["mail", "-s", subj, MAILTO], input=text.encode(), check=True)
        print(f"{now_iso()} mailed {len(new_items) + len(events)} item(s)")
    if not a.no_mail:
        state["mailed"] = cond
    state["checked"] = now_iso()
    with open(STATE + ".tmp", "w") as f:
        json.dump(state, f, indent=1)
    os.replace(STATE + ".tmp", STATE)
    print(f"{now_iso()} {len(lines)} finding(s)")


if __name__ == "__main__":
    main()
