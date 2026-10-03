#!/usr/bin/env python3
"""pool-survey.py - probe every known pool endpoint and write a survey JSON.

Produces one row per pool joining four independent things:
  1. what its advertised endpoints actually speak      (measured here)
  2. whether its DATUM service answers a real handshake (measured here, datum-check.py)
  3. what its blocks say built them                    (reorg-watch's D/G/O class)
  4. how the reward leaves the block                   (coinbase output shape)

Endpoints come from two places: the hand-kept list (pool-endpoints.json, with
the pool's own pages as the source) and the endpoints pool-site-watch.py last
read off those pages (site-endpoints.json). A port that appears on a pool's
page is probed the next hour whether or not anyone has edited the list, and a
listed port the page no longer shows is still probed and marked as such.

A stratum port is probed with one mining.subscribe. A DATUM port is probed
with one real DATUM handshake against the pool's published pubkey, which
proves a prime is listening under that key; nothing is asked of it after that.

Nothing here is a verdict. Every field records what was observed, when, and says
"unknown" when it was not observed. A consistency flag fires only on a specific,
stated contradiction; anything else reads "consistent" or "not testable".

Usage: pool-survey.py [--endpoints FILE] [--rewards FILE] [--out FILE]
                      [--window N] [--rest URL] [--delay S] [--no-probe]
"""

import argparse, collections, importlib.machinery, importlib.util, json, os, sys, time
from datetime import datetime, timezone, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
SD = os.path.expanduser("~/.reorg-watch")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


pp = _load("pp", os.path.join(HERE, "pool-probe.py"))
try:
    dc = _load("dc", os.path.join(HERE, "datum-check.py"))
    dc.sodium()
except Exception as e:  # noqa: BLE001
    dc, DC_WHY = None, "datum-check.py unavailable: %s" % e
else:
    DC_WHY = ""

DISCOVERED_MAX_AGE_H = 48        # a page endpoint not seen for this long is not probed
VERIFIED_RECENT_H = 24           # a handshake this recent still counts as "seen working"
PERSISTENT_FAILS = 3             # consecutive failed runs before a failure is called persistent


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:  # noqa: BLE001
        return None


def spk_address():
    """reorg-watch's own script-to-address decoder, so the survey and the page read addresses
    the same way. reorg-watch.py sits one directory up."""
    path = os.path.join(os.path.dirname(HERE), "reorg-watch.py")
    loader = importlib.machinery.SourceFileLoader("reorg_watch", path)
    spec = importlib.util.spec_from_loader("reorg_watch", loader)
    mod = importlib.util.module_from_spec(spec)
    saved, sys.argv = sys.argv, ["reorg_watch"]
    loader.exec_module(mod)
    sys.argv = saved
    return lambda spk: mod.spk_to_address(bytes.fromhex(spk))


def probe_worker(path=os.path.join(SD, "probe-worker.json")):
    """The throwaway worker the probe authorizes on ports a site calls closed and on ports
    that answer a subscribe without a job: a valid P2WPKH address made from random bytes
    on first use (no key behind it, nothing is ever mined to it) plus a worker name that
    says who is asking."""
    try:
        return json.load(open(path))["username"]
    except Exception:  # noqa: BLE001
        pass
    spk = "0014" + os.urandom(20).hex()
    addr = spk_address()(spk)
    rec = {"spk": spk, "address": addr, "username": addr + ".reorg-watch-probe", "created": now_iso(),
           "note": "random bytes, no key; used only to authorize, never to mine"}
    with open(path + ".tmp", "w") as f:
        json.dump(rec, f, indent=1)
    os.replace(path + ".tmp", path)
    return rec["username"]


def onchain_facts(rewards_path, window, own_by_label=None):
    """Class mix and payout shape per label, from reorg-watch's own coinbase index.
    own_by_label maps a label to the addresses the survey records as the pool's own.
    Also returns every coinbase row per label, for the change detector."""
    try:
        cb = json.load(open(rewards_path))["coinbases"]
    except Exception:
        return {}, None, {}
    rows = sorted(cb.values(), key=lambda d: d["h"])
    if not rows:
        return {}, None, {}
    top = rows[-1]["h"]
    recent = [x for x in rows if x["h"] > top - window]
    out = collections.defaultdict(lambda: {"blocks": 0, "cls": collections.Counter(),
                                           "outs": [], "value_sats": 0, "scripts": collections.Counter()})
    for x in recent:
        r = out[x.get("label") or "unknown"]
        r["blocks"] += 1
        r["cls"][x.get("cls", "?")] += 1
        outs = x.get("outs") or {}
        r["outs"].append(len(outs))
        for spk, v in outs.values():
            r["value_sats"] += v
            r["scripts"][spk] += v
    # Payout shape from each label's last 20 coinbases, however old, so a pool that changes
    # how it pays is read correctly within a day or two instead of after the window slides.
    by_label = collections.defaultdict(list)
    for x in rows:
        by_label[x.get("label") or "unknown"].append(x)
    own_by_label = own_by_label or {}
    addr = spk_address() if any(own_by_label.values()) else None
    shape = {}
    for lab, xs in by_label.items():
        last = xs[-20:]
        scripts, total = collections.Counter(), 0
        for x in last:
            for spk, v in (x.get("outs") or {}).values():
                scripts[spk] += v
                total += v
        own = own_by_label.get(lab)
        if own and addr and total:
            own_pct = 100 * sum(v for spk, v in scripts.items() if addr(spk) in own) / total
            top_is_own = addr(scripts.most_common(1)[0][0]) in own
        else:
            own_pct = top_is_own = None
        shape[lab] = (sorted(len(x.get("outs") or {}) for x in last), scripts.most_common(1), total, len(last), own_pct, top_is_own)
    res = {}
    for lab, r in out.items():
        o, dom, shape_value, shape_blocks, own_pct, top_is_own = shape[lab]
        res[lab] = {
            "blocks": r["blocks"],
            "share_pct": round(100 * r["blocks"] / len(recent), 2),
            "class_mix": dict(r["cls"]),
            "class_majority": r["cls"].most_common(1)[0][0] if r["cls"] else None,
            "median_outputs": o[len(o) // 2] if o else None,
            "mean_outputs": round(sum(o) / len(o), 2) if o else None,
            "value_btc": round(r["value_sats"] / 1e8, 2),
            "dominant_script": dom[0][0] if dom else None,
            "dominant_script_pct": round(100 * dom[0][1] / shape_value, 1) if dom and shape_value else None,
            "shape_blocks": shape_blocks,
            "own_known": own_pct is not None,
            "own_pct": round(own_pct, 1) if own_pct is not None else None,
            "dominant_is_own": top_is_own,
        }
    return res, {"window": window, "through_height": top, "blocks": len(recent)}, by_label


def onchain_changes(xs, days=30, min_blocks=3):
    """What changed in how a label's blocks are built and paid, read day by day.

    For each UTC day with at least min_blocks blocks: the majority coinbase class
    (D = through a DATUM gateway with a pool upstream, G = a stand-alone gateway or
    the pool's own stratum, O = other) and the median number of coinbase outputs,
    bucketed (1, 2, 3-9, 10+). The most recent switch that has held since
    is reported, with the values before and after and the day it started. Nothing
    is reported for a label whose days all agree."""
    daily = collections.OrderedDict()
    cutoff = time.time() - days * 86400
    for x in xs:
        if x["t"] < cutoff:
            continue
        d = time.strftime("%Y-%m-%d", time.gmtime(x["t"]))
        daily.setdefault(d, []).append(x)

    def bucket(n):
        return 1 if n <= 1 else 2 if n == 2 else 3 if n < 10 else 10

    def median(v):
        v = sorted(v)
        return v[len(v) // 2] if v else 0

    series = []
    for d, blocks in daily.items():
        if len(blocks) < min_blocks:
            continue
        cls = collections.Counter(b.get("cls", "?") for b in blocks).most_common(1)[0][0]
        outs = [len(b.get("outs") or {}) for b in blocks]
        tags = {(b.get("tags") or [None, None])[1] for b in blocks if len(b.get("tags") or []) > 1}
        series.append((d, cls, bucket(median(outs)), median(outs), len(tags - {None, ""})))
    if len(series) < 3:
        return [], (series[-1][4] if series else 0)
    out = []
    for key, name in ((1, "builder"), (2, "payout")):
        last = series[-1][key]
        i = len(series) - 1
        while i > 0 and series[i - 1][key] == last:
            i -= 1
        if i == 0 or i == len(series) - 1:
            continue                                    # no switch, or it started today (wait a day)
        before = series[i - 1][key]
        if any(s[key] == before for s in series[i:]):
            continue                                    # flapping, not a switch
        rec = {"kind": name, "since": series[i][0], "days": len(series) - i}
        if name == "builder":
            rec.update(**{"from": before, "to": last})
        else:
            rec.update(**{"from": series[i - 1][3], "to": series[-1][3]})
        out.append(rec)
    return out, series[-1][4]


def payout_shape(f):
    """How the reward leaves the block. Wording matches the existing page."""
    m = f.get("median_outputs")
    if m is None:
        return "unknown"
    if m <= 1:
        return "one output, paid out later"
    if m <= 2 and f.get("own_known") and not f.get("dominant_is_own"):
        return "paid in the coinbase to one address, not the pool's"
    if m <= 2:
        return "two outputs"
    return "paid to miners in the coinbase"


def site_endpoints_for(site, label, listed):
    """Endpoints and pubkeys pool-site-watch.py read off this pool's pages recently."""
    rec = (site.get("pools") or {}).get(label) or {}
    cutoff = datetime.now(timezone.utc) - timedelta(hours=DISCOVERED_MAX_AGE_H)
    found, gone = [], []
    for hp, info in (rec.get("endpoints") or {}).items():
        seen = parse_iso(info.get("last_seen", ""))
        if seen and seen >= cutoff:
            if hp not in listed:
                found.append((hp, info.get("page", "")))
        elif hp in listed:
            gone.append(hp)
    for hp in listed:
        info = (rec.get("endpoints") or {}).get(hp)
        if rec.get("read") and rec.get("readable") and not info:
            gone.append(hp)
    keys = [k for k, info in (rec.get("pubkeys") or {}).items()
            if (parse_iso(info.get("last_seen", "")) or datetime.min.replace(tzinfo=timezone.utc)) >= cutoff]
    return found, sorted(set(gone)), keys, rec.get("read"), rec.get("pages") or [], bool(rec.get("readable"))


def datum_status(pool, checks, dstate, probed_eps=()):
    """Did we see a DATUM service? Never infer absence from silence alone.
    Returns (status string, summary dict). The string keeps the prefixes the page
    groups on: 'yes, ...', 'endpoint published ...', 'DATUM mining documented ...',
    'no DATUM ...', 'not mentioned ...', 'unknown ...'."""
    if pool.get("datum_note"):
        return pool["datum_note"], None
    eps = [e for e in pool.get("endpoints", []) if e.get("expect") == "datum" and (e.get("url") or e.get("host"))]
    pubkey = pool.get("datum_pubkey") or ""
    if checks:
        ok = [c for c in checks if c["result"] == "verified"]
        if ok:
            c = ok[0]
            return "yes, handshake verified %s" % c["checked_at"], {
                "result": "verified", "endpoint": c["endpoint"], "checked_at": c["checked_at"],
                "reply_ms": c.get("reply_ms"), "motd": c.get("detail", ""), "last_verified": c["checked_at"],
                "detail": "the pool's DATUM service answered a real handshake under its published key"}
        c = checks[0]
        st = dstate.get("%s|%s" % (c["endpoint"], (pool.get("datum_pubkey") or "")[:16]), {})
        lv = st.get("last_verified")
        recent = lv and (parse_iso(lv) or datetime.min.replace(tzinfo=timezone.utc)) >= datetime.now(timezone.utc) - timedelta(hours=VERIFIED_RECENT_H)
        fails = st.get("failed_runs", 0)
        why = "%s (%s)" % (c["result"], c.get("detail", "")) if c.get("detail") else c["result"]
        summary = {"result": "failed", "endpoint": c["endpoint"], "checked_at": c["checked_at"], "last_verified": lv,
                   "failed_runs": fails, "why": why, "motd": st.get("motd", "")}
        if recent:
            summary["detail"] = "verified at %s; the last handshake failed: %s" % (lv, why)
            return "yes, verified earlier, handshake failed now: %s" % why, summary
        summary["detail"] = "handshake failed %d run(s) in a row: %s" % (fails, why) if fails else "handshake failed: %s" % why
        if lv:
            return "yes, pubkey and endpoint published, handshake failed since %s: %s" % (lv, why), summary
        return "yes, pubkey and endpoint published, handshake failed: %s" % why, summary
    if eps and pubkey:
        return "yes, pubkey and endpoint published (handshake not attempted: %s)" % (DC_WHY or "no run"), \
            {"result": "not attempted", "detail": DC_WHY or "no handshake run"}
    if eps and not pubkey:
        # No key, no handshake. A live DATUM port accepts the connection and drops a stratum
        # subscribe without a word; a refused or timed-out port is not serving anything.
        opened = any(str(e.get("verdict") or "") in ("no-response", "read-timeout") or str(e.get("verdict") or "").startswith("socket-error")
                     for e in probed_eps if e.get("expect") == "datum")
        return "endpoint published, no pubkey found (handshake not possible)", \
            {"result": "not possible", "port_open": opened,
             "detail": "the pool has not published its DATUM pubkey, so its service cannot be verified; the port %s a connection"
                       % ("accepts" if opened else "does not accept")}
    if pool.get("datum_documented") and pool.get("site_checked"):
        return ("DATUM mining documented, pool host not listed on the page checked %s"
                % pool["site_checked"]), None
    if pool.get("site_checked"):
        # Absence from one page is not proof the service does not exist. Say exactly
        # what was and was not seen, and never let this drive a contradiction.
        return "not mentioned on the page checked %s" % pool["site_checked"], None
    return "unknown, no source checked", None


NO_ANSWER = ("refused", "connect-timeout", "no-response", "no-connection", "read-timeout")


def site_vs_probe(pool, eps, dh):
    """What the pool's own pages claim next to what the probe found, one record per
    claim: the closure of a path, a DATUM service, and each stratum port the page
    lists. 'agree' is True, False, or None when the probe cannot test the claim.
    Answering a subscribe with work is all the probe can see; whether a share sent
    there is credited or paid is not measured, and the page says so."""
    out = []

    def no_answer(e):
        v = str(e.get("verdict") or "")
        return v in NO_ANSWER or v.startswith(("socket-error", "dns-failure", "tls-error"))

    def when(es):
        return max((e.get("probed_at") or "" for e in es), default=None) or None

    closed = pool.get("sv1_closed")
    closed_eps = [e for e in eps if e.get("closed")]
    if closed or closed_eps:
        what = (closed or {}).get("what") or "the stratum path is closed"
        date = (closed or {}).get("date") or ""
        claim = "site says %s%s" % (what, ", " + date if date else "")
        answering = [e for e in closed_eps if e.get("verdict") == "stratum-v1"]
        if not closed_eps:
            found, agree = "no port named, nothing to test", None
        elif answering:
            work = sum(1 for e in answering if e.get("chain") == "this")
            found = "%d of %d port%s still answer%s a subscribe" % (
                len(answering), len(closed_eps), "s" if len(closed_eps) != 1 else "", "" if len(answering) != 1 else "s")
            if work:
                found += ", %s handing out work for this chain" % ("all" if work == len(answering) else work)
            auth = [e["authorize"] for e in answering if e.get("authorize")]
            if auth:
                ok = [a for a in auth if a.get("result") is True]
                if ok and any(a.get("jobs_after") for a in ok):
                    found += "; a throwaway worker was accepted and kept getting work"
                elif ok:
                    found += "; a throwaway worker was accepted as well"
                else:
                    why = "; ".join(str(a.get("error") or " / ".join(a.get("messages") or []) or ("connection closed" if a.get("closed") else "no reply")) for a in auth)
                    found += "; a throwaway worker was refused: " + why[:160]
            agree = False
        else:
            found = "port%s refused or silent" % ("s" if len(closed_eps) != 1 else "")
            agree = True
        out.append({"kind": "closure", "claim": claim, "found": found, "agree": agree,
                    "checked_at": when(closed_eps), "source": (closed or {}).get("source") or closed_eps[0].get("source", ""),
                    "ports": [e["endpoint"] for e in closed_eps]})
    datum_eps = [e for e in eps if e.get("expect") == "datum" and not e.get("discovered")]
    if datum_eps:
        claim = "site publishes a DATUM service at " + ", ".join(e["endpoint"] for e in datum_eps)
        if dh and dh.get("result") == "verified":
            found, agree = "handshake verified under the published key", True
        elif dh and dh.get("result") == "failed":
            found, agree = "handshake failed: " + (dh.get("why") or "no reply"), False
        elif dh and dh.get("result") == "not possible":
            # Without a pubkey the handshake cannot be tried. A DATUM port drops a stratum
            # subscribe without a word, so "opened, then silent" is what a live one looks like.
            opened = [e for e in datum_eps if str(e.get("verdict") or "") in ("no-response", "read-timeout")
                      or str(e.get("verdict") or "").startswith("socket-error")]
            found = "no pubkey published, so the handshake cannot be tried; the port %s" % (
                "accepts a connection" if opened else "does not accept a connection")
            agree = None
        else:
            found, agree = "not checked", None
        out.append({"kind": "datum", "claim": claim, "found": found, "agree": agree,
                    "checked_at": (dh or {}).get("checked_at") or when(datum_eps), "source": datum_eps[0].get("source", "")})
    # Every stratum port the pool's own material puts on file (its page, or its docs
    # and gateway source when the page prints no host:port), except ports the page has
    # since dropped and ports the site calls closed, which have their own claim.
    listed = [e for e in eps if e.get("on_site") is not False and not e.get("closed") and not e.get("unclaimed")
              and e.get("expect") == "stratum-v1" and not e.get("discovered")]
    if listed:
        n = len(listed)
        on_page = all(e.get("on_site") for e in listed)
        claim = "%s %d stratum port%s" % ("page lists" if on_page else "pool's own docs list", n, "s" if n != 1 else "")
        dead = [e for e in listed if no_answer(e)]
        work = [e for e in listed if e.get("chain") == "this"]
        other = [e for e in listed if e.get("chain") == "other"]
        parts = []
        if len(work) == n:
            parts.append("all hand out work for this chain" if n != 1 else "it hands out work for this chain")
        elif work:
            parts.append("work for this chain from %d of %d" % (len(work), n))
        silent = [e for e in listed if e not in dead and e not in work and e not in other]
        if silent:
            parts.append("%s answer%s a subscribe without a job" % (", ".join(e["endpoint"] for e in silent), "" if len(silent) != 1 else "s"))
        if other:
            parts.append("a job for another chain from " + ", ".join(e["endpoint"] for e in other))
        if dead:
            parts.append("no answer from " + ", ".join("%s (%s)" % (e["endpoint"], e.get("verdict")) for e in dead))
        found = "; ".join(parts) or "answer a subscribe"
        agree = False if (dead or other) else True
        out.append({"kind": "ports", "claim": claim, "found": found, "agree": agree, "checked_at": when(listed),
                    "ports": [e["endpoint"] for e in listed]})
    return out


def consistency(pool, f, sw_names, dstatus, dh):
    """Fires ONLY on positive evidence of a contradiction.

    Two conditions can produce "mismatch", and nothing else may:
      1. blocks declare a DATUM upstream (class D), a DATUM endpoint and pubkey ARE
         published, and the handshake against it has failed for PERSISTENT_FAILS
         consecutive hourly runs;
      2. a handshake succeeded and the pool's own signed payout scriptSig is not the
         script its attributed blocks actually pay (not measured by the handshake
         alone, kept for a future coinbaser fetch).
    Absence of a listing on a web page is NOT evidence of absence of service and can
    never reach this function as a contradiction. One failed handshake is not either.
    """
    maj = (f or {}).get("class_majority")
    if not f or not maj:
        return "not testable", "no on-chain blocks in the window"

    if dh and dh.get("result") == "verified":
        declared = (dh.get("payout_scriptsig") or "").lower()
        actual = (f.get("dominant_script") or "").lower()
        if declared and actual and declared != actual:
            return "mismatch", ("the pool's signed DATUM payout script does not match the "
                                "script its blocks pay (declared %s..., paid %s...)"
                                % (declared[:16], actual[:16]))
        return "consistent", "the published DATUM key answers a handshake" + (
            " and the blocks declare a DATUM upstream" if maj == "D" else "")

    if maj == "D":
        if dh and dh.get("result") == "failed" and dh.get("failed_runs", 0) >= PERSISTENT_FAILS:
            return "mismatch", ("blocks declare a DATUM upstream (class D) but the handshake "
                                "against the published endpoint has failed %d runs in a row: %s"
                                % (dh["failed_runs"], dh.get("why", "no reason given")))
        if dh and dh.get("result") == "failed":
            return "not testable", "blocks declare class D; the last handshake failed, waiting for it to persist"
        return "not testable", "blocks declare class D; no DATUM handshake has been run"

    if not sw_names:
        return "not testable", "no endpoint reached"
    return "consistent", "on-chain class and endpoint behavior agree"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoints", default=os.path.join(HERE, "pool-endpoints.json"))
    ap.add_argument("--site-endpoints", default=os.path.join(SD, "site-endpoints.json"))
    ap.add_argument("--rewards", default=os.path.join(SD, "rewards.json"))
    ap.add_argument("--out", default=os.path.join(HERE, "pool-survey.json"))
    ap.add_argument("--log", default=os.path.join(HERE, "probe-log.jsonl"))
    ap.add_argument("--datum-log", default=os.path.join(HERE, "datum-log.jsonl"))
    ap.add_argument("--datum-state", default=os.path.join(SD, "datum-check.json"))
    ap.add_argument("--window", type=int, default=2016)
    ap.add_argument("--rest", default="http://127.0.0.1:8332/rest")
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--min-diff", type=float, default=1.0)
    ap.add_argument("--no-probe", action="store_true", help="reuse the last probe and handshake logs")
    ap.add_argument("--no-datum", action="store_true", help="skip DATUM handshakes")
    args = ap.parse_args()

    doc = json.load(open(args.endpoints))
    doc_own = {p["label"]: set(p.get("own_addresses") or []) for p in doc.get("pools", [])}
    facts, window_meta, by_label = onchain_facts(args.rewards, args.window, doc_own)
    try:
        site = json.load(open(args.site_endpoints))
    except Exception:  # noqa: BLE001
        site = {}
    try:
        dstate = json.load(open(args.datum_state))
    except Exception:  # noqa: BLE001
        dstate = {}
    datum_on = bool(dc) and not args.no_datum

    # --- targets: the list, plus what the pools' pages show that the list does not ---
    targets = []                  # (label, host, port, tls, ep_dict)
    site_info = {}
    for p in doc.get("pools", []):
        listed = set()
        for ep in p.get("endpoints", []):
            host, port, tls = pp.parse_endpoint(ep)
            if host and port:
                listed.add("%s:%d" % (host, port))
                targets.append((p["label"], host, port, tls, ep))
        found, gone, keys, read, pages, readable = site_endpoints_for(site, p["label"], listed)
        site_info[p["label"]] = {"read": read, "pages": pages, "discovered": [hp for hp, _ in found],
                                 "gone": gone, "pubkeys_on_site": keys, "readable": readable}
        for hp, page in found:
            host, _, port = hp.rpartition(":")
            targets.append((p["label"], host, int(port), False,
                            {"url": "stratum+tcp://" + hp, "expect": "unknown", "role": "on the pool's site, not in the list",
                             "source": "%s (read %s)" % (page, (read or "")[:10]), "discovered": True}))

    # --- probe (or reuse the newest record per endpoint) ---
    results, checks = {}, {}
    if args.no_probe:
        for ln in open(args.log):
            r = json.loads(ln)
            results[(r["host"], r["port"])] = r
        if os.path.exists(args.datum_log):
            for ln in open(args.datum_log):
                r = json.loads(ln)
                if not r.get("guess") or r["result"] == "verified":
                    checks[(r["host"], r["port"], r.get("pubkey", ""))] = r
    else:
        keys = dc.load_keys() if datum_on else None
        stratum_targets, datum_targets = [], []      # datum_targets: (host, port, pubkey, listed)
        for label, host, port, tls, ep in targets:
            pool = next(x for x in doc["pools"] if x["label"] == label)
            pubkey = pool.get("datum_pubkey") or ""
            if not pubkey and len(site_info[label]["pubkeys_on_site"]) == 1 and ep.get("discovered"):
                pubkey = site_info[label]["pubkeys_on_site"][0]
            if ep.get("expect") == "datum":
                if datum_on and pubkey:
                    datum_targets.append((host, port, pubkey, True))
                else:
                    stratum_targets.append((host, port, tls))      # port check only
            else:
                stratum_targets.append((host, port, tls))
                if ep.get("discovered") and datum_on and pubkey:
                    datum_targets.append((host, port, pubkey, False))  # unknown port: try both, once
        # A port a site calls closed always gets the throwaway worker; any other port gets it
        # only when it answers the subscribe without a job, so "hands out work" means a job
        # for this chain reached a worker the pool has never seen.
        closed_ports = {(h, pt) for _, h, pt, _, ep in targets if ep.get("closed")}
        worker = probe_worker()
        seen = set()
        with open(args.log, "a") as log:
            for host, port, tls in stratum_targets:
                if (host, port) in seen:
                    continue
                seen.add((host, port))
                r = pp.probe(host, port, tls, args.timeout, pp.DEFAULT_UA, args.min_diff,
                             authorize=worker, authorize_if_idle=(host, port) not in closed_ports)
                ph = (r["facts"].get("job") or {}).get("prevhash")
                if ph:
                    r["built_on"] = pp.resolve_prevhash(ph, args.rest.rstrip("/"), 25)
                log.write(json.dumps(r) + "\n")
                log.flush()
                results[(host, port)] = r
                time.sleep(args.delay)
        # Listed DATUM endpoints first, so a guess never shadows a real check of the same
        # port; the same port under two different keys (PyBLOCK's three pools share a host)
        # is two different checks.
        seen = set()
        with open(args.datum_log, "a") as log:
            for host, port, pubkey, listed in sorted(datum_targets, key=lambda t: not t[3]):
                if (host, port, pubkey) in seen:
                    continue
                seen.add((host, port, pubkey))
                if (host, port) in results and results[(host, port)]["verdict"] == "stratum-v1":
                    continue                                          # a stratum port is not a DATUM port
                r = dc.check(host, port, pubkey, keys, args.timeout)
                r["endpoint"] = "%s:%d" % (host, port)
                r["guess"] = not listed
                r["pubkey"] = pubkey[:16]
                log.write(json.dumps(r) + "\n")
                log.flush()
                if not listed and r["result"] != "verified":
                    time.sleep(args.delay)
                    continue                                          # a guess that failed says nothing
                checks[(host, port, pubkey)] = r
                st = dstate.setdefault("%s|%s" % (r["endpoint"], pubkey[:16]), {})
                if r["result"] == "verified":
                    st.update(last_verified=r["checked_at"], failed_runs=0, motd=r.get("detail", ""))
                else:
                    st["failed_runs"] = st.get("failed_runs", 0) + 1
                st.update(last_result=r["result"], last_checked=r["checked_at"])
                time.sleep(args.delay)
        with open(args.datum_state + ".tmp", "w") as f:
            json.dump(dstate, f, indent=1, sort_keys=True)
        os.replace(args.datum_state + ".tmp", args.datum_state)

    # --- assemble one row per pool ---
    rows = []
    for p in doc.get("pools", []):
        label = p["label"]
        f = facts.get(label)
        eps_out, sw_names, pool_checks = [], [], []
        pool_key = p.get("datum_pubkey") or ""
        site_keys = site_info[label]["pubkeys_on_site"]
        for lab, host, port, tls, ep in targets:
            if lab != label:
                continue
            key = "%s:%d" % (host, port)
            r = results.get((host, port))
            pk = pool_key or (site_keys[0] if len(site_keys) == 1 and ep.get("discovered") else "")
            c = next((v for (h, pt, k), v in checks.items() if h == host and pt == port and k[:16] == pk[:16]), None) if pk else None
            rec = {"endpoint": key, "role": ep.get("role", ""), "expect": ep.get("expect", ""),
                   "source": ep.get("source", ""), "discovered": bool(ep.get("discovered")),
                   "closed": bool(ep.get("closed")), "unclaimed": bool(ep.get("unclaimed")),
                   "on_site": (key not in site_info[label]["gone"]) if site_info[label]["readable"] else None}
            if r:
                sub = next((l for l in r.get("reply_lines", []) if '"result"' in l and "mining." in l), None)
                sw, why = pp.fingerprint(sub, r["facts"].get("configure_reply", "(silent)")) if sub else ("-", "")
                if sw not in ("-", "unknown", "unparsed"):
                    sw_names.append(sw)
                job = r["facts"].get("job") or {}
                rec.update({
                    "verdict": r["verdict"], "software": sw, "software_why": why,
                    "set_difficulty": r["facts"].get("initial_difficulty"),
                    "built_on_height": (r.get("built_on") or {}).get("height"),
                    "chain": "this" if r.get("built_on") else ("other" if job.get("prevhash") else "unknown"),
                    "commitment": r["facts"].get("blake2b_commitment"),
                    "probed_at": r["probed_at"],
                })
                if r["facts"].get("authorize"):
                    rec["authorize"] = r["facts"]["authorize"]
            if c:
                st = dstate.get("%s|%s" % (key, pk[:16]), {})
                rec["datum_check"] = {"result": c["result"], "detail": c.get("detail", ""), "checked_at": c["checked_at"],
                                      "reply_ms": c.get("reply_ms"), "last_verified": st.get("last_verified"),
                                      "failed_runs": st.get("failed_runs", 0)}
                pool_checks.append(dict(c, endpoint=key))
                rec.setdefault("probed_at", c["checked_at"])
                # "verdict" is what every reader of this file shows next to the endpoint,
                # so a DATUM check always sets one, even when a stratum probe ran too.
                if c["result"] == "verified" or not r or ep.get("expect") == "datum":
                    rec["verdict"] = "datum " + c["result"]
                    rec.setdefault("software", "-")
                if c["result"] == "verified":
                    rec["software"] = "DATUM prime"
                    sw_names.append("DATUM prime")
            if not c and ep.get("discovered"):
                # A port on the page that answers another listed key is that product's DATUM port.
                other = next((v for (h, pt, k), v in checks.items() if h == host and pt == port and v["result"] == "verified"), None)
                if other:
                    rec["verdict"] = "datum, answers another listed key"
                    rec.setdefault("software", "DATUM prime")
            if r or c:
                eps_out.append(rec)
        dstat, dh = datum_status(p, pool_checks, dstate, eps_out)
        verdict, why = consistency(p, f, sw_names, dstat, dh)
        claims = site_vs_probe(p, eps_out, dh)
        changes, gateway_names = onchain_changes(by_label.get(label, [])) if by_label.get(label) else ([], 0)
        rows.append({
            "label": label,
            "kind": p.get("kind", "pool"),
            "link": p.get("link", ""),
            "notes": p.get("notes", ""),
            "terms": p.get("terms", {}),
            "own_addresses": p.get("own_addresses", []),
            "sv1_closed": p.get("sv1_closed"),
            "site": site_info.get(label),
            "endpoints": eps_out,
            "software": sorted(set(sw_names)),
            "datum": dstat,
            "datum_check": dh,
            "onchain": f,
            "onchain_changes": changes,
            "gateway_names_today": gateway_names,
            "payout_shape": payout_shape(f) if f else "unknown",
            "consistency": verdict,
            "consistency_why": why,
            "claims": claims,
        })

    # commitment reuse across DIFFERENT pools = shared template builder
    seen = collections.defaultdict(set)
    for row in rows:
        for e in row["endpoints"]:
            if e.get("commitment"):
                seen[e["commitment"]].add(row["label"])
    shared = {c: sorted(v) for c, v in seen.items() if len(v) > 1}

    rows.sort(key=lambda r: -((r.get("onchain") or {}).get("share_pct") or 0))
    json.dump({
        "generated": now_iso(),
        "window": window_meta,
        "pools": rows,
        "changes": doc.get("changes", []),
        "shared_templates": shared,
        "site_read": site.get("generated"),
        "datum_checks": "real handshakes" if datum_on else ("skipped: " + (DC_WHY or "--no-datum")),
        "method": ("Stratum endpoints are probed with one mining.subscribe and no credentials, and the job "
                   "they hand out is matched to this chain; a port that answers without a job, or one the "
                   "pool's site calls closed, is also sent one mining.authorize with a throwaway worker (an "
                   "address with no key behind it), and no share is ever submitted. DATUM endpoints are "
                   "probed with one real DATUM handshake against the pool's published pubkey and the session "
                   "is closed as soon as the reply is verified. Endpoints come from the hand-kept list and "
                   "from the pool's own pages as last read. Software is named by matching the subscribe "
                   "reply to each project's own source. On-chain class and payout shape come from the "
                   "coinbase index this site already keeps."),
    }, open(args.out + ".tmp", "w"), indent=2)
    os.replace(args.out + ".tmp", args.out)
    n_checks = sum(1 for r in rows for e in r["endpoints"] if e.get("datum_check"))
    n_ok = sum(1 for r in rows for e in r["endpoints"] if (e.get("datum_check") or {}).get("result") == "verified")
    print("wrote %s: %d pools, %d endpoints, %d/%d DATUM handshakes verified, %d shared-template groups"
          % (args.out, len(rows), sum(len(r["endpoints"]) for r in rows), n_ok, n_checks, len(shared)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
