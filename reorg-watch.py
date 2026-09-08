#!/usr/bin/env python3
# Copyright (c) 2026 Jason Sopko
# Distributed under the MIT software license, see the accompanying file LICENSE.
"""Watch a Bitcoin Knots node for chain reorganizations and say who mined what.

Each run (cron, once a minute):
  - reads the active chain from the node's REST interface (rest=1; no auth)
  - compares it with the height->hash window saved by the previous run
  - on a reorg, fetches the disconnected blocks and their replacements and
    attributes each to a pool by coinbase payout address, then by coinbase
    tag, using Kilombino's pools-v2.json (cached 6 h)
  - cross-checks the node's tip against a public explorer so a node that is
    partitioned, stalled, or fed a private fork shows up too
  - appends events to events.jsonl and to a publishable reorg-log.md, and
    runs --notify CMD for anything at or above --alert-depth
  - with --html, writes a self-contained status page (tip, explorer
    agreement, pool shares for the last 24 h by hour, recent events) to
    serve as a static file

Prints nothing unless something happened.

Usage: reorg-watch.py [--init] [--report] [--state DIR] [--rest URL]
                      [--explorer URL] [--notify CMD] [--alert-depth N]
                      [--keep N] [--floor H] [--html FILE] [--verbose]
  --init          seed the window from the node without logging history
  --report        print the current state and recent events, then exit
  --state DIR     state directory (default ~/.reorg-watch)
  --rest URL      Knots REST base (default http://127.0.0.1:8332/rest)
  --explorer URL  explorer base (default https://mempool.guide); "" disables
  --notify CMD    shell command; alert text arrives on stdin and in $REORG_MSG
  --alert-depth N reorg depth that counts as an alert (default 2; depth 1 is
                  a normal tie and is only logged)
  --keep N        heights kept in the window (default 400)
  --floor H       never seed below this height (default 961640, the mainnet
                  BLAKE2b fork block; use 150308 on testnet4)
  --html FILE     write the status page here after every run

Files in the state dir: state.json, events.jsonl, reorg-log.md,
pools-v2.json (cache), lock.
"""
import argparse
import fcntl
import html
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_FLOOR = 961640  # mainnet BLAKE2b fork block; nothing reorganizes across it
POOLS_URL = "https://raw.githubusercontent.com/Kilombino/mempool-bip110/main/pools-v2.json"
POOLS_REPO = "https://github.com/Kilombino/mempool-bip110"
UA = "reorg-watch/1.1 (Bitcoin Knots node monitor)"
REPO_URL = "https://github.com/jasonsopko/reorg-watch"
NOW = time.time()


def ts(t=None):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(NOW if t is None else t))


def http_get(url, timeout=10, retries=2):
    last = None
    for _ in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            last = e
        except Exception as e:  # noqa: BLE001 - any transport error is retried
            last = e
        time.sleep(1)
    raise last


class Rest:
    def __init__(self, base):
        self.base = base.rstrip("/")

    def json(self, path):
        return json.loads(http_get(f"{self.base}/{path}"))

    def chaininfo(self):
        return self.json("chaininfo.json")

    def hash_at(self, height):
        return self.json(f"blockhashbyheight/{height}.json")["blockhash"]

    def headers(self, start_hash, count):
        """Headers ascending from start_hash inclusive; REST caps count at 2000."""
        out = []
        h = start_hash
        while count > 0:
            batch = self.json(f"headers/{min(count, 2000)}/{h}.json")
            if not batch:
                break
            out.extend(batch)
            count -= len(batch)
            if count > 0:
                nxt = self.json(f"blockhashbyheight/{batch[-1]['height'] + 1}.json")
                h = nxt["blockhash"]
        return out

    def _maybe(self, path):
        try:
            return self.json(path)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    def block(self, blockhash):
        return self._maybe(f"block/{blockhash}.json")

    def block_notx(self, blockhash):
        return self._maybe(f"block/notxdetails/{blockhash}.json")

    def tx(self, txid):
        return self._maybe(f"tx/{txid}.json")


class Pools:
    def __init__(self, cache, verbose=False):
        self.by_addr = {}
        self.tags = []
        stale = not os.path.exists(cache) or NOW - os.path.getmtime(cache) > 6 * 3600
        if stale:
            try:
                data = http_get(POOLS_URL, timeout=15)
                json.loads(data)
                with open(cache + ".tmp", "wb") as f:
                    f.write(data)
                os.replace(cache + ".tmp", cache)
            except Exception as e:  # noqa: BLE001
                if verbose:
                    print(f"{ts()} pools list refresh failed: {e}")
                if os.path.exists(cache):
                    os.utime(cache)  # back off for another 6 h
        if os.path.exists(cache):
            with open(cache) as f:
                for e in json.load(f):
                    for a in e.get("addresses", []):
                        self.by_addr[a] = e["name"]
                    for t in e.get("tags", []):
                        if t:
                            self.tags.append((t, e["name"]))
            self.tags.sort(key=lambda x: -len(x[0]))

    def identify(self, addrs, tag):
        by_tag = next((n for t, n in self.tags if t in tag), None)
        for a in addrs:
            if a in self.by_addr:
                n = self.by_addr[a]
                # Kilombino autotags address-only solo miners as "Solo <prefix>";
                # a real pool tag on the same block is the better name.
                if n.startswith("Solo ") and by_tag:
                    return by_tag
                return n
        if by_tag:
            return by_tag
        return "Unknown (" + (addrs[0][:12] if addrs else "no address") + ")"


def coinbase_tag(sig_hex):
    runs, cur = [], b""
    for c in bytes.fromhex(sig_hex or ""):
        if 32 <= c < 127:
            cur += bytes([c])
        else:
            if len(cur) >= 4:
                runs.append(cur.decode())
            cur = b""
    if len(cur) >= 4:
        runs.append(cur.decode())
    return "/".join(runs)


def describe_block(rest, pools, height, blockhash):
    b = rest.block_notx(blockhash)
    cb = rest.tx(b["tx"][0]) if b else None
    if b and cb is None:  # stale block: its coinbase is not in the tx index
        full = rest.block(blockhash)
        cb = full["tx"][0] if full else None
    if b is None or cb is None:
        return {"height": height, "hash": blockhash, "pool": "unknown (no block data)",
                "ntx": None, "time": None, "weight": None, "addresses": [], "tag": ""}
    tag = coinbase_tag(cb["vin"][0].get("coinbase", ""))
    addrs = [v["scriptPubKey"]["address"] for v in cb["vout"]
             if v["scriptPubKey"].get("address") and v.get("value", 0) > 0]
    return {"height": height, "hash": blockhash, "pool": pools.identify(addrs, tag),
            "ntx": b["nTx"], "time": b["time"], "weight": b.get("weight"), "addresses": addrs, "tag": tag}


def remember(st, d):
    """Keep the per-block facts the status page needs."""
    st.setdefault("blocks", {})[str(d["height"])] = {"pool": d["pool"], "ntx": d["ntx"], "time": d["time"], "weight": d["weight"]}


def short(h):
    return h[:8] + ".." + h[-8:]


def explorer_check(base, st, H, X, events, verbose):
    base = base.rstrip("/")

    def fetch(paths):
        last = None
        for p in paths:
            try:
                return http_get(base + p, timeout=15, retries=1).decode().strip()
            except Exception as e:  # noqa: BLE001
                last = e
        raise last

    try:
        etip = int(fetch(["/api/blocks/tip/height", "/api/v1/blocks/tip/height"]))
    except Exception as e:  # noqa: BLE001
        st["explorer_fail_runs"] = st.get("explorer_fail_runs", 0) + 1
        if verbose:
            print(f"{ts()} explorer unreachable ({st['explorer_fail_runs']}): {e}")
        if st["explorer_fail_runs"] == 10:
            events.append({"type": "explorer_unreachable", "level": "INFO", "runs": 10, "explorer": base})
        return
    st["explorer_fail_runs"] = 0
    st["explorer_tip"] = etip
    st["explorer_url"] = base
    mismatch = False
    ehash = None
    if etip >= H:
        try:
            ehash = fetch([f"/api/block-height/{H}", f"/api/v1/block-height/{H}"])
            mismatch = ehash != X
        except Exception:  # noqa: BLE001
            pass
    st["explorer_mismatch_runs"] = st.get("explorer_mismatch_runs", 0) + 1 if mismatch else 0
    st["explorer_behind_runs"] = st.get("explorer_behind_runs", 0) + 1 if etip - H >= 3 else 0
    m, b = st["explorer_mismatch_runs"], st["explorer_behind_runs"]
    if m == 2 or (m > 2 and m % 30 == 0):
        events.append({"type": "explorer_mismatch", "level": "ALERT", "runs": m, "explorer": base,
                       "height": H, "our_hash": X, "explorer_hash": ehash, "explorer_tip": etip})
    if b == 3 or (b > 3 and b % 30 == 0):
        events.append({"type": "node_behind_explorer", "level": "ALERT", "runs": b, "explorer": base,
                       "our_tip": H, "explorer_tip": etip})


def blk_info(b):
    if b["ntx"] is None:
        return "no block data on this node"
    return f"{b['ntx']} tx, {ts(b['time'])}"


def md_for(e):
    t = e["type"]
    if t == "reorg":
        a, old, new = e["ancestor"], e["old"], e["new"]
        lo, hi = a["height"] + 1, a["height"] + e["depth"]
        lines = [f"## {ts()} - reorg depth {e['depth']} (heights {lo}-{hi})",
                 f"- Common ancestor: {a['height']} `{a['hash']}`",
                 "- Disconnected:"]
        lines += [f"  - {b['height']} {b['pool']} `{b['hash']}` ({blk_info(b)})" for b in old]
        lines.append("- Replaced by:")
        lines += [f"  - {b['height']} {b['pool']} `{b['hash']}` ({blk_info(b)})" for b in new]
        nt = e["new_tip"]
        extra = nt["height"] - hi
        lines.append(f"- New tip: {nt['height']} `{nt['hash']}`" + (f" ({extra} further blocks)" if extra > 0 else ""))
        return "\n".join(lines) + "\n\n"
    if t == "reorg_beyond_window":
        return (f"## {ts()} - reorg deeper than the {e['window']}-block window\n"
                f"- Previous tip {e['old_tip']['height']} `{e['old_tip']['hash']}`, new tip {e['new_tip']['height']} `{e['new_tip']['hash']}`\n"
                f"- No common ancestor at or above height {e['window_floor']}; window reseeded\n\n")
    if t == "explorer_mismatch":
        return (f"## {ts()} - explorer disagreement at height {e['height']} ({e['runs']} consecutive checks)\n"
                f"- Our block `{e['our_hash']}`\n- {e['explorer']} block `{e['explorer_hash']}` (explorer tip {e['explorer_tip']})\n\n")
    if t == "node_behind_explorer":
        return (f"## {ts()} - node behind explorer ({e['runs']} consecutive checks)\n"
                f"- Our tip {e['our_tip']}, {e['explorer']} tip {e['explorer_tip']}\n\n")
    return f"## {ts()} - {t}\n- {json.dumps({k: v for k, v in e.items() if k not in ('type', 'level')})}\n\n"


def line_for(e):
    t = e["type"]
    if t == "reorg":
        lo = e["ancestor"]["height"] + 1
        hi = lo + e["depth"] - 1
        out = ",".join(b["pool"] for b in e["old"])
        inn = ",".join(b["pool"] for b in e["new"])
        return f"{e['level']} reorg depth={e['depth']} heights={lo}-{hi} out=[{out}] in=[{inn}] tip={e['new_tip']['height']}"
    if t == "explorer_mismatch":
        return f"ALERT explorer disagrees at {e['height']}: ours {short(e['our_hash'])} theirs {short(e['explorer_hash'] or '?')} ({e['runs']} checks)"
    if t == "node_behind_explorer":
        return f"ALERT node at {e['our_tip']}, explorer at {e['explorer_tip']} ({e['runs']} checks)"
    if t == "reorg_beyond_window":
        return f"ALERT reorg deeper than window: {e['old_tip']['height']} -> {e['new_tip']['height']}, floor {e['window_floor']}"
    return f"{e.get('level', 'INFO')} {t} " + json.dumps({k: v for k, v in e.items() if k not in ('type', 'level')})



# Bitcoin Knots knot mark, from src/qt/res/src/bitcoinknots-logo.svg in the Knots
# repository (MIT; designers Kurtis Stirling, Blissmode, Skyler, Steven Hay).
KNOTS_PATHS = (
    "M540.681 696.414C529.339 653.751 478.297 622.884 453.145 587.814C416.799 537.137 417.823 468.303 461.839 414.562C474.635 428.893 477.708 431.72 495.107 447.83C464.819 485.851 462.481 522.417 483.666 555.915C514.484 604.645 576.678 630.626 586.815 695.55C586.815 695.55 563.783 696.062 540.681 696.414Z",
    "M639.533 534.328C672.801 560.942 707.293 587.769 706.034 630.028C704.183 692.176 655.731 716.019 589.886 717.047C581.943 717.171 492.641 717.559 492.641 717.559C488.63 741.195 489.824 761.777 496.725 779.731C496.725 779.731 607.471 780.041 607.192 780.041C708.889 780.041 790.939 731.742 790.939 630.028C790.939 569.471 751.621 532.792 696.856 499.012C675.36 511.808 657.446 521.532 639.533 534.328Z",
    "M542.287 589.092C531.976 579.426 518.232 567.084 509.019 556.336C589.978 450.901 687.227 449.366 689.209 369.541C690.26 327.228 653.826 303.713 613.233 296.005C616.829 273.396 615.802 256.953 612.205 238.455C685.684 239.997 761.525 290.867 761.525 369.541C761.525 481.61 638.981 473.105 542.287 589.092Z",
    "M406.796 718.134H372.746L372.768 291.899C372.768 291.899 476.276 291.899 526.904 291.899C532.042 273.914 531.082 255.477 525.282 238.158H270V244.424C305.969 272.369 312.524 295.041 312.524 337.212V680.378C312.524 718.257 302.886 748.184 270 773.131V779.397C270 779.397 365.271 779.293 407.617 779.396C403.75 756.841 403.367 740.086 406.796 718.134Z",
    "M509.715 174.475C532.372 197.061 547.556 229.06 549.75 261.027C551.836 291.363 539.921 322.594 522.283 347.389C532.329 358.989 544.368 369.198 555.683 378.22C577.948 349.335 591.421 316.778 593.544 280.178C597.443 212.944 564.807 160.188 509.362 125C470.561 148.692 446.749 175.499 431.333 216.874C447.476 216.874 463.899 216.839 480.148 216.874C485.8 201.973 498.221 185.63 509.715 174.475Z",
    "M538.662 801.18C531.334 816.154 521.386 831.937 509.421 843.548C486.765 820.963 471.581 787.94 469.386 755.973C467.301 725.637 472.607 690.04 491.105 659.723C479.333 647.439 468.585 637.715 457.325 627.478C435.23 662.933 427.715 700.222 425.592 736.822C421.86 801.18 455.734 858.859 509.775 892C545.777 870.016 573.708 841.218 587.267 801.286C571.124 801.286 554.981 801.286 538.733 801.251L538.662 801.18Z",
    "M606.039 440.395C573.436 417.311 500.015 378.767 477.809 314.504H430.436C447.05 385.719 505.794 430.763 559.28 475.073C574.181 461.976 586.513 454.268 606.039 440.395Z",
)


def pool_group(name):
    return "Unknown" if name.startswith("Unknown") or name.startswith("unknown") else name


def render_html(path, sd, st):
    E = html.escape
    now = NOW
    blocks = sorted((int(k), v) for k, v in st.get("blocks", {}).items() if v.get("time"))
    day = [b for h, b in blocks if now - b["time"] <= 86400]
    counts = {}
    unknown_addrs = set()
    for b in day:
        g = pool_group(b["pool"])
        counts[g] = counts.get(g, 0) + 1
        if g == "Unknown":
            unknown_addrs.add(b["pool"])
    total = len(day) or 1
    ranked = sorted(counts.items(), key=lambda kv: -kv[1])
    cols = [n for n, _ in ranked[:3]]
    earliest = min((b["time"] for _, b in blocks), default=now)

    hours = []
    h0 = int(now // 3600) * 3600
    for i in range(23, -1, -1):
        lo = h0 - i * 3600
        hb = [b for b in day if lo <= b["time"] < lo + 3600]
        row = {"label": time.strftime("%H:00", time.gmtime(lo)), "n": len(hb), "na": lo + 3600 <= earliest}
        for c in cols:
            row[c] = sum(1 for b in hb if pool_group(b["pool"]) == c)
        hours.append(row)

    evs = []
    ev_path = os.path.join(sd, "events.jsonl")
    if os.path.exists(ev_path):
        with open(ev_path) as f:
            evs = [json.loads(l) for l in f if l.strip()]
    reorgs = [e for e in evs if e["type"] == "reorg"]
    def depth_counts(window):
        sel = [e for e in reorgs if now - e["_t"] < window]
        return ", ".join(f"depth {d}: {sum(1 for e in sel if e['depth'] == d)}" for d in sorted({e["depth"] for e in sel})) or "none"
    alerts = [e for e in evs if e.get("level") == "ALERT"]
    last_alert = ts(alerts[-1]["_t"]) if alerts else "none recorded"

    tip_h, tip_hash = st.get("tip_height"), st.get("tip_hash", "")
    ex = st.get("explorer_url") or ""
    ex_name = urllib.parse.urlparse(ex).hostname or "explorer"
    ex_link = f'<a href="{E(ex)}">{E(ex_name)}</a>' if ex else "explorer"
    tip_html = f'<a href="{E(ex)}/block/{E(tip_hash)}"><code>{E(tip_hash)}</code></a>' if ex else f"<code>{E(tip_hash)}</code>"
    etip = st.get("explorer_tip")
    if etip is None:
        agree = ("unknown", "explorer not checked")
    elif st.get("explorer_mismatch_runs", 0) >= 2:
        agree = ("bad", f"disagrees at height {tip_h}")
    elif st.get("explorer_behind_runs", 0) >= 3:
        agree = ("bad", f"is {etip - tip_h} blocks ahead")
    elif st.get("explorer_fail_runs", 0) >= 10:
        agree = ("warn", "unreachable")
    else:
        agree = ("ok", f"agrees (tip {etip})")
    node_state = ("bad", f"unreachable for {st['rest_fail_runs']} runs") if st.get("rest_fail_runs", 0) >= 3 else ("ok", "reachable")

    def rows_shares():
        out = []
        for n, k in ranked[:15]:
            label = f"Unknown ({len(unknown_addrs)} payout address{'es' if len(unknown_addrs) != 1 else ''})" if n == "Unknown" else n
            out.append(f"<tr><td>{E(label)}</td><td class=n>{k}</td><td class=n>{100 * k / total:.1f}%</td></tr>")
        rest_n = sum(k for _, k in ranked[15:])
        if rest_n:
            out.append(f"<tr><td>{len(ranked) - 15} others</td><td class=n>{rest_n}</td><td class=n>{100 * rest_n / total:.1f}%</td></tr>")
        return "\n".join(out)

    def rows_hours():
        out = []
        for r in reversed(hours):
            label = r["label"] + (" so far" if r is hours[-1] else "")
            if r["na"]:
                out.append(f"<tr class=na><td>{label}</td><td class=n>-</td><td class=note colspan={len(cols)}>before the saved window</td></tr>")
                continue
            cells = []
            for c in cols:
                if not r["n"]:
                    cells.append("<td class=n>-</td>")
                    continue
                pct = 100 * r[c] / r["n"]
                cls = "n hi" if pct >= 50 else "n"
                cells.append(f"<td class=\"{cls}\">{pct:.0f}%</td>")
            out.append(f"<tr><td>{label}</td><td class=n>{r['n']}</td>{''.join(cells)}</tr>")
        return "\n".join(out)

    def rows_events():
        out = []
        for e in evs[-25:][::-1]:
            line = line_for(e)
            lvl = e.get("level", "INFO")
            if line.startswith(lvl + " "):
                line = line[len(lvl) + 1:]
            out.append(f"<tr><td class=t>{ts(e['_t'])}</td><td class={'alert' if lvl == 'ALERT' else 'info'}>{lvl}</td><td>{E(line)}</td></tr>")
        return "\n".join(out) or "<tr><td colspan=3 class=note>none yet</td></tr>"

    hour_heads = "".join(f"<th class=n>{E(c)}</th>" for c in cols)
    knot = ('<svg class="mark" viewBox="0 0 773 773" width="60" height="60" role="img" aria-label="Bitcoin Knots">'
            '<circle cx="386.5" cy="386.5" r="380" fill="#f7931a"/>'
            '<circle cx="386.5" cy="386.5" r="380" fill="none" stroke="#b8651a" stroke-width="14"/>'
            '<g transform="translate(108 108) scale(0.72) translate(-144 -122)" fill="#2d4b25" stroke="#7cb342" stroke-width="9" stroke-linejoin="round">'
            + "".join(f'<path d="{d}"/>' for d in KNOTS_PATHS) + '</g></svg>')
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="300">
<title>Bitcoin Knots reorg watch</title>
<style>
:root {{
  color-scheme: light dark;
  --ink: #171717; --paper: #f6f3ee; --card: #ffffff; --rule: #dcd5c8; --mute: #6b675f;
  --orange: #f7931a; --orange-tint: rgba(247, 147, 26, .26); --green: #2d4b25; --band: #2d4b25; --band-ink: #ffffff; --band-sub: #d9e3d3;
  --link: #2d4b25; --ok: #2e7d32; --warn: #a86400; --bad: #c62828;
}}
@media (prefers-color-scheme: dark) {{ :root {{
  --ink: #f2f2f2; --paper: #171717; --card: #222222; --rule: #3a3a3a; --mute: #a09a90;
  --orange-tint: rgba(247, 147, 26, .22); --green: #9ccc65; --band: #1f3519; --band-ink: #f2f2f2; --band-sub: #b7c7ad;
  --link: #9ccc65; --ok: #8bc34a; --warn: #ffb74d; --bad: #ff6b60;
}} }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; background: var(--paper); color: var(--ink); font: 16px/1.5 Manjari, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }}
a {{ color: var(--link); text-decoration: none; }} a:hover {{ text-decoration: underline; }}
header {{ border-bottom: 6px solid var(--orange); background: var(--band); color: var(--band-ink); }}
.bar {{ max-width: 62rem; margin: 0 auto; padding: 1.4rem 1.25rem 1.1rem; display: flex; align-items: center; gap: 1rem; }}
.mark {{ flex: none; filter: drop-shadow(0 1px 2px rgba(0,0,0,.35)); }}
h1 {{ margin: 0; font: 700 1.55rem/1.15 "Martel Sans", Georgia, "Times New Roman", serif; letter-spacing: -.01em; }}
.sub {{ margin: .2rem 0 0; color: var(--band-sub); font-size: .95rem; }}
main {{ max-width: 62rem; margin: 0 auto; padding: 0 1.25rem 3rem; }}
h2 {{ font: 700 1.1rem/1.2 "Martel Sans", Georgia, "Times New Roman", serif; color: var(--green); margin: 2rem 0 .6rem; padding-bottom: .35rem; border-bottom: 2px solid var(--orange); }}
.note, .muted {{ color: var(--mute); }} .note {{ font-size: .95rem; margin: 0 0 .7rem; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(13rem, 1fr)); gap: .75rem; margin-top: 1.2rem; }}
.card {{ background: var(--card); border: 1px solid var(--rule); border-radius: 6px; padding: .8rem .95rem; }}
.card .k {{ color: var(--green); font-size: .82rem; text-transform: uppercase; letter-spacing: .06em; }}
.card .v {{ font-size: 1.05rem; margin-top: .15rem; word-break: break-word; }}
.ok {{ color: var(--ok); }} .warn {{ color: var(--warn); }} .bad, .alert {{ color: var(--bad); font-weight: 700; }} .info {{ color: var(--mute); }}
.wrap {{ overflow-x: auto; background: var(--card); border: 1px solid var(--rule); border-radius: 6px; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ padding: .45rem .75rem; border-bottom: 1px solid var(--rule); text-align: left; vertical-align: top; }}
tr:last-child td {{ border-bottom: 0; }}
th {{ font-size: .82rem; text-transform: uppercase; letter-spacing: .05em; color: var(--mute); background: var(--paper); }}
td.n, th.n {{ text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }}
td.t {{ white-space: nowrap; font-variant-numeric: tabular-nums; }}
td.hi {{ background: var(--orange-tint); font-weight: 700; }}
table.hours {{ table-layout: fixed; min-width: 34rem; }}
table.hours th:first-child, table.hours td:first-child {{ width: 7.5rem; white-space: nowrap; }}
table.hours th:nth-child(2), table.hours td:nth-child(2) {{ width: 5.5rem; }}
tr.na td {{ color: var(--mute); font-size: .9rem; padding-top: .25rem; padding-bottom: .25rem; }}
code {{ font: .88em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }}
#stale {{ display: none; margin: 1.2rem 0 0; padding: .7rem .9rem; border: 2px solid var(--bad); border-radius: 6px; color: var(--bad); font-weight: 700; }}
footer {{ max-width: 62rem; margin: 0 auto; padding: 0 1.25rem 2rem; color: var(--mute); font-size: .9rem; }}
</style>
</head>
<body>
<header><div class="bar">{knot}<div><h1>Bitcoin Knots reorg watch</h1>
<p class="sub">Chain reorganizations and pool shares on the BLAKE2b chain, from one Bitcoin Knots node. Generated <span id="gen">{E(ts(now))}</span>.</p></div></div></header>
<main>
<div id="stale">This page is more than 15 minutes old. The generator or the upload has stopped; treat everything below as stale.</div>

<div class="cards">
<div class="card"><div class="k">Node</div><div class="v {node_state[0]}">{E(node_state[1])}</div></div>
<div class="card"><div class="k">Explorer</div><div class="v {agree[0]}">{ex_link if ex else ""} {E(agree[1])}</div></div>
<div class="card"><div class="k">Reorgs, 24 h</div><div class="v">{E(depth_counts(86400))}</div></div>
<div class="card"><div class="k">Reorgs, 7 d</div><div class="v">{E(depth_counts(7 * 86400))}</div></div>
<div class="card"><div class="k">Last alert</div><div class="v">{E(last_alert)}</div></div>
<div class="card"><div class="k">Tip</div><div class="v">{tip_h}<br>{tip_html}</div></div>
</div>

<h2>Blocks by pool, last 24 hours</h2>
<p class="note">{len(day)} blocks. Pools are named from the coinbase payout address, then the coinbase tag, using <a href="{POOLS_REPO}">Kilombino's pool list</a>. Both are chosen by the miner, so treat names as claims. Shares are block counts and carry a few points of noise.</p>
<div class="wrap"><table>
<tr><th>Pool</th><th class=n>Blocks</th><th class=n>Share</th></tr>
{rows_shares()}
</table></div>

<h2>By hour, UTC</h2>
<p class="note">Most recent hour first. Share of that hour's blocks for the three largest pools of the day. Cells at or above half are marked.</p>
<div class="wrap"><table class="hours">
<tr><th>Hour</th><th class=n>Blocks</th>{hour_heads}</tr>
{rows_hours()}
</table></div>

<h2>Recent events</h2>
<p class="note">Depth-1 reorgs are ordinary ties between two blocks found seconds apart. Depth 2 and deeper, explorer disagreement, and a node that has fallen behind are alerts.</p>
<div class="wrap"><table>
<tr><th>Time</th><th>Level</th><th>Event</th></tr>
{rows_events()}
</table></div>
</main>
<footer>Produced by <a href="{REPO_URL}">reorg-watch</a>, an independent monitor. Not affiliated with the Bitcoin Knots project. One node's view, cross-checked once a minute against {ex_link}, whose explorer also has the block-by-block detail. Pool names from <a href="{POOLS_REPO}">Kilombino's pool list</a>. Window {len(st.get('chain', {}))} heights.</footer>
<script>
(function () {{
  var gen = Date.parse(document.getElementById('gen').textContent.replace(' ', 'T'));
  if (!isNaN(gen) && Date.now() - gen > 15 * 60 * 1000) document.getElementById('stale').style.display = 'block';
}})();
</script>
</body>
</html>
"""
    with open(path + ".tmp", "w") as f:
        f.write(page)
    os.replace(path + ".tmp", path)


def load_state(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def save_state(path, st):
    with open(path + ".tmp", "w") as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.replace(path + ".tmp", path)


def seed(rest, st, H, keep, floor, pools):
    start = max(floor, H - keep + 1)
    hdrs = rest.headers(rest.hash_at(start), H - start + 1)
    st["chain"] = {str(h["height"]): h["hash"] for h in hdrs}
    st["blocks"] = {}
    for h in hdrs:
        remember(st, describe_block(rest, pools, h["height"], h["hash"]))
    st["tip_height"] = max(int(k) for k in st["chain"])
    st["tip_hash"] = st["chain"][str(st["tip_height"])]
    st["seeded_at"] = ts()


def backfill(rest, st, pools, chain, limit=500):
    """Attribute heights in the window that have no block record yet (upgrades, gaps)."""
    have = st.setdefault("blocks", {})
    for h in sorted(k for k in chain if str(k) not in have)[:limit]:
        remember(st, describe_block(rest, pools, h, chain[h]))


def report(sd, st):
    chain = st.get("chain", {})
    if not chain:
        print("no state yet; run with --init")
        return
    hs = sorted(int(k) for k in chain)
    print(f"tip {st.get('tip_height')} {st.get('tip_hash')}  updated {st.get('updated')}")
    print(f"window {hs[0]}-{hs[-1]} ({len(hs)} heights, {len(st.get('blocks', {}))} attributed)  seeded {st.get('seeded_at')}")
    print(f"explorer tip {st.get('explorer_tip')}  mismatch_runs {st.get('explorer_mismatch_runs', 0)}  "
          f"behind_runs {st.get('explorer_behind_runs', 0)}  fail_runs {st.get('explorer_fail_runs', 0)}  "
          f"rest_fail_runs {st.get('rest_fail_runs', 0)}")
    ev_path = os.path.join(sd, "events.jsonl")
    if not os.path.exists(ev_path):
        print("no events")
        return
    with open(ev_path) as f:
        evs = [json.loads(l) for l in f if l.strip()]
    day = [e for e in evs if NOW - e["_t"] < 86400 and e["type"] == "reorg"]
    week = [e for e in evs if NOW - e["_t"] < 7 * 86400 and e["type"] == "reorg"]
    depths = lambda L: ",".join(f"d{d}:{sum(1 for e in L if e['depth'] == d)}" for d in sorted({e["depth"] for e in L})) or "none"
    print(f"reorgs 24h: {depths(day)}   7d: {depths(week)}   total events: {len(evs)}")
    for e in evs[-10:]:
        print(f"  {ts(e['_t'])} {line_for(e)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--init", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--state", default=os.path.expanduser("~/.reorg-watch"))
    ap.add_argument("--rest", default="http://127.0.0.1:8332/rest")
    ap.add_argument("--explorer", default="https://mempool.guide")
    ap.add_argument("--notify", default="")
    ap.add_argument("--alert-depth", type=int, default=2)
    ap.add_argument("--keep", type=int, default=400)
    ap.add_argument("--floor", type=int, default=DEFAULT_FLOOR)
    ap.add_argument("--html", default="")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    sd = args.state
    os.makedirs(sd, exist_ok=True)
    state_path = os.path.join(sd, "state.json")
    st = load_state(state_path)
    if args.report:
        report(sd, st)
        return 0

    lock = open(os.path.join(sd, "lock"), "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        if args.verbose:
            print(f"{ts()} previous run still active, skipping")
        return 0

    rest = Rest(args.rest)
    events = []
    try:
        info = rest.chaininfo()
    except Exception as e:  # noqa: BLE001
        st["rest_fail_runs"] = st.get("rest_fail_runs", 0) + 1
        if st["rest_fail_runs"] == 3 or (st["rest_fail_runs"] > 3 and st["rest_fail_runs"] % 30 == 0):
            events.append({"type": "node_unreachable", "level": "ALERT", "runs": st["rest_fail_runs"], "error": str(e)})
        finish(sd, args, st, state_path, events)
        return 0
    if st.get("rest_fail_runs"):
        events.append({"type": "node_reachable_again", "level": "INFO", "after_runs": st["rest_fail_runs"]})
    st["rest_fail_runs"] = 0

    H, X = info["blocks"], info["bestblockhash"]
    if info.get("initialblockdownload") or info["headers"] > H + 6:
        st["syncing_runs"] = st.get("syncing_runs", 0) + 1
        if st["syncing_runs"] == 1:
            events.append({"type": "node_syncing", "level": "INFO", "blocks": H, "headers": info["headers"]})
        finish(sd, args, st, state_path, events)
        return 0
    st["syncing_runs"] = 0

    pools = Pools(os.path.join(sd, "pools-v2.json"), args.verbose)
    if args.init or not st.get("chain"):
        seed(rest, st, H, args.keep, args.floor, pools)
        finish(sd, args, st, state_path, events)
        print(f"{ts()} seeded window {min(int(k) for k in st['chain'])}-{st['tip_height']} tip {short(st['tip_hash'])}")
        return 0

    chain = {int(k): v for k, v in st["chain"].items()}
    last_tip = st["tip_height"]
    floor = min(chain)

    # Common ancestor: cheap path first (old tip still on the active chain).
    ancestor = None
    h = min(H, last_tip)
    while h >= floor:
        if chain.get(h) == rest.hash_at(h):
            ancestor = h
            break
        h -= 1

    if ancestor is None:
        events.append({"type": "reorg_beyond_window", "level": "ALERT", "window": args.keep, "window_floor": floor,
                       "old_tip": {"height": last_tip, "hash": st["tip_hash"]}, "new_tip": {"height": H, "hash": X}})
        seed(rest, st, H, args.keep, args.floor, pools)
        finish(sd, args, st, state_path, events)
        return 0

    depth = last_tip - ancestor
    if depth > 0:
        old = [describe_block(rest, pools, hh, chain[hh]) for hh in range(ancestor + 1, last_tip + 1)]
        new = [describe_block(rest, pools, hh, rest.hash_at(hh)) for hh in range(ancestor + 1, min(H, last_tip) + 1)]
        events.append({"type": "reorg", "level": "ALERT" if depth >= args.alert_depth else "INFO", "depth": depth,
                       "ancestor": {"height": ancestor, "hash": chain[ancestor]}, "old": old, "new": new,
                       "new_tip": {"height": H, "hash": X}})

    blocks = st.setdefault("blocks", {})
    for hh in [k for k in chain if k > ancestor]:
        del chain[hh]
        blocks.pop(str(hh), None)
    n = H - ancestor
    if 0 < n <= 3:
        for hh in range(ancestor + 1, H + 1):
            chain[hh] = rest.hash_at(hh)
    elif n > 3:
        for hdr in rest.headers(rest.hash_at(ancestor + 1), n):
            chain[hdr["height"]] = hdr["hash"]
    top = max(chain)
    for hh in [k for k in chain if k < top - args.keep + 1]:
        del chain[hh]
        blocks.pop(str(hh), None)
    for hh in range(ancestor + 1, top + 1):
        remember(st, describe_block(rest, pools, hh, chain[hh]))
    backfill(rest, st, pools, chain)
    st["chain"] = {str(k): v for k, v in chain.items()}
    st["tip_height"], st["tip_hash"] = top, chain[top]

    if args.explorer:
        explorer_check(args.explorer, st, top, chain[top], events, args.verbose)

    finish(sd, args, st, state_path, events)
    if args.verbose and not events:
        print(f"{ts()} ok tip {top} {short(chain[top])} window {min(chain)}-{top}")
    return 0


def finish(sd, args, st, state_path, events):
    st["updated"] = ts()
    save_state(state_path, st)
    if args.html and st.get("chain"):
        try:
            render_html(args.html, sd, st)
        except Exception as e:  # noqa: BLE001
            print(f"{ts()} html render failed: {e}")
    if not events:
        return
    md_path = os.path.join(sd, "reorg-log.md")
    if not os.path.exists(md_path):
        with open(md_path, "w") as f:
            f.write("# Reorg log\n\nChain reorganizations and explorer disagreements seen by a Bitcoin Knots node "
                    "on the BLAKE2b chain. Depth-1 events are ordinary ties. Pools are identified by coinbase "
                    "payout address, then coinbase tag.\n\n")
    alerts = []
    with open(os.path.join(sd, "events.jsonl"), "a") as ev, open(md_path, "a") as md:
        for e in events:
            e["_t"] = NOW
            ev.write(json.dumps(e, sort_keys=True) + "\n")
            md.write(md_for(e))
            line = line_for(e)
            print(f"{ts()} {line}")
            if e.get("level") == "ALERT":
                alerts.append(line)
    if alerts and args.notify:
        msg = "reorg-watch " + ts() + "\n" + "\n".join(alerts) + "\n"
        try:
            subprocess.run(args.notify, shell=True, input=msg.encode(), env=dict(os.environ, REORG_MSG=msg), timeout=60)
        except Exception as e:  # noqa: BLE001
            print(f"{ts()} notify failed: {e}")


if __name__ == "__main__":
    sys.exit(main())
