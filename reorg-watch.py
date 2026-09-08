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

Prints nothing unless something happened.

Usage: reorg-watch.py [--init] [--report] [--state DIR] [--rest URL]
                      [--explorer URL] [--notify CMD] [--alert-depth N]
                      [--keep N] [--floor H] [--verbose]
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

Files in the state dir: state.json, events.jsonl, reorg-log.md,
pools-v2.json (cache), lock.
"""
import argparse
import fcntl
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_FLOOR = 961640  # mainnet BLAKE2b fork block; nothing reorganizes across it
POOLS_URL = "https://raw.githubusercontent.com/Kilombino/mempool-bip110/main/pools-v2.json"
UA = "reorg-watch/1.0 (Bitcoin Knots node monitor)"
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

    def block(self, blockhash):
        try:
            return self.json(f"block/{blockhash}.json")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise


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
        for a in addrs:
            if a in self.by_addr:
                return self.by_addr[a]
        for t, n in self.tags:
            if t in tag:
                return n
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
    b = rest.block(blockhash)
    if b is None:
        return {"height": height, "hash": blockhash, "pool": "unknown (no block data)",
                "ntx": None, "time": None, "addresses": [], "tag": ""}
    cb = b["tx"][0]
    tag = coinbase_tag(cb["vin"][0].get("coinbase", ""))
    addrs = [v["scriptPubKey"]["address"] for v in cb["vout"]
             if v["scriptPubKey"].get("address") and v.get("value", 0) > 0]
    return {"height": height, "hash": blockhash, "pool": pools.identify(addrs, tag),
            "ntx": b["nTx"], "time": b["time"], "addresses": addrs, "tag": tag}


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


def load_state(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def save_state(path, st):
    with open(path + ".tmp", "w") as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.replace(path + ".tmp", path)


def seed(rest, st, H, keep, floor):
    start = max(floor, H - keep + 1)
    hdrs = rest.headers(rest.hash_at(start), H - start + 1)
    st["chain"] = {str(h["height"]): h["hash"] for h in hdrs}
    st["tip_height"] = max(int(k) for k in st["chain"])
    st["tip_hash"] = st["chain"][str(st["tip_height"])]
    st["seeded_at"] = ts()


def report(sd, st):
    chain = st.get("chain", {})
    if not chain:
        print("no state yet; run with --init")
        return
    hs = sorted(int(k) for k in chain)
    print(f"tip {st.get('tip_height')} {st.get('tip_hash')}  updated {st.get('updated')}")
    print(f"window {hs[0]}-{hs[-1]} ({len(hs)} heights)  seeded {st.get('seeded_at')}")
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

    if args.init or not st.get("chain"):
        seed(rest, st, H, args.keep, args.floor)
        finish(sd, args, st, state_path, events)
        print(f"{ts()} seeded window {min(int(k) for k in st['chain'])}-{st['tip_height']} tip {short(st['tip_hash'])}")
        return 0

    pools = Pools(os.path.join(sd, "pools-v2.json"), args.verbose)
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
        seed(rest, st, H, args.keep, args.floor)
        finish(sd, args, st, state_path, events)
        return 0

    depth = last_tip - ancestor
    if depth > 0:
        old = [describe_block(rest, pools, hh, chain[hh]) for hh in range(ancestor + 1, last_tip + 1)]
        new = [describe_block(rest, pools, hh, rest.hash_at(hh)) for hh in range(ancestor + 1, min(H, last_tip) + 1)]
        events.append({"type": "reorg", "level": "ALERT" if depth >= args.alert_depth else "INFO", "depth": depth,
                       "ancestor": {"height": ancestor, "hash": chain[ancestor]}, "old": old, "new": new,
                       "new_tip": {"height": H, "hash": X}})

    for hh in [k for k in chain if k > ancestor]:
        del chain[hh]
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
