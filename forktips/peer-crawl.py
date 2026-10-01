#!/usr/bin/env python3
"""peer-crawl.py - ask many peers directly which chain they are on.

node1 can only report the branches it was told about. A block orphaned before it reached us
is invisible here no matter how often we poll getchaintips. This asks other nodes instead:
handshake, then getheaders with a locator set a few blocks back so every peer has to answer
with real headers, then compare their blocks against ours height by height.

Two things come out of it that a single node cannot give:
  - agreement: how many peers hold the same block as us at each recent height
  - divergence: a peer on a different block, with its hash, which is a split in progress or
    a stale block we never received

Addresses come from our own peer list (getpeerinfo, so they are known-good) plus a seed
file. Every peer gets one short-lived connection per run and nothing is sent but a version
and a getheaders.

Usage: peer-crawl.py [--seeds FILE] [--limit N] [--back N] [--threads N] [--out FILE]
"""
import argparse, base64, importlib.util, json, os, queue, socket, sys, threading, time, urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
_s = importlib.util.spec_from_file_location("pp", os.path.join(HERE, "peer-probe.py"))
pp = importlib.util.module_from_spec(_s)
sys.modules["pp"] = pp
_s.loader.exec_module(pp)


def _atomic_write(path, obj):
    """The page reads these files on a one-minute cron. Writing in place lets it catch a
    half-written file and silently drop the section, so write beside and rename."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def rpc(url, creds, method, params=None):
    body = json.dumps({"jsonrpc": "1.0", "id": "crawl", "method": method,
                       "params": params or []}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "text/plain",
        "Authorization": "Basic " + base64.b64encode(creds.encode()).decode()})
    with urllib.request.urlopen(req, timeout=20) as r:
        out = json.load(r)
    if out.get("error"):
        raise RuntimeError(out["error"])
    return out["result"]


def our_chain(rest, tip, back):
    """height -> hash for the recent window, so a peer's headers can be checked against it."""
    out = {}
    for h in range(tip - back, tip + 1):
        try:
            out[h] = json.loads(urllib.request.urlopen(
                rest + "/blockhashbyheight/%d.json" % h, timeout=10).read())["blockhash"]
        except Exception:
            break
    return out


def judge(headers, ours, tip):
    """Compare a peer's headers to our chain. Returns a verdict and any divergence."""
    if not headers:
        return {"verdict": "no headers", "their_tip": None}
    seen = {}
    for h in headers:
        if "height" in h and "hash" in h:
            seen[h["height"]] = h["hash"]
    if not seen:
        return {"verdict": "legacy or unparsable headers", "their_tip": None}
    their_tip = max(seen)
    for ht in sorted(seen):
        if ht in ours and ours[ht] != seen[ht]:
            return {"verdict": "DIVERGES", "at_height": ht, "their_hash": seen[ht],
                    "our_hash": ours[ht], "their_tip": their_tip,
                    "their_tip_hash": seen[their_tip]}
    ahead = their_tip - tip
    return {"verdict": "agrees" + (" (ahead %d)" % ahead if ahead > 0 else ""),
            "their_tip": their_tip, "their_tip_hash": seen[their_tip],
            "matched": sum(1 for ht in seen if ht in ours and ours[ht] == seen[ht])}


def main():
    ap = argparse.ArgumentParser()
        # The list shipped in contrib/seeds is the legacy chain's. The fork's own list comes
    # from the seeds-blake2b branch and is refreshed into the state dir.
    ap.add_argument("--seeds", default=os.path.expanduser("~/.reorg-watch/seeds-blake2b.txt"))
    ap.add_argument("--rest", default="http://127.0.0.1:8332/rest")
    ap.add_argument("--rpc", default="http://127.0.0.1:8332/")
    ap.add_argument("--state", default=os.path.expanduser("~/.reorg-watch"))
    ap.add_argument("--limit", type=int, default=60)
    ap.add_argument("--back", type=int, default=6, help="how far back to start the locator")
    ap.add_argument("--threads", type=int, default=12)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out")
    args = ap.parse_args()

    rest = args.rest.rstrip("/")
    tip = json.loads(urllib.request.urlopen(rest + "/chaininfo.json", timeout=10).read())["blocks"]
    ours = our_chain(rest, tip, args.back + 4)

    # our own peers first: they are known reachable and known to be on this chain
    addrs, from_node = [], 0
    try:
        creds = open(os.path.join(args.state, "rpc.conf")).read().strip()
        for p in rpc(args.rpc, creds, "getpeerinfo"):
            a = p.get("addr", "")
            # Only outbound peers: for an inbound connection getpeerinfo reports the
            # source port it dialled from, which is ephemeral and not listening.
            if p.get("inbound"):
                continue
            if a and ".onion" not in a and not a.startswith("[") and a.rsplit(":", 1)[-1] == "8333":
                addrs.append(a)
                from_node += 1
    except Exception as e:
        print("getpeerinfo unavailable (%s); seeds only" % e, file=sys.stderr)
    try:
        for l in open(args.seeds):
            l = l.split("#")[0].strip()
            if l and ".onion" not in l and ".i2p" not in l and not l.startswith("["):
                addrs.append(l)
    except OSError:
        pass
    seen, uniq = set(), []
    for a in addrs:
        if a not in seen:
            seen.add(a)
            uniq.append(a)
    uniq = uniq[:args.limit]

    # locator a few blocks back, so every peer answers with headers we can check
    _, loc = pp.our_locator(rest)
    loc = [(h, x) for h, x in loc if h <= tip - args.back] or loc

    results, lock = [], threading.Lock()
    work = queue.Queue()
    for a in uniq:
        work.put(a)

    def worker():
        while True:
            try:
                a = work.get_nowait()
            except queue.Empty:
                return
            try:
                r = pp.probe(a, args.timeout, pp.DEFAULT_UA, loc, rest)
                rec = {"addr": a, "result": r.get("result"),
                       "user_agent": r.get("user_agent"),
                       "blake2b": r.get("blake2b"),
                       "start_height": r.get("start_height")}
                if r.get("result") == "ok":
                    hs = r.get("_headers") or []
                    rec.update(judge(hs, ours, tip))
                with lock:
                    results.append(rec)
            except Exception as e:
                with lock:
                    results.append({"addr": a, "result": "error (%s)" % e})
            finally:
                work.task_done()

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(args.threads)]
    [t.start() for t in ts]
    [t.join() for t in ts]

    ok = [r for r in results if r.get("result") == "ok"]
    b2 = [r for r in ok if r.get("blake2b")]
    agree = [r for r in b2 if str(r.get("verdict", "")).startswith("agrees")]
    diverge = [r for r in b2 if r.get("verdict") == "DIVERGES"]
    out = args.out or os.path.join(args.state, "peer-crawl.json")
    _atomic_write(out, {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "our_tip": tip, "our_tip_hash": ours.get(tip),
        "asked": len(uniq), "from_our_node": from_node,
        "answered": len(ok), "blake2b": len(b2),
        "agree": len(agree), "diverge": len(diverge),
        "divergent": diverge,
        "peers": sorted(results, key=lambda r: (r.get("result") != "ok", r.get("addr", ""))),
        "method": ("One version handshake and one getheaders per peer, locator set back "
                   "%d blocks so every peer answers with real headers. No credentials are "
                   "sent to anyone." % args.back),
    })
    print("asked %d (%d from our own peer list), %d answered, %d on this chain, "
          "%d agree, %d diverge -> %s"
          % (len(uniq), from_node, len(ok), len(b2), len(agree), len(diverge), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
