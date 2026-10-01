#!/usr/bin/env python3
"""chain-tips.py - record every branch the node knows about, with the pool that mined it.

reorg-watch.py sees a fork only when its own node reorganizes. Most stale blocks never
cause a reorg: they lose the race and the node keeps them without ever switching. Those
are invisible over REST, because only the getchaintips RPC enumerates them. This tool
makes that one RPC call, pulls each branch's blocks back over REST (which serves any block
the node has, by hash), attributes each one to a pool with reorg-watch's own coinbase
logic, and writes chain-tips.json for the page to render.

fork.observer does the same enumeration across many nodes. What it does not do is say who
mined the losing block, which on a chain with one pool near half the hashrate is the part
worth knowing.

Credentials: ~/.reorg-watch/rpc.conf holding one line "user:password" (chmod 600), or the
node's .cookie if this user can read it. Only getchaintips is called, so the RPC user can
be whitelisted to exactly that.

Usage: chain-tips.py [--rpc URL] [--rest URL] [--state DIR] [--depth N] [--fixture FILE]
"""

import argparse, importlib.util, json, os, stat, sys, urllib.request, base64
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("rw", os.path.join(HERE, "..", "reorg-watch.py"))
rw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rw)


def _atomic_write(path, obj):
    """The page reads these files on a one-minute cron. Writing in place lets it catch a
    half-written file and silently drop the section, so write beside and rename."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def credentials(state_dir):
    conf = os.path.join(state_dir, "rpc.conf")
    if os.path.exists(conf):
        mode = stat.S_IMODE(os.stat(conf).st_mode)
        if mode & 0o077:
            sys.exit("%s is mode %o; chmod 600 it before use" % (conf, mode))
        line = open(conf).read().strip()
        if line.startswith("rpcauth=") or "$" in line.split(":", 1)[-1]:
            sys.exit("%s holds the server-side rpcauth line. That is the salted hash for "
                     "bitcoin.conf and the password cannot be recovered from it. Put the "
                     "plaintext 'user:password' here instead - the password rpcauth.py "
                     "printed when the line was generated." % conf)
        return line
    for cookie in ("/home/bitcoin/.bitcoin/.cookie", os.path.expanduser("~/.bitcoin/.cookie")):
        try:
            return open(cookie).read().strip()
        except OSError:
            continue
    sys.exit("no RPC credentials: write user:password into %s (chmod 600), or make the "
             "node's .cookie readable" % conf)


def rpc(url, creds, method, params=None):
    body = json.dumps({"jsonrpc": "1.0", "id": "chain-tips", "method": method,
                       "params": params or []}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "text/plain",
        "Authorization": "Basic " + base64.b64encode(creds.encode()).decode(),
    })
    with urllib.request.urlopen(req, timeout=20) as r:
        out = json.load(r)
    if out.get("error"):
        raise RuntimeError("%s: %s" % (method, out["error"]))
    return out["result"]


def branch_blocks(rest, pools, tip_hash, branchlen, cap):
    """Walk a branch back from its tip. REST serves blocks the node has even when they are
    not on the active chain, which is the same path reorg-watch uses for a stale coinbase."""
    out, h = [], tip_hash
    for _ in range(min(branchlen, cap)):
        b = rest.block_notx(h)
        if not b:
            break
        out.append(rw.describe_block(rest, pools, b["height"], h))
        h = b.get("previousblockhash")
        if not h:
            break
    return list(reversed(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8332/")
    ap.add_argument("--rest", default="http://127.0.0.1:8332/rest")
    ap.add_argument("--state", default=os.path.expanduser("~/.reorg-watch"))
    ap.add_argument("--depth", type=int, default=20000, help="ignore branches older than this many blocks")
    ap.add_argument("--fork-height", type=int, default=961640,
                    help="never look below this height; older tips are the legacy chain")
    ap.add_argument("--cap", type=int, default=12, help="max blocks to pull per branch")
    ap.add_argument("--fixture", help="read a getchaintips response from a file instead of calling RPC")
    ap.add_argument("--out")
    args = ap.parse_args()

    rest = rw.Rest(args.rest.rstrip("/"))
    pools = rw.Pools(os.path.join(args.state, "pools-v2.json"), False)

    if args.fixture:
        tips = json.load(open(args.fixture))
    else:
        tips = rpc(args.rpc, credentials(args.state), "getchaintips")

    peers = []
    if not args.fixture:
        try:
            for pr in rpc(args.rpc, credentials(args.state), "getpeerinfo"):
                peers.append({k: pr.get(k) for k in (
                    "addr", "subver", "services", "startingheight", "synced_headers",
                    "synced_blocks", "inbound", "conntime", "relaytxes")})
        except Exception as e:
            peers = [{"error": str(e)}]

    active = next((t for t in tips if t["status"] == "active"), None)
    if not active:
        sys.exit("getchaintips returned no active tip")
    floor = max(active["height"] - args.depth, args.fork_height)

    branches = []
    for t in tips:
        # A branch belongs to this chain only if it left our chain AFTER the fork block.
        # The legacy SHA256d chain also has heights above the fork height, so filtering on
        # tip height alone keeps it in; filtering on the fork point is what separates them.
        if t["status"] == "active" or t["branchlen"] < 1:
            continue
        if t["height"] - t["branchlen"] < floor:
            continue
        blocks = [] if t["status"] == "headers-only" else branch_blocks(
            rest, pools, t["hash"], t["branchlen"], args.cap)
        forked_at = (blocks[0]["height"] - 1) if blocks else (t["height"] - t["branchlen"])
        winners = []
        for hh in range(forked_at + 1, min(t["height"], active["height"]) + 1):
            try:
                winners.append(rw.describe_block(rest, pools, hh, rest.hash_at(hh)))
            except Exception:
                break
        branches.append({
            "status": t["status"], "tip_hash": t["hash"], "tip_height": t["height"],
            "branchlen": t["branchlen"], "forked_at": forked_at,
            "lost": blocks, "won": winners,
        })

    branches.sort(key=lambda b: -b["tip_height"])
    out = args.out or os.path.join(args.state, "chain-tips.json")
    try:
        active_blk = rw.describe_block(rest, pools, active["height"], active["hash"])
    except Exception:
        active_blk = None
    _atomic_write(out, {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "active": {"height": active["height"], "hash": active["hash"],
                   "pool": (active_blk or {}).get("pool")},
        "window": args.depth,
        "fork_height": args.fork_height,
        "tips_total": len(tips),
        "branches": branches,
        "peers": peers,
        "method": ("One getchaintips call enumerates every branch the node knows. Branch "
                   "blocks come from the node's REST interface by hash and are attributed "
                   "with the same coinbase logic as the rest of this site."),
    })
    agree = sum(1 for p in peers if p.get("synced_headers") == active["height"])
    print("wrote %s: %d tips, %d competing branches at or above height %d, %d peers (%d at our tip)"
          % (out, len(tips), len(branches), floor, len(peers), agree))
    return 0


if __name__ == "__main__":
    sys.exit(main())
