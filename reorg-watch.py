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
  - keeps an index of every coinbase output since the fork and watches each
    new block for spends of them: which pool moved how much of its rewards,
    payout-shaped or sweep-shaped, and whether one wallet is spending rewards
    mined under two different pool names (a split identity)
  - with --html, writes a self-contained status page (tip, explorer
    agreement, pool shares for the last 24 h by hour, reward flow, recent
    events) to serve as a static file

Everything comes from the node's REST interface. No electrs, no address
index, no RPC credentials.

Prints nothing unless something happened.

Usage: reorg-watch.py [--init] [--report] [--state DIR] [--rest URL]
                      [--explorer URL] [--notify CMD] [--alert-depth N]
                      [--keep N] [--floor H] [--html FILE] [--no-rewards]
                      [--sweep-btc N] [--verbose]
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
  --no-rewards    skip the reward-flow index (saves the one-time backfill)
  --sweep-btc N   log a reward movement of at least N BTC into one or two
                  outputs as an event (default 10; 0 disables)
  --tz ZONE       time zone for the status page as rendered by the server,
                  e.g. America/New_York; browsers with JavaScript re-render
                  every time in the viewer's own zone (default UTC; logs and
                  JSON files always use UTC)

Files in the state dir: state.json, rewards.json, events.jsonl,
reorg-log.md, pools-v2.json (cache), lock.
"""
import argparse
import fcntl
import hashlib
import html
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from zoneinfo import ZoneInfo

DEFAULT_FLOOR = 961640  # mainnet BLAKE2b fork block; nothing reorganizes across it
POOLS_URL = "https://raw.githubusercontent.com/Kilombino/mempool-bip110/main/pools-v2.json"
POOLS_REPO = "https://github.com/Kilombino/mempool-bip110"
UA = "reorg-watch/1.1 (Bitcoin Knots node monitor)"
REPO_URL = "https://github.com/jasonsopko/reorg-watch"
NOW = time.time()


def ts(t=None):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(NOW if t is None else t))


PAGE_TZ = ZoneInfo("UTC")


def tsz(t=None, fmt="%Y-%m-%d %H:%M:%S %Z"):
    """Page-facing time in the --tz zone; logs and JSON stay UTC."""
    return datetime.fromtimestamp(NOW if t is None else t, PAGE_TZ).strftime(fmt)


def tt(t, fmt="full"):
    """Server-rendered time (in --tz) wrapped so the page script can show it in the viewer's zone.
    fmt: full = Y-m-d H:M:S zone, minute = Y-m-d H:M, clock = H:M:S, short = m-d H:M, hour = H:00."""
    py = {"full": "%Y-%m-%d %H:%M:%S %Z", "minute": "%Y-%m-%d %H:%M", "clock": "%H:%M:%S", "short": "%m-%d %H:%M", "hour": "%H:%M"}[fmt]
    return f'<time data-epoch="{int(t)}" data-fmt="{fmt}">{html.escape(tsz(t, py))}</time>'


def hour_floor(t):
    d = datetime.fromtimestamp(t, PAGE_TZ).replace(minute=0, second=0, microsecond=0)
    return int(d.timestamp())


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

    def block_raw(self, blockhash):
        return http_get(f"{self.base}/block/{blockhash}.bin", timeout=30)


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


# ---------------------------------------------------------------------------
# Address encoding (for naming coinbase outputs parsed from raw blocks)

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def b58check(payload):
    raw = payload + sha256d(payload)[:4]
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def bech32_encode(hrp, witver, prog):
    def polymod(values):
        gen = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
        chk = 1
        for v in values:
            b = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in range(5):
                chk ^= gen[i] if (b >> i) & 1 else 0
        return chk
    acc, bits, data = 0, 0, [witver]
    for byte in prog:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expand = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    const = 1 if witver == 0 else 0x2bc830a3
    pm = polymod(expand + data + [0] * 6) ^ const
    return hrp + "1" + "".join(BECH[d] for d in data + [(pm >> 5 * (5 - i)) & 31 for i in range(6)])


def spk_to_address(spk, hrp="bc"):
    if len(spk) == 25 and spk[:3] == b"\x76\xa9\x14" and spk[-2:] == b"\x88\xac":
        return b58check(b"\x00" + spk[3:23])
    if len(spk) == 23 and spk[:2] == b"\xa9\x14" and spk[-1] == 0x87:
        return b58check(b"\x05" + spk[2:22])
    if 4 <= len(spk) <= 42 and (spk[0] == 0 or 0x51 <= spk[0] <= 0x60) and spk[1] == len(spk) - 2 and 2 <= spk[1] <= 40:
        return bech32_encode(hrp, 0 if spk[0] == 0 else spk[0] - 0x50, spk[2:])
    return None


# ---------------------------------------------------------------------------
# Raw block parsing. Version bit 31 marks the 164-byte BLAKE2b header; txids
# stay SHA256d of the non-witness serialization.

def varint(b, i):
    v = b[i]
    if v < 0xfd:
        return v, i + 1
    if v == 0xfd:
        return struct.unpack_from("<H", b, i + 1)[0], i + 3
    if v == 0xfe:
        return struct.unpack_from("<I", b, i + 1)[0], i + 5
    return struct.unpack_from("<Q", b, i + 1)[0], i + 9


def parse_tx(b, i):
    ver = b[i:i + 4]
    i += 4
    segwit = b[i] == 0 and b[i + 1] == 1
    if segwit:
        i += 2
    body = i
    nin, i = varint(b, i)
    vins, sig0 = [], b""
    for k in range(nin):
        prev = b[i:i + 32][::-1].hex()
        n = struct.unpack_from("<I", b, i + 32)[0]
        i += 36
        sl, i = varint(b, i)
        if k == 0:
            sig0 = b[i:i + sl]
        i += sl + 4
        vins.append((prev, n))
    nout, i = varint(b, i)
    vouts = []
    for _ in range(nout):
        val = struct.unpack_from("<q", b, i)[0]
        i += 8
        sl, i = varint(b, i)
        vouts.append((val, b[i:i + sl]))
        i += sl
    end = i
    if segwit:
        for _ in range(nin):
            nw, i = varint(b, i)
            for _ in range(nw):
                wl, i = varint(b, i)
                i += wl
    lock = b[i:i + 4]
    i += 4
    txid = sha256d(ver + b[body:end] + lock)[::-1].hex()
    return {"txid": txid, "vin": vins, "vout": vouts, "coinbase": nin == 1 and vins[0][0] == "00" * 32, "sig": sig0}, i


def parse_header(raw):
    """Header fields that say how the block was mined. v2 layout after the 80 classic bytes:
    nonce2(4) nonce3(4) extranonce(16) time_offset(4) txcount(2) flags(1) xor_clear_bits(1) xor_key(16) height(4) mm_rhs(32)."""
    version, = struct.unpack_from("<I", raw, 0)
    h = {"v2": bool(version & 0x80000000), "time": struct.unpack_from("<I", raw, 68)[0], "nonce": struct.unpack_from("<I", raw, 76)[0]}
    if not h["v2"]:
        return h
    nonce2, nonce3 = struct.unpack_from("<II", raw, 80)
    time_offset, txcount, flags, xor_clear = struct.unpack_from("<IHBB", raw, 104)
    xor_key = raw[112:128]
    h.update({"nonce2": nonce2, "nonce3": nonce3, "toff": time_offset, "flags": flags, "xor": any(xor_key),
              "n3": "time" if nonce3 == h["time"] else ("zero" if nonce3 == 0 else "other"),
              "tof": "time" if time_offset and abs(time_offset - h["time"]) < 2 * 86400 else ("value" if time_offset else None)})
    return h


def parse_block(raw, with_header=False):
    version = struct.unpack_from("<I", raw, 0)[0]
    i = 164 if version & 0x80000000 else 80
    ntx, i = varint(raw, i)
    txs = []
    for _ in range(ntx):
        tx, i = parse_tx(raw, i)
        txs.append(tx)
    return (txs, parse_header(raw)) if with_header else txs



def script_pushes(sig):
    out, i = [], 0
    while i < len(sig):
        op = sig[i]
        i += 1
        if 1 <= op <= 75:
            out.append(sig[i:i + op])
            i += op
        elif op == 76 and i < len(sig):
            n = sig[i]
            out.append(sig[i + 1:i + 1 + n])
            i += 1 + n
        else:
            out.append(None)  # a non-push opcode; unusual in a coinbase
    return out


def classify_coinbase(sig, vouts):
    """Who built the template, from the coinbase layout the DATUM gateway writes:
    height push, one tag push (primary [0x0F secondary] 0x00), a unique-id push of 3 bytes when the
    gateway runs standalone or 7+ bytes when a DATUM pool is upstream, then a 14-byte extranonce
    push (or an OP_RETURN carrying it). Returns (class, primary_tag, secondary_tag).
      D = DATUM pool: the miner's own gateway and node built the block
      G = standalone gateway: the payout address owner's node built it (a pool, or a solo miner)
      O = something else"""
    p = script_pushes(sig)
    primary = secondary = ""
    if len(p) >= 2 and p[1] is not None and p[1] and p[1][-1] == 0:
        parts = p[1].rstrip(b"\x00").split(b"\x0f")
        primary = parts[0].decode("latin1")
        secondary = parts[1].decode("latin1") if len(parts) > 1 else ""
        uid = len(p[2]) if len(p) >= 3 and p[2] is not None else 0
        en = (len(p) >= 4 and p[-1] is not None and len(p[-1]) == 14) or any(len(spk) == 16 and spk[:2] == b"\x6a\x0e" for _, spk in vouts)
        if uid >= 7 and en:
            return "D", primary, secondary
        if uid == 3 and en:
            return "G", primary, secondary
    return "O", primary, secondary


CLASS_NAMES = {"D": "DATUM pool", "G": "Gateway, stratum v1", "O": "Other software"}


def describe_header(hd):
    """Short text for the page: ASIC profile, time-rolling flag, offset, Sia time slot, xor."""
    if not hd:
        return "-"
    parts = [f"profile {hd.get('flags', 0) & 3}"]
    if hd.get("flags", 0) & 4:
        parts.append("time roll allowed")
    if hd.get("tof") == "time":
        parts.append("time in offset field")
    elif hd.get("toff"):
        parts.append(f"offset {hd['toff']}")
    parts.append({"time": "time in slot 3", "zero": "slot 3 empty", "other": "slot 3 other"}.get(hd.get("n3"), "?"))
    if hd.get("xor"):
        parts.append("xor key")
    return ", ".join(parts)


def subsidy(height):
    return 5000000000 >> (height // 210000)


# ---------------------------------------------------------------------------
# Reward flow: every coinbase output since the fork, and every spend of one.

def named(label):
    return not (label.startswith("Solo ") or label.lower().startswith("unknown") or label.lower().startswith("solo"))


class Rewards:
    def __init__(self, sd):
        self.path = os.path.join(sd, "rewards.json")
        self.d = {"version": 6, "scanned_to": None, "coinbases": {}, "spends": [], "overlaps": []}
        if os.path.exists(self.path):
            with open(self.path) as f:
                old = json.load(f)
            if old.get("version", 1) >= 6:
                self.d = old
            else:
                print(f"{ts()} reward index format changed; rebuilding", flush=True)
        self.dropped = set()  # spend txids removed by a rollback this run; not re-announced

    def save(self):
        with open(self.path + ".tmp", "w") as f:
            json.dump(self.d, f, separators=(",", ":"))
        os.replace(self.path + ".tmp", self.path)

    def rollback(self, height):
        cbs = self.d["coinbases"]
        for txid in [t for t, c in cbs.items() if c["h"] > height]:
            del cbs[txid]
        self.dropped = {x["txid"] for x in self.d["spends"] if x["h"] > height}
        self.d["spends"] = [x for x in self.d["spends"] if x["h"] <= height]
        self.d["scanned_to"] = height

    def process_block(self, rest, pools, height, blockhash, t, label=None):
        cbs = self.d["coinbases"]
        txs, hdr = parse_block(rest.block_raw(blockhash), with_header=True)
        for tx in txs:
            if tx["coinbase"]:
                outs = {str(n): [spk.hex(), val] for n, (val, spk) in enumerate(tx["vout"]) if val > 0}
                if label is None:
                    addrs = [a for a in (spk_to_address(bytes.fromhex(o[0])) for o in outs.values()) if a]
                    label = pools.identify(addrs, coinbase_tag(tx["sig"].hex()))
                cls, primary, secondary = classify_coinbase(tx["sig"], tx["vout"])
                cbs[tx["txid"]] = {"h": height, "t": t, "label": label, "outs": outs, "cls": cls,
                                   "tags": [primary, secondary], "ntx": len(txs),
                                   "hdr": {k: hdr.get(k) for k in ("flags", "toff", "n3", "xor", "tof") if k in hdr}}
                continue
            hit = [(p, n) for p, n in tx["vin"] if p in cbs and str(n) in cbs[p]["outs"]]
            if not hit:
                continue
            ins, labels, cb_sats = [], {}, 0
            for p, n in tx["vin"]:
                if p in cbs and str(n) in cbs[p]["outs"]:
                    spk, sats = cbs[p]["outs"][str(n)]
                    ins.append(spk_to_address(bytes.fromhex(spk)) or spk)
                    labels[cbs[p]["label"]] = labels.get(cbs[p]["label"], 0) + sats
                    cb_sats += sats
                else:
                    prev = rest.tx(p)
                    a = prev["vout"][n]["scriptPubKey"].get("address") if prev else None
                    ins.append(a or f"prefork:{p[:12]}")
            outs = sorted((v for v, _ in tx["vout"] if v > 0), reverse=True)
            kind = "payout" if len(outs) >= 3 else ("sweep" if len(hit) >= 2 else "transfer")
            self.d["spends"].append({"h": height, "t": t, "txid": tx["txid"], "n_cb": len(hit), "cb_sats": cb_sats,
                                     "labels": labels, "ins": sorted(set(ins)), "n_in": len(tx["vin"]),
                                     "n_out": len(outs), "out_max": outs[0] if outs else 0, "kind": kind})
        self.d["scanned_to"] = height

    def sync(self, rest, pools, chain, blocks_meta, top, ancestor, floor, sweep_sats, verbose):
        """Bring the index up to `top`. Returns the list of new spend records."""
        if self.d["scanned_to"] is not None and ancestor is not None and ancestor < self.d["scanned_to"]:
            self.rollback(ancestor)
        before = len(self.d["spends"])
        backfill = self.d["scanned_to"] is None
        if backfill:
            start = floor
            print(f"{ts()} reward index: backfilling from {start} to {top}, one pass over the raw blocks", flush=True)
        else:
            start = self.d["scanned_to"] + 1
        if start <= top:
            hashes = {}
            if top - start + 1 > 3:
                first = rest.hash_at(start)
                for hdr in rest.headers(first, top - start + 1):
                    hashes[hdr["height"]] = (hdr["hash"], hdr["time"])
            for h in range(start, top + 1):
                if h in hashes:
                    bh, t = hashes[h]
                else:
                    bh = chain.get(h) or rest.hash_at(h)
                    meta = blocks_meta.get(str(h), {})
                    t = meta.get("time") or rest.json(f"headers/1/{bh}.json")[0]["time"]
                label = blocks_meta.get(str(h), {}).get("pool")
                self.process_block(rest, pools, h, bh, t, label)
                if verbose and (h - start) % 1000 == 999:
                    print(f"{ts()} reward index at {h}", flush=True)
        new = [x for x in self.d["spends"][before:] if x["txid"] not in self.dropped]
        events = []
        if backfill:
            sweep_sats = 0  # history is recorded, not announced
        if sweep_sats:
            for x in new:
                if x["cb_sats"] >= sweep_sats and x["n_out"] <= 2:
                    events.append({"type": "reward_sweep", "level": "INFO", "height": x["h"], "txid": x["txid"], "btc": x["cb_sats"] / 1e8,
                                   "labels": x["labels"], "n_cb": x["n_cb"], "n_out": x["n_out"]})
        counts = {}
        for c in self.d["coinbases"].values():
            counts[c["label"]] = counts.get(c["label"], 0) + 1
        groups = self.wallet_groups()
        for pair, example in self.overlaps().items():
            if list(pair) in self.d["overlaps"]:
                continue
            self.d["overlaps"].append(list(pair))
            if not backfill and counts.get(pair[0], 0) >= 100 and counts.get(pair[1], 0) >= 100:
                events.append({"type": "label_overlap", "level": "ALERT", "labels": list(pair), "shared_address": example,
                               "blocks": [counts[pair[0]], counts[pair[1]]]})
        day = [b for b in blocks_meta.values() if b.get("time") and NOW - b["time"] <= 86400]
        if day:
            for g in groups:
                if len(g) < 2:
                    continue
                n = sum(1 for b in day if b["pool"] in g)
                key = "|".join(sorted(g))
                if n >= len(day) / 3 and key not in self.d.setdefault("share_alerts", []):
                    self.d["share_alerts"].append(key)
                    if backfill:
                        continue
                    events.append({"type": "wallet_share", "level": "ALERT", "labels": sorted(g), "blocks": n, "of": len(day),
                                   "share": round(100 * n / len(day), 1)})
        self.save()
        return events

    def clusters(self):
        parent = {}

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        for x in self.d["spends"]:
            real = [a for a in x["ins"] if not a.startswith("prefork:")]
            for a in real[1:]:
                parent[find(real[0])] = find(a)
        out = {}
        for a in list(parent):
            out.setdefault(find(a), set()).add(a)
        return out

    def identity_addresses(self):
        """Address -> set of labels for which it is the pool's own wallet: paid in at least 90% of
        that label's blocks (and at least 5). Miners paid directly in a coinbase recur far less."""
        blocks, seen = {}, {}
        for c in self.d["coinbases"].values():
            blocks[c["label"]] = blocks.get(c["label"], 0) + 1
            for spk, _ in c["outs"].values():
                key = (c["label"], spk)
                seen[key] = seen.get(key, 0) + 1
        out = {}
        for (label, spk), n in seen.items():
            if blocks[label] >= 5 and n >= 0.9 * blocks[label]:
                out.setdefault(spk_to_address(bytes.fromhex(spk)) or spk, set()).add(label)
        return out

    def wallet_groups(self):
        """Labels merged by shared wallet: one identity address paid under several names, or identity
        addresses co-spent in one cluster. Returns {frozenset(labels): example address}."""
        ident = self.identity_addresses()
        parent, example = {}, {}

        def find(x):
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(labels, addr):
            labels = sorted(labels)
            for l in labels[1:]:
                parent[find(labels[0])] = find(l)
            for l in labels:
                example.setdefault(l, addr)
        for a, ls in ident.items():
            union(ls, a)
        for members in self.clusters().values():
            ls = {l for a in members if a in ident for l in ident[a]}
            if len(ls) > 1:
                union(ls, sorted(m for m in members if m in ident)[0])
        groups = {}
        for l in {c["label"] for c in self.d["coinbases"].values()}:
            groups.setdefault(find(l), set()).add(l)
        return {frozenset(g): example.get(sorted(g)[0], "") for g in groups.values()}

    def overlaps(self):
        """Pairs of named labels that share a wallet -> example address."""
        found = {}
        for g, addr in self.wallet_groups().items():
            ls = sorted(l for l in g if named(l))
            for i in range(len(ls)):
                for j in range(i + 1, len(ls)):
                    found[(ls[i], ls[j])] = addr
        return found

    def summary(self, tip):
        per = {}
        for c in self.d["coinbases"].values():
            p = per.setdefault(c["label"], {"blocks": 0, "mined": 0, "matured": 0, "moved": 0, "n_spends": 0, "last_t": None, "last_kind": None,
                                            "cls": {}, "nouts": []})
            sats = sum(v for _, v in c["outs"].values())
            p["blocks"] += 1
            p["mined"] += sats
            p["cls"][c.get("cls", "O")] = p["cls"].get(c.get("cls", "O"), 0) + 1
            p["nouts"].append(len(c["outs"]))
            if c["h"] <= tip - 100:
                p["matured"] += sats
        for x in self.d["spends"]:
            for label, sats in x["labels"].items():
                p = per.setdefault(label, {"blocks": 0, "mined": 0, "matured": 0, "moved": 0, "n_spends": 0, "last_t": None, "last_kind": None,
                                           "cls": {}, "nouts": []})
                p["moved"] += sats
                p["n_spends"] += 1
                if p["last_t"] is None or x["t"] > p["last_t"]:
                    p["last_t"], p["last_kind"] = x["t"], x["kind"]
        return sorted(per.items(), key=lambda kv: -kv[1]["blocks"])



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
    if t == "label_overlap":
        nb = e.get("blocks", ["?", "?"])
        return (f"## {ts()} - one wallet behind two pool names: {e['labels'][0]} and {e['labels'][1]}\n"
                f"- {nb[0]} and {nb[1]} blocks since the fork; shared or co-spent address `{e.get('shared_address', '?')}`\n\n")
    if t == "wallet_share":
        return (f"## {ts()} - one wallet mined {e['share']}% of the last 24 hours\n"
                f"- {e['blocks']} of {e['of']} blocks under the labels {', '.join(e['labels'])}\n\n")
    if t == "reward_sweep":
        who = ", ".join(f"{k} {v / 1e8:.3f} BTC" for k, v in e["labels"].items())
        return (f"## {ts()} - reward movement of {e['btc']:.3f} BTC at height {e['height']}\n"
                f"- {e['n_cb']} coinbase outputs spent into {e['n_out']} output(s) in `{e['txid']}`\n- {who}\n\n")
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
    if t == "reward_sweep":
        who = ", ".join(f"{k} {v / 1e8:.2f}" for k, v in e["labels"].items())
        return f"INFO reward sweep {e['btc']:.2f} BTC at {e['height']}: {e['n_cb']} coinbase outputs -> {e['n_out']} output(s); {who}"
    if t == "label_overlap":
        nb = e.get("blocks", ["?", "?"])
        return f"ALERT one wallet behind both {e['labels'][0]} ({nb[0]} blocks) and {e['labels'][1]} ({nb[1]} blocks); address {e.get('shared_address', '?')[:16]}.."
    if t == "wallet_share":
        return f"ALERT one wallet mined {e['share']}% of the last 24 h ({e['blocks']}/{e['of']} blocks) under labels {', '.join(e['labels'])}"
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


TIPS = {
    "node": "The node answered its REST interface this run. Three misses in a row is an alert.",
    "explorer": "The explorer's block hash at our tip height is compared with ours once a minute. A different hash for 2 consecutive checks, or the explorer 3 or more blocks ahead for 3 checks, is an alert.",
    "reorgs": "A reorg is counted when the active chain's hash at an already-seen height changes. Depth is the number of blocks replaced. Depth 1 is an ordinary tie between two blocks found seconds apart; depth 2 or more is an alert.",
    "last_alert": "Most recent event that was emailed: a reorg of depth 2 or more, an explorer disagreement, a node that fell behind, a node outage, or two substantial pool names found sharing one wallet.",
    "tip": "Height and hash of the node's best block at the time this page was generated.",
    "pool": "Named from the coinbase payout address in Kilombino's pool list first, then from the coinbase tag. Both are chosen by the miner, so a name is a claim, not proof.",
    "blocks24": "Blocks whose header time falls in the last 24 hours. Shares are block counts and carry a few points of statistical noise.",
    "share24": "This pool's blocks divided by all blocks in the last 24 hours.",
    "builder": "Read from the coinbase layout the DATUM gateway writes. DATUM pool: the unique-id push is 7 or more bytes, which the gateway writes only with a DATUM pool upstream, so the miner's own node built the block. Gateway, stratum v1: a 3-byte unique-id push, the gateway running standalone, so the node of whoever owns the payout address built the block. Other software: a coinbase this page does not recognize.",
    "hour": "Hour by block header time, labeled in your browser's time zone (the server's zone without JavaScript). Buckets are whole hours. The current hour is still filling.",
    "hourshare": "This pool's share of that hour's blocks. The three columns are the three largest pools of the day. Cells at or above half are marked.",
    "blocks_fork": "All blocks this label has mined since the BLAKE2b fork block.",
    "payout": "Median number of value-bearing outputs in this pool's coinbases. One output means the pool keeps the reward and pays miners later; two is a split; three or more is paid directly to miners in the coinbase.",
    "mined": "Sum of this pool's coinbase outputs since the fork: subsidy plus fees, in BTC.",
    "matured": "Mined at least 100 blocks ago, so spendable.",
    "moved": "Coinbase outputs of this pool that have been spent in any later transaction, whether a payout to miners, a consolidation, or a transfer. The chain shows movement, not a sale.",
    "moved_pct": "Moved divided by matured. 100 percent means every spendable reward has left the coinbase address.",
    "held": "Mined minus moved. Includes rewards that are not yet mature.",
    "last_move": "Header time of the latest transaction spending this pool's coinbase outputs, and its shape: payout has 3 or more outputs, sweep gathers several rewards into 1 or 2 outputs, transfer moves one reward to 1 or 2 outputs.",
    "wallet": "Labels merged into one wallet when the same pool address is paid in at least 90 percent of the blocks of both labels, or when pool addresses of both labels are spent together in one transaction, which means one key holder. A pool that lets miners write their own tag shows up here as one wallet with many labels.",
    "wallet_labels": "The other labels whose blocks this wallet collected.",
    "wallet24": "Blocks in the last 24 hours across every label in this wallet.",
    "wallet_fork": "Blocks since the fork across every label in this wallet.",
    "height": "Block height.",
    "time": "Block header time, set by the miner, shown in your browser's time zone (the server's zone without JavaScript).",
    "tags": "The primary and secondary coinbase tags as the gateway wrote them: pool or operator first, then the miner's own tag.",
    "txs": "Transactions in the block, including the coinbase.",
    "outputs": "Value-bearing outputs of the coinbase transaction.",
    "reward": "Total value of the coinbase outputs: subsidy plus fees.",
    "fees": "Reward minus the subsidy for that height.",
    "hdr": "Read from the 164-byte header. Every BLAKE2b block has three nonce fields: nonce is the ASIC's 32-bit nonce, nonce2 the gateway's second nonce, nonce3 the Sia time slot, which Sia-protocol ASICs fill with the timestamp ('time in slot 3'); software that leaves it zero is not driving a Sia-protocol miner. Profile is the low two bits of the flags byte and picks one of four header layouts; every block so far is profile 0. 'Time roll allowed' is flag bit 4, set by a gateway configured to let the hasher roll the timestamp, with the real time recovered from the offset. An offset without the flag is ignored by the node for timekeeping and acts as extra nonce space; 'time in offset field' marks software that writes the timestamp there instead of slot 3. 'xor key' means the miner used the header's xor mask.",
    "mv_pool": "Labels of the coinbases this transaction spent, with the BTC from each.",
    "mv_btc": "Total coinbase value this transaction spent.",
    "mv_in": "Number of coinbase outputs consumed.",
    "mv_out": "Number of value-bearing outputs.",
    "shape": "Payout has 3 or more outputs, sweep gathers several rewards into 1 or 2 outputs, transfer moves one reward to 1 or 2 outputs.",
    "level": "INFO is logged. ALERT is logged and emailed.",
    "event": "Reorgs name the pools on both sides. Explorer and node events say which check failed and for how many consecutive runs.",
}
CLASS_TIPS = {
    "D": "Unique-id push of 7 or more bytes: the gateway had a DATUM pool upstream, so the miner's own node built this template. The pool could not choose the transactions.",
    "G": "Unique-id push of 3 bytes: the DATUM gateway running standalone, serving stratum v1. The node of whoever owns the payout address built this template.",
    "O": "A coinbase layout this page does not recognize. Not built by the DATUM gateway software.",
}
KIND_TIPS = {"payout": "3 or more outputs: rewards distributed to miners.",
             "sweep": "Several rewards gathered into 1 or 2 outputs.",
             "transfer": "One reward moved to 1 or 2 outputs."}


def tipped(label, tip, cls=""):
    E = html.escape
    c = f' class="{cls}"' if cls else ""
    return f'<span{c} tabindex="0" data-tip="{E(tip)}">{E(label)}</span>'


def th(label, key, cls="", width=""):
    a = (f' class="{cls}"' if cls else "") + (f' style="width:{width}"' if width else "")
    return f"<th{a}>{tipped(label, TIPS[key], 'tip')}</th>"


def stackable(page):
    """Give every td in tables marked class=stack a data-l label from its header, so the
    narrow-screen CSS can show label: value pairs instead of a sideways scroll."""
    def fix_table(m):
        t = m.group(0)
        rows = re.split(r"(?=<tr)", t)
        head_i = next((i for i, r in enumerate(rows) if r.startswith("<tr")), None)
        if head_i is None:
            return t
        labels = [re.sub(r"<[^>]+>", "", x).strip() for x in re.findall(r"<th[^>]*>(.*?)</th>", rows[head_i], re.S)]
        rows[head_i] = rows[head_i].replace("<tr>", '<tr class="head">', 1)
        for i in range(head_i + 1, len(rows)):
            if "colspan" in rows[i]:
                continue
            k = iter(labels)
            rows[i] = re.sub(r"<td(?=[\s>])", lambda _: f'<td data-l="{html.escape(next(k, ""))}"', rows[i])
        return "".join(rows)
    return re.sub(r'<table class="stack[^"]*">.*?</table>', fix_table, page, flags=re.S)


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
    h0 = hour_floor(now)
    for i in range(23, -1, -1):
        lo = h0 - i * 3600
        hb = [b for b in day if lo <= b["time"] < lo + 3600]
        row = {"label": tt(lo, "hour"), "n": len(hb), "na": lo + 3600 <= earliest}
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
    last_alert = tt(alerts[-1]["_t"]) if alerts else "none recorded"

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

    cls_by_h = {}
    if os.path.exists(os.path.join(sd, "rewards.json")):
        cls_by_h = {c["h"]: c.get("cls", "O") for c in Rewards(sd).d["coinbases"].values()}
    day_h = {h: b for h, b in blocks if now - b["time"] <= 86400}

    def builder_mix(group):
        cnt = {}
        for h, b in day_h.items():
            if pool_group(b["pool"]) == group and h in cls_by_h:
                cnt[cls_by_h[h]] = cnt.get(cls_by_h[h], 0) + 1
        n = sum(cnt.values())
        if not n:
            return "-"
        top = sorted(cnt.items(), key=lambda kv: -kv[1])
        return ", ".join(tipped(CLASS_NAMES[k] + (f" {100 * v / n:.0f}%" if len(top) > 1 else ""), CLASS_TIPS[k]) for k, v in top[:2])

    def rows_shares():
        out = []
        for n, k in ranked[:15]:
            label = f"Unknown ({len(unknown_addrs)} payout address{'es' if len(unknown_addrs) != 1 else ''})" if n == "Unknown" else n
            out.append(f"<tr><td>{E(label)}</td><td class=n>{k}</td><td class=n>{100 * k / total:.1f}%</td><td>{builder_mix(n)}</td></tr>")
        rest_n = sum(k for _, k in ranked[15:])
        if rest_n:
            out.append(f"<tr><td>{len(ranked) - 15} others</td><td class=n>{rest_n}</td><td class=n>{100 * rest_n / total:.1f}%</td><td></td></tr>")
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
            out.append(f"<tr><td class=t>{tt(e['_t'], 'minute')}</td><td class={'alert' if lvl == 'ALERT' else 'info'}>{lvl}</td><td>{E(line)}</td></tr>")
        return "\n".join(out) or "<tr><td colspan=3 class=note>none yet</td></tr>"

    hour_heads = "".join(f"<th class=n>{E(c)}</th>" for c in cols)

    rw_path = os.path.join(sd, "rewards.json")
    reward_rows, move_rows, wallet_rows, block_rows, overlap_text, rw_note = "", "", "", "", "", ""
    if os.path.exists(rw_path):
        rw = Rewards(sd)
        tip_for = tip_h or 0
        summ = rw.summary(tip_for)
        def template_mix(cls):
            n = sum(cls.values()) or 1
            top = sorted(cls.items(), key=lambda kv: -kv[1])
            return ", ".join(tipped(CLASS_NAMES[k] + (f" {100 * v / n:.0f}%" if len(top) > 1 else ""), CLASS_TIPS[k]) for k, v in top[:2])

        def payout_style(nouts):
            if not nouts:
                return "-"
            med = sorted(nouts)[len(nouts) // 2]
            return "1 output, pool custody" if med <= 1 else ("2 outputs" if med == 2 else f"direct, median {med} outputs")
        for label, p in summ[:12]:
            pct = f"{100 * p['moved'] / p['matured']:.0f}%" if p["matured"] else "-"
            last = f"{tt(p['last_t'], 'minute')}<br>{p['last_kind']}" if p["last_t"] else "never"
            reward_rows += (f"<tr><td>{E(label)}</td><td class=n>{p['blocks']}</td><td>{template_mix(p['cls'])}</td><td>{E(payout_style(p['nouts']))}</td>"
                            f"<td class=n>{p['mined'] / 1e8:.2f}</td><td class=n>{p['matured'] / 1e8:.2f}</td><td class=n>{p['moved'] / 1e8:.2f}</td><td class=n>{pct}</td>"
                            f"<td class=n>{(p['mined'] - p['moved']) / 1e8:.2f}</td><td class=t>{last}</td></tr>")
        latest = sorted(rw.d["coinbases"].values(), key=lambda c: -c["h"])[:20]
        for c in latest:
            reward_total = sum(v for _, v in c["outs"].values())
            fee = reward_total - subsidy(c["h"])
            tag = c.get("tags", ["", ""])
            tagtxt = " / ".join(t for t in tag if t)
            block_rows += (f"<tr><td class=n>{c['h']}</td><td class=t>{tt(c['t'], 'clock')}</td><td>{E(c['label'])}</td><td>{tipped(CLASS_NAMES[c.get('cls', 'O')], CLASS_TIPS[c.get('cls', 'O')])}</td>"
                           f"<td class=note>{E(tagtxt[:40])}</td><td class=note>{E(describe_header(c.get('hdr')))}</td><td class=n>{c.get('ntx', '-')}</td><td class=n>{len(c['outs'])}</td>"
                           f"<td class=n>{reward_total / 1e8:.4f}</td><td class=n>{max(fee, 0) / 1e8:.5f}</td></tr>")
        for x in sorted(rw.d["spends"], key=lambda x: -x["h"])[:12]:
            who = ", ".join(f"{E(k)} {v / 1e8:.3f}" for k, v in sorted(x["labels"].items(), key=lambda kv: -kv[1]))
            move_rows += (f"<tr><td class=t>{tt(x['t'], 'short')}</td><td class=n>{x['h']}</td><td>{who}</td><td class=n>{x['cb_sats'] / 1e8:.3f}</td>"
                          f"<td class=n>{x['n_cb']}</td><td class=n>{x['n_out']}</td><td>{tipped(x['kind'], KIND_TIPS.get(x['kind'], ''))}</td></tr>")
        groups = rw.wallet_groups()
        since = {}
        for c in rw.d["coinbases"].values():
            since[c["label"]] = since.get(c["label"], 0) + 1
        total_since = sum(since.values()) or 1
        wrows = []
        for g in groups:
            n24 = sum(1 for b in day if b["pool"] in g)
            nsf = sum(since.get(l, 0) for l in g)
            primary = max(g, key=lambda l: since.get(l, 0))
            wrows.append((n24, nsf, primary, sorted(g, key=lambda l: -since.get(l, 0))))
        wrows.sort(key=lambda r: (-r[0], -r[1]))
        for n24, nsf, primary, ls in wrows[:12]:
            others = ", ".join(E(l) for l in ls if l != primary)
            wallet_rows += (f"<tr><td>{E(primary)}</td><td class=note>{others or '-'}</td><td class=n>{n24}</td><td class=n>{100 * n24 / total:.1f}%</td>"
                            f"<td class=n>{nsf}</td><td class=n>{100 * nsf / total_since:.1f}%</td></tr>")
        multi = sum(1 for g in groups if len(g) > 1)
        overlap_text = (f"{len(groups)} wallets behind {sum(len(g) for g in groups)} labels; {multi} wallet(s) carry more than one label. "
                        "A pool that lets miners put their own tag in the coinbase shows up here as one wallet with many labels.")
        rw_note = (f"{len(rw.d['coinbases'])} coinbases indexed since height {DEFAULT_FLOOR}, {len(rw.d['spends'])} transactions have spent one. "
                   "Moved means a coinbase output was spent: a payout to miners, a consolidation, or a transfer out. "
                   "The chain shows movement, not a sale. Held is mined minus moved and includes immature rewards.")
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
.wrap {{ background: var(--card); border: 1px solid var(--rule); border-radius: 6px; }}
table {{ border-collapse: collapse; width: 100%; table-layout: fixed; }}
th, td {{ padding: .45rem .6rem; border-bottom: 1px solid var(--rule); text-align: left; vertical-align: top; overflow-wrap: break-word; }}
tr:last-child td {{ border-bottom: 0; }}
th {{ font-size: .78rem; text-transform: uppercase; letter-spacing: .04em; color: var(--mute); background: var(--paper); }}
td.n, th.n {{ text-align: right; font-variant-numeric: tabular-nums; }}
td.n {{ white-space: nowrap; }}
table.wide {{ table-layout: auto; }}
table.dense {{ font-size: .88rem; }}
table.dense th {{ font-size: .7rem; letter-spacing: .03em; }}
table.dense th, table.dense td {{ padding: .35rem .45rem; }}
td.t {{ font-variant-numeric: tabular-nums; }}
td.hi {{ background: var(--orange-tint); font-weight: 700; }}
table.hours th:first-child, table.hours td:first-child {{ width: 22%; }}
table.hours th:nth-child(2), table.hours td:nth-child(2) {{ width: 14%; }}
tr.na td {{ color: var(--mute); font-size: .9rem; padding-top: .25rem; padding-bottom: .25rem; }}
code {{ font: .88em ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; word-break: break-all; }}
[data-tip] {{ position: relative; }}
th [data-tip] {{ border-bottom: 1px dotted var(--mute); }}
td [data-tip] {{ border-bottom: 1px dotted var(--rule); }}
[data-tip]:hover::after, [data-tip]:focus::after {{ content: attr(data-tip); position: absolute; left: 0; top: calc(100% + .35rem); z-index: 9; width: 20rem; max-width: 80vw; white-space: normal; text-transform: none; letter-spacing: 0; font-weight: 400; font-size: .85rem; line-height: 1.45; color: var(--ink); background: var(--card); border: 1px solid var(--rule); border-radius: 6px; padding: .5rem .7rem; box-shadow: 0 6px 18px rgba(0, 0, 0, .22); }}
th.n [data-tip]:hover::after, th.n [data-tip]:focus::after, td.n [data-tip]:hover::after, td.n [data-tip]:focus::after {{ left: auto; right: 0; }}
.how li {{ margin: .3rem 0; }}
@media (max-width: 960px) {{
  table.wide, table.wide tbody, table.wide tr, table.wide td {{ display: block; width: 100%; }}
  table.wide tr.head {{ display: none; }}
  table.wide tr {{ border-bottom: 2px solid var(--rule); padding: .35rem 0; }}
  table.wide tr:last-child {{ border-bottom: 0; }}
  table.wide td {{ border: 0; padding: .12rem .6rem; text-align: left; white-space: normal; }}
  table.wide td.n {{ text-align: left; }}
  table.wide td::before {{ content: attr(data-l) ": "; color: var(--mute); }}
  table.wide td[colspan]::before, table.wide td:not([data-l])::before {{ content: ""; }}
}}
@media (max-width: 700px) {{
  table.stack, table.stack tbody, table.stack tr, table.stack td {{ display: block; width: 100%; }}
  table.stack tr.head {{ display: none; }}
  table.stack tr {{ border-bottom: 2px solid var(--rule); padding: .35rem 0; }}
  table.stack tr:last-child {{ border-bottom: 0; }}
  table.stack td {{ border: 0; padding: .12rem .6rem; text-align: left; white-space: normal; }}
  table.stack td.n {{ text-align: left; }}
  table.stack td::before {{ content: attr(data-l) ": "; color: var(--mute); }}
  table.stack td[colspan]::before, table.stack td:not([data-l])::before {{ content: ""; }}
  table.hours {{ font-size: .85rem; }}
  [data-tip]:hover::after, [data-tip]:focus::after {{ left: 0; right: auto; }}
}}
</style>
</head>
<body>
<header><div class="bar">{knot}<div><h1>Bitcoin Knots reorg watch</h1>
<p class="sub">Chain reorganizations and pool shares on the BLAKE2b chain, from one Bitcoin Knots node. Generated {tt(now)}. Times are shown in your browser's time zone, <span class="tzname">{E(tsz(now, "%Z"))}</span> right now.</p></div></div></header>
<main>
<div id="stale">This page is more than 15 minutes old. The generator or the upload has stopped; treat everything below as stale.</div>

<div class="cards">
<div class="card"><div class="k">{tipped("Node", TIPS["node"])}</div><div class="v {node_state[0]}">{E(node_state[1])}</div></div>
<div class="card"><div class="k">{tipped("Explorer", TIPS["explorer"])}</div><div class="v {agree[0]}">{ex_link if ex else ""} {E(agree[1])}</div></div>
<div class="card"><div class="k">{tipped("Reorgs, 24 h", TIPS["reorgs"])}</div><div class="v">{E(depth_counts(86400))}</div></div>
<div class="card"><div class="k">{tipped("Reorgs, 7 d", TIPS["reorgs"])}</div><div class="v">{E(depth_counts(7 * 86400))}</div></div>
<div class="card"><div class="k">{tipped("Last alert", TIPS["last_alert"])}</div><div class="v">{last_alert}</div></div>
<div class="card"><div class="k">{tipped("Tip", TIPS["tip"])}</div><div class="v">{tip_h}<br>{tip_html}</div></div>
</div>

<h2>Blocks by pool, last 24 hours</h2>
<p class="note">{len(day)} blocks. Pools are named from the coinbase payout address, then the coinbase tag, using <a href="{POOLS_REPO}">Kilombino's pool list</a>. Both are chosen by the miner, so treat names as claims. Shares are block counts and carry a few points of noise.</p>
<div class="wrap"><table class="stack">
<tr>{th("Pool", "pool", width="34%")}{th("Blocks", "blocks24", "n", "14%")}{th("Share", "share24", "n", "14%")}{th("Template built by", "builder")}</tr>
{rows_shares()}
</table></div>

<h2>By hour, <span class="tzname">{E(tsz(now, "%Z"))}</span></h2>
<p class="note">Most recent hour first. Share of that hour's blocks for the three largest pools of the day. Cells at or above half are marked.</p>
<div class="wrap"><table class="hours">
<tr>{th("Hour", "hour")}{th("Blocks", "blocks24", "n")}{hour_heads}</tr>
{rows_hours()}
</table></div>

<h2>Reward flow since the fork</h2>
<p class="note">{rw_note or "Reward index disabled."}</p>
<div class="wrap"><table class="stack wide dense">
<tr>{th("Pool", "pool")}{th("Blocks", "blocks_fork", "n")}{th("Template built by", "builder")}{th("Coinbase payout", "payout")}{th("Mined BTC", "mined", "n")}{th("Matured", "matured", "n")}{th("Moved", "moved", "n")}{th("Moved / matured", "moved_pct", "n")}{th("Held", "held", "n")}{th("Last movement", "last_move")}</tr>
{reward_rows or "<tr><td colspan=10 class=note>none</td></tr>"}
</table></div>
<p class="note"><strong>Template built by</strong> comes from the coinbase layout the DATUM gateway writes. <em>DATUM pool</em>: the miner's own gateway and node built the block; the pool only coordinated payout. <em>Gateway, stratum v1</em>: the gateway software running standalone, so the node of whoever owns the payout address built the block; for a pool label that is the pool. <em>Other</em>: software this page does not recognize. <strong>Coinbase payout</strong> is how the reward leaves the block: one output kept by the pool and paid out later, two outputs, or paid directly to miners in the coinbase.</p>

<h2>Latest blocks</h2>
<div class="wrap"><table class="stack wide dense">
<tr>{th("Height", "height", "n")}{th("Time", "time")}{th("Pool", "pool")}{th("Template built by", "builder")}{th("Coinbase tags", "tags")}{th("Header", "hdr")}{th("Txs", "txs", "n")}{th("Outputs", "outputs", "n")}{th("Reward BTC", "reward", "n")}{th("Fees BTC", "fees", "n")}</tr>
{block_rows or "<tr><td colspan=9 class=note>none</td></tr>"}
</table></div>

<h2>Blocks by wallet</h2>
<p class="note">Labels merged when they pay the same pool address or their pool addresses are spent together. This is the label-independent view: what one operator's wallet actually collected. {overlap_text}</p>
<div class="wrap"><table class="stack">
<tr>{th("Wallet", "wallet", width="18%")}{th("Other labels in this wallet", "wallet_labels")}{th("Blocks 24 h", "wallet24", "n", "11%")}{th("Share 24 h", "share24", "n", "11%")}{th("Since fork", "wallet_fork", "n", "11%")}{th("Share", "wallet_fork", "n", "11%")}</tr>
{wallet_rows or "<tr><td colspan=6 class=note>none</td></tr>"}
</table></div>

<h2>Recent reward movements</h2>
<p class="note">Latest transactions spending coinbase outputs. Payout means three or more outputs, sweep means several rewards into one or two outputs, transfer means one reward to one or two outputs.</p>
<div class="wrap"><table class="stack">
<tr>{th("Time", "time", width="17%")}{th("Height", "height", "n", "9%")}{th("Pool (BTC)", "mv_pool")}{th("BTC", "mv_btc", "n", "10%")}{th("Rewards in", "mv_in", "n", "10%")}{th("Outputs", "mv_out", "n", "9%")}{th("Shape", "shape", width="11%")}</tr>
{move_rows or "<tr><td colspan=7 class=note>none yet</td></tr>"}
</table></div>

<h2>Recent events</h2>
<p class="note">Depth-1 reorgs are ordinary ties between two blocks found seconds apart. Depth 2 and deeper, explorer disagreement, and a node that has fallen behind are alerts.</p>
<div class="wrap"><table class="stack">
<tr>{th("Time", "time", width="20%")}{th("Level", "level", width="10%")}{th("Event", "event")}</tr>
{rows_events()}
</table></div>
<h2>How this page decides</h2>
<ul class="how">
<li><strong>Reorgs.</strong> {E(TIPS["reorgs"])}</li>
<li><strong>Explorer check.</strong> {E(TIPS["explorer"])}</li>
<li><strong>Pool names.</strong> {E(TIPS["pool"])}</li>
<li><strong>Template built by.</strong> {E(TIPS["builder"])}</li>
<li><strong>Coinbase payout.</strong> {E(TIPS["payout"])}</li>
<li><strong>Moved and held.</strong> {E(TIPS["moved"])} {E(TIPS["held"])}</li>
<li><strong>Wallets.</strong> {E(TIPS["wallet"])}</li>
<li><strong>Movement shapes.</strong> {E(TIPS["shape"])}</li>
<li><strong>Header fields.</strong> {E(TIPS["hdr"])}</li>
<li><strong>Alerts.</strong> {E(TIPS["last_alert"])}</li>
</ul>
</main>
<footer>Produced by <a href="{REPO_URL}">reorg-watch</a>, an independent monitor. Not affiliated with the Bitcoin Knots project. One node's view, cross-checked once a minute against {ex_link}, whose explorer also has the block-by-block detail. Pool names from <a href="{POOLS_REPO}">Kilombino's pool list</a>. Window {len(st.get('chain', {}))} heights.</footer>
<script>
(function () {{
  var gen = 1000 * parseInt(document.querySelector('.sub time[data-epoch]').getAttribute('data-epoch'), 10);
  if (!isNaN(gen) && Date.now() - gen > 15 * 60 * 1000) document.getElementById('stale').style.display = 'block';
  // Re-render every timestamp in the viewer's own time zone; the server text stays as the fallback.
  var pad = function (n) {{ return (n < 10 ? '0' : '') + n; }};
  var zone = '';
  try {{
    var parts = new Intl.DateTimeFormat(undefined, {{ timeZoneName: 'short' }}).formatToParts(new Date());
    for (var i = 0; i < parts.length; i++) if (parts[i].type === 'timeZoneName') zone = parts[i].value;
  }} catch (e) {{}}
  var els = document.querySelectorAll('time[data-epoch]');
  for (var j = 0; j < els.length; j++) {{
    var el = els[j], d = new Date(1000 * parseInt(el.getAttribute('data-epoch'), 10));
    if (isNaN(d.getTime())) continue;
    var Y = d.getFullYear(), M = pad(d.getMonth() + 1), D = pad(d.getDate()), h = pad(d.getHours()), m = pad(d.getMinutes()), s = pad(d.getSeconds());
    var f = el.getAttribute('data-fmt'), out;
    if (f === 'full') out = Y + '-' + M + '-' + D + ' ' + h + ':' + m + ':' + s + (zone ? ' ' + zone : '');
    else if (f === 'minute') out = Y + '-' + M + '-' + D + ' ' + h + ':' + m;
    else if (f === 'clock') out = h + ':' + m + ':' + s;
    else if (f === 'short') out = M + '-' + D + ' ' + h + ':' + m;
    else if (f === 'hour') out = h + ':' + m;
    if (out) el.textContent = out;
  }}
  if (zone) {{ var zs = document.querySelectorAll('.tzname'); for (var k = 0; k < zs.length; k++) zs[k].textContent = zone; }}
}})();
</script>
</body>
</html>
"""
    page = stackable(page)
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
    rw_path = os.path.join(sd, "rewards.json")
    if os.path.exists(rw_path):
        rw = Rewards(sd)
        print(f"rewards: {len(rw.d['coinbases'])} coinbases indexed to {rw.d['scanned_to']}, {len(rw.d['spends'])} spending txs, "
              f"named-label overlaps {len(rw.overlaps())}")
        for label, p in rw.summary(st.get("tip_height", 0))[:8]:
            print(f"  {label[:22]:22s} blocks {p['blocks']:5d}  mined {p['mined'] / 1e8:9.3f}  moved {p['moved'] / 1e8:9.3f}  "
                  f"held {(p['mined'] - p['moved']) / 1e8:9.3f}  last {ts(p['last_t']) if p['last_t'] else '-'}")
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
    ap.add_argument("--no-rewards", action="store_true")
    ap.add_argument("--tz", default="UTC", help="time zone for the status page, e.g. America/New_York")
    ap.add_argument("--sweep-btc", type=float, default=10.0)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    global PAGE_TZ
    try:
        PAGE_TZ = ZoneInfo(args.tz)
    except Exception:  # noqa: BLE001
        print(f"{ts()} unknown time zone {args.tz!r}, using UTC")

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
        if not args.no_rewards:
            rw = Rewards(sd)
            chain0 = {int(k): v for k, v in st["chain"].items()}
            rw.sync(rest, pools, chain0, st["blocks"], st["tip_height"], None, args.floor, 0, args.verbose)
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

    if not args.no_rewards:
        try:
            rw = Rewards(sd)
            events += rw.sync(rest, pools, chain, st["blocks"], top, ancestor if depth > 0 else None, args.floor,
                              int(args.sweep_btc * 1e8), args.verbose)
        except Exception as e:  # noqa: BLE001
            print(f"{ts()} reward index failed: {e}")

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
