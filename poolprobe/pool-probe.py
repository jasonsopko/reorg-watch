#!/usr/bin/env python3
"""pool-probe.py - ask a mining pool's advertised endpoint what protocol it speaks.

Opens one connection per endpoint, sends the Stratum v1 mining.subscribe handshake,
records what comes back (the first job included), and disconnects. That is the
opening exchange any miner makes against a public endpoint, once per run. It never
submits a share. When the caller passes authorize=<user>, and only then, it also
sends one mining.authorize with that throwaway worker after the subscribe and
records the answer and whether jobs keep coming: the survey does this on ports a
pool's own site calls closed, to see whether the pool still takes workers, and,
with authorize_if_idle, on any port that answers the subscribe without a job, since
some servers send work only to an authorized worker.

What a result means: this shows what a pool OFFERS, not how any particular block was
built. A pool can offer both Stratum v1 and DATUM. "Speaks v1" is evidence; "only
advertises v1" is the finding worth reporting.

Usage: pool-probe.py [--endpoints FILE] [--out FILE] [--label NAME] [--delay S]
                     [--timeout S] [--ua STRING] [--dry-run] [--quiet]

  --endpoints FILE  endpoint list (default pool-endpoints.json next to this script)
  --out FILE        append JSONL results here (default probe-log.jsonl)
  --label NAME      probe only this pool label (repeatable)
  --delay S         seconds between endpoints, default 2
  --timeout S       connect and read timeout, default 10
  --ua STRING       user agent sent in mining.subscribe
  --dry-run         print what would be probed and exit
"""

import argparse, json, os, re, socket, ssl, sys, time
from datetime import datetime, timezone

DEFAULT_UA = "reorg.watch-probe/0.1 (protocol survey; contact via reorg.watch)"
NOTIFY_METHOD = re.compile(rb'"method"\s*:\s*"mining\.notify"')


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_endpoint(ep):
    """Accept {'url': 'stratum+tcp://host:port'} or {'host':..,'port':..,'tls':..}."""
    url = (ep.get("url") or "").strip()
    host, port, tls = ep.get("host", ""), int(ep.get("port") or 0), bool(ep.get("tls"))
    if url:
        scheme, _, rest = url.partition("://")
        if not rest:
            rest, scheme = url, "stratum+tcp"
        tls = tls or scheme in ("stratum+ssl", "stratum+tls", "ssl", "tls")
        h, _, p = rest.rstrip("/").rpartition(":")
        if h:
            host, port = h, int(p)
        else:
            host = rest
    return host.strip(), port, tls


def sia_coinb1_commitment(coinb1_hex):
    """BLAKE2b jobs do not carry a coinbase. datum_pow.c:172 builds a 39-byte
    'sia coinb1': 3 zero bytes, the 32-byte header commitment, 4 zero bytes."""
    try:
        b = bytes.fromhex(coinb1_hex)
    except Exception:
        return None
    if len(b) != 39 or b[0:3] != b"\x00" * 3 or b[35:39] != b"\x00" * 4:
        return None
    return b[3:35].hex()


def sia_prevhash_for(blockhash_display_hex):
    """datum_pow.c:178 - tagged hash of the block hash, first 6 bytes zeroed."""
    import hashlib
    t = hashlib.sha256(b"Bitcoin prevblock header, hashed").digest()
    out = bytearray(hashlib.sha256(t + t + bytes.fromhex(blockhash_display_hex)).digest())
    out[:6] = b"\x00" * 6
    return bytes(out).hex()


def resolve_prevhash(observed, rest_base, depth):
    """Which block of OUR chain is this job built on? None means not our chain."""
    import urllib.request
    def j(path):
        return json.loads(urllib.request.urlopen(rest_base + "/" + path, timeout=10).read())
    try:
        tip = j("chaininfo.json")["blocks"]
    except Exception:
        return None
    for h in range(tip, max(0, tip - depth), -1):
        try:
            bh = j("blockhashbyheight/%d.json" % h)["blockhash"]
        except Exception:
            break
        if sia_prevhash_for(bh) == observed:
            return {"height": h, "blockhash": bh, "behind_tip": tip - h}
    return None


def _varint(b, i):
    n = b[i]
    if n < 0xfd: return n, i + 1
    if n == 0xfd: return int.from_bytes(b[i+1:i+3], "little"), i + 3
    if n == 0xfe: return int.from_bytes(b[i+1:i+5], "little"), i + 5
    return int.from_bytes(b[i+1:i+9], "little"), i + 9


def coinbase_outputs(coinb1, coinb2, extranonce1, en2_size):
    """Rebuild the coinbase the pool is handing out and read its outputs.

    coinb1 + extranonce1 + extranonce2 + coinb2 is the full coinbase serialization;
    a zero extranonce2 is fine because only the scriptSig bytes change."""
    try:
        raw = bytes.fromhex(coinb1 + (extranonce1 or "") + "00" * int(en2_size or 0) + coinb2)
        i = 4                                    # version
        if raw[i] == 0 and raw[i+1] == 1:        # segwit marker/flag
            i += 2
        nin, i = _varint(raw, i)
        for _ in range(nin):
            i += 36                              # prevout
            slen, i = _varint(raw, i)
            sig = raw[i:i+slen]
            i += slen + 4                        # scriptSig + sequence
        nout, i = _varint(raw, i)
        outs = []
        for _ in range(nout):
            value = int.from_bytes(raw[i:i+8], "little"); i += 8
            slen, i = _varint(raw, i)
            outs.append({"value_sats": value, "scriptPubKey": raw[i:i+slen].hex()})
            i += slen
        tag = "".join(chr(c) if 32 <= c < 127 else "." for c in sig)
        return {"outputs": outs, "n_outputs": len(outs),
                "coinbase_scriptsig_hex": sig.hex(), "coinbase_text": tag}
    except Exception:
        return None


def fingerprint(sub_line, configure_reply):
    """Name the server software from the shape of its mining.subscribe reply.

    Signatures taken from each project's own source:
      datum_gateway   datum_stratum.c:1925  "[[[notify,<sid>1],[set_difficulty,<sid>2]],<sid>,8]"
      miningcore      BitcoinPool.cs:56     "[[[set_difficulty,<cid>],[notify,<cid>]],...]"
      node-stratum    lib/stratum.js:105    same shape as miningcore, key order id/result/error
      ckpool          stratifier.c:5826     "[[[notify,<8hex sid>]],<enonce1>,<n2len>]"
      public-pool     StratumV1Client.spec  "[[[notify,<en+sid>]],<en+sid>,8]", key order id/error/result
    """
    try:
        msg = json.loads(sub_line)
        res = msg["result"]
        entries, en1 = res[0], res[1]
    except Exception:
        return "unparsed", ""
    names = [e[0] for e in entries if isinstance(e, list) and e]
    ids = [e[1] for e in entries if isinstance(e, list) and len(e) > 1]
    order = [k for k in msg.keys()]
    answers_min_diff = isinstance(configure_reply, dict) and "minimum-difficulty" in configure_reply
    answers_vroll = isinstance(configure_reply, dict) and "version-rolling" in configure_reply

    if names == ["mining.notify", "mining.set_difficulty"] and len(ids) == 2:
        sid = ids[0][:-1]
        if ids[0] == sid + "1" and ids[1] == sid + "2":
            if en1 == sid and answers_min_diff:
                return "datum_gateway", "stock: format and mining.configure both match"
            if en1 != sid and answers_min_diff:
                return "datum_gateway (fork)", "widened extranonce1 (%d hex vs 8)" % len(en1)
            if configure_reply is None or configure_reply == "(silent)":
                return "gateway-shaped reply, no mining.configure", "stock datum_gateway always answers mining.configure; this endpoint does not"
            return "datum_gateway (variant)", "configure reply differs"
    if names == ["mining.set_difficulty", "mining.notify"] and len(set(ids)) == 1:
        fam = "miningcore/node-stratum family"
        if order[:1] == ["result"] and answers_vroll:
            fam = "miningcore (likely)"
        return fam, "one id for both subscriptions, set_difficulty first"
    if names == ["mining.notify"] and len(entries) == 1:
        if en1 == ids[0]:
            return "public-pool (likely)", "single notify subscription, id == extranonce1"
        return "ckpool or custom", "single notify subscription, id %r" % (ids[0],)
    return "unknown", ""


def classify(lines, raw, opened, err):
    """What did the far end sound like? Reads every line before deciding."""
    if err:
        return err, {}
    if not raw:
        return ("no-response" if opened else "no-connection"), {}

    facts, msgs, saw_json = {}, [], False
    for ln in lines:
        try:
            msgs.append(json.loads(ln))
            saw_json = True
        except Exception:
            continue

    verdict = None
    for msg in msgs:                                  # the mining.configure reply, if we sent one
        if msg.get("id") == 0:
            facts["configure_reply"] = msg.get("result", msg.get("error"))
            verdict = "stratum-v1"
    for msg in msgs:                                  # the subscribe reply first:
        if msg.get("id") == 1 and isinstance(msg.get("result"), list):
            res = msg["result"]
            if len(res) >= 3:
                facts["extranonce1"] = res[1]
                facts["extranonce2_size"] = res[2]
            if res and isinstance(res[0], list):
                facts["subscriptions"] = [x[0] for x in res[0] if isinstance(x, list) and x]
            verdict = "stratum-v1"
        elif msg.get("id") == 1 and msg.get("error"):
            facts["error"] = msg["error"]
            verdict = verdict or "stratum-v1 (subscribe refused)"

    for msg in msgs:                                  # then anything it pushed at us
        m = msg.get("method", "")
        if not (isinstance(m, str) and m.startswith("mining.")):
            continue
        facts.setdefault("unsolicited", []).append(m)
        verdict = verdict or "stratum-v1"
        if m == "mining.set_difficulty":
            facts["initial_difficulty"] = (msg.get("params") or [None])[0]
        elif m == "mining.notify":
            pr = msg.get("params") or []
            if len(pr) >= 9:
                facts["job"] = {"job_id": pr[0], "prevhash": pr[1],
                                "merkle_branches": len(pr[4]) if isinstance(pr[4], list) else None,
                                "version": pr[5], "nbits": pr[6], "ntime": pr[7],
                                "clean_jobs": pr[8]}
                cb = coinbase_outputs(pr[2], pr[3], facts.get("extranonce1", ""),
                                      facts.get("extranonce2_size", 0))
                if cb:
                    facts["template_outputs"] = cb
                else:
                    commit = sia_coinb1_commitment(pr[2])
                    if commit:
                        facts["blake2b_commitment"] = commit
                        facts["work_format"] = "BLAKE2b sia coinb1 (datum_pow.c:172)"
                    facts["job"]["coinb1"] = pr[2]
                    facts["job"]["coinb2"] = pr[3]
                    facts["job"]["merkle_branch"] = pr[4]

    if verdict:
        return verdict, facts
    if saw_json:
        return "json-rpc, not Stratum v1", facts
    printable = sum(1 for b in raw[:64] if 9 <= b < 127)
    facts["first_bytes_hex"] = raw[:32].hex()
    return ("text, not JSON" if printable > 48 else "binary (not Stratum v1)"), facts


def authorize_facts(lines, closed):
    """What came back after mining.authorize: the reply, any client.show_message,
    and how many jobs followed."""
    out = {"result": None, "error": None, "messages": [], "jobs_after": 0, "closed": closed}
    seen_reply = False
    for ln in lines:
        try:
            msg = json.loads(ln)
        except Exception:
            continue
        if msg.get("id") == 2:
            out["result"] = msg.get("result")
            out["error"] = msg.get("error")
            seen_reply = True
        m = msg.get("method")
        if m == "client.show_message":
            out["messages"].append(str((msg.get("params") or [""])[0])[:200])
        elif m == "mining.notify" and seen_reply:
            out["jobs_after"] += 1
        elif m == "client.reconnect":
            out["messages"].append("client.reconnect " + json.dumps(msg.get("params"))[:120])
    return out


def subscribed_without_job(raw):
    """True when the subscribe was answered and no mining.notify came with it."""
    answered = False
    for ln in raw.decode("utf-8", "replace").split("\n"):
        try:
            msg = json.loads(ln)
        except Exception:
            continue
        if not isinstance(msg, dict):
            continue
        if msg.get("method") == "mining.notify":
            return False
        if msg.get("id") == 1 and isinstance(msg.get("result"), list):
            answered = True
    return answered


def probe(host, port, tls, timeout, ua, min_diff=None, authorize=None, authorize_if_idle=False):
    rec = {"host": host, "port": port, "tls": tls, "probed_at": now(), "configure_min_diff": min_diff}
    t0 = time.monotonic()
    sock = None
    opened = False
    raw = b""
    err = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        opened = True
        rec["connect_ms"] = round((time.monotonic() - t0) * 1000, 1)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        if min_diff is not None:
            cfg = json.dumps({"id": 0, "method": "mining.configure",
                              "params": [["minimum-difficulty"],
                                         {"minimum-difficulty.value": min_diff}]}) + "\n"
            sock.sendall(cfg.encode())
        req = json.dumps({"id": 1, "method": "mining.subscribe", "params": [ua]}) + "\n"
        sock.sendall(req.encode())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and len(raw) < 65536:
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            raw += chunk
            if b"\n" in raw and rec.get("first_byte_ms") is None:
                rec["first_byte_ms"] = round((time.monotonic() - t0) * 1000, 1)
            # keep reading until a COMPLETE mining.notify line is in hand: it carries
            # the template the pool built, which is what links an endpoint to a payout.
            # The subscribe reply names mining.notify too, so match the method, and give
            # the job a few seconds after that reply before calling the port idle.
            job = NOTIFY_METHOD.search(raw)
            if job and raw.rfind(b"\n") > job.start():
                break
            if raw.count(b"\n") >= 6:
                break
            if subscribed_without_job(raw[:raw.rfind(b"\n") + 1]):
                deadline = min(deadline, time.monotonic() + 3)
        if authorize and raw and (not authorize_if_idle or subscribed_without_job(raw)):
            req = json.dumps({"id": 2, "method": "mining.authorize", "params": [authorize, "x"]}) + "\n"
            sock.sendall(req.encode())
            rec["authorize_sent"] = authorize
            mark = len(raw)
            closed_after = False
            # Wait for the answer and a job, a refusal, or the deadline: some servers take
            # a few seconds to send the first job, and stopping at the first quiet moment
            # read a slow pool as handing out no work.
            deadline = time.monotonic() + min(timeout, 8)
            while time.monotonic() < deadline and len(raw) < 131072:
                sock.settimeout(max(0.1, deadline - time.monotonic()))
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    closed_after = True
                    break
                raw += chunk
                msgs = []
                for l in raw[mark:].decode("utf-8", "replace").split("\n"):
                    try:
                        m = json.loads(l)
                    except Exception:
                        continue
                    if isinstance(m, dict):
                        msgs.append(m)
                reply = next((m for m in msgs if m.get("id") == 2), None)
                job = any(m.get("method") == "mining.notify" for m in msgs)
                if reply is not None and (job or reply.get("result") is not True):
                    break
            after = [l for l in raw[mark:].decode("utf-8", "replace").split("\n") if l.strip()]
            rec["authorize"] = authorize_facts(after, closed_after)
    except socket.gaierror as e:
        err = f"dns-failure ({e.strerror or e})"
    except ConnectionRefusedError:
        err = "refused"
    except socket.timeout:
        err = "connect-timeout" if not opened else "read-timeout"
    except ssl.SSLError as e:
        err = f"tls-error ({e.reason or 'unknown'})"
    except OSError as e:
        err = f"socket-error ({e.strerror or e})"
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    lines = [l for l in raw.decode("utf-8", "replace").split("\n") if l.strip()]
    verdict, facts = classify(lines, raw, opened, err)
    if rec.get("authorize"):
        facts["authorize"] = rec.pop("authorize")
    rec["verdict"] = verdict
    rec["facts"] = facts
    rec["reply_lines"] = lines[:4]
    rec["bytes"] = len(raw)
    return rec


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--endpoints", default=os.path.join(here, "pool-endpoints.json"))
    ap.add_argument("--out", default=os.path.join(here, "probe-log.jsonl"))
    ap.add_argument("--label", action="append", default=[])
    ap.add_argument("--delay", type=float, default=2.0)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--ua", default=DEFAULT_UA)
    ap.add_argument("--min-diff", type=float, default=1.0,
                    help="minimum-difficulty to request in mining.configure; 'none' to skip")
    ap.add_argument("--rest", default="http://127.0.0.1:8332/rest",
                    help="local node REST base, to resolve which block a job is built on")
    ap.add_argument("--depth", type=int, default=25)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    doc = json.load(open(args.endpoints))
    targets = []
    for p in doc.get("pools", []):
        if args.label and p["label"] not in args.label:
            continue
        for ep in p.get("endpoints", []):
            host, port, tls = parse_endpoint(ep)
            if not host or not port:
                continue
            targets.append((p["label"], host, port, tls, ep.get("source", "")))

    if not targets:
        print("no endpoints with a host and port; fill in pool-endpoints.json", file=sys.stderr)
        return 1
    if args.dry_run:
        for lab, host, port, tls, src in targets:
            print("would probe %-20s %s:%d%s  [%s]" % (lab, host, port, " tls" if tls else "", src))
        return 0

    results = []
    with open(args.out, "a") as log:
        for i, (lab, host, port, tls, src) in enumerate(targets):
            rec = probe(host, port, tls, args.timeout, args.ua, args.min_diff)
            ph = (rec["facts"].get("job") or {}).get("prevhash")
            if ph:
                rec["built_on"] = resolve_prevhash(ph, args.rest.rstrip("/"), args.depth)
            rec["label"] = lab
            rec["source"] = src
            log.write(json.dumps(rec) + "\n")
            log.flush()
            results.append(rec)
            if not args.quiet:
                extra = ""
                f = rec["facts"]
                if "extranonce2_size" in f:
                    extra = "  en2=%s en1=%s" % (f["extranonce2_size"], str(f.get("extranonce1"))[:16])
                if "initial_difficulty" in f:
                    extra += "  diff=%s" % f["initial_difficulty"]
                if "configure_reply" in f:
                    extra += "  configure=%s" % json.dumps(f["configure_reply"])[:40]
                if rec.get("built_on"):
                    extra += "  on h=%d(-%d)" % (rec["built_on"]["height"], rec["built_on"]["behind_tip"])
                elif f.get("blake2b_commitment"):
                    extra += "  NOT-OUR-CHAIN"
                print("%-20s %-34s %-32s%s" % (lab, "%s:%d%s" % (host, port, "+tls" if tls else ""),
                                               rec["verdict"], extra))
            if i + 1 < len(targets):
                time.sleep(args.delay)

    if not args.quiet:
        print("\n%d probed, %d spoke Stratum v1, log %s"
              % (len(results), sum(1 for r in results if r["verdict"].startswith("stratum-v1")), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
