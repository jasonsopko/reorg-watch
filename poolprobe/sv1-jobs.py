#!/usr/bin/env python3
"""sv1-jobs.py - which public stratum port built a block.

Keeps one subscribed, never-submitting client on every public stratum v1 port the pool
survey saw handing out work for this chain, remembers every job each port hands out, and
checks each new block of our chain against them. A BLAKE2b job carries no coinbase, only
the 32-byte header commitment (datum_pow.c:172, bytes 3-35 of "coinb1"), and that same
commitment is computable from any block's 164-byte header (hdrv2.h2). A block whose
commitment a port handed out was built by the node behind that port: the pool's own, not a
miner's.

The commitment covers the coinbase, and the gateway writes the hasher's difficulty tier
into the coinbase (the byte before its unique id), so a port's jobs differ by tier and this
client sees only the tier it is on. The gateway starts a client at its opening difficulty
and halves it every eighty seconds or so while no share comes in, so an idle client walks
down through the tiers small miners find blocks on and then sits below them; the client
therefore reconnects every --recycle-min minutes to walk them again. One match is enough:
it names the gateway's coinbase identity (its tags, unique id and the pool's session id),
and every block with that identity is the port's, whatever tier found it, until the gateway
reconnects to its pool and the next match learns the new session.

State, in the reorg-watch directory:
  sv1-port-blocks.jsonl      one line per matched block
  sv1-port-identities.json   the coinbase identities learned from matches; cesspool reads it
  sv1-jobs-status.json       per-port connection state, rewritten every minute

Usage: sv1-jobs.py [--survey FILE] [--endpoints FILE] [--state-dir DIR] [--rest URL]
                   [--keep-min N] [--recycle-min N] [--only LABEL ...] [--verbose]
"""

import argparse, importlib.util, json, os, socket, ssl, sys, threading, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
SD = os.path.expanduser("~/.reorg-watch")
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "forktips"))
import hdrv2  # noqa: E402

UA = "reorg.watch-probe/0.1 (protocol survey; contact via reorg.watch)"
HEADER_SIZE = 164
POLL_S = 3            # chain tip
STATUS_S = 60
RELOAD_S = 3600       # endpoint list
BACKOFF_MIN, BACKOFF_MAX = 30, 900
READ_TIMEOUT = 20
JOB_WAIT_S = 8        # after the subscribe reply, before authorizing to coax a job out
LOOKBACK = 8          # headers checked when the tip moves


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg):
    print(f"{now()} {msg}", flush=True)


def probe_module():
    spec = importlib.util.spec_from_file_location("pool_probe", os.path.join(HERE, "pool-probe.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def worker_name(path):
    """The survey's throwaway worker (pool-survey.py probe_worker): a keyless address plus a name
    that says who is asking. Only sent to a port that answers the subscribe without a job."""
    try:
        return json.load(open(path))["username"]
    except Exception:  # noqa: BLE001
        return None


def script_pushes(sig):
    """Data pushes of a scriptSig, None for a non-push opcode."""
    out, i, n = [], 0, len(sig)
    while i < n:
        op = sig[i]
        i += 1
        if op < 0x4c:
            size = op
        elif op == 0x4c and i < n:
            size, i = sig[i], i + 1
        elif op == 0x4d and i + 1 < n:
            size, i = int.from_bytes(sig[i:i + 2], "little"), i + 2
        elif op == 0x4e and i + 3 < n:
            size, i = int.from_bytes(sig[i:i + 4], "little"), i + 4
        else:
            out.append(None)
            continue
        out.append(sig[i:i + size])
        i += size
    return out


def coinbase_identity(sig):
    """(primary tag, secondary tag, unique-id bytes after the difficulty byte) from the coinbase
    layout the DATUM gateway writes with a pool upstream: height push, tag push, unique-id push.
    None when the layout is not that."""
    p = script_pushes(sig)
    if len(p) < 3 or not p[1] or not p[2] or p[1][-1] != 0 or len(p[2]) < 7:
        return None
    parts = p[1].rstrip(b"\x00").split(b"\x0f")
    primary = parts[0].decode("utf-8", "replace")
    secondary = parts[1].decode("utf-8", "replace") if len(parts) > 1 else ""
    return primary, secondary, p[2][1:].hex()


# ---------------------------------------------------------------------------
# endpoints

def load_endpoints(survey_path, endpoints_path, only):
    """Ports the last survey saw speaking stratum v1 with work for this chain: [{label, host, port, tls}]."""
    pp = probe_module()
    tls_for = {}
    try:
        for p in json.load(open(endpoints_path)).get("pools", []):
            for ep in p.get("endpoints", []):
                host, port, tls = pp.parse_endpoint(ep)
                if host and port:
                    tls_for[f"{host}:{port}"] = tls
    except Exception as e:  # noqa: BLE001
        log(f"endpoint list unreadable: {e}")
    out, seen = [], set()
    try:
        rows = json.load(open(survey_path)).get("pools", [])
    except Exception as e:  # noqa: BLE001
        log(f"survey unreadable: {e}")
        return out
    for r in rows:
        label = r.get("label")
        if not label or (only and label not in only):
            continue
        for e in r.get("endpoints", []):
            key = e.get("endpoint", "")
            if e.get("verdict") != "stratum-v1" or e.get("chain") != "this" or key in seen:
                continue
            host, _, port = key.rpartition(":")
            if not host or not port.isdigit():
                continue
            seen.add(key)
            out.append({"label": label, "host": host, "port": int(port), "tls": tls_for.get(key, False), "key": key})
    return out


# ---------------------------------------------------------------------------
# jobs

class Jobs:
    """commitment -> (label, endpoint, seen, job_id), pruned past keep seconds."""

    def __init__(self, keep):
        self.keep = keep
        self.d = {}
        self.lock = threading.Lock()

    def add(self, commitment, label, key, job_id):
        with self.lock:
            self.d[commitment] = (label, key, time.time(), job_id)

    def get(self, commitment):
        with self.lock:
            return self.d.get(commitment)

    def prune(self):
        cut = time.time() - self.keep
        with self.lock:
            for c in [c for c, v in self.d.items() if v[2] < cut]:
                del self.d[c]
            return len(self.d)


class Port(threading.Thread):
    """One client on one port, reconnecting for as long as the port is on the list."""

    def __init__(self, ep, jobs, worker, recycle, verbose):
        super().__init__(daemon=True, name=ep["key"])
        self.ep, self.jobs, self.worker, self.recycle, self.verbose = ep, jobs, worker, recycle, verbose
        self.stop = threading.Event()
        self.state = {"label": ep["label"], "endpoint": ep["key"], "connected": False, "since": None,
                      "jobs": 0, "last_job": None, "diff": None, "last_error": None, "sessions": 0}

    def run(self):
        backoff = BACKOFF_MIN
        while not self.stop.is_set():
            t0 = time.time()
            try:
                why = self.session()
                err = None
            except Exception as e:  # noqa: BLE001
                why, err = "error", f"{type(e).__name__}: {e}"
            self.state.update(connected=False, since=None)
            if self.stop.is_set():
                break
            lasted = time.time() - t0
            if err:
                self.state["last_error"] = f"{now()} {err}"
            if why == "recycled":
                wait = 5
            else:
                # A session that held for a while was a working one; start the backoff over.
                backoff = BACKOFF_MIN if lasted > 600 else min(BACKOFF_MAX, backoff * 2)
                wait = backoff
            if self.verbose or err:
                log(f"{self.ep['key']} ({self.ep['label']}) session ended after {lasted:.0f}s: {err or why}; retry in {wait}s")
            self.stop.wait(wait)

    def session(self):
        """One connection, until the port closes it, the recycle time is up, or something fails."""
        ep = self.ep
        t_start = time.time()
        sock = socket.create_connection((ep["host"], ep["port"]), timeout=15)
        try:
            if ep["tls"]:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=ep["host"])
            sock.settimeout(READ_TIMEOUT)
            sock.sendall((json.dumps({"id": 1, "method": "mining.subscribe", "params": [UA]}) + "\n").encode())
            self.state.update(connected=True, since=now(), sessions=self.state["sessions"] + 1)
            buf = b""
            subscribed_at = None
            authorized = False
            had_job = False
            while not self.stop.is_set():
                if time.time() - t_start > self.recycle:
                    return "recycled"
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    # Nothing for a while is normal between jobs; a port that answered the
                    # subscribe but never sent work may want a worker first.
                    if subscribed_at and not had_job and not authorized and time.time() - subscribed_at > JOB_WAIT_S:
                        authorized = self.authorize(sock)
                    continue
                if not chunk:
                    return "closed"
                buf += chunk
                if len(buf) > 1 << 20:
                    raise RuntimeError("line too long")
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    try:
                        m = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(m, dict):
                        continue
                    meth = m.get("method")
                    if meth == "mining.notify":
                        pr = m.get("params") or []
                        if len(pr) >= 3 and isinstance(pr[2], str):
                            c = sia_commitment(pr[2])
                            if c:
                                had_job = True
                                self.jobs.add(c, ep["label"], ep["key"], str(pr[0]))
                                self.state["jobs"] += 1
                                self.state["last_job"] = now()
                    elif meth == "mining.set_difficulty":
                        pr = m.get("params") or [None]
                        self.state["diff"] = pr[0]
                    elif meth == "client.reconnect":
                        return "asked to reconnect"
                    elif m.get("id") == 1:
                        subscribed_at = time.time()
                        if m.get("error"):
                            raise RuntimeError(f"subscribe refused: {m['error']}")
                if subscribed_at and not had_job and not authorized and time.time() - subscribed_at > JOB_WAIT_S:
                    authorized = self.authorize(sock)
            return "stopped"
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def authorize(self, sock):
        if not self.worker:
            return True
        sock.sendall((json.dumps({"id": 2, "method": "mining.authorize", "params": [self.worker, "x"]}) + "\n").encode())
        return True


def sia_commitment(coinb1_hex):
    """The 32-byte header commitment in a BLAKE2b job's coinb1: 3 zero bytes, the commitment, then 4 zero
    bytes in stock datum_gateway (datum_pow.c:172); the fork with an 8-byte extranonce1 moves those 4
    bytes into extranonce1 and sends 35."""
    try:
        b = bytes.fromhex(coinb1_hex)
    except ValueError:
        return None
    if len(b) not in (35, 39) or b[:3] != b"\x00" * 3 or b[35:] != b"\x00" * (len(b) - 35):
        return None
    return b[3:35].hex()


# ---------------------------------------------------------------------------
# chain

class Chain:
    def __init__(self, rest):
        self.rest = rest.rstrip("/")

    def get(self, path, timeout=20):
        import urllib.request
        with urllib.request.urlopen(f"{self.rest}/{path}", timeout=timeout) as r:
            return r.read()

    def tip(self):
        d = json.loads(self.get("chaininfo.json", timeout=8))
        return d["blocks"], d["bestblockhash"]

    def recent_headers(self, tip_height, n):
        """[(height, hash, raw header)] for the last n blocks, oldest first."""
        start = max(0, tip_height - n + 1)
        h0 = json.loads(self.get(f"blockhashbyheight/{start}.json"))["blockhash"]
        raw = self.get(f"headers/{h0}.bin?count={n}")
        out = []
        for i in range(0, len(raw) - HEADER_SIZE + 1, HEADER_SIZE):
            hdr = raw[i:i + HEADER_SIZE]
            try:
                H = hdrv2.HeaderV2.deserialize(hdr)
            except ValueError:
                continue
            out.append((H.m_height, H.block_hash_display_hex(), H))
        return out

    def coinbase_sig(self, blockhash):
        blk = json.loads(self.get(f"block/notxdetails/{blockhash}.json"))
        txid = blk["tx"][0]
        tx = json.loads(self.get(f"tx/{txid}.json"))
        return bytes.fromhex(tx["vin"][0].get("coinbase", ""))


class Matches:
    """What the port matches taught us, on disk."""

    def __init__(self, sd):
        self.blocks_path = os.path.join(sd, "sv1-port-blocks.jsonl")
        self.ident_path = os.path.join(sd, "sv1-port-identities.json")
        self.identities = []
        try:
            self.identities = json.load(open(self.ident_path)).get("identities", [])
        except Exception:  # noqa: BLE001
            pass

    def record(self, height, blockhash, label, key, commitment, job, ident):
        row = {"h": height, "hash": blockhash, "label": label, "endpoint": key, "commitment": commitment,
               "job_id": job[3], "job_seen": datetime.fromtimestamp(job[2], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "matched": now()}
        if ident:
            row.update(primary=ident[0], secondary=ident[1], uid=ident[2])
        with open(self.blocks_path, "a") as f:
            f.write(json.dumps(row) + "\n")
        if not ident:
            return
        for it in self.identities:
            if (it["label"], it["primary"], it["secondary"], it["uid"]) == (label,) + ident:
                it["last_h"] = max(it["last_h"], height)
                it["first_h"] = min(it["first_h"], height)
                it["matches"] = sorted(set(it["matches"] + [height]))[-50:]
                it["endpoints"] = sorted(set(it.get("endpoints", []) + [key]))
                break
        else:
            self.identities.append({"label": label, "endpoint": key, "endpoints": [key], "primary": ident[0],
                                    "secondary": ident[1], "uid": ident[2], "first_h": height, "last_h": height,
                                    "matches": [height], "learned": now()})
        doc = {"generated": now(), "what": "Coinbase identities (tags, unique id and pool session id after the "
               "difficulty byte) of gateways behind public stratum ports, each learned from a block whose job "
               "the port handed to this client. A block with one of these identities was built by that port's node.",
               "identities": self.identities}
        with open(self.ident_path + ".tmp", "w") as f:
            json.dump(doc, f, indent=1)
        os.replace(self.ident_path + ".tmp", self.ident_path)


def check_headers(chain, jobs, matches, headers, seen, verbose):
    """Match every unseen header against the jobs on hand. Returns the matches made."""
    hits = []
    for height, blockhash, H in headers:
        if blockhash in seen:
            continue
        seen.add(blockhash)
        c = H.h2().hex()
        job = jobs.get(c)
        if verbose:
            log(f"block {height} {blockhash[:16]} commitment {c[:16]} {'MATCH ' + job[1] if job else 'no port job'}")
        if not job:
            continue
        label, key = job[0], job[1]
        ident = None
        try:
            ident = coinbase_identity(chain.coinbase_sig(blockhash))
        except Exception as e:  # noqa: BLE001
            log(f"block {height}: coinbase unreadable: {e}")
        matches.record(height, blockhash, label, key, c, job, ident)
        log(f"MATCH block {height} {blockhash} <- {key} ({label}) job {job[3]} seen {datetime.fromtimestamp(job[2], timezone.utc).strftime('%H:%M:%SZ')}"
            + (f" identity {ident}" if ident else ""))
        hits.append(height)
    return hits


def write_status(path, ports, jobs, matches, started):
    doc = {"generated": now(), "started": started, "jobs_on_hand": jobs.prune(),
           "identities": len(matches.identities),
           "ports": sorted((p.state for p in ports.values()), key=lambda s: (s["label"], s["endpoint"]))}
    with open(path + ".tmp", "w") as f:
        json.dump(doc, f, indent=1)
    os.replace(path + ".tmp", path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--survey", default=os.path.join(SD, "pool-survey.json"))
    ap.add_argument("--endpoints", default=os.path.join(HERE, "pool-endpoints.json"))
    ap.add_argument("--state-dir", default=SD)
    ap.add_argument("--rest", default="http://127.0.0.1:8332/rest")
    ap.add_argument("--keep-min", type=int, default=180, help="minutes a job stays on hand")
    ap.add_argument("--recycle-min", type=float, default=10, help="minutes a connection is kept before reconnecting")
    ap.add_argument("--only", action="append", default=[], help="watch this pool label only (repeatable)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    threading.stack_size(512 * 1024)
    jobs = Jobs(args.keep_min * 60)
    chain = Chain(args.rest)
    matches = Matches(args.state_dir)
    worker = worker_name(os.path.join(args.state_dir, "probe-worker.json"))
    status_path = os.path.join(args.state_dir, "sv1-jobs-status.json")
    started = now()
    ports = {}
    seen = set()

    def reload_ports():
        eps = {e["key"]: e for e in load_endpoints(args.survey, args.endpoints, set(args.only))}
        for key in [k for k in ports if k not in eps]:
            ports.pop(key).stop.set()
            log(f"dropped {key}: no longer handing out work for this chain")
        for key, ep in eps.items():
            if key not in ports:
                ports[key] = Port(ep, jobs, worker, args.recycle_min * 60, args.verbose)
                ports[key].start()
        return len(eps)

    n = reload_ports()
    log(f"watching {n} ports, {len(matches.identities)} identities on file")
    try:
        height, best = chain.tip()
        for _, blockhash, _ in chain.recent_headers(height, LOOKBACK):
            seen.add(blockhash)   # blocks from before any job was on hand
    except Exception as e:  # noqa: BLE001
        log(f"node unreachable at start: {e}")
        best = None
    last_status = last_reload = time.time()
    while True:
        time.sleep(POLL_S)
        try:
            height, tip = chain.tip()
            if tip != best:
                check_headers(chain, jobs, matches, chain.recent_headers(height, LOOKBACK), seen, args.verbose)
                best = tip
                if len(seen) > 5000:
                    seen.clear()
        except Exception as e:  # noqa: BLE001
            log(f"node: {e}")
        t = time.time()
        if t - last_status >= STATUS_S:
            write_status(status_path, ports, jobs, matches, started)
            last_status = t
        if t - last_reload >= RELOAD_S:
            reload_ports()
            last_reload = t


if __name__ == "__main__":
    main()
