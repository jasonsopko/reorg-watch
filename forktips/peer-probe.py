#!/usr/bin/env python3
"""peer-probe.py - ask peers directly what chain they are on. No RPC, no credentials.

The BLAKE2b fork kept the legacy P2P magic (f9beb4d9) and port 8333, so a handshake alone
does not tell you which chain a node follows. NODE_BLAKE2B (bit 28) does: it is set only by
nodes enforcing the fork rules. This sends a version message, reads the peer's reply, and
reports its services, advertised height and user agent.

Usage: peer-probe.py [--addrs FILE] [--limit N] [--timeout S] [--out FILE]
"""
import argparse, hashlib, importlib.util, json, os, random, socket, struct, sys, time, urllib.request
from datetime import datetime, timezone

MAGIC = bytes.fromhex("f9beb4d9")
NODE_BLAKE2B = 1 << 28
DEFAULT_UA = "/reorg.watch-peer-probe:0.1/"
LEGACY_HEADER_SIZE, V2_HEADER_SIZE, HEADER_V2_FLAG = 80, 164, 0x8000_0000

_hs = importlib.util.spec_from_file_location("hdrv2", os.path.join(os.path.dirname(os.path.abspath(__file__)), "hdrv2.py"))
hdrv2 = importlib.util.module_from_spec(_hs)
sys.modules["hdrv2"] = hdrv2   # dataclasses resolve __module__ through sys.modules
_hs.loader.exec_module(hdrv2)
FLAGS = {1: "NETWORK", 2: "GETUTXO", 4: "BLOOM", 8: "WITNESS", 1 << 10: "NETWORK_LIMITED",
         1 << 11: "P2P_V2", NODE_BLAKE2B: "BLAKE2B"}


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def msg(cmd, payload=b""):
    return MAGIC + cmd.encode().ljust(12, b"\x00") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload


def varstr(s):
    b = s.encode()
    return (bytes([len(b)]) if len(b) < 0xfd else b"\xfd" + struct.pack("<H", len(b))) + b


def netaddr(services=0):
    return struct.pack("<Q", services) + b"\x00" * 10 + b"\xff\xff" + b"\x00" * 4 + struct.pack(">H", 0)


def version_payload(ua):
    return (struct.pack("<i", 70016) + struct.pack("<Q", 0) + struct.pack("<q", int(time.time()))
            + netaddr() + netaddr() + struct.pack("<Q", random.getrandbits(64))
            + varstr(ua) + struct.pack("<i", 0) + b"\x00")


def read_msg(sock, deadline):
    hdr = b""
    while len(hdr) < 24:
        if time.monotonic() > deadline:
            return None, None
        c = sock.recv(24 - len(hdr))
        if not c:
            return None, None
        hdr += c
    if hdr[:4] != MAGIC:
        return None, None
    cmd = hdr[4:16].rstrip(b"\x00").decode("ascii", "replace")
    ln = struct.unpack("<I", hdr[16:20])[0]
    body = b""
    while len(body) < ln:
        if time.monotonic() > deadline:
            return cmd, None
        c = sock.recv(min(65536, ln - len(body)))
        if not c:
            return cmd, None
        body += c
    return cmd, body


def parse_version(p):
    i = 0
    ver, services, _ts = struct.unpack_from("<iQq", p, i); i += 20
    i += 26 + 26 + 8                      # addr_recv, addr_from, nonce
    n = p[i]; i += 1
    if n == 0xfd:
        n = struct.unpack_from("<H", p, i)[0]; i += 2
    ua = p[i:i + n].decode("ascii", "replace"); i += n
    height = struct.unpack_from("<i", p, i)[0]
    return {"version": ver, "services": services, "user_agent": ua, "start_height": height}


def varint(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def read_varint(b, i):
    n = b[i]; i += 1
    if n == 0xfd:
        return struct.unpack_from("<H", b, i)[0], i + 2
    if n == 0xfe:
        return struct.unpack_from("<I", b, i)[0], i + 4
    if n == 0xff:
        return struct.unpack_from("<Q", b, i)[0], i + 8
    return n, i


def our_locator(rest_base, depth=40):
    """Block locator from our own chain: tip, then stepping back exponentially.
    Hashes go on the wire in internal order, which is the display hex reversed."""
    def j(path):
        return json.loads(urllib.request.urlopen(rest_base + "/" + path, timeout=10).read())
    tip = j("chaininfo.json")["blocks"]
    heights, step, h = [], 1, tip
    while h > 0 and len(heights) < depth:
        heights.append(h)
        if len(heights) > 10:
            step *= 2
        h -= step
    out = []
    for ht in heights:
        try:
            out.append((ht, j("blockhashbyheight/%d.json" % ht)["blockhash"]))
        except Exception:
            break
    return tip, out


def getheaders_payload(locator):
    b = struct.pack("<i", 70016) + varint(len(locator))
    for _, disp in locator:
        b += bytes.fromhex(disp)[::-1]          # display -> internal
    return b + b"\x00" * 32                     # hash_stop: keep going


def parse_headers(body):
    """headers message: varint count, then each header followed by a varint tx count.
    Header length is 80 or 164 depending on bit 31 of the version field."""
    count, i = read_varint(body, 0)
    out = []
    for _ in range(count):
        if i + 4 > len(body):
            break
        v = struct.unpack_from("<I", body, i)[0]
        size = V2_HEADER_SIZE if (v & HEADER_V2_FLAG) else LEGACY_HEADER_SIZE
        raw = body[i:i + size]
        if len(raw) < size:
            break
        i += size
        _, i = read_varint(body, i)             # tx count, always 0 in a headers message
        rec = {"v2": bool(v & HEADER_V2_FLAG)}
        if rec["v2"]:
            try:
                h = hdrv2.HeaderV2.deserialize(raw)
                rec.update({"height": h.m_height,
                            "prev": hdrv2.wire_to_display(h.hashPrevBlock),
                            "hash": h.block_hash_display_hex()})
            except Exception as e:
                rec["error"] = str(e)
        else:
            rec["prev"] = raw[4:36][::-1].hex()
            rec["hash"] = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
        out.append(rec)
    return out


def compare_to_us(headers, rest_base):
    """Does this peer's branch build on our chain, and if not, where does it leave it?"""
    def our_hash(ht):
        try:
            return json.loads(urllib.request.urlopen(
                rest_base + "/blockhashbyheight/%d.json" % ht, timeout=10).read())["blockhash"]
        except Exception:
            return None
    if not headers:
        return {"verdict": "no headers returned; peer is at or behind our locator"}
    first = headers[0]
    if "height" not in first:
        return {"verdict": "legacy headers (not the BLAKE2b chain)", "count": len(headers)}
    parent_h = first["height"] - 1
    ours = our_hash(parent_h)
    if ours is None:
        return {"verdict": "could not read our own block at %d" % parent_h}
    if ours != first["prev"]:
        return {"verdict": "DIVERGES", "diverges_after": parent_h,
                "their_parent": first["prev"], "our_block": ours, "count": len(headers)}
    mine = our_hash(first["height"])
    same = mine == first["hash"]
    return {"verdict": "same chain, peer ahead by %d" % len(headers) if not same or len(headers) else "same chain",
            "builds_on": parent_h, "count": len(headers),
            "first_matches_ours": same, "their_tip": headers[-1]["hash"],
            "their_tip_height": headers[-1]["height"]}


def probe(addr, timeout, ua, locator=None, rest_base=None):
    host, _, port = addr.rpartition(":")
    host = host.strip("[]")
    rec = {"addr": addr, "probed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
    except OSError as e:
        rec["result"] = "unreachable (%s)" % (e.strerror or e)
        return rec
    try:
        s.settimeout(timeout)
        s.sendall(msg("version", version_payload(ua)))
        deadline = time.monotonic() + timeout
        while True:
            cmd, body = read_msg(s, deadline)
            if cmd is None:
                rec["result"] = "no version received"
                return rec
            if cmd == "version" and body:
                v = parse_version(body)
                rec.update(v)
                rec["blake2b"] = bool(v["services"] & NODE_BLAKE2B)
                rec["service_names"] = sorted(n for b, n in FLAGS.items() if v["services"] & b)
                rec["result"] = "ok"
                if not locator:
                    return rec
                s.sendall(msg("verack"))
                s.sendall(msg("getheaders", getheaders_payload(locator)))
                deadline = time.monotonic() + timeout
                while True:
                    c2, b2 = read_msg(s, deadline)
                    if c2 is None:
                        rec["branch"] = {"verdict": "no headers reply before timeout"}
                        return rec
                    if c2 == "ping" and b2:
                        s.sendall(msg("pong", b2))
                    if c2 == "headers":
                        hs = parse_headers(b2 or b"")
                        rec["headers_returned"] = len(hs)
                        rec["_headers"] = hs          # raw, for callers that judge them
                        rec["branch"] = compare_to_us(hs, rest_base)
                        return rec
    except Exception as e:
        rec["result"] = "handshake failed (%s)" % e
        return rec
    finally:
        try:
            s.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addrs", default=os.path.expanduser("~/.reorg-watch/seeds-blake2b.txt"))
    ap.add_argument("--limit", type=int, default=10)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--ua", default=DEFAULT_UA)
    ap.add_argument("--headers", action="store_true",
                    help="after the handshake, ask each peer which branch it is on")
    ap.add_argument("--rest", default="http://127.0.0.1:8332/rest")
    ap.add_argument("--out")
    args = ap.parse_args()

    addrs = []
    for l in open(args.addrs):
        l = l.split("#")[0].strip()
        if l and ".onion" not in l and ".i2p" not in l and not l.startswith("["):
            addrs.append(l)
    random.shuffle(addrs)
    locator = None
    if args.headers:
        tip, locator = our_locator(args.rest.rstrip("/"))
        print("our tip %d; locator of %d hashes\n" % (tip, len(locator)))
    out = []
    for a in addrs[:args.limit]:
        r = probe(a, args.timeout, args.ua, locator, args.rest.rstrip("/"))
        out.append(r)
        line = "%-24s %-22s %s" % (
            a, r["result"][:22],
            ("h=%-8d %s %s" % (r["start_height"], "BLAKE2B" if r["blake2b"] else "no-bit ",
                               r["user_agent"][:28])) if r["result"] == "ok" else "")
        if r.get("branch"):
            line += "  | " + r["branch"]["verdict"][:46]
        print(line)
    if args.out:
        json.dump({"generated": datetime.now(timezone.utc).isoformat(), "peers": out}, open(args.out, "w"), indent=2)
    ok = [r for r in out if r["result"] == "ok"]
    print("\n%d/%d answered; %d advertise NODE_BLAKE2B" % (len(ok), len(out), sum(1 for r in ok if r["blake2b"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
