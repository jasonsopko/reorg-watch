#!/usr/bin/env python3
"""datum-check.py - open a DATUM session with a pool and stop after the handshake.

A pool's DATUM service cannot be probed with a Stratum subscribe: the server
reads an encrypted header and drops the connection. The only way to know a
DATUM prime is listening, and that the published pool pubkey is its key, is
to do what a gateway does: send the handshake init sealed to the pool's
x25519 key and check that the reply is sealed to our session key and signed
by the pool's ed25519 key. That is all this does. It never asks for work,
never submits a share, and closes as soon as the handshake reply is parsed
(or refused, or times out).

The wire format is datum_gateway's src/datum_protocol.c (send_hello,
handshake_response, header_xor_feedback), and the crypto is libsodium
itself through ctypes, so the bytes are the same ones a gateway sends.

Identity: a gateway signs the hello with a long-lived key pair. This keeps
one pair in ~/.reorg-watch/datum-check-keys.json so a pool sees a single
identity named reorg.watch-datum-check, not a new gateway every hour.

Usage: datum-check.py host:port pool_pubkey_hex [--timeout S] [--keys FILE]
"""

import argparse, ctypes, ctypes.util, json, os, socket, struct, sys, time
from datetime import datetime, timezone

DATUM_PROTOCOL_VERSION = "v0.4.1-beta"         # datum_protocol.h, sent as the UA prefix
CLIENT_TAG = "reorg.watch-datum-check"        # where a gateway puts its git commit
INITIAL_SEND_KEY = 0xDC871829                 # datum_protocol.c:98
KEYS_PATH = os.path.expanduser("~/.reorg-watch/datum-check-keys.json")

CMD_HANDSHAKE_INIT = 1
CMD_HANDSHAKE_RESPONSE = 2
CMD_INFO = 7

_sodium = None


def sodium():
    global _sodium
    if _sodium is None:
        name = ctypes.util.find_library("sodium") or "libsodium.so.23"
        lib = ctypes.CDLL(name)
        if lib.sodium_init() < 0:
            raise RuntimeError("sodium_init failed")
        _sodium = lib
    return _sodium


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def feedback(i):
    """datum_header_xor_feedback(): the next header XOR key from the previous one."""
    M = 0xFFFFFFFF
    h = 0xb10cfeed
    k = (i * 0xcc9e2d51) & M
    k = ((k << 15) | (k >> 17)) & M
    k = (k * 0x1b873593) & M
    h ^= k
    h = ((h << 13) | (h >> 19)) & M
    h = (h * 5 + 0xe6546b64) & M
    h ^= 4
    h ^= h >> 16
    h = (h * 0x85ebca6b) & M
    h ^= h >> 13
    h = (h * 0xc2b2ae35) & M
    h ^= h >> 16
    return h


def pack_header(cmd_len, signed, enc_pubkey, enc_channel, cmd):
    """T_DATUM_PROTOCOL_HEADER: cmd_len:22, reserved:2, is_signed, is_encrypted_pubkey,
    is_encrypted_channel, proto_cmd:5, packed little-endian from the low bit up."""
    return (cmd_len & 0x3FFFFF) | (bool(signed) << 24) | (bool(enc_pubkey) << 25) \
        | (bool(enc_channel) << 26) | ((cmd & 0x1F) << 27)


def unpack_header(v):
    return {"cmd_len": v & 0x3FFFFF, "is_signed": bool(v >> 24 & 1),
            "is_encrypted_pubkey": bool(v >> 25 & 1), "is_encrypted_channel": bool(v >> 26 & 1),
            "proto_cmd": v >> 27 & 0x1F}


def gen_keys():
    lib = sodium()
    ed_pk, ed_sk = ctypes.create_string_buffer(32), ctypes.create_string_buffer(64)
    x_pk, x_sk = ctypes.create_string_buffer(32), ctypes.create_string_buffer(32)
    if lib.crypto_sign_keypair(ed_pk, ed_sk) != 0 or lib.crypto_box_keypair(x_pk, x_sk) != 0:
        raise RuntimeError("keypair generation failed")
    return {"ed_pk": ed_pk.raw, "ed_sk": ed_sk.raw, "x_pk": x_pk.raw, "x_sk": x_sk.raw}


def load_keys(path=KEYS_PATH):
    """The long-lived identity, made on first use. Mode 600; never published."""
    try:
        with open(path) as f:
            d = json.load(f)
        return {k: bytes.fromhex(d[k]) for k in ("ed_pk", "ed_sk", "x_pk", "x_sk")}
    except FileNotFoundError:
        pass
    keys = gen_keys()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({k: v.hex() for k, v in keys.items()} | {"created": now_iso(), "tag": CLIENT_TAG}, f, indent=1)
    os.replace(path + ".tmp", path)
    return keys


def sign(msg, ed_sk):
    lib = sodium()
    sig = ctypes.create_string_buffer(64)
    if lib.crypto_sign_detached(sig, None, msg, ctypes.c_ulonglong(len(msg)), ed_sk) != 0:
        raise RuntimeError("crypto_sign_detached failed")
    return sig.raw


def verify(sig, msg, ed_pk):
    return sodium().crypto_sign_verify_detached(sig, msg, ctypes.c_ulonglong(len(msg)), ed_pk) == 0


def seal(msg, x_pk):
    lib = sodium()
    out = ctypes.create_string_buffer(len(msg) + 48)
    if lib.crypto_box_seal(out, msg, ctypes.c_ulonglong(len(msg)), x_pk) != 0:
        raise RuntimeError("crypto_box_seal failed")
    return out.raw


def seal_open(box, x_pk, x_sk):
    lib = sodium()
    if len(box) < 48:
        return None
    out = ctypes.create_string_buffer(len(box) - 48)
    if lib.crypto_box_seal_open(out, box, ctypes.c_ulonglong(len(box)), x_pk, x_sk) != 0:
        return None
    return out.raw


def build_hello(keys, session, ua_extra=""):
    """datum_protocol_send_hello(): the signed, sealed handshake init, and the
    4 random bytes that seed both header XOR keys. After the seed comes the
    version 3 extension ("DRS\\x01", then a 0 for no session to resume), which
    CONVOY's gateway and ratum send and which a version 1 server reads as
    padding; primes started with --require-v3 refuse a hello without it."""
    ua = (DATUM_PROTOCOL_VERSION + "/" + CLIENT_TAG + ua_extra).encode()[:200]
    nk = os.urandom(4)
    pad = os.urandom(1) * (1 + os.urandom(1)[0] % 200)
    body = (keys["ed_pk"] + keys["x_pk"] + session["ed_pk"] + session["x_pk"] + ua + b"\x00" + b"\xfe" + nk
            + b"DRS\x01" + b"\x00" + pad)
    return body + sign(body, keys["ed_sk"]), struct.unpack("<I", nk)[0]


def recv_exact(sock, n, deadline):
    buf = b""
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise socket.timeout()
        sock.settimeout(min(left, 5))
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionResetError("closed")
        buf += chunk
    return buf


def check(host, port, pool_pubkey_hex, keys, timeout=10.0, ua_extra=""):
    """One handshake. Returns a record; 'result' is one of:
       verified        the reply was sealed to our session key and signed by the pool key
       refused         the server answered with a message instead of a handshake reply
       bad-signature   a reply came back that the published pool key did not sign
       no-reply        connected, sent the hello, nothing came back in time
       closed          the server closed the connection without replying
       refused-connect / timeout / dns / error   could not connect at all
    """
    rec = {"host": host, "port": port, "checked_at": now_iso(), "result": None, "detail": ""}
    pk = (pool_pubkey_hex or "").strip().lower()
    if len(pk) != 128 or any(c not in "0123456789abcdef" for c in pk):
        rec.update(result="error", detail="pool pubkey is not 128 hex characters")
        return rec
    pool_ed, pool_x = bytes.fromhex(pk[:64]), bytes.fromhex(pk[64:])
    session = gen_keys()
    hello, nk = build_hello(keys, session, ua_extra)
    sealed = seal(hello, pool_x)
    hdr = struct.pack("<I", pack_header(len(sealed), 1, 1, 0, CMD_HANDSHAKE_INIT) ^ INITIAL_SEND_KEY)
    recv_key = feedback(~nk & 0xFFFFFFFF)
    t0 = time.monotonic()
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        rec["connect_ms"] = round((time.monotonic() - t0) * 1000, 1)
        sock.sendall(hdr + sealed)
        deadline = time.monotonic() + timeout
        raw = recv_exact(sock, 4, deadline)
        h = unpack_header(struct.unpack("<I", raw)[0] ^ recv_key)
        rec["reply_ms"] = round((time.monotonic() - t0) * 1000, 1)
        if h["cmd_len"] > 65536:
            rec.update(result="error", detail="reply header did not decode (len %d, cmd %d)" % (h["cmd_len"], h["proto_cmd"]))
            return rec
        data = recv_exact(sock, h["cmd_len"], deadline) if h["cmd_len"] else b""
        if h["is_encrypted_pubkey"] and not h["is_encrypted_channel"]:
            data = seal_open(data, session["x_pk"], session["x_sk"])
            if data is None:
                rec.update(result="error", detail="reply was not sealed to our session key")
                return rec
        if h["is_signed"]:
            if len(data) < 64 or not verify(data[-64:], data[:-64], pool_ed):
                rec.update(result="bad-signature", detail="reply is not signed by the published pool key")
                return rec
            data = data[:-64]
        if h["proto_cmd"] == CMD_HANDSHAKE_RESPONSE:
            echoed = keys["ed_pk"] + keys["x_pk"] + session["ed_pk"] + session["x_pk"]
            if data[:128] != echoed:
                rec.update(result="error", detail="handshake reply echoed the wrong keys")
                return rec
            motd = data[192:].split(b"\x00", 1)[0].decode("utf-8", "replace")[:200]
            rec.update(result="verified", detail=motd, signed=h["is_signed"])
        elif h["proto_cmd"] == CMD_INFO:
            rec.update(result="refused", detail=data.split(b"\x00", 1)[0].decode("utf-8", "replace")[:200])
        else:
            rec.update(result="refused", detail="unexpected protocol command %d" % h["proto_cmd"])
    except socket.gaierror as e:
        rec.update(result="dns", detail=str(e.strerror or e))
    except ConnectionRefusedError:
        rec.update(result="refused-connect", detail="connection refused")
    except ConnectionResetError:
        rec.update(result="closed", detail="server closed the connection before replying")
    except socket.timeout:
        rec.update(result="timeout" if "connect_ms" not in rec else "no-reply",
                   detail="no reply within %.0f s" % timeout if "connect_ms" in rec else "connect timed out")
    except OSError as e:
        rec.update(result="error", detail=str(e.strerror or e))
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("endpoint", help="host:port")
    ap.add_argument("pubkey", help="the pool's 128-hex DATUM pubkey")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--keys", default=KEYS_PATH)
    ap.add_argument("--ua-extra", default="", help="text appended to the client string")
    a = ap.parse_args()
    host, _, port = a.endpoint.rpartition(":")
    rec = check(host, int(port), a.pubkey, load_keys(a.keys), a.timeout, a.ua_extra)
    print(json.dumps(rec, indent=1))
    return 0 if rec["result"] == "verified" else 1


if __name__ == "__main__":
    sys.exit(main())
