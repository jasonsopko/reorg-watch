"""Independent implementation of the Bitcoin Knots PR #359 "header v2" format and
its BLAKE2b proof-of-work hash (CBlockHeader::GetHash for m_header_v2 == true).

Written from src/primitives/block.{h,cpp} at pr-359 head b51bc6b1df for
differential testing against the official test vectors
(src/test/data/block_header_v2.json), the C++ unit test, and the reference
Python in test/functional/test_framework/messages.py.

Conventions used here (all derived from the C++):
  * "wire" order  = the byte order in serialized headers / hash inputs.
    Bitcoin uint256/uint128 fields are stored little-endian internally and
    serialized in that internal order; their *hex display* (GetHex/FromHex)
    is byte-reversed. This module keeps every uint256/uint128 field as
    wire-order `bytes` and converts at the JSON boundary only.
  * All hash digests are kept in digest order (as produced by the hash
    function). The C++ stores digests into uint256 in digest order too, so
    a digest written into a HashWriter/DataStream goes in unchanged.
  * The final block hash is byte-reversed into the uint256 (so that GetHex()
    shows blake2b_2 XOR mask in digest order). `block_hash_display_hex()`
    returns exactly what CBlockHeader::GetHash().GetHex() prints.
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

#: PR #359 head whose src/primitives/block.{h,cpp} this implementation matches,
#: verified against src/test/data/block_header_v2.json and messages.py. The
#: construction has changed four times in a week; if the node moves ahead of
#: this, hashes stop matching and submitblock answers "high-hash" rather than
#: failing loudly.
CONSTRUCTION_HEAD = "fee27ccfe9"

HEADER_V2_FLAG = 0x8000_0000
FLAG_USE_TIME_OFFSET = 0x04          # BlockHeaderFlag::UseTimeOffset
PROFILE_MASK = 0x03                  # m_flags & 3 selects the ASIC profile
LEGACY_HEADER_SIZE = 80
V2_HEADER_SIZE = 164

TAG_XOR_KEY = b"Bitcoin block hash PoW XOR key"
TAG_XOR_MASK = b"Bitcoin block hash PoW XOR mask"
TAG_H1 = b"Bitcoin block header 1"
TAG_H2 = b"Merge-mining hook"
TAG_PREV_HIDDEN = b"Bitcoin prevblock header, hashed"   # added in PR head a6d74ce52f (2026-08-18)
PREV_HIDDEN_ZERO_BYTES = 6                               # leading bytes of the hidden prevhash zeroed for profile 0

_U32 = struct.Struct("<I")
_I32 = struct.Struct("<i")
_U16 = struct.Struct("<H")


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def tagged_sha256(tag: bytes, msg: bytes) -> bytes:
    """BIP340-style tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)."""
    t = sha256(tag)
    return sha256(t + t + msg)


def blake2b_256(msg: bytes) -> bytes:
    """Unkeyed BLAKE2b with a 32-byte digest (blake2b_nokey(out, 32, in, len))."""
    return hashlib.blake2b(msg, digest_size=32).digest()


def display_to_wire(hex_str: str, nbytes: int) -> bytes:
    """uint256/uint128 hex display (FromHex) -> internal/wire bytes."""
    b = bytes.fromhex(hex_str)
    if len(b) != nbytes:
        raise ValueError(f"expected {nbytes} bytes, got {len(b)}")
    return b[::-1]


def wire_to_display(b: bytes) -> str:
    return b[::-1].hex()


@dataclass
class HeaderV2:
    # legacy 80-byte prefix
    nVersion: int = 0                     # int32, WITHOUT the 0x80000000 flag
    hashPrevBlock: bytes = b"\x00" * 32   # wire order
    hashMerkleRoot: bytes = b"\x00" * 32  # wire order
    nTime: int = 0                        # uint32, the *real* block time
    nBits: int = 0
    nNonce: int = 0
    # v2 extension
    m_nonce2: int = 0
    m_nonce3: int = 0
    m_extranonce: bytes = b"\x00" * 16    # wire order
    m_time_offset: int = 0
    m_txcount: int = 0                    # uint16
    m_flags: int = 0                      # uint8
    m_xor_key_mask_clear_bits: int = 0    # uint8
    m_xor_key: bytes = b"\x00" * 16       # wire order
    m_height: int = 0                     # int32
    m_mm_rhs: bytes = b"\x00" * 32        # wire order

    # ---- derived -----------------------------------------------------
    @property
    def asic_profile(self) -> int:
        return self.m_flags & PROFILE_MASK

    def time_on_wire(self) -> int:
        """CompressedHeader::GetTimeOnWire(): nTime - offset (mod 2^32) iff flag bit 2."""
        if self.m_flags & FLAG_USE_TIME_OFFSET:
            return (self.nTime - self.m_time_offset) & 0xFFFF_FFFF
        return self.nTime

    # ---- serialization -------------------------------------------------
    def serialize(self) -> bytes:
        self._check_ranges()
        out = bytearray()
        out += _U32.pack((self.nVersion & 0xFFFF_FFFF) | HEADER_V2_FLAG)
        out += self.hashPrevBlock
        out += self.hashMerkleRoot
        out += _U32.pack(self.time_on_wire())
        out += _U32.pack(self.nBits)
        out += _U32.pack(self.nNonce)
        # v2 fields, in SERIALIZE_METHODS order
        out += _U32.pack(self.m_nonce2)
        out += _U32.pack(self.m_nonce3)
        out += self.m_extranonce
        out += _U32.pack(self.m_time_offset)
        out += _U16.pack(self.m_txcount)
        out += bytes([self.m_flags, self.m_xor_key_mask_clear_bits])
        out += self.m_xor_key
        out += _I32.pack(self.m_height)
        out += self.m_mm_rhs
        assert len(out) == V2_HEADER_SIZE, len(out)
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes) -> "HeaderV2":
        if len(data) < LEGACY_HEADER_SIZE:
            raise ValueError("short header")
        v = _U32.unpack_from(data, 0)[0]
        if not (v & HEADER_V2_FLAG):
            raise ValueError("not a v2 header (bit 31 clear)")
        if len(data) != V2_HEADER_SIZE:
            raise ValueError(f"v2 header must be {V2_HEADER_SIZE} bytes, got {len(data)}")
        h = cls()
        h.nVersion = _I32.unpack_from(_U32.pack(v & ~HEADER_V2_FLAG), 0)[0]
        h.hashPrevBlock = data[4:36]
        h.hashMerkleRoot = data[36:68]
        wire_time = _U32.unpack_from(data, 68)[0]
        h.nBits = _U32.unpack_from(data, 72)[0]
        h.nNonce = _U32.unpack_from(data, 76)[0]
        p = 80
        h.m_nonce2 = _U32.unpack_from(data, p)[0]; p += 4
        h.m_nonce3 = _U32.unpack_from(data, p)[0]; p += 4
        h.m_extranonce = data[p:p + 16]; p += 16
        h.m_time_offset = _U32.unpack_from(data, p)[0]; p += 4
        h.m_txcount = _U16.unpack_from(data, p)[0]; p += 2
        h.m_flags = data[p]; p += 1
        h.m_xor_key_mask_clear_bits = data[p]; p += 1
        h.m_xor_key = data[p:p + 16]; p += 16
        h.m_height = _I32.unpack_from(data, p)[0]; p += 4
        h.m_mm_rhs = data[p:p + 32]; p += 32
        assert p == V2_HEADER_SIZE
        # nTime = wire time + offset (mod 2^32) iff flag bit 2
        h.nTime = (wire_time + h.m_time_offset) & 0xFFFF_FFFF if (h.m_flags & FLAG_USE_TIME_OFFSET) else wire_time
        return h

    def _check_ranges(self) -> None:
        for name, val, bits, signed in (
            ("nVersion", self.nVersion, 32, True), ("nTime", self.nTime, 32, False),
            ("nBits", self.nBits, 32, False), ("nNonce", self.nNonce, 32, False),
            ("m_nonce2", self.m_nonce2, 32, False), ("m_nonce3", self.m_nonce3, 32, False),
            ("m_time_offset", self.m_time_offset, 32, False), ("m_txcount", self.m_txcount, 16, False),
            ("m_flags", self.m_flags, 8, False), ("m_xor_key_mask_clear_bits", self.m_xor_key_mask_clear_bits, 8, False),
            ("m_height", self.m_height, 32, True),
        ):
            lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
            if not (lo <= val <= hi):
                raise ValueError(f"{name}={val} out of range")
        for name, val, n in (("hashPrevBlock", self.hashPrevBlock, 32), ("hashMerkleRoot", self.hashMerkleRoot, 32),
                             ("m_extranonce", self.m_extranonce, 16), ("m_xor_key", self.m_xor_key, 16),
                             ("m_mm_rhs", self.m_mm_rhs, 32)):
            if len(val) != n:
                raise ValueError(f"{name} must be {n} bytes")

    # ---- proof-of-work hash --------------------------------------------
    def xor_key_hash(self) -> bytes:
        return tagged_sha256(TAG_XOR_KEY, self.m_xor_key)

    def xor_mask(self) -> bytes:
        """32-byte mask XORed into the final digest. All-zero when the key is null.
        Otherwise tagged SHA256 of the key with the first `clear_bits` bits
        (counted from the start of the digest, MSB-first within a byte) cleared."""
        if self.m_xor_key == b"\x00" * 16:
            return b"\x00" * 32
        mask = bytearray(tagged_sha256(TAG_XOR_MASK, self.m_xor_key))
        nbytes, nbits = divmod(self.m_xor_key_mask_clear_bits, 8)
        for i in range(nbytes):
            mask[i] = 0
        # clear_bits <= 255 so nbytes <= 31: always in range (C++ relies on the same).
        mask[nbytes] &= 0xFF >> nbits
        return bytes(mask)

    def prev_ordered_sane(self) -> bytes:
        """hashPrevBlock.ReversedBytes() -- big-endian / display order of the prev block hash."""
        return self.hashPrevBlock[::-1]

    def prev_hidden(self) -> bytes:
        """TaggedHash("Bitcoin prevblock header, hashed") of the reversed prevhash (a6d74ce52f)."""
        return tagged_sha256(TAG_PREV_HIDDEN, self.prev_ordered_sane())

    def h1(self) -> bytes:
        """Fields the mining machine never sees; 119 bytes under the tag.

        At fee27ccfe9 this commits to GetCompleteVersion() (nVersion with bit 31
        masked off, then the v2 flag re-set) rather than the raw nVersion, so the
        v2 marker bit is now covered by h1.
        """
        msg = (
            _U32.pack((self.nVersion & ~HEADER_V2_FLAG) | HEADER_V2_FLAG)
            + self.prev_ordered_sane()
            + _I32.pack(self.m_height)
            + self.hashMerkleRoot
            + _U32.pack(self.time_on_wire())
            + b"\x00"                             # reserved for 40-bit time (u32->u8 at 5a3f788e84)
            + _U32.pack(self.nBits)
            + _U32.pack(self.m_txcount)        # uint16 widened to 4 bytes
            + bytes([self.m_flags, self.m_xor_key_mask_clear_bits])
            + self.xor_key_hash()
        )
        assert len(msg) == 119, len(msg)
        return tagged_sha256(TAG_H1, msg)

    def h2(self) -> bytes:
        """TaggedHash("Merge-mining hook")(h1 || 32 zero bytes || mm_rhs) -- 96 bytes (a6d74ce52f)."""
        return tagged_sha256(TAG_H2, self.h1() + b"\x00" * 32 + self.m_mm_rhs)

    def stage1_input(self) -> bytes:
        """What a pool would send as Sv1 coinb1 + extranonce: 4 zero bytes || h2 || extranonce (52 B)."""
        s = b"\x00\x00\x00\x00" + self.h2() + self.m_extranonce
        assert len(s) == 52
        return s

    def stage1_hash(self) -> bytes:
        return blake2b_256(self.stage1_input())

    def asic_input(self) -> bytes:
        """The exact bytes the mining hardware hashes (stage 2), per profile."""
        h = self.stage1_hash()
        h2 = self.h2()
        nonces_a = _U32.pack(self.nNonce) + _U32.pack(self.m_nonce2) + _U32.pack(self.m_time_offset) + _U32.pack(self.m_nonce3)
        nonces_b = _U32.pack(self.nNonce) + _U32.pack(self.m_nonce2) + _U32.pack(self.m_nonce3) + _U32.pack(self.m_time_offset)
        profile = self.asic_profile
        if profile == 0:
            # Sia-shaped 80 B: "parent id" slot carries the hidden prevhash with its first 6 bytes zeroed
            prev_slot = b"\x00" * PREV_HIDDEN_ZERO_BYTES + self.prev_hidden()[PREV_HIDDEN_ZERO_BYTES:]
            body = prev_slot + nonces_a + h
        elif profile == 1:
            body = nonces_b + h + h2
        else:  # 2, 3: h2 takes the prevhash slot; zero-fill to 128 / 160 bytes
            body = h2 + nonces_a + h
        pad = {0: 0, 1: 0, 2: 48, 3: 80}[profile]
        return b"\x00" * pad + body

    def stage2_hash(self) -> bytes:
        return blake2b_256(self.asic_input())

    def block_hash_digest_order(self) -> bytes:
        """blake2b_2 XOR mask, in digest order (== what GetHex() displays)."""
        return bytes(a ^ b for a, b in zip(self.stage2_hash(), self.xor_mask()))

    def block_hash_wire(self) -> bytes:
        """The uint256 internal bytes of CBlockHeader::GetHash() (reversed digest)."""
        return self.block_hash_digest_order()[::-1]

    def block_hash_display_hex(self) -> str:
        return self.block_hash_digest_order().hex()

    def components(self) -> dict:
        return {
            "xor_key_hash": self.xor_key_hash(),
            "h1": self.h1(),
            "h2": self.h2(),
            "blake2b_1": self.stage1_hash(),
            "asic_profile": self.asic_profile,
            "asic_input": self.asic_input(),
            "blake2b_2": self.stage2_hash(),
            "mask": self.xor_mask(),
            "block_hash": self.block_hash_digest_order(),
        }

    # ---- JSON boundary -----------------------------------------------------
    @classmethod
    def from_vector_fields(cls, f: dict) -> "HeaderV2":
        return cls(
            nVersion=f["nVersion"],
            hashPrevBlock=display_to_wire(f["hashPrevBlock"], 32),
            hashMerkleRoot=display_to_wire(f["hashMerkleRoot"], 32),
            nTime=f["nTime"], nBits=f["nBits"], nNonce=f["nNonce"],
            m_nonce2=f["m_nonce2"], m_nonce3=f["m_nonce3"],
            m_extranonce=display_to_wire(f["m_extranonce"], 16),
            m_time_offset=f["m_time_offset"], m_txcount=f["m_txcount"], m_flags=f["m_flags"],
            m_xor_key_mask_clear_bits=f["m_xor_key_mask_clear_bits"],
            m_xor_key=display_to_wire(f["m_xor_key"], 16),
            m_height=f["m_height"],
            m_mm_rhs=display_to_wire(f["m_mm_rhs"], 32),
        )

    def to_vector_fields(self) -> dict:
        return {
            "nVersion": self.nVersion,
            "hashPrevBlock": wire_to_display(self.hashPrevBlock),
            "hashMerkleRoot": wire_to_display(self.hashMerkleRoot),
            "nTime": self.nTime, "nBits": self.nBits, "nNonce": self.nNonce,
            "m_nonce2": self.m_nonce2, "m_nonce3": self.m_nonce3,
            "m_extranonce": wire_to_display(self.m_extranonce),
            "m_time_offset": self.m_time_offset, "m_txcount": self.m_txcount, "m_flags": self.m_flags,
            "m_xor_key_mask_clear_bits": self.m_xor_key_mask_clear_bits,
            "m_xor_key": wire_to_display(self.m_xor_key),
            "m_height": self.m_height,
            "m_mm_rhs": wire_to_display(self.m_mm_rhs),
        }
