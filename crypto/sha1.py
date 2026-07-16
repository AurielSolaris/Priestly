"""SHA-1 implemented from scratch (RFC 3174), plus payload validity helpers.

Used to verify the validity of a handshake or message: the sender attaches the
SHA-1 tag of the payload, and the receiver recomputes and compares it. The
digest itself is hand-rolled so nothing outside the standard library is needed
for the core algorithm; ``hmac.compare_digest`` is used only for a constant-time
tag comparison.

Note: SHA-1 is a good fit for an integrity/validity check but is NOT collision
resistant -- do not use it as a security signature against an active attacker.
"""

from __future__ import annotations

import hmac

# Initial hash values (RFC 3174 section 6.1).
_H0 = 0x67452301
_H1 = 0xEFCDAB89
_H2 = 0x98BADCFE
_H3 = 0x10325476
_H4 = 0xC3D2E1F0

_MASK32 = 0xFFFFFFFF


def _rotl(value: int, amount: int) -> int:
    """Rotate a 32-bit word left by ``amount`` bits."""
    return ((value << amount) | (value >> (32 - amount))) & _MASK32


def sha1(data: bytes) -> bytes:
    """Return the 20-byte SHA-1 digest of ``data``."""
    h0, h1, h2, h3, h4 = _H0, _H1, _H2, _H3, _H4

    # Pre-processing: append 0x80, pad with zeros to 56 mod 64, then the
    # original message length in bits as a 64-bit big-endian integer.
    message = bytearray(data)
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0x00)
    message += bit_len.to_bytes(8, "big")

    for offset in range(0, len(message), 64):
        block = message[offset:offset + 64]
        w = [0] * 80
        for i in range(16):
            w[i] = int.from_bytes(block[i * 4:i * 4 + 4], "big")
        for i in range(16, 80):
            w[i] = _rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)

        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20:
                f = (b & c) | ((~b & _MASK32) & d)
                k = 0x5A827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (_rotl(a, 5) + f + e + k + w[i]) & _MASK32
            a, b, c, d, e = temp, a, _rotl(b, 30), c, d

        h0 = (h0 + a) & _MASK32
        h1 = (h1 + b) & _MASK32
        h2 = (h2 + c) & _MASK32
        h3 = (h3 + d) & _MASK32
        h4 = (h4 + e) & _MASK32

    return b"".join(h.to_bytes(4, "big") for h in (h0, h1, h2, h3, h4))


def hexdigest(data: bytes) -> str:
    """Return the SHA-1 digest of ``data`` as a lowercase hex string."""
    return sha1(data).hex()


def tag(data: bytes) -> str:
    """Compute the validity tag (hex SHA-1) attached to a payload."""
    return hexdigest(data)


def verify(data: bytes, expected_tag: str) -> bool:
    """Constant-time check that ``data`` matches a previously computed tag."""
    return hmac.compare_digest(tag(data), expected_tag)
