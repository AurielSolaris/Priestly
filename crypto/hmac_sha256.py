"""HMAC-SHA256 authentication -- the keyed security layer above SHA-1.

SHA-1 (``crypto/sha1.py``) is an *unkeyed* integrity digest: it detects
accidental corruption, but anyone can recompute it, so it proves nothing about
*who* produced a payload. HMAC-SHA256 mixes in a shared secret key, so only a
holder of the key can produce a valid tag -- this authenticates the sender and
detects tampering by an active attacker.

Deliberately NOT hand-rolled. A keyed MAC is security-critical and easy to get
subtly wrong, so this uses the standard library's audited, constant-time
``hmac`` over ``hashlib.sha256`` rather than a from-scratch implementation.
"""

from __future__ import annotations

import hashlib
import hmac

_DIGEST = hashlib.sha256


def sign(key: bytes, data: bytes) -> str:
    """Return the hex HMAC-SHA256 tag authenticating ``data`` under ``key``."""
    return hmac.new(key, data, _DIGEST).hexdigest()


def sign_bytes(key: bytes, data: bytes) -> bytes:
    """Return the raw 32-byte HMAC-SHA256 tag.

    The hex form (:func:`sign`) is what travels on the wire; the raw bytes are
    what the PRF-based constructions (HKDF, the Covenant PAKE) build on.
    """
    return hmac.new(key, data, _DIGEST).digest()


def verify(key: bytes, data: bytes, tag: str) -> bool:
    """Constant-time check that ``tag`` is a valid HMAC for ``data``/``key``.

    Uses ``hmac.compare_digest`` so verification time does not leak how much of
    the tag matched.
    """
    return hmac.compare_digest(sign(key, data), tag)
