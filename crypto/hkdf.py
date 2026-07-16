"""HKDF-Expand (RFC 5869) using HMAC-SHA256 as the PRF.

Only the *Expand* half is implemented: the Covenant PAKE produces a shared
secret that is already uniformly distributed over the group, so it serves
directly as the pseudorandom key (PRK) and the Extract step would add nothing.
Expand then stretches that PRK into as many independent, labelled subkeys as the
session needs (one per direction, one per purpose).

Built on ``crypto.hmac_sha256`` -- no external dependency.
"""

from __future__ import annotations

from .hmac_sha256 import sign_bytes

_HASH_LEN = 32  # SHA-256 output size


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """Expand ``prk`` into ``length`` bytes of output keying material.

    ``info`` binds the output to a specific purpose, so two different labels
    yield cryptographically independent keys from the same PRK.
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    n = (length + _HASH_LEN - 1) // _HASH_LEN
    if n > 255:
        raise ValueError("requested length too large for HKDF-Expand")

    okm = bytearray()
    previous = b""
    for counter in range(1, n + 1):
        previous = sign_bytes(prk, previous + info + bytes([counter]))
        okm += previous
    return bytes(okm[:length])
