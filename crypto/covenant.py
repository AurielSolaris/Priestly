"""Covenant PAKE primitives -- Layer 3's cryptographic core.

An anonymous Password-Authenticated Key Exchange inspired by WPA3's SAE,
stripped to its essence. Two peers that share a secret derive the same session
key ``G^{ab} mod P`` without ever transmitting the secret; a peer that does not
know the secret cannot complete the exchange, and an eavesdropper cannot mount
an offline dictionary attack on the transcript.

This module holds the *math only* -- deterministic, side-effect-free functions.
The message flow that drives them over a live connection lives in
``protocol.covenant``. Everything here is stdlib + ``crypto.hmac_sha256``.
"""

from __future__ import annotations

import secrets

from .hkdf import hkdf_expand
from .hmac_sha256 import sign_bytes
from .sha1 import sha1

# RFC 3526 Group 14 (2048-bit MODP). Public, hardcoded, identical on every node.
# The browser client hardcodes the identical value, so both derive the same
# group; the hex is grouped in 64-char rows exactly as it appears in the RFC.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "0"
    "20BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374"
    "FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598D"
    "A48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED5"
    "29077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E7"
    "72C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2

# Number of bytes in a group element (2048 bits) -- the fixed wire width.
ELEMENT_BYTES = 256

_MAP_LABEL = b"Priestly-Covenant-Map"


# --------------------------------------------------------------------------- #
# Modular inverse (Extended Euclidean Algorithm)
# --------------------------------------------------------------------------- #

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return ``(g, x, y)`` with ``a*x + b*y == g == gcd(a, b)``.

    Iterative to avoid Python's recursion limit on 2048-bit inputs.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def modinv(a: int, m: int) -> int:
    """Modular multiplicative inverse of ``a`` mod ``m``."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("no modular inverse exists")
    return x % m


# --------------------------------------------------------------------------- #
# Password -> group element
# --------------------------------------------------------------------------- #

def secret_to_element(password: bytes, p: int = P) -> int:
    """Map a shared secret deterministically into the group.

    Squaring forces a quadratic residue (a simplified Dragonfly step). The
    result is non-zero mod ``p`` and therefore invertible, which the client
    relies on to unmask the server's challenge.
    """
    h = sign_bytes(password, _MAP_LABEL)
    val = int.from_bytes(h, "big") % p
    if val == 0:
        val = 1
    return pow(val, 2, p)


# --------------------------------------------------------------------------- #
# Ephemeral key pairs and the shared secret
# --------------------------------------------------------------------------- #

def random_exponent() -> int:
    """A fresh private exponent in ``[1, P-1)`` -- discarded after the handshake
    (this ephemerality is what gives the session forward secrecy)."""
    return secrets.randbelow(P - 2) + 1


def public_element(exponent: int) -> int:
    """``G^exponent mod P`` -- the value a peer contributes to the exchange."""
    return pow(G, exponent, P)


def commit_digest(public: int) -> bytes:
    """SHA-1 commitment to a public element (binds the client's choice of A)."""
    return sha1(public.to_bytes(ELEMENT_BYTES, "big"))


def mask(public_b: int, pe: int) -> int:
    """Server-side: hide B behind the password element -> ``(B * PE) mod P``."""
    return (public_b * pe) % P


def unmask(masked_b: int, pe: int) -> int:
    """Client-side: recover B from the masked challenge using ``PE^-1``."""
    return (masked_b * modinv(pe, P)) % P


def shared_secret(peer_public: int, own_exponent: int) -> int:
    """Diffie-Hellman shared value ``peer_public^own_exponent mod P``."""
    return pow(peer_public, own_exponent, P)


# --------------------------------------------------------------------------- #
# Key-confirmation MACs
# --------------------------------------------------------------------------- #

def confirm_mac(shared: int, commit: bytes, role: bytes, public: int) -> bytes:
    """Key-confirmation tag proving knowledge of ``shared``.

    Keyed by the shared secret and bound to the transcript (``commit`` +
    role label + the sender's public element), so a peer that derived a
    different shared secret -- i.e. did not know the password -- produces a tag
    that will not verify.
    """
    message = commit + role + public.to_bytes(ELEMENT_BYTES, "big")
    return sign_bytes(shared.to_bytes(ELEMENT_BYTES, "big"), message)


# --------------------------------------------------------------------------- #
# Session-key derivation (WPA3-style directional separation)
# --------------------------------------------------------------------------- #

def derive_session_keys(shared: int) -> dict[str, bytes]:
    """Expand the shared secret into four independent directional subkeys.

    Client and server each get their own write key and MAC key, so a message
    authored by one side can never verify as though authored by the other.
    """
    prk = shared.to_bytes(ELEMENT_BYTES, "big")
    return {
        "client_write": hkdf_expand(prk, b"Priestly-v1-client-write", 32),
        "server_write": hkdf_expand(prk, b"Priestly-v1-server-write", 32),
        "client_mac": hkdf_expand(prk, b"Priestly-v1-client-mac", 32),
        "server_mac": hkdf_expand(prk, b"Priestly-v1-server-mac", 32),
    }
