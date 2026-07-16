"""Crypto layer: integrity (SHA-1), authenticity (HMAC-SHA256), compression
(Huffman), key derivation (HKDF), and the Covenant PAKE -- all from scratch or
on the stdlib, no external crypto libraries."""

from . import covenant, hkdf, hmac_sha256, huffman
from .hkdf import hkdf_expand
from .sha1 import hexdigest, sha1, tag, verify

__all__ = [
    "sha1",
    "hexdigest",
    "tag",
    "verify",
    "huffman",
    "hmac_sha256",
    "hkdf",
    "hkdf_expand",
    "covenant",
]
