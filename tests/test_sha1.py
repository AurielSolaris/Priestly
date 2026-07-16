"""Tests for the from-scratch SHA-1 (crypto/sha1.py).

Correctness is checked against the standard library's ``hashlib`` as an oracle,
plus the canonical RFC 3174 vectors and the padding boundaries around the
64-byte block size.
"""

from __future__ import annotations

import hashlib
import os

import pytest

from crypto.sha1 import hexdigest, sha1, tag, verify


def test_empty_vector():
    assert hexdigest(b"") == "da39a3ee5e6b4b0d3255bfef95601890afd80709"


def test_abc_vector():
    assert hexdigest(b"abc") == "a9993e364706816aba3e25717850c26c9cd0d89d"


def test_rfc_two_block_vector():
    msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    assert hexdigest(msg) == "84983e441c3bd26ebaae4aa1f95129e5e54670f1"


@pytest.mark.parametrize("length", [0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 1000])
def test_matches_hashlib_by_length(length):
    data = bytes((i * 37) % 256 for i in range(length))
    assert sha1(data) == hashlib.sha1(data).digest()


@pytest.mark.parametrize("_", range(50))
def test_matches_hashlib_random(_):
    data = os.urandom(os.urandom(1)[0])  # 0..255 random bytes
    assert hexdigest(data) == hashlib.sha1(data).hexdigest()


def test_digest_is_20_bytes():
    assert len(sha1(b"anything")) == 20


# --------------------------------------------------------------------------- #
# Validity tag / verify
# --------------------------------------------------------------------------- #

def test_tag_equals_hexdigest():
    assert tag(b"payload") == hexdigest(b"payload")


def test_verify_accepts_correct_tag():
    data = b"handshake-bytes"
    assert verify(data, tag(data)) is True


def test_verify_rejects_tampered_data():
    good = tag(b"handshake-bytes")
    assert verify(b"handshake-bytez", good) is False


def test_verify_rejects_wrong_tag():
    assert verify(b"data", "0" * 40) is False
