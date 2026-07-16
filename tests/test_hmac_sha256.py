"""Tests for the HMAC-SHA256 authentication layer (crypto/hmac_sha256.py)."""

from __future__ import annotations

import hashlib
import hmac
import os

import pytest

from crypto.hmac_sha256 import sign, verify


def test_canonical_vector():
    # Well-known HMAC-SHA256 test vector.
    key = b"key"
    data = b"The quick brown fox jumps over the lazy dog"
    assert sign(key, data) == (
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    )


@pytest.mark.parametrize("_", range(50))
def test_matches_stdlib_oracle(_):
    key = os.urandom(os.urandom(1)[0] or 1)
    data = os.urandom(os.urandom(1)[0])
    assert sign(key, data) == hmac.new(key, data, hashlib.sha256).hexdigest()


def test_deterministic():
    assert sign(b"k", b"payload") == sign(b"k", b"payload")


def test_tag_is_64_hex_chars():
    tag = sign(b"k", b"payload")
    assert len(tag) == 64
    assert all(c in "0123456789abcdef" for c in tag)


# --------------------------------------------------------------------------- #
# Verification (authenticity)
# --------------------------------------------------------------------------- #

def test_verify_accepts_valid_tag():
    key, data = b"secret", b"authentic message"
    assert verify(key, data, sign(key, data)) is True


def test_verify_rejects_tampered_data():
    key = b"secret"
    tag = sign(key, b"authentic message")
    assert verify(key, b"authentic messagE", tag) is False


def test_verify_rejects_wrong_key():
    data = b"authentic message"
    tag = sign(b"secret", data)
    assert verify(b"attacker-key", data, tag) is False


def test_verify_rejects_garbage_tag():
    assert verify(b"secret", b"data", "0" * 64) is False
    assert verify(b"secret", b"data", "not-a-tag") is False


def test_empty_key_and_data_are_handled():
    assert verify(b"", b"", sign(b"", b"")) is True
