"""Tests for HKDF-Expand (crypto/hkdf.py)."""

from __future__ import annotations

import pytest

from crypto.hkdf import hkdf_expand


def test_rfc5869_appendix_a1_vector():
    # RFC 5869 Appendix A.1: the Expand step for the basic SHA-256 case.
    prk = bytes.fromhex(
        "077709362c2e32df0ddc3f0dc47bba63"
        "90b6c73bb50f9c3122ec844ad7c2b3e5"
    )
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert hkdf_expand(prk, info, 42) == okm


@pytest.mark.parametrize("length", [0, 1, 31, 32, 33, 64, 255 * 32])
def test_output_length(length):
    assert len(hkdf_expand(b"prk", b"info", length)) == length


def test_different_info_gives_independent_output():
    a = hkdf_expand(b"prk-material", b"label-a", 32)
    b = hkdf_expand(b"prk-material", b"label-b", 32)
    assert a != b


def test_deterministic():
    assert hkdf_expand(b"prk", b"info", 40) == hkdf_expand(b"prk", b"info", 40)


def test_prefix_property():
    # HKDF-Expand output for a shorter length is a prefix of a longer one.
    long = hkdf_expand(b"prk", b"info", 64)
    short = hkdf_expand(b"prk", b"info", 20)
    assert long[:20] == short


def test_too_long_rejected():
    with pytest.raises(ValueError):
        hkdf_expand(b"prk", b"info", 255 * 32 + 1)


def test_negative_length_rejected():
    with pytest.raises(ValueError):
        hkdf_expand(b"prk", b"info", -1)
