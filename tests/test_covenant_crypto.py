"""Tests for the Covenant PAKE primitives (crypto/covenant.py)."""

from __future__ import annotations

import pytest

from crypto import covenant as cv


# --------------------------------------------------------------------------- #
# Modular inverse / extended gcd
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("a", [1, 2, 3, 5, 12345, cv.P - 2, 2**200 + 1])
def test_modinv_matches_pow_oracle(a):
    # Python 3.8+ can compute pow(a, -1, m) directly -- use it as an oracle.
    assert cv.modinv(a, cv.P) == pow(a, -1, cv.P)


def test_modinv_roundtrip():
    a = 987654321
    inv = cv.modinv(a, cv.P)
    assert (a * inv) % cv.P == 1


def test_extended_gcd_identity():
    a, b = 240, 46
    g, x, y = cv.extended_gcd(a, b)
    assert g == 2
    assert a * x + b * y == g


def test_modinv_no_inverse_raises():
    # No inverse mod a composite when gcd != 1.
    with pytest.raises(ValueError):
        cv.modinv(4, 8)


# --------------------------------------------------------------------------- #
# secret_to_element
# --------------------------------------------------------------------------- #

def test_secret_to_element_deterministic():
    assert cv.secret_to_element(b"pw") == cv.secret_to_element(b"pw")


def test_secret_to_element_differs_by_password():
    assert cv.secret_to_element(b"pw1") != cv.secret_to_element(b"pw2")


def test_secret_to_element_is_invertible():
    pe = cv.secret_to_element(b"anything")
    assert 0 < pe < cv.P
    assert cv.modinv(pe, cv.P)  # does not raise


# --------------------------------------------------------------------------- #
# mask / unmask / shared secret
# --------------------------------------------------------------------------- #

def test_mask_unmask_roundtrip():
    b = cv.random_exponent()
    public_b = cv.public_element(b)
    pe = cv.secret_to_element(b"shared")
    assert cv.unmask(cv.mask(public_b, pe), pe) == public_b


def test_full_agreement_with_matching_password():
    pw = b"matching"
    a = cv.random_exponent(); A = cv.public_element(a)
    b = cv.random_exponent(); B = cv.public_element(b)
    pe = cv.secret_to_element(pw)
    B_recovered = cv.unmask(cv.mask(B, pe), pe)
    assert cv.shared_secret(B_recovered, a) == cv.shared_secret(A, b)


def test_wrong_password_diverges():
    a = cv.random_exponent(); A = cv.public_element(a)
    b = cv.random_exponent(); B = cv.public_element(b)
    masked = cv.mask(B, cv.secret_to_element(b"right"))
    B_wrong = cv.unmask(masked, cv.secret_to_element(b"wrong"))
    assert cv.shared_secret(B_wrong, a) != cv.shared_secret(A, b)


# --------------------------------------------------------------------------- #
# Commit + confirmation MACs
# --------------------------------------------------------------------------- #

def test_commit_digest_is_sha1_width():
    assert len(cv.commit_digest(cv.public_element(cv.random_exponent()))) == 20


def test_confirm_mac_agrees_for_same_shared():
    shared = 123456789
    commit = b"\x01" * 20
    pub = cv.public_element(2)
    assert cv.confirm_mac(shared, commit, b"client", pub) == cv.confirm_mac(
        shared, commit, b"client", pub
    )


def test_confirm_mac_differs_by_role():
    shared, commit, pub = 42, b"\x00" * 20, cv.public_element(3)
    assert cv.confirm_mac(shared, commit, b"client", pub) != cv.confirm_mac(
        shared, commit, b"server", pub
    )


def test_confirm_mac_differs_by_shared_secret():
    commit, pub = b"\x00" * 20, cv.public_element(3)
    assert cv.confirm_mac(1, commit, b"client", pub) != cv.confirm_mac(
        2, commit, b"client", pub
    )


# --------------------------------------------------------------------------- #
# Session-key derivation
# --------------------------------------------------------------------------- #

def test_derive_session_keys_are_distinct_and_sized():
    keys = cv.derive_session_keys(cv.shared_secret(cv.public_element(5), 7))
    assert set(keys) == {"client_write", "server_write", "client_mac", "server_mac"}
    assert all(len(v) == 32 for v in keys.values())
    assert len(set(keys.values())) == 4  # all independent


def test_derive_session_keys_deterministic():
    shared = 555
    assert cv.derive_session_keys(shared) == cv.derive_session_keys(shared)


def test_random_exponent_in_range():
    for _ in range(20):
        e = cv.random_exponent()
        assert 1 <= e < cv.P - 1
