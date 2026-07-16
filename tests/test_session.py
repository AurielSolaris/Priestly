"""Tests for the sealed-message session (protocol/session.py)."""

from __future__ import annotations

import base64

import pytest

from crypto.covenant import derive_session_keys
from protocol.session import (
    AuthenticationError,
    ReplayError,
    SessionState,
    compute_tag,
    pack,
    unpack,
)


def _key_pair():
    keys = derive_session_keys(0xABCDEF)
    return SessionState(keys, is_client=True), SessionState(keys, is_client=False)


# --------------------------------------------------------------------------- #
# pack / unpack (compression marker)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "data",
    [b"", b"a", b"A" * 1000, bytes(range(256)), b"the quick brown fox"],
)
def test_pack_unpack_roundtrip(data):
    assert unpack(pack(data)) == data


def test_pack_uses_huffman_only_when_smaller():
    repetitive = b"A" * 500
    assert pack(repetitive)[0] == 0x01  # huffman marker
    random_ish = bytes(range(256))
    assert pack(random_ish)[0] == 0x00  # stored (compression would not help)


def test_unpack_rejects_unknown_marker():
    with pytest.raises(AuthenticationError):
        unpack(b"\x09garbage")


def test_unpack_rejects_empty():
    with pytest.raises(AuthenticationError):
        unpack(b"")


# --------------------------------------------------------------------------- #
# seal / open round trips
# --------------------------------------------------------------------------- #

def test_client_to_server_roundtrip():
    client, server = _key_pair()
    frame = client.seal(b"hello server")
    assert server.open(frame) == b"hello server"


def test_server_to_client_roundtrip():
    client, server = _key_pair()
    frame = server.seal(b"hello client")
    assert client.open(frame) == b"hello client"


def test_sequence_numbers_increment():
    client, server = _key_pair()
    assert client.seal(b"a").seq == 1
    assert client.seal(b"b").seq == 2
    assert client.seal(b"c").seq == 3


def test_large_payload_roundtrip():
    client, server = _key_pair()
    data = b"x" * 200_000
    assert server.open(client.seal(data)) == data


# --------------------------------------------------------------------------- #
# Security properties
# --------------------------------------------------------------------------- #

def test_replay_is_rejected():
    client, server = _key_pair()
    frame = client.seal(b"once")
    assert server.open(frame) == b"once"
    with pytest.raises(ReplayError):
        server.open(frame)


def test_out_of_order_lower_seq_rejected():
    client, server = _key_pair()
    f1, f2 = client.seal(b"1"), client.seal(b"2")
    assert server.open(f2) == b"2"
    with pytest.raises(ReplayError):
        server.open(f1)  # seq 1 after seq 2


def test_tampered_tag_rejected():
    client, server = _key_pair()
    frame = client.seal(b"data")
    frame.tag = "0" * 64
    with pytest.raises(AuthenticationError):
        server.open(frame)


def test_tampered_payload_rejected():
    client, server = _key_pair()
    frame = client.seal(b"data")
    frame.payload = base64.b64encode(b"\x00tampered").decode()
    with pytest.raises(AuthenticationError):
        server.open(frame)


def test_wrong_direction_rejected():
    client, server = _key_pair()
    # A client frame fed back to another client (same direction) must fail.
    other_client, _ = _key_pair()
    frame = client.seal(b"data")
    with pytest.raises(AuthenticationError):
        other_client.open(frame)  # client expects "server" direction


def test_invalid_base64_rejected():
    client, server = _key_pair()
    frame = client.seal(b"data")
    frame.payload = "!!!not base64!!!"
    with pytest.raises(AuthenticationError):
        server.open(frame)


def test_different_keys_do_not_verify():
    client_a = SessionState(derive_session_keys(1), is_client=True)
    server_b = SessionState(derive_session_keys(2), is_client=False)
    with pytest.raises(AuthenticationError):
        server_b.open(client_a.seal(b"data"))


# --------------------------------------------------------------------------- #
# compute_tag
# --------------------------------------------------------------------------- #

def test_compute_tag_binds_direction():
    key = b"k" * 32
    c = compute_tag(key, 0, 1, "client", b"p")
    s = compute_tag(key, 0, 1, "server", b"p")
    assert c != s


def test_compute_tag_binds_epoch_and_seq():
    key = b"k" * 32
    assert compute_tag(key, 0, 1, "client", b"p") != compute_tag(key, 1, 1, "client", b"p")
    assert compute_tag(key, 0, 1, "client", b"p") != compute_tag(key, 0, 2, "client", b"p")
