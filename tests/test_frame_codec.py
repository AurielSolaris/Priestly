"""Tests for the WebSocket frame codec: encode_frame / read_frame."""

from __future__ import annotations

import pytest

from transport.ws import (
    OP_BINARY,
    OP_TEXT,
    ConnectionClosed,
    encode_frame,
    read_frame,
)
from tests.conftest import FakeSocket


@pytest.mark.parametrize("length", [0, 1, 125, 126, 127, 65535, 65536, 70000])
@pytest.mark.parametrize("mask", [False, True])
def test_round_trip(length, mask):
    payload = bytes(i % 256 for i in range(length))
    encoded = encode_frame(OP_BINARY, payload, mask=mask)
    fin, opcode, decoded = read_frame(FakeSocket(encoded))
    assert fin is True
    assert opcode == OP_BINARY
    assert decoded == payload


def test_length_selects_correct_header_width():
    # <126 -> 1 length byte; 126..65535 -> 2-byte ext; >=65536 -> 8-byte ext.
    assert encode_frame(OP_TEXT, b"x" * 10, mask=False)[1] == 10
    assert encode_frame(OP_TEXT, b"x" * 200, mask=False)[1] & 0x7F == 126
    assert encode_frame(OP_TEXT, b"x" * 70000, mask=False)[1] & 0x7F == 127


def test_mask_bit_and_key_present_when_masked():
    frame = encode_frame(OP_TEXT, b"hello", mask=True)
    assert frame[1] & 0x80  # mask bit set
    assert len(frame) == 2 + 4 + 5  # header + 4-byte key + payload
    assert frame[6:] != b"hello"  # payload is masked, not plaintext


def test_unmasked_frame_has_no_mask_bit():
    frame = encode_frame(OP_TEXT, b"hello", mask=False)
    assert not (frame[1] & 0x80)
    assert frame[2:] == b"hello"


def test_read_frame_short_stream_raises():
    with pytest.raises(ConnectionClosed):
        read_frame(FakeSocket(b"\x81"))  # opcode byte only, no length
