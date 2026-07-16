"""Tests for malformed / truncated WebSocket frame handling.

read_frame must reject frames that violate RFC 6455 with ProtocolError, and
must surface a truncated stream as ConnectionClosed rather than an index error
or a hang. WebSocket.recv must propagate the same failures.
"""

from __future__ import annotations

import pytest

from transport.ws import (
    OP_BINARY,
    OP_PING,
    OP_TEXT,
    ConnectionClosed,
    ProtocolError,
    WebSocket,
    read_frame,
)
from tests.conftest import FakeSocket


# --------------------------------------------------------------------------- #
# Truncated streams -> ConnectionClosed
# --------------------------------------------------------------------------- #

def test_header_only_first_byte():
    with pytest.raises(ConnectionClosed):
        read_frame(FakeSocket(b"\x81"))  # opcode byte, no length byte


def test_missing_16bit_extended_length():
    # length marker 126 promises 2 more length bytes that never arrive.
    with pytest.raises(ConnectionClosed):
        read_frame(FakeSocket(bytes([0x80 | OP_TEXT, 126])))


def test_missing_64bit_extended_length():
    with pytest.raises(ConnectionClosed):
        read_frame(FakeSocket(bytes([0x80 | OP_TEXT, 127, 0x00])))  # only 1 of 8


def test_missing_masking_key():
    # mask bit set, length 3, but no masking key / payload follows.
    with pytest.raises(ConnectionClosed):
        read_frame(FakeSocket(bytes([0x80 | OP_TEXT, 0x80 | 3])))


def test_payload_shorter_than_declared():
    # declares 10 bytes, provides 3.
    frame = bytes([0x80 | OP_BINARY, 10]) + b"abc"
    with pytest.raises(ConnectionClosed):
        read_frame(FakeSocket(frame))


# --------------------------------------------------------------------------- #
# Protocol violations -> ProtocolError
# --------------------------------------------------------------------------- #

def test_reserved_bits_rejected():
    # RSV1 set (0x40) with a normal text frame.
    with pytest.raises(ProtocolError, match="reserved bits"):
        read_frame(FakeSocket(bytes([0x80 | 0x40 | OP_TEXT, 0])))


@pytest.mark.parametrize("opcode", [0x3, 0x4, 0x5, 0x6, 0x7, 0xB, 0xC, 0xF])
def test_unknown_opcode_rejected(opcode):
    with pytest.raises(ProtocolError, match="unknown opcode"):
        read_frame(FakeSocket(bytes([0x80 | opcode, 0])))


def test_fragmented_control_frame_rejected():
    # PING with FIN=0 is illegal (control frames cannot be fragmented).
    with pytest.raises(ProtocolError, match="must not be fragmented"):
        read_frame(FakeSocket(bytes([OP_PING, 3]) + b"abc"))


def test_oversized_control_frame_rejected():
    # PING declaring a 200-byte payload exceeds the 125-byte control limit.
    frame = bytes([0x80 | OP_PING, 126, 0x00, 0xC8]) + b"x" * 200
    with pytest.raises(ProtocolError, match="control frame payload too large"):
        read_frame(FakeSocket(frame))


# --------------------------------------------------------------------------- #
# WebSocket.recv propagates the failures
# --------------------------------------------------------------------------- #

def test_recv_propagates_protocol_error():
    conn = WebSocket(FakeSocket(bytes([0x80 | 0x40 | OP_TEXT, 0])), is_client=True)
    with pytest.raises(ProtocolError):
        conn.recv()


def test_recv_propagates_truncation_as_closed():
    conn = WebSocket(FakeSocket(b"\x81"), is_client=True)
    with pytest.raises(ConnectionClosed):
        conn.recv()
