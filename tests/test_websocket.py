"""Tests for the WebSocket connection wrapper: send, recv, control frames, close."""

from __future__ import annotations

import struct

import pytest

from transport.ws import (
    OP_BINARY,
    OP_CLOSE,
    OP_CONT,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    ConnectionClosed,
    ProtocolError,
    WebSocket,
)
from tests.conftest import FakeSocket


def _raw(fin: bool, opcode: int, payload: bytes) -> bytes:
    """Build a small unmasked server->client frame with explicit FIN."""
    b0 = (0x80 if fin else 0x00) | opcode
    return bytes([b0, len(payload)]) + payload


# --------------------------------------------------------------------------- #
# Sending
# --------------------------------------------------------------------------- #

def test_client_send_is_masked_server_send_is_not():
    client_sock = FakeSocket()
    WebSocket(client_sock, is_client=True).send("hi")
    assert client_sock.written[1] & 0x80  # masked

    server_sock = FakeSocket()
    WebSocket(server_sock, is_client=False).send("hi")
    assert not (server_sock.written[1] & 0x80)  # unmasked


def test_send_bytes_uses_binary_opcode():
    sock = FakeSocket()
    WebSocket(sock, is_client=False).send_bytes(b"\x01\x02")
    assert sock.written[0] & 0x0F == OP_BINARY


# --------------------------------------------------------------------------- #
# Receiving
# --------------------------------------------------------------------------- #

def test_recv_text_and_binary():
    ws_text = WebSocket(FakeSocket(_raw(True, OP_TEXT, b"hello")), is_client=True)
    assert ws_text.recv() == "hello"

    ws_bin = WebSocket(FakeSocket(_raw(True, OP_BINARY, b"\x00\xff")), is_client=True)
    assert ws_bin.recv() == b"\x00\xff"


def test_recv_reassembles_fragments():
    stream = (
        _raw(False, OP_TEXT, b"Hel")
        + _raw(False, OP_CONT, b"lo ")
        + _raw(True, OP_CONT, b"world")
    )
    assert WebSocket(FakeSocket(stream), is_client=True).recv() == "Hello world"


def test_recv_answers_ping_with_pong():
    sock = FakeSocket(_raw(True, OP_PING, b"pingdata") + _raw(True, OP_TEXT, b"after"))
    conn = WebSocket(sock, is_client=False)
    assert conn.recv() == "after"
    assert sock.written[0] & 0x0F == OP_PONG
    assert bytes(sock.written).endswith(b"pingdata")


def test_recv_ignores_pong():
    sock = FakeSocket(_raw(True, OP_PONG, b"x") + _raw(True, OP_TEXT, b"y"))
    assert WebSocket(sock, is_client=True).recv() == "y"


def test_recv_close_raises_connection_closed():
    payload = struct.pack("!H", 1000) + b"bye"
    conn = WebSocket(FakeSocket(_raw(True, OP_CLOSE, payload)), is_client=True)
    with pytest.raises(ConnectionClosed) as exc:
        conn.recv()
    assert exc.value.code == 1000
    assert exc.value.reason == "bye"


def test_recv_continuation_without_start_raises():
    conn = WebSocket(FakeSocket(_raw(True, OP_CONT, b"orphan")), is_client=True)
    with pytest.raises(ProtocolError):
        conn.recv()


# --------------------------------------------------------------------------- #
# Closing
# --------------------------------------------------------------------------- #

def test_close_sends_close_frame_and_marks_closed():
    sock = FakeSocket()
    conn = WebSocket(sock, is_client=False)
    conn.close(code=1001, reason="going")
    assert sock.closed is True
    assert sock.written[0] & 0x0F == OP_CLOSE


def test_close_is_idempotent():
    sock = FakeSocket()
    conn = WebSocket(sock, is_client=False)
    conn.close()
    written_once = len(sock.written)
    conn.close()  # must not send another frame
    assert len(sock.written) == written_once


def test_send_after_close_raises():
    conn = WebSocket(FakeSocket(), is_client=True)
    conn.close()
    with pytest.raises(ConnectionClosed):
        conn.send("nope")


def test_context_manager_closes_on_exit():
    sock = FakeSocket()
    with WebSocket(sock, is_client=False) as conn:
        conn.send("hi")
    assert sock.closed is True
