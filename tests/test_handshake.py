"""Tests for the WebSocket opening handshake (server and client sides)."""

from __future__ import annotations

import base64

import pytest

from transport import ws
from transport.ws import (
    ProtocolError,
    accept_token,
    client_handshake,
    server_handshake,
)
from tests.conftest import FakeSocket


def test_accept_token_rfc_vector():
    # The canonical example from RFC 6455 section 1.3.
    assert accept_token("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="


def _http_request(key: str = "dGhlIHNhbXBsZSBub25jZQ==") -> bytes:
    return (
        f"GET /chat HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()


# --------------------------------------------------------------------------- #
# Server side
# --------------------------------------------------------------------------- #

def test_server_writes_correct_accept():
    sock = FakeSocket(_http_request())
    headers = server_handshake(sock)
    assert headers["upgrade"] == "websocket"
    response = bytes(sock.written).decode()
    assert response.startswith("HTTP/1.1 101")
    assert "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" in response


def test_server_missing_key_raises():
    req = _http_request().replace(b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n", b"")
    with pytest.raises(ProtocolError):
        server_handshake(FakeSocket(req))


def test_server_non_get_raises():
    req = _http_request().replace(b"GET", b"POST", 1)
    with pytest.raises(ProtocolError):
        server_handshake(FakeSocket(req))


def test_server_missing_upgrade_raises():
    req = _http_request().replace(b"Upgrade: websocket\r\n", b"")
    with pytest.raises(ProtocolError):
        server_handshake(FakeSocket(req))


def test_oversized_header_block_raises():
    junk = b"GET / HTTP/1.1\r\nX: " + b"a" * (ws._MAX_HEADER_BYTES + 10)
    with pytest.raises(ProtocolError):
        server_handshake(FakeSocket(junk))


# --------------------------------------------------------------------------- #
# Client side
# --------------------------------------------------------------------------- #

def test_client_happy_path(monkeypatch):
    monkeypatch.setattr(ws.os, "urandom", lambda n: b"\x00" * n)
    key = base64.b64encode(b"\x00" * 16).decode()
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        f"Sec-WebSocket-Accept: {accept_token(key)}\r\n\r\n"
    ).encode()
    sock = FakeSocket(response)
    headers = client_handshake(sock, host="localhost")
    assert headers["upgrade"] == "websocket"
    assert b"Sec-WebSocket-Key" in bytes(sock.written)


def test_client_rejects_non_101(monkeypatch):
    monkeypatch.setattr(ws.os, "urandom", lambda n: b"\x00" * n)
    sock = FakeSocket(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    with pytest.raises(ProtocolError):
        client_handshake(sock, host="localhost")


def test_client_rejects_bad_accept(monkeypatch):
    monkeypatch.setattr(ws.os, "urandom", lambda n: b"\x00" * n)
    sock = FakeSocket(
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Sec-WebSocket-Accept: wrong\r\n\r\n"
    )
    with pytest.raises(ProtocolError):
        client_handshake(sock, host="localhost")
