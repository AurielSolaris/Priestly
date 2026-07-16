"""End-to-end tests over a real TLS + WebSocket connection to a live server."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from protocol import (
    AckFrame,
    ErrorFrame,
    Handshake,
    HelloFrame,
    Message,
    MessageFrame,
    dumps,
    loads,
)
from transport import ConnectionClosed, WSSClient
from tests.conftest import CERT


def _hello(id_: int = 1) -> HelloFrame:
    return HelloFrame(handshake=Handshake(
        id=id_, user_id=42, device_id=7, timestamp=datetime.now(timezone.utc), status="init",
    ))


def _message(id_: int, text: str) -> MessageFrame:
    return MessageFrame(message=Message(
        id=id_, sender_id=42, receiver_id=99,
        ciphertext=text, timestamp=datetime.now(timezone.utc), status="sent",
    ))


def test_hello_is_acked(client):
    client.send(dumps(_hello(id_=1)))
    reply = loads(client.recv())
    assert isinstance(reply, AckFrame)
    assert reply.ref_id == 1


def test_message_is_acked(client):
    client.send(dumps(_message(100, "ciphertext")))
    reply = loads(client.recv())
    assert isinstance(reply, AckFrame)
    assert reply.ref_id == 100


def test_multiple_sequential_messages(client):
    for i in range(1, 6):
        client.send(dumps(_message(i, f"m{i}")))
        assert loads(client.recv()).ref_id == i


def test_large_message_round_trips(client):
    # ~500 KB drives the 64-bit frame-length path through real TLS.
    big = "x" * 500_000
    client.send(dumps(_message(200, big)))
    reply = loads(client.recv())
    assert isinstance(reply, AckFrame)
    assert reply.ref_id == 200


def test_unexpected_frame_gets_error(client):
    # A client should never send an ACK; the server rejects it.
    client.send(dumps(AckFrame(ref_id=5)))
    reply = loads(client.recv())
    assert isinstance(reply, ErrorFrame)
    assert reply.code == 422


def test_malformed_text_gets_error(client):
    client.send("this is not a packet")
    reply = loads(client.recv())
    assert isinstance(reply, ErrorFrame)
    assert reply.code == 400


def test_wrong_ca_is_rejected(live_server):
    # Connecting with verification on but no trusted CA must fail the TLS
    # handshake -- proof the transport is genuinely authenticated.
    host, port = live_server
    with pytest.raises(Exception):
        WSSClient(host=host, port=port, cafile=None).connect()


def test_insecure_client_can_connect(live_server):
    host, port = live_server
    ws = WSSClient(host=host, port=port, insecure=True).connect()
    try:
        ws.send(dumps(_hello(id_=9)))
        assert loads(ws.recv()).ref_id == 9
    finally:
        ws.close()


def test_full_session_flow(live_server):
    """Scripted happy path: connect -> HELLO -> MESSAGE -> ACK -> clean close."""
    host, port = live_server

    # start server (fixture) + connect client
    ws = WSSClient(host=host, port=port, cafile=str(CERT)).connect()

    # HELLO -> ACK
    ws.send(dumps(_hello(id_=1)))
    hello_ack = loads(ws.recv())
    assert isinstance(hello_ack, AckFrame)
    assert hello_ack.ref_id == 1

    # MESSAGE -> ACK
    ws.send(dumps(_message(100, "ciphertext-body")))
    message_ack = loads(ws.recv())
    assert isinstance(message_ack, AckFrame)
    assert message_ack.ref_id == 100

    # disconnect cleanly
    ws.close()
    with pytest.raises(ConnectionClosed):
        ws.recv()


def test_recv_after_server_closes_raises(live_server):
    host, port = live_server
    ws = WSSClient(host=host, port=port, insecure=True).connect()
    ws.close()
    with pytest.raises(ConnectionClosed):
        ws.recv()
