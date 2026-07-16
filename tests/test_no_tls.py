"""Tests for the plain-ws:// (no-TLS) transport mode.

Local browser testing runs without a certificate, so the server and client can
drop TLS. Everything above the transport -- HELLO, the Covenant handshake,
sealed relay -- must still work identically; only wire confidentiality is gone.
"""

from __future__ import annotations

import threading
import time

import pytest

from cli.chat_client import ChatClient
from protocol.covenant import CovenantError
from transport import WSSClient


def _connect_plain(host, port):
    ws = WSSClient(host=host, port=port, use_tls=False).connect()
    return ChatClient(ws)


def test_plain_ws_hello(chat_server):
    host, port = chat_server(password=None, use_tls=False)
    a = _connect_plain(host, port)
    ack = a.hello(user_id=1)
    assert ack.password_required is False


def test_plain_ws_open_relay(chat_server):
    host, port = chat_server(password=None, use_tls=False)
    a = _connect_plain(host, port)
    b = _connect_plain(host, port)
    a.hello(user_id=1)
    b.hello(user_id=2)

    received: list = []
    ready = threading.Event()

    def listen():
        ready.set()
        received.append(b.receive())

    t = threading.Thread(target=listen)
    t.start()
    ready.wait()
    time.sleep(0.2)
    a.send("plain hello", sender="A")
    t.join(5)

    assert received == [("plain hello", "A")]


def test_plain_ws_covenant_still_authenticates(chat_server):
    # Layer 3 must work over plain ws exactly as over wss.
    host, port = chat_server(password="pw", use_tls=False)
    a = _connect_plain(host, port)
    b = _connect_plain(host, port)
    a.hello(user_id=1)
    b.hello(user_id=2)
    a.authenticate(b"pw")
    b.authenticate(b"pw")

    received: list = []
    ready = threading.Event()

    def listen():
        ready.set()
        received.append(b.receive())

    t = threading.Thread(target=listen)
    t.start()
    ready.wait()
    time.sleep(0.2)
    a.send("sealed over plain ws", sender="A")
    t.join(5)

    assert received == [("sealed over plain ws", "A")]


def test_plain_ws_wrong_password_rejected(chat_server):
    host, port = chat_server(password="right", use_tls=False)
    a = _connect_plain(host, port)
    a.hello(user_id=1)
    with pytest.raises(CovenantError):
        a.authenticate(b"wrong")
