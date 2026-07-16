"""End-to-end chat tests: two clients through one central WSS server.

Exercises the full stack -- TLS, WebSocket, HELLO/HELLO_ACK, the Covenant
handshake, sealed relay -- in both open and password-protected modes. All
traffic goes through the server (the hub relays); clients never talk directly.
"""

from __future__ import annotations

import threading

import pytest

from cli.chat_client import ChatClient
from protocol.covenant import CovenantError
from transport import WSSClient

from tests.conftest import CERT


def _connect(host, port):
    ws = WSSClient(host=host, port=port, cafile=str(CERT)).connect()
    return ChatClient(ws)


# --------------------------------------------------------------------------- #
# Open mode (no password)
# --------------------------------------------------------------------------- #

def test_open_mode_hello_reports_no_password(chat_server):
    host, port = chat_server(password=None, server_name="open-node")
    a = _connect(host, port)
    ack = a.hello(user_id=1)
    assert ack.password_required is False
    assert a.server_name == "open-node"


def test_open_mode_relay_between_two_clients(chat_server):
    host, port = chat_server(password=None)
    a = _connect(host, port)
    b = _connect(host, port)
    a.hello(user_id=1)
    b.hello(user_id=2)

    # b listens in a thread; a sends.
    received: list = []
    ready = threading.Event()

    def listen():
        ready.set()
        received.append(b.receive())

    t = threading.Thread(target=listen)
    t.start()
    ready.wait()
    import time
    time.sleep(0.2)  # ensure b is blocked in recv before a sends
    a.send("hello from A", sender="A")
    t.join(5)

    assert received == [("hello from A", "A")]


# --------------------------------------------------------------------------- #
# Password-protected mode (Covenant)
# --------------------------------------------------------------------------- #

def test_password_mode_hello_reports_required(chat_server):
    host, port = chat_server(password="s3cret")
    a = _connect(host, port)
    ack = a.hello(user_id=1)
    assert ack.password_required is True


def test_correct_password_authenticates_and_relays(chat_server):
    host, port = chat_server(password="covenant-pw")
    a = _connect(host, port)
    b = _connect(host, port)
    a.hello(user_id=1)
    b.hello(user_id=2)
    a.authenticate(b"covenant-pw")
    b.authenticate(b"covenant-pw")

    received: list = []
    ready = threading.Event()

    def listen():
        ready.set()
        received.append(b.receive())

    t = threading.Thread(target=listen)
    t.start()
    ready.wait()
    import time
    time.sleep(0.2)
    a.send("sealed hello", sender="A")
    t.join(5)

    assert received == [("sealed hello", "A")]


def test_wrong_password_is_rejected(chat_server):
    host, port = chat_server(password="right-password")
    a = _connect(host, port)
    a.hello(user_id=1)
    with pytest.raises(CovenantError):
        a.authenticate(b"wrong-password")


def test_sealed_message_survives_relay_reseal(chat_server):
    # A and B negotiate *different* ephemeral sessions with the server; the
    # server opens A's frame and re-seals under B's keys. B must still read it.
    host, port = chat_server(password="pw")
    a = _connect(host, port)
    b = _connect(host, port)
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
    import time
    time.sleep(0.2)
    a.send("cross-session message", sender="A")
    t.join(5)

    assert received == [("cross-session message", "A")]
