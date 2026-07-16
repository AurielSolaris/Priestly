"""Tests for the Covenant handshake driver (protocol/covenant.py).

Runs the real 3-message flow over an in-memory ``socket.socketpair`` -- no TLS
needed, since the driver only depends on the WebSocket framing.
"""

from __future__ import annotations

import socket
import threading

import pytest

from protocol import covenant, dumps
from protocol.covenant import CovenantError, run_client, run_server
from protocol.packets import CovenantChallengeFrame
from protocol.session import SessionState
from transport.ws import WebSocket


def _pair():
    a, b = socket.socketpair()
    return WebSocket(a, is_client=True), WebSocket(b, is_client=False)


def _run_server_in_thread(sws, password, box):
    def target():
        try:
            box["session"] = run_server(sws, password)
        except Exception as exc:  # noqa: BLE001 - captured for the test to inspect
            box["error"] = exc
    t = threading.Thread(target=target)
    t.start()
    return t


def test_matching_password_succeeds():
    cws, sws = _pair()
    box: dict = {}
    t = _run_server_in_thread(sws, b"secret", box)
    client_session = run_client(cws, b"secret")
    t.join(5)

    assert isinstance(client_session, SessionState)
    assert isinstance(box.get("session"), SessionState)
    # And the negotiated session actually works.
    frame = client_session.seal(b"hi")
    assert box["session"].open(frame) == b"hi"


def test_wrong_password_rejected_both_sides():
    cws, sws = _pair()
    box: dict = {}
    t = _run_server_in_thread(sws, b"server-secret", box)
    with pytest.raises(CovenantError):
        run_client(cws, b"client-guess")
    t.join(5)
    assert isinstance(box.get("error"), CovenantError)


def test_forward_secrecy_fresh_keys_each_run():
    # Two handshakes with the same password must yield different session keys,
    # because the DH exponents are ephemeral.
    sessions = []
    for _ in range(2):
        cws, sws = _pair()
        box: dict = {}
        t = _run_server_in_thread(sws, b"pw", box)
        sessions.append(run_client(cws, b"pw"))
        t.join(5)
    f0 = sessions[0].seal(b"x")
    # A frame sealed under run 0's keys must not open under run 1's keys.
    with pytest.raises(Exception):
        sessions[1].open(f0)


def test_server_rejects_non_commit_first_frame():
    cws, sws = _pair()
    box: dict = {}
    t = _run_server_in_thread(sws, b"pw", box)
    # Client sends a challenge instead of a commit.
    cws.send(dumps(CovenantChallengeFrame(masked_b="ab")))
    t.join(5)
    assert isinstance(box.get("error"), CovenantError)


def test_tampered_challenge_fails_client():
    # A man-in-the-middle server that does not know the password cannot produce
    # a valid confirm_s, so the client rejects it.
    cws, sws = _pair()
    box: dict = {}
    t = _run_server_in_thread(sws, b"real-password", box)
    with pytest.raises(CovenantError):
        run_client(cws, b"different-password")
    t.join(5)
