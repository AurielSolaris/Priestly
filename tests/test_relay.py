"""Tests for the server relay registry (cli/relay.py)."""

from __future__ import annotations

import pytest

from cli.relay import (
    ClientRegistry,
    RegisteredClient,
    decode_message,
    encode_message,
)


class _CaptureWS:
    """Records frames sent to it; can be told to fail like a dead peer."""

    def __init__(self, fail: bool = False):
        self.sent: list[str] = []
        self.fail = fail

    def send(self, text: str) -> None:
        if self.fail:
            raise OSError("dead peer")
        self.sent.append(text)


# --------------------------------------------------------------------------- #
# Message codec
# --------------------------------------------------------------------------- #

def test_encode_decode_roundtrip():
    blob = encode_message("hello", "alice")
    assert decode_message(blob) == ("hello", "alice")


def test_decode_tolerates_missing_fields():
    assert decode_message(b"{}") == ("", "anon")


# --------------------------------------------------------------------------- #
# Broadcast fan-out
# --------------------------------------------------------------------------- #

def test_broadcast_reaches_others_not_sender():
    reg = ClientRegistry()
    sender = RegisteredClient(_CaptureWS(), "sender", None)
    peer1 = RegisteredClient(_CaptureWS(), "p1", None)
    peer2 = RegisteredClient(_CaptureWS(), "p2", None)
    for c in (sender, peer1, peer2):
        reg.add(c)

    reg.broadcast(sender, "hi all", "sender")

    assert sender.ws.sent == []  # sender excluded
    assert len(peer1.ws.sent) == 1
    assert len(peer2.ws.sent) == 1
    assert "hi all" in peer1.ws.sent[0]


def test_broadcast_with_no_peers_is_noop():
    reg = ClientRegistry()
    solo = RegisteredClient(_CaptureWS(), "solo", None)
    reg.add(solo)
    reg.broadcast(solo, "echo?", "solo")  # must not raise
    assert solo.ws.sent == []


def test_dead_peer_is_removed():
    reg = ClientRegistry()
    sender = RegisteredClient(_CaptureWS(), "sender", None)
    dead = RegisteredClient(_CaptureWS(fail=True), "dead", None)
    reg.add(sender)
    reg.add(dead)

    reg.broadcast(sender, "hi", "sender")
    # The dead peer raised on send and should have been dropped; a second
    # broadcast must not attempt it again (no exception).
    reg.broadcast(sender, "again", "sender")
    assert dead not in reg._clients


def test_remove_is_idempotent():
    reg = ClientRegistry()
    c = RegisteredClient(_CaptureWS(), "c", None)
    reg.add(c)
    reg.remove(c)
    reg.remove(c)  # must not raise
