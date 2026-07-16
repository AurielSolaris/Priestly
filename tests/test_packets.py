"""Unit tests for the packet envelope (protocol/packets.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from protocol import (
    AckFrame,
    ErrorFrame,
    Handshake,
    HelloFrame,
    Message,
    MessageFrame,
    Packet,
    dumps,
    loads,
)
from protocol.packets import PROTOCOL_VERSION


def _handshake() -> Handshake:
    return Handshake(id=1, user_id=2, device_id=3, timestamp=datetime.now(timezone.utc), status="init")


def _message() -> Message:
    return Message(
        id=9, sender_id=2, receiver_id=5,
        ciphertext="deadbeef", timestamp=datetime.now(timezone.utc), status="sent",
    )


# --------------------------------------------------------------------------- #
# Round-trips for every frame type
# --------------------------------------------------------------------------- #

def test_hello_round_trip():
    frame = loads(dumps(HelloFrame(handshake=_handshake())))
    assert isinstance(frame, HelloFrame)
    assert frame.handshake.user_id == 2


def test_message_round_trip():
    frame = loads(dumps(MessageFrame(message=_message())))
    assert isinstance(frame, MessageFrame)
    assert frame.message.ciphertext == "deadbeef"


def test_ack_round_trip():
    frame = loads(dumps(AckFrame(ref_id=77)))
    assert isinstance(frame, AckFrame)
    assert frame.ref_id == 77


def test_error_round_trip():
    frame = loads(dumps(ErrorFrame(code=422, reason="bad")))
    assert isinstance(frame, ErrorFrame)
    assert frame.code == 422 and frame.reason == "bad"


# --------------------------------------------------------------------------- #
# Discrimination and validation
# --------------------------------------------------------------------------- #

def test_discriminator_selects_correct_model():
    # Two different frames must never be confused for one another.
    assert isinstance(loads(dumps(AckFrame(ref_id=1))), AckFrame)
    assert isinstance(loads(dumps(ErrorFrame(code=1, reason="x"))), ErrorFrame)


def test_unknown_frame_type_rejected():
    with pytest.raises(ValidationError):
        Packet.model_validate_json('{"version": 1, "frame": {"type": "bogus"}}')


def test_malformed_json_rejected():
    with pytest.raises(ValidationError):
        loads("this is not json")


def test_missing_required_field_rejected():
    # AckFrame requires ref_id.
    with pytest.raises(ValidationError):
        Packet.model_validate_json('{"version": 1, "frame": {"type": "ack"}}')


def test_version_mismatch_rejected():
    payload = Packet(frame=AckFrame(ref_id=1)).model_dump()
    payload["version"] = PROTOCOL_VERSION + 1
    import json

    with pytest.raises(ValueError, match="unsupported protocol version"):
        loads(json.dumps(payload))


def test_default_version_is_current():
    assert Packet(frame=AckFrame(ref_id=1)).version == PROTOCOL_VERSION


def test_model_field_type_coercion_rejects_garbage():
    # Message.id must be an int; a non-numeric string must fail validation.
    with pytest.raises(ValidationError):
        Message(
            id="not-an-int", sender_id=1, receiver_id=2,
            ciphertext="x", timestamp=datetime.now(timezone.utc), status="s",
        )
