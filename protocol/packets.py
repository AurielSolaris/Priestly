"""The packet envelope: the typed messages that travel over the WSS transport.

Each packet is a small, versioned wrapper around exactly one *frame*. Frames
form a discriminated union keyed on ``type``, so ``Packet.model_validate_json``
parses arbitrary wire text straight into the correct model and rejects anything
malformed -- this is the validation/rule-enforcement job pydantic is kept for.

Wire format is JSON in a WebSocket text frame. The transport layer
(``transport.ws``) knows nothing about any of this; ``dumps``/``loads`` are the
only bridge between the two.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field

from .models import Handshake, Message

PROTOCOL_VERSION = 1


class FrameType(str, Enum):
    HELLO = "hello"
    HELLO_ACK = "hello_ack"
    MESSAGE = "message"
    ACK = "ack"
    ERROR = "error"
    # Layer 3 (Covenant) handshake frames.
    COVENANT_COMMIT = "covenant_commit"
    COVENANT_CHALLENGE = "covenant_challenge"
    COVENANT_CONFIRM = "covenant_confirm"
    AUTH_OK = "auth_ok"
    AUTH_FAIL = "auth_fail"
    # Post-handshake authenticated application message.
    SEALED = "sealed"
    # Plain application chat message (open nodes, no Layer 3).
    CHAT = "chat"


class HelloFrame(BaseModel):
    """Opens a session by presenting the peer's handshake record."""

    type: Literal[FrameType.HELLO] = FrameType.HELLO
    handshake: Handshake


class HelloAckFrame(BaseModel):
    """Server's reply to HELLO. Signals whether Layer 3 auth is required."""

    type: Literal[FrameType.HELLO_ACK] = FrameType.HELLO_ACK
    status: str = "ok"
    server_name: str
    password_required: bool = False


class CovenantCommitFrame(BaseModel):
    """Client -> server, message 1: SHA-1 commitment to the client's element A."""

    type: Literal[FrameType.COVENANT_COMMIT] = FrameType.COVENANT_COMMIT
    commit: str  # hex SHA-1 (40 chars)


class CovenantChallengeFrame(BaseModel):
    """Server -> client, message 2: the masked server element ``B * PE``."""

    type: Literal[FrameType.COVENANT_CHALLENGE] = FrameType.COVENANT_CHALLENGE
    masked_b: str  # hex of the 256-byte group element


class CovenantConfirmFrame(BaseModel):
    """Client -> server, message 3: the revealed element A + client key MAC."""

    type: Literal[FrameType.COVENANT_CONFIRM] = FrameType.COVENANT_CONFIRM
    a: str          # hex of the 256-byte group element
    confirm_c: str  # hex HMAC-SHA256 (64 chars)


class AuthOkFrame(BaseModel):
    """Server -> client: authentication succeeded, carrying the server's key
    MAC so the client can mutually authenticate the server."""

    type: Literal[FrameType.AUTH_OK] = FrameType.AUTH_OK
    confirm_s: str  # hex HMAC-SHA256 (64 chars)


class AuthFailFrame(BaseModel):
    """Either side: the Covenant handshake failed."""

    type: Literal[FrameType.AUTH_FAIL] = FrameType.AUTH_FAIL
    reason: str = "authentication failed"


class SealedFrame(BaseModel):
    """A post-handshake application message: authenticated + sequence-numbered.

    ``payload`` is base64-encoded Huffman-compressed bytes; ``tag`` is the hex
    HMAC-SHA256 over ``epoch || seq || direction || payload``. The transport
    only ever sees this envelope, never the plaintext."""

    type: Literal[FrameType.SEALED] = FrameType.SEALED
    epoch: int
    seq: int
    direction: str  # "client" or "server"
    payload: str    # base64
    tag: str        # hex HMAC-SHA256


class ChatFrame(BaseModel):
    """A plaintext chat message for open (unauthenticated) nodes."""

    type: Literal[FrameType.CHAT] = FrameType.CHAT
    text: str
    sender: str = "anon"


class MessageFrame(BaseModel):
    """Carries one (already-encrypted) message."""

    type: Literal[FrameType.MESSAGE] = FrameType.MESSAGE
    message: Message


class AckFrame(BaseModel):
    """Acknowledges receipt of the frame whose id is ``ref_id``."""

    type: Literal[FrameType.ACK] = FrameType.ACK
    ref_id: int


class ErrorFrame(BaseModel):
    """Reports a protocol- or application-level failure."""

    type: Literal[FrameType.ERROR] = FrameType.ERROR
    code: int
    reason: str


Frame = Annotated[
    Union[
        HelloFrame,
        HelloAckFrame,
        MessageFrame,
        AckFrame,
        ErrorFrame,
        CovenantCommitFrame,
        CovenantChallengeFrame,
        CovenantConfirmFrame,
        AuthOkFrame,
        AuthFailFrame,
        SealedFrame,
        ChatFrame,
    ],
    Field(discriminator="type"),
]


class Packet(BaseModel):
    """Top-level envelope: a protocol version plus exactly one frame."""

    version: int = PROTOCOL_VERSION
    frame: Frame


# --------------------------------------------------------------------------- #
# Bridge to the transport layer
# --------------------------------------------------------------------------- #

def dumps(frame: Frame) -> str:
    """Serialize a frame to the JSON text that goes in a WebSocket frame."""
    return Packet(frame=frame).model_dump_json()


def loads(raw: str) -> Frame:
    """Parse wire text into a validated frame, raising on version mismatch."""
    packet = Packet.model_validate_json(raw)
    if packet.version != PROTOCOL_VERSION:
        raise ValueError(
            f"unsupported protocol version {packet.version} "
            f"(this build speaks v{PROTOCOL_VERSION})"
        )
    return packet.frame
