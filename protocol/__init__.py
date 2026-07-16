"""Protocol layer: data models, the typed packet envelope, the Covenant
handshake driver, and the sealed-message session."""

from . import covenant
from .covenant import CovenantError
from .models import Handshake, Message
from .packets import (
    AckFrame,
    AuthFailFrame,
    AuthOkFrame,
    ChatFrame,
    CovenantChallengeFrame,
    CovenantCommitFrame,
    CovenantConfirmFrame,
    ErrorFrame,
    Frame,
    FrameType,
    HelloAckFrame,
    HelloFrame,
    MessageFrame,
    Packet,
    PROTOCOL_VERSION,
    SealedFrame,
    dumps,
    loads,
)
from .session import SessionState, compute_tag

__all__ = [
    "Handshake",
    "Message",
    "Packet",
    "Frame",
    "FrameType",
    "HelloFrame",
    "HelloAckFrame",
    "MessageFrame",
    "AckFrame",
    "ErrorFrame",
    "CovenantCommitFrame",
    "CovenantChallengeFrame",
    "CovenantConfirmFrame",
    "AuthOkFrame",
    "AuthFailFrame",
    "SealedFrame",
    "ChatFrame",
    "PROTOCOL_VERSION",
    "dumps",
    "loads",
    "SessionState",
    "compute_tag",
    "covenant",
    "CovenantError",
]
