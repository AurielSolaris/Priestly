"""Client-side protocol flow: HELLO, optional Covenant auth, send/receive.

Wraps a connected :class:`~transport.ws.WebSocket` and speaks the full chat
protocol, so both the CLI entry point and the test-suite drive the same logic.
"""

from __future__ import annotations

from protocol import (
    ChatFrame,
    Handshake,
    HelloAckFrame,
    HelloFrame,
    SealedFrame,
    covenant,
    dumps,
    loads,
)
from datetime import datetime, timezone

from .relay import decode_message, encode_message


class ProtocolError(Exception):
    """The server returned an unexpected or error frame."""


class ChatClient:
    """Drives one client connection through handshake and messaging."""

    def __init__(self, ws):
        self._ws = ws
        self.session = None
        self.server_name: str | None = None
        self.password_required = False

    def _recv(self):
        raw = self._ws.recv()
        return loads(raw if isinstance(raw, str) else raw.decode("utf-8"))

    def hello(self, user_id: int = 42, device_id: int = 7) -> HelloAckFrame:
        """Send HELLO and record the server's capabilities from HELLO_ACK."""
        handshake = Handshake(
            id=1, user_id=user_id, device_id=device_id,
            timestamp=datetime.now(timezone.utc), status="init",
        )
        self._ws.send(dumps(HelloFrame(handshake=handshake)))
        ack = self._recv()
        if not isinstance(ack, HelloAckFrame):
            raise ProtocolError(f"expected HELLO_ACK, got {type(ack).__name__}")
        self.server_name = ack.server_name
        self.password_required = ack.password_required
        return ack

    def authenticate(self, password: bytes) -> None:
        """Run the Covenant handshake; raises covenant.CovenantError on failure."""
        self.session = covenant.run_client(self._ws, password)

    def send(self, text: str, sender: str = "cli") -> None:
        """Send a chat message, sealed if the session is authenticated."""
        if self.session is not None:
            self._ws.send(dumps(self.session.seal(encode_message(text, sender))))
        else:
            self._ws.send(dumps(ChatFrame(text=text, sender=sender)))

    def receive(self) -> tuple[str, str]:
        """Block for the next inbound message; return ``(text, sender)``."""
        frame = self._recv()
        if isinstance(frame, SealedFrame):
            if self.session is None:
                raise ProtocolError("received sealed frame before authentication")
            return decode_message(self.session.open(frame))
        if isinstance(frame, ChatFrame):
            return frame.text, frame.sender
        raise ProtocolError(f"unexpected frame {type(frame).__name__}")
