"""Connected-client registry and message relay for the chat server.

The server keeps one :class:`RegisteredClient` per authorized connection. When a
message arrives it is delivered to every *other* client. Because each connection
negotiated its own ephemeral session, the server re-seals the plaintext
separately for each recipient using that recipient's keys -- it is a decrypting
relay (consistent with the threat model: the server can read messages; only the
peers' shared password gates entry, and TLS guards the wire).

Each client carries a lock so concurrent relay threads never interleave writes
or race the per-direction sequence counter.
"""

from __future__ import annotations

import json
import threading
from typing import Optional

from protocol import ChatFrame, SealedFrame, SessionState, dumps


def encode_message(text: str, sender: str) -> bytes:
    """The application payload carried inside a sealed frame."""
    return json.dumps({"text": text, "sender": sender}).encode("utf-8")


def decode_message(plaintext: bytes) -> tuple[str, str]:
    """Inverse of :func:`encode_message`; tolerant of missing fields."""
    obj = json.loads(plaintext.decode("utf-8"))
    return str(obj.get("text", "")), str(obj.get("sender", "anon"))


class RegisteredClient:
    def __init__(self, ws, name: str, session: Optional[SessionState]):
        self.ws = ws
        self.name = name
        self.session = session
        self._lock = threading.Lock()

    def deliver(self, text: str, sender: str) -> None:
        """Send one message to this client, sealed if the session is authenticated."""
        with self._lock:
            if self.session is not None:
                frame = self.session.seal(encode_message(text, sender))
            else:
                frame = ChatFrame(text=text, sender=sender)
            self.ws.send(dumps(frame))


class ClientRegistry:
    """Thread-safe set of connected clients with fan-out delivery."""

    def __init__(self):
        self._clients: set[RegisteredClient] = set()
        self._lock = threading.Lock()

    def add(self, client: RegisteredClient) -> None:
        with self._lock:
            self._clients.add(client)

    def remove(self, client: RegisteredClient) -> None:
        with self._lock:
            self._clients.discard(client)

    def broadcast(self, sender: RegisteredClient, text: str, sender_name: str) -> None:
        """Deliver ``text`` to every client except ``sender``.

        A client that fails to receive (already disconnected) is dropped rather
        than aborting the whole fan-out.
        """
        with self._lock:
            recipients = [c for c in self._clients if c is not sender]
        for client in recipients:
            try:
                client.deliver(text, sender_name)
            except Exception:  # noqa: BLE001 - one dead peer must not stop the rest
                self.remove(client)
