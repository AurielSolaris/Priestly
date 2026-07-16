"""A WSS client built on raw sockets, stdlib ``ssl``, and ``transport.ws``."""

from __future__ import annotations

import socket

from .tls import client_context
from .ws import WebSocket, client_handshake


class WSSClient:
    def __init__(
        self,
        host: str = "localhost",
        port: int = 8765,
        *,
        cafile: str | None = None,
        insecure: bool = False,
        path: str = "/",
        use_tls: bool = True,
    ):
        self._host = host
        self._port = port
        self._path = path
        self._use_tls = use_tls
        # ``use_tls=False`` speaks plain ws:// -- for local dev where a self-signed
        # certificate is more friction than it is worth (no wire confidentiality,
        # but the Covenant handshake and per-message HMAC still apply).
        self._tls = client_context(cafile, insecure=insecure) if use_tls else None

    def connect(self) -> WebSocket:
        """Open the TCP connection, negotiate TLS (unless disabled), run the WS handshake."""
        raw = socket.create_connection((self._host, self._port))
        conn = self._tls.wrap_socket(raw, server_hostname=self._host) if self._use_tls else raw
        client_handshake(conn, host=self._host, path=self._path)
        return WebSocket(conn, is_client=True)
