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
    ):
        self._host = host
        self._port = port
        self._path = path
        self._tls = client_context(cafile, insecure=insecure)

    def connect(self) -> WebSocket:
        """Open the TCP connection, negotiate TLS, run the WS handshake."""
        raw = socket.create_connection((self._host, self._port))
        tls = self._tls.wrap_socket(raw, server_hostname=self._host)
        client_handshake(tls, host=self._host, path=self._path)
        return WebSocket(tls, is_client=True)
