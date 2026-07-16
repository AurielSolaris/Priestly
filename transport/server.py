"""A WSS server built on raw sockets, stdlib ``ssl``, and ``transport.ws``.

One thread per connection keeps the model simple and dependency-free. Each
accepted socket is TLS-wrapped, taken through the WebSocket handshake, and then
handed to a user-supplied handler as a :class:`~transport.ws.WebSocket`.
"""

from __future__ import annotations

import socket
import threading
from typing import Callable

from .tls import server_context
from .ws import ConnectionClosed, ProtocolError, WebSocket, server_handshake

# handler(ws, peer_address) -> None. The handler owns the receive loop.
Handler = Callable[[WebSocket, tuple], None]


class WSSServer:
    def __init__(
        self,
        handler: Handler,
        *,
        certfile: str | None = None,
        keyfile: str | None = None,
        host: str = "localhost",
        port: int = 8765,
        use_tls: bool = True,
    ):
        self._handler = handler
        self._host = host
        self._port = port
        self._use_tls = use_tls
        # ``use_tls=False`` serves plain ws:// -- convenient for local browser
        # testing where a self-signed certificate is refused. Confidentiality is
        # then delegated away, but Covenant auth and per-message HMAC still hold.
        self._tls = server_context(certfile, keyfile) if use_tls else None
        self._sock: socket.socket | None = None

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._host, self._port))
        self._sock.listen(64)
        scheme = "wss" if self._use_tls else "ws"
        print(f"WebSocket server listening on {scheme}://{self._host}:{self._port}")

        try:
            while True:
                raw, addr = self._sock.accept()
                thread = threading.Thread(
                    target=self._serve_connection, args=(raw, addr), daemon=True
                )
                thread.start()
        except KeyboardInterrupt:
            print("\nshutting down")
        finally:
            self._sock.close()

    def _serve_connection(self, raw: socket.socket, addr: tuple) -> None:
        if self._use_tls:
            try:
                conn = self._tls.wrap_socket(raw, server_side=True)
            except OSError as exc:
                print(f"[{addr}] TLS handshake failed: {exc}")
                raw.close()
                return
        else:
            conn = raw

        try:
            server_handshake(conn)
            ws = WebSocket(conn, is_client=False)
            self._handler(ws, addr)
        except ConnectionClosed:
            pass
        except ProtocolError as exc:
            print(f"[{addr}] protocol error: {exc}")
        except OSError as exc:
            # A peer that drops mid-send/recv (browser probe, abrupt close)
            # should not spill a traceback from the worker thread.
            print(f"[{addr}] connection dropped: {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass
