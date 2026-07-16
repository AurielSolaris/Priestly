"""Tiny local HTTP server that hosts the browser UI.

Serves a single page (and its logo) that opens a WebSocket straight to the
central Priestly server -- the browser never talks peer-to-peer, only to the
hub. The page's WebSocket target is injected at serve time so the same static
files work against any server host/port.
"""

from __future__ import annotations

import http.server
import socketserver
import threading
import webbrowser
from pathlib import Path

_UI_DIR = Path(__file__).resolve().parent.parent / "ui"


def _load(name: str) -> str:
    return (_UI_DIR / name).read_text(encoding="utf-8")


def _render_index(ws_host: str, ws_port: int) -> bytes:
    html = _load("index.html")
    html = html.replace("__WS_HOST__", ws_host).replace("__WS_PORT__", str(ws_port))
    return html.encode("utf-8")


def serve_ui(ws_host: str, ws_port: int, ui_port: int = 8080) -> None:
    """Serve the UI, auto-incrementing the port if ``ui_port`` is taken."""
    index_bytes = _render_index(ws_host, ws_port)
    covenant_bytes = _load("covenant.js").encode("utf-8")
    try:
        logo_bytes = _load("logo.svg").encode("utf-8")
    except FileNotFoundError:
        logo_bytes = b""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - stdlib naming
            if self.path in ("/", "/index.html"):
                self._respond(200, "text/html; charset=utf-8", index_bytes)
            elif self.path == "/covenant.js":
                self._respond(200, "application/javascript; charset=utf-8", covenant_bytes)
            elif self.path == "/logo.svg":
                self._respond(200, "image/svg+xml", logo_bytes)
            else:
                self.send_error(404)

        def _respond(self, code: int, content_type: str, body: bytes):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence per-request logging
            pass

    port = ui_port
    while True:
        try:
            server = socketserver.TCPServer(("localhost", port), Handler)
            break
        except OSError:
            port += 1
            if port > ui_port + 100:
                raise RuntimeError("no free UI port found")

    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://localhost:{port}"
    print(f"Priestly UI at {url}  ->  server wss://{ws_host}:{ws_port}")
    webbrowser.open(url)

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        server.shutdown()
