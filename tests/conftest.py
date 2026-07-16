"""Shared test fixtures: an in-memory socket and a real loopback WSS server."""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from protocol import AckFrame, ErrorFrame, HelloFrame, MessageFrame, dumps, loads
from transport import ConnectionClosed, WSSClient, WSSServer, WebSocket

ROOT = Path(__file__).resolve().parent.parent
CERT = ROOT / "certs" / "dev.crt"
KEY = ROOT / "certs" / "dev.key"


class FakeSocket:
    """A deterministic stand-in for a socket: reads drain a preset buffer,
    writes accumulate for inspection. ``recv`` returns b'' at EOF."""

    def __init__(self, read_bytes: bytes = b""):
        self._read = bytearray(read_bytes)
        self.written = bytearray()
        self.closed = False

    def feed(self, data: bytes) -> None:
        self._read += data

    def recv(self, n: int) -> bytes:
        if not self._read:
            return b""
        chunk = bytes(self._read[:n])
        del self._read[:n]
        return chunk

    def sendall(self, data: bytes) -> None:
        self.written += data

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_socket():
    return FakeSocket


@pytest.fixture(scope="session", autouse=True)
def _ensure_cert():
    """Generate the dev certificate once if it is not already present."""
    if not (CERT.exists() and KEY.exists()):
        subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "gen_dev_cert.py")],
            check=True,
            cwd=ROOT,
        )


def _echo_handler(ws: WebSocket, addr: tuple) -> None:
    """Session handler used by the integration server: ACK valid frames,
    error on everything else. Mirrors cli.main so tests exercise real logic."""
    try:
        while True:
            raw = ws.recv()
            try:
                frame = loads(raw if isinstance(raw, str) else raw.decode())
            except ValueError as exc:  # JSON/validation/version errors
                ws.send(dumps(ErrorFrame(code=400, reason=str(exc)[:80])))
                continue

            if isinstance(frame, HelloFrame):
                ws.send(dumps(AckFrame(ref_id=frame.handshake.id)))
            elif isinstance(frame, MessageFrame):
                ws.send(dumps(AckFrame(ref_id=frame.message.id)))
            else:
                ws.send(dumps(ErrorFrame(code=422, reason="unexpected frame")))
    except ConnectionClosed:
        return


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("localhost", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server(_ensure_cert):
    """Start a real WSS server in a background thread; yield (host, port)."""
    port = _free_port()
    server = WSSServer(
        _echo_handler,
        certfile=str(CERT),
        keyfile=str(KEY),
        host="localhost",
        port=port,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("localhost", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError("server did not come up")

    yield "localhost", port


@pytest.fixture
def client(live_server):
    """A connected WebSocket to the live server, closed on teardown."""
    host, port = live_server
    ws = WSSClient(host=host, port=port, cafile=str(CERT)).connect()
    try:
        yield ws
    finally:
        ws.close()


@pytest.fixture
def chat_server(_ensure_cert):
    """Factory: start a real cli.server chat node with a given config.

    Yields a function ``start(password=None, server_name=...) -> (host, port)``.
    Each node gets its own isolated relay registry.
    """
    import config as config_module
    from cli.relay import ClientRegistry
    from cli.server import make_handler

    def start(password=None, server_name="test-node", use_tls=True):
        cfg = config_module.ServerConfig(server_name=server_name, password=password)
        port = _free_port()
        server = WSSServer(
            make_handler(cfg, ClientRegistry()),
            certfile=str(CERT) if use_tls else None,
            keyfile=str(KEY) if use_tls else None,
            host="localhost",
            port=port,
            use_tls=use_tls,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                with socket.create_connection(("localhost", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("chat server did not come up")
        return "localhost", port

    yield start
