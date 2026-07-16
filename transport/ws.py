"""Minimal WebSocket (RFC 6455) implementation on the standard library.

No third-party dependencies: raw sockets carry the bytes, ``hashlib`` and
``base64`` drive the opening handshake, and ``struct``/``os`` handle frame
encoding and masking. TLS (the "S" in WSS) is layered underneath by wrapping
the socket before it reaches this module -- see ``transport.tls``.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from typing import Union

# Magic value every server appends to the client key when computing the
# handshake accept token (RFC 6455 section 4.2.2).
_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Frame opcodes (RFC 6455 section 5.2).
OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

_VALID_OPCODES = frozenset({OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG})
_CONTROL_OPCODES = frozenset({OP_CLOSE, OP_PING, OP_PONG})

_MAX_HEADER_BYTES = 16 * 1024  # cap on the opening HTTP handshake size


class ConnectionClosed(Exception):
    """Raised when the peer has closed the connection or the stream ended."""

    def __init__(self, code: int | None = None, reason: str = ""):
        self.code = code
        self.reason = reason
        super().__init__(f"connection closed (code={code}, reason={reason!r})")


class ProtocolError(Exception):
    """Raised on a malformed handshake or frame."""


def accept_token(key: str) -> str:
    """Compute the ``Sec-WebSocket-Accept`` value for a client key."""
    digest = hashlib.sha1((key + _GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


# --------------------------------------------------------------------------- #
# Low-level socket byte helpers
# --------------------------------------------------------------------------- #

def _recv_exact(sock, n: int) -> bytes:
    """Read exactly ``n`` bytes from ``sock`` or raise ConnectionClosed."""
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except OSError as exc:
            raise ConnectionClosed(reason=f"socket error: {exc}") from exc
        if not chunk:
            raise ConnectionClosed(reason="stream ended mid-frame")
        buf += chunk
    return bytes(buf)


def _read_http_headers(sock) -> str:
    """Read a CRLF-terminated HTTP header block one byte at a time.

    Byte-at-a-time reading guarantees we stop exactly at the end of the header
    block and never consume the first WebSocket frame that follows it.
    """
    buf = bytearray()
    while not buf.endswith(b"\r\n\r\n"):
        byte = sock.recv(1)
        if not byte:
            raise ConnectionClosed(reason="stream ended during handshake")
        buf += byte
        if len(buf) > _MAX_HEADER_BYTES:
            raise ProtocolError("handshake header block too large")
    return buf.decode("iso-8859-1")


def _parse_headers(block: str) -> tuple[str, dict[str, str]]:
    """Split an HTTP header block into its request/status line and headers."""
    lines = block.split("\r\n")
    start_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return start_line, headers


# --------------------------------------------------------------------------- #
# Opening handshake
# --------------------------------------------------------------------------- #

def server_handshake(sock) -> dict[str, str]:
    """Perform the server side of the opening handshake.

    Returns the request headers so callers can inspect the path or origin.
    """
    block = _read_http_headers(sock)
    start_line, headers = _parse_headers(block)

    if not start_line.upper().startswith("GET"):
        raise ProtocolError(f"expected GET request, got {start_line!r}")
    if headers.get("upgrade", "").lower() != "websocket":
        raise ProtocolError("missing 'Upgrade: websocket' header")
    key = headers.get("sec-websocket-key")
    if not key:
        raise ProtocolError("missing Sec-WebSocket-Key header")

    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept_token(key)}\r\n"
        "\r\n"
    )
    sock.sendall(response.encode("iso-8859-1"))
    return headers


def client_handshake(sock, host: str, path: str = "/") -> dict[str, str]:
    """Perform the client side of the opening handshake."""
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("iso-8859-1"))

    block = _read_http_headers(sock)
    status_line, headers = _parse_headers(block)
    if "101" not in status_line:
        raise ProtocolError(f"handshake rejected: {status_line!r}")
    if headers.get("sec-websocket-accept") != accept_token(key):
        raise ProtocolError("server returned an invalid Sec-WebSocket-Accept")
    return headers


# --------------------------------------------------------------------------- #
# Frame codec
# --------------------------------------------------------------------------- #

def encode_frame(opcode: int, payload: bytes, *, mask: bool) -> bytes:
    """Serialize a single, unfragmented frame with FIN set."""
    header = bytearray([0x80 | opcode])  # FIN=1, RSV=0
    length = len(payload)
    mask_bit = 0x80 if mask else 0x00

    if length < 126:
        header.append(mask_bit | length)
    elif length < 65536:
        header.append(mask_bit | 126)
        header += struct.pack("!H", length)
    else:
        header.append(mask_bit | 127)
        header += struct.pack("!Q", length)

    if mask:
        masking_key = os.urandom(4)
        header += masking_key
        payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

    return bytes(header) + payload


def read_frame(sock) -> tuple[bool, int, bytes]:
    """Read one frame, returning ``(fin, opcode, unmasked_payload)``."""
    b0, b1 = _recv_exact(sock, 2)
    fin = bool(b0 & 0x80)
    if b0 & 0x70:
        raise ProtocolError("reserved bits must be zero")
    opcode = b0 & 0x0F
    if opcode not in _VALID_OPCODES:
        raise ProtocolError(f"unknown opcode 0x{opcode:x}")
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F

    if opcode in _CONTROL_OPCODES:
        # Control frames must be final and short (RFC 6455 section 5.5).
        if not fin:
            raise ProtocolError("control frames must not be fragmented")
        if length > 125:
            raise ProtocolError("control frame payload too large")

    if length == 126:
        (length,) = struct.unpack("!H", _recv_exact(sock, 2))
    elif length == 127:
        (length,) = struct.unpack("!Q", _recv_exact(sock, 8))

    masking_key = _recv_exact(sock, 4) if masked else b""
    payload = _recv_exact(sock, length)
    if masked:
        payload = bytes(b ^ masking_key[i % 4] for i, b in enumerate(payload))

    return fin, opcode, payload


# --------------------------------------------------------------------------- #
# Connection wrapper
# --------------------------------------------------------------------------- #

class WebSocket:
    """A framed message channel over an (already TLS-wrapped) socket.

    Clients MUST mask frames and servers MUST NOT (RFC 6455 section 5.1), so
    the side is fixed at construction time via ``is_client``.
    """

    def __init__(self, sock, *, is_client: bool):
        self._sock = sock
        self._is_client = is_client
        self._closed = False

    # -- sending ----------------------------------------------------------- #

    def send(self, text: str) -> None:
        """Send a UTF-8 text message."""
        self._send(OP_TEXT, text.encode("utf-8"))

    def send_bytes(self, data: bytes) -> None:
        """Send a binary message."""
        self._send(OP_BINARY, data)

    def _send(self, opcode: int, payload: bytes) -> None:
        if self._closed:
            raise ConnectionClosed(reason="send on closed connection")
        self._sock.sendall(encode_frame(opcode, payload, mask=self._is_client))

    # -- receiving --------------------------------------------------------- #

    def recv(self) -> Union[str, bytes]:
        """Return the next application message, transparently handling control
        frames (ping/pong/close) and reassembling fragmented messages."""
        if self._closed:
            raise ConnectionClosed(reason="recv on closed connection")

        chunks: list[bytes] = []
        message_opcode: int | None = None

        while True:
            fin, opcode, payload = read_frame(self._sock)

            if opcode == OP_CLOSE:
                code, reason = self._parse_close(payload)
                self._closed = True
                raise ConnectionClosed(code, reason)
            if opcode == OP_PING:
                self._send(OP_PONG, payload)
                continue
            if opcode == OP_PONG:
                continue

            if opcode == OP_CONT:
                if message_opcode is None:
                    raise ProtocolError("continuation frame without a start")
            else:
                message_opcode = opcode
            chunks.append(payload)

            if fin:
                data = b"".join(chunks)
                if message_opcode == OP_TEXT:
                    return data.decode("utf-8")
                return data

    # -- teardown ---------------------------------------------------------- #

    def close(self, code: int = 1000, reason: str = "") -> None:
        if self._closed:
            return
        # Send the Close frame *before* marking closed, otherwise _send's
        # closed-guard would swallow it. Write it directly to bypass that guard.
        payload = struct.pack("!H", code) + reason.encode("utf-8")
        try:
            self._sock.sendall(encode_frame(OP_CLOSE, payload, mask=self._is_client))
        except OSError:
            pass
        finally:
            self._closed = True
            try:
                self._sock.close()
            except OSError:
                pass

    @staticmethod
    def _parse_close(payload: bytes) -> tuple[int | None, str]:
        if len(payload) >= 2:
            (code,) = struct.unpack("!H", payload[:2])
            return code, payload[2:].decode("utf-8", "replace")
        return None, ""

    def __enter__(self) -> "WebSocket":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
