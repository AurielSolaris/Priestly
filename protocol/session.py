"""Per-packet security: seal, verify, and anti-replay.

After the Covenant handshake both peers hold the four directional keys. A
:class:`SessionState` turns those keys into an authenticated, ordered message
channel:

* **seal** -- Huffman-compress the plaintext, attach an HMAC-SHA256 tag over
  ``epoch || seq || direction || payload``, and stamp a strictly increasing
  per-direction sequence number.
* **open** -- recompute the tag with the *peer's* MAC key, reject on mismatch,
  reject any sequence number that is not strictly greater than the last seen
  (replay / reorder), then decompress.

Confidentiality is provided by the underlying TLS tunnel; this layer adds
authenticity, integrity, and replay protection. Directional key separation
means a message authored by the client can never verify as one from the server.
"""

from __future__ import annotations

import base64
import hmac
import struct

from crypto import huffman
from crypto.hmac_sha256 import sign

from .packets import SealedFrame


# Compression markers, prefixed to the payload before authentication so both
# ends (and a non-Python peer such as the browser) can interoperate: the sender
# picks whichever is smaller, and the MAC covers the marker byte.
_STORED = 0x00    # payload follows verbatim
_HUFFMAN = 0x01   # payload is Huffman-compressed


class ReplayError(Exception):
    """Raised when a sealed frame's sequence number is not fresh."""


class AuthenticationError(Exception):
    """Raised when a sealed frame's authentication tag does not verify."""


def pack(plaintext: bytes) -> bytes:
    """Prefix a compression marker, using Huffman only when it actually shrinks."""
    compressed = huffman.compress(plaintext)
    if len(compressed) < len(plaintext):
        return bytes([_HUFFMAN]) + compressed
    return bytes([_STORED]) + plaintext


def unpack(blob: bytes) -> bytes:
    """Invert :func:`pack`; reject an unknown or empty marker."""
    if not blob:
        raise AuthenticationError("empty sealed payload")
    marker, body = blob[0], blob[1:]
    if marker == _HUFFMAN:
        return huffman.decompress(body)
    if marker == _STORED:
        return body
    raise AuthenticationError(f"unknown compression marker 0x{marker:02x}")


def compute_tag(
    mac_key: bytes, epoch: int, seq: int, direction: str, payload: bytes
) -> str:
    """Per-packet authentication tag (hex HMAC-SHA256).

    The header binds the tag to the rekeying epoch, the sequence number, and the
    direction, so a captured frame cannot be replayed in the other direction or
    across an epoch boundary.
    """
    direction_byte = b"C" if direction == "client" else b"S"
    header = struct.pack(">Q", epoch) + struct.pack(">Q", seq) + direction_byte
    return sign(mac_key, header + payload)


class SessionState:
    """Sending/receiving state for one authenticated connection."""

    def __init__(self, keys: dict[str, bytes], *, is_client: bool, compress: bool = True):
        self.is_client = is_client
        # Huffman compression is optional per session: peers that cannot
        # decompress our custom format (e.g. the browser client) negotiate it
        # off, and we then always send verbatim ("stored") payloads.
        self.compress = compress
        self._tx_dir = "client" if is_client else "server"
        self._rx_dir = "server" if is_client else "client"
        self._tx_mac = keys["client_mac"] if is_client else keys["server_mac"]
        self._rx_mac = keys["server_mac"] if is_client else keys["client_mac"]
        self.tx_seq = 0
        self.rx_seq = 0
        self.epoch = 0

    def seal(self, plaintext: bytes) -> SealedFrame:
        """Compress (optionally), authenticate, and sequence a plaintext payload."""
        self.tx_seq += 1
        body = pack(plaintext) if self.compress else bytes([_STORED]) + plaintext
        tag = compute_tag(self._tx_mac, self.epoch, self.tx_seq, self._tx_dir, body)
        return SealedFrame(
            epoch=self.epoch,
            seq=self.tx_seq,
            direction=self._tx_dir,
            payload=base64.b64encode(body).decode("ascii"),
            tag=tag,
        )

    def open(self, frame: SealedFrame) -> bytes:
        """Verify and decompress an incoming sealed frame.

        Raises :class:`AuthenticationError` on a bad tag or wrong direction, and
        :class:`ReplayError` on a stale/duplicate sequence number.
        """
        if frame.direction != self._rx_dir:
            raise AuthenticationError(
                f"expected {self._rx_dir!r} frame, got {frame.direction!r}"
            )
        try:
            body = base64.b64decode(frame.payload, validate=True)
        except (ValueError, TypeError) as exc:
            raise AuthenticationError(f"payload is not valid base64: {exc}") from exc

        expected = compute_tag(
            self._rx_mac, frame.epoch, frame.seq, frame.direction, body
        )
        if not hmac.compare_digest(expected, frame.tag):
            raise AuthenticationError("authentication tag does not verify")
        if frame.seq <= self.rx_seq:
            raise ReplayError(
                f"stale sequence number {frame.seq} (last seen {self.rx_seq})"
            )
        self.rx_seq = frame.seq
        return unpack(body)
