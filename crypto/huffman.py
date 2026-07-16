"""Huffman compression implemented from scratch.

``compress`` turns a byte string into a self-describing blob: a small header
(original length + symbol frequency table) followed by the bit-packed codes.
``decompress`` rebuilds the identical tree from the transmitted frequencies and
decodes exactly ``original length`` symbols, so trailing bit padding is ignored.

The tree build is fully deterministic (ties broken by the smallest symbol in a
subtree), which is what lets the decoder reconstruct the same codes the encoder
used without transmitting the code table itself.
"""

from __future__ import annotations

import heapq
from collections import Counter

_LEN_BYTES = 4      # original payload length
_COUNT_BYTES = 2    # number of distinct symbols
_FREQ_BYTES = 4     # frequency per symbol


class _Node:
    __slots__ = ("symbol", "left", "right")

    def __init__(self, symbol=None, left=None, right=None):
        self.symbol = symbol
        self.left = left
        self.right = right

    @property
    def is_leaf(self) -> bool:
        return self.symbol is not None


def _build_tree(freq: dict[int, int]) -> _Node:
    """Build a deterministic Huffman tree from a symbol->frequency map.

    Heap entries are ``(frequency, min_symbol, node)``. Because every symbol is
    unique, ``(frequency, min_symbol)`` is a total order, so nodes are never
    compared directly and encoder/decoder always agree on the tree shape.
    """
    heap = [(f, s, _Node(symbol=s)) for s, f in freq.items()]
    heapq.heapify(heap)
    while len(heap) > 1:
        f1, s1, n1 = heapq.heappop(heap)
        f2, s2, n2 = heapq.heappop(heap)
        heapq.heappush(heap, (f1 + f2, min(s1, s2), _Node(left=n1, right=n2)))
    return heap[0][2]


def _build_codes(node: _Node, prefix: str, out: dict[int, str]) -> None:
    if node.is_leaf:
        # A tree with a single distinct symbol still needs a 1-bit code.
        out[node.symbol] = prefix or "0"
        return
    _build_codes(node.left, prefix + "0", out)
    _build_codes(node.right, prefix + "1", out)


def _pack_bits(bitstring: str) -> bytes:
    padded = bitstring + "0" * (-len(bitstring) % 8)
    return bytes(int(padded[i:i + 8], 2) for i in range(0, len(padded), 8))


def compress(data: bytes) -> bytes:
    """Compress ``data`` into a self-describing Huffman blob."""
    out = bytearray(len(data).to_bytes(_LEN_BYTES, "big"))
    if not data:
        out += (0).to_bytes(_COUNT_BYTES, "big")
        return bytes(out)

    freq = Counter(data)
    out += len(freq).to_bytes(_COUNT_BYTES, "big")
    for symbol in sorted(freq):
        out.append(symbol)
        out += freq[symbol].to_bytes(_FREQ_BYTES, "big")

    codes: dict[int, str] = {}
    _build_codes(_build_tree(freq), "", codes)
    out += _pack_bits("".join(codes[b] for b in data))
    return bytes(out)


def decompress(blob: bytes) -> bytes:
    """Invert :func:`compress`."""
    pos = 0
    length = int.from_bytes(blob[pos:pos + _LEN_BYTES], "big")
    pos += _LEN_BYTES
    count = int.from_bytes(blob[pos:pos + _COUNT_BYTES], "big")
    pos += _COUNT_BYTES

    if length == 0:
        return b""

    freq: dict[int, int] = {}
    for _ in range(count):
        symbol = blob[pos]
        pos += 1
        freq[symbol] = int.from_bytes(blob[pos:pos + _FREQ_BYTES], "big")
        pos += _FREQ_BYTES

    root = _build_tree(freq)
    payload = blob[pos:]

    # Single-symbol payloads have a trivial (leaf) tree and no meaningful bits.
    if root.is_leaf:
        return bytes([root.symbol]) * length

    result = bytearray()
    node = root
    for byte in payload:
        for bit in range(7, -1, -1):
            node = node.left if not (byte >> bit) & 1 else node.right
            if node.is_leaf:
                result.append(node.symbol)
                if len(result) == length:
                    return bytes(result)
                node = root
    return bytes(result)
