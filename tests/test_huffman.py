"""Tests for the from-scratch Huffman codec (crypto/huffman.py).

The central property is lossless round-tripping: ``decompress(compress(x)) == x``
for every kind of input, including the awkward edge cases (empty, single byte,
one repeated symbol, all 256 byte values, random data).
"""

from __future__ import annotations

import os

import pytest

from crypto.huffman import compress, decompress


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"a",
        b"aaaaaaaa",
        b"abracadabra",
        b"the quick brown fox jumps over the lazy dog",
        bytes(range(256)),
        b"\x00" * 1000,
        bytes([7, 7, 7, 1, 2, 2, 3]),
    ],
)
def test_round_trip_known_inputs(data):
    assert decompress(compress(data)) == data


@pytest.mark.parametrize("_", range(50))
def test_round_trip_random(_):
    data = os.urandom(os.urandom(1)[0] * 4)  # 0..1020 random bytes
    assert decompress(compress(data)) == data


def test_round_trip_large_repetitive():
    data = (b"priestly-protocol " * 5000)
    assert decompress(compress(data)) == data


def test_repetitive_data_compresses_smaller():
    data = b"A" * 10_000 + b"B" * 100
    assert len(compress(data)) < len(data)


def test_single_symbol_uses_one_bit_per_symbol():
    # 8 identical symbols -> ~1 byte of packed code bits (plus header).
    blob = compress(b"Z" * 8)
    assert decompress(blob) == b"Z" * 8


def test_empty_blob_is_minimal():
    blob = compress(b"")
    assert decompress(blob) == b""
    assert len(blob) == 6  # 4-byte length + 2-byte symbol count, no table
