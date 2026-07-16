"""Fuzz tests for the packet parser (protocol/packets.loads).

Robustness contract: for *any* input string, ``loads`` must either return a
valid Frame or raise ``ValueError`` (pydantic's ValidationError is a subclass).
It must never raise a different exception type, and never hang. Anything that
parses successfully must be a known frame and must re-serialize stably.

The RNG is seeded so failures are reproducible.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timezone

import pytest

from protocol import (
    AckFrame,
    ErrorFrame,
    Frame,
    Handshake,
    HelloFrame,
    Message,
    MessageFrame,
    dumps,
    loads,
)
from typing import get_args

# Every concrete frame type in the discriminated union -- a successful parse
# must be one of these regardless of how many new frame kinds were added.
_FRAME_TYPES = tuple(get_args(get_args(Frame)[0]))
_ALPHABET = "{}[]\":,0123456789abcdef truefalsenull.-_/\\\x00\n\t"


def _valid_serialized() -> list[str]:
    now = datetime.now(timezone.utc)
    return [
        dumps(HelloFrame(handshake=Handshake(
            id=1, user_id=2, device_id=3, timestamp=now, status="init"))),
        dumps(MessageFrame(message=Message(
            id=9, sender_id=2, receiver_id=5, ciphertext="ab", timestamp=now, status="s"))),
        dumps(AckFrame(ref_id=77)),
        dumps(ErrorFrame(code=400, reason="oops")),
    ]


def _assert_graceful(raw: str) -> None:
    """The core property: loads either rejects with ValueError or returns a
    valid, round-trip-stable frame -- nothing else is allowed."""
    try:
        frame = loads(raw)
    except ValueError:
        return  # acceptable rejection (incl. pydantic ValidationError)
    except Exception as exc:  # noqa: BLE001 - any other type is a bug
        pytest.fail(f"loads raised {type(exc).__name__} for {raw!r}: {exc}")
    assert isinstance(frame, _FRAME_TYPES)
    assert isinstance(loads(dumps(frame)), type(frame))


# --------------------------------------------------------------------------- #
# Degenerate inputs
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "raw",
    ["", " ", "\n", "null", "true", "123", "[]", "{}", '{"version": 1}',
     '{"frame": null}', '{"version": 1, "frame": {}}',
     '{"version": 1, "frame": {"type": "hello"}}',  # missing handshake
     '{"version": "x", "frame": {"type": "ack", "ref_id": 1}}',
     '{"version": 1, "frame": {"type": "ack", "ref_id": "NaN"}}',
     '\ud800', "\x00\x00\x00"],
)
def test_degenerate_inputs_are_graceful(raw):
    _assert_graceful(raw)


# --------------------------------------------------------------------------- #
# Random-string fuzzing
# --------------------------------------------------------------------------- #

def test_random_garbage_strings():
    rng = random.Random(0xC0FFEE)
    for _ in range(4000):
        n = rng.randint(0, 60)
        raw = "".join(rng.choice(_ALPHABET) for _ in range(n))
        _assert_graceful(raw)


# --------------------------------------------------------------------------- #
# Mutation fuzzing (bit-flip style, seeded from valid packets)
# --------------------------------------------------------------------------- #

def _mutate(s: str, rng: random.Random) -> str:
    chars = list(s)
    for _ in range(rng.randint(1, 6)):
        if not chars:
            chars.append(rng.choice(_ALPHABET))
            continue
        op = rng.randint(0, 3)
        i = rng.randrange(len(chars))
        if op == 0:               # delete
            del chars[i]
        elif op == 1:             # replace
            chars[i] = rng.choice(_ALPHABET)
        elif op == 2:             # insert
            chars.insert(i, rng.choice(_ALPHABET))
        else:                     # truncate
            del chars[i:]
    return "".join(chars)


def test_mutations_of_valid_packets():
    rng = random.Random(0xBADF00D)
    seeds = _valid_serialized()
    for _ in range(4000):
        _assert_graceful(_mutate(rng.choice(seeds), rng))


# --------------------------------------------------------------------------- #
# Schema fuzzing: structurally valid JSON, wrong shapes
# --------------------------------------------------------------------------- #

def test_wrong_shapes_with_valid_json():
    rng = random.Random(0x5EED)
    junk_values = [None, 0, -1, 1.5, "s", [], {}, [1, 2], {"x": 1}, True,
                   10 ** 40, "hello", {"type": "ack"}, {"type": "bogus"}]
    for _ in range(3000):
        payload = {
            "version": rng.choice([1, 2, 0, -5, "1", None, 1.0]),
            "frame": rng.choice(junk_values),
        }
        if rng.random() < 0.3:
            payload.pop(rng.choice(list(payload)))  # drop a required key
        _assert_graceful(json.dumps(payload))


def test_deeply_nested_json_is_graceful():
    # Excess nesting must be rejected cleanly, not blow the stack.
    raw = '{"version": 1, "frame": ' + "[" * 5000 + "]" * 5000 + "}"
    _assert_graceful(raw)
