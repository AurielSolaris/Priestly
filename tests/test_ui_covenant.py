"""Cross-implementation test: the browser Covenant crypto (ui/covenant.js) must
agree bit-for-bit with the Python implementation, and seal/open must interop in
both directions.

Runs ui/covenant.js under Node with deterministic inputs and compares against
crypto/covenant.py + protocol/session.py. Skipped if Node is unavailable.
"""

from __future__ import annotations

import base64
import json
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from crypto import covenant as cv
from crypto.hmac_sha256 import sign_bytes
from protocol.session import SessionState

ROOT = Path(__file__).resolve().parent.parent
CROSSCHECK = ROOT / "tests" / "js" / "crosscheck.cjs"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")

# Deterministic exponents so both sides compute identical elements.
A_HEX = "0" * 500 + "1234567def"
B_HEX = "0" * 500 + "abcdef0987"
PASSWORD = "cross-check-secret"


def _hexz(value: int) -> str:
    return value.to_bytes(cv.ELEMENT_BYTES, "big").hex()


@pytest.fixture(scope="module")
def crosscheck():
    """Compute the Python values and the Node values from the same inputs."""
    a = int(A_HEX, 16)
    b = int(B_HEX, 16)
    public_a = cv.public_element(a)
    public_b = cv.public_element(b)
    commit = cv.commit_digest(public_a)
    pe = cv.secret_to_element(PASSWORD.encode())
    masked = (public_b * pe) % cv.P
    b_rec = cv.unmask(masked, pe)
    shared = cv.shared_secret(b_rec, a)
    keys = cv.derive_session_keys(shared)

    # A Python *server* session seals a frame for the browser to open.
    server = SessionState(keys, is_client=False, compress=False)
    server_frame = server.seal(json.dumps({"text": "from-python", "sender": "srv"}).encode())

    py = {
        "A": _hexz(public_a),
        "commit": commit.hex(),
        "pe": _hexz(pe),
        "masked": _hexz(masked),
        "shared": _hexz(shared),
        "confirm_c": cv.confirm_mac(shared, commit, b"client", public_a).hex(),
        "confirm_s": cv.confirm_mac(shared, commit, b"server", public_b).hex(),
        "client_mac": keys["client_mac"].hex(),
        "server_mac": keys["server_mac"].hex(),
    }

    job = {
        "password": PASSWORD,
        "a_hex": A_HEX,
        "b_hex": B_HEX,
        "server_frame": server_frame.model_dump(),
    }
    proc = subprocess.run(
        ["node", str(CROSSCHECK)],
        input=json.dumps(job),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"node failed: {proc.stderr}"
    js = json.loads(proc.stdout)
    return py, js, keys


@pytest.mark.parametrize(
    "field",
    ["A", "commit", "pe", "masked", "shared", "confirm_c", "confirm_s", "client_mac", "server_mac"],
)
def test_primitive_matches_python(crosscheck, field):
    py, js, _ = crosscheck
    assert js[field] == py[field], f"{field} diverged between JS and Python"


def test_python_opens_js_sealed_frame(crosscheck):
    # The browser sealed a client frame; a Python server session must open it.
    _, js, keys = crosscheck
    from protocol.packets import SealedFrame

    server = SessionState(keys, is_client=False, compress=False)
    frame = SealedFrame(**js["js_client_frame"])
    plaintext = server.open(frame)
    obj = json.loads(plaintext)
    assert obj == {"text": "from-browser", "sender": "browser"}


def test_js_opened_python_frame(crosscheck):
    # The browser opened the Python-sealed server frame and echoed its content.
    _, js, _ = crosscheck
    assert js["opened_server_frame"] == {"text": "from-python", "sender": "srv"}
