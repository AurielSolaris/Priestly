"""The Covenant handshake driver -- runs the 3-message PAKE over a connection.

This is the message-flow half of Layer 3; the cryptographic primitives live in
``crypto.covenant``. Each driver takes an authenticated-but-anonymous
:class:`~transport.ws.WebSocket`, walks the commit/challenge/confirm exchange,
and returns a ready :class:`~protocol.session.SessionState` on success or raises
:class:`CovenantError` on any failure (wrong password, tampering, or an
out-of-order frame).

Mutual authentication is preserved: the server's ``AUTH_OK`` carries its own key
MAC (``confirm_s``), which the client verifies before trusting the session. A
server that does not know the password cannot produce a passing ``confirm_s``.

    Client                         Server
      | ---- COVENANT_COMMIT ------> |
      | <--- COVENANT_CHALLENGE ---- |
      | ---- COVENANT_CONFIRM -----> |
      | <--- AUTH_OK / AUTH_FAIL --- |
"""

from __future__ import annotations

import hmac

from crypto import covenant as cv

from .packets import (
    AuthFailFrame,
    AuthOkFrame,
    CovenantChallengeFrame,
    CovenantCommitFrame,
    CovenantConfirmFrame,
    dumps,
    loads,
)
from .session import SessionState


class CovenantError(Exception):
    """The Covenant handshake did not complete successfully."""


def _recv_frame(ws):
    raw = ws.recv()
    return loads(raw if isinstance(raw, str) else raw.decode("utf-8"))


def _element_hex(value: int) -> str:
    return value.to_bytes(cv.ELEMENT_BYTES, "big").hex()


def _parse_element(text: str) -> int:
    """Parse a wire group element and reject degenerate / out-of-range values."""
    try:
        value = int(text, 16)
    except (ValueError, TypeError) as exc:
        raise CovenantError(f"malformed group element: {exc}") from exc
    if not (1 < value < cv.P - 1):
        raise CovenantError("group element out of range")
    return value


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

def run_client(ws, password: bytes) -> SessionState:
    """Drive the client side of the handshake; return the sealed session."""
    a = cv.random_exponent()
    public_a = cv.public_element(a)
    commit = cv.commit_digest(public_a)

    ws.send(dumps(CovenantCommitFrame(commit=commit.hex())))

    challenge = _recv_frame(ws)
    if isinstance(challenge, AuthFailFrame):
        raise CovenantError(f"server rejected handshake: {challenge.reason}")
    if not isinstance(challenge, CovenantChallengeFrame):
        raise CovenantError(f"expected challenge, got {type(challenge).__name__}")

    masked_b = _parse_element(challenge.masked_b)
    pe = cv.secret_to_element(password)
    public_b = cv.unmask(masked_b, pe)
    shared = cv.shared_secret(public_b, a)

    confirm_c = cv.confirm_mac(shared, commit, b"client", public_a)
    ws.send(dumps(CovenantConfirmFrame(a=_element_hex(public_a), confirm_c=confirm_c.hex())))

    result = _recv_frame(ws)
    if isinstance(result, AuthFailFrame):
        raise CovenantError(f"authentication failed: {result.reason}")
    if not isinstance(result, AuthOkFrame):
        raise CovenantError(f"expected auth result, got {type(result).__name__}")

    # Mutually authenticate the server before trusting the session.
    expected_s = cv.confirm_mac(shared, commit, b"server", public_b).hex()
    if not hmac.compare_digest(expected_s, result.confirm_s):
        raise CovenantError("server key confirmation failed (wrong password or MITM)")

    return SessionState(cv.derive_session_keys(shared), is_client=True)


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #

def run_server(ws, password: bytes) -> SessionState:
    """Drive the server side of the handshake; return the sealed session.

    On any client-side failure the server sends an ``AUTH_FAIL`` frame (so the
    client learns the outcome) and then raises.
    """
    commit_frame = _recv_frame(ws)
    if not isinstance(commit_frame, CovenantCommitFrame):
        _fail(ws, "expected commit")
    try:
        commit = bytes.fromhex(commit_frame.commit)
    except ValueError:
        _fail(ws, "malformed commit")
    if len(commit) != 20:
        _fail(ws, "malformed commit")

    b = cv.random_exponent()
    public_b = cv.public_element(b)
    pe = cv.secret_to_element(password)
    masked_b = cv.mask(public_b, pe)
    ws.send(dumps(CovenantChallengeFrame(masked_b=_element_hex(masked_b))))

    confirm_frame = _recv_frame(ws)
    if not isinstance(confirm_frame, CovenantConfirmFrame):
        _fail(ws, "expected confirm")

    public_a = _parse_element_or_fail(ws, confirm_frame.a)
    if not hmac.compare_digest(cv.commit_digest(public_a), commit):
        _fail(ws, "commit does not match revealed element")

    shared = cv.shared_secret(public_a, b)
    expected_c = cv.confirm_mac(shared, commit, b"client", public_a).hex()
    if not hmac.compare_digest(expected_c, confirm_frame.confirm_c):
        _fail(ws, "client key confirmation failed")

    confirm_s = cv.confirm_mac(shared, commit, b"server", public_b)
    ws.send(dumps(AuthOkFrame(confirm_s=confirm_s.hex())))
    return SessionState(cv.derive_session_keys(shared), is_client=False)


def _fail(ws, reason: str) -> None:
    """Send AUTH_FAIL and abort the handshake."""
    try:
        ws.send(dumps(AuthFailFrame(reason=reason)))
    except Exception:  # noqa: BLE001 - the peer may already be gone
        pass
    raise CovenantError(reason)


def _parse_element_or_fail(ws, text: str) -> int:
    try:
        return _parse_element(text)
    except CovenantError as exc:
        _fail(ws, str(exc))
