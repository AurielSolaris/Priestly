"""Unit tests for the TLS context helpers (transport/tls.py)."""

from __future__ import annotations

import ssl

import pytest

from tests.conftest import CERT, KEY
from transport.tls import client_context, server_context


def test_server_context_loads_cert():
    ctx = server_context(str(CERT), str(KEY))
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


def test_server_context_bad_path_raises():
    with pytest.raises((FileNotFoundError, ssl.SSLError, OSError)):
        server_context("does/not/exist.crt", "does/not/exist.key")


def test_client_context_default_verifies():
    ctx = client_context(cafile=str(CERT))
    assert ctx.check_hostname is True
    assert ctx.verify_mode == ssl.CERT_REQUIRED


def test_client_context_insecure_disables_verification():
    ctx = client_context(insecure=True)
    assert ctx.check_hostname is False
    assert ctx.verify_mode == ssl.CERT_NONE
