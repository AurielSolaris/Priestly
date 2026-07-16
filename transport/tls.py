"""TLS context helpers -- the "S" in WSS -- built on the stdlib ``ssl`` module.

Certificate *generation* is not part of the standard library, so it lives in
``scripts/gen_dev_cert.py`` (which shells out to ``openssl``). These helpers
only load and configure contexts.
"""

from __future__ import annotations

import ssl


def server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """Build a TLS context for the WSS server from a cert/key pair."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    return context


def client_context(cafile: str | None = None, *, insecure: bool = False) -> ssl.SSLContext:
    """Build a TLS context for the WSS client.

    Pass ``cafile`` to trust a self-signed dev certificate. ``insecure=True``
    disables verification entirely -- only ever for throwaway local testing.
    """
    context = ssl.create_default_context(cafile=cafile)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context
