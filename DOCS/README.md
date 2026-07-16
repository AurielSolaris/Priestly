# Priestly Documentation

Priestly is a two-layer system:

- **Protocol layer** — a from-scratch encrypted messaging protocol over WSS
  (WebSocket Secure), with three stacked security layers.
- **Product layer** — the demo that makes the protocol usable: a central chat
  server, a CLI client, and a browser UI. *A protocol is only as real as the
  product that exercises it.*

| Document | What it covers |
|----------|----------------|
| [architecture.md](architecture.md) | The full stack, every layer, and how bytes flow through it |
| [covenant.md](covenant.md) | Layer 3 (Covenant): the anonymous PAKE handshake and per-message sealing |
| [product.md](product.md) | The CLI chat app, the browser UI, password enforcement, and two-client testing |

## Design principles

- **UNIX philosophy** — one file does one job; each test file targets one feature.
- **NASA / SQLite philosophy** — every module is tested against its edge cases,
  including cross-checking the browser crypto against the Python implementation.
- **From scratch, minimal dependencies** — everything is stdlib or hand-rolled;
  the sole runtime dependency is `pydantic` (typing/validation). The one
  deliberate exception is HMAC-SHA256, which uses the stdlib's audited `hmac`
  rather than a hand-rolled keyed MAC.

## Quickstart

```sh
make install      # deps + dev tools
make cert         # self-signed dev certificate
make test         # full suite

# open node (no password)
make run-server
python -m cli.client --ui          # browser UI, or:
python -m cli.client "hello"       # one-shot CLI send

# protected node (Covenant)
PRIESTLY_PASSWD="shared-secret" make run-server
python -m cli.client "hi" --password "shared-secret"
```
