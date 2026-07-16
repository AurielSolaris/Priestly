<p align="center">
  <img src="./ui/logo-horizontal.svg" alt="Priestly" height="64">
</p>

A custom, encrypted messaging **protocol** built from scratch over **WSS**
(WebSocket Secure), plus the **product** that makes it real: a central chat
server, a CLI client, and a browser UI. A protocol is only as useful as the demo
that exercises it, so Priestly is a two-layer system — protocol + product.

Everything is hand-rolled on the Python standard library: the WebSocket layer
(RFC 6455), TLS wiring, packet framing, JSONX config, SHA-1, the Huffman codec,
and the Covenant PAKE. The sole runtime dependency is `pydantic` (typing /
validation). The one deliberate exception to "from scratch" is HMAC-SHA256 — a
keyed MAC is security-critical, so it uses the stdlib's audited `hmac`.

## Design principles

- **UNIX philosophy** — one file does one job; each test file targets one feature.
- **NASA / SQLite philosophy** — every module is tested against its edge cases.
  SHA-1, HMAC-SHA256, and HKDF are checked against stdlib oracles; Huffman by
  lossless round-trip; the WebSocket codec at every frame boundary and against
  malformed frames; the packet parser is fuzz-tested; the Covenant PAKE is
  driven end-to-end; and the **browser** crypto is cross-checked against Python
  bit-for-bit under Node. Current suite: **406 tests**.

## The three security layers

| Layer | Primitive | Property |
|-------|-----------|----------|
| 1 | SHA-1 | unkeyed integrity (corruption detection) |
| 2 | HMAC-SHA256 | keyed authenticity (tamper detection) |
| 3 | **Covenant** | anonymous PAKE: session authorization + forward secrecy |

Covenant authenticates a connection against a shared password that is **never
transmitted**, derives per-direction session keys, and then seals every message
with an HMAC tag and a sequence number (replay-protected). See
[DOCS/covenant.md](DOCS/covenant.md).

## Layout

```
config.py            JSONX config loader + env password
config.cfg           node config: server_name, host, port
Makefile             test / coverage / build workflow
DOCS/                architecture, covenant, product docs
transport/           WebSocket (RFC 6455) over stdlib sockets + TLS
  ws.py  tls.py  server.py  client.py
protocol/            typed frames + the protocol logic
  models.py          Handshake / Message models
  packets.py         packet envelope (discriminated union) + wire codec
  covenant.py        Covenant handshake driver (Layer 3)
  session.py         sealed messages: seal / open / anti-replay
crypto/              from-scratch / stdlib primitives
  sha1.py            SHA-1 (Layer 1, integrity)
  hmac_sha256.py     HMAC-SHA256 (Layer 2, authenticity)
  hkdf.py            HKDF-Expand (session-key derivation)
  covenant.py        PAKE math: group, mapping, modinv, key derivation
  huffman.py         Huffman compression
cli/                 the product
  server.py          central chat server (relay hub)
  client.py          CLI client (send / --listen / --ui)
  chat_client.py     shared client protocol flow
  relay.py           connected-client registry + fan-out
  ui_server.py       serves the browser UI
ui/                  the browser client
  index.html         X-inspired chat UI (Discord-blurple × Apple-blue)
  covenant.js        browser Covenant crypto (shared with the tests)
  logo.svg           rosary emblem (favicon / badge / UI header)
  logo-horizontal.svg  brand lockup for the README header
tests/               one file per feature (Python + a Node cross-check)
```

## Quickstart

```sh
make install        # uv sync (deps + dev tools)
make cert           # generate certs/dev.crt + certs/dev.key
make test           # run the full suite

# open node (no password)
make run-server
python -m cli.client --ui              # browser UI  (or:)
python -m cli.client "hello over WSS"  # one-shot CLI send

# protected node (Covenant)
PRIESTLY_PASSWD="shared-secret" make run-server
python -m cli.client "hi" --password "shared-secret"
python -m cli.client --listen --password "shared-secret"
```

Two browser clients: run `python -m cli.client --ui` twice — each connects to
the central server, authenticates, and sees the other's messages. Clients never
talk peer-to-peer; the server is a decrypting relay that re-seals per recipient.

### Local browser testing (`--no-tls`)

Browsers refuse the self-signed dev certificate, so for local testing run the
server in plain-`ws://` mode:

```sh
python -m cli.server --no-tls
python -m cli.client --ui --no-tls      # UI connects over ws://, no cert prompt
python -m cli.client "hi" --no-tls      # CLI over ws://
```

This drops only *wire confidentiality* — the Covenant handshake still
authenticates and every message is still HMAC-sealed. TLS (`wss://`) remains the
default for real use; to keep it, trust `certs/dev.crt` in your browser/OS first.

## Standalone binaries

The client and server compile to independent executables (the test bench is a
single machine):

```sh
make build          # -> dist/priestly-server(.exe) and dist/priestly-client(.exe)
```

## Configuration (JSONX)

`config.cfg` uses **JSONX** = JSONL + JSONC: one JSON object per line (records
merge top-to-bottom, later keys win), with `//` / `#` / `/* */` comments and
trailing commas allowed. The Covenant password may live here or, preferably, in
the `PRIESTLY_PASSWD` environment variable (which overrides the file).

```jsonc
/* Priestly node configuration */
{"server_name": "priestly-node-1"}
{"host": "localhost", "port": 8765,}
// {"password": "shared-secret"}   // or set PRIESTLY_PASSWD instead
```

## Status

Working end-to-end across the whole stack: TLS → WebSocket → typed packets →
the three security layers. The Covenant handshake authenticates clients, sealed
messages carry per-message HMAC + sequence numbers, and the central server
relays between authenticated clients. The CLI and browser UI both drive the full
flow, and the browser crypto is verified against the Python implementation.
Documentation lives in [DOCS/](DOCS/README.md).
