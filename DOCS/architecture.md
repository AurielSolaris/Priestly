# Architecture

Priestly is organized as a **protocol layer** and a **product layer**, kept
strictly decoupled: the transport knows nothing about packets, the protocol
knows nothing about sockets, and the product wires them together.

## The stack

```
┌──────────────────────────────────────────────┐
│  Product: CLI client / browser UI            │  cli/, ui/
├──────────────────────────────────────────────┤
│  Central server (relay hub)                  │  cli/server.py, cli/relay.py
├──────────────────────────────────────────────┤
│  Layer 3: Covenant                           │  protocol/covenant.py
│   • anonymous PAKE handshake (once)          │  crypto/covenant.py
│   • per-message HMAC + sequence (sealing)    │  protocol/session.py
│   • directional keys via HKDF                │  crypto/hkdf.py
├──────────────────────────────────────────────┤
│  Layer 2: HMAC-SHA256 (keyed authenticity)   │  crypto/hmac_sha256.py
├──────────────────────────────────────────────┤
│  Layer 1: SHA-1 (unkeyed integrity)          │  crypto/sha1.py
├──────────────────────────────────────────────┤
│  Huffman compression                         │  crypto/huffman.py
├──────────────────────────────────────────────┤
│  Packet envelope (typed frames)              │  protocol/packets.py
├──────────────────────────────────────────────┤
│  WebSocket (RFC 6455)  →  TLS*  →  TCP        │  transport/
└──────────────────────────────────────────────┘
```

\* TLS is the default (`wss://`) but optional: `--no-tls` serves plain `ws://`
for local browser testing. Dropping it removes only wire confidentiality —
Covenant auth and the per-message HMAC still hold. See
[product.md](product.md#tls-and-the-dev-certificate).

## Client/server topology

Every client connects to a **central server**; clients never talk peer-to-peer.
The server is a *decrypting relay*: because each connection negotiates its own
ephemeral Covenant session, the server opens an incoming sealed message and
re-seals it under each recipient's own keys before forwarding. This is
consistent with the threat model — the server can read messages (TLS guards the
wire; the password gates entry) — and it keeps every client's session
independent and forward-secret.

```
   Client A ──wss──┐                 ┌──wss── Client C
                   ├──► central server ──►
   Client B ──wss──┘   (opens, re-seals,     └──wss── ...
                        fans out to peers)
```

## The three security layers

| Layer | Primitive | Property | Keyed? |
|-------|-----------|----------|--------|
| 1 | SHA-1 | integrity / corruption detection | no |
| 2 | HMAC-SHA256 | authenticity / tamper detection | yes (shared key) |
| 3 | Covenant | session authorization + forward secrecy | yes (derived per session) |

Layer 3 is the subject of [covenant.md](covenant.md). Layers 1 and 2 are the
underlying digests it (and the sealed-message tags) are built from.

## Packet envelope

Every wire message is a JSON `Packet` = `{version, frame}`, where `frame` is a
pydantic discriminated union keyed on `type`. Adding a new message kind means
adding a frame class and a union member; `dumps`/`loads` in
`protocol/packets.py` are the only bridge between the protocol and transport
layers. Frame types: `hello`, `hello_ack`, `message`, `ack`, `error`,
`covenant_commit`, `covenant_challenge`, `covenant_confirm`, `auth_ok`,
`auth_fail`, `sealed`, `chat`.

## Message flow

```
HELLO         → client announces itself (status="browser" for the web UI)
HELLO_ACK     ← server states whether a password is required
[Covenant]    ↔ if required, the 3-message PAKE authenticates the client
CHAT / SEALED ↔ authorized clients exchange messages, relayed to all peers
```

Open nodes exchange plaintext `chat` frames; protected nodes exchange
authenticated `sealed` frames.
