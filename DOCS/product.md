# Product Layer

The protocol is exercised by a small product: a **central chat server**, a
**CLI client**, and a **browser UI**. Everything runs on one machine for
testing, and clients only ever talk to the server (never peer-to-peer).

## Server (`cli/server.py`, `cli/relay.py`)

A threaded WSS server that, per connection, runs `HELLO → HELLO_ACK →
[Covenant] → message loop`. Authorized clients are held in a thread-safe
`ClientRegistry`; each inbound message is relayed to every *other* client,
re-sealed under that recipient's session keys.

### Password from the environment

The Covenant password is read from `PRIESTLY_PASSWD` (or `PASSWD`), falling back
to `config.cfg`. The environment always wins, so the secret need never touch
disk:

```sh
PRIESTLY_PASSWD="my-shared-secret" make run-server   # protected node
make run-server                                       # open node (no password)
```

`HELLO_ACK` carries a `password_required` flag so a client knows before sending
anything whether it must authenticate.

## CLI client (`cli/client.py`, `cli/chat_client.py`)

```sh
python -m cli.client "hello"        # send one message and exit
python -m cli.client --listen       # stay connected, print incoming messages
python -m cli.client --ui           # open the browser UI
```

Password via `--password` or `PRIESTLY_PASSWD`. The `ChatClient` class drives
the whole flow (HELLO, optional Covenant auth, seal/open) and is shared with the
test suite, so the CLI and the tests exercise identical logic.

## Browser UI (`ui/`, `cli/ui_server.py`)

`python -m cli.client --ui` starts a tiny local HTTP server (auto-incrementing
from port 8080) that serves a single page and opens it in the browser. The page
connects a WebSocket **straight to the central server** — the browser never
talks peer-to-peer.

- **`ui/index.html`** — an X-inspired single-column chat UI (sticky header,
  timeline, bottom composer) themed in a Discord-blurple × Apple-blue accent.
  Built with Alpine.js from a CDN; no build step.
- **`ui/covenant.js`** — a faithful port of the Covenant + sealing crypto
  (BigInt + WebCrypto), shared verbatim with the test suite so the browser
  path is verified against Python.
- **`ui/logo.svg`** — an original rosary mark (a loop of beads and a cross).

The browser advertises `status="browser"` in its `HELLO`, which tells the
server to seal to it without Huffman (the browser sends/receives only "stored"
payloads).

### Note on the dev certificate

Because the server uses a self-signed cert, the browser must trust it before
`wss://` will connect. Visit `https://<host>:<port>/` once and accept the
certificate, then load the UI. (WebCrypto itself is available because the UI is
served from `localhost`, a secure context.)

## Running two clients

```sh
PRIESTLY_PASSWD="secret" make run-server   # terminal 1

python -m cli.client --ui                  # terminal 2 — client A
python -m cli.client --ui                  # terminal 3 — client B (port auto-increments)
```

Both authenticate with the password, then messages from A appear for B and vice
versa, relayed through the server. Without a password the node runs open and the
password gate is skipped entirely.

## Testing

- `tests/test_config_password.py` — env/file password precedence.
- `tests/test_relay.py` — registry fan-out, dead-peer removal, message codec.
- `tests/test_chat_integration.py` — two live clients through one server, open
  and password-protected, including the cross-session re-seal relay.
- `tests/test_ui_covenant.py` — the browser crypto vs Python (Node cross-check).
