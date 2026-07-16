"""Standalone WSS chat server entry point.

Flow per connection:

    HELLO        -> the client announces itself
    HELLO_ACK    <- server replies, signalling whether a password is required
    [Covenant]   <> if required, the 3-message PAKE authenticates the client
    CHAT/SEALED  <> authorized clients exchange messages, relayed to all peers

The password comes from ``PRIESTLY_PASSWD`` (or ``PASSWD``) in the environment,
falling back to ``config.cfg``. With no password the node runs open: clients
connect directly and exchange plaintext ``CHAT`` frames.
"""

from __future__ import annotations

import argparse
import sys

import config as config_module
from protocol import (
    ChatFrame,
    ErrorFrame,
    HelloAckFrame,
    HelloFrame,
    SealedFrame,
    covenant,
    dumps,
    loads,
)
from protocol.session import AuthenticationError, ReplayError
from transport import ConnectionClosed, WSSServer, WebSocket

from .relay import ClientRegistry, RegisteredClient, decode_message

DEFAULT_CERT = "certs/dev.crt"
DEFAULT_KEY = "certs/dev.key"

_registry = ClientRegistry()


def _recv_frame(ws: WebSocket):
    raw = ws.recv()
    return loads(raw if isinstance(raw, str) else raw.decode("utf-8"))


def make_handler(cfg: config_module.ServerConfig, registry: ClientRegistry | None = None):
    """Build the per-connection session handler bound to a config.

    ``registry`` defaults to the module-global hub; tests inject their own so
    each server instance has an isolated set of clients.
    """
    password = cfg.password.encode("utf-8") if cfg.password_required else None
    hub = registry if registry is not None else _registry

    def handle_session(ws: WebSocket, addr: tuple) -> None:
        client = None
        try:
            # 1. HELLO / HELLO_ACK
            hello = _recv_frame(ws)
            if not isinstance(hello, HelloFrame):
                ws.send(dumps(ErrorFrame(code=400, reason="expected HELLO")))
                return
            name = f"user{hello.handshake.user_id}"
            # A browser client cannot decompress our custom Huffman format, so
            # it flags itself here and we seal to it verbatim.
            is_browser = hello.handshake.status == "browser"
            ws.send(dumps(HelloAckFrame(
                server_name=cfg.server_name,
                password_required=cfg.password_required,
            )))

            # 2. Covenant handshake if the node is protected.
            session = None
            if password is not None:
                try:
                    session = covenant.run_server(ws, password)
                except covenant.CovenantError as exc:
                    print(f"[{addr}] auth failed: {exc}")
                    return
                if is_browser:
                    session.compress = False
                print(f"[{addr}] authenticated ({name})")
            else:
                print(f"[{addr}] joined open ({name})")

            # 3. Register and enter the message loop.
            client = RegisteredClient(ws, name, session)
            hub.add(client)
            _message_loop(ws, client, name, hub)
        except ConnectionClosed:
            pass
        finally:
            if client is not None:
                hub.remove(client)
            print(f"[{addr}] disconnected")

    return handle_session


def _message_loop(ws: WebSocket, client: RegisteredClient, name: str, hub: ClientRegistry) -> None:
    while True:
        frame = _recv_frame(ws)
        if isinstance(frame, SealedFrame):
            if client.session is None:
                ws.send(dumps(ErrorFrame(code=403, reason="not authenticated")))
                continue
            try:
                text, sender = decode_message(client.session.open(frame))
            except (AuthenticationError, ReplayError, ValueError) as exc:
                ws.send(dumps(ErrorFrame(code=400, reason=f"bad sealed frame: {exc}"[:120])))
                continue
            print(f"[{name}] {text!r}")
            hub.broadcast(client, text, sender or name)
        elif isinstance(frame, ChatFrame):
            if client.session is not None:
                ws.send(dumps(ErrorFrame(code=400, reason="node requires sealed frames")))
                continue
            print(f"[{name}] {frame.text!r}")
            hub.broadcast(client, frame.text, frame.sender or name)
        else:
            ws.send(dumps(ErrorFrame(code=422, reason="unexpected frame")))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="priestly-server", description="WSS chat server")
    parser.add_argument("--config", default=config_module.DEFAULT_PATH,
                        help="JSONX config file (default: config.cfg)")
    parser.add_argument("--name", default=None, help="override config server_name")
    parser.add_argument("--host", default=None, help="override config host")
    parser.add_argument("--port", type=int, default=None, help="override config port")
    parser.add_argument("--cert", default=DEFAULT_CERT)
    parser.add_argument("--key", default=DEFAULT_KEY)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    cfg = config_module.load_with_env(args.config)
    if args.name:
        cfg.server_name = args.name
    if args.host:
        cfg.host = args.host
    if args.port:
        cfg.port = args.port

    mode = "password-protected" if cfg.password_required else "open"
    print(f"[{cfg.server_name}] starting ({mode})")
    server = WSSServer(
        make_handler(cfg),
        certfile=args.cert,
        keyfile=args.key,
        host=cfg.host,
        port=cfg.port,
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
