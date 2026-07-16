"""Standalone WSS chat client entry point.

    python -m cli.client "hello"          # send one message and exit
    python -m cli.client --listen         # stay connected, print incoming messages
    python -m cli.client --ui             # open the browser UI

Authentication: if the server requires a password, supply it with --password or
the PRIESTLY_PASSWD / PASSWD environment variable.
"""

from __future__ import annotations

import argparse
import sys

import config as config_module
from protocol.covenant import CovenantError
from transport import ConnectionClosed, WSSClient

from .chat_client import ChatClient

DEFAULT_CERT = "certs/dev.crt"


def _connect(args) -> ChatClient:
    cfg = config_module.load(args.config)
    host = args.host or cfg.host
    port = args.port or cfg.port
    ws = WSSClient(
        host=host, port=port,
        cafile=None if args.insecure else args.cafile,
        insecure=args.insecure,
    ).connect()
    print(f"connected to wss://{host}:{port}")

    client = ChatClient(ws)
    ack = client.hello()
    print(f"server: {client.server_name} (password_required={ack.password_required})")

    if client.password_required:
        password = args.password or config_module.password_from_env()
        if not password:
            print("error: server requires a password (use --password or PRIESTLY_PASSWD)")
            raise SystemExit(2)
        try:
            client.authenticate(password.encode("utf-8"))
        except CovenantError as exc:
            print(f"authentication failed: {exc}")
            raise SystemExit(2)
        print("authenticated (Covenant)")
    return client


def cmd_send(args) -> int:
    client = _connect(args)
    client.send(args.text)
    print(f"sent: {args.text!r}")
    return 0


def cmd_listen(args) -> int:
    client = _connect(args)
    print("listening for messages (Ctrl-C to quit)...")
    try:
        while True:
            text, sender = client.receive()
            print(f"<{sender}> {text}")
    except (ConnectionClosed, KeyboardInterrupt):
        return 0


def cmd_ui(args) -> int:
    from .ui_server import serve_ui
    cfg = config_module.load(args.config)
    serve_ui(
        ws_host=args.host or cfg.host,
        ws_port=args.port or cfg.port,
        ui_port=args.ui_port,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="priestly-client", description="WSS chat client")
    parser.add_argument("text", nargs="?", help="message to send (omit for --listen/--ui)")
    parser.add_argument("--listen", action="store_true", help="stay connected and print messages")
    parser.add_argument("--ui", action="store_true", help="open the browser UI")
    parser.add_argument("--ui-port", type=int, default=8080, help="preferred UI port")
    parser.add_argument("--password", default=None, help="Covenant password")
    parser.add_argument("--config", default=config_module.DEFAULT_PATH)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--cafile", default=DEFAULT_CERT, help="CA/cert to trust")
    parser.add_argument("--insecure", action="store_true", help="skip TLS verification")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.ui:
        return cmd_ui(args)
    if args.listen:
        return cmd_listen(args)
    if args.text is None:
        build_parser().error("provide a message, or use --listen / --ui")
    return cmd_send(args)


if __name__ == "__main__":
    sys.exit(main())
