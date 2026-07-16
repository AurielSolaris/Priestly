"""JSONX config: JSONL records + JSONC ergonomics.

JSONX is this project's config format, combining two useful ideas:

* **JSONL** -- one JSON object per line. Records are merged top to bottom, so a
  later line overrides an earlier key. This makes layering and appending config
  trivial (drop a new line at the bottom to override a value).
* **JSONC** -- ``//`` and ``#`` line comments, ``/* ... */`` block comments, and
  trailing commas are all allowed and stripped before parsing.

Comment and trailing-comma removal is string-aware, so a ``"//"`` or ``",}"``
appearing inside a JSON string value is left untouched. Because records are
line-delimited, each object must sit on a single line.

    /* priestly node config */
    {"server_name": "priestly-node-1"}
    {"host": "localhost", "port": 8765}   // later lines override earlier keys
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field

DEFAULT_PATH = "config.cfg"

# Environment variables that supply the Layer 3 (Covenant) password, in
# precedence order. The env var always wins over any value in the config file
# so secrets need not be written to disk.
_PASSWORD_ENV_VARS = ("PRIESTLY_PASSWD", "PASSWD")


class ServerConfig(BaseModel):
    """Validated node configuration. Unknown keys are rejected to catch typos."""

    model_config = ConfigDict(extra="forbid")

    server_name: str = "priestly"
    host: str = "localhost"
    port: int = Field(default=8765, ge=1, le=65535)
    # Layer 3 Covenant password. None => open node (no authentication required).
    password: Optional[str] = None

    @property
    def password_required(self) -> bool:
        """Whether a client must complete the Covenant handshake to proceed."""
        return bool(self.password)


# --------------------------------------------------------------------------- #
# JSONX parsing
# --------------------------------------------------------------------------- #

def _strip_comments(text: str) -> str:
    """Remove //, # and /* */ comments, ignoring any inside string literals.

    Newlines inside block comments are preserved so line numbers -- and the
    JSONL record boundaries -- stay intact.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = escaped = False

    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            i += 1
            continue

        if c == '"':
            in_string = True
            out.append(c)
        elif c == "#" or (c == "/" and i + 1 < n and text[i + 1] == "/"):
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                if text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 2  # consume the closing */
            continue
        else:
            out.append(c)
        i += 1

    return "".join(out)


def _strip_trailing_commas(text: str) -> str:
    """Drop commas that directly precede a } or ], ignoring string contents."""
    out: list[str] = []
    i, n = 0, len(text)
    in_string = escaped = False

    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if escaped:
                escaped = False
            elif c == "\\":
                escaped = True
            elif c == '"':
                in_string = False
            i += 1
            continue

        if c == '"':
            in_string = True
            out.append(c)
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1  # trailing comma -> drop it
                continue
            out.append(c)
        else:
            out.append(c)
        i += 1

    return "".join(out)


def parse_jsonx(text: str) -> dict:
    """Parse JSONX text into a single merged dict."""
    cleaned = _strip_trailing_commas(_strip_comments(text))
    merged: dict = {}
    for lineno, line in enumerate(cleaned.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"config line {lineno}: invalid JSON ({exc})") from exc
        if not isinstance(record, dict):
            raise ValueError(f"config line {lineno}: each record must be a JSON object")
        merged.update(record)
    return merged


def load(path: str = DEFAULT_PATH) -> ServerConfig:
    """Load and validate config from ``path``; use defaults if it is absent."""
    p = Path(path)
    if not p.exists():
        return ServerConfig()
    return ServerConfig.model_validate(parse_jsonx(p.read_text(encoding="utf-8")))


def password_from_env(env: Optional[dict] = None) -> Optional[str]:
    """Return the Covenant password from the environment, or None if unset.

    ``env`` defaults to ``os.environ``; it is injectable for testing. An empty
    string is treated as unset so ``PASSWD=`` does not accidentally lock a node.
    """
    source = os.environ if env is None else env
    for name in _PASSWORD_ENV_VARS:
        value = source.get(name)
        if value:
            return value
    return None


def load_with_env(path: str = DEFAULT_PATH, env: Optional[dict] = None) -> ServerConfig:
    """Load config, then let the environment override the Covenant password.

    This keeps the secret out of ``config.cfg``: set ``PRIESTLY_PASSWD`` in the
    environment and the node requires authentication without the password ever
    touching disk.
    """
    cfg = load(path)
    env_password = password_from_env(env)
    if env_password is not None:
        cfg.password = env_password
    return cfg
