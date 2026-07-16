"""Generate a self-signed dev certificate for local WSS testing.

Certificate creation is not in the Python standard library, so this shells out
to ``openssl``. The result is trusted by the client via ``--cafile certs/dev.crt``
-- never use this certificate anywhere but localhost development.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parent.parent / "certs"


def main() -> int:
    CERT_DIR.mkdir(exist_ok=True)
    key = CERT_DIR / "dev.key"
    crt = CERT_DIR / "dev.crt"

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key),
        "-out", str(crt),
        "-days", "365",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("openssl not found on PATH -- install it or generate a cert manually.")
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"openssl failed: {exc}")
        return exc.returncode

    print(f"wrote {crt}\nwrote {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
