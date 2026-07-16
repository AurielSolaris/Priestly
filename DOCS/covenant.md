# Layer 3 — Covenant

> *"I do not need to know who you are. I only need to know that you are the
> correct person."*

Covenant is a **Minimal-Information authentication layer**: an anonymous
Password-Authenticated Key Exchange (PAKE) inspired by WPA3's SAE, stripped to
its cryptographic essence. It transmits **zero identity metadata** — the only
thing exchanged is proof that both peers share the same secret.

- **Anonymous** — no usernames, certificates, or device IDs.
- **Mutual** — both sides prove knowledge of the secret to each other.
- **Forward-secret** — the ephemeral exponents `a` and `b` are discarded after
  the handshake, so a later secret compromise cannot decrypt past sessions.
- **Offline-resistant** — an eavesdropper cannot dictionary-attack the transcript.
- **Small** — ~3 messages, and no dependency beyond stdlib + our HMAC-SHA256.

## Building blocks (`crypto/covenant.py`, `crypto/hkdf.py`)

- **Group** — RFC 3526 Group 14, the 2048-bit MODP prime `P` (verified prime in
  the test suite) with generator `G = 2`. Public and hardcoded on every node,
  including the browser.
- **`secret_to_element(password)`** — maps the shared secret into the group via
  `HMAC-SHA256(password, "Priestly-Covenant-Map")`, reduced mod `P` and squared
  to a quadratic residue (a simplified Dragonfly step). The result is invertible.
- **`modinv` / `extended_gcd`** — iterative modular inverse (iterative to avoid
  recursion limits on 2048-bit inputs), tested against Python's `pow(a, -1, m)`.
- **`hkdf_expand`** (`crypto/hkdf.py`) — HKDF-Expand (RFC 5869) over HMAC-SHA256;
  the shared secret is already uniform, so Expand alone suffices.

## The handshake (`protocol/covenant.py`)

```
Client                                   Server
  │                                        │
  │  a = random;  A = G^a mod P            │
  │  commit = SHA-1(A)                     │
  │ ──────── COVENANT_COMMIT (commit) ───► │
  │                                        │  b = random;  B = G^b mod P
  │                                        │  PE = secret_to_element(pw)
  │                                        │  masked_B = B·PE mod P
  │ ◄─── COVENANT_CHALLENGE (masked_B) ─── │
  │  PE = secret_to_element(pw)            │
  │  B  = masked_B · PE⁻¹ mod P            │
  │  shared = B^a  (= G^{ab})              │
  │  confirm_c = MAC(shared, …A)           │
  │ ─── COVENANT_CONFIRM (A, confirm_c) ─► │  verify commit == SHA-1(A)
  │                                        │  shared = A^b  (= G^{ab})
  │                                        │  verify confirm_c
  │                                        │  confirm_s = MAC(shared, …B)
  │ ◄──────── AUTH_OK (confirm_s) ──────── │
  │  verify confirm_s  ────────────────────┤  (or AUTH_FAIL on any failure)
```

Both sides derive `shared = G^{ab} mod P`. If either side does not know the
password, `PE` is wrong, the unmask produces the wrong `B`, the shared secrets
diverge, and the confirmation MACs fail to verify.

**As-built note.** The original spec sketched an async flow and folded the
server confirmation into a bare `AUTH_OK`. The shipped code is synchronous
(matching the threaded transport) and keeps `confirm_s` inside `AUTH_OK`, which
the client verifies — without it the client would never authenticate the
*server*, losing mutual authentication.

## Session keys

On success both sides run `derive_session_keys(shared)`, which HKDF-expands the
shared secret into four independent 32-byte subkeys:

```
client_write   server_write   client_mac   server_mac
```

This gives WPA3-style **directional separation**: a message authored by the
client can never verify as one authored by the server.

## Per-message sealing (`protocol/session.py`)

After the handshake, every application message is a `SealedFrame`:

```
epoch | seq | direction | payload (base64) | tag (hex HMAC-SHA256)
```

- **seal** — prefix a 1-byte compression marker (`0x00` stored / `0x01`
  Huffman, whichever is smaller), then tag `HMAC-SHA256(mac_key,
  epoch‖seq‖direction‖body)` and stamp a strictly increasing per-direction
  sequence number.
- **open** — recompute the tag with the *peer's* MAC key (constant-time
  compare), reject any `seq ≤ last_seen` (replay/reorder), then decompress.

Confidentiality comes from the underlying TLS tunnel; this layer adds
authenticity, integrity, and replay protection.

**Compression marker.** The marker exists so a non-Python peer (the browser)
can interoperate without reimplementing our custom Huffman codec: browser-facing
sessions set `compress=False` and always send `0x00` stored, which every peer
can read. Python↔Python sessions still use Huffman when it helps.

## What was intentionally left out

| Omitted | Reason |
|---------|--------|
| AES-GCM / ChaCha20 | TLS already provides confidentiality for this threat model |
| Certificates / X.509 | Violates "Minimal Information" — we don't need to know *who* you are |
| Digital signatures | We only need proof of shared-secret knowledge |
| 802.11 4-way handshake | The 3-message Covenant replaces it |

## Testing

- `tests/test_covenant_crypto.py` — PAKE math, `modinv` oracle, key derivation.
- `tests/test_covenant_handshake.py` — full flow over a socket pair: success,
  wrong password, forward secrecy, tampering.
- `tests/test_session.py` — seal/open, replay, tamper, direction, compression.
- `tests/test_ui_covenant.py` — cross-checks the **browser** crypto
  (`ui/covenant.js`) against Python bit-for-bit, and interops seal/open both ways.
