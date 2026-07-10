"""AITP Agent ID (AID) parsing and key derivation (RFC-AITP-0001 §5.3).

An AID is a self-certifying identifier: the public key is embedded in the
identifier component, so a ``pubkey`` AID resolves to a key with no network
step. Three accepted forms:

* ``aid:pubkey:<43-char>``           — legacy, implicitly Ed25519
* ``aid:pubkey:ed25519:<43-char>``   — algorithm-tagged Ed25519
* ``aid:pubkey:p256:<44-char>``      — algorithm-tagged P-256 (SEC1 compressed)

The algorithm tag also pins the sole acceptable JOSE ``alg`` for the compact-JWS
profile (§5.4.5): Ed25519 → ``EdDSA``, P-256 → ``ES256``.
"""

from __future__ import annotations

from dataclasses import dataclass

from .b64 import b64url_decode
from .crypto import ALG_ED25519, ALG_P256, PublicKey

__all__ = ["Aid", "parse_aid"]

_JOSE_ALG = {ALG_ED25519: "EdDSA", ALG_P256: "ES256"}


@dataclass(frozen=True)
class Aid:
    """A parsed AID: its wire string, algorithm, raw key bytes, and public key."""

    aid: str
    alg: str
    raw_key: bytes
    public_key: PublicKey

    @property
    def jose_alg(self) -> str:
        """The sole acceptable compact-JWS ``alg`` for this AID (§5.4.5)."""
        return _JOSE_ALG[self.alg]


def parse_aid(aid: str) -> Aid:
    """Parse an AID string. Raises ``ValueError`` on any malformed form.

    Length and alphabet are enforced strictly (§5.4): Ed25519 identifiers are
    exactly 43 unpadded-base64url chars (32 bytes), P-256 exactly 44 (33 bytes
    SEC1 compressed). A wrong length or an unregistered algorithm tag is a hard
    reject — verifiers MUST NOT guess.
    """
    if not aid.startswith("aid:pubkey:"):
        raise ValueError(f"unsupported AID method (only aid:pubkey: is defined): {aid!r}")
    rest = aid[len("aid:pubkey:") :]
    if rest.startswith("ed25519:"):
        alg, ident = ALG_ED25519, rest[len("ed25519:") :]
    elif rest.startswith("p256:"):
        alg, ident = ALG_P256, rest[len("p256:") :]
    else:
        alg, ident = ALG_ED25519, rest  # legacy untagged form
    expected_len = 43 if alg == ALG_ED25519 else 44
    if len(ident) != expected_len:
        raise ValueError(f"{alg} AID identifier must be {expected_len} chars, got {len(ident)}: {aid!r}")
    raw = b64url_decode(ident)
    return Aid(aid=aid, alg=alg, raw_key=raw, public_key=PublicKey.from_raw(alg, raw))
