"""Algorithm-tagged JCS-profile signature fields (RFC-AITP-0001 §5.4.3).

Envelope / Manifest / revocation / PoP / pinned-key proof signature fields may
carry an optional ``ed25519.`` or ``p256.`` prefix in v0.2; the untagged
86-char form is legacy Ed25519. The algorithm the field declares -- its tag,
or ``ed25519`` when untagged -- MUST match the signing AID's algorithm: a
mismatch is a downgrade attempt and rejects with the field's signature code.
So a ``p256`` signer MUST emit the tagged form; an untagged signature under a
``p256`` AID is read as Ed25519 and rejected (RFC-AITP-0001 §5.4.3 rule 3,
proposal agentidentitytrustprotocol#72 Item 2, fixture id-011).
"""

from __future__ import annotations

from .aid import Aid
from .b64 import b64url_decode
from .errors import AitpError

__all__ = ["decode_tagged_signature"]


def decode_tagged_signature(sig: object, aid: Aid, *, sig_err: str) -> bytes:
    """Return the raw signature bytes, enforcing the §5.4.3 tag rules."""
    if not isinstance(sig, str):
        raise AitpError(sig_err, f"signature is {type(sig).__name__}, not a string")
    tag = "ed25519"  # untagged = legacy Ed25519
    body = sig
    if "." in sig:
        tag, _, body = sig.partition(".")
        if tag not in ("ed25519", "p256"):
            raise AitpError(sig_err, f"unknown signature algorithm tag: {tag!r}")
    if tag != aid.alg:
        raise AitpError(sig_err, f"signature algorithm {tag!r} != signer AID algorithm {aid.alg!r}")
    try:
        raw = b64url_decode(body)
    except ValueError as exc:
        raise AitpError(sig_err, f"signature is not valid base64url: {exc}") from exc
    if len(raw) != 64:
        raise AitpError(sig_err, f"signature must be 64 raw bytes, got {len(raw)}")
    return raw
