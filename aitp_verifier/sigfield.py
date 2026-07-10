"""Algorithm-tagged JCS-profile signature fields (RFC-AITP-0001 §5.4.3).

Envelope / Manifest / revocation / PoP signature fields may carry an optional
``ed25519.`` or ``p256.`` prefix in v0.2; the untagged 86-char form is legacy
Ed25519. The tag, when present, MUST match the signing AID's algorithm — a
mismatch is a downgrade attempt and rejects with the field's signature code.
"""

from __future__ import annotations

from .aid import Aid
from .b64 import b64url_decode
from .errors import AitpError

__all__ = ["decode_tagged_signature"]


def decode_tagged_signature(sig: str, aid: Aid, *, sig_err: str) -> bytes:
    """Return the raw signature bytes, enforcing the §5.4.3 tag rules."""
    tag = None
    body = sig
    if "." in sig:
        tag, _, body = sig.partition(".")
        if tag not in ("ed25519", "p256"):
            raise AitpError(sig_err, f"unknown signature algorithm tag: {tag!r}")
        if tag != aid.alg:
            raise AitpError(sig_err, f"signature tag {tag!r} != signer AID algorithm {aid.alg!r}")
    try:
        raw = b64url_decode(body)
    except ValueError as exc:
        raise AitpError(sig_err, f"signature is not valid base64url: {exc}") from exc
    if len(raw) != 64:
        raise AitpError(sig_err, f"signature must be 64 raw bytes, got {len(raw)}")
    return raw
