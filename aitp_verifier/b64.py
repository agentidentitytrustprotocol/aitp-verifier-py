"""Unpadded base64url helpers (RFC 4648 §5).

AITP encodes every binary field — AID identifiers, signatures, nonces, JWK
thumbprints, JWS segments — as unpadded base64url. Emitting ``=`` padding is
non-conformant (RFC-AITP-0001 §5.4); decoding tolerates missing padding but
rejects the presence of ``=`` and any non-alphabet character so a signature
segment's bytes are never silently normalized.
"""

from __future__ import annotations

import base64

__all__ = ["b64url_decode", "b64url_encode"]

_ALPHABET = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def b64url_encode(data: bytes) -> str:
    """Encode *data* as unpadded base64url."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url. Reject ``=`` padding and stray characters."""
    if any(ch not in _ALPHABET for ch in text):
        raise ValueError("input contains non-base64url characters (or '=' padding)")
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)
