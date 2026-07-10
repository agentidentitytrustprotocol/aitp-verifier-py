"""aitp-verifier — an independent Python implementation of the AITP v0.2
verification core.

Written from the RFC-AITP specifications and JSON schemas only, to serve as the
second independent implementation the AITP spec requires before a surface can
be promoted from Draft to Final. It shares no code with the Rust reference
implementation (aitp-rs); the two meet only at the conformance pack's
byte-pinned golden vectors.

Public surface: the per-artifact verifiers, the crypto/JCS/JWS primitives they
build on, and the typed error vocabulary.
"""

from __future__ import annotations

from . import (
    aid,
    crypto,
    delegation,
    envelope,
    jcs,
    jwk,
    jws,
    manifest,
    revocation,
    tct,
    verify,
    voucher,
)
from .errors import AitpError

__all__ = [
    "AitpError",
    "aid",
    "crypto",
    "delegation",
    "envelope",
    "jcs",
    "jwk",
    "jws",
    "manifest",
    "revocation",
    "tct",
    "verify",
    "voucher",
]

__version__ = "0.1.0"
