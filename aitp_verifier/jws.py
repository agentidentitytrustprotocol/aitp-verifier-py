"""Compact JWS profile for the portable trust artifacts (RFC-AITP-0001 §5.4.5).

The TCT, grant voucher, and delegation token are RFC 7515 compact JWS strings.
Verification is strict and deliberately narrow:

* exactly three non-empty ``.``-separated unpadded-base64url segments;
* the protected header contains **exactly** ``alg`` and ``typ`` — any other
  parameter (``kid``, ``jwk``, ``crit`` …) is rejected;
* ``typ`` must equal the single value expected for the verification context;
* ``alg`` is pinned from the signer's AID (never read from the token) and
  ``none`` in any capitalization is rejected;
* the signature covers the transmitted ``header.payload`` bytes — verifiers
  never re-serialize.

The error code raised at each step is supplied by the calling surface module,
because the same structural failure maps to different wire codes for a TCT
(``TCT_SIGNATURE_INVALID``) versus a delegation token
(``DELEGATION_INVALID_SIGNATURE``).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .aid import parse_aid
from .b64 import b64url_decode, b64url_encode
from .crypto import PrivateKey
from .errors import AitpError
from .jcs import canonicalize, loads

__all__ = ["ParsedJws", "parse_compact", "verify_jws", "encode_jws"]

_BAD = "INVALID_TOKEN"


@dataclass(frozen=True)
class ParsedJws:
    header: dict[str, Any]
    claims: dict[str, Any]
    signing_input: bytes
    signature: bytes


def parse_compact(token: str, *, structural_code: str = _BAD) -> ParsedJws:
    """Strictly parse a compact JWS. Raises ``AitpError(structural_code)``."""
    if not isinstance(token, str):
        raise AitpError(structural_code, "token is not a string")
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise AitpError(structural_code, "compact JWS must have three non-empty segments")
    try:
        header_bytes = b64url_decode(parts[0])
        payload_bytes = b64url_decode(parts[1])
        signature = b64url_decode(parts[2])
    except ValueError as exc:
        raise AitpError(structural_code, f"segment is not valid base64url: {exc}") from exc
    try:
        header = loads(header_bytes)
        claims = loads(payload_bytes)
    except Exception as exc:  # noqa: BLE001 - JcsError or json error
        raise AitpError(structural_code, f"segment is not valid JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise AitpError(structural_code, "header and payload must be JSON objects")
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    return ParsedJws(header=header, claims=claims, signing_input=signing_input, signature=signature)


def verify_jws(
    token: str,
    *,
    iss_aid: str,
    expected_typ: str,
    typ_err: str,
    alg_err: str,
    sig_err: str,
) -> dict[str, Any]:
    """Parse + verify a compact JWS, returning its decoded claims.

    Runs the §5.4.5 order: strict parse → ``typ`` → AID-pinned ``alg`` →
    signature. Each failure raises ``AitpError`` with the caller-supplied code.
    Structural failures raise ``sig_err`` (the artifact's signature-family code).
    """
    parsed = parse_compact(token, structural_code=sig_err)

    # Header must be exactly {alg, typ}.
    if set(parsed.header.keys()) != {"alg", "typ"}:
        raise AitpError(alg_err, f"JWS header must contain exactly alg and typ, got {sorted(parsed.header)}")

    if parsed.header.get("typ") != expected_typ:
        raise AitpError(typ_err, f"typ {parsed.header.get('typ')!r} != {expected_typ!r}")

    aid = parse_aid(iss_aid)
    if parsed.header.get("alg") != aid.jose_alg:
        raise AitpError(alg_err, f"alg {parsed.header.get('alg')!r} != AID-pinned {aid.jose_alg!r}")

    if not aid.public_key.verify_jose(parsed.signing_input, parsed.signature):
        raise AitpError(sig_err, "compact JWS signature verification failed")

    return parsed.claims


def encode_jws(typ: str, claims: dict[str, Any], private_key: PrivateKey, *, alg: str) -> str:
    """Mint a compact JWS (used by the conformance minter only).

    The protected header is exactly ``{"alg": <alg>, "typ": <typ>}`` in that
    member order; the payload is the JCS canonical form of *claims* so re-mints
    are byte-stable (verifiers never rely on this — they use transmitted bytes).
    """
    header_bytes = json.dumps({"alg": alg, "typ": typ}, separators=(",", ":")).encode("ascii")
    payload_bytes = canonicalize(claims)
    signing_input = b64url_encode(header_bytes) + "." + b64url_encode(payload_bytes)
    signature = private_key.sign_jose(signing_input.encode("ascii"))
    return signing_input + "." + b64url_encode(signature)
