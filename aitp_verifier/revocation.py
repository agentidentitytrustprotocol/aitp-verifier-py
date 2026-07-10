"""Revocation-snapshot verification (RFC-AITP-0008 §1.5, JCS profile).

A snapshot is a signed ``revocation_list`` body. ``verify_revocation_snapshot``
checks the issuer, the signature, and freshness, then applies the deny list.
A stale/invalid snapshot is "no fresh snapshot": under ``fail_closed`` that is
treated as revoked (``TCT_REVOKED``); under ``soft_fail`` the queried jti is
reported not-revoked (the safe read-only subset).
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .crypto import sha256
from .errors import AitpError
from .jcs import canonicalize
from .sigfield import decode_tagged_signature

__all__ = ["verify_revocation_snapshot"]


def verify_revocation_snapshot(inp: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    policy = inp["policy"]
    snapshot = inp["snapshot"]
    now = int(inp["now"]) if now is None else now
    body = snapshot["revocation_list"]

    issuer = parse_aid(body["issuer"])
    fail_mode = policy.get("fail_mode", "fail_closed")

    sig_ok = True
    try:
        raw = decode_tagged_signature(snapshot["signature"], issuer, sig_err="TCT_SIGNATURE_INVALID")
        sig_ok = issuer.public_key.verify_digest(sha256(canonicalize(body)), raw)
    except AitpError:
        sig_ok = False

    issuer_ok = body["issuer"] == inp.get("expected_issuer")
    fresh = (now - int(body["published_at"])) <= int(policy["max_staleness_secs"]) and now < int(body["expires_at"])

    if not (sig_ok and issuer_ok and fresh):
        if fail_mode == "soft_fail":
            return {"revoked": False, "stale": True}
        raise AitpError("TCT_REVOKED", "no fresh valid revocation snapshot (fail_closed)")

    queried = inp.get("queried_jti")
    if queried is not None and any(e.get("jti") == queried for e in body.get("entries", [])):
        raise AitpError("TCT_REVOKED", "queried jti is on the deny list")
    return {"revoked": False}
