"""Session Trust Bundle verification (RFC-AITP-0010 §5).

A coordinator-signed bundle binds a set of participants, each with an embedded
peer-issued TCT. Verification order is load-bearing: version, then expiry
(**before** the signature — a stale bundle is rejected even if it would verify),
then the expiry-window invariant (``expires_at`` == the minimum participant TCT
``exp``), then the coordinator signature over the JCS-canonical bundle body,
then each participant TCT (issued by the coordinator, ``aud`` == the participant
AID), then self-membership.

Draft surface (``experimental-session-bundle``): a core verifier reports SKIP
for this operation; this module is the opt-in implementation.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .crypto import sha256
from .errors import AitpError
from .jcs import canonicalize
from .jws import parse_compact, verify_jws
from .sigfield import decode_tagged_signature

__all__ = ["verify_session_bundle"]


def verify_session_bundle(inp: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    now = int(inp["now"]) if now is None else now
    self_aid = inp["self_aid"]
    outer = inp["session_bundle"]
    body = outer["session_bundle"]
    participants = body["participants"]

    if body.get("version") != "aitp/0.2":
        raise AitpError("BUNDLE_VERSION_MISMATCH", f"unknown bundle version {body.get('version')!r}")
    # Expiry MUST run before the signature check (bundle-003).
    if now >= int(body["expires_at"]):
        raise AitpError("BUNDLE_EXPIRED", "session bundle expired")
    if not participants:
        raise AitpError("BUNDLE_EMPTY_PARTICIPANTS", "session bundle has no participants")

    tct_exps = [int(parse_compact(p["tct"], structural_code="BUNDLE_PARTICIPANT_TCT_INVALID").claims["exp"]) for p in participants]
    if int(body["expires_at"]) != min(tct_exps):
        raise AitpError("BUNDLE_EXPIRY_WINDOW_INVARIANT", "expires_at != min participant TCT exp")

    coordinator = body["coordinator"]
    coord = parse_aid(coordinator)
    raw = decode_tagged_signature(outer["signature"], coord, sig_err="BUNDLE_INVALID_SIGNATURE")
    if not coord.public_key.verify_digest(sha256(canonicalize(body)), raw):
        raise AitpError("BUNDLE_INVALID_SIGNATURE", "coordinator signature invalid")

    for p in participants:
        iss = parse_compact(p["tct"], structural_code="BUNDLE_PARTICIPANT_TCT_INVALID").claims.get("iss")
        claims = verify_jws(
            p["tct"], iss_aid=str(iss), expected_typ="aitp-tct+jwt",
            typ_err="BUNDLE_PARTICIPANT_TCT_INVALID", alg_err="BUNDLE_PARTICIPANT_TCT_INVALID",
            sig_err="BUNDLE_PARTICIPANT_TCT_INVALID",
        )
        if claims.get("iss") != coordinator:
            raise AitpError("BUNDLE_COORDINATOR_ISSUER_MISMATCH", "participant TCT iss != coordinator")
        if claims.get("aud") != p["aid"]:
            raise AitpError("BUNDLE_AUDIENCE_MISMATCH", "participant TCT aud != participant AID")

    if self_aid not in {p["aid"] for p in participants}:
        raise AitpError("BUNDLE_NOT_MEMBER", "verifier AID is not a bundle participant")

    return {"ok": True}
