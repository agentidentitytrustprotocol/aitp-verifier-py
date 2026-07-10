"""Trust Context Token verification (RFC-AITP-0005 §7.2 / §10).

``verify_tct`` runs the ordered checklist: strict compact-JWS parse → ``typ``
(``aitp-tct+jwt``) → AID-pinned ``alg`` → signature → claims (``ver``, ``aud``,
literal ``exp``, ``cnf.jkt`` binding) → the §10.4 conditional issuer-Manifest
expiry bound → revocation. Revocation runs strictly last so a tampered token
fails at the signature step and never reaches a (potentially networked) deny
list — the RFC-AITP-0008 §3.3 ordering rev-004 pins.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .errors import AitpError
from .jwk import thumbprint
from .jws import parse_compact, verify_jws
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_tct"]


def verify_tct(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    token = inp["tct_token"]
    iss = parse_compact(token, structural_code="TCT_SIGNATURE_INVALID").claims.get("iss")
    claims = verify_jws(
        token,
        iss_aid=str(iss),
        expected_typ="aitp-tct+jwt",
        typ_err="TOKEN_TYP_MISMATCH",
        alg_err="TOKEN_ALG_MISMATCH",
        sig_err="TCT_SIGNATURE_INVALID",
    )

    if claims.get("ver") != "aitp/0.2":
        raise AitpError("UNKNOWN_VERSION", f"unknown ver {claims.get('ver')!r}")

    expected_aud = inp.get("expected_audience")
    if expected_aud is not None and claims.get("aud") != expected_aud:
        raise AitpError("AUDIENCE_MISMATCH", "TCT aud does not match verifier AID")

    if now >= int(claims["exp"]):
        raise AitpError("TCT_EXPIRED", "TCT exp is in the past")

    # cnf.jkt MUST equal the thumbprint of the key in the subject AID.
    if claims.get("cnf", {}).get("jkt") != thumbprint(parse_aid(str(claims["sub"]))):
        raise AitpError("TCT_CNF_MISMATCH", "cnf.jkt does not bind the subject key")

    # §10.4 conditional bound: only when the issuer Manifest is supplied.
    issuer_manifest = inp.get("issuer_manifest")
    if issuer_manifest is not None and int(claims["exp"]) > int(issuer_manifest["expires_at"]):
        raise AitpError("TCT_EXPIRES_AFTER_MANIFEST", "TCT outlives the issuer Manifest")

    _check_revocation(claims, inp)
    return {"grants": claims["grants"]}


def _check_revocation(claims: dict[str, Any], inp: dict[str, Any]) -> None:
    revlist = inp.get("issuer_revocation_list")
    if not isinstance(revlist, dict):
        return
    snapshot = revlist.get("snapshot", {})
    entries = snapshot.get("revocation_list", {}).get("entries", [])
    if any(e.get("jti") == claims.get("jti") for e in entries):
        raise AitpError("TCT_REVOKED", "TCT jti is on the issuer revocation snapshot")
