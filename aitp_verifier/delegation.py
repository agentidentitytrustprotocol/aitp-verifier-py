"""Single-hop delegation verification (RFC-AITP-0006 §4).

A delegation token carrying a ``chain`` claim is a multi-hop token; a core v0.2
verifier that has not opted into RFC-AITP-0011 rejects it with
``DELEGATION_MULTIHOP_NOT_SUPPORTED`` *before* any per-hop signature work — a
structural rejection on mere presence of ``chain`` (del-007). Otherwise the
§4 checklist runs: outer JWS (typ/alg/signature) → addressing/expiry → embedded
voucher (issued by, and signed under, the verifier's own key) → delegator held
the grant → expiry monotonicity → scope subset → no self-delegation.
"""

from __future__ import annotations

from typing import Any

from .errors import AitpError
from .jws import parse_compact, verify_jws
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_delegation_token"]


def verify_delegation_token(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    self_aid = inp["self_aid"]
    token = inp["delegation_token"]
    outer = parse_compact(token, structural_code="DELEGATION_INVALID_SIGNATURE").claims

    # Multi-hop guard — structural, before any signature work.
    if "chain" in outer:
        raise AitpError("DELEGATION_MULTIHOP_NOT_SUPPORTED", "chain claim requires RFC-AITP-0011 opt-in")

    claims = verify_jws(
        token,
        iss_aid=str(outer.get("iss")),
        expected_typ="aitp-delegation+jwt",
        typ_err="TOKEN_TYP_MISMATCH",
        alg_err="TOKEN_ALG_MISMATCH",
        sig_err="DELEGATION_INVALID_SIGNATURE",
    )

    if claims["iss"] == claims["sub"]:
        raise AitpError("DELEGATION_INVALID_SIGNATURE", "self-delegation")
    if claims.get("aud") != self_aid:
        raise AitpError("DELEGATION_AUDIENCE_MISMATCH", "delegation aud is not this verifier")
    if now >= int(claims["exp"]):
        raise AitpError("DELEGATION_EXPIRED", "delegation exp in the past")

    # Embedded voucher: issued by, and signed under, the verifier's own key.
    voucher = claims.get("voucher")
    if not isinstance(voucher, str):
        raise AitpError("DELEGATION_INVALID_VOUCHER", "single-hop delegation must carry a voucher")
    v_iss = parse_compact(voucher, structural_code="DELEGATION_INVALID_VOUCHER").claims.get("iss")
    if v_iss != self_aid:
        raise AitpError("DELEGATION_INVALID_VOUCHER", "voucher not issued by this verifier")
    vclaims = verify_jws(
        voucher,
        iss_aid=str(v_iss),
        expected_typ="aitp-grant+jwt",
        typ_err="TOKEN_TYP_MISMATCH",
        alg_err="TOKEN_ALG_MISMATCH",
        sig_err="DELEGATION_INVALID_VOUCHER",
    )

    if vclaims.get("sub") != claims["iss"]:
        raise AitpError("DELEGATION_INVALID_VOUCHER", "voucher.sub != delegator (delegator lacked the grant)")
    if now >= int(vclaims["exp"]) or int(claims["exp"]) > int(vclaims["exp"]):
        raise AitpError("DELEGATION_EXPIRED", "voucher expired or delegation outlives voucher")
    if not set(claims["scope"]).issubset(set(vclaims["grants"])):
        raise AitpError("DELEGATION_SCOPE_EXCEEDED", "scope exceeds the voucher grants")

    return {"grants": claims["scope"]}
