"""Grant-voucher verification (RFC-AITP-0005 §8).

A voucher is only ever verified by its own issuer, during delegation
verification — so the signature is checked against the ``iss`` key directly.
Voucher expiry surfaces as ``DELEGATION_EXPIRED`` (there is no voucher-specific
expiry code; PLACEHOLDERS.md / RFC-AITP-0006 §4 step 5).
"""

from __future__ import annotations

from typing import Any

from .errors import AitpError
from .fields import check_types, reject_unknown_fields, require_members
from .jws import parse_compact, verify_jws
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_grant_voucher", "VOUCHER_CLAIM_FIELDS", "check_voucher_claims_shape"]

# aitp-grant-voucher.schema.json: additionalProperties: false. `ext` is the
# RFC-AITP-0012 §1.1 extensions slot (also reserved as the future
# `ext.sd_grant` selective-disclosure hook, §4). No dedicated voucher-shape
# code exists in the registry; DELEGATION_INVALID_VOUCHER is already this
# module's structural code for every other malformed-voucher case.
VOUCHER_CLAIM_FIELDS = frozenset({"ver", "iss", "sub", "grants", "iat", "exp", "src_jti", "ext"})
# aitp-grant-voucher.schema.json `required`. Every one of these is
# dereferenced unguarded downstream -- by this module's own `int(claims["exp"])`,
# and by delegation.py's embedded-voucher checks (`int(vclaims["exp"])`,
# `set(vclaims["grants"])`, both single- and multi-hop) -- so this is the one
# place all three close together instead of each guessing at its own copy.
_VOUCHER_REQUIRED_CLAIMS = ("ver", "iss", "sub", "grants", "iat", "exp", "src_jti")
_VOUCHER_CLAIM_TYPES: dict[str, tuple[type, ...]] = {
    "ver": (str,), "iss": (str,), "sub": (str,), "grants": (list,),
    "iat": (int,), "exp": (int,), "src_jti": (str,),
}


def check_voucher_claims_shape(claims: dict[str, Any], *, shape_code: str) -> None:
    """RFC-AITP-0005 §8's grant-voucher claims-membership + required-member/
    type check, shared by this module's own ``verify_grant_voucher`` and by
    ``delegation.py``'s embedded-voucher verification (both single-hop and
    multi-hop), so all three call sites enforce the identical shape instead
    of each keeping (or risking drifting from) its own partial copy.
    """
    require_members(claims, _VOUCHER_REQUIRED_CLAIMS, shape_code=shape_code, what="grant voucher claims")
    check_types(claims, _VOUCHER_CLAIM_TYPES, shape_code=shape_code, what="grant voucher claims")
    if not all(isinstance(g, str) for g in claims["grants"]):
        raise AitpError(shape_code, "grant voucher claims.grants must be an array of strings")
    reject_unknown_fields(claims, VOUCHER_CLAIM_FIELDS, shape_code=shape_code, what="grant voucher claims")


def verify_grant_voucher(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    token = inp["voucher_token"]
    iss = parse_compact(token, structural_code="DELEGATION_INVALID_VOUCHER").claims.get("iss")
    claims = verify_jws(
        token,
        iss_aid=str(iss),
        expected_typ="aitp-grant+jwt",
        typ_err="TOKEN_TYP_MISMATCH",
        alg_err="TOKEN_ALG_MISMATCH",
        sig_err="DELEGATION_INVALID_VOUCHER",
    )
    check_voucher_claims_shape(claims, shape_code="DELEGATION_INVALID_VOUCHER")
    if claims.get("ver") != "aitp/0.2":
        raise AitpError("UNKNOWN_VERSION", f"unknown ver {claims.get('ver')!r}")
    if not claims.get("grants"):
        raise AitpError("DELEGATION_INVALID_VOUCHER", "voucher grants must be non-empty")
    if now >= int(claims["exp"]):
        raise AitpError("DELEGATION_EXPIRED", "voucher exp is in the past")
    return {"grants": claims["grants"]}
