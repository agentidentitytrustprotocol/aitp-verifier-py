"""Grant-voucher verification (RFC-AITP-0005 §8).

A voucher is only ever verified by its own issuer, during delegation
verification — so the signature is checked against the ``iss`` key directly.
Voucher expiry surfaces as ``DELEGATION_EXPIRED`` (there is no voucher-specific
expiry code; PLACEHOLDERS.md / RFC-AITP-0006 §4 step 5).
"""

from __future__ import annotations

from typing import Any

from .errors import AitpError
from .jws import parse_compact, verify_jws
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_grant_voucher"]


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
    if claims.get("ver") != "aitp/0.2":
        raise AitpError("UNKNOWN_VERSION", f"unknown ver {claims.get('ver')!r}")
    if not claims.get("grants"):
        raise AitpError("DELEGATION_INVALID_VOUCHER", "voucher grants must be non-empty")
    if now >= int(claims["exp"]):
        raise AitpError("DELEGATION_EXPIRED", "voucher exp is in the past")
    return {"grants": claims["grants"]}
