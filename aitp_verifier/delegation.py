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

from .b64 import b64url_encode
from .crypto import sha256
from .errors import AitpError
from .jcs import canonicalize
from .jws import parse_compact, verify_jws
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_delegation_token", "compute_chain_hash"]

MAX_DELEGATION_HOPS = 3
_MULTIHOP_FEATURE = "experimental-multihop-delegation"


def compute_chain_hash(chain: list[str]) -> str:
    """RFC-AITP-0011 §5 digest-array commitment over the chain JWS strings.

    ``chain_hash = base64url(sha256(JCS([base64url(sha256(ascii(chain[i]))) …])))``.
    """
    digests: list[Any] = [b64url_encode(sha256(entry.encode("ascii"))) for entry in chain]
    return b64url_encode(sha256(canonicalize(digests)))


def verify_delegation_token(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    self_aid = inp["self_aid"]
    token = inp["delegation_token"]
    outer = parse_compact(token, structural_code="DELEGATION_INVALID_SIGNATURE").claims

    # Multi-hop guard — structural, before any signature work. A verifier that
    # has not opted into RFC-AITP-0011 rejects on the mere presence of `chain`.
    if "chain" in outer:
        if inp.get("_feature") != _MULTIHOP_FEATURE:
            raise AitpError("DELEGATION_MULTIHOP_NOT_SUPPORTED", "chain claim requires RFC-AITP-0011 opt-in")
        return {"grants": _verify_multihop(inp, token, outer, self_aid, now)}

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


def _revocation_index(inp: dict[str, Any]) -> dict[str, set[str]]:
    """Map issuer AID -> set of revoked jti, from the fixture's per-hop snapshots."""
    index: dict[str, set[str]] = {}
    for record in inp.get("revocation_snapshots", []) or []:
        issuer = record.get("issuer_aid")
        entries = record.get("snapshot", {}).get("revocation_list", {}).get("entries", [])
        index.setdefault(issuer, set()).update(e.get("jti") for e in entries)
    return index


def _verify_multihop(
    inp: dict[str, Any], token: str, outer: dict[str, Any], self_aid: str, now: int
) -> list[str]:
    from .aid import parse_aid
    from .jwk import thumbprint

    chain: list[str] = outer["chain"]

    # Hop limit (§2), before any signature work.
    if len(chain) + 2 > MAX_DELEGATION_HOPS + 1:
        raise AitpError("DELEGATION_HOP_LIMIT_EXCEEDED", "delegation chain too long")

    # Chain-hash commitment (§5) — recompute from the carried chain strings.
    if compute_chain_hash(chain) != outer.get("chain_hash"):
        raise AitpError("DELEGATION_CHAIN_HASH_MISMATCH", "chain_hash != recomputed digest-array commitment")

    hops = chain + [token]  # oldest-first; the outer token is the final hop
    seen_jti: set[str] = set()
    prev: dict[str, Any] | None = None
    prev_scope: set[str] | None = None
    root_voucher: dict[str, Any] = {}

    for i, hop in enumerate(hops):
        hc = verify_jws(
            hop, iss_aid=str(parse_compact(hop, structural_code="DELEGATION_INVALID_SIGNATURE").claims.get("iss")),
            expected_typ="aitp-delegation+jwt", typ_err="TOKEN_TYP_MISMATCH",
            alg_err="TOKEN_ALG_MISMATCH", sig_err="DELEGATION_INVALID_SIGNATURE",
        )
        if hc.get("ver") != "aitp/0.2":
            raise AitpError("UNKNOWN_VERSION", "unknown ver")
        if hc["iss"] == hc["sub"]:
            raise AitpError("DELEGATION_INVALID_SIGNATURE", "self-delegation")
        if hc.get("aud") != self_aid:
            raise AitpError("DELEGATION_AUDIENCE_MISMATCH", "hop aud is not this verifier")
        if hc.get("cnf", {}).get("jkt") != thumbprint(parse_aid(str(hc["sub"]))):
            raise AitpError("DELEGATION_INVALID_VOUCHER", "hop cnf.jkt does not bind sub key")
        jti = hc.get("jti")
        if not jti or jti in seen_jti:
            raise AitpError("DELEGATION_INVALID_VOUCHER", "hop jti missing or not unique")
        seen_jti.add(jti)
        if now >= int(hc["exp"]):
            raise AitpError("DELEGATION_EXPIRED", "hop expired")

        scope = set(hc["scope"])
        if i == 0:
            # Root authority: the embedded voucher (issued + signed by A/self).
            voucher = hc.get("voucher")
            if not isinstance(voucher, str):
                raise AitpError("DELEGATION_INVALID_VOUCHER", "root hop must carry a voucher")
            v_iss = parse_compact(voucher, structural_code="DELEGATION_INVALID_VOUCHER").claims.get("iss")
            if v_iss != self_aid:
                raise AitpError("DELEGATION_INVALID_VOUCHER", "voucher not issued by this verifier")
            root_voucher = verify_jws(
                voucher, iss_aid=str(v_iss), expected_typ="aitp-grant+jwt", typ_err="TOKEN_TYP_MISMATCH",
                alg_err="TOKEN_ALG_MISMATCH", sig_err="DELEGATION_INVALID_VOUCHER",
            )
            if root_voucher.get("sub") != hc["iss"]:
                raise AitpError("DELEGATION_INVALID_VOUCHER", "voucher.sub != root delegator")
            if now >= int(root_voucher["exp"]) or int(hc["exp"]) > int(root_voucher["exp"]):
                raise AitpError("DELEGATION_EXPIRED", "voucher expired or hop outlives voucher")
            if not scope.issubset(set(root_voucher["grants"])):
                raise AitpError("DELEGATION_SCOPE_EXCEEDED", "root scope exceeds voucher grants")
        else:
            if "voucher" in hc:
                raise AitpError("DELEGATION_INVALID_VOUCHER", "only the root hop may carry a voucher")
            assert prev is not None and prev_scope is not None
            if hc["iss"] != prev["sub"]:
                raise AitpError("DELEGATION_INVALID_VOUCHER", "hop iss != previous hop sub (broken continuity)")
            if int(hc["exp"]) > int(prev["exp"]):
                raise AitpError("DELEGATION_EXPIRED", "hop outlives its predecessor")
            if not scope.issubset(prev_scope):
                raise AitpError("DELEGATION_SCOPE_EXCEEDED", "hop scope exceeds its predecessor")
        prev, prev_scope = hc, scope

    # Per-hop revocation (§6) — only after every signature check.
    revoked = _revocation_index(inp)
    if root_voucher.get("src_jti") in revoked.get(self_aid, set()):
        raise AitpError("DELEGATION_SOURCE_TCT_REVOKED", "source TCT revoked")
    for hop in hops:
        hc = parse_compact(hop, structural_code="DELEGATION_INVALID_SIGNATURE").claims
        if hc.get("jti") in revoked.get(str(hc.get("iss")), set()):
            raise AitpError("DELEGATION_SOURCE_TCT_REVOKED", "a hop jti is revoked")

    assert prev is not None
    return list(prev["scope"])
