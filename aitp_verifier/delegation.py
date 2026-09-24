"""Single-hop delegation verification (RFC-AITP-0006 §4).

A delegation token carrying a ``chain`` claim is a multi-hop token; a core v0.2
verifier that has not opted into RFC-AITP-0011 rejects it with
``DELEGATION_MULTIHOP_NOT_SUPPORTED`` *before* any per-hop signature work — a
structural rejection on mere presence of ``chain`` (del-007). Otherwise the
§4 checklist runs: outer JWS (typ/alg/signature) → addressing/expiry → embedded
voucher (issued by, and signed under, the verifier's own key) → delegator held
the grant → expiry monotonicity → scope subset → no self-delegation.

Multi-hop's per-hop revocation snapshots (RFC-AITP-0011 §6) are each fully
verified (structural + member-set + signature, via
``revocation.py::verify_snapshot_trust``) before their ``entries`` are
consulted — not merely consulted at face value — and the deny-list index is
keyed on each snapshot's own *verified* issuer, not a caller-supplied label.
"""

from __future__ import annotations

from typing import Any

from .b64 import b64url_encode
from .crypto import sha256
from .errors import AitpError
from .fields import check_types, reject_unknown_fields, require_members
from .jcs import canonicalize
from .jws import parse_compact, verify_jws
from .revocation import verify_snapshot_trust
from .timeutil import REFERENCE_CLOCK
from .voucher import check_voucher_claims_shape

__all__ = ["verify_delegation_token", "compute_chain_hash"]

MAX_DELEGATION_HOPS = 3
_MULTIHOP_FEATURE = "experimental-multihop-delegation"

# aitp-delegation.schema.json: additionalProperties: false. One property set
# covers both the single-hop token (RFC-AITP-0006) and the multi-hop hop
# shape (RFC-AITP-0011, draft) -- `chain`/`chain_hash` are schema-legal on
# every hop, not just the outer token. `ext` is the RFC-AITP-0012 §1.1
# extensions slot. No dedicated shape code exists; DELEGATION_INVALID_SIGNATURE
# is already this module's `structural_code` for every other malformed-token
# case (see jws.parse_compact call sites below).
_DELEGATION_CLAIM_FIELDS = frozenset({
    "ver", "iss", "sub", "aud", "scope", "exp", "cnf", "voucher", "jti", "chain", "chain_hash", "ext",
})
_DELEGATION_CNF_FIELDS = frozenset({"jkt"})
# aitp-delegation.schema.json `required`. Every one of these is dereferenced
# unguarded downstream in both the single-hop path (`claims["iss"]`,
# `int(claims["exp"])`, `set(claims["scope"])`) and the multi-hop per-hop
# loop (the identical pattern on `hc`) -- `_check_delegation_claims_shape`
# below is what closes both at once instead of each guessing at its own copy.
# `voucher`/`jti`/`chain`/`chain_hash` are schema-optional (checked
# contextually in code, not required here).
_DELEGATION_REQUIRED_CLAIMS = ("ver", "iss", "sub", "aud", "scope", "exp", "cnf")
_DELEGATION_CLAIM_TYPES: dict[str, tuple[type, ...]] = {
    "ver": (str,), "iss": (str,), "sub": (str,), "aud": (str,), "scope": (list,),
    "exp": (int,), "cnf": (dict,), "voucher": (str,), "jti": (str,), "chain": (list,), "chain_hash": (str,),
}


def _check_delegation_claims_shape(claims: dict[str, Any], *, shape_code: str) -> None:
    """RFC-AITP-0006 §4's delegation claims-membership + required-member/type
    check. One property set covers both the single-hop token and each
    multi-hop hop (see the module docstring), so this runs identically for
    both -- ``claims`` (single-hop) and each ``hc`` (multi-hop) below.
    """
    require_members(claims, _DELEGATION_REQUIRED_CLAIMS, shape_code=shape_code, what="delegation claims")
    check_types(claims, _DELEGATION_CLAIM_TYPES, shape_code=shape_code, what="delegation claims")
    if not all(isinstance(s, str) for s in claims["scope"]):
        raise AitpError(shape_code, "delegation claims.scope must be an array of strings")
    reject_unknown_fields(claims, _DELEGATION_CLAIM_FIELDS, shape_code=shape_code, what="delegation claims")
    reject_unknown_fields(claims["cnf"], _DELEGATION_CNF_FIELDS, shape_code=shape_code, what="delegation claims.cnf")


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
    _check_delegation_claims_shape(claims, shape_code="DELEGATION_INVALID_SIGNATURE")

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
    check_voucher_claims_shape(vclaims, shape_code="DELEGATION_INVALID_VOUCHER")

    if vclaims.get("sub") != claims["iss"]:
        raise AitpError("DELEGATION_INVALID_VOUCHER", "voucher.sub != delegator (delegator lacked the grant)")
    if now >= int(vclaims["exp"]) or int(claims["exp"]) > int(vclaims["exp"]):
        raise AitpError("DELEGATION_EXPIRED", "voucher expired or delegation outlives voucher")
    if not set(claims["scope"]).issubset(set(vclaims["grants"])):
        raise AitpError("DELEGATION_SCOPE_EXCEEDED", "scope exceeds the voucher grants")

    return {"grants": claims["scope"]}


def _revocation_index(inp: dict[str, Any]) -> dict[str, set[str]]:
    """Map issuer AID -> set of revoked jti, from the caller's per-hop
    snapshots (RFC-AITP-0011 §6).

    Each snapshot is fully verified (structural + member-set + signature, via
    `revocation.py::verify_snapshot_trust`) before its ``entries`` are
    consulted -- closing issue #24's gap, where a forged/unsigned snapshot
    was previously accepted at face value via a bare ``.get()`` chain.
    Indexes on the *verified* ``body["issuer"]``, not the caller-supplied
    ``record.get("issuer_aid")`` label: the signed value wins, so a
    correctly-signed snapshot can never be filed under an issuer the caller's
    own wrapper merely claims for it.

    ``revocation_snapshots`` itself is untrusted remote input, same as every
    record inside it -- a scalar there (e.g. an int/bool/float) is truthy and
    would otherwise survive `or []` and reach the ``for`` loop as a bare
    ``TypeError: '...' object is not iterable``, escaping this module's own
    ``AitpError``-or-verdict contract.
    """
    snaps = inp.get("revocation_snapshots") or []
    if not isinstance(snaps, list):
        raise AitpError(
            "REVOCATION_SNAPSHOT_INVALID",
            f"revocation_snapshots must be an array, got {type(snaps).__name__}",
        )
    index: dict[str, set[str]] = {}
    for record in snaps:
        body = verify_snapshot_trust(record.get("snapshot") if isinstance(record, dict) else None)
        index.setdefault(body["issuer"], set()).update(e.get("jti") for e in body["entries"])
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
        _check_delegation_claims_shape(hc, shape_code="DELEGATION_INVALID_SIGNATURE")
        if hc.get("ver") != "aitp/0.2":
            raise AitpError("UNKNOWN_VERSION", "unknown ver")
        if hc["iss"] == hc["sub"]:
            raise AitpError("DELEGATION_INVALID_SIGNATURE", "self-delegation")
        if hc.get("aud") != self_aid:
            raise AitpError("DELEGATION_AUDIENCE_MISMATCH", "hop aud is not this verifier")
        try:
            sub_aid = parse_aid(str(hc["sub"]))
        except ValueError as exc:
            # `parse_aid` signals a malformed AID with a bare ValueError,
            # which is not an AitpError and escapes this module's caller.
            # `sub` is a claims-shape-typed string by now, so this is a
            # grammar defect -> DELEGATION_INVALID_VOUCHER, matching the
            # code this same cnf.jkt-binding check already uses on the line
            # below for every other "hop is malformed" defect.
            raise AitpError("DELEGATION_INVALID_VOUCHER", f"hop claims.sub is not a valid AID: {exc}") from exc
        if hc.get("cnf", {}).get("jkt") != thumbprint(sub_aid):
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
            check_voucher_claims_shape(root_voucher, shape_code="DELEGATION_INVALID_VOUCHER")
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
