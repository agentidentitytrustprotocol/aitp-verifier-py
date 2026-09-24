"""Trust Context Token verification (RFC-AITP-0005 §7.2 / §10).

``verify_tct`` runs the ordered checklist: strict compact-JWS parse → ``typ``
(``aitp-tct+jwt``) → claims (shape: ``check_tct_claims_shape``, run via
``verify_jws``'s ``after_typ_check`` hook so it lands between ``typ`` and
``alg``, per RFC-AITP-0005 §7.2 step 1's explicit sub-step order -- "this
step's segment-parsing, then step 2, then this step's claims-membership
clause, then steps 3-4") → AID-pinned ``alg`` → signature → claims (semantic:
``ver``, ``aud``, literal ``exp``, ``cnf.jkt`` binding) → the §10.4 conditional
issuer-Manifest expiry bound → revocation. Revocation runs strictly last so a
tampered token fails at the signature step and never reaches a (potentially
networked) deny list — the RFC-AITP-0008 §3.3 ordering rev-004 pins. The
issuer's revocation snapshot, once supplied, is itself fully verified
(structural + member-set + signature, via ``revocation.py``'s
``verify_snapshot_trust``) before its ``entries`` are consulted — not merely
consulted at face value.

``check_tct_claims_shape`` is exported so ``handshake.py`` and
``sessionbundle.py`` -- which each verify an *embedded* peer-issued TCT
inline, rather than calling ``verify_tct`` (they need the raw claims dict
afterward for their own checks, and each remaps a subset of TCT-level
failures to their own containing artifact's code) -- run the identical
claims-shape check, in the identical position, instead of each duplicating
(and risking drifting) their own copy.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .errors import AitpError
from .fields import check_types, reject_unknown_fields, require_members
from .jwk import thumbprint
from .jws import parse_compact, verify_jws
from .revocation import verify_snapshot_trust
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_tct", "TCT_CLAIM_FIELDS", "TCT_CNF_FIELDS", "check_tct_claims_shape"]

# aitp-tct.schema.json: additionalProperties: false. `ext` is the
# RFC-AITP-0012 §1.1 extensions slot on this claims object -- listing it here
# permits its presence without inspecting its contents (unknown keys inside
# `ext` MUST be ignored). No dedicated shape-rejection code exists in the
# registry for the TCT, so TCT_SIGNATURE_INVALID is reused, matching the
# `structural_code` convention jws.parse_compact already applies.
TCT_CLAIM_FIELDS = frozenset({"ver", "jti", "iss", "sub", "aud", "iat", "exp", "grants", "cnf", "ext"})
TCT_CNF_FIELDS = frozenset({"jkt"})
# aitp-tct.schema.json `required`. Every one of these is dereferenced
# unguarded downstream -- by this module's own verify_tct (`int(claims["exp"])`,
# `claims["sub"]`), by handshake.py's embedded-TCT check in _verify_commit
# (identical pattern, plus `set(claims["grants"])`), and by sessionbundle.py's
# pre-signature expiry-invariant peek -- so this is the one place all three
# close together instead of each guessing at its own copy.
_TCT_REQUIRED_CLAIMS = ("ver", "jti", "iss", "sub", "aud", "iat", "exp", "grants", "cnf")
_TCT_CLAIM_TYPES: dict[str, tuple[type, ...]] = {
    "ver": (str,), "jti": (str,), "iss": (str,), "sub": (str,), "aud": (str,),
    "iat": (int,), "exp": (int,), "grants": (list,), "cnf": (dict,),
}


def check_tct_claims_shape(claims: dict[str, Any], *, shape_code: str) -> None:
    """RFC-AITP-0005 §7.2 step 1's claims-membership check: the decoded TCT
    claims set MUST contain only the claims registered in §2 (``ext``'s
    contents excepted), every claim §2 requires MUST be present and of its
    declared JSON type, and ``cnf`` -- itself ``additionalProperties: false``
    -- MUST contain only ``jkt``.

    Factored out of ``verify_tct`` so ``handshake.py`` and ``sessionbundle.py``
    run the identical check via the same ``verify_jws(after_typ_check=...)``
    hook rather than each keeping their own copy. *shape_code* is the code
    each caller's own ``reject_unknown_fields`` non-dict-guard already used
    (``TCT_SIGNATURE_INVALID`` for ``tct.py``/``handshake.py``,
    ``BUNDLE_PARTICIPANT_TCT_INVALID`` for ``sessionbundle.py``) -- it is
    never used for the unknown-member case itself, which is always the core
    ``UNKNOWN_FIELD`` (``fields.py``); a caller that needs a different code
    for *that* case (``sessionbundle.py`` does) remaps it at its own call
    site, exactly as it already did before this was factored out.
    """
    require_members(claims, _TCT_REQUIRED_CLAIMS, shape_code=shape_code, what="TCT claims")
    check_types(claims, _TCT_CLAIM_TYPES, shape_code=shape_code, what="TCT claims")
    if not all(isinstance(g, str) for g in claims["grants"]):
        raise AitpError(shape_code, "TCT claims.grants must be an array of strings")
    reject_unknown_fields(claims, TCT_CLAIM_FIELDS, shape_code=shape_code, what="TCT claims")
    reject_unknown_fields(claims["cnf"], TCT_CNF_FIELDS, shape_code=shape_code, what="TCT claims.cnf")


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
        after_typ_check=lambda c: check_tct_claims_shape(c, shape_code="TCT_SIGNATURE_INVALID"),
    )

    if claims.get("ver") != "aitp/0.2":
        raise AitpError("UNKNOWN_VERSION", f"unknown ver {claims.get('ver')!r}")

    expected_aud = inp.get("expected_audience")
    if expected_aud is not None and claims.get("aud") != expected_aud:
        raise AitpError("AUDIENCE_MISMATCH", "TCT aud does not match verifier AID")

    if now >= int(claims["exp"]):
        raise AitpError("TCT_EXPIRED", "TCT exp is in the past")

    # cnf.jkt MUST equal the thumbprint of the key in the subject AID.
    try:
        sub_aid = parse_aid(str(claims["sub"]))
    except ValueError as exc:
        # `parse_aid` signals a malformed AID with a bare ValueError, which is
        # not an AitpError and escapes this module's caller. `sub` is a
        # claims-shape-typed string by now (`check_tct_claims_shape`), so this
        # is a grammar defect -> TCT_SIGNATURE_INVALID, matching the shape
        # code `check_tct_claims_shape` itself already uses for this claims
        # object.
        raise AitpError("TCT_SIGNATURE_INVALID", f"TCT claims.sub is not a valid AID: {exc}") from exc
    if claims.get("cnf", {}).get("jkt") != thumbprint(sub_aid):
        raise AitpError("TCT_CNF_MISMATCH", "cnf.jkt does not bind the subject key")

    # §10.4 conditional bound: only when the issuer Manifest is supplied.
    issuer_manifest = inp.get("issuer_manifest")
    if issuer_manifest is not None and int(claims["exp"]) > int(issuer_manifest["expires_at"]):
        raise AitpError("TCT_EXPIRES_AFTER_MANIFEST", "TCT outlives the issuer Manifest")

    _check_revocation(claims, inp)
    return {"grants": claims["grants"]}


def _check_revocation(claims: dict[str, Any], inp: dict[str, Any]) -> None:
    """RFC-AITP-0008 §3.3: the issuer's revocation snapshot, if supplied, MUST
    itself be trusted (structurally valid, correctly shaped, genuinely
    signed by its own claimed issuer) before its ``entries`` are consulted --
    `verify_snapshot_trust` (`revocation.py`) is what closed issue #24's gap,
    where a forged/unsigned snapshot was previously accepted at face value via
    a bare ``.get()`` chain. An absent or non-dict ``issuer_revocation_list``
    is a deliberately separate, still-open fail-open gap (see the follow-up
    issue linked in `plans/hardening-issues-23-27.md`'s Phase 8 section) --
    this function only hardens the snapshot *once its containing wrapper is
    present*, matching this phase's own documented scope.
    """
    revlist = inp.get("issuer_revocation_list")
    if not isinstance(revlist, dict):
        return
    body = verify_snapshot_trust(revlist.get("snapshot"))
    # A snapshot signed by someone other than this TCT's own issuer does not
    # speak for it -- not a rejection (the snapshot itself may be perfectly
    # valid, just for a different issuer), so the deny-list scan is simply
    # skipped rather than treated as a defect.
    if body["issuer"] != claims.get("iss"):
        return
    if any(e.get("jti") == claims.get("jti") for e in body["entries"]):
        raise AitpError("TCT_REVOKED", "TCT jti is on the issuer revocation snapshot")
