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

``verify_tct``'s input carries one **optional** top-level ``policy`` key,
spelled exactly as ``verify_revocation_snapshot``'s own required one
(``{"fail_mode": ..., "max_staleness_secs": ...}``). It answers the single
question RFC-AITP-0008 §3.1 reserves for ``fail_mode``: what to do when **no
trusted, applicable revocation snapshot was supplied at all** — "unknown is
treated as revoked" under ``fail_closed``, proceed under
``soft_fail``/``fail_open``. It never answers what to do about a snapshot that
*was* obtained and cannot be trusted; §1.5 decides that first, and
``verify_snapshot_trust`` still reports that snapshot's own defect under every
mode. With no ``policy`` supplied and no wrapper-level ``fail_mode``, this
module behaves exactly as it did before the key existed (fail-open on
absence) — see ``_check_revocation`` for the full precedence and
``ASSUMPTIONS.md`` for why that default, rather than §3.1's configured-policy
default of ``fail_closed``, governs the no-policy case.

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

    _check_revocation(claims, inp, now)
    return {"grants": claims["grants"]}


# RFC-AITP-0008 §3.1's three revocation-policy modes. Anything else -- a
# misspelling, a value of the wrong JSON type, a mode minted by some future
# revision -- resolves to `fail_closed` (`_resolve_fail_mode`): unrecognized
# configuration is never silently permissive.
_FAIL_MODES = frozenset({"fail_closed", "fail_open", "soft_fail"})


def _resolve_fail_mode(value: Any) -> str:
    """Normalize one declared ``fail_mode`` value to a §3.1 mode.

    A present-but-non-``str`` value (``5``, ``None``, ``[]``) lands on
    ``fail_closed`` for the same reason a misspelled one does. The obvious
    alternative spelling -- an ``isinstance(..., str)`` guard that *falls
    through* to the caller's default -- would send a **wrong-typed**
    ``fail_mode`` to the permissive default while a merely **misspelled** one
    (``"fail_klosed"``) failed closed: the more broken input treated more
    leniently, which is backwards.
    """
    return value if isinstance(value, str) and value in _FAIL_MODES else "fail_closed"


def _effective_fail_mode(inp: dict[str, Any], revlist: Any) -> str:
    """Resolve the ``fail_mode`` that governs *absence*, in strict precedence.

    1. A top-level ``policy`` key, when supplied, is **authoritative** and
       cannot be overridden by anything in the input artifact. A ``policy``
       dict without ``fail_mode`` resolves to ``fail_closed``, matching
       ``revocation.py``'s own ``policy.get("fail_mode", "fail_closed")`` --
       so ``policy: {}`` is enough to opt into fail-closed. A non-dict
       ``policy`` resolves to ``fail_closed`` too, never to a raw
       ``AttributeError``.
    2. Else ``issuer_revocation_list["fail_mode"]``, the member the spec's own
       ``tct-004-revoked`` fixture already carries and this module read
       nowhere before (issue #30's "the wrapper's declared members are never
       read at all").
    3. Else -- no ``policy`` key and no wrapper ``fail_mode`` -- ``fail_open``,
       preserving this module's pre-``policy`` behavior byte for byte. See
       ``ASSUMPTIONS.md``: an unconditional fail-closed default would turn the
       spec's own ``tct-012`` (``required_for_v0_2``) success fixture red,
       since it supplies no revocation data at all.

    **Why 1 outranks 2, and why that ordering is security-relevant.**
    ``issuer_revocation_list.fail_mode`` is an *unsigned* member of the
    caller-supplied wrapper -- the snapshot signature covers only the inner
    ``revocation_list`` body -- and for a real integrator that wrapper is a
    remote ``ListRevoked`` response with a locally-added envelope. Were it to
    outrank the top-level ``policy``, a deployment that had explicitly
    configured ``fail_closed`` could be silently downgraded to
    ``soft_fail``/``fail_open`` by whatever assembled the wrapper. It is the
    same reason the sibling member ``issuer_revocation_list["issuer"]`` is
    ignored for every trust decision below: neither unsigned label may ever
    override something the deployment or the signature has already said. In
    the one position it does hold -- the deployment said nothing -- the
    wrapper's ``fail_mode`` is monotone-safe: rule 3's default is
    ``fail_open``, the most permissive mode, so the wrapper can only tighten.
    """
    if "policy" in inp:
        policy = inp["policy"]
        if not isinstance(policy, dict):
            return "fail_closed"
        return _resolve_fail_mode(policy.get("fail_mode", "fail_closed"))
    if isinstance(revlist, dict) and "fail_mode" in revlist:
        return _resolve_fail_mode(revlist["fail_mode"])
    return "fail_open"


def _apply_absence(fail_mode: str, detail: str) -> None:
    """RFC-AITP-0008 §3.1 applied to the *absent* case only: under
    ``fail_closed`` an absent snapshot means revocation status is unknown, and
    unknown is treated as revoked; under ``soft_fail``/``fail_open`` the TCT
    verifies on degraded revocation data.

    ``verify_tct``'s verdict stays exactly ``{"grants": [...]}`` in the
    permissive modes -- no ``stale`` member is added, deliberately: this entry
    point returns no grant-restriction surface for a caller to act on, and the
    §3.1 distinction between ``soft_fail`` ("allow with restricted grants") and
    ``fail_open`` ("allow, log a warning") has no representation here.
    """
    if fail_mode == "fail_closed":
        raise AitpError(
            "TCT_REVOKED",
            f"no trusted, applicable revocation snapshot for this TCT ({detail}); "
            "fail_closed treats unknown revocation status as revoked",
        )


def _snapshot_is_stale(body: dict[str, Any], policy: dict[str, Any], now: int) -> bool:
    """RFC-AITP-0008 §3.2's freshness rule, the same formula
    ``revocation.py``'s stage 4 applies: a snapshot past its own
    ``expires_at``, or published longer than ``max_staleness_secs`` ago, gives
    this verifier no usable revocation data.

    Every *policy* member is read with ``.get()``, never a bracket: a policy is
    untrusted caller configuration, and this module's boundary contract is
    "raise ``AitpError`` or return a verdict", never a raw ``KeyError``. A
    ``max_staleness_secs`` that is present but not an integer is treated as
    stale rather than ignored -- unusable configuration resolves toward
    "status unknown", which the effective ``fail_mode`` then answers, instead
    of quietly skipping the check. *body* is already type-validated by
    ``verify_snapshot_trust``, so its two timestamps are ``int`` by here.

    ``OverflowError`` sits in that except tuple beside ``TypeError`` and
    ``ValueError`` for the same boundary-contract reason, and it is genuinely
    reachable: ``json.loads`` parses a bare ``Infinity``/``-Infinity`` by
    default, so a JSON-sourced ``policy`` can hand this function a
    ``max_staleness_secs`` of ``float("inf")``, on which ``int()`` raises
    ``OverflowError`` rather than ``ValueError``. Left uncaught it escaped
    ``verify_tct`` raw -- the exact bug class issue #31 targets.
    """
    if now >= int(body["expires_at"]):
        return True
    max_staleness = policy.get("max_staleness_secs")
    if max_staleness is None:
        return False
    try:
        bound = int(max_staleness)
    except (TypeError, ValueError, OverflowError):
        return True
    return (now - int(body["published_at"])) > bound


def _check_revocation(claims: dict[str, Any], inp: dict[str, Any], now: int) -> None:
    """RFC-AITP-0008 §3.3 + §3.1, in that order.

    **Obtained but untrustworthy comes first and is never answered by
    ``fail_mode``.** A supplied snapshot MUST itself be trusted (structurally
    valid, correctly shaped, genuinely signed by its own claimed issuer)
    before its ``entries`` are consulted -- ``verify_snapshot_trust``
    (``revocation.py``) is what closed issue #24's gap, where a forged/unsigned
    snapshot was accepted at face value via a bare ``.get()`` chain. It still
    raises ``REVOCATION_SNAPSHOT_INVALID``/``UNKNOWN_FIELD``/
    ``REVOCATION_SNAPSHOT_SIGNATURE_INVALID`` under **every** ``fail_mode``,
    including the permissive ones: collapsing "malformed" into "absent" is
    precisely the bug ``revocation.py``'s module docstring records as having
    shipped once already.

    **Absence** -- the one case ``fail_mode`` answers (issue #30) -- is
    exactly three things:

    * (a) ``issuer_revocation_list`` missing or not a dict: nothing was
      obtained;
    * (b) the trusted snapshot's **signed** ``issuer`` is not this TCT's
      ``iss``: a perfectly valid snapshot that does not speak for this
      issuer leaves this TCT's status unknown (the wrapper's own unsigned
      ``issuer`` label is deliberately never consulted -- the signed value
      wins, as ``delegation.py::_revocation_index`` already establishes);
    * (c) **only when a top-level ``policy`` is supplied**: the snapshot is
      expired or staler than ``max_staleness_secs``. Gating (c) on ``policy``
      is what keeps this diff auditable -- with no ``policy`` key, freshness
      and expiry are never evaluated at all, so on *that* dimension
      ``verify_tct`` behaves exactly as it did before this key existed. (Only
      that dimension: a wrapper carrying ``fail_mode`` with no top-level
      ``policy`` does change the outcome on absence, via rule 2 of
      ``_effective_fail_mode`` -- it is "no ``policy`` **and** no
      wrapper-level ``fail_mode``" that is byte-for-byte the old behavior,
      as this module's own docstring states.) The wrapper's ``fail_mode``
      selects what happens *on* absence; it does not switch on freshness
      evaluation, because ``max_staleness_secs`` is a deployment value with no
      per-wrapper spelling in the fixture shape.

    Present, trusted and applicable ⇒ the deny-list scan, unchanged.
    """
    revlist = inp.get("issuer_revocation_list")
    fail_mode = _effective_fail_mode(inp, revlist)

    # (a) Nothing was obtained at all.
    if not isinstance(revlist, dict):
        _apply_absence(fail_mode, "no issuer_revocation_list was supplied")
        return

    # Trust before policy, always -- an untrustworthy snapshot reports its own
    # defect here rather than being silently downgraded to "absent".
    body = verify_snapshot_trust(revlist.get("snapshot"))

    # (b) A snapshot signed by someone other than this TCT's own issuer does
    # not speak for it. The snapshot itself may be perfectly valid, so this is
    # not a defect in it -- it just leaves this TCT's revocation status
    # unknown, which is what `fail_mode` is for.
    if body["issuer"] != claims.get("iss"):
        _apply_absence(fail_mode, "the supplied snapshot is signed by a different issuer")
        return

    # (c) Freshness, evaluated only under an explicitly supplied policy. A
    # non-dict `policy` has already resolved `fail_mode` to `fail_closed`
    # above; it carries no readable `max_staleness_secs`, so only the
    # snapshot's own `expires_at` bound applies to it.
    if "policy" in inp:
        policy = inp["policy"]
        if _snapshot_is_stale(body, policy if isinstance(policy, dict) else {}, now):
            _apply_absence(fail_mode, "the supplied snapshot is expired or stale")
            return

    if any(e.get("jti") == claims.get("jti") for e in body["entries"]):
        raise AitpError("TCT_REVOKED", "TCT jti is on the issuer revocation snapshot")
