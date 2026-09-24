"""Single-hop delegation verification (RFC-AITP-0006 §4).

A delegation token carrying a ``chain`` claim is a multi-hop token; a core v0.2
verifier that has not opted into RFC-AITP-0011 rejects it with
``DELEGATION_MULTIHOP_NOT_SUPPORTED`` *before* any per-hop signature work — a
structural rejection on mere presence of ``chain`` (del-007). Otherwise the
§4 checklist runs: outer JWS (typ/alg/signature) → addressing/expiry → embedded
voucher (issued by, and signed under, the verifier's own key) → delegator held
the grant → expiry monotonicity → scope subset → no self-delegation → source-TCT
revocation. That last step is §4 step 7: ``voucher.src_jti`` is looked up in the
verifier's *own* deny list (``DELEGATION_SOURCE_TCT_REVOKED``), strictly after
every signature and claims check, per RFC-AITP-0008 §3.3 — one deny-list entry
on the source TCT invalidates the voucher and every delegation built on it
(RFC-AITP-0008 §1.1/§2). Both paths — single-hop and multi-hop — read that deny
list from ``revocation_snapshots``; no other carrier is accepted on either.

Every revocation snapshot, single-hop step 7 and multi-hop's per-hop snapshots
(RFC-AITP-0011 §6) alike, is fully verified (structural + member-set +
signature, via ``revocation.py::verify_snapshot_trust``) before its ``entries``
are consulted — not merely consulted at face value — and the deny-list index is
keyed on each snapshot's own *verified* issuer, not a caller-supplied label.

``verify_delegation_token``'s input carries a top-level ``policy`` key,
spelled exactly as ``verify_tct``'s and ``verify_revocation_snapshot``'s own
(``{"fail_mode": ..., "max_staleness_secs": ...}``) — one shape, not a third
spelling. It answers the single question RFC-AITP-0008 §3.1 reserves for
``fail_mode``: what to do when **no trusted, applicable revocation snapshot
for ``self_aid`` was supplied at all** — "unknown is treated as revoked"
(``DELEGATION_SOURCE_TCT_REVOKED``) under ``fail_closed``, proceed under
``soft_fail``/``fail_open``. It never answers what to do about a snapshot
that *was* supplied and cannot be trusted: §1.5 decides that first, and
``verify_snapshot_trust`` still reports that snapshot's own defect under
every mode. **A revocation decision is mandatory, not optional**: unlike
``tct.py``, this entry point has no per-wrapper fallback, so a caller
supplying no ``policy`` at all gets a raw ``KeyError("policy")``, the same
failure mode this function already gives a caller who omits any of its other
required top-level arguments — never a silent ``fail_open``. A caller with
no revocation infrastructure must say so explicitly:
``policy={"fail_mode": "fail_open"}``. See ``_effective_fail_mode`` for the
precedence and ``ASSUMPTIONS.md``/``DECISIONS.md`` for why a mandatory
decision, not a configured default, governs the no-policy case — reversed
from this module's own initial design via `/reconcile` before any real
caller could depend on the permissive default.

That policy governs **A's own deny list and nothing else** — the §4 step 7 /
RFC-AITP-0011 §6 source-TCT lookup, which both the single-hop and the multi-hop
path run through the one ``_check_source_tct_revocation`` below rather than
each answering separately. It is deliberately **not** extended to the multi-hop
per-hop issuer sweep: an absent snapshot for an intermediate hop issuer
proceeds under every ``fail_mode``, exactly as it did before this key existed.
RFC-AITP-0011 is Draft, its §6 per-hop lookup says nothing about absence, and
requiring N trusted snapshots under fail-closed would be a materially wider
policy with no RFC-stated default; ``ASSUMPTIONS.md`` records that boundary as
a decision rather than an omission.
"""

from __future__ import annotations

from typing import Any

from .b64 import b64url_encode
from .crypto import sha256
from .errors import AitpError
from .fields import check_types, reject_unknown_fields, require_members
from .jcs import canonicalize
from .jws import parse_compact, verify_jws
from .revocation import resolve_fail_mode, snapshot_is_stale, verify_snapshot_trust
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

    # Source TCT revocation (RFC-AITP-0006 §4 step 7) — strictly after every
    # signature and claims check above, per RFC-AITP-0008 §3.3. `src_jti` is a
    # shape-guaranteed `str` by here (`check_voucher_claims_shape` above).
    # This is the *same* `_check_source_tct_revocation` the multi-hop path
    # calls, not a second spelling of it: one implementation is what keeps the
    # two paths from drifting apart again (the single-hop path silently
    # skipping this step is exactly how they last diverged).
    _check_source_tct_revocation(inp, _verified_snapshot_bodies(inp), self_aid, vclaims["src_jti"], now)

    return {"grants": claims["scope"]}


def _verified_snapshot_bodies(inp: dict[str, Any]) -> list[dict[str, Any]]:
    """Every supplied revocation snapshot, fully verified, in input order.

    Each snapshot is fully verified (structural + member-set + signature, via
    `revocation.py::verify_snapshot_trust`) before its ``entries`` are
    consulted -- closing issue #24's gap, where a forged/unsigned snapshot
    was previously accepted at face value via a bare ``.get()`` chain.
    Returns the verified ``revocation_list`` bodies because that is what both
    consumers need: ``_revocation_index`` keys them by issuer for the per-hop
    sweep, and ``_check_source_tct_revocation`` additionally reads their
    ``published_at``/``expires_at`` for the §3.2 freshness bound. Scanning once
    and sharing the result is also what keeps each snapshot's signature
    verified exactly once per call.

    ``revocation_snapshots`` itself is untrusted remote input, same as every
    record inside it. Absent (``None``) is the one legitimate "no snapshots"
    case and defaults to ``[]``; anything else that isn't a list -- truthy
    (an int/bool/float, which would otherwise reach the ``for`` loop as a
    bare ``TypeError: '...' object is not iterable``) or falsy (``""``,
    ``0``, ``False``, ``{}``, ``0.0``, which would otherwise be silently
    folded into "no snapshots" by a naive ``or []`` and never reach the type
    check at all) -- is a malformed field, not an absent one, and must be
    rejected the same way. Checking ``is None`` explicitly, rather than
    truthiness, is what keeps the two cases apart.

    That whole discipline sits deliberately *upstream* of every ``fail_mode``:
    a malformed ``revocation_snapshots``, or a record whose snapshot is
    unsigned/forged/misshapen, is RFC-AITP-0008 §1.5's
    obtained-but-untrustworthy case, not its absent one, so it raises its own
    code under every mode and is never routed through the absence policy
    below. Collapsing "malformed" into "absent" is precisely the bug
    ``revocation.py``'s module docstring records as having shipped once
    already.
    """
    snaps = inp.get("revocation_snapshots")
    if snaps is None:
        snaps = []
    elif not isinstance(snaps, list):
        raise AitpError(
            "REVOCATION_SNAPSHOT_INVALID",
            f"revocation_snapshots must be an array, got {type(snaps).__name__}",
        )
    return [
        verify_snapshot_trust(record.get("snapshot") if isinstance(record, dict) else None)
        for record in snaps
    ]


def _revocation_index(bodies: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Map issuer AID -> set of revoked jti, over already-verified snapshot
    bodies (`_verified_snapshot_bodies`). RFC-AITP-0011 §6's per-hop sweep is
    this map's one consumer.

    Indexes on the *verified* ``body["issuer"]``, not the caller-supplied
    ``record.get("issuer_aid")`` label: the signed value wins, so a
    correctly-signed snapshot can never be filed under an issuer the caller's
    own wrapper merely claims for it.

    Deliberately policy-free and ``now``-free -- a pure index. The per-hop
    sweep that consumes it is RFC-AITP-0011 §6 (Draft), where the absence of a
    snapshot for a hop issuer is not governed by ``fail_mode`` at all (the
    module docstring's stated non-goal), so neither ``policy`` nor freshness
    has any business in this function. Both live in
    ``_check_source_tct_revocation``, which answers for ``self_aid`` alone.
    """
    index: dict[str, set[str]] = {}
    for body in bodies:
        index.setdefault(body["issuer"], set()).update(e.get("jti") for e in body["entries"])
    return index


def _effective_fail_mode(inp: dict[str, Any]) -> str:
    """Resolve the ``fail_mode`` that governs *absence* on this entry point.

    Two rules, where ``tct.py`` has three:

    1. A top-level ``policy`` key, when supplied, is authoritative. A ``policy``
       dict without ``fail_mode`` resolves to ``fail_closed``, matching
       ``revocation.py``'s own ``policy.get("fail_mode", "fail_closed")`` -- so
       ``policy: {}`` is enough to opt into fail-closed. A non-dict ``policy``
       resolves to ``fail_closed`` too, never to a raw ``AttributeError``.
    2. Else -- no ``policy`` key at all -- **raise ``KeyError("policy")``**. A
       revocation decision is mandatory: this entry point has no per-wrapper
       rung (see below) for a caller to fall back on, so "no `policy`" here
       means no decision was made at all, not merely a lenient one. See
       ``ASSUMPTIONS.md``/``DECISIONS.md`` for the full reasoning, including
       why the conformance-pack constraint that originally justified a
       permissive default does not force it: ``run_conformance.py`` supplies
       the deployment's own policy for fixtures that carry none, so
       ``del-001``/``del-mh-001`` (both ``required_for_v0_2``/draft-opt-in
       success fixtures with no revocation data) still pass without their
       inputs being edited.

    ``tct.py``'s rule 2 -- the per-wrapper ``issuer_revocation_list["fail_mode"]``
    -- has **no counterpart here, on purpose**. The wire shape a delegation
    input carries is ``revocation_snapshots: [{issuer_aid, snapshot}]``
    (``schemas/conformance/PLACEHOLDERS.md``), whose records have no policy
    member at all; honoring one would be *widening the accepted wire shape*
    rather than reading what the spec already puts on the wire, and it would
    hand an unsigned caller-assembled wrapper a say in this deployment's
    revocation posture. Absent that rung, and unlike ``tct.py``, there is no
    fallback source for a decision here at all: ``policy`` is this entry
    point's only way to make one, so it is unconditionally required. ``policy``
    joins this function's other required top-level call arguments in that
    sense (not a wire artifact, so a raw ``KeyError`` on its absence is
    consistent with how every other required top-level argument already fails
    when a caller omits it -- see ``tests/test_boundary_contract.py``'s own
    documented scope exclusion for exactly this category of key).
    """
    if "policy" in inp:
        policy = inp["policy"]
        if not isinstance(policy, dict):
            return "fail_closed"
        return resolve_fail_mode(policy.get("fail_mode", "fail_closed"))
    raise KeyError("policy")


def _apply_absence(fail_mode: str, detail: str) -> None:
    """RFC-AITP-0008 §3.1 applied to the *absent* case only: under
    ``fail_closed`` an absent deny list means the source TCT's revocation
    status is unknown, and unknown is treated as revoked; under
    ``soft_fail``/``fail_open`` the delegation verifies on degraded revocation
    data.

    ``verify_delegation_token``'s verdict stays exactly ``{"grants": [...]}``
    in the permissive modes -- no ``stale`` member is added, for the same
    reason ``tct.py`` adds none: this entry point exposes no
    grant-restriction surface for a caller to act on, so §3.1's distinction
    between ``soft_fail`` ("allow with restricted grants") and ``fail_open``
    ("allow, log a warning") has no representation here.
    """
    if fail_mode == "fail_closed":
        raise AitpError(
            "DELEGATION_SOURCE_TCT_REVOKED",
            "no trusted, applicable revocation snapshot for this verifier's own deny list "
            f"({detail}); fail_closed treats unknown revocation status as revoked",
        )


def _check_source_tct_revocation(
    inp: dict[str, Any], bodies: list[dict[str, Any]], self_aid: str, src_jti: Any, now: int
) -> None:
    """RFC-AITP-0006 §4 step 7 (single-hop) and RFC-AITP-0011 §6's source-TCT
    clause (multi-hop): look up the root voucher's ``src_jti`` in **A's own**
    deny list -- plus RFC-AITP-0008 §3.1's answer for the case where A has no
    such deny list to look in.

    **Both entry paths call this one function.** The asymmetry this closes came
    from two call sites answering the same RFC step separately; a single
    implementation is what makes "the absence policy fires identically from
    both paths" a property of the code rather than of two test suites that
    happen to agree today.

    *bodies* are already fully verified (``_verified_snapshot_bodies``), so
    §1.5's obtained-but-untrustworthy case has already raised -- under every
    ``fail_mode`` -- before anything here runs. What is left is §1.5's *absent*
    case, which on this entry point is exactly two things:

    * no trusted snapshot whose **signed** ``issuer`` is ``self_aid``. Note the
      shape difference from ``tct.py``: absence here is "the supplied set has
      no entry for A", not "the input field is missing", because a present list
      carrying only other peers' snapshots leaves A's own deny list just as
      unknown as an empty one -- B cannot answer whether A revoked a TCT A
      issued. "Data was supplied" is not an escape from absence;
    * **only when a top-level ``policy`` is supplied**: every such snapshot is
      expired or staler than ``max_staleness_secs``. Gating freshness on
      ``policy`` is what keeps this auditable -- with no ``policy`` key,
      freshness and expiry are never evaluated at all, so on that dimension
      this path behaves exactly as it did before the key existed.

    The deny-list scan then reads only the applicable, still-fresh snapshots'
    own ``entries``, never a stale one's -- §3.2 treats a stale snapshot as
    data this verifier has no business reading rather than as a deny list to
    consult anyway. ``ASSUMPTIONS.md`` records the one counter-intuitive
    consequence, shared with ``tct.py`` and with ``revocation.py``'s own
    pre-existing stage-4 ordering: an explicitly *permissive* ``policy`` over a
    stale snapshot that genuinely lists ``src_jti`` verifies, where the
    identical input with no ``policy`` at all rejects.

    Per-hop issuer deny lists are governed by none of this -- see the module
    docstring's stated non-goal.

    ``_effective_fail_mode`` is resolved **eagerly, unconditionally, before**
    the applicability/freshness filtering below -- not lazily, only once
    absence is actually about to be reported. A caller who omits ``policy``
    entirely must find out on every call, not only on the first call whose
    supplied snapshot happens to be missing or stale: resolving lazily would
    let a caller who always supplies a fresh, applicable snapshot ship for
    months before discovering the missing key in production on the first
    stale day.
    """
    fail_mode = _effective_fail_mode(inp)
    applicable = [body for body in bodies if body["issuer"] == self_aid]
    detail = "no trusted snapshot signed by this verifier was supplied"
    if applicable and "policy" in inp:
        policy = inp["policy"]
        applicable = [
            body
            for body in applicable
            if not snapshot_is_stale(body, policy if isinstance(policy, dict) else {}, now)
        ]
        detail = "every snapshot signed by this verifier is expired or stale"

    if not applicable:
        _apply_absence(fail_mode, detail)
        return

    if any(entry.get("jti") == src_jti for body in applicable for entry in body["entries"]):
        raise AitpError("DELEGATION_SOURCE_TCT_REVOKED", "source TCT revoked")


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
    bodies = _verified_snapshot_bodies(inp)

    # The source-TCT check, through the identical helper the single-hop path
    # calls — same lookup, same absence policy, one implementation.
    _check_source_tct_revocation(inp, bodies, self_aid, root_voucher.get("src_jti"), now)

    # The per-hop sweep is RFC-AITP-0011 §6 (Draft) and is deliberately NOT
    # policy-governed: a hop issuer with no supplied snapshot proceeds under
    # every `fail_mode`, exactly as before (module docstring's non-goal).
    revoked = _revocation_index(bodies)
    for hop in hops:
        hc = parse_compact(hop, structural_code="DELEGATION_INVALID_SIGNATURE").claims
        if hc.get("jti") in revoked.get(str(hc.get("iss")), set()):
            raise AitpError("DELEGATION_SOURCE_TCT_REVOKED", "a hop jti is revoked")

    assert prev is not None
    return list(prev["scope"])
