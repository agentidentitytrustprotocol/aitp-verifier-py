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

``verify_delegation_token``'s input takes an optional top-level ``policy``
key, spelled exactly as ``verify_tct``'s and ``verify_revocation_snapshot``'s
own (``{"fail_mode": ..., "max_staleness_secs": ...}``). It answers the single
question RFC-AITP-0008 §3.1 reserves for ``fail_mode``: what to do when **no
trusted, applicable revocation snapshot for ``self_aid`` was supplied at
all**. Under ``fail_closed`` unknown is treated as revoked
(``DELEGATION_SOURCE_TCT_REVOKED``); under ``soft_fail``/``fail_open``
verification proceeds. It never answers what to do about a snapshot that *was*
supplied and cannot be trusted: §1.5 decides that first. With no ``policy`` the
verifier runs its default, ``fail_closed`` (``revocation.policy_fail_mode``).
A caller with no revocation infrastructure must say so explicitly:
``policy={"fail_mode": "fail_open"}``.

That policy governs **A's own deny list and nothing else** — the §4 step 7 /
RFC-AITP-0011 §6 source-TCT lookup, which both the single-hop and the multi-hop
path run through the one ``_check_source_tct_revocation`` below rather than
each answering separately. A's own deny list is local state, so a snapshot carrying it
that fails verification is rejected with its own code under every mode, never
treated as absent (RFC-AITP-0006 §4 step 7, ``del-008``).

The multi-hop per-hop issuer sweep (RFC-AITP-0011 §6) reads the same policy.
A hop issuer with no fresh, trusted snapshot is absent -- none supplied (as for
an unreachable endpoint, RFC-AITP-0008 §3.1), or its snapshot discarded under
§1.5 (fails verification, signed by an issuer other than its record's
``issuer_aid``, expired or stale) -- and under ``fail_closed`` that hop counts
as revoked (``del-mh-006``). The conformance pack's fixtures that carry no
revocation input do not test revocation (spec conformance README, "Revocation
inputs"); ``run_conformance.py`` supplies ``fail_open`` for them, which is what
keeps ``del-mh-001`` passing. ``DECISIONS.md`` records this as the reversal of
the earlier per-hop non-goal.
"""

from __future__ import annotations

from typing import Any

from .b64 import b64url_encode
from .crypto import sha256
from .errors import AitpError
from .fields import check_types, reject_unknown_fields, require_members
from .jcs import canonicalize
from .jws import parse_compact, verify_jws
from .manifest import resolve_key_from_manifests
from .revocation import policy_fail_mode, policy_of, snapshot_is_stale, verify_snapshot_trust
from .timeutil import REFERENCE_CLOCK
from .version import PROTOCOL_VERSION
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


def _resolve_issuer(inp: dict[str, Any], iss: Any, now: int) -> None:
    """RFC-AITP-0006 §4 step 1 / RFC-AITP-0011 §3 step 1: when the caller
    supplies its Manifest source (``issuer_manifests``), each hop issuer's key
    must be designated by one of those Manifests before its signature is
    checked (del-mh-005). The key itself is the AID's for ``aid:pubkey``."""
    if "issuer_manifests" in inp:
        resolve_key_from_manifests(str(iss), inp["issuer_manifests"], now)


def _reject_v01_object_token(token: dict[str, Any]) -> None:
    """The retired v0.1 object-shaped token (del-004). It is never verified,
    only rejected structurally: a non-empty ``chain`` is multi-hop, which no
    v0.3 object token can carry; anything else is a malformed token."""
    if token.get("chain"):
        raise AitpError("DELEGATION_MULTIHOP_NOT_SUPPORTED", "v0.1 object token with a non-empty chain")
    raise AitpError("DELEGATION_INVALID_SIGNATURE", "v0.1 object-shaped delegation token is not a compact JWS")


def verify_delegation_token(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    token = inp.get("delegation_token")
    if token is None and isinstance(inp.get("delegation"), dict):
        _reject_v01_object_token(inp["delegation"])
    if not isinstance(token, str):
        raise AitpError("DELEGATION_INVALID_SIGNATURE", "delegation_token is absent or not a compact JWS string")
    outer = parse_compact(token, structural_code="DELEGATION_INVALID_SIGNATURE").claims

    # Multi-hop guard — structural, before any signature work or key lookup. A
    # verifier that has not opted into RFC-AITP-0011 rejects on the mere
    # presence of `chain`.
    if "chain" in outer and inp.get("_feature") != _MULTIHOP_FEATURE:
        raise AitpError("DELEGATION_MULTIHOP_NOT_SUPPORTED", "chain claim requires RFC-AITP-0011 opt-in")
    self_aid = inp.get("self_aid")
    if not isinstance(self_aid, str):
        raise AitpError("DELEGATION_AUDIENCE_MISMATCH", "no verifier AID to match the delegation aud against")
    if "chain" in outer:
        return {"grants": _verify_multihop(inp, token, outer, self_aid, now)}

    _resolve_issuer(inp, outer.get("iss"), now)
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
    _check_source_tct_revocation(inp, _verified_snapshot_bodies(inp, self_aid), self_aid, vclaims["src_jti"], now)

    return {"grants": claims["scope"]}


def _verified_snapshot_bodies(inp: dict[str, Any], self_aid: str) -> list[dict[str, Any]]:
    """Every supplied revocation snapshot that verifies, in input order.

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

    A record whose snapshot fails verification is split by its unsigned
    ``issuer_aid`` label, the only attribution a snapshot that did not verify
    has:

    * labelled ``self_aid`` (or unlabelled, so it may be): A's own deny list.
      That is local state, not a fetched snapshot, so RFC-AITP-0006 §4 step 7
      rejects with the snapshot's own code under every mode (``del-008``).
    * labelled with another issuer: a hop issuer's snapshot, discarded under
      RFC-AITP-0008 §1.5 and left out, so the per-hop sweep finds that issuer
      absent and applies ``fail_mode`` (``del-mh-006``). Mislabelling cannot
      weaken fail-closed: the label only decides whether the failure surfaces
      as the snapshot's own code or as a policy decision.

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
    """
    snaps = inp.get("revocation_snapshots")
    if snaps is None:
        snaps = []
    elif not isinstance(snaps, list):
        raise AitpError(
            "REVOCATION_SNAPSHOT_INVALID",
            f"revocation_snapshots must be an array, got {type(snaps).__name__}",
        )
    bodies: list[dict[str, Any]] = []
    for record in snaps:
        label = record.get("issuer_aid") if isinstance(record, dict) else None
        try:
            bodies.append(verify_snapshot_trust(record.get("snapshot") if isinstance(record, dict) else None))
        except AitpError:
            if not isinstance(label, str) or label == self_aid:
                raise
    return bodies


def _revocation_index(bodies: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Map issuer AID -> set of revoked jti, over already-verified snapshot
    bodies (`_verified_snapshot_bodies`). RFC-AITP-0011 §6's per-hop sweep is
    this map's one consumer.

    Indexes on the *verified* ``body["issuer"]``, not the caller-supplied
    ``record.get("issuer_aid")`` label: the signed value wins, so a
    correctly-signed snapshot can never be filed under an issuer the caller's
    own wrapper merely claims for it.

    Deliberately policy-free and ``now``-free -- a pure index. The per-hop
    sweep that consumes it filters out stale bodies first and applies
    ``fail_mode`` to absence itself, so neither has any business in here.
    """
    index: dict[str, set[str]] = {}
    for body in bodies:
        index.setdefault(body["issuer"], set()).update(e.get("jti") for e in body["entries"])
    return index


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

    *bodies* are already fully verified (``_verified_snapshot_bodies``), so a
    snapshot carrying A's own deny list that fails verification has already
    raised its own code -- under every ``fail_mode``, since A's own list is
    local state, not a fetched snapshot (RFC-AITP-0006 §4 step 7) -- before
    anything here runs. What is left is §1.5's *absent*
    case, which on this entry point is exactly two things:

    * no trusted snapshot whose **signed** ``issuer`` is ``self_aid``. Note the
      shape difference from ``tct.py``: absence here is "the supplied set has
      no entry for A", not "the input field is missing", because a present list
      carrying only other peers' snapshots leaves A's own deny list just as
      unknown as an empty one -- B cannot answer whether A revoked a TCT A
      issued. "Data was supplied" is not an escape from absence;
    * every such snapshot is expired or staler than ``max_staleness_secs``,
      evaluated against the caller's ``policy`` (or the default, which bounds
      freshness by each snapshot's own ``expires_at`` only).

    The deny-list scan then reads only the applicable, still-fresh snapshots'
    own ``entries``, never a stale one's -- §3.2 treats a stale snapshot as
    data this verifier has no business reading rather than as a deny list to
    consult anyway.

    Per-hop issuer deny lists are the multi-hop sweep's job, under the same
    ``fail_mode`` -- see the module docstring.
    """
    fail_mode = policy_fail_mode(inp)
    applicable = [body for body in bodies if body["issuer"] == self_aid]
    detail = "no trusted snapshot signed by this verifier was supplied"
    if applicable:
        policy = policy_of(inp)
        applicable = [body for body in applicable if not snapshot_is_stale(body, policy, now)]
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
        hop_iss = parse_compact(hop, structural_code="DELEGATION_INVALID_SIGNATURE").claims.get("iss")
        _resolve_issuer(inp, hop_iss, now)
        hc = verify_jws(
            hop, iss_aid=str(hop_iss),
            expected_typ="aitp-delegation+jwt", typ_err="TOKEN_TYP_MISMATCH",
            alg_err="TOKEN_ALG_MISMATCH", sig_err="DELEGATION_INVALID_SIGNATURE",
        )
        _check_delegation_claims_shape(hc, shape_code="DELEGATION_INVALID_SIGNATURE")
        if hc.get("ver") != PROTOCOL_VERSION:
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
    bodies = _verified_snapshot_bodies(inp, self_aid)

    # The source-TCT check, through the identical helper the single-hop path
    # calls — same lookup, same absence policy, one implementation.
    _check_source_tct_revocation(inp, bodies, self_aid, root_voucher.get("src_jti"), now)

    # The per-hop sweep (RFC-AITP-0011 §6). A hop issuer with no fresh, trusted
    # snapshot -- none supplied, or discarded (RFC-AITP-0008 §1.5) -- is absent
    # and `fail_mode` decides (RFC-AITP-0008 §3.1).
    policy = policy_of(inp)
    fresh = [body for body in bodies if not snapshot_is_stale(body, policy, now)]
    revoked = _revocation_index(fresh)
    fail_mode = policy_fail_mode(inp)
    for hop in hops:
        hc = parse_compact(hop, structural_code="DELEGATION_INVALID_SIGNATURE").claims
        iss = str(hc.get("iss"))
        if hc.get("jti") in revoked.get(iss, set()):
            raise AitpError("DELEGATION_SOURCE_TCT_REVOKED", "a hop jti is revoked")
        if iss not in revoked and fail_mode == "fail_closed":
            raise AitpError(
                "DELEGATION_SOURCE_TCT_REVOKED",
                "no fresh, trusted revocation snapshot for a hop issuer; "
                "fail_closed treats unknown revocation status as revoked",
            )

    assert prev is not None
    return list(prev["scope"])
