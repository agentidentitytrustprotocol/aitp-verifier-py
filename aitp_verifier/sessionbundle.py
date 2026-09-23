"""Session Trust Bundle verification (RFC-AITP-0010 §5).

A coordinator-signed bundle binds a set of participants, each with an embedded
peer-issued TCT. The ``signature`` member lives INSIDE the inner
``session_bundle`` body (RFC-AITP-0010 §3; the bundle is redistributable and
must carry its own proof across any hop that strips the transport wrapper —
RFC-AITP-0001 §5.4.1), and is excluded from the bytes it covers: the
signature verifies over ``sha256(JCS(body))`` with the ``signature`` member
itself removed, the same convention as the Manifest (``manifest.py``). This
differs from the revocation snapshot, whose ``signature`` is a sibling of its
body — deliberately, since a snapshot is polled point-to-point and never
relayed (see ``revocation.py``).

Verification order is load-bearing: envelope shape (the wrapper carries no
member beside ``session_bundle``, the body carries its own ``signature``),
then body shape and participant-entry shape (RFC-AITP-0001 §7 — every
``additionalProperties: false`` object in the schema, not just the wrapper;
``extensions`` on the body is the one schema-reserved escape hatch and is
admitted without its contents being inspected, per RFC-AITP-0012 §1 —
bundle-005-extensions-accepted pins this). Body and participant-entry shape
now covers required-member presence and declared type as well as the member
set, so every other member the rest of this module dereferences (``participants``,
``expires_at``, ``coordinator``, each entry's ``aid``/``tct``) is guaranteed
present and correctly typed by the time it is used. Then version, then expiry
(**before** the signature — a stale bundle is rejected even if it would
verify), then the expiry-window invariant (``expires_at`` == the minimum
participant TCT ``exp``), then the coordinator signature, then each
participant TCT (shape, issued by the coordinator, ``aud`` == the participant
AID), then self-membership.

Shape precedes expiry deliberately: a bundle that is both expired and
malformed reports its shape defect (``SESSION_BUNDLE_INVALID`` for the
wrapper, ``UNKNOWN_FIELD`` for an unknown member of the signed body), not
``BUNDLE_EXPIRED``. Only well-formed input is worth evaluating semantically,
and bundle-003's expiry-before-signature ordering is unaffected — it sits
entirely downstream. RFC-AITP-0010 §5 states the same precedence for its own
reason: an unknown member is rejected "before coordinator key resolution
(step 5) triggers any network fetch and before any signature verification
(steps 6–7) is spent on it".

Draft surface (``experimental-session-bundle``): a core verifier reports SKIP
for this operation; this module is the opt-in implementation.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .crypto import sha256
from .errors import AitpError
from .fields import canonical_bytes, check_types, reject_unknown_fields, require_members
from .jws import parse_compact, verify_jws
from .sigfield import decode_tagged_signature
from .tct import check_tct_claims_shape

__all__ = ["verify_session_bundle"]

# aitp-session-bundle.schema.json: the inner `session_bundle` body and each
# `participants[]` entry are additionalProperties: false, same as the
# transport wrapper checked below. `extensions` is the RFC-AITP-0012 §1
# slot on the body (bundle-005-extensions-accepted pins it as schema-legal
# and ignored-inside).
_BODY_FIELDS = frozenset({
    "version", "session_id", "coordinator", "issued_at", "expires_at", "participants", "extensions", "signature",
})
_PARTICIPANT_FIELDS = frozenset({"aid", "tct"})
# `extensions` is the lone optional body member (RFC-AITP-0012 §1); every
# other member here is dereferenced somewhere in this module (directly, or
# via `signing_body`/`canonical_bytes`) with no presence guard before this
# phase. `issued_at`'s type check exists for completeness/fail-fast reasons
# -- it is carried through into the signed body but never itself compared,
# so `canonical_bytes` alone already prevented a crash from it; nothing here
# additionally depends on its type being checked early.
_REQUIRED_BODY_FIELDS = ("version", "session_id", "coordinator", "issued_at", "expires_at", "participants", "signature")
_BODY_TYPES: dict[str, tuple[type, ...]] = {
    "version": (str,), "session_id": (str,), "coordinator": (str,), "issued_at": (int,),
    "expires_at": (int,), "participants": (list,), "extensions": (dict,), "signature": (str,),
}
_REQUIRED_PARTICIPANT_FIELDS = ("aid", "tct")
_PARTICIPANT_TYPES: dict[str, tuple[type, ...]] = {"aid": (str,), "tct": (str,)}


def verify_session_bundle(inp: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    now = int(inp["now"]) if now is None else now
    self_aid = inp["self_aid"]
    outer = inp["session_bundle"]

    # Shape rejection runs before every semantic check: a malformed envelope is
    # not a bundle whose claims are worth evaluating. The wrapper is
    # ``additionalProperties: false`` in aitp-session-bundle.schema.json, so it
    # admits no member beside ``session_bundle``; the body lists ``signature``
    # in its ``required`` set. Together these reject the pre-erratum shape,
    # where ``signature`` sat beside the wrapper (bundle-004): a hop that
    # strips the wrapper would strip the proof with it, which is the whole
    # reason RFC-AITP-0010 §3 moved it inside. Rejecting ANY unknown wrapper
    # member, not just ``signature``, is what RFC-AITP-0001 §7 requires —
    # unknown fields outside an explicit ``extensions`` namespace MUST be
    # rejected, and the wrapper sits outside the signed bytes entirely.
    #
    # Scope: this first gate covers the transport wrapper only. The body and
    # each participant entry get their own ``reject_unknown_fields`` calls
    # below, once they are known to be objects at all — RFC-AITP-0001 §7
    # applies to every ``additionalProperties: false`` object in the schema,
    # not just the wrapper.
    #
    # The wrapper and the body deliberately fail with DIFFERENT codes.
    # RFC-AITP-0010 §5 scopes its member-set check — and the core
    # ``UNKNOWN_FIELD`` code — to "the received inner ``session_bundle``
    # body", and says of this gate: "(A ``signature`` sitting beside the
    # ``session_bundle`` wrapper key instead of inside the body is the
    # distinct pre-v0.2 shape, rejected per §3 …)". So the wrapper is a §3
    # transport-shape rule, not a §7 unknown-member one, and keeps the
    # RFC-AITP-0010 §5 aggregate: no per-step ``BUNDLE_*`` code covers
    # structural rejection, so the aggregate is the only registry code that
    # fits. bundle-004 pins the wrapper at ``SESSION_BUNDLE_INVALID`` and
    # bundle-006 pins the body at ``UNKNOWN_FIELD``; collapsing the two gates
    # into one would fail whichever fixture it was not collapsed toward.
    #
    # (RFC-AITP-0008 §1.5 draws this line differently for the revocation
    # snapshot, folding that artifact's wrapper INTO its member-set check.
    # The two artifacts are pinned differently on purpose — see revocation.py.)
    if not isinstance(outer, dict):
        raise AitpError("SESSION_BUNDLE_INVALID", f"transport wrapper is {type(outer).__name__}, not an object")
    if "session_bundle" not in outer:
        raise AitpError("SESSION_BUNDLE_INVALID", "transport wrapper has no session_bundle member")
    # ``key=repr`` because a non-JSON caller can mix key types, and bare
    # ``sorted`` would raise TypeError comparing str to int — a raw traceback
    # out of the very gate whose job is to turn malformed input into AitpError.
    if extra := sorted(set(outer) - {"session_bundle"}, key=repr):
        raise AitpError("SESSION_BUNDLE_INVALID", f"transport wrapper carries non-wrapper member(s) {extra}")

    body = outer["session_bundle"]
    if not isinstance(body, dict):
        raise AitpError("SESSION_BUNDLE_INVALID", f"session bundle body is {type(body).__name__}, not an object")
    # Presence -> type -> member-set, matching `manifest.py`'s interleaved
    # convention (Phase 4 also adopts it for envelope.py) rather than
    # revocation.py's deferred one: this validates one flat object (plus its
    # `participants[]` entries, each independently) rather than a tree.
    require_members(body, _REQUIRED_BODY_FIELDS, shape_code="SESSION_BUNDLE_INVALID", what="session bundle body")
    check_types(body, _BODY_TYPES, shape_code="SESSION_BUNDLE_INVALID", what="session bundle body")
    reject_unknown_fields(body, _BODY_FIELDS, shape_code="SESSION_BUNDLE_INVALID", what="session bundle body")

    participants = body["participants"]
    for p in participants:
        if not isinstance(p, dict):
            raise AitpError("SESSION_BUNDLE_INVALID", f"participant entry is {type(p).__name__}, not an object")
        require_members(p, _REQUIRED_PARTICIPANT_FIELDS, shape_code="SESSION_BUNDLE_INVALID", what="participant entry")
        check_types(p, _PARTICIPANT_TYPES, shape_code="SESSION_BUNDLE_INVALID", what="participant entry")
        reject_unknown_fields(p, _PARTICIPANT_FIELDS, shape_code="SESSION_BUNDLE_INVALID", what="participant entry")

    if body.get("version") != "aitp/0.2":
        raise AitpError("BUNDLE_VERSION_MISMATCH", f"unknown bundle version {body.get('version')!r}")
    # Expiry MUST run before the signature check (bundle-003).
    if now >= int(body["expires_at"]):
        raise AitpError("BUNDLE_EXPIRED", "session bundle expired")
    if not participants:
        raise AitpError("BUNDLE_EMPTY_PARTICIPANTS", "session bundle has no participants")

    # `parse_compact` only structurally decodes the JWS -- it does not verify
    # the signature or the claims shape, both of which run later, per
    # participant, only after the coordinator signature check below (the
    # bundle-003 ordering this module's docstring pins). `check_tct_claims_shape`
    # is pure JSON-shape validation with no cryptographic dependency, so
    # running it here too (before exp is dereferenced) is safe and does not
    # weaken that ordering -- it only makes this pre-signature expiry-window
    # peek crash-safe against an attacker-controlled, not-yet-verified `exp`.
    tct_exps = []
    for p in participants:
        claims = parse_compact(p["tct"], structural_code="BUNDLE_PARTICIPANT_TCT_INVALID").claims
        try:
            check_tct_claims_shape(claims, shape_code="BUNDLE_PARTICIPANT_TCT_INVALID")
        except AitpError as exc:
            # Same RFC-AITP-0010 §5 step 7 remap the later, official
            # per-participant check applies below (see its own comment) --
            # `check_tct_claims_shape` always raises the core UNKNOWN_FIELD
            # for an unrecognized claim, never *shape_code*, so this peek
            # needs the identical remap or an unknown claim would surface the
            # bare TCT-level code here instead of the bundle-scoped one.
            if exc.code != "UNKNOWN_FIELD":
                raise
            raise AitpError("BUNDLE_PARTICIPANT_TCT_INVALID", exc.message) from exc
        tct_exps.append(int(claims["exp"]))
    if int(body["expires_at"]) != min(tct_exps):
        raise AitpError("BUNDLE_EXPIRY_WINDOW_INVARIANT", "expires_at != min participant TCT exp")

    coordinator = body["coordinator"]
    try:
        coord = parse_aid(coordinator)
    except ValueError as exc:
        # `parse_aid` signals a malformed AID with a bare ValueError, which is
        # not an AitpError and escapes this module's caller. `coordinator` is
        # a schema-typed string, so this is a grammar defect ->
        # SESSION_BUNDLE_INVALID, matching manifest.py's/envelope.py's own
        # `parse_aid` guard.
        raise AitpError("SESSION_BUNDLE_INVALID", f"session bundle coordinator is not a valid AID: {exc}") from exc
    signature = body["signature"]
    signing_body = {k: v for k, v in body.items() if k != "signature"}
    raw = decode_tagged_signature(signature, coord, sig_err="BUNDLE_INVALID_SIGNATURE")
    # `canonical_bytes` converts `JcsError` (a ValueError, not an AitpError,
    # so it would otherwise escape this module's caller) to
    # SESSION_BUNDLE_INVALID. The offending value can sit anywhere inside
    # `extensions`, whose interior RFC-AITP-0001 §7 forbids inspecting, or in
    # `issued_at`/`expires_at`, both plain `int`-typed fields wide enough that
    # JCS refuses to serialize a sufficiently large one -- both arrive as
    # ordinary valid JSON from an unauthenticated coordinator.
    digest = sha256(canonical_bytes(signing_body, shape_code="SESSION_BUNDLE_INVALID", what="session bundle body"))
    if not coord.public_key.verify_digest(digest, raw):
        raise AitpError("BUNDLE_INVALID_SIGNATURE", "coordinator signature invalid")

    for p in participants:
        iss = parse_compact(p["tct"], structural_code="BUNDLE_PARTICIPANT_TCT_INVALID").claims.get("iss")
        # The embedded TCT is the one place §7's generic UNKNOWN_FIELD is
        # remapped. RFC-AITP-0010 §5 step 7 runs the standard RFC-AITP-0005
        # §7.2 order over each participant token and then states that "other
        # TCT-level failures — including TOKEN_TYP_MISMATCH / TOKEN_ALG_MISMATCH
        # rejections of an embedded token — surface as
        # BUNDLE_PARTICIPANT_TCT_INVALID". An unrecognized claim is such a
        # failure, and the three codes just above (typ_err/alg_err/sig_err) are
        # already collapsed by that same clause, so leaving this one uncollapsed
        # would report a bare-TCT code from an operation whose §8 error surface
        # is bundle-scoped. Remapped here, at the call site, rather than by
        # letting callers choose a code in fields.py: the clause is specific to
        # this containment, not a per-artifact preference, and the helper's
        # single-code guarantee is what keeps the other call sites honest.
        # RFC-AITP-0004 carries no equivalent clause, so the identical claims
        # check in handshake.py correctly reports UNKNOWN_FIELD.
        #
        # The claims-shape check now runs INSIDE verify_jws, via
        # after_typ_check -- between typ and alg, matching §7.2's now-explicit
        # sub-step order -- so it can raise from inside the call below rather
        # than only after it returns; the try/except here wraps the whole call
        # for exactly that reason, not just a trailing reject_unknown_fields.
        try:
            claims = verify_jws(
                p["tct"], iss_aid=str(iss), expected_typ="aitp-tct+jwt",
                typ_err="BUNDLE_PARTICIPANT_TCT_INVALID", alg_err="BUNDLE_PARTICIPANT_TCT_INVALID",
                sig_err="BUNDLE_PARTICIPANT_TCT_INVALID",
                after_typ_check=lambda c: check_tct_claims_shape(c, shape_code="BUNDLE_PARTICIPANT_TCT_INVALID"),
            )
        except AitpError as exc:
            if exc.code != "UNKNOWN_FIELD":
                raise
            raise AitpError("BUNDLE_PARTICIPANT_TCT_INVALID", exc.message) from exc
        if claims.get("iss") != coordinator:
            raise AitpError("BUNDLE_COORDINATOR_ISSUER_MISMATCH", "participant TCT iss != coordinator")
        if claims.get("aud") != p["aid"]:
            raise AitpError("BUNDLE_AUDIENCE_MISMATCH", "participant TCT aud != participant AID")

    if self_aid not in {p["aid"] for p in participants}:
        raise AitpError("BUNDLE_NOT_MEMBER", "verifier AID is not a bundle participant")

    return {"ok": True}
