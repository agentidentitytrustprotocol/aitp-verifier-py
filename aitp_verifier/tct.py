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

``verify_tct``'s input takes an optional top-level ``policy`` key, spelled
exactly as ``verify_revocation_snapshot``'s own (``{"fail_mode": ...,
"max_staleness_secs": ...}``). It answers the single question RFC-AITP-0008
§3.1 reserves for ``fail_mode``: what to do when **no trusted, applicable
revocation snapshot was obtained at all**. Under ``fail_closed`` unknown is
treated as revoked; under ``soft_fail``/``fail_open`` verification proceeds. It
never answers what to do about a snapshot that *was* obtained and cannot be
trusted: §1.5 decides that first. With no ``policy`` the verifier runs its
default, ``fail_closed`` (``revocation.policy_fail_mode``; ``tct-024``). A
caller with no revocation infrastructure must say so explicitly:
``policy={"fail_mode": "fail_open"}``. The input artifact never sets the mode:
an ``issuer_revocation_list`` wrapper is unsigned, so a ``fail_mode`` member on
it is never read.

``check_tct_claims_shape`` is exported so ``handshake.py`` and
``sessionbundle.py`` -- which each verify an *embedded* peer-issued TCT
inline, rather than calling ``verify_tct`` (they need the raw claims dict
afterward for their own checks, and each remaps a subset of TCT-level
failures to their own containing artifact's code) -- run the identical
claims-shape check, in the identical position, instead of each duplicating
(and risking drifting) their own copy.
"""

from __future__ import annotations

import re
from typing import Any

from .aid import parse_aid
from .b64 import b64url_decode
from .crypto import sha256
from .envelope import envelope_signing_input, validate_envelope_shape
from .errors import AitpError
from .fields import check_types, reject_unknown_fields, require_members
from .identity import trust_store_entry
from .jwk import thumbprint
from .jws import parse_compact, verify_jws
from .revocation import policy_fail_mode, policy_of, snapshot_is_stale, verify_snapshot_trust
from .sigfield import decode_tagged_signature
from .timeutil import REFERENCE_CLOCK
from .version import PROTOCOL_VERSION

__all__ = ["verify_tct", "verify_tct_as_issuer", "TCT_CLAIM_FIELDS", "TCT_CNF_FIELDS", "check_tct_claims_shape", "outlives_manifest"]

# aitp-tct.schema.json: additionalProperties: false. `ext` is the
# RFC-AITP-0012 §1.1 extensions slot on this claims object -- listing it here
# permits its presence without inspecting its contents (unknown keys inside
# `ext` MUST be ignored). No dedicated shape-rejection code exists in the
# registry for the TCT, so TCT_SIGNATURE_INVALID is reused, matching the
# `structural_code` convention jws.parse_compact already applies.
TCT_CLAIM_FIELDS = frozenset({"ver", "jti", "iss", "sub", "aud", "iat", "exp", "grants", "cnf", "ext"})
TCT_CNF_FIELDS = frozenset({"jkt"})

# RFC-AITP-0005 §2.2: lowercase, hyphenated, version nibble 4, variant 10.
_JTI_V4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")

# RFC-AITP-0005 §5.3: confers no capability; never valid in a grant context.
ATTESTATION_MARKER = "aitp.attestation"
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
    # §7.2 step 1 checks `jti` here, before the signature (tct-013, tct-014).
    if not _JTI_V4.fullmatch(claims["jti"]):
        raise AitpError(shape_code, "TCT claims.jti is not a lowercase UUID v4 (RFC-AITP-0005 §2.2)")


def check_grant_context(claims: dict[str, Any], *, code: str = "TCT_SIGNATURE_INVALID") -> None:
    """RFC-AITP-0005 §5.3 / §7.2 step 5: a TCT evaluated as a capability
    grant MUST NOT be self-issued and MUST NOT carry the attestation marker,
    alone or beside other grants (``tct-015``, ``tct-016``, ``tct-018``).
    Runs after the signature has verified.
    """
    if claims["iss"] == claims["sub"]:
        raise AitpError(code, "self-issued TCT (iss == sub) in a grant context")
    if ATTESTATION_MARKER in claims["grants"]:
        raise AitpError(code, f"TCT carries the {ATTESTATION_MARKER} marker in a grant context")


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

    if claims.get("ver") != PROTOCOL_VERSION:
        raise AitpError("UNKNOWN_VERSION", f"unknown ver {claims.get('ver')!r}")

    expected_aud = inp.get("expected_audience")
    if expected_aud is not None and claims.get("aud") != expected_aud:
        raise AitpError("AUDIENCE_MISMATCH", "TCT aud does not match verifier AID")

    if now >= int(claims["exp"]):
        raise AitpError("TCT_EXPIRED", "TCT exp is in the past")

    check_grant_context(claims)

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
    if issuer_manifest is not None and outlives_manifest(claims, issuer_manifest):
        raise AitpError("TCT_EXPIRES_AFTER_MANIFEST", "TCT outlives the issuer Manifest")

    _check_revocation(claims, inp, now)
    return {"grants": claims["grants"]}


def verify_tct_as_issuer(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    """A TCT presented back to the peer that issued it (RFC-AITP-0005 §10.5).

    Inputs: ``self_aid`` (the verifier, which MUST be ``iss``), ``tct_token``,
    and the presenter's authenticated source, which is one of:

    * ``envelope``, a ``pop_response`` answering a challenge in
      ``outstanding_pop_challenges`` (``[{tct_jti, nonce, expires_at}]``, the
      challenges this verifier issued); or
    * ``channel_bound_aid``, the AID whose key the transport channel proves.

    There is no third source, so with neither the TCT is rejected
    ``POP_RESPONSE_INVALID`` whatever the grant's PoP policy (§10.5 item 3).
    The expected audience comes only from that source, never from the token
    (item 5). Revocation runs last (item 6), under ``policy`` as for
    ``verify_tct``. Returns the presenter AID and the authorized grants.
    """
    token = inp["tct_token"]
    self_aid = inp["self_aid"]
    iss = parse_compact(token, structural_code="TCT_SIGNATURE_INVALID").claims.get("iss")
    # Item 1: in this mode only our own tokens are verified, under our own key.
    if iss != self_aid:
        raise AitpError("TCT_SIGNATURE_INVALID", "issuer-side verification of a TCT this verifier did not issue")
    claims = verify_jws(
        token,
        iss_aid=str(self_aid),
        expected_typ="aitp-tct+jwt",
        typ_err="TOKEN_TYP_MISMATCH",
        alg_err="TOKEN_ALG_MISMATCH",
        sig_err="TCT_SIGNATURE_INVALID",
        after_typ_check=lambda c: check_tct_claims_shape(c, shape_code="TCT_SIGNATURE_INVALID"),
    )

    # Item 2: §7.2 step 5 read from the issuer's side.
    if claims["ver"] != PROTOCOL_VERSION:
        raise AitpError("UNKNOWN_VERSION", f"unknown ver {claims['ver']!r}")
    if claims["aud"] != claims["sub"]:
        raise AitpError("TCT_SIGNATURE_INVALID", "issuer-side TCT whose aud != sub")
    if now >= int(claims["exp"]):
        raise AitpError("TCT_EXPIRED", "TCT exp is in the past")
    check_grant_context(claims)
    try:
        sub_aid = parse_aid(claims["sub"])
    except ValueError as exc:
        raise AitpError("TCT_SIGNATURE_INVALID", f"TCT claims.sub is not a valid AID: {exc}") from exc
    if claims["cnf"].get("jkt") != thumbprint(sub_aid):
        raise AitpError("TCT_CNF_MISMATCH", "cnf.jkt does not bind the subject key")

    # Items 3 and 4: the presenter AID, from PoP or a channel binding only.
    if inp.get("envelope") is not None:
        presenter = _presenter_from_pop(inp, claims, now)
    elif inp.get("channel_bound_aid") is not None:
        presenter = inp["channel_bound_aid"]
    else:
        raise AitpError("POP_RESPONSE_INVALID", "no downstream PoP and no channel binding for the presenter")
    if presenter != claims["sub"]:
        raise AitpError("POP_RESPONSE_INVALID", "presenter AID is not the TCT sub")

    _check_revocation(claims, inp, now)
    return {"presenter_aid": presenter, "grants": claims["grants"]}


def _presenter_from_pop(inp: dict[str, Any], claims: dict[str, Any], now: int) -> str:
    """RFC-AITP-0005 §6.2 over a challenge this verifier issued for ``jti``.
    Returns ``sub``, the only AID a valid response can establish."""
    try:
        env = validate_envelope_shape(inp["envelope"])
        sender = parse_aid(env["sender"]["agent_id"])
    except (AitpError, ValueError) as exc:
        raise AitpError("POP_RESPONSE_INVALID", f"pop_response envelope is malformed: {exc}") from exc
    payload = env["payload"]
    if env["message_type"] != "pop_response" or not all(
        isinstance(payload.get(k), str) for k in ("tct_jti", "nonce_echo", "pop_signature")
    ):
        raise AitpError("POP_RESPONSE_INVALID", "not a pop_response with tct_jti, nonce_echo and pop_signature")

    # §6.2 step 1: the response envelope signature.
    raw = decode_tagged_signature(env["signature"], sender, sig_err="POP_RESPONSE_INVALID")
    if not sender.public_key.verify_digest(sha256(envelope_signing_input(env)), raw):
        raise AitpError("POP_RESPONSE_INVALID", "pop_response envelope signature invalid")

    # The challenge it answers: one we issued for this jti, still live.
    if payload["tct_jti"] != claims["jti"]:
        raise AitpError("POP_RESPONSE_INVALID", "pop_response names a different tct_jti")
    challenges = [
        c for c in inp.get("outstanding_pop_challenges") or []
        if isinstance(c, dict) and c.get("tct_jti") == claims["jti"] and c.get("nonce") == payload["nonce_echo"]
    ]
    if not challenges:
        # §6.2 step 2: the echo matches no challenge this verifier sent.
        raise AitpError("POP_RESPONSE_INVALID", "nonce_echo matches no outstanding challenge for this jti")
    challenge = challenges[0]
    expires_at = challenge.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or now >= expires_at:
        raise AitpError("POP_CHALLENGE_INVALID", "the challenge is expired or malformed")
    try:
        nonce = b64url_decode(challenge["nonce"])
    except ValueError as exc:
        raise AitpError("POP_CHALLENGE_INVALID", f"challenge nonce is not base64url: {exc}") from exc

    # §6.2 steps 3-4: signed by the key in `sub`, and `cnf.jkt` binds that
    # key (checked by the caller). Any other key, however valid, fails.
    sub_aid = parse_aid(claims["sub"])
    sig = decode_tagged_signature(payload["pop_signature"], sub_aid, sig_err="POP_RESPONSE_INVALID")
    if not sub_aid.public_key.verify_digest(sha256(nonce), sig):
        raise AitpError("POP_RESPONSE_INVALID", "pop_signature does not verify under the sub key")
    return str(claims["sub"])


def outlives_manifest(claims: dict[str, Any], manifest: dict[str, Any]) -> bool:
    """RFC-AITP-0005 §10.4: a token MUST NOT outlive its issuer's Manifest.
    Equal is within the bound. Shared by every Manifest-capped check."""
    return int(claims["exp"]) > int(manifest["expires_at"])


def verify_attestation(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    """Relying-party verification of a self-attestation (RFC-AITP-0005 §5.3
    "Verification"). Not a grant context: ``aud`` need not be this party's
    AID, and ``iss == sub`` is the required shape.

    Runs §7.2 steps 1-4 and 6 unchanged. In place of step 5 it checks
    ``ver``, ``exp``, ``cnf.jkt``, ``iss == sub == aud``, that ``grants`` is
    exactly ``["aitp.attestation"]``, and that ``ext`` carries
    ``expected_ext_key`` (``tct-019``). Each shape defect is
    ``TCT_SIGNATURE_INVALID``.

    Issuer key resolution follows the §7.3 exception: ``iss`` MUST be in
    ``trust_store``, the relying party's own record of keys trusted at
    ``iat``. The Manifest-cap decision is mandatory: pass
    ``issuer_manifest`` (§10.4 applies) or ``waive_manifest_cap: True``
    (the issuer publishes none). Omitting both is a caller error
    (``ValueError``), never a silent waiver.
    """
    token = inp["tct_token"]
    statement_key = inp["expected_ext_key"]
    issuer_manifest = inp.get("issuer_manifest")
    if issuer_manifest is None and inp.get("waive_manifest_cap") is not True:
        raise ValueError("verify_attestation: pass issuer_manifest or waive_manifest_cap; the Manifest-cap decision is mandatory")

    iss = parse_compact(token, structural_code="TCT_SIGNATURE_INVALID").claims.get("iss")
    claims = verify_jws(
        token,
        iss_aid=str(iss),
        expected_typ="aitp-tct+jwt",
        typ_err="TOKEN_TYP_MISMATCH",
        alg_err="TOKEN_ALG_MISMATCH",
        sig_err="TCT_SIGNATURE_INVALID",
        after_typ_check=lambda c: _attestation_pre_signature(c, inp.get("trust_store")),
    )

    if claims["ver"] != PROTOCOL_VERSION:
        raise AitpError("UNKNOWN_VERSION", f"unknown ver {claims['ver']!r}")
    if now >= int(claims["exp"]):
        raise AitpError("TCT_EXPIRED", "attestation exp is in the past")
    if not (claims["iss"] == claims["sub"] == claims["aud"]):
        raise AitpError("TCT_SIGNATURE_INVALID", "attestation is not iss == sub == aud")
    if claims["grants"] != [ATTESTATION_MARKER]:
        raise AitpError("TCT_SIGNATURE_INVALID", f"attestation grants must be exactly [{ATTESTATION_MARKER!r}]")
    if claims["cnf"].get("jkt") != thumbprint(parse_aid(str(claims["sub"]))):
        raise AitpError("TCT_SIGNATURE_INVALID", "attestation cnf.jkt does not bind the issuer key")
    ext = claims.get("ext")
    if not isinstance(ext, dict) or statement_key not in ext:
        raise AitpError("TCT_SIGNATURE_INVALID", f"attestation ext lacks {statement_key!r}")
    if issuer_manifest is not None and outlives_manifest(claims, issuer_manifest):
        raise AitpError("TCT_EXPIRES_AFTER_MANIFEST", "attestation outlives the issuer Manifest")

    _check_revocation(claims, inp, now)
    return {"statement": ext[statement_key]}


def _attestation_pre_signature(claims: dict[str, Any], trust_store: Any) -> None:
    check_tct_claims_shape(claims, shape_code="TCT_SIGNATURE_INVALID")
    # §7.3 exception: without a Manifest to resolve, the issuer key must be
    # one the relying party already records as trusted.
    issuer = trust_store_entry(claims.get("iss"))
    trusted = {e for e in map(trust_store_entry, trust_store or []) if e is not None}
    if issuer is None or issuer not in trusted:
        raise AitpError("TCT_SIGNATURE_INVALID", "attestation issuer is not in trust_store")


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


def _check_revocation(claims: dict[str, Any], inp: dict[str, Any], now: int) -> None:
    """RFC-AITP-0008 §3.3 + §3.1, in that order.

    **A discarded snapshot is an absent one** (RFC-AITP-0008 §1.5). A supplied
    snapshot MUST itself be trusted (structurally valid, correctly shaped,
    genuinely signed by its own claimed issuer) before its ``entries`` are
    consulted. When that check fails, ``verify_revocation_snapshot`` would
    report the snapshot's own code; the *token* decision instead discards it
    and applies ``fail_mode``, exactly as for an unreachable endpoint
    (``tct-022``/``tct-023``). So under ``fail_closed`` corrupting a snapshot
    in transit cannot turn fail-closed into fail-open.

    **Absence** is the discarded case above plus:

    * (a) ``issuer_revocation_list`` missing or not an object: no source, nothing obtained
      (``tct-024``/``tct-025``);
    * (b) the trusted snapshot's **signed** ``issuer`` is not this TCT's
      ``iss``. The wrapper's own unsigned ``issuer`` label is never
      consulted;
    * (c) the snapshot is expired or staler than the policy's
      ``max_staleness_secs`` (RFC-AITP-0008 §3.2).

    Present, trusted, applicable and fresh ⇒ the deny-list scan.
    """
    fail_mode = policy_fail_mode(inp)
    revlist = inp.get("issuer_revocation_list")

    # (a) Nothing was obtained at all.
    if not isinstance(revlist, dict):
        _apply_absence(fail_mode, "no revocation source for the issuer")
        return

    # Trust before the deny-list scan, always. A snapshot that fails it is
    # discarded and absent for this decision (RFC-AITP-0008 §1.5).
    try:
        body = verify_snapshot_trust(revlist.get("snapshot"))
    except AitpError as err:
        _apply_absence(fail_mode, f"the supplied snapshot was discarded ({err.code})")
        return

    # (b) A snapshot signed by someone other than this TCT's own issuer does
    # not speak for it.
    if body["issuer"] != claims.get("iss"):
        _apply_absence(fail_mode, "the supplied snapshot is signed by a different issuer")
        return

    # (c) Freshness.
    if snapshot_is_stale(body, policy_of(inp), now):
        _apply_absence(fail_mode, "the supplied snapshot is expired or stale")
        return

    if any(e.get("jti") == claims.get("jti") for e in body["entries"]):
        raise AitpError("TCT_REVOKED", "TCT jti is on the issuer revocation snapshot")
