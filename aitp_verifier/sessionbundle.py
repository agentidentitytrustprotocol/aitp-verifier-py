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
then version, then expiry (**before** the signature — a stale bundle is
rejected even if it would verify), then the expiry-window invariant
(``expires_at`` == the minimum participant TCT ``exp``), then the
coordinator signature, then each participant TCT (issued
by the coordinator, ``aud`` == the participant AID), then self-membership.

Shape precedes expiry deliberately: a bundle that is both expired and
malformed reports ``SESSION_BUNDLE_INVALID``, not ``BUNDLE_EXPIRED``. Only
well-formed input is worth evaluating semantically, and bundle-003's
expiry-before-signature ordering is unaffected — it sits entirely downstream.

Draft surface (``experimental-session-bundle``): a core verifier reports SKIP
for this operation; this module is the opt-in implementation.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .crypto import sha256
from .errors import AitpError
from .jcs import canonicalize
from .jws import parse_compact, verify_jws
from .sigfield import decode_tagged_signature

__all__ = ["verify_session_bundle"]


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
    # Scope: this gate covers the envelope only. Unknown members INSIDE the
    # signed body or a participant entry are still accepted, though the schema
    # marks those objects ``additionalProperties: false`` too — a pre-existing
    # gap, not one this check closes. It is narrower than it sounds: the body
    # is signed, so this admits only members the coordinator itself signed; a
    # member stapled on afterwards fails as BUNDLE_INVALID_SIGNATURE.
    #
    # These raise the RFC-AITP-0010 §5 aggregate rather than a ``BUNDLE_*``
    # code. Specific codes are preferred everywhere else in this module, but no
    # per-step code covers structural rejection, so the aggregate is the only
    # registry code that fits.
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
    if "signature" not in body:
        raise AitpError("SESSION_BUNDLE_INVALID", "session bundle body has no signature")
    if not isinstance(body["signature"], str):
        # Schema pins `type: string`; sigfield.py annotates `sig: str` but is
        # handed unvalidated input, so a non-string tracebacks there instead.
        raise AitpError("SESSION_BUNDLE_INVALID", f"signature is {type(body['signature']).__name__}, not a string")

    participants = body["participants"]

    if body.get("version") != "aitp/0.2":
        raise AitpError("BUNDLE_VERSION_MISMATCH", f"unknown bundle version {body.get('version')!r}")
    # Expiry MUST run before the signature check (bundle-003).
    if now >= int(body["expires_at"]):
        raise AitpError("BUNDLE_EXPIRED", "session bundle expired")
    if not participants:
        raise AitpError("BUNDLE_EMPTY_PARTICIPANTS", "session bundle has no participants")

    tct_exps = [int(parse_compact(p["tct"], structural_code="BUNDLE_PARTICIPANT_TCT_INVALID").claims["exp"]) for p in participants]
    if int(body["expires_at"]) != min(tct_exps):
        raise AitpError("BUNDLE_EXPIRY_WINDOW_INVARIANT", "expires_at != min participant TCT exp")

    coordinator = body["coordinator"]
    coord = parse_aid(coordinator)
    signature = body["signature"]
    signing_body = {k: v for k, v in body.items() if k != "signature"}
    raw = decode_tagged_signature(signature, coord, sig_err="BUNDLE_INVALID_SIGNATURE")
    if not coord.public_key.verify_digest(sha256(canonicalize(signing_body)), raw):
        raise AitpError("BUNDLE_INVALID_SIGNATURE", "coordinator signature invalid")

    for p in participants:
        iss = parse_compact(p["tct"], structural_code="BUNDLE_PARTICIPANT_TCT_INVALID").claims.get("iss")
        claims = verify_jws(
            p["tct"], iss_aid=str(iss), expected_typ="aitp-tct+jwt",
            typ_err="BUNDLE_PARTICIPANT_TCT_INVALID", alg_err="BUNDLE_PARTICIPANT_TCT_INVALID",
            sig_err="BUNDLE_PARTICIPANT_TCT_INVALID",
        )
        if claims.get("iss") != coordinator:
            raise AitpError("BUNDLE_COORDINATOR_ISSUER_MISMATCH", "participant TCT iss != coordinator")
        if claims.get("aud") != p["aid"]:
            raise AitpError("BUNDLE_AUDIENCE_MISMATCH", "participant TCT aud != participant AID")

    if self_aid not in {p["aid"] for p in participants}:
        raise AitpError("BUNDLE_NOT_MEMBER", "verifier AID is not a bundle participant")

    return {"ok": True}
