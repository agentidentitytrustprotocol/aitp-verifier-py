"""Agent Manifest verification (RFC-AITP-0003 §5, JCS profile).

Ordered checklist: shape → version → expiry → proof-of-possession →
signature. Shape runs first, as elsewhere in this verifier (see
``sessionbundle.py``): an object carrying a field outside the schema's
``additionalProperties: false`` set is not worth evaluating semantically
(RFC-AITP-0001 §7). The Manifest signature covers
``sha256(JCS(manifest_body))`` with the top-level ``signature`` member
removed (§6.1); the PoP covers ``sha256(base64url_decode(challenge))``
(§3.1). Both verify under the key embedded in ``manifest.aid``.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .b64 import b64url_decode
from .crypto import sha256
from .errors import AitpError
from .fields import reject_unknown_fields
from .jcs import canonicalize
from .sigfield import decode_tagged_signature
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_manifest"]

# aitp-manifest.schema.json's `manifest` body and `proof_of_possession`
# sub-object are both additionalProperties: false. Structural rejection maps to
# MANIFEST_INVALID, the code the registry's structural-rejection table assigns
# the Manifest. This module previously reused MANIFEST_SIGNATURE_INVALID
# because no such code existed -- the gap was filed upstream and closed by
# spec PR #42, which added MANIFEST_INVALID (and the revocation pair) precisely
# so that a shape defect is not reported as a signature failure.
#
# MANIFEST_INVALID vs UNKNOWN_FIELD: a missing REQUIRED member or a mistyped
# one is MANIFEST_INVALID; an unrecognized member outside `extensions` is
# UNKNOWN_FIELD (RFC-AITP-0001 §7). The registry is explicit that the §7 code
# applies "when the only defect is an unknown member", which is why the
# required-member check below runs first.
_MANIFEST_FIELDS = frozenset({
    "version", "aid", "display_name", "identity_hint", "handshake_endpoint",
    "accepted_trust_anchors", "offered_capabilities", "required_peer_capabilities",
    "accepted_identity_types", "accepted_signature_algorithms", "proof_of_possession",
    "published_at", "expires_at", "extensions", "signature",
})
_POP_FIELDS = frozenset({"challenge", "signature"})
# Declared types and `required` sets, so a mistyped member is rejected as
# MANIFEST_INVALID rather than reaching the crypto steps. The registry defines
# the code as covering "a missing REQUIRED member, a member of the wrong type,
# or a value outside its grammar" -- all three, not just the first. This is
# remote-reachable: handshake.py feeds a peer's inline manifest from a
# `mutual_hello` straight into verify_manifest, so an unvalidated member
# surfaced there as a raw TypeError/ValueError/AttributeError past the
# caller's `except AitpError`.
_MANIFEST_TYPES: dict[str, tuple[type, ...]] = {
    "version": (str,), "aid": (str,), "display_name": (str,), "identity_hint": (dict,),
    "handshake_endpoint": (str,), "accepted_trust_anchors": (list,),
    "offered_capabilities": (list,), "required_peer_capabilities": (list,),
    "accepted_identity_types": (list,), "accepted_signature_algorithms": (list,),
    "proof_of_possession": (dict,), "published_at": (int,), "expires_at": (int,),
    "extensions": (dict,), "signature": (str,),
}
_POP_TYPES: dict[str, tuple[type, ...]] = {"challenge": (str,), "signature": (str,)}
_IDENTITY_HINT_TYPES: dict[str, tuple[type, ...]] = {
    "type": (str,), "issuer": (str,), "subject": (str,), "public_key": (str,),
}
_REQUIRED_POP_FIELDS = ("challenge", "signature")
_REQUIRED_IDENTITY_HINT_FIELDS = ("type", "subject")


def _shape(obj: Any, required: tuple[str, ...], allowed: frozenset[str],
           types: dict[str, tuple[type, ...]], what: str) -> None:
    """Schema validation for one manifest object: presence, member set, types.

    Ordered so the reported code is the right one when an object has several
    defects: presence and type both yield MANIFEST_INVALID and both run first,
    because UNKNOWN_FIELD applies (per the registry) only when an unknown
    member is the ONLY defect.
    """
    if not isinstance(obj, dict):
        raise AitpError("MANIFEST_INVALID", f"{what} is {type(obj).__name__}, not an object")
    if missing := [k for k in required if k not in obj]:
        raise AitpError("MANIFEST_INVALID", f"{what} is missing required member(s) {missing}")
    for key, allowed_types in types.items():
        if key not in obj:
            continue
        value = obj[key]
        # `bool` is excluded from `int` deliberately: Python makes True an int,
        # JSON does not. An integral float IS a valid JSON `integer` and
        # canonicalizes identically, so it is admitted.
        if isinstance(value, bool) and bool not in allowed_types:
            raise AitpError("MANIFEST_INVALID", f"{what}.{key} is bool, not {allowed_types[0].__name__}")
        if int in allowed_types and isinstance(value, float) and value.is_integer():
            continue
        if not isinstance(value, allowed_types):
            raise AitpError("MANIFEST_INVALID", f"{what}.{key} is {type(value).__name__}, not {allowed_types[0].__name__}")
    # Last, so that an object which is BOTH mistyped and carrying an unknown
    # member reports the structural code. The registry scopes UNKNOWN_FIELD to
    # "when the only defect is an unknown member", and revocation.py orders it
    # the same way -- a divergence here would be invisible, since every fixture
    # carries one defect at a time.
    reject_unknown_fields(obj, allowed, shape_code="MANIFEST_INVALID", what=what)
# The schema's `required` set for the body. `identity_hint` is REQUIRED (it is
# how a peer states which identity family it will present), so the check below
# is unconditional rather than `if "identity_hint" in man`.
_REQUIRED_MANIFEST_FIELDS = (
    "version", "aid", "identity_hint", "handshake_endpoint", "accepted_trust_anchors",
    "offered_capabilities", "proof_of_possession", "published_at", "expires_at", "signature",
)
# $defs/IdentityHint, reached through a `$ref` from the body's `identity_hint`
# -- also additionalProperties: false, and REQUIRED by the body's `required`
# array (it is how a peer states which identity family it will present).
# handshake.py:82 reads it, so leaving it open would have been a real hole
# behind an indirection.
_IDENTITY_HINT_FIELDS = frozenset({"type", "issuer", "subject", "public_key"})


def verify_manifest(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    man = inp["manifest"]
    # RFC-AITP-0003 §5 step 2: structural validation runs before the
    # cryptographic steps, so a Manifest that does not match its schema is
    # rejected before any proof-of-possession or signature work is spent on it
    # (man-006). Required members first, then the member set -- a Manifest with
    # both defects reports the structural one, per the registry's "only defect"
    # wording for UNKNOWN_FIELD.
    _shape(man, _REQUIRED_MANIFEST_FIELDS, _MANIFEST_FIELDS, _MANIFEST_TYPES, "manifest")
    _shape(man["proof_of_possession"], _REQUIRED_POP_FIELDS, _POP_FIELDS, _POP_TYPES, "manifest.proof_of_possession")
    _shape(man["identity_hint"], _REQUIRED_IDENTITY_HINT_FIELDS, _IDENTITY_HINT_FIELDS,
           _IDENTITY_HINT_TYPES, "manifest.identity_hint")
    now = int(inp.get("now", now))
    supported = inp.get("supported_versions", ["aitp/0.2"])

    if man.get("version") not in supported:
        raise AitpError("MANIFEST_VERSION_UNKNOWN", f"unsupported version {man.get('version')!r}")
    if now >= int(man["expires_at"]):
        raise AitpError("MANIFEST_EXPIRED", "manifest expires_at is in the past")

    try:
        aid = parse_aid(man["aid"])
    except ValueError as exc:
        # `parse_aid` signals a malformed AID with a bare ValueError, which is
        # not an AitpError and escapes the caller. `aid` is a schema-typed
        # string, so this is a grammar defect -> MANIFEST_INVALID. Reachable
        # from a remote `mutual_hello` via handshake.py's inline manifest.
        raise AitpError("MANIFEST_INVALID", f"manifest aid is not a valid AID: {exc}") from exc

    pop = man["proof_of_possession"]
    pop_sig = decode_tagged_signature(pop["signature"], aid, sig_err="MANIFEST_POP_FAILED")
    if not aid.public_key.verify_digest(sha256(b64url_decode(pop["challenge"])), pop_sig):
        raise AitpError("MANIFEST_POP_FAILED", "proof-of-possession signature invalid")

    man_sig = decode_tagged_signature(man["signature"], aid, sig_err="MANIFEST_SIGNATURE_INVALID")
    body = {k: v for k, v in man.items() if k != "signature"}
    if not aid.public_key.verify_digest(sha256(canonicalize(body)), man_sig):
        raise AitpError("MANIFEST_SIGNATURE_INVALID", "manifest signature invalid")

    return {"aid": man["aid"]}
