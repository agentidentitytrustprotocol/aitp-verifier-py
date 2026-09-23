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

import re
from typing import Any

from .aid import parse_aid
from .b64 import b64url_decode
from .crypto import sha256
from .errors import AitpError
from .fields import canonical_bytes, check_types, decode_b64url, reject_unknown_fields, require_members
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
    require_members(obj, required, shape_code="MANIFEST_INVALID", what=what)
    check_types(obj, types, shape_code="MANIFEST_INVALID", what=what)
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
# $defs/IdentityHint's own conditional requirements, beyond `_shape`'s flat
# presence/type/member-set check: `if type == "oidc"` -> `issuer` required,
# `public_key` forbidden; `else` -> `public_key` required. `type`'s `enum` and
# `public_key`'s `pattern` (both from the schema, not invented here) are
# likewise unenforced by `_shape`, which only confirms both are strings.
_IDENTITY_HINT_TYPE_VALUES = frozenset({"oidc", "pinned_key"})
_PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43,44}$")


def _validate_identity_hint(hint: dict[str, Any]) -> None:
    """Enforce `$defs/IdentityHint`'s conditional requirements, enum, and pattern.

    `_shape` has already confirmed `type`/`subject` are present and every
    present member is correctly typed -- this covers what a flat
    presence/type/member-set check cannot express. `type`'s enum is checked
    first so an unrecognized value reports itself rather than a spurious
    "public_key required" for a type that was never valid to begin with.
    """
    hint_type = hint["type"]
    if hint_type not in _IDENTITY_HINT_TYPE_VALUES:
        raise AitpError(
            "MANIFEST_INVALID",
            f"manifest.identity_hint.type is {hint_type!r}, not one of {sorted(_IDENTITY_HINT_TYPE_VALUES)}",
        )
    if hint_type == "oidc":
        if "issuer" not in hint:
            raise AitpError(
                "MANIFEST_INVALID",
                "manifest.identity_hint is missing required member(s) ['issuer'] (required when type is 'oidc')",
            )
        if "public_key" in hint:
            raise AitpError(
                "MANIFEST_INVALID", "manifest.identity_hint.public_key is forbidden when type is 'oidc'",
            )
    elif "public_key" not in hint:
        raise AitpError(
            "MANIFEST_INVALID",
            "manifest.identity_hint is missing required member(s) ['public_key'] (required when type is not 'oidc')",
        )
    if "public_key" in hint and not _PUBLIC_KEY_PATTERN.match(hint["public_key"]):
        raise AitpError("MANIFEST_INVALID", "manifest.identity_hint.public_key does not match the required pattern")


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
    _validate_identity_hint(man["identity_hint"])
    # Grammar, not just type: `challenge` is confirmed a `str` above, but a
    # non-base64url string (or one carrying '=' padding) would otherwise reach
    # the raw `b64url_decode` below unguarded and escape this module's
    # `except AitpError` caller as a bare ValueError/binascii.Error. The
    # registry scopes MANIFEST_INVALID to include "a value outside its
    # grammar", so this stays part of the structural pass -- the PoP
    # signature step is never reached for a malformed challenge, keeping a
    # structural defect from being reported as a signature-family failure.
    decode_b64url(
        man["proof_of_possession"]["challenge"], code="MANIFEST_INVALID",
        what="manifest.proof_of_possession.challenge",
    )
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
    # `canonical_bytes` converts `JcsError` (a ValueError, not an AitpError,
    # so it would otherwise escape this module's `except AitpError` caller) to
    # MANIFEST_INVALID. `check_types`/`_shape` cannot prevent this on their
    # own: the offending value can sit anywhere inside `extensions`, whose
    # interior RFC-AITP-0001 §7 forbids inspecting, and a plain `"published_at":
    # 1` with 400 zeros is a valid JSON integer of a magnitude JCS refuses to
    # serialize -- both arrive as ordinary valid JSON from a remote peer via
    # handshake.py's inline manifest.
    digest = sha256(canonical_bytes(body, shape_code="MANIFEST_INVALID", what="manifest"))
    if not aid.public_key.verify_digest(digest, man_sig):
        raise AitpError("MANIFEST_SIGNATURE_INVALID", "manifest signature invalid")

    return {"aid": man["aid"]}
