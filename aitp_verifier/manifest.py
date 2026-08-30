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
# sub-object are both additionalProperties: false. The registry has no
# aggregate MANIFEST_INVALID/schema-validation code (unlike INVALID_ENVELOPE
# for the envelope) -- MANIFEST_SIGNATURE_INVALID is reused for shape
# rejection here, following the same convention jws.py already applies to the
# JWS artifacts (a structural failure raises the artifact's signature-family
# code; see jws.parse_compact's `structural_code`). Flagged upstream as a
# candidate registry gap.
_MANIFEST_FIELDS = frozenset({
    "version", "aid", "display_name", "identity_hint", "handshake_endpoint",
    "accepted_trust_anchors", "offered_capabilities", "required_peer_capabilities",
    "accepted_identity_types", "accepted_signature_algorithms", "proof_of_possession",
    "published_at", "expires_at", "extensions", "signature",
})
_POP_FIELDS = frozenset({"challenge", "signature"})
# $defs/IdentityHint, reached through a `$ref` from the body's `identity_hint`
# -- also additionalProperties: false. It is optional, and handshake.py:79
# reads it, so leaving it open would have been a real hole behind an indirection.
_IDENTITY_HINT_FIELDS = frozenset({"type", "issuer", "subject", "public_key"})


def verify_manifest(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    man = inp["manifest"]
    reject_unknown_fields(man, _MANIFEST_FIELDS, code="MANIFEST_SIGNATURE_INVALID", what="manifest")
    reject_unknown_fields(
        man["proof_of_possession"], _POP_FIELDS, code="MANIFEST_SIGNATURE_INVALID", what="manifest.proof_of_possession"
    )
    if "identity_hint" in man:
        reject_unknown_fields(
            man["identity_hint"], _IDENTITY_HINT_FIELDS,
            code="MANIFEST_SIGNATURE_INVALID", what="manifest.identity_hint",
        )
    now = int(inp.get("now", now))
    supported = inp.get("supported_versions", ["aitp/0.2"])

    if man.get("version") not in supported:
        raise AitpError("MANIFEST_VERSION_UNKNOWN", f"unsupported version {man.get('version')!r}")
    if now >= int(man["expires_at"]):
        raise AitpError("MANIFEST_EXPIRED", "manifest expires_at is in the past")

    aid = parse_aid(man["aid"])

    pop = man["proof_of_possession"]
    pop_sig = decode_tagged_signature(pop["signature"], aid, sig_err="MANIFEST_POP_FAILED")
    if not aid.public_key.verify_digest(sha256(b64url_decode(pop["challenge"])), pop_sig):
        raise AitpError("MANIFEST_POP_FAILED", "proof-of-possession signature invalid")

    man_sig = decode_tagged_signature(man["signature"], aid, sig_err="MANIFEST_SIGNATURE_INVALID")
    body = {k: v for k, v in man.items() if k != "signature"}
    if not aid.public_key.verify_digest(sha256(canonicalize(body)), man_sig):
        raise AitpError("MANIFEST_SIGNATURE_INVALID", "manifest signature invalid")

    return {"aid": man["aid"]}
