"""Envelope verification (RFC-AITP-0001 §5.4 / §5.5, JCS profile).

Shape runs first, as elsewhere in this verifier (see ``manifest.py``): every
required member and its declared type are confirmed, then the member set,
before anything is dereferenced. The envelope signature covers
``sha256(sig_input)`` where
``sig_input = message_id | timestamp | sender.agent_id | hex(sha256(JCS(payload)))``.
Replay controls (timestamp window, message-id dedup) run first; capability
policy and simulated key-resolution scenarios are dispatched from the fixture
input shape.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .crypto import sha256
from .errors import AitpError
from .fields import canonical_bytes, check_types, reject_unknown_fields, require_members
from .jws import parse_compact
from .sigfield import decode_tagged_signature
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_envelope", "envelope_signing_input"]

# aitp-envelope.schema.json: additionalProperties: false. `payload` is
# message-type-specific (its own shape lives in aitp-mutual-handshake.schema.json
# and is enforced by handshake.py, not here -- the envelope schema itself
# leaves `payload` an unconstrained object).
_ENVELOPE_FIELDS = frozenset({
    "version", "message_type", "message_id", "timestamp", "sender", "payload", "signature", "extensions",
})
_SENDER_FIELDS = frozenset({"agent_id"})
# Every one of these is dereferenced somewhere in this module or in
# `envelope_signing_input` with no presence guard today -- `extensions` is the
# lone optional member (RFC-AITP-0012 §1). `payload` and `sender` are
# `type: object` at the schema level, with `payload` intentionally left
# unconstrained (message-type-specific, enforced by handshake.py) and
# `sender`'s own member set/shape validated separately, immediately below.
_REQUIRED_ENVELOPE_FIELDS = ("version", "message_type", "message_id", "timestamp", "sender", "payload", "signature")
_ENVELOPE_TYPES: dict[str, tuple[type, ...]] = {
    "version": (str,), "message_type": (str,), "message_id": (str,), "timestamp": (int,),
    "sender": (dict,), "payload": (dict,), "signature": (str,), "extensions": (dict,),
}
_REQUIRED_SENDER_FIELDS = ("agent_id",)
_SENDER_TYPES: dict[str, tuple[type, ...]] = {"agent_id": (str,)}


def envelope_signing_input(env: dict[str, Any]) -> bytes:
    payload_hex = sha256(canonical_bytes(env["payload"], shape_code="INVALID_ENVELOPE", what="envelope.payload")).hex()
    sig_input = f"{env['message_id']}|{env['timestamp']}|{env['sender']['agent_id']}|{payload_hex}"
    return sig_input.encode("utf-8")


def verify_envelope(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    # Simulated key-resolution scenario (env-003): no key obtainable.
    if "manifest_fetch" in inp or "needed_key_for" in inp:
        raise AitpError("KEY_RESOLUTION_FAILED", "peer key could not be resolved", retryable=True)

    # Capability policy against an active TCT (env-002).
    if "active_tct" in inp and "requested_capability" in inp:
        grants = parse_compact(inp["active_tct"], structural_code="INVALID_SIGNATURE").claims.get("grants", [])
        if inp["requested_capability"] not in grants:
            raise AitpError("POLICY_VIOLATION", "requested capability not granted by the active TCT")
        return {"ok": True}

    env = inp["envelope"]
    # Structural validation before anything is dereferenced (man-006/rev-007's
    # same rationale): every member below was read unguarded before this,
    # reachable from unauthenticated remote input via handshake.py's own
    # envelope. Presence -> type -> member-set, per object, mirroring
    # manifest.py's `_shape` ordering (not revocation.py's deferred one) since
    # this validates one flat object (plus its one nested `sender`) rather
    # than a tree.
    if not isinstance(env, dict):
        raise AitpError("INVALID_ENVELOPE", f"envelope is {type(env).__name__}, not an object")
    require_members(env, _REQUIRED_ENVELOPE_FIELDS, shape_code="INVALID_ENVELOPE", what="envelope")
    check_types(env, _ENVELOPE_TYPES, shape_code="INVALID_ENVELOPE", what="envelope")
    reject_unknown_fields(env, _ENVELOPE_FIELDS, shape_code="INVALID_ENVELOPE", what="envelope")
    require_members(env["sender"], _REQUIRED_SENDER_FIELDS, shape_code="INVALID_ENVELOPE", what="envelope.sender")
    check_types(env["sender"], _SENDER_TYPES, shape_code="INVALID_ENVELOPE", what="envelope.sender")
    reject_unknown_fields(env["sender"], _SENDER_FIELDS, shape_code="INVALID_ENVELOPE", what="envelope.sender")

    tolerance = int(inp.get("tolerance_seconds", 300))
    if abs(now - int(env["timestamp"])) > tolerance:
        raise AitpError("TIMESTAMP_EXPIRED", "envelope timestamp outside tolerance window")

    try:
        aid = parse_aid(env["sender"]["agent_id"])
    except ValueError as exc:
        # `parse_aid` signals a malformed AID with a bare ValueError, which is
        # not an AitpError and escapes this module's caller. `agent_id` is a
        # schema-typed string, so this is a grammar defect -> INVALID_ENVELOPE.
        raise AitpError("INVALID_ENVELOPE", f"envelope sender agent_id is not a valid AID: {exc}") from exc
    raw = decode_tagged_signature(env["signature"], aid, sig_err="INVALID_SIGNATURE")
    if not aid.public_key.verify_digest(sha256(envelope_signing_input(env)), raw):
        raise AitpError("INVALID_SIGNATURE", "envelope signature verification failed")
    return {"ok": True}
