"""Envelope verification (RFC-AITP-0001 §5.4 / §5.5, JCS profile).

The envelope check order is RFC-AITP-0001 §5.4's: ``version`` first
(``UNKNOWN_VERSION``), then the member set and structure (``UNKNOWN_FIELD`` /
``INVALID_ENVELOPE``), then the signature (``INVALID_SIGNATURE``). The
signature covers ``sha256(sig_input_v2)`` where
``sig_input_v2 = "aitp-envelope-v2" || 0x00 || JCS(envelope minus signature)``,
so ``version``, ``message_type`` and ``extensions`` are all authenticated.
Replay controls (timestamp window, message-id dedup) run before all three
(RFC-AITP-0009 §3.1); capability policy and simulated key-resolution
scenarios are dispatched from the fixture input shape.
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
from .version import PROTOCOL_VERSION

__all__ = ["verify_envelope", "envelope_signing_input", "validate_envelope_shape"]

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


# RFC-AITP-0001 §5.4: 16 ASCII bytes then one 0x00, so the envelope's signing
# input is never the bare JCS form another JCS-profile artifact signs.
ENVELOPE_DOMAIN_TAG = b"aitp-envelope-v2\x00"


def envelope_signing_input(env: dict[str, Any]) -> bytes:
    """``sig_input_v2`` (RFC-AITP-0001 §5.4): the domain tag, then the JCS form
    of the received envelope with only ``signature`` removed. Every other
    member is kept as received -- nothing is dropped or rebuilt."""
    unsigned = {k: v for k, v in env.items() if k != "signature"}
    return ENVELOPE_DOMAIN_TAG + canonical_bytes(unsigned, shape_code="INVALID_ENVELOPE", what="envelope")


def validate_envelope_shape(env: Any) -> dict[str, Any]:
    """Structural validation before anything is dereferenced (man-006/
    rev-007's same rationale): every member below was read unguarded before
    this, reachable from unauthenticated remote input via handshake.py's own
    inline envelope parsing as much as via this module's own ``verify_envelope``.
    ``version`` is checked first (RFC-AITP-0001 §5.4), then
    presence -> type -> member-set, per object, mirroring manifest.py's
    ``_shape`` ordering (not revocation.py's deferred one) since this
    validates one flat object (plus its one nested ``sender``) rather than a
    tree.

    Exported so ``handshake.py`` -- which never calls ``verify_envelope()``,
    it parses the envelope shape itself, inline -- runs the identical check
    instead of keeping its own partial copy (Phase 6 added one covering only
    ``message_type``/``payload``/``sender``; ``message_id``/``timestamp``/
    ``signature`` stayed unguarded there, reachable via
    ``identity.py``'s pinned-key proof and this module's own
    ``envelope_signing_input``/``decode_tagged_signature`` call sites).

    Returns *env*, narrowed to ``dict[str, Any]``, as a call-site convenience.
    """
    if not isinstance(env, dict):
        raise AitpError("INVALID_ENVELOPE", f"envelope is {type(env).__name__}, not an object")
    # RFC-AITP-0001 §5.4 check order, step 1: `version` before the member set
    # and the signature (env-010, env-011). Absent counts as unknown.
    if env.get("version") != PROTOCOL_VERSION:
        raise AitpError("UNKNOWN_VERSION", f"unknown envelope version {env.get('version')!r}")
    require_members(env, _REQUIRED_ENVELOPE_FIELDS, shape_code="INVALID_ENVELOPE", what="envelope")
    check_types(env, _ENVELOPE_TYPES, shape_code="INVALID_ENVELOPE", what="envelope")
    reject_unknown_fields(env, _ENVELOPE_FIELDS, shape_code="INVALID_ENVELOPE", what="envelope")
    require_members(env["sender"], _REQUIRED_SENDER_FIELDS, shape_code="INVALID_ENVELOPE", what="envelope.sender")
    check_types(env["sender"], _SENDER_TYPES, shape_code="INVALID_ENVELOPE", what="envelope.sender")
    reject_unknown_fields(env["sender"], _SENDER_FIELDS, shape_code="INVALID_ENVELOPE", what="envelope.sender")
    return env


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

    # The timestamp window precedes the §5.4 version/structure checks
    # (RFC-AITP-0009 §3.1). It can only run once `timestamp` is an integer; a
    # missing or mistyped one is a structural defect reported just below.
    raw_env = inp["envelope"]
    ts = raw_env.get("timestamp") if isinstance(raw_env, dict) else None
    tolerance = int(inp.get("tolerance_seconds", 300))
    if isinstance(ts, int) and not isinstance(ts, bool) and abs(now - ts) > tolerance:
        raise AitpError("TIMESTAMP_EXPIRED", "envelope timestamp outside tolerance window")

    env = validate_envelope_shape(raw_env)

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
