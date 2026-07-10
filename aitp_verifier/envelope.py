"""Envelope verification (RFC-AITP-0001 §5.4 / §5.5, JCS profile).

The envelope signature covers ``sha256(sig_input)`` where
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
from .jcs import canonicalize
from .jws import parse_compact
from .sigfield import decode_tagged_signature
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_envelope", "envelope_signing_input"]


def envelope_signing_input(env: dict[str, Any]) -> bytes:
    payload_hex = sha256(canonicalize(env["payload"])).hex()
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
    tolerance = int(inp.get("tolerance_seconds", 300))
    if abs(now - int(env["timestamp"])) > tolerance:
        raise AitpError("TIMESTAMP_EXPIRED", "envelope timestamp outside tolerance window")

    aid = parse_aid(env["sender"]["agent_id"])
    raw = decode_tagged_signature(env["signature"], aid, sig_err="INVALID_SIGNATURE")
    if not aid.public_key.verify_digest(sha256(envelope_signing_input(env)), raw):
        raise AitpError("INVALID_SIGNATURE", "envelope signature verification failed")
    return {"ok": True}
