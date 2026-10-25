"""Operation registry — maps a fixture ``input.operation`` to a verifier.

An operation absent from this table is one this implementation does not yet
support; the conformance runner reports SKIP for it (never a silent pass),
exactly as PLACEHOLDERS.md §"Operation key" requires.
"""

from __future__ import annotations

from typing import Any, Callable

from . import delegation, envelope, handshake, manifest, revocation, sessionbundle, tct, voucher

__all__ = ["OPERATIONS", "REQUIRED_ARGUMENTS", "missing_argument", "supported"]

Verifier = Callable[..., dict[str, Any]]

OPERATIONS: dict[str, Verifier] = {
    "verify_envelope": envelope.verify_envelope,
    "verify_manifest": manifest.verify_manifest,
    "verify_tct": tct.verify_tct,
    "verify_tct_as_issuer": tct.verify_tct_as_issuer,
    "verify_attestation": tct.verify_attestation,
    "verify_grant_voucher": voucher.verify_grant_voucher,
    "verify_delegation_token": delegation.verify_delegation_token,
    "verify_revocation_snapshot": revocation.verify_revocation_snapshot,
    "verify_handshake_payload": handshake.verify_handshake_payload,
    "verify_session_bundle": sessionbundle.verify_session_bundle,
}

# The top-level arguments each operation reads unconditionally, as the
# alternative argument sets it accepts: a request must carry every name in at
# least one set. Only the adapter checks this table; for a direct Python
# caller a missing key stays a calling-convention defect (``KeyError``).
REQUIRED_ARGUMENTS: dict[str, tuple[tuple[str, ...], ...]] = {
    # env-002 checks a capability against an active TCT and env-003 simulates
    # a failed key resolution; neither carries an envelope.
    "verify_envelope": (("envelope",), ("active_tct", "requested_capability"), ("manifest_fetch",), ("needed_key_for",)),
    "verify_manifest": (("manifest",),),
    "verify_tct": (("tct_token",),),
    "verify_tct_as_issuer": (("tct_token", "self_aid"),),
    "verify_attestation": (("tct_token", "expected_ext_key"),),
    "verify_grant_voucher": (("voucher_token",),),
    # del-004 sends the retired v0.1 object token as `delegation`.
    "verify_delegation_token": (("delegation_token",), ("delegation",)),
    "verify_revocation_snapshot": (("snapshot",),),
    "verify_handshake_payload": (("envelope",), ("peer_a", "peer_b")),
    "verify_session_bundle": (("self_aid", "session_bundle"),),
}


def missing_argument(operation: str, params: dict[str, Any]) -> str | None:
    """The first argument *params* lacks for *operation*, or ``None`` when one
    of its argument sets is complete. Of several incomplete sets, the one the
    request has begun (most arguments present, then fewest missing, then first
    listed) names it."""
    sets = REQUIRED_ARGUMENTS.get(operation, ((),))
    missing = [[a for a in names if a not in params] for names in sets]
    if any(not m for m in missing):
        return None
    best = min(range(len(sets)), key=lambda i: (len(missing[i]) - len(sets[i]), len(missing[i])))
    return missing[best][0]


def supported(operation: str) -> bool:
    return operation in OPERATIONS
