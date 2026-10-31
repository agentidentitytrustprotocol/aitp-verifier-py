"""Operation registry — maps a fixture ``input.operation`` to a verifier.

An operation absent from this table is one this implementation does not yet
support; the conformance runner reports SKIP for it (never a silent pass),
exactly as PLACEHOLDERS.md §"Operation key" requires.
"""

from __future__ import annotations

from typing import Any, Callable

from . import delegation, envelope, handshake, manifest, revocation, sessionbundle, tct, voucher

__all__ = ["OPERATIONS", "REQUIRED_ARGUMENTS", "missing_argument", "invalid_argument", "supported"]

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
# Each alternative maps required names to JSON types. None delegates type
# validation to the operation when the wire protocol defines its own verdict.
REQUIRED_ARGUMENTS: dict[str, tuple[dict[str, str | None], ...]] = {
    "verify_envelope": ({"envelope": "object"},
                        {"active_tct": "string", "requested_capability": "string"},
                        {"manifest_fetch": "object"}, {"needed_key_for": "string"}),
    "verify_manifest": ({"manifest": "object"},),
    "verify_tct": ({"tct_token": "string"},),
    "verify_tct_as_issuer": ({"tct_token": "string", "self_aid": "string"},),
    "verify_attestation": ({"tct_token": "string", "expected_ext_key": "string"},),
    "verify_grant_voucher": ({"voucher_token": "string"},),
    # Non-string delegation_token is DELEGATION_INVALID_SIGNATURE, not a
    # malformed adapter call. del-004 uses the retired object-shaped token.
    "verify_delegation_token": ({"delegation_token": None}, {"delegation": "object"}),
    "verify_revocation_snapshot": ({"snapshot": "object"},),
    "verify_handshake_payload": ({"envelope": "object"}, {"peer_a": "object", "peer_b": "object"}),
    "verify_session_bundle": ({"self_aid": "string", "session_bundle": "object"},),
}


def missing_argument(operation: str, params: dict[str, Any]) -> str | None:
    """The first argument *params* lacks for *operation*, or ``None`` when one
    of its argument sets is complete. Of several incomplete sets, the one the
    request has begun (most arguments present, then fewest missing, then first
    listed) names it."""
    sets = REQUIRED_ARGUMENTS.get(operation, ({},))
    missing = [[a for a in names if a not in params] for names in sets]
    if any(not m for m in missing):
        return None
    best = min(range(len(sets)), key=lambda i: (len(missing[i]) - len(sets[i]), len(missing[i])))
    return missing[best][0]


def supported(operation: str) -> bool:
    return operation in OPERATIONS


def invalid_argument(operation: str, params: dict[str, Any]) -> str | None:
    """Describe the first wrong-typed required argument present in a request.

    Check all declared arguments that are present, including partial alternate
    sets, before the harness can interpret them. Nested wire values are left
    to their verifiers, as are entries explicitly marked None in the table.
    """
    json_types = {dict: "object", list: "array", str: "string", bool: "boolean",
                  int: "number", float: "number", type(None): "null"}
    for arguments in REQUIRED_ARGUMENTS.get(operation, ()):
        for name, expected in arguments.items():
            if name not in params or expected is None:
                continue
            actual = json_types.get(type(params[name]), "non-JSON value")
            if actual != expected:
                article = "an" if expected in ("object", "array") else "a"
                return f"argument {name!r} must be {article} {expected}, got {actual}"
    return None
