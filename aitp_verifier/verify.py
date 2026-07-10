"""Operation registry — maps a fixture ``input.operation`` to a verifier.

An operation absent from this table is one this implementation does not yet
support; the conformance runner reports SKIP for it (never a silent pass),
exactly as PLACEHOLDERS.md §"Operation key" requires.
"""

from __future__ import annotations

from typing import Any, Callable

from . import delegation, envelope, handshake, manifest, revocation, sessionbundle, tct, voucher

__all__ = ["OPERATIONS", "supported"]

Verifier = Callable[..., dict[str, Any]]

OPERATIONS: dict[str, Verifier] = {
    "verify_envelope": envelope.verify_envelope,
    "verify_manifest": manifest.verify_manifest,
    "verify_tct": tct.verify_tct,
    "verify_grant_voucher": voucher.verify_grant_voucher,
    "verify_delegation_token": delegation.verify_delegation_token,
    "verify_revocation_snapshot": revocation.verify_revocation_snapshot,
    "verify_handshake_payload": handshake.verify_handshake_payload,
    "verify_session_bundle": sessionbundle.verify_session_bundle,
}


def supported(operation: str) -> bool:
    return operation in OPERATIONS
