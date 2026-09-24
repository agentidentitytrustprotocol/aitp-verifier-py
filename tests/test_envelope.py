"""Envelope hardening (issue #23, item 1 "envelope.py", plus adjacent
completeness gaps).

Before this phase, `envelope.py` had `reject_unknown_fields` only -- no
required-member or type validation at all -- so every direct dereference
(`env["timestamp"]`, `env["sender"]["agent_id"]`, ...) was one malformed
remote input away from a raw `KeyError`/`TypeError`/`ValueError` escaping
past a caller's `except AitpError`. `canonicalize(env["payload"])` in
`envelope_signing_input` also let a bare `JcsError` escape, for both of its
callers -- `verify_envelope` itself and `handshake.py::_verify_bootstrap` --
reproduced here for both.

Minting note, same as `test_manifest.py`: hostile values are injected
*after* `mint_input` mints a well-formed fixture, never passed through
minting itself. `minter.py::_sign_envelope` canonicalizes `env["payload"]`
and looks up `keys[env["sender"]["agent_id"]]` while producing a valid
signature, so a hostile value present at mint time raises there (or
`KeyError`s on an unregistered AID) instead of in the code under test.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.b64 import b64url_encode
from aitp_verifier.envelope import verify_envelope
from aitp_verifier.errors import AitpError
from aitp_verifier.handshake import verify_handshake_payload
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.minter import mint_input
from aitp_verifier.timeutil import REFERENCE_CLOCK

NOW = REFERENCE_CLOCK

# Pinned KAT AIDs, reused byte-for-byte from tests/test_unknown_fields.py /
# tests/test_manifest.py so no new key material needs pinning.
ISSUER = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
SUBJECT = "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"


def _deep_dict(n: int, leaf: Any = 1) -> Any:
    """*n* nested `dict` levels around a scalar leaf -- the same helper shape
    `tests/test_fields.py` pins the exact `jcs` depth boundary against. Here it
    is only ever used far past that boundary (2000), so no counting convention
    is load-bearing: what matters is that 2000 is deep enough to exhaust the
    interpreter's own stack, which is how issue #31 surfaced.
    """
    value: Any = leaf
    for _ in range(n):
        value = {"a": value}
    return value


def _envelope_input(**env_extra: Any) -> dict[str, Any]:
    env = {
        "version": "aitp/0.2",
        "message_type": "mutual_hello",
        "message_id": str(uuid.uuid4()),
        "timestamp": NOW,
        "sender": {"agent_id": SUBJECT},
        "payload": {"hello": True},
        "signature": "__VALID_ENVELOPE_SIG__",
    }
    env.update(env_extra)
    return {"self_aid": ISSUER, "tolerance_seconds": 300, "envelope": env}


def _hello_input(self_aid: str, sender_aid: str) -> dict[str, Any]:
    """A minimal self-signed `mutual_hello` -- the remote path
    `envelope_signing_input`'s second caller (`handshake.py`) exercises.
    """
    bare_key = sender_aid.split(":")[-1]
    manifest = {
        "version": "aitp/0.2",
        "aid": sender_aid,
        "handshake_endpoint": "https://x.example/handshake",
        "accepted_trust_anchors": [],
        "accepted_identity_types": ["pinned_key"],
        "offered_capabilities": ["macp.mode.task.v1"],
        "required_peer_capabilities": [],
        "proof_of_possession": {"challenge": b64url_encode(b"\x22" * 16), "signature": "__VALID_POP_SIG__"},
        "published_at": NOW,
        "expires_at": NOW + 86400,
        "identity_hint": {"type": "pinned_key", "subject": "worker", "public_key": bare_key},
        "signature": "__VALID_MANIFEST_SIG__",
    }
    payload = {
        "identity": {"type": "pinned_key", "subject": "worker", "public_key": bare_key, "proof": "__VALID_PINNED_PROOF__"},
        "manifest": manifest,
        "requested_grants": ["macp.mode.task.v1"],
        "pop_nonce": b64url_encode(b"\x33" * 16),
        "extensions": {"a": 1},
    }
    env = {
        "version": "aitp/0.2",
        "message_type": "mutual_hello",
        "message_id": str(uuid.uuid4()),
        "timestamp": NOW,
        "sender": {"agent_id": sender_aid},
        "payload": payload,
        "signature": "__VALID_ENVELOPE_SIG__",
    }
    return {"self_aid": self_aid, "trust_store": [sender_aid], "envelope": env}


# ── required-member / type validation (previously entirely absent) ────────


@pytest.mark.parametrize("dropped", [
    "version", "message_type", "message_id", "timestamp", "sender", "payload", "signature",
])
def test_envelope_every_required_member_is_enforced(dropped: str, spec_dir: Path) -> None:
    """Each schema `required` member is independently pinned -- before this
    phase, dropping any of these raised a raw `KeyError` from this module's
    own direct dereference or from `envelope_signing_input`.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    assert verify_envelope(minted) == {"ok": True}

    del minted["envelope"][dropped]
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"
    assert dropped in exc.value.message


@pytest.mark.parametrize(("member", "value"), [
    ("message_id", 5),
    ("sender", "not-an-object"),
    ("sender", None),
    ("payload", []),
    ("signature", 5),
])
def test_envelope_mistyped_member_is_a_structural_rejection(member: str, value: Any, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    minted["envelope"][member] = value
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_envelope_sender_missing_agent_id_is_enforced(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    del minted["envelope"]["sender"]["agent_id"]
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


# ── JcsError must not escape (issue #23 item 1, envelope.py) ──────────────


def test_envelope_infinite_payload_value_does_not_crash(spec_dir: Path) -> None:
    """`json.loads("1e400")` returns `float("inf")` from ordinary valid JSON;
    `payload` is intentionally unconstrained (message-type-specific), so no
    member/type check can catch a hostile value inside it -- only the
    `canonicalize` call itself can.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"] = {"x": json.loads("1e400")}
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_envelope_huge_int_payload_value_does_not_crash(spec_dir: Path) -> None:
    """A 400-digit integer is valid JSON but outside JCS's representable range."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"] = {"x": json.loads("1" + "0" * 400)}
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_envelope_infinite_payload_value_does_not_crash_via_handshake(spec_dir: Path) -> None:
    """The end-to-end remote path: `handshake.py::_verify_bootstrap` calls
    `envelope_signing_input` (the shared function) after manifest/identity
    verification already succeeded -- so this exercises the SECOND of its
    two callers, not just `verify_envelope`'s own.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_hello_input(ISSUER, SUBJECT), REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"]["extensions"] = {"x": json.loads("1e400")}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_envelope_huge_int_payload_value_does_not_crash_via_handshake(spec_dir: Path) -> None:
    """The huge-int variant of the test above -- a distinct JCS hazard
    (`jcs.py`'s IEEE-754-range check vs. its non-finite-value check) reaching
    the same `envelope_signing_input` call inside `handshake.py`.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_hello_input(ISSUER, SUBJECT), REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"]["extensions"] = {"x": json.loads("1" + "0" * 400)}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


# ── nesting depth must not escape either (issue #31) ──────────────────────


def test_envelope_deeply_nested_payload_value_does_not_crash(spec_dir: Path) -> None:
    """A 2000-deep value is ordinary valid JSON that any peer can send, and
    `payload` is intentionally unconstrained -- so before `jcs.py`'s depth cap
    this escaped `verify_envelope` as a raw `RecursionError`, past the
    `except AitpError` every caller's contract says is sufficient.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"] = {"x": _deep_dict(2000)}
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_envelope_deeply_nested_payload_value_does_not_crash_via_handshake(spec_dir: Path) -> None:
    """The same hazard through `envelope_signing_input`'s SECOND caller,
    `handshake.py::_verify_bootstrap`, with the deep value inside `extensions`
    -- the member RFC-AITP-0001 §7 forbids inspecting, and therefore the one
    place nothing upstream of `canonicalize` could ever have caught it.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_hello_input(ISSUER, SUBJECT), REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"]["extensions"] = {"x": _deep_dict(2000)}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


# ── timestamp type/magnitude hazards ────────────────────────────────────────


def test_envelope_timestamp_as_string_does_not_crash(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    minted["envelope"]["timestamp"] = "not a number"
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_envelope_infinite_timestamp_does_not_crash(spec_dir: Path) -> None:
    """`int(float("inf"))` raises `OverflowError` -- neither `TypeError` nor
    `ValueError` -- so the type table must reject the float BEFORE
    `int(env["timestamp"])` in the tolerance-window check ever runs.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    minted["envelope"]["timestamp"] = json.loads("1e400")
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_envelope_huge_integer_timestamp_is_a_timestamp_rejection_not_a_crash(spec_dir: Path) -> None:
    """A 400-digit Python int has no overflow, so it passes the type table --
    it must reach the tolerance-window comparison and fail there
    (`TIMESTAMP_EXPIRED`), not crash, and not be misreported as
    `INVALID_ENVELOPE` (the type table's job is admitting-or-rejecting the
    JSON type, not judging magnitude).
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    minted["envelope"]["timestamp"] = json.loads("1" + "0" * 400)
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "TIMESTAMP_EXPIRED"


# ── malformed sender.agent_id (issue #23, adjacent completeness) ──────────


def test_envelope_malformed_sender_agent_id_does_not_crash(spec_dir: Path) -> None:
    """`parse_aid` signals a malformed AID with a bare `ValueError`, which is
    not an `AitpError` -- must be caught and reported as `INVALID_ENVELOPE`.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(), REFERENCE_CLOCK, keys)
    minted["envelope"]["sender"]["agent_id"] = "not-an-aid"
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "INVALID_ENVELOPE"
