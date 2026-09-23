"""Manifest hardening (issue #23, items 1 "manifest.py" and 2).

Every verifier entry point's contract is "raise `AitpError` or return a
verdict" -- these pin the two `manifest.py` gaps that broke it on
remote-reachable input, both confirmed live against this repo before the fix:

* `canonicalize(body)` at the signature-verification step let a bare
  `JcsError` (a `ValueError`, not an `AitpError`) escape whenever the
  offending value sat inside `extensions` (§7 forbids inspecting that
  interior, so no member/type check can intercept it) or in a numeric field
  wide enough that JCS refuses to serialize it.
* `proof_of_possession.challenge`'s base64url *grammar* (not just its `str`
  type) was never validated before `b64url_decode`, so `"x"` or `"a:b"`
  reached it unguarded and raised `binascii.Error`/`ValueError`.

Both are reproduced two ways: directly against `verify_manifest`, and through
`verify_handshake_payload` on a self-signed `mutual_hello` -- `handshake.py`
feeds a peer's inline manifest straight into `verify_manifest` with no guard
of its own, so the remote path is the one the issue was actually filed
against.

Minting note: hostile values here are injected *after* `mint_input` mints a
well-formed fixture, never passed through minting itself. `mint_input`
canonicalizes/`b64url_decode`s the same fields while producing a valid
signature (`minter.py::_sign_manifest`), so a hostile value present at mint
time raises there instead of inside the code under test.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.b64 import b64url_encode
from aitp_verifier.errors import AitpError
from aitp_verifier.handshake import verify_handshake_payload
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.manifest import verify_manifest
from aitp_verifier.minter import mint_input
from aitp_verifier.timeutil import REFERENCE_CLOCK

NOW = REFERENCE_CLOCK

# Pinned KAT AIDs (schemas/conformance/known-answer/keypairs.json), reused
# byte-for-byte from tests/test_unknown_fields.py so no new key material needs
# pinning: kat-keypair-001 (Ed25519), kat-keypair-002 (Ed25519).
ISSUER = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
SUBJECT = "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"


def _manifest_input(**body_extra: Any) -> dict[str, Any]:
    man = {
        "version": "aitp/0.2",
        "aid": SUBJECT,
        "handshake_endpoint": "https://b.agents.example.com/aitp/handshake",
        "accepted_trust_anchors": [],
        "offered_capabilities": ["macp.mode.task.v1"],
        "required_peer_capabilities": [],
        "proof_of_possession": {"challenge": b64url_encode(b"\x11" * 16), "signature": "__VALID_POP_SIG__"},
        "published_at": NOW,
        "expires_at": NOW + 86400,
        "identity_hint": {"type": "oidc", "issuer": "https://auth.example", "subject": "agent"},
        "signature": "__VALID_MANIFEST_SIG__",
    }
    man.update(body_extra)
    return {"manifest": man, "now": NOW}


def _hello_input(self_aid: str, sender_aid: str) -> dict[str, Any]:
    """A minimal self-signed `mutual_hello` carrying `sender_aid`'s own
    inline manifest -- the exact remote path issue #23 was filed against.
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


# ── JcsError must not escape (issue #23 item 1, manifest.py) ──────────────


def test_manifest_infinite_extension_value_does_not_crash(spec_dir: Path) -> None:
    """`json.loads("1e400")` returns `float("inf")` from ordinary valid JSON.
    §7 forbids inspecting `extensions`' interior, so no member/type check can
    catch this -- only the `canonicalize` call itself can.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(extensions={"a": 1}), REFERENCE_CLOCK, keys)
    minted["manifest"]["extensions"] = {"x": json.loads("1e400")}
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_huge_published_at_does_not_crash(spec_dir: Path) -> None:
    """A 400-digit integer is a valid Python/JSON `int`, so it passes
    `check_types` -- only JCS's own representable-range check catches it.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["published_at"] = json.loads("1" + "0" * 400)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_infinite_extension_value_does_not_crash_via_handshake(spec_dir: Path) -> None:
    """The end-to-end remote path: a peer's self-signed `mutual_hello` inline
    manifest, fed straight into `verify_manifest` by `handshake.py` with no
    guard of its own.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_hello_input(ISSUER, SUBJECT), REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"]["manifest"]["extensions"] = {"x": json.loads("1e400")}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "MANIFEST_INVALID"


# ── PoP challenge base64url grammar (issue #23 item 2, manifest.py) ───────


@pytest.mark.parametrize("challenge", ["x", "a:b", "not_base64!"])
def test_manifest_malformed_pop_challenge_does_not_crash(challenge: str, spec_dir: Path) -> None:
    """A challenge outside base64url's alphabet or length grammar must raise
    `MANIFEST_INVALID` (a structural defect -- the PoP signature step is never
    reached), not `binascii.Error`/`ValueError` from an unguarded
    `b64url_decode`.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["proof_of_possession"]["challenge"] = challenge
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_malformed_pop_challenge_does_not_crash_via_handshake(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_hello_input(ISSUER, SUBJECT), REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"]["manifest"]["proof_of_possession"]["challenge"] = "a:b"
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_empty_pop_challenge_is_grammatically_valid(spec_dir: Path) -> None:
    """`b64url_decode("")` succeeds (decodes to `b""`) -- an empty challenge is
    NOT a grammar defect, so it must reach the PoP signature comparison
    (and fail there, as an ordinary crypto mismatch) rather than being
    rejected as MANIFEST_INVALID.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["proof_of_possession"]["challenge"] = ""
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_POP_FAILED"
