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
import time
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
        "version": "aitp/0.3",
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
        "version": "aitp/0.3",
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
        "version": "aitp/0.3",
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


def test_manifest_empty_pop_challenge_is_rejected_as_structural(spec_dir: Path) -> None:
    """The schema's `challenge` is exactly 22 base64url chars, so an empty one
    is a grammar defect: `MANIFEST_INVALID`, with the PoP step never reached.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["proof_of_possession"]["challenge"] = ""
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


# ── §5 step 2: every member's grammar (aitp-manifest.schema.json) ─────────
#
# Each bad value is minted INTO the signed body wherever minting allows, so the
# Manifest carries a valid PoP and signature and the grammar check is the only
# thing that can reject it.

_CAPABILITY_BAD = [[""], ["a b"], ["a\tb"], ["a\n"], ["a\u00a0b"], ["a\ufeff"], ["a", "a"], [1], [None]]
_URI_BAD = ["", "no-scheme", "not a uri", "https://a b", "https://a\n", "https://[zz]/", "https://[::1%25eth0]/",
            "https://a/%zz", "https://a#b#c", "https://h:port/", "https://\u00e9.example", "1https://a"]
_SIG_BAD = ["", "short", "A" * 85, "A" * 87, "A" * 86 + "\n", "rsa." + "A" * 86, "ed25519." + "A" * 85, "A" * 85 + "="]

_REJECTED_MEMBERS: list[tuple[str, Any]] = [
    *[("accepted_signature_algorithms", v) for v in (
        ["EdDSA"], ["ES256"], ["ED25519"], [""], ["ed25519", "ed25519"], ["ed25519", "p256", "p256"], [1],
    )],
    *[("accepted_identity_types", v) for v in (["x509"], ["OIDC"], [""], ["oidc", "oidc"], [1])],
    *[("offered_capabilities", v) for v in _CAPABILITY_BAD],
    *[("required_peer_capabilities", v) for v in _CAPABILITY_BAD],
    *[("accepted_trust_anchors", [v]) for v in _URI_BAD],
    ("accepted_trust_anchors", ["https://a.example", "https://a.example"]),
    ("accepted_trust_anchors", [1]),
    *[("handshake_endpoint", v) for v in _URI_BAD],
    *[("handshake_endpoint", v) for v in ("http://a.example", "HTTPS://a.example", "ftp://a.example", "urn:a:b")],
    ("display_name", "x" * 129),
    ("published_at", -1),
    ("expires_at", 0),
    ("expires_at", -1),
]


@pytest.mark.parametrize(("member", "value"), _REJECTED_MEMBERS)
def test_manifest_member_outside_grammar_rejected(member: str, value: Any, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(**{member: value}), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


@pytest.mark.parametrize("value", ["", "no-scheme", "not a uri", "https://a b"])
def test_manifest_identity_hint_issuer_outside_uri_grammar_rejected(value: str, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    hint = {"type": "oidc", "issuer": value, "subject": "agent"}
    minted = mint_input(_manifest_input(identity_hint=hint), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_identity_hint_empty_subject_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    hint = {"type": "oidc", "issuer": "https://auth.example", "subject": ""}
    minted = mint_input(_manifest_input(identity_hint=hint), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_identity_hint_public_key_trailing_newline_rejected(spec_dir: Path) -> None:
    """The schema's `$` is ECMA-262's, the end of the string; Python's `$` also
    matches before a final newline.
    """
    keys = load_kat_keys(spec_dir)
    hint = {"type": "pinned_key", "subject": "agent", "public_key": SUBJECT.split(":")[-1] + "\n"}
    minted = mint_input(_manifest_input(identity_hint=hint), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


@pytest.mark.parametrize("aid", [
    SUBJECT + "\n", "aid:pubkey:short", "aid:web:example.com", "did:pubkey:x",
    "aid:pubkey:p256:" + "A" * 43, "aid:pubkey:ed25519:" + "A" * 44, "aid:pubkey:" + "=" * 43,
])
def test_manifest_aid_outside_pattern_rejected(aid: str, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["aid"] = aid
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


@pytest.mark.parametrize("challenge", ["E1P1xitRfiKsGDoeyKCI0", "E1P1xitRfiKsGDoeyKCI0wA", "E1P1xitRfiKsGDoeyKCI0w\n"])
def test_manifest_pop_challenge_wrong_length_rejected(challenge: str, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["proof_of_possession"]["challenge"] = challenge
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


@pytest.mark.parametrize("signature", _SIG_BAD)
def test_manifest_signature_outside_pattern_is_structural(signature: str, spec_dir: Path) -> None:
    """The registry: a value outside its grammar MUST NOT be reported as
    `MANIFEST_SIGNATURE_INVALID`, because the signature was never reached.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["signature"] = signature
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


@pytest.mark.parametrize("signature", _SIG_BAD)
def test_manifest_pop_signature_outside_pattern_is_structural(signature: str, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["proof_of_possession"]["signature"] = signature
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_signature_tag_mismatch_stays_a_signature_failure(spec_dir: Path) -> None:
    """Inside the schema's pattern, so §5 step 2 passes it on: a `p256.` tag under
    an Ed25519 AID is the signature step's rejection (RFC-AITP-0001 §5.4.3 rule 3).
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"]["signature"] = "p256." + "A" * 86
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_SIGNATURE_INVALID"


@pytest.mark.parametrize(("member", "value"), [
    ("display_name", ""),
    ("display_name", "x" * 128),
    ("display_name", "\U0001f600" * 128),
    ("accepted_signature_algorithms", []),
    ("accepted_signature_algorithms", ["ed25519"]),
    ("accepted_signature_algorithms", ["p256", "ed25519"]),
    ("accepted_identity_types", []),
    ("accepted_identity_types", ["oidc", "pinned_key", "spiffe"]),
    ("offered_capabilities", []),
    ("offered_capabilities", ["macp.mode.task.v1", "read_data", "a:b/c?d", "caf\u00e9"]),
    # Outside ECMA-262's `\s`, though Python's `\s` includes both and excludes U+FEFF.
    ("offered_capabilities", ["a\x85", "b\x1c"]),
    ("required_peer_capabilities", []),
    ("required_peer_capabilities", ["read_data"]),
    ("accepted_trust_anchors", ["https://auth.example", "https://auth.example/", "urn:example:a", "mailto:a@b.example"]),
    ("accepted_trust_anchors", ["https://[::1]:8443/x", "https://[v1.a]/", "https://u:p@a.example/%41?q=/?#f", "a:"]),
    ("handshake_endpoint", "https://a.example"),
    ("handshake_endpoint", "https://a.example:8443/aitp/handshake?x=1#f"),
    ("handshake_endpoint", "https://[::1]:8443/"),
    ("published_at", 0),
    ("published_at", float(NOW)),
    # Inside `extensions`, unknown keys and their values are never inspected.
    ("extensions", {"accepted_signature_algorithms": ["EdDSA"], "offered_capabilities": ["a a", "a a"]}),
])
def test_manifest_member_inside_grammar_accepted(member: str, value: Any, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(**{member: value}), REFERENCE_CLOCK, keys)
    assert verify_manifest(minted) == {"aid": SUBJECT}


def test_manifest_uri_check_cost_is_bounded(spec_dir: Path) -> None:
    """A long value fails in time proportional to its length."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    start = time.monotonic()
    for value in ("a:" + "%41" * 200_000 + " ", "a://" + "u" * 500_000 + " ", "a:" + "/a" * 200_000 + " "):
        minted["manifest"]["accepted_trust_anchors"] = [value]
        with pytest.raises(AitpError) as exc:
            verify_manifest(minted)
        assert exc.value.code == "MANIFEST_INVALID"
    assert time.monotonic() - start < 5


# ── §5 order around the grammar check ─────────────────────────────────────


def test_manifest_grammar_runs_before_expiry(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input(accepted_signature_algorithms=["EdDSA"], expires_at=NOW - 1)
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_aid_pattern_runs_before_expiry(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(expires_at=NOW - 1), REFERENCE_CLOCK, keys)
    minted["manifest"]["aid"] = "aid:pubkey:short"
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_version_check_runs_before_grammar(spec_dir: Path) -> None:
    """§5 step 1 precedes step 2, for a well-typed `version`."""
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input(version="aitp/9.9", accepted_signature_algorithms=["EdDSA"])
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_VERSION_UNKNOWN"


@pytest.mark.parametrize("defect", [
    {"accepted_signature_algorithms": ["EdDSA"]},
    {"handshake_endpoint": "http://a.example"},
    {"identity_hint": {"type": "oidc", "subject": "agent"}},
    {"identity_hint": {"type": "oidc", "issuer": "https://auth.example", "subject": ""}},
])
def test_manifest_grammar_defect_outranks_unknown_member(defect: dict[str, Any], spec_dir: Path) -> None:
    """`UNKNOWN_FIELD` is the code only when the unknown member is the ONLY defect."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(routing_hint="x", **defect), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


@pytest.mark.parametrize("nested", ["proof_of_possession", "identity_hint"])
def test_manifest_grammar_defect_outranks_nested_unknown_member(nested: str, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input(accepted_signature_algorithms=["EdDSA"])
    inp["manifest"][nested]["routing_hint"] = "x"
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_grammar_defect_rejected_via_handshake(spec_dir: Path) -> None:
    """An inline Manifest in a `mutual_hello` gets the same grammar check."""
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    inp["envelope"]["payload"]["manifest"]["accepted_signature_algorithms"] = ["EdDSA"]
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "MANIFEST_INVALID"
