"""RFC-AITP-0001 §7 unknown-field rejection, pinned per artifact.

    "Unknown JSON fields outside explicit `extensions` namespaces MUST be
    rejected. ... Forward compatibility is provided exclusively through
    explicit `extensions` objects (see RFC-AITP-0012) ... unknown keys
    *inside* `extensions` MUST be ignored."

Every case below pins BOTH directions of the asymmetry directly against the
verifier functions, independently of the conformance pack (which only pins
one direction, ``bundle-005-extensions-accepted``, for one artifact):

* a member outside the schema's allowed set is rejected with the core
  ``UNKNOWN_FIELD`` code -- one code for every signed AITP object, JCS-profile
  and compact-JWS alike, never the artifact's own signature-family code;
* a member INSIDE the artifact's reserved ``extensions``/``ext`` slot,
  carrying an unrecognized key, does not affect the outcome.

For every JCS-signed or compact-JWS artifact here, the extra/unknown field is
inserted *before* minting -- the minter signs whatever is present, so the
resulting signature is self-consistent either way. That is what makes the
"unknown field rejected" cases meaningful rather than tautological: the
token/body is validly signed; ``reject_unknown_fields`` is the only thing
standing between it and acceptance. Without shape running before signature
verification (JCS artifacts) or as a mandatory post-verification claims check
(compact-JWS artifacts), these fixtures would sail through as ``success``.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.b64 import b64url_encode
from aitp_verifier.delegation import verify_delegation_token
from aitp_verifier.envelope import verify_envelope
from aitp_verifier.errors import AitpError
from aitp_verifier.fields import reject_unknown_fields
from aitp_verifier.handshake import verify_handshake_payload
from aitp_verifier.jwk import thumbprint_for_aid
from aitp_verifier.jws import encode_jws
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.manifest import verify_manifest
from aitp_verifier.minter import mint_input
from aitp_verifier.revocation import verify_revocation_snapshot
from aitp_verifier.tct import verify_tct
from aitp_verifier.timeutil import REFERENCE_CLOCK
from aitp_verifier.voucher import verify_grant_voucher

NOW = REFERENCE_CLOCK

# Pinned KAT AIDs (schemas/conformance/known-answer/keypairs.json), reused
# byte-for-byte from the conformance fixtures elsewhere in this repo so no
# new key material needs pinning: kat-keypair-001 (Ed25519), kat-keypair-002
# (Ed25519), kat-keypair-003 (Ed25519).
ISSUER = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
SUBJECT = "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
DELEGATE = "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU"


# ── the helper itself ────────────────────────────────────────────────────


def test_reject_unknown_fields_asymmetry() -> None:
    """The core asymmetry, independent of any artifact: a member outside
    *allowed* is rejected; a reserved extension member's presence is fine
    regardless of what is inside it (contents are never inspected).
    """
    allowed = frozenset({"a", "b", "extensions"})
    reject_unknown_fields({"a": 1, "b": 2}, allowed, shape_code="X", what="obj")  # no raise
    reject_unknown_fields({"a": 1, "extensions": {"anything": "at all"}}, allowed, shape_code="X", what="obj")  # no raise

    with pytest.raises(AitpError) as exc:
        reject_unknown_fields({"a": 1, "c": 3}, allowed, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "UNKNOWN_FIELD"
    assert "c" in exc.value.message

    # A key literally named "extensions" is only special if the caller put it
    # in *allowed* -- this is what makes the handshake IdentityDescriptor
    # (which has no extensions slot at all) correctly reject one.
    with pytest.raises(AitpError):
        reject_unknown_fields({"a": 1, "extensions": {}}, frozenset({"a", "b"}), shape_code="X", what="obj")


def test_unknown_field_code_is_not_the_callers_to_choose() -> None:
    """§7 has ONE core code for every signed object, so *shape_code* must not
    reach the unknown-member path.

    The assertion above would still pass if `shape_code` were merely renamed
    and still used for both branches -- "MY_CODE" would just have to become
    "UNKNOWN_FIELD" at every call site, and a single site left behind would
    silently emit the wrong code. Passing a deliberately wrong `shape_code`
    here proves the code is hard-coded in the helper rather than threaded
    through, which is what makes divergence across the twenty-four call sites
    impossible rather than merely unlikely.
    """
    with pytest.raises(AitpError) as exc:
        reject_unknown_fields({"c": 3}, frozenset({"a"}), shape_code="DEFINITELY_NOT_THIS", what="obj")
    assert exc.value.code == "UNKNOWN_FIELD"


def test_reject_unknown_fields_tolerates_non_str_keys() -> None:
    """A caller feeding a raw (non-JSON-parsed) dict with mixed key types
    must not crash with TypeError out of a bare ``sorted()`` -- the whole
    point of this gate is to turn malformed input into AitpError, not into a
    traceback.
    """
    with pytest.raises(AitpError):
        reject_unknown_fields({"a": 1, 2: "y"}, frozenset({"a"}), shape_code="X", what="obj")


# ── TCT claims (tct.py, and the same claim shape reused in handshake.py /
#    sessionbundle.py) ────────────────────────────────────────────────────


def _tct_claims(**overrides: Any) -> dict[str, Any]:
    base = {
        "ver": "aitp/0.2",
        "jti": str(uuid.uuid4()),
        "iss": ISSUER,
        "sub": SUBJECT,
        "aud": SUBJECT,
        "iat": NOW,
        "exp": NOW + 3600,
        "grants": ["macp.mode.task.v1"],
        "cnf": {"jkt": thumbprint_for_aid(SUBJECT)},
    }
    base.update(overrides)
    return base


def test_tct_unknown_claim_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    claims = _tct_claims(routing_hint="https://attacker.example/relay")
    token = encode_jws("aitp-tct+jwt", claims, keys[ISSUER], alg="EdDSA")
    with pytest.raises(AitpError) as exc:
        verify_tct({"tct_token": token})
    assert exc.value.code == "UNKNOWN_FIELD"
    assert "routing_hint" in exc.value.message


def test_tct_ext_claim_ignored(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    claims = _tct_claims(ext={"com.example.vendor_hint": "opaque"})
    token = encode_jws("aitp-tct+jwt", claims, keys[ISSUER], alg="EdDSA")
    assert verify_tct({"tct_token": token}) == {"grants": ["macp.mode.task.v1"]}


def test_tct_cnf_unknown_key_rejected(spec_dir: Path) -> None:
    """`cnf` is itself additionalProperties: false ({"jkt"} only) -- an
    unrecognized member inside `cnf` (not `ext`) must reject too, not just
    the top-level claim set.
    """
    keys = load_kat_keys(spec_dir)
    claims = _tct_claims(cnf={"jkt": thumbprint_for_aid(SUBJECT), "kid": "attacker-supplied"})
    token = encode_jws("aitp-tct+jwt", claims, keys[ISSUER], alg="EdDSA")
    with pytest.raises(AitpError) as exc:
        verify_tct({"tct_token": token})
    assert exc.value.code == "UNKNOWN_FIELD"


# ── Grant voucher claims (voucher.py, reused embedded in delegation.py) ───


def _voucher_claims(**overrides: Any) -> dict[str, Any]:
    base = {
        "ver": "aitp/0.2",
        "iss": ISSUER,
        "sub": SUBJECT,
        "grants": ["macp.mode.task.v1"],
        "iat": NOW,
        "exp": NOW + 3600,
    }
    base.update(overrides)
    return base


def test_voucher_unknown_claim_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    claims = _voucher_claims(routing_hint="x")
    token = encode_jws("aitp-grant+jwt", claims, keys[ISSUER], alg="EdDSA")
    with pytest.raises(AitpError) as exc:
        verify_grant_voucher({"voucher_token": token})
    assert exc.value.code == "UNKNOWN_FIELD"


def test_voucher_ext_claim_ignored(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    claims = _voucher_claims(ext={"sd_grant": {"sd_alg": "sha-256", "disclosures": []}})
    token = encode_jws("aitp-grant+jwt", claims, keys[ISSUER], alg="EdDSA")
    assert verify_grant_voucher({"voucher_token": token}) == {"grants": ["macp.mode.task.v1"]}


# ── Delegation token claims (delegation.py, single-hop) ───────────────────


def _mint_root_voucher(keys: dict[str, Any]) -> str:
    vclaims = _voucher_claims(sub=SUBJECT, src_jti=str(uuid.uuid4()), exp=NOW + 7200)
    return encode_jws("aitp-grant+jwt", vclaims, keys[ISSUER], alg="EdDSA")


def _delegation_claims(voucher_token: str, **overrides: Any) -> dict[str, Any]:
    base = {
        "ver": "aitp/0.2",
        "iss": SUBJECT,
        "sub": DELEGATE,
        "aud": ISSUER,
        "scope": ["macp.mode.task.v1"],
        "exp": NOW + 3600,
        "voucher": voucher_token,
        "jti": str(uuid.uuid4()),
    }
    base.update(overrides)
    return base


def test_delegation_unknown_claim_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    voucher_token = _mint_root_voucher(keys)
    claims = _delegation_claims(voucher_token, routing_hint="x")
    token = encode_jws("aitp-delegation+jwt", claims, keys[SUBJECT], alg="EdDSA")
    with pytest.raises(AitpError) as exc:
        verify_delegation_token({"self_aid": ISSUER, "delegation_token": token})
    assert exc.value.code == "UNKNOWN_FIELD"


def test_delegation_ext_claim_ignored(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    voucher_token = _mint_root_voucher(keys)
    claims = _delegation_claims(voucher_token, ext={"com.example.audit_tag": "abc"})
    token = encode_jws("aitp-delegation+jwt", claims, keys[SUBJECT], alg="EdDSA")
    result = verify_delegation_token({"self_aid": ISSUER, "delegation_token": token})
    assert result == {"grants": ["macp.mode.task.v1"]}


def test_delegation_embedded_voucher_unknown_claim_rejected(spec_dir: Path) -> None:
    """The unknown field can hide inside the embedded voucher rather than
    the outer token -- both are independently signed JWS claims objects and
    both get their own shape check.
    """
    keys = load_kat_keys(spec_dir)
    vclaims = _voucher_claims(sub=SUBJECT, src_jti=str(uuid.uuid4()), exp=NOW + 7200, routing_hint="x")
    voucher_token = encode_jws("aitp-grant+jwt", vclaims, keys[ISSUER], alg="EdDSA")
    claims = _delegation_claims(voucher_token)
    token = encode_jws("aitp-delegation+jwt", claims, keys[SUBJECT], alg="EdDSA")
    with pytest.raises(AitpError) as exc:
        verify_delegation_token({"self_aid": ISSUER, "delegation_token": token})
    assert exc.value.code == "UNKNOWN_FIELD"


# ── Envelope (envelope.py) ────────────────────────────────────────────────


def _envelope_input(**payload_extra: Any) -> dict[str, Any]:
    env = {
        "version": "aitp/0.2",
        "message_type": "mutual_hello",
        "message_id": str(uuid.uuid4()),
        "timestamp": NOW,
        "sender": {"agent_id": SUBJECT},
        "payload": {"hello": True},
        "signature": "__VALID_ENVELOPE_SIG__",
    }
    env.update(payload_extra)
    return {"self_aid": ISSUER, "tolerance_seconds": 300, "envelope": env}


def test_envelope_unknown_field_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(routing_hint="https://attacker.example/relay"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_envelope_extensions_accepted(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_envelope_input(extensions={"tee": {"platform": "sgx"}}), REFERENCE_CLOCK, keys)
    assert verify_envelope(minted) == {"ok": True}


def test_envelope_sender_unknown_field_rejected(spec_dir: Path) -> None:
    """`sender` is its own additionalProperties: false object ({"agent_id"}
    only) -- pin it separately from the top-level envelope check.
    """
    keys = load_kat_keys(spec_dir)
    inp = _envelope_input()
    inp["envelope"]["sender"]["routing_hint"] = "x"
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_envelope(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


# ── Manifest (manifest.py) ─────────────────────────────────────────────────


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
        # REQUIRED by aitp-manifest.schema.json -- a Manifest without it is
        # MANIFEST_INVALID, which would mask whatever each test is really about.
        "identity_hint": {"type": "oidc", "issuer": "https://auth.example", "subject": "agent"},
        "signature": "__VALID_MANIFEST_SIG__",
    }
    man.update(body_extra)
    return {"manifest": man, "now": NOW}


def test_manifest_unknown_field_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(routing_hint="x"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_manifest_extensions_accepted(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(extensions={"tee": {"platform": "sev"}}), REFERENCE_CLOCK, keys)
    assert verify_manifest(minted) == {"aid": SUBJECT}


def test_manifest_pop_unknown_field_rejected(spec_dir: Path) -> None:
    """`proof_of_possession` is its own additionalProperties: false object
    ({"challenge", "signature"}) -- pin it separately from the manifest body.
    """
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    inp["manifest"]["proof_of_possession"]["routing_hint"] = "x"
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_manifest_optional_fields_are_not_rejected(spec_dir: Path) -> None:
    """Optional body members that appear in NO conformance fixture.

    This is the false-rejection direction, and nothing else covers it: the
    pack carries no manifest using `display_name` or
    `accepted_signature_algorithms`, so dropping either from the allow-list
    would reject perfectly valid manifests while the whole suite stayed
    green. The allow-list is only as trustworthy as the keys pinned here.
    """
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    inp["manifest"]["display_name"] = "Test Agent"
    inp["manifest"]["accepted_signature_algorithms"] = ["EdDSA", "ES256"]
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_manifest(minted) == {"aid": SUBJECT}


def test_manifest_identity_hint_unknown_field_rejected(spec_dir: Path) -> None:
    """`identity_hint` is additionalProperties: false too, but reaches that
    constraint through a `$ref` to $defs/IdentityHint -- so a survey that
    only reads the body's inline `properties` sees an unconstrained object
    and misses it. handshake.py reads this member, so an unguarded slot
    would have been a real hole hidden behind one level of indirection.
    """
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    inp["manifest"]["identity_hint"] = {"type": "oidc", "subject": "s", "routing_hint": "x"}
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_manifest_identity_hint_known_fields_accepted(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    inp["manifest"]["identity_hint"] = {
        "type": "oidc", "issuer": "https://issuer.example", "subject": "s", "public_key": "k",
    }
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_manifest(minted) == {"aid": SUBJECT}


@pytest.mark.parametrize("obj", [None, 5, "text", ["a"], True])
def test_non_object_is_an_aitp_error_not_a_traceback(obj: Any) -> None:
    """A scalar where the schema requires an object is a shape defect.

    It must raise AitpError, not TypeError. Every caller of this helper is a
    verifier entry point whose contract is "AitpError or a verdict", and the
    objects reaching it come off the wire, so a raw TypeError from `for k in
    obj` escapes past any `except AitpError` the caller wrote and crashes it
    on remote input instead. `verify_revocation_snapshot` is the case that
    forced this guard: it fed remotely-fetched snapshot bodies straight in.
    """
    with pytest.raises(AitpError) as exc:
        reject_unknown_fields(obj, frozenset({"a"}), shape_code="INVALID_ENVELOPE", what="thing")
    assert exc.value.code == "INVALID_ENVELOPE"
    assert "not an object" in exc.value.message


# ── Revocation snapshot (revocation.py) ────────────────────────────────────


def _revocation_body(**overrides: Any) -> dict[str, Any]:
    """A well-formed `revocation_list` body, for mutating one member at a time."""
    body: dict[str, Any] = {
        "version": "aitp/0.2",
        "issuer": ISSUER,
        "published_at": NOW,
        "expires_at": NOW + 3600,
        "entries": [],
    }
    body.update(overrides)
    return body


def _revocation_input(**body_extra: Any) -> dict[str, Any]:
    body = {
        "version": "aitp/0.2",
        "issuer": ISSUER,
        "published_at": NOW,
        "expires_at": NOW + 3600,
        "entries": [{"jti": "revoked-1", "revoked_at": NOW, "reason": "compromised"}],
    }
    body.update(body_extra)
    snapshot = {"revocation_list": body, "signature": "__VALID_A_SIG__"}
    return {
        "policy": {"fail_mode": "fail_closed", "max_staleness_secs": 600},
        "snapshot": snapshot,
        "now": NOW,
        "expected_issuer": ISSUER,
        "queried_jti": "not-on-the-list",
    }


def test_revocation_unknown_field_rejected(spec_dir: Path) -> None:
    """An unknown member reports §7's code, not the policy's answer.

    RFC-AITP-0008 §1.5 separates a snapshot the peer OBTAINED and could not
    trust from one that is ABSENT (unreachable or stale). Only the second
    consults `fail_mode`. An unknown member is the first, so reporting
    `TCT_REVOKED` here would be a true statement about the queried jti by
    accident and would say nothing about the defect actually found.
    `test_revocation_unknown_field_survives_soft_fail` pins the direction in
    which conflating the two is outright unsafe.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_revocation_input(routing_hint="x"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_revocation_extensions_accepted(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_revocation_input(extensions={"tee": {"platform": "sgx"}}), REFERENCE_CLOCK, keys)
    assert verify_revocation_snapshot(minted) == {"revoked": False}


def test_revocation_entry_unknown_field_rejected(spec_dir: Path) -> None:
    """Each `entries[]` item is additionalProperties: false too."""
    keys = load_kat_keys(spec_dir)
    inp = _revocation_input()
    inp["snapshot"]["revocation_list"]["entries"][0]["source"] = "attacker-supplied"
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_revocation_unknown_field_survives_soft_fail(spec_dir: Path) -> None:
    """`soft_fail` MUST NOT downgrade an unknown member to "merely stale".

    This is the direction that makes the distinction load-bearing rather than
    cosmetic. Under `fail_closed`, routing an untrustworthy snapshot through
    the policy still rejects (as `TCT_REVOKED`), so the bug hides. Under
    `soft_fail` the same routing RETURNS `{"revoked": False, "stale": True}`
    -- a §7-MUST-reject artifact accepted as a valid-but-stale snapshot, with
    the caller told only that its revocation data is old. `fail_mode` answers
    "what if there is no fresh snapshot"; it was never meant to answer "what
    if the snapshot is malformed", which RFC-AITP-0008 §1.5 decides first.
    This module used to do exactly that.

    Schema defects take the sibling code and are pinned by
    `test_revocation_malformed_snapshot_is_a_structural_rejection`; the
    ordering between the two is pinned by
    `test_revocation_unknown_field_yields_to_a_structural_defect`.
    """
    keys = load_kat_keys(spec_dir)
    inp = _revocation_input(routing_hint="x")
    inp["policy"]["fail_mode"] = "soft_fail"
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


# ── Handshake payload + identity descriptor (handshake.py / identity.py) ──


def _hello_input(self_aid: str, sender_aid: str, **payload_extra: Any) -> dict[str, Any]:
    bare_key = sender_aid.split(":")[-1]
    identity = {"type": "pinned_key", "subject": "worker", "public_key": bare_key, "proof": "__VALID_PINNED_PROOF__"}
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
    payload: dict[str, Any] = {
        "identity": identity,
        "manifest": manifest,
        "requested_grants": ["macp.mode.task.v1"],
        "pop_nonce": b64url_encode(b"\x33" * 16),
    }
    payload.update(payload_extra)
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


def test_handshake_payload_unknown_field_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT, routing_hint="x")
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_handshake_payload_extensions_accepted(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT, extensions={"tee": {"platform": "trustzone"}})
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_handshake_payload(minted) == {"ok": True}


def test_identity_descriptor_unknown_field_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    inp["envelope"]["payload"]["identity"]["vendor_hint"] = "x"
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_identity_descriptor_extensions_accepted(spec_dir: Path) -> None:
    """The handshake `IdentityDescriptor` reserves an `extensions` slot like
    every other signed object, so an unrecognized key inside it is IGNORED.

    This test asserted the opposite until spec PR #42. Two committed schemas
    disagreed: `aitp-identity.schema.json` carried an `extensions` property
    while the handshake's `$defs/IdentityDescriptor` did not, and RFC-AITP-0002
    §1 named the former canonical while the handshake payload is validated
    against the latter. This verifier followed the governing schema and
    rejected -- the fail-closed reading, but a false rejection if the other
    schema was right. PR #42 ("one identity descriptor instead of two")
    resolved it by giving the descriptor the slot, and `id-009` now pins
    acceptance, so the over-rejection is gone.

    Kept as the paired positive for `test_identity_descriptor_unknown_field_rejected`:
    the MUST-ignore half of §7 is the direction a verifier fails silently, since
    rejecting everything unrecognized passes every reject fixture.
    """
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    inp["envelope"]["payload"]["identity"]["extensions"] = {"vendor.example/attestation_tier": "gold"}
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_handshake_payload(minted) == {"ok": True}


@pytest.mark.parametrize(
    ("entries", "label"),
    [
        pytest.param([5], "scalar-entry", id="scalar-entry"),
        pytest.param([None], "null-entry", id="null-entry"),
        pytest.param([{"jti": "j"}], "entry-missing-revoked_at", id="entry-missing-revoked_at"),
        pytest.param([{"jti": 5, "revoked_at": 1}], "entry-jti-mistyped", id="entry-jti-mistyped"),
        pytest.param(5, "scalar-entries", id="entries-is-a-scalar"),
        pytest.param(None, "null-entries", id="entries-is-null"),
        pytest.param("abc", "string-entries", id="entries-is-a-string"),
    ],
)
def test_revocation_malformed_entries_are_a_structural_rejection(entries: Any, label: str) -> None:
    """A malformed `entries` array is an obtained-but-invalid snapshot.

    It reports `REVOCATION_SNAPSHOT_INVALID` under BOTH fail modes, and never
    crashes. Two things changed here at once, so both are pinned:

    * The code. RFC-AITP-0008 §1.5's blockquote separates a snapshot that is
      *absent* (unreachable or stale -> `fail_mode`) from one the peer obtained
      and could not trust (-> a snapshot code). A malformed array is the
      second, so `fail_mode` never sees it. This test previously asserted
      `TCT_REVOKED` / `{"stale": True}`, which said nothing about the defect
      and, under `soft_fail`, reported a broken snapshot as merely old.
    Only the code changed here, not the crash-safety: the previous module
    already guarded `entries` explicitly (an `isinstance(..., list)` check plus
    `reject_unknown_fields`'s own non-dict guard), and every parameter above
    returned a verdict rather than a traceback. The raw-exception escapes this
    commit fixes were on the `snapshot`/`body` surface, not this one --
    `test_revocation_malformed_snapshot_is_a_structural_rejection` is where
    that claim belongs and where it is true.
    """
    for mode in ("fail_closed", "soft_fail"):
        inp: dict[str, Any] = {
            "policy": {"fail_mode": mode, "max_staleness_secs": 600},
            "now": NOW + 100, "expected_issuer": ISSUER,
            "snapshot": {"revocation_list": _revocation_body(entries=entries), "signature": "x"},
        }
        with pytest.raises(AitpError) as exc:
            verify_revocation_snapshot(inp)
        assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID", f"{label}/{mode}"


@pytest.mark.parametrize(
    ("snapshot", "label"),
    [
        pytest.param("pwned", "snapshot-is-a-string", id="snapshot-is-a-string"),
        pytest.param(None, "snapshot-is-null", id="snapshot-is-null"),
        pytest.param(5, "snapshot-is-a-scalar", id="snapshot-is-a-scalar"),
        pytest.param({"revocation_list": "pwned", "signature": "x"}, "body-is-a-string", id="body-is-a-string"),
        pytest.param({"revocation_list": None, "signature": "x"}, "body-is-null", id="body-is-null"),
        pytest.param({"revocation_list": {}, "signature": "x"}, "body-is-empty", id="body-is-empty"),
        pytest.param({"signature": "x"}, "no-body-at-all", id="no-body-at-all"),
        pytest.param({"revocation_list": _revocation_body()}, "no-signature", id="no-signature"),
        pytest.param({"revocation_list": _revocation_body(), "signature": None}, "signature-is-null", id="signature-is-null"),
        pytest.param({"revocation_list": _revocation_body(issuer="aid:pubkey:tooshort"), "signature": "x"}, "issuer-unparseable", id="issuer-unparseable"),
        pytest.param({"revocation_list": _revocation_body(issuer=None), "signature": "x"}, "issuer-is-null", id="issuer-is-null"),
        pytest.param({"revocation_list": _revocation_body(published_at="nope"), "signature": "x"}, "published_at-not-numeric", id="published_at-not-numeric"),
        pytest.param({"revocation_list": _revocation_body(published_at=True), "signature": "x"}, "published_at-is-bool", id="published_at-is-bool"),
        pytest.param({"revocation_list": _revocation_body(expires_at=None), "signature": "x"}, "expires_at-is-null", id="expires_at-is-null"),
    ],
)
def test_revocation_malformed_snapshot_is_a_structural_rejection(snapshot: Any, label: str) -> None:
    """Every malformed snapshot reports `REVOCATION_SNAPSHOT_INVALID`, both modes.

    Every case here but one (`published_at-is-bool`, which merely reported the
    wrong code) previously escaped as a RAW exception -- `TypeError` from
    `snapshot["revocation_list"]`, `KeyError: 'issuer'`, `AttributeError` from
    `parse_aid` calling `.startswith` on a non-string, `ValueError` from an
    unparseable AID. The module dereferenced `snapshot` and `body` before its
    `try`, so every shape guard inside it was dead code and a caller that
    correctly wrapped `except AitpError` got a traceback instead of a verdict.
    Conformance `rev-007` proved it independently: against this repo's `main`
    it did not merely report the wrong code, it crashed with
    `KeyError: 'published_at'`.

    `published_at-is-bool` is not padding: Python makes `True` an `int`, JSON
    does not, so a bare `isinstance(v, int)` accepts a timestamp of `true`.

    `UNKNOWN_FIELD` is deliberately absent -- none of these carries an
    unrecognized member. That boundary runs both ways and both sides are
    pinned: `test_revocation_unknown_field_rejected` requires §7's code when an
    unknown member is the ONLY defect, and
    `test_revocation_unknown_field_yields_to_a_structural_defect` requires this
    code when it is not.
    """
    for mode in ("fail_closed", "soft_fail"):
        inp: dict[str, Any] = {
            "policy": {"fail_mode": mode, "max_staleness_secs": 600},
            "now": NOW + 100, "expected_issuer": ISSUER, "snapshot": snapshot,
        }
        with pytest.raises(AitpError) as exc:
            verify_revocation_snapshot(inp)
        assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID", f"{label}/{mode}"


def test_revocation_unknown_field_yields_to_a_structural_defect() -> None:
    """`UNKNOWN_FIELD` means the unknown member is the ONLY defect.

    The registry is explicit: `REVOCATION_SNAPSHOT_INVALID` covers a snapshot
    that fails schema validation, and "when the only defect is an unknown
    member outside `extensions`, use `UNKNOWN_FIELD` instead". So the two codes
    are ordered, not alternatives, and both directions need pinning -- one code
    swallowing the other is invisible to the conformance pack, which carries no
    two-defect fixture.
    """
    # Only defect is the unknown member -> §7's code.
    only = {"revocation_list": _revocation_body(list_owner="x"), "signature": "x"}
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot({
            "policy": {"fail_mode": "soft_fail", "max_staleness_secs": 600},
            "now": NOW + 100, "expected_issuer": ISSUER, "snapshot": only,
        })
    assert exc.value.code == "UNKNOWN_FIELD"

    # Unknown member PLUS a schema defect -> the structural code wins.
    extra_defects: list[dict[str, Any]] = [
        {"signature": None},                                   # mistyped wrapper member
        {"revocation_list": _revocation_body(list_owner="x", published_at="nope")},
    ]
    for extra_defect in extra_defects:
        snapshot: dict[str, Any] = {"revocation_list": _revocation_body(list_owner="x"), "signature": "x"}
        snapshot.update(extra_defect)
        for mode in ("fail_closed", "soft_fail"):
            with pytest.raises(AitpError) as exc:
                verify_revocation_snapshot({
                    "policy": {"fail_mode": mode, "max_staleness_secs": 600},
                    "now": NOW + 100, "expected_issuer": ISSUER, "snapshot": snapshot,
                })
            assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID", f"{extra_defect}/{mode}"


@pytest.mark.parametrize("raw_json", ['1e400', '-1e400', '1e999'])
def test_revocation_infinite_timestamp_does_not_crash(raw_json: str) -> None:
    """`json.loads("1e400")` returns `float("inf")` from ordinary valid JSON,
    and `int(inf)` raises OverflowError -- not TypeError or ValueError.

    A guard catching only the latter two lets a remote peer take the caller
    down with a two-character payload. This needs no non-standard JSON
    literal (`Infinity`, `NaN`), just an exponent large enough to overflow a
    float, so `json.loads` with default settings produces it.
    """
    import json as _json

    body = _revocation_body(published_at=_json.loads(raw_json))
    assert isinstance(body["published_at"], float)  # the payload really does parse to inf
    for mode in ("fail_closed", "soft_fail"):
        inp = {
            "policy": {"fail_mode": mode, "max_staleness_secs": 600},
            "now": NOW + 100, "expected_issuer": ISSUER,
            "snapshot": {"revocation_list": body, "signature": "x"},
        }
        with pytest.raises(AitpError) as exc:
            verify_revocation_snapshot(inp)
        assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


@pytest.mark.parametrize("dropped", [
    "version", "aid", "identity_hint", "handshake_endpoint", "accepted_trust_anchors",
    "offered_capabilities", "proof_of_possession", "published_at", "expires_at", "signature",
])
def test_manifest_every_required_member_is_enforced(dropped: str, spec_dir: Path) -> None:
    """Each entry of the schema's `required` array is independently pinned.

    `man-006` covers exactly one member (`handshake_endpoint`), so nine of the
    ten could be deleted from `_REQUIRED_MANIFEST_FIELDS` with the whole suite
    and the whole conformance pack still green. Four are load-bearing beyond
    the code they report: against this repo's previous `main`, dropping
    `signature`, `proof_of_possession`, `aid` or `expires_at` raised a raw
    `KeyError` -- on input `handshake.py` accepts from a remote `mutual_hello`.
    """
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    # Minted first: the fixture must be a Manifest that WOULD verify, so that
    # the missing member is provably the only defect.
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_manifest(minted) == {"aid": SUBJECT}

    del minted["manifest"][dropped]
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"
    assert dropped in exc.value.message


@pytest.mark.parametrize(("member", "value"), [
    ("published_at", "not-a-number"),
    ("expires_at", None),
    ("aid", 5),
    ("accepted_trust_anchors", "not-a-list"),
    ("proof_of_possession", "not-an-object"),
    ("identity_hint", []),
    ("signature", 5),
    ("published_at", True),
])
def test_manifest_mistyped_member_is_a_structural_rejection(member: str, value: Any, spec_dir: Path) -> None:
    """A member of the wrong type is MANIFEST_INVALID, not a raw exception.

    The registry defines MANIFEST_INVALID as covering "a missing REQUIRED
    member, a member of the wrong type, or a value outside its grammar"; only
    the first was implemented at first. The rest escaped as raw
    `TypeError`/`ValueError`/`AttributeError` from the expiry comparison and
    `parse_aid` -- reachable end-to-end from a remote `mutual_hello`, because
    `handshake.py` feeds the peer's inline manifest straight into
    `verify_manifest`.

    `published_at=True` is not padding: Python makes `True` an `int`, JSON does
    not, so a bare `isinstance(v, int)` accepts a timestamp of `true`.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
    minted["manifest"][member] = value
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_integral_float_timestamp_is_accepted(spec_dir: Path) -> None:
    """`1711900000.0` is a valid JSON Schema `integer` and canonicalizes to the
    same JCS bytes as `1711900000`, so the peer signed what we reconstruct.
    Rejecting it would be a false rejection -- the direction the reject-side
    fixtures cannot catch.
    """
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    minted["manifest"]["published_at"] = float(minted["manifest"]["published_at"])
    assert verify_manifest(minted) == {"aid": SUBJECT}


def test_manifest_unknown_field_yields_to_a_structural_defect(spec_dir: Path) -> None:
    """`UNKNOWN_FIELD` means the unknown member is the ONLY defect.

    The mirror of `test_revocation_unknown_field_yields_to_a_structural_defect`
    for the Manifest. The two modules diverged on this once already: the
    manifest checked the member set before types, so a Manifest that was both
    mistyped and carrying an unknown member reported the §7 code. Every fixture
    carries one defect at a time, so the whole pack stayed green either way --
    which is exactly why the precedence needs a test rather than a fixture.
    """
    keys = load_kat_keys(spec_dir)

    # Only defect is the unknown member -> §7's code.
    only = mint_input(_manifest_input(bogus="x"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(only)
    assert exc.value.code == "UNKNOWN_FIELD"

    # Unknown member PLUS a structural defect -> the structural code wins,
    # for a mistyped member and for a missing REQUIRED one alike.
    mistyped = mint_input(_manifest_input(bogus="x"), REFERENCE_CLOCK, keys)
    mistyped["manifest"]["published_at"] = "not-a-number"
    with pytest.raises(AitpError) as exc:
        verify_manifest(mistyped)
    assert exc.value.code == "MANIFEST_INVALID"

    missing = mint_input(_manifest_input(bogus="x"), REFERENCE_CLOCK, keys)
    del missing["manifest"]["handshake_endpoint"]
    with pytest.raises(AitpError) as exc:
        verify_manifest(missing)
    assert exc.value.code == "MANIFEST_INVALID"


def test_manifest_sub_object_required_members_are_enforced(spec_dir: Path) -> None:
    """`proof_of_possession` and `identity_hint` have their own `required`
    arrays, reached through a `$ref`. Only the body's list is parametrized
    above, so these are pinned here -- dropping `challenge` previously raised a
    raw `KeyError` from the PoP verification step.
    """
    keys = load_kat_keys(spec_dir)
    for sub, member in (
        ("proof_of_possession", "challenge"), ("proof_of_possession", "signature"),
        ("identity_hint", "type"), ("identity_hint", "subject"),
    ):
        minted = mint_input(_manifest_input(), REFERENCE_CLOCK, keys)
        del minted["manifest"][sub][member]
        with pytest.raises(AitpError) as exc:
            verify_manifest(minted)
        assert exc.value.code == "MANIFEST_INVALID", f"{sub}.{member}"
        assert member in exc.value.message
