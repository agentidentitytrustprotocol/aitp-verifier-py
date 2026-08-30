"""RFC-AITP-0001 §7 unknown-field rejection, pinned per artifact.

    "Unknown JSON fields outside explicit `extensions` namespaces MUST be
    rejected. ... Forward compatibility is provided exclusively through
    explicit `extensions` objects (see RFC-AITP-0012) ... unknown keys
    *inside* `extensions` MUST be ignored."

Every case below pins BOTH directions of the asymmetry directly against the
verifier functions, independently of the conformance pack (which only pins
one direction, ``bundle-005-extensions-accepted``, for one artifact):

* a member outside the schema's allowed set is rejected with the artifact's
  chosen error code;
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
    reject_unknown_fields({"a": 1, "b": 2}, allowed, code="X", what="obj")  # no raise
    reject_unknown_fields({"a": 1, "extensions": {"anything": "at all"}}, allowed, code="X", what="obj")  # no raise

    with pytest.raises(AitpError) as exc:
        reject_unknown_fields({"a": 1, "c": 3}, allowed, code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"
    assert "c" in exc.value.message

    # A key literally named "extensions" is only special if the caller put it
    # in *allowed* -- this is what makes the handshake IdentityDescriptor
    # (which has no extensions slot at all) correctly reject one.
    with pytest.raises(AitpError):
        reject_unknown_fields({"a": 1, "extensions": {}}, frozenset({"a", "b"}), code="X", what="obj")


def test_reject_unknown_fields_tolerates_non_str_keys() -> None:
    """A caller feeding a raw (non-JSON-parsed) dict with mixed key types
    must not crash with TypeError out of a bare ``sorted()`` -- the whole
    point of this gate is to turn malformed input into AitpError, not into a
    traceback.
    """
    with pytest.raises(AitpError):
        reject_unknown_fields({"a": 1, 2: "y"}, frozenset({"a"}), code="X", what="obj")


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
    assert exc.value.code == "TCT_SIGNATURE_INVALID"
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
    assert exc.value.code == "TCT_SIGNATURE_INVALID"


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
    assert exc.value.code == "DELEGATION_INVALID_VOUCHER"


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
    assert exc.value.code == "DELEGATION_INVALID_SIGNATURE"


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
    assert exc.value.code == "DELEGATION_INVALID_VOUCHER"


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
    assert exc.value.code == "INVALID_ENVELOPE"


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
    assert exc.value.code == "INVALID_ENVELOPE"


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
        "signature": "__VALID_MANIFEST_SIG__",
    }
    man.update(body_extra)
    return {"manifest": man, "now": NOW}


def test_manifest_unknown_field_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_manifest_input(routing_hint="x"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_SIGNATURE_INVALID"


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
    assert exc.value.code == "MANIFEST_SIGNATURE_INVALID"


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
    assert exc.value.code == "MANIFEST_SIGNATURE_INVALID"


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

    It must raise AitpError, not TypeError. Callers that fold shape failures
    into a boolean catch AitpError only -- revocation.py's
    `except AitpError: sig_ok = False` is the case that matters -- so a raw
    TypeError escapes the verifier entirely and turns a fail-closed path into
    a crash on remote input.
    """
    with pytest.raises(AitpError) as exc:
        reject_unknown_fields(obj, frozenset({"a"}), code="INVALID_ENVELOPE", what="thing")
    assert exc.value.code == "INVALID_ENVELOPE"
    assert "not an object" in exc.value.message


# ── Revocation snapshot (revocation.py) ────────────────────────────────────


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
    """Shape violations fold into the same sig_ok/fail_mode path this
    module already uses for a bad signature (no dedicated shape code exists
    for revocation snapshots in the registry -- see the module comment).
    Under `fail_closed` a shape-invalid snapshot is "no fresh valid
    snapshot", i.e. `TCT_REVOKED`, exactly like every other structural
    failure this module already treats that way.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_revocation_input(routing_hint="x"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot(minted)
    assert exc.value.code == "TCT_REVOKED"


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
    assert exc.value.code == "TCT_REVOKED"


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
    assert exc.value.code == "INVALID_ENVELOPE"


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
    assert exc.value.code == "IDENTITY_FAILED"


def test_identity_descriptor_has_no_extensions_slot(spec_dir: Path) -> None:
    """Unlike most signed objects, the handshake `IdentityDescriptor`
    ($defs in aitp-mutual-handshake.schema.json) reserves NO `extensions`
    member at all -- RFC-AITP-0002 §1's field table lists exactly `type`,
    `issuer`, `subject`, `proof`, `public_key`, and nothing else, and the
    schema agrees (unlike the standalone `aitp-identity.schema.json`, which
    does carry an `extensions` property -- a discrepancy worth flagging
    upstream, see this repo's task report). A member literally named
    `extensions` on the handshake identity descriptor is therefore just
    another unknown field, not the escape hatch it would be on the envelope
    or the Manifest.
    """
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    inp["envelope"]["payload"]["identity"]["extensions"] = {"whatever": 1}
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "IDENTITY_FAILED"


@pytest.mark.parametrize(
    ("entries", "label"),
    [
        pytest.param([5], "scalar-entry", id="scalar-entry"),
        pytest.param([None], "null-entry", id="null-entry"),
        pytest.param(5, "scalar-entries", id="entries-is-a-scalar"),
        pytest.param(None, "null-entries", id="entries-is-null"),
        pytest.param("abc", "string-entries", id="entries-is-a-string"),
    ],
)
def test_revocation_malformed_entries_still_fail_closed(entries: Any, label: str) -> None:
    """A malformed snapshot must fail closed, never crash.

    Snapshots come from the issuer's remote endpoint, so this is
    attacker-reachable. The shape guard folds into `except AitpError: sig_ok
    = False`, which catches AitpError only -- so any raw TypeError from
    iterating a non-list `entries`, or from scanning a non-dict entry,
    escapes the verifier and takes the caller down instead of returning the
    fail_mode answer. Both directions are pinned: fail_closed reports
    revoked, soft_fail reports stale.
    """
    issuer = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
    snapshot = {
        "revocation_list": {
            "version": "aitp/0.2", "issuer": issuer,
            "published_at": 1711900000, "expires_at": 1711903600, "entries": entries,
        },
        "signature": "x",
    }

    closed: dict[str, Any] = {
        "policy": {"fail_mode": "fail_closed", "max_staleness_secs": 600},
        "now": 1711900100, "expected_issuer": issuer, "snapshot": snapshot,
    }
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot(closed)
    assert exc.value.code == "TCT_REVOKED"

    soft = dict(closed, policy={"fail_mode": "soft_fail", "max_staleness_secs": 600})
    assert verify_revocation_snapshot(soft) == {"revoked": False, "stale": True}
