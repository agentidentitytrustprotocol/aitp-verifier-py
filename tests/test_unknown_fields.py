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

import copy
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.delegation import verify_delegation_token
from aitp_verifier.envelope import verify_envelope
from aitp_verifier.errors import AitpError
from aitp_verifier.fields import reject_unknown_fields
from aitp_verifier.handshake import verify_handshake_payload
from aitp_verifier.identity import verify_identity
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


def test_tct_unknown_claim_and_bad_alg_reports_unknown_field(spec_dir: Path) -> None:
    """RFC-AITP-0005 §7.2 step 1's claims-membership check now runs BEFORE
    step 3's alg-pin (spec commit 993da8c's now-explicit sub-step order:
    segment-parse -> typ -> claims-membership -> alg-pin -> signature). A TCT
    carrying BOTH an unrecognized claim and a header `alg` that does not
    match the issuer AID's pinned algorithm must report `UNKNOWN_FIELD`, not
    `TOKEN_ALG_MISMATCH` -- even though the alg defect alone reports the
    latter (`tct-009`). Before this ordering fix, `verify_jws` ran alg-pin
    (and signature) fully, internally, before claims-membership was ever
    checked, so this combined-defect case would have reported
    `TOKEN_ALG_MISMATCH` instead.
    """
    keys = load_kat_keys(spec_dir)
    claims = _tct_claims(routing_hint="https://attacker.example/relay")
    # Signed with the issuer's real Ed25519 key, but the header claims ES256
    # -- a mismatch against the AID's pinned EdDSA, independent of the
    # unrecognized claim above.
    token = encode_jws("aitp-tct+jwt", claims, keys[ISSUER], alg="ES256")
    with pytest.raises(AitpError) as exc:
        verify_tct({"tct_token": token})
    assert exc.value.code == "UNKNOWN_FIELD"


def test_tct_unknown_claim_and_bad_alg_reports_unknown_field_via_handshake(spec_dir: Path) -> None:
    """Same combined defect as above, exercised through the handshake's
    embedded-TCT path (`handshake.py::_verify_commit`), which runs the
    identical check via the shared `check_tct_claims_shape` helper rather
    than its own copy -- this pins that the two call sites do not drift.

    Uses the `peer_a`/`peer_b` input shape (no envelope signature required)
    since this test is about the embedded TCT's internal ordering, not the
    envelope crypto around it; `peer_a` is processed first and raises before
    `peer_b` is ever touched.
    """
    keys = load_kat_keys(spec_dir)
    claims = _tct_claims(routing_hint="x")
    token = encode_jws("aitp-tct+jwt", claims, keys[ISSUER], alg="ES256")
    inp = {
        "peer_a": {"self_aid": SUBJECT, "received_payload": {"tct": token}},
        "peer_b": {"self_aid": SUBJECT, "received_payload": {}},
    }
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(inp)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_tct_typ_mismatch_still_wins_over_unknown_claim(spec_dir: Path) -> None:
    """Negative control for the ordering fix: `typ` is still checked before
    claims-membership (RFC-AITP-0005 §7.2 step 2 before step 1's
    claims-membership sub-clause) -- a token whose `typ` is wrong AND whose
    claims carry an unrecognized field must still report `TOKEN_TYP_MISMATCH`,
    not `UNKNOWN_FIELD`. Already covered at the fixture level by `tct-010`;
    pinned here directly since this phase changes the surrounding order and
    this is the other half of the ordering contract it must not invert.
    """
    keys = load_kat_keys(spec_dir)
    claims = _tct_claims(routing_hint="x")
    token = encode_jws("aitp-grant+jwt", claims, keys[ISSUER], alg="EdDSA")
    with pytest.raises(AitpError) as exc:
        verify_tct({"tct_token": token})
    assert exc.value.code == "TOKEN_TYP_MISMATCH"


# ── Grant voucher claims (voucher.py, reused embedded in delegation.py) ───


def _voucher_claims(**overrides: Any) -> dict[str, Any]:
    base = {
        "ver": "aitp/0.2",
        "iss": ISSUER,
        "sub": SUBJECT,
        "grants": ["macp.mode.task.v1"],
        "iat": NOW,
        "exp": NOW + 3600,
        "src_jti": str(uuid.uuid4()),
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
        "cnf": {"jkt": "not-checked-for-single-hop"},
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


def test_manifest_identity_hint_oidc_known_fields_accepted(spec_dir: Path) -> None:
    """`oidc` with `issuer` and no `public_key` -- the shape `$defs/IdentityHint`
    actually requires for that type (RFC-AITP-0003, schema `if/then/else`).

    Until this phase, this test instead asserted an `oidc` entry CARRYING
    `public_key` was accepted -- the exact under-enforcement issue #23 item 4
    reports. See `test_manifest_identity_hint_conditional_requirements_enforced`
    for the now-covered rejection of that combined shape.
    """
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    inp["manifest"]["identity_hint"] = {"type": "oidc", "issuer": "https://issuer.example", "subject": "s"}
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_manifest(minted) == {"aid": SUBJECT}


def test_manifest_identity_hint_pinned_key_known_fields_accepted(spec_dir: Path) -> None:
    """`pinned_key` with a `public_key` matching the schema's pattern
    (`^[A-Za-z0-9_-]{43,44}$`) -- the paired positive for the `pinned_key`
    branch, reusing a real 43-char AID key so the grammar is exercised
    against actual key material, not a placeholder.
    """
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    inp["manifest"]["identity_hint"] = {
        "type": "pinned_key", "subject": "s", "public_key": SUBJECT.split(":")[-1],
    }
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_manifest(minted) == {"aid": SUBJECT}


@pytest.mark.parametrize(
    ("hint", "label"),
    [
        pytest.param(
            {"type": "oidc", "issuer": "https://issuer.example", "subject": "s", "public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"},
            "oidc-with-forbidden-public-key", id="oidc-with-forbidden-public-key",
        ),
        pytest.param({"type": "oidc", "subject": "s"}, "oidc-missing-issuer", id="oidc-missing-issuer"),
        pytest.param({"type": "pinned_key", "subject": "s"}, "pinned-key-missing-public-key", id="pinned-key-missing-public-key"),
        pytest.param({"type": "bogus", "subject": "s"}, "unrecognized-type", id="unrecognized-type"),
        pytest.param(
            {"type": "pinned_key", "subject": "s", "public_key": "too-short"},
            "public-key-fails-pattern", id="public-key-fails-pattern",
        ),
    ],
)
def test_manifest_identity_hint_conditional_requirements_enforced(hint: dict[str, Any], label: str, spec_dir: Path) -> None:
    """`$defs/IdentityHint`'s `if/then/else` (oidc <-> issuer required/public_key
    forbidden; else <-> public_key required), `type` enum, and `public_key`
    pattern -- issue #23 item 4. `_shape`'s flat presence/type/member-set check
    cannot express any of these; before this phase they were silently
    unenforced (`test_manifest_identity_hint_known_fields_accepted` used to
    assert the `oidc-with-forbidden-public-key` shape below was ACCEPTED).
    """
    keys = load_kat_keys(spec_dir)
    inp = _manifest_input()
    inp["manifest"]["identity_hint"] = hint
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_manifest(minted)
    assert exc.value.code == "MANIFEST_INVALID", label


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


# ── Embedded revocation-snapshot trust (issue #24): tct.py / delegation.py
#    each consume a revocation snapshot as an EMBEDDED artifact rather than
#    their own top-level operation, and (before this phase) read its
#    `entries` via a bare `.get()` chain with no structural/member-set/
#    signature check at all -- so a forged or unsigned snapshot was trusted
#    at face value. Both now route through the same
#    `revocation.py::verify_snapshot_trust` that `verify_revocation_snapshot`
#    itself uses. ─────────────────────────────────────────────────────────


def _tct_revocation_input(entry_jti: str, **snapshot_body_overrides: Any) -> dict[str, Any]:
    """A `verify_tct` input carrying an embedded, to-be-minted revocation
    snapshot that lists *entry_jti* as revoked -- the shape `tct-004-revoked`
    pins, built directly (rather than loaded from that fixture) so each test
    below can mutate one member in isolation.
    """
    return {
        "tct_token": "__JWS_TCT__",
        "tct_token_claims": _tct_claims(jti=entry_jti),
        "issuer_revocation_list": {
            "issuer": ISSUER,
            "fail_mode": "fail_closed",
            "snapshot": {
                "revocation_list": _revocation_body(
                    entries=[{"jti": entry_jti, "revoked_at": NOW}], **snapshot_body_overrides
                ),
                "signature": "__VALID_B_SIG__",
            },
        },
    }


def test_tct_revocation_snapshot_genuinely_signed_and_matching_issuer_revokes(spec_dir: Path) -> None:
    """Positive control: a genuinely signed snapshot, from the TCT's own
    issuer, listing the TCT's jti, still revokes post-fix -- proving the new
    signature check is a real pass, not coincidentally the same outcome for
    the wrong reason (mirrors `tct-004-revoked`'s own conformance pin).
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_revocation_input(str(uuid.uuid4())), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_tct_revocation_snapshot_forged_signature_is_rejected_not_silently_trusted(spec_dir: Path) -> None:
    """Issue #24's core finding: before this phase, a forged/unsigned
    snapshot claiming a jti was revoked was trusted at face value (and,
    worse, a forged snapshot claiming a jti was NOT revoked would have
    silently defeated a genuine revocation) -- there was no signature check
    at all. Tampering one byte of the minted signature must now surface
    `REVOCATION_SNAPSHOT_SIGNATURE_INVALID`, not the `TCT_REVOKED` a
    face-value read of `entries` would still (correctly, by accident) report
    for this jti.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_revocation_input(str(uuid.uuid4())), REFERENCE_CLOCK, keys)
    sig = minted["issuer_revocation_list"]["snapshot"]["signature"]
    tampered = bytearray(b64url_decode(sig))
    tampered[-1] ^= 0x01
    minted["issuer_revocation_list"]["snapshot"]["signature"] = b64url_encode(bytes(tampered))
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_SIGNATURE_INVALID"


def test_tct_revocation_snapshot_missing_signature_is_a_structural_rejection(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_revocation_input(str(uuid.uuid4())), REFERENCE_CLOCK, keys)
    del minted["issuer_revocation_list"]["snapshot"]["signature"]
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


def test_tct_revocation_snapshot_unknown_body_member_is_rejected(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_revocation_input(str(uuid.uuid4()), routing_hint="x"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "UNKNOWN_FIELD"


def test_tct_revocation_snapshot_absent_snapshot_is_a_structural_rejection_not_a_crash(spec_dir: Path) -> None:
    """`.get("snapshot")` (not `["snapshot"]`) plus `verify_snapshot_trust`'s
    own `isinstance` guard is what makes a wholly-absent `snapshot` key raise
    `AitpError` instead of a raw `KeyError` from the old `.get("snapshot", {})`
    -> `.get("revocation_list", {})` chain's silent-empty-dict fallback.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_revocation_input(str(uuid.uuid4())), REFERENCE_CLOCK, keys)
    del minted["issuer_revocation_list"]["snapshot"]
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


@pytest.mark.parametrize("junk", ["not-an-object", ["a"], 5, True], ids=["string", "list", "int", "bool"])
def test_tct_revocation_snapshot_malformed_shape_is_rejected_not_a_crash(junk: Any, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_revocation_input(str(uuid.uuid4())), REFERENCE_CLOCK, keys)
    minted["issuer_revocation_list"]["snapshot"] = junk
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


def test_tct_revocation_snapshot_different_issuer_does_not_apply(spec_dir: Path) -> None:
    """A snapshot genuinely signed, but by an issuer other than this TCT's
    own `iss`, does not speak for it -- not a rejection (the snapshot may be
    perfectly valid, just for a different issuer), so the deny-list scan is
    simply skipped and the TCT verifies successfully.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_revocation_input(str(uuid.uuid4()))
    inp["issuer_revocation_list"]["issuer"] = SUBJECT
    inp["issuer_revocation_list"]["snapshot"]["revocation_list"]["issuer"] = SUBJECT
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_tct(minted) == {"grants": ["macp.mode.task.v1"]}


def _load_conformance_input(spec_dir: Path, fixture_id: str) -> dict[str, Any]:
    """Load one conformance fixture's `input` dict by id, for mutation --
    reused here rather than hand-building a fresh multi-hop delegation chain,
    since `del-mh-004-revoked-hop.json` already proves a genuinely valid
    chain end to end and every test below only needs to vary its
    `revocation_snapshots`. Carries the fixture's own `feature` (draft-RFC
    opt-in) into `inp["_feature"]`, the same marker `run_conformance.py`
    sets on the minted dict -- `del-mh-*` fixtures are gated on
    ``experimental-multihop-delegation`` and `verify_delegation_token`
    rejects the chain outright with `DELEGATION_MULTIHOP_NOT_SUPPORTED`
    without it.
    """
    conf_dir = spec_dir / "schemas/conformance"
    for path in conf_dir.glob("*.json"):
        d = json.loads(path.read_text())
        if d.get("id") == fixture_id:
            inp: dict[str, Any] = copy.deepcopy(d["input"])
            inp["_feature"] = d.get("feature")
            return inp
    raise AssertionError(f"conformance fixture {fixture_id!r} not found under {conf_dir}")


def test_delegation_revocation_snapshot_forged_signature_is_rejected_not_silently_trusted(spec_dir: Path) -> None:
    """Same finding as the TCT case above, through the multi-hop path
    (`delegation.py::_revocation_index`, RFC-AITP-0011 §6)."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "del-mh-004"), REFERENCE_CLOCK, keys)
    sig = minted["revocation_snapshots"][0]["snapshot"]["signature"]
    tampered = bytearray(b64url_decode(sig))
    tampered[-1] ^= 0x01
    minted["revocation_snapshots"][0]["snapshot"]["signature"] = b64url_encode(bytes(tampered))
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_SIGNATURE_INVALID"


def test_delegation_revocation_snapshot_missing_is_a_structural_rejection_not_a_crash(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "del-mh-004"), REFERENCE_CLOCK, keys)
    del minted["revocation_snapshots"][0]["snapshot"]
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


def test_delegation_revocation_snapshots_non_dict_record_is_rejected_not_a_crash(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "del-mh-004"), REFERENCE_CLOCK, keys)
    minted["revocation_snapshots"][0] = "not-an-object"
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


@pytest.mark.parametrize("junk", ["not-an-object", ["a"], 5, True], ids=["string", "list", "int", "bool"])
def test_delegation_revocation_snapshot_malformed_shape_is_rejected_not_a_crash(junk: Any, spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "del-mh-004"), REFERENCE_CLOCK, keys)
    minted["revocation_snapshots"][0]["snapshot"] = junk
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


@pytest.mark.parametrize("junk", [5, True, 1.5], ids=["int", "bool", "float"])
def test_delegation_revocation_snapshots_container_scalar_is_rejected_not_a_crash(junk: Any, spec_dir: Path) -> None:
    """`revocation_snapshots` itself is untrusted remote input, same as any
    record inside it. A scalar there is truthy and would otherwise survive
    `inp.get("revocation_snapshots", []) or []` and reach the `for` loop as a
    bare `TypeError: '...' object is not iterable`, escaping this module's
    own `AitpError`-or-verdict contract.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "del-mh-004"), REFERENCE_CLOCK, keys)
    minted["revocation_snapshots"] = junk
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


def test_delegation_revocation_index_keys_on_the_signed_issuer_not_the_wrapper_label(spec_dir: Path) -> None:
    """`record["issuer_aid"]` is caller-supplied and unverified; the entry
    must be indexed (and looked up) under the snapshot's own SIGNED `issuer`,
    so a wrapper cannot file a snapshot under a different AID than the one
    whose key actually signed it. `del-mh-004`'s snapshot is genuinely signed
    by SUBJECT (== chain[0].iss); mislabeling the wrapper's `issuer_aid` as
    DELEGATE must not move the index entry -- if it did, chain[0]'s own
    lookup (keyed on `hc.iss` == SUBJECT) would find nothing and the
    fixture's expected `DELEGATION_SOURCE_TCT_REVOKED` would silently
    disappear, which is exactly the gap issue #24 reports.
    """
    keys = load_kat_keys(spec_dir)
    inp = _load_conformance_input(spec_dir, "del-mh-004")
    assert inp["revocation_snapshots"][0]["issuer_aid"] == SUBJECT  # pin the fixture's own pre-condition
    inp["revocation_snapshots"][0]["issuer_aid"] = DELEGATE
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


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


# ── handshake.py: validate before dereferencing (issue #23 item 3, plus a
#    review-round finding) ─────────────────────────────────────────────────
#
# `handshake.py` never calls `verify_envelope()` -- it parses the envelope
# shape itself, inline -- so none of `envelope.py`'s Phase 4 hardening
# covers it. The checks below all run BEFORE any manifest/identity/envelope
# signature verification, so (unlike the identity-type-check case further
# down) they need no minted crypto -- a raw, unminted `verify_handshake_payload`
# call reaches them directly.


def test_handshake_missing_envelope_is_a_structural_rejection() -> None:
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload({"self_aid": ISSUER})
    assert exc.value.code == "INVALID_ENVELOPE"


@pytest.mark.parametrize("envelope", [5, "not-an-object", None, []])
def test_handshake_mistyped_envelope_is_a_structural_rejection(envelope: Any) -> None:
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload({"self_aid": ISSUER, "envelope": envelope})
    assert exc.value.code == "INVALID_ENVELOPE"


def test_handshake_missing_message_type_is_a_structural_rejection() -> None:
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload({"self_aid": ISSUER, "envelope": {}})
    assert exc.value.code == "INVALID_ENVELOPE"


@pytest.mark.parametrize("message_type", [5, None, [], {}])
def test_handshake_mistyped_message_type_is_a_structural_rejection(message_type: Any) -> None:
    """`message_type` as a `list`/`dict` (unhashable) previously raised a raw
    `TypeError` from `mtype in _BOOTSTRAP`, not just `KeyError` for the
    missing case -- both must be a structural `AitpError` now.
    """
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload({"self_aid": ISSUER, "envelope": {"message_type": message_type}})
    assert exc.value.code == "INVALID_ENVELOPE"


def test_handshake_hello_missing_payload_is_a_structural_rejection() -> None:
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload({"self_aid": ISSUER, "envelope": {"message_type": "mutual_hello"}})
    assert exc.value.code == "INVALID_ENVELOPE"


def test_handshake_commit_missing_payload_is_a_structural_rejection() -> None:
    """Same hazard, the dispatcher's own `env["payload"]` dereference for the
    `mutual_commit`/`mutual_commit_ack` branch (distinct code path from the
    bootstrap branch above -- guarded in `verify_handshake_payload` itself,
    not in `_verify_bootstrap`).
    """
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload({"self_aid": ISSUER, "envelope": {"message_type": "mutual_commit"}})
    assert exc.value.code == "INVALID_ENVELOPE"


@pytest.mark.parametrize("sender", ["not-an-object", ["a"], 5, None], ids=["string", "list", "int", "null"])
def test_handshake_hello_mistyped_sender_is_a_structural_rejection(sender: Any, spec_dir: Path) -> None:
    """`env["sender"]`'s first dereference in `_verify_bootstrap` (the
    `manifest.aid != sender.agent_id` comparison) runs AFTER `verify_manifest`
    -- so, like the identity-type-check test below, this needs a genuinely
    valid, minted manifest+envelope to reach; a bare dict input would fail
    manifest verification first and never get here.
    """
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    minted["envelope"]["sender"] = sender
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_handshake_hello_payload_missing_manifest_is_a_structural_rejection() -> None:
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload({
            "self_aid": ISSUER,
            "envelope": {
                "message_type": "mutual_hello",
                "sender": {"agent_id": SUBJECT},
                "payload": {"identity": {}},
            },
        })
    assert exc.value.code == "INVALID_ENVELOPE"


def test_handshake_hello_payload_missing_identity_is_a_structural_rejection(spec_dir: Path) -> None:
    """Unlike the missing-`manifest` case above, an empty `{"manifest": {}}`
    payload can't pin this: an empty manifest fails `verify_manifest`'s own
    structural check (MANIFEST_INVALID) before the code ever reaches
    `payload["identity"]`, so it would mask the very hazard this test needs
    to prove -- a raw `KeyError` from that dereference. Needs a genuinely
    valid, minted manifest (which passes `verify_manifest` cleanly) so the
    code actually reaches the `identity` presence check afterward.
    """
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    del minted["envelope"]["payload"]["identity"]
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_handshake_hello_missing_pop_nonce_with_valid_manifest_is_a_structural_rejection(spec_dir: Path) -> None:
    """Same reasoning as the missing-`identity` case above, for `pop_nonce`:
    needs a genuinely valid, minted manifest+identity (which pass
    `verify_manifest` cleanly) so the code actually reaches
    `verify_identity`'s pinned-key path -- `identity.py::_verify_pinned_key`'s
    own `envelope["payload"]["pop_nonce"]` dereference is what a missing
    `pop_nonce` would otherwise crash on with a raw `KeyError`, if this
    presence check (added for issue #23's Phase-7 sweep finding) didn't catch
    it first. Unlike the identity/manifest guards, this one specifically
    guards a field `test_boundary_contract.py`'s own harness cannot reach --
    `minter.py::_mint_pinned_proof` dereferences the same key during minting,
    so a mutation deleting it there is intercepted (and skipped) before ever
    reaching the verifier, the same minting-time-interception blind spot
    `ASSUMPTIONS.md` already documents for the `manifest.py`/`JcsError` case.
    """
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    del minted["envelope"]["payload"]["pop_nonce"]
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "INVALID_ENVELOPE"


def test_verify_identity_pinned_key_missing_pop_nonce_is_identity_failed_not_a_crash(spec_dir: Path) -> None:
    """Defense in depth for the same hazard as the test above, exercised at
    `identity.verify_identity`'s own public call surface directly --
    bypassing `handshake.py`'s new presence guard entirely, the way
    `test_boundary_contract_identity_never_raises_a_bare_exception` calls
    `verify_identity` directly with no other caller-side guarantee.
    `_verify_pinned_key`'s except tuple now also catches `KeyError`.
    """
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    env = minted["envelope"]
    del env["payload"]["pop_nonce"]
    with pytest.raises(AitpError) as exc:
        verify_identity(
            env["payload"]["identity"],
            env,
            minted.get("self_aid", ""),
            trust_anchors=minted.get("self_trust_anchors"),
            trust_store=minted.get("trust_store"),
            issuer_keys=minted.get("resolved_issuer_keys", {}),
            now=REFERENCE_CLOCK,
        )
    assert exc.value.code == "IDENTITY_FAILED"


@pytest.mark.parametrize("identity", ["not-an-object", ["a"], 5, None])
def test_handshake_hello_mistyped_identity_reports_identity_failed(identity: Any, spec_dir: Path) -> None:
    """Unlike the checks above, this one runs AFTER `verify_manifest` (mh-002/
    mh-003's own "manifest surfaces MANIFEST_* before identity" ordering), so
    it needs a genuinely valid, minted manifest+envelope to reach -- a bare
    dict input would fail manifest verification first and never get here.
    Deliberately `IDENTITY_FAILED`, not `INVALID_ENVELOPE`: this is the same
    code `identity.py`'s own (otherwise unreachable, via this call path)
    non-dict guard uses for the identical defect.
    """
    keys = load_kat_keys(spec_dir)
    inp = _hello_input(ISSUER, SUBJECT)
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    minted["envelope"]["payload"]["identity"] = identity
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "IDENTITY_FAILED"


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


def test_revocation_wrapper_unknown_field_yields_to_body_type_defect() -> None:
    """An unrecognized WRAPPER-level member (a top-level key beside
    `revocation_list`/`signature`) combined with a body-level type defect
    still reports `REVOCATION_SNAPSHOT_INVALID`, not `UNKNOWN_FIELD`.

    `test_revocation_unknown_field_yields_to_a_structural_defect` already
    pins this ordering for a BODY-level unknown member; this pins it
    independently for a WRAPPER-level one, since `reject_unknown_fields` is
    called separately for the wrapper and the body (`revocation.py`'s
    deferred member-set pass), and a refactor that collapsed the two into one
    sweep could pass the body-level case while still getting this one wrong.
    """
    snapshot = {
        "revocation_list": _revocation_body(published_at="nope"),
        "signature": "x",
        "list_owner": "x",  # unrecognized wrapper-level member
    }
    for mode in ("fail_closed", "soft_fail"):
        with pytest.raises(AitpError) as exc:
            verify_revocation_snapshot({
                "policy": {"fail_mode": mode, "max_staleness_secs": 600},
                "now": NOW + 100, "expected_issuer": ISSUER, "snapshot": snapshot,
            })
        assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID", mode


def test_revocation_entry_unknown_field_yields_to_entry_type_defect() -> None:
    """An unrecognized member inside a body-level `entries[]` item, combined
    with a type defect on that SAME entry, still reports
    `REVOCATION_SNAPSHOT_INVALID`, not `UNKNOWN_FIELD`.

    Pins the entry-level ordering dependency (`_typed`/`check_types` on the
    entry running before `reject_unknown_fields` is ever called on it)
    independently of the body-level and wrapper-level cases above -- a
    refactor that fixed those two but left the entry-level check deferred
    ahead of its own type check would still pass both other tests.
    """
    body = _revocation_body(entries=[{"jti": 5, "revoked_at": NOW, "source": "attacker-supplied"}])
    snapshot = {"revocation_list": body, "signature": "x"}
    for mode in ("fail_closed", "soft_fail"):
        with pytest.raises(AitpError) as exc:
            verify_revocation_snapshot({
                "policy": {"fail_mode": mode, "max_staleness_secs": 600},
                "now": NOW + 100, "expected_issuer": ISSUER, "snapshot": snapshot,
            })
        assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID", mode


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
