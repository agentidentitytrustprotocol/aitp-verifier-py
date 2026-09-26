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
import aitp_verifier.jwk as jwk
from aitp_verifier.jwk import _MAX_B64_MEMBER_CHARS, _MAX_CANDIDATES, _MAX_NODES_VISITED, thumbprint_for_aid
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
    inp = {"tct_token": token, "policy": {"fail_mode": "fail_open"}}
    assert verify_tct(inp) == {"grants": ["macp.mode.task.v1"]}


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
    inp = {"self_aid": ISSUER, "delegation_token": token, "policy": {"fail_mode": "fail_open"}}
    result = verify_delegation_token(inp)
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


@pytest.mark.parametrize(
    ("fail_mode", "expected"),
    [
        ("fail_closed", None),
        ("soft_fail", {"revoked": False, "stale": True}),
        ("fail_open", {"revoked": False, "stale": True}),
    ],
)
def test_revocation_absent_snapshot_honors_all_three_fail_modes(
    fail_mode: str, expected: dict[str, Any] | None, spec_dir: Path
) -> None:
    """RFC-AITP-0008 §3.1 defines three modes; stage 4 used to implement two.

    `fail_open` fell through to the same `raise` as an unrecognized mode, so a
    deployment that had explicitly opted into availability-first behavior got
    `fail_closed`'s rejection instead -- a valid mode silently mishandled. No
    conformance fixture exercises `fail_open` (`rev-001`/`003`/`005`-`008` are
    `fail_closed`, `rev-002` is `soft_fail`), which is why it stayed invisible.

    The snapshot here is genuinely signed and structurally perfect; only its
    `published_at` is older than the policy's `max_staleness_secs`, so this is
    the *absent* branch -- the one branch `fail_mode` is allowed to answer.
    `fail_open` shares `soft_fail`'s `stale: True` rather than returning a bare
    `{"revoked": False}`: both mean "proceed on degraded revocation data", and
    dropping `stale` would make a degraded verdict indistinguishable from a
    fully-verified fresh one.
    """
    keys = load_kat_keys(spec_dir)
    inp = _revocation_input(published_at=NOW - 10_000)
    inp["policy"]["fail_mode"] = fail_mode
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    if expected is None:
        with pytest.raises(AitpError) as exc:
            verify_revocation_snapshot(minted)
        assert exc.value.code == "TCT_REVOKED"
    else:
        assert verify_revocation_snapshot(minted) == expected


def test_revocation_unrecognized_fail_mode_is_fail_closed(spec_dir: Path) -> None:
    """Handling `fail_open` explicitly must not turn the fall-through into a
    permissive default: a mode outside §3.1's three still rejects.
    """
    keys = load_kat_keys(spec_dir)
    inp = _revocation_input(published_at=NOW - 10_000)
    inp["policy"]["fail_mode"] = "typo_mode"
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_revocation_fail_open_still_reports_a_listed_jti_as_revoked(spec_dir: Path) -> None:
    """Control for the pair above: `fail_open` answers *absence* only. A fresh,
    trusted, applicable snapshot that lists the queried jti still rejects --
    the mode never suppresses a deny-list hit the verifier actually has.
    """
    keys = load_kat_keys(spec_dir)
    inp = _revocation_input()
    inp["policy"]["fail_mode"] = "fail_open"
    inp["queried_jti"] = "revoked-1"
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot(minted)
    assert exc.value.code == "TCT_REVOKED"


@pytest.mark.parametrize(
    "max_staleness",
    [float("inf"), float("-inf"), float("nan"), "ten minutes", [600], {"secs": 600}],
    ids=["inf", "negative_inf", "nan", "string", "list", "dict"],
)
def test_revocation_unusable_max_staleness_secs_is_stale_not_a_crash(max_staleness: Any, spec_dir: Path) -> None:
    """A hostile `max_staleness_secs` -- this entry point's own top-level call
    argument, not a wire artifact -- used to reach
    `int(policy["max_staleness_secs"])` raw: `float("inf")` raised
    `OverflowError`, `float("nan")` and a non-numeric string raised
    `ValueError`, a list/dict raised `TypeError`. Found during this plan's
    finalization pass -- the identical bug class Phase 3 (`tct.py`) and
    Phase 4 (`delegation.py`) had already found and fixed on their own copy
    of this exact formula, one function away, while this module (the one that
    actually owns RFC-AITP-0008 §3.2) kept the unguarded original. Unusable
    configuration now resolves toward "stale" (status unknown), which
    `fail_mode` then answers, instead of escaping as a raw exception.
    """
    keys = load_kat_keys(spec_dir)
    inp = _revocation_input(published_at=NOW)  # fresh by wall-clock -- only the policy is hostile
    inp["policy"]["max_staleness_secs"] = max_staleness
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_revocation_snapshot(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_revocation_missing_max_staleness_secs_applies_only_the_expires_at_bound(spec_dir: Path) -> None:
    """No `max_staleness_secs` in `policy` means no staleness bound -- only
    `expires_at` governs freshness -- matching `tct.py`/`delegation.py`'s
    already-shipped `snapshot_is_stale` default (``.get(...) is None`` ->
    not stale), not a raw `KeyError`. Before this plan's finalization fix,
    this member was read with a bare `policy["max_staleness_secs"]` and its
    absence escaped uncaught.
    """
    keys = load_kat_keys(spec_dir)
    inp = _revocation_input(published_at=NOW - 10_000)  # would be stale under any nonzero bound
    del inp["policy"]["max_staleness_secs"]
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_revocation_snapshot(minted) == {"revoked": False}


@pytest.mark.parametrize("policy", [None, "fail_closed", 5, [], True], ids=["null", "string", "int", "list", "bool"])
def test_revocation_non_dict_policy_is_an_aitp_error_not_a_crash(policy: Any, spec_dir: Path) -> None:
    """A non-dict `policy` -- this entry point's own top-level call argument,
    the same category as `tct.py`/`delegation.py`'s optional one -- used to
    reach `policy.get("fail_mode", ...)` and `policy["max_staleness_secs"]`
    raw and escape as `AttributeError`/`TypeError`. It now resolves the same
    way a non-dict `policy` resolves on the other two entry points:
    `fail_closed`, with no staleness bound beyond `expires_at`. A fresh,
    unexpired, correctly-issued snapshot with no matching queried jti still
    verifies even under a broken `policy`, since nothing about the snapshot
    itself was untrustworthy.
    """
    keys = load_kat_keys(spec_dir)
    inp = _revocation_input(published_at=NOW)
    inp["policy"] = policy
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    assert verify_revocation_snapshot(minted) == {"revoked": False}


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


@pytest.mark.parametrize("fail_mode", ["soft_fail", "fail_open"], ids=["soft_fail", "fail_open"])
@pytest.mark.parametrize(
    ("defect", "expected_code"),
    [("forged_signature", "REVOCATION_SNAPSHOT_SIGNATURE_INVALID"), ("unknown_member", "UNKNOWN_FIELD")],
)
def test_tct_untrustworthy_snapshot_survives_a_permissive_policy(
    defect: str, expected_code: str, fail_mode: str, spec_dir: Path
) -> None:
    """A snapshot that was OBTAINED and cannot be TRUSTED reports its own
    defect under every `fail_mode`, including the permissive ones.

    RFC-AITP-0008 §1.5 decides trustworthiness before §3.1's `fail_mode` is
    consulted at all; `fail_mode` answers "what if there is no snapshot", never
    "what if the snapshot is malformed". Under `fail_closed` the distinction
    hides -- both routes reject -- so this pins the direction where collapsing
    them is outright unsafe: a forged or §7-MUST-reject snapshot must not be
    downgraded to "merely absent" and waved through because the deployment
    opted into availability-first behavior. The mode is supplied as an explicit
    top-level `policy` (the authoritative source), so this proves the
    highest-precedence permissive setting still cannot reach these branches.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_revocation_input(str(uuid.uuid4()), **({"routing_hint": "x"} if defect == "unknown_member" else {}))
    inp["policy"] = {"fail_mode": fail_mode}
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    if defect == "forged_signature":
        tampered = bytearray(b64url_decode(minted["issuer_revocation_list"]["snapshot"]["signature"]))
        tampered[-1] ^= 0x01
        minted["issuer_revocation_list"]["snapshot"]["signature"] = b64url_encode(bytes(tampered))
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == expected_code


# ── Absence policy (issue #30): `verify_tct` gains an optional top-level
#    `policy` key, spelled exactly as `verify_revocation_snapshot`'s own
#    required one, plus honoring the per-wrapper `issuer_revocation_list.
#    fail_mode` the spec's `tct-004` fixture already carries. The effective
#    mode answers ONE question -- what to do when no trusted, applicable,
#    fresh snapshot was supplied -- in this precedence: (1) a top-level
#    `policy` is authoritative; (2) else the wrapper's `fail_mode`; (3) else
#    `fail_open`, today's behavior byte for byte. ─────────────────────────


def _tct_policy_input(**policy: Any) -> dict[str, Any]:
    """A `verify_tct` input carrying a top-level `policy` and **no**
    `issuer_revocation_list` at all -- absence case (a), the plainest input the
    effective `fail_mode` answers for.

    `**policy` builds the policy object, mirroring the
    `inp["policy"]["fail_mode"]` shape `_revocation_input` already establishes
    for `verify_revocation_snapshot`: the new key is deliberately the same
    spelling, not a second one. Called with no arguments it yields
    `policy: {}`, which is itself a case -- an explicitly supplied policy with
    no `fail_mode` fails closed, matching `revocation.py`'s own
    `policy.get("fail_mode", "fail_closed")`.
    """
    return {"tct_token": "__JWS_TCT__", "tct_token_claims": _tct_claims(), "policy": dict(policy)}


def _tct_different_issuer_input(**wrapper_overrides: Any) -> dict[str, Any]:
    """`_tct_revocation_input`'s wrapper, re-issued by a *different* peer:
    genuinely signed and listing this TCT's jti, but by `SUBJECT` rather than
    the TCT's own `iss`. Absence case (b) -- a valid snapshot that does not
    speak for this issuer leaves this TCT's status unknown. Keeping the TCT's
    own jti on its deny list is what makes the applicability skip observable:
    were the signed issuer ignored, this would revoke.
    """
    inp = _tct_revocation_input(str(uuid.uuid4()))
    inp["issuer_revocation_list"]["issuer"] = SUBJECT
    inp["issuer_revocation_list"]["snapshot"]["revocation_list"]["issuer"] = SUBJECT
    inp["issuer_revocation_list"].update(wrapper_overrides)
    return inp


def _tct_applicable_snapshot_input(**body_overrides: Any) -> dict[str, Any]:
    """A wrapper whose snapshot is genuinely signed by the TCT's own issuer and
    lists someone *else's* jti, so the deny-list scan finds nothing and only
    the absence rules (staleness, expiry) can change the outcome.
    """
    inp = _tct_revocation_input(str(uuid.uuid4()))
    body = inp["issuer_revocation_list"]["snapshot"]["revocation_list"]
    body["entries"] = [{"jti": "someone-elses-tct", "revoked_at": NOW}]
    body.update(body_overrides)
    return inp


def test_tct_no_policy_and_no_snapshot_raises_key_error(spec_dir: Path) -> None:
    """Resolution rule 3, stated as its own test rather than left to the
    unrelated assertions that happen to cover it: with no `policy` key and no
    `issuer_revocation_list`, `verify_tct` made no revocation decision at
    all, and raises `KeyError("policy")` rather than silently defaulting to
    `fail_open` -- a `/reconcile` reversal of this module's own initial
    design (see `ASSUMPTIONS.md`/`DECISIONS.md`), applied before any real
    caller could depend on the permissive default. The spec's own `tct-012`
    (`required_for_v0_2`) is exactly this input shape; `run_conformance.py`
    supplies the deployment's own policy for it rather than editing the
    fixture, the same role it already plays for other call-time-only inputs.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_policy_input()
    del inp["policy"]
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(KeyError):
        verify_tct(minted)


def test_tct_policy_fail_closed_with_no_snapshot_is_revoked(spec_dir: Path) -> None:
    """Issue #30's headline: RFC-AITP-0008 §3.1's "an absent snapshot means
    revocation status is unknown, and unknown is treated as revoked". Before
    this phase a TCT whose `jti` genuinely sat on an unreachable deny list
    verified successfully no matter what the deployment had configured.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_policy_input(fail_mode="fail_closed"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_tct_policy_without_a_fail_mode_defaults_to_fail_closed(spec_dir: Path) -> None:
    """`policy: {}` is enough to opt in. Secure-by-default *within* an
    explicitly supplied policy -- the same `policy.get("fail_mode",
    "fail_closed")` `revocation.py` has always applied. The permissive default
    lives one level up, at "no `policy` key at all", not inside a policy the
    caller took the trouble to supply.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_policy_input(), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


@pytest.mark.parametrize("fail_mode", ["soft_fail", "fail_open"])
def test_tct_policy_permissive_mode_with_no_snapshot_verifies(fail_mode: str, spec_dir: Path) -> None:
    """§3.1's two availability-first modes. The verdict stays exactly
    `{"grants": [...]}` -- no `stale` member is added, deliberately:
    `verify_tct` returns no grant-restriction surface for a caller to act on,
    so `soft_fail` and `fail_open` are indistinguishable here.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_policy_input(fail_mode=fail_mode), REFERENCE_CLOCK, keys)
    assert verify_tct(minted) == {"grants": ["macp.mode.task.v1"]}


def test_tct_policy_unrecognized_mode_is_fail_closed(spec_dir: Path) -> None:
    """A misspelled or future mode is never silently permissive."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_policy_input(fail_mode="typo_mode"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


@pytest.mark.parametrize("junk", ["not-an-object", 5, ["fail_open"], None], ids=["string", "int", "list", "none"])
def test_tct_policy_non_dict_is_fail_closed_not_a_crash(junk: Any, spec_dir: Path) -> None:
    """A `policy` that is not an object at all resolves to `fail_closed` --
    `AitpError`, never a raw `AttributeError` out of a bare `.get()` on a
    string. `None` is included on purpose: the key was supplied, so the
    malformed value is answered strictly rather than read as "no policy".
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_policy_input()
    inp["policy"] = junk
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


@pytest.mark.parametrize("junk", [5, None, [], True], ids=["int", "none", "list", "bool"])
def test_tct_policy_non_str_fail_mode_is_fail_closed(junk: Any, spec_dir: Path) -> None:
    """A present-but-wrong-typed `fail_mode` lands on `fail_closed`, exactly
    where a misspelled one does.

    The obvious spelling -- an `isinstance(..., str)` guard that falls through
    to the caller's default -- would send `fail_mode: 5` to the *permissive*
    default while `"fail_klosed"` failed closed: the more broken input treated
    more leniently, which is backwards. `True` is in the sweep because
    `bool` is a `str`-adjacent trap in the other direction (it is an `int`, and
    an `in`-based check against the mode set would not save it either).
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_policy_input(fail_mode=junk), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


@pytest.mark.parametrize("junk", [5, None, [], True], ids=["int", "none", "list", "bool"])
def test_tct_wrapper_non_str_fail_mode_is_fail_closed(junk: Any, spec_dir: Path) -> None:
    """The same rule on the other source: a wrapper carrying a wrong-typed
    `fail_mode`, with no top-level `policy` to outrank it, resolves to
    `fail_closed` rather than falling back to rule 3's `fail_open`.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_different_issuer_input(fail_mode=junk), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_tct_wrapper_misspelled_fail_mode_is_fail_closed(spec_dir: Path) -> None:
    """The `str`-typed half of the rule above, which the wrong-typed sweep
    cannot reach: a wrapper `fail_mode` that IS a string but is not one of
    §3.1's three (`"fail_klosed"`) resolves to `fail_closed`, not to rule 3's
    `fail_open` fall-through.

    Worth its own case because the two halves fail differently under the
    tempting alternative implementation: an `isinstance(..., str)` guard that
    falls through to the default would send `fail_mode: 5` to `fail_open`
    while catching this one, so only a membership check against the mode set
    -- which is what `revocation.py::resolve_fail_mode` does -- gets both right.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_different_issuer_input(fail_mode="fail_klosed"), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_tct_wrapper_without_a_fail_mode_and_no_policy_raises_key_error(spec_dir: Path) -> None:
    """Resolution rule 3 reached through a *present* wrapper, rather than
    through no `issuer_revocation_list` at all: the wrapper exists but
    declares no `fail_mode`, and no top-level `policy` was supplied -- no
    decision was made through either channel, so this raises `KeyError`
    rather than falling through to `fail_open` (the `/reconcile` reversal;
    see `ASSUMPTIONS.md`/`DECISIONS.md`).

    The `del` is the point of the test -- `_tct_revocation_input`'s wrapper
    always carries `fail_mode: "fail_closed"` (mirroring `tct-004-revoked`),
    so without removing it rule 2 would answer and rule 3's `in`-check
    (`"fail_mode" in revlist`) would never be exercised on a dict that lacks
    the key.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_different_issuer_input()
    del inp["issuer_revocation_list"]["fail_mode"]
    assert "policy" not in inp
    with pytest.raises(KeyError):
        verify_tct(mint_input(inp, REFERENCE_CLOCK, keys))


@pytest.mark.parametrize("wrapper_mode", ["soft_fail", "fail_open"])
def test_tct_wrapper_fail_mode_cannot_downgrade_an_explicit_policy(wrapper_mode: str, spec_dir: Path) -> None:
    """**The security-relevant precedence direction.** A supplied top-level
    `policy` is authoritative and cannot be overridden by the input artifact.

    `issuer_revocation_list.fail_mode` is an *unsigned* member of the
    caller-supplied wrapper -- the snapshot signature covers only the inner
    `revocation_list` body, as `tct-004`'s own `$comment` says ("the
    `{revocation_list, signature}` envelope is the wire shape and is never
    signed"). For a real integrator that wrapper is a remote `ListRevoked`
    response with a locally-added envelope. If it outranked the top-level
    `policy`, a deployment that had explicitly configured `fail_closed` could
    be silently downgraded to `soft_fail`/`fail_open` by whatever assembled the
    wrapper -- a remotely-triggerable downgrade of a configured security
    posture, and exactly what this module already refuses for the sibling
    unsigned member `issuer_revocation_list["issuer"]`.

    This test is the one that pins that correction: invert the two branches in
    `_effective_fail_mode` and it fails (the wrapper's permissive mode wins and
    the TCT verifies), which is what makes it non-vacuous rather than merely
    green. The companion direction -- the wrapper IS honored when no `policy`
    was supplied -- is pinned by the two `different_issuer` tests below.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_different_issuer_input(fail_mode=wrapper_mode)
    inp["policy"] = {"fail_mode": "fail_closed"}
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_tct_revocation_snapshot_different_issuer_under_wrapper_fail_closed_is_revoked(spec_dir: Path) -> None:
    """A snapshot genuinely signed, but by an issuer other than this TCT's own
    `iss`, does not speak for it: the deny-list scan is skipped (the snapshot
    is not a defect -- it may be perfectly valid, just for a different issuer),
    leaving this TCT's revocation status **unknown**.

    This test asserted plain success before this phase, because the wrapper's
    declared `fail_mode` was never read at all. It supplies no top-level
    `policy`, so resolution rule 2 governs and `_tct_revocation_input`'s own
    `fail_mode: "fail_closed"` -- the member `tct-004-revoked.json` ships --
    is honored: unknown status under `fail_closed` is treated as revoked. The
    `soft_fail` half of the same input is pinned immediately below, so the
    applicability skip itself is still proven to work rather than merely
    replaced by a rejection.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_different_issuer_input(), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_tct_revocation_snapshot_different_issuer_under_wrapper_soft_fail_verifies(spec_dir: Path) -> None:
    """The other half of the flipped case, and rule 2's permissive direction:
    the identical wrapper with `fail_mode: "soft_fail"` still verifies. The
    wrong-issuer snapshot lists this TCT's own jti, so a verifier that had
    quietly dropped the signed-issuer applicability check would revoke here --
    success is a real pass of the skip, not an absence of checking.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_tct_different_issuer_input(fail_mode="soft_fail"), REFERENCE_CLOCK, keys)
    assert verify_tct(minted) == {"grants": ["macp.mode.task.v1"]}


@pytest.mark.parametrize(
    ("body_override", "policy_extra"),
    [
        ({"published_at": NOW - 10_000}, {"max_staleness_secs": 600}),
        ({"expires_at": NOW - 1}, {}),
    ],
    ids=["stale_beyond_max_staleness_secs", "expired"],
)
def test_tct_policy_stale_or_expired_snapshot_is_absent(
    body_override: dict[str, Any], policy_extra: dict[str, Any], spec_dir: Path
) -> None:
    """RFC-AITP-0008 §3.2's freshness rule, the same formula `revocation.py`'s
    stage 4 applies: a trusted, applicable snapshot the deployment considers
    too old gives this verifier no usable revocation data, so it is *absent*
    and the effective mode answers. Both bounds are covered -- the snapshot's
    own `expires_at`, and the deployment's `max_staleness_secs` against
    `published_at`.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_applicable_snapshot_input(**body_override)
    inp["policy"] = {"fail_mode": "fail_closed", **policy_extra}
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"

    soft = _tct_applicable_snapshot_input(**body_override)
    soft["policy"] = {"fail_mode": "soft_fail", **policy_extra}
    assert verify_tct(mint_input(soft, REFERENCE_CLOCK, keys)) == {"grants": ["macp.mode.task.v1"]}


def test_tct_fresh_applicable_snapshot_under_fail_closed_still_verifies(spec_dir: Path) -> None:
    """Control for the pair above: `fail_closed` answers *absence* only. A
    fresh, trusted, applicable snapshot that simply does not list this TCT's
    jti verifies normally -- the strictest mode must not turn "checked and
    clean" into a rejection, or the whole policy would be a constant.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_applicable_snapshot_input()
    inp["policy"] = {"fail_mode": "fail_closed", "max_staleness_secs": 600}
    assert verify_tct(mint_input(inp, REFERENCE_CLOCK, keys)) == {"grants": ["macp.mode.task.v1"]}


@pytest.mark.parametrize(
    "max_staleness",
    [float("inf"), float("-inf"), float("nan"), "ten minutes", [600], {"secs": 600}],
    ids=["inf", "negative_inf", "nan", "string", "list", "dict"],
)
def test_tct_policy_unusable_max_staleness_secs_is_stale_not_a_crash(max_staleness: Any, spec_dir: Path) -> None:
    """An unparseable `max_staleness_secs` resolves toward "status unknown" --
    an `AitpError`, never a raw exception out of `verify_tct`.

    `inf`/`-inf` are the reason this is a regression test and not just a
    coverage filler: `json.loads` parses a bare `Infinity`/`-Infinity` by
    default, so a JSON-sourced `policy` reaches `int(max_staleness)` with a
    float infinity, on which `int()` raises `OverflowError` -- which is
    neither `TypeError` nor `ValueError`, and so escaped `verify_tct` raw,
    breaking the "raise `AitpError` or return a verdict" boundary contract
    every entry point owes its caller (issue #31's bug class). `nan` and the
    non-numeric string take the `ValueError` route, the list and dict the
    `TypeError` route, so all three arms of the except tuple are pinned here.
    (A *numeric* string is deliberately not in this sweep: `int("600")`
    succeeds, so it is a usable bound, not an unusable one.)

    The snapshot is fresh, trusted, applicable and does NOT list this TCT's
    jti, so under `fail_closed` the only path to `TCT_REVOKED` is the
    unusable bound being treated as stale -- making the assertion prove the
    intended direction (toward absence) rather than merely "some error".
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_applicable_snapshot_input()
    inp["policy"] = {"fail_mode": "fail_closed", "max_staleness_secs": max_staleness}
    minted = mint_input(inp, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_tct_policy_without_max_staleness_secs_applies_only_the_expires_at_bound(spec_dir: Path) -> None:
    """A supplied `policy` that omits `max_staleness_secs` sets no age bound at
    all: the snapshot's own `expires_at` is still enforced, but `published_at`
    is simply not consulted.

    The snapshot here was published far outside any plausible staleness window
    yet is not expired, and it verifies under `fail_closed` -- so the
    `max_staleness is None` early return is doing real work, rather than the
    case coincidentally passing because the snapshot is fresh on both bounds.
    The expiry half of the same policy shape is pinned by
    `test_tct_policy_stale_or_expired_snapshot_is_absent`'s `expired` case,
    which supplies no `max_staleness_secs` either.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_applicable_snapshot_input(published_at=NOW - 10_000, expires_at=NOW + 3600)
    inp["policy"] = {"fail_mode": "fail_closed"}
    assert verify_tct(mint_input(inp, REFERENCE_CLOCK, keys)) == {"grants": ["macp.mode.task.v1"]}


def test_tct_non_dict_policy_with_a_snapshot_present_still_governs_as_fail_closed(spec_dir: Path) -> None:
    """The non-dict-`policy` rule, reached with a trusted, applicable snapshot
    actually present -- the branch the existing non-dict sweep cannot reach,
    since it supplies no `issuer_revocation_list` at all and so returns at
    absence case (a) before the freshness gate is ever read.

    Two directions, because "present" is not by itself an answer. A snapshot
    that is fresh and clean is real revocation data, so the TCT verifies (and
    the `policy if isinstance(policy, dict) else {}` guard hands
    `revocation.py::snapshot_is_stale` an empty dict instead of `.get()`-ing a string). An
    *expired* one is not usable data, so the unreadable policy's `fail_closed`
    governs and the TCT is rejected -- a snapshot merely being in the input
    must not buy silent success. `max_staleness_secs` is unreachable through a
    non-dict `policy`, so `expires_at` is the only bound that can apply here.
    """
    keys = load_kat_keys(spec_dir)
    fresh = _tct_applicable_snapshot_input()
    fresh["policy"] = "not-an-object"
    assert verify_tct(mint_input(fresh, REFERENCE_CLOCK, keys)) == {"grants": ["macp.mode.task.v1"]}

    expired = _tct_applicable_snapshot_input(expires_at=NOW - 1)
    expired["policy"] = "not-an-object"
    minted = mint_input(expired, REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_tct(minted)
    assert exc.value.code == "TCT_REVOKED"


def test_tct_staleness_is_not_evaluated_without_a_top_level_policy(spec_dir: Path) -> None:
    """Freshness is gated on a top-level `policy` being supplied, and that
    gating is deliberate rather than incidental -- it is what makes this diff
    auditable: with no `policy` key, `verify_tct` behaves exactly as it did for
    every input that reaches it.

    The wrapper here carries `fail_mode: "fail_closed"` and its snapshot is
    both expired and far staler than any plausible bound, yet the TCT verifies:
    the wrapper's `fail_mode` selects what happens *on* absence, it does not
    switch on freshness evaluation, because `max_staleness_secs` is a
    deployment value with no per-wrapper spelling in the fixture shape. Pass a
    `policy` and the same input rejects -- pinned directly above.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_applicable_snapshot_input(published_at=NOW - 10_000, expires_at=NOW - 1)
    assert "policy" not in inp
    assert inp["issuer_revocation_list"]["fail_mode"] == "fail_closed"
    assert verify_tct(mint_input(inp, REFERENCE_CLOCK, keys)) == {"grants": ["macp.mode.task.v1"]}


def test_tct_policy_fail_open_does_not_suppress_a_genuine_deny_list_hit(spec_dir: Path) -> None:
    """The deny-list scan is untouched by any of this: a fresh, trusted,
    applicable snapshot listing this TCT's jti still reports `TCT_REVOKED` for
    the real reason, even under the *most permissive* explicit policy
    (`fail_open`) -- the mode answers absence, never a hit the verifier
    actually has. The without-policy direction is not re-proven here; it is
    already pinned by
    `test_tct_revocation_snapshot_genuinely_signed_and_matching_issuer_revokes`,
    which runs the identical wrapper with no `policy` key at all.
    """
    keys = load_kat_keys(spec_dir)
    inp = _tct_revocation_input(str(uuid.uuid4()))
    inp["policy"] = {"fail_mode": "fail_open", "max_staleness_secs": 600}
    with pytest.raises(AitpError) as exc:
        verify_tct(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "TCT_REVOKED"


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


@pytest.mark.parametrize(
    "junk",
    [5, True, 1.5, "", 0, False, {}, 0.0],
    ids=["int", "bool", "float", "empty-str", "zero", "false", "empty-dict", "zero-float"],
)
def test_delegation_revocation_snapshots_container_scalar_is_rejected_not_a_crash(junk: Any, spec_dir: Path) -> None:
    """`revocation_snapshots` itself is untrusted remote input, same as any
    record inside it. A truthy scalar there would otherwise survive
    `inp.get("revocation_snapshots", []) or []` and reach the `for` loop as a
    bare `TypeError: '...' object is not iterable`; a falsy-but-present
    scalar (`""`, `0`, `False`, `{}`, `0.0`) would otherwise be silently
    folded into "no snapshots" by that same `or []` and never even reach a
    type check. Both escape this module's own `AitpError`-or-verdict
    contract unless `None`-vs-anything-else is checked explicitly rather
    than by truthiness.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "del-mh-004"), REFERENCE_CLOCK, keys)
    minted["revocation_snapshots"] = junk
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


def test_delegation_revocation_snapshots_genuinely_absent_is_accepted_not_rejected(spec_dir: Path) -> None:
    """The one legitimate falsy case: the field is not present at all. This
    must default to "no snapshots" and verify successfully, distinguishing
    it from the malformed-falsy cases above (`""`/`0`/`False`/`{}`/`0.0`),
    which must all still raise. Proves the fix checks `is None`, not
    truthiness.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "del-mh-004"), REFERENCE_CLOCK, keys)
    del minted["revocation_snapshots"]
    minted["policy"] = {"fail_mode": "fail_open"}
    verify_delegation_token(minted)


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
    minted["policy"] = {"fail_mode": "fail_open"}
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


# ── Single-hop source-TCT revocation (RFC-AITP-0006 §4 step 7). The
#    single-hop path used to perform NO revocation check at all: a present,
#    structurally valid, correctly-signed snapshot from `self_aid` listing the
#    voucher's own `src_jti` was silently ignored and the delegation verified.
#    That is not the "absent snapshot" question (RFC-AITP-0008 §3.1's
#    `fail_mode`, deliberately untouched here) -- it is trusted evidence being
#    computed by `_revocation_index` and then never consulted. §4:111 ("Look up
#    `voucher.src_jti` in A's own deny list ... MUST be rejected =>
#    DELEGATION_SOURCE_TCT_REVOKED") is a MUST on the core, required_for_v0_2
#    path (del-001), and §4:97/RFC-AITP-0008 §3.3 fix its position: after every
#    signature check. ────────────────────────────────────────────────────────

# `del-001`'s own voucher `src_jti` -- the source TCT whose revocation §4 step 7
# looks up. Pinned as a constant so each test below can assert against the
# fixture's real handle rather than a jti it invented itself.
DEL_001_SRC_JTI = "550e8400-e29b-41d4-a716-446655440101"


def _single_hop_revoked_input(
    spec_dir: Path, *, entry_jti: str = DEL_001_SRC_JTI, snapshot_issuer: str = ISSUER
) -> dict[str, Any]:
    """`del-001`'s single-hop input plus one to-be-minted `revocation_snapshots`
    record listing *entry_jti* as revoked, genuinely signed by *snapshot_issuer*.

    Built on the conformance fixture (via `_load_conformance_input`) rather than
    hand-rolled, the same reuse the multi-hop tests above make of `del-mh-004`:
    `del-001` already proves a valid single-hop token end to end, and every test
    here only needs to vary its revocation data. The record shape is the one
    `del-mh-004` and `PLACEHOLDERS.md` pin -- `{issuer_aid, snapshot}` -- and
    `minter.py` signs the inner `revocation_list` body under whichever AID that
    body's own `issuer` names, so `snapshot_issuer` produces a *genuinely*
    signed snapshot for that peer, never a forgery.
    """
    inp = _load_conformance_input(spec_dir, "del-001")
    # Pin the fixture's own pre-conditions: A (self) is the deny list's owner,
    # and the voucher's src_jti is the handle §4 step 7 looks up.
    assert inp["self_aid"] == ISSUER
    assert inp["delegation_token_claims"]["voucher_claims"]["src_jti"] == DEL_001_SRC_JTI
    # `policy` is now mandatory (a revocation decision is required -- see
    # `/reconcile` on `plans/hardening-issues-30-31.md`). Every test built on
    # this helper supplies genuine, present deny-list data and is testing
    # whether it's consulted correctly, not the absence case -- `fail_open`
    # is inert here, the same as any other mode would be.
    inp["policy"] = {"fail_mode": "fail_open"}
    inp["revocation_snapshots"] = [
        {
            "issuer_aid": snapshot_issuer,
            "snapshot": {
                "revocation_list": _revocation_body(
                    issuer=snapshot_issuer, entries=[{"jti": entry_jti, "revoked_at": NOW}]
                ),
                "signature": "__VALID_B_SIG__",
            },
        }
    ]
    return inp


def test_delegation_single_hop_revoked_source_tct_is_rejected(spec_dir: Path) -> None:
    """The live bypass this phase closes. `del-001` verifies successfully today
    (`{"grants": ["read_data"]}`) *even with* a fully trusted snapshot from A
    (== self_aid) listing the voucher's `src_jti` -- the single-hop path never
    consulted the deny list `_revocation_index` was already able to compute.
    Hand-verified non-vacuous: on pre-fix code this exact input returns
    `{"grants": ["read_data"]}`.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_single_hop_revoked_input(spec_dir), REFERENCE_CLOCK, keys)
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


def test_delegation_single_hop_unrelated_revoked_jti_still_verifies(spec_dir: Path) -> None:
    """Negative control on the jti: A's deny list is genuine and applicable, but
    lists someone else's jti. A verifier that rejected on the mere presence of a
    deny list (rather than on a hit in it) would pass the test above for the
    wrong reason -- this is what separates the two.
    """
    keys = load_kat_keys(spec_dir)
    inp = _single_hop_revoked_input(spec_dir, entry_jti="550e8400-e29b-41d4-a716-4466554409ff")
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == {"grants": ["read_data"]}


def test_delegation_single_hop_snapshot_from_another_issuer_does_not_apply(spec_dir: Path) -> None:
    """Negative control on the issuer: the deny list consulted is A's OWN
    (`revoked.get(self_aid, ...)`), not any deny list anyone hands the verifier.
    A snapshot genuinely signed by B, listing this voucher's `src_jti`, is
    indexed under B's *verified* `body["issuer"]` and never reaches A's lookup
    -- B cannot revoke a TCT A issued. This is the difference between "consult
    A's deny list" and "consult any deny list supplied", and it is the property
    the index's signed-issuer keying buys for free.
    """
    keys = load_kat_keys(spec_dir)
    inp = _single_hop_revoked_input(spec_dir, snapshot_issuer=SUBJECT)
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == {"grants": ["read_data"]}


def test_delegation_single_hop_forged_snapshot_signature_is_rejected(spec_dir: Path) -> None:
    """Routing single-hop through `_revocation_index` gives it the same
    snapshot-trust guarantee the multi-hop path has (issue #24): the snapshot is
    structurally validated, member-set checked and signature-verified before its
    `entries` are read. One flipped signature byte must surface
    `REVOCATION_SNAPSHOT_SIGNATURE_INVALID`, not the `DELEGATION_SOURCE_TCT_REVOKED`
    a face-value read of `entries` would (correctly, by accident) still report.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_single_hop_revoked_input(spec_dir), REFERENCE_CLOCK, keys)
    tampered = bytearray(b64url_decode(minted["revocation_snapshots"][0]["snapshot"]["signature"]))
    tampered[-1] ^= 0x01
    minted["revocation_snapshots"][0]["snapshot"]["signature"] = b64url_encode(bytes(tampered))
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_SIGNATURE_INVALID"


def test_delegation_single_hop_scope_check_precedes_revocation(spec_dir: Path) -> None:
    """RFC-AITP-0006 §4's step order, pinned by an input that fails two steps at
    once: the scope subset check is step 6 and the source-TCT revocation lookup
    is step 7, so a token whose scope exceeds the voucher grants AND whose
    source TCT is revoked must report `DELEGATION_SCOPE_EXCEEDED`. Placing the
    new lookup anywhere earlier would flip this code.
    """
    keys = load_kat_keys(spec_dir)
    inp = _single_hop_revoked_input(spec_dir)
    inp["delegation_token_claims"]["scope"] = ["admin"]  # not in voucher grants
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SCOPE_EXCEEDED"


# ── `verify_delegation_token`'s absence policy (RFC-AITP-0008 §3.1, issue #30).
#    The same optional top-level `policy` key `verify_tct` takes, answering the
#    same question for the analogous case: A supplied no trusted, applicable
#    revocation snapshot of its *own*, so the source TCT's status is unknown.
#    Resolution is `tct.py`'s minus its per-wrapper rung, which has no spelling
#    on this path: (1) a top-level `policy` (default `fail_closed` within it);
#    (2) else `fail_open`, today's behavior byte for byte.
#
#    EVERY case below runs against BOTH entry paths -- `del-001` (single-hop,
#    required_for_v0_2) and `del-mh-001` (multi-hop, draft opt-in) -- from one
#    parametrized test body, not two hand-written ones. That is deliberate and
#    is the point of the block: the bug this plan closes was two call sites
#    answering the same RFC step separately, so "both paths honor one policy"
#    has to be asserted as one assertion run twice, never as two assertions
#    that happen to agree today. `delegation.py` backs that with one
#    `_check_source_tct_revocation` both paths call. ─────────────────────────

# Both success fixtures supply NO revocation data at all, which is what makes
# them the absence case straight from the spec's own pack -- and what makes
# `fail_open` (not §3.1's `fail_closed`) the only possible no-policy default.
_BOTH_DELEGATION_PATHS = pytest.mark.parametrize(
    "fixture_id", ["del-001", "del-mh-001"], ids=["single-hop", "multi-hop"]
)
_DELEGATION_GRANTS = {"grants": ["read_data"]}

# The `src_jti` each path's root voucher carries -- the source TCT handle §4
# step 7 / RFC-AITP-0011 §6 look up in A's own deny list.
DEL_MH_001_SRC_JTI = "550e8400-e29b-41d4-a716-446655443001"
_SRC_JTI = {"del-001": DEL_001_SRC_JTI, "del-mh-001": DEL_MH_001_SRC_JTI}


def _delegation_policy_input(spec_dir: Path, fixture_id: str, **policy: Any) -> dict[str, Any]:
    """Either path's own success fixture plus a top-level `policy` and no
    revocation data whatsoever -- the plainest absence case the effective
    `fail_mode` answers.

    `**policy` builds the policy object, the same spelling `_tct_policy_input`
    and `_revocation_input` already use: one key shape across all three entry
    points, deliberately not a third. Called with no keyword arguments it
    yields `policy: {}`, which is itself a case -- an explicitly supplied
    policy with no `fail_mode` fails closed.
    """
    inp = _load_conformance_input(spec_dir, fixture_id)
    # Pin the fixtures' own pre-conditions: A (self) owns the deny list these
    # tests are about, its `src_jti` is the handle looked up, and neither
    # fixture ships revocation data -- so "absent" is the fixture's shape, not
    # something this helper deleted.
    assert inp["self_aid"] == ISSUER
    assert "revocation_snapshots" not in inp
    inp["policy"] = dict(policy)
    return inp


def _delegation_snapshot_record(
    issuer: str = ISSUER, entries: list[dict[str, Any]] | None = None, **body_overrides: Any
) -> dict[str, Any]:
    """One to-be-minted `{issuer_aid, snapshot}` record -- the shape
    `PLACEHOLDERS.md` and `del-mh-004` pin -- genuinely signed by *issuer*.

    `minter.py::_sign_revocation` signs the inner `revocation_list` under
    whichever AID that body's own `issuer` names, so a record built here is
    always a real signature by that peer, never a forgery: an "absent for
    `self_aid`" verdict over one of these is a genuine applicability decision,
    not a trust failure in disguise.
    """
    body = _revocation_body(issuer=issuer, entries=entries if entries is not None else [])
    body.update(body_overrides)
    return {"issuer_aid": issuer, "snapshot": {"revocation_list": body, "signature": "__VALID_B_SIG__"}}


@_BOTH_DELEGATION_PATHS
def test_delegation_absent_snapshot_fail_closed_rejects(fixture_id: str, spec_dir: Path) -> None:
    """Issue #30 on this entry point: RFC-AITP-0008 §3.1's "an absent snapshot
    means revocation status is unknown, and unknown is treated as revoked".
    Before this phase a delegation whose source TCT genuinely sat on an
    unreachable deny list verified successfully no matter what the deployment
    had configured.

    The message assertion is what pins *which* branch raised: this is the
    absence branch, not a deny-list hit -- there is no deny list here to hit.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="fail_closed")
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"
    assert "fail_closed treats unknown revocation status as revoked" in exc.value.message


@_BOTH_DELEGATION_PATHS
def test_delegation_absent_snapshot_fail_closed_by_default_within_a_supplied_policy(
    fixture_id: str, spec_dir: Path
) -> None:
    """`policy: {}` is enough to opt in. Secure-by-default *within* an
    explicitly supplied policy -- the same `policy.get("fail_mode",
    "fail_closed")` `revocation.py` has always applied and `verify_tct` now
    applies. The permissive default lives one level up, at "no `policy` key at
    all", never inside a policy the caller took the trouble to supply.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id)
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


@_BOTH_DELEGATION_PATHS
def test_delegation_absent_snapshot_soft_fail_verifies(fixture_id: str, spec_dir: Path) -> None:
    """§3.1's first availability-first mode. The verdict stays exactly
    `{"grants": [...]}` -- no `stale` member is added, deliberately:
    `verify_delegation_token` exposes no grant-restriction surface for a caller
    to act on, so `soft_fail` and `fail_open` are indistinguishable here, the
    same call `verify_tct` makes.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="soft_fail")
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == _DELEGATION_GRANTS


@_BOTH_DELEGATION_PATHS
def test_delegation_absent_snapshot_fail_open_verifies(fixture_id: str, spec_dir: Path) -> None:
    """§3.1's second availability-first mode, spelled explicitly rather than
    left to the no-policy default it coincides with."""
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="fail_open")
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == _DELEGATION_GRANTS


@_BOTH_DELEGATION_PATHS
def test_delegation_absent_snapshot_no_policy_raises_key_error(
    fixture_id: str, spec_dir: Path
) -> None:
    """Resolution rule 2, as its own test rather than left to the conformance
    runner: with no `policy` key at all, this entry point has no fallback
    source for a decision (unlike `tct.py`'s wrapper rung), so it raises
    `KeyError("policy")` rather than silently defaulting to `fail_open` -- a
    `/reconcile` reversal of this module's own initial design (see
    `ASSUMPTIONS.md`/`DECISIONS.md`), applied before any real caller could
    depend on the permissive default. `del-001`/`del-mh-001` are both
    success fixtures shipping exactly this input shape;
    `run_conformance.py` supplies the deployment's own policy for them
    rather than editing the fixtures, the same role it already plays for
    other call-time-only inputs.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id)
    del inp["policy"]
    with pytest.raises(KeyError):
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))


@_BOTH_DELEGATION_PATHS
def test_delegation_no_policy_with_a_fresh_applicable_snapshot_still_raises_key_error(
    fixture_id: str, spec_dir: Path
) -> None:
    """Regression guard for `_check_source_tct_revocation`'s eager, not lazy,
    resolution -- distinct from the sibling test above, which supplies no
    revocation data at all and so cannot tell eager and lazy resolution
    apart (both reach the same absence branch either way).

    Here `applicable` is genuinely non-empty: a fresh, self-signed snapshot
    for `self_aid` that lists nothing, so absent lazy resolution the
    function would never reach the branch that calls `_effective_fail_mode`
    at all and would return successfully with `policy` never having been
    consulted -- exactly the "caller with always-fresh snapshots discovers
    the missing key only in production, on the first stale day" gap the
    module docstring records `/reconcile` closing. With `policy` resolved
    eagerly, this still raises `KeyError("policy")` immediately.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id)
    del inp["policy"]
    inp["revocation_snapshots"] = [_delegation_snapshot_record(issuer=ISSUER, entries=[])]
    with pytest.raises(KeyError):
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))


@_BOTH_DELEGATION_PATHS
def test_delegation_absent_snapshot_unknown_mode_rejects(fixture_id: str, spec_dir: Path) -> None:
    """A misspelled or future mode is never silently permissive."""
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="typo_mode")
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


@_BOTH_DELEGATION_PATHS
@pytest.mark.parametrize("junk", ["not-an-object", 5, ["fail_open"], None], ids=["string", "int", "list", "none"])
def test_delegation_absent_snapshot_non_dict_policy_rejects(
    junk: Any, fixture_id: str, spec_dir: Path
) -> None:
    """A `policy` that is not an object at all resolves to `fail_closed` --
    `AitpError`, never a raw `AttributeError` out of a bare `.get()` on a
    string. `None` is included on purpose: the key was supplied, so the
    malformed value is answered strictly rather than read as "no policy".
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id)
    inp["policy"] = junk
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


@_BOTH_DELEGATION_PATHS
@pytest.mark.parametrize("fail_mode", [5, None, [], True], ids=["int", "none", "list", "bool"])
def test_delegation_absent_snapshot_non_str_fail_mode_rejects(
    fail_mode: Any, fixture_id: str, spec_dir: Path
) -> None:
    """A present-but-wrong-typed `fail_mode` lands on `fail_closed`, exactly
    where a misspelled one does -- falling through to the permissive default
    would treat the more broken input more leniently than a typo.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode=fail_mode)
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


@_BOTH_DELEGATION_PATHS
def test_delegation_absent_snapshot_other_issuer_snapshot_is_absent_for_self(
    fixture_id: str, spec_dir: Path
) -> None:
    """The subtle one: `revocation_snapshots` is PRESENT and every record in it
    is genuinely signed and fully trusted -- but none of them is A's. "Data was
    supplied" is not an escape from absence: B cannot answer whether A revoked
    a TCT A issued, so A's own deny list is exactly as unknown as it was with
    an empty list, and `fail_closed` must still reject.

    The delegation-side analogue of `verify_tct`'s wrong-issuer case, and the
    one an implementation that keyed absence off `"revocation_snapshots" in
    inp` would get wrong while passing every other test in this block. The
    snapshot lists this path's own `src_jti`, so a verifier that ignored the
    signed issuer would reject here for the wrong reason -- hence the
    `soft_fail` half below, which must VERIFY: the record is trusted and
    names the src_jti, and only the applicability skip keeps it from applying.
    """
    keys = load_kat_keys(spec_dir)
    entries = [{"jti": _SRC_JTI[fixture_id], "revoked_at": NOW}]

    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="fail_closed")
    inp["revocation_snapshots"] = [_delegation_snapshot_record(issuer=SUBJECT, entries=entries)]
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"
    assert "no trusted snapshot signed by this verifier was supplied" in exc.value.message

    permissive = _delegation_policy_input(spec_dir, fixture_id, fail_mode="soft_fail")
    permissive["revocation_snapshots"] = [_delegation_snapshot_record(issuer=SUBJECT, entries=entries)]
    assert verify_delegation_token(mint_input(permissive, REFERENCE_CLOCK, keys)) == _DELEGATION_GRANTS


@_BOTH_DELEGATION_PATHS
@pytest.mark.parametrize(
    "body_overrides",
    [{"published_at": NOW - 7200}, {"expires_at": NOW - 1}],
    ids=["staler-than-max_staleness_secs", "past-its-own-expires_at"],
)
def test_delegation_absent_snapshot_stale_snapshot_rejects_under_fail_closed(
    body_overrides: dict[str, Any], fixture_id: str, spec_dir: Path
) -> None:
    """RFC-AITP-0008 §3.2's two freshness bounds, each making an otherwise
    trusted, applicable snapshot from A *absent*: past its own `expires_at`, or
    published longer than `max_staleness_secs` ago. Same formula `verify_tct`
    and `verify_revocation_snapshot` apply.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="fail_closed", max_staleness_secs=600)
    inp["revocation_snapshots"] = [_delegation_snapshot_record(**body_overrides)]
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"
    assert "expired or stale" in exc.value.message


@_BOTH_DELEGATION_PATHS
def test_delegation_absent_snapshot_stale_snapshot_verifies_under_soft_fail(
    fixture_id: str, spec_dir: Path
) -> None:
    """The permissive half of the staleness rule: the identical stale snapshot
    under `soft_fail` proceeds on degraded revocation data."""
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="soft_fail", max_staleness_secs=600)
    inp["revocation_snapshots"] = [_delegation_snapshot_record(published_at=NOW - 7200)]
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == _DELEGATION_GRANTS


@_BOTH_DELEGATION_PATHS
def test_delegation_staleness_is_always_evaluated_once_policy_is_mandatory(
    fixture_id: str, spec_dir: Path
) -> None:
    """Before the `/reconcile` reversal, freshness/expiry were evaluated only
    when a top-level `policy` was supplied -- so a caller with NO `policy` at
    all got `fail_open`'s default AND skipped staleness filtering entirely,
    meaning a long-stale, long-expired, genuinely-listing snapshot still
    reached the deny-list scan and rejected (a documented asymmetry: an
    explicit `fail_open` policy over that same stale snapshot verified,
    while no policy at all rejected).

    Now that `policy` is mandatory, that asymmetry cannot occur: every call
    that reaches this far necessarily has `"policy" in inp`, so staleness
    filtering is now unconditional. The identical long-stale, long-expired,
    genuinely-listing snapshot from A, under an explicit `fail_open` policy,
    now VERIFIES -- the stale snapshot is filtered out as inapplicable
    before the deny-list scan ever runs, exactly matching what
    `test_delegation_absent_snapshot_stale_snapshot_verifies_under_soft_fail`
    already pins for `soft_fail`. This is the previously-documented
    non-monotonicity collapsing, not a new gap: it can no longer be
    constructed by any legitimate caller, since "no policy at all" now
    raises `KeyError` before reaching this code.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="fail_open")
    inp["revocation_snapshots"] = [
        _delegation_snapshot_record(
            entries=[{"jti": _SRC_JTI[fixture_id], "revoked_at": NOW}],
            published_at=NOW - 999999,
            expires_at=NOW - 1,
        )
    ]
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == _DELEGATION_GRANTS


@_BOTH_DELEGATION_PATHS
def test_delegation_fresh_applicable_snapshot_under_fail_closed_still_verifies(
    fixture_id: str, spec_dir: Path
) -> None:
    """The negative control the whole block needs: `fail_closed` rejects on
    ABSENCE, not on the mere presence of a policy. A trusted, fresh snapshot
    from A that lists someone else's jti answers the question -- the source TCT
    is not revoked -- and the delegation verifies.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="fail_closed", max_staleness_secs=600)
    inp["revocation_snapshots"] = [
        _delegation_snapshot_record(entries=[{"jti": "someone-elses-source-tct", "revoked_at": NOW}])
    ]
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == _DELEGATION_GRANTS


@_BOTH_DELEGATION_PATHS
@pytest.mark.parametrize(
    "max_staleness",
    [float("inf"), float("-inf"), float("nan"), "ten minutes", [600], {"secs": 600}],
    ids=["inf", "negative_inf", "nan", "string", "list", "dict"],
)
def test_delegation_policy_unusable_max_staleness_secs_is_stale_not_a_crash(
    max_staleness: Any, fixture_id: str, spec_dir: Path
) -> None:
    """`delegation.py`'s use of the shared `revocation.py::snapshot_is_stale`
    regression test (`test_tct_policy_unusable_max_staleness_secs_is_stale_not_a_crash`).

    Same reasoning, same three exception arms, same reason it matters: a
    JSON-sourced `policy` can carry a bare `Infinity`/`-Infinity`, and
    `int()` on a float infinity raises `OverflowError` -- neither `TypeError`
    nor `ValueError` -- which would otherwise escape `verify_delegation_token`
    raw. The snapshot here is fresh, trusted, applicable, and does NOT list
    this path's `src_jti`, so under `fail_closed` the only route to
    `DELEGATION_SOURCE_TCT_REVOKED` is the unusable bound being treated as
    stale, not a deny-list hit.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="fail_closed", max_staleness_secs=max_staleness)
    inp["revocation_snapshots"] = [
        _delegation_snapshot_record(entries=[{"jti": "someone-elses-source-tct", "revoked_at": NOW}])
    ]
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"


@_BOTH_DELEGATION_PATHS
def test_delegation_policy_without_max_staleness_secs_applies_only_the_expires_at_bound(
    fixture_id: str, spec_dir: Path
) -> None:
    """`delegation.py`'s copy of
    `test_tct_policy_without_max_staleness_secs_applies_only_the_expires_at_bound`.
    A `policy` that omits `max_staleness_secs` sets no age bound at all: the
    snapshot's own `expires_at` is still enforced, `published_at` is not
    consulted. Published far outside any plausible staleness window yet not
    expired, and it verifies under `fail_closed` -- proving the
    `max_staleness is None` early return does real work here too, not just
    in `tct.py`.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, fixture_id, fail_mode="fail_closed")
    inp["revocation_snapshots"] = [
        _delegation_snapshot_record(
            entries=[{"jti": "someone-elses-source-tct", "revoked_at": NOW}],
            published_at=NOW - 10_000,
            expires_at=NOW + 3600,
        )
    ]
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == _DELEGATION_GRANTS


@_BOTH_DELEGATION_PATHS
@pytest.mark.parametrize("fail_mode", ["fail_closed", "soft_fail", "fail_open"])
@pytest.mark.parametrize("junk", [5, "", {}, False], ids=["int", "empty-str", "empty-dict", "false"])
def test_delegation_malformed_revocation_snapshots_is_invalid_under_every_fail_mode(
    junk: Any, fail_mode: str, fixture_id: str, spec_dir: Path
) -> None:
    """RFC-AITP-0008 §1.5's obtained-but-untrustworthy half, preserved exactly:
    a malformed `revocation_snapshots` container is a defect in the data, not
    an absence of it, so it reports `REVOCATION_SNAPSHOT_INVALID` under EVERY
    mode and is never routed through the new absence policy.

    The falsy values are the ones that matter most (`""`/`{}`/`False`): a naive
    `or []` would fold them into "no snapshots", which under `fail_closed`
    would still reject -- but with the wrong code, and under `soft_fail` would
    silently succeed. Both would be the `/reconcile`-era `None`-vs-falsy fix
    being undone by the policy layer.

    The junk is injected *after* minting, as
    `test_delegation_revocation_snapshots_container_scalar_is_rejected_not_a_crash`
    already does: `minter.py` is test scaffolding, not the verifier under test,
    and a truthy scalar stops it before `verify_delegation_token` is ever
    called.
    """
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_delegation_policy_input(spec_dir, fixture_id, fail_mode=fail_mode), REFERENCE_CLOCK, keys)
    minted["revocation_snapshots"] = junk
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(minted)
    assert exc.value.code == "REVOCATION_SNAPSHOT_INVALID"


def test_delegation_multihop_per_hop_absence_is_not_fail_closed(spec_dir: Path) -> None:
    """The explicit non-goal, pinned so it cannot be widened by accident.

    `fail_closed` governs A's OWN deny list -- the §4 step 7 / RFC-AITP-0011 §6
    source-TCT lookup -- and nothing else. It is deliberately NOT extended to
    require a trusted snapshot for every intermediate hop issuer in the
    multi-hop per-hop sweep: RFC-AITP-0011 is Draft, its §6 lookup says nothing
    about absence, requiring N snapshots would be a materially wider policy
    with no RFC-stated default, and `del-mh-001` (a draft-opt-in success
    fixture) supplies none.

    So: `del-mh-001` under `fail_closed`, with a trusted fresh snapshot from A
    that lists nothing, VERIFIES -- even though the chain's two hop issuers (B
    and C) have no snapshot supplied at all. Were the absence policy applied
    per hop, this would reject.
    """
    keys = load_kat_keys(spec_dir)
    inp = _delegation_policy_input(spec_dir, "del-mh-001", fail_mode="fail_closed", max_staleness_secs=600)
    # Pin the pre-condition the test rests on: the hops really are issued by
    # peers with no snapshot in the supplied data.
    hop_issuers = {inp["delegation_token_claims"]["iss"]} | {
        hop["iss"] for hop in inp["delegation_token_claims"]["chain_claims"]
    }
    assert hop_issuers == {DELEGATE, SUBJECT} and ISSUER not in hop_issuers
    inp["revocation_snapshots"] = [_delegation_snapshot_record(issuer=ISSUER, entries=[])]
    assert verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys)) == _DELEGATION_GRANTS


def test_delegation_multihop_per_hop_revocation_still_fires_with_a_fresh_self_snapshot(
    spec_dir: Path,
) -> None:
    """The other side of the non-goal: not applying the policy per hop does not
    mean the per-hop sweep stopped working. `del-mh-004`'s B-signed snapshot
    still revokes B's hop, and adding a fresh, empty A snapshot (so the
    source-TCT check finds A's deny list present and clean, and the absence
    branch is never taken) leaves that rejection exactly where it was.
    """
    keys = load_kat_keys(spec_dir)
    inp = _load_conformance_input(spec_dir, "del-mh-004")
    inp["policy"] = {"fail_mode": "fail_closed", "max_staleness_secs": 600}
    inp["revocation_snapshots"].append(_delegation_snapshot_record(issuer=ISSUER, entries=[]))
    with pytest.raises(AitpError) as exc:
        verify_delegation_token(mint_input(inp, REFERENCE_CLOCK, keys))
    assert exc.value.code == "DELEGATION_SOURCE_TCT_REVOKED"
    assert exc.value.message == "a hop jti is revoked"


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


# --- resolved_issuer_keys depth bound + malformed-shape hazards (issue #38),
# --- end to end through verify_handshake_payload -----------------------------
#
# `id-009` is the OIDC conformance fixture (unlike `_hello_input` above, which
# builds a `pinned_key` identity that never reaches `jwk.py` at all): minting
# it populates `resolved_issuer_keys[issuer]` with one genuine, resolvable
# key, so mutating that one entry (or the container itself) after minting --
# not before, per this file's own convention -- reaches `identity.py:210`'s
# call into `jwk.issuer_keys_from` through the real handshake entry point,
# with every other gate ahead of it (manifest, envelope, proof) still
# genuinely satisfied.


def test_handshake_deeply_nested_resolved_issuer_key_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    value: Any = "deep-leaf-sentinel"
    for _ in range(3000):
        value = [value]
    minted["resolved_issuer_keys"][issuer] = value
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_malformed_resolved_issuer_key_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    minted["resolved_issuer_keys"][issuer] = 12345
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_deeply_nested_kty_in_resolved_issuer_key_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    value: Any = "deep-leaf-sentinel"
    for _ in range(20000):
        value = {"a": value}
    minted["resolved_issuer_keys"][issuer] = {"kty": value}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_non_mapping_resolved_issuer_keys_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    """The whole `resolved_issuer_keys` container, not one issuer's entry
    inside it, being a non-`Mapping` -- used to raise a raw `AttributeError`
    from `identity.py`'s own `.get()`."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    minted["resolved_issuer_keys"] = "not-a-mapping"
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_past_max_candidates_resolved_issuer_key_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    """Adjacent hazard to the depth bound above, found by #38's own
    verification pass and filed as issue #47: `issuer_keys_from`'s candidate
    count had no cap. `_MAX_CANDIDATES + 1` well-formed entries in a JWKS
    replacing the fixture's single resolved key must still resolve to
    `KEY_RESOLUTION_FAILED`, not a slow-but-successful parse."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(b"\x01" * 32)}
    minted["resolved_issuer_keys"][issuer] = {"keys": [jwk] * (_MAX_CANDIDATES + 1)}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_rsa_modulus_over_ceiling_resolved_issuer_key_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    """Sibling hazard, same issue #47: `from_rsa_numbers` had no upper bound
    on the RSA modulus. An 8193-bit synthetic modulus, replacing the
    fixture's single resolved key, must still resolve to
    `KEY_RESOLUTION_FAILED`."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    n_int = (1 << 8192) | 1  # exactly 8193 bits, odd
    n_b64u = b64url_encode(n_int.to_bytes((n_int.bit_length() + 7) // 8, "big"))
    minted["resolved_issuer_keys"][issuer] = {"kty": "RSA", "n": n_b64u, "e": "AQAB"}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_rsa_exponent_over_ceiling_resolved_issuer_key_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    """Sibling hazard, same issue #47: `from_rsa_numbers` had no bound on the
    RSA public exponent, unlike `ring`'s own 33-bit ceiling. A 34-bit
    synthetic exponent against a valid 2048-bit modulus, replacing the
    fixture's single resolved key, must still resolve to
    `KEY_RESOLUTION_FAILED`."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    n_int = (1 << 2047) | 1  # a valid, exactly-2048-bit synthetic modulus
    e_int = (1 << 33) | 1  # exactly 34 bits, odd -- one past the 33-bit ceiling
    n_b64u = b64url_encode(n_int.to_bytes((n_int.bit_length() + 7) // 8, "big"))
    e_b64u = b64url_encode(e_int.to_bytes((e_int.bit_length() + 7) // 8, "big"))
    minted["resolved_issuer_keys"][issuer] = {"kty": "RSA", "n": n_b64u, "e": e_b64u}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_rsa_zero_padded_modulus_resolved_issuer_key_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    """Sibling hazard, issue #52 (a follow-up to #50): an at-cap `n`
    consisting mostly of `\\x00` padding around a genuine 2048-bit modulus
    decodes to an in-range `bit_length()`, so it was not malformed before
    this fix -- it parsed successfully rather than resolving to
    `KEY_RESOLUTION_FAILED`. `from_rsa_numbers`'s new minimal-encoding check
    (RFC 7518 §2/§6.3.1.1) now rejects it, replacing the fixture's single
    resolved key."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    real_modulus = (1 << 2047) | 1  # exactly 2048 bits
    real_bytes = real_modulus.to_bytes(256, "big")
    zero_padded_n = b64url_encode(b"\x00" * (6144 - 256) + real_bytes)
    minted["resolved_issuer_keys"][issuer] = {"kty": "RSA", "n": zero_padded_n, "e": "AQAB"}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_jwks_within_candidate_cap_with_over_ceiling_rsa_candidate_is_key_resolution_failed(
    spec_dir: Path,
) -> None:
    """Phase 1 x Phase 2 seam, end to end: a JWKS well within the
    candidate-count cap (5 entries, not 65) whose one RSA entry exceeds the
    modulus ceiling must still resolve to `KEY_RESOLUTION_FAILED`, proving
    the RSA bound is reached and enforced for a JWKS-embedded candidate
    through the full handshake path, not only for a bare top-level JWK
    (every other Phase 2 e2e test above replaces the whole resolved value
    with a single JWK, never a JWKS containing one)."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    ed_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(b"\x01" * 32)}
    n_int = (1 << 8192) | 1  # exactly 8193 bits, odd -- one past the modulus ceiling
    bad_rsa_jwk = {"kty": "RSA", "n": b64url_encode(n_int.to_bytes((n_int.bit_length() + 7) // 8, "big")), "e": "AQAB"}
    minted["resolved_issuer_keys"][issuer] = {"keys": [ed_jwk, ed_jwk, bad_rsa_jwk, ed_jwk, ed_jwk]}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"


def test_handshake_oversized_jwk_member_resolved_issuer_key_is_key_resolution_failed_not_a_crash(
    spec_dir: Path,
) -> None:
    """Sibling hazard, issue #50 (a follow-up to #47): `issuer_key_from_jwk`
    decoded each base64url member (OKP `x`; EC `x`/`y`; RSA `n`/`e`) before
    checking its length, paying full decode cost for an oversized value
    before any bound rejected it. An over-cap `x`, replacing the fixture's
    single resolved key, must still resolve to `KEY_RESOLUTION_FAILED` --
    and via the new pre-gate's own message, not merely via whatever
    downstream check an oversized-but-eventually-decoded value happened to
    fail (the code alone already passed before this fix, since the existing
    catch-all already converts any `ValueError` here)."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    oversized_x = b64url_encode(b"\x01" * (_MAX_B64_MEMBER_CHARS + 1))
    minted["resolved_issuer_keys"][issuer] = {"kty": "OKP", "crv": "Ed25519", "x": oversized_x}
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"
    assert "exceeds the maximum encoded length" in str(exc.value)


def test_handshake_aliased_resolved_issuer_key_is_key_resolution_failed_via_node_visit_cap(
    spec_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sibling hazard, issue #49 (a follow-up to #47): `_issuer_keys_from`'s
    walk had no bound on total nodes visited, so a *candidate-free* value
    (`_MAX_CANDIDATES` never fires) was linear-and-unbounded for ordinary
    input, and genuinely exponential for an *aliased* Python object graph --
    16 nested lists each holding 3 references to the same next-level list
    object (~384 bytes of actual allocated memory), which the fixture's
    single resolved key is replaced with here. Without this cap:
    sum(3**i for i in range(17)) (~64.5 million) node visits, multiple
    seconds of CPU, before eventually
    still resolving to `KEY_RESOLUTION_FAILED` -- so an assertion on the
    error code alone would already have passed before this fix and would
    prove nothing about whether the new cap fired. Proven instead via the
    same non-vacuous monkeypatch-proof technique issue #50's tests already
    established (`tests/test_identity_oidc.py`'s `_guarded_b64url_decode`),
    here wrapping `_issuer_keys_from` itself to count every recursive call:
    the wrapper is installed as the module's own `_issuer_keys_from`
    binding, so both the initial call from `issuer_keys_from` and every one
    of its own internal recursive calls (which resolve the name against the
    same module namespace at call time) route through it, giving an exact
    count of every node visited -- not merely that some `ValueError`
    eventually surfaced."""
    keys = load_kat_keys(spec_dir)
    minted = mint_input(_load_conformance_input(spec_dir, "id-009"), REFERENCE_CLOCK, keys)
    issuer = minted["envelope"]["payload"]["identity"]["issuer"]
    aliased: Any = None
    for _ in range(16):
        aliased = [aliased, aliased, aliased]
    minted["resolved_issuer_keys"][issuer] = aliased

    real_issuer_keys_from = jwk._issuer_keys_from
    calls = [0]

    def _counting_issuer_keys_from(*args: Any, **kwargs: Any) -> None:
        calls[0] += 1
        return real_issuer_keys_from(*args, **kwargs)

    monkeypatch.setattr(jwk, "_issuer_keys_from", _counting_issuer_keys_from)
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(minted)
    assert exc.value.code == "KEY_RESOLUTION_FAILED"
    assert "visits more than" in str(exc.value)
    assert calls[0] == _MAX_NODES_VISITED + 1


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
