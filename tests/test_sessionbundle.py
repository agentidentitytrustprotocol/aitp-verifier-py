"""Session bundle `signature` placement (RFC-AITP-0010 §3, spec issue #23).

The `signature` member lives INSIDE the inner `session_bundle` body, not as a
sibling of the `{"session_bundle": ...}` transport wrapper, and is excluded
from the bytes it covers. These tests pin both directions of that contract
directly against `verify_session_bundle`, independently of the conformance
pack: the OLD sibling shape must be rejected (not silently accepted, and not
a crash), and a signature computed WITHOUT excluding its own member must be
rejected too -- otherwise a self-consistent-but-wrong implementation would
pass every fixture that only checks self-consistency.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.b64 import b64url_encode
from aitp_verifier.crypto import sha256
from aitp_verifier.errors import AitpError
from aitp_verifier.jcs import canonicalize
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.minter import mint_input
from aitp_verifier.sessionbundle import verify_session_bundle
from aitp_verifier.timeutil import REFERENCE_CLOCK


def _minted_bundle_input(spec_dir: Path) -> dict[str, Any]:
    """A fully-minted, valid `bundle-001` input (real coordinator signature)."""
    fixture = json.loads((spec_dir / "schemas/conformance/bundle-001-success.json").read_text())
    keys = load_kat_keys(spec_dir)
    return mint_input(fixture["input"], REFERENCE_CLOCK, keys)


def test_minted_bundle_001_verifies(spec_dir: Path) -> None:
    """Sanity: the corrected inner-shaped fixture verifies as-is."""
    minted = _minted_bundle_input(spec_dir)
    assert verify_session_bundle(minted)["ok"] is True


def test_old_sibling_shape_is_rejected(spec_dir: Path) -> None:
    """A bundle with `signature` as a SIBLING of the wrapper (the old, now-wrong
    shape) must be rejected with a proper AitpError -- not silently accepted
    (that would reintroduce the exact ambiguity issue #23 removes) and not a
    KeyError/traceback.
    """
    minted = _minted_bundle_input(spec_dir)
    outer = minted["session_bundle"]
    body = outer["session_bundle"]

    sibling = copy.deepcopy(minted)
    sibling_outer = sibling["session_bundle"]
    sibling_body = sibling_outer["session_bundle"]
    sibling_outer["signature"] = sibling_body.pop("signature")

    assert "signature" not in sibling["session_bundle"]["session_bundle"]
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(sibling)
    # The aggregate, not a BUNDLE_* code: this is a structural rejection (the
    # wrapper carries a member it may not carry, the body is missing one it
    # must), and no per-step code covers that. Pinned by conformance fixture
    # bundle-004-signature-sibling-rejected.
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"

    # The original (inner-shaped, untouched) input is unaffected by the copy.
    assert body["signature"] == outer["session_bundle"]["signature"]


def test_wrapper_rejects_any_extra_member(spec_dir: Path) -> None:
    """The transport wrapper is `additionalProperties: false`: it carries
    `session_bundle` and nothing else. Fixture bundle-004 only exercises the
    `signature` sibling, but the rule is not signature-specific -- an attacker
    who can staple ANY member onto the wrapper is outside the signed bytes,
    since the coordinator signature covers only the inner body. This pins the
    general case so a later narrowing to `if "signature" in outer` would fail.

    Note the code: the wrapper reports `SESSION_BUNDLE_INVALID`, NOT the
    `UNKNOWN_FIELD` that `test_body_rejects_any_extra_member` just below
    expects for the same-shaped defect one level in. That asymmetry is
    RFC-AITP-0010's, not an oversight -- §5 scopes its member-set check (and
    `UNKNOWN_FIELD`) to the inner body and leaves the wrapper to §3's
    transport-shape rule. Collapsing the two gates into one code would break
    bundle-004 or bundle-006 depending on which way it collapsed.
    """
    minted = _minted_bundle_input(spec_dir)
    assert verify_session_bundle(copy.deepcopy(minted))["ok"] is True

    stapled = copy.deepcopy(minted)
    stapled["session_bundle"]["routing_hint"] = "https://attacker.example/relay"

    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(stapled)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"
    assert "routing_hint" in exc_info.value.message


def test_body_rejects_any_extra_member(spec_dir: Path) -> None:
    """The inner `session_bundle` body is ALSO `additionalProperties: false`
    (RFC-AITP-0001 §7) -- this is the gap the module docstring used to call
    out explicitly as unenforced ("Unknown members INSIDE the signed body or
    a participant entry are still accepted"). A member stapled onto the body
    is inside the coordinator-signed bytes, unlike the wrapper member above,
    so this pins a distinct code path: the shape check must run BEFORE the
    signature check fires, or a self-consistently-signed extra field would
    verify and this test would need to re-sign to be meaningful. Because the
    shape gate runs first, mutating an already-minted (validly signed) body
    post-hoc is sufficient to prove the rejection is real.
    """
    minted = _minted_bundle_input(spec_dir)
    stapled = copy.deepcopy(minted)
    stapled["session_bundle"]["session_bundle"]["routing_hint"] = "https://attacker.example/relay"

    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(stapled)
    assert exc_info.value.code == "UNKNOWN_FIELD"
    assert "routing_hint" in exc_info.value.message


def test_participant_entry_rejects_any_extra_member(spec_dir: Path) -> None:
    """Each `participants[]` entry is `additionalProperties: false` too
    ({"aid", "tct"} only) -- the other half of the same pre-existing gap
    `test_body_rejects_any_extra_member` closes for the body itself.
    """
    minted = _minted_bundle_input(spec_dir)
    stapled = copy.deepcopy(minted)
    stapled["session_bundle"]["session_bundle"]["participants"][0]["routing_hint"] = "x"

    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(stapled)
    assert exc_info.value.code == "UNKNOWN_FIELD"
    assert "routing_hint" in exc_info.value.message


def test_participant_tct_claims_unknown_field_rejected(spec_dir: Path) -> None:
    """The embedded participant TCT is a compact-JWS claims object with its
    own `additionalProperties: false` schema (aitp-tct.schema.json). Unlike
    the body/participant-entry cases above, an unknown TCT claim is inside
    the TCT's OWN signature, not the bundle's -- so it must be re-signed
    (via a fresh mint) rather than stapled onto already-minted output, or the
    TCT signature check would reject it first and this test would not prove
    the claims-shape gate does anything.

    The code is the bundle-scoped one, NOT the `UNKNOWN_FIELD` that the body
    and participant-entry cases above report: RFC-AITP-0010 §5 step 7 collapses
    "other TCT-level failures" of an embedded token into
    `BUNDLE_PARTICIPANT_TCT_INVALID`, the same clause that already collapses
    `TOKEN_TYP_MISMATCH` and `TOKEN_ALG_MISMATCH` here. No fixture pins this
    (bundle-006 covers the body, not the embedded TCT), so this test is the
    only thing holding the remap in place. `handshake.py` runs the identical
    claims check and correctly reports `UNKNOWN_FIELD`, because RFC-AITP-0004
    has no equivalent collapsing clause -- filed upstream for confirmation.
    """
    fixture = json.loads((spec_dir / "schemas/conformance/bundle-001-success.json").read_text())
    tampered = copy.deepcopy(fixture["input"])
    tampered["session_bundle"]["session_bundle"]["participants"][0]["tct_claims"]["routing_hint"] = "x"
    keys = load_kat_keys(spec_dir)
    minted = mint_input(tampered, REFERENCE_CLOCK, keys)

    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "BUNDLE_PARTICIPANT_TCT_INVALID"


def test_participant_tct_combined_unknown_claim_and_bad_alg_reports_bundle_code(spec_dir: Path) -> None:
    """RFC-AITP-0005 §7.2's now-explicit sub-step order (spec commit 993da8c)
    moved the claims-membership check to run inside `verify_jws`, before the
    alg-pin, reached here through this module's own try/except remap (see the
    comment above the participant loop in `sessionbundle.py`). This module
    already collapses `TOKEN_ALG_MISMATCH` and `UNKNOWN_FIELD` to the same
    `BUNDLE_PARTICIPANT_TCT_INVALID` code (the single-defect cases are pinned
    separately above and in the conformance pack), so a TCT combining BOTH
    defects reports the same code either way -- this test is not able to
    distinguish the old order from the new one behaviorally (that observable
    difference only exists for `tct.py`/`handshake.py`, pinned in
    `test_unknown_fields.py`). It exists to prove the collapse survives the
    internal reordering intentionally, not merely by accident.

    `__JWS_TCT_WRONG_ALG__` (`minter.py`) always mints a header claiming
    `ES256`, which mismatches kat-keypair-001's actual Ed25519 AID -- the
    same technique `tct-009`-style alg-mismatch fixtures use.
    """
    fixture = json.loads((spec_dir / "schemas/conformance/bundle-001-success.json").read_text())
    tampered = copy.deepcopy(fixture["input"])
    participant = tampered["session_bundle"]["session_bundle"]["participants"][0]
    participant["tct"] = "__JWS_TCT_WRONG_ALG__"
    participant["tct_claims"]["routing_hint"] = "x"
    keys = load_kat_keys(spec_dir)
    minted = mint_input(tampered, REFERENCE_CLOCK, keys)

    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "BUNDLE_PARTICIPANT_TCT_INVALID"


@pytest.mark.parametrize(
    ("outer", "expected"),
    [
        pytest.param(["session_bundle"], "wrapper is list", id="wrapper-is-a-list"),
        pytest.param(None, "wrapper is NoneType", id="wrapper-is-null"),
        pytest.param({}, "no session_bundle member", id="wrapper-is-empty"),
        pytest.param({"session_bundle": "signature"}, "body is str", id="body-is-a-string"),
        pytest.param({"session_bundle": None}, "body is NoneType", id="body-is-null"),
        pytest.param({"session_bundle": []}, "body is list", id="body-is-a-list"),
        pytest.param({"session_bundle": {}, 1: "y", "zz": "w"}, "non-wrapper member(s)", id="extra-keys-of-mixed-type"),
    ],
)
def test_malformed_envelope_raises_aitp_error_not_a_traceback(outer: Any, expected: str) -> None:
    """A malformed envelope is a protocol error, never a raw traceback.

    Two cases defeat a naive check specifically. `["session_bundle"]` contains
    the literal wrapper key, so `set(outer) == {"session_bundle"}` compares
    equal and a set-only gate waves it through. `{"session_bundle": "signature"}`
    survives a `"signature" in body` test by *substring* membership. Both then
    crash one line later. The mixed-type case defeats a bare `sorted()` over
    the extra keys. A library consumer feeding attacker-shaped input must get
    an AitpError it can catch, not a TypeError.

    Asserting the message, not just the code, is what pins the three branches
    apart -- a single collapsed check would still satisfy every `.code` here.
    """
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle({"self_aid": "aid:pubkey:x", "now": 0, "session_bundle": outer})
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"
    assert expected in exc_info.value.message


def test_signature_covering_its_own_member_is_rejected(spec_dir: Path) -> None:
    """A signature computed over the body WITH its own `signature` member
    included (i.e. an implementation that forgot the exclusion) must fail
    verification under this (correct) verifier. Without this test, an
    implementation that signs and verifies self-consistently -- always
    including `signature` in the hashed bytes on both ends -- would pass
    every fixture. That is exactly how the wrapper-vs-body divergence this
    issue fixes survived a full release undetected.
    """
    minted = _minted_bundle_input(spec_dir)
    keys = load_kat_keys(spec_dir)

    tampered = copy.deepcopy(minted)
    body = tampered["session_bundle"]["session_bundle"]
    coordinator = body["coordinator"]
    key = keys[coordinator]

    # Sign over the body with the CURRENT signature string still present --
    # i.e. do not exclude `signature` from the signing input.
    wrong_raw = key.sign_digest(sha256(canonicalize(body)))
    body["signature"] = b64url_encode(wrong_raw)

    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(tampered)
    assert exc_info.value.code == "BUNDLE_INVALID_SIGNATURE"


def test_bundle_body_without_signature_member_is_a_protocol_error(spec_dir: Path) -> None:
    """A bundle body that carries no `signature` at all raises AitpError, not
    a raw KeyError/traceback.
    """
    minted = _minted_bundle_input(spec_dir)
    body = minted["session_bundle"]["session_bundle"]
    del body["signature"]

    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"


# ── body/participant required-member and type validation (issue #23, item 1
#    "sessionbundle.py") ───────────────────────────────────────────────────
#
# Before this phase, `participants`, `expires_at`, and `coordinator` were
# dereferenced directly with no presence guard, and participant entries got
# only a member-*set* check, never a required-member check for `aid`/`tct`.
# Minting note, same as `tests/test_manifest.py`/`tests/test_envelope.py`:
# hostile/missing values are injected *after* `mint_input` mints a
# well-formed fixture (`_minted_bundle_input`, above), never passed through
# minting itself -- `minter.py::_mint_bundle` canonicalizes `signing_body`
# and looks up `keys[body["coordinator"]]` while producing a valid
# signature, so a hostile value present at mint time raises there instead of
# in the code under test.


@pytest.mark.parametrize("dropped", [
    "version", "session_id", "coordinator", "issued_at", "expires_at", "participants",
])
def test_bundle_body_every_required_member_is_enforced(dropped: str, spec_dir: Path) -> None:
    minted = _minted_bundle_input(spec_dir)
    assert verify_session_bundle(minted)["ok"] is True

    body = minted["session_bundle"]["session_bundle"]
    del body[dropped]
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"
    assert dropped in exc_info.value.message


@pytest.mark.parametrize(("member", "value"), [
    ("participants", 5),
    ("expires_at", "soon"),
    ("session_id", 5),
    ("issued_at", "not a number"),
])
def test_bundle_body_mistyped_member_is_a_structural_rejection(member: str, value: Any, spec_dir: Path) -> None:
    minted = _minted_bundle_input(spec_dir)
    body = minted["session_bundle"]["session_bundle"]
    body[member] = value
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"


def test_bundle_participant_missing_both_required_members_is_enforced(spec_dir: Path) -> None:
    """A participant entry `{}` (missing both `aid` and `tct`) raises
    AitpError, not a raw KeyError from `p["tct"]`/`p["aid"]` downstream.
    """
    minted = _minted_bundle_input(spec_dir)
    body = minted["session_bundle"]["session_bundle"]
    body["participants"].append({})
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"


@pytest.mark.parametrize(("member", "value"), [("aid", 5), ("tct", 5)])
def test_bundle_participant_mistyped_member_is_a_structural_rejection(member: str, value: Any, spec_dir: Path) -> None:
    minted = _minted_bundle_input(spec_dir)
    body = minted["session_bundle"]["session_bundle"]
    body["participants"][0][member] = value
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"


# ── JcsError must not escape (issue #23 item 1, sessionbundle.py) ─────────


def test_bundle_infinite_extension_value_does_not_crash(spec_dir: Path) -> None:
    """`json.loads("1e400")` returns `float("inf")` from ordinary valid JSON.
    `extensions`'s interior is never inspected (RFC-AITP-0001 §7), so no
    member/type check can catch this -- only the `canonicalize` call itself
    (now wrapped by `canonical_bytes`) can.
    """
    minted = _minted_bundle_input(spec_dir)
    body = minted["session_bundle"]["session_bundle"]
    body["extensions"] = {"x": json.loads("1e400")}
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"


def test_bundle_huge_issued_at_does_not_crash(spec_dir: Path) -> None:
    """A 400-digit integer is a valid Python/JSON `int` (no overflow), so it
    passes `check_types` -- only JCS's own representable-range check catches
    it. `issued_at` is otherwise unused by any comparison in this module.
    """
    minted = _minted_bundle_input(spec_dir)
    body = minted["session_bundle"]["session_bundle"]
    body["issued_at"] = json.loads("1" + "0" * 400)
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"


# ── malformed coordinator AID (issue #23, adjacent completeness) ──────────


def test_bundle_malformed_coordinator_does_not_crash(spec_dir: Path) -> None:
    """`parse_aid` signals a malformed AID with a bare `ValueError`, which is
    not an `AitpError` -- must be caught and reported as SESSION_BUNDLE_INVALID.
    """
    minted = _minted_bundle_input(spec_dir)
    body = minted["session_bundle"]["session_bundle"]
    body["coordinator"] = "not-an-aid"
    with pytest.raises(AitpError) as exc_info:
        verify_session_bundle(minted)
    assert exc_info.value.code == "SESSION_BUNDLE_INVALID"
