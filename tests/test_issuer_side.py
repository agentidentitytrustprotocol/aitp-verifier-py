"""Issuer-side TCT verification (RFC-AITP-0005 §10.5) and the handshake's
receiver-policy step (RFC-AITP-0004 §5.1 step 8), beyond what the fixtures pin.

Each case starts from a spec fixture's minted input and changes one thing.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.errors import AitpError
from aitp_verifier.handshake import verify_handshake_payload
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.minter import mint_input
from aitp_verifier.tct import verify_tct_as_issuer
from aitp_verifier.timeutil import REFERENCE_CLOCK
from aitp_verifier.harness import NOT_TESTED, issuer_resolver, receiver_policy

SUB = "aid:pubkey:A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"
OTHER = "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU"


def _input(spec_dir: Path, fixture_id: str) -> dict[str, Any]:
    for path in (spec_dir / "schemas/conformance").glob(f"{fixture_id}-*.json"):
        inp: dict[str, Any] = copy.deepcopy(json.loads(path.read_text(encoding="utf-8"))["input"])
        return mint_input(inp, REFERENCE_CLOCK, load_kat_keys(spec_dir))
    raise AssertionError(f"fixture {fixture_id!r} not found")


def _issuer_side(spec_dir: Path, **changes: Any) -> dict[str, Any]:
    inp = _input(spec_dir, "tct-029")
    inp["policy"] = NOT_TESTED
    inp.update(changes)
    return inp


def _code(inp: dict[str, Any]) -> str:
    with pytest.raises(AitpError) as exc:
        verify_tct_as_issuer(inp)
    return exc.value.code


def test_pop_success_establishes_sub(spec_dir: Path) -> None:
    assert verify_tct_as_issuer(_issuer_side(spec_dir)) == {"presenter_aid": SUB, "grants": ["macp.mode.task.v1"]}


def test_no_pop_and_no_channel_binding_is_rejected(spec_dir: Path) -> None:
    """There is no third source for the presenter (§10.5 item 3)."""
    inp = _issuer_side(spec_dir)
    del inp["envelope"]
    assert _code(inp) == "POP_RESPONSE_INVALID"


def test_channel_binding_to_the_sub_key_establishes_sub(spec_dir: Path) -> None:
    inp = _issuer_side(spec_dir, channel_bound_aid=SUB)
    del inp["envelope"]
    assert verify_tct_as_issuer(inp)["presenter_aid"] == SUB


def test_channel_binding_to_another_key_is_rejected(spec_dir: Path) -> None:
    inp = _issuer_side(spec_dir, channel_bound_aid=OTHER)
    del inp["envelope"]
    assert _code(inp) == "POP_RESPONSE_INVALID"


def test_a_tct_this_verifier_did_not_issue_is_rejected(spec_dir: Path) -> None:
    assert _code(_issuer_side(spec_dir, self_aid=OTHER)) == "TCT_SIGNATURE_INVALID"


def test_a_response_to_no_outstanding_challenge_is_rejected(spec_dir: Path) -> None:
    assert _code(_issuer_side(spec_dir, outstanding_pop_challenges=[])) == "POP_RESPONSE_INVALID"


def test_a_challenge_for_another_jti_does_not_count(spec_dir: Path) -> None:
    inp = _issuer_side(spec_dir)
    inp["outstanding_pop_challenges"][0]["tct_jti"] = "11111111-1111-4111-8111-111111111111"
    assert _code(inp) == "POP_RESPONSE_INVALID"


def test_a_tampered_response_envelope_is_rejected(spec_dir: Path) -> None:
    inp = _issuer_side(spec_dir)
    inp["envelope"]["timestamp"] += 1
    assert _code(inp) == "POP_RESPONSE_INVALID"


def test_a_malformed_challenge_expiry_is_a_challenge_error(spec_dir: Path) -> None:
    inp = _issuer_side(spec_dir)
    inp["outstanding_pop_challenges"][0]["expires_at"] = "soon"
    assert _code(inp) == "POP_CHALLENGE_INVALID"


def test_revocation_runs_last_and_defaults_to_fail_closed(spec_dir: Path) -> None:
    """With no `policy` and no deny list the default `fail_closed` rejects,
    but only after PoP: a bad response still reports the PoP code."""
    inp = _issuer_side(spec_dir)
    del inp["policy"]
    assert _code(inp) == "TCT_REVOKED"
    del inp["envelope"]
    assert _code(inp) == "POP_RESPONSE_INVALID"


# ── RFC-AITP-0004 §5.1 step 8 ───────────────────────────────────────────────


def _hello(spec_dir: Path, fixture_id: str) -> dict[str, Any]:
    inp = _input(spec_dir, fixture_id)
    receiver_policy(inp, accept_presented_type=fixture_id.startswith("id-"))
    inp["resolved_issuer_keys"] = issuer_resolver(load_kat_keys(spec_dir))
    return inp


def test_accepted_identity_types_default_is_oidc_only(spec_dir: Path) -> None:
    """id-017 (pinned_key) passes when the receiver accepts the type, and
    fails step 8 under the default."""
    inp = _hello(spec_dir, "id-017")
    assert verify_handshake_payload(inp) == {"ok": True}
    del inp["self_accepted_identity_types"]
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(inp)
    assert exc.value.code == "INCOMPATIBLE_IDENTITY_TYPE"


@pytest.mark.parametrize("junk", ["pinned_key", None, {"pinned_key": True}])
def test_non_list_accepted_types_accept_nothing(spec_dir: Path, junk: Any) -> None:
    """A string is not a list: `"pinned_key"` must not match by substring."""
    inp = _hello(spec_dir, "id-017")
    inp["self_accepted_identity_types"] = junk
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(inp)
    assert exc.value.code == "INCOMPATIBLE_IDENTITY_TYPE"


def test_no_trust_anchors_trust_no_oidc_issuer(spec_dir: Path) -> None:
    inp = _hello(spec_dir, "id-009")
    assert verify_handshake_payload(inp) == {"ok": True}
    del inp["self_trust_anchors"]
    with pytest.raises(AitpError) as exc:
        verify_handshake_payload(inp)
    assert exc.value.code == "INCOMPATIBLE_TRUST_ANCHORS"
