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
    assert exc_info.value.code == "BUNDLE_INVALID_SIGNATURE"

    # The original (inner-shaped, untouched) input is unaffected by the copy.
    assert body["signature"] == outer["session_bundle"]["signature"]


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
    assert exc_info.value.code == "BUNDLE_INVALID_SIGNATURE"
