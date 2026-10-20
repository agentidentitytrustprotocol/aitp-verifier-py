"""TCT claim rules added with the #72 promotion (RFC-AITP-0005).

* §2.2 / §7.2 step 1: ``jti`` is a lowercase UUID v4 (version nibble ``4``,
  variant bits ``10``), checked before signature verification
  (``tct-013``, ``tct-014``).
* §5.3 / §7.2 step 5: in a grant context, ``iss`` MUST differ from ``sub``
  and ``grants`` MUST NOT contain ``aitp.attestation`` (``tct-015``,
  ``tct-016``, ``tct-018``).
"""

from __future__ import annotations

from typing import Any

import pytest

from aitp_verifier.aid import parse_aid
from aitp_verifier.b64 import b64url_encode
from aitp_verifier.crypto import PrivateKey
from aitp_verifier.errors import AitpError
from aitp_verifier.jwk import thumbprint
from aitp_verifier.jws import encode_jws
from aitp_verifier.tct import verify_tct

ISSUER = PrivateKey.ed25519_from_seed(bytes([1]) * 32)
SUBJECT = PrivateKey.ed25519_from_seed(bytes(32))
ISS_AID = "aid:pubkey:" + b64url_encode(ISSUER.raw_public())
SUB_AID = "aid:pubkey:" + b64url_encode(SUBJECT.raw_public())
NOW = 1_711_900_000


def _claims(**over: Any) -> dict[str, Any]:
    c: dict[str, Any] = {
        "ver": "aitp/0.3",
        "jti": "550e8400-e29b-41d4-a716-446655440000",
        "iss": ISS_AID,
        "sub": SUB_AID,
        "aud": SUB_AID,
        "iat": NOW - 100,
        "exp": NOW + 3600,
        "grants": ["read_data"],
        "cnf": {"jkt": thumbprint(parse_aid(SUB_AID))},
    }
    c.update(over)
    return c


def _verify(claims: dict[str, Any], key: PrivateKey = ISSUER) -> dict[str, Any]:
    token = encode_jws("aitp-tct+jwt", claims, key, alg="EdDSA")
    return verify_tct({"tct_token": token, "policy": {"fail_mode": "fail_open"}}, NOW)


def _code(claims: dict[str, Any], key: PrivateKey = ISSUER) -> str:
    with pytest.raises(AitpError) as exc:
        _verify(claims, key)
    return exc.value.code


def test_baseline_verifies() -> None:
    assert _verify(_claims())["grants"] == ["read_data"]


@pytest.mark.parametrize(
    "jti",
    [
        "01928f3e-8c00-7a5b-9c3d-4e5f60713013",  # v7
        "770e8400-e29b-41d4-c716-446655440702",  # variant 110
        "550E8400-E29B-41D4-A716-446655440000",  # uppercase
        "550e8400e29b41d4a716446655440000",  # unhyphenated
        "not-a-uuid",
    ],
)
def test_jti_outside_the_v4_layout_is_rejected(jti: str) -> None:
    assert _code(_claims(jti=jti)) == "TCT_SIGNATURE_INVALID"


def test_jti_is_checked_before_the_signature() -> None:
    # Signed by the wrong key: a verifier that checked the signature first
    # would still say TCT_SIGNATURE_INVALID, so assert on the message.
    token = encode_jws("aitp-tct+jwt", _claims(jti="01928f3e-8c00-7a5b-9c3d-4e5f60713013"), SUBJECT, alg="EdDSA")
    with pytest.raises(AitpError, match="jti"):
        verify_tct({"tct_token": token, "policy": {"fail_mode": "fail_open"}}, NOW)


def test_self_issued_tct_is_rejected_in_a_grant_context() -> None:
    claims = _claims(iss=SUB_AID)
    assert _code(claims, SUBJECT) == "TCT_SIGNATURE_INVALID"


@pytest.mark.parametrize("grants", [["aitp.attestation"], ["read_data", "aitp.attestation"]])
def test_attestation_marker_is_rejected_in_a_grant_context(grants: list[str]) -> None:
    assert _code(_claims(grants=grants)) == "TCT_SIGNATURE_INVALID"


# --- relying-party attestation verification (§5.3 "Verification") ----------

KAT_KEY = "io.agentidentitytrustprotocol.kat"
RP_AID = ISS_AID  # a third party: neither the attestation's iss nor its aud


def _attestation(**over: Any) -> dict[str, Any]:
    c = _claims(
        iss=SUB_AID,
        grants=["aitp.attestation"],
        exp=4_867_660_000,
        ext={KAT_KEY: {"statement": "archival attestation"}},
    )
    c.update(over)
    return c


def _attest(claims: dict[str, Any], **inp: Any) -> dict[str, Any]:
    from aitp_verifier.tct import verify_attestation

    token = encode_jws("aitp-tct+jwt", claims, SUBJECT, alg="EdDSA")
    args: dict[str, Any] = {
        "tct_token": token,
        "self_aid": RP_AID,
        "expected_ext_key": KAT_KEY,
        "trust_store": [SUB_AID],
        "waive_manifest_cap": True,
        "policy": {"fail_mode": "fail_open"},
    }
    args.update(inp)
    return verify_attestation(args, NOW)


def _attest_code(claims: dict[str, Any], **inp: Any) -> str:
    with pytest.raises(AitpError) as exc:
        _attest(claims, **inp)
    return exc.value.code


def test_attestation_verifies_for_a_third_party() -> None:
    out = _attest(_attestation())
    assert out["statement"] == {"statement": "archival attestation"}


def test_attestation_is_rejected_by_verify_tct() -> None:
    token = encode_jws("aitp-tct+jwt", _attestation(), SUBJECT, alg="EdDSA")
    with pytest.raises(AitpError) as exc:
        verify_tct({"tct_token": token, "expected_audience": SUB_AID, "policy": {"fail_mode": "fail_open"}}, NOW)
    assert exc.value.code == "TCT_SIGNATURE_INVALID"


@pytest.mark.parametrize(
    "over",
    [
        {"aud": ISS_AID},  # iss == sub != aud
        {"grants": ["aitp.attestation", "read_data"]},
        {"grants": ["read_data"]},
        {"ext": {"com.example.note": {"statement": "x"}}},  # tct-019
        {"jti": "01928f3e-8c00-7a5b-9c3d-4e5f60713013"},
    ],
    ids=["aud", "marker-beside-grant", "no-marker", "ext-key-missing", "jti-v7"],
)
def test_attestation_shape_defects_are_rejected(over: dict[str, Any]) -> None:
    assert _attest_code(_attestation(**over)) == "TCT_SIGNATURE_INVALID"


def test_attestation_issuer_must_be_in_the_relying_partys_records() -> None:
    assert _attest_code(_attestation(), trust_store=[ISS_AID]) == "TCT_SIGNATURE_INVALID"


def test_attestation_manifest_cap_decision_is_mandatory() -> None:
    with pytest.raises(ValueError, match="Manifest"):
        _attest(_attestation(), waive_manifest_cap=False)
    code = _attest_code(_attestation(), waive_manifest_cap=False, issuer_manifest={"expires_at": NOW + 10})
    assert code == "TCT_EXPIRES_AFTER_MANIFEST"


def test_attestation_wrong_typ_is_type_confusion() -> None:
    from aitp_verifier.tct import verify_attestation

    token = encode_jws("aitp-voucher+jwt", _attestation(), SUBJECT, alg="EdDSA")
    with pytest.raises(AitpError) as exc:
        verify_attestation(
            {"tct_token": token, "expected_ext_key": KAT_KEY, "trust_store": [SUB_AID], "waive_manifest_cap": True},
            NOW,
        )
    assert exc.value.code == "TOKEN_TYP_MISMATCH"
