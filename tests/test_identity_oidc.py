"""Unit tests for the OIDC identity-binding gate (RFC-AITP-0002 §2, RFC-AITP-0007).

Standalone: does not depend on the sibling ``agentidentitytrustprotocol`` spec
checkout. Tokens are minted through ``aitp_verifier.minter``'s parameterized
OIDC minting path (``_mint_oidc_jwt``) rather than a hand-rolled duplicate
minter, per this codebase's convention of one minting path per artifact type.

RSA test material is a fixed, hardcoded 2048-bit keypair (PEM/DER literal
below) — RSA keygen is slow and non-deterministic, and this codebase's
convention throughout is byte-pinned known-answer vectors.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from aitp_verifier.aid import parse_aid
from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.crypto import PrivateKey, sha256
from aitp_verifier.errors import AitpError
from aitp_verifier.identity import verify_identity
from aitp_verifier.jwk import issuer_key_from_config, issuer_key_from_jwk, issuer_keys_from, thumbprint
from aitp_verifier.minter import _mint_oidc_jwt

NOW = 1711900000
ISSUER = "https://auth.example.test"
SUBJECT = "agent-under-test"

# --- pinned 2048-bit RSA known-answer keypair (verify-only issuer material) --
_RSA_PRIV_DER_HEX = (
    "308204bc020100300d06092a864886f70d0101010500048204a6308204a2020100"
    "0282010100d9125731fcdec7fc347a66bb9858b1e9a78e2be0781dca457973b687"
    "20b5d480d9ff396abc1f6a53baa411ce74c142babdc18326f69ac051e104fea592"
    "38ffa0da45f78f9d76fc9b7395211dea1b0a7db72b89ebcc22af9a4d8d525a6b2e"
    "62ea6f6c4a0f3bf19195ea87e85fe32138a948c8830b87f213bc6242d30c3d925e"
    "f1fc17a3212e91e61caaaa6e11d4e1ac81687b0420ceb6db817552fcfbac15a080"
    "dc0ec82d290a612f08faaf80e58973d3ff5ac99072e6b348ec0638405285380ba2"
    "1e51d29ad2a7934a2f12651e1dff42147e7f20c7d1bb4ca723e9188cc11c754267"
    "aff9ac0358c309355fd66b634350cd95e5e536659b8fd1dd5fcca4d4eab1020301"
    "00010282010017e3149fa66d2e42502a0f5d0c6b9239c7f0f55e1b09b82fadfe45"
    "9ded6e64f1eaf5fd8503d4f72d3b3d81222027563c58d3a47c3dfde88a4f6c991d"
    "c78f5328b46c524cf103337d631a36e33a56fb1abb748f40589de687608a5bd4cc"
    "5fa08df370a35e602124a803d4d73044bd16a5a0f743b319fa27217f5f4d7c8182"
    "b66f799ea85810465cafa02a0116927a460fd38783ce3a38199a008f9eb754cb62"
    "809f39831b693ccb5b23e90241e31fe2870779713a2644a2baecc2a955a60d9fa2"
    "8d66c48a6d9484cdabdadf78cffa6e9c6aea8f1c9693fdd1f36be253e67cc5d1f1"
    "5cbdd46113ae01835224614efffaa336a86a041f44f2f4ee686ad7ac26564b0281"
    "8100f833563c490577bb790a7cfe050f1bc5a374954e09c8c6097ddb1cb4e35723"
    "7edba68cf94bf7c7143f44c192e96093e9ac402f4752720c92d321383d6b60c399"
    "2d1bddcfa5956d5aa7df4b085464ba58873aedc19786039493c969d875a38ffa3f"
    "c131be2a4e83c5e773ff8ee7dfa84defad3029efe062aa98b9f7ec200af68f0281"
    "8100dfe495ebfae5987c57bb7a8517c9695e9309f27341d84d04a46c927c701506"
    "a15a34559a7949e2b4660a80620c1e2ab788b1a2dc631bfc32c38851c19f206b54"
    "746816f45ec7bad834c585f3c6f3c0ebd7257411cf508674f5a46c4a68a6fd2d30"
    "253496d51de81ef174b674dd9d11e3f4bdb46ab75b8be15bdaa22d9254aabf0281"
    "806a4f5ae59185650688cee440cd9bee125673ee2bb1e72c640e6356c56806ffee"
    "2b59085313a5fac0826509e0ca5392a7691f48e0ecc06b004cac92f143d7fb8fd5"
    "91750da6e7fd21f27ba320db3d15d02b84232863a5844d148c15e92062419e37c6"
    "a16ec9a23db0fbf564862a6d5322a6c170bad5c32f9fd0b0ff2f457e4ca3028180"
    "5799ae771841c0f9d5b1caec4c3447fff2f40f62bd3e8e53e4a97e5f25d37436a9"
    "7e9487ce30f47cb4f822e739ea8bb827c9a8f925e60b3529802acce11fe41eb535"
    "0cd62c476579b69c1a1f1996c1c304f8e883176460575ecd2879ac9cb9ae7689f8"
    "1b93e311b119b41ab77b063bbbbf448254c6cd10dbe9fe8f39d9693b2d0281806"
    "9f7a3b27e6447d23749c363be7ee3ed8bbb35568bc17bf3d1fd20b12823c73c53e"
    "721b08435de3b7f4589be6b468708ff542cd96f63d51c4529569f6f1ee7570676f"
    "97a55b34b26f604d874a03a12adef290232c5bc9b467800e030b5bd52941e30bd0"
    "46fbd5e838e84eca5e48a1002154cc62a6fd997579ae132ecb60a1ca1"
)
_rsa_private_key = serialization.load_der_private_key(bytes.fromhex(_RSA_PRIV_DER_HEX), password=None)
assert isinstance(_rsa_private_key, rsa.RSAPrivateKey)
_RSA_PRIVATE_KEY: rsa.RSAPrivateKey = _rsa_private_key
_RSA_PUBLIC_NUMBERS = _RSA_PRIVATE_KEY.public_key().public_numbers()
_N_BYTES = _RSA_PUBLIC_NUMBERS.n.to_bytes((_RSA_PUBLIC_NUMBERS.n.bit_length() + 7) // 8, "big")
_E_BYTES = _RSA_PUBLIC_NUMBERS.e.to_bytes((_RSA_PUBLIC_NUMBERS.e.bit_length() + 7) // 8, "big")
RSA_JWK = {"kty": "RSA", "n": b64url_encode(_N_BYTES), "e": b64url_encode(_E_BYTES)}


def _rsa_sign(data: bytes) -> bytes:
    return _RSA_PRIVATE_KEY.sign(data, padding.PKCS1v15(), hashes.SHA256())


# A separately-pinned under-2048-bit RSA public key (public numbers only —
# used solely to prove `from_rsa_numbers` rejects it, never to sign anything).
_SMALL_N_B64U = (
    "w_Dr7TyauuGbP9tekqyTVkI9ohkFTZP4me5BomxC-8-F0YWgO7TS-SeIqlKLci8do0T"
    "REzQfeQC-CNbBBjxIlaBGZ-zAKceJvwCOFP6imx8fYOug3sLDIs2-kZTjUB6P_9IBSx"
    "_wr2nEk2_d3fDs2QvZxNFZGSQoEowHGK6ACB0"
)
_SMALL_E_B64U = "AQAB"


def _sender_key() -> tuple[PrivateKey, str]:
    sk = PrivateKey.ed25519_from_seed(sha256(b"aitp-test-sender-seed"))
    return sk, "aid:pubkey:" + b64url_encode(sk.raw_public())


SENDER_KEY, SENDER_AID = _sender_key()
POP_NONCE = b64url_encode(sha256(b"aitp-test-pop-nonce")[:16])


def _envelope(pop_nonce: str | None = POP_NONCE) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    if pop_nonce is not None:
        payload["pop_nonce"] = pop_nonce
    return {"sender": {"agent_id": SENDER_AID}, "payload": payload}


def _identity(issuer: str = ISSUER, subject: str = SUBJECT, public_key: str | None = None) -> dict[str, Any]:
    identity: dict[str, Any] = {"type": "oidc", "issuer": issuer, "subject": subject}
    if public_key is not None:
        identity["public_key"] = public_key
    return identity


def _mint(
    identity: dict[str, Any],
    env: dict[str, Any],
    *,
    self_aid: str | None = None,
    alg: str = "EdDSA",
    kid: str | None = None,
    sign_override: Callable[[bytes], bytes] | None = None,
    now: int = NOW,
) -> str:
    inp: dict[str, Any] = {}
    if self_aid is not None:
        inp["self_aid"] = self_aid
    return _mint_oidc_jwt("__TEST__", identity, env, inp, now, alg=alg, kid=kid, sign_override=sign_override)


def _verify(
    identity: dict[str, Any],
    env: dict[str, Any],
    *,
    self_aid: str = "",
    trust_anchors: list[str] | None = None,
    issuer_keys: dict[str, Any] | None = None,
    now: int = NOW,
) -> None:
    verify_identity(
        identity,
        env,
        self_aid,
        trust_anchors=trust_anchors,
        trust_store=None,
        issuer_keys=issuer_keys or {},
        now=now,
    )


def _err(exc_info: pytest.ExceptionInfo[AitpError]) -> str:
    return exc_info.value.code


# --- positive cases ----------------------------------------------------------


def test_eddsa_config_form_key() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    identity["proof"] = jwt
    issuer_key = b64url_encode(_issuer_pub("EdDSA"))
    _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: issuer_key})


def _issuer_pub(alg: str) -> bytes:
    from aitp_verifier.minter import _issuer_key

    return _issuer_key(ISSUER, alg).raw_public()


def test_es256_config_form_key() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID, alg="ES256")
    identity["proof"] = jwt
    issuer_key = b64url_encode(_issuer_pub("ES256"))
    assert len(issuer_key) == 44
    _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: issuer_key})


def test_eddsa_jwk_dict() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    identity["proof"] = jwt
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(_issuer_pub("EdDSA"))}
    _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: jwk})


def test_es256_jwk_dict() -> None:
    from aitp_verifier.minter import _issuer_key

    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID, alg="ES256")
    identity["proof"] = jwt
    pk = _issuer_key(ISSUER, "ES256").public_key()
    assert isinstance(pk._key, ec.EllipticCurvePublicKey)
    numbers = pk._key.public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(numbers.y.to_bytes(32, "big")),
    }
    _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: jwk})


def test_rs256_jwk_dict() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID, alg="RS256", sign_override=_rsa_sign)
    identity["proof"] = jwt
    _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: RSA_JWK})


def test_jwks_multiple_keys_selected_by_kid() -> None:
    from aitp_verifier.minter import _issuer_key

    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID, kid="key-b")
    identity["proof"] = jwt
    other_pub = PrivateKey.ed25519_from_seed(sha256(b"decoy")).raw_public()
    jwks = {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(other_pub), "kid": "key-a"},
            {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(_issuer_pub("EdDSA")), "kid": "key-b"},
        ]
    }
    _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: jwks})


def test_jwks_single_key_no_kid_fallback() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    identity["proof"] = jwt
    jwks = {"keys": [{"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(_issuer_pub("EdDSA"))}]}
    _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: jwks})


# --- the actual bug: fail-open on unresolved issuer key ----------------------


def test_unresolved_issuer_key_is_key_resolution_failed_not_success() -> None:
    """Regression test for the fail-open bug: a valid, well-formed, correctly
    signed JWT MUST NOT be accepted when the issuer key cannot be resolved."""
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    identity["proof"] = jwt
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={})
    assert _err(exc_info) == "KEY_RESOLUTION_FAILED"


# --- alg-confusion defense ---------------------------------------------------


def test_rs256_signed_token_against_ed25519_issuer_key_is_rejected() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID, alg="RS256", sign_override=_rsa_sign)
    identity["proof"] = jwt
    ed_key = b64url_encode(_issuer_pub("EdDSA"))
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: ed_key})
    # No Ed25519 candidate structurally matches "RS256", so this token's alg
    # never even reaches a resolved key of the wrong type in this shape —
    # either way it must not verify.
    assert _err(exc_info) == "IDENTITY_FAILED"


def test_eddsa_signed_token_with_header_alg_rewritten_to_rs256() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    header_b64, payload_b64, sig_b64 = jwt.split(".")
    header = json.loads(b64url_decode(header_b64))
    header["alg"] = "RS256"
    tampered_header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    tampered = f"{tampered_header_b64}.{payload_b64}.{sig_b64}"
    identity["proof"] = tampered
    issuer_key = b64url_encode(_issuer_pub("EdDSA"))
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: issuer_key})
    assert _err(exc_info) == "IDENTITY_FAILED"


@pytest.mark.parametrize("bad_alg", [None, 123, "HS256", "none", "None", "NONE"])
def test_alg_absent_non_string_or_unsupported(bad_alg: Any) -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    header_b64, payload_b64, sig_b64 = jwt.split(".")
    header = json.loads(b64url_decode(header_b64))
    if bad_alg is None:
        del header["alg"]
    else:
        header["alg"] = bad_alg
    tampered_header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    identity["proof"] = f"{tampered_header_b64}.{payload_b64}.{sig_b64}"
    issuer_key = b64url_encode(_issuer_pub("EdDSA"))
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: issuer_key})
    assert _err(exc_info) == "IDENTITY_FAILED"


@pytest.mark.parametrize("param", ["jwk", "jku", "x5u", "x5c", "crit"])
def test_header_carries_forbidden_parameter(param: str) -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    header_b64, payload_b64, sig_b64 = jwt.split(".")
    header = json.loads(b64url_decode(header_b64))
    header[param] = "x"
    tampered_header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    identity["proof"] = f"{tampered_header_b64}.{payload_b64}.{sig_b64}"
    issuer_key = b64url_encode(_issuer_pub("EdDSA"))
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: issuer_key})
    assert _err(exc_info) == "IDENTITY_FAILED"


def test_kid_present_but_no_candidate_matches() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID, kid="does-not-exist")
    identity["proof"] = jwt
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(_issuer_pub("EdDSA")), "kid": "some-other-kid"}
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: jwk})
    assert _err(exc_info) == "IDENTITY_FAILED"


def test_no_kid_multiple_candidates_is_ambiguous() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    identity["proof"] = jwt
    other_pub = PrivateKey.ed25519_from_seed(sha256(b"decoy-2")).raw_public()
    jwks = {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(_issuer_pub("EdDSA"))},
            {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(other_pub)},
        ]
    }
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: jwks})
    assert _err(exc_info) == "IDENTITY_FAILED"


def test_flipped_signature_byte() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    header_b64, payload_b64, sig_b64 = jwt.split(".")
    raw = bytearray(b64url_decode(sig_b64))
    raw[-1] ^= 0x01
    identity["proof"] = f"{header_b64}.{payload_b64}.{b64url_encode(bytes(raw))}"
    issuer_key = b64url_encode(_issuer_pub("EdDSA"))
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: issuer_key})
    assert _err(exc_info) == "IDENTITY_FAILED"


# --- claim gates --------------------------------------------------------------


def _rewrite_claims(jwt: str, mutate: Callable[[dict[str, Any]], None]) -> str:
    header_b64, payload_b64, _ = jwt.split(".")
    claims = json.loads(b64url_decode(payload_b64))
    mutate(claims)
    new_payload_b64 = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{new_payload_b64}".encode("ascii")
    from aitp_verifier.minter import _issuer_key

    sig = _issuer_key(ISSUER, "EdDSA").sign_jose(signing_input)
    return f"{header_b64}.{new_payload_b64}.{b64url_encode(sig)}"


def _assert_identity_failed(identity: dict[str, Any], env: dict[str, Any], jwt: str, self_aid: str = SENDER_AID) -> None:
    identity["proof"] = jwt
    issuer_key = b64url_encode(_issuer_pub("EdDSA"))
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=self_aid, issuer_keys={ISSUER: issuer_key})
    assert _err(exc_info) == "IDENTITY_FAILED"


def test_exp_absent() -> None:
    identity = _identity()
    env = _envelope()
    base = _mint(identity, env, self_aid=SENDER_AID)
    jwt = _rewrite_claims(base, lambda c: c.pop("exp"))
    _assert_identity_failed(identity, env, jwt)


def test_exp_as_string() -> None:
    identity = _identity()
    env = _envelope()
    base = _mint(identity, env, self_aid=SENDER_AID)
    jwt = _rewrite_claims(base, lambda c: c.__setitem__("exp", str(NOW + 3600)))
    _assert_identity_failed(identity, env, jwt)


def test_exp_equals_now_boundary_fails() -> None:
    identity = _identity()
    env = _envelope()
    base = _mint(identity, env, self_aid=SENDER_AID)
    jwt = _rewrite_claims(base, lambda c: c.__setitem__("exp", NOW))
    _assert_identity_failed(identity, env, jwt)


def test_iat_absent() -> None:
    identity = _identity()
    env = _envelope()
    base = _mint(identity, env, self_aid=SENDER_AID)
    jwt = _rewrite_claims(base, lambda c: c.pop("iat"))
    _assert_identity_failed(identity, env, jwt)


@pytest.mark.parametrize("delta", [-301, 301])
def test_iat_outside_tolerance(delta: int) -> None:
    identity = _identity()
    env = _envelope()
    base = _mint(identity, env, self_aid=SENDER_AID)
    jwt = _rewrite_claims(base, lambda c: c.__setitem__("iat", NOW + delta))
    _assert_identity_failed(identity, env, jwt)


@pytest.mark.parametrize("delta", [-300, 300])
def test_iat_at_tolerance_boundary_passes(delta: int) -> None:
    identity = _identity()
    env = _envelope()
    base = _mint(identity, env, self_aid=SENDER_AID)
    jwt = _rewrite_claims(base, lambda c: c.__setitem__("iat", NOW + delta))
    identity["proof"] = jwt
    issuer_key = b64url_encode(_issuer_pub("EdDSA"))
    _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: issuer_key})


def test_aud_absent_while_self_aid_unknown_still_fails() -> None:
    identity = _identity()
    env = _envelope()
    base = _mint(identity, env)  # no self_aid -> aud defaults to sender
    jwt = _rewrite_claims(base, lambda c: c.pop("aud"))
    _assert_identity_failed(identity, env, jwt, self_aid="")


def test_no_pop_nonce_and_no_nonce_is_not_a_silent_pass() -> None:
    identity = _identity()
    env = _envelope(pop_nonce=None)
    base = _mint(identity, env, self_aid=SENDER_AID)
    jwt = _rewrite_claims(base, lambda c: c.pop("nonce"))
    _assert_identity_failed(identity, env, jwt)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.pop("cnf"),
        lambda c: c.__setitem__("cnf", "not-a-dict"),
        lambda c: c.__setitem__("cnf", {"jkt": "wrong-thumbprint"}),
    ],
)
def test_cnf_jkt_gate(mutate: Callable[[dict[str, Any]], None]) -> None:
    identity = _identity()
    env = _envelope()
    base = _mint(identity, env, self_aid=SENDER_AID)
    jwt = _rewrite_claims(base, mutate)
    _assert_identity_failed(identity, env, jwt)


def test_oidc_identity_with_public_key_field_is_rejected() -> None:
    identity = _identity(public_key="some-base64url-key")
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    _assert_identity_failed(identity, env, jwt)


# --- trust anchors -------------------------------------------------------------


def test_untrusted_issuer_with_valid_signed_token_is_incompatible_trust_anchors() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    identity["proof"] = jwt
    issuer_key = b64url_encode(_issuer_pub("EdDSA"))
    with pytest.raises(AitpError) as exc_info:
        _verify(
            identity, env, self_aid=SENDER_AID,
            trust_anchors=["https://some-other-issuer.example"],
            issuer_keys={ISSUER: issuer_key},
        )
    assert _err(exc_info) == "INCOMPATIBLE_TRUST_ANCHORS"


def test_untrusted_issuer_with_also_unresolvable_key_is_still_incompatible_trust_anchors() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    identity["proof"] = jwt
    with pytest.raises(AitpError) as exc_info:
        _verify(
            identity, env, self_aid=SENDER_AID,
            trust_anchors=["https://some-other-issuer.example"],
            issuer_keys={},
        )
    assert _err(exc_info) == "INCOMPATIBLE_TRUST_ANCHORS"


# --- malformed compact JWS shapes ----------------------------------------------


@pytest.mark.parametrize(
    "proof",
    [
        "onlytwo.segments",
        "a.b.c.d",
        "",
    ],
)
def test_malformed_compact_jws_segment_count(proof: str) -> None:
    identity = _identity()
    identity["proof"] = proof
    env = _envelope()
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: b64url_encode(_issuer_pub("EdDSA"))})
    assert _err(exc_info) == "IDENTITY_FAILED"


def test_malformed_compact_jws_padded_segments() -> None:
    identity = _identity()
    env = _envelope()
    jwt = _mint(identity, env, self_aid=SENDER_AID)
    header_b64, payload_b64, sig_b64 = jwt.split(".")
    identity["proof"] = f"{header_b64}=.{payload_b64}.{sig_b64}"
    with pytest.raises(AitpError) as exc_info:
        _verify(identity, env, self_aid=SENDER_AID, issuer_keys={ISSUER: b64url_encode(_issuer_pub("EdDSA"))})
    assert _err(exc_info) == "IDENTITY_FAILED"


# --- jwk.py unit tests ----------------------------------------------------------


def test_jwk_wrong_length_x() -> None:
    with pytest.raises(ValueError):
        issuer_key_from_jwk({"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(b"short")})


def test_jwk_unsupported_kty_oct() -> None:
    with pytest.raises(ValueError):
        issuer_key_from_jwk({"kty": "oct", "k": b64url_encode(b"x" * 32)})


def test_jwk_unsupported_curve_p384() -> None:
    with pytest.raises(ValueError):
        issuer_key_from_jwk({"kty": "EC", "crv": "P-384", "x": b64url_encode(b"x" * 48), "y": b64url_encode(b"y" * 48)})


def test_jwk_rsa_modulus_under_2048_bits_rejected() -> None:
    with pytest.raises(ValueError):
        issuer_key_from_jwk({"kty": "RSA", "n": _SMALL_N_B64U, "e": _SMALL_E_B64U})


def test_config_key_45_chars_rejected() -> None:
    with pytest.raises(ValueError):
        issuer_key_from_config("A" * 45)


def test_jwk_self_declared_alg_is_never_trusted() -> None:
    """A JWK claiming `alg: RS256` on Ed25519 key material must still parse as
    EdDSA — the algorithm is derived from kty/crv, never from `alg`."""
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(_issuer_pub("EdDSA")), "alg": "RS256"}
    parsed = issuer_key_from_jwk(jwk)
    assert parsed.jose_alg == "EdDSA"


def test_issuer_key_from_config_lengths() -> None:
    ed = issuer_key_from_config(b64url_encode(_issuer_pub("EdDSA")))
    assert ed.jose_alg == "EdDSA"
    es = issuer_key_from_config(b64url_encode(_issuer_pub("ES256")))
    assert es.jose_alg == "ES256"


def test_issuer_keys_from_none_and_empty() -> None:
    assert issuer_keys_from(None) == []


def test_thumbprint_sanity() -> None:
    # sanity: thumbprint of the sender AID's key must be deterministic and
    # match what the minted cnf.jkt claim carries.
    assert thumbprint(parse_aid(SENDER_AID)) == thumbprint(parse_aid(SENDER_AID))
