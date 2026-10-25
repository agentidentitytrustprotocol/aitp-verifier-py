"""The ``spiffe`` identity binding (RFC-AITP-0002 §6, aitp_verifier/spiffe.py).

The corpus fixtures id-024..id-030 are re-run here with the reason each one
must fail for, so a negative cannot pass by failing early for some other
reason. The rest mutate one rule at a time against verify_identity directly:
the identity binding is checked before the envelope signature, so a mutated
descriptor needs no re-signed envelope.
"""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import NameOID

from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.crypto import PrivateKey, sha256
from aitp_verifier.errors import AitpError
from aitp_verifier.harness import run_operation
from aitp_verifier.identity import pinned_key_proof_input, verify_identity
from aitp_verifier.jwk import thumbprint_for_aid
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.manifest import verify_manifest
from aitp_verifier.minter import _spiffe_ca, _spiffe_key, mint_input
from aitp_verifier.spiffe import SPIFFE_FEATURE, parse_spiffe_id, spiffe_x509_proof_input
from aitp_verifier.timeutil import REFERENCE_CLOCK

NOW = REFERENCE_CLOCK
SUBJECT = "spiffe://prod.example.com/ns/payments/sa/agent-b"
LEAF_AID = "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU"  # kat-keypair-003


def _fixture(spec_dir: Path, fixture_id: str) -> dict[str, Any]:
    path = next((spec_dir / "schemas/conformance").glob(f"{fixture_id}-*.json"))
    fixture: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return fixture


def _minted(spec_dir: Path, fixture_id: str) -> dict[str, Any]:
    inp = mint_input(_fixture(spec_dir, fixture_id)["input"], NOW, load_kat_keys(spec_dir))
    inp.pop("operation")
    return inp


# ── The corpus, for the right reason ────────────────────────────────────────


@pytest.mark.parametrize(("fixture_id", "reason"), [
    ("id-024", None),
    ("id-025", None),
    ("id-026", "no SPIFFE bundle for trust domain staging.example.com"),
    ("id-027", "nonce != message pop_nonce"),
    ("id-028", "exp missing, not an integer, or not strictly in the future"),
    ("id-029", "aud != verifier AID"),
    ("id-030", "carries 2 URI SANs"),
])
def test_corpus_fixture_outcome_and_reason(spec_dir: Path, fixture_id: str, reason: str | None) -> None:
    inp = {**_minted(spec_dir, fixture_id), "_feature": SPIFFE_FEATURE}
    code, result = run_operation("verify_handshake_payload", inp, load_kat_keys(spec_dir), accept_presented_type=True)
    if reason is None:
        assert (code, result) == (None, {"ok": True})
    else:
        assert code == "IDENTITY_FAILED" and reason in result["message"]


def test_without_the_feature_spiffe_is_an_unknown_type(spec_dir: Path) -> None:
    inp = _minted(spec_dir, "id-024")
    code, result = run_operation("verify_handshake_payload", inp, load_kat_keys(spec_dir), accept_presented_type=True)
    assert code == "IDENTITY_FAILED" and "unknown identity type 'spiffe'" in result["message"]


def test_enabled_with_no_bundle_store_trusts_no_trust_domain(spec_dir: Path) -> None:
    inp = {**_minted(spec_dir, "id-024"), "_feature": SPIFFE_FEATURE}
    del inp["trust_anchors_config"]
    code, result = run_operation("verify_handshake_payload", inp, load_kat_keys(spec_dir), accept_presented_type=True)
    assert code == "IDENTITY_FAILED" and "no SPIFFE bundle" in result["message"]


def test_a_receiver_that_does_not_accept_spiffe_rejects_the_type(spec_dir: Path) -> None:
    """§6.6: the receiver's step 8 policy, after a valid binding."""
    inp = {**_minted(spec_dir, "id-024"), "_feature": SPIFFE_FEATURE, "self_accepted_identity_types": ["oidc"]}
    code, _ = run_operation("verify_handshake_payload", inp, load_kat_keys(spec_dir), accept_presented_type=False)
    assert code == "INCOMPATIBLE_IDENTITY_TYPE"


# ── kat-spiffe-x509-proof-001 (§6.4.1) ──────────────────────────────────────


def test_x509_proof_kat(spec_dir: Path) -> None:
    vectors = json.loads((spec_dir / "schemas/conformance/known-answer/jcs-sha256.json").read_text(encoding="utf-8"))
    kat = next(v for v in vectors["vectors"] if v["id"] == "kat-spiffe-x509-proof-001")
    args = (kat["sender_aid"], kat["receiver_aid"], kat["message_id"], kat["timestamp"], kat["pop_nonce"])
    proof_input = spiffe_x509_proof_input(*args)
    assert proof_input.hex() == kat["proof_input_hex"] and len(proof_input) == kat["proof_input_len_bytes"] == 194
    assert sha256(proof_input).hex() == kat["sha256_hex"]
    keys = load_kat_keys(spec_dir)
    sig = b64url_decode(kat["signature_b64url"])
    assert keys[kat["signer_aid"]].public_key().verify_digest(sha256(proof_input), sig)
    assert not keys[kat["sender_aid"]].public_key().verify_digest(sha256(proof_input), sig)
    assert not keys[kat["signer_aid"]].public_key().verify_digest(sha256(pinned_key_proof_input(*args)), sig)


# ── SPIFFE ID grammar (§6.1) ────────────────────────────────────────────────


@pytest.mark.parametrize("value", [
    SUBJECT,
    "spiffe://td/a",
    "spiffe://a.b-c_d/A.b-C_9/...",
])
def test_valid_spiffe_ids(value: str) -> None:
    assert parse_spiffe_id(value)[0] == value.split("/")[2]


@pytest.mark.parametrize("value", [
    "SPIFFE://prod.example.com/a",  # scheme not lowercase (Tightening: no case folding)
    "spiffe://Prod.example.com/a",  # trust domain not lowercase
    "spiffe://prod.example.com",  # no path: a trust domain, not a workload
    "spiffe://prod.example.com/",  # trailing /
    "spiffe://prod.example.com/a/",
    "spiffe://prod.example.com/a//b",
    "spiffe://prod.example.com/./a",
    "spiffe://prod.example.com/a/..",
    "spiffe://prod.example.com:443/a",  # port
    "spiffe://user@prod.example.com/a",  # userinfo
    "spiffe://prod.example.com/a?x=1",
    "spiffe://prod.example.com/a#f",
    "spiffe:///a",
    "spiffe://" + "a" * 256 + "/a",
    "spiffe://td/" + "a" * 2048,
    "https://prod.example.com/a",
])
def test_invalid_spiffe_ids(value: str) -> None:
    with pytest.raises(AitpError) as exc:
        parse_spiffe_id(value)
    assert exc.value.code == "IDENTITY_FAILED"


# ── Builders for single-rule mutations ──────────────────────────────────────


def _bundles(*keys: dict[str, Any], trust_domain: str = "prod.example.com") -> list[dict[str, Any]]:
    return [{"trust_domain": trust_domain, "bundle": {"keys": list(keys)}}]


def _ec_jwk(key: PrivateKey) -> dict[str, Any]:
    numbers = key.native.public_key().public_numbers()  # type: ignore[attr-defined]
    return {"kty": "EC", "crv": "P-256", "x": b64url_encode(numbers.x.to_bytes(32, "big")),
            "y": b64url_encode(numbers.y.to_bytes(32, "big"))}


JWT_KEY = _spiffe_key("jwt-authority")
JWT_JWK = {**_ec_jwk(JWT_KEY), "kid": "aitp-test-spiffe-jwt-1", "use": "jwt-svid"}
CA_KEY = _spiffe_key("x509-ca")


def _der_b64(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


def _ca_jwk(cert: x509.Certificate | None = None) -> dict[str, Any]:
    return {**_ec_jwk(CA_KEY), "use": "x509-svid", "x5c": [_der_b64(cert or _spiffe_ca(NOW))]}


def _envelope(spec_dir: Path) -> tuple[dict[str, Any], str]:
    inp = _minted(spec_dir, "id-024")
    return inp["envelope"], inp["self_aid"]


def _jwt(env: dict[str, Any], self_aid: str, *, header: dict[str, Any] | None = None,
         key: PrivateKey = JWT_KEY, **claims: Any) -> str:
    body: dict[str, Any] = {
        "sub": SUBJECT, "aud": [self_aid], "iat": NOW, "exp": NOW + 300, "nonce": env["payload"]["pop_nonce"],
        "cnf": {"jkt": thumbprint_for_aid(env["sender"]["agent_id"])},
    }
    for name, value in claims.items():
        if value is None:
            body.pop(name, None)
        else:
            body[name] = value
    head = header if header is not None else {"alg": "ES256", "kid": "aitp-test-spiffe-jwt-1", "typ": "JWT"}
    signing_input = (b64url_encode(json.dumps(head).encode()) + "." + b64url_encode(json.dumps(body).encode()))
    return signing_input + "." + b64url_encode(key.sign_jose(signing_input.encode()))


def _check(identity: dict[str, Any], env: dict[str, Any], self_aid: str, bundles: Any) -> None:
    verify_identity(identity, env, self_aid, trust_anchors=(), trust_store=None, issuer_keys={}, now=NOW,
                    spiffe_bundles=bundles)


def _rejects(reason: str, identity: dict[str, Any], env: dict[str, Any], self_aid: str, bundles: Any) -> None:
    with pytest.raises(AitpError) as exc:
        _check(identity, env, self_aid, bundles)
    assert exc.value.code == "IDENTITY_FAILED"
    assert reason in exc.value.message


def _jwt_identity(proof: str, **extra: Any) -> dict[str, Any]:
    return {"type": "spiffe", "subject": SUBJECT, "svid_type": "jwt-svid", "proof": proof, **extra}


# ── JWT-SVID (§6.3) ─────────────────────────────────────────────────────────


def test_jwt_svid_string_aud_is_one_value(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    _check(_jwt_identity(_jwt(env, me, aud=me)), env, me, _bundles(JWT_JWK))


@pytest.mark.parametrize(("mutate", "reason"), [
    (lambda env, me: _jwt(env, me, aud=[me, "aid:pubkey:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"]),
     "does not hold exactly one value"),
    (lambda env, me: _jwt(env, me, aud=None), "does not hold exactly one value"),
    (lambda env, me: _jwt(env, me, sub="spiffe://prod.example.com/ns/payments/sa/other"), "sub != identity subject"),
    (lambda env, me: _jwt(env, me, iat=None), "iat missing"),
    (lambda env, me: _jwt(env, me, iat=NOW - 301), "iat missing"),
    (lambda env, me: _jwt(env, me, nonce=None), "nonce != message pop_nonce"),
    (lambda env, me: _jwt(env, me, cnf=None), "cnf.jkt does not bind the sender key"),
    (lambda env, me: _jwt(env, me, cnf={"jkt": "x"}), "cnf.jkt does not bind the sender key"),
    (lambda env, me: _jwt(env, me, header={"alg": "ES256", "typ": "JWT"}), "no string kid"),
    (lambda env, me: _jwt(env, me, header={"alg": "ES256", "kid": "other"}), "0 jwt-svid bundle keys carry kid"),
    (lambda env, me: _jwt(env, me, header={"alg": "ES256", "kid": "aitp-test-spiffe-jwt-1", "typ": "jwt"}),
     "is not JWT or JOSE"),
    (lambda env, me: _jwt(env, me, header={"alg": "ES256", "kid": "aitp-test-spiffe-jwt-1", "x5u": "https://x"}),
     "only alg, kid, typ are allowed"),
    (lambda env, me: _jwt(env, me, header={"alg": "EdDSA", "kid": "aitp-test-spiffe-jwt-1"}), "not a JWT-SVID algorithm"),
    (lambda env, me: _jwt(env, me, header={"alg": "none", "kid": "aitp-test-spiffe-jwt-1"}), "not a JWT-SVID algorithm"),
    (lambda env, me: _jwt(env, me, header={"alg": "HS256", "kid": "aitp-test-spiffe-jwt-1"}), "not a JWT-SVID algorithm"),
    (lambda env, me: _jwt(env, me, header={"alg": "ES384", "kid": "aitp-test-spiffe-jwt-1"}), "needs an EC P-384 key"),
    (lambda env, me: _jwt(env, me, header={"alg": "RS256", "kid": "aitp-test-spiffe-jwt-1"}), "needs an RSA key"),
    (lambda env, me: _jwt(env, me, header={"alg": "PS256", "kid": "aitp-test-spiffe-jwt-1"}), "needs an RSA key"),
    (lambda env, me: _jwt(env, me, key=CA_KEY), "signature invalid"),
])
def test_jwt_svid_rules(spec_dir: Path, mutate: Callable[[dict[str, Any], str], str], reason: str) -> None:
    env, me = _envelope(spec_dir)
    _rejects(reason, _jwt_identity(mutate(env, me)), env, me, _bundles(JWT_JWK))


_RSA_KEY = rsa.generate_private_key(65537, 2048)
_EC_KEYS = {"ES256": ec.generate_private_key(ec.SECP256R1()), "ES384": ec.generate_private_key(ec.SECP384R1()),
            "ES512": ec.generate_private_key(ec.SECP521R1())}
_HASHES = {"256": hashes.SHA256(), "384": hashes.SHA384(), "512": hashes.SHA512()}
_CRV = {"ES256": ("P-256", 32), "ES384": ("P-384", 48), "ES512": ("P-521", 66)}


def _uint(n: int) -> str:
    return b64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def _authority(alg: str) -> tuple[dict[str, Any], Callable[[bytes], bytes]]:
    """A bundle JWK for *alg* and a JOSE signer under its private key."""
    digest = _HASHES[alg[2:]]
    if alg.startswith("ES"):
        priv = _EC_KEYS[alg]
        crv, size = _CRV[alg]
        nums = priv.public_key().public_numbers()
        jwk = {"kty": "EC", "crv": crv, "x": b64url_encode(nums.x.to_bytes(size, "big")),
               "y": b64url_encode(nums.y.to_bytes(size, "big"))}

        def sign(data: bytes) -> bytes:
            r, s_ = decode_dss_signature(priv.sign(data, ec.ECDSA(digest)))
            return r.to_bytes(size, "big") + s_.to_bytes(size, "big")
    else:
        pub = _RSA_KEY.public_key().public_numbers()
        jwk = {"kty": "RSA", "n": _uint(pub.n), "e": _uint(pub.e)}
        pad: padding.AsymmetricPadding = (padding.PKCS1v15() if alg.startswith("RS")
                                          else padding.PSS(mgf=padding.MGF1(digest), salt_length=digest.digest_size))

        def sign(data: bytes) -> bytes:
            return _RSA_KEY.sign(data, pad, digest)
    return {**jwk, "kid": "k1", "use": "jwt-svid"}, sign


def _signed_jwt(env: dict[str, Any], me: str, alg: str, sign: Callable[[bytes], bytes]) -> str:
    body = {"sub": SUBJECT, "aud": me, "iat": NOW, "exp": NOW + 300, "nonce": env["payload"]["pop_nonce"],
            "cnf": {"jkt": thumbprint_for_aid(env["sender"]["agent_id"])}}
    signing_input = (b64url_encode(json.dumps({"alg": alg, "kid": "k1"}).encode()) + "."
                     + b64url_encode(json.dumps(body).encode()))
    return signing_input + "." + b64url_encode(sign(signing_input.encode()))


@pytest.mark.parametrize("alg", sorted(f"{f}{b}" for f in ("RS", "PS", "ES") for b in ("256", "384", "512")))
def test_every_jwt_svid_algorithm_verifies(spec_dir: Path, alg: str) -> None:
    """RFC-AITP-0002 §6.3: all nine JWT-SVID algorithms, each signed with a
    generated key and verified; a tampered signature then fails."""
    env, me = _envelope(spec_dir)
    jwk, sign = _authority(alg)
    token = _signed_jwt(env, me, alg, sign)
    _check(_jwt_identity(token), env, me, _bundles(jwk))
    head, body, sig = token.split(".")
    flipped = bytearray(b64url_decode(sig))
    flipped[len(flipped) // 2] ^= 1
    _rejects("signature invalid", _jwt_identity(f"{head}.{body}.{b64url_encode(bytes(flipped))}"), env, me, _bundles(jwk))


@pytest.mark.parametrize(("key_alg", "header_alg", "reason"), [
    ("ES256", "ES384", "needs an EC P-384 key"),  # a curve fixes its one ES* alg
    ("ES384", "ES256", "needs an EC P-256 key"),
    ("ES512", "RS512", "needs an RSA key"),
    ("RS256", "ES256", "needs an EC P-256 key"),
    ("RS256", "PS256", "signature invalid"),  # same key, other padding: no cross-verification
    ("PS384", "RS384", "signature invalid"),
    ("RS256", "RS384", "signature invalid"),  # same key, other hash
])
def test_jwt_svid_alg_must_fit_the_key_and_the_signature(spec_dir: Path, key_alg: str, header_alg: str,
                                                        reason: str) -> None:
    env, me = _envelope(spec_dir)
    jwk, sign = _authority(key_alg)
    _rejects(reason, _jwt_identity(_signed_jwt(env, me, header_alg, sign)), env, me, _bundles(jwk))


@pytest.mark.parametrize("alg", ["none", "HS256", "HS512", "EdDSA", "Ed25519", "ES256K", "es256"])
def test_non_jwt_svid_algorithms_are_rejected(spec_dir: Path, alg: str) -> None:
    env, me = _envelope(spec_dir)
    jwk, sign = _authority("ES256")
    _rejects("not a JWT-SVID algorithm", _jwt_identity(_signed_jwt(env, me, alg, sign)), env, me, _bundles(jwk))


def test_jwt_svid_kid_must_name_exactly_one_key(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    _rejects("2 jwt-svid bundle keys carry kid", _jwt_identity(_jwt(env, me)), env, me, _bundles(JWT_JWK, JWT_JWK))


def test_a_key_without_the_jwt_svid_use_is_ignored(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    for jwk in ({k: v for k, v in JWT_JWK.items() if k != "use"}, {**JWT_JWK, "use": "sig"}, {**JWT_JWK, "use": "x509-svid"}):
        _rejects("bundle has no jwt-svid keys", _jwt_identity(_jwt(env, me)), env, me, _bundles(jwk))


# ── Descriptor and bundle store (§6.1, §6.2) ────────────────────────────────


@pytest.mark.parametrize(("extra", "reason"), [
    ({"issuer": "https://auth.openai.com"}, "MUST NOT carry 'issuer'"),
    ({"public_key": "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg"}, "MUST NOT carry 'public_key'"),
    ({"x5c": []}, "x5c is required for an x509-svid and forbidden for a jwt-svid"),
    ({"svid_type": "svid"}, "not jwt-svid or x509-svid"),
    ({"subject": "spiffe://PROD.example.com/ns/payments/sa/agent-b"}, "not lowercase"),
])
def test_descriptor_rules(spec_dir: Path, extra: dict[str, Any], reason: str) -> None:
    env, me = _envelope(spec_dir)
    _rejects(reason, _jwt_identity(_jwt(env, me), **extra), env, me, _bundles(JWT_JWK))


def test_a_trust_domain_listed_twice_rejects_the_store(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    _rejects("lists trust domain prod.example.com twice", _jwt_identity(_jwt(env, me)), env, me,
             [*_bundles(JWT_JWK), *_bundles(JWT_JWK)])


def test_only_the_subject_trust_domain_bundle_is_used(spec_dir: Path) -> None:
    """The authority key sits in another trust domain's bundle only."""
    env, me = _envelope(spec_dir)
    store = [*_bundles(trust_domain="prod.example.com"), *_bundles(JWT_JWK, trust_domain="other.example.com")]
    _rejects("bundle has no jwt-svid keys", _jwt_identity(_jwt(env, me)), env, me, store)


@pytest.mark.parametrize("itype", ["oidc", "pinned_key"])
def test_spiffe_members_are_rejected_on_other_types(spec_dir: Path, itype: str) -> None:
    env, me = _envelope(spec_dir)
    with pytest.raises(AitpError) as exc:
        _check({"type": itype, "subject": "s", "proof": "p", "svid_type": "jwt-svid"}, env, me, None)
    assert exc.value.code == "IDENTITY_FAILED" and "MUST NOT carry ['svid_type']" in exc.value.message


# ── X509-SVID (§6.4) ────────────────────────────────────────────────────────


def _cert(subject_key: Any, issuer_key: Any, issuer: x509.Name, *, sans: list[str] | None = None, ca: bool = False,
          path_length: int | None = None, digital_signature: bool = True, key_cert_sign: bool = False,
          crl_sign: bool = False, not_before: int = NOW - 60, not_after: int = NOW + 3600,
          extra: list[tuple[x509.ExtensionType, bool]] = (), name: str = "svid") -> x509.Certificate:  # type: ignore[assignment]
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(issuer)
        .public_key(subject_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.fromtimestamp(not_before, tz=timezone.utc))
        .not_valid_after(datetime.fromtimestamp(not_after, tz=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(digital_signature, False, False, False, False, key_cert_sign, crl_sign, False, False),
                       critical=True)
    )
    if sans is not None:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in sans]),
                                        critical=False)
    for ext, critical in extra:
        builder = builder.add_extension(ext, critical=critical)
    return builder.sign(issuer_key, hashes.SHA256())


def _leaf_pub(spec_dir: Path) -> tuple[Any, PrivateKey]:
    key = load_kat_keys(spec_dir)[LEAF_AID]
    return key.native.public_key(), key  # type: ignore[attr-defined]


def _x509_identity(env: dict[str, Any], me: str, chain: list[x509.Certificate], signer: PrivateKey,
                   proof: str | None = None) -> dict[str, Any]:
    if proof is None:
        data = spiffe_x509_proof_input(env["sender"]["agent_id"], me, env["message_id"], int(env["timestamp"]),
                                       env["payload"]["pop_nonce"])
        raw = b64url_encode(signer.sign_digest(sha256(data)))
        proof = f"p256.{raw}" if signer.alg == "p256" else raw
    return {"type": "spiffe", "subject": SUBJECT, "svid_type": "x509-svid", "proof": proof,
            "x5c": [_der_b64(c) for c in chain]}


CA = _spiffe_ca(NOW)


def _leaf(spec_dir: Path, **kw: Any) -> tuple[x509.Certificate, PrivateKey]:
    pub, priv = _leaf_pub(spec_dir)
    kw.setdefault("sans", [SUBJECT])
    return _cert(pub, CA_KEY.native, CA.subject, **kw), priv


def test_x509_svid_valid_and_p256_leaf(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    leaf, priv = _leaf(spec_dir)
    _check(_x509_identity(env, me, [leaf], priv), env, me, _bundles(_ca_jwk()))
    p256 = PrivateKey.p256_from_scalar(12345)
    p256_leaf = _cert(p256.native.public_key(), CA_KEY.native, CA.subject, sans=[SUBJECT])  # type: ignore[attr-defined]
    _check(_x509_identity(env, me, [p256_leaf], p256), env, me, _bundles(_ca_jwk()))


def test_x509_svid_through_an_intermediate(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    mid_key = ec.generate_private_key(ec.SECP256R1())
    mid = _cert(mid_key.public_key(), CA_KEY.native, CA.subject, ca=True, digital_signature=False, key_cert_sign=True,
                name="intermediate")
    pub, priv = _leaf_pub(spec_dir)
    leaf = _cert(pub, mid_key, mid.subject, sans=[SUBJECT])
    _check(_x509_identity(env, me, [leaf, mid], priv), env, me, _bundles(_ca_jwk()))
    # The same chain with the intermediate missing does not chain.
    _rejects("does not chain to an x509-svid CA", _x509_identity(env, me, [leaf], priv), env, me, _bundles(_ca_jwk()))
    # A pathLenConstraint of 0 on the anchor forbids the intermediate.
    zero = _cert(CA_KEY.native.public_key(), CA_KEY.native, CA.subject, ca=True, path_length=0,  # type: ignore[attr-defined]
                 digital_signature=False, key_cert_sign=True, name="aitp-test-spiffe-ca", not_before=NOW - 3600)
    _rejects("pathLenConstraint 0 is exceeded", _x509_identity(env, me, [leaf, mid], priv), env, me, _bundles(_ca_jwk(zero)))


def test_x509_svid_intermediate_must_be_a_ca(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    mid_key = ec.generate_private_key(ec.SECP256R1())
    mid = _cert(mid_key.public_key(), CA_KEY.native, CA.subject, ca=False, name="not-a-ca")
    pub, priv = _leaf_pub(spec_dir)
    leaf = _cert(pub, mid_key, mid.subject, sans=[SUBJECT])
    _rejects("x5c[1] is not a CA certificate", _x509_identity(env, me, [leaf, mid], priv), env, me, _bundles(_ca_jwk()))


@pytest.mark.parametrize(("kw", "reason"), [
    ({"sans": []}, "carries 0 URI SANs"),
    ({"sans": None}, "carries 0 URI SANs"),
    ({"sans": ["spiffe://prod.example.com/ns/payments/sa/other"]}, "URI SAN != identity subject"),
    ({"ca": True}, "cA is true"),
    ({"digital_signature": False}, "key usage must include digitalSignature"),
    ({"key_cert_sign": True}, "exclude keyCertSign and cRLSign"),
    ({"crl_sign": True}, "exclude keyCertSign and cRLSign"),
    ({"not_after": NOW - 1}, "outside its validity period"),
    ({"not_before": NOW + 1}, "outside its validity period"),
    ({"extra": [(x509.InhibitAnyPolicy(0), True)]}, "unprocessed critical extension"),
])
def test_x509_svid_leaf_rules(spec_dir: Path, kw: dict[str, Any], reason: str) -> None:
    env, me = _envelope(spec_dir)
    leaf, priv = _leaf(spec_dir, **kw)
    _rejects(reason, _x509_identity(env, me, [leaf], priv), env, me, _bundles(_ca_jwk()))


def test_x509_svid_rsa_leaf_key_is_rejected(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    rsa_leaf = _cert(rsa.generate_private_key(65537, 2048).public_key(), CA_KEY.native, CA.subject, sans=[SUBJECT])
    _rejects("neither Ed25519 nor P-256", _x509_identity(env, me, [rsa_leaf], PrivateKey.p256_from_scalar(1), proof="x"),
             env, me, _bundles(_ca_jwk()))


def test_x509_svid_from_another_ca_does_not_chain(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    rogue = ec.generate_private_key(ec.SECP256R1())
    pub, priv = _leaf_pub(spec_dir)
    leaf = _cert(pub, rogue, CA.subject, sans=[SUBJECT])  # same issuer name, other key
    _rejects("does not chain to an x509-svid CA", _x509_identity(env, me, [leaf], priv), env, me, _bundles(_ca_jwk()))


@pytest.mark.parametrize(("constraints", "reason"), [
    (x509.NameConstraints(permitted_subtrees=[x509.UniformResourceIdentifier("other.example.com")], excluded_subtrees=None),
     "do not permit trust domain prod.example.com"),
    (x509.NameConstraints(permitted_subtrees=None, excluded_subtrees=[x509.UniformResourceIdentifier(".example.com")]),
     "exclude trust domain prod.example.com"),
    (x509.NameConstraints(permitted_subtrees=[x509.DNSName("example.com")], excluded_subtrees=None),
     "name form other than URI"),
])
def test_ca_name_constraints(spec_dir: Path, constraints: x509.NameConstraints, reason: str) -> None:
    env, me = _envelope(spec_dir)
    constrained = _cert(CA_KEY.native.public_key(), CA_KEY.native, CA.subject, ca=True,  # type: ignore[attr-defined]
                        digital_signature=False, key_cert_sign=True, name="aitp-test-spiffe-ca", not_before=NOW - 3600,
                        extra=[(constraints, True)])
    leaf, priv = _leaf(spec_dir)
    _rejects(reason, _x509_identity(env, me, [leaf], priv), env, me, _bundles(_ca_jwk(constrained)))


def test_ca_uri_name_constraint_that_permits_the_trust_domain(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    nc = x509.NameConstraints(permitted_subtrees=[x509.UniformResourceIdentifier("prod.example.com")], excluded_subtrees=None)
    constrained = _cert(CA_KEY.native.public_key(), CA_KEY.native, CA.subject, ca=True,  # type: ignore[attr-defined]
                        digital_signature=False, key_cert_sign=True, name="aitp-test-spiffe-ca", not_before=NOW - 3600,
                        extra=[(nc, True)])
    leaf, priv = _leaf(spec_dir)
    _check(_x509_identity(env, me, [leaf], priv), env, me, _bundles(_ca_jwk(constrained)))


def test_x509_svid_proof_rules(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    leaf, priv = _leaf(spec_dir)
    good = _x509_identity(env, me, [leaf], priv)
    # Signed by the sender AID key, not the leaf key.
    sender_key = load_kat_keys(spec_dir)[env["sender"]["agent_id"]]
    _rejects("does not verify under the leaf key", _x509_identity(env, me, [leaf], sender_key), env, me, _bundles(_ca_jwk()))
    # A p256. tag under an Ed25519 leaf is an algorithm mismatch.
    _rejects("signature algorithm 'p256' != signer algorithm 'ed25519'", {**good, "proof": "p256." + good["proof"]},
             env, me, _bundles(_ca_jwk()))
    # The pinned-key input of the same tuple is a different domain.
    pinned = pinned_key_proof_input(env["sender"]["agent_id"], me, env["message_id"], int(env["timestamp"]),
                                    env["payload"]["pop_nonce"])
    _rejects("does not verify under the leaf key", {**good, "proof": b64url_encode(priv.sign_digest(sha256(pinned)))},
             env, me, _bundles(_ca_jwk()))


@pytest.mark.parametrize("bad", ["not base64!", "QUJD", "QUJD\n"])
def test_x5c_entries_are_strict_padded_base64_der(spec_dir: Path, bad: str) -> None:
    env, me = _envelope(spec_dir)
    leaf, priv = _leaf(spec_dir)
    ident = _x509_identity(env, me, [leaf], priv)
    _rejects("x5c[0] is not", {**ident, "x5c": [bad]}, env, me, _bundles(_ca_jwk()))
    url_safe = ident["x5c"][0].replace("+", "-").replace("/", "_")
    if url_safe != ident["x5c"][0]:
        _rejects("x5c[0] is not standard padded base64", {**ident, "x5c": [url_safe]}, env, me, _bundles(_ca_jwk()))


def test_bundle_ca_must_carry_exactly_one_certificate(spec_dir: Path) -> None:
    env, me = _envelope(spec_dir)
    leaf, priv = _leaf(spec_dir)
    two = {**_ca_jwk(), "x5c": [_der_b64(CA), _der_b64(CA)]}
    _rejects("exactly one x5c certificate", _x509_identity(env, me, [leaf], priv), env, me, _bundles(two))


# ── Manifest hint (§6.6) ────────────────────────────────────────────────────


def test_manifest_spiffe_hint(spec_dir: Path) -> None:
    man = _minted(spec_dir, "id-024")["envelope"]["payload"]["manifest"]
    assert man["identity_hint"] == {"type": "spiffe", "subject": SUBJECT}
    verify_manifest({"manifest": man}, NOW)
    for hint, reason in (
        ({"type": "spiffe", "subject": SUBJECT, "issuer": "https://x"}, "issuer is forbidden"),
        ({"type": "spiffe", "subject": SUBJECT, "public_key": "A" * 43}, "public_key is forbidden"),
        ({"type": "spiffe", "subject": "spiffe://Prod.example.com/a"}, "not a SPIFFE ID"),
        ({"type": "spiffe", "subject": SUBJECT + "\n"}, "not a SPIFFE ID"),
    ):
        bad = copy.deepcopy(man)
        bad["identity_hint"] = hint
        with pytest.raises(AitpError) as exc:
            verify_manifest({"manifest": bad}, NOW)
        assert exc.value.code == "MANIFEST_INVALID" and reason in exc.value.message
