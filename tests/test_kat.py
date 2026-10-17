"""Re-derive the spec's byte-pinned known-answer vectors.

These are the interop contract: every value here must match the AITP spec
byte-for-byte, independently of the Rust reference implementation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typing import Any, cast

from aitp_verifier import jcs, jwk
from aitp_verifier.aid import parse_aid
from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.crypto import PrivateKey, sha256


def _ka(spec_dir: Path, name: str) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads((spec_dir / "schemas/conformance/known-answer" / name).read_text(encoding="utf-8")))


def test_keypairs_derive_aids(spec_dir: Path) -> None:
    for v in _ka(spec_dir, "keypairs.json")["vectors"]:
        if v.get("algorithm") == "p256":
            sk = PrivateKey.p256_from_scalar(int(v["private_scalar_hex"], 16))
            assert sk.raw_public().hex() == v["pubkey_compressed_hex"]
        else:
            sk = PrivateKey.ed25519_from_seed(bytes.fromhex(v["seed_hex"]))
        assert b64url_encode(sk.raw_public()) == v["pubkey_b64url"]
        assert b64url_encode(parse_aid(v["aid"]).raw_key) == v["pubkey_b64url"]


def test_jwk_thumbprints(spec_dir: Path) -> None:
    kp = {k["id"]: k["aid"] for k in _ka(spec_dir, "keypairs.json")["vectors"]}
    for v in _ka(spec_dir, "jwk-thumbprints.json")["vectors"]:
        aid = parse_aid(kp[v["keypair_ref"]])
        assert jwk.thumbprint(aid) == v["jkt"]


# The JCS-profile artifact vectors, and the transport wrapper key each one
# must NOT be canonicalized inside of.
#
# Hard-coded deliberately. Reading the vector's own `signing_input` and
# echoing it back would let a future vector re-declare the convention and
# still pass -- a vector may not self-certify a non-conformant signing
# input. RFC-AITP-0001 §5.4.1: the artifact-naming key is transport routing
# metadata and is never part of the signing bytes.
JCS_ARTIFACT_VECTORS = {
    "kat-manifest-001": "manifest",
    "kat-revocation-001": "revocation_list",
    "kat-session-bundle-001": "session_bundle",
}

# Vectors that legitimately pin no canonical bytes (PoP input, chain
# hashes). An allowlist rather than skip-on-absence: a vector that lost its
# `object` must fail, not silently drop out of coverage.
NON_CANONICAL_VECTORS = {
    "kat-manifest-pop-001",
    "kat-multihop-chain-001",
    "kat-multihop-truncation-001",
    # Pins a concatenated §3.1 proof input, not the JCS form of an object.
    # Machine-checked by test_pinned_key_proof_kat below -- allowlisting it
    # here drops it from THIS test's coverage, not from the suite's.
    "kat-pinned-key-proof-001",
    "kat-pinned-key-proof-002-p256",
    "kat-pinned-key-proof-003-tagged-ed25519",
    # Pin a JCS preimage plus a signature, a raw PoP challenge, and a derived
    # UUID respectively; each machine-checked by its own test below.
    "kat-p256-jcs-sign-001",
    "kat-manifest-pop-002-p256",
    "kat-derived-uuid-001",
}


def test_jcs_canonical_and_sha256(spec_dir: Path) -> None:
    vectors = _ka(spec_dir, "jcs-sha256.json")["vectors"]
    seen = set()

    for v in vectors:
        vid = v["id"]
        seen.add(vid)
        if vid in NON_CANONICAL_VECTORS:
            continue
        for member in ("object", "jcs_canonical_hex", "jcs_canonical_len_bytes", "sha256_hex"):
            assert member in v, f"{vid}: canonical-form vector is missing `{member}`"

        # A vector pinning canonical bytes must say what they are the
        # canonicalization OF. Absent is a failure, never a default --
        # defaulting is how a harness becomes adaptive and stops being able
        # to fail.
        declared = v.get("signing_input")
        assert declared is not None, f"{vid}: pins canonical bytes but declares no `signing_input`"
        assert declared == "body", (
            f"{vid}: JCS-profile vectors sign the inner artifact body "
            f"(RFC-AITP-0001 §5.4.1); `{declared}` is not conformant"
        )

        canon = jcs.canonicalize(v["object"])
        assert len(canon) == v["jcs_canonical_len_bytes"], f"{vid}: canonical length"
        assert canon.hex() == v["jcs_canonical_hex"], f"{vid}: canonical bytes"
        assert sha256(canon).hex() == v["sha256_hex"], f"{vid}: sha256"
        assert b64url_encode(sha256(canon)) == v["sha256_b64url"], f"{vid}: sha256_b64url"

        # The wrapper must not be present, and the pinned bytes must not be
        # the canonicalization of the wrapped form. Two independent checks:
        # the first catches a wholesale re-wrap, the second catches pinned
        # bytes swapped to the wrapped form with `object` left inner.
        wrapper = JCS_ARTIFACT_VECTORS.get(vid)
        if wrapper is not None:
            assert wrapper not in v["object"], (
                f"{vid}: `object` still carries the `{wrapper}` transport wrapper"
            )
            wrapped_hex = jcs.canonicalize({wrapper: v["object"]}).hex()
            assert wrapped_hex != v["jcs_canonical_hex"], (
                f"{vid}: pinned bytes equal JCS of the wrapped form -- the "
                f"transport wrapper is being signed"
            )

    # Every expected vector must be PRESENT. Without this, deleting a vector
    # from the file just makes this test assert less, silently.
    missing = set(JCS_ARTIFACT_VECTORS) - seen
    assert not missing, f"JCS-profile vectors missing from jcs-sha256.json: {sorted(missing)}"


def test_session_bundle_pinned_signature(spec_dir: Path) -> None:
    """`kat-session-bundle-001` pins a real coordinator signature that no
    test in EITHER implementation verified before.

    Asserts both directions: valid over the inner body, invalid over the
    wrapper. A signature valid under both pins no convention.
    """
    v = next(
        x for x in _ka(spec_dir, "jcs-sha256.json")["vectors"]
        if x["id"] == "kat-session-bundle-001"
    )
    body = v["object"]
    coordinator = parse_aid(body["coordinator"])
    sig = b64url_decode(v["coordinator_signature_b64url"])

    assert coordinator.public_key.verify_digest(sha256(jcs.canonicalize(body)), sig), (
        "pinned coordinator signature must verify over the inner bundle body"
    )
    assert not coordinator.public_key.verify_digest(
        sha256(jcs.canonicalize({"session_bundle": body})), sig
    ), "coordinator signature verified over the WRAPPED form (RFC-AITP-0010 §3)"


def test_pinned_key_proof_input_matches_golden(spec_dir: Path) -> None:
    """The id-007 fixture carries a real five-field pinned-key proof — verify it."""
    fixtures = list((spec_dir / "schemas/conformance").glob("id-007*.json"))
    if not fixtures:
        return
    inp = json.loads(fixtures[0].read_text(encoding="utf-8"))["input"]
    identity = inp["envelope"]["payload"]["identity"]
    from aitp_verifier.crypto import PublicKey
    from aitp_verifier.identity import pinned_key_proof_input

    data = pinned_key_proof_input(
        inp["envelope"]["sender"]["agent_id"],
        inp["self_aid"],
        inp["envelope"]["message_id"],
        inp["envelope"]["timestamp"],
        inp["envelope"]["payload"]["pop_nonce"],
    )
    key = PublicKey.from_raw("ed25519", b64url_decode(identity["public_key"]))
    assert key.verify_digest(sha256(data), b64url_decode(identity["proof"]))


def _vector(spec_dir: Path, vid: str) -> dict[str, Any]:
    v = {v["id"]: v for v in _ka(spec_dir, "jcs-sha256.json")["vectors"]}.get(vid)
    if v is None:
        pytest.skip(f"{vid} not in this spec revision")
    return cast("dict[str, Any]", v)


def test_pop_signature_vector(spec_dir: Path) -> None:
    kp = {k["id"]: k for k in _ka(spec_dir, "keypairs.json")["vectors"]}
    v = _vector(spec_dir, "kat-manifest-pop-001")
    seed = bytes.fromhex(kp[v["signing_keypair_id"]]["seed_hex"])
    sk = PrivateKey.ed25519_from_seed(seed)
    digest = sha256(b64url_decode(v["challenge"]))
    assert digest.hex() == v["sha256_hex"]
    assert b64url_encode(sk.sign_digest(digest)) == v["signature_b64url"]
    assert sk.public_key().verify_digest(digest, sk.sign_digest(digest))


def _check_p256_single_hash(v: dict[str, Any], digest: bytes) -> None:
    """The shared P-256 obligations (RFC-AITP-0001 §5.4.3, §5.4.6, §5.4.7):
    the untagged and tagged signatures agree and verify over ``digest``; the
    double-hashed (and, when present, high-S) siblings do not."""
    from aitp_verifier.sigfield import decode_tagged_signature

    signer = parse_aid(v["signer_aid"])
    key = signer.public_key
    sig = b64url_decode(v["signature_b64url"])
    assert decode_tagged_signature(v["signature"], signer, sig_err="X") == sig
    assert key.verify_digest(digest, sig)
    dh = decode_tagged_signature(v["double_hash_signature_MUST_NOT_verify"], signer, sig_err="X")
    assert not key.verify_digest(digest, dh), "double-hashed P-256 signature must NOT verify"
    if "high_s_sibling_MUST_NOT_verify" in v:
        hs = decode_tagged_signature(v["high_s_sibling_MUST_NOT_verify"], signer, sig_err="X")
        assert not key.verify_digest(digest, hs), "high-S P-256 sibling must NOT verify (sig-003)"


def test_manifest_pop_p256_vector(spec_dir: Path) -> None:
    v = _vector(spec_dir, "kat-manifest-pop-002-p256")
    decoded = b64url_decode(v["challenge"])
    assert decoded.hex() == v["decoded_hex"]
    digest = sha256(decoded)
    assert digest.hex() == v["sha256_hex"]
    assert b64url_encode(digest) == v["sha256_b64url"]
    _check_p256_single_hash(v, digest)


def test_p256_jcs_sign_vector(spec_dir: Path) -> None:
    v = _vector(spec_dir, "kat-p256-jcs-sign-001")
    preimage = jcs.canonicalize(v["preimage_json"])
    assert preimage == bytes.fromhex(v["preimage_hex"])
    assert len(preimage) == v["preimage_len_bytes"]
    digest = sha256(preimage)
    assert digest.hex() == v["sha256_hex"]
    assert b64url_encode(digest) == v["sha256_b64url"]
    _check_p256_single_hash(v, digest)


def test_derived_uuid_vector(spec_dir: Path) -> None:
    """RFC-AITP-0005 §2.2 derived ``jti``: sha256(tag || 0x00 || input), the
    first 16 bytes with the v4 version and RFC 9562 variant bits set. The
    result must pass the verifier's own jti v4 layout check."""
    import uuid

    from aitp_verifier.tct import _JTI_V4

    v = _vector(spec_dir, "kat-derived-uuid-001")
    preimage = v["domain_tag"].encode("ascii") + b"\x00" + bytes.fromhex(v["input_hex"])
    assert preimage.hex() == v["preimage_hex"]
    h = sha256(preimage)
    assert h.hex() == v["sha256_hex"]
    b = bytearray(h[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    derived = str(uuid.UUID(bytes=bytes(b)))
    assert derived == v["uuid"]
    assert _JTI_V4.fullmatch(derived)


@pytest.mark.parametrize(
    "vid",
    ["kat-pinned-key-proof-001", "kat-pinned-key-proof-002-p256", "kat-pinned-key-proof-003-tagged-ed25519"],
)
def test_pinned_key_proof_kat(spec_dir: Path, vid: str) -> None:
    """`kat-pinned-key-proof-001` pins issue #17 erratum 1: the §3.1 timestamp
    is its base-10 ASCII decimal string, NOT the 8-byte big-endian integer the
    prose once described. The vector states both obligations, so both are
    checked -- the negative especially: an implementation that packed the
    timestamp as 8-byte BE would still satisfy every positive assertion here
    if all we did was rebuild our own input and compare it to itself.

    `-002-p256` is the P-256 sibling (proposal #72 Item 2): its wire
    `signature` is `p256.`-tagged and its `double_hash_signature_MUST_NOT_verify`
    (ECDSA over SHA-256 of the digest) must not verify. `-003` is the tagged
    `aid:pubkey:ed25519:` spelling: the AID string bytes enter the proof input.
    """
    from aitp_verifier.identity import pinned_key_proof_input
    from aitp_verifier.sigfield import decode_tagged_signature

    vectors = {v["id"]: v for v in _ka(spec_dir, "jcs-sha256.json")["vectors"]}
    v = vectors.get(vid)
    if v is None:  # vector predates this spec revision
        pytest.skip(f"{vid} not in this spec revision")

    data = pinned_key_proof_input(
        v["sender_aid"], v["receiver_aid"], v["message_id"], v["timestamp"], v["pop_nonce"]
    )
    assert data == bytes.fromhex(v["proof_input_hex"])
    assert len(data) == v["proof_input_len_bytes"]

    digest = sha256(data)
    assert digest.hex() == v["sha256_hex"]
    assert b64url_encode(digest) == v["sha256_b64url"]

    signer = parse_aid(v["signer_aid"])
    key = signer.public_key
    sig = b64url_decode(v["signature_b64url"])
    assert key.verify_digest(digest, sig), "pinned signature must verify over the ASCII-decimal proof input"

    if "signature" in v:  # the wire form, algorithm-tagged (§5.4.3)
        assert decode_tagged_signature(v["signature"], signer, sig_err="POP_VERIFICATION_FAILED") == sig
    if "double_hash_signature_MUST_NOT_verify" in v:
        dh = decode_tagged_signature(v["double_hash_signature_MUST_NOT_verify"], signer, sig_err="POP_VERIFICATION_FAILED")
        assert not key.verify_digest(digest, dh), "double-hashed P-256 signature must NOT verify"

    # The negative MUST. Same five fields, timestamp packed the way the
    # erratum'd prose said, which must NOT verify under the pinned signature.
    be8 = data.replace(
        str(int(v["timestamp"])).encode("ascii"),
        int(v["timestamp"]).to_bytes(8, "big", signed=True),
        1,
    )
    assert be8 != data
    assert not key.verify_digest(sha256(be8), sig), "8-byte big-endian timestamp must NOT verify"
