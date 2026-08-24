"""Re-derive the spec's byte-pinned known-answer vectors.

These are the interop contract: every value here must match the AITP spec
byte-for-byte, independently of the Rust reference implementation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from aitp_verifier import jcs, jwk
from aitp_verifier.aid import parse_aid
from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.crypto import PrivateKey, sha256


def _ka(spec_dir: Path, name: str) -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads((spec_dir / "schemas/conformance/known-answer" / name).read_text()))


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
    inp = json.loads(fixtures[0].read_text())["input"]
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


def test_pop_signature_vector(spec_dir: Path) -> None:
    kp = {k["id"]: k for k in _ka(spec_dir, "keypairs.json")["vectors"]}
    for v in _ka(spec_dir, "jcs-sha256.json")["vectors"]:
        if v["id"] != "kat-manifest-pop-001":
            continue
        seed = bytes.fromhex(kp[v["signing_keypair_id"]]["seed_hex"])
        sk = PrivateKey.ed25519_from_seed(seed)
        digest = sha256(b64url_decode(v["challenge"]))
        assert digest.hex() == v["sha256_hex"]
        assert b64url_encode(sk.sign_digest(digest)) == v["signature_b64url"]
        assert sk.public_key().verify_digest(digest, sk.sign_digest(digest))
