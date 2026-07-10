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


def test_jcs_canonical_and_sha256(spec_dir: Path) -> None:
    for v in _ka(spec_dir, "jcs-sha256.json")["vectors"]:
        if "object" not in v:
            continue
        canon = jcs.canonicalize(v["object"])
        assert canon.hex() == v["jcs_canonical_hex"]
        assert sha256(canon).hex() == v["sha256_hex"]


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
