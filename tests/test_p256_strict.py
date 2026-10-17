"""P-256 strictness and the algorithm-agile pinned-key profile (proposal
agentidentitytrustprotocol#72 Items 2 and 4).

* RFC-AITP-0001 §5.4.7: P-256 verifiers reject high-S, and ``R``/``S`` that
  are 0 or ``>= n``, in both the JCS and the JWS profile.
* RFC-AITP-0001 §5.4.3 rule 3: an untagged signature is Ed25519, so under a
  ``p256`` AID it is an algorithm mismatch.
* RFC-AITP-0002 §3.2 (amended): ``public_key`` is the sender AID's own key,
  trust-store entries are ``(algorithm, key)`` pairs, and a P-256 proof is a
  tagged JCS-profile signature.
"""

from __future__ import annotations

from typing import Any

import pytest

from aitp_verifier.aid import parse_aid
from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.crypto import P256_N, PrivateKey, sha256
from aitp_verifier.errors import AitpError
from aitp_verifier.identity import pinned_key_proof_input, verify_identity
from aitp_verifier.sigfield import decode_tagged_signature

# kat-keypair-005-p256 (scalar 0x05 x 32) and kat-keypair-001 (zero seed).
P256 = PrivateKey.p256_from_scalar(int.from_bytes(bytes([5]) * 32, "big"))
ED = PrivateKey.ed25519_from_seed(bytes(32))
P256_AID = "aid:pubkey:p256:" + b64url_encode(P256.raw_public())
ED_AID = "aid:pubkey:" + b64url_encode(ED.raw_public())
RECEIVER = "aid:pubkey:" + b64url_encode(PrivateKey.ed25519_from_seed(bytes([0x77]) * 32).raw_public())
NONCE = "AAECAwQFBgcICQoLDA0ODw"
MESSAGE_ID = "2a9f4e1b-8c7d-4a6e-b5f4-e3d2c1b0a998"
NOW = 1_711_900_000


def _high_s(raw: bytes) -> bytes:
    s = int.from_bytes(raw[32:], "big")
    assert s <= P256_N // 2, "signer must emit low-S"
    return raw[:32] + (P256_N - s).to_bytes(32, "big")


def test_signer_emits_low_s_and_verifier_rejects_the_high_s_twin() -> None:
    key = parse_aid(P256_AID).public_key
    for i in range(32):
        digest = sha256(bytes([i]))
        raw = P256.sign_digest(digest)
        assert int.from_bytes(raw[32:], "big") <= P256_N // 2
        assert key.verify_digest(digest, raw)
        assert not key.verify_digest(digest, _high_s(raw))


def test_jws_profile_rejects_high_s() -> None:
    key = parse_aid(P256_AID).public_key
    signing_input = b"eyJhbGciOiJFUzI1NiJ9.e30"
    raw = P256.sign_jose(signing_input)
    assert key.verify_jose(signing_input, raw)
    assert not key.verify_jose(signing_input, _high_s(raw))


@pytest.mark.parametrize(
    "r, s",
    [(0, 1), (1, 0), (P256_N, 1), (1, P256_N)],
    ids=["r=0", "s=0", "r=n", "s=n"],
)
def test_out_of_range_scalars_are_rejected(r: int, s: int) -> None:
    key = parse_aid(P256_AID).public_key
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert not key.verify_digest(sha256(b"x"), raw)


def test_untagged_signature_under_a_p256_aid_is_an_algorithm_mismatch() -> None:
    raw = P256.sign_digest(sha256(b"x"))
    aid = parse_aid(P256_AID)
    assert decode_tagged_signature("p256." + b64url_encode(raw), aid, sig_err="E") == raw
    with pytest.raises(AitpError) as exc:
        decode_tagged_signature(b64url_encode(raw), aid, sig_err="E")
    assert exc.value.code == "E"
    # The legacy untagged form stays valid for Ed25519.
    ed_raw = ED.sign_digest(sha256(b"x"))
    assert decode_tagged_signature(b64url_encode(ed_raw), parse_aid(ED_AID), sig_err="E") == ed_raw


def _pinned(signer: PrivateKey, sender: str, *, tag: str | None) -> tuple[dict[str, Any], dict[str, Any]]:
    proof_input = pinned_key_proof_input(sender, RECEIVER, MESSAGE_ID, NOW, NONCE)
    raw = signer.sign_digest(sha256(proof_input))
    proof = b64url_encode(raw) if tag is None else f"{tag}.{b64url_encode(raw)}"
    identity = {
        "type": "pinned_key",
        "subject": "agent",
        "public_key": sender.rsplit(":", 1)[-1],
        "proof": proof,
    }
    envelope = {
        "sender": {"agent_id": sender},
        "message_id": MESSAGE_ID,
        "timestamp": NOW,
        "payload": {"pop_nonce": NONCE},
    }
    return identity, envelope


def _verify(identity: dict[str, Any], envelope: dict[str, Any], trust_store: list[str] | None) -> None:
    verify_identity(
        identity,
        envelope,
        RECEIVER,
        trust_anchors=[],
        trust_store=trust_store,
        issuer_keys={},
        now=NOW,
    )


def test_p256_pinned_key_verifies_with_a_tagged_proof() -> None:
    identity, envelope = _pinned(P256, P256_AID, tag="p256")
    _verify(identity, envelope, [P256_AID])
    # A bare 44-char identifier is read as p256, per the AID grammar.
    _verify(identity, envelope, [identity["public_key"]])


def test_p256_pinned_key_rejects_an_untagged_proof() -> None:
    identity, envelope = _pinned(P256, P256_AID, tag=None)
    with pytest.raises(AitpError) as exc:
        _verify(identity, envelope, [P256_AID])
    assert exc.value.code == "IDENTITY_FAILED"


def test_p256_pinned_key_rejects_a_high_s_proof() -> None:
    identity, envelope = _pinned(P256, P256_AID, tag="p256")
    raw = b64url_decode(identity["proof"].split(".", 1)[1])
    identity["proof"] = "p256." + b64url_encode(_high_s(raw))
    with pytest.raises(AitpError) as exc:
        _verify(identity, envelope, [P256_AID])
    assert exc.value.code == "IDENTITY_FAILED"


def test_public_key_must_be_the_sender_aid_key() -> None:
    # A valid P-256 descriptor presented under an Ed25519 sender.
    identity, _ = _pinned(P256, P256_AID, tag="p256")
    _, envelope = _pinned(ED, ED_AID, tag=None)
    with pytest.raises(AitpError) as exc:
        _verify(identity, envelope, [P256_AID, ED_AID])
    assert exc.value.code == "IDENTITY_FAILED"
    assert "sender AID" in str(exc.value)


def test_trust_store_is_keyed_by_algorithm_and_key() -> None:
    identity, envelope = _pinned(P256, P256_AID, tag="p256")
    with pytest.raises(AitpError, match="not in trust store"):
        _verify(identity, envelope, [ED_AID])
    with pytest.raises(AitpError, match="not in trust store"):
        _verify(identity, envelope, ["not-an-aid", 7])  # type: ignore[list-item]


def test_ed25519_pinned_key_still_accepts_both_wire_forms() -> None:
    for tag in (None, "ed25519"):
        identity, envelope = _pinned(ED, ED_AID, tag=tag)
        _verify(identity, envelope, [ED_AID])


def test_issuer_member_is_rejected() -> None:
    # RFC-AITP-0002 §1: `issuer` MUST be absent for pinned_key (id-018).
    identity, envelope = _pinned(ED, ED_AID, tag=None)
    identity["issuer"] = "https://auth.example.test"
    with pytest.raises(AitpError, match="issuer") as exc:
        _verify(identity, envelope, [ED_AID])
    assert exc.value.code == "IDENTITY_FAILED"
