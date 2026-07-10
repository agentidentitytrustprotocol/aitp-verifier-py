"""Mutual-handshake payload verification (RFC-AITP-0004).

``verify_handshake_payload`` dispatches on ``envelope.message_type``:

* **mutual_hello / mutual_hello_ack** (bootstrap) — Manifest PoP + signature run
  first (before identity, so a bad Manifest surfaces as ``MANIFEST_*`` not
  ``IDENTITY_FAILED``), then the identity-hint/identity type match, then the
  identity binding (RFC-AITP-0002), then the envelope signature, then the ACK
  nonce echo.
* **mutual_commit / mutual_commit_ack** (round 2) — envelope signature, the
  round-2 PoP signature over the peer's own nonce, then the embedded
  peer-issued TCT (``aud`` == self, ``grants`` ⊆ the issuer's offered
  capabilities).
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .b64 import b64url_decode
from .crypto import sha256
from .envelope import envelope_signing_input
from .errors import AitpError
from .identity import verify_identity
from .jwk import thumbprint
from .jws import parse_compact, verify_jws
from .manifest import verify_manifest
from .sigfield import decode_tagged_signature
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_handshake_payload"]

_BOOTSTRAP = {"mutual_hello", "mutual_hello_ack"}
_COMMIT = {"mutual_commit", "mutual_commit_ack"}


def verify_handshake_payload(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    if "peer_a" in inp and "peer_b" in inp:
        grants: list[str] = []
        for side in ("peer_a", "peer_b"):
            grants = _verify_commit(inp[side], inp[side].get("received_payload", {}), inp[side]["self_aid"], now)
        return {"grants": grants}

    env = inp["envelope"]
    mtype = env["message_type"]
    if mtype in _BOOTSTRAP:
        return _verify_bootstrap(inp, env, now)
    if mtype in _COMMIT:
        grants = _verify_commit(inp, env["payload"], inp.get("self_aid"), now)
        return {"grants": grants}
    raise AitpError("INVALID_ENVELOPE", f"unsupported handshake message_type {mtype!r}")


def _verify_bootstrap(inp: dict[str, Any], env: dict[str, Any], now: int) -> dict[str, Any]:
    payload = env["payload"]
    man = payload["manifest"]

    # Manifest first (mh-002/mh-003 must surface MANIFEST_* before identity).
    verify_manifest({"manifest": man, "now": now}, now)
    if man["aid"] != env["sender"]["agent_id"]:
        raise AitpError("INVALID_ENVELOPE", "manifest.aid != envelope sender")

    identity = payload["identity"]
    if man.get("identity_hint", {}).get("type") != identity.get("type"):
        raise AitpError("IDENTITY_FAILED", "identity_hint.type != identity.type")

    verify_identity(
        identity,
        env,
        inp.get("self_aid", ""),
        trust_anchors=inp.get("self_trust_anchors"),
        trust_store=inp.get("trust_store"),
        issuer_keys=inp.get("resolved_issuer_keys", {}),
        now=now,
    )

    # Envelope signature (RFC-AITP-0004 §5.1 step 7).
    aid = parse_aid(env["sender"]["agent_id"])
    raw = decode_tagged_signature(env["signature"], aid, sig_err="INVALID_SIGNATURE")
    if not aid.public_key.verify_digest(sha256(envelope_signing_input(env)), raw):
        raise AitpError("INVALID_SIGNATURE", "envelope signature invalid")

    # ACK nonce echo (§5.2 step 8).
    if env["message_type"] == "mutual_hello_ack" and "sent_pop_nonce" in inp:
        if payload.get("pop_nonce_echo") != inp["sent_pop_nonce"]:
            raise AitpError("NONCE_MISMATCH", "pop_nonce_echo != nonce sent")

    return {"ok": True}


def _verify_commit(
    inp: dict[str, Any], payload: dict[str, Any], self_aid: str | None, now: int
) -> list[str]:
    sender = inp.get("envelope", {}).get("sender", {}).get("agent_id")
    if sender is None:  # peer_a/peer_b shape carries no envelope; issuer is the TCT iss
        sender = parse_compact(payload["tct"], structural_code="TCT_SIGNATURE_INVALID").claims.get("iss")

    # Round-2 PoP over the verifier's own nonce (mh-008).
    self_nonce = (
        inp.get("self_pop_nonce_sent_in_hello_ack")
        or inp.get("self_pop_nonce_sent_in_hello")
        or inp.get("self_pop_nonce")
    )
    if isinstance(payload.get("pop_signature"), str) and self_nonce:
        key = parse_aid(str(sender)).public_key
        try:
            sig = b64url_decode(payload["pop_signature"].split(".")[-1])
        except ValueError as exc:
            raise AitpError("POP_VERIFICATION_FAILED", f"pop_signature not base64url: {exc}") from exc
        if not key.verify_digest(sha256(b64url_decode(self_nonce)), sig):
            raise AitpError("POP_VERIFICATION_FAILED", "round-2 PoP signature invalid")

    # Embedded peer-issued TCT.
    tct = payload["tct"]
    iss = parse_compact(tct, structural_code="TCT_SIGNATURE_INVALID").claims.get("iss")
    claims = verify_jws(
        tct, iss_aid=str(iss), expected_typ="aitp-tct+jwt",
        typ_err="TOKEN_TYP_MISMATCH", alg_err="TOKEN_ALG_MISMATCH", sig_err="TCT_SIGNATURE_INVALID",
    )
    if claims.get("ver") != "aitp/0.2":
        raise AitpError("UNKNOWN_VERSION", f"unknown ver {claims.get('ver')!r}")
    if self_aid is not None and claims.get("aud") != self_aid:
        raise AitpError("AUDIENCE_MISMATCH", "TCT aud != self AID")
    if now >= int(claims["exp"]):
        raise AitpError("TCT_EXPIRED", "TCT expired")
    if claims.get("cnf", {}).get("jkt") != thumbprint(parse_aid(str(claims["sub"]))):
        raise AitpError("TCT_CNF_MISMATCH", "cnf.jkt does not bind the subject key")
    offered = inp.get("issuer_offered_capabilities")
    if offered is not None and not set(claims["grants"]).issubset(set(offered)):
        raise AitpError("GRANT_OVERFLOW", "TCT grants exceed the issuer's offered capabilities")
    return list(claims["grants"])
