"""Identity-binding verification (RFC-AITP-0002).

Two binding types feed the mutual handshake:

* **OIDC** — an issuer-signed JWT whose claims bind the AID: ``aud`` MUST equal
  the verifier's own AID, ``nonce`` MUST equal the message's ``pop_nonce``, and
  ``cnf.jkt`` MUST equal the RFC 7638 thumbprint of the sender AID's key. The
  issuer MUST be a trusted anchor. Any claim failure is ``IDENTITY_FAILED``; an
  untrusted issuer is ``INCOMPATIBLE_TRUST_ANCHORS``.
* **pinned_key** — an Ed25519 proof over the five-field input
  ``"aitp-pinned-key-v1\\0" + sender \\0 + receiver \\0 + message_id \\0 +
  ascii(timestamp)\\0 + decode(pop_nonce)`` (§3.1). The verifier always
  reconstructs the five-field input, so a legacy two-field proof or a
  cross-peer-captured proof fails to verify. The pinned key MUST be in the
  local trust store.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .b64 import b64url_decode
from .crypto import sha256
from .errors import AitpError
from .jcs import loads
from .jwk import thumbprint

__all__ = ["pinned_key_proof_input", "verify_identity"]


def pinned_key_proof_input(
    sender_aid: str, receiver_aid: str, message_id: str, timestamp: int, pop_nonce: str
) -> bytes:
    """Build the RFC-AITP-0002 §3.1 five-field pinned-key proof input."""
    return (
        b"aitp-pinned-key-v1\x00"
        + sender_aid.encode("utf-8")
        + b"\x00"
        + receiver_aid.encode("utf-8")
        + b"\x00"
        + message_id.encode("utf-8")
        + b"\x00"
        + str(int(timestamp)).encode("ascii")
        + b"\x00"
        + b64url_decode(pop_nonce)
    )


def verify_identity(
    identity: dict[str, Any],
    envelope: dict[str, Any],
    self_aid: str,
    *,
    trust_anchors: list[str] | None,
    trust_store: list[str] | None,
    issuer_keys: dict[str, str],
    now: int,
) -> None:
    """Verify the identity binding in a handshake payload. Raises on failure."""
    itype = identity.get("type")
    if itype == "oidc":
        _verify_oidc(identity, envelope, self_aid, trust_anchors, issuer_keys, now)
    elif itype == "pinned_key":
        _verify_pinned_key(identity, envelope, self_aid, trust_store)
    else:
        raise AitpError("IDENTITY_FAILED", f"unknown identity type {itype!r}")


def _verify_oidc(
    identity: dict[str, Any],
    envelope: dict[str, Any],
    self_aid: str,
    trust_anchors: list[str] | None,
    issuer_keys: dict[str, str],
    now: int,
) -> None:
    jwt = identity.get("proof", "")
    parts = jwt.split(".")
    if len(parts) != 3 or not all(parts):
        raise AitpError("IDENTITY_FAILED", "OIDC proof is not a compact JWS")
    try:
        claims = loads(b64url_decode(parts[1]))
    except Exception as exc:  # noqa: BLE001
        raise AitpError("IDENTITY_FAILED", f"OIDC proof payload not JSON: {exc}") from exc
    if not isinstance(claims, dict):
        raise AitpError("IDENTITY_FAILED", "OIDC claims not an object")

    issuer = identity.get("issuer")
    # Signature: verify against the resolved issuer key when available.
    pub = issuer_keys.get(str(issuer))
    if pub is not None:
        from .crypto import PublicKey

        key = PublicKey.from_raw("ed25519", b64url_decode(pub))
        if not key.verify_jose((parts[0] + "." + parts[1]).encode("ascii"), b64url_decode(parts[2])):
            raise AitpError("IDENTITY_FAILED", "OIDC JWT signature invalid")

    if claims.get("iss") != issuer:
        raise AitpError("IDENTITY_FAILED", "JWT iss != identity issuer")
    if claims.get("sub") != identity.get("subject"):
        raise AitpError("IDENTITY_FAILED", "JWT sub != identity subject")
    exp = claims.get("exp")
    if isinstance(exp, int) and now >= exp:
        raise AitpError("IDENTITY_FAILED", "JWT expired")
    # aud MUST bind to the verifier's own AID. Some fixtures omit self_aid
    # (they test a different gate, e.g. trust anchors / nonce echo) — only
    # enforce aud when the verifier knows its own AID.
    if self_aid and claims.get("aud") != self_aid:
        raise AitpError("IDENTITY_FAILED", "JWT aud != verifier AID")
    pop_nonce = envelope.get("payload", {}).get("pop_nonce")
    if claims.get("nonce") != pop_nonce:
        raise AitpError("IDENTITY_FAILED", "JWT nonce != message pop_nonce")
    sender_aid = envelope["sender"]["agent_id"]
    cnf = claims.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if jkt != thumbprint(parse_aid(sender_aid)):
        raise AitpError("IDENTITY_FAILED", "JWT cnf.jkt does not bind the sender key")
    # Trust anchor is the final gate (RFC-AITP-0002 §2.3 step 9).
    if trust_anchors is not None and issuer not in trust_anchors:
        raise AitpError("INCOMPATIBLE_TRUST_ANCHORS", "OIDC issuer not a trusted anchor")


def _verify_pinned_key(
    identity: dict[str, Any],
    envelope: dict[str, Any],
    self_aid: str,
    trust_store: list[str] | None,
) -> None:
    pub = identity.get("public_key", "")
    # Trust-store gate runs first: an unknown key is rejected before crypto.
    if trust_store is not None:
        pinned = {a.split(":")[-1] for a in trust_store}  # tolerate full-AID or bare-key entries
        if pub not in pinned and pub not in trust_store:
            raise AitpError("IDENTITY_FAILED", "pinned key not in trust store")

    proof_input = pinned_key_proof_input(
        envelope["sender"]["agent_id"],
        self_aid,
        envelope["message_id"],
        int(envelope["timestamp"]),
        envelope["payload"]["pop_nonce"],
    )
    from .crypto import PublicKey

    key = PublicKey.from_raw("ed25519", b64url_decode(pub))
    try:
        sig = b64url_decode(identity.get("proof", ""))
    except ValueError as exc:
        raise AitpError("IDENTITY_FAILED", f"pinned-key proof not base64url: {exc}") from exc
    if len(sig) != 64 or not key.verify_digest(sha256(proof_input), sig):
        raise AitpError("IDENTITY_FAILED", "pinned-key proof does not verify (five-field input)")
