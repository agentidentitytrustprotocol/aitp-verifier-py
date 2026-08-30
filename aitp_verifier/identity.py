"""Identity-binding verification (RFC-AITP-0002).

Two binding types feed the mutual handshake:

* **OIDC** — an issuer-signed JWT. Verification runs a strict, ordered gate
  (see ``_verify_oidc``'s docstring) built around one invariant, stated in
  RFC-AITP-0007 §3.2: "An unverified identity proof MUST NOT be accepted
  under any fail mode." Concretely: the JWT signature is verified against a
  resolved issuer key on *every* code path — there is no branch where claim
  checks (``iss``/``sub``/``exp``/``iat``/``aud``/``nonce``/``cnf.jkt``) run
  without a successful signature verification directly ahead of them. The
  issuer MUST be a trusted anchor. Supported algorithms are ``EdDSA``
  (Ed25519), ``ES256`` (P-256) and ``RS256`` (RSA, 2048+ bit modulus); the
  issuer key may be supplied as a legacy 43/44-char raw base64url string, a
  single JWK, or a JWKS (``{"keys": [...]}"``) — see ``jwk.py``. The header's
  ``alg`` is pinned to the *resolved key's own structural algorithm* and
  compared, never trusted on its own (alg-confusion defense); ``none`` in any
  spelling is never in the allowed set. Any claim/structural failure is
  ``IDENTITY_FAILED``; zero resolvable issuer-key candidates is
  ``KEY_RESOLUTION_FAILED``; an untrusted issuer is
  ``INCOMPATIBLE_TRUST_ANCHORS``.
* **pinned_key** — an Ed25519 proof over the five-field input
  ``"aitp-pinned-key-v1\\0" + sender \\0 + receiver \\0 + message_id \\0 +
  ascii(timestamp)\\0 + decode(pop_nonce)`` (§3.1). The verifier always
  reconstructs the five-field input, so a legacy two-field proof or a
  cross-peer-captured proof fails to verify. The pinned key MUST be in the
  local trust store.
"""

from __future__ import annotations

from typing import Any, Mapping

from .aid import parse_aid
from .b64 import b64url_decode
from .crypto import sha256
from .errors import AitpError
from .jwk import IssuerKey, issuer_keys_from, thumbprint
from .jws import parse_compact

__all__ = ["pinned_key_proof_input", "verify_identity"]

_ALLOWED_OIDC_ALGS = {"EdDSA", "ES256", "RS256"}
_FORBIDDEN_HEADER_PARAMS = {"jwk", "jku", "x5u", "x5c", "crit"}
_IAT_TOLERANCE_SECS = 300


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
    issuer_keys: Mapping[str, Any],
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
    issuer_keys: Mapping[str, Any],
    now: int,
) -> None:
    """Verify an OIDC identity binding (RFC-AITP-0002 §2, RFC-AITP-0007).

    Fixed gate order, every step fail-closed (RFC-AITP-0007 §3.2: "An
    unverified identity proof MUST NOT be accepted under any fail mode" — no
    claim below is ever evaluated without a signature verification having
    already succeeded on the same call):

    0. ``identity.public_key`` MUST be absent (RFC-AITP-0002 §1: forbidden
       for the ``oidc`` branch — the AID's own key is the only key).
    1. ``identity.issuer`` MUST be present and a string.
    2. ``issuer`` MUST be in ``trust_anchors`` when a trust-anchor list is
       configured (``None`` means "not modelled here", not "trust nothing").
       This gate is deliberately checked before any crypto so an untrusted
       issuer is rejected as untrusted, never masked by an unrelated
       resolution or signature failure.
    3. ``proof`` MUST be a strict 3-segment compact JWS (``jws.parse_compact``).
    4. The header MUST decode to an object, MUST NOT carry ``jwk``/``jku``/
       ``x5u``/``x5c``/``crit``, and MUST carry a string ``alg`` in
       ``{EdDSA, ES256, RS256}`` (``none`` in any spelling is not in this set).
    5. Resolve issuer-key candidates (``jwk.issuer_keys_from``). Zero
       candidates -> ``KEY_RESOLUTION_FAILED`` (retryable — a key might show
       up on a later resolution attempt). A header ``kid`` with no matching
       candidate, or no ``kid`` with 2+ candidates (ambiguous), -> a
       resolution *target* did exist but couldn't be pinned, which is a
       proof-shape problem, not a resolution problem: ``IDENTITY_FAILED``.
    6. The header ``alg`` MUST equal the resolved key's own structural
       algorithm (derived from key type in ``jwk.py``, never from a token's
       or JWK's self-declared ``alg``) — the alg-confusion defense.
    7. Verify the signature over the transmitted ``header_b64.payload_b64``
       ASCII bytes. Nothing past this point runs on a failed signature.
    8. ``claims.iss == issuer``.
    9. ``claims.sub == identity.subject``.
    10. ``claims.exp`` present, a non-bool int, and strictly greater than
        ``now`` (``now == exp`` is expired, not "expiring now").
    11. ``claims.iat`` present, a non-bool int, within ±300s of ``now``.
    12. ``claims.aud`` MUST be present (independent of the equality check
        below — an absent ``aud`` can never bind the JWT to a peer). When
        ``self_aid`` is known, ``aud`` MUST additionally equal it.
    13. ``claims.nonce`` MUST be present, non-``None``, and equal to the
        envelope's ``payload.pop_nonce`` (also required present/non-``None``)
        — both sides absent is a replay hole, not a pass.
    14. ``cnf.jkt`` MUST equal the RFC 7638 thumbprint of the envelope
        sender's AID key.
    """
    if identity.get("public_key") is not None:
        raise AitpError("IDENTITY_FAILED", "OIDC identity descriptor MUST NOT carry public_key")

    issuer = identity.get("issuer")
    if not isinstance(issuer, str):
        raise AitpError("IDENTITY_FAILED", "OIDC identity missing string issuer")

    # Trust-anchor gate runs before any crypto (see docstring step 2). `None`
    # means the caller has not modelled trust anchors for this check at all.
    if trust_anchors is not None and issuer not in trust_anchors:
        raise AitpError("INCOMPATIBLE_TRUST_ANCHORS", "OIDC issuer not a trusted anchor")

    parsed = parse_compact(identity.get("proof", ""), structural_code="IDENTITY_FAILED")
    header = parsed.header
    if _FORBIDDEN_HEADER_PARAMS & header.keys():
        raise AitpError("IDENTITY_FAILED", f"OIDC JWT header carries forbidden parameter(s): {sorted(_FORBIDDEN_HEADER_PARAMS & header.keys())}")
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in _ALLOWED_OIDC_ALGS:
        raise AitpError("IDENTITY_FAILED", f"OIDC JWT alg {alg!r} is not one of {sorted(_ALLOWED_OIDC_ALGS)}")

    candidates = issuer_keys_from(issuer_keys.get(issuer))
    if not candidates:
        raise AitpError("KEY_RESOLUTION_FAILED", f"no issuer key resolvable for {issuer!r}", retryable=True)

    kid = header.get("kid")
    resolved = _select_issuer_key(candidates, kid)
    if resolved.jose_alg != alg:
        raise AitpError("IDENTITY_FAILED", f"OIDC JWT alg {alg!r} != resolved key alg {resolved.jose_alg!r}")
    if not resolved.public_key.verify_jose(parsed.signing_input, parsed.signature):
        raise AitpError("IDENTITY_FAILED", "OIDC JWT signature invalid")

    # --- nothing above this line ran without a just-verified signature. ---
    claims = parsed.claims

    if claims.get("iss") != issuer:
        raise AitpError("IDENTITY_FAILED", "JWT iss != identity issuer")
    if claims.get("sub") != identity.get("subject"):
        raise AitpError("IDENTITY_FAILED", "JWT sub != identity subject")

    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, int) or exp <= now:
        raise AitpError("IDENTITY_FAILED", "JWT exp missing, not an integer, or not strictly in the future")

    iat = claims.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int) or abs(now - iat) > _IAT_TOLERANCE_SECS:
        raise AitpError("IDENTITY_FAILED", "JWT iat missing, not an integer, or outside the timestamp tolerance")

    aud = claims.get("aud")
    if aud is None:
        raise AitpError("IDENTITY_FAILED", "JWT missing aud claim")
    if self_aid and aud != self_aid:
        raise AitpError("IDENTITY_FAILED", "JWT aud != verifier AID")

    pop_nonce = envelope.get("payload", {}).get("pop_nonce")
    nonce = claims.get("nonce")
    if nonce is None or pop_nonce is None or nonce != pop_nonce:
        raise AitpError("IDENTITY_FAILED", "JWT nonce != message pop_nonce")

    sender_aid = envelope["sender"]["agent_id"]
    cnf = claims.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if jkt != thumbprint(parse_aid(sender_aid)):
        raise AitpError("IDENTITY_FAILED", "JWT cnf.jkt does not bind the sender key")


def _select_issuer_key(candidates: list[IssuerKey], kid: Any) -> IssuerKey:
    """Pick the one candidate key a JWT header identifies (or the sole one)."""
    if kid is not None:
        matches = [c for c in candidates if c.kid == kid]
        if len(matches) != 1:
            raise AitpError("IDENTITY_FAILED", f"no issuer key candidate matches kid {kid!r}")
        return matches[0]
    if len(candidates) != 1:
        raise AitpError("IDENTITY_FAILED", "OIDC JWT header has no kid and multiple issuer key candidates exist (ambiguous)")
    return candidates[0]


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
