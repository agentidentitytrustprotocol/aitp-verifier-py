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
  (Ed25519), ``ES256`` (P-256) and ``RS256`` (RSA, modulus between 2048 and
  8192 bits, public exponent at most 33 bits — see ``crypto.py``); the
  issuer key may be supplied as a legacy 43/44-char raw base64url string, a
  single JWK, or a JWKS (``{"keys": [...]}"``) — see ``jwk.py``. The header's
  ``alg`` is pinned to the *resolved key's own structural algorithm* and
  compared, never trusted on its own (alg-confusion defense); ``none`` in any
  spelling is never in the allowed set. Any claim/structural failure is
  ``IDENTITY_FAILED``; zero resolvable issuer-key candidates, or a
  malformed, too-deeply-nested, too-numerous, or wrongly-shaped
  ``resolved_issuer_keys`` value (issues #38, #47 — this is
  caller/resolver-supplied, not schema-validated), is
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
from .fields import describe_value, reject_unknown_fields
from .jwk import IssuerKey, issuer_keys_from, thumbprint
from .jws import parse_compact

__all__ = ["pinned_key_proof_input", "verify_identity"]

_ALLOWED_OIDC_ALGS = {"EdDSA", "ES256", "RS256"}
_FORBIDDEN_HEADER_PARAMS = {"jwk", "jku", "x5u", "x5c", "crit"}
_IAT_TOLERANCE_SECS = 300

# The IdentityDescriptor ($defs in aitp-mutual-handshake.schema.json) is
# additionalProperties: false and, like every other signed AITP object,
# reserves an `extensions` slot -- so an unrecognized key INSIDE it is ignored
# (RFC-AITP-0001 §7) while an unrecognized member beside it is rejected.
#
# That slot is new. Two committed schemas used to disagree: the handshake
# descriptor omitted `extensions` while the standalone aitp-identity.schema.json
# carried one, and RFC-AITP-0002 §1 named the standalone schema canonical even
# though the handshake payload is validated against the inline one. This module
# followed the governing (handshake) schema and rejected `extensions` -- the
# fail-closed reading of an ambiguity, but a false rejection if the other side
# was right. Spec PR #42 collapsed the two definitions into one and added
# `extensions` here; id-009 now pins acceptance.
_IDENTITY_FIELDS = frozenset({"type", "issuer", "subject", "proof", "public_key", "extensions"})


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
    reject_unknown_fields(identity, _IDENTITY_FIELDS, shape_code="IDENTITY_FAILED", what="identity descriptor")
    itype = identity.get("type")
    if itype == "oidc":
        _verify_oidc(identity, envelope, self_aid, trust_anchors, issuer_keys, now)
    elif itype == "pinned_key":
        _verify_pinned_key(identity, envelope, self_aid, trust_store)
    else:
        # `describe_value`, not `{itype!r}`: nothing upstream has constrained
        # `type`'s JSON type -- `reject_unknown_fields` above checks the member
        # SET only -- so this is reached with an arbitrarily deep container.
        raise AitpError("IDENTITY_FAILED", f"unknown identity type {describe_value(itype)}")


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
       up on a later resolution attempt). The same code covers every way
       resolution can fail to produce usable candidates in the first place
       (issues #38, #47): ``issuer_keys`` itself not being a mapping, or its
       per-issuer value being too deeply nested, carrying too many candidate
       keys, carrying an RSA key outside the accepted modulus/exponent
       range, or otherwise malformed for ``issuer_keys_from`` to walk —
       none of these are a proof-shape problem, so none get
       ``IDENTITY_FAILED``. A header ``kid`` with no
       matching candidate, or no ``kid`` with 2+ candidates (ambiguous), ->
       a resolution *target* did exist but couldn't be pinned, which IS a
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
        # `describe_value` again: this branch is entered PRECISELY when `alg` failed
        # the `isinstance(alg, str)` test, so the value being reported is by
        # construction unvalidated header JSON, container included.
        raise AitpError("IDENTITY_FAILED", f"OIDC JWT alg {describe_value(alg)} is not one of {sorted(_ALLOWED_OIDC_ALGS)}")

    # `issuer_keys` is caller/resolver-supplied, not schema-validated (issues
    # #38, #47): a non-`Mapping` argument, or a per-issuer value too deeply
    # nested, carrying too many candidate keys, carrying an out-of-range RSA
    # modulus/exponent, or otherwise malformed for `issuer_keys_from` to
    # walk, must not escape as a raw
    # `AttributeError`/`ValueError`/`RecursionError`. All of these collapse
    # into the same "no usable candidates" outcome as the existing
    # zero-candidates case immediately below -- a resolver that hands back
    # garbage has produced exactly as much usable key material as one that
    # hands back nothing.
    #
    # `isinstance(..., Mapping)` is structural only for the caller's own type
    # already being registered with (or subclassing) `collections.abc.Mapping`
    # -- unlike `Hashable`/`Iterable`/`Sized`, `Mapping` defines no
    # `__subclasshook__`, so a plain duck-typed object exposing only `.get()`
    # (e.g. a lazy resolver wrapper) fails this check and is silently treated
    # as "no issuer key resolvable", the same as a genuinely absent issuer,
    # rather than consulted. `dict` and every stdlib mapping type are
    # registered, so this only affects a caller's own custom, unregistered
    # mapping-like class -- a real but narrow edge, not fixed here since
    # registering with `Mapping.register(...)` (or subclassing it) is the
    # caller's own, cheaper fix on their side.
    resolved = issuer_keys.get(issuer) if isinstance(issuer_keys, Mapping) else None
    try:
        candidates = issuer_keys_from(resolved)
    except RecursionError as exc:
        # Defense in depth behind jwk.py's own depth cap, same reasoning as
        # fields.py::canonical_bytes: the cap bounds THIS walk's frames, but
        # a caller whose stack was already near-exhausted before calling in
        # can still exhaust it inside a walk the cap would have admitted.
        # Message is a constant literal -- formatting one while the stack
        # is exhausted can itself re-trigger the error.
        raise AitpError("KEY_RESOLUTION_FAILED", "issuer key value is too deeply nested to resolve", retryable=True) from exc
    except ValueError as exc:
        raise AitpError("KEY_RESOLUTION_FAILED", f"issuer key value for {issuer!r} is malformed: {exc}", retryable=True) from exc
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
    """Pick the one candidate key a JWT header identifies (or the sole one).

    *kid* is typed ``Any`` because it is raw header JSON: the caller reads it
    with a bare ``header.get("kid")`` and no type check (a non-string ``kid``
    simply matches no candidate), so it reaches the message below as a
    container -- hence ``describe_value`` rather than ``{kid!r}``.
    """
    if kid is not None:
        matches = [c for c in candidates if c.kid == kid]
        if len(matches) != 1:
            raise AitpError("IDENTITY_FAILED", f"no issuer key candidate matches kid {describe_value(kid)}")
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
    from .crypto import PublicKey

    pub = identity.get("public_key", "")
    # `identity.public_key`/`identity.proof` are RFC-AITP-0002 §1's own
    # payload -- unconstrained-type at the schema level like every other
    # signed-object member, so nothing upstream has confirmed they are even
    # strings yet. Building the five-field proof input, decoding either
    # base64url value, and constructing the raw public key can each raise a
    # different stdlib exception (AttributeError from `.encode()` on a
    # non-string `message_id`, TypeError/ValueError/OverflowError from
    # `int(timestamp)` or a non-string `b64url_decode` argument,
    # binascii.Error from malformed base64) for a mistyped/malformed value at
    # any of these fields -- none of them AitpError, so all would otherwise
    # escape this module's caller. This module's own OIDC docstring already
    # states the operative rule for every claim/structural failure here:
    # IDENTITY_FAILED. `KeyError` is caught too, as defense in depth: this
    # function's own caller (`handshake.py::_verify_bootstrap`) now guards
    # `payload["pop_nonce"]`'s presence before calling here, but this
    # function is reachable on its own via the public `verify_identity` too,
    # with no such guarantee from that caller.
    try:
        # Trust-store gate runs first: an unknown key is rejected before
        # crypto. `pub not in pinned` needs `pub` hashable -- inside the try
        # for the same reason as everything below it.
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
        key = PublicKey.from_raw("ed25519", b64url_decode(pub))
        sig = b64url_decode(identity.get("proof", ""))
    except AitpError:
        raise
    except (TypeError, ValueError, AttributeError, OverflowError, KeyError) as exc:
        raise AitpError("IDENTITY_FAILED", f"pinned-key identity is malformed: {exc}") from exc
    if len(sig) != 64 or not key.verify_digest(sha256(proof_input), sig):
        raise AitpError("IDENTITY_FAILED", "pinned-key proof does not verify (five-field input)")
