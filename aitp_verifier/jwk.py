"""JWK thumbprints (RFC 7638) and JWK/issuer-key parsing (RFC 7517).

Two directions live here:

* **Thumbprint computation** (``thumbprint`` / ``thumbprint_for_aid``) — the
  portable trust artifacts (TCT, delegation token) and the OIDC identity
  binding carry ``cnf.jkt``, the base64url-unpadded SHA-256 over the
  canonical JWK (RFC-AITP-0001 §5.4.4). A verifier derives the *expected*
  thumbprint from the subject AID's key and rejects the token if ``cnf.jkt``
  differs. The canonical JWK has members in lexicographic order and no
  whitespace:

  * Ed25519 (OKP): ``{"crv":"Ed25519","kty":"OKP","x":<raw-32>}``
  * P-256 (EC):    ``{"crv":"P-256","kty":"EC","x":<X-32>,"y":<Y-32>}``

  Validated against ``known-answer/jwk-thumbprints.json``.

* **Issuer-key parsing** (``issuer_key_from_jwk`` / ``issuer_key_from_config``
  / ``issuer_keys_from``) — the inverse direction, used to resolve a
  third-party OIDC issuer's public key(s) when verifying an identity JWT
  (RFC-AITP-0002 §2, RFC-AITP-0007). A candidate key's algorithm is always
  derived from its own *structure* — ``kty``/``crv`` for a JWK, encoded
  length for the legacy static-config form — and **never** trusted from a
  JWK's own ``alg`` member or from anything the token itself claims. A JWK
  that lies about ``alg`` still parses under the algorithm its structure
  actually implies; this is the alg-confusion defense described in
  RFC-AITP-0007 §3 and RFC-AITP-0002 §2.3. ``issuer_keys_from``'s value is
  caller/resolver-supplied, not schema-validated (issue #38): its list walk
  is depth-bounded (``_MAX_DEPTH``, enforced by a private helper so the
  public function's signature can't be used to bypass it), its total
  candidate count across every shape/nesting combination is bounded
  (``_MAX_CANDIDATES``, checked before each candidate is parsed, not only
  after the final list is built — issue #47), and
  ``issuer_key_from_jwk``'s own rejection messages route an unrecognized
  ``kty``/``crv`` through ``fields.describe_value`` rather than ``repr()``,
  so a container value there can neither blow the message budget nor raise
  ``RecursionError`` while the message is being built. Every ``ValueError``
  either can raise is converted to ``AitpError`` at the one call site,
  ``identity.py``'s ``_verify_oidc``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .aid import Aid
from .b64 import b64url_decode, b64url_encode
from .crypto import ALG_ED25519, ALG_P256, PublicKey, sha256
from .fields import describe_value

__all__ = [
    "thumbprint",
    "thumbprint_for_aid",
    "IssuerKey",
    "issuer_key_from_jwk",
    "issuer_key_from_config",
    "issuer_keys_from",
]


def _canonical_jwk(aid: Aid) -> bytes:
    if aid.alg == ALG_ED25519:
        x = b64url_encode(aid.raw_key)
        return f'{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}'.encode("ascii")
    # P-256: decompress the SEC1 point to its affine X/Y coordinates.
    key = aid.public_key._key
    assert isinstance(key, ec.EllipticCurvePublicKey)
    numbers = key.public_numbers()
    x = b64url_encode(numbers.x.to_bytes(32, "big"))
    y = b64url_encode(numbers.y.to_bytes(32, "big"))
    return f'{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}'.encode("ascii")


def thumbprint(aid: Aid) -> str:
    """Return the RFC 7638 ``jkt`` (unpadded base64url SHA-256) for *aid*'s key."""
    return b64url_encode(sha256(_canonical_jwk(aid)))


def thumbprint_for_aid(aid_str: str) -> str:
    from .aid import parse_aid

    return thumbprint(parse_aid(aid_str))


@dataclass(frozen=True)
class IssuerKey:
    """A single candidate verification key resolved for an OIDC issuer.

    ``jose_alg`` is derived from the key's structure at parse time (never
    from a self-declared ``alg``) — see the module docstring.
    """

    kid: str | None
    jose_alg: str
    public_key: PublicKey


def _require_str(value: Any, member: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"JWK member {member!r} must be a string")
    return value


def issuer_key_from_jwk(value: dict[str, Any]) -> IssuerKey:
    """Parse one JWK object (RFC 7517 §4) into an :class:`IssuerKey`.

    ``kty``/``crv`` (never the JWK's own ``alg``) determine the algorithm:

    * ``kty=OKP``, ``crv=Ed25519`` — a 32-byte ``x`` — ``jose_alg="EdDSA"``.
    * ``kty=EC``, ``crv=P-256`` — 32-byte ``x`` and ``y`` — ``jose_alg="ES256"``.
    * ``kty=RSA`` — base64url ``n``/``e`` — ``jose_alg="RS256"`` (modulus MUST
      be at least 2048 bits; see ``crypto.PublicKey.from_rsa_numbers``).

    Raises ``ValueError`` for any other/malformed shape.
    """
    if not isinstance(value, dict):
        raise ValueError("JWK must be a JSON object")
    kty = value.get("kty")
    kid = value.get("kid")
    if kid is not None and not isinstance(kid, str):
        raise ValueError("JWK 'kid' must be a string when present")

    if kty == "OKP":
        crv = value.get("crv")
        if crv != "Ed25519":
            raise ValueError(f"unsupported OKP curve: {describe_value(crv)}")
        x = b64url_decode(_require_str(value.get("x"), "x"))
        if len(x) != 32:
            raise ValueError(f"Ed25519 JWK 'x' must decode to 32 bytes, got {len(x)}")
        return IssuerKey(kid=kid, jose_alg="EdDSA", public_key=PublicKey.from_raw(ALG_ED25519, x))

    if kty == "EC":
        crv = value.get("crv")
        if crv != "P-256":
            raise ValueError(f"unsupported EC curve: {describe_value(crv)}")
        x = b64url_decode(_require_str(value.get("x"), "x"))
        y = b64url_decode(_require_str(value.get("y"), "y"))
        if len(x) != 32 or len(y) != 32:
            raise ValueError(f"P-256 JWK 'x'/'y' must each decode to 32 bytes, got {len(x)}/{len(y)}")
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        )
        return IssuerKey(kid=kid, jose_alg="ES256", public_key=PublicKey(ALG_P256, numbers.public_key()))

    if kty == "RSA":
        n = b64url_decode(_require_str(value.get("n"), "n"))
        e = b64url_decode(_require_str(value.get("e"), "e"))
        return IssuerKey(kid=kid, jose_alg="RS256", public_key=PublicKey.from_rsa_numbers(n, e))

    raise ValueError(f"unsupported or missing JWK 'kty': {describe_value(kty)}")


def issuer_key_from_config(b64url: str) -> IssuerKey:
    """Parse the legacy static-config form: a bare unpadded-base64url string.

    Algorithm is inferred from the decoded length, mirroring the AID
    convention in ``aid.py``: 43 chars -> Ed25519 (``EdDSA``), 44 chars ->
    P-256 (``ES256``). Any other length is rejected. ``kid`` is always
    ``None`` — this form carries no key identifier.
    """
    if not isinstance(b64url, str):
        raise ValueError("issuer key config value must be a string")
    if len(b64url) == 43:
        raw = b64url_decode(b64url)
        return IssuerKey(kid=None, jose_alg="EdDSA", public_key=PublicKey.from_raw(ALG_ED25519, raw))
    if len(b64url) == 44:
        raw = b64url_decode(b64url)
        return IssuerKey(kid=None, jose_alg="ES256", public_key=PublicKey.from_raw(ALG_P256, raw))
    raise ValueError(f"issuer key config string must be 43 (Ed25519) or 44 (P-256) chars, got {len(b64url)}")


# Maximum LIST nesting depth this walk will descend before rejecting a
# caller-supplied issuer-key value as malformed. Unlike jcs.py's _MAX_DEPTH
# (a full JSON-tree walk over input of unknown provenance), this recursion
# is over LIST nesting only: a dict is always a terminal JWK/JWKS leaf,
# parsed within the same call frame rather than recursed into again -- so
# a genuine value nests at most 1 level deep (a flat list of
# JWK/JWKS/config-string entries; RFC-AITP-0007 gives no meaning to a
# nested list). 16 is generous headroom over that, not a number tightly
# calibrated to it. Kept as its own constant rather than importing
# jcs.py's private _MAX_DEPTH: that cap is calibrated against a
# structurally different (full-tree, not list-only) recursion, and
# reaching into a sibling module's private name would be a leakier
# coupling than one small, independently-justified number.
_MAX_DEPTH = 16

# Maximum total candidate keys a single issuer_keys_from call will resolve,
# across every shape/nesting combination that can produce a candidate (a
# JWKS's `keys` array, a flat list, or any mix of the two). Checked before
# each candidate is parsed, not only after the final list is built -- same
# "guard at entry, not only at the recursion site" reasoning _MAX_DEPTH
# above already establishes: checking only the final list length would
# still pay full parse cost for every candidate past the cap before
# rejecting. 64 is generous headroom (2-6x) over real-world OIDC-provider
# JWKS practice (Google/Microsoft/Okta/Auth0 typically carry 2-10 keys,
# rarely up to ~20-30 during rotation overlap; RFC 7517 gives no size
# guidance) -- not a number tightly calibrated to it (issue #47).
_MAX_CANDIDATES = 64


def issuer_keys_from(value: Any) -> list[IssuerKey]:
    """Normalize a caller-supplied issuer-key value into a flat candidate list.

    Accepts, in any combination:

    * a bare config string (``issuer_key_from_config``);
    * a single JWK object (``issuer_key_from_jwk``);
    * a JWKS object (``{"keys": [...]}``) — each entry parsed as a JWK;
    * a list mixing any of the above.

    Returns ``[]`` for ``None`` or an empty/absent value (the caller treats
    zero candidates as key-resolution failure). Raises ``ValueError``
    immediately on the first malformed candidate — partial tolerance would
    let a malformed entry silently vanish instead of surfacing as a
    resolution error. Depth-bounded (``_MAX_DEPTH``, issue #38): a value
    nesting lists past that bound also raises ``ValueError`` rather than a
    raw ``RecursionError``. Bounded to at most ``_MAX_CANDIDATES`` total
    candidates across every shape/nesting combination (issue #47); checked
    before parsing each one, not only after. This function's own signature
    carries no ``depth``/accumulator parameter — the bounded walk lives in
    a private helper — so a caller cannot pass a starting state that
    defeats either cap.
    """
    out: list[IssuerKey] = []
    _issuer_keys_from(value, 0, out)
    return out


def _issuer_keys_from(value: Any, depth: int, out: list[IssuerKey]) -> None:
    # Guard at entry, not only at the recursion site: a caller passing an
    # already-deep value could exceed the cap before the first check ever
    # ran if the guard sat only where the recursive call is made (same
    # reasoning as jcs.py::_serialize). `depth` is an internal walk
    # counter, not part of the public contract -- see issuer_keys_from's
    # own docstring for why it is not exposed as a parameter there.
    if depth > _MAX_DEPTH:
        raise ValueError(f"issuer key value nesting exceeds the maximum depth ({_MAX_DEPTH})")
    if value is None:
        return
    if isinstance(value, str):
        _reserve(out)
        out.append(issuer_key_from_config(value))
        return
    if isinstance(value, dict):
        if "keys" in value:
            keys = value["keys"]
            if not isinstance(keys, list):
                raise ValueError("JWKS 'keys' must be a list")
            for k in keys:
                _reserve(out)
                out.append(issuer_key_from_jwk(k))
            return
        _reserve(out)
        out.append(issuer_key_from_jwk(value))
        return
    if isinstance(value, list):
        for item in value:
            _issuer_keys_from(item, depth + 1, out)
        return
    raise ValueError(f"unsupported issuer key value shape: {type(value).__name__}")


def _reserve(out: list[IssuerKey]) -> None:
    # Checked before every append, at all three candidate-producing sites
    # above -- not only inside the JWKS "keys" loop -- so a value that
    # spreads candidates across many small containers (many sibling
    # single-JWK list entries, or many small-`keys` JWKS objects nested
    # inside a list) cannot evade the cap by never presenting one single
    # oversized array. `out` is threaded through every recursive call
    # rather than built-and-merged per frame (the pre-#47 shape), which is
    # what makes a *global*, cross-shape running total possible at all.
    if len(out) >= _MAX_CANDIDATES:
        raise ValueError(f"issuer key value carries more than {_MAX_CANDIDATES} candidate keys")
