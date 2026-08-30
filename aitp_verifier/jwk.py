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
  RFC-AITP-0007 §3 and RFC-AITP-0002 §2.3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from .aid import Aid
from .b64 import b64url_decode, b64url_encode
from .crypto import ALG_ED25519, ALG_P256, PublicKey, sha256

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
            raise ValueError(f"unsupported OKP curve: {crv!r}")
        x = b64url_decode(_require_str(value.get("x"), "x"))
        if len(x) != 32:
            raise ValueError(f"Ed25519 JWK 'x' must decode to 32 bytes, got {len(x)}")
        return IssuerKey(kid=kid, jose_alg="EdDSA", public_key=PublicKey.from_raw(ALG_ED25519, x))

    if kty == "EC":
        crv = value.get("crv")
        if crv != "P-256":
            raise ValueError(f"unsupported EC curve: {crv!r}")
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

    raise ValueError(f"unsupported or missing JWK 'kty': {kty!r}")


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
    resolution error.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [issuer_key_from_config(value)]
    if isinstance(value, dict):
        if "keys" in value:
            keys = value["keys"]
            if not isinstance(keys, list):
                raise ValueError("JWKS 'keys' must be a list")
            return [issuer_key_from_jwk(k) for k in keys]
        return [issuer_key_from_jwk(value)]
    if isinstance(value, list):
        out: list[IssuerKey] = []
        for item in value:
            out.extend(issuer_keys_from(item))
        return out
    raise ValueError(f"unsupported issuer key value shape: {type(value).__name__}")
