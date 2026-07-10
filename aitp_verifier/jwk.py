"""RFC 7638 JWK SHA-256 thumbprints for the ``cnf.jkt`` binding.

The portable trust artifacts (TCT, delegation token) and the OIDC identity
binding carry ``cnf.jkt`` — the base64url-unpadded SHA-256 over the canonical
JWK (RFC-AITP-0001 §5.4.4). A verifier derives the *expected* thumbprint from
the subject AID's key and rejects the token if ``cnf.jkt`` differs. The
canonical JWK has members in lexicographic order and no whitespace:

* Ed25519 (OKP): ``{"crv":"Ed25519","kty":"OKP","x":<raw-32>}``
* P-256 (EC):    ``{"crv":"P-256","kty":"EC","x":<X-32>,"y":<Y-32>}``

Validated against ``known-answer/jwk-thumbprints.json``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec

from .aid import Aid
from .b64 import b64url_encode
from .crypto import ALG_ED25519, sha256

__all__ = ["thumbprint", "thumbprint_for_aid"]


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
