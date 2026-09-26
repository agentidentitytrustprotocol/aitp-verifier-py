"""Ed25519 and ECDSA-P256 primitives for the two AITP signing profiles.

AITP v0.2 mandates both algorithms (RFC-AITP-0001 §5.4.3). Two profiles hash
their input differently, so verification is exposed as two operations:

* ``verify_digest`` — JCS embedded-signature profile (envelope, Manifest,
  revocation snapshot), plus PoP and the pinned-key proof. The spec pseudocode
  signs ``sign(sk, sha256(input))``: Ed25519 takes the 32-byte SHA-256 digest as
  its message; ECDSA-P256 signs that same digest (pre-hashed).
* ``verify_jose`` — compact-JWS profile (TCT, grant voucher, delegation token).
  The signature covers the transmitted ``header.payload`` ASCII bytes directly:
  JOSE ``EdDSA`` signs the input verbatim (no outer SHA-256); ``ES256`` is
  ECDSA over SHA-256 of the input.

P-256 signatures are the JOSE raw ``R||S`` 64-byte form (RFC 7518 §3.4), not
ASN.1/DER — converted here.

A third algorithm, RSA (JOSE ``RS256``), is supported for **verification
only** and **only** as third-party OIDC-issuer key material resolved via
``jwk.py`` (RFC-AITP-0002 §2, RFC-AITP-0007). RSA is never a valid AID
algorithm (``aid.py`` only ever parses ``ed25519``/``p256`` identifiers) and
is unreachable from the AID-keyed ``verify_digest`` profile — an AITP agent's
own signing key is always Ed25519 or P-256. RSA public keys built here MUST
carry a modulus between 2048 and 8192 bits and a public exponent of at most
33 bits, matching the range ``ring::signature::RSA_PKCS1_2048_8192_SHA256``
and ``ring::rsa::PublicExponent::MAX`` give the companion Rust implementation
for free, so both independent implementations accept the same issuer keys —
and, for the ceiling and the exponent bound (issue #47), so this
implementation never accepts an RSA key the companion implementation would
refuse to verify against. Both bounds are checked from the raw ``n``/``e``
bytes before a key object is ever constructed. Each is also required to be
minimally encoded, i.e. carry no leading zero byte (issue #52): a
zero-padded value still satisfies these bounds (leading zero bytes are free
under ``bit_length()``) while forcing this module's caller (``jwk.py``) to
pay a much larger base64url decode cost per key than a real, minimally
encoded key ever would.
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

ALG_ED25519 = "ed25519"
ALG_P256 = "p256"
ALG_RSA = "rsa"

_MIN_RSA_MODULUS_BITS = 2048
# Ceiling matches ring::signature::RSA_PKCS1_2048_8192_SHA256, the algorithm
# identifier the companion Rust implementation uses for RS256 verification
# (issue #47): without it, this implementation would silently accept (and
# verify a JWT against) an RSA JWK the companion implementation's own `ring`
# call refuses. Not a DoS-motivated-only number -- it is the range this
# module's own docstring already claimed to match.
_MAX_RSA_MODULUS_BITS = 8192
# Matches ring::rsa::PublicExponent::MAX = (1u64 << 33) - 1, the same
# resource-exhaustion-motivated ceiling `ring` enforces on the public
# exponent, for the identical cross-implementation-parity reason as the
# modulus ceiling above -- Python `cryptography`'s own floor check
# (`e >= 3`, enforced inside `.public_key()`, not here) is far weaker than
# `ring`'s and is not a substitute for this bound.
_MAX_RSA_EXPONENT_BITS = 33

__all__ = ["ALG_ED25519", "ALG_P256", "ALG_RSA", "PublicKey", "PrivateKey", "sha256"]


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _p256_raw_to_der(sig: bytes) -> bytes:
    if len(sig) != 64:
        raise ValueError(f"ES256 signature must be 64 raw bytes, got {len(sig)}")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    return encode_dss_signature(r, s)


def _p256_der_to_raw(der: bytes) -> bytes:
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class PublicKey:
    """A verifying key tagged with its AITP algorithm (``ed25519`` / ``p256``)."""

    def __init__(self, alg: str, key: object) -> None:
        self.alg = alg
        self._key = key

    @classmethod
    def from_raw(cls, alg: str, raw: bytes) -> "PublicKey":
        """Build from the raw encoding embedded in an AID (§5.3).

        Ed25519: 32-byte raw public key. P-256: 33-byte SEC1 compressed point.
        """
        if alg == ALG_ED25519:
            if len(raw) != 32:
                raise ValueError(f"ed25519 public key must be 32 bytes, got {len(raw)}")
            return cls(alg, ed25519.Ed25519PublicKey.from_public_bytes(raw))
        if alg == ALG_P256:
            if len(raw) != 33:
                raise ValueError(f"p256 public key must be 33 SEC1-compressed bytes, got {len(raw)}")
            return cls(alg, ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw))
        raise ValueError(f"unknown algorithm: {alg}")

    @classmethod
    def from_rsa_numbers(cls, n: bytes, e: bytes) -> "PublicKey":
        """Build a verification-only RSA key from JWK ``n``/``e`` byte strings.

        Reachable only via a third-party OIDC-issuer JWK/JWKS (``jwk.py``) —
        never via an AID. Rejects any modulus outside [2048, 8192] bits or a
        public exponent wider than 33 bits, checked before constructing a key
        object for it (issue #47) so an out-of-range value costs a
        ``bit_length()`` call, not a full RSA public-key construction. Both
        bounds match ``ring``'s own enforced range/ceiling in the companion
        Rust implementation. Also rejects a non-minimally-encoded ``n``/``e``
        (a leading zero byte in more than one byte of input) once its range
        has already been judged in-bounds (issue #52): ``bit_length()``
        strips leading zero bytes for free, so a zero-padded value can carry
        an in-range bit length while still costing ``jwk.py``'s full
        ``_MAX_B64_MEMBER_CHARS`` decode budget -- RFC 7518 SS2's
        ``Base64urlUInt`` already requires the minimum number of octets, and
        SS6.3.1.1 names this exact bug class, so this is spec-compliance, not
        an invented restriction.
        """
        n_int = int.from_bytes(n, "big")
        bits = n_int.bit_length()
        if not (_MIN_RSA_MODULUS_BITS <= bits <= _MAX_RSA_MODULUS_BITS):
            raise ValueError(
                f"RSA modulus must be between {_MIN_RSA_MODULUS_BITS} and "
                f"{_MAX_RSA_MODULUS_BITS} bits, got {bits}"
            )
        if len(n) > 1 and n[0] == 0:
            raise ValueError(
                f"RSA modulus 'n' is not minimally encoded (leading zero byte), "
                f"got {len(n)} bytes for a {bits}-bit value"
            )
        e_int = int.from_bytes(e, "big")
        e_bits = e_int.bit_length()
        if e_bits > _MAX_RSA_EXPONENT_BITS:
            raise ValueError(
                f"RSA public exponent must be at most {_MAX_RSA_EXPONENT_BITS} bits, "
                f"got {e_bits}"
            )
        if len(e) > 1 and e[0] == 0:
            raise ValueError(
                f"RSA public exponent 'e' is not minimally encoded (leading zero byte), "
                f"got {len(e)} bytes for a {e_bits}-bit value"
            )
        public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
        return cls(ALG_RSA, public_numbers.public_key())

    def verify_digest(self, digest: bytes, sig: bytes) -> bool:
        """Verify a JCS-profile / PoP signature over a 32-byte SHA-256 *digest*.

        This is the AID-keyed profile: RSA is never a valid AID algorithm
        (``aid.py`` only constructs ``ed25519``/``p256`` keys), so there is no
        code path that reaches this method with ``self.alg == ALG_RSA``.
        """
        try:
            if self.alg == ALG_ED25519:
                assert isinstance(self._key, ed25519.Ed25519PublicKey)
                self._key.verify(sig, digest)
            else:
                assert isinstance(self._key, ec.EllipticCurvePublicKey)
                self._key.verify(_p256_raw_to_der(sig), digest, ec.ECDSA(utils.Prehashed(_SHA256)))
            return True
        except (_CryptoInvalidSignature, ValueError):
            return False

    def verify_jose(self, signing_input: bytes, sig: bytes) -> bool:
        """Verify a compact-JWS signature over the ``header.payload`` bytes."""
        try:
            if self.alg == ALG_ED25519:
                assert isinstance(self._key, ed25519.Ed25519PublicKey)
                self._key.verify(sig, signing_input)
            elif self.alg == ALG_P256:
                assert isinstance(self._key, ec.EllipticCurvePublicKey)
                self._key.verify(_p256_raw_to_der(sig), signing_input, ec.ECDSA(_SHA256))
            elif self.alg == ALG_RSA:
                assert isinstance(self._key, rsa.RSAPublicKey)
                self._key.verify(sig, signing_input, padding.PKCS1v15(), _SHA256)
            else:
                raise ValueError(f"unrecognized algorithm for JOSE verification: {self.alg!r}")
            return True
        except (_CryptoInvalidSignature, ValueError):
            return False


class PrivateKey:
    """A signing key — used only by the conformance minter, never by verifiers."""

    def __init__(self, alg: str, key: object) -> None:
        self.alg = alg
        self._key = key

    @classmethod
    def ed25519_from_seed(cls, seed: bytes) -> "PrivateKey":
        return cls(ALG_ED25519, ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def p256_from_scalar(cls, scalar: int) -> "PrivateKey":
        return cls(ALG_P256, ec.derive_private_key(scalar, ec.SECP256R1()))

    def public_key(self) -> PublicKey:
        return PublicKey(self.alg, self._key.public_key())  # type: ignore[attr-defined]

    def raw_public(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        pub = self._key.public_key()  # type: ignore[attr-defined]
        if self.alg == ALG_ED25519:
            raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            raw = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        return bytes(raw)

    def sign_digest(self, digest: bytes) -> bytes:
        if self.alg == ALG_ED25519:
            return bytes(self._key.sign(digest))  # type: ignore[attr-defined]
        der = self._key.sign(digest, ec.ECDSA(utils.Prehashed(_SHA256)))  # type: ignore[attr-defined]
        return _p256_der_to_raw(bytes(der))

    def sign_jose(self, signing_input: bytes) -> bytes:
        if self.alg == ALG_ED25519:
            return bytes(self._key.sign(signing_input))  # type: ignore[attr-defined]
        der = self._key.sign(signing_input, ec.ECDSA(_SHA256))  # type: ignore[attr-defined]
        return _p256_der_to_raw(bytes(der))


from cryptography.hazmat.primitives import hashes as _hashes  # noqa: E402

_SHA256 = _hashes.SHA256()
