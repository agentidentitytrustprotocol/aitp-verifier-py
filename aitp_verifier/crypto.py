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
"""

from __future__ import annotations

import hashlib

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

ALG_ED25519 = "ed25519"
ALG_P256 = "p256"

__all__ = ["ALG_ED25519", "ALG_P256", "PublicKey", "PrivateKey", "sha256"]


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

    def verify_digest(self, digest: bytes, sig: bytes) -> bool:
        """Verify a JCS-profile / PoP signature over a 32-byte SHA-256 *digest*."""
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
            else:
                assert isinstance(self._key, ec.EllipticCurvePublicKey)
                self._key.verify(_p256_raw_to_der(sig), signing_input, ec.ECDSA(_SHA256))
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
