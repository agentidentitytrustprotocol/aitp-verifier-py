"""The handshake proof input shared by the pinned-key proof (RFC-AITP-0002
§3.1) and the X509-SVID proof (§6.4.1): the same five fields, each NUL
terminated, after a domain prefix that keeps the two proofs apart."""

from __future__ import annotations

from .b64 import b64url_decode

__all__ = ["PINNED_KEY_DOMAIN", "SPIFFE_X509_DOMAIN", "handshake_proof_input"]

PINNED_KEY_DOMAIN = b"aitp-pinned-key-v1\x00"
SPIFFE_X509_DOMAIN = b"aitp-spiffe-x509-v1\x00"


def handshake_proof_input(
    domain: bytes, sender_aid: str, receiver_aid: str, message_id: str, timestamp: int, pop_nonce: str
) -> bytes:
    return (
        domain
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
