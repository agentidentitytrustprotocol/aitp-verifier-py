"""Agent Manifest verification (RFC-AITP-0003 §5, JCS profile).

Ordered checklist: version → expiry → proof-of-possession → signature. The
Manifest signature covers ``sha256(JCS(manifest_body))`` with the top-level
``signature`` member removed (§6.1); the PoP covers
``sha256(base64url_decode(challenge))`` (§3.1). Both verify under the key
embedded in ``manifest.aid``.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .b64 import b64url_decode
from .crypto import sha256
from .errors import AitpError
from .jcs import canonicalize
from .sigfield import decode_tagged_signature
from .timeutil import REFERENCE_CLOCK

__all__ = ["verify_manifest"]


def verify_manifest(inp: dict[str, Any], now: int = REFERENCE_CLOCK) -> dict[str, Any]:
    man = inp["manifest"]
    now = int(inp.get("now", now))
    supported = inp.get("supported_versions", ["aitp/0.2"])

    if man.get("version") not in supported:
        raise AitpError("MANIFEST_VERSION_UNKNOWN", f"unsupported version {man.get('version')!r}")
    if now >= int(man["expires_at"]):
        raise AitpError("MANIFEST_EXPIRED", "manifest expires_at is in the past")

    aid = parse_aid(man["aid"])

    pop = man["proof_of_possession"]
    pop_sig = decode_tagged_signature(pop["signature"], aid, sig_err="MANIFEST_POP_FAILED")
    if not aid.public_key.verify_digest(sha256(b64url_decode(pop["challenge"])), pop_sig):
        raise AitpError("MANIFEST_POP_FAILED", "proof-of-possession signature invalid")

    man_sig = decode_tagged_signature(man["signature"], aid, sig_err="MANIFEST_SIGNATURE_INVALID")
    body = {k: v for k, v in man.items() if k != "signature"}
    if not aid.public_key.verify_digest(sha256(canonicalize(body)), man_sig):
        raise AitpError("MANIFEST_SIGNATURE_INVALID", "manifest signature invalid")

    return {"aid": man["aid"]}
