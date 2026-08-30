"""Revocation-snapshot verification (RFC-AITP-0008 §1.5, JCS profile).

A snapshot is a signed ``revocation_list`` body. ``verify_revocation_snapshot``
checks the issuer, the signature, and freshness, then applies the deny list.
A stale/invalid snapshot is "no fresh snapshot": under ``fail_closed`` that is
treated as revoked (``TCT_REVOKED``); under ``soft_fail`` the queried jti is
reported not-revoked (the safe read-only subset).
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .crypto import sha256
from .errors import AitpError
from .fields import reject_unknown_fields
from .jcs import canonicalize
from .sigfield import decode_tagged_signature

__all__ = ["verify_revocation_snapshot"]

# aitp-revocation-list.schema.json: the wrapper, the `revocation_list` body,
# and each `entries[]` item are all additionalProperties: false. No
# revocation-specific code family exists in the registry at all (this module
# already reuses TCT_SIGNATURE_INVALID below for its own structural signature
# failures, in the absence of one) -- shape rejection folds into that same
# existing sig_ok/fail_mode path rather than raising a bespoke code, since an
# unrecognized-shape snapshot is exactly as untrustworthy as one with a bad
# signature and this module already treats every structural failure that way.
_SNAPSHOT_FIELDS = frozenset({"revocation_list", "signature"})
_BODY_FIELDS = frozenset({"version", "issuer", "published_at", "expires_at", "entries", "extensions"})
_ENTRY_FIELDS = frozenset({"jti", "revoked_at", "reason"})


def verify_revocation_snapshot(inp: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    policy = inp["policy"]
    snapshot = inp["snapshot"]
    now = int(inp["now"]) if now is None else now
    body = snapshot["revocation_list"]

    issuer = parse_aid(body["issuer"])
    fail_mode = policy.get("fail_mode", "fail_closed")

    sig_ok = True
    # The `code=` passed below never reaches the caller: every AitpError here
    # is swallowed into sig_ok, and the outcome comes from fail_mode. It is
    # supplied because reject_unknown_fields requires one, and TCT_SIGNATURE_INVALID
    # keeps this consistent with the structural-signature failures just below.
    try:
        reject_unknown_fields(snapshot, _SNAPSHOT_FIELDS, code="TCT_SIGNATURE_INVALID", what="revocation snapshot")
        reject_unknown_fields(body, _BODY_FIELDS, code="TCT_SIGNATURE_INVALID", what="revocation_list")
        entries = body.get("entries", [])
        if not isinstance(entries, list):
            # `for entry in entries` would raise a raw TypeError on a scalar,
            # escaping the AitpError-only handler below and crashing instead of
            # failing closed. Snapshots arrive from the issuer's remote
            # endpoint, so this is attacker-reachable input.
            raise AitpError("TCT_SIGNATURE_INVALID", f"revocation_list entries is {type(entries).__name__}, not an array")
        for entry in entries:
            reject_unknown_fields(entry, _ENTRY_FIELDS, code="TCT_SIGNATURE_INVALID", what="revocation_list entry")
        raw = decode_tagged_signature(snapshot["signature"], issuer, sig_err="TCT_SIGNATURE_INVALID")
        sig_ok = issuer.public_key.verify_digest(sha256(canonicalize(body)), raw)
    except AitpError:
        sig_ok = False

    issuer_ok = body["issuer"] == inp.get("expected_issuer")
    fresh = (now - int(body["published_at"])) <= int(policy["max_staleness_secs"]) and now < int(body["expires_at"])

    if not (sig_ok and issuer_ok and fresh):
        if fail_mode == "soft_fail":
            return {"revoked": False, "stale": True}
        raise AitpError("TCT_REVOKED", "no fresh valid revocation snapshot (fail_closed)")

    queried = inp.get("queried_jti")
    if queried is not None and any(e.get("jti") == queried for e in body.get("entries", [])):
        raise AitpError("TCT_REVOKED", "queried jti is on the deny list")
    return {"revoked": False}
