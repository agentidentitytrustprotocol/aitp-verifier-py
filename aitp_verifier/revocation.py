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
# and each `entries[]` item are all additionalProperties: false. RFC-AITP-0008
# §1.5 includes the wrapper in the member-set check ("the transport wrapper
# MUST contain exactly the members `revocation_list` and `signature`"), unlike
# RFC-AITP-0010, which scopes its check to the bundle's inner body and leaves
# the wrapper to its own §3 shape rule -- the two artifacts are pinned
# differently on purpose and each is followed as written.
#
# An unknown member raises the core UNKNOWN_FIELD (fields.py) and propagates;
# a non-object where the schema requires one keeps TCT_SIGNATURE_INVALID and
# folds into the sig_ok/fail_mode path, since no revocation-specific structural
# code family exists in the registry and such a snapshot is exactly as
# untrustworthy as one with a bad signature.
_SNAPSHOT_FIELDS = frozenset({"revocation_list", "signature"})
_BODY_FIELDS = frozenset({"version", "issuer", "published_at", "expires_at", "entries", "extensions"})
# The schema's `required` set: `extensions` is the only optional body member.
# Checked explicitly because `reject_unknown_fields` rejects members that are
# present and unrecognized, and says nothing about ones that are absent.
_REQUIRED_BODY_FIELDS = ("version", "issuer", "published_at", "expires_at", "entries")
_ENTRY_FIELDS = frozenset({"jti", "revoked_at", "reason"})


def verify_revocation_snapshot(inp: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    policy = inp["policy"]
    snapshot = inp["snapshot"]
    now = int(inp["now"]) if now is None else now
    fail_mode = policy.get("fail_mode", "fail_closed")

    # `body` and `usable` are established INSIDE the try, not above it. They
    # used to be dereferenced before it (`snapshot["revocation_list"]`, then
    # `parse_aid(body["issuer"])`), which made every shape guard below dead
    # code: a non-object snapshot or body raised a raw TypeError, and a body
    # missing `issuer` a raw KeyError, one line before the handler that exists
    # to catch exactly that. Snapshots are fetched from the issuer's remote
    # endpoint, so this is attacker-reachable: a caller that correctly wrapped
    # `except AitpError` still got a traceback instead of its fail_mode answer.
    #
    # `usable` records whether the body reached a state worth evaluating
    # semantically. The freshness and issuer comparisons below index `body`
    # directly, so they may only run once it is known to be a dict carrying
    # every required member.
    body: Any = None
    usable = False
    sig_ok = True
    # The `shape_code=` passed below never reaches the caller: a non-object
    # where the schema requires one is swallowed into sig_ok, and the outcome
    # comes from fail_mode. It is supplied because reject_unknown_fields
    # requires one, and TCT_SIGNATURE_INVALID keeps this consistent with the
    # structural-signature failures just below. UNKNOWN_FIELD is the exception
    # -- see the handler.
    try:
        if not isinstance(snapshot, dict):
            raise AitpError("TCT_SIGNATURE_INVALID", f"revocation snapshot is {type(snapshot).__name__}, not an object")
        reject_unknown_fields(snapshot, _SNAPSHOT_FIELDS, shape_code="TCT_SIGNATURE_INVALID", what="revocation snapshot")
        if not isinstance(snapshot.get("signature"), str):
            # Schema pins `type: string`. `decode_tagged_signature` annotates
            # `sig: str` but is handed unvalidated remote input, so a missing
            # or non-string value tracebacks inside it rather than here.
            raise AitpError("TCT_SIGNATURE_INVALID", f"revocation snapshot signature is {type(snapshot.get('signature')).__name__}, not a string")
        body = snapshot.get("revocation_list")
        reject_unknown_fields(body, _BODY_FIELDS, shape_code="TCT_SIGNATURE_INVALID", what="revocation_list")
        if missing := [k for k in _REQUIRED_BODY_FIELDS if k not in body]:
            raise AitpError("TCT_SIGNATURE_INVALID", f"revocation_list is missing required member(s) {missing}")
        if not isinstance(body["issuer"], str):
            # `parse_aid` calls `.startswith` on its argument, so a non-string
            # issuer raises AttributeError -- not the ValueError handled below.
            raise AitpError("TCT_SIGNATURE_INVALID", f"revocation_list issuer is {type(body['issuer']).__name__}, not a string")
        usable = True
        entries = body.get("entries", [])
        if not isinstance(entries, list):
            # `for entry in entries` would raise a raw TypeError on a scalar,
            # escaping the AitpError-only handler below and crashing instead of
            # failing closed. Snapshots arrive from the issuer's remote
            # endpoint, so this is attacker-reachable input.
            raise AitpError("TCT_SIGNATURE_INVALID", f"revocation_list entries is {type(entries).__name__}, not an array")
        for entry in entries:
            reject_unknown_fields(entry, _ENTRY_FIELDS, shape_code="TCT_SIGNATURE_INVALID", what="revocation_list entry")
        try:
            issuer = parse_aid(body["issuer"])
        except ValueError as exc:
            # `parse_aid` signals a malformed AID with a bare ValueError, not
            # an AitpError, so it would sail past the handler below. The issuer
            # string is remote-supplied, so an unparseable one has to fail
            # closed like any other structural defect rather than crash the
            # caller.
            raise AitpError("TCT_SIGNATURE_INVALID", f"revocation_list issuer is not a valid AID: {exc}") from exc
        raw = decode_tagged_signature(snapshot["signature"], issuer, sig_err="TCT_SIGNATURE_INVALID")
        sig_ok = issuer.public_key.verify_digest(sha256(canonicalize(body)), raw)
    except AitpError as exc:
        # UNKNOWN_FIELD is the one failure in this block that MUST reach the
        # caller intact. RFC-AITP-0008 §1.5 puts member-set validation first,
        # "before any signature work", and gives it its own core code: an
        # unknown member that one implementation hashes into the reconstructed
        # JCS signing input and another drops must never reach the signature
        # check at all. Folding it into sig_ok would report TCT_REVOKED under
        # fail_closed -- a true statement about the queried jti only by
        # accident, and under soft_fail it would report the snapshot merely
        # stale, silently accepting an artifact §7 says MUST be rejected. The
        # policy's fail_mode answers "what if there is no fresh snapshot"; a
        # malformed one is a different question, decided before freshness.
        if exc.code == "UNKNOWN_FIELD":
            raise
        sig_ok = False

    # A body that never reached `usable` cannot be compared or dated, so the
    # two checks below are skipped rather than guarded individually. The
    # outcome is the same one an unverifiable signature produces: this is
    # "no fresh valid snapshot", which RFC-AITP-0008 §3 hands to the policy.
    issuer_ok = usable and body["issuer"] == inp.get("expected_issuer")
    fresh = False
    if usable:
        try:
            fresh = (now - int(body["published_at"])) <= int(policy["max_staleness_secs"]) and now < int(body["expires_at"])
        except (TypeError, ValueError):
            # Timestamps are `type: integer` in the schema, but a remote peer
            # can send anything; a non-numeric one is a stale-equivalent
            # defect, not a crash.
            fresh = False

    if not (sig_ok and issuer_ok and fresh):
        if fail_mode == "soft_fail":
            return {"revoked": False, "stale": True}
        raise AitpError("TCT_REVOKED", "no fresh valid revocation snapshot (fail_closed)")

    queried = inp.get("queried_jti")
    if queried is not None and any(e.get("jti") == queried for e in body.get("entries", [])):
        raise AitpError("TCT_REVOKED", "queried jti is on the deny list")
    return {"revoked": False}
