"""Revocation-snapshot verification (RFC-AITP-0008 §1.5, JCS profile).

A snapshot is a signed ``revocation_list`` body. ``verify_revocation_snapshot``
runs the §1.5 order: structural validation, then member-set validation, then
the signature, then freshness, then the deny list.

The load-bearing distinction is **obtained-but-untrustworthy vs. absent**,
which RFC-AITP-0008 §1.5 spells out in its own blockquote. A snapshot the peer
obtained and could not trust reports what was wrong with it, and the policy's
``fail_mode`` never sees it:

* schema defect (missing REQUIRED member, wrong type) ⇒ ``REVOCATION_SNAPSHOT_INVALID``
* unknown member outside ``extensions`` ⇒ ``UNKNOWN_FIELD`` (RFC-AITP-0001 §7)
* signature does not verify ⇒ ``REVOCATION_SNAPSHOT_SIGNATURE_INVALID``

A snapshot that is unreachable, stale beyond ``max_staleness_secs``, or issued
by someone other than the expected peer is **absent** — the peer never obtained
one it could evaluate. Only that case consults ``fail_mode``: ``fail_closed``
treats unknown revocation status as revoked (``TCT_REVOKED``), ``soft_fail``
reports the queried jti not-revoked and stale (the safe read-only subset).

Every one of those codes is raised, not folded into a boolean. An earlier
version of this module collapsed all three untrustworthy cases into a
``sig_ok`` flag and answered from ``fail_mode``; under ``soft_fail`` that
returned ``{"revoked": False, "stale": True}`` for artifacts the spec says MUST
be rejected.
"""

from __future__ import annotations

from typing import Any

from .aid import parse_aid
from .crypto import sha256
from .errors import AitpError
from .fields import reject_unknown_fields
from .jcs import JcsError, canonicalize
from .sigfield import decode_tagged_signature

__all__ = ["verify_revocation_snapshot"]

# aitp-revocation-list.schema.json. The wrapper, the `revocation_list` body,
# and each `entries[]` item are all additionalProperties: false. RFC-AITP-0008
# §1.5 includes the wrapper in the member-set check ("the transport wrapper
# MUST contain exactly the members `revocation_list` and `signature`"), unlike
# RFC-AITP-0010, which scopes its check to the bundle's inner body and leaves
# the wrapper to its own §3 shape rule -- the two artifacts are pinned
# differently on purpose and each is followed as written.
_SNAPSHOT_FIELDS = frozenset({"revocation_list", "signature"})
_BODY_FIELDS = frozenset({"version", "issuer", "published_at", "expires_at", "entries", "extensions"})
_ENTRY_FIELDS = frozenset({"jti", "revoked_at", "reason"})

# The schema's declared types, checked before anything dereferences them.
# `reject_unknown_fields` rejects members that are PRESENT and unrecognized; it
# says nothing about ones that are absent or of the wrong type, which is the
# other half of schema validation and a separate code (REVOCATION_SNAPSHOT_INVALID
# vs UNKNOWN_FIELD -- the registry: "When the only defect is an unknown member
# outside `extensions`, use `UNKNOWN_FIELD` instead").
_BODY_TYPES: dict[str, tuple[type, ...]] = {
    "version": (str,), "issuer": (str,), "published_at": (int,),
    "expires_at": (int,), "entries": (list,), "extensions": (dict,),
}
_ENTRY_TYPES: dict[str, tuple[type, ...]] = {"jti": (str,), "revoked_at": (int,), "reason": (str,)}
_REQUIRED_BODY_FIELDS = ("version", "issuer", "published_at", "expires_at", "entries")
_REQUIRED_ENTRY_FIELDS = ("jti", "revoked_at")

_INVALID = "REVOCATION_SNAPSHOT_INVALID"
_VERSION = "aitp/0.2"


def _typed(obj: dict[str, Any], types: dict[str, tuple[type, ...]], what: str) -> None:
    """Reject any present member whose value is not of its declared JSON type.

    ``bool`` is excluded from ``int`` deliberately: Python makes ``True`` an
    ``int``, JSON does not, and a timestamp of ``true`` is a schema defect. The
    same check is what stops ``json.loads("1e400")`` -- ordinary valid JSON
    that yields ``float("inf")`` -- from reaching ``int()`` and raising
    ``OverflowError`` out of the freshness comparison, which is neither a
    ``TypeError`` nor a ``ValueError``, so it defeats the obvious guard around
    the freshness arithmetic; rejecting the value as mistyped up here removes
    the arithmetic hazard entirely rather than enumerating exception types.
    """
    for key, allowed in types.items():
        if key not in obj:
            continue
        value = obj[key]
        if isinstance(value, bool) and bool not in allowed:
            raise AitpError(_INVALID, f"{what}.{key} is bool, not {allowed[0].__name__}")
        if int in allowed and isinstance(value, float) and value.is_integer():
            # JSON Schema `integer` admits `1711900000.0`, and JCS serializes
            # it to the same bytes as `1711900000` -- so the peer signed what
            # we would reconstruct, and rejecting it would be a false
            # rejection. `is_integer()` is False for inf and NaN, so this
            # widening does not readmit them.
            continue
        if not isinstance(value, allowed):
            raise AitpError(_INVALID, f"{what}.{key} is {type(value).__name__}, not {allowed[0].__name__}")


def _validate_shape(snapshot: Any) -> dict[str, Any]:
    """RFC-AITP-0008 §1.5 step 1: schema conformance, before any signature work.

    Runs to completion before the caller dereferences anything, so no malformed
    snapshot can reach a bare ``[...]`` index. It does not cover values nested
    inside ``extensions`` -- §7 forbids inspecting that interior -- so the one
    remaining hazard, a number JCS cannot serialize, is caught at the
    ``canonicalize`` call instead. Snapshots are fetched from the
    issuing peer's remote endpoint, so every branch here is attacker-reachable:
    before this existed the module raised raw ``TypeError``/``KeyError``/
    ``AttributeError``/``ValueError``/``OverflowError`` past its own
    ``except AitpError`` handler and took the caller down instead of returning
    a verdict.
    """
    if not isinstance(snapshot, dict):
        raise AitpError(_INVALID, f"revocation snapshot is {type(snapshot).__name__}, not an object")
    if missing := [k for k in ("revocation_list", "signature") if k not in snapshot]:
        raise AitpError(_INVALID, f"revocation snapshot is missing required member(s) {missing}")
    if not isinstance(snapshot["signature"], str):
        raise AitpError(_INVALID, f"revocation snapshot signature is {type(snapshot['signature']).__name__}, not a string")

    body = snapshot["revocation_list"]
    if not isinstance(body, dict):
        raise AitpError(_INVALID, f"revocation_list is {type(body).__name__}, not an object")
    if missing := [k for k in _REQUIRED_BODY_FIELDS if k not in body]:
        raise AitpError(_INVALID, f"revocation_list is missing required member(s) {missing}")
    _typed(body, _BODY_TYPES, "revocation_list")
    if body["version"] != _VERSION:
        # §1.5: "every value inside its grammar". The schema pins
        # `const: "aitp/0.2"`, and this is load-bearing rather than pedantic --
        # §1.5's migration note records that rc.3-era implementations signed
        # the WRAPPED form, so evaluating a body that declares an older version
        # under v0.2 signing rules is a version-confusion surface.
        raise AitpError(_INVALID, f"revocation_list version is {body['version']!r}, not {_VERSION!r}")

    for i, entry in enumerate(body["entries"]):
        if not isinstance(entry, dict):
            raise AitpError(_INVALID, f"revocation_list entries[{i}] is {type(entry).__name__}, not an object")
        if missing := [k for k in _REQUIRED_ENTRY_FIELDS if k not in entry]:
            raise AitpError(_INVALID, f"revocation_list entries[{i}] is missing required member(s) {missing}")
        _typed(entry, _ENTRY_TYPES, f"revocation_list entries[{i}]")
    return body


def verify_revocation_snapshot(inp: dict[str, Any], now: int | None = None) -> dict[str, Any]:
    policy = inp["policy"]
    now = int(inp["now"]) if now is None else now
    fail_mode = policy.get("fail_mode", "fail_closed")

    # 1. Structural validation (rev-007).
    body = _validate_shape(inp["snapshot"])
    snapshot = inp["snapshot"]

    # 2. Member-set validation (rev-005/006). Reached only once the snapshot is
    #    otherwise schema-valid, which is what makes UNKNOWN_FIELD mean "the
    #    unknown member is the ONLY defect", per the registry.
    reject_unknown_fields(snapshot, _SNAPSHOT_FIELDS, shape_code=_INVALID, what="revocation snapshot")
    reject_unknown_fields(body, _BODY_FIELDS, shape_code=_INVALID, what="revocation_list")
    for entry in body["entries"]:
        reject_unknown_fields(entry, _ENTRY_FIELDS, shape_code=_INVALID, what="revocation_list entry")

    # 3. Signature (rev-008). `parse_aid` signals a malformed AID with a bare
    #    ValueError, so an unparseable remote issuer would otherwise escape as
    #    a traceback rather than a verdict.
    try:
        issuer = parse_aid(body["issuer"])
    except ValueError as exc:
        raise AitpError(_INVALID, f"revocation_list issuer is not a valid AID: {exc}") from exc
    raw = decode_tagged_signature(snapshot["signature"], issuer, sig_err="REVOCATION_SNAPSHOT_SIGNATURE_INVALID")
    try:
        digest = sha256(canonicalize(body))
    except JcsError as exc:
        # `JcsError` subclasses ValueError, so it is NOT an AitpError and
        # escapes the caller's handler. `_typed` cannot prevent this on its
        # own: the offending value can sit anywhere inside `extensions`, whose
        # interior §7 forbids inspecting, and a plain `"published_at": 1` with
        # 400 zeros is a valid JSON integer of a magnitude JCS refuses to
        # serialize. Both arrive as ordinary valid JSON from an unauthenticated
        # endpoint, so this is caught at the one point every such value must
        # pass through.
        raise AitpError(_INVALID, f"revocation_list is not canonicalizable: {exc}") from exc
    if not issuer.public_key.verify_digest(digest, raw):
        raise AitpError("REVOCATION_SNAPSHOT_SIGNATURE_INVALID", "snapshot signature does not verify under the issuing peer's key")

    # 4. Absence semantics (rev-001/002). ONLY reached by a snapshot that was
    #    obtained and is trustworthy, so this is the one branch `fail_mode`
    #    answers: stale, or issued by someone other than the expected peer,
    #    both mean the peer has no usable revocation data.
    issuer_ok = body["issuer"] == inp.get("expected_issuer")
    fresh = (now - int(body["published_at"])) <= int(policy["max_staleness_secs"]) and now < int(body["expires_at"])
    if not (issuer_ok and fresh):
        if fail_mode == "soft_fail":
            return {"revoked": False, "stale": True}
        raise AitpError("TCT_REVOKED", "no fresh valid revocation snapshot (fail_closed)")

    queried = inp.get("queried_jti")
    if queried is not None and any(e.get("jti") == queried for e in body["entries"]):
        raise AitpError("TCT_REVOKED", "queried jti is on the deny list")
    return {"revoked": False}
