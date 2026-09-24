"""Unknown-field rejection (RFC-AITP-0001 §7).

    "Unknown JSON fields outside explicit `extensions` namespaces MUST be
    rejected. Signed AITP objects depend on canonical JCS representation;
    silently ignoring unknown fields would create signature ambiguity across
    implementations ... Forward compatibility is provided exclusively through
    explicit `extensions` objects (see RFC-AITP-0012) ... unknown keys
    *inside* `extensions` MUST be ignored."

Every artifact schema under ``schemas/json/`` is ``additionalProperties:
false``. This module is the one place that rule is enforced, rather than a
duplicated ``set(obj) - allowed`` check inlined at each artifact's verifier.

The asymmetry is the entire point: a member NAME outside the allowed set is
rejected, but the CONTENTS of the reserved extension member (``extensions``
on JCS-signed payloads, ``ext`` on compact-JWS claims objects, per
RFC-AITP-0012 §1.1) are never inspected here, or anywhere else in this
verifier. ``reject_unknown_fields`` only ever looks at *obj*'s own top-level
key set; the caller includes its extension-member name (if the schema
reserves one) in *allowed*, and this function does not recurse into it. That
is sufficient and correct: an object with no extension slot at all in its
schema simply omits any such name from *allowed*, and any attempt to smuggle
unknown data in under a same-named-but-unreserved key is rejected like any
other unknown member. (Every artifact currently reserves one. The handshake
``IdentityDescriptor`` was the lone exception until spec PR #42 unified it
with the standalone identity schema — see ``identity.py``.)

**The code is not the caller's to choose.** §7's MUST has one core code,
``UNKNOWN_FIELD`` (registries/error-codes.md; not retryable), shared by every
signed AITP object rather than split into per-artifact variants — the failing
object is whichever one was being verified, exactly as for ``UNKNOWN_VERSION``.
Hard-coding it here, instead of threading it through each call site, is what
makes divergence between the twenty-four call sites impossible. Before the code
existed, this verifier raised each artifact's signature-family code instead
(``MANIFEST_SIGNATURE_INVALID``, ``TCT_SIGNATURE_INVALID``, …); that was a
stopgap, and upstream issue #37 — filed because enforcing §7 here left the
whole conformance pack green, proving nothing tested the rule — is what closed
the gap.

This module also carries three narrower boundary-conversion helpers used
alongside ``reject_unknown_fields``: ``require_members`` (required-member
presence), ``check_types`` (declared-JSON-type checking for present members),
and ``canonical_bytes``/``decode_b64url`` (converting the non-``AitpError``
exceptions ``canonicalize``/``b64url_decode`` raise into the caller's own
structural code). None of the four decides *when*, or in what order relative
to each other, a caller runs them -- each artifact module owns that ordering
itself, since it is not the same across modules (see ``manifest.py`` vs.
``revocation.py`` for two deliberately different orderings).

The single exception is remapped at its call site, not here:
``sessionbundle.py``'s embedded participant TCT, where RFC-AITP-0010 §5 step 7
collapses "other TCT-level failures" into ``BUNDLE_PARTICIPANT_TCT_INVALID``.
That is a containment rule specific to the bundle, so it is applied visibly
where it applies rather than by reopening the code as a parameter.

*shape_code* survives for a genuinely different failure: *obj* not being an
object at all. A scalar where the schema requires an object carries no member,
so it is not an unknown-field defect and keeps the artifact's own structural
code. Note that most call sites cannot actually reach it: ``jws.py`` already
guarantees a dict for every compact-JWS claims object (14 sites), and
``manifest.py``, ``revocation.py`` and ``sessionbundle.py`` now validate shape
explicitly before calling in (6 more). Only ``envelope.py``'s two and
``handshake.py``'s two payload checks can still observe it. It is kept for
those — and as a standing guarantee, since the alternative at any future
unguarded site is a raw ``TypeError`` escaping an ``except AitpError`` caller
rather than a verdict.
"""

from __future__ import annotations

from typing import Any, Container

from .b64 import b64url_decode
from .errors import AitpError
from .jcs import JcsError, canonicalize

__all__ = ["reject_unknown_fields", "require_members", "check_types", "canonical_bytes", "decode_b64url"]


def reject_unknown_fields(obj: dict[Any, Any], allowed: Container[str], *, shape_code: str, what: str) -> None:
    """Raise ``AitpError("UNKNOWN_FIELD")`` if *obj* carries a member outside *allowed*.

    *allowed* MUST include *obj*'s reserved extension-member name (if any) --
    this function never recurses into it, so listing it here is what makes
    unknown keys *inside* extensions permitted while unknown keys *beside* it
    are not. ``key=repr`` handles a caller feeding a raw (non-JSON-parsed)
    dict with non-``str`` keys, which a bare ``sorted()`` cannot compare.

    *shape_code* is used only when *obj* is not an object at all; the
    unknown-member case always raises the core ``UNKNOWN_FIELD``.
    """
    if not isinstance(obj, dict):
        # Guarding here, not at each call site, because the alternative is a
        # raw TypeError from `for k in obj`. Every caller is a verifier entry
        # point whose contract is "AitpError or a verdict", and the objects
        # reaching it come off the wire, so a TypeError escapes past whatever
        # `except AitpError` the caller wrote and crashes it instead of
        # producing a verdict. `revocation.py` is what forced this: it fed
        # remotely-fetched snapshot bodies straight in. A non-object
        # where the schema requires one is a shape defect like any other --
        # and NOT an unknown-field one: nothing was carried, so this keeps the
        # caller's structural code rather than UNKNOWN_FIELD.
        raise AitpError(shape_code, f"{what} is {type(obj).__name__}, not an object")
    extra = sorted((k for k in obj if k not in allowed), key=repr)
    if extra:
        raise AitpError("UNKNOWN_FIELD", f"{what} carries unrecognized field(s): {extra}")


def require_members(obj: dict[str, Any], required: tuple[str, ...], *, shape_code: str, what: str) -> None:
    """Raise if any of *required* is missing from *obj*.

    Presence only -- says nothing about the type of what's present (see
    ``check_types``) or about members outside *required* (see
    ``reject_unknown_fields``). The caller decides when, and in what order
    relative to those two, this runs.
    """
    if missing := [k for k in required if k not in obj]:
        raise AitpError(shape_code, f"{what} is missing required member(s) {missing}")


def check_types(obj: dict[str, Any], types: dict[str, tuple[type, ...]], *, shape_code: str, what: str) -> None:
    """Reject any PRESENT member of *obj* whose value is not of its declared JSON type.

    ``bool`` is excluded from ``int`` deliberately: Python makes ``True`` an
    ``int``, JSON does not. An integral float IS a valid JSON ``integer`` and
    JCS-canonicalizes to the same bytes as the int form, so it is admitted
    wherever ``int`` is allowed -- a peer that signed ``1711900000.0`` signed
    what we would reconstruct, and rejecting it would be a false rejection.

    Says nothing about presence (see ``require_members``) or about members
    outside *types* (see ``reject_unknown_fields``) -- deliberately: the
    caller decides when, and in what order relative to those two, this runs.
    """
    for key, allowed in types.items():
        if key not in obj:
            continue
        value = obj[key]
        if isinstance(value, bool) and bool not in allowed:
            raise AitpError(shape_code, f"{what}.{key} is bool, not {allowed[0].__name__}")
        if int in allowed and isinstance(value, float) and value.is_integer():
            continue
        if not isinstance(value, allowed):
            raise AitpError(shape_code, f"{what}.{key} is {type(value).__name__}, not {allowed[0].__name__}")


def canonical_bytes(value: Any, *, shape_code: str, what: str) -> bytes:
    """JCS-canonicalize *value*, converting ``JcsError`` to *shape_code*.

    ``JcsError`` subclasses ``ValueError``, not ``AitpError``, so it escapes a
    caller's ``except AitpError`` handler unless converted. The offending
    value can sit anywhere inside an ``extensions`` member, whose interior
    RFC-AITP-0001 §7 forbids inspecting, so no upstream ``check_types`` call
    can intercept it -- this is the one point every such value must pass
    through.

    ``RecursionError`` is converted too, as defense in depth behind
    ``jcs.py``'s own depth cap: the cap bounds this walk's frames, but a
    caller whose stack was already near-exhausted when it called in can still
    exhaust it inside a walk the cap would have admitted. ``RecursionError``
    subclasses ``RuntimeError``, not ``ValueError``, so the two clauses are
    disjoint and their order is immaterial. Its message is a constant literal
    with no interpolation on purpose: formatting a message while the stack is
    exhausted can itself re-trigger the error, and this recovery path must not
    be fragile.
    """
    try:
        return canonicalize(value)
    except JcsError as exc:
        raise AitpError(shape_code, f"{what} is not canonicalizable: {exc}") from exc
    except RecursionError as exc:
        raise AitpError(shape_code, "value is too deeply nested to canonicalize") from exc


def decode_b64url(text: str, *, code: str, what: str) -> bytes:
    """Decode unpadded base64url, converting the decoder's ``ValueError`` to *code*.

    ``binascii.Error`` (raised on invalid alphabet/padding) subclasses
    ``ValueError``, so both grammar defects are caught by the same handler.
    """
    try:
        return b64url_decode(text)
    except ValueError as exc:
        raise AitpError(code, f"{what} is not valid base64url: {exc}") from exc
