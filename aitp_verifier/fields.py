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
schema (e.g. the handshake ``IdentityDescriptor``) simply omits any such name
from *allowed*, and any attempt to smuggle unknown data in under a
same-named-but-unreserved key is rejected like any other unknown member.

**The code is not the caller's to choose.** §7's MUST has one core code,
``UNKNOWN_FIELD`` (registries/error-codes.md; not retryable), shared by every
signed AITP object rather than split into per-artifact variants — the failing
object is whichever one was being verified, exactly as for ``UNKNOWN_VERSION``.
Hard-coding it here, instead of threading it through each call site, is what
makes divergence between the twenty-six call sites impossible. Before the code
existed, this verifier raised each artifact's signature-family code instead
(``MANIFEST_SIGNATURE_INVALID``, ``TCT_SIGNATURE_INVALID``, …); that was a
stopgap, and upstream issue #37 — filed because enforcing §7 here left the
whole conformance pack green, proving nothing tested the rule — is what closed
the gap.

The single exception is remapped at its call site, not here:
``sessionbundle.py``'s embedded participant TCT, where RFC-AITP-0010 §5 step 7
collapses "other TCT-level failures" into ``BUNDLE_PARTICIPANT_TCT_INVALID``.
That is a containment rule specific to the bundle, so it is applied visibly
where it applies rather than by reopening the code as a parameter.

*shape_code* survives for a genuinely different failure: *obj* not being an
object at all. A scalar where the schema requires an object carries no member,
so it is not an unknown-field defect and keeps the artifact's own structural
code. Note that most call sites cannot actually reach it — ``jws.py`` already
guarantees a dict for every compact-JWS claims object, and several JCS sites
are pre-guarded by an explicit ``isinstance`` — so it is observable at roughly
a third of them. It is kept for those, and because the alternative at an
unguarded site is a raw ``TypeError`` escaping an ``except AitpError`` caller.
"""

from __future__ import annotations

from typing import Any, Container

from .errors import AitpError

__all__ = ["reject_unknown_fields"]


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
        # raw TypeError from `for k in obj` -- and callers that fold shape
        # failures into a boolean (revocation.py's `except AitpError: sig_ok =
        # False`) catch AitpError only, so a TypeError escapes the verifier
        # entirely and turns a fail-closed path into a crash. A non-object
        # where the schema requires one is a shape defect like any other --
        # and NOT an unknown-field one: nothing was carried, so this keeps the
        # caller's structural code rather than UNKNOWN_FIELD.
        raise AitpError(shape_code, f"{what} is {type(obj).__name__}, not an object")
    extra = sorted((k for k in obj if k not in allowed), key=repr)
    if extra:
        raise AitpError("UNKNOWN_FIELD", f"{what} carries unrecognized field(s): {extra}")
