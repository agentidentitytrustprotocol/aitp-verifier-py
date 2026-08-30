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
"""

from __future__ import annotations

from typing import Any, Container

from .errors import AitpError

__all__ = ["reject_unknown_fields"]


def reject_unknown_fields(obj: dict[Any, Any], allowed: Container[str], *, code: str, what: str) -> None:
    """Raise ``AitpError(code)`` if *obj* carries a member outside *allowed*.

    *allowed* MUST include *obj*'s reserved extension-member name (if any) --
    this function never recurses into it, so listing it here is what makes
    unknown keys *inside* extensions permitted while unknown keys *beside* it
    are not. ``key=repr`` handles a caller feeding a raw (non-JSON-parsed)
    dict with non-``str`` keys, which a bare ``sorted()`` cannot compare.
    """
    if not isinstance(obj, dict):
        # Guarding here, not at each call site, because the alternative is a
        # raw TypeError from `for k in obj` -- and callers that fold shape
        # failures into a boolean (revocation.py's `except AitpError: sig_ok =
        # False`) catch AitpError only, so a TypeError escapes the verifier
        # entirely and turns a fail-closed path into a crash. A non-object
        # where the schema requires one is a shape defect like any other.
        raise AitpError(code, f"{what} is {type(obj).__name__}, not an object")
    extra = sorted((k for k in obj if k not in allowed), key=repr)
    if extra:
        raise AitpError(code, f"{what} carries unrecognized field(s): {extra}")
