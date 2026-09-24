"""Unit tests for the boundary-conversion helpers in `fields.py`.

`require_members`, `check_types`, `canonical_bytes`, and `decode_b64url` are
exercised directly here, independent of any artifact module -- the module
docstring in `fields.py` and each helper's own docstring state what it does
and, just as importantly, what it deliberately does not decide (member-set
ordering stays each caller's own choice). `test_unknown_fields.py` and
`test_signed_examples.py` cover the same code paths end-to-end through
`verify_manifest`/`verify_revocation_snapshot`/etc.; these tests exist so a
regression in the shared helper itself fails here, close to the cause,
instead of surfacing as a mystery in one artifact module's suite.
"""

from __future__ import annotations

from typing import Any

import pytest

from aitp_verifier import fields
from aitp_verifier.b64 import b64url_encode
from aitp_verifier.errors import AitpError
from aitp_verifier.fields import canonical_bytes, check_types, decode_b64url, require_members
from aitp_verifier.jcs import _MAX_DEPTH, JcsError, canonicalize


def _deep_dict(n: int, leaf: Any = 1) -> Any:
    """*n* nested ``dict`` levels around a scalar leaf: ``_deep_dict(1)`` is
    ``{"a": 1}``, ``_deep_dict(2)`` is ``{"a": {"a": 1}}``, and so on.

    Counting convention, which the depth tests below pin against: the
    top-level ``jcs._serialize`` call runs at ``depth == 0`` and each nested
    value one deeper, so the leaf of ``_deep_dict(n)`` -- passed **unwrapped**
    to ``canonicalize``/``canonical_bytes`` -- is serialized at ``depth == n``.
    The guard raises on ``depth > _MAX_DEPTH``, so ``n == _MAX_DEPTH`` is the
    deepest value that still canonicalizes and ``n == _MAX_DEPTH + 1`` is the
    first that does not. Wrapping the value in anything shifts that by one,
    which is exactly why the convention is spelled out rather than left to
    "a 256-deep dict".
    """
    value: Any = leaf
    for _ in range(n):
        value = {"a": value}
    return value


def _deep_list(n: int, leaf: Any = 1) -> Any:
    """*n* nested ``list`` levels around a scalar leaf: ``_deep_list(1)`` is
    ``[1]``, ``_deep_list(2)`` is ``[[1]]``, and so on.

    The list twin of ``_deep_dict``, with the identical counting convention:
    the top-level ``jcs._serialize`` call runs at ``depth == 0`` and each
    nested element one deeper, so the leaf of ``_deep_list(n)`` -- passed
    **unwrapped** -- is serialized at ``depth == n``, ``n == _MAX_DEPTH`` is
    the deepest that still canonicalizes, and ``n == _MAX_DEPTH + 1`` is the
    first rejected.

    This exists because ``jcs._serialize`` has **two** recursion sites, one per
    container type, and they are guarded independently: every other nesting
    test in this repo builds dicts, so the list-element site (``_serialize(
    item, out, depth + 1)``) had no coverage at all -- a regression that
    dropped its ``depth + 1`` left the whole suite green while fully reopening
    issue #31 for list-nested values.
    """
    value: Any = leaf
    for _ in range(n):
        value = [value]
    return value

# ── require_members ─────────────────────────────────────────────────────


def test_require_members_passes_when_all_present() -> None:
    require_members({"a": 1, "b": 2, "c": 3}, ("a", "b"), shape_code="X", what="obj")  # no raise


def test_require_members_rejects_missing() -> None:
    with pytest.raises(AitpError) as exc:
        require_members({"a": 1}, ("a", "b", "c"), shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"
    assert "b" in exc.value.message and "c" in exc.value.message


def test_require_members_says_nothing_about_type() -> None:
    """Presence only -- a present-but-wrong-typed value is `check_types`'s concern, not this one's."""
    require_members({"a": "not-an-int"}, ("a",), shape_code="X", what="obj")  # no raise


# ── check_types ──────────────────────────────────────────────────────────


def test_check_types_passes_for_correct_types() -> None:
    check_types({"a": 1, "b": "s"}, {"a": (int,), "b": (str,)}, shape_code="X", what="obj")  # no raise


def test_check_types_ignores_absent_members() -> None:
    """Says nothing about presence -- that's `require_members`'s concern."""
    check_types({}, {"a": (int,)}, shape_code="X", what="obj")  # no raise


def test_check_types_rejects_wrong_type() -> None:
    with pytest.raises(AitpError) as exc:
        check_types({"a": "not-an-int"}, {"a": (int,)}, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"
    assert "a" in exc.value.message


def test_check_types_excludes_bool_from_int() -> None:
    """Python makes ``True`` an ``int``; JSON does not."""
    with pytest.raises(AitpError) as exc:
        check_types({"a": True}, {"a": (int,)}, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


def test_check_types_bool_admitted_when_declared() -> None:
    check_types({"a": True}, {"a": (bool,)}, shape_code="X", what="obj")  # no raise


def test_check_types_admits_integral_float_for_int() -> None:
    """A JSON `integer` may arrive as a Python float (`5.0`); JCS canonicalizes
    it to the same bytes as the int form, so a peer that signed the float
    signed what we would reconstruct -- rejecting it would be a false
    rejection."""
    check_types({"a": 5.0}, {"a": (int,)}, shape_code="X", what="obj")  # no raise


def test_check_types_rejects_non_integral_float_for_int() -> None:
    with pytest.raises(AitpError) as exc:
        check_types({"a": 5.5}, {"a": (int,)}, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


def test_check_types_rejects_infinite_float_for_int() -> None:
    """`is_integer()` is False for inf and NaN, so the float-widening above
    does not readmit them."""
    with pytest.raises(AitpError) as exc:
        check_types({"a": float("inf")}, {"a": (int,)}, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


# ── canonical_bytes ──────────────────────────────────────────────────────


def test_canonical_bytes_returns_jcs_bytes_for_valid_input() -> None:
    assert canonical_bytes({"a": 1}, shape_code="X", what="obj") == b'{"a":1}'


def test_canonical_bytes_converts_jcserror_to_aitperror() -> None:
    """`float('inf')` cannot be canonicalized -- JCS has no representation for
    a non-finite number."""
    with pytest.raises(AitpError) as exc:
        canonical_bytes({"a": float("inf")}, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


def test_canonical_bytes_rejects_huge_int() -> None:
    """A 400-digit integer is valid JSON but outside JCS's representable
    range -- reachable from ordinary remote input, not a crafted edge case."""
    with pytest.raises(AitpError) as exc:
        canonical_bytes({"a": 10**400}, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


# ── nesting depth (issue #31) ────────────────────────────────────────────


def test_canonical_bytes_rejects_excessive_nesting() -> None:
    """The attacker-realistic shape: the deep value sits inside `extensions`,
    whose interior RFC-AITP-0001 §7 forbids inspecting, so no upstream
    `check_types` can intercept it -- `canonicalize` is the only place it can
    be caught, and before the depth cap it escaped as a raw `RecursionError`
    past every caller's `except AitpError`.
    """
    with pytest.raises(AitpError) as exc:
        canonical_bytes({"extensions": _deep_dict(300)}, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


def test_canonical_bytes_accepts_nesting_at_the_cap() -> None:
    """`_deep_dict(_MAX_DEPTH)` unwrapped puts its leaf at exactly `depth ==
    _MAX_DEPTH`, the deepest the guard admits (see `_deep_dict`'s docstring
    for the counting convention). Pinned one level apart from the rejection
    test below so the boundary is exact, not approximate.
    """
    assert _MAX_DEPTH == 256
    out = canonical_bytes(_deep_dict(_MAX_DEPTH), shape_code="X", what="obj")
    # Confirms the helper nests as its docstring claims, so the two boundary
    # numbers mean what the test names say they mean.
    assert out.count(b"{") == 256
    assert out.endswith(b"1" + b"}" * 256)


def test_canonical_bytes_rejects_nesting_one_past_the_cap() -> None:
    """One level deeper than the test above -- `_MAX_DEPTH + 1` == 257 -- is
    the first depth rejected."""
    assert _MAX_DEPTH + 1 == 257
    with pytest.raises(AitpError) as exc:
        canonical_bytes(_deep_dict(_MAX_DEPTH + 1), shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


def test_canonicalize_raises_jcserror_not_recursionerror() -> None:
    """The `jcs` layer's own contract, asserted directly: the cap raises this
    library's error type, not the interpreter's. `pytest.raises(JcsError)`
    cannot absorb a `RecursionError` (`JcsError` subclasses `ValueError`,
    `RecursionError` subclasses `RuntimeError`), so a regressed cap fails this
    test rather than passing it. 2000 is well past the interpreter's own
    ceiling from this call site, which is what makes it the real proof.
    """
    with pytest.raises(JcsError):
        canonicalize(_deep_dict(_MAX_DEPTH + 1))
    with pytest.raises(JcsError):
        canonicalize(_deep_dict(2000))


def test_canonical_bytes_accepts_list_nesting_at_the_cap() -> None:
    """The same boundary on the **list**-element recursion site, which is a
    separate guarded call from the dict-member one above.

    `_deep_list(_MAX_DEPTH)` unwrapped puts its leaf at exactly `depth ==
    _MAX_DEPTH`, the deepest the guard admits (see `_deep_list`'s docstring for
    the counting convention, which is identical to `_deep_dict`'s). Pinned one
    level apart from the rejection test below so the boundary is exact.
    """
    assert _MAX_DEPTH == 256
    out = canonical_bytes(_deep_list(_MAX_DEPTH), shape_code="X", what="obj")
    # Byte-exact, which also confirms the helper nests as its docstring claims:
    # the two boundary numbers mean what the test names say they mean.
    assert out == b"[" * 256 + b"1" + b"]" * 256


def test_canonical_bytes_rejects_list_nesting_one_past_the_cap() -> None:
    """One level deeper than the test above -- `_MAX_DEPTH + 1` == 257 nested
    lists -- is the first list depth rejected. This is the test that catches a
    regression on the list-element recursion site specifically: without its
    `depth + 1`, `depth` never advances through a list chain and nothing is
    ever rejected.
    """
    assert _MAX_DEPTH + 1 == 257
    with pytest.raises(AitpError) as exc:
        canonical_bytes(_deep_list(_MAX_DEPTH + 1), shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


def test_canonicalize_list_nesting_raises_jcserror_not_recursionerror() -> None:
    """The `jcs`-layer contract for list nesting, asserted directly and past
    the interpreter's own ceiling.

    Necessary in addition to the `canonical_bytes` pair above: at 2000 deep an
    unguarded list site raises a genuine `RecursionError`, which
    `canonical_bytes` would dutifully convert into the same `AitpError` a
    working cap produces -- so only the `jcs` layer can tell the two apart.
    `pytest.raises(JcsError)` cannot absorb a `RecursionError` (`JcsError`
    subclasses `ValueError`, `RecursionError` subclasses `RuntimeError`).
    """
    with pytest.raises(JcsError):
        canonicalize(_deep_list(_MAX_DEPTH + 1))
    with pytest.raises(JcsError):
        canonicalize(_deep_list(2000))


def test_canonicalize_counts_alternating_dict_and_list_levels_together() -> None:
    """Depth accumulates across container *kinds*: one walk, one counter.

    The pair count is chosen so the test fails if **either** recursion site
    stops advancing `depth`. `(_MAX_DEPTH // 2) + 1` == 129 pairs of
    `{"a": [ ... ]}` nests 258 levels -- past the cap, so a correct
    serializer rejects it -- but only 129 of them are dicts and 129 are lists,
    so a serializer counting just one kind reaches 129, stays under the cap,
    and accepts. (The single-kind tests above are still the precise ones: this
    one only proves the two sites share a counter.)
    """
    pairs = (_MAX_DEPTH // 2) + 1
    assert pairs <= _MAX_DEPTH < 2 * pairs
    value: Any = 1
    for _ in range(pairs):
        value = {"a": [value]}
    with pytest.raises(JcsError):
        canonicalize(value)


def test_canonical_bytes_converts_recursionerror_to_aitperror(monkeypatch: pytest.MonkeyPatch) -> None:
    """Defense in depth behind the cap: a `RecursionError` raised by
    `canonicalize` anyway -- because the *caller's* own stack was already near
    exhaustion on entry, which the relative cap cannot see -- still becomes an
    `AitpError` carrying the caller's shape code. Patched on the name
    `fields.py` imports directly, since that is the binding the call site
    resolves. The message is asserted to be the constant literal: interpolating
    one while the stack is exhausted can re-trigger the error.
    """
    def _boom(value: object) -> bytes:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(fields, "canonicalize", _boom)
    with pytest.raises(AitpError) as exc:
        canonical_bytes({"a": 1}, shape_code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"
    assert exc.value.message == "value is too deeply nested to canonicalize"


# ── decode_b64url ────────────────────────────────────────────────────────


def test_decode_b64url_decodes_valid_input() -> None:
    raw = b"hello world"
    assert decode_b64url(b64url_encode(raw), code="X", what="obj") == raw


def test_decode_b64url_rejects_bad_alphabet() -> None:
    with pytest.raises(AitpError) as exc:
        decode_b64url("a:b", code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"


def test_decode_b64url_rejects_bad_length() -> None:
    """`binascii.Error` (raised for a length that isn't a valid base64url
    length) subclasses `ValueError`, so it must be caught by the same guard
    as an alphabet defect."""
    with pytest.raises(AitpError) as exc:
        decode_b64url("x", code="MY_CODE", what="obj")
    assert exc.value.code == "MY_CODE"
