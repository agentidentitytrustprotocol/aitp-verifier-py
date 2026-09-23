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

import pytest

from aitp_verifier.b64 import b64url_encode
from aitp_verifier.errors import AitpError
from aitp_verifier.fields import canonical_bytes, check_types, decode_b64url, require_members

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
