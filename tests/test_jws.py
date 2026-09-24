"""`jws.py`'s JWS-header error messages must never render an unvalidated container.

Issue #31's hazard, at the two sites in `verify_jws` that compare a protected
header member against an expected value. The header gate immediately above
them checks the member SET only -- `set(header) == {"alg", "typ"}` -- and
nothing upstream type-checks either VALUE, so both `typ` and `alg` reach their
comparison as arbitrary JSON straight off the wire, a deeply nested container
included. Before this fix both messages interpolated them with `{x!r}`.

`repr()` recurses once per nesting level and has no depth cap of its own, so
what it costs is bounded only by the interpreter's C-stack budget. That budget
is NOT the same one the JSON parser spends getting the value there, and the
gap between the two is where this bites. Measured on this repo's four CI
interpreters, for a `typ` nested as one-member objects:

    3.11   parser ceiling   ~991   repr ceiling   ~990    window: 1 level
    3.12   parser ceiling  ~9995   repr ceiling  ~9995    window: none
    3.13   parser ceiling  ~9996   repr ceiling  ~9996    window: none
    3.14   parser ceiling ~116214  repr ceiling ~69730    window: ~46500 levels

On 3.14 -- default stack, default recursion limit, a plain token string -- a
`typ` anywhere in that window parses cleanly and then makes `repr()` raise a
bare `RecursionError` *before* the `AitpError` the message was being built for
exists. That is the same contract break (`AitpError` or a verdict, never a raw
Python exception) that `jcs.py`'s depth cap closes for canonicalization,
reached by a path that never calls `canonicalize`, so no cap there can see it.
Verified end-to-end on 3.14.6: pre-fix, `verify_tct` on a `typ` at the parser
ceiling raises `RecursionError` from `jws.py`'s own line; post-fix it returns
`TOKEN_TYP_MISMATCH` with a 28-character message. The same crash reaches
3.11-3.13 wherever the stack is smaller than the default -- on a 1 MiB thread
stack (`threading.stack_size`), pre-fix 3.13 takes SIGBUS on a depth-5000
`typ` at a depth its parser handles fine, where post-fix it returns the same
28-character verdict.

Where the stack is not the binding limit the second half of the exposure
remains: the rejected value's own `repr` goes verbatim into the caller's logs.
Measured pre-fix at each parser ceiling, that is a ~7 KB message on 3.11 and
~68 KB on 3.12/3.13; on 3.14, ~472 KB at the deepest `typ` that still renders
at all. All from one token, all attacker-chosen. `describe_value` closes both
halves at once by making a rejection's cost independent of what was rejected,
which is why the assertions below pin the message's SIZE and TYPE-only content
rather than only the absence of a crash.

Every test here builds its token by hand rather than minting one: both sites
are checked ahead of signature verification (RFC-AITP-0001 §5.4.5 order), so
no key material is needed and the module stays runnable under `AITP_SPEC=none`.
"""

from __future__ import annotations

import json
from typing import Any, Callable

import pytest

from aitp_verifier.b64 import b64url_encode
from aitp_verifier.errors import AitpError
from aitp_verifier.jcs import loads
from aitp_verifier.tct import verify_tct
from aitp_verifier.voucher import verify_grant_voucher

# Pinned KAT AID (schemas/conformance/known-answer/keypairs.json,
# kat-keypair-001), reused as a *syntactically* valid issuer AID only: it is
# parsed for its pinned algorithm, never used to verify anything here.
ISSUER = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"

_LEAF = "deep-leaf-sentinel"

# Deep enough to be unambiguous (measured: a 6342-byte message pre-fix, 28
# post-fix) and shallow enough to clear the *lowest* parser ceiling in the
# table above -- 3.11's ~991 -- so it behaves identically on all four. This is
# the CI-realistic case: it fails pre-fix everywhere, on assertions about the
# message rather than about a crash, because on three of the four interpreters
# no crash is available at any depth the parser will admit.
_PORTABLE_DEPTH = 900

# Slack between the depth `_deepest_admissible_depth` measures and the depth a
# test actually sends. The two `loads` calls sit at different stack positions
# -- the measuring one under `parses`, the real one under `verify_* ->
# parse_compact -> loads` -- so the end-to-end ceiling is a few levels below
# the measured one. Measured at 1 level on 3.13; 32 is slack, not a tuned
# value, and is negligible against every ceiling in the table.
_FRAME_SLACK = 32


def _deep_object_json(depth: int) -> str:
    """JSON text for *depth* nested one-member objects around `_LEAF`."""
    return '{"a":' * depth + json.dumps(_LEAF) + "}" * depth


def _deepest_admissible_depth() -> int:
    """The deepest nesting this interpreter's JSON parser will hand `verify_jws`.

    Derived, not pinned: the ceiling is a property of the build's C-stack
    budget and moves by two orders of magnitude across the supported
    interpreters (see the module docstring), so a hard-coded depth would either
    fail to parse on 3.11 or sit far below the interesting region on 3.14.

    Defined purely in terms of the PARSER, deliberately. Defining it in terms
    of "the deepest value `verify_tct` still turns into a verdict" would be
    self-defeating: pre-fix that search converges just below the window where
    `repr()` blows up, and the test it feeds would pass against the bug it
    exists to catch.

    Called from inside each test rather than at import so the stack position it
    measures from matches the one the test then calls `verify_*` at.
    """

    def parses(depth: int) -> bool:
        try:
            loads(_deep_object_json(depth))
        except RecursionError:
            return False
        return True

    lo, hi = 64, 128  # 64 parses on every interpreter this package supports
    while hi < 2**20 and parses(hi):
        lo, hi = hi, hi * 2
    while lo < hi:
        mid = (lo + hi + 1) // 2
        lo, hi = (mid, hi) if parses(mid) else (lo, mid - 1)
    return lo


def _token(header_json: str, claims: dict[str, Any] | None = None) -> str:
    """A compact JWS with *header_json* used verbatim as the protected header.

    The signature segment is filler: every assertion here concerns a check that
    runs strictly before signature verification.
    """
    payload = json.dumps({"iss": ISSUER} if claims is None else claims, separators=(",", ":"))
    return ".".join(
        (
            b64url_encode(header_json.encode()),
            b64url_encode(payload.encode()),
            b64url_encode(b"filler-signature"),
        )
    )


def _assert_bounded_type_only(exc: AitpError, expected_code: str) -> None:
    """The post-fix contract for a container-valued header member."""
    assert exc.code == expected_code
    assert "<dict>" in exc.message, "the rejected value must be named by TYPE"
    assert _LEAF not in exc.message, "the rejected value's CONTENTS must never be rendered"
    assert len(exc.message) < 200, f"message cost must be bounded, got {len(exc.message)} chars"


# ── `typ`: reachable through two public entry points, no key material ───────


@pytest.mark.parametrize("depth_of", ["portable", "deepest-this-interpreter-admits"])
def test_deeply_nested_typ_is_a_verdict_not_a_recursionerror(depth_of: str) -> None:
    """`verify_tct` with a container at the header's `typ`.

    Two depths, for the reason the module docstring gives. The portable one
    fails pre-fix on every interpreter, but on the message assertions only. The
    derived one is the case the fix actually exists for: on 3.14 it lands in
    the window where the parser succeeds and `repr()` does not, so pre-fix a
    bare `RecursionError` escapes `verify_tct` entirely.
    """
    depth = _PORTABLE_DEPTH if depth_of == "portable" else _deepest_admissible_depth() - _FRAME_SLACK
    token = _token('{"alg":"EdDSA","typ":' + _deep_object_json(depth) + "}")
    with pytest.raises(AitpError) as exc_info:
        verify_tct({"tct_token": token})
    _assert_bounded_type_only(exc_info.value, "TOKEN_TYP_MISMATCH")


def test_deeply_nested_typ_via_grant_voucher() -> None:
    """The same defect through a second public entry point, confirming this is
    `jws.py`'s shared gate and not something `tct.py` happens to reach.
    `verify_grant_voucher` passes no `after_typ_check`, so it reaches the `typ`
    comparison on a claims object that `verify_tct` would have rejected first
    -- different surrounding code, identical exposure."""
    token = _token('{"alg":"EdDSA","typ":' + _deep_object_json(_PORTABLE_DEPTH) + "}")
    with pytest.raises(AitpError) as exc_info:
        verify_grant_voucher({"voucher_token": token})
    _assert_bounded_type_only(exc_info.value, "TOKEN_TYP_MISMATCH")


# ── `alg`: the second site, reached only once `typ` already matched ─────────


_TCT_CLAIMS: dict[str, Any] = {
    "ver": "aitp/0.2",
    "jti": "6f1f0e4e-2b1a-4a44-9f7f-0c4a4d3a3f11",
    "iss": ISSUER,
    "sub": ISSUER,
    "aud": ISSUER,
    "iat": 1,
    "exp": 2,
    "grants": ["macp.mode.task.v1"],
    "cnf": {"jkt": "x" * 43},
}


@pytest.mark.parametrize(
    "entry, key, typ, claims",
    [
        (verify_grant_voucher, "voucher_token", "aitp-grant+jwt", None),
        (verify_tct, "tct_token", "aitp-tct+jwt", _TCT_CLAIMS),
    ],
    ids=["voucher", "tct"],
)
def test_deeply_nested_alg_is_a_verdict_not_a_recursionerror(
    entry: Callable[[dict[str, Any]], dict[str, Any]],
    key: str,
    typ: str,
    claims: dict[str, Any] | None,
) -> None:
    """A container at the header's `alg`, past a matching `typ`.

    The AID-pinned `alg` comparison is the other unguarded interpolation. It is
    a narrower reach than `typ` -- the token must carry the right `typ` and, for
    `verify_tct`, claims that also survive the `after_typ_check` hook running
    between the two -- but it is reached the same way and was rendered the same
    way. Hence the full, structurally valid TCT claims set; none of it is
    signed, because `alg` is pinned and compared before any signature check.
    """
    header = '{"alg":' + _deep_object_json(_PORTABLE_DEPTH) + ',"typ":' + json.dumps(typ) + "}"
    with pytest.raises(AitpError) as exc_info:
        entry({key: _token(header, claims)})
    _assert_bounded_type_only(exc_info.value, "TOKEN_ALG_MISMATCH")


# ── the properties the fix is FOR, pinned directly ─────────────────────────


def test_rejection_cost_is_independent_of_the_rejected_value() -> None:
    """A rejection's message length must not track the input's size.

    This is the half of the exposure that survives on interpreters where the
    stack never runs out: pre-fix these two messages were 49 and 6342 bytes on
    every supported interpreter, and the gap widens to hundreds of kilobytes at
    each one's parser ceiling -- every byte of it attacker-chosen and bound for
    the caller's logs. Asserting equality (not just a cap) is what makes any
    reintroduction of `{x!r}` -- at any depth, on any interpreter -- fail here.
    """
    lengths = set()
    for depth in (1, _PORTABLE_DEPTH):
        token = _token('{"alg":"EdDSA","typ":' + _deep_object_json(depth) + "}")
        with pytest.raises(AitpError) as exc_info:
            verify_tct({"tct_token": token})
        lengths.add(len(exc_info.value.message))
    assert len(lengths) == 1, f"message length tracks the rejected value: {sorted(lengths)}"


@pytest.mark.parametrize(
    "header, expected_code",
    [
        ('{"alg":"EdDSA","typ":"wrong-and-scalar"}', "TOKEN_TYP_MISMATCH"),
        ('{"alg":"wrong-and-scalar","typ":"aitp-grant+jwt"}', "TOKEN_ALG_MISMATCH"),
    ],
    ids=["typ", "alg"],
)
def test_scalar_header_values_are_still_rendered_verbatim(header: str, expected_code: str) -> None:
    """The negative control the guard must not cost us.

    `describe_value` bounds containers; it must NOT flatten scalars, or every
    "wrong typ"/"wrong alg" report loses the one detail that makes it
    actionable. A regression that replaced the interpolation with a blanket
    type name would pass every assertion above and fail here.
    """
    with pytest.raises(AitpError) as exc_info:
        verify_grant_voucher({"voucher_token": _token(header)})
    assert exc_info.value.code == expected_code
    assert "wrong-and-scalar" in exc_info.value.message


def test_header_member_set_gate_does_not_type_check_its_values() -> None:
    """Why the two sites above are reachable at all, pinned as a fact rather
    than left as a comment: the only check between `parse_compact` and the
    comparisons is on the member SET, so a header carrying exactly `alg` and
    `typ` with container values passes it and both values arrive unvalidated.
    If a future change added real type-checking there, this test is what says
    the guards downstream may be revisited.
    """
    header = '{"alg":{"a":1},"typ":{"a":1}}'
    with pytest.raises(AitpError) as exc_info:
        verify_tct({"tct_token": _token(header)})
    # Not the member-set error (`TOKEN_ALG_MISMATCH` with "must contain
    # exactly") -- the set was fine; it is the `typ` comparison that rejects.
    assert exc_info.value.code == "TOKEN_TYP_MISMATCH"
    assert "must contain exactly" not in exc_info.value.message
