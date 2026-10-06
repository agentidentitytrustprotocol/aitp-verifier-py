# Plan: bound `jwk.py::issuer_keys_from`'s recursion and convert its exceptions at the boundary (issue #38)

## Context

`aitp_verifier/jwk.py::issuer_keys_from` (`jwk.py:162-194`) normalizes a caller-supplied
issuer-key value (a bare config string, a single JWK, a JWKS `{"keys": [...]}"`, or a list
mixing any of those) into a flat `list[IssuerKey]`. Its list branch (`jwk.py:189-193`)
self-recurses once per list element with **no depth bound**:

```python
if isinstance(value, list):
    out: list[IssuerKey] = []
    for item in value:
        out.extend(issuer_keys_from(item))   # unbounded self-recursion
    return out
```

It has exactly one production call site, `identity.py:181`
(`candidates = issuer_keys_from(issuer_keys.get(issuer))`, inside `_verify_oidc`), which is
reached by the public `verify_identity` entry point and, through it, by
`verify_handshake_payload` (`handshake.py:111` passes
`issuer_keys=inp.get("resolved_issuer_keys", {})` — a free-form, caller/resolver-supplied
mapping, not a schema-validated wire field: confirmed by grepping every JSON schema and
conformance fixture under `agentidentitytrustprotocol/schemas/` — the string
`resolved_issuer_keys` appears in none of them; `handshake.py:111` itself is an unchecked
Python `dict.get()`, not a validated field read). Neither `identity.py:181` nor any caller
above it catches `ValueError`, so:

1. A deeply nested list value (`[[[...]]]`) drives `issuer_keys_from` past the interpreter's
   recursion limit, raising a raw `RecursionError`.
2. A merely malformed (not deep) value — e.g. an `int` — hits `issuer_keys_from`'s own
   existing final-else `raise ValueError(f"unsupported issuer key value shape: ...")`
   (`jwk.py:194`), or a similar `ValueError` from `issuer_key_from_jwk`/
   `issuer_key_from_config` for a malformed JWK/config-string shape.

Both escape `verify_handshake_payload`/`verify_identity` as a bare Python exception, breaking
this repo's boundary contract, stated throughout the codebase (`fields.py`'s module
docstring, `ASSUMPTIONS.md`'s Phase 7 entries, issue #23/#31's own fixes): *every public
verifier entry point raises `AitpError` or returns a verdict; a caller that writes
`except AitpError` must never see anything else.* This is the exact class of bug issue #31
(closed) fixed for `jcs.py::_serialize`/`fields.py::canonical_bytes`, and the exact class
issue #23/Phase 7 swept for everywhere else — except `jwk.py`'s own self-recursion predates
that sweep untouched (confirmed: `jwk.py` is byte-identical to `main` across the #31 diff,
last substantively changed in `c5ecb60`, long before) and involves no `canonicalize`/
`canonical_bytes` call at all, so neither fix's diff could have caught it.

**Confirmed live** (this session, `/tmp/aitpvenv313`, CPython 3.13.7, stock recursion limit
1000, spec pack at `../agentidentitytrustprotocol`) by re-reading `jwk.py` and `identity.py`
in full and re-deriving the issue's own reproduction against the current `main` (`2bbf36d`),
then independently re-verified across **two rounds** of fresh-Opus plan review, each re-running
live repros against the actual code rather than trusting this file's prose:

- `jwk.py:162-194` is unchanged in substance from the issue's citation; the list branch still
  recurses with no guard. The issue's own line citations (`identity.py:175`, `jwk.py:193`)
  have drifted slightly under later commits — the current lines are `identity.py:181` and
  `jwk.py:194` respectively — but the code and the defect are otherwise unchanged.
- `identity.py:181` is the sole call site; its `if not candidates:` guard two lines below
  (`identity.py:182-183`) already distinguishes "resolution produced nothing" from every
  other outcome, and is the only place issue #38's fix needs to plug in.
- `jcs.py:150-176`'s `_MAX_DEPTH = 256` / entry-guard pattern (issue #31's fix) is the
  precedent this plan mirrors, including its "guard at entry, not at the recursion site"
  reasoning (a caller passing an already-deep value could exceed the cap before the first
  check ran if the guard sat only at the recursive call site) — **and** the fact that `depth`
  lives only on `jcs.py`'s *private* `_serialize` (`jcs.py:171`), never on its public
  `dumps`/`canonicalize` (`jcs.py:212,219`), which take no depth parameter at all. This plan's
  fix mirrors that split, not just the guard (see Phase 1 step 1 — an earlier draft of this
  plan put `depth` on the public `issuer_keys_from` itself, which round 1 of review caught as
  bypassable: `issuer_keys_from(v, depth=-10**6)` would defeat the cap outright).
- `fields.py::canonical_bytes` (`fields.py:201-226`) is the second precedent: it converts
  both `JcsError` (with an interpolated message — safe, the stack isn't near-exhausted when
  the *cap itself* raises cleanly) and `RecursionError` (with a **constant, non-interpolated**
  message — "formatting a message while the stack is exhausted can itself re-trigger the
  error, and this recovery path must not be fragile") as defense in depth behind `jcs.py`'s
  cap, because a caller whose own stack was already near-exhausted before calling in can
  still exhaust it inside a walk the cap alone would have admitted. This plan applies the
  identical two-clause shape at `identity.py`'s new call-site guard.
- **A second hazard in the same file, found by round 1 of review, not the original issue:**
  `issuer_key_from_jwk` (`jwk.py:94-140`) interpolates two caller-supplied values with `!r`
  and no type guard — `crv` at `jwk.py:116,125` and `kty` at `jwk.py:140`
  (`f"unsupported OKP curve: {crv!r}"`, `f"unsupported EC curve: {crv!r}"`,
  `f"unsupported or missing JWK 'kty': {kty!r}"`). Measured live (independently re-measured
  by round 2): a JWK-shaped value like `{"kty": <dict nested ~2000 levels>}` produces a
  ~14 KB `ValueError` message that leaks the attacker's own leaf content verbatim; a value
  nested deep enough (~20000 levels) makes `repr()` itself raise a raw `RecursionError`
  *while constructing the exception message* (`"...while getting the repr of an object"`) —
  the same escaping-exception class this whole issue is about, reached through a sibling
  function's message formatting rather than through recursion in `issuer_keys_from` itself,
  and **not bounded by the depth cap**, since these values are JWK leaves (depth ≤ 1 under
  `issuer_keys_from`'s own walk) that `issuer_key_from_jwk` inspects in a single call frame.
  This repo already has the fix for exactly this class: `fields.py::describe_value`
  (`fields.py:98-132`), the cost-bounded value-description helper `identity.py` itself already
  uses at three of its own analogous sites (`identity.py:103,179,237`). `jwk.py` was never
  swept for it. Folded into this phase, not filed separately — same file, same call path,
  same parameter (`resolved_issuer_keys`), same "every reachable shape of a hostile value"
  scope this plan already commits to (see Phase 1's Delivers).
- **A third hazard, one level up, found by round 2 of review, also not the original issue:**
  the original draft of this plan treated "`issuer_keys` itself is not a `Mapping`" (e.g. the
  whole `resolved_issuer_keys` argument is an `int`, a `list`, or a bare string, rather than
  one issuer's value inside it) as out of scope, reasoning it was a fixed-shape
  Python-calling-convention parameter like `trust_anchors`/`trust_store`. Round 2 measured
  this live and found that reasoning doesn't hold: `issuer_keys.get(issuer)` on a non-`Mapping`
  raises a raw `AttributeError` (`'int' object has no attribute 'get'`, etc.) through
  `verify_handshake_payload` today — the exact contract break this plan exists to close, on
  the exact parameter, delivered through the exact same unchecked `handshake.py:111` read.
  Unlike `trust_anchors`/`now` — genuinely fixed-shape values with no resolver in the loop —
  `resolved_issuer_keys` is resolver-supplied per this plan's own framing above, so a resolver
  handing back a non-mapping is no less plausible than one handing back a hostile per-issuer
  value. Folded into Phase 1 step 3 below, not scoped out.
- A repo-wide AST sweep (`ast.walk` over every `aitp_verifier/*.py` function def, looking for
  a function calling itself by name — independently re-run by both review rounds, same
  result) found exactly three such self-recursive functions in the whole package:
  `jcs.py::_serialize` (already capped, issue #31), `jwk.py::issuer_keys_from` (this issue),
  and `minter.py::_resolve_times` (`minter.py:50-63`). The third is confirmed out of scope:
  `minter.py` is the conformance-fixture/test-minting tool, not part of the shipped
  verification surface, and `_resolve_times` only ever walks a fixture's own `*_claims`
  template dict at minting time — never caller-supplied verification input. Same
  "test/fixture-minting code only, never reachable from untrusted verification input"
  reasoning `ASSUMPTIONS.md`'s Phase-8 residual-gap entry already applied to a different
  `minter.py:389` finding. **This method's coverage is narrower than issue #38's own "sweep
  for the same class" ask, and the plan says so rather than claim full coverage:** a
  same-function-name AST sweep does not catch mutual recursion (round 1 found one real cycle,
  `minter.py::_mint_claims_object` (`minter.py:75-91`, which calls `_mint_token` at line 82)
  ↔ `minter.py::_mint_token` (`minter.py:94`) — out of scope for the identical
  fixture-minting-only reason as `_resolve_times`) or C-level recursion driven by
  `repr()`/`copy.deepcopy` over an attacker-shaped value — which is exactly the `crv`/`kty`
  hazard above, an instance of the *already-tracked* `describe_value` class
  (`fields.py:108-119`'s own docstring names this exact mechanism), not a new class this
  sweep discovered. This plan closes the new instances it found; it does not claim to have
  exhaustively swept every recursion-shaped hazard in the package.

**Error code, checked against two additional sources the original issue didn't cite (found
by round 1 of review, both re-verified by round 2):**
`agentidentitytrustprotocol/registries/error-codes.md:25-45` is a *normative*
structural-rejection table ("implementations MUST use the code named here") mapping each
signed AITP **artifact** to its structural-rejection code — including "Identity descriptor →
`IDENTITY_FAILED`" at line 37. This does not govern the case here: `resolved_issuer_keys` is
not the Identity descriptor (which is `identity.issuer`/`identity.subject`/`identity.proof`/
`identity.type`/`identity.public_key` — the wire object `identity.py` already validates via
`reject_unknown_fields`) or any other artifact the table lists; it is local, resolver-supplied
key-resolution context passed as a separate argument, the same class of Python-calling-
convention parameter as `trust_anchors`/`trust_store`. The table's own scope statement
(`error-codes.md:22-30`) confirms this: it governs "a missing REQUIRED member, a member of
the wrong type, a value outside its grammar" of a *schema-defined artifact*, and
`resolved_issuer_keys` has no schema at all (confirmed above). Independent
cross-implementation corroboration for `KEY_RESOLUTION_FAILED` specifically: the sibling Rust
implementation, `aitp-rs/crates/aitp-handshake/tests/oidc_key_resolution.rs:1-10,142-175`,
pins exactly this line — a resolver hard error "(network failure, **malformed body**, etc.)"
maps to `HandshakeError::KeyResolutionFailed` (wire code `KEY_RESOLUTION_FAILED`), explicitly
retryable, while a resolved-but-non-matching key (bad `kid`/`alg`) or invalid proof stays
`HandshakeError::Identity` (wire code `IDENTITY_FAILED`) — the identical line this plan draws
below, arrived at independently by a second implementation.

Nothing else in the issue turned out to be stale or wrong — the plan below implements its
suggested fix shape essentially as written, with refinements (the private-helper split, the
exact depth constant, defense-in-depth `RecursionError` handling at the call site, the
`crv`/`kty` message-safety fix, the non-`Mapping`-`issuer_keys` guard, and extending the
existing boundary-contract harness) grounded in this repo's own established precedent and two
completed review rounds, rather than invented fresh or left for `/implement` to discover.

## Phases

### Phase 1 — depth-cap `issuer_keys_from`, bound its sibling's message construction, guard the one call site against every reachable shape, and close the class-level test-harness gap

**Status:** DONE (fresh-Opus verification gate: PASS — see `PROGRESS.md` for the full
verdict and the four non-blocking follow-ups closed same-session, including
[issue #47](https://github.com/agentidentitytrustprotocol/aitp-verifier-py/issues/47) filed
for the one genuinely out-of-scope finding)

**Divergence notes:**
- The four end-to-end tests in `tests/test_unknown_fields.py` are named without the
  `_hello_` infix the plan's Tests section used (e.g.
  `test_handshake_deeply_nested_resolved_issuer_key_is_key_resolution_failed_not_a_crash`,
  not `test_handshake_hello_deeply_nested_resolved_issuer_key_is_key_resolution_failed_not_a_crash`)
  — a naming-only divergence with no behavioral difference; each test still does exactly what
  its corresponding acceptance criterion specifies, against the same `id-009` `mutual_hello`
  fixture.
- `test_issuer_keys_from_past_max_depth_raises_value_error_not_recursion_error`'s leaf value
  is a well-formed JWK, not this section's usual `"deep-leaf-sentinel"` string convention. Found
  during the mandatory fault-injection pass (acceptance criterion 11b): with the sentinel leaf,
  reverting only the depth-cap guard did *not* make the test's `pytest.raises(ValueError)`
  fail — `issuer_key_from_config` itself still rejects that malformed 17-char-ish string,
  independent of the cap, so the test stayed green with no cap present at all. That directly
  contradicts criterion 11b's own stated expectation ("nothing raised at that depth at all")
  and would have made the test vacuous. Switched the leaf to a real, resolvable JWK so the
  cap-absent outcome is genuinely "resolves with no exception" — confirmed live: with the cap
  defeated the test now correctly fails with `Failed: DID NOT RAISE ValueError`, and with the
  cap restored it passes. No other test needed this change (every other crash-reproducing test
  already uses a leaf/value whose only path to an exception is through the code this phase
  fixes).

**Delivers:** `verify_handshake_payload` and `verify_identity` raise `AitpError` (never a
raw `RecursionError`/`ValueError`/`AttributeError`) for every reachable shape of a hostile
`resolved_issuer_keys`/`issuer_keys` value: too-deeply-nested, malformed, a container value
buried inside a JWK's own `kty`/`crv` member, the whole argument not being a mapping at all,
or a caller whose own stack was already low on headroom before calling in.
`test_boundary_contract.py`'s own identity sweep — the capstone harness issue #23/Phase 7
built to catch exactly this class — is extended to cover the parameter it previously read but
never mutated, closing the reason this bug survived it.

**Depends on:** nothing (single-phase plan).

**Files:**
- `aitp_verifier/jwk.py` — split `issuer_keys_from` into an unchanged public wrapper plus a
  new private, depth-guarded `_issuer_keys_from`; bound `issuer_key_from_jwk`'s `crv`/`kty`
  message construction via `fields.describe_value`; update the module docstring.
- `aitp_verifier/identity.py` — convert `issuer_keys_from`'s exceptions to `AitpError` at
  `identity.py:181`, and guard against a non-`Mapping` `issuer_keys` at the same site; update
  both the module docstring's OIDC code-mapping bullet and `_verify_oidc`'s docstring (step 5).
- `aitp_verifier/fields.py` — one-line docstring update: `describe_value` gains a third
  consumer/importer (`jwk.py`), which its own "lives here because exactly these two modules
  need it" rationale (`fields.py:50-56`) needs to keep saying accurately.
- `tests/test_identity_oidc.py` — direct `jwk.py`-level regression tests pinning the depth
  boundary one level apart (mirrors `test_fields.py`'s `_MAX_DEPTH`/`_MAX_DEPTH + 1`
  discipline for issue #31), a malformed-shape unit test, a `crv`/`kty` message-safety unit
  test, and the through-`verify_identity` regression tests (including the monkeypatched
  `RecursionError` defense-in-depth case and the non-`Mapping`-`issuer_keys` cases).
- `tests/test_unknown_fields.py` — end-to-end regression tests through
  `verify_handshake_payload`, reproducing the issue's own repro shape (a deeply nested
  `resolved_issuer_keys` entry, a malformed one, and a non-`Mapping` one) against a real
  minted OIDC fixture.
- `tests/test_boundary_contract.py` — extend
  `test_boundary_contract_identity_never_raises_a_bare_exception` to also sweep `issuer_keys`'
  own scalar leaves (currently read at `test_boundary_contract.py:288` but never mutated),
  reusing the harness's existing `_iter_leaf_paths`/`_mutate`/`_MUTATIONS` machinery as-is.
- `CHANGELOG.md` — one `### Security-relevant` entry (this is a crash-to-rejection hardening
  fix on a public entry point, the same category every prior such fix in this file logs).

**Approach — the fix, and why this shape:**

1. **`jwk.py`: split `issuer_keys_from` into a public wrapper and a private, depth-guarded
   walker.** The public function's signature stays exactly `issuer_keys_from(value)` — no new
   parameter — so the cap cannot be bypassed by a caller (including this codebase's own
   `identity.py:181`, which passes one positional argument) supplying an adversarial `depth`.
   This mirrors `jcs.py`'s own split exactly: `depth` lives only on private `_serialize`
   (`jcs.py:171`), never on public `dumps`/`canonicalize` (`jcs.py:212,219`).

   ```python
   # Maximum LIST nesting depth this walk will descend before rejecting a
   # caller-supplied issuer-key value as malformed. Unlike jcs.py's _MAX_DEPTH
   # (a full JSON-tree walk over input of unknown provenance), this recursion
   # is over LIST nesting only: a dict is always a terminal JWK/JWKS leaf,
   # parsed within the same call frame rather than recursed into again -- so
   # a genuine value nests at most 1 level deep (a flat list of
   # JWK/JWKS/config-string entries; RFC-AITP-0007 gives no meaning to a
   # nested list). 16 is generous headroom over that, not a number tightly
   # calibrated to it. Kept as its own constant rather than importing
   # jcs.py's private _MAX_DEPTH: that cap is calibrated against a
   # structurally different (full-tree, not list-only) recursion, and
   # reaching into a sibling module's private name would be a leakier
   # coupling than one small, independently-justified number.
   _MAX_DEPTH = 16

   def issuer_keys_from(value: Any) -> list[IssuerKey]:
       """... (existing docstring, plus one line: "Depth-bounded -- see
       _MAX_DEPTH -- and every ValueError this raises, including on a value
       too deeply nested to walk, is converted to AitpError at its one
       caller, identity.py's _verify_oidc.") ..."""
       return _issuer_keys_from(value, 0)


   def _issuer_keys_from(value: Any, depth: int) -> list[IssuerKey]:
       # Guard at entry, not only at the recursion site: a caller passing an
       # already-deep value could exceed the cap before the first check ever
       # ran if the guard sat only where the recursive call is made (same
       # reasoning as jcs.py::_serialize). `depth` is an internal walk
       # counter, not part of the public contract -- see issuer_keys_from's
       # own docstring for why it is not exposed as a parameter there.
       if depth > _MAX_DEPTH:
           raise ValueError(f"issuer key value nesting exceeds the maximum depth ({_MAX_DEPTH})")
       if value is None:
           return []
       if isinstance(value, str):
           return [issuer_key_from_config(value)]
       if isinstance(value, dict):
           if "keys" in value:
               keys = value["keys"]
               if not isinstance(keys, list):
                   raise ValueError("JWKS 'keys' must be a list")
               return [issuer_key_from_jwk(k) for k in keys]
           return [issuer_key_from_jwk(value)]
       if isinstance(value, list):
           out: list[IssuerKey] = []
           for item in value:
               out.extend(_issuer_keys_from(item, depth + 1))
           return out
       raise ValueError(f"unsupported issuer key value shape: {type(value).__name__}")
   ```

   `__all__` stays unchanged (`_issuer_keys_from` is private, not exported). Rejected: a
   keyword-only `depth` parameter on the public function (this plan's own first draft) — round
   1 of review pointed out `issuer_keys_from(v, depth=-10**6)` would defeat the guard entirely,
   since nothing stops a caller from passing an out-of-range starting value; the
   private-helper split is the only shape that makes the cap non-bypassable while keeping
   `issuer_keys_from` a normal, single-argument public function. Rejected: reusing
   `jcs._MAX_DEPTH` (256) — a private name in a sibling module calibrated for a structurally
   different (full-tree, not list-only) walk, and 256 gives no real signal value for a shape
   that legitimately never nests past 1; a small, purpose-justified constant is more correct,
   not merely simpler. Rejected: a module-level recursion counter or
   `sys.setrecursionlimit` tweak — not re-entrant/thread-safe, exactly `jcs.py`'s own
   already-rejected alternative, for the identical reason.

2. **`jwk.py`: bound `issuer_key_from_jwk`'s `crv`/`kty` message construction.** Replace the
   three unguarded `!r` interpolations with `fields.describe_value` (already imported
   elsewhere in this codebase for exactly this purpose):

   ```python
   from .fields import describe_value
   ...
       if kty == "OKP":
           crv = value.get("crv")
           if crv != "Ed25519":
               raise ValueError(f"unsupported OKP curve: {describe_value(crv)}")
           ...
       if kty == "EC":
           crv = value.get("crv")
           if crv != "P-256":
               raise ValueError(f"unsupported EC curve: {describe_value(crv)}")
           ...
       raise ValueError(f"unsupported or missing JWK 'kty': {describe_value(kty)}")
   ```

   No import cycle: `fields.py` imports only `.b64`/`.errors`/`.jcs` (confirmed by reading
   it), none of which import `.jwk`, and `jwk.py`'s own existing imports (`.aid`, `.b64`,
   `.crypto`) import nothing from `.fields` either (confirmed by reading `aid.py`/`crypto.py`/
   `b64.py`) — `jwk.py` importing `fields.describe_value` introduces no new edge risk.
   `describe_value` is *cost-bounded* by construction (it never calls `repr()` on a
   non-scalar, so message cost cannot grow with nesting depth or container size — a very long
   individual scalar's own `repr()` is unaffected, matching `fields.py`'s own docstring
   wording, not a stronger "O(1) regardless of input" claim). This closes both the
   unbounded-message-length leak and the RecursionError-during-formatting crash in one change,
   with no behavior change for the well-typed values every existing test already exercises
   (`describe_value` on a JSON scalar returns `repr(value)`, byte-identical to what
   `{value!r}` already produced — confirmed against `test_identity_oidc.py`'s existing
   `test_jwk_unsupported_kty_oct`/`test_jwk_unsupported_curve_p384`, which assert only
   `pytest.raises(ValueError)` with no message content check). This is the one place in
   `jwk.py` where an unvalidated caller-supplied value reaches a message via `!r` with no
   prior type check — every other `ValueError` message in this file interpolates only a fixed
   literal, an `int`, or `type(value).__name__`, none of which are affected.

3. **`identity.py`: convert every `issuer_keys_from` failure mode to `AitpError` at
   `identity.py:181`, and guard against `issuer_keys` itself not being a `Mapping`**, mirroring
   `fields.py::canonical_bytes`'s two-clause shape for the exception conversion (this whole
   step is unaffected by the private-helper split above — `issuer_keys_from`'s public call
   signature at this call site does not change):

   ```python
   resolved = issuer_keys.get(issuer) if isinstance(issuer_keys, Mapping) else None
   try:
       candidates = issuer_keys_from(resolved)
   except RecursionError as exc:
       # Defense in depth behind jwk.py's own depth cap, same reasoning as
       # fields.py::canonical_bytes: the cap bounds THIS walk's frames, but a
       # caller whose stack was already near-exhausted before calling in can
       # still exhaust it inside a walk the cap would have admitted. Message
       # is a constant literal -- formatting one while the stack is exhausted
       # can itself re-trigger the error.
       raise AitpError("KEY_RESOLUTION_FAILED", "issuer key value is too deeply nested to resolve", retryable=True) from exc
   except ValueError as exc:
       raise AitpError("KEY_RESOLUTION_FAILED", f"issuer key value for {issuer!r} is malformed: {exc}", retryable=True) from exc
   if not candidates:
       raise AitpError("KEY_RESOLUTION_FAILED", f"no issuer key resolvable for {issuer!r}", retryable=True)
   ```

   `Mapping` is already imported in this module (`from typing import Any, Mapping`, used in
   this same function's own parameter annotation), so the guard needs no new import. A
   non-`Mapping` `issuer_keys` — the whole resolver-supplied argument, not one issuer's value
   inside it — is treated identically to "issuer not found" (falls through to the existing
   `if not candidates:` branch) rather than a distinct error path: a resolver that can't even
   hand back a mapping has produced exactly as much usable key material as one that returned
   zero candidates for this issuer specifically — none, and for the same retryable reason.
   Without this guard, `issuer_keys.get(issuer)` on a non-`Mapping` raises a raw
   `AttributeError` today (confirmed live by round 2 of review: an `int`, a `list`, and a bare
   `str` all raise `AttributeError: '<type>' object has no attribute 'get'`) — the identical
   contract break this whole plan exists to close, on the identical parameter, found only
   because round 2 checked the plan's own "every reachable shape" Delivers claim against a
   live repro rather than accepting the "out of scope, fixed Python-calling-convention shape"
   reasoning an earlier draft used here (that reasoning is right for `trust_anchors`/
   `trust_store`/`now`, which have no resolver in the loop, and wrong for
   `resolved_issuer_keys`, which this plan's own Context already establishes is
   resolver-supplied).

   The `except ValueError` clause's `{exc}` interpolation is safe once step 2 lands: every
   `ValueError` `jwk.py` can now raise has a cost-bounded message (a fixed literal, an `int`,
   a type name, or `describe_value`'s output), so nothing unbounded or
   recursion-formatting-hazardous can flow through `exc` into the `AitpError` a caller logs.

   **Error code decision (issue #38 explicitly left this open — "both look defensible; pick
   one and pin it with a test"): `KEY_RESOLUTION_FAILED`, not `IDENTITY_FAILED`, for every
   failure mode this step converts, including the new non-`Mapping` case.** Decided directly
   (reversible, no wire-schema impact — see Long-term posture) rather than escalated:
   `_verify_oidc`'s own docstring (step 5, `identity.py:133-138`) already draws exactly this
   line for the sibling case two statements below — "Zero candidates -> `KEY_RESOLUTION_FAILED`
   (retryable — a key might show up on a later resolution attempt)" vs. "a resolution *target*
   did exist but couldn't be pinned ... `IDENTITY_FAILED`". A malformed, too-deep, or
   altogether-wrong-shaped `resolved_issuer_keys`/`resolved_issuer_keys[issuer]` value is
   squarely the first case, not the second: resolution produced *nothing usable at all*, before
   there was ever a set of candidates to pin a `kid` against. It is also the
   RFC-AITP-0007-registry-literal fit (`KEY_RESOLUTION_FAILED`: "Could not resolve issuer or
   peer keys.", retryable — vs. `IDENTITY_FAILED`: "Identity binding could not be verified.",
   not retryable), does not collide with `registries/error-codes.md`'s normative
   structural-rejection table (which governs schema-defined artifacts, and
   `resolved_issuer_keys` is not one — see Context), and is independently corroborated by the
   sibling Rust implementation's own test suite (see Context) drawing the identical line for
   the identical reason. `retryable=True` is honest, not merely convenient: a resolver that
   hands the verifier a hostile/malformed/wrongly-shaped value on one fetch may hand back a
   well-formed one on the next, exactly the existing zero-candidates case's own rationale,
   unchanged by why zero candidates resulted.

4. **Docs.** `jwk.py`'s module docstring (issuer-key-parsing bullet) gets a line naming the
   depth bound and the `crv`/`kty` message-safety fix. `identity.py` gets two updates: its
   *module* docstring (`identity.py:18-21`, which already states the OIDC code mapping —
   "zero resolvable issuer-key candidates is `KEY_RESOLUTION_FAILED`" — needs to additionally
   say "...or a malformed, too-deeply-nested, or wrongly-shaped `resolved_issuer_keys`
   value"), and `_verify_oidc`'s own step-5 docstring line. `fields.py`'s docstring
   (`fields.py:50-56`) states `describe_value` "lives here because the modules that need it"
   are exactly `jws.py` and `identity.py` — once `jwk.py` becomes a third consumer and
   importer, that sentence needs the same one-line update or it goes stale the moment this
   phase lands (found by round 2 of review; an earlier draft updated only `jwk.py`'s and
   `identity.py`'s own docstrings and missed this one).

5. **Extend `test_boundary_contract.py`'s identity sweep to cover `issuer_keys` itself.**
   `test_boundary_contract_identity_never_raises_a_bare_exception` already reads
   `issuer_keys = minted.get("resolved_issuer_keys", {})` (`test_boundary_contract.py:288`) and
   passes it straight through to every mutated call — but only `identity`'s own leaves are
   ever mutated; `issuer_keys` never is. This is precisely why issue #38 survived the capstone
   harness issue #23/Phase 7 built for exactly this class of bug, and it is cheap to close, not
   a design problem to defer: `_iter_leaf_paths`/`_mutate` (`test_boundary_contract.py:127-171`)
   already operate on any dict/path/mutation triple with no dependency on `identity`'s own
   shape, and `_MUTATIONS` (`:111-128`) already includes `("deep-nesting", _deep_dict(2000))`
   — the exact shape that would have caught this issue at this exact position. Add a second
   loop inside the same test function, alongside the existing `identity`-leaf loop, that walks
   `_iter_leaf_paths(issuer_keys)` and calls `verify_identity` with
   `issuer_keys=_mutate(issuer_keys, leaf_rel, mutation)` (holding `identity` at its own
   original, valid value for this half of the sweep) instead of adding new harness machinery.
   Round 2 of review confirmed live that all 12 `_MUTATIONS` land on `AitpError` at this
   position once Phase 1 steps 1-3 land, so this addition is expected to be green immediately,
   not a follow-up needing its own investigation. (This sweep targets leaves *inside*
   `issuer_keys` — e.g. `issuer_keys[ISSUER]` — the same class steps 1-2 close; it does not
   cover `issuer_keys` itself being replaced wholesale by a non-dict, which step 3's own
   direct/end-to-end tests cover instead, since the harness's leaf-mutation model has no
   natural way to replace a sweep's own root argument.)

**Edge cases & failure modes:**

- **Depth exactly at the cap (`_MAX_DEPTH` == 16 levels of list nesting):** must still resolve
  normally if the leaf is well-formed — the cap bounds *rejection*, not legitimate depth.
  Pinned by a positive test (see Tests). Note the realistic legitimate depth is 0 or 1 (a bare
  value, or a flat list of entries); 16 is headroom, not a tight fit, so this test exists to
  pin the exact boundary rather than to validate a shape any real caller would produce.
- **Depth one past the cap (`_MAX_DEPTH + 1` == 17):** first depth rejected, as `AitpError`,
  not `RecursionError`. Pinned by a negative test. Note this is a boundary-correctness test,
  not a crash reproduction — 17 levels of list nesting is nowhere near the interpreter's own
  recursion limit, so pre-fix (with no cap at all) this value simply resolves without error;
  see Tests/acceptance criterion 10 for how this test's non-vacuity is actually established.
- **A non-list, non-dict, non-`str`, non-`None` scalar at any nesting level (e.g. `int`,
  `bool`, `float`) inside an otherwise well-formed list:** already correctly raises
  `ValueError` today via the existing final-else branch (`jwk.py:194`) — unaffected by the
  depth change, now also converted to `AitpError` by this phase's `identity.py` fix. Pinned by
  a malformed-shape test (both a bare scalar `resolved_issuer_keys[issuer]` value, matching
  the issue's own second repro, and a scalar buried inside a shallow list).
  A JWKS `{"keys": ...}` where `keys` isn't a list, or a JWK missing a required member (e.g.
  `x`), already correctly raises `ValueError` too (`jwk.py:186`, `issuer_key_from_jwk`'s own
  guards) — same conversion applies, no new test needed beyond what's already listed, since
  these are pre-existing `ValueError` shapes the call-site `except ValueError` clause catches
  identically regardless of which line inside `jwk.py` raised it.
- **A container value (dict or list) sitting where a JWK's `kty` or `crv` member is expected**
  (e.g. `resolved_issuer_keys[issuer] = {"kty": <deeply nested dict>}`): this is *not* caught
  by the depth cap (it never enters `_issuer_keys_from`'s own recursion — the outer value is a
  plain dict, a terminal leaf), and is a *different* hazard the depth cap alone does not close
  — see Approach step 2. Pinned by its own dedicated test, both at the direct `jwk.py` level
  and end-to-end.
- **`issuer_keys` itself (the whole resolver-supplied argument) is not a `Mapping`** (e.g. an
  `int`, a `list`, a bare string): found live by round 2 of review, not the original issue.
  `issuer_keys.get(issuer)` on a non-`Mapping` raises a raw `AttributeError` — a fourth failure
  mode alongside the three above, on the exact same parameter, and a direct contradiction of
  this phase's own "every reachable shape" Delivers claim if left unguarded. Fixed in Approach
  step 3 via `isinstance(issuer_keys, Mapping)`, treated identically to "zero candidates"
  (`KEY_RESOLUTION_FAILED`, retryable). Both a truthy (`12345`) and a falsy (`0`) non-`Mapping`
  value are tested: falsy matters because `test_identity_oidc.py`'s own `_verify` test helper
  has an `issuer_keys or {}` convenience default (`issuer_keys=issuer_keys or {}`, in `_verify`
  itself, not in any production code) that would silently substitute `{}` for a falsy value
  and mask exactly the case under test — the same class of falsy-value-bypass
  `ASSUMPTIONS.md` already documents once for `delegation.py`'s `revocation_snapshots`, here
  found in a test helper rather than production code. The falsy case therefore needs to call
  `verify_identity` directly, bypassing `_verify`'s own default (see Tests); the end-to-end
  test through `verify_handshake_payload` needs only the truthy case, since `handshake.py:111`'s
  own `inp.get("resolved_issuer_keys", {})` substitutes `{}` only when the key is *absent*, not
  when it is present-but-falsy, so a falsy `resolved_issuer_keys` value already passes through
  production code unmasked (no separate production-side falsy test is needed the way one is
  for the test helper).
- **A caller whose own stack is already near-exhausted before calling `verify_identity`/
  `verify_handshake_payload` at all**, hitting a genuine `RecursionError` on a value the cap
  would otherwise have admitted (e.g. depth 3, well under 16): converted to `AitpError` via
  the dedicated `except RecursionError` clause, with a constant (non-interpolated) message —
  this is the scenario the depth cap alone cannot close, per `canonical_bytes`'s own
  precedent. **Not testable by lowering `sys.setrecursionlimit()`** — this was tried and
  measured not to work: at every limit tested, the `RecursionError` fires either inside
  `b64url_decode` (`b64.py:26`, reached earlier in `_verify_oidc`'s own gate order, at
  `identity.py:170`) or not at all; `_verify_oidc` spends more stack frames on
  `parse_compact`/`b64url_decode` before ever reaching `issuer_keys_from` than
  `issuer_keys_from` itself uses, so there is no recursion-limit value that reliably trips
  *inside* `issuer_keys_from` specifically without first tripping (or never tripping) upstream.
  Exercised instead via `monkeypatch` (see Tests) — this is also this repo's own existing
  pattern for this exact scenario (`test_fields.py`'s `canonicalize`-boom test).
- **Concurrency / partial failure:** none apply — `issuer_keys_from`/`_issuer_keys_from` are
  pure functions with no shared or mutable module state; the new `_MAX_DEPTH` constant is
  read-only.

**Acceptance criteria:**

1. `issuer_keys_from`'s public signature is unchanged (`issuer_keys_from(value)`, one
   positional argument, no `depth` parameter) — the depth-bounded walk lives entirely in a
   new private `_issuer_keys_from(value, depth)`, not exported in `__all__`. Every existing
   call site (`identity.py:181`, `tests/test_identity_oidc.py`'s existing calls) is
   unaffected.
2. A list nested exactly `_MAX_DEPTH` (16) levels deep, terminating in a single well-formed
   JWK, resolves via `issuer_keys_from` to a one-element `list[IssuerKey]` — proving the cap
   does not reject legitimate-depth input.
3. A list nested `_MAX_DEPTH + 1` (17) levels deep raises `ValueError` from `issuer_keys_from`
   directly — never `RecursionError` — and, through `verify_identity`, raises `AitpError` with
   code `KEY_RESOLUTION_FAILED`.
4. `resolved_issuer_keys[issuer]` set to a bare malformed scalar (e.g. an `int`) raises
   `AitpError` with code `KEY_RESOLUTION_FAILED` through both `verify_identity` directly and
   `verify_handshake_payload` end to end — never a raw `ValueError`.
5. The issue's own two reproductions (a `resolved_issuer_keys` entry nested ~3000 levels; the
   same entry set to `12345`), run against a minted OIDC conformance fixture through
   `verify_handshake_payload`, both raise `AitpError` with code `KEY_RESOLUTION_FAILED` —
   never `RecursionError` or `ValueError`.
6. A genuine `RecursionError` raised *inside* `issuer_keys_from` — forced deterministically via
   `monkeypatch.setattr(identity, "issuer_keys_from", <raiser>)` (not via
   `sys.setrecursionlimit()`, confirmed unreliable for this specific call path — see Edge
   cases) — is converted to `AitpError` with code `KEY_RESOLUTION_FAILED` and the exact
   constant, non-interpolated message `"issuer key value is too deeply nested to resolve"` at
   `identity.py`'s call site, not left to propagate.
7. A JWK-shaped value whose `kty` (or, for `kty in {"OKP","EC"}`, whose `crv`) is itself a
   deeply nested container (dict or list) never raises `RecursionError` while constructing the
   rejection message, and the resulting `ValueError`'s message contains `describe_value`'s
   bounded rendering (e.g. `<dict>`), not a `repr()` of the container — through both
   `issuer_key_from_jwk` directly and `verify_handshake_payload` end to end, converted to
   `AitpError` with code `KEY_RESOLUTION_FAILED`.
8. `issuer_keys` set to a non-`Mapping` value — both a truthy one (`12345`) and a falsy one
   (`0`, exercised via a direct `verify_identity` call that bypasses the `_verify` test
   helper's own `or {}` default) — raises `AitpError` with code `KEY_RESOLUTION_FAILED`
   through `verify_identity`, and (for the truthy case) through `verify_handshake_payload` end
   to end — never a raw `AttributeError`.
9. `test_boundary_contract_identity_never_raises_a_bare_exception` also sweeps every scalar
   leaf of the `issuer_keys` argument, across all 12 existing `_MUTATIONS`, in addition to its
   existing `identity`-leaf sweep — zero violations.
10. Full suite green, `run_conformance.py` unchanged (68 passed / 0 failed / 1 skipped —
    nothing in the conformance pack exercises `resolved_issuer_keys` hostility, so no fixture
    outcome moves), `mypy` clean.
11. Fault-injection distinguishes two test categories correctly, and both are checked:
    (a) the crash-reproducing tests (criterion 4's malformed scalar, criterion 5's ~3000-level
    reproductions, criterion 7's `crv`/`kty` cases, criterion 8's non-`Mapping` cases) each
    fail against the pre-fix code with the exact bare exception they claim (`RecursionError`
    for the deep-nesting reproductions and the deeply-nested-`kty`/`crv` case, bare
    `ValueError` for the malformed-scalar and the non-recursive malformed-`kty`/`crv` case,
    bare `AttributeError` for the non-`Mapping` cases). (b) The exact-boundary tests (criteria
    2 and 3, pinning `_MAX_DEPTH`/`_MAX_DEPTH + 1` precisely at 16/17 levels) are *not* crash
    reproductions — pre-fix, 17 levels of nesting is nowhere near the interpreter's own
    recursion limit and simply resolves without any cap rejecting it. Their non-vacuity check
    is different in kind: reverting only the depth-cap guard (leaving every other line of the
    fix in place) must make the `_MAX_DEPTH + 1` test's rejection assertion fail (nothing
    raised at that depth at all), confirming the cap itself — not some other check — is what
    the test is pinned to; criterion 2's own positive test needs no fault-injection at all
    (there is nothing pre-existing it is proving fixed). The criterion-6 monkeypatch test is
    separately confirmed non-vacuous by reverting only `identity.py`'s new
    `except RecursionError` clause (leaving the depth cap and the `except ValueError` clause
    in place) and confirming the monkeypatched `RecursionError` then escapes uncaught — this
    is the one test whose "pre-fix" state isn't simply pre-this-whole-diff, since it
    deliberately forces a condition the depth cap by itself cannot produce.

**Tests:**

- `tests/test_identity_oidc.py` (direct `jwk.py`-level, mirroring `test_fields.py`'s
  `_MAX_DEPTH`/`_MAX_DEPTH + 1` discipline for issue #31, including an
  `assert _MAX_DEPTH == 16` at the top of that section so the boundary tests' names keep
  meaning what they say if the constant is ever changed):
  - `test_issuer_keys_from_at_max_depth_resolves` — a list nested exactly `_MAX_DEPTH` levels
    around one well-formed JWK resolves successfully (acceptance criterion 2).
  - `test_issuer_keys_from_past_max_depth_raises_value_error_not_recursion_error` — `_MAX_DEPTH
    + 1` levels raises `ValueError`, explicitly asserting it is not `RecursionError` (acceptance
    criterion 3, direct-call half).
  - `test_issuer_keys_from_malformed_scalar_raises_value_error` — a bare `int`/`bool` value
    raises `ValueError` (pins the existing, pre-this-phase behavior of `jwk.py:194` stays
    correct after the private-helper split).
  - `test_issuer_key_from_jwk_deeply_nested_kty_does_not_crash_the_message` — `{"kty": <dict
    nested well past any realistic depth>}` raises `ValueError` (not `RecursionError`) whose
    message is `describe_value`'s bounded form (acceptance criterion 7, direct-call half); a
    sibling case for `crv` under `kty: "OKP"`.
- `tests/test_identity_oidc.py` (through `verify_identity`, via the existing `_verify` helper
  unless noted otherwise):
  - `test_identity_oidc_deeply_nested_issuer_key_is_key_resolution_failed_not_a_crash` —
    `issuer_keys={ISSUER: <_MAX_DEPTH + 1-deep nested list>}` raises `AitpError` with
    `KEY_RESOLUTION_FAILED` (acceptance criterion 3, through-`verify_identity` half).
  - `test_identity_oidc_malformed_issuer_key_is_key_resolution_failed_not_a_crash` —
    `issuer_keys={ISSUER: 12345}` raises `AitpError` with `KEY_RESOLUTION_FAILED` (acceptance
    criterion 4, through-`verify_identity` half).
  - `test_identity_oidc_deeply_nested_kty_is_key_resolution_failed_not_a_crash` —
    `issuer_keys={ISSUER: {"kty": <deeply nested dict>}}` raises `AitpError` with
    `KEY_RESOLUTION_FAILED` (acceptance criterion 7, through-`verify_identity` half).
  - `test_identity_oidc_non_mapping_issuer_keys_truthy_is_key_resolution_failed_not_a_crash` —
    `_verify(identity, env, issuer_keys=12345)` raises `AitpError` with `KEY_RESOLUTION_FAILED`
    (acceptance criterion 8, truthy half).
  - `test_verify_identity_non_mapping_issuer_keys_falsy_is_key_resolution_failed_not_a_crash` —
    calls `verify_identity` directly (not via `_verify`) with `issuer_keys=0`, since `_verify`'s
    own `issuer_keys or {}` default would otherwise mask the falsy value under test (acceptance
    criterion 8, falsy half).
  - `test_identity_oidc_issuer_key_recursion_error_is_key_resolution_failed_not_a_crash` —
    `monkeypatch.setattr(identity, "issuer_keys_from", <function raising RecursionError>)`,
    mirroring `tests/test_fields.py`'s own `monkeypatch.setattr(fields, "canonicalize", _boom)`
    pattern for issue #31's identical defense-in-depth scenario; asserts `AitpError` with code
    `KEY_RESOLUTION_FAILED` **and** the exact constant message (acceptance criterion 6).
- `tests/test_unknown_fields.py` (end to end, using this file's own established
  `_load_conformance_input(spec_dir, "id-009")` → `mint_input` → mutate → `verify_handshake_payload`
  pattern already used for the sibling `revocation_snapshots`/`identity` hostile-input tests
  in this same file — mutating `minted["resolved_issuer_keys"]`/`[<issuer>]` strictly *after*
  `mint_input` runs, not before: a pre-mint 3000-deep value would itself blow the stack inside
  `minter.py`'s own `copy.deepcopy`/`_resolve_times` walk before ever reaching the code this
  phase fixes, the same minting-time-interception blind spot `ASSUMPTIONS.md`'s Phase 7 entry
  already documents for a different field):
  - `test_handshake_hello_deeply_nested_resolved_issuer_key_is_key_resolution_failed_not_a_crash`
    — mints `id-009` (an OIDC `mutual_hello`, the same fixture family the issue's own repro
    used), then sets `minted["resolved_issuer_keys"][<issuer>]` to a list nested well past
    `_MAX_DEPTH`, asserts `AitpError`/`KEY_RESOLUTION_FAILED` through `verify_handshake_payload`
    (acceptance criterion 5, first repro).
  - `test_handshake_hello_malformed_resolved_issuer_key_is_key_resolution_failed_not_a_crash` —
    same fixture, `minted["resolved_issuer_keys"][<issuer>] = 12345`, asserts
    `AitpError`/`KEY_RESOLUTION_FAILED` (acceptance criterion 5, second repro).
  - `test_handshake_hello_deeply_nested_issuer_key_kty_is_key_resolution_failed_not_a_crash` —
    same fixture, `minted["resolved_issuer_keys"][<issuer>] = {"kty": <deeply nested dict>}`,
    asserts `AitpError`/`KEY_RESOLUTION_FAILED` (acceptance criterion 7, end-to-end half).
  - `test_handshake_hello_non_mapping_resolved_issuer_keys_is_key_resolution_failed_not_a_crash`
    — same fixture, `minted["resolved_issuer_keys"] = 12345` (replacing the whole dict with a
    truthy scalar), asserts `AitpError`/`KEY_RESOLUTION_FAILED` (acceptance criterion 8, truthy
    end-to-end half; no falsy variant needed here — see Edge cases for why).
- `tests/test_boundary_contract.py` — extend
  `test_boundary_contract_identity_never_raises_a_bare_exception` with a second leaf-sweep
  loop over `issuer_keys` (acceptance criterion 9), per Approach step 5.
- **Fault-injection (executor, done once; verifier re-does it independently per `/implement`'s
  own per-phase verification gate):** stash the `jwk.py`/`identity.py` diff, run the
  crash-reproducing tests above against the pre-fix code, confirm each fails with the exact
  bare exception it claims; separately confirm the two exact-boundary tests' and the
  monkeypatch test's non-vacuity per acceptance criterion 11's own (different, for each
  category) instructions; restore.

**Docs:** see Approach step 4 above (`jwk.py`'s module docstring, `identity.py`'s module
docstring and `_verify_oidc`'s step-5 docstring, `fields.py`'s `describe_value`-consumers
sentence). `CHANGELOG.md` gets one new `### Security-relevant` bullet under `## Unreleased`,
matching this file's existing entries' voice: what changed (the depth cap, the `crv`/`kty`
message-safety fix, and the non-`Mapping`-`issuer_keys` guard, all closing a
crash-to-`AitpError` gap, not a policy change), and that no known caller depended on the old
crash (package unpublished, per every prior entry's own framing).

## Long-term posture

No one-way door here. `resolved_issuer_keys`/`issuer_keys` is a Python-calling-convention
parameter, not a wire schema — `issuer_keys_from`'s public signature does not change at all
(the depth bound lives entirely behind a new private helper), and the `KEY_RESOLUTION_FAILED`
code choice is a reversible, internal classification decision (this package has never been
released, per every prior `ASSUMPTIONS.md`/`CHANGELOG.md` entry's own framing of that fact)
that costs nothing to change later if a downstream integrator's telemetry ever argues for
`IDENTITY_FAILED` instead. The `_MAX_DEPTH = 16` constant is a defensible default, not a
spec-mandated number (no schema governs this Python-side value) — raising or lowering it later
is a one-line, fully reversible change with no fixture or public-contract dependency on the
current value.

**A test-infrastructure gap this plan found and closed, not deferred:** an earlier draft of
this plan proposed deferring `test_boundary_contract.py`'s own blind spot for
`resolved_issuer_keys` (it reads the value at `test_boundary_contract.py:288` but never
mutated it, which is why issue #38 survived that capstone harness) as a follow-up issue, on
the theory that widening the harness's mutation surface was a separable design question.
Round 2 of review checked that reasoning against the actual harness code and found it didn't
hold: `_iter_leaf_paths`/`_mutate` already operate on any dict with no dependency on
`identity`'s own shape, `_MUTATIONS` already contains the exact mutation
(`_deep_dict(2000)`) that would have caught this issue, and all 12 mutations were confirmed
live to land on `AitpError` at this position once the rest of Phase 1 lands — so the "cheap
fix" and the "needs its own diff" framings were both available, and this plan now does the
cheap one (Approach step 5) rather than defer a fix that turned out to cost about ten lines.

## Enterprise concerns

This is a denial-of-service hardening fix on a public library entry point: an unbounded
recursive walk over caller/resolver-supplied input is a crash primitive (CWE-674,
uncontrolled recursion) reachable by any embedding application whose OIDC-issuer-key resolver
can be influenced (a compromised or spoofed JWKS endpoint, a resolver bug, or a malicious
peer if the resolver ever echoes anything peer-supplied — out of scope to characterize
further here, since the verifier's contract is "never crash regardless of why the value is
hostile"). Closing it converts an uncaught interpreter exception (which can crash a whole
request-handling process depending on the embedding application's own exception handling) into
an ordinary, catchable `AitpError` — the same value proposition every prior `#23`/`#31` fix in
this repo already delivers, extended to a path those fixes' own diffs did not touch, plus two
adjacent hazards (the `crv`/`kty` message-construction crash, and the non-`Mapping`
`issuer_keys` crash) those fixes' own diffs could not have found and this plan's own review
process did. No SLO/observability change beyond what `AitpError`'s existing contract already
provides (a caller that logs rejected verdicts by code sees `KEY_RESOLUTION_FAILED` instead of
a stack trace); no migration or rollback story beyond a normal revert, since nothing about the
wire protocol or persisted state changes.

## Open questions

None escalated. The one genuinely ambiguous point the issue itself flagged — which error code
to use for a malformed/too-deep issuer-key value — was decided directly above (Phase 1,
step 3) rather than raised to the user: it is reversible (internal classification, no wire
schema, unpublished package), corroborated by both the registry text and the sibling Rust
implementation's own independently-arrived-at test suite, and the existing code's own
docstring (`identity.py:133-138`) already states the exact distinguishing principle needed to
answer it — a "consequential but decidable" call per the Autonomy ladder, not a fork requiring
escalation. The exact value of `_MAX_DEPTH` (16) is similarly a defensible default already
justified above, not an open question. The `test_boundary_contract.py` gap that an earlier
draft flagged as a possible open question is resolved above (Long-term posture): it turned out
to be cheap enough to just fix, not something needing a decision.

## Repo map

See `PROGRESS.md`'s own `## Repo map` section for
`plans/issue-38-jwk-issuer-keys-depth-bound.md` (appended alongside this plan; kept in sync
across both review rounds).

## Plan review

**Round 1 (fresh Opus agent, reviewing against the code, not this prose): REVISE.**
Independently re-ran both of the issue's own reproductions live against `main` and confirmed
every line citation this plan makes, then found: (1) the original draft's `depth: int = 0`
keyword parameter on the *public* `issuer_keys_from` was bypassable
(`issuer_keys_from(v, depth=-10**6)`) and inverted issue #31's own precedent, where `depth`
lives only on the private `_serialize` — fixed via the public/private split (Approach step 1);
(2) acceptance criterion 6's proposed `sys.setrecursionlimit()`-based test was measured live
to be unreliable for this specific call path — replaced with the `monkeypatch`-based approach
this repo already uses for the identical scenario in `test_fields.py`; (3) the real, adjacent
`crv`/`kty` message-construction hazard, not closed by the depth cap — folded in as Approach
step 2, with its own tests and acceptance criterion; (4) the "sweep satisfied" claim
overstated relative to the AST method's actual coverage — narrowed in Context; (5) the
error-code decision's own grounding strengthened with the normative table's actual scope and
the sibling Rust implementation's independent precedent; (6) `identity.py`'s module docstring
added to the Docs field; (7) several line-citation slips corrected; (8) `test_boundary_contract.py`'s
blind spot recorded under Long-term posture as a deliberate deferral. All applied.

**Round 2 (fresh Opus agent, checking round 1's fixes against the code plus one light
independent pass): REVISE.** Confirmed all 8 round-1 fixes genuinely hold (mirror to `jcs.py`
accurate; monkeypatch test correctly scoped; `crv`/`kty` fix in scope and non-cycle-forming;
sweep-claim honest; error-code citations verbatim-accurate; docstring gap real; citation slips
fixed), then independently found three further problems by re-running live repros rather than
trusting the plan's prose: (A) a fabricated citation attributing the phrase "free-form" to
`handshake.py`'s module docstring, which does not contain it — replaced with the actual
grounding (a schema grep plus the real `handshake.py:111` citation); (B) acceptance criterion
9 (now 11) claimed the exact-boundary tests fail pre-fix with `RecursionError`, which is false
— a 17-deep value resolves fine with no cap present; rewrote the criterion to distinguish
crash-reproducing tests from boundary-pinning tests and give each its own correct non-vacuity
check; (C) a live repro showing `issuer_keys` itself being a non-`Mapping` raises a raw
`AttributeError` today, contradicting this plan's own Delivers claim and the very Context
paragraph that motivates the whole fix — the earlier draft's "out of scope, fixed-shape
parameter" reasoning for this case did not survive that repro, so it is now fixed (Approach
step 3, new edge case, new acceptance criterion 8, new tests) rather than scoped out; (D) the
`test_boundary_contract.py` deferral's stated reason (a structurally incompatible harness) was
checked against the actual harness code and found false — the fix is ~10 lines reusing
existing machinery, confirmed green live, so it is now done in this phase (Approach step 5)
rather than deferred; (E) `fields.py`'s own docstring goes stale once `jwk.py` becomes a third
`describe_value` consumer — added to Files/Docs; (F) an "O(1)" cost claim overstated relative
to what `describe_value` actually guarantees — restated as "cost-bounded", matching
`fields.py`'s own wording; (G) several cosmetic citation-precision nits in supporting prose,
applied where independently re-verified against direct file reads (one of round 2's own
proposed corrections, for `minter.py:50-63`, was itself checked against a fresh direct read
and found to already be correct in the plan — not changed). All substantive items (A-F)
applied to this file directly, as above.

Two rounds run, per this plan's own cap; both returned findings and both sets of findings were
applied directly to this file. Ready for `/implement`.
