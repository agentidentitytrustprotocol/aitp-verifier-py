# Hardening: close issues #23–#27 (contract, revocation-trust, and test/CI blind spots)

## Context

`aitp-verifier-py` is a pure-Python, network-free, independent re-implementation of AITP
verification, built from RFC text alone. Every public verifier entry point's contract is
"raise `AitpError` or return a verdict dict" — a caller that writes `except AitpError` must
never see a raw Python exception. Five issues (#23–#27), filed 2026-08-30 by adversarial
review during PR #22 and deliberately left out of that PR's scope, were re-verified against
current `main` (`fba3a95`, merged today via PR #28) by two fresh Opus subagents plus direct
reads of every file the fixes touch. All claims held; several turned out to be **broader**
than the issue text states:

- **#23** (contract): `JcsError` (a `ValueError` subclass, not `AitpError`) escapes
  `canonicalize()` unguarded at 3 sites (`manifest.py:155`, `envelope.py:36`,
  `sessionbundle.py:150`); `manifest.py:150` decodes `proof_of_possession.challenge` via
  unguarded `b64url_decode`; `handshake.py:81` reads `identity.get("type")` before
  `identity`'s dict-ness is validated (a bare `AttributeError` on non-dict input, and the
  reason `identity.py`'s own non-dict guard is unreachable in production); `$defs
  /IdentityHint`'s conditional requirements (`oidc` ⇒ `issuer` required, `public_key`
  forbidden; else ⇒ `public_key` required) are unenforced. **Broader than filed**:
  `envelope.py` and `sessionbundle.py` have essentially **no** required-member/type
  validation at all (only `reject_unknown_fields`, which checks the member *set*, not
  presence or type) — contrast `manifest.py`'s `_shape` and `revocation.py`'s
  `_typed`/`_validate_shape`, which both exist for exactly this reason. This produces raw
  `KeyError`/`TypeError`/`ValueError`/`OverflowError` escapes independent of the `JcsError`
  class (e.g. missing `participants`, non-int `expires_at`, malformed `coordinator`/
  `sender.agent_id` AIDs) — verified live against real signed artifacts.
- **#24** (revocation-trust consistency): `tct.py::_check_revocation` and
  `delegation.py::_revocation_index` each consume a signed revocation snapshot
  (`issuer_revocation_list`, `revocation_snapshots`) via bare `.get()` chains, with **no**
  `reject_unknown_fields`, **no** signature verification, and **no** structural validation —
  while `revocation.py::verify_revocation_snapshot` does all three for the identical
  artifact shape (RFC-AITP-0008 §1.5). Confirmed empirically: forging a snapshot signature,
  stripping it entirely, or injecting an unknown member all produce the identical
  `TCT_REVOKED`/`DELEGATION_SOURCE_TCT_REVOKED` verdict as a genuinely signed snapshot.
  Reachable direction: **false-positive revocation** (a network attacker who can tamper an
  unauthenticated snapshot source gets any valid TCT/delegation chain hard-rejected — RFC-
  AITP-0008 §1.5's own stated threat model) plus the same raw-exception contract violations
  as #23 (`AttributeError`/`TypeError` on malformed snapshot shapes). Not a false-negative
  bypass (both call sites are raise-only). **Also confirmed**: the two conformance fixtures
  that exercise these paths (`tct-004-revoked`, `del-mh-004-revoked-hop`) pass today
  *because* the signature is never checked — `minter.py` never signs these two snapshot
  holders correctly (`_sign_revocation` doesn't recognize `__VALID_B_SIG__`; `mint_input`
  never walks the `revocation_snapshots` list) — so any correct fix must also fix the
  minter, in the same change, or the conformance pack goes red.
- **#25** (test blind spot): `test_manifest_signed_example_verifies_over_inner_body`
  (`tests/test_signed_examples.py:80-96`) re-implements the manifest signature check inline
  instead of driving the real `verify_manifest()` — unlike its revocation/bundle siblings
  (`test_revocation_signed_example_runs_the_real_verifier`,
  `test_session_bundle_signed_example_runs_the_real_verifier`), which do. Confirmed:
  `minter.py:150-153`'s `_sign_manifest` signs the inner body (unwrapped), matching
  `manifest.py:154-156`'s verification convention — so today the two sides agree, but
  nothing in the test suite would catch either side silently drifting to the wrapped form,
  because the one test that could is checking crypto primitives directly, not the
  production entry point.
- **#26** (local test-run hazard): `tests/conftest.py:29-34`'s `spec_dir` fixture calls
  `pytest.skip(...)` when the sibling spec repo can't be resolved, silently dropping 73
  tests (confirmed via parametrize expansion, not the raw fixture-use count — includes
  `test_signed_examples.py` entirely, plus the KAT/conformance-dependent tests elsewhere)
  while the run still reports green. CI itself is unaffected (`ci.yml` always checks out
  the spec repo) — this is purely a local-contributor hazard, with no opt-out mechanism
  for a deliberate no-spec run.
- **#27** (CI blind spot): `.github/workflows/ci.yml` has zero references to `aitp-rs`; the
  `conformance` job's `pytest -q` step (line 81) bundles `test_signed_examples.py` into the
  general suite rather than surfacing it as its own named, visible check — so a signing-
  input regression introduced in this repo is invisible as a *distinct* CI signal, found
  only when `aitp-rs` next happens to bump its (separately-tracked, currently stale) pin.
  Scope, per the issue's own preference: a same-repo CI job that runs the production
  verifiers over the committed `signed-examples/`, not a cross-language `aitp-rs` build.

**Stale-doc note**: none of the plan's resource text conflicted with current code except
line numbers (both source PRs since #23–#27 were filed shifted `tct.py`/`handshake.py`/
`jws.py`/`sessionbundle.py`) — already corrected throughout this document via fresh reads.

## Phases

### Phase 1 — Close the manifest-convention test blind spot (issue #25)

**Status:** DONE. Implemented exactly as planned, no divergence — `test_manifest_signed_example_runs_the_real_verifier` added alongside (not replacing) the existing crypto-primitive test; hand-verification of acceptance criterion 3 (flipping the signing convention makes the new test fail) performed independently by both the executor and the fresh Opus verifier, same result both times.

**Delivers:** `tests/test_signed_examples.py` gains a test that drives the real
`verify_manifest()` over the committed signed example (positive: the committed signature
verifies through the production entry point; negative: the same input wrapped as
`{"manifest": ...}` — the pre-#25 convention — is rejected), extending the shape
`test_revocation_signed_example_runs_the_real_verifier` and
`test_session_bundle_signed_example_runs_the_real_verifier` already establish for driving
the real verifier over committed bytes. Correction from this plan's review round: neither
of those two sibling tests actually carries a negative case of its own (both are positive-
only) — this phase's wrapped-form negative is new, modeled instead on the crypto-primitive
negatives already present at `test_signed_examples.py:93-96`/`123-126`. This becomes the
regression net for every later phase that touches `manifest.py`.

**Depends on:** none.

**Files:**
- `tests/test_signed_examples.py`

**Approach:** Add a new test function (do not delete the existing
`test_manifest_signed_example_verifies_over_inner_body`, which still documents the raw-
crypto placement invariant and stays useful) that constructs `verify_manifest`'s actual
input contract — confirmed from `manifest.py:119-120`: `inp["manifest"]` directly (**not**
wrapped like the session bundle's `{"session_bundle": {...}}` or the revocation snapshot's
`{"snapshot": {...}}`), plus `inp.get("now")`/`now=` and `inp.get("supported_versions")`.
Positive case: load `manifest/kat-keypair-001-manifest.json`, call
`verify_manifest({"manifest": wrapped["manifest"], "now": <a timestamp before expires_at>},
now=...)`, assert it returns `{"aid": ...}` without raising. Negative case: build a manifest
body whose committed `signature` was produced over the WRAPPED form (construct
`{"manifest": body}` and re-sign it with the KAT key locally, mirroring the negative pattern
the revocation/bundle tests already use at `test_signed_examples.py:93-96`/`123-126`), and
assert `verify_manifest` raises `AitpError` with code `MANIFEST_SIGNATURE_INVALID`. This is
the *right* fix (not a shortcut) because it is the only way this file proves the production
verification path — not just the crypto primitives — agrees with the committed convention,
exactly the property the sibling tests already establish for the other two JCS-profile
artifacts.

**Edge cases & failure modes:** the committed example's `expires_at` must remain in the
future relative to whatever `now` the test passes (reuse the same
`int(body["published_at"]) + 100`-style pattern the sibling tests use, adapted to
`manifest`'s own timestamp fields — confirm the fixture's actual `published_at`/`expires_at`
values when writing the test); `proof_of_possession` must be a genuine valid PoP in the
fixture or the positive case fails for an unrelated reason — read the fixture JSON before
writing assertions, don't assume shape.

**Acceptance criteria:**
- A new test drives `verify_manifest` (not raw crypto) over the committed
  `manifest/kat-keypair-001-manifest.json` example and asserts `{"aid": ...}`.
- A new negative assertion proves the same signature does NOT verify through
  `verify_manifest` when the body is transport-wrapped, with the specific
  `MANIFEST_SIGNATURE_INVALID` code asserted (not just "raises").
- Manually flipping `manifest.py`'s signing convention to sign the wrapped form (temporary,
  local-only edit, reverted after the check) makes this new test fail — confirm this by
  hand before considering the phase done; this is the exact regression #25 reports is
  currently invisible.
- Existing `test_manifest_signed_example_verifies_over_inner_body` still passes unmodified.

**Tests:** the new test itself; existing signed-examples/unit/conformance suite unaffected
(no production code touched).

**Docs:** none.

---

### Phase 2 — Shared boundary-conversion helpers in `fields.py`

**Status:** DONE. Implemented exactly as planned. `check_types`/`require_members` extracted
byte-for-byte from the old `manifest.py`/`revocation.py` inline logic (confirmed by diffing
against the pre-refactor code); `manifest.py`'s interleaved-per-object ordering and
`revocation.py`'s deferred-member-set-pass ordering both preserved unchanged. Both required
ordering regression tests added and independently confirmed non-vacuous by fault injection
(twice — once by the executor, once by the verifier) that reproduces the exact "collapsed
interleaved sweep" regression this phase exists to prevent.

**Delivers:** Two narrow, genuinely-shared helpers in `aitp_verifier/fields.py` —
`check_types` (the duplicated presence-of-a-declared-JSON-type loop) and `require_members`
(a tiny required-member-presence check) — plus `canonical_bytes` and `decode_b64url`, all
alongside the existing `reject_unknown_fields`. A behavior-preserving refactor of
`manifest.py`'s `_shape` and `revocation.py`'s `_typed`/the presence checks inside
`_validate_shape` to call the first two. **Revised after this plan's own review round**: the
original design here was one monolithic `validate_shape` doing presence, type, *and*
member-set rejection in a single call with one fixed internal order. That is wrong — see
Approach below — and has been replaced with this narrower pair, which each artifact module
composes with its *own* member-set-check ordering rather than a forced shared one.

**Depends on:** none (Phase 1 is independent; ordered first only because it's a quick,
free-standing regression net worth having before Phase 3 touches `manifest.py`).

**Files:**
- `aitp_verifier/fields.py` — add `check_types`, `require_members`, `canonical_bytes`,
  `decode_b64url`.
- `aitp_verifier/manifest.py` — `_shape` (lines 72-103) delegates its type-checking loop
  (lines 85-97) to `fields.check_types` and its presence check (line 83-84) to
  `fields.require_members`; its own per-object `reject_unknown_fields` call (line 103) stays
  local, unchanged, in its current interleaved position (presence → type → member-set, per
  object, called 3 times from `verify_manifest` at lines 127-130).
- `aitp_verifier/revocation.py` — `_typed` (lines 71-98) is replaced by a call to
  `fields.check_types`; the presence checks inside `_validate_shape` (lines 116-117,
  124-125, 138-139) delegate to `fields.require_members`; the module's own deferred
  member-set pass (lines 156-159, run only once *after* the whole tree's shape is confirmed
  valid) and its `except JcsError` canonicalize wrap (lines 169-180, refactored to call
  `canonical_bytes`) are both left in their current position — this phase does not change
  when either runs relative to the rest of `verify_revocation_snapshot`.

**Approach:** This plan's own review round found the original design overstated the real
duplication and got the ordering wrong. Verified directly against the code:
`revocation.py::_validate_shape` (lines 100-141) contains **no member-set check of its
own** — `verify_revocation_snapshot` defers all three `reject_unknown_fields` calls to a
separate pass, run only once shape is otherwise confirmed valid (lines 156-159).
`manifest.py::_shape` (lines 72-103) instead calls `reject_unknown_fields` **per object**,
interleaved with that same object's own presence/type checks, called once for each of the
3 objects `verify_manifest` validates. These are two genuinely different, deliberate
orderings, not one rule implemented twice with accidental drift. Forcing both through a
single `validate_shape` call with one fixed internal order — the original design — is not a
behavior-preserving refactor, it is a silent behavior change: verified live, a revocation
snapshot with an unknown **wrapper**-level member *and* a **body**-level type defect in the
same input reports `REVOCATION_SNAPSHOT_INVALID` today (the type defect wins, found first,
before the deferred member-set pass ever runs); a single interleaved sweep would instead
report `UNKNOWN_FIELD` for that same input. No existing test covers this exact combination,
so "run the full suite, see it stay green" would not have caught the very regression this
plan's own Long-term-posture section was worried about — which is precisely why this phase
now includes a dedicated new test for it (see Acceptance criteria).

The duplication that *is* real, confirmed by direct side-by-side comparison, is narrower:
`manifest.py:85-97`'s type-checking loop and `revocation.py:83-97`'s `_typed` are a true
near-duplicate — identical `bool`-excluded-from-`int` guard, identical integral-float-
admitted-for-JCS-equivalence widening, identical per-key structure, differing only in the
hardcoded error-code constant and the message-format string. `check_types(obj, types, *,
shape_code, what)` extracts exactly this and nothing more — no member-set logic, no
ordering decision. `require_members` extracts the 2-line "which of these required keys are
missing" pattern present (with a different hardcoded code) in both `manifest.py:83-84` and
`revocation.py:116-117`/`124-125`/`138-139`. Neither extraction changes either module's
relative ordering: each still calls `require_members`, then `check_types`, then its own
`reject_unknown_fields` — per-object or deferred, whichever it already does — in exactly the
sequence it uses today. This is the right scope: it removes the duplication Phases 4/5
would otherwise re-copy a third and fourth time, without manufacturing a false equivalence
between two modules whose member-set-check ordering is a deliberate, documented difference.
Phases 4/5 compose `require_members` + `check_types` with their *own* choice of
`reject_unknown_fields` placement (interleaved, matching `manifest.py`'s simpler flat-object
convention, since neither `envelope.py` nor `sessionbundle.py`'s body-level validation needs
revocation.py's deferred-until-the-whole-tree-is-confirmed approach).

`canonical_bytes` and `decode_b64url` are unaffected by this correction — each wraps a
single library call's exception type, not a multi-stage validation sequence, so no ordering
question exists for either; the review round confirmed both as "cleanly justified as-is."
`revocation.py:169-180`'s existing `except JcsError` block is refactored to call
`canonical_bytes` in this phase (a 1:1 swap — and the review round found no existing test
actually asserts this message's exact text, which makes this swap lower-risk than
originally assumed, not higher). `canonical_bytes`'s other 2 call sites (`manifest.py:155`,
`envelope.py:36`) are wired up in Phases 3/4 respectively, once those phases exist to use
them — not here.

```python
# fields.py additions (sketch — exact signatures decided during implementation)
def require_members(obj: dict[str, Any], required: tuple[str, ...], *, shape_code: str, what: str) -> None:
    """Raise if any of `required` is missing from `obj`. Presence only — says
    nothing about type or about members outside `required`; the caller's own
    `check_types`/`reject_unknown_fields` calls own those separately."""

def check_types(obj: dict[str, Any], types: dict[str, tuple[type, ...]], *, shape_code: str, what: str) -> None:
    """Reject any PRESENT member whose value is not of its declared JSON type.
    `bool` is excluded from `int` (Python's bool is an int subclass; JSON's is
    not); an integral float is admitted wherever `int` is allowed (JSON-Schema
    `integer` admits it, and JCS serializes it to the same bytes as the int
    form). Says nothing about presence (see `require_members`) or about
    members outside `types` (see `reject_unknown_fields`) — deliberately: the
    caller decides when, and in what order relative to those two, this runs."""

def canonical_bytes(value: Any, *, shape_code: str, what: str) -> bytes:
    """JCS-canonicalize, converting JcsError (a ValueError, not an AitpError) to
    the artifact's own structural code. The offending value can sit anywhere
    inside `extensions`, whose interior RFC-AITP-0001 §7 forbids inspecting, so
    no upstream member/type check can intercept it — this is the one point
    every such value must pass through."""

def decode_b64url(text: str, *, code: str, what: str) -> bytes:
    """Decode unpadded base64url, converting the decoder's ValueError
    (binascii.Error included — it subclasses ValueError) to an AitpError."""
```

Message wording for `canonical_bytes` matches `revocation.py:180`'s existing `f"{what} is
not canonicalizable: {exc}"` phrasing; wording for `decode_b64url` mirrors
`sigfield.py:31`'s `f"... is not valid base64url: {exc}"` for consistency, even though
`sigfield.py` itself is not refactored to use it (its guard is `AitpError`-coupled to a
signature-specific `sig_err` parameter shape already, and touching a proven-correct,
well-tested module outside this plan's scope is unjustified churn — leave it as-is).

**Edge cases & failure modes:** `check_types` must preserve both the `bool`-exclusion and
integral-float-widening behavior exactly (a refactor that dropped either would be a silent
regression, not just a style change — a KAT vector or real peer may emit `1711900000.0` for
a JSON `integer` field and JCS canonicalizes it identically to the int form).
`canonical_bytes` must catch `JcsError` specifically, not a bare `Exception` — over-catching
would mask genuine bugs in `canonicalize`'s own logic as if they were input defects. The one
case verified as **not** covered by any existing test — an unknown wrapper member combined
with a body-level type defect in the same revocation snapshot — gets its own new test in
this phase specifically so the refactor's correctness on exactly the failure mode this plan
is worried about is proven, not assumed.

**Acceptance criteria:**
- `fields.check_types` and `fields.require_members` exist, exported, each with a docstring
  stating what it does and explicitly does *not* decide (neither performs member-set
  rejection; that stays each caller's own `reject_unknown_fields` call, at whatever point in
  its own sequence the caller already uses).
- `manifest.py::_shape` and `revocation.py::_typed`/the presence checks inside
  `_validate_shape` are refactored to call the new helpers, with **zero** change to either
  module's externally observable behavior or call ordering: every existing `man-*`/`rev-*`
  conformance fixture and every existing unit test in `tests/test_unknown_fields.py` covering
  these two modules passes unmodified, with unmodified expected codes and messages.
- **New** regression tests, both required (Round 2 review found the first alone pins only
  one of two independent ordering dependencies — a refactor that collapsed member-set
  checking into `_validate_shape` at the body level only, leaving the entry level deferred,
  would still pass a test covering only the first case):
  1. A revocation snapshot with an unrecognized wrapper-level member (an extra top-level key
     beside `revocation_list`/`signature`) *and* a body-level type defect (e.g.
     `published_at` as a string) in the same input still reports `REVOCATION_SNAPSHOT_INVALID`
     (the type defect), not `UNKNOWN_FIELD`.
  2. A revocation snapshot with an unrecognized member inside a body-level `entries[]` item
     *and* a type defect on that same entry (e.g. `jti` as an int) still reports
     `REVOCATION_SNAPSHOT_INVALID`, not `UNKNOWN_FIELD` — pinning the entry-level ordering
     dependency (`revocation.py:140` vs. `:157`) separately from the body-level one above.
- New unit tests for `check_types`/`require_members`/`canonical_bytes`/`decode_b64url`
  directly, independent of any artifact module: `check_types` rejects wrong-type input
  (including the bool/int and integral-float edge cases) with the right code;
  `require_members` rejects missing-required input; `canonical_bytes` converts a
  `JcsError`-triggering input (`float('inf')`, a 400-digit int) to the given `shape_code`;
  `decode_b64url` converts both alphabet and length defects.

**Tests:** `tests/test_fields.py` (new, if it doesn't already exist — confirm during
implementation) for the four helpers directly; the new cross-level ordering regression test
described above; full existing suite (`pytest tests/`, `run_conformance.py`) re-run to prove
the refactor is behavior-preserving.

**Docs:** `fields.py`'s module docstring gains a short note on what the two new shape
helpers own — and, explicitly, what they deliberately do not own (member-set-check ordering
stays each caller's own decision, not something this module imposes).

---

### Phase 3 — `manifest.py` hardening (issue #23, items 1 "manifest.py", 2, 4)

**Status:** TODO

**Delivers:** The three manifest-specific gaps close: `canonicalize(body)` at
`manifest.py:155` no longer lets `JcsError` escape; `proof_of_possession.challenge`'s
base64url grammar is validated before use (not just its Python type); `identity_hint`'s
conditional requirements (`oidc` ⇒ `issuer` required + `public_key` forbidden; else ⇒
`public_key` required), `type` enum (`oidc`/`pinned_key`), and `public_key` pattern
(`^[A-Za-z0-9_-]{43,44}$`) are enforced.

**Depends on:** Phase 2 (uses `canonical_bytes`; the `challenge` grammar check is folded
into the existing `_shape` structural pass, which itself now calls Phase 2's `check_types`/
`require_members`). Benefits from, but does not strictly require, Phase 1's regression test
being in place first.

**Files:**
- `aitp_verifier/manifest.py`

**Approach:** Wrap the signature-covering canonicalize call:
`canonical_bytes(body, shape_code="MANIFEST_INVALID", what="manifest")` in place of the bare
`canonicalize(body)` at line 155. For the PoP challenge, validate its base64url grammar
inside the structural pass (alongside `_shape`'s existing type check, which already confirms
`challenge` is a `str`) rather than at the `b64url_decode` call site at line 150 — this keeps
the module's documented ordering intact ("shape → version → expiry → proof-of-possession →
signature", `manifest.py:3`): a grammar defect is a structural defect, and the registry
(`registries/error-codes.md:115`) explicitly scopes `MANIFEST_INVALID` to include "a value
outside its grammar", not only presence/type. Rejected alternative: wrapping
`b64url_decode(pop["challenge"])` in a local try/except at line 150 with
`sig_err="MANIFEST_POP_FAILED"` — rejected because the registry is explicit that a
structural defect must not be reported as a signature-family code ("the signature was never
reached"), and `MANIFEST_POP_FAILED` is exactly that family. Add the IdentityHint
conditional-requirement, enum, and pattern checks as an explicit block immediately after the
existing `_shape(man["identity_hint"], ...)` call at line 129-130, all raising
`MANIFEST_INVALID` (the registry code already used for every other Manifest grammar defect —
no new code needed).

**Edge cases & failure modes:** `challenge = ""` (empty string) — confirm whether
`b64url_decode("")` succeeds (decodes to `b""`) or should itself be treated as a grammar
defect; check `b64.py`'s actual behavior for the empty string during implementation and
write a test pinning whichever is correct, don't assume. `identity_hint.type` absent
entirely — the existing `_REQUIRED_IDENTITY_HINT_FIELDS = ("type", "subject")` already
requires it, so the conditional block only runs once `type` is confirmed present; order the
enum check before the oidc/else branch so an unrecognized `type` value reports the enum
violation, not a spurious "public_key required" for a type that isn't even valid.

**Acceptance criteria:**
- `extensions: {"x": <a value produced by `json.loads("1e400")`>}` and
  `published_at: <a value produced by `json.loads("1" + "0"*400)`>` each cause
  `verify_manifest` to raise `AitpError(code="MANIFEST_INVALID")`, not a raw `JcsError` or
  `OverflowError` — reproduced both via direct `verify_manifest` call and via
  `verify_handshake_payload` on a self-signed `mutual_hello` manifest (proving the
  end-to-end remote-input path from the issue's own reproduction, not just the unit-level
  one).
- `challenge = "x"` and `challenge = "a:b"` each cause `verify_manifest` to raise
  `AitpError(code="MANIFEST_INVALID")`, not a raw `binascii.Error`/`ValueError`.
- A manifest with `identity_hint = {"type": "oidc", "subject": "s", "public_key": "..."}`
  (missing required `issuer`, carrying forbidden `public_key`) raises `MANIFEST_INVALID`.
- A manifest with `identity_hint = {"type": "pinned_key", "subject": "s"}` (missing required
  `public_key`) raises `MANIFEST_INVALID`.
- A manifest with `identity_hint.type = "bogus"` raises `MANIFEST_INVALID`.
- A manifest with a `public_key` that doesn't match the pattern raises `MANIFEST_INVALID`.
- Every existing `man-*` conformance fixture passes unmodified. Every existing
  `tests/test_unknown_fields.py` manifest test passes unmodified **except**
  `test_manifest_identity_hint_known_fields_accepted` (`test_unknown_fields.py:443-450`),
  which today asserts `identity_hint = {"type": "oidc", "issuer": ..., "subject": "s",
  "public_key": "k"}` is *accepted* — confirmed live during this plan's review round, and
  that is precisely the under-enforcement issue #23 item 4 reports (the schema's own
  `$defs/IdentityHint` `if/then/else` forbids `public_key` when `type == "oidc"`). This
  phase deliberately flips that test's expectation: rewrite it to use two known-good
  fixtures (an `oidc` entry without `public_key`, and a `pinned_key` entry with one) instead
  of the single combined shape it uses today. Log this accept→reject behavior change
  explicitly in `ASSUMPTIONS.md` at implementation time — it is a correct, intentional fix,
  but a real behavioral flip for any caller relying on the old under-enforcement, not a pure
  addition (see also this plan's Open questions section).

**Tests:** new cases added to whichever manifest-focused test module is idiomatic here
(check whether `tests/test_unknown_fields.py` already has a manifest section to extend, per
its existing per-artifact-block structure, or whether a new `tests/test_manifest.py` is
warranted — there is currently no dedicated manifest test file, only conformance +
signed-examples + the shared unknown-fields suite; decide based on what's actually there
when implementing, this is a "consequential but decidable" call per the autonomy ladder).

**Docs:** `manifest.py`'s module docstring (lines 1-11) gains a note on the challenge-grammar
and IdentityHint-conditional checks if its current wording implies shape validation stops at
type-checking (re-read it during implementation and update only if it's actually made stale).

---

### Phase 4 — `envelope.py` hardening (issue #23, item 1 "envelope.py", plus adjacent completeness gaps)

**Status:** TODO

**Delivers:** `envelope.py` gains the required-member/type validation it currently lacks
entirely (today it has only `reject_unknown_fields`, which checks the member *set*, never
presence or type); `envelope_signing_input`'s `canonicalize(env["payload"])` call no longer
lets `JcsError` escape; `parse_aid(env["sender"]["agent_id"])` no longer lets a bare
`ValueError` escape. The `canonicalize`-escape fix closes that one gap for both of
`envelope_signing_input`'s callers — `envelope.py:62` (`verify_envelope`) and
`handshake.py:97` (`_verify_bootstrap`) — since it's a shared function. **Correction from
this plan's review round**: the required-member/type validation and the `parse_aid` guard
added here apply only to `verify_envelope` itself — `handshake.py` never calls
`verify_envelope`, it dereferences `env["message_type"]`/`env["payload"]`/`env["sender"]`
directly with the same class of gap. That direct-dereferencing gap is closed separately, in
Phase 6, which already touches `handshake.py` and is the natural place for it.

**Depends on:** Phase 2 (`require_members`, `check_types`, `canonical_bytes`).

**Files:**
- `aitp_verifier/envelope.py`

**Approach:** Add `_ENVELOPE_TYPES`/`_REQUIRED_ENVELOPE_FIELDS` and
`_SENDER_TYPES`/`_REQUIRED_SENDER_FIELDS` tables mirroring `manifest.py`'s established
convention (confirmed required members by reading every direct dereference in the module:
`version`, `message_type`, `message_id`, `timestamp`, `sender`, `payload`, `signature` are
all read without a presence guard today; `extensions` stays optional per RFC-AITP-0012 §1).
Call `require_members` then `check_types` (in that order, before the existing
`reject_unknown_fields` calls) at `envelope.py:54-55`, mirroring `manifest.py::_shape`'s own
per-object interleaved ordering (presence → type → member-set) rather than
`revocation.py`'s deferred one, since `verify_envelope` — like `manifest.py` — validates one
flat object at a time rather than a nested tree. Rewrite `envelope_signing_input` (line
35-38) to call `canonical_bytes(env["payload"], shape_code="INVALID_ENVELOPE",
what="envelope.payload")` instead of the bare `canonicalize(env["payload"])` —
`INVALID_ENVELOPE` unconditionally, regardless of caller, since this is a defect in the
envelope artifact itself and the registry assigns that code to both "Envelope" and
"Handshake payload" (confirmed: `registries/error-codes.md` rows cited by the issue-#23
analysis agent). Wrap `parse_aid(env["sender"]["agent_id"])` at line 60 in the same
`try/except ValueError` pattern `manifest.py:139-146` and `revocation.py:164-167` already
use, raising `INVALID_ENVELOPE`. This is the right fix, not a patch, because it brings
`envelope.py` up to the same structural-completeness bar `manifest.py` and `revocation.py`
already meet, using the Phase 2 helpers specifically so the third and fourth near-duplicate
implementation this codebase would otherwise accumulate never gets written.

**Edge cases & failure modes:** `timestamp` as a huge int (`10**400`) must be caught by the
new type/shape table before `int(env["timestamp"])` at line 57 runs — confirm `check_types`
admits ordinary ints of any magnitude (Python has no int overflow) but the *comparison*
`abs(now - int(env["timestamp"]))` is fine since both are already-validated plain ints by
then; the actual hazard is `timestamp` as `1e400` (a `float`, rejected by the type table
before `int()` ever sees it) — verify this is genuinely closed, don't assume the shape check
alone prevents every arithmetic hazard without checking the call order. `sender` present but
not a dict is already caught by `reject_unknown_fields`'s (or `require_members`'s) own
non-dict guard today — confirm this still holds after the refactor rather than assuming it
does.

**Acceptance criteria:**
- An envelope missing any one of `version`/`message_type`/`message_id`/`timestamp`/`sender`/
  `payload`/`signature` causes `verify_envelope` to raise `AitpError(code="INVALID_ENVELOPE")`,
  not a raw `KeyError`.
- `payload: {"x": <1e400-derived value>}` and a payload containing a 400-digit int each
  cause `verify_envelope` (and `verify_handshake_payload` on a `mutual_hello`/`mutual_commit`
  built around the same envelope) to raise `AitpError(code="INVALID_ENVELOPE")`, not a raw
  `JcsError`.
- `timestamp: "not a number"` and `timestamp: <1e400-derived value>` each raise
  `AitpError(code="INVALID_ENVELOPE")`, not a raw `ValueError`/`OverflowError`.
- A malformed `sender.agent_id` (fails `parse_aid`) raises `AitpError(code="INVALID_ENVELOPE")`,
  not a raw `ValueError`.
- Every existing `env-*` conformance fixture and `tests/test_unknown_fields.py` envelope
  coverage still passes unmodified.

**Tests:** extend (or create) a dedicated envelope malformed-input test, following the exact
pattern `tests/test_sessionbundle.py:199-228`'s
`test_malformed_envelope_raises_aitp_error_not_a_traceback` already establishes for this
module (that test's docstring — "A library consumer feeding attacker-shaped input must get
an AitpError it can catch, not a TypeError" — states precisely this phase's acceptance bar;
reuse its parametrize style rather than inventing a new one).

**Docs:** `envelope.py`'s module docstring (lines 1-8) updated if it implies the schema is
enforced today (it currently only describes the signing-input formula, not shape
validation — check and update if misleading after the change).

---

### Phase 5 — `sessionbundle.py` hardening (issue #23, item 1 "sessionbundle.py", plus adjacent completeness gaps)

**Status:** TODO

**Delivers:** `sessionbundle.py`'s body- and participant-level required-member/type
validation is completed (today: `signature` presence/type is checked explicitly, but
`participants`, `expires_at`, `coordinator` are dereferenced directly with no guard, and
participant entries only get a member-*set* check, not a required-member check for `aid`/
`tct`); `canonicalize(signing_body)` at line 150 no longer lets `JcsError` escape;
`parse_aid(coordinator)` at line 146 no longer lets a bare `ValueError` escape.

**Depends on:** Phase 2 (`require_members`, `check_types`, `canonical_bytes`).

**Files:**
- `aitp_verifier/sessionbundle.py`

**Approach:** Add `_REQUIRED_BODY_FIELDS = ("version", "session_id", "coordinator",
"issued_at", "expires_at", "participants", "signature")` (all of `_BODY_FIELDS` except
`extensions`, confirmed optional per the module's own RFC-AITP-0012 §1 comment) and a
`_BODY_TYPES` table (`version`/`session_id`/`coordinator`/`signature`: `str`; `issued_at`/
`expires_at`: `int`; `participants`: `list`; `extensions`: `dict`), plus
`_REQUIRED_PARTICIPANT_FIELDS = ("aid", "tct")` with `_PARTICIPANT_TYPES = {"aid": (str,),
"tct": (str,)}` (confirmed both are dereferenced directly at lines 141/154/189/192 with no
presence guard today). Route the existing manual checks at lines 106-125 and the
per-participant loop at 128-131 through `require_members` + `check_types` (called in that
order, before each object's own `reject_unknown_fields`, matching `manifest.py`'s
interleaved convention Phase 4 also adopts — not revocation.py's deferred one) instead of
the current mix of explicit `if`/`reject_unknown_fields` calls — preserving the deliberate
two-tier wrapper-vs-body distinction the module's own inline comments (lines 72-114,
immediately inside `verify_session_bundle` — the module-level docstring itself is lines
1-39) already document in detail (the wrapper keeps its own
`SESSION_BUNDLE_INVALID`-vs-implicit-not-`UNKNOWN_FIELD` handling exactly as today; only
the body/participant tier gains the new completeness checks). Wrap
`canonicalize(signing_body)` at line 150 with `canonical_bytes(signing_body,
shape_code="SESSION_BUNDLE_INVALID", what="session bundle body")`. Wrap
`parse_aid(coordinator)` at line 146 in `try/except ValueError` raising
`SESSION_BUNDLE_INVALID`, matching the established pattern.

**Edge cases & failure modes:** the module's documented verification order (shape → version
→ expiry → invariant → signature → per-participant, per its own docstring lines 14-35) MUST
be preserved — the new required/type checks belong in the existing shape-validation stage
(before the `version`/expiry checks at lines 133-137), not scattered later, or `bundle-003`'s
"expiry runs before signature even when both are wrong" invariant could silently reorder.
Confirm `bundle-003`'s fixture still resolves to `BUNDLE_EXPIRED` (not a new structural code)
after the change — a malformed-AND-expired bundle should still report expiry only if its
shape is otherwise valid; a malformed-AND-expired bundle where the malformation is what this
phase newly catches should report the new structural code instead, consistent with the
module's own stated precedence ("shape precedes expiry deliberately"). `issued_at` is
confirmed unused by any comparison in the module (only carried through into the signed
body) — its new type check exists for completeness/fail-fast reasons, not because a specific
crash it prevents currently exists beyond the `canonical_bytes` wrap already covering it;
note this explicitly rather than overclaiming a crash-preventing benefit for that one field.

**Acceptance criteria:**
- A bundle body missing `participants`, `expires_at`, or `coordinator` causes
  `verify_session_bundle` to raise `AitpError(code="SESSION_BUNDLE_INVALID")`, not a raw
  `KeyError`.
- `participants: 5` and `expires_at: "soon"` each raise `AitpError(code=
  "SESSION_BUNDLE_INVALID")`, not a raw `TypeError`/`ValueError`.
- `session_bundle.extensions = {"x": <1e400-derived value>}` and `issued_at` set to a
  400-digit int each raise `AitpError(code="SESSION_BUNDLE_INVALID")`, not a raw `JcsError`.
- A malformed `coordinator` AID raises `AitpError(code="SESSION_BUNDLE_INVALID")`, not a raw
  `ValueError`.
- A participant entry `{}` (missing both `aid` and `tct`) raises `AitpError(code=
  "SESSION_BUNDLE_INVALID")`, not a raw `KeyError`.
- `bundle-003`'s expiry-before-signature ordering invariant still holds (re-run its exact
  fixture and confirm the same code as before the change).
- Every existing `bundle-*` conformance fixture, `tests/test_sessionbundle.py`, and
  `tests/test_unknown_fields.py` bundle coverage still passes unmodified.

**Tests:** extend
`tests/test_sessionbundle.py::test_malformed_envelope_raises_aitp_error_not_a_traceback`'s
parametrize list with the new cases (missing/mistyped body members, missing participant
members, the `1e400`/huge-int canonicalize cases, malformed coordinator).

**Docs:** `sessionbundle.py`'s module docstring's verification-order description (lines
14-35) updated only if the new checks change where in that prose the structural gate is
described — likely a one-line addition noting participant/body completeness is now enforced
there, not a rewrite.

---

### Phase 6 — `handshake.py`: validate before dereferencing, at both the dispatcher and the bootstrap payload (issue #23, item 3, plus a review-round finding)

**Status:** TODO

**Delivers:** Two gaps in the same module close together, both the same "reads before
validating" class of bug: (1) — **new in this phase, found during this plan's review
round** — `verify_handshake_payload`'s dispatcher (lines 50-64) dereferences
`inp["envelope"]` (line 57) and `env["message_type"]` (line 58) with no presence/type guard
before deciding which sub-verifier to call, and `_verify_bootstrap`/`_verify_commit`
similarly dereference `env["payload"]`/`env["sender"]` without one — none of this is covered
by `envelope.py`'s own Phase 4 hardening, because `handshake.py` never calls
`verify_envelope()`, it parses the envelope shape itself, inline, so a malformed envelope
reaching this module crashes with a raw `KeyError` regardless of what Phase 4 does. (2) —
the plan's original finding — `_verify_bootstrap` no longer crashes with a raw `KeyError`
when `payload["manifest"]` or `payload["identity"]` is absent, and no longer crashes with a
raw `AttributeError` when `identity` is present but not a dict — closing the reachability
gap that makes `identity.py`'s own non-dict guard (`fields.py`'s `reject_unknown_fields`
inside `verify_identity`) unreachable in production, since the crash today happens three
lines upstream of it.

**Depends on:** none. **Correction from this plan's review round**: the original "Depends
on: Phase 2 conceptually" was inaccurate — this phase's checks are written as direct,
explicit guards (see Approach), not calls into Phase 2's helpers, so nothing here is
actually blocked on Phase 2 landing first; it could ship before or after it.

**Files:**
- `aitp_verifier/handshake.py`

**Approach:** Add an explicit presence-and-type check for `inp["envelope"]` at the top of
`verify_handshake_payload`, before line 57, raising `AitpError("INVALID_ENVELOPE", ...)` for
a missing or non-dict envelope — this only applies to the non-`peer_a`/`peer_b` branch
(lines 51-55 already handle that shape separately and never touch `env`, so the new check
must run only once that branch is ruled out, matching the function's existing control
flow). Add the same kind of check for `env["message_type"]` immediately after (line 58),
before it's used to decide the `_verify_bootstrap` vs. `_verify_commit` dispatch (lines
59-63) — placing it after that dispatch decision would defeat the point, since the crash it
prevents happens at the dispatch step itself. Add presence checks for `env["payload"]` and
`env["sender"]` wherever each is first dereferenced in `_verify_bootstrap`/`_verify_commit`.
All of these raise `INVALID_ENVELOPE`, matching the registry's code for "Handshake payload".

Then, as originally planned: insert an explicit presence check for `manifest`/`identity`
immediately after the existing `reject_unknown_fields(payload, allowed, ...)` call at line
70 (which validates the payload's member *set* but not which of those optional-looking
members are actually required), raising `AitpError("INVALID_ENVELOPE", ...)` for either
missing. Then check `isinstance(identity, dict)` immediately after `identity =
payload["identity"]` (line 78), raising `AitpError("IDENTITY_FAILED", ...)` for a non-dict —
deliberately `IDENTITY_FAILED`, not `INVALID_ENVELOPE`, because this field *is* the identity
descriptor `identity.py:93`'s own `reject_unknown_fields` call already uses
`shape_code="IDENTITY_FAILED"` for the identical defect; making the guard reachable here
should preserve the code it was designed to emit, not invent a new one. Do **not** add a
symmetric dict-check for `manifest` — `verify_manifest`'s own `_shape` (via Phase 2's
`require_members`/`check_types`, once that phase lands — or the module's pre-Phase-2 `_shape`
if this phase ships first) already raises `MANIFEST_INVALID` for a non-dict manifest at the
very first line of its own structural pass (`manifest.py:81-82` today), called immediately
after at line 74, so a second check here would be redundant, not defensive.

All of this stays a set of small, targeted, explicit checks rather than routing through a
single generic helper — different fields here need different codes on a type violation
(`INVALID_ENVELOPE` for the envelope-level fields and for bare presence of
`manifest`/`identity`; `IDENTITY_FAILED` specifically for `identity`'s own type violation),
and forcing them through one call with a single `shape_code` parameter would be less
correct, not more reusable — matching this module's existing style of explicit, narrowly-
scoped checks (e.g. the ACK nonce-echo check at lines 101-103) rather than table-driven
validation.

**Edge cases & failure modes:** every new check must run strictly before the dereference it
protects — the envelope/message_type checks before line 57-58's own use, the payload/sender
checks before their first use in `_verify_bootstrap`/`_verify_commit`, and the
manifest/identity checks before lines 71/78/81 as originally planned. Confirm the existing
`reject_unknown_fields` calls (line 70, and whichever cover `env`/`payload` today) still run
at their current point in the sequence — this phase adds *presence* checks alongside them,
it does not reorder any existing member-set check.

**Acceptance criteria:**
- A call to `verify_handshake_payload` with `inp["envelope"]` missing or not a dict raises
  `AitpError(code="INVALID_ENVELOPE")`, not a raw `KeyError`/downstream `AttributeError`.
- The same with `env["message_type"]` missing raises `AitpError(code="INVALID_ENVELOPE")`,
  not a raw `KeyError`.
- The same with `env["payload"]` or `env["sender"]` missing (for whichever message type
  reaches that dereference) raises `AitpError(code="INVALID_ENVELOPE")`, not a raw
  `KeyError`.
- A `mutual_hello`/`mutual_hello_ack` payload missing `manifest` raises `AitpError(code=
  "INVALID_ENVELOPE")`, not a raw `KeyError`.
- The same payload missing `identity` raises `AitpError(code="INVALID_ENVELOPE")`, not a raw
  `KeyError`.
- A payload where `identity` is a string, list, int, or `None` raises `AitpError(code=
  "IDENTITY_FAILED")`, not a raw `AttributeError`.
- `identity.py`'s own `reject_unknown_fields` non-dict guard remains correctly unreachable
  in production for this call path (it's now redundant-but-harmless dead code reached only
  via `verify_identity`'s direct-call test path — this is fine and expected, not a defect to
  chase further; note it in the phase's `PROGRESS.md` entry rather than trying to also
  "fix" `identity.py` itself, which is out of scope).
- Every existing `mh-*`/`env-*`-via-handshake conformance fixture and handshake-related unit
  test still passes unmodified.

**Tests:** new cases in whichever test module already covers `handshake.py`'s malformed-
input handling (check `tests/test_unknown_fields.py` for an existing handshake-payload
section to extend, consistent with Phase 3's approach to `manifest.py`) — covering both the
new dispatcher-level envelope/message_type/payload/sender cases and the original
manifest/identity cases.

**Docs:** none (the module docstring's described order — "Manifest PoP + signature run
first ... then the identity-hint/identity type match" — is unchanged; this phase makes an
already-documented ordering crash-safe, it doesn't change the ordering).

---

### Phase 7 — Generic boundary-contract regression test (spans issue #23's whole class)

**Status:** TODO

**Delivers:** `tests/test_boundary_contract.py` (new): a parametrized regression harness
that, for every public verifier entry point, mutates known-answer conformance-fixture input
at each JSON path with a fixed set of hostile values, **re-signs via `mint_input`** (so the
mutation reaches the code under test instead of being rejected earlier by a signature
check — the load-bearing design point both analysis agents independently identified), and
asserts the result is always either an `AitpError` or a `dict` verdict — never a bare Python
exception. This is the capstone that pins the entire class of bug Phases 3–6 closed, so a
future change that reopens any one of them fails a single, obviously-named test instead of
waiting for another adversarial review pass.

**Depends on:** Phases 2–6 (written last on purpose — it is expected to be RED before those
land, and is the phase that proves they're done).

**Files:**
- `tests/test_boundary_contract.py` (new)

**Approach:** Cover every entry in `aitp_verifier/verify.py`'s `OPERATIONS` dispatch table
(`verify_envelope`, `verify_manifest`, `verify_tct`, `verify_grant_voucher`,
`verify_delegation_token`, `verify_revocation_snapshot`, `verify_handshake_payload`,
`verify_session_bundle` — confirmed this is the authoritative list, not the package
`__init__.py`, which exports modules rather than functions), plus `identity.verify_identity`
directly (confirmed it's public and has no other path that would otherwise exercise its
guards, per Phase 6's finding). For each conformance fixture and each JSON path within its
`input`, apply each of a fixed mutation set — `None`, `[]`, `{}`, `""`, `0`, `True`,
`json.loads("1e400")` (→ `float('inf')`), `json.loads("1" + "0"*400)` (a huge int),
`"a:b"`, `"x"` (both invalid-base64url shapes), and a delete-the-key sentinel — re-sign the
mutated input through `mint_input` (reusing `run_conformance.py`'s own
`keys.load_kat_keys`/`minter.mint_input` plumbing, already proven against every fixture in
this suite), call the corresponding `OPERATIONS[op]`, and assert either an `AitpError` is
raised or a `dict` is returned — nothing else. This is the right design, not merely a working
one, because a harness that mutates without re-signing would find none of these bugs (the
mutation would trip a signature-mismatch error long before reaching the code Phases 3-6
fixed) — confirmed by the issue-#23 analysis agent's own repro process, which only surfaced
the bugs once it started re-signing after mutating.

**Mutation-target scope, corrected during this plan's review round.** The original design
mutated *any* JSON path in `input`, including its top level. That is unsatisfiable: verified
live, deleting a top-level call-argument key (`tct_token`, `envelope`, `manifest`,
`session_bundle`, `delegation_token`, `policy`, `snapshot`, `self_aid`, and similarly
`inp["envelope"]`/`env["sender"]` before this plan's Phase 6 lands) raises a raw `KeyError`
on every one of the 8 `OPERATIONS` entries — a defect in the *Python calling convention*
these functions use, not in any AITP wire artifact, and none of issues #23-#27 are about
that boundary. Scope every mutation to paths **inside** each entry point's artifact-bearing
argument (inside `envelope`, inside `manifest`, inside `session_bundle`, inside `snapshot`,
inside the decoded claims of `tct_token`/`delegation_token`) — never to the top-level
call-argument keys themselves. This is not a weaker test: every gap Phases 3–6 actually
close is reachable this way (`extensions`, `challenge`, `participants`, `coordinator`,
`identity`, `message_type` are all nested at least one level below the excluded top-level
keys), so the revert-criterion below still holds within this scope. Two of Phase 6's
guards specifically (`env["sender"]["agent_id"]`, `env["payload"]`/`message_id`/`timestamp`)
are *not* reachable via this harness — `minter.py:130-132`/`:303` dereference those same keys
by bracket access during minting itself, so a mutation deleting them dies inside
`mint_input` and is skipped (see Edge cases below), before ever reaching the verifier. That
is fine: Phase 6's own direct-call unit tests (not this harness) are what actually prove
those two guards, so this phase's revert-criterion is scoped to the guards enumerated above,
not claimed for the full list of everything Phase 6 touches.

Beyond that exclusion, scope the combinatorial size deliberately: even the in-scope surface
— dozens of conformance fixtures × ~11 mutations × every interior JSON path — is large
enough to matter for CI time. Cap it — e.g. sample a bounded number of paths per fixture (or
restrict to paths at or under `extensions`/scalar leaf fields specifically, since those are
exactly where the fixed-shape upstream checks Phases 3-6 added cannot reach) rather than
exhaustively walking every interior path of every fixture. This is a "consequential but
decidable" call (Autonomy ladder) — decide the concrete sampling/capping strategy during
implementation and record the reasoning in `ASSUMPTIONS.md` if the choice is anything other
than "exhaustive within the in-scope path set, but only within `extensions` and untyped leaf
fields."

**Note on `voucher.py`:** it is in the `OPERATIONS` table (`verify.py:22`) but was not
independently deep-audited by either background agent that grounded issues #23/#24 — their
investigations were scoped to the artifacts those two issues actually name. If this phase's
sweep surfaces a genuine finding in `voucher.py` (or in `jws.py`'s own guarantees), that is
legitimate new-scope discovery to close via the normal implement-time gap-closing loop, not
evidence this plan under-scoped itself — note any such finding in `PROGRESS.md` when it
happens rather than silently folding a `voucher.py` fix into this phase's own diff.

**Edge cases & failure modes:** a mutation that makes `mint_input` itself raise
`MinterError`/`KeyError`/`JcsError` (e.g. because the mutated field was required for
minting, like an AID `mint_input` needs to look up a signing key for) should be treated as
"not a reachable case for this mutation at this path" and skipped, not treated as a test
failure — mirror `run_conformance.py:129-132`'s own `except (MinterError, KeyError): SKIP`
handling, **widened to also catch `JcsError`**: unlike `run_conformance.py`'s own fixtures
(which never carry a hostile numeric value), this harness's `1e400`/400-digit-int mutations
can land on a field the minting step itself canonicalizes (e.g. inside `_sign_manifest`,
`_sign_envelope`, or `_sign_revocation`) — `JcsError` there is a `ValueError`, not a
`MinterError`/`KeyError`, so the narrower except clause would let it escape `mint_input` and
fail the harness for the wrong reason (a minting-time artifact, not a verifier-contract
violation). A mutation that legitimately produces a *correct* `AitpError` (the
overwhelmingly common case — most mutations should be correctly rejected) is a **pass**, not
a finding; the test only fails on an exception that is neither `AitpError` nor a normal
return.

**Acceptance criteria:**
- The new test file runs all 9 entry points against the full mutation set (or the
  documented, ASSUMPTIONS.md-recorded sampled subset) and is green after Phases 2–6 land.
- Temporarily reverting any one of Phases 3, 4, 5, or 6 locally (to confirm the test
  actually depends on them, not just coincidentally passes) makes at least one case in this
  new test fail — verify this by hand for at least one phase before considering Phase 7
  done, the same way Phase 1's acceptance criteria requires a hand-verified regression.
- No case in the suite ever reports a bare Python exception type (`TypeError`, `KeyError`,
  `AttributeError`, `ValueError`, `OverflowError`, `binascii.Error`) as a test failure
  reason — every failure line, if any exist at merge time, names the concrete gap still
  open.

**Tests:** this phase *is* the test; no further separate test doc needed.

**Docs:** none.

---

### Phase 8 — Close the revocation-snapshot trust gap in `tct.py`/`delegation.py` (issue #24)

**Status:** TODO

**Delivers:** `tct.py::_check_revocation` and `delegation.py::_revocation_index`/
`_verify_multihop`'s revocation lookup both route through the same structural + member-set +
signature verification `revocation.py::verify_revocation_snapshot` already performs, instead
of trusting a bare `.get()`-chained, unauthenticated snapshot. `minter.py` gains the ability
to correctly sign both consuming paths' fixtures, so the conformance pack's `tct-004-revoked`
and `del-mh-004-revoked-hop` continue to pass — now because the check is real, not because
it's absent.

**Depends on:** Phase 2. **Correction from this plan's review round**: the original
"Depends on: none, independent of Phases 1-7" was false — this phase edits
`revocation.py`'s `_validate_shape`/member-set/signature code (lines 100-141, 150-182), the
exact lines Phase 2 refactors first. Sequencing Phase 8 after Phase 2 means the extraction
below starts from the already-`check_types`/`require_members`-based version, not the
pre-refactor original, avoiding two refactors of the same lines in two different phases.

**Files:**
- `aitp_verifier/revocation.py` — extract stages (a) shape [itself now calling Phase 2's
  `check_types`/`require_members`], (b) member-set, (c) signature (currently
  `_validate_shape` at lines 100-141 plus inline code at lines 150-182) into a new exported
  `verify_snapshot_trust(snapshot: Any) -> dict[str, Any]`, returning the verified
  `revocation_list` body. **No `expected_issuer` parameter** — see Approach for why this
  differs from the plan's original design. `verify_revocation_snapshot` itself collapses to
  call this helper for stages (a)-(c), leaving stage (d) (issuer/freshness/`fail_mode`/
  deny-list query, lines 184-198 — including today's own `issuer_ok` comparison at line
  188) untouched — a **zero** externally-observable change to `verify_revocation_snapshot`'s
  own behavior, verified by the existing `rev-*` conformance fixtures and
  `tests/test_unknown_fields.py`'s seven revocation tests passing unmodified.
- `aitp_verifier/tct.py` — `_check_revocation` (lines 104-111) rewritten to call
  `body = verify_snapshot_trust(revlist.get("snapshot"))` (using `.get()`, not `["snapshot"]`
  — see Approach), then, only if `body["issuer"] == claims.get("iss")`, scan `body["entries"]`
  for `claims.get("jti")`.
- `aitp_verifier/delegation.py` — `_revocation_index` (lines 110-117) rewritten to call
  `body = verify_snapshot_trust(record.get("snapshot"))` per record and index on the
  **returned, signature-verified** `body["issuer"]` rather than the caller-supplied
  `record.get("issuer_aid")` (closing the additional gap the #24 analysis surfaced: today
  the index is keyed on unverified caller input, so even a correctly-signed snapshot could
  be filed under the wrong issuer).
- `aitp_verifier/minter.py` — `_sign_revocation` (line 165) widen the placeholder allow-list
  to include `__VALID_B_SIG__` (already keys the signing key off `body["issuer"]`, so no
  other change needed there); `mint_input` (lines 379-384) gains a loop over
  `d.get("revocation_snapshots", [])`, signing each record's `snapshot` the same way the
  existing `snapshot`/`issuer_revocation_list` holders are signed.
- `tests/test_unknown_fields.py` — new negative-path tests through `verify_tct` and
  `verify_delegation_token` specifically (not just `verify_revocation_snapshot`, which
  already has this coverage), extending the file's existing revocation test block.

**Approach:** Extract-and-share, not call-`verify_revocation_snapshot`-directly — confirmed
this is right, not merely convenient, for three independently-sufficient reasons found while
reading `verify_revocation_snapshot`'s actual signature: (1) it requires `inp["policy"]`
unconditionally (`revocation.py:145`, `int(policy["max_staleness_secs"])` at line 189 with
no `.get()`), and neither `tct-004`'s wrapper shape nor `del-mh-004`'s per-hop record shape
carries a policy at all — calling it directly would `KeyError` on both, and inventing a
default would silently impose a staleness policy on two call sites the spec does not scope
that way; (2) it returns `{"revoked": bool, ...}`/raises `TCT_REVOKED` even for staleness,
which would surface the wrong code in `delegation.py` (`DELEGATION_SOURCE_TCT_REVOKED` is
that module's own code, and staleness would become indistinguishable from an actual deny-
list hit); (3) it answers about one `queried_jti`, while `delegation.py` needs a whole
per-issuer entry set queried repeatedly across hops. This is also the precedent this exact
codebase already set today, in the PR that merged hours before this plan was written:
`check_tct_claims_shape` (`tct.py:46-65`) was extracted from `verify_tct` into a helper
*owned by the artifact's own module*, exported, and imported by the other two modules that
inline-verify the same artifact shape (`handshake.py`, `sessionbundle.py`) — with the shape
check shared and each caller's own containment/remapping logic staying local to its call
site. `verify_snapshot_trust` is the same pattern applied to revocation snapshots.
`delegation.py`'s error-code mapping: let `verify_snapshot_trust`'s own codes
(`REVOCATION_SNAPSHOT_INVALID`/`UNKNOWN_FIELD`/`REVOCATION_SNAPSHOT_SIGNATURE_INVALID`)
propagate unremapped, rather than collapsing them into `DELEGATION_SOURCE_TCT_REVOKED` —
`fields.py`'s own docstring states the `sessionbundle.py` remap is "the single exception",
justified there by RFC-AITP-0010 §5 step 7's explicit containment text; RFC-AITP-0011 §6 (the
delegation multi-hop RFC) carries no equivalent clause, so manufacturing a remap here would
contradict the codebase's own stated policy on when remapping is allowed.

**Two design errors this plan's review round found in the original `verify_snapshot_trust`
sketch, corrected here:**

1. **`revlist["snapshot"]`/`record["snapshot"]` (bracket access) would reintroduce a raw
   `KeyError`** — exactly the class of bug Phases 3-6 close — if either key is absent, since
   today's code uses `.get("snapshot", {})` (`tct.py:108`, `delegation.py:115`), which never
   raises. The fix uses `.get("snapshot")` (returning `None` when absent) and relies on
   `verify_snapshot_trust`'s own first-line shape guard (`not isinstance(snapshot, dict)`,
   carried over unchanged from today's `_validate_shape`) to convert a `None` into the
   correct structural `AitpError` — the same pattern `manifest.py`/`envelope.py`/
   `sessionbundle.py` already use everywhere else in this plan. Likewise use
   `claims.get("iss")`, not `claims["iss"]`, in `tct.py` — `check_tct_claims_shape` does not
   itself require `iss` to be present, so a bracket access there would be a second new
   `KeyError` path this phase would otherwise introduce.
2. **The original design's `expected_issuer` parameter conflated two different things and
   made one acceptance criterion unreachable.** It would have made `verify_snapshot_trust`
   itself raise on an issuer mismatch — but the plan's own criterion ("the signed value wins
   when `record['issuer_aid']` disagrees with the snapshot's signed `issuer`") describes
   *re-keying*, not *rejecting*, and a function that raises on mismatch never gets the chance
   to re-key. **Fixed by dropping the parameter entirely** — `verify_snapshot_trust` does
   only stages (a)-(c) (shape, member-set, signature) and returns the verified body; each
   caller applies its *own* issuer semantics locally, which also turn out to differ
   correctly between the two callers: in `delegation.py`, there is no gate at all — the
   index is simply keyed on `body["issuer"]` instead of `record.get("issuer_aid")`, so "the
   signed value wins" holds by construction, trivially. In `tct.py`, a mismatched
   `body["issuer"]` vs. `claims.get("iss")` is **not** treated as a rejection either — it
   means this particular snapshot does not speak for this TCT's issuer, so the deny-list
   scan for it is simply skipped, preserving today's existing "no applicable snapshot"
   semantics rather than inventing a new rejection code for a case that isn't actually
   malformed (a signed-but-differently-issued snapshot is not a defective artifact).

**Edge cases & failure modes:** `tct.py:106-107`'s existing "absent or non-dict
`issuer_revocation_list` ⇒ silently skip the check" behavior is a **separate, adjacent**
fail-open gap (confirmed live: dropping the field from `tct-004`'s input makes `verify_tct`
return success) that RFC-AITP-0008 §3.1's `fail_closed` default arguably requires treating as
`TCT_REVOKED` when absent — matching `revocation.py:190-193`'s own absence-handling. This
plan explicitly does **not** fix that in this phase: it is a materially different, wider-
reaching behavioral change (it would require threading a `policy`/`fail_mode` concept into
`verify_tct`'s own input contract, which #24 doesn't ask for and which isn't scoped by any of
the five filed issues). Flag it here as a known, deliberately out-of-scope finding — file a
follow-up GitHub issue for it as part of this phase's own completion (not a code change), so
it isn't silently lost.

**A second, distinct behavior change, also deliberate and also to be called out on its own
in `PROGRESS.md`/`ASSUMPTIONS.md`, separate from the one above:** today, a `record`/`revlist`
whose `snapshot` is absent, `None`, malformed (non-dict), or present-but-lacking
`revocation_list`/`entries` all silently produce an empty (or skipped) entry set — via the
existing `.get(..., {})` chains, or (for the top-level `issuer_revocation_list` field itself)
the `tct.py:106-107` non-dict short-circuit. After this phase, `verify_snapshot_trust`'s own
shape validation hard-rejects every one of those `snapshot`-level cases (absent, `None`, or
structurally malformed) with an `AitpError`. This is intentional — it is the same class of
gap #24 exists to close, applied one level deeper — but it is not the same finding as the
"`issuer_revocation_list`/`revocation_snapshots` field absent entirely" fail-open gap above
(which stays a silent skip, deliberately deferred to the follow-up issue), and the two should
not be conflated in the phase's tracking-file entry: log this one as covering "the `snapshot`
sub-field, once its containing record is present," not "every possible absence."

**Acceptance criteria:**
- `verify_snapshot_trust` is exported from `revocation.py`, takes only `snapshot` (no
  `expected_issuer` parameter), and `verify_revocation_snapshot` itself is behaviorally
  unchanged (every `rev-*` fixture, every existing revocation unit test, passes with
  identical codes/messages).
- A forged/garbage signature on `issuer_revocation_list.snapshot` now causes `verify_tct` to
  raise `AitpError(code="REVOCATION_SNAPSHOT_SIGNATURE_INVALID")` rather than silently
  returning the same `TCT_REVOKED` verdict as a genuinely signed snapshot (reproduce the #24
  analysis agent's exact repro and confirm the new, correct behavior).
- The same for `revocation_snapshots[*].snapshot` via `verify_delegation_token`.
- Stripping the `signature` member entirely, or injecting an unknown member into the
  snapshot body, from either consuming path now raises the appropriate
  `REVOCATION_SNAPSHOT_INVALID`/`UNKNOWN_FIELD`, not a silent pass-through.
- A `revocation_snapshots` record whose `snapshot` is missing entirely (key absent, or
  `None`) raises the correct structural `AitpError`, not a raw `KeyError` — proving the
  `.get()`-not-`[]` fix actually holds.
- `record["issuer_aid"]` no longer determines the index key when it disagrees with the
  snapshot's own signed `issuer` — the signed value wins, verified by constructing a record
  whose `issuer_aid` names one AID while `snapshot.revocation_list.issuer` (correctly
  signed) names a different one, and confirming the entry is indexed under the *signed* AID.
- Malformed non-dict/non-list shapes at every level previously producing raw
  `AttributeError`/`TypeError` (per the #24 analysis agent's full reproduction list) now
  raise `AitpError` instead.
- `tct-004-revoked` and `del-mh-004-revoked-hop` conformance fixtures still resolve to
  `TCT_REVOKED`/`DELEGATION_SOURCE_TCT_REVOKED` respectively — now via a genuinely verified
  snapshot, not an absent check (confirm the minter changes make this a *real* pass, not
  coincidentally the same outcome for the wrong reason).
- A follow-up GitHub issue is filed (not fixed) documenting the fail-open gap when
  `issuer_revocation_list`/`revocation_snapshots` is absent entirely from `verify_tct`'s
  input, linking to this plan file's Phase 8 section for context.

**Tests:** new tests in `tests/test_unknown_fields.py`'s revocation block (or a sibling if
that file's structure doesn't fit): per-path negatives for forged signature, missing
signature, unknown body/entry member, missing required body member, wrong `version`, issuer
mismatch — each asserted through both `verify_tct` and `verify_delegation_token`; a
parametrized non-dict/non-list junk-shape sweep asserting `AitpError` (not a raw exception);
positive controls confirming `tct-004`/`del-mh-004` still reach their expected revoked
verdict post-fix.

**Docs:** `tct.py`'s module docstring (lines 1-12) and `delegation.py`'s module docstring
(lines 1-10) both gain a short note that revocation-snapshot consumption is now fully
verified (structural + member-set + signature), not just consulted — since both currently
describe check *ordering* but say nothing about the snapshot's own trustworthiness, which was
the actual gap.

---

### Phase 9 — `conftest.py`: fail loudly, not silently, when the spec repo is missing (issue #26)

**Status:** TODO

**Delivers:** Running `pytest` locally without the sibling spec repo cloned now fails loudly
(not a silent 73-test skip that still reports green), with an explicit, documented opt-out
for a deliberate no-spec run.

**Depends on:** none.

**Files:**
- `tests/conftest.py`

**Approach:** Change `spec_dir`'s fixture body (`tests/conftest.py:29-34`) so that, as the
**first statement in the fixture — before `_find_spec()` is ever called** — it checks
`os.environ.get("AITP_SPEC") == "none"` and, if so, skips immediately with a clearly-labeled
message stating this was a deliberate, explicitly requested no-spec run. **This ordering is
load-bearing, and was wrong in the plan's original design**: `_find_spec()`
(`conftest.py:22-26`) tries the sibling-directory convention *regardless* of `$AITP_SPEC`'s
value, so placing the opt-out check *inside* the `found is None` branch — the original
design — would never actually trigger on any machine that happens to have the sibling repo
checked out. Confirmed live during this plan's review round: `AITP_SPEC=/nonexistent` still
resolved via the sibling directory and ran the full 166-test suite here, meaning an opt-out
gated on "resolution already failed" is unreachable whenever a sibling checkout exists —
exactly the common case for a contributor working in this multi-repo workspace. With the
check moved to the top of the fixture, `AITP_SPEC=none` short-circuits unconditionally, independent of what else is on disk. When the opt-out isn't set, fall through to
`_find_spec()` as today, but with the failure branch changed to `pytest.fail(...)` (naming
both resolution paths) instead of `pytest.skip`. This is the right fix, not a shortcut,
because it preserves the one legitimate use case (a contributor deliberately wants to run the
subset of tests that don't need the spec checkout) while removing the accidental one (forgot
to clone the sibling repo, got a quietly-smaller green run). Rejected alternative: leaving
`pytest.skip` but adding a loud summary line — rejected because a summary line is still
something a human must notice and correctly interpret, where a hard failure cannot be missed
and requires no interpretation.

**Edge cases & failure modes:** CI itself must be unaffected — `ci.yml` always checks out the
spec repo, and every job that actually runs `pytest` (`conformance`, `floors`,
`cross-platform`) sets `AITP_SPEC` (`wheel-smoke-test` also checks out the spec repo but
never invokes `pytest` at all — it's unaffected for an unrelated reason, since it never
touches `conftest.py`'s fixture in the first place) — so this change should produce zero CI
behavior difference; confirm this by re-running the full local suite with `AITP_SPEC`
correctly set after the change and seeing identical pass counts to before. A contributor
with `$AITP_SPEC` pointing at a stale/wrong path (not simply unset, and not `"none"`) should
get the same loud failure, not a different, more confusing one — `_find_spec()` already
returns `None` uniformly for "not found" regardless of why, so this should fall out
naturally; confirm rather than assume.

**Acceptance criteria:**
- Running `pytest` with `$AITP_SPEC` unset and no sibling `agentidentitytrustprotocol`
  directory present fails the run (nonzero exit), with a message naming both resolution
  paths and the `AITP_SPEC=none` opt-out.
- Running `pytest` with `AITP_SPEC=none` explicitly set produces a skip (not a failure) for
  every spec-dependent test, with a message distinct from the old default-skip wording,
  clearly stating this was requested.
- Running `pytest` with `$AITP_SPEC` correctly set (or the sibling directory present)
  produces byte-identical pass/fail counts to before this phase.
- CI (`ci.yml`, unmodified by this phase) is unaffected — confirmed by this phase's own
  local verification run using the exact `AITP_SPEC` value `ci.yml` sets.

**Tests:** a small dedicated test (or a documented manual verification step, if a true
"pytest inside a pytest" test is awkward here — decide during implementation, note the
choice in `PROGRESS.md`) confirming both the new failure path and the new opt-out path
behave as specified; this may reasonably be a subprocess-invocation test
(`subprocess.run([sys.executable, "-m", "pytest", ...], env={...})`) rather than something
expressible as an ordinary fixture-level unit test, since the behavior under test is
`pytest`'s own collection/fixture-failure machinery.

**Docs:** any repo `README`/`CONTRIBUTING`-equivalent text describing how to run the test
suite gets a one-line update if it currently implies a bare `pytest` "just works" without
mentioning the spec-repo dependency — check for such a doc during implementation (none was
found as of this plan's writing, but confirm rather than assume) and add the line only if a
matching file with this kind of run instructions actually exists.

---

### Phase 10 — CI: a dedicated, visible signed-examples check (issue #27)

**Status:** TODO

**Delivers:** `.github/workflows/ci.yml` gains a separately named CI step/job that runs the
production verifiers over the committed spec `signed-examples/` fixtures — the same tests
Phase 1 fixed for the manifest case — as its own visible check, so a signing-input regression
in this repo shows up as a distinct red status instead of being buried inside the general
"conformance + tests + types" bundle.

**Depends on:** Phase 1 (the manifest signed-example test must actually drive the real
verifier before it's worth surfacing as a dedicated gate — running the pre-Phase-1 version as
a "named check" would still miss a manifest convention flip, defeating the point).

**Files:**
- `.github/workflows/ci.yml`

**Approach:** Add a new step inside the existing `conformance` job (not a wholly separate
job — a separate job would re-checkout both repos and re-install dependencies, pure overhead
for what's fundamentally a `pytest -k` subset of work already-installed in the same job) that
runs specifically `pytest tests/test_signed_examples.py -v` as its own named step, positioned
so its failure is attributable in the GitHub Checks UI independent of the broader "Unit
tests" step's outcome. Confirmed this repo's existing job-naming convention
(`.github/workflows/ci.yml`'s own extensive comments on why job/check names are chosen
carefully, e.g. the `conformance` job's comment on why it's deliberately not an `os` matrix,
to avoid silently renaming required-status-check contexts) — adding a *step* inside the
existing job, rather than a new top-level job, avoids introducing a new required-check name
that would need separate branch-protection configuration, while still making the step's
pass/fail independently visible in the job's own step-by-step log and summary. Do **not**
attempt to pull/build `aitp-rs` — explicitly out of scope per the issue's own stated
preference (needs a Rust toolchain, meaningfully heavier, and the issue names the
same-repo-verifier approach as the one to actually build).

**Edge cases & failure modes:** the new step must run after the existing "Install" step
(needs the package installed) and can run either before or after the existing "Conformance"/
"Unit tests" steps — decide placement based on fastest useful signal (this is cheap; running
it early gives a fast fail for exactly the regression class Phase 1 exists to catch, ahead of
the slower full suite) — a "consequential but decidable" ordering call, not one requiring
escalation. This addition must appear in all three jobs that already run the full test suite
identically (`conformance` matrix, `floors`, `cross-platform`) or be justified as
appearing in only one — decide and record the reasoning (duplicating it three times over
already-duplicated install/checkout steps may be pure noise if the general `pytest -q` step
already covers the same ground in those other jobs; a single clearly-surfaced step in the
primary `conformance` job, matrixed across Python versions like everything else in that job,
is likely sufficient — this is the phase's own call to make, not a default to assume without
checking the existing job structure first).

**Acceptance criteria:**
- `ci.yml` runs `test_signed_examples.py` as its own named, independently-attributable step
  (not merely folded into the bundled `pytest -q` step it's already part of).
- The new step's failure is distinguishable in the GitHub Checks UI from a failure in the
  general unit-test step, when either is examined in isolation (verify by locally reasoning
  through the workflow YAML's step structure, since a genuine CI failure isn't something to
  manufacture just to test this — confirm structurally, not by breaking CI on purpose).
- No new required-status-check context name is introduced without deliberately deciding
  whether branch protection needs updating to match (if a *new job* were added instead of a
  step — confirm the final approach doesn't do this unless intentionally decided and noted).
- The existing `conformance`/`floors`/`cross-platform`/`wheel-smoke-test` jobs' overall pass/
  fail semantics are otherwise unchanged — this phase adds visibility, it does not change
  what causes CI to go red.

**Tests:** none in the traditional sense (this phase's "test" is the CI workflow file
itself); verify by pushing the branch and observing the new step appear and pass in the
`/ship` phase's CI run.

**Docs:** none beyond the workflow file's own inline comments, which should explain the new
step's purpose the same way every other block in this heavily-commented file does (match the
existing documentation density — this file consistently explains *why*, not just *what*, for
every job/step).

---

## Long-term posture

- **Phase 2's `fields.check_types`/`require_members` are the one closest-to-shared-
  infrastructure decision in this plan — deliberately scoped narrower than the plan's first
  draft.** The original design was one monolithic `validate_shape` imposing a single fixed
  presence→type→member-set order on every caller; this plan's own review round found that
  order is not actually uniform across the codebase today (`manifest.py` interleaves
  member-set checking per object, `revocation.py` defers it to one pass over the whole
  tree — a real, deliberate difference, not drift), and the monolithic version would have
  silently changed `revocation.py`'s observable behavior on a specific, previously-untested
  input shape. The corrected design extracts only the genuinely-identical piece (the
  type-checking loop, and the required-member-presence check) and leaves member-set-check
  ordering as each caller's own decision, composed locally. This is narrower, and correct
  because of it: a bug in `check_types`/`require_members` is still load-bearing across every
  artifact that calls them, but there is no shared *ordering* decision left to get wrong on
  their behalf. Phase 2 is still scoped as a strictly behavior-preserving refactor of two
  already-correct, already-tested implementations, with its acceptance criteria requiring
  the full existing suite to pass unmodified plus one new test targeting the exact ordering
  case the original design would have silently changed.
- **Where a fast approach would create debt, named explicitly:** Phase 6's handshake.py fix
  deliberately stays a handful of small, explicit checks rather than routing through
  `require_members`/`check_types`, because the fields it guards need different error codes
  on a type violation — forcing uniformity there would trade correctness for a superficial
  consistency. This is the right call, not corner-cutting: the plan calls it out rather than
  silently taking the shortcut of "always use the shared helper everywhere," which would
  produce a wrong code on a real, reachable path.
- **Phase 8's fail-open gap (`issuer_revocation_list` absent ⇒ silent pass in `verify_tct`)
  is explicitly deferred**, not fixed, because closing it correctly requires deciding how
  `verify_tct`'s input contract should carry a `fail_mode`/policy concept it doesn't have
  today — a design question none of the five filed issues actually asks this plan to answer,
  and forcing an answer here risks a rushed, under-considered API shape for a function
  several other things already call. Filing the follow-up issue (part of Phase 8's own
  acceptance criteria) is the correct way to not lose the finding while not turning this
  plan into a sixth, unrequested issue's worth of scope.
- **No public API signatures change.** `verify.py`'s `OPERATIONS` dispatch table, and every
  function's existing parameter shape, stay exactly as today — confirmed for both #23's and
  #24's fixes by grepping every caller of every function touched. This means none of these
  ten phases are a one-way door in the schema/contract sense; they are strictly internal
  hardening.

## Enterprise concerns

- **Observability**: every new guard added by Phases 3–6 raises a typed `AitpError` with a
  code already present in the registry (no new codes are minted anywhere in this plan) —
  meaning any existing caller-side error-code-to-metric/alert mapping already covers these
  new rejection paths without any downstream consumer needing to learn a new code.
- **Failure domains**: this is a pure-computation, network-free library — there is no
  partial-failure/retry/concurrency concern in the traditional sense. The closest analogue is
  Phase 8's "obtained-but-untrustworthy vs. absent" distinction (`revocation.py`'s own
  documented framing), which this plan explicitly preserves rather than collapses, for
  exactly the reason its own module docstring gives: collapsing them previously produced a
  `soft_fail` verdict for artifacts the spec says MUST be rejected.
- **Regression-proofing spans phases, not just within them**: Phase 1 (test-only) is
  sequenced before Phase 3 (the manifest code it guards) specifically so the regression net
  exists before the code it protects changes; Phase 7 is sequenced after Phases 2-6
  specifically so it can prove, by construction, that reverting any one of them breaks a
  test. This is the plan's version of a migration/rollback story for a library with no
  runtime state: the tests *are* the rollback signal.
- **CI cost**: Phase 7's mutation-sweep test is the one place this plan risks meaningfully
  lengthening CI runtime if implemented naively (exhaustive path × fixture × mutation
  product). Its Approach section requires a deliberate, recorded scoping decision rather than
  defaulting to "run everything" — call this out again during `/ship`'s review if the
  resulting test suite's wall-clock time grows noticeably.

## Open questions

- **Phase 3's IdentityHint enforcement flips one existing test's expected outcome**
  (`test_unknown_fields.py:443-450`, confirmed live during this plan's review round — see
  Phase 3's acceptance criteria) from accept to reject. This is a correct, intentional fix —
  the schema itself already requires it, and the test currently pins the exact under-
  enforcement issue #23 item 4 reports — so it isn't escalated as an open question requiring
  my input; it's flagged here and logged to `ASSUMPTIONS.md` at implementation time per that
  phase's own acceptance criteria, per the Autonomy ladder's "consequential but decidable,
  record and proceed" tier.
- **Phase 3's test-file placement** (extend `tests/test_unknown_fields.py`'s existing
  structure vs. create `tests/test_manifest.py`) is left as a decidable call for
  implementation time, per that phase's Tests section — cheap to reverse, no need to decide
  in the plan itself.
- **Phase 9's opt-out mechanism** (`AITP_SPEC=none` as specified) is a clearly-best default
  (matches the existing `$AITP_SPEC` env-var convention already in place, needs no new
  configuration surface) and is cheap to reverse if a maintainer later prefers a different
  spelling (e.g. a `--no-spec` pytest flag) — proceed with `AITP_SPEC=none`, flagged here as
  `UNCONFIRMED`-worthy only if a reviewer objects during `/ship`.
- **Phase 10's placement** (one step inside the existing `conformance` job vs. a new
  top-level job) is explicitly deferred to implementation time in that phase's own Approach/
  Edge-cases text, with a stated default (one step, inside the existing job) and the
  reasoning already recorded — this is a "consequential but decidable" call per the autonomy
  ladder, not a fork requiring escalation.
- **No critical/one-way-door decision in this plan required Fable.** Every phase is internal
  hardening of an unpublished (no PyPI release) package with no external callers beyond this
  monorepo's own sibling repos (which consume this package as a Python library dependency,
  not a network service) — confirmed via the #23/#24 analysis agents' own caller greps,
  which found no external call sites for anything touched. Nothing here crosses a trust
  boundary, changes a public contract, or performs a cross-repo write.

## Repo map

(Written to `PROGRESS.md`, appended as a new section — see that file for the full map,
covering all ten phases' files plus the already-documented map from the prior
`spec-sync-2026-09` plan.)

## Plan review

**Round 1: REVISE.** A fresh Opus agent (not the drafting agent) read every cited file in
full and reproduced this plan's #23/#25/#26 premises live, confirming the diagnosis was
sound but finding 6 blocking implementation-level issues plus several non-blocking drift
items:

- **B1** — Phase 3's IdentityHint enforcement would silently break
  `test_unknown_fields.py:443-450` (`test_manifest_identity_hint_known_fields_accepted`),
  contradicting that phase's own "passes unmodified" criterion. *Fixed*: acceptance criteria
  now name the test explicitly, require it be rewritten (not left broken), and require the
  accept→reject flip be logged to `ASSUMPTIONS.md`; also flagged in Open questions.
- **B2** — Phase 8's "Depends on: none, independent of Phases 1-7" was false; Phase 2 and
  Phase 8 both edit `revocation.py`'s shape-validation code. *Fixed*: Phase 8 now depends on
  Phase 2, with the sequencing rationale stated.
- **B3** — Phase 7's harness, as originally scoped (mutate any JSON path including the
  top level), could never be green: deleting a top-level call-argument key raises a raw
  `KeyError` on every entry point, and Phase 6 didn't yet cover `handshake.py`'s own direct
  `envelope`/`message_type`/`payload`/`sender` dereferencing. *Fixed*: Phase 7's mutation
  scope now explicitly excludes top-level call-argument keys (a Python-calling-convention
  boundary, not an AITP wire-artifact one, and out of scope for issues #23-#27); Phase 6's
  scope expanded to close the `handshake.py` dispatcher-level gap the review round found,
  which is genuinely in-scope (it's the same "reads before validating" bug class, one layer
  up from the originally-planned identity/manifest fix).
- **B4** — Phase 2's "near-duplicate" premise was wrong on the load-bearing point:
  `revocation.py` defers member-set checking to one pass over the whole tree,
  `manifest.py` interleaves it per object — a real difference a monolithic `validate_shape`
  would have silently collapsed, changing observable behavior on an untested input
  combination. *Fixed*: Phase 2 redesigned around two narrower helpers (`check_types`,
  `require_members`) that capture only the genuinely-duplicated logic, with each caller
  keeping its own member-set-check ordering; a new regression test added pinning the exact
  case the collapse would have broken. Every phase referencing the old `validate_shape` name
  updated to the corrected helpers.
- **B5** — Phase 8's `verify_snapshot_trust` sketch didn't fit its call sites: bracket
  access (`revlist["snapshot"]`, `claims["iss"]`) would reintroduce the exact raw-`KeyError`
  class Phases 3-6 close; the `expected_issuer` parameter conflated "reject on mismatch"
  with "re-key on the signed value," making the "signed value wins" acceptance criterion
  unreachable as designed. *Fixed*: switched to `.get()` access throughout; dropped
  `expected_issuer` entirely — `delegation.py` now unconditionally indexes on the verified
  `body["issuer"]` (making "signed value wins" hold by construction, no gate involved), and
  `tct.py` treats an issuer mismatch as "snapshot doesn't apply, skip" rather than a
  rejection, preserving existing absence semantics instead of inventing a new one.
- **B6** — Phase 9's `AITP_SPEC=none` opt-out was unreachable as designed: `_find_spec()`
  tries the sibling-directory convention regardless of `$AITP_SPEC`'s value, so gating the
  opt-out inside the "resolution failed" branch meant it would never fire on any machine
  with the sibling repo checked out — confirmed live (`AITP_SPEC=/nonexistent` still
  resolved and ran the full suite). *Fixed*: the opt-out check now runs first, before
  `_find_spec()` is called at all.
- **Non-blocking drift**, also corrected: the issue #26 test count (69 → 73, confirmed via
  parametrize expansion); a `sessionbundle.py` docstring line-range citation (was citing an
  inline comment as "the docstring"); an overclaim that `revocation.py`'s canonicalize error
  message is asserted by an existing test (it isn't — noted as making the refactor easier,
  not harder); Phase 1's claim to be "matching" a negative pattern neither sibling test
  actually has (corrected to state the negative is new); Phase 6's false "depends on Phase 2"
  (it doesn't, changed to "none"); Phase 4's overclaim that one fix closes both
  `envelope_signing_input` callers entirely (true only for the canonicalize wrap — the
  shape/`parse_aid` work is `verify_envelope`-only, with the corresponding `handshake.py` gap
  now folded into Phase 6); a note that `voucher.py` was never independently audited by
  either grounding agent, added to Phase 7 so a finding there reads as legitimate new-scope
  discovery, not a plan gap.
- Reviewer's direct answers to the two questions this plan asked it to weigh: the
  migration/rollback-is-N/A claim is **confirmed correct** (no persisted state, unpublished
  package, `OPERATIONS` table unchanged); no phase secretly needed Fable — the one item
  flagged (B1's behavior flip) is a "record and proceed" call, not a one-way door, and is now
  logged as such in Open questions rather than left as a silent side effect of an acceptance
  criterion.

All fixes above were applied directly to this document. Given the scale of the revision
(effectively a rewrite of Phases 2, 6, and 8, plus targeted fixes to Phases 1, 3, 4, 5, 9,
Long-term posture, and Open questions), a **Round 2** re-review was run before handoff to
`/implement`.

**Round 2: SOUND.** A second fresh Opus agent (not Round 1's agent, not the drafting agent)
verified each of the 6 blocking fixes against live code — re-reading `test_unknown_fields.py`,
`revocation.py`, `manifest.py`, `tct.py`, `delegation.py`, `handshake.py`, `conftest.py` —
rather than re-reviewing the whole plan cold, per this process's "check closure" instruction
for a re-verify round. All 6 confirmed correct, including one live reproduction (the B4
cross-level-ordering case: a wrapper-unknown-member-plus-body-type-defect snapshot genuinely
reports `REVOCATION_SNAPSHOT_INVALID`, not `UNKNOWN_FIELD`, today — proving the new Phase 2
regression test would catch a collapsed refactor). It also reasoned through B5's "skip on
mismatch" design independently and confirmed it closes a real gap without opening a new one
(today there is no issuer check on the `tct.py` path at all, and an attacker with that much
control could bypass revocation more cheaply by omitting the field entirely — already the
flagged, deliberately-deferred fail-open gap). Three non-blocking notes came back (Phase 7's
skip guard needed to widen from `MinterError`/`KeyError` to also catch `JcsError`, since a
hostile numeric mutation can land on a field `mint_input` itself canonicalizes; two of Phase
6's `handshake.py` guards are dereferenced during minting itself and so aren't reachable
through Phase 7's harness, only through Phase 6's own direct-call tests; Phase 2's new
ordering test as originally worded pinned only the body-level case, not the parallel
entry-level one) — all three applied directly to this document (Phase 7's Edge cases and
Approach sections, Phase 2's acceptance criteria, Phase 8's behavior-change note). None
changed the verdict.

Two rounds run, cap reached with a SOUND verdict on the second — this plan is ready for
`/implement`.
