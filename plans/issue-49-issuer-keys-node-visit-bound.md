# Plan: bound total nodes walked in issuer_keys_from (issue #49)

## Context

`aitp_verifier/jwk.py::_issuer_keys_from` (`jwk.py:269-300`) recursively walks a
caller/resolver-supplied `resolved_issuer_keys` value. Issue #47 added two bounds:
`_MAX_DEPTH` (`jwk.py:225`, list-nesting depth ≤ 16) and `_MAX_CANDIDATES` (`jwk.py:238`,
total candidate keys actually *appended* to `out` ≤ 64, checked before each candidate is
parsed via `_reserve`, `jwk.py:303-313`). Neither bounds the number of **nodes visited** —
how many times `_issuer_keys_from` itself is called. A value made entirely of
candidate-free entries (`None`, or `{"keys": []}`) never touches `_reserve` at all: the
`if value is None: return` branch (`jwk.py:278-279`) and the empty-`"keys"`-loop branch
(`jwk.py:285-292`, loop body never executes) both return without ever calling `_reserve`,
so the walk stays linear and completely unbounded in the size of the caller-supplied
structure.

Issue #49 (spun off during #47's own Phase 1 implementation, the same "spin off the
residual" pattern #38's verification pass used to spin off #47 itself, and #47's own
`/ship` gate used to spin off #50) measured this directly, and its own `/ship`-gate
follow-up correction (recorded in the issue body) established the real severity:

- **Non-aliased (JSON-reachable):** `issuer_keys_from([None] * 5_000_000)` costs ~159ms, 0
  candidates, no cap fires — linear, unbounded cost proportional to caller-supplied
  structure size, but at least bounded by *some* concrete structure the caller had to
  materialize (`O(memory already allocated)`).
- **Aliased (only reachable via a direct Python caller — `json.loads` never produces
  aliased structures):** because a `dict` is always a terminal leaf in this walk (parsed
  inline, never recursed into again) and only `list`s recurse, `_MAX_DEPTH` (16) nested
  lists each holding `F` references to the *same* next-level list object produce
  `sum(F**i for i in range(17))` node visits (order `F^16`) from only `O(16·F)` actual
  allocated memory — genuine **exponential**
  amplification, not `O(allocated memory)`. Measured: fanout 3 (`value = None; for _ in
  range(16): value = [value, value, value]`, ~384 bytes) costs **2.64s CPU, 0 candidates,
  neither `_MAX_DEPTH` nor `_MAX_CANDIDATES` ever fires** (each branch is exactly 16 lists
  deep — at the depth cap's boundary, not past it). Fanout 4 did not return within 10s.

This is pre-existing behavior, unchanged since #38 — not a regression #47 or #50
introduced — but genuinely reachable end-to-end (`verify_identity(...,
issuer_keys={issuer: <a ~384-byte aliased value>})` burns multiple seconds of CPU before
returning `KEY_RESOLUTION_FAILED`) for any caller/resolver path that constructs Python
objects directly rather than only round-tripping through JSON.

## Phase 1: node-visit counter threaded alongside depth and the candidate accumulator

**Status: DONE.** Implemented exactly as planned after round-1 review, including all
applied fixes (the three-cap-composition note; the corrected `_MAX_DEPTH`-necessity
figure; the exact-count/monkeypatch-counting-wrapper tests replacing the originally-
proposed wall-clock assertions; the at-cap-resolves boundary test). 534 tests passed
(529 + 5 new: 4 unit including the direct-call exact-count proof, 1 e2e using the
counting-wrapper technique), mypy clean. No divergence from the planned approach.

**Phase 1 verification gate: PASS** (fresh Opus verifier, round 1). All 7 acceptance
criteria independently confirmed with live reproductions (not just diff review),
including three independent checks of the monkeypatch counting-wrapper mechanism
(positive control, aliased-case count, and a negative control using a globals-snapshot
clone to prove the assertion is genuinely load-bearing for the interception claim) and
break-the-fix mutation testing (commenting out `_visit` made all 3 new non-vacuous
assertions fail loudly). 4 non-blocking nits raised; 2 applied directly (a stale
"loop above" comment corrected to "below" at `_MAX_NODES_VISITED`'s definition; two
test docstrings' "3**16 (~43 million)" corrected to the accurate total-node figure
"sum(3**i for i in range(17)) (~64.5 million)"), re-verified green (534 passed, mypy
clean) — no re-verify round needed for such mechanical corrections. The other 2 nits
(a harmless module-vs-local `jwk` name reuse in test_unknown_fields.py; a cosmetic
docstring-clause ordering in jwk.py's module docstring) are accepted as-is, not worth
a diff.

**`/ship` pre-merge gate: PASS** (fresh Opus verifier, round 1). Independently
re-derived the node counts, headroom claim, and composition-with-other-caps reasoning
rather than trusting the Phase 1 gate's numbers on sight; ran its own break-the-fix
mutation (via a pytest plugin, no repo file touched) confirming the e2e test's extra
assertions are load-bearing, not just the error code. Confirmed zero `ASSUMPTIONS.md`
entries for this plan, zero doc drift (no `docs/` or `CLAUDE.md` describes this
behavior), and tracked-file consistency (`Status: DONE` here, `PROGRESS.md`'s trail
matches the diff exactly). 4 non-blocking documentation nits raised, all applied
directly (no re-verify round, purely comment/doc/test-coverage corrections, no
executable-code change): the `F^16` leaf-count figure corrected to the exact
`sum(F**i for i in range(17))` total-visit figure in the remaining 3 spots
(`jwk.py`, `CHANGELOG.md`, this file's Context, and the second `test_identity_oidc.py`
occurrence); the CHANGELOG's "60x+ headroom" over-claim corrected to "~40-60x" to
match the code comment's own stated range; a new test
(`test_issuer_keys_from_large_candidate_free_jwks_list_raises_node_visit_error`)
added for the `{"keys": []}` candidate-free shape the docs already claimed was
covered. Re-verified green: 535 passed (534 + 1 new test), mypy clean.

**Delivers:** a `_MAX_NODES_VISITED` cap on the total number of `_issuer_keys_from` calls
made while resolving one `issuer_keys_from` value, checked at the top of every call (same
"guard at entry" placement `_MAX_DEPTH`'s own check already uses) — bounding total work to
a negligible constant regardless of whether the caller-supplied value is candidate-free,
candidate-rich, or aliased.

**Depends on:** nothing (single-phase plan; independent of #50's already-merged member-
decode-length fix — different hazard, same file, no interaction).

**Files:**
- `aitp_verifier/jwk.py` — add `_MAX_NODES_VISITED` and thread a `visits: list[int]`
  counter through `issuer_keys_from`/`_issuer_keys_from`, checked via a new `_visit` helper.
- `tests/test_identity_oidc.py` — unit tests for the new cap, including a live
  reproduction of the issue's own aliased fanout-3 case.
- `tests/test_unknown_fields.py` — one end-to-end handshake test proving the aliased case
  resolves to `KEY_RESOLUTION_FAILED` quickly, not after burning multiple seconds of CPU.
- `CHANGELOG.md` — one `### Security-relevant` entry under `## Unreleased`.

**Approach:**

Add one constant and thread one more mutable accumulator through the existing recursion,
mirroring exactly how `out: list[IssuerKey]` is already threaded (a shared, mutated-in-
place object, not a per-frame value) — a `list[int]` used as a single-element counter box,
since a bare `int` can't be mutated across recursive calls by reference in Python:

```python
# Maximum number of _issuer_keys_from calls (list-walk "nodes") one
# issuer_keys_from call will make, checked before any other work at entry
# -- same "guard at entry, not only at the recursion site" placement
# _MAX_DEPTH's own check already uses. _MAX_CANDIDATES (via _reserve) bounds
# candidates actually appended to `out`; it does nothing for a
# candidate-free value (None, or {"keys": []}), which never calls _reserve
# at all -- the walk over such a value stays linear and unbounded in the
# caller-supplied structure's size. Worse, for an *aliased* Python value
# (the same list object referenced more than once inside its own
# containing structure -- unreachable via JSON, only via a direct Python
# caller), the walk is not merely unbounded but exponential: _MAX_DEPTH (16)
# nested lists each holding F references to the same next-level list
# produce F^16 node visits from O(16*F) actual allocated memory (issue
# #49). A counter over total _issuer_keys_from calls closes both cases in
# one fix, since it bounds total work regardless of aliasing or shape --
# unlike _MAX_DEPTH (bounds nesting depth, catches deep-but-narrow chains
# early enough to also protect Python's own call-stack recursion limit)
# and _MAX_CANDIDATES (bounds successfully-parsed candidates), this bounds
# breadth x depth together, which neither existing cap does.
# 4096 is generous headroom (~60x) over any realistic legitimate value --
# a genuine value nests at most 1 level deep per this module's own
# _MAX_DEPTH comment, so even a generously-shaped legitimate structure
# (candidates spread across sibling containers, up to _MAX_CANDIDATES=64,
# plus a handful of wrapper lists) tops out around 65-100 nodes -- not a
# number tightly calibrated to it. At ~0.03-0.09us/node (measured in the
# issue), the worst case at the cap costs a few hundred microseconds.
_MAX_NODES_VISITED = 4096


def issuer_keys_from(value: Any) -> list[IssuerKey]:
    ...
    out: list[IssuerKey] = []
    visits = [0]
    _issuer_keys_from(value, 0, out, visits)
    return out


def _issuer_keys_from(value: Any, depth: int, out: list[IssuerKey], visits: list[int]) -> None:
    _visit(visits)
    if depth > _MAX_DEPTH:
        raise ValueError(f"issuer key value nesting exceeds the maximum depth ({_MAX_DEPTH})")
    ...
    if isinstance(value, list):
        for item in value:
            _issuer_keys_from(item, depth + 1, out, visits)
        return
    ...


def _visit(visits: list[int]) -> None:
    visits[0] += 1
    if visits[0] > _MAX_NODES_VISITED:
        raise ValueError(f"issuer key value visits more than {_MAX_NODES_VISITED} nodes while resolving")
```

`_visit` runs as the *first* statement in `_issuer_keys_from`, ahead of the depth check —
every value the walk touches (dict, string, list, `None`) is counted exactly once,
including candidate-free ones, since dict/string leaves are handled inline within the same
call frame rather than via a further recursive call (per the module docstring's existing
"a dict is always a terminal leaf" framing) — one `_visit` call per `_issuer_keys_from`
invocation already covers every node the walk can visit.

Why this closes *both* cases in one fix: the check runs before any further recursion is
attempted, so a depth-first walk over an exponential (aliased) tree aborts after exactly
`_MAX_NODES_VISITED` calls, however astronomically large the full unvisited tree would have
been — the cap bounds *calls made*, not *calls that would eventually complete*. Confirmed
by direct reasoning, not merely asserted: Python's `for item in value` loop does not
accumulate stack frames across sibling iterations (each per-item call returns before the
next iteration starts), so the wide/non-aliased case (a flat list of millions of `None`)
was never a call-stack-depth risk in the first place, only a total-work one — which this
counter closes directly.

**The bound is a composition of three caps, not the node-visit counter alone — stated
explicitly, verified during plan review by instrumenting the actual proposed code.** The
JWKS `"keys"` loop (`jwk.py:289-291`) does real parse work (`issuer_key_from_jwk`, itself
now decode-length-bounded by #50's `_MAX_B64_MEMBER_CHARS`) *between* two consecutive
`_visit` calls, with no `_visit` call of its own inside that loop — it is bounded only
because `_reserve` (`jwk.py:312`) already caps that loop's total iterations at 64 *across
the whole walk*, not because `_visit` sees it. So the real, airtight total-work bound this
phase delivers is `O(_MAX_NODES_VISITED) walk work + O(_MAX_CANDIDATES × _MAX_B64_MEMBER_CHARS)
parse work` — three caps composing, each already independently verified (this phase's own
`_visit`; #47's `_reserve`; #50's `_decode_member`), not one counter doing the whole job
alone.

Rejected alternatives:
- **Relying on `_MAX_DEPTH` alone, raised.** Doesn't help: the aliased fanout-3
  reproduction is exactly 16 levels deep — at the existing cap's boundary, not past it —
  by construction (any real caller wanting to defeat only a depth cap can always choose
  fanout instead of depth). Raising `_MAX_DEPTH` trades one exploitable dimension
  (nesting) for another (breadth) without closing either; the two constants bound
  genuinely different properties (structural nesting depth/call-stack safety vs. total
  work) and neither can substitute for the other.
- **A wall-clock/time-based cutoff inside the walk** (e.g., check `time.monotonic()`
  every N calls, abort past some budget). Rejected as this module's own established style
  already establishes for every other cap here: a *count*-based bound is deterministic,
  testable without timing flakiness, and portable across machine speed — the same reason
  `_MAX_CANDIDATES`/`_MAX_DEPTH`/`_MAX_B64_MEMBER_CHARS` (#50) are all counts, never
  timers.
- **Deriving `_MAX_NODES_VISITED` from `_MAX_CANDIDATES × _MAX_DEPTH`** (64 × 16 = 1024).
  Considered, but this ties an independently-motivated cost bound to two other constants'
  *product*, which is coincidental, not causal — a future change to either existing
  constant would silently reshape this one with no signal that it should. Kept as an
  independently-justified, independently-changeable number, matching the module's existing
  precedent (`_MAX_DEPTH` kept independent of `jcs.py`'s; `_MAX_B64_MEMBER_CHARS` kept
  independent of `crypto.py`'s RSA bit constants, issue #50).
- **A dedup/memoization set keyed by `id(value)`** to detect and short-circuit aliasing
  specifically (visit each *distinct* object only once). This would fix the exponential
  case elegantly, but leaves the non-aliased linear case (`[None] * 5_000_000`, no
  aliasing at all) completely open — a memoization set doesn't help when every node really
  is distinct. It would also add real complexity (an unbounded-growing `set` of `id()`s is
  itself a resource cost) to solve only half the problem. A simple counter solves both
  halves with less code and no new failure mode.

**Edge cases & failure modes:**
- **Composition with `_MAX_CANDIDATES`/`_reserve`:** unaffected. Verified by instrumenting
  the actual proposed code against every existing boundary test: a single JWKS dict at
  exactly `_MAX_CANDIDATES` (`{"keys": [jwk] * 64}`) is a terminal leaf and costs exactly
  **1** node visit (all 64 candidates parsed inline, no recursion); the split-across-
  containers shape (`[jwk] * 65`) costs **66** visits. Both are far under the 4096 cap;
  neither cap shadows or interferes with the other.
- **Composition with `_MAX_DEPTH`:** a deeply-but-narrowly nested value (e.g. 3000 singly-
  nested lists, `tests/test_unknown_fields.py`'s existing deep-nesting fixture) still hits
  the depth cap first — verified live at exactly 18 visits (depth 0 through 17) — the
  node-visit cap never gets a chance to fire, and the existing "nesting exceeds the maximum
  depth" error message is unchanged. `_MAX_DEPTH` remains load-bearing for this case
  specifically because it fires at a much shallower point than `_MAX_NODES_VISITED` would
  for a fanout-1 chain — without it, a fanout-1 chain nesting past **~990 levels** (Python's
  default `sys.getrecursionlimit()` of 1000, at roughly one interpreter stack frame per
  nesting level — measured live: a no-depth-cap chain at n=900 completes, n=4200 raises a
  raw `RecursionError`) would hit a raw Python `RecursionError` from the interpreter's own
  call-stack limit long before the node-visit counter ever reached 4096, reintroducing
  issue #38's original hazard on this axis. The two caps are complementary, not redundant;
  neither phase of this plan removes either existing one.
- **A value that is *both* wide and deep** (many siblings at a nesting level well under
  16) — the node-visit cap fires first if total visits exceed 4096 before depth exceeds
  16; the depth cap fires first if nesting exceeds 16 before 4096 total visits accumulate.
  Whichever threshold the value crosses first raises; both remain independently correct.
- **`_MAX_NODES_VISITED`'s interaction with `_reserve`'s own message:** unchanged — a
  value that legitimately reaches the candidate cap raises `_reserve`'s own "more than 64
  candidate keys" message exactly as before, since candidate accumulation still happens
  well under 4096 total visits for any value that could plausibly reach 64 real candidates
  via `_reserve`'s own linear counting.
- **Observable message change for a previously-*accepted* input:** a candidate-free value
  of more than 4096 nodes today returns `[]` (zero candidates, no error), which
  `identity.py:228` turns into `KEY_RESOLUTION_FAILED "no issuer key resolvable"`. After
  this phase, the same value instead raises inside the walk, producing
  `KEY_RESOLUTION_FAILED "... is malformed: visits more than 4096 nodes while resolving"`
  (`identity.py:225-226`) — same error code, same `retryable=True`, different message text.
  No existing test pins the old message for this specific case, so this is safe, but it is
  the one observable behavior change for an input that was never previously rejected
  outright (it just silently resolved to "no keys").
- **`visits` does not persist across separate `issuer_keys_from` calls.** `visits = [0]` is
  a fresh local created inside `issuer_keys_from` (`jwk.py:264` today) each time it's
  called — a verification flow that resolves keys for multiple issuers, or walks a
  multi-hop chain, gets an independent, fresh 4096-node budget per call, not one shared
  budget across a whole verification. This is the same scoping `out`/`depth` already have;
  called out explicitly since a reviewer will otherwise ask.
- This phase does not change `issuer_keys_from`'s public signature (`visits` is threaded
  only through the private `_issuer_keys_from`/`_visit` helpers, exactly as `depth` and
  `out` already are) — a caller cannot pass a starting state that defeats the cap, same
  property the module docstring already claims for the existing two bounds.

**Acceptance criteria:**
1. `_MAX_NODES_VISITED = 4096` and a `_visit` helper exist in `jwk.py`; `_issuer_keys_from`
   calls `_visit(visits)` as its first statement; `issuer_keys_from` initializes
   `visits = [0]` and threads it through; `_issuer_keys_from`'s own recursive call (the
   `list` branch) passes `visits` forward unchanged.
2. A non-aliased, candidate-free value whose node count exceeds `_MAX_NODES_VISITED`
   (e.g. `[None] * (_MAX_NODES_VISITED + 10)`) raises `ValueError` containing "visits more
   than" and the constant's value — proving the new cap fires, not `_MAX_DEPTH` (depth
   stays at 1 the whole time) or `_MAX_CANDIDATES` (0 candidates ever produced).
3. The issue's own aliased fanout-3 reproduction (`value = None; for _ in range(16): value
   = [value, value, value]`) raises `ValueError` containing "visits more than" — proving
   the cap closes the exponential case, not merely the linear one. Proven via a
   **deterministic, non-timing assertion** — a call directly into `_issuer_keys_from` with
   its own `out`/`visits` accumulators, asserting `visits[0] == _MAX_NODES_VISITED + 1`
   after the raise (verified live during plan review: exactly 4097, vs. ~64.5 million calls
   for the uncapped walk) — not a wall-clock bound. Timing assertions are exactly what this
   plan's own "Rejected alternatives" argues against as a *bounding mechanism*; using one as
   the *test evidence* here would be the same inconsistency, and this repo has no existing
   timing-based test to match anyway. The exact-count assertion is strictly stronger: it
   fails loudly and deterministically on a regressed cap, independent of machine speed.
4. A candidate-free value at *exactly* the cap (`[None] * (_MAX_NODES_VISITED - 1)` — the
   root list itself consumes the first visit, so `_MAX_NODES_VISITED - 1` list items land
   exactly on 4096 total visits) resolves successfully to `[]`, not an error — the cap
   bounds rejection at the boundary, same "accept at, reject one past" property
   `_MAX_CANDIDATES`/`_MAX_DEPTH` both already have their own at/past test pairs for.
5. Every existing legitimate-value test (at exactly `_MAX_CANDIDATES`, at exactly
   `_MAX_DEPTH`, split-across-containers) still resolves/raises with its existing message,
   unaffected by the new cap — zero regressions.
6. One end-to-end test in `tests/test_unknown_fields.py`: a handshake whose resolved
   issuer key value is the aliased fanout-3 reproduction resolves to
   `AitpError("KEY_RESOLUTION_FAILED")` — proven via the same deterministic technique as
   criterion 3, adapted for the black-box handshake entry point (where `visits` isn't
   directly reachable): monkeypatch `aitp_verifier.jwk._issuer_keys_from` with a counting
   wrapper that delegates to the real function, and assert the wrapper was called exactly
   `_MAX_NODES_VISITED + 1` times — the same non-vacuous monkeypatch-proof technique #50's
   own tests already established (`tests/test_identity_oidc.py`'s `_guarded_b64url_decode`),
   here counting recursive calls instead of intercepting a single decode call.
7. `uv run pytest -q` green; `uv run --extra dev mypy` clean; `CHANGELOG.md` has a
   `### Security-relevant` entry under `## Unreleased` citing issue #49.

**Tests:**
- `test_max_nodes_visited_is_4096` (constant-pinning, matching `_MAX_DEPTH`/
  `_MAX_CANDIDATES`/`_MAX_B64_MEMBER_CHARS` precedent)
- `test_issuer_keys_from_large_candidate_free_flat_list_raises_node_visit_error` (linear
  case, criterion 2)
- `test_issuer_keys_from_aliased_structure_raises_node_visit_error_exact_count` (exponential
  case, criterion 3 — the issue's own reproduction, asserting the exact `visits[0]` count)
- `test_issuer_keys_from_at_max_nodes_visited_resolves` (boundary, criterion 4)
- `test_issuer_keys_from_at_max_candidates_resolves` / `test_issuer_keys_from_at_max_depth_resolves`
  / `test_issuer_keys_from_candidates_split_across_containers_still_capped` (all pre-existing,
  re-run unmodified — regression, criterion 5)
- `test_handshake_aliased_resolved_issuer_key_is_key_resolution_failed_via_node_visit_cap`
  in `tests/test_unknown_fields.py`, using the monkeypatched counting-wrapper technique
  (criterion 6)

**Docs:** `jwk.py`'s module docstring (`jwk.py:18-43`) already describes the depth/count/
member-length bounds from #38/#47/#50 in its "Issuer-key parsing" paragraph; extend that
paragraph with one clause for this phase's node-visit bound, same pattern #47 and #50 both
used when adding their own clauses there. `issuer_keys_from`'s own docstring
(`jwk.py:242-263`) gets the same treatment.

## Long-term posture

No one-way door: purely additive, internal cost-bounding on an already-`ValueError`-raising
path (`identity.py`'s existing catch-all needs zero changes, same as #38/#47/#50 — the new
`ValueError` converts to `AitpError("KEY_RESOLUTION_FAILED")` through the same unmodified
call site). No public contract, schema, or wire-format change. `_MAX_NODES_VISITED` is
fully reversible/tunable in isolation if it ever proves too tight (it won't, per the sizing
math above, which is ~40-60x over realistic legitimate use).

## Enterprise concerns

Closes the last unbounded-cost dimension in `issuer_keys_from`'s own walk: with #47
(candidate count), #50 (member decode length), and this phase (nodes visited) all in
place, every axis along which a caller/resolver-supplied value could drive unbounded cost
— parse count, decode size, and walk breadth×depth — is now bounded by a small constant,
for both JSON-reachable and (uniquely relevant to this phase) Python-object-aliasing-
reachable input. No observability changes needed: the rejection is a plain `ValueError` →
`AitpError`, same shape as every other malformed-`resolved_issuer_keys` hazard already
handled.

## Open questions

- **`_MAX_NODES_VISITED = 4096`, an independently-justified constant, not derived from
  `_MAX_CANDIDATES`/`_MAX_DEPTH`'s product** — decided directly (Consequential-but-
  decidable, no escalation needed). Reasoning and rejected alternatives recorded in
  Phase 1's Approach above.
- **A `list[int]` single-element counter box, not a small mutable class/dataclass** —
  decided directly: matches the existing threaded-accumulator style (`out: list[IssuerKey]`)
  already established in this exact function, rather than introducing a new internal
  state-holding type for one integer.
- No critical/one-way-door decisions in this plan; Fable was not engaged.

## Repo map

(Reuses the map already built for `jwk.py`/`crypto.py`/`identity.py`/the two test files/
`CHANGELOG.md` in `PROGRESS.md` from issues #47 and #50 — no new files or directories enter
scope for this plan.)

## Plan review

**Round 1 — REVISE, applied.** A fresh Opus agent checked this plan against `jwk.py`,
`identity.py`, and both test files directly, and ran live reproductions in the repo's own
venv against the current (post-#47/#50) code — not merely re-derived the plan's own
arithmetic. Every line-number and mechanism claim verified clean, including the core
exponential-amplification trace (confirmed non-memoized, confirmed `F^16` node visits from
`O(16·F)` memory) and a live timing reproduction (2.751s for the aliased case, 117.3ms/
79.2ms for the two non-aliased cases — all close to the issue's own originally-measured
figures, confirming they still hold against the current code). The proposed fix was
independently prototyped and confirmed correct: the aliased case raises in 0.0005s after
exactly 4097 calls. Four findings applied:
1. **Approach was missing the three-cap composition** the actual per-visit work bound
   depends on (the JWKS `"keys"` loop does real parse work between two `_visit` calls,
   bounded by `_reserve`+`_decode_member`, not by `_visit` itself) — added explicitly.
2. **Two factual errors in Edge cases**, both corrected with live-measured figures: the
   `_MAX_DEPTH`-necessity argument understated the `RecursionError` risk by ~4x ("slightly
   past 4096" → the real threshold is ~990, Python's default recursion limit); the
   candidate-cap example cited the wrong test (`..._at_max_candidates_resolves` visits
   exactly 1 node, not "65-100" — that figure belongs to the flat-list shapes instead).
3. **Criteria 3 and 5's wall-clock timing assertions were internally inconsistent** with
   this same plan's own rejection of timers as the *bounding mechanism*, and were weaker
   than available alternatives — replaced with a deterministic exact-count assertion
   (`visits[0] == _MAX_NODES_VISITED + 1`, verified live) for the unit test, and a
   monkeypatched call-counting wrapper (matching #50's own established non-vacuous-proof
   precedent) for the end-to-end test. Also added a missing at-cap-resolves boundary test/
   criterion, matching `_MAX_DEPTH`/`_MAX_CANDIDATES`'s own existing at/past test-pair
   convention.
4. **One rejected-alternative sub-argument was wrong** (an `id()`-reuse/garbage-collection
   correctness-trap claim against the memoization-set alternative — false, since every
   object live during one walk is reachable from the caller's own held root and can't be
   collected mid-walk) — deleted rather than defended; the alternative's actual rejection
   reason (doesn't help the non-aliased case) stands on its own.

Also added to Edge cases: the observable message-text change for a previously-*silently-
accepted* candidate-free input past the new cap (same error code, different text — no
existing test pins the old text, so safe), and an explicit note that `visits` resets fresh
per `issuer_keys_from` call, not shared across a multi-issuer/multi-hop verification.

**Not re-reviewed as a second round:** every change is a direct, cited, verified-live
application of a specific finding (a missing composition note, two corrected citations, a
strictly-stronger test-evidence swap, a deleted false sub-clause) with no new design
surface — the core fix (the counter, its placement, its value) was independently
prototyped and confirmed correct in round 1 itself, not merely reasoned about.

**Filed as a separate follow-up, not folded into this plan:** the review surfaced that
`aitp_verifier/jcs.py::_serialize` has the *same* aliasing-amplification shape (recurses
into both dicts and lists, `_MAX_DEPTH = 256`, no node-visit bound) — live-reproduced at
0.56s CPU / 4.2MB output from ~1.4KB of aliased input (fanout 2, depth 20) — and is
actually worse than this issue, since it also allocates output per node (an OOM risk, not
only a CPU one). Out of scope for this plan (different module, different function, no
shared code with `jwk.py`'s walk) — tracked as issue #54, same "spin off the residual"
pattern #38/#47/#47-Phase-1/#47's-`/ship`-gate used for #47/#49/#50 themselves.
