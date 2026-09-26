# Plan: issue #54 — bound total nodes visited in jcs.py::_serialize

## Context

Found during issue #49's plan review round 1: `aitp_verifier/jcs.py::_serialize`
(`jcs.py:171-209`) has the same underlying shape as the hazard #49 fixed in
`jwk.py::_issuer_keys_from` — a recursive walk over a caller-supplied value
with no bound on total nodes visited, only on nesting *depth*
(`_MAX_DEPTH = 256`, `jcs.py:168`). Unlike `jwk.py`'s walk (a `dict` is always
a terminal leaf there — only `list` recurses), `_serialize` recurses into
**both** `dict` and `list` values (`jcs.py:187-207`), so the aliasing
primitive #49 describes — the same list/dict object referenced more than
once inside its own containing structure, unreachable via JSON (which never
aliases), reachable only from a direct Python caller constructing the value
in-process — is reachable through either container type here, not just
lists.

`_serialize` also **allocates output per node** (`out.append(...)`,
`jcs.py:178-207`) rather than merely recursing, so an aliased input doesn't
just cost CPU walking references — it allocates real (non-deduplicated)
memory for the serialized output, an OOM risk on top of the CPU-exhaustion
one #49 was purely about.

Measured live during planning (`uv run python3`, current code): an aliased
**list** structure with fanout 2, depth 20 (`~1.4KB` of actual allocated
Python objects — 20 list objects, each holding 2 references to the next
level's single shared list) costs **0.56s CPU and ~4.2MB of allocated
output** — confirms the issue's own reproduction, unchanged since it was
filed. The equivalent **dict**-aliased shape (same fanout/depth, but each
level a dict holding 2 keys both pointing at the same next-level dict) costs
more, not the same: **1.32s CPU and ~14MB of allocated output** — the dict
branch's per-node work (`sorted(value.keys(), key=...)`, `jcs.py:198`) is
strictly more expensive per revisit than the list branch's, so this issue's
own framing ("arguably worse than #49" because dicts recurse too) is not
just a reachability claim, it's a measured cost-per-node claim: dict
aliasing is the specific shape that needs to drive this plan's cap-cost
estimate, not list aliasing (see Approach).

**No existing schema-level cap bounds legitimate document size upstream of
this call.** Checked (`grep`) across every module that calls `jcs.dumps`/
`jcs.canonicalize` (`delegation.py`, `jws.py`, `fields.py`, `minter.py`) and
`revocation.py`/`manifest.py`/`sessionbundle.py` (the structures most likely
to carry variable-length arrays — revocation entries, manifest files, session
participants): none cap array length. Checked further (per plan review round
1): no `maxItems` constraint exists anywhere in the sibling spec repo's
schemas/RFCs either, and every conformance-pack known-answer vector for
manifest/revocation/session-bundle carries at most 1 entry in its
variable-length arrays — so "a legitimately large document" below is an
honestly-labeled assumption, not something calibrated against a real
observed maximum (same epistemic status `jwk.py`'s own "generous, not
tightly calibrated" constants have). This is consistent with the
`_MAX_DEPTH` constant's own comment (`jcs.py:151-153`, not the top-of-file
module docstring), which already frames total *document* size as "an
orthogonal concern already bounded by input size" — this library trusts that
whatever ingests raw bytes bounds them before they ever reach a parsed
`JsonValue`. That framing is unaffected by this plan: a large but
*non-aliased* document (e.g. a revocation snapshot with many entries) costs
real, already-paid-for allocation, linear in input size, which is exactly
the "expected, not a bug" cost that comment already documents. What this
plan closes is the *disproportion* aliasing introduces — non-deduplicated
revisits of the same already-allocated object turning a small amount of real
memory into an unboundedly (here, exponentially) larger amount of walk-time
and output.

## Approach

Mirror #49's exact mechanism: thread a mutable visit-counter (a single-element
list, the same "mutable counter box" #49 established for `jwk.py`, since a
bare `int` can't be mutated across recursive calls by reference) through
`_serialize`'s recursion, checked at entry — **before** the existing depth
check, same "guard at entry, not only at the recursion site" ordering #49
used for `jwk.py`'s `_visit`, and the same ordering `_serialize`'s own
existing depth check already uses relative to its two recursion sites
(`jcs.py:172-173`'s comment: "Guard at entry, not at the two recursion
sites").

```python
def _serialize(value: JsonValue, out: list[str], depth: int = 0, visits: list[int] | None = None) -> None:
    if visits is None:
        visits = [0]
    _visit(visits)
    if depth > _MAX_DEPTH:
        raise JcsError(...)
    ...
```

`dumps` needs no signature change (`visits` defaults to `None` and is
initialized on the outermost call, the same reason `depth` already defaults
to `0` per the existing comment) — but see Open questions below for why a
plain default-`None`-per-call is *wrong* for this function specifically,
unlike `jwk.py`'s `issuer_keys_from` (which owns a public wrapper that always
initializes a fresh `[0]` before calling its private recursive helper,
`jwk.py:315-317`). `_serialize` **is** both the public entry point's helper
*and* the recursive function — there is no separate `dumps`-only wrapper
layer to own the initialization the way `issuer_keys_from`/`_issuer_keys_from`
split does. The actual implementation therefore keeps `dumps` as the sole
place that creates the fresh counter, passing it through explicitly, with
`_serialize`'s own default staying only as a safety net for any direct
caller of `_serialize` that isn't `dumps` (none currently exist — `grep`
confirms `_serialize` has exactly one caller, `dumps`, `jcs.py:214-216` —
but the function is private, not `__all__`-exported, so this is a
belt-and-suspenders default, not a public contract).

**Node-visit cap value — `_MAX_NODES_VISITED = 200000`.** Reasoning, mirroring
#49's "generous, not tightly calibrated" style:
- Real AITP artifacts nest 3-5 levels (per `_MAX_DEPTH`'s own comment,
  unchanged), but *width* (array length — revocation entries, manifest
  files, session participants) has no schema-level cap (confirmed above).
  A legitimately large document — e.g. a revocation snapshot with several
  thousand entries, each contributing ~1 dict node + ~5 scalar-field nodes —
  could plausibly reach tens of thousands of node visits. 200,000 leaves
  generous (5-10x+) headroom over that without being so large it stops
  meaning anything as a ceiling.
- At the cap, worst-case cost is cheap in absolute terms, **using the more
  expensive dict-aliased shape, not the list-aliased one**, to estimate it
  (per plan review round 1 — the list-only extrapolation this plan
  originally used understated the true worst case by 2-3x): measured
  directly at ~200,000 visits (not merely extrapolated), the list-aliased
  shape costs 56ms CPU / 391KB output, the dict-aliased shape costs **132ms
  CPU / ~1.37MB output**, and a flat non-aliased dict of width 200,000 costs
  192ms / ~3.18MB. The code comment states a range covering all three
  (roughly 50-200ms CPU, 0.4-3.2MB output) rather than a single
  list-derived figure — still negligible for a synchronous per-call
  verification path, just not understated.
- The exact figures get re-measured against the real cap during
  implementation (not assumed from this plan's own numbers) — same practice
  #49's own implementation phase used before finalizing its comment's
  stated cost claims, and specifically re-measured for the **dict**-aliased
  shape, not only re-confirming the list one, since dict aliasing is the
  more expensive case this issue is actually about.

**On the "load-bearing question" the issue names** (does bounding node-visits
also bound total output size, for this function's specific allocation
pattern?) — resolved here, not deferred:

Bounding visits does **not** make total output `O(1)` — a single leaf
(string/number) node's own formatting cost (`_format_string`,
`_format_number`) is proportional to *that value's own size*, which this fix
does not cap. But that is not a new gap this fix introduces or fails to
close: it is the same "document size is bounded by input size" cost the
module docstring already treats as expected, non-aliasing-driven, and
out of scope (a single huge string the caller already had to allocate once
costs proportional, already-real memory to format once — that's linear, not
disproportionate). What the node-visit cap *does* guarantee, precisely: for
any value that is visited more than once via aliasing, its own formatting
cost is paid at most `_MAX_NODES_VISITED` times, not an unbounded (here,
exponential-in-depth) number of times. Total worst-case output is therefore
bounded by `_MAX_NODES_VISITED x (largest single leaf's own real, already-
allocated size)` — a **bounded multiplier over the attacker's own real
allocated memory**, not an unbounded one. That is exactly the same guarantee
#49 established for `jwk.py` (CPU-only there; CPU-and-allocation here) —
converting an exponential/unbounded multiplier into a bounded, small one.

**Precision note (per plan review round 1): "bounded," not literally
"fixed."** The dict branch re-sorts `value.keys()` on every visit
(`sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))`, `jcs.py:198`,
uncached), so revisiting an aliased dict of width `w` pays `O(w log w)`, not
`O(w)` or `O(1)`, each time — the per-visit multiplier for a dict node isn't
literally constant, it carries a `log(w)` factor. This doesn't change the
conclusion (bounded and negligible at the proposed cap — `log(200000) ≈ 18`
— versus genuinely unbounded/exponential today), but the guarantee is
"bounded by `_MAX_NODES_VISITED` times a per-node cost that itself scales
with that node's own width," not literally "a fixed constant per visit."
A dedicated per-leaf size cap (analogous to jwk.py's
`_MAX_B64_MEMBER_CHARS`, issue #50) is therefore **not needed** to make this
fix's guarantee sound; adding one would be tightening a different,
already-documented-as-accepted axis (raw non-aliased document size) that
this issue was never about. Decided here as a consequential-but-decidable
Autonomy-ladder call, not escalated and not deferred to yet another
follow-up issue — see Open questions.

**Rejected alternative:** a separate output-size cap (total `sum(len(s) for s
in out)`, checked incrementally). Rejected per the reasoning above: it would
bound a different, already-accepted-as-linear-in-input axis, not the
aliasing-driven disproportion this issue is actually about, and would need
its own separate calibration against real document *byte* sizes (which,
unlike node *counts*, this codebase has even less existing signal for) —
scope creep relative to what issue #54 measured and asked for.

**Also considered and rejected: memoizing by `id(value)`** to deduplicate
serialization of aliased substructures instead of rejecting them (JCS output
is purely structural, not reference-aware, so memoized output would be
byte-identical to the naive walk's). Rejected because every current caller
(`delegation.py`, `jws.py`, `fields.py`, `minter.py`) only ever passes
already-parsed JSON or plain in-process values with no legitimate reason to
alias — treating aliasing as pathological (reject via a cap) rather than a
case worth optimizing for is the right, minimal posture, and is the same
choice issue #49 already made for the identical primitive in `jwk.py`
(no memoization there either).

## Files

- `aitp_verifier/jcs.py`:
  - `_MAX_NODES_VISITED` constant (new), with a comment mirroring
    `jwk.py`'s `_MAX_NODES_VISITED` comment style — states the aliasing
    mechanism, the exponential-vs-actual-memory framing, and the resolved
    load-bearing question about output-size boundedness (see Approach).
  - `_visit(visits: list[int]) -> None` helper (new), identical shape to
    `jwk.py::_visit` (`jwk.py:376-382`).
  - `_serialize` — add the `visits` parameter and the entry-guard call,
    ahead of the existing depth check (see Approach for exact placement and
    the `dumps`-owns-initialization detail).
  - `dumps` (`jcs.py:212-216`) — initialize `visits = [0]` and pass it
    through, mirroring `issuer_keys_from`'s `visits = [0]` initialization
    (`jwk.py:316`).
  - Module docstring (`jcs.py:1-20`) — add a sentence naming the new bound,
    mirroring how the existing depth-cap sentence is phrased.
- `tests/test_fields.py` — **not** a new `test_jcs.py`: there is no dedicated
  test file for `jcs.py`. Its own unit-level tests (the `_MAX_DEPTH` boundary
  tests, `_deep_dict`/`_deep_list` helpers, `JcsError` coverage, including
  the `RecursionError`->`JcsError` conversion test) already live here
  (`tests/test_fields.py:24-298`), exercised via `fields.py`'s
  `canonical_bytes`/`jcs.canonicalize` re-export — confirmed via `grep`
  during planning (no `test_jcs.py` exists; `jcs.py`-specific tests are
  co-located with `fields.py`'s, which wraps it). This plan adds to that
  existing home rather than inventing a new file, and reuses its
  `_deep_dict`/`_deep_list` helpers (`tests/test_fields.py:27-68`) where they
  fit:
  - A deterministic exact-count test: call `_serialize` (or `dumps`) with a
    value engineered to visit exactly `_MAX_NODES_VISITED + 1` nodes,
    asserting `JcsError` and (mirroring #49's non-vacuous-proof technique)
    an exact visit count via a monkeypatched counting wrapper or a
    deliberately-sized flat list — whichever is simpler to make genuinely
    non-vacuous without relying on wall-clock timing (per this repo's
    established preference, see #49's plan/tests).
  - An aliased-structure test: the same fanout/depth-aliasing shape as the
    issue's own reproduction (and #49's `jwk.py` sibling test), proving the
    cap catches the *exponential* case specifically, not only a flat long
    list. Needs a **dict**-aliasing variant specifically (a dict object
    referenced from two+ sibling keys within its own ancestry), not only
    list-aliasing — `_deep_dict`/`_deep_list` as written build simple
    fanout-1 chains, not aliased/shared-reference graphs, so this test
    constructs its own value rather than reusing them unmodified.
  - A regression test: `_MAX_DEPTH` is 256 unchanged, and a legitimate,
    non-aliased, moderately sized document (a few hundred nodes) still
    serializes correctly and identically to its pre-fix output — proves the
    new counter changes nothing about output content, only adds a rejection
    path. `test_kat.py::test_jcs_canonical_and_sha256` (spec-pinned
    known-answer vectors, `tests/test_kat.py:69-116`) already gives this
    property broad, pre-existing coverage — re-run as part of the full
    suite, not duplicated with a new test unless it's found to miss
    something during implementation.
  - A composition test: a value at exactly `_MAX_DEPTH` nesting but with
    total node count safely under `_MAX_NODES_VISITED` still serializes
    (proves the two caps don't shadow each other for an in-budget value —
    same "seam" proof style #47/#49's own composition tests used for
    `jwk.py`'s caps). `_deep_dict(_MAX_DEPTH)`/`_deep_list(_MAX_DEPTH)`
    (already-existing helpers) are a direct fit here: exactly `_MAX_DEPTH`
    visits, far under `_MAX_NODES_VISITED`.
  - A break-the-fix mutation check performed during implementation (not
    committed as a test, per #49's own practice): temporarily neutralizing
    `_visit`'s cap confirms the new exact-count assertion fails loudly, not
    vacuously.
  - A default-path test (per plan review round 1 — this branch shipped
    uncovered in the original draft): call `_serialize` directly (not
    through `dumps`) with no `visits` argument, confirming the `visits is
    None` belt-and-suspenders default (`_serialize`'s own safety net, see
    Approach) actually initializes and enforces the cap on its own, not
    only via `dumps`'s explicit initialization.
  - A cross-call isolation test (per plan review round 1): call `dumps`
    twice in sequence, each on a value near (but under) the cap, asserting
    neither call spuriously fails from state leaking out of the other —
    the direct proof that `dumps`'s `visits = [0]` is fresh per call, not
    shared. (Note: `jwk.py`'s own `#49` suite has no equivalent test for
    `issuer_keys_from`'s identical per-call `visits = [0]` — this closes a
    real gap on both sides, not a deviation unique to this plan.)
- `CHANGELOG.md` — new `### Security-relevant` entry under `## Unreleased`.
- No `identity.py`/other call-site changes: `JcsError` already propagates
  through every `jcs.dumps`/`jcs.canonicalize` caller as a `ValueError`
  subclass (`class JcsError(ValueError)`, `jcs.py:33-34`) — every existing
  caller's exception handling is unchanged.

## Edge cases & failure modes

- **Aliased dict structure** (not just list, unlike #49's `jwk.py` walk,
  which never recurses into a dict's *values* as containers again beyond
  one level — `_serialize` recurses through nested dicts freely): the
  aliased-structure test must exercise dict aliasing specifically (a dict
  whose value is the same nested dict object referenced from two sibling
  keys, repeated to depth), not only list aliasing, since that is the
  detail issue #54 calls out as making this "arguably worse than #49."
- **A single oversized non-aliased leaf value**: explicitly out of scope,
  reasoned through in Approach — not a regression this fix introduces, and
  not silently ignored either (the docstring addition names it).
- **`dumps`/`canonicalize`'s existing callers** (`delegation.py`, `jws.py`,
  `fields.py`, `minter.py`): no signature change to either public function,
  so no caller-visible change except the new rejection path for a
  pathological (aliased) input none of them currently constructs — a purely
  additive behavior change, same posture as #49's own `issuer_keys_from`
  fix had for its callers.
- **Interaction with `_MAX_DEPTH`**: as in `jwk.py`, a fanout-1 chain (no
  aliasing, no width) hits `_MAX_DEPTH` (256) long before `_MAX_NODES_VISITED`
  (200,000) could fire from depth alone — the new cap's value is chosen to
  bound breadth x depth together, which `_MAX_DEPTH` alone cannot (identical
  reasoning to `jwk.py`'s own `_MAX_NODES_VISITED` comment).

## Acceptance criteria

- `_serialize` calls `_visit(visits)` as its first statement, ahead of the
  existing depth check, for every value shape (`dict`, `list`, scalar,
  `None`) — verified by the exact-count test counting *every* visit, not
  just container ones.
- `dumps` initializes a fresh `visits = [0]` per call (not shared across
  separate `dumps`/`canonicalize` invocations).
- An aliased **dict** structure (not just list) past the cap raises
  `JcsError` naming the node-visit bound.
- An aliased **list** structure past the cap raises the same.
- A flat, non-aliased structure past the cap (candidate-free-analogue: many
  small sibling nodes, no recursion depth) also raises — proves the cap
  catches linear-but-huge inputs too, not only the exponential aliased case
  (mirrors #49's own `{"keys": []}`-list coverage gap it closed in its own
  `/ship` gate).
- A legitimate document at or near realistic size (a few hundred nodes,
  depth <= 5) serializes identically to its pre-fix JCS output — proves no
  behavior change for real input. `test_kat.py::test_jcs_canonical_and_sha256`
  already re-derives the spec's byte-pinned known-answer vectors
  (`schemas/conformance/known-answer/jcs-sha256.json`, in the sibling spec
  checkout `spec_dir` fixture resolves to) on every run — passing unchanged
  through this fix is this criterion's proof; no new test needed for it.
- A value at exactly `_MAX_DEPTH` depth but safely under `_MAX_NODES_VISITED`
  total visits still serializes (cap composition, no shadowing).
- `_serialize`'s own `visits is None` default path is exercised directly
  (not only reached transitively through `dumps`) and correctly enforces the
  cap on its own.
- Two sequential `dumps` calls, each near but under the cap, both succeed —
  proves no counter state leaks across separate `dumps` invocations.
- `uv run pytest -q` and `uv run --extra dev mypy` both clean.

## Tests

Listed above, under Files.

## Docs

- `jcs.py` module docstring — one new sentence naming the node-visit bound
  (see Files).
- `CHANGELOG.md` — new entry (see Files).

## Long-term posture

Not a one-way door: `_serialize`/`dumps`/`canonicalize`'s public signatures
are unchanged (the new `visits` parameter on `_serialize` is a private,
optional, internally-threaded implementation detail, not exported —
`_serialize` is not in `jcs.py`'s `__all__`). The only externally-visible
change is that a pathological (aliased, caller-constructed, not
JSON-reachable) input that previously could hang or OOM the process now
raises `JcsError` instead — a strict improvement, reversible in a follow-up
commit if the chosen constant ever proves too tight for a real workload
(none is currently known to approach it).

## Enterprise concerns

Single-module, single-function fix; no concurrency surface (the counter is
per-call, never shared, same as `jwk.py`'s). Observability: the raised
`JcsError` message names the exact bound, matching every other cap in this
codebase's own convention (`_MAX_DEPTH`, `jwk.py`'s three caps) — no separate
logging/metrics need, consistent with how #38/#47/#49/#50 were each closed.

## Open questions

Two Autonomy-ladder calls, both decided here (consequential-but-decidable,
neither critical — no public contract, schema, auth model, or external
dependency is touched):

1. **Does the node-visit cap alone suffice, or is a separate output-size cap
   also needed?** Decided: node-visit cap alone suffices, for the reasoning
   in Approach above (it bounds the *multiplier* aliasing introduces to a
   bounded, negligible-at-the-cap quantity — not literally `O(1)` per visit,
   since a revisited dict's own `sorted()` call scales with that dict's
   width, but bounded nonetheless; it does not and need not bound raw
   non-aliased document size, which this codebase already treats as an
   accepted, orthogonal, input-size-bounded cost). Not deferred to a further
   follow-up issue.
2. **Where does `visits` get initialized — `_serialize`'s own default, or
   `dumps`?** Decided: `dumps` owns it explicitly (mirrors `jwk.py`'s
   public-wrapper-initializes-the-counter split), with `_serialize`'s
   `None`-default kept only as a non-public safety net. See Approach for
   the full reasoning (there is no separate `dumps`-only layer the way
   `jwk.py` splits `issuer_keys_from`/`_issuer_keys_from`, since `_serialize`
   is itself both the entry point's helper and the recursive function).

## Repo map

- `aitp_verifier/jcs.py:150-217` — `_MAX_DEPTH`, `_serialize`, `dumps`,
  `canonicalize`: this plan's entire edit surface.
- `aitp_verifier/jwk.py:247-282,376-382` — `_MAX_NODES_VISITED`/`_visit`
  (issue #49), the mechanism this plan mirrors.
- `tests/test_fields.py:1-298` — where `jcs.py`'s own unit-level tests
  actually live (no dedicated `test_jcs.py` exists); `_deep_dict`/
  `_deep_list` helpers and the existing `_MAX_DEPTH` boundary tests; this
  plan's test-addition site.
- `tests/test_kat.py:69-116` — `test_jcs_canonical_and_sha256`, the spec-
  pinned known-answer regression coverage this plan relies on rather than
  duplicating.
- `aitp_verifier/delegation.py`, `jws.py`, `fields.py`, `minter.py` — the
  four existing callers of `jcs.dumps`/`canonicalize` (confirmed via `grep`
  during planning); no changes needed, checked for call-site impact only.
- `aitp_verifier/revocation.py`, `manifest.py`, `sessionbundle.py` — checked
  during planning for any existing array-length cap (none found); grounds
  this plan's `_MAX_NODES_VISITED` calibration reasoning.

## Plan review

Round 1 (fresh Opus agent, code-grounded): **REVISE**. Every file:line
citation, the mechanism/ordering claims, the "no dedicated test_jcs.py"
claim, and the "`_serialize` has exactly one caller" claim were all
independently confirmed exact. Found one real precision gap: the plan's
original cap-cost estimate extrapolated only from a **list**-aliased repro,
but this issue is specifically about **dict** aliasing being the more
expensive, worse-than-#49 case (per the issue's own framing) — the reviewer
independently measured dict-aliasing at both the original small repro shape
(1.32s CPU / ~14MB output, vs. list's 0.56s / ~4.2MB) and directly at
~200,000 visits (132ms CPU / ~1.37MB output, vs. list's 56ms / 391KB and a
flat non-aliased dict's 192ms / ~3.18MB) — 2-3x higher than the plan's
original list-derived "~50ms / ~400KB" claim. Also found: the dict branch's
uncached `sorted()` call means the per-visit cost isn't literally `O(1)`/
fixed, just bounded; two test-coverage gaps against the plan's own
acceptance criteria (`_serialize`'s `visits=None` default path, and
cross-call counter isolation); and three trivial line-citation slips.
Applied directly (no design change, so no re-review round needed): the cost
estimate now cites both container shapes with a stated range re-measured
directly at the cap rather than extrapolated; the "fixed multiplier"
language softened to "bounded" with the `sorted()`-cost caveat stated
explicitly; two new tests added (default-path, cross-call isolation) plus
their acceptance-criteria bullets; the three citation slips fixed; one
sentence added noting the memoization alternative was considered and
rejected (mirroring the plan's existing rejected-alternatives treatment).
No second round needed — every item was a calibration/precision/coverage
fix, none touched the plan's mechanism, ordering, or safety reasoning, which
the same review round already confirmed sound.
