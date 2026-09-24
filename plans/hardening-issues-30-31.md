# Hardening: close issues #30–#31, plus a live single-hop revocation bypass found during grounding

## Context

`aitp-verifier-py` is a pure-Python, network-free, independent re-implementation of AITP
verification, built from RFC text alone. Every public verifier entry point's contract is
"raise `AitpError` or return a verdict dict" — a caller that writes `except AitpError` must
never see a raw Python exception, and a verifier must never report "not revoked" for an
artifact it has trusted evidence against.

Two issues (#30, #31) were filed during the previous plan's (`plans/hardening-issues-23-27.md`)
Phase 8 work and deliberately left out of that PR's scope — #30 because closing it correctly
requires a design decision about `verify_tct`'s input contract, #31 because it is a
cross-cutting fix to shared canonicalization infrastructure rather than anything specific to
the revocation-snapshot trust fix. Both were re-grounded against current `main` (`adcd06f`)
by fresh Opus subagents, and every load-bearing claim below was re-confirmed by direct reads
and live measurement while writing this plan. A **third finding, not in either filed issue**,
surfaced during that grounding and is the highest-severity item here.

- **#30** (`tct.py::_check_revocation` fails open on absence): confirmed live on current code.
  `_check_revocation` (`tct.py:134-157`) reads `inp.get("issuer_revocation_list")` at
  `:146` and returns silently at `:147-148` when it is absent or non-dict — a TCT whose
  `jti` genuinely sits on an unreachable/omitted deny list verifies successfully. Two further
  silent-skip paths live in the same function: a snapshot whose *verified* issuer is someone
  other than this TCT's `iss` skips the deny-list scan entirely (`:154-155`), and the
  wrapper's own `issuer`/`fail_mode` members are never read at all. **Decisive finding:** the
  spec's own conformance fixture already carries the lever —
  `schemas/conformance/tct-004-revoked.json` supplies
  `issuer_revocation_list = {"issuer": ..., "fail_mode": "fail_closed", "snapshot": {...}}`,
  and `tests/test_unknown_fields.py:636-657`'s `_tct_revocation_input` helper mirrors it. A
  `fail_mode` concept is *already in `verify_tct`'s spec-side input shape*; `tct.py` ignores
  it. This is unimplemented, not absent.
- **#31** (`canonical_bytes` lets a deep-nesting `RecursionError` escape): confirmed live,
  and the numbers matter. `canonicalize` (`jcs.py:187-189`) → `dumps` (`:180-184`) →
  `_serialize` (`:144-177`), which recurses once per JSON value (`:160` for a list element,
  `:174` for a dict member). No depth or size guard exists anywhere in `jcs.py`. Measured
  today on the repo's own 3.13 venv (`/tmp/aitpvenv313`, stock `sys.getrecursionlimit()` =
  1000, nothing in the repo or CI changes it): `canonical_bytes({"extensions": <993-deep
  dict>})` succeeds, `<1200-deep>` raises a raw `RecursionError` — surfacing from inside
  `key.encode("utf-16-be")` at `jcs.py:166`, an arbitrary deep C call, exactly the "fragile
  place to recover" issue #31 predicts. Meanwhile `json.loads` accepts a 5,000-deep document
  on the same interpreter (it only fails around 20,000), so **`json.loads` will not reject
  the input first** — a depth cap inside the canonicalizer is genuinely reached and genuinely
  necessary. (Correction to the grounding notes: the measured `json.loads` tolerance is
  between 5,000 and 10,000 — re-measured during plan review on the same interpreter: 5,000
  accepted, 10,000 raises — not "~10k–60k" and not "~20,000"; the load-bearing conclusion is
  unchanged.)
- **Newly discovered during grounding, in neither filed issue — `delegation.py`'s single-hop
  path performs ZERO revocation checking, including when a present, fully-trusted snapshot
  proves the token's source TCT is revoked.** Verified independently by a fresh critical-tier
  agent (trust-boundary finding) that read the code and ran a live reproduction, and
  re-confirmed statically while writing this plan: the single-hop body is
  `delegation.py:97-138`; `_revocation_index` (`:141-177`) has exactly one caller, at `:267`,
  inside `_verify_multihop`. The single-hop path never reads `revocation_snapshots`,
  `issuer_revocation_list`, or `vclaims["src_jti"]` at all. The live reproduction minted
  spec fixture `del-001`, attached a revocation snapshot **signed by A (`self_aid`) listing
  the voucher's own `src_jti`**, confirmed the snapshot passes `verify_snapshot_trust`
  (genuinely trusted, not bogus), and got `{'grants': ['read_data']}` — success. This is not
  #30's "absent ⇒ silent pass" class. **This is "present-and-cryptographically-verified-
  revoked ⇒ pass anyway":** the verifier's own trusted deny list is computed and then never
  consulted on this path. The spec is an unambiguous MUST on the **core** path:
  `rfcs/RFC-AITP-0006-delegation.md:97` ("A MUST verify all of the following, in order …
  the revocation lookup (step 7) comes after all signature checks") and `:111` ("Source TCT
  revocation. Look up `voucher.src_jti` in A's own deny list … MUST be rejected ⇒
  `DELEGATION_SOURCE_TCT_REVOKED`"), with `RFC-AITP-0008-revocation.md:25` ("One deny-list
  entry therefore invalidates the TCT, its voucher, and every delegation token built on that
  voucher"). `del-001` is `status: core`, `required_for_v0_2: true`. This is a gap, not a
  design decision: `src_jti` is schema-required and enforced today
  (`voucher.py::_VOUCHER_REQUIRED_CLAIMS` includes it, and `check_voucher_claims_shape` runs
  on the single-hop path at `delegation.py:129`, so `vclaims["src_jti"]` is a
  shape-guaranteed `str` by then); `minter.py:389` already signs `revocation_snapshots`
  records for *any* operation. No new field, no new error code, no wire-format change is
  needed. No prior deferral of it exists anywhere in `ASSUMPTIONS.md`,
  `plans/hardening-issues-23-27.md`, or `PROGRESS.md` — it was unnoticed, not decided.
- **A small, separate latent defect in already-shipped code**, found while grounding #30:
  `revocation.py:184-187` handles `soft_fail` and falls through to `raise` for everything
  else — so `fail_mode: "fail_open"`, a valid RFC-AITP-0008 §3.1 mode, currently behaves
  identically to `fail_closed`. No conformance fixture exercises `fail_open` (verified: only
  `rev-001` `fail_closed`, `rev-002` `soft_fail`, `rev-003`/`005`/`006`/`007`/`008`
  `fail_closed` — seven fixtures, not eight: `rev-004` is a `verify_tct` fixture that carries
  no `policy` at all), which is why it has gone unnoticed.

**Conformance constraints, re-derived live rather than taken from the grounding notes** (the
grounding's "tct-012 plus eight siblings expect success without revocation data" was
imprecise). Walking every fixture in `schemas/conformance/`:

- `verify_tct` has 10 fixtures. Exactly **one** expects success with no `issuer_revocation_list`
  supplied: `tct-012-ext-unknown-key-accepted` (`required_for_v0_2: true`). The other eight
  `verify_tct` failure fixtures never reach `_check_revocation` (they fail at signature,
  expiry, `typ`, `alg`, or member-set checks first), and `tct-004-revoked` supplies the
  wrapper.
- `verify_delegation_token` has 10 fixtures. **Two** expect success with no
  `revocation_snapshots` supplied: `del-001-success` (`required_for_v0_2: true`, core) and
  `del-mh-001-success` (draft opt-in `experimental-multihop-delegation`).

So an unconditional fail-closed-on-absent default — with no policy supplied at all — would
turn three currently-passing success fixtures red, one of them a required-for-v0.2 core
fixture on each of the two entry points. That is the hard constraint shaping Phases 3–4's
default, and it is a *conformance* constraint, not a preference.

**What RFC-AITP-0008 §3.1 does and does not say.** `rfcs/RFC-AITP-0008-revocation.md:143-175`
defines `revocation_policy.mode` ∈ {`fail_closed`, `fail_open`, `soft_fail`}, states "Under
`fail_closed` an absent snapshot means revocation status is unknown, and unknown is treated
as revoked … rejected with `TCT_REVOKED`. Conformance fixture `rev-001` pins this", and
"The schema default for `revocation_policy.mode` is **`fail_closed`** … Deployments that
need availability-first behavior MUST opt into `soft_fail` or `fail_open` explicitly". This
is a *deployment policy* concept: it presupposes a configured policy object exists. It does
not mandate that a verifier function given **no policy at all** invent `fail_closed` for
itself — and the spec's own pack proves the point, since it ships core success fixtures with
no revocation input on both entry points. Hence: adding a `policy` concept to `verify_tct`/
`verify_delegation_token` is a **contract widening**, a new capability whose default is a
fresh, deliberate design choice, not the restoration of originally-intended behavior. It is
the one genuine one-way door in this plan (see Open questions).

**Backward compatibility is free**: never released (`pyproject.toml` version `0.1.0`, no git
tags, Alpha), no external callers, `verify.py`'s `OPERATIONS` dispatch table unchanged by
every phase here.

## PR grouping and sequencing

This plan is **5 phases grouped into 3 PRs**. The reasoning is recorded here rather than
applied silently, because the grouping is itself a judgment call about what is honestly
reviewable together and what must not wait behind a design decision:

- **PR 1 — Phase 1** (closes #31). Fully independent: no design decision, no contract change,
  ~6 lines of production code across two files plus tests. It touches `jcs.py`/`fields.py`,
  which no other phase here edits. Ships first and alone so a mechanical, obviously-correct
  hardening fix is not held hostage to the revocation-policy discussion in PR 3.
- **PR 2 — Phase 2** (the single-hop present-snapshot revocation check). This is the
  highest-severity live finding in this plan: a present, cryptographically-verified
  revocation is currently ignored on a spec-core, `required_for_v0_2` path. It is
  independent of the one-way-door policy decision in Phases 3–4 (it concerns a snapshot that
  IS supplied and IS trusted), reuses an existing helper, an existing registered error code,
  and an ordering the spec already mandates. Ships urgently, on its own, rather than bundled
  behind the slower design phases.
- **PR 3 — Phases 3, 4 and 5** (closes #30, plus the `fail_open` bug fix and docs). Phases 3
  and 4 are **one design decision landing across two files**: the same `policy`/`fail_mode`
  shape and the same default, applied symmetrically to `tct.py` and `delegation.py`.
  Reviewing them in separate PRs would be reviewing half a decision at a time — and the
  previous plan's `/reconcile` pass established symmetry across these two consumers as the
  right posture (precisely: `DECISIONS.md:64-66` records that **fail-closed treatment of an
  obtained-but-untrustworthy snapshot** is "correctly and symmetrically applied across both
  consumers"; `ASSUMPTIONS.md:138` uses the same wording). That pass was about the
  untrustworthy branch, not about `fail_mode`, so it is a *precedent for symmetry*, not a
  ruling on this default — but splitting Phases 3 and 4 would still recreate exactly the
  asymmetry that pass closed.
  Phase 5 documents precisely this change, so it belongs in the same PR — but it is written
  as its own phase and lands as its own commit, matching the previous plan's convention of
  one phase = one commit even when phases share a PR.

Phase 1 and Phase 2 have no dependency on each other and could ship in either order; Phase 1
is listed first only because it is smaller and touches shared infrastructure that a later
reviewer will otherwise see move underneath them. Phase 4 depends on Phase 3. Phase 5
depends on 1–4 having landed (it describes them).

**One hard branch-ordering constraint, stated because the files overlap:** PR 3's Phase 4
edits the very call site Phase 2 inserts, in the same file (`delegation.py`). PR 3 must
therefore be branched from — or rebased onto — PR 2's merge commit, not cut from the same
`main` PR 2 was cut from. PR 1 shares no file with either (`jcs.py`/`fields.py` are touched
by no other phase here, confirmed) and is order-free against both. Confirm the merge-base
before starting Phase 3, the same way the previous plan's Phase 2/Phase 8 same-file overlap
was called out.

## Phases

### Phase 1 — Depth-cap `jcs.py`'s serializer, and convert `RecursionError` at the `fields.py` boundary (closes #31)

**Status:** DONE (2026-09-23). Implemented exactly as planned — no divergence in the
production diff: `_MAX_DEPTH = 256` with the three-bounds rationale comment, the entry guard
on `_serialize`'s new `depth: int = 0`, `depth + 1` at both recursion sites, the constant-
message `except RecursionError` clause in `canonical_bytes`, the `JcsError` message left
byte-identical, and every named test present under its planned name. Two additions beyond
the plan's literal text, both from the fresh-verifier gap round: (a) three **list**-nesting
tests in `tests/test_fields.py` (`_deep_list` helper) — the plan's test list built only
nested dicts, leaving `_serialize`'s list-element recursion site with zero coverage, proven
by mutation (dropping its `depth + 1` left the whole suite green); (b) the two measurements
this phase's acceptance criteria require are now recorded in `PROGRESS.md`'s `## Phase 1`
subsection (max canonicalization depth across the pack and `signed-examples/`; the
`deep-nesting` `_MUTATIONS` entry's per-operation vacuity). This phase's **Delivers** was
also narrowed during that round — see issue #38, an unbounded recursive walk with no
`canonicalize` involvement that this phase correctly does not close.

**Delivers:** `jcs.py::_serialize` refuses to descend past a fixed relative nesting depth,
raising `JcsError` — which every attacker-reachable call site already converts to its own
structural `AitpError` via `fields.canonical_bytes`. `fields.canonical_bytes` additionally
converts a `RecursionError` that reaches it anyway (from a caller whose own stack was
already near-exhausted) into the same `AitpError`, with a constant message. After this
phase no verifier entry point can be made to raise a raw `RecursionError` by nesting depth
in any attacker-supplied JSON **that reaches `canonical_bytes`/`canonicalize`** — including
inside an `extensions` member whose interior RFC-AITP-0001 §7 forbids inspecting. The scope
qualifier is load-bearing, not hedging: a separate unbounded recursive walk that involves no
canonicalization at all (`jwk.py::issuer_keys_from`, reachable from
`verify_handshake_payload` via `resolved_issuer_keys`) has the same symptom and is untouched
by this phase — filed as issue #38, deliberately out of scope here.

**Depends on:** none.

**Files:**
- `aitp_verifier/jcs.py` — new module constant `_MAX_DEPTH`; `_serialize` (`:144`) gains an
  explicit `depth: int = 0` parameter and an entry guard; the two recursive calls (`:160`
  list element, `:174` dict member value) pass `depth + 1`.
- `aitp_verifier/fields.py` — `canonical_bytes` (`:146-159`) gains a second `except` clause
  for `RecursionError`.
- `tests/test_fields.py`, `tests/test_envelope.py`, `tests/test_boundary_contract.py`.

**Approach:** Thread an explicit `depth` parameter rather than using a module-level counter
or `sys.setrecursionlimit` — a parameter is re-entrant, thread-safe, and costs one integer
per frame. At `_serialize`'s entry:

```python
_MAX_DEPTH = 256  # see the rationale comment this phase adds above the constant

def _serialize(value: JsonValue, out: list[str], depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        raise JcsError(f"JSON nesting exceeds the maximum canonicalizable depth ({_MAX_DEPTH})")
```

The cap bounds the **relative nesting depth of this walk only** — deliberately not total
document size, which is an orthogonal concern already bounded by input size (JCS output is
linear in input, and this library parses nothing itself: every entry point receives an
already-parsed `dict`, per `verify.py`'s `OPERATIONS` table).

`_MAX_DEPTH = 256` is chosen against three measured bounds: real AITP artifacts nest ≤ ~5
levels (deepest observed shape in the pack: `session_bundle.session_bundle.participants[i]`
and `issuer_revocation_list.snapshot.revocation_list.entries[i]`); the interpreter's actual
ceiling from these call sites is ~993–1200 frames (measured live on 3.13.7 with the stock
limit of 1000 — 993-deep canonicalizes, 1200-deep raises); and the cap must leave generous
headroom for the *embedding caller's* stack, which is unmeasurable from inside this library.
256 is ~50× any legitimate document and leaves ≥ ~730 frames of the interpreter budget to
the caller.

Defense-in-depth at the boundary, as two separate `except` clauses (`RecursionError`
subclasses `RuntimeError`, not `ValueError`, so the two are disjoint and clause order does
not matter):

```python
    except JcsError as exc:
        raise AitpError(shape_code, f"{what} is not canonicalizable: {exc}") from exc
    except RecursionError as exc:
        raise AitpError(shape_code, "value is too deeply nested to canonicalize") from exc
```

The `RecursionError` message is a **constant literal** with no interpolation: formatting a
message while the stack is exhausted can itself re-trigger the error, and the phase's whole
point is that the recovery path must not be fragile. The existing `JcsError` message stays
byte-identical (no existing test asserts it, but preserving it keeps the diff honest).

No new registry error code is needed anywhere. Each attacker-reachable call site already
passes its own `shape_code` into `canonical_bytes`, and a depth defect is structurally the
same class as the huge-int rejection those codes already cover: `envelope.py:51`
(`INVALID_ENVELOPE`, reached by `verify_envelope` **and** `handshake.py`'s bootstrap path
through the shared `envelope_signing_input`), `manifest.py:204` (`MANIFEST_INVALID`, whole
manifest body including `extensions`), `revocation.py:164` (`REVOCATION_SNAPSHOT_INVALID`,
reached by `verify_revocation_snapshot` directly **and** as an embedded snapshot from
`tct.py:149` and `delegation.py:175` via `verify_snapshot_trust`), `sessionbundle.py:207`
(`SESSION_BUNDLE_INVALID`). The raw `canonicalize` calls that do **not** go through
`canonical_bytes` need no change — there are eight, not two (re-swept during plan review):
`delegation.py:82` canonicalizes a flat `list[str]` of digests (fixed depth 2, not
attacker-nestable); `jws.py:125` sits inside `encode_jws`, which its own docstring scopes to
"the conformance minter only"; and `minter.py:107`, `:111`, `:131`, `:152`, `:169`, `:327`
are all fixture-minting code, never reachable from verifier input. The repo's only
`json.loads` on remote-ish input, `jcs.loads` via `jws.py:60-61`, is already wrapped by the
`except Exception` at `jws.py:62-63`, which does catch `RecursionError` (`keys.py:25`'s
`json.loads` reads local KAT key files, not wire input).

**Edge cases & failure modes:** the guard must be at function entry, not at the recursion
sites — putting it at the two call sites would let the top-level call itself exceed the cap
when a caller passes an already-deep value. `depth` must default to `0` so `dumps`
(`:180-184`) needs no change and no external caller of `_serialize` (there are none outside
this module) breaks. The cap counts *this walk's* frames, so a 256-deep value nested inside
another 256-deep value is correctly rejected as 512, not accepted twice. Confirm the sorted-
key line at `:166` still runs only after the depth guard (it is the line the live
`RecursionError` surfaces from today). `_MAX_DEPTH` must not be tuned to the current
interpreter limit at import time (e.g. `sys.getrecursionlimit() // 4`): a fixed constant
makes the rejection reproducible across interpreters and across a caller that changes the
limit, which is what makes it testable at all.

For `tests/test_boundary_contract.py`, the new `_MUTATIONS` entry has a **known scope
limitation that must be measured rather than assumed**: the prior plan's Phase 7 recorded
that any mutation landing on a field `mint_input` itself canonicalizes dies inside
`mint_input` and is skipped by `_sweep`'s `except Exception` (`:160-214`) before reaching
the verifier. A deep-nesting value is exactly that shape — and `RecursionError` *is* an
`Exception` subclass, so it is caught by that same skip guard both pre- and post-fix. The
entry may therefore be vacuous for every one of the eight operations. Add it anyway (it
keeps the harness's hostile-value catalogue complete for any future entry point whose
minting path does not canonicalize the mutated field), but **do not** claim it as this
phase's proof; the proof is the direct unit tests plus the mint-then-mutate end-to-end tests
below, which inject the deep value *after* minting and so bypass the blind spot entirely.
Measure whether the entry is vacuous (a temporary counter in `_sweep`) and record the result
in `PROGRESS.md`, exactly as the prior plan recorded its own harness-scope finding.

**Acceptance criteria:**
- `aitp_verifier/jcs.py` defines `_MAX_DEPTH = 256` with a comment stating the three bounds
  it was chosen against, and `_serialize` raises `JcsError` (not `RecursionError`) for a
  value nested deeper than it.
- `canonical_bytes({"extensions": <a 300-deep dict>}, shape_code="MY_CODE", what="obj")`
  raises `AitpError(code="MY_CODE")`.
- The boundary is pinned **exactly**, by two tests one level apart, and the counting
  convention is stated in the test names/docstrings rather than left implicit — because
  "a 256-deep dict" is ambiguous on its own and shifts by one depending on whether the value
  is wrapped. Pin it against the `depth` parameter, whose meaning the guard fixes: the
  top-level `_serialize` call runs at `depth == 0`, each nested value one deeper, and
  `depth > _MAX_DEPTH` raises — so the deepest value that can still be serialized sits at
  `depth == _MAX_DEPTH`. With `_deep_dict(n)` defined as *n* nested `dict` levels around a
  leaf (`_deep_dict(1) == {"a": <leaf>}`), passed **unwrapped** to `canonicalize`, that means
  `canonicalize(_deep_dict(256))` succeeds and `canonicalize(_deep_dict(257))` raises
  `JcsError`. The implementer MUST verify these two numbers against the chosen `_deep_dict`
  spelling at implementation time and correct them in the test names if the helper counts
  differently — what is non-negotiable is that two adjacent depths are asserted and that the
  accepted one is exactly one below the rejected one.
- `canonical_bytes` converts a `RecursionError` raised by `canonicalize` itself into
  `AitpError(code=<shape_code>)` with a constant message — proven by monkeypatching
  `aitp_verifier.fields.canonicalize` (the name `fields.py:75` imports directly) to raise
  `RecursionError`.
- `verify_envelope` and `verify_handshake_payload` each raise `AitpError(code="INVALID_ENVELOPE")`
  — not a raw `RecursionError` — for an envelope whose `payload` carries a 2000-deep value
  injected after minting, mirroring `tests/test_envelope.py:148-199`'s existing
  `1e400`/huge-int pair and their `_via_handshake` siblings exactly.
- The maximum JSON nesting depth actually reached by any `canonical_bytes`/`canonicalize`
  call across the whole conformance pack and `signed-examples/` is **measured** (a temporary
  instrumented run) and recorded in `PROGRESS.md`; it must be ≤ 8, i.e. ≥ 30× headroom below
  the cap. If it is not, stop and re-derive the constant rather than raising it silently.
  (Already measured once during plan review, by wrapping `fields.canonical_bytes` and
  `jcs.canonicalize` and running `run_conformance.py`: **max container depth 3**, far inside
  the bound. The phase still runs its own measurement — this number is the expected answer,
  not a substitute for producing it.)
- `tests/test_boundary_contract.py::_MUTATIONS` gains a `("deep-nesting", _deep_dict(2000))`
  entry (with a module-level `_deep_dict(n)` helper), and whether that entry is reachable or
  vacuous per operation is measured and recorded — not assumed either way.
- Full existing suite unchanged: `pytest tests/` green, `run_conformance.py` reports the same
  pass/fail/skip counts as before the change, `mypy --strict` clean (the new `depth`
  parameter is typed).

**Tests:**
- `tests/test_fields.py` (extend the `canonical_bytes` block at `:96-115`):
  `test_canonical_bytes_rejects_excessive_nesting`,
  `test_canonical_bytes_accepts_nesting_at_the_cap`,
  `test_canonical_bytes_rejects_nesting_one_past_the_cap`,
  `test_canonical_bytes_converts_recursionerror_to_aitperror` (monkeypatched).
  Also one direct-`jcs` assertion here — `test_canonicalize_raises_jcserror_not_recursionerror`
  — proving the cap raises the library's own error type at the `jcs` layer, since there is
  no `tests/test_jcs.py` today and creating one for a single assertion is churn (decidable
  at implementation time if that judgment changes).
- `tests/test_envelope.py`: `test_envelope_deeply_nested_payload_value_does_not_crash` and
  `test_envelope_deeply_nested_payload_value_does_not_crash_via_handshake`, following
  `:148-199`'s mint-then-mutate shape verbatim.
- `tests/test_boundary_contract.py`: the `_MUTATIONS` entry above.

**Docs:** `jcs.py`'s module docstring gains one sentence noting the serializer is depth-
capped and why (it currently describes only number handling and the JCS profile). No
`CHANGELOG.md` entry in this phase — Phase 5 writes all of them together.

---

### Phase 2 — `delegation.py` single-hop: consult the trusted deny list that is already being computed (RFC-AITP-0006 §4 step 7)

**Status:** DONE (2026-09-24) — code and tests landed, independently verified PASS by a fresh
agent, which independently reproduced the bypass on pre-fix code (an `AitpError`-free
`{"grants": [...]}` verdict for a `del-001` input whose voucher's `src_jti` sat in a
self-signed, trusted deny list) and confirmed the fix closes it, confirmed both stated
non-goals hold behaviorally (not just by reading), mutation-tested the ordering acceptance
criterion, and re-ran the full gate independently (336 passed, mypy clean, conformance
68/0/1 unchanged across all 10 fixtures). Implemented exactly as planned, with no divergence:
the four-line insertion is the Approach block verbatim (`_revocation_index(inp)`, then
`vclaims["src_jti"] in revoked.get(self_aid, set())` ⇒ `DELEGATION_SOURCE_TCT_REVOKED`),
placed after the scope check and before the final `return`, with the bracket access the plan
argues for; `delegation.py`'s module docstring updated per the Docs field; all five named
tests present under their planned names, built on `_load_conformance_input(spec_dir,
"del-001")` as specified. One addition beyond the plan's literal text, mechanical only: a
module-level `DEL_001_SRC_JTI` constant and a `_single_hop_revoked_input(...)` helper in
`tests/test_unknown_fields.py`, parameterized on entry jti and snapshot issuer so the four
positive/negative-control cases vary exactly one thing each — the same shape
`_tct_revocation_input` already establishes for the TCT side. The load-bearing non-vacuity
criterion was hand-verified against pre-fix code: the revoked-source-TCT input returns
`{"grants": ["read_data"]}` on `main`'s `delegation.py` (with `_revocation_index` on that
same input demonstrably holding the voucher's `src_jti` under the `self_aid` key) and raises
`DELEGATION_SOURCE_TCT_REVOKED` after the fix; two of the five new tests fail pre-fix (the
revoked case and the forged-signature case), while the three negative controls pass in both
worlds, which is what they are for. `pytest tests/ -q` 331 → **336 passed**;
`run_conformance.py` **68 passed / 0 failed / 1 skipped**, unchanged, no fixture verdict
moved; `mypy` clean, 37 source files. This phase's acceptance criteria require no
`PROGRESS.md` measurement (unlike Phase 1's two), so none was recorded.

**Delivers:** `verify_delegation_token`'s single-hop path performs the RFC-AITP-0006 §4
step-7 source-TCT revocation lookup it currently skips entirely. A delegation token whose
embedded voucher's `src_jti` appears in a **present, structurally valid, member-set-valid,
correctly-signed** revocation snapshot issued by `self_aid` (A's own deny list) is rejected
with `DELEGATION_SOURCE_TCT_REVOKED`, instead of verifying successfully as it does today.
This is the live bypass described in Context: not an absence gap, but trusted evidence
computed and then ignored.

**Depends on:** none. Explicitly independent of Phases 3–4: this phase concerns a snapshot
that IS supplied and IS trusted, so no `fail_mode`/policy concept is involved, and nothing
here presupposes which default Phase 3 lands on.

**Files:**
- `aitp_verifier/delegation.py` — the single-hop path, after the scope check at `:135-136`
  and before `return {"grants": claims["scope"]}` at `:138`.
- `tests/test_unknown_fields.py` (the delegation/revocation block).

**Approach:** Reuse the existing multi-hop pattern at `:267-269` verbatim — same helper,
same index semantics, same error code:

```python
    # Source TCT revocation (RFC-AITP-0006 §4 step 7) — strictly after every
    # signature and claims check above, per RFC-AITP-0008 §3.3.
    revoked = _revocation_index(inp)
    if vclaims["src_jti"] in revoked.get(self_aid, set()):
        raise AitpError("DELEGATION_SOURCE_TCT_REVOKED", "source TCT revoked")
```

Three properties make this a 4-line change rather than a design exercise:

1. **Ordering is already satisfied.** Lines `:97-136` are all JWS/claims checks (outer
   signature, self-delegation, audience, expiry, embedded-voucher signature, voucher subject,
   expiry monotonicity, scope subset) — RFC-AITP-0006 §4's steps 1–6 **plus step 8**
   (no-self-delegation, which this module already runs early, at `:107-108`, rather than
   after step 7; that pre-existing reordering is outside this phase's scope and is harmless,
   since step 8 is a pure claims comparison). Inserting the lookup after `:136` puts it
   exactly where §4:97 and §4:111 require ("the revocation lookup (step 7) comes after all
   signature checks"), which is also what `rev-004`'s side-effect assertion pins for the TCT
   path, and it lands after step 6 (scope) as §4's numbering requires.
2. **Bracket access on `vclaims["src_jti"]` is safe here**, unlike multi-hop's
   `root_voucher.get("src_jti")` at `:268`: `check_voucher_claims_shape` runs at `:129` and
   `voucher.py::_VOUCHER_REQUIRED_CLAIMS` includes `src_jti` with a declared `str` type, so
   by this line it is a shape-guaranteed string. (Use `.get()` anyway if the implementer
   prefers symmetry with `:268` — either is correct; bracket is stated here because it is
   provably safe and documents the invariant.)
3. **The index is keyed on the verified issuer.** `_revocation_index` (`:141-177`) runs each
   record through `verify_snapshot_trust` and indexes on the signed `body["issuer"]`, never
   the caller-supplied `record["issuer_aid"]` label — the "signed value wins" property the
   previous plan's Phase 8 established. `revoked.get(self_aid, set())` is therefore literally
   "A's own deny list", as §4 step 7 words it.

Deliberately **not** in scope for this phase: making the single-hop path also accept
`issuer_revocation_list` as a carrier. `revocation_snapshots` is the field the multi-hop
path already uses, that `minter.py:389` already signs for any operation, and that the
conformance pack already carries for this operation family; adding a second accepted carrier
for the same data would widen the input contract for no spec-stated reason. Noted here so a
reviewer sees it was considered, not overlooked.

Also deliberately **not** in scope: extending the multi-hop path's *second* revocation check
— the per-hop `hc["jti"] in revoked[hc["iss"]]` loop at `:270-273` — to the single-hop token.
That loop implements RFC-AITP-0011 §6 (Draft, multi-hop only). Core RFC-AITP-0006 §4 step 7
names exactly one lookup, `voucher.src_jti`, and RFC-AITP-0008 §1.1 is explicit that the
voucher "has no independent revocation handle" — one deny-list entry on the source TCT's
`jti` is what invalidates the whole derived chain. So the single-hop path gets one check, not
two, and the resulting asymmetry with `:270-273` is spec-faithful rather than an omission.

**Edge cases & failure modes:** this insertion makes `_revocation_index` reachable from the
single-hop path for the first time, which means **two new rejection paths appear for
single-hop inputs that carry revocation data**: a malformed `revocation_snapshots` (non-list,
including the falsy values the previous plan's `/reconcile` pass fixed) now raises
`REVOCATION_SNAPSHOT_INVALID`, and a snapshot that fails `verify_snapshot_trust` (bad shape,
unknown member, forged/absent signature) now raises its own structural/signature code rather
than being ignored. Both are correct and are the same obtained-but-untrustworthy semantics
`tct.py` and the multi-hop path already have — but they are a behavior change for a caller
who was passing junk in that field to a single-hop verification and getting away with it.
State this in the `CHANGELOG.md` entry Phase 5 writes.

`del-001` and every other single-hop fixture supplies no `revocation_snapshots`, so
`_revocation_index` returns `{}`, `revoked.get(self_aid, set())` is empty, and no fixture
changes verdict — confirmed by walking all 10 `verify_delegation_token` fixtures. Absence
handling stays exactly as it is today (`:165-167`, `None ⇒ []`); changing it is Phase 4's
job and must not be pre-empted here.

A snapshot genuinely signed by someone **other than** `self_aid` that lists this `src_jti`
must NOT reject: it is not A's deny list. This falls out of the `revoked.get(self_aid, ...)`
keying for free, but it needs its own test — it is the difference between "consult A's deny
list" and "consult any deny list anyone hands us."

**Acceptance criteria:**
- A single-hop `del-001`-shaped input, plus a `revocation_snapshots` record whose snapshot is
  genuinely signed by `self_aid` and lists the voucher's `src_jti`
  (`550e8400-e29b-41d4-a716-446655440101`), causes `verify_delegation_token` to raise
  `AitpError(code="DELEGATION_SOURCE_TCT_REVOKED")`. Hand-verify that this exact input
  returns `{"grants": ["read_data"]}` on pre-fix code (`git stash`), so the test is proven
  non-vacuous — this is the single most important check in the phase.
- The same input with the snapshot listing an unrelated `jti` still returns
  `{"grants": ["read_data"]}`.
- The same input with the snapshot genuinely signed by a **different** peer (not `self_aid`)
  and listing the voucher's `src_jti` still returns `{"grants": ["read_data"]}` — the deny
  list consulted is A's own, not anyone's.
- The same input with one byte of the snapshot signature flipped raises
  `AitpError(code="REVOCATION_SNAPSHOT_SIGNATURE_INVALID")` — proving the single-hop path now
  gets the same snapshot-trust guarantee the multi-hop path has, not a face-value read.
- The revocation check runs **after** the scope check: an input that is both scope-exceeding
  and source-revoked reports `DELEGATION_SCOPE_EXCEEDED`, pinning §4's step order.
- All 10 `verify_delegation_token` conformance fixtures pass unchanged;
  `tests/test_conformance.py:33`'s `assert passed >= 51` still holds with the same count
  (baseline re-measured during plan review: `run_conformance.py` → 68 passed / 0 failed /
  1 skipped).
- Every existing `tests/test_unknown_fields.py` delegation test passes unmodified.

**Tests:** new cases in `tests/test_unknown_fields.py`'s delegation block, reusing the
existing `_load_conformance_input(spec_dir, "del-001")` helper (`:747`) rather than
hand-building a chain — the same reuse the multi-hop revocation tests already make of
`del-mh-004`. Names: `test_delegation_single_hop_revoked_source_tct_is_rejected`,
`test_delegation_single_hop_unrelated_revoked_jti_still_verifies`,
`test_delegation_single_hop_snapshot_from_another_issuer_does_not_apply`,
`test_delegation_single_hop_forged_snapshot_signature_is_rejected`,
`test_delegation_single_hop_scope_check_precedes_revocation`.

**Docs:** `delegation.py`'s module docstring (`:1-16`) currently describes revocation as a
multi-hop-only concern ("Multi-hop's per-hop revocation snapshots (RFC-AITP-0011 §6) are each
fully verified …"). Update it to state that the single-hop checklist ends with the §4 step-7
source-TCT lookup, so the docstring stops documenting the gap as if it were the design.
`CHANGELOG.md` entry is written in Phase 5.

---

### Phase 3 — `verify_tct` gains an optional `policy`/`fail_mode`, and `revocation.py`'s `fail_open` stops behaving like `fail_closed` (closes #30's core)

**Status:** NOT STARTED.

**Delivers:** `verify_tct`'s input contract gains one optional top-level key, `policy`,
mirroring `verify_revocation_snapshot`'s existing `inp["policy"]` shape; `_check_revocation`
honors it, and also honors the per-wrapper `issuer_revocation_list.fail_mode` the spec's own
`tct-004` fixture already carries and this code currently ignores. Under an effective
`fail_closed`, a TCT for which no trusted, applicable, fresh revocation snapshot was supplied
is rejected with `TCT_REVOKED` — RFC-AITP-0008 §3.1's "unknown is treated as revoked". In the
same phase, `revocation.py:184-187` stops treating `fail_open` as `fail_closed`.

**Depends on:** none strictly, but sequenced after Phases 1–2 because it is the one one-way
door here and should land with the smaller fixes already green.

**Files:**
- `aitp_verifier/tct.py` — `verify_tct` (`:88-131`, the `_check_revocation(claims, inp)` call
  at `:130`) and `_check_revocation` (`:134-157`).
- `aitp_verifier/revocation.py` — stage 4's mode dispatch at `:184-187`.
- `tests/test_unknown_fields.py`, `ASSUMPTIONS.md`.

**Approach — the input contract.** Mirror `verify_revocation_snapshot` exactly rather than
inventing a second spelling: an optional top-level `inp["policy"] = {"fail_mode": ...,
"max_staleness_secs": ...}`. `verify_tct` already takes `now`, so `_check_revocation` gains a
`now: int` parameter threaded from `verify_tct`'s own (it has none today, which is why no
freshness evaluation is possible in it).

**Approach — resolving the effective mode**, in this order. **The precedence here was
inverted during plan review; the original draft had rule 2 outranking rule 1, which opened a
security downgrade. Do not re-invert it without re-reading the reasoning below.**

1. `policy["fail_mode"]` when a top-level `policy` key is supplied and is a dict; a `policy`
   dict **without** `fail_mode` resolves to `fail_closed`, matching `revocation.py:173`'s own
   `policy.get("fail_mode", "fail_closed")` exactly. Supplying `policy: {}` therefore fails
   closed — secure-by-default *within* an explicitly-supplied policy. A supplied top-level
   `policy` is **authoritative and cannot be overridden by anything in the input artifact.**
2. else `issuer_revocation_list["fail_mode"]`, when `issuer_revocation_list` is a dict
   carrying a `str` there. This is the member the spec's own fixture
   (`tct-004-revoked.json:34`) and this repo's own test helper
   (`test_unknown_fields.py:636-655`) already carry and `tct.py` reads nowhere — honoring it
   is reading the spec's input shape as written, and is the half of #30 that says the
   wrapper's declared members are "never read at all".
3. else — no `policy` key at all and no wrapper `fail_mode` — **`fail_open`**, preserving
   today's behavior byte-for-byte. See Open questions: this is the plan's one substantive
   design decision, forced by the conformance constraint in Context (`tct-012` is a
   `required_for_v0_2` success fixture with no revocation data supplied at all, and
   `verify_tct` — unlike `verify_revocation_snapshot` — has no precedent of `policy` being a
   required, always-present field).
4. A non-dict `policy`, an unrecognized mode string from either source, **or a present
   `fail_mode` that is not a `str` at all** (e.g. `5`, `None`, `[]`), resolves to
   `fail_closed` — never silently permissive, and never a raw `TypeError`/`KeyError`. The
   non-`str` case is called out because the obvious spelling (an `isinstance(..., str)` guard
   that falls through on failure) would send a **wrong-typed** `fail_mode` (`5`) to the
   permissive default while a merely **misspelled** one (`"fail_klosed"`) lands on
   `fail_closed` — the more broken input treated more leniently, which is backwards.

**Why rule 1 outranks rule 2 (the review correction).** `issuer_revocation_list.fail_mode` is
an **unsigned member of the caller-supplied wrapper**: the snapshot signature covers only the
inner `revocation_list` body (`revocation.py:164`, and `tct-004`'s own `$comment` says so
explicitly — "the `{revocation_list, signature}` envelope is the wire shape and is never
signed"). If the wrapper outranked the top-level `policy`, a deployment that had explicitly
configured `policy: {"fail_mode": "fail_closed"}` could be silently downgraded to
`soft_fail`/`fail_open` by whatever assembled the `issuer_revocation_list` wrapper — which,
for a real integrator, is a remote `ListRevoked` response with a locally-added envelope. That
is precisely the class of thing this plan refuses two paragraphs below for the sibling member
`issuer_revocation_list["issuer"]`, on the previous plan's "signed value wins" grounds; the
two members are identically untrusted and must be treated identically. With the inverted
order, the wrapper's `fail_mode` is consulted **only when the deployment has said nothing**,
where it can only ever be *equal to or stricter than* today's behavior (today's absent-case
default is `fail_open`, the most permissive mode, so `soft_fail`/`fail_open` are no-ops and
`fail_closed`/garbage tighten). It is therefore monotone-safe in the one position it holds.
Nothing about the conformance pack or the existing tests depends on the order: `tct-004` and
every `_tct_revocation_input`-built test supplies a wrapper and no top-level `policy`, so
rule 2 still fires for all of them.

**Approach — what counts as "absent" (the only case the mode answers).** Preserve
`revocation.py`'s documented obtained-but-untrustworthy vs. absent split (its module
docstring, `:7-26`) rather than collapsing it: `verify_snapshot_trust` at `tct.py:149` keeps
raising `REVOCATION_SNAPSHOT_INVALID`/`UNKNOWN_FIELD`/`REVOCATION_SNAPSHOT_SIGNATURE_INVALID`
for a snapshot that was obtained and cannot be trusted, and those never consult `fail_mode`.
Absent means:

- (a) `issuer_revocation_list` missing or not a dict (`:146-148` today's silent return); or
- (b) the trusted snapshot's **signed** `body["issuer"] != claims["iss"]` (`:154-155` today's
  silent skip) — a valid snapshot that does not speak for this TCT's issuer leaves this TCT's
  status unknown; or
- (c) **only when a top-level `policy` object is supplied**: `now >= int(body["expires_at"])`,
  or `policy["max_staleness_secs"]` is supplied and
  `now - int(body["published_at"]) > int(policy["max_staleness_secs"])` — RFC-AITP-0008 §3.2's
  staleness rule, the same formula as `revocation.py:183`.

Gating (c) on a top-level `policy` being supplied is deliberate and is what keeps the diff
auditable: with no `policy` key, `verify_tct` behaves **exactly** as today for every input
that reaches it, including `tct-004` (whose snapshot is fresh at `REFERENCE_CLOCK` anyway —
`published_at` 1711900000 = `REFERENCE_CLOCK`, `expires_at` 1711903600 — so the pack would
not have caught a mistake here either way; verified, not assumed). The wrapper's `fail_mode`
alone selects what happens *on* absence; it does not switch on freshness evaluation, because
`max_staleness_secs` is a deployment value with no per-wrapper spelling in the fixture shape.

Then: absent + `fail_closed` ⇒ `raise AitpError("TCT_REVOKED", ...)`; absent +
`soft_fail`/`fail_open` ⇒ return (verify normally). Present and applicable ⇒ the existing
deny-list scan at `:156-157`, unchanged.

**Approach — what is deliberately NOT read.** `issuer_revocation_list["issuer"]` stays
ignored for every trust decision. It is a caller-supplied label, and the previous plan's
review round (`plans/hardening-issues-23-27.md:1426-1432`, finding **B5**, plus the shipped
`_revocation_index` design — `delegation.py:149-152` and `:176`, whose own docstring says
"the signed value wins") established that the **signed** `body["issuer"]` wins over any
wrapper label — reintroducing the label into an applicability decision would regress that.
The wrapper's `issuer` remains a permitted, ignored member, as today. This is a deliberate
deviation from the grounding note's "honor `.issuer`", recorded here with its reason. Note
the consistency this buys with the mode-resolution order above: `fail_mode` and `issuer` are
siblings in the same unsigned wrapper, and neither is ever allowed to override something the
deployment or the signature has already said.

**Approach — the verdict shape.** `verify_tct` keeps returning exactly `{"grants": [...]}`
on success; no `stale` member is added under `soft_fail`/`fail_open`. `verify_tct` returns no
grant-restriction surface for a caller to act on, and several existing tests assert exact
dict equality (`test_unknown_fields.py:151`, `:744`). Recorded as a deliberate scope limit,
not an oversight.

**Approach — the `revocation.py` `fail_open` fix.** At `:184-187`, `fail_open` currently
falls through to the `raise`. Handle all three §3.1 modes explicitly, returning
`{"revoked": False, "stale": True}` for both `soft_fail` and `fail_open`, and raising
`TCT_REVOKED` only for `fail_closed` (and for any unrecognized mode string — never silently
permissive). Rejected alternative: returning a bare `{"revoked": False}` for `fail_open`,
which would make a degraded verdict indistinguishable from a fully-verified fresh one — a
strictly worse security signal. The §3.1 difference between `fail_open` ("allow, log a
warning") and `soft_fail` ("allow with restricted grants") has no representation in this
entry point's verdict, which returns no grants at all; both mean "proceed on degraded
revocation data", and `stale: True` is that signal. **On what `stale` means here** (raised in
review as a possible misnomer, and it is not one): the branch this verdict comes from is
`not (issuer_ok and fresh)` (`:184`), so it also fires for a perfectly fresh snapshot issued
by the wrong peer. `stale: True` therefore already means "this verifier's revocation *status*
for the queried subject is stale/unknown", not "this snapshot document is old" — a reading
the existing `soft_fail` path has shipped with since `revocation.py` was written, and which
`fail_open` inherits unchanged. No caller is newly misled, because no caller could have been
reading it the narrow way and been right. Add one clarifying clause to the module docstring
saying so, rather than inventing a fourth verdict member. This lands in the same phase because it
is the same stage-4 mode dispatch being read and reasoned about, it is small and contained,
and no conformance fixture exercises `fail_open` today (verified across all `rev-*`), so it
would otherwise stay invisible indefinitely.

**Edge cases & failure modes:** every member of `policy` must be read via `.get()`, never
bracket — a `policy` is untrusted caller configuration and the boundary contract ("`AitpError`
or a verdict") applies. `_check_revocation`'s new `now` parameter must be threaded from
`verify_tct`'s own `now`, not read from the wall clock, or the reference-clock-anchored
fixtures become non-reproducible. Order matters inside the function: `verify_snapshot_trust`
must still run before any fail_mode reasoning about (b)/(c), so an untrustworthy snapshot
still reports its own defect rather than being silently downgraded to "absent" — collapsing
those two is precisely the bug `revocation.py`'s docstring records as having shipped once
before.

**One existing test flips expectation**:
`tests/test_unknown_fields.py:733-744`'s
`test_tct_revocation_snapshot_different_issuer_does_not_apply` builds a wrapper carrying
`fail_mode: "fail_closed"` (from `_tct_revocation_input`) with a snapshot issued by a
different peer, and asserts success. It supplies no top-level `policy`, so resolution rule 2
governs and the wrapper's `fail_closed` is honored: that same input is absent-for-this-issuer
under an explicit `fail_closed`, so it must become `TCT_REVOKED`. Rewrite it into two
tests — one pinning the fail-closed rejection, one pinning that the same wrapper with
`fail_mode: "soft_fail"` still verifies — rather than deleting the case. Log the flip in
`ASSUMPTIONS.md` as `UNCONFIRMED`, alongside the default-mode entry below.

**Acceptance criteria:**
- `verify_tct({"tct_token": <valid>})` with no `policy` and no `issuer_revocation_list`
  returns its verdict, exactly as today — pinned by the existing assertions at
  `test_unknown_fields.py:151` passing unmodified.
- `verify_tct({"tct_token": <valid>, "policy": {"fail_mode": "fail_closed"}})` with no
  `issuer_revocation_list` raises `AitpError(code="TCT_REVOKED")`.
- The same with `"policy": {}` (no `fail_mode`) also raises `TCT_REVOKED` — an explicitly
  supplied policy defaults to fail-closed, matching `revocation.py:173`.
- The same with `"policy": {"fail_mode": "soft_fail"}` and with `"fail_mode": "fail_open"`
  each return the normal verdict.
- `"policy": {"fail_mode": "typo_mode"}` and `"policy": "not-an-object"` each raise
  `TCT_REVOKED`, not a raw `TypeError`/`AttributeError` — unrecognized configuration is never
  silently permissive.
- **Precedence, both directions, one test each.** (a) A wrapper-level
  `issuer_revocation_list["fail_mode"] = "soft_fail"` **does NOT** override a top-level
  `policy: {"fail_mode": "fail_closed"}` — the input still raises `TCT_REVOKED`. This is the
  security-relevant direction and the test that pins the review correction; it must be
  hand-verified to fail under the inverted (draft) ordering, so it is provably not vacuous.
  (b) With **no** top-level `policy`, a wrapper-level `fail_mode: "fail_closed"` is honored
  (the `different_issuer` flip below is exactly this case), and a wrapper-level
  `fail_mode: "soft_fail"` verifies.
- A present-but-non-`str` `fail_mode` (`5`) in either the wrapper or the `policy` resolves to
  `fail_closed`, not to the permissive default.
- With a top-level `policy` supplied, a trusted snapshot from the right issuer whose
  `published_at` is older than `max_staleness_secs`, and one whose `expires_at` is in the
  past, each raise `TCT_REVOKED` under `fail_closed` and verify under `soft_fail`. Without a
  `policy`, neither is evaluated at all (today's behavior) — one test pinning that
  non-evaluation explicitly.
- An untrustworthy snapshot (forged signature, unknown member, malformed shape) still reports
  its own code under **every** `fail_mode`, including `soft_fail`/`fail_open` — the
  obtained-but-untrustworthy split is preserved, not collapsed. The existing tests at
  `test_unknown_fields.py:671-731` pass unmodified, plus one new `soft_fail` variant proving
  the mode does not downgrade them.
- `revocation.py`: `fail_mode: "fail_open"` with a stale/wrong-issuer snapshot returns
  `{"revoked": False, "stale": True}` instead of raising `TCT_REVOKED`; `fail_closed` and
  `soft_fail` behave exactly as today; an unrecognized mode raises `TCT_REVOKED`.
- All 10 `verify_tct` fixtures (which already include `rev-004` — it is a `verify_tct`
  fixture, not a snapshot one) and all 7 `verify_revocation_snapshot` fixtures
  (`rev-001`/`002`/`003`/`005`/`006`/`007`/`008`) pass unchanged;
  `run_conformance.py` reports the same counts; `tests/test_conformance.py:33` still holds.
- `ASSUMPTIONS.md` carries an `UNCONFIRMED` entry for the no-policy default and the
  `different_issuer` test flip, in this repo's established What changed / Why / How to apply
  / Status format.

**Tests:** a new `_tct_policy_input(**policy)` helper in `tests/test_unknown_fields.py`,
modeled on the `fail_mode`-toggling pattern `_revocation_input` + `inp["policy"]["fail_mode"]`
already establishes at `:545-625`, placed in the same TCT-revocation block as
`_tct_revocation_input` (`:636`). One test per acceptance bullet above; the `fail_open`
revocation fix gets its own test beside the existing `soft_fail` one.

**Docs:** `tct.py`'s module docstring (`:1-25`) and `_check_revocation`'s docstring
(`:135-145`) both currently describe the absence gap as deliberately open and point at the
previous plan's Phase 8 — rewrite both to describe the policy semantics this phase lands.
`revocation.py`'s module docstring (`:16-20`) lists only `fail_closed` and `soft_fail` in its
absence paragraph — add `fail_open`, and in the same sentence state what `stale: True` means
there ("this verifier has no fresh, applicable revocation data for the queried subject" — it
fires on the wrong-issuer case too, not only on an old snapshot), so the shared
`soft_fail`/`fail_open` verdict is documented rather than inferred. `CHANGELOG.md` in
Phase 5.

---

### Phase 4 — `verify_delegation_token`: the same absence policy, applied symmetrically

**Status:** NOT STARTED.

**Delivers:** `verify_delegation_token` honors the identical optional `inp["policy"]`
contract Phase 3 introduces, for the same absence case: when no trusted, applicable snapshot
for `self_aid` was supplied, an effective `fail_closed` rejects with
`DELEGATION_SOURCE_TCT_REVOKED` rather than proceeding. Applies to both the single-hop path
(Phase 2's new check) and the multi-hop path's source-TCT check at `:268`.

**Depends on:** **Phase 3** (same design, same default — reuse its exact shape; do not
redesign) and **Phase 2** (the single-hop call site this policy applies at must exist first).

**Files:**
- `aitp_verifier/delegation.py` — `_revocation_index` (`:141-177`), specifically the absent
  branch at `:165-167`; the single-hop call site added in Phase 2; the multi-hop call site at
  `:267-269`.
- `tests/test_unknown_fields.py`, `ASSUMPTIONS.md`.

**Approach:** Resolve the effective mode with Phase 3's rules, minus its **rule 2** (the
per-wrapper one; note the rule numbering was inverted during plan review, so this is the
`issuer_revocation_list["fail_mode"]` rule, not the top-level `policy` rule) — there is no
per-wrapper `fail_mode` spelling on this path (`revocation_snapshots` records are
`{issuer_aid, snapshot}` per `schemas/conformance/PLACEHOLDERS.md:92`, with no policy member,
and inventing one would be widening the wire shape rather than reading it). So: top-level
`policy["fail_mode"]` when `policy` is a dict, defaulting to `fail_closed` within a supplied
policy; **`fail_open` when no `policy` key is supplied at all** (preserving today's behavior,
and required by `del-001` and `del-mh-001`, both success fixtures with no revocation data);
`fail_closed` for a non-dict `policy` or an unrecognized mode string.

Absent, for this entry point, means: no trusted snapshot whose **verified** `body["issuer"]`
equals `self_aid` is present in the index — i.e. `self_aid not in _revocation_index(inp)` —
or, when a top-level `policy` is supplied, that snapshot exists but is stale/expired under
the same §3.2 formula Phase 3 uses. Thread `now` into `_revocation_index` (or compute
freshness at the call sites, whichever keeps `_revocation_index` a pure index — decide at
implementation, both are correct; the pure-index split is marginally cleaner because the
index is also consumed by the per-hop loop). Note the shape difference from `tct.py`:
absence here is "the index has no entry for `self_aid`", not "the input field is missing",
because a supplied-but-irrelevant snapshot list leaves A's own status just as unknown as an
empty one.

**Explicit non-goal, stated rather than silently skipped:** `fail_closed` is applied **only
to A's own deny list** — the §4-step-7 / RFC-AITP-0011 §6 *source-TCT* check — and NOT
extended to require a trusted snapshot for every intermediate hop issuer in the multi-hop
loop at `:270-273`. Requiring N snapshots under fail-closed is a materially wider policy with
no RFC-stated default and no fixture: RFC-AITP-0011 is Draft, its §6 per-hop lookup says
nothing about absence, and `del-mh-001` (a draft-opt-in success fixture) supplies none. Log
this boundary in `ASSUMPTIONS.md` alongside the default so `/reconcile` sees it as a decision
rather than an omission.

**Edge cases & failure modes:** `_revocation_index` has two callers after Phase 2 (single-hop
and multi-hop); the absence policy must fire identically from both, or this plan reintroduces
exactly the single-hop/multi-hop asymmetry it exists to close — one test per path is a hard
requirement, not a nicety. A `revocation_snapshots` list that is present but contains only
snapshots from other issuers must be treated as absent-for-`self_aid`, not as "data was
supplied, so we're fine" — that is the delegation-side analogue of `tct.py`'s (b) case, and
it is the subtle one. `_revocation_index`'s existing `None`-vs-falsy discipline at `:165-172`
(the `/reconcile`-era fix recorded in `ASSUMPTIONS.md`) must be preserved exactly: a malformed
non-list still raises `REVOCATION_SNAPSHOT_INVALID` and never routes through `fail_mode`.

**Acceptance criteria:**
- `verify_delegation_token` on a `del-001`-shaped input with no `revocation_snapshots` and no
  `policy` still returns `{"grants": ["read_data"]}` — today's behavior, pinned.
- The same input with `"policy": {"fail_mode": "fail_closed"}` raises
  `AitpError(code="DELEGATION_SOURCE_TCT_REVOKED")`.
- The same with `"policy": {}` also raises it; with `"soft_fail"` and with `"fail_open"` it
  verifies; with `"typo_mode"` and with a non-dict `policy` it raises — the identical matrix
  Phase 3 pins for `verify_tct`, asserted here so the symmetry is testable, not assumed.
- The same matrix asserted on the **multi-hop** path via `del-mh-001` (with its
  `experimental-multihop-delegation` feature marker set, as
  `_load_conformance_input` already handles), proving both paths honor one policy.
- A `revocation_snapshots` list carrying only a trusted snapshot from a peer **other than**
  `self_aid` behaves as absent under `fail_closed` (raises) — not as "data supplied".
- A trusted snapshot from `self_aid` that is stale beyond `policy["max_staleness_secs"]`
  raises under `fail_closed` and verifies under `soft_fail`; with no `policy` supplied,
  staleness is not evaluated at all.
- A malformed (non-list, including falsy) `revocation_snapshots` still raises
  `REVOCATION_SNAPSHOT_INVALID` under every mode — untrustworthy never becomes absent.
- Per-hop issuer deny lists are NOT subject to fail-closed absence handling (the explicit
  non-goal): `del-mh-001` with `"policy": {"fail_mode": "fail_closed"}` and a trusted
  `self_aid` snapshot that lists nothing still verifies, even though no snapshot is supplied
  for the intermediate hop issuers.
- All 10 `verify_delegation_token` fixtures pass unchanged; `run_conformance.py` counts
  unchanged; `mypy --strict` clean.
- `ASSUMPTIONS.md` entry covers the default and the per-hop non-goal, marked `UNCONFIRMED`
  and cross-referencing Phase 3's entry as the same decision.

**Tests:** `tests/test_unknown_fields.py`, delegation block —
`test_delegation_absent_snapshot_fail_closed_rejects`,
`..._fail_closed_by_default_within_a_supplied_policy`,
`..._soft_fail_verifies`, `..._fail_open_verifies`, `..._unknown_mode_rejects`,
`..._non_dict_policy_rejects`, `..._other_issuer_snapshot_is_absent_for_self`,
`..._stale_snapshot_rejects_under_fail_closed`,
`test_delegation_multihop_absent_snapshot_fail_closed_rejects`,
`test_delegation_multihop_per_hop_absence_is_not_fail_closed`.

**Docs:** `delegation.py`'s `_revocation_index` docstring (`:142-164`) documents the current
`None ⇒ []` absence rule in detail — rewrite that paragraph for the policy semantics. Module
docstring updated if Phase 2's edit left it describing absence. `CHANGELOG.md` in Phase 5.

---

### Phase 5 — Docs, `CHANGELOG.md`, and the spec-repo fixture follow-ups

**Status:** NOT STARTED.

**Delivers:** `CHANGELOG.md` records every behavior change in this plan under its existing
`## Unreleased` → `### Security-relevant` structure; the README is checked and updated only
where it is actually made stale; and the conformance-coverage gaps this plan exposes are
filed as read-only issues against the spec repo so the pack pins them going forward.

**Depends on:** Phases 1–4 (it documents them). Lands as its own commit inside PR 3.

**Files:**
- `CHANGELOG.md`
- `README.md` (only if stale — see Approach)
- spec-repo issues (filed via `gh`, no writes to the spec checkout)

**Approach — `CHANGELOG.md`.** The file already establishes the exact pattern to follow: a
`## Unreleased` section with a `### Security-relevant` subsection whose entries are bolded
one-line behavior statements followed by the what/why/who-is-affected prose and a trailing
issue reference. Add four entries there, in severity order:

1. **`verify_delegation_token` now performs the RFC-AITP-0006 §4 step-7 source-TCT revocation
   check on the single-hop path** — previously it was performed only on the multi-hop path, so
   a delegation token whose source TCT was listed in a present, correctly-signed deny list
   issued by the verifier itself verified successfully. Note the two secondary rejection
   paths this opens for single-hop callers who supply malformed or untrustworthy
   `revocation_snapshots` (Phase 2's Edge cases).
2. **`verify_tct` and `verify_delegation_token` accept an optional `policy` object** — with
   the resolution rules and, stated plainly, the default: **absent `policy` preserves today's
   permissive behavior**; fail-closed is an explicit opt-in, and supplying `policy: {}` is
   enough to get it. Also note `verify_tct` now honors `issuer_revocation_list.fail_mode`,
   which it previously ignored, and that a snapshot from another issuer is now treated as
   absent (policy-governed) rather than silently skipped.
3. **`verify_revocation_snapshot` now honors `fail_mode: "fail_open"`**, which previously
   behaved identically to `fail_closed`.
4. **`canonicalize`/`canonical_bytes` reject excessively nested values** with the artifact's
   own structural code instead of letting a raw `RecursionError` escape; note the 256-level
   cap and that no legitimate AITP artifact approaches it (issue #31).

Entries 1–3 reference issue #30 / this plan; entry 4 references #31.

**Approach — README.** Checked while writing this plan: `README.md` documents a per-module
coverage table, the independence claim, conformance counts, and the dev workflow — it does
**not** document any entry point's input-contract keys, so the new optional `policy` key
needs no README change. (`README.md:39`'s per-module table already says the `revocation`
module covers "fail-mode"; that stays true and needs no edit.)

**Corrected during plan review — the "Current status" line is *already* stale, independent of
this plan.** `README.md:53` reads "Current status: **53 fixtures pass, 0 fail**", while
`run_conformance.py` on current `main` reports **68 passed / 0 failed / 1 skipped** (measured
during review; the previous plan's `PROGRESS.md` notes the same discrepancy and explicitly
scoped it out). So the rule "if the counts did not move, leave it untouched" would, on a false
baseline, leave a line that is already wrong. The phase's actual instruction: confirm the
runner still reports 68/0/1 (no phase here changes a fixture verdict); then **either** update
`README.md:53` to 68/0/1 as a one-line, clearly-labelled drive-by correction, **or** leave it
and record in `PROGRESS.md` that the staleness is known, pre-existing and deliberately not
touched. Decide once, do not leave it ambiguous — what is not acceptable is silently
concluding "counts didn't move" and therefore believing the README is accurate.

**Approach — spec-repo follow-ups** (read-only cross-repo issues, the same pattern already
used once this session for spec issue #59; no commits or edits to the spec checkout):

1. **A `del-002`-style source-TCT-revocation fixture for the single-hop path.** The
   `del-*` numbering has a hole at `del-002` (confirmed: the pack ships `del-001`, `del-003`
   … `del-007`, and the spec's fixture table — `schemas/conformance/README.md:357-362`, not
   the spec root `README.md` — lists no `del-002`), and **no**
   fixture anywhere exercises RFC-AITP-0006 §4 step 7 on the core single-hop path — which is
   precisely why this plan's most severe finding went unnoticed by a pack-passing
   implementation. Ask for `del-002-source-tct-revoked`: a `del-001`-shaped input plus a
   `revocation_snapshots` record signed by A listing the voucher's `src_jti`, expecting
   `failure: DELEGATION_SOURCE_TCT_REVOKED`. Note in the issue that
   `schemas/conformance/PLACEHOLDERS.md:92` currently documents `revocation_snapshots` only
   on the `del-mh-*` row, not the `del-*` row (`:86`) — so the fixture request carries a
   small doc request with it.
2. **A `fail_open` revocation fixture.** No fixture in the pack exercises
   `revocation_policy.mode: fail_open` (verified across all seven `verify_revocation_snapshot`
   fixtures — the eight `rev-*` files minus `rev-004`, which is a `verify_tct` fixture:
   `rev-002` is the only non-`fail_closed` one, and it is `soft_fail`), which is why
   `revocation.py` could treat `fail_open` as `fail_closed` indefinitely without a red test.
   Ask for a `rev-0NN-fail-open` sibling of `rev-001`/`rev-002` — identical stale snapshot,
   `mode: fail_open`, expecting success.

**Judgment call on the third candidate fixture, stated rather than silently dropped:** the
#30 grounding suggested also asking for a `tct-0NN-no-snapshot-fail-closed` fixture. Given
the default Phase 3 actually lands on — absent `policy` preserves fail-open, fail-closed is
an explicit opt-in — such a fixture would need to carry an explicit `policy` in its input to
be meaningful, and `verify_tct`'s fixture inputs have never carried a `policy` object (only
`verify_revocation_snapshot`'s do). That makes it a request to extend the `verify_tct`
*input shape*, not just to add a vector, which is a bigger ask than a missing fixture and one
this repo should not make before its own `policy` design has been through `/reconcile`.
**Defer it**; revisit after the Open-questions decision below is confirmed. Both issues above
stand on their own regardless of how that decision lands.

**Edge cases & failure modes:** the `CHANGELOG.md` entries must state the *permissive*
default plainly rather than burying it — a reader upgrading this library needs to know that
`policy` is opt-in, or they will assume the secure default applies and get the old behavior.
Do not add a `## 0.1.x` release heading; the file's own preamble states there has been no
tagged release, and the `## Unreleased` section is where everything belongs.

**Acceptance criteria:**
- `CHANGELOG.md` carries all four entries under the existing `## Unreleased` →
  `### Security-relevant` heading, matching the established entry format, each naming the
  affected entry points and the observable before/after.
- The `policy` default (permissive when absent) is stated explicitly in the changelog text,
  not implied.
- `README.md` is either updated (if a conformance count or skip-list line actually moved) or
  verifiably untouched, with the check recorded in `PROGRESS.md`.
- Two spec-repo issues filed, each linking the RFC text and fixture ids above; their numbers
  recorded in `PROGRESS.md`. Neither issue is a blocker for merging PR 3.
- No spec-repo file is modified (`git -C ../agentidentitytrustprotocol status` clean).

**Tests:** none (documentation-only phase). The full suite and `run_conformance.py` are
re-run once more at the end of the PR as the finalization check, per the previous plan's
convention.

**Docs:** this phase *is* the docs phase; the per-module docstring updates belong to Phases
1–4 and land with the code they describe.

---

## Long-term posture

- **The `policy` concept is the only new public-contract surface in this plan, and it is
  deliberately one shape reused three times** (`verify_revocation_snapshot`'s existing
  `inp["policy"]`, `verify_tct`'s new one, `verify_delegation_token`'s new one) rather than
  three spellings. A future fourth consumer should reuse the same resolution rules and the
  same defaults; if the `/reconcile` decision flips the default to fail-closed, it must flip
  in all three places at once, which is why Phases 3 and 4 share a PR.
- **Phase 2's fix is deliberately scoped to "consult the list that is already computed", not
  to "redesign revocation for single-hop".** The absence half of the same question is Phase
  4, gated behind Phase 3's design decision. Splitting them this way means the severe, live,
  no-design-needed bypass ships on its own timeline and is reviewable in isolation — the
  alternative (one big "fix delegation revocation" change) would have held a MUST-level core-
  path fix behind a contract discussion.
- **Where a fast approach would create debt, named explicitly:** the obvious quick fix for
  #31 is to widen `canonical_bytes`'s `except` to include `RecursionError` and stop there.
  This plan does that *as well*, but not *instead* — recovering after the interpreter has
  already unwound most of its stack is a fragile place to be, and it would only cover the
  four call sites that go through `canonical_bytes`, leaving `canonicalize`'s other callers
  (and any future one) uncovered. The depth cap in `jcs.py` is the fix; the widened `except`
  is the backstop.
- **No public API signature changes.** `verify.py`'s `OPERATIONS` table and every function's
  Python signature stay exactly as today; `policy` is a new optional *member* of an existing
  input dict, and `_check_revocation`/`_revocation_index` are private. The only one-way door
  is the semantic one (what an absent policy means), which is why it is logged for
  `/reconcile` rather than decided silently.
- **Two spec-coverage gaps are being fixed in this repo and reported, not just fixed.**
  Neither the single-hop step-7 check nor `fail_open` is pinned by any fixture today; both
  are now covered by this repo's own tests, and Phase 5 asks the spec to pin them for every
  implementation. Fixing without reporting would leave the second implementation
  (`aitp-rs`) exposed to the same gap.

## Enterprise concerns

- **Observability**: no new error code is minted anywhere in this plan. `TCT_REVOKED`
  (`registries/error-codes.md:98`), `DELEGATION_SOURCE_TCT_REVOKED` (`:188`), and the four
  per-artifact structural codes Phase 1 reuses are all already registered with exactly these
  semantics — so any existing caller-side code-to-metric mapping already covers the new
  rejection paths. What *is* new is which codes each operation can emit: after Phase 2,
  single-hop `verify_delegation_token` can additionally surface
  `REVOCATION_SNAPSHOT_INVALID`, `REVOCATION_SNAPSHOT_SIGNATURE_INVALID` and `UNKNOWN_FIELD`
  (all already emitted by the multi-hop path today, so this is an operation reaching parity,
  not a registry change) — a caller alerting per (operation, code) pair will see new pairs.
- **Failure domains**: still a pure-computation, network-free library — no retry,
  concurrency, or partial-failure story exists. The nearest analogue is the
  obtained-but-untrustworthy vs. absent distinction, which Phases 3 and 4 explicitly preserve
  rather than collapse, for the reason `revocation.py`'s own docstring records: collapsing
  them once already produced a `soft_fail` pass for artifacts the spec says MUST be rejected.
- **Availability vs. security posture is now the deployer's explicit choice**, which is the
  substantive enterprise change here: before this plan, `verify_tct`/`verify_delegation_token`
  were unconditionally availability-first on absence with no way to say otherwise; after it,
  a deployment handling high-value capabilities can pass `policy: {}` and get RFC-AITP-0008
  §3.1's `fail_closed` posture. The default stays permissive for conformance reasons (see
  Open questions) — which makes the `CHANGELOG.md` wording in Phase 5 load-bearing, not
  cosmetic.
- **Rollback**: the tests are the rollback signal, as before — no persisted state, no
  published package, no schema migration. Each phase is independently revertible; Phase 4 is
  the only one that must be reverted together with another (Phase 3), since they are one
  decision.
- **CI cost**: Phase 1's boundary-contract mutation entry multiplies the existing sweep by
  one more mutation across all 8 operations. The deep-nesting value is cheap to build and
  most of its instances are skipped at mint time (see that phase's Edge cases); measure the
  wall-clock delta during implementation and call it out at `/ship` if the suite noticeably
  slows.

## Open questions

- **The one substantive open question: what an absent `policy` means for `verify_tct` and
  `verify_delegation_token` (Phases 3–4).** Decided in this plan as **absent `policy` ⇒
  today's permissive behavior preserved; `fail_closed` is an explicit opt-in, and supplying
  `policy: {}` is enough to get it**. The reasoning, in order of weight: (1) an unconditional
  fail-closed-on-absent default fails the spec's own conformance pack — `tct-012`
  (`required_for_v0_2`), `del-001` (`required_for_v0_2`, core) and `del-mh-001` all expect
  success with no revocation data supplied at all, re-derived live for this plan rather than
  taken on trust; (2) RFC-AITP-0008 §3.1's `fail_closed` default is a *deployment policy*
  default, stated for `revocation_policy.mode` in a configured trust-anchor document, and it
  does not speak to a verifier function invoked with no policy object in the first place;
  (3) `verify_tct`/`verify_delegation_token` have no precedent — unlike
  `verify_revocation_snapshot`, whose `inp["policy"]` is required and always present — of
  `policy` being a mandatory input, so there is no existing caller expectation to honor;
  (4) secure-by-default is still honored *within* an explicitly supplied policy, matching
  `revocation.py:173`'s own `policy.get("fail_mode", "fail_closed")`. **This is a genuine
  one-way door** (it sets what every future caller's silence means) and it is the plan's one
  item to confirm with the user at `/reconcile`: log it to `ASSUMPTIONS.md` as `UNCONFIRMED`
  at implementation time, exactly as the previous plan handled its Phase 3/Phase 8 entries.
  **The `ASSUMPTIONS.md` entry MUST say, in one sentence, that this does not reverse the
  prior `/reconcile` decision** (`DECISIONS.md:58-93`, Phase 8): the user confirmed
  fail-closed there for the **obtained-but-untrustworthy** branch (a malformed/forged
  snapshot), which this plan preserves untouched and even extends to the single-hop path in
  Phase 2. This default governs the **absent** branch, which RFC-AITP-0008 §3.1's own
  blockquote defines as a *different* case, and which `ASSUMPTIONS.md:122` records as having
  been explicitly and deliberately left open by that same pass. Without that sentence a
  `/reconcile` reviewer reasonably reads the new entry as relitigating a settled decision.
  The alternative worth weighing there is "fail-closed default, and patch the three affected
  fixtures' inputs to carry an explicit permissive policy" — rejected here because it means
  this implementation would no longer run the pack as shipped, which is the whole point of
  an independent second implementation.
- **Phase 4's per-hop non-goal** (fail-closed absence handling applies to A's own deny list
  only, not to each intermediate hop issuer's) is a "consequential but decidable" call, not a
  fork requiring escalation: RFC-AITP-0011 is Draft, its §6 says nothing about absence, and
  `del-mh-001` ships with no snapshots. Recorded in `ASSUMPTIONS.md` at implementation time
  and surfaced at `/reconcile` alongside the entry above, since it is the same decision's
  blast radius.
- **Phase 1's `_MAX_DEPTH = 256`** is a decidable constant, not an open question — it is
  bounded above by the measured interpreter ceiling (~993) and below by the measured real
  artifact depth (≤ 8, to be re-confirmed as an acceptance criterion), and changing it later
  is a one-line, fully reversible edit with no contract implications.
- **Phase 5's deferred third fixture request** (a `tct-0NN-no-snapshot-fail-closed` vector)
  is deliberately not filed until the default above is confirmed — reasoning recorded in that
  phase. Not an open question about this plan; a sequencing note about the spec repo.
- **No other phase is a one-way door**, and nothing here crosses a trust boundary in a way
  that needs a critical-tier agent beyond the one already run (the single-hop bypass finding
  in Context, which was independently reproduced live before this plan was written).

## Repo map

(Written to `PROGRESS.md`, appended as a new top-level section — see that file for the full
map, covering all five phases' files. The existing
`# PROGRESS (plans/hardening-issues-23-27.md)` section above it is complete and untouched.)

## Plan review

### Round 1 (2026-09-23) — verdict: **REVISE**, fixes applied above, now **SOUND**

Run by a fresh Opus agent that did not draft this plan, adversarially against the code rather
than against the plan's own prose. One substantive design correction and thirteen
accuracy/falsifiability fixes were applied directly to the sections above. The plan's phase
structure, PR grouping and Phase 2 fix all survived review unchanged.

**What was independently re-verified (not taken from the draft):**

- **Every file:line citation in every phase was opened.** `tct.py` (`verify_tct` `:88-131`,
  call at `:130`, `_check_revocation` `:134-157`, the `:146` read, `:147-148` fail-open
  return, `:149` trust call, `:154-155` wrong-issuer skip, `:156-157` scan) — all exact.
  `delegation.py` (single-hop `:97-138`, `check_voucher_claims_shape` `:129`, scope check
  `:135-136`, return `:138`, `_revocation_index` `:141-177` with the `is None` discipline at
  `:165-172` and the verified-issuer keying at `:176`, sole caller `:267`, multi-hop
  source-TCT check `:268-269`, per-hop loop `:270-273`, `compute_chain_hash` `:82`) — all
  exact. `revocation.py` (`verify_snapshot_trust` `:111-167`, `verify_revocation_snapshot`
  `:170-192`, `policy` `:171`, the `fail_closed` default `:173`, stage 4 `:178-187`, the
  `fail_open` fall-through to the raise at `:187`, freshness `:183`, `canonical_bytes` `:164`)
  — all exact. `jcs.py` (`_serialize` `:144-177`, recursion at `:160`/`:174`, UTF-16 sort key
  `:166`, `dumps` `:180-184`, `canonicalize` `:187-189`) and `fields.py`
  (`canonical_bytes` `:146-159`, `from .jcs import … canonicalize` at `:75`) — all exact.
  The four `canonical_bytes` call sites (`envelope.py:51`, `manifest.py:204`,
  `revocation.py:164`, `sessionbundle.py:207`) — all exact, each with the claimed
  `shape_code`. `minter.py:379-384` and `:389-391` — exact. `jws.py:60-63` — exact.
  `voucher.py`: `_VOUCHER_REQUIRED_CLAIMS` includes `src_jti` and `_VOUCHER_CLAIM_TYPES`
  declares it `str`, so Phase 2's bracket access is provably safe. Test-file citations
  (`test_fields.py:96-115`, `test_envelope.py:148-199`, `test_unknown_fields.py:545`/`:636`/
  `:658-744`/`:747`, `test_boundary_contract.py:68`/`:92-105`/`:107`/`:160-214`) — exact.
  **Two drifted** and were corrected (see fix 5).
- **The conformance pack was re-walked from scratch**, by enumerating every
  `schemas/conformance/*.json`, grouping on `input.operation` and reading each `expected`.
  The plan's corrected counts hold exactly: `verify_tct` has 10 fixtures and exactly one
  (`tct-012`, `required_for_v0_2`) succeeds with no `issuer_revocation_list`; `tct-004`
  supplies the wrapper; the remaining eight (`rev-004`, `tct-002`/`003`/`005`/`008`/`009`/
  `010`/`011`) each reject at a check that precedes `tct.py:130`, individually confirmed
  against the code path. `verify_delegation_token` has 10 fixtures and exactly two
  (`del-001` core/`required_for_v0_2`, `del-mh-001` draft) succeed with no
  `revocation_snapshots`; only `del-mh-004` supplies any. **The grounding-note correction the
  plan flagged as its highest-stakes fact is confirmed correct.** One residual miscount was
  found in the `rev-*` family (fix 12).
- **The single-hop bypass was reproduced live**, not accepted on the draft's word: minting
  `del-001` plus a `revocation_snapshots` record genuinely signed by `self_aid` and listing
  `voucher_claims.src_jti` (`550e8400-e29b-41d4-a716-446655440101`),
  `verify_delegation_token` returns `{'grants': ['read_data']}` on current `main`, while
  `_revocation_index` on that same input returns that jti under that exact `self_aid` key.
  The three negative controls behave as Phase 2's acceptance criteria require: the same
  snapshot signed by a different peer indexes under that peer (fix does not fire), a
  one-character signature edit raises `REVOCATION_SNAPSHOT_SIGNATURE_INVALID`, and the
  unmodified `del-001` yields an empty index. **All four of Phase 2's load-bearing acceptance
  criteria are therefore proven non-vacuous before implementation starts.**
- **Counter-example hunt on Phase 2's fix** (asked for explicitly): no spec-legal input shape
  was found where the described fix lets a revoked delegation through or wrongly rejects a
  legitimate one. Checked and cleared: expired-but-signed snapshots (rejecting is fail-safe;
  deny-list entries are monotonic in this model, so there is no un-revocation to be wrong
  about); snapshots whose verified issuer is a third party (correctly non-applicable by the
  `revoked.get(self_aid, …)` keying, since `voucher.iss == self_aid` is already enforced at
  `:119-120`); non-`str` or missing `jti` inside `entries` (impossible past
  `_validate_shape`); a missing `src_jti` (impossible past `check_voucher_claims_shape`).
  Two genuine scope boundaries surfaced and are now stated in the plan rather than left
  implicit: the deny list can only be supplied via `revocation_snapshots` (already an
  explicit non-goal, and the subject of Phase 5's first spec issue), and the delegation
  token's own `jti` is deliberately not checked (fix 7b).
- **Both recursion measurements were re-taken** on `/tmp/aitpvenv313` (CPython 3.13.7, stock
  limit 1000): `canonical_bytes({"extensions": <n-deep>})` → 993 OK, 995 raw
  `RecursionError`, matching the draft. `json.loads` → 5,000 OK, **10,000 raises**, which
  corrected the draft's stated upper bound (fix 4). The Phase 1 headroom claim in the other
  direction was measured rather than assumed: instrumenting `fields.canonical_bytes` and
  `jcs.canonicalize` across a full `run_conformance.py` run gives a **max container depth of
  3** — ~85× below the cap, comfortably inside the ≤ 8 acceptance bound.
- **The "signed value wins" citation was chased to its source and holds.**
  `plans/hardening-issues-23-27.md:1426-1432` is finding B5 and says what the plan says it
  says; the shipped consequence is visible at `delegation.py:149-152` (docstring) and `:176`
  (the keying itself). It does apply here — and applying it *consistently* is what produced
  this round's one substantive correction.
- **`DECISIONS.md` and `ASSUMPTIONS.md` were cross-checked.** The Phase 3/4 default is a
  genuinely new design surface: `DECISIONS.md:58-93`'s confirmed fail-closed ruling is about
  the *obtained-but-untrustworthy* branch, and `ASSUMPTIONS.md:122` records the
  `issuer_revocation_list`-absent-entirely case as explicitly, deliberately left open by that
  same pass. **No contradiction and no duplication — fresh `/reconcile` treatment is
  warranted.** One framing risk was added to the plan so the next reviewer is not misled
  (fix 10).
- **Baseline re-run green** on current `main` (`adcd06f`): `pytest tests/ -q` → 300 passed;
  `run_conformance.py` → 68 passed / 0 failed / 1 skipped; `mypy` → clean, 36 source files.
  Recorded in `PROGRESS.md`.

**Verdict rationale.** REVISE rather than SOUND on exactly one item: fix 1 below is a genuine
security defect in the *plan* (not yet in the code), and it contradicts a principle the same
phase states two paragraphs later. Everything else is accuracy and falsifiability work that
would have cost `/implement` time but not correctness. With all fourteen applied, the plan is
**SOUND**.

**What changed:**

1. **[substantive — security]** Phase 3's mode-resolution precedence was **inverted**. The
   draft let `issuer_revocation_list["fail_mode"]` — an *unsigned* member of the
   caller-supplied wrapper, sibling to the `issuer` label the same phase refuses to trust —
   outrank a supplied top-level `policy`, including downward (`fail_closed` → `soft_fail`).
   For an integrator whose wrapper is assembled around a remote `ListRevoked` response, that
   is a remotely-triggerable downgrade of an explicitly configured security posture. Now: a
   supplied top-level `policy` is authoritative; the wrapper's `fail_mode` is consulted only
   when no `policy` was supplied, where it is monotone-safe (today's no-policy default is
   `fail_open`, the most permissive mode, so the wrapper can only tighten). #30's "the
   wrapper's members are never read at all" is still closed. No fixture or existing test
   depends on the order — `tct-004` and every `_tct_revocation_input` test supplies a wrapper
   and no `policy` — so the single documented test flip is unchanged. The reasoning is written
   into the phase, and the precedence acceptance criterion was rewritten (fix 2).
2. **[acceptance criteria]** Phase 3's precedence criterion, which pinned the now-wrong
   direction, was replaced with a two-part criterion whose security-relevant half
   (wrapper `soft_fail` must NOT defeat `policy` `fail_closed`) must be hand-verified against
   the draft's ordering to prove it non-vacuous.
3. **[correctness of a rule]** Phase 3 rule 4 now also covers a present-but-non-`str`
   `fail_mode`. In the draft, `fail_mode: 5` fell through the `str` guard to the *permissive*
   default while `fail_mode: "typo"` resolved to `fail_closed` — malformed configuration
   treated more leniently than misspelled configuration.
4. **[measurement]** `json.loads` tolerance corrected to "5,000 accepted / 10,000 raises"
   (the draft said "~5,000–20,000" / "fails around 20,000"). Conclusion unchanged: the parser
   still never rejects a 300–2,000-deep document before the canonicalizer sees it.
5. **[line drift]** `tests/test_conformance.py`'s `assert passed >= 51` is at **`:33`**, not
   `:31` (two places in the plan, one in `PROGRESS.md`). `PROGRESS.md`'s repo map put
   `_mutate` at `:145`; it is at **`:135`**. Both corrected. Every other cited location was
   confirmed accurate.
6. **[falsifiability]** Phase 1's depth-boundary criterion ("a 256-deep dict succeeds, a
   257-deep dict raises") was not confirmable from a diff: it never pinned the counting
   convention, and the same bullet wrapped the value in `{"extensions": …}`, which shifts the
   boundary by one. It now states the guard (`depth > _MAX_DEPTH`, top-level call at
   `depth == 0`), defines `_deep_dict(n)`, gives the expected numbers for an unwrapped value,
   and makes the non-negotiable requirement "two adjacent depths, accepted exactly one below
   rejected" rather than two literal integers.
7. **[spec fidelity, two items]** (a) Phase 2 described `delegation.py:97-136` as
   "RFC-AITP-0006 §4's steps 1–6"; self-delegation (`:107-108`) is §4 **step 8**, which this
   module already runs early. Corrected, with a note that the pre-existing reordering is
   harmless and out of scope — the §3.3 requirement that matters (revocation last) is still
   satisfied. (b) Added the considered non-goal that single-hop does **not** also check the
   delegation token's own `jti`, unlike the multi-hop per-hop loop at `:270-273`: §4 step 7
   names one lookup, and RFC-AITP-0008 §1.1 says the voucher has "no independent revocation
   handle". An implementer would otherwise read the asymmetry as an oversight.
8. **[completeness]** Phase 1 said "the two raw `canonicalize` calls" outside
   `canonical_bytes`; there are **eight** (`delegation.py:82`, `jws.py:125`, and six in
   `minter.py`). All are listed now, with why none needs the fix. Also noted that
   `keys.py:25`'s `json.loads` reads local KAT files, closing the "only `json.loads` on
   remote input" claim properly.
9. **[citation precision]** The PR-grouping section attributed to the previous `/reconcile`
   pass a ruling on "fail-mode handling applied symmetrically". What `DECISIONS.md:64-66` and
   `ASSUMPTIONS.md:138` actually establish is symmetry for the *obtained-but-untrustworthy*
   branch. Reworded to a precedent-for-symmetry, which is what it is, and which still
   supports keeping Phases 3 and 4 in one PR.
10. **[`/reconcile` framing]** The Phase 3/4 `ASSUMPTIONS.md` entry must now state explicitly
    that this default does not reverse the prior pass's user-confirmed fail-closed decision —
    that one governs the untrustworthy branch, this one the absent branch, and
    `ASSUMPTIONS.md:122` records the latter as deliberately left open. Without the sentence a
    `/reconcile` reviewer reasonably reads it as relitigation.
11. **[sequencing hazard]** The PR-grouping section never stated that **PR 3 must be branched
    from or rebased onto PR 2's merge**: Phase 4 edits the very call site Phase 2 inserts, in
    the same file. Added, along with the confirmation that PR 1 shares no file with either and
    is order-free.
12. **[miscount]** "All 8 `rev-*` fixtures" appears in Phase 3's acceptance criteria and
    Phase 5's `fail_open` survey; there are only **7** `verify_revocation_snapshot` fixtures —
    `rev-004` is a `verify_tct` fixture (and was already being counted in the same bullet's
    "all 10 `verify_tct` fixtures"). Corrected in three places. The Context bullet's own
    enumeration was already right.
13. **[stale premise]** Phase 5's README instruction assumed `README.md:53`'s "53 fixtures
    pass" tracks `run_conformance.py`. It does not — the runner reports 68/0/1 today, so the
    line is already stale independent of this plan, and "the counts didn't move, leave it
    alone" would have preserved a wrong line on a false baseline. The phase now names the
    discrepancy and requires an explicit decision either way.
14. **[semantics, answered not changed]** The `fail_open` verdict shape
    (`{"revoked": False, "stale": True}`) was challenged as potentially misleading for a
    fresh-but-wrong-issuer snapshot. It is not: `revocation.py:184`'s branch is
    `not (issuer_ok and fresh)`, so `stale` has always meant "revocation *status* is
    stale/unknown" — the existing `soft_fail` path has returned it for wrong-issuer since the
    module was written. Decision kept; a clarifying sentence added to the phase and a
    docstring clause added to its Docs field so the meaning is written down rather than
    inferred. Also recorded, under Enterprise concerns, that single-hop
    `verify_delegation_token` gains three newly-observable (already-registered) codes —
    parity with multi-hop, but new (operation, code) pairs for anyone alerting on them.

**Not changed, and why** — flagged here so a later reader does not mistake silence for
oversight: `_MAX_DEPTH = 256` stands (measured headroom is ~85× above real artifacts and
~4× below the interpreter ceiling); the absent-`policy`-is-permissive default stands (the
re-walked pack confirms an unconditional fail-closed default turns three currently-green
fixtures red, two of them `required_for_v0_2`, so this remains a genuine `/reconcile`
question and not a drafting error); the 5-phase / 3-PR split stands (each phase is
independently shippable and independently verifiable, and the `Depends on` fields are
complete and honest once fix 11's branch-ordering constraint is stated); Phase 1's
"the boundary-contract mutation entry is probably vacuous" assessment stands unverified by
design — the phase already requires it to be *measured* rather than assumed, which is the
correct treatment.
