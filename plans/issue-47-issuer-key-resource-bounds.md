# Plan: bound `resolved_issuer_keys`'s candidate count and RSA modulus size (issue #47)

## Context

Issue #47 is a direct follow-up to issue #38 (closed, merged as PR #48, `13093ca`), filed by
that PR's own pre-merge verification pass. Issue #38 closed the **depth** dimension of
`jwk.py::issuer_keys_from`'s unbounded walk over the caller/resolver-supplied
`resolved_issuer_keys` argument (a raw `RecursionError` on a deeply nested value). Two adjacent
dimensions on the same parameter — never a bare-exception escape, so out of #38's own scope —
remain open:

1. **No bound on candidate count.** `aitp_verifier/jwk.py:225-229` (the JWKS `{"keys": [...]}`
   branch) and `:231-235` (the list-nesting branch) both accumulate `IssuerKey` candidates with
   no limit. Confirmed live this session: `issuer_keys_from({"keys": [<a 2048-bit Ed25519
   JWK>] * 500_000})` parses in **~1.7s** (measured: 1000 candidates → 6.5ms, 10,000 → 32.3ms,
   100,000 → 331.4ms, 500,000 → 1737.4ms — linear, ~3.5µs/candidate; independently reproduced
   during this plan's review pass at 5.5 / 28.6 / 297.7 / 1637.7ms, ~3.3µs/candidate, i.e.
   within ~15%). Not an instant crash the
   way #38's `RecursionError` was, but real, uncapped, linearly-compounding CPU cost driven
   entirely by resolver-supplied input, paid on *every* `verify_handshake_payload`/
   `verify_identity` call (nothing caches a resolved candidate list across calls).
2. **No upper bound on RSA modulus size.** `aitp_verifier/crypto.py:91-101`
   (`PublicKey.from_rsa_numbers`) enforces only `_MIN_RSA_MODULUS_BITS = 2048`
   (`crypto.py:45`) — no ceiling — and **checks it only after already constructing the full
   `cryptography` key object** (`key = public_numbers.public_key()` at `crypto.py:98`, *then*
   `if key.key_size < _MIN_RSA_MODULUS_BITS` at `:99`), so even the existing floor check pays
   full construction cost before rejecting. Measured (re-measured and corrected during this
   plan's own review pass — an earlier draft of this paragraph overstated all three figures by
   2-3x): `RSAPublicNumbers(65537, n).public_key()` costs ~3.1-3.6ms at an 8,388,608-bit (1 MB)
   modulus, ~6-8ms at 16,000,000 bits, ~23-28ms at 64,000,000 bits (warm/cold) — construction
   itself scales linearly and is **not** the dominant cost on this path (see Phase 2's own
   Approach step 2: the `b64url_decode` of `n` at `jwk.py:146`, which runs *before*
   `from_rsa_numbers` is ever entered, costs roughly 7x more than the key construction it
   feeds). It is nonetheless entirely unbounded, entirely resolver-driven, and (per the
   candidate-count finding above) repeated once per candidate in a large JWKS. The
   **security** defect here — an accepted modulus the companion implementation would refuse
   to verify against — is the load-bearing one; the construction cost is secondary.

**Both are the same resource-exhaustion class (CWE-770, allocation of resources without
limits) issue #38 already established the framing for** — "a compromised or misbehaving
OIDC-issuer-key resolver (or a resolver bug) can hand the verifier something costly to
process, and nothing currently stops it" — just the *count*/*size* dimensions rather than
*depth*. Neither fix needs a new call-site change in `identity.py`: `_verify_oidc`'s existing
`except ValueError` clause (`identity.py:219-220`, landed by #38 — guarding the
`issuer_keys_from` call at `identity.py:210`) already converts any
`ValueError` `issuer_keys_from` raises to `AitpError("KEY_RESOLUTION_FAILED", retryable=True)`
— the same "a resolver that hands back garbage has produced exactly as much usable key
material as one that hands back nothing" reasoning #38 already established covers a
too-large-modulus or too-many-candidates value exactly as it covers any other malformed JWK
shape. This is the one thing the issue's own suggested shape got slightly wrong ("converted to
`AitpError` at the same `identity.py` call site issue #38 already guards" reads as if
`identity.py` needs a new edit — it doesn't; #38's guard already generalizes).

**Cross-implementation grounding, found this session, not in the original issue:** the sibling
Rust implementation's `crypto.py`-equivalent (`aitp-handshake/src/jwk.rs`) does **no** RSA
size validation at parse time at all — by design, its own doc comment says so explicitly
("Does not apply any key-strength policy (e.g. an RSA modulus floor) — that is a
transport-specific hardening decision left to the caller"). Its actual enforcement comes from
`ring::signature::RSA_PKCS1_2048_8192_SHA256` (`aitp-handshake/src/jwk.rs:288`), the algorithm
identifier `ring` uses at *verify* time, which rejects any modulus outside **[2048, 8192]**
bits as part of its own internal, built-in bound. `aitp-transport-http`'s own
`rsa_modulus_bits_ok` helper (`aitp-transport-http/src/common.rs:65-79`) additionally checks
only the *floor* (`MIN_RSA_MODULUS_BITS = 2048`, `common.rs:54` — confirmed identical to this
repo's own `_MIN_RSA_MODULUS_BITS`; `bits >= MIN_RSA_MODULUS_BITS` at `common.rs:78` is its
only comparison, and no `MAX_RSA_MODULUS_BITS` exists anywhere in `aitp-rs`), and only for its
own transport-layer call sites (DPoP proof validation at `dpop.rs:411`, JWKS client fetch at
`client.rs:874`), not the core handshake-verification path at all. `ring`'s own
`[2048, 8192]` range is confirmed in `ring-0.17.14/src/rsa/verification.rs:88-91`
(`min_bits: 2048`, doc text "Verification of signatures using RSA keys of 2048-8192 bits"),
with the 8192 ceiling coming from `PUBLIC_KEY_PUBLIC_MODULUS_MAX_LEN`. **This
means today, this Python implementation silently accepts (and would successfully verify a JWT
against) an RSA JWK with a modulus over 8192 bits that the Rust implementation's own `ring`
call would refuse to verify** — a real cross-implementation behavioral divergence, not merely
a DoS-hardening gap. Choosing **8192 bits** as this repo's own ceiling isn't an arbitrary
DoS-mitigation number: it closes that divergence and achieves behavioral parity with the
companion implementation, the same kind of grounding issue #38's plan used for
`KEY_RESOLUTION_FAILED`'s own semantics (the `aitp-rs` test suite's independently-arrived-at
`resolver hard error → KeyResolutionFailed` line).

**A second, parallel parity gap on the same method, found by this plan's review pass and
folded into Phase 2 below** (decided directly — a "consequential but decidable" call per the
Autonomy ladder, recorded in Open questions rather than left open): `ring` also bounds the RSA
*public exponent* to 33 bits (`ring-0.17.14/src/rsa/public_exponent.rs:27`,
`PublicExponent::MAX = (1u64 << 33) - 1`, whose own comment names resource exhaustion as the
motive), while Python `cryptography` bounds `e` only by `3 <= e < n` and `e` odd. Verified
live: an `e` of the same bit-width as a valid 2048-bit `n` constructs a `PublicKey`
successfully here, and `ring` would refuse to verify against it. Left half-closed,
`_MAX_RSA_MODULUS_BITS = 8192` alone would close only the *modulus* half of ring parity while
leaving the *exponent* half open in the very method whose own stated goal is parity — the same
kind of half-true claim this plan's Approach step 1 already flags the *pre-existing* docstring
for making about the floor alone (see Phase 2 Approach step 1). Closing both bounds in the same
phase costs one extra constant, one extra clause (same citation), and one boundary test, and
avoids shipping a "parity" fix that is only half parity.

No fixture in `agentidentitytrustprotocol/schemas/conformance/` carries a
`resolved_issuer_keys` member **at all** (confirmed by grepping all 72 fixtures: zero hits) —
the field is synthesized by `minter.py:314` at mint time and consumed at
`handshake.py:111`, so there is no fixture-shaped JWKS to calibrate against. Real-world
grounding for the candidate-count cap comes instead from common
OIDC-provider practice (Google/Microsoft/Okta/Auth0 JWKS endpoints typically carry 2-10 keys,
rarely up to ~20-30 during rotation overlap; RFC 7517 gives no size guidance) rather than this
repo's own fixtures, unlike #38's `_MAX_DEPTH`, which had a fixture-grounded "legitimate
nesting is 0-1 levels" claim to lean on.

## Phases

### Phase 1 — bound `issuer_keys_from`'s total candidate count, checked before each parse

**Status:** DONE (2026-09-25). Implemented exactly as planned, no approach divergence. A fresh
Opus verification gate returned **PASS** on the first round, having independently re-run the
full suite (499→501 passed after two additional tests added post-verification), `mypy`, and
`run_conformance.py`, and having performed the acceptance-criterion-7 fault injection itself
(confirmed the guard-dependent tests fail with the guard defeated, pass restored). Two
non-blocking test-strength notes from that gate were closed before commit: added
`test_issuer_keys_from_candidates_split_across_multiple_jwks_still_capped` (the 5×13-JWKS
shape acceptance criterion 4 names as an alternative to the flat-list shape, not previously
tested) and `test_issuer_keys_from_config_string_candidates_also_capped` (`_reserve`'s
bare-config-string append site, the one of the three candidate-producing sites no other test
exercised in its raising state). The KNOWN RESIDUAL edge case below (candidate-free-container
walk cost) was filed as a follow-up rather than closed in this phase, per its own stated
disposition: **issue #49**.

**Delivers:** `issuer_keys_from`/`_issuer_keys_from` rejects a caller-supplied
`resolved_issuer_keys` value that would resolve to more than a fixed number of candidate keys
— across *every* shape that can produce candidates (a JWKS's `keys` array, a flat list, or any
combination/nesting of the two) — with a `ValueError` raised *before* parsing the
over-the-cap entry, not merely after building an oversized list. Converts to
`AitpError("KEY_RESOLUTION_FAILED")` through the existing, unmodified `identity.py` call site.

**Depends on:** nothing (independently shippable; touches only `jwk.py` and its own tests).

**Files:**
- `aitp_verifier/jwk.py` — new `_MAX_CANDIDATES` constant; restructure `_issuer_keys_from` from
  a pure "build and return a list" recursive walk into one that threads a single shared
  accumulator (`out: list[IssuerKey]`) through every recursive call and every candidate-append
  site, checking the running count *before* each parse call (`issuer_key_from_jwk`/
  `issuer_key_from_config`) rather than only after building the final list; update the module
  and `issuer_keys_from` docstrings.
- `tests/test_identity_oidc.py` — direct `jwk.py`-level boundary tests (mirroring the
  `_MAX_DEPTH`/`_MAX_DEPTH + 1` pattern #38 established for this same file/module), a
  multi-container-evasion test, an early-exit (parse-never-reached) test, and through-
  `verify_identity` tests.
- `tests/test_unknown_fields.py` — one end-to-end test through `verify_handshake_payload`
  against a real minted OIDC fixture (`id-009`, the same fixture #38's own e2e tests used),
  mutating `minted["resolved_issuer_keys"][<issuer>]` to an over-the-cap JWKS *after* minting
  (same "mutate after minting, not before" convention #38's plan established, to avoid
  `minter.py`'s own `copy.deepcopy` paying the cost of a hostile pre-mint value).
- `tests/test_boundary_contract.py` — no change needed: the capstone identity sweep #38 added
  (`test_boundary_contract_identity_never_raises_a_bare_exception`'s second loop over
  `issuer_keys`) already exercises `_MUTATIONS` against `resolved_issuer_keys`' *scalar leaves*,
  not its *candidate count* — an over-the-cap `keys` array isn't a leaf mutation this harness's
  existing model can express, so this phase's own dedicated tests (above) are what prove it,
  not an extension of that harness. (Confirmed by reading `_iter_leaf_paths`/`_mutate`,
  `test_boundary_contract.py:131-171`: they walk to *scalar* leaves only, never replace a whole
  list/array with a differently-sized one.)
- `CHANGELOG.md` — one `### Security-relevant` entry, matching #38's own entry's voice.

**Approach — the fix, and why this shape:**

1. **Add `_MAX_CANDIDATES = 64`.** Generous headroom (2-6x the largest realistic real-world
   JWKS size) over any legitimate use, matching this codebase's own established style for such
   constants (`_MAX_DEPTH = 16` in this same file at `jwk.py:185`, `jcs.py`'s
   `_MAX_DEPTH = 256`) — "16 is generous headroom over that, not a number tightly calibrated to
   it" (`jwk.py:179-180`, that constant's own comment; the same reasoning applies here).
   Placed next to `_MAX_DEPTH`.

2. **Restructure `_issuer_keys_from` to thread a shared accumulator and check before parsing,
   not after.** This is the one substantive design decision this phase makes, and it mirrors
   `_MAX_DEPTH`'s own already-established principle exactly: `_issuer_keys_from`'s own comment
   (`jwk.py:212-217`) says "Guard at entry, not only at the recursion site: a caller passing an
   already-deep value could exceed the cap before the first check ever ran if the guard sat
   only where the recursive call is made." The identical reasoning applies to candidate count:
   checking only the *final* list length (after a list comprehension has already parsed every
   entry) still pays full parsing cost for every candidate past the cap before rejecting —
   exactly the "check too late" failure mode the depth guard was written to avoid. Rejected:
   leaving the current `[issuer_key_from_jwk(k) for k in keys]` list-comprehension shape and
   checking `len(result) > _MAX_CANDIDATES` only once, at the end — this closes the *symptom*
   (an oversized final list) but not the *cost* (every entry still gets parsed first), and
   would not close the multi-container evasion below either.

   ```python
   _MAX_CANDIDATES = 64  # (with a comment mirroring _MAX_DEPTH's own justification style)

   def issuer_keys_from(value: Any) -> list[IssuerKey]:
       """... (existing docstring, plus one line: "Bounded to at most
       _MAX_CANDIDATES total candidates across every shape/nesting
       combination (issue #47); checked before parsing each one, not only
       after.") ..."""
       out: list[IssuerKey] = []
       _issuer_keys_from(value, 0, out)
       return out

   def _issuer_keys_from(value: Any, depth: int, out: list[IssuerKey]) -> None:
       if depth > _MAX_DEPTH:
           raise ValueError(f"issuer key value nesting exceeds the maximum depth ({_MAX_DEPTH})")
       if value is None:
           return
       if isinstance(value, str):
           _reserve(out)
           out.append(issuer_key_from_config(value))
           return
       if isinstance(value, dict):
           if "keys" in value:
               keys = value["keys"]
               if not isinstance(keys, list):
                   raise ValueError("JWKS 'keys' must be a list")
               for k in keys:
                   _reserve(out)
                   out.append(issuer_key_from_jwk(k))
               return
           _reserve(out)
           out.append(issuer_key_from_jwk(value))
           return
       if isinstance(value, list):
           for item in value:
               _issuer_keys_from(item, depth + 1, out)
           return
       raise ValueError(f"unsupported issuer key value shape: {type(value).__name__}")


   def _reserve(out: list[IssuerKey]) -> None:
       # Checked before every append, at all three candidate-producing
       # sites above -- not only inside the JWKS "keys" loop -- so a value
       # that spreads candidates across many small containers (many
       # sibling single-JWK list entries, or many small-`keys` JWKS
       # objects nested inside a list) cannot evade the cap by never
       # presenting one single oversized array. `out` is threaded through
       # every recursive call rather than built-and-merged per frame
       # (the pre-#47 shape), which is what makes a *global*, cross-shape
       # running total possible at all.
       if len(out) >= _MAX_CANDIDATES:
           raise ValueError(f"issuer key value carries more than {_MAX_CANDIDATES} candidate keys")
   ```

   `_issuer_keys_from`'s signature changes from `(value, depth) -> list[IssuerKey]` to
   `(value, depth, out) -> None` (mutate `out` in place). This is safe: it is a private helper
   (absent from `__all__`, `jwk.py:51-58`), and grepped this session — its only caller anywhere
   in the repo, tests included, is the public `issuer_keys_from` wrapper (`jwk.py:208`,
   confirmed via `grep -rn "_issuer_keys_from\b"` across the whole repo). `issuer_keys_from`'s
   own public signature is unchanged (`issuer_keys_from(value) -> list[IssuerKey]`), preserving
   #38's own "the public function's signature can't be used to bypass a cap" property for this
   cap too.

3. **No `identity.py` change needed.** `_verify_oidc`'s `except ValueError` clause
   (`identity.py:219-220`) already converts whatever `ValueError` this raises to
   `AitpError("KEY_RESOLUTION_FAILED", ..., retryable=True)` — traced end to end during this
   plan's review pass: `resolved = issuer_keys.get(issuer)` (`identity.py:208`) →
   `candidates = issuer_keys_from(resolved)` inside `try:` (`identity.py:209-210`) →
   `except ValueError as exc: raise AitpError("KEY_RESOLUTION_FAILED", f"issuer key value for
   {issuer!r} is malformed: {exc}", retryable=True) from exc` (`identity.py:219-220`). Nothing
   between the `try` and the `except` narrows the exception type, so *any* `ValueError` either
   phase raises is covered. This phase's `Files` list above deliberately does not include
   `identity.py`.

**Edge cases & failure modes:**

- **Exactly `_MAX_CANDIDATES` (64) candidates, from a single well-formed JWKS:** must resolve
  normally — the cap bounds rejection, not legitimate width. Pinned by a positive test.
- **`_MAX_CANDIDATES + 1` (65) candidates, from a single JWKS:** first count rejected, as
  `ValueError` (and, through `verify_identity`, `AitpError`/`KEY_RESOLUTION_FAILED`) — not a
  slow-but-successful parse. Pinned by a negative test.
- **The same total (65) split across many small containers** — e.g. 65 single-JWK list
  entries, or a list of 5 JWKS objects each carrying 13 keys (5×13=65) — must be rejected
  identically to the single-JWKS case, proving the cap is a genuine running total and not a
  per-container check. Pinned by its own dedicated test (this is the scenario a naive
  "check `len(keys)` inside the JWKS branch only" fix would miss).
- **Early exit is real, not just a smaller final list:** a value shaped as 64 well-formed JWKs
  followed by one deliberately-malformed 65th entry (e.g. `{"kty": "nonsense"}`, which would
  itself raise a *different* `ValueError` if ever parsed) must still raise the *count* message,
  proving the 65th entry's parse was never attempted — if the cap were checked only after
  building the full list, the malformed entry's own parse error would surface instead (a
  distinguishable, observable difference this test asserts on).
- **A single bare JWK object or bare config string (not a JWKS):** always exactly 1 candidate;
  `_reserve` is still called (uniform code path) but never trips at this scale — no behavior
  change from today, pinned implicitly by every existing positive test continuing to pass.
- **Concurrency / partial failure:** none apply — `out` is a fresh, function-local list per
  `issuer_keys_from` call (never shared across calls or threads); `_MAX_CANDIDATES` is a
  read-only module constant.
- **KNOWN RESIDUAL — a shape this cap does *not* bound: containers that produce zero
  candidates.** `_MAX_CANDIDATES` bounds *appends/parses*, not *nodes walked*, so a value made
  entirely of candidate-free entries never trips `_reserve` at all and the walk stays linear
  and unbounded. Measured during this plan's review pass:
  `issuer_keys_from([None] * 5_000_000)` → **159ms, 0 candidates, cap never fires**;
  `issuer_keys_from([{"keys": []}] * 1_000_000)` → **89ms, 0 candidates**. So this phase does
  not *eliminate* the resolver-driven CPU cost named in Context item 1 — it removes the
  expensive multiplier (per-candidate `issuer_key_from_jwk`: ~3.3µs/entry, measured) and leaves
  the cheap one (bare walk: ~0.03-0.09µs/entry, measured), a **~35-100x reduction in
  amplification per input element, not a bound on total work**.

  **Correction, found by `/ship`'s own pre-merge gate, not by this session's earlier review
  passes:** an earlier draft of this bullet justified deferring the fix partly on "the value
  is a Python object the *caller* has already materialized, so the residual walk is
  O(memory the caller already allocated) with **no amplification**." That claim is **false**
  for an *aliased* value — one where the same list object appears more than once inside its
  own containing structure, something JSON (which cannot express aliasing/reference-sharing)
  can never produce, but a Python caller constructing `resolved_issuer_keys` directly
  (bypassing `json.loads`) can. Because a `dict` is always a terminal leaf here and only
  `list`s recurse, `_MAX_DEPTH` nested lists each containing `F` references to the *same*
  next-level list produce `F^_MAX_DEPTH` node visits from `O(_MAX_DEPTH * F)` actual
  allocated memory — genuine amplification, not O(allocated memory). Measured live: 16
  aliased lists at fanout 3 (a ~384-byte structure) → **2.64s CPU, 0 candidates,
  `_MAX_CANDIDATES` never fires, `_MAX_DEPTH` never trips** (each branch is only 16 lists
  deep); fanout 4 did not return within 10s. Reachable end-to-end: a resolver/caller
  supplying such a value to `verify_identity`'s `issuer_keys` argument burns multiple seconds
  of CPU before returning `KEY_RESOLUTION_FAILED`. This is **pre-existing behavior unchanged
  since #38** (not a regression introduced by this diff), not a bound either of this plan's
  phases claims to close, and does not affect the correctness of anything actually shipped
  here — but the *rationale* for deferring it was wrong, so the "no amplification" ground
  above is retracted: the deferral now rests solely on closing it needing a second, different
  kind of cap (a nodes-visited counter threaded alongside `out` — which this phase's
  accumulator restructure would make easy to add later, at the cost of a second constant and
  a second set of boundary tests), which still holds. Accepted as still-deferred, but
  **issue #49's own body has been corrected to match** — see that issue for the current,
  accurate severity assessment. Filed as **issue #49** rather than closed in this phase; this phase's
  Delivers line must not be read as claiming it. **Do not describe Phase 1 as "bounding
  `issuer_keys_from`'s CPU cost" — it bounds its candidate count.**

**Acceptance criteria:**

1. `issuer_keys_from`'s public signature is unchanged (`issuer_keys_from(value)`, one
   positional argument) — the accumulator lives entirely in the private
   `_issuer_keys_from(value, depth, out)`, not exported in `__all__`.
2. A JWKS with exactly `_MAX_CANDIDATES` (64) well-formed entries resolves to a 64-element
   `list[IssuerKey]`.
3. A JWKS with `_MAX_CANDIDATES + 1` (65) entries raises `ValueError` from `issuer_keys_from`
   directly, and `AitpError`/`KEY_RESOLUTION_FAILED` through `verify_identity` and
   `verify_handshake_payload`.
4. The identical 65-candidate total, split across multiple sibling containers (a list of
   several smaller JWKS objects, or many single-JWK list entries), is rejected identically to
   criterion 3 — proving the running total is global across the whole walk, not per-container.
5. A value shaped as 64 valid entries followed by one entry that would itself raise a
   *different* `ValueError` if parsed never surfaces that entry's own error — the count-limit
   `ValueError` fires first, proving the 65th entry's parse was never attempted. Concretely
   checkable from test output alone, because the two messages are textually disjoint: the test
   asserts `"more than 64 candidate keys"` is in `str(exc)` **and** that
   `"unsupported or missing JWK 'kty'"` (`jwk.py:150`, what `{"kty": "nonsense"}` would raise)
   is *not*. Both assertions are needed: the positive one alone would also pass a
   check-after-building implementation if that implementation happened to report the count
   first, and the negative one is what actually pins "never parsed."
6. Full suite green (baseline measured on `main` at `d7e76cd`: **492 passed**),
   `run_conformance.py --spec-dir ../agentidentitytrustprotocol` unchanged (baseline measured
   live during Phase 1's own implementation, run twice for consistency: **71 passed, 0 failed,
   1 skipped** — no fixture carries `resolved_issuer_keys` at all),
   `mypy aitp_verifier` clean (baseline: "Success: no issues found in 23 source files").
   **Note the conformance baseline is 71/0/1, not the 68/0/1 recorded throughout most of
   `PROGRESS.md`, nor the 70/0/1 this plan's own review round recorded minutes earlier against
   the identical sibling-repo commit (`67639c3`, clean tree — re-confirmed):** the count moved
   again between the review round and Phase 1's implementation despite no sibling-repo change
   being found, so an implementer must **re-measure fresh, every time**, rather than trust any
   number written down here, including this one.
7. Fault-injection: reverting only `_reserve`'s guard (leaving the accumulator threading in
   place) makes criterion 3's and criterion 4's tests fail (`DID NOT RAISE ValueError`),
   confirming the check itself — not some other change — is what they're pinned to.

**Tests:**

- `tests/test_identity_oidc.py` (direct `jwk.py`-level, mirroring #38's own
  `_MAX_DEPTH`/`_MAX_DEPTH + 1` discipline, including an `assert _MAX_CANDIDATES == 64` pin):
  - `test_issuer_keys_from_at_max_candidates_resolves` — a JWKS with exactly 64 well-formed
    entries resolves (acceptance criterion 2).
  - `test_issuer_keys_from_past_max_candidates_raises_value_error` — 65 entries raises
    `ValueError` (acceptance criterion 3, direct-call half).
  - `test_issuer_keys_from_candidates_split_across_containers_still_capped` — the same 65-total
    split across multiple sibling JWKS/list entries also raises (acceptance criterion 4).
  - `test_issuer_keys_from_stops_parsing_at_the_cap` — 64 valid entries + 1 entry that would
    itself raise a distinguishable, different `ValueError` message if parsed; asserts the
    count-limit message, not the malformed-entry message (acceptance criterion 5).
  - `test_issuer_keys_from_malformed_scalar_raises_value_error`-adjacent: no new test needed —
    #38's own existing tests of this name already cover non-JWKS malformed shapes untouched by
    this phase.
- `tests/test_identity_oidc.py` (through `verify_identity`, via the existing `_verify` helper):
  - `test_identity_oidc_past_max_candidates_is_key_resolution_failed_not_a_crash` —
    `issuer_keys={ISSUER: {"keys": [<jwk>] * 65}}` raises `AitpError`/`KEY_RESOLUTION_FAILED`
    (acceptance criterion 3, through-`verify_identity` half).
- `tests/test_unknown_fields.py` (end to end, reusing #38's own established
  `_load_conformance_input(spec_dir, "id-009")` → `mint_input` → mutate → `verify_handshake_payload`
  pattern, mutating strictly *after* minting):
  - `test_handshake_past_max_candidates_resolved_issuer_key_is_key_resolution_failed_not_a_crash`
    — mints `id-009`, sets `minted["resolved_issuer_keys"][<issuer>]` to a 65-entry JWKS,
    asserts `AitpError`/`KEY_RESOLUTION_FAILED` (acceptance criterion 3, end-to-end half).
- **Fault-injection (executor, per acceptance criterion 7):** temporarily defeat `_reserve`'s
  guard (e.g. `if len(out) >= 10**9:`), confirm the count-boundary tests fail, restore.

**Docs:** `jwk.py`'s module docstring gains a line naming the candidate-count bound alongside
the existing depth-bound line. `CHANGELOG.md` gets one new `### Security-relevant` entry.

---

### Phase 2 — bound RSA modulus size, checked before key construction

**Status:** DONE (2026-09-25). Implemented exactly as planned (including the exponent-bound
scope addition decided during the plan's own review pass), no further approach divergence. A
fresh Opus verification gate returned **PASS** on the first round, having independently
re-run the full suite (501→512 passed after this phase's 11 new tests), `mypy` (including
`tests/`), and `run_conformance.py` (0 failed, both against a `git stash` of just this
phase's diff and against the diff applied), performed both fault-injection acceptance
criteria itself (modulus ceiling and exponent ceiling, one at a time, `Edit`-based, tree
restored byte-identically each time), and additionally proved the two monkeypatch tests
non-vacuous with a third, independent injection (a bare `RSAPublicNumbers(...)` call inserted
before the bound checks, confirmed both monkeypatch tests catch it). Five non-blocking items
from that gate were closed before commit: `identity.py`'s own docstring ("RSA, 2048+ bit
modulus") updated to the full `[2048, 8192]` + 33-bit-exponent range (a doc-drift item the
gate found in a file outside this phase's `Files` list, since Phase 1 and Phase 2 together
made `jwk.py`'s equivalent line stale but `identity.py`'s was missed); `PROGRESS.md`'s Repo
map updated to describe the post-implementation shape of `jwk.py` and `crypto.py`, not the
pre-implementation one; `uv.lock` added to `.gitignore` (never tracked in this repo's
history, flagged as a hygiene risk by three separate verification passes this session); two
exponent-boundary test assertions tightened to check the `"public exponent"` message text,
not only the bit count; and a literal `test_jwk_rsa_modulus_at_2047_bits_rejected` added
(criterion 2 was previously pinned only by a separately-sized 1024-bit key, per the plan's own
Tests section, not the exact `_MIN_RSA_MODULUS_BITS - 1` edge).

**Delivers:** `PublicKey.from_rsa_numbers` rejects an RSA modulus outside `[2048, 8192]` bits
*and* a public exponent wider than 33 bits, both checked *before* constructing a
`cryptography` key object (closing the new modulus ceiling, the new exponent ceiling, and an
existing inefficiency in the pre-existing floor check), converted to `AitpError` through the
same unmodified `identity.py` call site as Phase 1. Achieves full behavioral parity with the
companion Rust implementation's own `ring`-enforced `[2048, 8192]`-bit modulus range and
33-bit public-exponent ceiling.

**Depends on:** nothing *functionally* (touches only `crypto.py` and its own tests; does not
depend on Phase 1's code). One **documentation** coupling, called out honestly rather than
hidden in the Files list: this phase's `CHANGELOG.md` text is specified below as an extension
of the entry Phase 1 adds. Shipped on its own (Phase 2 first, or Phase 2 alone) there is no
such entry to extend, so the instruction is: **extend Phase 1's `### Security-relevant` entry
if it already exists, otherwise add this phase's own bullet in the same voice.** With that
wording the phase is genuinely independently shippable in either order.

**Files:**
- `aitp_verifier/crypto.py` — new `_MAX_RSA_MODULUS_BITS = 8192` and
  `_MAX_RSA_EXPONENT_BITS = 33` constants; reorder `from_rsa_numbers` to compute `n`'s and
  `e`'s bit lengths (via `int.from_bytes(..., "big").bit_length()`) and check all bounds
  *before* calling `RSAPublicNumbers(...).public_key()`; update the module docstring's
  existing RSA paragraph and the method's own docstring.
- `tests/test_identity_oidc.py` — boundary tests at/past the new modulus ceiling and the new
  exponent ceiling, mirroring the existing `test_jwk_rsa_modulus_under_2048_bits_rejected`'s
  own style; construction-skipped (cost) tests via `monkeypatch` for both.
- `tests/test_unknown_fields.py` — one end-to-end test through `verify_handshake_payload`.
- `CHANGELOG.md` — extends the entry Phase 1 adds **if that entry exists**, else its own bullet
  in the same voice (see this phase's `Depends on` note). Both phases are the same issue and the
  same "no bound on X" class, and CHANGELOG voice throughout this repo groups same-issue changes
  into one bullet — see #38's own single entry (`CHANGELOG.md:151-156`) covering several failure
  modes at once.

**Approach — the fix, and why this shape:**

1. **Add `_MAX_RSA_MODULUS_BITS = 8192` and `_MAX_RSA_EXPONENT_BITS = 33`, next to the
   existing `_MIN_RSA_MODULUS_BITS = 2048` (`crypto.py:45`).** The modulus ceiling is grounded
   in `ring::signature::RSA_PKCS1_2048_8192_SHA256` (`aitp-handshake/src/jwk.rs:288` in the
   sibling Rust repo, confirmed this session) — the exact algorithm identifier the companion
   implementation uses for RS256 verification, whose name encodes its own accepted range. This
   repo's own `crypto.py` module docstring already says its floor was chosen to match "the
   floor `ring::signature::RSA_PKCS1_2048_8192_SHA256` gives the companion Rust implementation
   for free" (`crypto.py:23-27`) — that docstring already names the ceiling half of the same
   identifier without adopting it; this phase closes that gap and makes the docstring's own
   claim fully true rather than half true. The exponent ceiling is grounded in the same
   sibling implementation's `ring::rsa::PublicExponent::MAX = (1u64 << 33) - 1`
   (`ring-0.17.14/src/rsa/public_exponent.rs:27`, confirmed live this session), which `ring`
   enforces on every RSA public key it accepts — without it, a modulus-bounded fix would still
   leave this repo accepting an RSA JWK with an oversized exponent that `ring` would refuse,
   the identical class of divergence the modulus ceiling exists to close, just on the sibling
   parameter. Rejected: an arbitrary, DoS-motivated-only number for either bound (e.g. 4096 or
   16384 for the modulus) with no cross-implementation grounding — both chosen values are not
   merely *defensible*, they are *the* values this repo already implicitly claims to match.

2. **Move the bound check before key construction, using an integer bit-length probe rather
   than `key.key_size` after the fact.** Measured and re-measured during this plan's review
   pass: `int.from_bytes(n, "big")` + `.bit_length()` together cost ~3.6ms at a 64,000,000-bit
   modulus versus `RSAPublicNumbers(...).public_key()`'s own ~24-28ms at the same size (~7x),
   so the reorder does save the larger of those two — without needing a hand-rolled
   byte-scanning routine (unlike the Rust sibling's own `rsa_modulus_bits_ok`, which scans raw
   bytes manually because Rust has no free `bit_length()` on an arbitrary-width integer type the
   way Python's built-in `int` does — a case where the *more* idiomatic Python solution is also
   the simpler one, not a compromise). Note `.bit_length()` itself is O(1) on a CPython `int`
   (~0.001ms even at 64M bits); essentially all of that ~3.6ms is `int.from_bytes`.

   **Do NOT justify this phase primarily on cost — measured, the reorder saves roughly a tenth
   of this path's total work, not "most" of it.** An earlier draft of this step claimed the
   reorder "captures the overwhelming majority of the possible savings"; that is wrong, because
   the dominant cost on the RSA path runs *upstream* of `from_rsa_numbers` and is untouched by
   either phase. Measured per RSA candidate, for an `n` of the given decoded size:

   | decoded `n` | `b64url_decode(n)` (`jwk.py:146`) | `int.from_bytes` | `.public_key()` |
   |---|---|---|---|
   | 1 MB (8,388,608 bits) | **23.2 ms** | 0.47 ms | 3.1 ms |
   | 8 MB (67,108,864 bits) | **188 ms** | 3.6 ms | ~24 ms |

   So the reorder removes ~3.1ms of ~27ms (~11%) at 1 MB. **Corrected during this plan's
   finalization pass** (an earlier draft of this paragraph claimed "~12s for a 64-entry JWKS
   of 8 MB moduli," extrapolating the per-candidate decode cost across all 64 candidates —
   that does not happen): `issuer_keys_from` fails fast on the first malformed/rejected
   candidate (Phase 1's own `_issuer_keys_from`, and `issuer_key_from_jwk`'s own
   final-else/`ValueError` branches, both existed before #47), so an 8 MB modulus — itself
   already over `_MAX_RSA_MODULUS_BITS` — is decoded and rejected on the *first* such entry a
   JWKS carries; the walk never reaches a second one. Measured live during finalization: a
   64-entry JWKS of 8 MB moduli costs **~194ms**, not ~12s — indistinguishable from the
   1-candidate case (~180ms), because only one decode ever happens. The true residual is
   bounded by a small constant number of oversized decodes per call (worst case measured
   ~410ms, from the EC `x`+`y` path, which decodes both coordinates before checking either's
   length), genuinely O(what the caller already materialized) with no amplification — the
   same acceptability argument this plan already makes for the KNOWN RESIDUAL in Phase 1's
   own edge cases. Still worth closing eventually (see issue #49's sibling below), but at a
   far smaller magnitude than originally stated here. A cheap O(1) pre-gate on the *encoded*
   length of `n` (reject before decoding when `len(value["n"])` exceeds the ~1366 base64url
   chars an 8192-bit modulus needs, plus slack) would close that, but it lives in
   `jwk.py::issuer_key_from_jwk`, not `crypto.py`, so adopting it here would break this
   phase's "touches only `crypto.py`" boundary. It is therefore left
   out and recorded as a follow-up candidate (see Long-term posture). **This phase's real
   justification is the security/parity one in step 1 — an accepted modulus the companion
   implementation refuses to verify against — with the reorder as a cheap, correct bonus.**

   The reorder also fixes a **pre-existing inefficiency in the floor check**, not only adds the
   new ceiling: today's code (`crypto.py:97-100`) already pays full construction cost before
   checking the floor at all; the restructure benefits both bounds symmetrically, at no extra
   cost.

   ```python
   _MIN_RSA_MODULUS_BITS = 2048
   _MAX_RSA_MODULUS_BITS = 8192  # (with a comment citing ring::signature::RSA_PKCS1_2048_8192_SHA256)
   _MAX_RSA_EXPONENT_BITS = 33   # (with a comment citing ring::rsa::PublicExponent::MAX)

   @classmethod
   def from_rsa_numbers(cls, n: bytes, e: bytes) -> "PublicKey":
       """Build a verification-only RSA key from JWK ``n``/``e`` byte strings.

       Reachable only via a third-party OIDC-issuer JWK/JWKS (``jwk.py``) --
       never via an AID. Rejects any modulus outside [2048, 8192] bits or a
       public exponent wider than 33 bits, checked before constructing a key
       object for it (issue #47) so an out-of-range value costs a
       `bit_length()` call, not a full RSA public-key construction. Both
       bounds match `ring`'s own enforced range/ceiling in the companion
       Rust implementation.
       """
       n_int = int.from_bytes(n, "big")
       bits = n_int.bit_length()
       if not (_MIN_RSA_MODULUS_BITS <= bits <= _MAX_RSA_MODULUS_BITS):
           raise ValueError(
               f"RSA modulus must be between {_MIN_RSA_MODULUS_BITS} and "
               f"{_MAX_RSA_MODULUS_BITS} bits, got {bits}"
           )
       e_int = int.from_bytes(e, "big")
       e_bits = e_int.bit_length()
       if e_bits > _MAX_RSA_EXPONENT_BITS:
           raise ValueError(
               f"RSA public exponent must be at most {_MAX_RSA_EXPONENT_BITS} bits, "
               f"got {e_bits}"
           )
       public_numbers = rsa.RSAPublicNumbers(e_int, n_int)
       return cls(ALG_RSA, public_numbers.public_key())
   ```

   `bits`/`e_bits` (plain `int`s) are the only caller-influenced values in the new messages —
   safe to interpolate directly, no `describe_value` needed (matching `crypto.py`'s own
   existing message style, which already interpolates `key.key_size`, an `int`, today). The
   exponent check has no floor: `cryptography`'s own `e >= 3` (odd) check inside
   `.public_key()` still runs afterward and is not being duplicated here (see the `e`
   edge-case note below for exactly where that check now happens relative to this one).

3. **No `identity.py` change needed**, for the identical reason as Phase 1 step 3: the
   `except ValueError` clause at `identity.py:219-220` already generalizes (traced in full
   there). `from_rsa_numbers` is reached only via `issuer_key_from_jwk`'s `kty == "RSA"` branch
   (`jwk.py:145-148`), which is inside that same guarded `issuer_keys_from` call, so this
   phase's `ValueError` travels the same path. This phase's `Files` list does not include
   `identity.py`.

**Edge cases & failure modes:**

- **Exactly 2048 and exactly 8192 bits:** both must still resolve (the existing floor test
  already pins 2048 as accepted; a new test pins 8192). The cap bounds rejection at *both*
  ends, not legitimate range.
- **2047 and 8193 bits:** both rejected as `ValueError`, with the (unchanged in spirit, now
  two-sided) message reporting the actual bit count.
- **A modulus whose raw bytes carry leading zero octets** (RFC 7518 §6.3.1 forbids this in a
  conformant JWK, but a malformed/hostile one might carry them anyway): `int.from_bytes` and
  `.bit_length()` already ignore leading zero bytes naturally (they don't change the integer's
  value), so this is handled correctly with no special-case code — unlike the Rust sibling's
  own manual byte-stripping, which needs to handle this explicitly because it works on raw
  bytes rather than a language-native arbitrary-precision integer.
- **`e` IS now separately bounded, to 33 bits — closing the same-method parity gap this
  bullet originally left open.** An earlier draft of this bullet asserted that
  `cryptography`'s `RSAPublicNumbers` *constructor* enforces `e >= 3 and e < n` and that
  "bounding `n` alone closes this dimension too." Both halves were checked live during this
  plan's review pass and were wrong in detail — which is exactly why this phase now adds its
  own explicit exponent check rather than relying on `cryptography`'s:
  - **Where `cryptography`'s own floor check happens:** `rsa.RSAPublicNumbers(e, n)`'s
    constructor validates nothing. `ValueError: e must be >= 3 and < n.` comes from
    **`.public_key()`**, not `__init__` — so it still runs, but only *after* this phase's own
    bit-length checks (both `n` and now `e`), as a final backstop.
  - **What `cryptography`'s own check does not do:** `e < n` is a *much* weaker bound than
    `ring`'s. Verified live: an `e` of the same bit-width as a valid 2048-bit `n` (e.g. `n - 2`,
    odd) constructs a `PublicKey` without complaint under `cryptography`'s check alone, while
    `ring` caps the public exponent at 33 bits (`ring-0.17.14/src/rsa/public_exponent.rs:27`).
    This phase's new `_MAX_RSA_EXPONENT_BITS = 33` check is what actually closes this —
    `cryptography`'s own floor is not a substitute for it and is left in place unchanged, as a
    defense-in-depth backstop, not the mechanism doing the work.
  - **Cost** was never the concern here (`.verify()` against a garbage signature costs
    ~0.01-0.02ms regardless of `e`'s value once `n` is capped) — this is, and remains, a
    *parity/correctness* fix, not a DoS one; it is included in this phase precisely because it
    is cheap (one constant, one clause, one test) relative to its correctness value, not because
    it is expensive to leave open.
- **Concurrency / partial failure:** none apply — `from_rsa_numbers` is a pure classmethod
  with no shared state; both constants are read-only.

**Acceptance criteria:**

1. A 2048-bit modulus and an 8192-bit modulus both construct a `PublicKey` successfully
   (boundary-inclusive at both ends).
2. A 2047-bit modulus still raises `ValueError` (pins the pre-existing floor behavior is
   unchanged in outcome, only in *when* it's checked).
3. An 8193-bit modulus raises `ValueError` from `from_rsa_numbers` directly, and
   `AitpError`/`KEY_RESOLUTION_FAILED` through `verify_identity`/`verify_handshake_payload`.
4. For an over-ceiling modulus, `rsa.RSAPublicNumbers(...).public_key()` is never called —
   proven via `monkeypatch` (patch `crypto.rsa.RSAPublicNumbers` to raise if invoked, confirm
   the over-ceiling test still raises the *bit-count* `ValueError`, not the monkeypatch's own
   raiser). Verified implementable during this plan's review pass: `crypto.py:35` imports `rsa`
   as a module attribute of `aitp_verifier.crypto`, the new code looks up
   `rsa.RSAPublicNumbers` at call time (not bound at import), and the attribute is
   settable (confirmed live). Two mechanics the test must get right: the raiser must raise
   something `pytest.raises(ValueError)` cannot absorb (`AssertionError`, not `ValueError`, or
   the test becomes vacuous), and `monkeypatch.setattr(crypto.rsa, ...)` mutates the *shared*
   `cryptography...rsa` module for the duration of the test — fine under pytest's own
   per-test undo and under `pytest-xdist`'s process isolation, but it is not scoped to
   `aitp_verifier.crypto`, so nothing else in the same test may construct RSA public numbers.
5. A public exponent with bit length exactly 33 (e.g. `(1 << 33) - 1`, `ring`'s own `MAX`)
   still constructs a `PublicKey` successfully against a valid 2048-bit modulus
   (boundary-inclusive); a public exponent with bit length 34 (e.g. `(1 << 33) + 1`) raises
   `ValueError` from `from_rsa_numbers` directly, and `AitpError`/`KEY_RESOLUTION_FAILED`
   through `verify_identity`/`verify_handshake_payload`.
6. For an over-ceiling exponent (modulus otherwise valid), `rsa.RSAPublicNumbers(...)` is
   never reached — proven via the same `monkeypatch` mechanics as criterion 4, confirming the
   *exponent-bit-count* `ValueError` fires, not the monkeypatch's own raiser.
7. Full suite green (baseline on `main` at `d7e76cd`: **492 passed**),
   `run_conformance.py --spec-dir ../agentidentitytrustprotocol` unchanged (re-measure fresh —
   see Phase 1's criterion 6 for why this number has already moved twice within this plan's own
   lifetime, most recently to **71 passed, 0 failed, 1 skipped**, and must not be pinned),
   `mypy aitp_verifier` clean (baseline: 23 source files).
8. Fault-injection: reverting only the new modulus-ceiling half of the bound check (leaving
   the floor check, the exponent check, and the reordering in place) makes the 8193-bit-modulus
   test fail (`DID NOT RAISE ValueError`).
9. Fault-injection: reverting only the new exponent-ceiling check (leaving the modulus checks
   in place) makes the 34-bit-exponent test fail (`DID NOT RAISE ValueError`).

**Tests:**

- `tests/test_identity_oidc.py`:
  - `test_jwk_rsa_modulus_at_2048_bits_accepted` / a re-check that the existing
    `test_jwk_rsa_modulus_under_2048_bits_rejected` (`tests/test_identity_oidc.py:824-826`,
    using the pinned `_SMALL_N_B64U`/`_SMALL_E_B64U` at `:88-95`) still passes unchanged
    (acceptance criteria 1, 2 — the existing test needs no edit, just confirmation it survives
    the reorder; note the reorder *changes its message* from "at least 2048 bits, got N" to the
    new two-sided text, so a message assertion must not be added to it, and none exists today).
  - `test_jwk_rsa_modulus_at_8192_bits_accepted` — a synthetic (non-prime-product, since no
    cryptographic operation is exercised before the bound check) 8192-bit `n` resolves
    (acceptance criterion 1). Confirmed live during this plan's review pass that a synthetic
    odd 8192-bit `n` with `e = 65537` does construct successfully (`key_size == 8192`) —
    `cryptography` validates only `n >= 3`, `3 <= e < n`, and `e` odd for a *public* key, never
    primality — so this test is implementable without generating a real 8192-bit RSA key.
  - `test_jwk_rsa_modulus_over_8192_bits_rejected` — a synthetic 8193-bit `n` raises
    `ValueError` (acceptance criterion 3, direct-call half).
  - `test_jwk_rsa_modulus_over_ceiling_never_constructs_a_key_object` — `monkeypatch`s
    `crypto.rsa.RSAPublicNumbers` to raise `AssertionError("should not be called")`, confirms
    the over-ceiling case still raises the bit-count `ValueError` (acceptance criterion 4).
  - `test_identity_oidc_rsa_modulus_over_ceiling_is_key_resolution_failed_not_a_crash` —
    through `_verify`, `issuer_keys={ISSUER: {"kty": "RSA", "n": <8193-bit>, "e": ...}}` raises
    `AitpError`/`KEY_RESOLUTION_FAILED` (acceptance criterion 3, through-`verify_identity`
    half).
  - `test_jwk_rsa_exponent_at_33_bits_accepted` — `e = (1 << 33) - 1` against a valid
    2048-bit `n` resolves (acceptance criterion 5, positive half).
  - `test_jwk_rsa_exponent_over_33_bits_rejected` — `e = (1 << 33) + 1` against the same valid
    `n` raises `ValueError` (acceptance criterion 5, direct-call negative half).
  - `test_jwk_rsa_exponent_over_ceiling_never_constructs_a_key_object` — `monkeypatch`s
    `crypto.rsa.RSAPublicNumbers` as above, confirms the over-ceiling exponent case still
    raises the exponent-bit-count `ValueError` (acceptance criterion 6).
  - `test_identity_oidc_rsa_exponent_over_ceiling_is_key_resolution_failed_not_a_crash` —
    through `_verify`, `issuer_keys={ISSUER: {"kty": "RSA", "n": <valid>, "e": <34-bit>}}`
    raises `AitpError`/`KEY_RESOLUTION_FAILED` (acceptance criterion 5, through-`verify_identity`
    half).
- `tests/test_unknown_fields.py`:
  - `test_handshake_rsa_modulus_over_ceiling_resolved_issuer_key_is_key_resolution_failed_not_a_crash`
    — end to end through `verify_handshake_payload` against `id-009` (acceptance criterion 3,
    end-to-end half).
  - `test_handshake_rsa_exponent_over_ceiling_resolved_issuer_key_is_key_resolution_failed_not_a_crash`
    — end to end through `verify_handshake_payload` against `id-009` (acceptance criterion 5,
    end-to-end half).
- **Fault-injection (executor, per acceptance criteria 8 and 9):** temporarily widen
  `_MAX_RSA_MODULUS_BITS` (e.g. to `10**9`), confirm the 8193-bit-modulus test fails, restore;
  separately, temporarily widen `_MAX_RSA_EXPONENT_BITS` (e.g. to `10**9`), confirm the
  34-bit-exponent test fails, restore — one revert at a time, so each fault-injection result
  is attributable to the one check it disabled.

**Docs:** `crypto.py`'s module docstring RSA paragraph (`crypto.py:18-27`) updated to say the
ceiling is now enforced, not only the floor named at `:23-27` today. `CHANGELOG.md` per this
phase's `Depends on` note (extend Phase 1's entry if present, else add this phase's own).

## Long-term posture

No one-way door in either phase. `_MAX_CANDIDATES`, `_MAX_RSA_MODULUS_BITS`, and
`_MAX_RSA_EXPONENT_BITS` are all Python-side-only constants with no wire-schema impact —
`issuer_keys_from`'s and `from_rsa_numbers`'s public signatures are both unchanged, and all
three bounds are reversible, one-line changes with no fixture or public-contract dependency on
their current values (same framing #38's own Long-term posture used for `_MAX_DEPTH`). The two
genuinely load-bearing choices are `_MAX_RSA_MODULUS_BITS = 8192` and
`_MAX_RSA_EXPONENT_BITS = 33`'s cross-implementation grounding — raising either later would
reopen the interop-parity gap this phase closes (this repo would again accept RSA keys the
Rust implementation's own `ring` call refuses), so a future change to either constant should
re-check `aitp-rs`'s own algorithm/constant choice first, not be made unilaterally. This is
noted here rather than treated as a reason to escalate now, since the current choice **closes**
the gap rather than leaving it open.

**Phase scoping.** Phases 1 and 2 are correctly separate and should not be merged: different
files (`jwk.py` vs `crypto.py`), different failure classes (count vs size), no shared code, and
each has its own complete acceptance criteria. Nothing here should be split further either —
each phase is one constant plus one restructure.

**Two dimensions this plan deliberately leaves open, both measured, neither a regression
introduced here.** Each is a follow-up-issue candidate on the #38 → #47 precedent; an
implementer may fold either in later, but neither is required for either phase to be
complete. (A third dimension — the RSA public exponent's own `ring`-parity gap — was found by
this plan's review pass in the same category as these two, but was decided directly and folded
into Phase 2 instead of left open; see Phase 2's own `e` edge case and Open questions below for
why that one, specifically, didn't stay on this list.)

1. **Unbounded walk over candidate-free containers** (Phase 1's own "KNOWN RESIDUAL" edge case):
   `issuer_keys_from([None] * 5_000_000)` → 159ms, 0 candidates, `_MAX_CANDIDATES` never fires.
   For a non-aliased value this is linear (no amplification); for an *aliased* one (a shape
   JSON cannot produce, but a direct Python caller can) it is genuinely exponential — 16
   aliased lists at fanout 3 measured 2.64s CPU from a ~384-byte structure (found by `/ship`'s
   pre-merge gate; the "no amplification" framing in an earlier draft of this residual was
   wrong for that case — see Phase 1's own KNOWN RESIDUAL edge case above for the full
   correction). Closing it needs a nodes-visited counter threaded alongside `out`. **Filed as
   issue #49**, body corrected to match this finding.
2. **Unbounded `b64url_decode` of `n`/`e`** (Phase 2's Approach step 2): 188ms for one 8 MB
   modulus, upstream of `from_rsa_numbers` at `jwk.py:150-151` and untouched by either phase.
   Bounded in practice to a small constant number of such decodes per call (~194ms measured
   for a full 64-entry hostile JWKS, not a per-candidate multiple — `issuer_keys_from` fails
   fast on the first rejected candidate; worst variant measured ~410ms, via the EC `x`+`y`
   path) — corrected during this plan's finalization pass, which found an earlier draft of
   Phase 2's own Approach section overstated this residual by roughly 60x. Closing it needs an
   O(1) encoded-length pre-gate in `jwk.py::issuer_key_from_jwk`. **Filed as issue #50.**

Both remaining dimensions are pure resource-cost gaps, not security/parity ones — the one
security/interop-flavored gap this review pass found (the RSA exponent) is the one that got
folded in rather than deferred, which is the deliberate distinguishing factor in what stayed on
this list and what didn't.

## Enterprise concerns

Same resource-exhaustion (CWE-770) framing as #38's own Enterprise concerns section, extended
to the count/size dimensions: an unbounded candidate list or an unbounded RSA modulus is a
cost-amplification primitive reachable by any embedding application whose OIDC-issuer-key
resolver can be influenced (compromised/spoofed JWKS endpoint, resolver bug). Neither bound
introduces a new failure mode observable in production beyond the existing `AitpError` contract
(a caller logging rejected verdicts by code sees `KEY_RESOLUTION_FAILED`, as it already does
for #38's three hazards) — no new error code, no SLO change. No migration/rollback story beyond
a normal revert; neither phase touches persisted state or the wire protocol.

## Open questions

None escalated. `_MAX_CANDIDATES = 64`, `_MAX_RSA_MODULUS_BITS = 8192`, and
`_MAX_RSA_EXPONENT_BITS = 33` are all "consequential but decidable" calls per the Autonomy
ladder, decided directly above with concrete grounding (real-world JWKS-size practice for the
first; the sibling Rust implementation's own `ring` algorithm choice for the other two, which
is closer to a *known constraint* than a *judgment call* — the issue's own filed text left the
first two numbers as "for whoever picks this up to evaluate," and all three have now been
evaluated against measured cost and, for the two RSA bounds, an existing cross-implementation
fact rather than an arbitrary choice).

**Decided during this review pass, not left open:** whether to fold `ring`'s 33-bit
public-exponent ceiling into Phase 2 (closing RSA parity with the sibling implementation
completely) or file it as a follow-up. **Decision: fold it in** — done directly above (Phase 2's
Approach, code block, edge cases, acceptance criteria 5-6 and 9, and Tests all updated). Reasoning:
it is one constant, one clause, and one boundary test, grounded in the identical citation
Phase 2 already uses for the modulus; leaving it open would mean shipping a phase whose own
stated goal is `ring` parity while knowingly leaving a cheap-to-close parity hole in the same
method on the sibling parameter — the same "half-true docstring claim" failure mode Phase 2
step 1 already names and fixes for the pre-existing floor-only docstring. Blast radius if this
call is wrong: near zero — it's a Python-side-only, reversible constant with no wire-schema
impact, identical in kind to `_MAX_RSA_MODULUS_BITS` itself (see Long-term posture).

Whether Phase 1 and Phase 2 ship as one PR or two is `/implement`'s own call (§0) — both are
small, independently shippable, filed under the same issue, and match the precedent set by
#38's own single-PR bundling of several related hazards; this plan gives honest, independent
phase boundaries either way.

## Repo map

See `PROGRESS.md`'s own `## Repo map` section for
`plans/issue-47-issuer-key-resource-bounds.md` (appended alongside this plan).

## Plan review

**Round 1 — fresh Opus agent, checked against the actual code (not this plan's own prose):
REVISE.** Read `jwk.py`, `crypto.py`, `identity.py` in full; read the sibling `aitp-rs` repo's
`jwk.rs`/`common.rs` and `ring-0.17.14`'s own sources directly; ran the full suite (492 passed),
`mypy` (clean, 23 files), and conformance (**70 passed / 0 failed / 1 skipped** — not the
68/0/1 this plan and `PROGRESS.md` had recorded), plus five independent live measurement
scripts. Findings (15 items, all fixed in place in this file during the same round):
- 8 stale/incorrect `file:line` citations, corrected.
- The stale conformance baseline (68/0/1 → 70/0/1, both a falsifiability defect in the
  acceptance criteria and a stale number throughout `PROGRESS.md`), corrected in both files.
- An imprecise fixture claim (no fixture carries `resolved_issuer_keys` *at all*, not merely
  "not in a JWKS shape"), corrected.
- Three RSA construction cost figures in Context, overstated 2-3x and self-contradicting the
  plan's own Approach section, replaced with re-measured figures.
- Phase 2's central cost claim ("captures the overwhelming majority of the possible savings")
  was false — `b64url_decode`, upstream of `from_rsa_numbers`, dominates the RSA path by ~7-9x
  and is untouched by either phase — rewritten to lead with the security/parity rationale and
  to name the decode gap honestly as an out-of-scope residual.
- The `e`-bound bullet was wrong on both the mechanism (`.public_key()`, not `__init__`, does
  the floor check) and the conclusion ("bounding `n` alone closes this dimension" was false —
  `ring` also caps `e` at 33 bits, unenforced here) — this became the one open call below.
- Phase 1's accumulator restructure was confirmed to close the split-across-containers
  evasion, but a genuinely un-bounded residual was found and independently verified live
  (`issuer_keys_from([None] * 5_000_000)` → 159ms, 0 candidates, cap never fires) and recorded
  as an explicit "KNOWN RESIDUAL" rather than left implicit.
- Phase 2's `Depends on: nothing` was incomplete (a real CHANGELOG-text coupling existed if
  shipped out of order), reworded to be honest in either PR order.
- One test-message-change note added; one cosmetic naming nit (`_reserve`) left as-is.
- Both flagged acceptance criteria (Phase 1's early-exit test, Phase 2's monkeypatch test) were
  independently confirmed implementable as specified, with the exact mechanics verified live.

**Post-round-1 follow-up (this session, same review cycle, not a second review round):** the
one item round 1 deliberately left as an open call rather than applying unilaterally — whether
to fold `ring`'s 33-bit RSA public-exponent ceiling into Phase 2 — was decided directly
(fold it in; see Open questions above for the recorded reasoning) and the plan updated
throughout Phase 2 (Delivers, Files, Approach, code block, edge cases, acceptance criteria,
Tests, Long-term posture, Open questions) to reflect `_MAX_RSA_EXPONENT_BITS = 33` as part of
Phase 2's scope, not a follow-up. This is a scope decision within an already-`REVISE`d round,
not new factual grounding, so it did not require a fresh round-2 agent — the citation and
measurements it rests on (`ring-0.17.14/src/rsa/public_exponent.rs:27`) were already
independently verified live by round 1's agent.

**Verdict: SOUND** (after the round-1 fixes and the post-round-1 exponent-bound decision above).
Not re-reviewed a second time per the two-round cap, since round 1's own findings were fully
closed within round 1 and the one remaining item was a decidable scope call, not a fact in
question.
