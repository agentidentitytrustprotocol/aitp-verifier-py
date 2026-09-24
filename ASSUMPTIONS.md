# Assumptions

Tracks judgment calls made while implementing this repo's phased hardening
plans (`plans/hardening-issues-23-27.md`, then `plans/hardening-issues-30-31.md`
— each section names its own plan) that are correct-and-intentional but
represent a real behavior change (not a pure addition), or a "consequential but
decidable" call per the Autonomy ladder where the plan left a defensible
default rather than a hard spec. Closed out by `/reconcile` at the end of the
whole plan.

## Phase 3 — manifest.py hardening

### `identity_hint` accept→reject flip (issue #23 item 4)

**What changed:** Before this phase, `verify_manifest` accepted an
`identity_hint` of `{"type": "oidc", "issuer": ..., "subject": ..., "public_key":
...}` — an `oidc` entry that ALSO carries `public_key`. After this phase, the
same shape is rejected with `MANIFEST_INVALID`.

**Why:** `$defs/IdentityHint`'s own JSON Schema `if/then/else`
(`../agentidentitytrustprotocol/schemas/json/aitp-manifest.schema.json`)
forbids `public_key` when `type == "oidc"` and requires `issuer` instead; the
verifier's `_shape` flat presence/type/member-set check could not express
that conditional, so the schema's own rule went silently unenforced. This is
exactly the under-enforcement issue #23 item 4 reports — confirmed live
against the schema file during this plan's review round before implementation
began (see `plans/hardening-issues-23-27.md`, Phase 3's Acceptance criteria).

**How to apply:** This is a correct, intentional fix, not a design choice open
to reconsideration — the schema is unambiguous and the old behavior was a
gap, not a deliberate looser policy. Any caller that was relying on the old
under-enforcement (accepting an oidc manifest that also declared a
`public_key`) will now see `MANIFEST_INVALID` where it previously saw
success. No known caller in this repo depended on it —
`tests/test_unknown_fields.py`'s own `test_manifest_identity_hint_known_fields_accepted`
was the only place asserting the old (wrong) behavior, and this phase
rewrote it into two split positive fixtures
(`test_manifest_identity_hint_oidc_known_fields_accepted`,
`test_manifest_identity_hint_pinned_key_known_fields_accepted`) that each
assert a shape the schema actually allows. Flagged here per the plan's
explicit instruction so a downstream integrator reading this file sees the
flip called out, not just buried in a test diff.

**Status:** CONFIRMED (2026-09-24, via `/reconcile`). Fable's independent
analysis confirmed the fix matches the spec schema exactly and matches
`aitp-rs`'s existing behavior (Python was the outlier, not Rust), with no
external-breakage risk (package has never been released). Follow-up filed:
`agentidentitytrustprotocol/agentidentitytrustprotocol#59` (missing `man-007`
conformance vector + a one-line RFC-AITP-0003 §3 prose gap). See
`DECISIONS.md`.

## Phase 7 — Generic boundary-contract regression test

### Harness cannot prove the `canonicalize`/`JcsError`-escape bug class when minting itself canonicalizes the same field

**What was found:** `tests/test_boundary_contract.py`'s `_sweep` wraps `mint_input` in a
broad `except Exception: continue` (necessary — see the plan's own Edge Cases section,
which anticipated `JcsError` from `mint_input` and asked for it to be treated as
"not reachable, skip"). This has a side effect the plan didn't anticipate: for any field
that a `minter.py` signing function (`_sign_manifest`, `_sign_envelope`, `_mint_bundle`,
`_sign_revocation`, `_mint_token`) *also* canonicalizes during minting — e.g.
`manifest.extensions`, `manifest.published_at` — a hostile `1e400`/huge-int mutation at
that path raises `JcsError` inside `mint_input` itself, is caught by the harness's broad
except, and is silently skipped before the mutation ever reaches the verifier under test.
Confirmed live: reverting `manifest.py` to its pre-Phase-3 state (no `canonical_bytes`
wrapping) and re-running `test_boundary_contract_never_raises_a_bare_exception[verify_manifest]`
still passes — the harness cannot distinguish "Phase 3's fix is present" from "Phase 3's
fix is absent" for this specific bug class, because the hostile case never reaches
`verify_manifest` either way.

**Why this doesn't invalidate Phase 7:** the harness still correctly catches every *other*
gap class — missing required-member checks, missing type checks, unguarded downstream
`parse_aid`/`int`/`set` calls — confirmed by the successful hand-verification against
`envelope.py`'s Phase 4 `require_members` call (22 genuine `KeyError` violations on
revert). Phase 3/4/5's `canonical_bytes` fixes for `extensions`/`payload`/session-bundle
fields are proven by those phases' own direct-call unit tests instead (same pattern the
plan already established for Phase 6's `env["sender"]["agent_id"]`/`message_id`/`timestamp`
exclusions, which are unreachable via this harness for the same minting-time-interception
reason, just via `KeyError` rather than `JcsError`).

**How to apply:** if a future phase adds a new `canonicalize`/`canonical_bytes` call site,
do not rely on `test_boundary_contract.py` alone to prove it — mint's own signing function
for that artifact type must be checked for whether it canonicalizes the same field, and if
so, a direct-call unit test (mutate-after-minting, per every phase's established pattern) is
required to actually exercise the fix, the same way Phase 6's excluded guards are proven
by unit tests rather than this harness.

**Status:** CONFIRMED (2026-09-24, via `/reconcile`). A fresh Opus analysis re-verified the
claim live against current code (`test_boundary_contract.py:184`'s `_sweep` still wraps
`mint_input` broadly; `minter.py`'s `_sign_envelope:131`, `_sign_manifest:152`,
`_sign_revocation:169`, `_mint_bundle:327`, `_mint_pinned_proof:250` all still
canonicalize/dereference the fields described) — no harness redesign has occurred since
this was written, so the mitigation stands unchanged. See `DECISIONS.md`.

**Second confirmed instance (round-1 gap-closing):** the same blind spot recurred for
`envelope.payload.pop_nonce` — `minter.py::_mint_pinned_proof` dereferences that key
unguarded during minting, and `identity.py::_verify_pinned_key` dereferenced it unguarded
downstream, so `test_boundary_contract.py` silently skipped every mutation at that path. A
fresh Opus verifier caught it directly (not via this harness) during Phase 7's round-1
review. Fixed via a `require_members` presence check in `handshake.py::_verify_bootstrap`
plus a direct-call regression test, per the "How to apply" guidance above. This confirms
the failure mode is real and recurring, not a one-off — worth treating "does minting
dereference the same field unguarded?" as a standing question for any future required-field
guard, not just a one-time finding.

## Phase 8 — revocation-snapshot trust gap (`tct.py`/`delegation.py`, issue #24)

### `verify_snapshot_trust` hard-rejects a malformed `snapshot` sub-field that used to silently produce an empty entry set

**What changed:** Before this phase, a `record`/`revlist` whose `snapshot` was absent,
`None`, malformed (non-dict), or present-but-lacking `revocation_list`/`entries` all
silently produced an empty (`tct.py`) or skipped (`delegation.py`) entry set via `.get()`
chains with safe defaults — the caller's revocation check simply found nothing to flag,
no error surfaced. After this phase, `revocation.py::verify_snapshot_trust`'s own shape
validation (`_validate_shape`'s `isinstance` guard, `require_members`, `check_types`) hard-
rejects every one of those `snapshot`-level cases with an `AitpError`
(`REVOCATION_SNAPSHOT_INVALID` or `UNKNOWN_FIELD`) instead.

**Why:** This is the same class of gap issue #24 exists to close (an untrustworthy input
silently treated as "nothing to report" rather than surfaced as a defect), applied one
level deeper than the headline finding (a *malformed* snapshot, not just an *unsigned* one).
Confirmed via `plans/hardening-issues-23-27.md`'s Phase 8 section, which explicitly
anticipated and pre-authorized this exact change as intentional, distinct from the separate,
still-open, deliberately-deferred `issuer_revocation_list`-*absent-entirely* fail-open gap
(tracked in agentidentitytrustprotocol/aitp-verifier-py#30) — this entry covers only "the
`snapshot` sub-field, once its containing record/wrapper is present," not every possible
absence.

**How to apply:** This is a correct, intentional hardening fix, not a design choice open to
reconsideration. Any caller that was relying on a malformed embedded `snapshot` being
silently treated as "no revocation data" will now see `AitpError` (`verify_tct`) or a raised
error from `verify_delegation_token`'s multi-hop path, where it previously saw success. No
known caller in this repo depended on the old silent-empty-set behavior — confirmed via the
new `tests/test_unknown_fields.py` malformed-shape sweep (both `verify_tct` and
`verify_delegation_token`), hand-verified via `git stash` fault injection to genuinely
distinguish old (crash or silent-accept) from new (clean `AitpError`) behavior.

**Status:** CONFIRMED (2026-09-24, via `/reconcile`). Fable's independent analysis confirmed
fail-closed is the correct security default for a revocation-checking library, applied
symmetrically across `tct.py` and `delegation.py`. The same pass also found a residual gap
in this fix's own shipped code (see next entry) — fixed, tested, independently
re-verified, and merged (`8f03366`) as part of closing out this entry. See `DECISIONS.md`.

### Residual gap found and fixed during `/reconcile`: falsy-value bypass in `revocation_snapshots`

**What was found:** `delegation.py::_revocation_index`'s original guard,
`snaps = inp.get("revocation_snapshots") or []` followed by `isinstance(snaps, list)`,
only caught *truthy* non-list scalars (int/bool/float). A falsy-but-present, non-list
value (`""`, `0`, `False`, `{}`, `0.0`) was silently folded into `[]` by the `or` and
never reached the type check at all — the exact fail-open outcome issue #24 exists to
close, at values the original fix's own test sweep hadn't covered.

**Fix:** check `snaps is None` explicitly instead of by truthiness — only genuine absence
defaults to `[]`; every other non-list value, falsy or truthy, now raises
`REVOCATION_SNAPSHOT_INVALID`. Shipped in PR #36 (`8f03366`), with a discriminating
control test proving absence-vs-malformed are still correctly told apart, and a
`CHANGELOG.md` entry recording it as a security-relevant behavior change. A related
`or []` pattern was found in `minter.py:389` but confirmed to be test/fixture-minting
code only (never reachable from untrusted verification input) — not fixed, no security
impact.

**Status:** CONFIRMED (2026-09-24, via `/reconcile`) — fixed and merged, not deferred.

## Phase 3 (`plans/hardening-issues-30-31.md`) — `verify_tct`'s absence policy (issue #30)

### An absent `policy` means today's permissive behavior, not `fail_closed`

**What changed:** `verify_tct`'s input contract gains one optional top-level key, `policy`,
spelled exactly as `verify_revocation_snapshot`'s existing required one
(`{"fail_mode": ..., "max_staleness_secs": ...}`). The effective `fail_mode` it resolves
answers one question — what to do when no trusted, applicable, fresh revocation snapshot was
supplied — in this precedence: (1) a supplied top-level `policy` is **authoritative** and
cannot be overridden by anything in the input artifact (a `policy` dict without `fail_mode`,
and a non-dict `policy`, both resolve to `fail_closed`); (2) else the wrapper's
`issuer_revocation_list["fail_mode"]`, the member `tct-004-revoked` already carries and
`tct.py` read nowhere; (3) else — **no `policy` key and no wrapper `fail_mode` — `fail_open`,
preserving today's behavior byte for byte**. That third rule is the assumption logged here.
An unrecognized mode string, or a present-but-non-`str` `fail_mode` from either source,
resolves to `fail_closed`.

**Why:** In order of weight. (1) An unconditional fail-closed-on-absent default fails the
spec's own conformance pack — `tct-012` (`required_for_v0_2`) expects success with no
revocation data supplied at all, as do `del-001` (`required_for_v0_2`, core) and
`del-mh-001` for Phase 4's sibling entry point; re-derived live by walking every fixture in
`schemas/conformance/` rather than taken on trust. (2) RFC-AITP-0008 §3.1's `fail_closed`
default is a *deployment policy* default, stated for `revocation_policy.mode` in a
configured trust-anchor document; it does not speak to a verifier function invoked with no
policy object in the first place. (3) `verify_tct` has no precedent — unlike
`verify_revocation_snapshot`, whose `inp["policy"]` is required and always present — of
`policy` being a mandatory input, so there is no existing caller expectation to honor.
(4) Secure-by-default is still honored *within* an explicitly supplied policy, matching
`revocation.py:173`'s own `policy.get("fail_mode", "fail_closed")` — supplying `policy: {}`
is enough to get fail-closed. **This does not reverse the prior `/reconcile` pass's
user-confirmed fail-closed decision (`DECISIONS.md:58-93`, Phase 8): that one governs the
*obtained-but-untrustworthy* branch (a malformed/forged snapshot), which this phase preserves
untouched under every `fail_mode` and which Phase 2 even extended to the single-hop
delegation path, whereas this default governs the *absent* branch — a different case by
RFC-AITP-0008 §3.1's own blockquote, and one `ASSUMPTIONS.md`'s Phase 8 entry above records
as having been explicitly and deliberately left open by that same pass.**

**How to apply:** This is a genuine one-way door — it sets what every future caller's silence
means — and it is this plan's one item to confirm at `/reconcile`. Callers that want
RFC-AITP-0008 §3.1's fail-closed posture MUST opt in explicitly by passing `policy` (any
dict, including `{}`); callers that pass nothing keep the pre-existing behavior and are
unaffected by this phase. The alternative worth weighing is "fail-closed default, and patch
the three affected fixtures' inputs to carry an explicit permissive policy" — rejected here
because it would mean this implementation no longer runs the conformance pack as shipped,
which is the whole point of an independent second implementation. Phase 4 applies the
identical contract and the identical default to `verify_delegation_token`, so confirming or
reversing this decision settles both entry points at once.

**A consequence worth stating outright — a permissive `policy` is not monotonically weaker
than no `policy`:** because freshness is evaluated *before* the deny-list scan, and only
under a supplied `policy`, `policy: {"fail_mode": "soft_fail", "max_staleness_secs": 600}`
over a **stale** trusted snapshot that genuinely lists this TCT's own `jti` returns success
— the staleness check short-circuits into the absence branch and the deny-list scan never
runs — whereas the *identical* snapshot with **no** `policy` supplied returns `TCT_REVOKED`,
since no staleness is evaluated without a policy and the scan therefore reaches the hit.
Supplying an explicit permissive policy can, in that one case, produce a weaker outcome than
supplying nothing. This is a property of the design, not a regression: it is exactly
`revocation.py`'s own pre-existing stage-4 ordering (its `fresh` check at `revocation.py:190`
precedes its `queried_jti` scan at `:203`, with the same short-circuit), and it follows from
RFC-AITP-0008 §3.2 treating a stale snapshot as data the verifier has no business reading
rather than as a deny list to consult anyway. Deployments that want the strictest reading of
a stale-but-hit snapshot should use `fail_closed`, under which both spellings reject.

**Status:** UNCONFIRMED — pending `/reconcile`.

### The `different_issuer` test flip: a wrapper-declared `fail_closed` now rejects where the same input verified

**What changed:** `tests/test_unknown_fields.py`'s
`test_tct_revocation_snapshot_different_issuer_does_not_apply` built a wrapper carrying
`fail_mode: "fail_closed"` (from `_tct_revocation_input`, mirroring `tct-004-revoked`'s own
shape) around a snapshot signed by a *different* issuer, and asserted the TCT verified
successfully. Under resolution rule 2 that input supplies no top-level `policy`, so the
wrapper's declared `fail_closed` is now honored — and a valid snapshot that does not speak
for this TCT's issuer leaves its revocation status unknown, which under `fail_closed` is
treated as revoked. The same input now raises `TCT_REVOKED`.

**Why:** The flip is the direct consequence of closing the half of issue #30 that says the
wrapper's declared members "are never read at all". The wrapper's `fail_mode` is consulted
only where no top-level `policy` was supplied, which is monotone-safe: the no-policy default
is `fail_open`, the most permissive mode, so the wrapper can only ever tighten. The signed
issuer's applicability check itself is unchanged — the wrapper's unsigned `issuer` label
remains ignored for every trust decision, per the previous plan's "signed value wins"
finding (B5).

**How to apply:** The case was rewritten into two tests rather than deleted, so both
directions stay pinned:
`test_tct_revocation_snapshot_different_issuer_under_wrapper_fail_closed_is_revoked` pins the
rejection, and `..._under_wrapper_soft_fail_verifies` pins that the identical wrapper with
`fail_mode: "soft_fail"` still verifies — the wrong-issuer snapshot lists this TCT's own
`jti`, so that success is a real pass of the applicability skip, not an absence of checking.
Any caller that supplied a wrapper declaring `fail_closed` around a snapshot from another
issuer and relied on success will now see `TCT_REVOKED`; no conformance fixture does
(`tct-004`'s snapshot is from the TCT's own issuer and lists its `jti`, so it rejects for the
deny-list reason, unchanged).

**Status:** UNCONFIRMED — pending `/reconcile`, alongside the default-mode entry above (it is
that decision's blast radius on existing behavior, not a separate design choice).

## Phase 4 (`plans/hardening-issues-30-31.md`) — `verify_delegation_token`'s absence policy (issue #30)

### The same permissive no-`policy` default, and the per-hop boundary it is deliberately not extended across

**What changed:** `verify_delegation_token`'s input contract gains the same optional
top-level `policy` key Phase 3 gave `verify_tct`, governing the analogous absence case: when
no trusted, applicable revocation snapshot for `self_aid` was supplied, an effective
`fail_closed` rejects with `DELEGATION_SOURCE_TCT_REVOKED` instead of proceeding. Two things
are logged here.

**(1) The default.** The precedence is Phase 3's *minus its rule 2*: (a) a supplied top-level
`policy` is authoritative (a `policy` dict without `fail_mode`, and a non-dict `policy`, both
resolve to `fail_closed`; an unrecognized or non-`str` mode likewise); (b) else — **no
`policy` key at all — `fail_open`, preserving today's behavior byte for byte**. There is no
per-wrapper rung because there is no per-wrapper spelling to read: a delegation input carries
`revocation_snapshots: [{issuer_aid, snapshot}]` (`schemas/conformance/PLACEHOLDERS.md:92`),
whose records have no policy member, and honoring an invented one would be *widening the
accepted wire shape* rather than reading what the spec puts on the wire. **This is the same
underlying decision as the Phase 3 entry above ("An absent `policy` means today's permissive
behavior, not `fail_closed`"), not a second one** — the same contract, the same default, at
the sibling entry point, logged here only so the delegation path's own blast radius is
visible. Confirming or reversing that decision settles both entry points at once and MUST be
applied to both together; the plan's Long-term posture is explicit that if `/reconcile` flips
the default to fail-closed it flips in all three places (`verify_revocation_snapshot`,
`verify_tct`, `verify_delegation_token`) at once. `del-001` (`required_for_v0_2`, core) and
`del-mh-001` are both success fixtures supplying no revocation data whatsoever, so an
unconditional fail-closed default would turn the spec's own pack red here exactly as
`tct-012` does on the TCT path.

**(2) The per-hop non-goal, stated rather than silently skipped.** `fail_closed` is applied
**only to A's own deny list** — the RFC-AITP-0006 §4 step-7 / RFC-AITP-0011 §6 *source-TCT*
check, which both the single-hop and the multi-hop path now run through one shared
`_check_source_tct_revocation`. It is **not** extended to require a trusted snapshot for
every intermediate hop issuer in the multi-hop per-hop sweep: absence there proceeds under
every `fail_mode`, exactly as before this key existed. Requiring N snapshots under
fail-closed is a materially wider policy with no RFC-stated default and no fixture —
RFC-AITP-0011 is Draft, its §6 per-hop lookup says nothing about absence, and `del-mh-001`
(a draft-opt-in success fixture) supplies none. Logged as a decision so `/reconcile` sees a
boundary that was chosen, not one that was overlooked.

**How to apply:** Callers wanting RFC-AITP-0008 §3.1's fail-closed posture on delegation MUST
opt in explicitly by passing `policy` (any dict, including `{}`); callers that pass nothing
keep the pre-existing behavior and are unaffected. No conformance fixture supplies a
top-level `policy` to this operation, so all 10 `verify_delegation_token` fixtures pass
unchanged and `run_conformance.py`'s counts do not move. Two adjacent behaviors are
preserved untouched and MUST stay that way if the default is ever flipped: a malformed
`revocation_snapshots` (non-list, truthy or falsy) still raises
`REVOCATION_SNAPSHOT_INVALID`, and an untrustworthy snapshot still reports its own code,
under **every** `fail_mode` — obtained-but-untrustworthy is never routed through the absence
policy. The one counter-intuitive consequence the Phase 3 entry records — an explicitly
permissive `policy` over a *stale* snapshot that genuinely lists the handle verifies, where
the identical input with no `policy` rejects, because freshness is evaluated before the
deny-list scan and only under a supplied policy — holds identically here, for the same
reason, and `tests/test_unknown_fields.py` pins both directions on both paths. If
`/reconcile` reverses the default, the per-hop boundary in (2) is a *separate* question and
does not flip with it.

**Status:** UNCONFIRMED — pending `/reconcile`, as the same decision as the Phase 3
default-mode entry above rather than an independent one.

**Follow-up noted during verification, not a decision to confirm — RESOLVED during this
plan's finalization pass (2026-09-23), not left for later:** `_resolve_fail_mode`,
`_snapshot_is_stale`, and `_FAIL_MODES` were spelled out identically (byte-for-byte,
confirmed via AST comparison) in both `tct.py` (Phase 3) and `delegation.py` (this phase),
rather than sharing one implementation — and `revocation.py`'s own stage-4 dispatch had a
*third*, differently-spelled freshness formula (bracket access, no `OverflowError` guard,
predating this plan), which the finalization pass's whole-feature verifier found was not
merely stale but genuinely **unguarded**: `revocation.py`'s own `policy`/`max_staleness_secs`
reads leaked 8 raw Python exceptions past its `AitpError` contract (GAP 1 in
`PROGRESS.md`'s Finalization pass entry). Consolidated in that same pass: `FAIL_MODES`,
`resolve_fail_mode`, and `snapshot_is_stale` now live once, in `revocation.py` (added to its
`__all__`), imported by both `tct.py` and `delegation.py` in place of their own private
copies — no new dependency edge, since both already imported `verify_snapshot_trust` from
it. `verify_revocation_snapshot` itself was hardened onto the same shared, tested formula in
the same motion. See `PROGRESS.md`'s Finalization pass section for the fix, the 12 new
regression tests, and the full re-verification.
