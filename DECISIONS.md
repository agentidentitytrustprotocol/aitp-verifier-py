# Decisions

Durable record of `/reconcile` passes closing out `ASSUMPTIONS.md` entries. One entry per
assumption, dated. `/ship` and any later reconciliation read this instead of replaying the
conversation that produced it.

## 2026-09-24 — `/reconcile` on `plans/hardening-issues-23-27.md`

All 3 `ASSUMPTIONS.md` entries from this plan reviewed. Ranked by blast radius: Phase 8
(revocation/trust-boundary, security-relevant) and Phase 3 (auth-model-adjacent, public
verifier behavior flip) analyzed by Fable and decided by the user; Phase 7 (a test-harness
scope note, no behavior change, cheap to reverse) analyzed and settled by Opus without
escalation.

### Phase 3 — `identity_hint` accept→reject flip (issue #23 item 4)

- **Assumed/Chose:** `verify_manifest` now rejects an oidc `identity_hint` that also
  carries `public_key`, where it previously accepted it silently.
- **Analysis (Fable):** Confirmed against `agentidentitytrustprotocol/schemas/json/aitp-manifest.schema.json`'s
  `$defs/IdentityHint` if/then/else — the fix matches the schema exactly. Confirmed
  against `aitp-rs/crates/aitp-manifest/src/verifier.rs:121-131` — the Rust reference
  implementation already rejected this shape; Python was the outlier, not Rust, so the
  two required implementations now agree rather than diverge. External-breakage risk
  assessed as nil: package has never been released (no PyPI listing, no git tags,
  `0.1.0`/Alpha), and the one sibling repo that touches manifests (`aitp-playground`)
  builds oidc hints through the Rust builder, which cannot produce the forbidden shape.
  Gap found: the spec's conformance pack has no vector pinning this case, and
  RFC-AITP-0003 §3's prose never states the oidc-side `MUST NOT contain public_key` (only
  the schema and RFC-AITP-0002 §1 do). Recommendation: CONFIRM-WITH-FOLLOWUP.
- **Decided by:** User (critical tier — public verifier behavior flip, auth-model
  adjacent).
- **Verdict:** CONFIRM.
- **Status:** CONFIRMED. Follow-up filed:
  `agentidentitytrustprotocol/agentidentitytrustprotocol#59` (missing `man-007`
  conformance vector + RFC-AITP-0003 §3 prose gap) — a read-only cross-repo issue, no
  code changed in that repo.

### Phase 7 — Boundary-contract harness scope limitation (minting-time interception)

- **Assumed/Chose:** N/A — not a behavior change. A documented limitation of
  `tests/test_boundary_contract.py`'s generic fuzzing harness: when `minter.py`'s own
  signing function canonicalizes/dereferences the same field a test mutates, the
  mutation is intercepted during minting and never reaches the verifier under test, so
  the harness can't prove certain bug classes at those field paths.
- **Analysis (Opus):** Re-verified live against current code: `_sweep`
  (`test_boundary_contract.py:184`) still wraps `mint_input` in a broad
  `except Exception: continue`; `minter.py`'s `_sign_envelope:131`, `_sign_manifest:152`,
  `_sign_revocation:169`, `_mint_bundle:327` still canonicalize their full artifact
  bodies, and `_mint_pinned_proof:250` still dereferences `pop_nonce` unguarded — matching
  the entry's claims exactly. No harness redesign has occurred since the entry was
  written; the mitigation (new `canonicalize` call sites need their own direct-call unit
  test, not reliance on this harness) remains the correct and only fix.
- **Decided by:** Opus (reversible tier — a documentation/process note, not a behavior
  change; settled without escalation per the Autonomy ladder).
- **Verdict:** CONFIRM, no correction.
- **Status:** CONFIRMED.

### Phase 8 — `verify_snapshot_trust` hard-rejects a malformed `snapshot` sub-field (issue #24)

- **Assumed/Chose:** `verify_tct`/`verify_delegation_token` now hard-reject a malformed
  embedded revocation `snapshot` (absent, `None`, non-dict, or missing
  `revocation_list`/`entries`) with `AitpError`, where it previously silently produced an
  empty (`tct.py`) or skipped (`delegation.py`) revoked-jti set.
- **Analysis (Fable):** Confirmed against current code (`tct.py:149`,
  `delegation.py:168`, `revocation.py:84-166`) that fail-closed is correctly and
  symmetrically applied across both consumers. Assessed the security posture directly:
  fail-closed is unambiguously correct for a revocation-checking library — an unparseable
  snapshot is *obtained-but-untrustworthy*, not "no revocations reported," and the old
  behavior let an attacker who could merely corrupt a snapshot's shape (no forged
  signature needed) suppress a genuine revocation. The library-vs-service distinction
  (integrators already must catch `AitpError` on every `verify_*` call; this is a
  spec-conformance reference implementation, so silently diverging from the spec to
  preserve buggy leniency would defeat its purpose) further supports fail-closed with no
  rollout/canary concern. **Found a live, unfixed residual gap**: `delegation.py:160`'s
  `snaps = inp.get("revocation_snapshots") or []` (evaluated before the
  `isinstance` check) let falsy-but-malformed values (`""`, `0`, `False`, `{}`, `0.0`)
  bypass validation and silently produce an empty index — the same fail-open class issue
  #24 was meant to close, missed by the original fix's test sweep (which only covered
  truthy scalars). Recommendation: CONFIRM-WITH-FOLLOWUP — fix the ordering bug, and add a
  changelog/security callout for the new hard-fail codes given the security-relevant,
  breaking nature of the change.
- **Decided by:** User (critical tier — security/trust-boundary behavior flip).
- **Verdict:** CONFIRM, with the follow-up fix included immediately rather than deferred.
- **Status:** CONFIRMED. The residual gap was fixed same-session: `delegation.py`'s guard
  now checks `snaps is None` explicitly instead of by truthiness (only genuine absence
  defaults to `[]`; every other non-list value, falsy or truthy, now raises
  `REVOCATION_SNAPSHOT_INVALID`). Verified independently by a fresh Opus agent (PASS —
  confirmed the new control test genuinely discriminates absent-vs-malformed, and swept
  the codebase for the same `or []`-before-typecheck pattern elsewhere; found one instance
  in `minter.py:389` but confirmed it's fixture-minting code unreachable from untrusted
  verification input, not fixed, no security impact). Shipped as PR #36, merged into
  `main` at `8f03366` (CI: 8/8 green). `CHANGELOG.md` created to record both this and the
  original issue #24 fix as security-relevant behavior changes for future integrators.

## Summary

3 of 3 entries reviewed. 3 confirmed (0 changed-in-design, 0 deferred). 1 settled by Opus
without escalation (Phase 7); 2 decided by the user after independent Fable analysis
(Phase 3, Phase 8). Phase 8's review directly produced a genuine, previously-unknown
security-relevant bug (the falsy-value bypass) — found, fixed, independently re-verified,
and merged in the same pass, not left open. One cross-repo follow-up filed (spec repo
issue #59, read-only — no code changed there). No entry needs further code follow-up
before the next `/ship`; all three PRs (#29, #32/#33, #34/#35) plus this reconcile pass's
own PR (#36) are merged into `main`.

## 2026-09-23 — `/reconcile` on `plans/hardening-issues-30-31.md`

3 `UNCONFIRMED` `ASSUMPTIONS.md` entries from this plan, effectively 2 distinct decisions
(Phase 3's `different_issuer` entry is the first decision's direct behavioral corollary,
not independent — its own `Status:` line says so). Ranked by blast radius: the
absent-`policy`-default-permissive decision (a genuine one-way door — sets the permanent
public-API default for `verify_tct`/`verify_delegation_token`'s new `policy` parameter,
spanning the Phase 3 and Phase 4 entries as the same decision applied to both entry
points) analyzed by Fable, decided by the user; the multi-hop per-hop non-goal boundary
(Phase 4's second point — reversible, no fixture depends on it either way) analyzed and
settled by Opus without escalation.

### `verify_tct`/`verify_delegation_token`'s absent-`policy` default

- **Assumed/Chose:** As originally implemented (Phase 3/Phase 4), a caller supplying no
  top-level `policy` at all — and on `verify_tct`, no wrapper-declared
  `issuer_revocation_list["fail_mode"]` fallback either — got a silent `fail_open`:
  byte-for-byte the same behavior as before `policy` existed. Justified at implementation
  time primarily by conformance-pack compatibility: `tct-012`, `del-001`, and `del-mh-001`
  are all `required_for_v0_2` success fixtures that supply no revocation data whatsoever,
  and an unconditional fail-closed-on-absent default would turn them red.
- **Analysis (Fable):** Recommended reversing the default to a mandatory decision — no
  `policy` (and no wrapper fallback, on `verify_tct`) raises `KeyError("policy")` rather
  than defaulting to `fail_open` — for four converging reasons:
  1. **The load-bearing constraint isn't load-bearing.** The stated justification (the
     three required fixtures would go red) does not actually force a permissive default.
     `run_conformance.py` already plays the role of "the deployment" for one other
     call-time-only input (`minted["_feature"] = fixture.get("feature")`); it can do the
     same for `policy` — `minted.setdefault("policy", {"fail_mode": "fail_open"})` for
     fixtures carrying none — keeping the pack green with zero fixture edits. Verified
     empirically, not just in Fable's own simulation: re-run live after the code change,
     68 passed / 0 failed / 1 skipped, unchanged.
  2. **Cross-implementation precedent already exists.** The sibling Rust reference
     implementation (`aitp-rs`) made the identical call the strict way for its TCT path
     (commit `07c167b`, "R3 strict verify": `TctVerifyContext::builder().build()` returns
     `Err(RevocationDecisionRequired)` unless the caller supplies `.revocation_check(...)`
     or explicitly calls `accept_unchecked_revocation_dangerous()`), after Rust's own
     security review concluded "a verifier with no revocation source silently accepts
     revoked-but-unexpired TCTs" — the exact bug class issue #30 was filed against in this
     implementation. Rust's delegation path (`VerifyDelegationContext`) is asymmetrically
     still permissive there — flagged as a caveat/follow-up for that repo, not matched
     here (a cross-repo issue, not this repo's call to fix).
  3. **A silent permissive default reintroduces exactly the bug class this plan closes.**
     Issue #30 was filed because a revocation check could be skipped by omission, not by
     choice. A configured-but-defaulted-permissive `policy` merely moves that omission one
     level up — from "the check runs but is silently ignored" to "the check runs but the
     caller never decided whether it should" — rather than closing it.
  4. **A caller with genuinely no revocation infrastructure isn't blocked** — the
     mandatory decision is one line, `policy: {"fail_mode": "fail_open"}`, matching the
     old default byte-for-byte when explicitly chosen. The cost falls entirely on making
     the omission itself impossible, not on any real deployment's capability.

  Recommendation carried a caution, not just a conclusion: implementing it naively (a bare
  `raise KeyError("policy")` at the point of use) risked a **lazy-resolution trap** —
  `delegation.py::_check_source_tct_revocation` originally called `_effective_fail_mode`
  only inside the `if not applicable:` branch, so a caller whose snapshots are always
  fresh/applicable in testing would never discover the missing `policy` key until the
  first time absence was actually reached, potentially in production. Fable's
  recommendation included resolving eagerly, unconditionally, at the top of the function —
  applied during implementation (see `ASSUMPTIONS.md`'s Phase 4 entry).
- **Options presented to the user:** "Require policy" (raise `KeyError("policy")` on
  absence — Fable's pick), "Fail-closed by default" (treat absence as revoked rather than
  raising), "Confirm as shipped" (keep the permissive default), "Defer" (leave
  `UNCONFIRMED`).
- **Decided by:** User — a genuine one-way door (sets the permanent public-API contract
  for what a caller's silence means on both `verify_tct` and `verify_delegation_token`),
  so Fable analyzed and the user chose directly, per the Autonomy ladder.
- **Verdict:** CHANGE — "Require policy" (Fable's pick).
- **Status:** Implemented and independently re-verified in this same pass (2026-09-23).
  `_effective_fail_mode`'s rule 3 (`tct.py`) and rule 2 (`delegation.py`, which has no
  wrapper-fallback rung at all) now raise `KeyError("policy")` instead of returning
  `"fail_open"`; `run_conformance.py` and `tests/test_boundary_contract.py`'s `_sweep`
  supply `policy: {"fail_mode": "fail_open"}` for fixtures/mutations carrying none, per
  Fable's finding (1) above. 15 tests across `tests/test_boundary_contract.py` and
  `tests/test_unknown_fields.py` updated: some renamed and rewritten to assert
  `KeyError` instead of success, some given an explicit `policy` because they were never
  testing this default in the first place, and
  `test_delegation_staleness_is_always_evaluated_once_policy_is_mandatory` rewritten
  entirely — its old premise (staleness is not evaluated without a top-level `policy`) is
  now structurally impossible to construct on `verify_delegation_token` once `policy` is
  mandatory there (see `ASSUMPTIONS.md`'s Phase 3/Phase 4 entries for the full detail,
  including why this specific asymmetry survives on `verify_tct` via its rung-2 wrapper
  fallback but not on `verify_delegation_token`). Full suite green (473 passed), `mypy`
  clean, conformance pack unchanged (68 passed / 0 failed / 1 skipped) — confirming
  Fable's central empirical claim held in practice, not just in simulation. The change
  itself was mutation-tested for non-vacuity: the four tests asserting `KeyError` were
  confirmed to fail under the reverted (old, permissive) code before the fix was restored.
  Two optional cross-repo follow-ups Fable surfaced are left for the user to decide
  whether to file, not required to close this decision: a spec-repo issue proposing
  conformance runners supply the deployment's own policy for fixtures that carry none, and
  an `aitp-rs` issue noting its `VerifyDelegationContext` lacks the `R3` strict-verify gate
  its TCT sibling has.

### Phase 4 — the multi-hop per-hop sweep is deliberately not governed by `fail_closed`

- **Assumed/Chose:** An effective `fail_closed` on `verify_delegation_token` governs only
  the root voucher's source-TCT check (the verifier's own, `self_aid`'s, deny list) — not
  the multi-hop per-hop sweep that checks each intermediate hop issuer's own deny list.
  Absence at an intermediate hop proceeds under every `fail_mode`, unaffected by this
  plan's `policy` parameter entirely.
- **Analysis (Opus):** Confirmed the boundary in code —
  `_check_source_tct_revocation` (`aitp_verifier/delegation.py:310`) is the sole consumer
  of `_effective_fail_mode`/`_apply_absence`, called from both the single-hop (`:178`) and
  multi-hop (`:463`) source-TCT checks; the per-hop sweep (`:466-471`) consumes
  `_revocation_index(bodies)` with no policy and no staleness filter, pinned by
  `tests/test_unknown_fields.py:1965`. Found the gap is real but narrow and not closable
  in this implementation: RFC-AITP-0011 (multi-hop) is still Draft, its §6 per-hop lookup
  states no absence semantics, there is no snapshot fetch/distribution mechanism defined
  for per-hop issuers at all (snapshots arrive only as caller-supplied input), and the
  only fixture exercising this path (`del-mh-001`, draft opt-in) supplies none. Concluded
  that requiring N trusted snapshots under `fail_closed` would reject essentially every
  real multi-hop chain today, pushing callers off `fail_closed` entirely — a net security
  loss, not a gain, in an independent second implementation whose value is running the
  spec's own pack as shipped. The one implementation-revealed change: Phase 4 unified the
  single-hop and multi-hop source-TCT call sites into one function, which if anything
  strengthens (not weakens) the part of this boundary that IS governed. Recommended one
  small, safe, immediately-applicable fix: `CHANGELOG.md`'s `policy` entry didn't state
  the per-hop scope limit, so a caller reading it alone would reasonably assume
  `fail_closed` covers the whole chain.
- **Decided by:** Opus (reversible tier — an internal scope boundary within an already-
  optional parameter, not a public-contract change; explicitly independent of the other
  decision's outcome per the `ASSUMPTIONS.md` entry itself, "does not flip with it").
- **Verdict:** CONFIRM, with the CHANGELOG clarification applied immediately (not deferred
  as a follow-up task, since it was small and safe): `CHANGELOG.md`'s `policy` entry now
  states the per-hop scope limit explicitly.
- **Status:** CONFIRMED (2026-09-23).

## Summary

3 `UNCONFIRMED` entries reviewed (2 distinct decisions — see the ranking note above). 1
confirmed as-is (the per-hop non-goal, settled by Opus without escalation), 1 changed (the
absent-`policy` default, decided by the user after Fable's analysis — from a silent
permissive default to a mandatory `KeyError("policy")` on absence), 0 deferred. The
`different_issuer` test-flip entry (`ASSUMPTIONS.md`, Phase 3) was resolved directly as a
mechanical corollary of the default-mode decision, without a separate agent dispatch,
since it is entirely governed by rung 1/2 precedence, which the reversal left untouched —
confirmed as originally shipped, no code change. The CHANGE needed code follow-up before
the next `/ship`, and that follow-up is done and independently verified in this same
pass: `tct.py`, `delegation.py`, `run_conformance.py`, and 15 tests updated, full suite
green (473 passed), mypy clean, conformance pack unchanged (68/0/1), the specific behavior
change mutation-tested for non-vacuity, and `CHANGELOG.md`/`ASSUMPTIONS.md` corrected to
describe what actually shipped rather than the superseded permissive design. Two optional
cross-repo issues Fable surfaced (spec-repo conformance-runner-supplies-policy; `aitp-rs`
delegation-path parity with its own TCT-path strict gate) are noted above and left to the
user's discretion — not required to close this pass. Ships as its own PR, following
`/ship`'s normal cycle from a feature branch, since `main` already has the previously
permissive default from this plan's earlier merge.
