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
