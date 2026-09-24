# Assumptions

Tracks judgment calls made while implementing `plans/hardening-issues-23-27.md`
that are correct-and-intentional but represent a real behavior change (not a
pure addition), or a "consequential but decidable" call per the Autonomy
ladder where the plan left a defensible default rather than a hard spec.
Closed out by `/reconcile` at the end of the whole plan.

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

**Status:** UNCONFIRMED (per the plan's own Open questions section: "Phase
3's B1 behavior-flip [is a] 'record and proceed' (not escalate) item" — this
entry exists so `/reconcile` can formally confirm it at the end of the whole
plan, not because the fix itself is in doubt).

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

**Status:** UNCONFIRMED (a "consequential but decidable" finding recorded for `/reconcile`
to review at end-of-plan — not a behavior change, a scope-limitation discovery worth
surfacing so it isn't silently rediscovered by a future phase).

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

**Status:** UNCONFIRMED (per the plan's own explicit instruction to log this behavior change
here for `/reconcile` to review at end-of-plan — not because the fix itself is in doubt).
