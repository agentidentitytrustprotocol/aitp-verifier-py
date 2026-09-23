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
