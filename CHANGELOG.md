# Changelog

This project has not yet had a tagged release (still `0.1.0` / Alpha, unpublished). This
file starts tracking security-relevant and other breaking verifier-behavior changes from
here, so a future integrator has one place to check before upgrading.

## Unreleased

### Security-relevant

- **`verify_tct` / `verify_delegation_token` now hard-reject a malformed embedded
  revocation snapshot** instead of silently treating it as "nothing revoked." Previously,
  if a revocation record's `snapshot` sub-field was absent, `None`, non-dict, or missing
  `revocation_list`/`entries`, the verifier fell through `.get()` chains with safe
  defaults to an empty revoked-jti set — meaning malformed or stripped revocation data
  produced a silent pass rather than a surfaced defect. Both entry points now call
  `revocation.py::verify_snapshot_trust`, which raises `AitpError` with
  `REVOCATION_SNAPSHOT_INVALID` or `UNKNOWN_FIELD` in these cases. Fail-closed is the
  correct default for a revocation check: an unparseable snapshot is
  *obtained-but-untrustworthy*, not "no revocations reported." Any caller whose input
  happened to include malformed embedded revocation data will now see `AitpError` where
  it previously saw a successful verification. (issue #24)
- **`verify_delegation_token`'s multi-hop path now also rejects a falsy-but-malformed
  top-level `revocation_snapshots` field** (`""`, `0`, `False`, `{}`, `0.0`) with
  `REVOCATION_SNAPSHOT_INVALID`, closing a residual gap in the fix above: an `or []`
  ordering bug let these specific falsy values bypass the type check and silently fold
  into "no snapshots," the same fail-open outcome the fix above closes for the snapshot
  sub-field. A genuinely absent field (`None`) is unaffected and still verifies
  successfully with no revocations applied.
- **`verify_delegation_token` now performs the RFC-AITP-0006 §4 step-7 source-TCT
  revocation check on the single-hop path**, which it previously performed only on the
  multi-hop path. A single-hop delegation token whose embedded voucher's `src_jti`
  appeared in a present, structurally valid, member-set-valid, correctly-signed revocation
  snapshot issued by the verifier itself (`self_aid`) verified successfully: the trusted
  deny list was computed and then never consulted. Such a token is now rejected with
  `DELEGATION_SOURCE_TCT_REVOKED`, raised strictly after every signature and claims check
  (including the scope check), per RFC-AITP-0008 §3.3's ordering requirement. The deny list
  consulted is the verifier's own — a snapshot genuinely signed by some other peer that
  lists the same `src_jti` still verifies, unchanged. Two secondary rejection paths open
  with it, because the single-hop path now reads `revocation_snapshots` at all: an input
  whose top-level `revocation_snapshots` is malformed (a non-list, including the falsy
  values `""`, `0`, `False`, `{}`, `0.0`) now raises `REVOCATION_SNAPSHOT_INVALID`, and one
  carrying a snapshot that fails `verify_snapshot_trust` (bad shape, unknown member,
  forged or absent signature) now raises that snapshot's own structural or signature code
  — both were silently ignored on this path before. These are the same
  obtained-but-untrustworthy semantics `verify_tct` and the multi-hop path already had, but
  they are a behavior change for a caller who was passing junk in that field to a
  single-hop verification and getting away with it. A genuinely absent
  `revocation_snapshots` is unaffected. (issue #30)
- **`verify_tct` and `verify_delegation_token` require a top-level `policy` object** —
  `{"fail_mode": ..., "max_staleness_secs": ...}`, the same shape `verify_revocation_snapshot`
  has always taken — governing what happens when *no* trusted, applicable revocation
  snapshot was supplied. **A revocation decision is mandatory, not optional: a caller
  supplying no `policy` — and, on `verify_tct` only, no `issuer_revocation_list.fail_mode`
  fallback either (see rung 2 below) — gets a raw `KeyError("policy")`, never a silent
  `fail_open`.** This was reversed from this release's own initial permissive-default
  design via `/reconcile`, before any real caller could come to depend on it — see
  `ASSUMPTIONS.md`/`DECISIONS.md` for the full reasoning, including why the
  conformance-pack constraint that originally justified the permissive default does not,
  on inspection, force it: `run_conformance.py` supplies the deployment's own policy for
  fixtures that carry none, the same role it already plays for other call-time-only inputs
  like `_feature`. A caller with no revocation infrastructure must say so explicitly —
  `policy: {"fail_mode": "fail_open"}` — rather than getting that outcome by omission.
  Supplying `policy: {}` is enough to opt into fail-closed: within a supplied `policy`, an
  absent `fail_mode` resolves to `fail_closed`, matching `verify_revocation_snapshot`'s own
  long-standing `policy.get("fail_mode", "fail_closed")`. Under an effective `fail_closed`,
  absence is rejected with `TCT_REVOKED` (`verify_tct`) or
  `DELEGATION_SOURCE_TCT_REVOKED` (`verify_delegation_token`) — RFC-AITP-0008 §3.1's
  "unknown is treated as revoked"; `soft_fail` and `fail_open` verify normally. A non-dict
  `policy`, an unrecognized mode string, or a `fail_mode` of the wrong JSON type (`5`,
  `None`, `[]`) all resolve to `fail_closed`: unrecognized configuration is never silently
  permissive, and never a raw `TypeError`/`AttributeError`. On `verify_delegation_token`,
  an effective `fail_closed` governs only the verifier's own (`self_aid`'s) deny list — the
  RFC-AITP-0006 §4 step-7 / RFC-AITP-0011 §6 source-TCT check — and is deliberately **not**
  extended to require a trusted snapshot for every intermediate hop issuer on the multi-hop
  path: an intermediate hop's absent revocation data is unaffected by `policy` and proceeds
  under every mode, unchanged by this release.

  The effective mode resolves in strict precedence: (1) a supplied top-level `policy` is
  **authoritative** and cannot be overridden by anything in the input artifact; (2)
  `verify_tct` only — `issuer_revocation_list["fail_mode"]`; (3) otherwise — no `policy`
  and, on `verify_tct`, no wrapper `fail_mode` either — **raise `KeyError("policy")`**, not
  a default. Rung (2) is deliberately below rung (1) because the
  `{revocation_list, signature}` wrapper is unsigned caller-supplied data: were it to
  outrank an explicitly configured `policy`, a deployment that had chosen `fail_closed`
  could be silently downgraded by whatever assembled the wrapper. In the one position it
  does hold — the deployment supplied no top-level `policy` at all — it is what keeps that
  specific case from raising: a caller whose only outstanding fail-mode signal is the
  wrapper's own declared member (as the spec's own `tct-004` fixture already carries) still
  gets a decision instead of `KeyError`. `verify_delegation_token` has no rung (2):
  `revocation_snapshots` records are `{issuer_aid, snapshot}` and carry no policy member,
  and inventing one would widen the wire shape rather than read it — so `policy` is
  unconditionally required there.

  Two more consequences to check before upgrading, both on `verify_tct`. It **now honors
  `issuer_revocation_list.fail_mode`, which it previously ignored entirely** even though
  the spec's own `tct-004` fixture carries that member — so an input supplying a wrapper
  that declares `fail_mode: "fail_closed"` and no top-level `policy` is now governed by it
  instead of raising. And a trusted snapshot whose **signed** `issuer` is not this TCT's
  `iss` is now treated as *absent* and answered by the effective `fail_mode`, rather than
  being silently skipped — under an effective `fail_closed` that input now rejects where it
  previously verified. (The wrapper's own unsigned `issuer` label remains ignored for every
  trust decision: the signed value wins.) Unchanged in both entry points: an
  obtained-but-untrustworthy snapshot is never answered by `fail_mode` and still raises its
  own `REVOCATION_SNAPSHOT_INVALID` / `UNKNOWN_FIELD` /
  `REVOCATION_SNAPSHOT_SIGNATURE_INVALID` under every mode. On `verify_delegation_token`,
  snapshot freshness/staleness is now evaluated on every successful call, since reaching one
  requires a `policy` decision to already have been made — the asymmetry this module
  previously documented, where an explicitly permissive `policy` over a stale snapshot
  could verify while the identical input with no `policy` at all rejected outright, can no
  longer be constructed by any caller once `policy` is mandatory. (issue #30)
- **`verify_revocation_snapshot` now honors `fail_mode: "fail_open"`**, which previously
  fell through to the `fail_closed` branch and so behaved identically to it, raising
  `TCT_REVOKED` for a stale or wrong-issuer snapshot — a valid RFC-AITP-0008 §3.1 mode
  silently mishandled. It now returns `{"revoked": False, "stale": True}`, the same
  degraded verdict `soft_fail` returns: both §3.1 modes mean "proceed on degraded
  revocation data", and this entry point exposes no grant-restriction surface to
  distinguish them. `stale: True` is kept rather than a bare `{"revoked": False}` so a
  degraded verdict stays distinguishable from a fully-verified fresh one. `fail_closed` and
  any unrecognized mode string still raise. No fixture in the conformance pack exercises
  `fail_open`, which is why this could not have been caught by a red test. (issue #30)
- **`canonicalize` / `canonical_bytes` reject excessively nested values** with the calling
  artifact's own structural error code, instead of letting a raw `RecursionError` escape a
  verifier entry point. `jcs.py`'s serializer is depth-capped at 256 levels of relative
  nesting and raises `JcsError`, which every attacker-reachable call site already converts
  to its own shape code (`INVALID_ENVELOPE`, `MANIFEST_INVALID`,
  `REVOCATION_SNAPSHOT_INVALID`, `SESSION_BUNDLE_INVALID`); `fields.canonical_bytes`
  additionally converts a `RecursionError` that reaches it anyway — from a caller whose own
  stack was already near-exhausted — into the same `AitpError`, with a constant message. No
  new error code was needed. No legitimate AITP artifact approaches the cap: the deepest
  value this implementation is ever asked to canonicalize, measured across the whole
  conformance pack plus `known-answer/signed-examples/`, nests 4 levels, so the cap sits
  64× above it. It is reachable only by hostile input — including input nested inside an
  `extensions` member whose interior RFC-AITP-0001 §7 forbids inspecting. Callers now see
  `AitpError` where they previously saw an unhandled `RecursionError`, which is the
  boundary contract this library states everywhere else. (issue #31)
- **`verify_identity`'s OIDC path now bounds and converts every failure mode of its
  `resolved_issuer_keys` argument** — a caller/resolver-supplied value carrying no schema
  at all, unlike this entry point's other arguments. `jwk.issuer_keys_from`'s list walk was
  unbounded and could drive a raw `RecursionError` on a deeply nested value; its own
  `issuer_key_from_jwk` rendered an unrecognized `kty`/`crv` with `repr()`, the same
  RecursionError-during-formatting and unbounded-*container*-message hazard `describe_value`
  (issue #31) already closed elsewhere, just never swept here — `describe_value` is
  cost-bounded, not O(1): a `kty`/`crv` that is itself a container can no longer blow the
  message budget or the stack, but an enormous *scalar* string there still renders in full,
  same as any other JSON scalar `describe_value` is asked to describe; and `resolved_issuer_keys`
  itself not being a mapping raised a raw `AttributeError` from `.get()`. All three now raise
  `AitpError("KEY_RESOLUTION_FAILED")`, the same code already used for "no usable
  candidates" — a resolver that hands back garbage has produced exactly as much usable key
  material as one that hands back nothing. `issuer_keys_from`'s list nesting is capped at
  16 levels (public signature unchanged; the cap lives in a private helper so it cannot be
  bypassed by a caller-supplied starting depth). No legitimate value nests past 1 level.
  (issue #38)
- **`verify_revocation_snapshot` now guards its own `policy` argument** the same way
  `verify_tct`/`verify_delegation_token`'s new `policy` handling above does, instead of
  bracket-reading it raw. Previously, a missing `max_staleness_secs` raised `KeyError`; a
  value of `Infinity` raised `OverflowError`; `NaN` or a non-numeric string raised
  `ValueError`; a list or dict raised `TypeError`; and a non-dict `policy` raised
  `AttributeError` — none of them `AitpError`, on this entry point's own top-level call
  argument. A **missing `max_staleness_secs` now behaves differently**: previously a crash,
  it now means "no staleness bound — only the snapshot's own signed `expires_at` governs",
  matching `verify_tct`/`verify_delegation_token`'s identical default. A non-dict `policy`
  now resolves to `fail_closed` rather than crashing, the same resolution the other two
  entry points already give a non-dict `policy`. Found and fixed during this plan's
  finalization pass, closing the fail-mode-helper triplication the `policy` work above had
  already introduced across three modules.
