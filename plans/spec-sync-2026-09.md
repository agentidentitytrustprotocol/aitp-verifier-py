# Spec sync: absorb agentidentitytrustprotocol@main changes (2026-08-30 → 2026-09-23)

## Context

`aitp-verifier-py` is a pure-Python, network-free, independent re-implementation of the
AITP verification core. Its README states the independence claim explicitly: it is
"implemented from the RFC-AITP texts and JSON schemas only" — no code shared with, or
ported from, `aitp-rs`. CI (`.github/workflows/ci.yml`) does **not** pin the spec: every
run checks out `agentidentitytrustprotocol@main` fresh (see the comment block at
`ci.yml:7-13`), by design, with a daily 06:17 UTC cron (`ci.yml:14-20`) as the "drift
canary" for exactly the failure mode this plan addresses — a spec merge turning this repo
red with zero commits here.

This repo's own last substantive commit is `adcd06f` (2026-08-30), which adopted spec
commit `ea22c71` (`UNKNOWN_FIELD` + structural-rejection codes + the unified identity
descriptor). Between then and now (2026-09-23), the spec repo gained 7 more commits (all
dated 2026-09-20) and the reference Rust implementation (`aitp-rs`) gained several more
through 2026-09-23. This plan is the result of diffing every one of those commits against
this repo's actual code and against a live run of this repo's test suite pointed at the
current spec checkout.

**One finding is a confirmed, reproduced, live test failure** (Phase 1) — not a
hypothetical drift risk. Run today:

```
AITP_SPEC=/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol \
  /tmp/aitpvenv313/bin/python -m pytest tests/ -q
```

produces `1 failed, 161 passed`: `tests/test_signed_examples.py::test_revocation_signed_example_runs_the_real_verifier`
fails with `AitpError: UNKNOWN_FIELD: revocation snapshot carries unrecognized field(s): ['signing_input']`.
`run_conformance.py --spec-dir ../agentidentitytrustprotocol` is unaffected (68 passed, 0
failed, 1 skipped) — the fixture-pack runner never touches the file this test reads
directly. This means the nightly drift-canary cron is either already red right now, or
will go red at its next 06:17 UTC run, silently (it only runs `pytest -q` per
`ci.yml:77-81`, and nobody watches a passing repo for a newly-scheduled job going red
until this plan).

A second finding (Phase 2) is a real but currently fixture-invisible divergence between
this codebase's TCT-verification step order and the spec's newly-explicit text. No
conformance fixture distinguishes the two orders today, so nothing is failing — but the
project's own stated mission (an independent implementation whose entire value is
catching exactly this class of spec-vs-code divergence before a second implementation's
fixture does) makes this worth fixing deliberately rather than waiting for a fixture to
force it.

Everything else evaluated in this sync window was traced to ground truth and ruled out.
Recording the "ruled out" reasoning here so a future reader doesn't re-open these:

- **Spec `ec2ff81`** (RFC-AITP-0010 §4.3.1: the session-bundle HTTP `POST`/`GET` body MUST
  be the wrapped transport envelope, not the bare inner object) is a transport-binding
  clarification for an HTTP server endpoint. This repo has no network/HTTP layer
  (README: "No network I/O exists anywhere in this codebase"), and
  `aitp_verifier/sessionbundle.py::verify_session_bundle` already takes the wrapped
  `{"session_bundle": {...}}` shape as its `session_bundle` input — confirmed via the
  passing `bundle-004/005/006` conformance fixtures and
  `tests/test_signed_examples.py::test_session_bundle_signed_example_runs_the_real_verifier`
  (`test_signed_examples.py:191-197`, which explicitly constructs
  `{"session_bundle": body}` before calling in). No code change.
- **aitp-rs `30b673b`** (`REVOCATION_SNAPSHOT_INVALID` for malformed snapshots, not
  `SignatureInvalid`) fixed a bug in `aitp-rs`'s `aitp-transport-http` crate — an
  HTTP-fetch abstraction (`RevocationProvider`/`RevocationCache`) that has no Python
  counterpart in this codebase at all. `aitp_verifier/revocation.py::_validate_shape`
  (`revocation.py:100-141`) already independently raises `REVOCATION_SNAPSHOT_INVALID` for
  every structural defect, confirmed by the passing `rev-007` and `man-006` conformance
  fixtures. No action.
- **aitp-rs `511d4ef`** (adopts spec `ea22c71`: `MANIFEST_INVALID`/`REVOCATION_SNAPSHOT_*`
  codes; identity descriptor gains `extensions`) — already fully present:
  `aitp_verifier/identity.py:61`'s `_IDENTITY_FIELDS` includes `"extensions"`, and the
  `man-004`/`man-006`/`rev-005`/`rev-007` conformance fixtures all pass with the correct
  codes. Already absorbed by `adcd06f`.
- **Spec `f2a7d4d`, `818f146`, `4cfa46a`, `21f2384`** (RFC status-ladder normalization,
  decision-log/errata tracking, a DPoP/token-exchange non-decision, README maintenance
  posture) are docs/governance-only — confirmed via `git show --stat` showing no
  `rfcs/*.md` body content changed beyond `Version`/`Status` headers. No code action.
- **`aitp-control-plane` `2861f13`** and **`aitp-playground`**'s dependency bumps in this
  window are downstream-consumer test hygiene tracking `aitp-rs`'s already-shipped
  0.9–0.12 breaking changes (`UNKNOWN_FIELD`, `MANIFEST_INVALID`, the pinned-key
  timestamp's ASCII-decimal encoding, session-bundle sibling-signature rejection) — all of
  which this repo already independently implements from spec text, predating this sync
  window. No new signal.
- **`registries/error-codes.md`** has not changed since `ea22c71` (`git diff ea22c71 HEAD
  -- registries/error-codes.md` is empty). Codes this repo doesn't implement
  (`REPLAY_DETECTED`, `MANIFEST_NOT_FOUND`, `POP_CHALLENGE_INVALID`/`POP_RESPONSE_INVALID`,
  `INSUFFICIENT_GRANTS`, `INCOMPATIBLE_IDENTITY_TYPE`, `DELEGATION_POP_FAILED`,
  `DELEGATION_INVALID_GRANT_PROOF`) are pre-existing and out of this plan's scope (they
  need state or network I/O this library deliberately doesn't have — a separate,
  intentional scope question, not a regression from this sync window).

## Phases

### Phase 1 — Fix the confirmed `signing_input` regression in the revocation signed-example test

**Status:** DONE. Implemented exactly as planned (allow-list filter, no enumerate-to-remove); no divergence from the planned approach.

**Delivers:** `pytest tests/` passes with 0 failures against the live
`agentidentitytrustprotocol@main` checkout again; the drift canary goes green on its next
run.

**Depends on:** none.

**Files:**
- `tests/test_signed_examples.py` (edit)

**Approach**

Spec commit `4b656b1` added a top-level `"signing_input": "body"` companion key to three
committed fixture files under `schemas/conformance/known-answer/signed-examples/`
(`manifest/kat-keypair-001-manifest.json`, `revocation/kat-keypair-001-snapshot.json`,
`session-bundle/kat-keypair-001-bundle.json`). Per that fixture family's own README (spec
repo, `schemas/conformance/known-answer/signed-examples/README.md`), `signing_input` —
like the pre-existing `_kat_input` and `decoded_claims` — "sit\[s\] beside \[the
artifact\] at the top level of the file" and is explicitly **not** part of the signed
artifact.

Confirmed by reading `tests/test_signed_examples.py` end to end and by running it in
isolation (`pytest tests/test_signed_examples.py -v` → 6 passed, 1 failed, 7 total): the
file has 7 test functions. Two (`test_tct_verifies_and_remints`,
`test_voucher_and_delegation_verify`) read compact-JWS fixture files that never received
the new companion key (it was only added to the three JCS-profile files) and are
unaffected on that basis alone. Of the remaining 5, which do read the 3 affected files,
only one is actually broken —
`test_revocation_signed_example_runs_the_real_verifier` (`test_signed_examples.py:201-217`)
— because it is the only one of the 5 that forwards the *entire loaded fixture dict* into a
real, strictly-checking verifier entry point (`verify_revocation_snapshot`, called with
`"snapshot": snapshot` at line 213-214). It already pops `_kat_input`
(`test_signed_examples.py:206`) for exactly this reason, but was never updated for the new
`signing_input` key, which is a sibling of `revocation_list`/`signature` at the same top
level `_SNAPSHOT_FIELDS` in `aitp_verifier/revocation.py:49` strictly rejects.

The other 4 file-reading functions are unaffected because they either index into a specific
inner key (`wrapped["manifest"]` at `test_signed_examples.py:84`, `wrapped["session_bundle"]`
at line 142) rather than passing the outer dict through, or explicitly reconstruct a minimal
input dict themselves (`test_session_bundle_signed_example_runs_the_real_verifier` builds
`{"session_bundle": body}` from scratch at lines 191-197, never touching the wrapper's
other top-level keys). This was verified directly, not assumed (isolated `-v` run, above) —
re-run `AITP_SPEC=... pytest tests/test_signed_examples.py -v` after the fix and confirm
all 7 pass individually, not just as a net "0 failed".

**Fix, and the "shared helper" question, decided:** Replace the single `.pop("_kat_input",
None)` call at `test_signed_examples.py:206` with an explicit allow-list filter over the
one affected variable, immediately before the `verify_revocation_snapshot` call:

```python
snapshot = {k: v for k, v in snapshot.items() if k in ("revocation_list", "signature")}
```

This is chosen over (a) adding a second ad hoc `.pop("signing_input", None)` line, and
over (b) introducing a new shared "companion-key-stripping" helper/module. Rejected (a)
because it repeats the exact bug shape: a third companion key added by a future spec
commit would silently reintroduce this failure the same way `signing_input` just did —
an enumerate-what-to-remove list is inherently incomplete against additions. Rejected (b)
as over-engineering: this is the *only* call site in the entire test suite that forwards a
whole loaded signed-example fixture into a real verifier (confirmed by grepping every
`tests/*.py` for the `_kat_input`/`decoded_claims`/`signing_input` companion-key handling
pattern — it is unique to this one function). A module-level abstraction for a single call
site adds indirection without preventing recurrence any better than the allow-list filter
does, and the allow-list is self-documenting at the point of use (it states exactly what
`verify_revocation_snapshot`'s real wire contract is: `revocation_list` + `signature`,
nothing else) — an enumerate-what-to-remove list does not.

**Edge cases & failure modes**

- If a *fourth* companion key is ever added to this fixture file, the allow-list filter
  silently continues to work (it keeps only the two real fields) — this is the specific
  property the enumerate-what-to-remove approach lacks, and the reason this approach was
  chosen.
- If `revocation_list` or `signature` themselves were ever removed from the fixture file
  (a real defect, not new metadata), the filtered dict would be missing a required key and
  `verify_revocation_snapshot`'s own `_validate_shape` (`revocation.py:116-117`) would
  correctly raise `REVOCATION_SNAPSHOT_INVALID` — the allow-list doesn't mask that class of
  bug, it only strips *known-extra* metadata.
- The manifest and session-bundle signed-example tests are not touched by this phase
  (confirmed unaffected above) — do not preemptively "fix" them; that would be scope creep
  against nothing that's broken. If a future spec change adds a companion key that a
  manifest/session-bundle test *does* forward wholesale, address it then, following this
  phase's pattern (allow-list, not enumerate-to-remove).

**Acceptance criteria**

- `AITP_SPEC=/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol /tmp/aitpvenv313/bin/python -m pytest tests/ -q` reports `0 failed`.
- `test_revocation_signed_example_runs_the_real_verifier` specifically passes when run in
  isolation (`pytest tests/test_signed_examples.py::test_revocation_signed_example_runs_the_real_verifier -v`).
- No other test in `test_signed_examples.py` changes behavior (diff the full `-v` output
  before/after; every other test's PASS/FAIL status is identical).
- `run_conformance.py --spec-dir ../agentidentitytrustprotocol` still reports `0 failed`
  (it already does; this phase must not regress it).
- `mypy` (`/tmp/aitpvenv313/bin/python -m mypy`) remains clean.

**Tests**

- The existing `test_revocation_signed_example_runs_the_real_verifier` is the regression
  test — no new test needed, since the fixture file itself (already vendored via
  `--spec-dir`) is what exercises the new `signing_input` key. Confirm this test fails
  before the fix and passes after (`git stash` the fix, re-run, `git stash pop`) as the
  before/after proof.

**Docs:** None. This is a test-only fix; no public contract, README claim, or docstring
described the pre-fix behavior as correct.

---

### Phase 2 — Align TCT claims-membership check with RFC-AITP-0005 §7.2's explicit sub-step order

**Status:** DONE. Implemented as planned (the `after_typ_check` callback on `verify_jws`, the shared `check_tct_claims_shape` helper, all three call sites). One divergence from the plan's literal text: the session-bundle combined-defect test landed in `tests/test_sessionbundle.py` (as `test_participant_tct_combined_unknown_claim_and_bad_alg_reports_bundle_code`) instead of `tests/test_unknown_fields.py` as the plan's Tests section named — that file already had the exact fixture-minting/`tct_claims`/`__JWS_TCT_WRONG_ALG__` machinery this test needs (mirroring its own existing `test_participant_tct_claims_unknown_field_rejected`), which `test_unknown_fields.py` does not. A fresh-Opus verifier confirmed this was a reasonable call, not a gap.

**Delivers:** `verify_tct`, the handshake's embedded-TCT check, and the session bundle's
embedded participant-TCT check all run the claims-membership check between `typ` and
`alg`-pin, matching the spec's now-literal "segment-parse → typ → claims-membership →
alg-pin → signature" order (RFC-AITP-0005 §7.2 step 1, spec commit `993da8c`). A regression
test pins this order so a future refactor can't silently regress it back.

**Depends on:** Phase 1 (independent in principle — different files, no shared code path —
but sequenced after Phase 1 so the verification gate always runs against a fully-green
baseline; do not parallelize the two against a red baseline).

**Files:**
- `aitp_verifier/jws.py` (edit — `verify_jws`, `jws.py:70-101`)
- `aitp_verifier/tct.py` (edit — `verify_tct`, `tct.py:34-45`; add the shared claims-shape
  helper)
- `aitp_verifier/handshake.py` (edit — `_verify_commit`, `handshake.py:134-140`)
- `aitp_verifier/sessionbundle.py` (edit — the per-participant TCT check,
  `sessionbundle.py:153-182`; see the third call site below)
- `tests/test_unknown_fields.py` (new tests; see Tests below — not a new file, see the
  "test home" correction below)

**Approach**

Confirmed by reading `rfcs/RFC-AITP-0005-tct.md` at spec commit `993da8c`: step 1's
closing sentence is now explicit — "Full execution order: this step's segment-parsing,
then step 2 \[`typ` enforcement\], then this step's claims-membership clause, then steps
3–4 \[`alg`-pin, signature verification\]." This is TCT-specific: the equivalent sections
of RFC-AITP-0005 §8 (grant voucher) and RFC-AITP-0006/RFC-AITP-0011 (delegation) carry no
matching explicit sub-step language (confirmed: `grep -n "MUST, in order\|verification
order" rfcs/RFC-AITP-0006-delegation.md rfcs/RFC-AITP-0011-multihop-delegation.md` returns
nothing), so this fix's scope is deliberately narrow — it must not change
`aitp_verifier/voucher.py` or the non-embedded-TCT parts of `aitp_verifier/delegation.py`,
whose current crypto-then-shape order remains spec-correct for those artifacts.

Today, `verify_jws` (`jws.py:70-101`) runs segment-parse → header-exact-check → `typ` →
`alg`-pin → signature, entirely internally, and returns claims only once every one of
those has passed. `tct.py:44-45` and `handshake.py:137-138` then call
`reject_unknown_fields` on the *already-signature-verified* claims. The net order actually
executed today is parse → typ → alg → signature → claims-membership — the opposite of
steps 3–4 vs. the claims-membership clause. This is unobservable by any existing fixture:
`tct-010` (the one order-pinning fixture in the pack) only exercises typ-vs-claims-
membership, which already passes, because `verify_jws` raises `TOKEN_TYP_MISMATCH`
internally (`jws.py:91-92`) before alg/signature are ever reached, let alone before claims
are returned for the membership check. Concretely demonstrable divergence: a TCT with a
correct `typ`, one unrecognized claim, *and* a wrong `alg` (or an invalid signature) would
today report `TOKEN_ALG_MISMATCH` (or `TCT_SIGNATURE_INVALID`) — under the spec's literal
order it must report `UNKNOWN_FIELD` instead, since the claims-membership check runs
before the alg/signature steps are reached at all.

**Chosen approach: extend `verify_jws` with an optional callback invoked right after the
`typ` check, before the `alg`-pin.**

```python
def verify_jws(
    token: str,
    *,
    iss_aid: str,
    expected_typ: str,
    typ_err: str,
    alg_err: str,
    sig_err: str,
    after_typ_check: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    ...
    if parsed.header.get("typ") != expected_typ:
        raise AitpError(typ_err, ...)

    if after_typ_check is not None:
        after_typ_check(parsed.claims)

    aid = parse_aid(iss_aid)
    if parsed.header.get("alg") != aid.jose_alg:
        raise AitpError(alg_err, ...)
    ...
```

`tct.py::verify_tct`, `handshake.py::_verify_commit`, and `sessionbundle.py`'s
per-participant TCT check all pass `after_typ_check=lambda claims:
_check_tct_claims_shape(claims, shape_code=...)`, where `_check_tct_claims_shape` performs
both the existing top-level `TCT_CLAIM_FIELDS` check and the nested `cnf`-object
`TCT_CNF_FIELDS` check that today run after `verify_jws` returns (`tct.py:45-47`,
`handshake.py:138-140`, `sessionbundle.py:176-178`) — both are grouped under the same
"parse strictly" step in the RFC text, so moving them together, in the same relative order
between each other, preserves everything the spec pins while moving the pair earlier.
Extract this shared claims-shape check into one function in `tct.py` (exported alongside
`TCT_CLAIM_FIELDS`/`TCT_CNF_FIELDS`, which both `handshake.py` and `sessionbundle.py`
already import from `tct.py` — `handshake.py:31`, `sessionbundle.py:52`) so the three call
sites can't drift from each other, the same duplication-avoidance rationale `fields.py`'s
own module docstring already states for why `reject_unknown_fields` lives in one place.

**Third call site, found during review and folded in:** `sessionbundle.py:153-182`
verifies each participant's embedded TCT with the identical `verify_jws`-then-
`reject_unknown_fields` pattern (lines 155-159, then 176-178), and its own inline comment
(160-174) explicitly states "RFC-AITP-0010 §5 step 7 runs the standard RFC-AITP-0005 §7.2
order over each participant token" — so this module's own documented intent is the
spec-literal order, making the same restructuring correct here too, not merely consistent.
One nuance that does NOT change the fix but is worth recording: `sessionbundle.py` already
collapses `typ_err`/`alg_err`/`sig_err` (155-158) and remaps `UNKNOWN_FIELD` via a
try/except (175-182) to a single shared code, `BUNDLE_PARTICIPANT_TCT_INVALID` — so the
*externally observable* error code for the combined-defect case is unaffected by this
phase for this module specifically (it was, and remains, `BUNDLE_PARTICIPANT_TCT_INVALID`
either way). The fix is still correct to make here: it makes the code's actual execution
order match what the module's own docstring already claims it does, and it means a future
change that un-collapses these codes (e.g. if RFC-AITP-0010 ever gives the claims-membership
failure its own bundle-scoped code) inherits the right order instead of silently inheriting
this same bug a second time.

**Rejected alternatives:**
- *Splitting `verify_jws` into two public functions* (`parse_and_check_typ`, then
  `check_alg_and_signature`) was rejected: it would force every one of `voucher.py`'s and
  `delegation.py`'s call sites (5 call sites: `voucher.py:31`, `delegation.py:64,90,143,175`,
  per the `verify_jws(` grep) to change their call shape for no behavioral reason, for a
  requirement scoped to three call sites across two RFCs (TCT proper, and the two embedded-TCT
  reuses in the handshake and session bundle). A single optional keyword argument, defaulted
  to `None`, changes nothing for those 5 call sites and needs no changes to `voucher.py` or
  the non-embedded parts of `delegation.py` at all.
- *Leaving the order as-is and only documenting the deviation* was rejected: the module's
  entire raison d'être (README: implemented independently from the RFC text specifically
  so cross-implementation divergences are caught) argues against knowingly leaving an
  RFC-literal MUST unimplemented once identified, even absent a failing fixture — and the
  fix is a small, contained, backward-compatible signature addition, not a risky rewrite.

**Edge cases & failure modes**

- A TCT with *both* an unrecognized claim and a `typ` mismatch must still report
  `TOKEN_TYP_MISMATCH` (typ is checked first, unchanged) — assert this explicitly in the
  new test as the negative control, so the fix doesn't accidentally invert typ-vs-
  membership ordering while fixing membership-vs-alg/sig ordering.
  order.
- A TCT with an unrecognized claim and a *valid* signature/alg (no other defect) must
  still report `UNKNOWN_FIELD` exactly as before (this is `tct-011`, already passing) —
  confirm it's unaffected since it never reaches the alg/signature branch either way.
- `handshake.py`'s embedded-TCT check has no separate `verify_tct` call — it duplicates
  the logic inline because it needs the raw `claims` dict afterward for handshake-specific
  checks (`aud`, `exp`, `cnf.jkt`, `GRANT_OVERFLOW` against `issuer_offered_capabilities`)
  that `verify_tct` doesn't expose in its return shape (`verify_tct` returns only
  `{"grants": ...}`, `tct.py:69`). Do not attempt to collapse `_verify_commit` into calling
  `verify_tct` as part of this phase — that is a larger refactor with its own risk surface
  (e.g. `verify_tct`'s revocation-snapshot and Manifest-expiry-bound checks, which
  `_verify_commit` deliberately does not run) and is out of scope; only the shared
  claims-shape helper is extracted, not the whole verification path.
- `mypy --strict` must accept the new `Callable[[dict[str, Any]], None] | None` parameter
  type on `verify_jws` — import `Callable` from `typing`, matching this codebase's existing
  precedent for an identically-shaped optional callback parameter:
  `aitp_verifier/minter.py:207`'s `sign_override: Callable[[bytes], bytes] | None = None`
  (imported at `minter.py:18` as `from typing import Any, Callable, cast`; also
  `aitp_verifier/verify.py:10,16`). Do not use `collections.abc.Callable` — it would be the
  only such import in the package and would deviate from the established convention for no
  benefit.

**Acceptance criteria**

- New test: a synthetic TCT signed with a *valid* signature under the correct issuer key,
  whose claims carry one unrecognized field (e.g. `device_id`, mirroring `tct-011`'s
  fixture) **and** whose header `alg` does not match the issuer AID's pinned algorithm (or
  whose signature bytes are corrupted) — `verify_tct` must raise `AitpError("UNKNOWN_FIELD",
  ...)`, not `TOKEN_ALG_MISMATCH` / `TCT_SIGNATURE_INVALID`.
- The same combined-defect case, run through `handshake.py`'s embedded-TCT path (a
  `mutual_commit` payload carrying this TCT), must also raise `UNKNOWN_FIELD`.
- The same combined-defect case, run through `sessionbundle.py`'s per-participant TCT path
  (a bundle whose one participant carries this TCT), must raise
  `BUNDLE_PARTICIPANT_TCT_INVALID` (unchanged code, per the collapse noted above) — assert
  this explicitly so the collapse is proven intentional and stable, not merely unbroken by
  accident.
- `tct-010` and `tct-011` (existing conformance fixtures) still pass unchanged.
- Full `run_conformance.py --spec-dir ../agentidentitytrustprotocol`: `0 failed`.
- Full `pytest tests/`: `0 failed`.
- `mypy --strict`: clean.
- `voucher.py` and `delegation.py`'s non-embedded-TCT verification paths are byte-for-byte
  unchanged (no diff in those files' logic; `verify_jws` calls there pass no
  `after_typ_check`, so their behavior is provably identical, not just tested-identical).

**Tests**

- **Test home, corrected:** `tests/test_unknown_fields.py`, not a new file. It already
  has exactly the right scaffolding for this — `_tct_claims()` (line 118), `load_kat_keys`/
  `encode_jws` for hand-minting a signed TCT with an arbitrary claim override (the same
  pattern `test_tct_unknown_claim_rejected`, line 134, already uses), and an established
  precedent for pinning cross-defect *precedence* rather than single-defect rejection:
  `test_revocation_unknown_field_yields_to_a_structural_defect` (line 690). `test_kat.py`
  was considered and rejected — it never imports or calls `verify_jws`/`verify_tct` at all
  (confirmed by grep; it only reads `known-answer/jcs-sha256.json` KAT vectors), so it has
  no fitting precedent for this test shape.
- New, added to `tests/test_unknown_fields.py`'s TCT-claims section (near line 134):
  - `test_tct_unknown_claim_and_bad_alg_reports_unknown_field` — the combined-defect case
    (valid signature, one unrecognized claim, `alg` header not matching the issuer AID's
    pinned algorithm) via `verify_tct`; asserts `UNKNOWN_FIELD`, not `TOKEN_ALG_MISMATCH`.
  - `test_tct_unknown_claim_and_bad_alg_reports_unknown_field_via_handshake` — the same
    combined-defect TCT, embedded in a `mutual_commit` payload, via
    `verify_handshake_payload`; asserts `UNKNOWN_FIELD`.
  - `test_tct_unknown_claim_and_bad_alg_reports_bundle_code_via_sessionbundle` — the same
    combined-defect TCT, embedded as a bundle participant, via `verify_session_bundle`;
    asserts `BUNDLE_PARTICIPANT_TCT_INVALID` (the collapse case — see Acceptance criteria).
  - `test_tct_typ_mismatch_still_wins_over_unknown_claim` — negative control: `typ` wrong
    *and* claims carry an unrecognized field ⇒ still `TOKEN_TYP_MISMATCH` (already covered
    at the fixture level by `tct-010`, but add a direct unit-level assertion here since
    Phase 2 is specifically about ordering and this is the other half of the ordering
    contract this phase must not invert).
- Existing: full `pytest tests/` and `run_conformance.py` runs, per Acceptance criteria.

**Docs:** Update `aitp_verifier/tct.py`'s module docstring (`tct.py:1-9`), which currently
states the check order as "strict compact-JWS parse → `typ` → AID-pinned `alg` → signature
→ claims" — this line becomes stale the moment this phase lands and must be corrected in
the same commit to "strict compact-JWS parse → `typ` → claims (shape) → AID-pinned `alg` →
signature → claims (semantic: `ver`, `aud`, `exp`, `cnf.jkt` binding)" or equivalent,
naming RFC-AITP-0005 §7.2's now-explicit sub-step order. No `README.md` change needed (it
doesn't describe verification order at this granularity).

---

### Phase 3 — Full-suite verification gate

**Status:** TODO

**Delivers:** Confirmation that Phases 1 and 2 together leave the repo in the same state
CI will independently confirm on its next run — this phase exists so a human/reviewer has
one place that states the whole-feature acceptance bar, distinct from each phase's own
local gate.

**Depends on:** Phase 1, Phase 2.

**Files:** None (verification only; no source changes).

**Approach:** Re-run, in order, against the live spec checkout:

```
cd /Users/Shared/agentIdenitytrustprotocol/aitp-verifier-py
AITP_SPEC=/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol \
  /tmp/aitpvenv313/bin/python run_conformance.py --spec-dir ../../agentidentitytrustprotocol
AITP_SPEC=/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol \
  /tmp/aitpvenv313/bin/python -m pytest tests/ -v
/tmp/aitpvenv313/bin/python -m mypy
```

(Note: `run_conformance.py --spec-dir` is relative to the CWD, not `AITP_SPEC` — pass the
correct relative or absolute path; `tests/conftest.py`'s `spec_dir` fixture resolves via
`$AITP_SPEC` first per its own docstring, so both must point at the same checkout to avoid
a confusing split-brain result.)

This mirrors exactly what `.github/workflows/ci.yml`'s `conformance` job does
(`ci.yml:74-84`), so a clean local run here is strong evidence CI's next run (including the
06:17 UTC drift-canary cron) goes green too — the one thing this whole plan exists to
restore before that cron fires again.

**Edge cases & failure modes:** If the spec repo moves again between when this plan is
written and when Phase 3 runs (it floats on `main`), re-diff `git log` in
`agentidentitytrustprotocol` against `ea22c71`/`4b656b1`/`993da8c` before treating a new
failure as this plan's responsibility — it may be a further, out-of-plan drift that needs
its own triage, not a sign Phase 1/2 were done wrong.

**Acceptance criteria:**
- `run_conformance.py`: `N passed, 0 failed, 1 skipped` (N ≥ 68). The one expected skip is
  `del-004` (frozen in the retired v0.1 wire shape, per README) — confirmed by an actual
  run's fixture list, not by the README alone: `mh-002` is listed in the README as a second
  documented skip, but a live run today shows `mh-002` PASSES (it is not absent from the
  pass list) and only `del-004` is missing from it, so the README's "two fixtures skipped"
  claim is itself stale. That staleness predates this sync window and is out of this plan's
  scope to fix (it's a doc correction in this repo's own README, not a spec-drift item) —
  noted here only so Phase 3 checks the right fixture ID and doesn't mistake a live,
  correct `mh-002` pass for a regression. Do not treat any *other* change in skip count or
  skip identity as automatically fine without checking why.
- `pytest tests/ -v`: every test passes, `0 failed`.
- `mypy`: `Success: no issues found`.

**Tests:** N/A — this phase *is* the test-running gate for the other two.

**Docs:** None.

## Long-term posture

No one-way doors in this plan. Phase 1 is a test-only fix against fixture metadata that
was always documented as non-signed. Phase 2 adds one optional, backward-compatible
keyword parameter to an internal (non-`__all__`-exported-as-public-API-in-practice, but
still importable) function — `verify_jws` is exported via `jws.py`'s `__all__` and used
externally by `tests/test_signed_examples.py` and `tests/test_kat.py` directly with
keyword arguments only, so an additional optional keyword-only parameter is additive and
non-breaking for any current caller, internal or external to this package.

The one thing worth pricing explicitly: this repo's floating-on-`main` CI posture
(deliberate, per `ci.yml`'s own comment) means this exact class of drift — a spec commit
that adds fixture metadata or clarifies an execution order — will recur. This plan fixes
the two known instances; it does not add a structural guard against the next one. That
guard (e.g., a lint/test that fails loudly whenever a *new* top-level key appears in a
signed-example fixture file that isn't in a known-allowed set, forcing a human decision
about whether it's inert metadata or a real behavioral change) was considered and
deliberately deferred — it's a genuinely separate, larger piece of work (designing what
"known top-level metadata key" means generically across all three signed-example families,
not just revocation) that would expand this plan's scope well beyond "absorb the last 3.5
weeks of drift." Flagged here as a real gap, not silently dropped.

## Enterprise concerns

- **Observability:** The existing daily cron (`ci.yml:14-20`) already is the production
  observability story for this repo's core risk (spec drift silently breaking a
  floating-main consumer) — this plan restores it to a truthful signal rather than adding
  a new mechanism. No new alerting/dashboarding is in scope.
- **Reliability / blast radius:** Both phases touch only verification logic exercised by
  this repo's own test suite and conformance runner — there are no external callers of
  this package published (per `pyproject.toml`, "3 - Alpha", not yet on PyPI), so there is
  no deployed-consumer blast radius to manage for this change.
- **Rollback:** Both phases are ordinary code commits with full test coverage; rollback is
  `git revert`, no data migration or external state involved anywhere in this library.

## Open questions

- **Phase 1's allow-list-filter vs. a broader companion-key convention** — decided above
  (allow-list, no shared module) as a consequential-but-decidable call; recorded here per
  the autonomy ladder, not escalated. Revisit only if a third companion key surfaces and a
  second call site is affected by it — at that point a shared helper becomes justified by
  actual duplication rather than anticipated duplication.
- **Phase 2's `Callable` parameter naming (`after_typ_check`)** — a naming choice, not a
  contract question; `/implement` may rename it during execution if a clearer name
  surfaces while writing the code, without needing to re-open this plan.
- **Whether to also fix `voucher.py`/`delegation.py`'s crypto-then-shape order** even
  though their governing RFC sections don't (yet) carry the same explicit sub-step
  language — deliberately **not** done in this plan (confirmed via direct grep: no
  matching order text exists for those RFCs today). If a future spec commit adds
  equivalent explicit ordering language there, that is new-window work for a future sync
  plan, not retroactively part of this one.
- No genuine one-way-door / critical decision surfaced in this sync window (no schema
  shape change, no auth-model change, no cross-repo write) — Fable was not engaged, per
  the autonomy ladder; both phases are internal, reversible, unpublished-package changes.

## Repo map

(See `PROGRESS.md` for the persisted version `/implement` reads.)

- `aitp_verifier/jws.py` — the shared compact-JWS parse/verify primitive (`parse_compact`,
  `verify_jws`, `encode_jws`) every JWS-based artifact (TCT, grant voucher, delegation,
  handshake's embedded TCT) calls through. Phase 2's extension point.
- `aitp_verifier/tct.py` — `verify_tct`: TCT verification entry point (RFC-AITP-0005
  §7.2/§10). Owns `TCT_CLAIM_FIELDS`/`TCT_CNF_FIELDS`, which `handshake.py` also imports.
  Phase 2's primary edit site.
- `aitp_verifier/handshake.py` — `verify_handshake_payload` (RFC-AITP-0004): bootstrap
  (`mutual_hello[_ack]`) and commit (`mutual_commit[_ack]`) message verification.
  `_verify_commit` (`handshake.py:108-152`) duplicates `tct.py`'s claims-verification
  pattern inline for the embedded peer-issued TCT. Phase 2's second edit site.
- `aitp_verifier/sessionbundle.py` — `verify_session_bundle` (RFC-AITP-0010 §5). Its
  per-participant TCT check (lines 153-182) is a third instance of the same
  `verify_jws`-then-`reject_unknown_fields` pattern, and its own comment (160-174) states
  it follows "the standard RFC-AITP-0005 §7.2 order" — found during plan review, folded
  into Phase 2 as a third call site. `UNKNOWN_FIELD` is remapped to
  `BUNDLE_PARTICIPANT_TCT_INVALID` at this call site only (fields.py's docstring names this
  as the one exception to the shared `UNKNOWN_FIELD` code), so the externally observable
  code for this module doesn't change even though the internal order does.
- `aitp_verifier/revocation.py` — `verify_revocation_snapshot` (RFC-AITP-0008 §1.5).
  `_SNAPSHOT_FIELDS`/`_BODY_FIELDS`/`_ENTRY_FIELDS` (lines 49-51) are the strict member
  sets Phase 1's fixture-metadata leak hits.
  `_validate_shape` (100-141) already correctly separates `REVOCATION_SNAPSHOT_INVALID`
  (structural) from `REVOCATION_SNAPSHOT_SIGNATURE_INVALID` (crypto) — confirmed already
  correct, not part of this plan's changes.
  `aitp_verifier/fields.py` — `reject_unknown_fields`, the single shared implementation of
  RFC-AITP-0001 §7's unknown-field rule, used by every artifact module. Not modified by
  this plan; Phase 2 reuses it inside the new shared claims-shape helper.
  `aitp_verifier/identity.py` — `_IDENTITY_FIELDS` (line 61) already includes
  `"extensions"`; confirmed already-absorbed, no changes.
  `aitp_verifier/manifest.py`, `aitp_verifier/voucher.py`, `aitp_verifier/delegation.py` —
  read for this plan's ruled-out items; no changes (voucher.py/delegation.py's own
  non-embedded verify_jws call sites are deliberately not touched by Phase 2 either — see
  its Approach).
  `tests/test_signed_examples.py` — Phase 1's edit site (`_se` fixture loader at lines
  24-26; 7 test functions total at lines 29-217; the specific broken one at 201-217).
  `tests/test_unknown_fields.py` — Phase 2's test home (corrected during review from an
  originally-proposed new file): `_tct_claims()` (line 118) and the
  `load_kat_keys`/`encode_jws` hand-minting pattern (`test_tct_unknown_claim_rejected`,
  line 134) are the right scaffolding; `test_revocation_unknown_field_yields_to_a_structural_defect`
  (line 690) is the precedent for pinning cross-defect precedence, which is exactly Phase
  2's new tests' shape.
  `tests/test_kat.py` — does NOT call `verify_jws`/`verify_tct` (confirmed by grep); only
  reads `known-answer/jcs-sha256.json`'s own pre-declared `signing_input` values (line 85).
  Considered and rejected as Phase 2's test home for this reason.
  `run_conformance.py` — the fixture-pack runner; unaffected by either phase's fix
  (confirmed: 68 passed / 0 failed / 1 skipped both before and after Phase 1 in isolation).
  `.github/workflows/ci.yml` — `conformance` (lines 40-84), `floors` (95-146),
  `cross-platform` (162-207), `wheel-smoke-test` (218-282) jobs; the `schedule: cron: "17
  6 * * *"` drift canary (14-20) is what this whole plan exists to keep truthful.
- **Sibling repos** (read-only signal sources for this plan, not touched):
  `/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol` (spec, checked out
  at whatever `main` is at plan-write time — re-check `git log` before Phase 3 if time has
  passed), `aitp-rs`, `aitp-control-plane`, `aitp-playground`.
- **Verification venv:** `/tmp/aitpvenv313` (python3.13, package installed editable with
  `[dev]` extras) — the system `python3` is 3.9.6 and too old for this package's
  `requires-python = ">=3.11"`; use the venv for every phase's local verification.

## Plan review

**Round 1:** REVISE → applied. A fresh Plan-agent review (read-only — it lacked write
access to the plan file, so it reported findings rather than applying them; findings
applied above by the drafting session instead) re-verified every `file:line` citation
against the actual source and re-ran both `pytest tests/ -q` and `run_conformance.py`
against the live spec checkout, reproducing the same `1 failed, 161 passed` /
`68 passed, 0 failed, 1 skipped` split this plan opens with, and independently confirmed
the RFC-AITP-0005 §7.2 quote and the RFC-0006/0011 grep-returns-nothing claim. Findings,
and what changed:

- **Function-count error** in Phase 1's Approach: "6 functions... 5 unaffected" was wrong.
  `test_signed_examples.py` has 7 test functions; 2 never read the affected files at all,
  5 do, and of those 5 only 1 is broken. Corrected.
- **Missing third call site**: `sessionbundle.py:153-182`'s per-participant TCT check has
  the identical ordering bug, and its own comment explicitly claims it already runs "the
  standard RFC-AITP-0005 §7.2 order" — confirmed by reading the file. Folded into Phase 2's
  Files, Approach, Edge cases, Acceptance criteria, and Tests, including the nuance that
  this module's own `UNKNOWN_FIELD`→`BUNDLE_PARTICIPANT_TCT_INVALID` remap means the fix
  changes internal order without changing this module's externally observable code.
- **Call-site miscount**: "7 call sites across voucher.py/delegation.py" corrected to the
  actual grep result (5: `voucher.py:31`, `delegation.py:64,90,143,175`).
- **False claim** that `tests/test_kat.py` calls `verify_jws` — it doesn't (confirmed by
  grep); removed as a candidate test home.
- **Wrong `Callable` import guidance** — corrected from `collections.abc.Callable` to
  `typing.Callable`, matching the actual existing precedent (`minter.py:207`'s
  `sign_override: Callable[[bytes], bytes] | None = None`).
- **Phase 3's skip-fixture claim was backward** — `del-004` is the one live skip; `mh-002`
  (which the README separately claims is skipped) actually passes today. Corrected, with a
  note that the README's own staleness here is out of this plan's scope.
- **Better test home identified**: `tests/test_unknown_fields.py` already has the right
  helpers (`_tct_claims`, `load_kat_keys`/`encode_jws`) and an existing precedent for
  cross-defect precedence tests (`test_revocation_unknown_field_yields_to_a_structural_defect`)
  — adopted in place of a new `tests/test_tct_order.py` file.
- The `after_typ_check` callback design itself was independently judged sound (confirmed
  against the `minter.py` precedent) — the review's findings were about scope completeness
  and citation accuracy, not the core approach.

No second review round was run: every finding above was a concrete, independently-verified
correction (not an ambiguity), so it was applied directly per the autonomy ladder's
"consequential but decidable" tier rather than re-queued for a second pass.
