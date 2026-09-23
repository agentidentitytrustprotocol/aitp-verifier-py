# PROGRESS

Tracking file for `plans/spec-sync-2026-09.md`. `/implement` reads this instead of
re-scanning the repo from scratch.

## Repo map

- `aitp_verifier/jws.py` — shared compact-JWS parse/verify primitive (`parse_compact`,
  `verify_jws`, `encode_jws`). Every JWS artifact (TCT, grant voucher, delegation,
  handshake's embedded TCT) calls `verify_jws`. Phase 2 extension point (adds an optional
  `after_typ_check` callback).
- `aitp_verifier/tct.py` — `verify_tct`, TCT verification entry point (RFC-AITP-0005
  §7.2/§10.4). Owns `TCT_CLAIM_FIELDS`/`TCT_CNF_FIELDS` (imported by `handshake.py`).
  Phase 2 primary edit site; module docstring at lines 1-9 states check order and goes
  stale once Phase 2 lands.
- `aitp_verifier/handshake.py` — `verify_handshake_payload` (RFC-AITP-0004).
  `_verify_commit` (lines 108-152) duplicates the TCT claims-verification pattern inline
  (lines 134-140) for the embedded peer-issued TCT in `mutual_commit[_ack]`. Phase 2
  second edit site. Deliberately does NOT call `tct.py::verify_tct` (different return
  shape/check set) — do not collapse the two as part of Phase 2.
- `aitp_verifier/sessionbundle.py` — `verify_session_bundle` (RFC-AITP-0010 §5). Third
  Phase 2 edit site (found during plan review): per-participant TCT check at lines
  153-182 duplicates the same pattern a third time; its own comment (160-174) claims it
  already runs "the standard RFC-AITP-0005 §7.2 order". `UNKNOWN_FIELD` is remapped to
  `BUNDLE_PARTICIPANT_TCT_INVALID` at this call site (try/except, lines 175-182), so
  fixing the internal order does not change this module's externally observable codes.
- `aitp_verifier/revocation.py` — `verify_revocation_snapshot` (RFC-AITP-0008 §1.5).
  `_SNAPSHOT_FIELDS`/`_BODY_FIELDS`/`_ENTRY_FIELDS` (lines 49-51) are the strict member
  sets Phase 1's fixture-metadata leak (`signing_input`) hits via `reject_unknown_fields`
  at line 156. `_validate_shape` (100-141) already correctly distinguishes
  `REVOCATION_SNAPSHOT_INVALID` (structural) from `REVOCATION_SNAPSHOT_SIGNATURE_INVALID`
  (crypto) — already correct, not part of this plan's edits.
- `aitp_verifier/fields.py` — `reject_unknown_fields`, the single shared implementation of
  RFC-AITP-0001 §7's unknown-field rule. Not modified by this plan; Phase 2 reuses it
  inside a new shared claims-shape helper in `tct.py`.
- `aitp_verifier/identity.py` — `_IDENTITY_FIELDS` (line 61) already includes
  `"extensions"` (spec `ea22c71`, already absorbed by commit `adcd06f`). No changes.
- `aitp_verifier/sessionbundle.py`, `manifest.py`, `voucher.py`, `delegation.py` — read
  for this plan's ruled-out items (session-bundle HTTP wrapping is transport-only;
  manifest/revocation structural codes already correct). No changes in this plan.
- `tests/test_signed_examples.py` — Phase 1 edit site. `_se()` fixture loader (lines
  24-26); 6 signed-example test functions (29-217); the broken one is
  `test_revocation_signed_example_runs_the_real_verifier` (201-217), which forwards the
  whole loaded fixture dict into `verify_revocation_snapshot` and is the only one of the 6
  that does so (the other 5 index into a specific inner key or reconstruct a minimal input
  dict themselves).
- `tests/test_kat.py` — already reads `known-answer/jcs-sha256.json`'s own
  `signing_input` declarations (line 85). Check whether Phase 2's new order-regression
  test fits here before creating a new `tests/test_tct_order.py`.
- `tests/conftest.py` — `spec_dir` fixture; resolution order `$AITP_SPEC` env var, then a
  sibling-directory search (line ~16, ~33).
- `run_conformance.py` — fixture-pack runner. Unaffected by either phase's fix (68
  passed / 0 failed / 1 skipped, confirmed before Phase 1 too — the bug Phase 1 fixes is
  only reachable via the direct-fixture-forwarding pytest test, not the fixture-pack
  runner's own input construction).
- `.github/workflows/ci.yml` — `conformance` job (lines 40-84) is what Phase 3 mirrors
  locally. `schedule: cron: "17 6 * * *"` (lines 14-20) is the drift canary this whole
  plan exists to keep truthful; see its own explanatory comment at lines 7-13 for why the
  spec is intentionally unpinned.
- `pyproject.toml` — `requires-python = ">=3.11"`; the floor dependency is
  `cryptography>=50.0`. Not touched by this plan.

## Sibling repos (read-only signal sources, not touched by this plan)

- `/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol` — the spec.
  Sync point for this plan: commit `ea22c71` (2026-08-30, already absorbed) through
  `4b656b1` (2026-09-20, HEAD as of plan-write time). Re-check `git log` before Phase 3
  if significant time has passed — this repo floats on `main`.
- `/Users/Shared/agentIdenitytrustprotocol/aitp-rs` — reference Rust implementation.
  Commits through `c7814a5` (2026-09-23) reviewed; `511d4ef` (spec `ea22c71` adoption)
  and `30b673b` (`REVOCATION_SNAPSHOT_INVALID` fix) both ruled out as already-covered /
  not-applicable — see plan Context section for why.
- `/Users/Shared/agentIdenitytrustprotocol/aitp-control-plane`,
  `/Users/Shared/agentIdenitytrustprotocol/aitp-playground` — downstream TS/Python
  consumers. Reviewed for signal only; nothing in this window added new requirements
  beyond what the spec repo itself already states.

## Verification environment

`/tmp/aitpvenv313` — python3.13 venv, `aitp-verifier-py` installed editable with `[dev]`
extras (`pytest`, `mypy`). The system `python3` is 3.9.6 (too old; `requires-python
= ">=3.11"`) with an ancient `pip` — do not use it. Recreate if needed:

```
/opt/homebrew/bin/python3.13 -m venv /tmp/aitpvenv313
/tmp/aitpvenv313/bin/pip install -q -e ".[dev]"
```

Standard verification command (both phases and Phase 3's gate):

```
cd /Users/Shared/agentIdenitytrustprotocol/aitp-verifier-py
AITP_SPEC=/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol \
  /tmp/aitpvenv313/bin/python run_conformance.py --spec-dir ../agentidentitytrustprotocol
AITP_SPEC=/Users/Shared/agentIdenitytrustprotocol/agentidentitytrustprotocol \
  /tmp/aitpvenv313/bin/python -m pytest tests/ -v
/tmp/aitpvenv313/bin/python -m mypy
```

Do not touch `.mypy_cache/`, `build/`, or `aitp_verifier.egg-info/` — build/cache
artifacts, not source.

## PR strategy

One PR at the end, covering Phases 1 and 2 (Phase 3 is a verification gate only, no
separate diff). Why: both phases are small (a test fix; one optional-parameter addition
plus 3 call-site edits), touch the same conceptual feature ("absorb this sync window's
spec drift"), and neither is independently useful to ship alone ahead of the other — a
reviewer gets more value seeing the confirmed-broken-test fix and the spec-fidelity fix
together with one full green suite run than as two tiny separate PRs. Branch:
`spec-sync-2026-09`.

## Ship checkpoints

- pushed spec-sync-2026-09 c6537cb
- PR #28 opened: https://github.com/agentidentitytrustprotocol/aitp-verifier-py/pull/28

## Status

- **Phase 1: DONE** (2026-09-23). Verdict: PASS, 1 round, Opus verifier (routine — not
  critical per the autonomy ladder). Files touched: `tests/test_signed_examples.py` (the
  `.pop("_kat_input", None)` line replaced with an allow-list filter keeping only
  `revocation_list`/`signature`). No gaps. `pytest`: 162 passed. `run_conformance.py`: 68
  passed / 0 failed / 1 skipped (unchanged). `mypy`: clean. No new `ASSUMPTIONS.md` entry —
  the fix followed the plan's decided approach exactly, nothing ambiguous. No docs to
  update (plan's own Phase 1 Docs field: none). Next: Phase 2.
- **Phase 2: DONE** (2026-09-23). Verdict: PASS, 1 round, Opus verifier (routine — an
  internal, reversible, unpublished-package change; not critical per the autonomy
  ladder). Files touched: `aitp_verifier/jws.py` (`verify_jws` gains optional
  `after_typ_check` callback, invoked between `typ` and `alg`-pin), `aitp_verifier/tct.py`
  (new shared `check_tct_claims_shape` helper, exported; `verify_tct` wired through the
  hook; module docstring updated), `aitp_verifier/handshake.py` (`_verify_commit`'s
  embedded-TCT check wired through the hook, replacing its inline duplicate),
  `aitp_verifier/sessionbundle.py` (per-participant TCT check wired through the hook; its
  `UNKNOWN_FIELD`→`BUNDLE_PARTICIPANT_TCT_INVALID` try/except now wraps the whole
  `verify_jws` call instead of a trailing `reject_unknown_fields`), `tests/test_unknown_fields.py`
  (3 new tests), `tests/test_sessionbundle.py` (1 new test — see plan's Phase 2 status for
  why this one landed here instead of `test_unknown_fields.py`). `voucher.py`/`delegation.py`
  confirmed untouched. `pytest`: 166 passed. `run_conformance.py`: 68 passed / 0 failed / 1
  skipped (unchanged). `mypy`: clean. No new `ASSUMPTIONS.md` entry — the test-home
  deviation was a decided, verified-reasonable call, not an open/unconfirmed one. Docs:
  `tct.py`'s module docstring updated per the plan's Phase 2 Docs field. Next: Phase 3.
- **Phase 3: DONE** (2026-09-23). Verification-only, no files touched beyond the tracked
  ones here. `run_conformance.py`: 68 passed / 0 failed / 1 skipped (`del-004`, confirmed
  the correct expected skip — `mh-002` passes live, contradicting the repo's own stale
  README claim that it's also skipped; that README staleness is out of this plan's scope).
  `pytest tests/ -v`: 166 passed, 0 failed. `mypy`: clean. Next: finalization pass, then
  hand off to `/ship`.

---

# PROGRESS (plans/hardening-issues-23-27.md)

Tracking file for `plans/hardening-issues-23-27.md` (issues #23-#27). Appended below the
`spec-sync-2026-09` plan's own tracking section above — that plan is fully shipped (PR #28,
merged, `fba3a95`); this section starts fresh for the new plan.

## Repo map

- `aitp_verifier/fields.py` — currently owns only `reject_unknown_fields` (RFC-AITP-0001 §7
  member-set rejection). Phase 2 primary edit site: adds `validate_shape`, `canonical_bytes`,
  `decode_b64url`. No import cycle risk — currently imports only `.errors`; new imports
  (`.jcs`, `.b64`) import nothing from the package themselves.
- `aitp_verifier/manifest.py` — `verify_manifest` (line 119), input contract
  `inp["manifest"]` (NOT wrapped, unlike session bundle/revocation), returns
  `{"aid": man["aid"]}`. `_shape` (lines 72-103) is the presence+type+unknown-field
  helper Phase 2 lifts into `fields.py`. Canonicalize-for-signature at line 155 (Phase 3);
  unguarded `b64url_decode(pop["challenge"])` at line 150 (Phase 3); IdentityHint
  conditional requirements unenforced (Phase 3). `_REQUIRED_MANIFEST_FIELDS` (line 107),
  `_IDENTITY_HINT_FIELDS` (line 116) — existing member-set tables to extend, not replace.
- `aitp_verifier/envelope.py` — `verify_envelope` (line 41) + shared `envelope_signing_input`
  (line 35, also called from `handshake.py:97`). Has ONLY `reject_unknown_fields` today (no
  presence/type table at all — contrast manifest.py). Phase 4 primary edit site: add
  `_ENVELOPE_TYPES`/`_REQUIRED_ENVELOPE_FIELDS`/`_SENDER_TYPES` tables, wrap `canonicalize`
  at line 36, wrap `parse_aid` at line 60.
  `_ENVELOPE_FIELDS`/`_SENDER_FIELDS` (lines 29-32) — existing member-set tables to extend.
- `aitp_verifier/sessionbundle.py` — `verify_session_bundle` (line 67). `_BODY_FIELDS`/
  `_PARTICIPANT_FIELDS` (lines 61-64) are member-set-only today; no required/type table for
  the body or participant entries (confirmed: `participants`/`expires_at`/`coordinator`
  dereferenced directly at lines 127/136/145 with no presence guard; `issued_at` is schema-
  required but never dereferenced by verification logic itself, only carried into the signed
  body). Canonicalize-for-signature at line 150 (Phase 5); unguarded `parse_aid(coordinator)`
  at line 146 (Phase 5). `p["tct"]`/`p["aid"]` dereferenced directly at lines 141/154/189/192
  — participant `aid`/`tct` both need a required-field check (Phase 5).
- `aitp_verifier/handshake.py` — `_verify_bootstrap` (line 67). `payload["manifest"]` (line
  71) and `payload["identity"]` (line 78) both dereferenced with no presence guard;
  `identity.get("type")` (line 81) crashes on non-dict `identity` — Phase 6 primary edit
  site. `_HELLO_PAYLOAD_FIELDS`/`_HELLO_ACK_PAYLOAD_FIELDS` (lines 45-46) are member-set-only
  (no required-subset semantics) — this is WHY the presence gap exists.
- `aitp_verifier/identity.py` — `verify_identity` (line 82), its own
  `reject_unknown_fields(identity, ..., shape_code="IDENTITY_FAILED")` at line 93 is the
  guard `handshake.py`'s crash makes unreachable in production today; Phase 6 makes it
  reachable via handshake.py's own new check (identity.py itself is NOT modified).
- `aitp_verifier/revocation.py` — `verify_revocation_snapshot` (line 144). `_validate_shape`
  (lines 100-141, stage a), inline member-set checks (lines 156-159, stage b), inline
  signature check (lines 162-182, stage c, including the existing `except JcsError` pattern
  at lines 169-180 — the template Phase 2's `canonical_bytes` generalizes), then absence/
  freshness/deny-list (lines 184-198, stage d, untouched). Phase 8 extracts stages a+b+c into
  new exported `verify_snapshot_trust`; Phase 2 refactors `_typed` (lines 71-98) into
  `fields.validate_shape`. Both phases touch this file — sequenced independently (Phase 2
  first structurally, Phase 8 much later; confirm no merge-order surprises when
  implementing, since both edit the same file).
- `aitp_verifier/tct.py` — `_check_revocation` (lines 104-111): reads
  `inp["issuer_revocation_list"]` via bare `.get()` chains, NO signature/member-set check.
  Phase 8 primary edit site. `verify_tct` (line 68) itself, `check_tct_claims_shape` (line
  46, added by the just-merged spec-sync PR) — NOT touched by this plan.
- `aitp_verifier/delegation.py` — `_revocation_index` (lines 110-117): reads
  `inp["revocation_snapshots"]`, same gap; index keyed on unverified `record["issuer_aid"]`
  rather than the signed body's own `issuer`. Consumed at `_verify_multihop` lines 199-205.
  Phase 8 primary edit site. `verify_delegation_token` (line 52), `_verify_multihop` (line
  120) otherwise unchanged.
- `aitp_verifier/minter.py` — `_sign_revocation` (line 164): only signs when placeholder is
  `__VALID_A_SIG__`/`__VALID_MANIFEST_SIG__`; `del-mh-004`'s/`tct-004`'s fixtures use
  `__VALID_B_SIG__`, currently never signed. `mint_input` (line 356): the
  `for snap_holder in ("snapshot", "issuer_revocation_list")` loop (lines 379-384) never
  walks `revocation_snapshots` (a list, not a dict holder) — Phase 8 needs a new loop.
  `_sign_manifest` (line 137): confirms manifest signing is inner-body-only (lines 150-153),
  grounding Phase 1/#25's premise.
- `tests/test_signed_examples.py` — `test_manifest_signed_example_verifies_over_inner_body`
  (line 80) is the Phase 1 edit site: re-implements crypto inline instead of calling
  `verify_manifest`, unlike its siblings `test_revocation_signed_example_runs_the_real_
  verifier` (line 201) and `test_session_bundle_signed_example_runs_the_real_verifier` (line
  177), which are the pattern to match.
- `tests/test_sessionbundle.py` — `test_malformed_envelope_raises_aitp_error_not_a_traceback`
  (line ~199-228) is the existing parametrized malformed-input pattern Phases 4/5 extend for
  envelope.py/sessionbundle.py respectively.
- `tests/test_unknown_fields.py` — has per-artifact test blocks (manifest, TCT, delegation,
  revocation — the revocation block spans roughly lines 470-565 and 669-816) to extend for
  Phases 3, 6, 8; confirmed during grounding that NONE of its revocation tests currently
  reach `tct.py`/`delegation.py`'s consumption paths (all go through
  `verify_revocation_snapshot` directly) — Phase 8's new tests are wholly additive, not
  modifications of existing ones.
- `tests/conftest.py` — `spec_dir` fixture (lines 29-34), `pytest.skip` → Phase 9's edit
  site. Resolution order already correct (`$AITP_SPEC`, then sibling-directory search,
  lines 15-19) — unchanged by Phase 9.
- `.github/workflows/ci.yml` — `conformance` job (lines 40-84), `pytest -q` step (line 81)
  is where `test_signed_examples.py` is currently bundled invisibly — Phase 10's edit site.
  Zero `aitp-rs` references confirmed (`grep -c aitp-rs` → 0).
- `run_conformance.py` — `run_fixture` (line 118) already catches bare `Exception` (lines
  140-141) and reports it as a fixture FAIL rather than crashing the whole runner — this is
  why none of #23/#24's gaps show up as `run_conformance.py` crashes today, only as
  `test_signed_examples.py`/direct-unit-test-level escapes or (for #24) silent false
  verdicts the runner has no way to distinguish from a correct one.
- `aitp_verifier/jws.py`, `aitp_verifier/b64.py`, `aitp_verifier/sigfield.py`,
  `aitp_verifier/jcs.py` — read in full for this plan's grounding, NOT edited by any phase.
  `jcs.py:27` `JcsError(ValueError)` is the root cause class for every "wrap canonicalize"
  fix; `b64.py:24-29` `b64url_decode`'s two distinct failure shapes (`ValueError` for bad
  alphabet, `binascii.Error` — a `ValueError` subclass — for bad length) are what
  `decode_b64url`/Phase 3's challenge-grammar check must both handle; `sigfield.py:28-31`
  is the existing correct pattern for signature-field decoding, used as the message-wording
  template.

## Verification environment

Same as the `spec-sync-2026-09` plan's environment section above — `/tmp/aitpvenv313`,
same `run_conformance.py --spec-dir ../agentidentitytrustprotocol` / `pytest tests/ -v` /
`mypy` commands. Re-verify the venv still exists before Phase 1; recreate per the command
block above if not.

## PR strategy

**Decided at `/implement` Phase 0 (2026-09-23): 3 PRs.**
- **PR 1 — Phases 1-7** (branch `hardening-issues-23-27`, this branch): closes #25 and #23.
  Cohesive unit — Phase 1 is the regression net Phase 3 needs, Phase 2 is the shared
  foundation Phases 3-6 build on, Phase 7 is the capstone that proves 3-6 actually closed
  the class of bug. Splitting these further would mean reviewing Phase 2's helpers with no
  visible consumer yet, or Phase 7's regression test with nothing it's protecting — neither
  is honestly reviewable alone.
- **PR 2 — Phase 8**: closes #24. Fully independent of PR 1 (different files: `tct.py`,
  `delegation.py`, `minter.py`; only shares `revocation.py` with Phase 2, and depends on it
  landing first per the plan's explicit "Depends on: Phase 2").
- **PR 3 — Phases 9-10**: closes #26 and #27. Both lightweight test/CI-infrastructure
  changes (`conftest.py`, `ci.yml`) with no production-code overlap with PR 1 or PR 2 —
  bundling them avoids two near-trivial PRs for two one-file changes.

Baseline confirmed green before starting: `pytest tests/`: 166 passed. `run_conformance.py`:
68 passed / 0 failed / 1 skipped. `mypy`: clean, 31 source files.

## Status

- **Plan written, reviewed (2 rounds), SOUND — ready for `/implement`** (2026-09-23).
  Grounded via two parallel background Opus subagents (issue #23, issue #24 — both did live
  reproduction against real signed artifacts, not just static reading) plus direct reads of
  every file every phase touches (`manifest.py`, `envelope.py`, `sessionbundle.py`,
  `handshake.py`, `identity.py`, `revocation.py`, `tct.py`, `delegation.py`, `fields.py`,
  `jcs.py`, `b64.py`, `sigfield.py`, `minter.py`, `conftest.py`, `ci.yml`,
  `run_conformance.py`, `test_signed_examples.py`). Round 1: REVISE (6 blocking issues,
  detailed in the plan's own "Plan review" section — effectively a redesign of Phases 2, 6,
  and 8). Round 2 (after fixes applied): SOUND, plus 3 non-blocking notes, also applied.

## Phase checkpoints

### Phase 1 — manifest-convention test blind spot (issue #25) — DONE (2026-09-23)

- **Verdict:** PASS, round 1, fresh Opus verifier (not critical per the Autonomy ladder —
  test-only, no production code, no public contract). One-line why: a targeted regression
  test with a hand-verified negative case doesn't cross a trust boundary or land a one-way
  door.
- **Files touched:** `tests/test_signed_examples.py` (new test
  `test_manifest_signed_example_runs_the_real_verifier`, added imports for `pytest`,
  `b64url_encode`, `AitpError`, `verify_manifest`; existing
  `test_manifest_signed_example_verifies_over_inner_body` untouched).
- **Tests:** `pytest tests/test_signed_examples.py -v` → 8 passed. `pytest tests/ -q` → 167
  passed (baseline 166). `run_conformance.py --spec-dir ../agentidentitytrustprotocol` →
  68/0/1, unchanged from baseline (no production code touched). `mypy` → clean.
  Acceptance criterion 3 (flipping `manifest.py`'s signing convention makes the new test
  fail) hand-verified independently by both the executor and the verifier — same result:
  the positive-case assertion fails with `MANIFEST_SIGNATURE_INVALID`, file reverted after
  (`git diff --stat aitp_verifier/manifest.py` empty both times).
- **Gap rounds:** 0 — PASS on first verify.
- **ASSUMPTIONS.md:** none logged this phase — the `now` value follows the plan's specified
  pattern (`published_at + 100`, same shape as the sibling revocation/bundle tests), not a
  new judgment call.
- **What's next:** Phase 2 (shared boundary-conversion helpers in `fields.py`).

### Phase 2 — shared boundary-conversion helpers in `fields.py` — DONE (2026-09-23)

- **Verdict:** PASS, round 1, fresh Opus verifier (not critical per the Autonomy ladder —
  an internal refactor with no public-contract or signing-format change). One-line why: a
  behavior-preserving refactor backed by two independent fault-injection checks (executor's
  and verifier's own) isn't a one-way door or a trust-boundary crossing.
- **Files touched:** `aitp_verifier/fields.py` (added `require_members`, `check_types`,
  `canonical_bytes`, `decode_b64url`, module docstring note), `aitp_verifier/manifest.py`
  (`_shape` delegates presence/type checks to the new helpers, ordering unchanged),
  `aitp_verifier/revocation.py` (`_typed` deleted, `_validate_shape` delegates to the new
  helpers, `except JcsError` block replaced by `canonical_bytes`, all ordering unchanged),
  `tests/test_unknown_fields.py` (2 new ordering-regression tests), `tests/test_fields.py`
  (new, 17 unit tests for the four helpers directly).
- **Tests:** `pytest tests/ -q` → 186 passed (baseline 167: +17 `test_fields.py` + 2 new
  ordering tests in `test_unknown_fields.py`). `run_conformance.py` → 68/0/1, unchanged.
  `mypy` → clean, 31 source files. Both required ordering-regression acceptance criteria
  (wrapper-level unknown+body type defect; entry-level unknown+entry type defect)
  independently confirmed non-vacuous by fault injection, done twice: once by the executor
  (reordered `verify_revocation_snapshot` to collapse the deferred member-set pass ahead of
  shape validation, watched all 3 ordering tests fail with `UNKNOWN_FIELD`, reverted), once
  more by the verifier from a cold read (same reorder, same failure, plus a narrower
  single-point entry-level-only regression that failed only the entry-level test —
  confirming the two new tests pin genuinely independent dependencies, not the same one
  twice).
- **Gap rounds:** 0 — PASS on first verify.
- **ASSUMPTIONS.md:** none logged this phase — the helper signatures and ordering were
  fully specified by the plan (itself already corrected for this exact ordering question
  during the plan's own Round 1 review), not a new judgment call made during implementation.
- **What's next:** Phase 3 (`manifest.py` hardening — issue #23 items 1/manifest, 2, 4).

### Phase 3 — `manifest.py` hardening (issue #23 items 1/manifest, 2, 4) — DONE (2026-09-23)

- **Verdict:** PASS (functional/acceptance criteria), round 1, fresh Opus verifier (not
  critical per the Autonomy ladder — internal validation hardening, no public-contract
  change beyond the already-flagged, already-logged identity_hint flip). One-line why: the
  behavior flip is schema-mandated and pre-approved by the plan's own review round, not a
  new judgment call at implementation time. Verifier flagged 2 non-functional process gaps
  (missing `ASSUMPTIONS.md`, plan `Status` not yet flipped) — both closed immediately as part
  of this phase's own tracked-file closeout (see below), not a re-verify-worthy code gap.
- **Files touched:** `aitp_verifier/manifest.py` (challenge-grammar check via `decode_b64url`
  inserted into the structural pass; `_validate_identity_hint` added, enforcing the schema's
  `if/then/else`, `type` enum, `public_key` pattern; final signature digest now via
  `canonical_bytes`), `tests/test_unknown_fields.py` (the one required test rewrite, split
  into 2 positive + 1 five-case-parametrized-negative), `tests/test_manifest.py` (new, 8
  tests: JcsError-escape direct + via-handshake, PoP-challenge-grammar direct + via-handshake
  + an empty-challenge control case), `ASSUMPTIONS.md` (new file, this phase's behavior-flip
  entry).
- **Tests:** `pytest tests/ -q` → 200 passed (baseline 186: +8 `test_manifest.py`, net +6 in
  `test_unknown_fields.py`). `run_conformance.py` → 68/0/1, unchanged. `mypy` → clean, 32
  source files. Verifier independently cross-checked `_validate_identity_hint` against the
  actual JSON schema (`$defs/IdentityHint` in the sibling spec checkout) character-for-
  character, confirmed every new test avoids the `mint_input`-signs-the-hostile-value-itself
  trap (hostile values injected only after minting a well-formed fixture), and confirmed
  every existing manifest test outside the one required rewrite is byte-for-byte unmodified.
- **Gap rounds:** 0 code gaps — PASS on first verify. 2 non-blocking process gaps (both
  closed same-turn, see above): `ASSUMPTIONS.md` didn't exist yet (created now, with this
  phase's entry); plan `Status` line wasn't yet flipped (flipped now).
- **ASSUMPTIONS.md:** 1 entry logged this phase — the `identity_hint` oidc+public_key
  accept→reject flip, marked `UNCONFIRMED` pending the end-of-plan `/reconcile` pass, per the
  plan's own Open-questions note that this is a "record and proceed" item.
- **What's next:** Phase 4 (`envelope.py` hardening — issue #23 item 1/envelope, plus
  adjacent completeness gaps).

### Phase 4 — `envelope.py` hardening (issue #23 item 1/envelope, plus completeness gaps) — DONE (2026-09-23)

- **Verdict:** PASS, round 1, fresh Opus verifier (not critical per the Autonomy ladder —
  internal validation hardening mirroring an already-established pattern, no public-contract
  change). One-line why: same class of fix as Phase 3, already precedented. Verifier flagged
  1 non-blocking test-coverage completeness note (see below), closed same-turn; not a code
  gap requiring a re-verify round.
- **Files touched:** `aitp_verifier/envelope.py` (required-member/type tables added;
  `require_members`→`check_types`→`reject_unknown_fields` ordering for both `envelope` and
  nested `sender`, mirroring `manifest.py`; `envelope_signing_input` routed through
  `canonical_bytes` — fixes the JcsError-escape gap for both its callers, `verify_envelope`
  and `handshake.py::_verify_bootstrap`; `parse_aid` wrapped), `tests/test_envelope.py` (new,
  21 tests). `tests/test_unknown_fields.py` and `aitp_verifier/handshake.py` deliberately
  untouched (confirmed empty diffs) — the latter's own direct dereferencing gaps are Phase 6.
- **Tests:** `pytest tests/ -q` → 221 passed (baseline 200: +21 in `test_envelope.py`).
  `run_conformance.py` → 68/0/1, unchanged. `mypy` → clean, 33 source files. Verifier
  independently traced the `OverflowError` edge case (confirmed `check_types` rejects
  `float('inf')` before `int(env["timestamp"])` ever runs, and separately confirmed a
  400-digit Python int passes `check_types` fine and reaches the ordinary
  `TIMESTAMP_EXPIRED` path, not a crash) and confirmed every hostile-value test mints a
  well-formed fixture before mutating it (the same `minter.py`-signs-the-same-fields trap as
  Phases 1/3).
- **Gap rounds:** 0 code gaps — PASS on first verify. 1 non-blocking coverage note (the
  400-digit-int payload hazard wasn't yet reproduced via the handshake path, only directly)
  — closed same-turn by adding `test_envelope_huge_int_payload_value_does_not_crash_via_handshake`.
- **ASSUMPTIONS.md:** none logged this phase — every table/ordering choice was fully
  specified by the plan (mirrors `manifest.py`'s already-established convention), not a new
  judgment call.
- **What's next:** Phase 5 (`sessionbundle.py` hardening — issue #23 item 1/sessionbundle,
  plus adjacent completeness gaps).

### Phase 5 — `sessionbundle.py` hardening (issue #23 item 1/sessionbundle, plus completeness gaps) — DONE (2026-09-23)

- **Verdict:** PASS, round 1, fresh Opus verifier (not critical per the Autonomy ladder —
  internal validation hardening mirroring `manifest.py`'s/`envelope.py`'s already-established
  pattern, no public-contract change). Verifier additionally fault-injected: it stashed the
  production diff, ran all 16 new tests against the pre-fix code, and confirmed every one
  fails with the exact hazard claimed (raw `KeyError`/`TypeError`/`ValueError`/`JcsError`) —
  proving none are vacuous — then restored the working tree.
- **Files touched:** `aitp_verifier/sessionbundle.py` (`_REQUIRED_BODY_FIELDS`/`_BODY_TYPES`/
  `_REQUIRED_PARTICIPANT_FIELDS`/`_PARTICIPANT_TYPES` tables added; body and participant
  validation routed through `require_members`→`check_types`→`reject_unknown_fields`, matching
  `manifest.py`'s interleaved convention, inside the existing shape stage — before version/
  expiry, preserving `bundle-003`'s "shape precedes expiry" ordering invariant; `coordinator`'s
  `parse_aid` wrapped in try/except → `SESSION_BUNDLE_INVALID`; `canonicalize(signing_body)`
  routed through `canonical_bytes`; module docstring updated one line), `tests/test_sessionbundle.py`
  (+16 tests: required-member coverage for all 6 body fields, mistyped-member coverage for 4
  body fields, participant missing-both-members, participant mistyped `aid`/`tct`, `extensions`
  1e400-hazard, huge-int `issued_at`-hazard, malformed-coordinator-hazard).
- **Tests:** `pytest tests/ -q` → 237 passed (baseline 221: +16 in `test_sessionbundle.py`).
  `run_conformance.py` → 68/0/1, unchanged; `bundle-003` individually re-confirmed →
  `BUNDLE_EXPIRED` (the load-bearing ordering invariant, untouched). `mypy` → clean, 33 source
  files. All 16 new hostile-mutation tests mint a well-formed `bundle-001` fixture first via
  `_minted_bundle_input`, then mutate afterward — never pass a hostile value through
  `mint_input`/`_mint_bundle` itself (the same minting-order-of-operations trap as Phases 1/3/4).
- **Gap rounds:** 0 — PASS on first verify.
- **ASSUMPTIONS.md:** none logged this phase. One minor implementation divergence noted
  directly in `plans/hardening-issues-23-27.md`'s Phase 5 section instead (not ambiguous
  enough to warrant an `ASSUMPTIONS.md` entry): `_BODY_TYPES` additionally type-checks the
  optional `extensions` member as `(dict,)`, a benign superset the plan's table didn't list,
  confirmed non-breaking by the verifier.
- **What's next:** Phase 6 (`handshake.py` — dispatcher-level gaps plus `_verify_bootstrap`
  gaps, issue #23 item 3).

### Phase 6 — `handshake.py`: validate before dereferencing (issue #23 item 3, plus a review-round finding) — DONE (2026-09-23)

- **Verdict:** PASS, round 1, fresh Opus verifier (not critical per the Autonomy ladder —
  internal validation hardening, no public-contract change). Verifier `git stash`-fault-injected
  20 of the 22 new tests against the pre-fix module and confirmed each fails with the exact raw
  exception claimed (`KeyError`, `TypeError: unhashable type`, `TypeError: ... not
  subscriptable`, `AttributeError`); the other 2 (`message_type` mistyped to `5`/`None`) pass
  even pre-fix by design — they fall through to the pre-existing "unsupported message_type"
  fallback rather than the unhashable-type crash the `[]`/`{}` cases specifically target.
- **Files touched:** `aitp_verifier/handshake.py` (presence/type guards for `inp["envelope"]`,
  `env["message_type"]`, `env["payload"]` at both its dereference sites — the dispatcher's
  commit branch and `_verify_bootstrap` — and `env["sender"]` in `_verify_bootstrap`, all
  raising `INVALID_ENVELOPE`; explicit `manifest`/`identity` presence check inserted right
  after the existing `reject_unknown_fields` call; `isinstance(identity, dict)` check raising
  `IDENTITY_FAILED` — deliberately the same code `identity.py`'s own otherwise-unreachable
  non-dict guard already uses for this defect; no symmetric `manifest` dict-check added, since
  `verify_manifest` already covers that). `tests/test_unknown_fields.py` (+22 tests). `identity.py`
  deliberately untouched (confirmed empty diff) — its own non-dict guard remains correctly
  unreachable in production via this call path (dead code reached only through
  `verify_identity`'s direct-call test path); this is fine and expected, not a defect, per the
  plan's own acceptance criteria.
- **Tests:** `pytest tests/ -q` → 259 passed (baseline 237: +22 in `test_unknown_fields.py`).
  `run_conformance.py` → 68/0/1, unchanged. `mypy` → clean, 33 source files. All checks that run
  before any crypto (envelope/message_type/payload/manifest-presence/identity-presence) use raw
  dict input with no minting; the two checks positioned after `verify_manifest()` succeeds (the
  sender-type-check and identity-type-check tests) mint a well-formed fixture via `mint_input`
  first, then mutate the hostile value in afterward — the same minting-order-of-operations
  pattern as every prior phase.
- **Gap rounds:** 0 code gaps — PASS on first verify. 1 non-blocking test-precision nuance
  (the missing-`identity` test's `manifest: {}` fixture failed pre-fix with `MANIFEST_INVALID`
  rather than the literal `KeyError` the acceptance criterion names, because an empty manifest
  trips `verify_manifest`'s own structural check before the code ever reaches
  `payload["identity"]`) — closed same-turn by switching that test to mint a genuinely valid
  manifest first, then delete `identity` afterward; hand-confirmed via `git stash` that it now
  fails with the literal `KeyError: 'identity'` pre-fix.
- **ASSUMPTIONS.md:** none logged this phase — every check's placement and error code was
  fully specified by the plan, not a new judgment call.
- **What's next:** Phase 7 (generic boundary-contract regression test,
  `tests/test_boundary_contract.py` — spans issue #23's whole class; depends on Phases 2-6,
  all now landed).

### Phase 7 — Generic boundary-contract regression test (spans issue #23's whole class) — DONE (2026-09-23)

- **Verdict:** PASS (round 2, after 1 gap round — see below). Scope grew substantially beyond
  the plan's literal "this phase IS the test" framing — see the divergence note in
  `plans/hardening-issues-23-27.md`'s Phase 7 section for the full root-cause writeup.
- **Files touched:** `tests/test_boundary_contract.py` (new — the harness itself: mutates
  every scalar-leaf JSON path inside each of 9 entry points' artifact-bearing argument with
  11 hostile mutations, re-signs via `mint_input`, asserts only `AitpError` or a normal
  return). Production fixes, all following the established shared-helper pattern
  (`check_tct_claims_shape` precedent): `aitp_verifier/tct.py` (`check_tct_claims_shape`
  extended with required-member/type/grants-element checks), `aitp_verifier/voucher.py`
  (new exported `check_voucher_claims_shape`, same pattern), `aitp_verifier/delegation.py`
  (new private `_check_delegation_claims_shape`; both embedded-voucher call sites — single-hop
  `vclaims` and multi-hop `root_voucher` — now route through `voucher.py`'s shared checker;
  multi-hop `hc["sub"]`→`parse_aid` wrapped), `aitp_verifier/identity.py`
  (`_verify_pinned_key` rewritten to wrap malformed base64/key-material errors),
  `aitp_verifier/envelope.py` (new exported `validate_envelope_shape`, factored out of
  `verify_envelope`'s own inline block), `aitp_verifier/handshake.py` (dispatcher now calls
  the exported `validate_envelope_shape` instead of its own Phase-6 partial inline check,
  closing a gap where `message_id`/`timestamp`/`signature` were unguarded there;
  `_verify_commit` gained a `"tct" not in payload` guard and a `parse_aid`-on-`sub` try/except),
  `aitp_verifier/sessionbundle.py` (pre-signature expiry-invariant peek now calls
  `check_tct_claims_shape` early, wrapped in the module's existing `UNKNOWN_FIELD`→
  `BUNDLE_PARTICIPANT_TCT_INVALID` remap pattern — confirmed this doesn't weaken the
  bundle-003 "shape precedes expiry" ordering invariant, since the shape check is pure JSON
  validation with no cryptographic dependency). Test-fixture completeness fixes:
  `tests/test_unknown_fields.py` (`_voucher_claims`/`_delegation_claims` helpers gained
  missing schema-required `src_jti`/`cnf` defaults — pre-existing latent gaps, surfaced only
  once required-member enforcement was correctly added upstream).
- **Tests:** `pytest tests/ -q` → 268 passed (baseline 259: +9 in `test_boundary_contract.py`,
  covering the 8 `OPERATIONS` entries plus `verify_identity` directly).
  `run_conformance.py` → 68/0/1, unchanged. `mypy aitp_verifier tests` → clean, 34 source
  files. `pyflakes` clean on all 9 touched files (no unused imports after `VOUCHER_CLAIM_FIELDS`
  was removed from `delegation.py`'s import list).
- **Hand-verification (acceptance criterion 2):** done — see the plan's Phase 7 divergence
  note for the full writeup. First attempt (reverting `manifest.py`'s Phase 3 fix) surfaced a
  genuine harness-scope limitation instead of a failure: for the `canonicalize`/`JcsError`-
  escape bug class specifically, `minter.py`'s own signing function canonicalizes the same
  fields the harness mutates, so the mutation is intercepted (and silently skipped) during
  minting itself, before ever reaching the verifier — true regardless of whether the fix is
  present. Second attempt (reverting `envelope.py`'s Phase 4 `require_members` call, a plain
  presence check outside that blind spot) succeeded as designed: 22 genuine `KeyError`
  violations across `verify_envelope` and `verify_handshake_payload`. Restored, re-confirmed
  268 passed.
- **Gap rounds:** 1. Round-1 fresh Opus verifier verdict: **GAPS** — one item. It found
  `identity.py::_verify_pinned_key` still leaked a bare `KeyError` for a missing
  `envelope.payload.pop_nonce`, reachable directly via `verify_handshake_payload`
  (`_verify_bootstrap` runs identity verification *before* the envelope signature check, so
  no valid signature is needed to trigger it) — root-caused to `handshake.py:76` never
  checking `pop_nonce`/`requested_grants` presence, the same "minting dereferences what the
  harness mutates" blind spot already documented once for `manifest.py`/`JcsError`, here as
  `minter.py::_mint_pinned_proof` sharing the identical unguarded `envelope["payload"]["pop_nonce"]`
  dereference during minting, so `test_boundary_contract.py`'s own harness silently skips the
  case. Closed same-round: `handshake.py::_verify_bootstrap` now runs `require_members(payload,
  _HELLO_REQUIRED_PAYLOAD_FIELDS, ...)` (`identity`, `manifest`, `requested_grants`, `pop_nonce`
  — the schema-required set for `MutualHelloPayload`/`MutualHelloAckPayload`, deliberately
  excluding the ack-only `pop_nonce_echo` since it's read via `.get()` and carries no crash
  risk) before dispatching to `verify_identity`; `identity.py::_verify_pinned_key`'s except
  tuple also gained `KeyError` as defense in depth, since `verify_identity` is itself public
  with no guarantee from every caller. Two new regression tests added to
  `tests/test_unknown_fields.py` (`test_handshake_hello_missing_pop_nonce_with_valid_manifest_is_a_structural_rejection`,
  `test_verify_identity_pinned_key_missing_pop_nonce_is_identity_failed_not_a_crash`) —
  hand-verified via `git stash` fault injection: both fail with the exact bare
  `KeyError: 'pop_nonce'` against the pre-fix code, confirming neither is vacuous. Full suite
  now 270 passed (268 + 2), conformance 68/0/1 unchanged, mypy clean on 34 files, pyflakes
  clean. **Round-2 re-verify verdict: PASS.** The fresh re-verifier confirmed no leftover
  conflict-resolution artifacts in `identity.py` (the `git stash pop` used to hand-verify the
  fix hit a merge conflict, resolved manually), confirmed the `require_members` call's
  ordering genuinely gates `verify_identity`, confirmed `KeyError` is in the except tuple,
  independently re-ran the hand-verification with the same bare-`KeyError` result (no conflict
  that time), confirmed `requested_grants`'s inclusion in the new required set breaks no
  existing positive test, re-ran the full suite/conformance/mypy (270 / 68·0·1 / clean, all
  unchanged), and swept `minter.py`'s other `_mint_*` functions against their corresponding
  `handshake.py`/`identity.py`/`tct.py` call sites for a second instance of the same
  "minting dereferences what the harness mutates" pattern — found none in scope for this phase.
- **ASSUMPTIONS.md:** the harness-scope limitation (canonicalize-escape mutations intercepted
  during minting) is a genuine, non-obvious finding worth recording — added as a new entry
  under Phase 7 for `/reconcile` to review at end-of-plan, not a behavior-flip needing
  confirmation, but worth flagging so a future phase adding a new canonicalize-wrap doesn't
  assume this harness alone proves it.
- **What's next:** commit Phase 7 (this diff), then run PR 1's finalization pass
  (`/implement` §4 — Phases 1-7 collectively close #25 and #23) before handing off to `/ship`.

## PR 1 finalization (2026-09-23)

Phase 7 committed as `fddbffb`. Confirmed branch is current with `origin/main` (no rebase
needed; merge-base `fba3a95` == `origin/main` HEAD). Doc sweep: every phase's own `Docs`
field was already applied inline during that phase's own commit (module docstrings in
`manifest.py`/`envelope.py`/`sessionbundle.py`/`fields.py`/`tct.py`); no repo-level
`README`/`CLAUDE.md` enumerates individual test files, so no further doc update needed.
Whole-feature integration coverage: `tests/test_boundary_contract.py` (Phase 7) already
functions as the cross-phase integration test — it exercises every entry point's guards in
combination on real minted input, which is the closest thing to an I/O/network/DB boundary
this pure-Python, dependency-free library has; no additional integration tests were needed.

**Final whole-PR verification (fresh Opus, cumulative diff `main...HEAD`, all 7 phases
against the plan as a whole): PASS.** Confirmed: issues #25 and #23 are genuinely closed by
the combined diff (not just phase-by-phase); `fields.py`'s shared helpers are used
consistently everywhere (no module reinvented its own copy); `handshake.py` cleanly uses
`envelope.validate_envelope_shape` with no residual partial duplicate; Phase 7's shared
claims-shape validators are used at every claimed call site including both of
`sessionbundle.py`'s TCT checks and both of `delegation.py`'s embedded-voucher checks;
`revocation.py` itself has no residual #23-class gap (already closed by PR #22); the two
`tct.py`/`delegation.py` revocation-trust gaps noted are correctly deferred to Phase 8/PR 2
(issue #24), not a PR-1 scope miss. Independently re-ran and confirmed: `pytest tests/ -q`
→ 270 passed; `run_conformance.py` → 68/0/1; `mypy aitp_verifier tests` → clean, 34 files.
Two non-blocking observations, both pre-existing/out-of-scope (not regressions): an
unguarded `inp[side]["self_aid"]` index in `handshake.py`'s peer_a/peer_b commit-simulation
branch (byte-identical to the merge-base, predates this PR, same excluded
"Python-calling-convention, not a wire artifact" class Phase 7 already scoped out) and a
bare-`AttributeError` risk in `tct.py`/`delegation.py`'s revocation-entry handling (issue
#24's exact subject, correctly deferred to Phase 8).

No gaps. Ready for `/ship`.

## Ship checkpoints

- pushed hardening-issues-23-27 fddbffb9b9a202257cebb97ebd543bebb36cc653
- PR #29 opened: https://github.com/agentidentitytrustprotocol/aitp-verifier-py/pull/29
- CI green: 8/8 checks passed (conformance+tests+types × 4 Python versions, 2 cross-platform,
  wheel build/smoke-test, declared-floors advisory check). `call / auto-merge` reported
  `skipping` (repo's reusable auto-merge workflow declined to act — reason not inspected,
  merged manually instead, consistent with `/ship`'s green-CI merge authorization).
- merged #29 (squash) into `main` at `37279e0`, branch `hardening-issues-23-27` deleted.
  Issues #25 and #23 auto-closed by the merge (confirmed via `gh issue view`). No deploy to
  watch — this repo is a pure-Python library with no `vercel.json`/`railway.json` or
  equivalent deploy config.
- **PR 1 (Phases 1-7) fully shipped.** Next: Phase 8 (PR 2 scope, issue #24 — depends on
  Phase 2, already landed on `main`).
