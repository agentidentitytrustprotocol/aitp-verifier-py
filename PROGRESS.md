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

### Phase 8 — revocation-snapshot trust gap in `tct.py`/`delegation.py` (issue #24) — DONE (2026-09-23)

- **Branch:** `revocation-snapshot-trust-24`, off `main` (post-PR-1-merge). Process note: PR
  1's own final ship-checkpoint doc update was mistakenly pushed directly to `main`,
  bypassing branch protection's required status checks (disclosed to the user at the time).
  Corrected going forward — every change from Phase 8 onward goes through a proper feature
  branch + PR + CI, no direct pushes to `main`.
- **Files touched:** `aitp_verifier/revocation.py` (new exported `verify_snapshot_trust`,
  extracted from `verify_revocation_snapshot`'s own stages 1-3 — structural, member-set,
  signature; `verify_revocation_snapshot` itself now just calls it then layers stage 4,
  behaviorally unchanged), `aitp_verifier/tct.py` (`_check_revocation` rewritten to call
  `verify_snapshot_trust(revlist.get("snapshot"))`, skip the deny-list scan when the verified
  `body["issuer"] != claims.get("iss")` rather than rejecting; module docstring updated),
  `aitp_verifier/delegation.py` (`_revocation_index` rewritten to call
  `verify_snapshot_trust` per record and index on the *verified* `body["issuer"]`, not the
  caller-supplied `record.get("issuer_aid")` — closing the additional re-keying gap the #24
  analysis surfaced; module docstring updated), `aitp_verifier/minter.py` (`_sign_revocation`
  allow-list widened to include `__VALID_B_SIG__`; `mint_input` gains a loop signing each
  `revocation_snapshots[*].snapshot`), `tests/test_unknown_fields.py` (+21 new tests: 10
  through `verify_tct`, 11 through `verify_delegation_token` — forged signature, missing
  signature, missing/absent `snapshot`, non-dict record, a scalar `revocation_snapshots`
  container (round-1 gap fix, see below), unknown body member, a parametrized
  non-dict/non-list junk-shape sweep, a different-issuer-does-not-apply positive case, a
  genuinely-signed positive control, and the signed-value-wins re-keying test).
- **Tests:** `pytest tests/ -q` → 291 passed (baseline 270: +21). `run_conformance.py` →
  68/0/1, unchanged — `tct-004-revoked`/`del-mh-004-revoked-hop` confirmed still reach
  `TCT_REVOKED`/`DELEGATION_SOURCE_TCT_REVOKED`, now via a genuinely verified snapshot (the
  minter previously left their `__VALID_B_SIG__` placeholder unsigned since it predated
  `_sign_revocation`'s allow-list including it — meaning these two fixtures previously passed
  "by coincidence," exactly the #24 finding). `mypy aitp_verifier tests` → clean, 34 files.
  `pyflakes` clean on all touched files (one pre-existing, out-of-scope finding confirmed
  via `git show main:aitp_verifier/minter.py`: `.jcs.dumps` imported but unused, predates
  this phase, not touched).
- **Hand-verification:** all 21 new tests fault-injected against pre-fix production code
  (git-stash for the original 18, a targeted `git checkout HEAD --`/restore for the 3
  round-1 additions) — 20 of 21 failed as expected (1 test, the genuinely-signed positive
  control, correctly still passes pre-fix, since that fixture was never broken). Failures
  split three ways: 4 genuine bare `AttributeError` crashes (`'int'/'bool' object has no
  attribute 'get'`, confirming the malformed-shape sweep is not vacuous), 3 genuine bare
  `TypeError: '...' object is not iterable` (the round-1 container-scalar guard), and — most
  importantly — the signed-value-wins re-keying test **did not raise at all** pre-fix,
  meaning the old `record.get("issuer_aid")`-keyed index genuinely let a mislabeled snapshot
  bypass detection silently, precisely the vulnerability issue #24 reports. Both restores
  confirmed clean, re-confirmed 291 passed.
- **Follow-up issue filed** (plan's Phase 8 acceptance criteria requirement, not a code
  change): agentidentitytrustprotocol/aitp-verifier-py#30, documenting the separate,
  deliberately-deferred fail-open gap when `issuer_revocation_list` is absent entirely from
  `verify_tct`'s input. Extended after round-1 verification to also cover a present-but-
  wrong-issuer snapshot silently skipping the wrapper's own declared `issuer`/`fail_mode`
  members (`tct.py`'s skip-not-reject branch), a related fail-open sub-case the original
  filing didn't scope in. A second, separate follow-up issue (#31) was filed for a
  pre-existing, repo-wide `RecursionError`-escapes-`canonicalize` class, newly reachable
  through two more entry points by this phase's own routing — cross-cutting, not specific
  to Phase 8, so tracked as its own follow-up (open, unfixed) rather than folded into this
  diff.
- **ASSUMPTIONS.md:** one new entry (Phase 8) — `verify_snapshot_trust`'s shape validation
  now hard-rejects a malformed `snapshot` sub-field that previously silently produced an
  empty entry set, per the plan's own explicit instruction to log this distinct-from-the-
  headline-fix behavior change for end-of-plan `/reconcile` review.
- **Docs:** `tct.py`'s and `delegation.py`'s module docstrings both updated per the plan's
  Phase 8 Docs field.
- **Gap rounds:** 1. Round-1 fresh-Opus verifier (general-purpose agent, Opus model — the
  default tier; this phase isn't a one-way-door/trust-boundary change per the Autonomy
  ladder, so Fable wasn't warranted) returned `GAPS`: one substantive item (the
  `revocation_snapshots` container-scalar `TypeError`, fixed above) plus three advisory/doc
  items (test-count/split inaccuracies in this file and the plan, both now corrected; two
  narrow-scope fail-open sub-cases better tracked as follow-up issues than fixed in this
  diff, per the verifier's own recommendation — issue #30 extended, issue #31 filed). All
  items closed same round, committed as `4fdcdae` on top of `a276c28`, both on
  `revocation-snapshot-trust-24`, to be squash-merged as one PR. A round-2 fresh-Opus
  verifier (given the round-1 gap list, checking closure rather than reviewing cold)
  independently re-derived every claimed count and hand-verified the new guard's
  non-vacuity itself (reverted it in place, confirmed the same raw `TypeError` on all 3
  new tests, restored) — returned `PASS`, no same-gap survival, no new substantive issue
  introduced by the round-1 fix. Two cosmetic doc-wording slips it flagged (PROGRESS.md
  said issue #31 was "fixed" rather than "tracked/open"; the plan file asserted "verified
  PASS on round 2" before that verification had actually run) were corrected immediately
  after, non-blocking. Proceeding to `/ship` for PR 2.

## Ship checkpoints (PR 2)

- pushed revocation-snapshot-trust-24 d0643a2, then a further doc-checkpoint push to
  de76880 (PR-opened checkpoint recorded before CI finished, both via `git push`, never a
  direct push to `main` — the corrected process held for the whole of PR 2).
- PR #32 opened: https://github.com/agentidentitytrustprotocol/aitp-verifier-py/pull/32
- CI green: 8/8 checks passed (conformance+tests+types × 4 Python versions, 2
  cross-platform, wheel build/smoke-test, declared-floors advisory check). `call /
  auto-merge` reported `skipping` again, same as PR 1's reusable workflow behavior — merged
  manually, consistent with `/ship`'s green-CI merge authorization. (The first
  `gh pr checks --watch` invocation raced ahead of GitHub registering the just-pushed
  commit's checks and returned "no checks reported" — re-ran once the runs existed;
  unrelated to CI health.)
- merged #32 (squash) into `main` at `b2d9aec`, branch `revocation-snapshot-trust-24`
  deleted (both locally, via `gh pr merge --delete-branch`, and its stale remote-tracking
  ref pruned via `git fetch --prune`). Issue #24 auto-closed by the merge (confirmed via
  `gh issue view 24`). No deploy to watch — same pure-Python-library reasoning as PR 1.
- **PR 2 (Phase 8) fully shipped.** Follow-up issues #30 (extended) and #31 (filed) remain
  open by design, tracked separately from this plan's own 10 phases. Next: Phases 9-10
  (PR 3 scope, issues #26/#27 — no dependency on Phase 8, both lightweight test/CI-
  infrastructure changes with no production-code overlap with either merged PR).

### Phase 9 — `conftest.py`: fail loudly, not silently, when the spec repo is missing (issue #26) — DONE (2026-09-24)

- **Branch:** `test-infra-26-27` (PR 3 scope), off `main` post-PR-2-merge.
- **Files touched:** `tests/conftest.py` (`spec_dir` fixture: `AITP_SPEC == "none"` checked
  unconditionally as the *first* statement, before `_find_spec()` runs — this ordering is
  load-bearing per the plan's own review-round correction, since `_find_spec()` tries the
  sibling-directory convention regardless of `$AITP_SPEC`'s value, so an opt-out gated on
  "resolution already failed" would never trigger on a machine with the sibling repo
  checked out; the not-found branch now calls `pytest.fail(...)` naming both resolution
  paths and the opt-out, instead of the old `pytest.skip(...)`; module docstring gained a
  paragraph explaining why the ordering matters), `tests/test_conftest_spec_resolution.py`
  (new — 3 subprocess-invocation tests, decided over an in-process unit test because the
  behavior under test is `pytest`'s own fixture-collection-time failure/skip machinery,
  which only manifests by actually running a nested `pytest` process; each copies
  `conftest.py` into an isolated `tmp_path` tree with no `agentidentitytrustprotocol`
  ancestor, so the real in-repo `conftest.py` — which always has a resolvable sibling on
  this machine — can't be used to exercise the "not found" path directly), `README.md` (one
  clause added naming the `AITP_SPEC=none` opt-out, now that a missing spec repo is a hard
  failure rather than a silent skip — not required by the plan's own Docs conditional, since
  the README already flagged the `$AITP_SPEC`/`--spec-dir` dependency, but cheap and
  genuinely useful now that the failure mode changed).
- **Tests:** `pytest tests/ -q` (AITP_SPEC set, as `ci.yml` does) → 294 passed (baseline
  291 after PR 2: +3 new tests in `test_conftest_spec_resolution.py`). Same command with
  `$AITP_SPEC` unset (sibling-directory fallback) → byte-identical 294 passed, no skips —
  confirming this phase's own acceptance criterion that a correctly-resolvable spec repo
  produces unchanged pass counts either way. `mypy aitp_verifier tests` → clean, 35 source
  files. `pyflakes` clean on both touched files.
- **Hand-verification:** all 3 new tests confirmed non-vacuous by reverting `conftest.py`
  to its pre-fix state (old `pytest.skip`, no opt-out) — all 3 fail as expected, on the
  right assertions. The round-1 gap (below) additionally required reintroducing the plan's
  *original, review-round-corrected-away* buggy design (opt-out nested inside
  `found is None`, not unconditional-first) to prove the third test's own discriminating
  power — confirmed it (and only it) fails against that specific bug (`1 passed` instead of
  `1 skipped`, meaning the opt-out was silently ignored in favor of a resolvable sibling),
  while the other two tests pass identically under both orderings (they can't tell the two
  apart, since neither has a resolvable sibling present). Restored, re-confirmed 294 passed.
- **ASSUMPTIONS.md:** none logged this phase — the fixture's exact ordering, wording, and
  failure/skip semantics were fully specified by the plan (including its own review-round
  correction), not a new judgment call made during implementation.
- **Docs:** `README.md`'s Development section, per the reasoning above (advisory, not
  triggered by the plan's own conditional, done anyway).
- **Gap rounds:** 1. Round-1 fresh-Opus verifier (not critical per the Autonomy ladder —
  test-infra-only, no production code, no public contract) returned `GAPS`: one substantive
  item (the original 2 tests only ever exercised the no-resolvable-sibling case, which is
  exactly the condition under which the buggy and fixed orderings behave identically — so
  the regression protection covered everything *except* the one correction the review round
  produced) plus two housekeeping items (this file and the plan's `Status` line not yet
  updated) plus one advisory (README). All closed same round: added
  `test_explicit_no_spec_opt_out_wins_even_when_sibling_is_resolvable` (plants a fake-but-
  resolvable sibling, asserts the opt-out still wins), flipped the plan's Phase 9 `Status`,
  wrote this entry, added the README clause, and (a second advisory the same verifier
  raised) stripped `$PYTEST_ADDOPTS` from the subprocess tests' environment for robustness
  against a future CI change, though nothing in this repo currently sets it.
- **What's next:** Phase 10 (CI: a dedicated, visible signed-examples check — issue #27,
  depends on Phase 1, already landed on `main`), then PR 3's finalization pass and `/ship`.

### Phase 10 — CI: a dedicated, visible signed-examples check (issue #27) — DONE (2026-09-24)

- **Files touched:** `.github/workflows/ci.yml` (one new step, "Signed examples (byte-exact
  known-answer/signed-examples/ fixtures)", inside the existing `conformance` job — not a
  new job, so no new required-status-check context is introduced — positioned after
  `Install` and before `Conformance`/`Unit tests`/`Types` for fastest-useful-signal ordering;
  runs `pytest tests/test_signed_examples.py -v` with the same `AITP_SPEC` env the adjacent
  `Unit tests` step already sets; a 20-line comment explains the regression class, the
  step-not-job naming rationale, why the ordering, why not duplicated into
  `floors`/`cross-platform`, and why `aitp-rs` stays out of scope). No test/production files
  touched — this phase is CI-config-only.
- **Tests:** none in the traditional sense (the plan's own Tests field: "this phase's 'test'
  is the CI workflow file itself"). Verified locally the way CI runs it:
  `AITP_SPEC=... pytest tests/test_signed_examples.py -v` → 8 passed. Full suite unaffected
  (this phase touches no test files): `pytest tests/ -q` → 294 passed, unchanged from Phase
  9's count. `mypy aitp_verifier tests` → clean, 35 files. YAML validated via
  `yaml.safe_load` — well-formed, new step lands at the claimed position with the claimed
  `env` block, job `name:`/`matrix` fields byte-identical to before (confirmed no
  required-check-context rename).
- **Acceptance criteria confirmed:** `pytest --collect-only` from the repo root shows
  `floors`'s and `cross-platform`'s existing bundled `pytest -q` steps already collect all 8
  `test_signed_examples.py` items, confirming the "don't duplicate" call adds zero coverage
  gap, only skips a redundant fast-fail-ordering step in those two jobs. Since
  `test_signed_examples.py` was already inside the general `Unit tests` step's collection
  before this phase, a regression there already reddened the job — this phase only changes
  *when in the step sequence* that becomes visible, not *whether* CI goes red, satisfying
  the plan's "adds visibility, does not change what causes CI to go red" criterion.
- **ASSUMPTIONS.md:** none logged this phase — the step-vs-job choice, placement, and scope
  (conformance job only) were fully specified/reasoned through in the plan itself, not a
  new judgment call.
- **Docs:** the workflow file's own inline comment, per the plan's Docs field (no separate
  doc file to update).
- **Gap rounds:** 0 — PASS on first verify. Fresh Opus verifier (not critical per the
  Autonomy ladder — CI-visibility-only, no production code, no public contract) confirmed
  the step position, the zero-new-check-context claim (byte-exact comparison of `name:`/
  `matrix` fields), the non-duplication reasoning (independently re-ran
  `pytest --collect-only`), ran the new step and the full suite itself, spot-checked that
  `test_signed_examples.py`'s functions genuinely call real `aitp_verifier` entry points
  (not vacuous inline crypto), and judged the new comment's density against the file's
  existing established convention (found it consistent, not thin).
- **What's next:** PR 3's finalization pass (`/implement` §4 — Phases 9-10 collectively
  close #26 and #27) before handing off to `/ship`.

## PR 3 finalization (2026-09-24)

Phase 10 committed as `8945582` on top of Phase 9's `debd6cf`. Confirmed branch is current
with `origin/main` (no rebase needed; `main` == `origin/main` == merge-base(`main`,
`test-infra-26-27`) == `fbb0694`). Doc sweep: both phases' own `Docs` fields already applied
inline (README clause in Phase 9, `ci.yml`'s own comment in Phase 10); no further doc update
needed. No new integration-test boundary introduced by either phase (test-infra/CI-config
only) beyond what each phase's own tests already cover.

**Final whole-PR verification (fresh Opus, cumulative diff `main...HEAD`, both phases
against the plan as a whole): PASS.** Confirmed the one seam between the two phases worth
checking: Phase 10's new CI step sets the same `AITP_SPEC` env var the adjacent `Unit tests`
step already does (byte-identical expression), so it cannot accidentally trip Phase 9's new
hard-failure path in CI for the wrong reason — verified by reading every `pytest`-invoking
step across the whole workflow file (4 total, all set `AITP_SPEC`), plus confirmed a second,
independent safety net (the sibling-directory fallback resolves correctly in CI's checkout
layout even if the env var were dropped). Test-count chain re-confirmed by running, not
reading: 291 (Phase 8 baseline, on `main`) → 294 (Phase 9, both with `AITP_SPEC` set and
unset) → 294 (Phase 10, CI-config-only, no new tests). Both phases' `Status` lines in
`plans/hardening-issues-23-27.md` read `DONE`, mutually consistent with each other and with
this file's own entries. Independently re-derived the non-vacuity of Phase 9's 3 tests a
second time (against `main`'s pre-Phase-9 code: 3/3 fail; against the plan's rejected nested-
ordering design: exactly 1/3 fails, on the discriminating test, as claimed). Confirmed issue
closure for both #26 (hard `pytest.fail` naming both resolution paths + the opt-out,
verified executing both the failure and opt-out paths) and #27 (own named,
independently-attributable CI step). Three non-blocking advisories, none requiring action
before ship: (1) `plans/hardening-issues-23-27.md`'s Phase 9 prose still says "a silent
73-test skip," pre-existing plan-authoring-time text predating Phases 1-8 growing the suite,
not touched by either phase's actual diff; (2) the plan's own Phase 10 "Delivers" wording
("a distinct red status") reads in slight tension with its "Approach" section's deliberate
step-not-job choice — the plan's own Acceptance Criteria are worded correctly
("independently-attributable step") and are what was actually verified against; (3) this PR
introduces the suite's first nested-`pytest`-subprocess tests, which the `cross-platform`
job will run on Windows/macOS for the first time — code looks sound (full env passthrough,
`sys.executable`, `pathlib`, a 60s timeout), but real CI is what actually confirms Windows
behavior; `/ship`'s CI watch covers this directly.

No gaps. Ready for `/ship`.

## Ship checkpoints (PR 3)

- pushed test-infra-26-27 26ea67d
- PR #34 opened: https://github.com/agentidentitytrustprotocol/aitp-verifier-py/pull/34
- CI green: 8/8 checks passed (conformance+tests+types × 4 Python versions, 2 cross-platform,
  wheel build/smoke-test, declared-floors advisory check) — notably the first PR to exercise
  the new nested-pytest-subprocess tests (Phase 9) on `cross-platform (windows-latest, 3.13)`
  (1m7s) and `cross-platform (macos-latest, 3.13)` (26s), both confirmed passing. `call /
  auto-merge` reported `skipping` again, merged manually per `/ship`'s green-CI authorization.
- merged #34 (squash) into `main` at `bada685`, branch `test-infra-26-27` deleted. Issues #26
  and #27 confirmed auto-closed by the merge (`gh issue view` — both `state: CLOSED`). No
  deploy to watch — same pure-Python-library reasoning as PR 1/PR 2 (no `vercel.json`/
  `railway.json` in this repo).

**PR 3 (Phases 9-10) fully shipped. All 10 phases across all 3 PRs (#29, #32+#33, #34) are
now merged into `main`.** All 5 target issues (#23, #24, #25, #26, #27) confirmed CLOSED.
Follow-up issues #30 (extended) and #31 (filed) remain open by design — out of scope for
this plan, tracked separately. Next: `/reconcile` to close out `ASSUMPTIONS.md`'s 3
UNCONFIRMED entries (Phase 3 `identity_hint` flip, Phase 7 harness-scope limitation, Phase 8
`verify_snapshot_trust` hard-rejection).

## `/reconcile` (2026-09-24)

All 3 `ASSUMPTIONS.md` entries reviewed and CONFIRMED — see `DECISIONS.md` for the full
record. Phase 7 (test-harness scope note, no behavior change) settled by Opus without
escalation. Phase 3 (`identity_hint` flip) and Phase 8 (`verify_snapshot_trust`
hard-rejection) — both public verifier-behavior flips, one auth-model-adjacent and one a
security/trust-boundary — analyzed by Fable and decided by explicit user confirmation
(both CONFIRM).

Phase 8's Fable analysis directly found a genuine, previously-unknown, live security gap
in the already-merged fix: `delegation.py`'s `revocation_snapshots` guard let
falsy-but-malformed values (`""`, `0`, `False`, `{}`, `0.0`) bypass validation via an
`or []`-before-`isinstance` ordering bug, silently producing an empty (no-op) revocation
index instead of raising — the exact fail-open class issue #24 was meant to close, missed
by the original fix's test sweep (which only covered truthy scalars). Fixed same-session
(`is None` check instead of truthiness), independently re-verified by a fresh Opus agent
(PASS — confirmed the new control test genuinely discriminates absent-vs-malformed, and
swept for the same pattern elsewhere; one instance found in `minter.py:389` but confirmed
harmless, fixture-minting-only code, not fixed), shipped as PR #36, merged into `main` at
`8f03366` (CI: 8/8 green). Added `CHANGELOG.md` (new file) recording both this and the
original issue #24 fix as security-relevant behavior changes.

One cross-repo follow-up filed (read-only, no code changed elsewhere):
`agentidentitytrustprotocol/agentidentitytrustprotocol#59` — missing `man-007`
conformance vector for the oidc-`identity_hint`-forbids-`public_key` case, plus a
one-line RFC-AITP-0003 §3 prose gap.

**The whole plan is now fully closed: all 10 phases, all 4 PRs (#29, #32+#33, #34+#35,
#36), all 5 target issues, and all 3 `ASSUMPTIONS.md` entries are done.**

---

# PROGRESS (plans/hardening-issues-30-31.md)

Tracking file for `plans/hardening-issues-30-31.md` (issues #30, #31, plus a live
single-hop revocation bypass found during that plan's grounding). Appended below the
`hardening-issues-23-27` plan's own tracking section above — that plan is fully shipped
(PRs #29, #32/#33, #34/#35, #36, all merged); this section starts fresh for the new plan.

## Repo map

- `aitp_verifier/jcs.py` — Phase 1 primary edit site. `JcsError(ValueError)` at `:27-28`;
  `_serialize` at `:144-177` with its two recursive calls at `:160` (list element) and
  `:174` (dict member value); the UTF-16 sort-key line at `:166` is where the raw
  `RecursionError` surfaces today; `dumps` `:180-184`; `canonicalize` `:187-189`. No depth
  or size guard exists anywhere in the module. Measured live on `/tmp/aitpvenv313`
  (CPython 3.13.7, stock recursion limit 1000): 993-deep canonicalizes, 1200-deep raises;
  `json.loads` accepts 5,000-deep on the same interpreter, so the parser never rejects
  first. Imports nothing from the package — no cycle risk from the new constant.
- `aitp_verifier/fields.py` — Phase 1 secondary edit site. `canonical_bytes` at `:146-159`,
  its `except JcsError` at `:158-159`; `from .jcs import JcsError, canonicalize` at `:75`
  (so the monkeypatch target for the new `RecursionError`-conversion test is
  `aitp_verifier.fields.canonicalize`). Not touched by any other phase.
- `aitp_verifier/tct.py` — Phase 3 primary edit site. `verify_tct` `:88-131` (it owns the
  `now` parameter Phase 3 must thread down); the `_check_revocation(claims, inp)` call at
  `:130`; `_check_revocation` `:134-157` — `inp.get("issuer_revocation_list")` `:146`, the
  fail-open `return` at `:147-148`, `verify_snapshot_trust(revlist.get("snapshot"))` `:149`,
  the wrong-issuer silent skip at `:154-155`, the deny-list scan at `:156-157`. The
  wrapper's own `issuer`/`fail_mode` members are read nowhere in the module today.
  `check_tct_claims_shape` (`:62-85`) is NOT touched by this plan.
- `aitp_verifier/revocation.py` — Phase 3 secondary edit site (stage-4 mode dispatch only).
  Module docstring `:1-27` documents the obtained-but-untrustworthy vs. absent split both
  Phases 3 and 4 must preserve; `verify_snapshot_trust` `:111-167` (shared, unchanged by
  this plan); `verify_revocation_snapshot` `:170-192` — `policy = inp["policy"]` `:171`,
  `fail_mode = policy.get("fail_mode", "fail_closed")` `:173` (the exact default Phases 3/4
  mirror), stage 4 at `:178-187` where `fail_open` currently falls through to the
  `TCT_REVOKED` raise at `:187`, freshness formula at `:183`, deny-list scan `:189-191`.
- `aitp_verifier/delegation.py` — Phase 2 AND Phase 4 primary edit site. Single-hop body
  `:97-138` (insert the §4 step-7 check after the scope check at `:135-136`, before the
  `return` at `:138`); `check_voucher_claims_shape(vclaims, ...)` at `:129` is what makes
  `vclaims["src_jti"]` a shape-guaranteed `str` by then. `_revocation_index` `:141-177` —
  today's single caller is `:267`; absence branch `:165-167` (`None ⇒ []`, with the
  `/reconcile`-era `is None`-not-truthiness discipline at `:165-172` that must be
  preserved); index keyed on the verified `body["issuer"]` at `:176`. Multi-hop revocation
  block `:266-273`: the source-TCT check at `:268-269` is the pattern Phase 2 copies
  verbatim, and the per-hop loop at `:270-273` is Phase 4's explicit non-goal.
  `compute_chain_hash`'s raw `canonicalize` at `:82` is a fixed-depth-2 `list[str]` — not
  attacker-nestable, not touched by Phase 1.
- `aitp_verifier/voucher.py` — read-only for this plan. `_VOUCHER_REQUIRED_CLAIMS` includes
  `src_jti` with a `str` type in `_VOUCHER_CLAIM_TYPES`, which is the invariant Phase 2's
  bracket access relies on. No edits.
- `aitp_verifier/envelope.py` `:51`, `aitp_verifier/manifest.py` `:204`,
  `aitp_verifier/revocation.py` `:164`, `aitp_verifier/sessionbundle.py` `:207` — the four
  attacker-reachable `canonical_bytes` call sites Phase 1 fixes at once, each already
  passing its own `shape_code` (`INVALID_ENVELOPE` / `MANIFEST_INVALID` /
  `REVOCATION_SNAPSHOT_INVALID` / `SESSION_BUNDLE_INVALID`). None of these files is edited.
- `aitp_verifier/jws.py` — read-only. `:60-63`'s `except Exception` around `loads()` already
  catches `RecursionError` on the JWS-segment parse path; `encode_jws` `:116-127` (raw
  `canonicalize` at `:125`) is minter-only per its own docstring. No edits.
- `aitp_verifier/minter.py` — read-only for this plan, but load-bearing for the tests:
  `:379-384` signs the `snapshot`/`issuer_revocation_list` holders, `:389-391` signs every
  `revocation_snapshots` record **for any operation** (so Phase 2/4's single-hop tests need
  no minter change); `:131` canonicalizes `env["payload"]` during minting, which is the
  source of `test_boundary_contract.py`'s known mint-time skip blind spot.
- `aitp_verifier/verify.py` — `OPERATIONS` table unchanged by every phase; listed here only
  to record that no public dispatch surface moves.
- `tests/test_fields.py` — Phase 1 edit site. `canonical_bytes` block at `:96-115`
  (`test_canonical_bytes_returns_jcs_bytes_for_valid_input` `:96`,
  `..._converts_jcserror_to_aitperror` `:100`, `..._rejects_huge_int` `:108`) is the exact
  shape the new depth/`RecursionError` tests extend.
- `tests/test_envelope.py` — Phase 1 edit site. The mint-then-mutate end-to-end pattern at
  `:148-199` (`..._infinite_payload_value_does_not_crash` `:148`, `..._huge_int...` `:162`,
  and the two `_via_handshake` siblings `:172`/`:186`) injects the hostile value AFTER
  minting, which is what bypasses the harness's mint-time blind spot.
- `tests/test_boundary_contract.py` — Phase 1 edit site (one `_MUTATIONS` entry).
  `_ARTIFACT_ROOTS` `:68-80`, `_MUTATIONS` `:92-105`, `_iter_leaf_paths` `:107`, `_mutate`
  `:135` (the draft said `:145` — corrected in plan review), `_sweep` `:160-214` with its
  `except Exception` mint-time skip at `:184`, the parametrized capstone at `:214-215`. Its docstring (`:22-35`) already documents that top-level
  call-argument keys are out of mutation scope — so Phases 3/4's new top-level `policy` key
  needs no harness change.
- `tests/test_unknown_fields.py` — Phases 2, 3 and 4 edit site. `verify_tct`-with-no-
  revocation-list assertions at `:142`, `:151`, `:163`, `:186`, `:226` (these pin the
  Phase 3 default and must keep passing unmodified); `_revocation_input` `:545` and the
  `fail_mode`-toggling pattern at `:607-625` (the model for Phase 3's new
  `_tct_policy_input`); `_tct_revocation_input` `:636-657` (already carries `issuer` and
  `fail_mode`, both currently ignored by `tct.py`); the TCT-revocation trust tests
  `:658-731` (must pass unmodified under every mode);
  `test_tct_revocation_snapshot_different_issuer_does_not_apply` `:733-744` — **the one
  existing test Phase 3 flips**, since its wrapper carries `fail_mode: "fail_closed"`;
  `_load_conformance_input(spec_dir, fixture_id)` `:747` (loads a fixture `input` by id and
  carries its draft `feature` marker — reused by Phases 2 and 4 for `del-001`/`del-mh-001`).
- `tests/test_conformance.py` — `assert passed >= 51` at `:33` (the draft said `:31` —
  corrected in plan review); no phase may lower it.
- `CHANGELOG.md` — Phase 5 edit site. `## Unreleased` → `### Security-relevant` already
  established by the previous plan's two entries; four new entries append there.
- `README.md` — checked during planning: documents a per-module coverage table, the
  independence claim, conformance counts and the dev workflow, but **no** per-operation
  input-contract keys — so the new optional `policy` key needs no README change. Only the
  "53 fixtures pass" line needs re-checking in Phase 5.
- `ASSUMPTIONS.md` — Phases 3 and 4 append `UNCONFIRMED` entries (the absent-`policy`
  default, the Phase 3 test flip, the Phase 4 per-hop non-goal), in the existing
  What changed / Why / How to apply / Status format, for `/reconcile` to settle.
- Sibling spec checkout `../agentidentitytrustprotocol` (read-only, never written):
  `rfcs/RFC-AITP-0006-delegation.md:97` (§4 ordered MUST list) and `:111` (step 7, source-TCT
  revocation ⇒ `DELEGATION_SOURCE_TCT_REVOKED`); `rfcs/RFC-AITP-0008-revocation.md:25`
  (one deny-list entry invalidates the voucher and every delegation built on it), `:143-175`
  (§3.1 modes, the `fail_closed` schema default, the absent-vs-untrustworthy blockquote),
  `:177-179` (§3.2 staleness); `registries/error-codes.md:98` (`TCT_REVOKED`) and `:188`
  (`DELEGATION_SOURCE_TCT_REVOKED`) — both already registered, no new codes in this plan;
  `schemas/conformance/tct-004-revoked.json:32-36` (the `issuer`/`fail_mode` wrapper shape
  `tct.py` ignores); `schemas/conformance/del-001-success.json` (core single-hop success,
  `voucher_claims.src_jti = 550e8400-e29b-41d4-a716-446655440101`);
  `schemas/conformance/PLACEHOLDERS.md:86` (the `del-*` row, no `revocation_snapshots`
  mentioned) vs `:92` (the `del-mh-*` row, which documents it) — the doc asymmetry Phase 5's
  first spec issue notes; spec `README.md:357-362` (the `del-*` fixture table with the
  `del-002` numbering hole).

## Conformance constraints (re-derived live, 2026-09-23)

Walked every fixture in `schemas/conformance/` while writing the plan:
- `verify_tct`: 10 fixtures; exactly **one** (`tct-012`, `required_for_v0_2`) expects success
  with no `issuer_revocation_list`. `tct-004` supplies the wrapper; the other eight fail
  before `_check_revocation` is reached.
- `verify_delegation_token`: 10 fixtures; **two** expect success with no
  `revocation_snapshots` — `del-001` (`required_for_v0_2`, core) and `del-mh-001` (draft
  opt-in). Only `del-mh-004` supplies snapshots.
- No fixture anywhere exercises `revocation_policy.mode: fail_open` (all `rev-*` are
  `fail_closed` except `rev-002`, which is `soft_fail`), and none exercises RFC-AITP-0006
  §4 step 7 on the single-hop path.

These three counts are what the Phase 3/4 default rests on — re-verify them before changing
that default.

**Independently re-walked during plan review (2026-09-23) and confirmed exactly**, by
enumerating every `schemas/conformance/*.json`, grouping on `input.operation` and reading
each `expected`: `verify_tct` → 10 fixtures, exactly one (`tct-012`) succeeds with no
`issuer_revocation_list`, `tct-004` supplies the wrapper, and all eight remaining fixtures
(`rev-004`, `tct-002`/`003`/`005`/`008`/`009`/`010`/`011`) reject before `tct.py:130` is ever
reached. `verify_delegation_token` → 10 fixtures, exactly two succeed with no
`revocation_snapshots` (`del-001`, `del-mh-001`), only `del-mh-004` supplies any.
`verify_revocation_snapshot` → **7** fixtures, not 8: `rev-004` is a `verify_tct` fixture.

## Measured baseline (plan review, 2026-09-23, current `main` `adcd06f`)

- `pytest tests/ -q` → **300 passed**.
- `run_conformance.py --spec-dir ../agentidentitytrustprotocol` → **68 passed / 0 failed /
  1 skipped**.
- `mypy` → clean, **36 source files**.
- Max JSON container depth reached by any `canonical_bytes`/`canonicalize` call across the
  whole conformance run → **3** (Phase 1's own acceptance criterion re-measures this; the
  bound it must satisfy is ≤ 8).
- `canonical_bytes({"extensions": <n-deep dict>})` on `/tmp/aitpvenv313` (CPython 3.13.7,
  recursion limit 1000): **993 OK, 995 raw `RecursionError`**. `json.loads` on the same
  interpreter: **5,000 OK, 10,000 `RecursionError`**.
- Single-hop revocation bypass **reproduced live**: `del-001` + a `revocation_snapshots`
  record genuinely signed by `self_aid` listing `voucher_claims.src_jti` →
  `verify_delegation_token` returns `{'grants': ['read_data']}` today, while
  `_revocation_index` on the same input returns
  `{<self_aid>: {'550e8400-e29b-41d4-a716-446655440101'}}`. The same snapshot signed by a
  different peer indexes under that peer (fix correctly does not fire); a one-character
  signature edit raises `REVOCATION_SNAPSHOT_SIGNATURE_INVALID`.

## Verification environment

Same as the previous plan's section above — `/tmp/aitpvenv313` (confirmed present and
working, CPython 3.13.7), `python run_conformance.py --spec-dir ../agentidentitytrustprotocol`,
`pytest tests/ -v`, `mypy`. CI runs 3.11–3.14 (`.github/workflows/ci.yml:53`); Phase 1's
recursion-depth behavior should be sanity-checked on more than one of them, since the depth
cap is a fixed constant and the interpreter ceiling is not.

## PR strategy

5 phases, 3 PRs — the reasoning is recorded in the plan's own `## PR grouping and sequencing`
section rather than here: **PR 1 = Phase 1** (issue #31), **PR 2 = Phase 2** (the live
single-hop revocation bypass, highest severity, ships on its own), **PR 3 = Phases 3+4+5**
(issue #30's `policy` design landing symmetrically across `tct.py`/`delegation.py`, plus the
`fail_open` fix and the docs/changelog/spec-issue phase). One phase = one commit, even inside
a shared PR.

## Status

- **Plan reviewed (round 1, 2026-09-23): REVISE → fixes applied → SOUND.** A fresh Opus
  agent that did not draft the plan re-verified every cited file, re-walked the conformance
  pack independently, re-ran the recursion measurements, and reproduced the single-hop
  revocation bypass live. One substantive correction (Phase 3's mode-resolution precedence
  was inverted — an unsigned wrapper `fail_mode` could downgrade an explicit deployment
  `policy`) plus 13 accuracy/falsifiability fixes, all applied to the plan. See the plan's
  own `## Plan review` section for the itemized list. Ready for `/implement`.
- **Plan written (2026-09-23).** Grounded by two Opus
  subagent analyses (issues #30 and #31) plus a fresh critical-tier agent that independently
  reproduced the single-hop revocation bypass live, and re-verified while drafting by direct
  reads of `tct.py`, `revocation.py`, `delegation.py`, `voucher.py`, `jcs.py`, `fields.py`,
  `jws.py`, `minter.py`, `verify.py`, the four test modules above, `CHANGELOG.md`,
  `README.md`, `ASSUMPTIONS.md`, and the sibling spec checkout's RFC/registry/fixture files.
  Live measurements taken during drafting: the recursion boundary (993 OK / 1200 raise on
  3.13.7) and `json.loads`'s own tolerance (5,000 OK / 20,000 raise). The plan's
  `## Plan review` section lists the four claims a reviewer should re-derive first.

## Phase 1 — depth-cap `jcs.py`'s serializer, convert `RecursionError` at the `fields.py` boundary (issue #31) — DONE (2026-09-23)

- **Verdict:** PASS after 1 gap round. Round-1 fresh-Opus verifier: PASS on every code
  acceptance item; round-2 fresh-Opus verifier: **GAPS** (three items, all closed in this
  same phase — see *Gap rounds* below). Not critical per the Autonomy ladder: a mechanical
  hardening fix to shared infrastructure, no public-contract change, no one-way door.
- **Files touched:** `aitp_verifier/jcs.py` (`_MAX_DEPTH = 256` with the three-bounds
  rationale comment; `_serialize` gains `depth: int = 0` plus an entry guard raising
  `JcsError`; both recursion sites — list element and dict member value — pass `depth + 1`;
  module docstring gains the depth-cap sentence), `aitp_verifier/fields.py`
  (`canonical_bytes` gains a second `except RecursionError` clause raising `AitpError` with
  a **constant** message, `"value is too deeply nested to canonicalize"`; the existing
  `JcsError` message left byte-identical), `tests/test_fields.py` (+10: the dict-nesting
  boundary pair, the `extensions`-shaped rejection, the direct-`jcs` `JcsError`-not-
  `RecursionError` assertion, the monkeypatched `RecursionError`-conversion test, and the
  four list/mixed-nesting tests from the gap round), `tests/test_envelope.py` (+2
  mint-then-mutate end-to-end tests, direct and via-handshake), `tests/test_boundary_contract.py`
  (the `("deep-nesting", _deep_dict(2000))` `_MUTATIONS` entry plus its `_deep_dict` helper).
- **Tests:** `pytest tests/ -q` → **311 passed** (baseline 300: +9 `test_fields.py` (17→26),
  +2 `test_envelope.py`; `test_boundary_contract.py`'s count is unchanged — its new entry is
  one more mutation inside the existing parametrized cases). `run_conformance.py
  --spec-dir ../agentidentitytrustprotocol` → **68 passed / 0 failed / 1 skipped**,
  unchanged. `mypy` → clean, **36 source files** (strict; `files` covers `tests` too, so the
  new `depth` parameter and every new helper are type-checked).

### Measurement 1 — max canonicalization depth across the pack and `signed-examples/`

Required by this phase's acceptance criteria (must be ≤ 8, i.e. ≥ 30× headroom below
`_MAX_DEPTH = 256`). Measured by patching `jcs._serialize` (which every `canonicalize`/
`canonical_bytes` call funnels through, and which recurses via the module global, so the
patch covers the recursion too) to record the largest `depth` argument it ever sees, then
running the full conformance pack followed by `tests/test_signed_examples.py` in the same
process:

- conformance pack alone → **3**
- conformance pack **+ `signed-examples/`** → **4**

Both numbers were cross-checked against a second, independent metric computed at the same
time — the structural container depth of each top-level `canonicalize`/`canonical_bytes`
argument — which agreed exactly (3 and 4). So the cap sits **64× above** the deepest shape
this implementation is ever asked to canonicalize in practice; no re-derivation of the
constant is needed. (Independently re-measured three times now: once during plan review —
which reported the conformance-pack figure of 3 but did not extend the run to
`signed-examples/` — and twice during verification. The `signed-examples/` figure of 4 is
`known-answer/signed-examples/revocation/kat-keypair-001-snapshot.json`'s wrapper canonicalized
whole — `{revocation_list: {…, entries: [{…}]}}` — one level deeper than anything the
conformance pack itself canonicalizes.)

### Measurement 2 — the `deep-nesting` `_MUTATIONS` entry is vacuous for all 8 operations

Required by this phase's acceptance criteria: whether the new `test_boundary_contract.py`
entry is reachable or vacuous per operation had to be **measured, not assumed either way**.
Measured with a temporary counter around `_sweep`'s loop, restricted to the one mutation
(the test file itself is unchanged — the counter lived in a throwaway script that imports
the module's own helpers):

| operation | mutations attempted | reached the verifier |
|---|---|---|
| `verify_envelope` | 30 | 0 |
| `verify_manifest` | 79 | 0 |
| `verify_tct` | 90 | 0 |
| `verify_grant_voucher` | 16 | 0 |
| `verify_delegation_token` | 183 | 0 |
| `verify_revocation_snapshot` | 39 | 0 |
| `verify_handshake_payload` | 412 | 0 |
| `verify_session_bundle` | 172 | 0 |
| **total** | **1021** | **0** |

**Vacuous for every one of the eight operations: 0 of 1021 mutations reached any verifier.**
All 1021 die inside `mint_input`'s own `copy.deepcopy(inp)` (`minter.py:358`) — itself an
unbounded recursive walk, which blows the stack on a 2000-deep value long before the
verifier, and therefore long before this phase's guard, is ever reached. `_sweep`'s
`except Exception` mint-time skip then swallows it (`RecursionError` **is** an `Exception`),
so the entry is silently skipped both pre- and post-fix. This is a **test-harness/fixture-
minting limitation, not a production code path**: `minter.py` is imported by no verifier
module (confirmed by grep — the only mentions elsewhere are docstring prose), so its
unbounded `deepcopy` is not an attacker-reachable defect and is deliberately not fixed here.

This is the same class of blind spot the previous plan's Phase 7 recorded ("a mutation
landing on a field `mint_input` itself canonicalizes dies inside `mint_input` and is skipped
by `_sweep`'s `except Exception` before reaching the verifier"), and it is recorded the same
way: the entry is **kept anyway**, to keep the harness's hostile-value catalogue complete for
any future entry point whose minting path does not touch the mutated field — but it is
explicitly **not** this phase's proof. The proof is `tests/test_fields.py`'s direct unit
tests plus `tests/test_envelope.py`'s two mint-then-mutate tests, which inject the deep value
*after* minting and so bypass the blind spot entirely. `_deep_dict`'s docstring in
`tests/test_boundary_contract.py` states this in-file so a future reader does not mistake a
green harness run for coverage.

### Gap rounds

1 round. Round-2 fresh-Opus verifier verdict: **GAPS**, three items, all closed:

1. **(blocking) The two measurements above were not recorded in `PROGRESS.md`** — an explicit
   acceptance-criteria requirement, not an optional note. Closed by this subsection; both
   values were independently re-measured before being written down, not copied forward.
2. **(blocking) `_serialize`'s list-element recursion site had ZERO test coverage.** Every
   `_deep_dict` helper in all three test files builds nested **dicts**; nothing built nested
   **lists**, so the two independently-guarded recursion sites had one covered and one not.
   Proven exploitable by mutation: reverting that one call site's `depth + 1` back to no
   `depth` argument left the full 307-test suite green — a regression fully reopening #31 for
   list-nested values would have shipped silently. Closed by a `_deep_list(n)` helper and four
   tests in `tests/test_fields.py`: the accept-at-cap / reject-one-past-cap boundary pair for
   lists (same adjacent-depth-pinning discipline and same explicitly-stated counting
   convention as the dict pair), a direct-`jcs` `canonicalize(_deep_list(2000))` →
   `JcsError`-not-`RecursionError` assertion (necessary because at 2000 deep an unguarded list
   site raises a real `RecursionError`, which `canonical_bytes` would convert into the *same*
   `AitpError` a working cap produces — only the `jcs` layer can tell them apart), and an
   alternating-dict/list test proving the two sites share one counter (129 `{"a": [...]}`
   pairs = 258 levels, past the cap, but only 129 of each kind — so a serializer counting just
   one kind accepts it). **Hand-verified both directions:** with the list site's `depth + 1`
   removed, exactly 3 tests fail and they are all new ones (308 passed / 3 failed, no
   pre-existing test disturbed); with the *dict* site's removed instead, the 3 pre-existing
   dict tests plus the new alternating test fail. Restored, re-confirmed 311 passed.
3. **(informational, correctly out of scope) `jwk.py::issuer_keys_from` has no depth bound.**
   `jwk.py:162`, self-recursing at `:191-192`, reachable from `verify_handshake_payload` via
   `handshake.py:111` → `identity.py:175`. Reproduced live here (base fixture
   `id-009-identity-extensions-accepted`, a 3000-deep list under a `resolved_issuer_keys`
   entry → raw `RecursionError`; same with `id-001`), plus an adjacent finding from the same
   helper: a merely malformed value (`12345`) escapes as a bare
   `ValueError: unsupported issuer key value shape: int`. This predates Phase 1 entirely
   (`jwk.py` is byte-identical to `main` across this diff, last changed in `c5ecb60`) and
   involves **no `canonicalize`/`canonical_bytes` at all**, so it is structurally a different
   defect, not a miss by this phase's fix. Filed as
   **agentidentitytrustprotocol/aitp-verifier-py#38** with the reproduction, the file:line
   chain, the out-of-scope reasoning and a suggested fix shape (mirror this phase's explicit
   `depth` parameter, and convert both failure modes at `identity.py:175`). Phase 1's
   **Delivers** in the plan was narrowed in the same pass — the claim is now scoped to JSON
   "that reaches `canonical_bytes`/`canonicalize`", with #38 named inline.

- **`ASSUMPTIONS.md`:** none logged this phase — the constant, the guard placement, the
  message text and the test shapes were all fully specified by the plan (and by its own
  review round), not new judgment calls. The one genuinely non-obvious finding, Measurement
  2's vacuity result, is a *measurement* recorded here rather than an unconfirmed assumption,
  matching how the previous plan's Phase 7 recorded its analogous harness-scope limitation.
- **Deliberately not done:** de-duplicating `_deep_dict`, which now appears in all three test
  files. Each copy carries a different, load-bearing docstring (the exact counting convention
  in `test_fields.py`, the "2000 is past the interpreter ceiling, no convention is
  load-bearing here" note in `test_envelope.py`, the harness-vacuity note in
  `test_boundary_contract.py`), and this repo has no shared test-helper module today — adding
  one, or a `conftest.py` fixture, to share four lines of loop would cost more than the
  duplication and would restructure imports across three files for no behavior change.
- **What's next:** Phase 2 (the single-hop present-snapshot revocation check — PR 2, ships
  on its own).
pushed fix/jcs-depth-cap-31 a7c47dbd0de49451619f7699267d409720acef82

## Phase 1 — CI-driven follow-up (2026-09-24): two more raw-`RecursionError` escapes, found and fixed before merge

PR #39 (Phase 1) went red on `conformance + tests + types (3.11)` and `declared floors` —
green locally on 3.13, because the underlying defect is stack-headroom-sensitive across
interpreters, not a flake. Root cause: Phase 1's own new `("deep-nesting", _deep_dict(2000))`
entry in `tests/test_boundary_contract.py::_MUTATIONS` is shared by
`test_boundary_contract_identity_never_raises_a_bare_exception`, a `verify_identity`-specific
sweep neither this plan nor its two prior verification rounds knew reused that list. It
exposed a **different mechanism of the same bug class #31 targets**: an f-string calling
Python's own uncapped `repr()`/`str()` (`{x!r}`) on a value that was never type-checked before
being formatted into an error message. `jcs.py`'s `_MAX_DEPTH` guard cannot catch this — the
value never reaches `canonicalize` at all.

**Two real, live, previously-unknown instances found and fixed, same PR, before merge (not
deferred):**

1. **`identity.py:134`** (was `f"unknown identity type {itype!r}"`) — `itype = identity.get("type")`
   at `:94` has zero type check before that line. A ~2000-deep container there raises
   `RecursionError: maximum recursion depth exceeded while getting the repr of an object`
   instead of `AitpError`. Two more sites in the same file (`:210` OIDC `alg` mismatch, `:268`
   `kid` lookup) had the identical pattern and were fixed the same way; every other `!r}` site
   in the file was individually confirmed provably-already-a-`str` by an earlier
   `require_members`/`check_types`/`isinstance` gate, and left alone.
2. **`jws.py:109,116`** (`typ`/`alg` mismatch messages) — the header shape check
   (`jws.py:97-103`) validates only the member *set* (`{"alg","typ"}`), never either value's
   type, so a deeply-nested `typ`/`alg` reaches the same unguarded `{x!r}` pattern.
   **Confirmed reachable from public entry points**: `verify_tct` and `verify_grant_voucher`
   both hit it end to end. Confirmed to **crash the process (SIGBUS)**, not merely raise, on a
   1 MiB constrained thread stack at depth 5000-6000 on 3.13 — and, on a **default-sized**
   stack, CPython 3.14 (already in this repo's CI matrix) parses JSON far deeper than `repr()`
   survives (parser ceiling ~116k, `repr()` ceiling ~70k), so the same crash is reachable with
   no constrained stack at all on that interpreter. Also unbounded log amplification even
   where it doesn't crash: a few bytes of malicious JSON produced up to ~472 KB of
   attacker-chosen text in the error message pre-fix (linear in depth, not super-linear —
   an earlier "35 KB from a few bytes" framing during triage overstated this as amplification;
   the real property is "unbounded and attacker-chosen," which is what matters).

**Fix, shared:** a `describe_value(value)` helper — return `repr(value)` for a JSON scalar
(`str`/`int`/`float`/`bool`/`None`), else `f"<{type(value).__name__}>"` — added to
`fields.py` (not `identity.py`, where it was first written) once `jws.py` needed it too:
`identity.py` imports `jws.py`, so a fields.py-level home was the only option without
inverting the dependency or duplicating it. `identity.py`'s original local copy was deleted in
favor of the shared one; a test (`test_fields.py`) pins that both modules resolve to the same
object so a second copy can't silently reappear.

**Verification, both fixes:** independently confirmed by a fresh verifier (not the
implementer) for `identity.py`'s fix, which also independently re-ran the crash reproduction
and corrected its methodology (the first attempt confounded a constrained-stack crash with
dict deallocation on scope exit; re-run holding the deep value alive on the main thread
confirmed the claim cleanly) and caught that the `jws.py` sibling instance had been flagged
but not yet fixed — which is why item 2 above exists in this same round rather than being
deferred. `jws.py`'s own fix was cross-checked against all four CI interpreters locally
(3.11/3.12/3.13/3.14) via a parser-vs-`repr()`-ceiling measurement per interpreter, and the
pre-fix/post-fix suite was run on all four, not just 3.13.

**Filed, not fixed in this PR:** `agentidentitytrustprotocol/aitp-verifier-py#38` —
`jwk.py::issuer_keys_from`'s own unbounded recursion (a structurally different defect, no
`repr()`/`canonicalize` involved, predates this plan). Six sibling `{ver!r}`/`{version!r}`
sites (`tct.py:102`, `voucher.py:65`, `handshake.py:168`, `manifest.py:176`,
`sessionbundle.py:153`, `revocation.py:101`) were independently audited and confirmed safe
(each is provably a `str` by an earlier shape/type check on every code path) by two separate
verification rounds — no further action needed there.

**Final gate after this round:** `pytest tests/ -q` → **331 passed** (was 300 pre-Phase-1, 311
after the first gap-closing round, +20 more from this CI-driven round: identity.py describe
tests, jws.py's new test file, fields.py's `describe_value` unit tests); `mypy` clean, 37
source files; `run_conformance.py` unchanged at 68 passed/0 failed/1 skipped.
`plans/hardening-issues-30-31.md`'s Phase 1 **Delivers** wording, already narrowed once for
issue #38, was not further narrowed for this round — `identity.py`/`jws.py` are not
`canonicalize` call sites, so the (already-narrowed) claim was never inaccurate with respect
to them; this section is the record of the additional, adjacent hardening done in the same
PR.

## Ship checkpoints (PR 1)

- CI went red twice on first push (3.11 + "declared floors", both from the `identity.py`
  `repr()` gap above), fixed forward on the same branch/PR rather than opened as a follow-up
  — see the "CI-driven follow-up" section above for both rounds. Re-pushed, 8/8 green
  (`call / auto-merge` reports "skipping", as every PR in this repo does).
- Merged `5179952` via `gh pr merge 39 --squash --delete-branch`. Branch `fix/jcs-depth-cap-31`
  deleted, both locally and on `origin`. `main` fast-forwarded to `5179952`.
- Issue #31 closed by the merge (commit trailer `Closes #31` in the Phase 1 commit carried
  through the squash). Issue #38 (the separate `jwk.py` finding) remains open, filed but not
  fixed, as planned.
- **What's next:** Phase 2 (`delegation.py` single-hop present-snapshot revocation check —
  PR 2, the highest-severity live finding in this plan, ships on its own).

## Phase 2 — ship checkpoint (PR 2)

- Implemented, verified `PASS` (a fresh agent independently reproduced both the pre-fix
  bypass and the post-fix rejection, mutation-tested the RFC-AITP-0006 §4 step-ordering
  acceptance criterion, and behaviorally confirmed both stated non-goals don't fire), CI
  green 8/8 on first push — no fix-forward round needed this time.
- Merged `32d01b3` via `gh pr merge 41 --squash --delete-branch`. Branch
  `fix/delegation-singlehop-revocation-check` deleted, both locally and on `origin`. `main`
  fast-forwarded to `32d01b3`.
- Suite at 336 passed, mypy clean (37 files), conformance unchanged at 68/0/1.
- **What's next:** Phase 3 (`tct.py` `policy`/`fail_mode` + the `revocation.py` `fail_open`
  bug fix — the one one-way door in this plan) and Phase 4 (`delegation.py` absence-policy
  parity, depends on Phase 3) and Phase 5 (docs/changelog/conformance follow-ups) — all three
  ship together as PR 3, per the plan's PR-grouping section. **Hard constraint from that
  section, restated here so it isn't missed while branching:** PR 3 must be branched from —
  or rebased onto — PR 2's merge commit (`32d01b3`), not cut from an earlier `main`, because
  Phase 4 edits the exact call site Phase 2 just inserted, in the same file
  (`delegation.py`). Confirmed: the branch for Phase 3/4/5 is being cut from `main` at
  `32d01b3` (post-PR-2), satisfying this.

## Phase 3 — `verify_tct` gains an optional `policy`/`fail_mode` (closes #30's core) — DONE (2026-09-24)

- **Verdict:** PASS after 1 gap round (2 verification rounds total). Not critical to
  *execute* by the Autonomy ladder's usual "trust boundary" sense, but this is the plan's
  one true one-way door (a new, permanent public-input-contract member on `verify_tct`), so
  both rounds got a fresh-Opus verifier holding the plan's own security-relevant precedence
  ordering, not just its acceptance-criteria checklist.
- **Round 1:** mutation-tested the security-critical precedence ordering itself — confirmed
  the "top-level `policy` beats wrapper `fail_mode`" test provably fails under the original,
  inverted draft ordering (the exact bug the plan-review round caught and fixed before any
  code existed) — plus the `revocation.py` `fail_open` fix, the freshness-gated-on-`policy`
  behavior, and the obtained-but-untrustworthy/absent isolation. **GAPS** (4 items): a raw
  `OverflowError` on `max_staleness_secs: Infinity` (`int(inf)` in the staleness formula —
  the exact bug class issue #31 targets, on a path #31's own fix doesn't reach since the
  value never touches `jcs.canonicalize`), an undocumented non-monotonicity (an explicitly
  permissive `policy` over a stale-but-genuinely-revoking snapshot can verify where the
  identical input with *no* `policy` at all rejects, because freshness is only evaluated
  when `policy` is present), 4 untested branches, 2 doc/naming inaccuracies.
- **Round 2 (re-verify against the round-1 gap list):** all 4 items confirmed closed — `PASS`.
- **Files touched:** `aitp_verifier/tct.py` (`_FAIL_MODES`, `_resolve_fail_mode`,
  `_effective_fail_mode` — the corrected 3-rule precedence — `_apply_absence`,
  `_snapshot_is_stale`, rewritten `_check_revocation`; `verify_tct` threads its own `now`
  through), `aitp_verifier/revocation.py` (stage-4 mode dispatch: `fail_open` now returns
  `{"revoked": False, "stale": True}` instead of falling through to `fail_closed`'s raise),
  `tests/test_unknown_fields.py` (+~45 tests across both rounds), `ASSUMPTIONS.md` (2 new
  `UNCONFIRMED` entries: the no-`policy`-default-permissive decision, and the
  `different_issuer` test-expectation flip), `plans/hardening-issues-30-31.md`.
- **Tests:** commit `13a7af1` — `ASSUMPTIONS.md` +110, `tct.py` +217/-cut, `revocation.py`
  +20/-cut, `tests/test_unknown_fields.py` +529. Full suite green, mypy clean, conformance
  68/0/1 unchanged (all 10 `verify_tct` fixtures plus all 7 `verify_revocation_snapshot`
  fixtures pass exactly as before).
- **What's next:** Phase 4 (`delegation.py`, same decision applied symmetrically — depends on
  this phase and on Phase 2) and Phase 5 (docs), both landing in the same PR (PR 3) per the
  plan's hard branch-ordering constraint.

## Phase 4 — `verify_delegation_token`: the same absence policy, symmetrically — DONE (2026-09-24)

- **Verdict:** PASS after 1 gap round. Not critical to execute (reuses Phase 3's
  already-reviewed design, doesn't reopen the precedence question), but verified with the
  same rigor given it touches the exact call site Phase 2 inserted, in the same file.
- **Round 1:** the reviewer **regenerated the executor's mutation-testing proof from
  scratch** rather than taking it on the executor's word — forcing `_effective_fail_mode` to
  always return `fail_open` fails the single-hop and multi-hop test pairs *together*;
  reverting either call site alone fails only that path's half — confirming single-hop and
  multi-hop genuinely share one `_check_source_tct_revocation` implementation, not two that
  happen to agree today. Also independently reproduced the malformed-input combinations, the
  per-hop non-goal, the wrong-issuer-only case, and the staleness-not-evaluated-without-policy
  claim live. **GAPS** (1 blocking, 1 non-blocking): delegation's copy of `tct.py`'s
  `OverflowError`/missing-`max_staleness_secs` regression tests was absent (the code itself
  already carried the fix, copied correctly from `tct.py` — only the *test* coverage was
  missing) — closed same-round by mirroring `tct.py`'s two tests exactly (14 test items:
  `_BOTH_DELEGATION_PATHS` parametrized). The non-blocking note (freshness formula and
  `_FAIL_MODES` spelled out three times across `tct.py`/`delegation.py`/`revocation.py`) was
  logged to `ASSUMPTIONS.md` as a follow-up, not treated as a gap requiring this phase to
  fix — **resolved during the finalization pass below**, not deferred indefinitely.
- **Files touched:** `aitp_verifier/delegation.py` (`_revocation_index` split into
  `_verified_snapshot_bodies`/pure `_revocation_index`; new `_FAIL_MODES`,
  `_resolve_fail_mode`, `_apply_absence`, `_snapshot_is_stale`, `_effective_fail_mode` — the
  2-rule version, no per-wrapper rung since `revocation_snapshots` records carry no policy
  member — and `_check_source_tct_revocation`, called from both the single-hop and multi-hop
  sites), `tests/test_unknown_fields.py` (+~80 tests across both rounds, including the 14
  gap-closure items added directly, not via a subagent), `ASSUMPTIONS.md` (1 new
  `UNCONFIRMED` entry, explicit that it's the same decision as Phase 3's, not independent).
- **Tests:** commit `29eb603` — `delegation.py` +281/-cut, `tests/test_unknown_fields.py`
  +438, `ASSUMPTIONS.md` +74. Full suite green, mypy clean, conformance 68/0/1 unchanged
  (`del-001`/`del-mh-001` — the only two fixtures requiring success with zero revocation
  data supplied — both still pass).
- **What's next:** Phase 5 (docs/changelog/spec-repo follow-ups), then the finalization pass
  over all 5 phases together, then PR 3.

## Phase 5 — docs, `CHANGELOG.md`, and the spec-repo fixture follow-ups — DONE (2026-09-23)

Documentation-only phase, on branch `feat/revocation-policy-fail-mode` after Phases 3
(`13a7af1`) and 4 (`29eb603`). **No code or test file was touched**, by design.

- **Files touched:** `CHANGELOG.md` (four new entries), `README.md` (conformance-coverage
  section — see the decision below), `PROGRESS.md` (this section),
  `plans/hardening-issues-30-31.md` (Phase 5 status line).
- **Gate, re-run before and after, identical both times:** `pytest tests/ -q` → **461
  passed**; `mypy` → clean, **37 source files**; `run_conformance.py --spec-dir
  ../agentidentitytrustprotocol` → **68 passed / 0 failed / 1 skipped**. Unchanged, as a
  docs-only phase requires.
- **`CHANGELOG.md`:** four entries appended under the existing `## Unreleased` →
  `### Security-relevant` heading, in the plan's severity order — single-hop §4 step-7
  revocation check (Phase 2), the optional `policy` object on `verify_tct`/
  `verify_delegation_token` (Phases 3–4), `verify_revocation_snapshot`'s `fail_open` fix
  (Phase 3), and the `canonicalize`/`canonical_bytes` depth cap (Phase 1, issue #31 —
  confirmed *not* already present; Phase 1 deliberately deferred its entry to here).
  Appended after the two existing issue-#24 entries rather than interleaved by severity, so
  the already-shipped record is not rewritten. No `## 0.1.x` release heading added, per the
  phase's Edge cases. The permissive default is stated in bold in the `policy` entry —
  "an input with no `policy` key behaves exactly as it did before this key existed, and
  fail-closed is an explicit opt-in" — rather than implied, which that entry's acceptance
  criterion requires.

### Decision — `README.md` was updated, not left (and the staleness was wider than the plan measured)

The plan required an explicit choice. **Chosen: update it.** The plan's own review had
already established that `README.md`'s conformance line was stale *before* this plan started
(it read "53 fixtures pass, 0 fail"; the runner has reported 68/0/1 since well before Phase
1). Re-measured live at the end of Phase 5: still **68 passed / 0 failed / 1 skipped**, so
no verdict moved during this plan and the staleness is entirely pre-existing.

Measuring it also turned up **two further stale statements the plan had not measured**, in
the same paragraph, which is why this is a three-line correction and not the one-line one the
plan anticipated. `run_conformance.py --verbose` reports exactly **one** SKIP — `del-004`
("not required for v0.2 (draft/extension/v0.1-frozen)") — while the README claimed "Only
**two** fixtures are skipped" and listed `mh-002` as the second. `mh-002` now **passes**
(`MANIFEST_SIGNATURE_INVALID`); the README's stated reason for skipping it (the spec does not
publish the attacker key's seed) no longer describes what the runner does. Leaving the count
line corrected while the skip list next to it stayed wrong would have been worse than either
option the plan offered, so all three were corrected together:

- `README.md:53` — "**53 fixtures pass, 0 fail**" → "**68 fixtures pass, 0 fail, 1 skipped**".
- `README.md:65` — "Only **two** fixtures are skipped" → "Exactly **one** fixture is skipped".
- The `mh-002` bullet removed; the `del-004` bullet kept verbatim.

Nothing else in the section changed: the surrounding claims (the whole re-mintable v0.2 pack,
both Draft opt-ins, all multi-step sequences, the byte-for-byte KAT validation list, and the
closing "Every other required-for-v0.2 fixture … passes") were each re-checked against the
runner output and are accurate as written. Confirmed separately that `README.md` documents no
entry point's input-contract keys at all — only the per-module coverage table, the
independence claim, conformance counts and the dev workflow — so the new optional `policy`
key needs no README change, exactly as the plan predicted.

### Spec-repo follow-ups filed (read-only; no file in the spec checkout was modified)

`git -C ../agentidentitytrustprotocol status --short` clean before and after; the spec
checkout stays at `4b656b1`. Neither issue blocks PR 3.

- **[#60](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/issues/60)**
  — "Conformance pack has no vector for RFC-AITP-0006 §4 step 7 on the single-hop delegation
  path (del-002 is an unused id)". Asks for `del-002-source-tct-revoked`: a `del-001`-shaped
  input plus a `revocation_snapshots` record signed by A listing the voucher's `src_jti`
  (`550e8400-e29b-41d4-a716-446655440101`), expecting
  `failure: DELEGATION_SOURCE_TCT_REVOKED`. Verified while filing: `del-002` appears nowhere
  in the spec repo, and the only step-7 vector that exists (`del-mh-004`) is a draft opt-in
  (`required_for_v0_2: false`), so a core implementation can skip step 7 entirely and still
  pass the required pack — which is exactly how this plan's most severe finding survived a
  green pack. Carries the accompanying doc request: `PLACEHOLDERS.md:92` documents
  `revocation_snapshots` only on the `del-mh-*` row, not the `del-*` row (`:86`).
- **[#61](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/issues/61)**
  — "No conformance vector exercises revocation policy fail_mode: fail_open — one of
  RFC-AITP-0008 §3.1's three modes is untested". Asks for a `rev-0NN-fail-open` sibling of
  `rev-001`/`rev-002`: byte-identical stale snapshot, `mode: fail_open`, expecting success.
  Verified while filing: the string `fail_open` appears in **no** fixture in the pack, and
  the eight `fail_mode` literals across it are 7 × `fail_closed` + 1 × `soft_fail` — which is
  why `revocation.py` could alias `fail_open` to `fail_closed` indefinitely without a red
  test (the bug Phase 3 fixed).
- **Third candidate deliberately NOT filed**, per the plan's own judgment call: a
  `tct-0NN-no-snapshot-fail-closed` vector. Because Phase 3's default is permissive-when-
  absent, such a fixture would have to carry an explicit `policy` in its input to mean
  anything, and no `verify_tct` fixture has ever carried a `policy` object — so it is a
  request to extend the `verify_tct` *input shape*, not to add a vector. Deferred until
  after `/reconcile` confirms this repo's own default. Both filed issues stand regardless of
  how that lands.

## Finalization pass (whole-plan, before PR 3) — 2026-09-23

Per `/implement` §4: after all 5 phases individually passed their own gate, one Opus
verification pass over the *cumulative* diff (`git diff 8f03366...HEAD`, `8f03366` being the
commit immediately before Phase 1 merged) against the plan as a whole — not re-reviewing any
phase in isolation, but checking the seams between them.

- **Gates, fresh run:** 461 passed, mypy clean (37 files), conformance 68/0/1 — all unchanged.
- **Seam A (Phase 2 → Phase 4's rework of the same call site): PASS**, proven live plus
  mutation. Traced a `del-001` input plus a self-signed snapshot listing the voucher's
  `src_jti` through the current `delegation.py` end to end — correctly raises
  `DELEGATION_SOURCE_TCT_REVOKED`. Re-proved non-vacuous by neutering
  `_check_source_tct_revocation`, which then returns the pre-fix grant instead. All three
  Phase 2 negative controls (unrelated jti, other-issuer snapshot, forged signature) still
  hold. **No silent regression from Phase 4's rework of Phase 2's insertion point.**
- **Seam B (`tct.py` vs `delegation.py` behavioral equivalence): PASS**, confirmed
  behaviorally identical, not merely similar — `_resolve_fail_mode` agrees over 17 hostile
  values, `_snapshot_is_stale` over 234 cells, `_effective_fail_mode` over 60 cells, and an
  end-to-end 9-shape absence matrix agrees on every verdict class through both real entry
  points. `tct.py`'s extra rule-2 rung is the only difference, confirmed one-directional (a
  wrapper `fail_mode` never overrides a supplied `policy`).
- **Seam C (Phase 1's depth cap vs Phase 3/4's new fields): PASS.** A deep value inside
  `revocation_snapshots[].snapshot` or `issuer_revocation_list.snapshot` still hits the cap
  (`REVOCATION_SNAPSHOT_INVALID`); `policy` has no recursion surface at all (never
  canonicalized, only `.get()`-read), confirmed structurally safe across 6 spellings.
- **Automated seam coverage: PASS, not a gap** — Phase 2's five original single-hop tests
  are unmodified in Phase 4's diff and still exercise the reworked helper directly; two
  further present-snapshot × policy tests cover the interaction explicitly.
- **Context's 3 named findings: all genuinely closed**, re-verified live — issue #31 (cap
  plus boundary conversion), the single-hop bypass (Seam A), and all three of issue #30's
  sub-findings (absent wrapper now policy-governed, wrong-issuer snapshot now rejects under
  `fail_closed` where it silently passed before, wrapper `fail_mode` now read).

**Verdict: GAPS (2 items), both closed in this same pass — no second round needed.**

- **GAP 1 (medium, closed) — `verify_revocation_snapshot` leaked 8 raw exceptions on its own
  `policy`.** `revocation.py:178`/`:190` bracket-read `inp["policy"]` and
  `policy["max_staleness_secs"]` directly: a missing `max_staleness_secs` raised `KeyError`,
  `Infinity` raised `OverflowError`, `NaN`/a non-numeric string raised `ValueError`, a
  list/dict raised `TypeError`, a non-dict `policy` raised `AttributeError` — none of them
  `AitpError`. This is the same `policy["max_staleness_secs"]` formula Phase 3 hardened in
  `tct.py` and Phase 4 mirrored into `delegation.py`, left unfixed in the one module that
  actually owns RFC-AITP-0008 §3.2 — a genuine seam finding (Phase 3 edited this exact
  function four lines away for the `fail_open` fix) and a real regression risk given
  CHANGELOG entry 2's headline claim that `policy` is "one shape reused three times."
  **Fixed by consolidating the three independently-hand-copied implementations into one**:
  `FAIL_MODES`/`resolve_fail_mode`/`snapshot_is_stale` now live once in `revocation.py`
  (public within the package, added to `__all__`), imported by both `tct.py` and
  `delegation.py` in place of their own private copies — no circular import, since
  `revocation.py` already had zero dependency on either and both already imported
  `verify_snapshot_trust` from it. `verify_revocation_snapshot` now guards `policy` the same
  way the other two entry points guard theirs: a non-dict `policy` resolves to `fail_closed`
  with no staleness bound beyond `expires_at`, never a structural rejection (there is no wire
  schema for a local call argument to violate) and never a raw exception. This also closes
  the triplication follow-up Phase 4 had already logged to `ASSUMPTIONS.md` as a non-blocking
  design note — resolved here rather than left for an indefinite future cleanup.
  Added 12 new regression tests to `tests/test_unknown_fields.py`
  (`test_revocation_unusable_max_staleness_secs_is_stale_not_a_crash` ×6 hostile shapes,
  `test_revocation_missing_max_staleness_secs_applies_only_the_expires_at_bound`,
  `test_revocation_non_dict_policy_is_an_aitp_error_not_a_crash` ×5 hostile shapes). Full
  suite re-run green (473 passed), mypy clean, conformance 68/0/1 unchanged.
- **GAP 2 (low, closed) — this file had no `## Phase 3`/`## Phase 4` sections.** The trail
  broke precisely at the two phases carrying the one-way door, the security-critical
  precedence inversion, and both phases' verification rounds. Not a correctness gap (the
  content lived in the plan's own `Status:` lines and the two commit messages, both
  tracked), but `/implement` requires a timestamped per-phase entry here regardless. Added
  above, matching Phase 1's level of detail.

`plans/hardening-issues-30-31.md` already shows all 5 phases `Status: DONE`; `ASSUMPTIONS.md`
carries Phase 3's 2 entries and Phase 4's 1 entry, all logged (not transcript-only). No
`CLAUDE.md` exists in this repo, so no doc-drift check was owed there.

**Re-verification (`863e9a9` → `PASS`) and cleanup (`cfe3bfe`).** A fresh Opus agent
re-verified both gaps above closed against a live measurement (all 5 hostile `policy`
categories traced through `mint_input`-signed snapshots; non-vacuity proved by running the
12 new tests against an isolated pre-fix copy of the three files, built in the scratchpad
without touching the working tree), confirmed no import cycle and no regression (473
passed, mypy clean, conformance unchanged), and flagged two non-blocking observations:
`CHANGELOG.md` had no entry for `863e9a9`'s own behavior change, and 3 docstrings in
`tests/test_unknown_fields.py` still named the pre-consolidation private helpers. Both
closed in `cfe3bfe` (docs/comments only, re-run green). The `/ship` pre-merge gate then ran
fresh against the full 5-commit diff (`main...HEAD`), independently re-proving the
precedence invariant post-consolidation via mutation testing (inverting rule 1/rule 2
fails exactly 4 tests; forcing either module's `_effective_fail_mode` to always `fail_open`
fails 20-40 tests) and a ~100-call raw-exception hunt across all three entry points (zero
escapes) — verdict **PASS**, clear to ship.

## Ship checkpoint (PR 3) — plan complete

- Pushed `feat/revocation-policy-fail-mode` (6 commits: Phase 3 `13a7af1`, Phase 4 `29eb603`,
  Phase 5 `d75d985`, the finalization fix `863e9a9`, its changelog/docstring cleanup
  `cfe3bfe`, and this file's own re-verification addendum `f5fa0bb`). Opened
  [PR #43](https://github.com/agentidentitytrustprotocol/aitp-verifier-py/pull/43), "fix:
  verify_tct/verify_delegation_token honor an optional revocation policy (closes #30)".
- CI green 8/8 on first push (all 4 Python versions × conformance+tests+types, both
  cross-platform runners, wheel build/smoke-test, declared-floors advisory check;
  `call / auto-merge` reported "skipping" as it reliably does) — no fix-forward round
  needed.
- Merged `276f763` via `gh pr merge 43 --squash --delete-branch`. Branch
  `feat/revocation-policy-fail-mode` deleted, both locally and on `origin`. `main`
  fast-forwarded to `276f763`. Issue #30 closed by the merge (commit trailer `closes #30`
  carried through the squash) — confirmed via `gh issue view 30`.
- Suite at 473 passed, mypy clean (37 files), conformance unchanged at 68/0/1.
- **This was the last PR in `plans/hardening-issues-30-31.md`.** All 5 phases `Status: DONE`,
  both named issues (#30, #31) plus the newly-discovered single-hop delegation bypass all
  closed. **What's next:** `/reconcile` on this plan's 3 `UNCONFIRMED` `ASSUMPTIONS.md`
  entries (the absent-`policy`-default-permissive decision, spanning Phase 3 and Phase 4 as
  one decision since Phase 4's entry explicitly says so, plus the `different_issuer`
  test-expectation flip) — the last step of the plan, per its own Handoff section.

## `/reconcile` pass (2026-09-23)

Ran `/reconcile` on this plan's 3 `UNCONFIRMED` `ASSUMPTIONS.md` entries — effectively 2
distinct decisions, ranked by blast radius: the absent-`policy`-default (a genuine one-way
door spanning Phase 3 and Phase 4) analyzed by Fable and decided by the user; the multi-hop
per-hop non-goal boundary (Phase 4's second point, reversible) analyzed and settled by Opus
without escalation. Full reasoning and verdicts are logged in `DECISIONS.md`'s
`## 2026-09-23 — /reconcile on plans/hardening-issues-30-31.md` section; this checkpoint
records only the outcome and the follow-up work it required.

- **Per-hop non-goal — CONFIRMED as shipped**, Opus's independent analysis. One small,
  safe fix applied immediately: `CHANGELOG.md`'s `policy` entry now states the per-hop
  scope limit explicitly (it previously covered only the top-level default).
- **Absent-`policy` default — CHANGED.** Fable's analysis found the permissive default's
  own stated justification (three required conformance fixtures would go red under
  fail-closed) isn't actually load-bearing — `run_conformance.py` can supply the
  deployment's own `policy` for fixtures that carry none, the same role it already plays
  for `_feature`, verified live (pack stays 68/0/1, no fixture edited) — and found the
  sibling Rust implementation (`aitp-rs`) already made the stricter call on its own TCT
  path after its own security review. Presented to the user as 4 options; the user chose
  **"Require policy."**
- **Code follow-up this decision required, implemented and independently verified in this
  same pass** (a `NEEDS-CHANGE` per `/reconcile`'s own rule that a one-way-door CHANGE
  blocks shipping until its follow-up lands — now landed):
  - `tct.py`'s `_effective_fail_mode` rule 3 and `delegation.py`'s `_effective_fail_mode`
    rule 2 (its only no-`policy` rung — no wrapper fallback exists there) now raise
    `KeyError("policy")` instead of returning `"fail_open"`.
  - `delegation.py::_check_source_tct_revocation` now resolves `_effective_fail_mode`
    eagerly, unconditionally, at the top of the function — was previously resolved lazily,
    only inside the `if not applicable:` branch, which would have let a caller with
    always-fresh snapshots discover a missing `policy` key only in production.
  - `run_conformance.py` and `tests/test_boundary_contract.py`'s `_sweep` both supply
    `policy: {"fail_mode": "fail_open"}` for `verify_tct`/`verify_delegation_token`
    fixtures/mutations that carry none, mirroring how `_feature` is already supplied —
    keeping the conformance pack and the boundary-contract sweep green with zero fixture
    edits.
  - 15 tests fixed across `tests/test_boundary_contract.py` and
    `tests/test_unknown_fields.py`: some renamed and rewritten to assert `KeyError`
    instead of success, some given an explicit `policy` because they weren't testing this
    default at all, and `test_delegation_staleness_is_always_evaluated_once_policy_is_mandatory`
    rewritten entirely — its old premise (an explicit permissive `policy` over a stale
    snapshot can verify while an absent `policy` on the identical input rejects) is now
    structurally impossible to construct on `verify_delegation_token` once `policy` is
    mandatory there with no wrapper fallback. The same asymmetry still holds on
    `verify_tct`, which does have a wrapper fallback (rung 2) — documented, not fixed,
    since it isn't the decision under review.
  - Full suite green: **473 passed**, `mypy` clean (37 files), conformance pack unchanged
    at **68 passed / 0 failed / 1 skipped**.
  - **Mutation-tested for non-vacuity**: reverted both `raise KeyError("policy")` lines
    back to `return "fail_open"`, ran the 4 tests specifically asserting `KeyError`,
    confirmed all 4 failed as predicted ("DID NOT RAISE KeyError"), then restored both
    files byte-identically from a `/tmp` backup (sha256-verified) and reconfirmed the full
    suite green.
  - `CHANGELOG.md`'s previously-stale "the default is permissive" claim corrected to
    describe the mandatory-`policy` design; `ASSUMPTIONS.md`'s Phase 3/Phase 4 entries and
    `plans/hardening-issues-30-31.md`'s Phase 3/Phase 4 status lines and Open questions
    section all updated to point at the reversal rather than describe the superseded
    design as current.
- **Branch `fix/require-revocation-policy` created, committed (`7357f02`).** Independently
  verified by a fresh Opus agent against the full `main...HEAD` diff: **PASS**, with 3
  non-blocking gaps, all closed before shipping (not deferred, since they were small and
  safe):
  1. `delegation.py::_check_source_tct_revocation`'s own docstring still described the
     superseded permissive design in two places, contradicting the same commit's
     `ASSUMPTIONS.md`/test-name updates — rewritten to match, mirroring `tct.py`'s already-
     corrected (c) bullet, and to state explicitly that the stale-snapshot-over-no-`policy`
     asymmetry now survives only on `verify_tct` (which has a wrapper fallback), not here.
  2. The eager-resolution fix (moving `_effective_fail_mode(inp)` to the top of the
     function) had no regression test — reverting it to the old lazy position left the full
     suite green. Closed with a new test,
     `test_delegation_no_policy_with_a_fresh_applicable_snapshot_still_raises_key_error`
     (both single-hop/multi-hop parametrizations): a genuinely applicable, fresh,
     self-signed snapshot with no `policy` key, which under lazy resolution would never
     reach the branch that raises at all and would verify silently — exactly the gap the
     eager fix closes. Mutation-tested: reverting both the eager-resolution position and
     the dead-conjunct fix below together makes this new test fail as predicted ("DID NOT
     RAISE KeyError") on both parametrizations; restored byte-identically (sha256-verified)
     and full suite reconfirmed green.
  3. A dead conjunct, `if applicable and "policy" in inp:` — unreachable-false since
     `_effective_fail_mode`'s eager call already raises if `policy` is absent. Simplified to
     `if applicable:` with a comment explaining the guarantee and contrasting it with
     `tct.py`'s outwardly-identical-looking but *live* `if "policy" in inp:` (which stays
     live there because of the wrapper-fallback rung this entry point doesn't have).
  Full suite green after closing all three: **475 passed** (473 + the 2 new
  parametrizations), `mypy` clean (23 source files). No second verifier round dispatched —
  the original verdict was already `PASS`; these were non-blocking gaps closed on the same
  discipline this plan's earlier rounds used for non-blocking observations.
- **Optional cross-repo follow-ups Fable surfaced, left to the user's discretion, not
  required to close this pass:** a spec-repo issue proposing conformance runners supply
  the deployment's own policy for fixtures that carry none; an `aitp-rs` issue noting its
  `VerifyDelegationContext` lacks the `R3` strict-verify gate its own TCT-path sibling has.

---

# PROGRESS (plans/issue-38-jwk-issuer-keys-depth-bound.md)

Tracking file for `plans/issue-38-jwk-issuer-keys-depth-bound.md` (issue #38). Appended
below the `hardening-issues-30-31` plan's own tracking section above — that plan is fully
shipped and `/reconcile`d (PRs #43/#45, merged); this section starts fresh for the new plan.

## Repo map

- `aitp_verifier/jwk.py` — `issuer_keys_from` (lines 162-194) is this plan's primary edit
  site: its list branch (189-193) self-recurses with no depth bound. Per the plan's Round-1
  review, this becomes a public/private split — public `issuer_keys_from(value)` (unchanged
  signature) delegating to a new private, depth-guarded `_issuer_keys_from(value, depth)`, not
  a `depth` kwarg on the public function (bypassable). `issuer_key_from_jwk` (94-140) is a
  SECOND edit site (found during review, not the original issue): its `crv`/`kty` `!r`
  interpolation at lines 116/125/140 is unguarded against a container value and both leaks an
  unbounded message and can itself raise `RecursionError` during formatting — fixed via
  `fields.describe_value`, imported fresh into this module (no import cycle: confirmed
  `fields.py`/`aid.py`/`crypto.py`/`b64.py`'s own import graphs). `issuer_key_from_config`
  (143-159) is untouched — already fully bounded. Module docstring (1-28) gets a one-line
  addition naming both fixes.
- `aitp_verifier/identity.py` — `_verify_oidc` (line 106), specifically `identity.py:181`
  (`candidates = issuer_keys_from(issuer_keys.get(issuer))`) is this plan's third edit site:
  the sole call site of `issuer_keys_from`, currently catching nothing; unaffected by the
  jwk.py public/private split since the call signature here doesn't change. Per round 2's
  review, this site also gains an `isinstance(issuer_keys, Mapping) else None` guard before
  the `.get(issuer)` call — found live that a non-`Mapping` `issuer_keys` (the whole argument,
  not one issuer's value) raises a raw `AttributeError` today, contradicting the plan's own
  "every reachable shape" Delivers claim. `Mapping` is already imported (`from typing import
  Any, Mapping`, line 32), no new import needed. Its docstring's step 5 (lines 133-138)
  already draws the exact "zero candidates -> `KEY_RESOLUTION_FAILED`, retryable" vs. "target
  existed but couldn't be pinned -> `IDENTITY_FAILED`" distinction this plan's error-code
  decision (§Phase 1 step 3) leans on. The module docstring (lines 18-21) also states the same
  OIDC code mapping and needs the identical one-line addition per round 1's finding.
  `verify_identity` (line 82) is the public entry point that reaches this call site;
  `handshake.py:111` (`issuer_keys=inp.get("resolved_issuer_keys", {})`) is the only
  production caller above it.
- `agentidentitytrustprotocol/registries/error-codes.md` (sibling spec repo, lines 25-45,
  76, 80) and `agentidentitytrustprotocol/../aitp-rs/crates/aitp-handshake/tests/
  oidc_key_resolution.rs` (sibling repo, lines 1-10/142-175) — both read in full during the
  review round to ground the `KEY_RESOLUTION_FAILED` error-code decision: the former's
  normative structural-rejection table does not govern `resolved_issuer_keys` (not a listed
  schema artifact); the latter independently pins the identical resolver-hard-error ->
  `KeyResolutionFailed` line in the sibling Rust implementation. Read-only references.
- `tests/test_fields.py` (lines 282-298) — the `monkeypatch.setattr(fields, "canonicalize",
  _boom)` pattern this plan's own `RecursionError` defense-in-depth test
  (`test_identity_oidc_issuer_key_recursion_error_is_key_resolution_failed_not_a_crash`)
  mirrors, in place of the original draft's `sys.setrecursionlimit()` approach, which the
  review round measured live to be unreliable for this specific call path (the limit trips
  inside `b64url_decode`, reached earlier in `_verify_oidc`'s own gate order, before
  `issuer_keys_from` is ever called).
- `aitp_verifier/handshake.py` — read in full for this plan's grounding, NOT edited. `_verify_bootstrap`
  (line 67) at line 111 is confirmed the only place `resolved_issuer_keys` is threaded through
  to `verify_identity`; `verify_handshake_payload` (line 51) is the public dispatcher the
  plan's end-to-end regression tests exercise.
- `aitp_verifier/jcs.py` — `_MAX_DEPTH = 256` / `_serialize`'s entry-guard pattern (lines
  150-176) is issue #31's precedent this plan mirrors for its own, independently-justified,
  smaller constant (list-nesting-only recursion, not a full JSON-tree walk) — NOT imported
  from or otherwise touched by this plan.
- `aitp_verifier/fields.py` — `canonical_bytes` (lines 201-226) is the second precedent: its
  two-clause `JcsError` (interpolated message)/`RecursionError` (constant, non-interpolated
  message, "defense in depth behind jcs.py's own cap") shape is what `identity.py`'s new
  `except RecursionError` / `except ValueError` clauses mirror — the conversion itself is
  applied directly at `identity.py`'s one call site, per this module's own documented
  convention that a single remapped call site belongs at the call site, not here (see this
  file's own docstring's note on `sessionbundle.py`'s analogous remap). `describe_value`
  (lines 98-132) IS a fourth edit site (found by round 1, correction to round 0's "not
  touched" note): `jwk.py` becomes a new consumer/importer of it (§Approach step 2), so this
  module's own docstring (lines 50-56, "the modules that need it" naming exactly `jws.py` and
  `identity.py`) needs a one-line update per round 2's finding, or it goes stale.
- `aitp_verifier/minter.py` — `_resolve_times` (lines 50-63) is the one other self-recursive
  function found by this plan's repo-wide AST sweep, besides `jcs.py`/`jwk.py`. Confirmed out
  of scope: fixture/test-minting-only, never reachable from untrusted verification input —
  same reasoning `ASSUMPTIONS.md`'s Phase-8 residual-gap entry already applied to an unrelated
  `minter.py:389` finding. Not touched by this plan.
- `aitp_verifier/errors.py` — `AitpError` (line 19), the exception type both new `except`
  clauses raise. Not touched.
- `tests/test_identity_oidc.py` — this plan's primary test file. Already imports
  `issuer_keys_from`/`issuer_key_from_jwk`/`issuer_key_from_config` (line 21) and has an
  existing "jwk.py unit tests" section (~line 620 onward, ending with
  `test_issuer_keys_from_none_and_empty`) — this plan's direct `jwk.py`-level tests land
  there. Its `_verify` helper (~line 143) calls `verify_identity` directly with an
  `issuer_keys` kwarg — reused as-is for this plan's through-`verify_identity` tests, no new
  helper needed.
- `tests/test_fields.py` — `_MAX_DEPTH`/`_MAX_DEPTH + 1` test-naming discipline (lines
  164-257, issue #31's own tests) is the pattern this plan's depth-boundary tests mirror. Not
  touched.
- `tests/test_unknown_fields.py` — `_load_conformance_input` (line ~1335, loads one
  conformance fixture's `input` dict by id for mutation) and the existing
  `test_handshake_hello_*`/`test_delegation_revocation_snapshot_*` hostile-input tests built
  on it are the pattern this plan's end-to-end `verify_handshake_payload` regression tests
  follow. `_hello_input` (line 2070) is NOT reused — it builds a `pinned_key`-typed identity,
  which never reaches `jwk.py`; this plan's end-to-end tests instead load the spec repo's
  `id-009-identity-extensions-accepted` fixture (OIDC-typed, confirmed present at
  `agentidentitytrustprotocol/schemas/conformance/id-009-identity-extensions-accepted.json`)
  via `_load_conformance_input`, matching the issue's own reproduction fixture family.
- `aitp_verifier/minter.py::_mint_handshake` (lines 278-314) — confirmed this is what
  populates `inp["resolved_issuer_keys"]` for a minted OIDC fixture (line 314), as
  `{issuer: <base64url config-string>}` — the shape this plan's end-to-end tests mutate
  (`minted["resolved_issuer_keys"][<issuer>] = <hostile value>`).
- `CHANGELOG.md` — `## Unreleased` / `### Security-relevant` (lines 7-9 onward) is where this
  plan's one new entry lands, matching every prior entry's voice (what changed, why, that no
  known caller depended on the old crash since the package is unpublished).
- `registries/error-codes.md` (sibling spec repo,
  `agentidentitytrustprotocol/registries/error-codes.md:76,80`) — confirmed
  `KEY_RESOLUTION_FAILED` ("Could not resolve issuer or peer keys.", retryable) vs.
  `IDENTITY_FAILED` ("Identity binding could not be verified.", not retryable) registry text,
  grounding this plan's error-code decision. Read-only reference, not touched.
- `tests/test_boundary_contract.py` — a FIFTH edit site added by round 2's review:
  `test_boundary_contract_identity_never_raises_a_bare_exception` (reads `issuer_keys` at line
  288 but never mutates it) gains a second leaf-sweep loop over `issuer_keys` itself, reusing
  `_iter_leaf_paths`/`_mutate`/`_MUTATIONS` (lines 111-171) as-is — no new harness machinery.
  This is the capstone harness issue #23/Phase 7 built for exactly this bug class; extending it
  (rather than deferring, per an earlier draft) closes the reason issue #38 survived it.

## Verification environment

Same as every prior plan's environment section in this file — `/tmp/aitpvenv313`, same
`run_conformance.py --spec-dir ../agentidentitytrustprotocol` / `pytest tests/ -v` / `mypy`
commands. Re-verify the venv still exists before Phase 1; recreate per the command block
above if not.

Baseline confirmed green before starting (2026-09-24): `pytest tests/`: 475 passed.
`run_conformance.py`: 68 passed / 0 failed / 1 skipped. `mypy`: clean.

## PR strategy

One PR, one phase (this plan has only one phase — see the plan's own Context section for why
the depth cap and the call-site exception conversion are one atomic fix, not two: the cap
alone still leaves the pre-existing malformed-value `ValueError` escaping, and the call-site
conversion alone still leaves a `RecursionError` escaping for deep values, so neither half is
independently a complete fix). Branch: `fix/jwk-issuer-keys-depth-bound`.

## Status

- **Plan written (2026-09-24).** Grounded via direct reads of `jwk.py`, `identity.py`,
  `handshake.py`, `jcs.py`, `fields.py`, `errors.py` in full; a repo-wide AST self-recursion
  sweep across every `aitp_verifier/*.py` module; existing test files
  (`test_identity_oidc.py`, `test_fields.py`, `test_unknown_fields.py`, `test_boundary_contract.py`)
  for pattern precedent; the spec repo's `registries/error-codes.md` and
  `id-009-identity-extensions-accepted.json` fixture; and `ASSUMPTIONS.md`/`CHANGELOG.md` for
  the `minter.py`-out-of-scope precedent and changelog voice.
- **Plan review, round 1: REVISE, applied (2026-09-24).** Fresh Opus agent, reviewing against
  live code. Found the public `depth` kwarg was bypassable (fixed via a public/private split
  mirroring `jcs.py`'s own `_serialize`/`dumps` split), the proposed
  `sys.setrecursionlimit()` test was unreliable for this call path (measured live; replaced
  with `test_fields.py`'s own `monkeypatch` pattern), a real adjacent `crv`/`kty`
  message-construction hazard in `jwk.py` not closed by the depth cap (folded in as a new
  edit), the sweep-coverage claim overstated, the error-code grounding under-cited (added the
  normative-table-scope argument and the `aitp-rs` cross-implementation precedent), a stale
  `identity.py` module-docstring gap, several citation slips, and recorded the
  `test_boundary_contract.py` blind spot as a deliberate deferral. All applied to the plan
  file directly.
- **Plan review, round 2: REVISE, applied (2026-09-24).** Fresh Opus agent, checking round 1's
  fixes plus one independent pass. Confirmed all 8 round-1 fixes hold, then found: a
  fabricated "free-form" docstring citation (fixed — replaced with a schema-grep + real
  `handshake.py:111` citation); the fault-injection acceptance criterion wrongly claimed the
  exact-boundary tests fail pre-fix with `RecursionError` (they don't — 17 levels resolves
  fine with no cap present; criterion rewritten to give crash-reproducing tests and
  boundary-pinning tests their own correct non-vacuity checks); a live repro proving
  `issuer_keys` itself being non-`Mapping` raises a raw `AttributeError` today, contradicting
  the plan's own Delivers claim (fixed — added the `isinstance(issuer_keys, Mapping)` guard,
  a new edge case, a new acceptance criterion, and new tests, rather than left scoped out);
  the `test_boundary_contract.py` deferral's stated reason didn't survive a live check against
  the actual harness code (it's ~10 lines reusing existing machinery, confirmed green live —
  now done in this phase instead of deferred); `fields.py`'s own `describe_value`-consumers
  docstring sentence going stale (added to Files/Docs); an overstated "O(1)" cost claim
  (restated as "cost-bounded", matching `fields.py`'s own wording); and several cosmetic
  citation nits (one of the reviewer's own proposed corrections, for `minter.py:50-63`, was
  independently re-checked against a fresh direct read and found to already be correct in the
  plan — left unchanged). All substantive items applied to the plan file directly.
- **Two review rounds run, per the plan's own cap.** Both rounds' findings were concrete,
  cite-backed, and directly fixable (not genuine requirements ambiguity), so per the cap this
  plan is not sent for a third round — ready for `/implement`.

## Phase 1 — depth-cap `issuer_keys_from`, bound its sibling's message construction, guard the one call site against every reachable shape, and close the class-level test-harness gap — DONE (2026-09-24)

**Diff:** `aitp_verifier/jwk.py` (public/private `issuer_keys_from`/`_issuer_keys_from` split,
`_MAX_DEPTH = 16`, `describe_value` at the three `crv`/`kty` message sites, module docstring),
`aitp_verifier/identity.py` (`isinstance(issuer_keys, Mapping)` guard + two-clause
`except RecursionError`/`except ValueError` conversion to `AitpError("KEY_RESOLUTION_FAILED")`
at `_verify_oidc`'s one call site, module + `_verify_oidc` docstring updates),
`aitp_verifier/fields.py` (`describe_value` docstring: `jwk.py` added as a third
consumer/importer), `tests/test_identity_oidc.py` (+13 tests, final count including the
follow-up commit below: 7 direct `jwk.py`-level, 6 through-`verify_identity`, matching the
plan's Tests section), `tests/test_unknown_fields.py`
(+4 end-to-end tests through `verify_handshake_payload` against the `id-009` `mutual_hello`
fixture), `tests/test_boundary_contract.py` (second leaf-sweep loop over `issuer_keys` inside
`test_boundary_contract_identity_never_raises_a_bare_exception`), `CHANGELOG.md` (one
`### Security-relevant` entry matching the `jcs.py`/issue #31 entry's voice). Two divergences
from the plan's exact prose, both recorded inline in `plans/issue-38-jwk-issuer-keys-depth-bound.md`'s
own Phase 1 section: the 4 end-to-end test names omit the plan's `_hello_` infix
(cosmetic only), and `test_issuer_keys_from_past_max_depth_raises_value_error_not_recursion_error`
uses a well-formed JWK leaf rather than the section's usual sentinel string, found necessary
during fault-injection (see below).

**Verification:**
- Full suite as of this commit (`6781415`, before the follow-up commit below): 491 passed
  (baseline 475 + 16 new: `test_identity_oidc.py` 57→69, `test_unknown_fields.py` 285→289).
  Final count after the follow-up commit's added test: 492 (`test_identity_oidc.py` 57→70,
  +13). `test_boundary_contract.py` stays at 9 test functions throughout — the new sweep is a
  second loop inside an existing one, not a new test.
- `mypy`: clean, "Success: no issues found in 37 source files".
- `run_conformance.py --spec-dir ../agentidentitytrustprotocol`: 68 passed, 0 failed, 1 skipped
  — unchanged from baseline, as the plan's acceptance criterion 10 predicted (no fixture
  exercises `resolved_issuer_keys` hostility).
- **Fault-injection (acceptance criterion 11), all performed live against this diff, not
  assumed:**
  - Reverted `jwk.py`/`identity.py`/`fields.py` to `HEAD` (via `git stash push --keep-index`,
    scoped to just those three files so the test edits stayed in place) and ran the 4
    end-to-end crash-reproducing tests in `test_unknown_fields.py`: all 4 failed, each with its
    exact claimed bare exception — `RecursionError: maximum recursion depth exceeded` (deep
    nesting), `ValueError: unsupported issuer key value shape: int` (malformed scalar),
    `RecursionError: maximum recursion depth exceeded while getting the repr of an object`
    (deeply nested `kty`), `AttributeError: 'str' object has no attribute 'get'` (non-Mapping).
    Restored via `git stash pop`.
  - **Process note:** the `git stash pop` initially left `jwk.py` on a later, unrelated
    `git checkout -- aitp_verifier/jwk.py` call made to revert a separate temporary
    fault-injection edit — that command discards a file's entire working-tree state, not just
    the one line intended, and wiped the whole Phase 1 `jwk.py` fix since it had never been
    committed. Recovered by re-reading the reverted file and re-applying the exact same edits
    from this session's own record of them; `git diff aitp_verifier/jwk.py` after recovery is
    byte-for-byte the intended fix (confirmed against a scratchpad backup taken just before,
    and against the full suite/mypy passing again after). Lesson applied for the rest of this
    pass: fault-injection reverts on uncommitted files now use `Edit` to change/restore the
    exact line, never `git checkout` on a file with unstaged work.
  - Boundary-pinning tests (criterion 2/3, at/past `_MAX_DEPTH`): temporarily changed the
    guard to `if depth > 999999:` (via `Edit`, reverted via `Edit`). This is what surfaced the
    vacuous-leaf finding recorded in the plan's own Divergence notes — the past-cap test, as
    originally written with the section's sentinel-string leaf, stayed green even with the cap
    fully defeated (the sentinel string fails `issuer_key_from_config`'s own length check
    independent of any cap). Fixed by switching that one test's leaf to a well-formed JWK; with
    the cap defeated the fixed test now correctly fails (`Failed: DID NOT RAISE ValueError`),
    and with the cap restored it passes.
  - Monkeypatch test (criterion 6): temporarily removed `identity.py`'s
    `except RecursionError` clause (via `Edit`, reverted via `Edit`, `except ValueError`
    clause untouched). The monkeypatched `RecursionError` then escaped uncaught as expected,
    confirming the clause — not something else — is what the test is pinned to.
  - Final state re-confirmed: full suite 491 passed, `mypy` clean, `run_conformance.py`
    68/0/1, `jwk.py` identical to the scratchpad backup taken before fault injection began.

**Tracked-file closeout:**
- `plans/issue-38-jwk-issuer-keys-depth-bound.md` — Phase 1 `Status: DONE`, divergence notes
  added inline.
- `ASSUMPTIONS.md` — no entry needed. Every judgment call made during implementation (test
  leaf content, exact test names) was mechanical/cosmetic, not a genuine ambiguity the plan
  left open; the plan's own Open Questions section already confirms nothing was escalated.
- Local `docs/`/`CLAUDE.md` — none reference `jwk.py`/`issuer_keys_from` (confirmed: no repo
  `CLAUDE.md`/`docs/` directory exists at this repo's root beyond `README.md`), so nothing
  else needed updating beyond the module docstrings already in the diff.

**Verification gate (§2): fresh Opus subagent, independent — PASS (2026-09-24).** Read the
plan and the diff cold, then independently ran the full suite (491 passed), `mypy` (clean),
`run_conformance.py` (68/0/1), and 8 of the 11 acceptance criteria by direct experimentation
(throwaway probe scripts, not by trusting the tests) — including sweeping depths 13-19 live to
confirm the cap fires at exactly `_MAX_DEPTH + 1`, confirming all three `describe_value` sites
live on 20000-deep containers, and independently re-running every fault-injection from
acceptance criterion 11 (cap defeated, `except RecursionError` removed, `identity.py` reverted
to pre-fix, all three `describe_value` calls reverted to `!r`) with matching results. Verdict:
`PASS`. Four non-blocking follow-ups, all closed same-session rather than deferred (all were
"not critical" per the Autonomy ladder — reversible, cheap, no re-verify round needed):
- **(a) Duck-typed-`Mapping` silent downgrade** — `isinstance(issuer_keys, Mapping)` only
  recognizes types registered with/subclassing `collections.abc.Mapping` (unlike
  `Hashable`/`Iterable`/`Sized`, `Mapping` defines no `__subclasshook__`), so a caller's own
  duck-typed resolver wrapper exposing only `.get()` would silently read as "no issuer key
  resolvable", indistinguishable from a genuinely absent issuer. Documented in place
  (`identity.py`, the guard's own comment) rather than changed — `dict` and every stdlib
  mapping type are registered, so this only affects a caller's own unregistered mapping-like
  class, and registering it is the caller's own cheaper fix.
- **(b) AC7 test-coverage gap** — the plan's Tests section specified only an OKP-branch `crv`
  message-safety sibling test, but AC7 itself names `kty in {"OKP","EC"}`; added
  `test_issuer_key_from_jwk_deeply_nested_crv_under_ec_does_not_crash_the_message` to close it
  (`jwk.py:135`'s own `crv` guard was already correctly implemented — only the test was
  missing).
- **(c) `PROGRESS.md` count error** — this file's own Verification section said "+14 tests:
  6 direct + 6 through" (14 ≠ 6+6=12) and "`test_identity_oidc.py` 55→69" (should be 57→69);
  both corrected above.
- **(d) Breadth/key-size follow-up filed as a separate issue**, not folded into this phase:
  `issuer_keys_from` has no cap on JWKS candidate count (200,000 entries parsed in ~0.6s in the
  verifier's own probe) and `PublicKey.from_rsa_numbers` has no RSA-modulus upper bound —
  genuinely orthogonal to issue #38's own depth-recursion/bare-exception scope (neither is a
  crash — both simply cost more than they should on hostile resolver input) —
  [issue #47](https://github.com/agentidentitytrustprotocol/aitp-verifier-py/issues/47).

Also tightened the `CHANGELOG.md` entry's wording per the verifier's finding that
"unbounded-message ... hazard already closed" read as claiming more than `describe_value`
actually guarantees — a `kty`/`crv` that is itself a huge *scalar* string still renders in
full (matching `fields.py`'s own "cost-bounded, not O(1)" framing); only the container/
RecursionError dimensions are closed. Re-ran full suite (492 passed, +1 for item (b)) and
`mypy` (clean) after applying (a)-(d) and the wording fix.

## Finalization pass (`/implement` §4, whole-feature) — 2026-09-24

Cumulative diff `ff601ce..HEAD` (commits `6781415` + `4371150`), reviewed as one feature by a
fresh Opus subagent, independent of both prior verification passes:

- **Full suite / mypy / conformance:** re-run independently — 492 passed, `mypy` clean,
  `run_conformance.py` 68/0/1 — and cross-checked on CI's floor (3.11.15) and ceiling (3.14.6)
  Pythons in throwaway envs, all clean.
- **Integration-test-gap check (§4's own explicit ask):** confirmed by *positive control* — the
  agent minted the unmutated `id-009` fixture itself and confirmed it verifies successfully
  through the real `verify_handshake_payload` first, establishing every gate ahead of
  `_verify_oidc` (manifest, envelope, OIDC proof) is genuinely satisfied before any hostile
  mutation is applied, then confirmed all three seams this feature touches are covered
  together: `handshake.py` → `identity.py` → `jwk.py` (4 e2e tests, each independently
  fault-injected), `identity.py` → `jwk.py` (6 through-`verify_identity` tests + the 108-call
  boundary sweep), and `jwk.py` alone (7 direct unit tests).
- **Docs check:** independently confirmed no `docs/`/`CLAUDE.md` exists and `README.md`'s only
  `jwk` reference (line 32, the thumbprint role) says nothing about issuer-key resolution —
  nothing left stale.
- **Follow-up commit `4371150` re-audited on its own:** confirmed the `identity.py` change is
  comment-only (zero behavior change), the one new test is genuinely non-vacuous (fault-injected
  independently), and nothing new was added unverified.
- **Whole-feature Delivers claim:** independently probed ~40 additional hostile shapes beyond
  what any test covers (the JWKS branch's `keys: [<non-dict>]` case specifically hunted for and
  confirmed closed by `issuer_key_from_jwk`'s pre-existing `isinstance` guard at `jwk.py:116`;
  containers on every JWK member across all three key-type branches; malformed config strings;
  an integer mapping key) — all converge on `AitpError("KEY_RESOLUTION_FAILED")`. Confirmed both
  defense layers (the depth cap and the `except RecursionError` clause) are independently
  load-bearing, not redundant: a cap-only fault-injection leaves the ~3000-level e2e test green
  via the exception clause, and a clause-only fault-injection leaves it failing via the cap.
- **`ASSUMPTIONS.md`/issue #47 re-confirmed:** `git diff ff601ce..HEAD -- ASSUMPTIONS.md` is
  empty; issue #47 confirmed open and correctly self-scoped as non-blocking follow-up work, not
  a gap in this feature.

**Findings, none blocking:** (1) a `Mapping`-subclass whose own `.get()` raises a non-`ValueError`/
`RecursionError` propagates raw — explicitly *not* filed as a gap: this is hostile caller code
executing inside a caller-supplied object, the same property every argument in this library
shares (a `trust_anchors` whose `__iter__` raises, etc.), and closing it would need a blanket
`except Exception` this repo deliberately avoids; the real path always hands a JSON-deserialized
dict, so the actual data-shape threat surface is fully closed. (2) `PROGRESS.md`'s own test
counts had drifted by one after the follow-up commit's 13th test (the very sentence a prior
fix corrected was made stale again by the next fix) — corrected above (see the Files list and
Verification bullet earlier in this section). (3) `uv.lock` is untracked and un-gitignored, a
local `uv run` artifact from this session, not a feature change — flagged as a hygiene note for
`/ship` so a broad `git add` doesn't sweep it in accidentally; not part of this diff.

**VERDICT: PASS.** Ready to ship as-is.

**What's next:** hand off to `/ship`. No `/reconcile` needed (no `ASSUMPTIONS.md` entries this
plan; issue #47 is a filed, correctly-scoped follow-up, not an open assumption). Before
pushing/opening the PR, do not `git add -A`/`git add .` — stage tracked files explicitly, the
same way each commit in this phase already did, so the untracked local `uv.lock` (finding 3
above) isn't swept in.

## `/ship` (2026-09-25)

- **Synced with `origin/main`:** 0 behind, 4 ahead — no rebase needed.
- **Pre-merge verification gate: fresh Opus subagent, independent — PASS.** Re-verified from
  scratch (not trusting the two prior `/implement`-phase passes): re-ran the full suite (492
  passed), `mypy` (clean), `run_conformance.py` (68/0/1); independently swept the depth-cap
  boundary (0-24 levels, including a 200,000-deep and a self-referential list); confirmed
  `describe_value`'s message-safety fix at all three sites; confirmed the non-`Mapping` guard
  across 7 hostile shapes; **diffed pre/post against a real `origin/main` worktree** and
  confirmed all five hazards escape raw on `main` (3× `RecursionError`, 1×`AttributeError`,
  1×`ValueError`) and all five convert to `AitpError KEY_RESOLUTION_FAILED` on this branch —
  one more hazard than the three the CHANGELOG originally named (the malformed-scalar
  `ValueError`, which also escaped unconverted pre-fix); confirmed both defense layers (cap +
  `except RecursionError`) are independently load-bearing by defeating each in turn; probed
  ~25 additional hostile JWK shapes beyond any test, found no non-`ValueError` escape; and
  confirmed `retryable=True` is spec-mandated (`registries/error-codes.md:80`), not a judgment
  call. Verdict: PASS, with 4 non-blocking nits — two stale `identity.py:181` line references
  in test comments (the call site moved to `:210` across this branch's commits) and the
  CHANGELOG's "all three" undercount (fixed to "all four", closing the same gap the pre/post
  diff found independently); a `resolved`-name-reuse readability nit (left as-is, confirmed no
  mypy-coverage cost); and the already-flagged `uv.lock` hygiene note. Fixed the two
  substantive nits in commit `d832e7e`.
- **Pushed:** `fix/jwk-issuer-keys-depth-bound` @ `d832e7e3ac5c3d9eb7104e84306bc0e4c2197752`.
- **PR #48 opened:** https://github.com/agentidentitytrustprotocol/aitp-verifier-py/pull/48
- **CI:** all 8 jobs green (wheel build/smoke-test, cross-platform macOS/Windows @ 3.13,
  conformance+tests+types @ 3.11/3.12/3.13/3.14, declared-floors install) — squash-merged as
  `13093ca`, branch deleted, issue #38 closed automatically via the PR title. No deploy to
  watch (library package, no `vercel.json`/`railway.json` in this repo).
