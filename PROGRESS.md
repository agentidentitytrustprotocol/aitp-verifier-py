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
- Phase 3: TODO
