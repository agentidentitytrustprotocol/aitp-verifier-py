# docs-refresh

## Context
Docs-only change. README.md is the only user doc (no `docs/`, no CLAUDE.md). Verified against code
(`python3 run_conformance.py --spec-dir ../agentidentitytrustprotocol` → 71 pass / 0 fail / 1 skip):
- README says "68 fixtures pass" → actually 71 (spec added fail_open rev-009, RFC-0006 §4 step 7 vector, etc.). One skip is still del-004.
- Module table omits modules that exist: `fields`, `verify` (operation registry), `minter`, `errors`, `keys`, `sigfield`, `b64`, `timeutil` (`aitp_verifier/`).
- Says surfaces "promoted to Final" and quotes VERSIONING.md; spec now uses one status ladder (Draft→…→Accepted, rfcs/README.md) and VERSIONING.md has no such quote (only identity types "graduate to Stable once two independent implementations interoperate", VERSIONING.md:63).
- "RFC-AITP-0001…0013" glosses over 0012 (Reserved) / 0013 (Planned) — they are not implemented here beyond the `extensions` slot (fields.py).
- No link to the error-code registry (`registries/error-codes.md`), no mention that aitp-rs pins this repo for cross-impl `xcheck` (aitp-rs/docs/testing.md, docs/conformance.md), no usage/boundary-contract section.
- Spec docs link to README anchor `#conformance-coverage` (implementer-quickstart.md:168) — heading must stay.
- CHANGELOG.md already covers issues #24–#54 (matches git log); only verify, no rewrite.
Principle: link sibling docs, never copy their content (counts of spec fixtures, RFC prose, error tables).

## Phases
### P1 — README + metadata refresh  (Status: DONE)
- **Delivers:** accurate README; verified links.
- **Depends on:** none. **Files:** `README.md`, `pyproject.toml` (description string only), `aitp_verifier/__init__.py` (docstring wording only), `CHANGELOG.md` (add #23 entry).
- **Approach:** (1) fix pass count to 71/0/1; avoid pinning a count in prose where possible ("see run_conformance.py output") — state current number once with command. (2) Complete module table incl. support modules, one line each, RFC section cites checked against the RFC files. (3) Replace Final-promotion wording with links to `VERSIONING.md` and `rfcs/README.md` status ladder; no quotes. (4) RFC range sentence: name implemented RFCs (0001–0011) and note 0012/0013 status by link. (5) Add "Usage & boundary contract" (verifiers raise only `AitpError`; error codes → link `registries/error-codes.md`; no network I/O). (6) Add "Cross-implementation" section linking aitp-rs `docs/testing.md#cross-implementation-acceptance-xcheck` and `docs/conformance.md`. (7) Development: keep commands, verify against ci.yml/pyproject. Keep `## Conformance coverage` heading. Use GitHub URLs for sibling links (matches how siblings link here).
- **Edge cases:** broken anchors; stale counts; pasting sibling content (rejected: duplicates drift).
- **Acceptance:** every sibling link resolves to an existing file/heading in the sibling checkout; every module in `aitp_verifier/` appears in README; README numbers equal runner output; no "Final promotion" quote; `#conformance-coverage` heading present; `pytest` and `mypy` still pass; no non-doc code change.
- **Tests:** run `python3 run_conformance.py`, `pytest`, `mypy`; script check of links/headings.
- **Docs:** this is the docs phase.

## Long-term posture
No one-way doors. Avoid hardcoded counts to reduce future drift.

## Open questions
None critical. Decision (Opus): no new docs/ tree — repo is small; README + links suffice.

## Repo map
README.md (only user doc), CHANGELOG.md (security changelog, current), aitp_verifier/* (verification core), run_conformance.py, tests/, pyproject.toml, .github/workflows/ci.yml, plans/archive/.

## Plan review
Round 1 (fresh Opus): REVISE. Applied: (a) "Final promotion" wording is stale in README:3-5, pyproject.toml:8, __init__.py:5-6 — spec gate lives in governance/RFC-PROCESS.md, not VERSIONING.md; link it and drop "requires". (b) Implemented-RFC claim narrowed: 0001–0006, 0008, 0010, 0011 have modules; 0007 only caller-supplied key handling, 0009 threat model, 0012 `extensions` slot only, 0013 none. (c) Boundary contract limited to verifier entry points (jcs raises JcsError, minter MinterError). (d) xcheck section notes aitp-rs pins this repo via tests/AITP_VERIFIER_PY_VERSION (older commit) and the reverse direction (minter → session-bundle fixture). (e) Keep `#conformance-coverage` heading and aitp_verifier/tct.py, jws.py paths (linked from spec docs). (f) README Development: pytest resolves spec via $AITP_SPEC then sibling dir (no --spec-dir). (g) CHANGELOG gains an issue #23 entry. Verdict after revision: SOUND.
