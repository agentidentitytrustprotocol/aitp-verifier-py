# aitp-rs 0.17.0 / aitp/0.3 conformance and interop alignment

## Context

Supersedes `plans/aitp-rs-0.15-adoption.md` (written 2026-10-19, never committed). It now
targets aitp-rs **0.17.0** (published 2026-10-20) and protocol **aitp/0.3** at spec `bf00e75`.

`aitp-verifier-py` is an independent implementation. It has **no dependency on aitp-rs**
(`pyproject.toml` depends only on `cryptography`), so the current pin is "none", and there is
nothing to bump. The two implementations meet in two places:

1. **Spec fixtures, floating.** CI checks out spec `main` on every push and in a daily 06:17 UTC
   canary (`.github/workflows/ci.yml`). Spec `origin/main` is still `bf00e75`, with no new fixtures
   since #65. The only open spec PR, #92, is docs-only ("no wire, fixture or vector change").
2. **aitp-rs `xcheck`.** `aitp-rs/tests/AITP_VERIFIER_PY_VERSION` = `f335f4f`, this repo's
   `main` HEAD. `aitp-rs/scripts/xcheck-verify.py` imports this package and calls
   `verify_session_bundle`, `verify_envelope` and others directly (`xcheck-verify.py:262-270`, :437).

**Most of the 0.15 plan was done by PR #65** (merge `f335f4f`, closes #64 and #59):

- aitp/0.3 strict cutover (`aitp_verifier/version.py`).
- Envelope signing input v2.
- RFC-AITP-0001 §5.4 receive order.
- Manifest-sourced key resolution for bundles and for single-hop and multi-hop delegation
  (`manifest.py::resolve_key_from_manifests`).
- README counts.

Measured today against spec `bf00e75`:

- `python3 run_conformance.py --spec-dir ../agentidentitytrustprotocol`: **93 passed, 0 failed,
  9 skipped**. All skips are non-core (`del-004`, `id-013..016`, `id-019..022`).
- `AITP_SPEC=... pytest -q`: **604 passed**.
- `mypy`: clean.
- The last CI runs on `main` (push of `f335f4f`, canary 2026-10-20 11:31Z) are green.

No open PRs. No open issues; #59 is closed.

**What remains is small:** two of the four #262 envelope schema rules, the 0.16 TCT-vs-Manifest cap
for bundles, and the runner profile gate. Plus one policy decision: whether Manifests become
mandatory.

## aitp/0.2 artifacts in this repo

None need action. All three remaining hits are intentional:

- `CHANGELOG.md:12` documents the cutover.
- `aitp_verifier/version.py:4` is the docstring.
- `tests/test_envelope.py:313-316` is the strict-cutover negative test.

No `v0.2/` schema `$id`s and no "AITP v0.2 …" claim strings remain. `samples/` is clean. Nothing
is vendored: the spec is checked out live, and there are no seeded DB rows or cached Manifests.

## Impact table (0.15 + 0.16 + 0.17)

| Change | Affected? | Where | Action |
|---|---|---|---|
| 0.17 #254 aitp/0.3 literal, strict cutover | Done (#65) | `version.py`; every checker | None |
| 0.17 #254 envelope signing input v2 | Done (#65) | `envelope.py:57-62` | None |
| 0.17 #254 receive order: version → member set → signature | Done (#65) | `envelope.py:88-97` | None |
| 0.17 #259 HTTP server §3.1 order (replay/rate/timestamp before structure) | Done where applicable. No server, replay or rate-limit state. `verify_envelope` runs the window before `validate_envelope_shape` (`envelope.py:116-122`). aitp-rs §4 says its fall-through "follows aitp-verifier-py at f335f4f". | `envelope.py:116-122`; `handshake.py:65` has no window by design | None |
| 0.17 #262 `payload` must be an object | Already enforced (`_ENVELOPE_TYPES`) | `envelope.py:44-47` | None (add a regression test, Phase 1) |
| 0.17 #262 `"extensions": null` rejected | Already enforced: `None` is not `dict` → `INVALID_ENVELOPE` | `envelope.py:44-47`, `fields.py:191-200` | None (regression test, Phase 1) |
| **0.17 #262 `timestamp >= 0`** | **Yes, not enforced.** With the window disabled, a negative timestamp reaches the signature step: `INVALID_SIGNATURE`, where aitp-rs gives `INVALID_ENVELOPE`. The handshake path has no window, so it hits this directly. | `envelope.py:93-94` | Phase 1 |
| **0.17 #262 signature pattern `^((ed25519\|p256)\.)?[A-Za-z0-9_-]{86}$`** | **Yes, not enforced at structure.** Short, padded, `+` or `rsa.` all give `INVALID_SIGNATURE` from `sigfield.py:22-40`; aitp-rs gives `INVALID_ENVELOPE`. | `envelope.py:93-97` (add the check); `sigfield.py` unchanged | Phase 1 |
| 0.17 #260 bindings `verify_envelope`/`sign_envelope` | Not applicable (bindings). This repo's `verify_envelope` already exists. | n/a | None |
| 0.16 #237 single-hop delegation via issuer Manifest | Done when supplied (#65) | `delegation.py:126-132`, :147 | See Phase 3 (mandatory?) |
| 0.15 #234 multi-hop hop keys via issuer Manifests | Done when supplied (#65); del-mh-005 passes | `delegation.py:449-450` | See Phase 3 |
| 0.15 #197 / 0.16 #238 bundle coordinator Manifest (step 5) | Done when supplied (#65); bundle-007 passes | `sessionbundle.py:199-203` | See Phase 3 |
| **0.16 §4 participant TCT `exp` capped at coordinator Manifest `expires_at`** | **Yes, missing.** aitp-rs → `BUNDLE_PARTICIPANT_TCT_INVALID` (`ExpiresAfterManifest`). | `sessionbundle.py:218-255` (participant loop); logic to reuse at `tct.py:174-175` | Phase 2 |
| 0.15 #194 runner gate on `required_for_v0_2`, `--profile` | **Yes, missing.** A core fixture that turns into SKIP (`run_conformance.py:105`, :127, :132) stays green; exit is FAIL-only (:213). | `run_conformance.py:187-213` | Phase 4 |
| 0.15 #239 / spec #86 fixtures carry `issuer_manifests` / `coordinator_manifest` | Done (#65); the minter handles them | `minter.py:385-386` | None |

Not affected (no network, session store, bindings, or renewal):

- `CheckedJson` / `unknown_field` (already covered by `tests/test_unknown_fields.py`)
- pinned admission 429/503
- ListRevoked default
- handshake server defaults
- renewal replay guard (RFC-AITP-0013 Planned)
- bindings parity
- `cnf_jkt` (#240)
- claim-string rename (no emitter)

## Phase 1 - Envelope schema rules (aitp-rs #262 parity)

**Status:** DONE

Steps (`aitp_verifier/envelope.py::validate_envelope_shape`, after `check_types` and before the
`sender` checks, so the order stays version → member set/structure → signature):

1. `timestamp`: reject a value below 0 → `INVALID_ENVELOPE`. Keep the integral-float admission
   (`fields.py:197-198`); see Open question 3.
2. `signature`: `re.fullmatch(r"((ed25519|p256)\.)?[A-Za-z0-9_-]{86}", sig)`, else `INVALID_ENVELOPE`.
   Keep `decode_tagged_signature` unchanged: the tag-vs-AID-alg rule is still a signature-step
   failure (`INVALID_SIGNATURE`), as in aitp-rs.
3. Both checks run in the shared validator, so `verify_envelope`, `handshake.py:65` and the
   pinned-key proof path all get them.
4. Tests in `tests/test_envelope.py`, against `kat-keypair-001-envelope.json` with the window
   disabled:
   - `payload` `[]` / `null` → `INVALID_ENVELOPE` (regression)
   - `extensions: null` → `INVALID_ENVELOPE` (regression)
   - `timestamp: -1` → `INVALID_ENVELOPE`; with the default window → `TIMESTAMP_EXPIRED` (matches
     the aitp-rs adapter)
   - signature short, `==`-padded, `+`, `rsa.` tag → `INVALID_ENVELOPE`
   - well-formed but wrong signature → still `INVALID_SIGNATURE`
   - `aitp/0.2` plus an unknown member → still `UNKNOWN_VERSION`
5. CHANGELOG `## Unreleased`: a malformed signature string changes code from `INVALID_SIGNATURE`
   to `INVALID_ENVELOPE`.

**Verify:** `AITP_SPEC=$PWD/../agentidentitytrustprotocol pytest -q`, `mypy`,
`python3 run_conformance.py --spec-dir ../agentidentitytrustprotocol` (still 93/0/9; env-001..011
unaffected).

## Phase 2 - Bundle participant TCTs capped at the coordinator Manifest (0.16 §4)

**Status:** DONE

1. In `sessionbundle.py`, keep the Manifest that `resolve_key_from_manifests` matched (it returns
   only the `Aid` today). Add a small helper in `manifest.py` that returns the matched Manifest,
   or have the function return both.
2. In the participant loop (`sessionbundle.py:218-255`), after `verify_jws` and the claims-shape
   check: if a coordinator Manifest was supplied and `claims["exp"] > manifest["expires_at"]`, raise
   `BUNDLE_PARTICIPANT_TCT_INVALID` ("TCT outlives the coordinator Manifest"). Use one comparison,
   shared with `tct.py:174-175`, not a copy.
3. Tests in `tests/test_sessionbundle.py`: a TCT that outlives the Manifest is rejected; equal `exp`
   is accepted; no Manifest supplied means no cap (today's behaviour).
4. Before you merge, confirm `bundle-001`/`bundle-005` still pass. Their fixture Manifests must
   outlive the TCTs.

**Verify:** as in Phase 1. Also run aitp-rs `scripts/xcheck-verify.py` locally against this
branch. It passes no Manifest, so it must stay green.

## Phase 3 - Decide: Manifests mandatory or optional (no code until decided)

**Status:** DECIDED 2026-10-20: keep OPTIONAL. Open item until aitp-rs `xcheck-verify.py` supplies a Manifest or a waiver.

Today a Manifest is checked only when the caller supplies it (`"coordinator_manifest" in inp`,
`"issuer_manifests" in inp`). aitp-rs 0.16 requires them in its bindings and adapter. Without them it
falls back to the AID-derived key only under `UnverifiedAidDangerous`. Every spec bundle and delegation
fixture now carries them, except `del-004`, which is v0.1-only and skipped. So making them mandatory
would not break this repo's own conformance run.

It would break aitp-rs xcheck, though. `xcheck-verify.py:262-270` calls `verify_session_bundle`
without `coordinator_manifest`.

If the decision is "mandatory":

- Missing input → `ValueError`, or an explicit `waive_*: True` modelled on `tct.py:201-203`.
- Land an aitp-rs PR first that adds the waiver or the Manifest to `xcheck-verify.py`.
- Then merge here, and bump `AITP_VERIFIER_PY_VERSION`.

## Phase 4 - Runner profile gate (RFC-AITP-0001 §10 item 9)

**Status:** DONE

1. `run_conformance.py`: add `--profile {v0.2,v0.1}`, defaulting to `v0.2`. A fixture with
   `required_for_v0_2` (absent counts as true, as in aitp-rs) that ends SKIP exits 1, unless an
   enabled feature negates it: `del-007` under multi-hop in v0.2, `del-004` in v0.1. Print each
   exemption on stderr. FAIL stays fatal under both profiles.
   *As built:* negation exempts only fixtures outside the current core tier. Core fixtures
   run feature-less here, so `del-007` runs and passes rather than being exempted.
2. Note on line 187: the pre-filter treats a missing `required_for_v0_2` as false, but aitp-rs
   treats it as true. Align the filter with the gate.
3. `tests/test_conformance.py`:
   - the default profile exits 0 at `bf00e75`;
   - a synthetic required fixture with an unsupported op exits 1.
4. README: document `--profile`. CI command lines are unchanged.

**Verify:** the runner exits 0 with the default profile and with `--profile v0.1`; `pytest -q`.

## Phase 5 - Cross-repo cutover and release hygiene

**Status:** DONE (single PR; CHANGELOG entries added)

- There is no wire cutover here. This repo has no peers on the network, and the aitp/0.3 flip already
  happened in #65, in lockstep with aitp-rs 0.17 (its xcheck pin is `f335f4f`).
- Ship Phases 1, 2 and 4 as separate PRs, in any order. After each merge, aitp-rs's weekly
  `bump-verifier-py` opens a pin bump. Its `xcheck` job must stay green: Phase 1 changes only the
  codes for malformed input, and Phase 2 bites only when a Manifest is supplied.
- Phase 3, if "mandatory": aitp-rs `xcheck-verify.py` change first, then this repo.
- Optional: file a spec issue for env fixtures that pin the #262 rules (negative `timestamp`,
  malformed `signature`, `extensions: null`, non-object `payload`). Today only the two
  implementations' own tests cover them, and the daily canary would pick such fixtures up.
- CHANGELOG `## Unreleased`: one entry per phase, with Phase 1 under "Security-relevant / behaviour
  change".

## Open questions

1. Manifests mandatory (Phase 3)? The recommendation is yes, with an explicit waiver, so the AID
   fallback is never silent. This needs a same-day aitp-rs `xcheck-verify.py` change.
2. Delegation ordering differs. Here the Manifest lookup runs before `verify_jws`, so before `typ`.
   aitp-rs runs it after `typ` and the member set, before `alg` (`upgrading-0.16.md` §8). A
   wrong-`typ` token from an issuer without a Manifest gives `KEY_RESOLUTION_FAILED` here and
   `TOKEN_TYP_MISMATCH` in aitp-rs. No fixture pins this. Align with aitp-rs, or ask the spec to
   pin it?
3. Integral-float `timestamp` (`1.0`): this repo accepts it, since JSON Schema `integer` admits it.
   aitp-rs rejects it ("stricter than the schema", `upgrading-0.17.md` §5). Leave the divergence
   documented, or match aitp-rs?
4. Spec PR #92 says an unknown revocation-snapshot version is `REVOCATION_SNAPSHOT_INVALID`, which
   is what this repo returns (`revocation.py:170-176`). aitp-rs `upgrading-0.17.md` §1 lists
   `UNKNOWN_VERSION` for its adapter. That is an aitp-rs-side question, not a change here.
