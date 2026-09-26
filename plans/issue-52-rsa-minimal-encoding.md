# Plan: issue #52 — reject non-minimally-encoded RSA `n`/`e` in jwk.py

## Context

Issue #52 (follow-up to #50, found during #50's own `/ship` pre-merge gate) is
pinned as *known, accepted* behavior by an existing test:
`tests/test_identity_oidc.py::test_issuer_key_from_jwk_rsa_n_at_length_cap_zero_padded_still_parses`
(`tests/test_identity_oidc.py:1249`).

`aitp_verifier/jwk.py::_decode_member` (`jwk.py:140`) bounds base64url decode
cost per JWK member (OKP `x`; EC `x`/`y`; RSA `n`/`e`) to `_MAX_B64_MEMBER_CHARS
= 8192` chars (issue #50), checked before `b64url_decode` ever runs. That
closes the *unbounded*-decode-cost gap. But `aitp_verifier/crypto.py`'s
`PublicKey.from_rsa_numbers` (`crypto.py:109-135`) judges the decoded `n`/`e`
bytes only by `int.from_bytes(n, "big").bit_length()` (`crypto.py:121`,
`crypto.py:128`) — a computation that strips leading zero bytes for free. An
`n` consisting of e.g. 5888 zero-padding bytes followed by a genuine 256-byte
2048-bit value decodes to a perfectly in-range `bit_length()` and **parses
successfully**: it is not malformed, so `issuer_keys_from`'s fail-fast
behavior (issue #47, `_reserve`/candidate-cap in `jwk.py:363-373`) never stops
the walk on it. A JWKS of 64 such padded RSA entries (the `_MAX_CANDIDATES`
ceiling, `jwk.py:245`) each pays close to the full 8192-char decode cost
before `from_rsa_numbers` even runs, reaching ~1 MiB of total decode work per
`issuer_keys_from` call — a real, bounded (fixed `64 x 2 x 8192` product, no
caller-controlled multiplier beyond it), but avoidable, residual.

RFC 7518 §2's `Base64urlUInt` definition already requires minimal encoding
("MUST utilize the minimum number of octets"), and §6.3.1.1 names this exact
bug class directly: "some cryptographic libraries prefix an extra zero-valued
octet to the modulus representations they return... implementations...
will need to take care to omit the extra octet." A zero-padded `n`/`e` is
therefore **already non-conformant**, not merely wasteful — rejecting it is
spec-compliance, not an invented restriction, and the RFC's own authors
anticipated precisely this failure mode. This is issue #52's own "more
directly addressing the actual mechanism" alternative (over "per-member-tuned
caps," which would shrink the window without closing the underlying validity
gap: an attacker could still pad up to a smaller cap and still parse).

Verified live during planning (`uv run python3`): the current code accepts
`int.from_bytes(b"\x00"*5888 + real_2048_bit_modulus, "big").bit_length() ==
2048` — confirms the mechanism exactly as the issue describes, unchanged since
#50 merged.

## Approach

Add a minimal-encoding check to `crypto.py::from_rsa_numbers`, not to
`jwk.py`: it's the RSA-numeric-construction boundary (same site as the
existing `bit_length()` range checks it sits beside), so any future caller of
`from_rsa_numbers` inherits the invariant automatically rather than relying on
every call site to remember it separately. `grep` confirms `jwk.py:195` is
`from_rsa_numbers`'s only current call site — this doesn't change that, it
just puts the check at the right boundary for whoever calls it next.

**Ordering matters, and is chosen deliberately:** check minimal encoding
*after* each value's own range check (`bit_length()` floor/ceiling), not
before:

```python
n_int = int.from_bytes(n, "big")
bits = n_int.bit_length()
if not (_MIN_RSA_MODULUS_BITS <= bits <= _MAX_RSA_MODULUS_BITS):
    raise ValueError(...)          # unchanged
if len(n) > 1 and n[0] == 0:
    raise ValueError("RSA modulus 'n' is not minimally encoded (leading zero byte)")
# ... same shape for e, after its own bit_length ceiling check
```

This preserves the existing `test_issuer_key_from_jwk_rsa_n_at_length_cap_reaches_decode`
test unchanged: an all-zero-byte `n` (`"A" * cap`, `bit_length() == 0`) still
fails the *floor* check first ("got 0"), the same message it raises today —
the new check only ever fires for a value that already has a valid,
in-range, non-zero `bit_length()` but was padded to reach it. This is exactly
issue #52's mechanism (a padded-but-otherwise-valid modulus), and nothing
else. `len(n) > 1` exempts the single-byte encoding of the integer `0`
(RFC 7518 doesn't ask a caller to omit the value entirely) — it's excluded
purely by construction since it can never be in the `[2048, 8192]`-bit range
anyway, but the guard makes the check's own intent ("more than one byte, and
the first one is padding") self-evident without relying on that fact.

**Why this closes the cumulative-cost hazard, not just the single-value
one:** `issuer_keys_from` raises `ValueError` immediately on the first
malformed candidate (issue #47's fail-fast). Today, a padded `n` isn't
malformed, so a JWKS of 64 of them all parse and all pay decode cost. After
this fix, a padded `n` is malformed (raises inside `from_rsa_numbers`), so
`_issuer_keys_from`'s JWKS `"keys"` loop (`jwk.py:349-351`) stops at
**candidate 1**, not candidate 64 — the reachable *cumulative* cost across a
whole call drops from ~64x a single candidate's decode cost back down to ~1x
it (still up to one ~8192-char decode, since the padded value must still be
fully decoded before `from_rsa_numbers` can inspect its bytes — but that
single decode was already the accepted, bounded cost issue #50 established;
this closes the *multiplier*, the same "convert a multiplier into a fixed
constant" shape issue #49's own fix used for `jwk.py`'s node-visit count).

**Rejected alternative** (named in the issue itself): per-member-tuned caps
(a small dedicated cap for RSA `n`/`e`, separate from OKP/EC `x`/`y`'s shared
8192). Rejected because it only shrinks the exploitable window without
closing the underlying non-conformance — a smaller cap still lets a padded
value pad up to *that* smaller ceiling and still parse, so the fail-fast
short-circuit this plan relies on wouldn't trigger; the fix would then need
recalibrating again if the cap is ever loosened. The minimal-encoding check
is a one-time, spec-grounded closure with no such recalibration surface.

## Files

- `aitp_verifier/crypto.py` — `from_rsa_numbers` (`crypto.py:109-135`): add the
  two minimal-encoding checks described above. Update its docstring to name
  the new check alongside the existing bit-length ones.
- `aitp_verifier/jwk.py` — module docstring (`jwk.py:1-51`): the existing
  issue #50 sentence ("each base64url member it decodes... is length-checked
  against `_MAX_B64_MEMBER_CHARS`...") gets a follow-on clause naming that
  RSA `n`/`e` must also be minimally encoded (issue #52), so the docstring's
  own claim about what bounds RSA decode cost stays accurate.
- `tests/test_identity_oidc.py`:
  - Replace `test_issuer_key_from_jwk_rsa_n_at_length_cap_zero_padded_still_parses`
    (`tests/test_identity_oidc.py:1249-1266`) — its own docstring says it pins
    "known, accepted behavior... tracked for tightening in #52," so this is
    the test issue #52 exists to flip. New version: same zero-padded at-cap
    `n`, now asserted to raise `ValueError` mentioning minimal/leading-zero
    encoding.
  - Add a sibling for `e` (zero-padded exponent, otherwise valid) — same
    shape, not currently covered by any existing test.
  - Add a boundary test: a single `0x00` byte (`len(n) == 1`) is *not*
    rejected by the new check (still fails the pre-existing floor check,
    "got 0", unchanged) — pins that the `len(n) > 1` guard is deliberate, not
    an oversight. `e`'s equivalent single-`0x00`-byte case is asymmetric and
    out of scope for this test: `crypto.py` has no floor check on `e` at all
    (only the `_MAX_RSA_EXPONENT_BITS` ceiling), so a single-byte `e` of
    `0x00` is rejected downstream by `cryptography`'s own
    `RSAPublicNumbers(...).public_key()` call ("`e must be >= 3 and < n.`"),
    unaffected by this plan either way — no test needed for it here.
  - Add a cumulative-cost test: a JWKS (`{"keys": [...]}`) of `_MAX_CANDIDATES`
    entries where entry 0 is a zero-padded-but-in-range RSA `n` — asserts
    `issuer_keys_from` raises on the *first* entry (fail-fast), not after
    parsing all of them — the direct proof that the multiplier this issue is
    about is now closed.
  - Regression check (no new test needed, existing coverage suffices): every
    other RSA test in this file builds `n`/`e` via `_rsa_n_b64u`/`_rsa_e_b64u`
    (`.to_bytes((bits + 7) // 8, "big")`, minimal by construction) or
    `_N_BYTES`/`_SMALL_N_B64U`/`_SMALL_E_B64U` (all real/synthetic minimal
    values, verified during planning) — confirmed none of them trip the new
    check, so no existing RSA test should change behavior.
- `tests/test_unknown_fields.py` — add one e2e test: a handshake whose
  `resolved_issuer_keys` JWKS carries a zero-padded RSA `n` (otherwise
  in-range), asserting `KEY_RESOLUTION_FAILED` (mirrors the existing sibling
  e2e tests at `tests/test_unknown_fields.py:2401`/`2419` for the #47 RSA
  ceiling checks — same file, same pattern, same "resolved_issuer_keys" shape
  reachable only via a caller/resolver, not via the token itself).
- `CHANGELOG.md` — new `### Security-relevant` entry under `## Unreleased`
  describing the behavior change: a JWKS RSA `n`/`e` that was previously
  accepted (non-minimally encoded but otherwise in-range) is now rejected.
- `plans/issue-50-jwk-member-decode-bound.md` — no changes needed (it already
  correctly links to #52 as the residual it left open; nothing in it becomes
  stale).

## Edge cases & failure modes

- **All-zero `n`/`e`** (`"A" * cap`, `bit_length() == 0`): still rejected by
  the pre-existing floor check, unchanged message — covered by the existing
  test, explicitly re-confirmed unchanged in this plan's own test additions.
- **Single `0x00` byte** (`len == 1`, encodes the integer `0`): exempted from
  the new check by design (`len(n) > 1` guard); still rejected downstream by
  the floor check regardless. New test pins this boundary.
- **Legitimate 2048–8192-bit RSA key, minimally encoded**: unaffected — every
  existing passing RSA test in the suite already builds minimal encodings
  (confirmed during planning), so this is a true no-op for real keys.
- **Padded `e` only, minimal `n`**: covered by the new sibling test for `e`;
  the fix checks both members independently, in the same order they're
  already decoded (`n` then `e`, `jwk.py:192-195`).
- **Cumulative JWKS cost**: closed via fail-fast (issue #47's existing
  mechanism, not new code) — the cumulative-cost test proves this
  behaviorally rather than via a timing assertion (matching this repo's
  established preference for deterministic assertions over wall-clock
  timing — see #49's plan/tests).

## Acceptance criteria

- `crypto.py::from_rsa_numbers` rejects any `n` or `e` whose decoded byte
  length is greater than 1 and whose first byte is `0x00`, checked
  independently for each member, after that member's own existing
  `bit_length()` range check.
- The existing all-zero-`n` test's assertions (`"RSA modulus must be
  between"`, `"got 0"`) are unchanged.
- The existing zero-padded-`n`-parses test is replaced with one asserting
  `ValueError` (minimal-encoding message) instead of successful parsing.
- A new zero-padded-`e` test asserts the same rejection for `e`.
- A new single-`0x00`-byte test asserts the check does *not* fire for `len ==
  1` (rejection still happens, but via the pre-existing floor check).
- A new JWKS-of-64-candidates test, with a zero-padded RSA `n` at position 0,
  asserts `issuer_keys_from` raises without needing to reach positions 1-63.
- A new e2e test in `test_unknown_fields.py` asserts `KEY_RESOLUTION_FAILED`
  for a handshake resolving to a JWKS carrying the same zero-padded `n`.
- Every pre-existing RSA-shaped test in the suite still passes unchanged
  (regression proof that minimal-by-construction test fixtures are
  unaffected).
- `uv run pytest -q` and `uv run --extra dev mypy` both clean.

## Tests

Listed above, under Files — one flip (existing test's intent inverted to
match the new, correct behavior), four new (`e`-sibling, single-byte
boundary, JWKS fail-fast, e2e).

## Docs

- `crypto.py::from_rsa_numbers` docstring — updated to name the new check.
- `jwk.py` module docstring — one follow-on clause (see Files above).
- `CHANGELOG.md` — new entry (see Files above).

## Long-term posture

Not a one-way door: this is a stricter, spec-conformant validation rule with
no schema/contract/API-shape change (`IssuerKey`'s shape, `issuer_keys_from`'s
signature, and every non-RSA code path are untouched). The only behavior
change is that a JWKS presenting a non-minimally-encoded RSA `n`/`e` — already
non-conformant per RFC 7518 §6.3.1, and never something a real OIDC provider's
own key-generation code would produce — now fails resolution instead of
silently succeeding. Reversible in a follow-up commit if some real-world
issuer is ever found violating minimal encoding in practice (none is known;
this is a defense against a deliberately hostile or badly-misconfigured
issuer, per the same CWE-770 framing as #38/#47/#49/#50).

## Enterprise concerns

Single-phase, single-module-boundary fix; no concurrency, migration, or
observability surface beyond the existing `ValueError` -> `AitpError`
conversion at `identity.py`'s `_verify_oidc` (unchanged call site, already
covered by existing e2e-test infrastructure this plan reuses).

## Open questions

None requiring escalation. One Autonomy-ladder call, decided here
(consequential-but-decidable, not critical): fix location is
`crypto.py::from_rsa_numbers`, not `jwk.py::_decode_member` or
`issuer_key_from_jwk` — chosen because minimal-encoding is an RSA-numeric
invariant, not a JWK-parsing one, and belongs at the same boundary as the
existing bit-length checks it composes with, per the Approach section above.

## Repo map

- `aitp_verifier/crypto.py:109-135` — `PublicKey.from_rsa_numbers`, this
  plan's edit site.
- `aitp_verifier/jwk.py:140-147` — `_decode_member` (issue #50's cap; not
  edited by this plan, just the thing whose module-docstring claim needs one
  added clause).
- `aitp_verifier/jwk.py:192-195` — `issuer_key_from_jwk`'s RSA branch, the
  only current call site of `from_rsa_numbers`.
- `aitp_verifier/jwk.py:363-373` — `_reserve`, the fail-fast candidate-count
  guard this fix's cumulative-cost closure relies on (issue #47, unchanged).
- `tests/test_identity_oidc.py:1008-1266` — existing RSA modulus/exponent
  boundary tests (floor #38, ceiling #47, decode-length #50, this plan's
  edit/addition site); `_rsa_n_b64u`/`_rsa_e_b64u` helpers at
  `tests/test_identity_oidc.py:1034-1046`.
- `tests/test_unknown_fields.py:2401-2455` — existing RSA e2e tests (#47),
  this plan's e2e addition site.

## Plan review

Round 1 (fresh Opus agent, code-grounded, not prose-trusted): **SOUND**. Every
file:line citation confirmed exact; the ordering claim (minimal-encoding
check after, not before, the bit_length range check) verified by live byte
tracing, including the counterfactual (checking order reversed would have
broken the existing all-zero-`n` test, confirming the plan's own reasoning
for why it doesn't); every existing RSA test's `n`/`e` construction confirmed
minimal-by-construction via live decode of all 22 RSA JWK-literal sites in
the test suite, including a general mathematical proof that
`(1 << (bits-1)) | 1).to_bytes((bits+7)//8, "big")` can never produce a
leading zero byte; the OKP/EC-needs-no-check claim confirmed structurally
correct (those members are gated by exact decoded length, not a bit-length
computation, so no invisible-padding channel exists there). Fetched RFC 7518
directly during review: confirmed minimality lives in §2 (not §6.3.1 as
originally cited) and that §6.3.1.1 names this exact bug class by name —
applied as a correction above. Two other cosmetic nits applied directly (no
re-review round needed — citation/doc-only, no design change): the
`test_unknown_fields.py` line citation (2401, not 2404) and an explicit note
on `e`'s asymmetric single-zero-byte edge case (no floor check on `e` exists,
so it's rejected downstream by `cryptography` itself, unaffected either way).
No second round needed.

## Implementation verification

Fresh Opus agent, mandatory gate (`/implement` §2): **PASS**. Worked in an isolated git
worktree to avoid disturbing the concurrent #54 session in the shared working directory.
Every claim independently re-verified live (not diff-trusted): all 5 behavioral cases
(all-zero `n`, zero-padded-in-range `n`, single-zero-byte `n`, padded `e`, minimal valid
key) reproduced directly against `from_rsa_numbers`; a mutation test (both new checks
neutralized) confirmed all 4 new/modified tests fail loudly without the fix, including
the e2e test failing on a *different* assertion (`IDENTITY_FAILED` vs
`KEY_RESOLUTION_FAILED`) that proves it's genuinely tied to this check, not passing for
an unrelated reason. Confirmed no bypass path exists (`from_rsa_numbers` is the only RSA
`PublicKey` construction site in the whole codebase). Confirmed no doc drift and that
`PROGRESS.md`/`CHANGELOG.md` accurately match the diff (test counts independently
recounted via `grep`, not trusted from the commit message). Re-ran the full suite (539
passed) and mypy (clean, 37 files) independently. Two non-blocking notes carried forward,
not gaps: the e2e suite covers a padded `n` but not a padded `e` at that layer (a
deliberate, plan-scoped choice — this plan's own Files section names only one e2e test,
for `n`); and the fix accepts a known, RFC-7518-§6.3.1.1-documented interop risk against
any real issuer whose JWK-producer code has the "extra zero-valued octet" bug — already
named and accepted in this plan's own Long-term posture section, not a new gap.
