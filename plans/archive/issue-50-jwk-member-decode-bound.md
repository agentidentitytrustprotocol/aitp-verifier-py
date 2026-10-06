# Plan: bound base64url member length before decode in jwk.py (issue #50)

## Context

`aitp_verifier/jwk.py::issuer_key_from_jwk` parses a caller-supplied JWK dict into an
`IssuerKey`. For every `kty` it supports, it calls `b64url_decode` on one or more
string members (OKP's `x` at `jwk.py:131`; EC's `x`/`y` at `jwk.py:140-141`; RSA's
`n`/`e` at `jwk.py:150-151`) and only checks the *decoded* byte length afterward (OKP/EC:
`len(x) != 32` etc. right after decode; RSA: no length check at all in `jwk.py` — the
bit-length ceiling lives downstream in `crypto.py::PublicKey.from_rsa_numbers`, added by
issue #47's Phase 2). `b64url_decode` itself (`aitp_verifier/b64.py:24-29`) is O(len(text))
twice over before it ever returns: an alphabet-membership scan (`any(ch not in _ALPHABET
for ch in text)`) followed by `base64.urlsafe_b64decode`. Read together, this means a
caller/resolver-supplied JWK with an arbitrarily long string in any of these five member
positions pays the full decode cost *before* any bound — the 32-byte check for OKP/EC, or
crypto.py's `bit_length()` ceiling for RSA — ever gets a chance to reject it.

Issue #50 (filed during #47's own finalization pass — the same "spin off the residual as a
follow-up issue" pattern #38's verification pass used to spin off #47, and #47's Phase 1
used to spin off #49) measured this directly: a base64url string decoding to an 8 MB
(67,108,864-bit) modulus costs ~188ms to decode before `from_rsa_numbers`'s bit-length
check rejects it. Because `issuer_keys_from` (issue #47) fails fast on the first malformed
candidate, a hostile JWKS of many such entries still costs at most two such decodes per
verification call, not one per entry — both members on the EC or RSA path are decoded
before either is judged (`jwk.py:140-141`, `:150-151`), which is exactly the ~410ms worst
case #50 measured via the EC path (roughly 2×188ms) — so this is a real but modest hazard
(a constant, bounded-by-caller-input cost per call), not an amplification primitive like
#49's aliased-container finding. Still worth closing under the same "guard before the
expensive operation, not only after" discipline `_MAX_DEPTH`, `_MAX_CANDIDATES`, and
crypto.py's `bit_length()` checks already establish (CWE-770, same framing as #38/#47/#49).

**Scope correction from the issue text:** #50's own body only names the RSA `n`/`e` sites
explicitly (suggesting the EC `x`/`y` path "could use the same treatment"). Reading
`jwk.py:127-154` directly (this session) shows the OKP branch has the *identical* shape —
`x = b64url_decode(_require_str(value.get("x"), "x"))` at line 131, then `len(x) != 32`
checked only after decode at line 132 — so OKP's `x` carries the same unbounded-decode-
before-length-check gap as EC's `x`/`y` and RSA's `n`/`e`. All five sites share one root
cause and one fix shape; this plan closes all five in one phase rather than only the two
the issue's title names literally. This is not scope creep — it is the same hazard, in the
same file, caught while reading the code this plan is grounded in.

## Phase 1: pre-decode length gate for every JWK member string

**Status: DONE.** Implemented exactly as planned, including all six round-1 review fixes
(placement between `_require_str` and `issuer_key_from_jwk`; the `issuer_key_from_config`
exclusion noted in code (`jwk.py`'s constant comment); non-vacuous monkeypatch proofs per site via a guarded
decode stand-in that lets a sibling in-budget member still legitimately decode in the same
call; boundary tests asserting the specific downstream message and the pre-gate's absence,
for both OKP and RSA; the e2e test asserting the pre-gate's own message text, not just the
error code). 528 tests passed (519 + 9 new: 8 unit, 1 e2e), mypy clean. No divergence from
the planned approach.

**Delivers:** every base64url member `issuer_key_from_jwk` decodes (OKP `x`; EC `x`, `y`;
RSA `n`, `e`) is length-checked against a generous, fixed ceiling *before* `b64url_decode`
is ever called, so an oversized value is rejected in O(1) (a cached Python `str` length
check) instead of paying decode cost proportional to its size.

**Depends on:** nothing (single-phase plan; no dependency on #49, which is a separate,
independent residual against the same module).

**Files:**
- `aitp_verifier/jwk.py` — add `_MAX_B64_MEMBER_CHARS` and a `_decode_member` helper;
  route all five decode call sites through it.
- `tests/test_identity_oidc.py` — unit tests for the pre-gate (per member, per `kty`).
- `tests/test_unknown_fields.py` — one end-to-end handshake test proving an oversized
  member value resolves to `KEY_RESOLUTION_FAILED`, not a crash or a hang.
- `CHANGELOG.md` — one `### Security-relevant` entry under `## Unreleased`.

**Approach:**

Add one private helper and one constant, mirroring `_reserve`'s shape (a small guard
function called at every candidate-producing site, not duplicated inline five times):

```python
# Maximum encoded length (unpadded base64url characters) this module will
# decode for any single JWK member (OKP `x`; EC `x`/`y`; RSA `n`/`e`), checked
# before b64url_decode is ever called -- not merely before the length check
# each branch already runs on the *decoded* bytes. b64url_decode's own
# alphabet scan (b64.py:26) is already O(len(text)) before the actual
# base64 decode runs, so the bound has to sit ahead of that call, not just
# ahead of crypto.py's bit_length() check on the RSA path (issue #50).
#
# 8192 is generous headroom over every real member's minimal encoding: a
# fixed 32-byte OKP/EC coordinate needs exactly 43 unpadded chars; an
# 8192-bit RSA modulus (_MAX_RSA_MODULUS_BITS in crypto.py) needs at most
# 1366 when minimally encoded per RFC 7518 SS6.3.1's "as small as possible"
# requirement -- ~6x headroom on the tightest case, not a number tightly
# calibrated to it (same "generous, not tight" style _MAX_CANDIDATES uses).
# One shared constant across all five sites, rather than five individually-
# tuned ones, keeps the bound simple to state and test; the goal is bounding
# cost to a negligible constant, not fitting each member's exact minimum.
_MAX_B64_MEMBER_CHARS = 8192


def _decode_member(value: dict[str, Any], member: str) -> bytes:
    text = _require_str(value.get(member), member)
    if len(text) > _MAX_B64_MEMBER_CHARS:
        raise ValueError(
            f"JWK member {member!r} exceeds the maximum encoded length "
            f"({_MAX_B64_MEMBER_CHARS} base64url characters), got {len(text)}"
        )
    return b64url_decode(text)
```

Replace all five call sites in `issuer_key_from_jwk` (`jwk.py:127-154`):
- OKP: `x = b64url_decode(_require_str(value.get("x"), "x"))` → `x = _decode_member(value, "x")`
- EC: same for `x` and `y`
- RSA: same for `n` and `e`

`issuer_key_from_config` (`jwk.py:157-173`) already establishes this exact pattern for the
legacy static-config form — `if len(b64url) == 43:` / `elif len(b64url) == 44:` gate on
*encoded* length before either branch calls `b64url_decode` (`jwk.py:167`, `:170`) — which
is why only five of `jwk.py`'s seven `b64url_decode` call sites need this phase: the other
two are already gated pre-decode by construction. This is the more on-point precedent for
`_decode_member`'s shape than `_reserve`; both are cited below.

Rejected alternatives:
- **Adding a `max_len` parameter to `b64url_decode` itself (`b64.py`).** `b64.py` is a
  generic, repo-wide codec (24 call sites across `aid.py`, `jws.py`, `handshake.py`,
  `manifest.py`, `fields.py`, `sigfield.py`, `identity.py`, `minter.py`, `jwk.py` itself —
  not just JWK parsing); every other caller already has its own fixed, small expected size
  enforced by its own logic. Changing a shared primitive's signature to serve one caller's
  bound is a broader change than this issue calls for, and couples an unrelated module to
  jwk.py's specific ceiling. A private, module-local helper is the same shape #47 already
  chose for `_reserve` (bounding `jwk.py`'s own recursive walk) over touching a shared
  module, and the same shape `issuer_key_from_config` already uses for its own two sites.
- **Per-member-tuned caps** (43-ish for OKP/EC, ~1400-ish for RSA). More "precise," but
  three numbers to justify and test instead of one, for no real safety benefit — the point
  of the cap is bounding cost to a negligible constant, and 8192 chars (~6 KB) decodes in a
  fraction of a millisecond regardless of which member it gates. A single shared constant
  is simpler to state, test, and keep consistent if the RSA ceiling in `crypto.py` ever
  changes.
- **Exact-length equality for OKP/EC** (`len(text) != 43` → reject, mirroring
  `issuer_key_from_config`'s own `== 43`/`== 44` gates), instead of a generous cap. This is
  strictly tighter and would work — a 32-byte value has exactly one possible encoded
  length. Rejected anyway, for a *behavioral*, not just a simplicity, reason: it would move
  the rejection point and change the error message for a near-miss OKP/EC input (e.g. a
  33-byte-decoding, 44-char `x`) from the existing, already-tested post-decode message —
  `"Ed25519 JWK 'x' must decode to 32 bytes, got 33"` (`jwk.py:133`, asserted by
  `tests/test_identity_oidc.py:917-919`) — to a new, less specific pre-decode message. The
  generous shared cap only ever intercepts genuinely oversized input; every near-miss still
  reaches, and is judged by, the existing decoded-length check with its existing message.
- **Deriving `_MAX_B64_MEMBER_CHARS` from `crypto.py`'s `_MAX_RSA_MODULUS_BITS`.** Would
  couple two modules' private constants together for a number that doesn't need to track
  it exactly (see "generous, not tight" above) — same reasoning the module docstring
  already gives for keeping `_MAX_DEPTH` independent of `jcs.py`'s: "reaching into a
  sibling module's private name would be a leakier coupling than one small,
  independently-justified number."

**Placement:** `jwk.py` puts each bound immediately above its consumer (`_MAX_DEPTH` sits
at `jwk.py:176`, directly above `issuer_keys_from` at `:205`). Put `_MAX_B64_MEMBER_CHARS`
and `_decode_member` the same way: between `_require_str` (`jwk.py:101-104`) and
`issuer_key_from_jwk` (`:107`), not down near `_MAX_DEPTH`/`_MAX_CANDIDATES` — it gates
`issuer_key_from_jwk` specifically, not the list-walk those two constants bound.

**Edge cases & failure modes:**
- A member exactly at the cap (8192 chars) is *not* rejected by the pre-gate — it proceeds
  to `b64url_decode` and is judged by the existing downstream checks (decoded-length for
  OKP/EC, `crypto.py`'s bit-length ceiling for RSA), exactly as today. The pre-gate only
  ever rejects what was already going to be rejected downstream, faster.
- A **legitimate, valid key** of any supported `kty`/size never approaches 8192 chars (the
  largest real value, an 8192-bit RSA modulus, needs at most 1366) — zero risk of rejecting
  a valid key.
- **Missing/non-string member** (e.g. `value.get("n")` is `None` or a `dict`) — unchanged:
  `_require_str` (called first, inside `_decode_member`) still raises its own `ValueError`
  before length or decode is ever considered. The new check composes with the existing one,
  doesn't replace it.
- **Composition with `_MAX_CANDIDATES` (#47) — corrected during `/ship`'s pre-merge gate.**
  An earlier draft of this section claimed the reachable worst case was far below the loose
  `64 × 2 × 8192 = 1,048,576`-char (1 MiB) upper bound, reasoning that "an at-cap member is
  always oversized for its own downstream check too," so fail-fast would stop the walk at
  the first one. **That premise is false for RSA and was independently reproduced, not
  merely asserted:** `crypto.py:120-122` computes `int.from_bytes(n, "big").bit_length()`,
  which strips leading zero bytes for free — an at-cap (6144-byte-decoding) `n` consisting
  mostly of `\x00` padding around a genuine small modulus (e.g. 5888 zero bytes + a real
  256-byte 2048-bit value) decodes to a perfectly valid, in-range `bit_length`, and **parses
  successfully**. Fail-fast never fires, because there is no malformed candidate to fail on.
  64 such at-cap-but-valid RSA candidates therefore *do* all parse in one `issuer_keys_from`
  call — measured at ~9-18ms (machine-dependent) for the full 1 MiB of decode work, vs.
  ~0.7ms for 64 legitimate minimal-size candidates: roughly a 25x cost multiplier over
  legitimate JWKS practice, not the "~100 KB, fail-fast stops it" this section previously
  claimed. **This is still a strict improvement over `main`** (a single unbounded decode
  costing up to ~188-410ms per call, per issue #50's own pre-fix measurements) and is fully
  bounded (no caller-controlled multiplier beyond the fixed 64/2/8192 product) — but the
  bound is the honest ~1 MiB/~18ms figure, not the ~100 KB one. Tracked as a residual in
  issue #52 (below) rather than tightened here: the generous-shared-cap design (one number,
  not five individually-tuned ones) was a deliberate Phase 1 choice, and ~18ms is not, on
  its own, a reason to reverse it mid-`/ship`.
- This phase does **not** bound the memory cost of the caller already holding an oversized
  string in the JSON/config value passed into `issuer_keys_from` — that string exists
  before this module ever sees it (upstream JSON/config parsing, out of this module's
  control), same scope boundary #47's Phase 2 already drew around `crypto.py`-only changes.
  Not a gap this plan claims to close.
- The new pre-gate's error message interpolates only `{member!r}` and `{len(text)}` — never
  the oversized string itself — so the rejection path cannot blow the message budget or
  raise while formatting, the same hazard `describe_value` (`jwk.py:130`, `:139`, `:154`)
  already exists to avoid for unrecognized `kty`/`crv` values.

**Acceptance criteria:**
1. `_MAX_B64_MEMBER_CHARS` and `_decode_member` exist in `jwk.py`, placed between
   `_require_str` and `issuer_key_from_jwk`; all five decode sites in `issuer_key_from_jwk`
   (OKP `x`; EC `x`, `y`; RSA `n`, `e`) call `_decode_member` instead of `b64url_decode`
   directly. The other two `b64url_decode` call sites in `jwk.py` — `issuer_key_from_config`
   at `:168`/`:171` — are intentionally untouched: they already gate on encoded length
   (`== 43`/`== 44`) before decoding, so they don't share this phase's gap.
2. For each of the five sites, a member string longer than `_MAX_B64_MEMBER_CHARS` raises
   `ValueError` **without** `b64url_decode` ever being invoked — proven by monkeypatching
   the module's own `b64url_decode` binding to raise `AssertionError` if called, and
   asserting the resulting exception is `ValueError` (the pre-gate's own message), not the
   `AssertionError` a fallthrough-to-decode would produce. Same non-vacuous-proof technique
   #47 used for `crypto.py`'s RSA bit-length checks.
3. A member string at exactly the cap is **not** rejected by the pre-gate: for OKP/EC,
   asserting the raised `ValueError` matches the existing downstream decoded-length message
   (e.g. `"must decode to 32 bytes"`) and does **not** contain `"exceeds the maximum
   encoded length"`; for RSA, asserting it matches `crypto.py`'s bit-length message instead.
   A bare `pytest.raises(ValueError)` is not sufficient — it would pass whether the
   pre-gate or the downstream check fired, proving nothing about which one did.
4. Every existing valid-key fixture (Ed25519 OKP, P-256 EC, RSA across the 2048-8192 bit
   range) still parses successfully — zero regressions.
5. One end-to-end test in `tests/test_unknown_fields.py`: a handshake whose resolved issuer
   key value carries an oversized member resolves to `AitpError("KEY_RESOLUTION_FAILED")`
   **whose message contains `"exceeds the maximum encoded length"`** (the pre-gate's own
   text) — not merely `KEY_RESOLUTION_FAILED` on its own, which already passes today before
   this fix (an oversized member already reaches that code via the existing catch-all,
   after paying full decode cost; asserting only the code proves nothing about whether the
   pre-gate fired). No wall-clock/hang assertion — not reliably falsifiable from test output.
6. `uv run pytest -q` green; `uv run --extra dev mypy` clean; `CHANGELOG.md` has a
   `### Security-relevant` entry under `## Unreleased` citing issue #50.

**Tests:**
- `test_max_b64_member_chars_is_8192` (constant-pinning, same convention as the existing
  `_MAX_DEPTH == 16` / `_MAX_CANDIDATES == 64` pins at `tests/test_identity_oidc.py:652`,
  `:833`)
- `test_issuer_key_from_jwk_okp_x_over_length_cap_rejected_before_decode` (monkeypatch
  proof, per acceptance criterion 2)
- `test_issuer_key_from_jwk_ec_x_over_length_cap_rejected_before_decode`
- `test_issuer_key_from_jwk_ec_y_over_length_cap_rejected_before_decode`
- `test_issuer_key_from_jwk_rsa_n_over_length_cap_rejected_before_decode`
- `test_issuer_key_from_jwk_rsa_e_over_length_cap_rejected_before_decode`
- `test_issuer_key_from_jwk_member_at_length_cap_reaches_decode` (boundary, criterion 3)
- existing valid-key fixtures re-run unmodified (regression, criterion 4)
- `test_handshake_oversized_jwk_member_resolved_issuer_key_is_key_resolution_failed_not_a_crash`
  in `tests/test_unknown_fields.py`, asserting on the pre-gate's own message text per
  criterion 5

**Docs:** `jwk.py`'s module docstring (`jwk.py:18-39`) already describes the depth/count
bounds from #38/#47 in its "Issuer-key parsing" paragraph; extend that paragraph with one
clause for this phase's member-length bound so the docstring stays the single accurate
description of every bound the walk enforces, same pattern #47 used when it added its own
clause there.

## Long-term posture

No one-way door: this is an additive input-validation tightening on an already-`ValueError`-
raising path (`identity.py`'s catch-all already converts any `ValueError` here to
`AitpError("KEY_RESOLUTION_FAILED", retryable=True)`, per #38/#47 — zero code changes
needed at that call site for this phase either). No public contract, schema, or wire-format
change. Fully reversible by deleting the two new names if `_MAX_B64_MEMBER_CHARS` ever
proves too tight (it won't, per the sizing math above) — not a decision that forecloses
anything.

## Enterprise concerns

Closes the last unbounded-per-candidate cost in `issuer_key_from_jwk`, composing with #47's
global candidate-count cap to give `issuer_keys_from` a genuine constant-bound total cost
per verification call (see Edge cases above for the composed-bound arithmetic) — modulo
#49's still-open, orthogonal residual (candidate-*free* / aliased containers bypass both
`_MAX_CANDIDATES` and `_MAX_DEPTH` entirely, since they never produce a candidate to count;
this plan does not touch that path and does not claim to close it — tracked separately).
No observability changes needed: the rejection is a plain `ValueError` → `AitpError`, same
shape as every other malformed-JWK rejection already handled.

## Open questions

- **One shared cap vs. per-member-tuned caps** — decided directly (Consequential-but-
  decidable, no escalation needed): one shared `_MAX_B64_MEMBER_CHARS = 8192` across all
  five sites. Reasoning and rejected alternative recorded in Phase 1's Approach above.
- **Scope: fix OKP/EC too, not just the RSA sites the issue names** — decided directly:
  yes, same root cause, same file, same fix shape, caught while reading the code this
  session. Recorded in Context's "Scope correction" paragraph above.
- No critical/one-way-door decisions in this plan; Fable was not engaged.

## Repo map

(Reuses the map `plans/issue-47-issuer-key-resource-bounds.md` already built in
`PROGRESS.md` for this same module — `jwk.py`, `crypto.py`, `identity.py`, the two test
files, `CHANGELOG.md` — no new files or directories enter scope for this plan.)

## Plan review

**Round 1 — REVISE, applied.** A fresh Opus agent checked this plan against `jwk.py`,
`b64.py`, `crypto.py`, `identity.py`, and both test files directly, independently
recomputing the 43-char/1366-char encoding arithmetic and the composed-bound math. Every
factual claim about the code (line numbers, decode-then-check shape, the OKP scope
correction, `identity.py`'s zero-change status, test-file/fixture/naming precedents)
verified clean. Six defects found, all applied:
1. Context's "8 MB base64url string" restated the issue's measurement backwards (8 MB is
   the decoded size, not the encoded string) — corrected.
2. Context's "only one such decode per verification call" contradicted the plan's own
   Edge-cases section and issue #50's own ~410ms EC-path measurement — corrected to "at
   most two."
3. `issuer_key_from_config`'s two already-safe `b64url_decode` sites (`jwk.py:168`,`:171`)
   were an unexplained gap in "all five" — added as an explicit exclusion in acceptance
   criterion 1, and promoted to the primary design precedent (stronger than `_reserve`)
   in Approach.
4. The plan never considered exact-length equality for OKP/EC (a strictly tighter
   alternative `issuer_key_from_config`'s own precedent invites) — added as a rejected
   alternative with the actual (behavioral, not simplicity) reason: it would change the
   rejection point and error message for near-miss inputs already covered by an existing,
   tested assertion.
5. Acceptance criterion 5's e2e test was vacuous — `KEY_RESOLUTION_FAILED` alone already
   passes today, before the fix. Tightened to assert the pre-gate's own message text;
   dropped the non-falsifiable "not a multi-second hang" clause.
6. Acceptance criterion 3's boundary test was vacuous for the same reason (a bare
   `pytest.raises(ValueError)` can't distinguish which check fired) — tightened to assert
   the specific downstream message and the absence of the pre-gate's message.

Also added: a constant-pinning test (matching existing `_MAX_DEPTH`/`_MAX_CANDIDATES`
precedent), an explicit placement instruction (between `_require_str` and
`issuer_key_from_jwk`), a note on the new error message's bounded interpolation (message-
budget safety, same reasoning as `describe_value`), and a correction of the composed-bound
arithmetic from a loose 1 MiB upper bound to the ~100 KB reachable worst case under
fail-fast. Not re-reviewed as a second round: every change is a direct, mechanical
application of a specific, cited finding (a restated fact, an added exclusion, a tightened
assertion) with no new design surface introduced — nothing here needs a second fresh read
to confirm.
