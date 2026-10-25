# aitp-verifier-py

An **independent Python implementation of the AITP verification core** — a
second implementation, written from the spec alone, that cross-checks the
reference one. The first implementation is
[`aitp-rs`](https://github.com/agentidentitytrustprotocol/aitp-rs); its
Python/Node bindings wrap the same Rust core and therefore do **not** count as
independent. How implementations feed RFC promotion is defined by the spec, not
here: see [`governance/RFC-PROCESS.md`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/governance/RFC-PROCESS.md)
and [`VERSIONING.md`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/VERSIONING.md).
Status of each RFC: [`rfcs/README.md`](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/README.md).

**Wire freeze:** the `aitp/0.3` wire is frozen until 1.0, except for security fixes
([what is frozen](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/VERSIONING.md#what-is-frozen-aitp03-line)).
This verifier tracks that one wire. The conformance claim it passes is `AITP v0.3` (with
`AITP v0.3 self-attestation`) at the spec commit in [`SPEC_VERSION`](SPEC_VERSION); see
[Conformance coverage](#conformance-coverage).

## Independence claim

This codebase was implemented **from the RFC-AITP texts and JSON schemas only**
([RFC-AITP-0001…0013](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/tree/main/rfcs),
`schemas/json/*`, and the conformance pack's pinned
*expectations* under `schemas/conformance/`). No algorithmic code was read
from, ported from, or shared with `aitp-rs`, and nothing shells out to any Rust
binary. The two implementations meet only at the conformance pack's byte-pinned
golden vectors (`known-answer/`) — which is the point: cross-verifying the same
vectors from two independently written codebases is what makes the check
meaningful.

## Scope

A **verification library plus a conformance-fixture runner** — not an agent, not
an HTTP client, not a registry. No network I/O exists anywhere in this codebase.

Implemented: RFC-AITP-0001–0006, 0008, 0010, 0011. RFC-AITP-0007 (key resolution)
is covered only as far as verifying with caller-supplied keys (`jwk`, `identity`) —
nothing is fetched. RFC-AITP-0009 is a
[security RFC](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/rfcs/RFC-AITP-0009-security.md)
and has no module of its own. RFC-AITP-0012 (extensions) is honored only as the
opaque `extensions` slot (`fields`); RFC-AITP-0013 (TCT renewal) is not implemented.

| Module | Covers |
|---|---|
| `aitp_verifier.jcs` | RFC 8785 JSON canonicalization (own implementation) |
| `aitp_verifier.crypto` | Ed25519 + ECDSA-P256, the JCS-profile vs JOSE signing split (RFC-AITP-0001 §5.4) |
| `aitp_verifier.aid` | AID parsing + self-certifying key derivation (§5.3), incl. the `p256` tag |
| `aitp_verifier.jwk` | RFC 7638 JWK thumbprints for the `cnf.jkt` binding (§5.4.4) |
| `aitp_verifier.jws` | Strict compact-JWS profile: `typ`/`alg` pinning, no `alg:none`, exact-bytes verify (§5.4.5) |
| `aitp_verifier.envelope` | Envelope check order (version → member set → signature), `aitp-envelope-v2` signing input, replay controls (§5.4/§5.5) |
| `aitp_verifier.manifest` | Agent Manifest: version, expiry, PoP, signature (RFC-AITP-0003) |
| `aitp_verifier.tct` | Trust Context Token verification incl. §10.4 Manifest-expiry bound + revocation ordering (RFC-AITP-0005) |
| `aitp_verifier.voucher` | Grant-voucher verification (RFC-AITP-0005 §8) |
| `aitp_verifier.delegation` | Single-hop delegation + the multi-hop chain (hop limit, chain-hash commitment, transitive scope, per-hop revocation) (RFC-AITP-0006 / RFC-AITP-0011) |
| `aitp_verifier.revocation` | Revocation-snapshot freshness / signature / fail-mode (RFC-AITP-0008) |
| `aitp_verifier.identity` | OIDC + pinned-key identity bindings, incl. the five-field pinned-key proof (RFC-AITP-0002) |
| `aitp_verifier.handshake` | Mutual-handshake payload verification: Manifest, identity, nonce echo, round-2 PoP, embedded TCT (RFC-AITP-0004) |
| `aitp_verifier.fields` | Closed-field-set enforcement: unknown fields → `UNKNOWN_FIELD`; `extensions` contents are never inspected (RFC-AITP-0012 §1) |
| `aitp_verifier.sigfield` | Algorithm-tagged (`ed25519.`/`p256.`) JCS-profile signature fields (RFC-AITP-0001 §5.4.3) |
| `aitp_verifier.keys` | Loads the pinned known-answer keypairs for the minter / runner |
| `aitp_verifier.errors` | `AitpError` and the typed error-code vocabulary |
| `aitp_verifier.verify` | Operation registry: maps a fixture `input.operation` to its verifier |
| `aitp_verifier.minter` | Conformance-fixture minter: fills `__PLACEHOLDER__` values with the pinned KAT keys (signs; the verification core never does) |
| `aitp_verifier.b64`, `aitp_verifier.timeutil` | base64url helpers; the reference-clock constant |
| `aitp_verifier.version` | `PROTOCOL_VERSION` (`aitp/0.3`), the one revision accepted under the strict cutover |
| `aitp_verifier.sessionbundle` | Session Trust Bundle: envelope shape, expiry-before-signature, expiry-window invariant, coordinator signature, per-participant TCT, self-membership (RFC-AITP-0010) |

## Conformance coverage

`run_conformance.py` re-derives every in-scope fixture from the pinned KAT
keypairs and runs it against this implementation:

```
python run_conformance.py --spec-dir ../agentidentitytrustprotocol [--claim "AITP v0.3"]
```

The run exits nonzero on any FAIL. `--claim` names one of the RFC-AITP-0001 §10 claim
strings, gated as the spec's
[conformance badge rules](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/docs/conformance-badge.md#claims)
define them, and a SKIP of any fixture behind the claim fails the run too:

| `--claim` | Gated on | Here |
|---|---|---|
| `AITP v0.3` (default) | every `status: core` fixture with `required_for_core` (a missing flag counts as required) | passes |
| `AITP v0.3 self-attestation` | every fixture with `feature: aitp-self-attestation` | passes |
| `AITP v0.3 pinned-admission` | every fixture with `feature: aitp-pinned-admission` | fails: not implemented |

There are no other claims and no named profiles. Core fixtures run with no draft feature
opted in, so `del-007`, which expects `DELEGATION_MULTIHOP_NOT_SUPPORTED`, is executed even
though this verifier implements multi-hop delegation.

Current status at the pinned spec commit (`SPEC_VERSION`, `ac481f8`, `aitp/0.3`; the runner
prints the live number): **111 fixtures pass, 0 fail, 22 skipped**. All 94 core fixtures
pass. So do both Draft opt-ins (`experimental-multihop-delegation`,
`experimental-session-bundle`), the `aitp-self-attestation` extension, and all multi-step
sequences (PoP challenge/response `tct-006`/`tct-007`, issuer-side PoP enforcement `tct-026`,
handshake replay `mh-001`). The surface — envelope, TCT (incl. `alg:none`, alg-confusion,
`typ`-confusion, expiry-after-Manifest, revocation-ordering, no revocation source, and the
issuer-side check of RFC-AITP-0005 §10.5), grant voucher, single- **and multi-hop**
delegation, Manifest, revocation snapshots, session bundles, and the full mutual-handshake /
identity family (OIDC and pinned-key bindings, the receiver's identity-type policy, nonce
echo, round-2 PoP, embedded peer-issued TCT) — is validated byte-for-byte against
`known-answer/keypairs.json`, `jwk-thumbprints.json`, `jcs-sha256.json`, the
`signed-examples/` artifacts (including both envelope KATs, `kat-envelope-001-p256` and
`kat-envelope-002-ed25519`), and the id-007 pinned-key proof vector.

The skips are reported explicitly, never as a silent pass (PLACEHOLDERS.md §"Operation key"):

- **`del-004`** — frozen in the retired v0.1 object wire shape
  (`required_for_v0_1` only); a current implementation legitimately does not run it.
- **`id-013`…`id-016`, `id-019`…`id-022`** — the optional pinned-admission profile
  (RFC-AITP-0002 §3.4, `feature: aitp-pinned-admission`), which this verifier does not
  claim.
- **`id-024`…`id-030`** — the Draft `spiffe` identity branch
  (`feature: experimental-spiffe-identity`), not yet implemented.
- **`a2a-001`…`a2a-006`** — the Draft A2A Agent Card binding (RFC-AITP-0014,
  `feature: aitp-a2a-agent-card`), not implemented.

## CI and the spec pin

The required checks in `ci.yml` run against the spec commit pinned in
[`SPEC_VERSION`](SPEC_VERSION), never the spec's moving `main`. A spec merge therefore
cannot turn this repo red without a PR here. On a conformance-relevant spec push, the
spec's `notify-spec-consumers.yml` dispatches `spec-released`, and
[`bump-spec.yml`](.github/workflows/bump-spec.yml) calls `aitp-ci`'s `bump-spec-ref` to
open a PR that moves the pin. The PR is held for review and its own CI runs the new
fixtures.

[`spec-canary.yml`](.github/workflows/spec-canary.yml) is the wire canary. It runs daily,
and on demand, against the spec's floating `main`. It is not a required check. When it fails
it comments on one tracking issue ("Spec canary: conformance fails against spec main"),
opening it if none is open, and a green run closes that issue.

## Usage and error contract

Every verifier entry point returns normally on success and raises `AitpError`
(`aitp_verifier.errors`) on rejection; malformed remote input never escapes as a
raw `KeyError`/`TypeError`/`RecursionError`. Caller bugs are the exception: a
missing revocation `policy` (on `verify_tct`, also no `issuer_revocation_list.fail_mode`
fallback) or a missing required argument raises a plain `KeyError`
(see [CHANGELOG.md](CHANGELOG.md)).
`jcs` raises `JcsError` and `minter` raises `MinterError` — they are not
verifier entry points. Error codes and their meaning are defined by the spec's
[error-code registry](https://github.com/agentidentitytrustprotocol/agentidentitytrustprotocol/blob/main/registries/error-codes.md),
not restated here. Security-relevant behavior changes are tracked in
[CHANGELOG.md](CHANGELOG.md).

## Cross-implementation checks

`aitp-rs` mints artifacts that this repo verifies, and verifies a session bundle
this repo minted (committed in aitp-rs's `tests/xcheck-fixtures/`) — see aitp-rs
[testing § cross-implementation acceptance](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/testing.md#cross-implementation-acceptance-xcheck)
and [conformance](https://github.com/agentidentitytrustprotocol/aitp-rs/blob/main/docs/conformance.md).
That job pins this repo at a specific commit (`tests/AITP_VERIFIER_PY_VERSION` in
aitp-rs), so it does not track `main` here.

## Development

```
pip install -e ".[dev]"
pytest          # KAT re-derivation, signed-example verify, full pack has no FAIL
mypy            # --strict, clean
```

Requires Python ≥ 3.11 and `cryptography`. The runner takes `--spec-dir`; `pytest` resolves the spec checkout from
`$AITP_SPEC`, then a sibling `agentidentitytrustprotocol/` directory, and fails
loudly if neither exists (set `AITP_SPEC=none` to deliberately run only the
spec-independent subset instead).

## License

Apache-2.0.
