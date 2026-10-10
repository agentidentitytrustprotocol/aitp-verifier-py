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
| `aitp_verifier.aid` | AID parsing + self-certifying key derivation (§5.3), incl. the v0.2 `p256` tag |
| `aitp_verifier.jwk` | RFC 7638 JWK thumbprints for the `cnf.jkt` binding (§5.4.4) |
| `aitp_verifier.jws` | Strict compact-JWS profile: `typ`/`alg` pinning, no `alg:none`, exact-bytes verify (§5.4.5) |
| `aitp_verifier.envelope` | Envelope signature + replay controls (§5.4/§5.5) |
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
| `aitp_verifier.sessionbundle` | Session Trust Bundle: envelope shape, expiry-before-signature, expiry-window invariant, coordinator signature, per-participant TCT, self-membership (RFC-AITP-0010) |

## Conformance coverage

`run_conformance.py` re-derives every in-scope fixture from the pinned KAT
keypairs and runs it against this implementation:

```
python run_conformance.py --spec-dir ../agentidentitytrustprotocol
```

Current status (the runner prints the live number; the pack grows with the spec): **71 fixtures pass, 0 fail, 1 skipped** — the entire re-mintable v0.2 pack
plus both Draft opt-ins (`experimental-multihop-delegation`,
`experimental-session-bundle`) and all multi-step sequences (PoP
challenge/response `tct-006`/`tct-007`, handshake replay `mh-001`). The surface — envelope, TCT (incl.
`alg:none`, alg-confusion, `typ`-confusion, expiry-after-Manifest,
revocation-ordering), grant voucher, single- **and multi-hop** delegation,
Manifest, revocation snapshots, and the full mutual-handshake / identity family
(OIDC and pinned-key bindings, nonce echo, round-2 PoP, embedded peer-issued
TCT) — is validated byte-for-byte against `known-answer/keypairs.json`,
`jwk-thumbprints.json`, `jcs-sha256.json`, the `signed-examples/` compact-JWS
artifacts, and the id-007 pinned-key proof vector.

Exactly **one** fixture is skipped, for a structural reason rather than missing
verification logic (SKIP is reported explicitly — never a silent pass, per
PLACEHOLDERS.md §"Operation key"):

- **`del-004`** — frozen in the retired v0.1 object wire shape
  (`required_for_v0_1` only); a v0.2 implementation legitimately does not run it.

Every other required-for-v0.2 fixture, both Draft opt-ins, and all multi-step
sequences pass.

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
