# aitp-verifier-py

An **independent Python implementation of the AITP verification core** — the
second implementation the AITP spec requires before its Draft trust surfaces
can be promoted to Final. The first implementation is
[`aitp-rs`](https://github.com/agentidentitytrustprotocol/aitp-rs); its
Python/Node bindings wrap the same Rust core and therefore do **not** count as
independent.

## Independence claim

This codebase was implemented **from the RFC-AITP texts and JSON schemas only**
(`rfcs/RFC-AITP-0001…0013`, `schemas/json/*`, and the conformance pack's pinned
*expectations* under `schemas/conformance/`). No algorithmic code was read
from, ported from, or shared with `aitp-rs`, and nothing shells out to any Rust
binary. The two implementations meet only at the conformance pack's byte-pinned
golden vectors (`known-answer/`) — which is the point: cross-verifying the same
vectors from two independently written codebases is what the promotion gate
tests (AITP `VERSIONING.md` — a surface goes Final once "two independent
implementations interoperate").

## Scope

A **verification library plus a conformance-fixture runner** — not an agent, not
an HTTP client, not a registry. No network I/O exists anywhere in this codebase.

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
| `aitp_verifier.delegation` | Single-hop delegation + the multi-hop structural rejection (RFC-AITP-0006) |
| `aitp_verifier.revocation` | Revocation-snapshot freshness / signature / fail-mode (RFC-AITP-0008) |

## Conformance coverage

`run_conformance.py` re-derives every in-scope fixture from the pinned KAT
keypairs and runs it against this implementation:

```
python run_conformance.py --spec-dir ../agentidentitytrustprotocol
```

Current status against the v0.2 pack: **26 required-for-v0.2 fixtures pass, 0
fail.** The implemented cryptographic surface — envelope, TCT (incl. `alg:none`,
alg-confusion, `typ`-confusion, expiry-after-Manifest, revocation-ordering),
grant voucher, single-hop delegation (incl. multi-hop rejection), Manifest, and
revocation snapshots — is complete and validated byte-for-byte against
`known-answer/keypairs.json`, `jwk-thumbprints.json`, `jcs-sha256.json`, and the
`signed-examples/` compact-JWS artifacts.

Operations not yet implemented are reported **SKIP — never a silent pass**
(exactly as PLACEHOLDERS.md §"Operation key" requires). The roadmap toward full
v0.2 parity:

1. **`verify_handshake_payload`** (RFC-AITP-0002/0004): the OIDC and pinned-key
   identity bindings and the mutual-handshake message checks (`id-*`, `mh-*`).
2. **PoP challenge/response sequences** (RFC-AITP-0005 §6): `tct-006`, `tct-007`.
3. **Multi-hop delegation opt-in** (RFC-AITP-0011): `del-mh-*` (Draft).
4. **Session trust bundle** (RFC-AITP-0010): `bundle-*` (Draft).

## Development

```
pip install -e ".[dev]"
pytest          # KAT re-derivation, signed-example verify, full pack has no FAIL
mypy            # --strict, clean
```

Requires Python ≥ 3.11 and `cryptography`. Point the tests/runner at a spec
checkout via `--spec-dir` or `$AITP_SPEC`.

## License

Apache-2.0.
