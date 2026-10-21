#!/usr/bin/env python3
"""AITP conformance-pack runner for aitp-verifier-py.

Walks ``<spec-dir>/schemas/conformance/``, mints each in-scope fixture's
placeholders with the pinned KAT keypairs, executes it against this
implementation, prints a per-fixture PASS/FAIL/SKIP table, and exits nonzero on
any FAIL. Operations this implementation does not yet support are reported SKIP
— explicitly, never as a silent pass (PLACEHOLDERS.md §"Operation key").

``--profile`` (default ``v0.2``) selects the gate: a ``status: core`` fixture
whose ``required_for_v0_N`` flag is set for the profile MUST execute, so a SKIP
of one also exits nonzero (RFC-AITP-0001 §10 item 9; the spec's conformance
README, "Conformance runner enforcement rules"). ``v0.2`` is the fixture key the
spec keeps for the ``aitp/0.3`` core tier.

Usage:
    python run_conformance.py --spec-dir ../agentidentitytrustprotocol [--profile v0.2|v0.1]
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from aitp_verifier.aid import parse_aid
from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.crypto import sha256
from aitp_verifier.errors import AitpError
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.minter import MinterError, mint_input
from aitp_verifier.timeutil import REFERENCE_CLOCK
from aitp_verifier.verify import OPERATIONS, supported
from aitp_verifier.version import PROTOCOL_VERSION

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"

# Draft opt-in features this implementation now exercises. A non-required
# fixture is run when its `feature` is one of these; otherwise it is out of
# scope (Draft not-yet-implemented, or a v0.1-frozen fixture).
SUPPORTED_FEATURES = {"experimental-multihop-delegation", "experimental-session-bundle", "aitp-self-attestation"}

# `--profile` -> the fixture flag it gates on. `v0.2` is the current
# revision's core tier (aitp/0.3 keeps the key name).
PROFILES = {"v0.2": "required_for_v0_2", "v0.1": "required_for_v0_1"}
CURRENT_TIER = PROFILES["v0.2"]

# A rejection a feature-less implementation asserts, mapped to the supported
# feature whose opt-in makes the assertion inapplicable (aitp-rs's
# `negated_by_feature`). This runner opts features in per fixture (`_feature`),
# so a current-tier fixture still runs feature-less and its "not supported"
# assertion is really exercised (del-007 passes). Only a fixture outside the
# current tier -- frozen in an older shape this aitp/0.3-only implementation
# does not parse, e.g. del-004 -- is exempted, never silently.
NEGATED_BY_FEATURE = {
    "DELEGATION_MULTIHOP_NOT_SUPPORTED": "experimental-multihop-delegation",
    "BUNDLE_NOT_SUPPORTED": "experimental-session-bundle",
}


def is_required(fixture: dict[str, Any], flag: str) -> bool:
    """A core fixture's ``required_for_v0_N``; absent counts as required, as
    in aitp-rs, so a fixture missing its metadata is never quietly skipped."""
    return fixture.get("status", "core") == "core" and fixture.get(flag, True) is True


def negating_feature(fixture: dict[str, Any]) -> str | None:
    """The supported feature that negates *fixture*'s assertion, if any."""
    if is_required(fixture, CURRENT_TIER):
        return None
    feature = NEGATED_BY_FEATURE.get(str(fixture.get("expected", {}).get("error_code")))
    return feature if feature in SUPPORTED_FEATURES else None


class _SeqState:
    """State carried across the steps of a multi-step conformance sequence."""

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.nonce: str | None = None
        self.pop_response: dict[str, str] | None = None
        self.pop_challenge_issued = False
        self.capability_authorized = False


def _pop_required(inp: dict[str, Any]) -> bool:
    marked = set(inp.get("issuer_policy", {}).get("pop_required_grants", []))
    return bool(marked & set(inp.get("tct_token_claims", {}).get("grants", [])))


def _run_step(state: _SeqState, step: dict[str, Any], inp: dict[str, Any], keys: dict[str, Any]) -> tuple[str, str | None, dict[str, Any]] | None:
    """Execute one sequence step. Returns (outcome, code, side_effects) or None if unsupported."""
    op = step.get("operation")

    if op in (None, "process_handshake_message"):  # message-id dedup engine (env-004, mh-001)
        mid = str(step.get("message_id"))
        if mid in state.seen:
            return "failure", "REPLAY_DETECTED", {}
        state.seen.add(mid)
        return "success", None, {}

    sub = inp.get("tct_token_claims", {}).get("sub")

    if op == "issue_pop_challenge":  # verifier mints a fresh nonce (RFC-AITP-0005 §6.1)
        state.nonce = b64url_encode(sha256(b"aitp-pop:" + str(inp.get("tct_token_claims", {}).get("jti")).encode())[:16])
        state.pop_challenge_issued = True
        return "success", None, {}
    if op == "produce_pop_response":  # holder signs sha256(decode(nonce)) with the subject key
        assert state.nonce is not None
        sig = keys[sub].sign_digest(sha256(b64url_decode(state.nonce)))
        state.pop_response = {"nonce_echo": state.nonce, "pop_signature": b64url_encode(sig)}
        return "success", None, {}
    if op == "verify_pop_response":  # verifier checks nonce echo + signature under the subject key
        assert state.nonce is not None and state.pop_response is not None
        key = parse_aid(str(sub)).public_key
        ok = state.pop_response["nonce_echo"] == state.nonce and key.verify_digest(
            sha256(b64url_decode(state.nonce)), b64url_decode(state.pop_response["pop_signature"])
        )
        return ("success", None, {}) if ok else ("failure", "POP_RESPONSE_INVALID", {})

    if op == "authorize_capability_invocation":  # marked grant -> verifier MUST issue a challenge (§6.2)
        if _pop_required(inp):
            state.pop_challenge_issued = True
        return "success", None, {}
    if op == "expect_pop_challenge_issued":
        return "success", None, {"pop_challenge_issued": state.pop_challenge_issued}
    if op == "withhold_pop_response":  # no valid response -> reject, do NOT authorize
        state.capability_authorized = False
        return "failure", "POP_RESPONSE_INVALID", {"capability_authorized": False}

    return None


def _run_sequence(inp: dict[str, Any], keys: dict[str, Any]) -> tuple[str, str]:
    """Execute a multi-step sequence (replay dedup, PoP challenge/response)."""
    state = _SeqState()
    for i, step in enumerate(inp["sequence"]):
        result = _run_step(state, step, inp, keys)
        if result is None:
            return SKIP, f"unsupported sequence op {step.get('operation')}"
        outcome, code, side = result
        exp = step.get("expected", {})
        if exp.get("outcome") == "success" and outcome != "success":
            return FAIL, f"step {i} ({step.get('operation')}): expected success, got {code}"
        if exp.get("outcome") == "failure" and not (outcome == "failure" and code == exp.get("error_code")):
            return FAIL, f"step {i} ({step.get('operation')}): expected {exp.get('error_code')}, got {outcome}/{code}"
        for k, v in exp.get("side_effects", {}).items():
            if side.get(k) != v:
                return FAIL, f"step {i}: side effect {k}={side.get(k)}, expected {v}"
    return PASS, "sequence"


def _cover_unsupplied_issuers(inp: dict[str, Any]) -> dict[str, Any]:
    """The spec's per-issuer fixture convention (conformance README, "Revocation
    inputs", spec 59407d2). In a delegation fixture that supplies
    ``revocation_snapshots``, an issuer with no entry is not under test and
    reads "not revoked" whatever the mode. Only the supplied entries are
    evaluated, including being discarded under RFC-AITP-0008 §1.5.

    The library applies ``fail_mode`` to an issuer with no snapshot (RFC-AITP-0008
    §3.1, RFC-AITP-0011 §6), which is right for a deployment. Here it would make
    ``del-mh-004``/``del-mh-006`` pass on A's or C's absence rather than on the
    supplied entry. So the adapter gives every uncovered issuer (``self_aid``,
    the token's ``iss`` and each hop's ``iss``) a fresh, empty, genuinely signed
    snapshot, which is what "not revoked" means to the verifier.
    """
    snaps = inp.get("revocation_snapshots")
    if inp.get("operation") != "verify_delegation_token" or not isinstance(snaps, list):
        return inp
    claims = inp.get("delegation_token_claims") or {}
    hop_issuers = [h.get("iss") for h in claims.get("chain_claims") or []]
    covered = {r.get("issuer_aid") for r in snaps if isinstance(r, dict)}
    now = int(inp.get("now", REFERENCE_CLOCK))
    added = []
    for aid in dict.fromkeys([inp.get("self_aid"), claims.get("iss"), *hop_issuers]):
        if isinstance(aid, str) and aid not in covered:
            body = {
                "version": PROTOCOL_VERSION,
                "issuer": aid,
                "published_at": now,
                "expires_at": now + 3600,
                "entries": [],
            }
            added.append({"issuer_aid": aid, "snapshot": {"revocation_list": body, "signature": "__VALID_B_SIG__"}})
    return {**inp, "revocation_snapshots": [*snaps, *added]} if added else inp


def run_fixture(fixture: dict[str, Any], keys: dict[str, Any]) -> tuple[str, str]:
    inp = fixture.get("input", {})
    expected = fixture.get("expected", {})

    if "sequence" in inp:
        return _run_sequence(inp, keys)

    op = inp.get("operation")
    if op is None or not supported(op):
        return SKIP, f"unsupported operation: {op}"

    try:
        minted = mint_input(_cover_unsupplied_issuers(inp), REFERENCE_CLOCK, keys)
    except (MinterError, KeyError) as exc:
        return SKIP, f"could not mint fixture: {exc}"
    minted["_feature"] = fixture.get("feature")

    # `verify_tct`/`verify_delegation_token` require a top-level `policy` key
    # (a revocation decision is mandatory, not optional -- a caller must say
    # explicitly how to treat absent revocation data, per `/reconcile` on
    # `plans/archive/hardening-issues-30-31.md`). This runner is a deployment, the
    # same role it already plays via `_feature` above, and most conformance
    # fixtures predate `policy` entirely: supply the pack's own long-standing
    # default (`fail_open`, i.e. run the fixture as every implementation ran
    # it before `policy` existed) for one that carries none, exactly as a
    # real deployment would supply its own configured policy rather than
    # leaving the decision unmade. A fixture that DOES carry a `policy`
    # always wins -- `setdefault` only fills the gap, never overrides.
    #
    # Two narrower gaps take the fixture's own declared decision instead
    # (RFC-AITP-0008 §1.5, 0.3.1-draft): a `verify_tct` wrapper declaring
    # `fail_mode` is the fixture's decision (`tct-022`/`tct-023`), so no
    # top-level `policy` is added over it; and a delegation fixture carrying
    # `revocation_snapshots` gets the schema default `fail_closed`
    # (`del-mh-006`), since its expected outcome is stated under that default.
    revlist = minted.get("issuer_revocation_list")
    declares_mode = isinstance(revlist, dict) and "fail_mode" in revlist
    if op == "verify_delegation_token" and "revocation_snapshots" in minted:
        minted.setdefault("policy", {"fail_mode": "fail_closed"})
    elif op in ("verify_tct", "verify_attestation", "verify_delegation_token") and not declares_mode:
        minted.setdefault("policy", {"fail_mode": "fail_open"})

    try:
        OPERATIONS[op](minted)
        outcome, code = "success", None
    except AitpError as exc:
        outcome, code = "failure", exc.code
    except Exception as exc:  # noqa: BLE001 - a crash is a fixture failure, not a runner abort
        return FAIL, f"verifier raised {type(exc).__name__}: {exc}"

    if expected.get("outcome") == "success":
        if outcome == "success":
            return PASS, "success"
        return FAIL, f"expected success, got failure/{code}"

    exp_code = expected.get("error_code")
    if outcome == "failure" and code == exp_code:
        return PASS, str(code)
    return FAIL, f"expected failure/{exp_code}, got {outcome}/{code}"


class PackResult:
    """Per-fixture rows plus the profile gate's verdict."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.rows: list[tuple[str, str, str]] = []
        self.violations: list[str] = []
        self.exempted: list[str] = []

    @property
    def exit_code(self) -> int:
        return 1 if self.counts[FAIL] or self.violations else 0


def run_pack(conf_dir: Path, keys: dict[str, Any], profile: str = "v0.2") -> PackResult:
    """Run every fixture in *conf_dir* and apply the *profile* gate."""
    flag = PROFILES[profile]
    res = PackResult()
    for path in sorted(conf_dir.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        if "id" not in fixture or "input" not in fixture:
            continue  # not a scenario fixture (e.g. a schema helper)
        fid = fixture["id"]
        required = is_required(fixture, flag)
        feature = negating_feature(fixture)
        if required and feature is not None:
            status, detail = SKIP, f"feature `{feature}` enabled — assertion no longer applies"
            res.exempted.append(f"{fid}: {detail}")
        elif required or is_required(fixture, CURRENT_TIER) or fixture.get("feature") in SUPPORTED_FEATURES:
            status, detail = run_fixture(fixture, keys)
            if required and status == SKIP:
                res.violations.append(f"{fid}: SKIP of a required fixture — {detail}")
        else:
            status, detail = SKIP, "not core (draft/extension/v0.1-frozen)"
        res.counts[status] += 1
        res.rows.append((status, fid, detail))
    return res


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--spec-dir", required=True, type=Path, help="path to the agentidentitytrustprotocol spec repo")
    ap.add_argument("--profile", choices=sorted(PROFILES), default="v0.2",
                    help="core tier to gate on (default v0.2, the aitp/0.3 core tier)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    conf_dir = args.spec_dir / "schemas/conformance"
    if not conf_dir.is_dir():
        print(f"conformance dir not found: {conf_dir}", file=sys.stderr)
        return 2
    res = run_pack(conf_dir, load_kat_keys(args.spec_dir), args.profile)

    # Windows' default stdout encoding is cp1252, which cannot encode the
    # ✓/✗/– markers below -- the runner died with UnicodeEncodeError there
    # before this, while passing everywhere else. Reconfiguring beats
    # downgrading the markers to ASCII for every other platform, and
    # errors="replace" means a console that still cannot represent them
    # prints a placeholder instead of taking the whole run down.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")

    width = max(len(fid) for _, fid, _ in res.rows) if res.rows else 10
    for status, fid, detail in res.rows:
        if status == SKIP and not args.verbose:
            continue
        marker = {PASS: "✓", FAIL: "✗", SKIP: "–"}[status]
        print(f"{marker} {status:4} {fid:<{width}}  {detail}")

    print()
    print(f"{res.counts[PASS]} passed, {res.counts[FAIL]} failed, {res.counts[SKIP]} skipped")
    for line in res.exempted:
        print(f"{args.profile} gate: exempted {line}", file=sys.stderr)
    for line in res.violations:
        print(f"{args.profile} gate: {line}", file=sys.stderr)
    return res.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
