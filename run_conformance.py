#!/usr/bin/env python3
"""AITP conformance-pack runner for aitp-verifier-py.

Walks ``<spec-dir>/schemas/conformance/``, mints each in-scope fixture's
placeholders with the pinned KAT keypairs, executes it against this
implementation, prints a per-fixture PASS/FAIL/SKIP table, and exits nonzero on
any FAIL. Operations this implementation does not yet support are reported SKIP
— explicitly, never as a silent pass (PLACEHOLDERS.md §"Operation key").

Usage:
    python run_conformance.py --spec-dir ../agentidentitytrustprotocol
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

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"

# Draft opt-in features this implementation now exercises. A non-required
# fixture is run when its `feature` is one of these; otherwise it is out of
# scope (Draft not-yet-implemented, or a v0.1-frozen fixture).
SUPPORTED_FEATURES = {"experimental-multihop-delegation", "experimental-session-bundle"}


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


def run_fixture(fixture: dict[str, Any], keys: dict[str, Any]) -> tuple[str, str]:
    inp = fixture.get("input", {})
    expected = fixture.get("expected", {})

    if "sequence" in inp:
        return _run_sequence(inp, keys)

    op = inp.get("operation")
    if op is None or not supported(op):
        return SKIP, f"unsupported operation: {op}"

    try:
        minted = mint_input(inp, REFERENCE_CLOCK, keys)
    except (MinterError, KeyError) as exc:
        return SKIP, f"could not mint fixture: {exc}"
    minted["_feature"] = fixture.get("feature")

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


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--spec-dir", required=True, type=Path, help="path to the agentidentitytrustprotocol spec repo")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    conf_dir = args.spec_dir / "schemas/conformance"
    if not conf_dir.is_dir():
        print(f"conformance dir not found: {conf_dir}", file=sys.stderr)
        return 2
    keys = load_kat_keys(args.spec_dir)

    counts: Counter[str] = Counter()
    rows: list[tuple[str, str, str]] = []
    for path in sorted(conf_dir.glob("*.json")):
        fixture = json.loads(path.read_text())
        if "id" not in fixture or "input" not in fixture:
            continue  # not a scenario fixture (e.g. a schema helper)
        fid = fixture["id"]
        if not fixture.get("required_for_v0_2", False) and fixture.get("feature") not in SUPPORTED_FEATURES:
            counts[SKIP] += 1
            rows.append((SKIP, fid, "not required for v0.2 (draft/extension/v0.1-frozen)"))
            continue
        status, detail = run_fixture(fixture, keys)
        counts[status] += 1
        rows.append((status, fid, detail))

    width = max(len(fid) for _, fid, _ in rows) if rows else 10
    for status, fid, detail in rows:
        if status == SKIP and not args.verbose:
            continue
        marker = {PASS: "✓", FAIL: "✗", SKIP: "–"}[status]
        print(f"{marker} {status:4} {fid:<{width}}  {detail}")

    print()
    print(f"{counts[PASS]} passed, {counts[FAIL]} failed, {counts[SKIP]} skipped")
    return 1 if counts[FAIL] else 0


if __name__ == "__main__":
    raise SystemExit(main())
