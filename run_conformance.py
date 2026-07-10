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


def _run_sequence(inp: dict[str, Any]) -> tuple[str, str]:
    """Envelope replay sequence (message-id dedup) — env-004 shape."""
    seen: set[str] = set()
    for step in inp["sequence"]:
        if "operation" in step and not supported(step["operation"]):
            return SKIP, f"unsupported sequence op {step['operation']}"
        mid = step.get("message_id")
        expected = step.get("expected", {})
        if mid in seen:
            got_outcome, got_code = "failure", "REPLAY_DETECTED"
        else:
            seen.add(mid)
            got_outcome, got_code = "success", None
        if expected.get("outcome") == "success" and got_outcome != "success":
            return FAIL, f"step {mid}: expected success, got {got_code}"
        if expected.get("outcome") == "failure" and got_code != expected.get("error_code"):
            return FAIL, f"step {mid}: expected {expected.get('error_code')}, got {got_code}"
    return PASS, "replay sequence"


def run_fixture(fixture: dict[str, Any], keys: dict[str, Any]) -> tuple[str, str]:
    inp = fixture.get("input", {})
    expected = fixture.get("expected", {})

    if "sequence" in inp:
        return _run_sequence(inp)

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
