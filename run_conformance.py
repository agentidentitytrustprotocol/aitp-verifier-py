#!/usr/bin/env python3
"""AITP conformance-pack runner for aitp-verifier-py.

Walks ``<spec-dir>/schemas/conformance/``, mints each in-scope fixture's
placeholders with the pinned KAT keypairs, executes it against this
implementation, prints a per-fixture PASS/FAIL/SKIP table, and exits nonzero on
any FAIL. Operations this implementation does not yet support are reported SKIP
— explicitly, never as a silent pass (PLACEHOLDERS.md §"Operation key").

``--claim`` (default ``AITP v0.3``) names the RFC-AITP-0001 §10 claim to
gate on, as the spec's ``docs/conformance-badge.md`` defines it. Every fixture
behind the claim MUST pass: for ``AITP v0.3`` that is each ``status: core``
fixture with ``required_for_core``, so a SKIP of one also exits nonzero (§10
item 9; the conformance README, "Conformance runner enforcement rules"). An
extension claim gates on every fixture carrying its ``feature``.

Usage:
    python run_conformance.py --spec-dir ../agentidentitytrustprotocol [--claim "AITP v0.3"]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from collections import Counter
from pathlib import Path
from typing import Any

from aitp_verifier.aid import parse_aid
from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.crypto import sha256
from aitp_verifier.harness import FixtureError, pop_required, run_operation
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.minter import MinterError, mint_input
from aitp_verifier.timeutil import REFERENCE_CLOCK
from aitp_verifier.verify import OPERATIONS, supported
from aitp_verifier.version import PROTOCOL_VERSION

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"

# Draft opt-in features this implementation now exercises. A non-required
# fixture is run when its `feature` is one of these; otherwise it is out of
# scope (Draft not-yet-implemented, or a v0.1-frozen fixture).
SUPPORTED_FEATURES = {
    "experimental-multihop-delegation",
    "experimental-session-bundle",
    "experimental-spiffe-identity",
    "aitp-self-attestation",
}

# The RFC-AITP-0001 §10 claim strings (conformance-badge.md, "Claims") -> the
# fixture `feature` an extension claim gates on. The core claim, None, gates on
# `required_for_core`. There are no other claims and no named profiles.
CORE_CLAIM = "AITP v0.3"
CLAIMS: dict[str, str | None] = {
    CORE_CLAIM: None,
    "AITP v0.3 pinned-admission": "aitp-pinned-admission",
    "AITP v0.3 self-attestation": "aitp-self-attestation",
}

def is_required(fixture: dict[str, Any]) -> bool:
    """A core fixture's ``required_for_core`` flag; absent counts as required,
    as in aitp-rs, so a fixture missing its metadata is never quietly skipped."""
    return fixture.get("status", "core") == "core" and fixture.get("required_for_core", True) is True


def gates(fixture: dict[str, Any], claim: str) -> bool:
    """Whether *fixture* is behind *claim*."""
    feature = CLAIMS[claim]
    return is_required(fixture) if feature is None else fixture.get("feature") == feature


class _SeqState:
    """State carried across the steps of a multi-step conformance sequence."""

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.nonce: str | None = None
        self.pop_response: dict[str, str] | None = None
        self.pop_challenge_issued = False
        self.capability_authorized = False


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
        if pop_required(inp, inp.get("tct_token_claims", {})):
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
        code, result = run_operation(op, minted, keys, accept_presented_type=fixture["id"].startswith("id-"))
    except FixtureError as exc:
        return FAIL, f"malformed fixture: {exc}"
    except Exception as exc:  # noqa: BLE001 - a crash is a fixture failure, not a runner abort
        return FAIL, f"verifier raised {type(exc).__name__}: {exc}"
    outcome = "success" if code is None else "failure"

    authorized = expected.get("side_effects", {}).get("capability_authorized")
    if authorized is not None and authorized != (outcome == "success"):
        return FAIL, f"side effect capability_authorized={outcome == 'success'}, expected {authorized}"

    if expected.get("outcome") == "success":
        if outcome != "success":
            return FAIL, f"expected success, got failure/{code}"
        if op == "verify_tct_as_issuer":
            for key in ("presenter_aid", "grants"):
                if key in expected and result.get(key) != expected[key]:
                    return FAIL, f"{key} {result.get(key)!r}, expected {expected[key]!r}"
        return PASS, "success"

    exp_code = expected.get("error_code")
    if outcome == "failure" and code == exp_code:
        return PASS, str(code)
    return FAIL, f"expected failure/{exp_code}, got {outcome}/{code}"


class PackResult:
    """Per-fixture rows plus the claim gate's verdict."""

    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.rows: list[tuple[str, str, str]] = []
        self.violations: list[str] = []
        # Fixture id -> the fixture, for the report's copied metadata.
        self.fixtures: dict[str, dict[str, Any]] = {}

    @property
    def exit_code(self) -> int:
        return 1 if self.counts[FAIL] or self.violations else 0


def run_pack(conf_dir: Path, keys: dict[str, Any], claim: str = CORE_CLAIM) -> PackResult:
    """Run every fixture in *conf_dir* and apply the *claim* gate."""
    res = PackResult()
    for path in sorted(conf_dir.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        if "id" not in fixture or "input" not in fixture:
            continue  # not a scenario fixture (e.g. a schema helper)
        fid = fixture["id"]
        if fixture.get("status") == "reserved":
            continue  # ignored by every runner (conformance README)
        res.fixtures[fid] = fixture
        if is_required(fixture) or fixture.get("feature") in SUPPORTED_FEATURES:
            status, detail = run_fixture(fixture, keys)
        else:
            status, detail = SKIP, "not core (draft/extension/v0.1-frozen)"
        if status == SKIP and gates(fixture, claim):
            res.violations.append(f"{fid}: SKIP of a fixture behind the claim — {detail}")
        res.counts[status] += 1
        res.rows.append((status, fid, detail))
    return res


# ── Conformance report (spec docs/conformance-badge.md, report_version "1") ──

REPOSITORY = "https://github.com/agentidentitytrustprotocol/aitp-verifier-py"
OUTCOMES = {PASS: "pass", FAIL: "fail", SKIP: "skip"}


class ReportError(Exception):
    """The report's provenance cannot be established, so none is written."""


def _git(repo: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout.strip()


def spec_provenance(spec_dir: Path, commit: str | None, spec_version: str | None) -> dict[str, str]:
    """``spec.commit`` and ``spec.version``, never guessed: the flags, else a
    clean spec checkout's ``HEAD`` and its newest ``v*`` tag."""
    if commit is None:
        if _git(spec_dir, "status", "--porcelain", "--", "schemas/conformance") != "":
            raise ReportError(f"{spec_dir} is not a clean git checkout; pass --spec-commit")
        commit = _git(spec_dir, "rev-parse", "HEAD")
    if commit is None or len(commit) != 40:
        raise ReportError("cannot determine the spec commit; pass --spec-commit")
    if spec_version is None:
        spec_version = _git(spec_dir, "describe", "--tags", "--abbrev=0", "--match", "v[0-9]*", commit)
    if not spec_version:
        raise ReportError("no v* tag at or before the spec commit; pass --spec-version")
    return {"commit": commit, "version": spec_version, "protocol": PROTOCOL_VERSION}


def fixtures_dir_digest(conf_dir: Path) -> str:
    """``sha256:`` + SHA-256 of the ``sha256sum`` listing of the top-level
    ``*.json`` files, sorted by name in byte order (conformance-badge.md)."""
    names = sorted((p.name for p in conf_dir.glob("*.json") if p.is_file()), key=lambda n: n.encode())
    listing = "".join(f"{hashlib.sha256((conf_dir / n).read_bytes()).hexdigest()}  {n}\n" for n in names)
    return "sha256:" + hashlib.sha256(listing.encode()).hexdigest()


def _implementation() -> dict[str, str]:
    try:
        impl = {"name": "aitp-verifier-py", "version": version("aitp-verifier"), "repository": REPOSITORY}
    except PackageNotFoundError:
        impl = {"name": "aitp-verifier-py", "version": "unknown", "repository": REPOSITORY}
    here = Path(__file__).resolve().parent
    commit = _git(here, "rev-parse", "HEAD")
    if commit and _git(here, "status", "--porcelain", "--", "aitp_verifier") == "":
        impl["commit"] = commit
    return impl


def build_report(res: PackResult, conf_dir: Path, spec: dict[str, str], features: list[str],
                 ci_run_url: str | None = None) -> dict[str, Any]:
    results = []
    for status, fid, detail in res.rows:
        fixture = res.fixtures[fid]
        row: dict[str, Any] = {
            "id": fid,
            "status": fixture["status"],
            "feature": fixture.get("feature"),
            "required_for_core": fixture.get("required_for_core"),
            "outcome": OUTCOMES[status],
        }
        if status != PASS:
            row["reason"] = detail
        results.append(row)
    totals = {tier: {o: 0 for o in ("pass", "fail", "skip", "excluded_by_role")} for tier in ("core", "extension", "draft")}
    for row in results:
        totals[row["status"]][row["outcome"]] += 1
    gate_list = []
    for claim, feature in CLAIMS.items():
        if feature is not None and feature not in features:
            continue  # an extension claim is evaluated only when its feature is enabled
        blocking = [r["id"] for r in results if gates(res.fixtures[r["id"]], claim) and r["outcome"] != "pass"]
        covered = feature is None or any(r["feature"] == feature for r in results)
        gate: dict[str, Any] = {
            "name": claim,
            "passed": covered and not blocking,
            "criteria": "core-required-all-pass" if feature is None else "feature-all-pass",
        }
        if blocking:
            gate["blocking"] = blocking
        gate_list.append(gate)
    doc: dict[str, Any] = {
        "report_version": "1",
        "implementation": _implementation(),
        "spec": spec,
        "fixtures_dir_digest": fixtures_dir_digest(conf_dir),
        "features_enabled": features,
        "results": results,
        "totals": totals,
        "gates": gate_list,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if ci_run_url:
        doc["provenance"] = {"ci_run_url": ci_run_url}
    return doc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--spec-dir", required=True, type=Path, help="path to the agentidentitytrustprotocol spec repo")
    ap.add_argument("--claim", choices=list(CLAIMS), default=CORE_CLAIM,
                    help=f"RFC-AITP-0001 §10 claim to gate on (default {CORE_CLAIM!r})")
    ap.add_argument("--report", type=Path, metavar="PATH",
                    help="also write the spec's conformance report (aitp-conformance-report.schema.json)")
    ap.add_argument("--spec-commit", help="report spec.commit (default: HEAD of a clean --spec-dir checkout)")
    ap.add_argument("--spec-version", help="report spec.version (default: the newest v* tag at that commit)")
    ap.add_argument("--ci-run-url", help="report provenance.ci_run_url")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    conf_dir = args.spec_dir / "schemas/conformance"
    if not conf_dir.is_dir():
        print(f"conformance dir not found: {conf_dir}", file=sys.stderr)
        return 2
    if args.report is not None:
        try:
            spec = spec_provenance(args.spec_dir, args.spec_commit, args.spec_version)
        except ReportError as exc:
            print(f"--report: {exc}", file=sys.stderr)
            return 2
    res = run_pack(conf_dir, load_kat_keys(args.spec_dir), args.claim)
    if args.report is not None:
        doc = build_report(res, conf_dir, spec, sorted(SUPPORTED_FEATURES), args.ci_run_url)
        args.report.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")

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
    for line in res.violations:
        print(f"{args.claim} gate: {line}", file=sys.stderr)
    return res.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
