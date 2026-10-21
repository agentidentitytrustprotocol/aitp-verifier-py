"""Drive the whole conformance pack and assert no in-scope fixture FAILs.

Every ``required_for_v0_2`` fixture whose operation this implementation
supports must pass; unsupported operations report SKIP (never a silent pass),
and a SKIP of a required core fixture fails the profile gate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.keys import load_kat_keys
from run_conformance import FAIL, PASS, SKIP, _cover_unsupplied_issuers, run_pack


def test_conformance_pack_has_no_failures(spec_dir: Path) -> None:
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir))
    for status, fid, detail in res.rows:
        if status == FAIL:
            print(f"FAIL {fid}: {detail}")
    assert res.counts[FAIL] == 0
    assert res.violations == []
    assert res.exit_code == 0
    assert res.counts[PASS] >= 93  # all 78 core + Draft opt-ins + self-attestation at spec bf00e75


def test_v0_1_profile_exempts_only_del_004(spec_dir: Path) -> None:
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir), "v0.1")
    assert res.exit_code == 0
    assert [line.split(":")[0] for line in res.exempted] == ["del-004"]


def test_del_007_runs_rather_than_being_exempted(spec_dir: Path) -> None:
    """Core fixtures run feature-less here, so del-007's not-supported
    assertion is exercised under the default profile, not waived."""
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir))
    assert (PASS, "del-007", "DELEGATION_MULTIHOP_NOT_SUPPORTED") in res.rows
    assert res.exempted == []


def _pack(tmp_path: Path, **fixture: Any) -> Path:
    body = {"id": "syn-001", "input": {"operation": "no_such_operation"}, "expected": {"outcome": "success"}}
    body.update(fixture)
    (tmp_path / "syn-001.json").write_text(json.dumps(body), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("meta", [
    pytest.param({"status": "core", "required_for_v0_2": True}, id="flagged"),
    pytest.param({"status": "core"}, id="flag-absent-counts-as-required"),
])
def test_skip_of_a_required_fixture_fails_the_gate(meta: dict[str, Any], tmp_path: Path, spec_dir: Path) -> None:
    res = run_pack(_pack(tmp_path, **meta), load_kat_keys(spec_dir))
    assert res.rows[0][0] == SKIP
    assert res.violations and res.exit_code == 1


def test_skip_of_a_non_required_fixture_passes_the_gate(tmp_path: Path, spec_dir: Path) -> None:
    res = run_pack(_pack(tmp_path, status="draft", required_for_v0_2=False, feature="not-implemented"),
                   load_kat_keys(spec_dir))
    assert res.rows[0][0] == SKIP
    assert res.exit_code == 0


def test_required_under_v0_1_only_is_not_gated_under_v0_2(tmp_path: Path, spec_dir: Path) -> None:
    pack = _pack(tmp_path, status="core", required_for_v0_1=True, required_for_v0_2=False)
    assert run_pack(pack, load_kat_keys(spec_dir), "v0.2").exit_code == 0
    assert run_pack(pack, load_kat_keys(spec_dir), "v0.1").exit_code == 1


def _fixture(spec_dir: Path, fixture_id: str) -> dict[str, Any]:
    for path in (spec_dir / "schemas/conformance").glob("*.json"):
        d = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(d, dict) and d.get("id") == fixture_id:
            return d
    raise AssertionError(f"fixture {fixture_id!r} not found")


def test_uncovered_issuers_read_not_revoked(spec_dir: Path) -> None:
    """Spec 59407d2's per-issuer convention: in del-mh-006 only B's snapshot is
    under test. The adapter adds fresh, empty snapshots for A (self) and C, so
    the fixture rejects on B's discarded snapshot, not on A's or C's absence
    under the runner's fail_closed default. B's own entry is left as supplied."""
    inp = _fixture(spec_dir, "del-mh-006")["input"]
    covered = _cover_unsupplied_issuers(inp)
    supplied, added = covered["revocation_snapshots"][:1], covered["revocation_snapshots"][1:]
    assert supplied == inp["revocation_snapshots"]
    claims = inp["delegation_token_claims"]
    expected = {inp["self_aid"], claims["iss"], *(h["iss"] for h in claims["chain_claims"])}
    expected -= {r["issuer_aid"] for r in inp["revocation_snapshots"]}
    assert {r["issuer_aid"] for r in added} == expected and inp["self_aid"] in expected
    assert all(r["snapshot"]["revocation_list"]["entries"] == [] for r in added)


def test_fixture_without_revocation_input_is_left_alone(spec_dir: Path) -> None:
    inp = _fixture(spec_dir, "del-mh-001")["input"]
    assert "revocation_snapshots" not in inp
    assert _cover_unsupplied_issuers(inp) is inp
