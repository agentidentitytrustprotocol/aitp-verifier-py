"""Drive the whole conformance pack and assert no in-scope fixture FAILs.

Every ``required_for_core`` fixture must pass; unsupported operations report
SKIP (never a silent pass), and a SKIP of a fixture behind the claim fails the
claim gate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.keys import load_kat_keys
from aitp_verifier.harness import (
    NOT_TESTED, FixtureError, cover_unsupplied_issuers, issuer_resolver, receiver_policy, revocation_conventions,
)
from aitp_verifier.minter import mint_input
from aitp_verifier.timeutil import REFERENCE_CLOCK
from run_conformance import CLAIMS, FAIL, PASS, SKIP, main, parse_args, run_pack


def test_conformance_pack_has_no_failures(spec_dir: Path) -> None:
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir))
    for status, fid, detail in res.rows:
        if status == FAIL:
            print(f"FAIL {fid}: {detail}")
    assert res.counts[FAIL] == 0
    assert res.violations == []
    assert res.exit_code == 0
    # All 94 core + 14 Draft opt-ins + 3 self-attestation at spec ac481f8.
    assert res.counts[PASS] >= 111


def test_del_007_runs_feature_less(spec_dir: Path) -> None:
    """Core fixtures run with no draft feature opted in, so del-007's
    not-supported assertion is exercised, not waived."""
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir))
    assert (PASS, "del-007", "DELEGATION_MULTIHOP_NOT_SUPPORTED") in res.rows


def test_self_attestation_claim_passes(spec_dir: Path) -> None:
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir), "AITP v0.3 self-attestation")
    assert res.exit_code == 0


def test_pinned_admission_claim_is_blocked_by_its_skipped_fixtures(spec_dir: Path) -> None:
    """This verifier does not implement the profile, so the claim fails on
    the skips rather than passing on an empty set."""
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir), "AITP v0.3 pinned-admission")
    assert res.exit_code == 1
    assert {v.split(":")[0] for v in res.violations} >= {"id-013", "id-019"}


def test_claim_choices_are_the_rfc_0001_claim_strings() -> None:
    assert list(CLAIMS) == ["AITP v0.3", "AITP v0.3 pinned-admission", "AITP v0.3 self-attestation"]
    assert parse_args(["--spec-dir", "x"]).claim == "AITP v0.3"
    assert parse_args(["--spec-dir", "x", "--claim", "AITP v0.3 self-attestation"]).claim == "AITP v0.3 self-attestation"


def test_min_passed_floor_accepts_count_and_rejects_drop(spec_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    passed = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir)).counts[PASS]
    assert main(["--spec-dir", str(spec_dir), "--min-passed", str(passed)]) == 0
    capsys.readouterr()

    assert main(["--spec-dir", str(spec_dir), "--min-passed", str(passed + 1)]) == 1
    assert f"passed {passed} < required {passed + 1}" in capsys.readouterr().err


def test_only_filters_rows_counts_and_fixtures(spec_dir: Path) -> None:
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir), only="del-mh-*")
    assert res.rows
    ids = {fid for _, fid, _ in res.rows}
    assert all(fid.startswith("del-mh-") for fid in ids)
    assert set(res.fixtures) == ids
    assert sum(res.counts.values()) == len(res.rows)


def test_only_with_no_matches_exits_2(spec_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--spec-dir", str(spec_dir), "--only", "nope-*"]) == 2
    captured = capsys.readouterr()
    assert captured.err == "no fixture matches --only nope-*\n"
    assert captured.out == ""


def test_only_cannot_write_incomplete_report(spec_dir: Path, tmp_path: Path,
                                             capsys: pytest.CaptureFixture[str]) -> None:
    report = tmp_path / "partial.json"
    assert main(["--spec-dir", str(spec_dir), "--only", "env-*", "--report", str(report)]) == 2
    assert capsys.readouterr().err == "--report requires the full fixture pack; omit --only\n"
    assert not report.exists()


@pytest.mark.parametrize("argv", [
    ["--profile", "core"],
    ["--profile", "v0.1"],
    ["--claim", "core"],
    ["--claim", "v0.1"],
])
def test_profile_flag_and_profile_names_are_rejected(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        parse_args(["--spec-dir", "x", *argv])
    assert exc.value.code == 2


def _pack(tmp_path: Path, **fixture: Any) -> Path:
    body = {"id": "syn-001", "input": {"operation": "no_such_operation"}, "expected": {"outcome": "success"}}
    body.update(fixture)
    (tmp_path / "syn-001.json").write_text(json.dumps(body), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("meta", [
    pytest.param({"status": "core", "required_for_core": True}, id="flagged"),
    pytest.param({"status": "core"}, id="flag-absent-counts-as-required"),
])
def test_skip_of_a_required_fixture_fails_the_gate(meta: dict[str, Any], tmp_path: Path, spec_dir: Path) -> None:
    res = run_pack(_pack(tmp_path, **meta), load_kat_keys(spec_dir))
    assert res.rows[0][0] == SKIP
    assert res.violations and res.exit_code == 1


def test_only_keeps_gate_for_selected_required_skip(tmp_path: Path, spec_dir: Path) -> None:
    pack = _pack(tmp_path, status="core", required_for_core=True)
    (tmp_path / "draft-001.json").write_text(json.dumps({
        "id": "draft-001", "input": {"operation": "no_such_operation"},
        "expected": {"outcome": "success"}, "status": "draft", "feature": "not-implemented",
    }), encoding="utf-8")
    keys = load_kat_keys(spec_dir)
    required = run_pack(pack, keys, only="syn-*")
    assert required.counts[SKIP] == 1
    assert required.violations and required.exit_code == 1
    draft = run_pack(pack, keys, only="draft-*")
    assert draft.counts[SKIP] == 1
    assert draft.violations == [] and draft.exit_code == 0


def test_skip_of_a_non_required_fixture_passes_the_gate(tmp_path: Path, spec_dir: Path) -> None:
    res = run_pack(_pack(tmp_path, status="draft", required_for_core=False, feature="not-implemented"),
                   load_kat_keys(spec_dir))
    assert res.rows[0][0] == SKIP
    assert res.exit_code == 0


def test_required_under_v0_1_only_is_not_gated(tmp_path: Path, spec_dir: Path) -> None:
    pack = _pack(tmp_path, status="core", required_for_v0_1=True, required_for_core=False)
    assert run_pack(pack, load_kat_keys(spec_dir)).exit_code == 0


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
    raw = _fixture(spec_dir, "del-mh-006")["input"]
    keys = load_kat_keys(spec_dir)
    inp = mint_input(raw, REFERENCE_CLOCK, keys)
    covered = cover_unsupplied_issuers(inp, keys)
    supplied, added = covered["revocation_snapshots"][:1], covered["revocation_snapshots"][1:]
    assert supplied == inp["revocation_snapshots"]
    claims = raw["delegation_token_claims"]
    expected = {inp["self_aid"], claims["iss"], *(h["iss"] for h in claims["chain_claims"])}
    expected -= {r["issuer_aid"] for r in inp["revocation_snapshots"]}
    assert {r["issuer_aid"] for r in added} == expected and inp["self_aid"] in expected
    assert all(r["snapshot"]["revocation_list"]["entries"] == [] for r in added)
    assert all(not r["snapshot"]["signature"].startswith("__") for r in added)


def test_fixture_without_revocation_input_is_left_alone(spec_dir: Path) -> None:
    inp = _fixture(spec_dir, "del-mh-001")["input"]
    assert "revocation_snapshots" not in inp
    assert cover_unsupplied_issuers(inp, load_kat_keys(spec_dir)) is inp


# ── Revocation inputs (README, "Revocation inputs") ─────────────────────────


def _unavailable(**extra: Any) -> dict[str, Any]:
    return {"issuer_revocation_list": {"issuer": "aid:pubkey:x", "available": False, **extra}}


def test_unavailable_source_with_no_mode_runs_the_verifier_default() -> None:
    """tct-024: no snapshot reaches the verifier and no mode is set, so the
    verifier's own default (fail_closed) decides."""
    out = revocation_conventions("verify_tct", _unavailable())
    assert "issuer_revocation_list" not in out
    assert "policy" not in out


def test_unavailable_source_with_a_mode_configures_that_mode() -> None:
    """tct-025: the fixture's fail_mode is the verifier's configured mode."""
    out = revocation_conventions("verify_tct", _unavailable(fail_mode="fail_open"))
    assert "issuer_revocation_list" not in out
    assert out["policy"] == {"fail_mode": "fail_open"}


def test_unavailable_source_beside_a_snapshot_is_a_fixture_error() -> None:
    with pytest.raises(FixtureError):
        revocation_conventions("verify_tct", _unavailable(snapshot={"revocation_list": {}, "signature": "x"}))


def test_non_boolean_available_is_a_fixture_error() -> None:
    with pytest.raises(FixtureError):
        revocation_conventions("verify_tct", {"issuer_revocation_list": {"available": "no"}})


def test_available_snapshot_keeps_the_wrapper_and_maps_the_mode() -> None:
    out = revocation_conventions("verify_tct", {"issuer_revocation_list": {"issuer": "i", "snapshot": {}, "fail_mode": "soft_fail"}})
    assert out["issuer_revocation_list"] == {"issuer": "i", "snapshot": {}}
    assert out["policy"] == {"fail_mode": "soft_fail"}


def test_no_revocation_input_is_not_tested() -> None:
    assert revocation_conventions("verify_tct", {})["policy"] == NOT_TESTED
    assert revocation_conventions("verify_delegation_token", {})["policy"] == NOT_TESTED
    assert "policy" not in revocation_conventions("verify_delegation_token", {"revocation_snapshots": []})


def test_a_fixture_policy_wins() -> None:
    out = revocation_conventions("verify_tct", {"policy": {"fail_mode": "fail_closed"}, **_unavailable(fail_mode="fail_open")})
    assert out["policy"] == {"fail_mode": "fail_closed"}


@pytest.mark.parametrize(("fixture_id", "detail"), [("tct-024", "TCT_REVOKED"), ("tct-025", "success")])
def test_unavailable_source_fixtures(spec_dir: Path, fixture_id: str, detail: str) -> None:
    res = run_pack(spec_dir / "schemas/conformance", load_kat_keys(spec_dir))
    assert (PASS, fixture_id, detail) in res.rows


# ── Receiver policy inputs (README, "Receiver policy inputs") ───────────────


def _hello(itype: str, **extra: Any) -> dict[str, Any]:
    return {"envelope": {"payload": {"identity": {"type": itype}}}, **extra}


def test_receiver_trusts_only_the_runner_issuer_by_default() -> None:
    inp = _hello("oidc")
    receiver_policy(inp, accept_presented_type=False)
    assert inp["self_trust_anchors"] == ["https://auth.openai.com"]
    assert "self_accepted_identity_types" not in inp  # mh-*: the verifier default


def test_id_fixture_accepts_the_presented_type() -> None:
    inp = _hello("pinned_key")
    receiver_policy(inp, accept_presented_type=True)
    assert inp["self_accepted_identity_types"] == ["pinned_key"]


def test_stated_receiver_policy_is_kept() -> None:
    inp = _hello("pinned_key", self_accepted_identity_types=["oidc"], self_trust_anchors=["https://x"])
    receiver_policy(inp, accept_presented_type=True)
    assert inp["self_accepted_identity_types"] == ["oidc"]
    assert inp["self_trust_anchors"] == ["https://x"]


def test_issuer_resolver_resolves_the_pinned_trusted_issuer_only(spec_dir: Path) -> None:
    """PLACEHOLDERS.md "Identity-issuer keys": https://auth.openai.com is
    kat-oidc-issuer-001, read from the file, and no other issuer resolves."""
    vectors = json.loads((spec_dir / "schemas/conformance/known-answer/oidc-test-issuers.json")
                         .read_text(encoding="utf-8"))["vectors"]
    trusted = next(v for v in vectors if v["id"] == "kat-oidc-issuer-001")
    assert issuer_resolver(load_kat_keys(spec_dir)) == {trusted["issuer"]: trusted["pubkey_b64url"]}


def test_corpus_oidc_jwts_are_signed_with_the_pinned_keys(spec_dir: Path) -> None:
    from aitp_verifier.jws import parse_compact

    keys = load_kat_keys(spec_dir)
    for fixture_id, key_id in (("id-009", "kat-oidc-issuer-001"), ("mh-004", "kat-oidc-issuer-002-unknown")):
        path = next((spec_dir / "schemas/conformance").glob(f"{fixture_id}-*.json"))
        minted = mint_input(json.loads(path.read_text(encoding="utf-8"))["input"], REFERENCE_CLOCK, keys)
        assert "resolved_issuer_keys" not in minted  # the resolver is the runner's, not the minter's
        jws = parse_compact(minted["envelope"]["payload"]["identity"]["proof"])
        assert keys[key_id].public_key().verify_jose(jws.signing_input, jws.signature)
