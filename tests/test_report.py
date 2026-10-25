"""run_conformance.py --report: the spec's conformance report (report_version
"1"), checked by the spec's own scripts/check-conformance-report.py."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from aitp_verifier.keys import load_kat_keys
from run_conformance import SUPPORTED_FEATURES, build_report, fixtures_dir_digest, main, run_pack

SPEC = {"commit": "0" * 40, "version": "v0.3.2-draft", "protocol": "aitp/0.3"}


def _checker(spec_dir: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_report", spec_dir / "scripts/check-conformance-report.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def report(spec_dir: Path) -> dict[str, Any]:
    conf = spec_dir / "schemas/conformance"
    return build_report(run_pack(conf, load_kat_keys(spec_dir)), conf, SPEC, sorted(SUPPORTED_FEATURES))


def test_report_passes_the_spec_checker(spec_dir: Path, report: dict[str, Any]) -> None:
    assert _checker(spec_dir).check(report, str(spec_dir / "schemas/conformance")) == []


def test_digest_matches_the_spec_checker(spec_dir: Path) -> None:
    conf = spec_dir / "schemas/conformance"
    assert fixtures_dir_digest(conf) == _checker(spec_dir).fixtures_dir_digest(str(conf))


def test_gates_cover_the_core_claim_and_each_enabled_extension(report: dict[str, Any]) -> None:
    assert [g["name"] for g in report["gates"]] == ["AITP v0.3", "AITP v0.3 self-attestation"]
    assert all(g["passed"] for g in report["gates"])


def test_every_non_pass_row_says_why(report: dict[str, Any]) -> None:
    assert all(r.get("reason") for r in report["results"] if r["outcome"] != "pass")


def test_report_refuses_an_unknown_spec_commit(tmp_path: Path, spec_dir: Path,
                                               capsys: pytest.CaptureFixture[str]) -> None:
    """A spec dir that is not a git checkout gives no commit, and no report
    is written rather than one with a guessed provenance."""
    copy = tmp_path / "spec"
    (copy / "schemas/conformance").mkdir(parents=True)
    out = tmp_path / "r.json"
    assert main(["--spec-dir", str(copy), "--report", str(out)]) == 2
    assert not out.exists()
    assert "--spec-commit" in capsys.readouterr().err


def test_report_flag_writes_the_document(tmp_path: Path, spec_dir: Path) -> None:
    out = tmp_path / "r.json"
    rc = main(["--spec-dir", str(spec_dir), "--report", str(out),
               "--spec-commit", SPEC["commit"], "--spec-version", SPEC["version"],
               "--ci-run-url", "https://example.invalid/run/1"])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["spec"] == SPEC and doc["provenance"] == {"ci_run_url": "https://example.invalid/run/1"}
    assert doc["implementation"]["name"] == "aitp-verifier-py"
