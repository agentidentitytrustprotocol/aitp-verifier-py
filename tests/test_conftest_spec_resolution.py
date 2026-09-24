"""Regression test for `conftest.py`'s `spec_dir` fixture (issue #26).

A missing AITP spec checkout must fail the run loudly, not quietly skip the
tests that need it (the old behavior — still green, just a much smaller
suite, easy to miss). The one legitimate no-spec run gets an explicit,
documented opt-out (`AITP_SPEC=none`) instead of relying on absence.

This is inherently a "pytest inside pytest" behavior -- the thing under test
is `spec_dir`'s own fixture-collection-time failure/skip, which only manifests
by actually running a nested `pytest` process against a copy of `conftest.py`
placed somewhere with no `agentidentitytrustprotocol` sibling directory (this
repo's own checkout always has one, on the machine these tests normally run
on, so the real `conftest.py` can't be exercised in place for the "not found"
path).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_CONFTEST = Path(__file__).parent / "conftest.py"


@pytest.fixture
def spec_env_without_aitp_spec() -> dict[str, str]:
    """A copy of this process's environment with `$AITP_SPEC` (and anything
    else that could steer the nested pytest's own behavior) removed, so the
    subprocess doesn't inherit whatever this outer test run was invoked with
    -- e.g. the `AITP_SPEC` this repo's own CI/local dev sets, or a
    `PYTEST_ADDOPTS` this repo doesn't currently set but a future CI change
    might.
    """
    env = dict(os.environ)
    env.pop("AITP_SPEC", None)
    env.pop("PYTEST_ADDOPTS", None)
    return env


def _isolated_copy(tmp_path: Path, *, with_resolvable_sibling: bool = False) -> Path:
    """Copy `conftest.py` + a trivial probe test into a tree with no
    `agentidentitytrustprotocol` sibling anywhere in its ancestry, so
    `_find_spec()`'s sibling-directory candidates cannot accidentally
    succeed regardless of what else is checked out on the host machine.

    `with_resolvable_sibling=True` additionally plants a fake, minimal
    `agentidentitytrustprotocol` sibling at the exact path `_find_spec()`'s
    own candidates probe (`tmp_path / "agentidentitytrustprotocol"` -- two
    levels above `tmp_path/somepkg/tests/conftest.py`, matching both
    `parents[2]` and `parents[1].parent`), so `AITP_SPEC=none` can be tested
    under the *other* real-world condition: a machine where the sibling
    convention WOULD otherwise silently resolve. That is the exact condition
    the plan's review round found the original (buggy) design failed under --
    an opt-out nested inside `found is None` never triggers when resolution
    would have succeeded anyway, so a sibling-repo-present contributor's
    explicit `AITP_SPEC=none` would have been silently ignored rather than
    honored. Without this variant, both tests here pass identically whether
    the opt-out check runs first (correct) or is nested inside the
    resolution-failed branch (the exact bug the ordering fix exists to
    prevent), since in the no-sibling case the two orderings behave the same.
    """
    tests_dir = tmp_path / "somepkg" / "tests"
    tests_dir.mkdir(parents=True)
    shutil.copy(_CONFTEST, tests_dir / "conftest.py")
    (tests_dir / "test_probe.py").write_text(
        "def test_probe(spec_dir):\n    pass\n"
    )
    if with_resolvable_sibling:
        kat_dir = tmp_path / "agentidentitytrustprotocol" / "schemas" / "conformance" / "known-answer"
        kat_dir.mkdir(parents=True)
        (kat_dir / "keypairs.json").write_text("{}")
    return tests_dir


def _run(tests_dir: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", str(tests_dir / "test_probe.py"), "-q", "-rs"],
        cwd=tests_dir.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_missing_spec_repo_fails_loudly_not_silently(tmp_path: Path, spec_env_without_aitp_spec: dict[str, str]) -> None:
    tests_dir = _isolated_copy(tmp_path)
    result = _run(tests_dir, spec_env_without_aitp_spec)
    assert result.returncode != 0, (
        f"expected a nonzero exit (a hard failure, not a skip) when no spec repo is "
        f"resolvable; got {result.returncode}\nstdout:\n{result.stdout}"
    )
    assert "AITP spec repo not found" in result.stdout
    assert "AITP_SPEC" in result.stdout
    assert "AITP_SPEC=none" in result.stdout
    # A skip would report as such; this must be a genuine failure.
    assert "1 failed" in result.stdout or "1 error" in result.stdout
    assert "1 skipped" not in result.stdout


def test_explicit_no_spec_opt_out_skips_not_fails(tmp_path: Path, spec_env_without_aitp_spec: dict[str, str]) -> None:
    tests_dir = _isolated_copy(tmp_path)
    env = dict(spec_env_without_aitp_spec)
    env["AITP_SPEC"] = "none"
    result = _run(tests_dir, env)
    assert result.returncode == 0, (
        f"expected a clean exit (a skip, not a failure) under the explicit AITP_SPEC=none "
        f"opt-out; got {result.returncode}\nstdout:\n{result.stdout}"
    )
    assert "1 skipped" in result.stdout
    assert "explicitly disabled" in result.stdout
    assert "deliberate no-spec run" in result.stdout


def test_explicit_no_spec_opt_out_wins_even_when_sibling_is_resolvable(
    tmp_path: Path, spec_env_without_aitp_spec: dict[str, str]
) -> None:
    """The load-bearing ordering fix itself: `AITP_SPEC=none` must be honored
    even on a machine where the sibling-directory convention would otherwise
    successfully resolve a spec checkout (the common case in this multi-repo
    workspace, and the exact condition under which the plan's original design
    -- opt-out nested inside `found is None` -- silently ignored the opt-out
    and ran the full suite instead of skipping). Without a sibling present,
    this scenario is indistinguishable from `test_explicit_no_spec_opt_out_
    skips_not_fails` above: both orderings behave identically when resolution
    would have failed anyway.
    """
    tests_dir = _isolated_copy(tmp_path, with_resolvable_sibling=True)
    env = dict(spec_env_without_aitp_spec)
    env["AITP_SPEC"] = "none"
    result = _run(tests_dir, env)
    assert result.returncode == 0, (
        f"expected a clean exit (a skip, not the full suite silently running) under "
        f"AITP_SPEC=none even with a resolvable sibling present; got {result.returncode}\n"
        f"stdout:\n{result.stdout}"
    )
    assert "1 skipped" in result.stdout, (
        f"the opt-out must win over a resolvable sibling, not be silently ignored in favor "
        f"of it\nstdout:\n{result.stdout}"
    )
    assert "1 passed" not in result.stdout
    assert "explicitly disabled" in result.stdout
