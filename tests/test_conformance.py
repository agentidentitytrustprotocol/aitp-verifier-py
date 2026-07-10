"""Drive the whole conformance pack and assert no in-scope fixture FAILs.

Every ``required_for_v0_2`` fixture whose operation this implementation
supports must pass; unsupported operations report SKIP (never a silent pass).
"""

from __future__ import annotations

import json
from pathlib import Path

from aitp_verifier.keys import load_kat_keys
from run_conformance import FAIL, PASS, SUPPORTED_FEATURES, run_fixture


def test_conformance_pack_has_no_failures(spec_dir: Path) -> None:
    keys = load_kat_keys(spec_dir)
    conf = spec_dir / "schemas/conformance"
    passed = failures = 0
    for path in sorted(conf.glob("*.json")):
        fixture = json.loads(path.read_text())
        if "id" not in fixture or "input" not in fixture:
            continue
        if not fixture.get("required_for_v0_2", False) and fixture.get("feature") not in SUPPORTED_FEATURES:
            continue
        status, detail = run_fixture(fixture, keys)
        if status == FAIL:
            failures += 1
            print(f"FAIL {fixture['id']}: {detail}")
        elif status == PASS:
            passed += 1
    assert failures == 0
    assert passed >= 51  # full re-mintable v0.2 + Draft surface
