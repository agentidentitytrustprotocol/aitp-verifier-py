"""Locate the AITP spec repo that holds the pinned golden vectors.

The tests re-derive every known-answer vector and run the conformance pack, so
they need the spec checkout. Resolution order: ``$AITP_SPEC`` env var, then a
sibling ``agentidentitytrustprotocol`` directory next to this repo.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

_CANDIDATES = [
    os.environ.get("AITP_SPEC"),
    Path(__file__).resolve().parents[2] / "agentidentitytrustprotocol",
    Path(__file__).resolve().parents[1].parent / "agentidentitytrustprotocol",
]


def _find_spec() -> Path | None:
    for c in _CANDIDATES:
        if c and Path(c, "schemas/conformance/known-answer/keypairs.json").is_file():
            return Path(c)
    return None


@pytest.fixture(scope="session")
def spec_dir() -> Path:
    found = _find_spec()
    if found is None:
        pytest.skip("AITP spec repo not found (set $AITP_SPEC or clone it as a sibling)")
    return found
