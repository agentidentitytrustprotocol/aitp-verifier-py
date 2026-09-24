"""Locate the AITP spec repo that holds the pinned golden vectors.

The tests re-derive every known-answer vector and run the conformance pack, so
they need the spec checkout. Resolution order: ``$AITP_SPEC`` env var, then a
sibling ``agentidentitytrustprotocol`` directory next to this repo.

A spec repo that cannot be resolved is a **hard failure**, not a silent skip:
running `pytest` locally without the sibling repo cloned used to still exit
green, just with a much smaller suite -- easy to miss, and issue #26's exact
failure mode. The one legitimate reason to run without the spec checkout
(deliberately exercising only the spec-independent subset) gets an explicit,
documented opt-out instead: `AITP_SPEC=none`. That check runs as the first
statement in `spec_dir`, before `_find_spec()` is ever consulted -- `_find_spec`
tries the sibling-directory convention regardless of what `$AITP_SPEC` is set
to, so an opt-out gated on "resolution already failed" would never trigger on
any machine that happens to have the sibling repo checked out, which is the
common case in this multi-repo workspace.
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
    if os.environ.get("AITP_SPEC") == "none":
        pytest.skip("AITP spec repo explicitly disabled (AITP_SPEC=none) -- deliberate no-spec run")
    found = _find_spec()
    if found is None:
        pytest.fail(
            "AITP spec repo not found: $AITP_SPEC is unset (or points at a path missing "
            "schemas/conformance/known-answer/keypairs.json) and no sibling "
            "agentidentitytrustprotocol directory was found next to this repo. Set $AITP_SPEC "
            "to the spec checkout, clone it as a sibling directory, or set AITP_SPEC=none to "
            "explicitly run only the spec-independent subset of tests."
        )
    return found
