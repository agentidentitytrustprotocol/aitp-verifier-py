#!/usr/bin/env python3
"""Diff two conformance reports fixture for fixture.

    python scripts/parity-diff.py native.json adapter.json

`native.json` comes from `run_conformance.py --report`, `adapter.json` from
`aitp-conformance run --target aitp-verifier-adapter --report`. Both run this
verifier; only the front end differs, so their outcomes must agree. The diff
fails on any disagreement not listed below, and on a listed fixture that now
agrees: the entry is stale and must be deleted.
"""

from __future__ import annotations

import json
import sys

# Fixtures the two runners schedule differently by design. A skip on one side
# is expected; any other disagreement is still a mismatch.
RUNNER_POLICY = {
    # aitp-conformance skips it when experimental-multihop-delegation is enabled
    # (feature negation); run_conformance.py opts features in per fixture, so
    # it runs del-007 feature-less.
    "del-007": "negated by experimental-multihop-delegation under aitp-conformance",
}

# Defects in the aitp-conformance runner at the pinned aitp-rs commit, reported
# upstream. The adapter's outcome is wrong because the runner sent it a wrong
# input, not because the verifier differs. Delete each entry when the pinned
# aitp-rs commit carries the fix.
_COMPANION = "runner leaves a *_claims minting companion inside a nested object"
KNOWN_RUNNER_GAPS = {
    **{fid: _COMPANION for fid in ("mh-006", "mh-007", "mh-008", "mh-success-001",
                                   "bundle-001", "bundle-002", "bundle-003",
                                   "bundle-005-extensions-accepted", "bundle-007")},
    "mh-002": "runner mints the inline Manifest's proof_of_possession signature invalid",
}


def outcomes(path: str) -> dict[str, dict[str, str]]:
    with open(path, encoding="utf-8") as handle:
        return {r["id"]: r for r in json.load(handle)["results"]}


def main() -> int:
    native, adapter = outcomes(sys.argv[1]), outcomes(sys.argv[2])
    problems = []
    for fid in sorted(set(native) | set(adapter)):
        a, b = native.get(fid), adapter.get(fid)
        if a is None or b is None:
            problems.append(f"{fid}: only in the {'adapter' if a is None else 'native'} report")
            continue
        agree = a["outcome"] == b["outcome"]
        if fid in KNOWN_RUNNER_GAPS:
            if agree:
                problems.append(f"{fid}: now agrees ({a['outcome']}); delete its KNOWN_RUNNER_GAPS entry")
            else:
                print(f"known {fid}: native {a['outcome']}, adapter {b['outcome']} ({KNOWN_RUNNER_GAPS[fid]})")
            continue
        if agree:
            continue
        if "skip" in (a["outcome"], b["outcome"]) and fid in RUNNER_POLICY:
            print(f"note {fid}: native {a['outcome']}, adapter {b['outcome']} ({RUNNER_POLICY[fid]})")
            continue
        detail = b.get("reason") or a.get("reason") or ""
        problems.append(f"{fid}: native {a['outcome']}, adapter {b['outcome']} {detail}".rstrip())
    for line in problems:
        print(f"MISMATCH {line}")
    print(f"{len(native)} fixtures compared, {len(problems)} mismatches")
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
