"""Boundary-contract regression harness (spans issue #23's whole class).

Every public verifier entry point's contract is "raise `AitpError` or return
a verdict" -- never a bare Python exception. Phases 3-6 closed every
concretely-identified violation of that contract one module at a time; this
is the capstone that pins the *class* of bug they closed, so a future change
that reopens any one of them fails a single, obviously-named test here
instead of waiting for another adversarial review pass.

For every operation in `aitp_verifier.verify.OPERATIONS`, plus
`identity.verify_identity` directly (public, and per Phase 6's own finding,
otherwise unreachable through `handshake.py`'s call path), this sweeps every
known-answer conformance fixture whose `input.operation` matches, mutates
every scalar-leaf JSON path inside that entry point's artifact-bearing
argument with a fixed set of hostile values, **re-signs via `mint_input`**,
and asserts the result is always either an `AitpError` or a normal return --
never anything else.

Re-signing is the load-bearing design point: a harness that mutated without
re-minting would find none of these bugs, because the mutation would trip a
signature-mismatch error long before reaching the code Phases 3-6 fixed.

Mutation-target scope is deliberately narrower than "every JSON path in the
fixture": it never touches the top-level call-argument keys themselves
(`envelope`, `manifest`, `tct_token`, `self_aid`, `policy`, ...) -- deleting
one of those is a defect in the *Python calling convention* these functions
use, not in any AITP wire artifact, and none of issues #23-#27 are about
that boundary; every real caller assembles that top-level dict itself and
controls its own keys. Scoped to scalar-leaf fields (including everything
nested under `extensions`, where RFC-AITP-0012 §1 forbids the interior from
being type-checked at all, and every other structurally-required leaf) is
exhaustive within that scope, not sampled -- the leaf count per fixture is
small enough that walking every one of them, times the mutation set, times
every in-scope fixture, stays well within CI budget. See `ASSUMPTIONS.md`:
this is the plan's own stated no-`ASSUMPTIONS.md`-entry-needed default.

Two of Phase 6's guards (`env["sender"]["agent_id"]`,
`env["message_id"]`/`env["timestamp"]` deletion) are *not* reachable through
this harness: `minter.py` dereferences those same keys by bracket access
during minting itself, so a mutation deleting them dies inside `mint_input`
and is skipped (see `_sweep`'s except clause below) before ever reaching the
verifier. That is expected, not a gap in this harness -- Phase 6's own
direct-call unit tests in `tests/test_unknown_fields.py` are what actually
prove those two guards.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Iterator

import pytest

from aitp_verifier.errors import AitpError
from aitp_verifier.identity import verify_identity
from aitp_verifier.jcs import JcsError
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.minter import MinterError, mint_input
from aitp_verifier.timeutil import REFERENCE_CLOCK
from aitp_verifier.verify import OPERATIONS

# Each entry point's artifact-bearing argument(s), as a dotted path from the
# fixture's `input` root. `verify_envelope` and `verify_handshake_payload`
# deliberately share "envelope" -- handshake.py parses the envelope shape
# itself, inline (Phase 6), so the same mutation surface applies to both.
_ARTIFACT_ROOTS: dict[str, str] = {
    "verify_envelope": "envelope",
    "verify_manifest": "manifest",
    "verify_tct": "tct_token_claims",
    "verify_grant_voucher": "voucher_token_claims",
    "verify_delegation_token": "delegation_token_claims",
    "verify_revocation_snapshot": "snapshot.revocation_list",
    "verify_handshake_payload": "envelope",
    "verify_session_bundle": "session_bundle.session_bundle",
}
assert set(_ARTIFACT_ROOTS) == set(OPERATIONS), "OPERATIONS drifted from this harness's coverage table"


class _Delete:
    def __repr__(self) -> str:
        return "<DELETE>"


_DELETE = _Delete()

# ~11 hostile values, per the plan: every JSON-representable degenerate
# scalar/container, the two JCS hazards (non-finite float, an int outside
# JCS's representable range), two invalid-base64url/AID-grammar shapes, and
# a delete-the-key sentinel.
_MUTATIONS: list[tuple[str, Any]] = [
    ("null", None),
    ("empty-list", []),
    ("empty-dict", {}),
    ("empty-string", ""),
    ("zero", 0),
    ("true", True),
    ("infinity", json.loads("1e400")),
    ("huge-int", json.loads("1" + "0" * 400)),
    ("colon-string", "a:b"),
    ("bad-base64url", "x"),
    ("deleted", _DELETE),
]


def _iter_leaf_paths(obj: Any, prefix: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    """Every scalar-leaf path reachable from `obj` (dicts and lists are
    walked, never themselves yielded as a mutation target)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = prefix + (k,)
            if isinstance(v, (dict, list)):
                yield from _iter_leaf_paths(v, path)
            else:
                yield path
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            path = prefix + (i,)
            if isinstance(v, (dict, list)):
                yield from _iter_leaf_paths(v, path)
            else:
                yield path


def _resolve(obj: Any, dotted: str) -> Any:
    node = obj
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _mutate(obj: Any, path: tuple[Any, ...], mutation: Any) -> Any:
    """A deep copy of `obj` with the value at `path` replaced by `mutation`
    (or the key/index at `path` removed, if `mutation` is `_DELETE`)."""
    out = copy.deepcopy(obj)
    node = out
    for part in path[:-1]:
        node = node[part]
    last = path[-1]
    if mutation is _DELETE:
        del node[last]
    else:
        node[last] = mutation
    return out


def _load_fixtures(spec_dir: Path) -> list[dict[str, Any]]:
    conf_dir = spec_dir / "schemas/conformance"
    out = []
    for path in sorted(conf_dir.glob("*.json")):
        d = json.loads(path.read_text())
        if "id" in d and "input" in d:
            out.append(d)
    return out


def _sweep(spec_dir: Path, op: str) -> list[str]:
    """Mutate every scalar leaf of `op`'s artifact-bearing argument, across
    every conformance fixture that exercises it, and return one line per
    violation -- a call that raised something other than `AitpError`.
    """
    keys = load_kat_keys(spec_dir)
    root_prefix = _ARTIFACT_ROOTS[op]
    root_path = tuple(root_prefix.split("."))
    violations: list[str] = []

    for fixture in _load_fixtures(spec_dir):
        inp = fixture["input"]
        if inp.get("operation") != op:
            continue
        root = _resolve(inp, root_prefix)
        if not isinstance(root, dict):
            continue  # fixture doesn't carry this artifact (e.g. a failure fixture missing it on purpose)

        for leaf_rel in _iter_leaf_paths(root):
            full_path = root_path + leaf_rel
            for label, mutation in _MUTATIONS:
                mutated_input = _mutate(inp, full_path, mutation)
                try:
                    minted = mint_input(mutated_input, REFERENCE_CLOCK, keys)
                except Exception:  # noqa: BLE001 - minting-time noise, not verifier signal
                    # Not reachable at this path for this mutation -- the
                    # mutated value was itself required to MINT a valid
                    # artifact (e.g. an AID minting looks up a signing key
                    # for, or a claim minting canonicalizes). Mirrors
                    # run_conformance.py's own `except (MinterError,
                    # KeyError): SKIP` handling, widened to catch anything:
                    # unlike its fixtures, this harness's hostile mutations
                    # (1e400/huge-int/wrong-shape) can land on a field the
                    # minting step itself dereferences or canonicalizes in
                    # ways `run_conformance.py` never needed to guard
                    # against (JcsError, but also a bare TypeError from an
                    # unhashable mutated value used as a dict key, etc.) --
                    # any exception here is minting-harness noise, never a
                    # finding about the verifier under test, which hasn't
                    # been called yet.
                    continue
                try:
                    OPERATIONS[op](minted)
                except AitpError:
                    pass  # the overwhelmingly common case: correctly rejected
                except Exception as exc:  # noqa: BLE001 - a crash IS the finding
                    dotted = ".".join(map(str, full_path))
                    violations.append(
                        f"{fixture['id']}: {op}({dotted}={label}) raised "
                        f"{type(exc).__name__}: {exc}"
                    )
    return violations


@pytest.mark.parametrize("op", sorted(_ARTIFACT_ROOTS))
def test_boundary_contract_never_raises_a_bare_exception(op: str, spec_dir: Path) -> None:
    violations = _sweep(spec_dir, op)
    assert not violations, "\n".join(violations)


def test_boundary_contract_identity_never_raises_a_bare_exception(spec_dir: Path) -> None:
    """`identity.verify_identity` directly -- it has no other call path that
    exercises its own guards end to end (Phase 6's finding: reaching it via
    `handshake.py` only ever sees an already-dict-checked `identity`, so
    `identity.py`'s own non-dict guard is dead code on that path). No
    re-minting needed here: we mutate the already-minted `identity` dict and
    call `verify_identity` directly, bypassing the envelope-signature layer
    entirely -- the same reasoning `test_unknown_fields.py`'s
    `test_handshake_hello_mistyped_identity_reports_identity_failed` already
    uses at the single-case level.
    """
    keys = load_kat_keys(spec_dir)
    violations: list[str] = []

    for fixture in _load_fixtures(spec_dir):
        inp = fixture["input"]
        if inp.get("operation") != "verify_handshake_payload":
            continue
        env = inp.get("envelope")
        if not isinstance(env, dict):
            continue
        payload = env.get("payload")
        if not isinstance(payload, dict) or not isinstance(payload.get("identity"), dict):
            continue
        try:
            minted = mint_input(inp, REFERENCE_CLOCK, keys)
        except (MinterError, KeyError, JcsError):
            continue

        menv = minted["envelope"]
        base_identity = menv["payload"]["identity"]
        self_aid = minted.get("self_aid", "")
        trust_anchors = minted.get("self_trust_anchors")
        trust_store = minted.get("trust_store")
        issuer_keys = minted.get("resolved_issuer_keys", {})

        for leaf_rel in _iter_leaf_paths(base_identity):
            for label, mutation in _MUTATIONS:
                mutated_identity = _mutate(base_identity, leaf_rel, mutation)
                try:
                    verify_identity(
                        mutated_identity,
                        menv,
                        self_aid,
                        trust_anchors=trust_anchors,
                        trust_store=trust_store,
                        issuer_keys=issuer_keys,
                        now=REFERENCE_CLOCK,
                    )
                except AitpError:
                    pass
                except Exception as exc:  # noqa: BLE001 - a crash IS the finding
                    dotted = ".".join(map(str, leaf_rel))
                    violations.append(
                        f"{fixture['id']}: verify_identity({dotted}={label}) raised "
                        f"{type(exc).__name__}: {exc}"
                    )
    assert not violations, "\n".join(violations)
