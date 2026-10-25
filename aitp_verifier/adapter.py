"""NDJSON subprocess adapter for the ``aitp-conformance`` runner (aitp-rs).

Run as ``python -m aitp_verifier.adapter`` or the ``aitp-verifier-adapter``
script. ``aitp-conformance run --target aitp-verifier-adapter`` spawns it,
writes one JSON request per line to its stdin and reads one JSON response per
line from its stdout (aitp-rs ``docs/conformance.md``, "Wire protocol"):

* request ``{"id": "req-N", "op": ..., "params": {...}}``;
* success ``{"id": ..., "ok": true, "result": {...}}``;
* failure ``{"id": ..., "ok": false, "error_code": ..., "message": ...}``.

The runner mints every placeholder before it sends a request, so ``params``
is a fixture ``input`` ready to verify. :func:`aitp_verifier.harness.run_operation`
applies the fixture conventions, exactly as ``run_conformance.py`` does, so the
two front ends agree fixture for fixture (CI diffs them).

A line that is not UTF-8, not JSON, carries a duplicate key or is not an
object gets a ``MALFORMED_REQUEST`` line and no verdict. An exception inside an
operation is reported as ``ADAPTER_INTERNAL_ERROR`` with its reason; the
process keeps serving. Logs go to stderr only. EOF on stdin exits 0.

Minting a fixture's placeholders needs the spec's KAT private keys. They ship
in the package, so no spec checkout is needed. ``AITP_SPEC``, when set, names
a spec checkout to read them from instead (for a run against an unreleased
spec). A set ``AITP_SPEC`` that is not a usable checkout fails ``init`` with an
error naming it, before any fixture runs.

Usage: ``aitp-verifier-adapter`` (or ``python -m aitp_verifier.adapter``),
spawned by aitp-conformance as ``run --target aitp-verifier-adapter``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import IO, Any, Callable

from .b64 import b64url_decode, b64url_encode
from .errors import AitpError
from .harness import FixtureError, pop_required, run_operation, unverified_claims
from .keys import KAT_FILES, load_kat_keys, load_packaged_kat_keys
from .tct import presenter_from_pop
from .timeutil import REFERENCE_CLOCK
from .verify import OPERATIONS

__all__ = ["Adapter", "main", "parse_request"]

PROTOCOL_VERSION = "1"
IMPLEMENTATION = "aitp-verifier-py"
REPOSITORY = "https://github.com/agentidentitytrustprotocol/aitp-verifier-py"
# The Draft features an operation reads from its input's `_feature`.
FEATURE_GATED_OPS = {
    "verify_delegation_token": "experimental-multihop-delegation",
    "verify_handshake_payload": "experimental-spiffe-identity",
}
# The challenge lifetime a verifier gives its own PoP challenge here.
POP_CHALLENGE_TTL_SECS = 300


class KatKeysError(Exception):
    """The KAT keys cannot be loaded from the ``AITP_SPEC`` checkout."""


def _load_keys() -> dict[str, Any]:
    spec = os.environ.get("AITP_SPEC")
    if not spec:
        return load_packaged_kat_keys()
    kat = Path(spec) / "schemas/conformance/known-answer"
    missing = [name for name in KAT_FILES if not (kat / name).is_file()]
    if missing:
        raise KatKeysError(
            f"AITP_SPEC={spec!r} is not a spec checkout: {kat}/{missing[0]} not found. "
            "Unset AITP_SPEC to use the KAT keys shipped in the package."
        )
    try:
        return load_kat_keys(Path(spec))
    except (ValueError, KeyError, TypeError) as exc:
        raise KatKeysError(f"AITP_SPEC={spec!r}: cannot read the KAT keys: {exc}") from exc


class MalformedRequest(Exception):
    """A request line the adapter cannot read as a request."""


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise MalformedRequest(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise MalformedRequest(f"non-JSON number {name}")


def parse_request(line: bytes) -> dict[str, Any]:
    """One request line, strictly: UTF-8, JSON, no duplicate key at any depth,
    an object. A duplicate key is the case a last-wins parser silently loses,
    so it is refused here, before anything reads the request."""
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedRequest(f"request is not UTF-8: {exc}") from exc
    try:
        request = json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
    except json.JSONDecodeError as exc:
        raise MalformedRequest(f"request is not JSON: {exc}") from exc
    if not isinstance(request, dict):
        raise MalformedRequest("request is not a JSON object")
    return request


def _ok(rid: str, result: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"id": rid, "ok": True, "result": result or {}}


def _err(rid: str, code: str, message: str) -> dict[str, Any]:
    return {"id": rid, "ok": False, "error_code": code, "message": message}


class Adapter:
    """Adapter state: the clock, the enabled features, and what one fixture's
    multi-step sequence carries from step to step (``begin_fixture`` drops it)."""

    def __init__(self, keys: dict[str, Any] | None = None) -> None:
        self._keys = keys
        self.clock = REFERENCE_CLOCK
        self.features: set[str] = set()
        self._begin_fixture()
        self._session_ops: dict[str, Callable[[dict[str, Any]], tuple[str | None, dict[str, Any]]]] = {
            "issue_pop_challenge": self._issue_pop_challenge,
            "produce_pop_response": self._produce_pop_response,
            "verify_pop_response": self._verify_pop_response,
            "authorize_capability_invocation": self._authorize_capability_invocation,
            "expect_pop_challenge_issued": self._expect_pop_challenge_issued,
            "withhold_pop_response": self._withhold_pop_response,
        }

    def _begin_fixture(self) -> None:
        self.seen_message_ids: set[str] = set()
        self.challenges: list[dict[str, Any]] = []
        self.pop_presenter: str | None = None
        self.pop_challenge_issued = False

    @property
    def keys(self) -> dict[str, Any]:
        if self._keys is None:
            self._keys = _load_keys()
        return self._keys

    def supported_ops(self) -> list[str]:
        control = ["init", "shutdown", "set_clock", "set_features", "begin_fixture", "process_handshake_message"]
        return [*control, *OPERATIONS, *self._session_ops]

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        rid = request.get("id")
        rid = rid if isinstance(rid, str) else "unknown"
        op = request.get("op")
        params = request.get("params", {})
        if not isinstance(op, str) or not isinstance(params, dict):
            return _err(rid, "MALFORMED_REQUEST", "request needs a string op and object params")
        try:
            return self._dispatch(rid, op, params)
        except Exception as exc:  # noqa: BLE001 - one bad op never takes the adapter down
            print(f"aitp-verifier-adapter: {op} raised {type(exc).__name__}: {exc}", file=sys.stderr)
            return _err(rid, "ADAPTER_INTERNAL_ERROR", f"{op} raised {type(exc).__name__}: {exc}")

    def _dispatch(self, rid: str, op: str, params: dict[str, Any]) -> dict[str, Any]:
        if op == "init":
            if params.get("version") != PROTOCOL_VERSION:
                return _err(rid, "MALFORMED_REQUEST", f"unsupported adapter protocol version {params.get('version')!r}")
            try:
                self.keys
            except KatKeysError as exc:
                return _err(rid, "ADAPTER_INTERNAL_ERROR", str(exc))
            return _ok(rid, {
                "implementation": IMPLEMENTATION,
                "version": _package_version(),
                "repository": REPOSITORY,
                "supported_ops": self.supported_ops(),
                "supported_features": [],
            })
        if op == "shutdown":
            return _ok(rid)
        if op == "set_clock":
            now = params.get("now_unix_secs", params.get("now"))
            if not isinstance(now, int) or isinstance(now, bool):
                return _err(rid, "MALFORMED_REQUEST", "set_clock needs an integer now_unix_secs")
            self.clock = now
            return _ok(rid)
        if op == "set_features":
            features = params.get("features", [])
            if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
                return _err(rid, "MALFORMED_REQUEST", "set_features needs a list of strings")
            self.features = set(features)
            return _ok(rid)
        if op == "begin_fixture":
            self._begin_fixture()
            return _ok(rid)

        # env-004, mh-001: a step that names only a message_id exercises the
        # verifier's replay check.
        mid = params.get("message_id")
        if op in ("verify_envelope", "process_handshake_message") and "envelope" not in params and isinstance(mid, str):
            if mid in self.seen_message_ids:
                return _err(rid, "REPLAY_DETECTED", f"message_id {mid} already seen")
            self.seen_message_ids.add(mid)
            return _ok(rid)

        session_op = self._session_ops.get(op)
        if session_op is not None:
            code, result = session_op(params)
        elif op in OPERATIONS:
            inp = {"now": self.clock, **params}
            feature = FEATURE_GATED_OPS.get(op)
            if feature is not None:
                inp["_feature"] = feature if feature in self.features else None
            try:
                code, result = run_operation(op, inp, self.keys, accept_presented_type=True)
            except FixtureError as exc:
                return _err(rid, "MALFORMED_FIXTURE", str(exc))
        else:
            return _err(rid, "OP_NOT_SUPPORTED", f"op {op} not implemented")
        return _ok(rid, result) if code is None else _err(rid, code, result.get("message", code))

    # ── PoP sequences (tct-006, tct-007, tct-026) ────────────────────────────

    def _claims(self, params: dict[str, Any]) -> dict[str, Any]:
        return unverified_claims(params.get("tct_token"))

    def _issue_pop_challenge(self, params: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        """RFC-AITP-0005 §6.1: the verifier challenges the presenter of the
        TCT's ``jti``. The fixture's own challenge envelope fixes the nonce."""
        nonce = params.get("envelope", {}).get("payload", {}).get("nonce")
        if not isinstance(nonce, str):
            nonce = b64url_encode(os.urandom(16))
        jti = self._claims(params).get("jti")
        self.challenges.append({"tct_jti": jti, "nonce": nonce, "expires_at": self.clock + POP_CHALLENGE_TTL_SECS})
        self.pop_challenge_issued = True
        return None, {"pop_nonce": nonce}

    def _produce_pop_response(self, params: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        """The presenter's ``pop_response`` (already signed by the runner),
        checked as the verifier receiving it: the envelope, the challenge it
        answers and the PoP signature under the TCT ``sub`` key (§6.2)."""
        claims = self._claims(params)
        try:
            self.pop_presenter = presenter_from_pop(
                {"envelope": params.get("envelope"), "outstanding_pop_challenges": self.challenges}, claims, self.clock
            )
        except AitpError as exc:
            self.pop_presenter = None
            return exc.code, {"message": exc.message}
        return None, {}

    def _verify_pop_response(self, params: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        if self.pop_presenter is None:
            return "POP_RESPONSE_INVALID", {"message": "no valid pop_response for an outstanding challenge"}
        return None, {"presenter_aid": self.pop_presenter}

    def _authorize_capability_invocation(self, params: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        """Accepting an invocation for processing is not authorizing it: when
        PoP is required the verifier first challenges the presenter."""
        if pop_required(params, self._claims(params)):
            self.pop_challenge_issued = True
            return None, {"side_effects": {"pop_challenge_issued": True}}
        return None, {"side_effects": {"capability_authorized": True}}

    def _expect_pop_challenge_issued(self, params: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        return None, {"side_effects": {"pop_challenge_issued": self.pop_challenge_issued}}

    def _withhold_pop_response(self, params: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
        """No response arrives within the challenge window: reject, never authorize."""
        if self.pop_challenge_issued:
            return "POP_RESPONSE_INVALID", {"message": "challenge unanswered; capability not authorized"}
        return None, {"side_effects": {"capability_authorized": True}}


def _package_version() -> str:
    try:
        return version("aitp-verifier")
    except PackageNotFoundError:
        return "unknown"


def _write(out: IO[str], response: dict[str, Any]) -> None:
    out.write(json.dumps(response, separators=(",", ":")) + "\n")
    out.flush()


def serve(stdin: IO[bytes], stdout: IO[str], adapter: Adapter | None = None) -> int:
    """Serve requests until ``shutdown`` or EOF. Returns the exit code."""
    adapter = adapter or Adapter()
    for line in stdin:
        if not line.strip():
            continue
        try:
            request = parse_request(line.rstrip(b"\r\n"))
        except MalformedRequest as exc:
            _write(stdout, _err("unknown", "MALFORMED_REQUEST", str(exc)))
            continue
        _write(stdout, adapter.handle(request))
        if request.get("op") == "shutdown":
            break
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aitp-verifier-adapter",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="environment:\n  AITP_SPEC  optional spec checkout to read the KAT keys from "
               "(default: the copies shipped in the package)",
    )
    parser.parse_args(argv)
    return serve(sys.stdin.buffer, sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
