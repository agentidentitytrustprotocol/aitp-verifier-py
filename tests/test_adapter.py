"""The aitp-conformance NDJSON adapter (aitp_verifier/adapter.py): the
protocol messages, its failure paths, and agreement with run_conformance.py."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from aitp_verifier.adapter import Adapter, main, serve
from aitp_verifier.keys import load_kat_keys
from aitp_verifier.minter import mint_input
from aitp_verifier.timeutil import REFERENCE_CLOCK
from aitp_verifier.verify import OPERATIONS


def _run(lines: list[bytes], adapter: Adapter | None = None) -> list[dict[str, Any]]:
    out = io.StringIO()
    assert serve(io.BytesIO(b"".join(line + b"\n" for line in lines)), out, adapter) == 0
    return [json.loads(line) for line in out.getvalue().splitlines()]


def _req(rid: str, op: str, **params: Any) -> bytes:
    return json.dumps({"id": rid, "op": op, "params": params}).encode()


@pytest.fixture
def keyed(spec_dir: Path) -> Adapter:
    return Adapter(load_kat_keys(spec_dir))


def _minted(spec_dir: Path, fixture_id: str) -> dict[str, Any]:
    path = next((spec_dir / "schemas/conformance").glob(f"{fixture_id}-*.json"))
    inp = mint_input(copy.deepcopy(json.loads(path.read_text(encoding="utf-8"))["input"]),
                     REFERENCE_CLOCK, load_kat_keys(spec_dir))
    inp.pop("operation")
    return inp


# ── Protocol messages ───────────────────────────────────────────────────────


def test_init_declares_the_implementation_and_every_operation() -> None:
    [reply] = _run([_req("req-1", "init", version="1")])
    assert reply["id"] == "req-1" and reply["ok"] is True
    result = reply["result"]
    assert result["implementation"] == "aitp-verifier-py"
    assert result["repository"].startswith("https://")
    assert isinstance(result["version"], str) and result["version"]
    assert set(OPERATIONS) <= set(result["supported_ops"])
    assert {"set_clock", "set_features", "begin_fixture", "shutdown"} <= set(result["supported_ops"])


def test_init_rejects_another_protocol_version() -> None:
    [reply] = _run([_req("req-1", "init", version="2")])
    assert reply == {"id": "req-1", "ok": False, "error_code": "MALFORMED_REQUEST",
                     "message": "unsupported adapter protocol version '2'"}


def test_ids_are_echoed_and_shutdown_stops_reading() -> None:
    replies = _run([_req("req-7", "set_clock", now_unix_secs=REFERENCE_CLOCK), _req("req-8", "shutdown"),
                    _req("req-9", "init", version="1")])
    assert [r["id"] for r in replies] == ["req-7", "req-8"]
    assert all(r["ok"] for r in replies)


def test_unknown_op_is_op_not_supported() -> None:
    [reply] = _run([_req("req-1", "issue_tct")])
    assert reply["ok"] is False and reply["error_code"] == "OP_NOT_SUPPORTED"


def test_verification_success_and_failure(spec_dir: Path, keyed: Adapter) -> None:
    ok, bad = _run([_req("req-1", "verify_tct", **_minted(spec_dir, "tct-025")),
                    _req("req-2", "verify_tct", **_minted(spec_dir, "tct-002"))], keyed)
    assert ok["ok"] is True and "result" in ok
    assert bad["ok"] is False and bad["error_code"] and bad["message"]


def test_spiffe_runs_only_under_its_feature(spec_dir: Path, keyed: Adapter) -> None:
    inp = _minted(spec_dir, "id-024")
    off, _, on = _run([_req("req-1", "verify_handshake_payload", **inp),
                       _req("req-2", "set_features", features=["experimental-spiffe-identity"]),
                       _req("req-3", "verify_handshake_payload", **inp)], keyed)
    assert not off["ok"] and "unknown identity type 'spiffe'" in off["message"]
    assert on["ok"] is True


def test_replay_state_is_per_fixture() -> None:
    step = _req("r", "process_handshake_message", message_id="550e8400-e29b-41d4-a716-446655440099")
    first, second, _, third = _run([step, step, _req("r", "begin_fixture"), step])
    assert first["ok"] and not second["ok"] and second["error_code"] == "REPLAY_DETECTED"
    assert third["ok"]


def test_pop_sequence_side_effects(spec_dir: Path, keyed: Adapter) -> None:
    """tct-007: a marked grant gets a challenge, and withholding the response
    rejects without authorizing."""
    inp = _minted_sequence(spec_dir, "tct-007")
    replies = _run([_req(f"req-{i}", step.pop("operation"), **{**inp, **step}) for i, step in enumerate(inp.pop("_steps"))], keyed)
    assert replies[0]["ok"]
    assert replies[1]["result"]["side_effects"] == {"pop_challenge_issued": True}
    assert replies[2]["ok"] is False and replies[2]["error_code"] == "POP_RESPONSE_INVALID"


def _minted_sequence(spec_dir: Path, fixture_id: str) -> dict[str, Any]:
    path = next((spec_dir / "schemas/conformance").glob(f"{fixture_id}-*.json"))
    raw = json.loads(path.read_text(encoding="utf-8"))["input"]
    context = mint_input({k: v for k, v in raw.items() if k != "sequence"}, REFERENCE_CLOCK, load_kat_keys(spec_dir))
    context = {k: v for k, v in context.items() if not k.endswith("_claims")}
    steps = [{k: v for k, v in s.items() if k not in ("step", "expected")} for s in raw["sequence"]]
    return {**context, "_steps": steps}


# ── Failure paths ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(("line", "why"), [
    (b'{"id":"req-1","op":"verify_tct","op":"init","params":{}}', "duplicate JSON key 'op'"),
    (b'{"id":"req-1","op":"verify_tct","params":{"tct_token":"a","tct_token":"b"}}', "duplicate JSON key 'tct_token'"),
    (b'{"id":"req-1", "op": ', "not JSON"),
    (b'["init"]', "not a JSON object"),
    (b'{"id":"req-1","op":"init","params":{"version":NaN}}', "non-JSON number NaN"),
    (b'{"id":"req-1","op":"\xff"}', "not UTF-8"),
])
def test_unreadable_lines_get_a_protocol_error_not_a_verdict(line: bytes, why: str) -> None:
    [reply] = _run([line])
    assert reply["ok"] is False and reply["error_code"] == "MALFORMED_REQUEST" and why in reply["message"]
    assert reply["id"] == "unknown"


def test_an_exception_inside_an_op_is_an_error_outcome_and_the_next_request_runs(
    monkeypatch: pytest.MonkeyPatch, spec_dir: Path, keyed: Adapter
) -> None:
    def boom(inp: dict[str, Any], now: int) -> dict[str, Any]:
        raise RuntimeError("injected")

    monkeypatch.setitem(OPERATIONS, "verify_manifest", boom)
    crashed, after = _run([_req("req-1", "verify_manifest", manifest={}), _req("req-2", "init", version="1")], keyed)
    assert crashed == {"id": "req-1", "ok": False, "error_code": "ADAPTER_INTERNAL_ERROR",
                       "message": "verify_manifest raised RuntimeError: injected"}
    assert after["ok"] is True


def test_without_aitp_spec_the_packaged_kat_keys_are_used(spec_dir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A PyPI install has no spec checkout: init and a key-needing op both work."""
    monkeypatch.delenv("AITP_SPEC", raising=False)
    adapter = Adapter()
    init, verdict = _run([_req("req-1", "init", version="1"),
                          _req("req-2", "verify_tct", **_minted(spec_dir, "tct-025"))], adapter)
    assert init["ok"] is True and verdict["ok"] is True
    assert adapter.keys.keys() == load_kat_keys(spec_dir).keys()


@pytest.mark.parametrize("layout", ["missing", "empty-dir"])
def test_an_unusable_aitp_spec_fails_init_naming_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                                    layout: str) -> None:
    target = tmp_path / "nope" if layout == "missing" else tmp_path
    monkeypatch.setenv("AITP_SPEC", str(target))
    [reply] = _run([_req("req-1", "init", version="1")], Adapter())
    assert reply["ok"] is False and reply["error_code"] == "ADAPTER_INTERNAL_ERROR"
    assert "AITP_SPEC=" in reply["message"] and "keypairs.json not found" in reply["message"]


def test_del_004_through_the_adapter(spec_dir: Path, keyed: Adapter) -> None:
    """The frozen v0.1 multi-hop token (no `self_aid`, object-shaped
    `delegation`) gets the structural rejection, never an internal error."""
    path = next((spec_dir / "schemas/conformance").glob("del-004-*.json"))
    fixture = json.loads(path.read_text(encoding="utf-8"))
    inp = mint_input(copy.deepcopy(fixture["input"]), REFERENCE_CLOCK, load_kat_keys(spec_dir))
    op = inp.pop("operation")
    [reply] = _run([_req("req-1", op, **inp)], keyed)
    assert reply["ok"] is False
    assert reply["error_code"] == fixture["expected"]["error_code"] == "DELEGATION_MULTIHOP_NOT_SUPPORTED"


def test_help_names_aitp_spec(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0 and "AITP_SPEC" in capsys.readouterr().out


def test_subprocess_flushes_each_line_logs_on_stderr_and_exits_0_on_eof() -> None:
    proc = subprocess.Popen([sys.executable, "-m", "aitp_verifier.adapter"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.stdin is not None and proc.stdout is not None
    proc.stdin.write(_req("req-1", "init", version="1") + b"\n")
    proc.stdin.flush()
    first = json.loads(proc.stdout.readline())  # arrives before EOF: the line was flushed
    assert first["id"] == "req-1" and first["ok"] is True
    proc.stdin.close()
    assert proc.wait(timeout=30) == 0
    assert proc.stdout.read() == b""
