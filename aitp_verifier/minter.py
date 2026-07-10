"""Conformance-fixture minter (RFC-AITP schemas/conformance/PLACEHOLDERS.md).

Fixtures ship with ``__UPPER_SNAKE__`` placeholders in place of signatures and
compact-JWS tokens so the JSON stays human-readable. A runner substitutes real
values with the pinned KAT keypairs before invoking the verifier — that is this
module's job. It is deliberately separate from the verification core: minting
signs, the core only verifies.

The reference clock (``1711900000``) anchors ``__NOW__`` so a re-mint is
byte-stable across implementations (PLACEHOLDERS.md §Reference clock).
"""

from __future__ import annotations

import copy
import re
from typing import Any, cast

from .b64 import b64url_encode
from .crypto import PrivateKey, sha256
from .jcs import canonicalize, dumps
from .jws import encode_jws

__all__ = ["mint_input", "MinterError"]

_TIME_RE = re.compile(r"^__NOW(?:_(MINUS|PLUS)_(\d+))?__$")

# placeholder -> (typ, variant)
_JWS_TOKENS = {
    "__JWS_TCT__": ("aitp-tct+jwt", "normal"),
    "__JWS_GRANT_VOUCHER__": ("aitp-grant+jwt", "normal"),
    "__JWS_DELEGATION__": ("aitp-delegation+jwt", "normal"),
    "__JWS_TCT_TAMPERED_SIG__": ("aitp-tct+jwt", "tamper"),
    "__JWS_DELEGATION_TAMPERED_SIG__": ("aitp-delegation+jwt", "tamper"),
    "__JWS_VOUCHER_TAMPERED_SIG__": ("aitp-grant+jwt", "tamper"),
    "__JWS_TCT_ALG_NONE__": ("aitp-tct+jwt", "alg_none"),
    "__JWS_TCT_WRONG_ALG__": ("aitp-tct+jwt", "wrong_alg"),
    "__ANY_JWS__": ("aitp-delegation+jwt", "any"),
}


class MinterError(RuntimeError):
    """A placeholder could not be materialized (unknown token or missing key)."""


def _resolve_times(obj: Any, now: int) -> Any:
    if isinstance(obj, str):
        m = _TIME_RE.match(obj)
        if not m:
            return obj
        if m.group(1) is None:
            return now
        delta = int(m.group(2))
        return now - delta if m.group(1) == "MINUS" else now + delta
    if isinstance(obj, list):
        return [_resolve_times(v, now) for v in obj]
    if isinstance(obj, dict):
        return {k: _resolve_times(v, now) for k, v in obj.items()}
    return obj


def _tamper_last_sig_byte(token: str) -> str:
    from .b64 import b64url_decode

    h, p, s = token.split(".")
    raw = bytearray(b64url_decode(s))
    raw[-1] ^= 0x01  # flip LSB of last raw signature byte (pinned recipe)
    return f"{h}.{p}.{b64url_encode(bytes(raw))}"


def _mint_claims_object(claims: dict[str, Any], keys: dict[str, PrivateKey], now: int) -> dict[str, Any]:
    """Resolve nested tokens + times inside a claims object and strip ``*_claims``."""
    out = copy.deepcopy(claims)
    out = _resolve_times(out, now)
    for base in list(out.keys()):
        sibling = f"{base}_claims"
        if sibling in out and isinstance(out[base], str) and out[base] in _JWS_TOKENS:
            out[base] = _mint_token(out[base], out[sibling], keys, now)
    return {k: v for k, v in out.items() if not k.endswith("_claims")}


def _mint_token(placeholder: str, claims: dict[str, Any], keys: dict[str, PrivateKey], now: int) -> str:
    if placeholder not in _JWS_TOKENS:
        raise MinterError(f"unknown JWS placeholder: {placeholder}")
    typ, variant = _JWS_TOKENS[placeholder]
    signing_claims = _mint_claims_object(claims, keys, now)
    iss = signing_claims.get("iss")
    if iss not in keys:
        raise MinterError(f"no KAT signing key for iss {iss!r}")
    key = keys[iss]
    jose_alg = "EdDSA" if key.alg == "ed25519" else "ES256"

    if variant == "alg_none":
        header = '{"alg":"none","typ":"' + typ + '"}'
        seg = b64url_encode(header.encode()) + "." + b64url_encode(canonicalize(signing_claims))
        return seg + "." + b64url_encode(bytes(64))
    if variant == "wrong_alg":
        header = '{"alg":"ES256","typ":"' + typ + '"}'
        signing_input = b64url_encode(header.encode()) + "." + b64url_encode(canonicalize(signing_claims))
        sig = key.sign_jose(signing_input.encode("ascii"))
        return signing_input + "." + b64url_encode(sig)

    token = encode_jws(typ, signing_claims, key, alg=jose_alg)
    if variant == "tamper":
        return _tamper_last_sig_byte(token)
    return token


# --- JCS-profile signatures --------------------------------------------------


def _env_wire_sig(key: PrivateKey, digest: bytes) -> str:
    sig = b64url_encode(key.sign_digest(digest))
    return f"p256.{sig}" if key.alg == "p256" else sig  # ed25519 stays legacy-untagged


def _sign_envelope(env: dict[str, Any], keys: dict[str, PrivateKey]) -> None:
    agent_id = env["sender"]["agent_id"]
    payload_hex = sha256(canonicalize(env["payload"])).hex()
    sig_input = f"{env['message_id']}|{env['timestamp']}|{agent_id}|{payload_hex}"
    digest = sha256(sig_input.encode("utf-8"))
    env["signature"] = _env_wire_sig(keys[agent_id], digest)


def _sign_manifest(man: dict[str, Any], keys: dict[str, PrivateKey]) -> None:
    key = keys[man["aid"]]
    pop = man.get("proof_of_possession")
    if pop and pop.get("signature") == "__VALID_POP_SIG__":
        from .b64 import b64url_decode

        pop["signature"] = b64url_encode(key.sign_digest(sha256(b64url_decode(pop["challenge"]))))
    if man.get("signature") in ("__VALID_MANIFEST_SIG__", "__TAMPERED_SIGNATURE__"):
        body = {k: v for k, v in man.items() if k != "signature"}
        sig = b64url_encode(key.sign_digest(sha256(canonicalize(body))))
        man["signature"] = _tamper_sig_str(sig) if man["signature"] == "__TAMPERED_SIGNATURE__" else sig


def _tamper_sig_str(sig_b64: str) -> str:
    from .b64 import b64url_decode

    raw = bytearray(b64url_decode(sig_b64))
    raw[-1] ^= 0x01
    return b64url_encode(bytes(raw))


def _sign_revocation(snapshot: dict[str, Any], keys: dict[str, PrivateKey]) -> None:
    if snapshot.get("signature") not in ("__VALID_A_SIG__", "__VALID_MANIFEST_SIG__"):
        return
    body = snapshot["revocation_list"]
    key = keys[body["issuer"]]
    snapshot["signature"] = b64url_encode(key.sign_digest(sha256(canonicalize(body))))


def mint_input(inp: dict[str, Any], now: int, keys: dict[str, PrivateKey]) -> dict[str, Any]:
    """Return a copy of the fixture ``input`` with every placeholder resolved."""
    d = cast("dict[str, Any]", _resolve_times(copy.deepcopy(inp), now))

    # Compact-JWS token fields (sibling `<key>_claims` carries the claims).
    for base in list(d.keys()):
        sibling = f"{base}_claims"
        if sibling in d and isinstance(d[base], str) and d[base] in _JWS_TOKENS:
            d[base] = _mint_token(d[base], d[sibling], keys, now)

    if isinstance(d.get("envelope"), dict) and isinstance(d["envelope"].get("signature"), str):
        if d["envelope"]["signature"].startswith("__VALID_ENVELOPE_SIG__"):
            _sign_envelope(d["envelope"], keys)

    if isinstance(d.get("manifest"), dict):
        _sign_manifest(d["manifest"], keys)

    for snap_holder in ("snapshot", "issuer_revocation_list"):
        node = d.get(snap_holder)
        if isinstance(node, dict) and isinstance(node.get("snapshot"), dict):
            _sign_revocation(node["snapshot"], keys)
        elif isinstance(node, dict) and "revocation_list" in node:
            _sign_revocation(node, keys)

    return d
