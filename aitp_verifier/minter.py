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
import json
import re
from typing import Any, cast

from .aid import parse_aid
from .b64 import b64url_decode, b64url_encode
from .crypto import PrivateKey, sha256
from .identity import pinned_key_proof_input
from .jcs import canonicalize, dumps
from .jwk import thumbprint
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
    # Multi-hop chain: an array of __JWS_DELEGATION__ tokens with a parallel
    # `chain_claims` array; then the RFC-AITP-0011 §5 chain_hash commitment.
    if "chain" in out and "chain_claims" in out:
        from .delegation import compute_chain_hash

        out["chain"] = [_mint_token("__JWS_DELEGATION__", cc, keys, now) for cc in out["chain_claims"]]
        if out.get("chain_hash") == "__COMPUTED_CHAIN_HASH__":
            out["chain_hash"] = compute_chain_hash(out["chain"])
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
    if man["aid"] not in keys:
        # e.g. mh-002's one-shot "attacker" key: the spec pins only its public
        # AID, not the seed, so an independent re-minter cannot reproduce its
        # valid PoP. A runner consuming pre-minted fixtures would have it.
        raise MinterError(f"no KAT signing key for manifest aid {man['aid']} (one-shot key not pinned in spec)")
    key = keys[man["aid"]]
    pop = man.get("proof_of_possession")
    if pop and pop.get("signature") == "__VALID_POP_SIG__":
        pop["signature"] = b64url_encode(key.sign_digest(sha256(b64url_decode(pop["challenge"]))))
    elif pop and pop.get("signature") == "__INVALID_POP_SIG__":
        # Sign the wrong digest so the PoP check fails at the crypto layer.
        pop["signature"] = b64url_encode(key.sign_digest(sha256(b"aitp-invalid-pop")))
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


# --- handshake payload minting ----------------------------------------------

_OTHER_AID = "aid:pubkey:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"  # kat-004, a peer != self
_WRONG_NONCE = b64url_encode(bytes([0xFF] * 16))  # 22-char b64url, decodes != any real nonce


def _issuer_key(issuer: str) -> PrivateKey:
    """Deterministic synthetic OIDC issuer key (both mint + inline its pubkey)."""
    return PrivateKey.ed25519_from_seed(sha256(b"aitp-conformance-issuer:" + issuer.encode()))


def _mint_oidc_jwt(placeholder: str, identity: dict[str, Any], env: dict[str, Any], inp: dict[str, Any], now: int) -> str:
    issuer = identity["issuer"]
    sender = env["sender"]["agent_id"]
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": identity["subject"],
        "aud": inp.get("self_aid") or sender,
        "iat": now,
        "exp": now + 3600,
        "nonce": env["payload"].get("pop_nonce"),
        "cnf": {"jkt": thumbprint(parse_aid(sender))},
    }
    if placeholder == "__JWT_MISSING_AUD_CLAIM__":
        claims.pop("aud")
    elif placeholder == "__JWT_AUD_TARGETS_DIFFERENT_PEER__":
        claims["aud"] = _OTHER_AID
    elif placeholder == "__JWT_MISSING_CNF_JKT_CLAIM__":
        claims.pop("cnf")
    header = json.dumps({"alg": "EdDSA", "typ": "JWT"}, separators=(",", ":")).encode()
    signing_input = b64url_encode(header) + "." + b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    sig = _issuer_key(issuer).sign_jose(signing_input.encode("ascii"))
    return signing_input + "." + b64url_encode(sig)


def _mint_pinned_proof(placeholder: str, identity: dict[str, Any], env: dict[str, Any], inp: dict[str, Any], keys: dict[str, PrivateKey]) -> str:
    sender = env["sender"]["agent_id"]
    sk = keys[sender]
    self_aid = inp["self_aid"]
    mid, ts, nonce = env["message_id"], env["timestamp"], env["payload"]["pop_nonce"]
    if placeholder == "__CAPTURED_PROOF_FROM_ORIGINAL_HANDSHAKE__":
        c = inp["captured_proof_context"]
        data = pinned_key_proof_input(
            c["original_sender_aid"], c["original_receiver_aid"], c["original_message_id"],
            c["original_timestamp"], c["original_pop_nonce"],
        )
    elif placeholder == "__LEGACY_PINNED_PROOF__":
        data = f"{mid}|{ts}".encode()  # pre-v0.1 two-field input — must fail five-field reconstruction
    elif placeholder == "__INVALID_POP_SIG_OVER_WRONG_NONCE__":
        data = pinned_key_proof_input(sender, self_aid, mid, ts, _WRONG_NONCE)
    else:
        data = pinned_key_proof_input(sender, self_aid, mid, ts, nonce)
    return b64url_encode(sk.sign_digest(sha256(data)))


def _mint_pop_signature(payload: dict[str, Any], sender: str, self_nonce: str | None, keys: dict[str, PrivateKey]) -> None:
    ph = payload.get("pop_signature")
    if not isinstance(ph, str) or not ph.startswith("__"):
        return
    sk = keys[sender]
    nonce = self_nonce or payload.get("pop_nonce_echo")
    if ph == "__INVALID_POP_SIG_OVER_WRONG_NONCE__":
        nonce = _WRONG_NONCE
    if nonce is None:
        return
    payload["pop_signature"] = b64url_encode(sk.sign_digest(sha256(b64url_decode(nonce))))


def _mint_handshake(inp: dict[str, Any], keys: dict[str, PrivateKey], now: int) -> None:
    env = inp["envelope"]
    payload = env.get("payload", {})
    issuer_keys: dict[str, str] = {}

    if isinstance(payload.get("manifest"), dict):
        _sign_manifest(payload["manifest"], keys)

    identity = payload.get("identity")
    if isinstance(identity, dict) and isinstance(identity.get("proof"), str) and identity["proof"].startswith("__"):
        if identity.get("type") == "oidc":
            identity["proof"] = _mint_oidc_jwt(identity["proof"], identity, env, inp, now)
            issuer_keys[identity["issuer"]] = b64url_encode(_issuer_key(identity["issuer"]).raw_public())
        elif identity.get("type") == "pinned_key":
            identity["proof"] = _mint_pinned_proof(identity["proof"], identity, env, inp, keys)

    if isinstance(payload.get("tct"), str) and payload["tct"] in _JWS_TOKENS and "tct_claims" in payload:
        payload["tct"] = _mint_token(payload["tct"], payload["tct_claims"], keys, now)

    self_nonce = (
        inp.get("self_pop_nonce_sent_in_hello_ack")
        or inp.get("self_pop_nonce_sent_in_hello")
        or inp.get("self_pop_nonce")
    )
    _mint_pop_signature(payload, env["sender"]["agent_id"], self_nonce, keys)

    # The wire payload carries no minting artifacts — strip *_claims before the
    # envelope signature covers the canonical payload bytes.
    for k in [k for k in payload if k.endswith("_claims")]:
        del payload[k]

    if isinstance(env.get("signature"), str) and env["signature"].startswith("__VALID_ENVELOPE_SIG__"):
        _sign_envelope(env, keys)

    if issuer_keys:
        inp["resolved_issuer_keys"] = issuer_keys


def _peer_nonce(self_aid: str) -> str:
    """A deterministic 16-byte nonce for a peer block (mh-success two-sided shape)."""
    return b64url_encode(sha256(b"aitp-conformance-nonce:" + self_aid.encode())[:16])


def _mint_peer(peer: dict[str, Any], keys: dict[str, PrivateKey], now: int) -> None:
    payload = peer.get("received_payload", {})
    self_nonce = _peer_nonce(peer["self_aid"])
    for k in ("self_pop_nonce_sent_in_hello", "self_pop_nonce_sent_in_hello_ack", "self_pop_nonce"):
        if peer.get(k) == "__VALID_NONCE__":
            peer[k] = self_nonce

    issuer = payload.get("tct_claims", {}).get("iss")
    for base in ("tct", "grant_voucher"):
        if isinstance(payload.get(base), str) and payload[base] in _JWS_TOKENS and f"{base}_claims" in payload:
            payload[base] = _mint_token(payload[base], payload[f"{base}_claims"], keys, now)

    if payload.get("pop_signature") == "__VALID_POP_SIG__" and issuer in keys:
        payload["pop_signature"] = b64url_encode(keys[issuer].sign_digest(sha256(b64url_decode(self_nonce))))
    if payload.get("pop_nonce_echo") == "__VALID_NONCE_ECHO__":
        payload["pop_nonce_echo"] = self_nonce

    for k in [k for k in payload if k.endswith("_claims")]:
        del payload[k]


def mint_input(inp: dict[str, Any], now: int, keys: dict[str, PrivateKey]) -> dict[str, Any]:
    """Return a copy of the fixture ``input`` with every placeholder resolved."""
    d = cast("dict[str, Any]", _resolve_times(copy.deepcopy(inp), now))

    # Compact-JWS token fields (sibling `<key>_claims` carries the claims).
    for base in list(d.keys()):
        sibling = f"{base}_claims"
        if sibling in d and isinstance(d[base], str) and d[base] in _JWS_TOKENS:
            d[base] = _mint_token(d[base], d[sibling], keys, now)

    if isinstance(d.get("envelope"), dict):
        _mint_handshake(d, keys, now)

    for side in ("peer_a", "peer_b"):
        if isinstance(d.get(side), dict):
            _mint_peer(d[side], keys, now)

    if isinstance(d.get("manifest"), dict):
        _sign_manifest(d["manifest"], keys)

    for snap_holder in ("snapshot", "issuer_revocation_list"):
        node = d.get(snap_holder)
        if isinstance(node, dict) and isinstance(node.get("snapshot"), dict):
            _sign_revocation(node["snapshot"], keys)
        elif isinstance(node, dict) and "revocation_list" in node:
            _sign_revocation(node, keys)

    return d
