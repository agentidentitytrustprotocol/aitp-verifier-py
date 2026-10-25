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

import base64
import copy
import functools
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from .aid import parse_aid
from .b64 import b64url_decode, b64url_encode
from .crypto import PrivateKey, sha256
from .envelope import envelope_signing_input
from .identity import pinned_key_proof_input
from .jcs import canonicalize
from .jwk import thumbprint
from .jws import encode_jws
from .keys import OIDC_ISSUER_KEY_IDS, UNKNOWN_OIDC_ISSUER_KEY_ID
from .spiffe import spiffe_x509_proof_input

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
    digest = sha256(envelope_signing_input(env))
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
        pop["signature"] = _env_wire_sig(key, sha256(b64url_decode(pop["challenge"])))
    elif pop and pop.get("signature") == "__INVALID_POP_SIG__":
        # Sign the wrong digest so the PoP check fails at the crypto layer.
        pop["signature"] = _env_wire_sig(key, sha256(b"aitp-invalid-pop"))
    if man.get("signature") in ("__VALID_MANIFEST_SIG__", "__TAMPERED_SIGNATURE__"):
        body = {k: v for k, v in man.items() if k != "signature"}
        sig = _env_wire_sig(key, sha256(canonicalize(body)))
        man["signature"] = _tamper_sig_str(sig) if man["signature"] == "__TAMPERED_SIGNATURE__" else sig


def _tamper_sig_str(sig_b64: str) -> str:
    from .b64 import b64url_decode

    raw = bytearray(b64url_decode(sig_b64))
    raw[-1] ^= 0x01
    return b64url_encode(bytes(raw))


def _sign_revocation(snapshot: dict[str, Any], keys: dict[str, PrivateKey]) -> None:
    if snapshot.get("signature") not in ("__VALID_A_SIG__", "__VALID_B_SIG__", "__VALID_MANIFEST_SIG__"):
        return
    body = snapshot["revocation_list"]
    key = keys[body["issuer"]]
    snapshot["signature"] = _env_wire_sig(key, sha256(canonicalize(body)))


# --- handshake payload minting ----------------------------------------------

_OTHER_AID = "aid:pubkey:iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w"  # kat-004, a peer != self
_WRONG_NONCE = b64url_encode(bytes([0xFF] * 16))  # 22-char b64url, decodes != any real nonce


_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _issuer_key(issuer: str, alg: str = "EdDSA") -> PrivateKey:
    """Deterministic synthetic OIDC issuer key, for unit tests that need an
    issuer of either AID algorithm. Corpus fixtures never use it: they are
    signed with the pinned keys (``_corpus_issuer_key``).

    Only ``EdDSA`` (Ed25519) and ``ES256`` (P-256) are derivable here — the
    two algorithms ``PrivateKey`` supports (AITP's AID algorithms). RS256 test
    vectors sign through a separately pinned RSA key supplied via
    ``_mint_oidc_jwt``'s ``sign_override`` — RSA is deliberately never wired
    into ``PrivateKey`` (it is verify-only, third-party issuer key material;
    see ``crypto.py``).
    """
    seed = sha256(b"aitp-conformance-issuer:" + issuer.encode())
    if alg == "ES256":
        scalar = (int.from_bytes(seed, "big") % (_P256_ORDER - 1)) + 1
        return PrivateKey.p256_from_scalar(scalar)
    return PrivateKey.ed25519_from_seed(seed)


def _corpus_issuer_key(placeholder: str, issuer: Any, keys: dict[str, PrivateKey]) -> PrivateKey:
    """The pinned key that signs a corpus OIDC JWT (known-answer/oidc-test-issuers.json):
    the unknown-issuer key for ``__VALID_JWT_FROM_UNKNOWN_ISSUER__``, else the
    issuer's own pinned key. An issuer with no pinned key is a fixture the
    corpus cannot mint byte-stably, so it is refused rather than given one."""
    if placeholder == "__VALID_JWT_FROM_UNKNOWN_ISSUER__":
        return keys[UNKNOWN_OIDC_ISSUER_KEY_ID]
    key_id = OIDC_ISSUER_KEY_IDS.get(issuer) if isinstance(issuer, str) else None
    if key_id is None:
        raise MinterError(f"no pinned OIDC test-issuer key for {issuer!r}")
    return keys[key_id]


def _mint_oidc_jwt(
    placeholder: str,
    identity: dict[str, Any],
    env: dict[str, Any],
    inp: dict[str, Any],
    now: int,
    *,
    alg: str = "EdDSA",
    kid: str | None = None,
    sign_override: Callable[[bytes], bytes] | None = None,
) -> str:
    """Mint a compact-JWS OIDC identity JWT.

    ``alg``/``kid`` default to the original hardcoded shape (bare
    ``{"alg":"EdDSA","typ":"JWT"}``, no ``kid``) so existing conformance
    fixtures re-mint byte-identically. ``sign_override`` lets a caller (e.g.
    a test building an RS256 vector) supply the raw signing function instead
    of deriving one from ``_issuer_key``.
    """
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
    header_obj: dict[str, Any] = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header_obj["kid"] = kid
    header = json.dumps(header_obj, separators=(",", ":")).encode()
    signing_input = b64url_encode(header) + "." + b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    if sign_override is not None:
        sig = sign_override(signing_input.encode("ascii"))
    else:
        sig = _issuer_key(issuer, alg).sign_jose(signing_input.encode("ascii"))
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
    elif placeholder in ("__PINNED_PROOF_OVER_WRONG_NONCE__", "__INVALID_POP_SIG_OVER_WRONG_NONCE__"):
        # The second spelling is the pre-#80 name of the same placeholder.
        data = pinned_key_proof_input(sender, self_aid, mid, ts, _WRONG_NONCE)
    elif placeholder == "__VALID_PINNED_PROOF__":
        data = pinned_key_proof_input(sender, self_aid, mid, ts, nonce)
    else:
        # Minting a valid proof for a name we do not know would turn a
        # negative fixture into a false pass.
        raise MinterError(f"unknown pinned-key proof placeholder {placeholder}")
    return _env_wire_sig(sk, sha256(data))


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


# ── SPIFFE test authorities (PLACEHOLDERS.md, spiffe fixtures id-024..030) ──
#
# Minted at runtime, like the pre-#133 OIDC issuers: one P-256 JWT-SVID
# signing key and one self-signed P-256 X.509 CA, both for prod.example.com.
# Their keys are derived from fixed labels; the CA certificate is built once
# per clock value, so every placeholder minted at one `now` agrees on it.

_SPIFFE_TRUST_DOMAIN = "prod.example.com"
_SPIFFE_JWT_KID = "aitp-test-spiffe-jwt-1"
_SPIFFE_LEAF_AID = "aid:pubkey:dqFZIESm5PURJlvKc6YE2QsFKdHfYCvjChmpJXZg0fU"  # kat-keypair-003, the leaf key
_SPIFFE_OTHER_SAN = "spiffe://prod.example.com/ns/payments/sa/other"
_SPIFFE_WRONG_NONCE = "YWl0cC1zcGlmZmUtand0OQ"  # the 16 bytes "aitp-spiffe-jwt9"


def _spiffe_key(label: str) -> PrivateKey:
    scalar = (int.from_bytes(sha256(b"aitp-conformance-spiffe:" + label.encode()), "big") % (_P256_ORDER - 1)) + 1
    return PrivateKey.p256_from_scalar(scalar)


def _ec_jwk(key: PrivateKey) -> dict[str, Any]:
    numbers = cast(Any, key.native).public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(numbers.x.to_bytes(32, "big")),
        "y": b64url_encode(numbers.y.to_bytes(32, "big")),
    }


@functools.lru_cache(maxsize=8)
def _spiffe_ca(now: int) -> x509.Certificate:
    key = _spiffe_key("x509-ca")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aitp-test-spiffe-ca")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(cast(Any, key.native).public_key())
        .serial_number(1)
        .not_valid_before(datetime.fromtimestamp(now - 3600, tz=timezone.utc))
        .not_valid_after(datetime.fromtimestamp(now + 86400, tz=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(f"spiffe://{_SPIFFE_TRUST_DOMAIN}")]), critical=False)
        .sign(cast(Any, key.native), hashes.SHA256())
    )


def _std_b64_der(cert: x509.Certificate) -> str:
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")


def _spiffe_bundle_key(placeholder: str, now: int) -> dict[str, Any]:
    if placeholder == "__TEST_SPIFFE_JWT_AUTHORITY_JWK__":
        return {**_ec_jwk(_spiffe_key("jwt-authority")), "kid": _SPIFFE_JWT_KID, "use": "jwt-svid"}
    if placeholder == "__TEST_SPIFFE_X509_CA_JWK__":
        return {**_ec_jwk(_spiffe_key("x509-ca")), "use": "x509-svid", "x5c": [_std_b64_der(_spiffe_ca(now))]}
    raise MinterError(f"unknown SPIFFE bundle key placeholder {placeholder}")


def _mint_spiffe_bundles(config: dict[str, Any], now: int) -> None:
    for entry in config.get("spiffe_bundles", []):
        bundle = entry.get("bundle") if isinstance(entry, dict) else None
        if isinstance(bundle, dict) and isinstance(bundle.get("keys"), list):
            bundle["keys"] = [
                _spiffe_bundle_key(k, now) if isinstance(k, str) and k.startswith("__") else k for k in bundle["keys"]
            ]


def _mint_x509_svid(placeholder: str, subject: str, keys: dict[str, PrivateKey], now: int) -> str:
    sans = [subject]
    if placeholder == "__X509_SVID_LEAF_TWO_URI_SANS__":
        sans.append(_SPIFFE_OTHER_SAN)
    elif placeholder != "__X509_SVID_LEAF__":
        raise MinterError(f"unknown X509-SVID placeholder {placeholder}")
    ca_key = _spiffe_key("x509-ca")
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "aitp-test-svid")]))
        .issuer_name(_spiffe_ca(now).subject)
        .public_key(cast(Any, keys[_SPIFFE_LEAF_AID].native).public_key())
        .serial_number(2)
        .not_valid_before(datetime.fromtimestamp(now - 60, tz=timezone.utc))
        .not_valid_after(datetime.fromtimestamp(now + 3600, tz=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(u) for u in sans]), critical=False)
        .sign(cast(Any, ca_key.native), hashes.SHA256())
    )
    return _std_b64_der(leaf)


def _mint_jwt_svid(placeholder: str, identity: dict[str, Any], env: dict[str, Any], inp: dict[str, Any], now: int) -> str:
    claims: dict[str, Any] = {
        "sub": identity["subject"],
        "aud": [inp.get("self_aid")],
        "iat": now,
        "exp": now + 300,
        "nonce": env["payload"].get("pop_nonce"),
        "cnf": {"jkt": thumbprint(parse_aid(env["sender"]["agent_id"]))},
    }
    if placeholder == "__JWT_SVID_WRONG_NONCE__":
        claims["nonce"] = _SPIFFE_WRONG_NONCE
    elif placeholder == "__JWT_SVID_EXPIRED__":
        claims["iat"], claims["exp"] = now - 360, now - 60
    elif placeholder == "__JWT_SVID_AUD_DIFFERENT_PEER__":
        claims["aud"] = [_OTHER_AID]
    elif placeholder not in ("__VALID_JWT_SVID__", "__JWT_SVID_STAGING_SUBJECT_PROD_KEY__"):
        raise MinterError(f"unknown JWT-SVID placeholder {placeholder}")
    header = json.dumps({"alg": "ES256", "kid": _SPIFFE_JWT_KID, "typ": "JWT"}, separators=(",", ":")).encode()
    signing_input = b64url_encode(header) + "." + b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    return signing_input + "." + b64url_encode(_spiffe_key("jwt-authority").sign_jose(signing_input.encode("ascii")))


def _mint_spiffe_identity(identity: dict[str, Any], env: dict[str, Any], inp: dict[str, Any], keys: dict[str, PrivateKey], now: int) -> None:
    x5c = identity.get("x5c")
    if isinstance(x5c, list):
        identity["x5c"] = [
            _mint_x509_svid(c, identity["subject"], keys, now) if isinstance(c, str) and c.startswith("__") else c for c in x5c
        ]
    proof = identity.get("proof")
    if not (isinstance(proof, str) and proof.startswith("__")):
        return
    if identity.get("svid_type") == "jwt-svid":
        identity["proof"] = _mint_jwt_svid(proof, identity, env, inp, now)
    elif proof == "__VALID_X509_SVID_PROOF__":
        data = spiffe_x509_proof_input(
            env["sender"]["agent_id"], inp.get("self_aid", ""), env["message_id"], int(env["timestamp"]), env["payload"]["pop_nonce"]
        )
        identity["proof"] = _env_wire_sig(keys[_SPIFFE_LEAF_AID], sha256(data))
    else:
        raise MinterError(f"unknown X509-SVID proof placeholder {proof}")


def _mint_handshake(inp: dict[str, Any], keys: dict[str, PrivateKey], now: int) -> None:
    env = inp["envelope"]
    payload = env.get("payload", {})
    if isinstance(payload.get("manifest"), dict):
        _sign_manifest(payload["manifest"], keys)

    identity = payload.get("identity")
    if isinstance(identity, dict) and isinstance(identity.get("proof"), str) and identity["proof"].startswith("__"):
        if identity.get("type") == "oidc":
            signer = _corpus_issuer_key(identity["proof"], identity.get("issuer"), keys)
            identity["proof"] = _mint_oidc_jwt(identity["proof"], identity, env, inp, now, sign_override=signer.sign_jose)
        elif identity.get("type") == "pinned_key":
            identity["proof"] = _mint_pinned_proof(identity["proof"], identity, env, inp, keys)
    if isinstance(identity, dict) and identity.get("type") == "spiffe":
        _mint_spiffe_identity(identity, env, inp, keys, now)

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


def _mint_bundle(outer: dict[str, Any], keys: dict[str, PrivateKey], now: int) -> None:
    body = outer["session_bundle"]
    for p in body.get("participants", []):
        if isinstance(p.get("tct"), str) and p["tct"] in _JWS_TOKENS and "tct_claims" in p:
            p["tct"] = _mint_token(p["tct"], p["tct_claims"], keys, now)
        for k in [k for k in p if k.endswith("_claims")]:
            del p[k]  # participant entries are additionalProperties:false on the wire
    if body.get("signature") == "__VALID_A_SIG__":
        key = keys[body["coordinator"]]
        signing_body = {k: v for k, v in body.items() if k != "signature"}
        body["signature"] = _env_wire_sig(key, sha256(canonicalize(signing_body)))


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

    if isinstance(d.get("trust_anchors_config"), dict):
        _mint_spiffe_bundles(d["trust_anchors_config"], now)

    if isinstance(d.get("envelope"), dict):
        _mint_handshake(d, keys, now)

    for side in ("peer_a", "peer_b"):
        if isinstance(d.get(side), dict):
            _mint_peer(d[side], keys, now)

    if isinstance(d.get("session_bundle"), dict) and "session_bundle" in d["session_bundle"]:
        _mint_bundle(d["session_bundle"], keys, now)

    if isinstance(d.get("manifest"), dict):
        _sign_manifest(d["manifest"], keys)

    # Manifest inputs (conformance README, "Manifest inputs"): the verifier's
    # whole Manifest source for delegation issuers and the bundle coordinator.
    held = d.get("issuer_manifests")
    for man in [d.get("coordinator_manifest"), *(held if isinstance(held, list) else [])]:
        if isinstance(man, dict):
            _sign_manifest(man, keys)

    for snap_holder in ("snapshot", "issuer_revocation_list"):
        node = d.get(snap_holder)
        if isinstance(node, dict) and isinstance(node.get("snapshot"), dict):
            _sign_revocation(node["snapshot"], keys)
        elif isinstance(node, dict) and "revocation_list" in node:
            _sign_revocation(node, keys)

    # Multi-hop delegation's per-hop revocation snapshots (RFC-AITP-0011 §6):
    # a list of `{"issuer_aid": ..., "snapshot": {...}}` records, each signed
    # the same way as the single-holder cases above.
    for record in d.get("revocation_snapshots", []) or []:
        if isinstance(record, dict) and isinstance(record.get("snapshot"), dict):
            _sign_revocation(record["snapshot"], keys)

    return d
