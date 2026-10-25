"""Known-answer keypairs for the conformance minter.

The conformance fixtures carry ``__..__`` placeholders in place of signatures
and compact-JWS tokens. A runner materializes them with the pinned KAT
keypairs (``schemas/conformance/known-answer/keypairs.json``) before invoking
the verifier — this module loads those seeds into signing keys indexed by AID.
The OIDC test issuers' signing keys (``known-answer/oidc-test-issuers.json``)
are not AIDs; they join the same mapping under their vector ids.

Signing lives strictly on the minting side; the verification core
(``aitp_verifier``'s surface modules) never imports it.
"""

from __future__ import annotations

import json
from pathlib import Path

from .b64 import b64url_encode
from .crypto import PrivateKey

__all__ = ["OIDC_ISSUER_KEY_IDS", "UNKNOWN_OIDC_ISSUER_KEY_ID", "load_kat_keys"]

# Issuer URL -> the oidc-test-issuers.json vector that signs its JWTs. An
# issuer resolver resolves these and no other issuer (PLACEHOLDERS.md,
# "Identity-issuer keys").
OIDC_ISSUER_KEY_IDS = {"https://auth.openai.com": "kat-oidc-issuer-001"}
# Signs __VALID_JWT_FROM_UNKNOWN_ISSUER__; never resolved for any issuer.
UNKNOWN_OIDC_ISSUER_KEY_ID = "kat-oidc-issuer-002-unknown"


def load_kat_keys(spec_dir: Path) -> dict[str, PrivateKey]:
    """Return a mapping of AID string -> signing key from the spec's KATs."""
    path = spec_dir / "schemas/conformance/known-answer/keypairs.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    keys: dict[str, PrivateKey] = {}
    for vec in data["vectors"]:
        if vec.get("algorithm") == "p256":
            key = PrivateKey.p256_from_scalar(int(vec["private_scalar_hex"], 16))
        else:
            key = PrivateKey.ed25519_from_seed(bytes.fromhex(vec["seed_hex"]))
        keys[vec["aid"]] = key
    path = spec_dir / "schemas/conformance/known-answer/oidc-test-issuers.json"
    for vec in json.loads(path.read_text(encoding="utf-8"))["vectors"]:
        key = PrivateKey.ed25519_from_seed(bytes.fromhex(vec["seed_hex"]))
        if b64url_encode(key.raw_public()) != vec["pubkey_b64url"]:
            raise ValueError(f"{vec['id']}: pubkey_b64url is not the public key of seed_hex")
        keys[vec["id"]] = key
    return keys
