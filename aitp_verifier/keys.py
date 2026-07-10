"""Known-answer keypairs for the conformance minter.

The conformance fixtures carry ``__..__`` placeholders in place of signatures
and compact-JWS tokens. A runner materializes them with the pinned KAT
keypairs (``schemas/conformance/known-answer/keypairs.json``) before invoking
the verifier — this module loads those seeds into signing keys indexed by AID.

Signing lives strictly on the minting side; the verification core
(``aitp_verifier``'s surface modules) never imports it.
"""

from __future__ import annotations

import json
from pathlib import Path

from .crypto import PrivateKey

__all__ = ["load_kat_keys"]


def load_kat_keys(spec_dir: Path) -> dict[str, PrivateKey]:
    """Return a mapping of AID string -> signing key from the spec's KATs."""
    path = spec_dir / "schemas/conformance/known-answer/keypairs.json"
    data = json.loads(path.read_text())
    keys: dict[str, PrivateKey] = {}
    for vec in data["vectors"]:
        if vec.get("algorithm") == "p256":
            key = PrivateKey.p256_from_scalar(int(vec["private_scalar_hex"], 16))
        else:
            key = PrivateKey.ed25519_from_seed(bytes.fromhex(vec["seed_hex"]))
        keys[vec["aid"]] = key
    return keys
