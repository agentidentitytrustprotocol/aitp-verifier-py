"""Verify the byte-exact signed compact-JWS artifacts and re-mint the TCT.

An implementation that fails to verify any artifact under
``known-answer/signed-examples/`` is non-conformant (its README). Re-minting
the TCT to the identical compact string additionally proves the JOSE signing +
JCS payload path matches the reference byte-for-byte.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from aitp_verifier.crypto import PrivateKey
from aitp_verifier.jws import encode_jws, verify_jws


def _se(spec_dir: Path, rel: str) -> dict[str, Any]:
    path = spec_dir / "schemas/conformance/known-answer/signed-examples" / rel
    return cast("dict[str, Any]", json.loads(path.read_text()))


def test_tct_verifies_and_remints(spec_dir: Path) -> None:
    t = _se(spec_dir, "tct/kat-keypair-001-issues-002.json")
    dc = t["decoded_claims"]
    claims = verify_jws(
        t["tct_token"], iss_aid=dc["iss"], expected_typ="aitp-tct+jwt",
        typ_err="TOKEN_TYP_MISMATCH", alg_err="TOKEN_ALG_MISMATCH", sig_err="TCT_SIGNATURE_INVALID",
    )
    assert claims == dc
    seed = bytes.fromhex("00" * 32)  # kat-keypair-001
    minted = encode_jws("aitp-tct+jwt", dc, PrivateKey.ed25519_from_seed(seed), alg="EdDSA")
    assert minted == t["tct_token"]


def test_voucher_and_delegation_verify(spec_dir: Path) -> None:
    for rel, typ, sig_err in [
        ("grant-voucher/kat-voucher-001.json", "aitp-grant+jwt", "DELEGATION_INVALID_VOUCHER"),
        ("delegation/single-hop-001-002-003.json", "aitp-delegation+jwt", "DELEGATION_INVALID_SIGNATURE"),
    ]:
        d = _se(spec_dir, rel)
        token = next(d[k] for k in d if k.endswith("_token"))
        claims = verify_jws(
            token, iss_aid=d["decoded_claims"]["iss"], expected_typ=typ,
            typ_err="TOKEN_TYP_MISMATCH", alg_err="TOKEN_ALG_MISMATCH", sig_err=sig_err,
        )
        assert claims == d["decoded_claims"]
