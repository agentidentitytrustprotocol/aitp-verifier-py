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

from aitp_verifier.aid import parse_aid
from aitp_verifier.crypto import PrivateKey, sha256
from aitp_verifier.jcs import canonicalize
from aitp_verifier.jws import encode_jws, verify_jws
from aitp_verifier.revocation import verify_revocation_snapshot
from aitp_verifier.sessionbundle import verify_session_bundle
from aitp_verifier.sigfield import decode_tagged_signature


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


# ── JCS-profile signed examples ──────────────────────────────────────────
#
# None of the JCS-profile examples were executed here. That is why a
# two-implementation divergence survived a full release: `aitp-rs` signed
# the transport-wrapped form and this implementation signs the inner body,
# and nothing on either side ever verified the OTHER's committed bytes.
#
# All three are now covered, and they do NOT share a convention: the Manifest
# and the session bundle carry `signature` as a member of the signed body
# (excluded from within), while the revocation snapshot carries it as a
# sibling of the body (which is signed as-is). Each case asserts the
# placement explicitly rather than inferring it, so a future artifact that
# silently switches conventions fails here instead of in the field.
#
# Had this test existed, it would have failed the day the snapshot was
# vendored -- which is exactly the point of `signed-examples/`. Its README:
# these files "MUST verify under any conformant AITP v0.2 implementation,
# byte-for-byte, without any placeholder substitution."
#
# Each case asserts both directions. A signature that verifies over the
# inner body AND over the wrapper pins no convention at all, so the
# negative is not optional decoration -- it is half the test.


def test_manifest_signed_example_verifies_over_inner_body(spec_dir: Path) -> None:
    """Manifest: `signature` is a MEMBER of the body, so it is excluded
    from within (RFC-AITP-0003 §6.1)."""
    wrapped = _se(spec_dir, "manifest/kat-keypair-001-manifest.json")
    body = dict(wrapped["manifest"])
    signature = body.pop("signature")
    issuer = parse_aid(body["aid"])
    raw = decode_tagged_signature(signature, issuer, sig_err="MANIFEST_SIGNATURE_INVALID")

    assert issuer.public_key.verify_digest(sha256(canonicalize(body)), raw), (
        "committed manifest signed example must verify over the inner body"
    )

    # Negative: the transport wrapper is not signed.
    assert not issuer.public_key.verify_digest(
        sha256(canonicalize({"manifest": body})), raw
    ), "manifest signature verified over the WRAPPED form (RFC-AITP-0001 §5.4.1)"


def test_revocation_signed_example_verifies_over_inner_body(spec_dir: Path) -> None:
    """Revocation snapshot: `signature` is a SIBLING of the wrapped body,
    never a member of it, so the body is signed as-is with nothing
    stripped (RFC-AITP-0008 §1.5).

    Asserted rather than filtered defensively: if `signature` ever appears
    inside the body, that is a defect to surface, not to paper over.
    """
    snapshot = _se(spec_dir, "revocation/kat-keypair-001-snapshot.json")
    body = snapshot["revocation_list"]
    assert "signature" not in body, (
        "the snapshot's `signature` must be a sibling of `revocation_list`, "
        "not a member of it"
    )

    issuer = parse_aid(body["issuer"])
    raw = decode_tagged_signature(
        snapshot["signature"], issuer, sig_err="TCT_SIGNATURE_INVALID"
    )

    assert issuer.public_key.verify_digest(sha256(canonicalize(body)), raw), (
        "committed revocation signed example must verify over the inner body"
    )

    # Negative: the transport wrapper is not signed.
    assert not issuer.public_key.verify_digest(
        sha256(canonicalize({"revocation_list": body})), raw
    ), "snapshot signature verified over the WRAPPED form (RFC-AITP-0001 §5.4.1)"


def test_session_bundle_signed_example_verifies_over_inner_body(spec_dir: Path) -> None:
    """Session bundle: `signature` is a MEMBER of the inner body (excluded
    from within), the same convention as the Manifest and the opposite of the
    revocation snapshot's sibling placement (RFC-AITP-0010 §3).

    This artifact is why the placement erratum matters most: the bundle is
    redistributable, so a hop that strips the transport wrapper must not
    strip the proof with it. The schema-vs-RFC disagreement here went
    undetected through a full release (spec PR #30) precisely because no
    committed artifact was ever executed -- so the shape assertions below are
    the point of the test, not preamble to it.
    """
    wrapped = _se(spec_dir, "session-bundle/kat-keypair-001-bundle.json")
    body = wrapped["session_bundle"]

    # The erratum, pinned in both directions: inside the body, not beside it.
    assert "signature" in body, (
        "the bundle's `signature` must be a member of the inner body "
        "(RFC-AITP-0010 §3), not a sibling of the transport wrapper"
    )
    assert "signature" not in wrapped, (
        "committed example carries the pre-PR-#30 sibling `signature` shape"
    )

    signing_body = {k: v for k, v in body.items() if k != "signature"}
    coordinator = parse_aid(body["coordinator"])
    raw = decode_tagged_signature(
        body["signature"], coordinator, sig_err="BUNDLE_INVALID_SIGNATURE"
    )

    assert coordinator.public_key.verify_digest(sha256(canonicalize(signing_body)), raw), (
        "committed session-bundle signed example must verify over the inner body"
    )

    # Negative: the transport wrapper is not signed.
    assert not coordinator.public_key.verify_digest(
        sha256(canonicalize({"session_bundle": signing_body})), raw
    ), "bundle signature verified over the WRAPPED form (RFC-AITP-0001 §5.4.1)"

    # Negative: `signature` is excluded from the bytes it covers. An
    # implementation that hashes the body WITH its own signature member
    # verifies self-consistently against itself and would pass every other
    # assertion here.
    assert not coordinator.public_key.verify_digest(sha256(canonicalize(body)), raw), (
        "bundle signature verified over a body INCLUDING its own `signature`"
    )


def test_session_bundle_signed_example_runs_the_real_verifier(spec_dir: Path) -> None:
    """Drive the production `verify_session_bundle` over the committed bytes.

    Unlike the revocation example, the file's top level is the bundle BODY,
    not the transport wrapper -- so the wrapper is constructed here, and
    `_kat_input` (a sibling of `session_bundle` in the file) never enters it.
    That matters now that the wrapper rejects any member beside
    `session_bundle`: passing the file through unaltered would be rejected
    for the metadata, which would look like a signature failure.
    """
    wrapped = _se(spec_dir, "session-bundle/kat-keypair-001-bundle.json")
    body = wrapped["session_bundle"]
    participant = body["participants"][0]["aid"]

    out = verify_session_bundle(
        {
            "self_aid": participant,
            "now": int(body["issued_at"]) + 100,
            "session_bundle": {"session_bundle": body},
        }
    )
    assert out == {"ok": True}


def test_revocation_signed_example_runs_the_real_verifier(spec_dir: Path) -> None:
    """Drive the production `verify_revocation_snapshot` over the committed
    bytes, not just the crypto primitives -- so a regression in the verifier
    itself (not only in canonicalization) is caught here too."""
    snapshot = _se(spec_dir, "revocation/kat-keypair-001-snapshot.json")
    snapshot.pop("_kat_input", None)
    body = snapshot["revocation_list"]

    out = verify_revocation_snapshot(
        {
            "policy": {"fail_mode": "fail_closed", "max_staleness_secs": 86400},
            "now": int(body["published_at"]) + 100,
            "expected_issuer": body["issuer"],
            "snapshot": snapshot,
        }
    )
    assert out == {"revoked": False}
