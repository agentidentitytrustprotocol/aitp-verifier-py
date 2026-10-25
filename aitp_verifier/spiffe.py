"""The ``spiffe`` identity binding (RFC-AITP-0002 §6), a Draft surface behind
``experimental-spiffe-identity``.

A SPIFFE ID ``subject`` is proven by an SVID that chains to the local SPIFFE
bundle of the ID's trust domain (§6.2), in one of two forms:

* **JWT-SVID** (§6.3): checked like the OIDC JWT, with the bundle's
  ``jwt-svid`` key named by the header ``kid`` in place of an issuer key. Of
  the nine algorithms JWT-SVID allows, this verifier implements ``ES256`` and
  ``RS256`` (the JWK forms ``jwk.py`` parses). A JWT-SVID under any other
  allowed algorithm is rejected, never verified some other way.
* **X509-SVID** (§6.4): ``x5c`` is validated as a certification path to the
  bundle's ``x509-svid`` CAs, and ``proof`` is the leaf key's signature over
  the §6.4.1 input.

Path validation is RFC 5280 §6 restricted to what an SVID chain needs, and it
fails closed on anything else. Each certificate must be in its validity
period. Each is issued by the next, by name and by signature. Every issuer is
a CA (``cA`` true, ``keyCertSign``) within its ``pathLenConstraint``. A CA's
URI name constraints are applied to the leaf's SPIFFE ID. A chain is
rejected when it carries a critical extension this module does not process,
or a name constraint of any other name form. There is no AIA fetching, no
system trust store, and no other bundle (§6.4 step 1).

The steps run in §6.5 order. The descriptor, the trust domain, the bundle
and its keys of the right ``use`` are all settled before any signature is
verified. Every failure is ``IDENTITY_FAILED``.
"""

from __future__ import annotations

import base64
import binascii
import re
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtensionOID

from .aid import parse_aid
from .crypto import ALG_ED25519, ALG_P256, PublicKey, sha256
from .errors import AitpError
from .fields import describe_value
from .jwk import issuer_key_from_jwk, thumbprint
from .jws import parse_compact
from .proofinput import SPIFFE_X509_DOMAIN, handshake_proof_input
from .sigfield import decode_tagged_signature_for

__all__ = ["SPIFFE_FEATURE", "parse_spiffe_id", "spiffe_x509_proof_input", "verify_spiffe"]

SPIFFE_FEATURE = "experimental-spiffe-identity"

_SVID_TYPES = {"jwt-svid", "x509-svid"}
# JWT-SVID §2.1. Anything else (`none`, `HS*`, `EdDSA`) is rejected outright.
_JWT_SVID_ALGS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
# The subset this verifier implements (see the module docstring).
_IMPLEMENTED_JWT_SVID_ALGS = {"ES256", "RS256"}
_JWT_SVID_HEADER = {"alg", "kid", "typ"}
_IAT_TOLERANCE_SECS = 300  # as for OIDC (§2.2)
_MAX_ID_BYTES = 2048
_MAX_TRUST_DOMAIN_BYTES = 255
_MAX_CHAIN = 8  # leaf + intermediates; a real SVID chain is two or three
_TRUST_DOMAIN = re.compile(r"[a-z0-9._-]+")
_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_STD_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")
# The critical extensions path validation here processes. Any other critical
# extension rejects the chain (RFC 5280 §6.1.4 (o), §6.1.5 (f)).
_PROCESSED_CRITICAL = {
    ExtensionOID.BASIC_CONSTRAINTS,
    ExtensionOID.KEY_USAGE,
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    ExtensionOID.EXTENDED_KEY_USAGE,
    ExtensionOID.NAME_CONSTRAINTS,
}


def _fail(reason: str) -> AitpError:
    return AitpError("IDENTITY_FAILED", reason)


def parse_spiffe_id(value: Any) -> tuple[str, str]:
    """``(trust_domain, path)`` of a canonical SPIFFE ID with a non-empty path
    (§6.1; SPIFFE-ID §2). Case is never folded. Raises :class:`AitpError`."""
    if not isinstance(value, str):
        raise _fail(f"SPIFFE ID is {describe_value(value)}, not a string")
    if len(value.encode("utf-8")) > _MAX_ID_BYTES:
        raise _fail("SPIFFE ID is longer than 2048 bytes")
    if not value.startswith("spiffe://"):
        raise _fail("SPIFFE ID does not start with the lowercase scheme spiffe://")
    trust_domain, slash, path = value[len("spiffe://"):].partition("/")
    if len(trust_domain) > _MAX_TRUST_DOMAIN_BYTES or not _TRUST_DOMAIN.fullmatch(trust_domain):
        raise _fail("SPIFFE trust domain is empty, too long, or not lowercase letters, digits, '.', '-', '_'")
    if not slash:
        raise _fail("SPIFFE ID names a trust domain, not a workload: its path is empty")
    for segment in path.split("/"):
        if segment in ("", ".", "..") or not _PATH_SEGMENT.fullmatch(segment):
            raise _fail("SPIFFE ID path has an empty, '.', '..' or non-[A-Za-z0-9._-] segment")
    return trust_domain, "/" + path


def spiffe_x509_proof_input(
    sender_aid: str, receiver_aid: str, message_id: str, timestamp: int, pop_nonce: str
) -> bytes:
    """The §6.4.1 X509-SVID proof input."""
    return handshake_proof_input(SPIFFE_X509_DOMAIN, sender_aid, receiver_aid, message_id, timestamp, pop_nonce)


def verify_spiffe(
    identity: dict[str, Any],
    envelope: dict[str, Any],
    self_aid: str,
    spiffe_bundles: Any,
    now: int,
) -> None:
    """Verify a ``spiffe`` identity binding (§6.5). *spiffe_bundles* is the
    verifier's whole bundle store, a list of ``{trust_domain, bundle}``."""
    try:
        _verify(identity, envelope, self_aid, spiffe_bundles, now)
    except AitpError:
        raise
    except (TypeError, ValueError, KeyError, AttributeError, OverflowError, UnsupportedAlgorithm) as exc:
        raise _fail(f"spiffe identity is malformed: {type(exc).__name__}: {exc}") from exc


def _verify(identity: dict[str, Any], envelope: dict[str, Any], self_aid: str, store: Any, now: int) -> None:
    # Step 1: the descriptor (§6.1).
    for member in ("issuer", "public_key"):
        if member in identity:
            raise _fail(f"spiffe descriptor MUST NOT carry {member!r}")
    svid_type = identity.get("svid_type")
    if svid_type not in _SVID_TYPES:
        raise _fail(f"svid_type is {describe_value(svid_type)}, not jwt-svid or x509-svid")
    if (svid_type == "x509-svid") != ("x5c" in identity):
        raise _fail("x5c is required for an x509-svid and forbidden for a jwt-svid")
    subject = identity.get("subject")
    trust_domain, _ = parse_spiffe_id(subject)

    # Steps 2-4: the subject's trust domain, its bundle, its keys of this use.
    bundle = _bundle_for(store, trust_domain)
    keys = bundle.get("keys") if isinstance(bundle, dict) else None
    if not isinstance(keys, list):
        raise _fail(f"the {trust_domain} bundle has no keys array")
    candidates = [k for k in keys if isinstance(k, dict) and k.get("use") == svid_type]
    if not candidates:
        raise _fail(f"the {trust_domain} bundle has no {svid_type} keys")

    # Step 5: the SVID. No signature has been verified before this point.
    if svid_type == "jwt-svid":
        _verify_jwt_svid(identity, envelope, self_aid, candidates, now)
    else:
        _verify_x509_svid(identity, envelope, self_aid, candidates, now)


def _bundle_for(store: Any, trust_domain: str) -> Any:
    if not isinstance(store, list):
        raise _fail("spiffe_bundles is not a list")
    seen: set[str] = set()
    found = None
    for entry in store:
        td = entry.get("trust_domain") if isinstance(entry, dict) else None
        if not isinstance(td, str):
            raise _fail("a spiffe_bundles entry has no string trust_domain")
        if td in seen:
            raise _fail(f"spiffe_bundles lists trust domain {td} twice")
        seen.add(td)
        if td == trust_domain:
            found = entry.get("bundle")
    if found is None:
        raise _fail(f"no SPIFFE bundle for trust domain {trust_domain}")
    return found


# ── JWT-SVID (§6.3) ─────────────────────────────────────────────────────────


def _verify_jwt_svid(
    identity: dict[str, Any], envelope: dict[str, Any], self_aid: str, candidates: list[dict[str, Any]], now: int
) -> None:
    parsed = parse_compact(identity.get("proof", ""), structural_code="IDENTITY_FAILED")
    header = parsed.header
    if not set(header) <= _JWT_SVID_HEADER:
        raise _fail(f"JWT-SVID header carries {sorted(set(header) - _JWT_SVID_HEADER)}; only alg, kid, typ are allowed")
    alg = header.get("alg")
    if alg not in _JWT_SVID_ALGS:
        raise _fail(f"JWT-SVID alg {describe_value(alg)} is not a JWT-SVID algorithm")
    if alg not in _IMPLEMENTED_JWT_SVID_ALGS:
        raise _fail(f"JWT-SVID alg {alg} is not implemented by this verifier")
    if "typ" in header and header["typ"] not in ("JWT", "JOSE"):
        raise _fail(f"JWT-SVID typ {describe_value(header['typ'])} is not JWT or JOSE")
    kid = header.get("kid")
    if not isinstance(kid, str):
        raise _fail("JWT-SVID header has no string kid")
    matches = [k for k in candidates if k.get("kid") == kid]
    if len(matches) != 1:
        raise _fail(f"{len(matches)} jwt-svid bundle keys carry kid {kid!r}; exactly one must")
    key = issuer_key_from_jwk(matches[0])
    if key.jose_alg != alg:
        raise _fail(f"JWT-SVID alg {alg} != bundle key alg {key.jose_alg}")
    # A SPIFFE authority's token, not an AITP signing input: §5.4.7 low-S
    # does not apply, as for an OIDC IdP token.
    if not key.public_key.verify_jose(parsed.signing_input, parsed.signature, idp_token=True):
        raise _fail("JWT-SVID signature invalid")

    # --- nothing below runs without a just-verified signature. ---
    claims = parsed.claims
    if claims.get("sub") != identity["subject"]:
        raise _fail("JWT-SVID sub != identity subject")
    aud = claims.get("aud")
    if isinstance(aud, list) and len(aud) == 1:
        aud = aud[0]
    if not isinstance(aud, str):
        raise _fail("JWT-SVID aud is absent or does not hold exactly one value")
    if not self_aid or aud != self_aid:
        raise _fail("JWT-SVID aud != verifier AID")
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, int) or exp <= now:
        raise _fail("JWT-SVID exp missing, not an integer, or not strictly in the future")
    iat = claims.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int) or abs(now - iat) > _IAT_TOLERANCE_SECS:
        raise _fail("JWT-SVID iat missing, not an integer, or outside the timestamp tolerance")
    pop_nonce = envelope.get("payload", {}).get("pop_nonce")
    nonce = claims.get("nonce")
    if nonce is None or pop_nonce is None or nonce != pop_nonce:
        raise _fail("JWT-SVID nonce != message pop_nonce")
    cnf = claims.get("cnf")
    jkt = cnf.get("jkt") if isinstance(cnf, dict) else None
    if jkt != thumbprint(parse_aid(envelope["sender"]["agent_id"])):
        raise _fail("JWT-SVID cnf.jkt does not bind the sender key")


# ── X509-SVID (§6.4) ────────────────────────────────────────────────────────


def _der(entry: Any, what: str) -> x509.Certificate:
    """One ``x5c`` entry: standard, padded base64 (RFC 4648 §4) of a DER
    certificate, decoded strictly."""
    if not isinstance(entry, str) or not _STD_B64.fullmatch(entry) or len(entry) % 4:
        raise _fail(f"{what} is not standard padded base64")
    try:
        der = base64.b64decode(entry, validate=True)
    except binascii.Error as exc:
        raise _fail(f"{what} is not standard padded base64") from exc
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as exc:
        raise _fail(f"{what} is not a DER certificate") from exc


def _anchors(candidates: list[dict[str, Any]]) -> list[x509.Certificate]:
    """The bundle's ``x509-svid`` CA certificates: each JWK carries exactly
    one, in ``x5c`` (X509-SVID §6.1)."""
    anchors = []
    for jwk in candidates:
        x5c = jwk.get("x5c")
        if not isinstance(x5c, list) or len(x5c) != 1:
            raise _fail("an x509-svid bundle key does not carry exactly one x5c certificate")
        anchors.append(_der(x5c[0], "an x509-svid bundle certificate"))
    return anchors


def _ext(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> Any:
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def _in_validity(cert: x509.Certificate, when: datetime, what: str) -> None:
    if not cert.not_valid_before_utc <= when <= cert.not_valid_after_utc:
        raise _fail(f"{what} is outside its validity period")


def _check_critical(cert: x509.Certificate, what: str) -> None:
    for ext in cert.extensions:
        if ext.critical and ext.oid not in _PROCESSED_CRITICAL:
            raise _fail(f"{what} carries an unprocessed critical extension {ext.oid.dotted_string}")


def _check_ca(cert: x509.Certificate, below: int, what: str) -> None:
    """*cert* may issue: ``cA`` true, ``keyCertSign``, and a
    ``pathLenConstraint`` that allows the *below* CA certificates under it."""
    bc = _ext(cert, ExtensionOID.BASIC_CONSTRAINTS)
    if bc is None or not bc.ca:
        raise _fail(f"{what} is not a CA certificate")
    if bc.path_length is not None and below > bc.path_length:
        raise _fail(f"{what} pathLenConstraint {bc.path_length} is exceeded")
    ku = _ext(cert, ExtensionOID.KEY_USAGE)
    if ku is None or not ku.key_cert_sign:
        raise _fail(f"{what} key usage does not include keyCertSign")


def _uri_host_matches(host: str, constraint: str) -> bool:
    """RFC 5280 §4.2.1.10 for a URI name: a constraint starting with ``.``
    matches any subdomain, otherwise only that host."""
    if constraint.startswith("."):
        return host.endswith(constraint)
    return host == constraint


def _check_name_constraints(cert: x509.Certificate, trust_domain: str, what: str) -> None:
    nc = _ext(cert, ExtensionOID.NAME_CONSTRAINTS)
    if nc is None:
        return
    subtrees = [*(nc.permitted_subtrees or ()), *(nc.excluded_subtrees or ())]
    if any(not isinstance(name, x509.UniformResourceIdentifier) for name in subtrees):
        raise _fail(f"{what} has a name constraint on a name form other than URI, which is not processed")
    permitted = [n.value for n in nc.permitted_subtrees or ()]
    if nc.permitted_subtrees is not None and not any(_uri_host_matches(trust_domain, c) for c in permitted):
        raise _fail(f"{what} name constraints do not permit trust domain {trust_domain}")
    if any(_uri_host_matches(trust_domain, n.value) for n in nc.excluded_subtrees or ()):
        raise _fail(f"{what} name constraints exclude trust domain {trust_domain}")


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False
    return True


def _leaf_key(leaf: x509.Certificate) -> PublicKey:
    key = leaf.public_key()
    if isinstance(key, ed25519.Ed25519PublicKey):
        return PublicKey(ALG_ED25519, key)
    if isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1):
        return PublicKey(ALG_P256, key)
    raise _fail("X509-SVID leaf key is neither Ed25519 nor P-256")


def _verify_x509_svid(
    identity: dict[str, Any], envelope: dict[str, Any], self_aid: str, candidates: list[dict[str, Any]], now: int
) -> None:
    x5c = identity["x5c"]
    if not isinstance(x5c, list) or not x5c:
        raise _fail("x5c is not a non-empty array")
    if len(x5c) > _MAX_CHAIN:
        raise _fail(f"x5c carries more than {_MAX_CHAIN} certificates")
    chain = [_der(entry, f"x5c[{i}]") for i, entry in enumerate(x5c)]
    anchors = _anchors(candidates)
    leaf = chain[0]
    subject = identity["subject"]
    trust_domain, _ = parse_spiffe_id(subject)
    when = datetime.fromtimestamp(now, tz=timezone.utc)

    # Step 2: exactly one URI SAN, and it is the subject, byte for byte.
    san = _ext(leaf, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    uris = san.get_values_for_type(x509.UniformResourceIdentifier) if san is not None else []
    if len(uris) != 1:
        raise _fail(f"X509-SVID leaf carries {len(uris)} URI SANs; exactly one is required")
    if uris[0] != subject:
        raise _fail("X509-SVID URI SAN != identity subject")

    # Step 3: the leaf is not a CA, and signs but does not certify.
    bc = _ext(leaf, ExtensionOID.BASIC_CONSTRAINTS)
    if bc is None or bc.ca:
        raise _fail("X509-SVID leaf basic constraints are absent or cA is true")
    ku = _ext(leaf, ExtensionOID.KEY_USAGE)
    if ku is None or not ku.digital_signature or ku.key_cert_sign or ku.crl_sign:
        raise _fail("X509-SVID leaf key usage must include digitalSignature and exclude keyCertSign and cRLSign")

    # Step 4: an AITP signing key.
    leaf_key = _leaf_key(leaf)

    # Step 1: the certification path, leaf -> x5c[1..] -> a bundle CA.
    for i, cert in enumerate(chain):
        what = "X509-SVID leaf" if i == 0 else f"x5c[{i}]"
        if cert.version != x509.Version.v3:
            raise _fail(f"{what} is not an X.509 v3 certificate")
        _in_validity(cert, when, what)
        _check_critical(cert, what)
        if i > 0:
            _check_ca(cert, i - 1, what)
            _check_name_constraints(cert, trust_domain, what)
        if i + 1 < len(chain) and not _issued_by(cert, chain[i + 1]):
            raise _fail(f"{what} is not issued by x5c[{i + 1}]")
    anchor = next((a for a in anchors if _issued_by(chain[-1], a)), None)
    if anchor is None:
        raise _fail(f"x5c does not chain to an x509-svid CA of the {trust_domain} bundle")
    _in_validity(anchor, when, "the bundle CA")
    _check_ca(anchor, len(chain) - 1, "the bundle CA")
    _check_name_constraints(anchor, trust_domain, "the bundle CA")

    # §6.5 step 5: the proof, under the leaf key, over the §6.4.1 input.
    proof_input = spiffe_x509_proof_input(
        envelope["sender"]["agent_id"],
        self_aid,
        envelope["message_id"],
        int(envelope["timestamp"]),
        envelope["payload"]["pop_nonce"],
    )
    sig = decode_tagged_signature_for(identity.get("proof"), leaf_key.alg, sig_err="IDENTITY_FAILED")
    if not leaf_key.verify_digest(sha256(proof_input), sig):
        raise _fail("X509-SVID proof does not verify under the leaf key")
