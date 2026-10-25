"""The conformance fixtures' runner conventions, shared by both front ends.

``run_conformance.py`` (which mints each fixture itself) and
``aitp_verifier.adapter`` (which ``aitp-conformance`` drives with inputs it
has already minted) hand a minted fixture ``input`` to :func:`run_operation`.
It maps the fixture's conventions onto the verifier's inputs and calls the
operation, so both front ends report the same outcome for the same fixture.

The conventions (the spec's ``schemas/conformance/README.md``):

* "Revocation inputs": a fixture with no revocation input is not testing
  revocation, ``issuer_revocation_list.fail_mode`` is the verifier's
  configured mode, ``available: false`` means no source at all, and in a
  delegation fixture every issuer without a supplied snapshot reads "not
  revoked".
* "Receiver policy inputs": the receiver's OIDC trust anchors default to the
  runner-minted test issuer alone.
* "Identity-issuer keys" (PLACEHOLDERS.md): the issuer-key resolver maps
  ``https://auth.openai.com`` to ``kat-oidc-issuer-001`` from
  ``known-answer/oidc-test-issuers.json`` and resolves no other issuer.

None of this is protocol behaviour. A deployment configures its own policy.
"""

from __future__ import annotations

from typing import Any

from .errors import AitpError
from .b64 import b64url_encode
from .jws import parse_compact
from .keys import OIDC_ISSUER_KEY_IDS
from .minter import mint_input
from .timeutil import REFERENCE_CLOCK
from .verify import OPERATIONS
from .version import PROTOCOL_VERSION

__all__ = [
    "NOT_TESTED",
    "RUNNER_OIDC_ISSUER",
    "FixtureError",
    "cover_unsupplied_issuers",
    "issuer_resolver",
    "pop_required",
    "receiver_policy",
    "revocation_conventions",
    "run_operation",
    "unverified_claims",
]

# The runner-minted OIDC test issuer (PLACEHOLDERS.md, "Identity-issuer keys"):
# the receiver's only trust anchor when a fixture states no `self_trust_anchors`.
RUNNER_OIDC_ISSUER = "https://auth.openai.com"

# The policy for a fixture that supplies no revocation input: it is not testing
# revocation, so every lookup reads "not revoked" (README, "Revocation inputs").
NOT_TESTED = {"fail_mode": "fail_open"}


class FixtureError(Exception):
    """A fixture whose inputs contradict each other; reported, never guessed at."""


def unverified_claims(token: Any) -> dict[str, Any]:
    """The claims of a compact JWS, unverified, or ``{}``. For reading what a
    fixture is about (an issuer, a ``jti``), never for a decision."""
    try:
        return parse_compact(token).claims
    except AitpError:
        return {}


def cover_unsupplied_issuers(inp: dict[str, Any], keys: dict[str, Any]) -> dict[str, Any]:
    """The per-issuer convention for a minted delegation input. When a fixture
    supplies ``revocation_snapshots``, an issuer with no entry is not under
    test and reads "not revoked" whatever the mode. Only the supplied entries
    are evaluated, including being discarded under RFC-AITP-0008 §1.5.

    The library applies ``fail_mode`` to an issuer with no snapshot
    (RFC-AITP-0008 §3.1, RFC-AITP-0011 §6), which is right for a deployment.
    Here it would make ``del-mh-004``/``del-mh-006`` pass on A's or C's
    absence rather than on the supplied entry. So every uncovered issuer
    (``self_aid``, the token's ``iss`` and each hop's ``iss``) gets a fresh,
    empty snapshot signed with its KAT key, which is what "not revoked" means
    to the verifier.
    """
    snaps = inp.get("revocation_snapshots")
    if not isinstance(snaps, list):
        return inp
    claims = unverified_claims(inp.get("delegation_token"))
    chain = claims.get("chain")
    hop_issuers = [unverified_claims(h).get("iss") for h in chain] if isinstance(chain, list) else []
    covered = {r.get("issuer_aid") for r in snaps if isinstance(r, dict)}
    now = int(inp.get("now", REFERENCE_CLOCK))
    added = [
        {
            "issuer_aid": aid,
            "snapshot": {
                "revocation_list": {
                    "version": PROTOCOL_VERSION,
                    "issuer": aid,
                    "published_at": now,
                    "expires_at": now + 3600,
                    "entries": [],
                },
                "signature": "__VALID_B_SIG__",
            },
        }
        for aid in dict.fromkeys([inp.get("self_aid"), claims.get("iss"), *hop_issuers])
        if isinstance(aid, str) and aid not in covered
    ]
    if not added:
        return inp
    signed = mint_input({"revocation_snapshots": added}, now, keys)["revocation_snapshots"]
    return {**inp, "revocation_snapshots": [*snaps, *signed]}


def revocation_conventions(op: str, inp: dict[str, Any]) -> dict[str, Any]:
    """Map a fixture's revocation inputs onto the verifier's.

    * No revocation input: not testing revocation, so ``NOT_TESTED``.
    * ``issuer_revocation_list.fail_mode`` is the verifier's configured
      ``revocation_policy.mode``, so it becomes ``policy``. When it is absent
      the verifier runs its own default, which is the point of ``tct-024``.
    * ``available: false`` is "no revocation source for the issuer", so the
      verifier gets no snapshot at all, never an empty one. Beside a
      ``snapshot`` it contradicts itself, which is a fixture error.

    A fixture's own top-level ``policy`` (the ``rev-*`` family) always wins.
    """
    out = dict(inp)
    if op == "verify_delegation_token":
        if "revocation_snapshots" not in out:
            out.setdefault("policy", NOT_TESTED)
        return out
    if op not in ("verify_tct", "verify_attestation", "verify_tct_as_issuer"):
        return out
    revlist = out.get("issuer_revocation_list")
    if revlist is None:
        out.setdefault("policy", NOT_TESTED)
        return out
    if not isinstance(revlist, dict):
        return out
    revlist = dict(revlist)
    mode = revlist.pop("fail_mode", None)
    available = revlist.pop("available", True)
    if not isinstance(available, bool):
        raise FixtureError(f"issuer_revocation_list.available is {available!r}, not a boolean")
    if available:
        out["issuer_revocation_list"] = revlist
    elif "snapshot" in revlist:
        raise FixtureError("issuer_revocation_list has available: false beside a snapshot")
    else:
        del out["issuer_revocation_list"]
    if mode is not None:
        out.setdefault("policy", {"fail_mode": mode})
    return out


def receiver_policy(inp: dict[str, Any], *, accept_presented_type: bool) -> None:
    """The receiver's policy for a handshake fixture. Its OIDC trust anchors
    default to the runner-minted issuer alone.

    An ``id-*`` fixture checks the identity binding (step 6) and does not run
    step 8, so a receiver that always runs step 8 accepts the type the fixture
    presents (*accept_presented_type*). An ``mh-*`` fixture keeps the stated
    types or the verifier's default ``["oidc"]``, and the runner adds none."""
    inp.setdefault("self_trust_anchors", [RUNNER_OIDC_ISSUER])
    identity = inp.get("envelope", {}).get("payload", {}).get("identity")
    if accept_presented_type and isinstance(identity, dict):
        inp.setdefault("self_accepted_identity_types", [identity.get("type")])


def issuer_resolver(keys: dict[str, Any]) -> dict[str, str]:
    """``resolved_issuer_keys`` for a handshake: each pinned test issuer's
    public key, and nothing for any other issuer."""
    return {issuer: b64url_encode(keys[key_id].raw_public()) for issuer, key_id in OIDC_ISSUER_KEY_IDS.items()}


def pop_required(inp: dict[str, Any], claims: dict[str, Any]) -> bool:
    """PoP is required for an invocation when the posture is enforce-for-all,
    when the grant is marked (RFC-AITP-0005 §6.2), or when the TCT comes back
    to its own issuer, which has no other source for the presenter (§10.5)."""
    policy = inp.get("issuer_policy", {})
    if policy.get("pop_posture") == "enforce-for-all" or inp.get("self_aid") == claims.get("iss"):
        return True
    return bool(set(policy.get("pop_required_grants", [])) & set(claims.get("grants", [])))


def run_operation(
    op: str, inp: dict[str, Any], keys: dict[str, Any], *, accept_presented_type: bool
) -> tuple[str | None, dict[str, Any]]:
    """Run one minted fixture input through *op* under the conventions.

    Returns ``(None, result)`` on success or ``(code, {"message": ...})`` on an
    AITP error.
    Raises :class:`FixtureError` for a self-contradicting fixture; any other
    exception is the verifier's own and propagates.
    """
    if op == "verify_delegation_token":
        inp = cover_unsupplied_issuers(inp, keys)
    inp = revocation_conventions(op, inp)
    if op == "verify_handshake_payload":
        receiver_policy(inp, accept_presented_type=accept_presented_type)
        inp.setdefault("resolved_issuer_keys", issuer_resolver(keys))
    # A fixture's `now` is the verifier's clock (PLACEHOLDERS.md, "Reference
    # clock"); otherwise the pinned reference clock.
    now = int(inp.get("now", REFERENCE_CLOCK))
    try:
        return None, OPERATIONS[op](inp, now)
    except AitpError as exc:
        return exc.code, {"message": exc.message}
