"""Direct tests for the low-level parsers' accept and reject branches.

``parse_aid``, ``b64url_decode`` and ``trust_store_entry`` sit under every
verifier, but the KAT tests only feed them valid inputs. These cover each
branch without the spec checkout, so they also run under ``AITP_SPEC=none``.
"""

from __future__ import annotations

from typing import Any

import pytest

from aitp_verifier.aid import parse_aid
from aitp_verifier.b64 import b64url_decode, b64url_encode
from aitp_verifier.crypto import ALG_ED25519, ALG_P256
from aitp_verifier.identity import trust_store_entry

# Known-answer AIDs from the spec's keypairs.json.
ED25519_ID = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
P256_ID = "AweBDql0zqV3PmO4l_N-O-mgnnpf6blxpE0QZawqOpMR"
ED25519_AID = f"aid:pubkey:{ED25519_ID}"
P256_AID = f"aid:pubkey:p256:{P256_ID}"


# --- parse_aid -------------------------------------------------------------


@pytest.mark.parametrize(
    ("aid", "alg", "ident", "jose_alg"),
    [
        (ED25519_AID, ALG_ED25519, ED25519_ID, "EdDSA"),  # legacy untagged form
        (f"aid:pubkey:ed25519:{ED25519_ID}", ALG_ED25519, ED25519_ID, "EdDSA"),
        (P256_AID, ALG_P256, P256_ID, "ES256"),
    ],
)
def test_parse_aid_accepts(aid: str, alg: str, ident: str, jose_alg: str) -> None:
    parsed = parse_aid(aid)
    assert parsed.aid == aid
    assert parsed.alg == alg
    assert parsed.raw_key == b64url_decode(ident)
    assert parsed.jose_alg == jose_alg


@pytest.mark.parametrize(
    ("aid", "match"),
    [
        (f"aid:web:{ED25519_ID}", "unsupported AID method"),
        (f"did:key:{ED25519_ID}", "unsupported AID method"),
        ("", "unsupported AID method"),
        # Wrong length for the algorithm: an Ed25519 identifier is 43 chars, P-256 is 44.
        (f"aid:pubkey:{P256_ID}", "must be 43 chars, got 44"),
        (f"aid:pubkey:ed25519:{P256_ID}", "must be 43 chars, got 44"),
        (f"aid:pubkey:ed25519:{ED25519_ID[:-1]}", "must be 43 chars, got 42"),
        (f"aid:pubkey:p256:{ED25519_ID}", "must be 44 chars, got 43"),
        (f"aid:pubkey:p256:{P256_ID}A", "must be 44 chars, got 45"),
        # An unregistered tag falls through to the legacy form and fails its length check.
        (f"aid:pubkey:rsa:{ED25519_ID}", "must be 43 chars, got 47"),
    ],
)
def test_parse_aid_rejects(aid: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        parse_aid(aid)


# --- b64url_decode ---------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "AA==",  # padding
        "AAA=",
        "AA+A",  # standard-alphabet characters
        "AA/A",
        "AA A",  # whitespace
        "AA.A",
        "Zé",  # non-ASCII
    ],
)
def test_b64url_decode_rejects(text: str) -> None:
    with pytest.raises(ValueError, match="non-base64url"):
        b64url_decode(text)


@pytest.mark.parametrize(
    ("text", "data"),
    [
        ("", b""),
        ("AA", b"\x00"),  # unpadded, 2 of 4 chars
        ("AAA", b"\x00\x00"),  # unpadded, 3 of 4 chars
        ("AAAA", b"\x00\x00\x00"),
        ("-_8", b"\xfb\xff"),  # url-safe alphabet characters
    ],
)
def test_b64url_decode_accepts_unpadded(text: str, data: bytes) -> None:
    assert b64url_decode(text) == data


@pytest.mark.parametrize("length", range(6))
def test_b64url_round_trip(length: int) -> None:
    data = bytes(range(250, 250 + length))
    encoded = b64url_encode(data)
    assert "=" not in encoded
    assert b64url_decode(encoded) == data


# --- trust_store_entry -----------------------------------------------------


@pytest.mark.parametrize("entry", [None, 42, b"aid:pubkey:x", [ED25519_AID], {"aid": ED25519_AID}])
def test_trust_store_entry_non_str(entry: Any) -> None:
    assert trust_store_entry(entry) is None


@pytest.mark.parametrize(
    ("entry", "alg", "ident"),
    [
        (ED25519_AID, ALG_ED25519, ED25519_ID),  # full AID
        (f"aid:pubkey:ed25519:{ED25519_ID}", ALG_ED25519, ED25519_ID),
        (P256_AID, ALG_P256, P256_ID),
        (ED25519_ID, ALG_ED25519, ED25519_ID),  # bare 43 chars → ed25519
        (P256_ID, ALG_P256, P256_ID),  # bare 44 chars → p256
    ],
)
def test_trust_store_entry_accepts(entry: str, alg: str, ident: str) -> None:
    assert trust_store_entry(entry) == (alg, b64url_decode(ident))


@pytest.mark.parametrize(
    "entry",
    [
        "",
        "not-an-aid",
        f"aid:web:{ED25519_ID}",  # unsupported method
        f"aid:pubkey:p256:{ED25519_ID}",  # wrong length for the tag
        ED25519_ID[:-1],  # bare, 42 chars
        P256_ID + "A",  # bare, 45 chars
        "A" * 42 + "=",  # bare, 43 chars but padded
    ],
)
def test_trust_store_entry_unparseable(entry: str) -> None:
    assert trust_store_entry(entry) is None
