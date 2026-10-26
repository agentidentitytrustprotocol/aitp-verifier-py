"""The KAT keys shipped in the package (aitp_verifier/kat/) are the spec's."""

from __future__ import annotations

from pathlib import Path

import pytest

from aitp_verifier.keys import KAT_FILES, load_kat_keys, load_packaged_kat_keys

PACKAGED = Path(__file__).resolve().parent.parent / "aitp_verifier" / "kat"


@pytest.mark.parametrize("name", KAT_FILES)
def test_packaged_kat_file_is_byte_equal_to_the_pinned_spec(spec_dir: Path, name: str) -> None:
    """A spec-pin bump that changes a KAT file fails here until the copy is refreshed."""
    spec_copy = spec_dir / "schemas/conformance/known-answer" / name
    assert (PACKAGED / name).read_bytes() == spec_copy.read_bytes(), f"refresh aitp_verifier/kat/{name} from the spec"


def test_packaged_keys_equal_the_spec_keys(spec_dir: Path) -> None:
    packaged, spec = load_packaged_kat_keys(), load_kat_keys(spec_dir)
    assert packaged.keys() == spec.keys()
    assert all(packaged[k].raw_public() == spec[k].raw_public() for k in spec)
