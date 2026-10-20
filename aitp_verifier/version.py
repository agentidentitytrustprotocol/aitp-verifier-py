"""The protocol revision this verifier implements.

``aitp/0.3`` is a strict cutover (spec VERSIONING.md): every artifact whose
``version``/``ver`` is any other value -- the previous ``aitp/0.2`` included --
is rejected with that artifact's unknown-version code. There is no
dual-accept window.
"""

from __future__ import annotations

__all__ = ["PROTOCOL_VERSION"]

PROTOCOL_VERSION = "aitp/0.3"
