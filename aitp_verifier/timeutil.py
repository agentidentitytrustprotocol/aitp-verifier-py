"""Time helpers for AITP verification.

AITP timestamps are Unix seconds (integers). The conformance fixtures pin a
reference clock so a re-mint is byte-stable; a runner passes that clock in as
``now`` rather than reading the wall clock.
"""

from __future__ import annotations

__all__ = ["REFERENCE_CLOCK"]

# The pinned conformance reference clock for `__NOW__` (RFC-AITP schemas/
# conformance/README.md and PLACEHOLDERS.md). Runners anchor time-sensitive
# checks to this value so signed bytes are reproducible across implementations.
REFERENCE_CLOCK = 1711900000
