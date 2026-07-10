"""Typed error vocabulary for the AITP verification core.

Every verification failure raises :class:`AitpError` carrying a wire error
code from the AITP error-code registry (RFC-AITP-0001 §5.7 envelope codes plus
the per-RFC codes in ``registries/error-codes.md``). The conformance runner
maps a raised code to a fixture's ``expected.error_code``; a clean return maps
to ``expected.outcome == "success"``.

Codes are plain strings rather than a closed enum so a fixture referencing a
code this implementation has not yet special-cased still round-trips through
the runner as an exact-match comparison.
"""

from __future__ import annotations

__all__ = ["AitpError"]


class AitpError(Exception):
    """A verification failure carrying an AITP wire error code.

    ``code`` is the UPPER_SNAKE registry string (e.g. ``INVALID_SIGNATURE``,
    ``TOKEN_TYP_MISMATCH``). ``retryable`` mirrors the §5.7 registry column;
    it is informational and never used in the pass/fail comparison.
    """

    def __init__(self, code: str, message: str = "", *, retryable: bool = False) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.message = message
        self.retryable = retryable
