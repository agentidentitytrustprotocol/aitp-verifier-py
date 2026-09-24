# Changelog

This project has not yet had a tagged release (still `0.1.0` / Alpha, unpublished). This
file starts tracking security-relevant and other breaking verifier-behavior changes from
here, so a future integrator has one place to check before upgrading.

## Unreleased

### Security-relevant

- **`verify_tct` / `verify_delegation_token` now hard-reject a malformed embedded
  revocation snapshot** instead of silently treating it as "nothing revoked." Previously,
  if a revocation record's `snapshot` sub-field was absent, `None`, non-dict, or missing
  `revocation_list`/`entries`, the verifier fell through `.get()` chains with safe
  defaults to an empty revoked-jti set — meaning malformed or stripped revocation data
  produced a silent pass rather than a surfaced defect. Both entry points now call
  `revocation.py::verify_snapshot_trust`, which raises `AitpError` with
  `REVOCATION_SNAPSHOT_INVALID` or `UNKNOWN_FIELD` in these cases. Fail-closed is the
  correct default for a revocation check: an unparseable snapshot is
  *obtained-but-untrustworthy*, not "no revocations reported." Any caller whose input
  happened to include malformed embedded revocation data will now see `AitpError` where
  it previously saw a successful verification. (issue #24)
- **`verify_delegation_token`'s multi-hop path now also rejects a falsy-but-malformed
  top-level `revocation_snapshots` field** (`""`, `0`, `False`, `{}`, `0.0`) with
  `REVOCATION_SNAPSHOT_INVALID`, closing a residual gap in the fix above: an `or []`
  ordering bug let these specific falsy values bypass the type check and silently fold
  into "no snapshots," the same fail-open outcome the fix above closes for the snapshot
  sub-field. A genuinely absent field (`None`) is unaffected and still verifies
  successfully with no revocations applied.
