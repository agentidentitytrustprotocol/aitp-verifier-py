# Handoff: PyPI trusted publisher for `aitp-verifier`

**Who:** the owner of the PyPI (and TestPyPI) account that will own the project. No
session can do this, because it needs that account's logged-in session and 2FA.
**Why:** [`release.yml`](../../.github/workflows/release.yml) publishes with OIDC trusted
publishing, so no API token exists to leak or rotate. PyPI only accepts the upload once a
publisher matching the workflow is registered.

The GitHub side is already in place: the `pypi` and `testpypi` environments exist on the
repository, and `pypi` deploys only from `v*` tags.

## 1. Register the pending publishers

Do this on both indexes with the same values. The only difference is the environment
name.

| Field | TestPyPI ([test.pypi.org](https://test.pypi.org/manage/account/publishing/)) | PyPI ([pypi.org](https://pypi.org/manage/account/publishing/)) |
|---|---|---|
| PyPI Project Name | `aitp-verifier` | `aitp-verifier` |
| Owner | `agentidentitytrustprotocol` | `agentidentitytrustprotocol` |
| Repository name | `aitp-verifier-py` | `aitp-verifier-py` |
| Workflow name | `release.yml` | `release.yml` |
| Environment name | `testpypi` | `pypi` |

Use "Add a new pending publisher" on the account's Publishing page, under the GitHub tab.
A pending publisher does not reserve the name. The first successful upload creates the
project, so do the dry run promptly.

## 2. Dry run: TestPyPI

1. Actions → Release → Run workflow on `main`. Only `workflow_dispatch` publishes to
   TestPyPI.
2. The `build` job builds the distributions, checks them with `twine check --strict`, and
   smoke-tests the wheel. The `testpypi` job then uploads.
3. Verify from a clean venv:
   ```
   python -m venv /tmp/v && /tmp/v/bin/pip install -i https://test.pypi.org/simple/ \
     --extra-index-url https://pypi.org/simple/ aitp-verifier
   echo '{"id":"req-1","op":"init","params":{"version":"1"}}' | /tmp/v/bin/python -m aitp_verifier.adapter
   ```
   The reply is one line with `"ok":true` and `"implementation":"aitp-verifier-py"`.

A TestPyPI version can be uploaded only once. To dry-run again, bump `version` in
`pyproject.toml` first.

## 3. Release: PyPI

1. Make sure `pyproject.toml` `version` is the version to publish, for example `0.1.0`,
   and that `CHANGELOG.md` has its section.
2. `git tag v0.1.0 && git push origin v0.1.0`. The `build` job fails closed if the tag is
   not `v` plus the pyproject version.
3. Verify with `pip install aitp-verifier` and the same `init` check as above.

## Rollback

- **A bad release:** yank it on PyPI (project → Manage → Releases → the version → Yank).
  A yank keeps the file for pinned installs but takes it out of resolution. Then fix it and
  release the next patch version. The same file name can never be uploaded again.
- **A wrong or unwanted publisher:** delete it on the account's (or project's) Publishing
  page. Deleting the `pypi` GitHub environment also stops any upload, because the
  publisher is bound to that environment name.
