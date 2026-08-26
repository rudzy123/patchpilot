# CI security

Threats that apply to GitHub Actions for this repository, and how Session 4 workflows respond. This is not a penetration test and not a certification.

## Untrusted pull requests

- Event is `pull_request`, never `pull_request_target` for installing or executing pull-request code.
- Workflow permissions default to `contents: read`.
- `persist-credentials: false` on checkout.
- `fetch-depth: 1` unless a job needs history (none currently do).
- No repository secrets in pull-request jobs. Integration credentials are development placeholders in job `env`.
- No workflow uses `id-token: write`. Scorecard and SBOM do not run on `pull_request`.

## Script injection

Untrusted values (pull-request title, body, branch name, tag name) are not interpolated into `run:` scripts. Concurrency keys use GitHub expressions (`github.ref`, pull-request number) which are not executed as shell. Release dry-run passes `github.sha` and `github.ref_name` through environment variables into Node.

## Mutable actions

Third-party actions are pinned to 40-character commit SHAs with a version comment. `main`, `master`, and `latest` refs are not used.

## Cache poisoning

- pnpm store cache is keyed from the lockfile via setup-node `package-manager-cache`.
- `node_modules` is not cached.
- Turborepo remote cache is disabled. Do not add `TURBO_TOKEN` for forked pull requests.
- SBOM artifacts are not produced from fork pull requests.

## Artifacts

Short retention, unique names, no `.env` or data volumes. See [artifact-retention.md](../development/artifact-retention.md).

## Runners

GitHub-hosted `ubuntu-latest` only. No self-hosted runners.

## OIDC and writes

No workflow requests `id-token: write`. Scorecard sets `publish_results: false`, so OpenSSF OIDC publication is not used. There is no package or deployment write token.

## Workflow linting

`actionlint` 1.7.12 is checksum-verified on every run, including cache hits: the script verifies the archive SHA-256 after download and the extracted binary SHA-256 before execution. A cache hit that fails the binary digest is not executed. Tracked files under `.cache/actionlint` are rejected. It does not execute repository application code.

## Related

- [CI](../development/ci.md)
- [Secret scanning](secret-scanning.md)
- [CI failure runbook](../runbooks/ci-failure.md)
