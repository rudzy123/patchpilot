# Continuous integration

This document describes the GitHub Actions workflows added in Session 4. It is process documentation, not a claim that PatchPilot is production-ready or certified.

Local commands remain authoritative when GitHub-hosted checks have not run yet. After a pull request is opened, the workflow names below are the status checks.

## Workflow inventory

| Workflow file | Name | Purpose |
| --- | --- | --- |
| `.github/workflows/ci.yml` | CI | Frozen install, workflow lint, format, lint, typecheck, unit tests, Prisma validate/generate, production build |
| `.github/workflows/integration.yml` | Integration | PostgreSQL, Redis, and MinIO service containers plus `pnpm test:integration` |
| `.github/workflows/e2e.yml` | E2E | Runs the repository `pnpm test:e2e` command |
| `.github/workflows/codeql.yml` | CodeQL | JavaScript/TypeScript analysis |
| `.github/workflows/dependency-review.yml` | Dependency review | Pull-request dependency and license change review |
| `.github/workflows/scorecard.yml` | Scorecard | OpenSSF Scorecard on `main` and a weekly schedule |
| `.github/workflows/container-build.yml` | Container build | Deferred guard until runtime Dockerfiles exist |
| `.github/workflows/sbom.yml` | SBOM | Supply-chain CycloneDX SBOM for this repository |
| `.github/workflows/release-dry-run.yml` | Release dry run | Manual verification without publishing |

Workflows are split so permissions, failure diagnosis, and required checks stay narrow. Shared Node.js/pnpm setup lives in [`.github/actions/setup-node-pnpm`](../../.github/actions/setup-node-pnpm/action.yml).

## Triggers

| Workflow | `pull_request` | `push` to `main` | Schedule | `workflow_dispatch` |
| --- | --- | --- | --- | --- |
| CI | yes | yes | no | no |
| Integration | yes | yes | no | no |
| E2E | yes | yes | no | no |
| CodeQL | yes | yes | weekly Monday | no |
| Dependency review | yes | no | no | no |
| Scorecard | no | yes | weekly Monday | no |
| Container build | yes | yes | no | no |
| SBOM | no | yes | weekly Monday | yes |
| Release dry run | no | no | no | yes |

Pull-request workflows use `pull_request`, not `pull_request_target`. They do not receive repository secrets. There are no path filters on required checks, so documentation-only pull requests still run the same quality, integration, and E2E jobs.

## Permissions

Every workflow sets `permissions.contents: read` at the workflow level. Additional permissions are job-scoped:

| Workflow | Extra job permissions |
| --- | --- |
| CI, Integration, E2E, Container build, SBOM, Release dry run, Dependency review | none |
| CodeQL | `security-events: write`, `actions: read`, `packages: read` |
| Scorecard | `security-events: write`, `actions: read`, `id-token: write` |

`id-token: write` on Scorecard is the documented OpenSSF OIDC publish path for public repositories (`publish_results` is false for private repositories). There is no `contents: write`, `packages: write`, `deployments: write`, or `pull-requests: write`.

## Required status-check names

After these workflows exist, the exact GitHub check names are:

- `CI / Quality`
- `CI / Workflows`
- `Integration / Integration`
- `E2E / End-to-end`
- `CodeQL / Analyze`
- `Dependency review / Dependency review`
- `Container build / Deferred`

Do not require Scorecard, SBOM, or Release dry run on pull requests. Those jobs do not run on `pull_request`.

## Pull-request CI

The `Quality` job uses Node.js from `.nvmrc` (24), Corepack, `packageManager` pnpm `11.24.0`, and `pnpm install --frozen-lockfile`. setup-node caches the pnpm store through `package-manager-cache` (not `node_modules`). Turborepo remote cache is not enabled and must not be enabled with repository secrets for forked pull requests.

The job runs `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm test:unit`, `pnpm db:validate`, `pnpm db:generate`, and `pnpm build`. Failures are not masked with `continue-on-error` or `|| true`.

## Integration testing

Service containers match the Session 3 Compose images and the hardcoded URLs in `createFoundationTestEnv()`:

- PostgreSQL `postgres:16-alpine` on host port `55432`
- Redis `redis:7-alpine` on host port `16379`

PostgreSQL and Redis use GitHub Actions service containers with health checks. MinIO cannot: the service-container schema does not support `command`, and the pinned MinIO image requires `minio server /data`. CI therefore starts MinIO with `docker run` on `127.0.0.1:19000` and waits on `GET /minio/health/live` for at most 60 seconds (one-second poll, not an unbounded sleep). Container logs are not dumped on failure because MinIO may print root credentials. The job fails if MinIO never becomes healthy.

Credentials are the documented development placeholders. They are job-scoped environment values, not production secrets and not GitHub repository secrets. GitHub waits on PostgreSQL and Redis health checks before the job starts; an unhealthy service fails the job.

Prisma Client is generated, then `pnpm db:migrate:deploy` applies the Session 3 `SchemaFoundation` migration. Tests still run through `pnpm test:integration`. There are no live OSV/KEV calls.

Compose is not used in GitHub Actions for PostgreSQL and Redis because service containers can publish the same host ports the tests already expect.

## End-to-end testing

Playwright is **not** a repository dependency. `pnpm test:e2e` currently prints that browser journeys are not wired and exits 0. The E2E workflow still runs that command on every pull request so the check name is stable. Do not treat a green `E2E / End-to-end` result as a Playwright pass. Landing copy and `/health` remain unit-tested.

When Playwright is added, install only the browsers the suite needs, bind applications to `127.0.0.1`, wait on health rather than sleep, and retain traces only on failure. Do not start PostgreSQL, Redis, MinIO, API, or worker unless a test actually requires them.

## CodeQL

`build-mode: none` is used for this JavaScript/TypeScript monorepo so CodeQL does not require a second production build. Generated and dependency directories are excluded in `.github/codeql/codeql-config.yml`. Tests are not excluded. Maintainers inspect results in the repository **Security → Code scanning** view. False positives are handled per [code-scanning-finding.md](../runbooks/code-scanning-finding.md); they are not auto-dismissed.

## Dependency review

The workflow runs on every pull request (not only lockfile paths) so manifest edits cannot skip the check. It fails on **high** or **critical** severity. License changes are reported (`license-check: true`). There is no allow/deny license list in this session; Apache-2.0 is the project license, and licensing decisions that need interpretation require qualified review. The action does not rewrite `pnpm-lock.yaml`.

## OpenSSF Scorecard

Scorecard runs on `main`, a weekly schedule, and `branch_protection_rule`. It does not execute untrusted pull-request code. Results are uploaded as SARIF to code scanning and as a short-lived artifact. A Scorecard score is **not** certification or comprehensive security assurance.

## Container validation

Session 3 has no runtime Dockerfiles. The container workflow fails if a tracked `Dockerfile` appears, so the deployment milestone must replace the deferred job with BuildKit builds that do not push. Do not add placeholder Dockerfiles only to satisfy CI.

## Supply-chain SBOM

The SBOM workflow generates a CycloneDX JSON document for **this repository** using Syft via `anchore/sbom-action`. It is not customer-SBOM ingestion and must not be fed into PatchPilot product functionality ([ADR 0009](../adr/0009-cyclonedx-json.md) is about uploaded operator SBOMs). The file is an artifact with 7-day retention. It is not a release asset and is not signed in this session.

### Local generation

`anchore/sbom-action` v0.24.0 bundles Syft 1.42.3. If you have that Syft version locally:

```bash
syft dir:. -o cyclonedx-json=patchpilot-sbom.cdx.json
```

Inspect the file for secrets before sharing it. Do not commit generated SBOMs.

## Release dry run

`Release dry run` is manual (`workflow_dispatch`). It re-runs quality gates, prints version and changelog readiness, and records a step summary. It has no publishing tokens and does not create GitHub Releases, packages, images, or production migrations.

## Workflow linting

`pnpm workflows:lint` downloads pinned `actionlint` 1.7.12, verifies the archive SHA-256, and lints `.github/workflows`. GitHub-hosted `ubuntu-latest` also has shellcheck, which actionlint uses when present. The binary is cached under `.cache/actionlint/` (gitignored).

## Action pinning

Third-party actions are pinned to full commit SHAs with a trailing version comment. SHAs were resolved from GitHub tag objects (annotated tags dereferenced to commits) on 2026-08-26. Dependabot is configured to update them.

## Turborepo

`turbo.json` does not enable remote caching. Task outputs do not include `.env` files. `test:integration` and `test:e2e` have `cache: false`. `test:unit` does not cache coverage. Shared lockfile and config files are `globalDependencies` so lockfile and toolchain edits invalidate tasks.

## Related documents

- [CI security](../security/ci-security.md)
- [Artifact retention](artifact-retention.md)
- [Branch protection](branch-protection.md)
- [Repository settings](repository-settings.md)
- [CI failure runbook](../runbooks/ci-failure.md)
