# Continuous integration

This document describes the seven GitHub Actions workflows added in Session 4. It is process documentation, not a claim that PatchPilot is production-ready, certified, or comprehensively assured.

Local commands remain authoritative when GitHub-hosted checks have not run yet. After a pull request is opened, confirm the check names GitHub actually emits before applying branch protection.

## Workflow inventory

| Workflow file | Name | Purpose |
| --- | --- | --- |
| `.github/workflows/ci.yml` | CI | Two jobs: workflow/governance lint, then quality gates |
| `.github/workflows/integration.yml` | Integration | PostgreSQL, Redis, MinIO, SchemaFoundation migrate deploy, `pnpm test:integration` |
| `.github/workflows/codeql.yml` | CodeQL | JavaScript/TypeScript analysis (`build-mode: none`) |
| `.github/workflows/dependency-review.yml` | Dependency review | Pull-request dependency and license change review |
| `.github/workflows/scorecard.yml` | Scorecard | OpenSSF Scorecard on `main` and a weekly schedule |
| `.github/workflows/sbom.yml` | SBOM | Supply-chain CycloneDX SBOM for this repository |
| `.github/workflows/release-dry-run.yml` | Release dry run | Manual quality verification without publishing |

There is no GitHub-hosted E2E workflow and no container-build workflow in this session. Those checks are deferred (see [Deferred CI work](#deferred-ci-work)).

Workflows are split so permissions, failure diagnosis, and required checks stay narrow. Shared Node.js/pnpm setup lives in [`.github/actions/setup-node-pnpm`](../../.github/actions/setup-node-pnpm/action.yml).

## Triggers

| Workflow | `pull_request` | `push` to `main` | Schedule | `workflow_dispatch` |
| --- | --- | --- | --- | --- |
| CI | yes | yes | no | no |
| Integration | yes | yes | no | no |
| CodeQL | yes | yes | weekly Monday | no |
| Dependency review | yes | no | no | no |
| Scorecard | no | yes | weekly Monday | no |
| SBOM | no | yes | weekly Monday | yes |
| Release dry run | no | no | no | yes |

Pull-request workflows use `pull_request`, not `pull_request_target`. They do not receive repository secrets. There are no path filters on pull-request jobs, so documentation-only pull requests still run CI, Integration, CodeQL, and Dependency review.

## Permissions

Every workflow sets `permissions.contents: read` at the workflow level. Additional permissions are job-scoped:

| Workflow | Extra job permissions |
| --- | --- |
| CI, Integration, SBOM, Release dry run, Dependency review | none |
| CodeQL | `security-events: write`, `actions: read` |
| Scorecard | `security-events: write`, `actions: read` |

No workflow uses `id-token: write`. Scorecard sets `publish_results: false`, so OpenSSF OIDC publication is disabled and no OIDC permission is required. There is no `contents: write`, `packages: write`, `packages: read`, `deployments: write`, or `pull-requests: write`.

`packages: read` is omitted from CodeQL because this repository uses `build-mode: none` and the default queries bundled with `github/codeql-action`. GitHub's starter workflow grants `packages: read` only to fetch internal or private CodeQL packs, which this configuration does not use.

## Intended pull-request required checks

These are the **intended** GitHub check names from workflow `name:` plus job `name:`. Record the names GitHub actually shows after the first hosted runs. Do not guess a different pattern.

- `CI / Workflows`
- `CI / Quality`
- `Integration / Integration`
- `CodeQL / Analyze`
- `Dependency review / Dependency review`

Do **not** require on pull requests:

- Scorecard (runs on `main`, schedule, and `branch_protection_rule` only)
- SBOM (runs on `main`, schedule, and `workflow_dispatch` only)
- Release dry run (manual `workflow_dispatch` only)
- E2E (no workflow in this session)
- Container build (no workflow in this session)

## CI / Workflows

The `Workflows` job does not install application dependencies. It runs `pnpm workflows:lint`, which:

- Confirms required GitHub governance files exist (`CODEOWNERS`, Dependabot, PR and issue templates, the local setup action, CodeQL config)
- Rejects a public vulnerability issue template
- Rejects Dependabot auto-merge configuration
- Rejects placeholder `.github/workflows/e2e.yml` and `.github/workflows/container-build.yml`
- Downloads pinned `actionlint` 1.7.12, verifies the archive SHA-256, and lints workflow YAML

## CI / Quality

The `Quality` job uses Node.js from `.nvmrc` (24), Corepack, `packageManager` pnpm `11.24.0`, and `pnpm install --frozen-lockfile`. setup-node caches the pnpm store through `package-manager-cache` (not `node_modules`, not `.env` files). Turborepo remote cache is not enabled and must not be enabled with repository secrets for forked pull requests.

The job runs `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm test:unit`, `pnpm db:validate`, `pnpm db:generate`, and `pnpm build`. Failures are not masked with `continue-on-error` or `|| true`.

It does **not** run `pnpm test:e2e`. That command is a local placeholder only (see [End-to-end testing](#end-to-end-testing)).

## Integration testing

Service containers match the Session 3 Compose **image tags** and the hardcoded URLs in `createFoundationTestEnv()`:

- PostgreSQL `postgres:16-alpine` on host port `55432`
- Redis `redis:7-alpine` on host port `16379`
- MinIO `minio/minio:RELEASE.2025-09-07T16-13-09Z` on `127.0.0.1:19000`

CI additionally pins those tags to Docker Hub **index digests** resolved on 2026-08-26 so GitHub-hosted jobs do not follow a rebuilt floating tag. `latest` is not used. Local Compose keeps the same version tags without digest pins so developer machines stay aligned with Session 3.

PostgreSQL and Redis use GitHub Actions service containers with health checks. GitHub waits on those health checks before the job starts; an unhealthy service fails the job. MinIO cannot use a service container: the service-container schema does not support `command`, and this MinIO image requires `minio server /data`. CI therefore starts MinIO with `docker run`, publishes only `127.0.0.1:19000:9000` (loopback, no console port), and waits on `GET /minio/health/live` for at most 60 seconds (one-second poll, not an unbounded sleep). Container logs are not dumped on failure because MinIO may print root credentials. The job fails if MinIO never becomes healthy. A job `if: always()` step removes the container when it exists.

On GitHub-hosted `ubuntu-latest`, the job process and `docker run` share the runner VM, so `127.0.0.1` reaches published service-container ports and the MinIO publish. That is different from Compose on a laptop only in how MinIO is started (`docker run` vs Compose `command`); the test URLs stay the same.

Credentials are the documented development placeholders. They are job-scoped environment values, not production secrets and not GitHub repository secrets.

Prisma Client is generated, then `pnpm db:migrate:deploy` applies the existing Session 3 `SchemaFoundation` migration to an empty CI database. That is appropriate: CI must apply committed migrations non-interactively. It is not a production product-schema migration. Tests still run through `pnpm test:integration`. There are no live OSV/KEV calls.

## End-to-end testing

Playwright is **not** a repository dependency. `pnpm test:e2e` currently prints that browser journeys are not wired and exits 0. It is kept as a documented local command interface only. GitHub Actions does **not** run it. Do not describe that placeholder as end-to-end validation.

Landing copy and `/health` remain unit-tested. GitHub-hosted E2E coverage is deferred until actual Playwright tests exist ([CI-DEFER-1](#deferred-ci-work)).

## CodeQL

`build-mode: none` is used for this JavaScript/TypeScript monorepo so CodeQL does not require a second production build. Generated and dependency directories are excluded in `.github/codeql/codeql-config.yml`. Tests are not excluded. Maintainers inspect results in the repository **Security → Code scanning** view. False positives are handled per [code-scanning-finding.md](../runbooks/code-scanning-finding.md); they are not auto-dismissed.

## Dependency review

The workflow runs on every pull request (not only lockfile paths) so manifest edits cannot skip the check. Permissions are `contents: read` only. It fails on **high** or **critical** severity. License changes are reported (`license-check: true`) as review signals, not automated legal conclusions. There is no allow/deny license list in this session; Apache-2.0 is the project license, and licensing decisions that need interpretation require qualified review. The action does not rewrite `pnpm-lock.yaml` and does not comment on the pull request.

## OpenSSF Scorecard

Scorecard runs on `main`, a weekly schedule, and `branch_protection_rule`. It does not execute untrusted pull-request code. Results are uploaded as SARIF to GitHub code scanning. A short-lived Actions artifact (5 days, unique name) is retained so maintainers can inspect the same SARIF if code scanning is not yet enabled in repository settings. The SARIF contains Scorecard check results, not secrets, tokens, or SBOM bodies.

`publish_results` is **false**. Scorecard results are not published to the OpenSSF API. No OIDC (`id-token: write`) permission is granted.

A Scorecard score is **not** certification or comprehensive security assurance.

## Container validation

There are no production runtime Dockerfiles. There is no container-build workflow and no fake container-build job in CI. Do not add placeholder Dockerfiles only to satisfy a status check. Real container validation is deferred to the production containerization milestone ([CI-DEFER-2](#deferred-ci-work)).

## Supply-chain SBOM

The SBOM workflow generates a CycloneDX JSON document for **this repository** using Syft via `anchore/sbom-action`. It is supply-chain reporting for PatchPilot itself, not customer-SBOM ingestion and must not be fed into PatchPilot product functionality ([ADR 0009](../adr/0009-cyclonedx-json.md) is about uploaded operator SBOMs). Triggers are `push` to `main`, weekly schedule, and `workflow_dispatch`. It does not run on pull requests. It uses no secrets, does not attach a release, and does not sign or attest the file. The artifact uses a unique name and 7-day retention. It must not contain customer or uploaded SBOM content.

### Local generation

`anchore/sbom-action` v0.24.0 bundles Syft 1.42.3. If you have that Syft version locally:

```bash
syft dir:. -o cyclonedx-json=patchpilot-sbom.cdx.json
```

Inspect the file for secrets before sharing it. Do not commit generated SBOMs.

## Release dry run

`Release dry run` is manual (`workflow_dispatch`). It may duplicate CI / Quality intentionally. It re-runs frozen install, format, lint, typecheck, unit tests, Prisma validate/generate, and production build, then writes a GitHub step summary. It uses `contents: read` and no secrets. It must not publish packages, create GitHub Releases, log in to a registry, deploy, or run production migrations.

## Workflow linting

`pnpm workflows:lint` downloads pinned `actionlint` 1.7.12, verifies the archive SHA-256, checks governance files, and lints `.github/workflows`. GitHub-hosted `ubuntu-latest` also has shellcheck, which actionlint uses when present. The binary is cached under `.cache/actionlint/` (gitignored).

## Action pinning

Third-party actions are pinned to full commit SHAs with a trailing version comment. SHAs were resolved from official GitHub repositories on 2026-08-26: tag objects were fetched, and annotated tags were dereferenced to the tagged commit. Do not pin `main`, `master`, `latest`, or a mutable major-only tag (`v4`).

| Action | Release tag | Commit SHA |
| --- | --- | --- |
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-node` | v7.0.0 | `820762786026740c76f36085b0efc47a31fe5020` |
| `actions/upload-artifact` | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| `github/codeql-action` | v4.37.7 | `ff2f1c621b7f889edc0d3c761ac2e6a3f8cdb0dd` |
| `actions/dependency-review-action` | v5.0.0 | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` |
| `ossf/scorecard-action` | v2.4.4 | `2d1146689b8cda280b9bc96326124645441f03bc` |
| `anchore/sbom-action` | v0.24.0 | `e22c389904149dbc22b58101806040fa8d37a610` |

### How maintainers update a pin

1. Prefer the Dependabot `github-actions` group pull request.
2. Confirm the new SHA from the official action repository: fetch the release tag, and if the tag object is annotated, use the tagged **commit** SHA, not the tag-object SHA.
3. Update every `uses:` line that should move together (for example all `github/codeql-action/*` lines) and the trailing version comment.
4. Re-run `pnpm workflows:lint`.
5. Do not accept `main`, `master`, `latest`, or major-only refs.

## Turborepo

`turbo.json` does not enable remote caching. Task outputs do not include `.env` files. `test:integration` and `test:e2e` have `cache: false`. `test:unit` does not cache coverage. Shared lockfile and config files are `globalDependencies` so lockfile and toolchain edits invalidate tasks.

## Deferred CI work

These items are tracked so they are not forgotten and so they are **not** treated as present required checks.

### CI-DEFER-1 — GitHub-hosted Playwright E2E

Introduce a real E2E workflow only after Playwright tests exist in the repository. Until then, do not create or advertise an E2E / End-to-end required check, and do not upload Playwright artifacts.

When that workflow is added it must:

- Use health-based application startup (not unbounded `sleep`)
- Use bounded timeouts
- Upload privacy-reviewed traces, screenshots, or video **on failure only**
- Clean up started processes safely
- Bind services to loopback where applicable
- Avoid capturing cookies, tokens, signed URLs, or SBOM bodies
- Remove `.github/workflows/e2e.yml` from the forbidden list in `scripts/lint-workflows.mjs`

### CI-DEFER-2 — Container-build workflow

Introduce a real container-build workflow only when reviewed runtime Dockerfiles exist for web, API, and worker. Until then, do not create `.github/workflows/container-build.yml`, do not fold a fake container-build job into CI, and do not add placeholder Dockerfiles.

When that workflow is added it must build with BuildKit (or the repository-approved equivalent), must not push images, must not log registry credentials, must fail on Dockerfiles that are not the reviewed production files, and must remove `.github/workflows/container-build.yml` from the forbidden list in `scripts/lint-workflows.mjs`.

## Related documents

- [CI security](../security/ci-security.md)
- [Artifact retention](artifact-retention.md)
- [Branch protection](branch-protection.md)
- [Repository settings](repository-settings.md)
- [CI failure runbook](../runbooks/ci-failure.md)
