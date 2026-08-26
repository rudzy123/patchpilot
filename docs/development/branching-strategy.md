# Branching strategy

PatchPilot uses **short-lived feature branches** and pull requests into `main`.

## Default branch

- `main` is the integration branch. It should stay releasable according to [release principles](release-principles.md), even before the first tagged release.
- Do not commit directly to `main` once branch protection is available. Until protection exists, still use pull requests.

## Branch naming

Create branches from an up-to-date `main`:

| Prefix | Use |
| --- | --- |
| `feat/` | New user-facing or domain capability |
| `fix/` | Defect fix |
| `docs/` | Documentation only |
| `chore/` | Tooling, constitution, non-user-facing maintenance |
| `test/` | Test-only changes |
| `refactor/` | Behavior-preserving restructure |
| `ci/` | GitHub Actions and pipeline |
| `security/` | Security fix (still avoid public exploit detail) |

Examples: `feat/sbom-upload`, `fix/org-scope-findings`, `docs/mvp-scope`.

Keep branches short-lived (days, not months). Merge or close them. Do not maintain long-lived team branches that diverge from `main`.

## Updates from main

Prefer rebase only on **unshared** branches. If others use the branch, merge `main` into the feature branch instead. Do not force-push `main`. Do not use interactive rebase in agent-driven workflows that cannot confirm the todo list.

## Pull requests

Every change lands through a pull request.

### Required checks

When GitHub Actions is configured, these checks are **required** to merge:

- Lint (including Markdown/link checks if configured)
- TypeScript (`strict` pipeline)
- Unit and integration tests (Vitest)
- Playwright for changes that affect `apps/web` user-visible behavior (may be `paths`-filtered but must not be skippable without a documented reason)
- Secret scanning / dependency review when those workflows exist
- Build of the touched applications

Until CI exists, authors must run the equivalent local commands and report actual results in the pull request. Do not claim checks passed if they were not run.

Human review must complete the [review checklist](review-checklist.md). Architecture changes need an [ADR](../adr/README.md) in the same or a preceding pull request.

### Permissions

- Deny merge with failing required checks.
- Do not skip hooks (`--no-verify`) unless a maintainer explicitly requests it for a documented emergency.
- Security disclosures follow [SECURITY.md](../../SECURITY.md), not a public `security/` branch with exploit code.
