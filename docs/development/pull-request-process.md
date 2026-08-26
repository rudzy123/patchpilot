# Pull request process

Every change lands through a pull request into `main`. Direct pushes to `main` should be blocked once [branch protection](branch-protection.md) is applied.

## Before you open

1. Branch from an up-to-date `main` using a short-lived prefix (`feat/`, `fix/`, `docs/`, `chore/`, `test/`, `refactor/`, `ci/`, `security/`).
2. Keep the change focused. Do not mix product work with unrelated formatting.
3. Use [Conventional Commits](commit-guidelines.md).
4. Complete the [review checklist](review-checklist.md) for the kind of change you made.

## Template

[`.github/pull_request_template.md`](../../.github/pull_request_template.md) asks for summary, motivation, scope, and impact sections. Use **Not applicable:** plus a short reason for sections that do not apply. A documentation-only pull request should not invent architecture or tenancy impact.

## Checks

GitHub Actions must pass the required checks listed in [ci.md](ci.md) and [branch-protection.md](branch-protection.md). Until a given run has finished, report local command results honestly.

Do not skip hooks unless a maintainer explicitly requests it for a documented emergency.

## Security

Do not discuss unfixed vulnerabilities, exploit steps, or customer SBOMs in a public pull request. Use [SECURITY.md](../../SECURITY.md).

## Review and merge

During the single-maintainer phase, `@rudzy123` may merge after required checks pass. CODEOWNERS documents intended paths but must not be configured as a blocking code-owner review until another maintainer can approve. Prefer squash or rebase according to [repository settings](repository-settings.md) once those settings are applied.
