# Dependency management

PatchPilot uses one pnpm lockfile for the TypeScript workspace ([ADR 0002](../adr/0002-pnpm-turborepo.md)).

## Install

```bash
corepack enable
pnpm install --frozen-lockfile
```

CI always uses `--frozen-lockfile`. Local first-time lockfile updates use `pnpm install` without freeze, then commit the lockfile in the same change that added the dependency.

## Adding a dependency

1. Explain why it is required in the pull request.
2. Prefer established libraries over custom security mechanisms.
3. Do not add product dependencies for GitHub Apps, AI providers, or vulnerability-feed clients unless a later session and ADR require them.
4. Run the quality gates and integration tests that the change can affect.

## Dependabot

[`.github/dependabot.yml`](../../.github/dependabot.yml) opens weekly grouped pull requests for:

- Compatible development tooling (ESLint, TypeScript types, Prettier, Vitest, Turbo)
- GitHub Actions, with CodeQL action pins grouped so `init` / `analyze` / `upload-sarif` move together

Production runtime libraries (Next.js, Fastify, Prisma, Pino, and similar) are **not** stuffed into one group. Security updates from GitHub remain visible as their own pull requests. Dependabot does **not** auto-merge.

Reviewers must run normal CI. See [dependency-security.md](../security/dependency-security.md) and [dependency-alert.md](../runbooks/dependency-alert.md).

Runtime images live in `deploy/docker/Dockerfile`. Dependabot's docker ecosystem is not enabled against that file or `deploy/compose/compose.yaml`. Review image digest updates manually.

## License review

The project is Apache-2.0. Dependency Review reports license changes on pull requests. That report is not a legal opinion. Allow or deny lists are not encoded as policy in this session; decisions that need interpretation should get qualified review.

## Lockfile integrity

Do not hand-edit `pnpm-lock.yaml`. Do not use a workflow to rewrite the lockfile. If a lockfile is out of date, regenerate it locally and commit the result.
