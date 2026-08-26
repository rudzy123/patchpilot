# Release strategy

PatchPilot has no tagged product release yet. Root `package.json` is `0.0.0` and `private: true`. Passing CI does not make a release production-ready ([release principles](release-principles.md)).

## What Session 4 does

The **Release dry run** workflow (`workflow_dispatch`) verifies that a commit can:

- Install with a frozen lockfile
- Pass format, lint, typecheck, unit tests, Prisma validate/generate, and production build
- Report version metadata and whether `CHANGELOG.md` exists

It does **not** publish npm packages, container images, GitHub Releases, or deployments. It does not run production migrations. It has read-only permissions and no publishing tokens.

## What a future tagged release should do

When the MVP journey is actually runnable:

1. Record operator-facing notes (migrations, policy version, known limits).
2. Keep artifacts free of credentials and development adapters.
3. Prefer additive migrations.
4. Sign or attest artifacts only after a reviewed signing strategy exists (not in this session).

Automatic package publishing, automatic GitHub Releases, and automatic production deploys are out of scope until a later milestone explicitly adds them.

## Versioning

Follow [release principles](release-principles.md). Policy version is independent of the application version once scoring exists.

## Changelog

There is no `CHANGELOG.md` in the Session 3/4 tree. The dry-run summary reports that absence. Do not invent release notes for unimplemented product features.
