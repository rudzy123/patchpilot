# Testing

Vitest is the unit and integration runner. Playwright is **not** wired in this foundation; the landing page, health contract, and Session 6 authentication UI are covered by unit and component tests. Browser journeys belong to a later milestone when product UI exists. GitHub-hosted E2E testing is deferred until actual Playwright tests exist; see [CI-DEFER-1](ci.md#deferred-ci-work). Do not treat the local `pnpm test:e2e` placeholder as end-to-end validation.

## Labels

| Label | How to recognize | Infrastructure |
| --- | --- | --- |
| Unit | `*.test.ts` excluding `*.integration.test.ts` | None. Fakes, inject-without-listen, and in-memory doubles. |
| Integration | `*.integration.test.ts` | Local Compose: PostgreSQL, Redis, MinIO. |
| End-to-end | not present | Would use Playwright against the web app. |

## Commands

```bash
pnpm test:unit
pnpm infrastructure:up
pnpm test:integration
pnpm test:e2e
pnpm infrastructure:down
```

`pnpm test` is an alias for `pnpm test:unit`. `pnpm test:e2e` is reserved and currently prints that Playwright is not wired; it exits 0 because there are no browser tests to execute. Do not treat that as a Playwright pass. GitHub Actions does not run this command. Keep it locally only to preserve the documented command interface.

## What unit tests cover in this foundation

- Config validation, including production rejection of development adapters and placeholder credentials.
- Logger redaction of authorization, cookies, tokens, and env dumps.
- Health contract shapes (no URLs or credentials).
- API factory: live/ready, request ids, error envelope, CORS allowlist, body limit, header redaction, `trustProxy=false`.
- Authentication routes (Fastify inject): login/logout/session/organizations/select-organization, cookie attributes, Origin, CSRF, rotation, tenancy, audit redaction, limiter failure.
- Worker factory: fake Redis/database, idempotent shutdown, init failure.
- Web landing copy, landmarks, `/health` contract, and Session 6 authentication UI (login, session bootstrap, organization selector, logout, expired-session, access-denied). Web auth tests use jsdom and Testing Library; they do not start Next.js or the API.

## What integration tests cover

- PostgreSQL `SELECT 1` readiness through `@patchpilot/database`.
- Redis `PING` through the worker ioredis adapter.
- MinIO `/minio/health/live` over HTTP (no MinIO SDK).
- Session 8 Batch 5: private streaming S3-compatible Put/Head/Copy/Get against Compose MinIO through `@patchpilot/integrations` (no public ACL, no signed URLs).
- Session 6: authentication persistence (digest-only sessions, audit actors) and API authentication routes against PostgreSQL (valid/invalid auth, cookie attributes, Origin, CSRF, rotation, tenancy, audit redaction, limiter failure). Redis login limiter adapter.

They use the same development placeholder URLs as Compose defaults. Constraint tests create ephemeral `patchpilot_it_*` / `patchpilot_migrate_*` databases and drop them. They do not upload SBOMs or call vulnerability feeds.

## Determinism

- No arbitrary `sleep`. Time helpers freeze UTC (`createFrozenClock`).
- API tests use Fastify `inject` and do not listen on a port.
- Do not skip tests without a tracked reason in the test file.

## Security tests

Tenant isolation, job replay, and SBOM parser tests are required when those features exist. Session 5 persists tenant isolation at the repository and constraint layer. Parser and HTTP isolation tests remain later.
