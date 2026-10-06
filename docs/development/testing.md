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
pnpm test:integration:serial
pnpm test:e2e
pnpm infrastructure:down
```

`pnpm test` is an alias for `pnpm test:unit`. `pnpm test:integration` is the parallel integration command. `pnpm test:integration:serial` runs the same package tasks one at a time for diagnosis. `pnpm test:e2e` is reserved and currently prints that Playwright is not wired; it exits 0 because there are no browser tests to execute. Do not treat that as a Playwright pass. GitHub Actions does not run the e2e command. Keep it locally only to preserve the documented command interface. GitHub Actions runs `pnpm test:integration`.

## What unit tests cover in this foundation

- Config validation, including production rejection of development adapters and placeholder credentials.
- Logger redaction of authorization, cookies, tokens, and env dumps.
- Health contract shapes (no URLs or credentials).
- API factory: live/ready, request ids, error envelope, CORS allowlist, body limit, header redaction, `trustProxy=false`.
- Authentication routes (Fastify inject): login/logout/session/organizations/select-organization, cookie attributes, Origin, CSRF, rotation, tenancy, audit redaction, limiter failure.
- Worker factory: fake Redis/database, idempotent shutdown, init failure.
- Web landing copy, landmarks, `/health` contract, and Session 6 authentication UI (login, session bootstrap, organization selector, logout, expired-session, access-denied). Web auth tests use jsdom and Testing Library; they do not start Next.js or the API.
- Session 8 Batch 6: authorized, idempotent SBOM upload use case (no Fastify, Redis, or BullMQ).

## What integration tests cover

- PostgreSQL `SELECT 1` readiness through `@patchpilot/database` against a disposable database.
- Redis `PING` through the worker ioredis adapter.
- MinIO `/minio/health/live` over HTTP (no MinIO SDK).
- Session 8 Batch 5: private streaming S3-compatible Put/Head/Copy/Get against Compose MinIO through `@patchpilot/integrations` (no public ACL, no signed URLs).
- Session 8 Batch 6: PostgreSQL-backed upload finalization (idempotency, duplicate evidence, audit/outbox rollback). No Fastify route and no Redis/BullMQ publish.
- Session 6: authentication persistence (digest-only sessions, audit actors) and API authentication routes against PostgreSQL (valid/invalid auth, cookie attributes, Origin, CSRF, rotation, tenancy, audit redaction, limiter failure). Redis login limiter adapter.

Redis, MinIO, and object-storage checks use the same development placeholder URLs as Compose defaults. They do not stream live SBOMs or call vulnerability feeds. Session 8 Batch 6 upload integration tests use synthetic JSON streams and an in-memory storage fake.

## Integration database isolation

Automated integration suites use disposable PostgreSQL databases. They do not read or write the persistent development database named `patchpilot`. `DATABASE_URL` in the shell or CI job is only the loopback server template (host, port, and credentials). Each suite creates its own database and deploys the frozen migration chain with `prisma migrate deploy`.

Test isolation is not product tenant isolation. Organization scoping, foreign-versus-absent results, and evidence immutability stay covered by their own tests.

| Suite | Isolation grain | Migration deployment | Cleanup |
| --- | --- | --- | --- |
| `apps/api` | One disposable database per Vitest process | Full frozen chain once, before tests | Drop that database after the process, including when tests fail |
| `apps/worker` | One disposable database per Vitest process | Full frozen chain once, before tests | Drop that database after the process, including when tests fail |
| `packages/database` | One disposable database per test file, or per migration case when a test needs its own schema | The chain that case requires, including full `migrate deploy` where the test says so | Drop that database in the test's `afterAll` or `finally` |

API and worker files stay sequential (`fileParallelism: false`) because the process owns one database and the Prisma client is a singleton. That is the isolation grain. It is not a workaround for cross-package interference. `pnpm test:integration` still runs package tasks concurrently through Turbo. Concurrent API, worker, and database processes cannot see one another's rows.

`pnpm test:integration:serial` runs the same tasks with Turbo concurrency 1. Use it to diagnose a failure. Passing only when serialized does not make the suite hermetic.

### Lifecycle

Shared helpers in `packages/database/src/integration-database.ts` and `integration-process-database.ts` own name generation, the administrator connection to the `postgres` maintenance database, `CREATE DATABASE`, migration deployment, the test database URL, disconnect, and `DROP DATABASE`. Those modules are excluded from the production build. Environment helpers live at `@patchpilot/config/integration-test`. The production `@patchpilot/config` entry does not export them, and production startup does not import them. The lifecycle refuses to run when `NODE_ENV` or `PATCHPILOT_DEPLOYMENT_ENVIRONMENT` is `production`, including when a synthetic test env record would otherwise allow a loopback command.

Database names match `patchpilot_it_*` or `patchpilot_migrate_*`, use only lowercase letters, digits, and underscores, and stay within PostgreSQL's 63-byte identifier limit. Process databases look like `patchpilot_it_<scope>_<unix-seconds>_<12 hex chars>`. The scope is `api` or `worker`. A process drops only the name in its own state file, and only when that name starts with its scope prefix. `patchpilot`, `postgres`, and template databases are rejected.

Creation and drop are one-shot. There is no retry loop. If migration deployment fails, cleanup drops the database that was just created and the original deployment error is rethrown. A cleanup error is written to stderr with the connection string redacted and does not replace the original failure. API and worker file hooks disconnect their Prisma client after that file's own cleanup and before process teardown drops the database. A disconnect failure is reported separately and does not replace an earlier cleanup failure. Process teardown then drops only the database named in that process's state file. `DROP DATABASE ... WITH (FORCE)` runs after that disconnect. Process teardown runs after passing and failing tests. If teardown itself fails, that failure is reported and the original test output remains.

A later run reaps at most 8 timestamped disposable databases older than 2 hours that have no active sessions. It does not drop fresh databases, databases with open sessions, the persistent `patchpilot` database, or historical names that do not carry a timestamp. Reap failures are counted and written to stderr; they do not hide a test failure and they do not retry.

Local Compose and the GitHub Actions PostgreSQL service use this same contract. CI does not migrate the service's `patchpilot` database before tests. Each disposable database receives its own migration deployment.

## Determinism

- No arbitrary `sleep`. Time helpers freeze UTC (`createFrozenClock`).
- API tests use Fastify `inject` and do not listen on a port.
- Do not skip tests without a tracked reason in the test file.

## Security tests

Tenant isolation, job replay, and SBOM parser tests are required when those features exist. Session 5 persists tenant isolation at the repository and constraint layer. Parser and HTTP isolation tests remain later.
