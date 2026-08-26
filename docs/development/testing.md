# Testing

Vitest is the unit and integration runner. Playwright is **not** wired in this foundation; the landing page and health contract are covered by unit tests. Browser journeys belong to a later milestone when product UI exists.

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
pnpm infrastructure:down
```

`pnpm test` is an alias for `pnpm test:unit`.

## What unit tests cover in this foundation

- Config validation, including production rejection of development adapters and placeholder credentials.
- Logger redaction of authorization, cookies, tokens, and env dumps.
- Health contract shapes (no URLs or credentials).
- API factory: live/ready, request ids, error envelope, CORS allowlist, body limit, header redaction.
- Worker factory: fake Redis/database, idempotent shutdown, init failure.
- Web landing copy, landmarks, and `/health` contract.

## What integration tests cover

- PostgreSQL `SELECT 1` readiness through `@patchpilot/database`.
- Redis `PING` through the worker ioredis adapter.
- MinIO `/minio/health/live` over HTTP (no MinIO SDK).

They use the same development placeholder URLs as Compose defaults. They do not create product rows, upload SBOMs, or call vulnerability feeds.

## Determinism

- No arbitrary `sleep`. Time helpers freeze UTC (`createFrozenClock`).
- API tests use Fastify `inject` and do not listen on a port.
- Do not skip tests without a tracked reason in the test file.

## Security tests

Tenant isolation, job replay, and SBOM parser tests are required when those features exist. They are out of scope for this foundation because the product entities are not implemented.
