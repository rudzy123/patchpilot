# Deployment model

PatchPilot v0.1 is **self-hosted**. The project does not operate a multi-tenant SaaS control plane ([non-goals](../product/non-goals.md)). Local development uses Docker Compose for PostgreSQL, Redis, and MinIO. The same Compose file has an `application` profile for `web`, `api`, and `worker` ([ADR 0001](../adr/0001-modular-monolith.md), [MVP scope](../product/mvp-scope.md)).

This document is architecture. The operator procedure is [self-hosted deployment](../runbooks/self-hosted-deployment.md). A healthy application profile does not create a first user, does not compose the priority engine, and still needs operator HTTPS before a browser can log in.

## Deployable units

Three apps, one schema, shared packages ([ADR 0001](../adr/0001-modular-monolith.md)):

| Unit | Scales by | Notes |
| --- | --- | --- |
| `apps/web` | Stateless replicas | Talks to API only |
| `apps/api` | Stateless replicas | Sticky sessions not required if sessions are in PostgreSQL |
| `apps/worker` | Competing consumers | Same job types; idempotent |

Do not split these into independently owned microservices without an ADR.

## Local Compose

`deploy/compose/compose.yaml` is the only Compose file.

`pnpm infrastructure:up` starts PostgreSQL, Redis, and MinIO on Compose project `patchpilot`. It loads the developer `.env` when that file exists. It does not pass `--profile application` and it does not read `deploy/compose/application.env`.

The application profile runs as Compose project `patchpilot-eval` through `node scripts/run-application-deployment.mjs`. That project name keeps its volumes off the development volumes. `down` does not pass `-v`.

```text
postgres, redis, minio
        |
        v
migrate --> bootstrap --> api, worker, web
minio --> object-storage-init --> worker
api --> web
```

`migrate`, `bootstrap`, and `object-storage-init` are one-shot (`restart: "no"`). `api`, `worker`, and `web` use `restart: unless-stopped` and `stop_grace_period: 15s`. Published ports stay on `127.0.0.1`: web `3000`, API `3001`. Postgres, Redis, and MinIO stay on loopback. The worker publishes nothing. Internal URLs use service DNS (`postgres`, `redis`, `minio`).

The API writes the outbox in PostgreSQL and does not publish jobs to Redis. The worker relays that outbox. Outbound OSV acquisition stays disabled. The application-profile example sets `INTELLIGENCE_KEV_ENABLED=false`, so startup does not open the CISA scheduler. The code default for that flag stays `true`.

An operator can replace the Compose data plane with their own PostgreSQL, Redis, and S3-compatible **private** storage ([OD-5](open-decisions.md)). This profile does not add that replacement, a TLS proxy, or a public bucket.

## Images

One Dockerfile, `deploy/docker/Dockerfile`, with the repository root as context. Targets are `api`, `worker`, `web`, and `migrate`. The base is `node:24-bookworm-slim`, pinned by digest, matching the Node 24 major in `.nvmrc`. pnpm comes from Corepack and `packageManager` `pnpm@11.24.0`. App containers run as the image `node` user. Infrastructure images keep their upstream users. Runtime app images copy a `pnpm deploy --prod` tree and do not include the Prisma CLI. The migrate target keeps the CLI and `packages/database/prisma`. Its command is `pnpm db:migrate:deploy`. There is no `DATABASE_URL` build arg. `.dockerignore` drops `.env`, `.env.*`, `node_modules`, `dist`, `.next`, `.turbo`, `.git`, and `deploy/compose/application.env`.

`.github/workflows/container-build.yml` builds those four targets with BuildKit. It does not push images or log registry credentials.

## Configuration

Only `packages/config` reads `process.env`. Production must:

- Require HTTPS termination (operator ingress).
- Disable development adapters: `deploymentEnvironment=production` implies `allowDevelopmentAdapters=false`. Construction of fake auth, unrestricted HTTP, or unsigned webhooks must throw at boot.
- Require secrets for DB, Redis, object storage, session material, and credential KEK ([OD-4](open-decisions.md)). Future protected listing-evidence encryption keys are a separate instance-level operator secret loaded only through `packages/config`. Session 13 Batch 3D-E defines that policy and does not add environment variables, generate keys, or enable encryption at startup. Session 13 Batch 3D-E-R independently reviewed that boundary.
- Set allowlists for OSV and KEV hosts.
- First boot with empty intel catalogs is supported; correlation simply finds nothing until snapshots exist.

Images and repos must not contain `.env` files with live secrets or default admin passwords.

The application profile reads `deploy/compose/application.env`, copied from `deploy/compose/application.env.example`. The filled file is gitignored. Production values include `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production`, `PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS=false`, `LOG_PRETTY=false`, `AUTH_COOKIE_SECURE=true`, cookie name `__Host-patchpilot.sid`, HTTPS CORS origins, and an authenticated `REDIS_URL`. Secrets must not contain `patchpilot-dev`, `not-for-production`, `minioadmin`, `changeme`, or `password`. Listing-evidence key material is omitted. `PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE` is not set. The example sets `INTELLIGENCE_KEV_ENABLED=false` and `INTELLIGENCE_OSV_ENABLED=false`.

`NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT` and `NEXT_PUBLIC_API_BASE_URL` are public. Next.js inlines the bracket reads in `packages/config/src/public.ts` into the built server. Compose also sets them at runtime. The built server ignores a runtime change, so another operator HTTPS origin requires a web image rebuild. `trustProxy` stays false. This profile does not terminate TLS.

## Network

- Browser reaches web and API. This profile publishes both on loopback without TLS. Operator HTTPS is still required for a browser session. `__Host-` cookies and HTTPS CORS stay mandatory.
- Redis, PostgreSQL, and object storage are not browser-accessible. The worker publishes no port.
- Egress from worker to allowlisted intel hosts only (plus storage/DB/Redis).
- API needs egress to storage and DB, not to OSV, unless a future ADR moves refresh (v0.1: worker-only feed fetch).

## Migrations

Prisma migrations apply before new API/worker versions that need them. Prefer additive migrations. Do not destroy evidentiary tables as rollback ([release principles](../development/release-principles.md)).

The application profile runs the existing `pnpm db:migrate:deploy` once, after PostgreSQL is healthy. A non-zero exit does not start api, worker, or web. The job does not retry, seed, reset, or resolve migrations. It does not add a migration. The frozen count remains 27. Bootstrap then runs `scripts/production-bootstrap.mjs` from the migrate image. That process exits 0 only when `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production`. It accepts no arguments, opens no database connection, and writes nothing. It does not call `seedDevelopmentData`, `ensurePublishedBuiltinPriorityPolicy`, `pnpm instance-advisory-authority`, or `pnpm offline-npm-osv-import`. API `GET /health/ready` remains a PostgreSQL `SELECT 1`. The worker has no HTTP server. Startup already requires PostgreSQL, `HeadBucket`, the migrated `cisa_kev` row, and Redis.

## Backups

Operator duty ([OD-13](open-decisions.md)):

- PostgreSQL logical/physical backups **and** object-storage backups together (SBOMs are not only in the DB).
- Treat backups as **Restricted**. Encrypt at rest if the operator's platform supports it.
- Restoring backups does not grant a product-level cross-org console.
- Protected listing-evidence ciphertext may appear in PostgreSQL backups. Raw listing-evidence encryption keys must not. Restoring the database without the required key capability leaves protected object identities unavailable. Restoring old database state must not reactivate destroyed keys. Backup operators must not receive general decryption authority merely because they control backups. Cryptographic erasure does not immediately remove ciphertext from backups. Session 13 Batch 3D persisted one `review_pending` evidence set of 1000 AES-256-GCM envelopes through uncomposed adapters. Production composition does not construct the factory. Session 13 Batch 3D used a process-local key unused by startup. Session 13 Batch 3D-R independently reviewed that evidence: the process-local operator key is unavailable for later reveal; restoring the database without that key leaves protected identities unavailable. Session 13 Batch 3D-E-R treats recorded purge evidence as authoritative after restore even if keys remain available.

## AI

No AI provider in default deploy. If optional AI is enabled later, users supply keys at runtime; keys never ship in images ([ADR 0017](../adr/0017-optional-ai-user-credentials.md)).

## CLI

No Go CLI in v0.1 ([ADR 0018](../adr/0018-go-cli-deferred.md)).

The instance advisory authority command is not that product CLI. It is one explicit deployment-local process, `pnpm instance-advisory-authority`, and it is the sole supported writer for instance advisory grants and for the user disable and enable operations that command owns. API, web, worker, scheduler, queue, seed, and migration startup do not invoke it. The procedure and exit codes are in [the instance advisory authority runbook](../runbooks/instance-advisory-authority-command.md).

The offline npm OSV import is the same kind of process: `pnpm offline-npm-osv-import`. It is implemented and production uncomposed. It is not an API route, web action, worker job, seed, or migration. The procedure and exit codes are in [the offline npm OSV import runbook](../runbooks/offline-npm-osv-import.md). Production OSV acquisition stays disabled.

## Related documents

- [Self-hosted deployment](../runbooks/self-hosted-deployment.md)
- [Container architecture](container-architecture.md)
- [Reliability model](reliability-model.md)
- [Retention and deletion](retention-and-deletion.md)
