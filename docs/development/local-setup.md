# Local development setup

This is the local **development foundation** through Session 9 Batch 9B (schema, API auth routes, minimal web login, the SBOM upload-to-graph pipeline, and KEV catalog import when enabled). It is not a production deployment. It does not include vulnerability correlation, Findings from intelligence, scoring, remediation, an SBOM web UI, or a vulnerability dashboard.

## Prerequisites

- Node.js **24** (Active LTS). `.nvmrc` is authoritative. `package.json` `engines.node` is `^24.0.0`.
- pnpm **11.24.0** via Corepack (`packageManager` in the root `package.json`).
- Docker Engine with Compose v2 (`docker compose version`).
- Git.

```bash
corepack enable
nvm use        # or install Node 24 another way
```

## First-time setup

1. Copy environment templates. Do not commit the copies.

   ```bash
   cp .env.example .env
   cp packages/database/.env.example packages/database/.env
   cp apps/web/.env.example apps/web/.env.local
   ```

   Values in these files are **development placeholders and are unfit for production**. `packages/config` rejects them when `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production`. API and worker `dev` processes load the repository-root `.env` through `loadServerConfig()` when production is not already selected. `pnpm start` does not load `.env` files.

2. Install workspace dependencies.

   ```bash
   pnpm install
   ```

3. Start PostgreSQL, Redis, and MinIO. Applications are **not** started by Compose.

   ```bash
   pnpm infrastructure:up
   ```

4. Apply Prisma migrations. Session 3 created `SchemaFoundation`; Session 5 replaces it with the tenant schema (`20260827120000_tenant_model`). Later forward-only corrections follow that file. Committed migration SQL is authoritative.

   ```bash
   pnpm db:generate
   pnpm db:migrate:deploy
   ```

   Optional synthetic data (not for production):

   ```bash
   pnpm db:seed
   ```

5. Start the application shells from the repository root.

   ```bash
   pnpm dev
   ```

   - Web: `http://127.0.0.1:3000`
   - API: `http://127.0.0.1:3001`
   - Worker: process only (no HTTP listener)

## Daily commands

First terminal (apps):

```bash
pnpm install
pnpm infrastructure:up
pnpm db:generate
pnpm dev
```

Second terminal (quality gates):

```bash
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test:unit
pnpm test:integration
pnpm build
pnpm workflows:lint
```

| Command | Purpose |
| --- | --- |
| `pnpm install` | Install or update the lockfile |
| `pnpm format` / `pnpm format:check` | Prettier |
| `pnpm lint` | ESLint (root + packages) |
| `pnpm typecheck` | TypeScript |
| `pnpm test:unit` | Vitest unit tests (no Compose) |
| `pnpm test:integration` | Compose-backed PostgreSQL, Redis, and MinIO checks |
| `pnpm build` | Production build of packages and apps |
| `pnpm workflows:lint` | Checksum-pinned actionlint on `.github/workflows` |
| `pnpm infrastructure:up` | Start local PostgreSQL, Redis, MinIO and wait until healthchecks pass |
| `pnpm infrastructure:status` | Show Compose container status and health. After `infrastructure:down`, this prints an empty table and exits 0; that means no PatchPilot containers are running, not a healthcheck failure |
| `pnpm infrastructure:down` | Stop Compose services. Named volumes persist; this is not a data reset |
| `pnpm infrastructure:logs` | Follow Compose logs until interrupted |
| `pnpm db:validate` | Prisma schema validate |
| `pnpm db:generate` | Generate Prisma Client |
| `pnpm db:migrate` | Create/apply migrations locally (`prisma migrate dev`, interactive) |
| `pnpm db:migrate:deploy` | Apply existing migrations non-interactively (`prisma migrate deploy`) |
| `pnpm db:reset` | Reset the local database (destructive; requires loopback host, `patchpilot` database name, and `PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE=true`; refused in production) |
| `pnpm db:seed` | Idempotent synthetic development seed (refused in production) |

Environment variables are documented in [environment-variables.md](environment-variables.md). Test labels are in [testing.md](testing.md). Failures: [troubleshooting.md](troubleshooting.md) and [local infrastructure runbook](../runbooks/local-infrastructure-failure.md). GitHub Actions: [ci.md](ci.md).

## Object storage (MinIO)

`pnpm infrastructure:up` starts MinIO alongside PostgreSQL and Redis. It is the local stand-in for S3-compatible private object storage; nothing about it is production guidance.

| Setting | Local value |
| --- | --- |
| API endpoint | `http://127.0.0.1:19000` (`PATCHPILOT_MINIO_API_PORT`) |
| Console | `http://127.0.0.1:19001` (`PATCHPILOT_MINIO_CONSOLE_PORT`) |
| Healthcheck | `GET /minio/health/live` |
| Bucket | `OBJECT_STORAGE_BUCKET`, `patchpilot-dev` in `.env.example` |
| Credentials | `OBJECT_STORAGE_ACCESS_KEY` / `OBJECT_STORAGE_SECRET_KEY`, matching the Compose literals |
| TLS | `OBJECT_STORAGE_USE_SSL=false`, which must agree with the `http` endpoint scheme |

PatchPilot talks to MinIO through `@aws-sdk/client-s3` with `forcePathStyle: true`. There is no MinIO JavaScript SDK dependency, and there is no presigned-URL support in any environment.

The bucket is created on demand, but only under development guardrails: the deployment environment must not be `production`, `PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS` must be `true`, and the requested bucket must equal the configured one. Production never creates a missing bucket; there, a missing bucket is an operator error and surfaces as a `bucket_missing` storage failure.

To verify the pipeline locally after `pnpm dev`:

1. Log in through `/login` and select an organization so you hold a session and a CSRF token.
2. `POST /assets/:assetId/sboms` with `Content-Type: application/json`, an `Origin` in `CORS_ALLOWED_ORIGINS`, the CSRF header, a unique `Idempotency-Key`, and a CycloneDX 1.4–1.6 JSON body. The repository ships no sample SBOM yet; generate one, and do not use a real customer document.
3. Expect `202` with an `ingestionId`, and an object under `org/{organizationId}/assets/{assetId}/sboms/sha256/{sha256}` in the bucket.
4. Poll `GET /assets/:assetId/sbom-ingestions/:ingestionId` until the state leaves `accepted`/`queued`/`processing`.

If the state does not advance, the worker is the thing to check first: the relay publishes from PostgreSQL, so a stopped worker leaves `outbox_event` rows `pending` rather than losing them. See [sbom-ingestion-failure](../runbooks/sbom-ingestion-failure.md).

Do not put real customer SBOMs in this bucket. Local MinIO has placeholder credentials, no TLS, and no backup.

## What this foundation does not include

See [database.md](database.md) and [migrations.md](migrations.md). Do not expect registration, password reset, an SBOM web UI, retry or quarantine-release APIs, orphan-object cleanup, risk scoring, advisory matching, Findings from intelligence, a vulnerability dashboard, or GitHub integration in this milestone. KEV runtime synchronization exists when `INTELLIGENCE_KEV_ENABLED=true`; OSV runtime remains disabled (`INTELLIGENCE_OSV_ENABLED=true` is rejected). Local tests use synthetic provider data; ordinary CI and test suites do not call live CISA. Do not download the production KEV catalog by hand. Operators may inspect sanitized state with the authenticated provider-status GET routes (`intelligence:read` and an active Organization). Session 6 login uses `/login` against the API origin in `NEXT_PUBLIC_API_BASE_URL`.
