# Local development setup

This is the local **development foundation** through Session 6 (schema, API auth routes, and minimal web login). It is not a production deployment and it does not include product workflows (SBOM processing, scoring, or remediation).

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

## What this foundation does not include

See [database.md](database.md) and [migrations.md](migrations.md). Do not expect registration, password reset, SBOM upload, vulnerability feeds, risk scoring, or GitHub integration in this milestone. Session 6 login uses `/login` against the API origin in `NEXT_PUBLIC_API_BASE_URL`.
