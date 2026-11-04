# Runbook: self-hosted deployment

Use this to build and run the application profile. It is the operator path for `web`, `api`, and `worker` containers. It is not the local development procedure. Development still uses [local setup](../development/local-setup.md) and [local infrastructure failure](local-infrastructure-failure.md).

A healthy stack is not production-ready, certified, or a browser login. The profile does not create a first user. The priority routes are composed with an empty allowlist and return 503 until a signed pair is published. CISA KEV synchronization and OSV acquisition stay off unless an operator changes the existing flags. `INTELLIGENCE_OSV_ENABLED=true` stays rejected. Login still needs operator HTTPS. This profile does not add a TLS proxy, and `trustProxy` stays false. Health checks do not prove a browser session.

Architecture: [deployment model](../architecture/deployment-model.md), [container architecture](../architecture/container-architecture.md). Current capability: [current state](../project/current-state.md).

## Layout

`deploy/compose/compose.yaml` is the only Compose file.

| Path | What it does |
| --- | --- |
| `pnpm infrastructure:up` | PostgreSQL, Redis, and MinIO on Compose project `patchpilot`. No application profile. Uses the developer `.env` when that file exists. Does not read `deploy/compose/application.env`. |
| `node scripts/run-application-deployment.mjs` | Application profile on Compose project `patchpilot-eval`. Volumes stay off the development project. |

Published ports stay on `127.0.0.1`: web `3000`, API `3001`. Postgres, Redis, and MinIO stay on loopback. The worker publishes nothing. Containers reach each other by service DNS (`postgres`, `redis`, `minio`), not by the host ports.

`api`, `worker`, and `web` use `restart: unless-stopped` and `stop_grace_period: 15s` (above the 10 second `SHUTDOWN_TIMEOUT_MS`). `object-storage-init`, `migrate`, and `bootstrap` are one-shot (`restart: "no"`). App containers run as the image `node` user. Infrastructure images keep their upstream users.

`down` does not pass `-v`. Do not add `-v` to keep the evaluation database.

The example host ports match the development defaults (`55432`, `16379`, `19000`, `19001`, plus web `3000` and API `3001`). The two projects cannot bind those ports at the same time. Stop one project, or change only the host publish variables. Do not point `DATABASE_URL`, `REDIS_URL`, or `OBJECT_STORAGE_ENDPOINT` at `127.0.0.1`.

## Images

One Dockerfile, `deploy/docker/Dockerfile`, context at the repository root. Targets:

| Target | Command | Notes |
| --- | --- | --- |
| `api` | `node dist/server.js` | `API_HOST=0.0.0.0` inside the container. Local `pnpm start` stays on `127.0.0.1`. |
| `worker` | `node dist/main.js` | No listen port. |
| `web` | `next start --port 3000 --hostname 0.0.0.0` | Public values are inlined at build. |
| `migrate` | `pnpm db:migrate:deploy` | Keeps the Prisma CLI and `packages/database/prisma`. Runtime app images do not. |

The base is `node:24-bookworm-slim`, pinned by digest. pnpm comes from Corepack and `packageManager` `pnpm@11.24.0`. There is no `DATABASE_URL` build arg. `.dockerignore` drops `.env`, `.env.*`, `node_modules`, `dist`, `.next`, `.turbo`, `.git`, and `deploy/compose/application.env`.

Next.js replaces the bracket reads in `packages/config/src/public.ts` with string literals in the server bundle. Runtime changes to `NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT` and `NEXT_PUBLIC_API_BASE_URL` do not affect a built web image. Those two values are public. Rebuild the web image after changing the operator HTTPS API origin. Compose build args for the web target are those two names.

GitHub Actions [container build](../development/ci.md#container-validation) builds the same four targets with BuildKit and does not push images.

## Environment file

Copy the committed template and edit the copy. Do not commit the copy.

```bash
cp deploy/compose/application.env.example deploy/compose/application.env
```

`deploy/compose/application.env` is gitignored. PostgreSQL keeps the password from the first initialization of the evaluation volume. The production configuration rejects the development passwords, so this file cannot reuse them. Changing `POSTGRES_PASSWORD` after that volume exists does not change the server password. A mismatch is an authentication failure. Discard the volume only when that database can be lost. `down` does not discard it.

The wrapper requires:

- `NODE_ENV=production`
- `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production`
- `PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS=false`
- `LOG_PRETTY=false`
- `API_HOST=0.0.0.0`, `API_PORT=3001`, `WEB_PORT=3000`
- `AUTH_COOKIE_SECURE=true` and `AUTH_COOKIE_NAME=__Host-patchpilot.sid`
- HTTPS origins in `CORS_ALLOWED_ORIGINS` (no `*`)
- `NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT=production`
- `NEXT_PUBLIC_API_BASE_URL` as an `https` URL without credentials
- `DATABASE_URL` as `postgresql://patchpilot:<password>@postgres:5432/patchpilot`
- `REDIS_URL` as `redis://:<password>@redis:6379`
- `OBJECT_STORAGE_ENDPOINT=http://minio:9000` and `OBJECT_STORAGE_USE_SSL=false`
- `INTELLIGENCE_OSV_ENABLED=false`
- `INTELLIGENCE_KEV_ENABLED` set to `true` or `false`. The example uses `false`. The code default remains `true`.
- `POSTGRES_USER=patchpilot` and `POSTGRES_DB=patchpilot`
- `MINIO_ROOT_USER` equal to `OBJECT_STORAGE_ACCESS_KEY`
- `MINIO_ROOT_PASSWORD` equal to `OBJECT_STORAGE_SECRET_KEY`
- `PATCHPILOT_MINIO_DEFAULT_BUCKETS` equal to `OBJECT_STORAGE_BUCKET`

Secret values must not contain `patchpilot-dev`, `not-for-production`, `minioadmin`, `changeme`, or `password`. Omit listing-evidence key material (`INTELLIGENCE_OSV_LISTING_EVIDENCE*`). Do not set `PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE`.

`check`, `config`, `build`, `down`, `status`, and `logs` may use the example file when the filled file is absent. `up`, `migrate`, `bootstrap`, and `restart` require the filled file. `check` is the only command that honors `PATCHPILOT_APPLICATION_ENV_FILE`.

```bash
node scripts/run-application-deployment.mjs check
```

Success prints `application env accepted` and the file path. It does not start containers and it does not print secret values. `config` renders Compose interpolation, which includes those secrets. Do not paste `config` output into tickets or logs.

## Build

From the repository root, with Docker Compose v2:

```bash
node scripts/run-application-deployment.mjs build
```

That builds `api`, `worker`, `web`, `migrate`, and `bootstrap`. `bootstrap` uses the migrate image. The web target receives the two public build args from the env file.

## Start

```bash
node scripts/run-application-deployment.mjs up
```

This is `docker compose up -d --wait` for project `patchpilot-eval` and profile `application`.

Order in the Compose file:

1. `postgres`, `redis`, and `minio` become healthy.
2. `migrate` runs `pnpm db:migrate:deploy` once and must exit 0.
3. `bootstrap` runs `node scripts/production-bootstrap.mjs` and must exit 0.
4. `object-storage-init` creates one private bucket with the pinned MinIO image and exits 0.
5. `api` and `worker` start after bootstrap. The worker also waits for the bucket init.
6. `web` starts after the API healthcheck passes.

Migrate does not retry, seed, reset, or resolve migrations. It does not edit the frozen chain. The frozen migration count is 28. A second migrate against the same database is a no-op. A non-zero migrate exit does not start `api`, `worker`, or `web`, because those services wait on bootstrap, and bootstrap waits on migrate.

Bootstrap exits 0 only when `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production`. It accepts no arguments. It creates no files, opens no database connection, and writes nothing. It does not call `seedDevelopmentData`, `ensurePublishedBuiltinPriorityPolicy`, `pnpm instance-advisory-authority`, or `pnpm offline-npm-osv-import`. Any other deployment value exits 1. Success prints `Production bootstrap completed without writing data.`

`object-storage-init` does not call `initializeDevelopmentBucket` and does not set a public bucket policy. The production worker only calls `HeadBucket`. A missing bucket makes the worker exit.

`pnpm db:seed` writes synthetic tenants and is refused when `NODE_ENV` or `PATCHPILOT_DEPLOYMENT_ENVIRONMENT` is `production`. Do not run it in this profile.

Empty catalogs, no grants, no Findings, and no priority rows are the expected result.

## Health

```bash
node scripts/run-application-deployment.mjs status
```

From the host:

- API readiness: `GET http://127.0.0.1:3001/health/ready`. HTTP 200 means PostgreSQL accepted `SELECT 1`. It does not mean Redis, object storage, or a later schema drift is healthy. The migrate job is what gates startup. Not ready is HTTP 503 with check `database` `down`.
- API liveness: `GET http://127.0.0.1:3001/health/live`.
- Web liveness: `GET http://127.0.0.1:3000/health`. This does not call the API.

The worker has no port and no healthcheck. A probe that always passes would hide a failed startup. Startup already requires PostgreSQL, `HeadBucket` on the private bucket, the migrated `cisa_kev` intelligence source row, and Redis. Health is the container staying up. The log line to look for is `worker started`. Process exit is the failure signal. Compose then restarts it because `restart` is `unless-stopped`.

`up --wait` waits for healthchecks where a service defines one, and for one-shot commands to finish. The worker has no healthcheck, so confirm its log after `up` returns:

```bash
node scripts/run-application-deployment.mjs logs worker
```

`logs` follows until interrupted. An optional service name limits the stream (`api`, `worker`, `web`, `migrate`, `bootstrap`, `postgres`, `redis`, `minio`, `object-storage-init`). Do not paste connection strings or object-storage credentials from those logs.

## Migrate and bootstrap again

`up` is the ordered path. These commands rerun one service with `--no-deps`, so they do not start PostgreSQL themselves:

```bash
node scripts/run-application-deployment.mjs migrate
node scripts/run-application-deployment.mjs bootstrap
```

Run them after the evaluation project is already up. `migrate` still needs the `postgres` service on that project network. `bootstrap` does not open a database connection.

## Restart

```bash
node scripts/run-application-deployment.mjs restart
```

With no extra names, this restarts `api` and `worker`. You may pass `api`, `worker`, or `web`.

Compose sends SIGTERM and waits for the 15 second grace period. The existing API and worker SIGTERM handlers are unchanged.

## Stop

```bash
node scripts/run-application-deployment.mjs down
```

This stops project `patchpilot-eval` and keeps named volumes. The script prints that volumes were kept. It does not pass `-v`. The evaluation Postgres volume should still exist afterward (`docker volume ls` and the `patchpilot-eval` project prefix).

`pnpm infrastructure:down` stops the development project only. It also keeps named volumes. It does not select the application profile.

## Failures

| Symptom | What it means | Next step |
| --- | --- | --- |
| `up` fails before migrate | Docker is down, a host port is taken, or an image pull failed | `docker info`. Stop the other Compose project or change host publish ports only. |
| Migrate exits non-zero | Deploy failed. `api`, `worker`, and `web` stay unstarted | [Database migration failure](database-migration-failure.md). Do not edit a frozen migration. Do not run `pnpm db:reset` or `pnpm db:seed`. |
| Bootstrap exits 1 | `PATCHPILOT_DEPLOYMENT_ENVIRONMENT` is not `production`, or an argument was passed | Fix the env file. The process writes nothing. stderr is `Production bootstrap requires PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production and writes nothing.` or `Production bootstrap accepts no arguments.` |
| `object-storage-init` exits 1 | Bucket name, root credentials, or the MinIO client | The worker will not start. The init does not apply a public policy. stderr names the refusal without printing the secret. |
| API `/health/ready` is 503 | PostgreSQL `SELECT 1` failed | Confirm migrate exited 0 and `DATABASE_URL` uses hostname `postgres`. Readiness is not a Redis or bucket check. |
| Worker exits | Database, `HeadBucket`, the `cisa_kev` row, or Redis | Logs include `Worker failed to start:` and one of `database is not ready`, `object storage is not ready`, `intelligence source is not ready`, or `redis is not ready`. Do not add a worker port or an always-passing healthcheck. |
| Web `/health` is 200 and login fails | Expected gap | No first user is created. `__Host-` cookies and HTTPS CORS stay mandatory. Rebuild web after changing the public API origin. This profile does not terminate TLS. |
| Redis or database authentication failure after a volume already exists | The volume kept the first password | Do not expect a later env edit to rewrite it. |
| KEV scheduler starts | `INTELLIGENCE_KEV_ENABLED=true` | The example uses `false` so startup does not open the CISA scheduler. The code default remains `true`. OSV acquisition stays off. |
| Wrapper rejects the env file | A required value is missing, a URL is wrong, or a secret contains a development fragment | `check` names the key. It does not print the secret. |

## What stays unavailable

- No first user, no registration, and no production seed.
- No priority rows until an operator runs the built-in publication command. That command exits 2 while V-0001 is unsigned. [ADR 0047](../adr/0047-controlled-priority-activation.md) composes the priority routes with an empty allowlist, so they return 503. No worker job or Outbox event calculates priority.
- No TLS proxy. `trustProxy` stays false. Loopback HTTP health is not a browser session.
- No public bucket.
- No grant command and no offline npm import in this profile. Those remain separate explicit commands.
- No new migration. The frozen count remains 28.

## Related

- [Local infrastructure failure](local-infrastructure-failure.md)
- [Database migration failure](database-migration-failure.md)
- [Authentication failure](authentication-failure.md)
- [CI container validation](../development/ci.md#container-validation)
- [Background job failure](background-job-failure.md)
