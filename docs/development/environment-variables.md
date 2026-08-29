# Environment variables

All server configuration is read in `@patchpilot/config`. Application, domain, and Next.js source must not read `process.env` directly. Public web values use `NEXT_PUBLIC_*` and `loadPublicConfig()` from `@patchpilot/config/public`.

Copy [`.env.example`](../../.env.example) to `.env`. Example values are **development placeholders and are unfit for production**.

`pnpm dev` for the API and worker calls `loadServerConfig()`, which loads the repository-root `.env` only when neither `NODE_ENV` nor `PATCHPILOT_DEPLOYMENT_ENVIRONMENT` is already `production`. Existing process environment values are never overridden. Production `start` scripts set `NODE_ENV=production` and do **not** read `.env` files; operators must inject runtime secrets. Next.js still loads `apps/web/.env.local` itself for public `NEXT_PUBLIC_*` values.

## Server (required unless noted)

| Variable | Purpose |
| --- | --- |
| `PATCHPILOT_DEPLOYMENT_ENVIRONMENT` | `development`, `test`, or `production`. This flag, not `NODE_ENV` alone, gates development adapters. |
| `PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS` | Must be `false` in production. Pretty logs, unauthenticated Redis, and placeholder credentials are development adapters. |
| `LOG_LEVEL` | Pino level (`fatal` … `silent`). |
| `LOG_PRETTY` | Pretty-print logs. Rejected when the deployment environment is `production`. |
| `API_HOST` | Fastify bind address. Local default `127.0.0.1`. |
| `API_PORT` | Fastify bind port. Local default `3001`. |
| `WEB_PORT` | Documented Next.js port. Local default `3000`. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated exact origin allowlist used for CORS and CSRF Origin checks. `*` is rejected. Production origins must be `https://` URLs. |
| `DATABASE_URL` | PostgreSQL URL. Never logged. |
| `PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE` | Must be `true` for `pnpm db:reset` and ephemeral integration-test databases. Never set in production. `NODE_ENV` alone is not a safety grant. |
| `REDIS_URL` | Redis URL. Never logged. |
| `OBJECT_STORAGE_ENDPOINT` | S3-compatible endpoint (local MinIO). |
| `OBJECT_STORAGE_ACCESS_KEY` | Object-storage access key. |
| `OBJECT_STORAGE_SECRET_KEY` | Object-storage secret. |
| `OBJECT_STORAGE_BUCKET` | S3-compatible bucket name (3–63 characters, lowercase, digits, dots, hyphens; not an IPv4 address; no adjacent periods). Production rejects development placeholders such as `patchpilot-dev`. Bucket creation is deferred until object operations exist. |
| `OBJECT_STORAGE_USE_SSL` | `true` or `false`. |
| `OBJECT_STORAGE_OPERATION_TIMEOUT_MS` | Timeout for a single object-storage operation used by SBOM upload/re-read. Default `30000`. Floor `1000`, ceiling `120000`. Must be less than `SBOM_PROCESSING_LEASE_MS`. |
| `OTEL_ENABLED` | Enables OpenTelemetry **trace** SDK initialization. Default `false`. Does not enable metrics, log export, or automatic instrumentation. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Optional OTLP **HTTP JSON** traces endpoint. Required only when exporting. When unset, enabled telemetry uses a no-op span processor and does not contact a collector. Other `OTEL_*` variables are not read by PatchPilot. |
| `READINESS_TIMEOUT_MS` | Budget for readiness probes. |
| `SHUTDOWN_TIMEOUT_MS` | Graceful shutdown budget. |
| `REQUEST_BODY_LIMIT_BYTES` | Ordinary Fastify JSON body limit. Independent of `SBOM_UPLOAD_MAX_BYTES`. Example `1048576`. |
| `REQUEST_ID_HEADER` | Incoming/outgoing request id header. Default `x-request-id`. |
| `CORRELATION_ID_HEADER` | Incoming/outgoing correlation id header. Default `x-correlation-id`. |

## SBOM ingestion ([ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md))

Required. These are reviewed **initial defaults**, not production performance guarantees. Runtime upload and parse are not implemented in Session 8 Batch 1. Values must be canonical integers (no `NaN`, `Infinity`, scientific notation, or leading zeros). Parser timeout and object-storage timeout must be less than the processing lease. Idempotency TTL must outlive the maximum plausible upload object-storage operation. Orphan grace must be greater than the idempotency TTL. Object-storage credentials stay on the existing `OBJECT_STORAGE_*` secret fields and are not part of the public SBOM config object.

| Variable | Purpose |
| --- | --- |
| `SBOM_UPLOAD_MAX_BYTES` | Raw SBOM upload cap. Default `20971520`. Floor `65536`, ceiling `33554432`. |
| `SBOM_JSON_MAX_DEPTH` | Max JSON nesting. Default `32`. Floor `8`, ceiling `64`. |
| `SBOM_JSON_MAX_NODES` | Max JSON values (objects, arrays, primitives). Default `200000`. Floor `1000`, ceiling `500000`. |
| `SBOM_JSON_MAX_STRING_BYTES` | Max UTF-8 bytes per JSON string. Default `65536`. Floor `1024`, ceiling `262144`. |
| `SBOM_MAX_COMPONENTS` | Max CycloneDX components. Default `10000`. Floor `1`, ceiling `25000`. |
| `SBOM_MAX_DEPENDENCY_EDGES` | Max dependency edges. Default `50000`. Floor `0`, ceiling `100000`. |
| `SBOM_MAX_BOM_REF_BYTES` | Max `bom-ref` bytes. Default `2048`. Floor `64`, ceiling `2048`. |
| `SBOM_MAX_PURL_BYTES` | Max PURL bytes. Default `2048`. Floor `64`, ceiling `2048`. |
| `SBOM_MAX_COMPONENT_NAME_CHARS` | Max component name characters. Default `512`. Floor `64`, ceiling `512`. |
| `SBOM_MAX_VERSION_CHARS` | Max version characters. Default `256`. Floor `1`, ceiling `256`. |
| `SBOM_MAX_METADATA_TOOLS` | Max metadata tools. Default `64`. Floor `0`, ceiling `256`. |
| `SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT` | Max external references per component. Default `32`. Floor `0`, ceiling `128`. |
| `SBOM_MAX_PROPERTIES_PER_COMPONENT` | Max properties per component. Default `64`. Floor `0`, ceiling `256`. |
| `SBOM_PARSER_TIMEOUT_MS` | Parser wall-clock budget (worker-thread termination). Default `60000`. Floor `10000`, ceiling `120000`. Must be less than `SBOM_PROCESSING_LEASE_MS`. |
| `SBOM_PROCESSING_LEASE_MS` | BackgroundJob processing lease. Default `900000`. Floor `120000`, ceiling `1800000`. `SbomIngestion.leaseExpiresAt` is unused in Session 8. |
| `SBOM_IDEMPOTENCY_TTL_SECONDS` | IdempotencyRecord TTL. Default `86400`. Floor `3600`, ceiling `259200`. |
| `SBOM_UPLOAD_RATE_LIMIT_MAX` | Max uploads per window per limiter key. Default `10`. Floor `1`, ceiling `60`. |
| `SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS` | Upload limiter window. Default `900`. Floor `60`, ceiling `3600`. |
| `SBOM_ORPHAN_GRACE_SECONDS` | Delay before unreferenced object cleanup. Default `604800`. Floor `7200`, ceiling `2592000`. Must be greater than `SBOM_IDEMPOTENCY_TTL_SECONDS`. |
| `SBOM_PARSER_VERSION` | Safe VARCHAR(64) parser label. Default `0.1.0`. |
| `SBOM_NORMALIZATION_VERSION` | Safe VARCHAR(64) normalization label. Default `1`. |

Test configuration may inject smaller limits only through typed test configuration, and only within these floors. Do not add object-storage access keys or endpoints to this SBOM object.

## Authentication ([ADR 0019](../adr/0019-local-password-sessions.md))

Required. There is **no** dummy password-hash environment variable. These variables are validated at process start so the API cannot boot with unsafe auth defaults.

| Variable | Purpose |
| --- | --- |
| `AUTH_SESSION_ABSOLUTE_TTL_SECONDS` | Absolute session lifetime. Default example `604800` (7 days). Must stay greater than or equal to the idle TTL. |
| `AUTH_SESSION_IDLE_TTL_SECONDS` | Idle session lifetime. Default example `43200` (12 hours). Must not exceed the absolute TTL. |
| `AUTH_SESSION_LAST_SEEN_MIN_INTERVAL_SECONDS` | Minimum seconds between `lastSeenAt` writes. Default example `60`. Must not exceed the idle TTL. |
| `AUTH_COOKIE_NAME` | Session cookie name. Development/test: `patchpilot.sid`. Production: `__Host-patchpilot.sid`. |
| `AUTH_COOKIE_SECURE` | `true` or `false`. Production must be `true`. `false` is allowed only for explicit loopback HTTP development/test. |
| `AUTH_CSRF_HEADER_NAME` | Header carrying the synchronizer token. Example `x-csrf-token`. |
| `AUTH_PASSWORD_MIN_LENGTH` | Minimum password characters. Must be at least `12`. |
| `AUTH_PASSWORD_MAX_BYTES` | Maximum password UTF-8 bytes. Must be at least the minimum length and at most `128`. |
| `AUTH_ARGON2_MEMORY_KIB` | Argon2id memory in KiB. Production minimum `19456`. Guarded test/development may use `8192`. Maximum `262144`. |
| `AUTH_ARGON2_TIME_COST` | Argon2id time cost. Production minimum `2`. Guarded test/development may use `1`. Maximum `6`. |
| `AUTH_ARGON2_PARALLELISM` | Argon2id parallelism. `1`–`4`. |
| `AUTH_LOGIN_RATE_LIMIT_IP_MAX` | Max `POST /auth/login` attempts per direct peer IP per window. `1`–`20`. |
| `AUTH_LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS` | IP limiter window. `30`–`3600`. |
| `AUTH_LOGIN_RATE_LIMIT_ACCOUNT_MAX` | Max attempts per normalized account digest per window. `1`–`20`. |
| `AUTH_LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS` | Account limiter window. `30`–`3600`. |
| `AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS` | Bounded Redis limiter operation timeout. `50`–`2000`. Login fails closed if Redis exceeds this. |

## Public (web)

| Variable | Purpose |
| --- | --- |
| `NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT` | Required public environment label (`development`, `test`, or `production`). `loadPublicConfigFrom` does not default it. Web `dev`/`build` scripts supply `development`/`production` only when the variable is unset, so a clean checkout can still build. |
| `NEXT_PUBLIC_API_BASE_URL` | Browser-visible API origin used by the web app for `fetch` to `apps/api` (`credentials: include`). No username, password, query, or fragment. Production must be `https`. Trailing slashes are stripped. Do not put CSRF tokens or session identifiers in this value. |

Do not add `DATABASE_URL`, Redis URLs, object-storage secrets, or API tokens to `NEXT_PUBLIC_*` files.

## Compose host ports (optional)

| Variable | Default | Purpose |
| --- | --- | --- |
| `PATCHPILOT_POSTGRES_PORT` | `55432` | Host port bound to `127.0.0.1`. |
| `PATCHPILOT_REDIS_PORT` | `16379` | Host port bound to `127.0.0.1`. |
| `PATCHPILOT_MINIO_API_PORT` | `19000` | Host port bound to `127.0.0.1`. |
| `PATCHPILOT_MINIO_CONSOLE_PORT` | `19001` | Host port bound to `127.0.0.1`. |

If you change these, also change `DATABASE_URL`, `REDIS_URL`, and `OBJECT_STORAGE_ENDPOINT` so applications still reach the services.

## Production notes

Production configuration must set `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production`, `PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS=false`, `LOG_PRETTY=false`, operator-supplied credentials (not `patchpilot-dev`, `not-for-production`, `minioadmin`, `changeme`, or `password` fragments), a Redis URL that includes a password, `AUTH_COOKIE_NAME=__Host-patchpilot.sid`, `AUTH_COOKIE_SECURE=true`, Argon2 parameters at or above OWASP minimums, an exact **https** CORS allowlist, and an object-storage bucket that is not a development placeholder. Bind addresses and TLS are operator responsibilities. Fastify `trustProxy` remains false; do not expect `X-Forwarded-For` to select the login rate-limit key.
