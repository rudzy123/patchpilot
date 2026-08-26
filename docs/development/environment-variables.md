# Environment variables

All server configuration is read in `@patchpilot/config`. Application, domain, and Next.js source must not read `process.env` directly. Public web values use `NEXT_PUBLIC_*` and `loadPublicConfig()` from `@patchpilot/config/public`.

Copy [`.env.example`](../../.env.example) to `.env`. Example values are **development placeholders and are unfit for production**.

## Server (required unless noted)

| Variable | Purpose |
| --- | --- |
| `PATCHPILOT_DEPLOYMENT_ENVIRONMENT` | `development`, `test`, or `production`. This flag, not `NODE_ENV` alone, gates development adapters. |
| `PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS` | Must be `false` in production. Pretty logs and placeholder credentials are development adapters. |
| `LOG_LEVEL` | Pino level (`fatal` … `silent`). |
| `LOG_PRETTY` | Pretty-print logs. Rejected when the deployment environment is `production`. |
| `API_HOST` | Fastify bind address. Local default `127.0.0.1`. |
| `API_PORT` | Fastify bind port. Local default `3001`. |
| `WEB_PORT` | Documented Next.js port. Local default `3000`. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated exact origin allowlist. `*` is rejected. |
| `DATABASE_URL` | PostgreSQL URL. Never logged. |
| `REDIS_URL` | Redis URL. Never logged. |
| `OBJECT_STORAGE_ENDPOINT` | S3-compatible endpoint (local MinIO). |
| `OBJECT_STORAGE_ACCESS_KEY` | Object-storage access key. |
| `OBJECT_STORAGE_SECRET_KEY` | Object-storage secret. |
| `OBJECT_STORAGE_BUCKET` | Bucket name. Bucket creation is deferred until object operations exist. |
| `OBJECT_STORAGE_USE_SSL` | `true` or `false`. |
| `OTEL_ENABLED` | Enables OpenTelemetry SDK initialization. |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | Optional OTLP HTTP traces endpoint. |
| `READINESS_TIMEOUT_MS` | Budget for readiness probes. |
| `SHUTDOWN_TIMEOUT_MS` | Graceful shutdown budget. |
| `REQUEST_BODY_LIMIT_BYTES` | Fastify body limit. |
| `REQUEST_ID_HEADER` | Incoming/outgoing request id header. Default `x-request-id`. |
| `CORRELATION_ID_HEADER` | Incoming/outgoing correlation id header. Default `x-correlation-id`. |

## Public (web)

| Variable | Purpose |
| --- | --- |
| `NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT` | Public environment label (`development`, `test`, or `production`). The app name is hardcoded as `PatchPilot`. |

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

Production configuration must set `PATCHPILOT_DEPLOYMENT_ENVIRONMENT=production`, `PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS=false`, `LOG_PRETTY=false`, operator-supplied credentials (not `patchpilot-dev`, `not-for-production`, `minioadmin`, `changeme`, or `password` fragments), and an exact CORS allowlist. Bind addresses and TLS are operator responsibilities.
