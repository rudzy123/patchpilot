# Runbook: local infrastructure failure

Use this when PostgreSQL, Redis, or MinIO on the developer workstation will not start, stay healthy, or accept connections. This is a **local Compose** failure plan. It is not a production incident process.

Compose file: `deploy/compose/compose.yaml`. Apps are not in Compose; start them with `pnpm dev`.

## Symptoms

- `pnpm infrastructure:up` exits non-zero or hangs on `--wait`.
- `pnpm test:integration` fails with connection errors.
- API `/health/ready` returns `503` with check name `database` `down`.
- Worker prints that PostgreSQL or Redis is not ready.
- MinIO console or API port refuses connections.

## Immediate actions

1. Confirm Docker is running: `docker info`.
2. Confirm Compose v2: `docker compose version`.
3. From the repository root: `pnpm infrastructure:status` (container names, ports, and health). Then `pnpm infrastructure:logs` if a service is not healthy.
4. Do not paste connection strings, MinIO root credentials, or `.env` contents into tickets or logs.

## Classify

| Class | Typical cause | Next step |
| --- | --- | --- |
| Daemon down | Docker Engine not running | Start Docker; retry `pnpm infrastructure:up` |
| Port conflict | Host port already bound | Change `PATCHPILOT_*_PORT` in `.env` and matching URLs |
| Unhealthy container | Image pull, volume, or healthcheck | Inspect `docker compose ... logs` for that service |
| Credential mismatch | `.env` does not match Compose literals | Align with `.env.example`; restart Compose |
| Bind not localhost | Accidental `0.0.0.0` publish | Keep `127.0.0.1` publishes from `compose.yaml` |

## Recovery

### PostgreSQL

Healthcheck is `pg_isready -U patchpilot -d patchpilot`. If the volume is corrupt, `pnpm infrastructure:down` then remove the named volume `patchpilot_postgres` **only if you can lose local data**. Re-apply `pnpm db:migrate` after a fresh volume.

### Redis

Healthcheck is `redis-cli ping`. Local Redis has no password. Production Redis must be authenticated; do not copy this Compose Redis into production.

### MinIO

Healthcheck is `GET /minio/health/live`. There is no MinIO SDK and no guaranteed bucket in this foundation. Object operations are deferred. If curl is missing inside the image, the healthcheck will fail even when the API listens; replace the image pin or healthcheck after confirming with `curl http://127.0.0.1:19000/minio/health/live` from the host.

## Data loss warning

Named volumes persist across `compose down`. `compose down -v` deletes them. That is acceptable for local placeholder data only.

## Related

- [Local setup](../development/local-setup.md)
- [Environment variables](../development/environment-variables.md)
- [Background job failure](background-job-failure.md) (product jobs are not registered yet)
