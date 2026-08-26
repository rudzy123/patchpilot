# Deployment model

PatchPilot v0.1 is **self-hosted**. The project does not operate a multi-tenant SaaS control plane ([non-goals](../product/non-goals.md)). Local topology once apps are scaffolded: Docker Compose with PostgreSQL, Redis/BullMQ, MinIO, and `web` / `api` / `worker` ([MVP scope](../product/mvp-scope.md)).

This document is architecture, not a runbook. Runbooks are added when features are implemented.

## Deployable units

Three apps, one schema, shared packages ([ADR 0001](../adr/0001-modular-monolith.md)):

| Unit | Scales by | Notes |
| --- | --- | --- |
| `apps/web` | Stateless replicas | Talks to API only |
| `apps/api` | Stateless replicas | Sticky sessions not required if sessions are in PostgreSQL |
| `apps/worker` | Competing consumers | Same job types; idempotent |

Do not split these into independently owned microservices without an ADR.

## Local Compose (target)

```text
web → api
api → postgres, minio (S3 API), (outbox writes)
worker → postgres, redis, minio, outbound OSV/KEV
relay may run inside worker process
```

Production replaces Compose services with operator-managed PostgreSQL, Redis, and S3-compatible **private** storage ([OD-5](open-decisions.md)).

## Configuration

Only `packages/config` reads `process.env`. Production must:

- Require HTTPS termination (operator ingress).
- Disable development adapters (fake auth, unrestricted HTTP, unsigned webhooks).
- Require secrets for DB, Redis, object storage, session material, and credential KEK ([OD-4](open-decisions.md)).
- Set allowlists for OSV and KEV hosts.

Images and repos must not contain `.env` files with live secrets or default admin passwords.

## Network

- Browser reaches web and API.
- Redis, PostgreSQL, and object storage are not browser-accessible.
- Egress from worker to allowlisted intel hosts only (plus storage/DB/Redis).
- API needs egress to storage and DB, not to OSV, unless a future ADR moves refresh (v0.1: worker-only feed fetch).

## Migrations

Prisma migrations apply before new API/worker versions that need them. Prefer additive migrations. Do not destroy evidentiary tables as rollback ([release principles](../development/release-principles.md)).

## Backups

Operator duty ([OD-13](open-decisions.md)):

- PostgreSQL logical/physical backups **and** object-storage backups together (SBOMs are not only in the DB).
- Treat backups as **Restricted**. Encrypt at rest if the operator's platform supports it.
- Restoring backups does not grant a product-level cross-org console.

## AI

No AI provider in default deploy. If optional AI is enabled later, users supply keys at runtime; keys never ship in images ([ADR 0017](../adr/0017-optional-ai-user-credentials.md)).

## CLI

No Go CLI in v0.1 ([ADR 0018](../adr/0018-go-cli-deferred.md)).

## Related documents

- [Container architecture](container-architecture.md)
- [Reliability model](reliability-model.md)
- [Retention and deletion](retention-and-deletion.md)
