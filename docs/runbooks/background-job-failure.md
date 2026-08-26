# Runbook: background job failure

Use this for outbox/BullMQ lag, retries, dead letters, lease expiry, or duplicate delivery. Architecture: [reliability-model.md](../architecture/reliability-model.md). PatchPilot does **not** claim exactly-once processing.

## Symptoms

- Outbox rows with null `publishedAt` accumulating.
- Queue lag / `running` jobs past the visibility timeout.
- Job state `failed` or `dead_lettered`.
- Duplicate-looking findings (should be prevented by unique keys).
- Worker crash loops.

## Immediate actions

1. Identify `jobId`, `eventType`, `organizationId` (if tenant work), `correlationId`.
2. Reload the aggregate from PostgreSQL. **Do not trust payload organizationId.**
3. If payload org ≠ persisted org: leave `dead_lettered`, do not "fix" by writing to the payload org. Treat as a [tenant-isolation incident](tenant-isolation-incident.md) if unexpected.
4. Do not put SBOM bodies on the queue or into the ticket.

## Classify

| Class | Retry | Notes |
| --- | --- | --- |
| Transient (DB, Redis, S3 503, feed 429) | Yes, exponential backoff with jitter | Default five attempts (configurable proposal) |
| Validation | No | Ingestion `rejected` |
| Poison / parse timeout | No | Quarantine + DLQ |
| Org mismatch / aggregate missing | No | DLQ |
| Duplicate delivery | N/A | Handler no-ops via `dedupeKey` |

## Recovery

### Unpublished outbox

Restore Redis if needed. Relay publishes remaining rows. PostgreSQL is the source of truth.

### Stale `running` (lease expired)

Another worker may start. Idempotent handlers make double execution safe. If a crash left a parse half-done, resume from `stage`.

### Dead letter

Fix the code or data, then operator replay: `dead_lettered` → `queued`. Replay tests must still show one tenant-visible effect.

### Cancel

Only `queued` jobs may move to `cancelled` before start. Do not cancel another organization's job.

### Graceful shutdown

Workers should stop taking new jobs, finish the current handler or return the lease, then exit. Forced kill relies on lease expiry.

## Verification

- Lag returning toward SLO proposals in [observability.md](../architecture/observability.md).
- No second organization's rows mutated.
- Audit events not duplicated for the same `(organizationId, action, subjectId, correlationId)` where that uniqueness applies.

## Escalation

Instance operator: Redis/Postgres health. Organization admin: only their ingestions/findings.
