# Runbook: background job failure

Use this for outbox/BullMQ lag, retries, lease expiry, or duplicate delivery. Architecture: [reliability-model.md](../architecture/reliability-model.md). PatchPilot does **not** claim exactly-once processing.

One job type exists today: `sbom.ingest`, run by `apps/worker` with `concurrency: 1`.

## The most important behavior to know

`sbom.ingest` is enqueued with a deterministic job id and **no** `attempts` or `backoff` options, and there is **no** poller that re-executes `queued` **BackgroundJob** rows. So when a handler returns a retryable outcome:

1. The ingestion and the BackgroundJob both return to `queued` in one transaction.
2. The handler throws so BullMQ records a failure.
3. Nothing redelivers the job.

State is left consistent and idempotently resumable, but recovery is an **operator replay**, not an automatic retry. Treat `queued` BackgroundJob rows with no queue activity as a stall.

## Symptoms

- Outbox rows accumulating unpublished ([outbox backlog](outbox-backlog.md)).
- **BackgroundJob** rows in `queued` that never move to `running`.
- Rows in `running` past `lease_expires_at`.
- Rows in `failed`.
- Worker crash loops.

## Immediate actions

1. Identify `jobId`, `jobType`, `organizationId`, `outboxEventId`, and `correlationId`.
2. Reload the aggregate from PostgreSQL. **Do not trust a payload's organizationId.** The job payload carries ids only, and every processor query applies an organization predicate.
3. If a payload org does not match persisted state, the row simply is not found and nothing is mutated. Investigate as a [tenant-isolation incident](tenant-isolation-incident.md) if that was unexpected.
4. Do not put SBOM bodies on the queue or into the ticket.

## Classify

| Class | Job outcome | Retry |
| --- | --- | --- |
| Transient storage or lost claim | Back to `queued` (`storage_timeout`, `object_missing`, `queue_unavailable`) | Operator replay |
| Deterministic validation | `failed` with a rejected-class code | No; the user re-uploads |
| Poison or parse timeout | `failed`, ingestion `quarantined` | No; human review |
| Aggregate missing or org mismatch | `failed` with `processing_failed`, or no mutation at all | No; investigate first |
| Already terminal | `already_complete`, or reported as failed | No-op; this is idempotency working |
| Duplicate delivery | No second effect | Deterministic job id plus unique `outbox_event_id` |

## Recovery

### Unpublished outbox

Restore Redis or the worker. The relay publishes remaining rows; PostgreSQL is the source of truth. See [outbox backlog](outbox-backlog.md).

### `queued` with no activity

Fix the underlying cause, then replay the BullMQ job. The claim is a conditional `UPDATE` requiring `queued` or an expired `running` lease, so a replay cannot double-run a job another worker currently holds.

### `running` past the lease

There is no heartbeat: `renewLease` exists on the port and adapter and is never called. A `running` row past its lease means the worker died, or the run genuinely exceeded `SBOM_PROCESSING_LEASE_MS` (default 15 minutes).

The row is claimable again, but nothing redelivers it. Replay the job. Double execution is safe because graph persistence is insert-once per `sbomIngestionId`, but if runs routinely approach the lease, raise `SBOM_PROCESSING_LEASE_MS` rather than tolerating the overlap. Configuration requires the parser and object-storage timeouts to stay below the lease, so raise the lease first.

### Terminal failure

Fix the code or data, then replay. Confirm afterwards that the tenant-visible effect happened exactly once. BackgroundJob terminal failures use status `failed`; the `dead_lettered` enum value exists but is never written today.

### Cancel

Only `queued` jobs may move to `cancelled` before start. Do not cancel another organization's job.

### Graceful shutdown

The worker stops accepting work, closes the ingest processor, stops the relay (aborting its poll delay and letting the in-flight batch finish), quits Redis, then shuts down telemetry. A forced kill relies on lease expiry, which without a heartbeat means up to the full lease before the job is claimable again.

## Verification

- Lag returning toward the SLO proposals in [observability.md](../architecture/observability.md).
- No second organization's rows mutated.
- Audit events not duplicated for the same `(organizationId, action, subjectId, correlationId)`.
- The related **SbomIngestion** reached a terminal state, not just the job.

## Escalation

Instance operator: Redis, PostgreSQL, and object-storage health. Organization admin: only their own ingestions and findings.
