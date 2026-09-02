# Runbook: background job failure

Use this for outbox/BullMQ lag, retries, lease expiry, or duplicate delivery. Architecture: [reliability-model.md](../architecture/reliability-model.md). PatchPilot does **not** claim exactly-once processing.

Two job types exist today: `sbom.ingest` and `intelligence.sync`, run by `apps/worker` on the shared `patchpilot` queue with `concurrency: 2`.

## The most important behavior to know

`sbom.ingest` is enqueued with a deterministic job id and **no** `attempts` or `backoff` options, and there is **no** poller that re-executes queued SBOM **BackgroundJob** rows. So when that handler returns a retryable outcome:

1. The ingestion and the BackgroundJob both return to `queued` in one transaction.
2. The handler throws so BullMQ records a failure.
3. Nothing redelivers the SBOM job.

SBOM state is left consistent and idempotently resumable, but SBOM recovery is an **operator replay**. Treat queued SBOM BackgroundJob rows with no queue activity as a stall.

`intelligence.sync` is different: PostgreSQL `retry_wait` / queued job state is retry-intent authority. The worker retry reconciler redispatches due intelligence work. BullMQ delayed jobs are a fast path only. BullMQ `attemptsMade` is not the attempt authority. The periodic KEV scheduler does not redispatch `retry_wait`.

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

There is no heartbeat for **SBOM ingest**: `renewLease` exists on the port and adapter and is never called for Session 8. A `running` SBOM row past its lease means the worker died, or the run genuinely exceeded `SBOM_PROCESSING_LEASE_MS` (default 15 minutes).

The row is claimable again, but nothing redelivers an SBOM job. Replay the job. Double execution is safe because graph persistence is insert-once per `sbomIngestionId`, but if runs routinely approach the lease, raise `SBOM_PROCESSING_LEASE_MS` rather than tolerating the overlap. Configuration requires the parser and object-storage timeouts to stay below the lease, so raise the lease first.

KEV synchronization renews the same BackgroundJob lease during execution. After lease expiry, another worker may claim the job and resume from persisted SyncRun state. Shutdown does not mark the SyncRun failed.

### Terminal failure

Fix the code or data, then replay. Confirm afterwards that the tenant-visible effect happened exactly once. BackgroundJob terminal failures use status `failed`; the `dead_lettered` enum value exists but is never written today.

### Cancel

Only `queued` jobs may move to `cancelled` before start. Do not cancel another organization's job.

### Graceful shutdown

Committed `apps/worker` stop order:

1. `acceptingWork` becomes false.
2. Intelligence runtime stop: abort in-flight synchronization (cancellation), then the KEV scheduler stops, then the retry reconciler stops.
3. Queue worker intake closes.
4. Outbox relay closes.
5. Intelligence redispatch/queue publisher resources close.
6. Redis quits.
7. Telemetry shuts down where present.
8. Prisma disconnects last.

Shutdown does **not** terminally fail a SyncRun solely because the process is stopping. A forced kill relies on lease-expiry recovery: another worker may claim the BackgroundJob after `lease_expires_at`. Session 9 KEV work renews the BackgroundJob lease during execution; SBOM ingest still has no heartbeat, so its lease must exceed the worst-case run.

## Verification

- Lag returning toward the SLO proposals in [observability.md](../architecture/observability.md).
- No second organization's rows mutated.
- Audit events not duplicated for the same `(organizationId, action, subjectId, correlationId)`.
- The related **SbomIngestion** reached a terminal state, not just the job.

## Escalation

Instance operator: Redis, PostgreSQL, and object-storage health. Organization admin: only their own ingestions and findings.
