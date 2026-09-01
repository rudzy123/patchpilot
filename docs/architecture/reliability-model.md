# Reliability model

PatchPilot v0.1 assumes **at-least-once** delivery of background work, **idempotent** handlers and relays, and no network/queue/object-storage I/O inside database transactions. Outbox: [ADR 0007](../adr/0007-transactional-outbox.md). Queue: [ADR 0006](../adr/0006-redis-bullmq.md).

Passing tests do not make a deployment production-ready. Each job type still needs an operational failure plan when implemented ([definition of done](../development/definition-of-done.md)).

## Write path

1. Validate at the HTTP or scheduler boundary.
2. Perform object-storage I/O **outside** a transaction (SBOM put; later, intelligence snapshot put).
3. Transaction: domain state + **OutboxEvent** + **AuditEvent**. No Redis, provider HTTP, or object-storage I/O inside that transaction.
4. Relay publishes to BullMQ; marks outbox `processedAt` (status `processed`). **OutboxEvent** `processed` means BullMQ **accepted** the job, not that the worker finished. Outbox row statuses are `pending`, `claimed`, `processed`, `failed`, `dead_lettered`. Delivery is at-least-once; the schema does not claim exactly-once.
5. Worker runs; retries; dead-letters poison. **BackgroundJob** represents actual processor execution. Statuses remain `pending`, `queued`, `running`, `succeeded`, `failed`, `dead_lettered`, `cancelled`. Terminal Session 9 sync runs remain historical; operator replay creates a **new** run rather than rewriting a terminal run.

If step 3 fails after step 2, an orphan object may exist. For tenant SBOM objects, a future reconcile job lists unreferenced keys in the org prefix and does not delete until retention policy says so. Intelligence snapshot orphans are instance-owned; their key layout is not defined yet and must not use a tenant org prefix.

If step 4 duplicates (relay retry), the queue may deliver twice. Handlers use `dedupeKey`.

## BackgroundJob lifecycle

States: `pending`, `queued`, `running`, `succeeded`, `failed`, `dead_lettered`, `cancelled`.

| From | To | Trigger |
| --- | --- | --- |
| (outbox written) | `pending` | Not yet published |
| `pending` | `queued` | Relay success |
| `queued` | `running` | Worker acquired |
| `queued` | `cancelled` | Operator cancel before start |
| `running` | `succeeded` | Handler completed idempotently |
| `running` | `failed` | Retryable error, attempts remaining |
| `running` | `dead_lettered` | Non-retryable poison or last attempt failed |
| `failed` | `queued` | Backoff retry |
| `failed` | `dead_lettered` | Max attempts |
| `dead_lettered` | `queued` | Operator replay |
| `running` | `queued` | Stalled lock recovery (worker crash) |

`succeeded`, `cancelled` are terminal. `dead_lettered` is terminal until replay.

### Stale jobs

A job is stale if it stays `running` past a visibility timeout (default 15 minutes, config). The worker lock expires; another worker may start. Handlers **must** be idempotent so double execution is safe.

Jobs referencing archived assets: SBOM ingest for archived assets should not be newly queued; in-flight jobs finish or cancel without creating a second org's data.

Reload outcomes in the implemented `sbom.ingest` processor:

| Reload result | Outcome |
| --- | --- |
| Payload not ids-only or not the expected event shape | `skipped`; nothing is mutated |
| **BackgroundJob** missing, or its organization does not match the payload | `retry` with `queue_unavailable`; nothing is mutated |
| BackgroundJob already `succeeded` | `already_complete` |
| BackgroundJob already terminal (`failed`, `dead_lettered`, `cancelled`) | Reported as failed; no re-execution |
| **SbomIngestion** missing or in another organization | Terminal `processing_failed` |
| **SBOM** row missing | `object_missing` (retryable) |
| Stored `objectKey` not a valid final key | Terminal `processing_failed` |

A tampered or mismatched organization never mutates tenant data: the org predicate is part of every reload query, so the row simply is not found ([tenant isolation](tenant-isolation.md)).

## Outbox relay (implemented)

The relay is a poll loop in `apps/worker`. Values below are the implemented constants, not proposals.

| Setting | Value |
| --- | --- |
| Poll interval | 1 s |
| Batch limit | 50 (persistence clamps any request to 100) |
| Claim lease | 30 s |
| Max publish attempts | 5 |
| Backoff | `min(900_000 ms, 5_000 ms * 2^(attempt-1))` scaled by jitter in `[0.5, 1.0)` |
| Queue | `patchpilot` |
| Job name | `sbom.ingest` |
| BullMQ job id | `{eventType}__{outboxEventId}` |

Claiming uses `FOR UPDATE SKIP LOCKED` over due `pending` rows ordered by `available_at`, then `id`, and fills any remaining batch capacity from `claimed` rows whose lease has expired. Expired-lease recovery is part of the claim query; there is no separate sweeper.

After BullMQ accepts a job the relay marks the event `processed` and creates or reuses the **BackgroundJob** row. Each batch then reconciles: `processed` events with no BackgroundJob row get one. Reconciliation creates the PostgreSQL row only and does **not** republish to BullMQ.

Two enum values are defined and never written by the relay: outbox `failed` and BackgroundJob `dead_lettered`. Relay poison goes to outbox `dead_lettered`; processor terminal failures set BackgroundJob `failed`. Do not build alerts on the unused values.

## Retry policy

| Class | Examples | Policy |
| --- | --- | --- |
| Transient publish | Redis unavailable during relay publish | Exponential backoff with jitter, 5 attempts, then outbox `dead_lettered` |
| Transient processing | Object-storage timeout, missing object, lost job claim | Ingestion and BackgroundJob return to `queued`; see the caveat below |
| Deterministic validation | CycloneDX schema, limit exceeded | No retry; ingestion `rejected` |
| Poison | Parser crash, timed-out parse, prototype-pollution keys, digest mismatch | No retry; ingestion `quarantined` |
| Authorization mismatch | Org mismatch on reload | No mutation; treated as a stalled delivery |

Backoff: `min(capped, base * 2^attempt)` with jitter. Relay defaults: base 5 s, cap 15 m.

### Processing retries do not resume on their own

The `sbom.ingest` job is added with a deterministic job id and no `attempts` or `backoff` options, so a thrown handler error does not schedule a BullMQ retry. There is also no poller that re-executes `queued` **BackgroundJob** rows. A retryable processing failure therefore leaves consistent, resumable state and then stops until an operator replays the job.

This is safe (the claim, the ingestion transition, and graph persistence are all idempotent) but it is **not** self-healing. A growing count of `queued` BackgroundJob rows with no queue activity is a stall. See [background job failure](../runbooks/background-job-failure.md).

## Idempotency

Tenant uniqueness always includes `organizationId`.

| Operation | Idempotency key |
| --- | --- |
| SBOM upload HTTP | `Idempotency-Key` + org |
| SBOM document | org + asset + sha256 |
| Outbox | org + `dedupeKey` |
| Finding create | org + asset + **versionless** component identity + **OSV id** |
| RiskCalculation | org + finding + `inputFingerprint` (canonical hash of reason, `policyDefinitionSha256`, sorted intel source record ids, `sbomIngestionId` or null, asset context version or null, override id or null). Intel refresh and ingest docs must use this same key — not a shorter `(finding, sourceRecordId, policyVersion)` tuple. |
| RiskAcceptance create | `Idempotency-Key` + org; at most one `active` acceptance per finding |
| Export create | `Idempotency-Key` + org |
| System intel refresh outbox | `eventType` + non-null `dedupeKey` (content SHA-256 of the source unit); unique on `(eventType, dedupeKey)` because `organizationId` is null. Do not treat unverified HTTP validators as the idempotency key. |
| Audit | Do not duplicate on replay: unique `(organizationId, action, subjectId, correlationId)` for tenant events. System events require a non-null `correlationId` and unique `(action, subjectId, correlationId)` where `organizationId` IS NULL. |

Replay of the same job twice produces one tenant-visible effect (required test).

## Queue duplication and races

- Two uploads of different hashes for one asset: both proceed; rescan compare and `lastSuccessfulSbomIngestionId` use the `completed` ingestion whose SBOM `receivedAt` is greatest, **not** the last worker to finish.
- Two workers correlating the same SBOM: unique constraints prevent duplicate findings; second worker updates observations idempotently.
- Risk acceptance vs rescan: last completed transaction wins; both leave audit rows.
- Intel refresh vs ingest: Session 9 import must not write Findings or `finding.recalculate`. When a later correlation session exists, calculations are append-only; last `currentRiskCalculationId` update is a compare-and-set on finding row version if needed.

## Poison and DLQ

Dead-lettered jobs retain payload **ids** only (no raw SBOM). Operators replay after fix. Metrics: `jobs_dead_lettered_total`, `ingestion_quarantined_total`.

## Data stores

| Store | Failure | Detection | Recovery |
| --- | --- | --- | --- |
| PostgreSQL | Unavailable | API 503, worker lag | Operator restore; do not skip migrations |
| Redis | Unavailable | Relay lag, publish errors | Outbox remains; drain when Redis returns. PostgreSQL is source of truth |
| Object storage | Unavailable | Upload 503 | No SBOM row; user retries |
| OSV/KEV | Outage | IntelligenceSource `degraded` (when runtime exists) | Last **accepted** catalog remains current; do not activate a partial import. See [vulnerability intelligence](vulnerability-intelligence.md). Session 9 import is design only. |

## Partial parse

Session 8 marks the ingestion `completed` after persist_graph succeeds. There is no Session 8 resume into `correlate`. Future correlation is a separate additive workflow and must not rewrite completed Session 8 rows. Do not leave a second organization's data mutated.

## Delivery semantics

Delivery is **at-least-once**. PatchPilot does **not** claim exactly-once processing. Idempotent consumers + org-scoped `dedupeKey` values make duplicates safe.

## Job leases

**OutboxEvent** and **BackgroundJob** have **separate** leases on separate rows.

| Lease | Column | Duration | Renewal |
| --- | --- | --- | --- |
| Relay claim | `outbox_event.lease_expires_at` | 30 s | Reclaimed by the next claim query when expired |
| Processor execution | `background_job.lease_expires_at` | `SBOM_PROCESSING_LEASE_MS` (SBOM ingest, default 15 min) or `INTELLIGENCE_KEV_JOB_LEASE_MS` (KEV sync, default 10 min) | SBOM ingest: none. KEV sync service: `renewLease` at stage boundaries and `INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS` |

Outbox `processed` is relay success (BullMQ accepted the job), not processor completion. `SbomIngestion.leaseExpiresAt` is unused in Session 8 and is never written; ingestion state is not a lock.

The BackgroundJob claim is one conditional `UPDATE` scoped by organization, succeeding only when the row is `queued` or is `running` with an expired lease, and it increments `attempt`. A lost claim is a conflict, and the processor treats it as a stalled delivery rather than proceeding unclaimed.

**SBOM ingest has no lease heartbeat.** `renewLease` exists on the port and Prisma adapter and is never called for Session 8 ingestion. The SBOM lease must therefore be longer than the worst-case run, and typed configuration enforces that `SBOM_PARSER_TIMEOUT_MS` and `OBJECT_STORAGE_OPERATION_TIMEOUT_MS` are both below `SBOM_PROCESSING_LEASE_MS`. Raising a timeout without raising the lease fails at process start rather than producing silent double execution.

The Batch 7B CISA KEV synchronization service renews the same BackgroundJob lease. It verifies ownership before external work and aborts HTTP, storage, and parser operations when renewal is lost. SyncRun has no lease fields. No worker currently starts that service, so production KEV jobs are not yet leased.

On expiry another worker may start (**lease theft** under clock skew: still safe because handlers are idempotent). Workers must not accept a client-supplied lease owner, and lease fields never appear in public API responses.

## Retry

Exponential backoff **with jitter**. Classify retryable vs not (see table above). Session 8 SBOM ingest still has no BullMQ `attempts`/`backoff`; a retryable failure leaves resumable state until an operator replays the job.

Session 9 Batch 7B bounds KEV execution attempts with `INTELLIGENCE_SYNC_MAX_ATTEMPTS` (default 5). Pre-snapshot retryable failures persist `retry_wait` and `nextAttemptAt`; the use case does not sleep. Post-snapshot retryable failures leave SyncRun in `stored`, `parsing`, `staging`, or `activating` and mark the BackgroundJob retryable so the next execution does not refetch CISA. Scheduler cadence and BullMQ intelligence redelivery are not implemented. Circuit-breaking, when implemented: after consecutive feed failures, **IntelligenceSource** → `degraded`; stop hammering; probe on a slow timer. Partial source units must not advance freshness.

## Timeouts and shutdown

Outbound HTTP and storage calls have timeouts. Session 8 storage/parser timeouts are typed configuration. Session 9 provider, parser, and object-storage timeouts are typed configuration; the Batch 7B service applies them when invoked. Graceful shutdown: stop leasing new jobs, finish or return the current lease, then exit. Forced kill relies on lease expiry. No intelligence scheduler currently leases jobs.

## Orphans and reconciliation

One reconciliation path is implemented: the relay's per-batch sweep that creates a missing **BackgroundJob** row for any `processed` outbox event.

Object-storage orphan cleanup is **not** implemented. `SBOM_ORPHAN_GRACE_SECONDS` (default 7 days, validated to exceed the idempotency TTL) is the policy floor a future job must honor; nothing reads it today. Orphans arise when a temporary-object delete fails, or when a promote succeeded and the database transaction then failed. The final object is intentionally retained in the second case because it may be the only copy of the evidence. See [SBOM ingestion](sbom-ingestion.md#orphan-reconciliation).

Still unimplemented and needed before those pipelines run: stale `running` sweeps, Session 9 import (scheduler, bounded provider retry, archive measurement, staging activation), intel orphan reconciliation, expired **RiskAcceptance**, and expired **manual_override** calculations. Runbooks: [docs/runbooks/](../runbooks/README.md).

## Backup, RPO, RTO (proposals)

These are **initial operational proposals**, not guarantees or contractual SLOs.

| Objective | Initial proposal | Notes |
| --- | --- | --- |
| RPO | ≤ 24 hours for PostgreSQL + object storage together | Operator-controlled backups ([OD-13](open-decisions.md)) |
| RTO | ≤ 8 hours to restore API/worker to accept uploads | Depends on operator runbooks |

Restore both stores together. Degraded mode during provider outages: last intel snapshots, freshness visible, no fake "all clear."

## Related documents

- [SBOM ingestion](sbom-ingestion.md)
- [Vulnerability intelligence](vulnerability-intelligence.md)
- [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)
- [Observability](observability.md)
- [Deployment model](deployment-model.md)
