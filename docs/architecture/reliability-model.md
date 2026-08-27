# Reliability model

PatchPilot v0.1 assumes **at-least-once** delivery of background work, **idempotent** handlers and relays, and no network/queue/object-storage I/O inside database transactions. Outbox: [ADR 0007](../adr/0007-transactional-outbox.md). Queue: [ADR 0006](../adr/0006-redis-bullmq.md).

Passing tests do not make a deployment production-ready. Each job type still needs an operational failure plan when implemented ([definition of done](../development/definition-of-done.md)).

## Write path

1. Validate at the HTTP or scheduler boundary.
2. Perform object-storage I/O **outside** a transaction (SBOM put).
3. Transaction: domain state + **OutboxEvent** + **AuditEvent**.
4. Relay publishes to BullMQ; marks outbox `processedAt` (status `processed`). Outbox row statuses are `pending`, `claimed`, `processed`, `failed`, `dead_lettered`. Delivery is at-least-once; the schema does not claim exactly-once.
5. Worker runs; retries; dead-letters poison. **BackgroundJob** statuses remain `pending`, `queued`, `running`, `succeeded`, `failed`, `dead_lettered`, `cancelled`.

If step 3 fails after step 2, an orphan object may exist. A reconcile job lists unreferenced keys in the org prefix and does not delete until retention policy says so.

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

Jobs whose aggregate is missing: `dead_lettered` with reason `aggregate_not_found` after reload.

Tampered/mismatched organization: `dead_lettered`, no mutation ([tenant isolation](tenant-isolation.md)).

## Retry policy

| Class | Examples | Policy |
| --- | --- | --- |
| Transient | PostgreSQL serialization, Redis blip, S3 503, OSV 429/5xx | Exponential backoff, default 5 attempts |
| Deterministic validation | CycloneDX schema, limit exceeded | No retry; ingestion `rejected` |
| Poison | Parser crash, timed-out parse, prototype pollution keys | No retry; quarantine + `dead_lettered` |
| Authorization mismatch | Org mismatch on reload | No retry; `dead_lettered` |

Backoff: `min(capped, base * 2^attempt)` with jitter. Defaults: base 5s, cap 15m.

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
| System intel refresh outbox | `eventType` + non-null `dedupeKey` (cursor/`payloadSha256`); unique on `(eventType, dedupeKey)` because `organizationId` is null |
| Audit | Do not duplicate on replay: unique `(organizationId, action, subjectId, correlationId)` for tenant events. System events require a non-null `correlationId` and unique `(action, subjectId, correlationId)` where `organizationId` IS NULL. |

Replay of the same job twice produces one tenant-visible effect (required test).

## Queue duplication and races

- Two uploads of different hashes for one asset: both proceed; rescan compare and `lastSuccessfulSbomIngestionId` use the `completed` ingestion whose SBOM `uploadedAt` is greatest, **not** the last worker to finish.
- Two workers correlating the same SBOM: unique constraints prevent duplicate findings; second worker updates observations idempotently.
- Risk acceptance vs rescan: last completed transaction wins; both leave audit rows.
- Intel refresh vs ingest: calculations are append-only; last `currentRiskCalculationId` update is a compare-and-set on finding row version if needed.

## Poison and DLQ

Dead-lettered jobs retain payload **ids** only (no raw SBOM). Operators replay after fix. Metrics: `jobs_dead_lettered_total`, `ingestion_quarantined_total`.

## Data stores

| Store | Failure | Detection | Recovery |
| --- | --- | --- | --- |
| PostgreSQL | Unavailable | API 503, worker lag | Operator restore; do not skip migrations |
| Redis | Unavailable | Relay lag, publish errors | Outbox remains; drain when Redis returns. PostgreSQL is source of truth |
| Object storage | Unavailable | Upload 503 | No SBOM row; user retries |
| OSV/KEV | Outage | IntelligenceSource `degraded` | Use last snapshot; see [vulnerability intelligence](vulnerability-intelligence.md) |

## Partial parse

If persist_graph succeeds and correlate fails transiently, resume from stage `correlate` without deleting components. The ingestion stays `processing` (not `completed`). Do not leave a second organization's data mutated.

## Delivery semantics

Delivery is **at-least-once**. PatchPilot does **not** claim exactly-once processing. Idempotent consumers + org-scoped `dedupeKey` values make duplicates safe.

## Job leases

`running` jobs hold a lease (`leaseExpiresAt`). Ingestion processing uses **that same lease**, not a second independent lock. Initial recommendation: 15 minutes, configurable, validate under load. Heartbeat while working. On expiry another worker may start (**lease theft** if clocks skew: still safe if idempotent). Workers must not accept a client-supplied lease owner.

## Retry

Exponential backoff **with jitter**. Classify retryable vs not (see table above). Circuit-breaking: after consecutive feed failures, **IntelligenceSource** → `degraded`; stop hammering; probe on a slow timer.

## Timeouts and shutdown

Outbound HTTP and storage calls have timeouts (intel defaults in [vulnerability-intelligence.md](vulnerability-intelligence.md)). Graceful shutdown: stop leasing new jobs, finish or return the current lease, then exit. Forced kill relies on lease expiry.

## Orphans and reconciliation

Orphan object cleanup after grace period. Reconciliation jobs: unpublished outbox, stale `running`, intel cursor stuck, expired **RiskAcceptance**, expired **manual_override** calculations. Runbooks: [docs/runbooks/](../runbooks/README.md).

## Backup, RPO, RTO (proposals)

These are **initial operational proposals**, not guarantees or contractual SLOs.

| Objective | Initial proposal | Notes |
| --- | --- | --- |
| RPO | ≤ 24 hours for PostgreSQL + object storage together | Operator-controlled backups ([OD-13](open-decisions.md)) |
| RTO | ≤ 8 hours to restore API/worker to accept uploads | Depends on operator runbooks |

Restore both stores together. Degraded mode during provider outages: last intel snapshots, freshness visible, no fake "all clear."

## Related documents

- [SBOM ingestion](sbom-ingestion.md)
- [Observability](observability.md)
- [Deployment model](deployment-model.md)
