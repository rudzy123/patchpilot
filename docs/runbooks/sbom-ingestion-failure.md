# Runbook: SBOM ingestion failure

Use this when uploads fail, ingestions stall, documents are quarantined, or object-storage orphans appear. Architecture: [sbom-ingestion.md](../architecture/sbom-ingestion.md), [reliability-model.md](../architecture/reliability-model.md).

## Symptoms

- API returns validation, 413, or `unprocessable_evidence` on upload.
- **SBOMIngestion** stays `queued` or `processing` beyond the job lease.
- State is `rejected`, `failed`, `quarantined`, or `duplicate` unexpectedly.
- Findings do not appear after a successful HTTP upload.
- Object storage has keys with no **SBOM** row.

## Immediate actions

1. Confirm **authorized organization** and asset id from the operator's membership. Do not query "all orgs."
2. Look up the ingestion by id **and** `organizationId`. Record `state`, `stage`, `parserVersion`, `errorCode`, `correlationId` / `jobId`.
3. Check metrics: `ingestion_state_transitions`, `jobs_dead_lettered_total`, `ingestion_quarantined_total`, upload reject reason.
4. Do **not** download or paste raw SBOM bytes into tickets or chat.

## Classify

| Class | Typical `errorCode` / state | Retry? |
| --- | --- | --- |
| Client validation | content-type, PDF/archive, size, specVersion | No — user must fix the document |
| Limit exceeded | depth, components, edges, string length | No unless operator raises a **validated** config limit |
| Duplicate | `duplicate` | No job — return existing SBOM |
| Transient | storage timeout, DB serialization | Yes — job backoff |
| Poison | `quarantined` | No automatic retry |
| Terminal attempts | `failed` | Operator requeue same ingestion |

## Recovery

### Rejected at the API

Explain the stable error to the user. No object should exist; if an orphan key appeared, note it for the cleanup job. Write or confirm `sbom.upload_rejected` audit if a DB write occurred.

### Stuck `queued` / `processing`

1. Check Redis/BullMQ and outbox `publishedAt`.
2. If the worker is down, restore it; the outbox is the source of unpublished work.
3. If the job lease expired, another worker should take the job. If not, inspect stalled `running` jobs ([background-job-failure.md](background-job-failure.md)).
4. Replay is allowed only because handlers are idempotent.

### Quarantined

1. `admin`/`owner` of **that** organization reviews `quarantineReason` (code only).
2. Release to `queued` only after a parser fix or confirmed false quarantine.
3. Otherwise mark `failed` and keep the object as evidence.
4. Audit `sbom.released_from_quarantine` or leave quarantined.

### Failed after retries

Requeue the **same** **SBOMIngestion** (`failed` → `queued`). Do not upload a second copy unless bytes changed.

### Orphan objects

List keys under `org/{organizationId}/...` with no **SBOM** row. After the grace period in [retention-and-deletion.md](../architecture/retention-and-deletion.md), delete orphans. Log hash and key template, not bytes.

### Partial graph persist

If `stage` is `correlate` or later and components exist, resume from that stage. Do not delete the graph. Do not mark `completed` until correlate, enrich, and score finish. Do not run a job for another organization. Do not apply finding-state updates unless this ingestion is **current** (greatest SBOM `uploadedAt` among `completed`).

## Verification

- Ingestion reaches `completed` or a documented terminal state.
- Findings and **RiskCalculation** exist only for the authorized organization.
- Replay of the same job does not duplicate findings or audit events.

## Escalation

Instance operators may inspect queue lag and storage health. They must not dump another organization's SBOM. Product vulnerabilities: [SECURITY.md](../../SECURITY.md).
