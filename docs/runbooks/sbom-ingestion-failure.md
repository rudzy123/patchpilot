# Runbook: SBOM ingestion failure

Use this when uploads fail, ingestions stall, documents are quarantined, or object-storage orphans appear. Architecture: [sbom-ingestion.md](../architecture/sbom-ingestion.md), [reliability-model.md](../architecture/reliability-model.md).

The pipeline is implemented end to end as of Session 8. There is still **no** retry API, **no** quarantine-release API, and **no** orphan cleanup job, so several recoveries below are direct database or bucket work by an instance operator.

## Symptoms

- API returns 400, 401, 403, 409, 413, 415, or 429 on upload.
- **SbomIngestion** stays `accepted`, `queued`, or `processing` and never reaches a terminal state.
- State is `rejected`, `quarantined`, or `failed` unexpectedly.
- **BackgroundJob** rows sit in `queued` with no queue activity.
- Object storage has keys with no **SBOM** row.

## Immediate actions

1. Confirm the **authorized organization** and asset id from the operator's membership. Do not query "all orgs."
2. Look up the ingestion by id **and** `organizationId`. Record `state`, `stage`, `parserVersion`, `failureCode`, `correlationId`, and the **BackgroundJob** `status` and `attempt`.
3. Check whether the worker process is running at all. The relay and the ingest processor are both in `apps/worker`; if it is down, everything downstream of `accepted` stalls.
4. Do **not** download or paste raw SBOM bytes, object keys, or filenames into tickets or chat. The `failureCode` and the SHA-256 are the safe identifiers.

## Classify by failure code

Every ingestion failure carries one code from the closed catalog in [sbom-ingestion.md](../architecture/sbom-ingestion.md#failure-taxonomy). The code determines the response; the state alone does not.

| Outcome | Codes | Response |
| --- | --- | --- |
| Rejected | `payload_too_large`, `content_type`, `utf8`, `json_syntax`, `json_depth`, `json_nodes`, `json_string_length`, `not_cyclonedx`, `unsupported_spec_version`, `schema_invalid`, `component_limit`, `edge_limit`, `identifier_length`, `tool_limit`, `reference_limit`, `property_limit`, `duplicate_bom_ref`, `unresolved_dependency_ref`, `invalid_purl`, `normalized_output_too_large` | The user must fix and re-upload. Do not requeue. Raising a limit is a **validated** configuration change, not an incident workaround. |
| Quarantined | `prototype_pollution`, `parser_timeout`, `parser_crash`, `hash_mismatch` | Human review. Never auto-release. |
| Retryable | `object_missing`, `storage_timeout`, `queue_unavailable` | Fix the infrastructure, then replay. |
| Terminal internal | `processing_failed` | A bug, a misconfiguration, missing state, or **objectKey** scope mismatch after reload. Investigate before replaying. |

`hash_mismatch` is the one to escalate. It means stored bytes no longer verify against the recorded digest, which is corruption or tampering, not a transient fault.

## Recovery

### Rejected at the API

Explain the stable error to the user. On a 4xx the upload usually never reached storage; if a temporary object was left behind, note it for the orphan section. There is currently no `sbom.upload_rejected` audit event, so API rejections are visible in logs and metrics only.

### Stuck `accepted` or `queued`

The outbox is the source of truth for unpublished work.

1. Check `outbox_event` for the ingestion's aggregate. `pending` means the relay has not published it.
2. If Redis is down, restore it. The relay drains the backlog when Redis returns; nothing is lost. See [outbox-backlog.md](outbox-backlog.md).
3. If the worker is down, restart it.
4. If the event is `processed` but no **BackgroundJob** row exists, the relay's per-batch reconcile creates one on the next pass. Give it a poll cycle before intervening.

### Stuck `processing`

1. Compare `background_job.lease_expires_at` to now. Within the lease, the job is legitimately running; parsing a large document can take up to `SBOM_PARSER_TIMEOUT_MS`.
2. Past the lease with no active worker, the row is claimable again, but **nothing redelivers it automatically**. There is no lease heartbeat and no requeue poller.
3. Replay the BullMQ job to resume. This is safe: the claim, the ingestion transition, and graph persistence are all idempotent, and the deterministic job id prevents a second parallel run.

### `queued` BackgroundJob after a retryable failure

This is the expected shape of a stall, not a bug in the state machine. A retryable failure returns both the ingestion and the job to `queued` in one transaction, then the handler throws. Because `sbom.ingest` is added without `attempts` or `backoff`, BullMQ does not reschedule it, and no poller picks it up.

Fix the underlying cause (object storage reachable, correct bucket, valid credentials), then replay the job. Confirm the ingestion reaches a terminal state afterwards.

### Quarantined

1. An `admin` or `owner` of **that** organization reviews the `failureCode`. The code only; never the payload.
2. `parser_timeout` and `parser_crash` mean the document beat the parser. Release only after a parser fix, and release by creating a **new** ingestion under the new `parserVersion` rather than re-running the old one.
3. `prototype_pollution` is a hostile-input signal. Treat it as a security event, not a parsing bug.
4. `hash_mismatch` means the evidence itself is suspect. Do not release. Verify the object's current digest against the **SBOM** row, check who has bucket write access, and escalate.
5. The object stays private and retained in every case. Quarantine preserves evidence.
6. There is no release API. `sbom.ingestion.released_from_quarantine` is specified but not yet emitted.

### Failed

`failed` means the ingestion can be requeued. Requeue the **same** **SbomIngestion**; do not ask the user to upload a second copy unless the bytes actually changed. A new upload of identical bytes deduplicates to the existing evidence anyway and will not produce a fresh ingestion.

### Orphan objects

No cleanup job exists. `SBOM_ORPHAN_GRACE_SECONDS` is a policy floor with no consumer.

1. List keys under `org/{organizationId}/assets/{assetId}/sboms/` and compare against **SBOM** rows for that organization.
2. Temporary keys (`.../sboms/tmp/{uploadId}`) older than the grace period with no in-flight upload are safe to delete.
3. Final keys (`.../sboms/sha256/{sha256}`) are **evidence**. Delete one only after confirming no **SBOM** row in any organization references that key, and only after the grace period. When in doubt, keep it.
4. Log the key template and the digest, not the key and not the bytes.

## Verification

- The ingestion reaches `completed` or a documented terminal state with a safe `failureCode`.
- A `sbom.ingestion.completed`, `.rejected`, `.quarantined`, or `.failed` audit event exists for the authorized organization.
- Replaying the same job does not duplicate component rows or audit events.
- No second organization's rows were touched.

## Escalation

Instance operators may inspect queue lag, worker health, and storage health. They must not dump another organization's SBOM. `hash_mismatch` and `prototype_pollution` warrant a security review; see [tenant-isolation-incident.md](tenant-isolation-incident.md) if cross-organization access is suspected. Product vulnerabilities: [SECURITY.md](../../SECURITY.md).
