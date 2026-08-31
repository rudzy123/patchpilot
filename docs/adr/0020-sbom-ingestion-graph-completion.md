# ADR 0020: Session 8 SBOM ingestion graph completion

- Status: Accepted
- Date: 2026-08-29
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted for implementation on this branch. Merge to `main` remains subject to normal pull-request review. This ADR does not supersede [ADR 0009](0009-cyclonedx-json.md) (format), [ADR 0007](0007-transactional-outbox.md) (outbox), [ADR 0006](0006-redis-bullmq.md) (queue), or [ADR 0008](0008-private-object-storage.md) (storage keys). It records the Session 8 meaning of **SBOMIngestion** `completed` and related upload/processing contracts.

## Context

Architecture documents previously described ingestion `completed` only after correlate, enrich, and score. Session 8 implements CycloneDX JSON upload, private evidence storage, and normalized graph persistence, and explicitly excludes vulnerability correlation, findings, intelligence enrichment, risk scoring, and remediation.

Leaving the old completion rule in force would make Session 8 ingestions never complete, or would force unimplemented work into this session. Redefining `completed` in-place later (after correlation ships) would rewrite history of Session 8 rows.

Synchronous `JSON.parse` and Ajv validation cannot be cancelled with `Promise.race`. A wall-clock parser budget that claims preemption without a separate isolate is false.

## Decision

### Format and HTTP

Accept **CycloneDX JSON** `specVersion` **1.4**, **1.5**, and **1.6** only. Reject other versions, SPDX, XML, archives, and remote-URL ingest.

Upload contract for v0.1 Session 8:

- `POST /assets/:assetId/sboms`
- Raw request-body stream (`application/vnd.cyclonedx+json` or `application/json`)
- No multipart; no Fastify JSON parse for this route
- UTF-8 only; optional UTF-8 BOM may be stripped; unsupported charset or unknown media-type parameters rejected
- Exactly one document per request
- Required `Idempotency-Key` (raw key not persisted; `SHA-256("patchpilot-idempotency-v1:" + rawKey)`)
- No client filename, `organizationId`, hash, byte length, parser version, object key, or ingestion status
- **202 Accepted** after private object persistence and an atomic PostgreSQL commit of SBOM metadata, ingestion, audit, idempotency finalization, and outbox
- `Cache-Control: private, no-store`

No web upload UI. No retry or quarantine-release HTTP API.

### Storage and delivery

Original bytes stay in **private**, tenant-and-Asset-scoped object storage. Keys:

```text
org/{organizationId}/assets/{assetId}/sboms/tmp/{uploadId}
org/{organizationId}/assets/{assetId}/sboms/sha256/{sha256}
```

No public ACL, no signed URLs, no application download route, no global cross-organization deduplication. Object bodies never enter PostgreSQL.

Durable work uses the transactional outbox, then a worker relay publishes to **BullMQ**. Delivery is **at-least-once**. Relays and processors are idempotent. Redis is not called inside a PostgreSQL transaction.

`OutboxEvent` `processed` means BullMQ **accepted** the job. **BackgroundJob** tracks processor execution. Those leases are separate. `SbomIngestion.leaseExpiresAt` is unused in Session 8.

### Meaning of `completed`

Session 8 uses stages **`validate`**, **`parse`**, and **`persist_graph`** only. Frozen enum values **`correlate`**, **`enrich`**, and **`score`** remain unused.

`completed` means all of the following succeeded:

1. Stored evidence was re-read from the stored object key.
2. Byte length and SHA-256 were verified.
3. JSON parse and structural limits passed.
4. Allowlisted CycloneDX schema validation passed.
5. Semantic limits passed.
6. Normalized component graph persistence committed.

`completed` does **not** mean exhaustive software inventory, vulnerability correlation, finding creation, intelligence enrichment, risk scoring, or remediation.

`graphCompleteness` on a completed ingestion is one of: `empty`, `no_dependencies`, `partial`, `complete`.

- `empty` does not mean the Asset contains no software.
- `no_dependencies` does not prove the software has no dependencies.
- `complete` means the document’s dependency graph was fully represented after validation, not that the product inventory is exhaustive.

Future correlation is a **separate additive workflow**. It must not rewrite the meaning or history of a completed Session 8 ingestion row.

### Graph rules

- Unknown `dependsOn` targets: reject the ingestion (`unresolved_dependency_ref`).
- Duplicate non-null `bom-ref` values in one ingestion: reject.
- Self-dependency edges: skip and count as warnings (database forbids self-edges; skipping avoids rejecting an otherwise usable document).
- Cycles: preserve.
- Duplicate evidence (`organizationId` + `assetId` + SHA-256): reuse the existing SBOM and ingestion resource. Do not insert a `duplicate`-state ingestion row. Do not enqueue a second outbox event.

### Parser time budget

The parser wall-clock budget is enforced by **worker-thread termination**, not by `Promise.race` around synchronous `JSON.parse` or Ajv. A timeout promise cannot preempt CPU-bound work on the same isolate. I/O (object GET) may use `AbortSignal`. The processing lease is an execution lock, not a parser kill switch.

### Unknown versions

Components may lack a version. Persistence will use `version_known = false` and an empty `version` placeholder that is not a real package version. Future matching must not treat that as affected or safe. That column is a later forward-only migration, not this documentation batch.

## Alternatives considered

- **Keep `completed` until correlate/enrich/score:** Session 8 could never complete; rejected.
- **Mark Session 8 success as `processing` at `persist_graph`:** operators and APIs would never see success; rejected.
- **Multipart upload:** extra parts, filenames, and archive risk; rejected for v0.1.
- **Parsed JSON body on the API:** destroys original bytes and SHA-256 fidelity; rejected.
- **Optional Idempotency-Key:** retry storms duplicate accepted work; rejected.
- **Skip BullMQ / claim only in PostgreSQL:** conflicts with [ADR 0006](0006-redis-bullmq.md); rejected.
- **`Promise.race` parser timeout:** does not cancel synchronous parse/validation; rejected as a control.
- **Child-process parser:** valid preemption; heavier than `worker_threads` for pure JS Ajv; reserved if threads prove insufficient.
- **Streaming JSON parser in Session 8:** not required while upload bytes are capped; Ajv still needs an object; deferred.
- **Silent drop of unknown dependency refs:** would persist a knowingly incomplete graph as valid; rejected.
- **Reject the whole document on self-edges:** the self-edge cannot be stored; skipping with a warning preserves remaining evidence.

## Consequences

Operators can treat Session 8 `completed` as “graph stored from verified CycloneDX evidence.” Finding queues remain empty until a later session. Documentation and APIs must expose `graphCompleteness` so empty or dependency-less documents are not read as “no software” or “no dependencies.”

A later correlation session must add work (new jobs and/or new ingestions), not mutate completed Session 8 rows into a new meaning of `completed`.

## Security and tenancy

Organization scope comes from `TrustedActor`, never from a client `organizationId`. Object keys include organization and asset. Duplicate SHA-256 across organizations does not share objects. Audit may include SHA-256 (Confidential) and must not include object keys, filenames, bodies, or parser excerpts. No SSRF via document URLs.

## Operational failure plan

Object put then database failure: no success audit, no Redis publish, final object may be an orphan; reconcile after grace. Parser timeout: terminate the worker thread; quarantine. Unknown refs / schema / limits: `rejected`, no retry. Poison: `quarantined`, no automatic retry. Retry HTTP is deferred.

Limits are typed configuration with floors and ceilings. They remain initial recommendations until performance-tested.

## Follow-up

Runtime batches: contracts, migration (`version_known`, bom-ref uniqueness, `graphCompleteness`), object-storage adapter, upload/idempotency, API routes, outbox relay, parser thread, graph persist. Vendored CycloneDX schemas and parser dependencies are a later batch. No web UI in Session 8.
