# Data flow

This document traces the v0.1 [MVP journey](../product/mvp-scope.md) through the modular monolith. It is a control-flow and evidence-flow description, not a network packet capture.

Authorization context is established as in [tenant isolation](tenant-isolation.md). Limits and poison handling are in [SBOM ingestion](sbom-ingestion.md). Session 8 upload, parse, and graph persist follow [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md): stages `validate`, `parse`, and `persist_graph` only. Session 9 catalog import follows [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md). Batch 8B schedules KEV work and processes `intelligence.sync` on the shared worker queue. Batch 9B adds sanitized authenticated provider-status GETs ([ADR 0022](../adr/0022-intelligence-provider-status-authorization.md)). Those GETs do not call CISA, Redis, BullMQ, MinIO, the parser, or the scheduler. Correlation, enrichment, scoring, findings, remediation, dashboards, and manual synchronization remain later additive workflows. Session 9 must not enqueue `finding.recalculate`. Session 8 has no web upload UI.

## End-to-end journey

```mermaid
sequenceDiagram
  actor User
  participant Web as apps/web
  participant API as apps/api
  participant PG as PostgreSQL
  participant OS as Object storage
  participant Relay as Outbox relay
  participant Q as Redis/BullMQ
  participant W as apps/worker
  participant OSV as OSV
  participant KEV as CISA KEV
  User->>Web: Create organization, register asset
  Web->>API: Authenticated commands
  API->>PG: Membership, asset, audit
  User->>API: Upload CycloneDX JSON (no Session 8 web UI)
  API->>API: Size, content-type, hash
  API->>OS: Put original bytes (tenant-and-Asset key)
  API->>PG: SBOM, ingestion accepted, outbox, audit
  Relay->>Q: Publish parse job (outbox processed = BullMQ accepted)
  W->>OS: Get copy of object
  W->>PG: Validate, parse, persist graph (Session 8 completed)
  Note over W,OSV: Session 9 Batch 8B: scheduled KEV import; zero Findings
  User->>API: GET sanitized provider status (Batch 9B; no CISA)
  Note over W,OSV: Future additive: correlate, enrich, score (not Session 9)
  W->>OSV: Future correlation query if used (not Session 8 or 9 import)
  W->>KEV: Future finding enrichment from imported snapshot (not Session 9)
  W->>PG: Findings, observations, calculations, audit (not Session 8 or 9)
  User->>API: Assign work, accept risk, export
  User->>API: Upload newer SBOM
  W->>PG: New observations, finding state, calculations
```

If the diagram is not rendered, the numbered flows below are complete.

## 1. Create an organization

1. There is **no** unauthenticated signup ([ADR 0019](../adr/0019-local-password-sessions.md)). Existing users authenticate with local email and password. First-user HTTP bootstrap and invitations are deferred. Development seed may attach synthetic credentials and is rejected in production.
2. Use case creates **Organization**, **Membership** (`owner`), default **Environment** options (optional), and an **AuditEvent** (`organization.created`, `membership.created`) — when those product routes exist.
3. Session is bound to that user. Subsequent commands use membership, not a client-supplied organization id as authority.

## 2. Register an asset

1. API validates name and optional environment id **in the authorized organization**.
2. Transaction: **Asset** (`active`) + optional **AssetOwner** + **AuditEvent** (`asset.created`).
3. **RepositoryConnection** is not created as a live integration; if a row exists it stays `not_configured`.

## 3–5. Upload, store, parse (Session 8)

Synchronous API work:

1. Authenticate. Authorize `sbom.upload` for the asset's organization.
2. Enforce content-type and upload size **before** unbounded parse. Raw body; required `Idempotency-Key`.
3. Stream body through a SHA-256 hasher and a byte counter. Abort over limit.
4. Put original bytes to private object storage using a tenant-and-Asset-scoped key. **Not** inside a DB transaction. No public or signed object URLs.
5. Transaction: **SBOM**, **SBOMIngestion** (`accepted`), **OutboxEvent** (`sbom.ingest`), **AuditEvent** (`sbom.uploaded`), idempotency finalization. No parser, feed, or further storage I/O in this transaction.
6. Duplicate SHA-256 for the same organization + asset **reuses** the existing SBOM and ingestion resource. No `duplicate`-state ingestion row. No second outbox event.

Asynchronous worker work:

1. Relay publishes the outbox row to BullMQ. **OutboxEvent** `processed` means BullMQ accepted the job. **BackgroundJob** represents processor execution.
2. Worker reloads SBOM by id **and** `organizationId`.
3. Get a **copy** of object bytes and re-verify length and SHA-256. Do not fetch `externalReferences`, license URLs, or bom-links.
4. Schema, depth, node, component, and edge limits. Failures become `rejected` or `quarantined` as defined in ingestion design.
5. Persist **Component**, **ComponentOccurrence**, **DependencyRelationship** keyed by **this** `sbomIngestionId`.
6. Ingestion stages are `validate`, `parse`, and `persist_graph` only. State becomes `completed` after those Session 8 steps succeed. `completed` does not imply exhaustive coverage. `correlate`, `enrich`, and `score` remain unused.

## 5b. Import shared vulnerability intelligence (Session 9 Batch 8B scheduled KEV)

[ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md). System job, null organization. OSV runtime remains disabled.

1. The worker scheduler evaluates UTC windows and, when due, writes a requested SyncRun, `intelligence.sync_requested` audit, and `intelligence.sync.requested.v1` OutboxEvent in one PostgreSQL transaction.
2. The Outbox relay publishes `intelligence.sync` on the existing `patchpilot` queue. `processed` means BullMQ accepted the job.
3. The shared Worker claims the BackgroundJob, reloads OutboxEvent and SyncRun, then invokes Batch 7B with locators only. CISA is not contacted before that claim.
4. Fetch the CISA KEV JSON snapshot through restricted HTTPS. Stream once to private object storage and SHA-256 **outside** PostgreSQL. Persist snapshot metadata, hashes, and provenance in a later PostgreSQL-only transaction. Do not refetch after SyncRun reaches `stored`.
5. Parse and normalize outside the database transaction. Stage entries in bounded PostgreSQL transactions. Activate the current projection only after a complete source unit succeeds. Partial imports must not become current.
6. Write system audit (`intelligence.sync_*`). Do **not** create Findings, FindingObservations, Vulnerability rows, or `finding.recalculate` outbox events.

PostgreSQL uniqueness and retry state remain authority. BullMQ delayed jobs are a fast path. Tests must not call live CISA.

## 5c. Read sanitized provider status (Session 9 Batch 9B)

[ADR 0022](../adr/0022-intelligence-provider-status-authorization.md). Authenticated product GET. No OpenAPI. No dashboard.

1. Authenticate the session cookie. Require an active Organization and `intelligence:read`. The Organization is access context only.
2. Reject a GET body (`400`). Unknown provider paths return `404`. Do not require mutation CSRF.
3. Derive OSV as deferred without a database read. Load one bounded CISA `IntelligenceSource` row joined to the active generation. Use `expectedEntryCount`. Do not COUNT `KevEntry`.
4. Map internal failure codes to the public allowlist. Apply KEV health precedence (disabled, never_synchronized, stale over degraded, degraded, current).
5. Respond `Cache-Control: private, no-store`. Do not write `AuditEvent`, `OutboxEvent`, `BackgroundJob`, Findings, or intelligence rows. Session `lastSeenAt` bookkeeping from session resolution is allowed.

## 6. Correlate (future additive workflow, not Session 9)

[ADR 0010](../adr/0010-osv-correlation.md) remains the future correlation ADR, not the Session 9 import mechanism.

1. For each occurrence, build ecosystem + name + version or PURL.
2. Match against **Vulnerability** / **VulnerabilitySourceRecord** using recorded **method**.
3. Prefer the already-imported shared catalog. If a later ADR still uses allowlisted OSV query APIs on cache miss, that fetch is **outside** Session 9 import, **outside** a database transaction, and must not persist tenant package names on the shared catalog.
4. Create or reuse **Finding** by stable identity. Add **FindingObservation** `present` in a transaction **without** HTTP I/O.
5. Do not send original SBOM documents to OSV.

## 7. Enrich with CISA KEV (future, not Session 9)

[ADR 0011](../adr/0011-cisa-kev-enrichment.md). Session 9 imports the KEV snapshot into the shared catalog and stops.

1. A later worker uses the latest imported KEV snapshot (shared catalog), not a live fetch per finding in the request path.
2. If the finding's CVE is listed, store **Evidence** `kev_match` with catalog version, retrieved-at, and match method.
3. KEV listing is **enrichment**, not proof of exploitation in the user's environment, and not by itself the **priority**.

## 8. Calculate priority

1. Collect **observed facts** (severity snapshot from intel, KEV listed boolean, environment sensitivity, direct/transitive if known, fix-available if present in the source record).
2. Load effective **RiskPolicy** (organization override if published, else built-in).
3. `packages/policy-engine` returns priority, full **contributing factors**, and policy version. No AI.
4. Insert **RiskCalculation** (including `policyDefinitionSha256`). Point the finding at it. **AuditEvent** `priority.calculated`.

## 9–10. Assign and record remediation

1. Create **RemediationTask** (`open` → `assigned`). If the finding is `open`, completing a task moves it to `verification_pending`. `risk_accepted` / `mitigated` / `false_positive` are not displaced by task completion.
2. Record activity as task state changes plus **AuditEvent**. Completing a task does **not** set finding `resolved`.
3. **RiskAcceptance** (`active`) and compensating **Evidence** are explicit rows plus audit events.

## 11–12. Newer SBOM and compare

1. Same upload pipeline; new **SBOM** (new hash) for the same asset.
2. Session 8 may already have marked the ingestion `completed` after graph persist. A later correlation workflow writes **FindingObservation** rows keyed by this `sbomIngestionId`: `present`, `absent`, or `inconclusive` with method. That workflow must not rewrite Session 8 completed history.
3. Finding state updates per [finding lifecycle](finding-lifecycle.md) **only if this ingestion is current** (greatest SBOM `receivedAt` among `completed`). `resolved` is a **calculated conclusion** requiring evidence from that current ingestion. An older SBOM that finishes later persists observations and must not change finding state.
4. Recalculate priority with a **new** RiskCalculation (`calculationReason: rescan`, `sbomIngestionId` set). Previous calculations remain.

## 13. Export

1. Authorize export. Rate-limit.
2. Build a snapshot labeled as a PatchPilot output, not a certification.
3. Store **Evidence** `export_snapshot` metadata (not a duplicate of raw SBOMs unless the operator requested included hashes only).
4. **AuditEvent** `export.created`.
5. Exports include policy version, factors, observation results, and acceptance records so a reviewer can see facts versus conclusions.

## Intelligence refresh (not user-initiated)

Session 9 ([ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)):

1. System **BackgroundJob** (null organization) for KEV snapshot import. OSV bulk export remains disabled.
2. Additive generations. KEV removal is absence from a later accepted complete snapshot. Historical snapshots remain.
3. Content SHA-256 is import idempotency. HTTP 304 is not product not-modified. Partial units do not become the current catalog.
4. Do **not** enqueue `finding.recalculate` or otherwise mutate Findings.

A scheduler creates these jobs on UTC windows. `createCisaKevSynchronizationService` resumes from persisted SyncRun state, renews the BackgroundJob lease, and uses pre-snapshot `retry_wait` versus post-snapshot job retry. PostgreSQL retry reconciliation redispatches lost work. BullMQ delayed jobs are a fast path only.

A **later** correlation/enrichment session may enqueue tenant-scoped recalculation after matching exists. Session 9 must not.

Provider outage: last accepted catalog remains current; freshness is not advanced.

## What never happens on these paths

- Network, queue, or object-storage I/O inside a state-transition transaction.
- Next.js reaching Prisma.
- Job payload as proof of organization.
- Silent overwrite of intelligence or historical scores.
- AI setting priority.

## Related documents

- [Reliability model](reliability-model.md)
- [SBOM ingestion](sbom-ingestion.md)
- [Vulnerability intelligence](vulnerability-intelligence.md)
- [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)
