# Data flow

This document traces the v0.1 [MVP journey](../product/mvp-scope.md) through the modular monolith. It is a control-flow and evidence-flow description, not a network packet capture.

Authorization context is established as in [tenant isolation](tenant-isolation.md). Limits and poison handling are in [SBOM ingestion](sbom-ingestion.md).

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
  User->>API: Upload CycloneDX JSON
  API->>API: Size, content-type, hash
  API->>OS: Put original bytes
  API->>PG: SBOM, ingestion accepted, outbox, audit
  Relay->>Q: Publish parse job
  W->>OS: Get copy of object
  W->>PG: Parse graph, correlate
  W->>OSV: Allowlisted query if cache miss
  W->>KEV: Not per upload; use snapshot
  W->>PG: Findings, observations, calculations, audit
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

## 3–5. Upload, store, parse

Synchronous API work:

1. Authenticate. Authorize `sbom.upload` for the asset's organization.
2. Enforce content-type and upload size **before** unbounded parse.
3. Stream body through a SHA-256 hasher and a byte counter. Abort over limit.
4. Cheap JSON and CycloneDX spec-version allowlist checks on a copy in memory only after size is known.
5. Put original bytes to private object storage using a content-addressed, organization-prefixed key. **Not** inside a DB transaction.
6. Transaction: **SBOM**, **SBOMIngestion** (`accepted` or `duplicate`), **OutboxEvent** (`sbom.ingest`), **AuditEvent** (`sbom.uploaded`). No parser, feed, or further storage I/O in this transaction.
7. Duplicate SHA-256 for the same organization + asset returns the existing SBOM without a second parse job (idempotent).

Asynchronous worker work:

1. Relay publishes the outbox row to BullMQ (**BackgroundJob** `queued`).
2. Worker reloads SBOM by id **and** `organizationId`.
3. Get a **copy** of object bytes. Do not fetch `externalReferences`, license URLs, or bom-links.
4. Schema, depth, component, and edge limits. Failures become `rejected` or `quarantined` as defined in ingestion design.
5. Persist **Component**, **ComponentOccurrence**, **DependencyRelationship** keyed by **this** `sbomIngestionId`.
6. Ingestion stage advances through parse; state stays `processing` until a terminal ingestion state. `completed` is allowed only after correlate, enrich, and score for this ingestion have finished (or failed terminal — then not `completed`).

## 6. Correlate

1. For each occurrence, build ecosystem + name + version or PURL.
2. Match against **Vulnerability** / **VulnerabilitySourceRecord** using recorded **method**.
3. On cache miss, the worker queries OSV through the integration adapter (allowlisted, rate-limited) **outside** a database transaction. Raw responses become additive **VulnerabilitySourceRecord** rows in a later transaction with provenance (`retrievedAt`, `payloadSha256`).
4. Create or reuse **Finding** by stable identity. Add **FindingObservation** `present` in a transaction **without** HTTP I/O.
5. Do not send original SBOM documents to OSV.

## 7. Enrich with CISA KEV

1. Worker uses the latest imported KEV snapshot (shared catalog), not a live fetch per finding in the request path.
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
2. After parse+correlate+enrich+score, the ingestion may become `completed`. For each existing finding on the asset, write a new **FindingObservation** keyed by this `sbomIngestionId`: `present`, `absent`, or `inconclusive` with method.
3. Finding state updates per [finding lifecycle](finding-lifecycle.md) **only if this ingestion is current** (greatest SBOM `receivedAt` among `completed`). `resolved` is a **calculated conclusion** requiring evidence from that current ingestion. An older SBOM that finishes later persists observations and must not change finding state.
4. Recalculate priority with a **new** RiskCalculation (`calculationReason: rescan`, `sbomIngestionId` set). Previous calculations remain.

## 13. Export

1. Authorize export. Rate-limit.
2. Build a snapshot labeled as a PatchPilot output, not a certification.
3. Store **Evidence** `export_snapshot` metadata (not a duplicate of raw SBOMs unless the operator requested included hashes only).
4. **AuditEvent** `export.created`.
5. Exports include policy version, factors, observation results, and acceptance records so a reviewer can see facts versus conclusions.

## Intelligence refresh (not user-initiated)

1. Scheduled **BackgroundJob** for OSV and KEV snapshot refresh.
2. Additive source records. Withdrawn advisories set `withdrawnAt`; they are not deleted.
3. Outbox events to re-correlate or re-enrich affected findings, then new **RiskCalculation** rows where inputs changed.
4. Provider outage: jobs retry with backoff; findings keep last known intel and a freshness timestamp. Stale is visible, not silently treated as current.

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
