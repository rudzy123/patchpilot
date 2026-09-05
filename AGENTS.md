# PatchPilot agent and contributor guide

This is the central navigation document for coding agents and human contributors.

PatchPilot is a production-minded, self-hosted platform for software asset inventory, CycloneDX SBOM processing, vulnerability correlation, explainable environmental risk, remediation tracking, and audit-preserving evidence. The product must remain fully useful without an AI provider.

Read this file before editing. Then read the Cursor rules and documents that apply to the files you will change.

## Rule precedence

1. Repository-wide security, tenancy, and authorization rules in this file and in [`.cursor/rules/security.mdc`](.cursor/rules/security.mdc) always apply.
2. Instructions closer to a file (narrower Cursor rules, directory guides, or file-level comments) may **add** constraints.
3. Closer instructions **must not silently weaken** repository-wide security, tenancy, authorization, secret handling, or audit rules.
4. If two instructions conflict, keep the stricter security and tenancy interpretation and record the conflict in the change description or an ADR.

Do not treat product, styling, or convenience guidance as permission to bypass deny-by-default authorization, organization scoping, input validation, or secret handling.

## Current repository state

The Session 3 **development foundation** and Session 4 CI/governance are in place. Session 5 adds the PostgreSQL tenant schema, repository adapters, migrations, and database integration tests. Session 6 Batch 1 accepts [ADR 0019](docs/adr/0019-local-password-sessions.md) (local passwords, opaque sessions, CSRF, interim permissions) and typed auth configuration. `packages/auth` installs `argon2@0.45.1`. Session 6 Batch 2 persists `LocalCredential`, opaque `Session` rows (digest-only), and audit actor columns (`anonymous`, restored `actorUserId`). Hashing, session use cases, and fail-closed login abuse control exist in `packages/auth` (Redis adapter in `apps/api`). Session 6 Fastify authentication routes are implemented: `POST /auth/login`, `POST /auth/logout`, `GET /auth/session`, `GET /auth/organizations`, and `POST /auth/select-organization` (cookies, Origin, CSRF, JSON-only mutations, no-store, audit, login limiter). Session 6 minimal web authentication is implemented: `/login`, client session bootstrap, organization selection, logout, expired-session, and access-denied. CSRF stays in React memory only; the session cookie remains HttpOnly. Session 7 persists asset inventory. Session 8 Batch 1 accepts [ADR 0020](docs/adr/0020-sbom-ingestion-graph-completion.md) (graph-complete ingestion semantics) and typed SBOM ingestion limits in `packages/config`. Session 8 Batch 2 vendors CycloneDX JSON schemas 1.4–1.6 (specification tag `1.6.1`) and installs parser/storage dependencies (`ajv@8.20.0`, `ajv-formats@3.0.1`, `packageurl-js@2.0.1`, `secure-json-parse@4.1.0`, `@aws-sdk/client-s3@3.1120.0`). Session 8 Batch 3 adds SBOM HTTP contracts, the Session 8 ingestion state machine, known/unknown component versions, normalized graph DTOs, and provider-neutral persistence/storage/job ports. Session 8 Batch 4 adds the forward-only migration `20260830120000_sbom_ingestion_graph_persistence` and Prisma adapters for SBOM metadata, ingestion, upload idempotency, outbox claim, BackgroundJob execution, and insert-once graph persistence. The Session 8 graph-persistence migration is **frozen**. Do not edit it; any SQL correction requires another forward-only migration. Session 8 Batch 5 implements private streaming S3-compatible SBOM object storage (`S3SbomObjectStorage` in `@patchpilot/integrations`, MinIO-compatible, no public ACL, no signed URLs). Session 8 Batch 6 implements the framework-independent authorized and idempotent SBOM upload use case (`createUploadSbomUseCase` in `@patchpilot/domain`): hashed Idempotency-Key reservation, streaming put/promote outside PostgreSQL, duplicate-evidence reuse, atomic metadata/audit/outbox/idempotency finalization, and best-effort temporary cleanup. Session 8 Batch 7 implements Fastify SBOM routes (`POST /assets/:assetId/sboms`, `GET /assets/:assetId/sboms`, `GET /assets/:assetId/sboms/:sbomId`, `GET /assets/:assetId/sbom-ingestions/:ingestionId`): session authentication, active Organization, `sbom:upload`/`sbom:read`, tenant-safe not-found, archived Asset conflict, exact Origin, synchronizer CSRF, required `Idempotency-Key`, raw-body streaming, approved UTF-8 JSON content types, per-route upload size, direct peer-IP and Organization rate limits, `trustProxy=false`, outbox-only (no request-path queue publication), and `Cache-Control: private, no-store`. Public responses omit object keys, filenames, worker IDs, lease fields, parser details, and audit payloads. Session 8 Batch 8 implements the worker outbox relay (PostgreSQL `SKIP LOCKED` claim, commit lease, BullMQ.add with deterministic job ID, mark `OutboxEvent` processed, create or reuse `BackgroundJob`). Session 8 Batch 9 implements the worker-thread CycloneDX parser in `@patchpilot/sbom`: `worker.terminate()` wall-clock timeout, secure JSON parse, prototype-key rejection, depth/node/string limits, offline CycloneDX 1.4–1.6 schemas, semantic limits, PURL normalization, explicit unknown versions, duplicate bom-ref rejection, unknown dependency-ref rejection, self-edge omission with `self_dependency_skipped`, cycle retention, bounded normalized results, and graph completeness. Persistence continues to reject DTO-invalid graphs (including remaining self-edges) and does not add self-edge warning behavior. Session 8 Batch 10 implements the ingestion processor in `apps/worker`: BullMQ `sbom.ingest` jobs, ids-only payload validation, BackgroundJob lease claim, authoritative tenant reload, stored-object GET with size and SHA-256 verification, worker-thread parse, transactional graph persist (no storage or Redis in that transaction), Asset pointer update, system audit, and terminal job marking. Session 8 Batch 11 completes the ingestion documentation set: the raw upload contract, storage behavior and failure categories, idempotency layers, orphan handling, outbox relay constants, job leases, parser timeout and quarantine, and the closed safe-failure catalog in [docs/architecture/sbom-ingestion.md](docs/architecture/sbom-ingestion.md), with matching updates to the reliability model, audit catalog, retention, threat model, risk register, local MinIO setup, and the ingestion, outbox, background-job, and local-infrastructure runbooks. The SBOM upload-to-graph path is therefore runnable end to end against local Compose infrastructure. Session 9 Batch 1B accepts [ADR 0021](docs/adr/0021-vulnerability-intelligence-import-foundation.md): global, instance-owned, import-only vulnerability intelligence from OSV GCS bulk export (`all.zip` completeness baseline) and the CISA KEV JSON snapshot, with an explicit zero-Finding boundary. Session 9 Batch 2C adds typed KEV-first intelligence configuration in `@patchpilot/config`. Session 9 Batch 3B vendors the official CISA KEV JSON Schema under `packages/vulnerability-intelligence/vendor/cisa-kev-schema/` and adds offline Ajv draft-07 compilation in `@patchpilot/vulnerability-intelligence` (`ajv@8.20.0`, `ajv-formats@3.0.1`, `secure-json-parse@4.1.0`). Session 9 Batch 4A adds KEV intelligence public status contracts, global domain records, sync-run transition rules, safe failure taxonomy, provider-neutral ports, outbox payload types, parser-thread DTOs, and system audit command types. Session 9 Batch 4C adds the forward-only migration `20260901120000_kev_intelligence_persistence`, domain snapshot/generation/audit corrections, and PostgreSQL adapters for SyncRun, snapshots, generations, atomic activation, scheduler request, not-modified, failure, and freshness. The Session 9 KEV persistence migration is **frozen**. Do not edit it; any SQL correction requires another forward-only migration. OSV runtime remains disabled (`INTELLIGENCE_OSV_ENABLED=true` fails validation). Session 9 Batch 5B adds restricted CISA KEV HTTPS transport (`node:https.request`, no redirects, no proxies, lookup-pin plus post-connect verification) and private S3-compatible intelligence snapshot storage in `@patchpilot/integrations`, reusing the existing Session 8 bucket. Snapshot keys are `intelligence/cisa_kev/cisa_kev_json_catalog/tmp/{uuid}` and `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/{sha256}`. Session 9 Batch 6B adds secure CISA KEV parsing, deterministic normalization, and one-shot worker-thread execution in `@patchpilot/vulnerability-intelligence` (`worker.terminate()` wall-clock timeout, strict UTF-8, secure JSON parse, iterative structural limits, offline official-schema validation, PatchPilot semantic checks, and a 16 MiB serialized-result ceiling). Session 9 Batch 7B adds the framework-independent CISA KEV synchronization service in `@patchpilot/domain` (`createCisaKevSynchronizationService`): authoritative job/outbox/SyncRun prechecks, crash-safe persisted-stage resume, provider fetch and snapshot orchestration, content-hash not-modified, catalog-regression quarantine, dense-prefix staging, atomic activation, BackgroundJob-only lease heartbeat, and pre-snapshot `retry_wait` versus post-snapshot job retry. Session 9 Batch 8B adds the worker KEV scheduler (UTC schedule windows, PostgreSQL dedupe), Outbox mapping of `intelligence.sync.requested.v1` to `intelligence.sync`, a shared `patchpilot` BullMQ Worker with concurrency 2, PostgreSQL-backed retry reconciliation, IntelligenceSource enablement reconciliation, and graceful shutdown. Session 9 Batch 9B accepts [ADR 0022](docs/adr/0022-intelligence-provider-status-authorization.md) and implements authenticated sanitized provider-status GETs (`GET /intelligence/providers`, `GET /intelligence/providers/:provider/status`) with `intelligence:read` for viewer, member, admin, and owner. Active Organization is product-access context, not a data-scope predicate on global intelligence rows. No web UI, dashboard, ZIP dependency, production catalog body, OSV runtime, manual synchronization, manual retry, detailed SyncRun API, or Finding integration exists. [ADR 0010](docs/adr/0010-osv-correlation.md) remains the future correlation ADR, not the Session 9 import mechanism. Generic Finding persistence exists and stays unused by Session 9. Web UI is **not** implemented. Registration, invitation, password reset, session listing, remote revoke, dashboards, and product UIs are **not** implemented. Live vulnerability-provider calls occur only from the worker intelligence processor after authoritative claim, never during configuration load or status GETs. Risk-scoring logic is **not** implemented. Session 10 Batch 1B accepts [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) and adds provider-neutral canonical CVE identity domain boundaries in `@patchpilot/domain` (`CveIdentity`, `VulnerabilityCveIdentityLink`, ensure commands, and persistence ports). Session 10 Batch 3A added the forward-only migration `20260902120000_canonical_cve_identity` with global append-only `cve_identity` and `vulnerability_cve_identity` tables, a canonical CVE CHECK, and exact canonical-only backfill from `vulnerability.cve_id`. Session 10 Batch 3B applied that migration to the persistent development database (eleven finished migrations) and froze it (SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). Session 10 Batch 4B adds `createCveIdentityPersistence` in `@patchpilot/database` (`identities` and `links`): insert-once ensure, unique-conflict reload of the authoritative row, database-generated identity `createdAt`, caller-supplied immutable link `linkedAt`, bounded batch lookup, and bounded keyset listing. The factory does not query KEV, does not take tenant arguments, and does not write Findings. Session 10 Batch 5B adds read-only active-catalog membership derivation (`createQueryActiveKevMembershipUseCase`, `createActiveKevMembershipPersistence`) for one exact canonical CVE against the accepted active CISA KEV generation. Results are `unavailable`, `absent`, or `listedInActiveKev` with `current`, `stale`, or `disabled_with_history` freshness. No CveIdentity or link row is required or created. No Finding query or write, tenant input, API, worker, Outbox, permission, or web UI is included. Session 10 Batch 6B hardens identity persistence (root Prisma client only; P2002 replay when target metadata is absent) and adds activation-race, corruption-path, and isolation tests. Session 10 remains zero-Finding. `Vulnerability.osvId` remains required and unique. KEV membership remains a global exploitation signal, not proof of tenant exposure. v0.1 architecture, security design, and operational runbooks exist under `docs/architecture/`, `docs/security/`, and `docs/runbooks/`. ADRs 0001–0026 are **Accepted**. Session 11 Batch 1A found the repository unable to authoritatively match versions. Session 11 Batch 1B accepts [ADR 0024](docs/adr/0024-authoritative-affected-version-source-and-osv-acquisition.md): OSV is the future affected-version authority; tenant package query APIs are rejected; instance-owned catalog acquisition is the approved direction. Exact object/listing transport remains unreviewed. ZIP remains absent and unauthorized. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 Batch 1C accepts [ADR 0025](docs/adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md): ecosystem-aware package identity, a closed fail-closed registry, and the future evaluator result model. The implemented ecosystem set is empty. No first ecosystem is selected. Session 11 Batch 1D accepts [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md): Finding natural key `organizationId` + `assetId` + `componentId` + `vulnerabilityId`, future append-only match evaluation, observation semantics, and the first Finding-write gate. Session 11 Batch 3A implements OSV metadata contracts, source-license registry, and fail-closed classification in `@patchpilot/vulnerability-intelligence`. Nine sources with fail-closed registry (MAL Apache-2.0, GHSA CC-BY-4.0, PYSEC CC-BY-4.0, GO CC-BY-4.0 vulnerability data, RUSTSEC CC0-1.0, GSD archived, EEF-CVE CC-BY-4.0, OSV ambiguous fail-closed, ECHO proprietary fail-closed). Session 11 Batch 3A-P incorporates verified provenance so seven sources are body-retrieval eligible; OSV and ECHO remain fail-closed. Session 11 Batch 3B adds framework-independent OSV transport contracts. Session 11 Batch 3C adds a compiled GCS JSON Objects list request builder and a bounded listing-page parser using synthetic fixtures. Session 11 Batch 4A vendors the official OSV advisory schema (v1.9.0) with immutable provenance. Session 11 Batch 4B defines the isolated OSV advisory parser protocol. Session 11 Batch 4B-P closes parser resource-policy v1 and authorizes synthetic bounded reference-parser requests. Session 11 Batch 4C implements an in-process reference parser for one bounded synthetic OSV advisory. Session 11 Batch 4D adversarially reviews that parser with synthetic hostile inputs and hardens identity whitespace/control rejection, abort checks, and unexpected-exception mapping. Session 11 Batch 4E closes the production isolation design (`worker_threads`, exact timeouts, pinned schema load inside the isolate, one-request-at-a-time Ajv, pool size 1, sequential reuse) without implementing a worker. Session 11 Batch 4F implements the isolated OSV advisory parser worker and parent-side adapter, aligning with the committed Batch 4E isolation architecture. Session 11 Batch 4F-R verified that implementation under Node.js 24: the worker loads only compiled `dist/osv/advisory-parser-worker.js`, verifies the pinned schema, compiles one Ajv instance, and parses one synthetic advisory at a time; the host enforces occupancy 1 with no pending queue, catalog failure kinds, idempotent shutdown, correlation matching, and parent validation of worker output. `worker_threads` is not an operating-system sandbox. No HTTP adapter, provider-object retrieval, scheduler, or OSV runtime exists. Session 11 Batch 5B adds framework-independent OSV persistence contracts. Session 11 Batch 5C adds Prisma models and the forward-only migration `20260904120000_osv_acquisition_persistence_foundation` (frozen SHA-256 `ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349`). Session 11 Batch 5C-R adds `20260904180000_osv_parsed_revision_id_check_correction` (thirteen finished migrations; frozen SHA-256 `43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570`) which replaces only the unsatisfiable parsed OSV ID CHECK. Session 11 Batch 5D adds `createOsvAcquisitionPersistence` in `@patchpilot/database`: PostgreSQL adapters for inventory, provider identity, snapshot/attachment metadata, parser attempts, parsed revisions, catalog-generation transitions, deterministic reconciliation, append-only quarantine and provider presence, and atomic active-pointer compare-and-swap with immutable activation history. The Batch 5C and Batch 5C-R migrations are unchanged. Session 11 Batch 5E adds an immutable S3-compatible object-storage adapter (`S3OsvAdvisoryObjectStorage` in `@patchpilot/integrations`) and staged-attachment orchestration (`createOsvArtifactAttachmentService` in `@patchpilot/vulnerability-intelligence`) for provider-body snapshots and parsed structural documents. Locators are `intelligence/osv/advisory_body/{tmp|sha256}/…` and `intelligence/osv/parsed_advisory/{tmp|sha256}/…`. Provider keys are never storage paths. PostgreSQL and object storage are not one transaction. Bytes are locally supplied synthetic test bytes only. Session 11 Batch 5F adversarially reviews and hardens that storage path (write-once GET hashing, bounded recovery, cleanup eligibility, and error confidentiality) without authorizing provider retrieval. Session 11 Batch 6A-P closes `osv_generation_bound_retrieval_policy_v1` and OD-8 at 1,048,576 received bytes. Session 11 Batch 6A implements one-attempt generation-bound HTTPS retrieval (`createOsvGenerationBoundRetrievalHttpsAdapter` in `@patchpilot/integrations`) with source and retention preflight, `ifGenerationMatch` binding, identity encoding, redirect rejection, and bounded streaming SHA-256. The adapter returns a validated retrieval result only. It does not attach snapshots, invoke the parser, retry, list GCS inventory, synchronize, or enable OSV. Tests use synthetic local streams and an injected HTTP seam. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding. Session 13 is the earliest candidate for Finding writes and is not authorized yet. No Finding repositories or lifecycle code, no match-evaluation model, and no OSV runtime, matching, comparator, evaluator, or Finding write exists. The layout below is the modular monolith. Do not invent a different topology without an accepted ADR.

### Known Session 8 gaps

These are deliberate, documented gaps. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- No SBOM web UI, retry API, or quarantine-release API. Requeueing a `failed` ingestion and releasing a `quarantined` one are operator database work.
- No object-storage orphan reconciliation job. `SBOM_ORPHAN_GRACE_SECONDS` is a validated policy floor with no consumer.
- No BackgroundJob lease heartbeat. `renewLease` exists on the port and adapter and is never called, so the lease must exceed the worst-case run.
- No BullMQ `attempts`/`backoff` on `sbom.ingest` and no BackgroundJob requeue poller. A retryable failure leaves resumable state and stops until an operator replays the job.
- `sbom.upload_rejected`, `sbom.ingestion.released_from_quarantine`, and `sbom.reprocessed` are specified in the audit model and not yet emitted.
- Ingestion limit values in `packages/config` are unmeasured proposals (risk R31).
- Idempotency reservation renewal during a slow client upload is not implemented (risk R43).

### Known Session 9 gaps (after Batch 9B)

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Official CISA KEV JSON Schema is vendored with checksums and provenance. Offline Ajv compiles it. Re-vendoring is maintainer-only (`scripts/vendor-cisa-kev-schema.mjs --execute`). Install, build, test, CI, and runtime do not download the schema.
- The framework-independent CISA KEV synchronization service exists in `@patchpilot/domain`. `apps/worker` schedules, relays, and processes KEV work. `apps/api` exposes sanitized provider-status GETs only; it does not start synchronization.
- Authenticated `GET /intelligence/providers` and `GET /intelligence/providers/:provider/status` exist (`intelligence:read`). Manual sync, manual retry, detailed SyncRun, generation-history, snapshot, and KEV CVE list APIs do not. There is no OpenAPI document and no web dashboard.
- PostgreSQL KEV persistence exists and is frozen. Do not edit `20260901120000_kev_intelligence_persistence`; any SQL correction requires another forward-only migration.
- Restricted CISA KEV HTTPS transport and private intelligence snapshot storage exist in `@patchpilot/integrations`. Configuration loading, API status GETs, and worker startup do not contact CISA. The processor fetches only after authoritative PostgreSQL validation and BackgroundJob claim.
- The production KEV catalog body is not stored in the repository.
- KEV-first typed configuration includes scheduler poll, startup delay, and retry-reconcile settings. Loading configuration does not start timers or Redis.
- OSV runtime remains disabled. `INTELLIGENCE_OSV_ENABLED=true` must fail configuration validation. Public OSV status is always deferred and is not loaded from PostgreSQL.
- Worker `resourceLimits` are not set in v0.1. Bounding is the 8 MiB input ceiling, 16 MiB serialized output ceiling, configured wall-clock timeout, and actual `worker.terminate()`. Duplicate JSON object keys are not detected; last-key-wins remains a documented limitation. Sub-millisecond `dateReleased` fractional digits are not retained in `catalogReleasedAt`.
- Snapshot object-key layout is closed: `intelligence/cisa_kev/cisa_kev_json_catalog/tmp/{uuid}` and `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/{sha256}` ([OD-20](docs/architecture/open-decisions.md)).
- No advisory-to-component matching, version-range evaluation, Finding writes, KEV enrichment of Findings, risk scoring, or `finding.recalculate`.
- Existing required unique `osvId` is unchanged. [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) accepts canonical CVE identity. Batch 3B applied and froze `20260902120000_canonical_cve_identity`. Batch 4B ships `createCveIdentityPersistence`. Batch 5B adds read-only active-catalog membership derivation. Full provider-neutral Vulnerability advisory identity remains open ([OD-19](docs/architecture/open-decisions.md)).
- Delivery remains at-least-once. PostgreSQL uniqueness and BackgroundJob leases are authority; Redis job IDs are not exact-once.
- Instance-operator identity remains unresolved ([OD-10](docs/architecture/open-decisions.md)).
- Session 9 is not complete.

### Session 10 Batch 1B

These were the Batch 1B gaps. Later Session 10 batches added the frozen migration, persistence adapters, and read-only membership derivation. Do not treat this list as current state:

- [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) is accepted on this feature branch. Canonical CVE identity and advisory-to-CVE links began as domain records, commands, and provider-neutral ports only.
- The current application has no production Finding creation path. The policy engine remains without production scoring.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, or Finding-adjacent command is added.
- `Vulnerability.osvId` remains required and unique. No Vulnerability rows are merged by CVE. No OSV identifier is manufactured.
- Canonical CVE identity persistence and the forward-only identity migration remained future relative to Batch 1B. Do not treat Batch 1B types as the shipped adapter story.
- KEV membership remains a global exploitation signal, not proof of tenant exposure. Read-only active-KEV derivation was not implemented in Batch 1B.
- No API route, worker, Outbox event, permission, or web UI was added in Batch 1B.

### Session 10 Batch 3B

These were the Batch 3B gaps after the freeze. Later batches added adapters and membership derivation. Do not treat the adapter/derivation sentences as current state:

- Migration `20260902120000_canonical_cve_identity` was applied to the persistent development database. That catalog now has eleven finished migrations.
- The migration is **frozen**. Frozen SHA-256: `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`. Do not edit it; any SQL correction requires another forward-only migration.
- Two global append-only tables exist: `CveIdentity` (`createdAt` only) and `VulnerabilityCveIdentityLink` (`linkedAt` only, source-free). Canonical-only backfill completed. Malformed legacy `cveId` values remain unchanged and unlinked.
- No CveIdentity persistence adapter, mapper, repository factory, or runtime service existed in Batch 3B.
- Read-only active-KEV derivation was not implemented in Batch 3B. `KevEntry` is unchanged.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, Outbox, BackgroundJob, API, worker, permission, risk, or web UI change is included. No fan-out runtime was added.
- `Vulnerability.osvId` remains required and unique. `Vulnerability.cveId` remains nullable `VARCHAR(32)` and unchanged. No Vulnerability merge occurred. OSV remains deferred.

### Session 10 Batch 4B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- `createCveIdentityPersistence` exposes `identities` and `links`. Ensure is insert-once. Unique conflicts reload the stored row. The database generates identity `createdAt`. Link `linkedAt` is supplied by the command and is never overwritten. Source-free links are unchanged. Batch lookup and keyset listing are bounded (1–100). Invalid keyset limits are rejected, not clamped.
- Global identity tables remain instance-owned. The adapters take no tenant arguments and do not query KEV entries or generations.
- The migration remains frozen and unchanged. Frozen SHA-256: `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`.
- Read-only active-KEV derivation is not implemented in Batch 4B. `KevEntry` is unchanged.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, Outbox, BackgroundJob, API, worker, permission, risk, or web UI change is included. No fan-out runtime was added.
- `Vulnerability.osvId` remains required and unique. `Vulnerability.cveId` remains nullable `VARCHAR(32)` and unchanged. No Vulnerability merge occurred. OSV remains deferred. ZIP processing remains absent.

### Session 10 Batch 5B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- `createQueryActiveKevMembershipUseCase` answers active-catalog membership for **one exact canonical CVE** against the currently accepted CISA KEV generation. Statuses are `unavailable` (`no_active_generation` only), `absent`, and `listedInActiveKev`. Freshness is `current`, `stale`, or `disabled_with_history` on absent and listed results only.
- Absence is relative to the accepted active snapshot, not live CISA. Listed means membership in that snapshot. Disablement stops refresh but does not erase accepted history. Stale results remain snapshot-relative. A future risk or Finding workflow must explicitly decide whether stale or disabled-with-history absence is usable.
- No provider prose is returned. Structured calendar dates and the normalized ransomware enum are the only listed attributes besides catalog metadata and freshness. No CveIdentity or advisory-link row is required or created. A KEV CVE may be listed without an identity row.
- The read port and Prisma adapter take no tenant, organization, provider, generation, or identity arguments. The query is bounded to one IntelligenceSource, the nested active generation, and at most two `KevEntry` rows (`take: 2`). Staging, complete, superseded, and abandoned generations are invisible.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, Component, Outbox, BackgroundJob, API, worker, scheduler, permission, risk, or web UI change is included. No fan-out or `finding.recalculate` event exists. The use case is not wired into `apps/api` or `apps/worker`.
- All eleven migrations remain frozen and unchanged. `Vulnerability.osvId` remains required and unique. OSV remains deferred. ZIP processing remains absent. KEV membership remains an exploitation signal, not proof of tenant exposure.

### Session 10 current state (after Batch 6B)

- The canonical CVE identity migration exists and is frozen.
- Identity and link persistence adapters exist.
- Read-only active-catalog KEV membership derivation exists.
- No Finding enrichment exists.
- No tenant join exists.
- No risk integration exists.
- No API or worker wiring exists.
- Zero-Finding remains enforced.

### Session 11 Batch 1A

Session 11 Batch 1A found the repository unable to authoritatively match versions. Current `VulnerabilitySourceRecord` normalized JSON is insufficient for affected-version evaluation. OSV is the recommended affected-package and affected-version source. CISA KEV remains an independent exploitation signal. Tenant SBOMs remain inventory, not advisory authority. Tenant package inventory must not be sent to an external provider without an explicit ADR. Current OSV query APIs must not be used with tenant package identities. OSV catalog ingestion must exist before authoritative matching. Session 11 remains zero-Finding. Finding writes are deferred beyond Session 11. Package identity and fail-closed evaluation belong to [ADR 0025](docs/adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md). Finding evidence and lifecycle belong to [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md).

### Session 11 Batch 1B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- [ADR 0024](docs/adr/0024-authoritative-affected-version-source-and-osv-acquisition.md) is accepted on this feature branch. OSV is the future affected-version authority. Tenant package query APIs are rejected. Instance-owned catalog acquisition is the approved direction.
- Exact provider object/listing transport, host, path, licensing, removal semantics, and limits remain to be reviewed. Implementation is not authorized until that review completes.
- ZIP remains absent and unauthorized. `all.zip` is not the first-implementation assumption.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. No OSV runtime, transport, parser, snapshot schema, scheduler, or worker exists.
- Session 11 remains zero-Finding. No matching exists. No Finding write exists.
- [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) (Finding evidence and lifecycle) is accepted as architecture in Batch 1D. It does not implement writes.
- Matching is Session 12 or later. Finding writes are Session 13 or later, subject to all gates including the [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) four-condition gate.
- Current `VulnerabilityNormalizedJson.affectedPackages` is not an approved matching authority.
- Full provider-neutral Vulnerability advisory identity remains open. `Vulnerability.osvId` remains required and unique.

### Session 11 Batch 1C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- [ADR 0025](docs/adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md) is accepted on this feature branch. Package identity is ecosystem-aware. There is no generic name matcher and no generic lexical or universal-semver comparator.
- The implemented ecosystem registry is **empty**. npm, PyPI, Maven, Go, NuGet, and crates.io are candidates to evaluate, not currently supported ecosystems.
- No first ecosystem is selected. Selection waits for OSV catalog measurements and a separate dependency and evaluator design review. npm is the preferred candidate to evaluate first after those measurements.
- Future evaluation is fail-closed. Unsupported, unknown, malformed, and withdrawn cases must not become `not_affected`. Only a deterministic `affected` result may eventually contribute to Finding creation.
- Evaluation remains read-only and zero-Finding in Session 11 and Session 12. No evaluator, comparator, PURL matching conversion, or version parser exists.
- GIT ranges, Linux distribution ecosystems, CPE identity, and plugin or environment-variable registries are rejected or deferred as specified in ADR 0025.
- Finding writes remain blocked until OSV acquisition, at least one reviewed registry entry, deterministic evaluation, match-evaluation persistence, Finding ensure semantics, the [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) gates, explicit authorization, and tenant-isolation proof all exist. ADR 0026 acceptance does not authorize writes.

### Session 11 Batch 1D

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- [ADR 0026](docs/adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) is accepted on this feature branch. Finding natural key is `organizationId` + `assetId` + `componentId` + `vulnerabilityId`. Future match evidence is tenant-owned append-only `VulnerabilityMatchEvaluation`. FindingObservation is one summarized result per Finding per completed ingestion.
- Only a deterministic `affected` result may eventually create a Finding. KEV, CVE, unknown versions, unsupported evaluation, and withdrawn advisories do not create Findings and do not automatically resolve them.
- The first Finding-write gate is recorded. Session 11 remains zero-Finding. Session 12 remains zero-Finding. Session 13 is the earliest candidate and is not authorized yet.
- No Finding repositories or lifecycle code is added. No match-evaluation model, observation ensure, risk, API, worker, Outbox, or matching runtime is added.
- OSV runtime remains disabled. ZIP remains absent. The implemented ecosystem set remains empty.

### Session 11 Batch 3A-P

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 3A implements OSV metadata contracts in `@patchpilot/vulnerability-intelligence`: source identifiers, inventory scope, source-license registry, object-key parser, family-candidate extraction, permission enums, evidence provenance contracts, pre-retrieval classification, and post-parse confirmation.
- The immutable versioned source-license registry (`osv_source_license_registry_v1`) defines 9 sources: MAL, GHSA, PYSEC, GO, RUSTSEC, GSD, EEF-CVE, OSV, ECHO.
- **Session 11 Batch 3A-P incorporates verified source-license provenance.** Seven sources (MAL, GHSA, PYSEC, GO, RUSTSEC, GSD, EEF-CVE) now have complete evidence and are **eligible for body retrieval**.
- MAL: Apache-2.0. Body retrieval eligible. Internal matching prohibited (malicious-package semantics not approved by ADR 0025).
- GHSA: CC-BY-4.0. Attribution required.
- PYSEC: CC-BY-4.0. Attribution required.
- GO: CC-BY-4.0 for /data/ directory. Attribution required.
- RUSTSEC: CC0-1.0 source-level with per-advisory license field. External exposure conservative until post-parse confirmation.
- GSD: CC0-1.0 public domain dedication. Archived status independent from licensing permission.
- EEF-CVE: CC-BY-4.0. Attribution required. Dynamic HTML evidence.
- OSV family fails closed (ambiguous aggregator provenance). ECHO fails closed (proprietary, no public license).
- Evidence provenance contracts define required fields: requested URL, final URL, redirects, HTTP status, media type, content encoding, byte count, SHA-256, retrieval timestamp, work covered, mutable-URL indicator.
- No OSV HTTP adapter, object retrieval, advisory parser, persistence, scheduler, worker, API, or runtime exists. Body retrieval implementation remains future work. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding.

### Session 11 Batch 3C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 3B added OSV-specific transport contracts (listing request, opaque continuation token, listing page, generation-bound retrieval request, failure taxonomy). Listing-request `pageSizePolicy` remains `unavailable` so callers cannot supply a numeric page size. Continuation-token and provider-object body byte bounds remain unavailable.
- Session 11 Batch 3C implements a compiled GCS JSON Objects list request builder and a bounded listing-page parser in `@patchpilot/vulnerability-intelligence`. Neither performs I/O.
- Compiled listing surface: HTTPS GET `storage.googleapis.com` `/storage/v1/b/osv-vulnerabilities/o`, unauthenticated, redirects described as `error`, `maxResults` 1000, field projection `kind,nextPageToken,items(name,generation,metageneration,size,etag,md5Hash,contentType,updated)`, listing-page cap 1,048,576 bytes.
- User-Agent is omitted from the request description; the future HTTP adapter owns it.
- The parser accepts supplied page bytes only. It does not fetch. Terminal state follows `nextPageToken` presence only. Listed observations reuse Batch 3A key parsing and Batch 3B classification.
- Duplicate JSON object keys are not detected. Last-key-wins remains the existing `secure-json-parse` limitation. Do not describe Batch 3C as rejecting duplicate keys. A later parser-hardening decision is required before duplicate-key detection exists.
- No HTTP client, provider-object retrieval, advisory parsing, snapshots, object storage, persistence, Prisma, migrations, workers, schedulers, Outbox, BackgroundJob, API, permissions, or OSV enablement is included.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4A

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4A vendors the official OSV advisory JSON Schema (v1.9.0) with immutable provenance and integrity verification. The schema is self-contained with local-only reference closure.
- **Upstream repository**: `https://github.com/ossf/osv-schema` (OpenSSF)
- **Version tag**: `v1.9.0`
- **Exact commit SHA**: `f3f826310aeca8e324baabd195632f2229952abe`
- **Byte length**: 16,816 bytes
- **SHA-256**: `cdb8292f72945cfdf06d3e044280d7c0867105a3a1ae6d4547c983eba20810a2`
- **Local path**: `packages/vulnerability-intelligence/vendor/osv-schema/schema.json`
- **Schema license**: Apache-2.0 (schema/software license, distinct from advisory content licenses)
- All `$ref` references are local fragments (`#/$defs/...`). No remote HTTP/HTTPS references. No external schema dependencies.
- Vendored artifacts include: `schema.json`, `PROVENANCE.json`, `SHA256SUMS`, `LICENSE`, `NOTICE`.
- Deterministic integrity tests verify: file existence, byte counts, SHA-256 checksums, valid JSON structure, local reference closure, no remote $ref, provenance immutability, no path traversal, no runtime network capability, zero-Finding enforcement.
- `@patchpilot/vulnerability-intelligence` exports immutable schema provenance constants and deterministic path helpers. No tenant input, no network I/O, no Findings.
- **Critical distinction**: Vendoring the OSV schema (Apache-2.0) does NOT license all OSV advisory bodies, change Batch 3A-P source-license registry decisions, make OSV or ECHO retrieval eligible, authorize provider-body retrieval, normalization, matching, external exposure, or Finding creation. The schema is a validation tool. Advisory content licensing remains per-source. OSV and ECHO remain fail-closed.
- No advisory parser implementation, validation runtime, HTTP transport, object-storage snapshots, persistence, Prisma, migrations, worker, scheduler, Outbox, BackgroundJob, API, permissions, package normalization, version comparison, matching, Finding creation, or OSV enablement (`INTELLIGENCE_OSV_ENABLED=true` remains rejected).
- Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4B defines the isolated OSV advisory parser protocol in `@patchpilot/vulnerability-intelligence` (`advisory-parser-protocol.ts`, `advisory-parser-policy.ts`): protocol identity `osv_advisory_parser_protocol_v1`, metadata-only request envelope, success/failure envelopes, resource-policy contract, execution-state transitions, cancellation/termination semantics, source-confirmation handoff, and worker-output validation.
- The protocol pins Batch 4A schema revision `v1.9.0` / commit `f3f826310aeca8e324baabd195632f2229952abe`, registry `osv_source_license_registry_v1`, and eligible-body scope `osv_eligible_body_scope_registry_v1`.
- Input payload representation remains deferred **for provider-object retrieval**. Parser resource-policy v1 is closed by Batch 4B-P. Executable *reference-parser* request construction is authorized only for locally supplied bounded bytes (`synthetic_bounded_reference_parser_authorized`). The parser port, production worker isolation, and provider retrieval remain deferred.
- Parser resource-policy v1 selects exact PatchPilot ceilings (1 MiB input, 2 MiB output, depth 32, and related collection/string bounds). They are not provider guarantees. Overflow fails closed. No environment or caller override. Worker timeouts were `unavailable` in this batch; Batch 4E later selected exact values without implementing a worker.
- Normalization eligibility is required; body-retrieval permission alone is insufficient. OSV and ECHO remain rejected. MAL may normalize while internal matching remains prohibited.
- Parser success never activates intelligence, authorizes matching, or creates Findings. Worker output is untrusted and must match the originating request correlation/protocol/schema/registry/digest/generation/hash.
- No advisory JSON parsing, AJV compilation, worker_threads, child_process, HTTP, provider retrieval, snapshots, persistence, Prisma, migrations, schedulers, Outbox, BackgroundJob, API, permissions, package normalization, version comparison, matching, or Finding path is included.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4B-P

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4B-P closes `osv_advisory_parser_resource_policy_v1` with exact PatchPilot v1 numeric ceilings and authorizes `synthetic_bounded_reference_parser_authorized` executable requests for locally supplied bounded bytes and synthetic fixtures.
- Input representation is `immutable_defensive_uint8array_copy`. The factory copies a `Uint8Array`, validates length against the policy, and never exposes the internal typed array. JSON, inspect, toString, and errors omit payload bytes.
- Values are PatchPilot security policy, not provider guarantees. Oversize records fail closed and must prevent later generation activation. Silent omission from a complete generation is forbidden.
- Provider-object body retrieval remains `unavailable` on the transport contract. Production worker isolation remained unauthorized in this batch; timeouts stayed `unavailable` until Batch 4E selected exact values. Parser implementation remained absent until Batch 4C.
- The parser port after Batch 4E is `deferred_isolated_worker_not_implemented`. No HTTP, provider retrieval, workers, snapshots, persistence, matching, or Findings.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4C implements `parseOsvAdvisoryWithInProcessReferenceParser` in `@patchpilot/vulnerability-intelligence`. It accepts one Batch 4B executable request with locally supplied bounded bytes and synthetic fixtures only.
- Input identity is verified (byte count and SHA-256) before fatal UTF-8 decoding and `secure-json-parse`. Prototype-pollution keys are rejected. Duplicate JSON object keys are **not** detected; last-key-wins remains a documented `secure-json-parse` limitation.
- Validation uses the pinned Batch 4A OSV schema (v1.9.0) compiled offline with Ajv 2020-12. Remote `$ref` loaders are not configured. PatchPilot structural bounds from parser resource-policy v1 fail closed without truncation.
- Success returns the Batch 4B envelope (structural counts, confirmed top-level OSV id, source confirmation). Affected data is counted, not interpreted. `database_specific` and URLs remain untrusted and are omitted from output. MAL may parse structurally while `authorizesMatching` stays false. OSV and ECHO cannot construct normalization-eligible requests.
- This is an in-process reference parser (`in_process_reference_parser_synthetic_only`). Production worker isolation is not implemented. Parser success does not activate intelligence, authorize matching, or create Findings.
- No provider retrieval, snapshots, object storage, persistence, Prisma, migrations, workers, schedulers, Outbox, BackgroundJob types, APIs, permissions, version comparison, matching, or Finding path is included.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4D

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4D is an adversarial security, resource-exhaustion, confidentiality, and protocol-compliance review of the committed Batch 4C parser. It does not add parser features, broaden the parsed advisory model, retrieve provider objects, implement HTTP, workers, snapshots, persistence, matching, or Findings, or enable OSV.
- Synthetic hostile inputs only. No live OSV advisories, copied provider records, real GHSA/CVE identifiers, real package names, tenant data, or megabyte-scale committed fixtures.
- Duplicate JSON object keys remain undetected (`last_key_wins_secure_json_parse_limitation`). Adversarial tests show last-key-wins cannot bypass identity confirmation, source classification, schema revision, resource limits, or normalization eligibility. Detection without a new dependency remains a parser-hardening follow-up.
- Parser isolation readiness after Batch 4D was `in_process_core_reviewed_worker_isolation_not_authorized`. Batch 4E supersedes that marker. Duplicate-key detection without a new dependency remains a follow-up before OSV runtime enablement.
- `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4E

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4E closes `osv_advisory_parser_isolation_design_v1` in `@patchpilot/vulnerability-intelligence`. The selected mechanism is `worker_threads`. Isolation readiness is `production_isolation_design_closed_worker_not_implemented`.
- Exact v1 timeouts: 5,000 ms initialization, 5,000 ms per-request execution, 250 ms cancellation grace, 1,000 ms forced termination. These are PatchPilot security policy, not performance guarantees, and are not environment-configurable.
- Future worker entrypoint and parent adapter belong in `@patchpilot/vulnerability-intelligence`. Domain stays free of `worker_threads`. Applications must not construct parser workers. Integrations must not own parser lifecycle. Those files are not created in this batch.
- Schema loading is worker-internal from the pinned vendor path with byte-length and SHA-256 verification before compile. The protocol must not carry schema paths or schema bytes. One Ajv instance per isolate; one request at a time; sequential reuse of a healthy worker is authorized. Recycle follows `terminationRequired`, plus `worker_start_failed`.
- v1 pool size is 1. Pending-queue size remains `unavailable`, so runtime composition is `blocked_pending_queue_size_unapproved`. Duplicate JSON keys remain undetected and do not block worker implementation; they must be resolved or explicitly accepted before OSV enablement.
- This batch does not implement a worker, timers, message channels, provider retrieval, persistence, matching, or Findings. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4F / 4F-R

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 4F implements `advisory-parser-worker.ts` and `advisory-parser-host.ts` in `@patchpilot/vulnerability-intelligence`. Batch 4F-R verified the host and worker under Node.js 24 with synthetic bounded fixtures only.
- The parent resolves the worker from compiled `dist/osv/advisory-parser-worker.js` (same pattern as the KEV parser host). Vitest does not load the TypeScript worker source. Missing dist fails closed as `worker_start_failed`.
- Correlation IDs remain caller-supplied UUIDs on the executable request. Production does not generate them and does not accept a public arbitrary generator. Tests use deterministic UUID v4 fixtures. `crypto.randomUUID()` is valid under Node.js 24 and was not the Batch 4F failure cause.
- The worker reconstructs a branded executable request inside the isolate from transferred bytes plus request metadata. The public envelope still omits the raw provider key; a WeakMap handoff exists only for isolate reconstruction and is omitted from JSON, inspect, and events.
- Occupancy is exactly one in-flight parse. Pending-queue size remains `unavailable`, so a second concurrent parse is rejected with `invalid_request`. Sequential reuse of a healthy worker is authorized.
- Host failures use the closed parser failure catalog (`cancelled`, `timeout`, `worker_terminated`, `worker_start_failed`, `malformed_worker_output`, and related kinds). Shutdown is idempotent. Late messages are discarded. Raw advisory bytes never enter errors or events.
- `worker_threads` is not an OS-level sandbox, container isolation, or filesystem/network denial. Compensating controls remain as in Batch 4E.
- No HTTP adapter, provider-object retrieval, snapshots, persistence, Prisma, migrations, schedulers, durable queues, APIs, matching, Findings, or OSV enablement (`INTELLIGENCE_OSV_ENABLED=true` remains rejected).
- Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 4G

Session 11 Batch 4G adversarially hardens the committed Batch 4F/4F-R isolated OSV parser worker and parent adapter. These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Comprehensive adversarial worker lifecycle tests cover initialization attacks, correlation attacks, timeout races, cancellation races, malformed messages, worker crashes, Ajv state isolation, input ownership attacks, backpressure attacks, worker recycle attacks, shutdown attacks, observability confidentiality, worker-construction security, and sandbox-claim review.
- Hardening corrections applied: timer cleanup in `terminateWorker` (forced-termination timeout cleared in finally block), explicit listener removal (`removeAllListeners()` for message/error/exit before termination), array index safety (undefined checks for `noUncheckedIndexedAccess`).
- Lifecycle verification: exactly one terminal response per request, stale/duplicate messages safely ignored, no second promise resolution, wrong-worker messages cannot complete request, no recycled worker messages accepted, timers cleared after resolution, no dangling promises or workers, every accepted request settles exactly once, no request runs twice, bounded queue maintained, capacity deterministic, shutdown idempotent, no active worker after successful shutdown.
- Duplicate JSON object keys remain undetected. Adversarial tests prove last-key-wins cannot bypass security gates. Detection without new dependency remains parser-hardening follow-up before OSV enablement.
- No provider retrieval, HTTP, snapshots, persistence, Prisma, migrations, schedulers, durable queues, APIs, matching, Findings, or OSV enablement (`INTELLIGENCE_OSV_ENABLED=true` remains rejected).
- Worker lifecycle hardening is complete. Pending-queue size approval and runtime composition remain blocked. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 5B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Framework-independent OSV persistence contracts exist in `@patchpilot/vulnerability-intelligence` (`src/osv/persistence/`). Identities, inventory, snapshots, parser attempts, parsed revisions, candidate generations, completeness, reconciliation, quarantine, presence, idempotency, activation, and repository ports are contracts only.
- Provider-generation identity is immutable and content-addressed. Body snapshots remain outside PostgreSQL. Object attachment is staged then attached; locators never contain a provider key.
- Parser attempts are immutable. Parser success does not activate a catalog. Matching completeness remains `not_in_scope`. MAL matching remains prohibited.
- Completeness dimensions stay separate. Reconciliation equations are exact integers with no waiver. Quarantine is append-only and blocks activation.
- The active catalog pointer is a contract for later atomic old-to-new replacement. No Prisma, migration, adapter, object storage, provider retrieval, synchronization, Outbox, BackgroundJob, API, permission, matching, or Finding path is included.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) is Proposed, not Accepted. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 5C

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Prisma models and exactly one forward-only migration exist: `20260904120000_osv_acquisition_persistence_foundation`. Frozen SHA-256: `ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349`. Do not edit it; any SQL correction requires another forward-only migration. The persistent development database has twelve finished migrations.
- Global, instance-owned OSV acquisition tables store identities, inventory observations, snapshot/attachment metadata, parser attempts, parsed-revision metadata, candidate generations, separate completeness dimensions, reconciliation counts, append-only quarantine, provider-presence observations, a separate active catalog pointer, and immutable activation history.
- Provider object keys are persisted as bounded validated keys plus SHA-256 digests for generation-bound retrieval. They are never object-storage paths. Body bytes remain outside PostgreSQL. Staged object attachment is metadata only.
- Parser attempts and parsed revisions are immutable rows. Parser success does not activate a catalog. Matching completeness remains `not_in_scope`.
- No active OSV generation is seeded. No object storage, provider retrieval, synchronization, catalog-activation execution against production data, Outbox, BackgroundJob type, API, permission, matching, or Finding path is included.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

### Session 11 Batch 5C-R

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Forward-only migration `20260904180000_osv_parsed_revision_id_check_correction` replaces only `osv_parsed_advisory_revision_osv_id_chk`. Frozen SHA-256: `43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570`. The Batch 5C migration is unchanged. The catalog now has thirteen finished migrations.
- The intended identifier grammar is preserved: nonempty, maximum 512 characters, first character `A-Z` or `0-9`, remaining characters `A-Z0-9._+-`. The CHECK uses `char_length` plus a grammar regular expression without a POSIX counted repetition above 255.
- Parsed-revision rows can now be inserted. The Batch 5C-R migration includes no adapter. Object storage, provider retrieval, synchronization, matching, and Findings remain absent. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding.

### Session 11 Batch 5D

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- `createOsvAcquisitionPersistence` in `@patchpilot/database` implements the committed Batch 5B ports against the frozen Batch 5C schema and the Batch 5C-R CHECK correction. Adapters live in the database package; `@patchpilot/vulnerability-intelligence` remains Prisma-free.
- Unique conflicts are reloaded and compared on immutable fields. Identical content is `already_applied`. Conflicting content is `immutable_conflict`. There is no generic upsert and no last-write-wins.
- Catalog-generation, attachment, and activation-prerequisite graphs are explicit adjacency sets. Transitions use `updateMany` compare-and-swap. Active has only a supersede edge.
- Parser success and parsed-revision attachment are coordinated in one PostgreSQL transaction. Failed attempts cannot reference a revision. After uniqueness abort, the adapter reloads the existing revision by natural key and compares immutable fields. Batch 5C-R makes a successful parsed-revision persist possible. Do not edit the frozen Batch 5C migration.
- Reconciliation uses the committed integer equations with no tolerance. Matching completeness remains `not_in_scope`. MAL matching does not participate in acquisition completeness.
- Quarantine and provider-presence observations are append-only. Absence is not withdrawal, source-license revocation, retrieval `generation_not_found`, parser failure, or catalog exclusion.
- Active-pointer replacement and activation history share one Serializable transaction. Cross-scope previous generations fail closed (`scope_mismatch`) without writing history or mutating the pointer. No production OSV generation is seeded.
- Object storage, provider retrieval, synchronization, schedulers, Outbox, BackgroundJob types, APIs, matching, and Findings remain absent. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed.

### Session 11 Batch 5E

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- `S3OsvAdvisoryObjectStorage` in `@patchpilot/integrations` stores two artifact categories only: provider-body snapshots and parsed structural documents. It reuses the existing private MinIO/S3-compatible bucket, static credentials, `forcePathStyle`, and no public ACL. There is no presigned URL, no caller-selected bucket or endpoint, and no filesystem fallback.
- Attached identity is `intelligence/osv/{advisory_body|parsed_advisory}/sha256/{sha256}`. Staged identity is `intelligence/osv/{advisory_body|parsed_advisory}/tmp/{uuid}`. Provider object keys, advisory IDs, package names, and tenant IDs are never storage paths.
- Write-once uses `If-None-Match: *` plus HEAD compare. Same identity and same SHA-256 is `already_applied`. Same identity and different bytes is `immutable_conflict`. Storage ETag is not content identity. PatchPilot SHA-256 is verified on read-back.
- `createOsvArtifactAttachmentService` in `@patchpilot/vulnerability-intelligence` coordinates Batch 5D PostgreSQL reservation and finalization with object storage. PostgreSQL and object storage are **not** one transaction. Failed storage work cannot create false attached metadata. Cleanup eligibility is determined only; there is no destructive cleanup service except best-effort deletion of a known staged duplicate after successful attach.
- Size policy is the committed snapshot ceiling `OSV_SNAPSHOT_MAX_BYTE_COUNT` (1 MiB) for both categories. Parser output remains 2 MiB, but coordinated attachment rejects above 1 MiB. Transport body-byte policy stays `unavailable` (OD-8 retrieval limit).
- Parsed documents use the committed compact `JSON.stringify` UTF-8 rule and identifier `osv_parsed_advisory_document_v1`. Provider-body retention fails closed for OSV, ECHO, incomplete evidence, legal-review, and ineligible sources.
- Tests use locally generated synthetic bytes only. No live OSV advisory, copied GHSA/CVE body, GCS response, or catalog dump is stored.
- No provider retrieval, HTTP adapter, GCS listing client, synchronization, scheduler, Outbox, BackgroundJob type, API, permission, matching, or Finding path is included. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed.

### Session 11 Batch 5F

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Batch 5F adversarially reviews the committed Batch 5E object-storage adapter, staged attachment protocol, recovery, read-back integrity, PostgreSQL coordination, concurrency, and cleanup eligibility. Production changes are defect corrections only.
- Write-once idempotency hashes stored bytes. HEAD metadata, storage ETag, and spoofed checksums are not content identity. 409 and 412 compare rather than overwrite.
- Recovery stays inside `OSV_STORAGE_CALL_BUDGETS`. Transient storage failures leave staged metadata. Integrity conflicts may reject. Orphaned and rejected rows cannot become attached. False attached state is not accepted when the deterministic object is missing or corrupt.
- Cleanup remains classification-only except the committed best-effort delete of a known temporary identity after successful attachment. In-flight staged objects, attached evidence, referenced objects, and conflicting objects are not executable cleanup targets.
- Layer tests cover the in-memory orchestrator, disposable MinIO, and disposable PostgreSQL attachment adapters. A composed MinIO-plus-PostgreSQL orchestration test is a Batch 6B prerequisite because adding it here would invert package dependencies.
- The 1 MiB snapshot ceiling is an object-storage admission limit. Session 11 Batch 6A-P closed OD-8 retrieval bytes at 1 MiB. Session 11 Batch 6A implements one-attempt generation-bound HTTPS retrieval. Do not treat Batch 5F as synchronization readiness.
- No provider retrieval, synchronization, matching, Findings, or OSV enablement existed in Batch 5F. Synthetic bytes only. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed.

### Session 11 Batch 6A

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Session 11 Batch 6A implements one generation-bound OSV provider-object HTTPS retrieval adapter in `@patchpilot/integrations` (`createOsvGenerationBoundRetrievalHttpsAdapter`). It enforces committed `osv_generation_bound_retrieval_policy_v1`. The injectable `https.request` test seam is not part of the package public export.
- Authorization, GCS get-media request compilation, and the validated result contract live in `@patchpilot/vulnerability-intelligence`. The adapter performs at most one HTTP attempt. Redirects are rejected. There is no retry, backoff, HEAD preflight, Range continuation, listing execution, storage attachment, parser invocation, catalog activation, scheduler, Outbox, BackgroundJob type, API, or permission change.
- Declared-size preflight, source eligibility, and private retention are enforced before HTTP. Generation is an ASCII decimal string bound with `ifGenerationMatch`. Response `x-goog-generation` must equal the requested generation. Received bytes must equal the declared listing size and cannot exceed 1,048,576.
- Streaming SHA-256 is computed over exact received bytes. Identity encoding only. Successful HTTP status is exactly 200. Failures omit body, raw key, URL, headers, Location, provider prose, stack, tenant, package, and Finding data.
- Tests use synthetic local byte streams and injected `node:https.request` / DNS seams only. They do not contact `storage.googleapis.com`. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.
- [ADR 0027](docs/adr/0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed. Synchronization orchestration is Batch 6B.

### Session 11 Batch 6A-R

Session 11 Batch 6A-R adversarially reviews and hardens the committed Batch 6A generation-bound retrieval adapter, resolving the HTTP 500/502/504 retryability inconsistency. These are deliberate:

- Batch 6A-R adds three dedicated orchestration-retryable failure kinds to `osv_generation_bound_retrieval_policy_v1`: `http_500`, `http_502`, and `http_504`. These statuses were declared `orchestration_retryable` in the policy but mapped to non-retryable `unexpected_http_status` at runtime. Now each has an exact dedicated kind with `orchestration_retryable` classification.
- The `mapHttpStatus` function in the HTTPS adapter now maps HTTP 500 to `http_500`, HTTP 502 to `http_502`, and HTTP 504 to `http_504`. HTTP 503 remains `service_unavailable`. HTTP 408 and 429 remain distinct with their own kinds. Unmapped statuses remain `unexpected_http_status` with `non_retryable` classification.
- Comprehensive retryability taxonomy tests verify: (1) HTTP 500/502/504 have dedicated kinds, (2) all three are `orchestration_retryable`, (3) HTTP 503 remains `service_unavailable`, (4) HTTP 408 and 429 remain distinct, (5) `unexpected_http_status` is `non_retryable`, (6) internal consistency between policy and catalog.
- The retrieval adapter performs exactly one HTTP attempt regardless of status (retryable or non-retryable). No internal retry loop exists. Future Batch 6B orchestration owns retry execution and backoff.
- Endpoint compilation remains fixed to `storage.googleapis.com`, HTTPS port 443, exact path prefix `/storage/v1/b/osv-vulnerabilities/o/`, and query parameters `alt=media` and `ifGenerationMatch`. Object names are URI-encoded exactly once. Generation is an ASCII decimal string with no Number conversion.
- Redirects (301, 302, 303, 307, 308) remain rejected with dedicated `redirect_rejected` kind. No redirect target is followed. Response generation must exactly equal requested generation (string equality).
- Compressed responses (gzip, br, deflate) remain rejected. Request sends `Accept-Encoding: identity`. Response must be `identity` or absent.
- Received body bytes are bounded to exactly 1,048,576 (1 MiB). First byte above policy terminates consumption immediately with `response_too_large`. Declared listing size, Content-Length, and received size must reconcile exactly. Partial bodies never succeed.
- Streaming incremental SHA-256 is computed over exact received bytes. ETag and md5Hash are informational only and cannot become PatchPilot content identity.
- Confidential failure taxonomy: body bytes, raw provider object key, complete URL, response headers, provider prose, stack traces, tenant data, package data, and Finding data remain omitted from all failures and events.
- Quality gates pass: 168 integrations tests pass (including 33 retryability tests and 72 retrieval tests with the fix), 753 vulnerability-intelligence tests pass, formatting passes, linting passes, typecheck passes.
- Batch 6A-R does not implement retry execution, backoff, storage attachment, parser invocation, synchronization orchestration, pending-work queue, scheduler, Outbox, BackgroundJob types, APIs, permissions, matching, Findings, or OSV enablement. `INTELLIGENCE_OSV_ENABLED=true` remains rejected. Session 11 remains zero-Finding. Session 12 remains zero-Finding.

## Target repository layout

```text
apps/
  web/                         # Next.js App Router (landing, Session 6 auth UI, /health)
  api/                         # Fastify TypeScript API (health, auth, assets, SBOM upload, intelligence status)

  worker/                      # Node.js TypeScript workers (outbox relay, SBOM ingest, KEV sync)
packages/
  config/                      # typed configuration; only place that may read process.env
  auth/                        # argon2 hashing, session use cases, permissions
  contracts/
  database/                    # Prisma adapters, tenant schema, repository implementations
  domain/                      # Result/error taxonomy; persistence ports; CISA KEV sync service; provider-status query; canonical CVE identity; active-catalog KEV membership; no Prisma types
  integrations/                # Object-storage S3 adapters, restricted CISA KEV HTTPS, OSV generation-bound retrieval HTTPS, Redis ports
  logger/
  observability/
  policy-engine/               # empty boundary
  sbom/                        # vendored CycloneDX JSON schemas; worker-thread parser
  test-utils/
  vulnerability-intelligence/  # vendored CISA KEV JSON Schema; offline Ajv compile; one-shot KEV parser worker
  eslint-config/
  typescript-config/
docs/
  adr/
  architecture/
  product/
  runbooks/
  security/
deploy/
  compose/
  containers/
examples/
  sample-sboms/
  vulnerable-apps/
```

Begin as a modular monolith with separately deployable `web`, `api`, and `worker` applications. Do not introduce microservices without a measured need and an accepted ADR.

## Document map

| Topic | Document |
| --- | --- |
| Product vision and MVP | [docs/product/vision.md](docs/product/vision.md), [docs/product/mvp-scope.md](docs/product/mvp-scope.md), [docs/product/non-goals.md](docs/product/non-goals.md) |
| Users and language | [docs/product/target-users.md](docs/product/target-users.md), [docs/product/glossary.md](docs/product/glossary.md) |
| Definition of done | [docs/development/definition-of-done.md](docs/development/definition-of-done.md) |
| Local setup | [docs/development/local-setup.md](docs/development/local-setup.md), [environment variables](docs/development/environment-variables.md), [testing](docs/development/testing.md), [troubleshooting](docs/development/troubleshooting.md) |
| Git, reviews, releases | [docs/development/branching-strategy.md](docs/development/branching-strategy.md), [docs/development/commit-guidelines.md](docs/development/commit-guidelines.md), [docs/development/review-checklist.md](docs/development/review-checklist.md), [docs/development/pull-request-process.md](docs/development/pull-request-process.md), [docs/development/release-principles.md](docs/development/release-principles.md), [docs/development/release-strategy.md](docs/development/release-strategy.md) |
| CI and repository governance | [docs/development/ci.md](docs/development/ci.md), [docs/development/dependency-management.md](docs/development/dependency-management.md), [docs/development/branch-protection.md](docs/development/branch-protection.md), [docs/development/repository-settings.md](docs/development/repository-settings.md), [docs/development/artifact-retention.md](docs/development/artifact-retention.md) |
| Architecture | [docs/architecture/README.md](docs/architecture/README.md) |
| Security design | [docs/security/README.md](docs/security/README.md) |
| Operational runbooks | [docs/runbooks/README.md](docs/runbooks/README.md) |
| Architecture decisions | [docs/adr/README.md](docs/adr/README.md) |
| Open architecture decisions | [docs/architecture/open-decisions.md](docs/architecture/open-decisions.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Vulnerability disclosure | [SECURITY.md](SECURITY.md) |
| Conduct | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| License | [LICENSE](LICENSE) (Apache License 2.0) |

## Cursor rules

| Rule | When it applies |
| --- | --- |
| [architecture.mdc](.cursor/rules/architecture.mdc) | Always: layering, dependencies, identifiers, time, transactions |
| [security.mdc](.cursor/rules/security.mdc) | Always: the ten security-sensitive areas (canonical) |
| [git-workflow.mdc](.cursor/rules/git-workflow.mdc) | Always: branches, commits, pull requests |
| [testing.mdc](.cursor/rules/testing.mdc) | Tests and fixtures |
| [database.mdc](.cursor/rules/database.mdc) | Prisma, migrations, persistence |
| [api.mdc](.cursor/rules/api.mdc) | Fastify API |
| [frontend.mdc](.cursor/rules/frontend.mdc) | Next.js web app |
| [workers.mdc](.cursor/rules/workers.mdc) | Workers, queue, outbox |
| [integrations.mdc](.cursor/rules/integrations.mdc) | External providers and feeds |
| [documentation.mdc](.cursor/rules/documentation.mdc) | Docs, ADRs, runbooks |

## Security-sensitive areas

Treat these as in-scope for threat modeling and review on every related change. Canonical rules: [architecture.mdc](.cursor/rules/architecture.mdc) and [security.mdc](.cursor/rules/security.mdc). Terms: [docs/product/glossary.md](docs/product/glossary.md).

1. Tenant isolation
2. SBOM handling
3. Vulnerability-intelligence provenance
4. External integrations
5. Background-job idempotency
6. Sensitive log redaction
7. Credential storage
8. Risk-score explainability
9. Audit integrity
10. Development versus production configurations

## Architectural invariants

Do not copy or weakly restate `security.mdc` here. If this file and a rule disagree, keep the stricter security and tenancy interpretation.

- Modular monolith only (`web`, `api`, `worker` share packages/schema). No microservices without an accepted ADR.
- Application **layer** (use cases) lives in `packages/`. Fastify handlers and Next.js are presentation. Next.js is not a second API.
- Deny by default. Tenant-owned data is scoped to the authorized organization, not a client-supplied id.
- Untrusted: SBOMs, archives, webhooks, feeds, headers, URLs, files, external API responses. Validate with Zod at boundaries.
- `process.env` only in `packages/config`. No hardcoded secrets. Canonical log redaction is in `security.mdc`.
- Outbox for durable work; at-least-once; idempotent handlers and relays, org-scoped for tenant work.
- Intelligence is versioned with provenance. Priorities are explainable and policy-versioned. AI must not set authoritative scores.
- Append-only audit for security- and remediation-sensitive operations. No cascade-delete of evidence.

AI features, if added later, are optional explanation and drafting aids. Users must supply their own API key or local compatible endpoint at runtime. API keys must never be hardcoded. The first usable release must work with AI disabled. GitHub and other source-control integrations are not MVP.

## Agent workflow

Before editing:

1. Read this file and applicable files under [`.cursor/rules/`](.cursor/rules/).
2. Inspect the existing repository. Application shells exist; do not assume product features exist.
3. Summarize current state, assumptions, plan, security-sensitive changes, expected files, and ambiguities.
4. Stay inside the requested scope.

During implementation:

1. Work in small coherent batches. Do not rewrite unrelated files.
2. Add or update tests with implementation.
3. Create new database migrations rather than editing applied migrations.
4. Do not add dependencies without explaining why they are required.
5. Prefer established standards and libraries over custom security mechanisms.
6. Run appropriate checks after each coherent batch.
7. Do not scaffold applications or product functionality unless the task explicitly asks for them.

After implementation:

1. List created and modified files.
2. Explain important decisions.
3. Report executed commands and their actual results. Do not claim that commands passed unless they were executed.
4. Identify untested areas, remaining risks, and follow-up work.
5. Suggest one focused Conventional Commit message.
6. Do not describe work as production-ready merely because tests pass.

## Git and reviews

Use short-lived feature branches and [Conventional Commits](docs/development/commit-guidelines.md). Open a pull request. Do not push directly to `main`. Required checks and review expectations are defined in [docs/development/branching-strategy.md](docs/development/branching-strategy.md), [docs/development/ci.md](docs/development/ci.md), and [docs/development/review-checklist.md](docs/development/review-checklist.md).

Do not file security vulnerabilities as public issues. Follow [SECURITY.md](SECURITY.md).
