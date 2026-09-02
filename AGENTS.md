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

The Session 3 **development foundation** and Session 4 CI/governance are in place. Session 5 adds the PostgreSQL tenant schema, repository adapters, migrations, and database integration tests. Session 6 Batch 1 accepts [ADR 0019](docs/adr/0019-local-password-sessions.md) (local passwords, opaque sessions, CSRF, interim permissions) and typed auth configuration. `packages/auth` installs `argon2@0.45.1`. Session 6 Batch 2 persists `LocalCredential`, opaque `Session` rows (digest-only), and audit actor columns (`anonymous`, restored `actorUserId`). Hashing, session use cases, and fail-closed login abuse control exist in `packages/auth` (Redis adapter in `apps/api`). Session 6 Fastify authentication routes are implemented: `POST /auth/login`, `POST /auth/logout`, `GET /auth/session`, `GET /auth/organizations`, and `POST /auth/select-organization` (cookies, Origin, CSRF, JSON-only mutations, no-store, audit, login limiter). Session 6 minimal web authentication is implemented: `/login`, client session bootstrap, organization selection, logout, expired-session, and access-denied. CSRF stays in React memory only; the session cookie remains HttpOnly. Session 7 persists asset inventory. Session 8 Batch 1 accepts [ADR 0020](docs/adr/0020-sbom-ingestion-graph-completion.md) (graph-complete ingestion semantics) and typed SBOM ingestion limits in `packages/config`. Session 8 Batch 2 vendors CycloneDX JSON schemas 1.4–1.6 (specification tag `1.6.1`) and installs parser/storage dependencies (`ajv@8.20.0`, `ajv-formats@3.0.1`, `packageurl-js@2.0.1`, `secure-json-parse@4.1.0`, `@aws-sdk/client-s3@3.1120.0`). Session 8 Batch 3 adds SBOM HTTP contracts, the Session 8 ingestion state machine, known/unknown component versions, normalized graph DTOs, and provider-neutral persistence/storage/job ports. Session 8 Batch 4 adds the forward-only migration `20260830120000_sbom_ingestion_graph_persistence` and Prisma adapters for SBOM metadata, ingestion, upload idempotency, outbox claim, BackgroundJob execution, and insert-once graph persistence. The Session 8 graph-persistence migration is **frozen**. Do not edit it; any SQL correction requires another forward-only migration. Session 8 Batch 5 implements private streaming S3-compatible SBOM object storage (`S3SbomObjectStorage` in `@patchpilot/integrations`, MinIO-compatible, no public ACL, no signed URLs). Session 8 Batch 6 implements the framework-independent authorized and idempotent SBOM upload use case (`createUploadSbomUseCase` in `@patchpilot/domain`): hashed Idempotency-Key reservation, streaming put/promote outside PostgreSQL, duplicate-evidence reuse, atomic metadata/audit/outbox/idempotency finalization, and best-effort temporary cleanup. Session 8 Batch 7 implements Fastify SBOM routes (`POST /assets/:assetId/sboms`, `GET /assets/:assetId/sboms`, `GET /assets/:assetId/sboms/:sbomId`, `GET /assets/:assetId/sbom-ingestions/:ingestionId`): session authentication, active Organization, `sbom:upload`/`sbom:read`, tenant-safe not-found, archived Asset conflict, exact Origin, synchronizer CSRF, required `Idempotency-Key`, raw-body streaming, approved UTF-8 JSON content types, per-route upload size, direct peer-IP and Organization rate limits, `trustProxy=false`, outbox-only (no request-path queue publication), and `Cache-Control: private, no-store`. Public responses omit object keys, filenames, worker IDs, lease fields, parser details, and audit payloads. Session 8 Batch 8 implements the worker outbox relay (PostgreSQL `SKIP LOCKED` claim, commit lease, BullMQ.add with deterministic job ID, mark `OutboxEvent` processed, create or reuse `BackgroundJob`). Session 8 Batch 9 implements the worker-thread CycloneDX parser in `@patchpilot/sbom`: `worker.terminate()` wall-clock timeout, secure JSON parse, prototype-key rejection, depth/node/string limits, offline CycloneDX 1.4–1.6 schemas, semantic limits, PURL normalization, explicit unknown versions, duplicate bom-ref rejection, unknown dependency-ref rejection, self-edge omission with `self_dependency_skipped`, cycle retention, bounded normalized results, and graph completeness. Persistence continues to reject DTO-invalid graphs (including remaining self-edges) and does not add self-edge warning behavior. Session 8 Batch 10 implements the ingestion processor in `apps/worker`: BullMQ `sbom.ingest` jobs, ids-only payload validation, BackgroundJob lease claim, authoritative tenant reload, stored-object GET with size and SHA-256 verification, worker-thread parse, transactional graph persist (no storage or Redis in that transaction), Asset pointer update, system audit, and terminal job marking. Session 8 Batch 11 completes the ingestion documentation set: the raw upload contract, storage behavior and failure categories, idempotency layers, orphan handling, outbox relay constants, job leases, parser timeout and quarantine, and the closed safe-failure catalog in [docs/architecture/sbom-ingestion.md](docs/architecture/sbom-ingestion.md), with matching updates to the reliability model, audit catalog, retention, threat model, risk register, local MinIO setup, and the ingestion, outbox, background-job, and local-infrastructure runbooks. The SBOM upload-to-graph path is therefore runnable end to end against local Compose infrastructure. Session 9 Batch 1B accepts [ADR 0021](docs/adr/0021-vulnerability-intelligence-import-foundation.md): global, instance-owned, import-only vulnerability intelligence from OSV GCS bulk export (`all.zip` completeness baseline) and the CISA KEV JSON snapshot, with an explicit zero-Finding boundary. Session 9 Batch 2C adds typed KEV-first intelligence configuration in `@patchpilot/config`. Session 9 Batch 3B vendors the official CISA KEV JSON Schema under `packages/vulnerability-intelligence/vendor/cisa-kev-schema/` and adds offline Ajv draft-07 compilation in `@patchpilot/vulnerability-intelligence` (`ajv@8.20.0`, `ajv-formats@3.0.1`, `secure-json-parse@4.1.0`). Session 9 Batch 4A adds KEV intelligence public status contracts, global domain records, sync-run transition rules, safe failure taxonomy, provider-neutral ports, outbox payload types, parser-thread DTOs, and system audit command types. Session 9 Batch 4C adds the forward-only migration `20260901120000_kev_intelligence_persistence`, domain snapshot/generation/audit corrections, and PostgreSQL adapters for SyncRun, snapshots, generations, atomic activation, scheduler request, not-modified, failure, and freshness. The Session 9 KEV persistence migration is **frozen**. Do not edit it; any SQL correction requires another forward-only migration. OSV runtime remains disabled (`INTELLIGENCE_OSV_ENABLED=true` fails validation). Session 9 Batch 5B adds restricted CISA KEV HTTPS transport (`node:https.request`, no redirects, no proxies, lookup-pin plus post-connect verification) and private S3-compatible intelligence snapshot storage in `@patchpilot/integrations`, reusing the existing Session 8 bucket. Snapshot keys are `intelligence/cisa_kev/cisa_kev_json_catalog/tmp/{uuid}` and `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/{sha256}`. Session 9 Batch 6B adds secure CISA KEV parsing, deterministic normalization, and one-shot worker-thread execution in `@patchpilot/vulnerability-intelligence` (`worker.terminate()` wall-clock timeout, strict UTF-8, secure JSON parse, iterative structural limits, offline official-schema validation, PatchPilot semantic checks, and a 16 MiB serialized-result ceiling). Session 9 Batch 7B adds the framework-independent CISA KEV synchronization service in `@patchpilot/domain` (`createCisaKevSynchronizationService`): authoritative job/outbox/SyncRun prechecks, crash-safe persisted-stage resume, provider fetch and snapshot orchestration, content-hash not-modified, catalog-regression quarantine, dense-prefix staging, atomic activation, BackgroundJob-only lease heartbeat, and pre-snapshot `retry_wait` versus post-snapshot job retry. Session 9 Batch 8B adds the worker KEV scheduler (UTC schedule windows, PostgreSQL dedupe), Outbox mapping of `intelligence.sync.requested.v1` to `intelligence.sync`, a shared `patchpilot` BullMQ Worker with concurrency 2, PostgreSQL-backed retry reconciliation, IntelligenceSource enablement reconciliation, and graceful shutdown. Session 9 Batch 9B accepts [ADR 0022](docs/adr/0022-intelligence-provider-status-authorization.md) and implements authenticated sanitized provider-status GETs (`GET /intelligence/providers`, `GET /intelligence/providers/:provider/status`) with `intelligence:read` for viewer, member, admin, and owner. Active Organization is product-access context, not a data-scope predicate on global intelligence rows. No web UI, dashboard, ZIP dependency, production catalog body, OSV runtime, manual synchronization, manual retry, detailed SyncRun API, or Finding integration exists. [ADR 0010](docs/adr/0010-osv-correlation.md) remains the future correlation ADR, not the Session 9 import mechanism. Generic Finding persistence exists and stays unused by Session 9. Web UI is **not** implemented. Registration, invitation, password reset, session listing, remote revoke, dashboards, and product UIs are **not** implemented. Live vulnerability-provider calls occur only from the worker intelligence processor after authoritative claim, never during configuration load or status GETs. Risk-scoring logic is **not** implemented. Session 10 Batch 1B accepts [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) and adds provider-neutral canonical CVE identity domain boundaries in `@patchpilot/domain` (`CveIdentity`, `VulnerabilityCveIdentityLink`, ensure commands, and persistence ports). Session 10 Batch 3A added the forward-only migration `20260902120000_canonical_cve_identity` with global append-only `cve_identity` and `vulnerability_cve_identity` tables, a canonical CVE CHECK, and exact canonical-only backfill from `vulnerability.cve_id`. Session 10 Batch 3B applied that migration to the persistent development database (eleven finished migrations) and froze it (SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). Persistence adapters, read-only KEV derivation, workers, APIs, permissions, and Finding-adjacent writes remain later work. Session 10 remains zero-Finding. `Vulnerability.osvId` remains required and unique. KEV membership remains a global exploitation signal, not proof of tenant exposure. v0.1 architecture, security design, and operational runbooks exist under `docs/architecture/`, `docs/security/`, and `docs/runbooks/`. ADRs 0001–0023 are **Accepted**. The layout below is the modular monolith. Do not invent a different topology without an accepted ADR.

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
- Existing required unique `osvId` is unchanged. [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) accepts canonical CVE identity. Batch 3B applied and froze `20260902120000_canonical_cve_identity`; adapters remain future. Full provider-neutral Vulnerability advisory identity remains open ([OD-19](docs/architecture/open-decisions.md)).
- Delivery remains at-least-once. PostgreSQL uniqueness and BackgroundJob leases are authority; Redis job IDs are not exact-once.
- Instance-operator identity remains unresolved ([OD-10](docs/architecture/open-decisions.md)).
- Session 9 is not complete.

### Session 10 Batch 1B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- [ADR 0023](docs/adr/0023-provider-neutral-cve-identity.md) is accepted on this feature branch. Canonical CVE identity and advisory-to-CVE links are domain records, commands, and provider-neutral ports only.
- The current application has no production Finding creation path. The policy engine remains without production scoring.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, or Finding-adjacent command is added.
- `Vulnerability.osvId` remains required and unique. No Vulnerability rows are merged by CVE. No OSV identifier is manufactured.
- Canonical CVE identity persistence and the forward-only identity migration remain future relative to Batch 1B. Do not treat Batch 1B types as a shipped adapter.
- KEV membership remains a global exploitation signal, not proof of tenant exposure. Read-only active-KEV derivation is not implemented in Batch 1B.
- No API route, worker, Outbox event, permission, or web UI was added in Batch 1B.

### Session 10 Batch 3B

These are deliberate. Do not silently close one inside an unrelated change, and do not write documentation that assumes any of them exists:

- Migration `20260902120000_canonical_cve_identity` was applied to the persistent development database. That catalog now has eleven finished migrations.
- The migration is **frozen**. Frozen SHA-256: `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`. Do not edit it; any SQL correction requires another forward-only migration.
- Two global append-only tables exist: `CveIdentity` (`createdAt` only) and `VulnerabilityCveIdentityLink` (`linkedAt` only, source-free). Canonical-only backfill completed. Malformed legacy `cveId` values remain unchanged and unlinked.
- No CveIdentity persistence adapter, mapper, repository factory, or runtime service exists.
- Read-only active-KEV derivation is not implemented. `KevEntry` is unchanged.
- Session 10 remains zero-Finding. No Finding, FindingObservation, Evidence, RiskCalculation, Outbox, BackgroundJob, API, worker, permission, risk, or web UI change is included. No fan-out runtime was added.
- `Vulnerability.osvId` remains required and unique. `Vulnerability.cveId` remains nullable `VARCHAR(32)` and unchanged. No Vulnerability merge occurred. OSV remains deferred.

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
  domain/                      # Result/error taxonomy; persistence ports; CISA KEV sync service; provider-status query; canonical CVE identity; no Prisma types
  integrations/                # Object-storage S3 adapters, restricted CISA KEV HTTPS, Redis ports
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
