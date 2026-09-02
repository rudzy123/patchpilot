# Unresolved architecture decisions

These items are intentionally not closed by the v0.1 ADR set. Until an ADR accepts a choice, implementers must follow the **interim default** and must not treat the default as an irreversible product promise.

None of these defaults weaken [tenant isolation](tenant-isolation.md) or [security controls](../security/security-controls.md).

## Closed in Session 6 (ADR 0019)

| ID | Topic | Closed by |
| --- | --- | --- |
| OD-1 | Authentication mechanism | [ADR 0019](../adr/0019-local-password-sessions.md): local email/password for existing users, Argon2id, opaque PostgreSQL sessions, CSRF, generic login failures. No public registration, JWT, or OIDC in v0.1. |
| OD-2 | Session store | [ADR 0019](../adr/0019-local-password-sessions.md) and [ADR 0006](../adr/0006-redis-bullmq.md): PostgreSQL is session authority. Redis is queue transport and login rate limiting only. |
| OD-3 | RBAC permission catalog | [ADR 0019](../adr/0019-local-password-sessions.md) interim four-role permission matrix. A later ADR may supersede the catalog without changing authentication. |

## Closed in Session 8 (ADR 0020)

| ID | Topic | Closed by |
| --- | --- | --- |
| Session 8 `completed` | SBOM ingestion success after evidence verification and graph persist | [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md). Stages `validate`, `parse`, and `persist_graph` only. `correlate`, `enrich`, and `score` remain unused. Future correlation is additive and must not rewrite Session 8 completed rows. |
| Graph completeness | `empty`, `no_dependencies`, `partial`, `complete` | [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md). `empty` does not mean the Asset contains no software. `no_dependencies` does not prove the software has no dependencies. |
| Parser time budget | Wall-clock parse limit | [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md): worker-thread termination, not `Promise.race` around synchronous parse. |

OD-14 (CycloneDX versions beyond 1.6) is unchanged: allowlist 1.4, 1.5, and 1.6.

## Closed in Session 9 Batch 1B (ADR 0021)

| ID | Topic | Closed by |
| --- | --- | --- |
| Session 9 import role | Global, instance-owned, import-only catalog; OSV GCS bulk export + CISA KEV JSON snapshot | [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md). At Batch 1B acceptance (2026-08-31) runtime was **not** implemented. Later Session 9 batches delivered KEV runtime; OSV runtime remains deferred. |
| Zero-Finding invariant | Import must not match components, write Findings/FindingObservations, enrich findings, score, remediate, or enqueue `finding.recalculate` | [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) |
| Import vs correlation | [ADR 0010](../adr/0010-osv-correlation.md) remains future correlation, not the Session 9 import mechanism | [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) |
| Snapshot/provenance strategy | Private raw snapshots, append-only revisions, guarded current-projection activation, content SHA-256 idempotency | [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md). Object-key layout closed in Batch 5B. |

## Closed in Session 9 Batch 2C (configuration)

| ID | Topic | Status after Batch 2C |
| --- | --- | --- |
| OD-8 KEV numeric limits | KEV response, count, parser, HTTP, lease, and staging-chunk bounds | Provisionally resolved for **initial KEV implementation** in `@patchpilot/config`. Values are PatchPilot safety margins from one 2026-08-31 snapshot, not CISA guarantees. |
| OD-8 OSV archive runtime limits | Compressed/expanded `all.zip` operator download authorization | **Remains open.** Observed ~1.43 GiB / ~8.74 GiB / 890,787 entries are documented, not encoded as runtime configuration. OSV runtime remains disabled. |
| OD-19 | Provider-neutral Vulnerability identity | **Remains open.** |

## Closed in Session 9 Batch 4C (KEV persistence)

| ID | Topic | Status after Batch 4C |
| --- | --- | --- |
| OD-20 staging and activation schema | Generation-scoped KEV tables, SQL state machines, atomic activation, and the `intelligence_source` active pointer | **Closed for schema.** Staging, complete, active, superseded, and abandoned generations are persisted. Activation is one PostgreSQL transaction. |

## Closed in Session 9 Batch 5B (CISA HTTPS and snapshot storage)

| ID | Topic | Status after Batch 5B |
| --- | --- | --- |
| OD-20 object-key layout | Temporary and final instance-owned snapshot keys | **Closed.** `intelligence/cisa_kev/cisa_kev_json_catalog/tmp/{uuid}` and `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/{sha256}`. No tenant identifiers, filenames, or signed URLs. |

## Closed in Session 9 Batch 6B (KEV parser)

| ID | Topic | Status after Batch 6B |
| --- | --- | --- |
| KEV parser isolation | One-shot worker thread, transferred bytes, actual `worker.terminate()` | **Closed for parsing** in Batch 6B (historical). Snapshot retrieval, catalog regression, staging, and activation were later delivered in Batches 5B–8B. Worker `resourceLimits` remain a future hardening decision. Duplicate JSON object keys are not detected in v0.1. |

## Closed in Session 9 Batch 9B (ADR 0022)

| ID | Topic | Closed by |
| --- | --- | --- |
| Provider-status authorization | Authenticated `intelligence:read` over instance-owned global status; active Organization is access context, not data scope | [ADR 0022](../adr/0022-intelligence-provider-status-authorization.md) |

OD-10 (instance-operator identity) **remains open**. Batch 9B does not add a cross-organization operator bypass, manual sync, retry, detailed SyncRun APIs, or a dashboard.

## Still open

| ID | Topic | Why it is open | Interim default for design and first implementation |
| --- | --- | --- | --- |
| OD-4 | Credential encryption key management | Envelope encryption needs an operator key, KMS, or Vault. | AES-256-GCM data keys wrapped by an operator-supplied key encryption key (KEK) loaded only through `packages/config`. No cloud KMS required for MVP. |
| OD-5 | Production object-storage vendor | The port is S3-compatible; AWS, MinIO, or GCS interop is an operations choice. | Provider-neutral port ([ADR 0008](../adr/0008-private-object-storage.md)). Local Compose uses MinIO. Production uses any S3-compatible private bucket the operator provides. |
| OD-6 | Application-layer package split | Use cases could live in `packages/domain` or a dedicated package. | Use cases live in `packages/domain` as application services. Revisit only if the package becomes unwieldy. |
| OD-7 | Priority vs risk score split | Glossary treats them as the same until an ADR splits them. | Keep **priority** as the stored calculated ranking. **Risk score** is a synonym. Do not introduce a second authoritative number. |
| OD-8 | Exact outbound rate-limit and import size numbers | KEV limits are provisionally in `@patchpilot/config`. OSV archive runtime limits are still not an operator download authorization. Conditional GET is not the KEV protocol. | Use the typed KEV bounds. Keep `INTELLIGENCE_OSV_ENABLED=false`. Do not treat earlier prose (30 req/min, 5 MiB) as provider SLAs. Do not encode the deferred ~1.8 GiB / ~11 GiB OSV discussion values as Session 9 configuration. |
| OD-9 | Notification channels | Email, chat, or in-app-only is unspecified. | In-app state and exports only for MVP. No outbound notification provider. |
| OD-10 | Instance operator identity | How a self-hosted admin authenticates separately from organization membership. | A config-gated bootstrap user that can manage **IntelligenceSource** rows and shared catalogs only. No cross-organization read of tenant evidence. A bypass ADR is required before any cross-org operator console. |
| OD-11 | Team semantics | Teams are in the domain model; MVP journey does not require them. | Persist Team and optional AssetOwner.teamId. Do not block the MVP journey on teams. |
| OD-12 | RepositoryConnection provider | GitHub is not MVP. | Persist the entity with status `not_configured`. No webhooks, no tokens, no repo API calls. |
| OD-13 | Backup encryption and off-site copies | Operator responsibility for a self-hosted system. | Document duties in [deployment-model.md](deployment-model.md) and [retention-and-deletion.md](retention-and-deletion.md). Do not ship a hosted backup service. |
| OD-14 | CycloneDX minor versions beyond 1.6 | Spec will evolve. | Allowlist 1.4, 1.5, and 1.6. New versions need an ADR and parser tests. |
| OD-15 | Matching algorithm details beyond OSV ranges | PURL aliases, CPE, and fuzzy name match are high-risk. | Exact ecosystem + package + version using OSV ranges and PURL when present. No fuzzy name match in MVP. Session 9 must not run matching ([ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md)). |
| OD-16 | Reserved organization slugs | Product URL routing is not implemented. A unique slug is not enough to keep `api`, `health`, `login`, and similar names off tenant routes. | Document the gap; do not invent a reserved-slug list in the database until routing exists. |
| OD-17 | MFA and account lockout | [ADR 0019](../adr/0019-local-password-sessions.md) specifies Argon2id and fail-closed login rate limits, not MFA or durable lockout. | Dual-key Redis login limits. No MFA. No lockout table. Revisit before treating the product as resistant to credential stuffing beyond those controls. |
| OD-18 | Reverse-proxy trust hops | `trustProxy` remains false in Session 6. Production TLS topology is operator-specific. | Direct socket peer IP for login rate limits. Do not trust `X-Forwarded-For`. Document hops in a later ADR before enabling `trustProxy`. |
| OD-19 | Provider-neutral Vulnerability identity | Existing required unique `osvId` cannot store a KEV-only CVE without a synthetic id or schema change. | Keep `osvId` until a later database-design ADR. Do not invent a Session 9 identity migration in Batch 1B. |
| OD-21 | Session 9 scheduler, heartbeat, and retry policy | Bounded automatic retry is required; cadence is not. | Follow Session 8 outbox + BackgroundJob leases. Terminal runs stay historical; replay creates a new run. Batch 8B runs a UTC schedule-window scheduler, maps `intelligence.sync.requested.v1` to `intelligence.sync`, and redispatches from PostgreSQL. BullMQ delayed jobs are a fast path only. BackgroundJob remains the only execution lease. |

Related: [ADR index](../adr/README.md), [architecture risk register](../security/risk-register.md).
