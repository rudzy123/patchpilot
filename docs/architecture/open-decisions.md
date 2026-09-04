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
| OD-8 OSV archive runtime limits | Compressed/expanded `all.zip` operator download authorization | **Deferred and not authorized.** [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md) does not approve `all.zip` as the first implementation. ZIP remains absent. Dated Session 9 size observations in [vulnerability-intelligence.md](vulnerability-intelligence.md) are non-contractual and are not download authorization. OSV runtime remains disabled. Session 11 Batch 3C compiles listing page-size and listing-page byte-cap constants only; those are not archive or object-body limits. |
| OD-19 | Provider-neutral Vulnerability identity | **Partially resolved** for canonical CVE identity by [ADR 0023](../adr/0023-provider-neutral-cve-identity.md). Migration `20260902120000_canonical_cve_identity` is applied and frozen on the persistent development database (eleven migrations; SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). Batch 4B ships `createCveIdentityPersistence`. Batch 5B adds read-only active-catalog membership derivation. Full advisory-identity replacement of `osvId` remains open. |

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

## Closed in Session 10 Batch 1B (ADR 0023)

| ID | Topic | Status after Batch 1B |
| --- | --- | --- |
| OD-19 canonical CVE identity | Global `CveIdentity` plus append-only `VulnerabilityCveIdentityLink` | **Partially resolved.** [ADR 0023](../adr/0023-provider-neutral-cve-identity.md) accepts the identity model. Batch 3B applied and froze `20260902120000_canonical_cve_identity` (SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). Batch 4B implements insert-once persistence adapters (`identities` and `links`). Batch 5B implements read-only active-catalog membership for one exact canonical CVE. Full advisory-identity replacement of `osvId` remains open. Finding enrichment remains blocked. The persistent development database has eleven finished migrations. |
| Full provider-neutral Vulnerability advisory identity | Replacing required unique `Vulnerability.osvId` | **Remains open.** `osvId` stays required and unique. |
| OSV runtime | Session 9/10 import of OSV dumps | **Remains deferred.** `INTELLIGENCE_OSV_ENABLED=true` stays rejected. |
| Finding correlation | Advisory-to-component matching and Finding writes | **Remains blocked** by the ADR 0023 four-condition gate and [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) zero-Finding. |
| Risk integration | Known-exploitation as a scored factor | **Remains deferred.** The production policy engine has no scoring implementation. |
| Finding APIs | Tenant Finding HTTP | **Remain absent.** Session 10 does not add them. |

## Closed in Session 11 Batch 1B (ADR 0024)

| ID | Topic | Status after Batch 1B |
| --- | --- | --- |
| Affected-version authority | Which provider supplies package-specific affected versions | **Closed as direction.** [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md) selects OSV. CISA KEV remains an exploitation signal only. Tenant SBOMs remain inventory. Canonical CVE identity remains identifier linkage. Current `VulnerabilityNormalizedJson.affectedPackages` is not matching authority. |
| Tenant package query APIs | `POST /v1/query` and other queries that send tenant PURLs, names, or versions | **Rejected** for the approved foundation. Tenant inventory must not leave the instance. |
| OSV acquisition model | How the instance obtains OSV data | **Instance-owned catalog acquisition** is the approved direction. Acquisition is independent of tenant matching. Provider data is stored privately and activated atomically. Exact host, path, listing, licensing, removal semantics, and limits remain subject to transport and provenance review. Implementation is not authorized until that review completes. |
| Provider object export | Allowlisted HTTPS objects from a closed OSV-controlled host | **Preferred direction to investigate** for the first implementation. Not implemented. Arbitrary public bucket listing is not automatically safe. |
| Per-advisory OSV API | Fetch by known instance-owned advisory ID | **Deferred** as a possible later reconciliation mechanism. Not a complete catalog. Must not accept tenant package identifiers. |
| `all.zip` | OSV full-database ZIP export | **Not approved** for initial implementation. [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) completeness-baseline research remains historical context. |
| Ecosystem archives | Per-ecosystem ZIP subsets | **Deferred.** Still require ZIP. Completeness and global deletion/withdrawal authority are unproven. Closed ecosystems belong to [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md). |
| Hybrid acquisition | Object export plus optional per-ID reconciliation, archive only after measured approval | **Permitted later refinement.** Must not include tenant package queries. |
| ZIP / archive support | Archive extraction, ZIP dependency, compressed/expanded limits | **Deferred and not authorized.** No ZIP dependency. Not closed as implemented. |
| OSV runtime | `INTELLIGENCE_OSV_ENABLED=true` | **Remains rejected** until transport, licensing, limits, parser, persistence, frozen migration, zero-Finding tests, runbooks, and adversarial review all pass. Batch 1B does not enable OSV. |
| Matching completeness | Advisory-to-component version evaluation | **Not complete.** Session 11 remains zero-Finding. Matching is Session 12 or later. Package identity and fail-closed evaluation architecture are accepted by [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md). No comparator or evaluator exists. The implemented ecosystem set is empty. |
| Provider ingestion completeness | OSV transport, parser, snapshots, generations, scheduler, worker | **Not complete.** No OSV runtime exists. |
| Finding evidence and lifecycle | Match evidence, Finding writes, observations | **Architecture accepted** by [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md). Schema, persistence, ensure repositories, and lifecycle automation remain unimplemented. Finding writes are Session 13 or later, subject to all gates. ADR acceptance does not authorize writes. |
| Full provider-neutral Vulnerability advisory identity | Replacing required unique `Vulnerability.osvId` | **Remains open** ([OD-19](#still-open)). This ADR does not make `osvId` nullable. |

## Closed in Session 11 Batch 1C (ADR 0025)

| ID | Topic | Status after Batch 1C |
| --- | --- | --- |
| Package identity | How a tenant component and an OSV affected package are compared | **Closed as architecture.** [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md) selects an ecosystem-aware identity: closed ecosystem, normalized name, namespace when required, optional derived versionless PURL, and a normalization version. A free-form display name or unparsed PURL is not the authoritative key. |
| PURL as sole identity | Versionless PURL as the only matching key | **Rejected** as sole identity. PURL remains a derived identifier and registry input. Conversion does not exist. Qualifiers are not automatic identity. Unknown or unreviewed identity-changing qualifiers return `unsupported`, not `indeterminate` or `not_affected`. |
| Generic matchers | Package-name-only, lexical version, or one-semver-for-all comparison | **Rejected.** Unsupported ecosystems fail closed. |
| Evaluator result model | Future affected-version evaluation statuses | **Closed as architecture.** Normal statuses are `affected`, `not_affected`, `indeterminate`, `unsupported`, and `withdrawn`. Invalid input and operational failures use `Result`/`AppError`. Evaluation remains zero-Finding in Session 11 and Session 12. |
| Implemented ecosystems | Runtime registry contents | **Empty.** npm, PyPI, Maven, Go, NuGet, and crates.io are candidates to evaluate, not supported ecosystems. |
| First ecosystem | Session 12 starting ecosystem | **Not selected.** OSV catalog measurements and affected-range inventory are absent. npm is the preferred candidate to evaluate first after those measurements. Session 12 should still implement one ecosystem first, with no generic fallback. |
| GIT ranges | Commit ancestry matching | **Deferred / unsupported** in the initial matcher. Do not fetch repositories. Return `unsupported`. |
| Finding writes from evaluation | Evaluator creating Findings | **Rejected.** Only a later deterministic `affected` result may eventually contribute, and only after ADR 0026 gates and explicit authorization. |

## Closed in Session 11 Batch 1D (ADR 0026)

| ID | Topic | Status after Batch 1D |
| --- | --- | --- |
| Finding natural key | Logical identity across rescans and upgrades | **Closed as architecture.** [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) selects `organizationId` + `assetId` + `componentId` + `vulnerabilityId`. Existing `finding_identity_key` already matches. ComponentOccurrence, SBOM, ingestion, CVE, CveIdentity, OSV revision, KEV, and package version are not part of the key. |
| Match-evaluation evidence | Dedicated positive-match proof | **Closed conceptually.** Future tenant-owned append-only `VulnerabilityMatchEvaluation`. Not implemented. No schema, repository, or domain contract in Batch 1D. |
| Match-evaluation persistence | Table, fingerprint, ensure | **Not implemented.** Bounded candidate comparisons only; no Cartesian product. |
| FindingObservation semantics | One summarized observation per Finding per ingestion | **Closed as architecture.** Natural key `organizationId` + `findingId` + `sbomIngestionId` already exists. Results are `present`, `absent`, and `inconclusive`. Ensure repository remains absent. |
| Current-ingestion authority | Which ingestion may update current Finding projection | **Specified, not consumed.** Use existing `Asset.lastSuccessfulSbomIngestionId` (greatest SBOM `receivedAt` among `completed` ingestions; tie-break ingestion `createdAt`, then id). Session 13 must apply this rule before Finding writes. Do not invent timestamp-only authority. |
| Finding ensure and observation repositories | Idempotent create/reload | **Remain absent.** Generic `FindingRepository.create` is insufficient. |
| Finding lifecycle automation | Create, observe, resolve, reopen | **Architecture accepted, runtime absent.** Session 11 and Session 12 remain zero-Finding. |
| KEV-after-Finding projection | Membership on a proven Finding | **Deferred.** KEV may be derived only after an `affected` Finding exists. KEV still creates no Finding. |
| Risk integration | Scoring from matching | **Deferred.** No `finding.recalculate`. No RiskCalculation from match evaluation. |
| Finding writes | Production Finding creation | **Blocked.** Session 13 is the earliest candidate. All ADR 0026 gates remain required. ADR acceptance does not authorize writes. |

## Closed in Session 11 Batch 4B-P (parser resource policy)

| ID | Topic | Closed by |
| --- | --- | --- |
| OD-8 parser numeric subset | OSV advisory parser resource limits | Session 11 Batch 4B-P closes `osv_advisory_parser_resource_policy_v1` with exact PatchPilot v1 ceilings (1 MiB input, 2 MiB output, depth 32, and the remaining table in [vulnerability-intelligence.md](vulnerability-intelligence.md)). Values are security policy, not provider guarantees. Oversize records fail closed and must not be silently omitted from a complete generation. Provider-object body retrieval limits, continuation-token byte bounds, ZIP, and outbound rate limits remain in OD-8. |

## Closed in Session 11 Batch 4C (advisory reference parser)

| ID | Topic | Closed by |
| --- | --- | --- |
| OD-8 parser execution subset | In-process bounded advisory parse | Session 11 Batch 4C implements `parseOsvAdvisoryWithInProcessReferenceParser` against parser resource-policy v1 and the pinned Batch 4A schema. Production worker isolation, provider-object retrieval byte limits, continuation-token bounds, and ZIP remain open in OD-8. |

## Closed in Session 11 Batch 4D (parser adversarial review)

| ID | Topic | Closed by |
| --- | --- | --- |
| OD-8 parser hardening subset | Adversarial review of the Batch 4C parser | Session 11 Batch 4D reviews the in-process parser with synthetic hostile inputs, rejects whitespace/control OSV ids, remaps unexpected internals to `worker_protocol_error`, and documents last-key-wins as a non-bypass limitation. Production worker isolation remained unauthorized after Batch 4D. Duplicate-key detection without a new dependency remains a follow-up before OSV runtime enablement. |

## Closed in Session 11 Batch 4E (parser isolation design)

| ID | Topic | Closed by |
| --- | --- | --- |
| OD-8 parser isolation subset | Production isolation architecture for the bounded OSV advisory parser | Session 11 Batch 4E selects `worker_threads`, closes worker timeouts (5 s init, 5 s parse, 250 ms cancel grace, 1 s forced terminate), schema loading inside the isolate, one-request-at-a-time Ajv ownership, pool size 1, sequential reuse, transfer/recycle/failure mapping, and duplicate-key disposition. The worker is **not** implemented. Pending-queue size stays `unavailable`, so runtime composition remains blocked. Provider-object body retrieval limits, continuation-token bounds, and ZIP remain open in OD-8. |

## Still open

| ID | Topic | Why it is open | Interim default for design and first implementation |
| --- | --- | --- | --- |
| OD-4 | Credential encryption key management | Envelope encryption needs an operator key, KMS, or Vault. | AES-256-GCM data keys wrapped by an operator-supplied key encryption key (KEK) loaded only through `packages/config`. No cloud KMS required for MVP. |
| OD-5 | Production object-storage vendor | The port is S3-compatible; AWS, MinIO, or GCS interop is an operations choice. | Provider-neutral port ([ADR 0008](../adr/0008-private-object-storage.md)). Local Compose uses MinIO. Production uses any S3-compatible private bucket the operator provides. |
| OD-6 | Application-layer package split | Use cases could live in `packages/domain` or a dedicated package. | Use cases live in `packages/domain` as application services. Revisit only if the package becomes unwieldy. |
| OD-7 | Priority vs risk score split | Glossary treats them as the same until an ADR splits them. | Keep **priority** as the stored calculated ranking. **Risk score** is a synonym. Do not introduce a second authoritative number. |
| OD-8 | Exact outbound rate-limit and import size numbers | KEV limits are provisionally in `@patchpilot/config`. Session 11 Batch 3C compiles OSV GCS listing `maxResults` (`1000`) and listing-page byte cap (`1,048,576`) in `@patchpilot/vulnerability-intelligence`. Session 11 Batch 4B-P closes **parser** numeric limits as PatchPilot policy on `osv_advisory_parser_resource_policy_v1` (not provider maxima). Session 11 Batch 4C executes those parser limits in-process for synthetic bounded bytes. Session 11 Batch 4D adversarially reviews that parser; last-key-wins duplicate JSON keys remain undetected and cannot bypass identity or eligibility. Session 11 Batch 4E closes **parser isolation design** (`worker_threads`, exact worker timeouts, schema-load/Ajv/reuse/transfer rules) without implementing a worker. Pending-queue size, continuation-token byte bounds, **provider-object body** retrieval limits, and ZIP remain unselected. Conditional GET is not the KEV protocol. | Use the typed KEV bounds. Use the compiled GCS listing protocol constants for listing construction and page parsing only. Use parser resource policy v1 and the in-process reference parser only for locally supplied bounded bytes and synthetic tests. Use the Batch 4E isolation design only as the contract for a later worker batch. Keep provider-object retrieval deferred. Keep `INTELLIGENCE_OSV_ENABLED=false`. Do not treat earlier prose (30 req/min, 5 MiB) as provider SLAs. Do not encode dated or discussion-only OSV archive sizes as configuration or as first-implementation authorization. |
| OD-9 | Notification channels | Email, chat, or in-app-only is unspecified. | In-app state and exports only for MVP. No outbound notification provider. |
| OD-10 | Instance operator identity | How a self-hosted admin authenticates separately from organization membership. | A config-gated bootstrap user that can manage **IntelligenceSource** rows and shared catalogs only. No cross-organization read of tenant evidence. A bypass ADR is required before any cross-org operator console. |
| OD-11 | Team semantics | Teams are in the domain model; MVP journey does not require them. | Persist Team and optional AssetOwner.teamId. Do not block the MVP journey on teams. |
| OD-12 | RepositoryConnection provider | GitHub is not MVP. | Persist the entity with status `not_configured`. No webhooks, no tokens, no repo API calls. |
| OD-13 | Backup encryption and off-site copies | Operator responsibility for a self-hosted system. | Document duties in [deployment-model.md](deployment-model.md) and [retention-and-deletion.md](retention-and-deletion.md). Do not ship a hosted backup service. |
| OD-14 | CycloneDX minor versions beyond 1.6 | Spec will evolve. | Allowlist 1.4, 1.5, and 1.6. New versions need an ADR and parser tests. |
| OD-15 | Matching algorithm details beyond OSV ranges | Identity and fail-closed results are accepted by [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md). Finding identity and lifecycle architecture are accepted by [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md). Remaining: first ecosystem selection after OSV measurements, comparator implementation, exact event-edge proof, numeric limits, match-evaluation persistence, and Finding-write authorization. | Do not run matching in Session 9 or Session 11. Session 12 may implement evaluation only and must remain zero-Finding (no Finding writes). The implemented ecosystem set is empty. Tenant package query APIs are rejected ([ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md)). No fuzzy name match, generic semver, or lexical fallback. Do not match against current `affectedPackages` JSON. |
| OD-16 | Reserved organization slugs | Product URL routing is not implemented. A unique slug is not enough to keep `api`, `health`, `login`, and similar names off tenant routes. | Document the gap; do not invent a reserved-slug list in the database until routing exists. |
| OD-17 | MFA and account lockout | [ADR 0019](../adr/0019-local-password-sessions.md) specifies Argon2id and fail-closed login rate limits, not MFA or durable lockout. | Dual-key Redis login limits. No MFA. No lockout table. Revisit before treating the product as resistant to credential stuffing beyond those controls. |
| OD-18 | Reverse-proxy trust hops | `trustProxy` remains false in Session 6. Production TLS topology is operator-specific. | Direct socket peer IP for login rate limits. Do not trust `X-Forwarded-For`. Document hops in a later ADR before enabling `trustProxy`. |
| OD-19 | Provider-neutral Vulnerability identity | Existing required unique `osvId` cannot store a KEV-only CVE without a synthetic id or schema change. Canonical CVE identity is accepted by [ADR 0023](../adr/0023-provider-neutral-cve-identity.md). Batch 3B applied and froze `cve_identity` persistence. Batch 4B ships insert-once adapters. Batch 5B derives active-catalog membership without creating identity rows. | Keep `osvId` required and unique. Do not edit frozen `20260902120000_canonical_cve_identity`. Finding enrichment and full advisory-identity replacement remain open. |
| OD-21 | Session 9 scheduler, heartbeat, and retry policy | Bounded automatic retry is required; cadence is not. | Follow Session 8 outbox + BackgroundJob leases. Terminal runs stay historical; replay creates a new run. Batch 8B runs a UTC schedule-window scheduler, maps `intelligence.sync.requested.v1` to `intelligence.sync`, and redispatches from PostgreSQL. BullMQ delayed jobs are a fast path only. BackgroundJob remains the only execution lease. |

Related: [ADR index](../adr/README.md), [architecture risk register](../security/risk-register.md).
