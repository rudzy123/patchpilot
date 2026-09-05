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
| OD-19 | Provider-neutral Vulnerability identity | **Partially resolved** for canonical CVE identity by [ADR 0023](../adr/0023-provider-neutral-cve-identity.md). Migration `20260902120000_canonical_cve_identity` is applied and frozen (SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). Session 11 Batch 5C adds the OSV acquisition foundation migration (twelve migrations). Batch 4B ships `createCveIdentityPersistence`. Batch 5B adds read-only active-catalog membership derivation. Full advisory-identity replacement of `osvId` remains open. |

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
| OD-19 canonical CVE identity | Global `CveIdentity` plus append-only `VulnerabilityCveIdentityLink` | **Partially resolved.** [ADR 0023](../adr/0023-provider-neutral-cve-identity.md) accepts the identity model. Batch 3B applied and froze `20260902120000_canonical_cve_identity` (SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). Batch 4B implements insert-once persistence adapters (`identities` and `links`). Batch 5B implements read-only active-catalog membership for one exact canonical CVE. Full advisory-identity replacement of `osvId` remains open. Finding enrichment remains blocked. The persistent development database has thirteen finished migrations after Session 11 Batch 5C-R. |
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

## Closed in Session 11 Batch 5B (persistence contracts)

| ID | Topic | Status after Batch 5B |
| --- | --- | --- |
| OSV persistence contracts | Identities, inventory, snapshots, parser attempts, revisions, generations, completeness, reconciliation, quarantine, activation, ports | **Contracts closed in Batch 5B.** Framework-independent types live in `@patchpilot/vulnerability-intelligence`. |
| Active catalog pointer | Separate pointer plus CAS, not a flag on generation rows and not `IntelligenceSource.activeGenerationId` | **Closed as contract in Batch 5B.** Batch 5D implements PostgreSQL CAS. Activation does not trigger matching. |
| Completeness dimensions | Inventory, eligible-body, parser, parsed-catalog, matching | **Closed as contract.** Matching remains `not_in_scope`. Equations are exact integers with no waiver. |
| OSV object-key prefixes | Advisory-body and parsed-document locators | **Closed in Batch 5E.** Prefixes are `intelligence/osv/advisory_body/{tmp\|sha256}/{uuid\|sha256}` and `intelligence/osv/parsed_advisory/{tmp\|sha256}/{uuid\|sha256}`. Provider keys are never storage paths. |

## Closed in Session 11 Batch 5C (acquisition schema)

| ID | Topic | Status after Batch 5C |
| --- | --- | --- |
| OSV acquisition persistence foundation | Prisma models plus `20260904120000_osv_acquisition_persistence_foundation` | **Schema only.** Frozen SHA-256 `ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349`. Batch 5C-R adds `20260904180000_osv_parsed_revision_id_check_correction` (SHA-256 `43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570`) replacing only the unsatisfiable parsed OSV ID CHECK. Thirteen finished migrations. No object storage, provider retrieval, or synchronization. No active OSV generation is seeded. |
| Immutable provider identities | Provider object and generation natural keys | **Closed in schema.** Unique `(provider, key)`, `(provider, digest)`, and `(object, generation)`. Provider generation is a checked decimal string. |
| Separate active pointer | One pointer per catalog scope | **Closed in schema.** `osv_active_catalog_pointer` is the mutable projection; `osv_activation_record` is append-only history. |

## Closed in Session 11 Batch 5D (PostgreSQL adapters)

| ID | Topic | Status after Batch 5D |
| --- | --- | --- |
| OSV acquisition adapters | `createOsvAcquisitionPersistence` | **Adapters exist** in `@patchpilot/database`. Immutable conflict detection, generation/attachment graphs, deterministic reconciliation, append-only quarantine and presence, and pointer CAS are implemented. Parser-attempt/revision writes are transactional. Batch 5C-R makes successful parsed-revision inserts possible. No production catalog is activated. Object storage, provider retrieval, and synchronization remain absent. |
| Cross-scope previous generation | ID-only previous-generation FK | **Closed in adapter.** Activation loads the previous generation and rejects a scope mismatch without writing history or mutating the pointer. |

## Closed in Session 11 Batch 5E (immutable object storage)

| ID | Topic | Status after Batch 5E |
| --- | --- | --- |
| OSV object-key prefixes | Advisory-body and parsed-document locators | **Closed.** Adapter tests confirm `intelligence/osv/{advisory_body\|parsed_advisory}/{tmp\|sha256}/…` in the existing private bucket. |
| OSV snapshot object storage | Immutable write-once adapter | **Adapter exists** for synthetic locally supplied bytes. Staged write, SHA-256 read-back, conflict detection, and cleanup eligibility exist. No provider retrieval, no destructive cleanup job, and no PostgreSQL+storage atomic commit. Batch 5F adversarially reviewed write-once, recovery bounds, and error confidentiality. |

## Closed in Session 11 Batch 5F (storage adversarial review)

| ID | Topic | Status after Batch 5F |
| --- | --- | --- |
| OSV storage write-once review | Immutable put/copy, 409/412 compare, GET hashing | **Hardened.** Idempotency requires hashed stored bytes plus content type, encoding, category, and layout. Metadata spoofing cannot mint `already_applied`. |
| OSV storage recovery bounds | Split-brain recovery without false attached state | **Hardened.** Recovery stays inside `OSV_STORAGE_CALL_BUDGETS`. Transient failures leave staged metadata. Integrity conflicts reject. Orphaned/rejected rows cannot self-heal into attached. |
| OSV composed storage+DB test | Single-process MinIO plus PostgreSQL orchestration | **Closed in Batch 6B** in `apps/worker` integration tests. Synthetic bytes and a fake retrieval port. No provider contact. No architecture inversion. |

## Closed in Session 11 Batch 6A-P (generation-bound retrieval policy)

| ID | Topic | Closed by |
| --- | --- | --- |
| OD-8 provider-object retrieval byte limit subset | Maximum received provider-object response-body bytes | **Closed.** Session 11 Batch 6A-P closes `osv_generation_bound_retrieval_policy_v1` with exact transport ceiling 1,048,576 bytes. This is an explicit independent security policy, aligned with but distinct from storage admission (1 MiB) and parser input (1 MiB). Oversize records fail closed and block generation completeness. Policy is immutable. Future changes require new version identifier and review. |
| OSV generation-bound retrieval surface | Canonical HTTPS GCS JSON Objects get media API | **Closed.** Scheme HTTPS, host `storage.googleapis.com`, bucket `osv-vulnerabilities`, method GET, path `/storage/v1/b/osv-vulnerabilities/o/{name}?alt=media&ifGenerationMatch={generation}`. No authentication, redirects prohibited, identity encoding only. |
| OSV retrieval timeouts | Connection, header, body, total deadline | **Closed as immutable v1.** Connection 5s, response header 10s, body inactivity 10s, total deadline 30s. No caller, tenant, or environment override. |
| OSV retrieval retry classification | Retryability, no automatic retry | **Closed.** Orchestration-retryable: connection timeout, DNS failure, 408, 429, 500-504. Non-retryable: invalid request, source ineligible, redirects, content validation failures, size policy violations, generation mismatch. No automatic retry within adapter. |
| OSV retrieval content policies | Content-Type, Content-Encoding, streaming enforcement | **Closed.** Strict `application/json`, identity encoding only, incremental SHA-256, terminate on overflow, discard partial. Rejects gzip/br/deflate, HTML, plain text, ZIP, octet-stream. |
| OSV retrieval source authorization | Pre-request gates | **Closed.** Body retrieval = `eligible`, private retention = `permitted`, complete verified evidence, exact source/registry/policy identifiers. OSV/ECHO/CVE fallback fail closed. MAL may retrieve if permitted but matching prohibited. |
| OSV retrieval failure taxonomy | Closed failure catalog, confidentiality | **Closed.** 41 kinds across request validation, network, HTTP, response validation, handoff phases. No body, raw key, URL, headers, credentials, stack, tenant/package/Finding data in failures. Bounded safe reason code, policy identifier, optional HTTP status. |
| OSV retrieval dependency graph | Required predecessors, no cycle | **Closed.** Validated key, exact generation, source classification, retrieval/retention permissions, complete evidence, size within policy. Provider prefix alone not authorization. Matching/tenant/Finding not predecessors. Retrieval does not imply activation. |

## Closed in Session 11 Batch 6A (generation-bound retrieval adapter)

| ID | Topic | Closed by |
| --- | --- | --- |
| OSV generation-bound HTTP retrieval | One-attempt provider-object GET | **Implemented.** `@patchpilot/integrations` adapter compiles the committed GCS get-media surface, rejects redirects, binds `ifGenerationMatch`, streams at most 1 MiB, and returns a validated retrieval result. No storage, parser, retry, listing, or synchronization. |

## Closed in Session 11 Batch 6B (disabled acquisition orchestration)

| ID | Topic | Closed by |
| --- | --- | --- |
| Disabled acquisition pending-work capacity | Active concurrency 1, pending maximum 32, observations per invocation 32 | **Closed for `osv_disabled_acquisition_orchestration_policy_v1`.** Pending items are metadata-only. Parser-worker pending-queue size remains unselected. No listing execution, scheduler, automatic retry, or catalog activation. |
| OSV composed MinIO and PostgreSQL rehearsal | Disabled acquisition composition | **Closed in `apps/worker` integration tests.** Synthetic GHSA bytes, fake retrieval, disposable MinIO, disposable PostgreSQL, isolated parser worker. No provider contact and no catalog activation. |

## Closed in Session 11 Batch 6C (disabled end-to-end rehearsal)

| ID | Topic | Closed by |
| --- | --- | --- |
| Disabled synthetic acquisition rehearsal | Bounded end-to-end pipeline under synthetic inventory | **Closed as a disabled rehearsal.** `apps/worker` integration tests compose synthetic complete-inventory evidence, authorized scripted retrieval, disposable MinIO, disposable PostgreSQL, and the isolated parser worker. Ineligible items terminate at `retrieval_skipped`. The orchestrator never activates a catalog. No provider contact. Parser-worker pending-queue size remains unselected and is not conflated with orchestration pending capacity. |

## Closed in Session 11 Batch 5C-R (parsed OSV ID CHECK)

| ID | Topic | Status after Batch 5C-R |
| --- | --- | --- |
| Parsed OSV ID CHECK | `osv_parsed_advisory_revision_osv_id_chk` | **Corrected.** Batch 5C SQL remains frozen with `{0,511}`. Live CHECK uses `char_length` 1–512 plus `^[A-Z0-9][A-Z0-9._+-]*$`. Parsed-revision inserts succeed. No Prisma schema change. |

## Still open

| ID | Topic | Why it is open | Interim default for design and first implementation |
| --- | --- | --- | --- |
| OD-4 | Credential encryption key management | Envelope encryption needs an operator key, KMS, or Vault. | AES-256-GCM data keys wrapped by an operator-supplied key encryption key (KEK) loaded only through `packages/config`. No cloud KMS required for MVP. |
| OD-5 | Production object-storage vendor | The port is S3-compatible; AWS, MinIO, or GCS interop is an operations choice. | Provider-neutral port ([ADR 0008](../adr/0008-private-object-storage.md)). Local Compose uses MinIO. Production uses any S3-compatible private bucket the operator provides. |
| OD-6 | Application-layer package split | Use cases could live in `packages/domain` or a dedicated package. | Use cases live in `packages/domain` as application services. Revisit only if the package becomes unwieldy. |
| OD-7 | Priority vs risk score split | Glossary treats them as the same until an ADR splits them. | Keep **priority** as the stored calculated ranking. **Risk score** is a synonym. Do not introduce a second authoritative number. |
| OD-8 | Exact outbound rate-limit and import size numbers | KEV limits are provisionally in `@patchpilot/config`. Session 11 Batch 3C compiles OSV GCS listing `maxResults` (`1000`) and listing-page byte cap (`1,048,576`) in `@patchpilot/vulnerability-intelligence`. Session 11 Batch 4B-P closes **parser** numeric limits as PatchPilot policy on `osv_advisory_parser_resource_policy_v1` (not provider maxima). Session 11 Batch 4E closes **parser isolation design** (`worker_threads`, exact worker timeouts). Session 11 Batch 5E/5F close the **object-storage admission ceiling** at 1 MiB for snapshots. **Session 11 Batch 6A-P closes provider-object retrieval byte limit: 1,048,576 bytes.** Session 11 Batch 6A implements the one-attempt generation-bound HTTPS adapter against that policy. **Session 11 Batch 6B closes disabled-acquisition pending work at 32 metadata-only items with active concurrency 1.** Parser-worker pending-queue size, continuation-token byte bounds, and ZIP remain unselected. | Use the typed KEV bounds. Use the compiled GCS listing protocol constants. Use parser resource policy v1. Use the Batch 4E isolation design. Use `osv_generation_bound_retrieval_policy_v1` and the Batch 6A retrieval adapter for one generation-bound object GET. Use `osv_disabled_acquisition_orchestration_policy_v1` for explicit disabled acquisition composition. Keep `INTELLIGENCE_OSV_ENABLED=false` until listing execution, scheduling, and remaining OD-8 items are authorized. |
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
