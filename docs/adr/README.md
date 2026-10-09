# Architecture decision records

ADRs record lasting technical choices for PatchPilot: context, decision, consequences, and security impact.

## When to write an ADR

Write an ADR before merging a change that:

- Splits or joins deployable units (for example, leaving the modular monolith).
- Chooses or changes persistence, queue, object-storage, or auth topology.
- Defines tenancy, RBAC, or credential-encryption approach.
- Versions or changes risk-scoring policy structure.
- Adopts a vulnerability-intelligence source or matching algorithm that operators will depend on.
- Introduces an external provider, webhook, or outbound fetch class (SSRF surface).
- Changes audit, retention, or evidence-deletion policy.

If you are unsure, write a short Proposed ADR. Lightweight implementation details do not need an ADR.

## Process

1. Copy [template.md](template.md) to `docs/adr/NNNN-short-title.md` using the next unused four-digit number.
2. Set status to **Proposed** and open a pull request (or include the ADR in the implementing PR).
3. Reviewers check alignment with [AGENTS.md](../../AGENTS.md) and [`.cursor/rules/`](../../.cursor/rules/).
4. A maintainer merges with status **Accepted** (or **Rejected** with rationale).
5. A later ADR may set this one to **Superseded** and link both ways.

Closer implementation notes may add detail. They must not silently weaken accepted security or tenancy decisions.

## Status

| Status | Meaning |
| --- | --- |
| Proposed | Under review |
| Accepted | In force |
| Rejected | Considered and not taken |
| Superseded | Replaced by a newer ADR |

## Index

**Accepted** for v0.1:

| Number | Title | Status |
| --- | --- | --- |
| [0001](0001-modular-monolith.md) | Modular monolith with separate web, API, and worker deployments | Accepted |
| [0002](0002-pnpm-turborepo.md) | pnpm and Turborepo monorepo | Accepted |
| [0003](0003-nextjs-frontend.md) | Next.js frontend | Accepted |
| [0004](0004-fastify-api.md) | Fastify API | Accepted |
| [0005](0005-postgresql-prisma.md) | PostgreSQL and Prisma | Accepted |
| [0006](0006-redis-bullmq.md) | Redis and BullMQ | Accepted |
| [0007](0007-transactional-outbox.md) | Transactional outbox | Accepted |
| [0008](0008-private-object-storage.md) | Private object storage for original SBOM evidence | Accepted |
| [0009](0009-cyclonedx-json.md) | CycloneDX JSON as the initial SBOM format | Accepted |
| [0010](0010-osv-correlation.md) | OSV as the initial vulnerability correlation source | Accepted |
| [0011](0011-cisa-kev-enrichment.md) | CISA KEV enrichment | Accepted |
| [0012](0012-explainable-policy-engine.md) | Explainable versioned policy engine | Accepted |
| [0013](0013-organization-scoped-tenancy.md) | Organization-scoped multi-tenancy | Accepted |
| [0014](0014-append-only-audit.md) | Append-only audit events | Accepted |
| [0015](0015-provider-neutral-integrations.md) | Provider-neutral external integrations | Accepted |
| [0016](0016-opentelemetry.md) | OpenTelemetry observability | Accepted |
| [0017](0017-optional-ai-user-credentials.md) | Optional AI with user-supplied credentials only | Accepted |
| [0018](0018-go-cli-deferred.md) | Go CLI deferred until after the web MVP | Accepted |
| [0019](0019-local-password-sessions.md) | Local password authentication and opaque sessions | Accepted |
| [0020](0020-sbom-ingestion-graph-completion.md) | Session 8 SBOM ingestion graph completion | Accepted |
| [0021](0021-vulnerability-intelligence-import-foundation.md) | Session 9 vulnerability intelligence import foundation | Accepted |
| [0022](0022-intelligence-provider-status-authorization.md) | Sanitized intelligence provider-status authorization | Accepted |
| [0023](0023-provider-neutral-cve-identity.md) | Provider-neutral CVE identity and the KEV enrichment boundary | Accepted |
| [0024](0024-authoritative-affected-version-source-and-osv-acquisition.md) | Authoritative affected-version source and OSV acquisition | Accepted |
| [0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md) | Ecosystem-aware package identity and version evaluation | Accepted |
| [0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) | Authoritative match evidence and Finding lifecycle | Accepted |
| [0028](0028-osv-runtime-enablement-architecture-and-safety.md) | OSV runtime enablement architecture and safety controls | Accepted |
| [0029](0029-first-real-provider-osv-canary-authorization-and-safety.md) | First real-provider OSV canary authorization and safety controls | Accepted |
| [0032](0032-maintainer-reviewed-advisory-authority.md) | Maintainer-reviewed advisory authority architecture | Accepted |
| [0033](0033-product-match-evidence-cardinality.md) | Product Match Evidence cardinality | Accepted |
| [0034](0034-multi-version-component-occurrence-normalization.md) | Multi-version component occurrence normalization | Accepted |
| [0035](0035-controlled-finding-creation.md) | Controlled Finding creation | Accepted |
| [0036](0036-controlled-finding-operator-api.md) | Controlled Finding operator API | Accepted |
| [0037](0037-controlled-finding-target-discovery.md) | Controlled Finding target discovery | Accepted |
| [0038](0038-controlled-finding-web-workflow.md) | Controlled Finding web workflow | Accepted |
| [0039](0039-controlled-finding-repeated-observation.md) | Controlled Finding repeated observation | Accepted |

**Proposed:**

| Number | Title | Status |
| --- | --- | --- |
| [0027](0027-osv-acquisition-persistence-and-catalog-activation.md) | OSV acquisition persistence and catalog activation | Proposed |
| [0030](0030-first-ecosystem-matching-architecture.md) | First ecosystem matching architecture (npm selected; in-memory evaluator uncomposed) | Proposed |
| [0031](0031-product-evidence-provenance-architecture.md) | Product-evidence provenance architecture | Proposed |

## Implementation status

[Current state](../project/current-state.md) is the checkpoint authority. Header status matches the index above.

- [ADR 0027](0027-osv-acquisition-persistence-and-catalog-activation.md) remains **Proposed**. OSV acquisition persistence is implemented and production uncomposed. Production OSV acquisition is disabled.
- [ADR 0030](0030-first-ecosystem-matching-architecture.md) remains **Proposed**. The npm evaluator and synthetic immutable match-evaluation persistence are implemented and production uncomposed. Real product-eligible match evidence is unavailable. Finding creation is unavailable.
- [ADR 0031](0031-product-evidence-provenance-architecture.md) remains **Proposed**. Immutable advisory revisions and reviewed Vulnerability bindings are implemented and production uncomposed. Product-evidence eligibility composition is implemented and production uncomposed. It produces no eligible record, invokes no product evaluator in the accepted zero-eligibility state, and writes no product match row. Real product-eligible evaluation count remains 0.
- [ADR 0032](0032-maintainer-reviewed-advisory-authority.md) is **Accepted**. Reviewer-capability issuance, database-time validity, exact target binding, immutable approval persistence, and atomic approval consumption are implemented and production uncomposed. The provider-free product-evidence path is implemented and verified in disposable PostgreSQL. Persistent product-eligible evaluation count: 0. Production composition remains absent. Acceptance does not create a Finding.
- [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) admits the creation-only exception `controlled_maintainer_reviewed_finding_creation_v1`. The provider-driven write gate remains in force for every other Finding power.
- [ADR 0035](0035-controlled-finding-creation.md) is **Accepted** as creation-only architecture. The atomic creation transaction is composed only by owner POST /findings in the API process. GET /findings/:findingId is composed for owners and admins. Automatic Finding creation remains unavailable. Lifecycle transitions remain unavailable.
- [ADR 0036](0036-controlled-finding-operator-api.md) is **Accepted** for `POST /findings` and `GET /findings/:findingId`. POST /findings is composed and owner-only. GET /findings/:findingId is composed for owners and admins. Exact replay is publicly reachable. The decision does not authorize a list, CLI, web action, worker, queue, scheduler, or lifecycle transition. Controlled Finding Operator API Session 2-R reviewed the composed routes.
- [ADR 0037](0037-controlled-finding-target-discovery.md) is **Accepted** for one later read-only route, `GET /assets/:assetId/controlled-finding-targets`. The route is implemented for owners and admins. Discovery is read-only. Acknowledgements come from the authoritative qualifying set. `POST /findings` still revalidates them and remains owner-only. The decision does not authorize a Finding list, a second preview, cross-asset discovery, a CLI, worker discovery, or a lifecycle transition.
- [ADR 0038](0038-controlled-finding-web-workflow.md) is **Accepted** for one nested asset web workflow and direct Finding inspection. The workflow is implemented as a web API client. Existing APIs remain authoritative. Owner confirmation is explicit. Admin review is read-only. Controlled Finding Web Workflow Session 1-R reviewed the committed workflow. The controlled Finding web workflow is merged. The decision does not authorize a Finding list, global search, cross-asset discovery, bulk creation, a lifecycle UI, or a preview-and-create route.
- [ADR 0039](0039-controlled-finding-repeated-observation.md) is **Accepted** for one persistence-only repeated observation of an existing open Finding. Repeated-observation contracts and process-local observation authority are implemented. The additive migration is implemented. The atomic repeated-observation transaction is implemented. Persistence remains production uncomposed. Finding state remains open. Only last_observed_at and updated_at may change. Creation inspection remains creation based. Later history is not publicly exposed. The frozen migration count is 25. Production reachability, automatic observation, and Finding state transitions remain unavailable. Controlled Finding Repeated Observation Session 1-R reviewed the process-local observation authority. Controlled Finding Repeated Observation Session 2-R reviewed the uncomposed PostgreSQL transaction. Current inspection tolerates legal repeated observations. Public inspection remains creation based. Repeated-observation history is not publicly exposed. The writer remains production uncomposed. Inspection performs no mutation. Controlled Finding Repeated Observation Session 3-R reviewed the creation-based read path. Repeated-observation branch closure remains the open review. The repeated-observation slice is not complete.

Still open before later implementation: MFA and account lockout beyond login rate limits, credential KEK/KMS, instance-operator identity, a dedicated `packages/application` split, remaining provider-neutral Vulnerability advisory identity, ZIP/archive support (deferred and unauthorized), Finding enrichment, tenant correlation, risk integration, Session 15 product-evidence provenance ([ADR 0031](0031-product-evidence-provenance-architecture.md); Batch 2 persists immutable revisions and bindings, eligibility is not stored, ADR 0031 remains Proposed), Finding ensure repositories, and advisory-to-component matching. Session 14 is merged. Session 11 acquisition foundation is closed and synthetically verified; production OSV remains disabled. [ADR 0028](0028-osv-runtime-enablement-architecture-and-safety.md) is **Accepted** for staged runtime architecture. Session 12 implemented the listing-page HTTPS adapter, pagination, durable coordination, disabled composition, halt, and bounded observability behind disabled configuration. It does not enable OSV, authorize canary execution, catalog activation, matching, or Finding writes. [ADR 0029](0029-first-real-provider-osv-canary-authorization-and-safety.md) is **Accepted** for first real-provider canary authorization and safety controls; Session 13 Batch 1-R does not contact a provider. Later listing canaries are operator only, unregistered, and historical. Session 13 Batch 2A adds framework-independent operator-identity and authorization contracts. Session 13 Batch 2B persists those contracts as schema only. Session 13 Batch 2C implements uncomposed PostgreSQL adapters without authentication, CLI, execution, or provider contact. Session 13 Batch 2C-R independently reviewed those adapters. Acceptance of ADR 0029 authorizes only later operational-control implementation. OD-8 generation-bound retrieval bytes are closed at 1,048,576 by Session 11 Batch 6A-P. Parser-host pending capacity is selected at 0 by ADR 0028; the committed host constant remains `unavailable` until a later implementation batch. ZIP remains unselected. [ADR 0027](0027-osv-acquisition-persistence-and-catalog-activation.md) remains Proposed; Session 11 closure, Session 12 closure, Session 13 Batch 1, and ADR 0028 do not accept it and do not authorize runtime enablement. See [open-decisions.md](../architecture/open-decisions.md). OD-1 (authentication mechanism), OD-2 (session store), and OD-3 (interim permission catalog) are closed by [ADR 0019](0019-local-password-sessions.md). Session 8 `completed` and graph-completeness semantics are closed by [ADR 0020](0020-sbom-ingestion-graph-completion.md). Session 9 import-only catalog access and the zero-Finding invariant are closed by [ADR 0021](0021-vulnerability-intelligence-import-foundation.md). Sanitized provider-status authorization is closed by [ADR 0022](0022-intelligence-provider-status-authorization.md); OD-10 instance-operator identity remains open. Canonical CVE identity is accepted by [ADR 0023](0023-provider-neutral-cve-identity.md). The identity migration is applied and frozen. Identity and link persistence adapters exist. Read-only active-catalog KEV membership derivation exists. [ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md) selects OSV as the future affected-version authority and instance-owned acquisition as the approved direction. Tenant package query APIs are rejected. [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md) accepts ecosystem-aware package identity, a closed fail-closed registry, and the future evaluator result model. The active registries that admit product eligibility are empty. The npm evaluator and synthetic immutable match-evaluation persistence are implemented and production uncomposed. Real product-eligible match evidence is unavailable. [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) accepts Finding natural-key architecture, append-only match-evaluation evidence, observation semantics, and the Finding-write gate. Controlled Finding creation from match evidence is composed only by owner POST /findings in the API process. GET /findings/:findingId is composed for owners and admins. [ADR 0037](0037-controlled-finding-target-discovery.md) is implemented as one read-only asset-scoped discovery route. [ADR 0038](0038-controlled-finding-web-workflow.md) is implemented as a nested web workflow. Owner confirmation is explicit. Admin review is read-only. Acknowledgements remain ephemeral. Stale acknowledgements fail closed. Exact replay is supported. Controlled Finding Web Workflow Session 1-R reviewed the committed workflow. The controlled Finding web workflow is merged. No Finding list or lifecycle UI is authorized. Discovery returns that acknowledgement from the authoritative qualifying set, and POST /findings still revalidates it. Automatic Finding creation remains unavailable. Explicit owner creation through the nested web workflow is implemented. The Finding schema remains placeholder infrastructure for every power except that controlled slice. Production Finding creation remained unavailable through Session 15. Historical canary and provenance checkpoints are in the [checkpoint ledger](../project/checkpoint-ledger.md). Automatic Finding creation remains unavailable. Explicit owner creation through the nested web workflow is implemented. A session number is not authorization. See [current state](../project/current-state.md). Finding enrichment, tenant correlation, risk integration, API and worker wiring, and full provider-neutral Vulnerability advisory identity remain later work. [ADR 0010](0010-osv-correlation.md) remains the future correlation ADR, not the Session 9 import mechanism; its targeted package-query language is rejected for the approved foundation by ADR 0024. OD-14 (CycloneDX versions beyond 1.6) is unchanged.
