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

Still open before later implementation: MFA and account lockout beyond login rate limits, credential KEK/KMS, instance-operator identity, a dedicated `packages/application` split, remaining provider-neutral Vulnerability advisory identity, measured OSV object/listing limits, OSV transport and provenance review, ZIP/archive support (deferred and unauthorized), Finding enrichment, tenant correlation, risk integration, match-evaluation persistence, Finding ensure repositories, and advisory-to-component matching. See [open-decisions.md](../architecture/open-decisions.md). OD-1 (authentication mechanism), OD-2 (session store), and OD-3 (interim permission catalog) are closed by [ADR 0019](0019-local-password-sessions.md). Session 8 `completed` and graph-completeness semantics are closed by [ADR 0020](0020-sbom-ingestion-graph-completion.md). Session 9 import-only catalog access and the zero-Finding invariant are closed by [ADR 0021](0021-vulnerability-intelligence-import-foundation.md). Sanitized provider-status authorization is closed by [ADR 0022](0022-intelligence-provider-status-authorization.md); OD-10 instance-operator identity remains open. Canonical CVE identity is accepted by [ADR 0023](0023-provider-neutral-cve-identity.md). The identity migration is applied and frozen. Identity and link persistence adapters exist. Read-only active-catalog KEV membership derivation exists. [ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md) selects OSV as the future affected-version authority and instance-owned acquisition as the approved direction. Tenant package query APIs are rejected. Exact object/listing transport remains unreviewed. [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md) accepts ecosystem-aware package identity, a closed fail-closed registry, and the future evaluator result model. The implemented ecosystem set is empty. No first ecosystem is selected. No comparator or evaluator exists. [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) accepts Finding natural-key architecture, append-only match-evaluation evidence, observation semantics, and the Finding-write gate. Schema, persistence, matching runtime, and Finding writes do not exist. Session 11 and Session 12 remain zero-Finding. Session 13 is the earliest candidate for writes and is not authorized by ADR acceptance. Finding enrichment, tenant correlation, risk integration, API and worker wiring, and full provider-neutral Vulnerability advisory identity remain later work. [ADR 0010](0010-osv-correlation.md) remains the future correlation ADR, not the Session 9 import mechanism; its targeted package-query language is rejected for the approved foundation by ADR 0024. OD-14 (CycloneDX versions beyond 1.6) is unchanged.
