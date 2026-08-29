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

Still open before later implementation: MFA and account lockout beyond login rate limits, credential KEK/KMS, instance-operator identity, and a dedicated `packages/application` split. See [open-decisions.md](../architecture/open-decisions.md). OD-1 (authentication mechanism), OD-2 (session store), and OD-3 (interim permission catalog) are closed by [ADR 0019](0019-local-password-sessions.md). Session 8 `completed` and graph-completeness semantics are closed by [ADR 0020](0020-sbom-ingestion-graph-completion.md). OD-14 (CycloneDX versions beyond 1.6) is unchanged.
