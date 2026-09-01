# Architecture

This directory is the v0.1 architecture design for PatchPilot. Sessions 3–4 scaffolded application shells, CI, and governance. Session 5 adds the PostgreSQL tenant schema and persistence adapters. Session 6 implements local-password authentication. Session 7 persists asset inventory. Session 8 implements CycloneDX JSON upload, private object storage, outbox relay, worker-thread parse, and graph persistence ([ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md)). Session 9 Batch 1B records [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) (import-only shared catalog). Session 9 Batch 5B adds restricted CISA HTTPS transport and private snapshot storage. Session 9 Batch 6B adds secure KEV parsing in a terminated worker thread. Session 9 Batch 7B adds the framework-independent CISA KEV synchronization service. A scheduler loop, BullMQ intelligence processor, status APIs, correlation, live scheduled feeds, and scoring are **not** implemented.

Decisions in this directory follow the Architecture Decision Records under [docs/adr/](../adr/README.md). ADRs 0001–0021 are **Accepted** for v0.1. Remaining gaps are listed in [open-decisions.md](open-decisions.md). OD-1, OD-2, and OD-3 are closed by [ADR 0019](../adr/0019-local-password-sessions.md). Session 8 ingestion completion is closed by [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md). Session 9 import-only catalog access is closed by [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md). [ADR 0010](../adr/0010-osv-correlation.md) remains future correlation. OD-14 is unchanged.

## How to read this set

1. [System context](system-context.md) — actors and external systems.
2. [Container architecture](container-architecture.md) — deployable units and data stores.
3. [Component architecture](component-architecture.md) — packages, layers, and dependency rules.
4. [Domain model](domain-model.md) — entities, identifiers, and canonical lifecycle states.
5. [Data flow](data-flow.md) — MVP journey through the system.
6. [Trust boundaries](trust-boundaries.md) and [tenant isolation](tenant-isolation.md) — authorization and organization scope.
7. Capability designs: [assets](asset-model.md), [SBOM ingestion](sbom-ingestion.md), [vulnerability intelligence](vulnerability-intelligence.md), [findings](finding-lifecycle.md), [risk policy](risk-policy.md), [remediation](remediation-lifecycle.md), [audit](audit-model.md).
8. Operations: [reliability](reliability-model.md), [observability](observability.md), [deployment](deployment-model.md), [testing](testing-strategy.md), [data classification](data-classification.md), [retention](retention-and-deletion.md), [database model](database-model.md).
9. Runbooks: [docs/runbooks/](../runbooks/README.md).

Security design lives in [docs/security/](../security/README.md). Product language lives in the [glossary](../product/glossary.md). Scope limits live in [MVP scope](../product/mvp-scope.md) and [non-goals](../product/non-goals.md).

## Canonical sources (avoid drift)

When two documents describe the same rule, treat this table as the source of truth:

| Topic | Canonical document |
| --- | --- |
| Entity definitions and lifecycle state names | [domain-model.md](domain-model.md) |
| Asset ownership and environments | [asset-model.md](asset-model.md) |
| Ingestion limits, hashing, quarantine | [sbom-ingestion.md](sbom-ingestion.md) |
| Session 8 `completed` and graph completeness | [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md) |
| Intelligence provenance, Session 9 import, and future matching | [vulnerability-intelligence.md](vulnerability-intelligence.md) and [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) |
| Finding states and rescan conclusions | [finding-lifecycle.md](finding-lifecycle.md) |
| Scoring, factors, policy versions | [risk-policy.md](risk-policy.md) |
| Remediation tasks and risk acceptance | [remediation-lifecycle.md](remediation-lifecycle.md) |
| Audit event types and immutability | [audit-model.md](audit-model.md) |
| Organization context and repository scoping | [tenant-isolation.md](tenant-isolation.md) |
| Authentication, sessions, CSRF, interim permissions | [ADR 0019](../adr/0019-local-password-sessions.md) |
| Outbox, retries, poison jobs | [reliability-model.md](reliability-model.md) |
| Classification labels | [data-classification.md](data-classification.md) |
| Physical schema, constraints, indexes, JSON versioning | [database-model.md](database-model.md) |

## What this design set does not claim

- Product workflows (SBOM processing, scoring, remediation) are specified here. Authentication HTTP exists (Session 6). Session 8 upload-to-graph is implemented. Session 9 vulnerability-intelligence import is **design only** after ADR 0021 and is **not** implemented. Correlation, findings, enrichment, and scoring remain later.
- The foundation does not claim SOC 2, ISO 27001, FedRAMP, PCI, HIPAA, or any other compliance status.

## Open decisions

Decisions that are **not** settled by the current ADR set are listed in [open-decisions.md](open-decisions.md). Implementers must not invent a conflicting topology to fill those gaps.
