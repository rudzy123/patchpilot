# Architecture

This directory is the v0.1 architecture design for PatchPilot. Application packages are not scaffolded yet. These documents are the intended shape of the modular monolith; they do not claim that runtime code exists.

Decisions in this directory assume the Architecture Decision Records under [docs/adr/](../adr/README.md). Those ADRs are **Proposed** until a maintainer accepts them.

## How to read this set

1. [System context](system-context.md) — actors and external systems.
2. [Container architecture](container-architecture.md) — deployable units and data stores.
3. [Component architecture](component-architecture.md) — packages, layers, and dependency rules.
4. [Domain model](domain-model.md) — entities, identifiers, and canonical lifecycle states.
5. [Data flow](data-flow.md) — MVP journey through the system.
6. [Trust boundaries](trust-boundaries.md) and [tenant isolation](tenant-isolation.md) — authorization and organization scope.
7. Capability designs: [assets](asset-model.md), [SBOM ingestion](sbom-ingestion.md), [vulnerability intelligence](vulnerability-intelligence.md), [findings](finding-lifecycle.md), [risk policy](risk-policy.md), [remediation](remediation-lifecycle.md), [audit](audit-model.md).
8. Operations: [reliability](reliability-model.md), [observability](observability.md), [deployment](deployment-model.md), [testing](testing-strategy.md), [data classification](data-classification.md), [retention](retention-and-deletion.md).

Security design lives in [docs/security/](../security/README.md). Product language lives in the [glossary](../product/glossary.md). Scope limits live in [MVP scope](../product/mvp-scope.md) and [non-goals](../product/non-goals.md).

## Canonical sources (avoid drift)

When two documents describe the same rule, treat this table as the source of truth:

| Topic | Canonical document |
| --- | --- |
| Entity definitions and lifecycle state names | [domain-model.md](domain-model.md) |
| Asset ownership and environments | [asset-model.md](asset-model.md) |
| Ingestion limits, hashing, quarantine | [sbom-ingestion.md](sbom-ingestion.md) |
| Intelligence provenance and matching | [vulnerability-intelligence.md](vulnerability-intelligence.md) |
| Finding states and rescan conclusions | [finding-lifecycle.md](finding-lifecycle.md) |
| Scoring, factors, policy versions | [risk-policy.md](risk-policy.md) |
| Remediation tasks and risk acceptance | [remediation-lifecycle.md](remediation-lifecycle.md) |
| Audit event types and immutability | [audit-model.md](audit-model.md) |
| Organization context and repository scoping | [tenant-isolation.md](tenant-isolation.md) |
| Outbox, retries, poison jobs | [reliability-model.md](reliability-model.md) |
| Classification labels | [data-classification.md](data-classification.md) |
| Purge and legal-hold-like holds | [retention-and-deletion.md](retention-and-deletion.md) |

## What this phase does not do

- Scaffold `apps/` or `packages/` runtime code.
- Install dependencies or generate Prisma migrations.
- Implement product functionality.
- Claim SOC 2, ISO 27001, FedRAMP, PCI, HIPAA, or any other compliance status.

## Open decisions

Decisions that are **not** settled by the current ADR set are listed in [open-decisions.md](open-decisions.md). Implementers must not invent a conflicting topology to fill those gaps.
