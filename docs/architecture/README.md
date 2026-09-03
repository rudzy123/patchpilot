# Architecture

This directory is the v0.1 architecture design for PatchPilot. Sessions 3–4 scaffolded application shells, CI, and governance. Session 5 adds the PostgreSQL tenant schema and persistence adapters. Session 6 implements local-password authentication. Session 7 persists asset inventory. Session 8 implements CycloneDX JSON upload, private object storage, outbox relay, worker-thread parse, and graph persistence ([ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md)). Session 9 Batch 1B records [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md) (import-only shared catalog). Subsequent Session 9 batches implement KEV import runtime: restricted CISA HTTPS and private snapshot storage, isolated parsing, crash-safe synchronization, the worker scheduler/processor/retry reconciler, and authenticated sanitized provider-status GETs ([ADR 0022](../adr/0022-intelligence-provider-status-authorization.md)). Session 10 adds canonical CVE identity persistence and read-only active-catalog KEV membership derivation ([ADR 0023](../adr/0023-provider-neutral-cve-identity.md)). Session 11 Batch 1B accepts [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md): OSV is the future affected-version authority and instance-owned catalog acquisition is the approved direction. Session 11 Batch 1C accepts [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md): ecosystem-aware package identity and fail-closed evaluation architecture. Session 11 Batch 1D accepts [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md): Finding natural key, append-only match evidence, observation semantics, and the Finding-write gate. No comparator, evaluator, OSV runtime, ZIP processing, matching, match-evaluation persistence, or Finding write exists.

Decisions in this directory follow the Architecture Decision Records under [docs/adr/](../adr/README.md). ADRs 0001–0026 are **Accepted** for v0.1. Remaining gaps are listed in [open-decisions.md](open-decisions.md). OD-1, OD-2, and OD-3 are closed by [ADR 0019](../adr/0019-local-password-sessions.md). Session 8 ingestion completion is closed by [ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md). Session 9 import-only catalog access is closed by [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md). Sanitized provider-status authorization is closed by [ADR 0022](../adr/0022-intelligence-provider-status-authorization.md). Canonical CVE identity is closed by [ADR 0023](../adr/0023-provider-neutral-cve-identity.md) for identity tables, persistence adapters, and read-only active-catalog membership; Finding enrichment, risk, APIs, workers, and fan-out do not exist. OSV affected-version authority and instance-owned acquisition direction are closed by [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md); exact object/listing transport, ZIP, matching, and Finding writes remain later. Package identity and fail-closed evaluation architecture are closed by [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md); the implemented ecosystem set is empty and no evaluator exists. Finding identity, match evidence, observation semantics, and the Finding-write gate are closed as architecture by [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md); schema, persistence, matching runtime, and Finding writes do not exist. Session 11 and Session 12 remain zero-Finding. [ADR 0010](../adr/0010-osv-correlation.md) remains future correlation. OD-14 is unchanged.

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
| Intelligence provenance, Session 9 import, and future matching | [vulnerability-intelligence.md](vulnerability-intelligence.md), [ADR 0021](../adr/0021-vulnerability-intelligence-import-foundation.md), [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md), [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md), and [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) |
| Session 10 canonical CVE identity and active-catalog KEV membership | [ADR 0023](../adr/0023-provider-neutral-cve-identity.md), [domain-model.md](domain-model.md), and [database-model.md](database-model.md) |
| Authoritative affected-version source and OSV acquisition direction | [ADR 0024](../adr/0024-authoritative-affected-version-source-and-osv-acquisition.md) |
| Package identity and fail-closed affected-version evaluation | [ADR 0025](../adr/0025-ecosystem-aware-package-identity-and-version-evaluation.md) |
| Authoritative match evidence and Finding lifecycle | [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) |
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

- Product workflows (SBOM processing, scoring, remediation) are specified here. Authentication HTTP exists (Session 6). Session 8 upload-to-graph is implemented. Session 9 KEV import runtime and sanitized provider-status APIs are implemented. Session 10 canonical CVE identities and active-catalog membership derivation exist. Session 11 Batch 1B records OSV as the future affected-version authority. Session 11 Batch 1C records ecosystem-aware package identity and fail-closed evaluation architecture. Session 11 Batch 1D records Finding identity, match evidence, and the Finding-write gate; no comparator, evaluator, OSV runtime, ZIP, matching, match-evaluation persistence, or Finding write exists. Finding enrichment, risk, APIs, workers, fan-out, advisory matching, Findings, scoring, OSV runtime, manual sync, detailed SyncRun APIs, and a dashboard remain later.
- The foundation does not claim SOC 2, ISO 27001, FedRAMP, PCI, HIPAA, or any other compliance status.

## Open decisions

Decisions that are **not** settled by the current ADR set are listed in [open-decisions.md](open-decisions.md). Implementers must not invent a conflicting topology to fill those gaps.
