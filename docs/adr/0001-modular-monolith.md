# ADR 0001: Modular monolith with separate web, API, and worker deployments

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

PatchPilot needs a production-minded, self-hosted system for SBOM processing, correlation, scoring, and evidence. Independently owned microservices would multiply tenancy, schema, and audit failure modes before the MVP journey exists. [AGENTS.md](../../AGENTS.md) already targets a modular monolith.

## Decision

Ship a **modular monolith**: separately deployable `apps/web`, `apps/api`, and `apps/worker` that **share packages and one PostgreSQL schema**. Separately deployable does not mean microservices. Domain and use cases live in `packages/`. Handlers and React are presentation. Next.js is not a second domain API. Splitting into independently owned services requires a later accepted ADR.

## Alternatives considered

- **Single process** combining HTTP and workers: simpler locally, harder to scale parse load independently.
- **Microservices per capability** (ingest, intel, scoring): rejected for v0.1; too much distributed tenancy risk.
- **Next.js as the only backend**: rejected; API and worker boundaries would blur; Prisma would leak into the web app.

## Consequences

Operators can scale worker replicas without a service split. All apps must deploy compatible schema versions. Local Compose runs three apps plus data stores.

## Security and tenancy

Shared schema makes organization predicates one implementation, not three. Worker and API must still reload **authorized organization** from persistence and must not trust job payloads. A split later would need a new tenancy review.

## Operational failure plan

If one app is down: web-only outage vs API outage vs delayed ingest. PostgreSQL remains the source of truth; Redis outage delays jobs via the outbox. Document per-app health in later runbooks.

## Follow-up

Accept this ADR before scaffolding apps. Tests: layering rules in review; no Prisma in `apps/web`.
