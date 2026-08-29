# Glossary

Terms below are used in product and engineering docs. Prefer these words in UI copy unless a user-facing label is decided separately.

| Term | Meaning |
| --- | --- |
| **Organization** | The tenant boundary. Customer-owned assets, SBOMs, findings, credentials, assignments, and audit events belong to one organization. Identified by UUID; `slug` is a globally unique lowercase label. |
| **Tenant** | Same as organization. Prefer **organization** in APIs and schema names (`organizationId`). |
| **Authorized organization** | Organization taken from authenticated membership/session, never from an untrusted field alone. |
| **Application (layer)** | Use cases that orchestrate domain ports. Lives in `packages/`, not in Fastify routes or Next.js. |
| **App (deployable)** | `apps/web`, `apps/api`, or `apps/worker`. Presentation or wiring, not the application layer. |
| **Port / adapter** | Port = interface; adapter = infrastructure implementation (Prisma, HTTP, queue, storage). |
| **Development adapter** | An implementation unsafe for production (fake auth, unsigned webhooks, plaintext credential stubs, unrestricted HTTP). Must be config-gated off in production. |
| **Asset** | A software system the organization tracks (application, service, or other inventoried target) that can receive SBOM uploads. |
| **SBOM** | Software bill of materials. MVP accepts CycloneDX JSON 1.4, 1.5, and 1.6. The original file is evidence and is stored, hashed, and not treated as trusted input. Object bodies never enter PostgreSQL. |
| **CycloneDX** | The SBOM specification used for MVP JSON uploads. Validate before parse. |
| **SBOM ingestion `completed`** | Successful evidence re-read, SHA-256 and length verification, JSON/structural and semantic limits, allowlisted schema validation, and normalized graph persistence ([ADR 0020](../adr/0020-sbom-ingestion-graph-completion.md)). It does **not** mean exhaustive software inventory, correlation, findings, enrichment, scoring, or remediation. |
| **Graph completeness** | `empty`, `no_dependencies`, `partial`, or `complete` on a completed ingestion. `empty` does not mean the Asset contains no software. `no_dependencies` does not prove the software has no dependencies. |
| **Component** | A package or library listed in an SBOM. Domain **Component** is **versionless** identity (type/namespace/name or ecosystem/namespace/name). Version lives on **ComponentOccurrence**. |
| **Dependency relationship** | An edge between components as recorded in the SBOM. Observed fact, not a risk score. Unknown dependency refs reject Session 8 ingestion. Self-edges are skipped as warnings. Cycles are preserved. |
| **Vulnerability record** | Intelligence about a vulnerability (for example a CVE) from a named source, with provenance. |
| **Finding** | Tenant-owned link between an **asset**'s **versionless** component identity and a **vulnerability record** (OSV id). Spans ingestions. Per-ingestion presence is a **Finding observation**, not a new finding when identity matches. |
| **Correlation** | Matching components to vulnerability records using defined identifiers and recorded method. |
| **CISA KEV** | CISA Known Exploited Vulnerabilities catalog. Used to **enrich** applicable findings. KEV listing is not by itself proof of exploitation in the user’s environment. |
| **Enrichment** | Additional observed or catalog data attached to a finding, with source and time. Distinct from the priority calculation. |
| **Priority** | The stored, explainable ranking for a finding under a versioned policy. **Risk score** means the same until an ADR splits the terms. Not an exploit proof. |
| **Environmental risk** | Product name for that calculated priority, including environment-specific factors. Still a calculated conclusion, not a fact. |
| **Policy version** | Identifier of the scoring rules used. Stored with each calculated priority. |
| **Contributing factors** | The inputs that produced a given priority, stored so the score can be explained later. |
| **Remediation work** | Assigned work to reduce or resolve a finding. |
| **Remediation activity** | A recorded action (fix, mitigate, verify) with actor and time. |
| **Risk acceptance** | An explicit, auditable decision to accept a finding for a defined reason and period. |
| **Compensating control** | A recorded control that reduces risk without removing the vulnerable component. It is evidence of a claim, not automatic score override unless policy says so. |
| **Re-scan** | Processing a newer SBOM for an asset and comparing prior findings. |
| **Resolved (on rescan)** | A calculated conclusion that the affected component is no longer observed **in range** on the **current** completed ingestion (greatest SBOM `receivedAt`, not last worker to finish) with **adequate coverage**. Requires stored observation evidence; not implied by ticket status or KEV absence. |
| **Audit event** | Append-only record of a security- or remediation-sensitive operation (see `security.mdc`). Never updated in place. |
| **Shared catalog** | Non-tenant data such as vulnerability intelligence and KEV snapshots. May be global. Findings that use it remain tenant-owned. |
| **Provenance** | Source, retrieved-at (UTC), and source identity for intelligence or evidence. Updates are versioned or additive, never a silent in-place replace. |
| **Outbox** | Transactional outbox row used to schedule background work without I/O inside the same database transaction as the state change. |
| **Idempotency** | Reprocessing the same job or retried mutation does not create duplicate side effects. For tenant-owned work, uniqueness is scoped to the organization. |
| **Evidence** | Stored artifacts and records needed to reproduce a finding (SBOM hash, parsed identifiers, intel source, policy version). |
| **Priority band** | Calculated grouping of **priority** (for example P1–P4). Not vulnerability severity. |
| **Finding observation** | Append-only per-**SBOMIngestion** **calculated** record of whether a finding's versionless component identity was `present`, `absent`, or `inconclusive`. |
| **Incomplete SBOM coverage** | Calculated concern that a newer SBOM is too thin to treat missing components as remediated. |
| **Processing lease** | Time-bounded claim. Session 8 uses separate leases: **OutboxEvent** (relay until BullMQ accepts) and **BackgroundJob** (processor execution). `SbomIngestion.leaseExpiresAt` is unused in Session 8. |
| **False positive (finding)** | Authorized decision that the *match* is wrong. Does not mean the advisory is invalid globally. |
| **Mitigated (finding)** | Compensating control recorded while the component is still observed. Not **resolved**. |
| **Membership** | Binding of a **User** to an **Organization** with a role (`owner`, `admin`, `member`, `viewer`) and status (`active`, `revoked`). |
| **Team** | Organization-scoped grouping. **Team membership** must share the team's organization. |
| **Environment** | Controlled deployment context (`production` / `non_production` sensitivity), unique per organization slug. |
| **SBOM ingestion** | One processing attempt against an SBOM artifact. Prior attempts are retained. |
| **Component occurrence** | Tenant-owned observation of a versionless **Component** in a specific SBOM ingestion. |
| **Risk policy** | Versioned scoring definition. Shared table with `scope` `builtin` (null organization) or `organization`. Published versions are immutable and cannot be deleted. |
| **Intelligence source** | Global OSV/CISA KEV synchronization state. Not a tenant installation. |
| **Integration** | Organization-owned installation of a provider catalog entry. `organizationId` is required. |
| **Risk calculation** | Append-only stored priority snapshot with factors, policy version, and engine version. |
| **Outbox event** | Transactional outbox row (`pending` → `claimed` → `processed`, or `failed` / `dead_lettered`). At-least-once; not exactly-once. |
| **Idempotency record** | Tenant-scoped hashed key for future mutation endpoints. Stores no raw bearer tokens. |

When in doubt, label data as **observed fact** or **calculated conclusion**.
