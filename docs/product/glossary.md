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
| **Component** | A package or library listed in an SBOM. Domain **Component** is **versionless** identity (type/namespace/name or ecosystem/namespace/name). Version lives on **ComponentOccurrence**. One ingestion may contain several occurrences of one Component when the observed versions differ. |
| **Dependency relationship** | An edge between occurrences as recorded in the SBOM. Observed fact, not a risk score. The edge stays on the version the document addressed. Unknown dependency refs reject ingestion. Self-edges are skipped as warnings. Cycles are preserved. |
| **Vulnerability record** | Intelligence about a vulnerability (for example a CVE) from a named source, with provenance. Session 9 imports these into a shared catalog; it does not match them to tenant components. |
| **Finding** | Placeholder product infrastructure for a future tenant-owned link between an **asset**, a **versionless** **Component**, and one **Vulnerability** advisory. Natural key: `organizationId` + `assetId` + `componentId` + `vulnerabilityId` ([ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md)). There is no implemented Finding workflow. A generic repository create path exists and is unreachable from application startup. Finding creation from match evidence is unavailable. |
| **Correlation** | Matching components to vulnerability records using defined identifiers and recorded method. Future work ([ADR 0010](../adr/0010-osv-correlation.md)). Not the Session 9 import mechanism. |
| **CISA KEV** | CISA Known Exploited Vulnerabilities catalog. Session 9 imports the official JSON snapshot into the shared catalog. Later, KEV may **enrich** applicable findings ([ADR 0011](../adr/0011-cisa-kev-enrichment.md)). KEV listing is an exploitation signal, not proof of tenant exposure, and is not a complete vulnerability catalog. |
| **Canonical CVE identity** | Exactly one global identity for one exact `CVE-YYYY-N…` string. Distinct from an advisory (`Vulnerability`) and from KEV membership. Not tenant exposure. |
| **CveIdentity** | Persisted canonical CVE identity row (`createdAt` only). Append-only. Instance-owned. No organization, provider, KEV, or Finding fields. |
| **VulnerabilityCveIdentityLink** | Append-only advisory-to-CVE association. Does not merge Vulnerabilities. `linkedAt` is caller-supplied and immutable. Source-free. |
| **Active-catalog KEV membership** | Read-time exact equality of one canonical CVE against the accepted active CISA KEV generation. Exploitation signal only. Not proof of tenant exposure. Not an API. Direct membership does not require a `CveIdentity` row. |
| **current** | Membership freshness: last successful sync is within the configured stale threshold while KEV refresh remains enabled. |
| **stale** | Membership freshness: accepted snapshot is older than the stale threshold. Absence and listing remain relative to that snapshot, not live CISA. |
| **disabled_with_history** | Membership freshness: refresh is disabled but the last accepted catalog remains readable. Absence stays snapshot-relative. |
| **Enrichment** | Additional observed or catalog data attached to a finding, with source and time. Distinct from the priority calculation. Session 9 does not enrich Findings. |
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
| **Shared catalog** | Instance-owned, non-tenant vulnerability intelligence and KEV snapshots. Not duplicated per Organization and not publicly accessible. Findings that later use it remain tenant-owned. |
| **Current projection** | Mutable shared-catalog view of an advisory activated only after a complete source unit succeeds. Distinct from immutable raw snapshots and source revisions. |
| **Source revision** | Append-only normalized provider record (plus structured children) with provenance. Not rewritten in place. |
| **Withdrawn (OSV)** | Provider fact: the advisory has an explicit withdrawn timestamp. The record is retained. Distinct from absence in an incomplete or per-ecosystem export. |
| **Missing from authoritative snapshot** | Provider record absent from a later accepted complete snapshot (KEV current membership). Historical snapshots remain. Not a Finding mutation in Session 9. |
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
| **Intelligence source** | Global CISA KEV and future OSV synchronization state. Not a tenant installation. CISA KEV scheduled import is production composed when enabled. Sanitized provider-status GET routes exist (`intelligence:read`). Production OSV acquisition is disabled. The OSV implementation foundation is implemented and production uncomposed. Historical canary tools are operator only and unregistered. ZIP processing, automatic matching, Findings, a dashboard, and manual sync/retry are not operational. |
| **Match-evaluation evidence** | Immutable tenant record of an affected-version evaluation. Synthetic match-evaluation persistence is implemented and production uncomposed. Real product-eligible match evidence is unavailable. An `affected` row is not Finding authority. |
| **Product eligibility** | Derived classification. The provider-free product-evidence path is implemented and verified in disposable PostgreSQL. Persistent product-eligible evaluation count: 0. Real product-eligible evaluation count remains 0. Eligibility composition is production uncomposed and is not product matching. Synthetic evidence is not product evidence. Automatic matching and Finding creation remain unavailable. |
| **Integration** | Organization-owned installation of a provider catalog entry. `organizationId` is required. |
| **Risk calculation** | Append-only stored priority snapshot with factors, policy version, and engine version. |
| **Outbox event** | Transactional outbox row (`pending` → `claimed` → `processed`, or `failed` / `dead_lettered`). At-least-once; not exactly-once. |
| **Idempotency record** | Tenant-scoped hashed key for future mutation endpoints. Stores no raw bearer tokens. |

When in doubt, label data as **observed fact** or **calculated conclusion**.
