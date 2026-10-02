# Current state

This document is the checkpoint authority for what PatchPilot implements, composes, and still withholds. It describes the repository after architecture-alignment reconciliation. Historical session narrative lives in [checkpoint-ledger.md](checkpoint-ledger.md) and is not an authority source.

Read this file before treating `AGENTS.md`, an ADR body, or an architecture narrative as the current capability list.

## Facts

- Frozen migrations: 19
- Real product-eligible evaluation count: 0
- Production OSV acquisition: disabled
- Finding creation from match evidence: unavailable

`INTELLIGENCE_OSV_ENABLED=true` remains rejected. Product-evidence eligibility composition produces no eligible record, invokes no product evaluator in the accepted zero-eligibility state, and writes no product match row. Composition is not product matching.

## Authority order

1. Committed production runtime behavior
2. Frozen database schema and migrations
3. Accepted ADRs
4. Tested domain contracts
5. This document
6. Architecture documents
7. [AGENTS.md](../../AGENTS.md) as a router
8. README and public positioning
9. [Checkpoint ledger](checkpoint-ledger.md) and other historical session reports

## Production composed

These paths are reachable from API, worker, or web startup:

- Authentication and tenant selection
- Asset inventory
- SBOM upload, storage, parsing, and graph persistence
- CISA KEV synchronization when enabled
- Sanitized intelligence-provider status

The worker queue accepts `sbom.ingest` and `intelligence.sync` only. Intelligence status reads do not contact a provider.

## Implemented but production uncomposed

Present in packages and tests, and not constructed by API, worker, web, seed, or migration startup:

- OSV transport and acquisition controls
- Protected listing observations
- npm evaluator
- Immutable match-evaluation persistence
- Immutable advisory revisions
- Reviewed Vulnerability bindings
- Product-evidence eligibility composition
- Canonical CVE identity persistence
- Read-only active-catalog KEV membership derivation

OSV implementation foundation: implemented but production uncomposed. Historical canary tools are operator only and unregistered. They are not production startup and they are not a second OSV runtime.

Synthetic match-evaluation evidence persistence is implemented, immutable, and production uncomposed. Affected and unaffected rows in that schema require synthetic origin. Immutable advisory revisions and Vulnerability bindings are implemented and production uncomposed. Real product-eligible match evidence is unavailable.

## Test only

- Simulated product-evidence composition
- Disposable PostgreSQL verification
- Disabled OSV acquisition rehearsals

Simulated fixtures are not real product evidence.

## Placeholder

- Finding and FindingObservation product infrastructure
- Risk, remediation, and related models

The Finding schema is placeholder infrastructure. It is not an implemented Finding workflow. The composed Finding repository is read-only (`findById`, `listForOrganization`). The generic `PrismaFindingRepository.create` path and its `CreateFindingInput` type have been removed, so production composition cannot create a Finding through the repository bundle. A future Finding write must be a purpose-specific reviewed command under [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md). Direct Prisma Finding writes exist only in tests and test fixtures.

`packages/policy-engine` has no scoring implementation. There is no export product model.

## Blocked or unavailable

- Real product-eligible evaluations
- Production OSV acquisition
- Automatic matching
- Finding creation from match evidence
- Prioritization
- Assignment
- Remediation
- Verification
- Export

The active ecosystem and evaluator registries that would admit `eligible` are empty. An empty registry blocks `eligible`. Synthetic evidence is denied as product evidence. KEV is not affectedness authority. `unknown` is not `unaffected`. An `affected` result is not Finding authority.

## User-visible capability

A signed-in user can select an organization and use the asset inventory. SBOM upload, ingestion, and graph persistence are available through the API and worker. Sanitized provider status is available through the API. There is no vulnerability dashboard, no Finding workflow, and no remediation workflow.

## Next product milestone

This document does not start the milestone.

- Preferred product goal: one legitimate non-synthetic affected evaluation
- Unresolved authority decision: a reviewed local advisory versus one separately authorized provider-body retrieval. Either choice needs an explicit provenance ADR. A local document can become synthetic evidence under another label, so this page does not authorize a product-approved local advisory.
- Mandatory prerequisite: a forward-only match-evidence shape that binds an advisory revision and `Vulnerability.id` without laundering synthetic evidence

Exit intent for a later branch, after that ADR: exactly one legal affected evaluation, `finding_creation` unavailable, and zero Findings. Production OSV acquisition stays disabled.

## Deferred technical branches

Recorded here and not implemented in architecture alignment:

| Branch | Purpose |
| --- | --- |
| `feat/product-match-evidence` | Carry the prerequisite above. Preserve `finding_creation = unavailable`. Admit only the reviewed npm evaluator. Do not choose local versus provider provenance until an ADR does. |
| `chore/dependency-security-baseline` | Re-run the dependency audit, replace the 2026-08-29 advisory snapshot, and assess the transitive `deepmerge-ts` advisory. Keep that work out of architecture reconciliation. |

## ADR posture

Accepted: ADR 0001–0026 and ADR 0028–0029. Proposed, and unchanged by this reconciliation: ADR 0027, ADR 0030, and ADR 0031. Proposed does not mean the related code is absent. It means the ADR is not accepted. Implementation notes live on those ADR pages and in the sections above.
