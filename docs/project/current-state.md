# Current state

This document is the checkpoint authority for what PatchPilot implements, composes, and still withholds. It describes the repository after Controlled Finding Session 2 persistence. [ADR 0032](../adr/0032-maintainer-reviewed-advisory-authority.md) is Accepted for production-uncomposed reviewer authority. [ADR 0035](../adr/0035-controlled-finding-creation.md) is Accepted for creation-only Finding architecture. Controlled Finding contracts and process-local creation authorization are implemented. Session 1-R reviewed the process-local creation authorization. The atomic creation transaction and evidence-link model are implemented and production uncomposed. Tenant-facing inspection is not implemented. Lifecycle transitions remain unavailable. Production composition is absent. A user-facing Finding product is not operational. Historical session narrative lives in [checkpoint-ledger.md](checkpoint-ledger.md) and is not an authority source.

Read this file before treating `AGENTS.md`, an ADR body, or an architecture narrative as the current capability list.

## Facts

- Frozen migrations: 24. Frozen hashes match `FROZEN_MIGRATIONS`. Disposable PostgreSQL verifies clean deployment, upgrade from the prior frozen head, and a repeated no-op for `20261006120000_controlled_finding_creation` (SHA-256 `b646ceb889e68ab76154fded3f3c6a9b186f82be28d34a7574cb17136d1aadb1`). The predecessor `20261005120000_product_match_evidence_cardinality` remains SHA-256 `6a62e06d0a5ae25c198f2227c25997a63588a9f24d39337cc95379b129a425d7`. The persistent development database was not reset.
- Persistent product-eligible evaluation count: 0
- Real product-eligible evaluation count: 0
- Persistent Finding count: 0
- Production OSV acquisition: disabled
- Automatic product matching: unavailable
- Finding creation from match evidence: controlled transaction implemented, production uncomposed. Automatic Finding creation remains unavailable.
- Suppression authority: false
- New CycloneDX graphs use normalization version `2`. Distinct observed versions of one versionless Component are distinct ComponentOccurrences. Historical completed graphs labeled `1` are not rewritten and are not reprocessed. No migration was added.

`INTELLIGENCE_OSV_ENABLED=true` remains rejected. Product-evidence eligibility composition produces no eligible record, invokes no product evaluator in the accepted zero-eligibility state, and writes no product match row. That composition is not product matching.

The provider-free product-evidence path is implemented and verified in disposable PostgreSQL. Persistent product-eligible evaluation count: 0.

Disposable PostgreSQL tests create isolated legal affected evaluations. A complete run of the product-match evaluation persistence suite may create multiple legal rows in the disposable organizations used by the tests that persist an evaluation, including more than one row for one organization when occurrences, revisions, or assets differ. That database is dropped after the run. Those rows are not a production count and they are not the persistent product-eligible evaluation count. Synthetic evidence remains product ineligible. KEV remains nonauthoritative for affectedness. Provider calls on that path remain zero.

Product Match Evidence branch closure is complete. Production startup does not invoke the evaluation command.

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
- Maintainer-reviewed advisory authority architecture contracts
- Immutable maintainer-reviewed advisory approval persistence
- Product Match Evidence composition for one reviewed npm evaluation command
- Reviewer approval capability architecture contracts (`reviewer_approval_capability_policy_v1`)
- Durable reviewer-capability issuance and atomic approval consumption (`20261003120000_reviewer_capability_issuance`)
- Controlled Finding creation contracts and process-local creation authorization (`create_finding_from_product_match_evidence`, `finding_creation_policy_v1` version 1). The authorization is process-local and is not durable. Session 1-R reviewed that authorization. The issuer function is not a package export. The atomic creation transaction and evidence-link model are implemented and production uncomposed. Tenant-facing inspection is not implemented. Lifecycle transitions remain unavailable. Production composition is absent.
- Canonical CVE identity persistence
- Read-only active-catalog KEV membership derivation

OSV implementation foundation: implemented but production uncomposed. Historical canary tools are operator only and unregistered. They are not production startup and they are not a second OSV runtime.

Synthetic match-evaluation evidence persistence is implemented, immutable, and production uncomposed. Affected and unaffected rows in that schema require synthetic origin. The Session 14 schema still cannot store a legal non-synthetic affected row. Product Match Evidence stores that evidence on `product_match_evaluation_evidence` (`20261002180000_product_match_evaluation_evidence`, SHA-256 `5a9736ae9ee5dc2b3ecb65325eeaebe98704ef00dffcb34d549a62cfe6cfcb6b`). The command binds one immutable maintainer-reviewed revision, one immutable independent approval, one reviewed `Vulnerability.id`, one tenant-owned component occurrence, the reviewed npm evaluator, and the reviewed matching policy. Exact replay inserts nothing and does not change the database timestamp. A conflicting replay does not overwrite the row. Synthetic origin and KEV membership fail closed before evaluation. `finding_creation` stays `unavailable`. Suppression authority stays false. An affected result is evidence only. The factories are production uncomposed. Tenant-facing occurrence and product-match evidence lookups require the organization and the resource identity together at the persistence boundary. A foreign row and an absent row return the same public not-found result. Malformed identities remain a separate closed failure and do not disclose whether a row exists. The adapter does not look up an occurrence globally and then reject it because the organization differs. It does not keep a private foreign-versus-absent classification, and that distinction does not change the public result or retry behavior. Authorized inspection and evaluation of the requesting organization's own occurrence remain available. Automatic matching remains unavailable. Product Match Evidence cardinality is accepted in [ADR 0033](../adr/0033-product-match-evidence-cardinality.md). One occurrence may retain immutable evidence for more than one advisory revision, and one revision may retain immutable evidence for more than one occurrence. Exact replay and reevaluation are different operations. Exact replay returns the existing row. A changed evaluator or policy identity may append a new row. Current applicability is derived at query time and is not stored by mutating evidence. Future Finding identity remains organization, asset, versionless component, and vulnerability. New graphs use normalization version `2` and preserve distinct observed versions. Historical version `1` graphs are not reprocessed.

Maintainer-reviewed advisory approval persistence is implemented and production uncomposed (`20261002120000_maintainer_reviewed_advisory_approval`, SHA-256 `9f4ae2a6402952ff0ecca27a88cb15859a2164d89591fe2afe64e7e9ddbfb380`). An approval binds one immutable maintainer-reviewed revision, its content and range fingerprints, the npm package identity, one `Vulnerability.id`, the author, a distinct reviewer, the approval purpose `approve_maintainer_reviewed_advisory_for_product_evaluation`, and the accepted `CC-BY-4.0` source-license decision. Exact replay does not insert or change the database timestamp. A conflicting replay does not overwrite the row. Update and delete are rejected. Parent deletion is restricted. Approval does not run evaluation, write product match evidence, or create a Finding. No approval is seeded. Approval is not a user-facing workflow.

## Test only

- Simulated product-evidence composition
- Disposable PostgreSQL verification of the provider-free legal evaluation path
- Disabled OSV acquisition rehearsals

Simulated fixtures are not product evidence. Disposable legal rows are not persistent product evidence.

## Placeholder

- Finding and FindingObservation product infrastructure
- Risk, remediation, and related models

The Finding schema now supports one controlled creation transaction. It is not an implemented Finding workflow. The composed Finding repository is read-only (`findById`, `listForOrganization`). The generic `PrismaFindingRepository.create` path and its `CreateFindingInput` type have been removed, so production composition cannot create a Finding through the repository bundle. The controlled writer is production uncomposed and is not a package export. [ADR 0035](../adr/0035-controlled-finding-creation.md) accepts creation-only architecture. Session 1 implements the framework-independent contracts and the process-local creation authorization. Session 1-R reviewed that authorization. The atomic creation transaction and evidence-link model are implemented and production uncomposed. Tenant-facing inspection is not implemented. Lifecycle transitions remain unavailable. Direct Prisma Finding writes exist only in tests and test fixtures. Product Match Evidence does not grant Finding authority by itself.

`packages/policy-engine` has no scoring implementation. There is no export product model.

## Blocked or unavailable

- Automatic or seeded product matching
- Production OSV acquisition
- Automatic matching
- Automatic Finding creation and tenant-facing Finding inspection
- Prioritization
- Assignment
- Remediation
- Verification
- Export

The active ecosystem and evaluator registries that would admit `eligible` are empty. An empty registry blocks `eligible`. Synthetic evidence is denied as product evidence. KEV is not affectedness authority. `unknown` is not `unaffected`. An `affected` result is not Finding authority.

## Reviewer authority

[ADR 0032](../adr/0032-maintainer-reviewed-advisory-authority.md) is Accepted. Decision 3 is implemented as an issued reviewer capability: one sealed issuer-authority boundary, an opaque process-local presentation handle, exact approval-target binding, separation of duties, and closed expiration, revocation, cancellation, and consumption classifications. Caller-supplied reviewer identity and `reviewerAuthorityClassification` remain insufficient. Reviewer identity alone is not authority. Administrator, owner, maintainer, Git author, code owner, CI actor, and other ambient role strings do not grant approval authority. Acceptance does not grant Finding authority.

Batch 1 and Batch 1-R are committed. Batch 2 adds durable issuance on `reviewer_capability_issuance` and one append-only terminal observation on `reviewer_capability_lifecycle_observation`. The natural identity is the approval-claim fingerprint. Correlation is request binding and does not mint a second capability. Issuance and expiration use PostgreSQL `clock_timestamp()`. Validity is half-open for 900000 milliseconds: valid while database time is before `expires_at`, expired when database time is greater than or equal to `expires_at`. The process-local secret handle is not a column. The persisted issuer proof is the authorization UUID and decision fingerprint. `recordMaintainerReviewedAdvisoryApproval` parses and then returns `capability_authority_required` with zero writes. The PostgreSQL writer is `persistMaintainerReviewedAdvisoryApprovalWithCapability`, which inserts the approval and the consumed observation in one transaction. Exact approval replay returns `already_applied` before capability presentation, inserts nothing, and does not change timestamps or renew authority. An immutable conflict overwrites nothing. Revocation and cancellation append one terminal observation and block unused presentation. A consumed capability stays consumed. Revocation or cancellation does not alter a committed approval. Update and delete are rejected. Parent deletion is `ON DELETE RESTRICT`. Public inspection returns `reusableAuthority: false` and omits handles, authorization ids, fingerprints, and identities. Issuer and lifecycle seals are not package exports. A consumed observation must match the stored approval target. Production startup does not construct the adapter. Evaluator calls, product-match writes, Finding writes, and provider calls remain zero. User-facing reviewer approval is not operational. ADR 0032 is Accepted. Batches 1, 1-R, 2, and 2-R are committed. Branch-closure review recorded this path as complete for the reviewer-authority prerequisite and production uncomposed. Product Match Evidence does not grant Finding authority by itself.

## Product-match cardinality

[ADR 0033](../adr/0033-product-match-evidence-cardinality.md) accepts the evidence grain. Uniqueness is organization-scoped exact evaluation identity: occurrence, advisory revision, reviewed approval, evaluator identity and version, matching policy identity and version, and product-evidence policy identity and version. Replay uniqueness is organization-scoped. Exact replay and reevaluation are different operations. Historical evidence remains after a successor revision becomes current. Current applicability is query-time. Automatic Finding creation remains unavailable. The controlled creation transaction is production uncomposed. Suppression authority remains false. Automatic matching remains unavailable. Multi-version occurrence normalization for new graphs is accepted by [ADR 0034](../adr/0034-multi-version-component-occurrence-normalization.md). Normalization version `2` preserves distinct observed versions. Version `1` graphs stay unchanged.

## User-visible capability

A signed-in user can select an organization and use the asset inventory. SBOM upload, ingestion, and graph persistence are available through the API and worker. Sanitized provider status is available through the API. There is no vulnerability dashboard, no Finding workflow, and no remediation workflow.

## Controlled Finding architecture

[ADR 0032](../adr/0032-maintainer-reviewed-advisory-authority.md), the [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md) creation-only exception, and [ADR 0035](../adr/0035-controlled-finding-creation.md) are Accepted. The controlled Finding architecture is accepted only because those ADRs are accepted together. Controlled Finding contracts and process-local creation authorization are implemented. The atomic creation transaction and evidence-link model are implemented and production uncomposed. Tenant-facing inspection is not implemented. Lifecycle transitions remain unavailable. Production composition is absent. The creation observation and evidence links are persisted only by that uncomposed transaction. Product Match Evidence does not grant Finding authority by itself. Membership, role, and administrator status do not grant Finding authority. `finding_creation_policy_v1` version 1 limits one creation evidence set to 16 Product Match Evidence identities. That ceiling is an implementation policy limit for the first slice. It is not the Finding natural identity, not a schema constraint, and not a permanent domain maximum. ADR 0035 does not fix the number. A larger set is rejected and writes nothing. A later policy version may raise it. The issuer function is not a package export. Relative import of the issuer module is an internal same-package trust boundary, not a supported minting API. Session 1-R reviewed the process-local creation authorization. Session 2-R reviewed the creation transaction. A Finding cannot commit without its creation observation, complete evidence links, and creation audit event. The controlled product slice is not complete. All lifecycle powers remain unavailable. Session 3 inspection and explanation is next.

## Next

The next repository step is Controlled Finding Session 3 inspection and explanation. Session 2-R reviewed the production-uncomposed creation transaction. It does not add tenant-facing inspection, lifecycle transitions, or production composition. Reviewer approval is not a user-facing workflow. All lifecycle powers remain unavailable.

Generalized product matching is not live. A user-facing Finding product is not operational. Production OSV acquisition stays disabled.

## Deferred technical work

Recorded here and not implemented in this checkpoint.

### High priority

1. Main CI verification. If a later main Quality rerun fails on the keyboard-focus test, suggested branch: `test/web-keyboard-focus-hermeticity`.

### Before the Finding implementation branch

The implementation branch may add the additive evidence-link migration and one production-uncomposed creation command only after this architecture is merged. That branch must not compose production and must not implement lifecycle transitions.

Adjacent generic writers remain a review item before remediation or risk workflows become reachable. They are not the creation-only command.

Already merged, and not remaining prerequisites: Product Match Evidence cardinality ([ADR 0033](../adr/0033-product-match-evidence-cardinality.md)), normalization version `2` ([ADR 0034](../adr/0034-multi-version-component-occurrence-normalization.md)), reviewer-capability issuance ([ADR 0032](../adr/0032-maintainer-reviewed-advisory-authority.md)), and integration-test database hermeticity. API and worker integration processes, and database-package integration tests, use disposable PostgreSQL databases. Test database isolation is not product tenant isolation.

Dependency advisory residuals remain repository supply-chain maintenance, not a product Finding. Re-audited on 2026-10-06 with Node.js 24.20.0 and pnpm 11.24.0. Two highs remain: `deepmerge-ts@7.1.5` through Prisma, and unpatched `braces@3.0.3` through ESLint tooling. `pnpm audit` and `pnpm audit --prod` still exit 1 because of those residuals. The record is [dependency-security.md](../security/dependency-security.md).

### Low priority

Recorded and not fixed. This checkpoint does not authorize destructive cleanup.

- No TRUNCATE guard on append-only tables
- Stale compiled gitignored fixture output
- Leaked throwaway databases that predate timestamped names. New disposable databases older than 2 hours and idle can be reaped, at most 8 per integration process start.
- Stale merged branches
- Development seed source-label precision
- Fastify 6 migration for top-level `disableRequestLogging`. Fastify 5.12.5 still honors it and emits `FSTDEP023`. The warning is not disabled.

## CI

CI status unavailable from the current environment. This checkpoint does not treat the latest main Quality run as green or failed.

## ADR posture

Accepted: ADR 0001–0026, ADR 0028–0029, and ADR 0032–0035. Proposed: ADR 0027, ADR 0030, and ADR 0031. ADR 0032 is Accepted and production uncomposed. ADR 0035 is Accepted as creation-only architecture. Session 1 contracts and process-local creation authorization are implemented and production uncomposed. Session 1-R reviewed that authorization. Session 2 implements the atomic creation transaction and evidence-link model. Both remain production uncomposed. Tenant-facing inspection is not implemented. Lifecycle transitions remain unavailable. A user-facing Finding product is not operational. Proposed does not mean the related code is absent. Implementation notes live on those ADR pages and in the sections above.
