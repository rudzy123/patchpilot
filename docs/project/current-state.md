# Current state

This document is the checkpoint authority for what PatchPilot implements, composes, and still withholds. It describes the repository after post-merge reconciliation PR #52 (merge commit `f822814`), committed Reviewer Approval Capability Batch 1 and Batch 1-R architecture, and Batch 2 durable issuance. Historical session narrative lives in [checkpoint-ledger.md](checkpoint-ledger.md) and is not an authority source.

Read this file before treating `AGENTS.md`, an ADR body, or an architecture narrative as the current capability list.

## Facts

- Frozen migrations: 22. Frozen hashes match `FROZEN_MIGRATIONS`. Disposable PostgreSQL verifies clean deployment, upgrade from the prior frozen head, and a repeated no-op for `20261003120000_reviewer_capability_issuance` (SHA-256 `08f18ce42ba19165f6d0a1bf872e5973bf74e26888e7f052c70c53779656dfbd`). The persistent development database was not reset.
- Persistent product-eligible evaluation count: 0
- Real product-eligible evaluation count: 0
- Persistent Finding count: 0
- Production OSV acquisition: disabled
- Automatic product matching: unavailable
- Finding creation from match evidence: unavailable
- Suppression authority: false

`INTELLIGENCE_OSV_ENABLED=true` remains rejected. Product-evidence eligibility composition produces no eligible record, invokes no product evaluator in the accepted zero-eligibility state, and writes no product match row. That composition is not product matching.

The provider-free product-evidence path is implemented and verified in disposable PostgreSQL. Persistent product-eligible evaluation count: 0.

Disposable PostgreSQL tests create isolated legal affected evaluations. A complete run of the product-match evaluation persistence suite may create three legal rows, one in each seeded organization used by the tests that persist an evaluation. That database is dropped after the run. Those rows are not a production count and they are not the persistent product-eligible evaluation count. Synthetic evidence remains product ineligible. KEV remains nonauthoritative for affectedness. Provider calls on that path remain zero.

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
- Canonical CVE identity persistence
- Read-only active-catalog KEV membership derivation

OSV implementation foundation: implemented but production uncomposed. Historical canary tools are operator only and unregistered. They are not production startup and they are not a second OSV runtime.

Synthetic match-evaluation evidence persistence is implemented, immutable, and production uncomposed. Affected and unaffected rows in that schema require synthetic origin. The Session 14 schema still cannot store a legal non-synthetic affected row. Product Match Evidence stores that evidence on `product_match_evaluation_evidence` (`20261002180000_product_match_evaluation_evidence`, SHA-256 `5a9736ae9ee5dc2b3ecb65325eeaebe98704ef00dffcb34d549a62cfe6cfcb6b`). The command binds one immutable maintainer-reviewed revision, one immutable independent approval, one reviewed `Vulnerability.id`, one tenant-owned component occurrence, the reviewed npm evaluator, and the reviewed matching policy. Exact replay inserts nothing and does not change the database timestamp. A conflicting replay does not overwrite the row. Synthetic origin and KEV membership fail closed before evaluation. `finding_creation` stays `unavailable`. Suppression authority stays false. An affected result is evidence only. The factories are production uncomposed.

Maintainer-reviewed advisory approval persistence is implemented and production uncomposed (`20261002120000_maintainer_reviewed_advisory_approval`, SHA-256 `9f4ae2a6402952ff0ecca27a88cb15859a2164d89591fe2afe64e7e9ddbfb380`). An approval binds one immutable maintainer-reviewed revision, its content and range fingerprints, the npm package identity, one `Vulnerability.id`, the author, a distinct reviewer, the approval purpose `approve_maintainer_reviewed_advisory_for_product_evaluation`, and the accepted `CC-BY-4.0` source-license decision. Exact replay does not insert or change the database timestamp. A conflicting replay does not overwrite the row. Update and delete are rejected. Parent deletion is restricted. Approval does not run evaluation, write product match evidence, or create a Finding. No approval is seeded. Approval is not a user-facing workflow.

## Test only

- Simulated product-evidence composition
- Disposable PostgreSQL verification of the provider-free legal evaluation path
- Disabled OSV acquisition rehearsals

Simulated fixtures are not product evidence. Disposable legal rows are not persistent product evidence.

## Placeholder

- Finding and FindingObservation product infrastructure
- Risk, remediation, and related models

The Finding schema is placeholder infrastructure. It is not an implemented Finding workflow. The composed Finding repository is read-only (`findById`, `listForOrganization`). The generic `PrismaFindingRepository.create` path and its `CreateFindingInput` type have been removed, so production composition cannot create a Finding through the repository bundle. No production Finding writer exists. A future Finding write must be a purpose-specific reviewed command under [ADR 0026](../adr/0026-authoritative-match-evidence-and-finding-lifecycle.md). Direct Prisma Finding writes exist only in tests and test fixtures.

`packages/policy-engine` has no scoring implementation. There is no export product model.

## Blocked or unavailable

- Automatic or seeded product matching
- Production OSV acquisition
- Automatic matching
- Finding creation from match evidence
- Prioritization
- Assignment
- Remediation
- Verification
- Export

The active ecosystem and evaluator registries that would admit `eligible` are empty. An empty registry blocks `eligible`. Synthetic evidence is denied as product evidence. KEV is not affectedness authority. `unknown` is not `unaffected`. An `affected` result is not Finding authority.

## Reviewer-authority discrepancy

[ADR 0032](../adr/0032-maintainer-reviewed-advisory-authority.md) remains Proposed. Decision 3 requires an issued reviewer capability. Reviewer Approval Capability Batch 1 defines that architecture: one sealed issuer-authority boundary, an opaque process-local presentation handle, exact approval-target binding, separation of duties, and closed expiration, revocation, cancellation, and consumption classifications. Caller-supplied reviewer identity and `reviewerAuthorityClassification` remain insufficient. Reviewer identity alone is not authority. Administrator, owner, maintainer, Git author, code owner, CI actor, and other ambient role strings do not grant approval authority.

Batch 1 and Batch 1-R are committed. Batch 2 adds durable issuance on `reviewer_capability_issuance` and one append-only terminal observation on `reviewer_capability_lifecycle_observation`. The natural identity is the approval-claim fingerprint. Correlation is request binding and does not mint a second capability. Issuance and expiration use PostgreSQL `clock_timestamp()`. Validity is half-open for 900000 milliseconds: valid while database time is before `expires_at`, expired when database time is greater than or equal to `expires_at`. The process-local secret handle is not a column. The persisted issuer proof is the authorization UUID and decision fingerprint. `recordMaintainerReviewedAdvisoryApproval` parses and then returns `capability_authority_required` with zero writes. The PostgreSQL writer is `persistMaintainerReviewedAdvisoryApprovalWithCapability`, which inserts the approval and the consumed observation in one transaction. Exact approval replay returns `already_applied` before capability presentation, inserts nothing, and does not change timestamps or renew authority. An immutable conflict overwrites nothing. Revocation and cancellation append one terminal observation and block unused presentation. A consumed capability stays consumed. Revocation or cancellation does not alter a committed approval. Update and delete are rejected. Parent deletion is `ON DELETE RESTRICT`. Public inspection returns `reusableAuthority: false` and omits handles, authorization ids, fingerprints, and identities. Issuer and lifecycle seals are not package exports. A consumed observation must match the stored approval target. Production startup does not construct the adapter. Evaluator calls, product-match writes, Finding writes, and provider calls remain zero. User-facing reviewer approval is not operational. ADR 0032 remains Proposed. Batch 2-R independently reviewed this uncommitted persistence.

## Open decision: product-match cardinality

`product_match_evaluation_evidence` is unique per organization and component occurrence, and unique per organization and advisory revision. Whether that cardinality is the intended product model is an open architecture decision. These constraints are recorded as an open decision. They are not classified as defects.

## User-visible capability

A signed-in user can select an organization and use the asset inventory. SBOM upload, ingestion, and graph persistence are available through the API and worker. Sanitized provider status is available through the API. There is no vulnerability dashboard, no Finding workflow, and no remediation workflow.

## Next

Reviewer Approval Capability Batch 2 durable issuance and atomic approval consumption is implemented and production uncomposed. Batch 2-R independently reviewed that persistence. Branch closure is next after commit. This document does not start Finding implementation and does not make reviewer approval a user-facing workflow.

Generalized product matching is not live. Finding creation remains unavailable. Production OSV acquisition stays disabled.

## Deferred technical work

Recorded here and not implemented in this checkpoint.

### High priority

1. Reviewer-authority capability review. Batch 2 persists issued capability authority and consumes it atomically with approval insertion. Batch 2-R independently reviewed durable issuance, database time, and atomic consumption. Caller role strings do not issue or persist an approval. The path is production uncomposed. Branch closure is next after commit. Do not treat this as a user-facing approval workflow or Finding authority.
2. Main CI verification. If a later main Quality rerun fails on the keyboard-focus test, suggested branch: `test/web-keyboard-focus-hermeticity`.

### Before Finding implementation

3. Cross-tenant existence oracle. Suggested future branch: `fix/product-match-tenant-indistinguishability`. Tenant-facing paths should normally collapse foreign and missing occurrence results into an indistinguishable not-found classification. An organization-scoped lookup does not authorize exposing whether a foreign occurrence exists.
4. Product-match evidence cardinality. Suggested future architecture checkpoint: decide whether uniqueness per organization and occurrence, and per organization and advisory revision, is the intended product model.
5. Integration-test database hermeticity. Suggested future branch: `test/integration-database-hermeticity`. API and worker integration tests should use disposable databases rather than the shared development database.
6. Dependency security baseline. Suggested future branch: `chore/dependency-security-baseline`. Run when registry access is available.
7. Adjacent generic writers. Review remediation and risk-policy create methods before those workflows become reachable.

### Low priority

Recorded and not fixed. This checkpoint does not authorize destructive cleanup.

- No TRUNCATE guard on append-only tables
- Stale compiled gitignored fixture output
- Leaked throwaway databases
- Stale merged branches
- Development seed source-label precision

## CI

CI status unavailable from the current environment. This checkpoint does not treat the latest main Quality run as green or failed.

## ADR posture

Accepted: ADR 0001–0026 and ADR 0028–0029. Proposed: ADR 0027, ADR 0030, ADR 0031, and ADR 0032. ADR 0032 remains Proposed. Proposed does not mean the related code is absent. Implementation notes live on those ADR pages and in the sections above.
