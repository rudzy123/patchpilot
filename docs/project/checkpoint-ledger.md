# Checkpoint ledger

Historical record only. This file is append-only and is not a source of truth.

Current checkpoint authority: [current-state.md](current-state.md).

Migration counts below are historical catalog sizes at the named checkpoint. The current frozen count is stated only in the current-state document.

## Session 8 — SBOM graph

Current checkpoint authority: [current-state.md](current-state.md).

CycloneDX JSON upload, private object storage, outbox relay, worker-thread parse, and graph persistence landed and are production composed. Deliberate gaps that remained: no SBOM web UI, no orphan-reconciliation job, no BackgroundJob lease heartbeat, and no automatic `sbom.ingest` retry poller.

## Session 9 — CISA KEV

Current checkpoint authority: [current-state.md](current-state.md).

CISA KEV synchronization and sanitized provider-status reads landed. KEV is an exploitation signal. It is not affectedness authority and it does not create Findings. At Session 9 closure, production OSV acquisition was not implemented.

## Session 11 — acquisition foundation

Current checkpoint authority: [current-state.md](current-state.md).

The OSV acquisition foundation was implemented and synthetically verified. Production OSV acquisition stayed disabled. Historical catalog size after Batch 5C-R: thirteen finished migrations. Catalog activation was not invoked. Finding creation stayed unavailable.

## Session 12 — runtime-enablement foundation

Current checkpoint authority: [current-state.md](current-state.md).

Listing transport, pagination, durable coordination schema and adapters, disabled composition, halt, and bounded observability were implemented and left production uncomposed. Historical catalog size after the runtime-coordination migration review: fourteen finished migrations. No production OSV job was registered.

## Session 13 — operator canaries

Current checkpoint authority: [current-state.md](current-state.md).

Canary authorization, provider-contact authorization, and protected listing-observation evidence were implemented and left production uncomposed. Two operator commands sent one listing request each and are not registered in application startup. One protected evidence set was persisted as `review_pending`. Candidate selection and body retrieval stayed unauthorized. Historical catalog sizes recorded during the session include fifteen, sixteen, and seventeen finished migrations. Those numbers are historical.

## Session 14 — npm evaluator and synthetic match evidence

Current checkpoint authority: [current-state.md](current-state.md).

npm was selected. An in-memory SemVer 2.0.0 evaluator and immutable synthetic match-evaluation persistence were implemented and left production uncomposed. Affected and unaffected evidence in that schema requires synthetic origin. A `limit` cut is not exclusion. Finding creation stayed unavailable. Historical catalog size after match-evaluation persistence: eighteen finished migrations.

## Session 15 — advisory provenance

Current checkpoint authority: [current-state.md](current-state.md).

Immutable advisory families, revisions, aliases, and one reviewed Vulnerability binding were implemented and left production uncomposed. Provider-free eligibility composition was implemented and left production uncomposed. It does not return `eligible` while the registries are empty, does not invoke the product evaluator in that state, and writes no product match row. Real product-eligible evaluation count remained 0. Historical catalog size after the advisory-revision migration: nineteen finished migrations. ADR 0031 stayed Proposed. The session merged after branch-closure review.

## Product Match Evidence — reviewed advisory authority

Current checkpoint authority: [current-state.md](current-state.md).

Product Match Evidence Batch 1 and Batch 1-R are committed on `feat/product-match-evidence`. Batch 2 adds uncommitted immutable approval persistence in `20261002120000_maintainer_reviewed_advisory_approval`. The working catalog size is twenty migrations. The approval binds one maintainer-reviewed revision, fingerprints, npm package identity, `Vulnerability.id`, distinct author and reviewer identities, the closed approval purpose, and the accepted `CC-BY-4.0` decision. It does not evaluate, write product match evidence, or create a Finding. Real product-eligible evaluation count remains 0. Batch 2-R keeps `maintainer_reviewed_advisory` out of the provider-derived source branch. Batch 3 is next only after commit. ADR 0032 stays Proposed.

## Product Match Evidence Batch 3 — one legal affected evaluation

Current checkpoint authority: [current-state.md](current-state.md).

Batch 3 adds `20261002180000_product_match_evaluation_evidence` because the Session 14 match-evaluation schema cannot store a maintainer-reviewed affected row. The working catalog size is twenty-one migrations. An explicit command binds one immutable approval, one revision, one `Vulnerability.id`, one tenant-owned component occurrence, and the reviewed npm evaluator. Disposable PostgreSQL tests persist one affected row. Exact replay inserts nothing. A conflicting replay overwrites nothing. Synthetic origin and KEV membership fail closed. Finding creation remains unavailable. Suppression authority remains false. Provider calls remain zero. Production startup does not invoke the command. The row is not seeded. Real product-eligible evaluation count remains 0. Batch 3-R is next. ADR 0032 stays Proposed.

## Product Match Evidence Batch 3-R — legal affected-evaluation review

Current checkpoint authority: [current-state.md](current-state.md).

Batch 3-R reviewed the uncommitted Batch 3 command on disposable PostgreSQL. The reviewed path persists one maintainer-reviewed, non-synthetic npm affected evaluation bound to the tenant component occurrence, advisory revision, independent approval, `Vulnerability.id`, reviewed evaluator, and matching policy. Exact replay inserts nothing and does not invoke the evaluator again. A conflicting replay does not overwrite the row. A stored replay fingerprint that does not match the stored immutable fields fails closed. Synthetic origin, KEV membership, self-approval, and a non-maintainer reviewer classification stay ineligible. Occurrence lookup is organization-scoped. The composition does not accept a replacement evaluator. Finding creation remains unavailable. Suppression authority remains false. Provider calls remain zero. Production startup does not invoke the command. The row is not seeded. Real product-eligible evaluation count remains 0. Generalized product matching is not live. Branch-closure review is next. ADR 0032 stays Proposed.

## Product Match Evidence — merged

Current checkpoint authority: [current-state.md](current-state.md).

Product Match Evidence merged through PR #51 at merge commit `433ea88`. Batches 1 through 3-R are complete. Product Match Evidence branch closure is complete. The legal non-synthetic affected evaluation path is verified in disposable PostgreSQL. Persistent product-eligible evaluation count remains zero. Finding creation remains unavailable. Provider calls remain zero. Production automatic matching remains unavailable. Reviewer-authority capability issuance and consumption remain deferred. ADR 0032 stays Proposed.

Earlier entries in this ledger that say occurrence lookup is organization-scoped record the query predicate used at that review. Organization scope does not authorize a tenant-facing path to expose a cross-tenant existence distinction. Foreign and missing occurrence results remain a deferred indistinguishability prerequisite. This ledger is not the current repository authority.

## Reviewer Approval Capability Batch 1 — issued-authority architecture

Current checkpoint authority: [current-state.md](current-state.md).

Post-merge reconciliation PR #52 is in the branch ancestry at `f822814`. This entry records architecture contracts for an issued reviewer capability under `reviewer_approval_capability_policy_v1`. The issuer is not a public export. The handle is process-local and unforgeable by an ordinary object. It binds one exact approval target. Caller-supplied reviewer classification is not authority. The saved approval command and PostgreSQL adapter are unchanged. No migration was added. No capability, approval, product-match row, or Finding is written by this batch. Production startup does not construct the issuer. ADR 0032 stays Proposed. The saved-path discrepancy remains open. Batch 1-R is next. This ledger is not the current repository authority.

## Reviewer Approval Capability Batch 1-R — issued-authority architecture review

Current checkpoint authority: [current-state.md](current-state.md).

Batch 1-R reviewed the uncommitted Batch 1 architecture on `fix/reviewer-approval-capability` at `f822814`. Reentrant clock callbacks fail closed and do not settle a second lifecycle transition. A different correlation ID does not mint a second capability for the same approval claim. Terminal targets are not reissued inside the process. The saved approval path is unchanged and still accepts caller-supplied reviewer claims. Process-local consumption is not atomic with PostgreSQL. The architecture commit witness is not a database commit. Batch 2 remains one immutable issuance row plus one append-only terminal observation, and only after this architecture is committed. No Prisma change, migration, evaluator call, product-match write, or Finding write was added. Production runtime does not construct the issuer. ADR 0032 stays Proposed. The saved-path discrepancy remains open. This ledger is not the current repository authority.

## Reviewer Approval Capability Batch 2 — durable issuance and atomic approval consumption

Current checkpoint authority: [current-state.md](current-state.md).

Batch 1 and Batch 1-R are committed. Batch 2 adds `20261003120000_reviewer_capability_issuance`. Batch 2-R independently reviewed that uncommitted migration and recorded final SHA-256 `08f18ce42ba19165f6d0a1bf872e5973bf74e26888e7f052c70c53779656dfbd`. The frozen count is 22. One immutable issuance row and one append-only terminal observation (`consumed`, `revoked`, or `cancelled`) are the durable model. Presentation is not stored. Issued-at and expires-at come from database time. The TTL is 900000 milliseconds and validity is half-open. Approval insertion and capability consumption commit in one transaction. A consumed observation must match the approval target. Exact replay does not renew authority. Immutable conflicts overwrite nothing. Issuer seals are not package exports. The saved approval command no longer writes from caller-supplied reviewer classification. Production runtime does not construct the adapter. Evaluator calls, product-match writes, Finding writes, and provider calls remain zero. User-facing reviewer approval is not operational. ADR 0032 stays Proposed. Branch closure is next after commit. This ledger is not the current repository authority.

## Reviewer Approval Capability branch closure

Current checkpoint authority: [current-state.md](current-state.md).

Batches 1, 1-R, 2, and 2-R are committed on `fix/reviewer-approval-capability`. The frozen migration `20261003120000_reviewer_capability_issuance` remains SHA-256 `08f18ce42ba19165f6d0a1bf872e5973bf74e26888e7f052c70c53779656dfbd`. The frozen count remains 22. Branch-closure review found the issued-capability chain complete for the reviewer-authority prerequisite and production uncomposed. Caller-supplied reviewer classification does not persist a new approval. ADR 0032 stays Proposed. The next repository step is the pull request. Finding creation remains unavailable. This ledger is not the current repository authority.

## Controlled Finding architecture governance

Current checkpoint authority: [current-state.md](current-state.md).

On 2026-10-06 the governance session accepted ADR 0032 from the committed reviewer-capability implementation, amended ADR 0026 with the creation-only exception `controlled_maintainer_reviewed_finding_creation_v1`, and accepted ADR 0035 for the controlled Finding creation slice. No migration was added. The frozen count remains 23. Finding creation remains unavailable. Production composition remains absent. Entries above that say ADR 0032 stays Proposed record earlier checkpoints. This ledger is not the current repository authority.
