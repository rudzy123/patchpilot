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
