# ADR 0027: OSV acquisition persistence and catalog activation

- Status: Proposed
- Date: 2026-09-04
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Proposed on this feature branch. This ADR records the Batch 5A persistence
architecture as contracts in Session 11 Batch 5B. It does **not** accept Prisma
models, a migration, adapters, object storage, provider retrieval,
synchronization, matching, or Finding writes. Accept this ADR before Session 11
Batch 5C creates the forward-only migration.

## Context

[ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md)
selects instance-owned OSV catalog acquisition and atomic activation. It does
not define tables, completeness equations, quarantine, or the OSV active
pointer. CISA KEV persistence (`IntelligenceSource.activeGenerationId`) is
KEV-only and must not be overloaded.

Session 11 Batch 5B encodes the approved architecture as framework-independent
contracts in `@patchpilot/vulnerability-intelligence`. Persistence,
catalog activation, and object storage do not exist yet.

## Decision

- Persist OSV acquisition as instance-owned, tenant-independent evidence.
- Identify provider objects by validated key plus SHA-256 digest. Identify
  generations by that object plus an exact positive decimal provider generation.
  ETag, md5Hash, and `latest` are not identity.
- Store advisory bodies and parsed documents in private object storage. PostgreSQL
  holds metadata only. Locators are compiled instance-owned prefixes; they never
  contain a provider key or tenant prefix.
- Keep parser attempts append-only. Each retry is a new attempt. Parser success
  does not activate a catalog.
- Use coarse catalog-generation lifecycle plus five orthogonal completeness
  dimensions. Matching completeness is `not_in_scope` in Session 11 and Session 12.
- Freeze exact integer reconciliation equations before `ready_for_activation`.
  Failed equations block activation. There is no waiver.
- Record quarantine as immutable evidence. Blocking quarantine prevents
  completeness and activation. Do not mutate historical evidence.
- Activate through a separate current-pointer row with version compare-and-swap
  in one PostgreSQL transaction. Do not reuse the KEV pointer. Activation does
  not match packages or write Findings.
- Object storage I/O stays outside PostgreSQL transactions. Attach metadata only
  after Head verification.

## Alternatives considered

- Copy the KEV single-snapshot model. Rejected: OSV has many objects and many
  generations.
- Store an `active` flag on every generation row as the sole pointer. Rejected:
  races and partial activation. KEV already uses a dedicated pointer.
- Collapse completeness into one boolean. Rejected: silent incompleteness.
- Relational affected-package tables in this foundation. Rejected until the
  ADR 0025 evaluator design exists.

## Consequences

Positive: Batch 5C can add Prisma models without redesigning identity, equations,
or activation. Evidence stays append-only and content-addressed.

Negative: Inventory observation cardinality is high. Storage/DB orphans remain
until a later reconciliation job. The parsed-document serializer is still a
parser-protocol follow-up.

## Security and tenancy

No `organizationId` or other tenant columns. No Finding, Component, Vulnerability,
or KEV-generation foreign keys. System audit, when added later, uses a null
organization. Provider keys must not appear in logs, metrics, or audit payloads.
Raw bodies must not appear in errors.

## Operational failure plan

Contracts describe recovery: restart a new inventory run after a crash; attach
only after Head; abort activation on CAS miss; never mark complete without rows.
No runtime exists in Batch 5B, so there is no operator job yet.

## Follow-up

- Accept this ADR before Batch 5C.
- Batch 5C: Prisma models and one forward-only migration.
- Batch 5D: PostgreSQL adapters and transactional activation.
- Batch 5E: object-storage adapter and prefix confirmation.
- Parser-document isolate serializer before attaching parsed revisions in sync.
- Keep `INTELLIGENCE_OSV_ENABLED=true` rejected.
