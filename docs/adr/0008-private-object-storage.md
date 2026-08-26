# ADR 0008: Private object storage for original SBOM evidence

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

Original SBOM bytes are evidence. They must not be replaced by a parsed graph. PostgreSQL is a poor store for large documents. Public buckets would leak Restricted data.

## Decision

Store original SBOM bytes in **private, S3-compatible object storage** behind a provider-neutral port. Local development may use **MinIO**. Keys include organization and SHA-256 digest:

`org/{organizationId}/assets/{assetId}/sboms/sha256/{sha256}`

Put/get occur **outside** DB transactions. No public-read ACL. Domain and handlers do not call storage SDKs directly. Production vendor is an operator choice ([OD-5](../architecture/open-decisions.md)).

## Alternatives considered

- **SBOM only in PostgreSQL bytea**: backup bloat, size limits.
- **Public CDN**: rejected.
- **Filesystem on the API container**: not multi-replica safe.

## Consequences

Backups must include the bucket and the database. Orphan objects possible; reconcile per [retention](../architecture/retention-and-deletion.md).

## Security and tenancy

Guessing a digest must not yield another organization's object. Get/put use the **stored** org-prefixed key from the **SBOM** row after an organization-scoped reload. Presigned public URLs need a future ADR.

## Operational failure plan

Storage 503: upload fails, no SBOM row. Storage up, DB down after put: orphan; grace-period reconcile.

## Follow-up

Adapter tests with MinIO in integration jobs when scaffolded.
