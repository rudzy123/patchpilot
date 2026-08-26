# ADR 0014: Append-only audit events

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

Reviewers need to see what was known, who decided, and which policy produced a score. Updating audit rows in place would destroy that property.

## Decision

Persist **AuditEvent** rows that are **insert-only**. No UPDATE or DELETE in v0.1. No cascade-delete of evidentiary data to satisfy FKs. Emit events for membership, SBOM upload/replace/reprocess, intelligence import, priority calculation, assignment, remediation, risk acceptance, compensating controls, exports, credential lifecycle, integration state, and (future) webhook acceptance. Payloads are redacted. Tenant events always include `organizationId`. Catalog: [audit-model.md](../architecture/audit-model.md).

## Alternatives considered

- **Log files as the audit trail**: not queryable per org, weaker integrity.
- **Mutable "last event" row**: rejected.

## Consequences

Audit volume grows. Retention cannot erase audit in v0.1. Corrections are new events.

## Security and tenancy

Org-scoped queries. Credential plaintext never in payload. DB role should deny UPDATE/DELETE on the table when practical.

## Operational failure plan

Failed audit insert fails the transaction (for DB-only mutations). Storage-first SBOM orphans do not invent a fake successful upload audit.

## Follow-up

Tests that UPDATE is rejected. Indexes for org + time.
