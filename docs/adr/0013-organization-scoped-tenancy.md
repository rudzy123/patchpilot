# ADR 0013: Organization-scoped multi-tenancy

- Status: Proposed
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

Self-hosted does not mean single-check security. Multiple organizations may exist on one instance. Looking up by resource id is not authorization.

## Decision

The **Organization** is the tenant boundary. Every tenant-owned operation uses **authorized organization** from session/membership, never a client-supplied id, GitHub field, or job payload alone. Repository ports require `organizationId`. Shared catalogs (OSV/KEV, builtin policies) are global; findings and SBOMs are tenant-owned. Components parsed from SBOMs are tenant-owned so private names are not globalized. No cross-organization operator bypass without a later ADR. Details: [tenant-isolation.md](../architecture/tenant-isolation.md).

## Alternatives considered

- **Single-org mode only**: insufficient if one instance hosts several teams.
- **Row-level security only in Postgres**: useful later, not a substitute for application predicates.
- **Instance admin can read all tenants**: rejected for the product API.

## Consequences

Users with multiple memberships select one org per request. Tests must prove A cannot read B.

## Security and tenancy

This ADR *is* the tenancy decision. Roles (`owner`, `admin`, `member`, `viewer`) are interim until a finer permission ADR ([OD-3](../architecture/open-decisions.md)).

## Operational failure plan

Mis-seeded org ids on jobs: dead-letter, no mutation. Backup restore does not add a bypass UI.

## Follow-up

Authn mechanism ADR (OD-1) before implementation. Isolation tests on first tenant APIs.
