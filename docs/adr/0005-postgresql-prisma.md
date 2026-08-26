# ADR 0005: PostgreSQL and Prisma

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

The system of record must support transactions, constraints for org-scoped uniqueness, append-only audit, and outbox rows. Domain code must not import an ORM.

## Decision

Use **PostgreSQL** as the system of record and **Prisma** in `packages/database` only. Repositories/adapters implement domain ports. Opaque IDs are UUIDs. Timestamps are UTC. New migrations rather than editing applied migrations. Tenant rows include `organizationId`. No cascade-delete of evidentiary data.

## Alternatives considered

- **SQL without Prisma**: more boilerplate; easier accidental string SQL.
- **Another ORM**: extra churn.
- **Document DB as system of record**: weaker transactional outbox with relational invariants.

## Consequences

Operators provide PostgreSQL. Prisma generate/migrate is part of deploy. Domain remains ORM-free.

## Security and tenancy

Parameterized queries. Org predicates in every tenant query. Intelligence additive. Policy version stored with scores.

## Operational failure plan

DB outage: API unready. Restore from operator backups together with object storage. Prefer additive migrations for rollback safety.

## Follow-up

Schema implementation after ADR acceptance. Persistence tests clean up their data.
