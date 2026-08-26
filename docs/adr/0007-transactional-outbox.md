# ADR 0007: Transactional outbox

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

Durable work must not be published to Redis inside the same database transaction as the state change (network I/O in transactions is forbidden). At-least-once delivery is assumed.

## Decision

Every mutation that needs background work writes an **OutboxEvent** in the **same PostgreSQL transaction** as the state change. A relay publishes to BullMQ and marks `publishedAt`. Relays and handlers are **idempotent**. Tenant `dedupeKey` values include `organizationId`. No parser, feed HTTP, queue publish, or object-storage I/O inside that transaction (including worker correlate/enrich stages).

## Alternatives considered

- **Publish to Redis in-request after commit**: race if process crashes after commit before publish; outbox is safer.
- **Dual write without outbox**: lost jobs.

## Consequences

Slight delay until relay. Outbox table growth needs operational monitoring. Dual-write orphans possible if object storage succeeded and DB failed (SBOM path stores first, then transaction).

## Security and tenancy

Payloads carry ids, not Restricted raw SBOMs. Handlers reload org from persistence.

## Operational failure plan

Relay crash: events remain unpublished. Duplicate publish: handler idempotency. Poison: dead-letter, not infinite retry.

## Follow-up

Relay implementation in worker. Replay tests required.
