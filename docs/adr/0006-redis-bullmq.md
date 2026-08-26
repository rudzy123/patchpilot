# ADR 0006: Redis and BullMQ

- Status: Proposed
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

Parse, correlate, enrich, and intel refresh are too heavy for the request path. We need a queue after a transactional outbox, with retries and dead letters.

## Decision

Use **Redis** and **BullMQ** as the job transport. Domain and use cases do not import BullMQ or Redis. Workers depend on queue adapters. Redis is not a second source of truth. Production Redis is authenticated and not browser-exposed. Sessions are **not** stored in Redis in the interim default ([OD-2](../architecture/open-decisions.md)).

## Alternatives considered

- **Postgres-only SKIP LOCKED queues**: viable; we still want BullMQ features (backoff, DLQ) familiar to the Node stack, fed by the outbox.
- **Kafka**: operationally heavier for self-hosted MVP.

## Consequences

Compose includes Redis. Worker lag is a primary metric. Redis loss delays processing; outbox retains unpublished work.

## Security and tenancy

Job payloads are untrusted for authorization. Process one org per job. Idempotency keys include organization. Do not put SBOM bytes on the queue.

## Operational failure plan

Redis down: relay retries; operators alert on outbox lag. Poison messages dead-letter. Replay is idempotent.

## Follow-up

Runbook per job type when implemented.
