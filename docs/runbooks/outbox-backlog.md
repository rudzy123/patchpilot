# Runbook: outbox backlog

Use this when unpublished or unprocessed `outbox_event` rows accumulate. Architecture: [reliability model](../architecture/reliability-model.md), [ADR 0007](../adr/0007-transactional-outbox.md).

Session 5 persists outbox rows. The worker relay is **not** implemented yet. A backlog with no relay is expected until that milestone.

## Symptoms

- Many rows with `status = pending` and `processed_at` null.
- `available_at` in the past.
- Claimed rows with expired `lease_expires_at`.

## Immediate actions

1. Identify counts by `status` and `event_type`. Use organization UUIDs, not names, in tickets.
2. Do not publish payloads that contain Restricted data; payloads must be ids and safe metadata only.
3. Do not run queue processors against another organization's events.

## Classify

| Class | Notes |
| --- | --- |
| Relay not deployed | Expected before the worker outbox relay exists |
| Relay crash | Rows remain `pending`; PostgreSQL is source of truth |
| Poison payload | Bound `last_failure_code`; do not retry infinitely |
| Duplicate delivery | At-least-once; handlers must be idempotent |

## Recovery

Until the relay exists, do not manually mark rows `processed` unless an operator is discarding work that will be rebuilt. After the relay exists, follow [background job failure](background-job-failure.md).

## Verification

- Pending count explained (no relay vs stuck relay).
- No cross-organization payload ids mixed into a tenant job.

## Delivery semantics

Delivery is **at-least-once**. PatchPilot does not claim exactly-once processing.
