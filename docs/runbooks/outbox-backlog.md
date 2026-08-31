# Runbook: outbox backlog

Use this when unpublished or unprocessed `outbox_event` rows accumulate. Architecture: [reliability model](../architecture/reliability-model.md), [ADR 0007](../adr/0007-transactional-outbox.md).

The worker relay is implemented: claim with `FOR UPDATE SKIP LOCKED`, publish to BullMQ, mark `processed`, then create or reuse a **BackgroundJob** row. A backlog therefore means the worker is down, Redis is unreachable, or events are dead-lettering.

## Relay behavior you can rely on

| Setting | Value |
| --- | --- |
| Poll interval | 1 s |
| Batch limit | 50 (clamped to 100) |
| Claim lease | 30 s |
| Max publish attempts | 5 |
| Backoff | `min(15 min, 5 s * 2^(attempt-1))` with jitter in `[0.5, 1.0)` |
| Queue / job name | `patchpilot` / `sbom.ingest` |
| BullMQ job id | `{eventType}__{outboxEventId}` |

Claiming takes due `pending` rows first, then fills the batch from `claimed` rows whose lease expired. Expired-lease recovery is part of the claim query, so there is no separate sweeper to restart.

## Symptoms

- Many rows with `status = 'pending'` and `processed_at` null.
- `available_at` in the past and rising.
- Rows in `claimed` with expired `lease_expires_at`.
- Rows in `dead_lettered`.
- `processed` rows with no matching `background_job`.

## Immediate actions

1. Count rows by `status` and `event_type`. Use organization UUIDs, not names, in tickets.
2. Confirm the worker process is alive and that Redis is reachable from it.
3. Do not publish payloads containing Restricted data. Payloads are ids and safe metadata only, and must stay that way.
4. Do not run queue processors against another organization's events.

## Classify

| Class | Evidence | Notes |
| --- | --- | --- |
| Worker down | Everything `pending`, `attempt_count` not increasing | PostgreSQL is the source of truth; nothing is lost |
| Redis unreachable | `attempt_count` climbing, rows returning to `pending` with backed-off `available_at` | Relay marks `queue_unavailable` and retries |
| Poison event | `status = 'dead_lettered'`, bounded `last_failure_code` | Unknown `event_type` or attempts exhausted |
| Relay crash mid-batch | Rows stuck `claimed` with expired lease | Reclaimed automatically on the next claim query |
| Publish/commit gap | `processed` rows with no `background_job` | Reconciled automatically at the end of each batch |
| Duplicate delivery | Same job id delivered twice | At-least-once; handlers are idempotent |

Two enum values are never written by the relay: outbox `failed` and BackgroundJob `dead_lettered`. Do not build alerts on them.

## Recovery

### Pending backlog

Restore Redis or the worker. The relay drains at up to 50 events per second-long poll. Do not hand-edit rows to `processed`; that discards work with no record of what was dropped.

### Dead-lettered events

Read `last_failure_code` first. An unknown `event_type` means a code or migration mismatch, and republishing before fixing that just re-dead-letters. After the fix, move the row back to `pending` with `available_at` set to now and `attempt_count` reset.

### Stuck claimed rows

Wait one poll cycle after the 30-second lease expires. If rows stay `claimed` with an expired lease, the relay is not running.

### Processed without a BackgroundJob

Wait one batch. If the row persists, the relay is not running or the event type is unmapped. Note that reconciliation creates the PostgreSQL row only; it does **not** republish to BullMQ. If BullMQ never actually received the job, the resulting BackgroundJob sits in `queued` and needs a replay ([background job failure](background-job-failure.md)).

## Verification

- Pending count trends down and `attempt_count` stops climbing.
- No `claimed` rows with expired leases persist across poll cycles.
- Every `processed` row has a `background_job` row.
- No cross-organization payload ids were mixed into a tenant job.

## Delivery semantics

Delivery is **at-least-once**. PatchPilot does not claim exactly-once processing. Duplicate delivery is made safe by the deterministic job id, the unique constraint on `background_job.outbox_event_id`, and idempotent handlers.
