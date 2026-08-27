# Runbook: database constraint failure

Use this when inserts or updates fail with check, unique, or foreign-key errors after Session 5. Schema: [database model](../architecture/database-model.md).

Do not weaken constraints to make a client succeed. Do not disable append-only triggers.

## Symptoms

- PostgreSQL `check_violation` / `unique_violation` / `restrict_violation`.
- Prisma `P2002` (unique) or `P2003` (FK).
- Application logs a validation-like database error without a connection string.

## Immediate actions

1. Record constraint name, table, organization id (UUID), and UTC time.
2. Inspect the **intended** invariant (tenant scope, SHA-256 shape, expiration order, append-only).
3. Do not `UPDATE` audit or calculation rows to "fix" them.

## Classify

| Constraint family | Meaning |
| --- | --- |
| Slug/SHA/byte-size checks | Caller sent malformed identity or evidence metadata |
| Compound FK | Cross-organization linkage attempted |
| Append-only trigger | Illegal mutation of history |
| Risk acceptance expiration/approval | Incomplete or unordered decision |
| Outbox lease/processed checks | Invalid job state combination |

## Recovery

1. Correct the application write path or the input.
2. If production data was written before a constraint existed, ship a forward-fix after an explicit data review. Session 5 has no such legacy tenant data.

## Verification

- Re-run the failing write with a legal payload.
- Integration tests in `packages/database` cover the constraint families.

## Escalation

Cross-organization FK failures that succeeded would be a [tenant isolation incident](tenant-isolation-incident.md). Constraint **rejection** is the control working.
