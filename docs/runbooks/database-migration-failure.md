# Runbook: database migration failure

Use this when `pnpm db:migrate:deploy` or a hosted migrate job fails. Architecture: [migrations](../development/migrations.md), [database model](../architecture/database-model.md).

Do not edit an already-applied migration. Do not restore by rewriting `_prisma_migrations` checksums.

## Symptoms

- Migrate deploy exits non-zero.
- `_prisma_migrations` shows a failed or rolled-back row.
- Application cannot start because expected tables are missing.

## Immediate actions

1. Capture the migration name, PostgreSQL error code, and UTC time. **Do not** log `DATABASE_URL`.
2. Confirm you are not pointed at production unless this is a planned production migrate.
3. Do not run `pnpm db:reset` against an unverified URL.

## Classify

| Class | Likely cause |
| --- | --- |
| SQL syntax / constraint | Forward-fix migration required |
| Lock timeout | Concurrent DDL or long transactions; retry in a window |
| Session 3 missing | Deployed Session 5 without Session 3 history; restore a consistent backup or apply from empty with both files |
| Shadow/P1003 | Local diff tooling; not a production apply failure |

## Recovery

1. If the transaction rolled back, the database should still match the previous migration. Retry only after the root cause is fixed.
2. If a partial apply occurred outside a transaction, restore from backup and re-apply.
3. Ship a new forward migration; never edit `20260826120000_schema_foundation` or an applied Session 5 file.

## Verification

- `pnpm db:migrate:deploy` succeeds.
- `SchemaFoundation` is absent after Session 5.
- `pnpm test:integration` migration cases pass.

## Escalation

Treat unexpected table drops as an [audit integrity](audit-integrity-failure.md) incident if evidence tables were affected.
