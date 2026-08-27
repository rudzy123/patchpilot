# Migrations

PatchPilot uses **forward-only** Prisma migrations against PostgreSQL.

## Policy

1. Never edit a migration that has been applied to shared environments.
2. The Session 3 migration `20260826120000_schema_foundation` is immutable.
3. Session 5 adds `20260827120000_tenant_model`, which creates product tables and drops `SchemaFoundation`.
4. Session 5 review corrections are `20260827140000_review_corrections`. `export_snapshot` evidence targeting is `20260827150000_evidence_export_snapshot_chk` because PostgreSQL must commit a new enum value before a CHECK may use it. Do not edit the earlier Session 3 or Session 5 files.
5. There is no down migration. Rollback is restore-from-backup or a **forward-fix** migration.

## Paths

### Clean database

`pnpm db:migrate:deploy` on an empty database applies Session 3, Session 5, then the review-correction migration. The placeholder table exists only between Session 3 and Session 5.

### Upgrade from Session 3

A database that already has `SchemaFoundation` applies `20260827120000_tenant_model`, then `20260827140000_review_corrections`, then `20260827150000_evidence_export_snapshot_chk`. The first of those drops the placeholder. No product data existed in Session 3, so this is not a data-loss event for tenant evidence.

## Locks and transactions

Prisma apply runs in a transaction where PostgreSQL allows it. Creating many indexes and adding check constraints can take `AccessExclusiveLock` on new tables; on a clean or Session 3 database those tables are empty, so lock time is expected to be short. Do not run this migration against a busy product database that already has tenant traffic without an operations window.

## Data-loss assessment

- Drops `SchemaFoundation` only (technical scaffolding, unused by application code).
- Does not drop or rewrite later evidentiary tables (they are created here).
- Check constraints and triggers may reject writes that violate invariants; that is intentional, not silent data loss.

## Verification

```bash
pnpm db:validate
pnpm db:generate
pnpm db:migrate:deploy
pnpm test:integration
```

Integration tests cover clean apply and Session 3 upgrade.

## Related documents

- [Database development](database.md)
- [Migration failure runbook](../runbooks/database-migration-failure.md)
