# Migrations

PatchPilot uses **forward-only** Prisma migrations against PostgreSQL.

## Policy

1. Never edit a migration that has been applied to shared environments.
2. The Session 3 migration `20260826120000_schema_foundation` is immutable.
3. Session 5 adds `20260827120000_tenant_model`, which creates product tables and drops `SchemaFoundation`.
4. Session 5 review corrections are `20260827140000_review_corrections`. `export_snapshot` evidence targeting is `20260827150000_evidence_export_snapshot_chk` because PostgreSQL must commit a new enum value before a CHECK may use it.
5. Organization risk-policy creators are `20260827160000_policy_creator_membership`.
6. Session 6 authentication persistence is two forward-only migrations: `20260827170000_audit_actor_anonymous` (adds `anonymous` to `audit_actor_type` only) and `20260827180000_local_credentials_and_sessions` (`LocalCredential`, `Session`, restored `actor_user_id`, replacement audit actor CHECK). Do not combine them: PostgreSQL cannot use a newly added enum label in a CHECK in the same transaction.
7. Session 7 asset inventory constraints are `20260828120000_asset_inventory_constraints`: the default Asset list keyset index (`asset_org_status_name_id_idx`), drop of redundant `asset_org_status_idx`, and `AssetExternalIdentifier` namespace/value CHECKs.
8. Session 8 graph persistence is `20260830120000_sbom_ingestion_graph_persistence`. It is frozen. Do not edit it. Any SQL correction requires another forward-only migration.
9. Session 9 KEV intelligence persistence is `20260901120000_kev_intelligence_persistence`. It is frozen. Do not edit it. Any SQL correction requires another forward-only migration.
10. Session 10 canonical CVE identity is `20260902120000_canonical_cve_identity`. Batch 3B applied it to the persistent development database (eleven finished migrations at that time) and froze it. Frozen SHA-256: `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`. Do not edit it. Any SQL correction requires another forward-only migration. Batch 4B adds persistence adapters only; it does not change this migration. The header comments inside that frozen `migration.sql` refer to the historical Batch 3A stage before independent review, persistent application, and freeze. Those comments must not be edited because their bytes are covered by the frozen SHA-256.
11. Session 11 OSV acquisition persistence foundation is `20260904120000_osv_acquisition_persistence_foundation`. Batch 5C creates Prisma models and this migration only. Frozen SHA-256: `ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349`. Do not edit it. Any SQL correction requires another forward-only migration. No repository adapter is included. No active OSV catalog is seeded.
12. Do not edit Session 3, Session 5, Session 6, Session 7, Session 8, Session 9, Session 10, Session 11, or the committed correction migration files. Those SQL files are the authoritative extras (checks, partial unique indexes, triggers). There is no separately applied `prisma/sql/*.sql` extras source.
13. There is no down migration. Rollback is restore-from-backup or a **forward-fix** migration.

## Paths

### Clean database

`pnpm db:migrate:deploy` on an empty database applies Session 3, Session 5, the Session 5 corrective migrations, Session 6 authentication persistence, Session 7 asset inventory constraints, Session 8 graph persistence, Session 9 KEV intelligence persistence, Session 10 canonical CVE identity, then Session 11 OSV acquisition persistence. Isolated migration tests use that twelve-migration sequence. The persistent development database has those twelve frozen migrations, including `20260904120000_osv_acquisition_persistence_foundation`. The placeholder table exists only between Session 3 and Session 5.

### Upgrade from Session 3

A database that already has `SchemaFoundation` applies `20260827120000_tenant_model` and every later committed migration. The Session 5 migration drops the placeholder. No product data existed in Session 3, so this is not a data-loss event for tenant evidence.

### Upgrade from Session 5

A database that already has `20260827120000_tenant_model` applies `20260827140000_review_corrections`, `20260827150000_evidence_export_snapshot_chk`, `20260827160000_policy_creator_membership`, `20260827170000_audit_actor_anonymous`, `20260827180000_local_credentials_and_sessions`, `20260828120000_asset_inventory_constraints`, `20260830120000_sbom_ingestion_graph_persistence`, `20260901120000_kev_intelligence_persistence`, and `20260902120000_canonical_cve_identity`. Do not reset the database or delete Docker volumes.

### Upgrade from Session 5 after policy-creator membership

A database that already has `20260827160000_policy_creator_membership` applies the two Session 6 authentication migrations, `20260828120000_asset_inventory_constraints`, `20260830120000_sbom_ingestion_graph_persistence`, `20260901120000_kev_intelligence_persistence`, and `20260902120000_canonical_cve_identity`. Existing tenant `user` audit rows receive `actor_user_id` from `membership` during that migration. The append-only trigger is disabled only for that backfill and is re-enabled before the migration completes. Runtime UPDATE/DELETE of `audit_event` remains forbidden.

### Upgrade from Session 6 (current main)

A database that already has `20260827180000_local_credentials_and_sessions` applies `20260828120000_asset_inventory_constraints`, `20260830120000_sbom_ingestion_graph_persistence`, `20260901120000_kev_intelligence_persistence`, and `20260902120000_canonical_cve_identity`. Do not reset the database or delete Docker volumes.

### Upgrade from Session 7

A database that already has `20260828120000_asset_inventory_constraints` applies `20260830120000_sbom_ingestion_graph_persistence`, `20260901120000_kev_intelligence_persistence`, then `20260902120000_canonical_cve_identity`. Existing completed ingestion rows without graph completeness evidence fail the Session 8 migration rather than receiving invented counts. Do not reset the database or delete Docker volumes.

### Upgrade from Session 8

A database that already has `20260830120000_sbom_ingestion_graph_persistence` applies `20260901120000_kev_intelligence_persistence` then `20260902120000_canonical_cve_identity`. The Session 9 migration adds KEV intelligence tables and additive `intelligence_source` columns. It does not rewrite Vulnerability or Finding rows. Do not reset the database or delete Docker volumes.

### Upgrade from Session 9

A database that already has `20260901120000_kev_intelligence_persistence` applies `20260902120000_canonical_cve_identity` then `20260904120000_osv_acquisition_persistence_foundation`. The Session 10 migration creates two global append-only identity tables. The Session 11 migration adds OSV acquisition tables only. Neither rewrites Vulnerability or Finding rows. No active OSV catalog is seeded. Isolated tests cover this path. Do not reset the database or delete Docker volumes.

### Upgrade from Session 10

A database that already has `20260902120000_canonical_cve_identity` applies only `20260904120000_osv_acquisition_persistence_foundation`. The migration adds global OSV acquisition tables and does not rewrite tenant, Finding, KEV, or canonical CVE identity rows. No active OSV catalog is seeded. Isolated tests cover this path. Do not reset the database or delete Docker volumes.

## Locks and transactions

Prisma apply runs in a transaction where PostgreSQL allows it. Creating many indexes and adding check constraints can take `AccessExclusiveLock` on new tables; on a clean or Session 3 database those tables are empty, so lock time is expected to be short. Do not run this migration against a busy product database that already has tenant traffic without an operations window.

## Data-loss assessment

- Drops `SchemaFoundation` only (technical scaffolding, unused by application code).
- Does not drop or rewrite later evidentiary tables (they are created here).
- Session 7 `20260828120000_asset_inventory_constraints` does not rewrite `asset` or `asset_external_identifier`. It creates an expression btree, drops redundant `asset_org_status_idx`, and adds CHECKs. Existing identifier rows that violate those CHECKs would fail the upgrade; v0.1 has no product identifier writes yet.
- Check constraints and triggers may reject writes that violate invariants; that is intentional, not silent data loss.

## Verification

```bash
pnpm db:validate
pnpm db:generate
pnpm db:migrate:deploy
pnpm test:integration
```

Integration tests cover clean apply, Session 3 upgrade, Session 5 upgrade, frozen migration checksums, Prisma-modeled objects, and named SQL-only extras. `prisma migrate diff` is not the sole drift check because Prisma cannot express those extras.

## Related documents

- [Database development](database.md)
- [Migration failure runbook](../runbooks/database-migration-failure.md)
