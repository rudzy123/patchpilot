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
12. Session 11 Batch 5C-R is `20260904180000_osv_parsed_revision_id_check_correction`. It drops and recreates only `osv_parsed_advisory_revision_osv_id_chk` so PostgreSQL POSIX regex no longer uses `{0,511}`. Frozen SHA-256: `43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570`. The 512-character identifier grammar is preserved with `char_length` plus `^[A-Z0-9][A-Z0-9._+-]*$`. No Prisma schema change. No seed data.
13. Session 12 Batch 6 / 6-R OSV runtime coordination persistence is `20260907120000_osv_runtime_coordination_persistence`. Batch 6 creates Prisma models and this migration. Batch 6-R reviewed and hardened the uncommitted SQL before freeze. Frozen SHA-256: `7017b1c4b1d4bcae8bed4bdd0eb43559c0c89fce5b3636e0e889b276013cc3a6`. Do not edit it. Any SQL correction requires another forward-only migration. Session 12 Batch 7 implements PostgreSQL adapters against this frozen schema and does not add a migration. No seed rows. No tenant or Finding relation. Lease projection DELETE is forbidden so fencing tokens cannot reset. Digest columns are TEXT with exact lowercase SHA-256 CHECKs so CHAR/VARCHAR(64) trailing-space truncation cannot admit a padded value.
14. Session 13 Batch 2B OSV canary authorization persistence is `20260908120000_osv_canary_authorization_persistence`. It creates instance-owned `osv_canary_instance_operator_identity` and `osv_canary_authorization` only. Session 13 Batch 2B-R independently reviewed and hardened the uncommitted SQL before freeze. Frozen SHA-256: `321ac38a02090470aa5f09661cb0e29562327c16c9e341b44bc99516bd7fbd99`. Do not edit it. Any SQL correction requires another forward-only migration. No seed rows. No tenant, Finding, credential, holder-token, or page-token columns. Session 13 Batch 2C implements uncomposed PostgreSQL adapters against this frozen schema and does not add a migration. Session 13 Batch 2C-R independently reviewed those adapters. Session 13 Batch 2D implements the uncomposed one-shot command against those adapters and does not add a migration. Session 13 Batch 2D-R independently reviewed that command and does not add a migration. Session 13 Batch 2E implements uncomposed heartbeat and deadline controllers and does not add a migration. Session 13 Batch 2E-R independently reviewed those controllers and does not add a migration. Session 13 Batch 2F implements uncomposed executable preflight and read-only readiness inspection and does not add a migration. Bounded-body listing review requires a completed listing_only authorization whose consumed request and run match. Consume, revoke, and expire transitions use database time. Fifteen frozen migrations existed after Batch 2B freeze.
15. Session 13 Batch 3B-P / 3B-P-R listing-only provider-contact authorization persistence is `20260909120000_osv_listing_provider_contact_authorization_persistence`. It creates instance-owned `osv_canary_provider_free_preflight_attestation` and `osv_listing_provider_contact_authorization` only. Existing `osv_canary_authorization` is not reused. Session 13 Batch 3B-P-R independently reviewed and hardened the uncommitted SQL before freeze. Frozen SHA-256: `8e9a462e329733660b970adca64fcadce0431d65f342d15dbaecf08b91a80bbc`. Do not edit it. Any SQL correction requires another forward-only migration. No seed rows. No tenant, Finding, credential, holder-token, page-token, body, URL, or arbitrary JSON columns. Listing-only is the only representable phase. Body retrieval remains prohibited. Database time owns issuance, expiration, consumption, revocation, and terminalization. DELETE is forbidden. Consumption rechecks an active operator, a still-consumed source, current legal revalidation, and the bound preflight still attesting unauthorized provider contact. `issued_at` cannot precede preflight `captured_at`. Future preflight timestamps and future `consumed_at` are rejected. A consumed source cannot leave consumed while a child grant is outstanding. Schema existence does not issue or consume an authorization. No issuance or consumption adapter exists. Sixteen frozen migrations.
16. Do not edit Session 3, Session 5, Session 6, Session 7, Session 8, Session 9, Session 10, Session 11, Session 12 Batch 6, Session 13 Batch 2B, Session 13 Batch 3B-P, or the committed correction migration files. Those SQL files are the authoritative extras (checks, partial unique indexes, triggers). There is no separately applied `prisma/sql/*.sql` extras source.
17. There is no down migration. Rollback is restore-from-backup or a **forward-fix** migration.

## Paths

### Clean database

`pnpm db:migrate:deploy` on an empty database applies Session 3, Session 5, the Session 5 corrective migrations, Session 6 authentication persistence, Session 7 asset inventory constraints, Session 8 graph persistence, Session 9 KEV intelligence persistence, Session 10 canonical CVE identity, Session 11 OSV acquisition persistence, the Session 11 parsed-revision ID CHECK correction, Session 12 Batch 6 OSV runtime coordination persistence, Session 13 Batch 2B OSV canary authorization persistence, then Session 13 Batch 3B-P listing-only provider-contact authorization persistence. Isolated migration tests use that sixteen-migration sequence. The persistent development database has those sixteen frozen migrations, including `20260909120000_osv_listing_provider_contact_authorization_persistence`. The placeholder table exists only between Session 3 and Session 5.

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

A database that already has `20260901120000_kev_intelligence_persistence` applies `20260902120000_canonical_cve_identity`, `20260904120000_osv_acquisition_persistence_foundation`, `20260904180000_osv_parsed_revision_id_check_correction`, `20260907120000_osv_runtime_coordination_persistence`, `20260908120000_osv_canary_authorization_persistence`, then `20260909120000_osv_listing_provider_contact_authorization_persistence`. The Session 10 migration creates two global append-only identity tables. The Session 11 Batch 5C migration adds OSV acquisition tables only. Batch 5C-R replaces only the parsed OSV ID CHECK. Batch 6 adds OSV runtime coordination tables only. Batch 2B adds canary authorization tables only. Batch 3B-P adds provider-contact authorization tables only. None rewrite Vulnerability or Finding rows. No active OSV catalog is seeded. Isolated tests cover this path. Do not reset the database or delete Docker volumes.

### Upgrade from Session 10

A database that already has `20260902120000_canonical_cve_identity` applies `20260904120000_osv_acquisition_persistence_foundation`, `20260904180000_osv_parsed_revision_id_check_correction`, `20260907120000_osv_runtime_coordination_persistence`, `20260908120000_osv_canary_authorization_persistence`, then `20260909120000_osv_listing_provider_contact_authorization_persistence`. The Batch 5C migration adds global OSV acquisition tables and does not rewrite tenant, Finding, KEV, or canonical CVE identity rows. Batch 5C-R changes no data. Batch 6 adds runtime coordination tables only and seeds no rows. Batch 2B adds canary authorization tables only and seeds no operator identity or authorization. Batch 3B-P adds provider-contact authorization tables only and seeds no authorization. No active OSV catalog is seeded. Isolated tests cover this path. Do not reset the database or delete Docker volumes.

### Upgrade from Session 11 Batch 5C

A database that already has `20260904120000_osv_acquisition_persistence_foundation` applies `20260904180000_osv_parsed_revision_id_check_correction`, `20260907120000_osv_runtime_coordination_persistence`, `20260908120000_osv_canary_authorization_persistence`, then `20260909120000_osv_listing_provider_contact_authorization_persistence`. Batch 5C-R drops and recreates `osv_parsed_advisory_revision_osv_id_chk`. Batch 6 adds OSV runtime coordination tables only. Batch 2B adds canary authorization tables only. Batch 3B-P adds provider-contact authorization tables only. They do not rewrite existing rows. Isolated tests cover this path. Do not reset the database or delete Docker volumes.

### Upgrade from Session 11 Batch 5C-R

A database that already has `20260904180000_osv_parsed_revision_id_check_correction` applies `20260907120000_osv_runtime_coordination_persistence`, `20260908120000_osv_canary_authorization_persistence`, then `20260909120000_osv_listing_provider_contact_authorization_persistence`. Batch 6 adds OSV runtime coordination tables only. Batch 2B adds canary authorization tables only. Batch 3B-P adds provider-contact authorization tables only. They do not rewrite existing rows. Isolated tests cover this path. Do not reset the database or delete Docker volumes.

### Upgrade from Session 12 Batch 6

A database that already has `20260907120000_osv_runtime_coordination_persistence` applies `20260908120000_osv_canary_authorization_persistence` then `20260909120000_osv_listing_provider_contact_authorization_persistence`. Batch 2B adds instance-owned canary operator-identity and authorization tables only. Batch 3B-P adds instance-owned provider-free preflight attestation and listing-only provider-contact authorization tables only. They do not rewrite tenant, Finding, KEV, canonical CVE identity, OSV acquisition, or runtime-coordination rows. No operator identity or authorization is seeded. Isolated tests cover this path. Do not reset the database or delete Docker volumes.

### Upgrade from Session 13 Batch 2B

A database that already has `20260908120000_osv_canary_authorization_persistence` applies only `20260909120000_osv_listing_provider_contact_authorization_persistence`. That migration adds instance-owned provider-free preflight attestation and listing-only provider-contact authorization tables only. It does not rewrite tenant, Finding, KEV, canonical CVE identity, OSV acquisition, runtime-coordination, or canary-authorization rows. No provider-contact authorization is seeded. Isolated tests cover this path. Do not reset the database or delete Docker volumes.

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
