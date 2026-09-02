# Database model

This is the Session 5–10 persistence design for PatchPilot. It implements the v0.1 [domain model](domain-model.md) in PostgreSQL through Prisma in `packages/database`. Session 8 Batch 4 adds graph-completeness columns, nullable Component `ecosystem`, occurrence `version_known`, insert-once graph persistence, outbox claim/execution adapters, and SQL-only CHECKs. Session 9 Batch 4C adds instance-owned KEV intelligence tables, generation-scoped entries, and PostgreSQL-only sync-run adapters. Session 10 Batch 3B applied and froze global `cve_identity` and `vulnerability_cve_identity` tables (`20260902120000_canonical_cve_identity`, SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). The persistent development database has eleven finished migrations. Persistence adapters and active-KEV derivation are **not** implemented. `SbomIngestion.leaseExpiresAt` remains **unused** in Session 8. Provider HTTP, snapshot object-storage runtime, KEV parsing, workers, and upload HTTP routes for intelligence are **not** implemented here.

Opaque IDs are UUIDs (`gen_random_uuid()`). Timestamps are `TIMESTAMPTZ` stored in UTC. Prisma lives only in `packages/database`. Domain ports in `packages/domain` do not import Prisma types.

## Global versus tenant-owned

| Global / shared catalog | Tenant-owned |
| --- | --- |
| `vulnerability` | `organization`, `membership`, `team`, `team_membership` |
| `vulnerability_alias` | `environment`, `asset`, `asset_owner`, `asset_tag` |
| `vulnerability_source_record` | `repository_connection`, `sbom`, `sbom_ingestion` |
| Built-in `risk_policy` (`scope = builtin`, `organization_id` null) | `component`, `component_occurrence`, `dependency_relationship` |
| `integration_provider` | `finding`, `finding_observation`, org `risk_policy` (`scope = organization`) |
| `intelligence_source` (OSV / CISA KEV sync state and active KEV pointer) | `risk_calculation`, `remediation_task`, `risk_acceptance` |
| `vulnerability_sync_run`, `vulnerability_provider_snapshot`, `kev_generation`, `kev_entry`, `kev_entry_cwe` | `evidence`, tenant `audit_event` |
| `cve_identity`, `vulnerability_cve_identity` | `integration` (`organization_id` required), `external_credential` |
| | tenant `outbox_event`, `background_job` (when org set), `idempotency_record` |

`user` is instance-level. Access to tenant data is via `membership`. Listing users is still scoped by membership in a later API session. `local_credential` and `session` are instance-level. `session.active_organization_id` is a selector only.

A global `vulnerability` may be referenced by findings in many organizations. Tenant queries always include `organization_id` from the authorized organization argument. Repository methods do not trust that argument as authentication; they enforce scope.

## Repository method rules

Tenant-owned ports require `organizationId` as a required argument (`findById(organizationId, id)`). There is no `findById(id)` for tenant aggregates. Global intelligence tables may be read without an organization id. Authentication ports (`UserRepository`, `LocalCredentialRepository`, `SessionRepository`, and the membership auth-boundary queries) are instance-level: they take the authenticated user id or a token digest, never a client-supplied organization as authority.

Adapters always add `WHERE organization_id = $organizationId` (or `id = $organizationId` for the organization row itself). Pagination is keyset by `id`, bounded to 1–100 rows (default 20), except the Session 7 Asset list, which is keyset on `(lower(name), id)` with default `lifecycle_status = active`, and the Session 8 SBOM list, which is keyset on `(received_at DESC, id DESC)`. The Asset list index is SQL-only (`asset_org_status_name_id_idx`); Prisma cannot express `lower(name)`. Mutable Asset aggregates use application compare-and-set on `organization_id`, `id`, `version`, and active lifecycle. Asynchronous `lastSuccessfulSbomIngestionId` pointer updates **do not** increment `Asset.version`: that column remains user compare-and-set concurrency for scalar and collection edits. Pointer fields are system-maintained observation metadata and are not part of `NormalizedUpdateAssetCommand`.

## Compound foreign keys

Related tenant rows must share an organization. Prisma unique `(organization_id, id)` keys on parents enable compound FKs, including:

- Team membership → team and membership in the same org
- Asset → environment and owning team in the same org
- Asset owner → asset, optional membership, optional team in the same org
- Repository connection → asset and optional tenant integration
- SBOM / ingestion / occurrence / dependency / finding / observation / calculation / task / acceptance / evidence → parents in the same org
- Ingestion → the same asset as its SBOM
- Occurrence → the same SBOM as its ingestion and the same asset as that SBOM
- Finding occurrence pointer → the same asset and component as the occurrence
- Dependency endpoints → occurrences from the same ingestion
- Asset `last_successful_sbom_ingestion_id` → an ingestion for that same asset
- Tenant user actions (assignee, uploader, acceptance actors, evidence submitter, tenant audit actor) → `membership` in the same organization

Built-in risk policies use `scope = builtin` and `organization_id` null. Organization policies use `scope = organization` and a non-null `organization_id`. A check constraint ties those two columns. A trigger rejects a `risk_calculation` whose policy belongs to a different organization. Published policies cannot be deleted; identity and definition cannot change after `published_at` is set. The only allowed published-status change is `published` → `retired`.

OSV and CISA KEV synchronization is `intelligence_source`, not a tenant `integration`. Session 9 KEV catalog rows are instance-owned and have no `organization_id`. They do not reference `vulnerability`, `finding`, `component`, or `sbom`. Session 10 canonical CVE identity tables are also instance-owned and have no `organization_id`. They do not reference KEV, Finding, Component, Asset, or SBOM rows. Reader-visible current KEV membership is `intelligence_source.active_generation_id` pointing at a generation whose `state` is `active`. Future membership derivation compares `cve_identity.cve` to active `kev_entry.normalized_cve`; that read is not implemented in Batch 3B. `BackgroundJob` remains the execution lease; `vulnerability_sync_run.version` is compare-and-set only. System `outbox_event` and `audit_event` rows may use `organization_id` null. `integration.organization_id` is required. Tenant credentials attach only to an organization-owned `integration`. `last_failure_code` and `last_failure_at` are sticky historical metadata: a later successful activation or `not_modified` advances `last_successful_sync_at` and `last_attempt_at` and does not clear the previous safe failure fields.

## Identifiers, time, and concurrency

- Primary keys are UUID.
- `created_at` / `updated_at` use `timestamptz(6)`.
- Append-only tables omit `updated_at`.
- Mutable aggregate roots store `version` (integer ≥ 1) for optimistic concurrency. Asset inventory compare-and-set is implemented in `packages/database`; other aggregates remain deferred.

## JSON documents

JSON is allowed only where the field is versioned and not the primary query key. Every documented JSON object must include `schemaVersion`.

| Field | Purpose | Versioning |
| --- | --- | --- |
| `risk_policy.definition` | Published factor catalog and weights | `schemaVersion`; published rows immutable |
| `risk_calculation.factors` / `result` | Reproducible factor snapshot and stored priority | `schemaVersion` |
| `audit_event.payload` | Redacted metadata | `schemaVersion` plus `audit_event.schema_version` |
| `outbox_event.payload` | Opaque ids and safe metadata | `event_schema_version` and payload `schemaVersion` |
| `evidence.metadata` | Extensible non-secret metadata | `schemaVersion` |
| `vulnerability_source_record.normalized` | Immutable normalized source revision | uniqueness includes `normalization_version`; `schemaVersion` in JSON |
| `finding_observation.evidence` | Safe compare metadata | `schemaVersion` |
| `integration.config` / `intelligence_source.config` | Non-secret endpoints/intervals | `schemaVersion` |
| `idempotency_record.response` | Bounded response metadata | `schemaVersion` |

Do not store raw SBOM bytes, provider payloads, tokens, or source code in JSON.

## Deletion

Foreign keys use `ON DELETE RESTRICT`. Evidentiary tables are not cascade-deleted. Organization archive is a status change. v0.1 has no product hard-delete of evidence. Append-only triggers reject `UPDATE`/`DELETE` on `audit_event`, `finding_observation`, `risk_calculation`, `vulnerability_source_record`, `evidence`, `vulnerability_provider_snapshot`, `kev_entry`, `kev_entry_cwe`, `cve_identity`, and `vulnerability_cve_identity`.

## SchemaFoundation

Session 3 created a technical `SchemaFoundation` table. Migration `20260827120000_tenant_model` drops it. Later forward-only corrections are `20260827140000_review_corrections`, `20260827150000_evidence_export_snapshot_chk`, and `20260827160000_policy_creator_membership`. Session 6 authentication persistence is `20260827170000_audit_actor_anonymous` plus `20260827180000_local_credentials_and_sessions`. Session 7 asset inventory extras are `20260828120000_asset_inventory_constraints`. Session 8 graph persistence extras are `20260830120000_sbom_ingestion_graph_persistence`. Session 9 KEV intelligence extras are `20260901120000_kev_intelligence_persistence` and are **frozen**. Session 10 canonical CVE identity is `20260902120000_canonical_cve_identity` and is **frozen** (SHA-256 `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`). It has been applied to the persistent development database. Committed `migration.sql` files are authoritative, including SQL extras Prisma cannot express. Duplicate `prisma/sql` extras files are not applied independently and are not kept. Frozen Session 3 through Session 10 migration files are unchanged. Any SQL correction after freeze requires another forward-only migration.

## Row-Level Security

RLS is **not** enabled. Application predicates and compound FKs are the v0.1 control ([ADR 0013](../adr/0013-organization-scoped-tenancy.md)). RLS remains a future defense-in-depth option.

## Check constraints (SQL extras)

Prisma cannot express every invariant. Those extras are defined only in committed `migration.sql` files. Migrations `20260827120000_tenant_model`, `20260827140000_review_corrections`, `20260827150000_evidence_export_snapshot_chk`, `20260827160000_policy_creator_membership`, `20260827180000_local_credentials_and_sessions`, `20260828120000_asset_inventory_constraints`, `20260830120000_sbom_ingestion_graph_persistence`, `20260901120000_kev_intelligence_persistence`, and `20260902120000_canonical_cve_identity` add named checks, including:

| Constraint | Invariant |
| --- | --- |
| `organization_slug_shape_chk` / `team_slug_shape_chk` / `environment_slug_shape_chk` | Lowercase `^[a-z0-9]+(-[a-z0-9]+)*$` |
| `sbom_sha256_chk` / evidence and intel SHA checks | 64 lowercase hex characters |
| `sbom_byte_length_chk` | Positive byte size |
| `dependency_relationship_not_self_chk` | Source ≠ target occurrence |
| `risk_policy_scope_ownership_chk` | `builtin` requires null org; `organization` requires a non-null org |
| `risk_policy_status_timestamps_chk` | Draft/published/retired timestamps stay consistent |
| `risk_policy_creator_scope_chk` | Built-ins have no membership creator; org policies may |
| `risk_acceptance_expiration_chk` | `expires_at > starts_at` |
| `risk_acceptance_approval_chk` / `*_active_approval_chk` / `*_revocation_chk` | Approver/timestamp and revocation fields stay consistent |
| `outbox_event_attempt_chk` / `*_lease_chk` / `*_processed_ts_chk` | Nonnegative attempts; lease and processed timestamps match status |
| `evidence_one_target_chk` | Exactly one supported target; `export_snapshot` is the only asset-targeted kind |
| `asset_owner_target_chk` | Exactly one of `user_id` or `team_id` |
| `asset_external_identifier_namespace_shape_chk` | Stored lowercase, length 1–64, `^[a-z0-9]+(-[a-z0-9]+)*$` (same shape as tags) |
| `asset_external_identifier_value_chk` | Character length 1–256; reject NUL, C0, DEL, and C1 (`[\x00-\x1F\x7F-\x9F]`). PostgreSQL `text` cannot store NUL; the class documents the floor. Application NFC/`\p{Cc}` validation is stricter. |
| `audit_event_actor_scope_chk` | Anonymous, instance user, tenant user, system, and instance_operator combinations from [audit-model.md](audit-model.md) |
| `local_credential_phc_chk` / `*_revision_chk` / `*_algorithm_chk` | Argon2id PHC prefix and length; revision ≥ 1; algorithm `argon2id` |
| `session_*_chk` | Lowercase hex digests, timestamp order, revoke pair consistency, `password` method |
| `intelligence_source_provider_chk` | Global sync rows are `osv` or `cisa_kev` only |
| `*_version_chk` | Optimistic concurrency version ≥ 1 |
| Archive / completed / failure-code timestamp consistency | Status and timestamps agree |
| `sbom_ingestion_*_chk` / `component_occurrence_version_known_chk` / `component_ecosystem_null_or_nonempty_chk` | Session 8 graph completeness, counts, labels, known/unknown versions, nullable ecosystem |
| `idempotency_record_status_response_chk` | Generic started/completed/conflict response matrix; not SBOM-specific |
| `cve_identity_cve_chk` | Exact canonical `^CVE-[0-9]{4}-[0-9]{4,19}$`; no trim, case-fold, or CITEXT. `vulnerability.cve_id` has no CHECK |

Partial unique indexes cover active asset names per organization, builtin vs org risk-policy versions, NULL-safe asset-owner identity, non-null SBOM ingestion idempotency keys, one active risk acceptance per finding, outbox/audit replay keys, and available outbox work. Ingestion uniqueness is **not** `(sbom_id, parser_version)`: retries keep history via `attempt_number`, and a newer parser may reprocess the same SBOM.

## Indexes

Every index maps to a documented access or uniqueness need: organization slug; membership by org+user and active memberships; team/environment lookup; assets by org+lifecycle+`lower(name)`+id (SQL-only `asset_org_status_name_id_idx`; supersedes `asset_org_status_idx`), owning team, environment, and last observation; active-name uniqueness (`asset_active_name_org_idx`); SBOMs by asset+received time and org+asset+hash; ingestion by state and current-ingestion keyset (`sbom_ingestion_org_sbom_created_idx`); component identity; occurrences by SBOM, component, and non-null bom-ref (`component_occurrence_org_ingestion_bom_ref_uidx`); dependency traversal; vulnerability OSV/CVE/aliases and source provenance; findings by org/status/asset/vulnerability/assignee/due; observations by finding+time; policies by org+status; calculations by finding+time; tasks by assignee/status/due; expiring acceptances; audit by org+time and target; outbox pending work and claimed-lease reclaim (`outbox_event_claimed_lease_idx`); job lease and outbox-event uniqueness (`background_job_outbox_event_uidx`); idempotency lookup and expiry; session token/CSRF digests, user, idle/absolute cleanup (worker deferred), and optional active organization. Do not add Prisma `@@index` rows for expression indexes; they stay in `migration.sql`. The broader `background_job_outbox_idx` is retained because the new unique index was not proven to cover every existing lookup, including null `outbox_event_id` rows.

## Append-only enforcement

`BEFORE UPDATE OR DELETE` triggers reject mutation of `audit_event`, `finding_observation`, `risk_calculation`, `vulnerability_source_record`, `evidence`, `cve_identity`, and `vulnerability_cve_identity`. A BEFORE INSERT trigger `patchpilot_audit_actor_membership_user` enforces that tenant audit actors match Membership user and organization. Published `risk_policy` rows cannot change identity or definition; they cannot be deleted; they may only move `published` → `retired`. Trigger functions set `search_path = pg_catalog, public` so they do not inherit the caller search path. These controls do not prevent a superuser from rewriting history.

## Limitations

Triggers and revoked DML are not WORM storage. Superusers can still rewrite history. Hash chaining is not implemented; this database does not claim non-repudiation.

Organization `slug` uniqueness does not reserve product route names (`api`, `health`, `login`, and similar). Do not treat the current unique index as URL-routing protection. Reserved slugs stay deferred until URL routing is implemented.

[ADR 0019](../adr/0019-local-password-sessions.md) `LocalCredential` and `Session` tables, restored `actor_user_id`, and `anonymous` audit actors are in `20260827170000_audit_actor_anonymous` plus `20260827180000_local_credentials_and_sessions`. Session 5 migrations stay frozen. Session 8 graph persistence is `20260830120000_sbom_ingestion_graph_persistence` and is **frozen**; do not edit it — any SQL correction requires another forward-only migration. Session 9 KEV intelligence persistence is `20260901120000_kev_intelligence_persistence` and is **frozen**; do not edit it — any SQL correction requires another forward-only migration. Session 10 canonical CVE identity is `20260902120000_canonical_cve_identity` and is **frozen**; do not edit it — any SQL correction requires another forward-only migration. Frozen SHA-256: `2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba`. The persistent development database has eleven finished migrations.

## Related documents

- [Tenant isolation](tenant-isolation.md)
- [Migrations](../development/migrations.md)
- [Database development](../development/database.md)
