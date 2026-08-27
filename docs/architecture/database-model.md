# Database model

This is the Session 5 persistence design for PatchPilot. It implements the v0.1 [domain model](domain-model.md) in PostgreSQL through Prisma in `packages/database`. Product APIs, parsers, and scoring are **not** implemented here.

Opaque IDs are UUIDs (`gen_random_uuid()`). Timestamps are `TIMESTAMPTZ` stored in UTC. Prisma lives only in `packages/database`. Domain ports in `packages/domain` do not import Prisma types.

## Global versus tenant-owned

| Global / shared catalog | Tenant-owned |
| --- | --- |
| `vulnerability` | `organization`, `membership`, `team`, `team_membership` |
| `vulnerability_alias` | `environment`, `asset`, `asset_owner`, `asset_tag` |
| `vulnerability_source_record` | `repository_connection`, `sbom`, `sbom_ingestion` |
| Built-in `risk_policy` (`organization_id` null) | `component`, `component_occurrence`, `dependency_relationship` |
| System `integration` (`organization_id` null) | `finding`, `finding_observation`, org `risk_policy` |
| | `risk_calculation`, `remediation_task`, `risk_acceptance` |
| | `evidence`, tenant `audit_event`, tenant `integration` |
| | `external_credential`, tenant `outbox_event` |
| | `background_job` (when org set), `idempotency_record` |

`user` is instance-level. Access to tenant data is via `membership`. Listing users is still scoped by membership in a later API session.

A global `vulnerability` may be referenced by findings in many organizations. Tenant queries always include `organization_id` from the authorized organization argument. Repository methods do not trust that argument as authentication; they enforce scope.

## Repository method rules

Tenant-owned ports require `organizationId` as a required argument (`findById(organizationId, id)`). There is no `findById(id)` for tenant aggregates. Global intelligence tables may be read without an organization id.

Adapters always add `WHERE organization_id = $organizationId` (or `id = $organizationId` for the organization row itself). Pagination is keyset by `id`, bounded to 1–100 rows (default 20).

## Compound foreign keys

Related tenant rows must share an organization. Prisma unique `(organization_id, id)` keys on parents enable compound FKs, including:

- Team membership → team and membership in the same org
- Asset → environment and owning team in the same org
- Asset owner → asset, optional membership, optional team in the same org
- Repository connection → asset and optional tenant integration
- SBOM / ingestion / occurrence / dependency / finding / observation / calculation / task / acceptance / evidence → parents in the same org

Built-in risk policies and system integrations have null `organization_id`. A trigger rejects a `risk_calculation` whose policy belongs to a different organization. Tenant credentials cannot attach to system integrations because the compound FK requires a non-null matching org.

## Identifiers, time, and concurrency

- Primary keys are UUID.
- `created_at` / `updated_at` use `timestamptz(6)`.
- Append-only tables omit `updated_at`.
- Mutable aggregate roots store `version` (integer ≥ 1) for later optimistic concurrency. Application compare-and-set is deferred.

## JSON documents

JSON is allowed only where the field is versioned and not the primary query key. Every documented JSON object must include `schemaVersion`.

| Field | Purpose | Versioning |
| --- | --- | --- |
| `risk_policy.definition` | Published factor catalog and weights | `schemaVersion`; published rows immutable |
| `risk_calculation.factors` / `result` | Reproducible factor snapshot and stored priority | `schemaVersion` |
| `audit_event.payload` | Redacted metadata | `schemaVersion` plus `audit_event.schema_version` |
| `outbox_event.payload` | Opaque ids and safe metadata | `event_schema_version` and payload `schemaVersion` |
| `evidence.metadata` | Extensible non-secret metadata | `schemaVersion` |
| `vulnerability_source_record.normalized` | Provider-normalized subset | `normalization_version` plus `schemaVersion` |
| `finding_observation.evidence` | Safe compare metadata | `schemaVersion` |
| `integration.config` | Non-secret endpoints/intervals | `schemaVersion` |
| `idempotency_record.response` | Bounded response metadata | `schemaVersion` |

Do not store raw SBOM bytes, provider payloads, tokens, or source code in JSON.

## Deletion

Foreign keys use `ON DELETE RESTRICT`. Evidentiary tables are not cascade-deleted. Organization archive is a status change. v0.1 has no product hard-delete of evidence. Append-only triggers reject `UPDATE`/`DELETE` on `audit_event`, `finding_observation`, `risk_calculation`, `vulnerability_source_record`, and `evidence`.

## SchemaFoundation

Session 3 created a technical `SchemaFoundation` table. Migration `20260827120000_tenant_model` drops it. The Session 3 migration file is unchanged.

## Row-Level Security

RLS is **not** enabled. Application predicates and compound FKs are the v0.1 control ([ADR 0013](../adr/0013-organization-scoped-tenancy.md)). RLS remains a future defense-in-depth option.

## Check constraints (SQL extras)

Prisma cannot express every invariant. Migration `20260827120000_tenant_model` adds named checks, including:

| Constraint | Invariant |
| --- | --- |
| `organization_slug_shape_chk` / `team_slug_shape_chk` / `environment_slug_shape_chk` | Lowercase `^[a-z0-9]+(-[a-z0-9]+)*$` |
| `sbom_sha256_chk` / evidence and intel SHA checks | 64 lowercase hex characters |
| `sbom_byte_length_chk` | Positive byte size |
| `dependency_relationship_not_self_chk` | Source ≠ target occurrence |
| `risk_acceptance_expiration_chk` | `expires_at > starts_at` |
| `risk_acceptance_approval_chk` / `*_active_approval_chk` / `*_revocation_chk` | Approver/timestamp and revocation fields stay consistent |
| `outbox_event_attempt_chk` / `*_lease_chk` / `*_processed_ts_chk` | Nonnegative attempts; lease and processed timestamps match status |
| `evidence_one_target_chk` | Exactly one supported evidence target |
| `*_version_chk` | Optimistic concurrency version ≥ 1 |
| Archive / completed / failure-code timestamp consistency | Status and timestamps agree |

Partial unique indexes cover active asset names per organization, builtin vs org risk-policy versions, one active risk acceptance per finding, outbox/audit replay keys, and available outbox work.

## Indexes

Every index maps to a documented access or uniqueness need: organization slug; membership by org+user and active memberships; team/environment lookup; assets by org/status/owner/environment/last observation; SBOMs by asset+received time and org+asset+hash; ingestion by state; component identity; occurrences by SBOM and component; dependency traversal; vulnerability OSV/CVE/aliases and source provenance; findings by org/status/asset/vulnerability/assignee/due; observations by finding+time; policies by org+status; calculations by finding+time; tasks by assignee/status/due; expiring acceptances; audit by org+time and target; outbox claim; job lease; idempotency lookup and expiry.

## Append-only enforcement

`BEFORE UPDATE OR DELETE` triggers reject mutation of `audit_event`, `finding_observation`, `risk_calculation`, `vulnerability_source_record`, and `evidence`. Published `risk_policy` rows are immutable via trigger. These controls do not prevent a superuser from rewriting history.

## Limitations

Triggers and revoked DML are not WORM storage. Superusers can still rewrite history. Hash chaining is not implemented; this database does not claim non-repudiation.

## Related documents

- [Tenant isolation](tenant-isolation.md)
- [Migrations](../development/migrations.md)
- [Database development](../development/database.md)
