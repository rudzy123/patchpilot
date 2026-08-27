-- Session 5 independent-review corrections. Forward-only.
-- Does not edit 20260826120000_schema_foundation or 20260827120000_tenant_model.

-- CreateEnum
CREATE TYPE "risk_policy_scope" AS ENUM ('builtin', 'organization');

-- AlterEnum
ALTER TYPE "evidence_kind" ADD VALUE 'export_snapshot';

-- CreateTable
CREATE TABLE "integration_provider" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "provider_key" "integration_provider_key" NOT NULL,
    "display_name" VARCHAR(200) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "integration_provider_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "intelligence_source" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "provider_key" "integration_provider_key" NOT NULL,
    "state" "integration_state" NOT NULL DEFAULT 'disabled',
    "config" JSONB NOT NULL,
    "last_successful_sync_at" TIMESTAMPTZ(6),
    "last_failure_at" TIMESTAMPTZ(6),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "intelligence_source_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "integration_provider_provider_key_key" ON "integration_provider"("provider_key");
CREATE UNIQUE INDEX "intelligence_source_provider_key_key" ON "intelligence_source"("provider_key");

INSERT INTO "integration_provider" ("provider_key", "display_name")
VALUES
  ('osv', 'OSV'),
  ('cisa_kev', 'CISA KEV'),
  ('reserved', 'Reserved');

INSERT INTO "intelligence_source" ("provider_key", "state", "config", "version")
VALUES
  ('osv', 'disabled', '{"schemaVersion": 1, "refreshIntervalSeconds": null, "endpointAllowlist": []}'::jsonb, 1),
  ('cisa_kev', 'disabled', '{"schemaVersion": 1, "refreshIntervalSeconds": null, "endpointAllowlist": []}'::jsonb, 1);

ALTER TABLE "intelligence_source"
  ADD CONSTRAINT "intelligence_source_provider_key_fkey"
  FOREIGN KEY ("provider_key") REFERENCES "integration_provider"("provider_key") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Convert any leftover null-org integration rows into intelligence sources, then require org ownership.
ALTER TABLE "integration" ADD COLUMN "provider_id" UUID;

UPDATE "intelligence_source" AS src
SET
  "state" = src_row."state",
  "config" = src_row."config",
  "last_successful_sync_at" = src_row."last_successful_sync_at",
  "last_failure_at" = src_row."last_failure_at",
  "version" = src_row."version",
  "updated_at" = src_row."updated_at"
FROM "integration" AS src_row
WHERE src_row."organization_id" IS NULL
  AND src."provider_key" = src_row."provider_key";

DELETE FROM "external_credential" WHERE "integration_id" IN (
  SELECT "id" FROM "integration" WHERE "organization_id" IS NULL
);
DELETE FROM "repository_connection" WHERE "integration_id" IN (
  SELECT "id" FROM "integration" WHERE "organization_id" IS NULL
);
DELETE FROM "integration" WHERE "organization_id" IS NULL;

UPDATE "integration" AS inst
SET "provider_id" = provider."id"
FROM "integration_provider" AS provider
WHERE provider."provider_key" = inst."provider_key";

ALTER TABLE "integration" ALTER COLUMN "organization_id" SET NOT NULL;
ALTER TABLE "integration" ALTER COLUMN "provider_id" SET NOT NULL;

DROP INDEX IF EXISTS "integration_org_provider_idx";
ALTER TABLE "integration" DROP CONSTRAINT IF EXISTS "integration_organization_id_fkey";
ALTER TABLE "integration" DROP COLUMN "provider_key";

ALTER TABLE "integration"
  ADD CONSTRAINT "integration_organization_id_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "integration"
  ADD CONSTRAINT "integration_provider_id_fkey"
  FOREIGN KEY ("provider_id") REFERENCES "integration_provider"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE UNIQUE INDEX "integration_org_provider_key" ON "integration"("organization_id", "provider_id");
CREATE INDEX "integration_org_state_idx" ON "integration"("organization_id", "state");

-- Risk policy scope
ALTER TABLE "risk_policy" ADD COLUMN "scope" "risk_policy_scope";
UPDATE "risk_policy"
SET "scope" = CASE
  WHEN "organization_id" IS NULL THEN 'builtin'::"risk_policy_scope"
  ELSE 'organization'::"risk_policy_scope"
END;
ALTER TABLE "risk_policy" ALTER COLUMN "scope" SET NOT NULL;
CREATE INDEX "risk_policy_scope_key_version_idx" ON "risk_policy"("scope", "policy_key", "version");

-- Graph consistency support columns and replacement foreign keys
ALTER TABLE "sbom" ADD COLUMN "uploaded_by_membership_id" UUID;
UPDATE "sbom" AS s
SET "uploaded_by_membership_id" = m."id"
FROM "membership" AS m
WHERE m."organization_id" = s."organization_id"
  AND m."user_id" = s."uploaded_by_user_id";
ALTER TABLE "sbom" DROP CONSTRAINT IF EXISTS "sbom_uploaded_by_user_id_fkey";
ALTER TABLE "sbom" DROP COLUMN "uploaded_by_user_id";

CREATE UNIQUE INDEX "sbom_org_id_asset_key" ON "sbom"("organization_id", "id", "asset_id");

ALTER TABLE "sbom_ingestion" DROP CONSTRAINT IF EXISTS "sbom_ingestion_organization_id_sbom_id_fkey";
CREATE UNIQUE INDEX "sbom_ingestion_org_id_sbom_key" ON "sbom_ingestion"("organization_id", "id", "sbom_id");
CREATE UNIQUE INDEX "sbom_ingestion_org_id_asset_key" ON "sbom_ingestion"("organization_id", "id", "asset_id");
ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT "sbom_ingestion_same_sbom_asset_fkey"
  FOREIGN KEY ("organization_id", "sbom_id", "asset_id")
  REFERENCES "sbom"("organization_id", "id", "asset_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "asset" DROP CONSTRAINT IF EXISTS "asset_organization_id_last_successful_sbom_ingestion_id_fkey";
ALTER TABLE "asset"
  ADD CONSTRAINT "asset_current_ingestion_same_asset_fkey"
  FOREIGN KEY ("organization_id", "last_successful_sbom_ingestion_id", "id")
  REFERENCES "sbom_ingestion"("organization_id", "id", "asset_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "component_occurrence" ADD COLUMN "asset_id" UUID;
UPDATE "component_occurrence" AS occ
SET "asset_id" = s."asset_id"
FROM "sbom" AS s
WHERE s."id" = occ."sbom_id";
ALTER TABLE "component_occurrence" ALTER COLUMN "asset_id" SET NOT NULL;

ALTER TABLE "component_occurrence" DROP CONSTRAINT IF EXISTS "component_occurrence_organization_id_sbom_id_fkey";
ALTER TABLE "component_occurrence" DROP CONSTRAINT IF EXISTS "component_occurrence_organization_id_sbom_ingestion_id_fkey";
CREATE UNIQUE INDEX "component_occurrence_org_id_ingestion_key"
  ON "component_occurrence"("organization_id", "id", "sbom_ingestion_id");
CREATE UNIQUE INDEX "component_occurrence_org_id_asset_component_key"
  ON "component_occurrence"("organization_id", "id", "asset_id", "component_id");
ALTER TABLE "component_occurrence"
  ADD CONSTRAINT "component_occurrence_organization_id_asset_id_fkey"
  FOREIGN KEY ("organization_id", "asset_id")
  REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "component_occurrence"
  ADD CONSTRAINT "component_occurrence_same_sbom_asset_fkey"
  FOREIGN KEY ("organization_id", "sbom_id", "asset_id")
  REFERENCES "sbom"("organization_id", "id", "asset_id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "component_occurrence"
  ADD CONSTRAINT "component_occurrence_same_ingestion_sbom_fkey"
  FOREIGN KEY ("organization_id", "sbom_ingestion_id", "sbom_id")
  REFERENCES "sbom_ingestion"("organization_id", "id", "sbom_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "dependency_relationship" DROP CONSTRAINT IF EXISTS "dependency_relationship_organization_id_from_occurrence_id_fkey";
ALTER TABLE "dependency_relationship" DROP CONSTRAINT IF EXISTS "dependency_relationship_organization_id_to_occurrence_id_fkey";
ALTER TABLE "dependency_relationship"
  ADD CONSTRAINT "dependency_from_same_ingestion_fkey"
  FOREIGN KEY ("organization_id", "from_occurrence_id", "sbom_ingestion_id")
  REFERENCES "component_occurrence"("organization_id", "id", "sbom_ingestion_id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "dependency_relationship"
  ADD CONSTRAINT "dependency_to_same_ingestion_fkey"
  FOREIGN KEY ("organization_id", "to_occurrence_id", "sbom_ingestion_id")
  REFERENCES "component_occurrence"("organization_id", "id", "sbom_ingestion_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Membership-scoped actors
ALTER TABLE "finding" ADD COLUMN "assigned_membership_id" UUID;
UPDATE "finding" AS f
SET "assigned_membership_id" = m."id"
FROM "membership" AS m
WHERE m."organization_id" = f."organization_id"
  AND m."user_id" = f."assigned_user_id";
DROP INDEX IF EXISTS "finding_org_assignee_idx";
ALTER TABLE "finding" DROP CONSTRAINT IF EXISTS "finding_assigned_user_id_fkey";
ALTER TABLE "finding" DROP COLUMN "assigned_user_id";
CREATE INDEX "finding_org_assignee_idx" ON "finding"("organization_id", "assigned_membership_id");

ALTER TABLE "finding" DROP CONSTRAINT IF EXISTS "finding_organization_id_component_occurrence_id_fkey";
ALTER TABLE "finding"
  ADD CONSTRAINT "finding_occurrence_same_asset_component_fkey"
  FOREIGN KEY ("organization_id", "component_occurrence_id", "asset_id", "component_id")
  REFERENCES "component_occurrence"("organization_id", "id", "asset_id", "component_id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "finding"
  ADD CONSTRAINT "finding_organization_id_assigned_membership_id_fkey"
  FOREIGN KEY ("organization_id", "assigned_membership_id")
  REFERENCES "membership"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "sbom"
  ADD CONSTRAINT "sbom_organization_id_uploaded_by_membership_id_fkey"
  FOREIGN KEY ("organization_id", "uploaded_by_membership_id")
  REFERENCES "membership"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "remediation_task" ADD COLUMN "assigned_membership_id" UUID;
UPDATE "remediation_task" AS t
SET "assigned_membership_id" = m."id"
FROM "membership" AS m
WHERE m."organization_id" = t."organization_id"
  AND m."user_id" = t."assigned_user_id";
DROP INDEX IF EXISTS "remediation_task_org_assignee_idx";
ALTER TABLE "remediation_task" DROP CONSTRAINT IF EXISTS "remediation_task_assigned_user_id_fkey";
ALTER TABLE "remediation_task" DROP COLUMN "assigned_user_id";
CREATE INDEX "remediation_task_org_assignee_idx" ON "remediation_task"("organization_id", "assigned_membership_id");
ALTER TABLE "remediation_task"
  ADD CONSTRAINT "remediation_task_organization_id_assigned_membership_id_fkey"
  FOREIGN KEY ("organization_id", "assigned_membership_id")
  REFERENCES "membership"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "risk_acceptance" DROP CONSTRAINT IF EXISTS risk_acceptance_approval_chk;
ALTER TABLE "risk_acceptance" DROP CONSTRAINT IF EXISTS risk_acceptance_active_approval_chk;
ALTER TABLE "risk_acceptance" ADD COLUMN "requested_by_membership_id" UUID;
ALTER TABLE "risk_acceptance" ADD COLUMN "approved_by_membership_id" UUID;
UPDATE "risk_acceptance" AS r
SET "requested_by_membership_id" = m."id"
FROM "membership" AS m
WHERE m."organization_id" = r."organization_id"
  AND m."user_id" = r."requested_by_user_id";
UPDATE "risk_acceptance" AS r
SET "approved_by_membership_id" = m."id"
FROM "membership" AS m
WHERE m."organization_id" = r."organization_id"
  AND m."user_id" = r."approved_by_user_id";
ALTER TABLE "risk_acceptance" DROP CONSTRAINT IF EXISTS "risk_acceptance_requested_by_user_id_fkey";
ALTER TABLE "risk_acceptance" DROP CONSTRAINT IF EXISTS "risk_acceptance_approved_by_user_id_fkey";
ALTER TABLE "risk_acceptance" DROP COLUMN "requested_by_user_id";
ALTER TABLE "risk_acceptance" DROP COLUMN "approved_by_user_id";
ALTER TABLE "risk_acceptance" ALTER COLUMN "requested_by_membership_id" SET NOT NULL;
ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT "risk_acceptance_organization_id_requested_by_membership_id_fkey"
  FOREIGN KEY ("organization_id", "requested_by_membership_id")
  REFERENCES "membership"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT "risk_acceptance_organization_id_approved_by_membership_id_fkey"
  FOREIGN KEY ("organization_id", "approved_by_membership_id")
  REFERENCES "membership"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_approval_chk
  CHECK ((approved_by_membership_id IS NULL) = (approved_at IS NULL));
ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_active_approval_chk
  CHECK (
    (status = 'active' AND approved_by_membership_id IS NOT NULL AND approved_at IS NOT NULL)
    OR status <> 'active'
  );

ALTER TABLE "evidence" ADD COLUMN "submitted_by_membership_id" UUID;
UPDATE "evidence" AS e
SET "submitted_by_membership_id" = m."id"
FROM "membership" AS m
WHERE m."organization_id" = e."organization_id"
  AND m."user_id" = e."submitted_by_user_id";
ALTER TABLE "evidence" DROP CONSTRAINT IF EXISTS "evidence_submitted_by_user_id_fkey";
ALTER TABLE "evidence" DROP COLUMN "submitted_by_user_id";
ALTER TABLE "evidence"
  ADD CONSTRAINT "evidence_organization_id_submitted_by_membership_id_fkey"
  FOREIGN KEY ("organization_id", "submitted_by_membership_id")
  REFERENCES "membership"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "audit_event" ADD COLUMN "actor_membership_id" UUID;
UPDATE "audit_event" AS a
SET "actor_membership_id" = m."id"
FROM "membership" AS m
WHERE m."organization_id" = a."organization_id"
  AND m."user_id" = a."actor_user_id";
ALTER TABLE "audit_event" DROP CONSTRAINT IF EXISTS "audit_event_actor_user_id_fkey";
ALTER TABLE "audit_event" DROP COLUMN "actor_user_id";
ALTER TABLE "audit_event"
  ADD CONSTRAINT "audit_event_organization_id_actor_membership_id_fkey"
  FOREIGN KEY ("organization_id", "actor_membership_id")
  REFERENCES "membership"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Vulnerability source revision identity: same bytes may be re-normalized
ALTER TABLE "vulnerability_source_record" DROP CONSTRAINT IF EXISTS "vulnerability_source_record_supersedes_record_id_fkey";
DROP INDEX IF EXISTS "vulnerability_source_record_provenance_key";
CREATE UNIQUE INDEX "vulnerability_source_record_revision_key"
  ON "vulnerability_source_record"("id", "vulnerability_id", "source", "source_identity");
CREATE UNIQUE INDEX "vulnerability_source_record_provenance_key"
  ON "vulnerability_source_record"("source", "source_identity", "payload_sha256", "normalization_version");
ALTER TABLE "vulnerability_source_record"
  ADD CONSTRAINT "vulnerability_source_record_supersedes_revision_fkey"
  FOREIGN KEY ("supersedes_record_id", "vulnerability_id", "source", "source_identity")
  REFERENCES "vulnerability_source_record"("id", "vulnerability_id", "source", "source_identity") ON DELETE RESTRICT ON UPDATE CASCADE;

-- Additional PostgreSQL constraints, indexes, and hardened triggers.
-- See packages/database/prisma/sql/review-corrections-extras.sql.

-- Risk policy scope and publication consistency
ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_scope_ownership_chk
  CHECK (
    (scope = 'builtin' AND organization_id IS NULL)
    OR (scope = 'organization' AND organization_id IS NOT NULL)
  );

ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_status_timestamps_chk
  CHECK (
    (status = 'draft' AND published_at IS NULL AND retired_at IS NULL)
    OR (status = 'published' AND published_at IS NOT NULL AND retired_at IS NULL)
    OR (
      status = 'retired'
      AND published_at IS NOT NULL
      AND retired_at IS NOT NULL
      AND retired_at >= published_at
    )
  );

-- Asset owner: exactly one target; NULL-safe uniqueness
ALTER TABLE "asset_owner" DROP CONSTRAINT IF EXISTS asset_owner_target_chk;

ALTER TABLE "asset_owner"
  ADD CONSTRAINT asset_owner_target_chk
  CHECK (
    (user_id IS NOT NULL AND team_id IS NULL)
    OR (user_id IS NULL AND team_id IS NOT NULL)
  );

DROP INDEX IF EXISTS "asset_owner_identity_key";

CREATE UNIQUE INDEX asset_owner_org_asset_role_user_uidx
  ON "asset_owner" (organization_id, asset_id, role, user_id)
  WHERE user_id IS NOT NULL;

CREATE UNIQUE INDEX asset_owner_org_asset_role_team_uidx
  ON "asset_owner" (organization_id, asset_id, role, team_id)
  WHERE team_id IS NOT NULL;

-- SBOM ingestion idempotency is org-scoped and only applies when a key is present
CREATE UNIQUE INDEX sbom_ingestion_org_idempotency_uidx
  ON "sbom_ingestion" (organization_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- Tenant audit actors must be memberships; system actors must not be
ALTER TABLE "audit_event"
  ADD CONSTRAINT audit_event_actor_scope_chk
  CHECK (
    (actor_type = 'user' AND organization_id IS NOT NULL AND actor_membership_id IS NOT NULL)
    OR (actor_type IN ('system', 'instance_operator') AND actor_membership_id IS NULL)
  );

-- Intelligence sources are global OSV/KEV sync state, never tenant installations
ALTER TABLE "intelligence_source"
  ADD CONSTRAINT intelligence_source_provider_chk
  CHECK (provider_key IN ('osv', 'cisa_kev'));

ALTER TABLE "intelligence_source"
  ADD CONSTRAINT intelligence_source_version_chk CHECK (version >= 1);

ALTER TABLE "intelligence_source"
  ADD CONSTRAINT intelligence_source_config_schema_chk
  CHECK (
    jsonb_typeof(config) = 'object'
    AND (config->>'schemaVersion') IS NOT NULL
  );

ALTER TABLE "integration_provider"
  ADD CONSTRAINT integration_provider_display_name_chk
  CHECK (char_length(display_name) BETWEEN 1 AND 200);

-- Harden trigger functions against search_path hijacking
CREATE OR REPLACE FUNCTION patchpilot_forbid_mutation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'append-only table % does not allow %', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE OR REPLACE FUNCTION patchpilot_protect_published_risk_policy()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.published_at IS NOT NULL THEN
    IF NEW.definition IS DISTINCT FROM OLD.definition
      OR NEW.policy_key IS DISTINCT FROM OLD.policy_key
      OR NEW.version IS DISTINCT FROM OLD.version
      OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
      OR NEW.scope IS DISTINCT FROM OLD.scope
      OR NEW.published_at IS DISTINCT FROM OLD.published_at THEN
      RAISE EXCEPTION 'published risk policies are immutable'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.status = 'published' AND NEW.status NOT IN ('published', 'retired') THEN
      RAISE EXCEPTION 'published risk policies may only be retired'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.status = 'retired' AND NEW.status IS DISTINCT FROM OLD.status THEN
      RAISE EXCEPTION 'retired risk policies are immutable'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION patchpilot_forbid_published_risk_policy_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.published_at IS NOT NULL THEN
    RAISE EXCEPTION 'published risk policies cannot be deleted'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS risk_policy_published_delete_forbidden ON "risk_policy";
CREATE TRIGGER risk_policy_published_delete_forbidden
  BEFORE DELETE ON "risk_policy"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_published_risk_policy_delete();

CREATE OR REPLACE FUNCTION patchpilot_protect_sbom_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.sha256 IS DISTINCT FROM OLD.sha256
    OR NEW.object_key IS DISTINCT FROM OLD.object_key
    OR NEW.byte_length IS DISTINCT FROM OLD.byte_length
    OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
    OR NEW.asset_id IS DISTINCT FROM OLD.asset_id THEN
    RAISE EXCEPTION 'SBOM identity fields are immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION patchpilot_risk_policy_org_consistency()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  policy_org uuid;
BEGIN
  SELECT organization_id INTO policy_org FROM public.risk_policy WHERE id = NEW.risk_policy_id;
  IF policy_org IS NOT NULL AND policy_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'risk policy organization does not match calculation organization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION patchpilot_job_outbox_org_consistency()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  outbox_org uuid;
BEGIN
  IF NEW.outbox_event_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT organization_id INTO outbox_org FROM public.outbox_event WHERE id = NEW.outbox_event_id;
  IF outbox_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'background job organization does not match outbox event organization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;
