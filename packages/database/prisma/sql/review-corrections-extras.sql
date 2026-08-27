-- Session 5 review corrections that Prisma cannot express natively.
-- Applied by migrations 20260827140000_review_corrections and
-- 20260827150000_evidence_export_snapshot_chk.

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

-- Evidence target CHECK that references export_snapshot is in
-- 20260827150000_evidence_export_snapshot_chk because PostgreSQL requires
-- the new enum value to be committed before it can be used.

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
