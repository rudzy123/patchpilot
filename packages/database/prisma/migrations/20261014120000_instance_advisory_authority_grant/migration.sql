-- Instance advisory authority grant persistence.
-- Forward-only. One instance-owned grant relation. No organization column.
-- Does not seed grants, users, credentials, or authority.
-- Does not alter advisory, capability, evidence, Finding, or observation rows.
-- Active-grant uniqueness, revocation immutability, and audit completeness
-- are database constraints. The application lock order is not a substitute.

CREATE TYPE "instance_advisory_authority" AS ENUM (
  'advisory_submit_local',
  'advisory_approve_for_product_evaluation'
);

CREATE TYPE "instance_advisory_issuance_classification" AS ENUM (
  'deployment_local_command'
);

CREATE TABLE "instance_advisory_authority_grant" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "user_id" UUID NOT NULL,
  "authority" "instance_advisory_authority" NOT NULL,
  "issuance_classification" "instance_advisory_issuance_classification" NOT NULL,
  "issued_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "revoked_at" TIMESTAMPTZ(6),
  "command_correlation_id" UUID NOT NULL,

  CONSTRAINT "instance_advisory_authority_grant_pkey" PRIMARY KEY ("id")
);

ALTER TABLE "instance_advisory_authority_grant"
  ADD CONSTRAINT "instance_advisory_authority_grant_user_alignment_key"
  UNIQUE ("user_id", "id");

ALTER TABLE "instance_advisory_authority_grant"
  ADD CONSTRAINT "instance_advisory_authority_grant_revoked_at_order_chk"
  CHECK ("revoked_at" IS NULL OR "revoked_at" >= "issued_at");

ALTER TABLE "instance_advisory_authority_grant"
  ADD CONSTRAINT "instance_advisory_authority_grant_user_id_fkey"
  FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE INDEX "instance_advisory_authority_grant_user_idx"
  ON "instance_advisory_authority_grant" ("user_id");

CREATE UNIQUE INDEX "instance_advisory_authority_grant_one_active_user_idx"
  ON "instance_advisory_authority_grant" ("user_id")
  WHERE "revoked_at" IS NULL;

CREATE OR REPLACE FUNCTION patchpilot_instance_advisory_grant_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_setting('patchpilot.instance_advisory_authority_grant', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'instance advisory grant insert rejected'
      USING ERRCODE = '42501';
  END IF;
  IF NEW."revoked_at" IS NOT NULL THEN
    RAISE EXCEPTION 'instance advisory grant insert rejected'
      USING ERRCODE = '23514';
  END IF;
  IF NEW."issued_at" IS DISTINCT FROM CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'instance advisory grant insert rejected'
      USING ERRCODE = '23514';
  END IF;
  IF NEW."authority"::text NOT IN (
    'advisory_submit_local',
    'advisory_approve_for_product_evaluation'
  ) THEN
    RAISE EXCEPTION 'instance advisory grant insert rejected'
      USING ERRCODE = '23514';
  END IF;
  IF NEW."issuance_classification"::text IS DISTINCT FROM 'deployment_local_command' THEN
    RAISE EXCEPTION 'instance advisory grant insert rejected'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER instance_advisory_authority_grant_insert_guard
  BEFORE INSERT ON "instance_advisory_authority_grant"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_instance_advisory_grant_insert_guard();

CREATE OR REPLACE FUNCTION patchpilot_instance_advisory_grant_update_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_setting('patchpilot.instance_advisory_authority_grant', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'instance advisory grant update rejected'
      USING ERRCODE = '42501';
  END IF;
  IF OLD."revoked_at" IS NOT NULL
    OR NEW."revoked_at" IS DISTINCT FROM CURRENT_TIMESTAMP
    OR NEW."id" IS DISTINCT FROM OLD."id"
    OR NEW."user_id" IS DISTINCT FROM OLD."user_id"
    OR NEW."authority" IS DISTINCT FROM OLD."authority"
    OR NEW."issuance_classification" IS DISTINCT FROM OLD."issuance_classification"
    OR NEW."issued_at" IS DISTINCT FROM OLD."issued_at"
    OR NEW."command_correlation_id" IS DISTINCT FROM OLD."command_correlation_id" THEN
    RAISE EXCEPTION 'instance advisory grant update rejected'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER instance_advisory_authority_grant_update_guard
  BEFORE UPDATE ON "instance_advisory_authority_grant"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_instance_advisory_grant_update_guard();

CREATE OR REPLACE FUNCTION patchpilot_instance_advisory_grant_delete_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'instance advisory grant delete rejected'
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER instance_advisory_authority_grant_delete_guard
  BEFORE DELETE ON "instance_advisory_authority_grant"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_instance_advisory_grant_delete_guard();

CREATE OR REPLACE FUNCTION patchpilot_instance_advisory_grant_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  expected_action text;
BEGIN
  IF TG_OP = 'INSERT' THEN
    expected_action := 'intelligence.instance_advisory_authority_granted';
  ELSIF TG_OP = 'UPDATE' THEN
    expected_action := 'intelligence.instance_advisory_authority_revoked';
  ELSE
    RAISE EXCEPTION 'instance advisory authority audit is incomplete'
      USING ERRCODE = '23514';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM "audit_event" AS audit
    WHERE audit."organization_id" IS NULL
      AND audit."actor_user_id" IS NULL
      AND audit."actor_membership_id" IS NULL
      AND audit."actor_type" = 'system'
      AND audit."action" = expected_action
      AND audit."subject_type" = 'instance_advisory_authority_grant'
      AND audit."subject_id" = NEW."id"
      AND (
        TG_OP = 'UPDATE'
        OR audit."correlation_id" = NEW."command_correlation_id"::text
      )
      AND audit."schema_version" = 1
      AND audit."retention_category" = 'security'
      AND audit.xmin = pg_current_xact_id()::xid
      AND audit."payload"->>'schemaVersion' = '1'
      AND audit."payload"->'metadata'->>'targetUserId' = NEW."user_id"::text
      AND audit."payload"->'metadata'->>'authority' = NEW."authority"::text
      AND audit."payload"->'metadata'->>'issuanceClassification' = 'deployment_local_command'
      AND audit."payload"->'metadata'->>'correlationId' = audit."correlation_id"
  ) THEN
    RAISE EXCEPTION 'instance advisory authority audit is incomplete'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER instance_advisory_authority_grant_insert_complete
  AFTER INSERT ON "instance_advisory_authority_grant"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_instance_advisory_grant_complete();

CREATE CONSTRAINT TRIGGER instance_advisory_authority_grant_revoke_complete
  AFTER UPDATE ON "instance_advisory_authority_grant"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_instance_advisory_grant_complete();

CREATE OR REPLACE FUNCTION patchpilot_user_instance_advisory_status_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW."status" IS NOT DISTINCT FROM OLD."status"
    AND NEW."disabled_at" IS NOT DISTINCT FROM OLD."disabled_at" THEN
    RETURN NEW;
  END IF;
  IF current_setting('patchpilot.instance_advisory_user_status', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'user status update rejected'
      USING ERRCODE = '42501';
  END IF;
  IF NEW."id" IS DISTINCT FROM OLD."id"
    OR NEW."email" IS DISTINCT FROM OLD."email"
    OR NEW."display_name" IS DISTINCT FROM OLD."display_name"
    OR NEW."created_at" IS DISTINCT FROM OLD."created_at"
    OR NEW."updated_at" IS DISTINCT FROM CURRENT_TIMESTAMP
    OR NEW."version" IS DISTINCT FROM OLD."version" + 1 THEN
    RAISE EXCEPTION 'user status update rejected'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NOT (
    (
      OLD."status" = 'active'
      AND NEW."status" = 'disabled'
      AND NEW."disabled_at" IS NOT DISTINCT FROM CURRENT_TIMESTAMP
    )
    OR (
      OLD."status" = 'disabled'
      AND NEW."status" = 'active'
      AND NEW."disabled_at" IS NULL
    )
  ) THEN
    RAISE EXCEPTION 'user status update rejected'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER user_instance_advisory_status_guard
  BEFORE UPDATE ON "user"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_user_instance_advisory_status_guard();

CREATE OR REPLACE FUNCTION patchpilot_user_instance_advisory_status_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  expected_action text;
BEGIN
  IF NEW."status" IS NOT DISTINCT FROM OLD."status"
    AND NEW."disabled_at" IS NOT DISTINCT FROM OLD."disabled_at" THEN
    RETURN NULL;
  END IF;
  IF NEW."status" = 'disabled' THEN
    expected_action := 'auth.user_disabled';
  ELSIF NEW."status" = 'active' THEN
    expected_action := 'auth.user_reenabled';
  ELSE
    RAISE EXCEPTION 'user status audit is incomplete'
      USING ERRCODE = '23514';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM "audit_event" AS audit
    WHERE audit."organization_id" IS NULL
      AND audit."actor_user_id" IS NULL
      AND audit."actor_membership_id" IS NULL
      AND audit."actor_type" = 'system'
      AND audit."action" = expected_action
      AND audit."subject_type" = 'user'
      AND audit."subject_id" = NEW."id"
      AND audit."schema_version" = 1
      AND audit."retention_category" = 'security'
      AND audit.xmin = pg_current_xact_id()::xid
      AND audit."payload"->>'schemaVersion' = '1'
      AND audit."payload"->'metadata'->>'targetUserId' = NEW."id"::text
  ) THEN
    RAISE EXCEPTION 'user status audit is incomplete'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER user_instance_advisory_status_complete
  AFTER UPDATE ON "user"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_user_instance_advisory_status_complete();

CREATE OR REPLACE FUNCTION patchpilot_instance_advisory_audit_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  payload_keys text[];
  metadata_keys text[];
  grant_action boolean;
  user_action boolean;
BEGIN
  grant_action := NEW."action" IN (
    'intelligence.instance_advisory_authority_granted',
    'intelligence.instance_advisory_authority_revoked'
  );
  user_action := NEW."action" IN ('auth.user_disabled', 'auth.user_reenabled');
  IF NOT grant_action AND NOT user_action THEN
    RETURN NEW;
  END IF;
  IF grant_action
    AND current_setting('patchpilot.instance_advisory_authority_grant', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '42501';
  END IF;
  IF user_action
    AND current_setting('patchpilot.instance_advisory_user_status', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '42501';
  END IF;
  IF NEW."actor_type" IS DISTINCT FROM 'system'
    OR NEW."actor_user_id" IS NOT NULL
    OR NEW."organization_id" IS NOT NULL
    OR NEW."actor_membership_id" IS NOT NULL
    OR NEW."schema_version" IS DISTINCT FROM 1
    OR NEW."retention_category" IS DISTINCT FROM 'security'
    OR NEW."request_id" IS NOT NULL
    OR NEW."source_ip" IS NOT NULL
    OR NEW."user_agent" IS NOT NULL
    OR NEW."occurred_at" IS DISTINCT FROM CURRENT_TIMESTAMP
    OR NEW."correlation_id" !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;
  IF grant_action AND NEW."subject_type" IS DISTINCT FROM 'instance_advisory_authority_grant' THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;
  IF user_action AND NEW."subject_type" IS DISTINCT FROM 'user' THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;
  IF jsonb_typeof(NEW."payload") IS DISTINCT FROM 'object'
    OR jsonb_typeof(NEW."payload"->'schemaVersion') IS DISTINCT FROM 'number'
    OR NEW."payload"->>'schemaVersion' IS DISTINCT FROM '1'
    OR jsonb_typeof(NEW."payload"->'metadata') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;

  SELECT COALESCE(array_agg(key ORDER BY key), ARRAY[]::text[])
    INTO payload_keys
  FROM jsonb_object_keys(NEW."payload") AS key;
  IF payload_keys IS DISTINCT FROM ARRAY['metadata', 'schemaVersion']::text[] THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;

  SELECT COALESCE(array_agg(key ORDER BY key), ARRAY[]::text[])
    INTO metadata_keys
  FROM jsonb_object_keys(NEW."payload"->'metadata') AS key;
  IF grant_action
    AND metadata_keys IS DISTINCT FROM ARRAY[
      'authority',
      'correlationId',
      'issuanceClassification',
      'targetUserId'
    ]::text[] THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;
  IF user_action
    AND metadata_keys IS DISTINCT FROM ARRAY['correlationId', 'targetUserId']::text[] THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;
  IF NEW."payload"->'metadata'->>'targetUserId' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    OR NEW."payload"->'metadata'->>'correlationId' IS DISTINCT FROM NEW."correlation_id" THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;
  IF grant_action AND (
    NEW."payload"->'metadata'->>'authority' NOT IN (
      'advisory_submit_local',
      'advisory_approve_for_product_evaluation'
    )
    OR NEW."payload"->'metadata'->>'issuanceClassification' IS DISTINCT FROM 'deployment_local_command'
  ) THEN
    RAISE EXCEPTION 'instance advisory authority audit rejected'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER instance_advisory_audit_insert_guard
  BEFORE INSERT ON "audit_event"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_instance_advisory_audit_insert_guard();

CREATE OR REPLACE FUNCTION patchpilot_instance_advisory_audit_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW."action" = 'intelligence.instance_advisory_authority_granted' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM "instance_advisory_authority_grant" AS grant_row
      WHERE grant_row."id" = NEW."subject_id"
        AND grant_row."revoked_at" IS NULL
        AND grant_row.xmin = pg_current_xact_id()::xid
    ) THEN
      RAISE EXCEPTION 'instance advisory authority audit is incomplete'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW."action" = 'intelligence.instance_advisory_authority_revoked' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM "instance_advisory_authority_grant" AS grant_row
      WHERE grant_row."id" = NEW."subject_id"
        AND grant_row."revoked_at" IS NOT NULL
        AND grant_row.xmin = pg_current_xact_id()::xid
    ) THEN
      RAISE EXCEPTION 'instance advisory authority audit is incomplete'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW."action" = 'auth.user_disabled' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM "user" AS account
      WHERE account."id" = NEW."subject_id"
        AND account."status" = 'disabled'
        AND account.xmin = pg_current_xact_id()::xid
    ) THEN
      RAISE EXCEPTION 'user status audit is incomplete'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW."action" = 'auth.user_reenabled' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM "user" AS account
      WHERE account."id" = NEW."subject_id"
        AND account."status" = 'active'
        AND account.xmin = pg_current_xact_id()::xid
    ) THEN
      RAISE EXCEPTION 'user status audit is incomplete'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER instance_advisory_audit_complete
  AFTER INSERT ON "audit_event"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_instance_advisory_audit_complete();
