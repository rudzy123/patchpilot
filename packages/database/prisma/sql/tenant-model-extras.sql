-- Additional PostgreSQL constraints, indexes, triggers, and SchemaFoundation removal.
-- Prisma cannot express these natively. See docs/architecture/database-model.md.

-- Slug and email normalization
ALTER TABLE "organization"
  ADD CONSTRAINT organization_slug_shape_chk
  CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) BETWEEN 2 AND 64);

ALTER TABLE "organization"
  ADD CONSTRAINT organization_version_chk CHECK (version >= 1);

ALTER TABLE "organization"
  ADD CONSTRAINT organization_archive_consistency_chk
  CHECK (
    (status = 'archived' AND archived_at IS NOT NULL)
    OR (status = 'active' AND archived_at IS NULL)
  );

ALTER TABLE "user"
  ADD CONSTRAINT user_email_lower_chk CHECK (email = lower(email));

ALTER TABLE "user"
  ADD CONSTRAINT user_version_chk CHECK (version >= 1);

ALTER TABLE "user"
  ADD CONSTRAINT user_disabled_consistency_chk
  CHECK (
    (status = 'disabled' AND disabled_at IS NOT NULL)
    OR (status = 'active' AND disabled_at IS NULL)
  );

ALTER TABLE "membership"
  ADD CONSTRAINT membership_version_chk CHECK (version >= 1);

ALTER TABLE "membership"
  ADD CONSTRAINT membership_revoked_consistency_chk
  CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL)
    OR (status = 'active' AND revoked_at IS NULL)
  );

ALTER TABLE "team"
  ADD CONSTRAINT team_slug_shape_chk
  CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) BETWEEN 2 AND 64);

ALTER TABLE "team"
  ADD CONSTRAINT team_version_chk CHECK (version >= 1);

ALTER TABLE "environment"
  ADD CONSTRAINT environment_slug_shape_chk
  CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) BETWEEN 2 AND 64);

ALTER TABLE "environment"
  ADD CONSTRAINT environment_version_chk CHECK (version >= 1);

-- Asset
ALTER TABLE "asset"
  ADD CONSTRAINT asset_version_chk CHECK (version >= 1);

ALTER TABLE "asset"
  ADD CONSTRAINT asset_archive_consistency_chk
  CHECK (
    (lifecycle_status = 'archived' AND archived_at IS NOT NULL)
    OR (lifecycle_status = 'active' AND archived_at IS NULL)
  );

CREATE UNIQUE INDEX asset_active_name_org_idx
  ON "asset" (organization_id, lower(name))
  WHERE lifecycle_status = 'active';

ALTER TABLE "asset_owner"
  ADD CONSTRAINT asset_owner_target_chk
  CHECK (user_id IS NOT NULL OR team_id IS NOT NULL);

ALTER TABLE "asset_tag"
  ADD CONSTRAINT asset_tag_shape_chk
  CHECK (tag = lower(tag) AND char_length(tag) BETWEEN 1 AND 64 AND tag ~ '^[a-z0-9]+(-[a-z0-9]+)*$');

-- SBOM evidence
ALTER TABLE "sbom"
  ADD CONSTRAINT sbom_sha256_chk CHECK (sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE "sbom"
  ADD CONSTRAINT sbom_byte_length_chk CHECK (byte_length > 0);

ALTER TABLE "sbom"
  ADD CONSTRAINT sbom_spec_version_chk
  CHECK (specification_version IS NULL OR specification_version IN ('1.4', '1.5', '1.6'));

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_attempt_chk CHECK (attempt_number >= 1);

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_version_chk CHECK (version >= 1);

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_failure_code_chk
  CHECK (
    (state IN ('failed', 'rejected', 'quarantined') AND failure_code IS NOT NULL)
    OR state NOT IN ('failed', 'rejected', 'quarantined')
  );

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_completed_ts_chk
  CHECK (
    (state = 'completed' AND completed_at IS NOT NULL)
    OR state <> 'completed'
  );

ALTER TABLE "dependency_relationship"
  ADD CONSTRAINT dependency_relationship_not_self_chk
  CHECK (from_occurrence_id <> to_occurrence_id);

-- Intelligence
ALTER TABLE "vulnerability_source_record"
  ADD CONSTRAINT vulnerability_source_record_sha256_chk
  CHECK (payload_sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE "vulnerability_source_record"
  ADD CONSTRAINT vulnerability_source_record_normalized_schema_chk
  CHECK (
    jsonb_typeof(normalized) = 'object'
    AND (normalized->>'schemaVersion') IS NOT NULL
  );

-- Findings
ALTER TABLE "finding"
  ADD CONSTRAINT finding_version_chk CHECK (version >= 1);

ALTER TABLE "finding"
  ADD CONSTRAINT finding_resolved_ts_chk
  CHECK (
    (state = 'resolved' AND resolved_at IS NOT NULL)
    OR state <> 'resolved'
  );

ALTER TABLE "finding_observation"
  ADD CONSTRAINT finding_observation_evidence_schema_chk
  CHECK (
    jsonb_typeof(evidence) = 'object'
    AND (evidence->>'schemaVersion') IS NOT NULL
  );

-- Risk policy and calculations
ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_version_chk CHECK (version >= 1);

ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_schema_version_chk CHECK (policy_schema_version >= 1);

ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_definition_schema_chk
  CHECK (
    jsonb_typeof(definition) = 'object'
    AND (definition->>'schemaVersion') IS NOT NULL
  );

CREATE UNIQUE INDEX risk_policy_builtin_key_version_uidx
  ON "risk_policy" (policy_key, version)
  WHERE organization_id IS NULL;

CREATE UNIQUE INDEX risk_policy_org_key_version_uidx
  ON "risk_policy" (organization_id, policy_key, version)
  WHERE organization_id IS NOT NULL;

ALTER TABLE "risk_calculation"
  ADD CONSTRAINT risk_calculation_policy_sha256_chk
  CHECK (policy_definition_sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE "risk_calculation"
  ADD CONSTRAINT risk_calculation_input_fingerprint_chk
  CHECK (input_fingerprint ~ '^[a-f0-9]{64}$');

ALTER TABLE "risk_calculation"
  ADD CONSTRAINT risk_calculation_json_schema_chk
  CHECK (
    jsonb_typeof(factors) = 'object'
    AND (factors->>'schemaVersion') IS NOT NULL
    AND jsonb_typeof(result) = 'object'
    AND (result->>'schemaVersion') IS NOT NULL
  );

-- Remediation
ALTER TABLE "remediation_task"
  ADD CONSTRAINT remediation_task_version_chk CHECK (version >= 1);

ALTER TABLE "remediation_task"
  ADD CONSTRAINT remediation_task_completed_ts_chk
  CHECK (
    (status = 'completed' AND completed_at IS NOT NULL)
    OR status <> 'completed'
  );

ALTER TABLE "remediation_task"
  ADD CONSTRAINT remediation_task_cancelled_ts_chk
  CHECK (
    (status = 'cancelled' AND cancelled_at IS NOT NULL)
    OR status <> 'cancelled'
  );

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_expiration_chk CHECK (expires_at > starts_at);

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_review_chk CHECK (review_at < expires_at AND review_at >= starts_at);

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_approval_chk
  CHECK (
    (approved_by_user_id IS NULL) = (approved_at IS NULL)
  );

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_active_approval_chk
  CHECK (
    (status = 'active' AND approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL)
    OR status <> 'active'
  );

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_revocation_chk
  CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    OR (status <> 'revoked' AND revoked_at IS NULL AND revocation_reason IS NULL)
  );

CREATE UNIQUE INDEX risk_acceptance_one_active_per_finding_idx
  ON "risk_acceptance" (organization_id, finding_id)
  WHERE status = 'active';

-- Evidence
ALTER TABLE "evidence"
  ADD CONSTRAINT evidence_one_target_chk
  CHECK (
    (kind = 'sbom_object' AND sbom_id IS NOT NULL AND finding_id IS NULL AND asset_id IS NULL)
    OR (
      kind IN ('kev_match', 'intel_record', 'policy_snapshot', 'compensating_control')
      AND finding_id IS NOT NULL
      AND sbom_id IS NULL
      AND asset_id IS NULL
    )
  );

ALTER TABLE "evidence"
  ADD CONSTRAINT evidence_sha256_chk
  CHECK (sha256 IS NULL OR sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE "evidence"
  ADD CONSTRAINT evidence_byte_length_chk
  CHECK (byte_length IS NULL OR byte_length > 0);

ALTER TABLE "evidence"
  ADD CONSTRAINT evidence_metadata_schema_chk
  CHECK (
    jsonb_typeof(metadata) = 'object'
    AND (metadata->>'schemaVersion') IS NOT NULL
  );

-- Audit
ALTER TABLE "audit_event"
  ADD CONSTRAINT audit_event_payload_schema_chk
  CHECK (
    jsonb_typeof(payload) = 'object'
    AND (payload->>'schemaVersion') IS NOT NULL
  );

ALTER TABLE "audit_event"
  ADD CONSTRAINT audit_event_schema_version_chk CHECK (schema_version >= 1);

CREATE UNIQUE INDEX audit_event_tenant_replay_idx
  ON "audit_event" (organization_id, action, subject_id, correlation_id)
  WHERE organization_id IS NOT NULL;

CREATE UNIQUE INDEX audit_event_system_replay_idx
  ON "audit_event" (action, subject_id, correlation_id)
  WHERE organization_id IS NULL;

-- Integration / credentials
ALTER TABLE "integration"
  ADD CONSTRAINT integration_version_chk CHECK (version >= 1);

ALTER TABLE "integration"
  ADD CONSTRAINT integration_config_schema_chk
  CHECK (
    jsonb_typeof(config) = 'object'
    AND (config->>'schemaVersion') IS NOT NULL
  );

ALTER TABLE "external_credential"
  ADD CONSTRAINT external_credential_version_chk CHECK (version >= 1);

-- Outbox
ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_attempt_chk CHECK (attempt_count >= 0);

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_schema_version_chk CHECK (event_schema_version >= 1);

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_payload_schema_chk
  CHECK (
    jsonb_typeof(payload) = 'object'
    AND (payload->>'schemaVersion') IS NOT NULL
  );

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_processed_ts_chk
  CHECK (
    (status = 'processed' AND processed_at IS NOT NULL)
    OR status <> 'processed'
  );

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_lease_chk
  CHECK (
    (status = 'claimed' AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR status <> 'claimed'
  );

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_failed_code_chk
  CHECK (
    (status IN ('failed', 'dead_lettered') AND last_failure_code IS NOT NULL)
    OR status NOT IN ('failed', 'dead_lettered')
  );

CREATE UNIQUE INDEX outbox_event_tenant_dedupe_idx
  ON "outbox_event" (organization_id, dedupe_key)
  WHERE organization_id IS NOT NULL;

CREATE UNIQUE INDEX outbox_event_system_dedupe_idx
  ON "outbox_event" (event_type, dedupe_key)
  WHERE organization_id IS NULL;

CREATE INDEX outbox_event_available_work_idx
  ON "outbox_event" (available_at, id)
  WHERE status = 'pending';

-- Background jobs
ALTER TABLE "background_job"
  ADD CONSTRAINT background_job_attempt_chk CHECK (attempt >= 0);

ALTER TABLE "background_job"
  ADD CONSTRAINT background_job_failed_code_chk
  CHECK (
    (status IN ('failed', 'dead_lettered') AND failure_code IS NOT NULL)
    OR status NOT IN ('failed', 'dead_lettered')
  );

ALTER TABLE "background_job"
  ADD CONSTRAINT background_job_succeeded_ts_chk
  CHECK (
    (status = 'succeeded' AND completed_at IS NOT NULL)
    OR status <> 'succeeded'
  );

-- Idempotency
ALTER TABLE "idempotency_record"
  ADD CONSTRAINT idempotency_record_hashes_chk
  CHECK (key_hash ~ '^[a-f0-9]{64}$' AND request_fingerprint ~ '^[a-f0-9]{64}$');

ALTER TABLE "idempotency_record"
  ADD CONSTRAINT idempotency_record_expiry_chk CHECK (expires_at > created_at);

ALTER TABLE "idempotency_record"
  ADD CONSTRAINT idempotency_record_completed_ts_chk
  CHECK (
    (status = 'completed' AND completed_at IS NOT NULL)
    OR status <> 'completed'
  );

-- Append-only enforcement. Database roles with table privileges still cannot UPDATE/DELETE
-- through the application role. Superusers can bypass this; it is not WORM storage.
CREATE OR REPLACE FUNCTION patchpilot_forbid_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'append-only table % does not allow %', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER audit_event_append_only
  BEFORE UPDATE OR DELETE ON "audit_event"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER finding_observation_append_only
  BEFORE UPDATE OR DELETE ON "finding_observation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER risk_calculation_append_only
  BEFORE UPDATE OR DELETE ON "risk_calculation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER vulnerability_source_record_append_only
  BEFORE UPDATE OR DELETE ON "vulnerability_source_record"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER evidence_append_only
  BEFORE UPDATE OR DELETE ON "evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE OR REPLACE FUNCTION patchpilot_protect_published_risk_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.published_at IS NOT NULL THEN
    IF NEW.definition IS DISTINCT FROM OLD.definition
      OR NEW.policy_key IS DISTINCT FROM OLD.policy_key
      OR NEW.version IS DISTINCT FROM OLD.version
      OR NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
      RAISE EXCEPTION 'published risk policies are immutable'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER risk_policy_published_immutable
  BEFORE UPDATE ON "risk_policy"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_published_risk_policy();

CREATE OR REPLACE FUNCTION patchpilot_protect_sbom_identity()
RETURNS trigger
LANGUAGE plpgsql
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

CREATE TRIGGER sbom_identity_immutable
  BEFORE UPDATE ON "sbom"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_sbom_identity();

CREATE OR REPLACE FUNCTION patchpilot_risk_policy_org_consistency()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  policy_org uuid;
BEGIN
  SELECT organization_id INTO policy_org FROM "risk_policy" WHERE id = NEW.risk_policy_id;
  IF policy_org IS NOT NULL AND policy_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'risk policy organization does not match calculation organization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER risk_calculation_policy_org_consistency
  BEFORE INSERT OR UPDATE ON "risk_calculation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_risk_policy_org_consistency();

CREATE OR REPLACE FUNCTION patchpilot_job_outbox_org_consistency()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  outbox_org uuid;
BEGIN
  IF NEW.outbox_event_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT organization_id INTO outbox_org FROM "outbox_event" WHERE id = NEW.outbox_event_id;
  IF outbox_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'background job organization does not match outbox event organization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER background_job_outbox_org_consistency
  BEFORE INSERT OR UPDATE ON "background_job"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_job_outbox_org_consistency();

-- Remove Session 3 technical scaffolding. The original migration is unchanged.
DROP TABLE IF EXISTS "SchemaFoundation";
