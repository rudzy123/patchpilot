-- Controlled Finding creation persistence.
-- Forward-only. Completes the Finding and FindingObservation placeholders.
-- Does not alter finding_identity_key. Does not seed Findings.
-- Does not add a durable creation-authority table.
-- Existing placeholder Finding or observation rows are incompatible and fail closed.

LOCK TABLE "finding", "finding_observation" IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM "finding") OR EXISTS (SELECT 1 FROM "finding_observation") THEN
    RAISE EXCEPTION 'incompatible placeholder finding rows exist'
      USING ERRCODE = '23514';
  END IF;
END $$;

ALTER TABLE "finding"
  ALTER COLUMN "first_observed_at" SET DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE "finding"
  ALTER COLUMN "last_observed_at" SET DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE "finding"
  ALTER COLUMN "updated_at" SET DEFAULT CURRENT_TIMESTAMP;

ALTER TABLE "finding"
  ADD CONSTRAINT "finding_creation_initial_state_chk"
  CHECK (
    "state" = 'open'
    AND "component_occurrence_id" IS NULL
    AND "resolved_at" IS NULL
    AND "reopened_at" IS NULL
    AND "assigned_membership_id" IS NULL
    AND "assigned_team_id" IS NULL
    AND "due_at" IS NULL
    AND "current_risk_calculation_id" IS NULL
    AND "version" = 1
  );

CREATE UNIQUE INDEX "finding_alignment_key"
  ON "finding" (
    "organization_id",
    "id",
    "asset_id",
    "component_id",
    "vulnerability_id"
  );

ALTER TABLE "finding_observation"
  ADD COLUMN "transition_classification" VARCHAR(64),
  ADD COLUMN "creation_purpose" VARCHAR(80),
  ADD COLUMN "creation_policy_id" VARCHAR(80),
  ADD COLUMN "creation_policy_version" SMALLINT,
  ADD COLUMN "actor_membership_id" UUID,
  ADD COLUMN "correlation_id" UUID,
  ADD COLUMN "replay_fingerprint" CHAR(64),
  ADD COLUMN "affected_evidence_count" INTEGER;

ALTER TABLE "finding_observation"
  ADD CONSTRAINT "finding_observation_creation_shape_chk"
  CHECK (
    (
      "method" = 'controlled_finding_creation'
      AND "result" = 'present'
      AND "occurrence_id" IS NULL
      AND "transition_classification" = 'initial_creation'
      AND "creation_purpose" = 'create_finding_from_product_match_evidence'
      AND "creation_policy_id" = 'finding_creation_policy_v1'
      AND "creation_policy_version" = 1
      AND "actor_membership_id" IS NOT NULL
      AND "correlation_id" IS NOT NULL
      AND "replay_fingerprint" ~ '^[a-f0-9]{64}$'
      AND "affected_evidence_count" >= 1
      AND "observed_at" = "created_at"
      AND "evidence" = jsonb_build_object(
        'schemaVersion', 'finding_creation_observation_v1',
        'transition', 'initial_creation',
        'purpose', "creation_purpose",
        'policyId', "creation_policy_id",
        'policyVersion', "creation_policy_version",
        'affectedEvidenceCount', "affected_evidence_count",
        'evidenceSetFingerprint', "replay_fingerprint"
      )
    )
  );

CREATE UNIQUE INDEX "finding_observation_org_id_key"
  ON "finding_observation" ("organization_id", "id");

CREATE UNIQUE INDEX "finding_observation_alignment_key"
  ON "finding_observation" (
    "organization_id",
    "id",
    "finding_id",
    "sbom_ingestion_id"
  );

ALTER TABLE "finding_observation"
  ADD CONSTRAINT "finding_observation_actor_membership_fkey"
  FOREIGN KEY ("organization_id", "actor_membership_id")
  REFERENCES "membership" ("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE UNIQUE INDEX "product_match_evaluation_evidence_alignment_key"
  ON "product_match_evaluation_evidence" (
    "organization_id",
    "id",
    "asset_id",
    "component_id",
    "vulnerability_id",
    "sbom_ingestion_id",
    "component_occurrence_id"
  );

CREATE TABLE "finding_creation_evidence_link" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "organization_id" UUID NOT NULL,
  "finding_id" UUID NOT NULL,
  "finding_observation_id" UUID NOT NULL,
  "product_match_evaluation_evidence_id" UUID NOT NULL,
  "asset_id" UUID NOT NULL,
  "component_id" UUID NOT NULL,
  "vulnerability_id" UUID NOT NULL,
  "sbom_ingestion_id" UUID NOT NULL,
  "component_occurrence_id" UUID NOT NULL,
  "outcome" "match_evaluation_outcome" NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "finding_creation_evidence_link_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "finding_creation_evidence_link_outcome_chk" CHECK ("outcome" = 'affected')
);

CREATE UNIQUE INDEX "finding_creation_evidence_link_org_id_key"
  ON "finding_creation_evidence_link" ("organization_id", "id");

CREATE UNIQUE INDEX "finding_creation_evidence_link_evidence_uidx"
  ON "finding_creation_evidence_link" (
    "organization_id",
    "product_match_evaluation_evidence_id"
  );

CREATE UNIQUE INDEX "finding_creation_evidence_link_observation_evidence_uidx"
  ON "finding_creation_evidence_link" (
    "organization_id",
    "finding_observation_id",
    "product_match_evaluation_evidence_id"
  );

ALTER TABLE "finding_creation_evidence_link"
  ADD CONSTRAINT "finding_creation_evidence_link_finding_fkey"
  FOREIGN KEY (
    "organization_id",
    "finding_id",
    "asset_id",
    "component_id",
    "vulnerability_id"
  )
  REFERENCES "finding" (
    "organization_id",
    "id",
    "asset_id",
    "component_id",
    "vulnerability_id"
  )
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "finding_creation_evidence_link"
  ADD CONSTRAINT "finding_creation_evidence_link_observation_fkey"
  FOREIGN KEY (
    "organization_id",
    "finding_observation_id",
    "finding_id",
    "sbom_ingestion_id"
  )
  REFERENCES "finding_observation" (
    "organization_id",
    "id",
    "finding_id",
    "sbom_ingestion_id"
  )
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "finding_creation_evidence_link"
  ADD CONSTRAINT "finding_creation_evidence_link_evidence_fkey"
  FOREIGN KEY (
    "organization_id",
    "product_match_evaluation_evidence_id",
    "asset_id",
    "component_id",
    "vulnerability_id",
    "sbom_ingestion_id",
    "component_occurrence_id"
  )
  REFERENCES "product_match_evaluation_evidence" (
    "organization_id",
    "id",
    "asset_id",
    "component_id",
    "vulnerability_id",
    "sbom_ingestion_id",
    "component_occurrence_id"
  )
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE OR REPLACE FUNCTION patchpilot_finding_creation_qualifying_evidence(
  p_organization_id uuid,
  p_asset_id uuid,
  p_component_id uuid,
  p_vulnerability_id uuid,
  p_sbom_ingestion_id uuid
)
RETURNS TABLE (id uuid)
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
  SELECT evidence."id"
  FROM "product_match_evaluation_evidence" AS evidence
  INNER JOIN "component_occurrence" AS occurrence
    ON occurrence."organization_id" = evidence."organization_id"
   AND occurrence."id" = evidence."component_occurrence_id"
   AND occurrence."asset_id" = evidence."asset_id"
   AND occurrence."component_id" = evidence."component_id"
   AND occurrence."sbom_ingestion_id" = evidence."sbom_ingestion_id"
   AND occurrence."version_known" IS TRUE
  INNER JOIN "sbom_ingestion" AS ingestion
    ON ingestion."organization_id" = evidence."organization_id"
   AND ingestion."id" = evidence."sbom_ingestion_id"
   AND ingestion."asset_id" = evidence."asset_id"
   AND ingestion."state" = 'completed'
   AND ingestion."normalization_version" = '2'
  INNER JOIN "asset" AS asset
    ON asset."organization_id" = evidence."organization_id"
   AND asset."id" = evidence."asset_id"
   AND asset."last_successful_sbom_ingestion_id" = evidence."sbom_ingestion_id"
  INNER JOIN "advisory_revision" AS revision
    ON revision."id" = evidence."advisory_revision_id"
   AND revision."origin" = 'maintainer_reviewed_advisory'
   AND revision."withdrawal_classification" = 'not_withdrawn'
   AND revision."quarantine_classification" = 'not_quarantined'
   AND NOT EXISTS (
     SELECT 1
     FROM "advisory_revision" AS successor
     WHERE successor."supersedes_advisory_revision_id" = revision."id"
   )
  INNER JOIN "maintainer_reviewed_advisory_approval" AS approval
    ON approval."id" = evidence."approval_id"
   AND approval."advisory_revision_id" = evidence."advisory_revision_id"
   AND approval."vulnerability_id" = evidence."vulnerability_id"
   AND approval."approval_purpose" = 'approve_maintainer_reviewed_advisory_for_product_evaluation'
  INNER JOIN "advisory_vulnerability_binding" AS binding
    ON binding."advisory_revision_id" = evidence."advisory_revision_id"
   AND binding."vulnerability_id" = evidence."vulnerability_id"
   AND binding."mapping_review_state" = 'reviewed'
   AND binding."conflict_classification" = 'none'
  WHERE evidence."organization_id" = p_organization_id
    AND evidence."asset_id" = p_asset_id
    AND evidence."component_id" = p_component_id
    AND evidence."vulnerability_id" = p_vulnerability_id
    AND evidence."sbom_ingestion_id" = p_sbom_ingestion_id
    AND evidence."outcome" = 'affected'
    AND evidence."product_origin" = 'maintainer_reviewed_advisory'
    AND evidence."finding_creation" = 'unavailable'
    AND evidence."suppression_authority" = FALSE
    AND evidence."evaluator_id" = 'osv_first_ecosystem_affected_version_evaluator_v1'
    AND evidence."evaluator_version" = 'session_14_batch_2_in_memory'
    AND evidence."matching_policy_id" = 'osv_first_ecosystem_matching_architecture_v1'
    AND evidence."matching_policy_version" = 'osv_first_ecosystem_matching_architecture_v1'
    AND evidence."product_evidence_policy_id" = 'product_match_evaluation_policy_v1'
    AND evidence."product_evidence_policy_version" = 1
    AND evidence."evidence_schema_version" = 'product_match_evaluation_evidence_v1'
  ORDER BY evidence."id"::text COLLATE "C";
$$;

CREATE OR REPLACE FUNCTION patchpilot_finding_creation_insert_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_setting('patchpilot.controlled_finding_creation', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'finding insert requires the controlled creation transaction'
      USING ERRCODE = '42501';
  END IF;
  IF NEW."first_observed_at" IS DISTINCT FROM CURRENT_TIMESTAMP
    OR NEW."last_observed_at" IS DISTINCT FROM CURRENT_TIMESTAMP
    OR NEW."created_at" IS DISTINCT FROM CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'finding creation timestamp must be database time'
      USING ERRCODE = '23514';
  END IF;
  NEW."updated_at" := CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$;

CREATE TRIGGER finding_creation_insert_guard
  BEFORE INSERT ON "finding"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_finding_creation_insert_guard();

CREATE OR REPLACE FUNCTION patchpilot_finding_reject_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'finding update rejected'
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER finding_update_rejected
  BEFORE UPDATE ON "finding"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_finding_reject_update();

CREATE OR REPLACE FUNCTION patchpilot_finding_reject_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'finding delete rejected'
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER finding_delete_rejected
  BEFORE DELETE ON "finding"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_finding_reject_delete();

CREATE OR REPLACE FUNCTION patchpilot_finding_creation_row_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM "finding_observation" AS observation
    WHERE observation."organization_id" = NEW."organization_id"
      AND observation."finding_id" = NEW."id"
      AND observation."method" = 'controlled_finding_creation'
      AND observation.xmin = pg_current_xact_id()::xid
  ) THEN
    RAISE EXCEPTION 'finding creation evidence set is incomplete'
      USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER finding_creation_row_complete
  AFTER INSERT ON "finding"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_finding_creation_row_complete();

CREATE OR REPLACE FUNCTION patchpilot_finding_observation_creation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW."method" IS DISTINCT FROM 'controlled_finding_creation' THEN
    RAISE EXCEPTION 'finding observation insert rejected'
      USING ERRCODE = '42501';
  END IF;
  IF current_setting('patchpilot.controlled_finding_creation', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'finding creation observation rejected'
      USING ERRCODE = '42501';
  END IF;
  IF NEW."observed_at" IS DISTINCT FROM CURRENT_TIMESTAMP
    OR NEW."created_at" IS DISTINCT FROM CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'finding creation timestamp must be database time'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER finding_observation_creation_guard
  BEFORE INSERT ON "finding_observation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_finding_observation_creation_guard();

CREATE OR REPLACE FUNCTION patchpilot_finding_creation_evidence_link_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  evidence_outcome "match_evaluation_outcome";
  observation_xmin xid;
BEGIN
  IF current_setting('patchpilot.controlled_finding_creation', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'finding evidence link rejected'
      USING ERRCODE = '42501';
  END IF;
  IF NEW."created_at" IS DISTINCT FROM CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'finding creation timestamp must be database time'
      USING ERRCODE = '23514';
  END IF;
  SELECT observation.xmin
    INTO observation_xmin
  FROM "finding_observation" AS observation
  WHERE observation."organization_id" = NEW."organization_id"
    AND observation."id" = NEW."finding_observation_id"
    AND observation."method" = 'controlled_finding_creation';
  IF observation_xmin IS DISTINCT FROM pg_current_xact_id()::xid THEN
    RAISE EXCEPTION 'finding evidence link rejected'
      USING ERRCODE = '23514';
  END IF;
  SELECT evidence."outcome"
    INTO evidence_outcome
  FROM "product_match_evaluation_evidence" AS evidence
  WHERE evidence."organization_id" = NEW."organization_id"
    AND evidence."id" = NEW."product_match_evaluation_evidence_id"
    AND evidence."asset_id" = NEW."asset_id"
    AND evidence."component_id" = NEW."component_id"
    AND evidence."vulnerability_id" = NEW."vulnerability_id"
    AND evidence."sbom_ingestion_id" = NEW."sbom_ingestion_id"
    AND evidence."component_occurrence_id" = NEW."component_occurrence_id";
  IF evidence_outcome IS DISTINCT FROM 'affected' THEN
    RAISE EXCEPTION 'finding evidence link rejected'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER finding_creation_evidence_link_guard
  BEFORE INSERT ON "finding_creation_evidence_link"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_finding_creation_evidence_link_guard();

CREATE TRIGGER finding_creation_evidence_link_append_only
  BEFORE UPDATE OR DELETE ON "finding_creation_evidence_link"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE OR REPLACE FUNCTION patchpilot_finding_creation_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  observation_id uuid;
  stored_organization uuid;
  stored_finding uuid;
  stored_ingestion uuid;
  stored_count integer;
  stored_membership uuid;
  stored_correlation uuid;
  stored_asset uuid;
  stored_component uuid;
  stored_vulnerability uuid;
  linked_ids uuid[];
  qualifying_ids uuid[];
BEGIN
  IF TG_TABLE_NAME = 'finding_observation' THEN
    IF NEW."method" IS DISTINCT FROM 'controlled_finding_creation' THEN
      RETURN NULL;
    END IF;
    observation_id := NEW."id";
  ELSE
    observation_id := NEW."finding_observation_id";
  END IF;

  SELECT observation."organization_id",
         observation."finding_id",
         observation."sbom_ingestion_id",
         observation."affected_evidence_count",
         observation."actor_membership_id",
         observation."correlation_id",
         finding."asset_id",
         finding."component_id",
         finding."vulnerability_id"
    INTO stored_organization,
         stored_finding,
         stored_ingestion,
         stored_count,
         stored_membership,
         stored_correlation,
         stored_asset,
         stored_component,
         stored_vulnerability
  FROM "finding_observation" AS observation
  INNER JOIN "finding" AS finding
    ON finding."organization_id" = observation."organization_id"
   AND finding."id" = observation."finding_id"
  WHERE observation."organization_id" = NEW."organization_id"
    AND observation."id" = observation_id
    AND observation."method" = 'controlled_finding_creation';

  IF stored_finding IS NULL THEN
    RAISE EXCEPTION 'finding creation evidence set is incomplete'
      USING ERRCODE = '23514';
  END IF;

  SELECT COALESCE(array_agg(link."product_match_evaluation_evidence_id" ORDER BY link."product_match_evaluation_evidence_id"::text COLLATE "C"), ARRAY[]::uuid[])
    INTO linked_ids
  FROM "finding_creation_evidence_link" AS link
  WHERE link."organization_id" = stored_organization
    AND link."finding_observation_id" = observation_id;

  SELECT COALESCE(array_agg(qualifying.id ORDER BY qualifying.id::text COLLATE "C"), ARRAY[]::uuid[])
    INTO qualifying_ids
  FROM patchpilot_finding_creation_qualifying_evidence(
    stored_organization,
    stored_asset,
    stored_component,
    stored_vulnerability,
    stored_ingestion
  ) AS qualifying;

  IF linked_ids IS DISTINCT FROM qualifying_ids
    OR COALESCE(cardinality(linked_ids), 0) IS DISTINCT FROM stored_count
    OR stored_count < 1 THEN
    RAISE EXCEPTION 'finding creation evidence set is incomplete'
      USING ERRCODE = '23514';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM "audit_event" AS audit
    WHERE audit."organization_id" = stored_organization
      AND audit."subject_type" = 'finding'
      AND audit."subject_id" = stored_finding
      AND audit."action" = 'finding.created'
      AND audit."actor_membership_id" = stored_membership
      AND audit."correlation_id" = stored_correlation::text
      AND audit.xmin = pg_current_xact_id()::xid
  ) THEN
    RAISE EXCEPTION 'finding creation audit is incomplete'
      USING ERRCODE = '23514';
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER finding_observation_creation_complete
  AFTER INSERT ON "finding_observation"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_finding_creation_complete();

CREATE CONSTRAINT TRIGGER finding_creation_evidence_link_complete
  AFTER INSERT ON "finding_creation_evidence_link"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_finding_creation_complete();
