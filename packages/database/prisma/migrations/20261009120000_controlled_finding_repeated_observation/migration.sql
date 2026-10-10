-- Controlled Finding repeated-observation persistence.
-- Forward-only. One later observation of an existing open Finding.
-- Does not alter finding_identity_key or finding_observation_identity_key.
-- Does not rewrite creation rows, creation links, or Product Match Evidence.
-- Does not seed observations. Does not add a durable authority table.
-- Same-asset creation, pointer replacement, and observations serialize on the
-- existing organization-and-asset advisory lock. Different assets proceed
-- until the shared Product Match Evidence table lock.

CREATE TYPE "finding_repeated_observation_aggregate" AS ENUM (
  'affected',
  'unaffected',
  'unknown',
  'component_absent'
);

ALTER TABLE "finding_observation"
  ADD COLUMN "observation_purpose" VARCHAR(80),
  ADD COLUMN "observation_policy_id" VARCHAR(80),
  ADD COLUMN "observation_policy_version" SMALLINT,
  ADD COLUMN "aggregate_classification" "finding_repeated_observation_aggregate",
  ADD COLUMN "evidence_link_count" INTEGER,
  ADD COLUMN "absence_graph_completeness" "sbom_graph_completeness",
  ADD COLUMN "absence_component_count" INTEGER,
  ADD COLUMN "absence_dependency_edge_count" INTEGER;

ALTER TABLE "finding_observation"
  DROP CONSTRAINT "finding_observation_creation_shape_chk";

ALTER TABLE "finding_observation"
  ADD CONSTRAINT "finding_observation_shape_chk"
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
      AND "observation_purpose" IS NULL
      AND "observation_policy_id" IS NULL
      AND "observation_policy_version" IS NULL
      AND "aggregate_classification" IS NULL
      AND "evidence_link_count" IS NULL
      AND "absence_graph_completeness" IS NULL
      AND "absence_component_count" IS NULL
      AND "absence_dependency_edge_count" IS NULL
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
    OR
    (
      "method" = 'controlled_finding_repeated_observation'
      AND "occurrence_id" IS NULL
      AND "transition_classification" = 'evidence_observation'
      AND "creation_purpose" IS NULL
      AND "creation_policy_id" IS NULL
      AND "creation_policy_version" IS NULL
      AND "affected_evidence_count" IS NULL
      AND "observation_purpose" = 'record_finding_repeated_observation'
      AND "observation_policy_id" = 'finding_observation_policy_v1'
      AND "observation_policy_version" = 1
      AND "actor_membership_id" IS NOT NULL
      AND "correlation_id" IS NOT NULL
      AND "replay_fingerprint" ~ '^[a-f0-9]{64}$'
      AND "observed_at" = "created_at"
      AND "evidence_link_count" IS NOT NULL
      AND (
        (
          "aggregate_classification" = 'affected'
          AND "result" = 'present'
        )
        OR (
          "aggregate_classification" = 'unaffected'
          AND "result" = 'absent'
        )
        OR (
          "aggregate_classification" = 'unknown'
          AND "result" = 'inconclusive'
        )
        OR (
          "aggregate_classification" = 'component_absent'
          AND "result" = 'absent'
        )
      )
      AND (
        (
          "aggregate_classification" = 'component_absent'
          AND "evidence_link_count" = 0
          AND "absence_graph_completeness" IN ('complete', 'no_dependencies')
          AND "absence_component_count" >= 1
          AND "absence_dependency_edge_count" >= 0
          AND (
            (
              "absence_graph_completeness" = 'complete'
              AND "absence_dependency_edge_count" >= 1
            )
            OR (
              "absence_graph_completeness" = 'no_dependencies'
              AND "absence_dependency_edge_count" = 0
            )
          )
        )
        OR (
          "aggregate_classification" IN ('affected', 'unaffected', 'unknown')
          AND "evidence_link_count" >= 1
          AND "absence_graph_completeness" IS NULL
          AND "absence_component_count" IS NULL
          AND "absence_dependency_edge_count" IS NULL
        )
      )
      AND "evidence" = jsonb_build_object(
        'schemaVersion', 'finding_repeated_observation_v1',
        'purpose', "observation_purpose",
        'policyId', "observation_policy_id",
        'policyVersion', "observation_policy_version",
        'aggregate', "aggregate_classification",
        'mappedResult', "result",
        'evidenceLinkCount', "evidence_link_count",
        'replayFingerprint', "replay_fingerprint"
      )
    )
  );

CREATE OR REPLACE FUNCTION patchpilot_finding_observation_creation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW."method" = 'controlled_finding_creation' THEN
    IF current_setting('patchpilot.controlled_finding_creation', true) IS DISTINCT FROM 'on' THEN
      RAISE EXCEPTION 'finding creation observation rejected'
        USING ERRCODE = '42501';
    END IF;
  ELSIF NEW."method" = 'controlled_finding_repeated_observation' THEN
    IF current_setting('patchpilot.controlled_finding_repeated_observation', true) IS DISTINCT FROM 'on' THEN
      RAISE EXCEPTION 'finding repeated observation rejected'
        USING ERRCODE = '42501';
    END IF;
  ELSE
    RAISE EXCEPTION 'finding observation insert rejected'
      USING ERRCODE = '42501';
  END IF;
  IF NEW."observed_at" IS DISTINCT FROM CURRENT_TIMESTAMP
    OR NEW."created_at" IS DISTINCT FROM CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'finding observation timestamp must be database time'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION patchpilot_finding_reject_update()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF current_setting('patchpilot.controlled_finding_repeated_observation', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'finding update rejected'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."id" IS DISTINCT FROM OLD."id"
    OR NEW."organization_id" IS DISTINCT FROM OLD."organization_id"
    OR NEW."asset_id" IS DISTINCT FROM OLD."asset_id"
    OR NEW."vulnerability_id" IS DISTINCT FROM OLD."vulnerability_id"
    OR NEW."component_id" IS DISTINCT FROM OLD."component_id"
    OR NEW."component_occurrence_id" IS DISTINCT FROM OLD."component_occurrence_id"
    OR NEW."state" IS DISTINCT FROM OLD."state"
    OR NEW."first_observed_at" IS DISTINCT FROM OLD."first_observed_at"
    OR NEW."resolved_at" IS DISTINCT FROM OLD."resolved_at"
    OR NEW."reopened_at" IS DISTINCT FROM OLD."reopened_at"
    OR NEW."assigned_membership_id" IS DISTINCT FROM OLD."assigned_membership_id"
    OR NEW."assigned_team_id" IS DISTINCT FROM OLD."assigned_team_id"
    OR NEW."due_at" IS DISTINCT FROM OLD."due_at"
    OR NEW."current_risk_calculation_id" IS DISTINCT FROM OLD."current_risk_calculation_id"
    OR NEW."version" IS DISTINCT FROM OLD."version"
    OR NEW."created_at" IS DISTINCT FROM OLD."created_at"
  THEN
    RAISE EXCEPTION 'finding update rejected'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW."last_observed_at" IS DISTINCT FROM NEW."updated_at"
    OR NEW."last_observed_at" < OLD."last_observed_at"
  THEN
    RAISE EXCEPTION 'finding observation timestamp rejected'
      USING ERRCODE = '23514';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM "finding_observation" AS observation
    WHERE observation."organization_id" = NEW."organization_id"
      AND observation."finding_id" = NEW."id"
      AND observation."method" = 'controlled_finding_repeated_observation'
      AND observation."observed_at" = NEW."last_observed_at"
      AND observation.xmin = pg_current_xact_id()::xid
  ) THEN
    RAISE EXCEPTION 'finding observation timestamp rejected'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION patchpilot_finding_repeated_observation_current_evidence(
  p_organization_id uuid,
  p_asset_id uuid,
  p_component_id uuid,
  p_vulnerability_id uuid,
  p_sbom_ingestion_id uuid
)
RETURNS TABLE (
  id uuid,
  component_occurrence_id uuid,
  outcome "match_evaluation_outcome"
)
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $$
  SELECT evidence."id",
         evidence."component_occurrence_id",
         evidence."outcome"
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
    AND evidence."outcome" IN ('affected', 'unaffected', 'unknown')
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

CREATE TABLE "finding_repeated_observation_evidence_link" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "organization_id" UUID NOT NULL,
  "finding_id" UUID NOT NULL,
  "finding_observation_id" UUID NOT NULL,
  "sbom_id" UUID NOT NULL,
  "product_match_evaluation_evidence_id" UUID,
  "asset_id" UUID NOT NULL,
  "component_id" UUID NOT NULL,
  "vulnerability_id" UUID NOT NULL,
  "sbom_ingestion_id" UUID NOT NULL,
  "component_occurrence_id" UUID NOT NULL,
  "support_kind" VARCHAR(64) NOT NULL,
  "outcome" "match_evaluation_outcome",
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "finding_repeated_observation_evidence_link_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "finding_repeated_observation_evidence_link_shape_chk" CHECK (
    (
      "support_kind" = 'product_match_evidence'
      AND "product_match_evaluation_evidence_id" IS NOT NULL
      AND "outcome" IN ('affected', 'unaffected', 'unknown')
    )
    OR (
      "support_kind" = 'unknown_version_occurrence'
      AND "product_match_evaluation_evidence_id" IS NULL
      AND "outcome" IS NULL
    )
  )
);

CREATE UNIQUE INDEX "finding_repeated_observation_evidence_link_org_id_key"
  ON "finding_repeated_observation_evidence_link" ("organization_id", "id");

CREATE UNIQUE INDEX "finding_repeated_observation_evidence_link_occurrence_uidx"
  ON "finding_repeated_observation_evidence_link" (
    "organization_id",
    "finding_observation_id",
    "component_occurrence_id"
  );

CREATE UNIQUE INDEX "finding_repeated_observation_evidence_link_evidence_uidx"
  ON "finding_repeated_observation_evidence_link" (
    "organization_id",
    "product_match_evaluation_evidence_id"
  )
  WHERE "product_match_evaluation_evidence_id" IS NOT NULL;

ALTER TABLE "finding_repeated_observation_evidence_link"
  ADD CONSTRAINT "finding_repeated_observation_evidence_link_finding_fkey"
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

ALTER TABLE "finding_repeated_observation_evidence_link"
  ADD CONSTRAINT "finding_repeated_observation_evidence_link_observation_fkey"
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

ALTER TABLE "finding_repeated_observation_evidence_link"
  ADD CONSTRAINT "finding_repeated_observation_evidence_link_evidence_fkey"
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

ALTER TABLE "finding_repeated_observation_evidence_link"
  ADD CONSTRAINT "finding_repeated_observation_evidence_link_occurrence_fkey"
  FOREIGN KEY (
    "organization_id",
    "component_occurrence_id",
    "asset_id",
    "component_id"
  )
  REFERENCES "component_occurrence" (
    "organization_id",
    "id",
    "asset_id",
    "component_id"
  )
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "finding_repeated_observation_evidence_link"
  ADD CONSTRAINT "finding_repeated_observation_evidence_link_ingestion_fkey"
  FOREIGN KEY (
    "organization_id",
    "sbom_ingestion_id",
    "sbom_id"
  )
  REFERENCES "sbom_ingestion" (
    "organization_id",
    "id",
    "sbom_id"
  )
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE OR REPLACE FUNCTION patchpilot_finding_repeated_observation_link_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  observation_xmin xid;
  observation_method text;
  evidence_outcome "match_evaluation_outcome";
  version_known boolean;
BEGIN
  IF current_setting('patchpilot.controlled_finding_repeated_observation', true) IS DISTINCT FROM 'on' THEN
    RAISE EXCEPTION 'finding repeated observation link rejected'
      USING ERRCODE = '42501';
  END IF;
  IF NEW."created_at" IS DISTINCT FROM CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'finding repeated observation timestamp must be database time'
      USING ERRCODE = '23514';
  END IF;
  SELECT observation.xmin, observation."method"
    INTO observation_xmin, observation_method
  FROM "finding_observation" AS observation
  WHERE observation."organization_id" = NEW."organization_id"
    AND observation."id" = NEW."finding_observation_id"
    AND observation."finding_id" = NEW."finding_id"
    AND observation."sbom_ingestion_id" = NEW."sbom_ingestion_id";
  IF observation_method IS DISTINCT FROM 'controlled_finding_repeated_observation'
    OR observation_xmin IS DISTINCT FROM pg_current_xact_id()::xid THEN
    RAISE EXCEPTION 'finding repeated observation link rejected'
      USING ERRCODE = '23514';
  END IF;
  SELECT occurrence."version_known"
    INTO version_known
  FROM "component_occurrence" AS occurrence
  WHERE occurrence."organization_id" = NEW."organization_id"
    AND occurrence."id" = NEW."component_occurrence_id"
    AND occurrence."asset_id" = NEW."asset_id"
    AND occurrence."component_id" = NEW."component_id"
    AND occurrence."sbom_ingestion_id" = NEW."sbom_ingestion_id";
  IF version_known IS NULL THEN
    RAISE EXCEPTION 'finding repeated observation link rejected'
      USING ERRCODE = '23514';
  END IF;
  IF NEW."support_kind" = 'unknown_version_occurrence' THEN
    IF version_known IS DISTINCT FROM FALSE THEN
      RAISE EXCEPTION 'finding repeated observation link rejected'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF version_known IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'finding repeated observation link rejected'
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
  IF evidence_outcome IS NULL OR evidence_outcome IS DISTINCT FROM NEW."outcome" THEN
    RAISE EXCEPTION 'finding repeated observation link rejected'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER finding_repeated_observation_evidence_link_guard
  BEFORE INSERT ON "finding_repeated_observation_evidence_link"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_finding_repeated_observation_link_guard();

CREATE TRIGGER finding_repeated_observation_evidence_link_append_only
  BEFORE UPDATE OR DELETE ON "finding_repeated_observation_evidence_link"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE OR REPLACE FUNCTION patchpilot_finding_repeated_observation_complete()
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
  stored_sbom uuid;
  stored_aggregate "finding_repeated_observation_aggregate";
  stored_observed timestamptz;
  stored_absence_graph "sbom_graph_completeness";
  stored_absence_components integer;
  stored_absence_edges integer;
  creation_ingestion uuid;
  link_count integer;
  occurrence_count integer;
  live_components integer;
  live_edges integer;
  target_components integer;
  target_edges integer;
  target_graph "sbom_graph_completeness";
  target_state text;
  target_normalization text;
  later_than_creation boolean;
BEGIN
  IF TG_TABLE_NAME = 'finding_observation' THEN
    IF NEW."method" IS DISTINCT FROM 'controlled_finding_repeated_observation' THEN
      RETURN NULL;
    END IF;
    observation_id := NEW."id";
  ELSE
    observation_id := NEW."finding_observation_id";
  END IF;

  SELECT observation."organization_id",
         observation."finding_id",
         observation."sbom_ingestion_id",
         observation."sbom_id",
         observation."evidence_link_count",
         observation."actor_membership_id",
         observation."correlation_id",
         observation."aggregate_classification",
         observation."observed_at",
         observation."absence_graph_completeness",
         observation."absence_component_count",
         observation."absence_dependency_edge_count",
         finding."asset_id",
         finding."component_id",
         finding."vulnerability_id"
    INTO stored_organization,
         stored_finding,
         stored_ingestion,
         stored_sbom,
         stored_count,
         stored_membership,
         stored_correlation,
         stored_aggregate,
         stored_observed,
         stored_absence_graph,
         stored_absence_components,
         stored_absence_edges,
         stored_asset,
         stored_component,
         stored_vulnerability
  FROM "finding_observation" AS observation
  INNER JOIN "finding" AS finding
    ON finding."organization_id" = observation."organization_id"
   AND finding."id" = observation."finding_id"
   AND finding."state" = 'open'
   AND finding."version" = 1
   AND finding."last_observed_at" = observation."observed_at"
   AND finding."updated_at" = observation."observed_at"
  WHERE observation."organization_id" = NEW."organization_id"
    AND observation."id" = observation_id
    AND observation."method" = 'controlled_finding_repeated_observation';

  IF stored_finding IS NULL THEN
    RAISE EXCEPTION 'finding repeated observation is incomplete'
      USING ERRCODE = '23514';
  END IF;

  SELECT creation."sbom_ingestion_id"
    INTO creation_ingestion
  FROM "finding_observation" AS creation
  INNER JOIN "sbom_ingestion" AS ingestion
    ON ingestion."organization_id" = creation."organization_id"
   AND ingestion."id" = creation."sbom_ingestion_id"
   AND ingestion."asset_id" = stored_asset
   AND ingestion."state" = 'completed'
   AND ingestion."normalization_version" = '2'
  WHERE creation."organization_id" = stored_organization
    AND creation."finding_id" = stored_finding
    AND creation."method" = 'controlled_finding_creation';
  IF creation_ingestion IS NULL THEN
    RAISE EXCEPTION 'finding repeated observation is incomplete'
      USING ERRCODE = '23514';
  END IF;

  SELECT (
           target_sbom."received_at",
           target_ingestion."created_at",
           target_ingestion."id"
         ) > (
           creation_sbom."received_at",
           creation_ingestion_row."created_at",
           creation_ingestion_row."id"
         ),
         target_ingestion."state"::text,
         target_ingestion."normalization_version",
         target_ingestion."graph_completeness",
         target_ingestion."component_count",
         target_ingestion."dependency_edge_count"
    INTO later_than_creation,
         target_state,
         target_normalization,
         target_graph,
         target_components,
         target_edges
  FROM "sbom_ingestion" AS target_ingestion
  INNER JOIN "sbom" AS target_sbom
    ON target_sbom."organization_id" = target_ingestion."organization_id"
   AND target_sbom."id" = target_ingestion."sbom_id"
  INNER JOIN "sbom_ingestion" AS creation_ingestion_row
    ON creation_ingestion_row."organization_id" = stored_organization
   AND creation_ingestion_row."id" = creation_ingestion
  INNER JOIN "sbom" AS creation_sbom
    ON creation_sbom."organization_id" = creation_ingestion_row."organization_id"
   AND creation_sbom."id" = creation_ingestion_row."sbom_id"
  INNER JOIN "asset" AS asset
    ON asset."organization_id" = stored_organization
   AND asset."id" = stored_asset
   AND asset."last_successful_sbom_ingestion_id" = target_ingestion."id"
  WHERE target_ingestion."organization_id" = stored_organization
    AND target_ingestion."id" = stored_ingestion
    AND target_ingestion."asset_id" = stored_asset
    AND target_ingestion."sbom_id" = stored_sbom;

  IF later_than_creation IS DISTINCT FROM TRUE
    OR target_state IS DISTINCT FROM 'completed'
    OR target_normalization IS DISTINCT FROM '2' THEN
    RAISE EXCEPTION 'finding repeated observation is incomplete'
      USING ERRCODE = '23514';
  END IF;

  SELECT COUNT(*)::int
    INTO link_count
  FROM "finding_repeated_observation_evidence_link" AS link
  WHERE link."organization_id" = stored_organization
    AND link."finding_observation_id" = observation_id;

  SELECT COUNT(*)::int
    INTO occurrence_count
  FROM "component_occurrence" AS occurrence
  WHERE occurrence."organization_id" = stored_organization
    AND occurrence."asset_id" = stored_asset
    AND occurrence."component_id" = stored_component
    AND occurrence."sbom_ingestion_id" = stored_ingestion;

  IF stored_aggregate = 'component_absent' THEN
    SELECT COUNT(*)::int
      INTO live_components
    FROM "component_occurrence" AS occurrence
    WHERE occurrence."organization_id" = stored_organization
      AND occurrence."sbom_ingestion_id" = stored_ingestion;
    SELECT COUNT(*)::int
      INTO live_edges
    FROM "dependency_relationship" AS edge
    WHERE edge."organization_id" = stored_organization
      AND edge."sbom_ingestion_id" = stored_ingestion;
    IF link_count <> 0
      OR stored_count <> 0
      OR occurrence_count <> 0
      OR target_graph IS DISTINCT FROM stored_absence_graph
      OR target_components IS DISTINCT FROM stored_absence_components
      OR target_edges IS DISTINCT FROM stored_absence_edges
      OR live_components IS DISTINCT FROM stored_absence_components
      OR live_edges IS DISTINCT FROM stored_absence_edges
      OR stored_absence_components < 1
      OR (
        target_graph IS DISTINCT FROM 'complete'::"sbom_graph_completeness"
        AND target_graph IS DISTINCT FROM 'no_dependencies'::"sbom_graph_completeness"
      )
      OR (target_graph = 'complete'::"sbom_graph_completeness" AND live_edges < 1)
      OR (target_graph = 'no_dependencies'::"sbom_graph_completeness" AND live_edges <> 0) THEN
      RAISE EXCEPTION 'finding repeated observation is incomplete'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF link_count IS DISTINCT FROM stored_count
      OR link_count IS DISTINCT FROM occurrence_count
      OR link_count < 1
      OR stored_absence_graph IS NOT NULL THEN
      RAISE EXCEPTION 'finding repeated observation is incomplete'
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
      SELECT 1
      FROM "component_occurrence" AS occurrence
      WHERE occurrence."organization_id" = stored_organization
        AND occurrence."asset_id" = stored_asset
        AND occurrence."component_id" = stored_component
        AND occurrence."sbom_ingestion_id" = stored_ingestion
        AND (
          occurrence."version_known" IS NULL
          OR NOT EXISTS (
            SELECT 1
            FROM "finding_repeated_observation_evidence_link" AS link
            WHERE link."organization_id" = stored_organization
              AND link."finding_observation_id" = observation_id
              AND link."component_occurrence_id" = occurrence."id"
          )
        )
    ) THEN
      RAISE EXCEPTION 'finding repeated observation is incomplete'
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
      SELECT 1
      FROM "component_occurrence" AS occurrence
      WHERE occurrence."organization_id" = stored_organization
        AND occurrence."asset_id" = stored_asset
        AND occurrence."component_id" = stored_component
        AND occurrence."sbom_ingestion_id" = stored_ingestion
        AND occurrence."version_known" IS TRUE
        AND (
          SELECT COUNT(*)
          FROM patchpilot_finding_repeated_observation_current_evidence(
            stored_organization,
            stored_asset,
            stored_component,
            stored_vulnerability,
            stored_ingestion
          ) AS current_evidence
          WHERE current_evidence.component_occurrence_id = occurrence."id"
        ) <> 1
    ) THEN
      RAISE EXCEPTION 'finding repeated observation is incomplete'
        USING ERRCODE = '23514';
    END IF;
    IF EXISTS (
      SELECT 1
      FROM "finding_repeated_observation_evidence_link" AS link
      INNER JOIN "component_occurrence" AS occurrence
        ON occurrence."organization_id" = link."organization_id"
       AND occurrence."id" = link."component_occurrence_id"
      WHERE link."organization_id" = stored_organization
        AND link."finding_observation_id" = observation_id
        AND (
          (
            occurrence."version_known" IS TRUE
            AND (
              link."support_kind" IS DISTINCT FROM 'product_match_evidence'
              OR NOT EXISTS (
                SELECT 1
                FROM patchpilot_finding_repeated_observation_current_evidence(
                  stored_organization,
                  stored_asset,
                  stored_component,
                  stored_vulnerability,
                  stored_ingestion
                ) AS current_evidence
                WHERE current_evidence.id = link."product_match_evaluation_evidence_id"
                  AND current_evidence.component_occurrence_id = link."component_occurrence_id"
                  AND current_evidence.outcome = link."outcome"
              )
            )
          )
          OR (
            occurrence."version_known" IS FALSE
            AND (
              link."support_kind" IS DISTINCT FROM 'unknown_version_occurrence'
              OR link."product_match_evaluation_evidence_id" IS NOT NULL
              OR EXISTS (
                SELECT 1
                FROM "product_match_evaluation_evidence" AS evidence
                WHERE evidence."organization_id" = link."organization_id"
                  AND evidence."component_occurrence_id" = link."component_occurrence_id"
              )
            )
          )
        )
    ) THEN
      RAISE EXCEPTION 'finding repeated observation is incomplete'
        USING ERRCODE = '23514';
    END IF;
    IF stored_aggregate = 'affected' THEN
      IF NOT EXISTS (
        SELECT 1
        FROM "finding_repeated_observation_evidence_link" AS link
        WHERE link."organization_id" = stored_organization
          AND link."finding_observation_id" = observation_id
          AND link."outcome" = 'affected'
      ) THEN
        RAISE EXCEPTION 'finding repeated observation is incomplete'
          USING ERRCODE = '23514';
      END IF;
    ELSIF stored_aggregate = 'unknown' THEN
      IF EXISTS (
        SELECT 1
        FROM "finding_repeated_observation_evidence_link" AS link
        WHERE link."organization_id" = stored_organization
          AND link."finding_observation_id" = observation_id
          AND link."outcome" = 'affected'
      ) OR NOT EXISTS (
        SELECT 1
        FROM "finding_repeated_observation_evidence_link" AS link
        WHERE link."organization_id" = stored_organization
          AND link."finding_observation_id" = observation_id
          AND (
            link."outcome" = 'unknown'
            OR link."support_kind" = 'unknown_version_occurrence'
          )
      ) THEN
        RAISE EXCEPTION 'finding repeated observation is incomplete'
          USING ERRCODE = '23514';
      END IF;
    ELSIF stored_aggregate = 'unaffected' THEN
      IF EXISTS (
        SELECT 1
        FROM "finding_repeated_observation_evidence_link" AS link
        WHERE link."organization_id" = stored_organization
          AND link."finding_observation_id" = observation_id
          AND (
            link."outcome" IS DISTINCT FROM 'unaffected'
            OR link."support_kind" IS DISTINCT FROM 'product_match_evidence'
          )
      ) THEN
        RAISE EXCEPTION 'finding repeated observation is incomplete'
          USING ERRCODE = '23514';
      END IF;
    ELSE
      RAISE EXCEPTION 'finding repeated observation is incomplete'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM "audit_event" AS audit
    WHERE audit."organization_id" = stored_organization
      AND audit."subject_type" = 'finding'
      AND audit."subject_id" = stored_finding
      AND audit."action" = 'finding.observed'
      AND audit."actor_membership_id" = stored_membership
      AND audit."correlation_id" = stored_correlation::text
      AND audit.xmin = pg_current_xact_id()::xid
      AND audit."payload" = jsonb_build_object(
        'schemaVersion', 1,
        'metadata', jsonb_build_object(
          'purpose', 'record_finding_repeated_observation',
          'policyId', 'finding_observation_policy_v1',
          'policyVersion', 1,
          'aggregate', stored_aggregate,
          'sbomIngestionId', stored_ingestion,
          'evidenceLinkCount', stored_count,
          'supportClassification', CASE
            WHEN stored_aggregate = 'component_absent' THEN 'component_absence'
            ELSE 'evidence_set'
          END
        )
      )
  ) THEN
    RAISE EXCEPTION 'finding repeated observation audit is incomplete'
      USING ERRCODE = '23514';
  END IF;

  RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER finding_repeated_observation_complete
  AFTER INSERT ON "finding_observation"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_finding_repeated_observation_complete();

CREATE CONSTRAINT TRIGGER finding_repeated_observation_evidence_link_complete
  AFTER INSERT ON "finding_repeated_observation_evidence_link"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_finding_repeated_observation_complete();
