-- Session 14 Batch 3: immutable npm match-evaluation evidence.
-- Forward-only. Does not edit earlier migrations.
-- New tables only. No Finding tables, no seeds, no evaluator execution.

CREATE TYPE "match_evaluation_outcome" AS ENUM (
  'affected',
  'unaffected',
  'unknown'
);

CREATE TYPE "match_evaluation_explanation_code" AS ENUM (
  'affected_within_introduced_fixed_range',
  'affected_at_introduced_boundary',
  'affected_within_last_affected_range',
  'affected_explicit_version_equal',
  'unaffected_before_introduced',
  'unaffected_at_or_after_fixed_boundary',
  'unaffected_after_last_affected',
  'unaffected_outside_all_ranges',
  'unknown_unsupported_ecosystem',
  'unknown_invalid_package_identity',
  'unknown_invalid_observed_version',
  'unknown_unsupported_version_syntax',
  'unknown_invalid_range',
  'unknown_unsupported_range_type',
  'unknown_unsupported_event',
  'unknown_contradictory_events',
  'unknown_incomplete_evidence',
  'unknown_untrusted_advisory_evidence',
  'unknown_kev_not_affectedness_authority',
  'unknown_capacity_exceeded',
  'unknown_policy_mismatch',
  'unknown_evaluator_unavailable',
  'unknown_comparator_not_implemented',
  'unknown_range_order_not_verified',
  'unknown_prerelease_membership_not_proven',
  'unknown_withdrawn_advisory',
  'unknown_internal_failure'
);

CREATE TYPE "match_evaluation_advisory_source" AS ENUM (
  'synthetic_fixture',
  'cisa_kev',
  'unrecognized'
);

CREATE TYPE "match_evaluation_advisory_origin" AS ENUM (
  'synthetic',
  'untrusted_not_recorded'
);

CREATE TYPE "match_evaluation_version_retention" AS ENUM (
  'retained',
  'omitted_over_capacity'
);

CREATE TYPE "match_evaluation_version_classification" AS ENUM (
  'valid_strict_semver',
  'absent',
  'malformed',
  'unsupported',
  'capacity_exceeded',
  'not_classified'
);

CREATE TABLE "match_evaluation_evidence" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "organization_id" UUID NOT NULL,
  "component_occurrence_id" UUID NOT NULL,
  "asset_id" UUID NOT NULL,
  "sbom_id" UUID NOT NULL,
  "sbom_ingestion_id" UUID NOT NULL,
  "component_id" UUID NOT NULL,
  "sbom_sha256" TEXT NOT NULL,
  "component_identity_key" VARCHAR(2048) NOT NULL,
  "version_known" BOOLEAN NOT NULL,
  "component_evidence_fingerprint" TEXT NOT NULL,
  "evidence_schema_version" VARCHAR(80) NOT NULL,
  "evaluation_id" UUID NOT NULL,
  "evaluator_id" VARCHAR(80) NOT NULL,
  "evaluator_version" VARCHAR(64) NOT NULL,
  "evaluator_implementation" VARCHAR(64) NOT NULL,
  "policy_id" VARCHAR(80) NOT NULL,
  "ecosystem" VARCHAR(16) NOT NULL,
  "package_namespace" VARCHAR(214),
  "package_name" VARCHAR(214) NOT NULL,
  "package_identity_key" VARCHAR(1024) NOT NULL,
  "raw_observed_version" VARCHAR(256) NOT NULL,
  "raw_observed_version_sha256" TEXT NOT NULL,
  "raw_observed_version_retention" "match_evaluation_version_retention" NOT NULL,
  "parsed_version_classification" "match_evaluation_version_classification" NOT NULL,
  "advisory_identity" VARCHAR(512) NOT NULL,
  "advisory_source_classification" "match_evaluation_advisory_source" NOT NULL,
  "advisory_evidence_fingerprint" TEXT NOT NULL,
  "advisory_evidence_origin" "match_evaluation_advisory_origin" NOT NULL,
  "range_fingerprint" TEXT NOT NULL,
  "outcome" "match_evaluation_outcome" NOT NULL,
  "replay_fingerprint" TEXT NOT NULL,
  "finding_creation" VARCHAR(32) NOT NULL,
  "suppression_authority" BOOLEAN NOT NULL DEFAULT false,
  "evaluation_timestamp_classification" VARCHAR(16) NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "match_evaluation_evidence_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "match_evaluation_explanation" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "organization_id" UUID NOT NULL,
  "match_evaluation_evidence_id" UUID NOT NULL,
  "ordinal" SMALLINT NOT NULL,
  "explanation_code" "match_evaluation_explanation_code" NOT NULL,

  CONSTRAINT "match_evaluation_explanation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "match_evaluation_evidence_evaluation_uidx"
  ON "match_evaluation_evidence" ("evaluation_id");

CREATE UNIQUE INDEX "match_evaluation_evidence_occurrence_replay_uidx"
  ON "match_evaluation_evidence" ("organization_id", "component_occurrence_id", "replay_fingerprint");

CREATE INDEX "match_evaluation_evidence_replay_idx"
  ON "match_evaluation_evidence" ("replay_fingerprint");

CREATE UNIQUE INDEX "match_evaluation_evidence_org_id_key"
  ON "match_evaluation_evidence" ("organization_id", "id");

CREATE INDEX "match_evaluation_evidence_org_occurrence_idx"
  ON "match_evaluation_evidence" ("organization_id", "component_occurrence_id");

CREATE INDEX "match_evaluation_evidence_org_advisory_idx"
  ON "match_evaluation_evidence" ("organization_id", "advisory_identity");

CREATE UNIQUE INDEX "match_evaluation_explanation_ordinal_uidx"
  ON "match_evaluation_explanation" ("match_evaluation_evidence_id", "ordinal");

CREATE UNIQUE INDEX "match_evaluation_explanation_code_uidx"
  ON "match_evaluation_explanation" ("match_evaluation_evidence_id", "explanation_code");

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_organization_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organization"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_occurrence_fkey"
  FOREIGN KEY ("organization_id", "component_occurrence_id", "asset_id", "component_id")
  REFERENCES "component_occurrence"("organization_id", "id", "asset_id", "component_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_component_fkey"
  FOREIGN KEY ("organization_id", "component_id")
  REFERENCES "component"("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_sbom_fkey"
  FOREIGN KEY ("organization_id", "sbom_id", "asset_id")
  REFERENCES "sbom"("organization_id", "id", "asset_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_ingestion_fkey"
  FOREIGN KEY ("organization_id", "sbom_ingestion_id", "sbom_id")
  REFERENCES "sbom_ingestion"("organization_id", "id", "sbom_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "match_evaluation_explanation"
  ADD CONSTRAINT "match_evaluation_explanation_evidence_fkey"
  FOREIGN KEY ("organization_id", "match_evaluation_evidence_id")
  REFERENCES "match_evaluation_evidence"("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_schema_chk"
  CHECK ("evidence_schema_version" = 'osv_first_ecosystem_match_evaluation_evidence_v1');

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_evaluator_chk"
  CHECK (
    "evaluator_id" = 'osv_first_ecosystem_affected_version_evaluator_v1'
    AND "evaluator_version" = 'session_14_batch_2_in_memory'
    AND "evaluator_implementation" = 'in_memory_uncomposed'
    AND "policy_id" = 'osv_first_ecosystem_matching_architecture_v1'
    AND "ecosystem" = 'npm'
    AND "evaluation_timestamp_classification" = 'not_used'
  );

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_authority_chk"
  CHECK (
    "finding_creation" = 'unavailable'
    AND "suppression_authority" = false
  );

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_retention_chk"
  CHECK ("raw_observed_version_retention" = 'retained');

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_origin_chk"
  CHECK (
    (
      "advisory_source_classification" = 'synthetic_fixture'
      AND "advisory_evidence_origin" = 'synthetic'
    )
    OR (
      "advisory_source_classification" = 'cisa_kev'
      AND "advisory_evidence_origin" = 'untrusted_not_recorded'
      AND "outcome" = 'unknown'
    )
    OR (
      "advisory_source_classification" = 'unrecognized'
      AND "advisory_evidence_origin" = 'untrusted_not_recorded'
      AND "outcome" = 'unknown'
    )
  );

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_fingerprint_chk"
  CHECK (
    char_length("component_evidence_fingerprint") = 64
    AND "component_evidence_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("raw_observed_version_sha256") = 64
    AND "raw_observed_version_sha256" ~ '^[a-f0-9]{64}$'
    AND char_length("advisory_evidence_fingerprint") = 64
    AND "advisory_evidence_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("range_fingerprint") = 64
    AND "range_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("replay_fingerprint") = 64
    AND "replay_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("sbom_sha256") = 64
    AND "sbom_sha256" ~ '^[a-f0-9]{64}$'
  );

ALTER TABLE "match_evaluation_evidence"
  ADD CONSTRAINT "match_evaluation_evidence_bounds_chk"
  CHECK (
    octet_length("raw_observed_version") <= 256
    AND octet_length("package_name") BETWEEN 1 AND 214
    AND (
      "package_namespace" IS NULL
      OR octet_length("package_namespace") BETWEEN 1 AND 214
    )
    AND octet_length("package_identity_key") BETWEEN 1 AND 1024
    AND octet_length("component_identity_key") BETWEEN 1 AND 2048
    AND octet_length("advisory_identity") BETWEEN 1 AND 512
    AND "package_identity_key" = 'npm' || E'\x1f' || COALESCE("package_namespace", '') || E'\x1f' || "package_name"
  );

ALTER TABLE "match_evaluation_explanation"
  ADD CONSTRAINT "match_evaluation_explanation_ordinal_chk"
  CHECK ("ordinal" BETWEEN 1 AND 8);

CREATE FUNCTION patchpilot_match_evaluation_code_outcome(
  code "match_evaluation_explanation_code"
) RETURNS "match_evaluation_outcome"
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, public
AS $$
  SELECT CASE
    WHEN code IN (
      'affected_within_introduced_fixed_range',
      'affected_at_introduced_boundary',
      'affected_within_last_affected_range',
      'affected_explicit_version_equal'
    ) THEN 'affected'::"match_evaluation_outcome"
    WHEN code IN (
      'unaffected_before_introduced',
      'unaffected_at_or_after_fixed_boundary',
      'unaffected_after_last_affected',
      'unaffected_outside_all_ranges'
    ) THEN 'unaffected'::"match_evaluation_outcome"
    ELSE 'unknown'::"match_evaluation_outcome"
  END;
$$;

CREATE FUNCTION patchpilot_match_evaluation_evidence_bind_parents()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  occurrence "component_occurrence"%ROWTYPE;
  component_row "component"%ROWTYPE;
  sbom_row "sbom"%ROWTYPE;
  ingestion_row "sbom_ingestion"%ROWTYPE;
BEGIN
  SELECT * INTO occurrence
  FROM "component_occurrence"
  WHERE "organization_id" = NEW."organization_id"
    AND "id" = NEW."component_occurrence_id"
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'match evaluation component occurrence is absent'
      USING ERRCODE = '23503';
  END IF;

  IF occurrence."asset_id" IS DISTINCT FROM NEW."asset_id"
    OR occurrence."sbom_id" IS DISTINCT FROM NEW."sbom_id"
    OR occurrence."sbom_ingestion_id" IS DISTINCT FROM NEW."sbom_ingestion_id"
    OR occurrence."component_id" IS DISTINCT FROM NEW."component_id"
    OR convert_to(occurrence."version", 'UTF8')
      IS DISTINCT FROM convert_to(NEW."raw_observed_version", 'UTF8')
    OR occurrence."version_known" IS DISTINCT FROM NEW."version_known"
  THEN
    RAISE EXCEPTION 'match evaluation component evidence does not match'
      USING ERRCODE = '23514';
  END IF;

  SELECT * INTO component_row
  FROM "component"
  WHERE "organization_id" = NEW."organization_id"
    AND "id" = NEW."component_id"
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'match evaluation component occurrence is absent'
      USING ERRCODE = '23503';
  END IF;

  IF component_row."identity_state" IS DISTINCT FROM 'resolved'
    OR component_row."ecosystem" IS DISTINCT FROM 'npm'
    OR convert_to(component_row."name", 'UTF8')
      IS DISTINCT FROM convert_to(NEW."package_name", 'UTF8')
    OR convert_to(component_row."namespace", 'UTF8')
      IS DISTINCT FROM convert_to(NEW."package_namespace", 'UTF8')
    OR convert_to(component_row."identity_key", 'UTF8')
      IS DISTINCT FROM convert_to(NEW."component_identity_key", 'UTF8')
  THEN
    RAISE EXCEPTION 'match evaluation component evidence does not match'
      USING ERRCODE = '23514';
  END IF;

  SELECT * INTO sbom_row
  FROM "sbom"
  WHERE "organization_id" = NEW."organization_id"
    AND "id" = NEW."sbom_id"
    AND "asset_id" = NEW."asset_id"
  FOR SHARE;

  IF NOT FOUND
    OR convert_to(rtrim(sbom_row."sha256"::text, ' '), 'UTF8')
      IS DISTINCT FROM convert_to(NEW."sbom_sha256", 'UTF8')
  THEN
    RAISE EXCEPTION 'match evaluation component evidence does not match'
      USING ERRCODE = '23514';
  END IF;

  SELECT * INTO ingestion_row
  FROM "sbom_ingestion"
  WHERE "organization_id" = NEW."organization_id"
    AND "id" = NEW."sbom_ingestion_id"
    AND "sbom_id" = NEW."sbom_id"
    AND "asset_id" = NEW."asset_id"
  FOR SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'match evaluation component evidence does not match'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_match_evaluation_explanations_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  explanation_count integer;
  ordinals_ok boolean;
  order_ok boolean;
  outcome_ok boolean;
  tenant_ok boolean;
BEGIN
  SELECT COUNT(*)::integer INTO explanation_count
  FROM "match_evaluation_explanation"
  WHERE "match_evaluation_evidence_id" = NEW."id";

  IF explanation_count < 1 OR explanation_count > 8 THEN
    RAISE EXCEPTION 'match evaluation explanation set is incomplete'
      USING ERRCODE = '23514';
  END IF;

  SELECT
    MIN("ordinal") = 1
    AND MAX("ordinal") = explanation_count
    AND COUNT(*) = COUNT(DISTINCT "ordinal")
    AND COUNT(*) = COUNT(DISTINCT "explanation_code")
  INTO ordinals_ok
  FROM "match_evaluation_explanation"
  WHERE "match_evaluation_evidence_id" = NEW."id";

  IF ordinals_ok IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'match evaluation explanation ordinals are not contiguous'
      USING ERRCODE = '23514';
  END IF;

  SELECT bool_and(previous_code IS NULL OR "explanation_code" > previous_code)
  INTO order_ok
  FROM (
    SELECT
      "explanation_code",
      lag("explanation_code") OVER (ORDER BY "ordinal") AS previous_code
    FROM "match_evaluation_explanation"
    WHERE "match_evaluation_evidence_id" = NEW."id"
  ) ordered;

  IF order_ok IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'match evaluation explanation order is not canonical'
      USING ERRCODE = '23514';
  END IF;

  SELECT bool_and(patchpilot_match_evaluation_code_outcome("explanation_code") = NEW."outcome")
  INTO outcome_ok
  FROM "match_evaluation_explanation"
  WHERE "match_evaluation_evidence_id" = NEW."id";

  IF outcome_ok IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'match evaluation explanation outcome disagrees'
      USING ERRCODE = '23514';
  END IF;

  SELECT bool_and("organization_id" = NEW."organization_id")
  INTO tenant_ok
  FROM "match_evaluation_explanation"
  WHERE "match_evaluation_evidence_id" = NEW."id";

  IF tenant_ok IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'match evaluation explanation tenant disagrees'
      USING ERRCODE = '23514';
  END IF;

  IF NEW."advisory_source_classification" = 'cisa_kev' THEN
    IF explanation_count <> 1 OR NOT EXISTS (
      SELECT 1
      FROM "match_evaluation_explanation"
      WHERE "match_evaluation_evidence_id" = NEW."id"
        AND "explanation_code" = 'unknown_kev_not_affectedness_authority'
    ) THEN
      RAISE EXCEPTION 'match evaluation kev evidence is not unknown'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM "match_evaluation_evidence" peer
    WHERE peer."replay_fingerprint" = NEW."replay_fingerprint"
      AND peer."id" <> NEW."id"
      AND (
        peer."evaluator_id" IS DISTINCT FROM NEW."evaluator_id"
        OR peer."evaluator_version" IS DISTINCT FROM NEW."evaluator_version"
        OR peer."evaluator_implementation" IS DISTINCT FROM NEW."evaluator_implementation"
        OR peer."policy_id" IS DISTINCT FROM NEW."policy_id"
        OR peer."ecosystem" IS DISTINCT FROM NEW."ecosystem"
        OR convert_to(peer."package_namespace", 'UTF8')
          IS DISTINCT FROM convert_to(NEW."package_namespace", 'UTF8')
        OR convert_to(peer."package_name", 'UTF8')
          IS DISTINCT FROM convert_to(NEW."package_name", 'UTF8')
        OR convert_to(peer."package_identity_key", 'UTF8')
          IS DISTINCT FROM convert_to(NEW."package_identity_key", 'UTF8')
        OR convert_to(peer."raw_observed_version", 'UTF8')
          IS DISTINCT FROM convert_to(NEW."raw_observed_version", 'UTF8')
        OR peer."raw_observed_version_sha256" IS DISTINCT FROM NEW."raw_observed_version_sha256"
        OR peer."raw_observed_version_retention" IS DISTINCT FROM NEW."raw_observed_version_retention"
        OR peer."parsed_version_classification" IS DISTINCT FROM NEW."parsed_version_classification"
        OR convert_to(peer."advisory_identity", 'UTF8')
          IS DISTINCT FROM convert_to(NEW."advisory_identity", 'UTF8')
        OR peer."advisory_source_classification" IS DISTINCT FROM NEW."advisory_source_classification"
        OR peer."advisory_evidence_fingerprint" IS DISTINCT FROM NEW."advisory_evidence_fingerprint"
        OR peer."advisory_evidence_origin" IS DISTINCT FROM NEW."advisory_evidence_origin"
        OR peer."range_fingerprint" IS DISTINCT FROM NEW."range_fingerprint"
        OR peer."outcome" IS DISTINCT FROM NEW."outcome"
        OR EXISTS (
          SELECT 1
          FROM (
            SELECT "ordinal", "explanation_code"
            FROM "match_evaluation_explanation"
            WHERE "match_evaluation_evidence_id" = peer."id"
            EXCEPT
            SELECT "ordinal", "explanation_code"
            FROM "match_evaluation_explanation"
            WHERE "match_evaluation_evidence_id" = NEW."id"
          ) missing_explanation
        )
        OR EXISTS (
          SELECT 1
          FROM (
            SELECT "ordinal", "explanation_code"
            FROM "match_evaluation_explanation"
            WHERE "match_evaluation_evidence_id" = NEW."id"
            EXCEPT
            SELECT "ordinal", "explanation_code"
            FROM "match_evaluation_explanation"
            WHERE "match_evaluation_evidence_id" = peer."id"
          ) extra_explanation
        )
      )
  ) THEN
    RAISE EXCEPTION 'match evaluation replay fingerprint disagrees'
      USING ERRCODE = 'exclusion_violation';
  END IF;

  RETURN NULL;
END;
$$;

CREATE TRIGGER match_evaluation_evidence_append_only
  BEFORE UPDATE OR DELETE ON "match_evaluation_evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER match_evaluation_explanation_append_only
  BEFORE UPDATE OR DELETE ON "match_evaluation_explanation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER match_evaluation_evidence_bind_parents
  BEFORE INSERT ON "match_evaluation_evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_match_evaluation_evidence_bind_parents();

CREATE CONSTRAINT TRIGGER match_evaluation_evidence_explanations_complete
  AFTER INSERT ON "match_evaluation_evidence"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION patchpilot_match_evaluation_explanations_complete();

CREATE FUNCTION patchpilot_match_evaluation_explanation_same_transaction()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_xmin xid;
BEGIN
  SELECT parent.xmin
  INTO parent_xmin
  FROM "match_evaluation_evidence" parent
  WHERE parent."id" = NEW."match_evaluation_evidence_id"
    AND parent."organization_id" = NEW."organization_id";

  IF parent_xmin IS DISTINCT FROM pg_current_xact_id()::xid THEN
    RAISE EXCEPTION 'match evaluation explanations are closed'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER match_evaluation_explanation_same_transaction
  BEFORE INSERT ON "match_evaluation_explanation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_match_evaluation_explanation_same_transaction();
