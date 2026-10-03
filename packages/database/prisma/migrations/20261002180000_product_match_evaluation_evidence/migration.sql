-- Product Match Evidence Batch 3.
-- Forward-only. Session 14 match_evaluation_evidence is unchanged.
-- That table still requires synthetic origin for affected and unaffected rows,
-- and it does not bind an advisory revision, approval, or Vulnerability.id.
-- No seed rows. No Finding relation. No catalog activation.

CREATE TABLE "advisory_revision_range_event" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "advisory_revision_id" UUID NOT NULL,
  "range_ordinal" SMALLINT NOT NULL,
  "event_ordinal" SMALLINT NOT NULL,
  "event_name" VARCHAR(16) NOT NULL,
  "event_value" VARCHAR(256) NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "advisory_revision_range_event_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "advisory_revision_range_event_ordinal_uidx"
  ON "advisory_revision_range_event" ("advisory_revision_id", "range_ordinal", "event_ordinal");

CREATE INDEX "advisory_revision_range_event_revision_idx"
  ON "advisory_revision_range_event" ("advisory_revision_id");

ALTER TABLE "advisory_revision_range_event"
  ADD CONSTRAINT "advisory_revision_range_event_revision_fkey"
  FOREIGN KEY ("advisory_revision_id")
  REFERENCES "advisory_revision"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "advisory_revision_range_event"
  ADD CONSTRAINT "advisory_revision_range_event_shape_chk"
  CHECK (
    "range_ordinal" BETWEEN 0 AND 31
    AND "event_ordinal" BETWEEN 0 AND 15
    AND "event_name" IN ('introduced', 'fixed', 'last_affected', 'limit')
    AND char_length("event_value") BETWEEN 1 AND 256
  );

CREATE TABLE "product_match_evaluation_evidence" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "organization_id" UUID NOT NULL,
  "component_occurrence_id" UUID NOT NULL,
  "asset_id" UUID NOT NULL,
  "sbom_id" UUID NOT NULL,
  "sbom_ingestion_id" UUID NOT NULL,
  "component_id" UUID NOT NULL,
  "sbom_sha256" TEXT NOT NULL,
  "component_identity_key" VARCHAR(2048) NOT NULL,
  "component_evidence_fingerprint" TEXT NOT NULL,
  "evidence_schema_version" VARCHAR(80) NOT NULL,
  "package_identity_key" VARCHAR(1024) NOT NULL,
  "raw_observed_version" VARCHAR(256) NOT NULL,
  "raw_observed_version_sha256" TEXT NOT NULL,
  "advisory_family_id" UUID NOT NULL,
  "advisory_revision_id" UUID NOT NULL,
  "approval_id" UUID NOT NULL,
  "content_fingerprint" TEXT NOT NULL,
  "range_fingerprint" TEXT NOT NULL,
  "vulnerability_id" UUID NOT NULL,
  "evaluator_id" VARCHAR(80) NOT NULL,
  "evaluator_version" VARCHAR(64) NOT NULL,
  "matching_policy_id" VARCHAR(80) NOT NULL,
  "matching_policy_version" VARCHAR(80) NOT NULL,
  "product_evidence_policy_id" VARCHAR(80) NOT NULL,
  "product_evidence_policy_version" SMALLINT NOT NULL,
  "outcome" "match_evaluation_outcome" NOT NULL,
  "product_origin" VARCHAR(64) NOT NULL,
  "replay_fingerprint" TEXT NOT NULL,
  "finding_creation" VARCHAR(32) NOT NULL,
  "suppression_authority" BOOLEAN NOT NULL DEFAULT false,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "product_match_evaluation_evidence_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "product_match_evaluation_evidence_org_id_key"
  ON "product_match_evaluation_evidence" ("organization_id", "id");

CREATE UNIQUE INDEX "product_match_evaluation_evidence_occurrence_uidx"
  ON "product_match_evaluation_evidence" ("organization_id", "component_occurrence_id");

CREATE UNIQUE INDEX "product_match_evaluation_evidence_revision_uidx"
  ON "product_match_evaluation_evidence" ("organization_id", "advisory_revision_id");

CREATE UNIQUE INDEX "product_match_evaluation_evidence_replay_uidx"
  ON "product_match_evaluation_evidence" ("replay_fingerprint");

CREATE INDEX "product_match_evaluation_evidence_org_idx"
  ON "product_match_evaluation_evidence" ("organization_id");

CREATE TABLE "product_match_evaluation_explanation" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "organization_id" UUID NOT NULL,
  "product_match_evaluation_evidence_id" UUID NOT NULL,
  "ordinal" SMALLINT NOT NULL,
  "explanation_code" "match_evaluation_explanation_code" NOT NULL,
  CONSTRAINT "product_match_evaluation_explanation_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "product_match_evaluation_explanation_ordinal_uidx"
  ON "product_match_evaluation_explanation" ("product_match_evaluation_evidence_id", "ordinal");

CREATE UNIQUE INDEX "product_match_evaluation_explanation_code_uidx"
  ON "product_match_evaluation_explanation" ("product_match_evaluation_evidence_id", "explanation_code");

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_organization_fkey"
  FOREIGN KEY ("organization_id") REFERENCES "organization"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_occurrence_fkey"
  FOREIGN KEY ("organization_id", "component_occurrence_id", "asset_id", "component_id")
  REFERENCES "component_occurrence"("organization_id", "id", "asset_id", "component_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_component_fkey"
  FOREIGN KEY ("organization_id", "component_id")
  REFERENCES "component"("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_sbom_fkey"
  FOREIGN KEY ("organization_id", "sbom_id", "asset_id")
  REFERENCES "sbom"("organization_id", "id", "asset_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_ingestion_fkey"
  FOREIGN KEY ("organization_id", "sbom_ingestion_id", "sbom_id")
  REFERENCES "sbom_ingestion"("organization_id", "id", "sbom_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_family_fkey"
  FOREIGN KEY ("advisory_family_id") REFERENCES "advisory_family"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_revision_fkey"
  FOREIGN KEY ("advisory_revision_id") REFERENCES "advisory_revision"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_approval_fkey"
  FOREIGN KEY ("approval_id") REFERENCES "maintainer_reviewed_advisory_approval"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_vulnerability_fkey"
  FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_explanation"
  ADD CONSTRAINT "product_match_evaluation_explanation_evidence_fkey"
  FOREIGN KEY ("organization_id", "product_match_evaluation_evidence_id")
  REFERENCES "product_match_evaluation_evidence"("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "product_match_evaluation_evidence"
  ADD CONSTRAINT "product_match_evaluation_evidence_closed_chk"
  CHECK (
    "evidence_schema_version" = 'product_match_evaluation_evidence_v1'
    AND "evaluator_id" = 'osv_first_ecosystem_affected_version_evaluator_v1'
    AND "evaluator_version" = 'session_14_batch_2_in_memory'
    AND "matching_policy_id" = 'osv_first_ecosystem_matching_architecture_v1'
    AND "matching_policy_version" = 'osv_first_ecosystem_matching_architecture_v1'
    AND "product_evidence_policy_id" = 'product_match_evaluation_policy_v1'
    AND "product_evidence_policy_version" = 1
    AND "product_origin" = 'maintainer_reviewed_advisory'
    AND "finding_creation" = 'unavailable'
    AND "suppression_authority" = false
    AND char_length("component_evidence_fingerprint") = 64
    AND "component_evidence_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("raw_observed_version_sha256") = 64
    AND "raw_observed_version_sha256" ~ '^[a-f0-9]{64}$'
    AND char_length("content_fingerprint") = 64
    AND "content_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("range_fingerprint") = 64
    AND "range_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("replay_fingerprint") = 64
    AND "replay_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("sbom_sha256") = 64
    AND "sbom_sha256" ~ '^[a-f0-9]{64}$'
    AND octet_length("raw_observed_version") BETWEEN 1 AND 256
    AND octet_length("package_identity_key") BETWEEN 1 AND 1024
  );

ALTER TABLE "product_match_evaluation_explanation"
  ADD CONSTRAINT "product_match_evaluation_explanation_ordinal_chk"
  CHECK ("ordinal" BETWEEN 1 AND 8);

CREATE FUNCTION patchpilot_product_match_evaluation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  occurrence_version text;
  occurrence_known boolean;
  component_ecosystem text;
  component_namespace text;
  component_name text;
  revision_origin text;
  revision_source text;
  revision_content text;
  revision_range text;
  revision_package text;
  revision_family uuid;
  revision_withdrawal text;
  revision_quarantine text;
  revision_disposition text;
  revision_supersedes text;
  revision_spdx text;
  approval_revision uuid;
  approval_vulnerability uuid;
  approval_content text;
  approval_range text;
  approval_package text;
  approval_author text;
  approval_reviewer text;
  approval_purpose text;
  binding_vulnerability uuid;
  binding_revision uuid;
  binding_conflict text;
  successor_count integer;
  range_count integer;
BEGIN
  IF NEW."created_at" IS DISTINCT FROM CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'product match timestamp must be database time'
      USING ERRCODE = '23514';
  END IF;

  SELECT occurrence."version", occurrence."version_known"
  INTO occurrence_version, occurrence_known
  FROM "component_occurrence" occurrence
  WHERE occurrence."organization_id" = NEW."organization_id"
    AND occurrence."id" = NEW."component_occurrence_id"
    AND occurrence."asset_id" = NEW."asset_id"
    AND occurrence."sbom_id" = NEW."sbom_id"
    AND occurrence."sbom_ingestion_id" = NEW."sbom_ingestion_id"
    AND occurrence."component_id" = NEW."component_id";

  IF occurrence_version IS NULL OR occurrence_known IS DISTINCT FROM true
    OR occurrence_version IS DISTINCT FROM NEW."raw_observed_version" THEN
    RAISE EXCEPTION 'product match component occurrence does not agree'
      USING ERRCODE = '23514';
  END IF;

  SELECT component."ecosystem", component."namespace", component."name"
  INTO component_ecosystem, component_namespace, component_name
  FROM "component" component
  WHERE component."organization_id" = NEW."organization_id"
    AND component."id" = NEW."component_id"
    AND component."identity_key" = NEW."component_identity_key";

  IF component_ecosystem IS DISTINCT FROM 'npm' OR component_name IS NULL THEN
    RAISE EXCEPTION 'product match component identity does not agree'
      USING ERRCODE = '23514';
  END IF;

  SELECT revision."origin"::text,
         revision."source"::text,
         revision."content_fingerprint",
         revision."session14_range_fingerprint",
         revision."package_identity_key",
         revision."advisory_family_id",
         revision."withdrawal_classification"::text,
         revision."quarantine_classification"::text,
         revision."revision_disposition"::text,
         revision."supersedes_revision_digest",
         revision."spdx_license_id"
  INTO revision_origin, revision_source, revision_content, revision_range, revision_package,
       revision_family, revision_withdrawal, revision_quarantine, revision_disposition,
       revision_supersedes, revision_spdx
  FROM "advisory_revision" revision
  WHERE revision."id" = NEW."advisory_revision_id";

  IF revision_origin IS DISTINCT FROM 'maintainer_reviewed_advisory'
    OR revision_source IS DISTINCT FROM 'maintainer_reviewed_advisory'
    OR revision_content IS DISTINCT FROM NEW."content_fingerprint"
    OR revision_range IS DISTINCT FROM NEW."range_fingerprint"
    OR revision_package IS DISTINCT FROM NEW."package_identity_key"
    OR revision_family IS DISTINCT FROM NEW."advisory_family_id"
    OR revision_withdrawal IS DISTINCT FROM 'not_withdrawn'
    OR revision_quarantine IS DISTINCT FROM 'not_quarantined'
    OR revision_disposition IS DISTINCT FROM 'recorded'
    OR revision_supersedes IS DISTINCT FROM 'none'
    OR revision_spdx IS DISTINCT FROM 'CC-BY-4.0' THEN
    RAISE EXCEPTION 'product match advisory revision is not admissible'
      USING ERRCODE = '23514';
  END IF;

  SELECT COUNT(*)::integer INTO successor_count
  FROM "advisory_revision" successor
  WHERE successor."supersedes_advisory_revision_id" = NEW."advisory_revision_id";

  IF successor_count <> 0 THEN
    RAISE EXCEPTION 'product match advisory revision is superseded'
      USING ERRCODE = '23514';
  END IF;

  SELECT approval."advisory_revision_id",
         approval."vulnerability_id",
         approval."content_fingerprint",
         approval."range_fingerprint",
         approval."package_identity_key",
         approval."author_identity",
         approval."reviewer_identity",
         approval."approval_purpose"
  INTO approval_revision, approval_vulnerability, approval_content, approval_range,
       approval_package, approval_author, approval_reviewer, approval_purpose
  FROM "maintainer_reviewed_advisory_approval" approval
  WHERE approval."id" = NEW."approval_id";

  IF approval_revision IS DISTINCT FROM NEW."advisory_revision_id"
    OR approval_vulnerability IS DISTINCT FROM NEW."vulnerability_id"
    OR approval_content IS DISTINCT FROM NEW."content_fingerprint"
    OR approval_range IS DISTINCT FROM NEW."range_fingerprint"
    OR approval_package IS DISTINCT FROM NEW."package_identity_key"
    OR approval_author IS NOT DISTINCT FROM approval_reviewer
    OR approval_purpose IS DISTINCT FROM 'approve_maintainer_reviewed_advisory_for_product_evaluation' THEN
    RAISE EXCEPTION 'product match approval does not agree'
      USING ERRCODE = '23514';
  END IF;

  SELECT binding."vulnerability_id", binding."advisory_revision_id", binding."conflict_classification"
  INTO binding_vulnerability, binding_revision, binding_conflict
  FROM "advisory_vulnerability_binding" binding
  WHERE binding."advisory_revision_id" = NEW."advisory_revision_id";

  IF binding_vulnerability IS DISTINCT FROM NEW."vulnerability_id"
    OR binding_revision IS DISTINCT FROM NEW."advisory_revision_id"
    OR binding_conflict IS DISTINCT FROM 'none' THEN
    RAISE EXCEPTION 'product match vulnerability binding does not agree'
      USING ERRCODE = '23514';
  END IF;

  SELECT COUNT(*)::integer INTO range_count
  FROM "advisory_revision_range_event" event
  WHERE event."advisory_revision_id" = NEW."advisory_revision_id";

  IF range_count < 1 THEN
    RAISE EXCEPTION 'product match range evidence is missing'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER product_match_evaluation_evidence_guard
  BEFORE INSERT ON "product_match_evaluation_evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_product_match_evaluation_guard();

CREATE TRIGGER product_match_evaluation_evidence_append_only
  BEFORE UPDATE OR DELETE ON "product_match_evaluation_evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER advisory_revision_range_event_append_only
  BEFORE UPDATE OR DELETE ON "advisory_revision_range_event"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE FUNCTION patchpilot_product_match_explanation_same_transaction()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_xmin xid;
BEGIN
  SELECT parent.xmin
  INTO parent_xmin
  FROM "product_match_evaluation_evidence" parent
  WHERE parent."id" = NEW."product_match_evaluation_evidence_id"
    AND parent."organization_id" = NEW."organization_id";

  IF parent_xmin IS DISTINCT FROM pg_current_xact_id()::xid THEN
    RAISE EXCEPTION 'product match explanations are closed'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER product_match_evaluation_explanation_same_transaction
  BEFORE INSERT ON "product_match_evaluation_explanation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_product_match_explanation_same_transaction();

CREATE TRIGGER product_match_evaluation_explanation_append_only
  BEFORE UPDATE OR DELETE ON "product_match_evaluation_explanation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE FUNCTION patchpilot_product_match_explanations_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  explanation_count integer;
  ordinals_ok boolean;
  outcome_ok boolean;
BEGIN
  SELECT COUNT(*)::integer INTO explanation_count
  FROM "product_match_evaluation_explanation"
  WHERE "product_match_evaluation_evidence_id" = NEW."id";

  IF explanation_count < 1 OR explanation_count > 8 THEN
    RAISE EXCEPTION 'product match explanation set is incomplete'
      USING ERRCODE = '23514';
  END IF;

  SELECT
    MIN("ordinal") = 1
    AND MAX("ordinal") = explanation_count
    AND COUNT(*) = COUNT(DISTINCT "ordinal")
    AND COUNT(*) = COUNT(DISTINCT "explanation_code")
  INTO ordinals_ok
  FROM "product_match_evaluation_explanation"
  WHERE "product_match_evaluation_evidence_id" = NEW."id";

  IF ordinals_ok IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'product match explanation ordinals are not contiguous'
      USING ERRCODE = '23514';
  END IF;

  SELECT bool_and(patchpilot_match_evaluation_code_outcome("explanation_code") = NEW."outcome")
  INTO outcome_ok
  FROM "product_match_evaluation_explanation"
  WHERE "product_match_evaluation_evidence_id" = NEW."id";

  IF outcome_ok IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'product match explanation outcome does not agree'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE CONSTRAINT TRIGGER product_match_evaluation_explanations_complete
  AFTER INSERT ON "product_match_evaluation_evidence"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION patchpilot_product_match_explanations_complete();
