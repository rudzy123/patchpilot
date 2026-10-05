-- Product Match Evidence cardinality correction.
-- Forward-only. Does not edit a predecessor migration, rewrite evidence,
-- seed rows, create Findings, or activate matching.
-- Occurrence-only and revision-only uniqueness were accidental.
-- Replay uniqueness is organization-scoped.
-- Exact evaluation identity is organization-scoped and includes the
-- occurrence, advisory revision, reviewed approval, evaluator, matching
-- policy, and product-evidence policy.
-- Current applicability is not stored.

DROP INDEX "product_match_evaluation_evidence_occurrence_uidx";

DROP INDEX "product_match_evaluation_evidence_revision_uidx";

DROP INDEX "product_match_evaluation_evidence_replay_uidx";

CREATE INDEX "product_match_evaluation_evidence_occurrence_idx"
  ON "product_match_evaluation_evidence" ("organization_id", "component_occurrence_id");

CREATE INDEX "product_match_evaluation_evidence_revision_idx"
  ON "product_match_evaluation_evidence" ("organization_id", "advisory_revision_id");

CREATE UNIQUE INDEX "product_match_evaluation_evidence_org_replay_uidx"
  ON "product_match_evaluation_evidence" ("organization_id", "replay_fingerprint");

CREATE UNIQUE INDEX "product_match_evaluation_evidence_evaluation_uidx"
  ON "product_match_evaluation_evidence" (
    "organization_id",
    "component_occurrence_id",
    "advisory_revision_id",
    "approval_id",
    "evaluator_id",
    "evaluator_version",
    "matching_policy_id",
    "matching_policy_version",
    "product_evidence_policy_id",
    "product_evidence_policy_version"
  );

CREATE OR REPLACE FUNCTION patchpilot_product_match_evaluation_guard()
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
  revision_author text;
  approval_revision uuid;
  approval_vulnerability uuid;
  approval_content text;
  approval_range text;
  approval_package text;
  approval_author text;
  approval_reviewer text;
  approval_purpose text;
  approval_policy text;
  approval_policy_version smallint;
  approval_source text;
  approval_reviewer_classification text;
  approval_family uuid;
  approval_license text;
  approval_license_policy text;
  approval_license_policy_version smallint;
  approval_license_canonical text;
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
         revision."spdx_license_id",
         revision."author_identity"
  INTO revision_origin, revision_source, revision_content, revision_range, revision_package,
       revision_family, revision_withdrawal, revision_quarantine, revision_disposition,
       revision_supersedes, revision_spdx, revision_author
  FROM "advisory_revision" revision
  WHERE revision."id" = NEW."advisory_revision_id";

  IF revision_origin IS DISTINCT FROM 'maintainer_reviewed_advisory'
    OR revision_source IS DISTINCT FROM 'maintainer_reviewed_advisory'
    OR revision_content IS DISTINCT FROM NEW."content_fingerprint"
    OR revision_range IS DISTINCT FROM NEW."range_fingerprint"
    OR revision_package IS DISTINCT FROM NEW."package_identity_key"
    OR revision_family IS DISTINCT FROM NEW."advisory_family_id"
    OR revision_spdx IS DISTINCT FROM 'CC-BY-4.0' THEN
    RAISE EXCEPTION 'product match advisory revision is not admissible'
      USING ERRCODE = '23514';
  END IF;

  IF revision_withdrawal IS DISTINCT FROM 'not_withdrawn' THEN
    RAISE EXCEPTION 'product match advisory revision is withdrawn'
      USING ERRCODE = '23514';
  END IF;

  IF revision_quarantine IS DISTINCT FROM 'not_quarantined' THEN
    RAISE EXCEPTION 'product match advisory revision is quarantined'
      USING ERRCODE = '23514';
  END IF;

  IF NOT (
    (
      revision_disposition = 'recorded'
      AND revision_supersedes = 'none'
    )
    OR (
      revision_disposition = 'superseding'
      AND revision_supersedes ~ '^[a-f0-9]{64}$'
      AND char_length(revision_supersedes) = 64
    )
  ) THEN
    RAISE EXCEPTION 'product match advisory revision is not the current tip'
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
         approval."approval_purpose",
         approval."approval_policy_id",
         approval."approval_policy_version",
         approval."source_classification",
         approval."reviewer_classification",
         approval."advisory_family_id",
         approval."approved_license_classification",
         approval."source_license_policy_id",
         approval."source_license_policy_version",
         approval."license_decision_canonical"
  INTO approval_revision, approval_vulnerability, approval_content, approval_range,
       approval_package, approval_author, approval_reviewer, approval_purpose,
       approval_policy, approval_policy_version, approval_source,
       approval_reviewer_classification, approval_family, approval_license,
       approval_license_policy, approval_license_policy_version, approval_license_canonical
  FROM "maintainer_reviewed_advisory_approval" approval
  WHERE approval."id" = NEW."approval_id";

  IF approval_revision IS DISTINCT FROM NEW."advisory_revision_id"
    OR approval_vulnerability IS DISTINCT FROM NEW."vulnerability_id"
    OR approval_content IS DISTINCT FROM NEW."content_fingerprint"
    OR approval_range IS DISTINCT FROM NEW."range_fingerprint"
    OR approval_package IS DISTINCT FROM NEW."package_identity_key"
    OR approval_author IS NOT DISTINCT FROM approval_reviewer
    OR approval_author IS DISTINCT FROM revision_author
    OR approval_family IS DISTINCT FROM NEW."advisory_family_id"
    OR approval_purpose IS DISTINCT FROM 'approve_maintainer_reviewed_advisory_for_product_evaluation'
    OR approval_policy IS DISTINCT FROM 'maintainer_reviewed_advisory_approval_policy_v1'
    OR approval_policy_version IS DISTINCT FROM 1
    OR approval_source IS DISTINCT FROM 'maintainer_reviewed_advisory'
    OR approval_reviewer_classification IS DISTINCT FROM 'maintainer_reviewer'
    OR approval_license IS DISTINCT FROM 'CC-BY-4.0'
    OR approval_license_policy IS DISTINCT FROM 'maintainer_reviewed_source_license_policy_v1'
    OR approval_license_policy_version IS DISTINCT FROM 1
    OR approval_license_canonical IS DISTINCT FROM '6:policy44:maintainer_reviewed_source_license_policy_v1|13:policyVersion1:1|4:spdx9:CC-BY-4.0|10:productUse31:permitted_for_internal_matching|12:modification9:permitted|14:redistribution9:permitted|6:notice8:required|10:provenance19:maintainer_original|8:decision8:accepted' THEN
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
