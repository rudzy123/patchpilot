-- Product Match Evidence Batch 2: immutable maintainer-reviewed advisory approval.
-- One forward-only migration. No seed rows. No match-evaluation writes.
-- No Findings. No catalog activation. No evaluator invocation.
-- Match-evaluation evidence columns are unchanged: the product row shape is not settled here.

ALTER TYPE "advisory_evidence_source" ADD VALUE 'maintainer_reviewed_advisory';
ALTER TYPE "advisory_evidence_origin" ADD VALUE 'maintainer_reviewed_advisory';
ALTER TYPE "advisory_retrieval_classification" ADD VALUE 'local_not_retrieved';

ALTER TABLE "advisory_revision"
  ALTER COLUMN "advisory_schema_version" TYPE VARCHAR(80);

ALTER TABLE "advisory_revision"
  ADD COLUMN "author_identity" VARCHAR(128);

ALTER TABLE "advisory_family" DROP CONSTRAINT "advisory_family_identity_chk";
ALTER TABLE "advisory_family"
  ADD CONSTRAINT "advisory_family_identity_chk"
  CHECK (
    (
      "family_schema_version" = 'osv_advisory_family_identity_v1'
      AND "source_registry_version" = 'osv_source_license_registry_v1'
      AND "source"::text <> 'maintainer_reviewed_advisory'
      AND char_length("advisory_id") BETWEEN 1 AND 512
      AND "advisory_id" ~ '^[A-Z0-9][A-Z0-9._+-]*$'
      AND "family_digest" ~ '^[a-f0-9]{64}$'
      AND char_length("family_digest") = 64
    )
    OR (
      "family_schema_version" = 'maintainer_reviewed_advisory_family_v1'
      AND "source_registry_version" = 'maintainer_reviewed_source_license_policy_v1'
      AND "source"::text = 'maintainer_reviewed_advisory'
      AND char_length("advisory_id") BETWEEN 1 AND 512
      AND "advisory_id" ~ '^[A-Z0-9][A-Z0-9._+-]*$'
      AND "family_digest" ~ '^[a-f0-9]{64}$'
      AND char_length("family_digest") = 64
    )
  );

ALTER TABLE "advisory_revision" DROP CONSTRAINT "advisory_revision_pin_chk";
ALTER TABLE "advisory_revision"
  ADD CONSTRAINT "advisory_revision_pin_chk"
  CHECK (
    (
      "origin"::text <> 'maintainer_reviewed_advisory'
      AND "revision_schema_version" = 'osv_advisory_revision_identity_v1'
      AND "parser_id" = 'osv_advisory_parser_protocol_v1'
      AND "parser_resource_policy" = 'osv_advisory_parser_resource_policy_v1'
      AND "advisory_schema_version" = 'v1.9.0'
      AND "advisory_schema_commit" = 'f3f826310aeca8e324baabd195632f2229952abe'
      AND "source_license_registry_version" = 'osv_source_license_registry_v1'
      AND "source_license_policy_version" = 'osv_source_license_registry_v1'
      AND "retrieval_policy_id" = 'osv_generation_bound_retrieval_policy_v1'
      AND "ecosystem" = 'npm'
      AND "evaluator_version" = 'session_14_batch_2_in_memory'
      AND "matching_policy_id" = 'osv_first_ecosystem_matching_architecture_v1'
      AND char_length("advisory_id") BETWEEN 1 AND 512
      AND "advisory_id" ~ '^[A-Z0-9][A-Z0-9._+-]*$'
      AND char_length("package_name") BETWEEN 1 AND 214
      AND char_length("package_identity_key") BETWEEN 1 AND 1024
      AND "alias_count" BETWEEN 0 AND 256
      AND "cve_alias_count" BETWEEN 0 AND "alias_count"
    )
    OR (
      "origin"::text = 'maintainer_reviewed_advisory'
      AND "source"::text = 'maintainer_reviewed_advisory'
      AND "revision_schema_version" = 'maintainer_reviewed_advisory_revision_v1'
      AND "parser_id" = 'maintainer_reviewed_advisory_document_v1'
      AND "parser_resource_policy" = 'canonicalization_policy_v1'
      AND "advisory_schema_version" = 'maintainer_reviewed_advisory_document_v1'
      AND "advisory_schema_commit" = 'not_a_provider_schema_commit'
      AND "source_license_registry_version" = 'maintainer_reviewed_source_license_policy_v1'
      AND "source_license_policy_version" = '1'
      AND "retrieval_policy_id" = 'local_advisory_not_retrieved_v1'
      AND "ecosystem" = 'npm'
      AND "evaluator_version" = 'session_14_batch_2_in_memory'
      AND "matching_policy_id" = 'osv_first_ecosystem_matching_architecture_v1'
      AND "product_range_fingerprint" = "session14_range_fingerprint"
      AND char_length("advisory_id") BETWEEN 1 AND 512
      AND "advisory_id" ~ '^[A-Z0-9][A-Z0-9._+-]*$'
      AND char_length("package_name") BETWEEN 1 AND 214
      AND char_length("package_identity_key") BETWEEN 1 AND 1024
      AND "alias_count" BETWEEN 0 AND 256
      AND "cve_alias_count" BETWEEN 0 AND "alias_count"
    )
  );

ALTER TABLE "advisory_revision" DROP CONSTRAINT "advisory_revision_classification_chk";
ALTER TABLE "advisory_revision"
  ADD CONSTRAINT "advisory_revision_classification_chk"
  CHECK (
    (
      "origin" = 'synthetic_fixture'
      AND "source" = 'synthetic_fixture'
      AND "trust_classification" = 'not_applicable_synthetic'
      AND "revision_disposition" = 'synthetic'
      AND "withdrawal_classification" = 'not_withdrawn'
      AND "quarantine_classification" = 'not_quarantined'
      AND "supersedes_revision_digest" = 'none'
      AND "spdx_license_id" IS NULL
      AND "retrieval_classification" = 'synthetic_not_retrieved'
      AND "retrieval_evidence_id" = 'synthetic_retrieval_not_applicable'
      AND "provider_generation" = 'synthetic_not_a_provider_generation'
    )
    OR (
      "origin" = 'unrecognized'
      AND "source" = 'unrecognized'
      AND "trust_classification" = 'unreviewed'
      AND "revision_disposition" = 'unrecognized'
      AND "withdrawal_classification" = 'not_withdrawn'
      AND "quarantine_classification" = 'not_quarantined'
      AND "supersedes_revision_digest" = 'none'
      AND "spdx_license_id" IS NULL
      AND "retrieval_classification" = 'synthetic_not_retrieved'
      AND "retrieval_evidence_id" = 'synthetic_retrieval_not_applicable'
      AND "provider_generation" = 'synthetic_not_a_provider_generation'
    )
    OR (
      "origin" = 'provider_derived'
      AND "source"::text NOT IN (
        'synthetic_fixture',
        'unrecognized',
        'maintainer_reviewed_advisory'
      )
      AND "retrieval_classification" = 'recorded_reference'
      AND "retrieval_evidence_id" ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND "provider_generation" ~ '^[1-9][0-9]{0,19}$'
      AND (
        (
          "withdrawal_classification" = 'withdrawn'
          AND "revision_disposition" = 'withdrawn'
          AND "trust_classification" = 'unreviewed'
        )
        OR (
          "withdrawal_classification" = 'not_withdrawn'
          AND "quarantine_classification" = 'quarantined'
          AND "revision_disposition" = 'quarantined'
          AND "trust_classification" = 'unreviewed'
        )
        OR (
          "withdrawal_classification" = 'not_withdrawn'
          AND "quarantine_classification" = 'not_quarantined'
          AND "supersedes_revision_digest" <> 'none'
          AND "revision_disposition" = 'superseding'
          AND "trust_classification" IN ('unreviewed', 'reviewed')
        )
        OR (
          "withdrawal_classification" = 'not_withdrawn'
          AND "quarantine_classification" = 'not_quarantined'
          AND "supersedes_revision_digest" = 'none'
          AND "revision_disposition" = 'recorded'
          AND "trust_classification" IN ('unreviewed', 'reviewed')
        )
      )
    )
    OR (
      "origin"::text = 'maintainer_reviewed_advisory'
      AND "source"::text = 'maintainer_reviewed_advisory'
      AND "trust_classification" = 'unreviewed'
      AND "spdx_license_id" = 'CC-BY-4.0'
      AND "retrieval_classification"::text = 'local_not_retrieved'
      AND "retrieval_evidence_id" = 'local_retrieval_not_applicable'
      AND "provider_generation" = 'not_a_provider_generation'
      AND (
        (
          "withdrawal_classification" = 'not_withdrawn'
          AND "quarantine_classification" = 'not_quarantined'
          AND "supersedes_revision_digest" = 'none'
          AND "revision_disposition" = 'recorded'
        )
        OR (
          "withdrawal_classification" = 'withdrawn'
          AND "quarantine_classification" = 'not_quarantined'
          AND "supersedes_revision_digest" = 'none'
          AND "revision_disposition" = 'withdrawn'
        )
        OR (
          "withdrawal_classification" = 'not_withdrawn'
          AND "quarantine_classification" = 'quarantined'
          AND "supersedes_revision_digest" = 'none'
          AND "revision_disposition" = 'quarantined'
        )
        OR (
          "withdrawal_classification" = 'not_withdrawn'
          AND "quarantine_classification" = 'not_quarantined'
          AND "supersedes_revision_digest" <> 'none'
          AND "revision_disposition" = 'superseding'
        )
      )
    )
  );

ALTER TABLE "advisory_revision" DROP CONSTRAINT "advisory_revision_license_chk";
ALTER TABLE "advisory_revision"
  ADD CONSTRAINT "advisory_revision_license_chk"
  CHECK (
    (
      "source" = 'synthetic_fixture' AND "spdx_license_id" IS NULL
    )
    OR (
      "source" = 'unrecognized' AND "spdx_license_id" IS NULL
    )
    OR (
      "source" = 'github_advisory_database' AND "spdx_license_id" = 'CC-BY-4.0'
    )
    OR (
      "source" = 'ossf_malicious_packages' AND "spdx_license_id" = 'Apache-2.0'
    )
    OR (
      "source" = 'pypa_advisory_database' AND "spdx_license_id" = 'CC-BY-4.0'
    )
    OR (
      "source" = 'go_vulnerability_database' AND "spdx_license_id" = 'CC-BY-4.0'
    )
    OR (
      "source" = 'rustsec_advisory_database' AND "spdx_license_id" = 'CC0-1.0'
    )
    OR (
      "source" = 'global_security_database' AND "spdx_license_id" = 'CC0-1.0'
    )
    OR (
      "source" = 'erlang_ecosystem_foundation_cna' AND "spdx_license_id" = 'CC-BY-4.0'
    )
    OR (
      "source" = 'osv_ambiguous_origin' AND "spdx_license_id" IS NULL
    )
    OR (
      "source" = 'echo_advisory_database' AND "spdx_license_id" IS NULL
    )
    OR (
      "source"::text = 'maintainer_reviewed_advisory' AND "spdx_license_id" = 'CC-BY-4.0'
    )
  );

ALTER TABLE "advisory_revision"
  ADD CONSTRAINT "advisory_revision_author_chk"
  CHECK (
    (
      "origin"::text <> 'maintainer_reviewed_advisory'
      AND "author_identity" IS NULL
    )
    OR (
      "origin"::text = 'maintainer_reviewed_advisory'
      AND "author_identity" IS NOT NULL
      AND char_length("author_identity") BETWEEN 1 AND 128
      AND "author_identity" ~ '^[A-Za-z0-9][A-Za-z0-9._@-]*$'
    )
  );

ALTER TABLE "advisory_vulnerability_binding" DROP CONSTRAINT "advisory_vulnerability_binding_shape_chk";
ALTER TABLE "advisory_vulnerability_binding"
  ADD CONSTRAINT "advisory_vulnerability_binding_shape_chk"
  CHECK (
    (
      "binding_schema_version" = 'osv_advisory_vulnerability_binding_v1'
      OR "binding_schema_version" = 'maintainer_reviewed_advisory_vulnerability_binding_v1'
    )
    AND "mapping_policy_id" = 'one_vulnerability_id_per_product_evidence_record_v1'
    AND "mapping_method" = 'exact_uuid_and_exact_alias_set'
    AND "mapping_review_state" = 'reviewed'
    AND "mapping_source_classification" = 'explicit_reviewed_binding'
    AND "conflict_classification" = 'none'
    AND "mapping_evidence_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("mapping_evidence_fingerprint") = 64
    AND "replay_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("replay_fingerprint") = 64
  );

CREATE TABLE "maintainer_reviewed_advisory_approval" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "approval_schema_version" VARCHAR(80) NOT NULL,
  "advisory_revision_id" UUID NOT NULL,
  "advisory_family_id" UUID NOT NULL,
  "family_digest" TEXT NOT NULL,
  "approval_policy_id" VARCHAR(80) NOT NULL,
  "approval_policy_version" SMALLINT NOT NULL,
  "approval_purpose" VARCHAR(80) NOT NULL,
  "source_classification" VARCHAR(64) NOT NULL,
  "author_identity" VARCHAR(128) NOT NULL,
  "reviewer_identity" VARCHAR(128) NOT NULL,
  "reviewer_classification" VARCHAR(64) NOT NULL,
  "content_fingerprint" TEXT NOT NULL,
  "range_fingerprint" TEXT NOT NULL,
  "package_identity_key" VARCHAR(1024) NOT NULL,
  "vulnerability_id" UUID NOT NULL,
  "advisory_vulnerability_binding_id" UUID NOT NULL,
  "source_license_policy_id" VARCHAR(80) NOT NULL,
  "source_license_policy_version" SMALLINT NOT NULL,
  "approved_license_classification" VARCHAR(32) NOT NULL,
  "license_decision_canonical" TEXT NOT NULL,
  "replay_fingerprint" TEXT NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "maintainer_reviewed_advisory_approval_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "maintainer_reviewed_advisory_approval_revision_uidx"
  ON "maintainer_reviewed_advisory_approval" ("advisory_revision_id");
CREATE UNIQUE INDEX "maintainer_reviewed_advisory_approval_binding_uidx"
  ON "maintainer_reviewed_advisory_approval" ("advisory_vulnerability_binding_id");
CREATE UNIQUE INDEX "maintainer_reviewed_advisory_approval_replay_uidx"
  ON "maintainer_reviewed_advisory_approval" ("replay_fingerprint");
CREATE INDEX "maintainer_reviewed_advisory_approval_family_idx"
  ON "maintainer_reviewed_advisory_approval" ("advisory_family_id");
CREATE INDEX "maintainer_reviewed_advisory_approval_vulnerability_idx"
  ON "maintainer_reviewed_advisory_approval" ("vulnerability_id");

ALTER TABLE "maintainer_reviewed_advisory_approval"
  ADD CONSTRAINT "maintainer_reviewed_advisory_approval_revision_fkey"
  FOREIGN KEY ("advisory_revision_id") REFERENCES "advisory_revision"("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "maintainer_reviewed_advisory_approval"
  ADD CONSTRAINT "maintainer_reviewed_advisory_approval_family_fkey"
  FOREIGN KEY ("advisory_family_id") REFERENCES "advisory_family"("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "maintainer_reviewed_advisory_approval"
  ADD CONSTRAINT "maintainer_reviewed_advisory_approval_vulnerability_fkey"
  FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "maintainer_reviewed_advisory_approval"
  ADD CONSTRAINT "maintainer_reviewed_advisory_approval_binding_fkey"
  FOREIGN KEY ("advisory_vulnerability_binding_id") REFERENCES "advisory_vulnerability_binding"("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "maintainer_reviewed_advisory_approval"
  ADD CONSTRAINT "maintainer_reviewed_advisory_approval_closed_chk"
  CHECK (
    "approval_schema_version" = 'maintainer_reviewed_advisory_approval_v1'
    AND "approval_policy_id" = 'maintainer_reviewed_advisory_approval_policy_v1'
    AND "approval_policy_version" = 1
    AND "approval_purpose" = 'approve_maintainer_reviewed_advisory_for_product_evaluation'
    AND "source_classification" = 'maintainer_reviewed_advisory'
    AND "reviewer_classification" = 'maintainer_reviewer'
    AND "source_license_policy_id" = 'maintainer_reviewed_source_license_policy_v1'
    AND "source_license_policy_version" = 1
    AND "approved_license_classification" = 'CC-BY-4.0'
    AND "license_decision_canonical" = '6:policy44:maintainer_reviewed_source_license_policy_v1|13:policyVersion1:1|4:spdx9:CC-BY-4.0|10:productUse31:permitted_for_internal_matching|12:modification9:permitted|14:redistribution9:permitted|6:notice8:required|10:provenance19:maintainer_original|8:decision8:accepted'
  );

ALTER TABLE "maintainer_reviewed_advisory_approval"
  ADD CONSTRAINT "maintainer_reviewed_advisory_approval_fingerprint_chk"
  CHECK (
    "family_digest" ~ '^[a-f0-9]{64}$'
    AND char_length("family_digest") = 64
    AND "content_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("content_fingerprint") = 64
    AND "range_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("range_fingerprint") = 64
    AND "replay_fingerprint" ~ '^[a-f0-9]{64}$'
    AND char_length("replay_fingerprint") = 64
    AND char_length("package_identity_key") BETWEEN 1 AND 1024
  );

ALTER TABLE "maintainer_reviewed_advisory_approval"
  ADD CONSTRAINT "maintainer_reviewed_advisory_approval_identity_chk"
  CHECK (
    char_length("author_identity") BETWEEN 1 AND 128
    AND "author_identity" ~ '^[A-Za-z0-9][A-Za-z0-9._@-]*$'
    AND char_length("reviewer_identity") BETWEEN 1 AND 128
    AND "reviewer_identity" ~ '^[A-Za-z0-9][A-Za-z0-9._@-]*$'
    AND "author_identity" <> "reviewer_identity"
    AND translate("author_identity", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
      <> translate("reviewer_identity", 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
  );

ALTER TABLE "maintainer_reviewed_advisory_approval"
  ADD CONSTRAINT "maintainer_reviewed_advisory_approval_uuid_chk"
  CHECK (
    "vulnerability_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  );

CREATE OR REPLACE FUNCTION patchpilot_advisory_vulnerability_binding_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_origin "advisory_evidence_origin";
  parent_trust "advisory_evidence_trust";
  parent_withdrawal "advisory_withdrawal_classification";
  parent_quarantine "advisory_quarantine_classification";
  parent_cves integer;
BEGIN
  SELECT parent."origin",
         parent."trust_classification",
         parent."withdrawal_classification",
         parent."quarantine_classification",
         parent."cve_alias_count"
  INTO parent_origin, parent_trust, parent_withdrawal, parent_quarantine, parent_cves
  FROM "advisory_revision" parent
  WHERE parent."id" = NEW."advisory_revision_id";

  IF parent_origin::text = 'maintainer_reviewed_advisory' THEN
    IF parent_trust IS DISTINCT FROM 'unreviewed'
      OR parent_withdrawal IS DISTINCT FROM 'not_withdrawn'
      OR parent_quarantine IS DISTINCT FROM 'not_quarantined'
      OR NEW."binding_schema_version" IS DISTINCT FROM 'maintainer_reviewed_advisory_vulnerability_binding_v1'
    THEN
      RAISE EXCEPTION 'advisory binding parent is ineligible'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF parent_origin IS NULL
      OR parent_origin IS DISTINCT FROM 'provider_derived'
      OR parent_trust IS DISTINCT FROM 'reviewed'
      OR parent_withdrawal IS DISTINCT FROM 'not_withdrawn'
      OR parent_quarantine IS DISTINCT FROM 'not_quarantined'
      OR NEW."binding_schema_version" IS DISTINCT FROM 'osv_advisory_vulnerability_binding_v1'
    THEN
      RAISE EXCEPTION 'advisory binding parent is ineligible'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  IF parent_cves = 0 AND NEW."binding_classification" IS DISTINCT FROM 'provider_native_without_cve' THEN
    RAISE EXCEPTION 'advisory binding classification is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  IF parent_cves = 1 AND NEW."binding_classification" IS DISTINCT FROM 'one_cve_alias_evidence' THEN
    RAISE EXCEPTION 'advisory binding classification is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  IF parent_cves > 1 OR parent_cves < 0 THEN
    RAISE EXCEPTION 'advisory binding is ambiguous'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_maintainer_reviewed_advisory_approval_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_origin text;
  parent_source text;
  parent_family uuid;
  parent_digest text;
  parent_content text;
  parent_range text;
  parent_package text;
  parent_author text;
  parent_withdrawal text;
  parent_quarantine text;
  parent_disposition text;
  parent_spdx text;
  parent_license_policy text;
  parent_trust text;
  binding_vulnerability uuid;
  binding_revision uuid;
  binding_policy text;
  binding_review text;
  binding_conflict text;
  binding_schema text;
BEGIN
  IF NEW."created_at" IS DISTINCT FROM CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'approval timestamp must be database time'
      USING ERRCODE = '23514';
  END IF;

  SELECT parent."origin"::text,
         parent."source"::text,
         parent."advisory_family_id",
         parent."family_digest",
         parent."content_fingerprint",
         parent."session14_range_fingerprint",
         parent."package_identity_key",
         parent."author_identity",
         parent."withdrawal_classification"::text,
         parent."quarantine_classification"::text,
         parent."revision_disposition"::text,
         parent."spdx_license_id",
         parent."source_license_policy_version",
         parent."trust_classification"::text
  INTO parent_origin, parent_source, parent_family, parent_digest, parent_content,
       parent_range, parent_package, parent_author, parent_withdrawal, parent_quarantine,
       parent_disposition, parent_spdx, parent_license_policy, parent_trust
  FROM "advisory_revision" parent
  WHERE parent."id" = NEW."advisory_revision_id";

  IF parent_origin IS NULL
    OR parent_origin IS DISTINCT FROM 'maintainer_reviewed_advisory'
    OR parent_source IS DISTINCT FROM 'maintainer_reviewed_advisory'
    OR parent_trust IS DISTINCT FROM 'unreviewed'
    OR parent_family IS DISTINCT FROM NEW."advisory_family_id"
    OR parent_digest IS DISTINCT FROM NEW."family_digest"
    OR parent_content IS DISTINCT FROM NEW."content_fingerprint"
    OR parent_range IS DISTINCT FROM NEW."range_fingerprint"
    OR parent_package IS DISTINCT FROM NEW."package_identity_key"
    OR parent_author IS DISTINCT FROM NEW."author_identity"
    OR parent_spdx IS DISTINCT FROM NEW."approved_license_classification"
    OR parent_license_policy IS DISTINCT FROM '1'
  THEN
    RAISE EXCEPTION 'approval parent binding is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  IF parent_withdrawal IS DISTINCT FROM 'not_withdrawn'
    OR parent_quarantine IS DISTINCT FROM 'not_quarantined'
    OR parent_disposition NOT IN ('recorded', 'superseding')
  THEN
    RAISE EXCEPTION 'approval parent is not approvable'
      USING ERRCODE = '23514';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM "advisory_revision" successor
    WHERE successor."supersedes_advisory_revision_id" = NEW."advisory_revision_id"
  ) THEN
    RAISE EXCEPTION 'approval parent is superseded'
      USING ERRCODE = '23514';
  END IF;

  SELECT binding."vulnerability_id",
         binding."advisory_revision_id",
         binding."mapping_policy_id",
         binding."mapping_review_state",
         binding."conflict_classification",
         binding."binding_schema_version"
  INTO binding_vulnerability, binding_revision, binding_policy, binding_review,
       binding_conflict, binding_schema
  FROM "advisory_vulnerability_binding" binding
  WHERE binding."id" = NEW."advisory_vulnerability_binding_id";

  IF binding_vulnerability IS NULL
    OR binding_revision IS DISTINCT FROM NEW."advisory_revision_id"
    OR binding_vulnerability IS DISTINCT FROM NEW."vulnerability_id"
    OR binding_policy IS DISTINCT FROM 'one_vulnerability_id_per_product_evidence_record_v1'
    OR binding_review IS DISTINCT FROM 'reviewed'
    OR binding_conflict IS DISTINCT FROM 'none'
    OR binding_schema IS DISTINCT FROM 'maintainer_reviewed_advisory_vulnerability_binding_v1'
  THEN
    RAISE EXCEPTION 'approval vulnerability binding is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER maintainer_reviewed_advisory_approval_guard
  BEFORE INSERT ON "maintainer_reviewed_advisory_approval"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_maintainer_reviewed_advisory_approval_guard();

CREATE TRIGGER maintainer_reviewed_advisory_approval_append_only
  BEFORE UPDATE OR DELETE ON "maintainer_reviewed_advisory_approval"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();
