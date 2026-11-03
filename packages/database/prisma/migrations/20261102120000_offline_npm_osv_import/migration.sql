-- Offline npm GHSA OSV import persistence.
-- Forward-only. Three instance-owned tables. No organization column.
-- No seed rows. No Finding, evidence, Vulnerability, or Outbox writes.
-- Does not edit frozen SQL. Does not enable production OSV acquisition.
-- Existing classification and pin branches stay. One offline branch is added
-- to each. Cross-package supersession fails closed for every later insert.
-- Same-package successors that already commit still commit.

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
    OR (
      "origin" = 'provider_derived'
      AND "source" = 'github_advisory_database'
      AND "revision_schema_version" = 'offline_npm_advisory_revision_identity_v1'
      AND "parser_id" = 'osv_advisory_parser_protocol_v1'
      AND "parser_resource_policy" = 'osv_advisory_parser_resource_policy_v1'
      AND "advisory_schema_version" = 'v1.9.0'
      AND "advisory_schema_commit" = 'f3f826310aeca8e324baabd195632f2229952abe'
      AND "source_license_registry_version" = 'osv_source_license_registry_v1'
      AND "source_license_policy_version" = 'osv_source_license_registry_v1'
      AND "retrieval_policy_id" = 'offline_osv_import_retrieval_policy_v1'
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
    OR (
      "origin" = 'provider_derived'
      AND "source" = 'github_advisory_database'
      AND "trust_classification" = 'unreviewed'
      AND "quarantine_classification" = 'not_quarantined'
      AND "spdx_license_id" = 'CC-BY-4.0'
      AND "retrieval_classification" = 'local_not_retrieved'
      AND "retrieval_evidence_id" = 'offline_import_retrieval_not_applicable'
      AND "provider_generation" = 'offline-import-v1'
      AND (
        (
          "withdrawal_classification" = 'not_withdrawn'
          AND "supersedes_revision_digest" = 'none'
          AND "revision_disposition" = 'recorded'
        )
        OR (
          "withdrawal_classification" = 'not_withdrawn'
          AND "supersedes_revision_digest" <> 'none'
          AND "revision_disposition" = 'superseding'
        )
        OR (
          "withdrawal_classification" = 'withdrawn'
          AND "revision_disposition" = 'withdrawn'
        )
      )
    )
  );

-- Keeps an offline retrieval shape on the offline pin. Existing branches of
-- the two checks above are unchanged, so this closes a mix of those branches.
ALTER TABLE "advisory_revision"
  ADD CONSTRAINT "advisory_revision_offline_import_shape_chk"
  CHECK (
    NOT (
      "origin" = 'provider_derived'
      AND "source" = 'github_advisory_database'
      AND "retrieval_classification" = 'local_not_retrieved'
      AND "retrieval_evidence_id" = 'offline_import_retrieval_not_applicable'
      AND "provider_generation" = 'offline-import-v1'
    )
    OR (
      "revision_schema_version" = 'offline_npm_advisory_revision_identity_v1'
      AND "retrieval_policy_id" = 'offline_osv_import_retrieval_policy_v1'
      AND "parser_id" = 'osv_advisory_parser_protocol_v1'
      AND "parser_resource_policy" = 'osv_advisory_parser_resource_policy_v1'
      AND "advisory_schema_version" = 'v1.9.0'
      AND "advisory_schema_commit" = 'f3f826310aeca8e324baabd195632f2229952abe'
      AND "source_license_registry_version" = 'osv_source_license_registry_v1'
      AND "source_license_policy_version" = 'osv_source_license_registry_v1'
      AND "ecosystem" = 'npm'
      AND "evaluator_version" = 'session_14_batch_2_in_memory'
      AND "matching_policy_id" = 'osv_first_ecosystem_matching_architecture_v1'
      AND "trust_classification" = 'unreviewed'
      AND "quarantine_classification" = 'not_quarantined'
      AND "spdx_license_id" = 'CC-BY-4.0'
      AND "author_identity" IS NULL
    )
  );

CREATE TABLE "offline_advisory_import_batch" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "manifest_sha256" TEXT NOT NULL,
  "source_license_registry_version" VARCHAR(80) NOT NULL,
  "retrieved_at" TIMESTAMPTZ(6) NOT NULL,

  CONSTRAINT "offline_advisory_import_batch_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "offline_advisory_import_batch_manifest_uidx"
  ON "offline_advisory_import_batch" ("manifest_sha256");

ALTER TABLE "offline_advisory_import_batch"
  ADD CONSTRAINT "offline_advisory_import_batch_shape_chk"
  CHECK (
    "manifest_sha256" ~ '^[a-f0-9]{64}$'
    AND char_length("manifest_sha256") = 64
    AND "source_license_registry_version" = 'osv_source_license_registry_v1'
  );

CREATE TABLE "advisory_revision_source_provenance" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "advisory_revision_id" UUID NOT NULL,
  "source" "advisory_evidence_source" NOT NULL,
  "source_license_registry_version" VARCHAR(80) NOT NULL,
  "advisory_id" VARCHAR(512) NOT NULL,
  "package_identity_key" VARCHAR(1024) NOT NULL,
  "raw_content_sha256" TEXT NOT NULL,
  "parser_id" VARCHAR(80) NOT NULL,
  "parser_resource_policy" VARCHAR(80) NOT NULL,
  "advisory_schema_version" VARCHAR(80) NOT NULL,
  "advisory_schema_commit" VARCHAR(40) NOT NULL,
  "normalization_identity" VARCHAR(80) NOT NULL,
  "retrieved_at" TIMESTAMPTZ(6) NOT NULL,
  "modified_at" TIMESTAMPTZ(6) NOT NULL,
  "published_at" TIMESTAMPTZ(6),
  "withdrawn_at" TIMESTAMPTZ(6),
  "purl" TEXT,
  "license_admission_reason" VARCHAR(80) NOT NULL,
  "offline_advisory_import_batch_id" UUID NOT NULL,

  CONSTRAINT "advisory_revision_source_provenance_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "advisory_revision_source_provenance_revision_uidx"
  ON "advisory_revision_source_provenance" ("advisory_revision_id");

CREATE INDEX "advisory_revision_source_provenance_batch_idx"
  ON "advisory_revision_source_provenance" ("offline_advisory_import_batch_id");

ALTER TABLE "advisory_revision_source_provenance"
  ADD CONSTRAINT "advisory_revision_source_provenance_revision_fkey"
  FOREIGN KEY ("advisory_revision_id") REFERENCES "advisory_revision"("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "advisory_revision_source_provenance"
  ADD CONSTRAINT "advisory_revision_source_provenance_batch_fkey"
  FOREIGN KEY ("offline_advisory_import_batch_id") REFERENCES "offline_advisory_import_batch"("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "advisory_revision_source_provenance"
  ADD CONSTRAINT "advisory_revision_source_provenance_shape_chk"
  CHECK (
    "source" = 'github_advisory_database'
    AND "source_license_registry_version" = 'osv_source_license_registry_v1'
    AND "normalization_identity" = 'offline_npm_osv_normalization_v1'
    AND "license_admission_reason" = 'approved_source_license'
    AND "parser_id" = 'osv_advisory_parser_protocol_v1'
    AND "parser_resource_policy" = 'osv_advisory_parser_resource_policy_v1'
    AND "advisory_schema_version" = 'v1.9.0'
    AND "advisory_schema_commit" = 'f3f826310aeca8e324baabd195632f2229952abe'
    AND "raw_content_sha256" ~ '^[a-f0-9]{64}$'
    AND char_length("raw_content_sha256") = 64
    AND char_length("advisory_id") BETWEEN 1 AND 512
    AND "advisory_id" ~ '^[A-Z0-9][A-Z0-9._+-]*$'
    AND char_length("package_identity_key") BETWEEN 1 AND 1024
    AND (
      "purl" IS NULL
      OR (
        octet_length("purl") BETWEEN 9 AND 8192
        AND "purl" LIKE 'pkg:npm/%'
        AND "purl" !~ '[[:space:]]'
      )
    )
  );

CREATE TABLE "advisory_revision_explicit_version" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "advisory_revision_id" UUID NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "version_text" VARCHAR(256) NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "advisory_revision_explicit_version_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "advisory_revision_explicit_version_ordinal_uidx"
  ON "advisory_revision_explicit_version" ("advisory_revision_id", "ordinal");

CREATE UNIQUE INDEX "advisory_revision_explicit_version_text_uidx"
  ON "advisory_revision_explicit_version" ("advisory_revision_id", "version_text");

CREATE INDEX "advisory_revision_explicit_version_revision_idx"
  ON "advisory_revision_explicit_version" ("advisory_revision_id");

ALTER TABLE "advisory_revision_explicit_version"
  ADD CONSTRAINT "advisory_revision_explicit_version_revision_fkey"
  FOREIGN KEY ("advisory_revision_id") REFERENCES "advisory_revision"("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "advisory_revision_explicit_version"
  ADD CONSTRAINT "advisory_revision_explicit_version_shape_chk"
  CHECK (
    "ordinal" >= 0
    AND "ordinal" < 50000
    AND char_length("version_text") BETWEEN 1 AND 256
  );

CREATE FUNCTION patchpilot_advisory_revision_supersession_package()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  prior_package text;
BEGIN
  IF NEW."supersedes_advisory_revision_id" IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT prior."package_identity_key"
  INTO prior_package
  FROM "advisory_revision" prior
  WHERE prior."id" = NEW."supersedes_advisory_revision_id";

  IF NOT FOUND THEN
    RETURN NEW;
  END IF;

  IF prior_package IS DISTINCT FROM NEW."package_identity_key" THEN
    RAISE EXCEPTION 'advisory supersession package is inconsistent'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_advisory_revision_source_provenance_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_xmin xid;
  parent_source "advisory_evidence_source";
  parent_advisory_id text;
  parent_package text;
  parent_parser_id text;
  parent_parser_policy text;
  parent_schema_version text;
  parent_schema_commit text;
  parent_registry text;
  parent_origin "advisory_evidence_origin";
  parent_retrieval "advisory_retrieval_classification";
  parent_retrieval_evidence text;
  parent_generation text;
  parent_revision_schema text;
  parent_retrieval_policy text;
  parent_withdrawal "advisory_withdrawal_classification";
  batch_retrieved timestamptz;
  batch_registry text;
BEGIN
  SELECT parent.xmin,
         parent."source",
         parent."advisory_id",
         parent."package_identity_key",
         parent."parser_id",
         parent."parser_resource_policy",
         parent."advisory_schema_version",
         parent."advisory_schema_commit",
         parent."source_license_registry_version",
         parent."origin",
         parent."retrieval_classification",
         parent."retrieval_evidence_id",
         parent."provider_generation",
         parent."revision_schema_version",
         parent."retrieval_policy_id",
         parent."withdrawal_classification"
  INTO parent_xmin,
       parent_source,
       parent_advisory_id,
       parent_package,
       parent_parser_id,
       parent_parser_policy,
       parent_schema_version,
       parent_schema_commit,
       parent_registry,
       parent_origin,
       parent_retrieval,
       parent_retrieval_evidence,
       parent_generation,
       parent_revision_schema,
       parent_retrieval_policy,
       parent_withdrawal
  FROM "advisory_revision" parent
  WHERE parent."id" = NEW."advisory_revision_id";

  IF parent_xmin IS NULL THEN
    RAISE EXCEPTION 'offline advisory provenance parent is missing'
      USING ERRCODE = '23514';
  END IF;

  IF parent_xmin IS DISTINCT FROM pg_current_xact_id()::xid THEN
    RAISE EXCEPTION 'offline advisory provenance is closed'
      USING ERRCODE = '23514';
  END IF;

  IF parent_origin IS DISTINCT FROM 'provider_derived'
    OR parent_source IS DISTINCT FROM 'github_advisory_database'
    OR parent_retrieval IS DISTINCT FROM 'local_not_retrieved'
    OR parent_retrieval_evidence IS DISTINCT FROM 'offline_import_retrieval_not_applicable'
    OR parent_generation IS DISTINCT FROM 'offline-import-v1'
    OR parent_revision_schema IS DISTINCT FROM 'offline_npm_advisory_revision_identity_v1'
    OR parent_retrieval_policy IS DISTINCT FROM 'offline_osv_import_retrieval_policy_v1'
    OR parent_source IS DISTINCT FROM NEW."source"
    OR parent_advisory_id IS DISTINCT FROM NEW."advisory_id"
    OR parent_package IS DISTINCT FROM NEW."package_identity_key"
    OR parent_parser_id IS DISTINCT FROM NEW."parser_id"
    OR parent_parser_policy IS DISTINCT FROM NEW."parser_resource_policy"
    OR parent_schema_version IS DISTINCT FROM NEW."advisory_schema_version"
    OR parent_schema_commit IS DISTINCT FROM NEW."advisory_schema_commit"
    OR parent_registry IS DISTINCT FROM NEW."source_license_registry_version"
  THEN
    RAISE EXCEPTION 'offline advisory provenance does not agree'
      USING ERRCODE = '23514';
  END IF;

  IF parent_withdrawal = 'withdrawn' AND NEW."withdrawn_at" IS NULL THEN
    RAISE EXCEPTION 'offline advisory provenance withdrawal is missing'
      USING ERRCODE = '23514';
  END IF;

  IF parent_withdrawal IS DISTINCT FROM 'withdrawn' AND NEW."withdrawn_at" IS NOT NULL THEN
    RAISE EXCEPTION 'offline advisory provenance withdrawal is unexpected'
      USING ERRCODE = '23514';
  END IF;

  SELECT batch."retrieved_at", batch."source_license_registry_version"
  INTO batch_retrieved, batch_registry
  FROM "offline_advisory_import_batch" batch
  WHERE batch."id" = NEW."offline_advisory_import_batch_id";

  IF batch_retrieved IS NULL
    OR batch_retrieved IS DISTINCT FROM NEW."retrieved_at"
    OR batch_registry IS DISTINCT FROM NEW."source_license_registry_version"
  THEN
    RAISE EXCEPTION 'offline advisory provenance batch does not agree'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_advisory_revision_explicit_version_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_xmin xid;
  parent_origin "advisory_evidence_origin";
  parent_source "advisory_evidence_source";
  parent_retrieval "advisory_retrieval_classification";
  parent_retrieval_evidence text;
  parent_generation text;
  parent_revision_schema text;
  parent_retrieval_policy text;
BEGIN
  SELECT parent.xmin,
         parent."origin",
         parent."source",
         parent."retrieval_classification",
         parent."retrieval_evidence_id",
         parent."provider_generation",
         parent."revision_schema_version",
         parent."retrieval_policy_id"
  INTO parent_xmin,
       parent_origin,
       parent_source,
       parent_retrieval,
       parent_retrieval_evidence,
       parent_generation,
       parent_revision_schema,
       parent_retrieval_policy
  FROM "advisory_revision" parent
  WHERE parent."id" = NEW."advisory_revision_id";

  IF parent_xmin IS NULL THEN
    RAISE EXCEPTION 'offline advisory explicit version parent is missing'
      USING ERRCODE = '23514';
  END IF;

  IF parent_xmin IS DISTINCT FROM pg_current_xact_id()::xid THEN
    RAISE EXCEPTION 'offline advisory explicit versions are closed'
      USING ERRCODE = '23514';
  END IF;

  IF parent_origin IS DISTINCT FROM 'provider_derived'
    OR parent_source IS DISTINCT FROM 'github_advisory_database'
    OR parent_retrieval IS DISTINCT FROM 'local_not_retrieved'
    OR parent_retrieval_evidence IS DISTINCT FROM 'offline_import_retrieval_not_applicable'
    OR parent_generation IS DISTINCT FROM 'offline-import-v1'
    OR parent_revision_schema IS DISTINCT FROM 'offline_npm_advisory_revision_identity_v1'
    OR parent_retrieval_policy IS DISTINCT FROM 'offline_osv_import_retrieval_policy_v1'
  THEN
    RAISE EXCEPTION 'offline advisory explicit version parent is ineligible'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_advisory_revision_range_event_offline_closed()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_xmin xid;
  parent_origin "advisory_evidence_origin";
  parent_source "advisory_evidence_source";
  parent_retrieval "advisory_retrieval_classification";
  parent_retrieval_evidence text;
  parent_generation text;
  parent_revision_schema text;
  parent_retrieval_policy text;
BEGIN
  SELECT parent.xmin,
         parent."origin",
         parent."source",
         parent."retrieval_classification",
         parent."retrieval_evidence_id",
         parent."provider_generation",
         parent."revision_schema_version",
         parent."retrieval_policy_id"
  INTO parent_xmin,
       parent_origin,
       parent_source,
       parent_retrieval,
       parent_retrieval_evidence,
       parent_generation,
       parent_revision_schema,
       parent_retrieval_policy
  FROM "advisory_revision" parent
  WHERE parent."id" = NEW."advisory_revision_id";

  IF parent_xmin IS NULL THEN
    RETURN NEW;
  END IF;

  IF parent_origin IS DISTINCT FROM 'provider_derived'
    OR parent_source IS DISTINCT FROM 'github_advisory_database'
    OR parent_retrieval IS DISTINCT FROM 'local_not_retrieved'
    OR parent_retrieval_evidence IS DISTINCT FROM 'offline_import_retrieval_not_applicable'
    OR parent_generation IS DISTINCT FROM 'offline-import-v1'
    OR parent_revision_schema IS DISTINCT FROM 'offline_npm_advisory_revision_identity_v1'
    OR parent_retrieval_policy IS DISTINCT FROM 'offline_osv_import_retrieval_policy_v1'
  THEN
    RETURN NEW;
  END IF;

  IF parent_xmin IS DISTINCT FROM pg_current_xact_id()::xid THEN
    RAISE EXCEPTION 'offline advisory ranges are closed'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_offline_npm_advisory_revision_complete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  offline boolean;
  provenance_count integer;
  range_count integer;
  version_count integer;
  version_min integer;
  version_max integer;
BEGIN
  offline := NEW."origin" = 'provider_derived'
    AND NEW."source" = 'github_advisory_database'
    AND NEW."retrieval_classification" = 'local_not_retrieved'
    AND NEW."retrieval_evidence_id" = 'offline_import_retrieval_not_applicable'
    AND NEW."provider_generation" = 'offline-import-v1'
    AND NEW."revision_schema_version" = 'offline_npm_advisory_revision_identity_v1'
    AND NEW."retrieval_policy_id" = 'offline_osv_import_retrieval_policy_v1';

  SELECT COUNT(*)::integer
  INTO provenance_count
  FROM "advisory_revision_source_provenance" provenance
  WHERE provenance."advisory_revision_id" = NEW."id";

  SELECT COUNT(*)::integer,
         MIN(version."ordinal"),
         MAX(version."ordinal")
  INTO version_count, version_min, version_max
  FROM "advisory_revision_explicit_version" version
  WHERE version."advisory_revision_id" = NEW."id";

  IF NOT offline THEN
    IF provenance_count > 0 OR version_count > 0 THEN
      RAISE EXCEPTION 'offline advisory evidence is closed'
        USING ERRCODE = '23514';
    END IF;
    RETURN NULL;
  END IF;

  IF provenance_count IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'offline advisory provenance is missing'
      USING ERRCODE = '23514';
  END IF;

  SELECT COUNT(*)::integer
  INTO range_count
  FROM "advisory_revision_range_event" event
  WHERE event."advisory_revision_id" = NEW."id";

  IF range_count < 1 AND version_count < 1 THEN
    RAISE EXCEPTION 'offline advisory affectedness is empty'
      USING ERRCODE = '23514';
  END IF;

  IF version_count > 0 AND (
    version_min IS DISTINCT FROM 0
    OR version_max IS DISTINCT FROM version_count - 1
  ) THEN
    RAISE EXCEPTION 'offline advisory explicit versions are not contiguous'
      USING ERRCODE = '23514';
  END IF;

  RETURN NULL;
END;
$$;

CREATE TRIGGER offline_advisory_import_batch_append_only
  BEFORE UPDATE OR DELETE ON "offline_advisory_import_batch"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER advisory_revision_source_provenance_append_only
  BEFORE UPDATE OR DELETE ON "advisory_revision_source_provenance"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER advisory_revision_explicit_version_append_only
  BEFORE UPDATE OR DELETE ON "advisory_revision_explicit_version"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER patchpilot_advisory_revision_supersession_package
  BEFORE INSERT ON "advisory_revision"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_advisory_revision_supersession_package();

CREATE TRIGGER advisory_revision_source_provenance_guard
  BEFORE INSERT ON "advisory_revision_source_provenance"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_advisory_revision_source_provenance_guard();

CREATE TRIGGER advisory_revision_explicit_version_guard
  BEFORE INSERT ON "advisory_revision_explicit_version"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_advisory_revision_explicit_version_guard();

CREATE TRIGGER advisory_revision_range_event_offline_closed
  BEFORE INSERT ON "advisory_revision_range_event"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_advisory_revision_range_event_offline_closed();

CREATE CONSTRAINT TRIGGER offline_npm_advisory_revision_complete
  AFTER INSERT ON "advisory_revision"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION patchpilot_offline_npm_advisory_revision_complete();
