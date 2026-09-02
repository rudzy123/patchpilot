-- Session 9 Batch 4C: instance-owned KEV intelligence persistence.
-- Forward-only. Does not edit 20260826120000_schema_foundation through
-- 20260830120000_sbom_ingestion_graph_persistence.
-- New enums and tables only; no ALTER TYPE ADD VALUE on existing enums.
-- Do not freeze this file until independent review and tests succeed.

CREATE TYPE "intelligence_sync_run_state" AS ENUM (
  'requested',
  'fetching',
  'retry_wait',
  'stored',
  'parsing',
  'staging',
  'activating',
  'completed',
  'not_modified',
  'failed',
  'quarantined'
);

CREATE TYPE "intelligence_sync_run_stage" AS ENUM (
  'fetch',
  'store_snapshot',
  'validate',
  'parse',
  'stage_generation',
  'activate_generation',
  'finalize'
);

CREATE TYPE "kev_generation_state" AS ENUM (
  'staging',
  'complete',
  'active',
  'superseded',
  'abandoned'
);

CREATE TYPE "known_ransomware_campaign_use" AS ENUM (
  'known',
  'unknown',
  'other'
);

CREATE TYPE "intelligence_not_modified_reason" AS ENUM (
  'content_sha256_unchanged',
  'http_not_modified'
);

ALTER TABLE "intelligence_source"
  ADD COLUMN "last_attempt_at" TIMESTAMPTZ(6),
  ADD COLUMN "last_failure_code" VARCHAR(64),
  ADD COLUMN "active_generation_id" UUID;

CREATE TABLE "vulnerability_sync_run" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "provider_key" "integration_provider_key" NOT NULL,
  "source_identifier" VARCHAR(64) NOT NULL,
  "state" "intelligence_sync_run_state" NOT NULL DEFAULT 'requested',
  "stage" "intelligence_sync_run_stage",
  "requested_at" TIMESTAMPTZ(6) NOT NULL,
  "started_at" TIMESTAMPTZ(6),
  "completed_at" TIMESTAMPTZ(6),
  "next_attempt_at" TIMESTAMPTZ(6),
  "execution_attempt" INTEGER NOT NULL DEFAULT 0,
  "snapshot_id" UUID,
  "generation_id" UUID,
  "prior_accepted_generation_id" UUID,
  "parser_version" VARCHAR(64) NOT NULL,
  "normalization_version" VARCHAR(64) NOT NULL,
  "failure_category" VARCHAR(64),
  "failure_code" VARCHAR(64),
  "accepted_entry_count" INTEGER,
  "warning_count" INTEGER,
  "not_modified_reason" "intelligence_not_modified_reason",
  "correlation_id" VARCHAR(128) NOT NULL,
  "version" INTEGER NOT NULL DEFAULT 1,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "vulnerability_sync_run_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "vulnerability_provider_snapshot" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "provider_key" "integration_provider_key" NOT NULL,
  "source_identifier" VARCHAR(64) NOT NULL,
  "response_sha256" CHAR(64) NOT NULL,
  "byte_length" INTEGER NOT NULL,
  "declared_content_type" VARCHAR(128),
  "detected_content_type" VARCHAR(128),
  "object_key" VARCHAR(512) NOT NULL,
  "retrieved_at" TIMESTAMPTZ(6) NOT NULL,
  "stored_at" TIMESTAMPTZ(6) NOT NULL,
  "etag_hash" CHAR(64),
  "last_modified" TIMESTAMPTZ(6),
  "creating_sync_run_id" UUID NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "vulnerability_provider_snapshot_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "kev_generation" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "provider_key" "integration_provider_key" NOT NULL,
  "source_identifier" VARCHAR(64) NOT NULL,
  "sync_run_id" UUID NOT NULL,
  "snapshot_id" UUID NOT NULL,
  "state" "kev_generation_state" NOT NULL DEFAULT 'staging',
  "expected_entry_count" INTEGER NOT NULL,
  "staged_entry_count" INTEGER NOT NULL DEFAULT 0,
  "parser_version" VARCHAR(64) NOT NULL,
  "normalization_version" VARCHAR(64) NOT NULL,
  "catalog_version" VARCHAR(128),
  "catalog_released_at" TIMESTAMPTZ(6),
  "completed_at" TIMESTAMPTZ(6),
  "activated_at" TIMESTAMPTZ(6),
  "superseded_at" TIMESTAMPTZ(6),
  "abandoned_at" TIMESTAMPTZ(6),
  "version" INTEGER NOT NULL DEFAULT 1,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "kev_generation_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "kev_entry" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "generation_id" UUID NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "normalized_cve" VARCHAR(32) NOT NULL,
  "vendor_project" TEXT NOT NULL,
  "product" TEXT NOT NULL,
  "vulnerability_name" TEXT NOT NULL,
  "date_added" CHAR(10) NOT NULL,
  "short_description" TEXT NOT NULL,
  "required_action" TEXT NOT NULL,
  "due_date" CHAR(10) NOT NULL,
  "known_ransomware_campaign_use" "known_ransomware_campaign_use" NOT NULL,
  "raw_known_ransomware_campaign_use" VARCHAR(64),
  "notes" TEXT,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "kev_entry_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "kev_entry_cwe" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "entry_id" UUID NOT NULL,
  "ordinal" INTEGER NOT NULL,
  "normalized_cwe" VARCHAR(32) NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "kev_entry_cwe_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "vulnerability_provider_snapshot_natural_key"
  ON "vulnerability_provider_snapshot" ("provider_key", "source_identifier", "response_sha256");

CREATE UNIQUE INDEX "kev_generation_sync_run_uidx"
  ON "kev_generation" ("sync_run_id");

CREATE UNIQUE INDEX "kev_generation_id_sync_run_key"
  ON "kev_generation" ("id", "sync_run_id");

CREATE UNIQUE INDEX "kev_entry_generation_cve_uidx"
  ON "kev_entry" ("generation_id", "normalized_cve");

CREATE UNIQUE INDEX "kev_entry_generation_ordinal_uidx"
  ON "kev_entry" ("generation_id", "ordinal");

CREATE UNIQUE INDEX "kev_entry_cwe_ordinal_uidx"
  ON "kev_entry_cwe" ("entry_id", "ordinal");

CREATE UNIQUE INDEX "kev_entry_cwe_value_uidx"
  ON "kev_entry_cwe" ("entry_id", "normalized_cwe");

CREATE UNIQUE INDEX "kev_generation_one_active_uidx"
  ON "kev_generation" ("provider_key", "source_identifier")
  WHERE "state" = 'active';

CREATE UNIQUE INDEX "vulnerability_sync_run_inflight_uidx"
  ON "vulnerability_sync_run" ("provider_key", "source_identifier")
  WHERE "state" NOT IN ('completed', 'not_modified', 'failed', 'quarantined');

CREATE INDEX "vulnerability_sync_run_provider_requested_idx"
  ON "vulnerability_sync_run" ("provider_key", "source_identifier", "requested_at" DESC, "id" DESC);

CREATE INDEX "vulnerability_sync_run_retry_wait_idx"
  ON "vulnerability_sync_run" ("next_attempt_at", "id")
  WHERE "state" = 'retry_wait';

CREATE INDEX "kev_generation_snapshot_idx"
  ON "kev_generation" ("snapshot_id");

CREATE INDEX "kev_generation_incomplete_age_idx"
  ON "kev_generation" ("state", "created_at")
  WHERE "state" IN ('staging', 'complete');

CREATE INDEX "kev_entry_generation_ordinal_id_idx"
  ON "kev_entry" ("generation_id", "ordinal", "id");

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_provider_key_fkey"
  FOREIGN KEY ("provider_key") REFERENCES "integration_provider"("provider_key")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "vulnerability_provider_snapshot"
  ADD CONSTRAINT "vulnerability_provider_snapshot_provider_key_fkey"
  FOREIGN KEY ("provider_key") REFERENCES "integration_provider"("provider_key")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "vulnerability_provider_snapshot"
  ADD CONSTRAINT "vulnerability_provider_snapshot_creating_sync_run_id_fkey"
  FOREIGN KEY ("creating_sync_run_id") REFERENCES "vulnerability_sync_run"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_snapshot_id_fkey"
  FOREIGN KEY ("snapshot_id") REFERENCES "vulnerability_provider_snapshot"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_provider_key_fkey"
  FOREIGN KEY ("provider_key") REFERENCES "integration_provider"("provider_key")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_sync_run_id_fkey"
  FOREIGN KEY ("sync_run_id") REFERENCES "vulnerability_sync_run"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_snapshot_id_fkey"
  FOREIGN KEY ("snapshot_id") REFERENCES "vulnerability_provider_snapshot"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_generation_id_fkey"
  FOREIGN KEY ("generation_id") REFERENCES "kev_generation"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_generation_owned_fkey"
  FOREIGN KEY ("generation_id", "id") REFERENCES "kev_generation"("id", "sync_run_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_prior_accepted_generation_id_fkey"
  FOREIGN KEY ("prior_accepted_generation_id") REFERENCES "kev_generation"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "kev_entry"
  ADD CONSTRAINT "kev_entry_generation_id_fkey"
  FOREIGN KEY ("generation_id") REFERENCES "kev_generation"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "kev_entry_cwe"
  ADD CONSTRAINT "kev_entry_cwe_entry_id_fkey"
  FOREIGN KEY ("entry_id") REFERENCES "kev_entry"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "intelligence_source"
  ADD CONSTRAINT "intelligence_source_active_generation_id_fkey"
  FOREIGN KEY ("active_generation_id") REFERENCES "kev_generation"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_provider_chk"
  CHECK ("provider_key" = 'cisa_kev');

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_source_chk"
  CHECK ("source_identifier" = 'cisa_kev_json_catalog');

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_version_chk"
  CHECK ("version" >= 1);

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_execution_attempt_chk"
  CHECK ("execution_attempt" >= 0);

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_parser_version_label_chk"
  CHECK ("parser_version" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$');

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_normalization_version_label_chk"
  CHECK ("normalization_version" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$');

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_correlation_id_chk"
  CHECK ("correlation_id" ~ '^[A-Za-z0-9._:-]{1,128}$');

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_failure_token_chk"
  CHECK (
    ("failure_category" IS NULL OR "failure_category" ~ '^[a-z0-9_]{1,64}$')
    AND ("failure_code" IS NULL OR "failure_code" ~ '^[a-z0-9_]{1,64}$')
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_counts_nonnegative_chk"
  CHECK (
    ("accepted_entry_count" IS NULL OR "accepted_entry_count" >= 0)
    AND ("warning_count" IS NULL OR "warning_count" >= 0)
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_completed_after_started_chk"
  CHECK (
    "completed_at" IS NULL
    OR "started_at" IS NULL
    OR "completed_at" >= "started_at"
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_requested_chk"
  CHECK (
    "state" <> 'requested'
    OR (
      "stage" IS NULL
      AND "started_at" IS NULL
      AND "completed_at" IS NULL
      AND "next_attempt_at" IS NULL
      AND "execution_attempt" = 0
      AND "snapshot_id" IS NULL
      AND "generation_id" IS NULL
      AND "prior_accepted_generation_id" IS NULL
      AND "failure_category" IS NULL
      AND "failure_code" IS NULL
      AND "accepted_entry_count" IS NULL
      AND "warning_count" IS NULL
      AND "not_modified_reason" IS NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_fetching_chk"
  CHECK (
    "state" <> 'fetching'
    OR (
      "started_at" IS NOT NULL
      AND "stage" = 'fetch'
      AND "execution_attempt" >= 1
      AND "completed_at" IS NULL
      AND "next_attempt_at" IS NULL
      AND "failure_category" IS NULL
      AND "failure_code" IS NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_retry_wait_chk"
  CHECK (
    "state" <> 'retry_wait'
    OR (
      "started_at" IS NOT NULL
      AND "completed_at" IS NULL
      AND "next_attempt_at" IS NOT NULL
      AND "execution_attempt" >= 1
      AND "failure_category" IS NOT NULL
      AND "failure_code" IS NOT NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_stored_chk"
  CHECK (
    "state" <> 'stored'
    OR (
      "started_at" IS NOT NULL
      AND "snapshot_id" IS NOT NULL
      AND "generation_id" IS NULL
      AND "completed_at" IS NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_parsing_chk"
  CHECK (
    "state" <> 'parsing'
    OR (
      "started_at" IS NOT NULL
      AND "snapshot_id" IS NOT NULL
      AND "completed_at" IS NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_staging_chk"
  CHECK (
    "state" <> 'staging'
    OR (
      "started_at" IS NOT NULL
      AND "snapshot_id" IS NOT NULL
      AND "generation_id" IS NOT NULL
      AND "completed_at" IS NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_activating_chk"
  CHECK (
    "state" <> 'activating'
    OR (
      "started_at" IS NOT NULL
      AND "snapshot_id" IS NOT NULL
      AND "generation_id" IS NOT NULL
      AND "completed_at" IS NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_completed_chk"
  CHECK (
    "state" <> 'completed'
    OR (
      "started_at" IS NOT NULL
      AND "snapshot_id" IS NOT NULL
      AND "generation_id" IS NOT NULL
      AND "completed_at" IS NOT NULL
      AND "accepted_entry_count" IS NOT NULL
      AND "accepted_entry_count" >= 0
      AND "warning_count" IS NOT NULL
      AND "warning_count" >= 0
      AND "failure_category" IS NULL
      AND "failure_code" IS NULL
      AND "not_modified_reason" IS NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_not_modified_chk"
  CHECK (
    "state" <> 'not_modified'
    OR (
      "started_at" IS NOT NULL
      AND "completed_at" IS NOT NULL
      AND "prior_accepted_generation_id" IS NOT NULL
      AND "not_modified_reason" IS NOT NULL
      AND "snapshot_id" IS NULL
      AND "generation_id" IS NULL
      AND "failure_category" IS NULL
      AND "failure_code" IS NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_failed_chk"
  CHECK (
    "state" <> 'failed'
    OR (
      "completed_at" IS NOT NULL
      AND "failure_category" IS NOT NULL
      AND "failure_code" IS NOT NULL
    )
  );

ALTER TABLE "vulnerability_sync_run"
  ADD CONSTRAINT "vulnerability_sync_run_quarantined_chk"
  CHECK (
    "state" <> 'quarantined'
    OR (
      "completed_at" IS NOT NULL
      AND "failure_category" IS NOT NULL
      AND "failure_code" IS NOT NULL
    )
  );

ALTER TABLE "vulnerability_provider_snapshot"
  ADD CONSTRAINT "vulnerability_provider_snapshot_provider_chk"
  CHECK ("provider_key" = 'cisa_kev');

ALTER TABLE "vulnerability_provider_snapshot"
  ADD CONSTRAINT "vulnerability_provider_snapshot_source_chk"
  CHECK ("source_identifier" = 'cisa_kev_json_catalog');

ALTER TABLE "vulnerability_provider_snapshot"
  ADD CONSTRAINT "vulnerability_provider_snapshot_sha256_chk"
  CHECK ("response_sha256" ~ '^[a-f0-9]{64}$');

ALTER TABLE "vulnerability_provider_snapshot"
  ADD CONSTRAINT "vulnerability_provider_snapshot_etag_hash_chk"
  CHECK ("etag_hash" IS NULL OR "etag_hash" ~ '^[a-f0-9]{64}$');

ALTER TABLE "vulnerability_provider_snapshot"
  ADD CONSTRAINT "vulnerability_provider_snapshot_byte_length_chk"
  CHECK ("byte_length" > 0);

ALTER TABLE "vulnerability_provider_snapshot"
  ADD CONSTRAINT "vulnerability_provider_snapshot_object_key_chk"
  CHECK (
    char_length("object_key") BETWEEN 1 AND 512
    AND octet_length("object_key") BETWEEN 1 AND 512
    AND "object_key" ~ '^[A-Za-z0-9][A-Za-z0-9._~/-]*$'
    AND position('://' in "object_key") = 0
    AND position('//' in "object_key") = 0
    AND position('..' in "object_key") = 0
  );

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_provider_chk"
  CHECK ("provider_key" = 'cisa_kev');

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_source_chk"
  CHECK ("source_identifier" = 'cisa_kev_json_catalog');

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_version_chk"
  CHECK ("version" >= 1);

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_counts_chk"
  CHECK (
    "expected_entry_count" >= 0
    AND "expected_entry_count" <= 8192
    AND "staged_entry_count" >= 0
  );

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_parser_version_label_chk"
  CHECK ("parser_version" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$');

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_normalization_version_label_chk"
  CHECK ("normalization_version" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$');

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_completed_after_created_chk"
  CHECK ("completed_at" IS NULL OR "completed_at" >= "created_at");

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_activated_after_completed_chk"
  CHECK (
    "activated_at" IS NULL
    OR ("completed_at" IS NOT NULL AND "activated_at" >= "completed_at")
  );

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_superseded_after_activated_chk"
  CHECK (
    "superseded_at" IS NULL
    OR ("activated_at" IS NOT NULL AND "superseded_at" >= "activated_at")
  );

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_staging_chk"
  CHECK (
    "state" <> 'staging'
    OR (
      "completed_at" IS NULL
      AND "activated_at" IS NULL
      AND "superseded_at" IS NULL
      AND "abandoned_at" IS NULL
    )
  );

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_complete_chk"
  CHECK (
    "state" <> 'complete'
    OR (
      "completed_at" IS NOT NULL
      AND "activated_at" IS NULL
      AND "superseded_at" IS NULL
      AND "abandoned_at" IS NULL
      AND "staged_entry_count" = "expected_entry_count"
      AND "catalog_version" IS NOT NULL
      AND "catalog_released_at" IS NOT NULL
    )
  );

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_active_chk"
  CHECK (
    "state" <> 'active'
    OR (
      "completed_at" IS NOT NULL
      AND "activated_at" IS NOT NULL
      AND "superseded_at" IS NULL
      AND "abandoned_at" IS NULL
      AND "staged_entry_count" = "expected_entry_count"
      AND "catalog_version" IS NOT NULL
      AND "catalog_released_at" IS NOT NULL
    )
  );

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_superseded_chk"
  CHECK (
    "state" <> 'superseded'
    OR (
      "completed_at" IS NOT NULL
      AND "activated_at" IS NOT NULL
      AND "superseded_at" IS NOT NULL
      AND "abandoned_at" IS NULL
      AND "staged_entry_count" = "expected_entry_count"
      AND "catalog_version" IS NOT NULL
      AND "catalog_released_at" IS NOT NULL
    )
  );

ALTER TABLE "kev_generation"
  ADD CONSTRAINT "kev_generation_abandoned_chk"
  CHECK (
    "state" <> 'abandoned'
    OR (
      "abandoned_at" IS NOT NULL
      AND "activated_at" IS NULL
      AND "superseded_at" IS NULL
    )
  );

ALTER TABLE "kev_entry"
  ADD CONSTRAINT "kev_entry_ordinal_chk"
  CHECK ("ordinal" >= 0);

ALTER TABLE "kev_entry"
  ADD CONSTRAINT "kev_entry_cve_chk"
  CHECK ("normalized_cve" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$');

ALTER TABLE "kev_entry"
  ADD CONSTRAINT "kev_entry_date_added_chk"
  CHECK (
    "date_added" ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
    AND ("date_added"::date)::text = "date_added"
  );

ALTER TABLE "kev_entry"
  ADD CONSTRAINT "kev_entry_due_date_chk"
  CHECK (
    "due_date" ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
    AND ("due_date"::date)::text = "due_date"
  );

ALTER TABLE "kev_entry"
  ADD CONSTRAINT "kev_entry_text_bytes_chk"
  CHECK (
    octet_length("vendor_project") BETWEEN 1 AND 16384
    AND octet_length("product") BETWEEN 1 AND 16384
    AND octet_length("vulnerability_name") BETWEEN 1 AND 16384
    AND octet_length("short_description") BETWEEN 1 AND 16384
    AND octet_length("required_action") BETWEEN 1 AND 16384
    AND ("notes" IS NULL OR octet_length("notes") BETWEEN 1 AND 16384)
  );

ALTER TABLE "kev_entry"
  ADD CONSTRAINT "kev_entry_ransomware_raw_chk"
  CHECK (
    (
      "known_ransomware_campaign_use" = 'other'
      AND "raw_known_ransomware_campaign_use" IS NOT NULL
      AND char_length("raw_known_ransomware_campaign_use") BETWEEN 1 AND 64
    )
    OR (
      "known_ransomware_campaign_use" IN ('known', 'unknown')
      AND "raw_known_ransomware_campaign_use" IS NULL
    )
  );

ALTER TABLE "kev_entry_cwe"
  ADD CONSTRAINT "kev_entry_cwe_ordinal_chk"
  CHECK ("ordinal" >= 0 AND "ordinal" <= 15);

ALTER TABLE "kev_entry_cwe"
  ADD CONSTRAINT "kev_entry_cwe_value_chk"
  CHECK ("normalized_cwe" ~ '^CWE-[0-9]{1,8}$');

ALTER TABLE "intelligence_source"
  ADD CONSTRAINT "intelligence_source_active_provider_chk"
  CHECK ("active_generation_id" IS NULL OR "provider_key" = 'cisa_kev');

ALTER TABLE "intelligence_source"
  ADD CONSTRAINT "intelligence_source_last_failure_code_chk"
  CHECK (
    "last_failure_code" IS NULL
    OR "last_failure_code" ~ '^[a-z0-9_]{1,64}$'
  );

CREATE OR REPLACE FUNCTION patchpilot_intelligence_source_active_generation()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  generation_state kev_generation_state;
  generation_provider integration_provider_key;
  generation_source VARCHAR(64);
BEGIN
  IF NEW.active_generation_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT "state", "provider_key", "source_identifier"
    INTO generation_state, generation_provider, generation_source
    FROM "kev_generation"
    WHERE "id" = NEW.active_generation_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION
      'intelligence_source active_generation_id must reference an existing generation';
  END IF;
  IF NEW.provider_key <> 'cisa_kev'
     OR generation_provider <> 'cisa_kev'
     OR generation_source <> 'cisa_kev_json_catalog'
     OR generation_state <> 'active' THEN
    RAISE EXCEPTION
      'intelligence_source active_generation_id must reference an active CISA KEV catalog generation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER intelligence_source_active_generation
  BEFORE INSERT OR UPDATE OF "active_generation_id", "provider_key"
  ON "intelligence_source"
  FOR EACH ROW
  EXECUTE FUNCTION patchpilot_intelligence_source_active_generation();

CREATE TRIGGER vulnerability_provider_snapshot_append_only
  BEFORE UPDATE OR DELETE ON "vulnerability_provider_snapshot"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER kev_entry_append_only
  BEFORE UPDATE OR DELETE ON "kev_entry"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER kev_entry_cwe_append_only
  BEFORE UPDATE OR DELETE ON "kev_entry_cwe"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();
