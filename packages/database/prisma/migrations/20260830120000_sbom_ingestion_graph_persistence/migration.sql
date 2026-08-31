-- Session 8 Batch 4: SBOM ingestion graph persistence columns, insert-once
-- graph constraints, nullable Component.ecosystem, occurrence versionKnown,
-- generic idempotency response matrix, and claim/execution indexes.
-- Forward-only. Does not edit 20260826120000_schema_foundation through
-- 20260828120000_asset_inventory_constraints.

CREATE TYPE "sbom_graph_completeness" AS ENUM (
  'empty',
  'no_dependencies',
  'partial',
  'complete'
);

ALTER TABLE "sbom_ingestion"
  ADD COLUMN "graph_completeness" "sbom_graph_completeness",
  ADD COLUMN "normalization_version" VARCHAR(64) NOT NULL DEFAULT '1',
  ADD COLUMN "component_count" INTEGER,
  ADD COLUMN "dependency_edge_count" INTEGER,
  ADD COLUMN "warning_count" INTEGER;

ALTER TABLE "component_occurrence"
  ADD COLUMN "version_known" BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE "component"
  ALTER COLUMN "ecosystem" DROP NOT NULL;

-- Existing completed rows cannot be truthfully given graph completeness or
-- counts. Refuse to invent values; stop rather than backfill.
DO $$
DECLARE
  incomplete_completed integer;
  missing_failure integer;
  empty_known_version integer;
BEGIN
  SELECT COUNT(*) INTO incomplete_completed
  FROM "sbom_ingestion"
  WHERE "state" = 'completed'
    AND (
      "graph_completeness" IS NULL
      OR "component_count" IS NULL
      OR "dependency_edge_count" IS NULL
      OR "warning_count" IS NULL
      OR "completed_at" IS NULL
    );
  IF incomplete_completed > 0 THEN
    RAISE EXCEPTION
      'sbom_ingestion has % completed rows without graph completeness evidence; refusing to invent values',
      incomplete_completed;
  END IF;

  SELECT COUNT(*) INTO missing_failure
  FROM "sbom_ingestion"
  WHERE "state" IN ('rejected', 'quarantined', 'failed')
    AND ("failure_category" IS NULL OR "failure_code" IS NULL);
  IF missing_failure > 0 THEN
    RAISE EXCEPTION
      'sbom_ingestion has % terminal failure rows missing failure_category or failure_code',
      missing_failure;
  END IF;

  SELECT COUNT(*) INTO empty_known_version
  FROM "component_occurrence"
  WHERE "version" = '';
  IF empty_known_version > 0 THEN
    RAISE EXCEPTION
      'component_occurrence has % empty version rows; cannot default version_known to true',
      empty_known_version;
  END IF;
END $$;

ALTER TABLE "sbom_ingestion"
  DROP CONSTRAINT IF EXISTS sbom_ingestion_completed_ts_chk;

ALTER TABLE "sbom_ingestion"
  DROP CONSTRAINT IF EXISTS sbom_ingestion_failure_code_chk;

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_processing_started_chk
  CHECK ("state" <> 'processing' OR "started_at" IS NOT NULL);

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_completed_requirements_chk
  CHECK (
    "state" <> 'completed'
    OR (
      "completed_at" IS NOT NULL
      AND "graph_completeness" IS NOT NULL
      AND "component_count" IS NOT NULL
      AND "dependency_edge_count" IS NOT NULL
      AND "warning_count" IS NOT NULL
      AND "failure_category" IS NULL
      AND "failure_code" IS NULL
    )
  );

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_graph_counts_nonnegative_chk
  CHECK (
    ("component_count" IS NULL OR "component_count" >= 0)
    AND ("dependency_edge_count" IS NULL OR "dependency_edge_count" >= 0)
    AND ("warning_count" IS NULL OR "warning_count" >= 0)
  );

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_graph_completeness_counts_chk
  CHECK (
    "graph_completeness" IS NULL
    OR (
      (
        "graph_completeness" = 'empty'
        AND "component_count" = 0
        AND "dependency_edge_count" = 0
      )
      OR (
        "graph_completeness" = 'no_dependencies'
        AND "component_count" > 0
        AND "dependency_edge_count" = 0
      )
      OR (
        "graph_completeness" IN ('partial', 'complete')
        AND "component_count" > 0
        AND "dependency_edge_count" > 0
      )
    )
  );

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_non_completed_graph_null_chk
  CHECK (
    "state" = 'completed'
    OR (
      "graph_completeness" IS NULL
      AND "component_count" IS NULL
      AND "dependency_edge_count" IS NULL
      AND "warning_count" IS NULL
    )
  );

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_failure_pair_chk
  CHECK (
    "state" NOT IN ('rejected', 'quarantined', 'failed')
    OR ("failure_category" IS NOT NULL AND "failure_code" IS NOT NULL)
  );

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_completed_after_started_chk
  CHECK (
    "completed_at" IS NULL
    OR "started_at" IS NULL
    OR "completed_at" >= "started_at"
  );

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_parser_version_label_chk
  CHECK ("parser_version" ~ '^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$');

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_normalization_version_label_chk
  CHECK ("normalization_version" ~ '^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$');

ALTER TABLE "sbom"
  ADD CONSTRAINT sbom_parser_version_last_succeeded_label_chk
  CHECK (
    "parser_version_last_succeeded" IS NULL
    OR "parser_version_last_succeeded" ~ '^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$'
  );

ALTER TABLE "component"
  ADD CONSTRAINT component_ecosystem_null_or_nonempty_chk
  CHECK ("ecosystem" IS NULL OR char_length("ecosystem") > 0);

ALTER TABLE "component_occurrence"
  ADD CONSTRAINT component_occurrence_version_known_chk
  CHECK (
    ("version_known" = TRUE AND char_length("version") > 0)
    OR ("version_known" = FALSE AND "version" = '')
  );

CREATE UNIQUE INDEX component_occurrence_org_ingestion_bom_ref_uidx
  ON "component_occurrence" ("organization_id", "sbom_ingestion_id", "bom_ref")
  WHERE "bom_ref" IS NOT NULL;

CREATE INDEX "sbom_ingestion_org_sbom_created_idx"
  ON "sbom_ingestion" ("organization_id", "sbom_id", "created_at", "id");

-- Expired-claimed outbox branch: status='claimed' ORDER BY available_at, id.
-- Distinct from outbox_event_available_work_idx (pending only).
CREATE INDEX outbox_event_claimed_lease_idx
  ON "outbox_event" ("available_at", "id")
  WHERE "status" = 'claimed';

CREATE UNIQUE INDEX "background_job_outbox_event_uidx"
  ON "background_job" ("outbox_event_id");

ALTER TABLE "idempotency_record"
  DROP CONSTRAINT IF EXISTS idempotency_record_completed_ts_chk;

ALTER TABLE "idempotency_record"
  ADD CONSTRAINT idempotency_record_status_response_chk
  CHECK (
    (
      "status" = 'started'
      AND "response" IS NULL
      AND "response_status" IS NULL
      AND "completed_at" IS NULL
    )
    OR (
      "status" = 'completed'
      AND "response" IS NOT NULL
      AND jsonb_typeof("response") = 'object'
      AND "response" ? 'schemaVersion'
      AND jsonb_typeof("response" -> 'schemaVersion') = 'number'
      AND "response_status" IS NOT NULL
      AND "completed_at" IS NOT NULL
    )
    OR "status" = 'conflict'
  );
