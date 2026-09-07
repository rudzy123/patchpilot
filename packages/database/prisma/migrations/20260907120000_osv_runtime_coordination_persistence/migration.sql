-- Session 12 Batch 6: OSV runtime coordination persistence foundation.
-- Forward-only. Does not edit 20260826120000_schema_foundation through
-- 20260904180000_osv_parsed_revision_id_check_correction.
-- New enums and tables only. No ALTER TYPE ADD VALUE on existing enums.
-- No lease seed, no synchronization-request seed, no retry-attempt seed,
-- no tenant rows, no Finding rows, no active catalog seed, no provider
-- bodies, no raw holder tokens, no page tokens, and no arbitrary JSON.
-- All new foreign keys are ON DELETE RESTRICT.

-- CreateEnum
CREATE TYPE "osv_runtime_job_request_state" AS ENUM ('requested', 'accepted', 'rejected', 'duplicate', 'superseded');

-- CreateEnum
CREATE TYPE "osv_runtime_synchronization_reason" AS ENUM ('scheduler', 'operator_canary', 'operator_production');

-- CreateEnum
CREATE TYPE "osv_runtime_work_scope" AS ENUM ('osv_runtime_production_scope_six_prefix_v1', 'osv_runtime_canary_scope_crates_io_rustsec_v1');

-- CreateEnum
CREATE TYPE "osv_runtime_job_request_kind" AS ENUM ('scheduler_window', 'operator_request');

-- CreateEnum
CREATE TYPE "osv_runtime_run_state" AS ENUM ('planned', 'waiting_for_lease', 'running', 'retry_wait', 'halted', 'cancelled', 'failed', 'completed');

-- CreateEnum
CREATE TYPE "osv_runtime_lease_projection_state" AS ENUM ('held', 'released');

-- CreateEnum
CREATE TYPE "osv_runtime_lease_release_reason" AS ENUM ('completed', 'cancelled', 'failed', 'shutdown');

-- CreateEnum
CREATE TYPE "osv_runtime_retryable_stage" AS ENUM ('listing_page', 'inventory_convergence', 'provider_body_retrieval', 'artifact_attachment', 'database_stage', 'parser_startup', 'parser_execution_timeout', 'parser_capacity');

-- CreateEnum
CREATE TYPE "osv_runtime_attempt_state" AS ENUM ('planned', 'running', 'succeeded', 'retryable_failed', 'permanent_failed', 'exhausted', 'cancelled');

-- CreateEnum
CREATE TYPE "osv_runtime_retry_eligibility" AS ENUM ('durable_retry', 'new_synchronization_attempt', 'no_retry', 'quarantine_required', 'retry_exhausted');

-- CreateTable
CREATE TABLE "osv_runtime_synchronization_request" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "job_type" VARCHAR(128) NOT NULL,
    "job_schema_version" VARCHAR(128) NOT NULL,
    "synchronization_reason" "osv_runtime_synchronization_reason" NOT NULL,
    "work_scope" "osv_runtime_work_scope" NOT NULL,
    "lease_scope" VARCHAR(128) NOT NULL,
    "catalog_scope" VARCHAR(128) NOT NULL,
    "version_set_fingerprint" TEXT NOT NULL,
    "requested_at" TIMESTAMPTZ(6) NOT NULL,
    "correlation_id" UUID NOT NULL,
    "canary_policy_identifier" VARCHAR(128),
    "request_kind" "osv_runtime_job_request_kind" NOT NULL,
    "scheduler_window_id" VARCHAR(128),
    "operator_request_id" UUID,
    "request_state" "osv_runtime_job_request_state" NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_runtime_synchronization_request_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_runtime_synchronization_run" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "request_id" UUID NOT NULL,
    "work_scope" "osv_runtime_work_scope" NOT NULL,
    "lease_scope" VARCHAR(128) NOT NULL,
    "synchronization_reason" "osv_runtime_synchronization_reason" NOT NULL,
    "pagination_policy_identifier" VARCHAR(128) NOT NULL,
    "version_set_fingerprint" TEXT NOT NULL,
    "runtime_architecture_identifier" VARCHAR(128) NOT NULL,
    "synchronization_algorithm_identifier" VARCHAR(128) NOT NULL,
    "retry_policy_identifier" VARCHAR(128) NOT NULL,
    "state" "osv_runtime_run_state" NOT NULL,
    "started_at" TIMESTAMPTZ(6),
    "terminal_at" TIMESTAMPTZ(6),
    "terminal_code" VARCHAR(64),
    "retry_disposition" "osv_runtime_retry_eligibility",
    "last_accepted_stage" "osv_runtime_retryable_stage",
    "cancellation_boundary" VARCHAR(64),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "osv_runtime_synchronization_run_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_runtime_lease_projection" (
    "scope" VARCHAR(128) NOT NULL,
    "run_id" UUID NOT NULL,
    "holder_token_digest" TEXT NOT NULL,
    "row_revision" BIGINT NOT NULL,
    "fencing_token" BIGINT NOT NULL,
    "state" "osv_runtime_lease_projection_state" NOT NULL,
    "acquired_at" TIMESTAMPTZ(6) NOT NULL,
    "heartbeat_at" TIMESTAMPTZ(6) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "released_at" TIMESTAMPTZ(6),
    "release_reason" "osv_runtime_lease_release_reason",
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "osv_runtime_lease_projection_pkey" PRIMARY KEY ("scope")
);

-- CreateTable
CREATE TABLE "osv_runtime_stage_attempt" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "run_id" UUID NOT NULL,
    "stage" "osv_runtime_retryable_stage" NOT NULL,
    "target_identity_digest" TEXT,
    "attempt_ordinal" INTEGER NOT NULL,
    "retry_policy_identifier" VARCHAR(128) NOT NULL,
    "state" "osv_runtime_attempt_state" NOT NULL,
    "started_at" TIMESTAMPTZ(6),
    "terminal_at" TIMESTAMPTZ(6),
    "failure_code" VARCHAR(64),
    "failure_catalog" VARCHAR(32),
    "retry_disposition" "osv_runtime_retry_eligibility" NOT NULL,
    "nominal_delay_ms" INTEGER NOT NULL,
    "selected_delay_ms" INTEGER NOT NULL,
    "retry_not_before" TIMESTAMPTZ(6),
    "retry_exhausted" BOOLEAN NOT NULL,
    "version_set_fingerprint" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_runtime_stage_attempt_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "osv_runtime_sync_request_correlation_idx" ON "osv_runtime_synchronization_request"("correlation_id");

-- CreateIndex
CREATE INDEX "osv_runtime_sync_request_requested_idx" ON "osv_runtime_synchronization_request"("requested_at");

-- CreateIndex
CREATE UNIQUE INDEX "osv_runtime_sync_request_pin_key" ON "osv_runtime_synchronization_request"("id", "work_scope", "synchronization_reason", "version_set_fingerprint", "lease_scope");

-- CreateIndex
CREATE UNIQUE INDEX "osv_runtime_sync_request_operator_uidx" ON "osv_runtime_synchronization_request"("operator_request_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_runtime_sync_request_scheduler_uidx" ON "osv_runtime_synchronization_request"("scheduler_window_id", "work_scope", "synchronization_reason", "version_set_fingerprint") WHERE "request_kind" = 'scheduler_window';

-- CreateIndex
CREATE INDEX "osv_runtime_sync_run_scope_state_idx" ON "osv_runtime_synchronization_run"("work_scope", "state");

-- CreateIndex
CREATE INDEX "osv_runtime_sync_run_fingerprint_idx" ON "osv_runtime_synchronization_run"("version_set_fingerprint");

-- CreateIndex
CREATE INDEX "osv_runtime_sync_run_state_created_idx" ON "osv_runtime_synchronization_run"("state", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "osv_runtime_sync_run_request_uidx" ON "osv_runtime_synchronization_run"("request_id");

-- CreateIndex
CREATE INDEX "osv_runtime_lease_projection_run_idx" ON "osv_runtime_lease_projection"("run_id");

-- CreateIndex
CREATE INDEX "osv_runtime_lease_projection_expires_idx" ON "osv_runtime_lease_projection"("expires_at");

-- CreateIndex
CREATE INDEX "osv_runtime_stage_attempt_run_stage_idx" ON "osv_runtime_stage_attempt"("run_id", "stage");

-- CreateIndex
CREATE INDEX "osv_runtime_stage_attempt_target_ordinal_idx" ON "osv_runtime_stage_attempt"("run_id", "target_identity_digest", "attempt_ordinal");

-- CreateIndex
CREATE INDEX "osv_runtime_stage_attempt_retry_not_before_idx" ON "osv_runtime_stage_attempt"("retry_not_before");

-- CreateIndex
CREATE INDEX "osv_runtime_stage_attempt_run_state_idx" ON "osv_runtime_stage_attempt"("run_id", "state");

-- CreateIndex
CREATE UNIQUE INDEX "osv_runtime_stage_attempt_null_target_uidx" ON "osv_runtime_stage_attempt"("run_id", "stage", "attempt_ordinal") WHERE "target_identity_digest" IS NULL;

-- CreateIndex
CREATE UNIQUE INDEX "osv_runtime_stage_attempt_target_uidx" ON "osv_runtime_stage_attempt"("run_id", "stage", "target_identity_digest", "attempt_ordinal") WHERE "target_identity_digest" IS NOT NULL;

-- AddForeignKey
ALTER TABLE "osv_runtime_synchronization_run" ADD CONSTRAINT "osv_runtime_synchronization_run_request_id_work_scope_sync_fkey" FOREIGN KEY ("request_id", "work_scope", "synchronization_reason", "version_set_fingerprint", "lease_scope") REFERENCES "osv_runtime_synchronization_request"("id", "work_scope", "synchronization_reason", "version_set_fingerprint", "lease_scope") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_runtime_lease_projection" ADD CONSTRAINT "osv_runtime_lease_projection_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "osv_runtime_synchronization_run"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_runtime_stage_attempt" ADD CONSTRAINT "osv_runtime_stage_attempt_run_id_fkey" FOREIGN KEY ("run_id") REFERENCES "osv_runtime_synchronization_run"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_runtime_synchronization_request"
  ADD CONSTRAINT "osv_runtime_sync_request_job_type_chk"
  CHECK (
    "job_type" = 'intelligence.osv.sync'
    AND "job_schema_version" = 'osv_runtime_sync_job_schema_v1'
  );

ALTER TABLE "osv_runtime_synchronization_request"
  ADD CONSTRAINT "osv_runtime_sync_request_scope_chk"
  CHECK (
    "lease_scope" = 'osv_runtime_lease_scope_osv_gcs_public_export_v1'
    AND "catalog_scope" = 'osv_gcs_six_prefix_public_export_v1'
  );

ALTER TABLE "osv_runtime_synchronization_request"
  ADD CONSTRAINT "osv_runtime_sync_request_fingerprint_chk"
  CHECK (
    char_length("version_set_fingerprint") = 64
    AND "version_set_fingerprint" ~ '^[a-f0-9]{64}$'
  );

ALTER TABLE "osv_runtime_synchronization_request"
  ADD CONSTRAINT "osv_runtime_sync_request_reason_scope_chk"
  CHECK (
    (
      "synchronization_reason" = 'operator_canary'
      AND "work_scope" = 'osv_runtime_canary_scope_crates_io_rustsec_v1'
      AND "canary_policy_identifier" IS NOT NULL
      AND "canary_policy_identifier" = 'osv_disabled_first_provider_canary_policy_v1'
      AND "request_kind" = 'operator_request'
    )
    OR (
      "synchronization_reason" = 'scheduler'
      AND "work_scope" = 'osv_runtime_production_scope_six_prefix_v1'
      AND "canary_policy_identifier" IS NULL
      AND "request_kind" = 'scheduler_window'
    )
    OR (
      "synchronization_reason" = 'operator_production'
      AND "work_scope" = 'osv_runtime_production_scope_six_prefix_v1'
      AND "canary_policy_identifier" IS NULL
      AND "request_kind" = 'operator_request'
    )
  );

ALTER TABLE "osv_runtime_synchronization_request"
  ADD CONSTRAINT "osv_runtime_sync_request_kind_chk"
  CHECK (
    (
      "request_kind" = 'scheduler_window'
      AND "scheduler_window_id" IS NOT NULL
      AND char_length("scheduler_window_id") BETWEEN 1 AND 128
      AND position('://' in "scheduler_window_id") = 0
      AND "operator_request_id" IS NULL
    )
    OR (
      "request_kind" = 'operator_request'
      AND "scheduler_window_id" IS NULL
      AND "operator_request_id" IS NOT NULL
    )
  );

ALTER TABLE "osv_runtime_synchronization_run"
  ADD CONSTRAINT "osv_runtime_sync_run_identifiers_chk"
  CHECK (
    "lease_scope" = 'osv_runtime_lease_scope_osv_gcs_public_export_v1'
    AND "runtime_architecture_identifier" = 'osv_runtime_enablement_architecture_v1'
    AND "synchronization_algorithm_identifier" = 'osv_catalog_sync_algorithm_v1'
    AND "retry_policy_identifier" = 'osv_runtime_retry_policy_v1'
    AND char_length("version_set_fingerprint") = 64
    AND "version_set_fingerprint" ~ '^[a-f0-9]{64}$'
  );

ALTER TABLE "osv_runtime_synchronization_run"
  ADD CONSTRAINT "osv_runtime_sync_run_reason_scope_chk"
  CHECK (
    (
      "synchronization_reason" = 'operator_canary'
      AND "work_scope" = 'osv_runtime_canary_scope_crates_io_rustsec_v1'
      AND "pagination_policy_identifier" = 'osv_disabled_first_provider_canary_policy_v1'
    )
    OR (
      "synchronization_reason" IN ('scheduler', 'operator_production')
      AND "work_scope" = 'osv_runtime_production_scope_six_prefix_v1'
      AND "pagination_policy_identifier" = 'osv_listing_pagination_policy_v1'
    )
  );

ALTER TABLE "osv_runtime_synchronization_run"
  ADD CONSTRAINT "osv_runtime_sync_run_timestamps_chk"
  CHECK (
    "updated_at" >= "created_at"
    AND ("started_at" IS NULL OR "started_at" >= "created_at")
    AND ("terminal_at" IS NULL OR "terminal_at" >= "created_at")
    AND ("terminal_at" IS NULL OR "started_at" IS NULL OR "terminal_at" >= "started_at")
  );

ALTER TABLE "osv_runtime_synchronization_run"
  ADD CONSTRAINT "osv_runtime_sync_run_state_chk"
  CHECK (
    (
      "state" IN ('planned', 'waiting_for_lease')
      AND "started_at" IS NULL
      AND "terminal_at" IS NULL
      AND "terminal_code" IS NULL
      AND "cancellation_boundary" IS NULL
    )
    OR (
      "state" IN ('running', 'retry_wait')
      AND "started_at" IS NOT NULL
      AND "terminal_at" IS NULL
      AND "terminal_code" IS NULL
      AND "cancellation_boundary" IS NULL
    )
    OR (
      "state" = 'completed'
      AND "started_at" IS NOT NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_code" IS NULL
      AND "cancellation_boundary" IS NULL
      AND ("retry_disposition" IS NULL OR "retry_disposition" = 'no_retry')
    )
    OR (
      "state" = 'failed'
      AND "started_at" IS NOT NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_code" IS NOT NULL
      AND char_length("terminal_code") BETWEEN 1 AND 64
      AND "terminal_code" ~ '^[a-z0-9_]+$'
      AND "cancellation_boundary" IS NULL
    )
    OR (
      "state" = 'halted'
      AND "terminal_at" IS NOT NULL
      AND "cancellation_boundary" IS NULL
    )
    OR (
      "state" = 'cancelled'
      AND "terminal_at" IS NOT NULL
      AND "cancellation_boundary" IS NOT NULL
      AND "cancellation_boundary" IN (
        'before_job_acceptance',
        'before_lease_acquisition',
        'while_waiting_for_lease',
        'after_lease_acquisition',
        'during_pagination',
        'during_provider_retrieval',
        'during_storage_attachment',
        'during_parser_execution',
        'during_retry_backoff',
        'during_database_transaction',
        'before_readiness',
        'before_release',
        'after_terminal_completion'
      )
    )
  );

ALTER TABLE "osv_runtime_lease_projection"
  ADD CONSTRAINT "osv_runtime_lease_scope_chk"
  CHECK ("scope" = 'osv_runtime_lease_scope_osv_gcs_public_export_v1');

ALTER TABLE "osv_runtime_lease_projection"
  ADD CONSTRAINT "osv_runtime_lease_holder_digest_chk"
  CHECK (
    char_length("holder_token_digest") = 64
    AND "holder_token_digest" ~ '^[a-f0-9]{64}$'
  );

ALTER TABLE "osv_runtime_lease_projection"
  ADD CONSTRAINT "osv_runtime_lease_integers_chk"
  CHECK ("row_revision" > 0 AND "fencing_token" > 0);

ALTER TABLE "osv_runtime_lease_projection"
  ADD CONSTRAINT "osv_runtime_lease_updated_chk"
  CHECK ("updated_at" >= "created_at" AND "heartbeat_at" >= "acquired_at");

ALTER TABLE "osv_runtime_lease_projection"
  ADD CONSTRAINT "osv_runtime_lease_state_chk"
  CHECK (
    (
      "state" = 'held'
      AND "released_at" IS NULL
      AND "release_reason" IS NULL
      AND "expires_at" > "heartbeat_at"
    )
    OR (
      "state" = 'released'
      AND "released_at" IS NOT NULL
      AND "release_reason" IS NOT NULL
      AND "released_at" >= "acquired_at"
      AND "released_at" >= "heartbeat_at"
    )
  );

ALTER TABLE "osv_runtime_stage_attempt"
  ADD CONSTRAINT "osv_runtime_stage_attempt_policy_chk"
  CHECK (
    "retry_policy_identifier" = 'osv_runtime_retry_policy_v1'
    AND char_length("version_set_fingerprint") = 64
    AND "version_set_fingerprint" ~ '^[a-f0-9]{64}$'
    AND (
      "target_identity_digest" IS NULL
      OR (
        char_length("target_identity_digest") = 64
        AND "target_identity_digest" ~ '^[a-f0-9]{64}$'
      )
    )
  );

ALTER TABLE "osv_runtime_stage_attempt"
  ADD CONSTRAINT "osv_runtime_stage_attempt_ordinal_chk"
  CHECK (
    "attempt_ordinal" IN (1, 2, 3)
    AND ("stage" <> 'parser_execution_timeout' OR "attempt_ordinal" IN (1, 2))
    AND ("stage" <> 'inventory_convergence' OR "attempt_ordinal" = 1)
  );

ALTER TABLE "osv_runtime_stage_attempt"
  ADD CONSTRAINT "osv_runtime_stage_attempt_delay_chk"
  CHECK (
    (
      ("attempt_ordinal" = 1 AND "nominal_delay_ms" = 0)
      OR ("attempt_ordinal" = 2 AND "nominal_delay_ms" = 1000)
      OR ("attempt_ordinal" = 3 AND "nominal_delay_ms" = 4000)
    )
    AND "selected_delay_ms" >= 0
    AND "selected_delay_ms" <= 30000
    AND ("attempt_ordinal" <> 1 OR "selected_delay_ms" = 0)
    AND (
      "attempt_ordinal" <> 3
      OR ("retry_not_before" IS NULL AND "retry_disposition" <> 'durable_retry')
    )
    AND (
      NOT ("stage" = 'parser_execution_timeout' AND "attempt_ordinal" = 2)
      OR ("retry_not_before" IS NULL AND "retry_disposition" <> 'durable_retry')
    )
    AND (
      "stage" <> 'inventory_convergence'
      OR (
        "retry_not_before" IS NULL
        AND "retry_disposition" <> 'durable_retry'
        AND "state" <> 'retryable_failed'
      )
    )
  );

ALTER TABLE "osv_runtime_stage_attempt"
  ADD CONSTRAINT "osv_runtime_stage_attempt_state_chk"
  CHECK (
    (
      "state" = 'planned'
      AND "started_at" IS NULL
      AND "terminal_at" IS NULL
      AND "failure_code" IS NULL
      AND "failure_catalog" IS NULL
      AND "retry_not_before" IS NULL
      AND "retry_exhausted" = FALSE
      AND "retry_disposition" IN ('durable_retry', 'no_retry')
    )
    OR (
      "state" = 'running'
      AND "started_at" IS NOT NULL
      AND "terminal_at" IS NULL
      AND "failure_code" IS NULL
      AND "failure_catalog" IS NULL
      AND "retry_not_before" IS NULL
      AND "retry_exhausted" = FALSE
      AND "retry_disposition" IN ('durable_retry', 'no_retry')
    )
    OR (
      "state" = 'succeeded'
      AND "started_at" IS NOT NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_at" >= "started_at"
      AND "failure_code" IS NULL
      AND "failure_catalog" IS NULL
      AND "retry_not_before" IS NULL
      AND "retry_exhausted" = FALSE
      AND "retry_disposition" = 'no_retry'
    )
    OR (
      "state" = 'retryable_failed'
      AND "started_at" IS NOT NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_at" >= "started_at"
      AND "failure_code" IS NOT NULL
      AND char_length("failure_code") BETWEEN 1 AND 64
      AND "failure_code" ~ '^[a-z0-9_]+$'
      AND "failure_catalog" IS NOT NULL
      AND "failure_catalog" IN (
        'listing_pagination',
        'listing_transport',
        'retrieval',
        'storage',
        'parser',
        'runtime_coordination'
      )
      AND "retry_not_before" IS NOT NULL
      AND "retry_not_before" >= "terminal_at"
      AND "retry_not_before" <= "terminal_at" + INTERVAL '30 seconds'
      AND "retry_exhausted" = FALSE
      AND "retry_disposition" = 'durable_retry'
    )
    OR (
      "state" = 'permanent_failed'
      AND "started_at" IS NOT NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_at" >= "started_at"
      AND "failure_code" IS NOT NULL
      AND char_length("failure_code") BETWEEN 1 AND 64
      AND "failure_code" ~ '^[a-z0-9_]+$'
      AND "failure_catalog" IS NOT NULL
      AND "failure_catalog" IN (
        'listing_pagination',
        'listing_transport',
        'retrieval',
        'storage',
        'parser',
        'runtime_coordination'
      )
      AND "retry_not_before" IS NULL
      AND "retry_exhausted" = FALSE
      AND "retry_disposition" IN ('no_retry', 'quarantine_required', 'new_synchronization_attempt')
    )
    OR (
      "state" = 'exhausted'
      AND "started_at" IS NOT NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_at" >= "started_at"
      AND "failure_code" IS NOT NULL
      AND char_length("failure_code") BETWEEN 1 AND 64
      AND "failure_code" ~ '^[a-z0-9_]+$'
      AND "failure_catalog" IS NOT NULL
      AND "failure_catalog" IN (
        'listing_pagination',
        'listing_transport',
        'retrieval',
        'storage',
        'parser',
        'runtime_coordination'
      )
      AND "retry_not_before" IS NULL
      AND "retry_exhausted" = TRUE
      AND "retry_disposition" = 'retry_exhausted'
      AND (
        ("stage" = 'parser_execution_timeout' AND "attempt_ordinal" = 2)
        OR ("stage" <> 'parser_execution_timeout' AND "stage" <> 'inventory_convergence' AND "attempt_ordinal" = 3)
      )
    )
    OR (
      "state" = 'cancelled'
      AND "terminal_at" IS NOT NULL
      AND ("started_at" IS NULL OR "terminal_at" >= "started_at")
      AND "retry_not_before" IS NULL
      AND "retry_exhausted" = FALSE
      AND "retry_disposition" = 'no_retry'
      AND (
        (
          "failure_code" IS NULL
          AND "failure_catalog" IS NULL
        )
        OR (
          "failure_code" IS NOT NULL
          AND "failure_catalog" IS NOT NULL
          AND char_length("failure_code") BETWEEN 1 AND 64
          AND "failure_code" ~ '^[a-z0-9_]+$'
          AND "failure_catalog" IN (
            'listing_pagination',
            'listing_transport',
            'retrieval',
            'storage',
            'parser',
            'runtime_coordination'
          )
        )
      )
    )
  );

CREATE FUNCTION patchpilot_forbid_osv_runtime_lease_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'osv runtime lease projection cannot be deleted; fencing token must not reset'
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE FUNCTION patchpilot_protect_osv_runtime_lease_projection()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.scope IS DISTINCT FROM OLD.scope THEN
    RAISE EXCEPTION 'osv runtime lease scope is immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.row_revision <= OLD.row_revision THEN
    RAISE EXCEPTION 'osv runtime lease row revision must increase'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.fencing_token < OLD.fencing_token THEN
    RAISE EXCEPTION 'osv runtime lease fencing token cannot decrease'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'held' AND NEW.state = 'held'
     AND NEW.run_id IS NOT DISTINCT FROM OLD.run_id
     AND NEW.holder_token_digest IS NOT DISTINCT FROM OLD.holder_token_digest THEN
    IF NEW.fencing_token IS DISTINCT FROM OLD.fencing_token THEN
      RAISE EXCEPTION 'osv runtime lease heartbeat cannot change fencing token'
        USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.fencing_token <= OLD.fencing_token THEN
    RAISE EXCEPTION 'osv runtime lease fencing token must increase when ownership changes'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_protect_osv_runtime_stage_attempt()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.run_id IS DISTINCT FROM OLD.run_id
     OR NEW.stage IS DISTINCT FROM OLD.stage
     OR NEW.target_identity_digest IS DISTINCT FROM OLD.target_identity_digest
     OR NEW.attempt_ordinal IS DISTINCT FROM OLD.attempt_ordinal
     OR NEW.retry_policy_identifier IS DISTINCT FROM OLD.retry_policy_identifier
     OR NEW.version_set_fingerprint IS DISTINCT FROM OLD.version_set_fingerprint
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.nominal_delay_ms IS DISTINCT FROM OLD.nominal_delay_ms
     OR NEW.selected_delay_ms IS DISTINCT FROM OLD.selected_delay_ms THEN
    RAISE EXCEPTION 'osv runtime stage attempt identity fields are immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state IN ('succeeded', 'retryable_failed', 'permanent_failed', 'exhausted', 'cancelled') THEN
    RAISE EXCEPTION 'osv runtime terminal stage attempts are immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'planned' AND NEW.state NOT IN ('planned', 'running', 'cancelled') THEN
    RAISE EXCEPTION 'osv runtime planned attempt may only become running or cancelled'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'running' AND NEW.state NOT IN (
    'running',
    'succeeded',
    'retryable_failed',
    'permanent_failed',
    'exhausted',
    'cancelled'
  ) THEN
    RAISE EXCEPTION 'invalid osv runtime running attempt transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER osv_runtime_synchronization_request_append_only
  BEFORE UPDATE OR DELETE ON "osv_runtime_synchronization_request"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_runtime_lease_projection_delete_forbidden
  BEFORE DELETE ON "osv_runtime_lease_projection"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_osv_runtime_lease_delete();

CREATE TRIGGER osv_runtime_lease_projection_fencing_monotonic
  BEFORE UPDATE ON "osv_runtime_lease_projection"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_runtime_lease_projection();

CREATE TRIGGER osv_runtime_stage_attempt_delete_forbidden
  BEFORE DELETE ON "osv_runtime_stage_attempt"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_runtime_stage_attempt_identity_terminal_immutable
  BEFORE UPDATE ON "osv_runtime_stage_attempt"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_runtime_stage_attempt();
