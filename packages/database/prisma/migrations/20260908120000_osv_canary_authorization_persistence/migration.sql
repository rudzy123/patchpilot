-- Session 13 Batch 2B / 2B-R: OSV canary instance-operator identity and
-- single-use authorization persistence foundation.
-- Forward-only. Does not edit 20260826120000_schema_foundation through
-- 20260907120000_osv_runtime_coordination_persistence.
-- New enums and tables only. No ALTER TYPE ADD VALUE on existing enums.
-- Additive unique index on osv_runtime_synchronization_run (id, request_id)
-- so consumed authorizations can bind a run to its request.
-- No operator-identity seed, no authorization seed, no tenant rows, no
-- Finding rows, no active catalog seed, no credentials, no holder tokens,
-- no page tokens, no provider bodies, and no arbitrary JSON.
-- All new foreign keys are ON DELETE RESTRICT.
-- Schema only; no issuance, consumption, CLI, heartbeat, or provider contact.
-- Batch 2B-R requires insert-as-issued, insert-as-active operator, completed
-- listing consume-binding agreement for bounded-body review evidence, one
-- listing authorization per bounded-body row, and database-time consume,
-- revoke, and expire transitions.

-- CreateEnum
CREATE TYPE "osv_canary_operator_identity_status" AS ENUM ('active', 'revoked');

-- CreateEnum
CREATE TYPE "osv_canary_phase" AS ENUM ('listing_only', 'bounded_body');

-- CreateEnum
CREATE TYPE "osv_canary_authorization_purpose" AS ENUM (
  'initial_listing_compatibility',
  'approved_listing_repetition',
  'bounded_body_compatibility',
  'corrective_canary_after_review'
);

-- CreateEnum
CREATE TYPE "osv_canary_authorization_state" AS ENUM (
  'issued',
  'consumed',
  'completed',
  'failed',
  'cancelled',
  'revoked',
  'expired'
);

-- CreateEnum
CREATE TYPE "osv_canary_listing_review_verdict" AS ENUM (
  'listing_canary_evidence_accepted',
  'listing_evidence_accepted_with_corrections'
);

-- CreateEnum
CREATE TYPE "osv_canary_legal_permitted_operation" AS ENUM (
  'list_object_metadata',
  'retrieve_provider_bodies'
);

-- CreateTable
CREATE TABLE "osv_canary_instance_operator_identity" (
    "id" UUID NOT NULL,
    "identity_schema_version" VARCHAR(128) NOT NULL,
    "identity_type" VARCHAR(64) NOT NULL,
    "authentication_source" VARCHAR(128) NOT NULL,
    "provenance_identifier" VARCHAR(128) NOT NULL,
    "display_label" VARCHAR(64) NOT NULL,
    "established_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" "osv_canary_operator_identity_status" NOT NULL,
    "revoked_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_canary_instance_operator_identity_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_canary_authorization" (
    "id" UUID NOT NULL,
    "operator_identity_id" UUID NOT NULL,
    "authorization_schema_version" VARCHAR(128) NOT NULL,
    "canary_architecture_identifier" VARCHAR(128) NOT NULL,
    "runtime_architecture_identifier" VARCHAR(128) NOT NULL,
    "listing_protocol_identifier" VARCHAR(128) NOT NULL,
    "actor_kind" VARCHAR(64) NOT NULL,
    "phase" "osv_canary_phase" NOT NULL,
    "synchronization_reason" "osv_runtime_synchronization_reason" NOT NULL,
    "authorization_purpose" "osv_canary_authorization_purpose" NOT NULL,
    "provider_prefix" VARCHAR(32) NOT NULL,
    "source_identifier" VARCHAR(128) NOT NULL,
    "family" VARCHAR(32) NOT NULL,
    "canary_policy_identifier" VARCHAR(128) NOT NULL,
    "work_scope" "osv_runtime_work_scope" NOT NULL,
    "lease_scope" VARCHAR(128) NOT NULL,
    "runtime_version_set_fingerprint" TEXT NOT NULL,
    "budget_profile_identifier" VARCHAR(128) NOT NULL,
    "unused_ttl_seconds" INTEGER NOT NULL,
    "single_use_policy" VARCHAR(32) NOT NULL,
    "catalog_activation_authorization" VARCHAR(32) NOT NULL,
    "matching_authorization" VARCHAR(32) NOT NULL,
    "finding_authorization" VARCHAR(32) NOT NULL,
    "postcanary_review_requirement" VARCHAR(32) NOT NULL,
    "legal_decision_reference_identifier" VARCHAR(128) NOT NULL,
    "legal_decision_id" UUID NOT NULL,
    "legal_decision_source_registry_version" VARCHAR(128) NOT NULL,
    "legal_decision_phase" "osv_canary_phase" NOT NULL,
    "legal_decision_permitted_operation" "osv_canary_legal_permitted_operation" NOT NULL,
    "legal_decision_state" VARCHAR(128) NOT NULL,
    "legal_decision_issuance" VARCHAR(128) NOT NULL,
    "legal_decision_issued_at" TIMESTAMPTZ(6) NOT NULL,
    "legal_decision_revalidation_boundary_at" TIMESTAMPTZ(6) NOT NULL,
    "legal_decision_responsible_role" VARCHAR(128) NOT NULL,
    "legal_decision_evidence_set_id" UUID NOT NULL,
    "body_legal_decision_id" UUID,
    "body_legal_decision_phase" "osv_canary_phase",
    "body_legal_decision_permitted_operation" "osv_canary_legal_permitted_operation",
    "body_legal_decision_issued_at" TIMESTAMPTZ(6),
    "body_legal_decision_revalidation_boundary_at" TIMESTAMPTZ(6),
    "body_legal_decision_evidence_set_id" UUID,
    "body_retrieve_disposition" VARCHAR(128),
    "body_transient_inspection_disposition" VARCHAR(128),
    "body_private_retention_disposition" VARCHAR(128),
    "body_parse_disposition" VARCHAR(128),
    "body_external_exposure_disposition" VARCHAR(128),
    "body_matching_disposition" VARCHAR(128),
    "listing_review_evidence_identifier" VARCHAR(128),
    "listing_review_id" UUID,
    "listing_authorization_id" UUID,
    "listing_request_id" UUID,
    "listing_run_id" UUID,
    "listing_canonical_inventory_evidence_id" UUID,
    "listing_review_verdict" "osv_canary_listing_review_verdict",
    "listing_reviewed_at" TIMESTAMPTZ(6),
    "listing_reviewer_role" VARCHAR(128),
    "body_selection_algorithm_identifier" VARCHAR(128),
    "runbook_set_identifier" VARCHAR(128) NOT NULL,
    "runbook_version" VARCHAR(128) NOT NULL,
    "runbook_acknowledged_at" TIMESTAMPTZ(6) NOT NULL,
    "runbook_emergency_halt_procedure" VARCHAR(128) NOT NULL,
    "halt_acknowledgement_identifier" VARCHAR(128) NOT NULL,
    "halt_acknowledged_at" TIMESTAMPTZ(6) NOT NULL,
    "activation_prohibition_identifier" VARCHAR(128) NOT NULL,
    "retry_prohibition_identifier" VARCHAR(128) NOT NULL,
    "issued_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6) NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '3600 seconds'),
    "state" "osv_canary_authorization_state" NOT NULL,
    "consumed_at" TIMESTAMPTZ(6),
    "consumed_by_synchronization_request_id" UUID,
    "consumed_by_synchronization_run_id" UUID,
    "terminal_at" TIMESTAMPTZ(6),
    "terminal_disposition" "osv_canary_authorization_state",
    "terminal_reason_code" VARCHAR(64),
    "revoked_at" TIMESTAMPTZ(6),
    "revoked_by_operator_identity_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_canary_authorization_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "osv_canary_operator_identity_status_idx" ON "osv_canary_instance_operator_identity"("status");

-- CreateIndex
CREATE INDEX "osv_canary_authorization_state_expires_idx" ON "osv_canary_authorization"("state", "expires_at");

-- CreateIndex
CREATE INDEX "osv_canary_authorization_operator_issued_idx" ON "osv_canary_authorization"("operator_identity_id", "issued_at");

-- CreateIndex
CREATE INDEX "osv_canary_authorization_consumed_request_idx" ON "osv_canary_authorization"("consumed_by_synchronization_request_id");

-- CreateIndex
CREATE INDEX "osv_canary_authorization_consumed_run_idx" ON "osv_canary_authorization"("consumed_by_synchronization_run_id");

-- CreateIndex
CREATE INDEX "osv_canary_authorization_phase_state_idx" ON "osv_canary_authorization"("phase", "state");

-- CreateIndex
CREATE INDEX "osv_canary_authorization_revoker_idx" ON "osv_canary_authorization"("revoked_by_operator_identity_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_runtime_sync_run_id_request_uidx" ON "osv_runtime_synchronization_run"("id", "request_id");

-- Partial unique: one consumed request may bind one authorization.
-- Predicate uses IS NOT NULL. Issued rows have NULL and are excluded.
-- Empty UUID cannot bypass because the column is UUID, not text.
CREATE UNIQUE INDEX "osv_canary_authorization_consumed_request_uidx"
  ON "osv_canary_authorization"("consumed_by_synchronization_request_id")
  WHERE "consumed_by_synchronization_request_id" IS NOT NULL;

-- Partial unique: one consumed run may bind one authorization.
CREATE UNIQUE INDEX "osv_canary_authorization_consumed_run_uidx"
  ON "osv_canary_authorization"("consumed_by_synchronization_run_id")
  WHERE "consumed_by_synchronization_run_id" IS NOT NULL;

-- Partial unique: one listing-review identity may authorize one bounded-body row.
CREATE UNIQUE INDEX "osv_canary_authorization_listing_review_uidx"
  ON "osv_canary_authorization"("listing_review_id")
  WHERE "listing_review_id" IS NOT NULL;

-- Partial unique: one completed listing authorization may authorize one
-- bounded-body row. A second fabricated review identity cannot reuse it.
CREATE UNIQUE INDEX "osv_canary_authorization_listing_auth_uidx"
  ON "osv_canary_authorization"("listing_authorization_id")
  WHERE "listing_authorization_id" IS NOT NULL;

-- AddForeignKey
ALTER TABLE "osv_canary_authorization" ADD CONSTRAINT "osv_canary_authorization_operator_identity_id_fkey" FOREIGN KEY ("operator_identity_id") REFERENCES "osv_canary_instance_operator_identity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_canary_authorization" ADD CONSTRAINT "osv_canary_authorization_revoked_by_operator_identity_id_fkey" FOREIGN KEY ("revoked_by_operator_identity_id") REFERENCES "osv_canary_instance_operator_identity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_canary_authorization" ADD CONSTRAINT "osv_canary_authorization_listing_authorization_id_fkey" FOREIGN KEY ("listing_authorization_id") REFERENCES "osv_canary_authorization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_canary_authorization" ADD CONSTRAINT "osv_canary_authorization_listing_request_id_fkey" FOREIGN KEY ("listing_request_id") REFERENCES "osv_runtime_synchronization_request"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_canary_authorization" ADD CONSTRAINT "osv_canary_authorization_listing_run_id_fkey" FOREIGN KEY ("listing_run_id") REFERENCES "osv_runtime_synchronization_run"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_canary_authorization" ADD CONSTRAINT "osv_canary_authorization_listing_run_request_fkey" FOREIGN KEY ("listing_run_id", "listing_request_id") REFERENCES "osv_runtime_synchronization_run"("id", "request_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_canary_authorization" ADD CONSTRAINT "osv_canary_authorization_consumed_by_synchronization_reque_fkey" FOREIGN KEY ("consumed_by_synchronization_request_id", "work_scope", "synchronization_reason", "runtime_version_set_fingerprint", "lease_scope") REFERENCES "osv_runtime_synchronization_request"("id", "work_scope", "synchronization_reason", "version_set_fingerprint", "lease_scope") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_canary_authorization" ADD CONSTRAINT "osv_canary_authorization_consumed_by_synchronization_run_i_fkey" FOREIGN KEY ("consumed_by_synchronization_run_id", "consumed_by_synchronization_request_id") REFERENCES "osv_runtime_synchronization_run"("id", "request_id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_canary_instance_operator_identity"
  ADD CONSTRAINT "osv_canary_operator_identity_uuid_v4_chk"
  CHECK (
    "id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  );

ALTER TABLE "osv_canary_instance_operator_identity"
  ADD CONSTRAINT "osv_canary_operator_identity_closed_chk"
  CHECK (
    "identity_schema_version" = 'osv_canary_instance_operator_identity_v1'
    AND "identity_type" = 'instance_operator'
    AND "authentication_source" = 'local_host_control_of_one_shot_administrative_command'
    AND "provenance_identifier" = 'configured_instance_operator_attestation_v1'
    AND char_length("display_label") BETWEEN 1 AND 64
    AND "display_label" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]*$'
  );

ALTER TABLE "osv_canary_instance_operator_identity"
  ADD CONSTRAINT "osv_canary_operator_identity_state_chk"
  CHECK (
    "created_at" >= "established_at"
    AND (
      (
        "status" = 'active'
        AND "revoked_at" IS NULL
      )
      OR (
        "status" = 'revoked'
        AND "revoked_at" IS NOT NULL
        AND "revoked_at" >= "established_at"
      )
    )
  );

ALTER TABLE "osv_canary_authorization"
  ADD CONSTRAINT "osv_canary_authorization_uuid_v4_chk"
  CHECK (
    "id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "operator_identity_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "legal_decision_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "legal_decision_evidence_set_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "id" <> "operator_identity_id"
    AND "id" <> "legal_decision_id"
    AND (
      "body_legal_decision_id" IS NULL
      OR "body_legal_decision_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "listing_review_id" IS NULL
      OR "listing_review_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "listing_authorization_id" IS NULL
      OR "listing_authorization_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "listing_request_id" IS NULL
      OR "listing_request_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "listing_run_id" IS NULL
      OR "listing_run_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "listing_canonical_inventory_evidence_id" IS NULL
      OR "listing_canonical_inventory_evidence_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "body_legal_decision_evidence_set_id" IS NULL
      OR "body_legal_decision_evidence_set_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "revoked_by_operator_identity_id" IS NULL
      OR "revoked_by_operator_identity_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "consumed_by_synchronization_request_id" IS NULL
      OR "consumed_by_synchronization_request_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
    AND (
      "consumed_by_synchronization_run_id" IS NULL
      OR "consumed_by_synchronization_run_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    )
  );

ALTER TABLE "osv_canary_authorization"
  ADD CONSTRAINT "osv_canary_authorization_policy_chk"
  CHECK (
    "authorization_schema_version" = 'osv_canary_execution_authorization_record_v1'
    AND "canary_architecture_identifier" = 'osv_first_real_provider_canary_authorization_v1'
    AND "runtime_architecture_identifier" = 'osv_runtime_enablement_architecture_v1'
    AND "listing_protocol_identifier" = 'osv_gcs_json_objects_list_v1'
    AND "actor_kind" = 'instance_operator'
    AND "synchronization_reason" = 'operator_canary'
    AND "provider_prefix" = 'crates.io/'
    AND "source_identifier" = 'rustsec_advisory_database'
    AND "family" = 'RUSTSEC'
    AND "canary_policy_identifier" = 'osv_disabled_first_provider_canary_policy_v1'
    AND "work_scope" = 'osv_runtime_canary_scope_crates_io_rustsec_v1'
    AND "lease_scope" = 'osv_runtime_lease_scope_osv_gcs_public_export_v1'
    AND char_length("runtime_version_set_fingerprint") = 64
    AND "runtime_version_set_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "unused_ttl_seconds" = 3600
    AND "single_use_policy" = 'single_use'
    AND "catalog_activation_authorization" = 'prohibited'
    AND "matching_authorization" = 'prohibited'
    AND "finding_authorization" = 'prohibited'
    AND "postcanary_review_requirement" = 'required'
    AND "legal_decision_reference_identifier" = 'osv_canary_legal_decision_reference_v1'
    AND "legal_decision_source_registry_version" = 'osv_source_license_registry_v1'
    AND "legal_decision_phase" = 'listing_only'
    AND "legal_decision_permitted_operation" = 'list_object_metadata'
    AND "legal_decision_state" = 'recorded_reference_not_execution_authority'
    AND "legal_decision_issuance" = 'blocking_preexecution_dependency_not_issued_in_batch_2a'
    AND "legal_decision_responsible_role" = 'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator'
    AND "runbook_set_identifier" = 'osv_canary_runbook_set_v1'
    AND "runbook_version" = 'osv_canary_runbook_outlines_v1'
    AND "runbook_emergency_halt_procedure" = 'stop_next_protected_stage_production_remains_halted'
    AND "halt_acknowledgement_identifier" = 'osv_canary_halt_control_acknowledgement_v1'
    AND "activation_prohibition_identifier" = 'osv_canary_activation_prohibition_v1'
    AND "retry_prohibition_identifier" = 'osv_canary_automatic_retry_prohibition_v1'
  );

ALTER TABLE "osv_canary_authorization"
  ADD CONSTRAINT "osv_canary_authorization_phase_purpose_budget_chk"
  CHECK (
    (
      "phase" = 'listing_only'
      AND "authorization_purpose" IN (
        'initial_listing_compatibility',
        'approved_listing_repetition',
        'corrective_canary_after_review'
      )
      AND "budget_profile_identifier" = 'osv_canary_listing_only_budget_v1'
    )
    OR (
      "phase" = 'bounded_body'
      AND "authorization_purpose" IN (
        'bounded_body_compatibility',
        'corrective_canary_after_review'
      )
      AND "budget_profile_identifier" = 'osv_canary_bounded_body_budget_v1'
    )
  );

ALTER TABLE "osv_canary_authorization"
  ADD CONSTRAINT "osv_canary_authorization_phase_body_chk"
  CHECK (
    (
      "phase" = 'listing_only'
      AND "body_legal_decision_id" IS NULL
      AND "body_legal_decision_phase" IS NULL
      AND "body_legal_decision_permitted_operation" IS NULL
      AND "body_legal_decision_issued_at" IS NULL
      AND "body_legal_decision_revalidation_boundary_at" IS NULL
      AND "body_legal_decision_evidence_set_id" IS NULL
      AND "body_retrieve_disposition" IS NULL
      AND "body_transient_inspection_disposition" IS NULL
      AND "body_private_retention_disposition" IS NULL
      AND "body_parse_disposition" IS NULL
      AND "body_external_exposure_disposition" IS NULL
      AND "body_matching_disposition" IS NULL
      AND "listing_review_evidence_identifier" IS NULL
      AND "listing_review_id" IS NULL
      AND "listing_authorization_id" IS NULL
      AND "listing_request_id" IS NULL
      AND "listing_run_id" IS NULL
      AND "listing_canonical_inventory_evidence_id" IS NULL
      AND "listing_review_verdict" IS NULL
      AND "listing_reviewed_at" IS NULL
      AND "listing_reviewer_role" IS NULL
      AND "body_selection_algorithm_identifier" IS NULL
    )
    OR (
      "phase" = 'bounded_body'
      AND "body_legal_decision_id" IS NOT NULL
      AND "body_legal_decision_id" <> "legal_decision_id"
      AND "body_legal_decision_phase" = 'bounded_body'
      AND "body_legal_decision_permitted_operation" = 'retrieve_provider_bodies'
      AND "body_legal_decision_issued_at" IS NOT NULL
      AND "body_legal_decision_revalidation_boundary_at" IS NOT NULL
      AND "body_legal_decision_evidence_set_id" IS NOT NULL
      AND "body_retrieve_disposition" = 'required_current_before_bounded_body'
      AND "body_transient_inspection_disposition" = 'permitted_for_license_evaluation_only'
      AND "body_private_retention_disposition" = 'reject_body_retrieval_until_retention_resolved'
      AND "body_parse_disposition" = 'license_inspection_only_before_retention'
      AND "body_external_exposure_disposition" = 'forbidden'
      AND "body_matching_disposition" = 'forbidden'
      AND "listing_review_evidence_identifier" = 'osv_canary_listing_review_evidence_v1'
      AND "listing_review_id" IS NOT NULL
      AND "listing_authorization_id" IS NOT NULL
      AND "listing_authorization_id" IS DISTINCT FROM "id"
      AND "listing_request_id" IS NOT NULL
      AND "listing_run_id" IS NOT NULL
      AND "listing_canonical_inventory_evidence_id" IS NOT NULL
      AND "listing_review_verdict" IS NOT NULL
      AND "listing_reviewed_at" IS NOT NULL
      AND "listing_reviewer_role" = 'instance_canary_evidence_reviewer'
      AND "body_selection_algorithm_identifier" = 'osv_canary_bounded_body_selection_v1'
    )
  );

ALTER TABLE "osv_canary_authorization"
  ADD CONSTRAINT "osv_canary_authorization_ttl_chk"
  CHECK (
    "expires_at" = "issued_at" + INTERVAL '3600 seconds'
    AND "created_at" >= "issued_at"
    AND "runbook_acknowledged_at" <= "issued_at"
    AND "halt_acknowledged_at" <= "issued_at"
    AND "legal_decision_issued_at" <= "issued_at"
    AND "legal_decision_revalidation_boundary_at" >= "legal_decision_issued_at"
    AND (
      "body_legal_decision_issued_at" IS NULL
      OR (
        "body_legal_decision_issued_at" <= "issued_at"
        AND "body_legal_decision_revalidation_boundary_at" >= "body_legal_decision_issued_at"
      )
    )
    AND (
      "listing_reviewed_at" IS NULL
      OR "listing_reviewed_at" <= "issued_at"
    )
  );

ALTER TABLE "osv_canary_authorization"
  ADD CONSTRAINT "osv_canary_authorization_state_chk"
  CHECK (
    (
      "state" = 'issued'
      AND "consumed_at" IS NULL
      AND "consumed_by_synchronization_request_id" IS NULL
      AND "consumed_by_synchronization_run_id" IS NULL
      AND "terminal_at" IS NULL
      AND "terminal_disposition" IS NULL
      AND "terminal_reason_code" IS NULL
      AND "revoked_at" IS NULL
      AND "revoked_by_operator_identity_id" IS NULL
    )
    OR (
      "state" = 'consumed'
      AND "consumed_at" IS NOT NULL
      AND "consumed_at" >= "issued_at"
      AND "consumed_at" < "expires_at"
      AND "consumed_by_synchronization_request_id" IS NOT NULL
      AND "consumed_by_synchronization_run_id" IS NOT NULL
      AND "consumed_by_synchronization_request_id" <> "id"
      AND "consumed_by_synchronization_run_id" <> "id"
      AND "consumed_by_synchronization_run_id" <> "consumed_by_synchronization_request_id"
      AND "terminal_at" IS NULL
      AND "terminal_disposition" IS NULL
      AND "terminal_reason_code" IS NULL
      AND "revoked_at" IS NULL
      AND "revoked_by_operator_identity_id" IS NULL
    )
    OR (
      "state" = 'completed'
      AND "consumed_at" IS NOT NULL
      AND "consumed_at" >= "issued_at"
      AND "consumed_at" < "expires_at"
      AND "consumed_by_synchronization_request_id" IS NOT NULL
      AND "consumed_by_synchronization_run_id" IS NOT NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_at" >= "consumed_at"
      AND "terminal_disposition" = 'completed'
      AND "terminal_reason_code" IS NULL
      AND "revoked_at" IS NULL
      AND "revoked_by_operator_identity_id" IS NULL
    )
    OR (
      "state" = 'failed'
      AND "consumed_at" IS NOT NULL
      AND "consumed_at" >= "issued_at"
      AND "consumed_at" < "expires_at"
      AND "consumed_by_synchronization_request_id" IS NOT NULL
      AND "consumed_by_synchronization_run_id" IS NOT NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_at" >= "consumed_at"
      AND "terminal_disposition" = 'failed'
      AND "terminal_reason_code" IS NOT NULL
      AND char_length("terminal_reason_code") BETWEEN 1 AND 64
      AND "terminal_reason_code" ~ '^[a-z0-9_]+$'
      AND "revoked_at" IS NULL
      AND "revoked_by_operator_identity_id" IS NULL
    )
    OR (
      "state" = 'cancelled'
      AND "terminal_at" IS NOT NULL
      AND "terminal_disposition" = 'cancelled'
      AND "terminal_reason_code" IS NULL
      AND "revoked_at" IS NULL
      AND "revoked_by_operator_identity_id" IS NULL
      AND (
        (
          "consumed_at" IS NULL
          AND "consumed_by_synchronization_request_id" IS NULL
          AND "consumed_by_synchronization_run_id" IS NULL
          AND "terminal_at" >= "issued_at"
        )
        OR (
          "consumed_at" IS NOT NULL
          AND "consumed_at" >= "issued_at"
          AND "consumed_at" < "expires_at"
          AND "consumed_by_synchronization_request_id" IS NOT NULL
          AND "consumed_by_synchronization_run_id" IS NOT NULL
          AND "terminal_at" >= "consumed_at"
        )
      )
    )
    OR (
      "state" = 'revoked'
      AND "consumed_at" IS NULL
      AND "consumed_by_synchronization_request_id" IS NULL
      AND "consumed_by_synchronization_run_id" IS NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_disposition" = 'revoked'
      AND "terminal_reason_code" IS NULL
      AND "revoked_at" IS NOT NULL
      AND "revoked_at" >= "issued_at"
      AND "terminal_at" >= "revoked_at"
      AND "revoked_by_operator_identity_id" IS NOT NULL
      AND "revoked_by_operator_identity_id" = "operator_identity_id"
    )
    OR (
      "state" = 'expired'
      AND "consumed_at" IS NULL
      AND "consumed_by_synchronization_request_id" IS NULL
      AND "consumed_by_synchronization_run_id" IS NULL
      AND "terminal_at" IS NOT NULL
      AND "terminal_at" >= "expires_at"
      AND "terminal_disposition" = 'expired'
      AND "terminal_reason_code" IS NULL
      AND "revoked_at" IS NULL
      AND "revoked_by_operator_identity_id" IS NULL
    )
  );

CREATE FUNCTION patchpilot_protect_osv_canary_operator_identity()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.identity_schema_version IS DISTINCT FROM OLD.identity_schema_version
     OR NEW.identity_type IS DISTINCT FROM OLD.identity_type
     OR NEW.authentication_source IS DISTINCT FROM OLD.authentication_source
     OR NEW.provenance_identifier IS DISTINCT FROM OLD.provenance_identifier
     OR NEW.display_label IS DISTINCT FROM OLD.display_label
     OR NEW.established_at IS DISTINCT FROM OLD.established_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'osv canary operator identity fields are immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.status = 'revoked' THEN
    RAISE EXCEPTION 'osv canary revoked operator identity is immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.status IS DISTINCT FROM 'revoked' OR NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION 'osv canary operator identity may only revoke from active'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_protect_osv_canary_authorization()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.operator_identity_id IS DISTINCT FROM OLD.operator_identity_id
     OR NEW.authorization_schema_version IS DISTINCT FROM OLD.authorization_schema_version
     OR NEW.canary_architecture_identifier IS DISTINCT FROM OLD.canary_architecture_identifier
     OR NEW.runtime_architecture_identifier IS DISTINCT FROM OLD.runtime_architecture_identifier
     OR NEW.listing_protocol_identifier IS DISTINCT FROM OLD.listing_protocol_identifier
     OR NEW.actor_kind IS DISTINCT FROM OLD.actor_kind
     OR NEW.phase IS DISTINCT FROM OLD.phase
     OR NEW.synchronization_reason IS DISTINCT FROM OLD.synchronization_reason
     OR NEW.authorization_purpose IS DISTINCT FROM OLD.authorization_purpose
     OR NEW.provider_prefix IS DISTINCT FROM OLD.provider_prefix
     OR NEW.source_identifier IS DISTINCT FROM OLD.source_identifier
     OR NEW.family IS DISTINCT FROM OLD.family
     OR NEW.canary_policy_identifier IS DISTINCT FROM OLD.canary_policy_identifier
     OR NEW.work_scope IS DISTINCT FROM OLD.work_scope
     OR NEW.lease_scope IS DISTINCT FROM OLD.lease_scope
     OR NEW.runtime_version_set_fingerprint IS DISTINCT FROM OLD.runtime_version_set_fingerprint
     OR NEW.budget_profile_identifier IS DISTINCT FROM OLD.budget_profile_identifier
     OR NEW.unused_ttl_seconds IS DISTINCT FROM OLD.unused_ttl_seconds
     OR NEW.single_use_policy IS DISTINCT FROM OLD.single_use_policy
     OR NEW.catalog_activation_authorization IS DISTINCT FROM OLD.catalog_activation_authorization
     OR NEW.matching_authorization IS DISTINCT FROM OLD.matching_authorization
     OR NEW.finding_authorization IS DISTINCT FROM OLD.finding_authorization
     OR NEW.postcanary_review_requirement IS DISTINCT FROM OLD.postcanary_review_requirement
     OR NEW.legal_decision_reference_identifier IS DISTINCT FROM OLD.legal_decision_reference_identifier
     OR NEW.legal_decision_id IS DISTINCT FROM OLD.legal_decision_id
     OR NEW.legal_decision_source_registry_version IS DISTINCT FROM OLD.legal_decision_source_registry_version
     OR NEW.legal_decision_phase IS DISTINCT FROM OLD.legal_decision_phase
     OR NEW.legal_decision_permitted_operation IS DISTINCT FROM OLD.legal_decision_permitted_operation
     OR NEW.legal_decision_state IS DISTINCT FROM OLD.legal_decision_state
     OR NEW.legal_decision_issuance IS DISTINCT FROM OLD.legal_decision_issuance
     OR NEW.legal_decision_issued_at IS DISTINCT FROM OLD.legal_decision_issued_at
     OR NEW.legal_decision_revalidation_boundary_at IS DISTINCT FROM OLD.legal_decision_revalidation_boundary_at
     OR NEW.legal_decision_responsible_role IS DISTINCT FROM OLD.legal_decision_responsible_role
     OR NEW.legal_decision_evidence_set_id IS DISTINCT FROM OLD.legal_decision_evidence_set_id
     OR NEW.body_legal_decision_id IS DISTINCT FROM OLD.body_legal_decision_id
     OR NEW.body_legal_decision_phase IS DISTINCT FROM OLD.body_legal_decision_phase
     OR NEW.body_legal_decision_permitted_operation IS DISTINCT FROM OLD.body_legal_decision_permitted_operation
     OR NEW.body_legal_decision_issued_at IS DISTINCT FROM OLD.body_legal_decision_issued_at
     OR NEW.body_legal_decision_revalidation_boundary_at IS DISTINCT FROM OLD.body_legal_decision_revalidation_boundary_at
     OR NEW.body_legal_decision_evidence_set_id IS DISTINCT FROM OLD.body_legal_decision_evidence_set_id
     OR NEW.body_retrieve_disposition IS DISTINCT FROM OLD.body_retrieve_disposition
     OR NEW.body_transient_inspection_disposition IS DISTINCT FROM OLD.body_transient_inspection_disposition
     OR NEW.body_private_retention_disposition IS DISTINCT FROM OLD.body_private_retention_disposition
     OR NEW.body_parse_disposition IS DISTINCT FROM OLD.body_parse_disposition
     OR NEW.body_external_exposure_disposition IS DISTINCT FROM OLD.body_external_exposure_disposition
     OR NEW.body_matching_disposition IS DISTINCT FROM OLD.body_matching_disposition
     OR NEW.listing_review_evidence_identifier IS DISTINCT FROM OLD.listing_review_evidence_identifier
     OR NEW.listing_review_id IS DISTINCT FROM OLD.listing_review_id
     OR NEW.listing_authorization_id IS DISTINCT FROM OLD.listing_authorization_id
     OR NEW.listing_request_id IS DISTINCT FROM OLD.listing_request_id
     OR NEW.listing_run_id IS DISTINCT FROM OLD.listing_run_id
     OR NEW.listing_canonical_inventory_evidence_id IS DISTINCT FROM OLD.listing_canonical_inventory_evidence_id
     OR NEW.listing_review_verdict IS DISTINCT FROM OLD.listing_review_verdict
     OR NEW.listing_reviewed_at IS DISTINCT FROM OLD.listing_reviewed_at
     OR NEW.listing_reviewer_role IS DISTINCT FROM OLD.listing_reviewer_role
     OR NEW.body_selection_algorithm_identifier IS DISTINCT FROM OLD.body_selection_algorithm_identifier
     OR NEW.runbook_set_identifier IS DISTINCT FROM OLD.runbook_set_identifier
     OR NEW.runbook_version IS DISTINCT FROM OLD.runbook_version
     OR NEW.runbook_acknowledged_at IS DISTINCT FROM OLD.runbook_acknowledged_at
     OR NEW.runbook_emergency_halt_procedure IS DISTINCT FROM OLD.runbook_emergency_halt_procedure
     OR NEW.halt_acknowledgement_identifier IS DISTINCT FROM OLD.halt_acknowledgement_identifier
     OR NEW.halt_acknowledged_at IS DISTINCT FROM OLD.halt_acknowledged_at
     OR NEW.activation_prohibition_identifier IS DISTINCT FROM OLD.activation_prohibition_identifier
     OR NEW.retry_prohibition_identifier IS DISTINCT FROM OLD.retry_prohibition_identifier
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'osv canary authorization immutable fields cannot change'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state IN ('completed', 'failed', 'cancelled', 'revoked', 'expired') THEN
    RAISE EXCEPTION 'osv canary terminal authorization is immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'issued' AND NEW.state = 'consumed' AND CURRENT_TIMESTAMP >= OLD.expires_at THEN
    RAISE EXCEPTION 'osv canary authorization is expired and cannot be consumed'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'issued' AND NEW.state = 'revoked' AND CURRENT_TIMESTAMP >= OLD.expires_at THEN
    RAISE EXCEPTION 'osv canary authorization is expired and cannot be revoked'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'issued' AND NEW.state = 'expired' AND CURRENT_TIMESTAMP < OLD.expires_at THEN
    RAISE EXCEPTION 'osv canary authorization is not expired'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'issued' AND NEW.state NOT IN ('issued', 'consumed', 'revoked', 'expired', 'cancelled') THEN
    RAISE EXCEPTION 'invalid osv canary issued authorization transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'consumed' AND NEW.state NOT IN ('consumed', 'completed', 'failed', 'cancelled') THEN
    RAISE EXCEPTION 'invalid osv canary consumed authorization transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'consumed' AND NEW.state = 'consumed' THEN
    IF NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
       OR NEW.consumed_by_synchronization_request_id IS DISTINCT FROM OLD.consumed_by_synchronization_request_id
       OR NEW.consumed_by_synchronization_run_id IS DISTINCT FROM OLD.consumed_by_synchronization_run_id THEN
      RAISE EXCEPTION 'osv canary consumption binding is immutable'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_osv_canary_operator_identity_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.status IS DISTINCT FROM 'active' OR NEW.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'osv canary operator identity must be inserted as active'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_osv_canary_authorization_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.state IS DISTINCT FROM 'issued' THEN
    RAISE EXCEPTION 'osv canary authorization must be inserted as issued'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_osv_canary_listing_authorization_phase()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  listing_phase osv_canary_phase;
  listing_state osv_canary_authorization_state;
  listing_request uuid;
  listing_run uuid;
  listing_fingerprint text;
  listing_terminal timestamptz;
BEGIN
  IF NEW.listing_authorization_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT
    phase,
    state,
    consumed_by_synchronization_request_id,
    consumed_by_synchronization_run_id,
    runtime_version_set_fingerprint,
    terminal_at
  INTO
    listing_phase,
    listing_state,
    listing_request,
    listing_run,
    listing_fingerprint,
    listing_terminal
  FROM osv_canary_authorization
  WHERE id = NEW.listing_authorization_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'osv canary listing review target is missing'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF listing_phase IS DISTINCT FROM 'listing_only' THEN
    RAISE EXCEPTION 'osv canary listing review must reference a listing_only authorization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF listing_state IS DISTINCT FROM 'completed' THEN
    RAISE EXCEPTION 'osv canary listing review requires a completed listing_only authorization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF listing_request IS DISTINCT FROM NEW.listing_request_id
     OR listing_run IS DISTINCT FROM NEW.listing_run_id THEN
    RAISE EXCEPTION 'osv canary listing review must match the consumed listing request and run'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF listing_fingerprint IS DISTINCT FROM NEW.runtime_version_set_fingerprint THEN
    RAISE EXCEPTION 'osv canary listing review must match the listing version-set fingerprint'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF listing_terminal IS NULL
     OR NEW.listing_reviewed_at IS NULL
     OR NEW.listing_reviewed_at < listing_terminal THEN
    RAISE EXCEPTION 'osv canary listing review must occur at or after listing completion'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER osv_canary_instance_operator_identity_insert_active
  BEFORE INSERT ON "osv_canary_instance_operator_identity"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_canary_operator_identity_insert();

CREATE TRIGGER osv_canary_instance_operator_identity_delete_forbidden
  BEFORE DELETE ON "osv_canary_instance_operator_identity"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_canary_instance_operator_identity_immutable
  BEFORE UPDATE ON "osv_canary_instance_operator_identity"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_canary_operator_identity();

CREATE TRIGGER osv_canary_authorization_insert_issued
  BEFORE INSERT ON "osv_canary_authorization"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_canary_authorization_insert();

CREATE TRIGGER osv_canary_authorization_delete_forbidden
  BEFORE DELETE ON "osv_canary_authorization"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_canary_authorization_lifecycle
  BEFORE UPDATE ON "osv_canary_authorization"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_canary_authorization();

CREATE TRIGGER osv_canary_authorization_listing_phase
  BEFORE INSERT OR UPDATE ON "osv_canary_authorization"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_canary_listing_authorization_phase();
