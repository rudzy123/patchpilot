-- Session 11 Batch 5C: OSV acquisition persistence foundation.
-- Forward-only. Does not edit 20260826120000_schema_foundation through
-- 20260902120000_canonical_cve_identity.
-- New enums and tables only; no ALTER TYPE ADD VALUE on existing enums.
-- No provider bodies, tenant rows, Finding rows, or active catalog seed.
-- All OSV foreign keys are ON DELETE RESTRICT. Parser attempt and parsed
-- revision form an insert cycle: persist the attempt with a null revision
-- reference, insert the revision, then attach the attempt reference.

-- CreateEnum
CREATE TYPE "osv_catalog_lifecycle_state" AS ENUM ('planned', 'acquiring', 'ready_for_activation', 'active', 'superseded', 'failed', 'quarantined', 'cancelled');

-- CreateEnum
CREATE TYPE "osv_acquisition_run_state" AS ENUM ('requested', 'running', 'retry_wait', 'completed', 'failed', 'quarantined', 'cancelled');

-- CreateEnum
CREATE TYPE "osv_inventory_run_state" AS ENUM ('running', 'complete', 'failed', 'cancelled');

-- CreateEnum
CREATE TYPE "osv_inventory_pass_completeness_status" AS ENUM ('incomplete', 'complete', 'failed');

-- CreateEnum
CREATE TYPE "osv_inventory_convergence_status" AS ENUM ('converged', 'divergent', 'not_comparable');

-- CreateEnum
CREATE TYPE "osv_classification_status" AS ENUM ('eligible', 'ineligible', 'legal_review_required', 'unknown', 'ambiguous');

-- CreateEnum
CREATE TYPE "osv_parser_attempt_result_state" AS ENUM ('succeeded', 'failed');

-- CreateEnum
CREATE TYPE "osv_worker_lifecycle_outcome" AS ENUM ('reused', 'recycled', 'terminated', 'not_started');

-- CreateEnum
CREATE TYPE "osv_attachment_state" AS ENUM ('staged', 'attached', 'orphaned', 'rejected');

-- CreateEnum
CREATE TYPE "osv_presence_kind" AS ENUM ('provider_absent_observed', 'provider_generation_superseded', 'source_license_eligibility_revoked', 'generation_not_found', 'parser_failure', 'catalog_exclusion');

-- CreateEnum
CREATE TYPE "osv_quarantine_reason_code" AS ENUM ('generation_content_conflict', 'byte_count_mismatch', 'content_hash_mismatch', 'source_identity_mismatch', 'registry_mismatch', 'parser_protocol_mismatch', 'schema_validation_failed', 'structural_bound_failure', 'timeout_exhausted', 'malformed_worker_output', 'unsupported_source', 'legal_review_required', 'duplicate_provider_identity_conflict', 'oversize_body', 'listing_rejected_key');

-- CreateEnum
CREATE TYPE "osv_quarantine_phase" AS ENUM ('inventory', 'retrieval', 'parse', 'revision', 'reconciliation', 'activation');

-- CreateEnum
CREATE TYPE "osv_activation_outcome" AS ENUM ('activated', 'already_active', 'stale_pointer', 'generation_not_ready', 'completeness_failed', 'version_mismatch', 'quarantine_blocked', 'immutable_conflict');

-- CreateEnum
CREATE TYPE "osv_completeness_dimension" AS ENUM ('inventory', 'eligible_body', 'parser', 'parsed_catalog', 'matching');

-- CreateEnum
CREATE TYPE "osv_completeness_status" AS ENUM ('not_started', 'incomplete', 'complete', 'failed', 'not_in_scope');

-- CreateEnum
CREATE TYPE "osv_object_storage_kind" AS ENUM ('advisory_body', 'parsed_advisory');

-- CreateEnum
CREATE TYPE "osv_object_storage_role" AS ENUM ('temporary', 'final');

-- CreateEnum
CREATE TYPE "osv_family_candidate_kind" AS ENUM ('known', 'unknown_uppercase', 'unclassifiable');

-- CreateEnum
CREATE TYPE "osv_inventory_failure_code" AS ENUM ('incomplete_pass', 'divergent_passes', 'listing_rejected', 'classification_mismatch', 'cancelled');

-- CreateEnum
CREATE TYPE "osv_reconciliation_discrepancy_code" AS ENUM ('listing_rejected_nonzero', 'classification_mismatch', 'missing_eligible_snapshot', 'non_eligible_snapshot_present', 'parser_result_mismatch', 'revision_mismatch', 'membership_mismatch', 'blocking_quarantine', 'immutable_conflict_present', 'fail_closed_body_present', 'pin_mismatch', 'matching_not_not_in_scope');

-- CreateEnum
CREATE TYPE "osv_source_identifier" AS ENUM ('ossf_malicious_packages', 'github_advisory_database', 'pypa_advisory_database', 'go_vulnerability_database', 'rustsec_advisory_database', 'global_security_database', 'erlang_ecosystem_foundation_cna', 'osv_ambiguous_origin', 'echo_advisory_database');

-- CreateEnum
CREATE TYPE "osv_advisory_parser_warning_code" AS ENUM ('self_reference_omitted', 'database_specific_fields_omitted', 'ecosystem_specific_fields_omitted');

-- CreateEnum
CREATE TYPE "osv_advisory_parser_retryability" AS ENUM ('non_retryable', 'orchestration_retryable');

-- CreateEnum
CREATE TYPE "osv_advisory_parser_failure_phase" AS ENUM ('request_validation', 'policy', 'input_identity', 'execution', 'decode', 'schema', 'structure', 'source_confirmation', 'output_validation');

-- CreateTable
CREATE TABLE "osv_catalog_generation" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "scope_fingerprint" CHAR(64) NOT NULL,
    "provider_identifier" VARCHAR(32) NOT NULL,
    "inventory_scope" VARCHAR(128) NOT NULL,
    "eligible_body_scope" VARCHAR(128) NOT NULL,
    "source_license_registry" VARCHAR(128) NOT NULL,
    "listing_protocol" VARCHAR(128) NOT NULL,
    "transport_policy" VARCHAR(128) NOT NULL,
    "parser_protocol" VARCHAR(128) NOT NULL,
    "parser_resource_policy" VARCHAR(128) NOT NULL,
    "schema_revision" VARCHAR(32) NOT NULL,
    "schema_commit" CHAR(40) NOT NULL,
    "metadata_policy" VARCHAR(128) NOT NULL,
    "sync_algorithm" VARCHAR(128) NOT NULL,
    "lifecycle_state" "osv_catalog_lifecycle_state" NOT NULL DEFAULT 'planned',
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ready_at" TIMESTAMPTZ(6),
    "activated_at" TIMESTAMPTZ(6),
    "superseded_at" TIMESTAMPTZ(6),
    "failed_at" TIMESTAMPTZ(6),
    "cancelled_at" TIMESTAMPTZ(6),
    "quarantined_at" TIMESTAMPTZ(6),
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_catalog_generation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_acquisition_run" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "catalog_generation_id" UUID NOT NULL,
    "scope_fingerprint" CHAR(64) NOT NULL,
    "state" "osv_acquisition_run_state" NOT NULL,
    "attempt_number" INTEGER NOT NULL,
    "correlation_id" UUID NOT NULL,
    "requested_at" TIMESTAMPTZ(6) NOT NULL,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_acquisition_run_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_inventory_run" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "catalog_generation_id" UUID NOT NULL,
    "state" "osv_inventory_run_state" NOT NULL,
    "inventory_scope" VARCHAR(128) NOT NULL,
    "listing_protocol" VARCHAR(128) NOT NULL,
    "transport_policy" VARCHAR(128) NOT NULL,
    "source_license_registry" VARCHAR(128) NOT NULL,
    "pass_count" INTEGER NOT NULL,
    "started_at" TIMESTAMPTZ(6) NOT NULL,
    "completed_at" TIMESTAMPTZ(6),
    "accepted_listed_count" INTEGER NOT NULL,
    "listing_rejected_count" INTEGER NOT NULL,
    "eligible_count" INTEGER NOT NULL,
    "ineligible_count" INTEGER NOT NULL,
    "legal_review_count" INTEGER NOT NULL,
    "unknown_count" INTEGER NOT NULL,
    "ambiguous_count" INTEGER NOT NULL,
    "convergence" "osv_inventory_convergence_status" NOT NULL,
    "failure_code" "osv_inventory_failure_code",
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_inventory_run_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_inventory_prefix_pass" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "inventory_run_id" UUID NOT NULL,
    "provider_prefix" VARCHAR(32) NOT NULL,
    "pass_number" INTEGER NOT NULL,
    "listing_protocol" VARCHAR(128) NOT NULL,
    "transport_policy" VARCHAR(128) NOT NULL,
    "source_license_registry" VARCHAR(128) NOT NULL,
    "inventory_scope" VARCHAR(128) NOT NULL,
    "page_count" INTEGER NOT NULL,
    "response_byte_count" INTEGER NOT NULL,
    "accepted_item_count" INTEGER NOT NULL,
    "listing_rejected_count" INTEGER NOT NULL,
    "terminal_page_observed" BOOLEAN NOT NULL,
    "completeness" "osv_inventory_pass_completeness_status" NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_inventory_prefix_pass_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_inventory_object_observation" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "inventory_run_id" UUID NOT NULL,
    "provider_object_key_digest" CHAR(64) NOT NULL,
    "provider_generation" VARCHAR(20) NOT NULL,
    "provider_prefix" VARCHAR(32) NOT NULL,
    "declared_byte_count" INTEGER NOT NULL,
    "classification_status" "osv_classification_status" NOT NULL,
    "source_identifier" "osv_source_identifier",
    "etag_metadata" VARCHAR(128),
    "md5_hash_metadata" VARCHAR(128),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_inventory_object_observation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_provider_object" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "provider_identifier" VARCHAR(32) NOT NULL,
    "provider_object_key" VARCHAR(512) NOT NULL,
    "provider_object_key_digest" CHAR(64) NOT NULL,
    "provider_prefix" VARCHAR(32) NOT NULL,
    "family_kind" "osv_family_candidate_kind" NOT NULL,
    "family_value" VARCHAR(64),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_provider_object_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_provider_generation" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "provider_object_id" UUID NOT NULL,
    "provider_object_key_digest" CHAR(64) NOT NULL,
    "provider_generation" VARCHAR(20) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_provider_generation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_object_attachment" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "storage_kind" "osv_object_storage_kind" NOT NULL,
    "role" "osv_object_storage_role" NOT NULL,
    "object_key" VARCHAR(512) NOT NULL,
    "locator_content_sha256" CHAR(64),
    "upload_id" UUID,
    "content_sha256" CHAR(64) NOT NULL,
    "byte_count" INTEGER NOT NULL,
    "content_type" VARCHAR(128) NOT NULL,
    "content_encoding" VARCHAR(32) NOT NULL,
    "state" "osv_attachment_state" NOT NULL,
    "cleanup_eligible" BOOLEAN NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_object_attachment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_provider_body_snapshot" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "provider_generation_id" UUID NOT NULL,
    "attachment_id" UUID NOT NULL,
    "content_sha256" CHAR(64) NOT NULL,
    "received_byte_count" INTEGER NOT NULL,
    "declared_byte_count" INTEGER NOT NULL,
    "content_type" VARCHAR(128) NOT NULL,
    "content_encoding" VARCHAR(32) NOT NULL,
    "source_identifier" "osv_source_identifier" NOT NULL,
    "registry_identifier" VARCHAR(128) NOT NULL,
    "eligible_body_scope" VARCHAR(128) NOT NULL,
    "transport_policy" VARCHAR(128) NOT NULL,
    "retrieved_at" TIMESTAMPTZ(6) NOT NULL,
    "classification_status" "osv_classification_status" NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_provider_body_snapshot_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_parser_attempt" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "snapshot_id" UUID NOT NULL,
    "protocol_identifier" VARCHAR(128) NOT NULL,
    "schema_revision" VARCHAR(32) NOT NULL,
    "schema_commit" CHAR(40) NOT NULL,
    "resource_policy" VARCHAR(128) NOT NULL,
    "registry_identifier" VARCHAR(128) NOT NULL,
    "source_identifier" "osv_source_identifier" NOT NULL,
    "input_sha256" CHAR(64) NOT NULL,
    "input_byte_count" INTEGER NOT NULL,
    "attempt_number" INTEGER NOT NULL,
    "result_state" "osv_parser_attempt_result_state" NOT NULL,
    "failure_kind" VARCHAR(64),
    "retryability" "osv_advisory_parser_retryability",
    "phase" "osv_advisory_parser_failure_phase",
    "termination_required" BOOLEAN NOT NULL,
    "warning_codes" "osv_advisory_parser_warning_code"[] NOT NULL DEFAULT '{}',
    "worker_lifecycle_outcome" "osv_worker_lifecycle_outcome" NOT NULL,
    "parsed_revision_id" UUID,
    "correlation_id" UUID NOT NULL,
    "started_at" TIMESTAMPTZ(6) NOT NULL,
    "completed_at" TIMESTAMPTZ(6) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_parser_attempt_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_parsed_advisory_revision" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "snapshot_id" UUID NOT NULL,
    "parser_attempt_id" UUID NOT NULL,
    "provider_generation_id" UUID NOT NULL,
    "document_attachment_id" UUID NOT NULL,
    "document_identifier" VARCHAR(128) NOT NULL,
    "protocol_identifier" VARCHAR(128) NOT NULL,
    "schema_revision" VARCHAR(32) NOT NULL,
    "schema_commit" CHAR(40) NOT NULL,
    "resource_policy" VARCHAR(128) NOT NULL,
    "registry_identifier" VARCHAR(128) NOT NULL,
    "source_identifier" "osv_source_identifier" NOT NULL,
    "content_sha256" CHAR(64) NOT NULL,
    "parsed_output_sha256" CHAR(64) NOT NULL,
    "parsed_top_level_osv_id" VARCHAR(512) NOT NULL,
    "published_at" TIMESTAMPTZ(6),
    "modified_at" TIMESTAMPTZ(6),
    "withdrawn_at" TIMESTAMPTZ(6),
    "withdrawn" BOOLEAN NOT NULL,
    "alias_count" INTEGER NOT NULL,
    "related_count" INTEGER NOT NULL,
    "affected_package_count" INTEGER NOT NULL,
    "range_count" INTEGER NOT NULL,
    "event_count" INTEGER NOT NULL,
    "explicit_version_count" INTEGER NOT NULL,
    "reference_count" INTEGER NOT NULL,
    "credit_count" INTEGER NOT NULL,
    "severity_count" INTEGER NOT NULL,
    "normalization_state" VARCHAR(64) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_parsed_advisory_revision_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_catalog_membership" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "catalog_generation_id" UUID NOT NULL,
    "revision_id" UUID NOT NULL,
    "attached_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_catalog_membership_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_acquisition_completeness" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "catalog_generation_id" UUID NOT NULL,
    "dimension" "osv_completeness_dimension" NOT NULL,
    "status" "osv_completeness_status" NOT NULL,
    "required_count" INTEGER NOT NULL,
    "observed_count" INTEGER NOT NULL,
    "discrepancy_codes" "osv_reconciliation_discrepancy_code"[] NOT NULL DEFAULT '{}',
    "blocks_activation" BOOLEAN NOT NULL,
    "mal_matching_prohibited" BOOLEAN NOT NULL,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_acquisition_completeness_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_reconciliation" (
    "catalog_generation_id" UUID NOT NULL,
    "accepted_listed_count" INTEGER NOT NULL,
    "eligible_count" INTEGER NOT NULL,
    "ineligible_count" INTEGER NOT NULL,
    "legal_review_count" INTEGER NOT NULL,
    "unknown_count" INTEGER NOT NULL,
    "ambiguous_count" INTEGER NOT NULL,
    "listing_rejected_count" INTEGER NOT NULL,
    "attached_eligible_snapshot_count" INTEGER NOT NULL,
    "missing_eligible_snapshot_count" INTEGER NOT NULL,
    "non_eligible_snapshot_count" INTEGER NOT NULL,
    "parser_success_count" INTEGER NOT NULL,
    "parser_failure_count" INTEGER NOT NULL,
    "quarantined_snapshot_count" INTEGER NOT NULL,
    "accepted_revision_count" INTEGER NOT NULL,
    "withdrawn_revision_count" INTEGER NOT NULL,
    "membership_count" INTEGER NOT NULL,
    "provider_absent_count" INTEGER NOT NULL,
    "immutable_conflict_count" INTEGER NOT NULL,
    "blocking_quarantine_count" INTEGER NOT NULL,
    "fail_closed_retrieved_body_count" INTEGER NOT NULL,
    "pin_mismatch_count" INTEGER NOT NULL,
    "passed" BOOLEAN NOT NULL,
    "discrepancy_codes" "osv_reconciliation_discrepancy_code"[] NOT NULL DEFAULT '{}',
    "blocks_activation" BOOLEAN NOT NULL,
    "matching_completeness" VARCHAR(32) NOT NULL,
    "frozen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_reconciliation_pkey" PRIMARY KEY ("catalog_generation_id")
);

-- CreateTable
CREATE TABLE "osv_quarantine_record" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "catalog_generation_id" UUID NOT NULL,
    "provider_object_key_digest" CHAR(64),
    "snapshot_id" UUID,
    "parser_attempt_id" UUID,
    "revision_id" UUID,
    "reason_code" "osv_quarantine_reason_code" NOT NULL,
    "originating_phase" "osv_quarantine_phase" NOT NULL,
    "diagnostic_code" "osv_quarantine_reason_code" NOT NULL,
    "recorded_at" TIMESTAMPTZ(6) NOT NULL,
    "blocks_activation" BOOLEAN NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_quarantine_record_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_provider_presence_observation" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "catalog_generation_id" UUID NOT NULL,
    "provider_object_id" UUID NOT NULL,
    "provider_object_key_digest" CHAR(64) NOT NULL,
    "kind" "osv_presence_kind" NOT NULL,
    "recorded_at" TIMESTAMPTZ(6) NOT NULL,
    "historical_snapshot_id" UUID,
    "historical_revision_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_provider_presence_observation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_active_catalog_pointer" (
    "scope_fingerprint" CHAR(64) NOT NULL,
    "generation_id" UUID,
    "version" INTEGER NOT NULL,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_active_catalog_pointer_pkey" PRIMARY KEY ("scope_fingerprint")
);

-- CreateTable
CREATE TABLE "osv_activation_record" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "scope_fingerprint" CHAR(64) NOT NULL,
    "candidate_generation_id" UUID NOT NULL,
    "previous_generation_id" UUID,
    "expected_pointer_version" INTEGER NOT NULL,
    "resulting_pointer_version" INTEGER,
    "activated_at" TIMESTAMPTZ(6) NOT NULL,
    "reason_code" VARCHAR(64) NOT NULL,
    "outcome" "osv_activation_outcome" NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_activation_record_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "osv_catalog_generation_scope_state_idx" ON "osv_catalog_generation"("scope_fingerprint", "lifecycle_state");

-- CreateIndex
CREATE UNIQUE INDEX "osv_catalog_generation_id_scope_key" ON "osv_catalog_generation"("id", "scope_fingerprint");

-- CreateIndex
CREATE INDEX "osv_acquisition_run_scope_state_idx" ON "osv_acquisition_run"("scope_fingerprint", "state");

-- CreateIndex
CREATE INDEX "osv_inventory_run_generation_state_idx" ON "osv_inventory_run"("catalog_generation_id", "state");

-- CreateIndex
CREATE UNIQUE INDEX "osv_inventory_prefix_pass_natural_key" ON "osv_inventory_prefix_pass"("inventory_run_id", "provider_prefix", "pass_number");

-- CreateIndex
CREATE UNIQUE INDEX "osv_inventory_object_observation_natural_key" ON "osv_inventory_object_observation"("inventory_run_id", "provider_object_key_digest", "provider_generation");

-- CreateIndex
CREATE UNIQUE INDEX "osv_provider_object_digest_uidx" ON "osv_provider_object"("provider_identifier", "provider_object_key_digest");

-- CreateIndex
CREATE UNIQUE INDEX "osv_provider_object_key_uidx" ON "osv_provider_object"("provider_identifier", "provider_object_key");

-- CreateIndex
CREATE INDEX "osv_provider_generation_digest_idx" ON "osv_provider_generation"("provider_object_key_digest", "provider_generation");

-- CreateIndex
CREATE UNIQUE INDEX "osv_provider_generation_natural_key" ON "osv_provider_generation"("provider_object_id", "provider_generation");

-- CreateIndex
CREATE INDEX "osv_object_attachment_cleanup_idx" ON "osv_object_attachment"("state", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "osv_provider_body_snapshot_generation_uidx" ON "osv_provider_body_snapshot"("provider_generation_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_provider_body_snapshot_attachment_uidx" ON "osv_provider_body_snapshot"("attachment_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_parser_attempt_revision_uidx" ON "osv_parser_attempt"("parsed_revision_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_parser_attempt_snapshot_ordinal_uidx" ON "osv_parser_attempt"("snapshot_id", "attempt_number");

-- CreateIndex
CREATE UNIQUE INDEX "osv_parsed_advisory_revision_attempt_uidx" ON "osv_parsed_advisory_revision"("parser_attempt_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_parsed_advisory_revision_attachment_uidx" ON "osv_parsed_advisory_revision"("document_attachment_id");

-- CreateIndex
CREATE INDEX "osv_parsed_advisory_revision_generation_idx" ON "osv_parsed_advisory_revision"("provider_generation_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_parsed_advisory_revision_pin_uidx" ON "osv_parsed_advisory_revision"("snapshot_id", "protocol_identifier", "schema_revision", "schema_commit", "resource_policy", "registry_identifier");

-- CreateIndex
CREATE UNIQUE INDEX "osv_catalog_membership_natural_key" ON "osv_catalog_membership"("catalog_generation_id", "revision_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_acquisition_completeness_natural_key" ON "osv_acquisition_completeness"("catalog_generation_id", "dimension");

-- CreateIndex
CREATE INDEX "osv_quarantine_record_generation_blocking_idx" ON "osv_quarantine_record"("catalog_generation_id", "blocks_activation");

-- CreateIndex
CREATE UNIQUE INDEX "osv_provider_presence_observation_natural_key" ON "osv_provider_presence_observation"("catalog_generation_id", "provider_object_id", "kind");

-- CreateIndex
CREATE INDEX "osv_activation_record_scope_time_idx" ON "osv_activation_record"("scope_fingerprint", "activated_at");

-- AddForeignKey
ALTER TABLE "osv_acquisition_run" ADD CONSTRAINT "osv_acquisition_run_catalog_generation_id_scope_fingerprin_fkey" FOREIGN KEY ("catalog_generation_id", "scope_fingerprint") REFERENCES "osv_catalog_generation"("id", "scope_fingerprint") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_inventory_run" ADD CONSTRAINT "osv_inventory_run_catalog_generation_id_fkey" FOREIGN KEY ("catalog_generation_id") REFERENCES "osv_catalog_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_inventory_prefix_pass" ADD CONSTRAINT "osv_inventory_prefix_pass_inventory_run_id_fkey" FOREIGN KEY ("inventory_run_id") REFERENCES "osv_inventory_run"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_inventory_object_observation" ADD CONSTRAINT "osv_inventory_object_observation_inventory_run_id_fkey" FOREIGN KEY ("inventory_run_id") REFERENCES "osv_inventory_run"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_provider_generation" ADD CONSTRAINT "osv_provider_generation_provider_object_id_fkey" FOREIGN KEY ("provider_object_id") REFERENCES "osv_provider_object"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_provider_body_snapshot" ADD CONSTRAINT "osv_provider_body_snapshot_provider_generation_id_fkey" FOREIGN KEY ("provider_generation_id") REFERENCES "osv_provider_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_provider_body_snapshot" ADD CONSTRAINT "osv_provider_body_snapshot_attachment_id_fkey" FOREIGN KEY ("attachment_id") REFERENCES "osv_object_attachment"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_parser_attempt" ADD CONSTRAINT "osv_parser_attempt_snapshot_id_fkey" FOREIGN KEY ("snapshot_id") REFERENCES "osv_provider_body_snapshot"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_parser_attempt" ADD CONSTRAINT "osv_parser_attempt_parsed_revision_id_fkey" FOREIGN KEY ("parsed_revision_id") REFERENCES "osv_parsed_advisory_revision"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_parsed_advisory_revision" ADD CONSTRAINT "osv_parsed_advisory_revision_snapshot_id_fkey" FOREIGN KEY ("snapshot_id") REFERENCES "osv_provider_body_snapshot"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_parsed_advisory_revision" ADD CONSTRAINT "osv_parsed_advisory_revision_parser_attempt_id_fkey" FOREIGN KEY ("parser_attempt_id") REFERENCES "osv_parser_attempt"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_parsed_advisory_revision" ADD CONSTRAINT "osv_parsed_advisory_revision_provider_generation_id_fkey" FOREIGN KEY ("provider_generation_id") REFERENCES "osv_provider_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_parsed_advisory_revision" ADD CONSTRAINT "osv_parsed_advisory_revision_document_attachment_id_fkey" FOREIGN KEY ("document_attachment_id") REFERENCES "osv_object_attachment"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_catalog_membership" ADD CONSTRAINT "osv_catalog_membership_catalog_generation_id_fkey" FOREIGN KEY ("catalog_generation_id") REFERENCES "osv_catalog_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_catalog_membership" ADD CONSTRAINT "osv_catalog_membership_revision_id_fkey" FOREIGN KEY ("revision_id") REFERENCES "osv_parsed_advisory_revision"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_acquisition_completeness" ADD CONSTRAINT "osv_acquisition_completeness_catalog_generation_id_fkey" FOREIGN KEY ("catalog_generation_id") REFERENCES "osv_catalog_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_reconciliation" ADD CONSTRAINT "osv_reconciliation_catalog_generation_id_fkey" FOREIGN KEY ("catalog_generation_id") REFERENCES "osv_catalog_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_quarantine_record" ADD CONSTRAINT "osv_quarantine_record_catalog_generation_id_fkey" FOREIGN KEY ("catalog_generation_id") REFERENCES "osv_catalog_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_quarantine_record" ADD CONSTRAINT "osv_quarantine_record_snapshot_id_fkey" FOREIGN KEY ("snapshot_id") REFERENCES "osv_provider_body_snapshot"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_quarantine_record" ADD CONSTRAINT "osv_quarantine_record_parser_attempt_id_fkey" FOREIGN KEY ("parser_attempt_id") REFERENCES "osv_parser_attempt"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_quarantine_record" ADD CONSTRAINT "osv_quarantine_record_revision_id_fkey" FOREIGN KEY ("revision_id") REFERENCES "osv_parsed_advisory_revision"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_provider_presence_observation" ADD CONSTRAINT "osv_provider_presence_observation_catalog_generation_id_fkey" FOREIGN KEY ("catalog_generation_id") REFERENCES "osv_catalog_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_provider_presence_observation" ADD CONSTRAINT "osv_provider_presence_observation_provider_object_id_fkey" FOREIGN KEY ("provider_object_id") REFERENCES "osv_provider_object"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_provider_presence_observation" ADD CONSTRAINT "osv_provider_presence_observation_historical_snapshot_id_fkey" FOREIGN KEY ("historical_snapshot_id") REFERENCES "osv_provider_body_snapshot"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_provider_presence_observation" ADD CONSTRAINT "osv_provider_presence_observation_historical_revision_id_fkey" FOREIGN KEY ("historical_revision_id") REFERENCES "osv_parsed_advisory_revision"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_active_catalog_pointer" ADD CONSTRAINT "osv_active_catalog_pointer_generation_id_scope_fingerprint_fkey" FOREIGN KEY ("generation_id", "scope_fingerprint") REFERENCES "osv_catalog_generation"("id", "scope_fingerprint") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_activation_record" ADD CONSTRAINT "osv_activation_record_candidate_generation_id_scope_finger_fkey" FOREIGN KEY ("candidate_generation_id", "scope_fingerprint") REFERENCES "osv_catalog_generation"("id", "scope_fingerprint") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "osv_activation_record" ADD CONSTRAINT "osv_activation_record_previous_generation_id_fkey" FOREIGN KEY ("previous_generation_id") REFERENCES "osv_catalog_generation"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE UNIQUE INDEX "osv_acquisition_run_inflight_uidx"
  ON "osv_acquisition_run" ("scope_fingerprint")
  WHERE "state" IN ('requested', 'running', 'retry_wait');

CREATE UNIQUE INDEX "osv_catalog_generation_one_active_uidx"
  ON "osv_catalog_generation" ("scope_fingerprint")
  WHERE "lifecycle_state" = 'active';

CREATE INDEX "osv_object_attachment_cleanup_eligible_idx"
  ON "osv_object_attachment" ("created_at")
  WHERE "cleanup_eligible" = TRUE;

ALTER TABLE "osv_catalog_generation"
  ADD CONSTRAINT "osv_catalog_generation_scope_fingerprint_chk"
  CHECK ("scope_fingerprint" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_catalog_generation"
  ADD CONSTRAINT "osv_catalog_generation_provider_chk"
  CHECK ("provider_identifier" = 'osv');

ALTER TABLE "osv_catalog_generation"
  ADD CONSTRAINT "osv_catalog_generation_schema_commit_chk"
  CHECK ("schema_commit" ~ '^[a-f0-9]{40}$');

ALTER TABLE "osv_catalog_generation"
  ADD CONSTRAINT "osv_catalog_generation_pin_shape_chk"
  CHECK (
    "inventory_scope" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
    AND "eligible_body_scope" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
    AND "source_license_registry" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
    AND "listing_protocol" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
    AND "transport_policy" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
    AND "parser_protocol" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
    AND "parser_resource_policy" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
    AND "schema_revision" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,31}$'
    AND "metadata_policy" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
    AND "sync_algorithm" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$'
  );

ALTER TABLE "osv_catalog_generation"
  ADD CONSTRAINT "osv_catalog_generation_version_chk"
  CHECK ("version" >= 1);

ALTER TABLE "osv_catalog_generation"
  ADD CONSTRAINT "osv_catalog_generation_lifecycle_timestamps_chk"
  CHECK (
    ("lifecycle_state" <> 'ready_for_activation' OR "ready_at" IS NOT NULL)
    AND ("lifecycle_state" <> 'active' OR "activated_at" IS NOT NULL)
    AND ("lifecycle_state" <> 'superseded' OR "superseded_at" IS NOT NULL)
    AND ("lifecycle_state" <> 'failed' OR "failed_at" IS NOT NULL)
    AND ("lifecycle_state" <> 'cancelled' OR "cancelled_at" IS NOT NULL)
    AND ("lifecycle_state" <> 'quarantined' OR "quarantined_at" IS NOT NULL)
  );

ALTER TABLE "osv_acquisition_run"
  ADD CONSTRAINT "osv_acquisition_run_scope_fingerprint_chk"
  CHECK ("scope_fingerprint" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_acquisition_run"
  ADD CONSTRAINT "osv_acquisition_run_attempt_chk"
  CHECK ("attempt_number" >= 1);

ALTER TABLE "osv_inventory_run"
  ADD CONSTRAINT "osv_inventory_run_counts_nonnegative_chk"
  CHECK (
    "pass_count" = 2
    AND "accepted_listed_count" >= 0
    AND "listing_rejected_count" >= 0
    AND "eligible_count" >= 0
    AND "ineligible_count" >= 0
    AND "legal_review_count" >= 0
    AND "unknown_count" >= 0
    AND "ambiguous_count" >= 0
  );

ALTER TABLE "osv_inventory_run"
  ADD CONSTRAINT "osv_inventory_run_classification_sum_chk"
  CHECK (
    "eligible_count" + "ineligible_count" + "legal_review_count"
      + "unknown_count" + "ambiguous_count" = "accepted_listed_count"
  );

ALTER TABLE "osv_inventory_run"
  ADD CONSTRAINT "osv_inventory_run_completed_after_started_chk"
  CHECK ("completed_at" IS NULL OR "completed_at" >= "started_at");

ALTER TABLE "osv_inventory_run"
  ADD CONSTRAINT "osv_inventory_run_running_chk"
  CHECK (
    "state" <> 'running'
    OR ("completed_at" IS NULL AND "failure_code" IS NULL)
  );

ALTER TABLE "osv_inventory_run"
  ADD CONSTRAINT "osv_inventory_run_complete_chk"
  CHECK (
    "state" <> 'complete'
    OR (
      "completed_at" IS NOT NULL
      AND "listing_rejected_count" = 0
      AND "convergence" = 'converged'
      AND "failure_code" IS NULL
    )
  );

ALTER TABLE "osv_inventory_run"
  ADD CONSTRAINT "osv_inventory_run_failed_chk"
  CHECK (
    "state" <> 'failed'
    OR ("completed_at" IS NOT NULL AND "failure_code" IS NOT NULL AND "failure_code" <> 'cancelled')
  );

ALTER TABLE "osv_inventory_run"
  ADD CONSTRAINT "osv_inventory_run_cancelled_chk"
  CHECK (
    "state" <> 'cancelled'
    OR ("completed_at" IS NOT NULL AND "failure_code" = 'cancelled')
  );

ALTER TABLE "osv_inventory_prefix_pass"
  ADD CONSTRAINT "osv_inventory_prefix_pass_prefix_chk"
  CHECK ("provider_prefix" IN ('npm/', 'PyPI/', 'Go/', 'Maven/', 'NuGet/', 'crates.io/'));

ALTER TABLE "osv_inventory_prefix_pass"
  ADD CONSTRAINT "osv_inventory_prefix_pass_number_chk"
  CHECK ("pass_number" IN (1, 2));

ALTER TABLE "osv_inventory_prefix_pass"
  ADD CONSTRAINT "osv_inventory_prefix_pass_counts_nonnegative_chk"
  CHECK (
    "page_count" >= 0
    AND "response_byte_count" >= 0
    AND "accepted_item_count" >= 0
    AND "listing_rejected_count" >= 0
  );

ALTER TABLE "osv_inventory_prefix_pass"
  ADD CONSTRAINT "osv_inventory_prefix_pass_complete_chk"
  CHECK (
    "completeness" <> 'complete'
    OR ("terminal_page_observed" = TRUE AND "listing_rejected_count" = 0)
  );

ALTER TABLE "osv_inventory_object_observation"
  ADD CONSTRAINT "osv_inventory_object_observation_digest_chk"
  CHECK ("provider_object_key_digest" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_inventory_object_observation"
  ADD CONSTRAINT "osv_inventory_object_observation_generation_chk"
  CHECK ("provider_generation" ~ '^[1-9][0-9]{0,19}$');

ALTER TABLE "osv_inventory_object_observation"
  ADD CONSTRAINT "osv_inventory_object_observation_prefix_chk"
  CHECK ("provider_prefix" IN ('npm/', 'PyPI/', 'Go/', 'Maven/', 'NuGet/', 'crates.io/'));

ALTER TABLE "osv_inventory_object_observation"
  ADD CONSTRAINT "osv_inventory_object_observation_byte_count_chk"
  CHECK ("declared_byte_count" >= 0);

ALTER TABLE "osv_inventory_object_observation"
  ADD CONSTRAINT "osv_inventory_object_observation_source_chk"
  CHECK (
    ("classification_status" <> 'eligible' OR "source_identifier" IS NOT NULL)
    AND (
      "classification_status" IN ('eligible', 'legal_review_required')
      OR "source_identifier" IS NULL
    )
  );

ALTER TABLE "osv_inventory_object_observation"
  ADD CONSTRAINT "osv_inventory_object_observation_metadata_chk"
  CHECK (
    ("etag_metadata" IS NULL OR ("etag_metadata" <> '' AND position('://' in "etag_metadata") = 0))
    AND ("md5_hash_metadata" IS NULL OR ("md5_hash_metadata" <> '' AND position('://' in "md5_hash_metadata") = 0))
  );

ALTER TABLE "osv_provider_object"
  ADD CONSTRAINT "osv_provider_object_provider_chk"
  CHECK ("provider_identifier" = 'osv');

ALTER TABLE "osv_provider_object"
  ADD CONSTRAINT "osv_provider_object_digest_chk"
  CHECK ("provider_object_key_digest" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_provider_object"
  ADD CONSTRAINT "osv_provider_object_key_chk"
  CHECK (
    char_length("provider_object_key") BETWEEN 1 AND 512
    AND "provider_object_key" LIKE '%/%'
    AND "provider_object_key" LIKE '%.json'
    AND "provider_object_key" NOT LIKE 'intelligence/%'
    AND position('://' in "provider_object_key") = 0
  );

ALTER TABLE "osv_provider_object"
  ADD CONSTRAINT "osv_provider_object_prefix_chk"
  CHECK ("provider_prefix" IN ('npm/', 'PyPI/', 'Go/', 'Maven/', 'NuGet/', 'crates.io/'));

ALTER TABLE "osv_provider_object"
  ADD CONSTRAINT "osv_provider_object_family_chk"
  CHECK (
    ("family_kind" = 'unclassifiable' AND "family_value" IS NULL)
    OR ("family_kind" <> 'unclassifiable' AND "family_value" ~ '^[A-Z][A-Z0-9-]{0,62}$')
  );

ALTER TABLE "osv_provider_generation"
  ADD CONSTRAINT "osv_provider_generation_digest_chk"
  CHECK ("provider_object_key_digest" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_provider_generation"
  ADD CONSTRAINT "osv_provider_generation_value_chk"
  CHECK ("provider_generation" ~ '^[1-9][0-9]{0,19}$');

ALTER TABLE "osv_object_attachment"
  ADD CONSTRAINT "osv_object_attachment_sha256_chk"
  CHECK (
    "content_sha256" ~ '^[a-f0-9]{64}$'
    AND ("locator_content_sha256" IS NULL OR "locator_content_sha256" ~ '^[a-f0-9]{64}$')
  );

ALTER TABLE "osv_object_attachment"
  ADD CONSTRAINT "osv_object_attachment_byte_count_chk"
  CHECK ("byte_count" BETWEEN 1 AND 1048576);

ALTER TABLE "osv_object_attachment"
  ADD CONSTRAINT "osv_object_attachment_type_chk"
  CHECK ("content_type" = 'application/json' AND "content_encoding" = 'identity');

ALTER TABLE "osv_object_attachment"
  ADD CONSTRAINT "osv_object_attachment_locator_chk"
  CHECK (
    "object_key" NOT LIKE '%://%'
    AND "object_key" NOT LIKE '%..%'
    AND (
      (
        "state" = 'staged'
        AND "role" = 'temporary'
        AND "upload_id" IS NOT NULL
        AND "locator_content_sha256" IS NULL
        AND "cleanup_eligible" = FALSE
        AND "object_key" ~ ('^intelligence/osv/(advisory_body|parsed_advisory)/tmp/' || "upload_id"::text || '$')
      )
      OR (
        "state" = 'attached'
        AND "role" = 'final'
        AND "upload_id" IS NULL
        AND "locator_content_sha256" = "content_sha256"
        AND "cleanup_eligible" = FALSE
        AND "object_key" = ('intelligence/osv/' || "storage_kind"::text || '/sha256/' || "content_sha256")
      )
      OR (
        "state" IN ('orphaned', 'rejected')
        AND "cleanup_eligible" = TRUE
        AND (
          (
            "role" = 'temporary'
            AND "upload_id" IS NOT NULL
            AND "locator_content_sha256" IS NULL
            AND "object_key" ~ ('^intelligence/osv/(advisory_body|parsed_advisory)/tmp/' || "upload_id"::text || '$')
          )
          OR (
            "role" = 'final'
            AND "upload_id" IS NULL
            AND "locator_content_sha256" = "content_sha256"
            AND "object_key" = ('intelligence/osv/' || "storage_kind"::text || '/sha256/' || "content_sha256")
          )
        )
      )
    )
  );

ALTER TABLE "osv_provider_body_snapshot"
  ADD CONSTRAINT "osv_provider_body_snapshot_sha256_chk"
  CHECK ("content_sha256" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_provider_body_snapshot"
  ADD CONSTRAINT "osv_provider_body_snapshot_bytes_chk"
  CHECK (
    "received_byte_count" BETWEEN 1 AND 1048576
    AND "declared_byte_count" = "received_byte_count"
  );

ALTER TABLE "osv_provider_body_snapshot"
  ADD CONSTRAINT "osv_provider_body_snapshot_type_chk"
  CHECK ("content_type" = 'application/json' AND "content_encoding" = 'identity');

ALTER TABLE "osv_provider_body_snapshot"
  ADD CONSTRAINT "osv_provider_body_snapshot_source_chk"
  CHECK (
    "classification_status" = 'eligible'
    AND "source_identifier" NOT IN ('osv_ambiguous_origin', 'echo_advisory_database')
  );

ALTER TABLE "osv_parser_attempt"
  ADD CONSTRAINT "osv_parser_attempt_sha256_chk"
  CHECK (
    "input_sha256" ~ '^[a-f0-9]{64}$'
    AND "schema_commit" ~ '^[a-f0-9]{40}$'
  );

ALTER TABLE "osv_parser_attempt"
  ADD CONSTRAINT "osv_parser_attempt_counts_chk"
  CHECK ("input_byte_count" BETWEEN 1 AND 1048576 AND "attempt_number" >= 1);

ALTER TABLE "osv_parser_attempt"
  ADD CONSTRAINT "osv_parser_attempt_completed_after_started_chk"
  CHECK ("completed_at" >= "started_at");

ALTER TABLE "osv_parser_attempt"
  ADD CONSTRAINT "osv_parser_attempt_outcome_chk"
  CHECK (
    (
      "result_state" = 'succeeded'
      AND "failure_kind" IS NULL
      AND "retryability" IS NULL
      AND "phase" IS NULL
      AND "termination_required" = FALSE
    )
    OR (
      "result_state" = 'failed'
      AND "failure_kind" IS NOT NULL
      AND "failure_kind" ~ '^[a-z0-9_]{1,64}$'
      AND "parsed_revision_id" IS NULL
      AND "retryability" IS NOT NULL
      AND "phase" IS NOT NULL
    )
  );

ALTER TABLE "osv_parsed_advisory_revision"
  ADD CONSTRAINT "osv_parsed_advisory_revision_sha256_chk"
  CHECK (
    "content_sha256" ~ '^[a-f0-9]{64}$'
    AND "parsed_output_sha256" ~ '^[a-f0-9]{64}$'
    AND "schema_commit" ~ '^[a-f0-9]{40}$'
  );

ALTER TABLE "osv_parsed_advisory_revision"
  ADD CONSTRAINT "osv_parsed_advisory_revision_osv_id_chk"
  CHECK ("parsed_top_level_osv_id" ~ '^[A-Z0-9][A-Z0-9._+-]{0,511}$');

ALTER TABLE "osv_parsed_advisory_revision"
  ADD CONSTRAINT "osv_parsed_advisory_revision_withdrawn_chk"
  CHECK ("withdrawn" = ("withdrawn_at" IS NOT NULL));

ALTER TABLE "osv_parsed_advisory_revision"
  ADD CONSTRAINT "osv_parsed_advisory_revision_counts_nonnegative_chk"
  CHECK (
    "alias_count" >= 0
    AND "related_count" >= 0
    AND "affected_package_count" >= 0
    AND "range_count" >= 0
    AND "event_count" >= 0
    AND "explicit_version_count" >= 0
    AND "reference_count" >= 0
    AND "credit_count" >= 0
    AND "severity_count" >= 0
  );

ALTER TABLE "osv_parsed_advisory_revision"
  ADD CONSTRAINT "osv_parsed_advisory_revision_normalization_chk"
  CHECK ("normalization_state" = 'uninterpreted_structural');

ALTER TABLE "osv_acquisition_completeness"
  ADD CONSTRAINT "osv_acquisition_completeness_counts_nonnegative_chk"
  CHECK ("required_count" >= 0 AND "observed_count" >= 0);

ALTER TABLE "osv_acquisition_completeness"
  ADD CONSTRAINT "osv_acquisition_completeness_dimension_chk"
  CHECK (
    (
      "dimension" = 'matching'
      AND "status" = 'not_in_scope'
      AND "required_count" = 0
      AND "observed_count" = 0
      AND "blocks_activation" = FALSE
      AND "mal_matching_prohibited" = TRUE
      AND cardinality("discrepancy_codes") = 0
    )
    OR (
      "dimension" <> 'matching'
      AND "status" <> 'not_in_scope'
      AND "mal_matching_prohibited" = FALSE
      AND "blocks_activation" = ("status" <> 'complete')
      AND (
        "status" <> 'complete'
        OR ("required_count" = "observed_count" AND cardinality("discrepancy_codes") = 0)
      )
    )
  );

ALTER TABLE "osv_reconciliation"
  ADD CONSTRAINT "osv_reconciliation_counts_nonnegative_chk"
  CHECK (
    "accepted_listed_count" >= 0
    AND "eligible_count" >= 0
    AND "ineligible_count" >= 0
    AND "legal_review_count" >= 0
    AND "unknown_count" >= 0
    AND "ambiguous_count" >= 0
    AND "listing_rejected_count" >= 0
    AND "attached_eligible_snapshot_count" >= 0
    AND "missing_eligible_snapshot_count" >= 0
    AND "non_eligible_snapshot_count" >= 0
    AND "parser_success_count" >= 0
    AND "parser_failure_count" >= 0
    AND "quarantined_snapshot_count" >= 0
    AND "accepted_revision_count" >= 0
    AND "withdrawn_revision_count" >= 0
    AND "membership_count" >= 0
    AND "provider_absent_count" >= 0
    AND "immutable_conflict_count" >= 0
    AND "blocking_quarantine_count" >= 0
    AND "fail_closed_retrieved_body_count" >= 0
    AND "pin_mismatch_count" >= 0
    AND "withdrawn_revision_count" <= "accepted_revision_count"
  );

ALTER TABLE "osv_reconciliation"
  ADD CONSTRAINT "osv_reconciliation_matching_chk"
  CHECK ("matching_completeness" = 'not_in_scope');

ALTER TABLE "osv_reconciliation"
  ADD CONSTRAINT "osv_reconciliation_result_chk"
  CHECK (
    "blocks_activation" = (NOT "passed")
    AND ("passed" = (cardinality("discrepancy_codes") = 0))
  );

ALTER TABLE "osv_quarantine_record"
  ADD CONSTRAINT "osv_quarantine_record_digest_chk"
  CHECK (
    "provider_object_key_digest" IS NULL
    OR "provider_object_key_digest" ~ '^[a-f0-9]{64}$'
  );

ALTER TABLE "osv_quarantine_record"
  ADD CONSTRAINT "osv_quarantine_record_blocks_chk"
  CHECK ("blocks_activation" = TRUE);

ALTER TABLE "osv_quarantine_record"
  ADD CONSTRAINT "osv_quarantine_record_diagnostic_chk"
  CHECK ("diagnostic_code" = "reason_code");

ALTER TABLE "osv_provider_presence_observation"
  ADD CONSTRAINT "osv_provider_presence_observation_digest_chk"
  CHECK ("provider_object_key_digest" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_active_catalog_pointer"
  ADD CONSTRAINT "osv_active_catalog_pointer_scope_chk"
  CHECK ("scope_fingerprint" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_active_catalog_pointer"
  ADD CONSTRAINT "osv_active_catalog_pointer_version_chk"
  CHECK ("version" >= 1);

ALTER TABLE "osv_activation_record"
  ADD CONSTRAINT "osv_activation_record_scope_chk"
  CHECK ("scope_fingerprint" ~ '^[a-f0-9]{64}$');

ALTER TABLE "osv_activation_record"
  ADD CONSTRAINT "osv_activation_record_version_chk"
  CHECK (
    "expected_pointer_version" >= 1
    AND ("resulting_pointer_version" IS NULL OR "resulting_pointer_version" >= 1)
  );

ALTER TABLE "osv_activation_record"
  ADD CONSTRAINT "osv_activation_record_reason_chk"
  CHECK ("reason_code" = 'promote_ready_generation');

ALTER TABLE "osv_activation_record"
  ADD CONSTRAINT "osv_activation_record_outcome_chk"
  CHECK (
    (
      "outcome" IN ('activated', 'already_active')
      AND "resulting_pointer_version" IS NOT NULL
    )
    OR (
      "outcome" NOT IN ('activated', 'already_active')
      AND "resulting_pointer_version" IS NULL
    )
  );
