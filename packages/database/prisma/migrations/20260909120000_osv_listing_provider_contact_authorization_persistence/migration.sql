-- Session 13 Batch 3B-P / 3B-P-R: listing-only OSV provider-contact
-- authorization persistence foundation and accepted provider-free preflight
-- attestation. Batch 3B-P-R independently reviewed and hardened this
-- uncommitted SQL before freeze. Forward-only. Does not edit
-- 20260826120000_schema_foundation through
-- 20260908120000_osv_canary_authorization_persistence.
-- New enum, tables, and lineage triggers only. No ALTER TYPE ADD VALUE on
-- existing enums. No seed rows. No tenant rows. No Finding rows. No active
-- catalog seed. No credentials, holder tokens, page tokens, provider bodies,
-- URLs, or arbitrary JSON. All new foreign keys are ON DELETE RESTRICT.
-- Schema only; no issuance adapter, consumption adapter, CLI, heartbeat,
-- deadline, or provider contact. Schema existence does not issue authority.

-- CreateEnum
CREATE TYPE "osv_listing_provider_contact_authorization_state" AS ENUM (
  'issued',
  'consumed_for_listing_execution',
  'completed',
  'failed',
  'cancelled',
  'revoked',
  'expired'
);

-- CreateTable
CREATE TABLE "osv_canary_provider_free_preflight_attestation" (
    "id" UUID NOT NULL,
    "evidence_schema_version" VARCHAR(128) NOT NULL,
    "source_canary_authorization_id" UUID NOT NULL,
    "operator_identity_id" UUID NOT NULL,
    "synchronization_request_id" UUID NOT NULL,
    "synchronization_run_id" UUID NOT NULL,
    "phase" VARCHAR(32) NOT NULL,
    "provider_identity" VARCHAR(128) NOT NULL,
    "approved_prefix" VARCHAR(32) NOT NULL,
    "canary_policy_identifier" VARCHAR(128) NOT NULL,
    "listing_budget_profile" VARCHAR(128) NOT NULL,
    "work_scope" "osv_runtime_work_scope" NOT NULL,
    "lease_scope" VARCHAR(128) NOT NULL,
    "synchronization_reason" "osv_runtime_synchronization_reason" NOT NULL,
    "runtime_version_set_fingerprint" TEXT NOT NULL,
    "legal_decision_version" VARCHAR(128) NOT NULL,
    "egress_evidence_version" VARCHAR(128) NOT NULL,
    "heartbeat_policy_identifier" VARCHAR(128) NOT NULL,
    "deadline_policy_identifier" VARCHAR(128) NOT NULL,
    "active_pointer_baseline_identity" UUID NOT NULL,
    "zero_finding_baseline_identity" UUID NOT NULL,
    "outcome" VARCHAR(128) NOT NULL,
    "provider_contact_authorized" BOOLEAN NOT NULL,
    "execution_permitted" BOOLEAN NOT NULL,
    "accepted_for_provider_contact_authorization" BOOLEAN NOT NULL,
    "captured_at" TIMESTAMPTZ(6) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_canary_provider_free_preflight_attestation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "osv_listing_provider_contact_authorization" (
    "id" UUID NOT NULL,
    "authorization_schema_version" VARCHAR(128) NOT NULL,
    "source_canary_authorization_id" UUID NOT NULL,
    "operator_identity_id" UUID NOT NULL,
    "synchronization_request_id" UUID NOT NULL,
    "synchronization_run_id" UUID NOT NULL,
    "preflight_evidence_id" UUID NOT NULL,
    "phase" VARCHAR(32) NOT NULL,
    "provider_identity" VARCHAR(128) NOT NULL,
    "bucket_identity" VARCHAR(64) NOT NULL,
    "listing_api_path_policy" VARCHAR(128) NOT NULL,
    "listing_protocol" VARCHAR(128) NOT NULL,
    "approved_prefix" VARCHAR(32) NOT NULL,
    "family" VARCHAR(32) NOT NULL,
    "canary_policy_identifier" VARCHAR(128) NOT NULL,
    "listing_budget_profile" VARCHAR(128) NOT NULL,
    "work_scope" "osv_runtime_work_scope" NOT NULL,
    "lease_scope" VARCHAR(128) NOT NULL,
    "synchronization_reason" "osv_runtime_synchronization_reason" NOT NULL,
    "runtime_architecture_identifier" VARCHAR(128) NOT NULL,
    "runtime_version_set_fingerprint" TEXT NOT NULL,
    "query_grammar_policy" VARCHAR(32) NOT NULL,
    "transport_policy" VARCHAR(128) NOT NULL,
    "content_encoding_policy" VARCHAR(32) NOT NULL,
    "redirect_policy" VARCHAR(32) NOT NULL,
    "unused_ttl_seconds" INTEGER NOT NULL,
    "single_use_policy" VARCHAR(32) NOT NULL,
    "provider_retry_authorization" VARCHAR(32) NOT NULL,
    "provider_body_authorization" VARCHAR(32) NOT NULL,
    "parser_authorization" VARCHAR(32) NOT NULL,
    "catalog_activation_authorization" VARCHAR(32) NOT NULL,
    "matching_authorization" VARCHAR(32) NOT NULL,
    "finding_authorization" VARCHAR(32) NOT NULL,
    "legal_approval_identifier" VARCHAR(128) NOT NULL,
    "legal_decision_id" UUID NOT NULL,
    "source_canary_legal_decision_id" UUID NOT NULL,
    "legal_decision_source_registry_version" VARCHAR(128) NOT NULL,
    "legal_listing_metadata_permission" VARCHAR(32) NOT NULL,
    "legal_body_retrieval_permission" VARCHAR(32) NOT NULL,
    "legal_parsing_permission" VARCHAR(32) NOT NULL,
    "legal_matching_permission" VARCHAR(32) NOT NULL,
    "legal_issued_at" TIMESTAMPTZ(6) NOT NULL,
    "legal_revalidation_boundary_at" TIMESTAMPTZ(6) NOT NULL,
    "legal_evidence_set_id" UUID NOT NULL,
    "legal_approval_role" VARCHAR(128) NOT NULL,
    "legal_supersession_status" VARCHAR(32) NOT NULL,
    "egress_evidence_identifier" VARCHAR(128) NOT NULL,
    "egress_evidence_id" UUID NOT NULL,
    "egress_evidence_version" VARCHAR(128) NOT NULL,
    "egress_reviewer_role" VARCHAR(128) NOT NULL,
    "egress_reviewed_at" TIMESTAMPTZ(6) NOT NULL,
    "provider_connectivity_exercised" BOOLEAN NOT NULL,
    "deployment_approval_identifier" VARCHAR(128) NOT NULL,
    "deployment_id" UUID NOT NULL,
    "environment_class" VARCHAR(128) NOT NULL,
    "runtime_artifact_version" VARCHAR(128) NOT NULL,
    "configuration_fingerprint" TEXT NOT NULL,
    "observability_policy" VARCHAR(128) NOT NULL,
    "deployment_approval_role" VARCHAR(128) NOT NULL,
    "deployment_approved_at" TIMESTAMPTZ(6) NOT NULL,
    "invalidates_on_deployment_change" BOOLEAN NOT NULL,
    "heartbeat_policy_identifier" VARCHAR(128) NOT NULL,
    "deadline_policy_identifier" VARCHAR(128) NOT NULL,
    "runbook_set_identifier" VARCHAR(128) NOT NULL,
    "runbook_version" VARCHAR(128) NOT NULL,
    "runbook_acknowledged_at" TIMESTAMPTZ(6) NOT NULL,
    "halt_procedure_identifier" VARCHAR(128) NOT NULL,
    "halt_acknowledged_at" TIMESTAMPTZ(6) NOT NULL,
    "containment_catalog_identifier" VARCHAR(128) NOT NULL,
    "containment_acknowledged_at" TIMESTAMPTZ(6) NOT NULL,
    "postcanary_review_policy_identifier" VARCHAR(128) NOT NULL,
    "required_review_role" VARCHAR(128) NOT NULL,
    "reviewer_assigned_at" TIMESTAMPTZ(6) NOT NULL,
    "issuing_operator_may_review" BOOLEAN NOT NULL,
    "automatic_progression" BOOLEAN NOT NULL,
    "evidence_retention_policy_identifier" VARCHAR(128) NOT NULL,
    "retention_acknowledged_at" TIMESTAMPTZ(6) NOT NULL,
    "active_pointer_baseline_identity" UUID NOT NULL,
    "zero_finding_baseline_identity" UUID NOT NULL,
    "issued_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6) NOT NULL DEFAULT (CURRENT_TIMESTAMP + INTERVAL '3600 seconds'),
    "state" "osv_listing_provider_contact_authorization_state" NOT NULL,
    "consumed_at" TIMESTAMPTZ(6),
    "consumed_by_synchronization_request_id" UUID,
    "consumed_by_synchronization_run_id" UUID,
    "terminal_at" TIMESTAMPTZ(6),
    "terminal_disposition" "osv_listing_provider_contact_authorization_state",
    "terminal_reason_code" VARCHAR(64),
    "revoked_at" TIMESTAMPTZ(6),
    "revoked_by_operator_identity_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_listing_provider_contact_authorization_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "osv_canary_provider_free_preflight_operator_idx"
  ON "osv_canary_provider_free_preflight_attestation"("operator_identity_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_canary_provider_free_preflight_source_uidx"
  ON "osv_canary_provider_free_preflight_attestation"("source_canary_authorization_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_canary_provider_free_preflight_request_uidx"
  ON "osv_canary_provider_free_preflight_attestation"("synchronization_request_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_canary_provider_free_preflight_run_uidx"
  ON "osv_canary_provider_free_preflight_attestation"("synchronization_run_id");

-- CreateIndex
CREATE INDEX "osv_listing_provider_contact_state_expires_idx"
  ON "osv_listing_provider_contact_authorization"("state", "expires_at");

-- CreateIndex
CREATE INDEX "osv_listing_provider_contact_operator_issued_idx"
  ON "osv_listing_provider_contact_authorization"("operator_identity_id", "issued_at");

-- CreateIndex
CREATE INDEX "osv_listing_provider_contact_consumed_run_idx"
  ON "osv_listing_provider_contact_authorization"("consumed_by_synchronization_run_id");

-- CreateIndex
CREATE INDEX "osv_listing_provider_contact_revoker_idx"
  ON "osv_listing_provider_contact_authorization"("revoked_by_operator_identity_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_listing_provider_contact_source_uidx"
  ON "osv_listing_provider_contact_authorization"("source_canary_authorization_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_listing_provider_contact_request_uidx"
  ON "osv_listing_provider_contact_authorization"("synchronization_request_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_listing_provider_contact_run_uidx"
  ON "osv_listing_provider_contact_authorization"("synchronization_run_id");

-- CreateIndex
CREATE UNIQUE INDEX "osv_listing_provider_contact_preflight_uidx"
  ON "osv_listing_provider_contact_authorization"("preflight_evidence_id");

-- Partial unique: one consumed request may bind one provider-contact authorization.
CREATE UNIQUE INDEX "osv_listing_provider_contact_consumed_request_uidx"
  ON "osv_listing_provider_contact_authorization"("consumed_by_synchronization_request_id")
  WHERE "consumed_by_synchronization_request_id" IS NOT NULL;

-- Partial unique: one consumed run may bind one provider-contact authorization.
CREATE UNIQUE INDEX "osv_listing_provider_contact_consumed_run_uidx"
  ON "osv_listing_provider_contact_authorization"("consumed_by_synchronization_run_id")
  WHERE "consumed_by_synchronization_run_id" IS NOT NULL;

-- AddForeignKey
ALTER TABLE "osv_canary_provider_free_preflight_attestation"
  ADD CONSTRAINT "osv_canary_provider_free_preflight_source_fkey"
  FOREIGN KEY ("source_canary_authorization_id")
  REFERENCES "osv_canary_authorization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_canary_provider_free_preflight_attestation"
  ADD CONSTRAINT "osv_canary_provider_free_preflight_operator_fkey"
  FOREIGN KEY ("operator_identity_id")
  REFERENCES "osv_canary_instance_operator_identity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_canary_provider_free_preflight_attestation"
  ADD CONSTRAINT "osv_canary_provider_free_preflight_request_fkey"
  FOREIGN KEY (
    "synchronization_request_id",
    "work_scope",
    "synchronization_reason",
    "runtime_version_set_fingerprint",
    "lease_scope"
  )
  REFERENCES "osv_runtime_synchronization_request"(
    "id",
    "work_scope",
    "synchronization_reason",
    "version_set_fingerprint",
    "lease_scope"
  ) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_canary_provider_free_preflight_attestation"
  ADD CONSTRAINT "osv_canary_provider_free_preflight_run_fkey"
  FOREIGN KEY ("synchronization_run_id", "synchronization_request_id")
  REFERENCES "osv_runtime_synchronization_run"("id", "request_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_source_fkey"
  FOREIGN KEY ("source_canary_authorization_id")
  REFERENCES "osv_canary_authorization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_operator_fkey"
  FOREIGN KEY ("operator_identity_id")
  REFERENCES "osv_canary_instance_operator_identity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_revoker_fkey"
  FOREIGN KEY ("revoked_by_operator_identity_id")
  REFERENCES "osv_canary_instance_operator_identity"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_preflight_fkey"
  FOREIGN KEY ("preflight_evidence_id")
  REFERENCES "osv_canary_provider_free_preflight_attestation"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_request_fkey"
  FOREIGN KEY (
    "synchronization_request_id",
    "work_scope",
    "synchronization_reason",
    "runtime_version_set_fingerprint",
    "lease_scope"
  )
  REFERENCES "osv_runtime_synchronization_request"(
    "id",
    "work_scope",
    "synchronization_reason",
    "version_set_fingerprint",
    "lease_scope"
  ) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_run_fkey"
  FOREIGN KEY ("synchronization_run_id", "synchronization_request_id")
  REFERENCES "osv_runtime_synchronization_run"("id", "request_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_consumed_request_fkey"
  FOREIGN KEY (
    "consumed_by_synchronization_request_id",
    "work_scope",
    "synchronization_reason",
    "runtime_version_set_fingerprint",
    "lease_scope"
  )
  REFERENCES "osv_runtime_synchronization_request"(
    "id",
    "work_scope",
    "synchronization_reason",
    "version_set_fingerprint",
    "lease_scope"
  ) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_consumed_run_fkey"
  FOREIGN KEY (
    "consumed_by_synchronization_run_id",
    "consumed_by_synchronization_request_id"
  )
  REFERENCES "osv_runtime_synchronization_run"("id", "request_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_canary_provider_free_preflight_attestation"
  ADD CONSTRAINT "osv_canary_provider_free_preflight_uuid_v4_chk"
  CHECK (
    "id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "source_canary_authorization_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "operator_identity_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "synchronization_request_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "synchronization_run_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "active_pointer_baseline_identity"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "zero_finding_baseline_identity"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "id" <> "source_canary_authorization_id"
    AND "id" <> "operator_identity_id"
    AND "id" <> "synchronization_request_id"
    AND "id" <> "synchronization_run_id"
    AND "synchronization_request_id" <> "synchronization_run_id"
    AND "active_pointer_baseline_identity" <> "zero_finding_baseline_identity"
  );

ALTER TABLE "osv_canary_provider_free_preflight_attestation"
  ADD CONSTRAINT "osv_canary_provider_free_preflight_policy_chk"
  CHECK (
    "evidence_schema_version" = 'osv_canary_provider_free_preflight_attestation_v1'
    AND "phase" = 'listing_only'
    AND "provider_identity" = 'rustsec_advisory_database'
    AND "approved_prefix" = 'crates.io/'
    AND "canary_policy_identifier" = 'osv_disabled_first_provider_canary_policy_v1'
    AND "listing_budget_profile" = 'osv_canary_listing_only_budget_v1'
    AND "work_scope" = 'osv_runtime_canary_scope_crates_io_rustsec_v1'
    AND "lease_scope" = 'osv_runtime_lease_scope_osv_gcs_public_export_v1'
    AND "synchronization_reason" = 'operator_canary'
    AND char_length("runtime_version_set_fingerprint") = 64
    AND "runtime_version_set_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "legal_decision_version" = 'osv_listing_provider_contact_legal_approval_v1'
    AND "egress_evidence_version" = 'osv_listing_provider_contact_egress_evidence_v1'
    AND "heartbeat_policy_identifier" = 'osv_canary_runtime_controls_v1'
    AND "deadline_policy_identifier" = 'osv_canary_runtime_controls_v1'
    AND "outcome" = 'canary_execution_preflight_passed_provider_contact_not_authorized'
    AND "provider_contact_authorized" = FALSE
    AND "execution_permitted" = FALSE
    AND "accepted_for_provider_contact_authorization" = TRUE
    AND "created_at" >= "captured_at"
  );

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_uuid_v4_chk"
  CHECK (
    "id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "source_canary_authorization_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "operator_identity_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "synchronization_request_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "synchronization_run_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "preflight_evidence_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "legal_decision_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "source_canary_legal_decision_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "legal_evidence_set_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "egress_evidence_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "deployment_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "active_pointer_baseline_identity"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "zero_finding_baseline_identity"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "id" <> "source_canary_authorization_id"
    AND "id" <> "operator_identity_id"
    AND "id" <> "synchronization_request_id"
    AND "id" <> "synchronization_run_id"
    AND "id" <> "preflight_evidence_id"
    AND "id" <> "legal_decision_id"
    AND "id" <> "deployment_id"
    AND "synchronization_request_id" <> "synchronization_run_id"
    AND "legal_decision_id" <> "source_canary_legal_decision_id"
    AND "active_pointer_baseline_identity" <> "zero_finding_baseline_identity"
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

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_policy_chk"
  CHECK (
    "authorization_schema_version" = 'osv_listing_only_provider_contact_authorization_v1'
    AND "phase" = 'listing_only'
    AND "provider_identity" = 'rustsec_advisory_database'
    AND "bucket_identity" = 'osv-vulnerabilities'
    AND "listing_api_path_policy" = '/storage/v1/b/osv-vulnerabilities/o'
    AND "listing_protocol" = 'osv_gcs_json_objects_list_v1'
    AND "approved_prefix" = 'crates.io/'
    AND "family" = 'RUSTSEC'
    AND "canary_policy_identifier" = 'osv_disabled_first_provider_canary_policy_v1'
    AND "listing_budget_profile" = 'osv_canary_listing_only_budget_v1'
    AND "work_scope" = 'osv_runtime_canary_scope_crates_io_rustsec_v1'
    AND "lease_scope" = 'osv_runtime_lease_scope_osv_gcs_public_export_v1'
    AND "synchronization_reason" = 'operator_canary'
    AND "runtime_architecture_identifier" = 'osv_runtime_enablement_architecture_v1'
    AND char_length("runtime_version_set_fingerprint") = 64
    AND "runtime_version_set_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "query_grammar_policy" = 'committed'
    AND "transport_policy" = 'osv_transport_policy_v1'
    AND "content_encoding_policy" = 'identity'
    AND "redirect_policy" = 'error'
    AND "unused_ttl_seconds" = 3600
    AND "single_use_policy" = 'single_use'
    AND "provider_retry_authorization" = 'prohibited'
    AND "provider_body_authorization" = 'prohibited'
    AND "parser_authorization" = 'prohibited'
    AND "catalog_activation_authorization" = 'prohibited'
    AND "matching_authorization" = 'prohibited'
    AND "finding_authorization" = 'prohibited'
    AND "legal_approval_identifier" = 'osv_listing_provider_contact_legal_approval_v1'
    AND "legal_decision_source_registry_version" = 'osv_source_license_registry_v1'
    AND "legal_listing_metadata_permission" = 'approved'
    AND "legal_body_retrieval_permission" = 'prohibited'
    AND "legal_parsing_permission" = 'prohibited'
    AND "legal_matching_permission" = 'prohibited'
    AND "legal_approval_role" = 'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator'
    AND "legal_supersession_status" = 'current'
    AND "egress_evidence_identifier" = 'osv_listing_provider_contact_egress_evidence_v1'
    AND "egress_evidence_version" = 'osv_listing_provider_contact_egress_evidence_v1'
    AND "egress_reviewer_role" = 'instance_operator_deployment_reviewer'
    AND "provider_connectivity_exercised" = FALSE
    AND "deployment_approval_identifier" = 'osv_listing_provider_contact_deployment_approval_v1'
    AND "environment_class" = 'dedicated_instance_operator_process'
    AND char_length("runtime_artifact_version") BETWEEN 8 AND 128
    AND "runtime_artifact_version" ~ '^[A-Za-z0-9][A-Za-z0-9._+-]*$'
    AND char_length("configuration_fingerprint") = 64
    AND "configuration_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "observability_policy" = 'osv_listing_provider_contact_observability_policy_v1'
    AND "deployment_approval_role" = 'instance_operator_deployment_reviewer'
    AND "invalidates_on_deployment_change" = TRUE
    AND "heartbeat_policy_identifier" = 'osv_canary_runtime_controls_v1'
    AND "deadline_policy_identifier" = 'osv_canary_runtime_controls_v1'
    AND "runbook_set_identifier" = 'osv_listing_provider_contact_runbook_set_v1'
    AND "runbook_version" = 'osv_listing_provider_contact_runbook_v1'
    AND "halt_procedure_identifier" = 'osv_listing_provider_contact_halt_procedure_v1'
    AND "containment_catalog_identifier" = 'osv_listing_provider_contact_emergency_containment_v1'
    AND "postcanary_review_policy_identifier" = 'osv_listing_provider_contact_postcanary_review_v1'
    AND "required_review_role" = 'instance_canary_evidence_reviewer'
    AND "issuing_operator_may_review" = FALSE
    AND "automatic_progression" = FALSE
    AND "evidence_retention_policy_identifier" = 'osv_listing_provider_contact_retention_disposition_v1'
  );

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_ttl_chk"
  CHECK (
    "expires_at" = "issued_at" + INTERVAL '3600 seconds'
    AND "created_at" >= "issued_at"
    AND "runbook_acknowledged_at" <= "issued_at"
    AND "halt_acknowledged_at" <= "issued_at"
    AND "containment_acknowledged_at" <= "issued_at"
    AND "retention_acknowledged_at" <= "issued_at"
    AND "reviewer_assigned_at" <= "issued_at"
    AND "legal_issued_at" <= "issued_at"
    AND "legal_revalidation_boundary_at" >= "legal_issued_at"
    AND "egress_reviewed_at" <= "issued_at"
    AND "deployment_approved_at" <= "issued_at"
  );

ALTER TABLE "osv_listing_provider_contact_authorization"
  ADD CONSTRAINT "osv_listing_provider_contact_state_chk"
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
      "state" = 'consumed_for_listing_execution'
      AND "consumed_at" IS NOT NULL
      AND "consumed_at" >= "issued_at"
      AND "consumed_at" < "expires_at"
      AND "consumed_by_synchronization_request_id" IS NOT NULL
      AND "consumed_by_synchronization_run_id" IS NOT NULL
      AND "consumed_by_synchronization_request_id" = "synchronization_request_id"
      AND "consumed_by_synchronization_run_id" = "synchronization_run_id"
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
      AND "consumed_by_synchronization_request_id" = "synchronization_request_id"
      AND "consumed_by_synchronization_run_id" = "synchronization_run_id"
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
      AND "consumed_by_synchronization_request_id" = "synchronization_request_id"
      AND "consumed_by_synchronization_run_id" = "synchronization_run_id"
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
          AND "consumed_by_synchronization_request_id" = "synchronization_request_id"
          AND "consumed_by_synchronization_run_id" = "synchronization_run_id"
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

CREATE FUNCTION patchpilot_osv_listing_provider_contact_source()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  source_phase osv_canary_phase;
  source_state osv_canary_authorization_state;
  source_operator uuid;
  source_request uuid;
  source_run uuid;
  source_fingerprint text;
  source_provider text;
  source_prefix text;
  source_policy text;
  source_budget text;
  operator_status osv_canary_operator_identity_status;
BEGIN
  SELECT status
  INTO operator_status
  FROM osv_canary_instance_operator_identity
  WHERE id = NEW.operator_identity_id
  FOR SHARE;
  IF NOT FOUND OR operator_status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'osv listing provider-contact operator must be active'
      USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT
    phase,
    state,
    operator_identity_id,
    consumed_by_synchronization_request_id,
    consumed_by_synchronization_run_id,
    runtime_version_set_fingerprint,
    source_identifier,
    provider_prefix,
    canary_policy_identifier,
    budget_profile_identifier
  INTO
    source_phase,
    source_state,
    source_operator,
    source_request,
    source_run,
    source_fingerprint,
    source_provider,
    source_prefix,
    source_policy,
    source_budget
  FROM osv_canary_authorization
  WHERE id = NEW.source_canary_authorization_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'osv listing provider-contact source authorization is missing'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_phase IS DISTINCT FROM 'listing_only' THEN
    RAISE EXCEPTION 'osv listing provider-contact source must be listing_only'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_state IS DISTINCT FROM 'consumed' THEN
    RAISE EXCEPTION 'osv listing provider-contact source must be consumed'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_operator IS DISTINCT FROM NEW.operator_identity_id THEN
    RAISE EXCEPTION 'osv listing provider-contact operator must match the source authorization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_request IS DISTINCT FROM NEW.synchronization_request_id
     OR source_run IS DISTINCT FROM NEW.synchronization_run_id THEN
    RAISE EXCEPTION 'osv listing provider-contact request and run must match the consumed source'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_fingerprint IS DISTINCT FROM NEW.runtime_version_set_fingerprint THEN
    RAISE EXCEPTION 'osv listing provider-contact version-set fingerprint must match the source'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_provider IS DISTINCT FROM NEW.provider_identity
     OR source_prefix IS DISTINCT FROM NEW.approved_prefix
     OR source_policy IS DISTINCT FROM NEW.canary_policy_identifier
     OR source_budget IS DISTINCT FROM NEW.listing_budget_profile THEN
    RAISE EXCEPTION 'osv listing provider-contact source identity must match the attestation'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_osv_provider_free_preflight_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.captured_at > CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'osv provider-free preflight captured_at cannot be after database now'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.created_at > CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'osv provider-free preflight created_at cannot be after database now'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.provider_contact_authorized IS DISTINCT FROM FALSE
     OR NEW.accepted_for_provider_contact_authorization IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'osv provider-free preflight must attest unauthorized provider contact'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_protect_osv_provider_free_preflight()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  RAISE EXCEPTION 'osv provider-free preflight attestation is immutable'
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE FUNCTION patchpilot_osv_listing_provider_contact_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  preflight osv_canary_provider_free_preflight_attestation%ROWTYPE;
  source_phase osv_canary_phase;
  source_state osv_canary_authorization_state;
  source_operator uuid;
  source_request uuid;
  source_run uuid;
  source_fingerprint text;
  source_legal uuid;
  source_provider text;
  source_prefix text;
  source_family text;
  source_policy text;
  source_budget text;
  operator_status osv_canary_operator_identity_status;
BEGIN
  IF NEW.state IS DISTINCT FROM 'issued' THEN
    RAISE EXCEPTION 'osv listing provider-contact authorization must be inserted as issued'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.issued_at > CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'osv listing provider-contact issued_at cannot be after database now'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.created_at > CURRENT_TIMESTAMP THEN
    RAISE EXCEPTION 'osv listing provider-contact created_at cannot be after database now'
      USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT status
  INTO operator_status
  FROM osv_canary_instance_operator_identity
  WHERE id = NEW.operator_identity_id
  FOR SHARE;
  IF NOT FOUND OR operator_status IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'osv listing provider-contact operator must be active'
      USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT
    phase,
    state,
    operator_identity_id,
    consumed_by_synchronization_request_id,
    consumed_by_synchronization_run_id,
    runtime_version_set_fingerprint,
    legal_decision_id,
    source_identifier,
    provider_prefix,
    family,
    canary_policy_identifier,
    budget_profile_identifier
  INTO
    source_phase,
    source_state,
    source_operator,
    source_request,
    source_run,
    source_fingerprint,
    source_legal,
    source_provider,
    source_prefix,
    source_family,
    source_policy,
    source_budget
  FROM osv_canary_authorization
  WHERE id = NEW.source_canary_authorization_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'osv listing provider-contact source authorization is missing'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_phase IS DISTINCT FROM 'listing_only' THEN
    RAISE EXCEPTION 'osv listing provider-contact source must be listing_only'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_state IS DISTINCT FROM 'consumed' THEN
    RAISE EXCEPTION 'osv listing provider-contact source must be consumed'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_operator IS DISTINCT FROM NEW.operator_identity_id THEN
    RAISE EXCEPTION 'osv listing provider-contact operator must match the source authorization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_request IS DISTINCT FROM NEW.synchronization_request_id
     OR source_run IS DISTINCT FROM NEW.synchronization_run_id THEN
    RAISE EXCEPTION 'osv listing provider-contact request and run must match the consumed source'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_fingerprint IS DISTINCT FROM NEW.runtime_version_set_fingerprint THEN
    RAISE EXCEPTION 'osv listing provider-contact version-set fingerprint must match the source'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_legal IS DISTINCT FROM NEW.source_canary_legal_decision_id THEN
    RAISE EXCEPTION 'osv listing provider-contact legal reference must match the source'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF source_provider IS DISTINCT FROM NEW.provider_identity
     OR source_prefix IS DISTINCT FROM NEW.approved_prefix
     OR source_family IS DISTINCT FROM NEW.family
     OR source_policy IS DISTINCT FROM NEW.canary_policy_identifier
     OR source_budget IS DISTINCT FROM NEW.listing_budget_profile THEN
    RAISE EXCEPTION 'osv listing provider-contact source identity must match the authorization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT *
  INTO preflight
  FROM osv_canary_provider_free_preflight_attestation
  WHERE id = NEW.preflight_evidence_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'osv listing provider-contact preflight evidence is missing'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.issued_at < preflight.captured_at THEN
    RAISE EXCEPTION 'osv listing provider-contact issued_at cannot precede preflight captured_at'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF preflight.source_canary_authorization_id IS DISTINCT FROM NEW.source_canary_authorization_id
     OR preflight.operator_identity_id IS DISTINCT FROM NEW.operator_identity_id
     OR preflight.synchronization_request_id IS DISTINCT FROM NEW.synchronization_request_id
     OR preflight.synchronization_run_id IS DISTINCT FROM NEW.synchronization_run_id
     OR preflight.runtime_version_set_fingerprint IS DISTINCT FROM NEW.runtime_version_set_fingerprint
     OR preflight.active_pointer_baseline_identity IS DISTINCT FROM NEW.active_pointer_baseline_identity
     OR preflight.zero_finding_baseline_identity IS DISTINCT FROM NEW.zero_finding_baseline_identity
     OR preflight.legal_decision_version IS DISTINCT FROM NEW.legal_approval_identifier
     OR preflight.egress_evidence_version IS DISTINCT FROM NEW.egress_evidence_version
     OR preflight.heartbeat_policy_identifier IS DISTINCT FROM NEW.heartbeat_policy_identifier
     OR preflight.deadline_policy_identifier IS DISTINCT FROM NEW.deadline_policy_identifier
     OR preflight.phase IS DISTINCT FROM NEW.phase
     OR preflight.provider_identity IS DISTINCT FROM NEW.provider_identity
     OR preflight.approved_prefix IS DISTINCT FROM NEW.approved_prefix
     OR preflight.canary_policy_identifier IS DISTINCT FROM NEW.canary_policy_identifier
     OR preflight.listing_budget_profile IS DISTINCT FROM NEW.listing_budget_profile
     OR preflight.work_scope IS DISTINCT FROM NEW.work_scope
     OR preflight.lease_scope IS DISTINCT FROM NEW.lease_scope
     OR preflight.synchronization_reason IS DISTINCT FROM NEW.synchronization_reason
     OR preflight.provider_contact_authorized IS DISTINCT FROM FALSE
     OR preflight.execution_permitted IS DISTINCT FROM FALSE
     OR preflight.accepted_for_provider_contact_authorization IS DISTINCT FROM TRUE THEN
    RAISE EXCEPTION 'osv listing provider-contact preflight evidence does not match'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_protect_osv_listing_provider_contact()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.authorization_schema_version IS DISTINCT FROM OLD.authorization_schema_version
     OR NEW.source_canary_authorization_id IS DISTINCT FROM OLD.source_canary_authorization_id
     OR NEW.operator_identity_id IS DISTINCT FROM OLD.operator_identity_id
     OR NEW.synchronization_request_id IS DISTINCT FROM OLD.synchronization_request_id
     OR NEW.synchronization_run_id IS DISTINCT FROM OLD.synchronization_run_id
     OR NEW.preflight_evidence_id IS DISTINCT FROM OLD.preflight_evidence_id
     OR NEW.phase IS DISTINCT FROM OLD.phase
     OR NEW.provider_identity IS DISTINCT FROM OLD.provider_identity
     OR NEW.bucket_identity IS DISTINCT FROM OLD.bucket_identity
     OR NEW.listing_api_path_policy IS DISTINCT FROM OLD.listing_api_path_policy
     OR NEW.listing_protocol IS DISTINCT FROM OLD.listing_protocol
     OR NEW.approved_prefix IS DISTINCT FROM OLD.approved_prefix
     OR NEW.family IS DISTINCT FROM OLD.family
     OR NEW.canary_policy_identifier IS DISTINCT FROM OLD.canary_policy_identifier
     OR NEW.listing_budget_profile IS DISTINCT FROM OLD.listing_budget_profile
     OR NEW.work_scope IS DISTINCT FROM OLD.work_scope
     OR NEW.lease_scope IS DISTINCT FROM OLD.lease_scope
     OR NEW.synchronization_reason IS DISTINCT FROM OLD.synchronization_reason
     OR NEW.runtime_architecture_identifier IS DISTINCT FROM OLD.runtime_architecture_identifier
     OR NEW.runtime_version_set_fingerprint IS DISTINCT FROM OLD.runtime_version_set_fingerprint
     OR NEW.query_grammar_policy IS DISTINCT FROM OLD.query_grammar_policy
     OR NEW.transport_policy IS DISTINCT FROM OLD.transport_policy
     OR NEW.content_encoding_policy IS DISTINCT FROM OLD.content_encoding_policy
     OR NEW.redirect_policy IS DISTINCT FROM OLD.redirect_policy
     OR NEW.unused_ttl_seconds IS DISTINCT FROM OLD.unused_ttl_seconds
     OR NEW.single_use_policy IS DISTINCT FROM OLD.single_use_policy
     OR NEW.provider_retry_authorization IS DISTINCT FROM OLD.provider_retry_authorization
     OR NEW.provider_body_authorization IS DISTINCT FROM OLD.provider_body_authorization
     OR NEW.parser_authorization IS DISTINCT FROM OLD.parser_authorization
     OR NEW.catalog_activation_authorization IS DISTINCT FROM OLD.catalog_activation_authorization
     OR NEW.matching_authorization IS DISTINCT FROM OLD.matching_authorization
     OR NEW.finding_authorization IS DISTINCT FROM OLD.finding_authorization
     OR NEW.legal_approval_identifier IS DISTINCT FROM OLD.legal_approval_identifier
     OR NEW.legal_decision_id IS DISTINCT FROM OLD.legal_decision_id
     OR NEW.source_canary_legal_decision_id IS DISTINCT FROM OLD.source_canary_legal_decision_id
     OR NEW.legal_decision_source_registry_version IS DISTINCT FROM OLD.legal_decision_source_registry_version
     OR NEW.legal_listing_metadata_permission IS DISTINCT FROM OLD.legal_listing_metadata_permission
     OR NEW.legal_body_retrieval_permission IS DISTINCT FROM OLD.legal_body_retrieval_permission
     OR NEW.legal_parsing_permission IS DISTINCT FROM OLD.legal_parsing_permission
     OR NEW.legal_matching_permission IS DISTINCT FROM OLD.legal_matching_permission
     OR NEW.legal_issued_at IS DISTINCT FROM OLD.legal_issued_at
     OR NEW.legal_revalidation_boundary_at IS DISTINCT FROM OLD.legal_revalidation_boundary_at
     OR NEW.legal_evidence_set_id IS DISTINCT FROM OLD.legal_evidence_set_id
     OR NEW.legal_approval_role IS DISTINCT FROM OLD.legal_approval_role
     OR NEW.legal_supersession_status IS DISTINCT FROM OLD.legal_supersession_status
     OR NEW.egress_evidence_identifier IS DISTINCT FROM OLD.egress_evidence_identifier
     OR NEW.egress_evidence_id IS DISTINCT FROM OLD.egress_evidence_id
     OR NEW.egress_evidence_version IS DISTINCT FROM OLD.egress_evidence_version
     OR NEW.egress_reviewer_role IS DISTINCT FROM OLD.egress_reviewer_role
     OR NEW.egress_reviewed_at IS DISTINCT FROM OLD.egress_reviewed_at
     OR NEW.provider_connectivity_exercised IS DISTINCT FROM OLD.provider_connectivity_exercised
     OR NEW.deployment_approval_identifier IS DISTINCT FROM OLD.deployment_approval_identifier
     OR NEW.deployment_id IS DISTINCT FROM OLD.deployment_id
     OR NEW.environment_class IS DISTINCT FROM OLD.environment_class
     OR NEW.runtime_artifact_version IS DISTINCT FROM OLD.runtime_artifact_version
     OR NEW.configuration_fingerprint IS DISTINCT FROM OLD.configuration_fingerprint
     OR NEW.observability_policy IS DISTINCT FROM OLD.observability_policy
     OR NEW.deployment_approval_role IS DISTINCT FROM OLD.deployment_approval_role
     OR NEW.deployment_approved_at IS DISTINCT FROM OLD.deployment_approved_at
     OR NEW.invalidates_on_deployment_change IS DISTINCT FROM OLD.invalidates_on_deployment_change
     OR NEW.heartbeat_policy_identifier IS DISTINCT FROM OLD.heartbeat_policy_identifier
     OR NEW.deadline_policy_identifier IS DISTINCT FROM OLD.deadline_policy_identifier
     OR NEW.runbook_set_identifier IS DISTINCT FROM OLD.runbook_set_identifier
     OR NEW.runbook_version IS DISTINCT FROM OLD.runbook_version
     OR NEW.runbook_acknowledged_at IS DISTINCT FROM OLD.runbook_acknowledged_at
     OR NEW.halt_procedure_identifier IS DISTINCT FROM OLD.halt_procedure_identifier
     OR NEW.halt_acknowledged_at IS DISTINCT FROM OLD.halt_acknowledged_at
     OR NEW.containment_catalog_identifier IS DISTINCT FROM OLD.containment_catalog_identifier
     OR NEW.containment_acknowledged_at IS DISTINCT FROM OLD.containment_acknowledged_at
     OR NEW.postcanary_review_policy_identifier IS DISTINCT FROM OLD.postcanary_review_policy_identifier
     OR NEW.required_review_role IS DISTINCT FROM OLD.required_review_role
     OR NEW.reviewer_assigned_at IS DISTINCT FROM OLD.reviewer_assigned_at
     OR NEW.issuing_operator_may_review IS DISTINCT FROM OLD.issuing_operator_may_review
     OR NEW.automatic_progression IS DISTINCT FROM OLD.automatic_progression
     OR NEW.evidence_retention_policy_identifier IS DISTINCT FROM OLD.evidence_retention_policy_identifier
     OR NEW.retention_acknowledged_at IS DISTINCT FROM OLD.retention_acknowledged_at
     OR NEW.active_pointer_baseline_identity IS DISTINCT FROM OLD.active_pointer_baseline_identity
     OR NEW.zero_finding_baseline_identity IS DISTINCT FROM OLD.zero_finding_baseline_identity
     OR NEW.issued_at IS DISTINCT FROM OLD.issued_at
     OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'osv listing provider-contact immutable fields cannot change'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state IN ('completed', 'failed', 'cancelled', 'revoked', 'expired') THEN
    RAISE EXCEPTION 'osv listing provider-contact terminal authorization is immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'issued'
     AND NEW.state = 'consumed_for_listing_execution'
     AND CURRENT_TIMESTAMP >= OLD.expires_at THEN
    RAISE EXCEPTION 'osv listing provider-contact authorization is expired and cannot be consumed'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'issued' AND NEW.state = 'consumed_for_listing_execution' THEN
    IF CURRENT_TIMESTAMP < OLD.issued_at THEN
      RAISE EXCEPTION 'osv listing provider-contact authorization is not yet valid'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.consumed_at IS NOT NULL AND NEW.consumed_at > CURRENT_TIMESTAMP THEN
      RAISE EXCEPTION 'osv listing provider-contact consumed_at cannot be after database now'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF CURRENT_TIMESTAMP >= OLD.legal_revalidation_boundary_at THEN
      RAISE EXCEPTION 'osv listing provider-contact legal approval is expired'
        USING ERRCODE = 'restrict_violation';
    END IF;
    DECLARE
      source_state osv_canary_authorization_state;
      operator_status osv_canary_operator_identity_status;
      preflight_authorized boolean;
      preflight_accepted boolean;
    BEGIN
      SELECT status
      INTO operator_status
      FROM osv_canary_instance_operator_identity
      WHERE id = OLD.operator_identity_id
      FOR SHARE;
      IF NOT FOUND OR operator_status IS DISTINCT FROM 'active' THEN
        RAISE EXCEPTION 'osv listing provider-contact operator must be active'
          USING ERRCODE = 'restrict_violation';
      END IF;
      SELECT state
      INTO source_state
      FROM osv_canary_authorization
      WHERE id = OLD.source_canary_authorization_id
      FOR SHARE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'osv listing provider-contact source authorization is missing'
          USING ERRCODE = 'restrict_violation';
      END IF;
      IF source_state IS DISTINCT FROM 'consumed' THEN
        RAISE EXCEPTION 'osv listing provider-contact source must remain consumed'
          USING ERRCODE = 'restrict_violation';
      END IF;
      SELECT provider_contact_authorized, accepted_for_provider_contact_authorization
      INTO preflight_authorized, preflight_accepted
      FROM osv_canary_provider_free_preflight_attestation
      WHERE id = OLD.preflight_evidence_id
      FOR SHARE;
      IF NOT FOUND
         OR preflight_authorized IS DISTINCT FROM FALSE
         OR preflight_accepted IS DISTINCT FROM TRUE THEN
        RAISE EXCEPTION 'osv listing provider-contact preflight evidence does not match'
          USING ERRCODE = 'restrict_violation';
      END IF;
    END;
  END IF;
  IF OLD.state = 'issued' AND NEW.state = 'revoked' AND CURRENT_TIMESTAMP >= OLD.expires_at THEN
    RAISE EXCEPTION 'osv listing provider-contact authorization is expired and cannot be revoked'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'issued' AND NEW.state = 'expired' AND CURRENT_TIMESTAMP < OLD.expires_at THEN
    RAISE EXCEPTION 'osv listing provider-contact authorization is not expired'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'issued'
     AND NEW.state NOT IN (
       'issued',
       'consumed_for_listing_execution',
       'revoked',
       'expired',
       'cancelled'
     ) THEN
    RAISE EXCEPTION 'invalid osv listing provider-contact issued authorization transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'consumed_for_listing_execution'
     AND NEW.state NOT IN (
       'consumed_for_listing_execution',
       'completed',
       'failed',
       'cancelled'
     ) THEN
    RAISE EXCEPTION 'invalid osv listing provider-contact consumed authorization transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.state = 'consumed_for_listing_execution'
     AND NEW.state = 'consumed_for_listing_execution' THEN
    IF NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
       OR NEW.consumed_by_synchronization_request_id IS DISTINCT FROM OLD.consumed_by_synchronization_request_id
       OR NEW.consumed_by_synchronization_run_id IS DISTINCT FROM OLD.consumed_by_synchronization_run_id THEN
      RAISE EXCEPTION 'osv listing provider-contact consumption binding is immutable'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_protect_osv_canary_authorization_provider_contact_lineage()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.state = 'consumed' AND NEW.state IS DISTINCT FROM 'consumed' THEN
    IF EXISTS (
      SELECT 1
      FROM osv_listing_provider_contact_authorization
      WHERE source_canary_authorization_id = OLD.id
        AND state IN ('issued', 'consumed_for_listing_execution')
    ) THEN
      RAISE EXCEPTION 'osv canary authorization cannot leave consumed while a listing provider-contact authorization is outstanding'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER osv_canary_provider_free_preflight_insert_source
  BEFORE INSERT ON "osv_canary_provider_free_preflight_attestation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_provider_contact_source();

CREATE TRIGGER osv_canary_provider_free_preflight_insert_attestation
  BEFORE INSERT ON "osv_canary_provider_free_preflight_attestation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_provider_free_preflight_insert();

CREATE TRIGGER osv_canary_provider_free_preflight_delete_forbidden
  BEFORE DELETE ON "osv_canary_provider_free_preflight_attestation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_canary_provider_free_preflight_immutable
  BEFORE UPDATE ON "osv_canary_provider_free_preflight_attestation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_provider_free_preflight();

CREATE TRIGGER osv_listing_provider_contact_insert_issued
  BEFORE INSERT ON "osv_listing_provider_contact_authorization"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_provider_contact_insert();

CREATE TRIGGER osv_listing_provider_contact_delete_forbidden
  BEFORE DELETE ON "osv_listing_provider_contact_authorization"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_listing_provider_contact_lifecycle
  BEFORE UPDATE ON "osv_listing_provider_contact_authorization"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_listing_provider_contact();

CREATE TRIGGER osv_canary_authorization_provider_contact_lineage
  BEFORE UPDATE ON "osv_canary_authorization"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_canary_authorization_provider_contact_lineage();
