-- Session 13 Batch 3D-S: protected OSV listing-observation evidence
-- persistence. Forward-only. Does not edit
-- 20260826120000_schema_foundation through
-- 20260909120000_osv_listing_provider_contact_authorization_persistence.
-- New enums, tables, check constraints, unique indexes, foreign keys,
-- and mutation-guard triggers only. No ALTER TYPE ADD VALUE on existing
-- enums. No seed rows. No tenant rows. No Finding rows. No active catalog
-- seed. No plaintext provider identity. No encryption keys. No ciphertext
-- seed. No credentials, page tokens, provider bodies, URLs, or arbitrary
-- JSON. All new foreign keys are ON DELETE RESTRICT. Schema only; no
-- encryption implementation, persistence adapter, CLI, or provider contact.
-- Schema existence does not encrypt, decrypt, or retain real observations.
-- Session 13 Batch 3D-S-R: legal hold blocks envelope cryptographic
-- erasure; deferred exactly-one-current envelope unless the observation
-- is fully erased; failed is successor-only on evidence-set insert.

-- CreateEnum
CREATE TYPE "osv_listing_observation_evidence_set_state" AS ENUM (
  'constructed',
  'incomplete',
  'overflow_rejected',
  'conflict_quarantine_required',
  'duplicate_ambiguous',
  'malformed_rejected',
  'review_pending',
  'review_accepted',
  'review_rejected',
  'failed',
  'purged'
);

CREATE TYPE "osv_listing_observation_set_candidate_readiness" AS ENUM (
  'metadata_complete_selection_not_authorized',
  'empty_page_not_candidate_ready',
  'ineligible_incomplete',
  'ineligible_overflow',
  'ineligible_conflict',
  'ineligible_duplicate_ambiguity',
  'ineligible_binding_mismatch',
  'review_not_accepted'
);

CREATE TYPE "osv_listing_observation_candidate_selection_eligibility" AS ENUM (
  'eligible_for_later_selection_evaluation',
  'ineligible_unknown_or_ambiguous_family',
  'ineligible_unclassifiable_family',
  'ineligible_declared_size',
  'ineligible_missing_protected_identity',
  'ineligible_missing_generation',
  'ineligible_duplicate',
  'ineligible_conflict',
  'ineligible_set_incomplete'
);

CREATE TYPE "osv_listing_observation_duplicate_classification" AS ENUM (
  'none',
  'exact_duplicate',
  'duplicate_across_translator_positions',
  'malformed_duplicate'
);

CREATE TYPE "osv_listing_observation_immutable_conflict_classification" AS ENUM (
  'none',
  'declared_size_mismatch_same_object_generation',
  'source_family_mismatch_same_object_generation',
  'classification_mismatch_same_object_generation',
  'binding_mismatch_same_object_generation',
  'provider_key_digest_collision',
  'cross_object_generation_substitution'
);

CREATE TYPE "osv_listing_observation_legal_hold_classification" AS ENUM (
  'hold_absent',
  'legal_hold_active',
  'hold_released'
);

CREATE TYPE "osv_listing_observation_retention_overdue_classification" AS ENUM (
  'not_overdue',
  'retention_overdue_review_required_no_automatic_delete'
);

CREATE TYPE "osv_listing_observation_envelope_state" AS ENUM (
  'current',
  'rotation_pending',
  'decrypt_only',
  'rotation_required',
  'retired',
  'failed',
  'erased'
);

CREATE TYPE "osv_listing_observation_envelope_rotation_state" AS ENUM (
  'current',
  'rotation_required',
  'rotated',
  'not_applicable_policy_only'
);

CREATE TYPE "osv_listing_observation_envelope_erasure_state" AS ENUM (
  'not_erased',
  'erasure_eligible',
  'cryptographically_erased',
  'erasure_blocked'
);

CREATE TYPE "osv_listing_observation_key_version_classification" AS ENUM (
  'current',
  'historical'
);

CREATE TYPE "osv_listing_observation_purge_erasure_outcome" AS ENUM (
  'envelopes_redacted_metadata_retained',
  'blocked_legal_hold',
  'blocked_dependency_authorization',
  'blocked_cleanup_unauthorized',
  'already_erased_cannot_restore',
  'shared_key_collateral_erasure_rejected'
);

-- CreateTable
CREATE TABLE "osv_listing_observation_evidence_set" (
    "id" UUID NOT NULL,
    "evidence_schema_version" VARCHAR(128) NOT NULL,
    "evidence_policy_id" VARCHAR(128) NOT NULL,
    "purpose_id" VARCHAR(128) NOT NULL,
    "ownership" VARCHAR(64) NOT NULL,
    "listing_execution_id" UUID NOT NULL,
    "provider_contact_authorization_id" UUID NOT NULL,
    "synchronization_request_id" UUID NOT NULL,
    "synchronization_run_id" UUID NOT NULL,
    "provider" VARCHAR(32) NOT NULL,
    "approved_prefix" VARCHAR(32) NOT NULL,
    "listing_protocol_id" VARCHAR(128) NOT NULL,
    "listing_policy_id" VARCHAR(128) NOT NULL,
    "budget_profile_id" VARCHAR(128) NOT NULL,
    "work_scope" "osv_runtime_work_scope" NOT NULL,
    "lease_scope" VARCHAR(128) NOT NULL,
    "synchronization_reason" "osv_runtime_synchronization_reason" NOT NULL,
    "runtime_version_set_fingerprint" TEXT NOT NULL,
    "source_license_registry_version" VARCHAR(128) NOT NULL,
    "classification_policy_id" VARCHAR(128) NOT NULL,
    "canonical_evidence_set_algorithm_id" VARCHAR(128) NOT NULL,
    "encryption_policy_id" VARCHAR(128) NOT NULL,
    "associated_data_policy_id" VARCHAR(128) NOT NULL,
    "associated_data_algorithm_id" VARCHAR(128) NOT NULL,
    "envelope_schema_version" VARCHAR(128) NOT NULL,
    "algorithm_id" VARCHAR(32) NOT NULL,
    "retention_policy_id" VARCHAR(128) NOT NULL,
    "page_ordinal" INTEGER NOT NULL,
    "canonical_evidence_set_digest" TEXT NOT NULL,
    "translator_observation_count" INTEGER NOT NULL,
    "accepted_observation_count" INTEGER NOT NULL,
    "protected_observation_count" INTEGER NOT NULL,
    "rejected_observation_count" INTEGER NOT NULL,
    "exact_duplicate_count" INTEGER NOT NULL,
    "duplicate_ambiguity_count" INTEGER NOT NULL,
    "immutable_conflict_count" INTEGER NOT NULL,
    "total_protected_key_plaintext_bytes" BIGINT NOT NULL,
    "total_envelope_bytes" BIGINT NOT NULL,
    "total_canonical_bytes" BIGINT NOT NULL,
    "total_metadata_bytes" BIGINT NOT NULL,
    "event_count" INTEGER NOT NULL,
    "evidence_state" "osv_listing_observation_evidence_set_state" NOT NULL,
    "candidate_selection_readiness" "osv_listing_observation_set_candidate_readiness" NOT NULL,
    "retention_overdue_classification" "osv_listing_observation_retention_overdue_classification" NOT NULL,
    "legal_hold_active" BOOLEAN NOT NULL,
    "legal_hold_classification" "osv_listing_observation_legal_hold_classification" NOT NULL,
    "dependent_authorizations_terminal" BOOLEAN NOT NULL,
    "candidate_selection_authorized" BOOLEAN NOT NULL,
    "body_retrieval_authorized" BOOLEAN NOT NULL,
    "batch_4p_permitted" BOOLEAN NOT NULL,
    "pagination_authorized" BOOLEAN NOT NULL,
    "activation_authorized" BOOLEAN NOT NULL,
    "matching_authorized" BOOLEAN NOT NULL,
    "finding_writes_authorized" BOOLEAN NOT NULL,
    "provider_contact_authorized" BOOLEAN NOT NULL,
    "row_revision" BIGINT NOT NULL,
    "captured_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "review_recorded_at" TIMESTAMPTZ(6),
    "legal_hold_changed_at" TIMESTAMPTZ(6),
    "retention_overdue_at" TIMESTAMPTZ(6),
    "purged_at" TIMESTAMPTZ(6),

    CONSTRAINT "osv_listing_observation_evidence_set_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "osv_listing_observation_evidence" (
    "id" UUID NOT NULL,
    "evidence_set_id" UUID NOT NULL,
    "listing_execution_id" UUID NOT NULL,
    "provider_contact_authorization_id" UUID NOT NULL,
    "synchronization_request_id" UUID NOT NULL,
    "synchronization_run_id" UUID NOT NULL,
    "provider" VARCHAR(32) NOT NULL,
    "approved_prefix" VARCHAR(32) NOT NULL,
    "listing_protocol_id" VARCHAR(128) NOT NULL,
    "source_license_registry_version" VARCHAR(128) NOT NULL,
    "runtime_version_set_fingerprint" TEXT NOT NULL,
    "evidence_schema_version" VARCHAR(128) NOT NULL,
    "classification_policy_id" VARCHAR(128) NOT NULL,
    "observation_canonical_algorithm_id" VARCHAR(128) NOT NULL,
    "encryption_policy_id" VARCHAR(128) NOT NULL,
    "associated_data_policy_id" VARCHAR(128) NOT NULL,
    "associated_data_algorithm_id" VARCHAR(128) NOT NULL,
    "envelope_schema_version" VARCHAR(128) NOT NULL,
    "observation_ordinal" INTEGER NOT NULL,
    "listing_observation_identity" TEXT NOT NULL,
    "provider_generation" TEXT NOT NULL,
    "declared_listing_byte_count" BIGINT NOT NULL,
    "source_family_classification" VARCHAR(96) NOT NULL,
    "classification_status" "osv_classification_status" NOT NULL,
    "duplicate_classification" "osv_listing_observation_duplicate_classification" NOT NULL,
    "immutable_conflict_classification" "osv_listing_observation_immutable_conflict_classification" NOT NULL,
    "candidate_selection_eligibility" "osv_listing_observation_candidate_selection_eligibility" NOT NULL,
    "evidence_state" "osv_listing_observation_evidence_set_state" NOT NULL,
    "candidate_selection_authorized" BOOLEAN NOT NULL,
    "body_retrieval_authorized" BOOLEAN NOT NULL,
    "batch_4p_permitted" BOOLEAN NOT NULL,
    "plaintext_length_accounting" INTEGER NOT NULL,
    "row_revision" BIGINT NOT NULL,
    "captured_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_listing_observation_evidence_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "osv_listing_observation_evidence_envelope" (
    "id" UUID NOT NULL,
    "observation_id" UUID NOT NULL,
    "evidence_set_id" UUID NOT NULL,
    "provider_generation" TEXT NOT NULL,
    "declared_listing_byte_count" BIGINT NOT NULL,
    "source_family_classification" VARCHAR(96) NOT NULL,
    "classification_status" "osv_classification_status" NOT NULL,
    "envelope_ordinal" INTEGER NOT NULL,
    "envelope_schema_version" VARCHAR(128) NOT NULL,
    "cryptographic_policy_id" VARCHAR(128) NOT NULL,
    "algorithm_id" VARCHAR(32) NOT NULL,
    "associated_data_policy_id" VARCHAR(128) NOT NULL,
    "opaque_key_alias" VARCHAR(64) NOT NULL,
    "key_version_classification" "osv_listing_observation_key_version_classification" NOT NULL,
    "envelope_state" "osv_listing_observation_envelope_state" NOT NULL,
    "rotation_state" "osv_listing_observation_envelope_rotation_state" NOT NULL,
    "erasure_state" "osv_listing_observation_envelope_erasure_state" NOT NULL,
    "plaintext_length_accounting" INTEGER NOT NULL,
    "ciphertext_length_accounting" INTEGER NOT NULL,
    "protected_identity_envelope" BYTEA,
    "row_revision" BIGINT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotation_recorded_at" TIMESTAMPTZ(6),
    "erasure_attempted_at" TIMESTAMPTZ(6),
    "erasure_completed_at" TIMESTAMPTZ(6),

    CONSTRAINT "osv_listing_observation_evidence_envelope_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "osv_listing_observation_evidence_purge" (
    "id" UUID NOT NULL,
    "evidence_set_id" UUID NOT NULL,
    "purge_authorization_classification" VARCHAR(128) NOT NULL,
    "purge_reason_code" VARCHAR(64) NOT NULL,
    "legal_hold_decision" VARCHAR(64) NOT NULL,
    "dependent_authority_terminal_decision" VARCHAR(64) NOT NULL,
    "erasure_mechanism_classification" VARCHAR(128) NOT NULL,
    "erasure_outcome" "osv_listing_observation_purge_erasure_outcome" NOT NULL,
    "attempted_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completed_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "osv_listing_observation_evidence_purge_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "osv_listing_observation_evidence_set_execution_uidx"
  ON "osv_listing_observation_evidence_set"("listing_execution_id");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_set_authorization_uidx"
  ON "osv_listing_observation_evidence_set"("provider_contact_authorization_id");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_set_request_uidx"
  ON "osv_listing_observation_evidence_set"("synchronization_request_id");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_set_run_uidx"
  ON "osv_listing_observation_evidence_set"("synchronization_run_id");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_set_aad_pin"
  ON "osv_listing_observation_evidence_set"(
    "id",
    "listing_execution_id",
    "provider_contact_authorization_id",
    "synchronization_request_id",
    "synchronization_run_id",
    "provider",
    "approved_prefix",
    "listing_protocol_id",
    "source_license_registry_version",
    "runtime_version_set_fingerprint"
  );

CREATE INDEX "osv_listing_observation_evidence_set_state_idx"
  ON "osv_listing_observation_evidence_set"("evidence_state");

CREATE INDEX "osv_listing_observation_evidence_set_retention_idx"
  ON "osv_listing_observation_evidence_set"("retention_overdue_classification");

CREATE INDEX "osv_listing_observation_evidence_set_legal_hold_idx"
  ON "osv_listing_observation_evidence_set"("legal_hold_active");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_ordinal_uidx"
  ON "osv_listing_observation_evidence"("evidence_set_id", "observation_ordinal");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_canonical_uidx"
  ON "osv_listing_observation_evidence"("evidence_set_id", "listing_observation_identity");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_envelope_pin"
  ON "osv_listing_observation_evidence"(
    "id",
    "evidence_set_id",
    "provider_generation",
    "declared_listing_byte_count",
    "source_family_classification",
    "classification_status"
  );

CREATE UNIQUE INDEX "osv_listing_observation_evidence_envelope_ordinal_uidx"
  ON "osv_listing_observation_evidence_envelope"("observation_id", "envelope_ordinal");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_envelope_current_uidx"
  ON "osv_listing_observation_evidence_envelope"("observation_id")
  WHERE "envelope_state" = 'current';

CREATE UNIQUE INDEX "osv_listing_observation_evidence_envelope_pending_uidx"
  ON "osv_listing_observation_evidence_envelope"("observation_id")
  WHERE "envelope_state" = 'rotation_pending';

CREATE INDEX "osv_listing_observation_evidence_envelope_set_state_idx"
  ON "osv_listing_observation_evidence_envelope"("evidence_set_id", "envelope_state");

CREATE INDEX "osv_listing_observation_evidence_envelope_observation_state_idx"
  ON "osv_listing_observation_evidence_envelope"("observation_id", "envelope_state");

CREATE INDEX "osv_listing_observation_evidence_purge_set_idx"
  ON "osv_listing_observation_evidence_purge"("evidence_set_id");

CREATE UNIQUE INDEX "osv_listing_observation_evidence_purge_success_uidx"
  ON "osv_listing_observation_evidence_purge"("evidence_set_id")
  WHERE "erasure_outcome" = 'envelopes_redacted_metadata_retained';

-- AddForeignKey
ALTER TABLE "osv_listing_observation_evidence_set"
  ADD CONSTRAINT "osv_listing_observation_evidence_set_authorization_fkey"
  FOREIGN KEY ("provider_contact_authorization_id")
  REFERENCES "osv_listing_provider_contact_authorization"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_observation_evidence_set"
  ADD CONSTRAINT "osv_listing_observation_evidence_set_request_fkey"
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

ALTER TABLE "osv_listing_observation_evidence_set"
  ADD CONSTRAINT "osv_listing_observation_evidence_set_run_fkey"
  FOREIGN KEY ("synchronization_run_id", "synchronization_request_id")
  REFERENCES "osv_runtime_synchronization_run"("id", "request_id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_observation_evidence"
  ADD CONSTRAINT "osv_listing_observation_evidence_set_aad_fkey"
  FOREIGN KEY (
    "evidence_set_id",
    "listing_execution_id",
    "provider_contact_authorization_id",
    "synchronization_request_id",
    "synchronization_run_id",
    "provider",
    "approved_prefix",
    "listing_protocol_id",
    "source_license_registry_version",
    "runtime_version_set_fingerprint"
  )
  REFERENCES "osv_listing_observation_evidence_set"(
    "id",
    "listing_execution_id",
    "provider_contact_authorization_id",
    "synchronization_request_id",
    "synchronization_run_id",
    "provider",
    "approved_prefix",
    "listing_protocol_id",
    "source_license_registry_version",
    "runtime_version_set_fingerprint"
  ) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_observation_evidence_envelope"
  ADD CONSTRAINT "osv_listing_observation_evidence_envelope_observation_fkey"
  FOREIGN KEY (
    "observation_id",
    "evidence_set_id",
    "provider_generation",
    "declared_listing_byte_count",
    "source_family_classification",
    "classification_status"
  )
  REFERENCES "osv_listing_observation_evidence"(
    "id",
    "evidence_set_id",
    "provider_generation",
    "declared_listing_byte_count",
    "source_family_classification",
    "classification_status"
  ) ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_observation_evidence_envelope"
  ADD CONSTRAINT "osv_listing_observation_evidence_envelope_set_fkey"
  FOREIGN KEY ("evidence_set_id")
  REFERENCES "osv_listing_observation_evidence_set"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_observation_evidence_purge"
  ADD CONSTRAINT "osv_listing_observation_evidence_purge_set_fkey"
  FOREIGN KEY ("evidence_set_id")
  REFERENCES "osv_listing_observation_evidence_set"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "osv_listing_observation_evidence_set"
  ADD CONSTRAINT "osv_listing_observation_evidence_set_uuid_v4_chk"
  CHECK (
    "id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "listing_execution_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "provider_contact_authorization_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "synchronization_request_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "synchronization_run_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "id" <> "listing_execution_id"
    AND "id" <> "provider_contact_authorization_id"
    AND "id" <> "synchronization_request_id"
    AND "id" <> "synchronization_run_id"
    AND "listing_execution_id" <> "provider_contact_authorization_id"
    AND "synchronization_request_id" <> "synchronization_run_id"
  );

ALTER TABLE "osv_listing_observation_evidence_set"
  ADD CONSTRAINT "osv_listing_observation_evidence_set_policy_chk"
  CHECK (
    "evidence_schema_version" = 'osv_protected_listing_observation_evidence_v1'
    AND "evidence_policy_id" = 'osv_protected_listing_observation_evidence_policy_v1'
    AND "purpose_id" = 'osv_protected_listing_observation_evidence_purpose_v1'
    AND "ownership" = 'instance_owned_non_tenant'
    AND "provider" = 'osv'
    AND "approved_prefix" = 'crates.io/'
    AND "listing_protocol_id" = 'osv_gcs_json_objects_list_v1'
    AND "listing_policy_id" = 'osv_disabled_first_provider_canary_policy_v1'
    AND "budget_profile_id" = 'osv_canary_listing_only_budget_v1'
    AND "work_scope" = 'osv_runtime_canary_scope_crates_io_rustsec_v1'
    AND "lease_scope" = 'osv_runtime_lease_scope_osv_gcs_public_export_v1'
    AND "synchronization_reason" = 'operator_canary'
    AND char_length("runtime_version_set_fingerprint") = 64
    AND "runtime_version_set_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "source_license_registry_version" = 'osv_source_license_registry_v1'
    AND "classification_policy_id" = 'osv_metadata_policy_v1'
    AND "canonical_evidence_set_algorithm_id" = 'osv_protected_listing_observation_evidence_set_canonical_v1'
    AND "encryption_policy_id" = 'osv_protected_listing_evidence_encryption_policy_v1'
    AND "associated_data_policy_id" = 'osv_protected_listing_evidence_associated_data_v1'
    AND "associated_data_algorithm_id" = 'osv_protected_listing_evidence_associated_data_canonical_v1'
    AND "envelope_schema_version" = 'osv_protected_listing_evidence_ciphertext_envelope_v1'
    AND "algorithm_id" = 'aes-256-gcm'
    AND "retention_policy_id" = 'osv_protected_listing_observation_evidence_retention_v1'
    AND "page_ordinal" = 1
    AND char_length("canonical_evidence_set_digest") = 64
    AND "canonical_evidence_set_digest" ~ '^[a-f0-9]{64}$'
    AND "candidate_selection_authorized" = FALSE
    AND "body_retrieval_authorized" = FALSE
    AND "batch_4p_permitted" = FALSE
    AND "pagination_authorized" = FALSE
    AND "activation_authorized" = FALSE
    AND "matching_authorized" = FALSE
    AND "finding_writes_authorized" = FALSE
    AND "provider_contact_authorized" = FALSE
  );

ALTER TABLE "osv_listing_observation_evidence_set"
  ADD CONSTRAINT "osv_listing_observation_evidence_set_capacity_chk"
  CHECK (
    "translator_observation_count" >= 0
    AND "translator_observation_count" <= 1000
    AND "accepted_observation_count" >= 0
    AND "accepted_observation_count" <= 1000
    AND "protected_observation_count" >= 0
    AND "protected_observation_count" <= 1000
    AND "protected_observation_count" <= "accepted_observation_count"
    AND "accepted_observation_count" <= "translator_observation_count"
    AND "rejected_observation_count" >= 0
    AND "rejected_observation_count" <= 1000
    AND "rejected_observation_count" <= "translator_observation_count"
    AND "translator_observation_count" = "accepted_observation_count" + "rejected_observation_count"
    AND "exact_duplicate_count" >= 0
    AND "exact_duplicate_count" <= "accepted_observation_count"
    AND "duplicate_ambiguity_count" >= 0
    AND "duplicate_ambiguity_count" <= "accepted_observation_count"
    AND "immutable_conflict_count" >= 0
    AND "immutable_conflict_count" <= "accepted_observation_count"
    AND "total_protected_key_plaintext_bytes" >= 0
    AND "total_protected_key_plaintext_bytes" <= 512000
    AND "total_protected_key_plaintext_bytes" <= ("protected_observation_count"::bigint * 512)
    AND (
      "protected_observation_count" = 0
      OR "total_protected_key_plaintext_bytes" >= "protected_observation_count"
    )
    AND "total_envelope_bytes" >= 0
    AND "total_envelope_bytes" <= 540000
    AND "total_canonical_bytes" >= 0
    AND "total_canonical_bytes" <= 4194304
    AND "total_metadata_bytes" >= 0
    AND "total_metadata_bytes" <= 1298432
    AND "event_count" >= 0
    AND "event_count" <= 16
    AND "row_revision" > 0
  );

ALTER TABLE "osv_listing_observation_evidence_set"
  ADD CONSTRAINT "osv_listing_observation_evidence_set_state_chk"
  CHECK (
    (
      (
        "legal_hold_active" = FALSE
        AND "legal_hold_classification" IN ('hold_absent', 'hold_released')
      )
      OR (
        "legal_hold_active" = TRUE
        AND "legal_hold_classification" = 'legal_hold_active'
      )
    )
    AND (
      (
        "legal_hold_classification" = 'hold_absent'
        AND "legal_hold_changed_at" IS NULL
      )
      OR (
        "legal_hold_classification" IN ('legal_hold_active', 'hold_released')
        AND "legal_hold_changed_at" IS NOT NULL
        AND "legal_hold_changed_at" >= "captured_at"
      )
    )
    AND (
      (
        "retention_overdue_classification" = 'not_overdue'
        AND "retention_overdue_at" IS NULL
      )
      OR (
        "retention_overdue_classification" = 'retention_overdue_review_required_no_automatic_delete'
        AND "retention_overdue_at" IS NOT NULL
        AND "retention_overdue_at" >= "captured_at"
      )
    )
    AND "created_at" >= "captured_at"
    AND (
      (
        "evidence_state" IN (
          'constructed',
          'incomplete',
          'overflow_rejected',
          'conflict_quarantine_required',
          'duplicate_ambiguous',
          'malformed_rejected',
          'review_pending',
          'failed'
        )
        AND "review_recorded_at" IS NULL
        AND "purged_at" IS NULL
      )
      OR (
        "evidence_state" IN ('review_accepted', 'review_rejected')
        AND "review_recorded_at" IS NOT NULL
        AND "review_recorded_at" >= "captured_at"
        AND "purged_at" IS NULL
      )
      OR (
        "evidence_state" = 'purged'
        AND "purged_at" IS NOT NULL
        AND "purged_at" >= "captured_at"
        AND "legal_hold_active" = FALSE
      )
    )
    AND (
      (
        "evidence_state" = 'duplicate_ambiguous'
        AND "duplicate_ambiguity_count" > 0
        AND "candidate_selection_readiness" = 'ineligible_duplicate_ambiguity'
      )
      OR (
        "evidence_state" = 'conflict_quarantine_required'
        AND "immutable_conflict_count" > 0
        AND "candidate_selection_readiness" = 'ineligible_conflict'
      )
      OR (
        "evidence_state" = 'overflow_rejected'
        AND "candidate_selection_readiness" = 'ineligible_overflow'
      )
      OR (
        "evidence_state" = 'incomplete'
        AND "candidate_selection_readiness" = 'ineligible_incomplete'
      )
      OR (
        "evidence_state" = 'malformed_rejected'
        AND "candidate_selection_readiness" IN ('ineligible_binding_mismatch', 'review_not_accepted')
      )
      OR (
        "evidence_state" = 'constructed'
        AND "duplicate_ambiguity_count" = 0
        AND "immutable_conflict_count" = 0
        AND (
          (
            "accepted_observation_count" = 0
            AND "candidate_selection_readiness" = 'empty_page_not_candidate_ready'
          )
          OR (
            "accepted_observation_count" > 0
            AND "candidate_selection_readiness" IN (
              'metadata_complete_selection_not_authorized',
              'review_not_accepted'
            )
          )
        )
      )
      OR (
        "evidence_state" = 'review_pending'
        AND "candidate_selection_readiness" = 'review_not_accepted'
      )
      OR (
        "evidence_state" = 'review_accepted'
        AND "candidate_selection_readiness" = 'metadata_complete_selection_not_authorized'
      )
      OR (
        "evidence_state" = 'review_rejected'
        AND "candidate_selection_readiness" = 'review_not_accepted'
      )
      OR (
        "evidence_state" IN ('failed', 'purged')
      )
    )
    AND (
      "accepted_observation_count" > 0
      OR "candidate_selection_readiness" IN (
        'empty_page_not_candidate_ready',
        'ineligible_incomplete',
        'ineligible_overflow',
        'ineligible_binding_mismatch',
        'review_not_accepted'
      )
    )
  );

ALTER TABLE "osv_listing_observation_evidence"
  ADD CONSTRAINT "osv_listing_observation_evidence_uuid_v4_chk"
  CHECK (
    "id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "evidence_set_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "listing_execution_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "provider_contact_authorization_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "synchronization_request_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "synchronization_run_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "id" <> "evidence_set_id"
    AND "synchronization_request_id" <> "synchronization_run_id"
  );

ALTER TABLE "osv_listing_observation_evidence"
  ADD CONSTRAINT "osv_listing_observation_evidence_policy_chk"
  CHECK (
    "provider" = 'osv'
    AND "approved_prefix" = 'crates.io/'
    AND "listing_protocol_id" = 'osv_gcs_json_objects_list_v1'
    AND "source_license_registry_version" = 'osv_source_license_registry_v1'
    AND char_length("runtime_version_set_fingerprint") = 64
    AND "runtime_version_set_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "evidence_schema_version" = 'osv_protected_listing_observation_evidence_v1'
    AND "classification_policy_id" = 'osv_metadata_policy_v1'
    AND "observation_canonical_algorithm_id" = 'osv_protected_listing_observation_canonical_v1'
    AND "encryption_policy_id" = 'osv_protected_listing_evidence_encryption_policy_v1'
    AND "associated_data_policy_id" = 'osv_protected_listing_evidence_associated_data_v1'
    AND "associated_data_algorithm_id" = 'osv_protected_listing_evidence_associated_data_canonical_v1'
    AND "envelope_schema_version" = 'osv_protected_listing_evidence_ciphertext_envelope_v1'
    AND "observation_ordinal" >= 1
    AND "observation_ordinal" <= 1000
    AND char_length("listing_observation_identity") = 64
    AND "listing_observation_identity" ~ '^[a-f0-9]{64}$'
    AND char_length("provider_generation") BETWEEN 1 AND 20
    AND "provider_generation" ~ '^[1-9][0-9]{0,19}$'
    AND "declared_listing_byte_count" >= 0
    AND "declared_listing_byte_count" <= 1048576
    AND "source_family_classification" ~ '^(known:[A-Z][A-Z0-9._-]{0,63}|unknown_uppercase:[A-Z][A-Z0-9._-]{0,63}|unclassifiable)$'
    AND "evidence_state" IN (
      'constructed',
      'incomplete',
      'overflow_rejected',
      'conflict_quarantine_required',
      'duplicate_ambiguous',
      'malformed_rejected'
    )
    AND "candidate_selection_authorized" = FALSE
    AND "body_retrieval_authorized" = FALSE
    AND "batch_4p_permitted" = FALSE
    AND "plaintext_length_accounting" >= 1
    AND "plaintext_length_accounting" <= 512
    AND "row_revision" > 0
    AND "created_at" >= "captured_at"
  );

ALTER TABLE "osv_listing_observation_evidence_envelope"
  ADD CONSTRAINT "osv_listing_observation_evidence_envelope_uuid_v4_chk"
  CHECK (
    "id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "observation_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "evidence_set_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "id" <> "observation_id"
    AND "id" <> "evidence_set_id"
  );

ALTER TABLE "osv_listing_observation_evidence_envelope"
  ADD CONSTRAINT "osv_listing_observation_evidence_envelope_policy_chk"
  CHECK (
    char_length("provider_generation") BETWEEN 1 AND 20
    AND "provider_generation" ~ '^[1-9][0-9]{0,19}$'
    AND "declared_listing_byte_count" >= 0
    AND "declared_listing_byte_count" <= 1048576
    AND "source_family_classification" ~ '^(known:[A-Z][A-Z0-9._-]{0,63}|unknown_uppercase:[A-Z][A-Z0-9._-]{0,63}|unclassifiable)$'
    AND "envelope_ordinal" >= 1
    AND "envelope_ordinal" <= 8
    AND "envelope_schema_version" = 'osv_protected_listing_evidence_ciphertext_envelope_v1'
    AND "cryptographic_policy_id" = 'osv_protected_listing_evidence_encryption_policy_v1'
    AND "algorithm_id" = 'aes-256-gcm'
    AND "associated_data_policy_id" = 'osv_protected_listing_evidence_associated_data_v1'
    AND "opaque_key_alias" ~ '^osv\.listing\.evidence\.k[a-z0-9]{1,24}$'
    AND char_length("opaque_key_alias") BETWEEN 8 AND 64
    AND "plaintext_length_accounting" >= 1
    AND "plaintext_length_accounting" <= 512
    AND "ciphertext_length_accounting" = "plaintext_length_accounting"
    AND "row_revision" > 0
    AND (
      (
        "erasure_state" = 'cryptographically_erased'
        AND "envelope_state" = 'erased'
        AND "protected_identity_envelope" IS NULL
        AND "erasure_completed_at" IS NOT NULL
        AND "erasure_attempted_at" IS NOT NULL
        AND "erasure_completed_at" >= "erasure_attempted_at"
      )
      OR (
        "erasure_state" IN ('not_erased', 'erasure_eligible', 'erasure_blocked')
        AND "envelope_state" <> 'erased'
        AND "protected_identity_envelope" IS NOT NULL
        AND octet_length("protected_identity_envelope") = "plaintext_length_accounting" + 28
        AND octet_length("protected_identity_envelope") BETWEEN 29 AND 540
        AND substring("protected_identity_envelope" from 1 for 12)
          IS DISTINCT FROM decode('000000000000000000000000', 'hex')
        AND "erasure_completed_at" IS NULL
      )
    )
    AND (
      (
        "envelope_state" = 'current'
        AND "rotation_state" = 'current'
        AND "key_version_classification" = 'current'
      )
      OR (
        "envelope_state" = 'rotation_pending'
        AND "rotation_state" IN ('current', 'rotation_required')
        AND "key_version_classification" = 'current'
      )
      OR (
        "envelope_state" IN ('decrypt_only', 'rotation_required', 'retired')
        AND "rotation_state" IN ('rotated', 'rotation_required', 'not_applicable_policy_only')
        AND "key_version_classification" = 'historical'
      )
      OR (
        "envelope_state" IN ('failed', 'erased')
      )
    )
  );

ALTER TABLE "osv_listing_observation_evidence_purge"
  ADD CONSTRAINT "osv_listing_observation_evidence_purge_uuid_v4_chk"
  CHECK (
    "id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "evidence_set_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    AND "id" <> "evidence_set_id"
  );

ALTER TABLE "osv_listing_observation_evidence_purge"
  ADD CONSTRAINT "osv_listing_observation_evidence_purge_policy_chk"
  CHECK (
    "purge_authorization_classification" = 'distinct_instance_operator_cleanup_grant_not_listing_authorization'
    AND "purge_reason_code" ~ '^[a-z0-9_]+$'
    AND char_length("purge_reason_code") BETWEEN 1 AND 64
    AND "legal_hold_decision" IN ('hold_absent_verified', 'hold_active_blocks_purge')
    AND "dependent_authority_terminal_decision" IN (
      'terminal_verified',
      'active_blocks_purge'
    )
    AND "erasure_mechanism_classification" = 'authorized_envelope_redaction_not_instance_key_destruction'
    AND "created_at" >= "attempted_at"
    AND (
      (
        "erasure_outcome" = 'envelopes_redacted_metadata_retained'
        AND "completed_at" IS NOT NULL
        AND "completed_at" >= "attempted_at"
        AND "legal_hold_decision" = 'hold_absent_verified'
        AND "dependent_authority_terminal_decision" = 'terminal_verified'
      )
      OR (
        "erasure_outcome" IN (
          'blocked_legal_hold',
          'blocked_dependency_authorization',
          'blocked_cleanup_unauthorized',
          'already_erased_cannot_restore',
          'shared_key_collateral_erasure_rejected'
        )
        AND "completed_at" IS NULL
      )
    )
    AND (
      "erasure_outcome" <> 'blocked_legal_hold'
      OR "legal_hold_decision" = 'hold_active_blocks_purge'
    )
    AND (
      "erasure_outcome" <> 'blocked_dependency_authorization'
      OR "dependent_authority_terminal_decision" = 'active_blocks_purge'
    )
  );

CREATE FUNCTION patchpilot_osv_listing_observation_evidence_set_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  authorization_request uuid;
  authorization_run uuid;
  authorization_prefix varchar(32);
  authorization_protocol varchar(128);
  authorization_fingerprint text;
  authorization_scope osv_runtime_work_scope;
  authorization_lease varchar(128);
  authorization_reason osv_runtime_synchronization_reason;
  authorization_policy varchar(128);
  authorization_budget varchar(128);
BEGIN
  NEW.captured_at := CURRENT_TIMESTAMP;
  NEW.created_at := CURRENT_TIMESTAMP;
  NEW.row_revision := 1;
  IF NEW.evidence_state IN ('review_accepted', 'review_rejected', 'failed', 'purged') THEN
    RAISE EXCEPTION 'osv listing observation evidence set cannot insert a successor-only state'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.review_recorded_at IS NOT NULL OR NEW.purged_at IS NOT NULL THEN
    RAISE EXCEPTION 'osv listing observation evidence set insert cannot record review or purge'
      USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT
    synchronization_request_id,
    synchronization_run_id,
    approved_prefix,
    listing_protocol,
    runtime_version_set_fingerprint,
    work_scope,
    lease_scope,
    synchronization_reason,
    canary_policy_identifier,
    listing_budget_profile
  INTO
    authorization_request,
    authorization_run,
    authorization_prefix,
    authorization_protocol,
    authorization_fingerprint,
    authorization_scope,
    authorization_lease,
    authorization_reason,
    authorization_policy,
    authorization_budget
  FROM osv_listing_provider_contact_authorization
  WHERE id = NEW.provider_contact_authorization_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'osv listing observation evidence set authorization is missing'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF authorization_request IS DISTINCT FROM NEW.synchronization_request_id
     OR authorization_run IS DISTINCT FROM NEW.synchronization_run_id
     OR authorization_prefix IS DISTINCT FROM NEW.approved_prefix
     OR authorization_protocol IS DISTINCT FROM NEW.listing_protocol_id
     OR authorization_fingerprint IS DISTINCT FROM NEW.runtime_version_set_fingerprint
     OR authorization_scope IS DISTINCT FROM NEW.work_scope
     OR authorization_lease IS DISTINCT FROM NEW.lease_scope
     OR authorization_reason IS DISTINCT FROM NEW.synchronization_reason
     OR authorization_policy IS DISTINCT FROM NEW.listing_policy_id
     OR authorization_budget IS DISTINCT FROM NEW.budget_profile_id THEN
    RAISE EXCEPTION 'osv listing observation evidence set authorization binding does not match'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_protect_osv_listing_observation_evidence_set()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.evidence_schema_version IS DISTINCT FROM OLD.evidence_schema_version
     OR NEW.evidence_policy_id IS DISTINCT FROM OLD.evidence_policy_id
     OR NEW.purpose_id IS DISTINCT FROM OLD.purpose_id
     OR NEW.ownership IS DISTINCT FROM OLD.ownership
     OR NEW.listing_execution_id IS DISTINCT FROM OLD.listing_execution_id
     OR NEW.provider_contact_authorization_id IS DISTINCT FROM OLD.provider_contact_authorization_id
     OR NEW.synchronization_request_id IS DISTINCT FROM OLD.synchronization_request_id
     OR NEW.synchronization_run_id IS DISTINCT FROM OLD.synchronization_run_id
     OR NEW.provider IS DISTINCT FROM OLD.provider
     OR NEW.approved_prefix IS DISTINCT FROM OLD.approved_prefix
     OR NEW.listing_protocol_id IS DISTINCT FROM OLD.listing_protocol_id
     OR NEW.listing_policy_id IS DISTINCT FROM OLD.listing_policy_id
     OR NEW.budget_profile_id IS DISTINCT FROM OLD.budget_profile_id
     OR NEW.work_scope IS DISTINCT FROM OLD.work_scope
     OR NEW.lease_scope IS DISTINCT FROM OLD.lease_scope
     OR NEW.synchronization_reason IS DISTINCT FROM OLD.synchronization_reason
     OR NEW.runtime_version_set_fingerprint IS DISTINCT FROM OLD.runtime_version_set_fingerprint
     OR NEW.source_license_registry_version IS DISTINCT FROM OLD.source_license_registry_version
     OR NEW.classification_policy_id IS DISTINCT FROM OLD.classification_policy_id
     OR NEW.canonical_evidence_set_algorithm_id IS DISTINCT FROM OLD.canonical_evidence_set_algorithm_id
     OR NEW.encryption_policy_id IS DISTINCT FROM OLD.encryption_policy_id
     OR NEW.associated_data_policy_id IS DISTINCT FROM OLD.associated_data_policy_id
     OR NEW.associated_data_algorithm_id IS DISTINCT FROM OLD.associated_data_algorithm_id
     OR NEW.envelope_schema_version IS DISTINCT FROM OLD.envelope_schema_version
     OR NEW.algorithm_id IS DISTINCT FROM OLD.algorithm_id
     OR NEW.retention_policy_id IS DISTINCT FROM OLD.retention_policy_id
     OR NEW.page_ordinal IS DISTINCT FROM OLD.page_ordinal
     OR NEW.canonical_evidence_set_digest IS DISTINCT FROM OLD.canonical_evidence_set_digest
     OR NEW.translator_observation_count IS DISTINCT FROM OLD.translator_observation_count
     OR NEW.accepted_observation_count IS DISTINCT FROM OLD.accepted_observation_count
     OR NEW.protected_observation_count IS DISTINCT FROM OLD.protected_observation_count
     OR NEW.rejected_observation_count IS DISTINCT FROM OLD.rejected_observation_count
     OR NEW.exact_duplicate_count IS DISTINCT FROM OLD.exact_duplicate_count
     OR NEW.duplicate_ambiguity_count IS DISTINCT FROM OLD.duplicate_ambiguity_count
     OR NEW.immutable_conflict_count IS DISTINCT FROM OLD.immutable_conflict_count
     OR NEW.total_protected_key_plaintext_bytes IS DISTINCT FROM OLD.total_protected_key_plaintext_bytes
     OR NEW.total_envelope_bytes IS DISTINCT FROM OLD.total_envelope_bytes
     OR NEW.total_canonical_bytes IS DISTINCT FROM OLD.total_canonical_bytes
     OR NEW.total_metadata_bytes IS DISTINCT FROM OLD.total_metadata_bytes
     OR NEW.event_count IS DISTINCT FROM OLD.event_count
     OR NEW.captured_at IS DISTINCT FROM OLD.captured_at
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR NEW.candidate_selection_authorized IS DISTINCT FROM OLD.candidate_selection_authorized
     OR NEW.body_retrieval_authorized IS DISTINCT FROM OLD.body_retrieval_authorized
     OR NEW.batch_4p_permitted IS DISTINCT FROM OLD.batch_4p_permitted
     OR NEW.pagination_authorized IS DISTINCT FROM OLD.pagination_authorized
     OR NEW.activation_authorized IS DISTINCT FROM OLD.activation_authorized
     OR NEW.matching_authorized IS DISTINCT FROM OLD.matching_authorized
     OR NEW.finding_writes_authorized IS DISTINCT FROM OLD.finding_writes_authorized
     OR NEW.provider_contact_authorized IS DISTINCT FROM OLD.provider_contact_authorized THEN
    RAISE EXCEPTION 'osv listing observation evidence set immutable fields cannot change'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.row_revision IS DISTINCT FROM OLD.row_revision + 1 THEN
    RAISE EXCEPTION 'osv listing observation evidence set row revision must increase by one'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.evidence_state IN (
    'review_accepted',
    'review_rejected',
    'failed',
    'purged',
    'incomplete',
    'overflow_rejected',
    'conflict_quarantine_required',
    'duplicate_ambiguous',
    'malformed_rejected'
  ) AND NEW.evidence_state IS DISTINCT FROM OLD.evidence_state THEN
    IF OLD.evidence_state = 'purged' THEN
      RAISE EXCEPTION 'osv listing observation evidence set purged state cannot reopen'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.evidence_state IN ('review_accepted', 'review_rejected', 'failed')
       AND NEW.evidence_state IS DISTINCT FROM 'purged'
       AND NEW.evidence_state IS DISTINCT FROM OLD.evidence_state THEN
      RAISE EXCEPTION 'invalid osv listing observation evidence set terminal transition'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.evidence_state IN (
      'incomplete',
      'overflow_rejected',
      'conflict_quarantine_required',
      'duplicate_ambiguous',
      'malformed_rejected'
    ) AND NEW.evidence_state NOT IN (OLD.evidence_state, 'failed', 'purged') THEN
      RAISE EXCEPTION 'invalid osv listing observation evidence set rejection transition'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  IF OLD.evidence_state = 'constructed'
     AND NEW.evidence_state NOT IN ('constructed', 'review_pending') THEN
    RAISE EXCEPTION 'invalid osv listing observation evidence set constructed transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.evidence_state = 'review_pending'
     AND NEW.evidence_state NOT IN ('review_pending', 'review_accepted', 'review_rejected') THEN
    RAISE EXCEPTION 'invalid osv listing observation evidence set review transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.evidence_state IN ('review_accepted', 'review_rejected')
     AND OLD.review_recorded_at IS NULL THEN
    NEW.review_recorded_at := CURRENT_TIMESTAMP;
  END IF;
  IF NEW.evidence_state = 'purged' THEN
    IF OLD.legal_hold_active = TRUE OR NEW.legal_hold_active = TRUE THEN
      RAISE EXCEPTION 'osv listing observation evidence set cannot purge under legal hold'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF EXISTS (
      SELECT 1
      FROM osv_listing_observation_evidence_envelope
      WHERE evidence_set_id = OLD.id
        AND erasure_state IS DISTINCT FROM 'cryptographically_erased'
    ) THEN
      RAISE EXCEPTION 'osv listing observation evidence set cannot purge while envelopes remain recoverable'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF OLD.purged_at IS NULL THEN
      NEW.purged_at := CURRENT_TIMESTAMP;
    END IF;
  END IF;
  IF NEW.legal_hold_classification IS DISTINCT FROM OLD.legal_hold_classification
     AND OLD.legal_hold_changed_at IS NOT DISTINCT FROM NEW.legal_hold_changed_at THEN
    NEW.legal_hold_changed_at := CURRENT_TIMESTAMP;
  END IF;
  IF NEW.retention_overdue_classification IS DISTINCT FROM OLD.retention_overdue_classification
     AND NEW.retention_overdue_classification = 'retention_overdue_review_required_no_automatic_delete'
     AND NEW.retention_overdue_at IS NULL THEN
    NEW.retention_overdue_at := CURRENT_TIMESTAMP;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_osv_listing_observation_evidence_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_state osv_listing_observation_evidence_set_state;
  parent_captured timestamptz;
  parent_protected integer;
  observation_count integer;
BEGIN
  SELECT evidence_state, captured_at, protected_observation_count
  INTO parent_state, parent_captured, parent_protected
  FROM osv_listing_observation_evidence_set
  WHERE id = NEW.evidence_set_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'osv listing observation evidence set is missing'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF parent_state IN ('review_accepted', 'review_rejected', 'failed', 'purged') THEN
    RAISE EXCEPTION 'osv listing observation evidence cannot append to a terminal set'
      USING ERRCODE = 'restrict_violation';
  END IF;
  NEW.captured_at := CURRENT_TIMESTAMP;
  NEW.created_at := CURRENT_TIMESTAMP;
  NEW.row_revision := 1;
  IF NEW.captured_at IS DISTINCT FROM parent_captured THEN
    RAISE EXCEPTION 'osv listing observation evidence cannot append after set capture'
      USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT COUNT(*)::integer
  INTO observation_count
  FROM osv_listing_observation_evidence
  WHERE evidence_set_id = NEW.evidence_set_id;
  IF observation_count + 1 > 1000 OR observation_count + 1 > parent_protected THEN
    RAISE EXCEPTION 'osv listing observation evidence exceeds protected count'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_osv_listing_observation_evidence_envelope_required()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM osv_listing_observation_evidence_envelope
    WHERE observation_id = NEW.id
  ) THEN
    RAISE EXCEPTION 'osv listing observation evidence requires a protected envelope'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION patchpilot_osv_listing_observation_evidence_set_protected_count()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  observation_count integer;
BEGIN
  SELECT COUNT(*)::integer
  INTO observation_count
  FROM osv_listing_observation_evidence
  WHERE evidence_set_id = NEW.id;
  IF observation_count IS DISTINCT FROM NEW.protected_observation_count THEN
    RAISE EXCEPTION 'osv listing observation evidence protected count must match observation rows'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION patchpilot_osv_listing_observation_evidence_envelope_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  expected_ordinal integer;
  parent_set uuid;
BEGIN
  NEW.created_at := CURRENT_TIMESTAMP;
  NEW.row_revision := 1;
  IF NEW.protected_identity_envelope IS NULL THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope insert requires ciphertext bytes'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.erasure_state IS DISTINCT FROM 'not_erased' OR NEW.envelope_state = 'erased' THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope cannot insert as erased'
      USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT evidence_set_id
  INTO parent_set
  FROM osv_listing_observation_evidence
  WHERE id = NEW.observation_id
  FOR SHARE;
  IF NOT FOUND OR parent_set IS DISTINCT FROM NEW.evidence_set_id THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope observation binding does not match'
      USING ERRCODE = 'restrict_violation';
  END IF;
  SELECT COALESCE(MAX(envelope_ordinal), 0) + 1
  INTO expected_ordinal
  FROM osv_listing_observation_evidence_envelope
  WHERE observation_id = NEW.observation_id;
  IF NEW.envelope_ordinal IS DISTINCT FROM expected_ordinal THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope ordinal must be contiguous'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF expected_ordinal = 1 AND NEW.envelope_state IS DISTINCT FROM 'current' THEN
    RAISE EXCEPTION 'osv listing observation evidence first envelope must be current'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF expected_ordinal > 1 AND NEW.envelope_state IS DISTINCT FROM 'rotation_pending' THEN
    RAISE EXCEPTION 'osv listing observation evidence successor envelope must be rotation_pending'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_protect_osv_listing_observation_evidence_envelope()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.observation_id IS DISTINCT FROM OLD.observation_id
     OR NEW.evidence_set_id IS DISTINCT FROM OLD.evidence_set_id
     OR NEW.provider_generation IS DISTINCT FROM OLD.provider_generation
     OR NEW.declared_listing_byte_count IS DISTINCT FROM OLD.declared_listing_byte_count
     OR NEW.source_family_classification IS DISTINCT FROM OLD.source_family_classification
     OR NEW.classification_status IS DISTINCT FROM OLD.classification_status
     OR NEW.envelope_ordinal IS DISTINCT FROM OLD.envelope_ordinal
     OR NEW.envelope_schema_version IS DISTINCT FROM OLD.envelope_schema_version
     OR NEW.cryptographic_policy_id IS DISTINCT FROM OLD.cryptographic_policy_id
     OR NEW.algorithm_id IS DISTINCT FROM OLD.algorithm_id
     OR NEW.associated_data_policy_id IS DISTINCT FROM OLD.associated_data_policy_id
     OR NEW.opaque_key_alias IS DISTINCT FROM OLD.opaque_key_alias
     OR NEW.plaintext_length_accounting IS DISTINCT FROM OLD.plaintext_length_accounting
     OR NEW.ciphertext_length_accounting IS DISTINCT FROM OLD.ciphertext_length_accounting
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope immutable fields cannot change'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.row_revision IS DISTINCT FROM OLD.row_revision + 1 THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope row revision must increase by one'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.envelope_state = 'erased' THEN
    RAISE EXCEPTION 'osv listing observation evidence erased envelope cannot change'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.protected_identity_envelope IS NOT NULL
     AND NEW.protected_identity_envelope IS NOT NULL
     AND NEW.protected_identity_envelope IS DISTINCT FROM OLD.protected_identity_envelope THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope bytes cannot be replaced'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.protected_identity_envelope IS NOT NULL
     AND NEW.protected_identity_envelope IS NULL
     AND NEW.erasure_state IS DISTINCT FROM 'cryptographically_erased' THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope redaction requires cryptographic erasure'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.protected_identity_envelope IS NULL
     AND NEW.protected_identity_envelope IS NOT NULL THEN
    RAISE EXCEPTION 'osv listing observation evidence envelope cannot restore redacted bytes'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF (
        NEW.envelope_state = 'erased'
        AND OLD.envelope_state IS DISTINCT FROM 'erased'
      )
     OR (
        OLD.protected_identity_envelope IS NOT NULL
        AND NEW.protected_identity_envelope IS NULL
      ) THEN
    IF EXISTS (
      SELECT 1
      FROM osv_listing_observation_evidence_set
      WHERE id = OLD.evidence_set_id
        AND legal_hold_active = TRUE
      FOR SHARE
    ) THEN
      RAISE EXCEPTION 'osv listing observation evidence envelope cannot erase under legal hold'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  IF OLD.envelope_state = 'current'
     AND NEW.envelope_state NOT IN (
       'current',
       'decrypt_only',
       'rotation_required',
       'retired',
       'erased'
     ) THEN
    RAISE EXCEPTION 'invalid osv listing observation evidence current envelope transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.envelope_state = 'rotation_pending'
     AND NEW.envelope_state NOT IN ('rotation_pending', 'current', 'failed', 'erased') THEN
    RAISE EXCEPTION 'invalid osv listing observation evidence pending envelope transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.envelope_state = 'decrypt_only'
     AND NEW.envelope_state NOT IN ('decrypt_only', 'retired', 'erased') THEN
    RAISE EXCEPTION 'invalid osv listing observation evidence decrypt-only envelope transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.envelope_state = 'rotation_required'
     AND NEW.envelope_state NOT IN ('rotation_required', 'decrypt_only', 'retired', 'erased') THEN
    RAISE EXCEPTION 'invalid osv listing observation evidence rotation-required envelope transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.envelope_state = 'retired'
     AND NEW.envelope_state NOT IN ('retired', 'erased') THEN
    RAISE EXCEPTION 'invalid osv listing observation evidence retired envelope transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF OLD.envelope_state = 'failed'
     AND NEW.envelope_state NOT IN ('failed', 'erased') THEN
    RAISE EXCEPTION 'invalid osv listing observation evidence failed envelope transition'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.envelope_state = 'erased' THEN
    NEW.erasure_state := 'cryptographically_erased';
    NEW.protected_identity_envelope := NULL;
    IF NEW.erasure_attempted_at IS NULL THEN
      NEW.erasure_attempted_at := CURRENT_TIMESTAMP;
    END IF;
    IF NEW.erasure_completed_at IS NULL THEN
      NEW.erasure_completed_at := CURRENT_TIMESTAMP;
    END IF;
  END IF;
  IF NEW.envelope_state IS DISTINCT FROM OLD.envelope_state
     AND NEW.envelope_state IN ('decrypt_only', 'retired', 'current')
     AND NEW.rotation_recorded_at IS NULL THEN
    NEW.rotation_recorded_at := CURRENT_TIMESTAMP;
  END IF;
  RETURN NEW;
END;
$$;

CREATE FUNCTION patchpilot_osv_listing_observation_evidence_envelope_current()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  target uuid;
  current_count integer;
  remaining_count integer;
BEGIN
  target := COALESCE(NEW.observation_id, OLD.observation_id);
  SELECT
    COUNT(*) FILTER (WHERE envelope_state = 'current')::integer,
    COUNT(*) FILTER (WHERE erasure_state IS DISTINCT FROM 'cryptographically_erased')::integer
  INTO current_count, remaining_count
  FROM osv_listing_observation_evidence_envelope
  WHERE observation_id = target;
  IF remaining_count > 0 AND current_count IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'osv listing observation evidence requires exactly one current envelope unless erased'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NULL;
END;
$$;

CREATE FUNCTION patchpilot_osv_listing_observation_evidence_purge_insert()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  parent_state osv_listing_observation_evidence_set_state;
  parent_hold boolean;
BEGIN
  NEW.attempted_at := CURRENT_TIMESTAMP;
  NEW.created_at := CURRENT_TIMESTAMP;
  SELECT evidence_state, legal_hold_active
  INTO parent_state, parent_hold
  FROM osv_listing_observation_evidence_set
  WHERE id = NEW.evidence_set_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'osv listing observation evidence purge set is missing'
      USING ERRCODE = 'restrict_violation';
  END IF;
  IF NEW.erasure_outcome = 'envelopes_redacted_metadata_retained' THEN
    NEW.completed_at := CURRENT_TIMESTAMP;
    IF parent_hold = TRUE THEN
      RAISE EXCEPTION 'osv listing observation evidence purge cannot succeed under legal hold'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF parent_state IS DISTINCT FROM 'purged' THEN
      RAISE EXCEPTION 'osv listing observation evidence successful purge requires purged set state'
        USING ERRCODE = 'restrict_violation';
    END IF;
    IF EXISTS (
      SELECT 1
      FROM osv_listing_observation_evidence_envelope
      WHERE evidence_set_id = NEW.evidence_set_id
        AND erasure_state IS DISTINCT FROM 'cryptographically_erased'
    ) THEN
      RAISE EXCEPTION 'osv listing observation evidence purge cannot succeed while envelopes remain recoverable'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER osv_listing_observation_evidence_set_insert
  BEFORE INSERT ON "osv_listing_observation_evidence_set"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_observation_evidence_set_insert();

CREATE TRIGGER osv_listing_observation_evidence_set_delete_forbidden
  BEFORE DELETE ON "osv_listing_observation_evidence_set"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_listing_observation_evidence_set_lifecycle
  BEFORE UPDATE ON "osv_listing_observation_evidence_set"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_listing_observation_evidence_set();

CREATE TRIGGER osv_listing_observation_evidence_insert
  BEFORE INSERT ON "osv_listing_observation_evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_observation_evidence_insert();

CREATE TRIGGER osv_listing_observation_evidence_delete_forbidden
  BEFORE DELETE ON "osv_listing_observation_evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_listing_observation_evidence_immutable
  BEFORE UPDATE ON "osv_listing_observation_evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE CONSTRAINT TRIGGER osv_listing_observation_evidence_envelope_required
  AFTER INSERT ON "osv_listing_observation_evidence"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_observation_evidence_envelope_required();

CREATE CONSTRAINT TRIGGER osv_listing_observation_evidence_set_protected_count
  AFTER INSERT ON "osv_listing_observation_evidence_set"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_observation_evidence_set_protected_count();

CREATE TRIGGER osv_listing_observation_evidence_envelope_insert
  BEFORE INSERT ON "osv_listing_observation_evidence_envelope"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_observation_evidence_envelope_insert();

CREATE TRIGGER osv_listing_observation_evidence_envelope_delete_forbidden
  BEFORE DELETE ON "osv_listing_observation_evidence_envelope"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_listing_observation_evidence_envelope_lifecycle
  BEFORE UPDATE ON "osv_listing_observation_evidence_envelope"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_osv_listing_observation_evidence_envelope();

CREATE CONSTRAINT TRIGGER osv_listing_observation_evidence_envelope_current_required
  AFTER INSERT OR UPDATE ON "osv_listing_observation_evidence_envelope"
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_observation_evidence_envelope_current();

CREATE TRIGGER osv_listing_observation_evidence_purge_insert
  BEFORE INSERT ON "osv_listing_observation_evidence_purge"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_osv_listing_observation_evidence_purge_insert();

CREATE TRIGGER osv_listing_observation_evidence_purge_delete_forbidden
  BEFORE DELETE ON "osv_listing_observation_evidence_purge"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER osv_listing_observation_evidence_purge_immutable
  BEFORE UPDATE ON "osv_listing_observation_evidence_purge"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();
