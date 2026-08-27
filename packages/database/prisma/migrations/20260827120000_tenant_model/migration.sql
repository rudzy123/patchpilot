-- Session 5: PostgreSQL tenant model. Forward-only. Does not edit 20260826120000_schema_foundation.
-- Generated from prisma migrate diff (from Session 3 migrations to current schema.prisma),
-- then appended with check constraints, partial unique indexes, append-only triggers, and SchemaFoundation removal safety.

-- CreateEnum
CREATE TYPE "organization_status" AS ENUM ('active', 'archived');

-- CreateEnum
CREATE TYPE "user_status" AS ENUM ('active', 'disabled');

-- CreateEnum
CREATE TYPE "membership_role" AS ENUM ('owner', 'admin', 'member', 'viewer');

-- CreateEnum
CREATE TYPE "membership_status" AS ENUM ('active', 'revoked');

-- CreateEnum
CREATE TYPE "team_status" AS ENUM ('active', 'archived');

-- CreateEnum
CREATE TYPE "environment_status" AS ENUM ('active', 'archived');

-- CreateEnum
CREATE TYPE "environment_sensitivity_class" AS ENUM ('production', 'non_production');

-- CreateEnum
CREATE TYPE "asset_type" AS ENUM ('application', 'service', 'library', 'container_image', 'other');

-- CreateEnum
CREATE TYPE "asset_lifecycle_status" AS ENUM ('active', 'archived');

-- CreateEnum
CREATE TYPE "business_criticality" AS ENUM ('critical', 'high', 'medium', 'low', 'unspecified');

-- CreateEnum
CREATE TYPE "internet_exposure" AS ENUM ('internet_facing', 'internal', 'unknown');

-- CreateEnum
CREATE TYPE "asset_data_classification" AS ENUM ('restricted', 'confidential', 'internal', 'public', 'unspecified');

-- CreateEnum
CREATE TYPE "asset_owner_role" AS ENUM ('technical', 'business', 'security');

-- CreateEnum
CREATE TYPE "repository_provider" AS ENUM ('reserved');

-- CreateEnum
CREATE TYPE "repository_connection_status" AS ENUM ('not_configured');

-- CreateEnum
CREATE TYPE "sbom_specification_type" AS ENUM ('cyclonedx');

-- CreateEnum
CREATE TYPE "sbom_source" AS ENUM ('upload', 'reprocess');

-- CreateEnum
CREATE TYPE "sbom_ingestion_state" AS ENUM ('accepted', 'queued', 'processing', 'completed', 'rejected', 'quarantined', 'failed', 'duplicate');

-- CreateEnum
CREATE TYPE "sbom_ingestion_stage" AS ENUM ('validate', 'parse', 'persist_graph', 'correlate', 'enrich', 'score');

-- CreateEnum
CREATE TYPE "component_identity_state" AS ENUM ('resolved', 'ambiguous', 'unsupported');

-- CreateEnum
CREATE TYPE "dependency_relationship_type" AS ENUM ('depends_on');

-- CreateEnum
CREATE TYPE "vulnerability_status" AS ENUM ('active', 'withdrawn');

-- CreateEnum
CREATE TYPE "vulnerability_source" AS ENUM ('osv', 'cisa_kev');

-- CreateEnum
CREATE TYPE "finding_state" AS ENUM ('open', 'verification_pending', 'risk_accepted', 'mitigated', 'false_positive', 'resolved', 'inconclusive');

-- CreateEnum
CREATE TYPE "finding_observation_result" AS ENUM ('present', 'absent', 'inconclusive');

-- CreateEnum
CREATE TYPE "risk_policy_status" AS ENUM ('draft', 'published', 'retired');

-- CreateEnum
CREATE TYPE "risk_calculation_reason" AS ENUM ('initial', 'rescan', 'intel_refresh', 'policy_change', 'asset_change', 'manual_recalc', 'manual_override');

-- CreateEnum
CREATE TYPE "remediation_task_status" AS ENUM ('open', 'assigned', 'in_progress', 'blocked', 'completed', 'cancelled');

-- CreateEnum
CREATE TYPE "risk_acceptance_status" AS ENUM ('active', 'expired', 'revoked', 'superseded');

-- CreateEnum
CREATE TYPE "evidence_kind" AS ENUM ('sbom_object', 'kev_match', 'intel_record', 'policy_snapshot', 'compensating_control');

-- CreateEnum
CREATE TYPE "audit_actor_type" AS ENUM ('user', 'system', 'instance_operator');

-- CreateEnum
CREATE TYPE "audit_retention_category" AS ENUM ('security');

-- CreateEnum
CREATE TYPE "integration_state" AS ENUM ('disabled', 'enabled', 'degraded');

-- CreateEnum
CREATE TYPE "integration_provider_key" AS ENUM ('osv', 'cisa_kev', 'reserved');

-- CreateEnum
CREATE TYPE "external_credential_status" AS ENUM ('pending', 'active', 'rotating', 'expired', 'revoked', 'failed_validation');

-- CreateEnum
CREATE TYPE "secret_storage_provider" AS ENUM ('encrypted_local', 'external_secret_manager');

-- CreateEnum
CREATE TYPE "outbox_event_status" AS ENUM ('pending', 'claimed', 'processed', 'failed', 'dead_lettered');

-- CreateEnum
CREATE TYPE "background_job_status" AS ENUM ('pending', 'queued', 'running', 'succeeded', 'failed', 'dead_lettered', 'cancelled');

-- CreateEnum
CREATE TYPE "idempotency_record_status" AS ENUM ('started', 'completed', 'conflict');

-- DropTable
DROP TABLE "SchemaFoundation";

-- CreateTable
CREATE TABLE "organization" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "slug" VARCHAR(64) NOT NULL,
    "name" VARCHAR(200) NOT NULL,
    "status" "organization_status" NOT NULL DEFAULT 'active',
    "version" INTEGER NOT NULL DEFAULT 1,
    "archived_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "email" VARCHAR(320) NOT NULL,
    "display_name" VARCHAR(200) NOT NULL,
    "status" "user_status" NOT NULL DEFAULT 'active',
    "version" INTEGER NOT NULL DEFAULT 1,
    "disabled_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "user_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "membership" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "role" "membership_role" NOT NULL,
    "status" "membership_status" NOT NULL DEFAULT 'active',
    "invited_at" TIMESTAMPTZ(6),
    "joined_at" TIMESTAMPTZ(6),
    "revoked_at" TIMESTAMPTZ(6),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "membership_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "team" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "name" VARCHAR(200) NOT NULL,
    "slug" VARCHAR(64) NOT NULL,
    "status" "team_status" NOT NULL DEFAULT 'active',
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "team_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "team_membership" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "team_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "team_membership_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "environment" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "name" VARCHAR(200) NOT NULL,
    "slug" VARCHAR(64) NOT NULL,
    "sensitivity_class" "environment_sensitivity_class" NOT NULL,
    "status" "environment_status" NOT NULL DEFAULT 'active',
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "environment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "asset" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "name" VARCHAR(200) NOT NULL,
    "description" VARCHAR(2000),
    "asset_type" "asset_type" NOT NULL,
    "lifecycle_status" "asset_lifecycle_status" NOT NULL DEFAULT 'active',
    "environment_id" UUID,
    "owning_team_id" UUID,
    "business_criticality" "business_criticality" NOT NULL DEFAULT 'unspecified',
    "internet_exposure" "internet_exposure" NOT NULL DEFAULT 'unknown',
    "data_classification" "asset_data_classification" NOT NULL DEFAULT 'unspecified',
    "repository_url" VARCHAR(2048),
    "deployment_context" VARCHAR(2000),
    "last_observed_at" TIMESTAMPTZ(6),
    "last_successful_sbom_ingestion_id" UUID,
    "last_successful_sbom_ingestion_at" TIMESTAMPTZ(6),
    "archived_at" TIMESTAMPTZ(6),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "asset_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "asset_owner" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "user_id" UUID,
    "team_id" UUID,
    "role" "asset_owner_role" NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "asset_owner_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "asset_tag" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "tag" VARCHAR(64) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "asset_tag_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "asset_external_identifier" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "namespace" VARCHAR(64) NOT NULL,
    "identifier" VARCHAR(256) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "asset_external_identifier_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "repository_connection" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "provider" "repository_provider" NOT NULL DEFAULT 'reserved',
    "external_repository_id" VARCHAR(256),
    "display_url" VARCHAR(2048),
    "default_branch" VARCHAR(256),
    "status" "repository_connection_status" NOT NULL DEFAULT 'not_configured',
    "integration_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "repository_connection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sbom" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "object_key" VARCHAR(512) NOT NULL,
    "sha256" CHAR(64) NOT NULL,
    "byte_length" INTEGER NOT NULL,
    "declared_content_type" VARCHAR(255) NOT NULL,
    "specification_type" "sbom_specification_type" NOT NULL DEFAULT 'cyclonedx',
    "specification_version" VARCHAR(16),
    "source" "sbom_source" NOT NULL DEFAULT 'upload',
    "original_filename" VARCHAR(255),
    "uploaded_by_user_id" UUID,
    "captured_at" TIMESTAMPTZ(6),
    "received_at" TIMESTAMPTZ(6) NOT NULL,
    "parser_version_last_succeeded" VARCHAR(64),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "sbom_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sbom_ingestion" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "sbom_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "state" "sbom_ingestion_state" NOT NULL DEFAULT 'accepted',
    "stage" "sbom_ingestion_stage",
    "attempt_number" INTEGER NOT NULL DEFAULT 1,
    "parser_version" VARCHAR(64) NOT NULL,
    "idempotency_key" VARCHAR(128),
    "started_at" TIMESTAMPTZ(6),
    "completed_at" TIMESTAMPTZ(6),
    "failure_category" VARCHAR(64),
    "failure_code" VARCHAR(64),
    "quarantine_reason" VARCHAR(64),
    "lease_expires_at" TIMESTAMPTZ(6),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "sbom_ingestion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "component" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "identity_key" VARCHAR(2048) NOT NULL,
    "purl" VARCHAR(2048),
    "ecosystem" VARCHAR(64) NOT NULL,
    "namespace" VARCHAR(512),
    "name" VARCHAR(512) NOT NULL,
    "identity_state" "component_identity_state" NOT NULL DEFAULT 'resolved',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "component_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "component_occurrence" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "sbom_id" UUID NOT NULL,
    "sbom_ingestion_id" UUID NOT NULL,
    "component_id" UUID NOT NULL,
    "bom_ref" VARCHAR(2048),
    "version" VARCHAR(256) NOT NULL,
    "versioned_purl" VARCHAR(2048),
    "is_direct" BOOLEAN,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "component_occurrence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "dependency_relationship" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "sbom_id" UUID NOT NULL,
    "sbom_ingestion_id" UUID NOT NULL,
    "from_occurrence_id" UUID NOT NULL,
    "to_occurrence_id" UUID NOT NULL,
    "relationship_type" "dependency_relationship_type" NOT NULL DEFAULT 'depends_on',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "dependency_relationship_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vulnerability" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "osv_id" VARCHAR(128) NOT NULL,
    "cve_id" VARCHAR(32),
    "status" "vulnerability_status" NOT NULL DEFAULT 'active',
    "published_at" TIMESTAMPTZ(6),
    "modified_at" TIMESTAMPTZ(6),
    "withdrawn_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "vulnerability_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vulnerability_alias" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "vulnerability_id" UUID NOT NULL,
    "alias" VARCHAR(128) NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vulnerability_alias_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vulnerability_source_record" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "vulnerability_id" UUID NOT NULL,
    "source" "vulnerability_source" NOT NULL,
    "source_identity" VARCHAR(256) NOT NULL,
    "source_url" VARCHAR(2048),
    "published_at" TIMESTAMPTZ(6),
    "modified_at" TIMESTAMPTZ(6),
    "retrieved_at" TIMESTAMPTZ(6) NOT NULL,
    "payload_sha256" CHAR(64) NOT NULL,
    "normalization_version" VARCHAR(64) NOT NULL,
    "withdrawn_at" TIMESTAMPTZ(6),
    "raw_object_key" VARCHAR(512),
    "normalized" JSONB NOT NULL,
    "supersedes_record_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vulnerability_source_record_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "finding" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "asset_id" UUID NOT NULL,
    "vulnerability_id" UUID NOT NULL,
    "component_id" UUID NOT NULL,
    "component_occurrence_id" UUID,
    "state" "finding_state" NOT NULL DEFAULT 'open',
    "first_observed_at" TIMESTAMPTZ(6) NOT NULL,
    "last_observed_at" TIMESTAMPTZ(6) NOT NULL,
    "resolved_at" TIMESTAMPTZ(6),
    "reopened_at" TIMESTAMPTZ(6),
    "assigned_user_id" UUID,
    "assigned_team_id" UUID,
    "due_at" TIMESTAMPTZ(6),
    "current_risk_calculation_id" UUID,
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "finding_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "finding_observation" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "finding_id" UUID NOT NULL,
    "sbom_id" UUID NOT NULL,
    "sbom_ingestion_id" UUID NOT NULL,
    "occurrence_id" UUID,
    "result" "finding_observation_result" NOT NULL,
    "method" VARCHAR(64) NOT NULL,
    "observed_at" TIMESTAMPTZ(6) NOT NULL,
    "evidence" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "finding_observation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risk_policy" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID,
    "policy_key" VARCHAR(128) NOT NULL,
    "name" VARCHAR(200) NOT NULL,
    "version" INTEGER NOT NULL,
    "status" "risk_policy_status" NOT NULL DEFAULT 'draft',
    "policy_schema_version" INTEGER NOT NULL,
    "definition" JSONB NOT NULL,
    "published_at" TIMESTAMPTZ(6),
    "retired_at" TIMESTAMPTZ(6),
    "created_by_user_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "risk_policy_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risk_calculation" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "finding_id" UUID NOT NULL,
    "risk_policy_id" UUID NOT NULL,
    "policy_version" INTEGER NOT NULL,
    "policy_definition_sha256" CHAR(64) NOT NULL,
    "calculated_at" TIMESTAMPTZ(6) NOT NULL,
    "factors" JSONB NOT NULL,
    "result" JSONB NOT NULL,
    "calculation_engine_version" VARCHAR(64) NOT NULL,
    "calculation_reason" "risk_calculation_reason" NOT NULL,
    "input_fingerprint" CHAR(64) NOT NULL,
    "sbom_ingestion_id" UUID,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "risk_calculation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "remediation_task" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "finding_id" UUID NOT NULL,
    "status" "remediation_task_status" NOT NULL DEFAULT 'open',
    "title" VARCHAR(200) NOT NULL,
    "description" VARCHAR(4000),
    "assigned_user_id" UUID,
    "assigned_team_id" UUID,
    "due_at" TIMESTAMPTZ(6),
    "started_at" TIMESTAMPTZ(6),
    "submitted_at" TIMESTAMPTZ(6),
    "verification_requested_at" TIMESTAMPTZ(6),
    "completed_at" TIMESTAMPTZ(6),
    "cancelled_at" TIMESTAMPTZ(6),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "remediation_task_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "risk_acceptance" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "finding_id" UUID NOT NULL,
    "status" "risk_acceptance_status" NOT NULL DEFAULT 'active',
    "requested_by_user_id" UUID NOT NULL,
    "approved_by_user_id" UUID,
    "reason" VARCHAR(4000) NOT NULL,
    "compensating_controls" VARCHAR(4000),
    "starts_at" TIMESTAMPTZ(6) NOT NULL,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "review_at" TIMESTAMPTZ(6) NOT NULL,
    "approved_at" TIMESTAMPTZ(6),
    "revoked_at" TIMESTAMPTZ(6),
    "revocation_reason" VARCHAR(4000),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "risk_acceptance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "evidence" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "kind" "evidence_kind" NOT NULL,
    "finding_id" UUID,
    "sbom_id" UUID,
    "asset_id" UUID,
    "object_key" VARCHAR(512),
    "sha256" CHAR(64),
    "byte_length" INTEGER,
    "content_type" VARCHAR(255),
    "description" VARCHAR(2000),
    "submitted_by_user_id" UUID,
    "metadata" JSONB NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "evidence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "audit_event" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID,
    "actor_user_id" UUID,
    "actor_type" "audit_actor_type" NOT NULL,
    "action" VARCHAR(128) NOT NULL,
    "subject_type" VARCHAR(64) NOT NULL,
    "subject_id" UUID NOT NULL,
    "occurred_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "request_id" VARCHAR(128),
    "correlation_id" VARCHAR(128) NOT NULL,
    "source_ip" VARCHAR(64),
    "user_agent" VARCHAR(512),
    "payload" JSONB NOT NULL,
    "schema_version" INTEGER NOT NULL,
    "retention_category" "audit_retention_category" NOT NULL DEFAULT 'security',

    CONSTRAINT "audit_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "integration" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID,
    "provider_key" "integration_provider_key" NOT NULL,
    "display_name" VARCHAR(200) NOT NULL,
    "state" "integration_state" NOT NULL DEFAULT 'disabled',
    "config" JSONB NOT NULL,
    "external_account_id" VARCHAR(256),
    "last_successful_sync_at" TIMESTAMPTZ(6),
    "last_failure_at" TIMESTAMPTZ(6),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "integration_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "external_credential" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "integration_id" UUID NOT NULL,
    "storage_provider" "secret_storage_provider" NOT NULL,
    "secret_reference" VARCHAR(512) NOT NULL,
    "key_version" VARCHAR(128) NOT NULL,
    "status" "external_credential_status" NOT NULL DEFAULT 'pending',
    "expires_at" TIMESTAMPTZ(6),
    "rotated_at" TIMESTAMPTZ(6),
    "version" INTEGER NOT NULL DEFAULT 1,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "external_credential_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "outbox_event" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID,
    "aggregate_type" VARCHAR(64) NOT NULL,
    "aggregate_id" UUID NOT NULL,
    "event_type" VARCHAR(128) NOT NULL,
    "event_schema_version" INTEGER NOT NULL,
    "payload" JSONB NOT NULL,
    "dedupe_key" VARCHAR(256) NOT NULL,
    "occurred_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "available_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "claimed_at" TIMESTAMPTZ(6),
    "lease_expires_at" TIMESTAMPTZ(6),
    "processed_at" TIMESTAMPTZ(6),
    "attempt_count" INTEGER NOT NULL DEFAULT 0,
    "last_failure_category" VARCHAR(64),
    "last_failure_code" VARCHAR(64),
    "status" "outbox_event_status" NOT NULL DEFAULT 'pending',
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "outbox_event_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "background_job" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID,
    "outbox_event_id" UUID,
    "job_type" VARCHAR(128) NOT NULL,
    "status" "background_job_status" NOT NULL DEFAULT 'pending',
    "attempt" INTEGER NOT NULL DEFAULT 0,
    "started_at" TIMESTAMPTZ(6),
    "lease_expires_at" TIMESTAMPTZ(6),
    "completed_at" TIMESTAMPTZ(6),
    "failure_category" VARCHAR(64),
    "failure_code" VARCHAR(64),
    "worker_identifier" VARCHAR(128),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "background_job_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "idempotency_record" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "organization_id" UUID NOT NULL,
    "scope" VARCHAR(128) NOT NULL,
    "key_hash" CHAR(64) NOT NULL,
    "request_fingerprint" CHAR(64) NOT NULL,
    "status" "idempotency_record_status" NOT NULL DEFAULT 'started',
    "response_status" INTEGER,
    "response" JSONB,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(6) NOT NULL,
    "completed_at" TIMESTAMPTZ(6),

    CONSTRAINT "idempotency_record_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "organization_slug_key" ON "organization"("slug");

-- CreateIndex
CREATE INDEX "organization_status_idx" ON "organization"("status");

-- CreateIndex
CREATE UNIQUE INDEX "user_email_key" ON "user"("email");

-- CreateIndex
CREATE INDEX "user_status_idx" ON "user"("status");

-- CreateIndex
CREATE INDEX "membership_org_status_idx" ON "membership"("organization_id", "status");

-- CreateIndex
CREATE INDEX "membership_user_idx" ON "membership"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "membership_org_id_key" ON "membership"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "membership_org_user_key" ON "membership"("organization_id", "user_id");

-- CreateIndex
CREATE INDEX "team_org_status_idx" ON "team"("organization_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "team_org_id_key" ON "team"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "team_org_slug_key" ON "team"("organization_id", "slug");

-- CreateIndex
CREATE UNIQUE INDEX "team_org_name_key" ON "team"("organization_id", "name");

-- CreateIndex
CREATE INDEX "team_membership_org_user_idx" ON "team_membership"("organization_id", "user_id");

-- CreateIndex
CREATE UNIQUE INDEX "team_membership_org_id_key" ON "team_membership"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "team_membership_org_team_user_key" ON "team_membership"("organization_id", "team_id", "user_id");

-- CreateIndex
CREATE INDEX "environment_org_status_idx" ON "environment"("organization_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "environment_org_id_key" ON "environment"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "environment_org_slug_key" ON "environment"("organization_id", "slug");

-- CreateIndex
CREATE UNIQUE INDEX "environment_org_name_key" ON "environment"("organization_id", "name");

-- CreateIndex
CREATE INDEX "asset_org_status_idx" ON "asset"("organization_id", "lifecycle_status");

-- CreateIndex
CREATE INDEX "asset_org_environment_idx" ON "asset"("organization_id", "environment_id");

-- CreateIndex
CREATE INDEX "asset_org_owning_team_idx" ON "asset"("organization_id", "owning_team_id");

-- CreateIndex
CREATE INDEX "asset_org_last_observed_idx" ON "asset"("organization_id", "last_observed_at");

-- CreateIndex
CREATE UNIQUE INDEX "asset_org_id_key" ON "asset"("organization_id", "id");

-- CreateIndex
CREATE INDEX "asset_owner_org_user_idx" ON "asset_owner"("organization_id", "user_id");

-- CreateIndex
CREATE INDEX "asset_owner_org_team_idx" ON "asset_owner"("organization_id", "team_id");

-- CreateIndex
CREATE UNIQUE INDEX "asset_owner_org_id_key" ON "asset_owner"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "asset_owner_identity_key" ON "asset_owner"("organization_id", "asset_id", "role", "user_id", "team_id");

-- CreateIndex
CREATE INDEX "asset_tag_org_tag_idx" ON "asset_tag"("organization_id", "tag");

-- CreateIndex
CREATE UNIQUE INDEX "asset_tag_org_asset_tag_key" ON "asset_tag"("organization_id", "asset_id", "tag");

-- CreateIndex
CREATE UNIQUE INDEX "asset_external_id_org_asset_ns_key" ON "asset_external_identifier"("organization_id", "asset_id", "namespace");

-- CreateIndex
CREATE UNIQUE INDEX "repository_connection_org_id_key" ON "repository_connection"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "repository_connection_org_asset_key" ON "repository_connection"("organization_id", "asset_id");

-- CreateIndex
CREATE UNIQUE INDEX "sbom_object_key_key" ON "sbom"("object_key");

-- CreateIndex
CREATE INDEX "sbom_org_asset_received_idx" ON "sbom"("organization_id", "asset_id", "received_at");

-- CreateIndex
CREATE UNIQUE INDEX "sbom_org_id_key" ON "sbom"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "sbom_org_asset_sha256_key" ON "sbom"("organization_id", "asset_id", "sha256");

-- CreateIndex
CREATE INDEX "sbom_ingestion_org_state_idx" ON "sbom_ingestion"("organization_id", "state", "created_at");

-- CreateIndex
CREATE INDEX "sbom_ingestion_org_sbom_parser_idx" ON "sbom_ingestion"("organization_id", "sbom_id", "parser_version");

-- CreateIndex
CREATE UNIQUE INDEX "sbom_ingestion_org_id_key" ON "sbom_ingestion"("organization_id", "id");

-- CreateIndex
CREATE INDEX "component_org_ecosystem_name_idx" ON "component"("organization_id", "ecosystem", "name");

-- CreateIndex
CREATE UNIQUE INDEX "component_org_id_key" ON "component"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "component_org_identity_key" ON "component"("organization_id", "identity_key");

-- CreateIndex
CREATE INDEX "component_occurrence_org_sbom_idx" ON "component_occurrence"("organization_id", "sbom_id");

-- CreateIndex
CREATE INDEX "component_occurrence_org_component_idx" ON "component_occurrence"("organization_id", "component_id");

-- CreateIndex
CREATE UNIQUE INDEX "component_occurrence_org_id_key" ON "component_occurrence"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "component_occurrence_identity_key" ON "component_occurrence"("organization_id", "sbom_ingestion_id", "component_id", "version");

-- CreateIndex
CREATE INDEX "dependency_relationship_from_idx" ON "dependency_relationship"("organization_id", "from_occurrence_id");

-- CreateIndex
CREATE INDEX "dependency_relationship_to_idx" ON "dependency_relationship"("organization_id", "to_occurrence_id");

-- CreateIndex
CREATE UNIQUE INDEX "dependency_relationship_edge_key" ON "dependency_relationship"("organization_id", "sbom_ingestion_id", "from_occurrence_id", "to_occurrence_id", "relationship_type");

-- CreateIndex
CREATE UNIQUE INDEX "vulnerability_osv_id_key" ON "vulnerability"("osv_id");

-- CreateIndex
CREATE INDEX "vulnerability_cve_idx" ON "vulnerability"("cve_id");

-- CreateIndex
CREATE INDEX "vulnerability_alias_alias_idx" ON "vulnerability_alias"("alias");

-- CreateIndex
CREATE UNIQUE INDEX "vulnerability_alias_vuln_alias_key" ON "vulnerability_alias"("vulnerability_id", "alias");

-- CreateIndex
CREATE INDEX "vulnerability_source_record_vuln_retrieved_idx" ON "vulnerability_source_record"("vulnerability_id", "retrieved_at");

-- CreateIndex
CREATE INDEX "vulnerability_source_record_provider_idx" ON "vulnerability_source_record"("source", "source_identity");

-- CreateIndex
CREATE UNIQUE INDEX "vulnerability_source_record_provenance_key" ON "vulnerability_source_record"("source", "source_identity", "payload_sha256");

-- CreateIndex
CREATE INDEX "finding_org_state_idx" ON "finding"("organization_id", "state");

-- CreateIndex
CREATE INDEX "finding_org_asset_idx" ON "finding"("organization_id", "asset_id");

-- CreateIndex
CREATE INDEX "finding_org_vulnerability_idx" ON "finding"("organization_id", "vulnerability_id");

-- CreateIndex
CREATE INDEX "finding_org_assignee_idx" ON "finding"("organization_id", "assigned_user_id");

-- CreateIndex
CREATE INDEX "finding_org_due_idx" ON "finding"("organization_id", "due_at");

-- CreateIndex
CREATE UNIQUE INDEX "finding_org_id_key" ON "finding"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "finding_identity_key" ON "finding"("organization_id", "asset_id", "component_id", "vulnerability_id");

-- CreateIndex
CREATE INDEX "finding_observation_finding_time_idx" ON "finding_observation"("organization_id", "finding_id", "observed_at");

-- CreateIndex
CREATE UNIQUE INDEX "finding_observation_identity_key" ON "finding_observation"("organization_id", "finding_id", "sbom_ingestion_id");

-- CreateIndex
CREATE INDEX "risk_policy_org_key_version_idx" ON "risk_policy"("organization_id", "policy_key", "version");

-- CreateIndex
CREATE INDEX "risk_policy_org_status_idx" ON "risk_policy"("organization_id", "status");

-- CreateIndex
CREATE UNIQUE INDEX "risk_policy_org_id_key" ON "risk_policy"("organization_id", "id");

-- CreateIndex
CREATE INDEX "risk_calculation_finding_time_idx" ON "risk_calculation"("organization_id", "finding_id", "calculated_at");

-- CreateIndex
CREATE UNIQUE INDEX "risk_calculation_org_id_key" ON "risk_calculation"("organization_id", "id");

-- CreateIndex
CREATE UNIQUE INDEX "risk_calculation_replay_key" ON "risk_calculation"("organization_id", "finding_id", "input_fingerprint");

-- CreateIndex
CREATE INDEX "remediation_task_org_status_idx" ON "remediation_task"("organization_id", "status");

-- CreateIndex
CREATE INDEX "remediation_task_org_assignee_idx" ON "remediation_task"("organization_id", "assigned_user_id");

-- CreateIndex
CREATE INDEX "remediation_task_org_due_idx" ON "remediation_task"("organization_id", "due_at");

-- CreateIndex
CREATE UNIQUE INDEX "remediation_task_org_id_key" ON "remediation_task"("organization_id", "id");

-- CreateIndex
CREATE INDEX "risk_acceptance_org_finding_status_idx" ON "risk_acceptance"("organization_id", "finding_id", "status");

-- CreateIndex
CREATE INDEX "risk_acceptance_org_expires_idx" ON "risk_acceptance"("organization_id", "expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "risk_acceptance_org_id_key" ON "risk_acceptance"("organization_id", "id");

-- CreateIndex
CREATE INDEX "evidence_org_kind_idx" ON "evidence"("organization_id", "kind", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "evidence_org_id_key" ON "evidence"("organization_id", "id");

-- CreateIndex
CREATE INDEX "audit_event_org_time_idx" ON "audit_event"("organization_id", "occurred_at");

-- CreateIndex
CREATE INDEX "audit_event_org_subject_idx" ON "audit_event"("organization_id", "subject_type", "subject_id");

-- CreateIndex
CREATE INDEX "integration_org_provider_idx" ON "integration"("organization_id", "provider_key");

-- CreateIndex
CREATE UNIQUE INDEX "integration_org_id_key" ON "integration"("organization_id", "id");

-- CreateIndex
CREATE INDEX "external_credential_org_integration_idx" ON "external_credential"("organization_id", "integration_id");

-- CreateIndex
CREATE UNIQUE INDEX "external_credential_org_id_key" ON "external_credential"("organization_id", "id");

-- CreateIndex
CREATE INDEX "outbox_event_claim_idx" ON "outbox_event"("status", "available_at");

-- CreateIndex
CREATE INDEX "outbox_event_org_type_idx" ON "outbox_event"("organization_id", "event_type");

-- CreateIndex
CREATE UNIQUE INDEX "outbox_event_org_id_key" ON "outbox_event"("organization_id", "id");

-- CreateIndex
CREATE INDEX "background_job_org_status_idx" ON "background_job"("organization_id", "status");

-- CreateIndex
CREATE INDEX "background_job_lease_idx" ON "background_job"("status", "lease_expires_at");

-- CreateIndex
CREATE INDEX "background_job_outbox_idx" ON "background_job"("outbox_event_id");

-- CreateIndex
CREATE INDEX "idempotency_record_expires_idx" ON "idempotency_record"("expires_at");

-- CreateIndex
CREATE UNIQUE INDEX "idempotency_record_org_scope_key" ON "idempotency_record"("organization_id", "scope", "key_hash");

-- AddForeignKey
ALTER TABLE "membership" ADD CONSTRAINT "membership_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "membership" ADD CONSTRAINT "membership_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "team" ADD CONSTRAINT "team_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "team_membership" ADD CONSTRAINT "team_membership_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "team_membership" ADD CONSTRAINT "team_membership_organization_id_team_id_fkey" FOREIGN KEY ("organization_id", "team_id") REFERENCES "team"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "team_membership" ADD CONSTRAINT "team_membership_organization_id_user_id_fkey" FOREIGN KEY ("organization_id", "user_id") REFERENCES "membership"("organization_id", "user_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "team_membership" ADD CONSTRAINT "team_membership_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "environment" ADD CONSTRAINT "environment_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset" ADD CONSTRAINT "asset_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset" ADD CONSTRAINT "asset_organization_id_environment_id_fkey" FOREIGN KEY ("organization_id", "environment_id") REFERENCES "environment"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset" ADD CONSTRAINT "asset_organization_id_owning_team_id_fkey" FOREIGN KEY ("organization_id", "owning_team_id") REFERENCES "team"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset" ADD CONSTRAINT "asset_organization_id_last_successful_sbom_ingestion_id_fkey" FOREIGN KEY ("organization_id", "last_successful_sbom_ingestion_id") REFERENCES "sbom_ingestion"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_owner" ADD CONSTRAINT "asset_owner_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_owner" ADD CONSTRAINT "asset_owner_organization_id_asset_id_fkey" FOREIGN KEY ("organization_id", "asset_id") REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_owner" ADD CONSTRAINT "asset_owner_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_owner" ADD CONSTRAINT "asset_owner_organization_id_team_id_fkey" FOREIGN KEY ("organization_id", "team_id") REFERENCES "team"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_owner" ADD CONSTRAINT "asset_owner_organization_id_user_id_fkey" FOREIGN KEY ("organization_id", "user_id") REFERENCES "membership"("organization_id", "user_id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_tag" ADD CONSTRAINT "asset_tag_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_tag" ADD CONSTRAINT "asset_tag_organization_id_asset_id_fkey" FOREIGN KEY ("organization_id", "asset_id") REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_external_identifier" ADD CONSTRAINT "asset_external_identifier_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "asset_external_identifier" ADD CONSTRAINT "asset_external_identifier_organization_id_asset_id_fkey" FOREIGN KEY ("organization_id", "asset_id") REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repository_connection" ADD CONSTRAINT "repository_connection_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repository_connection" ADD CONSTRAINT "repository_connection_organization_id_asset_id_fkey" FOREIGN KEY ("organization_id", "asset_id") REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "repository_connection" ADD CONSTRAINT "repository_connection_organization_id_integration_id_fkey" FOREIGN KEY ("organization_id", "integration_id") REFERENCES "integration"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sbom" ADD CONSTRAINT "sbom_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sbom" ADD CONSTRAINT "sbom_organization_id_asset_id_fkey" FOREIGN KEY ("organization_id", "asset_id") REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sbom" ADD CONSTRAINT "sbom_uploaded_by_user_id_fkey" FOREIGN KEY ("uploaded_by_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sbom_ingestion" ADD CONSTRAINT "sbom_ingestion_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sbom_ingestion" ADD CONSTRAINT "sbom_ingestion_organization_id_sbom_id_fkey" FOREIGN KEY ("organization_id", "sbom_id") REFERENCES "sbom"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sbom_ingestion" ADD CONSTRAINT "sbom_ingestion_organization_id_asset_id_fkey" FOREIGN KEY ("organization_id", "asset_id") REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "component" ADD CONSTRAINT "component_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "component_occurrence" ADD CONSTRAINT "component_occurrence_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "component_occurrence" ADD CONSTRAINT "component_occurrence_organization_id_sbom_id_fkey" FOREIGN KEY ("organization_id", "sbom_id") REFERENCES "sbom"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "component_occurrence" ADD CONSTRAINT "component_occurrence_organization_id_sbom_ingestion_id_fkey" FOREIGN KEY ("organization_id", "sbom_ingestion_id") REFERENCES "sbom_ingestion"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "component_occurrence" ADD CONSTRAINT "component_occurrence_organization_id_component_id_fkey" FOREIGN KEY ("organization_id", "component_id") REFERENCES "component"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "dependency_relationship" ADD CONSTRAINT "dependency_relationship_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "dependency_relationship" ADD CONSTRAINT "dependency_relationship_organization_id_sbom_id_fkey" FOREIGN KEY ("organization_id", "sbom_id") REFERENCES "sbom"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "dependency_relationship" ADD CONSTRAINT "dependency_relationship_organization_id_sbom_ingestion_id_fkey" FOREIGN KEY ("organization_id", "sbom_ingestion_id") REFERENCES "sbom_ingestion"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "dependency_relationship" ADD CONSTRAINT "dependency_relationship_organization_id_from_occurrence_id_fkey" FOREIGN KEY ("organization_id", "from_occurrence_id") REFERENCES "component_occurrence"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "dependency_relationship" ADD CONSTRAINT "dependency_relationship_organization_id_to_occurrence_id_fkey" FOREIGN KEY ("organization_id", "to_occurrence_id") REFERENCES "component_occurrence"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vulnerability_alias" ADD CONSTRAINT "vulnerability_alias_vulnerability_id_fkey" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vulnerability_source_record" ADD CONSTRAINT "vulnerability_source_record_vulnerability_id_fkey" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vulnerability_source_record" ADD CONSTRAINT "vulnerability_source_record_supersedes_record_id_fkey" FOREIGN KEY ("supersedes_record_id") REFERENCES "vulnerability_source_record"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding" ADD CONSTRAINT "finding_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding" ADD CONSTRAINT "finding_organization_id_asset_id_fkey" FOREIGN KEY ("organization_id", "asset_id") REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding" ADD CONSTRAINT "finding_vulnerability_id_fkey" FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding" ADD CONSTRAINT "finding_organization_id_component_id_fkey" FOREIGN KEY ("organization_id", "component_id") REFERENCES "component"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding" ADD CONSTRAINT "finding_organization_id_component_occurrence_id_fkey" FOREIGN KEY ("organization_id", "component_occurrence_id") REFERENCES "component_occurrence"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding" ADD CONSTRAINT "finding_assigned_user_id_fkey" FOREIGN KEY ("assigned_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding" ADD CONSTRAINT "finding_organization_id_assigned_team_id_fkey" FOREIGN KEY ("organization_id", "assigned_team_id") REFERENCES "team"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding" ADD CONSTRAINT "finding_organization_id_current_risk_calculation_id_fkey" FOREIGN KEY ("organization_id", "current_risk_calculation_id") REFERENCES "risk_calculation"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_observation" ADD CONSTRAINT "finding_observation_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_observation" ADD CONSTRAINT "finding_observation_organization_id_finding_id_fkey" FOREIGN KEY ("organization_id", "finding_id") REFERENCES "finding"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_observation" ADD CONSTRAINT "finding_observation_organization_id_sbom_id_fkey" FOREIGN KEY ("organization_id", "sbom_id") REFERENCES "sbom"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_observation" ADD CONSTRAINT "finding_observation_organization_id_sbom_ingestion_id_fkey" FOREIGN KEY ("organization_id", "sbom_ingestion_id") REFERENCES "sbom_ingestion"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "finding_observation" ADD CONSTRAINT "finding_observation_organization_id_occurrence_id_fkey" FOREIGN KEY ("organization_id", "occurrence_id") REFERENCES "component_occurrence"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_policy" ADD CONSTRAINT "risk_policy_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_policy" ADD CONSTRAINT "risk_policy_created_by_user_id_fkey" FOREIGN KEY ("created_by_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_calculation" ADD CONSTRAINT "risk_calculation_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_calculation" ADD CONSTRAINT "risk_calculation_organization_id_finding_id_fkey" FOREIGN KEY ("organization_id", "finding_id") REFERENCES "finding"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_calculation" ADD CONSTRAINT "risk_calculation_risk_policy_id_fkey" FOREIGN KEY ("risk_policy_id") REFERENCES "risk_policy"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_calculation" ADD CONSTRAINT "risk_calculation_organization_id_sbom_ingestion_id_fkey" FOREIGN KEY ("organization_id", "sbom_ingestion_id") REFERENCES "sbom_ingestion"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediation_task" ADD CONSTRAINT "remediation_task_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediation_task" ADD CONSTRAINT "remediation_task_organization_id_finding_id_fkey" FOREIGN KEY ("organization_id", "finding_id") REFERENCES "finding"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediation_task" ADD CONSTRAINT "remediation_task_assigned_user_id_fkey" FOREIGN KEY ("assigned_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediation_task" ADD CONSTRAINT "remediation_task_organization_id_assigned_team_id_fkey" FOREIGN KEY ("organization_id", "assigned_team_id") REFERENCES "team"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_acceptance" ADD CONSTRAINT "risk_acceptance_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_acceptance" ADD CONSTRAINT "risk_acceptance_organization_id_finding_id_fkey" FOREIGN KEY ("organization_id", "finding_id") REFERENCES "finding"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_acceptance" ADD CONSTRAINT "risk_acceptance_requested_by_user_id_fkey" FOREIGN KEY ("requested_by_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "risk_acceptance" ADD CONSTRAINT "risk_acceptance_approved_by_user_id_fkey" FOREIGN KEY ("approved_by_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_organization_id_finding_id_fkey" FOREIGN KEY ("organization_id", "finding_id") REFERENCES "finding"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_organization_id_sbom_id_fkey" FOREIGN KEY ("organization_id", "sbom_id") REFERENCES "sbom"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_organization_id_asset_id_fkey" FOREIGN KEY ("organization_id", "asset_id") REFERENCES "asset"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_submitted_by_user_id_fkey" FOREIGN KEY ("submitted_by_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_event" ADD CONSTRAINT "audit_event_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "audit_event" ADD CONSTRAINT "audit_event_actor_user_id_fkey" FOREIGN KEY ("actor_user_id") REFERENCES "user"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "integration" ADD CONSTRAINT "integration_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "external_credential" ADD CONSTRAINT "external_credential_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "external_credential" ADD CONSTRAINT "external_credential_organization_id_integration_id_fkey" FOREIGN KEY ("organization_id", "integration_id") REFERENCES "integration"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "outbox_event" ADD CONSTRAINT "outbox_event_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "background_job" ADD CONSTRAINT "background_job_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "background_job" ADD CONSTRAINT "background_job_outbox_event_id_fkey" FOREIGN KEY ("outbox_event_id") REFERENCES "outbox_event"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "idempotency_record" ADD CONSTRAINT "idempotency_record_organization_id_fkey" FOREIGN KEY ("organization_id") REFERENCES "organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;


-- Additional PostgreSQL constraints, indexes, triggers, and SchemaFoundation removal.
-- Prisma cannot express these natively. See docs/architecture/database-model.md.

-- Slug and email normalization
ALTER TABLE "organization"
  ADD CONSTRAINT organization_slug_shape_chk
  CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) BETWEEN 2 AND 64);

ALTER TABLE "organization"
  ADD CONSTRAINT organization_version_chk CHECK (version >= 1);

ALTER TABLE "organization"
  ADD CONSTRAINT organization_archive_consistency_chk
  CHECK (
    (status = 'archived' AND archived_at IS NOT NULL)
    OR (status = 'active' AND archived_at IS NULL)
  );

ALTER TABLE "user"
  ADD CONSTRAINT user_email_lower_chk CHECK (email = lower(email));

ALTER TABLE "user"
  ADD CONSTRAINT user_version_chk CHECK (version >= 1);

ALTER TABLE "user"
  ADD CONSTRAINT user_disabled_consistency_chk
  CHECK (
    (status = 'disabled' AND disabled_at IS NOT NULL)
    OR (status = 'active' AND disabled_at IS NULL)
  );

ALTER TABLE "membership"
  ADD CONSTRAINT membership_version_chk CHECK (version >= 1);

ALTER TABLE "membership"
  ADD CONSTRAINT membership_revoked_consistency_chk
  CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL)
    OR (status = 'active' AND revoked_at IS NULL)
  );

ALTER TABLE "team"
  ADD CONSTRAINT team_slug_shape_chk
  CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) BETWEEN 2 AND 64);

ALTER TABLE "team"
  ADD CONSTRAINT team_version_chk CHECK (version >= 1);

ALTER TABLE "environment"
  ADD CONSTRAINT environment_slug_shape_chk
  CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' AND char_length(slug) BETWEEN 2 AND 64);

ALTER TABLE "environment"
  ADD CONSTRAINT environment_version_chk CHECK (version >= 1);

-- Asset
ALTER TABLE "asset"
  ADD CONSTRAINT asset_version_chk CHECK (version >= 1);

ALTER TABLE "asset"
  ADD CONSTRAINT asset_archive_consistency_chk
  CHECK (
    (lifecycle_status = 'archived' AND archived_at IS NOT NULL)
    OR (lifecycle_status = 'active' AND archived_at IS NULL)
  );

CREATE UNIQUE INDEX asset_active_name_org_idx
  ON "asset" (organization_id, lower(name))
  WHERE lifecycle_status = 'active';

ALTER TABLE "asset_owner"
  ADD CONSTRAINT asset_owner_target_chk
  CHECK (user_id IS NOT NULL OR team_id IS NOT NULL);

ALTER TABLE "asset_tag"
  ADD CONSTRAINT asset_tag_shape_chk
  CHECK (tag = lower(tag) AND char_length(tag) BETWEEN 1 AND 64 AND tag ~ '^[a-z0-9]+(-[a-z0-9]+)*$');

-- SBOM evidence
ALTER TABLE "sbom"
  ADD CONSTRAINT sbom_sha256_chk CHECK (sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE "sbom"
  ADD CONSTRAINT sbom_byte_length_chk CHECK (byte_length > 0);

ALTER TABLE "sbom"
  ADD CONSTRAINT sbom_spec_version_chk
  CHECK (specification_version IS NULL OR specification_version IN ('1.4', '1.5', '1.6'));

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_attempt_chk CHECK (attempt_number >= 1);

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_version_chk CHECK (version >= 1);

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_failure_code_chk
  CHECK (
    (state IN ('failed', 'rejected', 'quarantined') AND failure_code IS NOT NULL)
    OR state NOT IN ('failed', 'rejected', 'quarantined')
  );

ALTER TABLE "sbom_ingestion"
  ADD CONSTRAINT sbom_ingestion_completed_ts_chk
  CHECK (
    (state = 'completed' AND completed_at IS NOT NULL)
    OR state <> 'completed'
  );

ALTER TABLE "dependency_relationship"
  ADD CONSTRAINT dependency_relationship_not_self_chk
  CHECK (from_occurrence_id <> to_occurrence_id);

-- Intelligence
ALTER TABLE "vulnerability_source_record"
  ADD CONSTRAINT vulnerability_source_record_sha256_chk
  CHECK (payload_sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE "vulnerability_source_record"
  ADD CONSTRAINT vulnerability_source_record_normalized_schema_chk
  CHECK (
    jsonb_typeof(normalized) = 'object'
    AND (normalized->>'schemaVersion') IS NOT NULL
  );

-- Findings
ALTER TABLE "finding"
  ADD CONSTRAINT finding_version_chk CHECK (version >= 1);

ALTER TABLE "finding"
  ADD CONSTRAINT finding_resolved_ts_chk
  CHECK (
    (state = 'resolved' AND resolved_at IS NOT NULL)
    OR state <> 'resolved'
  );

ALTER TABLE "finding_observation"
  ADD CONSTRAINT finding_observation_evidence_schema_chk
  CHECK (
    jsonb_typeof(evidence) = 'object'
    AND (evidence->>'schemaVersion') IS NOT NULL
  );

-- Risk policy and calculations
ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_version_chk CHECK (version >= 1);

ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_schema_version_chk CHECK (policy_schema_version >= 1);

ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_definition_schema_chk
  CHECK (
    jsonb_typeof(definition) = 'object'
    AND (definition->>'schemaVersion') IS NOT NULL
  );

CREATE UNIQUE INDEX risk_policy_builtin_key_version_uidx
  ON "risk_policy" (policy_key, version)
  WHERE organization_id IS NULL;

CREATE UNIQUE INDEX risk_policy_org_key_version_uidx
  ON "risk_policy" (organization_id, policy_key, version)
  WHERE organization_id IS NOT NULL;

ALTER TABLE "risk_calculation"
  ADD CONSTRAINT risk_calculation_policy_sha256_chk
  CHECK (policy_definition_sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE "risk_calculation"
  ADD CONSTRAINT risk_calculation_input_fingerprint_chk
  CHECK (input_fingerprint ~ '^[a-f0-9]{64}$');

ALTER TABLE "risk_calculation"
  ADD CONSTRAINT risk_calculation_json_schema_chk
  CHECK (
    jsonb_typeof(factors) = 'object'
    AND (factors->>'schemaVersion') IS NOT NULL
    AND jsonb_typeof(result) = 'object'
    AND (result->>'schemaVersion') IS NOT NULL
  );

-- Remediation
ALTER TABLE "remediation_task"
  ADD CONSTRAINT remediation_task_version_chk CHECK (version >= 1);

ALTER TABLE "remediation_task"
  ADD CONSTRAINT remediation_task_completed_ts_chk
  CHECK (
    (status = 'completed' AND completed_at IS NOT NULL)
    OR status <> 'completed'
  );

ALTER TABLE "remediation_task"
  ADD CONSTRAINT remediation_task_cancelled_ts_chk
  CHECK (
    (status = 'cancelled' AND cancelled_at IS NOT NULL)
    OR status <> 'cancelled'
  );

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_expiration_chk CHECK (expires_at > starts_at);

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_review_chk CHECK (review_at < expires_at AND review_at >= starts_at);

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_approval_chk
  CHECK (
    (approved_by_user_id IS NULL) = (approved_at IS NULL)
  );

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_active_approval_chk
  CHECK (
    (status = 'active' AND approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL)
    OR status <> 'active'
  );

ALTER TABLE "risk_acceptance"
  ADD CONSTRAINT risk_acceptance_revocation_chk
  CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    OR (status <> 'revoked' AND revoked_at IS NULL AND revocation_reason IS NULL)
  );

CREATE UNIQUE INDEX risk_acceptance_one_active_per_finding_idx
  ON "risk_acceptance" (organization_id, finding_id)
  WHERE status = 'active';

-- Evidence
ALTER TABLE "evidence"
  ADD CONSTRAINT evidence_one_target_chk
  CHECK (
    (kind = 'sbom_object' AND sbom_id IS NOT NULL AND finding_id IS NULL AND asset_id IS NULL)
    OR (
      kind IN ('kev_match', 'intel_record', 'policy_snapshot', 'compensating_control')
      AND finding_id IS NOT NULL
      AND sbom_id IS NULL
      AND asset_id IS NULL
    )
  );

ALTER TABLE "evidence"
  ADD CONSTRAINT evidence_sha256_chk
  CHECK (sha256 IS NULL OR sha256 ~ '^[a-f0-9]{64}$');

ALTER TABLE "evidence"
  ADD CONSTRAINT evidence_byte_length_chk
  CHECK (byte_length IS NULL OR byte_length > 0);

ALTER TABLE "evidence"
  ADD CONSTRAINT evidence_metadata_schema_chk
  CHECK (
    jsonb_typeof(metadata) = 'object'
    AND (metadata->>'schemaVersion') IS NOT NULL
  );

-- Audit
ALTER TABLE "audit_event"
  ADD CONSTRAINT audit_event_payload_schema_chk
  CHECK (
    jsonb_typeof(payload) = 'object'
    AND (payload->>'schemaVersion') IS NOT NULL
  );

ALTER TABLE "audit_event"
  ADD CONSTRAINT audit_event_schema_version_chk CHECK (schema_version >= 1);

CREATE UNIQUE INDEX audit_event_tenant_replay_idx
  ON "audit_event" (organization_id, action, subject_id, correlation_id)
  WHERE organization_id IS NOT NULL;

CREATE UNIQUE INDEX audit_event_system_replay_idx
  ON "audit_event" (action, subject_id, correlation_id)
  WHERE organization_id IS NULL;

-- Integration / credentials
ALTER TABLE "integration"
  ADD CONSTRAINT integration_version_chk CHECK (version >= 1);

ALTER TABLE "integration"
  ADD CONSTRAINT integration_config_schema_chk
  CHECK (
    jsonb_typeof(config) = 'object'
    AND (config->>'schemaVersion') IS NOT NULL
  );

ALTER TABLE "external_credential"
  ADD CONSTRAINT external_credential_version_chk CHECK (version >= 1);

-- Outbox
ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_attempt_chk CHECK (attempt_count >= 0);

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_schema_version_chk CHECK (event_schema_version >= 1);

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_payload_schema_chk
  CHECK (
    jsonb_typeof(payload) = 'object'
    AND (payload->>'schemaVersion') IS NOT NULL
  );

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_processed_ts_chk
  CHECK (
    (status = 'processed' AND processed_at IS NOT NULL)
    OR status <> 'processed'
  );

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_lease_chk
  CHECK (
    (status = 'claimed' AND claimed_at IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR status <> 'claimed'
  );

ALTER TABLE "outbox_event"
  ADD CONSTRAINT outbox_event_failed_code_chk
  CHECK (
    (status IN ('failed', 'dead_lettered') AND last_failure_code IS NOT NULL)
    OR status NOT IN ('failed', 'dead_lettered')
  );

CREATE UNIQUE INDEX outbox_event_tenant_dedupe_idx
  ON "outbox_event" (organization_id, dedupe_key)
  WHERE organization_id IS NOT NULL;

CREATE UNIQUE INDEX outbox_event_system_dedupe_idx
  ON "outbox_event" (event_type, dedupe_key)
  WHERE organization_id IS NULL;

CREATE INDEX outbox_event_available_work_idx
  ON "outbox_event" (available_at, id)
  WHERE status = 'pending';

-- Background jobs
ALTER TABLE "background_job"
  ADD CONSTRAINT background_job_attempt_chk CHECK (attempt >= 0);

ALTER TABLE "background_job"
  ADD CONSTRAINT background_job_failed_code_chk
  CHECK (
    (status IN ('failed', 'dead_lettered') AND failure_code IS NOT NULL)
    OR status NOT IN ('failed', 'dead_lettered')
  );

ALTER TABLE "background_job"
  ADD CONSTRAINT background_job_succeeded_ts_chk
  CHECK (
    (status = 'succeeded' AND completed_at IS NOT NULL)
    OR status <> 'succeeded'
  );

-- Idempotency
ALTER TABLE "idempotency_record"
  ADD CONSTRAINT idempotency_record_hashes_chk
  CHECK (key_hash ~ '^[a-f0-9]{64}$' AND request_fingerprint ~ '^[a-f0-9]{64}$');

ALTER TABLE "idempotency_record"
  ADD CONSTRAINT idempotency_record_expiry_chk CHECK (expires_at > created_at);

ALTER TABLE "idempotency_record"
  ADD CONSTRAINT idempotency_record_completed_ts_chk
  CHECK (
    (status = 'completed' AND completed_at IS NOT NULL)
    OR status <> 'completed'
  );

-- Append-only enforcement. Database roles with table privileges still cannot UPDATE/DELETE
-- through the application role. Superusers can bypass this; it is not WORM storage.
CREATE OR REPLACE FUNCTION patchpilot_forbid_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'append-only table % does not allow %', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER audit_event_append_only
  BEFORE UPDATE OR DELETE ON "audit_event"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER finding_observation_append_only
  BEFORE UPDATE OR DELETE ON "finding_observation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER risk_calculation_append_only
  BEFORE UPDATE OR DELETE ON "risk_calculation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER vulnerability_source_record_append_only
  BEFORE UPDATE OR DELETE ON "vulnerability_source_record"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER evidence_append_only
  BEFORE UPDATE OR DELETE ON "evidence"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE OR REPLACE FUNCTION patchpilot_protect_published_risk_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.published_at IS NOT NULL THEN
    IF NEW.definition IS DISTINCT FROM OLD.definition
      OR NEW.policy_key IS DISTINCT FROM OLD.policy_key
      OR NEW.version IS DISTINCT FROM OLD.version
      OR NEW.organization_id IS DISTINCT FROM OLD.organization_id THEN
      RAISE EXCEPTION 'published risk policies are immutable'
        USING ERRCODE = 'restrict_violation';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER risk_policy_published_immutable
  BEFORE UPDATE ON "risk_policy"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_published_risk_policy();

CREATE OR REPLACE FUNCTION patchpilot_protect_sbom_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.sha256 IS DISTINCT FROM OLD.sha256
    OR NEW.object_key IS DISTINCT FROM OLD.object_key
    OR NEW.byte_length IS DISTINCT FROM OLD.byte_length
    OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
    OR NEW.asset_id IS DISTINCT FROM OLD.asset_id THEN
    RAISE EXCEPTION 'SBOM identity fields are immutable'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER sbom_identity_immutable
  BEFORE UPDATE ON "sbom"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_protect_sbom_identity();

CREATE OR REPLACE FUNCTION patchpilot_risk_policy_org_consistency()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  policy_org uuid;
BEGIN
  SELECT organization_id INTO policy_org FROM "risk_policy" WHERE id = NEW.risk_policy_id;
  IF policy_org IS NOT NULL AND policy_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'risk policy organization does not match calculation organization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER risk_calculation_policy_org_consistency
  BEFORE INSERT OR UPDATE ON "risk_calculation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_risk_policy_org_consistency();

CREATE OR REPLACE FUNCTION patchpilot_job_outbox_org_consistency()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  outbox_org uuid;
BEGIN
  IF NEW.outbox_event_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT organization_id INTO outbox_org FROM "outbox_event" WHERE id = NEW.outbox_event_id;
  IF outbox_org IS DISTINCT FROM NEW.organization_id THEN
    RAISE EXCEPTION 'background job organization does not match outbox event organization'
      USING ERRCODE = 'restrict_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER background_job_outbox_org_consistency
  BEFORE INSERT OR UPDATE ON "background_job"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_job_outbox_org_consistency();

-- Remove Session 3 technical scaffolding. The original migration is unchanged.
DROP TABLE IF EXISTS "SchemaFoundation";
