-- Reviewer Approval Capability Batch 2.
-- One immutable issuance row and one append-only terminal observation.
-- No seeds, Findings, product-match rows, jobs, or provider activation.

CREATE OR REPLACE FUNCTION patchpilot_reviewer_capability_is_expired(
  expires_at timestamp with time zone,
  db_now timestamp with time zone
) RETURNS boolean
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, public
AS $$
  SELECT db_now >= expires_at;
$$;

CREATE TABLE "reviewer_capability_issuance" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "issuance_schema_version" VARCHAR(80) NOT NULL,
  "capability_policy_id" VARCHAR(80) NOT NULL,
  "capability_policy_version" SMALLINT NOT NULL,
  "approval_policy_id" VARCHAR(80) NOT NULL,
  "approval_policy_version" SMALLINT NOT NULL,
  "approval_purpose" VARCHAR(80) NOT NULL,
  "issuer_authorization_id" UUID NOT NULL,
  "issuer_decision_fingerprint" TEXT NOT NULL,
  "approval_claim_fingerprint" TEXT NOT NULL,
  "advisory_family_identity" TEXT NOT NULL,
  "advisory_revision_id" UUID NOT NULL,
  "content_fingerprint" TEXT NOT NULL,
  "affected_range_fingerprint" TEXT NOT NULL,
  "npm_package_identity" VARCHAR(1024) NOT NULL,
  "vulnerability_id" UUID NOT NULL,
  "source_license_policy_id" VARCHAR(80) NOT NULL,
  "source_license_policy_version" SMALLINT NOT NULL,
  "approved_license_classification" VARCHAR(32) NOT NULL,
  "license_decision_canonical" TEXT NOT NULL,
  "source_classification" VARCHAR(64) NOT NULL,
  "author_identity" VARCHAR(128) NOT NULL,
  "reviewer_identity" VARCHAR(128) NOT NULL,
  "correlation_id" UUID NOT NULL,
  "issued_at" TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
  "expires_at" TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT "reviewer_capability_issuance_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "reviewer_capability_issuance_authorization_uidx" UNIQUE ("issuer_authorization_id"),
  CONSTRAINT "reviewer_capability_issuance_claim_uidx" UNIQUE ("approval_claim_fingerprint"),
  CONSTRAINT "reviewer_capability_issuance_ttl_chk" CHECK (
    "expires_at" = "issued_at" + interval '900 seconds'
  ),
  CONSTRAINT "reviewer_capability_issuance_separation_chk" CHECK (
    "author_identity" <> "reviewer_identity"
    AND lower("author_identity") <> lower("reviewer_identity")
  ),
  CONSTRAINT "reviewer_capability_issuance_identity_chk" CHECK (
    "author_identity" ~ '^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$'
    AND "reviewer_identity" ~ '^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$'
  ),
  CONSTRAINT "reviewer_capability_issuance_fingerprint_chk" CHECK (
    "issuer_decision_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "approval_claim_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "advisory_family_identity" ~ '^[a-f0-9]{64}$'
    AND "content_fingerprint" ~ '^[a-f0-9]{64}$'
    AND "affected_range_fingerprint" ~ '^[a-f0-9]{64}$'
  ),
  CONSTRAINT "reviewer_capability_issuance_policy_chk" CHECK (
    "issuance_schema_version" = 'reviewer_approval_capability_v1'
    AND "capability_policy_id" = 'reviewer_approval_capability_policy_v1'
    AND "capability_policy_version" = 1
    AND "approval_policy_id" = 'maintainer_reviewed_advisory_approval_policy_v1'
    AND "approval_policy_version" = 1
    AND "approval_purpose" = 'approve_maintainer_reviewed_advisory_for_product_evaluation'
    AND "source_classification" = 'maintainer_reviewed_advisory'
    AND "source_license_policy_id" = 'maintainer_reviewed_source_license_policy_v1'
    AND "source_license_policy_version" = 1
    AND "approved_license_classification" = 'CC-BY-4.0'
    AND "license_decision_canonical" = '6:policy44:maintainer_reviewed_source_license_policy_v1|13:policyVersion1:1|4:spdx9:CC-BY-4.0|10:productUse31:permitted_for_internal_matching|12:modification9:permitted|14:redistribution9:permitted|6:notice8:required|10:provenance19:maintainer_original|8:decision8:accepted'
    AND char_length("npm_package_identity") > 0
    AND "npm_package_identity" ~ (
      '^npm' || chr(31) || '(@[a-z0-9][a-z0-9._-]*)?' || chr(31) || '[a-z0-9][a-z0-9._-]*$'
    )
    AND split_part("npm_package_identity", chr(31), 3) <> 'node_modules'
    AND split_part("npm_package_identity", chr(31), 3) <> 'favicon.ico'
  )
);

CREATE INDEX "reviewer_capability_issuance_revision_idx"
  ON "reviewer_capability_issuance" ("advisory_revision_id");

CREATE INDEX "reviewer_capability_issuance_vulnerability_idx"
  ON "reviewer_capability_issuance" ("vulnerability_id");

ALTER TABLE "reviewer_capability_issuance"
  ADD CONSTRAINT "reviewer_capability_issuance_revision_fkey"
  FOREIGN KEY ("advisory_revision_id") REFERENCES "advisory_revision" ("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "reviewer_capability_issuance"
  ADD CONSTRAINT "reviewer_capability_issuance_vulnerability_fkey"
  FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability" ("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE "reviewer_capability_lifecycle_observation" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "capability_issuance_id" UUID NOT NULL,
  "observation_classification" VARCHAR(16) NOT NULL,
  "lifecycle_authorization_id" UUID,
  "decision_fingerprint" TEXT,
  "approval_id" UUID,
  "observed_at" TIMESTAMPTZ(6) NOT NULL DEFAULT clock_timestamp(),
  CONSTRAINT "reviewer_capability_lifecycle_observation_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "reviewer_capability_lifecycle_observation_capability_uidx" UNIQUE ("capability_issuance_id"),
  CONSTRAINT "reviewer_capability_lifecycle_observation_approval_uidx" UNIQUE ("approval_id"),
  CONSTRAINT "reviewer_capability_lifecycle_observation_classification_chk" CHECK (
    "observation_classification" IN ('consumed', 'revoked', 'cancelled')
  ),
  CONSTRAINT "reviewer_capability_lifecycle_observation_shape_chk" CHECK (
    (
      "observation_classification" = 'consumed'
      AND "approval_id" IS NOT NULL
      AND "lifecycle_authorization_id" IS NULL
      AND "decision_fingerprint" IS NULL
    )
    OR (
      "observation_classification" IN ('revoked', 'cancelled')
      AND "approval_id" IS NULL
      AND "lifecycle_authorization_id" IS NOT NULL
      AND "decision_fingerprint" ~ '^[a-f0-9]{64}$'
    )
  )
);

ALTER TABLE "reviewer_capability_lifecycle_observation"
  ADD CONSTRAINT "reviewer_capability_lifecycle_observation_capability_fkey"
  FOREIGN KEY ("capability_issuance_id") REFERENCES "reviewer_capability_issuance" ("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "reviewer_capability_lifecycle_observation"
  ADD CONSTRAINT "reviewer_capability_lifecycle_observation_approval_fkey"
  FOREIGN KEY ("approval_id") REFERENCES "maintainer_reviewed_advisory_approval" ("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE OR REPLACE FUNCTION patchpilot_reviewer_capability_issuance_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
  NEW."issued_at" := clock_timestamp();
  NEW."expires_at" := NEW."issued_at" + interval '900 seconds';
  IF NEW."issuance_schema_version" IS DISTINCT FROM 'reviewer_approval_capability_v1'
    OR NEW."capability_policy_id" IS DISTINCT FROM 'reviewer_approval_capability_policy_v1'
    OR NEW."capability_policy_version" IS DISTINCT FROM 1
    OR NEW."approval_policy_id" IS DISTINCT FROM 'maintainer_reviewed_advisory_approval_policy_v1'
    OR NEW."approval_policy_version" IS DISTINCT FROM 1
    OR NEW."approval_purpose" IS DISTINCT FROM 'approve_maintainer_reviewed_advisory_for_product_evaluation'
    OR NEW."source_classification" IS DISTINCT FROM 'maintainer_reviewed_advisory'
    OR NEW."source_license_policy_id" IS DISTINCT FROM 'maintainer_reviewed_source_license_policy_v1'
    OR NEW."source_license_policy_version" IS DISTINCT FROM 1
    OR NEW."approved_license_classification" IS DISTINCT FROM 'CC-BY-4.0'
    OR lower(NEW."author_identity") = lower(NEW."reviewer_identity")
    OR NEW."npm_package_identity" !~ (
      '^npm' || chr(31) || '(@[a-z0-9][a-z0-9._-]*)?' || chr(31) || '[a-z0-9][a-z0-9._-]*$'
    )
    OR split_part(NEW."npm_package_identity", chr(31), 3) IN ('node_modules', 'favicon.ico')
  THEN
    RAISE EXCEPTION 'reviewer capability issuance rejected'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "reviewer_capability_issuance_guard"
  BEFORE INSERT ON "reviewer_capability_issuance"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_reviewer_capability_issuance_guard();

CREATE TRIGGER "reviewer_capability_issuance_append_only"
  BEFORE UPDATE OR DELETE ON "reviewer_capability_issuance"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE OR REPLACE FUNCTION patchpilot_reviewer_capability_observation_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  cap record;
  bound_approval record;
BEGIN
  NEW."observed_at" := clock_timestamp();
  SELECT issuance."issued_at",
         issuance."expires_at",
         issuance."issuer_decision_fingerprint",
         issuance."advisory_revision_id",
         issuance."advisory_family_identity",
         issuance."approval_policy_id",
         issuance."approval_policy_version",
         issuance."approval_purpose",
         issuance."source_classification",
         issuance."author_identity",
         issuance."reviewer_identity",
         issuance."content_fingerprint",
         issuance."affected_range_fingerprint",
         issuance."npm_package_identity",
         issuance."vulnerability_id",
         issuance."source_license_policy_id",
         issuance."source_license_policy_version",
         issuance."approved_license_classification",
         issuance."license_decision_canonical"
    INTO cap
  FROM "reviewer_capability_issuance" issuance
  WHERE issuance."id" = NEW."capability_issuance_id";
  IF cap.expires_at IS NULL THEN
    RAISE EXCEPTION 'reviewer capability parent missing'
      USING ERRCODE = '23503';
  END IF;
  IF NEW."observed_at" < cap.issued_at THEN
    RAISE EXCEPTION 'reviewer capability observation time rejected'
      USING ERRCODE = '23514';
  END IF;
  IF patchpilot_reviewer_capability_is_expired(cap.expires_at, NEW."observed_at") THEN
    RAISE EXCEPTION 'reviewer_capability_expired'
      USING ERRCODE = '23514';
  END IF;
  IF NEW."observation_classification" IN ('revoked', 'cancelled')
    AND NEW."decision_fingerprint" IS DISTINCT FROM cap.issuer_decision_fingerprint
  THEN
    RAISE EXCEPTION 'reviewer capability lifecycle target rejected'
      USING ERRCODE = '23514';
  END IF;
  IF NEW."observation_classification" = 'consumed' THEN
    SELECT approval_row."advisory_revision_id",
           approval_row."family_digest",
           approval_row."approval_policy_id",
           approval_row."approval_policy_version",
           approval_row."approval_purpose",
           approval_row."source_classification",
           approval_row."author_identity",
           approval_row."reviewer_identity",
           approval_row."content_fingerprint",
           approval_row."range_fingerprint",
           approval_row."package_identity_key",
           approval_row."vulnerability_id",
           approval_row."source_license_policy_id",
           approval_row."source_license_policy_version",
           approval_row."approved_license_classification",
           approval_row."license_decision_canonical"
      INTO bound_approval
    FROM "maintainer_reviewed_advisory_approval" approval_row
    WHERE approval_row."id" = NEW."approval_id";
    IF bound_approval.advisory_revision_id IS NULL
      OR bound_approval.advisory_revision_id IS DISTINCT FROM cap.advisory_revision_id
      OR bound_approval.family_digest IS DISTINCT FROM cap.advisory_family_identity
      OR bound_approval.approval_policy_id IS DISTINCT FROM cap.approval_policy_id
      OR bound_approval.approval_policy_version IS DISTINCT FROM cap.approval_policy_version
      OR bound_approval.approval_purpose IS DISTINCT FROM cap.approval_purpose
      OR bound_approval.source_classification IS DISTINCT FROM cap.source_classification
      OR bound_approval.author_identity IS DISTINCT FROM cap.author_identity
      OR bound_approval.reviewer_identity IS DISTINCT FROM cap.reviewer_identity
      OR bound_approval.content_fingerprint IS DISTINCT FROM cap.content_fingerprint
      OR bound_approval.range_fingerprint IS DISTINCT FROM cap.affected_range_fingerprint
      OR bound_approval.package_identity_key IS DISTINCT FROM cap.npm_package_identity
      OR bound_approval.vulnerability_id IS DISTINCT FROM cap.vulnerability_id
      OR bound_approval.source_license_policy_id IS DISTINCT FROM cap.source_license_policy_id
      OR bound_approval.source_license_policy_version IS DISTINCT FROM cap.source_license_policy_version
      OR bound_approval.approved_license_classification IS DISTINCT FROM cap.approved_license_classification
      OR bound_approval.license_decision_canonical IS DISTINCT FROM cap.license_decision_canonical
    THEN
      RAISE EXCEPTION 'reviewer capability approval binding rejected'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER "reviewer_capability_lifecycle_observation_guard"
  BEFORE INSERT ON "reviewer_capability_lifecycle_observation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_reviewer_capability_observation_guard();

CREATE TRIGGER "reviewer_capability_lifecycle_observation_append_only"
  BEFORE UPDATE OR DELETE ON "reviewer_capability_lifecycle_observation"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();
