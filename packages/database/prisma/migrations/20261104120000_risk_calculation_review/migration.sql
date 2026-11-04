-- Append-only priority review. Forward-only migration 28.
-- One row is a human review of one immutable RiskCalculation.
-- A review does not change the calculation, the Finding, or queue order.
-- No seed rows. No UPDATE or DELETE.

CREATE TABLE "risk_calculation_review" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "organization_id" UUID NOT NULL,
  "finding_id" UUID NOT NULL,
  "risk_calculation_id" UUID NOT NULL,
  "supersedes_review_id" UUID,
  "decision" TEXT NOT NULL,
  "corrected_band" TEXT,
  "expires_at" TIMESTAMPTZ(6),
  "reason" VARCHAR(2000),
  "reason_sha256" CHAR(64),
  "actor_user_id" UUID NOT NULL,
  "actor_membership_id" UUID NOT NULL,
  "correlation_id" UUID NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "risk_calculation_review_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "risk_calculation_review_org_id_key"
  ON "risk_calculation_review" ("organization_id", "id");

CREATE UNIQUE INDEX "risk_calculation_review_root_uidx"
  ON "risk_calculation_review" ("organization_id", "risk_calculation_id")
  WHERE "supersedes_review_id" IS NULL;

CREATE UNIQUE INDEX "risk_calculation_review_successor_uidx"
  ON "risk_calculation_review" ("organization_id", "supersedes_review_id")
  WHERE "supersedes_review_id" IS NOT NULL;

CREATE INDEX "risk_calculation_review_calculation_idx"
  ON "risk_calculation_review" ("organization_id", "risk_calculation_id");

CREATE INDEX "risk_calculation_review_finding_idx"
  ON "risk_calculation_review" ("organization_id", "finding_id");

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_organization_fkey"
  FOREIGN KEY ("organization_id")
  REFERENCES "organization" ("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_finding_fkey"
  FOREIGN KEY ("organization_id", "finding_id")
  REFERENCES "finding" ("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_calculation_fkey"
  FOREIGN KEY ("organization_id", "risk_calculation_id")
  REFERENCES "risk_calculation" ("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_supersedes_fkey"
  FOREIGN KEY ("organization_id", "supersedes_review_id")
  REFERENCES "risk_calculation_review" ("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_actor_membership_fkey"
  FOREIGN KEY ("organization_id", "actor_membership_id")
  REFERENCES "membership" ("organization_id", "id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_actor_user_fkey"
  FOREIGN KEY ("actor_user_id")
  REFERENCES "user" ("id")
  ON DELETE RESTRICT ON UPDATE RESTRICT;

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_decision_chk"
  CHECK ("decision" IN ('accepted', 'corrected', 'withdrawn'));

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_band_chk"
  CHECK ("corrected_band" IS NULL OR "corrected_band" IN ('P1', 'P2', 'P3', 'P4'));

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_correlation_chk"
  CHECK (
    "correlation_id"::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  );

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_reason_hash_chk"
  CHECK (
    (
      "reason" IS NULL
      AND "reason_sha256" IS NULL
    )
    OR (
      "reason" IS NOT NULL
      AND char_length("reason") BETWEEN 1 AND 2000
      AND "reason_sha256" IS NOT NULL
      AND btrim("reason_sha256") ~ '^[a-f0-9]{64}$'
    )
  );

ALTER TABLE "risk_calculation_review"
  ADD CONSTRAINT "risk_calculation_review_shape_chk"
  CHECK (
    (
      "decision" = 'accepted'
      AND "corrected_band" IS NULL
      AND "expires_at" IS NULL
    )
    OR (
      "decision" = 'corrected'
      AND "corrected_band" IS NOT NULL
      AND "reason" IS NOT NULL
      AND "expires_at" IS NOT NULL
      AND "expires_at" > "created_at"
      AND "expires_at" <= "created_at" + INTERVAL '180 days'
    )
    OR (
      "decision" = 'withdrawn'
      AND "supersedes_review_id" IS NOT NULL
      AND "reason" IS NOT NULL
      AND "corrected_band" IS NULL
      AND "expires_at" IS NULL
    )
  );

CREATE OR REPLACE FUNCTION patchpilot_risk_calculation_review_chain()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
  calculation_finding uuid;
  calculation_band text;
  prior_calculation uuid;
  membership_user uuid;
BEGIN
  SELECT rc."finding_id", rc."result" ->> 'priorityBand'
    INTO calculation_finding, calculation_band
  FROM "risk_calculation" rc
  WHERE rc."organization_id" = NEW."organization_id"
    AND rc."id" = NEW."risk_calculation_id";

  IF calculation_finding IS NULL OR calculation_finding IS DISTINCT FROM NEW."finding_id" THEN
    RAISE EXCEPTION 'risk calculation review finding mismatch'
      USING ERRCODE = '23514';
  END IF;

  IF NEW."decision" = 'corrected' AND (
    calculation_band IS NULL
    OR calculation_band NOT IN ('P1', 'P2', 'P3', 'P4')
    OR NEW."corrected_band" IS NOT DISTINCT FROM calculation_band
  ) THEN
    RAISE EXCEPTION 'risk calculation review band unchanged'
      USING ERRCODE = '23514';
  END IF;

  IF NEW."supersedes_review_id" IS NOT NULL THEN
    SELECT prior."risk_calculation_id"
      INTO prior_calculation
    FROM "risk_calculation_review" prior
    WHERE prior."organization_id" = NEW."organization_id"
      AND prior."id" = NEW."supersedes_review_id";
    IF prior_calculation IS NULL
      OR prior_calculation IS DISTINCT FROM NEW."risk_calculation_id" THEN
      RAISE EXCEPTION 'risk calculation review chain mismatch'
        USING ERRCODE = '23514';
    END IF;
  END IF;

  SELECT membership."user_id"
    INTO membership_user
  FROM "membership" membership
  WHERE membership."organization_id" = NEW."organization_id"
    AND membership."id" = NEW."actor_membership_id";
  IF membership_user IS NULL OR membership_user IS DISTINCT FROM NEW."actor_user_id" THEN
    RAISE EXCEPTION 'risk calculation review actor mismatch'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER risk_calculation_review_chain
  BEFORE INSERT ON "risk_calculation_review"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_risk_calculation_review_chain();

CREATE TRIGGER risk_calculation_review_append_only
  BEFORE UPDATE OR DELETE ON "risk_calculation_review"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();
