-- Session 10 Batch 3A: global canonical CVE identity.
-- Forward-only. Does not edit 20260826120000_schema_foundation through
-- 20260901120000_kev_intelligence_persistence.
-- New tables only; no ALTER TYPE ADD VALUE on existing enums.
-- Do not freeze this file until independent review and tests succeed.
-- Do not apply this migration to the persistent development database in Batch 3A.

CREATE TABLE "cve_identity" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "cve" VARCHAR(28) NOT NULL,
  "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "cve_identity_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "vulnerability_cve_identity" (
  "id" UUID NOT NULL DEFAULT gen_random_uuid(),
  "vulnerability_id" UUID NOT NULL,
  "cve_identity_id" UUID NOT NULL,
  "linked_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "vulnerability_cve_identity_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "cve_identity_cve_uidx"
  ON "cve_identity" ("cve");

CREATE UNIQUE INDEX "vulnerability_cve_identity_natural_key"
  ON "vulnerability_cve_identity" ("vulnerability_id", "cve_identity_id");

ALTER TABLE "vulnerability_cve_identity"
  ADD CONSTRAINT "vulnerability_cve_identity_vulnerability_id_fkey"
  FOREIGN KEY ("vulnerability_id") REFERENCES "vulnerability"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "vulnerability_cve_identity"
  ADD CONSTRAINT "vulnerability_cve_identity_cve_identity_id_fkey"
  FOREIGN KEY ("cve_identity_id") REFERENCES "cve_identity"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "cve_identity"
  ADD CONSTRAINT "cve_identity_cve_chk"
  CHECK ("cve" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$');

CREATE TRIGGER cve_identity_append_only
  BEFORE UPDATE OR DELETE ON "cve_identity"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

CREATE TRIGGER vulnerability_cve_identity_append_only
  BEFORE UPDATE OR DELETE ON "vulnerability_cve_identity"
  FOR EACH ROW EXECUTE FUNCTION patchpilot_forbid_mutation();

-- Begin canonical-only legacy backfill
INSERT INTO "cve_identity" ("cve", "created_at")
SELECT DISTINCT "cve_id", CURRENT_TIMESTAMP
FROM "vulnerability"
WHERE "cve_id" IS NOT NULL
  AND "cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'
ON CONFLICT ("cve") DO NOTHING;

INSERT INTO "vulnerability_cve_identity" ("vulnerability_id", "cve_identity_id", "linked_at")
SELECT v."id", i."id", CURRENT_TIMESTAMP
FROM "vulnerability" v
INNER JOIN "cve_identity" i ON i."cve" = v."cve_id"
WHERE v."cve_id" IS NOT NULL
  AND v."cve_id" ~ '^CVE-[0-9]{4}-[0-9]{4,19}$'
ON CONFLICT ("vulnerability_id", "cve_identity_id") DO NOTHING;
-- End canonical-only legacy backfill
