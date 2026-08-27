-- Forward-only: organization risk-policy creators are memberships.
-- Does not edit 20260826120000, 20260827120000, 20260827140000, or 20260827150000.

ALTER TABLE "risk_policy" ADD COLUMN "created_by_membership_id" UUID;

UPDATE "risk_policy" AS policy
SET "created_by_membership_id" = membership."id"
FROM "membership" AS membership
WHERE policy."scope" = 'organization'
  AND policy."organization_id" IS NOT NULL
  AND policy."created_by_user_id" IS NOT NULL
  AND membership."organization_id" = policy."organization_id"
  AND membership."user_id" = policy."created_by_user_id";

ALTER TABLE "risk_policy" DROP CONSTRAINT IF EXISTS "risk_policy_created_by_user_id_fkey";
ALTER TABLE "risk_policy" DROP COLUMN "created_by_user_id";

ALTER TABLE "risk_policy"
  ADD CONSTRAINT "risk_policy_created_by_membership_fkey"
  FOREIGN KEY ("organization_id", "created_by_membership_id")
  REFERENCES "membership"("organization_id", "id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "risk_policy"
  ADD CONSTRAINT risk_policy_creator_scope_chk
  CHECK (
    (scope = 'builtin' AND created_by_membership_id IS NULL)
    OR (scope = 'organization')
  );
