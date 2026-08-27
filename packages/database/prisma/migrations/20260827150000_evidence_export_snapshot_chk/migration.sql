-- Uses evidence_kind.export_snapshot added in 20260827140000_review_corrections.
-- PostgreSQL requires the new enum value to be committed before a CHECK may
-- reference it, so this cannot live in the previous migration transaction.

ALTER TABLE "evidence" DROP CONSTRAINT IF EXISTS evidence_one_target_chk;

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
    OR (
      kind = 'export_snapshot'
      AND asset_id IS NOT NULL
      AND finding_id IS NULL
      AND sbom_id IS NULL
    )
  );
