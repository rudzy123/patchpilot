-- Session 7 Batch 2: asset list keyset index and external-identifier CHECKs.
-- Forward-only. Does not edit 20260826120000_schema_foundation through
-- 20260827180000_local_credentials_and_sessions.

-- Default active Asset list: organization_id + lifecycle_status (default
-- active) + ORDER BY lower(name), id. This expression index is the minimum
-- covering index for that keyset. It is not redundant with
-- asset_active_name_org_idx (partial unique on (organization_id, lower(name))
-- WHERE active; no lifecycle_status, no id).
CREATE INDEX asset_org_status_name_id_idx
  ON "asset" (organization_id, lifecycle_status, lower(name), id);

-- asset_org_status_idx (organization_id, lifecycle_status) is a left prefix of
-- the new index. Drop it so the default list does not maintain two btrees.
DROP INDEX "asset_org_status_idx";

-- Namespace matches AssetTag shape and application ASSET_SLUG_SHAPE:
-- stored lowercase, length 1-64, ^[a-z0-9]+(-[a-z0-9]+)*$
ALTER TABLE "asset_external_identifier"
  ADD CONSTRAINT asset_external_identifier_namespace_shape_chk
  CHECK (
    namespace = lower(namespace)
    AND char_length(namespace) BETWEEN 1 AND 64
    AND namespace ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
  );

-- Identifier is opaque stored text: character length 1-256; reject NUL, C0,
-- DEL, and C1. PostgreSQL text cannot store NUL; the class still documents
-- the floor. Values may be URL-shaped; this CHECK does not fetch.
ALTER TABLE "asset_external_identifier"
  ADD CONSTRAINT asset_external_identifier_value_chk
  CHECK (
    char_length(identifier) BETWEEN 1 AND 256
    AND identifier !~ '[\x00-\x1F\x7F-\x9F]'
  );
