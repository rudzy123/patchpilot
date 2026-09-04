-- Session 11 Batch 5C-R: replace the unsatisfiable POSIX quantifier on
-- osv_parsed_advisory_revision_osv_id_chk. The Batch 5C migration remains
-- frozen. PostgreSQL POSIX regular expressions reject counted repetitions
-- above 255 (SQLSTATE 2201B). Preserve the 512-character identifier
-- grammar with an explicit length check plus a grammar check that does
-- not use a large counted repetition.
--
-- No table, column, index, foreign-key, enum, or data change.
-- No seed rows, active catalog, tenant rows, or Finding rows.

ALTER TABLE "osv_parsed_advisory_revision"
  DROP CONSTRAINT "osv_parsed_advisory_revision_osv_id_chk";

ALTER TABLE "osv_parsed_advisory_revision"
  ADD CONSTRAINT "osv_parsed_advisory_revision_osv_id_chk"
  CHECK (
    char_length("parsed_top_level_osv_id") BETWEEN 1 AND 512
    AND "parsed_top_level_osv_id" ~ '^[A-Z0-9][A-Z0-9._+-]*$'
  );
