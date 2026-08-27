-- Session 6 authentication persistence. Forward-only.
-- Commits the anonymous audit actor label so a later CHECK may reference it.
-- Does not change audit_event_actor_scope_chk, tables, or audit rows.

ALTER TYPE "audit_actor_type" ADD VALUE 'anonymous';
