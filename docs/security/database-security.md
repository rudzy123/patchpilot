# Database security

PostgreSQL stores tenant metadata, findings, audit events, and outbox ids. Original SBOM bytes and raw intelligence snapshots belong in private object storage, not in PostgreSQL ([ADR 0008](../adr/0008-private-object-storage.md)).

## Controls in Session 5

- UUID primary keys; organization predicates on tenant tables.
- Compound foreign keys for same-organization relationships and evidence-graph consistency (ingestion/occurrence/finding/dependency/asset current ingestion).
- Membership-scoped actors for tenant-sensitive user references.
- Check constraints for slugs, SHA-256, byte sizes, timestamp order, risk-policy scope and publication, risk-acceptance fields, outbox leases, evidence targets, and asset-owner identity.
- Append-only triggers on audit, observations, calculations, source records, and evidence.
- No plaintext credential columns. `external_credential` stores a secret **reference** and key version only. Encryption and secret-manager integration are future infrastructure ([OD-4](../architecture/open-decisions.md)).
- Password hash and session digest columns are in `local_credential` and `session` ([ADR 0019](../adr/0019-local-password-sessions.md)). `LocalCredential` stores one Argon2id PHC per User (`ON DELETE RESTRICT`). `Session` is opaque server-side state: repositories accept SHA-256 digests only, never raw session tokens, CSRF tokens, or cookies. `activeOrganizationId` is a selector, not authorization. Idle and absolute cleanup indexes exist; expiration cleanup jobs are deferred. No authentication HTTP routes, cookies, or CSRF handlers exist in this batch.
- Audit actor CHECK is the authentication truth table (`anonymous`, instance `user`, tenant `user`, `system`, `instance_operator`). Tenant `user` rows also pass `patchpilot_audit_actor_membership_user`. Restoring `actor_user_id` backfills from Membership inside migration `20260827180000_local_credentials_and_sessions` only; runtime UPDATE/DELETE of `audit_event` remains blocked. Existing Session 5 migrations stay frozen.
- Destructive scripts require loopback host, allowed database name, and `PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE=true`.
- Development seed is synthetic and production-rejected. Seed does not attach passwords in this batch.

## What these controls are not

- Not row-level security (deferred; [tenant isolation](../architecture/tenant-isolation.md)).
- Not WORM / non-repudiation. Superusers can still rewrite tables.
- Not a substitute for application authorization.

## Logging

Never log `DATABASE_URL`, authorization headers, raw SBOMs, or provider payloads.

## Related documents

- [Data access](data-access.md)
- [Security controls](security-controls.md)
