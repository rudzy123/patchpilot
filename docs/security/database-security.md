# Database security

PostgreSQL stores tenant metadata, findings, audit events, and outbox ids. Original SBOM bytes and raw intelligence snapshots belong in private object storage, not in PostgreSQL ([ADR 0008](../adr/0008-private-object-storage.md)).

## Controls in Session 5

- UUID primary keys; organization predicates on tenant tables.
- Compound foreign keys for same-organization relationships.
- Check constraints for slugs, SHA-256, byte sizes, timestamp order, risk-acceptance fields, outbox leases, and evidence targets.
- Append-only triggers on audit, observations, calculations, source records, and evidence.
- No plaintext credential columns. `external_credential` stores a secret **reference** and key version only. Encryption and secret-manager integration are future infrastructure ([OD-4](../architecture/open-decisions.md)).
- No password hash columns in this session ([OD-1](../architecture/open-decisions.md) is still open).
- Destructive scripts require loopback host, allowed database name, and `PATCHPILOT_ALLOW_DESTRUCTIVE_DATABASE=true`.
- Development seed is synthetic and production-rejected.

## What these controls are not

- Not row-level security (deferred; [tenant isolation](../architecture/tenant-isolation.md)).
- Not WORM / non-repudiation. Superusers can still rewrite tables.
- Not a substitute for application authorization.

## Logging

Never log `DATABASE_URL`, authorization headers, raw SBOMs, or provider payloads.

## Related documents

- [Data access](data-access.md)
- [Security controls](security-controls.md)
