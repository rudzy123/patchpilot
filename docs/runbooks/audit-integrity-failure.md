# Runbook: audit integrity failure

Use this when audit rows are missing, appear updated, were deleted, or evidence was cascade-deleted. Architecture: [audit-model.md](../architecture/audit-model.md), [retention-and-deletion.md](../architecture/retention-and-deletion.md).

Database privileges cannot make PostgreSQL a WORM store. Treat DB-only immutability as a **control**, not a physical guarantee. Instance operators with superuser access can still bypass it.

## Symptoms

- State change exists (membership, SBOM, calculation, acceptance) without a matching **AuditEvent**.
- Audit row `updatedAt` or UPDATE/DELETE in WAL/logs.
- Foreign-key cascade removed findings, SBOMs, or audit.
- Export or UI history gaps.

## Immediate actions

1. Stop applying migrations or ORM schema changes that add `ON DELETE CASCADE` to evidence tables.
2. Snapshot the database (operator backup) before "repair."
3. Do not UPDATE existing **AuditEvent** rows to "fix" them. Insert a new event describing the incident if the product has a suitable action; otherwise keep operator notes outside the table.

## Classify

| Class | Likely cause |
| --- | --- |
| Missing event | Transaction failed after side effect, or code path omitted audit |
| Altered row | Superuser, buggy migration, compromised app role |
| Cascade delete | Schema mistake |
| Backup restore | Expected resurrection/gap; not silent rewrite in the live table |

## Recovery

1. Restore from backup if rows were deleted and the backup is trusted.
2. If only the code omitted audit, deploy the fix; **do not** backfill fake historical actors. Optional: insert `system` events with `payload.note = reconstructed_gap` and no invented user actions.
3. Revoke application UPDATE/DELETE on `audit_event` if the role had it.
4. Recalculate nothing as a substitute for audit. **RiskCalculation** history is separate evidence.

## Verification

- Tests: UPDATE/DELETE on audit fail.
- New mutations write audit in the same DB transaction as the state change.
- No cascade-delete on SBOM, finding, calculation, acceptance, or audit.

## Escalation

Treat as a [tenant isolation](tenant-isolation-incident.md) incident if another organization could have been affected. Product defect: [SECURITY.md](../../SECURITY.md).
