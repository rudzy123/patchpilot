# Retention and deletion

PatchPilot preserves **evidence**. v0.1 does not cascade-delete SBOMs, findings, audit events, or remediation records to satisfy a foreign key. This document is not a legal hold product and does not claim regulatory compliance.

## Principles

1. **AuditEvent** rows are insert-only and are not deleted in v0.1 ([audit model](audit-model.md)).
2. Original SBOM objects remain for the operator-configured retention period.
3. Derived graphs may be rebuilt from originals (parser reprocess) and must not be the only copy of evidence.
4. Hard deletion, if ever added, is an explicit, audited job—not ORM `onDelete: Cascade` on evidence.
5. Organization archive ([asset](asset-model.md) and org status) hides write paths; it is not a wipe.

## v0.1 default

**Retain indefinitely** until an instance operator changes config. There is no automatic purge in the MVP journey.

Configurable knobs (for when operators opt in later in the same architecture):

| Data | Default | Optional purge |
| --- | --- | --- |
| Audit events | Keep forever | Not in v0.1 |
| SBOM objects + **SBOM** rows | Keep | Future job after `retainUntil`; still write `sbom.purged` audit **before** object delete, keeping hash in audit |
| Findings and calculations | Keep | Future; never without policy |
| Intelligence snapshots | Keep additive | Compact only identical hashes |
| Sessions | Expire | Delete expired session rows (not evidence) |
| Logs | Operator's collector | Outside the app |

Expired **RiskAcceptance** is a **state** change, not deletion of the row.

## What may be deleted in v0.1

| Item | Why |
| --- | --- |
| Expired server sessions | Authentication hygiene |
| Idempotency-key index after TTL (24h) | Storage; the SBOM row remains |
| BullMQ completed job payloads | Queue is not the system of record; ids live on **BackgroundJob** / outbox |

## What must not be deleted in v0.1

- Audit rows
- Original SBOM objects referenced by a **SBOM** row
- **RiskCalculation** history
- **FindingObservation** history
- Membership rows (revoke instead)

## Orphan object storage

If a put succeeded and the DB transaction failed, objects may lack a **SBOM** row. A reconcile job **lists** orphans for operators. Automatic delete of orphans is allowed only after a grace period (default 7 days) **and** only when no DB row references the key. Log object key template + hash, not bytes.

## Tenant off-boarding

v0.1 has no self-service "delete my organization and all evidence" button. Instance operators who wipe a database do so outside the application (infrastructure). Product APIs must not offer a cross-table hard delete.

## Backups

Restores can resurrect deleted sessions or purged orphans. Operators should encrypt backups and control access ([deployment](deployment-model.md), [OD-13](open-decisions.md)). Backup copies are **Restricted**.

## Related documents

- [Data classification](data-classification.md)
- [Privacy model](../security/privacy-model.md)
- [Database rules](../../.cursor/rules/database.mdc)
