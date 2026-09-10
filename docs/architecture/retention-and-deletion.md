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
| Protected OSV listing-observation evidence | Session 13 Batch 3D-S / 3D-S-R schema exists (`osv_listing_observation_evidence_set`, observation, envelope versions, append-only purge); legal hold blocks envelope erasure; overdue marker grants no purge authority; Session 13 Batch 3D-C can encrypt synthetic identities in process but does not persist envelopes; Session 13 Batch 3D-C-R independently reviewed that capability; no adapter; no TTL worker | Keep until independent review and dependent authorizations are terminal; maximum 7,776,000 seconds is an overdue marker, not automatic delete; Model B envelope redaction plus purge evidence; DELETE forbidden |
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
- Future protected OSV listing-observation evidence rows: DELETE forbidden; cleanup is a controlled redaction of one encrypted-envelope column then an append-only purged-state row after review and dependent-authorization closure

## Orphan object storage

If a put succeeded and the DB transaction failed, objects may lack a **SBOM** row. The upload path deletes its temporary object best-effort and deliberately does **not** delete a promoted final object, because after promotion those bytes may be the only copy of the user's evidence.

**No reconcile job exists yet.** `SBOM_ORPHAN_GRACE_SECONDS` (default 7 days, validated to exceed the idempotency TTL) is the policy floor a future job must honor; nothing reads it today, so orphans accumulate until an operator intervenes.

When that job is built: it **lists** orphans for operators, and automatic delete is allowed only after the grace period **and** only when no DB row references the key. Log the object key template plus hash, not the key and not the bytes. See [SBOM ingestion](sbom-ingestion.md#orphan-reconciliation).

## Protected OSV listing-observation evidence

Session 13 Batch 3D-P selects durable protected persistence for listing-observation metadata required by a future separately authorized listing. Session 13 Batch 3D-P-R independently reviewed that policy. Session 13 Batch 3D-E defines the encryption, envelope, associated-data, rotation, and cryptographic-erasure policy required before schema. Session 13 Batch 3D-E-R independently reviewed and hardened that policy. Prisma is unchanged, so no rows exist yet. Schema design may proceed around the closed authenticated envelope. When persisted:

- Retention policy `osv_protected_listing_observation_evidence_retention_v1`.
- Retention clock starts at database `captured_at`, not application `Date.now`.
- Minimum retention lasts until independent review is recorded and dependent authorizations are terminal.
- Maximum 7,776,000 seconds (90 days) is an overdue review marker. It does not authorize automatic delete.
- No cleanup loop, TTL worker, or cascade delete.
- Cleanup requires a distinct instance-operator cleanup grant, no legal hold, and a controlled redaction of the encrypted envelope column. Immutable evidence metadata remains. Deletion evidence is an append-only purge row without the raw object key or a bare key digest. Session 13 Batch 3D-E keeps this Model B controlled-redaction purge. Per-set cryptographic erasure is envelope redaction, not destruction of the shared instance key, because destroying that key would render unrelated remaining envelopes unrecoverable.
- Raw listing responses and continuation tokens remain prohibited and are not retained.
- Plaintext protected-key columns are forbidden, including as a temporary migration step.
- Backups that later include the encrypted envelope remain Restricted. Cryptographic erasure does not immediately remove ciphertext from backups. Restoring the database without the required key capability leaves protected values unavailable. Restoring old database state must not reactivate destroyed keys. Backup operators do not receive general decryption authority merely because they control database backups.

This is not a legal hold product. Legal hold, if asserted, extends retention until released.

## Tenant off-boarding

v0.1 has no self-service "delete my organization and all evidence" button. Instance operators who wipe a database do so outside the application (infrastructure). Product APIs must not offer a cross-table hard delete.

## Backups

Restores can resurrect deleted sessions or purged orphans. Operators should encrypt backups and control access ([deployment](deployment-model.md), [OD-13](open-decisions.md)). Backup copies are **Restricted**. Future protected listing-evidence ciphertext may appear in PostgreSQL backups; raw encryption keys must not. Restoring those backups without the required key capability leaves protected object identities unavailable. Recovery testing must not expose plaintext.

## Related documents

- [Data classification](data-classification.md)
- [Privacy model](../security/privacy-model.md)
- [Database rules](../../.cursor/rules/database.mdc)
