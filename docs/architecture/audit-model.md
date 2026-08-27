# Audit model

**Audit events** are append-only records of security-sensitive and remediation-sensitive operations ([ADR 0014](../adr/0014-append-only-audit.md)). They are never updated or deleted in place. Evidentiary data is not cascade-deleted to satisfy a foreign key.

## Purpose

A later reviewer should see what was known, who acted, when (UTC), which organization, and which **policy version** applied to a score. Audit is not a debugging log. Operational logs are separate ([observability](observability.md)).

## Immutability

| Operation | Allowed |
| --- | --- |
| INSERT | Yes |
| UPDATE | No |
| DELETE | No |
| UPDATE/DELETE via ORM cascade | No |

Retention jobs must not erase audit rows in v0.1. If law-driven erasure is ever required, that needs an ADR and will still preserve a tombstone event.

Application roles cannot "correct" an audit row. Corrections are new events.

## Identity and scope

| Field (logical) | Notes |
| --- | --- |
| `id` | UUID (event id) |
| `organizationId` | Required for tenant operations; null for system catalog events and instance-level authentication events |
| `actorUserId` | Optional; set for instance-level and tenant `user` actors ([ADR 0019](../adr/0019-local-password-sessions.md)). Restored by a forward-only migration; existing tenant user rows were backfilled from Membership. The backfill disables `audit_event_append_only` only for that migration. |
| `actorMembershipId` | Required for tenant `user` actors; null for `anonymous`, `system`, `instance_operator`, and instance-level `user` |
| `actorType` | `user`, `system`, `instance_operator`, `anonymous` |
| `action` | Stable dotted name |
| `subjectType` / `subjectId` | Target type / target id |
| `correlationId` | Request or job id |
| `createdAt` | Server UTC, set once |
| `schemaVersion` | Audit payload schema |
| `retentionCategory` | `security` (keep in v0.1) |
| `sourceIp` | Optional; store only if operator policy permits; never log in app logs if Restricted |
| `userAgent` | Optional; same policy |
| `payload` | Redacted structured metadata: ids, hashes, policy version, states |

**Must not** appear in payload or logs: raw SBOM documents, external API tokens, authorization headers, cookies, full third-party payloads, source code, sensitive object-storage URLs (including presigned/signed URLs).

### Actor truth table

| `actorType` | `actorUserId` | `organizationId` | `actorMembershipId` |
| --- | --- | --- | --- |
| `anonymous` | null | null | null |
| `user` (instance) | set | null | null |
| `user` (tenant) | set; equals Membership.user_id | set; equals Membership.organization_id | set |
| `system` | null | null or set | null |
| `instance_operator` | null | null or set | null |

A BEFORE INSERT trigger (`patchpilot_audit_actor_membership_user`) rejects tenant user events whose membership is not in `organizationId` or whose `actorUserId` is not `membership.user_id`. `instance_operator` is not a substitute for User authentication.

## Database-only immutability — limitations

Database-only immutability is implemented with `BEFORE UPDATE OR DELETE` triggers that raise `restrict_violation`. PostgreSQL INSERT-only plus those triggers is the v0.1 control. It is **not** physical WORM storage. Superusers, stolen credentials, backups, and disk snapshots can still alter or copy rows. Hash chaining is **not** implemented; the database does not claim non-repudiation. Operators who need stronger immutability must export audit to an external append-only store (future ADR). See [audit-integrity-failure.md](../runbooks/audit-integrity-failure.md).

Tenant audit queries always include `organizationId` from authorized context. System events are visible to instance operators only, not to org members of unrelated tenants.

## Required actions (v0.1)

At minimum, emit events for:

| Action | When |
| --- | --- |
| `membership.created` / `membership.revoked` / `membership.role_changed` | Membership changes |
| `organization.created` / `organization.archived` | Org lifecycle |
| `asset.created` / `asset.archived` / `asset.restored` / `asset.updated` | Asset model |
| `sbom.uploaded` / `sbom.duplicate` / `sbom.upload_rejected` | Upload recorded or rejected at the API |
| `sbom.ingestion.completed` / `rejected` / `quarantined` / `failed` / `released_from_quarantine` | Ingestion terminals and release |
| `sbom.reprocessed` | New ingestion on existing object |
| `intelligence.imported` | OSV/KEV snapshot stored |
| `priority.calculated` | **RiskCalculation** inserted |
| `risk_policy.published` | Org override or builtin publish |
| `finding.state_changed` | Finding lifecycle transition |
| `remediation_task.created` / `remediation_task.transition` | Assignment and activity |
| `risk_acceptance.created` / `expired` / `revoked` / `superseded` / `review_due` | Acceptance including requester/approver ids |
| `finding.false_positive` / `finding.mitigated` | Specialized transitions |
| `priority.override` | Manual override |
| `auth.login_succeeded` / `auth.login_failed` / `auth.logout` / `auth.session_revoked` / `auth.organization_selected` | Authentication ([ADR 0019](../adr/0019-local-password-sessions.md)); no secrets in payload. Anonymous failures use `actorType=anonymous`. Successful login uses instance-level `user`, not `system`. HTTP routes are not implemented in this batch. |
| `admin.access` | Instance-operator actions on system integrations |
| `compensating_control.recorded` | Evidence of a control claim |
| `export.created` | Exports |
| `credential.created` / `rotated` / `revoked` / `validation_failed` | **ExternalCredential** |
| `integration.enabled` / `disabled` / `degraded` | **Integration** |
| `webhook.accepted` / `webhook.rejected` | Reserved; unused until webhooks exist |

Do not log authorization headers or cookies in `payload`.

## Integrity properties

- Insert audit in the **same transaction** as the state change it describes, when both are PostgreSQL rows.
- Do not insert audit in a transaction that also calls object storage or HTTP.
- If object storage succeeded and DB commit fails, operators may see an orphan object; a later reconcile job should not invent an upload audit without a user. Failed HTTP uploads that never stored bytes still may record `sbom.upload_rejected` **if** a DB write is possible; otherwise metrics-only.
- Replay uniqueness: tenant events unique on `(organizationId, action, subjectId, correlationId)`. System events (`organizationId` null) **must** set `correlationId` and are unique on `(action, subjectId, correlationId)` among rows where `organizationId` IS NULL. Do not rely on a UNIQUE column that includes nullable `organizationId` alone.

## What audit is not

- Not a compliance certificate.
- Not a complete reconstruction of raw SBOM content (hash and object key are enough to retrieve evidence under authorization).
- Not a substitute for **RiskCalculation.contributingFactors**.

## Access

`viewer`+ may read audit events for their organization that are not credential-secret metadata. Credential audits include key ids and states, never plaintext. Instance operators do not receive a global tenant audit dump through the product API.

## Related documents

- [Retention and deletion](retention-and-deletion.md)
- [Security controls](../security/security-controls.md)
- [Domain model](domain-model.md#auditevent)
