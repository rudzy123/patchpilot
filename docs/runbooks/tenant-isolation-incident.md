# Runbook: tenant isolation incident

Use this when a user may have read or mutated another organization's assets, SBOMs, findings, exports, or credentials. Architecture: [tenant-isolation.md](../architecture/tenant-isolation.md). Threat: [threat-model.md](../security/threat-model.md).

This is a **security incident**. Do not file a public GitHub issue with reproduction payloads. Follow [SECURITY.md](../../SECURITY.md) if it is a product defect.

## Symptoms

- API returned another organization's resource body.
- Object-storage get succeeded for a key outside the caller's org prefix.
- Job with tampered `organizationId` mutated the wrong tenant.
- Metrics/logs contain another organization's Restricted data.
- Support request asks for a cross-org dump.

## Immediate actions

1. Preserve evidence: request id, actor user id, claimed org, target ids, timestamps (UTC). **Redact** tokens, cookies, raw SBOMs.
2. Set `allowDevelopmentAdapters=false` and restart API/worker if that flag could have been true.
3. Revoke sessions for the suspected actor (and all sessions if the leak path is unclear).
4. Pause **tenant** ingest/recalculate workers (system intel refresh may continue). Pausing is better than continued mix-up.
5. If the object-storage bucket is public or listable, make it private immediately and assume SBOM disclosure.
6. Do not open another organization's SBOM in a ticket, chat, or browser to "confirm."

## Containment queries (org-scoped)

Instance operators may run these **only** on a forensic copy when possible:

- Count rows whose `organization_id` does not match the object's key prefix `org/{organizationId}/`.
- List **BackgroundJob** rows in `running`/`succeeded` in the incident window and confirm each mutated aggregate's persisted `organizationId`.
- Compare API access logs by `requestId` for resource ids that do not belong to the caller's memberships (ids only, no bodies).

## Investigation questions

- Did the repository method omit `organizationId`?
- Did the route trust a client-supplied org id?
- Did cache keys omit organization?
- Did object keys omit `org/{organizationId}/`?
- Did a job skip reload-from-persistence?
- Did a write bypass repository adapters (raw SQL or an unrestricted Prisma client)?
- Did a compound foreign key fail to exist for the suspected parent/child pair? Schema: [database-model.md](../architecture/database-model.md).

## Recovery

1. Keep the application **without** a cross-org bypass. None exists in v0.1.
2. After a code fix, deploy and run the isolation tests in [testing-strategy.md](../architecture/testing-strategy.md).
3. Record operator notes outside tenant audit if no `incident` action exists; do not put Restricted payloads in **AuditEvent**.
4. Notify the affected organization's `owner` out of band. PatchPilot does not claim a legal notification SLA.
5. Rotate session signing material, object-storage credentials, and **ExternalCredential** rows if disclosure is plausible.

## Verification

- Repeat the isolation tests: org A session cannot read B's asset, SBOM, finding, export, credential ids.
- Job replay with swapped payload org dead-letters and does not mutate.
- Logs/metrics samples show no Restricted bodies.

## Administrative access

Instance operators have infrastructure access (disk, backups). That is not an application bypass. They must not use a hidden "all tenants" API — it must not exist.
