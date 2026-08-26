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
2. Disable development adapters if production config might have enabled them.
3. Do not "browse" other tenants to confirm. Use a scripted, org-scoped query or a restored copy.
4. Rotate session secrets and **ExternalCredential** material if leakage is plausible.
5. If object storage was public, make the bucket private immediately and assume SBOM disclosure.

## Containment

- Block the affected API keys/sessions.
- Pause workers only if jobs are writing across orgs; pausing is better than continued mix-up.
- Do not enable a cross-organization operator bypass. None exists in v0.1.

## Investigation questions

- Did the repository method omit `organizationId`?
- Did the route trust a client-supplied org id?
- Did cache keys omit organization?
- Did object keys omit `org/{organizationId}/`?
- Did a job skip reload-from-persistence?

## Recovery

- Patch the predicate; add/adjust isolation tests ([testing-strategy.md](../architecture/testing-strategy.md)).
- Audit: record `incident` metadata without Restricted payloads (if a suitable action exists; otherwise instance-operator notes outside the tenant audit table).
- Notify the affected organization's `owner` via the operator's out-of-band process. PatchPilot does not claim a legal notification SLA.

## Verification

- Repeat the isolation tests: org A session cannot read B's asset, SBOM, finding, export, credential ids.
- Job replay with swapped payload org dead-letters and does not mutate.
- Logs/metrics samples show no Restricted bodies.

## Administrative access

Instance operators have infrastructure access (disk, backups). That is not an application bypass. They must not use a hidden "all tenants" API — it must not exist.
