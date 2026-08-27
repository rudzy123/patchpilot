# Tenant isolation

Deny by default. Every tenant-owned operation is scoped to the **authorized organization** from session or membership context. Looking up a resource by id is not authorization.

This document is the canonical tenancy design for v0.1 ([ADR 0013](../adr/0013-organization-scoped-tenancy.md)).

## How organization context is established

1. The user authenticates (interim: session cookie bound to a **User** id, [OD-1](open-decisions.md)).
2. The API loads **Membership** rows that are not revoked.
3. The request names a target organization only as a **selector** among memberships the user already has (for example path `/organizations/{organizationId}/...` where `{organizationId}` must match a membership).
4. If the user has no membership for that id, the API returns **not found** for tenant-owned resources (same as a missing id). It does **not** return `forbidden` in a way that confirms another organization exists. `forbidden` is reserved for an authenticated member of **this** organization who lacks the role for the operation.
5. Use cases receive `AuthorizedContext { userId, organizationId, role }`. They never receive a raw client id as proof.

A client-supplied `organizationId` that does not match membership is ignored for authorization. GitHub accounts, webhook fields, and job payloads are not membership.

### Multi-organization users

A user may belong to several organizations. Switching org in the UI changes which membership is selected. It does not grant a union query across organizations.

After the first user exists, creating a user requires an invitation (or equivalent authenticated path). The instance must not offer unauthenticated organization signup ([OD-1](open-decisions.md)).

## How authorization is enforced

Authorization is **server-side** in use cases and repository adapters, not solely in React.

### Roles (interim OD-3)

| Role | Inventory and SBOM | Findings and exports | Remediation | Risk acceptance | Membership and policy override | Credentials |
| --- | --- | --- | --- | --- | --- | --- |
| `viewer` | Read | Read | Read | Read | No | No |
| `member` | Read; upload SBOM | Read; export if allowed by org setting default **yes** | Create and update tasks | No | No | No |
| `admin` | Full asset lifecycle except org delete | Full | Full | Create/revoke | Policy override; invite/revoke `member`/`viewer` | Create/rotate/revoke |
| `owner` | Full | Full | Full | Full | All membership including `admin`/`owner`; archive org | Full |

Exports are tenant-owned. Default: `member` and above may export. An organization setting may restrict export to `admin`/`owner` without changing historical export **Evidence**.

Instance operator ([OD-10](open-decisions.md)) may manage **system** integrations and shared catalogs only.

## How repository methods require organization scope

Every tenant-owned repository port includes organization as a required argument, not an optional filter:

```text
findAssetById(organizationId, assetId)
listFindings(organizationId, query)
getSbomObjectMeta(organizationId, sbomId)
```

Adapters translate this to a query that **always** contains `WHERE organization_id = $authorizedOrg` from **AuthorizedContext**, never from `query.organizationId` or the request body.

Session 5 persists this at the database layer: every tenant-owned Prisma repository method takes `organizationId` as a required argument. Compound foreign keys reject cross-organization parent/child pairs. Authentication and membership authorization remain application-layer work; persistence still does not treat a caller-supplied id as proof of membership.

Physical schema, constraints, and indexes: [database-model.md](database-model.md).

Forbidden patterns:

- `findById(id)` then check org in the caller "if you remember"
- `WHERE organization_id = $clientBody.organizationId`
- Global unique constraints on tenant natural keys without organization (for example SHA-256 alone)

Idempotency keys and upload hashes are unique per **organization** (and asset where specified).

## Global intelligence versus tenant-owned data

| Global / shared catalog | Tenant-owned |
| --- | --- |
| **Vulnerability** | **Organization**, **Membership**, **Team** |
| **VulnerabilitySourceRecord** | **User** is instance-level; access to org data is via membership |
| Built-in **RiskPolicy** | Org **RiskPolicy** overrides |
| CISA KEV snapshots (as source records) | **Asset**, **AssetOwner**, **Environment** |
| System **Integration** for OSV/KEV | **SBOM**, **SBOMIngestion**, **Component**, **ComponentOccurrence**, **DependencyRelationship** |
| | **Finding**, **FindingObservation**, **RiskCalculation** |
| | **RemediationTask**, **RiskAcceptance**, **Evidence** |
| | Tenant **AuditEvent** |
| | Tenant **Integration** / **ExternalCredential** (unused for GitHub in v0.1) |
| | **OutboxEvent** and **BackgroundJob** for tenant work |

**User** accounts are not a tenant table, but listing users is still scoped: only members of the authorized organization are visible.

## How global intelligence may be referenced

A **Finding** stores `vulnerabilityId` (and optionally `vulnerabilitySourceRecordId` used at correlation time). Display may denormalize CVE and summary **copies** for UI, but must also store the source record id so provenance is not stripped.

Rules:

- Do not embed another organization's finding id.
- Do not copy tenant component names into the global vulnerability table.
- Shared catalog reads are allowed for any authenticated member; they are not secret tenant data. Still do not log full feed payloads.

## How tests prevent cross-tenant access

Required even if a test glob did not attach ([testing rules](../../.cursor/rules/testing.mdc)):

1. Seed organization A and B with distinct assets, SBOMs, findings, and credentials.
2. Authenticate as a member of A.
3. Assert request for B's asset id, finding id, SBOM id, export id, and credential id using A's session is denied (not found / forbidden) and returns no B payload.
4. Assert `findById` without organization context is impossible at the type/repository layer (test the port).
5. Assert object key for A's digest is not readable via B's API.
6. Replay a job for A's SBOM with a tampered payload `organizationId: B` and assert no B mutation and no A/B mix.

Do not include exploit payloads. Minimal fixtures only.

## How background jobs retain and validate organization context

1. **OutboxEvent** for tenant work **must** include `organizationId` and a `dedupeKey` unique per organization.
2. **BackgroundJob** payload may repeat those ids for routing.
3. The handler loads the aggregate (`sbomId`, `findingId`, …) and **compares** persisted `organizationId` to the authorized value from the row.
4. On mismatch, the job **fails terminal** to the dead-letter path without mutating, and an operational metric fires. It does not "repair" by writing to the payload org.
5. Process one organization's data per job.

System jobs (OSV **modified-since** refresh) have null organization and must not write tenant findings except via a subsequent tenant-scoped outbox event per affected org/finding. Targeted package queries, if used, are **per-organization** jobs and must not persist tenant package names on global catalog rows.

## How cache keys include organization context

Any cache (HTTP response cache, Redis cache if added later) for tenant-owned data **must** include `organizationId` in the key. Global intel cache keys must **not** include tenant ids and must not store tenant component names.

Forbidden: `finding:{findingId}` without org. Required: `org:{organizationId}:finding:{findingId}` or no cache.

## PostgreSQL row-level security (future)

Application-level organization scoping is the v0.1 strategy. **Row-Level Security (RLS)** is a future defense-in-depth option. It is **not** an MVP requirement: session GUCs are easy to get wrong in connection pools, and RLS does not replace use-case authorization. Revisit with an ADR if pool-safe session variables and a compelling residual-risk argument exist.

## How logs and metrics avoid disclosure

Log organization and resource **UUIDs**, counts, and hashes — not raw SBOMs, package lists, or export bodies. Metric labels: event type and state, not tenant name or package name. See [observability](observability.md).

## How support and administrative access is controlled

No application API lists all organizations' Restricted data. Instance operators use infrastructure access (see [OD-10](open-decisions.md)). Support must not request a "break-glass org switcher." Incidents: [tenant-isolation-incident.md](../runbooks/tenant-isolation-incident.md).

## Tenant deletion vs evidentiary retention

v0.1 has no self-service hard delete of an organization. Archive hides writes. Purge, if ever added, must not cascade-delete audit or original SBOMs without the [retention](retention-and-deletion.md) job and new audit events. Application-level scoping remains required even if RLS is added later.

## How administrative operations are separated

| Plane | Examples | Data scope |
| --- | --- | --- |
| Tenant admin | Invite members, archive asset, publish org policy override, rotate **ExternalCredential** | Single authorized organization |
| Instance operator | Enable system OSV/KEV integration, set refresh schedule, inspect queue lag, restore backups | Shared catalogs, infrastructure. **No** API that lists all orgs' SBOMs |
| Break-glass | None in v0.1 | A cross-organization operator bypass requires an accepted ADR |

Backup restoration is an infrastructure action. Application login after restore still uses membership. Operators should treat database and object-storage backups as **Restricted** ([data classification](data-classification.md)).

## Confused deputy and IDOR

- Asset, SBOM, finding, assignment, export, and credential ids are unguessable UUIDs **and** still require org predicates.
- Object keys include organization so a leaked digest from a public SBOM discussion does not yield another tenant's object even if hashes collide across orgs (same content could theoretically match; keys still differ by org prefix, and ACL is private).
- Exports do not include other organizations' rows.

## Related documents

- [Trust boundaries](trust-boundaries.md)
- [Domain model](domain-model.md)
- [Testing strategy](testing-strategy.md)
- [Threat model](../security/threat-model.md)
