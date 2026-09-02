# ADR 0022: Intelligence provider-status authorization

- Status: Accepted
- Date: 2026-09-02
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted for implementation on this feature branch. Merge to `main` remains subject to normal pull-request review. This ADR does **not** supersede [ADR 0019](0019-local-password-sessions.md) (authentication and the interim permission catalog) or [ADR 0021](0021-vulnerability-intelligence-import-foundation.md) (import-only shared catalog). It does not close [OD-10](../architecture/open-decisions.md) instance-operator identity.

## Context

Session 9 imports a **global, instance-owned** vulnerability-intelligence catalog ([ADR 0021](0021-vulnerability-intelligence-import-foundation.md)). Batch 8B schedules and processes CISA KEV synchronization in `apps/worker`. Operators and authenticated product users still had no HTTP surface that could report whether KEV had ever synchronized, whether the accepted generation was current, or that OSV remains deferred.

Those facts are operational, not tenant-owned. Duplicating `IntelligenceSource` or `KevGeneration` per Organization would invent a false tenancy boundary and a consistency hazard. Treating the active Organization as a query predicate would also be incorrect: the rows have null organization identity by design.

Product access still requires an authenticated session and an active membership in an active Organization ([ADR 0013](0013-organization-scoped-tenancy.md), [ADR 0019](0019-local-password-sessions.md)). Global ownership must not become anonymous public access. Reusing `integration:read` (admin/owner only) or `finding:read` would either hide status from viewers or imply a Finding workflow that Session 9 must not have.

Internal failure codes, object keys, worker identifiers, SyncRun history, and queue state are too detailed for a product-status response. Manual synchronization, retry, and detailed run APIs remain deferred.

## Decision

Sanitized provider status is **instance-owned global operational data**. Access is authenticated and permission-protected. The active Organization is **product-access context only**. It does not scope, own, or duplicate the global intelligence rows. There is no synthetic global Organization.

### Permission

Add the closed permission `intelligence:read`. Grant it to `viewer`, `member`, `admin`, and `owner`. Do not reuse `integration:read`, `finding:read`, `sbom:read`, or asset permissions. Do not change unrelated grants.

Both Session 9 status GET routes require:

1. A valid authenticated session.
2. Active Organization context.
3. Active membership in an active Organization.
4. `intelligence:read`.

Do not pass `organizationId` into the provider-status read port. Do not add an organization predicate to global intelligence queries.

### Public surface

Implement exactly:

- `GET /intelligence/providers`
- `GET /intelligence/providers/:provider/status`

The path provider is closed and case-sensitive: `cisa_kev` and `osv`. Unknown values, aliases, mixed-case, and extra segments return tenant-safe `404` `not_found`. Do not query `IntegrationProvider` as a fallback.

Responses use one strict provider-status object for list entries and detail. The list contains exactly two entries, `cisa_kev` then `osv`. Nullable keys are present and explicit `null`. Responses are `Cache-Control: private, no-store`. Do not add ETag, Last-Modified, or shared caching.

GET requests are side-effect free except existing session `lastSeenAt` bookkeeping. They must not call CISA, Redis, BullMQ, MinIO, the parser, the scheduler, or worker runtime. They must not start synchronization, write `OutboxEvent`, `BackgroundJob`, `IntelligenceSource`, generations, or `AuditEvent`. Do not add `intelligence.status_read`.

OSV is always deferred: `runtimeEnabled=false`, `healthStatus=deferred`, and null attempt, catalog, and failure fields. OSV status must not depend on database state.

### Health and failure mapping

KEV `runtimeEnabled` comes from typed API-process configuration, not persisted `IntelligenceSource.state`. Health precedence is: disabled (when runtime-disabled, including disabled-with-history) → never_synchronized → stale over degraded → degraded → current. Disabled is never current, stale, or degraded. Public responses expose only the coarse mapped failure codes `provider_unavailable`, `synchronization_timeout`, `invalid_provider_response`, `storage_unavailable`, `processing_failed`, and `catalog_regression`. Internal codes, retryable flags, dispositions, stacks, provider bodies, object keys, and `nextAttemptAt` stay private.

### Deferred

This ADR does **not** add:

- POST synchronization, manual retry, DELETE/PUT/PATCH intelligence routes
- detailed SyncRun, generation-history, snapshot, or KEV CVE list APIs
- instance-operator identity or a cross-organization operator bypass ([OD-10](../architecture/open-decisions.md) remains open)
- OpenAPI, a web dashboard, OSV runtime, ZIP support, matching, Findings, risk scoring, or remediation

Session 9 provider-status reads create and change **zero Findings**.

## Alternatives considered

1. **Anonymous or public provider status.** Rejected: global ownership is not public access. Catalog freshness would become an unauthenticated reconnaissance surface.
2. **Scope status by `organizationId`.** Rejected: the rows are instance-owned. Per-org copies would diverge and imply tenant ownership of a shared catalog.
3. **Reuse `integration:read` or `finding:read`.** Rejected: `integration:read` is admin/owner-only and describes tenant integration installations. `finding:read` implies a Finding workflow Session 9 must not have.
4. **Instance-operator-only status.** Rejected: OD-10 is unresolved, and viewers need to know whether the shared catalog is current. Product members already have an authenticated Organization context.
5. **Expose internal SyncRun, worker, queue, or safe-failure enums.** Rejected: those leak execution internals and confuse product health (`syncing`, `failed`, `quarantined`) with catalog freshness.
6. **Audit every status GET.** Rejected: routine reads would drown the append-only audit log. Synchronization already emits `intelligence.sync_*` events.

## Consequences

Authenticated viewers can read sanitized KEV freshness and the OSV deferred invariant without waiting for an instance-operator console. Two Organizations on the same instance see the same payload when global status is unchanged.

Negative: operators still have no manual sync, retry, or detailed run API. Persistence inconsistency maps to a generic 500. A missing CISA `IntelligenceSource` row maps to 503 without revealing row existence. Enablement mismatches between typed config and persisted source state are not reconciled by GET.

## Security and tenancy

This ADR does not weaken [ADR 0013](0013-organization-scoped-tenancy.md). Active Organization remains mandatory product-access context. It is not authorization to read another tenant's SBOMs, Findings, or credentials, and it is not a data-scope predicate on global intelligence rows.

Construct public objects explicitly. Do not spread persistence records into HTTP responses. Canonical log redaction still forbids provider bodies, object keys, cookies, and credentials.

## Operational failure plan

| Failure | Detection | Recovery |
| --- | --- | --- |
| Missing CISA `IntelligenceSource` or database unavailable | HTTP 503 `Intelligence status is temporarily unavailable.` | Restore PostgreSQL / seed; do not fetch CISA from the API |
| Pointer or generation inconsistency | HTTP 500 generic internal message | Operator inspects global intelligence rows; GET must not repair pointers |
| Contract validation failure | HTTP 500 generic internal message | Fix mapping; do not guess current/stale/degraded |
| Unauthenticated or expired session | HTTP 401 | Re-authenticate |
| Missing Organization context or `intelligence:read` | HTTP 403 | Select an active Organization or use a granted role |

GET remains read-only. Last accepted catalog stays reader authority. Disabled-with-history preserves accepted metadata and never labels it current.

## Follow-up

Manual synchronization, retry, detailed SyncRun APIs, dashboards, OSV runtime, matching, Findings, and instance-operator identity remain later work. Required tests: contract invariants, permission matrix, derivation, bounded PostgreSQL read, route authorization, private no-store, source boundaries, and zero-Finding reads.
