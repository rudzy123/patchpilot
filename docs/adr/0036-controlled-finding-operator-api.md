# ADR 0036: Controlled Finding operator API

- Status: Accepted
- Date: 2026-10-07
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the reachability decision for the already implemented controlled Finding
creation and inspection capabilities. Merge to `main` remains subject to normal
pull-request review. This ADR does not implement routes, compose production, add a
migration, or authorize any Finding power beyond the two routes named here.

## Context

[ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) section 10A admits
one creation-only exception, `controlled_maintainer_reviewed_finding_creation_v1`.
[ADR 0035](0035-controlled-finding-creation.md) accepts that slice. The atomic creation
transaction, evidence links, `finding.created`, and safe inspection are implemented and
production uncomposed. The Controlled Finding vertical slice is merged. No API route
calls those services.

ADR 0026 item 11 and ADR 0035 section 8 withheld every API route. That withholding is
the governance condition this decision resolves. It is not permission to invent a
Finding product.

[ADR 0019](0019-local-password-sessions.md) is the authentication, opaque-session,
organization-selection, CSRF, and interim permission decision. A client-supplied
organization id is not authority. [Tenant isolation](../architecture/tenant-isolation.md)
requires an organization predicate from trusted context. A foreign tenant-owned row and
an absent row stay publicly indistinguishable. [Audit](../architecture/audit-model.md)
is append-only. `finding.created` is already the creation event inside the uncomposed
transaction. Rejected requests are not audit rows.

The runtime permission catalog still has `finding:read` and `finding:triage`. Neither
constant is this slice. The sealed issuer remains unexported. Worker, web, seed,
scheduler, queue, and Outbox composition cannot construct it.

## Decision

PatchPilot accepts deliberate, authenticated operator reachability for the existing
controlled Finding services, and withholds every other Finding surface.

### 1. Access surface

One production surface is authorized, and only as a later API-process implementation:

- `POST /findings`
- `GET /findings/:findingId`

This decision does not authorize a CLI, web action, worker command, queue, scheduler,
upload trigger, evaluator trigger, provider trigger, bulk route, Finding list route, or
qualifying-evidence preview route. `GET /findings` is not authorized. No other method
or path is authorized. This ADR does not register either route.

### 2. Creation route

`POST /findings` is owner-initiated controlled Finding creation. It calls the existing
controlled creation application service after the authorization-issuance boundary in
section 6. It creates at most one Finding for one target. It does not create
observations for later ingestions, and it does not transition an existing Finding.

### 3. Inspection route

`GET /findings/:findingId` is owner and admin inspection of one Finding in the active
session organization.

- The route requires `finding:inspect`.
- Organization scope is the active session organization.
- The route does not require `finding:create_controlled` or any other creation
  authority.
- A successful response returns only the existing bounded safe inspection projection.
- A foreign Finding and an absent Finding are publicly indistinguishable.
- The route changes no state. It writes no Finding, observation, evidence link, or
  audit row.

The projection's display names, component names, and observed versions remain untrusted
data. This ADR does not claim that a client can render them without output encoding.
The affected-version display limit remains 8. The response is `application/json` with
`Cache-Control: private, no-store`.

### 4. Permissions

Two permissions are added to the [ADR 0019](0019-local-password-sessions.md) interim
catalog. That catalog is extended, not superseded.

| Permission | Meaning |
| --- | --- |
| `finding:create_controlled` | Call `POST /findings` for one controlled creation |
| `finding:inspect` | Call `GET /findings/:findingId` for the safe projection |

Initial role mapping:

| Role | `finding:create_controlled` | `finding:inspect` |
| --- | --- | --- |
| owner | yes | yes |
| admin | no | yes |
| member | no | no |
| viewer | no | no |

These statements are binding:

- `finding:triage` is not creation authority.
- `finding:read` is not inspection authority for this slice.
- Organization administrator status is not creation authority.
- Creation and inspection permissions are not interchangeable. Holding one does not
  grant the other. The owner mapping grants both by role mapping, and each route still
  checks its own permission.
- Widening either permission, including granting one to `member` or `viewer`, or
  granting creation to `admin`, requires a later permission review.
- A role string, permission list, or administrator flag in the request is ambient
  authority and is rejected. The server derives the permission from the active
  membership role.

The runtime catalog does not grant these permissions until the implementation branch.
This ADR does not change that code.

### 5. Authentication and tenancy

The routes use the existing opaque server-side session from ADR 0019. The API derives
all of the following from committed server-side session state:

- the authenticated actor;
- the active organization;
- the active membership;
- the role-derived explicit permission.

The request body, path, query, header organization field, and webhook-shaped field do
not establish organization authority. `activeOrganizationId` remains a selector. The
server reloads the active membership from persistence before mutation, and the creation
transaction reloads that active membership again together with the complete evidence
set.

Foreign and absent assets, evidence, and Findings remain publicly indistinguishable
where this slice and the tenant-isolation architecture require it. Lookup by resource
id alone is not authorization. The organization predicate comes from the session.

### 6. Authorization-issuance boundary

Creation authority may be issued only inside one controlled application factory, and
only after all of the following have succeeded:

1. session authentication;
2. active organization and membership resolution;
3. `finding:create_controlled`;
4. strict request validation;
5. bounded canonical evidence acknowledgement.

The issuer function remains absent from public package exports and from API route
source. Route modules call the application service. They do not import or call the
issuer. The factory is the only production caller of the issuer. It is not a barrel
export of `@patchpilot/domain` or `@patchpilot/database`.

Worker, web, seed, scheduler, queue, and Outbox composition remain unable to construct
the creation factory. The API composition root is the only production constructor. The
implementation must keep a source test that proves that confinement. This ADR does not
add the factory.

The sealed authorization remains purpose-specific and process-local under ADR 0035.
The new permission is the route gate that allows the factory to be asked. It is not
itself the sealed authorization, and it is not a durable authority row.

### 7. Creation request

The public JSON object contains exactly these fields:

- `assetId`
- `componentId`
- `vulnerabilityId`
- `expectedSbomIngestionId`
- `expectedProductMatchEvidenceIds`

`expectedProductMatchEvidenceIds` is a JSON array of 1 to 16 identifiers. The array
is the evidence set the operator reviewed. Each identifier is a lowercase canonical
UUID. The array is strictly ascending in UTF-16 code-unit order, with no duplicates.
The server does not sort, deduplicate, or drop entries for the client.

The object is closed. `organizationId`, an authorization handle, purpose, policy,
correlation id, idempotency key, role, and any other property are invalid. The server
binds the target to the session organization and supplies correlation from the
transport correlation id. One request names one asset, one versionless component, and
one Vulnerability.

The evidence-set ceiling remains the existing `finding_creation_policy_v1` version 1
limit of 16. This ADR does not change that policy, Finding identity, or the creation
transaction's writes.

### 8. Evidence acknowledgement

The operator names the evidence set that was reviewed. The creation transaction
re-derives the complete current affected Product Match Evidence set from storage and
requires exact equality with that named set. The server must not silently substitute
newly discovered evidence, drop a member, or complete a partial set. An incomplete,
unequal, or stale set fails closed and writes nothing. The failure body does not
return the correct qualifying set.

### 9. Replay and stale evidence

No HTTP idempotency table or `Idempotency-Key` is required. Finding natural identity
and creation-lineage replay remain the idempotency authority.

Exact replay is the same organization, natural identity, creation purpose, policy
version, and sorted evidence-set fingerprint. Exact replay writes nothing, including
no second `finding.created` event, and returns the existing Finding id.

A different evidence-set fingerprint for the same natural identity is an immutable
conflict. It overwrites nothing and creates no second Finding. Evidence that is no
longer the current qualifying set is stale. Stale evidence and immutable conflict are
the same public conflict result. The response does not disclose which member differed
or what the current set is.

### 10. CSRF and Origin

`POST /findings` is an authenticated state-changing request under ADR 0019:

- `Content-Type: application/json`, with `charset=utf-8` as the only optional
  parameter;
- exact `Origin` match against `CORS_ALLOWED_ORIGINS`, with a missing or unlisted
  origin rejected rather than defaulted;
- the existing synchronizer CSRF header named by `AUTH_CSRF_HEADER_NAME`, matched to
  the session digest;
- the existing session cookie.

Referer is not sufficient. CSRF tokens are not logged. `GET /findings/:findingId` does
not require Origin or CSRF because it does not mutate. A GET body is an invalid
request. `SameSite=Lax` and `trustProxy=false` are unchanged.

Origin denial is forbidden. Missing session and CSRF failure are unauthenticated.
Those are different public results, matching the existing Origin and CSRF controls.

### 11. Rate and capacity

Initial architectural limits for this slice:

| Limit | Value |
| --- | --- |
| Creation targets per request | 1 |
| Evidence ids per creation | 1 to 16 |
| Creation route body | 4096 bytes |
| Creation peer | 5 per 60 seconds |
| Creation organization | 5 per 60 seconds |
| Inspection peer | 60 per 60 seconds |
| Affected-version display | 8 |

The creation route body limit is independent of the global request-body limit. The
creation peer limit and the creation organization limit both apply. The inspection
route has no organization limiter in this slice. Creation and inspection counters are
independent.

The peer key is the direct socket address. `X-Forwarded-For` is not a key.
`trustProxy` stays false. A missing peer shares one `unknown-peer` bucket. The
organization limiter is process-local, in memory, and uses a fixed 60-second window
of the same shape as the existing SBOM organization limiter. It scales per API
process: each process allows its own 5 creations per 60 seconds for an organization.
That multiplication is an accepted residual for this first slice. No rate-limit
migration, Redis schema, or new dependency is authorized. A limiter fault fails
closed as service unavailable and does not admit the request.

### 12. Audit

`finding.created` remains the sole immutable creation audit event. It is already
implemented by the controlled creation transaction. The payload stays the implemented
metadata: purpose, policy id, policy version, affected evidence count, and ingestion
id. It does not gain evidence ids. Exact replay creates no second audit event.

Rejected creation requests and routine inspection reads remain bounded security logs
or metrics. They are not immutable audit rows. This ADR does not add
`finding.inspected`, `finding.rejected`, or a second creation action.

### 13. Logging and telemetry

Logs and metrics for these routes may include:

- the route template;
- the public outcome;
- the request id;
- the transport correlation id;
- the authenticated actor and organization where an internal security log is
  appropriate.

They must omit:

- request bodies;
- evidence ids;
- Finding ids in metric labels;
- asset, component, vulnerability, ingestion, and other raw resource ids in logs and
  metric labels;
- authority handles;
- cookies;
- CSRF tokens;
- protected evidence;
- database internals, SQL, and constraint names.

Metric labels are the route template and the public outcome only. This is narrower
than the future logging allowance in ADR 0026 section 34, and it applies only to
these two routes. The authorized JSON response may still return the Finding id to
the caller. The audit row may still store that id as its subject.

### 14. Result translation

Public HTTP behavior is stable. Failure bodies use the existing error envelope and
expose no SQL, constraint name, authority state, evidence id, reviewer identity,
foreign tenant identity, or correct qualifying evidence set. Internal reason names
are not public codes.

| Condition | Status | Body |
| --- | --- | --- |
| `created` | 201 | `status` and Finding id only |
| `already_applied` | 200 | `status` and Finding id only |
| Invalid request, including a closed-body violation, unsorted or duplicate evidence ids, an empty or oversized set, a non-JSON content type, a body over 4096 bytes, or a non-UUID path id | 400 | Safe invalid-request message |
| Missing session or CSRF failure | 401 | Safe unauthenticated message |
| Origin denial, missing active organization or membership, or missing permission | 403 | Safe forbidden message |
| Absent or foreign target | 404 | Same not-found body for foreign and absent |
| Conflict or stale evidence, including an unequal evidence set, evidence that is not current, an immutable conflict, or an existing Finding that is not an exact replay | 409 | Safe conflict message, without the qualifying set |
| Ineligible or unavailable creation evidence | 422 | Safe unprocessable message |
| Rate limit exceeded | 429 | Safe rate-limit message |
| Database or limiter unavailable | 503 | Safe unavailable message |
| Malformed persisted state, aborted transaction, or other internal failure | 500 | Safe internal message |

Inspection success is 200 and the bounded projection only. Inspection `not_found` is
404 and is identical for a foreign Finding and an absent Finding. Inspection evidence
that cannot be explained is 422. Inspection malformed persisted state is 500.
Inspection does not return creation status.

A body-limit or content-type failure for this slice is 400, not a separate public
413 or 415. Every response on these routes is `Cache-Control: private, no-store`.

### 15. Production composition

This ADR authorizes only API-process composition of:

- the controlled creation application service;
- the private authorization-issuance boundary;
- the controlled creation persistence adapter;
- the controlled inspection permission wrapper;
- the safe inspection service and persistence adapter;
- the existing session, permission, CSRF, Origin, rate-limit, and audit dependencies.

It does not authorize worker, web-server action, scheduler, queue, matching, provider,
evaluator, or lifecycle composition. Production startup today does not construct these
routes. Seed and migration do not insert Findings. Acceptance of this ADR does not
perform the composition.

### 16. Explicit deferrals

The following remain unavailable:

- qualifying-evidence preview;
- Finding list;
- web UI;
- CLI;
- automatic matching;
- automatic and bulk Finding creation;
- repeated observations;
- lifecycle transitions;
- risk and priority;
- assignment and due dates;
- suppression;
- accepted risk;
- false-positive decisions;
- remediation;
- verification;
- notifications;
- dashboards;
- exports;
- ticketing;
- AI authority;
- automatic closure and reopening;
- historical backfill.

SLA policy stays deferred under ADR 0035. Provider-driven Finding creation stays
behind the ADR 0026 provider gate. This ADR does not satisfy that gate.

## Alternatives considered

- **Leave both routes withheld.** Rejected for this decision: the creation and
  inspection capabilities are already implemented, and operators still have no
  deliberate authenticated reachability. The withholding was a governance condition,
  not a finding that the services are unsafe to call under these controls.
- **Reuse `finding:read` and `finding:triage`.** Rejected: `finding:read` is already
  granted to every role, and `finding:triage` is already granted to members. Reuse
  would make this slice a general Finding workflow.
- **Treat the admin role as creation authority.** Rejected: administrator status is
  ambient. Creation stays on the explicit owner permission.
- **Add an HTTP idempotency table.** Rejected: Finding identity and lineage replay
  are already the authority. A second table would be a second writer.
- **Return the re-derived evidence set on mismatch.** Rejected: that response would
  disclose the qualifying set to a caller who did not name it.
- **Use a shared Redis organization limiter now.** Rejected for this slice: it would
  add operational machinery and possibly a migration. The process-local ceiling is
  an accepted residual.
- **Authorize a list, preview, web action, or CLI in the same decision.** Rejected:
  each widens tenant disclosure or the set of composers that can construct creation.

## Consequences

Positive: one owner can deliberately create one controlled Finding, and an owner or
admin can inspect it, without opening automatic creation or the rest of the lifecycle.
Replay, audit, and tenant indistinguishability stay on the existing transaction.

Negative: until the implementation branch, the permissions and routes are still
absent, so this acceptance is not an operator capability. The process-local
organization limit is weaker on multiple API processes than a shared limiter. The
runtime permission catalog and the sealed issuer stay unchanged by this ADR, so an
implementation that exports the issuer or grants `finding:read` as inspection would
violate this decision.

## Security and tenancy

The Finding, observation, evidence links, and `finding.created` event stay
tenant-owned. The session organization is the only organization predicate. Shared
advisory rows stay shared. No new object-storage layout, secret, or outbound fetch is
introduced. No cross-organization operator bypass is added.

Foreign and absent targets share one public not-found result. Logs follow section 13
and the canonical redaction list. Audit rows are not updated or deleted. Evidence is
not cascade-deleted. The issuer stays unexported. Product Match Evidence still does
not grant Finding authority by itself.

## Operational failure plan

An unauthenticated, forbidden, invalid, absent, conflicting, ineligible, or
rate-limited request writes nothing. Exact replay returns the existing Finding and
does not append audit. A database failure rolls back the creation transaction; a
later exact retry returns the existing Finding when the commit had succeeded, and
creates it once when the commit had not. A limiter fault fails closed. Operators do
not insert Findings, edit frozen migrations, or seed evidence to make a request
succeed. There is no route to operate until the implementation branch registers the
two paths.

## Follow-up

The implementation branch may register only `POST /findings` and
`GET /findings/:findingId`, add the two permission constants with the mapping in
section 4, and compose the API process as section 15 allows. It needs
tenant-isolation, CSRF and Origin, rate-limit, replay, stale-evidence, audit, and
issuer-confinement tests, without exploit payloads. It must not add a migration, a
dependency, a list route, a preview route, a worker composer, or a lifecycle
transition. A runbook for the composed routes belongs to that implementation, not to
this decision.
