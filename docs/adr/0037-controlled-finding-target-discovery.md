# ADR 0037: Controlled Finding target discovery

- Status: Accepted
- Date: 2026-10-07
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the governance decision for one read-only, asset-scoped operator discovery
route. Merge to `main` remains subject to normal pull-request review. This ADR does
not implement the route, register it, add a permission constant, add a migration, or
authorize any Finding lifecycle power.

## Context

[ADR 0035](0035-controlled-finding-creation.md) accepts creation-only Finding
architecture. [ADR 0036](0036-controlled-finding-operator-api.md) accepts owner
`POST /findings` and owner or admin `GET /findings/:findingId`. Those routes are
composed in the API process. Exact replay is publicly reachable. Creation still
requires the operator to name the evidence set. Neither composed route returns the
acknowledgement object `POST /findings` requires.

ADR 0035 and ADR 0036 withheld qualifying-evidence preview and any discovery
reachability. [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md)
section 10A item 11 carried the same withhold. That withhold is the governance
condition this decision resolves. It is not permission to add a Finding list, a second
preview, or a lifecycle workflow.

The creation transaction remains authoritative. It re-derives the complete current
qualifying Product Match Evidence set and requires exact equality with the named set.
Product Match Evidence does not grant Finding authority. A client-supplied
organization id is not tenancy.

## Decision

PatchPilot accepts one later read-only discovery route and withholds every other new
Finding surface.

### 1. Access surface

One route is authorized, and only as a later API-process implementation:

- `GET /assets/:assetId/controlled-finding-targets`

The path asset id is a resource selector. It is not tenancy authority. One request
names one asset. The route returns bounded current targets for that asset and, where
this decision allows it, the acknowledgement `POST /findings` already requires.

This decision does not authorize:

- a global discovery route;
- a Finding list, including `GET /findings`;
- a second preview route;
- arbitrary search or a filter language;
- cross-asset discovery;
- a web UI;
- a CLI;
- create-all;
- preview-and-create;
- worker, queue, scheduler, upload, evaluator, or provider discovery.

No other method or path is authorized. This ADR does not register the route.
`POST /findings` and `GET /findings/:findingId` remain the only creation and
inspection routes.

### 2. Permission

Add `finding:discover_controlled` to the [ADR 0019](0019-local-password-sessions.md)
interim catalog. That catalog is extended, not superseded.

The permission grants discovery only. It does not grant:

- `finding:create_controlled`;
- `finding:inspect`;
- `finding:triage`;
- Finding creation authority;
- Finding inspection authority;
- lifecycle authority.

`finding:read` and `finding:triage` are not this permission. Organization
administrator status is not this permission. The sealed creation authorization in
ADR 0035 is not this permission. Holding discovery does not allow the caller to
invoke `POST /findings` or `GET /findings/:findingId`. Holding creation or inspection
does not allow discovery. The owner role mapping below grants more than one
permission, and each route still checks only its own permission.

The runtime catalog does not include `finding:discover_controlled` until the
implementation branch. This ADR does not change that code. Widening the mapping,
including granting discovery to `member` or `viewer`, requires a later permission
review.

### 3. Role mapping

| Role | `finding:discover_controlled` | `finding:create_controlled` | `finding:inspect` |
| --- | --- | --- | --- |
| owner | yes | yes | yes |
| admin | yes | no | yes |
| member | no | no | no |
| viewer | no | no | no |

An admin may receive an acknowledgement and still cannot create. The acknowledgement
is not a creation grant. `POST /findings` continues to require
`finding:create_controlled`. A role string or permission list in the request is
ambient authority and is rejected. The server derives the permission from the active
membership role.

### 4. Tenant context

The route requires all of the following:

- an authenticated opaque session under ADR 0019;
- an active organization;
- an active membership in that organization;
- `finding:discover_controlled` on that membership;
- an organization-scoped asset lookup using the organization from that session.

The request path, query, header, and body do not establish organization authority.
Lookup by asset id alone is not authorization. Foreign and absent assets are publicly
indistinguishable: the same not-found result, with no body that reveals which case
occurred. Permission is checked before the asset lookup, so a caller without
discovery permission receives forbidden and does not learn whether the asset id
exists.

### 5. Candidate identity

One candidate is one current target:

- the trusted organization;
- one asset in that organization;
- one versionless Component;
- one Vulnerability;
- the asset's latest successful SBOM ingestion;
- the complete current qualifying Product Match Evidence set for that scope.

The Finding natural identity is unchanged:
`organization_id` + `asset_id` + `component_id` + `vulnerability_id`.
The candidate is not a Finding. It does not grant creation authority. Occurrence,
SBOM, ingestion, evidence id, package version, CVE, and KEV membership stay out of
Finding identity.

The examination space is the distinct Component and Vulnerability pairs that have
Product Match Evidence for the trusted organization, the authorized asset, and that
latest successful ingestion. Pairs that exist only on an older ingestion are not
candidates. Historical Findings that no longer have a current qualifying set do not
appear.

### 6. Candidate eligibility

Candidate evidence uses the same authoritative eligibility predicate as controlled
Finding creation. Today that predicate is
`patchpilot_finding_creation_qualifying_evidence`, as the creation transaction
already calls it. Discovery must call that predicate, or a repository port that
returns exactly the same set. It must not define a weaker predicate and must not
add or drop members.

A complete current set qualifies only when that predicate accepts it, including the
accepted requirements for:

- organization;
- asset;
- versionless Component;
- Vulnerability;
- latest successful ingestion;
- `affected` outcome;
- reviewed maintainer-reviewed advisory authority;
- consumed immutable approval;
- the accepted evaluator and policy identities;
- revision currentness, including not withdrawn, not quarantined, and not superseded;
- normalization version `2` on a completed graph;
- persisted-row integrity already enforced by that predicate, including occurrence
  linkage, `version_known`, the asset's latest-successful pointer, reviewed binding,
  `finding_creation` remaining `unavailable` on the evidence row, and suppression
  authority remaining false.

An unaffected, unknown, malformed, synthetic, or withdrawn row is not a member. An
unaffected occurrence does not veto an affected occurrence. KEV membership does not
add or remove a member. An empty result is not a candidate. An incomplete set is not
returned as a partial candidate.

### 7. Acknowledgement

For `eligible_for_creation` and `exact_replay_available`, the candidate includes the
existing `POST /findings` acknowledgement object and no other creation field:

- `assetId`;
- `componentId`;
- `vulnerabilityId`;
- `expectedSbomIngestionId`;
- `expectedProductMatchEvidenceIds`.

`expectedProductMatchEvidenceIds` is the complete qualifying set: 1 to 16 lowercase
canonical UUIDs, strictly ascending in UTF-16 code-unit order, with no duplicates.
Discovery emits that order so the operator can submit the object unchanged.
`POST /findings` still does not sort, deduplicate, or repair a client array.

The object is closed. Discovery does not add `organizationId`, a cursor, a purpose,
a policy, a correlation id, an idempotency key, a role, or an authorization handle
to the acknowledgement.

This decision does not introduce:

- a signed token;
- a durable acknowledgement;
- a second replay identity;
- server-side evidence substitution.

Evidence ids inside the acknowledgement are identifiers the operator explicitly
resubmits. They are not authority. The `POST /findings` transaction continues to
re-derive the qualifying set and require exact equality.

### 8. Product Match Evidence id classification

A Product Match Evidence id in this response is an acknowledgement identifier. It
does not authorize creation, inspection, replay, or a lifecycle change. Presenting
the id to any route other than a later operator `POST /findings` grants nothing.
The creation transaction ignores discovery as a trust source and reloads the set
from storage.

### 9. Candidate classifications

Each returned candidate has exactly one classification:

| Classification | Meaning | Acknowledgement |
| --- | --- | --- |
| `eligible_for_creation` | The complete current set has 1 to 16 members, and no Finding exists for the natural identity | returned |
| `exact_replay_available` | That set has 1 to 16 members, a Finding exists, and the creation replay comparison would be exact replay (`already_applied`) | returned |
| `existing_finding` | That set has 1 to 16 members, a Finding exists, and the creation replay comparison would be an immutable conflict | omitted |

Exact replay keeps the ADR 0035 comparison: same organization, natural identity,
creation purpose, policy version, and sorted evidence-set fingerprint.

`existing_finding` omits the acknowledgement, including evidence ids and the
ingestion id. The candidate still returns `componentId`, `vulnerabilityId`, and
`lifecycleUpdate` with the value `unavailable`. It does not return a Finding id.
Discovery must not become a Finding index. Lifecycle update stays unavailable.

Malformed Finding lineage fails the entire request closed. If any examined pair
with a current qualifying set has persisted creation state that the creation replay
comparison classifies as malformed, the request returns no page. The server does
not skip that pair, does not omit it as oversized, and does not continue.

### 10. Multiple versions

Several affected versions of one Component and one Vulnerability on that ingestion
are one candidate. Discovery does not emit one candidate per occurrence or per
evidence row.

Each returned candidate includes:

- one complete evidence acknowledgement, except `existing_finding`, which omits it;
- `affectedOccurrenceCount`, the number of qualifying affected occurrences;
- a bounded affected-version summary;
- explicit truncation metadata;
- `otherOccurrenceCount`.

The version summary follows the inspection display limit of 8 distinct version
strings, ordered by UTF-16 code-unit order, with `truncated` and the omitted
distinct count. Strings that fail the existing inspection display-text rule are
omitted from the summary and counted as truncated. They are not logged. Occurrence
count and the evidence acknowledgement still include those occurrences. Version
strings are untrusted display data. This ADR does not claim that a client can
render them without output encoding. Package names, PURLs, and component display
names are not returned.

`otherOccurrenceCount` is the number of occurrences of that versionless Component
on the same asset and latest successful ingestion that are not members of the
qualifying affected set. It is a count only. It does not list those occurrences,
their versions, or their evidence ids. It does not veto the candidate.

### 11. Oversized sets

`finding_creation_policy_v1` version 1 rejects a qualifying set larger than 16.
Discovery does not change that policy and does not truncate the set into a
creatable acknowledgement.

A pair whose complete qualifying set contains more than 16 evidence ids is omitted.
The response increments `oversizedCandidateCount` for that examined window. The
count is an integer from 0 through 100. It carries no Component, Vulnerability,
Finding, ingestion, asset, or evidence identity. A later page does not reveal the
omitted pair. An empty candidate list with a non-zero oversized count means every
examined qualifying pair on that window was oversized. It does not mean the asset
has no software.

### 12. Pagination and cursor

Pagination is keyset, not offset.

| Rule | Value |
| --- | --- |
| Page-size parameter | `limit` |
| Default page size | 10 |
| Minimum page size | 1 |
| Maximum page size | 20 |
| Maximum examined Component and Vulnerability pairs | 100 |
| Order | Component id, then Vulnerability id |
| Cursor binding | the latest successful ingestion used for that page |
| Cursor conflict | the cursor's ingestion is not that asset's current latest successful ingestion |
| Transaction | read-only repeatable read |

The only query fields are `limit` and `cursor`. Any other query field, a repeated
field, a non-integer `limit`, or a `limit` outside 1 to 20 is an invalid request.
An absent `limit` means 10. An absent `cursor` starts at the beginning. An empty
cursor is invalid.

The server examines pairs in order and stops at 100 examinations or at the end of
the pair space, whichever comes first. Non-qualifying pairs consume examination
budget and are not returned. Oversized pairs consume budget, increment the
anonymous count, and are not returned. Returned candidates stop at `limit`.

`nextCursor` is an opaque string positioned strictly after the last examined pair,
not merely the last returned candidate. It is present when the pair space continues
past the examination window. It is absent when the scan reached the end. The cursor
is bound to the latest successful ingestion id used for the page. It is not an
acknowledgement, not a signed token, and not authority.

A cursor whose ingestion is no longer the asset's latest successful ingestion,
including a cursor presented when the asset has no latest successful ingestion, is
a conflict. The server does not remap the cursor onto a newer ingestion and does
not return the new ingestion id. The client restarts without a cursor.

Each request uses its own read-only repeatable-read snapshot. Perfect consistency
across pages is not required. A commit between two requests can change a later
page. One request must not mix two ingestions.

An asset in the active organization with no qualifying pairs returns an empty
candidate page. That empty page is not the foreign-asset result.

### 13. Deterministic ordering

Component id and Vulnerability id are lowercase canonical UUIDs. Order is UTF-16
code-unit order on that canonical form: Component id first, Vulnerability id
second. The order is total. Evidence ids inside one acknowledgement use the same
UTF-16 order. Database collation must not reorder the page relative to that order.

### 14. Rate and capacity

| Limit | Value |
| --- | --- |
| Assets per request | 1 |
| Candidates per response | 20 |
| Evidence ids per returned candidate | 16 |
| Displayed distinct versions per candidate | 8 |
| Examined pairs per request | 100 |
| Peer | 30 per 60 seconds |
| Organization | 20 per 60 seconds |
| Statement timeout | 2 seconds |
| Response cache | `Cache-Control: private, no-store` |

The peer key is the direct socket address. `X-Forwarded-For` is not a key.
`trustProxy` stays false. A missing peer shares one `unknown-peer` bucket. The
peer limiter runs before authentication. A peer-limited request does not consume
the organization budget.

The organization limiter is process-local, in memory, and uses a fixed 60-second
window of the same shape as the existing SBOM and controlled-creation organization
limiters. It applies only after discovery permission succeeds. Each API process
allows 20 discovery requests per 60 seconds for an organization. Several API
processes multiply that ceiling. That multiplication is an accepted residual. No
rate-limit migration, Redis schema, or new dependency is authorized. A limiter
fault fails closed as service unavailable.

Discovery counters are independent of the creation counters (5 per 60 seconds) and
the inspection peer counter (60 per 60 seconds). The statement timeout applies to
the read-only transaction. A timeout returns no partial page.

### 15. Read-only behavior

The route must not:

- issue creation authority;
- invoke `POST /findings` or the creation application service;
- create a Finding;
- create an observation;
- create an evidence link;
- write an audit event;
- update evidence;
- acquire creation locks, row locks, or the controlled-creation session setting;
- mutate an asset or any other tenant row inside the discovery transaction;
- call a provider or evaluator.

The discovery transaction is read-only repeatable read. Existing session resolution
may update session last-seen metadata. That bookkeeping is not a discovery audit
event and is not a Finding write. Routine discovery requires no immutable audit
row. Do not add `finding.discovered`.

`GET` does not require Origin or CSRF. A request body is invalid. `SameSite=Lax`
and `trustProxy=false` are unchanged.

### 16. Staleness

Discovery is point-in-time. It does not promise that a later `POST /findings` will
succeed. The creation transaction remains authoritative. A stale or changed
acknowledgement fails closed. The server must not substitute a newly discovered
evidence set, drop a member, or complete a partial set. The failure body does not
return the correct qualifying set.

### 17. Result translation

Public HTTP behavior is stable. Failure bodies use the existing error envelope and
expose no SQL, constraint name, authority state, evidence id, cursor contents,
qualifying set, reviewer identity, or foreign tenant identity. Internal reason
names are not public codes. Every response is `Cache-Control: private, no-store`.

| Condition | Status | Body |
| --- | --- | --- |
| Page, including an empty page for an asset in the active organization | 200 | Bounded page only |
| Invalid request, including a non-UUID asset id, a body, an unknown or repeated query field, a bad `limit`, or a malformed cursor | 400 | Safe invalid-request message |
| Missing session | 401 | Safe unauthenticated message |
| Missing active organization or membership, or missing `finding:discover_controlled` | 403 | Safe forbidden message |
| Absent or foreign asset | 404 | Same not-found body for foreign and absent |
| Cursor ingestion is not the asset's current latest successful ingestion | 409 | Safe conflict message, without the current ingestion id or candidate identities |
| Rate limit exceeded | 429 | Safe rate-limit message |
| Database unavailable, limiter fault, or statement timeout | 503 | Safe unavailable message, with no partial page |
| Malformed Finding lineage, or any other internal failure | 500 | Safe internal message, with no partial page and no identities |

Ineligible pairs are omitted from a 200 page. They are not a 422 response.
`existing_finding` is a successful candidate, not a conflict. The conflict status
is reserved for a stale cursor.

A 200 body contains only:

- `candidates`;
- `oversizedCandidateCount`;
- `nextCursor`, when the pair space continues.

Each candidate contains `classification`, `componentId`, `vulnerabilityId`,
`affectedOccurrenceCount`, the bounded version summary and its truncation metadata,
and `otherOccurrenceCount`. `eligible_for_creation` and `exact_replay_available`
also contain `acknowledgement`. `existing_finding` contains `lifecycleUpdate` and
does not contain `acknowledgement` or a Finding id.

### 18. Logging, metrics, and audit

Logs for this route may include bounded:

- route template;
- public outcome;
- request id;
- transport correlation id;
- authenticated actor and organization, in an internal security log only;
- page size;
- candidate count;
- anonymous oversized count.

Metric labels are the route template and the public outcome only.

Logs, metrics, and traces must omit:

- evidence ids;
- asset, Component, Vulnerability, and Finding ids in metric labels;
- those raw resource ids in logs;
- package names;
- versions;
- cursors;
- acknowledgement bodies;
- authority material;
- raw advisory data;
- SQL and database internals.

Routine discovery writes no audit row. `finding.created` remains the only controlled
Finding audit event, and only the creation transaction writes it.

### 19. Anti-automation

The route is a deliberate operator read. It is not an automation trigger. The
implementation must not:

- call `POST /findings` for the caller;
- accept a create-all or preview-and-create flag;
- walk every asset in the organization;
- schedule discovery from the worker, web server, queue, or upload path;
- treat the acknowledgement as a bearer credential;
- relax the creation transaction's exact-equality check because discovery recently
  returned the same ids.

Page size, examination budget, peer limit, and organization limit bound enumeration.
They do not replace the permission check or the creation revalidation.

### 20. Production composition

This ADR authorizes only a later API-process composition of a read-only discovery
service. That composition may register only
`GET /assets/:assetId/controlled-finding-targets`. It may add the permission
constant and the role mapping in section 3. It may read through the existing
qualifying predicate.

It must not construct the creation factory, import the creation issuer, or compose
discovery into the worker, web server, scheduler, queue, seed, or migration. Web
startup and worker startup do not gain a Finding writer. Acceptance of this ADR
does not perform the composition.

### 21. Explicit deferrals

The following remain unavailable:

- automatic creation;
- bulk creation;
- create-all;
- Finding list;
- cross-asset discovery;
- arbitrary search;
- a second preview route;
- web UI;
- CLI;
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

Provider-driven Finding creation stays behind the ADR 0026 provider gate. This ADR
does not satisfy that gate. SLA policy stays deferred under ADR 0035.

## Migration intent

No schema change is required. No migration is required. No durable acknowledgement
model is required. No rate-limit persistence is required. No read-optimization
index is authorized in this slice. A future index requires separate measured
evidence and its own review. This decision does not change the frozen migration
count.

## Alternatives considered

- **Keep discovery withheld.** Rejected for this decision: owners can create a
  Finding only by already knowing the acknowledgement, and no composed route
  returns it. The withhold was a governance condition, not a finding that a bounded
  read is unsafe under these controls.
- **Authorize `GET /findings` or a global preview.** Rejected: either surface is a
  Finding list or a cross-asset disclosure channel.
- **Return one row per occurrence or evidence id.** Rejected: Finding identity is
  versionless, and a row-per-evidence response invites partial acknowledgement.
- **Truncate a set larger than 16 and still return it.** Rejected: the creation
  policy rejects that set. A truncated acknowledgement would train the operator to
  submit a set the transaction must refuse, or would hide members.
- **Sign the acknowledgement.** Rejected: a token would become a second authority.
  Explicit resubmission and transaction-time revalidation stay the control.
- **Return the Finding id for `existing_finding`.** Rejected: that would make
  discovery a Finding list and would grant inspection reachability without
  `finding:inspect`.
- **Persist a shared organization rate-limit row.** Rejected for this slice: it
  would add operational machinery this decision does not need. The process-local
  ceiling is an accepted residual.
- **Add a discovery index now.** Rejected: no measured read shows that the current
  schema cannot serve the examination budget.

## Consequences

Positive: an owner or admin can read bounded current targets for one asset and
receive the acknowledgement creation already requires, without a new writer and
without weakening exact replay.

Negative: until the implementation branch, the route and permission are absent, so
this acceptance is not an operator capability. Discovery can be stale before the
operator submits `POST /findings`. The process-local organization limit is weaker
on multiple API processes than a shared limiter. Admins can see acknowledgements
they are not allowed to submit. A page is not a consistent snapshot of later pages.

## Security and tenancy

Targets, Findings, and Product Match Evidence cited by a candidate are tenant-owned.
The session organization is the only organization predicate. Shared advisory rows
stay shared and are not returned as raw advisory data. No new object-storage layout,
secret, outbound fetch, or cross-organization bypass is introduced.

Foreign and absent assets share one public not-found result. Logs follow section 18
and the canonical redaction list. Audit rows are not updated or deleted. Evidence
is not cascade-deleted. The creation issuer stays unexported. Product Match Evidence
ids in the response are acknowledgement identifiers, not authority.

## Operational failure plan

An unauthenticated, forbidden, invalid, absent, conflicting, or rate-limited
request writes nothing. A database failure, limiter fault, statement timeout, or
malformed Finding lineage returns no partial page and writes nothing. Operators do
not insert Findings, edit frozen migrations, or add an index to make a page
succeed. There is no discovery route to operate until the implementation branch
registers the one path. Creation failure after a stale acknowledgement stays on
the existing `POST /findings` behavior: conflict, no substitution, no write.

## Follow-up

The implementation branch may register only
`GET /assets/:assetId/controlled-finding-targets`, add
`finding:discover_controlled` with the mapping in section 3, and compose the
read-only API path in section 20. It needs tenant-isolation, foreign-versus-absent,
permission, pagination, cursor-conflict, oversized-omission, classification,
read-only, rate-limit, timeout, and log-redaction tests, without exploit payloads.
It must not add a migration, a dependency, an index, a Finding list, a second
preview, a worker composer, or a lifecycle transition. A runbook for the composed
route belongs to that implementation, not to this decision.
