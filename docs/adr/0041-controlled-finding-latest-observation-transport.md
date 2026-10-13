# ADR 0041: Controlled Finding latest-observation transport

- Status: Accepted
- Date: 2026-10-13
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the transport decision for one protected, read-only latest-observation
route and one later read-only web section. Merge to `main` remains subject to
normal pull-request review. This ADR does not implement the route, the web
section, a permission, a migration, or a Finding lifecycle power.

## Context

[ADR 0036](0036-controlled-finding-operator-api.md) composes owner `POST /findings`
and owner or admin `GET /findings/:findingId`. The inspection route returns the
creation-based projection `finding_inspection_projection_v1`. It requires
`finding:inspect`. Owner and admin hold that permission. Member and viewer do
not. A foreign Finding and an absent Finding share one public not-found result.
Responses use `Cache-Control: private, no-store`. The direct-peer inspection
limit is 60 requests per 60 seconds and runs before authentication.
`X-Forwarded-For` is not the peer. The error envelope is `error.code`,
`error.message`, `error.requestId`, and `error.correlationId`.

[ADR 0039](0039-controlled-finding-repeated-observation.md) accepts one
persistence-only repeated observation. That persistence slice is merged and
production uncomposed. `finding.observed` is the write-side audit event for a
committed repeated observation. The writer is not a production constructor.

[ADR 0040](0040-controlled-finding-latest-observation-inspection-boundary.md)
selects bounded latest-observation inspection and defers operator
repeated-observation reachability. It does not define an HTTP schema.

The repository now contains three production-uncomposed read slices:

- the framework-independent legal selector in
  `packages/domain/src/findings/controlled-inspection/latest-observation-selection.ts`;
- the tenant-scoped, read-only PostgreSQL adapter in
  `packages/database/src/controlled-finding-latest-observation-read.ts`;
- the authorization-aware application service in
  `packages/domain/src/findings/controlled-latest-observation/service.ts`.

The service requires `finding:inspect`, derives the organization from the
trusted actor, and returns one of `authority_required`, `found`, `not_found`,
or `unavailable`. A found result carries
`finding_latest_observation_projection_v1`. Its aggregate labels are
`affected`, `unaffected`, `unknown`, and `component_absent`. Its internal
`mappedResult` values are `present`, `absent`, and `inconclusive`.
`unaffected` and `component_absent` both map to `absent`. The projection also
carries `assetId`, `componentId`, `vulnerabilityId`, and an evidence summary.
Occurrence evidence includes support counts and a distinct lexicographically
ordered `knownVersions` array of at most 16 strings. Component-absence evidence
includes `graphCompleteness`, `componentCount`, and `dependencyEdgeCount`.
Creation fallback is a found result with `observationSource: creation` and
`aggregate: affected`. Malformed persisted state, evidence unavailability,
unsupported envelopes, integrity failure, database unavailability, and
unexpected internal failure share `unavailable`. The read port performs no
write. No API, web, or worker startup constructs this service.

Those prior decisions authorized repeated-observation persistence, internal
selection, tenant-scoped PostgreSQL reading, and internal application
authorization. They did not authorize an HTTP route, a web section, transport
response semantics, transport error semantics, rate limiting for this read,
transport logging, or public latest-observation reachability.

`GET /findings/:findingId` remains creation based. The web page
`/findings/:findingId` renders that creation projection only. Latest-observation
transport is unavailable.

## Decision

Authorize exactly one future route:

`GET /findings/:findingId/latest-observation`

The later implementation composes the committed application service in the API
process only. It returns exactly one bounded selected observation. It is not an
observation history endpoint.

Authorize one later read-only section on the existing page
`/findings/:findingId`. That section calls the new route independently of
`GET /findings/:findingId`. This ADR does not implement either surface.

The next implementation branch after this ADR merges is
`feat/controlled-finding-latest-observation-reachability`.

### Routes that remain unauthorized

This decision does not authorize:

- any change to `GET /findings/:findingId`;
- `GET /findings/:findingId/observations`;
- an observation-history endpoint, list, or pagination contract;
- a global observation route or a global Finding route;
- repeated-observation mutation;
- bulk or batch reads or writes;
- a worker or automatic caller;
- provider-triggered or evaluator-triggered access.

### Existing inspection preservation

`GET /findings/:findingId` stays the creation inspection projection. The new
route must not replace it, amend its schema, append a latest-observation
property, change its errors, change its creation-evidence explanation, or make
it fail when latest-observation state is unavailable. Creation inspection does
not depend on repeated-observation state. The two reads have independent
failure domains.

### Authorization

Reuse `finding:inspect`. Do not add `finding:inspect_latest_observation`.

| Role | `finding:inspect` | This route, once implemented |
| --- | --- | --- |
| owner | allowed | allowed |
| admin | allowed | allowed |
| member | denied | denied |
| viewer | denied | denied |

These do not grant the route: `finding:create_controlled`,
`finding:discover_controlled`, `finding:triage`, `finding:read`, `asset:read`,
`asset:manage`, organization administration, membership alone, a role name
alone, or any caller-supplied permission string or array.

The handler uses the existing session and `requirePermission` infrastructure,
then calls `createControlledFindingLatestObservationApplication`. It does not
reimplement actor parsing, the role grant table, organization derivation,
latest-observation selection, creation fallback, or persisted-state
classification. The service remains the selection authority. The handler does
not call Prisma, the PostgreSQL adapter, the selector, or the
repeated-observation writer.

The call passes the trusted session actor and the committed command
`inspect_controlled_finding_latest_observation_v1`. That command contains only
`schemaVersion` and the canonical path `findingId`. It does not contain an
organization id, membership id, role, or permission. Organization scope stays
on the actor. A path id that fails the canonical UUID check is HTTP 400 and
does not reach the service. The service treats a noncanonical command id as
`unavailable`, so the handler must not use that result as request validation.

### Tenant context

Require an authenticated session, an active organization, an active membership,
`finding:inspect`, and one canonical Finding id. Organization scope comes only
from the trusted actor on that session. The path id is a resource selector.
The route rejects organization identity from query parameters, a request body,
custom headers, client application state, route metadata, cookies other than
the existing session cookie, and caller-selected roles or permissions.

The handler must not look up the Finding globally and then authorize the
tenant. The service query carries the actor's organization id and the path
Finding id together. A foreign Finding and an absent Finding both become the
same public 404.

### Request contract

Accept exactly one canonical lowercase UUID in the path, using the same
pattern as `controlledFindingIdParamSchema`:

`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`

Reject uppercase and other noncanonical forms with 400. Accept no request body
and no query parameter. Reject organization ids, membership ids, observation
ids, ingestion ids, history limits, pagination cursors, sorting, aggregate
filters, source filters, evidence ids, support ids, lifecycle fields, and any
other selector. Reject an unexpected body or query field with 400.

The route is read-only. It requires no mutation CSRF token and no Origin
check. It must not weaken session, cookie, Origin, or CSRF behavior on any
other route.

### Public success contract

The success body is a strict object. Its schema version is the new literal
`finding_latest_observation_transport_v1`. That literal is a transport
contract. It is not `finding_latest_observation_projection_v1` and not
`finding_latest_observation_external_result_v1`.

These fields are always present on 200:

| Field | Value |
| --- | --- |
| `schemaVersion` | `finding_latest_observation_transport_v1` |
| `findingId` | the path id, equal to the internal projection `findingId` |
| `observationSource` | `creation` or `latest_repeated` |
| `observedAt` | the internal canonical UTC timestamp string, copied unchanged, at `timestamptz(6)` microsecond precision |
| `aggregate` | `affected`, `unaffected`, `unknown`, or `component_absent` |
| `evidence` | one closed object, discriminated by `kind` |

`evidence.kind` is `occurrence_support` when `aggregate` is `affected`,
`unaffected`, or `unknown`. It is `component_absence` when `aggregate` is
`component_absent`. No field changes meaning because `observationSource`
changed. A found projection that breaks these pairs, or that disagrees with
the path id, becomes 503. The handler does not repair it.

`occurrence_support` contains only:

- `kind` with value `occurrence_support`;
- `affectedSupportCount`, `unaffectedSupportCount`, `unknownSupportCount`, and
  `unknownVersionSupportCount`, each an integer from 0 through 16;
- `knownVersions`, a strict object with only `values`, `truncated`,
  `omittedDistinctCount`, and `distinctCount`.

`knownVersions` is derived only from the internal `knownVersions` array. The
route must not query versions separately. Preserve the selector's existing
lexicographic code-unit order. Display at most eight distinct values.
`distinctCount` is the internal array length. `values` is the lexicographically
earliest eight strings in that already sorted array, or the whole array when
fewer than eight are present. `omittedDistinctCount` is `distinctCount` minus
`values.length`. `truncated` is true exactly when `omittedDistinctCount` is
greater than zero. Each string is one the service already accepted: length 1
through 256 and no NUL character. The route copies those strings. It does not
trim, parse, or reclassify them. Strings stay ordinary JSON strings. The UI
must not interpret them as HTML or Markdown. They are untrusted display data.
They are known version strings from the selected observation's
occurrence-support summary. They are not a partitioned affected-version list,
because an `affected` aggregate can still carry known versions from other
support outcomes under the committed selector.

`component_absence` contains only `kind` with value `component_absence` and
`graphCompleteness` with value `complete` or `no_dependencies`. It omits
`componentCount` and `dependencyEdgeCount`. Those counts stay inside the
internal projection. Neither evidence shape includes the other shape's fields.
Neither uses null as a placeholder for an omitted field.

The committed service returns no explanation-code field. This response
therefore omits `explanationCodes`. Creation-inspection explanation codes stay
on `GET /findings/:findingId`.

Creation source, as already enforced by the service, is `aggregate: affected`
with `occurrence_support`, `affectedSupportCount` of at least 1, and the other
three support counts at 0. Component absence is `latest_repeated` only. The
transport publishes the same fields for every legal occurrence-support result
so creation does not use a second shape.

Nullable fields: none. Omitted fields are omitted, not null.

### Mapped result

Do not publish `mappedResult`. Do not publish `absent` as the product meaning
of both `unaffected` and `component_absent`. The public aggregate labels stay
distinct. Internal mapping remains an implementation detail:

| Aggregate | Internal `mappedResult` | Public aggregate |
| --- | --- | --- |
| `affected` | `present` | `affected` |
| `unaffected` | `absent` | `unaffected` |
| `unknown` | `inconclusive` | `unknown` |
| `component_absent` | `absent` | `component_absent` |

### Creation fallback

When no legal repeated observation exists, the service returns a found
projection with `observationSource: creation`. The route returns 200 with that
source. Creation fallback is valid evidence selection. It is not a repeated
observation, and it is not described as stale, unavailable, missing, or
failed. It is not proof that no later ingestion exists, not proof of current
affectedness, and not current Finding state. The response preserves only facts
already present on the internal projection.

### Latest repeated observation

When one legal latest repeated observation exists, return
`observationSource: latest_repeated`. Describe it as the selected latest legal
repeated-observation evidence. Do not describe it as current Finding state,
verified current affectedness, remediation status, lifecycle status,
reopening, resolution, recurrence, or continuous presence. Do not expose the
preceding observation sequence.

### Aggregate language

`affected` means selected affected evidence from the selected observation. It
does not mean business risk, exploitability, priority, assignment, reopening,
or urgency.

`unaffected` means legally unaffected evidence for every relevant present
occurrence in the selected ingestion. It does not mean resolved, remediated,
verified, safe, or closed.

`unknown` means the selected observation could not establish affected or
unaffected for every relevant occurrence. It is not unaffected, safe,
resolved, or evidence absence.

`component_absent` means constrained evidence that no occurrence of the
component appeared in the selected ingestion graph. It does not mean
remediation, verification, resolution, safety, closure, operator package
removal, or intentional remediation.

### Prohibited response fields

The success body and every error body omit:

- `mappedResult`;
- observation id and observation-history arrays;
- observation count;
- Product Match Evidence ids, ComponentOccurrence ids, and support-link ids;
- support details beyond the counts and `knownVersions` object above;
- replay fingerprints and absence-proof fingerprints;
- graph-coverage internals and the raw absence counts;
- `assetId`, `componentId`, and `vulnerabilityId`;
- actor ids, membership ids, and correlation ids on the success body;
- authority material, reviewer identity, and provider identity;
- raw advisory content;
- SQL, table names, constraint names, trigger names, and Prisma objects;
- stack traces and database URLs;
- lifecycle, remediation, and verification claims.

Request and correlation identifiers stay on the existing error envelope only.
They are not success-body fields.

### Failure domains and status translation

The route invokes only the committed application service after the HTTP gates
below. It must not substitute the creation inspection body, convert malformed
latest state into `not_found` or creation fallback, expose adapter or selector
diagnostics, or repair malformed persistence.

| Condition | HTTP | `error.code` | `error.message` |
| --- | --- | --- | --- |
| Malformed path, body, or query | 400 | `validation` | `Invalid request.` |
| Missing or invalid session | 401 | `unauthorized` | `Authentication required.` |
| Authenticated actor without an active organization or active membership | 403 | `forbidden` | `Organization context is required.` |
| Authenticated actor without `finding:inspect`, including member and viewer | 403 | `forbidden` | `Permission denied.` |
| Service `authority_required` after the session and organization gates | 403 | `forbidden` | `Permission denied.` |
| Service `not_found` | 404 | `not_found` | `Not found.` |
| Direct-peer limit exceeded, or limiter evaluation failure | 429 | `rate_limited` | `Too many requests. Try again later.` |
| Service `unavailable`, handler throw, or response-contract mismatch | 503 | `internal` | `Finding operator is temporarily unavailable.` |

The public 503 does not say whether the cause was malformed persisted state,
evidence unavailability, an unsupported envelope, an integrity failure,
database unavailability, or an unexpected internal failure. This route must
not reuse the creation-inspection split that maps some of those causes to 422
or 500. This route has no 422 response and no 500 response.
`unprocessable_evidence` is not a status for this route. An oversized body is
400 `validation` with `Invalid request.`, not 413.

The existing Finding scope error handler maps an escaped throw to
`An internal error occurred.`, which is HTTP 500. This route must not use that
mapping. Catch handler failures and response-contract mismatches, then translate
them to `Finding operator is temporarily unavailable.` with HTTP 503 before
that handler can turn them into 500.

Session resolution still runs through the existing session resolver. That
resolver may update session `lastSeenAt` under its existing interval. That
bookkeeping is not a latest-observation write, not a Finding timestamp update,
and not an audit event. The route adds no other database write.

### Caching

Set `Cache-Control: private, no-store` on 200, 400, 401, 403, 404, 429, and
503. Do not place the selected observation in a shared HTTP cache, a CDN
cache, a Next.js shared cache, a persistent browser cache, `localStorage`,
`sessionStorage`, or IndexedDB.

### Rate limiting

One route-specific, process-local direct-peer limit: 30 requests per 60
seconds. Register it on this route's own scope. Reuse
`findingDirectPeerRateLimitKey` and `selectDirectPeerIp`. Do not reuse the
inspection counter or a discovery counter. Run the limiter on `onRequest`,
before authentication, with `skipOnError: false`.
Ignore untrusted `X-Forwarded-For`. Keep the existing IPv4, IPv6, and
IPv4-mapped IPv6 normalization. If peer selection or limiter evaluation
throws, return the bounded 429 and do not call the service. The 429 body does
not reveal whether a Finding exists.

Do not add Redis, a rate-limit table, a migration, an organization limiter, a
per-Finding key, or an evidence-derived key. This limit is independent of the
inspection limit of 60 and the discovery limits. Several API processes
multiply the 30-request ceiling. That multiplication is an accepted residual.
Restarting a process clears its window.

### Logging and metrics

Log only the route template
`/findings/:findingId/latest-observation`, the closed public outcome
(`found`, `validation`, `unauthorized`, `forbidden`, `not_found`,
`rate_limited`, or `unavailable`), `requestId`, `correlationId`, the
authenticated user id when the actor is already resolved, and the active
organization id when it is already resolved.

Do not log the Finding id, observation source, aggregate, `observedAt`,
version strings, version summary, evidence summary, support facts, adapter or
selector diagnostics, response body, authority data, foreign resource
identity, SQL, or database internals. Use the route template, not the raw
path. `found` does not record whether the source was creation or
`latest_repeated`.

Metrics export remains unimplemented. If this route later records a counter,
its labels are only the route template, HTTP method, public outcome class,
and status class. Do not label by Finding id, organization id, user id,
observation source, aggregate, version, evidence counts, request id, or
correlation id.

### Audit

Routine latest-observation inspection writes no immutable audit event. Do not
create `finding.inspected`, `observation.viewed`, or any other audit row.
`finding.observed` remains the write-side event for a committed repeated
observation, and this route does not emit it. Bounded security logs are not
domain audit history.

### Web successor

The later section lives on `/findings/:findingId` and calls
`GET /findings/:findingId/latest-observation` by itself. Creation inspection
stays usable while that call is loading and when it returns 404, 429, or 503.
A latest-observation failure does not erase or replace the creation
projection. The section may be refreshed independently. Refresh performs no
mutation and does not retry 429 or 503 automatically.

Owners and admins may see the section under `finding:inspect`. Members and
viewers may not. The client check is presentation only. The API remains
authoritative. Do not add a client-side permission.

The section distinguishes creation evidence from latest repeated-observation
evidence with those labels. It renders only authorized response fields.
Untrusted values, including version strings and identifiers, render as escaped
React text. Do not use `dangerouslySetInnerHTML`, raw Markdown,
string-generated HTML, or untrusted values as telemetry labels.

Required accessible states:

- loading;
- found with `creation`;
- found with `latest_repeated`;
- not found;
- unavailable;
- rate limited;
- unauthenticated;
- forbidden.

The unavailable state does not disclose corruption, evidence loss, database
failure, or internal failure. Use a semantic section heading, an accessible
loading status, and status or alert text for results and failures. Aggregate
meaning is not color alone. The source label and the non-lifecycle aggregate
explanation are visible text. A refresh control, if present, is a keyboard
control with visible focus. Motion respects reduced-motion preferences. Do not
add a design-system dependency.

There is no application-wide fetch interceptor that redirects every 401.
Creation inspection keeps its existing behavior: a 401 from
`GET /findings/:findingId` still navigates to `/session-expired`. A 401 from
`GET /findings/:findingId/latest-observation` is section-local. It renders the
unauthenticated state inside the section, leaves an already loaded creation
projection in place, and does not itself call that navigation. The section
must not cancel, swallow, or replace the creation request's navigation when
that request also returns 401. It must not retry after 401, and it must not
copy the error body into the creation projection. Already rendered creation
evidence stays only until creation inspection itself observes 401, the active
organization changes, or the operator leaves the page. This does not add an
exception to creation inspection's session-expired transition.

Ephemeral section state may hold only the current request status, one response,
and a request generation or cancellation identity. Do not persist the response
in `localStorage`, `sessionStorage`, IndexedDB, browser-history state, or URL
query parameters. When the active organization changes, discard the section
state, ignore stale responses, and load again only under the new trusted
organization. Do not display the previous organization's response.

### Production composition

The API composition root may construct the committed application service, the
committed PostgreSQL read adapter, the existing trusted-actor and session
infrastructure, the route-specific direct-peer limiter, and the bounded
response translator. The handler calls the application service. The web
process stays an HTTP client and does not construct the service, adapter,
selector, or Prisma.

Do not compose this read in worker startup, scheduler roots, queue processors,
background-job handlers, Outbox consumers, BullMQ processors, upload
processing, evaluator processing, provider synchronization, CLI, seeds,
migrations, health checks, or readiness checks.

### Zero-write and lifecycle boundary

The route and the web section are read-only. They do not create an
observation, update a Finding, update Finding timestamps, write audit rows,
repair malformed state, issue repeated-observation authority, invoke the
writer, call a provider or evaluator, close or reopen a Finding, verify
remediation, change risk or priority, assign ownership, set due dates,
suppress, accept risk, or decide a false positive.

Finding state remains `open`. Finding version remains 1. [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md)
section 20 remains unadopted.

### Migration and dependency boundary

Prisma change: no. Migration: no. The frozen migration count remains 25.
Dependency: no. `pnpm-lock.yaml` change: no. Permission addition: no.
Repeated-observation persistence change: no. Worker or queue composition: no.
If implementation needs any of those, it stops and requests a new review.

### Explicit deferrals

These remain unavailable: repeated-observation write reachability, operator
observation commands, automatic observation, observation history, observation
list, observation pagination, Finding list, global Finding search, closure,
reopening, remediation verification, suppression, accepted risk,
false-positive decisions, risk, priority, assignment, due dates,
notifications, dashboards, exports, ticketing, AI authority, historical
backfill, production Product Match Evidence acquisition, production OSV
acquisition, and automatic provider or evaluator processing.

## Alternatives considered

1. **Appending the latest observation to `GET /findings/:findingId`.**
   Rejected. One failure in repeated-observation state would couple to
   creation inspection, and the creation contract would change.
2. **Publishing `mappedResult`.** Rejected. `absent` collapses `unaffected`
   and `component_absent`.
3. **A new `finding:inspect_latest_observation` permission.** Rejected. ADR
   0040 already allows this read to reuse `finding:inspect`.
4. **An observation-history route.** Rejected. One selected result is the
   whole public read.
5. **Mapping malformed state to 404 or to creation fallback.** Rejected. Both
   would hide integrity failure or invent a successful selection.
6. **Reusing the creation-inspection 422 and 500 split.** Rejected. Distinct
   statuses would tell corruption from infrastructure failure.
7. **An organization or Redis limiter in this slice.** Rejected. The first
   transport slice stays a process-local direct-peer limit.
8. **Writing `finding.inspected`.** Rejected. Routine reads are security logs,
   not audit rows.
9. **Composing the service in the web process.** Rejected. The web application
   remains an HTTP client.

## Consequences

Positive:

- Operators can later see one selected legal observation without changing
  creation inspection.
- Tenant, permission, and confidentiality rules are fixed before the route
  exists.
- Malformed state stays one public unavailable result.
- Repeated-observation writes and history stay deferred.

Negative:

- No new user-visible behavior ships with this ADR.
- The process-local limit multiplies with API process count.
- Creation inspection and latest-observation inspection can fail separately,
  including a visible creation projection beside an unavailable latest
  observation.
- The internal `knownVersions` array is not an affected-only list. The public
  field keeps that limit visible instead of inventing a partitioned summary.

No migration, dependency, permission, or production registration changes with
this decision.

## Security and tenancy

Organization scope comes from the session actor. The path Finding id is not
tenancy. Foreign and absent Findings share one 404. The handler does not
perform a global lookup followed by an organization check. Hostile persisted
state and database failure share one 503, so the route is not a
malformed-state oracle and does not reveal observation existence on failure.
Logs and metrics omit the Finding id, aggregate, versions, and evidence.
Responses are private and uncached. The browser drops section state on
organization change. Version strings render as escaped text. No new audit
writer, credential, or outbound fetch is added.

### Threat mitigations

| Threat | Mitigation |
| --- | --- |
| Broken object-level authorization | `finding:inspect` plus the service's actor organization and Finding id query |
| Cross-tenant Finding substitution | No client-supplied organization; foreign and absent share 404 |
| Malformed Finding id | Canonical lowercase UUID or 400, before the service |
| Route enumeration | Peer limit before authentication; 429 reveals no Finding existence |
| Rate-limit bypass and `X-Forwarded-For` spoofing | Direct socket peer only; limiter failure is 429 |
| Aggregate or observation-existence inference on failure | Failures omit aggregate, source, and observation count |
| Malformed-state oracle | One 503 for every unavailable cause |
| Failure-domain coupling | Separate route and separate web request from creation inspection |
| Sensitive logs and high-cardinality metrics | Template, outcome class, and existing correlation fields only |
| Cache or browser-state leakage | `private, no-store`; no browser persistence; drop state on organization change |
| Stale organization state | Cancel or ignore responses from the previous organization |
| Unsafe version rendering | Escaped text; no HTML or Markdown interpretation |
| Accidental history expansion | One result; no list, cursor, or count |
| Accidental write composition | API read service only; prohibited composition roots |
| Lifecycle language drift | Closed aggregate wording in this ADR |

## Operational failure plan

No route is reachable from this ADR, so production startup gains no new
failure mode. After implementation, operators treat 503 as temporary
unavailability without distinguishing corruption from infrastructure failure.
They do not repair rows, insert observations, or edit frozen migrations from
this read. Creation inspection remains the available creation-evidence view
when the latest-observation route is unavailable. Several API processes
multiply the 30-request window; that residual does not authorize Redis.

## Follow-up

Implement only on `feat/controlled-finding-latest-observation-reachability`
after this ADR merges. That branch may add the route, the response contract,
the web section, and the tests below. It may not add a permission, migration,
dependency, history route, or write path.

The implementation must show:

- missing session is 401, and an authenticated actor without an active
  organization, active membership, or `finding:inspect` is 403;
- owner and admin succeed, and member and viewer are denied;
- foreign and absent Findings return the same 404 body;
- a noncanonical path id is 400, and any query or body is 400;
- the peer limiter is 30 per 60 seconds, ignores `X-Forwarded-For`, fails
  closed, and does not reveal Finding existence;
- creation fallback returns `observationSource: creation` without calling that
  result a repeated observation;
- all four aggregates use the public labels, and `mappedResult` is absent;
- malformed latest state is 503 while creation inspection still succeeds;
- `Cache-Control` is `private, no-store` on the listed statuses;
- logs and metrics omit protected facts, and the read writes no audit row and
  no Finding or observation row;
- the web section keeps creation inspection when the latest-observation call
  returns 401, 404, 429, or 503, and a section 401 does not suppress creation
  inspection's own navigation to `/session-expired`;
- organization change drops the previous response;
- version strings render as escaped text;
- the service is constructed only in the API process;
- worker, queue, scheduler, Outbox, health, and readiness roots do not
  construct it;
- schema, migration count, permissions, dependencies, and `pnpm-lock.yaml`
  stay unchanged.

Do not implement those tests in this governance change.
