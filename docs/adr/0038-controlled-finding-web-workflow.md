# ADR 0038: Controlled Finding web workflow

- Status: Accepted
- Date: 2026-10-08
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the governance decision for one nested browser workflow over the existing
controlled Finding APIs. Merge to `main` remains subject to normal pull-request review.
This ADR does not implement pages, components, Next.js configuration, API routes, or a
migration, and it does not authorize a Finding lifecycle power.

Further amended on 2026-10-09. [ADR 0039](0039-controlled-finding-repeated-observation.md)
accepts repeated-observation architecture and does not implement it. This workflow
does not gain an observation control, a history page, or a lifecycle action.

## Context

[ADR 0035](0035-controlled-finding-creation.md) accepts creation-only Finding architecture.
[ADR 0036](0036-controlled-finding-operator-api.md) accepts owner `POST /findings` and
owner or admin `GET /findings/:findingId`. Those routes are composed in the API process.
Exact replay is publicly reachable. Creation requires the session cookie, an exact
permitted Origin, a JSON body, and the synchronizer CSRF token.
[ADR 0037](0037-controlled-finding-target-discovery.md) accepts owner and admin
`GET /assets/:assetId/controlled-finding-targets`. That route is merged and API
reachable. It is read-only. Acknowledgements come from the authoritative qualifying
Product Match Evidence set. `POST /findings` still revalidates that set and remains
owner-only. Stale acknowledgements fail closed. Discovery does not return a Finding id.

The web application is a presentation client of the API. It already keeps the session
CSRF token in component memory, sends JSON mutations with `credentials: 'include'` and
`cache: 'no-store'`, and does not decide tenancy. Asset detail already exists at
`/assets/:assetId`. No Finding page exists.

The creation transaction remains authoritative. A client-supplied organization id is
not tenancy. Product Match Evidence does not grant Finding authority. The wider Finding
lifecycle remains unavailable.

## Decision

PatchPilot accepts one nested asset browser workflow and one direct inspection page.
The workflow uses the composed APIs and adds no backend route, writer, or schema.

The authorized path is:

1. An owner or admin opens asset detail and follows one link.
2. The nested target-review page loads one discovery page for that asset.
3. An owner explicitly confirms one creation or exact-replay request.
4. A confirmed success is either `created` or `already_applied`.
5. The browser opens direct inspection with the Finding id returned by that response.

An admin may review targets and may open a direct inspection URL when the Finding id
is already known. An admin receives no creation control.

### 1. Information architecture

The workflow is nested under one asset. Target review is a child of that asset.
Inspection is a direct address for one Finding the server has already named.

This decision does not authorize a global Findings area, a cross-asset browser, or a
preview step that creates a Finding without the explicit confirmation in section 9.

### 2. Web routes

Two browser routes are authorized, and only as a later web-client implementation:

- `/assets/:assetId/findings/targets`
- `/findings/:findingId`

The path asset id and the path Finding id are resource selectors. They are not
tenancy authority. The server reloads the active organization from the session.

This decision does not authorize:

- `/findings` as a list;
- global Finding search;
- cross-asset discovery;
- bulk creation;
- lifecycle-edit routes;
- a preview-and-create route.

No other Finding path is authorized. These routes do not add Next.js route handlers.
They render in the existing App Router client and call the API.

### 3. Asset-detail integration

The asset detail page may show one link for an owner or an admin:

`Review controlled Finding targets`

The link target is `/assets/:assetId/findings/targets` for the asset already on that
page. Member and viewer do not receive the link.

Asset detail does not prefetch targets, show candidate counts, show an evidence
acknowledgement, or render a creation control.

### 4. Role experiences

Presentation reads the active membership role from the authenticated session. That
role chooses which controls to render. It is not authorization. The API remains
authoritative for every request that is sent.

| Role | Target review | Creation control | Direct inspection |
| --- | --- | --- | --- |
| owner | yes | one explicit confirmation | after the server returns a Finding id, and for a known direct URL |
| admin | yes | no | a known direct URL only |
| member | no | no | no |
| viewer | no | no | no |

A missing role, or any role other than `owner` or `admin`, uses the member and viewer
behavior.

Owner:

- discover the current page of targets for one asset;
- review one candidate at a time;
- explicitly confirm one creation or exact-replay request;
- inspect the Finding named by that creation response.

Admin:

- discover and review the same target page;
- inspect `GET /findings/:findingId` when the Finding id is already known;
- receive no creation control and no replay control.

Member and viewer:

- receive no target or Finding workflow on asset detail;
- see a bounded unavailable state on direct navigation to either authorized route;
- cause no discovery request and no inspection request when the session role already
  shows they cannot use the workflow.

While the session role is still loading, the page waits and sends no Finding request.
When the session has no active organization, the page uses the existing
organization-required state and sends no Finding request. Member and viewer keep
their organization and still receive only the bounded unavailable state.

### 5. Candidate interaction

Each discovery candidate keeps the classification the API returns.

| Classification | Owner | Admin |
| --- | --- | --- |
| `eligible_for_creation` | review, then one confirmation that submits the acknowledgement | review only |
| `exact_replay_available` | review, then one confirmation that submits the same acknowledgement | review only |
| `existing_finding` | review the unavailable lifecycle update | review the unavailable lifecycle update |

`existing_finding` has no acknowledgement and no Finding id. The page shows
`lifecycleUpdate` as unavailable. It does not offer creation, replay, or an inspection
link.

The page must not invent a Finding id. Discovery does not provide one. An admin cannot
derive a Finding id from a candidate. Inspection from a candidate is available only
after owner creation returns a Finding id, or when the operator already has the
inspection URL.

### 6. Multiple versions

Several affected versions of one Component and one Vulnerability are one candidate and
one Finding. The page shows the API fields for that one candidate:

- `affectedOccurrenceCount`;
- the affected-version summary, at most 8 distinct version strings;
- truncation state: `truncated`, `omittedDistinctCount`, and `distinctCount`;
- `otherOccurrenceCount` as a count only.

`otherOccurrenceCount` does not list those occurrences, does not veto the candidate,
and does not add evidence ids. The page does not split one candidate into one row or
one confirmation per version.

### 7. Empty and oversized states

An empty candidate list for an asset in the active organization means this page has no
current qualifying target. It does not mean the asset has no software. The foreign-asset
result remains the API not-found result and uses the same bounded not-found state as an
absent asset.

`oversizedCandidateCount` is a count from 0 through 100. The page shows that count and
no Component, Vulnerability, Finding, ingestion, asset, or evidence identity for the
omitted pairs. An omitted pair has no acknowledgement and no creation control. An empty
candidate list with a non-zero oversized count means every examined qualifying pair on
that window was oversized.

### 8. Evidence acknowledgement

For `eligible_for_creation` and `exact_replay_available`, the API acknowledgement is
the only creation body. Its fields stay:

- `assetId`;
- `componentId`;
- `vulnerabilityId`;
- `expectedSbomIngestionId`;
- `expectedProductMatchEvidenceIds`.

The evidence-id array is the complete qualifying set: 1 to 16 lowercase canonical
UUIDs, strictly ascending, with no duplicates. The browser submits that object
unchanged. The browser does not sort, repair, add, remove, persist, or substitute
evidence ids. It does not add `organizationId` or any other field.

The page may show the evidence ids in an accessible disclosure on the candidate and
again inside the confirmation dialog. The ids are acknowledgement identifiers. They
are not authority.

The acknowledgement and its evidence ids live only in component memory for the
candidate the operator is confirming. They are discarded when the component unmounts,
the active organization changes, the operator cancels, the server returns a confirmed
stale refusal, or the operator chooses refresh-and-review.

### 9. Explicit confirmation

Each owner-initiated mutation uses one accessible confirmation dialog. The dialog
names the single candidate being submitted. Opening the dialog does not select a
consent checkbox, and the page does not use a generic consent sentence in place of
the facts below.

The dialog discloses:

- the asset, as the acknowledgement `assetId`, plus the untrusted asset display name
  when the existing asset read for that same path asset and active organization has
  succeeded;
- the Component identifier, which is `componentId`;
- the Vulnerability, as `vulnerabilityId` and the untrusted `vulnerabilityPublicId`;
- `affectedOccurrenceCount`;
- the affected-version summary;
- the truncation state;
- the evidence identifiers, in the server-provided order;
- that discovery is point-in-time;
- that `POST /findings` revalidates the set at transaction time;
- that a stale set is refused without substitution and without a write.

The dialog has a real cancel button and one real confirm button. The confirm button
names the action for that classification: create the controlled Finding, or submit the
exact-replay acknowledgement. Nothing is preselected. The page does not offer
multi-select or create-all.

The path asset id and the acknowledgement `assetId` must be the same canonical id.
A mismatch discards the acknowledgement and does not submit.

Admin, member, and viewer never receive this dialog. `existing_finding` never receives
it.

### 10. Creation result

`created` and `already_applied` are distinct successful outcomes.

| Server result | HTTP status | Meaning on the page |
| --- | --- | --- |
| `created` | 201 | The transaction created one Finding and wrote `finding.created` |
| `already_applied` | 200 | Exact replay returned the existing Finding and wrote no second audit event |

Both responses contain only `status` and `findingId`. The page states which status
returned. It then navigates to `/findings/:findingId` using that returned id. It does
not navigate from a candidate that has no returned id.

The page does not treat the discovery classification as the creation result. It
displays the status the server returned.

### 11. Replay

`exact_replay_available` is an owner confirmation of the current acknowledgement, not
a second Finding and not a lifecycle edit. The request is the same `POST /findings`
body. The server decides `created` or `already_applied`.

There is no automatic mutation retry. The browser does not generate an idempotency
key. The creation body remains the closed acknowledgement object.

### 12. Stale evidence

A parsed creation conflict is a confirmed refusal. The public message is the existing
conflict envelope. The body does not include a replacement evidence set. The page
discards the acknowledgement, tells the operator that the evidence is no longer
current, and offers refresh-and-review.

Refresh-and-review clears the cursor stack and loads the first discovery page again.
It does not resubmit the discarded acknowledgement and does not submit a newly loaded
acknowledgement without a new confirmation.

### 13. Commit uncertainty

A parsed `created` or `already_applied` body is a confirmed success. A parsed error
envelope for a documented creation failure is a confirmed refusal.

Absence of a parseable response, including a network failure, a timeout, or a
truncated body, is unconfirmed. The server may already have committed. The page does
not automatically retry. It keeps the same in-memory acknowledgement and offers one
deliberate retry. That retry is another owner confirmation and submits the same
object. The operator may instead choose refresh-and-review, which discards the
acknowledgement.

The page does not invent a browser idempotency key, a correlation id, or a second
request body to resolve the uncertainty.

### 14. Pagination

Discovery pagination stays the API keyset contract. The page uses page replacement
with two controls, Previous and Next. The rendered list is one page.

The API returns `nextCursor` and no previous cursor. Previous uses a cursor stack kept
in component memory: one entry for each page already opened in that component
instance. Next requests the returned `nextCursor`. Previous requests the prior stack
entry. The first page requests no cursor.

The document URL, history state, and storage do not carry the cursor. The
authenticated API request may send `cursor` because the discovery route requires that
query field. That request URL is not copied into the document location.

This decision does not authorize infinite scroll, offset simulation, a cursor in the
page URL, or accumulation of earlier pages into one list.

A discovery conflict whose public outcome is a stale cursor clears the stack and
loads the first page with no cursor. The client does not remap the cursor onto a
newer ingestion.

### 15. Browser state

Component memory may hold only:

- the current discovery page;
- the bounded cursor stack for pages opened in that component instance;
- one confirmation;
- one acknowledgement;
- in-flight request state;
- the organization id captured when the request started.

The stack is bounded by the pages opened in that instance. Unmount, organization
change, stale-cursor reset, and refresh-and-review discard it.

The following values stay out of local storage, session storage, URL search
parameters, browser history, and any shared persistent cache:

- acknowledgements;
- evidence ids;
- CSRF tokens;
- cursors.

The inspection path may contain the Finding id because `/findings/:findingId` is the
inspection address. That path is not an acknowledgement and not a cursor.

### 16. Organization switching

Tenant-scoped Finding view state is discarded when the active organization id
changes. That includes the current page, cursor stack, confirmation, acknowledgement,
and any result that has not yet been rendered.

Each discovery or creation request captures the active organization id at start. A
response whose captured id is not the active id is ignored. The page does not render
it, does not navigate from it, and does not submit an acknowledgement that was loaded
under another organization.

The acknowledgement object still must not contain `organizationId`. The captured id
is view state beside the object, used only for this discard check.

### 17. Data fetching and cache

The pages use the existing authenticated API client. Requests keep `cache: 'no-store'`.
Discovery uses `GET /assets/:assetId/controlled-finding-targets`. Creation uses
`POST /findings`. Inspection uses `GET /findings/:findingId`.

This decision does not add a Next.js route handler, a server-side authority proxy, a
shared cache, or a persistent acknowledgement cache. The web process remains an API
client. It does not construct domain authority, the creation factory, or a database
client.

A module-level or cross-request cache of candidates, acknowledgements, cursors, or
inspection projections is not authorized.

### 18. CSRF and Origin

Creation continues to use the session cookie, the exact permitted Origin, a JSON
body, and the synchronizer CSRF token already held in auth-provider memory. The
Finding page reads that token at submit time through the existing accessor. It does
not copy the token into its own stored state.

Discovery and inspection remain read-only GET requests. They do not add a CSRF
exemption and they do not gain a request body.

The UI must not weaken API security for convenience. It must not proxy creation
through a Next.js route, omit credentials, change the JSON media type, or send a
body the creation route does not already accept.

### 19. Untrusted display

Asset names, Component identifiers, version strings, Vulnerability identifiers,
`vulnerabilityPublicId`, and explanation labels are untrusted. The page renders them
only as escaped React text.

The closed discovery explanation codes may use fixed text labels. Unknown codes are
escaped text. They are not interpolated into HTML.

This decision prohibits `dangerouslySetInnerHTML`, raw markdown, string-generated
HTML, and untrusted values in telemetry labels. Discovery does not return a Component
display name. The page does not invent one.

### 20. Accessibility

The implementation uses existing components and platform behavior. It does not add a
design-system dependency.

The pages and dialog require:

- semantic headings, with one page heading;
- real buttons and links for every action;
- visible focus;
- keyboard operation;
- an accessible dialog name and description;
- Tab containment while the dialog is open;
- Escape cancellation while no mutation is in flight;
- focus return to the invoking control when the dialog closes;
- status text for loading and for `created` or `already_applied`;
- alert text for errors;
- explicit Previous page and Next page labels;
- visible loading text;
- errors associated with the controls they describe;
- a signal besides color for classification, truncation, and availability.

Escape does not close the dialog while a mutation is in flight, and it does not start
a second request. The platform `dialog` element is sufficient for the modal name,
description, Tab containment, and idle Escape behavior. A custom dialog must meet the
same requirements without a new dependency.

### 21. Clickjacking

The web application may add this response header through the existing Next.js
`headers` configuration:

`Content-Security-Policy: frame-ancestors 'none'`

This decision authorizes that one directive. It does not authorize a broader content
security policy, a new dependency, or a change to API CORS. This ADR does not add the
header.

### 22. Observability

This decision does not add a web analytics dependency. Browser logs and any future
browser telemetry omit:

- acknowledgements;
- evidence ids;
- cursors;
- package names;
- versions;
- cookies;
- CSRF tokens;
- authority data;
- resource ids as metric labels.

Allowed browser diagnostic fields are the route template and a public outcome. The
server `finding.created` event, written by the creation transaction, remains the
audit authority. The browser does not emit that event. Exact replay still writes no
second audit row. Discovery and inspection still write no Finding audit row.

### 23. Production composition

The later implementation may add the two page routes, the asset-detail link, client
calls through the existing API module, and the clickjacking header in section 21.

The web process must not construct the creation factory, the creation issuer, Prisma,
or a Finding repository. Worker, scheduler, queue, upload, evaluator, and provider
startup stay unchanged. Acceptance of this ADR does not perform the composition.

### 24. Backend compatibility

No backend change is required. The workflow uses the current API limits:

- discovery does not return Finding ids;
- discovery does not return Component display names;
- `existing_finding` cannot navigate to inspection;
- an admin cannot derive a Finding id from discovery;
- `exact_replay_available` returns an acknowledgement and still returns no Finding id;
- the Finding id used for navigation is the id in a `created` or `already_applied`
  response, or an id the operator already had.

A later change to those limits requires another architecture review. This ADR does
not authorize that change.

### 25. Explicit deferrals

The following remain unavailable:

- Finding list;
- global search;
- cross-asset discovery;
- create-all;
- multi-select creation;
- automatic creation;
- lifecycle transitions;
- repeated-observation implementation and reachability; architecture is accepted by
  [ADR 0039](0039-controlled-finding-repeated-observation.md) and is not implemented here;
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
- historical backfill;
- CLI;
- worker and scheduled automation.

Provider-driven Finding creation stays behind the ADR 0026 provider gate. This ADR
does not satisfy that gate.

## Migration intent

No schema change is required. No migration is required. No backend API change is
required. No new dependency is required. Finding authority and persistence stay on the
existing creation transaction. No worker or queue composition is required. This
decision does not change the frozen migration count.

## Alternatives considered

- **Keep the browser withheld.** Rejected for this decision: the composed APIs already
  support one asset-scoped review, one explicit owner write, and one direct inspection.
  The withhold was a governance condition, not a finding that this client is unsafe
  under these controls.
- **Authorize `/findings` or global search.** Rejected: either surface is a Finding
  list or a cross-asset disclosure channel.
- **Put candidate counts or creation controls on asset detail.** Rejected: asset detail
  would prefetch discovery or invite a create action without the review page.
- **Return Finding ids from discovery so `existing_finding` can open inspection.**
  Rejected in this slice: that would make discovery a Finding index. It requires a
  later architecture review.
- **Persist the acknowledgement in session storage or the URL.** Rejected: the
  acknowledgement is an explicit resubmission, not a credential cache.
- **Generate a browser idempotency key.** Rejected: the creation body is closed, and
  exact replay is the server control.
- **Proxy creation through a Next.js route handler.** Rejected: the web process would
  become a second authority path and could change Origin and CSRF behavior.
- **Add a dialog-library dependency.** Rejected: platform dialog behavior meets the
  accessibility requirements.

## Consequences

Positive: an owner can review one asset's current targets and create or replay one
Finding through the existing transaction. An admin can review targets and open a
known inspection URL. Member and viewer are not sent to those APIs when the session
role already excludes them.

Negative: the pages do not exist until the implementation branch. `existing_finding`
and admin review cannot open inspection from discovery. A lost creation response can
leave the operator unsure until a deliberate replay. The browser can still be wrong
about role presentation; the API remains the control that denies the request.

## Security and tenancy

Targets, Findings, and Product Match Evidence are tenant-owned. The session
organization is the only organization predicate. The browser discards tenant view
state on organization change and ignores a response captured for another
organization. Foreign and absent assets and Findings stay publicly indistinguishable.

The acknowledgement is resubmitted unchanged and is revalidated by `POST /findings`.
Evidence ids in the dialog are not authority. CSRF and Origin requirements for
creation stay in force. Logs follow section 22 and the canonical redaction list.
Audit rows are not updated or deleted. The creation issuer stays unexported.

## Operational failure plan

An unauthenticated, forbidden, invalid, absent, conflicting, or rate-limited API
response writes nothing through this client. A stale acknowledgement is a confirmed
conflict: the operator refreshes discovery and reviews the new page. An unconfirmed
transport failure is not retried automatically; the owner may confirm the same
in-memory acknowledgement once more.

Operators do not insert Findings, edit frozen migrations, or add an index to make the
page succeed. There is no Finding page to operate until the implementation branch
registers the two routes. Creation and discovery failures stay on the existing API
behavior. The server `finding.created` event remains the creation record.

## Follow-up

The implementation branch may add only the two routes in section 2, the asset-detail
link in section 3, the client calls in section 17, and the header in section 21.
It needs tests for role presentation, absent requests for member and viewer, exact
acknowledgement submission, organization-switch discard, stale conflict,
created versus already_applied, unconfirmed retry, cursor reset, and the dialog
accessibility requirements, without exploit payloads.

It must not add a migration, a dependency, an API route, a Finding list, a worker
composer, or a lifecycle transition. A runbook for the composed pages belongs to
that implementation, not to this decision.
