# Controlled Finding web workflow

Use this when an owner or admin reviews controlled Finding targets for one asset in the web application, or opens a Finding that is already known.

The web application is a client of the existing API. It does not create Findings by itself. Authentication, tenancy, permissions, creation, exact replay, and inspection remain API decisions. Inspection shows creation evidence. A separate section on the same page shows one selected latest observation. [ADR 0039](../adr/0039-controlled-finding-repeated-observation.md) does not add an observation write control. [ADR 0041](../adr/0041-controlled-finding-latest-observation-transport.md) governs `GET /findings/:findingId/latest-observation` and the independent section on `/findings/:findingId`. The API route is implemented and read only. The section is implemented. It calls that route by itself and does not replace creation inspection. Owners and admins may view it. Members and viewers may not. Aggregate language remains non-lifecycle. A latest-observation error does not erase creation inspection. Latest-observation data stays ephemeral. Repeated-observation writes, observation history, and Finding lifecycle behavior remain unavailable. Controlled Finding Latest-Observation Reachability Session 1-R reviewed the API route. Controlled Finding Latest-Observation Reachability Session 2 implements the section. Controlled Finding Latest-Observation Reachability Session 2-R reviewed the independent web section. Branch closure reviewed the reachable read-only workflow.

## Pages

- `/assets/:assetId/findings/targets` reviews one page of targets for that asset.
- `/findings/:findingId` shows the bounded creation inspection and one independent latest-observation section.

There is no `/findings` list. There is no cross-asset search.

Asset detail shows **Review controlled Finding targets** only for an owner or admin in the active organization. The link uses the asset id. The asset name stays on the page as text.

## Roles

- An owner can review one acknowledgement and confirm one creation or exact replay.
- An admin can review candidates and acknowledgements. The page does not offer a creation control.
- A member or viewer does not see the asset-detail entry. A direct URL shows that controlled Finding targets are unavailable for that role. The page does not request discovery, creation inspection, or latest observation when the session already shows that role.

Client-side role checks are presentation only.

## Owner confirmation

Eligible and exact-replay candidates show the server acknowledgement. The confirmation dialog shows the vulnerability identifier, the untrusted public identifier, and the complete evidence-id list before the owner confirms. Exact replay confirmation states that a second Finding should not be created. The page keeps a frozen copy of the acknowledgement that was reviewed, so a later change to the loaded candidate does not alter the submitted body.

The browser submits that acknowledgement unchanged. It does not sort, add, or remove evidence ids. It does not send an organization id or a browser idempotency key.

- `created` announces that one Finding was created and links to inspection.
- `already_applied` announces that the same creation lineage was already recorded and links to that Finding. Exact replay is convergence, not a duplicate error.
- A creation conflict asks the owner to refresh and review the new acknowledgement. The page does not resubmit the old one.
- A result that cannot be confirmed stays unconfirmed. The owner may retry that same in-memory acknowledgement or refresh and discard it. The page does not retry by itself.

An existing Finding candidate does not show an acknowledgement, a creation control, or a Finding link. Discovery does not return that Finding id.

## Latest observation evidence

The inspection page keeps creation inspection and adds **Latest observation evidence** after it. The browser calls `GET /findings/:findingId/latest-observation` separately. It does not send an organization id, a query, or a mutation header.

- Creation evidence says that creation evidence is the latest available observation evidence for the Finding.
- A latest repeated observation says that the section shows the latest legal repeated-observation evidence recorded for the Finding.
- Aggregate labels stay non-lifecycle. Unknown evidence stays unknown. Unaffected evidence stays an ingestion classification. Component absence stays an ingestion-graph fact.
- Loading, not-found, rate-limit, and unavailable results stay in the section. Creation inspection remains visible.
- A latest-observation 401 stays in the section and does not by itself open the session-expired page. A creation-inspection 401 still does.
- Refresh is a button. It does not run while a request is in flight, and it does not retry a 401. The page does not poll.
- The response stays in component memory. Changing organization, changing Finding, leaving the page, or reloading discards it. The browser does not write it to storage or the URL.

The section writes no audit event and does not change Finding state.

## What stays off the page

Acknowledgements, evidence ids, and page cursors stay in component memory. Changing organization, leaving the page, or reloading discards them. The pages do not write them to browser storage or the URL.

Update, assignment, risk, priority, due dates, suppression, accepted risk, false-positive marking, remediation, verification, ticketing, and notifications are unavailable.

The browser does not write `finding.created`. That audit event remains the API creation transaction. The latest-observation section writes no audit event and stores no observation response in browser storage.
