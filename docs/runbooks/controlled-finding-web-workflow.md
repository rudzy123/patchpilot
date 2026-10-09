# Controlled Finding web workflow

Use this when an owner or admin reviews controlled Finding targets for one asset in the web application, or opens a Finding that is already known.

The web application is a client of the existing API. It does not create Findings by itself. Authentication, tenancy, permissions, creation, exact replay, and inspection remain API decisions. Inspection shows creation evidence only. [ADR 0039](../adr/0039-controlled-finding-repeated-observation.md) does not add a page or an observation control.

## Pages

- `/assets/:assetId/findings/targets` reviews one page of targets for that asset.
- `/findings/:findingId` shows the bounded inspection projection.

There is no `/findings` list. There is no cross-asset search.

Asset detail shows **Review controlled Finding targets** only for an owner or admin in the active organization. The link uses the asset id. The asset name stays on the page as text.

## Roles

- An owner can review one acknowledgement and confirm one creation or exact replay.
- An admin can review candidates and acknowledgements. The page does not offer a creation control.
- A member or viewer does not see the asset-detail entry. A direct URL shows that controlled Finding targets are unavailable for that role. The page does not request discovery or inspection when the session already shows that role.

Client-side role checks are presentation only.

## Owner confirmation

Eligible and exact-replay candidates show the server acknowledgement. The confirmation dialog shows the vulnerability identifier, the untrusted public identifier, and the complete evidence-id list before the owner confirms. Exact replay confirmation states that a second Finding should not be created. The page keeps a frozen copy of the acknowledgement that was reviewed, so a later change to the loaded candidate does not alter the submitted body.

The browser submits that acknowledgement unchanged. It does not sort, add, or remove evidence ids. It does not send an organization id or a browser idempotency key.

- `created` announces that one Finding was created and links to inspection.
- `already_applied` announces that the same creation lineage was already recorded and links to that Finding. Exact replay is convergence, not a duplicate error.
- A creation conflict asks the owner to refresh and review the new acknowledgement. The page does not resubmit the old one.
- A result that cannot be confirmed stays unconfirmed. The owner may retry that same in-memory acknowledgement or refresh and discard it. The page does not retry by itself.

An existing Finding candidate does not show an acknowledgement, a creation control, or a Finding link. Discovery does not return that Finding id.

## What stays off the page

Acknowledgements, evidence ids, and page cursors stay in component memory. Changing organization, leaving the page, or reloading discards them. The pages do not write them to browser storage or the URL.

Update, assignment, risk, priority, due dates, suppression, accepted risk, false-positive marking, remediation, verification, ticketing, and notifications are unavailable.

The browser does not write `finding.created`. That audit event remains the API creation transaction.
