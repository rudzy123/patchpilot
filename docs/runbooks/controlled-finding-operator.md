# Controlled Finding operator

Use this when an authorized operator creates or inspects one controlled Finding through the API. This is not a Finding workflow, a list, or a lifecycle transition.

`POST /findings` is owner-only. `GET /findings/:findingId` is available to owners and admins. Member and viewer receive neither permission. `finding:triage` does not create. `finding:read` does not inspect through this surface.

## Request

Creation accepts one JSON object and nothing else:

- `assetId`
- `componentId`
- `vulnerabilityId`
- `expectedSbomIngestionId`
- `expectedProductMatchEvidenceIds`

Evidence identities are one to sixteen lowercase UUIDs, unique and strictly ascending. The operator sends the evidence set they reviewed. The transaction re-derives the current affected set and requires exact equality. The server does not substitute a newer set.

Organization, actor, and membership come from the authenticated session. A body or query organization id is not tenancy.

Creation requires `application/json`, a body of at most 4096 bytes, an exact allowed Origin, the session cookie, and the CSRF synchronizer header. Inspection is read-only and requires none of the Origin or CSRF checks.

## Limits

- Creation: 5 requests per 60 seconds for the direct peer socket, then 5 per 60 seconds for the authenticated organization
- Inspection: 60 requests per 60 seconds for the direct peer socket
- The peer limit runs before authentication. An unauthorized actor does not consume the organization budget
- `X-Forwarded-For` is not the peer or the tenant

The limiters are process-local. Restarting the API process clears them. There is no rate-limit table and no shared Redis limiter. Each API process allows its own 5 creations per 60 seconds for an organization, so several API processes multiply that organization ceiling. That multiplication is an accepted residual for this slice.

## Results

- `201` `created` and `200` `already_applied` return only `status` and the Finding id. An exact retry returns the original Finding id and does not write another `finding.created` audit event.
- Invalid requests are `400`. Missing session or CSRF failure is `401`. Missing permission or missing active organization is `403`. A foreign or absent target is `404` with the same public body. Stale or conflicting evidence is `409` and writes nothing. Ineligible evidence is `422`. Rate limit is `429`. A limiter or database fault is `503`. Malformed persisted state is `500`.
- Responses are `Cache-Control: private, no-store`.
- Failures do not return Finding ids, evidence ids, the qualifying evidence set, authority state, reviewer identity, membership details, SQL, or provider data.

## What this route does not do

Publishing the route does not authorize another component to call it. Web startup, workers, schedulers, queues, upload processing, evaluator processing, provider synchronization, seeds, and migrations do not construct it. There is no Finding list, bulk creation, or lifecycle route. [ADR 0037](../adr/0037-controlled-finding-target-discovery.md) accepts `GET /assets/:assetId/controlled-finding-targets` as a later read-only route. That route is not implemented, and this runbook does not operate it. No current route returns the complete creation acknowledgement.

## Related

- [ADR 0036](../adr/0036-controlled-finding-operator-api.md)
- [Authentication failure](authentication-failure.md)
- [Tenant isolation incident](tenant-isolation-incident.md)
- [Audit integrity failure](audit-integrity-failure.md)
