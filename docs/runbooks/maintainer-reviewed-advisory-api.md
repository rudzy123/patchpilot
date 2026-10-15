# Maintainer-reviewed advisory API

Use this when an authenticated User submits or approves one local maintainer-reviewed advisory through the API. These routes are instance-scoped. They do not use an organization, a membership, or a tenant role.

- `POST /intelligence/maintainer-reviewed-advisories` requires an active `advisory_submit_local` grant.
- `POST /intelligence/maintainer-reviewed-advisories/:revisionId/approval` requires an active `advisory_approve_for_product_evaluation` grant.

The session User is the principal. The application reloads that User and the exact grant inside the mutation transaction. Organization owner or admin status does not substitute for either grant. The grants are not interchangeable. There is no web UI, no advisory list, no status route, and no capability route.

Approval records eligibility only. It does not generate Product Match Evidence, contact a provider, run an evaluator, or create or change a Finding or observation. Evidence starvation remains until a later evaluation slice.

## Request

Both routes accept `application/json` only, a body of at most 65536 bytes, no query string, one allowed browser Origin, the session cookie, and the current synchronizer CSRF header. Forwarded host or protocol headers do not replace Origin. `X-Forwarded-For` does not select the peer.

The submission body is the committed strict submission command. The route does not accept a submitter id, an origin, a fingerprint, an approval field, or a capability field.

The approval path is one canonical lowercase UUID version 4. The approval body is an empty JSON object. The route binds the path revision id and the request correlation id. The body cannot override the revision id or supply a purpose or capability.

## Limits

Each route has its own process-local direct-peer limit of 5 requests per 60 seconds. The limiter runs before authentication. An unknown peer shares one bounded bucket. Limiter failure fails closed with 429. There is no Redis store, no rate-limit table, and no key that includes a User id or a revision id.

Restarting the API process clears the window. Several API processes multiply the ceiling. That multiplication is an accepted residual.

## Results

- Submission `submitted` is 201. Approval `approved` is 201. Exact replay `already_applied` is 200. The body returns the transport schema version, the outcome, and the advisory revision id.
- Invalid JSON, an unexpected field, a malformed revision path, or an unsupported advisory origin is 400. Missing or invalid session or CSRF is 401. A missing grant is 403 with `Advisory authority was not granted.`
- Self-approval and a private capability refusal share one 403: `The approval was not recorded.` That sentence does not disclose capability, seal, issuer, or author state.
- An absent revision is 404. An immutable conflict with stored advisory content or with another reviewer is 409.
- Non-JSON content is 415. An oversized body is 413. The peer limit is 429.
- Malformed stored state, a transaction abort, database unavailability, and an internal failure share one 503: `Maintainer-reviewed advisory storage is temporarily unavailable.` The body does not include SQL, constraints, fingerprints, or capability state.
- Responses use `Cache-Control: private, no-store`.

A failed request leaves the last committed revision unchanged. Do not repair a stored revision, approval, capability, or audit row in place. Exact replay writes no second audit event. Transport rejection writes no domain audit event.

## What these routes do not do

They do not mint a capability for the caller, list advisories, return the advisory document, evaluate a component, or enqueue work. The deployment-local grant command remains the only grant writer. The frozen migration count remains 26.
