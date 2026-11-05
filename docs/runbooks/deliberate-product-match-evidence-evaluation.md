# Deliberate Product Match Evidence evaluation

Use this when an organization owner evaluates one approved local maintainer-reviewed npm advisory revision against one asset. This is one synchronous API command. It is not an all-asset scan, a worker job, or a Finding workflow.

`POST /assets/:assetId/product-match-evaluations` requires `product_match:evaluate_controlled`. That permission belongs to the owner only. Admin, member, and viewer are denied. `finding:create_controlled`, `finding:discover_controlled`, `finding:inspect`, `finding:triage`, `finding:read`, `asset:manage`, `intelligence:read`, and an instance advisory grant do not substitute.

Organization, actor, and membership come from the authenticated session. A body, query, or header organization id is not tenancy. The application reloads the user, organization, membership, and owner role inside the transaction. A mismatch writes nothing.

Grant revocation or user disablement after approval does not block evaluation. Approval remains the publication decision.

## Request

The body is one JSON object and nothing else:

```json
{ "advisoryRevisionId": "<canonical UUID>" }
```

The asset id is the path parameter. Both identifiers are canonical UUIDs.

The route requires `application/json`, a body of at most 1024 bytes, no query string, an exact allowed Origin, the session cookie, and the CSRF synchronizer header. A repeated Origin or CSRF header is rejected. Forwarded headers do not replace Origin. `X-Forwarded-For` does not select the peer.

## What the command evaluates

The command uses one asset and that asset's locked latest successful SBOM ingestion. The ingestion must be present, `completed`, normalization version `2`, and still the locked pointer. A version `1` graph is not evaluable and is not rewritten.

The advisory must be one approved local maintainer-reviewed npm revision that is recorded, has no supersession, and is not withdrawn or quarantined. A superseding tip is rejected. An explicit-version-only revision is ineligible. Offline npm GHSA rows stay `ineligible_offline_import` with retrieval `local_not_retrieved` and are not evaluated.

Selection uses the stored npm package identity. There is no fuzzy match. Occurrences are ordered by `component_occurrence.id` text with the C collation. Sixteen selected occurrences can commit. A seventeenth selected occurrence rejects the request and writes nothing. The selected set is never truncated.

Stored outcomes remain `affected`, `unaffected`, and `unknown`. A version that is not known, including the empty version stored with that flag, is counted as `version_not_known` and is not a row. A known version the command parser rejects is counted as `version_unrepresentable` and is not a row. `no_relevant_occurrence` and `no_evaluable_occurrence` are command results. They are not evidence rows.

Evidence rows are immutable. An exact replay inserts nothing. A conflicting body writes nothing.

## Limits

- Direct peer: 5 requests per 60 seconds, before authentication, keyed by the socket peer
- Organization: 5 requests per 60 seconds, after permission and body validation
- An unauthorized actor does not consume the organization budget
- `X-Forwarded-For` is not the peer or the tenant

The limiters are process-local. Restarting the API process clears them. There is no rate-limit table and no shared Redis limiter. Each API process keeps its own window, so several API processes multiply the ceiling. That multiplication is an accepted residual for this slice. The evaluation transaction uses a 5000 ms statement timeout, a 2000 ms lock timeout, a 2000 ms interactive wait, and a 10000 ms transaction ceiling. A timeout returns 503 and writes nothing. This slice adds no migration. The frozen migration count is 28.

## Results

- `201` `evaluated` means at least one new evidence row committed.
- `200` `already_applied` means no new row was inserted and at least one occurrence was replayed.
- `200` `no_relevant_occurrence` means no occurrence was selected.
- `200` `no_evaluable_occurrence` means every selected occurrence was skipped.
- The success body is the count summary: schema version `deliberate_product_match_evaluation_response_v1`, status, asset id, advisory revision id, ingestion id, selected, evaluated, inserted, replayed, and skipped counts, skip reasons, outcome counts, and `findingCreation` `unavailable`. It contains no evidence ids, package names, versions, fingerprints, or explanation codes.
- Invalid requests are `400` `Invalid request.` Missing session or CSRF failure is `401` `Authentication required.` Missing permission is `403` `Permission denied.` A missing active organization is `403` `Organization context is required.` Origin failure is `403` `Origin is not allowed.`
- A foreign asset and an absent asset are both `404` `Not found.`
- A conflicting replay is `409` `The request conflicts with stored evidence.`
- Every advisory-ineligible reason is `422` `The advisory revision cannot be evaluated.` An ingestion that cannot be evaluated is `422` `The asset has no evaluable ingestion.` Capacity is `422` `The asset exceeds the evaluation occurrence limit.`
- Malformed persisted state and an aborted transaction are `500` `An internal error occurred.`
- A timeout, database outage, or limiter fault is `503` `Product Match Evidence evaluation is temporarily unavailable.`
- The peer or organization limit is `429` `Too many requests. Try again later.`
- Responses use `Cache-Control: private, no-store`.

A rejected request, a rollback, a capacity rejection, and a result with zero inserts leave the database unchanged. Do not update or delete an evidence row or an audit row in place.

## Audit

When at least one new evidence row commits, the same transaction writes one `vulnerability.match_evaluated` event. The actor type is `user`. The subject is the asset. The payload records purpose `deliberate_product_match_evidence_evaluation`, policy `deliberate_product_match_evaluation_policy_v1` version `1`, the advisory revision id, asset id, ingestion id, and counts. It does not record package names, versions, ranges, fingerprints, evidence ids, explanation codes, vulnerability ids, or CVE lists.

Exact replay, rejection, rollback, `no_relevant_occurrence`, `no_evaluable_occurrence`, and `capacity_exceeded` write no audit row. There is no database trigger tying evidence to the audit row. The adapter writes them in one transaction.

## What this route does not do

The command does not insert or update a Finding, an observation, or an evidence link. Finding state stays `open` and Finding version stays `1`. An existing open Finding is left unchanged. After `affected` evidence exists, the owner uses `GET /assets/:assetId/controlled-finding-targets` and `POST /findings`. Discovery and creation revalidate the qualifying set. `unaffected` and `unknown` evidence is not a Finding target.

The route does not write a `RiskCalculation`, call the priority engine, contact a provider, or enqueue work. Web startup, workers, schedulers, queues, upload processing, seeds, and migrations do not construct it. The original decision had no web UI. On 2026-11-04, [ADR 0050](../adr/0050-product-match-evaluation-web-workflow.md) admits owner `GET /assets/:assetId/product-match-candidates` and the page `/assets/:assetId/product-match-evaluations`. The page posts `{ advisoryRevisionId }` only. It does not create a Finding. A global advisory catalog, a withdrawal writer, and an all-asset scan remain unavailable.

## Candidate discovery

The read is owner only. Permission `product_match:discover_controlled` does not grant evaluation, and evaluation does not grant the read. Admin, member, and viewer receive 403. A missing asset and an asset in another organization both return 404 `not_found`. The read writes no audit row.

An empty list means there is nothing to evaluate for that asset. It does not mean a product-eligible catalog exists. The real product-eligible evaluation count remains 0.

A cursor bound to an older ingestion returns 409 with message `stale_cursor`. After a POST, if the returned ingestion id differs from the ingestion the page discovered, the page discards the list and does not retry the POST. A result whose commit is uncertain tells the owner to reload before trying again. Reload is a new GET. It is not an automatic POST.

The older single-occurrence evaluation command stays production uncomposed. This route does not call it.

## Related

- [ADR 0044](../adr/0044-deliberate-product-match-evidence-evaluation.md)
- [ADR 0050](../adr/0050-product-match-evaluation-web-workflow.md)
- [ADR 0035](../adr/0035-controlled-finding-creation.md)
- [Product-evidence provenance](../architecture/product-evidence-provenance.md)
- [Audit model](../architecture/audit-model.md)
- [Controlled Finding operator](controlled-finding-operator.md)
- [Audit integrity failure](audit-integrity-failure.md)
- [Tenant isolation incident](tenant-isolation-incident.md)
