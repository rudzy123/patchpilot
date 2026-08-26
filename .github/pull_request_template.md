## Summary

<!-- What changed, in one or two sentences. -->

## Motivation

<!-- Why this change is needed now. -->

## Scope

<!-- What is in and out of this pull request. Use "Not applicable: …" for sections that do not apply, with a short reason. Documentation-only changes may mark most engineering sections that way. -->

## Architecture impact

<!-- Layering, package boundaries, ADRs, or "Not applicable: …". -->

## Security and privacy impact

<!-- Secrets, redaction, untrusted input, XSS, SSRF, or "Not applicable: …". -->

## Tenant-isolation impact

<!-- Organization scoping, IDOR, or "Not applicable: no tenant-owned data is touched". -->

## Database and migration impact

<!-- Schema, migrations, evidence retention, or "Not applicable: …". -->

## API contract impact

<!-- HTTP/OpenAPI changes or "Not applicable: …". -->

## Background-job and idempotency impact

<!-- Outbox, replay, org-scoped uniqueness, or "Not applicable: …". -->

## Observability impact

<!-- Logs, metrics, traces, redaction, or "Not applicable: …". -->

## Testing performed

<!-- Commands actually run and their results. Do not claim checks passed if they were not run. -->

## Manual verification

<!-- What was checked outside automated tests, or "Not applicable: …". -->

## Deployment impact

<!-- Config, Compose, images, operator steps, or "Not applicable: …". -->

## Rollback or forward-fix plan

<!-- How to revert or fix forward if this lands badly. -->

## Documentation updates

<!-- Docs, ADRs, runbooks touched, or "Not applicable: …". -->

## Risks and mitigations

<!-- Residual risk after this change. -->

## Checklist

- [ ] Stays inside [MVP scope](docs/product/mvp-scope.md) or is labeled future work
- [ ] No secrets, `.env` files, or real SBOMs committed
- [ ] Tenant-owned operations remain organization-scoped from trusted context
- [ ] Tests added or updated where behavior changed
- [ ] Required CI checks are expected to run (no path-filter blind spots)
- [ ] [Review checklist](docs/development/review-checklist.md) considered
- [ ] Suspected vulnerabilities were **not** discussed in public issue or PR text ([SECURITY.md](SECURITY.md))
