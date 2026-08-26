# Definition of done

A change is done when it is safe to review and operate, not when it merely compiles or a happy-path test is green.

Passing tests do not make a release production-ready.

## Required for significant features

A **significant feature** is any change that affects tenant data, a trust boundary (upload, webhook, feed, authz), background jobs, scoring, evidence, or a user-visible workflow. Cosmetic copy-only changes are not significant.

Every significant feature must include:

1. **Behavior** that stays inside [MVP scope](../product/mvp-scope.md) or is labeled future work.
2. **Tests** (unit, integration, and browser coverage as appropriate) that are deterministic and not skipped without a tracked reason.
3. **Error handling** with the stable API/domain error taxonomy where applicable.
4. **Structured logs** (Pino, once the logger package exists) with correlation IDs and redaction of secrets, tokens, raw SBOMs, and feed payloads.
5. **Metrics** for the new operation (success, failure, and at least one saturation or lag signal for background work).
6. **Documentation** (user-facing, ADR, and/or runbook) adequate to operate the change.
7. **Operational failure plan**: what happens on retry, poison message, storage outage, feed outage, or partial parse; how to detect and recover.

## Security and tenancy

- Deny-by-default authorization from authenticated context.
- Organization scope on every tenant-owned operation.
- Zod validation at the trust boundary.
- No new secret in source or logs.
- Audit events for security-sensitive and remediation-sensitive mutations.
- Security regression tests when the change is security-sensitive.

## Data and jobs

- New migrations rather than edits to applied migrations.
- Transactions without network/queue/object-storage I/O inside them.
- Outbox + idempotent handlers for background work.
- Policy version and factors stored with new scores.
- Evidence retained; no casual cascade deletes.

## Pull request

- Conventional Commits and the [review checklist](review-checklist.md) completed.
- Required checks pass or, before CI exists, equivalent commands were run and reported accurately.
- No unexplained dependency additions.
