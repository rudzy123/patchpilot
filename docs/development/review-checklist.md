# Review checklist

Authors complete this before requesting review. Reviewers verify it. Coding agents include the relevant items in the pull-request summary.

## Scope and product

- [ ] Change matches [MVP scope](../product/mvp-scope.md) or is labeled future work.
- [ ] No new compliance, certification, exploitability, or remediation claims without evidence.
- [ ] Docs and UI keep observed facts separate from calculated conclusions.

## Architecture

- [ ] Layering preserved: no domain/application dependency on Fastify, Next.js, Prisma, Redis, BullMQ, MinIO, or vendor SDKs.
- [ ] Handlers and UI call use cases; business rules are not in routes.
- [ ] Lasting decisions have an [ADR](../adr/README.md) when required.
- [ ] `process.env` is not read outside the config package.

## Security and tenancy

- [ ] Deny-by-default authorization from authenticated context.
- [ ] Client-supplied `organizationId` is not sufficient authorization.
- [ ] Untrusted input validated with Zod at the boundary.
- [ ] Uploads hashed; private artifacts not logged in full.
- [ ] No secrets in source, examples, or logs.
- [ ] SSRF, IDOR, webhook signature/replay, and confused-deputy risks considered for integrations.
- [ ] Public PR does not disclose an unfixed vulnerability ([SECURITY.md](../../SECURITY.md)).

## Data and workers

- [ ] New migration rather than edited applied migration.
- [ ] No network/queue/storage I/O inside DB transactions.
- [ ] Outbox used for durable background work; handlers idempotent.
- [ ] Intelligence provenance preserved; no silent overwrite.
- [ ] Policy version and factors stored with new scores.
- [ ] Evidence not cascade-deleted.

## Quality

- [ ] Tests added or updated; deterministic; no arbitrary sleeps.
- [ ] No skipped tests without a tracked reason.
- [ ] Error handling, logs (redacted), and metrics for significant features.
- [ ] Operational failure plan documented when jobs or persistence change.
- [ ] Accessibility considered for UI changes.
- [ ] Required checks run; results reported honestly.

## Git

- [ ] Short-lived branch; Conventional Commits; no unrelated files.
