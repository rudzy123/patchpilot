# ADR 0004: Fastify API

- Status: Proposed
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

HTTP is the tenant trust boundary: authn context, validation, size limits, audit, outbox writes. Handlers must stay thin.

## Decision

Implement `apps/api` with **Fastify** and TypeScript. Handlers parse HTTP, apply authn context, validate with Zod, invoke use cases in `packages/`. No Prisma, Redis/BullMQ, or object-storage SDKs in handlers. Align types with OpenAPI. Stable error taxonomy. Rate limits on auth, upload, export. Idempotency keys on tenant-owned uploads.

## Alternatives considered

- **Express**: less structured defaults.
- **NestJS**: more magic; harder to keep domain isolated.
- **tRPC only**: weaker explicit OpenAPI for operators.

## Consequences

One HTTP surface for web and future CLI. Fastify plugins for security headers, size limits, and correlation ids.

## Security and tenancy

Authorized organization from membership. Webhooks not in MVP. Do not leak other organizations' existence in errors.

## Operational failure plan

API down: no mutations. Readiness fails if PostgreSQL is down. Validation failures do not enqueue jobs.

## Follow-up

OpenAPI spec when routes exist. CSRF for cookie sessions (OD-1).
