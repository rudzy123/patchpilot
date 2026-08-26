# ADR 0018: Go CLI deferred until after the web MVP

- Status: Proposed
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

A CLI is useful for CI uploads later. Building it in parallel would duplicate the HTTP contract before the web journey exists. Non-goals defer the Go CLI until the web MVP functions.

## Decision

**Do not** implement a Go CLI in v0.1. The web + API + worker journey is the first usable release. When a CLI is added, it must call `apps/api` (same authz) and must not import Prisma or skip tenant isolation. This ADR is the record that deferral is intentional, not an oversight.

## Alternatives considered

- **CLI-first**: rejected; product journey is operator UI + evidence.
- **CLI talking to the database**: rejected.

## Consequences

CI upload helpers are future work. API idempotency and OpenAPI should still be designed so a CLI can follow.

## Security and tenancy

Deferral reduces authn surface. A future CLI is a new client of the same trust boundary, not a bypass.

## Operational failure plan

None in v0.1 (no CLI process).

## Follow-up

After web MVP, a new ADR may choose Go (or another language) and auth method (session vs personal access token).
