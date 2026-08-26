# ADR 0003: Next.js frontend

- Status: Accepted
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

The MVP journey needs an accessible web UI for inventory, upload, findings, remediation, and export. The UI must not be the sole security control.

## Decision

Implement `apps/web` with **Next.js App Router** and React. The web app talks to `apps/api`. Next.js route handlers must not import Prisma, object-storage SDKs, or use cases that skip the API. Authorization, tenancy, and **priority** are decided on the server. Treat SBOM fields as untrusted text (XSS).

## Alternatives considered

- **SPA-only Vite**: possible; we still want SSR-friendly App Router and a conventional React path.
- **Server actions talking to Prisma**: rejected; would make Next a second domain API.

## Consequences

Operators deploy a Node Next.js app. Playwright covers user-visible journeys. Client bundles must not contain API keys or private URLs.

## Security and tenancy

Browser is untrusted. Session cookies follow [open decision OD-1](../architecture/open-decisions.md). No organization id in the client as authority.

## Operational failure plan

Web down: API may still accept uploads from future clients. Next.js misconfig must not expose `.env`.

## Follow-up

Frontend rule file `.cursor/rules/frontend.mdc`. Accessibility on interactive controls.
