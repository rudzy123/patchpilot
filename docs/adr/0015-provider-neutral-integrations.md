# ADR 0015: Provider-neutral external integrations

- Status: Proposed
- Date: 2026-08-26
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

OSV, KEV, and object storage must not leak vendor SDKs into domain code. GitHub is not MVP. Development adapters are unsafe in production.

## Decision

Reach external systems only through **ports and adapters**. Domain depends on ports. Object storage is S3-compatible and provider-neutral. HTTP feeds validate with Zod at the adapter. **Integration** and **ExternalCredential** entities exist even if v0.1 tenant credentials are unused. Development adapters (fake auth, unsigned webhooks, unrestricted HTTP, plaintext stubs) are not selectable when configuration is production. Decrypt credentials only in adapters.

## Alternatives considered

- **Call AWS SDK from use cases**: rejected.
- **GitHub in MVP**: rejected by product non-goals.

## Consequences

New providers need adapters and usually an ADR. **RepositoryConnection** stays `not_configured`.

## Security and tenancy

SSRF allowlists. Credentials tenant-owned when present. No token reuse across organizations if GitHub is added later (1:1 installation mapping).

## Operational failure plan

Provider outage: integration `degraded`; last snapshots remain. Rotation states on credentials.

## Follow-up

Integrations package when scaffolded. No webhook server in v0.1.
