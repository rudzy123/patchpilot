# Data access

This document describes how PatchPilot scopes data after Session 5. It is not an authorization product yet: membership checks and session binding remain future application-layer work. Persistence still requires `organizationId` on every tenant-owned repository method.

## Rules

- Deny by default at the repository adapter: tenant reads and writes include `organization_id`.
- Looking up by resource UUID is not authorization. Adapters take `organizationId` from the caller of the port; use cases must later pass **authorized organization**, never a client-supplied id as proof.
- Global intelligence (`vulnerability`, source records, aliases, built-in policies, `intelligence_source`) is shared. Findings that reference it remain tenant-owned.
- Object keys for SBOMs include `org/{organizationId}/...`. Guessing a digest must not yield another tenant's row even if hashes collide across organizations.
- No cross-organization operator API exists.

## Tests

`packages/database` integration tests create two organizations and assert that `findById` for the other org returns nothing. They do not include exploit payloads.

## Related documents

- [Tenant isolation](../architecture/tenant-isolation.md)
- [Database security](database-security.md)
