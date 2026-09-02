# ADR 0019: Local password authentication and opaque sessions

- Status: Accepted
- Date: 2026-08-27
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

## Context

PatchPilot is a self-hosted modular monolith. Session 5 persisted `User` and `Membership` without credentials or sessions. [OD-1](../architecture/open-decisions.md), [OD-2](../architecture/open-decisions.md), and [OD-3](../architecture/open-decisions.md) left authentication, session storage, and the permission catalog unspecified. Operators cannot depend on an identity provider. The browser is untrusted. Tenant data must use **authorized organization** from membership, never a client-supplied id ([ADR 0013](0013-organization-scoped-tenancy.md)).

This ADR closes OD-1 (authentication mechanism), OD-2 (session store), and OD-3 (interim permission catalog) for v0.1. It does not implement login, hashing, or schema. Later batches add a forward-only migration and runtime code.

## Decision

### Authentication

Authenticate **existing users only** with local email and password. There is no public registration, invite workflow, password reset, or email delivery in v0.1. First-user HTTP bootstrap is deferred; development may attach synthetic credentials through the production-rejected seed. OIDC, social login, passkeys, magic links, JWT access/refresh tokens, Passport, and Better Auth are out of scope.

Generic public login failures: unknown email, wrong password, and disabled user return the same `unauthorized` message. Internally, unknown email still performs **one** Argon2id verification against a fixed, server-only dummy PHC that belongs to no account. The dummy value is not an environment variable, is not generated at startup, is never returned, and is never logged.

### Password hashing

Store Argon2id hashes in PHC form using **one** library: `argon2` (node-argon2) **0.45.1**, declared only on `@patchpilot/auth`. Do not install `@node-rs/argon2`, JWT, Passport, Better Auth, bcrypt, or OIDC libraries. Use the library `hash`, `verify`, and `needsRehash` APIs. Reject passwords shorter than the configured minimum character length (default 12) and longer than 128 UTF-8 bytes **before** hashing. Do not compare Booleans with `timingSafeEqual`.

**Library selection (installed 2026-08-27; sources: npm registry `argon2@0.45.1` and `@node-rs/argon2@2.1.0`, node-argon2 README, published `index.d.ts`):**

| Criterion | `argon2` 0.45.1 | `@node-rs/argon2` 2.1.0 |
| --- | --- | --- |
| Node.js 24 | `engines.node` ≥ 16.17.0; README tests Node ≥ 22; 0.45.x CI includes Node 24 | `engines.node` ≥ 10; README benches Node 24 |
| Linux GitHub-hosted runners | Ubuntu 22.04 glibc prebuilds; compatible with `ubuntu-latest` (24.04) | NAPI `linux-x64-gnu` optional package |
| Local developer install | `node-gyp-build` loads prebuilds | optional platform package, no postinstall compile |
| Prebuilt binaries | Ubuntu, macOS, Windows, Alpine musl, FreeBSD | 15 optional platform packages plus wasm |
| Source-build fallback | yes (`node-gyp` / `--build-from-source`) | no C++ fallback; missing optional native package fails |
| Supply-chain footprint | four runtime JS deps; npm provenance attestation | zero JS runtime deps; fifteen optional native packages |
| Argon2id | default `type` is `argon2id` | default `Algorithm.Argon2id` |
| PHC strings | yes (`@phc/format`) | `hash()` returns an encoded string; no PHC helper API |
| `verify` | `Promise<boolean>` | `Promise<boolean>` |
| `needsRehash` / parameter inspection | first-class `needsRehash` | not in the published TypeScript API |
| TypeScript | shipped `argon2.d.cts` | shipped `index.d.ts` |
| Containers | Alpine musl prebuilds; rebuild if libc mismatches the prebuild | `linux-*-musl` optional packages |
| Maintenance | published 2026-07-21; Node 24 CI | published 2026-08-13 |
| License | MIT (compatible with Apache-2.0) | MIT |
| Testability | `hash` / `verify` / `needsRehash` | `hash` / `verify` only |
| Transitive runtime deps | `@phc/format` (MIT), `cross-env`, `node-addon-api`, `node-gyp-build` | platform `@node-rs/argon2-*` optionalDependencies |

Selected **`argon2@0.45.1`**. pnpm `allowBuilds.argon2` is enabled so `node-gyp-build` can load or compile the native addon. Hashing, dummy-PHC, and session services remain unimplemented. Tests may inject a cheap fake hasher later. Production and unguarded development must use at least OWASP minimum parameters (m=19456 KiB, t=2, p=1). Cheaper parameters are allowed only in `test` or development with `allowDevelopmentAdapters=true`. Config rejects below-minimum production parameters and unreasonable upper bounds. Never log PHC strings; the logger redacts `passwordHash`, `phc`, and related credential-hash fields.

### Sessions

Session authority is **PostgreSQL**, not Redis ([ADR 0006](0006-redis-bullmq.md) remains queue transport). Opaque cookies: 32 random bytes, base64url. Persist only domain-separated SHA-256 digests:

- session: `SHA-256("patchpilot-session-v1:" + rawToken)`
- CSRF: `SHA-256("patchpilot-csrf-v1:" + rawCsrfToken)`

No server pepper in v0.1. Do not store raw session or CSRF tokens. The session row UUID is separate for audit. Configurable absolute lifetime (default 7 days) and idle lifetime (default 12 hours). `lastSeenAt` may update at most once per configured interval (default 60 seconds). Expiration is enforced on read; a cleanup worker is deferred; cleanup indexes ship with the session table.

`passwordRevision` mismatch or `User.status=disabled` invalidates the session. Active organization and membership are **reloaded on every authenticated request**. Rotate **both** the session token and CSRF token on login, after organization selection, and after future privilege-sensitive changes, preferably in one transaction so the old session token is immediately unusable.

Logout revokes only the current session. Session listing and remote revoke are deferred.

### Cookies

Production: name `__Host-patchpilot.sid`, HttpOnly, Secure, SameSite=Lax, Path=/, no Domain. Development loopback HTTP: name `patchpilot.sid`, HttpOnly, Secure=false only for explicit loopback HTTP, SameSite=Lax, Path=/, no Domain. Production startup **rejects** insecure cookies and the development cookie name. Fastify `trustProxy` stays **false** in this milestone. Do not trust `X-Forwarded-For`.

### CSRF

Defense in depth: SameSite=Lax, exact Origin allowlist (`CORS_ALLOWED_ORIGINS`), synchronizer token from `GET /auth/session` in the `x-csrf-token` header on authenticated state-changing requests, and `application/json` for JSON mutations. `Cache-Control: no-store` on authentication and session responses. Referer is not sufficient. Do not log or trace raw CSRF tokens. Rotate CSRF with the session token.

### Organization context

Store `activeOrganizationId` on the session after membership verification. Auto-select only when the user has exactly one active membership in an active organization; otherwise leave it null. `POST /auth/select-organization` verifies membership and rotates tokens. Path or body organization ids are selectors only; they are not authority. Teams and AssetOwner do not grant authorization.

`TrustedActor` is constructed only after session, user, organization, and membership validation. Use cases receive that actor. Tenant repositories receive `organizationId` from it.

### Authorization (closes OD-3)

Deny by default. Check **permission constants**, not scattered role comparisons. Roles remain `owner`, `admin`, `member`, `viewer`. Interim mapping:

| Permission | viewer | member | admin | owner |
| --- | --- | --- | --- | --- |
| `organization:read` | yes | yes | yes | yes |
| `organization:manage` | | | | yes |
| `membership:read` | yes | yes | yes | yes |
| `membership:manage` | | | member/viewer only | all |
| `team:read` | yes | yes | yes | yes |
| `team:manage` | | | yes | yes |
| `asset:read` | yes | yes | yes | yes |
| `asset:manage` | | | yes | yes |
| `sbom:read` | yes | yes | yes | yes |
| `sbom:upload` | | yes | yes | yes |
| `finding:read` | yes | yes | yes | yes |
| `finding:triage` | | yes | yes | yes |
| `remediation:manage` | | yes | yes | yes |
| `risk_acceptance:request` | | | yes | yes |
| `risk_acceptance:approve` | | | | yes |
| `policy:read` | yes | yes | yes | yes |
| `policy:manage` | | | yes | yes |
| `integration:read` | | | yes | yes |
| `integration:manage` | | | yes | yes |
| `audit:read` | yes | yes | yes | yes |
| `intelligence:read` | yes | yes | yes | yes |

A later ADR may supersede this catalog. Owner can both request and approve risk acceptance; that residual is documented, not a bypass. [ADR 0022](0022-intelligence-provider-status-authorization.md) adds `intelligence:read` for sanitized global provider-status GETs. It does not supersede this catalog, reuse `integration:read`, or close instance-operator identity.

### Login abuse controls

Redis-backed distributed limits on `POST /auth/login` keyed by **direct socket peer IP** and a **normalized account-attempt digest** (not the raw email, not the password). **Fail closed** if the limiter is unavailable. Authenticated reads and logout must not require Redis. Bounded Redis timeouts; no infinite retries.

### Audit actors

Do not record successful login as `system`. Forthcoming schema (forward-only migration, not this batch):

- anonymous login failure: `actorType=anonymous`, null user/org/membership
- instance-level user auth: `actorType=user`, `actorUserId` set, null org/membership
- tenant user: `actorType=user`, user, org, and membership set

`system` and `instance_operator` keep their existing meanings. Payloads must not contain email, password, PHC, session token, CSRF token, cookie, or Authorization header.

### v0.1 auth HTTP surface (later batches)

`POST /auth/login`, `POST /auth/logout`, `GET /auth/session`, `GET /auth/organizations`, `POST /auth/select-organization` only.

## Alternatives considered

- **External OIDC only:** stronger for enterprises; blocks self-hosted individuals and nonprofits without an IdP.
- **JWT access and refresh tokens:** theft and replay without server-side revocation; unnecessary for a first-party cookie browser app.
- **Redis session store:** rejected for authority; Redis remains queue and login limiter only.
- **Better Auth / Passport / social login:** would become a second HTTP/identity stack across Fastify and Next.js and would pull provider-specific identity tables.
- **`@node-rs/argon2` or custom hashing:** extra dependency or custom cryptography; published 2.1.0 has no `needsRehash`. `argon2` 0.45.1 already provides PHC and `needsRehash`.
- **Operator-supplied dummy PHC in env:** secret sprawl and accidental logging; a fixed server-only constant is enough because it authenticates nobody.
- **Public registration / first-user HTTP in this milestone:** open instance abuse ([threat model](../security/threat-model.md)); deferred.
- **Session listing / remote revoke:** extra IDOR surface; logout current session only.
- **`trustProxy=true` now:** `X-Forwarded-For` spoofing until topology is specified.

## Consequences

Operators get a documented, config-gated authn design that works offline. Runtime login is not available until later batches. Login will fail closed if Redis is down. Stolen cookies last until idle/absolute expiry or logout on that device. `argon2@0.45.1` is installed on `@patchpilot/auth` with `allowBuilds`; GitHub-hosted Linux CI must still load the same prebuild. Audit actor constraint changes require a new migration, not an edit of Session 5 SQL.

## Security and tenancy

This ADR *is* the authentication, session, CSRF, and interim RBAC decision. It does not weaken [ADR 0013](0013-organization-scoped-tenancy.md). No JWT, no OIDC, no client-supplied organization as proof. Password hashes and dummy PHC are Restricted and must never be logged. Session cookies are Restricted.

## Operational failure plan

- PostgreSQL down: API unready; no session reads.
- Redis down: login rejected; session inspection and logout still work once implemented.
- Production cookie/Argon2/TTL/origin misconfig: process refuses to start.
- Compromised session: user logs out on that client; disable user invalidates all sessions at request time (when runtime exists).

Runtime failure runbooks land with the implementing batches, not this documentation-only batch.

## Follow-up

- Forward-only migration for `LocalCredential`, `Session`, and audit actors.
- Password hashing adapter, session services, API plugins, five routes, guarded seed credentials, minimal login UI.
- Confirm `argon2` 0.45.1 prebuilds on GitHub-hosted Node 24 Linux CI (local Linux install already succeeded).
- Future: OIDC as another `authenticationMethod` on the same session row; MFA; lockout beyond rate limits; first-user bootstrap; session listing; `trustProxy` after a documented proxy topology; password change (column `passwordRevision` is reserved).

Required tests for the library-install batch: Argon2id hash/verify of a synthetic password and proof that the PHC string is not logged. Runtime auth tests belong to later batches.
