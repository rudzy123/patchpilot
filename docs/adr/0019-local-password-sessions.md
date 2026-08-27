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

Store Argon2id hashes in PHC form using **one** library: `argon2` (node-argon2). Do not install `@node-rs/argon2` or invent a KDF. Use the library `hash`, `verify`, and `needsRehash` APIs. Reject passwords shorter than the configured minimum character length (default 12) and longer than 128 UTF-8 bytes **before** hashing. Do not compare Booleans with `timingSafeEqual`.

**Library selection (investigation, not installed in this batch):**

| Candidate | Node 24 / Linux CI / containers | PHC + `needsRehash` | Notes |
| --- | --- | --- | --- |
| `argon2` 0.45.x | Documents Node ≥ 22; Ubuntu and Alpine prebuilds | Yes | Selected |
| `@node-rs/argon2` | NAPI prebuilds, Node 24 benchmarks | No first-class `needsRehash` | Rejected so a second hasher is not added |
| `node:crypto.argon2` | Built into Node 24.7+ | No PHC helpers | Unsuitable as the password-store API |

Pin `argon2` when hashing code is implemented. Add it to pnpm `allowBuilds` if native compilation is required. Tests may inject a cheap fake hasher. Production and unguarded development must use at least OWASP minimum parameters (m=19456 KiB, t=2, p=1). Cheaper parameters are allowed only in `test` or development with `allowDevelopmentAdapters=true`. Config rejects below-minimum production parameters and unreasonable upper bounds.

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

A later ADR may supersede this catalog. Owner can both request and approve risk acceptance; that residual is documented, not a bypass.

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
- **`@node-rs/argon2` or custom hashing:** extra dependency or custom cryptography; `argon2` already provides PHC and `needsRehash`.
- **Operator-supplied dummy PHC in env:** secret sprawl and accidental logging; a fixed server-only constant is enough because it authenticates nobody.
- **Public registration / first-user HTTP in this milestone:** open instance abuse ([threat model](../security/threat-model.md)); deferred.
- **Session listing / remote revoke:** extra IDOR surface; logout current session only.
- **`trustProxy=true` now:** `X-Forwarded-For` spoofing until topology is specified.

## Consequences

Operators get a documented, config-gated authn design that works offline. Runtime login is not available until later batches. Login will fail closed if Redis is down. Stolen cookies last until idle/absolute expiry or logout on that device. Native `argon2` prebuilds must be confirmed on Linux CI when the dependency is added. Audit actor constraint changes require a new migration, not an edit of Session 5 SQL.

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
- `packages/auth`, API plugins, five routes, guarded seed credentials, minimal login UI.
- Confirm `argon2` prebuilds on Node 24 Linux CI when installing.
- Future: OIDC as another `authenticationMethod` on the same session row; MFA; lockout beyond rate limits; first-user bootstrap; session listing; `trustProxy` after a documented proxy topology; password change (column `passwordRevision` is reserved).

Required tests for this batch: typed config accept/reject cases in `packages/config`. Runtime auth tests belong to later batches.
