# ADR 0043: Instance advisory authority grants

- Status: Accepted
- Date: 2026-10-14
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the instance-scoped authority decision for maintainer-reviewed
advisory submission and approval. Acceptance records a resolved identity and
grant architecture. It does not implement a relation, a migration, a command,
a route, a permission, or an advisory writer. Merge to `main` remains subject
to normal pull-request review. [ADR 0042](0042-maintainer-reviewed-advisory-production-composition.md)
composes the later submission and approval commands on top of this decision.

Repository precedent accepts a fully resolved architecture before its
implementing migration. [ADR 0019](0019-local-password-sessions.md) was accepted
as the authentication design before login and the session migration existed.
This ADR is Accepted for the same reason. Implementation remains a later
feature branch.

## Context

[ADR 0032](0032-maintainer-reviewed-advisory-authority.md) requires distinct
author and reviewer identities and an issued capability for
`approve_maintainer_reviewed_advisory_for_product_evaluation`. The frozen
advisory, approval, and capability tables have no organization column. They
are instance-owned. The frozen schema has no instance advisory grant relation.
The current frozen migration count is 25.

[ADR 0019](0019-local-password-sessions.md) authenticates an existing `User`
with a local email and an Argon2id password, then resolves an opaque
PostgreSQL session. `User.id` is `gen_random_uuid()`. `TrustedActor.userId` is
that id. Session resolution succeeds for an active user when no organization
is selected. `TrustedActor.permissions` come only from the active membership
role and are empty when that role is null. Organization roles are `owner`,
`admin`, `member`, and `viewer`.

[ADR 0014](0014-append-only-audit.md) and the frozen
`audit_event_actor_scope_chk` already allow two shapes this decision uses:

- instance-level `user`: `actor_user_id` set, `organization_id` null,
  `actor_membership_id` null;
- `system`: `actor_user_id` null, `actor_membership_id` null, organization
  null or set.

`author_identity` and `reviewer_identity` are ASCII strings matching
`^[A-Za-z0-9][A-Za-z0-9._@-]*$`, at most 128 characters, with exact and
case-folded inequality. A lowercase UUID fits that check. Those columns are
not user foreign keys. This ADR does not add that foreign key.

[OD-10](../architecture/open-decisions.md) remains open for a general operator
console. Its interim default says not to use a tenant `User.id` as the
instance operator. The canary `instance_operator` attestation
(`osv_canary_instance_operator_identity_v1`) is canary-scoped and production
uncomposed. Neither is advisory authority.

No production path currently grants advisory submission or approval.
Organization permissions, including `finding:create_controlled`,
`finding:inspect`, `finding:discover_controlled`, and `intelligence:read`, are
tenant or sanitized-status powers. There is no production user-disable
command. `User.status` is `active` or `disabled`, and session resolution
rejects a disabled user.

## Decision

Instance advisory authority is:

existing authenticated `User`
→ one durable instance advisory authority grant
→ organization membership ignored.

The stable principal is the canonical lowercase `User.id`. The grant is
instance-owned PostgreSQL truth. Organization roles cannot grant or revoke it.
The canary `instance_operator` is unrelated. This ADR introduces no external
identity provider, no second account system, and no second login system.

### Principal identity

The instance advisory principal is the canonical lowercase text of `User.id`.

That identity stays stable across organization membership changes, organization
switching, session changes, role changes, email changes, and display-name
changes.

These are not the principal:

- membership id;
- organization id;
- session id;
- email;
- display name;
- role;
- capability id;
- `instance_operator` attestation;
- a caller-supplied user id.

`TrustedActor.userId` from the existing session resolver is the source. The
application lowercases it before persistence and comparison. A request body
cannot select it.

### Authentication boundary

Reuse [ADR 0019](0019-local-password-sessions.md) unchanged:

- local email and Argon2id password authentication of an existing user;
- opaque PostgreSQL-backed session;
- current secure cookie behavior, including `__Host-patchpilot.sid` in
  production and the development loopback cookie only where ADR 0019 already
  allows it;
- idle and absolute expiration;
- session revocation;
- user disablement on session resolution;
- existing Redis login limits and direct-peer limits, with `trustProxy` false;
- existing synchronizer CSRF and exact Origin checks on future state-changing
  HTTP requests.

This ADR does not authorize JWT access tokens, OIDC, unauthenticated headers,
environment usernames, raw actor ids, role assertions, Git identity, or email
allowlists.

Future advisory mutations authenticate with the current session resolver. A
resolved active user is sufficient when `organizationId`, `membershipId`, and
`role` are null. Missing membership is not an authentication failure for this
slice. Membership, when present, is ignored for advisory authority.

### Authority classifications

Exactly two active human advisory authorities exist. They are grant
classifications, not entries in the [ADR 0019](0019-local-password-sessions.md)
permission catalog:

- `advisory_submit_local`
- `advisory_approve_for_product_evaluation`

`advisory_submit_local` permits one authenticated active user to submit one
local maintainer-reviewed advisory document under
[ADR 0042](0042-maintainer-reviewed-advisory-production-composition.md). It
does not grant approval, capability issuance, product evaluation, Product
Match Evidence generation, or Finding authority.

`advisory_approve_for_product_evaluation` permits one authenticated active
user to approve one exact submitted advisory revision after the approval
application service validates authority, separation, and stored revision
facts. It does not grant submission, provider acquisition, evaluator
execution, Product Match Evidence generation, or Finding authority.

No status-inspection authority is composed in the first slice.

### Mutual exclusivity

At most one active instance advisory grant exists per user. A user cannot
simultaneously hold `advisory_submit_local` and
`advisory_approve_for_product_evaluation`.

A later revocation closes the active grant. A later re-grant inserts a new
row. A revoked row is not reactivated in place. This is not generic instance
RBAC.

### Separation of duties

Submission and approval compare canonical submitter `User.id` with canonical
reviewer `User.id`. They must be unequal, including the existing case-folded
database backstop.

The same user remains the same principal across several sessions, several
memberships, several organizations, a changed email, and a changed display
name. Membership, organization, session, role, email, display name, and
capability id do not determine separation.

Mutually exclusive grants are the preventive control. The stored identity
comparison is the transaction-time backstop. If persisted grant state is
malformed, including two active grants for one user, the transaction writes
nothing.

One human can control two `User` accounts. Canonical `User.id` comparison
cannot detect that. This ADR does not add identity proofing, enrollment, or
password reset. Operators must not knowingly grant the two authorities to
accounts controlled by one person. That residual remains.

### Grant relation

One later additive relation, `instance_advisory_authority_grant`, is required.
It has no organization ownership. Grant truth comes from PostgreSQL. No
process-local cache and no environment allowlist is authority. Every API
instance reads committed grant truth inside the governed mutation transaction.
Database unavailability fails closed.

The relation contains only these bounded fields:

| Field | Intent |
| --- | --- |
| `id` | UUID primary key |
| `user_id` | Existing `User.id`. Foreign key `ON DELETE RESTRICT` |
| `authority` | Closed to the two classifications above |
| `issued_at` | Database time. Immutable |
| `revoked_at` | Null while active. Set once on revocation |
| `issuance_classification` | Closed to `deployment_local_command` |
| `command_correlation_id` | Operator correlation identity. Not a secret |

Required properties:

- no organization column;
- one active row per user;
- revocation occurs at most once;
- revoked rows are immutable history;
- re-grant inserts a new row;
- no secret material;
- no capability material;
- no provider or Finding authority;
- tenant roles cannot write the relation.

Exact index names, compound-key syntax, and trigger text are implementation
details of the authority-foundation migration, provided that migration
enforces one active row per user, a closed authority, one revocation, and
immutability of a revoked row.

### Migration

One additive forward migration is required on
`feat/instance-advisory-authority-foundation`. That migration raises the
frozen migration count from 25 to 26 only on that branch. This ADR does not
create it.

The migration must:

- add `instance_advisory_authority_grant`;
- preserve all 25 predecessor migrations and hashes;
- seed no grants;
- assign no authority automatically;
- grant no owner or admin authority;
- create no default user;
- create no password;
- add no organization ownership;
- add no provider, evaluator, Product Match Evidence, Finding, observation, or
  lifecycle behavior.

Advisory family, revision, binding, approval, capability, and audit storage
remains sufficient for [ADR 0042](0042-maintainer-reviewed-advisory-production-composition.md).
That composition branch adds no migration.

```text
Current frozen migration count: 25
Future authority-foundation count: 26
```

### Grant controller

One deployment-local grant command is the sole supported grant writer. It is
not an API route, a web page, a worker, a scheduler, a startup hook, a seed,
an organization-admin operation, or an automatic installer grant. It is not
the deferred product CLI in [ADR 0018](0018-go-cli-deferred.md).

The command performs exactly one explicit operation at a time:

- grant `advisory_submit_local`;
- grant `advisory_approve_for_product_evaluation`;
- revoke the active advisory grant;
- disable an existing user;
- re-enable an existing user without granting authority.

It operates only on an existing user. It must not create users, set passwords,
reset passwords, create memberships, accept an organization, assign both
grants, reactivate a revoked grant row, or run automatically.

Re-enable does not grant authority and does not revoke an active grant. If
that user still has an active grant, re-enable makes that same grant usable
again and inserts no row. Recovery from compromise revokes the grant and
disables the user as two explicit operations. Re-enable after that revocation
does not restore the revoked row.

### Grant-command authority

Infrastructure access to execute the command is outside tenant administration.
The command executes as a bounded system operation. Grant-change and
user-status audit events use the existing `system` actor shape:
`actor_type = system`, null `actor_user_id`, null organization, and null
membership. `correlationId` is the command correlation identity.

The deployment operator is not an authenticated advisory reviewer, not
`instance_operator`, not a `User` principal for the advisory action, not an
organization owner, and not an approval capability issuer.

Manual SQL is an unsupported bypass equivalent to self-hosted database
compromise. It is not a supported grant procedure.

### Grant replay and conflict

**Exact grant replay.** The same active user already holds the same active
authority. Return `already_applied`. Zero inserts, zero updates, and no
second audit event. A different command correlation id does not make that
replay a second grant or a second audit event. If the operator does not
observe whether the attempt committed, the retry reads the stored grant and
uses this same classification.

**Conflicting grant.** The user already has another active advisory
authority. Return `active_grant_conflict`. Zero writes.

**Revocation replay.** The user's advisory grant is already revoked. Return
`already_applied`. Zero additional updates and no second audit event. A user
with no grant row returns `grant_absent` and writes nothing. That result is
not `already_applied`.

**Re-grant after revocation.** Insert a new grant row. Do not reactivate the
prior row.

Disable of an already disabled user, and re-enable of an already active user,
return `already_applied` with zero updates and no second audit event. A
missing user returns `user_absent` and writes nothing. The command does not
create the user.

Malformed grant state fails closed as `malformed_persisted_state` and writes
nothing. Database unavailability fails closed and writes nothing.

### Revocation and disablement

Grant revocation removes advisory authority prospectively. It does not disable
tenant access, rewrite submitted revisions, rewrite approvals, or invalidate
a previously committed approval.

User disablement prevents authentication and session resolution. It is
required for compromised credentials. It does not by itself rewrite advisory
rows.

An in-flight advisory transaction reloads user active status and the active
instance grant from PostgreSQL. If either check fails, the transaction writes
nothing, including no capability issuance. All API instances observe committed
user and grant truth. No grant cache is authorized.

### Outstanding capabilities

The first advisory approval slice issues and consumes the capability inside
one approval transaction. No caller-held long-lived capability is created.

A capability may be consumed only when the reviewer remains active, still
holds `advisory_approve_for_product_evaluation`, matches the capability
reviewer identity, remains distinct from the author, and the capability is
presented inside that transaction before expiry. The presentation handle does
not leave the transaction and is not an HTTP field.

Grant revocation or user disablement before consumption causes zero approval
writes. A previously committed approval remains immutable.

### Capability issuance

The approval application service is the only production boundary permitted to
call the private sealed issuer. The API process executes that service. The
API process is not the reviewer.

The service must:

1. authenticate the reviewer through the existing session resolver;
2. reload active user status;
3. reload the active approval grant;
4. load the submitted revision;
5. enforce separation of duties on canonical `User.id`;
6. derive immutable fingerprints and target facts from storage;
7. issue one narrowly bound capability for
   `approve_maintainer_reviewed_advisory_for_product_evaluation`;
8. insert that issuance and consume it in the same approval transaction.

This ADR does not authorize a public capability-minting route, a generic
issuer export, direct reviewer access to the issuer, worker issuance, seed
issuance, generic CLI issuance, or tenant-role issuance.

### Submission and approval boundaries

A future submission requires an authenticated active user and an active
`advisory_submit_local` grant. It requires no organization authority, no
membership, and no caller-selected principal. It persists canonical `User.id`
as `author_identity`, the immutable advisory revision, advisory provenance,
the required vulnerability binding, and one bounded audit event. Submission
grants no approval or downstream evidence authority.

A future approval requires an authenticated active user, an active
`advisory_approve_for_product_evaluation` grant, one exact submitted revision,
canonical reviewer `User.id`, author and reviewer inequality, one internally
issued exact capability, and the approved purpose. Approval grants eligibility
for later evaluation only. It does not run evaluation, generate Product Match
Evidence, create or update a Finding, record a repeated observation, or
contact a provider.

The first slice composes no status-inspection route. Submission and approval
return only their bounded mutation outcome and a safe revision identifier.
Broad advisory-document or catalog inspection remains separately governed.

### Audit identity

Human advisory actions use `actor_type = user` and
`actor_user_id = authenticated User.id`. Organization and membership stay
null. That is the existing instance-level user shape. Do not copy the
session's active organization onto these events.

Grant-command actions use `actor_type = system`, null `actor_user_id`, null
organization, and null membership.

Future grant actions are:

- `intelligence.instance_advisory_authority_granted`
- `intelligence.instance_advisory_authority_revoked`

Future user-status actions from this command are:

- `auth.user_disabled`
- `auth.user_reenabled`

Grant events use subject type `instance_advisory_authority_grant` and the
grant row id. User-status events use subject type `user` and `User.id`.
`schema_version` is 1. `retention_category` is `security`.

Payloads may include the target user id, the authority classification, the
revision id, the approval purpose, the capability issuer-authorization id, and
the command correlation identity.

Payloads and logs omit passwords, password hashes, session tokens, CSRF
tokens, capability seals, configuration secrets, raw advisory bodies, provider
payloads, and SQL or database details. The payload object includes
`schemaVersion` 1, which the frozen `audit_event_payload_schema_chk` requires,
in addition to column `schema_version` 1. `correlationId` is the command
correlation identity and is required because these events have a null
organization.

Exact replay writes no second audit event, including when a retry presents a
different command correlation id.

### Bootstrap

The first grants are established by explicitly running the deployment-local
command for two different existing active users, one for each authority.
This architecture does not provide user creation or password reset.

Do not use development seeds in production, ship default credentials, grant
every owner, grant at startup, grant through organization administration, or
leave a bootstrap mode permanently enabled.

Bootstrap replay follows grant replay. If two suitable existing users do not
exist, approval remains unavailable until users are provisioned through
separately governed identity work. [ADR 0019](0019-local-password-sessions.md)
still has no public registration and no password reset.

### Recovery

Recovery has no tenant-role fallback.

| Condition | Response |
| --- | --- |
| All submission grants lost | Grant `advisory_submit_local` to a different existing active user who has no active approval grant |
| All approval grants lost | Grant `advisory_approve_for_product_evaluation` to a different existing active user who has no active submission grant |
| Compromised user | Revoke the grant and disable the user |
| Lost password | Disable the user and assign authority to another existing active user. This slice adds no password reset |
| Malformed grant state | Fail closed |
| PostgreSQL unavailable | Fail closed on every API instance |
| All suitable users unavailable | Submission or approval remains unavailable until valid users exist through separately governed identity work |

### Tenant isolation

Instance advisory grants have no organization owner. Organization switching
does not change advisory authority. Organization roles do not imply advisory
grants. Advisory grants do not imply tenant permissions and do not grant
tenant asset or Finding access. Submission and approval accept no organization
field. No organization administrator may grant or revoke advisory authority.

A user may independently possess organization membership and one instance
advisory grant. The checks remain separate.

### Multi-instance consistency

Grant truth resides in PostgreSQL. Every API instance reads committed grant
state inside the governed mutation transaction. This ADR does not authorize
process-local authority caches, environment allowlists as ongoing authority,
stale configuration, or asynchronous propagation as the authority model.
Database unavailability fails closed.

### Implementation sequence

**Feature branch 1, `feat/instance-advisory-authority-foundation`.** Implements
only the additive grant migration, grant persistence and guards, the
deployment-local grant command, grant replay and conflict, revocation, user
disable and re-enable command behavior, grant audit events, an authorization
read port, and multi-instance PostgreSQL verification. It does not implement
advisory submission or approval routes.

**Feature branch 2, `feat/maintainer-reviewed-advisory-production-composition`.**
Implements only after feature branch 1 merges. It implements the submission
application service and route, the approval application service and route,
internal capability issuance and consumption, advisory and binding
persistence, audit events, replay and concurrency, and zero Product Match
Evidence and Finding writes. No web UI is authorized.

Product Match Evidence evaluation, Finding writes, repeated observations,
provider calls, and lifecycle behavior stay outside both branches.

## Alternatives considered

- **Organization owner or admin as the advisory principal.** Rejected. That
  gives tenant administration control of the instance catalog and collapses
  separation of duties into a role.
- **A new organization permission.** Rejected. The permission catalog is
  membership-scoped. This ADR does not extend it.
- **`User.id` alone, with no grant.** Rejected. Authentication proves the
  person. It does not prove advisory authority.
- **`User.id` as the OD-10 instance operator.** Rejected. OD-10 stays open.
  This principal is an advisory grant, not the operator console, not
  IntelligenceSource administration, and not cross-organization tenant access.
- **Canary `instance_operator`.** Rejected. That attestation is not a
  production user and is not advisory authority.
- **Environment allowlist or process-local set.** Rejected. Those are not
  durable across API instances and are not revocable PostgreSQL truth.
- **A second login system, OIDC, or JWT.** Rejected. [ADR 0019](0019-local-password-sessions.md)
  already authenticates the user.
- **Caller-held long-lived capability.** Rejected. The approval service issues
  and consumes one capability inside the approval transaction.
- **A separate human capability issuer.** Rejected. The approval service is
  the only production caller of the private issuer.
- **Reactivating a revoked grant row.** Rejected. Revoked rows stay history.

## Consequences

The authority decision is in force. Nothing in this ADR is implemented. A
normal installation still cannot submit or approve a local advisory. The
frozen migration count remains 25 until feature branch 1 merges.

Positive: submission and approval can later name a stable human principal
without giving that power to an organization role, and revocation is visible
to every API instance from PostgreSQL.

Negative: bootstrap requires two existing active users and explicit command
runs. Lost passwords are not reset here. A deployment with fewer than two
suitable users cannot complete approval.

## Security and tenancy

Advisory grants are instance-owned and organization-free. Tenant Finding and
asset authority is unchanged. No secret is logged. No outbound fetch is added.
The grant command is outside tenant administration. Self-approval still fails
closed on `User.id`. Exact grant replay is not a second grant.

Two accounts controlled by one person remain a residual. The deployment
operator who can execute the command is trusted to assign grants and can
choose those accounts. The command stays explicit, audited, and nonautomatic.
It cannot create users, reset passwords, or place both authorities on one
user. Manual SQL is database compromise, not recovery. There is no
organization-role fallback.

## Operational failure plan

Until the command exists, there is no operator procedure and no grant to
repair. After it exists, operators detect failure from the command result.
They do not update a revoked row. A conflicting grant requires revocation of
the active grant before a different authority is granted. Database
unavailability fails the command and fails every API advisory mutation closed.
There is no cache to flush and no queue to drain.

Compromised credentials are handled by revocation plus disablement, not by a
tenant role. A lost password disables that user and moves authority to
another existing user. This slice does not add password reset.

## Follow-up

- Feature branch 1 implements the migration, command, guards, audit, and
  PostgreSQL verification named above. Required tests cover tenant roles
  being unable to write the relation, one active grant, replay, conflict,
  revocation immutability, re-grant as a new row, disablement, and fail-closed
  behavior when PostgreSQL is unavailable. Tests use no exploit payloads and
  contact no provider.
- Feature branch 2 follows [ADR 0042](0042-maintainer-reviewed-advisory-production-composition.md)
  only after feature branch 1 merges.
- OD-10 stays open for the operator console, IntelligenceSource
  administration, global catalog administration, cross-organization
  administrative access, and other instance-wide operations.
- Product Match Evidence, provider acquisition, repeated-observation writes,
  and Finding lifecycle remain deferred.
