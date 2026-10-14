# ADR 0042: Maintainer-reviewed advisory production composition

- Status: Accepted
- Date: 2026-10-14
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the production-composition boundary for one local
maintainer-reviewed advisory submission and one independent capability-backed
approval. [ADR 0043](0043-instance-advisory-authority-grants.md) is the
authority decision: canonical `User.id` plus one durable instance advisory
grant. This ADR does not implement a command, a route, a permission, a
migration, a worker, or a Finding. Merge to `main` remains subject to normal
pull-request review.

The authority-foundation implementation precedes these routes. Feature branch
`feat/instance-advisory-authority-foundation` adds the grant relation.
Feature branch `feat/maintainer-reviewed-advisory-production-composition`
implements this ADR only after that branch merges. Neither branch exists as
implementation. The frozen migration count remains 25.

## Context

The controlled Finding workflow is reachable and evidence starved. Owner
`POST /findings` can create one Finding only from qualifying Product Match
Evidence. A normal installation can ingest and normalize a CycloneDX JSON
SBOM. It cannot produce the reviewed advisory input that Product Match
Evidence requires. Persistent product-eligible evaluation count remains 0.
Production OSV acquisition remains disabled.

[ADR 0032](0032-maintainer-reviewed-advisory-authority.md) is Accepted.
`maintainer_reviewed_advisory_architecture_v1` admits one local document as
`ineligible_unapproved`. Approval purpose is only
`approve_maintainer_reviewed_advisory_for_product_evaluation`. Reviewer
authority is an issued capability under `reviewer_approval_capability_policy_v1`.
Author and reviewer identities must be distinct. Ambient owner, admin,
maintainer, Git, and caller-supplied reviewer claims are not authority. The
public package entry does not export an issuer.

The frozen schema already stores that authority and does not compose it:

- `advisory_family` and `advisory_revision` accept source and origin
  `maintainer_reviewed_advisory` (`20261002120000_maintainer_reviewed_advisory_approval`).
  Those rows have no `organization_id`. They are instance-owned.
- `author_identity` is required for that origin and is an ASCII string, not a
  user foreign key.
- `maintainer_reviewed_advisory_approval` is the approval. There is no status
  boolean. The parent revision stays `trust_classification = unreviewed`. The
  check constraint does not allow `reviewed` trust for this origin.
- `reviewer_capability_issuance` and one append-only
  `reviewer_capability_lifecycle_observation` bind and consume one capability
  (`20261003120000_reviewer_capability_issuance`). Database time sets
  `issued_at` and `expires_at` to a half-open 900000 millisecond lifetime.
- `audit_event` is append-only. `organization_id` is nullable.
  `actor_type` includes `user`.

The Session 15 advisory-revision adapter rejects origin
`maintainer_reviewed_advisory`. That rejection stays. This slice needs a
separate writer. Approval persistence
(`persistMaintainerReviewedAdvisoryApprovalWithCapability`) and capability
issuance are implemented and production uncomposed. No production seed inserts
an approval. API, worker, web, scheduler, queue, and migration startup do not
construct these writers.

[ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) and
[ADR 0035](0035-controlled-finding-creation.md) keep Finding creation behind a
separate controlled transaction. [ADR 0033](0033-product-match-evidence-cardinality.md)
keeps Product Match Evidence on its own tenant-owned table. [ADR 0031](0031-product-evidence-provenance-architecture.md)
remains Proposed and does not make eligibility a stored flag.
[ADR 0014](0014-append-only-audit.md) requires append-only audit.
[ADR 0019](0019-local-password-sessions.md) authenticates a `User` through an
opaque session. Organization permissions come only from the active membership
role. That role is not instance advisory authority.
[ADR 0043](0043-instance-advisory-authority-grants.md) names the advisory
principal as canonical lowercase `User.id` and requires one durable instance
grant. [OD-10](../architecture/open-decisions.md) stays open for a general
operator console. This slice does not use a tenant `User.id` as that operator.
The canary `instance_operator` attestation is canary-scoped, production
uncomposed, and not advisory authority.

Local maintainer-reviewed input precedes Product Match Evidence composition
because the evaluation command already requires one immutable maintainer-reviewed
revision and one independent approval. Provider acquisition is not required for
that input. The document contract is local, origin is stamped by the parser,
and `retrieval_classification` is `local_not_retrieved`. Enabling OSV would
import a different origin and would not review it.

Submission and approval require separate identities because
[ADR 0032](0032-maintainer-reviewed-advisory-authority.md) Decision 4 rejects
self-approval, and the approval check rejects equal and case-folded-equal
author and reviewer identities. The compared values are canonical lowercase
`User.id` values. An owner or admin role is not approval authority: those
roles are organization membership grants, and this advisory is instance-owned
catalog input. Finding creation and inspection permissions are tenant Finding
powers. They do not review an advisory.

Product Match Evidence and Finding writes stay outside this slice.
[ADR 0032](0032-maintainer-reviewed-advisory-authority.md) Decision 11 says
approval is necessary and insufficient for evaluation and Finding creation.
An approved revision is eligibility for a later explicit evaluation. It is not
an evaluation and not a Finding command.

## Decision

Govern one future API-process slice, after
[ADR 0043](0043-instance-advisory-authority-grants.md) is implemented:

1. One authenticated active user with `advisory_submit_local` submits one
   local document.
2. One transaction persists one immutable unapproved revision and its document
   provenance, including the vulnerability-identity binding the frozen approval
   foreign key requires. `author_identity` is canonical lowercase `User.id`.
3. A distinct authenticated active user with
   `advisory_approve_for_product_evaluation` approves that exact revision.
4. The approval application service issues one narrowly bound capability and
   consumes it in the same transaction, inserts one approval, and inserts one
   approval audit event.
5. Exact replay writes nothing.
6. The slice writes no provider, evaluator, Product Match Evidence, Finding, or
   observation row.

Implementation order:

1. `feat/instance-advisory-authority-foundation` implements only the grant
   relation, grant command, and authorization read port from
   [ADR 0043](0043-instance-advisory-authority-grants.md).
2. `feat/maintainer-reviewed-advisory-production-composition` implements this
   ADR only after that branch merges.

Do not mount these routes before the grant relation exists. A caller without
the required active grant fails closed as `authority_rejected` and writes
nothing. An unauthenticated caller fails closed as `authority_required`.

### Authority

[ADR 0043](0043-instance-advisory-authority-grants.md) is the authority
decision. OD-10 stays open. This ADR does not close it and does not adopt its
interim config-gated bootstrap user or the canary `instance_operator`.

The principal is canonical lowercase `User.id` from the authenticated session.
Authority is the active instance advisory grant. `User.id` alone is not
authority. Organization membership is ignored. A lowercase UUID fits the
frozen identity check `^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`. Two different
users satisfy author ≠ reviewer, including case-folded inequality. The grant
does not receive Finding, evaluation, provider, or cross-organization read
authority.

These remain non-authority:

| Candidate | Why it is not this slice's authority |
| --- | --- |
| Organization owner, admin, member, or viewer | Membership role. Granting any of these roles instance advisory authority gives organization administration control of the global catalog. |
| `finding:create_controlled`, `finding:inspect`, `finding:discover_controlled`, `intelligence:read` | Those permissions are tenant Finding powers or sanitized status reads. |
| A new permission added to any current role | Same organization-role grant. This ADR adds none. |
| Caller-supplied `authorIdentity`, reviewer identity, or actor id | Untrusted input. The service copies the session `User.id`. |
| Email or display name | Not an authority key. |
| Git identity | [ADR 0032](0032-maintainer-reviewed-advisory-authority.md) rejects it. |
| Possession of a revision id | An identifier is not a capability. |
| `User.id` with no active instance grant | Authentication is not advisory authority. |
| `User.id` as the OD-10 instance operator | OD-10 stays open. This slice does not adopt that operator. |
| Canary `osv_canary_instance_operator_identity_v1` | Canary-scoped, production uncomposed, and not advisory authority. |

The frozen schema has no grant table. [ADR 0043](0043-instance-advisory-authority-grants.md)
requires one additive migration before these routes. This composition branch
does not add that migration and does not add an organization permission.

### Instance scope

`advisory_family` and `advisory_revision` have no organization column. That is
the instance scope. The submitted advisory is instance-owned reviewed
intelligence. It is not a tenant Finding, a tenant asset mutation, Product
Match Evidence, a Finding creation command, a repeated observation, provider
synchronization, or automatic evaluation.

Human advisory audit uses the instance-level user shape: `actor_type = user`,
`actor_user_id` set to canonical `User.id`, and null organization and
membership. Do not copy the session's active organization onto these events.
That column does not own the advisory. The advisory writer must not insert
`organization_id` onto family, revision, binding, approval, or capability
rows.

### Trusted principals and separation of duties

The application service compares canonical lowercase `User.id` from the
session, not the request body.

- The submitter `User.id` is copied into `author_identity`.
- The reviewer `User.id` must equal the capability's stored
  `reviewer_identity`.
- Comparison is exact. Leading or trailing whitespace, case-folded equality,
  and non-ASCII confusable text fail closed as `separation_of_duties_required`
  before any write. The database check is a backstop, not the public error.
- The same user through another membership, another organization, a second
  session, a changed email, a changed display name, or a body field is still
  that user. Those fields do not determine separation.
- Mutually exclusive grants are the preventive control. The `User.id`
  comparison remains the transaction-time backstop.
- A capability bound to another reviewer, revision, or fingerprint is
  `capability_rejected`.
- A replayed approval of the same stored decision is `already_applied` and
  does not issue or consume a second capability.

Document field `authorIdentity` is accepted only when it equals the canonical
submitter `User.id`. Any other value is `authority_rejected`. The body cannot
select the reviewer.

### Submission command

Future command name: `submit_maintainer_reviewed_advisory_v1`.

The body may contain only the closed document fields the admission parser
already accepts as input:

`schemaVersion`, `advisoryFamilyId`, `revisionNumber`, `vulnerabilityId`,
`aliases`, `packageEcosystem`, `packageName`, `packageUrl`, `affectedRanges`,
`withdrawal`, `supersedesRevisionId`, `sourceLicenseDecision`,
`authorIdentity`, `submissionCorrelationId`.

This slice admits only a first recorded revision: `revisionNumber` 1,
`withdrawal` `not_withdrawn`, and `supersedesRevisionId` null. Any other
lineage is `invalid_command`. Corrections remain [ADR 0032](0032-maintainer-reviewed-advisory-authority.md)
Decision 10 and are not this slice.

The command rejects caller-selected approval state, reviewer identity, approval
purpose, capability status, provider origin, synthetic origin, Product Match
Evidence, evaluator result, Finding identity, organization authority,
timestamps, audit action, persistence records, Prisma input, and transaction
callbacks. Unknown properties fail closed under the existing closed-object
admission.

The service derives origin and source `maintainer_reviewed_advisory`, content
fingerprint, range fingerprint, family digest, revision digest, replay
fingerprint, schema pins below, database timestamps, initial unapproved state,
and the submission audit action. The parser stamps origin. A caller origin is
rejected.

The license decision must canonicalize to the frozen approval literal in
`maintainer_reviewed_advisory_approval_closed_chk`. Any other license decision
is `malformed_document`. Apache-2.0, MIT, and copied provider material stay
rejected.

Before any insert, the transaction reloads `User.status` and the active
`advisory_submit_local` grant from PostgreSQL. A missing user, a disabled
user, or a missing or revoked grant is `authority_rejected` and writes
nothing. The body supplies no organization field and no principal.

### Submission persistence

One transaction writes:

- one `advisory_family` when that family digest is new;
- one `advisory_revision` with the pins below;
- alias rows and range-event rows required by the admitted document;
- one `advisory_vulnerability_binding` with schema
  `maintainer_reviewed_advisory_vulnerability_binding_v1`;
- one `vulnerability` row only when that exact `vulnerability.id` is absent;
- one audit event `intelligence.maintainer_reviewed_advisory_submitted`.

It writes no approval, capability issuance, capability consumption, Product
Match Evidence, product advisory evaluation, Finding, FindingObservation,
repeated-observation evidence, or Finding audit event.

The vulnerability row is identity provenance for the foreign key. It is not
provider acquisition and not a product binding. `vulnerability.id` is the
document UUID. On insert, `osv_id` is the derived label
`local-maintainer-reviewed:` plus that UUID. The writer inserts no
`vulnerability_source_record`, writes no `vulnerability_alias`, and does not
set `vulnerability.cve_id`.

The writer inserts that row only when the document UUID is absent. When that
id already exists, the writer reuses it only if `osv_id` equals the same
derived label, and it updates no column. Any other existing row for that id is
`immutable_conflict` and writes nothing. A colliding `osv_id` on a different id
is `immutable_conflict` and writes nothing. A caller-chosen UUID therefore
cannot attach this advisory to a provider or synthetic vulnerability row.

A CVE alias, when the admitted document has one, is stored only as an
`advisory_revision_alias` row. `alias_type` is `canonical_cve`.
`review_classification` is `unreviewed`, because the parent revision trust is
`unreviewed`. `alias_policy_version` is the frozen shape pin
`osv_advisory_alias_policy_v1`. That pin is not an OSV retrieval and not a
provider source record. `source_classification` is
`maintainer_reviewed_advisory`.

The binding uses the frozen shape pins
`one_vulnerability_id_per_product_evidence_record_v1`,
`exact_uuid_and_exact_alias_set`, `mapping_review_state` `reviewed`,
`explicit_reviewed_binding`, and `conflict_classification` `none`. Those
literals are the binding-shape check. They do not write
`product_match_evaluation_evidence`. `binding_classification` is
`provider_native_without_cve` when the admitted document has zero CVE aliases,
and `one_cve_alias_evidence` when it has one. The zero-alias name is the frozen
classification. It does not insert a provider source record.

Frozen revision pins, already enforced by check constraints:

- family schema `maintainer_reviewed_advisory_family_v1`;
- source registry `maintainer_reviewed_source_license_policy_v1`;
- revision schema `maintainer_reviewed_advisory_revision_v1`;
- parser `maintainer_reviewed_advisory_document_v1`;
- parser resource policy `canonicalization_policy_v1`;
- advisory schema `maintainer_reviewed_advisory_document_v1`;
- schema commit `not_a_provider_schema_commit`;
- retrieval policy `local_advisory_not_retrieved_v1`;
- retrieval `local_not_retrieved` / `local_retrieval_not_applicable`;
- provider generation `not_a_provider_generation`;
- ecosystem `npm`;
- evaluator version `session_14_batch_2_in_memory`;
- matching policy `osv_first_ecosystem_matching_architecture_v1`;
- `product_range_fingerprint` equal to `session14_range_fingerprint`;
- SPDX `CC-BY-4.0`;
- trust `unreviewed`;
- disposition `recorded`; withdrawal `not_withdrawn`; quarantine
  `not_quarantined`; supersedes digest `none`.

`created_at` is database time. The service does not set it from the caller.

Exact submission replay is the same canonical submitter `User.id` and the same
canonical document content for the same family id and revision number, with
agreeing content and range fingerprints. Canonical content includes the author.
`submissionCorrelationId` is not part of that content. A later request with a
different correlation id and otherwise exact content from the same submitter is
still `already_applied`. The transaction inserts, updates, and deletes nothing,
does not change timestamps, and does not write a second audit event.

Conflicting submission replay is the same family id and revision number with a
different canonical author, different canonical content, different fingerprints,
package identity, vulnerability id, aliases, or license canonical form. A
different author changes the content fingerprint and is `immutable_conflict`,
not `already_applied`. The transaction writes nothing and does not overwrite
the stored revision. A uniqueness violation is not replay until the service
re-reads and classifies the stored row. A different family or a different
revision number is not this command: this slice admits only revision 1 of a new
or exactly matching family slot.

Rollback after a revision insert writes no audit event and leaves no family,
revision, alias, range, binding, or vulnerability row from that attempt.

### Approval capability

Use the existing purpose
`approve_maintainer_reviewed_advisory_for_product_evaluation` and policy
`reviewer_approval_capability_policy_v1` version 1. Do not add a generic
approval capability.

The stored issuance already binds reviewer identity, advisory revision,
content fingerprint, affected-range fingerprint, family identity, npm package
identity, vulnerability id, license decision, purpose, capability version,
issuer authorization id, issuer decision fingerprint, and correlation id.
`issued_at` and `expires_at` are database time. The process-local presentation
handle is not a column and is not a public field.

The capability is purpose specific, single-use through the unique consumed
observation, and unusable for another revision, fingerprint, package, or
reviewer. Verification uses the existing sealed issuer. Callers cannot forge a
row by sending fingerprints or an authorization UUID.

### Capability issuance

Issuance stays behind the existing sealed issuer. That issuer is not a package
export. The approval application service is the only production boundary
permitted to call it. The reviewer cannot obtain a capability by requesting
one, and no caller-held long-lived capability is created.

Inside the approval transaction the service authenticates the reviewer,
reloads active user status, reloads the active approval grant, loads the
submitted revision, enforces separation of duties, derives fingerprints and
target facts from storage, issues one narrowly bound capability, and inserts
that issuance and consumes it before commit. The presentation handle does not
leave the transaction and is not an HTTP field.

This ADR does not authorize a public capability-minting route, a generic
issuer export, direct reviewer access to the issuer, worker issuance, seed
issuance, generic CLI issuance, or tenant-role issuance. Disposable tests may
use the existing unexported issuer harness. The API process executes the
trusted application service and is not the reviewer.

### Approval command

Future command name: `approve_maintainer_reviewed_advisory_v1`.

Required inputs are the authenticated reviewer from the session resolver, the
revision id from the path, and the fixed purpose above, which the service
supplies. The body is an empty closed object. It must not carry a capability,
a reviewer identity, or a caller-selected purpose. The body must not select
approval result, fingerprints, capability-consumption result, submission
author, timestamps, Product Match Evidence eligibility, Finding authority,
audit action, or raw persistence data.

The transaction loads the revision and binding from storage. It derives every
compared value from those rows and from the capability the service issues
inside the transaction. Path revision id must equal that capability's revision
id.

### Approval transaction

One database transaction, with no network, queue, notification, ticketing,
evaluator, provider, or AI call:

1. Validate the strict command.
2. Authenticate the reviewer. The principal is canonical lowercase `User.id`.
3. Reload `User.status` from PostgreSQL. A missing or disabled user is
   `authority_rejected` and writes nothing.
4. Reload the active `advisory_approve_for_product_evaluation` grant. Absence,
   revocation, or the wrong classification is `authority_rejected` and writes
   nothing.
5. Load the revision. Absence is `not_found` and writes nothing.
6. Require origin and source `maintainer_reviewed_advisory`.
7. Reject synthetic origin as `unsupported_origin`.
8. Reject provider-derived origin, including OSV-derived revisions, as
   `unsupported_origin`. KEV rows are not advisory revisions and are not this
   path.
9. Require stored author `User.id` ≠ reviewer `User.id`, including case-folded
   inequality. Failure is `separation_of_duties_required` and writes nothing.
10. Classify any stored approval before issuance. Continue when no approval
    exists. Exact replay is the same revision, the same purpose, the same
    canonical reviewer `User.id`, and agreeing content fingerprint, range
    fingerprint, package identity, vulnerability id, and license canonical
    form. Return `already_applied` without issuing a capability, without
    consuming a capability, and without a second audit event. A stored
    approval with a different reviewer, purpose, fingerprint, package
    identity, vulnerability id, or license canonical form is
    `immutable_conflict` and writes nothing. Step 9 still applies, so the
    revision author does not receive `already_applied`. Exact replay still
    requires the active user and active approval grant from steps 3 and 4. It
    does not require another capability consumption.
11. Derive fingerprints and target facts from the stored revision and binding.
12. Issue one narrowly bound capability through the private sealed issuer.
    Failure to issue is `capability_required` and writes nothing.
13. Validate purpose, policy version, reviewer binding, revision binding,
    content fingerprint, range fingerprint, package identity, vulnerability id,
    and license canonical form. A mismatch is `capability_rejected` and rolls
    back.
14. Treat database time greater than or equal to `expires_at` as
    `capability_expired` and roll back. Exact replay returns at step 10 and
    does not issue a capability.
15. Insert one approval using the frozen approval pins. Author identity comes
    from the revision row. Reviewer identity is the canonical `User.id`.
16. Insert one `consumed` lifecycle observation for that issuance and approval.
17. Insert one audit event `intelligence.maintainer_reviewed_advisory_approved`.
18. Re-read the approval, observation, and revision. A malformed stored row is
    `malformed_persisted_state` and rolls back.
19. Commit.
20. Return one bounded result.

Grant revocation or user disablement observed at steps 3 or 4 causes zero
approval writes. A previously committed approval remains immutable.

The revision's `trust_classification` stays `unreviewed`. Approval is the
approval row.

Concurrent approval of one revision has one winner because
`advisory_revision_id` is unique on the approval. Each attempt issues inside
its own transaction. The loser rolls back, writes nothing, and re-reads
committed state. If that state meets the exact-replay rule in step 10, the
result is `already_applied`. A different committed reviewer, purpose, or
fingerprint is `immutable_conflict`. The loser leaves no issuance. Within one
committed transaction, `capability_issuance_id` remains unique on the
observation, so that issuance is consumed once.

A capability bound to another revision, fingerprint, or reviewer is
`capability_rejected` and writes nothing. Exact replay of an approval already
recorded for the same canonical reviewer is `already_applied` and does not
issue again.

Malformed issuance or observation rows are `malformed_persisted_state` after
rollback when the transaction cannot classify them, and `capability_rejected`
when the issued capability does not meet the binding rules. Public results do
not include constraint names or raw capability state.

Failure after a capability observation insert and before the approval or audit
insert rolls back the transaction. No issuance, approval, observation, or
audit row remains.

### Replay

Submission and approval replay are defined above. Do not treat every unique
violation as replay. Classify only after reading the stored row inside the
same transaction. A conflict writes nothing. An exact replay writes nothing
and does not refresh `created_at`, `issued_at`, `expires_at`, or `observed_at`.

Commit uncertainty is the same classification. If the caller does not observe
whether the first attempt committed, the retry re-reads the stored revision or
approval. Exact stored state returns `already_applied` and writes nothing. A
conflict returns `immutable_conflict` and writes nothing. The retry does not
insert a second family, revision, binding, vulnerability, issuance, approval,
observation, or audit row.

### Origin

Accept only origin and source `maintainer_reviewed_advisory`. Reject
`synthetic_fixture`, `provider_derived`, `unrecognized`, OSV source enums,
CISA KEV records, and any caller-selected origin. Do not relabel provider or
synthetic rows. Provider quarantine and review rules on those origins stay as
they are. The Session 15 adapter continues to reject maintainer-reviewed
origin; the new writer is separate and accepts only that origin.

### Product binding boundary

This slice writes `advisory_vulnerability_binding` because the frozen approval
row requires it and [ADR 0032](0032-maintainer-reviewed-advisory-authority.md)
Decision 7 binds one `Vulnerability.id`. That binding is vulnerability-identity
provenance. It does not select a Product Match Evidence outcome, run version
evaluation, bind an occurrence, bind an asset, or create a Finding.

`product_match_evaluation_evidence` is not written. Product Match Evidence
generation stays uncomposed. Approval creates later evaluation eligibility
only.

### Audit events

Exactly two actions:

- `intelligence.maintainer_reviewed_advisory_submitted`
- `intelligence.maintainer_reviewed_advisory_approved`

`subject_type` is `advisory_revision`. `subject_id` is the revision UUID.
`schema_version` is 1. `actor_type` is `user`. `actor_user_id` is the
authenticated `User.id`. Organization and membership are null. Until the
routes exist, no event is written.

Submission payload may include revision id, document schema version
`maintainer_reviewed_advisory_document_v1`, origin
`maintainer_reviewed_advisory`, fingerprint classification `sha256`, and the
submitter principal id. Approval payload may include revision id, the approval
purpose, the capability issuer authorization UUID, and the reviewer principal
id.

Payloads omit the advisory document, vulnerability description, package ranges,
capability secrets and seals, credentials, raw reviewer assertions, provider
bodies, SQL, database internals, Product Match Evidence ids, and Finding ids.
`correlationId` is required. The first submission event uses the admitted
`submissionCorrelationId`. The first approval event uses the request
correlation id. The payload object includes `schemaVersion` 1, which the
frozen `audit_event_payload_schema_chk` requires, in addition to column
`schema_version` 1. Exact replay writes no second event even when a later
request carries a different correlation id. A uniqueness violation is not
replay until the stored row is re-read and classified. Rollback writes no
event. Update and delete of audit rows stay forbidden.

### Error taxonomy

Public envelope stays `error.code`, `error.message`, `error.requestId`, and
`error.correlationId`, with `Cache-Control: private, no-store`. Messages are
fixed sentences. They do not include SQL, constraint names, secrets, stack
traces, database URLs, or internal capability state.

Submission outcomes: `submitted`, `already_applied`, `invalid_command`,
`authority_required`, `authority_rejected`, `immutable_conflict`,
`unsupported_origin`, `malformed_document`, `database_unavailable`,
`transaction_aborted`, `internal_failure`.

Approval outcomes: `approved`, `already_applied`, `invalid_command`,
`authority_required`, `authority_rejected`, `not_found`,
`separation_of_duties_required`, `capability_required`, `capability_rejected`,
`capability_expired`, `immutable_conflict`, `unsupported_origin`,
`malformed_persisted_state`, `database_unavailable`, `transaction_aborted`,
`internal_failure`.

`not_found` covers an absent revision. It does not distinguish a foreign
tenant resource, because these rows are not tenant-owned. `unsupported_origin`
is used only after the row is loaded and its origin is not the local origin.
Limiter failure and database unavailability fail closed. They are not success.

HTTP mapping for a later implementation: `submitted` and `approved` are 201;
`already_applied` is 200; `invalid_command`, `malformed_document`, and
`unsupported_origin` are 400; `authority_required` is 401;
`authority_rejected`, `separation_of_duties_required`, `capability_required`,
`capability_rejected`, and `capability_expired` are 403; `not_found` is 404;
`immutable_conflict` is 409; `database_unavailable`, `transaction_aborted`,
`malformed_persisted_state`, and `internal_failure` are 503. Rate limit is
429 with the existing authentication rate-limit error.

### API successor

After `feat/instance-advisory-authority-foundation` merges, compose exactly
two cookie-authenticated mutation routes in the API process:

- `POST /intelligence/maintainer-reviewed-advisories`
- `POST /intelligence/maintainer-reviewed-advisories/:revisionId/approval`

The `/intelligence` prefix matches the existing provider-status routes. These
routes are registered outside that status plugin's actor helper. The helper
requires an active organization and `intelligence:read`. These routes must not
call it, must not require an active organization, and must not require an
organization permission. A resolved active user with null organization,
membership, and role is sufficient authentication. Authority is the instance
grant. These routes are deliberate, single-revision, and non-automatic. They
accept `application/json` only. They reject a query string, GET, and form
bodies. Body limit is 65536 bytes, the existing `DOCUMENT_MAX_UTF8_BYTES`.
They require
the current synchronizer CSRF token, a single browser `Origin` that passes
`exactOriginAllowed` against configured allowed origins, and credentials.
Clients cannot override Origin. There is no web UI in this slice.

Do not register the routes before the grant relation exists. Do not register
them in the authority-foundation branch.

### Permission model

Do not add an organization permission for this slice. Organization membership
is not the grant. Advisory audit events leave organization and membership
null.

Who may submit: an authenticated active user with an active
`advisory_submit_local` grant. No membership is required.

Who may request or receive a capability: nobody through HTTP. The approval
service calls the sealed issuer inside the approval transaction and names the
reviewer from the session `User.id`. The reviewer cannot mint one.

Who may approve: an authenticated active user with an active
`advisory_approve_for_product_evaluation` grant, whose canonical `User.id`
equals the internally issued capability's `reviewer_identity`, and who is not
the submitter.

Who may inspect submission status: nobody. This slice has no read route. The
mutation response returns only `revisionId` and the outcome code.

### Rate limiting

Each mutation route, once registered, uses its own process-local direct-peer
limit of 5 requests per 60 seconds. That matches `FINDING_CREATION_PEER_LIMIT`,
the strictest existing deliberate-mutation peer limit. The limiter runs on
`onRequest` before session resolution, uses `selectDirectPeerIp` on
`socket.remoteAddress`, and does not read `X-Forwarded-For`. An unknown peer
shares one bounded bucket. `skipOnError` is false. Excess requests return 429.
Limiter failure fails closed. There is no Redis store, no rate-limit migration,
and no key that includes the revision id. Several API processes multiply the
ceiling. That multiplication is an accepted residual. Restarting the process
clears the window. There is no organization bucket: an organization bucket
would treat tenant scope as advisory authority.

### Confidentiality

Public success bodies return the revision UUID and the outcome code. That UUID
is safe to return to the caller who submitted or approved it. Do not return
capability secrets, seals, presentation handles, full fingerprints, reviewer
credentials, the advisory document, package ranges, provider internals, SQL,
constraint names, stack traces, database URLs, Product Match Evidence, or
Finding details. Logs follow the same omission list.

### Production composition and zero downstream authority

Future composition is API-process only, and only after the authority-foundation
branch has merged. Do not compose the commands in the
worker, scheduler, queue, Outbox, BullMQ, ingestion, evaluator, provider
synchronization, CLI, seed, migration, health, readiness, or web server.

No SBOM ingestion path may call them. Approval does not evaluate a
ComponentOccurrence, generate Product Match Evidence, discover Finding targets,
create a Finding, record a repeated observation, close or reopen a Finding,
verify remediation, activate OSV, contact a provider, or run a scheduler.

### Schema sufficiency

**Advisory storage is sufficient. The grant relation is a predecessor
migration, not a migration in this composition branch.**

The 25 frozen migrations already enforce the revision pins, the approval
purpose, distinct author and reviewer identities, capability expiry, one
terminal observation per issuance, unique replay fingerprints, and append-only
guards on approval, capability, and audit tables. `vulnerability.id` can be the
document UUID. This composition branch adds no column, enum value, or foreign
key.

[ADR 0043](0043-instance-advisory-authority-grants.md) requires one additive
grant migration on `feat/instance-advisory-authority-foundation`. That
migration raises the frozen count from 25 to 26 only on that branch. This
composition branch does not create it and does not run before it merges.

```text
Current frozen migration count: 25
Future authority-foundation count: 26
```

Do not flip `trust_classification` to `reviewed`. The frozen check forbids it.
Do not add an organization column to advisory rows. Do not add a user foreign
key on `author_identity`. Canonical `User.id` is stored in the existing ASCII
identity columns.

### Dependency intent

No new dependency. Fingerprints stay on the existing SHA-256 canonical helper.
Capability sealing, document admission, and the PostgreSQL transaction helpers
already exist. Do not add a provider SDK, a queue, a scheduler, a form parser,
a workflow engine, or a new cryptographic package.

### Scenarios

**A. First valid submission.** A future trusted submitter sends one valid local
document. One transaction inserts the family, revision, provenance, binding,
vulnerability row when absent, and one submission audit event. Outcome
`submitted`. No approval, capability, Product Match Evidence, or Finding row.

**B. Exact submission replay.** The same principal resubmits the same document.
Outcome `already_applied`. Zero writes. Timestamps unchanged.

**C. Conflicting submission replay.** The same family and revision number arrive
with different content. Outcome `immutable_conflict`. Zero writes.

**D. Independent approval.** A different active user, holding only the approval
grant, approves the stored revision. The service issues and consumes one
capability in that transaction. Outcome `approved`. The revision trust stays
`unreviewed`.

**E. Self-approval.** The submitter calls approval. Outcome
`separation_of_duties_required`. Zero writes, including zero issuance.

**F. Expired capability.** Database time is greater than or equal to
`expires_at` for a capability the service just issued. If no exact approval is
stored, outcome `capability_expired` and zero writes. If the exact approval is
already stored, outcome `already_applied` and zero writes, including zero new
issuance.

**G. Concurrent approval.** Two approval commands target the same revision.
One commits its issuance, approval, consumption, and audit event. The other
rolls back and returns `already_applied` or `immutable_conflict` from the
committed row. The loser leaves no issuance.

**H. Synthetic origin.** A synthetic document or a stored synthetic revision
takes this path. Outcome `unsupported_origin` or `malformed_document`. Zero
writes. No relabel.

**I. Provider-derived origin.** An OSV-derived or other provider revision takes
the approval path. Outcome `unsupported_origin`. Zero writes. KEV is not
accepted on this path.

**J. Approval exact replay.** The same active reviewer approves the same stored
revision again. Outcome `already_applied`. No second issuance, no second
consumption, and no second audit event. A different reviewer is
`immutable_conflict`. The author is `separation_of_duties_required`.

**K. Failure during approval.** A forced failure after the observation insert
and before approval or audit rolls back. Zero issuance, approval, observation,
and audit rows remain.

**L. Downstream evidence check.** After A and D, Product Match Evidence count
and Finding count for that revision are unchanged. No evaluator runs.

### PostgreSQL evidence the implementation must add

Disposable PostgreSQL, with no provider network, must show zero extra writes
for each rejected case:

- first submission inserts one revision, provenance, binding, and one audit
  event;
- exact submission replay inserts nothing;
- conflicting submission inserts nothing and leaves the original bytes and
  timestamps;
- the revision row cannot be updated;
- first approval inserts one issuance, one approval, one consumed
  observation, and one audit event;
- a disabled user or a missing or revoked grant inserts nothing, including
  no issuance;
- a different author for the same family and revision inserts nothing;
- a different submission correlation id with the same canonical content and
  the same author inserts nothing, including no second audit event;
- an existing vulnerability id whose `osv_id` is not the local label inserts
  nothing;
- self-approval, a different reviewer against a stored approval, wrong
  revision, wrong fingerprint, wrong purpose, and expired capability insert
  nothing;
- concurrent approval yields one consumed row and no loser issuance;
- exact approval replay inserts nothing, including no second issuance;
- conflicting approval inserts nothing;
- synthetic and provider origins insert nothing on this path;
- rollback after the revision insert leaves no revision and no audit event;
- rollback after the capability observation insert leaves no issuance, no
  observation, no approval, and no audit event.

## Alternatives considered

- **Compose Product Match Evidence next.** Rejected for this slice. The
  evaluation command has no production source of a reviewed local revision, so
  a normal installation would still be evidence starved.
- **Enable OSV acquisition.** Rejected. Provider origin is not maintainer
  review, and production OSV remains disabled.
- **Let organization owners submit and approve.** Rejected. That grants global
  advisory authority to tenant administration and collapses separation of
  duties into a role.
- **Use the canary instance operator.** Rejected. That identity is not a
  production console and is not advisory authority.
- **Use `User.id` as the OD-10 instance operator.** Rejected.
  [ADR 0043](0043-instance-advisory-authority-grants.md) uses canonical
  `User.id` as the advisory principal of a durable grant. It does not adopt
  the operator console, and OD-10 stays open.
- **Use `User.id` with no grant.** Rejected. Authentication is not advisory
  authority.
- **Flip revision trust to `reviewed` on approval.** Rejected. The frozen check
  pins this origin to `unreviewed`. The approval row is the approval.
- **Skip the vulnerability binding.** Rejected. The approval foreign key and
  trigger require it. The binding is not Product Match Evidence.
- **Add the grant migration in this composition branch.** Rejected. Advisory
  storage is sufficient here. The grant migration belongs to the predecessor
  authority-foundation branch.
- **Require a separate human capability issuer.** Rejected. The approval
  service issues and consumes the capability inside one transaction.

## Consequences

The Finding workflow stays evidence starved until both implementation branches
merge. This acceptance does not implement either branch. The frozen migration
count remains 25 until the authority-foundation migration raises it to 26.
Approval remains necessary and insufficient for evaluation and Finding
creation.

The negative consequence is operational: a self-hosted installation still
cannot submit a local advisory until the grant command has been run for two
existing users and the advisory routes exist. That is intentional. No
organization role becomes a fallback.

## Security and tenancy

Instance-owned advisory rows stay globally unscoped by organization. Tenant
Finding authority is unchanged. No secret, token, or provider body is logged.
No outbound fetch is added. CSRF, Origin, and direct-peer rate limits match
existing mutation routes. Self-approval fails closed. Exact replay is not a
second grant.

One human can control two `User` accounts. Canonical `User.id` comparison
cannot see that. Mutually exclusive grants stop one account from holding both
authorities. They do not stop two accounts. This slice adds no identity
proofing. Operators must not knowingly grant the two authorities to accounts
controlled by one person. The deployment operator who can run the grant
command can assign those accounts. That residual is accepted in
[ADR 0043](0043-instance-advisory-authority-grants.md). There is no
organization-role fallback.

## Operational failure plan

Until the routes exist, there is no operator procedure. After they exist, a
failed transaction leaves the previous committed revision or approval in place.
Operators detect failure from the public outcome and the request id. They do
not repair advisory rows in place. A conflicting document requires a later
revision slice, not an update. Database unavailability returns
`database_unavailable` and does not partially commit. There is no queue to
drain and no poison message.

## Follow-up

- This ADR is Accepted together with
  [ADR 0043](0043-instance-advisory-authority-grants.md). Acceptance does not
  implement the grant relation or these routes.
- Open `feat/instance-advisory-authority-foundation` first. It does not mount
  advisory routes.
- Open `feat/maintainer-reviewed-advisory-production-composition` only after
  that branch merges. It adds the two API-process commands, internal
  capability issuance and consumption, and the disposable PostgreSQL evidence
  above. It adds no migration and no web UI.
- Product Match Evidence composition, evaluator activation, provider
  acquisition, repeated-observation writes, observation history, and Finding
  lifecycle remain deferred.
