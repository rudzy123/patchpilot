# ADR 0044: Deliberate Product Match Evidence evaluation

- Status: Accepted
- Date: 2026-10-15
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the governance decision for one future, owner-initiated, API-only
operation that turns one approved local maintainer-reviewed advisory revision and
one tenant asset's latest successful SBOM ingestion into immutable Product Match
Evidence. Merge to `main` remains subject to normal pull-request review. This ADR
does not implement the operation. It adds no permission constant, domain contract,
application service, PostgreSQL adapter, route, web UI, worker, queue, scheduler,
Outbox row, migration, dependency, or evidence row. It does not compose the
evaluator, generate Product Match Evidence, create a Finding, or record an
observation. Migration count remains 26.

## Context

Repository truth at the start of this decision (`main` at the merge of pull request
#93) is as follows. Each statement was checked against committed code, the frozen
schema, and the frozen migrations. Where the roadmap review differed, the
correction is recorded in the next section.

- Maintainer-reviewed advisory submission and independent approval are reachable
  only through two API routes ([ADR 0042](0042-maintainer-reviewed-advisory-production-composition.md),
  [ADR 0043](0043-instance-advisory-authority-grants.md)). Approval is eligibility
  for a later explicit evaluation. It is not an evaluation, not Product Match
  Evidence, and not Finding authority. `MaintainerReviewedAdvisoryApproval` is
  unique per `advisory_revision_id`, so a revision has at most one approval.
- `product_match_evaluation_evidence` (migration
  `20261002180000_product_match_evaluation_evidence`) is append-only, tenant scoped,
  and replay protected. One row is one `ComponentOccurrence` evaluated against one
  advisory revision ([ADR 0033](0033-product-match-evidence-cardinality.md)). The
  natural identity is organization, occurrence, advisory revision, approval,
  evaluator id and version, matching policy id and version, and product-evidence
  policy id and version (`product_match_evaluation_evidence_evaluation_uidx`). A
  second unique key is `(organization_id, replay_fingerprint)`.
- The outcome enum is `affected`, `unaffected`, `unknown`. There is no
  `component_absent` value in the enum, the evidence schema, the evaluator result
  model, or the discovery SQL.
- The evidence insert guard
  (`patchpilot_product_match_evaluation_guard`) requires `version_known` to be true
  on the occurrence for every row, including `unknown` rows. It re-checks occurrence
  and component agreement, npm ecosystem, revision admissibility, successor absence,
  approval agreement, Vulnerability binding agreement, and range evidence presence.
  It does not check ingestion state, normalization version, or the asset pointer.
- The closed check pins `evaluator_id = osv_first_ecosystem_affected_version_evaluator_v1`,
  `evaluator_version = session_14_batch_2_in_memory`,
  `matching_policy_id = matching_policy_version = osv_first_ecosystem_matching_architecture_v1`,
  `product_evidence_policy_id = product_match_evaluation_policy_v1`, version `1`,
  `product_origin = maintainer_reviewed_advisory`, `finding_creation = unavailable`,
  and `suppression_authority = false`. The same literals appear in the controlled
  Finding creation qualifying SQL, the repeated-observation SQL, and code.
- `createProductMatchEvaluationComposition`, the evaluator
  `evaluateReviewedNpmRange`, the registry gate `admitReviewedNpmProductRegistry`,
  and the Prisma persistence adapter exist. No app imports them.
  `source-boundary.test.ts` proves API, worker, and web runtime roots do not
  construct them. Production composition is absent.
- The low-level command operates on one occurrence. It expects caller-supplied
  internal identity and fingerprint facts and a UUID v4 `correlationId`. Its
  PostgreSQL `commit` opens its own transaction, locks only the occurrence row, and
  writes no actor and no audit event.
- Controlled Finding discovery (`GET /assets/:assetId/controlled-finding-targets`)
  reads the asset's `last_successful_sbom_ingestion_id` and evidence for that
  ingestion. `patchpilot_finding_creation_qualifying_evidence` qualifies `affected`
  evidence when the ingestion is `completed` with normalization version `2`, the
  occurrence is `version_known`, the asset still points at that ingestion, and the
  revision is a not-withdrawn, not-quarantined tip with a reviewed, unconflicted
  binding and an approval with the evaluation purpose. Newly written affected
  evidence that satisfies those predicates is consumed by discovery without a
  further change. With no evaluation writer, discovery is evidence starved.
- No advisory listing, advisory read route, withdrawal writer, quarantine writer,
  or supersession writer exists. Instance advisory authority reaches the API only
  for submission and approval.
- The existing audit table is append-only. Tenant events are unique on
  `(organization_id, action, subject_id, correlation_id)`. No action allowlist
  rejects a new action name, and no database trigger links evidence inserts to an
  audit row. [Audit model](../architecture/audit-model.md) and
  [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) already
  reserve `vulnerability.match_evaluated` as a bounded per-job aggregate.

### Corrections to the roadmap review

The roadmap review was directionally correct. Checking it against code changed
these points. Each is binding in the decision below.

1. The existing evidence writer cannot be reused as is. It opens its own database
   transaction per occurrence, so it cannot give one atomic multi-occurrence
   commit, and it takes neither the asset pointer lock nor an actor. The
   implementation must extract a transaction-scoped core without changing the
   behavior or tests of the existing single-occurrence command.
2. The asset pointer is written by ingestion completion under
   `pg_advisory_xact_lock(hashtextextended('<organizationId>:<assetId>', 0))` and
   `asset ... FOR UPDATE`. Controlled Finding creation takes the same two locks in
   the same order. The evaluation transaction must take that same pair first.
   Taking the membership lock before the asset lock would deadlock against creation.
3. The command parser requires `correlationId` to be a UUID v4. The HTTP
   correlation identifier is any bounded safe identifier, not necessarily a UUID.
   The two are different values (see section 11).
4. `assessProductMatchEligibility` combines component and advisory checks and also
   admits a `superseding` tip. The service needs an advisory-only eligibility
   assessment, so an ineligible advisory cannot be masked by "no relevant
   occurrence". The first slice admits only `recorded` revisions with no
   supersession.
5. The evidence guard rejects `version_known = false` for every outcome. A
   versionless occurrence therefore cannot become an `unknown` row. It is skipped
   and counted (section 7).
6. No database trigger enforces that evidence insert implies an audit row. Audit
   atomicity is an application and adapter guarantee that integration tests must
   prove. A deferred constraint trigger would need migration 27 and is not
   authorized.
7. The matching-policy version literal equals the matching-policy id string. That
   is cosmetic and frozen (section 8).
8. Organization owners have no way to learn an advisory revision identifier from
   PatchPilot. No advisory listing exists. The revision identifier reaches the
   owner out of band from the instance maintainer who submitted and approved it.
9. `docs/project/current-state.md` carried stale wording, including "the pull
   request is next" for merged pull request #93. It is reconciled with this ADR.

## Decision

PatchPilot accepts one future bounded production operation, **deliberate Product
Match Evidence evaluation**:

> one approved local maintainer-reviewed advisory revision
> × one organization-scoped asset
> × that asset's transactionally derived latest successful SBOM ingestion
> → bounded deterministic evaluation of the matching npm occurrences
> → immutable Product Match Evidence, committed atomically with one bounded audit
> event.

The operation is a protected, synchronous, owner-initiated API command. It is
evidence only. It creates no Finding, no observation, no risk or priority value, no
assignment, and no lifecycle transition.

### 1. Why this slice comes first

The roadmap review selected this slice because it is the smallest step that makes
every already-built layer reachable, and because every alternative either needs this
slice's decisions or widens authority:

| Deferred alternative | Why it follows this slice |
| --- | --- |
| Automatic ingestion-triggered evaluation | Needs the same occurrence selection, skip-versus-abort rule, audit, and replay semantics, plus a `system` actor and Outbox idempotency. Doing it first would invent those rules without an operator-reviewed baseline. |
| Worker evaluation | Needs a durable job identity, an Outbox row, and an accepted `system` audit actor. The first slice has none of that and is bounded enough not to need it (section 15). |
| All-advisory evaluation | Unbounded by advisory count. One advisory per request keeps work and blast radius bounded. |
| All-asset evaluation | Unbounded by asset count and a bulk write across tenants' assets. One asset per request keeps work bounded and authority per asset. |
| Provider acquisition (OSV) | Production OSV acquisition is disabled. This slice needs no provider and must not create pressure to enable one. |
| Repeated-observation reachability | Observation requires an existing Finding. Findings require qualifying evidence. Evidence is the missing input. |
| Finding navigation, list, or observation history | Read surfaces over Findings that exist only after evidence exists. Navigation to a Finding the product cannot yet reach is premature. |
| Finding lifecycle | Depends on all of the above and is a separate authority decision. |

The slice also removes the evidence starvation of the controlled Finding workflow
(`GET /assets/:assetId/controlled-finding-targets`, the nested web workflow, and
`POST /findings`) without adding any Finding capability.

### 2. Actor, permission, and role mapping

**Production actor.** An authenticated organization owner acting through the
existing cookie session with an active membership in the active organization.

**Owner only.** The roadmap recommendation is accepted after checking permission
conventions in `packages/auth/src/permissions.ts` and
[ADR 0036](0036-controlled-finding-operator-api.md):

- Durable, immutable, tenant-scoped writes that feed controlled Finding creation
  are owner-only today (`finding:create_controlled`). Admin receives read-side
  inspection and discovery only.
- Admin permissions are administrative: membership, team, asset, policy, and
  integration management. None of them is an evidentiary write authority, and
  admins do not hold `risk_acceptance:approve`.
- Evidence rows cannot be updated or deleted. An erroneous write is permanent
  evidentiary history. That is closer to Finding creation than to inspection.
- The product is usable with one owner. Requiring the owner for the evidence write
  does not block the owner-and-admin read workflow. An admin can still discover and
  inspect evidence an owner generated.

**Permission.** One new tenant permission, named by the existing
`resource:verb_controlled` convention (`finding:create_controlled`,
`finding:discover_controlled`):

| Permission | Meaning |
| --- | --- |
| `product_match:evaluate_controlled` | Call the one evaluation route for one asset and one approved advisory revision |

Role mapping:

| Role | `product_match:evaluate_controlled` |
| --- | --- |
| owner | yes |
| admin | no |
| member | no |
| viewer | no |

Binding statements:

- The permission is tenant scoped. It is derived from the active membership role
  by server-side mapping.
- Authority derives from the authenticated trusted actor and the active membership.
  The service reloads User status, active membership, role, and organization status
  from PostgreSQL inside the transaction. Any mismatch with the session actor is
  `authority_rejected` with zero writes.
- Organization derives only from the actor. The request accepts no organization
  identifier. A body, query, header, or path organization field is rejected or
  ignored for authority.
- Instance advisory grants (`advisory_submit_local`,
  `advisory_approve_for_product_evaluation`) do not grant this permission, tenant
  asset access, or an organization role.
- Organization roles and this permission do not grant instance advisory submission
  or approval authority. [ADR 0043](0043-instance-advisory-authority-grants.md)
  stays the only source of that authority.
- `finding:create_controlled`, `finding:discover_controlled`, `finding:inspect`,
  `finding:triage`, `finding:read`, `asset:manage`, and `intelligence:read` do not
  substitute for it. It does not grant any of them.
- No caller-selected role, permission, session, membership, or actor is accepted.
- The permission is added to the catalog only by the implementation branch.
  Widening it to admin requires a later permission review.

### 3. Tenant isolation

- Every tenant-owned read and write carries the actor's organization as a
  predicate: asset, ingestion, occurrence, component, SBOM, and evidence. A lookup
  by identifier alone is not authorization.
- A foreign asset and an absent asset are publicly indistinguishable: both return
  the same `not_found` response before any advisory work occurs.
- The advisory revision, approval, binding, and range events are shared instance
  catalog data, not tenant-owned. They are read without an organization predicate
  and never returned. Evidence derived from them is tenant owned.
- **Approval publishes the advisory to tenant evaluation.** An approved revision may
  be evaluated by the owner of any organization on the instance that holds the
  revision identifier. The response reveals counts only, but repeated evaluation
  against a tenant's own SBOM versions is an oracle for range membership. This is
  accepted: advisory content is maintainer-reviewed under an accepted source
  license, and approval is the instance maintainer's decision to make the advisory
  usable by tenants. Instances that need confidential advisories need a later
  decision.
- Object-storage keys, job payloads, webhook bodies, and request bodies are not
  organization proof. The operation has no object-storage I/O.

### 4. Approved-advisory eligibility envelope

The advisory revision is eligible only if the committed rows satisfy all of the
following. The service reloads them inside the transaction. The existing
`assessProductMatchEligibility` rules are reused. The first slice is stricter than
that function where noted.

- Origin and source are the local `maintainer_reviewed_advisory` origin. Synthetic,
  KEV, and unrecognized origins are rejected. KEV is never affectedness authority.
- Exactly one independent approval exists for the revision, with purpose
  `approve_maintainer_reviewed_advisory_for_product_evaluation`, the accepted
  approval policy id and version, reviewer classification, and source classification.
- Author and reviewer are distinct, and the approval author equals the revision
  author.
- The accepted license decision is `CC-BY-4.0` with the accepted source-license
  policy and canonical decision.
- The approval, revision, and binding agree on family, content fingerprint, range
  fingerprint, package identity, and `Vulnerability.id`.
- The Vulnerability binding is `reviewed`, the exact mapping method and policy, and
  has no conflict.
- The alias envelope and range-event envelope are complete and the recomputed Session
  14 range fingerprint matches.
- The package identity is a legal npm identity supported by the pinned evaluator.
- The revision is not withdrawn, not quarantined, and has no successor.
- **First-slice narrowing.** The revision disposition must be `recorded` with no
  supersession digest. The existing eligibility function also admits a `superseding`
  tip. No superseding writer exists, and superseding revisions are deferred, so the
  service rejects them as ineligible.

**Approval stays authoritative after authority changes.** Evaluation validates the
immutable approval lineage. It does not recheck the present account status or
present instance grants of the submitter or reviewer. This matches
[ADR 0043](0043-instance-advisory-authority-grants.md) ("Grant revocation removes
advisory authority prospectively. It does not ... invalidate a previously committed
approval"), [ADR 0042](0042-maintainer-reviewed-advisory-production-composition.md),
and the immutable approval persistence. Later User disablement or grant revocation
does not invalidate an approval. This ADR introduces no approval revocation.
Neutralizing an approved advisory after the fact is the job of a withdrawal or
quarantine writer, which does not exist and is deferred (accepted residual risk R-1).

The caller never supplies the approval identifier, fingerprints, vulnerability,
evaluator, or policy. The service derives the approval from the unique
`advisory_revision_id` relation and derives all expected facts from the
transaction's own reloaded rows.

### 5. Request target and server derivation

Exactly one route (section 13) with `assetId` in the path and `advisoryRevisionId`
in the body. The request accepts nothing else. In particular it rejects:
organization identifier, ingestion identifier, occurrence identifier, Product,
Component, package, version, evaluator, policy, fingerprints, authority, approval
state, and provider input.

The service derives:

| Fact | Source |
| --- | --- |
| Organization | The trusted actor's active membership |
| Asset | `asset` where `organization_id` is the actor's organization and `id` is the path value |
| Ingestion | `asset.last_successful_sbom_ingestion_id`, read under the asset row lock |
| Approval | The unique approval for the advisory revision |
| Occurrences | Organization, ingestion, and the advisory package identity (section 6) |
| Expected fingerprints and identities | The transaction's own reloaded rows, passed to the existing command parser and eligibility function |

The ingestion must be present, `completed`, normalization version `2`, and the
asset's current pointer under the transaction's locks. No pointer: `no_successful_ingestion`.
Pointer present but ingestion not `completed`, not version `2`, or not in the asset:
`ingestion_not_evaluable`. Normalization version `1` graphs are never evaluated and
are not reprocessed ([ADR 0034](0034-multi-version-component-occurrence-normalization.md)).

### 6. Occurrence selection and capacity

- Ecosystem is npm only.
- Package identity comes from the eligible advisory revision (namespace and name),
  never from the request.
- Only the derived ingestion is searched, scoped by organization and asset.
- Matching uses the existing npm identity classification
  (`classifyNpmPackageIdentityFromParts`). The query pre-filters on component
  ecosystem, namespace, and name equality. The existing eligibility function
  re-asserts the canonical identity key. No new case folding or normalization is
  introduced.
- Order is `component_occurrence.id::text COLLATE "C"` ascending. This matches the
  deterministic ordering convention in controlled Finding discovery.
- **Cap: 16 selected occurrences.** The query selects up to 17 rows. A 17th row
  yields `capacity_exceeded`.

Cap rationale:

- `finding_creation_policy_v1` limits one creation evidence set to 16 Product Match
  Evidence identities. One creation set is the affected evidence of one
  `(asset, component, vulnerability, ingestion)` tuple, which is one row per distinct
  observed version of one component. Writing more than 16 rows for one package would
  create evidence that controlled Finding creation could never use.
- Occurrence identity is `(organization, ingestion, component, version)`, and one
  organization has one `Component` per npm identity key. The selected set is
  therefore the distinct observed versions of one package. Realistic counts are one
  to a few. SBOM component limits (default 10,000) are not the relevant bound.
- At most 16 inserts, each with at most 8 explanation rows, plus 16 evaluator calls
  fit well inside the transaction budget in section 9.
- A larger cap increases lock hold time and abuse surface without producing usable
  evidence.

The cap counts every selected occurrence, including ones later skipped. It is part of
the operation policy (section 8) and may be raised only by a new operation-policy
version.

**Overflow.** More than 16 selected occurrences returns `capacity_exceeded` with
zero evidence writes and zero audit rows. The set is never silently truncated.

**No relevant occurrence.** Zero selected occurrences returns
`no_relevant_occurrence`: zero writes, zero audit rows. It states that no npm
occurrence of the advisory's package identity exists in the asset's latest
successful ingestion. It is not `unaffected`, not component absence, and not a graph
completeness claim. No evidence row represents it.

### 7. Per-occurrence classification: persist, skip, or abort

The operation is deterministic and auditable. Expected, benign states are skipped
individually and counted. Integrity violations abort the whole request with zero
writes. There is no silent omission: every selected occurrence is accounted for in
exactly one counter.

| Case | Decision | Result |
| --- | --- | --- |
| Known, strictly valid SemVer inside a reviewed range | Persist | `affected` row |
| Known, strictly valid SemVer outside every reviewed range | Persist | `unaffected` row |
| Known version the evaluator cannot decide: invalid observed version, unsupported SemVer syntax, numeric capacity exceeded, unsupported range type or event, contradictory events, incomplete evidence, internal evaluator failure | Persist | `unknown` row with the evaluator's closed explanation codes |
| `version_known = false` | Skip | counted as `version_not_known`, no row |
| Empty version, a version the command parser rejects (prohibited control characters), or a version over 256 UTF-8 bytes | Skip | counted as `version_unrepresentable`, no row |
| Occurrence already has exact evidence (same natural identity and replay body) | Replay | counted as replayed, no insert |
| Existing row with the same natural identity but a different replay body, or a malformed or non-matching stored row | Abort | `immutable_conflict` (changed body) or `malformed_persisted_state`, zero writes |
| Selected component whose identity state is not `resolved`, whose canonical npm identity is invalid or differs from the advisory identity, or whose stored fields are inconsistent | Abort | `malformed_persisted_state`, zero writes |
| Occurrence, SBOM, or component rows that fail the existing snapshot checks (missing SBOM hash, empty name, null ecosystem) | Abort | `malformed_persisted_state`, zero writes |
| Any advisory-level ineligibility | Abort | `advisory_not_eligible`, zero writes |
| Evidence guard, foreign-key, or check-constraint failure on insert | Abort | `transaction_aborted`, zero writes |

Rationale for skipping the two benign cases: a versionless occurrence is a legal
normalized state ([ADR 0034](0034-multi-version-component-occurrence-normalization.md))
and an untrusted SBOM can carry unrepresentable version strings. Aborting on them
would let one such component or one hostile document block evaluation for the whole
asset until the next SBOM, with no operator remedy. The evidence schema cannot
represent them, so fabricating `unknown` or `unaffected` evidence for them is
forbidden. They are reported only as bounded counts, with no version text.

A known but unparsable version is different: the evaluator represents it as
`unknown`, the schema stores it, and discovery ignores it. `unknown` is never
`unaffected`.

If every selected occurrence is skipped, the result is `no_evaluable_occurrence`:
zero writes, zero audit rows, and it is not `unaffected`.

### 8. Evaluator and policy pins

Only the existing admitted reviewed npm evaluator and current policy identities are
used:

| Identity | Value |
| --- | --- |
| Evaluator id | `osv_first_ecosystem_affected_version_evaluator_v1` |
| Evaluator version | `session_14_batch_2_in_memory` |
| Matching policy id | `osv_first_ecosystem_matching_architecture_v1` |
| Matching policy version | `osv_first_ecosystem_matching_architecture_v1` |
| Product-evidence policy id and version | `product_match_evaluation_policy_v1`, `1` |
| Evidence schema | `product_match_evaluation_evidence_v1` |
| Origin | `maintainer_reviewed_advisory` |

**Historical evaluator label accepted unchanged.** The version string
`session_14_batch_2_in_memory` is a frozen historical identity token, not a claim
that production composition is absent and not a claim about the evaluator's
implementation status. It is pinned in the evidence closed check, the controlled
Finding creation and repeated-observation SQL, and code. Changing it requires a
separate ADR, a new migration, and a discovery and creation SQL update, none of which
this slice needs. The `matching_policy_version` literal that equals the policy id is
likewise cosmetic and frozen.

Not authorized: another ecosystem, another evaluator, another policy version,
provider evaluation, dynamic registry selection, or any caller-selected evaluator or
policy. The registry gate `admitReviewedNpmProductRegistry` stays the closed
admission check. The active Session 15 registries stay empty.

The operation has its own **operation policy**,
`deliberate_product_match_evaluation_policy_v1` version `1`. It carries the cap of
16, the skip reasons, and the audit schema. It is recorded in the audit payload, not
on the evidence row. Evidence identity stays frozen. Changing the cap or skip rules
requires a new operation-policy version and does not touch evidence identity.

### 9. Transaction boundary and lock order

One bounded PostgreSQL transaction. Conceptual order:

1. Validate the HTTP request and the trusted actor in the API and application layer.
   Check the permission. Build one internal command with a fresh server-generated
   UUID v4 correlation value (section 11).
2. Start one interactive transaction at Read Committed with transaction-local
   bounds: `statement_timeout` 5000 ms, `lock_timeout` 2000 ms, interactive
   transaction `maxWait` 2000 ms and `timeout` 10000 ms. Verify the settings with
   `current_setting` before proceeding, as discovery does.
3. Take `pg_advisory_xact_lock(hashtextextended('<organizationId>:<assetId>', 0))`.
4. `SELECT ... FROM asset WHERE organization_id = <actor org> AND id = <assetId> FOR UPDATE`.
   No row: `not_found`.
5. Reload and validate the actor: User exists and is active (plain read, no User
   lock), organization exists and is active (plain read), membership in the actor's
   organization with the actor's membership id and user id, status active, role
   `owner` (`FOR SHARE`), and the permission by server mapping. Any mismatch:
   `authority_rejected`, zero writes.
6. Derive the ingestion from the locked asset row. Validate present, `completed`,
   normalization `2`, same organization and asset (section 5).
7. Reload the advisory revision, its unique approval, the binding, aliases, and range
   events by identifier (plain reads). Assess advisory-level eligibility once. An
   ineligible advisory, including an absent revision, ends here.
8. Select matching occurrences in deterministic order, up to 17 rows (section 6),
   and lock them `FOR UPDATE` in the same `id COLLATE "C"` order. More than 16:
   `capacity_exceeded`. Zero: `no_relevant_occurrence`.
9. Classify each occurrence (section 7). For each evaluable occurrence, look up the
   natural identity. Classify exact replay, immutable conflict, or malformed.
10. Evaluate each new, evaluable occurrence with the pinned pure evaluator
    (`evaluateReviewedNpmRange`) after re-running the existing component and
    advisory eligibility on the locked snapshots.
11. Insert evidence and explanation rows with the existing persistence semantics
    (database-time `created_at`, the replay fingerprint, closed constants).
12. Insert exactly one audit event if at least one new evidence row was inserted
    (section 10).
13. Validate stored state: re-read the inserted rows and confirm count, identity,
    outcome, and explanation completeness.
14. Commit atomically.
15. Return one bounded summary.

No network, provider, queue, worker, notification, ticket, object-storage, or AI call
occurs inside the transaction. No Outbox row is written. No Redis operation occurs.

**Pure in-memory evaluation inside the transaction: confirmed.** The evaluator is
synchronous, bounded by the committed range and version limits, performs no I/O, and
runs at most 16 times. Evaluating inside the transaction, after the locks, guarantees
that evaluation and insert see the same locked snapshot. The existing single-occurrence
writer already evaluates inside its transaction. Evaluating before the transaction
would need a second validation pass and adds a stale-snapshot window.

**Lock-order intent.** Advisory lock, asset row, membership row, then occurrence
rows in ascending `id COLLATE "C"`. This is the same prefix as the component-graph
pointer update and controlled Finding creation (advisory lock, asset row, membership
row). The evaluation transaction takes no table-level lock: evidence uniqueness is
enforced by constraints, so no phantom protection is needed. Controlled Finding
creation takes `LOCK TABLE ... SHARE ROW EXCLUSIVE` on the evidence table after the
shared prefix. A creation on another asset therefore waits for an in-flight
evaluation's evidence inserts, and an evaluation waits for it, but neither holds a
lock the other needs earlier in the order, so no cycle forms. The implementation must
prove the order with a concurrency integration test, and `lock_timeout` turns any
unexpected wait into the retryable `timeout` result (HTTP 503), not a hang.

Advisory catalog rows are not row-locked. They are immutable by trigger, and the
evidence insert guard re-checks successor absence, approval agreement, binding
agreement, and range evidence at insert time. A successor inserted concurrently
fails the insert and rolls the transaction back with zero writes.

### 10. Audit

One append-only audit event per committing request, written in the same transaction
as the evidence rows.

| Field | Value |
| --- | --- |
| `action` | `vulnerability.match_evaluated` (reserved in [audit-model.md](../architecture/audit-model.md) and ADR 0026 section 26) |
| `actor_type` | `user` |
| `actor_user_id` | the actor's User id |
| `organization_id` | the actor's organization id |
| `actor_membership_id` | the actor's membership id |
| `subject_type` | `asset` |
| `subject_id` | the asset id |
| `request_id` | the HTTP request id |
| `correlation_id` | the HTTP correlation id |
| `schema_version` | `1` |
| `retention_category` | `security` (default) |
| `payload` | `{ "schemaVersion": 1, "metadata": { ... } }` (below) |

Payload metadata, all bounded:

- `purpose`: `deliberate_product_match_evidence_evaluation`
- `policyId`: `deliberate_product_match_evaluation_policy_v1`, `policyVersion`: `1`
- `advisoryRevisionId`, `assetId`, `ingestionId`
- `selectedCount`, `insertedCount`, `replayedCount`, `skippedCount`
- `affectedCount`, `unaffectedCount`, `unknownCount`, counted over rows inserted by
  this request only

The payload never contains package names or versions, advisory content, ranges,
fingerprints, evidence identifiers, evidence rows, explanation codes, credentials,
SQL, database internals, Vulnerability identifiers, or CVE lists.

Rules:

- The first committing request writes one event.
- An exact all-replay request writes none.
- A rejected request writes none. These are bounded security logs, not audit rows.
- A rollback writes none.
- A mixed request (some new rows, some replays) writes one event for the committed
  request.
- Zero inserts (including `no_relevant_occurrence`, `no_evaluable_occurrence`, and
  `capacity_exceeded`) write none.

Existing audit conventions support this without a migration. The action and subject
columns are free-form, the `user` actor scope check and membership-user trigger fit,
and tenant replay uniqueness is `(organization_id, action, subject_id,
correlation_id)`. A unique violation on this insert (for example a client reusing one
correlation identifier for a second committing request on the same asset) aborts the
transaction with zero writes and returns `transaction_aborted`. It never produces
evidence without an audit row. The client retries with a fresh correlation
identifier. This affects only the requesting organization's own request.

No database constraint ties an evidence insert to this audit row. That linkage is an
adapter guarantee and an integration-test requirement. The only production writer of
product evidence must be this adapter (residual risk R-2).

Routine reads and rejected requests do not write audit rows.

### 11. Replay, idempotency, and concurrency

**Natural identity.** The existing evidence identity (organization, occurrence,
advisory revision, approval, evaluator id and version, matching policy id and
version, product-evidence policy id and version) bounds replay. The HTTP correlation
identifier and the internal command correlation value are not part of it and must not
redefine it. The internal command `correlationId` is a fresh server-generated UUID v4
per request, because the existing command parser requires a UUID v4. The audit row
carries the HTTP correlation identifier by repository convention.

**Per-occurrence replay.** An exact stored match returns as replayed and inserts
nothing. Replay never changes timestamps and never writes audit.

**Immutable conflict.** The same natural identity with a different replay body
aborts the whole request with `immutable_conflict`, zero writes.

**Changed inputs.**

| Change | Behavior |
| --- | --- |
| New successful ingestion | New occurrence identities. A new evaluation set. Prior evidence remains immutable history. Discovery uses only evidence for the asset's current ingestion. |
| Changed occurrence | Same as a new ingestion. Occurrences are immutable per ingestion. |
| Changed advisory revision | A different revision identifier is a different natural identity. A superseding revision is deferred. |
| Changed evaluator or policy | Rejected by the closed registry gate. It would need a new ADR and migration. |
| Stale ingestion | Prevented by the asset lock. The service evaluates the ingestion that is current when the lock is taken. If a newer ingestion becomes current afterward, discovery ignores the older evidence. It is harmless. |

**Concurrent identical requests.** Serialized by the per-asset advisory lock. The
second request finds exact replays and returns `already_applied` with no audit row.

**Concurrent conflicting requests.** Requests for the same asset are serialized.
Requests for different assets proceed independently. A unique-violation fallback
(the constraint tripped despite the locks) reloads outside the transaction and
classifies as the existing writer's reconcile does.

**Commit uncertainty.** If the commit result is unknown (connection loss at COMMIT),
the API returns a bounded unavailable error. A retry of the same request is safe. If
the first attempt committed, the retry finds replays and returns `already_applied`
with no second audit row. If it did not commit, the retry evaluates and commits once.
Neither the client nor an operator may assume either outcome.

A new successful ingestion creates new occurrence identities and therefore a new
evaluation set. Existing evidence remains immutable history. Finding discovery uses
only qualifying evidence from the asset's current latest successful ingestion.

### 12. Result semantics

Evidence only. None of these outcomes is risk, priority, assignment, exploitation, a
Finding, or a lifecycle transition.

- `affected`: evidence that the observed occurrence version is inside the reviewed
  range. It does not imply risk, priority, assignment, exploitation, Finding
  creation, or any lifecycle transition.
- `unaffected`: evidence that the occurrence version is outside the reviewed range.
  It does not mean remediated, verified, safe, resolved, or closed.
- `unknown`: evidence is insufficient or unsupported under the pinned evaluator
  semantics. It does not mean unaffected.
- `component_absent`: unavailable in the current persistence model. It is not
  implemented or simulated. No relevant occurrence is a command result
  (`no_relevant_occurrence`), not an evidence row and not `unaffected`.

Finding creation remains explicit and unavailable to this command. The command has
`findingWrites` of zero. `finding_creation` stays `unavailable` and
`suppression_authority` stays false.

### 13. Protected API contract

Exactly one future API mutation:

```
POST /assets/:assetId/product-match-evaluations
Content-Type: application/json

{ "advisoryRevisionId": "<canonical UUID>" }
```

The route:

- uses the existing cookie-session authentication;
- requires a trusted active organization membership and
  `product_match:evaluate_controlled`;
- derives the organization from the trusted actor only;
- requires the synchronizer CSRF header and an exact allowed `Origin`, as
  `POST /findings` does (a repeated `Origin` or CSRF header is rejected);
- requires `application/json` with only an optional UTF-8 `charset`;
- rejects any query string and any unknown or extra body key (strict schema);
- enforces a 1024-byte body limit and rejects an invalid or oversized
  `Content-Length`;
- validates `assetId` and `advisoryRevisionId` as canonical UUIDs with the validator
  the existing asset routes use;
- returns `Cache-Control: private, no-store` on every response, including errors;
- logs bounded route-template outcomes with request identifier, correlation
  identifier, actor user id, and organization id only;
- exposes no evidence identifiers, explanation codes, fingerprints, version text,
  approval internals, grant state, SQL, or raw evaluator diagnostics.

**Success and replay response** (`application/json`):

```json
{
  "schemaVersion": "deliberate_product_match_evaluation_response_v1",
  "status": "evaluated",
  "assetId": "<uuid>",
  "advisoryRevisionId": "<uuid>",
  "ingestionId": "<uuid>",
  "selectedCount": 3,
  "evaluatedCount": 2,
  "insertedCount": 2,
  "replayedCount": 0,
  "skippedCount": 1,
  "skippedByReason": { "version_not_known": 1, "version_unrepresentable": 0 },
  "outcomeCounts": { "affected": 1, "unaffected": 1, "unknown": 0 },
  "findingCreation": "unavailable"
}
```

Invariants: `selectedCount = evaluatedCount + skippedCount`, `evaluatedCount =
insertedCount + replayedCount`, and `evaluatedCount` equals the sum of
`outcomeCounts`. `outcomeCounts` covers inserted and replayed rows. `ingestionId` is
the tenant's own ingestion. The response contains no per-occurrence detail and no
evidence identifiers, so a Finding still starts from the discovery route.

Status determination: `evaluated` (HTTP 201) when at least one new row committed;
`already_applied` (200) when no new row was inserted and at least one occurrence was
replayed; `no_relevant_occurrence` (200) when no occurrence was selected;
`no_evaluable_occurrence` (200) when occurrences were selected and all were skipped.
The last two return zero counts and carry no evidence. They are results, not claims
about the asset's safety.

**Error taxonomy and public mappings:**

| Internal result | HTTP | Public code | Notes |
| --- | --- | --- | --- |
| `invalid_command` | 400 | `validation` | Malformed body, path, query, content type, or length |
| `unauthenticated` | 401 | `unauthorized` | No valid session, or CSRF failure |
| `forbidden` (`authority_required`, `authority_rejected`) | 403 | `forbidden` | Missing role permission or failed in-transaction reload. Origin failure uses the existing `ORIGIN_NOT_ALLOWED` |
| `not_found` | 404 | `not_found` | Foreign asset and absent asset are identical |
| `advisory_not_eligible` | 422 | `unprocessable_evidence` | One fixed message for absent, unapproved, withdrawn, quarantined, superseded, mismatched, or otherwise ineligible revisions. No reason is disclosed |
| `no_successful_ingestion`, `ingestion_not_evaluable` | 422 | `unprocessable_evidence` | One fixed asset-side message. Does not reveal advisory state |
| `capacity_exceeded` | 422 | `unprocessable_evidence` | One fixed capacity message. Reachable only after advisory eligibility passed |
| `immutable_conflict` | 409 | `conflict` | Generic message |
| `malformed_persisted_state`, `transaction_aborted`, `internal_failure` | 500 | `internal` | Generic message. The bounded internal code is logged only |
| `timeout`, `database_unavailable` | 503 | `internal` | `Product Match Evidence evaluation is temporarily unavailable.` Retryable |
| `rate_limited` | 429 | `rate_limited` | Existing `AUTH_HTTP_RATE_LIMITED` |

Confidential mappings: the public body never distinguishes a foreign asset from an
absent asset, never reveals approval internals or grant state, and never reveals why
an advisory is ineligible. The internal bounded rejection code is a closed enumeration
of tokens and is logged without values. Advisory-level eligibility is checked before
occurrence selection so that `capacity_exceeded`, `no_relevant_occurrence`, and
`no_evaluable_occurrence` cannot be used as an eligibility oracle beyond the single
fact that an eligible advisory exists for the revision identifier the owner already
holds.

### 14. Rate limits

Process-local, mirroring `POST /findings`:

| Control | Limit | Order |
| --- | --- | --- |
| Direct-peer | 5 requests per 60 seconds, keyed by the direct socket peer (`selectDirectPeerIp`, never `X-Forwarded-For`) | Fastify `onRequest`, before authentication |
| Per-organization | 5 requests per 60 seconds, keyed by the authenticated `actor.organizationId` | After session, CSRF, active organization, permission, and strict body validation. Before the application service |

An unauthenticated or unauthorized request does not consume the organization budget.
The organization identifier is never taken from the request. A limiter fault fails
closed as the existing "operator temporarily unavailable" pattern. A limited request
returns 429.

Both limiters are process-local. Each API process keeps its own window, so several
processes multiply the ceiling and restart clears it. That multiplication is accepted
for this slice. No Redis, no rate-limit table, and no migration are introduced for
rate limiting. At the accepted ceiling, one process admits at most 80 evidence rows
per organization per minute (5 requests times 16 occurrences).

### 15. API versus worker

The first implementation is a synchronous protected API command only. No web UI. No
worker. No queue, scheduler, Outbox row, or BullMQ job. No automatic ingestion
trigger. No deployment-local command. No CLI.

Synchronous evaluation is bounded because it involves one advisory package, one asset,
one latest ingestion, a fixed cap of 16 occurrences, a pure in-memory evaluator, no
provider or network call, and a 10-second transaction ceiling.

Moving future broader evaluation to a worker is required by any of these signals,
each of which needs its own ADR first:

- evaluation triggered by ingestion completion or any schedule;
- more than one advisory or more than one asset per command, or any bulk or
  cross-asset scope;
- a cap above 16, or measured request latency that approaches the 10-second budget;
- provider-derived or acquired advisories whose volume is not operator bounded;
- any need for retries, backoff, or progress reporting;
- a `system` audit actor.

A worker version needs an Outbox row in the triggering transaction, an idempotent job
identity scoped to organization, asset, ingestion, and revision, a `system` audit
actor decision, and organization re-binding from persistence rather than from the job
payload.

### 16. Schema, migration, and dependencies

**Existing schema sufficient; no migration required.** Evidence, explanation, audit,
asset pointer, ingestion, occurrence, advisory, approval, and binding tables already
carry everything this operation needs. Actor and audit fit the existing audit table
and its free-form action column. Multi-occurrence atomicity needs only one
transaction-scoped writer in the adapter, not a schema change. The frozen migration
count remains 26. Migration 27 is not authorized.

No dependency is authorized: no package manifest or lockfile change, no Redis, no
MinIO, no provider SDK, no scheduler, no evaluator library.

If implementation discovers that actor, audit, or atomicity cannot be met without a
schema change, the implementation stops and returns to governance with a blocker. It
must not make a migration-free claim it cannot support.

### 17. Provider boundary

The first slice uses local maintainer-reviewed advisories only. It makes no provider,
OSV, KEV, or network call. Provider acquisition is disabled and stays disabled. CISA
KEV remains membership data and never affectedness authority. Tests for the operation
must not contact `storage.googleapis.com` or `osv.dev`.

### 18. Explicit deferrals

The following stay unavailable and are not authorized by this ADR: automatic
evaluation after ingestion; worker-composed evaluation; all-approved-advisory
evaluation; all-asset evaluation; bulk operations; web UI; advisory listing and
inspection; provider and OSV acquisition; CISA KEV as affectedness authority;
`component_absent` evidence; graph-completeness absence claims; advisory withdrawal
and quarantine writers; superseding revisions; evaluator or policy changes;
repeated-observation reachability; observation history; a Finding list; Finding
lifecycle; automatic Finding creation; risk and priority; assignment and due dates;
suppression and accepted risk; false-positive decisions; remediation and
verification; notifications, exports, ticketing, and AI authority; and evidence
backfill. Evaluation for an archived asset is not specially treated, consistent with
discovery and creation; asset lifecycle is a separate decision.

### 19. Implementation sequence and exit criteria

Future branch: `feat/deliberate-product-match-evidence-evaluation`, created from
`main` after this ADR merges. Bounded sessions, each followed by a review:

1. **Contracts, permission, and application service.** Add
   `product_match:evaluate_controlled` and the owner-only mapping. Add the strict
   command, the closed result taxonomy, the operation-policy constants, and the
   application service over a port. Add an advisory-only eligibility assessment that
   shares the existing rules. Fake-port tests only.
2. **Transaction-scoped PostgreSQL adapter, uncomposed.** Extract a
   transaction-scoped evidence writer from the existing `commit` without changing its
   behavior. Add the locked asset, actor, ingestion, selection, classification,
   insert, audit, and validation steps. Disposable PostgreSQL integration tests.
3. **Protected API route and composition.** Add the route, limiters, HTTP contract
   tests, and the narrow source-boundary amendment that allows only the API
   composition root to construct the service. Add the operator runbook.
4. **Branch closure.** Reconcile `current-state.md` and index documents, and review the
   whole branch.

Exit criteria for the branch:

- The permission matrix is tested: owner yes, admin, member, and viewer no. Instance
  grants and Finding permissions do not substitute.
- Tenant isolation: organization A's owner cannot evaluate organization B's asset,
  and a foreign asset and an absent asset return the same response. Occurrence and
  ingestion selection never cross organizations.
- Replay: the same request twice yields one evidence set and one audit row. A mixed
  request writes one audit row. A rollback writes no evidence and no audit row.
  Injected faults before and after the audit insert prove atomicity.
- Concurrency: two identical concurrent requests yield one evidence set. A concurrent
  ingestion pointer change and a concurrent controlled Finding creation do not
  deadlock and are serialized.
- Ingestion cases: no pointer, not `completed`, normalization `1`, and a stale pointer.
- Capacity: 16 succeeds and 17 returns `capacity_exceeded` with zero writes.
- Classification: `affected`, `unaffected`, and every `unknown` reason persist.
  `version_known = false` and unrepresentable versions are skipped and counted.
  Integrity violations abort with zero writes.
- Advisory ineligibility: unapproved, withdrawn, quarantined, superseded, `superseding`
  disposition, self-approval, license, binding, fingerprint, synthetic, and KEV cases
  all return the same public response.
- Grant revocation and User disablement after approval do not block evaluation.
- Newly written affected evidence appears in controlled Finding target discovery.
  `unaffected` and `unknown` evidence does not.
- Audit payload contains no forbidden field, with a test that scans the stored JSON.
- Provider, network, queue, worker, and Finding writes are zero. A source test
  confines construction of the service and adapter to the API composition root.
- Rate-limit, body-limit, query-string, content-type, CSRF, Origin, and no-store tests.
- Migration count is 26 with unchanged hashes. No manifest or lockfile change.
- `current-state.md` and the checkpoint tests are updated in the same pull request.

## Alternatives considered

- **Owner and admin.** Rejected. Evidence is immutable and feeds owner-only Finding
  creation. Admin authority is administrative, and an admin gains the read side
  anyway.
- **Reuse `finding:create_controlled`.** Rejected. It would make evidence generation
  and Finding creation one permission and would let a future change to one widen the
  other. Permissions are not interchangeable in this repository.
- **Reuse an instance advisory grant.** Rejected. Instance authority over advisories
  must not grant tenant asset access, and tenant roles must not grant instance
  authority.
- **Abort on any unevaluable occurrence.** Rejected for benign cases. A versionless
  component or a hostile version string would block the asset's evaluation with no
  remedy. Integrity violations still abort.
- **Skip every failure.** Rejected. Silent partial evidence from corrupted state is
  not auditable.
- **Truncate to 16 occurrences.** Rejected. Silent truncation produces an evidence
  set that disagrees with the real graph.
- **Caller-supplied ingestion or occurrence identifiers.** Rejected. They are
  request-selected targets. The asset pointer under lock is the only ingestion source.
- **Evaluate every asset or every approved advisory.** Rejected. Unbounded work and
  authority for a first slice.
- **Worker or Outbox first.** Rejected. It needs a `system` actor, job identity, and
  retry decisions that the bounded synchronous slice does not need.
- **Automatic evaluation on ingestion.** Rejected for now, and a stated worker signal.
- **Renaming the evaluator label.** Rejected. It would need migration 27 and
  discovery and creation SQL changes for no behavioral gain.
- **One audit event per occurrence.** Rejected by ADR 0026 section 26.
- **A deferred constraint trigger linking evidence to audit.** Rejected for this slice
  because it needs migration 27. Reconsider if a second evidence writer appears.
- **Persist a `component_absent` row.** Rejected. The model does not support it and
  absence must not be represented as `unaffected`.

## Consequences

Positive:

- The controlled Finding workflow gets real, immutable, tenant-scoped evidence from
  an operator-reviewed source without enabling a provider.
- Authority, tenancy, replay, and audit are decided before code exists.
- No migration, dependency, or infrastructure is added.

Negative:

- Bad evidence is permanent. A wrong `affected` row cannot be edited or deleted.
  Neutralizing it needs a withdrawal writer that does not exist (R-1).
- Owners cannot discover revision identifiers inside PatchPilot. They need the
  identifier out of band (R-3).
- The 16-occurrence cap blocks a package observed in more than 16 versions in one
  SBOM until the SBOM changes.
- Rate limits are per process and multiply across processes (R-4).
- Evidence generation is an owner action. An owner must be available.
- Source-boundary tests that now forbid construction must be narrowly amended.

## Security and tenancy

- Deny by default. The permission is owner-only and independent of Finding and
  instance grants.
- Organization derives from the session. No client organization, ingestion,
  occurrence, evaluator, policy, fingerprint, or approval input is accepted.
- Foreign and absent assets are indistinguishable. The shared advisory catalog is
  never returned. Only counts are returned for tenant evidence.
- SBOM content is untrusted. Component names and versions are not logged or returned.
  Hostile version strings are skipped, not executed.
- No outbound fetch and no SSRF surface. No provider, KEV, or OSV access.
- Audit is append-only, bounded, and redacted. No evidence identifiers, versions,
  fingerprints, or advisory content appear in audit or logs.
- Never log authorization headers, cookies, tokens, raw SBOMs, private source, or
  vulnerability-feed payloads.
- Tenant-isolation and replay tests are required with the implementation.

## Operational failure plan

- **Lock contention or timeout.** `lock_timeout` and `statement_timeout` abort the
  transaction with zero writes and return a retryable 503. Retry after the competing
  ingestion completion or Finding creation finishes.
- **Commit uncertainty.** Retry the identical request. Replay returns
  `already_applied` and writes no second audit row.
- **Immutable conflict or malformed persisted state.** Zero writes. The request fails
  closed. Operators investigate the stored row through the tenant-isolation and audit
  runbooks. No update or delete of evidence is sanctioned.
- **Wrong evidence committed.** Evidence cannot be edited. The recorded recovery path
  is a future withdrawal or quarantine writer, because discovery already excludes
  withdrawn and quarantined revisions. Until that exists this is accepted risk R-1.
- **Audit unique collision.** The request aborts with zero writes. Retry with a fresh
  correlation identifier.
- **Capacity exceeded or no evaluable occurrence.** Zero writes. The operator changes
  the SBOM or the advisory scope. Neither is a defect.
- **Migration or constraint drift.** Frozen migration hashes and the closed evidence
  check still protect identity. A guard failure surfaces as `transaction_aborted`.
- **Operator signals.** Bounded route-template logs carry the outcome and closed
  internal code. An operator runbook is a required deliverable of implementation
  session 3.

## Follow-up

- Implement in the four sessions in section 19.
- Amend `source-boundary.test.ts` narrowly in session 3 so only the API composition
  root may construct the new service. Keep every other runtime root excluded.
- Update [current state](../project/current-state.md), the
  [ADR index](README.md), [audit model](../architecture/audit-model.md),
  [product-evidence provenance](../architecture/product-evidence-provenance.md), and
  add a runbook when the route is composed.
- Open governance questions, none of which this slice needs: advisory listing for
  owners, a withdrawal and quarantine writer, superseding revisions, automatic and
  worker evaluation, `component_absent`, and a possible evidence-to-audit constraint.

## Accepted residual risks

- **R-1.** No withdrawal, quarantine, or supersession writer exists. An approved
  advisory stays evaluable, and committed evidence stays permanent. A compromised
  maintainer's earlier approval remains valid under ADR 0043 until a writer exists.
  Impact is bounded to evidence rows consumed only by the owner-controlled Finding
  workflow.
- **R-2.** No database constraint links evidence inserts to the audit row. The adapter
  must remain the only production evidence writer.
- **R-3.** No advisory listing. Revision identifiers travel out of band.
- **R-4.** Process-local rate limits multiply across API processes.
- **R-5.** Approved advisory range membership is inferable by any tenant owner holding
  the revision identifier and a suitable SBOM.
- **R-6.** Archived assets are not specially treated.
