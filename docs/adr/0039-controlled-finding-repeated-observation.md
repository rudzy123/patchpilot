# ADR 0039: Controlled Finding repeated observation

- Status: Accepted
- Date: 2026-10-09
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the governance decision for one persistence-only repeated observation of an
existing open Finding. Merge to `main` remains subject to normal pull-request review.
This ADR does not implement the transaction, add a migration, compose production, or
authorize a Finding lifecycle power.

## Context

[ADR 0035](0035-controlled-finding-creation.md) accepts one creation-only Finding.
[ADR 0036](0036-controlled-finding-operator-api.md) composes owner `POST /findings` and
owner or admin `GET /findings/:findingId`. [ADR 0037](0037-controlled-finding-target-discovery.md)
composes read-only target discovery. [ADR 0038](0038-controlled-finding-web-workflow.md)
is merged as the nested asset web workflow. Those surfaces persist and show creation
evidence only.

The Finding natural key is already `organization_id` + `asset_id` + `component_id` +
`vulnerability_id` (`finding_identity_key`). The observation natural key is already
`organization_id` + `finding_id` + `sbom_ingestion_id` (`finding_observation_identity_key`).
`finding_observation_result` is `present`, `absent`, and `inconclusive`.
`match_evaluation_outcome` is `affected`, `unaffected`, and `unknown`.

The creation migration `20261006120000_controlled_finding_creation` admits only
`controlled_finding_creation`. It rejects every Finding update and every other
observation insert. `finding_creation_evidence_link` accepts only `affected` Product
Match Evidence. `finding_creation_initial_state_chk` keeps `state = open` and
`version = 1`. The frozen migration count is 24.

[ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) section 18
describes a later observation that does not create a second Finding. Section 20
describes evidence-backed resolution. Section 20 is not authorized by the creation
exception in section 10A. Current ingestion order is SBOM `received_at`, then
ingestion `created_at`, then ingestion `id`, stored as
`asset.last_successful_sbom_ingestion_id`.

Composed inspection, discovery, and creation replay currently treat an observation
count other than the single creation observation as malformed persisted state. A
later observation row would break those reads unless they keep projecting the
creation observation only.

## Decision

PatchPilot accepts one persistence-only, production-uncomposed repeated observation.

The governed progression is:

existing open Finding → later latest successful SBOM ingestion → complete current
evidence or constrained absence proof → purpose-specific repeated-observation
authorization → one immutable Finding observation → complete immutable evidence
links or absence metadata → bounded Finding timestamp update → one immutable audit
event → Finding remains open.

Stable Finding identity, immutable creation evidence, and every deferred lifecycle
power stay in force. This decision does not adopt [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md)
section 20.

### 1. Observation identity

The repeated-observation natural identity is the existing key:

`organization_id` + `finding_id` + `sbom_ingestion_id`.

At most one observation exists for one Finding and one ingestion. The identity is
organization scoped. It stays stable across Finding summary changes. It does not
include aggregate result, observation policy version, evidence fingerprint,
ComponentOccurrence, Product Match Evidence row, actor, or correlation identity.

Observation type, policy, aggregate result, and replay fingerprint are stored
attributes. The stored authority version is `finding_observation_policy_v1`
version 1. It is not a durable authority-table version.

The Finding natural identity remains:

`organization_id` + `asset_id` + `component_id` + `vulnerability_id`.

A later ingestion, version, occurrence, advisory revision, policy, or evidence row
does not create another Finding. The schema field for assignment is
`assigned_membership_id`.

### 2. Eligible ingestion

The target ingestion must be all of the following:

- scoped to the trusted organization;
- associated with the Finding's asset;
- `completed`;
- normalized under version `2`;
- equal to `asset.last_successful_sbom_ingestion_id` after the asset lock;
- strictly later than the creation observation's ingestion;
- immutable under the existing ingestion rules.

An observation row that already exists for this Finding and ingestion is not a
new insert. It is exact replay or immutable conflict.

Processing, failed, rejected, quarantined, duplicate, accepted, and queued
ingestions are ineligible. A completed ingestion that is not the current
latest-successful pointer is ineligible.

Strictly later uses the same comparison as
`replaceAssetPointerIfCandidateIsCurrent`:

1. SBOM `received_at`;
2. ingestion `created_at`;
3. ingestion `id`, compared as the UUID column.

That comparison is the row ordering `(received_at, created_at, id)`. It does
not cast `id` to text and it does not apply `COLLATE "C"`. `COLLATE "C"` remains
the ordering for evidence-id sets. The target tuple must be strictly greater
than the creation observation's ingestion tuple. An equal tuple is not later.
The creation ingestion is reloaded in the same transaction and must still be
`completed`, normalization version `2`, and aligned to the Finding's
organization and asset.

Outcomes:

- an older unobserved ingestion is rejected as not latest;
- the creation ingestion is rejected as not later, and is not a replay of the
  repeated-observation command;
- an existing repeated observation for the same Finding and ingestion is exact
  replay or immutable conflict;
- a foreign or absent Finding is publicly indistinguishable from a foreign or
  absent ingestion;
- a pointer that changed before lock acquisition is stale or not latest;
- pointer replacement during the transaction is prevented by the established
  organization-and-asset advisory lock and the asset row lock.

This slice does not backfill historical ingestions.

### 3. Result taxonomy

Keep `finding_observation_result`. Add a closed aggregate classification with
exactly:

- `affected`;
- `unaffected`;
- `unknown`;
- `component_absent`.

Mapping:

- `affected` maps to `present`;
- `unaffected` maps to `absent`;
- `unknown` maps to `inconclusive`;
- `component_absent` maps to `absent`.

The aggregate is stored separately. Stored `absent` cannot distinguish a legally
unaffected component from a component absent from the later ingestion.

`evidence_unavailable` is a command failure. It is not persisted and it is not a
result-enum value. Do not add a result-enum value for component absence.

### 4. Mixed-occurrence aggregation

Relevant occurrences are every ComponentOccurrence of the Finding's versionless
Component in the target ingestion, for the trusted organization and the Finding's
asset. Direct and transitive occurrences are equally relevant. `is_direct` null
does not drop an occurrence.

Completeness is decided before any aggregate. A known-version occurrence is
complete only when it has exactly one current legal evidence row. An
unknown-version occurrence is complete only through its unknown-version proof.
Zero occurrences are complete only through a valid absence proof.

If any known-version occurrence has no current legal row, or has more than one,
the command fails as `evidence_unavailable` and writes nothing. That failure
wins over every sibling, including a legally affected sibling, an unknown
outcome, and an unknown-version occurrence. Incomplete evidence is not stored
as an observation.

When the set is complete:

1. One or more legally affected occurrences make the aggregate `affected`.
   Unaffected, unknown, and unknown-version siblings do not veto it.
2. Otherwise an unknown outcome or an explicitly unknown version makes the
   aggregate `unknown`. `unknown` dominates `unaffected`.
3. `unaffected` requires at least one occurrence, and every occurrence must
   have a known version and one current legal unaffected row. Zero occurrences
   are never `unaffected`.
4. `component_absent` requires zero occurrences and a valid constrained absence
   proof. Any failed absence predicate is `evidence_unavailable`.
5. Per-occurrence evidence remains linked so the aggregate cannot conceal mixed
   outcomes.

Deterministic cases:

- one affected occurrence, with its one current row: `affected`;
- affected and unaffected, complete: `affected`;
- affected and unknown, complete: `affected`;
- all unaffected, at least one occurrence, complete: `unaffected`;
- unaffected and unknown, nothing affected, complete: `unknown`;
- all unknown outcomes, complete: `unknown`;
- one unknown-version occurrence and no incomplete known-version sibling:
  `unknown`;
- a known version with missing evidence, with or without other occurrences:
  `evidence_unavailable`;
- zero occurrences with sufficient absence proof: `component_absent`;
- zero occurrences with insufficient graph coverage or inconsistent counts:
  `evidence_unavailable`.

An unknown version is not Component absence.

### 5. Qualifying evidence

Require the complete current legal evidence set for every relevant occurrence.

For every known-version occurrence, require exactly one current Product Match
Evidence row aligned on organization, asset, versionless Component, Vulnerability,
ComponentOccurrence, SBOM ingestion, evaluator, matching policy, product-evidence
policy, evidence schema, maintainer-reviewed advisory authority, immutable
reviewed approval, reviewed non-conflicting Vulnerability binding, and the current
non-withdrawn and non-quarantined advisory revision.

The current-row predicate is the creation qualifying predicate except that the
outcome may be `affected`, `unaffected`, or `unknown`. Creation's affected-only
eligibility is unchanged.

The set may contain all three outcomes. Require the complete set, not only rows
that match the final aggregate. A caller subset or superset fails closed. More
than one current legal row for one occurrence is `evidence_unavailable` and
writes nothing.

Repeated observation does not grant Finding creation, suppression, closure,
verification, or remediation authority.

### 6. Unknown-version proof

An occurrence with `version_known = false` is a stored fact. It contributes to
aggregate `unknown`. Product Match Evidence requires a known version, so this
slice does not fabricate a Product Match Evidence row.

The proof is a repeated-observation evidence-link row aligned on organization,
Finding, ingestion, asset, versionless Component, ComponentOccurrence, and
Vulnerability target, with no Product Match Evidence identity. A known-version
occurrence with missing evidence must not use this proof.

### 7. Component-absence proof

Authorize `component_absent` only when all of the following hold:

- the ingestion is organization scoped and belongs to the Finding's asset;
- the ingestion is `completed` and is the latest successful ingestion;
- normalization version is `2`;
- `graph_completeness` is `complete` or `no_dependencies`;
- `component_count` is at least one and equals the live
  ComponentOccurrence cardinality for that organization and ingestion;
- `dependency_edge_count` equals the live dependency-edge cardinality for that
  organization and ingestion;
- the stored counts already satisfy the graph-completeness check:
  `complete` has at least one edge, and `no_dependencies` has zero edges;
- an organization- and asset-scoped query proves zero occurrences of the
  Finding's versionless Component;
- no caller-supplied absence assertion is accepted.

These comparisons are against the target ingestion's stored columns and live
rows. They are not a comparison with the creation ingestion's component count
or edge count. A smaller later document that is itself `complete` or
`no_dependencies` can satisfy the proof. Edge-count regression versus the
creation graph is not a predicate. This slice does not adopt the percentage
inventory-shrinkage proposal.

`empty` and `partial` are not proof. `partial` is the persisted classification
when at least one non-self edge was stored and at least one listed self-edge
was skipped. Duplicate listed edges are dropped without increasing that skip
count, so duplicates alone do not make the graph `partial`. Unknown dependency
references never reach `completed`.

`deriveGraphCompleteness` classifies zero stored edges as `no_dependencies` even
when every listed edge was a skipped self-edge. That skipped-edge count is not
a column and cannot be re-derived at observation time. Self-edge skips do not
remove component occurrences. This slice accepts `no_dependencies` when the
count equalities and the zero-occurrence query hold. It does not treat
`warning_count` as absence failure, because warning count mixes
`self_dependency_skipped` and `duplicate_identity_collapsed` and is not
skipped-edge identity.

The deferred check uses the stored `graph_completeness`, `component_count`, and
`dependency_edge_count` values, plus the live row counts. It does not invent a
second coverage classification.

Zero occurrences without adequate coverage is `evidence_unavailable`. Missing
Product Match Evidence is not Component absence. Component absence does not mean
remediated, verified, resolved, safe, or closed.

The accepted creation baseline is a latest successful, completed,
normalization-version-2 ingestion. Absence proof is stricter than that baseline.

A `component_absent` observation has zero repeated-observation evidence-link
rows. It stores absence metadata copied from the locked ingestion:
`absence_graph_completeness`, `absence_component_count`, and
`absence_dependency_edge_count`. Those columns are null for every other
aggregate. The deferred check requires them to equal the ingestion columns,
requires the live counts to equal those columns, requires zero occurrences of
the Finding's Component, and requires zero evidence-link rows. That metadata
supports replay and database completeness. It does not mean remediated,
verified, resolved, safe, or closed.

### 8. Purpose-specific observation authority

Authorize one sealed, process-local capability for
`record_finding_repeated_observation` under `finding_observation_policy_v1`
version 1.

The capability binds organization, authenticated actor, active membership,
Finding, asset, versionless Component, Vulnerability, target ingestion, the
complete evidence set or the constrained absence-proof fingerprint, observation
purpose, policy id and version, and correlation identity.

It is not a role string, a permission string, membership alone, administrator
status, a durable authority table, a caller-constructible structural object, or
a generic Finding mutation authority.

It grants no permission for Finding creation, closure, reopening, verification,
remediation, suppression, accepted risk, false-positive decisions, risk,
priority, assignment, due dates, automatic processing, bulk observation, or
provider or evaluator calls.

A later reachability decision must define the operator permission and access
surface. This slice adds no route permission.

### 9. Observation command

Govern one strict command, `finding_repeated_observation_command_v1`.

The command may carry expected conflict-check values: Finding id, asset id,
Component id, Vulnerability id, target ingestion id, the expected sorted
evidence-id set (empty only for absence), the expected absence-proof fingerprint
where applicable, the exact purpose, the exact observation policy and version,
the correlation id, and the sealed authority.

The caller must not choose organization, Finding natural identity, observation
result, aggregate classification, Finding state, timestamps, `last_observed_at`,
`resolved_at`, `reopened_at`, assignment, due date, risk, priority, suppression,
remediation, verification, explanation prose, audit action, raw persistence
input, or transaction callbacks.

The aggregate and stored result are derived from committed facts.

### 10. Atomic transaction

One transaction. Lock order matches controlled creation, then the evidence
stabilizer:

1. Validates the strict command.
2. Validates the sealed purpose-specific authorization.
3. Enables the transaction-local setting
   `patchpilot.controlled_finding_repeated_observation`.
4. Takes the established advisory lock. The key is the text
   `organizationId:assetId` passed to `hashtextextended(..., 0)`, the same key
   creation and `lockAssetForPointerUpdate` use. The statement returns a row,
   because Prisma cannot deserialize a void result from `pg_advisory_xact_lock`.
5. Locks the asset row `FOR UPDATE`.
6. Reloads the organization without a row lock.
7. Locks the active membership `FOR UPDATE` and requires the actor match.
8. Locks the Finding row `FOR UPDATE`.
9. Validates immutable Finding creation lineage.
10. Loads and validates the target ingestion.
11. Confirms latest-successful and strictly-later requirements.
12. Stabilizes Product Match Evidence with
    `LOCK TABLE product_match_evaluation_evidence IN SHARE ROW EXCLUSIVE MODE`.
13. Loads every relevant occurrence with `SELECT`. Does not take
    `component_occurrence` `FOR UPDATE`.
14. Loads and validates the complete current evidence set.
15. Derives unknown-version proofs where legal.
16. Derives per-occurrence outcomes.
17. Derives the aggregate classification and persisted result.
18. Derives the evidence or absence-proof fingerprint.
19. Inspects an existing repeated observation for exact replay.
20. Inserts one immutable later observation when absent.
21. Inserts the complete evidence-link set or constrained absence metadata.
22. Advances only `last_observed_at` and `updated_at` on the Finding.
23. Inserts exactly one `finding.observed` audit event.
24. Validates deferred completeness constraints.
25. Commits all records together.
26. Returns a bounded result.

`SHARE ROW EXCLUSIVE` blocks `INSERT`, `UPDATE`, and `DELETE` on
`product_match_evaluation_evidence` for every organization until commit. That
is the same global stabilizer creation uses. It is bounded serialization, not a
tenant lock. Same-asset creation, pointer replacement, and observations for
different Findings on that asset serialize earlier on the advisory lock.
Different assets proceed concurrently until this table lock. Product-match
commit locks one occurrence and then inserts evidence. This transaction takes
the table lock first and does not lock occurrence rows, so those two waiters do
not form a lock cycle. An observation cannot see an uncommitted Finding on the
same asset because creation holds the advisory lock until commit.

The creation setting `patchpilot.controlled_finding_creation` cannot insert a
repeated observation. The repeated-observation setting cannot insert a creation
observation or a Finding. The existing deferred creation-completeness trigger
returns immediately when `method` is not `controlled_finding_creation`. That
early return stays. Repeated-observation completeness uses its own deferred
trigger.

No provider, evaluator, parser, object storage, network, queue, scheduler,
notification, ticketing, or AI call occurs inside the transaction.

### 11. Evidence-link model

`finding_creation_evidence_link` stays unchanged, including its affected-only
check and its one-link-per-evidence uniqueness.

Authorize a separate append-only relation,
`finding_repeated_observation_evidence_link`.

A row supports affected, unaffected, or unknown Product Match Evidence, or an
unknown-version occurrence proof without Product Match Evidence.
`product_match_evaluation_evidence_id` is nullable. It is null exactly for an
unknown-version proof. A known-version row requires the evidence id, and its
stored outcome must match that evidence row. A partial unique index on
`(organization_id, product_match_evaluation_evidence_id)` applies only where
the evidence id is not null. One observation has at most one link per
ComponentOccurrence.

Each row aligns organization, Finding, observation, ingestion, asset, versionless
Component, Vulnerability, ComponentOccurrence, Product Match Evidence when
present, stored evidence outcome, and the aggregate target. `sbom_id` on the
observation and the link is the target ingestion's SBOM.

Require same-transaction insertion, compound tenant and target alignment,
append-only behavior, update rejection, deletion rejection, restricted parent
deletion, deferred complete-set validation, and replay comparison. A
`component_absent` observation has zero rows in this relation. Every other
legal aggregate has one row per relevant occurrence and no extra row.

Do not generalize or rewrite creation links. A later observation must not mutate
Product Match Evidence.

### 12. Observation shape

The creation-observation shape stays the creation branch of the new check. New
repeated-observation columns are null on that branch.

The repeated shape records:

- method `controlled_finding_repeated_observation`;
- transition classification `evidence_observation`;
- purpose `record_finding_repeated_observation` in new observation-purpose
  columns, not in `creation_purpose`;
- policy `finding_observation_policy_v1` version 1 in new observation-policy
  columns, not in the creation-policy columns;
- the aggregate classification;
- the mapped `finding_observation_result`;
- actor membership and correlation identity;
- the replay fingerprint;
- `sbom_ingestion_id` of the target ingestion;
- `sbom_id` of that ingestion's SBOM, organization-aligned, and not chosen by
  the caller;
- database-authoritative `observed_at`, equal to `created_at`;
- the evidence-link count;
- `absence_graph_completeness`, `absence_component_count`, and
  `absence_dependency_edge_count` when, and only when, the aggregate is
  `component_absent`;
- a closed `evidence` object, schema `finding_repeated_observation_v1`, equal
  to the observation's purpose, policy, aggregate, mapped result, evidence-link
  count, and replay fingerprint, with no arbitrary prose.

`occurrence_id` stays null. Creation purpose, creation policy, and
`affected_evidence_count` stay null on the repeated branch. The creation branch
keeps the new observation-purpose, observation-policy, aggregate, evidence-link
count, and absence columns null.

The repeated observation contains no closure, reopening, remediation,
verification, suppression, risk, priority, assignment, due date, or external
ticket data.

### 13. Permitted Finding mutation

A newly committed repeated observation may update only `last_observed_at` and
`updated_at`. Both use the same database-authoritative observation timestamp.

These fields remain unchanged: `organization_id`, `asset_id`, `component_id`,
`vulnerability_id`, `first_observed_at`, `state`, `version`,
`component_occurrence_id`, `resolved_at`, `reopened_at`,
`assigned_membership_id`, `assigned_team_id`, `due_at`,
`current_risk_calculation_id`, and `created_at`.

`last_observed_at` means the latest committed Finding observation time. It does
not mean the Component remains affected. `state` remains `open` for every
aggregate. `version` remains 1 because `finding_creation_initial_state_chk`
requires it. [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md)
section 17's Finding-version increment is not used by this slice. Concurrency
uses the asset advisory lock. `component_occurrence_id` remains null because
several versions may contribute. `asset.last_observed_at` is a different column
and is not modified.

The future migration may narrow `patchpilot_finding_reject_update` only enough
to permit those two timestamp updates while the repeated-observation setting is
on and a same-transaction repeated observation exists for that Finding. Every
other column must satisfy `IS NOT DISTINCT FROM` its previous value. Both
timestamps must equal that observation's `observed_at`. A `last_observed_at`
earlier than the stored value is rejected. Exact replay does not issue the
update.

### 14. Replay and concurrency

When Finding, ingestion, policy, aggregate, complete evidence set or absence
proof, and fingerprint agree:

- return `already_applied`;
- insert nothing;
- update nothing;
- delete nothing;
- change no timestamp;
- write no second audit event;
- renew no durable authority.

For the same Finding and ingestion, disagreement in policy, aggregate, evidence
set, absence proof, or replay fingerprint is `immutable_conflict`.

Do not insert a second observation for the same Finding and ingestion. The
existing unique key enforces that.

An existing row that fails the repeated-observation shape, the complete link
set or absence metadata, or the semantic comparison is not replay. It fails
closed. Do not repair it in this command.

Concurrent identical observations converge to one committed observation, one
complete evidence-link set or absence proof, one Finding timestamp update, one
`finding.observed` event, one observed result, and one `already_applied` result.
Use one conflict reload, not an unbounded retry loop. Reload compares policy,
aggregate, evidence set or absence proof, and fingerprint. An unexpected
uniqueness failure is not automatically replay. A retry after uncertain commit
uses that same comparison.

### 15. Audit event

Require exactly one immutable `finding.observed` event in the same transaction
as the observation. The row uses `subject_type` `finding`, `subject_id` of the
Finding, `actor_type` `user`, and the organization from the sealed capability.
Correlation id is stored as text, matching `finding.created`. The existing
unique index is `(organization_id, action, subject_id, correlation_id)`.
Several later ingestions may each have one event because each command has its
own correlation id. That index does not limit a Finding to one
`finding.observed` row for its lifetime. Reusing one correlation id for a
second ingestion of the same Finding fails closed on that index. It does not
merge the events.

Bounded metadata:

- schema version;
- purpose;
- policy id and version;
- aggregate classification;
- target ingestion id;
- evidence-link count or the component-absence classification.

Omit evidence ids, evidence bodies, authority seals, credentials, reviewer
identity, protected provider identity, SQL, database internals, and unbounded
display strings.

Exact replay writes no second event. The event belongs to the persistence
transaction. The writer remains production uncomposed. Do not emit
`finding.created` for a repeated observation.

### 16. Finding state and lifecycle

`affected`, `unaffected`, `unknown`, and `component_absent` each leave the
Finding `open`.

No repeated observation closes or reopens a Finding, writes `resolved_at` or
`reopened_at`, verifies remediation, suppresses the Finding, accepts risk,
declares a false positive, assigns ownership, sets a due date, or calculates
risk or priority.

Repeated observation is evidence only. [ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md)
section 20 stays deferred.

### 17. Continuous presence and recurrence

Affected evidence after the creation observation is continued affected evidence.
Affected evidence after an earlier unaffected observation, or after an earlier
component-absent observation, is a derived recurrence classification.

Recurrence is not a Finding state. It does not write `reopened_at` and it does
not reopen the Finding. A future inspection-history projection may derive it
from immutable observations.

### 18. Inspection compatibility

Current `GET /findings/:findingId` projects the creation observation, the
creation evidence links, and the existing safe projection. The loader and
projection treat `observations.length !== 1` as malformed persisted state.
Discovery well-formedness requires `observationCount <= 1`. Creation replay
selects a stored observation only when the count is exactly one.

The persistence implementation must change all three readers in the same change
that can persist a later observation:

- Inspection loader and `structuralFailure` identify the creation observation
  by method `controlled_finding_creation` and the creation shape: result
  `present`, null occurrence, transition `initial_creation`, and the creation
  purpose and policy. Legal repeated-observation rows do not make
  `observations.length !== 1` mean malformed creation state. The projection
  continues to use creation links only.
- Discovery lineage counts and selects that same creation-shape observation.
  `observationCount <= 1` applies to the creation observation, not to legal
  later rows.
- Creation replay in `classifyStored` uses that creation-shape observation for
  `already_applied`. A legal later observation must not set
  `persistedStateWellFormed` false and must not turn exact creation replay into
  `malformed_persisted_state`.

A repeated observation that fails its own shape remains malformed. A legal
later observation is not exposed. The filter adds no route, no history payload,
and no inspection-history authorization.

A later, separately governed inspection-history slice may expose the creation
observation, the latest later observation, aggregate classification, observation
timestamp, ingestion identity, affected-version summary, component absence,
current versus historical applicability, and continuous-presence or recurrence
classification. This decision does not authorize an unbounded history endpoint.

### 19. Production boundary

The first implementation is persistence and PostgreSQL tests only, plus the
read filter in section 18. It stays production uncomposed.

This decision does not authorize an API route, a permission grant, a web
control, a worker, a scheduler, a queue, a BackgroundJob handler, an Outbox
consumer, a BullMQ processor, an upload trigger, an evaluator trigger, a
provider trigger, automatic observation, bulk observation, or historical
backfill.

A later reachability ADR is required before an operator or automated system can
invoke repeated observation.

### 20. Migration intent

One additive forward-only migration is required on the implementation branch.
This governance branch does not create it. The frozen migration count remains
24. It becomes 25 only after that migration SQL and frozen hash are final.

The migration may:

- add nullable repeated-observation provenance fields, including observation
  purpose and policy columns that stay null on the creation branch;
- add the aggregate classification;
- add nullable absence metadata that is required only for `component_absent`;
- replace the creation-only shape check with a strict OR of the unchanged
  creation shape and the repeated-observation shape;
- narrow the observation insert guard for the repeated-observation setting;
- leave the creation-completeness trigger's early return for every other
  method in place, and add a separate deferred repeated-observation check;
- narrowly permit `last_observed_at` and `updated_at` changes under that
  setting, rejecting every other column change;
- add `finding_repeated_observation_evidence_link` with a nullable evidence id,
  a partial unique index for non-null evidence ids, and one link per
  occurrence;
- add compound tenant and target alignment keys;
- add append-only guards, restricted deletion, deferred completeness, and audit
  completeness enforcement.

The migration must not alter Finding or observation natural identity, modify
creation observation semantics, rewrite creation evidence links, add a durable
authority table, change Product Match Evidence semantics, seed or backfill
observations, change Finding state, add lifecycle transitions, or enable
production composition.

It must not fail merely because controlled creation Findings already exist. The
creation migration's empty-table guard is not repeated. New columns are
nullable. Existing creation rows remain valid because those columns are null
and the creation branch of the shape check is unchanged.

### 21. Existing data compatibility

No historical backfill. Zero later observations is valid. Existing controlled
Findings and creation observations remain valid under the unchanged creation
branch. Creation links and `finding.created` events remain unchanged.

The migration must deploy over databases that contain valid controlled
Findings. Incompatible malformed state fails closed under repository migration
policy. Do not add seeds or placeholder observations.

### 22. Explicit deferrals

The following remain unavailable:

- automatic, upload-triggered, evaluator-triggered, worker, or scheduled
  observation;
- bulk observation and historical backfill;
- automatic closure, reopening, resolution, and verification;
- remediation and verification workflows;
- risk scoring, priority, assignment, and due dates;
- suppression, accepted risk, and false-positive decisions;
- notifications, dashboards, exports, ticketing, and AI authority;
- paged full observation history and inventory-shrinkage heuristics;
- observation reachability and inspection-history expansion.

## Alternatives considered

- **Reuse `finding_creation_evidence_link`.** Rejected. That relation is
  affected-only and unique per evidence row. Later unaffected, unknown, and
  unknown-version proofs need a separate append-only relation.
- **Add `component_absent` to `finding_observation_result`.** Rejected. `absent`
  already means a calculated absence, and a new enum value would blur the
  creation shape. The aggregate column keeps the distinction.
- **Treat unknown version as component absence or as `unaffected`.** Rejected.
  Unknown version is a stored occurrence. Missing known-version evidence is a
  command failure.
- **Close the Finding when the aggregate is unaffected or component-absent.**
  Rejected. That is ADR 0026 section 20, which this slice does not adopt.
- **Increment `finding.version`.** Rejected for this slice. The creation state
  check requires version 1. Concurrency uses the existing asset lock.
- **Adopt a percentage inventory-shrinkage heuristic.** Rejected. Absence uses
  constrained graph facts already stored for a completed ingestion.
- **Expose later observations through the current inspection projection.**
  Rejected. Current inspection stays creation-focused. History needs a later
  decision.

## Consequences

Implementers add one forward migration and one uncomposed persistence
transaction. Composed creation, discovery, and inspection stay creation-focused
through the section 18 read filter. Operators gain no new command. Findings
remain open after every aggregate. A later reachability ADR is still required.

## Security and tenancy

The organization comes from the sealed capability, reloaded inside the
transaction. A client-supplied organization id is not authorization. Foreign and
absent Findings and ingestions stay publicly indistinguishable, including on
any later reachable surface. Evidence links, absence proof, replay lookup, and
the audit event use the same organization. Audit metadata omits evidence bodies
and seals. No outbound fetch is added. No credential is stored or logged.

## Operational failure plan

A failed transaction writes nothing. Exact replay is silent. Immutable conflict
overwrites nothing. `evidence_unavailable` writes nothing. A uniqueness conflict
reloads once. If the reload is not exact replay, the command fails closed.
Operators do not insert observations, edit frozen migrations, or backfill
history. Because the writer is uncomposed, production startup cannot emit
`finding.observed`.

## Follow-up

The next branch after this ADR merges is the persistence implementation. It
includes the migration, PostgreSQL tests, and the section 18 read filter. It
does not add a route. Inspection history and operator reachability remain
separate decisions.
