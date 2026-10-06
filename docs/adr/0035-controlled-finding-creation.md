# ADR 0035: Controlled Finding creation

- Status: Accepted
- Date: 2026-10-06
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as the architecture for one creation-only Finding slice under
`controlled_maintainer_reviewed_finding_creation_v1`. Merge to `main` remains subject to
normal pull-request review. This ADR does not implement the transaction, add a migration,
compose production, or authorize the wider Finding lifecycle.

## Context

[ADR 0026](0026-authoritative-match-evidence-and-finding-lifecycle.md) accepts Finding identity
and a provider-driven write gate. That gate requires OSV acquisition, catalog activation, and
the complete lifecycle before any Finding writer exists. Those conditions do not describe the
maintainer-reviewed Product Match Evidence path.

[ADR 0032](0032-maintainer-reviewed-advisory-authority.md) is accepted for issued reviewer
authority. Approval and Product Match Evidence remain production uncomposed. An affected
Product Match Evidence row is evidence. It is not Finding authority.

[ADR 0033](0033-product-match-evidence-cardinality.md) keeps evidence immutable and derives
current applicability at query time. [ADR 0034](0034-multi-version-component-occurrence-normalization.md)
keeps distinct observed versions as distinct occurrences on normalization version `2`.
Finding identity stays versionless.

The Finding and FindingObservation models remain placeholder infrastructure. Persistent Finding
count is 0. No production Finding writer exists.

## Decision

PatchPilot accepts one controlled creation path and withholds every other Finding power.

The path is:

one complete current affected evidence set → one purpose-specific creation decision → one
stable tenant-scoped Finding → one immutable creation observation → one complete immutable
evidence-link set → one safe read-time explanation.

### 1. Finding identity

The natural identity is unchanged:

`organization_id` + `asset_id` + `component_id` + `vulnerability_id`.

`component_id` is the versionless tenant Component. The key does not include occurrence,
SBOM, ingestion, Product Match Evidence id, evaluator version, package version, CVE, or KEV
membership. Existing uniqueness `finding_identity_key` remains the identity. This ADR does not
alter it.

### 2. Qualifying evidence

The qualifying set is the complete current affected Product Match Evidence set for one
organization, one asset, one versionless component, one Vulnerability, and the latest
successful SBOM ingestion whose graph uses normalization version `2`.

A row qualifies only when all of the following hold:

- the row is tenant-owned by the trusted organization;
- the outcome is `affected`;
- the origin is maintainer-reviewed Product Match Evidence, not synthetic evidence;
- the advisory revision is the current reviewed tip under
  [ADR 0032](0032-maintainer-reviewed-advisory-authority.md): not withdrawn and not superseded;
- reviewer authority for that revision is an issued capability that has already been consumed
  into an immutable approval;
- the occurrence belongs to the latest successful normalization-version-2 ingestion for that
  asset;
- current applicability is derived in the transaction from stored rows.

Every affected row in that scope is a member. A missing member makes the set incomplete.
An incomplete set fails closed and writes nothing. Unaffected, unknown, malformed, and
withdrawn rows are not members. An unaffected occurrence does not veto an affected occurrence.
KEV membership does not add or remove a member. Product Match Evidence does not grant Finding
authority by itself. The creation command re-derives the set from storage.

### 3. Creation authority

Creation authority is a sealed, process-local, purpose-specific authorization. The only
purpose is `create_finding_from_product_match_evidence` under
`finding_creation_policy_v1` version 1.

The authorization binds:

- the trusted organization from session or membership context;
- the active actor membership in that organization;
- the asset;
- the versionless component;
- the Vulnerability;
- the exact sorted fingerprint of the qualifying evidence-set identities;
- the creation purpose;
- the creation policy and version;
- the correlation identity.

A client-supplied `organizationId` is not authorization. Evidence authority is re-derived
from storage inside the creation transaction. The presented fingerprint must match that
re-derived set. No durable creation-authority table is required. The authorization is not a
reviewer-approval capability and cannot be reused for a second purpose. Ambient owner,
administrator, or maintainer role is not this authorization.

### 4. Atomic creation

One database transaction creates:

- one Finding for the natural identity;
- one immutable creation observation for that Finding and the chosen ingestion;
- one append-only evidence link per qualifying Product Match Evidence row;
- one append-only audit event for the creation.

The transaction contains no network, queue, object-storage, parser, evaluator, or provider
I/O. Timestamps that define creation are database time. The Finding is inserted so the
placeholder `open` state is only the creation record. The transaction does not set assignment,
due date, risk, `resolvedAt`, or `reopenedAt`, and it does not enqueue work.

If any write fails, the transaction rolls back. No partial Finding, observation, link, or
audit row remains.

### 5. Observation and evidence links

The creation observation is one Finding-level observation for the latest successful
normalization-version-2 ingestion. Its result is `present`. Its identity stays
organization, Finding, and ingestion. The observation's optional occurrence pointer is not
the evidence set.

Each qualifying Product Match Evidence row gets one immutable link from that observation.
Several affected versions on one asset therefore create one Finding, one observation, and
multiple evidence links. The link set is complete for the qualifying set. A later ingestion
does not add another observation in this slice.

### 6. Replay and concurrency

Exact replay is the same organization, natural identity, creation purpose, policy version,
and sorted evidence-set fingerprint. Exact replay writes nothing and returns the existing
Finding, observation, and link set.

A second request for the same natural identity with a different evidence-set fingerprint is
an immutable conflict. It overwrites nothing and does not create a second Finding.

Concurrent exact creation converges to one authoritative result. The unique natural key is
the concurrency authority. The loser reloads the committed product object and returns it.
A uniqueness failure that is not that identity is not reported as success.

### 7. Inspection and explanation

Inspection is tenant-scoped. The organization predicate comes from trusted context. Lookup
by Finding id alone is not authorization.

A safe explanation is derived at read time from the immutable creation observation and its
evidence links. It is bounded to the linked evidence identities, outcomes, and policy
versions. It does not include raw SBOM bytes, credentials, reviewer capability handles, or
another organization's data.

A foreign Finding and an absent Finding are publicly indistinguishable. The inspection result
does not reveal whether the identifier exists in another organization.

### 8. Production boundary

The implementation remains production uncomposed. This ADR authorizes no API route, web
action, worker, scheduler, queue, Outbox consumer, BullMQ processor, upload trigger,
evaluator trigger, or bulk command. Production startup does not construct the creation
command. Seed and migration do not insert Findings.

[ADR 0023](0023-provider-neutral-cve-identity.md) still requires a tested creation path
before a Finding writer exists. This ADR supplies the named architectural authorization
only. It does not add a dormant writer.

### 9. Explicit deferrals

The following remain unavailable:

- automatic matching;
- automatic and bulk Finding creation;
- repeated observations;
- risk and priority;
- assignment and due dates;
- suppression;
- accepted risk;
- false-positive decisions;
- remediation;
- verification;
- notifications;
- dashboards;
- exports;
- ticketing;
- SLA policy;
- AI authority;
- historical backfill;
- automatic closure;
- automatic reopening.

Provider-driven Finding creation remains under the ADR 0026 provider gate. This ADR does not
satisfy that gate.

## Migration intent

The intended implementation classification is an additive evidence-link model with one
forward migration. This ADR does not create that migration and does not change the frozen
migration count.

The future migration may:

- complete Finding insert, update, and delete guards so placeholder writers cannot bypass
  the creation-only command;
- complete creation-observation constraints so the first observation is immutable;
- add creation provenance fields for purpose, policy version, evidence-set fingerprint, and
  correlation identity;
- add the append-only observation-to-Product-Match-Evidence relation;
- add compound evidence-alignment keys that include the organization;
- add deferred completeness constraints that fail closed when the link set does not match
  the stored qualifying set;
- use database-authoritative timestamps;
- fail closed if incompatible placeholder Finding or observation rows exist.

The future migration must not:

- alter Finding natural identity;
- add durable creation-authority persistence;
- modify Product Match Evidence semantics;
- introduce lifecycle transitions;
- seed Findings;
- backfill historical Findings;
- enable production composition.

## Alternatives considered

- **Wait for the full ADR 0026 provider gate.** Rejected for this slice: OSV acquisition and
  catalog activation are not the authority of maintainer-reviewed Product Match Evidence, and
  requiring the complete lifecycle would block a creation-only record.
- **Treat one affected row as sufficient.** Rejected: a partial set can hide another affected
  version of the same component on the same asset.
- **Let an unaffected occurrence veto the Finding.** Rejected: unaffected evidence is not
  suppression authority, and one affected version remains affected.
- **Persist creation authority.** Rejected: the decision is re-derived from stored evidence
  inside the transaction. A durable authority table would become a second writer.
- **Automatic creation from evaluation.** Rejected: evaluation remains evidence, and this
  slice is one purpose-specific decision.

## Consequences

Positive: Finding identity stays stable. The first slice can explain itself from immutable
links without implementing remediation or risk. Replay and concurrency have one product
object.

Negative: placeholder Finding columns for assignment, due date, and risk remain in the schema
until a later migration guards them. Operators must not read those empty columns as an
implemented workflow. The creation command will not exist until a later implementation branch
adds the migration and the uncomposed writer.

## Security and tenancy

The Finding, observation, links, and audit event are tenant-owned. Every lookup and insert
uses the trusted organization. Object-storage keys are not part of this slice. Shared
advisory rows are not tenant-owned; the links that cite Product Match Evidence are.

Audit is append-only. Evidence links are append-only. Product Match Evidence is not updated.
No cascade delete of evidence is authorized. Logs for this slice must not include raw SBOMs,
credentials, capability handles, or complete evidence payloads.

## Operational failure plan

An incomplete evidence set, a withdrawn revision, a normalization-version-1 ingestion, a
foreign asset, or a fingerprint mismatch fails closed and writes nothing. Exact replay
returns the existing object. An immutable conflict modifies nothing. A failed future
migration is recovered by restoring the database and reapplying the forward-only chain.
Operators do not edit frozen migrations and do not seed Findings to make the migration pass.

## Follow-up

Implementation is a later branch. It may add one forward migration and one production-uncomposed
creation command with tenant-isolation, replay, and concurrency tests. It may not add a route,
worker, or scheduler. Repeated observations and lifecycle transitions remain unavailable until
a separate accepted decision.
