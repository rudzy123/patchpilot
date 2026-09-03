# ADR 0026: Authoritative match evidence and Finding lifecycle

- Status: Accepted
- Date: 2026-09-03
- Deciders: PatchPilot maintainers
- Supersedes: none
- Superseded by: none

Accepted as architectural direction on this feature branch. Merge to `main` remains subject to
normal pull-request review. This ADR does **not** implement match evaluation, match-evaluation
persistence, Finding creation, Finding mutation, FindingObservation writes, Evidence writes,
RiskCalculation writes, Finding repositories or repository methods, Finding transitions, audit
actions, Outbox events, BackgroundJob types, workers, fan-out, API routes, permissions, web UI,
OSV transport, OSV runtime enablement, configuration, ZIP or archive processing, PURL
normalization, ecosystem comparators, affected-version evaluation, domain contracts, Prisma,
migrations, or dependencies.

This ADR does **not** supersede [ADR 0010](0010-osv-correlation.md) as the future correlation ADR,
[ADR 0011](0011-cisa-kev-enrichment.md) as the future Finding-enrichment ADR,
[ADR 0021](0021-vulnerability-intelligence-import-foundation.md) as the Session 9 import-only catalog
and zero-Finding foundation, [ADR 0022](0022-intelligence-provider-status-authorization.md) as
sanitized provider-status authorization, [ADR 0023](0023-provider-neutral-cve-identity.md) as
canonical CVE identity and the four-condition Finding-write gate,
[ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md) as the OSV
affected-version authority and instance-owned acquisition direction, or
[ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md) as ecosystem-aware
package identity and fail-closed evaluation.

It **closes** the Finding-identity, match-evidence, observation, and lifecycle-policy portion of
[OD-15](../architecture/open-decisions.md) as architecture only. Schema, persistence, matching
runtime, and Finding writes remain unimplemented. ADR acceptance alone does **not** authorize
Finding writes.

## What this ADR is and is not

| Kind | Meaning in this ADR |
| --- | --- |
| Accepted architecture | Binding for later Session 12 evaluation design and Session 13 Finding-write design |
| Lifecycle policy | Binding occupancy, resolution, reopen, and protection rules; **not** implemented transitions |
| Finding-write authorization gate | The complete list that must all be true before any Finding writer exists |
| Future implementation | Required later; **not** present in Batch 1D |
| Deferred | Risk scoring, KEV-after-Finding projection, Finding APIs, and fan-out runtime |
| Rejected | Must not be the approved Finding or evidence foundation |

Batch 1D records decisions only. Session 11 remains zero-Finding after this ADR. No matcher, no
match-evaluation table, and no Finding writer exists.

## Context

Session 11 Batch 1A established, and ADRs 0024 and 0025 preserved:

1. PatchPilot cannot authoritatively determine whether a tenant component version is affected today.
2. OSV is the future authoritative provider for affected-package and affected-version data.
3. Tenant package inventory must not be sent to OSV.
4. OSV ingestion precedes matching. OSV runtime remains disabled.
5. Package identity is ecosystem-aware. The implemented registry is empty.
6. Evaluation is fail-closed. Statuses are `affected`, `not_affected`, `indeterminate`,
   `unsupported`, and `withdrawn`.
7. Only a deterministic `affected` result may eventually contribute to Finding creation.
8. Session 11 remains zero-Finding. Session 12 evaluator implementation remains zero-Finding.
9. KEV membership is an exploitation signal, not tenant exposure proof, and creates no Finding.
10. Canonical CVE identity is distinct from advisory identity. Sharing a CVE does not merge
    advisories.

Generic **Finding** and **FindingObservation** tables already exist and remain unused by production
workflows. `FindingRepository.create` exists and is insufficient for idempotent ensure. No
`FindingObservation` persistence port exists for matching. No match-evaluation persistence model
exists. The production policy engine has no scoring implementation. No production Finding API,
matching workflow, or Finding creation workflow exists.

Without an accepted evidence and lifecycle policy, later matching would mint Findings per
occurrence or ingestion, treat CVE or KEV as identity, rewrite historical evaluations, close
Findings from withdrawal or unknown versions, or copy provider due dates onto tenant workflow
fields.

This ADR must not reverse or weaken ADRs 0023 through 0025.

## Decision

### 1. Core decision

1. A tenant Finding may eventually be created only from a deterministic `affected` result produced
   by an approved evaluator under [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md).
2. Every positive match must be represented by immutable or append-only source-attributed match
   evidence.
3. Finding identity remains stable across rescans and component-version changes.
4. **FindingObservation** represents the result of evaluating a Finding against one completed SBOM
   ingestion.
5. Historical match evaluations and observations are never rewritten or deleted through ordinary
   application behavior.
6. Finding state changes depend on current authoritative observations, not KEV membership or
   provider prose.
7. KEV is attached or derived only after a Finding is proven through affected-version evaluation.
8. Risk scoring remains separate.
9. Session 11 remains zero-Finding.
10. Session 12 matcher remains zero-Finding.
11. The first Finding write requires a later session and explicit acceptance gates. This ADR does
    not itself authorize those writes.

### 2. Finding natural key

Logical Finding identity is:

- `organizationId`
- `assetId`
- `componentId`
- `vulnerabilityId`

Where:

- `organizationId` is tenant ownership
- `assetId` is the affected tenant asset
- `componentId` is the versionless tenant **Component** identity (UUID)
- `vulnerabilityId` is the global **Vulnerability** advisory identity (UUID)

This key remains stable across repeated SBOM ingestions, component version changes, repeated
observations, component occurrence changes, duplicate uploads, and advisory revisions under the
same **Vulnerability** identity.

The following are **not** part of the Finding natural key:

- **ComponentOccurrence** ID
- SBOM ID
- SBOM ingestion ID
- CVE string
- **CveIdentity**
- OSV source-record revision
- KEV membership
- package version
- OSV id string as a Finding-key column

Reasons:

- occurrence-scoped Findings would create upgrade and rescan churn
- ingestion-scoped Findings would create duplicates
- CVE-scoped Findings would incorrectly merge distinct advisories
- source-revision-scoped Findings would create a new Finding whenever OSV modifies an advisory
- version changes should become new observations of one logical Finding

The existing unique constraint `finding_identity_key` on
`(organizationId, assetId, componentId, vulnerabilityId)` already matches this key. Batch 1D does
not modify the schema. Preserve that uniqueness.

`vulnerabilityId` is the advisory row. Today that row is OSV-keyed by required unique `osvId`. The
Finding key uses the advisory UUID, not the OSV id string, not CVE, and not **CveIdentity**. Do not
merge **Vulnerability** rows through aliases or CVE identity.

### 3. Finding granularity

One Finding is:

> One vulnerability advisory affecting one versionless component identity on one tenant asset.

Consequences:

- multiple occurrences of the same versionless component on one asset may contribute to one Finding
- several affected versions in one current ingestion still produce one Finding
- the same component on two assets produces two Findings
- the same component in two Organizations produces isolated Findings
- two different **Vulnerability** advisory rows sharing one CVE remain two Findings when both are
  authoritatively matched
- a package upgrade does not create a second Finding
- a later advisory revision does not create a second Finding

Rejected granularities: one Finding per **ComponentOccurrence**, per ingestion, per CVE, per
provider revision, or per package version.

### 4. Authoritative match-evaluation evidence

Future dedicated append-only tenant-owned record. Conceptual name: **VulnerabilityMatchEvaluation**.

This is a future model name, not an implementation in Batch 1D. No table, Prisma model, domain
contract, or repository is added now.

It records one deterministic evaluation of:

- one tenant **ComponentOccurrence**
- one tenant SBOM ingestion
- one global **Vulnerability** advisory
- one pinned provider affected-data revision
- one evaluator version
- one exact package identity
- one observed component version

Ownership:

- tenant-owned
- `organizationId` required
- every tenant foreign key must be constrained to the same organization where repository
  conventions permit
- global **Vulnerability** and provider-revision references remain instance-owned
- no organization property is inferred from queue data alone

The record is immutable, append-only, replay-safe, source-attributed, bounded, structured,
evaluator-versioned, normalization-versioned, and tied to one exact input fingerprint.

It is **not**:

- a mutable cache
- a Finding itself
- a Finding status
- a **RiskCalculation**
- generic provider JSON
- unbounded range data
- provider prose
- an audit event
- a KEV signal

### 5. Match-evaluation statuses

The future persisted record may represent [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md)
evaluator statuses:

- `affected`
- `not_affected`
- `indeterminate`
- `unsupported`
- `withdrawn`

Only an `affected` evaluation may contribute to Finding creation.

`not_affected`, `indeterminate`, `unsupported`, and `withdrawn` evaluations:

- create no Finding by themselves
- do not reopen a Finding
- do not automatically close a Finding without current-ingestion observation policy
- remain useful as immutable evaluation history if persistence is later approved
- must never be converted into `affected` through fallback logic

Negative-comparison persistence policy:

- persist evaluation records only for bounded candidate comparisons selected by exact package
  identity
- do not persist every cross-product rejection
- no package-by-advisory global Cartesian product
- aggregate unsupported and failed counts at the job level
- positive and lifecycle-relevant evaluations receive stronger evidence retention

This policy is documentation only. Batch 1D does not persist evaluations.

### 6. Match-evaluation natural key

Future logical idempotency key:

- `organizationId`
- `componentOccurrenceId`
- `vulnerabilityId`
- `providerRevisionId`
- `evaluatorVersion`
- `inputFingerprint`

`sbomIngestionId` is **not** duplicated in the natural key. A **ComponentOccurrence** already
belongs to one ingestion. Current uniqueness includes
`(organizationId, id, sbomIngestionId)` and an occurrence is not permitted to move between
ingestions. Persist `sbomIngestionId` as an explicit locator and integrity field. Include it in the
natural key only if a later schema review shows an occurrence can change ingestion, which must not
occur.

If a content digest is used as a natural-key component, it must follow the existing repository
convention: lowercase hex SHA-256 of a versioned, deterministic canonical serialization, as already
used for **RiskCalculation.inputFingerprint** and SBOM/intelligence content hashes. Batch 1D does
not select a new hash algorithm or a serialization implementation.

### 7. Input fingerprint boundary

The input fingerprint must deterministically cover:

Tenant-side evaluated input:

- Organization scope identifier or a trusted ownership binding
- Asset ID
- SBOM ingestion ID
- Component ID
- ComponentOccurrence ID
- normalized package identity
- observed version
- version-known state
- relevant normalization versions

Provider-side evaluated input:

- Vulnerability ID
- pinned provider revision ID
- OSV advisory identity
- affected-package rule identity
- normalized affected ranges or explicit-version identity
- provider normalization version

Evaluator-side input:

- ecosystem registry key
- package normalization version
- comparator identifier
- comparator version
- evaluator version

Do **not** fingerprint:

- unrestricted provider body
- provider prose
- mutable current timestamps
- retry count
- worker ID
- queue job ID
- KEV membership
- risk score

### 8. Positive-proof content

An `affected` match evaluation must preserve bounded structured proof.

Required conceptual fields:

- `organizationId`
- `assetId`
- `sbomIngestionId`
- `componentId`
- `componentOccurrenceId`
- `observedVersion`
- normalized package identity
- Vulnerability ID
- provider revision ID
- OSV advisory ID
- affected-package record ID
- matched rule kind
- matched range type when applicable
- matched event or explicit-version locator
- package normalization version
- comparator identifier and version
- evaluator version
- input fingerprint
- `evaluatedAt`
- result status

Do **not** store:

- the complete raw provider object
- unbounded ranges
- unbounded explicit-version arrays
- full provider text
- CISA notes
- CISA `requiredAction`
- URLs
- SBOM body
- complete tenant package inventory
- KEV body
- risk score
- remediation instruction
- worker lease information
- queue payload

The evidence must be sufficient to explain which supported rule proved the component version
affected. It is not a substitute for the raw snapshot in private object storage.

### 9. Source revision pinning

Every evaluation must pin one immutable or generation-visible OSV provider revision.

- no evaluation against "latest" without a revision identity
- provider modification during matching does not change the in-flight evaluation's meaning
- an updated advisory produces a new evaluation
- old evaluations remain historical
- provider data is not mutated to reinterpret prior results
- withdrawal creates a later withdrawn revision or state
- withdrawal does not rewrite earlier evidence
- a Finding may have observations tied to several provider revisions over time

Do not place provider HTTP inside evaluation or tenant-write transactions.

### 10. Finding creation gate

A Finding may be created only when **all** of the following are true:

1. Organization context is trusted.
2. Asset belongs to the Organization.
3. SBOM belongs to the Organization and Asset.
4. SBOM ingestion belongs to the Organization and SBOM.
5. Component belongs to the Organization.
6. ComponentOccurrence belongs to the Organization and ingestion.
7. ComponentOccurrence references the same Component.
8. Package identity is resolved under an implemented registry entry.
9. Component version is known.
10. Component version is valid under the ecosystem parser.
11. OSV provider revision is accepted and active for matching.
12. Provider affected-package identity exactly matches.
13. Every rule required for the decision is supported.
14. Deterministic evaluation returns `affected`.
15. Advisory revision is not withdrawn.
16. Match evaluation is persisted or ensured idempotently.
17. Finding natural key is enforced.
18. Finding creation is idempotent.
19. FindingObservation for the current eligible ingestion is persisted with result `present`.
20. Tenant isolation is enforced by query and database constraints.
21. Audit behavior is defined.
22. Crash and replay tests pass.
23. A later session explicitly authorizes Finding writes.

If any condition fails, do not create a Finding. Unknown, unsupported, malformed, withdrawn, or
incomplete evaluation does not satisfy the gate. An `absent` or `inconclusive` observation does not
satisfy the gate.

### 11. Session write authorization

- Session 11 remains zero-Finding.
- Session 12 implements evaluation only and remains zero-Finding.
- Session 13 is the **earliest candidate** for Finding writes.
- Session 13 may write Findings only after all gates are demonstrated.
- ADR acceptance alone does not authorize writes.
- No dormant or unused Finding writer should be added before the implementation session.

This ADR does **not** authorize Finding writes for Session 11, Session 12, or Session 13. It
defines the gate those sessions must still satisfy. It also does not weaken the
[ADR 0023](0023-provider-neutral-cve-identity.md) four-condition gate.

Finding writes remain blocked until **all** of the following are complete:

1. [ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md) acquisition
   architecture is implemented.
2. OSV affected data is locally ingested, validated, and revisioned.
3. OSV catalog activation is complete and trustworthy.
4. [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md) registry contains at
   least one implemented ecosystem.
5. Package identity normalization is tested.
6. Component version parser is tested.
7. Affected-range evaluator is tested.
8. Deterministic `affected` result exists.
9. Match-evaluation persistence is designed and migrated.
10. Finding natural-key ensure semantics are implemented.
11. FindingObservation ensure semantics are implemented.
12. Current-ingestion authority is defined and applied to Finding writes.
13. Lifecycle transitions are implemented.
14. Tenant isolation is proven.
15. Crash, replay, and concurrency tests pass.
16. Audit behavior is implemented.
17. An adversarial review approves the complete write path.
18. A later implementation batch explicitly states Finding writes are authorized.

Do not give conditional permission before every gate is satisfied.

### 12. Future positive-match transaction

Design for a later tenant-scoped PostgreSQL transaction after pure evaluation has already produced
`affected`:

1. Validate or reload trusted tenant-owned records.
2. Ensure immutable **VulnerabilityMatchEvaluation**.
3. Ensure Finding by its natural key.
4. Ensure FindingObservation for the completed ingestion.
5. Update Finding observation timestamps through optimistic concurrency where required.
6. Append bounded lifecycle audit.
7. Add an Outbox event only if a later approved workflow requires one.

Requirements:

- PostgreSQL transaction only
- no provider HTTP
- no object storage
- no parser
- no comparator execution
- no Redis
- no BullMQ
- no external I/O
- no KEV query
- no risk calculation
- no remediation
- no cross-tenant operation
- no unbounded loop
- unique constraints are idempotency authority
- queue job ID is not authority
- retries reload authoritative state

Preferred sequence:

1. Perform pure affected-version evaluation before opening the write transaction.
2. Pin all immutable inputs, including the provider revision.
3. Open a short tenant-scoped transaction.
4. Revalidate current ownership and ingestion eligibility.
5. Write evidence, Finding, observation, and audit atomically.
6. Do not write current Finding projection when the ingestion is no longer eligible to affect
   current state, unless historical evaluation retention is separately approved.

If the ingestion becomes superseded during processing:

- do not update the current Finding projection
- do not create a present observation that would change current occupancy
- a completed superseded ingestion may retain a historical **VulnerabilityMatchEvaluation** and a
  historical **FindingObservation** if those rows were already authorized as ingestion-scoped
  evidence
- in-flight work that has not committed must not write current-state fields (`lastObservedAt`,
  Finding state, or `Asset.lastSuccessfulSbomIngestionId`)
- historical evaluation retention for a never-current superseded ingestion requires a later
  persistence review; the default is to skip current-state writes and only persist evaluation
  evidence when the future design explicitly authorizes historical retention

### 13. Finding ensure behavior

The future Finding persistence boundary must support:

- find by natural key
- ensure by natural key
- created versus existing result
- no duplicate Finding on replay
- no duplicate Finding under concurrent matching
- optimistic concurrency for mutable Finding projection fields
- tenant-scoped lookup
- safe conflict reload
- no global list without `organizationId`
- no update by untrusted ID alone
- no delete as normal lifecycle behavior

The existing generic `FindingRepository.create` is insufficient by itself. `Finding.version`
already exists for optimistic concurrency. Do not implement the correction in Batch 1D.

### 14. Finding initial state

A newly created Finding begins `open` only when:

- the current eligible ingestion has an `affected` evaluation
- a `present` observation is created
- the advisory revision is not withdrawn

Initial values must not be derived from:

- KEV status
- CISA `requiredAction`
- provider severity text
- risk policy
- remediation state
- unsupported or indeterminate evaluation

Finding may initially have no **RiskCalculation**. An unscored Finding is valid:
`currentRiskCalculationId` is already nullable. Do not add a risk calculation to creation.

Existing Finding states remain:

- `open`
- `verification_pending`
- `risk_accepted`
- `mitigated`
- `false_positive`
- `resolved`
- `inconclusive`

This ADR does not remove `verification_pending` or Finding-state `inconclusive`. Observation result
`inconclusive` is distinct from Finding state `inconclusive`. Batch 1D does not change the enum.

### 15. FindingObservation semantics

**FindingObservation** is one immutable observation of one logical Finding under one completed SBOM
ingestion.

Preferred natural key, already present as `finding_observation_identity_key`:

- `organizationId`
- `findingId`
- `sbomIngestionId`

An observation may reference:

- one representative **ComponentOccurrence**
- the match evaluation that supports its method and result (future FK or locator, not implemented)
- the provider revision indirectly or directly through the evaluation

One ingestion may contain multiple occurrences of the same component. The observation summarizes
the Finding-level result for that ingestion. It is **not** one row per occurrence.

Observations are append-only. Ordinary application behavior never updates or deletes them.

### 16. Observation outcomes and methods

Closed observation results remain:

- `present`
- `absent`
- `inconclusive`

**Present.** At least one eligible current occurrence for the Finding's component and advisory
evaluates `affected`. That occurrence requires a supported ecosystem, known version, deterministic
`affected` result, and a positive match evaluation. If any eligible occurrence is `affected`, the
Finding-level observation is `present` even when other occurrences of the same component are
`indeterminate`, `unsupported`, or have unknown versions. Those other occurrences must
not be treated as absence and must not veto `present`.

**Absent.** Every relevant occurrence in an adequately covered completed ingestion is
authoritatively `not_affected`, or the component is authoritatively not present according to
approved coverage semantics.

Do **not** use `absent` when:

- version unknown
- evaluation unsupported
- provider data malformed
- ingestion incomplete
- coverage inadequate
- some relevant occurrence is `indeterminate`
- some relevant occurrence remains `affected`

**Inconclusive.** Use when the ingestion or evaluation cannot establish `present` or `absent`.
Examples, all of which require that **no** eligible occurrence is `affected`: unknown version,
unsupported ecosystem, unsupported range type, incomplete coverage, malformed component identity,
evaluation unavailable, or remaining `indeterminate`/`unsupported` occurrences that prevent an
absence conclusion. Do **not** classify mixed `affected` and `indeterminate` (or `unsupported`) as
`inconclusive`.

Inconclusive must not create a new Finding. For an existing Finding, inconclusive must not
automatically resolve it.

Observation `method` must be a closed, versioned catalog. Exact enum design is deferred to
implementation contracts. Architectural examples, not implemented constants:

- `affected_version_match`
- `explicit_version_match`
- `version_out_of_affected_range`
- `component_not_observed`
- `unsupported_ecosystem`
- `unknown_version`
- `insufficient_coverage`
- `withdrawn_advisory`

Do not include free-form provider text as the authoritative method. Do not expose
dependency-internal comparator errors. Existing lifecycle sketches such as `exact_purl` remain
historical examples until Session 13 selects the closed catalog.

Current schema stores `method` as `VARCHAR(64)`. That is a later design-review item (closed enum
versus bounded string), not a Batch 1D schema change.

### 17. Current-ingestion authority

Only a successfully completed, accepted ingestion may update the current Finding projection.

The repository already has an authoritative current-ingestion pointer:
`Asset.lastSuccessfulSbomIngestionId`. Canonical rule, unchanged:

- among ingestions in state `completed` for the asset, the one whose SBOM `receivedAt` is greatest
- tie-break ingestion `createdAt`, then ingestion `id`
- completing an older upload still persists that ingestion's graph; it must not overwrite the
  pointer, `lastObservedAt`, or Finding state
- "latest completed" never means last worker to finish
- failed or quarantined ingestions cannot create observations that change current Finding state
- partial ingestion cannot resolve a Finding
- an older ingestion cannot overwrite state derived from a newer ingestion
- duplicate ingestion replay remains idempotent

Session 13 must apply this existing rule to Finding writes. It must not invent authority from a
bare timestamp without the pointer and compare-and-set protection. Asynchronous pointer updates
today do not increment `Asset.version`; Finding projection updates must use `Finding.version`.

Batch 1D does not implement the Finding-write consumer of this rule.

### 18. Repeated observation

When an existing Finding is present again in a later authoritative ingestion:

- do not create a new Finding
- create or ensure one new FindingObservation for that ingestion
- update `lastObservedAt` only if the ingestion is newer and eligible
- preserve `firstObservedAt`
- preserve prior observations
- do not rewrite prior match evaluations
- do not duplicate audit on replay
- do not change risk acceptance automatically
- do not change `dueAt` from provider data

### 19. Version-change behavior

A component version change on the same Asset and versionless Component:

- retains the same Finding natural key
- creates a new **ComponentOccurrence**
- produces a new match evaluation
- produces one observation for the new ingestion
- may change `present`, `absent`, or `inconclusive`
- does not delete the Finding
- does not rewrite prior evidence

A version upgrade that becomes `not_affected` may make the current observation `absent`.

### 20. Resolution policy

A system-created open Finding may become `resolved` only when:

1. A newer authoritative completed ingestion exists.
2. Coverage is adequate.
3. The component is no longer present, or every relevant occurrence is authoritatively
   `not_affected`.
4. No relevant occurrence remains `affected`.
5. No relevant occurrence is `indeterminate` or `unsupported` in a way that prevents an absence
   conclusion.
6. The advisory revision used for evaluation is accepted.
7. The lifecycle transition is allowed by the occupancy table below.
8. Optimistic concurrency succeeds.
9. Evidence and observation are persisted atomically.
10. No user-protected occupancy rule prevents the specific transition being attempted.

Do **not** automatically resolve because:

- KEV no longer lists the CVE
- OSV withdraws the advisory
- provider data is temporarily unavailable
- matching becomes unsupported
- a scan fails
- an old ingestion lacks the component
- a remediation task is completed
- an Asset is archived, unless a later explicit lifecycle policy authorizes it

Reconcile with the accepted [finding-lifecycle.md](../architecture/finding-lifecycle.md) occupancy
rules rather than inventing a conflicting model:

- evidence-backed current `absent` may set `resolved` from `open`, `verification_pending`,
  `risk_accepted`, `mitigated`, `inconclusive`, and `false_positive`, because absence is
  asset evidence, not a silent override of a user decision by matching heuristics
- the **RiskAcceptance** row remains historical and must not reopen a Finding that is already
  `resolved`
- `false_positive` remains until revoked **or** evidence-backed `resolved`
- task completion never sets `resolved`

Withdrawn advisory:

- no automatic resolution from withdrawal alone
- persist or derive a `withdrawn` evaluation
- require later lifecycle policy or reviewer action
- historical evidence remains

### 21. Reopen policy

A `resolved` Finding may reopen to `open` when:

- a later authoritative completed ingestion produces `present`
- a new positive match evaluation exists
- optimistic concurrency succeeds
- the status is eligible for automatic reopen under lifecycle policy

Do not automatically reopen `risk_accepted`, `mitigated`, or `false_positive`. Those remain until
revoked, expired, withdrawn, or evidence-backed `resolved` according to existing occupancy rules.

KEV membership must not reopen a Finding. Inconclusive must not reopen a Finding to `open`.

### 22. Protected status behavior

System-managed transitions:

- initial creation to `open`
- `open` to `resolved` from authoritative current absence
- `resolved` to `open` from authoritative later presence
- `open` / `verification_pending` to Finding-state `inconclusive` from a current inconclusive
  observation
- `verification_pending` occupancy from task completion or verify requested, only from `open`

User-protected or user-managed states:

- `risk_accepted`
- `mitigated`
- `false_positive`

Matching must not silently override those user decisions for `present` or inconclusive occupancy.
While those states still apply, a current `present` observation is recorded and does not force
`open`. Existing occupancy already allows evidence-backed `resolved` from those states; this ADR
keeps that rule.

### 23. Due-date boundary

CISA KEV `dueDate` and `requiredAction` must never populate or modify `Finding.dueAt`
automatically. OSV provider dates must not populate `Finding.dueAt` automatically. Finding due
dates are tenant workflow data, not provider catalog data. No provider text executes as
remediation. Due-date recommendations, when they exist later, belong on **RiskCalculation**, not as
authoritative Finding state.

### 24. KEV integration

KEV remains outside affected-version proof.

After a Finding exists through an `affected` result:

- active KEV membership may be derived using the Session 10 one-CVE lookup
- KEV may later appear as a read-only Finding projection
- KEV may later become append-only Evidence if separately approved
- KEV may later become a versioned risk factor if separately approved

KEV must not:

- create a Finding
- satisfy the affected-version gate
- substitute for match evaluation
- close a Finding
- reopen a Finding
- set `Finding.dueAt`
- override risk acceptance
- execute `requiredAction`
- match CISA vendor or product text to Components

Multi-CVE advisories must use bounded canonical-CVE links. Do not add reverse catalog scans.

### 25. Risk boundary

Risk integration is deferred.

- Finding creation may occur before risk calculation
- `currentRiskCalculationId` may remain null
- no hard-coded OSV score
- no hard-coded KEV score
- no `finding.recalculate` event in Session 11 or Session 12
- this ADR does **not** authorize `finding.recalculate` at all
- no **RiskCalculation** is created by match evaluation
- `risk_accepted` status is not automatically invalidated by matching or KEV refresh
- risk integration requires a versioned, published policy
- prior **RiskCalculations** remain historical
- stale or disabled KEV membership requires an explicit future policy
- `indeterminate` and `unsupported` do not mean low risk

No risk code is added. The production policy engine remains without approved scoring.

### 26. Audit model

Future bounded audit behavior. Do not add audit constants or actions in Batch 1D.

Per-positive lifecycle actions may later include:

- `finding.created`
- `finding.observed`
- `finding.resolved`
- `finding.reopened`

The existing v0.1 catalog already names `finding.state_changed`, `finding.false_positive`, and
`finding.mitigated`. Session 13 must reconcile specific lifecycle actions with that catalog rather
than emitting both a generic and a specific duplicate event for the same transition.

Per-job aggregate action may later include:

- `vulnerability.match_evaluated`

Requirements:

- do not create one **AuditEvent** per negative comparison
- positive match evidence is not replaced by an audit event
- audit payload contains bounded IDs, counts, versions, and status only
- no provider prose
- no full PURL unless internal policy explicitly permits it
- no package inventories
- no affected-version arrays
- no raw provider record
- no SBOM body
- no CVE list
- no KEV body
- no raw comparator error
- no credential or URL

Replay uniqueness remains `(organizationId, action, subjectId, correlationId)` for tenant events.

### 27. Outbox boundary

This ADR does **not** authorize `finding.recalculate`.

A future Finding transaction may create an Outbox event only when a separately approved downstream
workflow exists. Potential future events must:

- be versioned
- have locator-only payloads
- be organization-scoped
- not contain package inventories
- not contain provider records
- not contain CVE lists
- not contain affected ranges
- use PostgreSQL uniqueness for idempotency
- treat Redis delivery as at-least-once
- use **BackgroundJob** as execution lease

No Outbox event is needed merely to define a Finding. Batch 1D adds no event names as implemented
constants.

### 28. Tenant-isolation model

Future matching orchestration must:

1. Obtain `organizationId` from trusted session or execution context.
2. Reload Organization as authority.
3. Scope Asset by `organizationId`.
4. Scope SBOM by `organizationId` and Asset.
5. Scope ingestion by `organizationId` and SBOM.
6. Scope Component by `organizationId`.
7. Scope ComponentOccurrence by `organizationId`, Component, and ingestion.
8. Scope Finding by `organizationId` and natural key.
9. Scope FindingObservation by `organizationId` and Finding.
10. Scope MatchEvaluation by `organizationId`.
11. Never trust `organizationId` from a queue payload as authority.
12. Never pass tenant package inventory to OSV.
13. Never expose one tenant's matches to another tenant.
14. Use compound tenant foreign keys where repository conventions support them.
15. Ensure every tenant write includes `organizationId`.
16. Keep global **Vulnerability**, OSV records, **CveIdentity**, and KEV tables tenant-free.

A global OSV synchronization job uses `organizationId` null and must not write Findings. No tenant
matching exists in Batch 1D.

### 29. Trigger and fan-out boundary

Documented future trigger model. Not implemented.

Inventory changes: successful accepted SBOM ingestion may enqueue one organization-scoped matching
request for that ingestion.

Provider changes: accepted OSV generation may enqueue bounded reconciliation requests. No global
unbounded tenant transaction. No package or CVE list in queue payload. One organization failure
does not block another. PostgreSQL persists fan-out checkpoints. Organization authority is
reloaded. Work is paged. Duplicate requests are idempotent.

Catch-up: periodic bounded reconciliation may recover missed Redis delivery.

Do not implement fan-out, scheduling, jobs, Outbox, workers, or page cursors in Batch 1D.

### 30. Idempotency model

Match evaluation:

- deterministic natural key or fingerprint
- insert once
- immutable
- duplicate evaluation returns existing

Finding:

- unique natural key `organizationId + assetId + componentId + vulnerabilityId`
- concurrent creation returns one authoritative Finding
- no duplicate Finding on replay

FindingObservation:

- unique `organizationId + findingId + sbomIngestionId`
- one summarized observation per Finding per ingestion
- duplicate replay returns existing
- prior observation never overwritten

Lifecycle update:

- optimistic version or compare-and-set
- newer authoritative ingestion must not be overwritten by older work
- replay after commit produces no duplicate audit or observation

Audit:

- exact transaction and correlation identifiers
- no duplicate lifecycle action on replay

Future Outbox:

- stable organization-scoped dedupe key
- PostgreSQL authority
- Redis job ID not final authority

Do not implement any of these in Batch 1D.

### 31. Crash and replay behavior

| Failure | Expected future behavior |
| --- | --- |
| Crash before evaluation | No write. Job retry may reevaluate. |
| Crash after evaluation but before transaction | No tenant write. Retry is deterministic. |
| Crash during transaction | Entire transaction rolls back. |
| Crash after commit before queue acknowledgement | Replay returns existing evidence, Finding, and observation. No duplicate audit. No duplicate downstream request. |
| Provider revision changes during work | In-flight evaluation remains pinned to its revision. New revision receives separate reconciliation. |
| SBOM ingestion becomes superseded | Evaluation may be retained only if the future design authorizes historical retention. Superseded ingestion must not update current Finding projection. |
| Organization or tenant record deleted | Stop safely. No cross-tenant fallback. No global orphan Finding write. |
| Optimistic concurrency conflict | Reload authoritative Finding. Retry boundedly. Never overwrite a newer observation with older state. |
| Database outage | Retryable infrastructure failure. |
| Unsupported, indeterminate, withdrawn | No new Finding. No reopen. No automatic resolve without a valid current observation. |

### 32. Evidence retention

Match evaluations and observations are historical evidence.

Ordinary application behavior must not update them, delete them, rewrite them when a provider
revision changes, remove them when a component disappears, remove them when a Finding resolves,
remove them when an advisory withdraws, or overwrite their normalization or evaluator versions.

v0.1 [retention policy](../architecture/retention-and-deletion.md) retains findings and observation
history indefinitely until an instance operator changes config. There is no automatic purge in the
MVP journey. This ADR does not claim a stronger legal hold or indefinite retention beyond that
policy. Future archive or purge requires a separately reviewed compliance policy.

### 33. Finding deletion boundary

Findings must not be deleted merely because:

- the component is no longer present
- the version is upgraded
- the advisory is withdrawn
- KEV removes the CVE
- provider data changes
- risk is accepted
- the issue is mitigated
- the Finding is false positive
- the Asset is archived

Lifecycle uses status and evidence, not deletion. Any administrative deletion remains outside this
ADR.

### 34. Error and logging boundary

Future Finding orchestration errors must be bounded and sanitized.

Do not log:

- SBOM bodies
- package inventory lists
- provider objects
- provider prose
- affected-version arrays
- full tenant PURLs unless established logging policy allows them
- component versions in broad aggregate logs
- raw comparator errors
- database errors
- credentials
- object keys
- URLs from provider records
- KEV `requiredAction`
- CVE lists

Safe logging may include:

- `organizationId` under established internal policy
- ingestion ID
- Finding ID
- Vulnerability ID
- evaluator version
- result counts
- stable reason codes
- job ID under established internal policy

No per-comparison debug logging in production.

### 35. Security threats

In-scope threats for later implementation review. This ADR provides no exploit steps and no
implementation code.

| Threat | Architectural control |
| --- | --- |
| Forged organization IDs | Trusted session or execution context; reload Organization; never take org from queue payload |
| Cross-tenant component substitution | Compound tenant FKs; reload Component and occurrence with organization predicate |
| Cross-tenant Finding lookup | Tenant-scoped find; no global list without `organizationId` |
| Duplicate Finding creation | Unique natural key; ensure/reload on conflict |
| Duplicate observation creation | Unique `(organizationId, findingId, sbomIngestionId)` |
| Replay after worker crash | Immutable insert-once evidence; unique constraints are authority |
| Older ingestion overwriting newer state | Current-ingestion pointer plus `Finding.version` |
| Provider revision changing during evaluation | Pin revision before evaluate; new revision is a new evaluation |
| Withdrawn advisory causing unsafe closure | No automatic resolve from withdrawal |
| Unsupported evaluation becoming absence | `unsupported` ≠ `absent`; fail closed |
| Unknown version becoming absence | `indeterminate` ≠ `absent` |
| Mixed affected and indeterminate occurrences | Observation is `present` if any eligible occurrence is affected; otherwise `inconclusive`, never `absent` |
| Incomplete SBOM coverage causing unsafe resolution | Coverage gates; `insufficient_coverage` is inconclusive |
| KEV membership causing Finding creation | KEV is after-Finding only |
| Provider due date overriding tenant workflow | `Finding.dueAt` is not populated from KEV or OSV |
| User-protected status overwritten by automation | Occupancy table; matching does not force `open` from RA/mitigated/FP |
| Audit amplification | Aggregate job audit; no per-negative-comparison event |
| Fan-out amplification | Bounded paged org work; no global tenant transaction |
| Queue payload leakage | Locator-only payloads |
| Provider prose in evidence or logs | Bounded proof fields; redaction list |
| Optimistic concurrency failure | Reload and bounded retry; never clobber newer state |
| Stale source data | Evaluate only accepted active matching revision; staleness is not absence |
| Malformed source revision | Invalid source; no Finding |
| Evidence tampering | Append-only rows; no ordinary update/delete |
| Unauthorized deletion | Deletion is not lifecycle |
| Risk recalculation triggered before policy exists | No `finding.recalculate` authorization |

### 36. Database direction

Likely future schema work. No SQL in Batch 1D. Do not combine these with OSV ingestion migration,
package comparator dependencies, risk schema, API schema, or worker runtime.

1. Match-evaluation evidence: tenant-owned append-only evaluation table; provider revision
   reference; occurrence and ingestion references; evaluator and normalization versions; input
   fingerprint; result status; bounded proof fields; unique replay key; tenant compound
   constraints.
2. Finding persistence corrections: ensure natural key matches accepted identity (already true for
   `finding_identity_key`); verify optimistic concurrency (`Finding.version` already exists); add
   provenance linkage only if justified; no rewrite of historical Findings; no provider prose
   fields.
3. FindingObservation support: repository and ensure behavior; match-evaluation reference if
   approved; preserve current natural key; append-only enforcement.

The existing Finding natural key appears sufficient. Optional later design-review items, not Batch
1D defects requiring a migration now:

- `FindingObservation.method` is an unbounded `VARCHAR(64)` rather than a closed enum
- `Finding.componentOccurrenceId` is a nullable representative occurrence, correctly excluded from
  the natural key
- no match-evaluation table or FK exists

### 37. Dependency effect

This ADR requires no dependency. Do not add ORM, queue, state-machine, workflow, risk, semver,
provider SDK, or archive libraries.

Future implementation should reuse PostgreSQL uniqueness, Prisma transaction support, existing
`Result`/`AppError` conventions, and existing **BackgroundJob** and Outbox architecture if later
authorized. No dependency is selected in Batch 1D.

## Alternatives considered

| Alternative | Disposition | Rationale |
| --- | --- | --- |
| One Finding per ComponentOccurrence | **Rejected** | Upgrade and rescan churn; duplicates the same logical issue |
| One Finding per SBOM ingestion | **Rejected** | Duplicate Findings on every upload |
| One Finding per CVE / CveIdentity | **Rejected** | Merges distinct advisories; contradicts ADR 0023 |
| One Finding per OSV source-record revision | **Rejected** | New Finding whenever the advisory changes |
| Version as part of Finding identity | **Rejected** | Upgrade would mint a second Finding |
| KEV listing creates Findings | **Rejected** | KEV is not affected-version proof |
| Unknown or unsupported evaluation creates Findings | **Rejected** | Fail closed; only deterministic `affected` |
| Unsupported or unknown means `absent` | **Rejected** | Would auto-resolve unsafely |
| Withdrawn advisory automatically resolves Findings | **Rejected** | Withdrawal is intel, not asset evidence |
| Provider due date sets `Finding.dueAt` | **Rejected** | Tenant workflow data, not catalog data |
| Mutable observations | **Rejected** | Evidence integrity |
| Delete Findings or observations on resolve | **Rejected** | Lifecycle uses status, not deletion |
| Cartesian persistence of every non-match | **Rejected** | Amplification; persist bounded candidates only |
| Evaluate inside the tenant write transaction | **Rejected** | Comparator, parser, provider HTTP, and other external I/O must complete before the PostgreSQL tenant write |
| `finding.recalculate` from Session 11/12 matching | **Rejected** | No published risk policy; this ADR does not authorize the event |
| Dormant Finding writer before Session 13 | **Rejected** | ADR 0023 forbids unused write paths |
| Tenant package queries to OSV for matching | **Rejected** | Already rejected by ADR 0024 |
| Generic FindingRepository.create as ensure | **Rejected** as sufficient | No natural-key ensure, no conflict reload |

## Consequences

Positive:

- later Finding writes have a stable identity that survives rescans and upgrades
- positive matches have a named evidence record distinct from Findings, KEV, and risk
- fail-closed evaluation cannot become absence or Finding creation by accident
- existing schema uniqueness already matches the accepted Finding and observation keys
- Session 9 KEV runtime, Session 10 identity, and ADRs 0023–0025 remain intact

Negative / deferred cost:

- Session 11 still cannot create Findings
- Session 12 still cannot create Findings
- match-evaluation persistence, ensure repositories, and lifecycle automation remain unbuilt
- Session 13 remains only a candidate after every gate
- `FindingRepository.create` remains insufficient until a later implementation batch

This ADR does **not** claim that matching, match-evaluation persistence, or Finding creation
exists.

## Security and tenancy

Future match evidence, Findings, and observations are tenant-owned and must include authorized
`organizationId`. Global **Vulnerability**, OSV revisions, **CveIdentity**, and KEV tables remain
tenant-free. Instance-owned OSV synchronization must not write Findings.

Looking up a Vulnerability, CVE, or KEV membership is not authorization and is not tenant
exposure. Queue payloads, webhook bodies, and client-supplied ids are not organization proof.

Canonical log redaction in `security.mdc` still forbids logging raw SBOMs, complete
vulnerability-feed payloads, credentials, and authorization headers. This ADR adds no network
client, parser, or storage layout.

This ADR does not weaken [ADR 0013](0013-organization-scoped-tenancy.md),
[ADR 0021](0021-vulnerability-intelligence-import-foundation.md), or
[ADR 0023](0023-provider-neutral-cve-identity.md).

## Operational failure plan

No Finding writer, matcher, or match-evaluation table exists, so there is no Finding-write
operational failure path to recover. CISA KEV synchronization, Session 8 SBOM ingestion, and
authentication are unchanged.

When Finding writes are later implemented, failures must follow the crash and replay table above:
roll back incomplete transactions, reload authoritative tenant state, fail closed on unsupported
or withdrawn evaluation, and never invent a success path from KEV, unknown versions, or provider
outage.

## Follow-up

Open after Batch 1D:

- OSV transport, licensing, completeness, and persistence review ([ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md))
- Session 12 zero-Finding evaluator for one reviewed registry entry ([ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md))
- match-evaluation persistence design and forward-only migration
- Finding and FindingObservation ensure repositories
- Session 13 Finding-write implementation only after every authorization gate
- current-ingestion consumer for Finding projection updates
- closed observation-method catalog
- KEV-after-Finding projection ([ADR 0011](0011-cisa-kev-enrichment.md))
- versioned risk policy and any later `finding.recalculate` ADR
- [OD-19](../architecture/open-decisions.md) full provider-neutral **Vulnerability** advisory identity
- ZIP/archive support, remaining deferred and unauthorized
- OSV runtime enablement, remaining fail-closed

Required verification for this batch is documentation review against these ADR 0026 invariants. This
batch is documentation-only: it adds no Finding, matching, OSV runtime, ZIP, migration, dependency,
or new test module. Existing Session 11 invariant tests continue to assert eleven frozen migrations,
disabled OSV, and no `finding.recalculate`.

Docs updated with this ADR: [ADR index](README.md),
[open-decisions.md](../architecture/open-decisions.md),
[finding-lifecycle.md](../architecture/finding-lifecycle.md),
[domain-model.md](../architecture/domain-model.md),
[tenant-isolation.md](../architecture/tenant-isolation.md),
[audit-model.md](../architecture/audit-model.md),
[vulnerability-intelligence.md](../architecture/vulnerability-intelligence.md),
[architecture README](../architecture/README.md), [AGENTS.md](../../AGENTS.md),
[glossary](../product/glossary.md), [reliability-model.md](../architecture/reliability-model.md),
[testing-strategy.md](../architecture/testing-strategy.md),
[threat-model.md](../security/threat-model.md), [risk-register.md](../security/risk-register.md),
[ADR 0010](0010-osv-correlation.md),
[ADR 0024](0024-authoritative-affected-version-source-and-osv-acquisition.md),
and [ADR 0025](0025-ecosystem-aware-package-identity-and-version-evaluation.md).
